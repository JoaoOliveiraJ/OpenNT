//! Callbacks de modo usuário: KeUserModeCallback e o serviço
//! NtCallbackReturn.
//!
//! Um serviço do kernel (o win32k, dentro de uma syscall da thread) chama
//! uma rotina de usuário do processo, `PEB->KernelCallbackTable[ApiNumber]`,
//! e espera o retorno dela, como o KeUserModeCallback/KiCallUserMode do NT:
//!
//! - confere o contexto (o CalloutActive da KTHREAD, IRQL PASSIVE_LEVEL, sem
//!   anexação nem APCs desligadas — os bugchecks 0x107, 0x4A e 0x1 do NT) e
//!   conta o aninhamento em KTHREAD.CallbackNestingLevel (mais de 31 dá
//!   STATUS_STACK_OVERFLOW);
//! - cria uma pilha de kernel nova para o callback (o MmCreateKernelStack;
//!   sem memória, STATUS_NO_MEMORY) e preenche o KERNEL_STACK_CONTROL dela:
//!   o segmento corrente (StackBase, ActualLimit) e o anterior (StackBase,
//!   StackLimit, InitialStack da thread e, em Previous.KernelStack, o quadro
//!   do callout, que vive no kernel enquanto o callback roda);
//! - monta na pilha do usuário, abaixo do RSP da syscall, o UCALLOUT_FRAME
//!   (0x58 bytes: as homes, Buffer em +0x20, Length em +0x28, ApiNumber em
//!   +0x2C e o MACHINE_FRAME com o RIP e o RSP da syscall em +0x30/+0x48)
//!   seguido da cópia do buffer de entrada, alinhado a 16, sondando a faixa;
//!   uma falha na sonda ou na cópia é a exceção que o __except do NT
//!   converte no status devolvido (STATUS_ACCESS_VIOLATION), sem callback;
//!   cada recusa do próprio KeUserModeCallback (o callback não roda) sai
//!   numa linha `[callback]` da serial, com a rotina da tabela, o status, o
//!   aninhamento e o RSP do usuário, para o diagnóstico;
//! - troca a KTHREAD para a pilha nova (InitialStack, StackBase e
//!   StackLimit, que o despacho põe em KPRCB.RspBase e TSS.RSP0) e entra no
//!   anel 3 em ntdll!KiUserCallbackDispatcher (o KeUserCallbackDispatcher,
//!   publicado quando a DLL de sistema é mapeada) com o RSP no frame, os
//!   registradores do KiCallUserMode (RCX = RIP, R11 = RFLAGS, R8 = RSP,
//!   RBP e R9 = o RBP da syscall, os demais e os XMM zerados, o MXCSR da
//!   syscall). O despachante da ntdll chama a rotina da tabela e, se ela
//!   voltar, chama NtCallbackReturn(NULL, 0, retorno);
//! - as syscalls do callback rodam aninhadas no serviço, na pilha nova
//!   (`threads::run_callback`); a thread continua escalonável como no NT:
//!   uma syscall aninhada que espera deixa a CPU e as outras threads rodam
//!   (o laço repassa o bloqueio ao serviço de fora, ver [`CalloutStacks`]),
//!   até o NtCallbackReturn: ele acha o quadro
//!   do callout pelo KERNEL_STACK_CONTROL da InitialStack corrente, grava o
//!   ponteiro e o tamanho de saída nas variáveis do chamador e o status; sem
//!   callback ativo, STATUS_NO_CALLBACK_ACTIVE;
//! - na volta, a KTHREAD retoma a pilha anterior, o aninhamento cai, a pilha
//!   do callback volta ao Mm e, com TEB.GdiBatchCount pendente, o callout 7
//!   do win32k (o flush do lote GDI) roda com o RSP do usuário 0x100 abaixo;
//! - uma thread com o término pedido recebe a APC de término na volta ao
//!   anel 3 do callback e sai ali, sem voltar a este KeUserModeCallback
//!   (`threads::run_callback`): a pilha, o quadro e o CONTEXT do callback
//!   ficam num registro por thread e voltam pelo ceifador
//!   ([`release_abandoned`]).
//!
//! O RSP e o RIP da syscall vêm do CONTEXT do intervalo (o papel do
//! KTRAP_FRAME); o callback roda num CONTEXT próprio, então o da syscall
//! não muda.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::hal::amd64::usermode;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::extra_fs_fat::KernelStackControl;
use crate::ntos::inc::types::{Context, Kthread};
use crate::ntos::ke::{bugcheck, context_switch, irql};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::{kernel_stack, memory_map};
use crate::ntos::ps::user::{state, threads};
use crate::ntos::ps::{process, win32};
use crate::rtl::{KernelError, SpinLock};

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_STACK_OVERFLOW: u32 = 0xC000_00FD;
const STATUS_NO_CALLBACK_ACTIVE: u32 = 0xC000_0258;
/// Bugchecks do KeUserModeCallback e do NtCallbackReturn.
const APC_INDEX_MISMATCH: u32 = 0x1;
const IRQL_GT_ZERO_AT_SYSTEM_SERVICE: u32 = 0x4A;
const KERNEL_EXPAND_STACK_ACTIVE: u32 = 0x107;
const INVALID_CALLBACK_STACK_ADDRESS: u32 = 0x1CD;
/// KTHREAD.MiscFlags.CalloutActive (bit 12).
const CALLOUT_ACTIVE: u32 = 0x1000;
/// Aninhamento máximo de callbacks (o `cmp al, 1Fh` do NT).
const MAXIMUM_NESTING: u8 = 0x1F;
/// O que o flush do lote desce do RSP do usuário enquanto roda.
const GDI_BATCH_STACK: u64 = 0x100;
/// Seletores e RFLAGS do anel 3.
const USER_CODE: u16 = 0x33;
const USER_DATA: u16 = 0x2B;
/// Fim da faixa que o ProbeForWrite aceita (MmUserProbeAddress).
const USER_PROBE_ADDRESS: u64 = 0x7FFF_FFFF_0000;
const PAGE: u64 = 0x1000;

/// KeUserCallbackDispatcher: o ntdll!KiUserCallbackDispatcher da DLL de
/// sistema, publicado quando ela é mapeada (o PspLookupKernelUserEntryPoints
/// do NT); 0 enquanto ela não exporta o despachante.
static DISPATCHER: AtomicU64 = AtomicU64::new(0);

/// Publica o despachante de callbacks da DLL de sistema e devolve o
/// anterior.
pub fn set_dispatcher(address: u64) -> u64 {
    DISPATCHER.swap(address, Ordering::AcqRel)
}

/// UCALLOUT_FRAME (amd64): o que o KiUserCallbackDispatcher lê da pilha.
/// Do MACHINE_FRAME o NT só preenche o RIP e o RSP.
#[repr(C)]
struct UcalloutFrame {
    _homes: Reserved<0x20>,
    buffer: Field<u64>,
    length: Field<u32>,
    api_number: Field<u32>,
    machine_rip: Field<u64>,
    _machine_seg_cs_eflags: Reserved<0x10>,
    machine_rsp: Field<u64>,
    _machine_seg_ss: Reserved<8>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for UcalloutFrame {}

const _: () = {
    assert!(core::mem::size_of::<UcalloutFrame>() == 0x58);
    assert!(core::mem::offset_of!(UcalloutFrame, buffer) == 0x20);
    assert!(core::mem::offset_of!(UcalloutFrame, api_number) == 0x2C);
    assert!(core::mem::offset_of!(UcalloutFrame, machine_rip) == 0x30);
    assert!(core::mem::offset_of!(UcalloutFrame, machine_rsp) == 0x48);
};

/// O quadro do callout (o papel do KCALLOUT_FRAME do KiCallUserMode, que o
/// NtCallbackReturn acha por Previous.KernelStack): as variáveis de saída
/// do chamador, o status e se o callback já retornou. Memória do kernel,
/// viva enquanto o KeUserModeCallback espera.
#[repr(C)]
struct CalloutFrame {
    output_buffer: Field<u64>,
    output_length: Field<u64>,
    status: Field<u32>,
    returned: Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for CalloutFrame {}

/// Os dois segmentos de pilha de kernel de um KeUserModeCallback em curso
/// (InitialStack, StackBase, StackLimit): o do serviço que chamou e o do
/// callback.
///
/// Enquanto o callback roda, a KTHREAD fica no segmento do callback, como
/// depois do KiCallUserMode. O laço do callback (`threads::run_callback`)
/// roda no segmento de fora, e quando ele deixa a CPU (o bloqueio de um
/// serviço aninhado repassado, uma espera PENDING de uma syscall aninhada, o
/// fim do quantum) a KTHREAD volta a esse segmento: a troca de contexto
/// grava o quadro dele em KTHREAD.KernelStack, e o despacho confere esse
/// quadro contra InitialStack/StackLimit e carrega InitialStack em
/// RspBase/RSP0 na retomada. Retomado, o laço reinstala o segmento do
/// callback antes de voltar ao anel 3 ou ao serviço aninhado. O
/// KERNEL_STACK_CONTROL da pilha do callback (o segmento anterior e o quadro
/// do callout) não muda nesse meio-tempo.
#[derive(Clone, Copy)]
pub struct CalloutStacks {
    thread: u64,
    outer: (u64, u64, u64),
    callback: (u64, u64, u64),
}

impl CalloutStacks {
    fn install(&self, (initial, base, limit): (u64, u64, u64)) {
        // SAFETY: a KTHREAD corrente está viva enquanto o callback dela roda.
        let thread = unsafe { Kthread::at(self.thread) };
        thread.initial_stack.set(initial);
        thread.stack_base.set(base);
        thread.stack_limit.set(limit);
    }

    /// O laço do callback deixa a CPU por uma espera já instalada na thread
    /// (`context_switch::block_installed_wait`), no segmento de fora, e volta
    /// com o segmento do callback. `false` quando não pôde trocar.
    pub fn block_outer_service(&self, record_irql: bool) -> bool {
        self.install(self.outer);
        let blocked = context_switch::block_installed_wait(record_irql);
        self.install(self.callback);
        blocked
    }

    /// A thread sai de vez dentro deste nível de callback (o término dela):
    /// a KTHREAD volta ao segmento de fora, o deste quadro, onde a saída roda
    /// (e pode bloquear) e de onde o fim do intervalo segue para o nível de
    /// fora. O segmento do callback fica para o ceifador
    /// ([`release_abandoned`]).
    pub fn abandon_callback(&self) {
        self.install(self.outer);
    }
}

/// O que um KeUserModeCallback em curso alocou: a pilha do callback, o
/// quadro do callout e o CONTEXT do callback.
struct ActiveCallout {
    thread: u64,
    stack: kernel_stack::KernelStack,
    callout: u64,
    context: u64,
}

/// Os KeUserModeCallback em curso de todas as threads. Uma thread terminada
/// sai dentro do callback (a APC de término é entregue na volta ao anel 3
/// dele, como no KiCallUserMode do NT) e nunca volta ao KeUserModeCallback
/// que alocou: o ceifador devolve o que ficou ([`release_abandoned`]).
static ACTIVE: SpinLock<Vec<ActiveCallout>> = SpinLock::new(Vec::new());

/// Tira do registro o callback mais interno de `thread` com a pilha `base`.
fn retire(thread: u64, base: u64) {
    let mut active = ACTIVE.lock();
    if let Some(index) = active.iter().rposition(|entry| entry.thread == thread && entry.stack.base == base) {
        active.remove(index);
    }
}

/// O ceifador de uma thread que saiu dentro de callbacks de modo usuário:
/// devolve as pilhas, os quadros e os CONTEXTs dos KeUserModeCallback que
/// nunca voltaram e zera o aninhamento. Chamado depois que a thread deixou a
/// CPU (uma pilha em uso fica para o `kernel_stack::reap`).
pub fn release_abandoned(thread: u64) {
    let abandoned: Vec<ActiveCallout> = {
        let mut active = ACTIVE.lock();
        let (mine, others): (Vec<ActiveCallout>, Vec<ActiveCallout>) = active.drain(..).partition(|entry| entry.thread == thread);
        *active = others;
        mine
    };
    if abandoned.is_empty() {
        return;
    }
    for entry in abandoned {
        kernel_stack::delete(entry.stack);
        guest::free_bytes(entry.callout);
        guest::free_bytes(entry.context);
    }
    // SAFETY: a KTHREAD ainda está viva (o ceifador roda antes do fim dela).
    unsafe { Kthread::at(thread) }.callback_nesting_level.set(0);
}

/// O fim de um KeUserModeCallback: desfaz o aninhamento e devolve a pilha
/// do callback ao Mm.
fn release(thread: &Kthread, stack: Option<kernel_stack::KernelStack>, status: u32) -> u32 {
    thread.callback_nesting_level.set(thread.callback_nesting_level.get().wrapping_sub(1));
    if let Some(stack) = stack {
        kernel_stack::delete(stack);
    }
    status
}

/// Quantas recusas do próprio KeUserModeCallback (sem o callback rodar) a
/// serial ainda mostra.
static REFUSALS_SHOWN: AtomicU32 = AtomicU32::new(0);
const REFUSALS_LIMIT: u32 = 32;

/// Diagnóstico: o KeUserModeCallback devolve `status` sem entrar no anel 3
/// (fora de um serviço, aninhamento esgotado, sem memória, sonda ou cópia da
/// pilha do usuário recusada, sem despachante). O chamador do win32k só vê o
/// status; a linha mostra a rotina da tabela e onde estava a pilha.
fn refusal(api_number: u32, status: u32, user_rsp: u64, nesting: u8) -> u32 {
    if REFUSALS_SHOWN.fetch_add(1, Ordering::Relaxed) < REFUSALS_LIMIT {
        crate::debug_print!(
            "[callback] {}:{} KeUserModeCallback(api {:#x}) recusado com {:#x} (aninhamento {}, rsp do usuario {:#x})",
            process::get_current_process_id(),
            process::get_current_thread_id(),
            api_number,
            status,
            nesting,
            user_rsp
        );
    }
    status
}

/// Sonda de escrita da faixa do usuário (o ProbeForWrite do NT, que lê e
/// regrava um byte de cada página).
fn probe_for_write(start: u64, length: u64) -> bool {
    let Some(last) = start.checked_add(length - 1) else { return false };
    if last >= USER_PROBE_ADDRESS {
        return false;
    }
    let mut page = start;
    loop {
        match guest::try_read::<u8>(page) {
            Ok(value) if guest::try_write::<u8>(page, value).is_ok() => {}
            _ => return false,
        }
        page = (page & !(PAGE - 1)) + PAGE;
        if page > last {
            return true;
        }
    }
}

/// O CONTEXT em que o callback entra no anel 3: o da syscall, com os
/// registradores que o KiCallUserMode carrega.
fn prepare_context(callback: u64, syscall: &Context, dispatcher: u64, user_stack: u64) {
    guest::write_bytes(callback, &guest::read_bytes(syscall.address(), Context::SIZE as usize));
    // SAFETY: bloco do kernel recém-copiado, do tamanho do CONTEXT.
    let context = unsafe { Context::at(callback) };
    let eflags = syscall.e_flags.get();
    let rbp = syscall.rbp.get();
    for register in [&context.rax, &context.rbx, &context.rdx, &context.rsi, &context.rdi, &context.r10, &context.r12, &context.r13, &context.r14, &context.r15] {
        register.set(0);
    }
    context.rcx.set(dispatcher);
    context.r11.set(eflags as u64);
    context.r8.set(user_stack);
    context.r9.set(rbp);
    context.rbp.set(rbp);
    context.rsp.set(user_stack);
    context.rip.set(dispatcher);
    context.e_flags.set(eflags);
    context.seg_cs.set(USER_CODE);
    context.seg_ss.set(USER_DATA);
    // XMM0-XMM15 zerados; o MXCSR e o estado x87 são os da syscall.
    let xmm = context.flt_save.xmm_registers[0].address();
    guest::write_bytes(xmm, &[0u8; 16 * 16]);
}

/// KeUserModeCallback(ApiNumber, InputBuffer, InputLength, OutputBuffer,
/// OutputLength). Só uma thread de usuário dentro de uma syscall despachada
/// tem para onde voltar ao anel 3 (no NT, o KTRAP_FRAME de usuário da
/// thread); fora disso, STATUS_NOT_SUPPORTED.
pub fn user_mode_callback(api_number: u32, input: u64, input_length: u32, output_buffer: u64, output_length: u64) -> Result<u32, KernelError> {
    let pointer = process::get_current_thread();
    // SAFETY: a KTHREAD corrente está viva enquanto executa.
    let thread = unsafe { Kthread::at(pointer) };
    if thread.misc_flags.get() as u32 & CALLOUT_ACTIVE != 0 {
        bugcheck::bug_check_ex(KERNEL_EXPAND_STACK_ACTIVE, pointer, 0, 0, 0);
    }
    let level = irql::get_irql();
    if level != irql::PASSIVE_LEVEL {
        bugcheck::bug_check_ex(IRQL_GT_ZERO_AT_SYSTEM_SERVICE, 0, level as u64, 0, 0);
    }
    let (index, disable) = (thread.apc_state_index.get(), thread.combined_apc_disable.get());
    if index != 0 || disable != 0 {
        bugcheck::bug_check_ex(APC_INDEX_MISMATCH, 0, index as u64, disable as u64, 0);
    }
    let user = threads::current().filter(|user| user.pointer() == pointer);
    let syscall_context = usermode::block().context.get();
    let Some(user) = user.filter(|_| usermode::in_service() && syscall_context != 0) else {
        return Ok(refusal(api_number, STATUS_NOT_SUPPORTED, 0, thread.callback_nesting_level.get()));
    };
    let nesting = thread.callback_nesting_level.get().wrapping_add(1);
    thread.callback_nesting_level.set(nesting);
    if nesting > MAXIMUM_NESTING {
        return Ok(refusal(api_number, release(thread, None, STATUS_STACK_OVERFLOW), 0, nesting));
    }
    let Ok(stack) = kernel_stack::create(false) else { return Ok(refusal(api_number, release(thread, None, STATUS_NO_MEMORY), 0, nesting)) };
    // SAFETY: o KERNEL_STACK_CONTROL da pilha recém-criada.
    let control = unsafe { KernelStackControl::at(stack.initial) };
    control.current_stack_base.set(stack.base);
    control.actual_limit.set(stack.base - kernel_stack::KERNEL_STACK_SIZE);
    control.previous.stack_base.set(thread.stack_base.get());
    control.previous.stack_limit.set(thread.stack_limit.get());
    control.previous.initial_stack.set(thread.initial_stack.get());

    // O frame do callout e a cópia da entrada na pilha do usuário.
    // SAFETY: o CONTEXT do intervalo em curso (memória do kernel).
    let syscall = unsafe { Context::at(syscall_context) };
    let user_rsp = syscall.rsp.get();
    let size = ((input_length as u64 + 15) & !15) + UcalloutFrame::SIZE;
    let frame = user_rsp.wrapping_sub(size) & !15;
    if !probe_for_write(frame, size) {
        return Ok(refusal(api_number, release(thread, Some(stack), STATUS_ACCESS_VIOLATION), user_rsp, nesting));
    }
    let copied = guest::try_write_bytes(frame + UcalloutFrame::SIZE, &guest::read_bytes(input, input_length as usize));
    // SAFETY: faixa do usuário sondada para escrita acima.
    let ucallout = unsafe { UcalloutFrame::at(frame) };
    let written = copied.is_ok()
        && ucallout.buffer.probe_set(frame + UcalloutFrame::SIZE).is_ok()
        && ucallout.length.probe_set(input_length).is_ok()
        && ucallout.api_number.probe_set(api_number).is_ok()
        && ucallout.machine_rsp.probe_set(user_rsp).is_ok()
        && ucallout.machine_rip.probe_set(syscall.rip.get()).is_ok();
    if !written {
        return Ok(refusal(api_number, release(thread, Some(stack), STATUS_ACCESS_VIOLATION), user_rsp, nesting));
    }
    let dispatcher = DISPATCHER.load(Ordering::Acquire);
    let callout = guest::alloc_bytes(CalloutFrame::SIZE);
    let callback_context = guest::alloc_bytes(Context::SIZE);
    if dispatcher == 0 || callout == 0 || callback_context == 0 {
        for block in [callout, callback_context] {
            if block != 0 {
                guest::free_bytes(block);
            }
        }
        return Ok(refusal(api_number, release(thread, Some(stack), if dispatcher == 0 { STATUS_NOT_SUPPORTED } else { STATUS_NO_MEMORY }), user_rsp, nesting));
    }
    // SAFETY: bloco recém-alocado do tamanho do quadro.
    let frame_cells = unsafe { CalloutFrame::at(callout) };
    frame_cells.output_buffer.set(output_buffer);
    frame_cells.output_length.set(output_length);
    frame_cells.status.set(0);
    frame_cells.returned.set(0);
    prepare_context(callback_context, syscall, dispatcher, frame);

    // KiCallUserMode: a thread passa para a pilha do callback.
    control.previous.kernel_stack.set(callout);
    let stacks = CalloutStacks { thread: pointer, outer: (thread.initial_stack.get(), thread.stack_base.get(), thread.stack_limit.get()), callback: (stack.initial, stack.base, stack.limit) };
    ACTIVE.lock().push(ActiveCallout { thread: pointer, stack, callout, context: callback_context });
    stacks.install(stacks.callback);
    let exit = threads::run_callback(&user, callback_context, &|| frame_cells.returned.get() != 0, &stacks);
    // A volta do NtCallbackReturn: a pilha anterior.
    stacks.install(stacks.outer);
    retire(pointer, stack.base);
    let status = if exit == 0 { frame_cells.status.get() } else { exit };
    flush_gdi_batch(syscall);
    guest::free_bytes(callout);
    guest::free_bytes(callback_context);
    Ok(release(thread, Some(stack), status))
}

/// O lote GDI que o callback deixou na TEB: o callout do win32k o esvazia,
/// com o RSP do usuário 0x100 abaixo enquanto roda.
fn flush_gdi_batch(syscall: &Context) {
    if !win32::gdi_batch_pending() {
        return;
    }
    let rsp = syscall.rsp.get();
    syscall.rsp.set(rsp - GDI_BATCH_STACK);
    win32::flush_gdi_batch();
    syscall.rsp.set(rsp);
}

/// NtCallbackReturn(OutputBuffer, OutputLength, Status): o quadro do
/// callout vem do KERNEL_STACK_CONTROL da InitialStack corrente
/// (Previous.KernelStack); sem callback ativo, STATUS_NO_CALLBACK_ACTIVE, e
/// um endereço que não é do kernel é o bugcheck 0x1CD. O ponteiro e o
/// tamanho vão para as variáveis do KeUserModeCallback, o status para o
/// quadro, e o laço do callback encerra quando o serviço termina.
pub fn callback_return(output_buffer: u64, output_length: u32, status: u32) -> u32 {
    let pointer = process::get_current_thread();
    // SAFETY: a KTHREAD corrente está viva enquanto executa.
    let thread = unsafe { Kthread::at(pointer) };
    let initial = thread.initial_stack.get();
    // Uma thread na pilha de boot nunca está num callback (o
    // KeUserModeCallback sempre instala uma pilha da janela das pilhas).
    if !memory_map::is_kernel_stack(initial) {
        return STATUS_NO_CALLBACK_ACTIVE;
    }
    // SAFETY: o KERNEL_STACK_CONTROL da pilha de kernel corrente da thread.
    let frame = unsafe { KernelStackControl::at(initial) }.previous.kernel_stack.get();
    if frame == 0 {
        return STATUS_NO_CALLBACK_ACTIVE;
    }
    if (frame as i64) > 0 {
        bugcheck::bug_check_ex(INVALID_CALLBACK_STACK_ADDRESS, pointer, frame, 0, 0);
    }
    // SAFETY: o quadro do callout vivo do KeUserModeCallback que espera.
    let callout = unsafe { CalloutFrame::at(frame) };
    // SAFETY: as variáveis de saída do chamador de kernel do callback.
    unsafe {
        Field::<u64>::at(callout.output_buffer.get()).set(output_buffer);
        Field::<u32>::at(callout.output_length.get()).set(output_length);
    }
    callout.status.set(status);
    callout.returned.set(1);
    0
}

fn nt_callback_return(output_buffer: u64, output_length: u64, status: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(callback_return(output_buffer, output_length as u32, status as u32))
}

/// Registra o serviço NtCallbackReturn.
pub fn init() {
    state::register_handler("NtCallbackReturn", nt_callback_return);
}
