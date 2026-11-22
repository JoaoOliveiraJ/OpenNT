//! A thread WoW64: as duas pilhas, a área de CPU e o contexto x86 inicial.
//!
//! O PspAllocateThread do 19041 (0x6c4470) dá a toda thread de um processo
//! WoW64:
//!
//! - a pilha de 64 bits do PspSetupUserStack com tamanhos fixos (reserva de
//!   256 KB, commit de 32 KB), da camada WoW64, e no topo dela a área de CPU
//!   ([`setup_cpu_area`], o PspWow64SetupCpuArea 0x67a0a8): o StackBase
//!   desce para abrir o WOW64_CPURESERVED (Flags e Machine) seguido do
//!   contexto x86 (0x2CC bytes, alinhamento 4), e o novo StackBase,
//!   alinhado a 16, é o começo da área;
//! - a pilha de 32 bits ([`create_user_stack`], o RtlpWow64CreateUserStack
//!   0x692b5c do PspWow64SetupUserStack): sem tamanhos pedidos, o
//!   SizeOfStackCommit e o SizeOfStackReserve do cabeçalho PE32 da imagem;
//!   a reserva inteira pelo ProcessThreadStackAllocation, o commit no topo
//!   e, com espaço, duas páginas de guarda embaixo;
//! - a TEB de 64 bits e a de 32 bits (`mm/peb_teb.rs`);
//! - o [`init_thread`] (o PspWow64InitThread 0x679dc0, anexado ao processo):
//!   TEB.TlsSlots[WOW64_TLS_CPURESERVED] aponta para a área de CPU, Machine
//!   = IMAGE_FILE_MACHINE_I386, e o contexto x86 do
//!   PspWow64InitThreadGuestx86 (0x679fac): EIP no RtlUserThreadStart de 32
//!   bits quando a thread nativa começa no RtlUserThreadStart nativo
//!   (PspUserThreadStart), EAX = a rotina (o RCX do contexto nativo), EBX =
//!   o argumento (o RDX), ESP = o topo da pilha de 32 bits menos um sorteio
//!   de até 0x7FC bytes (sem ele com StackRandomizationDisabled) e menos
//!   0x10, CS 0x23, DS/ES/GS/SS 0x2B, FS 0x53, a palavra de controle do x87
//!   0x27F (também no FXSAVE), TagWord 0xFFFF, MXCSR 0x1F80 e ContextFlags
//!   CONTEXT_i386 | CONTEXT_ALL (0x1003F).
//!
//! O wow64.dll lê esse contexto na primeira entrada da thread (o
//! Wow64LdrpInitialize, chamado pela ntdll nativa porque a TEB tem
//! WowTebOffset) e o wow64cpu o carrega no código de 32 bits.

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_wow64::{Wow64Context, Wow64CpuReserved};
use crate::ntos::inc::types::{Eprocess, Teb};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user::memory::{self, UserStack};
use crate::rtl::KernelError;

use super::{MACHINE_I386, TLS_CPURESERVED};

/// Os tamanhos fixos da pilha de 64 bits de uma thread WoW64.
pub const NATIVE_STACK_COMMIT: u64 = 0x8000;
pub const NATIVE_STACK_RESERVE: u64 = 0x4_0000;
/// O alinhamento do contexto x86 (RtlpGetLegacyContextLength).
const CONTEXT_ALIGNMENT: u64 = 4;
/// CONTEXT_i386 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS |
/// CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS |
/// CONTEXT_EXTENDED_REGISTERS.
const CONTEXT_FLAGS: u32 = 0x1003F;
/// As palavras de controle iniciais do x87 e do SSE no x86.
const X87_CONTROL_WORD: u32 = 0x27F;
const MX_CSR: u32 = 0x1F80;

/// O PspWow64SetupCpuArea: o StackBase novo, abaixo da área de CPU aberta no
/// topo da pilha de 64 bits (o começo da área).
pub fn setup_cpu_area(stack_base: u64) -> u64 {
    let mut top = (stack_base - 4) & !3;
    top = (top - 5) & !7;
    top -= Wow64Context::SIZE;
    top &= !(CONTEXT_ALIGNMENT - 1);
    top = (top - 4) & !0xF;
    top
}

/// O RtlpWow64CreateUserStack no processo corrente: a pilha de 32 bits com
/// `commit` e `reserve` (zero: os do cabeçalho PE32 da imagem principal) e o
/// limite exclusivo `highest` do ZeroBits pedido (0: o do processo); a da
/// primeira thread fica residente (`pageable` falso), como a de 64 bits.
pub fn create_user_stack(commit: u64, reserve: u64, highest: u64, pageable: bool) -> Result<UserStack, u32> {
    // O tamanho que falta sai do cabeçalho; o pedido fica no outro.
    let (commit, reserve) = if commit == 0 || reserve == 0 {
        let (image_commit, image_reserve) = image_stack_sizes()?;
        (if commit != 0 { commit } else { image_commit }, if reserve != 0 { reserve } else { image_reserve })
    } else {
        (commit, reserve)
    };
    memory::create_wow64_user_stack(commit, reserve, highest, pageable)
}

/// SizeOfStackCommit e SizeOfStackReserve do cabeçalho PE32 da imagem do
/// processo corrente (EPROCESS.SectionBaseAddress), lidos sondados; sem
/// cabeçalho, STATUS_INVALID_IMAGE_FORMAT.
fn image_stack_sizes() -> Result<(u64, u64), u32> {
    // SAFETY: o EPROCESS corrente.
    let base = unsafe { Eprocess::at(crate::ntos::ps::process::get_current_process()) }.section_base_address.get();
    let read = |address: u64| guest::try_read::<u32>(address).map_err(|_| 0xC000_007Bu32);
    let headers = base + read(base + 0x3C)? as u64;
    if read(headers)? != 0x4550 {
        return Err(0xC000_007B);
    }
    // IMAGE_OPTIONAL_HEADER32: SizeOfStackReserve em +0x48 e
    // SizeOfStackCommit em +0x4C (o cabeçalho opcional em +0x18).
    Ok((read(headers + 0x18 + 0x4C)? as u64, read(headers + 0x18 + 0x48)? as u64))
}

/// O que o PspWow64InitThread recebe do PspAllocateThread.
pub struct InitialThread {
    /// A TEB de 64 bits.
    pub teb: u64,
    /// O começo da área de CPU (o StackBase da pilha de 64 bits).
    pub cpu_area: u64,
    /// O RIP, o RCX e o RDX do contexto nativo inicial.
    pub native_start: u64,
    pub start_routine: u64,
    pub argument: u64,
    /// O topo da pilha de 32 bits.
    pub stack_base32: u64,
}

/// O PspWow64InitThread no processo corrente (anexado): a área de CPU na
/// TEB e o contexto x86 inicial.
pub fn init_thread(thread: &InitialThread, ntdll32: &super::system_dll::Wow64Ntdll, randomize: bool) -> Result<(), KernelError> {
    // SAFETY: a TEB e a área de CPU acabaram de ser comprometidas no processo
    // corrente; a thread ainda não roda.
    let teb = unsafe { Teb::at(thread.teb) };
    teb.tls_slots[TLS_CPURESERVED].set(thread.cpu_area);
    let reserved = unsafe { Wow64CpuReserved::at(thread.cpu_area) };
    reserved.flags.set(0);
    reserved.machine.set(MACHINE_I386);
    let context_address = (thread.cpu_area + Wow64CpuReserved::CONTEXT_OFFSET + CONTEXT_ALIGNMENT - 1) & !(CONTEXT_ALIGNMENT - 1);
    guest::write_bytes(context_address, &[0; Wow64Context::SIZE as usize]);
    // SAFETY: o contexto x86 dentro da área de CPU.
    let context = unsafe { Wow64Context::at(context_address) };
    // A thread nativa que começa no RtlUserThreadStart nativo começa no de
    // 32 bits; outra rotina inicial é a própria EIP.
    let native_start = crate::ntos::ps::user::state::with(|state| state.ntdll_exports.as_ref().and_then(|exports| exports.get("RtlUserThreadStart").copied()).unwrap_or(0));
    let eip = if thread.native_start == native_start { ntdll32.shared_information[super::system_dll::SHARED_RTL_USER_THREAD_START] } else { thread.native_start };
    let random = if randomize { (super::random() & 0x1FF) << 2 } else { 0 };
    let esp = (thread.stack_base32 as u32).wrapping_sub(random).wrapping_sub(0x10);
    context.eip.set(eip as u32);
    context.eax.set(thread.start_routine as u32);
    context.ebx.set(thread.argument as u32);
    context.esp.set(esp);
    for segment in [&context.seg_gs, &context.seg_es, &context.seg_ds, &context.seg_ss] {
        segment.set(crate::hal::amd64::usermode::USER_DS as u32);
    }
    context.seg_fs.set(crate::hal::amd64::usermode::USER_COMPAT_FS as u32);
    context.seg_cs.set(crate::hal::amd64::usermode::USER_COMPAT_CS as u32);
    context.float_save.control_word.set(X87_CONTROL_WORD);
    context.float_save.tag_word.set(0xFFFF);
    let extended = context.extended_registers.as_ptr() as u64;
    guest::write_bytes(extended + Wow64Context::EXTENDED_CONTROL_WORD as u64, &(X87_CONTROL_WORD as u16).to_le_bytes());
    guest::write32(extended + Wow64Context::EXTENDED_MX_CSR as u64, MX_CSR);
    context.context_flags.set(CONTEXT_FLAGS);
    Ok(())
}

/// A pilha de 32 bits não é sorteada com StackRandomizationDisabled
/// (EPROCESS.MitigationFlags bit 6).
pub fn stack_randomization(process: u64) -> bool {
    // SAFETY: o EPROCESS do processo em montagem.
    unsafe { Eprocess::at(process) }.mitigation_flags_values.stack_randomization_disabled() == 0
}
