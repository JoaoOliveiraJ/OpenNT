//! Ponte para código nativo e células nativas do kernel.
//!
//! O NonPagedPoolLock (célula dentro da imagem do kernel, que a PCR publica)
//! e o gateway das chamadas MS-ABI (`exec_msabi_n`) para rotinas nativas.

use core::sync::atomic::AtomicU64;

/// NonPagedPoolLock: lock de 8 bytes na seção de dados da imagem, alinhado em
/// 16. Os bytes seguintes ficam reservados e zerados (vizinhos como flags e
/// ponteiros nulos), e drivers que acham estruturas do kernel a partir do
/// lock (o vgk lê e grava a partir de `lock+8`) não podem cair em outras
/// variáveis do kernel.
#[repr(C, align(16))]
struct PoolLockCell {
    lock: AtomicU64,
    _reserved: [u64; 31],
}
static NON_PAGED_POOL_LOCK: PoolLockCell = PoolLockCell { lock: AtomicU64::new(0), _reserved: [0; 31] };

pub fn non_paged_pool_lock_address() -> u64 {
    &NON_PAGED_POOL_LOCK.lock as *const AtomicU64 as u64
}

// ---- chamadas MS-ABI (exec_msabi_n) ---------------------------------------
//
// O gateway roda na VA de sistema da imagem do kernel: o CALL empilha um
// endereço de retorno dentro do ntoskrnl, como num chamador nativo real.

core::arch::global_asm!(
    r#"
.pushsection .text.native_gateway, "ax", @progbits
.global exec_msabi_n
exec_msabi_n:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    mov r12, rdi                    # rotina
    mov rbx, rsi                    # argumentos (pelo menos 4 qwords)
    mov r13, rdx                    # quantidade
    mov r14, r13
    sub r14, 4
    jae 2f
    xor r14d, r14d                  # argumentos na pilha = max(0, n - 4)
2:
    lea rax, [r14*8 + 32 + 15]
    and rax, -16
    sub rsp, rax
    and rsp, -16                    # ABI MS x64: RSP alinhado no CALL
    xor ecx, ecx
3:
    cmp rcx, r14
    jae 4f
    mov rax, qword ptr [rbx + rcx*8 + 32]
    mov qword ptr [rsp + rcx*8 + 32], rax
    inc rcx
    jmp 3b
4:
    mov rcx, qword ptr [rbx]
    mov rdx, qword ptr [rbx + 8]
    mov r8, qword ptr [rbx + 16]
    mov r9, qword ptr [rbx + 24]
    call r12
    lea rsp, [rbp - 32]
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.popsection
"#
);

extern "C" {
    fn exec_msabi_n(routine: u64, arguments: *const u64, count: u64) -> u64;
}

pub const MAX_NATIVE_ARGUMENTS: usize = 20;

/// Chama `routine` na ABI MS x64 com os argumentos inteiros dados e devolve
/// RAX.
pub fn call(routine: u64, arguments: &[u64]) -> u64 {
    assert!(arguments.len() <= MAX_NATIVE_ARGUMENTS, "too many native arguments");
    let mut padded = [0u64; MAX_NATIVE_ARGUMENTS];
    padded[..arguments.len()].copy_from_slice(arguments);
    // A posse anterior é guardada para chamadas aninhadas.
    let previous = set_sync_active(1);
    // SAFETY: o gateway preserva os registradores do chamador SysV e copia
    // os argumentos (pelo menos quatro qwords em `padded`).
    let result = unsafe { exec_msabi_n(routine, padded.as_ptr(), arguments.len().max(4) as u64) };
    set_sync_active(previous);
    result
}

// ---- as chamadas nativas em curso da CPU -----------------------------------
//
// Duas células por CPU, na reserva da KPCR (`pcr::layout::NATIVE_FRAME` e
// `NATIVE_OWNER`, endereçadas por `gs:` nos trampolins): o contexto nativo
// agendado que a CPU executa (`win32_thunk::run_kernel_context`; o RSP do
// hospedeiro para onde a saída volta fica no próprio quadro, não aqui) e a
// posse de execução nativa síncrona (só faltas numa execução nativa possuída
// entram no SEH de kernel). São da thread corrente: a troca de thread leva as
// da que sai e recoloca as da que entra (`NativeState`), então duas threads
// que se intercalam dentro de chamadas nativas, ou duas CPUs ao mesmo tempo,
// nunca veem o estado uma da outra. Antes da KPCR do BSP só ele executa, e a
// posse fica numa célula de partida que a KPCR herda.

use crate::ntos::ke::pcr;

/// A posse do processador de boot antes da KPCR dele.
static BOOT_OWNER: AtomicU64 = AtomicU64::new(0);

core::arch::global_asm!(
    r#"
.pushsection .data.kernel_native, "aw", @progbits
# Nao zero quando o GS de todo processador que executa o kernel e a KPCR
# dele: os trampolins de excecao so tocam as celulas `gs:` depois disso.
.global opennt_native_cells_ready
opennt_native_cells_ready: .byte 0
.popsection
"#
);

extern "C" {
    static mut opennt_native_cells_ready: u8;
}

fn cells_ready() -> bool {
    pcr::get_pcr_address() != 0
}

fn read_cell(offset: u64) -> u64 {
    let value: u64;
    // SAFETY: célula da reserva da KPCR desta CPU, publicada (`cells_ready`).
    unsafe { core::arch::asm!("mov {}, gs:[{}]", out(reg) value, in(reg) offset, options(nostack, readonly, preserves_flags)) };
    value
}

fn write_cell(offset: u64, value: u64) {
    // SAFETY: célula da reserva da KPCR desta CPU, publicada (`cells_ready`).
    unsafe { core::arch::asm!("mov gs:[{}], {}", in(reg) offset, in(reg) value, options(nostack, preserves_flags)) };
}

/// A KPCR do BSP acaba de ser publicada no GS: a posse de partida passa para
/// a célula dela, e os trampolins passam a usar as células `gs:` (os APs
/// carregam o GS antes de executar qualquer coisa).
pub fn publish_processor_cells() {
    write_cell(pcr::layout::NATIVE_FRAME, 0);
    write_cell(pcr::layout::NATIVE_OWNER, BOOT_OWNER.load(core::sync::atomic::Ordering::Relaxed));
    // SAFETY: byte da imagem lido pelos trampolins; um store simples.
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(opennt_native_cells_ready), 1) };
}

/// As chamadas nativas em curso da thread corrente, como a troca de thread
/// as leva e recoloca.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeState {
    /// O contexto nativo agendado em execução (0 = nenhum).
    pub frame: u64,
    /// A posse de execução nativa síncrona.
    pub owner: u64,
}

/// O estado das chamadas nativas da CPU agora.
pub fn state() -> NativeState {
    if !cells_ready() {
        return NativeState { frame: 0, owner: BOOT_OWNER.load(core::sync::atomic::Ordering::Relaxed) };
    }
    NativeState { frame: read_cell(pcr::layout::NATIVE_FRAME), owner: read_cell(pcr::layout::NATIVE_OWNER) }
}

/// Recoloca o estado das chamadas nativas de quem volta a executar.
pub fn restore_state(state: NativeState) {
    if !cells_ready() {
        BOOT_OWNER.store(state.owner, core::sync::atomic::Ordering::Relaxed);
        return;
    }
    write_cell(pcr::layout::NATIVE_FRAME, state.frame);
    write_cell(pcr::layout::NATIVE_OWNER, state.owner);
}

/// O contexto nativo agendado que a CPU executa agora (0 = nenhum).
pub fn scheduled_frame() -> u64 {
    state().frame
}

/// A posse de execução nativa síncrona da CPU agora.
pub fn sync_active() -> u64 {
    state().owner
}

/// Troca a posse de execução nativa síncrona e devolve a anterior: só
/// faltas numa execução nativa possuída entram no SEH de kernel.
pub fn set_sync_active(value: u64) -> u64 {
    if !cells_ready() {
        return BOOT_OWNER.swap(value, core::sync::atomic::Ordering::Relaxed);
    }
    let previous = read_cell(pcr::layout::NATIVE_OWNER);
    write_cell(pcr::layout::NATIVE_OWNER, value);
    previous
}
