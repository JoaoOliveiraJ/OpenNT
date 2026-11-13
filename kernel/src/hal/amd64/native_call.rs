//! Ponte para código nativo e células nativas do kernel.
//!
//! Nesta fase: o NonPagedPoolLock (célula dentro da imagem do kernel, cujo
//! alias virtual a PCR publica) e o registro do mapeamento permanente da
//! imagem em KERNEL_VIRTUAL_BASE. As chamadas MS-ABI (`exec_msabi*`) entram
//! com o loader PE (fase 6).

use core::sync::atomic::{AtomicU64, Ordering};

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

static PUBLISHED_PHYSICAL_BASE: AtomicU64 = AtomicU64::new(0);
static PUBLISHED_VIRTUAL_BASE: AtomicU64 = AtomicU64::new(0);
static PUBLISHED_IMAGE_SIZE: AtomicU64 = AtomicU64::new(0);

/// O loader publica uma única imagem permanente, depois de mapear suas
/// páginas. Tamanho zero identifica o boot anterior à publicação.
pub fn publish_native_kernel_mapping(physical_base: u64, virtual_base: u64, image_size: u64) -> bool {
    if image_size == 0
        || (physical_base | virtual_base | image_size) & 0xFFF != 0
        || virtual_base < 0xFFFF_8000_0000_0000
        || image_size > u64::MAX - physical_base
        || image_size > u64::MAX - virtual_base
    {
        return false;
    }
    let published = PUBLISHED_IMAGE_SIZE.load(Ordering::Acquire);
    if published != 0 {
        return physical_base == PUBLISHED_PHYSICAL_BASE.load(Ordering::Relaxed)
            && virtual_base == PUBLISHED_VIRTUAL_BASE.load(Ordering::Relaxed)
            && image_size == published;
    }
    PUBLISHED_PHYSICAL_BASE.store(physical_base, Ordering::Relaxed);
    PUBLISHED_VIRTUAL_BASE.store(virtual_base, Ordering::Relaxed);
    // Publicar o tamanho por último torna as bases visíveis antes.
    PUBLISHED_IMAGE_SIZE.store(image_size, Ordering::Release);
    true
}

/// Endereço de uma rotina do kernel no alias publicado (ou o de boot).
pub fn native_gateway_address(physical_entry: u64) -> u64 {
    if PUBLISHED_IMAGE_SIZE.load(Ordering::Acquire) == 0 {
        return physical_entry;
    }
    PUBLISHED_VIRTUAL_BASE.load(Ordering::Relaxed) + physical_entry - PUBLISHED_PHYSICAL_BASE.load(Ordering::Relaxed)
}

// ---- chamadas MS-ABI (exec_msabi_n) ---------------------------------------
//
// O gateway é independente de posição e roda no alias publicado da imagem:
// o CALL empilha um endereço de retorno dentro da VA real do kernel.
// A imagem inteira está mapeada nos dois endereços, então referências
// relativas caem no alias e absolutas no identity map — ambos válidos.
// A posse de traps para SEH de código nativo entra com o loader PE (fase 6).

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
    let gateway = native_gateway_address(exec_msabi_n as *const () as usize as u64);
    let gateway: extern "C" fn(u64, *const u64, u64) -> u64 = unsafe { core::mem::transmute(gateway as usize) };
    // A posse anterior é guardada para chamadas aninhadas.
    let previous = set_sync_active(1);
    let result = gateway(routine, padded.as_ptr(), arguments.len().max(4) as u64);
    set_sync_active(previous);
    result
}

extern "C" {
    static mut opennt_kernel_sync_active: u64;
}

/// Troca a posse de execução nativa síncrona e devolve a anterior: só
/// faltas numa execução nativa possuída entram no SEH de kernel.
pub fn set_sync_active(value: u64) -> u64 {
    unsafe {
        let cell = core::ptr::addr_of_mut!(opennt_kernel_sync_active);
        let previous = core::ptr::read_volatile(cell);
        core::ptr::write_volatile(cell, value);
        previous
    }
}
