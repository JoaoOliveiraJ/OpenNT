//! Autoteste da metade de usuário do espaço de endereços.
//!
//! Depois do boot nada do kernel fica em PML4[0..256), como no NT: percorre
//! as tabelas reais dessa metade e não acha folha de supervisor; o que existe
//! ali é de usuário (a visão somente leitura da KUSER_SHARED_DATA em
//! 0x7FFE0000 e as imagens, pilhas e seções dos processos). Nenhuma estrutura
//! do kernel tem identidade baixa: nem a imagem, nem a pilha de boot, nem o
//! trampolim dos APs, nem o heap, nem as tabelas de páginas. Roda no fim das
//! fases 6 e 7, depois dos drivers reais e dos programas de usuário.

use crate::hal::amd64::usermode;
use crate::ntos::mm::memory_map as map;
use crate::ntos::mm::{paging, user_half};
use crate::ntos::ps::user::state::KUSER_SHARED_DATA_USER_VA;

type Assert = fn(bool, &str);

pub fn run(assert: Assert) {
    let leftover = user_half::supervisor_mappings(8);
    for &(address, size) in &leftover {
        debug_print!("[userhalf] folha de supervisor na metade de usuario: {:#x} (+{:#x})", address, size);
    }
    assert(leftover.is_empty(), "userhalf: nenhuma folha de supervisor em PML4[0..256)");

    let kernel_frames = [
        map::KERNEL_IMAGE_PHYS,
        map::KERNEL_IMAGE_PHYS + 0x1000,
        map::BOOT_STACK_PHYS_BASE,
        map::AP_TRAMPOLINE_PHYS,
        map::SMP_MAILBOX_PHYS,
        map::PML4_PHYS,
        map::KERNEL_HEAP_PHYS_BASE,
    ];
    assert(kernel_frames.iter().all(|&frame| paging::translate(frame) == 0), "userhalf: estruturas do kernel sem identidade baixa");

    if usermode::ready() {
        let access = paging::access_flags(KUSER_SHARED_DATA_USER_VA);
        assert(
            access & (paging::PAGE_PRESENT | paging::PAGE_USER | paging::PAGE_RW) == paging::PAGE_PRESENT | paging::PAGE_USER,
            "userhalf: KUSER_SHARED_DATA de usuario em 0x7FFE0000, somente leitura",
        );
    }
}
