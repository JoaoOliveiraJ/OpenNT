//! Auditoria do mapa direto e da janela do heap (`--identity-audit`,
//! desligada no build normal).
//!
//! Depois que os APs sobem, desliga o PRESENT da identidade baixa sobre tudo
//! o que só deveria ser alcançado por endereço físico ou pela janela do heap:
//! o primeiro MB (menos a página de código do trampolim dos APs), a faixa
//! sem uso de 16 MB a 32 MB, os frames do heap do kernel e da arena dos
//! convidados (32 MB a 96 MB), as arenas do PFN, o resto da RAM acima delas e
//! o MMIO acima de 3 GB. Um acesso que ainda use um endereço físico como
//! ponteiro, ou um ponteiro de identidade para o heap ou para a arena, nessas
//! faixas falta no anel 0 e para o sistema com o diagnóstico. A imagem do
//! kernel, a pilha de boot e a janela do VirtualAlloc de kernel continuam
//! mapeadas: ainda são endereçadas como VAs de identidade.

use super::paging;
use crate::hal::{cpu, physical};
use crate::ntos::ke::smp;

/// Desliga o PRESENT da folha de identidade (`va == pa`) do tamanho dado.
fn clear_present(va: u64, expected_size: u64) -> bool {
    let Some(page) = paging::query_page(va, false) else { return false };
    if page.page_size != expected_size || page.physical_address != va {
        return false;
    }
    let entry = physical::read64(page.entry_address);
    physical::write64(page.entry_address, entry & !paging::PAGE_PRESENT);
    true
}

pub fn run() {
    let mut small = 0;
    let mut large = 0;
    if paging::split_large_page(0, false) {
        for page in (0..0x10_0000u64).step_by(0x1000) {
            if page != super::memory_map::AP_TRAMPOLINE_PHYS && clear_present(page, 0x1000) {
                small += 1;
            }
        }
    }
    // A faixa 0xB000_0000..0xC000_0000 fica fora: era a arena de imagens grandes,
    // hoje sem uso (as imagens de kernel moram na janela de sistema).
    // De 16 MB ao fim da primeira arena do PFN: a faixa sem uso, os frames do
    // heap e da arena (só pela janela do heap) e a primeira arena do PFN.
    const _: () = assert!(super::memory_map::KERNEL_HEAP_PHYS_BASE >= 0x100_0000 && super::memory_map::KERNEL_HEAP_PHYS_TOP <= 0x1000_0000);
    for (low, high) in [(0x100_0000u64, 0x1000_0000u64), (0x2000_0000, 0xB000_0000), (0xC000_0000, super::memory_map::PHYSICAL_MEMORY_LIMIT)] {
        for va in (low..high).step_by(0x20_0000) {
            if clear_present(va, 0x20_0000) {
                large += 1;
            }
        }
    }
    cpu::reload_cr3();
    let _ = smp::flush_remote_tlb(false);
    debug_print!("[mm] auditoria do mapa direto e da janela do heap: identidade desligada em {} paginas de 4KB e {} de 2MB", small, large);
}
