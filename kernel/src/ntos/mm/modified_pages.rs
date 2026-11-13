//! Páginas modificadas de vistas do sistema — MmSetAddressRangeModified
//! (RVA 0x323360 -> MmSetAddressRangeModifiedEx 0x28fcc0, ntoskrnl 10.0.19045),
//! que o LFS do NTFS chama depois de escrever no log por uma vista do cache.
//!
//! No NT a rotina anda os PTEs válidos da faixa, passa a sujeira do PTE para
//! o PFN (MiCaptureDirtyBitToPfn liga Modified) e limpa Dirty1/Dirty do PTE
//! (bits 1 e 6) para pegar a próxima escrita; devolve TRUE quando algum PTE
//! estava sujo. O OpenNT não tem o bit Modified do PFN: as vistas de arquivo
//! gravam de volta a página inteira na expulsão/flush, e os PTEs graváveis
//! têm R/W fixo (o OpenNT não emula o bit sujo por falta de página). Por isso
//! a sujeira fica onde a gravação do OpenNT a encontra — no PTE, intocado — e
//! o resultado é o do NT: TRUE se algum PTE válido da faixa tem Dirty.

use crate::ntos::mm::paging;

const PAGE_SIZE: u64 = 0x1000;
const PTE_DIRTY: u64 = 0x40;

/// MmSetAddressRangeModified(Address, Length): o primeiro PTE é sempre
/// visitado (o laço do NT testa o fim depois do corpo).
pub fn set_address_range_modified(address: u64, length: u64) -> bool {
    let last = address.wrapping_add(length).wrapping_sub(1) & !(PAGE_SIZE - 1);
    let mut page = address & !(PAGE_SIZE - 1);
    let mut dirty = false;
    loop {
        let step = match paging::query_page(page, false) {
            Some(query) => {
                dirty |= query.flags & PTE_DIRTY != 0;
                query.page_size.max(PAGE_SIZE) - (page & (query.page_size.max(PAGE_SIZE) - 1))
            }
            None => PAGE_SIZE,
        };
        match page.checked_add(step) {
            Some(next) if next <= last => page = next,
            _ => return dirty,
        }
    }
}
