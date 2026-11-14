//! Espaços de endereçamento: a raiz (PML4) de cada um.
//!
//! Como no NT, a metade de sistema é a mesma em todo espaço de
//! endereçamento. [`prepare_system_space`] deixa, no boot, as entradas de
//! sistema da PML4 do boot presentes e congeladas (`paging::freeze_kernel_half`);
//! uma raiz nova ([`create_root`]) copia PML4[257..512) dela uma única vez e
//! ganha a própria auto-referência em [256], de modo que o mapeamento
//! recursivo mostra sempre as tabelas da raiz carregada. A metade de
//! usuário, PML4[0..256), começa vazia e é só do espaço.
//!
//! Ainda há um só espaço em uso: todo EPROCESS recebe a PML4 do boot como
//! DirectoryTableBase e o CR3 não muda.

use super::{memory_map as map, paging, pfn, recursive_mapping};
use crate::hal::physical;
use crate::rtl::KernelError;

/// Raiz do System: a PML4 do boot.
pub const SYSTEM_ROOT: u64 = map::PML4_PHYS;

/// Fase 0, depois do PFN e do mapeamento recursivo e antes do banco nativo
/// de PFNs e de qualquer outro mapeamento de sistema: pré-aloca as PDPTs da
/// metade de sistema e a congela.
pub fn prepare_system_space() -> Result<(), KernelError> {
    let allocated = paging::freeze_kernel_half()?;
    debug_print!("[mm] metade de sistema congelada: {} PDPTs pre-alocadas", allocated);
    Ok(())
}

/// Uma PML4 nova num frame do PFN: a metade de sistema copiada da raiz do
/// System, a auto-referência própria e a metade de usuário vazia. Devolve o
/// endereço físico (o DirectoryTableBase do espaço).
pub fn create_root() -> Result<u64, KernelError> {
    if !paging::kernel_half_frozen() {
        return Err(KernelError::new("address-space roots need the frozen kernel half"));
    }
    let root = pfn::alloc_page();
    if root == 0 {
        return Err(KernelError::new("no frame for a page-table root"));
    }
    physical::zero(root, map::PAGE_SIZE as usize);
    for index in map::USER_PML4_ENTRIES..512 {
        let entry = if index == map::PAGE_TABLE_RECURSIVE_INDEX {
            recursive_mapping::self_reference(root)
        } else {
            paging::read_entry_exact(SYSTEM_ROOT + index * 8)
        };
        physical::write64(root + index * 8, entry);
    }
    Ok(root)
}

/// Devolve ao PFN uma raiz de [`create_root`]. As tabelas da metade de
/// usuário pertencem ao espaço e já devem ter sido desfeitas: com alguma
/// entrada de usuário ainda presente, recusa sem liberar nada. As da metade
/// de sistema são compartilhadas e ficam.
pub fn delete_root(root: u64) -> Result<(), KernelError> {
    if root == SYSTEM_ROOT || root == paging::current_root() {
        return Err(KernelError::new("page-table root still in use"));
    }
    if root % map::PAGE_SIZE != 0 || root >= map::PHYSICAL_MEMORY_LIMIT || paging::read_entry_exact(root + map::PAGE_TABLE_RECURSIVE_INDEX * 8) != recursive_mapping::self_reference(root) {
        return Err(KernelError::new("not an address-space root"));
    }
    if (0..map::USER_PML4_ENTRIES).any(|index| paging::read_entry_exact(root + index * 8) != 0) {
        return Err(KernelError::new("user half of the root is still mapped"));
    }
    physical::zero(root, map::PAGE_SIZE as usize);
    pfn::free_page(root);
    Ok(())
}
