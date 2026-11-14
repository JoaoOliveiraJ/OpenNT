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
//! [`create`] (MmCreateProcessAddressSpace) dá a um EPROCESS uma raiz
//! própria com a visão de usuário da KUSER_SHARED_DATA e a grava em
//! KPROCESS.DirectoryTableBase e no `ProcessState`; [`delete`]
//! (MmDeleteProcessAddressSpace) devolve ao PFN todas as tabelas da metade
//! de usuário e a raiz, no último dereference do EPROCESS
//! (`ps::process::collect_process`), o papel do PspProcessDelete.
//!
//! Ainda só a raiz do boot é carregada: os processos que o Ps cria recebem a
//! PML4 do boot como DirectoryTableBase, ninguém troca o CR3 para uma raiz de
//! [`create`] e o attach recusa um processo que tenha uma.

use alloc::collections::BTreeMap;
use core::sync::atomic::Ordering;

use super::{memory_map as map, paging, pfn, recursive_mapping, shared_user_data};
use crate::hal::physical;
use crate::ntos::inc::types::{Kprocess, NtStruct};
use crate::ntos::ps::user::process_state;
use crate::rtl::{KernelError, SpinLock};

/// Raiz do System: a PML4 do boot.
pub const SYSTEM_ROOT: u64 = map::PML4_PHYS;

/// EPROCESS -> a raiz própria que [`create`] lhe deu.
static SPACES: SpinLock<BTreeMap<u64, u64>> = SpinLock::new(BTreeMap::new());

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

/// A raiz própria do EPROCESS `process`, se ele tiver uma.
pub fn root_of(process: u64) -> Option<u64> {
    SPACES.lock().get(&process).copied()
}

/// Grava a raiz em KPROCESS.DirectoryTableBase (sem KVA shadow, a
/// UserDirectoryTableBase fica 0) e no `ProcessState`, se o processo ainda
/// tiver um.
fn publish(process: u64, root: u64) {
    // SAFETY: EPROCESS vivo, criado pelo Ps e retido pelo chamador.
    let pcb = unsafe { Kprocess::at(process) };
    pcb.directory_table_base.set(root);
    pcb.user_directory_table_base.set(0);
    if let Some(state) = process_state::get(process) {
        state.directory_table_base.store(root, Ordering::Release);
    }
}

/// MmCreateProcessAddressSpace: uma raiz nova ([`create_root`]) com a
/// visão de usuário da KUSER_SHARED_DATA em 0x7FFE0000, o mesmo frame da
/// visão de kernel, somente leitura. A raiz vai para
/// KPROCESS.DirectoryTableBase e para o `ProcessState` do processo; devolve
/// a raiz. Um processo que já tem raiz própria é recusado.
pub fn create(process: u64) -> Result<u64, KernelError> {
    if process == 0 {
        return Err(KernelError::new("address space without an EPROCESS"));
    }
    if root_of(process).is_some() {
        return Err(KernelError::new("process already has an address space"));
    }
    let root = create_root()?;
    if !shared_user_data::map_user_view_in(root) {
        discard(root);
        return Err(KernelError::new("no user view of KUSER_SHARED_DATA in the new address space"));
    }
    let inserted = {
        let mut spaces = SPACES.lock();
        let free = !spaces.contains_key(&process);
        if free {
            spaces.insert(process, root);
        }
        free
    };
    if !inserted {
        discard(root);
        return Err(KernelError::new("process already has an address space"));
    }
    publish(process, root);
    Ok(root)
}

/// Desfaz uma raiz de [`create`] que nunca foi publicada.
fn discard(root: u64) {
    if let Err(error) = paging::release_user_half_in(root, &[shared_user_data::MM_SHARED_USER_DATA_VA]).and_then(|_| delete_root(root)) {
        debug_print!("[mm] raiz {:#x} descartada com erro: {}", root, error);
    }
}

/// MmDeleteProcessAddressSpace: devolve ao PFN todas as tabelas da metade de
/// usuário da raiz própria de `process` (a visão da KUSER cai junto) e a
/// própria raiz; o processo volta a apontar para a raiz do System. A raiz
/// não pode estar carregada, e uma página de usuário ainda mapeada fora da
/// visão da KUSER faz a chamada recusar sem mudar nada: o VAD do processo
/// tem de ter sido desfeito antes.
pub fn delete(process: u64) -> Result<(), KernelError> {
    let Some(root) = SPACES.lock().remove(&process) else {
        return Err(KernelError::new("process has no address space of its own"));
    };
    let released = paging::release_user_half_in(root, &[shared_user_data::MM_SHARED_USER_DATA_VA]).and_then(|_| delete_root(root));
    if let Err(error) = released {
        SPACES.lock().insert(process, root);
        return Err(error);
    }
    publish(process, SYSTEM_ROOT);
    Ok(())
}
