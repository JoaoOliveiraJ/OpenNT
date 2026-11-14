//! Relaciona células físicas de paginação aos descritores dos frames.
//!
//! A PteAddress publicada é um alias recursivo da célula que contém o PFN,
//! inclusive para frames que são, eles próprios, tabelas de páginas.
//!
//! Os aliases físicos do kernel não são donos de frame e ficam de fora: a
//! identidade (VA == PA, só a página do trampolim dos APs enquanto eles
//! partem) e os slots inteiros do mapa direto (`DIRECT_MAP_PML4_INDEX`) e da
//! janela do heap (`KERNEL_HEAP_PML4_INDEX`), cujas tabelas nem são
//! acompanhadas.
//!
//! **A árvore de cada raiz.** O rastreador parte da raiz do System
//! (`PML4_PHYS`) e segue o que ela alcança: a metade de sistema inteira (as
//! PDPTs congeladas e tudo abaixo delas, compartilhadas por todas as raízes,
//! então toda folha de sistema é vista uma vez, venha a escrita de qualquer
//! raiz) e a metade de usuário do System. Cada raiz de processo
//! (`process_address_space::create_root`) entra com [`add_root`]: a
//! auto-referência dela (a referência de tabela do frame da raiz) e a metade
//! de usuário, PML4[0..256) — as PDPTs, PDs e PTs que só ela alcança e as
//! folhas de usuário delas, com PteAddress no banco nativo de PFNs. A
//! metade de sistema dela não é seguida de novo: as entradas são cópias das
//! do boot. Cada tabela sabe de que raiz é (`space`). Uma tabela ainda
//! ligada continua referenciada, e o PFN não a devolve (o frame não volta
//! nem duas vezes nem enquanto está em uso); [`remove_root`], no
//! `delete_root`, confere que nenhuma tabela da raiz sobrou no rastreador
//! (uma tabela vazada) antes de tirar a auto-referência e a raiz. A
//! PteAddress publicada é o alias recursivo: válido para uma folha de
//! sistema em qualquer raiz carregada e para uma folha de usuário com a raiz
//! dela carregada, como no NT.

use alloc::collections::BTreeMap;

use super::native_frame_descriptors::{self as descriptors, Reference};
use super::{memory_map as map, recursive_mapping};
use crate::hal::physical;
use crate::rtl::{KernelError, SpinLock};

const PHYSICAL_ADDRESS_MASK: u64 = 0x000F_FFFF_FFFF_F000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Add,
    Remove,
    Refresh,
}

struct Table {
    physical_address: u64,
    level: u32,
    prefix: u64,
    virtual_address: u64,
    primary_parent: u64,
    /// Entrada pai -> prefixo de VA por esse caminho.
    parents: BTreeMap<u64, u64>,
    /// A raiz (PML4) da árvore desta tabela: `PML4_PHYS` ou a de um
    /// processo.
    space: u64,
}

struct Tracker {
    tables: BTreeMap<u64, Table>,
    layout: Option<recursive_mapping::RecursiveLayout>,
    descriptor_count: u64,
}

static STATE: SpinLock<Tracker> =
    SpinLock::new(Tracker { tables: BTreeMap::new(), layout: None, descriptor_count: 0 });

fn read_entry(address: u64) -> u64 {
    physical::read64(address)
}

fn cache_attribute(entry: u64, level: u32) -> u8 {
    if entry & 0x10 != 0 {
        return 0;
    }
    if entry & if level == 1 { 0x80 } else { 0x1000 } != 0 { 2 } else { 1 }
}

impl Tracker {
    fn table_alias(&self, level: u32, prefix: u64) -> u64 {
        let layout = self.layout.expect("tracker not initialized");
        match level {
            4 => layout.root_table_address,
            3 => layout.directory_pointer_base + (prefix >> 39) * 4096,
            2 => layout.page_directory_base + (prefix >> 30) * 4096,
            _ => layout.page_table_base + (prefix >> 21) * 4096,
        }
    }

    fn reference_for(&self, table_pa: u64, index: u64, entry: u64, table_page: bool) -> Reference {
        let table = &self.tables[&table_pa];
        Reference {
            physical_address: table.physical_address + index * 8,
            virtual_address: table.virtual_address.wrapping_add(index * 8),
            table_page,
            cache_attribute: if table_page { 1 } else { cache_attribute(entry, table.level) },
        }
    }

    /// Uma tabela pode ter mais de um pai; seu alias principal muda quando o
    /// pai anterior desaparece.
    fn rebase_table(&mut self, table_pa: u64, prefix: u64) {
        let level = self.tables[&table_pa].level;
        let alias = self.table_alias(level, prefix);
        if let Some(table) = self.tables.get_mut(&table_pa) {
            table.prefix = prefix;
            table.virtual_address = alias;
        }
        for index in 0..512 {
            self.update_entry(table_pa, index, read_entry(table_pa + index * 8), Operation::Refresh);
        }
    }

    fn add_table(&mut self, parent_pa: u64, index: u64, entry: u64, prefix: u64) {
        let physical_address = entry & PHYSICAL_ADDRESS_MASK;
        let reference = self.reference_for(parent_pa, index, entry, true);
        let (parent_level, space) = {
            let parent = &self.tables[&parent_pa];
            (parent.level, parent.space)
        };
        let table_index = self.layout.unwrap().table_index;
        // A auto-referência de uma raiz (a do boot ou a de um processo).
        if parent_level == 4 && index == table_index && physical_address == parent_pa {
            descriptors::add_reference(physical_address / 4096, reference);
            return;
        }
        if let Some(table) = self.tables.get_mut(&physical_address) {
            assert!(table.level == parent_level - 1, "mixed-level page-table cycle");
            table.parents.insert(reference.physical_address, prefix);
            descriptors::add_reference(physical_address / 4096, reference);
            return;
        }
        let level = parent_level - 1;
        let table = Table {
            physical_address,
            level,
            prefix,
            virtual_address: self.table_alias(level, prefix),
            primary_parent: reference.physical_address,
            parents: BTreeMap::from([(reference.physical_address, prefix)]),
            space,
        };
        self.tables.insert(physical_address, table);
        descriptors::add_reference(physical_address / 4096, reference);
        // PTEs de um split são preenchidos antes de o PDE tornar a tabela visível.
        for child in 0..512 {
            self.update_entry(physical_address, child, read_entry(physical_address + child * 8), Operation::Add);
        }
    }

    fn remove_table(&mut self, parent_pa: u64, index: u64, entry: u64) {
        let physical_address = entry & PHYSICAL_ADDRESS_MASK;
        let parent_address = parent_pa + index * 8;
        assert!(self.tables.contains_key(&physical_address), "removed page table was not tracked");
        descriptors::remove_reference(physical_address / 4096, parent_address);
        if physical_address == parent_pa {
            return;
        }
        let table = self.tables.get_mut(&physical_address).unwrap();
        assert!(table.parents.remove(&parent_address).is_some(), "page-table parent missing");
        let replacement = table.parents.iter().next().map(|(&parent, &prefix)| (parent, prefix));
        if let Some((replacement_parent, replacement_prefix)) = replacement {
            let was_primary = table.primary_parent == parent_address;
            if was_primary {
                table.primary_parent = replacement_parent;
                self.rebase_table(physical_address, replacement_prefix);
            }
            return;
        }
        for child in 0..512 {
            self.update_entry(physical_address, child, read_entry(physical_address + child * 8), Operation::Remove);
        }
        self.tables.remove(&physical_address);
    }

    fn update_entry(&mut self, table_pa: u64, index: u64, entry: u64, operation: Operation) {
        let (level, table_prefix, space) = {
            let table = &self.tables[&table_pa];
            (table.level, table.prefix, table.space)
        };
        if level == 4 && (index == map::DIRECT_MAP_PML4_INDEX || index == map::KERNEL_HEAP_PML4_INDEX) {
            return;
        }
        // A metade de sistema de uma raiz de processo é a do boot, já seguida
        // por ela; só a auto-referência é da raiz.
        let table_index = self.layout.unwrap().table_index;
        if level == 4 && space != map::PML4_PHYS && index >= map::USER_PML4_ENTRIES && index != table_index {
            return;
        }
        let shift = 12 + (level - 1) * 9;
        let prefix = table_prefix | (index << shift);
        let present = entry & 1 != 0;
        let large_page = level > 1 && level < 4 && entry & 0x80 != 0;
        if level > 1 && !large_page {
            if !present {
                return;
            }
            match operation {
                Operation::Add => self.add_table(table_pa, index, entry, prefix),
                Operation::Remove => self.remove_table(table_pa, index, entry),
                Operation::Refresh => {
                    let physical_address = entry & PHYSICAL_ADDRESS_MASK;
                    let reference = self.reference_for(table_pa, index, entry, true);
                    descriptors::refresh_reference(physical_address / 4096, reference);
                    let rebase = physical_address != table_pa
                        && self
                            .tables
                            .get(&physical_address)
                            .is_some_and(|child| child.primary_parent == reference.physical_address);
                    if rebase {
                        self.rebase_table(physical_address, prefix);
                    }
                }
            }
            return;
        }
        // Folhas NOACCESS mantêm backing sem PRESENT; marcadores com PFN zero
        // não criam referência à página física zero.
        if !present && entry & PHYSICAL_ADDRESS_MASK == 0 {
            return;
        }
        let byte_length = 1u64 << shift;
        let physical_address = entry & PHYSICAL_ADDRESS_MASK & !(byte_length - 1);
        // VA canônica: estende o sinal do bit 47.
        let virtual_address = ((prefix << 16) as i64 >> 16) as u64;
        // Os aliases físicos do kernel só existem na árvore do boot; numa raiz
        // de processo toda folha é de usuário e dona do frame.
        if space == map::PML4_PHYS && (virtual_address == physical_address || virtual_address == map::direct_map(physical_address)) {
            return;
        }
        let reference = self.reference_for(table_pa, index, entry, false);
        let first_frame = physical_address / 4096;
        let end_frame = (first_frame + byte_length / 4096).min(self.descriptor_count);
        for frame_number in first_frame..end_frame {
            match operation {
                Operation::Add => descriptors::add_reference(frame_number, reference),
                Operation::Remove => descriptors::remove_reference(frame_number, reference.physical_address),
                Operation::Refresh => descriptors::refresh_reference(frame_number, reference),
            }
        }
    }
}

pub fn initialize() -> Result<(), KernelError> {
    let mut tracker = STATE.lock();
    if tracker.layout.is_some() {
        return Err(KernelError::new("frame mapping tracker already initialized"));
    }
    tracker.layout = Some(
        recursive_mapping::layout().ok_or_else(|| KernelError::new("native PFNs require the real recursive mapping"))?,
    );
    tracker.descriptor_count = descriptors::information().map_or(0, |information| information.frame_count);
    let root = Table {
        physical_address: map::PML4_PHYS,
        level: 4,
        prefix: 0,
        virtual_address: tracker.layout.unwrap().root_table_address,
        primary_parent: 0,
        parents: BTreeMap::new(),
        space: map::PML4_PHYS,
    };
    tracker.tables.insert(map::PML4_PHYS, root);
    for index in 0..512 {
        tracker.update_entry(map::PML4_PHYS, index, read_entry(map::PML4_PHYS + index * 8), Operation::Add);
    }
    Ok(())
}

/// Uma raiz de processo nova (`process_address_space::create_root`, já com a
/// metade de sistema copiada e a auto-referência): passa a ser seguida. A
/// auto-referência ganha a referência de tabela do frame da raiz, e a metade
/// de usuário (vazia na criação) é percorrida. Sem o rastreador instalado,
/// nada a fazer.
pub fn add_root(root: u64) -> Result<(), KernelError> {
    let mut tracker = STATE.lock();
    let Some(layout) = tracker.layout else { return Ok(()) };
    if tracker.tables.contains_key(&root) {
        return Err(KernelError::new("page-table root already tracked"));
    }
    let table = Table { physical_address: root, level: 4, prefix: 0, virtual_address: layout.root_table_address, primary_parent: 0, parents: BTreeMap::new(), space: root };
    tracker.tables.insert(root, table);
    for index in (0..map::USER_PML4_ENTRIES).chain(core::iter::once(layout.table_index)) {
        tracker.update_entry(root, index, read_entry(root + index * 8), Operation::Add);
    }
    Ok(())
}

/// A raiz `root` vai voltar ao PFN (`process_address_space::delete_root`,
/// com a metade de usuário já desfeita): recusa, sem mudar nada, se alguma
/// tabela da árvore dela ainda está no rastreador (uma tabela vazada); senão
/// tira a auto-referência e a raiz, que fica livre para o PFN.
pub fn remove_root(root: u64) -> Result<(), KernelError> {
    let mut tracker = STATE.lock();
    let Some(layout) = tracker.layout else { return Ok(()) };
    if root == map::PML4_PHYS || !tracker.tables.get(&root).is_some_and(|table| table.level == 4) {
        return Err(KernelError::new("page-table root not tracked"));
    }
    let leaked = tracker.tables.values().filter(|table| table.space == root && table.physical_address != root).count();
    if leaked != 0 {
        return Err(KernelError::new(alloc::format!("{leaked} page table(s) of the root still tracked")));
    }
    tracker.update_entry(root, layout.table_index, read_entry(root + layout.table_index * 8), Operation::Remove);
    tracker.tables.remove(&root);
    Ok(())
}

/// Os frames das tabelas da árvore de `root` (a própria raiz inclusive) que
/// o rastreador segue.
pub fn tables_of(root: u64) -> alloc::vec::Vec<u64> {
    STATE.lock().tables.values().filter(|table| table.space == root).map(|table| table.physical_address).collect()
}

/// Quantas tabelas o rastreador segue, de todas as raízes.
pub fn table_count() -> usize {
    STATE.lock().tables.len()
}

pub fn tracks_entry(address: u64) -> bool {
    STATE.lock().tables.contains_key(&(address / 4096 * 4096))
}

pub fn entry_changed(address: u64, previous: u64, replacement: u64) {
    if previous == replacement {
        return;
    }
    let mut tracker = STATE.lock();
    let table_pa = address / 4096 * 4096;
    let Some(table) = tracker.tables.get(&table_pa) else { return };
    // RW/USER/NX e A/D mudam a proteção da mesma PTE, não o dono do frame.
    let reference_bits = PHYSICAL_ADDRESS_MASK | 0x98;
    if table.level == 1 && previous != 0 && replacement != 0 && previous & reference_bits == replacement & reference_bits {
        return;
    }
    let index = (address % 4096) / 8;
    tracker.update_entry(table_pa, index, previous, Operation::Remove);
    tracker.update_entry(table_pa, index, replacement, Operation::Add);
}

pub fn reset() {
    let mut tracker = STATE.lock();
    tracker.tables.clear();
    tracker.layout = None;
    tracker.descriptor_count = 0;
}
