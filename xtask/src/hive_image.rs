//! Gera arquivos de hive do Registro (formato regf) para o volume.
//!
//! As hives de máquina (SYSTEM, SOFTWARE, SAM, SECURITY e DEFAULT) saem das
//! mesmas tabelas que o kernel semeia em memória quando um arquivo falta
//! (`kernel/src/ntos/cm/seed.rs` e as tabelas que ele reúne, incluídas aqui
//! por `#[path]` na mesma árvore de módulos), então o boot com os arquivos
//! e o boot sem eles veem as mesmas chaves e valores. Uma chave de link
//! (o `SAM` da SECURITY) leva KEY_SYM_LINK e o `SymbolicLinkValue`.
//!
//! O arquivo segue o formato que o Configuration Manager do Windows 10
//! grava (o mesmo que o kernel lê e grava em `cm/hive`):
//! - bloco base de 0x1000 bytes: 'regf', Sequence1 = Sequence2 = 1, o
//!   carimbo de tempo, Major 1, Minor 5, Type 0 (primário), Format 1, a
//!   célula raiz, o tamanho dos bins, Cluster 1, o nome do arquivo e a soma
//!   (XOR dos 127 primeiros DWORDs, 0xFFFFFFFF vira 0xFFFFFFFE e 0 vira 1);
//! - bins 'hbin' de múltiplos de 0x1000 com células de tamanho múltiplo de
//!   8 (negativo = alocada), o resto de cada bin numa célula livre;
//! - 'nk' com o nome comprimido em bytes (KEY_COMP_NAME), a raiz com
//!   KEY_HIVE_ENTRY | KEY_NO_DELETE e pai nil; listas de subchaves 'lh'
//!   ordenadas pelo nome sem caixa, com o hash h = h * 37 + maiúscula(c),
//!   e, numa chave com mais de 1012 subchaves, folhas 'lh' de 506 entradas
//!   sob uma raiz 'ri';
//!   'vk' com o nome comprimido (VALUE_COMP_NAME) e até 4 bytes de dado no
//!   próprio campo (bit 31 do tamanho); acima de 16344 bytes, 'db';
//! - uma célula 'sk' (lista circular dela mesma) com o descritor de todas
//!   as chaves e a contagem delas.
//!
//! O descritor é o que a política do kernel dá às chaves criadas no boot
//! sob `\Registry\Machine` (`cm/key/policy.rs`): as ACEs da raiz do
//! Registro herdadas (INHERITED_ACE | CONTAINER_INHERIT_ACE) — SYSTEM e
//! Administrators com KEY_ALL_ACCESS, Everyone com KEY_READ —, owner e
//! group SYSTEM e control SE_DACL_AUTO_INHERITED | SE_DACL_PRESENT. O
//! autoteste da hive confere que o kernel atribui o mesmo descritor.

#[allow(dead_code)]
mod cm {
    #[path = "../../../../kernel/src/ntos/cm/seed.rs"]
    pub mod seed;
    #[path = "../../../../kernel/src/ntos/cm/session_manager.rs"]
    pub mod session_manager;
    #[path = "../../../../kernel/src/ntos/cm/crypto_defaults.rs"]
    pub mod crypto_defaults;
    #[path = "../../../../kernel/src/ntos/cm/current_version.rs"]
    pub mod current_version;
    #[path = "../../../../kernel/src/ntos/cm/ini_file_mapping.rs"]
    pub mod ini_file_mapping;
    #[path = "../../../../kernel/src/ntos/cm/arbiters.rs"]
    pub mod arbiters;
    #[path = "../../../../kernel/src/ntos/cm/pnp_control.rs"]
    pub mod pnp_control;
    #[path = "../../../../kernel/src/ntos/cm/crash_control.rs"]
    pub mod crash_control;
    #[path = "../../../../kernel/src/ntos/cm/time_zone_information.rs"]
    pub mod time_zone_information;
    #[path = "../../../../kernel/src/ntos/cm/network_setup.rs"]
    pub mod network_setup;
    pub mod service {
        #[path = "../../../../../kernel/src/ntos/cm/service/boot_services.rs"]
        pub mod boot_services;
        #[path = "../../../../../kernel/src/ntos/cm/service/inbox_drivers.rs"]
        pub mod inbox_drivers;
        #[path = "../../../../../kernel/src/ntos/cm/service/file_system_filters.rs"]
        pub mod file_system_filters;
    }
}

use std::collections::BTreeMap;

const HBLOCK: usize = 0x1000;
const HBIN_HEADER: usize = 0x20;
const NIL: u32 = 0xFFFF_FFFF;
const MINOR: u32 = 5;
const BIG_SEGMENT: usize = 0x3fd8;
/// Entradas de uma folha de subchaves: o CmpAddSubKeyEx passa a folha com
/// 1013 entradas para baixo de uma raiz 'ri', dividida ao meio.
const MAX_LEAF: usize = 1012;
const SPLIT_LEAF: usize = MAX_LEAF / 2;

/// SID S-1-5-18 (SYSTEM).
const SYSTEM_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
/// (mask, SID) das ACEs da raiz: SYSTEM e Administrators com KEY_ALL_ACCESS
/// e Everyone com KEY_READ.
const ACES: [(u32, &[u8]); 3] = [(0xF003F, &SYSTEM_SID), (0xF003F, &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]), (0x20019, &[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0])];

/// SECURITY_DESCRIPTOR_RELATIVE: cabeçalho, DACL, owner e group (a ordem do
/// kernel em `cm/hive/security_cells.rs`).
fn descriptor(control: u16, ace_flags: u8) -> Vec<u8> {
    let mut acl = Vec::new();
    for (mask, sid) in ACES {
        let size = 8 + sid.len();
        acl.push(0);
        acl.push(ace_flags);
        acl.extend_from_slice(&(size as u16).to_le_bytes());
        acl.extend_from_slice(&mask.to_le_bytes());
        acl.extend_from_slice(sid);
    }
    let mut header = vec![2u8, 0];
    header.extend_from_slice(&((8 + acl.len()) as u16).to_le_bytes());
    header.extend_from_slice(&(ACES.len() as u16).to_le_bytes());
    header.extend_from_slice(&[0, 0]);
    header.extend_from_slice(&acl);
    let acl = header;
    let mut bytes = vec![0u8; 20];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&(control | 0x8000).to_le_bytes());
    let dacl = bytes.len() as u32;
    bytes.extend_from_slice(&acl);
    let owner = bytes.len() as u32;
    bytes.extend_from_slice(&SYSTEM_SID);
    let group = bytes.len() as u32;
    bytes.extend_from_slice(&SYSTEM_SID);
    bytes[4..8].copy_from_slice(&owner.to_le_bytes());
    bytes[8..12].copy_from_slice(&group.to_le_bytes());
    bytes[16..20].copy_from_slice(&dacl.to_le_bytes());
    bytes
}

/// Uma chave da árvore a gravar.
struct Key {
    name: String,
    values: Vec<(String, u32, Vec<u8>)>,
    children: BTreeMap<String, usize>,
    /// Chave de link (KEY_SYM_LINK).
    link: bool,
}

fn upcase(name: &str) -> Vec<u16> {
    name.encode_utf16().map(|unit| if (0x61..=0x7A).contains(&unit) { unit - 0x20 } else { unit }).collect()
}

/// Bins em construção: as células vão em sequência; uma que não cabe no
/// resto do bin abre outro (o resto vira célula livre).
struct Bins {
    data: Vec<u8>,
    bin_start: usize,
}

impl Bins {
    fn open_bin(&mut self, needed: usize) {
        let size = (needed + HBIN_HEADER).div_ceil(HBLOCK) * HBLOCK;
        let offset = self.data.len();
        self.data.resize(offset + size, 0);
        self.data[offset..offset + 4].copy_from_slice(b"hbin");
        self.data[offset + 4..offset + 8].copy_from_slice(&(offset as u32).to_le_bytes());
        self.data[offset + 8..offset + 12].copy_from_slice(&(size as u32).to_le_bytes());
        self.bin_start = offset;
        let free = size - HBIN_HEADER;
        self.data[offset + HBIN_HEADER..offset + HBIN_HEADER + 4].copy_from_slice(&(free as i32).to_le_bytes());
    }

    /// Uma célula com `size` bytes de dados; devolve o índice dela.
    fn cell(&mut self, size: usize) -> u32 {
        let needed = (size + 4).div_ceil(8) * 8;
        let mut cursor = self.bin_start + HBIN_HEADER;
        let bin_end = if self.data.is_empty() { 0 } else { self.bin_start + u32::from_le_bytes(self.data[self.bin_start + 8..self.bin_start + 12].try_into().unwrap()) as usize };
        // A célula livre do fim do bin corrente.
        let mut free = None;
        while cursor < bin_end {
            let raw = i32::from_le_bytes(self.data[cursor..cursor + 4].try_into().unwrap());
            if raw > 0 {
                free = Some((cursor, raw as usize));
                break;
            }
            cursor += raw.unsigned_abs() as usize;
        }
        let (start, available) = match free.filter(|&(_, available)| available >= needed) {
            Some(found) => found,
            None => {
                self.open_bin(needed);
                (self.bin_start + HBIN_HEADER, u32::from_le_bytes(self.data[self.bin_start + 8..self.bin_start + 12].try_into().unwrap()) as usize - HBIN_HEADER)
            }
        };
        let used = if available - needed >= 8 { needed } else { available };
        self.data[start..start + 4].copy_from_slice(&(-(used as i32)).to_le_bytes());
        if used < available {
            self.data[start + used..start + used + 4].copy_from_slice(&((available - used) as i32).to_le_bytes());
        }
        start as u32
    }

    fn put(&mut self, cell: u32, offset: usize, bytes: &[u8]) {
        let at = cell as usize + 4 + offset;
        self.data[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn put16(&mut self, cell: u32, offset: usize, value: u16) {
        self.put(cell, offset, &value.to_le_bytes());
    }

    fn put32(&mut self, cell: u32, offset: usize, value: u32) {
        self.put(cell, offset, &value.to_le_bytes());
    }

    fn put64(&mut self, cell: u32, offset: usize, value: u64) {
        self.put(cell, offset, &value.to_le_bytes());
    }
}

fn compressed(name: &str) -> Vec<u8> {
    assert!(name.chars().all(|character| (character as u32) < 0x80), "nome fora de ASCII na hive: {name}");
    name.bytes().collect()
}

/// O dado de um valor acima de 4 bytes: uma célula, ou 'db' com segmentos.
fn data_cell(bins: &mut Bins, data: &[u8]) -> u32 {
    if data.len() <= BIG_SEGMENT {
        let cell = bins.cell(data.len());
        bins.put(cell, 0, data);
        return cell;
    }
    let big = bins.cell(8);
    let count = data.len().div_ceil(BIG_SEGMENT);
    let list = bins.cell(count * 4);
    for (index, chunk) in data.chunks(BIG_SEGMENT).enumerate() {
        let segment = bins.cell(BIG_SEGMENT);
        bins.put(segment, 0, chunk);
        bins.put32(list, index * 4, segment);
    }
    bins.put(big, 0, b"db");
    bins.put16(big, 2, count as u16);
    bins.put32(big, 4, list);
    big
}

/// Grava a árvore (a primeira chave é a raiz) e devolve o arquivo inteiro.
fn write_hive(keys: &[Key], time: u64, file_name: &str) -> Vec<u8> {
    let mut bins = Bins { data: Vec::new(), bin_start: 0 };
    let shared = descriptor(0x0404, 0x12);
    let mut cells = vec![NIL; keys.len()];
    // Pré-ordem com o pai de cada chave.
    let mut order = Vec::new();
    let mut stack = vec![(0usize, None::<usize>)];
    while let Some((index, parent)) = stack.pop() {
        order.push((index, parent));
        for &child in keys[index].children.values().rev() {
            stack.push((child, Some(index)));
        }
    }
    let mut sk = NIL;
    for &(index, parent) in &order {
        let key = &keys[index];
        let name = compressed(&key.name);
        let cell = bins.cell(0x4c + name.len());
        cells[index] = cell;
        bins.put(cell, 0, b"nk");
        // KEY_COMP_NAME; a raiz com KEY_HIVE_ENTRY | KEY_NO_DELETE e um link
        // com KEY_SYM_LINK.
        bins.put16(cell, 2, (if parent.is_none() { 0x2c } else { 0x20 }) | if key.link { 0x10 } else { 0 });
        bins.put64(cell, 4, time);
        bins.put32(cell, 0x10, parent.map_or(NIL, |parent| cells[parent]));
        bins.put32(cell, 0x14, key.children.len() as u32);
        bins.put32(cell, 0x1c, NIL);
        bins.put32(cell, 0x20, NIL);
        bins.put32(cell, 0x24, key.values.len() as u32);
        bins.put32(cell, 0x28, NIL);
        bins.put32(cell, 0x30, NIL);
        let max_name = key.children.values().map(|&child| keys[child].name.encode_utf16().count() as u32 * 2).max().unwrap_or(0);
        bins.put32(cell, 0x34, max_name);
        bins.put32(cell, 0x3c, key.values.iter().map(|(name, _, _)| name.encode_utf16().count() as u32 * 2).max().unwrap_or(0));
        bins.put32(cell, 0x40, key.values.iter().map(|(_, _, data)| data.len() as u32).max().unwrap_or(0));
        bins.put16(cell, 0x48, name.len() as u16);
        bins.put(cell, 0x4c, &name);
        // Segurança: uma 'sk' só, criada com a raiz (lista circular dela
        // mesma), com a contagem de todas as chaves.
        if sk == NIL {
            sk = bins.cell(0x14 + shared.len());
            bins.put(sk, 0, b"sk");
            bins.put32(sk, 4, sk);
            bins.put32(sk, 8, sk);
            bins.put32(sk, 0x10, shared.len() as u32);
            bins.put(sk, 0x14, &shared);
        }
        let count = u32::from_le_bytes(bins.data[sk as usize + 4 + 0xc..sk as usize + 4 + 0x10].try_into().unwrap());
        bins.put32(sk, 0xc, count + 1);
        bins.put32(cell, 0x2c, sk);
        if !key.values.is_empty() {
            let list = bins.cell(key.values.len() * 4);
            bins.put32(cell, 0x28, list);
            for (position, (value_name, value_type, data)) in key.values.iter().enumerate() {
                let stored = compressed(value_name);
                let value = bins.cell(0x14 + stored.len());
                bins.put(value, 0, b"vk");
                bins.put16(value, 2, stored.len() as u16);
                if data.len() <= 4 {
                    let mut inline = [0u8; 4];
                    inline[..data.len()].copy_from_slice(data);
                    bins.put32(value, 4, 0x8000_0000 | data.len() as u32);
                    bins.put(value, 8, &inline);
                } else {
                    let data_cell = data_cell(&mut bins, data);
                    bins.put32(value, 4, data.len() as u32);
                    bins.put32(value, 8, data_cell);
                }
                bins.put32(value, 0xc, *value_type);
                bins.put16(value, 0x10, if stored.is_empty() { 0 } else { 1 });
                bins.put(value, 0x14, &stored);
                bins.put32(list, position * 4, value);
            }
        }
    }
    // Listas 'lh', com as células dos filhos já conhecidas; acima de
    // MAX_LEAF subchaves, folhas 'lh' sob uma raiz 'ri'.
    for &(index, _) in &order {
        let key = &keys[index];
        if key.children.is_empty() {
            continue;
        }
        let mut children: Vec<usize> = key.children.values().copied().collect();
        children.sort_by_key(|&child| upcase(&keys[child].name));
        let leaf = |bins: &mut Bins, children: &[usize]| -> u32 {
            let list = bins.cell(4 + children.len() * 8);
            bins.put(list, 0, b"lh");
            bins.put16(list, 2, children.len() as u16);
            for (position, &child) in children.iter().enumerate() {
                let hash = upcase(&keys[child].name).iter().fold(0u32, |hash, &unit| hash.wrapping_mul(37).wrapping_add(unit as u32));
                bins.put32(list, 4 + position * 8, cells[child]);
                bins.put32(list, 8 + position * 8, hash);
            }
            list
        };
        let list = if children.len() <= MAX_LEAF {
            leaf(&mut bins, &children)
        } else {
            let leaves: Vec<u32> = children.chunks(SPLIT_LEAF).map(|chunk| leaf(&mut bins, chunk)).collect();
            let root = bins.cell(4 + leaves.len() * 4);
            bins.put(root, 0, b"ri");
            bins.put16(root, 2, leaves.len() as u16);
            for (position, &leaf) in leaves.iter().enumerate() {
                bins.put32(root, 4 + position * 4, leaf);
            }
            root
        };
        bins.put32(cells[index], 0x1c, list);
    }
    if !bins.data.is_empty() {
        bins.data[0x14..0x1c].copy_from_slice(&time.to_le_bytes());
    }
    let mut base = vec![0u8; HBLOCK];
    base[0..4].copy_from_slice(b"regf");
    base[4..8].copy_from_slice(&1u32.to_le_bytes());
    base[8..12].copy_from_slice(&1u32.to_le_bytes());
    base[0xc..0x14].copy_from_slice(&time.to_le_bytes());
    base[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    base[0x18..0x1c].copy_from_slice(&MINOR.to_le_bytes());
    base[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
    base[0x24..0x28].copy_from_slice(&cells[0].to_le_bytes());
    base[0x28..0x2c].copy_from_slice(&(bins.data.len() as u32).to_le_bytes());
    base[0x2c..0x30].copy_from_slice(&1u32.to_le_bytes());
    let units: Vec<u16> = file_name.encode_utf16().collect();
    for (index, unit) in units[units.len().saturating_sub(31)..].iter().enumerate() {
        base[0x30 + index * 2..0x32 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
    let sum = base[..508].chunks_exact(4).fold(0u32, |sum, word| sum ^ u32::from_le_bytes(word.try_into().unwrap()));
    let sum = match sum {
        0xFFFF_FFFF => 0xFFFF_FFFE,
        0 => 1,
        sum => sum,
    };
    base[0x1fc..0x200].copy_from_slice(&sum.to_le_bytes());
    base.extend_from_slice(&bins.data);
    base
}

/// FILETIME de agora (100 ns desde 1601).
/// O ActiveTimeBias da hive SYSTEM (UTC − hora local, em minutos): o
/// relógio da máquina virtual guarda a hora local desse fuso.
pub fn active_time_bias_minutes() -> i32 {
    cm::time_zone_information::ACTIVE_TIME_BIAS
}

fn now_filetime() -> u64 {
    let since_unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|duration| duration.as_nanos() / 100).unwrap_or(0) as u64;
    since_unix + 116_444_736_000_000_000
}

/// Uma hive com as chaves das tabelas de semente (caminhos relativos à
/// raiz, que se chama ROOT).
fn hive_from_seeds(seeds: Vec<cm::seed::SeedKey>, file_name: &str) -> Vec<u8> {
    let mut keys = vec![Key { name: String::from("ROOT"), values: Vec::new(), children: BTreeMap::new(), link: false }];
    for seed in seeds {
        let mut current = 0;
        for component in seed.path.split('\\').filter(|component| !component.is_empty()) {
            let lower = component.to_lowercase();
            current = match keys[current].children.get(&lower) {
                Some(&child) => child,
                None => {
                    keys.push(Key { name: String::from(component), values: Vec::new(), children: BTreeMap::new(), link: false });
                    let child = keys.len() - 1;
                    keys[current].children.insert(lower, child);
                    child
                }
            };
        }
        keys[current].link |= seed.link;
        for (name, value_type, data) in seed.values {
            let values = &mut keys[current].values;
            match values.iter_mut().find(|(existing, _, _)| existing.eq_ignore_ascii_case(&name)) {
                Some(slot) => *slot = (name, value_type, data),
                None => values.push((name, value_type, data)),
            }
        }
    }
    write_hive(&keys, now_filetime(), file_name)
}

/// Uma chave copiada desta máquina como chave de semente.
fn seed_of(key: crate::host_language::HostKey) -> cm::seed::SeedKey {
    let mut seed = cm::seed::SeedKey::new(&key.path);
    for (name, value_type, data) in key.values {
        seed.value(&name, value_type, data);
    }
    seed
}

/// As hives de máquina de `\SystemRoot\System32\config`, com o nome do
/// arquivo: SYSTEM, SOFTWARE, SAM, SECURITY e DEFAULT. `smss_boot`: o boot
/// do processo inicial real (`--initial-process=smss`).
pub fn machine_hives(smss_boot: bool) -> Vec<(&'static str, Vec<u8>)> {
    let mut system = cm::seed::system_keys(smss_boot);
    let mut software = cm::seed::software_keys(smss_boot);
    let mut default = cm::seed::default_keys();
    // No boot do processo inicial real, o idioma desta instalação
    // (`host_language`): a SYSTEM e a DEFAULT levam as chaves daqui.
    if smss_boot {
        let control_set = format!("ControlSet{:03}", cm::seed::CURRENT_CONTROL_SET);
        system.extend(crate::host_language::system_keys(&control_set).into_iter().map(seed_of));
        // Os serviços Win32 da cadeia do LSM (`user_services`).
        system.extend(crate::user_services::system_keys(&control_set).into_iter().map(seed_of));
        software.extend(crate::user_services::software_keys().into_iter().map(seed_of));
        // As chaves que os serviços do início automático e o LSM leem
        // (`service_chain`).
        system.extend(crate::service_chain::system_keys(&control_set).into_iter().map(seed_of));
        software.extend(crate::service_chain::software_keys().into_iter().map(seed_of));
        default.extend(crate::host_language::default_keys().into_iter().map(seed_of));
        // E a SOFTWARE, os assemblies lado a lado do contexto de ativação
        // padrão do sistema e dos controles comuns (`side_by_side`), as
        // fontes da sessão (`fonts`) e as classes COM e WinRT que o LogonUI
        // ativa (`logon_screen`).
        software.extend(crate::side_by_side::software_keys(&crate::windows_binaries::windows_directory()).into_iter().map(seed_of));
        software.extend(crate::fonts::software_keys().into_iter().map(seed_of));
        software.extend(crate::logon_screen::software_keys().into_iter().map(seed_of));
    }
    let hives: [(&'static str, Vec<cm::seed::SeedKey>); 5] = [
        ("SYSTEM", system),
        ("SOFTWARE", software),
        ("SAM", cm::seed::sam_keys()),
        ("SECURITY", cm::seed::security_keys()),
        ("DEFAULT", default),
    ];
    hives.into_iter().map(|(name, seeds)| (name, hive_from_seeds(seeds, &format!("\\SystemRoot\\System32\\config\\{name}")))).collect()
}

#[cfg(test)]
mod tests {
    use super::{cm, hive_from_seeds, HBLOCK, MAX_LEAF, SPLIT_LEAF};

    fn u16_at(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
    }

    fn u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    /// Os dados de uma célula (depois do tamanho).
    fn cell(index: u32) -> usize {
        HBLOCK + index as usize + 4
    }

    /// O nome comprimido de uma 'nk'.
    fn name(hive: &[u8], nk: u32) -> String {
        let at = cell(nk);
        let length = u16_at(hive, at + 0x48) as usize;
        String::from_utf8(hive[at + 0x4c..at + 0x4c + length].to_vec()).unwrap()
    }

    /// Uma chave com mais subchaves que uma folha leva uma raiz 'ri' com
    /// folhas 'lh' em ordem, como o CmpAddSubKeyEx deixa depois de dividir.
    #[test]
    fn many_subkeys_go_under_an_index_root() {
        let total = MAX_LEAF + 100;
        let seeds: Vec<cm::seed::SeedKey> = (0..total).map(|number| cm::seed::SeedKey::new(&format!("Many\\Key{number:05}"))).collect();
        let hive = hive_from_seeds(seeds, "TEST");
        let root = u32_at(&hive, 0x24);
        let many = u32_at(&hive, cell(u32_at(&hive, cell(root) + 0x1c)) + 4);
        assert_eq!(name(&hive, many), "Many");
        assert_eq!(u32_at(&hive, cell(many) + 0x14) as usize, total);
        let list = cell(u32_at(&hive, cell(many) + 0x1c));
        assert_eq!(&hive[list..list + 2], b"ri");
        let leaves = u16_at(&hive, list + 2) as usize;
        assert_eq!(leaves, total.div_ceil(SPLIT_LEAF));
        let mut names = Vec::new();
        for position in 0..leaves {
            let leaf = cell(u32_at(&hive, list + 4 + position * 4));
            assert_eq!(&hive[leaf..leaf + 2], b"lh");
            for entry in 0..u16_at(&hive, leaf + 2) as usize {
                names.push(name(&hive, u32_at(&hive, leaf + 4 + entry * 8)));
            }
        }
        let expected: Vec<String> = (0..total).map(|number| format!("Key{number:05}")).collect();
        assert_eq!(names, expected);
    }
}
