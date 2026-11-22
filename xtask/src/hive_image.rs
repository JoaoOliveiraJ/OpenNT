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
//! - uma célula 'sk' por descritor distinto, com a contagem das chaves que
//!   o usam, numa lista circular que começa na célula da raiz: cada célula
//!   nova entra logo depois da célula do pai da primeira chave que a usa
//!   (CmpInsertSecurityCellList, 0x69e850).
//!
//! Os descritores são os de uma instalação nova (`HiveSecurity`):
//! - a raiz da SOFTWARE, da SYSTEM e da SAM é
//!   `O:BA G:SY D:PAI(A;CI;KR;;;BU)(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;KA;;;CO)(A;CI;KR;;;AC)(A;CI;KR;;;RR)`
//!   (RR é a capacidade registryRead); a da DEFAULT, a mesma com o AC e o RR
//!   sem herança; a da SECURITY, SYSTEM com KEY_ALL_ACCESS e Administradores
//!   com READ_CONTROL | WRITE_DAC, protegida;
//! - uma subchave herda do pai, na forma das chaves de uma instalação nova
//!   (`D:AI(A;CIID;KR;;;BU)…(A;CIIOID;KA;;;CO)…`, dono Administradores e
//!   grupo SYSTEM);
//! - no boot do processo inicial real, uma chave que existe nesta máquina
//!   com um descritor protegido ou com ACEs explícitas leva esse descritor,
//!   sem os SIDs de conta (as chaves de serviço com as ACEs do SID do
//!   serviço, de LocalService e de NetworkService; as do TrustedInstaller
//!   com leitura só para SYSTEM e Administradores).
//!
//! Com o AC (ALL APPLICATION PACKAGES) e o RR, um token LowBox lê o HKLM
//! (as chaves já passam pela checagem de acesso no modo usuário); um token
//! sem BUILTIN\Users perde a leitura, como no 19041.

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
    #[path = "../../../../kernel/src/ntos/cm/file_system.rs"]
    pub mod file_system;
    #[path = "../../../../kernel/src/ntos/cm/time_zone_information.rs"]
    pub mod time_zone_information;
    #[path = "../../../../kernel/src/ntos/cm/network_setup.rs"]
    pub mod network_setup;
    #[path = "../../../../kernel/src/ntos/cm/setup_state.rs"]
    pub mod setup_state;
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

use crate::host_security::descriptor::{self, Ace, Descriptor};

const HBLOCK: usize = 0x1000;
const HBIN_HEADER: usize = 0x20;
const NIL: u32 = 0xFFFF_FFFF;
const MINOR: u32 = 5;
const BIG_SEGMENT: usize = 0x3fd8;
/// Entradas de uma folha de subchaves: o CmpAddSubKeyEx passa a folha com
/// 1013 entradas para baixo de uma raiz 'ri', dividida ao meio.
const MAX_LEAF: usize = 1012;
const SPLIT_LEAF: usize = MAX_LEAF / 2;

/// KEY_READ e KEY_ALL_ACCESS; READ_CONTROL | WRITE_DAC.
const KEY_READ: u32 = 0x0002_0019;
const KEY_ALL_ACCESS: u32 = 0x000F_003F;
const READ_CONTROL_WRITE_DAC: u32 = 0x0006_0000;

/// SYSTEM, Administradores, Usuários, CREATOR OWNER, ALL APPLICATION
/// PACKAGES e a capacidade registryRead (S-1-15-3-1024-…, o SHA-256 de
/// "REGISTRYREAD" do RtlDeriveCapabilitySidsFromName).
fn system() -> Vec<u8> {
    descriptor::sid(5, &[18])
}
fn administrators() -> Vec<u8> {
    descriptor::sid(5, &[32, 544])
}
fn users() -> Vec<u8> {
    descriptor::sid(5, &[32, 545])
}
fn creator_owner() -> Vec<u8> {
    descriptor::sid(3, &[0])
}
fn all_application_packages() -> Vec<u8> {
    descriptor::sid(15, &[2, 1])
}
fn registry_read() -> Vec<u8> {
    descriptor::sid(15, &[3, 1024, 1_065_365_936, 1_281_604_716, 3_511_738_428, 1_654_721_687, 432_734_479, 3_232_135_806, 4_053_264_122, 3_456_934_681])
}

/// A raiz de uma hive de máquina de uma instalação nova:
/// `O:BA G:SY D:PAI(A;CI;KR;;;BU)(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;KA;;;CO)(A;CI;KR;;;AC)(A;CI;KR;;;RR)`.
/// Na DEFAULT (`packages_inherit` falso) o AC e o RR valem só para a raiz.
fn machine_root(packages_inherit: bool) -> Descriptor {
    const CI: u8 = descriptor::CONTAINER_INHERIT;
    let packages = if packages_inherit { CI } else { 0 };
    let aces = vec![
        Ace::new(0, CI, KEY_READ, users()),
        Ace::new(0, CI, KEY_ALL_ACCESS, administrators()),
        Ace::new(0, CI, KEY_ALL_ACCESS, system()),
        Ace::new(0, CI, KEY_ALL_ACCESS, creator_owner()),
        Ace::new(0, packages, KEY_READ, all_application_packages()),
        Ace::new(0, packages, KEY_READ, registry_read()),
    ];
    Descriptor { control: descriptor::SELF_RELATIVE | descriptor::DACL_PROTECTED | descriptor::DACL_AUTO_INHERITED | descriptor::DACL_PRESENT, owner: Some(administrators()), group: Some(system()), sacl: None, dacl: Some((2, aces)) }
}

/// A raiz da SECURITY: SYSTEM com KEY_ALL_ACCESS e Administradores com
/// READ_CONTROL | WRITE_DAC, protegida (o padrão conhecido; a hive desta
/// máquina não se lê sem elevação).
fn security_root() -> Descriptor {
    const CI: u8 = descriptor::CONTAINER_INHERIT;
    let aces = vec![Ace::new(0, CI, KEY_ALL_ACCESS, system()), Ace::new(0, CI, READ_CONTROL_WRITE_DAC, administrators())];
    Descriptor { control: descriptor::SELF_RELATIVE | descriptor::DACL_PROTECTED | descriptor::DACL_PRESENT, owner: Some(system()), group: Some(system()), sacl: None, dacl: Some((2, aces)) }
}

/// Onde uma hive do convidado está nesta máquina, para os descritores
/// próprios das chaves no boot do processo inicial real.
#[derive(Clone, Copy)]
enum HostHive {
    System,
    Software,
    Default,
}

/// Os descritores das chaves de uma hive: o da raiz e, no boot do processo
/// inicial real, a hive desta máquina de onde vêm os descritores próprios.
struct HiveSecurity {
    root: Descriptor,
    host: Option<HostHive>,
}

/// O descritor próprio desta máquina da chave `path` (relativa à raiz da
/// hive), sem os SIDs de conta: só quando é protegido ou tem ACEs
/// explícitas; os outros herdam do pai no convidado.
#[cfg(windows)]
fn host_key_descriptor(hive: HostHive, path: &str) -> Option<Descriptor> {
    use crate::host_language::registry;
    let control_set = format!("ControlSet{:03}", cm::seed::CURRENT_CONTROL_SET);
    let (root, host) = match hive {
        HostHive::System => match path.split_once('\\') {
            Some((first, rest)) if first.eq_ignore_ascii_case(&control_set) => (registry::LOCAL_MACHINE, format!("SYSTEM\\CurrentControlSet\\{rest}")),
            _ if path.eq_ignore_ascii_case(&control_set) => (registry::LOCAL_MACHINE, String::from("SYSTEM\\CurrentControlSet")),
            _ => (registry::LOCAL_MACHINE, format!("SYSTEM\\{path}")),
        },
        HostHive::Software => (registry::LOCAL_MACHINE, format!("SOFTWARE\\{path}")),
        HostHive::Default => (registry::USERS, format!(".DEFAULT\\{path}")),
    };
    let mut own = Descriptor::parse(&crate::host_security::key_security_of(root, &host)?)?;
    if own.dacl.is_none() || !(own.dacl_protected() || own.has_explicit_aces()) {
        return None;
    }
    own.remove_accounts();
    Some(own)
}

#[cfg(not(windows))]
fn host_key_descriptor(_hive: HostHive, _path: &str) -> Option<Descriptor> {
    None
}

/// O descritor de cada chave (no índice de `keys`), em pré-ordem: a raiz,
/// o próprio desta máquina ou o herdado do pai.
fn key_descriptors(keys: &[Key], security: &HiveSecurity) -> Vec<Vec<u8>> {
    let mut descriptors: Vec<Option<Descriptor>> = vec![None; keys.len()];
    let mut stack = vec![(0usize, None::<usize>, String::new())];
    while let Some((index, parent, path)) = stack.pop() {
        let descriptor = match parent {
            None => security.root.clone(),
            Some(parent) => {
                let own = security.host.and_then(|hive| host_key_descriptor(hive, &path));
                match (own, &descriptors[parent]) {
                    (Some(own), _) => own,
                    (None, Some(parent)) => descriptor::inherited_key(parent),
                    (None, None) => security.root.clone(),
                }
            }
        };
        descriptors[index] = Some(descriptor);
        for &child in keys[index].children.values() {
            let child_path = if path.is_empty() { keys[child].name.clone() } else { format!("{path}\\{}", keys[child].name) };
            stack.push((child, Some(index), child_path));
        }
    }
    descriptors.into_iter().map(|descriptor| descriptor.map(|descriptor| descriptor.to_bytes()).unwrap_or_default()).collect()
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

    fn get32(&self, cell: u32, offset: usize) -> u32 {
        let at = cell as usize + 4 + offset;
        u32::from_le_bytes(self.data[at..at + 4].try_into().unwrap())
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

/// Grava a árvore (a primeira chave é a raiz), com o descritor
/// autorrelativo de cada chave em `security` (no índice de `keys`), e
/// devolve o arquivo inteiro.
fn write_hive(keys: &[Key], security: &[Vec<u8>], time: u64, file_name: &str) -> Vec<u8> {
    let mut bins = Bins { data: Vec::new(), bin_start: 0 };
    let mut cells = vec![NIL; keys.len()];
    // A 'sk' de cada chave e, por descritor distinto, a célula e a contagem.
    let mut key_sk = vec![NIL; keys.len()];
    let mut sks: BTreeMap<&[u8], (u32, u32)> = BTreeMap::new();
    // Pré-ordem com o pai de cada chave.
    let mut order = Vec::new();
    let mut stack = vec![(0usize, None::<usize>)];
    while let Some((index, parent)) = stack.pop() {
        order.push((index, parent));
        for &child in keys[index].children.values().rev() {
            stack.push((child, Some(index)));
        }
    }
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
        // Segurança: a 'sk' do descritor da chave, se já existe, com mais
        // uma referência; senão uma célula nova, na lista circular logo
        // depois da 'sk' do pai (a da raiz aponta para si mesma).
        let descriptor = security[index].as_slice();
        let sk = match sks.get_mut(descriptor) {
            Some((sk, count)) => {
                *count += 1;
                *sk
            }
            None => {
                let sk = bins.cell(0x14 + descriptor.len());
                bins.put(sk, 0, b"sk");
                bins.put32(sk, 0x10, descriptor.len() as u32);
                bins.put(sk, 0x14, descriptor);
                match parent.map(|parent| key_sk[parent]) {
                    Some(anchor) if anchor != NIL => {
                        let next = bins.get32(anchor, 4);
                        bins.put32(sk, 4, next);
                        bins.put32(sk, 8, anchor);
                        bins.put32(anchor, 4, sk);
                        bins.put32(next, 8, sk);
                    }
                    _ => {
                        bins.put32(sk, 4, sk);
                        bins.put32(sk, 8, sk);
                    }
                }
                sks.insert(descriptor, (sk, 1));
                sk
            }
        };
        key_sk[index] = sk;
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
    // A contagem de cada 'sk': as chaves que a usam.
    for &(sk, count) in sks.values() {
        bins.put32(sk, 0xc, count);
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

/// O ActiveTimeBias da hive SYSTEM (UTC − hora local, em minutos): o
/// relógio da máquina virtual guarda a hora local desse fuso.
pub fn active_time_bias_minutes() -> i32 {
    cm::time_zone_information::ACTIVE_TIME_BIAS
}

/// Uma hive com as chaves das tabelas de semente (caminhos relativos à
/// raiz, que se chama ROOT) e os descritores de `security`.
fn hive_from_seeds(seeds: Vec<cm::seed::SeedKey>, file_name: &str, security: &HiveSecurity) -> Vec<u8> {
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
    let descriptors = key_descriptors(&keys, security);
    // A hora da última escrita de toda chave e do cabeçalho é a da
    // instalação, a mesma dos arquivos do volume: a hive de uma imagem
    // aplicada traz a hora em que a imagem foi feita, e a hora fixa deixa o
    // volume igual entre builds (a chave do primeiro logon feito,
    // `first_logon`, é o hash dele).
    write_hive(&keys, &descriptors, crate::ntfs_image::INSTALL_TIME, file_name)
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
/// do processo inicial real (`--initial-process=smss`). `setup_command`: o
/// gancho de primeiro boot do `--conta-de-teste`.
pub fn machine_hives(smss_boot: bool, system_volume: bool, setup_command: Option<&str>) -> Vec<(&'static str, Vec<u8>)> {
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
        // Os pacotes AppX da caixa que o primeiro logon registra, com os
        // serviços do registro (`inbox_packages`).
        system.extend(crate::inbox_packages::system_keys(&control_set).into_iter().map(seed_of));
        software.extend(crate::inbox_packages::software_keys().into_iter().map(seed_of));
        // A `ProfileList` e o serviço de perfis com o assinante do
        // winlogon (`user_profiles`).
        software.extend(crate::user_profiles::software_keys().into_iter().map(seed_of));
        system.extend(crate::user_profiles::system_keys(&control_set).into_iter().map(seed_of));
        // As chaves que os serviços do início automático e o LSM leem
        // (`service_chain`).
        system.extend(crate::service_chain::system_keys(&control_set).into_iter().map(seed_of));
        // As sessões de autologger do log de eventos, com os provedores do
        // Windows, e o serviço EventLog com os canais (`event_log`).
        system.extend(crate::event_log::system_keys(&control_set).into_iter().map(seed_of));
        software.extend(crate::event_log::software_keys().into_iter().map(seed_of));
        software.extend(crate::service_chain::software_keys().into_iter().map(seed_of));
        default.extend(crate::host_language::default_keys().into_iter().map(seed_of));
        // E a SOFTWARE, os assemblies lado a lado do contexto de ativação
        // padrão do sistema e dos controles comuns (`side_by_side`), as
        // fontes da sessão (`fonts`, com o perfil de hardware do DPI na
        // SYSTEM) e as classes COM e WinRT que o LogonUI ativa
        // (`logon_screen`).
        software.extend(crate::side_by_side::software_keys(&crate::windows_binaries::windows_directory()).into_iter().map(seed_of));
        software.extend(crate::fonts::software_keys().into_iter().map(seed_of));
        system.extend(crate::fonts::system_keys(&control_set).into_iter().map(seed_of));
        software.extend(crate::logon_screen::software_keys().into_iter().map(seed_of));
        // O tema visual que o uxinit do winlogon carrega (`theme`).
        software.extend(crate::theme::software_keys().into_iter().map(seed_of));
        default.extend(crate::theme::default_keys().into_iter().map(seed_of));
        // As preferências do DWM (`window_manager`).
        software.extend(crate::window_manager::software_keys().into_iter().map(seed_of));
        // O gancho de primeiro boot do `--conta-de-teste` (`test_account`),
        // depois do estado de setup: troca o `SetupType` e o `CmdLine`.
        if let Some(command) = setup_command {
            system.extend(crate::test_account::system_keys(command).into_iter().map(seed_of));
        }
    }
    // `--volume-sistema=ntfs.sys` (`system_volume`): o arquivo de paginação
    // no C:, servido pelo ntfs.sys, no lugar do D: do volume do kernel.
    if system_volume {
        for key in system.iter_mut().filter(|key| key.path.ends_with("Session Manager\\Memory Management")) {
            for value in key.values.iter_mut().filter(|value| value.0 == "PagingFiles") {
                value.2 = cm::seed::multi(cm::session_manager::SYSTEM_VOLUME_PAGING_FILES);
            }
        }
    }
    // Os descritores: as raízes de uma instalação nova e, no boot do
    // processo inicial real, os descritores próprios das chaves desta
    // máquina (a SAM e a SECURITY não se leem sem elevação).
    let host = |hive: HostHive| smss_boot.then_some(hive);
    let hives: [(&'static str, Vec<cm::seed::SeedKey>, HiveSecurity); 5] = [
        ("SYSTEM", system, HiveSecurity { root: machine_root(true), host: host(HostHive::System) }),
        ("SOFTWARE", software, HiveSecurity { root: machine_root(true), host: host(HostHive::Software) }),
        ("SAM", cm::seed::sam_keys(), HiveSecurity { root: machine_root(true), host: None }),
        ("SECURITY", cm::seed::security_keys(), HiveSecurity { root: security_root(), host: None }),
        ("DEFAULT", default, HiveSecurity { root: machine_root(false), host: host(HostHive::Default) }),
    ];
    hives.into_iter().map(|(name, seeds, security)| (name, hive_from_seeds(seeds, &format!("\\SystemRoot\\System32\\config\\{name}"), &security))).collect()
}

#[cfg(test)]
mod tests {
    use super::{cm, hive_from_seeds, machine_root, seed_of, HiveSecurity, HBLOCK, MAX_LEAF, SPLIT_LEAF};
    use crate::host_security::descriptor::{self, Descriptor};

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

    /// Os descritores de uma hive de máquina sem os desta máquina.
    fn plain() -> HiveSecurity {
        HiveSecurity { root: machine_root(true), host: None }
    }

    /// A 'nk' da subchave `child` de `parent` (lista 'lh').
    fn child(hive: &[u8], parent: u32, child: &str) -> u32 {
        let list = cell(u32_at(hive, cell(parent) + 0x1c));
        assert_eq!(&hive[list..list + 2], b"lh");
        (0..u16_at(hive, list + 2) as usize).map(|entry| u32_at(hive, list + 4 + entry * 8)).find(|&nk| name(hive, nk).eq_ignore_ascii_case(child)).expect(child)
    }

    /// O descritor da 'sk' de uma 'nk'.
    fn key_descriptor(hive: &[u8], nk: u32) -> Descriptor {
        let sk = cell(u32_at(hive, cell(nk) + 0x2c));
        assert_eq!(&hive[sk..sk + 2], b"sk");
        let length = u32_at(hive, sk + 0x10) as usize;
        Descriptor::parse(&hive[sk + 0x14..sk + 0x14 + length]).unwrap()
    }

    /// Cada descritor distinto numa 'sk', com a contagem das chaves que o
    /// usam e a lista circular a partir da 'sk' da raiz; a raiz com o
    /// descritor de uma instalação nova e os filhos na forma herdada, e
    /// nenhum SID de conta.
    #[test]
    fn keys_get_the_fresh_install_descriptors_in_shared_cells() {
        let seeds: Vec<cm::seed::SeedKey> = ["Services\\disk", "Services\\Tcpip\\Parameters", "Control"].iter().map(|path| cm::seed::SeedKey::new(path)).collect();
        let hive = hive_from_seeds(seeds, "TEST", &plain());
        let root = u32_at(&hive, 0x24);
        assert_eq!(key_descriptor(&hive, root), machine_root(true));
        let services = child(&hive, root, "Services");
        let disk = child(&hive, services, "disk");
        let inherited = descriptor::inherited_key(&machine_root(true));
        assert_eq!(key_descriptor(&hive, disk), inherited);
        assert_eq!(inherited.control, 0x8404);
        // Duas 'sk' (a da raiz e a herdada), em lista circular, com as
        // contagens 1 e 5 (Services, disk, Tcpip, Parameters e Control).
        let root_sk = u32_at(&hive, cell(root) + 0x2c);
        let child_sk = u32_at(&hive, cell(disk) + 0x2c);
        assert_ne!(root_sk, child_sk);
        assert_eq!(u32_at(&hive, cell(services) + 0x2c), child_sk);
        assert_eq!((u32_at(&hive, cell(root_sk) + 4), u32_at(&hive, cell(root_sk) + 8)), (child_sk, child_sk));
        assert_eq!((u32_at(&hive, cell(child_sk) + 4), u32_at(&hive, cell(child_sk) + 8)), (root_sk, root_sk));
        assert_eq!((u32_at(&hive, cell(root_sk) + 0xc), u32_at(&hive, cell(child_sk) + 0xc)), (1, 5));
        for descriptor in [key_descriptor(&hive, root), key_descriptor(&hive, disk)] {
            assert!(descriptor.sids().all(|sid| !descriptor::is_account(sid)));
        }
    }

    /// A raiz da DEFAULT dá aos filhos só Usuários, Administradores, SYSTEM
    /// e CREATOR OWNER: o AC e o RR valem só para a raiz.
    #[test]
    fn default_hive_packages_do_not_inherit() {
        let child = descriptor::inherited_key(&machine_root(false));
        let sids: Vec<Vec<u8>> = child.dacl.unwrap().1.into_iter().filter_map(|ace| ace.sid).collect();
        assert_eq!(sids, vec![descriptor::sid(5, &[32, 545]), descriptor::sid(5, &[32, 544]), descriptor::sid(5, &[18]), descriptor::sid(3, &[0])]);
    }

    /// Uma chave com mais subchaves que uma folha leva uma raiz 'ri' com
    /// folhas 'lh' em ordem, como o CmpAddSubKeyEx deixa depois de dividir.
    #[test]
    fn many_subkeys_go_under_an_index_root() {
        let total = MAX_LEAF + 100;
        let seeds: Vec<cm::seed::SeedKey> = (0..total).map(|number| cm::seed::SeedKey::new(&format!("Many\\Key{number:05}"))).collect();
        let hive = hive_from_seeds(seeds, "TEST", &plain());
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

    /// O valor `name` de `path` como a hive fica: a última semente vence.
    fn seeded<'a>(keys: &'a [cm::seed::SeedKey], path: &str, name: &str) -> Option<(u32, &'a [u8])> {
        keys.iter().rev().filter(|key| key.path.eq_ignore_ascii_case(path)).find_map(|key| key.values.iter().find(|(value, _, _)| value.eq_ignore_ascii_case(name)).map(|(_, kind, data)| (*kind, data.as_slice())))
    }

    /// O boot do processo inicial real é uma instalação concluída: o
    /// winlogon não roda o setup (SetupType 0 e CmdLine vazio), nada está em
    /// setup, OOBE ou auditoria, o OOBEComplete do kernel32 lê o estado pelo
    /// WNF e acha os dados persistidos dos dois nomes do fim do OOBE
    /// (carimbo 1, ULONG 1), e o LogonUI vê o primeiro logon já feito.
    #[test]
    fn smss_boot_hives_are_a_finished_install() {
        let system = cm::seed::system_keys(true);
        let dword = |value: u32| (cm::seed::REG_DWORD, value.to_le_bytes().to_vec());
        for (name, expected) in [("SetupType", 0), ("SystemSetupInProgress", 0), ("OOBEInProgress", 0), ("SetupPhase", 0), ("RestartSetup", 0), ("SetupSupported", 1)] {
            assert_eq!(seeded(&system, "Setup", name).map(|(kind, data)| (kind, data.to_vec())), Some(dword(expected)), "Setup\\{name}");
        }
        assert_eq!(seeded(&system, "Setup", "CmdLine"), Some((cm::seed::REG_SZ, &[0u8, 0][..])));
        assert!(!system.iter().any(|key| key.path.to_lowercase().starts_with("setup\\status") && (key.path.eq_ignore_ascii_case("Setup\\Status\\AuditBootVolatile") || key.values.iter().any(|(name, _, _)| name.eq_ignore_ascii_case("AuditBoot")))));
        let software = cm::seed::software_keys(true);
        let complete = [1u8, 0, 0, 0, 1, 0, 0, 0];
        for name in ["41960B29A3BC0C75", "0D83063EA3BC2475"] {
            assert_eq!(seeded(&software, "Microsoft\\Windows NT\\CurrentVersion\\Notifications\\Data", name), Some((cm::seed::REG_BINARY, &complete[..])), "Notifications\\Data\\{name}");
        }
        assert_eq!(seeded(&software, "Microsoft\\Windows\\CurrentVersion\\OOBE\\Stats", "OOBEUserSignedIn").map(|(kind, data)| (kind, data.to_vec())), Some(dword(1)));
        assert_eq!(seeded(&software, "Microsoft\\Windows\\CurrentVersion\\OOBE", "ProtectYourPC").map(|(kind, data)| (kind, data.to_vec())), Some(dword(3)));
        let image_state: Vec<u8> = "IMAGE_STATE_COMPLETE".encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect();
        assert_eq!(seeded(&software, "Microsoft\\Windows\\CurrentVersion\\Setup\\State", "ImageState"), Some((cm::seed::REG_SZ, image_state.as_slice())));
        // Os outros boots não levam o estado de setup.
        assert!(seeded(&cm::seed::system_keys(false), "Setup", "SetupType").is_none());
        assert!(seeded(&cm::seed::software_keys(false), "Microsoft\\Windows NT\\CurrentVersion\\Notifications\\Data", "41960B29A3BC0C75").is_none());
        let hive = hive_from_seeds(software, "SOFTWARE", &plain());
        assert_eq!(&hive[..4], b"regf");
    }

    /// O `--conta-de-teste` troca só o `SetupType` (2) e o `CmdLine` do estado
    /// de setup; os outros valores ficam os de uma instalação concluída.
    #[test]
    fn the_test_account_hook_replaces_only_the_setup_command() {
        let command = "cmd /d /c net user Usuario /add";
        let mut system = cm::seed::system_keys(true);
        system.extend(crate::test_account::system_keys(command).into_iter().map(seed_of));
        let dword = |value: u32| (cm::seed::REG_DWORD, value.to_le_bytes().to_vec());
        assert_eq!(seeded(&system, "Setup", "SetupType").map(|(kind, data)| (kind, data.to_vec())), Some(dword(2)));
        let text: Vec<u8> = command.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect();
        assert_eq!(seeded(&system, "Setup", "CmdLine"), Some((cm::seed::REG_SZ, text.as_slice())));
        for (name, expected) in [("SystemSetupInProgress", 0), ("OOBEInProgress", 0), ("SetupPhase", 0), ("RestartSetup", 0), ("SetupSupported", 1)] {
            assert_eq!(seeded(&system, "Setup", name).map(|(kind, data)| (kind, data.to_vec())), Some(dword(expected)), "Setup\\{name}");
        }
        assert_eq!(&hive_from_seeds(system, "SYSTEM", &plain())[..4], b"regf");
    }
}
