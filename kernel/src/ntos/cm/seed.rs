//! O conteúdo estático das hives de máquina: as chaves e valores que vêm de
//! tabelas fixas. Na SYSTEM, as chaves de serviço dos drivers que o boot
//! instala, os parâmetros e as classes de dispositivo, a configuração do
//! Session Manager no boot do processo inicial real e o `Select` do
//! conjunto de controle; na SOFTWARE, o que o kernel e os programas reais
//! leem (os CSPs, as Image File Execution Options e, no boot do processo
//! inicial real, o `IniFileMapping` do basesrv); na SAM, na SECURITY e na
//! DEFAULT (`\Registry\User\.DEFAULT`), a estrutura mínima de chaves.
//!
//! É uma fonte só para dois consumidores: o `xtask`, que grava com estas
//! chaves os arquivos de `\SystemRoot\System32\config` do volume, e o
//! kernel, que carrega esses arquivos no boot e só semeia as mesmas chaves
//! em memória quando um arquivo não existe (`cm/hive_init.rs`). Por isso
//! este arquivo e as tabelas que ele reúne (`cm/session_manager.rs`,
//! `cm/ini_file_mapping.rs`, `cm/crypto_defaults.rs`, `cm/arbiters.rs`,
//! `cm/service/boot_services.rs` e `cm/service/inbox_drivers.rs`) são
//! dados puros: não usam nada do kernel e o `xtask` os inclui por `#[path]`
//! na mesma árvore de módulos (`cm`, `cm::service`).
//!
//! Os caminhos são relativos à raiz de cada hive e os dados já vêm
//! codificados como o Registro os guarda (UTF-16LE com NUL, DWORD
//! little-endian, REG_MULTI_SZ com o NUL final extra). As tabelas da SYSTEM
//! nomeiam o conjunto de controle corrente (`CurrentControlSet\...`); a
//! hive o guarda como `ControlSet001`, que o `Select\Current` = 1 escolhe e
//! para onde o link volátil `CurrentControlSet` aponta depois da carga (o
//! CmpCreateControlSet do CmInitSystem1).

use alloc::string::String;
use alloc::vec::Vec;

pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_DWORD: u32 = 4;
pub const REG_LINK: u32 = 6;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_QWORD: u32 = 11;

/// O conjunto de controle que a hive SYSTEM guarda (`Select\Current`).
pub const CURRENT_CONTROL_SET: u32 = 1;
const CONTROL_SET_PREFIX: &str = "CurrentControlSet";

/// Uma chave da hive com os valores (nome, tipo, dados) na ordem de criação.
pub struct SeedKey {
    pub path: String,
    pub values: Vec<(String, u32, Vec<u8>)>,
    /// Chave de link (KEY_SYM_LINK), com o alvo no `SymbolicLinkValue`.
    pub link: bool,
}

impl SeedKey {
    pub fn new(path: &str) -> SeedKey {
        SeedKey { path: String::from(path), values: Vec::new(), link: false }
    }

    /// Uma chave de link para `target` (caminho absoluto do Registro): o
    /// `SymbolicLinkValue` REG_LINK sem o NUL, como o Cm o grava.
    pub fn link(path: &str, target: &str) -> SeedKey {
        let mut key = SeedKey::new(path);
        key.link = true;
        key.value("SymbolicLinkValue", REG_LINK, target.encode_utf16().flat_map(u16::to_le_bytes).collect());
        key
    }

    pub fn value(&mut self, name: &str, value_type: u32, data: Vec<u8>) -> &mut SeedKey {
        self.values.push((String::from(name), value_type, data));
        self
    }

    pub fn text(&mut self, name: &str, value_type: u32, text: &str) -> &mut SeedKey {
        self.value(name, value_type, wide(text))
    }

    pub fn dword(&mut self, name: &str, value: u32) -> &mut SeedKey {
        self.value(name, REG_DWORD, value.to_le_bytes().to_vec())
    }

    pub fn strings(&mut self, name: &str, strings: &[&str]) -> &mut SeedKey {
        self.value(name, REG_MULTI_SZ, multi(strings))
    }
}

/// UTF-16LE com NUL.
pub fn wide(text: &str) -> Vec<u8> {
    text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
}

/// REG_MULTI_SZ: cada texto com NUL e o NUL final.
pub fn multi(strings: &[&str]) -> Vec<u8> {
    let mut data: Vec<u8> = strings.iter().flat_map(|text| wide(text)).collect();
    data.extend_from_slice(&[0, 0]);
    data
}

/// `CurrentControlSet\X` da tabela vira `ControlSet001\X` na hive.
fn in_control_set(mut key: SeedKey) -> SeedKey {
    let components: Vec<&str> = key.path.split('\\').collect();
    if components.first().is_some_and(|first| first.eq_ignore_ascii_case(CONTROL_SET_PREFIX)) {
        let mut path = alloc::format!("ControlSet{CURRENT_CONTROL_SET:03}");
        for component in &components[1..] {
            path.push('\\');
            path.push_str(component);
        }
        key.path = path;
    }
    key
}

/// As chaves estáticas da hive SYSTEM, na ordem em que o boot as cria.
/// `smss_boot`: o boot do processo inicial real (`--initial-process=smss`).
pub fn system_keys(smss_boot: bool) -> Vec<SeedKey> {
    let mut keys = super::service::boot_services::driver_keys();
    keys.extend(super::service::inbox_drivers::seed_keys(smss_boot));
    keys.extend(super::service::boot_services::parameter_keys());
    keys.extend(super::arbiters::seed_keys());
    keys.extend(super::pnp_control::seed_keys());
    keys.extend(super::crash_control::seed_keys());
    if smss_boot {
        keys.extend(super::session_manager::seed_keys());
    }
    // Control\Windows: onde o ExpRecordShutdownTime grava o ShutdownTime de
    // cada desligamento.
    keys.push(SeedKey::new("CurrentControlSet\\Control\\Windows"));
    let mut keys: Vec<SeedKey> = keys.into_iter().map(in_control_set).collect();
    // Select: o conjunto corrente, o padrão, o que falhou (nenhum) e o
    // último bom, que o CmpCreateControlSet lê.
    let mut select = SeedKey::new("Select");
    select.dword("Current", CURRENT_CONTROL_SET).dword("Default", CURRENT_CONTROL_SET).dword("Failed", 0).dword("LastKnownGood", CURRENT_CONTROL_SET);
    keys.push(select);
    keys
}

/// A hive SOFTWARE: os CSPs que o advapi32/crypt32 leem, as Image File
/// Execution Options que o loader da ntdll consulta a cada processo e, no
/// boot do processo inicial real, o `IniFileMapping` que o basesrv.dll lê e
/// a chave SideBySide do sxssrv.dll.
pub fn software_keys(smss_boot: bool) -> Vec<SeedKey> {
    let mut keys = super::crypto_defaults::seed_keys();
    keys.push(SeedKey::new("Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"));
    if smss_boot {
        keys.extend(super::ini_file_mapping::seed_keys());
        // O sxssrv.dll do csrss abre Microsoft\Windows\CurrentVersion\SideBySide
        // na inicialização e lê o PublisherPolicyChangeTime (REG_QWORD; o
        // valor desta máquina); sem a chave o csrss termina.
        let mut side_by_side = SeedKey::new("Microsoft\\Windows\\CurrentVersion\\SideBySide");
        side_by_side.value("PublisherPolicyChangeTime", REG_QWORD, 0x01DD_6663_5F9A_F0F7u64.to_le_bytes().to_vec());
        keys.push(side_by_side);
    }
    keys
}

/// A hive SAM: o banco de contas, com os domínios Account e Builtin vazios.
pub fn sam_keys() -> Vec<SeedKey> {
    ["SAM\\Domains\\Account", "SAM\\Domains\\Builtin", "SAM\\RXACT"].iter().map(|path| SeedKey::new(path)).collect()
}

/// A hive SECURITY: a política da LSA e o `SAM`, um link para a raiz do
/// banco de contas da hive SAM.
pub fn security_keys() -> Vec<SeedKey> {
    alloc::vec![SeedKey::new("Policy"), SeedKey::new("RXACT"), SeedKey::link("SAM", "\\REGISTRY\\MACHINE\\SAM\\SAM")]
}

/// A hive DEFAULT (`\Registry\User\.DEFAULT`): o perfil do sistema, com as
/// chaves de topo vazias.
pub fn default_keys() -> Vec<SeedKey> {
    ["Control Panel", "Environment", "Software"].iter().map(|path| SeedKey::new(path)).collect()
}
