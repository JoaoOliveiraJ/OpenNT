//! Os perfis de usuário que uma instalação nova do Windows tem antes do
//! primeiro logon, no volume do boot do processo inicial real
//! (`--initial-process=smss`): `\Users` com o `desktop.ini` (o nome
//! localizado da pasta), o perfil padrão `\Users\Default` (a árvore de
//! pastas, o `NTUSER.DAT` com o `.LOG1` e o `.LOG2`), que o serviço de
//! perfis copia para o perfil de cada conta nova, e o perfil público
//! `\Users\Public`, cada pasta e arquivo com os atributos (oculto, sistema,
//! somente leitura das pastas personalizadas) e o descritor de segurança
//! (dono, grupo e DACL) daqui. E, na SOFTWARE, a `ProfileList`: os
//! diretórios de uma instalação nova (`ProfilesDirectory`, `Default`,
//! `Public` e `ProgramData`, que o wininit lê para o `%ProgramData%` e as
//! outras variáveis do sistema e o serviço de perfis para achar o perfil
//! padrão) e os perfis das contas de serviço (S-1-5-18, -19 e -20), e as
//! definições das pastas conhecidas (`Explorer\FolderDescriptions`). Na
//! SYSTEM, o serviço de perfis (ProfSvc, [`system_keys`]); o assinante
//! `Profiles` das notificações do winlogon, por onde o perfil de uma conta é
//! carregado no logon, vem com a chave `Control\Winlogon\Notifications`
//! inteira (`service_chain`). Os DLLs do serviço vão para o volume com os
//! outros serviços (`windows_binaries`).
//!
//! A origem é o `C:\Users` desta máquina, sem perfil de conta nenhum:
//! - do `\Users` só a pasta, o `desktop.ini` e as junções que apontam para o
//!   `ProgramData` e para o perfil padrão (os nomes antigos `All Users` e
//!   `Default User`, também localizados); as outras pastas são perfis de
//!   conta e ficam fora;
//! - o `Default` inteiro, menos os logs do gerenciador de transações do
//!   Registro (`NTUSER.DAT{guid}.TM.blf` e os `.regtrans-ms`), que o kernel
//!   cria quando carrega a hive;
//! - do `Public` só o que uma instalação nova tem (`PUBLIC_ENTRIES`): as
//!   pastas conhecidas com o `desktop.ini` de cada uma e a biblioteca
//!   `RecordedTV`. Os atalhos que os programas instalam na área de trabalho
//!   pública, os arquivos que alguém pôs nas pastas públicas e o
//!   `AccountPictures` (criado quando uma conta escolhe a imagem, com a conta
//!   como dona) ficam fora. O DACL do `Public\Desktop` é o da definição da
//!   pasta conhecida (o valor `Security` de
//!   `Explorer\FolderDescriptions\{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}`,
//!   o descritor com que o shell cria a pasta), e os filhos herdam dele.
//!
//! Nenhum descritor leva SID de conta (de domínio, S-1-5-21-…, de sessão
//! de logon, S-1-5-5-…, ou do Azure AD, S-1-12-1-…): a ACE com um sai, o
//! dono ou o grupo vira Administradores ou SYSTEM, e os filhos voltam a
//! herdar do pai corrigido (`inherited_aces`, a herança do NTFS: o
//! mapeamento genérico e o CREATOR OWNER na ACE efetiva, a cópia só de
//! herança para os netos). E nenhum arquivo leva marca das contas desta
//! máquina (`account_markers`: o SID de cada perfil de conta da
//! `ProfileList`, em texto e binário, o prefixo de domínio desses SIDs com
//! qualquer RID, o caminho do perfil e o nome da conta, o nome do
//! computador e os endereços MAC dos adaptadores): um arquivo com a marca
//! fica fora com um aviso, que não mostra a marca. Se for o `NTUSER.DAT`, a
//! hive padrão desta máquina tem dados de conta (há ferramentas que
//! escrevem nela) e o volume leva só as pastas: a hive precisa então ser
//! gerada limpa.
//!
//! As chaves copiadas daqui passam pelo mesmo filtro (`without_account_data`):
//! um descritor binário perde os SIDs de conta, e um valor com SID de conta
//! em texto ou binário fica fora com um aviso (só o caminho e o nome do
//! valor). O serviço de perfis só entra com a conta LocalSystem.
//!
//! As junções do perfil (os nomes antigos, como `Application Data`,
//! `Cookies` ou `My Documents`, localizados no idioma da instalação, e os
//! `My Music`, `My Pictures` e `My Videos` dos documentos públicos) ficam
//! fora do volume até o kernel tratar pontos de reanálise; [`Profiles`] as
//! lista com o destino, os atributos e o descritor de cada uma, e os
//! destinos estão no volume como pastas comuns.
//!
//! Fora do Windows nada é copiado.

use crate::host_language::HostKey;
use crate::host_security::{descriptor, settle as settle_descriptor};
use crate::ntfs_image::Node;

/// Uma junção do perfil que o volume ainda não leva: o caminho no volume,
/// o destino (o caminho DOS, como `C:\Users\Default\AppData\Roaming`), os
/// atributos e o descritor da própria junção.
pub struct Junction {
    pub path: String,
    pub target: String,
    pub attributes: u32,
    pub security: Option<Vec<u8>>,
}

/// O que vai para o volume: os arquivos, os metadados de cada pasta e
/// arquivo, e as junções pendentes.
#[derive(Default)]
pub struct Profiles {
    pub files: Vec<(String, Vec<u8>)>,
    pub nodes: Vec<Node>,
    pub junctions: Vec<Junction>,
}

/// A `ProfileList` na SOFTWARE (relativa à raiz da hive).
const PROFILE_LIST: &str = "Microsoft\\Windows NT\\CurrentVersion\\ProfileList";

/// Os perfis das contas de serviço: SYSTEM, LocalService e NetworkService.
const SERVICE_ACCOUNTS: &[&str] = &["S-1-5-18", "S-1-5-19", "S-1-5-20"];

/// Os diretórios da `ProfileList` de uma instalação nova (REG_EXPAND_SZ):
/// o volume tem os perfis nesses caminhos.
const PROFILE_DIRECTORIES: &[(&str, &str)] = &[
    ("Default", "%SystemDrive%\\Users\\Default"),
    ("ProfilesDirectory", "%SystemDrive%\\Users"),
    ("ProgramData", "%SystemDrive%\\ProgramData"),
    ("Public", "%SystemDrive%\\Users\\Public"),
];

/// O que o perfil público de uma instalação nova tem (relativo a
/// `\Users\Public`): o `desktop.ini`, as pastas conhecidas (área de
/// trabalho, documentos, downloads, bibliotecas, músicas, imagens e
/// vídeos) com o `desktop.ini` de cada uma, e a biblioteca `RecordedTV`.
/// As junções dos documentos públicos entram pela pasta que as contém.
const PUBLIC_ENTRIES: &[&str] = &[
    "desktop.ini",
    "Desktop",
    "Desktop/desktop.ini",
    "Documents",
    "Documents/desktop.ini",
    "Downloads",
    "Downloads/desktop.ini",
    "Libraries",
    "Libraries/desktop.ini",
    "Libraries/RecordedTV.library-ms",
    "Music",
    "Music/desktop.ini",
    "Pictures",
    "Pictures/desktop.ini",
    "Videos",
    "Videos/desktop.ini",
];

/// As pastas cujo DACL vem da definição da pasta conhecida, não do
/// descritor desta máquina: (caminho no volume, KNOWNFOLDERID).
const KNOWN_FOLDER_DACLS: &[(&str, &str)] = &[("Users/Public/Desktop", "{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}")];

/// UTF-16LE terminado em NUL, como o Registro guarda um REG_SZ.
fn registry_string(text: &str) -> Vec<u8> {
    text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
}

/// O texto de um REG_SZ (UTF-16LE até o primeiro NUL).
#[cfg_attr(not(windows), allow(dead_code))]
fn registry_text(data: &[u8]) -> String {
    let units: Vec<u16> = data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
    String::from_utf16_lossy(&units)
}

/// As contas com que um serviço copiado daqui pode rodar: um `ObjectName`
/// de outra conta (`.\usuario`) é desta máquina.
#[cfg_attr(not(windows), allow(dead_code))]
const SERVICE_OBJECT_NAMES: &[&str] = &["LocalSystem", "NT AUTHORITY\\LocalService", "NT AUTHORITY\\NetworkService"];

/// As definições das pastas conhecidas na SOFTWARE (relativas à raiz da
/// hive).
#[cfg_attr(not(windows), allow(dead_code))]
const FOLDER_DESCRIPTIONS: &str = "Microsoft\\Windows\\CurrentVersion\\Explorer\\FolderDescriptions";

/// As chaves da hive SOFTWARE: a `ProfileList` com os diretórios de uma
/// instalação nova e, desta máquina, os perfis das contas de serviço (os
/// perfis das contas desta máquina ficam de fora), a configuração do
/// grupo `netsvcs` do svchost do serviço de perfis (a segurança do COM e a
/// política de desempacotamento que o svchost aplica ao subir o grupo) e as
/// definições das pastas conhecidas (`Explorer\FolderDescriptions`: o nome,
/// o `RelativePath`, a pasta pai e o `Security` de cada KNOWNFOLDERID), que
/// o serviço de perfis lê ao criar as pastas do perfil novo (profsvc
/// EnsureKnownFolderCreated, 0x4364) e por onde o shell resolve cada pasta
/// conhecida. Tudo o que vem daqui passa por [`without_account_data`].
pub fn software_keys() -> Vec<HostKey> {
    let values = PROFILE_DIRECTORIES.iter().map(|(name, path)| (String::from(*name), 2, registry_string(path))).collect();
    #[allow(unused_mut)]
    let mut keys = vec![HostKey { path: String::from(PROFILE_LIST), values }];
    #[cfg(windows)]
    {
        use crate::host_language::registry;
        for account in SERVICE_ACCOUNTS {
            registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{PROFILE_LIST}\\{account}"), &format!("{PROFILE_LIST}\\{account}"), true, &mut keys);
        }
        let netsvcs = "Microsoft\\Windows NT\\CurrentVersion\\Svchost\\netsvcs";
        registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{netsvcs}"), netsvcs, true, &mut keys);
        registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{FOLDER_DESCRIPTIONS}"), FOLDER_DESCRIPTIONS, true, &mut keys);
        without_account_data(&mut keys, 1);
    }
    keys
}

/// As chaves da hive SYSTEM (no conjunto de controle `control_set`, como
/// `ControlSet001`): o serviço de perfis (`Services\ProfSvc` com os
/// `Parameters`: o profsvc.dll no `svchost.exe -k netsvcs -p`, conta
/// LocalSystem, início automático). O assinante `Profiles` das
/// notificações do winlogon (o componente com o ServiceName ProfSvc e os
/// eventos Logon e Logoff, e a ordem de cada evento em
/// `Configurations\Default`) vem com a chave `Control\Winlogon\Notifications`
/// inteira (`service_chain::system_keys`). No logon, o winlogon chama cada
/// assinante do evento pelo RPC do serviço dele, que ele inicia se preciso;
/// é assim que o perfil da conta é carregado. O serviço só entra com uma
/// conta de `SERVICE_OBJECT_NAMES`, e passa por [`without_account_data`].
pub fn system_keys(control_set: &str) -> Vec<HostKey> {
    #[allow(unused_mut)]
    let mut keys = Vec::new();
    #[cfg(windows)]
    {
        use crate::host_language::registry;
        let host = "SYSTEM\\CurrentControlSet";
        registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Services\\ProfSvc"), &format!("{control_set}\\Services\\ProfSvc"), true, &mut keys);
        // O serviço de perfis roda como LocalSystem em toda instalação; sem
        // ObjectName também (o padrão do SCM). Outra conta fica fora com o
        // serviço inteiro.
        let service = format!("{control_set}\\Services\\ProfSvc");
        let object_name = keys.iter().find(|key| key.path == service).and_then(|key| key.values.iter().find(|(name, _, _)| name.eq_ignore_ascii_case("ObjectName"))).map(|(_, _, data)| registry_text(data));
        if object_name.is_some_and(|name| !SERVICE_OBJECT_NAMES.iter().any(|known| known.eq_ignore_ascii_case(&name))) {
            println!("AVISO: Services\\ProfSvc roda com uma conta desta maquina (ObjectName); o servico de perfis fica fora");
            keys.clear();
        }
        // O assinante Profiles de Control\Winlogon\Notifications vem com a
        // chave inteira (`service_chain::system_keys`).
        without_account_data(&mut keys, 0);
    }
    #[cfg(not(windows))]
    let _ = control_set;
    keys
}

/// Se o componente de caminho `name` é um SID de conta em texto (a
/// subchave de uma conta, como as de `ProfileService\References`).
#[cfg_attr(not(windows), allow(dead_code))]
fn is_account_name(name: &str) -> bool {
    descriptor::sid_from_text(name).is_some_and(|sid| descriptor::is_account(&sid))
}

/// Se `data` tem um SID de conta: em binário (um SID inteiro de revisão 1
/// com [`descriptor::is_account`] em qualquer posição) ou em texto
/// (`S-1-5-21-`, `S-1-5-5-` ou `S-1-12-`, em bytes simples ou UTF-16LE, sem
/// diferença de caixa).
#[cfg_attr(not(windows), allow(dead_code))]
fn has_account_sid(data: &[u8]) -> bool {
    if (0..data.len()).any(|at| data[at] == 1 && descriptor::sid_at(data, at).is_some_and(|sid| descriptor::is_account(&sid))) {
        return true;
    }
    let text: Vec<Vec<u8>> = ["S-1-5-21-", "S-1-5-5-", "S-1-12-"].iter().flat_map(|prefix| text_markers(prefix)).collect();
    contains_marker(data, &text, &[])
}

/// Tira das chaves copiadas desta máquina (`keys[first..]`) os dados de
/// conta: uma subchave cujo caminho tem um SID de conta sai inteira; um
/// REG_BINARY que é um descritor autorrelativo perde as ACEs, o dono e o
/// grupo de conta (`remove_accounts`); qualquer outro valor com SID de
/// conta (o texto SDDL de um `Security`, um SID binário) sai. Cada retirada
/// deixa um aviso com o caminho e o nome do valor, nunca o dado.
#[cfg_attr(not(windows), allow(dead_code))]
fn without_account_data(keys: &mut Vec<HostKey>, first: usize) {
    let mut index = 0;
    keys.retain(|key| {
        index += 1;
        let kept = index <= first || !key.path.split('\\').any(is_account_name);
        if !kept {
            println!("AVISO: chave com SID de conta no caminho fica fora");
        }
        kept
    });
    for key in keys.iter_mut().skip(first) {
        let path = key.path.clone();
        key.values.retain_mut(|(name, kind, data)| {
            if *kind == 3 {
                if let Some(mut parsed) = descriptor::Descriptor::parse(data) {
                    if parsed.remove_accounts() {
                        *data = parsed.to_bytes();
                    }
                }
            }
            if has_account_sid(data) {
                println!("AVISO: {path}\\{name}: SID de conta no valor; o valor fica fora");
                return false;
            }
            true
        });
    }
}

/// A lista das junções pendentes, uma por linha: o caminho no volume, o
/// destino, os atributos e o descritor da junção em hexadecimal.
pub fn junction_report(junctions: &[Junction]) -> String {
    let mut report = String::new();
    for junction in junctions {
        let security: String = junction.security.as_deref().unwrap_or_default().iter().map(|byte| format!("{byte:02x}")).collect();
        report.push_str(&format!("{}\t{}\t0x{:x}\t{security}\n", junction.path, junction.target, junction.attributes));
    }
    report
}

/// Os perfis desta máquina para o volume.
pub fn stage() -> Profiles {
    #[cfg(windows)]
    {
        host::stage()
    }
    #[cfg(not(windows))]
    {
        Profiles::default()
    }
}

/// Se `relative` (relativo a `C:\Users`, com `/`; `junction` se é uma
/// junção) fica fora do volume.
fn excluded(relative: &str, junction: bool) -> bool {
    let (parent, leaf) = relative.rsplit_once('/').unwrap_or(("", relative));
    let lower = leaf.to_ascii_lowercase();
    if parent.eq_ignore_ascii_case("Default") && lower.starts_with("ntuser.dat{") && (lower.ends_with(".blf") || lower.ends_with(".regtrans-ms")) {
        return true;
    }
    let kept = |path: &str| PUBLIC_ENTRIES.iter().any(|entry| entry.eq_ignore_ascii_case(path));
    match relative.split_once('/') {
        Some((top, rest)) if top.eq_ignore_ascii_case("Public") => !(kept(rest) || junction && rest.rsplit_once('/').is_some_and(|(folder, _)| kept(folder))),
        _ => false,
    }
}

/// O destino de uma junção sem o prefixo do namespace NT (`\??\`) ou do
/// Win32 (`\\?\`).
fn junction_target(raw: &str) -> String {
    let trimmed = raw.strip_prefix("\\??\\").or_else(|| raw.strip_prefix("\\\\?\\")).unwrap_or(raw);
    String::from(trimmed)
}

/// Se `haystack` contém alguma das marcas: as de texto sem diferença de
/// caixa nas letras ASCII (vale para UTF-16LE e para bytes simples), as
/// binárias exatas.
fn contains_marker(haystack: &[u8], text: &[Vec<u8>], binary: &[Vec<u8>]) -> bool {
    let found = |data: &[u8], needle: &[u8]| !needle.is_empty() && data.windows(needle.len()).any(|window| window == needle);
    if binary.iter().any(|needle| found(haystack, needle)) {
        return true;
    }
    let lower = haystack.to_ascii_lowercase();
    text.iter().any(|needle| found(&lower, &needle.to_ascii_lowercase()))
}

/// Marcas de texto de `text`: em bytes simples e em UTF-16LE.
fn text_markers(text: &str) -> [Vec<u8>; 2] {
    [text.as_bytes().to_vec(), text.encode_utf16().flat_map(u16::to_le_bytes).collect()]
}

#[cfg(windows)]
mod host {
    //! A leitura do `C:\Users` desta máquina.

    use super::descriptor::{self, Descriptor};
    use super::{Junction, Node, Profiles};
    use crate::host_language::registry;
    use crate::host_security::{from_sddl, security_of};
    use std::fs;
    use std::os::windows::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

    /// O DACL da definição da pasta conhecida (`Security` em
    /// `Explorer\FolderDescriptions\<id>`).
    fn known_folder_dacl(id: &str) -> Option<Descriptor> {
        let path = format!("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FolderDescriptions\\{id}");
        let text = registry::strings(registry::LOCAL_MACHINE, &path, "Security").into_iter().next()?;
        Descriptor::parse(&from_sddl(&text)?)
    }

    /// Um nome com menos caracteres que isto não vira marca sozinho: em
    /// bytes simples, três letras aparecem por acaso em qualquer arquivo
    /// binário grande (a hive padrão ficaria fora sem motivo). O caminho
    /// `\Users\<nome>` continua marca para qualquer nome.
    const MIN_NAME_MARKER: usize = 4;

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetAdaptersAddresses(family: u32, flags: u32, reserved: *mut core::ffi::c_void, addresses: *mut u8, size: *mut u32) -> u32;
    }

    /// O começo do IP_ADAPTER_ADDRESSES_LH (x64), até o endereço físico.
    #[repr(C)]
    #[allow(dead_code)]
    struct AdapterAddresses {
        length: u32,
        if_index: u32,
        next: *const AdapterAddresses,
        adapter_name: *const u8,
        first_unicast: *const u8,
        first_anycast: *const u8,
        first_multicast: *const u8,
        first_dns_server: *const u8,
        dns_suffix: *const u16,
        description: *const u16,
        friendly_name: *const u16,
        physical_address: [u8; 8],
        physical_address_length: u32,
    }

    /// Os endereços MAC (6 bytes) dos adaptadores desta máquina, também os
    /// desligados: um atalho guarda o MAC no droid do TrackerDataBlock.
    fn mac_addresses() -> Vec<Vec<u8>> {
        // AF_UNSPEC; GAA_FLAG_SKIP_UNICAST, _ANYCAST, _MULTICAST e
        // _DNS_SERVER, e GAA_FLAG_INCLUDE_ALL_INTERFACES.
        const FLAGS: u32 = 0x0F | 0x100;
        const ERROR_BUFFER_OVERFLOW: u32 = 111;
        let mut size = 16 * 1024u32;
        let mut buffer: Vec<u64> = Vec::new();
        let mut filled = false;
        for _ in 0..4 {
            buffer = vec![0u64; (size as usize).div_ceil(8)];
            // SAFETY: buffer alinhado a 8 com pelo menos `size` bytes.
            let status = unsafe { GetAdaptersAddresses(0, FLAGS, core::ptr::null_mut(), buffer.as_mut_ptr().cast(), &mut size) };
            if status == 0 {
                filled = true;
                break;
            }
            if status != ERROR_BUFFER_OVERFLOW {
                break;
            }
        }
        let mut macs: Vec<Vec<u8>> = Vec::new();
        if !filled {
            println!("AVISO: GetAdaptersAddresses falhou; os enderecos MAC nao entram nas marcas");
            return macs;
        }
        let mut current = buffer.as_ptr() as *const AdapterAddresses;
        while !current.is_null() {
            // SAFETY: a lista ligada que a função escreveu no buffer, que
            // continua vivo aqui.
            let adapter = unsafe { &*current };
            let mac = adapter.physical_address[..6].to_vec();
            if adapter.physical_address_length == 6 && mac.iter().any(|&byte| byte != 0) && !macs.contains(&mac) {
                macs.push(mac);
            }
            current = adapter.next;
        }
        macs
    }

    /// As marcas das contas e da identidade desta máquina:
    /// - o SID de cada perfil de conta da `ProfileList`, em texto e em
    ///   binário, e, num SID de domínio (S-1-5-21-a-b-c-RID), o prefixo do
    ///   domínio em texto (`S-1-5-21-a-b-c`) e em binário (as subautoridades
    ///   21, a, b e c), que acha qualquer conta ou grupo da máquina, como o
    ///   -513;
    /// - o caminho do perfil a partir de `\Users` e o nome da pasta do perfil
    ///   sozinho, em texto;
    /// - o nome do computador (`ComputerName` e o `Hostname` do Tcpip), em
    ///   texto;
    /// - os endereços MAC dos adaptadores, em binário.
    fn account_markers() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let list = format!("SOFTWARE\\{}", super::PROFILE_LIST);
        let (mut text, mut binary) = (Vec::new(), Vec::new());
        let name_marker = |text: &mut Vec<Vec<u8>>, name: &str| {
            if name.chars().count() >= MIN_NAME_MARKER {
                text.extend(super::text_markers(name));
            }
        };
        for name in registry::list(registry::LOCAL_MACHINE, &list) {
            if super::SERVICE_ACCOUNTS.iter().any(|account| account.eq_ignore_ascii_case(&name)) {
                continue;
            }
            text.extend(super::text_markers(&name));
            if let Some(sid) = descriptor::sid_from_text(&name) {
                // S-1-5-21-a-b-c-RID: autoridade 5, cinco subautoridades.
                if sid[1] == 5 && sid[7] == 5 && sid[8..12] == 21u32.to_le_bytes() {
                    binary.push(sid[8..24].to_vec());
                    if let Some((domain, _)) = name.rsplit_once('-') {
                        text.extend(super::text_markers(domain));
                    }
                }
                binary.push(sid);
            }
            for path in registry::strings(registry::LOCAL_MACHINE, &format!("{list}\\{name}"), "ProfileImagePath") {
                if let Some(leaf) = path.trim_end_matches('\\').rsplit('\\').next().filter(|leaf| !leaf.is_empty()) {
                    text.extend(super::text_markers(&format!("\\Users\\{leaf}")));
                    name_marker(&mut text, leaf);
                }
            }
        }
        for (key, value) in [("SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName", "ComputerName"), ("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "Hostname")] {
            for computer in registry::strings(registry::LOCAL_MACHINE, key, value) {
                name_marker(&mut text, computer.as_str());
            }
        }
        binary.extend(mac_addresses());
        (text, binary)
    }

    struct Walk {
        profiles: Profiles,
        /// Descritor final e se mudou, por caminho no volume.
        settled: Vec<(String, Descriptor, bool)>,
        text: Vec<Vec<u8>>,
        binary: Vec<Vec<u8>>,
        known: Vec<(String, Descriptor)>,
    }

    impl Walk {
        fn parent_of(&self, volume: &str) -> Option<(&Descriptor, bool)> {
            let parent = volume.rsplit_once('/')?.0;
            self.settled.iter().find(|(path, _, _)| path.eq_ignore_ascii_case(parent)).map(|(_, descriptor, changed)| (descriptor, *changed))
        }

        /// O descritor final de `volume`, guardado para os filhos.
        fn settle(&mut self, host: &Path, volume: &str, directory: bool) -> Option<Vec<u8>> {
            let Some(raw) = security_of(host) else {
                println!("AVISO: {volume}: descritor ilegivel; fica com o comum do volume");
                return None;
            };
            let known = self.known.iter().find(|(path, _)| path.eq_ignore_ascii_case(volume)).map(|(_, dacl)| dacl);
            let (settled, changed) = super::settle_descriptor(&raw, known, self.parent_of(volume), directory)?;
            // O aviso não mostra o SID: é uma conta desta máquina.
            if settled.sids().any(|sid| descriptor::is_account(sid)) {
                println!("AVISO: {volume}: SID de conta no descritor; sem descritor proprio");
                return None;
            }
            let bytes = if changed { settled.to_bytes() } else { raw };
            self.settled.push((String::from(volume), settled, changed));
            Some(bytes)
        }

        /// A entrada `host` (com `relative` a partir de `C:\Users`) e, numa
        /// pasta, o que ela contém.
        fn entry(&mut self, host: &Path, relative: &str) {
            let Ok(metadata) = fs::symlink_metadata(host) else {
                println!("AVISO: {}: sem metadados", host.display());
                return;
            };
            let volume = format!("Users/{relative}");
            let attributes = metadata.file_attributes();
            let directory = attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
            let junction = attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
            if super::excluded(relative, junction) {
                return;
            }
            if junction {
                let target = fs::read_link(host).map(|target| super::junction_target(&target.to_string_lossy())).unwrap_or_default();
                let security = self.settle(host, &volume, directory);
                self.profiles.junctions.push(Junction { path: volume, target, attributes, security });
                return;
            }
            let security = self.settle(host, &volume, directory);
            if directory {
                self.profiles.nodes.push(Node { path: volume, directory: true, attributes, security });
                self.children(host, relative);
                return;
            }
            let bytes = match fs::read(host) {
                Ok(bytes) => bytes,
                Err(error) => {
                    println!("AVISO: {}: {error}", host.display());
                    return;
                }
            };
            if super::contains_marker(&bytes, &self.text, &self.binary) {
                println!("AVISO: {} tem dados de uma conta desta maquina e fica fora do volume{}", host.display(), if relative.eq_ignore_ascii_case("Default/NTUSER.DAT") { " (a hive padrao precisa ser gerada limpa)" } else { "" });
                return;
            }
            self.profiles.nodes.push(Node { path: volume.clone(), directory: false, attributes, security });
            self.profiles.files.push((volume, bytes));
        }

        fn children(&mut self, host: &Path, relative: &str) {
            let mut names: Vec<String> = fs::read_dir(host).map(|entries| entries.filter_map(|entry| entry.ok()?.file_name().into_string().ok()).collect()).unwrap_or_default();
            names.sort_by_key(|name| name.to_uppercase());
            for name in names {
                self.entry(&host.join(&name), &format!("{relative}/{name}"));
            }
        }
    }

    pub fn stage() -> Profiles {
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| String::from("C:"));
        let users = PathBuf::from(format!("{drive}\\Users"));
        let (text, binary) = account_markers();
        let known = super::KNOWN_FOLDER_DACLS.iter().filter_map(|(path, id)| {
            let dacl = known_folder_dacl(id);
            if dacl.is_none() {
                println!("AVISO: definicao da pasta conhecida {id} sem Security; {path} fica com o descritor desta maquina");
            }
            Some((String::from(*path), dacl?))
        }).collect();
        let mut walk = Walk { profiles: Profiles::default(), settled: Vec::new(), text, binary, known };
        // A pasta \Users, o desktop.ini e as junções para o ProgramData e o
        // perfil padrão; as outras pastas são perfis de conta.
        let Ok(metadata) = fs::metadata(&users) else {
            println!("AVISO: {} ausente; volume sem perfis", users.display());
            return walk.profiles;
        };
        let security = walk.settle(&users, "Users", true);
        walk.profiles.nodes.push(Node { path: String::from("Users"), directory: true, attributes: metadata.file_attributes(), security });
        let program_data = format!("{drive}\\ProgramData");
        let default = format!("{drive}\\Users\\Default");
        let mut names: Vec<String> = fs::read_dir(&users).map(|entries| entries.filter_map(|entry| entry.ok()?.file_name().into_string().ok()).collect()).unwrap_or_default();
        names.sort_by_key(|name| name.to_uppercase());
        for name in names {
            let path = users.join(&name);
            let legacy = fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
                && fs::read_link(&path).is_ok_and(|target| {
                    let target = super::junction_target(&target.to_string_lossy());
                    target.eq_ignore_ascii_case(&program_data) || target.eq_ignore_ascii_case(&default)
                });
            if legacy || ["desktop.ini", "Default", "Public"].iter().any(|kept| kept.eq_ignore_ascii_case(&name)) {
                walk.entry(&path, &name);
            }
        }
        walk.profiles
    }
}

#[cfg(test)]
mod tests {
    use super::descriptor::{self, sid, Ace, Descriptor};
    use super::*;

    const ALLOWED: u8 = 0;
    const DENIED: u8 = 1;
    const OICI: u8 = descriptor::OBJECT_INHERIT | descriptor::CONTAINER_INHERIT;
    const ID: u8 = descriptor::INHERITED;
    const IO: u8 = 0x08;
    const FULL: u32 = 0x001F_01FF;
    const READ_EXECUTE: u32 = 0x0012_00A9;
    /// GENERIC_READ | GENERIC_EXECUTE.
    const GXGR: u32 = 0xA000_0000;

    fn system() -> Vec<u8> {
        sid(5, &[18])
    }
    fn administrators() -> Vec<u8> {
        sid(5, &[32, 544])
    }
    fn users() -> Vec<u8> {
        sid(5, &[32, 545])
    }
    fn everyone() -> Vec<u8> {
        sid(1, &[0])
    }
    fn interactive() -> Vec<u8> {
        sid(5, &[4])
    }
    fn account() -> Vec<u8> {
        sid(5, &[21, 1, 2, 3, 1000])
    }

    /// O DACL do `\Users\Default` de uma instalação: Todos e Usuários com
    /// leitura e execução genéricas só de herança e efetivas na pasta,
    /// SYSTEM e Administradores com controle total herdável.
    fn default_profile_dacl() -> Vec<Ace> {
        vec![
            Ace::new(ALLOWED, OICI | IO, GXGR, everyone()),
            Ace::new(ALLOWED, 0, READ_EXECUTE, everyone()),
            Ace::new(ALLOWED, OICI, FULL, system()),
            Ace::new(ALLOWED, OICI, FULL, administrators()),
            Ace::new(ALLOWED, 0, READ_EXECUTE, users()),
            Ace::new(ALLOWED, OICI | IO, GXGR, users()),
        ]
    }

    #[test]
    fn descriptor_round_trips() {
        let original = Descriptor { control: 0x9404, owner: Some(system()), group: Some(system()), sacl: None, dacl: Some((2, default_profile_dacl())) };
        let bytes = original.to_bytes();
        assert_eq!(bytes.len() % 4, 0);
        assert_eq!(Descriptor::parse(&bytes), Some(original));
    }

    /// As pastas de dentro do `Default` desta instalação: o SYSTEM e os
    /// Administradores numa ACE só (OICI|ID), Todos e Usuários em duas (a
    /// efetiva com 0x1200A9 e a só de herança com os genéricos).
    #[test]
    fn a_folder_inherits_like_ntfs() {
        let aces = descriptor::inherited_aces(&default_profile_dacl(), true, &system(), &system());
        assert_eq!(aces, vec![
            Ace::new(ALLOWED, ID, READ_EXECUTE, everyone()),
            Ace::new(ALLOWED, OICI | IO | ID, GXGR, everyone()),
            Ace::new(ALLOWED, OICI | ID, FULL, system()),
            Ace::new(ALLOWED, OICI | ID, FULL, administrators()),
            Ace::new(ALLOWED, ID, READ_EXECUTE, users()),
            Ace::new(ALLOWED, OICI | IO | ID, GXGR, users()),
        ]);
    }

    /// Os arquivos do `Default`: só as ACEs efetivas, mapeadas.
    #[test]
    fn a_file_inherits_only_effective_aces() {
        let aces = descriptor::inherited_aces(&default_profile_dacl(), false, &system(), &system());
        assert_eq!(aces, vec![
            Ace::new(ALLOWED, ID, READ_EXECUTE, everyone()),
            Ace::new(ALLOWED, ID, FULL, system()),
            Ace::new(ALLOWED, ID, FULL, administrators()),
            Ace::new(ALLOWED, ID, READ_EXECUTE, users()),
        ]);
    }

    /// O CREATOR OWNER vira o dono na ACE efetiva e continua na cópia de
    /// herança.
    #[test]
    fn creator_owner_becomes_the_owner() {
        let parent = vec![Ace::new(ALLOWED, OICI | IO, FULL, sid(3, &[0]))];
        let aces = descriptor::inherited_aces(&parent, true, &system(), &system());
        assert_eq!(aces, vec![Ace::new(ALLOWED, ID, FULL, system()), Ace::new(ALLOWED, OICI | IO | ID, FULL, sid(3, &[0]))]);
    }

    /// A área de trabalho pública desta máquina tem ACEs que um programa
    /// ou uma conta acrescentou; com o DACL da pasta conhecida, o
    /// desktop.ini dentro dela herda de novo e fica sem a conta.
    #[test]
    fn known_folder_dacl_replaces_and_children_reinherit() {
        let dirty = Descriptor {
            control: 0x9404,
            owner: Some(system()),
            group: Some(system()),
            sacl: None,
            dacl: Some((2, vec![Ace::new(ALLOWED, OICI, READ_EXECUTE, interactive()), Ace::new(ALLOWED, OICI, FULL, system()), Ace::new(ALLOWED, OICI, FULL, administrators()), Ace::new(ALLOWED, OICI, 0x0013_01BF, users()), Ace::new(ALLOWED, OICI | IO, 0x0001_0040, account())])),
        };
        let known = Descriptor { control: 0x9004, owner: None, group: None, sacl: None, dacl: Some((2, vec![Ace::new(ALLOWED, OICI, FULL, administrators()), Ace::new(ALLOWED, OICI, READ_EXECUTE, interactive()), Ace::new(ALLOWED, OICI, FULL, system())])) };
        let (desktop, changed) = settle_descriptor(&dirty.to_bytes(), Some(&known), None, true).unwrap();
        assert!(changed && desktop.dacl_protected() && desktop.owner == Some(system()));
        assert_eq!(desktop.dacl, known.dacl);
        let explicit = vec![Ace::new(ALLOWED, 0, FULL, system()), Ace::new(ALLOWED, 0, FULL, administrators()), Ace::new(ALLOWED, 0, READ_EXECUTE, users())];
        let mut dirty_ini = explicit.clone();
        dirty_ini.extend(descriptor::inherited_aces(dirty.dacl.as_ref().map(|(_, aces)| aces.as_slice()).unwrap(), false, &administrators(), &system()));
        let ini = Descriptor { control: 0x8404, owner: Some(administrators()), group: Some(system()), sacl: None, dacl: Some((2, dirty_ini)) };
        let (ini, changed) = settle_descriptor(&ini.to_bytes(), None, Some((&desktop, true)), false).unwrap();
        let mut expected = explicit;
        expected.extend([Ace::new(ALLOWED, ID, FULL, administrators()), Ace::new(ALLOWED, ID, READ_EXECUTE, interactive()), Ace::new(ALLOWED, ID, FULL, system())]);
        assert!(changed);
        assert_eq!(ini.dacl, Some((2, expected)));
    }

    /// SID de conta fora: a ACE sai, o dono e o grupo viram Administradores
    /// e SYSTEM; os bem conhecidos, os de serviço e os de capacidade ficam.
    #[test]
    fn account_sids_are_removed() {
        let trusted_installer = sid(5, &[80, 956008885, 3418522649, 1831038044, 1853292631, 2271478464]);
        let capability = sid(15, &[3, 1024, 1, 2, 3, 4, 5, 6, 7, 8]);
        let logon = sid(5, &[5, 0, 12345]);
        let host = Descriptor {
            control: 0x8404,
            owner: Some(account()),
            group: Some(sid(5, &[21, 1, 2, 3, 513])),
            sacl: None,
            dacl: Some((2, vec![Ace::new(DENIED, 0, 1, everyone()), Ace::new(ALLOWED, 0, FULL, account()), Ace::new(ALLOWED, 0, FULL, trusted_installer.clone()), Ace::new(ALLOWED, OICI, READ_EXECUTE, capability.clone()), Ace::new(ALLOWED, 0, FULL, logon)])),
        };
        let (settled, changed) = settle_descriptor(&host.to_bytes(), None, None, true).unwrap();
        assert!(changed);
        assert_eq!(settled.owner, Some(administrators()));
        assert_eq!(settled.group, Some(system()));
        assert_eq!(settled.dacl, Some((2, vec![Ace::new(DENIED, 0, 1, everyone()), Ace::new(ALLOWED, 0, FULL, trusted_installer), Ace::new(ALLOWED, OICI, READ_EXECUTE, capability)])));
        let clean = Descriptor { control: 0x8404, owner: Some(system()), group: Some(system()), sacl: None, dacl: Some((2, default_profile_dacl())) };
        assert_eq!(settle_descriptor(&clean.to_bytes(), None, Some((&clean, false)), true), Some((clean, false)));
    }

    #[test]
    fn sid_text_round_trips() {
        let text = "S-1-5-21-1000-2000-3000-1000";
        let binary = descriptor::sid_from_text(text).unwrap();
        assert_eq!(binary.len(), 28);
        assert!(descriptor::is_account(&binary));
        assert_eq!(descriptor::sid_text(&binary), text);
        assert!(!descriptor::is_account(&descriptor::sid_from_text("S-1-5-32-544").unwrap()));
    }

    /// Os diretórios da `ProfileList` de uma instalação nova, em
    /// REG_EXPAND_SZ.
    #[test]
    fn profile_list_has_the_fresh_install_directories() {
        let keys = software_keys();
        let root = keys.iter().find(|key| key.path == PROFILE_LIST).unwrap();
        let value = |name: &str| root.values.iter().find(|(value, _, _)| value == name).map(|(_, kind, data)| (*kind, String::from_utf16_lossy(&data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect::<Vec<_>>())));
        assert_eq!(root.values.len(), 4);
        assert_eq!(value("ProfilesDirectory"), Some((2, String::from("%SystemDrive%\\Users\0"))));
        assert_eq!(value("Default"), Some((2, String::from("%SystemDrive%\\Users\\Default\0"))));
        assert_eq!(value("Public"), Some((2, String::from("%SystemDrive%\\Users\\Public\0"))));
        assert_eq!(value("ProgramData"), Some((2, String::from("%SystemDrive%\\ProgramData\0"))));
        let profiles: Vec<&str> = keys.iter().map(|key| key.path.as_str()).filter(|path| path.starts_with(PROFILE_LIST)).collect();
        assert!(profiles.iter().all(|path| *path == PROFILE_LIST || SERVICE_ACCOUNTS.iter().any(|account| path.starts_with(&format!("{PROFILE_LIST}\\{account}")))));
    }

    /// Na SYSTEM, só o serviço de perfis (o assinante Profiles vem com a chave
    /// inteira de Notifications, `service_chain`).
    #[test]
    fn only_the_profile_service_is_seeded() {
        let keys = system_keys("ControlSet001");
        assert!(keys.iter().all(|key| key.path.starts_with("ControlSet001\\Services\\ProfSvc")), "{:?}", keys.iter().map(|key| &key.path).collect::<Vec<_>>());
    }

    /// As definições das pastas conhecidas vêm desta máquina, com o
    /// `RelativePath` da área de trabalho pública.
    #[cfg(windows)]
    #[test]
    fn folder_descriptions_are_copied() {
        let keys = software_keys();
        let desktop = keys.iter().find(|key| key.path.eq_ignore_ascii_case(&format!("{FOLDER_DESCRIPTIONS}\\{{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}}"))).expect("FolderDescriptions do Public\\Desktop");
        assert!(desktop.values.iter().any(|(name, _, _)| name.eq_ignore_ascii_case("RelativePath")));
        assert!(keys.iter().flat_map(|key| key.values.iter()).all(|(_, _, data)| !has_account_sid(data)));
    }

    /// O filtro das chaves copiadas: o descritor binário perde a conta, o
    /// valor com SID de conta em texto ou em binário sai, a subchave de uma
    /// conta sai, o resto fica; as chaves antes de `first` não mudam.
    #[test]
    fn copied_keys_lose_account_data() {
        let utf16 = |text: &str| -> Vec<u8> { text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect() };
        let dirty = Descriptor {
            control: 0x8004,
            owner: Some(account()),
            group: Some(system()),
            sacl: None,
            dacl: Some((2, vec![Ace::new(ALLOWED, 0, FULL, system()), Ace::new(ALLOWED, 0, FULL, account())])),
        };
        let mut keys = vec![
            HostKey { path: String::from("Fixa"), values: vec![(String::from("Texto"), 1, utf16("S-1-5-21-1-2-3-1000"))] },
            HostKey {
                path: String::from("Copia"),
                values: vec![
                    (String::from("Security"), 3, dirty.to_bytes()),
                    (String::from("Sddl"), 1, utf16("O:BAD:(A;;GA;;;S-1-5-21-1-2-3-1000)")),
                    (String::from("Azure"), 1, utf16("s-1-12-1-10-20-30-40")),
                    (String::from("Sid"), 3, [vec![0xAA, 0xBB], account(), vec![0xCC]].concat()),
                    (String::from("Limpo"), 1, utf16("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")),
                    (String::from("Servico"), 3, sid(5, &[80, 1, 2, 3, 4, 5])),
                ],
            },
            HostKey { path: String::from("Copia\\S-1-5-21-1-2-3-1000\\Filho"), values: Vec::new() },
            HostKey { path: String::from("Copia\\S-1-5-18"), values: Vec::new() },
        ];
        without_account_data(&mut keys, 1);
        assert_eq!(keys.iter().map(|key| key.path.as_str()).collect::<Vec<_>>(), ["Fixa", "Copia", "Copia\\S-1-5-18"]);
        assert_eq!(keys[0].values.len(), 1);
        let names: Vec<&str> = keys[1].values.iter().map(|(name, _, _)| name.as_str()).collect();
        assert_eq!(names, ["Security", "Limpo", "Servico"]);
        let cleaned = Descriptor::parse(&keys[1].values[0].2).unwrap();
        assert_eq!(cleaned.owner, Some(administrators()));
        assert_eq!(cleaned.dacl, Some((2, vec![Ace::new(ALLOWED, 0, FULL, system())])));
    }

    /// O SID de usuário do Azure AD (S-1-12-1-…) é de conta.
    #[test]
    fn azure_ad_sids_are_accounts() {
        assert!(descriptor::is_account(&descriptor::sid_from_text("S-1-12-1-10-20-30-40").unwrap()));
        assert!(!descriptor::is_account(&descriptor::sid_from_text("S-1-15-2-1").unwrap()));
        assert!(!descriptor::is_account(&descriptor::sid_from_text("S-1-5-80-1-2-3-4-5").unwrap()));
    }

    #[test]
    fn exclusions_keep_a_fresh_install() {
        assert!(excluded("Default/NTUSER.DAT{53b39e88-18c4-11ea-a811-000d3aa4692b}.TM.blf", false));
        assert!(excluded("Default/NTUSER.DAT{53b39e88-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms", false));
        assert!(!excluded("Default/NTUSER.DAT", false) && !excluded("Default/NTUSER.DAT.LOG1", false) && !excluded("Default/AppData/Local/Microsoft/Windows/Shell/DefaultLayouts.xml", false));
        assert!(!excluded("Public/Desktop", false) && !excluded("Public/Desktop/desktop.ini", false) && !excluded("Public/Libraries/RecordedTV.library-ms", false));
        assert!(excluded("Public/Desktop/Program.lnk", false) && excluded("Public/AccountPictures", false) && excluded("Public/Documents/notes.txt", false));
        // As junções dos documentos públicos ficam (listadas); uma junção
        // fora das pastas conhecidas, não.
        assert!(!excluded("Public/Documents/My Music", true) && excluded("Public/Documents/My Music", false) && excluded("Public/Other/Link", true));
    }

    #[test]
    fn markers_match_any_case_and_encoding() {
        let text: Vec<Vec<u8>> = text_markers("\\Users\\someone").into_iter().collect();
        let binary = vec![account()];
        let wide: Vec<u8> = "x C:\\USERS\\SomeOne\\AppData".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(contains_marker(&wide, &text, &binary));
        assert!(contains_marker(b"path=c:\\users\\someone", &text, &binary));
        assert!(contains_marker(&[[0u8; 3].as_slice(), &account(), &[1]].concat(), &text, &binary));
        assert!(!contains_marker(b"%USERPROFILE%\\AppData\\Local", &text, &binary));
    }

    /// Os perfis desta máquina: nenhum descritor com SID de conta, cada
    /// arquivo com o nó dele, as junções com destino, e o volume monta.
    #[cfg(windows)]
    #[test]
    fn host_profiles_build_a_clean_volume() {
        let profiles = stage();
        for node in &profiles.nodes {
            let parsed = node.security.as_deref().map(|bytes| Descriptor::parse(bytes).expect("descritor ilegivel"));
            assert!(parsed.iter().flat_map(Descriptor::sids).all(|sid| !descriptor::is_account(sid)), "{}: SID de conta", node.path);
            assert!(node.path.starts_with("Users"), "{}", node.path);
            if std::env::var_os("OPENNT_PERFIS_DETALHE").is_some() {
                let security: String = node.security.as_deref().unwrap_or_default().iter().map(|byte| format!("{byte:02x}")).collect();
                println!("{}\t{:#x}\t{security}", node.path, node.attributes);
            }
        }
        for (path, _) in &profiles.files {
            assert!(profiles.nodes.iter().any(|node| !node.directory && node.path == *path), "{path} sem no");
        }
        for junction in &profiles.junctions {
            assert!(!junction.target.is_empty(), "{} sem destino", junction.path);
            assert!(junction.security.as_deref().and_then(Descriptor::parse).iter().flat_map(Descriptor::sids).all(|sid| !descriptor::is_account(sid)), "{}: SID de conta", junction.path);
        }
        if std::env::var_os("OPENNT_PERFIS_DETALHE").is_some() {
            print!("{}", junction_report(&profiles.junctions));
        }
        let directory = std::env::temp_dir().join(format!("opennt-perfis-{}", std::process::id()));
        let image = directory.join("ntfs.img");
        let built = crate::ntfs_image::build(&image, &profiles.files, &profiles.nodes, None, true, 1, 0);
        let _ = std::fs::remove_dir_all(&directory);
        assert!(built.is_ok(), "{built:?}");
    }

    #[test]
    fn junction_targets_lose_the_namespace_prefix() {
        assert_eq!(junction_target("\\??\\C:\\Users\\Default\\AppData\\Roaming"), "C:\\Users\\Default\\AppData\\Roaming");
        assert_eq!(junction_target("\\\\?\\C:\\ProgramData"), "C:\\ProgramData");
        assert_eq!(junction_target("C:\\Users\\Public\\Music"), "C:\\Users\\Public\\Music");
    }
}
