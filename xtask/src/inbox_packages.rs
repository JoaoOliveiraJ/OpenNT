//! Os pacotes AppX da caixa que o primeiro logon do usuário registra no boot
//! do processo inicial real (`--initial-process=smss`): o
//! Microsoft.Windows.StartMenuExperienceHost (o menu Iniciar) e o
//! Microsoft.Windows.ShellExperienceHost (a Central de Ações, os painéis do
//! relógio e da rede).
//!
//! No 19041 o registro é dos serviços reais, no convidado:
//!
//! - no primeiro logon de uma conta, o CLogonTaskFramework::RunAllLogonTasks
//!   do explorer roda os grupos AppReadinessPreRoamingGroup,
//!   AppReadinessPreShellGroup e AppReadinessLogonGroup antes da área de
//!   trabalho: o AppReadinessTaskStart ativa a classe COM do serviço
//!   AppReadiness ({C980E4C2-C178-4572-935D-A8A429884806}, o AppID
//!   {88283d7c-46f4-47d5-8fc2-db0b5cf0cb54} com `LocalService`
//!   AppReadiness), e o RPCSS inicia o serviço (o AppReadiness.dll no
//!   `svchost.exe -k AppReadiness -p`);
//! - o AppReadiness chama o AppXSvc (o AppXDeploymentServer.dll no
//!   `svchost.exe -k wsappx -p`, processo protegido) pelo
//!   AppXDeploymentClient.dll: primeiro o AppxPreRegisterAllInboxPackages,
//!   que põe cada pacote de `AppxAllUserStore\InboxApplications` (o
//!   `Path` do manifesto) no StateRepository da máquina, e depois o registro
//!   de cada pacote para o usuário, no grupo que o `SetupPhase` de
//!   `AppxAllUserStore\Config\<família>` escolhe;
//! - o AppXSvc confere a assinatura do pacote (o `AppxSignature.p7x`) pelo
//!   WinVerifyTrust, com o SIP do AppxSip.dll, o provedor de confiança
//!   genérico do wintrust e a cadeia até uma raiz da Microsoft, e grava os
//!   bancos do StateRepository em `%AppRepository%`, o
//!   `ActivationStore.dat` e o `<SID>.pckgdep` de cada pacote e o estado do
//!   usuário (o perfil do AppContainer, as pastas de
//!   `%LOCALAPPDATA%\Packages`).
//!
//! O volume leva as pastas dos dois pacotes de `\Windows\SystemApps` (sem a
//! `microsoft.system.package.metadata`, que o AppXSvc gera), e as hives os
//! dados que uma instalação nova traz para esse caminho: os valores de
//! configuração do AppX, o volume de pacotes padrão
//! (`Appx\PackageVolumes`), as extensões de implantação da caixa, as filas
//! vazias do AppXSvc, a chave
//! `Applications` do AppxAllUserStore vazia, as entradas dos dois pacotes em
//! `InboxApplications` e em `Config` (o nome completo sai do `<Identity>` do
//! manifesto que o volume leva), a chave do AppReadiness com o
//! `NotifyObject`, a classe COM e o AppID do AppReadiness (o dono e o grupo
//! de conta dos descritores trocados por Administradores e SYSTEM), os
//! serviços AppReadiness e AppXSvc, os SIPs do AppxSip.dll, o provedor
//! WINTRUST_ACTION_GENERIC_VERIFY_V2 e as raízes públicas da Microsoft do
//! repositório ROOT. Nada do estado que os serviços gravam vai: nem os
//! bancos, nem as outras subchaves de `AppxAllUserStore`, nem as
//! subchaves por usuário do AppReadiness; os identificadores são todos do
//! convidado. Fora do Windows nada é copiado.

use std::path::{Path, PathBuf};

use crate::host_language::HostKey;

/// As pastas dos pacotes em `\Windows\SystemApps`.
pub const PACKAGES: &[&str] = &["Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy", "ShellExperienceHost_cw5n1h2txyewy"];

/// A pasta que o AppXSvc gera dentro do pacote (o cache de bytecode e o
/// estado da implantação): não é da instalação.
const GENERATED: &str = "microsoft.system.package.metadata";

/// A chave do AppX na SOFTWARE e o repositório dos pacotes da caixa.
const APPX: &str = "Microsoft\\Windows\\CurrentVersion\\Appx";
const ALL_USER_STORE: &str = "Microsoft\\Windows\\CurrentVersion\\Appx\\AppxAllUserStore";

/// O volume de pacotes de uma instalação nova (`Appx\PackageVolumes`): o
/// volume 1, o padrão, com o `SISPath` em `C:\Program Files\WindowsApps`. A
/// imagem do Windows já traz a chave (o volume é criado quando a imagem é
/// gerada, antes de qualquer pacote), e o AppXSvc só a abre: o
/// VolumeManager (volumemanager.cpp) abre `PackageVolumes` (o
/// `AppxPackageVolumes` do GetPersistedRegistryLocationW) no começo de cada
/// implantação, e sem ela o StartDeploymentImplementation volta
/// ERROR_FILE_NOT_FOUND. Os valores são os da imagem, não os desta
/// máquina, que podem trazer volumes externos.
const PACKAGE_VOLUMES: &str = "Microsoft\\Windows\\CurrentVersion\\Appx\\PackageVolumes";
const DEFAULT_VOLUME_FLAGS: u32 = 0x17A;
const DEFAULT_VOLUME_PATH: &str = "C:\\Program Files\\WindowsApps";

/// As extensões de implantação da caixa (`Appx\DeploymentExtensionModules`,
/// um valor por módulo, na ordem em que o AppXSvc as carrega). As
/// extensões "desacopladas" dos pacotes instalados nesta máquina não vão.
const DEPLOYMENT_EXTENSIONS: &str = "Microsoft\\Windows\\CurrentVersion\\Appx\\DeploymentExtensionModules";
const DEPLOYMENT_EXTENSION_MODULES: &[&str] = &["C:\\Windows\\System32\\AppXDeploymentExtensions.onecore.dll", "C:\\Windows\\System32\\AppXDeploymentExtensions.desktop.dll"];

/// As filas do AppXSvc, vazias numa instalação nova (subchaves de `Appx`):
/// a das implantações pendentes (o deploymentqueuemanager.cpp abre
/// `NewDeploymentOperation` a cada registro), a da pré-compilação do
/// bytecode (o bytecodequeuemanager.cpp abre `ByteCodeQueue`) e a da
/// limpeza de pacotes (`PurgeList`). O serviço só abre as chaves; sem elas o
/// registro volta ERROR_FILE_NOT_FOUND.
const EMPTY_QUEUES: &[&str] = &["NewDeploymentOperation", "ByteCodeQueue", "PurgeList"];

/// A chave do AppReadiness (o `c_AppReadinessRegRoot`, que o serviço abre e
/// não cria) e o único valor dela que uma instalação traz.
const APP_READINESS: &str = "Microsoft\\Windows\\CurrentVersion\\AppReadiness";
#[cfg_attr(not(windows), allow(dead_code))]
const APP_READINESS_VALUES: &[&str] = &["NotifyObject"];

/// A classe COM do serviço AppReadiness e o AppID dela.
#[cfg_attr(not(windows), allow(dead_code))]
const APP_READINESS_CLASS: &str = "{C980E4C2-C178-4572-935D-A8A429884806}";
#[cfg_attr(not(windows), allow(dead_code))]
const APP_READINESS_APPID: &str = "{88283d7c-46f4-47d5-8fc2-db0b5cf0cb54}";

/// Os serviços do registro: o AppReadiness e o AppXSvc (com Parameters,
/// Security e TriggerInfo). O StateRepository vai com os de
/// `user_services`.
#[cfg_attr(not(windows), allow(dead_code))]
const SERVICES: &[&str] = &["AppReadiness", "AppXSvc"];

/// O provedor de confiança WINTRUST_ACTION_GENERIC_VERIFY_V2 (as funções do
/// WINTRUST.DLL em `Cryptography\Providers\Trust\<etapa>\{guid}`).
#[cfg_attr(not(windows), allow(dead_code))]
const GENERIC_VERIFY_V2: &str = "{00AAC56B-CD44-11D0-8CC2-00C04FC295EE}";

/// A DLL dos SIPs dos pacotes AppX (o `Dll` de
/// `Cryptography\OID\EncodingType 0\CryptSIPDll*\{guid}`).
#[cfg_attr(not(windows), allow(dead_code))]
const APPX_SIP: &str = "appxsip.dll";

/// As raízes públicas da Microsoft do repositório ROOT da máquina, pela
/// impressão digital SHA-1: a Microsoft Root Certificate Authority 2010 (a
/// raiz da cadeia "Microsoft Windows" → "Microsoft Windows Production PCA
/// 2011" dos pacotes da caixa e da "Microsoft Time-Stamp PCA 2010" da
/// contra-assinatura), a 2011, a de 2001, a Microsoft Root Authority, a
/// Authenticode, a "Copyright (c) 1997 Microsoft Corp.", as duas ECC de 2018
/// e a de carimbo de tempo de 2014. As outras raízes desta máquina não vão.
#[cfg_attr(not(windows), allow(dead_code))]
const MICROSOFT_ROOTS: &[&str] = &[
    "3B1EFD3A66EA28B16697394703A72CA340A05BD5",
    "8F43288AD272F3103B6FB1428485EA3014C0BCFE",
    "CDD4EEAE6000AC7F40C3802C171E30148030C072",
    "A43489159A520F0D93D032CCAF37E7FE20A8B419",
    "7F88CD7223F3C813818C994614A89C99FA3B5247",
    "245C97DF7514E7CF2DF8BE72AE957B9E04741E85",
    "06F1AA330B927B753A40E68CDF22E34BCBEF3352",
    "31F9FC8BA3805986B721EA7295C65B3A44534274",
    "0119E81BE9A14CD8E22F40AC118C687ECBA3F4D8",
];

/// A identidade de um pacote (`<Identity>` do manifesto).
#[derive(Debug, PartialEq)]
pub struct Identity {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub resource_id: String,
}

impl Identity {
    /// O começo do nome completo do pacote, até o identificador do
    /// publicador: `Nome_Versão_Arquitetura_Recurso_`.
    pub fn full_name_prefix(&self) -> String {
        format!("{}_{}_{}_{}_", self.name, self.version, self.architecture, self.resource_id)
    }
}

/// O valor do atributo `name` de um elemento XML (`name="..."`).
fn attribute(element: &str, name: &str) -> Option<String> {
    let mut rest = element;
    while let Some(at) = rest.find(name) {
        let before = rest[..at].chars().last();
        let after = &rest[at + name.len()..];
        rest = after;
        if before.is_some_and(|character| !character.is_whitespace()) {
            continue;
        }
        let Some(value) = after.trim_start().strip_prefix('=') else { continue };
        let value = value.trim_start();
        let quote = value.chars().next()?;
        if quote != '"' && quote != '\'' {
            return None;
        }
        return value[1..].find(quote).map(|end| String::from(&value[1..1 + end]));
    }
    None
}

/// A identidade do manifesto: o `Name` e a `Version`, a
/// `ProcessorArchitecture` (sem ela, neutral) e o `ResourceId` (sem ele,
/// vazio).
pub fn identity(manifest: &str) -> Option<Identity> {
    let start = manifest.find("<Identity")?;
    let element = &manifest[start..start + manifest[start..].find('>')?];
    Some(Identity {
        name: attribute(element, "Name")?,
        version: attribute(element, "Version")?,
        architecture: attribute(element, "ProcessorArchitecture").unwrap_or_else(|| String::from("neutral")),
        resource_id: attribute(element, "ResourceId").unwrap_or_default(),
    })
}

/// Os arquivos de uma pasta e das subpastas, menos [`GENERATED`]: (caminho
/// relativo com '/', arquivo de origem).
fn tree(directory: &Path, prefix: &str, files: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(directory) else { return };
    let mut entries: Vec<_> = entries.filter_map(|entry| entry.ok()).collect();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let Ok(name) = entry.file_name().into_string() else { continue };
        let path = entry.path();
        if path.is_dir() {
            if !name.eq_ignore_ascii_case(GENERATED) {
                tree(&path, &format!("{prefix}/{name}"), files);
            }
        } else if path.is_file() {
            files.push((format!("{prefix}/{name}"), path));
        }
    }
}

/// Os arquivos dos pacotes: (caminho no volume, arquivo de origem), em
/// `SystemApps\<pasta>` como no diretório do Windows.
pub fn files(windows: &Path) -> Vec<(String, PathBuf)> {
    let mut files = Vec::new();
    for package in PACKAGES {
        tree(&windows.join("SystemApps").join(package), &format!("SystemApps/{package}"), &mut files);
    }
    files
}

/// O caminho do manifesto de um pacote no convidado (o `Path` da entrada de
/// `InboxApplications`).
#[cfg_attr(not(windows), allow(dead_code))]
fn guest_manifest(package: &str) -> String {
    format!("C:\\Windows\\SystemApps\\{package}\\AppxManifest.xml")
}

/// Os dados de um REG_SZ (UTF-16LE terminado em NUL) como texto.
#[cfg_attr(not(windows), allow(dead_code))]
fn text(data: &[u8]) -> String {
    let units: Vec<u16> = data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
    String::from_utf16_lossy(&units)
}

/// Troca, nos descritores binários dos valores, o dono e o grupo de conta
/// por Administradores e SYSTEM e tira as ACEs de conta.
#[cfg_attr(not(windows), allow(dead_code))]
fn without_account_owners(keys: &mut [HostKey]) {
    use crate::host_security::descriptor::Descriptor;
    for key in keys.iter_mut() {
        for (_, kind, data) in key.values.iter_mut() {
            if *kind != 3 {
                continue;
            }
            if let Some(mut descriptor) = Descriptor::parse(data) {
                if descriptor.remove_accounts() {
                    *data = descriptor.to_bytes();
                }
            }
        }
    }
}

/// As chaves da hive SOFTWARE.
pub fn software_keys() -> Vec<HostKey> {
    let mut keys = Vec::new();
    #[cfg(windows)]
    {
        use crate::host_language::registry;
        let machine = registry::LOCAL_MACHINE;
        let windows = crate::windows_binaries::windows_directory();
        // Os valores de configuração do AppX (os diretórios, os tipos de
        // sistema de arquivos aceitos, as ACEs condicionais...), sem as
        // subchaves.
        registry::copy(machine, &format!("SOFTWARE\\{APPX}"), APPX, false, &mut keys);
        // O repositório da caixa: só a chave InboxApplications (com o valor
        // dela) e as entradas dos pacotes que o volume leva.
        let inbox = format!("{ALL_USER_STORE}\\InboxApplications");
        registry::copy(machine, &format!("SOFTWARE\\{inbox}"), &inbox, false, &mut keys);
        let entries = registry::list(machine, &format!("SOFTWARE\\{inbox}"));
        for package in PACKAGES {
            let manifest = windows.join("SystemApps").join(package).join("AppxManifest.xml");
            let Some(identity) = std::fs::read_to_string(&manifest).ok().as_deref().and_then(identity) else {
                println!("AVISO: {} ilegivel; o pacote fica fora do registro", manifest.display());
                continue;
            };
            let prefix = identity.full_name_prefix();
            let Some(full_name) = entries.iter().find(|entry| entry.len() > prefix.len() && entry[..prefix.len()].eq_ignore_ascii_case(&prefix)) else {
                println!("AVISO: InboxApplications sem {prefix}* (o manifesto de {package}); o pacote fica fora do registro");
                continue;
            };
            let first = keys.len();
            registry::copy(machine, &format!("SOFTWARE\\{inbox}\\{full_name}"), &format!("{inbox}\\{full_name}"), false, &mut keys);
            // O caminho do manifesto é o do convidado, onde o volume o põe.
            if let Some(entry) = keys.get_mut(first) {
                entry.values.retain(|(name, _, _)| !name.eq_ignore_ascii_case("Path"));
                entry.values.push((String::from("Path"), 1, crate::user_services::registry_string(&guest_manifest(package))));
            }
            let publisher = &full_name[prefix.len()..];
            let family = format!("{}_{publisher}", identity.name);
            registry::copy(machine, &format!("SOFTWARE\\{ALL_USER_STORE}\\Config\\{family}"), &format!("{ALL_USER_STORE}\\Config\\{family}"), false, &mut keys);
        }
        // A chave do AppReadiness, só com o NotifyObject.
        let first = keys.len();
        registry::copy(machine, &format!("SOFTWARE\\{APP_READINESS}"), APP_READINESS, false, &mut keys);
        if let Some(key) = keys.get_mut(first).filter(|key| key.path == APP_READINESS) {
            key.values.retain(|(name, _, _)| APP_READINESS_VALUES.iter().any(|kept| kept.eq_ignore_ascii_case(name)));
        }
        // A classe COM do serviço e o AppID dela.
        let mut classes = Vec::new();
        registry::copy(machine, &format!("SOFTWARE\\Classes\\CLSID\\{APP_READINESS_CLASS}"), &format!("Classes\\CLSID\\{APP_READINESS_CLASS}"), true, &mut classes);
        registry::copy(machine, &format!("SOFTWARE\\Classes\\AppID\\{APP_READINESS_APPID}"), &format!("Classes\\AppID\\{APP_READINESS_APPID}"), true, &mut classes);
        without_account_owners(&mut classes);
        keys.extend(classes);
        // Os SIPs do AppxSip.dll.
        let encoding = "Microsoft\\Cryptography\\OID\\EncodingType 0";
        for function in registry::list(machine, &format!("SOFTWARE\\{encoding}")) {
            if !function.to_ascii_lowercase().starts_with("cryptsipdll") {
                continue;
            }
            for subject in registry::list(machine, &format!("SOFTWARE\\{encoding}\\{function}")) {
                let path = format!("{encoding}\\{function}\\{subject}");
                let mut found = Vec::new();
                registry::copy(machine, &format!("SOFTWARE\\{path}"), &path, false, &mut found);
                let appx = found.first().is_some_and(|key| key.values.iter().any(|(name, kind, data)| name.eq_ignore_ascii_case("Dll") && matches!(kind, 1 | 2) && text(data).to_ascii_lowercase().ends_with(APPX_SIP)));
                if appx {
                    keys.extend(found);
                }
            }
        }
        // O provedor de confiança genérico, em cada etapa.
        let trust = "Microsoft\\Cryptography\\Providers\\Trust";
        for step in registry::list(machine, &format!("SOFTWARE\\{trust}")) {
            registry::copy(machine, &format!("SOFTWARE\\{trust}\\{step}\\{GENERIC_VERIFY_V2}"), &format!("{trust}\\{step}\\{GENERIC_VERIFY_V2}"), false, &mut keys);
        }
        // As raízes públicas da Microsoft.
        let roots = "Microsoft\\SystemCertificates\\ROOT\\Certificates";
        for thumbprint in registry::list(machine, &format!("SOFTWARE\\{roots}")) {
            if MICROSOFT_ROOTS.iter().any(|known| known.eq_ignore_ascii_case(&thumbprint)) {
                registry::copy(machine, &format!("SOFTWARE\\{roots}\\{thumbprint}"), &format!("{roots}\\{thumbprint}"), false, &mut keys);
            }
        }
    }
    keys.extend(clean_install_keys());
    keys
}

/// As chaves fixas de uma instalação nova: o volume de pacotes padrão, as
/// extensões de implantação da caixa, as filas vazias do AppXSvc
/// ([`EMPTY_QUEUES`]) e a chave `Applications` do
/// AppxAllUserStore vazia (a dos pacotes provisionados para todos os
/// usuários: o IsNonInboxAllUserPackageSpecificPackage do
/// AppxAllUserStore.dll a abre em cada registro e, sem ela, o AppXSvc
/// recusa o pacote com ERROR_FILE_NOT_FOUND; o convidado não tem pacotes
/// provisionados, e os desta máquina não vão).
fn clean_install_keys() -> Vec<HostKey> {
    use crate::user_services::registry_string;
    let dword = |name: &str, value: u32| (String::from(name), 4u32, value.to_le_bytes().to_vec());
    let text = |name: &str, value: &str| (String::from(name), 1u32, registry_string(value));
    let key = |path: String, values: Vec<(String, u32, Vec<u8>)>| HostKey { path, values };
    vec![
        key(String::from(PACKAGE_VOLUMES), vec![dword("DefaultVolumeKey", 1), dword("EnableExternalVolumes", 1)]),
        key(format!("{PACKAGE_VOLUMES}\\1"), vec![dword("Flags", DEFAULT_VOLUME_FLAGS), text("MediaId", ""), text("MountPoint", ""), text("Name", ""), text("SISPath", DEFAULT_VOLUME_PATH)]),
        key(format!("{PACKAGE_VOLUMES}\\1\\MutablePackagesOnline"), Vec::new()),
        key(String::from(DEPLOYMENT_EXTENSIONS), DEPLOYMENT_EXTENSION_MODULES.iter().enumerate().map(|(index, module)| text(&index.to_string(), module)).collect()),
        key(format!("{ALL_USER_STORE}\\Applications"), Vec::new()),
    ]
    .into_iter()
    .chain(EMPTY_QUEUES.iter().map(|queue| key(format!("{APPX}\\{queue}"), Vec::new())))
    .collect()
}

/// As chaves da hive SYSTEM, já no conjunto de controle que a hive guarda.
pub fn system_keys(control_set: &str) -> Vec<HostKey> {
    let mut keys = Vec::new();
    #[cfg(windows)]
    {
        use crate::host_language::registry;
        for service in SERVICES {
            registry::copy(registry::LOCAL_MACHINE, &format!("SYSTEM\\CurrentControlSet\\Services\\{service}"), &format!("{control_set}\\Services\\{service}"), true, &mut keys);
        }
        without_account_owners(&mut keys);
    }
    #[cfg(not(windows))]
    let _ = control_set;
    keys
}

#[cfg(test)]
mod tests {
    use super::{attribute, clean_install_keys, identity, Identity};

    /// O volume padrão é o 1, com o SISPath da imagem, e as extensões são
    /// as duas DLLs de System32, na ordem do AppXSvc.
    #[test]
    fn clean_install_keys_hold_the_default_volume() {
        let keys = clean_install_keys();
        let find = |path: &str| keys.iter().find(|key| key.path == path).unwrap_or_else(|| panic!("{path} faltou"));
        let value = |path: &str, name: &str| find(path).values.iter().find(|(found, _, _)| found == name).map(|(_, kind, data)| (*kind, data.clone())).unwrap_or_else(|| panic!("{path}\\{name} faltou"));
        let volumes = "Microsoft\\Windows\\CurrentVersion\\Appx\\PackageVolumes";
        assert_eq!(value(volumes, "DefaultVolumeKey"), (4, 1u32.to_le_bytes().to_vec()));
        let sis = value(&format!("{volumes}\\1"), "SISPath");
        assert_eq!(sis, (1, crate::user_services::registry_string("C:\\Program Files\\WindowsApps")));
        assert!(find(&format!("{volumes}\\1\\MutablePackagesOnline")).values.is_empty());
        let modules = find("Microsoft\\Windows\\CurrentVersion\\Appx\\DeploymentExtensionModules");
        assert_eq!(modules.values.iter().map(|(name, _, _)| name.as_str()).collect::<Vec<_>>(), ["0", "1"]);
        assert!(find("Microsoft\\Windows\\CurrentVersion\\Appx\\AppxAllUserStore\\Applications").values.is_empty());
        for queue in ["NewDeploymentOperation", "ByteCodeQueue", "PurgeList"] {
            assert!(find(&format!("Microsoft\\Windows\\CurrentVersion\\Appx\\{queue}")).values.is_empty());
        }
    }

    /// A identidade do manifesto do menu Iniciar: o nome completo é o da
    /// entrada de `InboxApplications` (`..._neutral_neutral_<publicador>`).
    #[test]
    fn identity_reads_the_manifest() {
        let manifest = r#"<?xml version="1.0"?><Package xmlns="x"><Identity Name="Microsoft.Windows.StartMenuExperienceHost" Publisher="CN=Microsoft Windows, O=Microsoft Corporation" Version="10.0.19041.5438" ResourceId="neutral"/><Properties/></Package>"#;
        let found = identity(manifest).unwrap();
        assert_eq!(found, Identity { name: String::from("Microsoft.Windows.StartMenuExperienceHost"), version: String::from("10.0.19041.5438"), architecture: String::from("neutral"), resource_id: String::from("neutral") });
        assert_eq!(found.full_name_prefix(), "Microsoft.Windows.StartMenuExperienceHost_10.0.19041.5438_neutral_neutral_");
        // Com a arquitetura e sem o ResourceId.
        let other = identity(r#"<Identity Version='1.2.3.4' ProcessorArchitecture='x64' Name='A.B'>"#).unwrap();
        assert_eq!(other.full_name_prefix(), "A.B_1.2.3.4_x64__");
        assert!(identity("<Package/>").is_none());
    }

    /// Um atributo é achado pelo nome inteiro: o `Name` não casa com o
    /// `DisplayName` nem com o `PublisherName`.
    #[test]
    fn attribute_matches_whole_names() {
        assert_eq!(attribute(r#"<X DisplayName="a" Name="b">"#, "Name").as_deref(), Some("b"));
        assert_eq!(attribute(r#"<X Name = 'c'>"#, "Name").as_deref(), Some("c"));
        assert_eq!(attribute(r#"<X PublisherName="a">"#, "Name"), None);
    }

    /// As chaves do registro não têm o SID de uma conta, e os arquivos não
    /// levam o estado que o AppXSvc gera no pacote.
    #[cfg(windows)]
    #[test]
    fn keys_and_files_carry_no_host_state() {
        let keys = super::software_keys().into_iter().chain(super::system_keys("ControlSet001"));
        for key in keys {
            assert!(!key.path.to_ascii_lowercase().contains("s-1-5-21-"), "{}", key.path);
            for (name, kind, data) in &key.values {
                assert!(!crate::logon_screen::holds_account_sid(*kind, data), "{}\\{name}", key.path);
            }
        }
        let windows = crate::windows_binaries::windows_directory();
        assert!(super::files(&windows).iter().all(|(path, _)| !path.to_ascii_lowercase().contains("microsoft.system.package.metadata")));
    }
}
