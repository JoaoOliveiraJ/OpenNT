//! O log de eventos de uma instalação nova no boot do processo inicial real
//! (`--initial-process=smss`).
//!
//! As sessões de autologger do log de eventos
//! (`Control\WMI\Autologger\EventLog-System` e `EventLog-Application`), que o
//! kernel inicia no boot (o EtwpInitializeAutoLoggers do 19041): os valores
//! da sessão e as subchaves dos provedores do próprio Windows, como esta
//! instalação os tem. O services.exe grava os eventos do Service Control
//! Manager só pelo ETW, e a sessão EventLog-System é quem habilita o
//! provedor dele ({555908d1-a6d7-4695-8e1e-26931d2012f4}). Um provedor entra
//! quando o registro dele em `WINEVT\Publishers` aponta para arquivos do
//! diretório do Windows (fora do DriverStore); os de programas e drivers
//! instalados nesta máquina ficam de fora. O `Status` de cada chave é estado
//! que o kernel grava a cada boot e não vem daqui.
//!
//! E o serviço do log de eventos (EventLog, o wevtsvc.dll no
//! `svchost.exe -k LocalServiceNetworkRestricted -p` com a conta
//! LocalService, início automático no grupo "Event Log"), que consome as
//! duas sessões em tempo real (o OpenTraceW e o ProcessTrace do
//! EventSession::StartProcessingEvents) e grava os `.evtx` em
//! `System32\winevt\Logs` (o diretório vazio de uma instalação nova, que
//! `windows_binaries` põe no volume):
//! - na SYSTEM, a chave `Services\EventLog` com o Parameters, o State e os
//!   canais clássicos (Application, System, Security, HardwareEvents,
//!   Internet Explorer, Key Management Service, Windows PowerShell), e em
//!   cada canal as fontes de eventos clássicas do próprio Windows (os
//!   arquivos de mensagens no diretório do Windows, o ProviderGuid de um
//!   provedor do Windows);
//! - na SOFTWARE, os provedores do Windows de `WINEVT\Publishers` (com as
//!   ChannelReferences), os canais de `WINEVT\Channels` cujo OwningPublisher
//!   é um deles e a configuração do grupo `LocalServiceNetworkRestricted`
//!   do svchost (a lista de serviços do grupo já vem com os valores de
//!   `Svchost`, `user_services`).
//! Uma chave que esta conta não pode ler (o canal Security, sem acesso para
//! quem não é administrador) fica de fora; o serviço cria a configuração
//! padrão dela.

use crate::host_language::HostKey;

/// As sessões de autologger do log de eventos.
#[cfg(windows)]
const AUTOLOGGERS: &[&str] = &["EventLog-System", "EventLog-Application"];

/// As subchaves de `Services\EventLog` de uma instalação nova: o
/// Parameters (o ServiceDll), o State e os canais clássicos.
#[cfg(windows)]
const SERVICE_SUBKEYS: &[&str] = &["Parameters", "State", "Application", "System", "Security", "HardwareEvents", "Internet Explorer", "Key Management Service", "Windows PowerShell"];

/// Os canais clássicos, com as fontes de eventos nas subchaves.
#[cfg(windows)]
const CLASSIC_CHANNELS: &[&str] = &["Application", "System", "Security", "HardwareEvents", "Internet Explorer", "Key Management Service", "Windows PowerShell"];

/// Um valor REG_SZ ou REG_EXPAND_SZ como texto (até o primeiro NUL).
#[cfg_attr(not(windows), allow(dead_code))]
fn string_value(kind: u32, data: &[u8]) -> Option<String> {
    if kind != 1 && kind != 2 {
        return None;
    }
    let units: Vec<u16> = data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
    Some(String::from_utf16_lossy(&units))
}

/// Uma fonte de eventos clássica do próprio Windows: os arquivos de
/// mensagens (os valores `*File`, com vários separados por ';') todos no
/// diretório do Windows e o ProviderGuid, se houver, de um provedor do
/// Windows; sem arquivo, só pelo ProviderGuid.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn windows_source(values: &[(String, u32, Vec<u8>)], inbox: impl Fn(&str) -> bool) -> bool {
    let mut files = Vec::new();
    let mut provider = None;
    for (name, kind, data) in values {
        let Some(text) = string_value(*kind, data) else { continue };
        if name.eq_ignore_ascii_case("ProviderGuid") {
            provider = Some(text);
        } else if name.to_ascii_lowercase().ends_with("file") {
            files.extend(text.split(';').map(str::trim).filter(|file| !file.is_empty()).map(String::from));
        }
    }
    let provider_ok = provider.as_deref().is_none_or(|guid| inbox(guid));
    if files.is_empty() {
        return provider.is_some() && provider_ok;
    }
    provider_ok && files.iter().all(|file| windows_file(file))
}

/// Um arquivo do próprio Windows: debaixo do diretório do sistema (pelas
/// variáveis ou pelo caminho de uma instalação padrão) e fora do
/// DriverStore, onde ficam os pacotes de drivers.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn windows_file(path: &str) -> bool {
    let lower = path.trim().trim_matches('"').to_ascii_lowercase();
    let inside = ["%systemroot%\\", "%windir%\\", "\\systemroot\\", "c:\\windows\\"].iter().any(|prefix| lower.starts_with(prefix));
    inside && !lower.contains("\\driverstore\\")
}

/// Tira o `Status` (o resultado que o kernel grava em cada boot).
#[cfg_attr(not(windows), allow(dead_code))]
fn without_status(key: &mut HostKey) {
    key.values.retain(|(name, _, _)| !name.eq_ignore_ascii_case("Status"));
}

/// O provedor `guid` tem registro em `WINEVT\Publishers` só com arquivos do
/// Windows (ResourceFileName e MessageFileName).
#[cfg(windows)]
fn inbox_publisher(guid: &str) -> bool {
    use crate::host_language::registry;
    let path = format!("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\{guid}");
    let files: Vec<String> = ["ResourceFileName", "MessageFileName"].iter().flat_map(|name| registry::strings(registry::LOCAL_MACHINE, &path, name)).collect();
    !files.is_empty() && files.iter().all(|file| windows_file(file))
}

/// As chaves da hive SYSTEM, já no conjunto de controle que a hive guarda
/// (`control_set`, como `ControlSet001`).
pub fn system_keys(control_set: &str) -> Vec<HostKey> {
    let mut keys = Vec::new();
    #[cfg(windows)]
    {
        use crate::host_language::registry;
        let host = "SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger";
        let guest = format!("{control_set}\\Control\\WMI\\Autologger");
        for session in AUTOLOGGERS {
            let first = keys.len();
            registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\{session}"), &format!("{guest}\\{session}"), false, &mut keys);
            for provider in registry::list(registry::LOCAL_MACHINE, &format!("{host}\\{session}")) {
                if inbox_publisher(&provider) {
                    registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\{session}\\{provider}"), &format!("{guest}\\{session}\\{provider}"), false, &mut keys);
                }
            }
            for key in &mut keys[first..] {
                without_status(key);
            }
        }
        // O serviço: os valores da chave, as subchaves dele e as fontes de
        // eventos do Windows em cada canal clássico.
        let service = "SYSTEM\\CurrentControlSet\\Services\\EventLog";
        let guest_service = format!("{control_set}\\Services\\EventLog");
        registry::copy(registry::LOCAL_MACHINE, service, &guest_service, false, &mut keys);
        for subkey in SERVICE_SUBKEYS {
            registry::copy(registry::LOCAL_MACHINE, &format!("{service}\\{subkey}"), &format!("{guest_service}\\{subkey}"), false, &mut keys);
        }
        for channel in CLASSIC_CHANNELS {
            for source in registry::list(registry::LOCAL_MACHINE, &format!("{service}\\{channel}")) {
                let mut copied = Vec::new();
                registry::copy(registry::LOCAL_MACHINE, &format!("{service}\\{channel}\\{source}"), &format!("{guest_service}\\{channel}\\{source}"), false, &mut copied);
                if copied.first().is_some_and(|key| windows_source(&key.values, inbox_publisher)) {
                    keys.extend(copied);
                }
            }
        }
    }
    #[cfg(not(windows))]
    let _ = control_set;
    keys
}

/// As chaves da hive SOFTWARE: os provedores e os canais do Windows em
/// `WINEVT` e a configuração do grupo do svchost do serviço.
pub fn software_keys() -> Vec<HostKey> {
    let mut keys = Vec::new();
    #[cfg(windows)]
    {
        use crate::host_language::registry;
        registry::copy(registry::LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost\\LocalServiceNetworkRestricted", "Microsoft\\Windows NT\\CurrentVersion\\Svchost\\LocalServiceNetworkRestricted", true, &mut keys);
        let winevt = "Microsoft\\Windows\\CurrentVersion\\WINEVT";
        let mut publishers = std::collections::HashSet::new();
        for guid in registry::list(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{winevt}\\Publishers")) {
            if inbox_publisher(&guid) {
                registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{winevt}\\Publishers\\{guid}"), &format!("{winevt}\\Publishers\\{guid}"), true, &mut keys);
                publishers.insert(guid.to_ascii_lowercase());
            }
        }
        for channel in registry::list(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{winevt}\\Channels")) {
            let path = format!("SOFTWARE\\{winevt}\\Channels\\{channel}");
            let owner = registry::strings(registry::LOCAL_MACHINE, &path, "OwningPublisher");
            if owner.first().is_some_and(|guid| publishers.contains(&guid.to_ascii_lowercase())) {
                registry::copy(registry::LOCAL_MACHINE, &path, &format!("{winevt}\\Channels\\{channel}"), false, &mut keys);
            }
        }
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::{windows_file, windows_source, without_status};
    use crate::host_language::HostKey;

    fn text(name: &str, value: &str) -> (String, u32, Vec<u8>) {
        (String::from(name), 2, value.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect())
    }

    /// As fontes clássicas: arquivos de mensagens no diretório do Windows e,
    /// quando há, o ProviderGuid de um provedor do Windows.
    #[test]
    fn windows_sources_only() {
        let inbox = |guid: &str| guid.eq_ignore_ascii_case("{555908d1-a6d7-4695-8e1e-26931d2012f4}");
        assert!(windows_source(&[text("ProviderGuid", "{555908D1-A6D7-4695-8E1E-26931D2012F4}"), text("EventMessageFile", "%SystemRoot%\\system32\\services.exe")], inbox));
        assert!(windows_source(&[text("EventMessageFile", "%SystemRoot%\\System32\\netevent.dll;%SystemRoot%\\System32\\kernel32.dll"), (String::from("TypesSupported"), 4, vec![7, 0, 0, 0])], inbox));
        assert!(!windows_source(&[text("EventMessageFile", "C:\\Program Files\\Google\\Chrome\\Application\\eventlog_provider.dll")], inbox));
        assert!(!windows_source(&[text("EventMessageFile", "%SystemRoot%\\System32\\netevent.dll;C:\\Program Files\\x.dll")], inbox));
        assert!(!windows_source(&[text("ProviderGuid", "{00000000-0000-0000-0000-000000000001}"), text("EventMessageFile", "%SystemRoot%\\system32\\x.dll")], inbox));
        assert!(windows_source(&[text("ProviderGuid", "{555908d1-a6d7-4695-8e1e-26931d2012f4}")], inbox));
        assert!(!windows_source(&[(String::from("TypesSupported"), 4, vec![7, 0, 0, 0])], inbox));
    }

    /// Só os arquivos do diretório do Windows, fora do DriverStore.
    #[test]
    fn windows_files_only() {
        assert!(windows_file("%SystemRoot%\\system32\\services.exe"));
        assert!(windows_file("%windir%\\System32\\lsasrv.dll"));
        assert!(windows_file("\"C:\\Windows\\System32\\wevtapi.dll\""));
        assert!(windows_file("\\SystemRoot\\system32\\drivers\\SerCx.sys"));
        assert!(!windows_file("%ProgramFiles%\\Windows Defender\\MpEvMsg.dll"));
        assert!(!windows_file("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MpEvMsg.dll"));
        assert!(!windows_file("%SystemRoot%\\System32\\DriverStore\\FileRepository\\x.inf_amd64\\x.sys"));
        assert!(!windows_file(""));
    }

    /// O Status sai; os outros valores ficam.
    #[test]
    fn status_is_dropped() {
        let mut key = HostKey { path: String::from("ControlSet001\\Control\\WMI\\Autologger\\EventLog-System"), values: vec![(String::from("Start"), 4, vec![1, 0, 0, 0]), (String::from("Status"), 4, vec![0; 4])] };
        without_status(&mut key);
        assert_eq!(key.values.len(), 1);
        assert_eq!(key.values[0].0, "Start");
    }
}
