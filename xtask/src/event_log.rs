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

use crate::host_language::HostKey;

/// As sessões de autologger do log de eventos.
#[cfg(windows)]
const AUTOLOGGERS: &[&str] = &["EventLog-System", "EventLog-Application"];

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
    }
    #[cfg(not(windows))]
    let _ = control_set;
    keys
}

#[cfg(test)]
mod tests {
    use super::{windows_file, without_status};
    use crate::host_language::HostKey;

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
