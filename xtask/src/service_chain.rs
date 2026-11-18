//! As chaves desta instalação que os serviços do início automático e o LSM
//! leem no boot do processo inicial real (`--initial-process=smss`), além
//! das chaves de serviço de `user_services`.
//!
//! A lista vem do mapa da cadeia (`docs/mapa-cadeia.md`), pelas strings de
//! caminho de registro dos binários:
//!
//! - o rpcss.dll do DcomLaunch e do RpcSs lê `Microsoft\OLE`,
//!   `Microsoft\COM3`, `Microsoft\Rpc`, `WindowsRuntime\AllowedCOMCLSIDs` e
//!   `Windows NT\CurrentVersion\Containers`; o RpcEpMap.dll do RpcEptMapper,
//!   `Rpc\Extensions` e `CurrentVersion\NetworkServiceTriggers`;
//! - o lsm.dll lê os valores de `Windows NT\CurrentVersion\Winlogon` e
//!   `CurrentVersion\SharedPC`; o winsrvext.dll do csrss lê
//!   `Control\PriorityControl`.
//!
//! O `SYSTEM\Setup` que o lsm.dll também lê não vem daqui: o estado de setup
//! de uma instalação concluída é o mesmo em toda máquina e sai da tabela
//! `cm/setup_state.rs`. Os valores que dizem respeito ao usuário desta
//! máquina (o último logon, o logon automático) ficam de fora. Fora do
//! Windows nada é copiado.

use crate::host_language::HostKey;

/// Valores de `Winlogon` que identificam o usuário ou o último logon desta
/// máquina.
#[cfg(windows)]
const WINLOGON_LOCAL_VALUES: &[&str] = &[
    "AutoLogonSID",
    "LastUsedUsername",
    "LastLogOffEndTimePerfCounter",
    "ShutdownFlags",
    "DefaultUserName",
    "DefaultDomainName",
    "DefaultPassword",
    "AltDefaultUserName",
    "AltDefaultDomainName",
    "AutoAdminLogon",
];

/// As chaves da hive SYSTEM, já no conjunto de controle que a hive guarda
/// (`control_set`, como `ControlSet001`).
pub fn system_keys(control_set: &str) -> Vec<HostKey> {
    let mut keys = Vec::new();
    #[cfg(windows)]
    {
        use crate::host_language::registry;
        let host = "SYSTEM\\CurrentControlSet";
        registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Control\\PriorityControl"), &format!("{control_set}\\Control\\PriorityControl"), false, &mut keys);
    }
    #[cfg(not(windows))]
    let _ = control_set;
    keys
}

/// As chaves da hive SOFTWARE.
pub fn software_keys() -> Vec<HostKey> {
    let mut keys = Vec::new();
    #[cfg(windows)]
    {
        use crate::host_language::registry;
        for path in [
            "Microsoft\\OLE",
            "Microsoft\\COM3",
            "Microsoft\\Rpc",
            "Microsoft\\WindowsRuntime\\AllowedCOMCLSIDs",
            "Microsoft\\Windows NT\\CurrentVersion\\Containers",
            "Microsoft\\Windows\\CurrentVersion\\NetworkServiceTriggers",
            "Microsoft\\Windows\\CurrentVersion\\SharedPC",
        ] {
            registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{path}"), path, true, &mut keys);
        }
        let first = keys.len();
        registry::copy(registry::LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Microsoft\\Windows NT\\CurrentVersion\\Winlogon", false, &mut keys);
        if let Some(winlogon) = keys.get_mut(first) {
            winlogon.values.retain(|(name, _, _)| !WINLOGON_LOCAL_VALUES.iter().any(|local| local.eq_ignore_ascii_case(name)));
        }
    }
    keys
}
