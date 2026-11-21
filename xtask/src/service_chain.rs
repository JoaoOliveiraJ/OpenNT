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
//!   `Control\PriorityControl`;
//! - o winlogon.exe lê os assinantes das notificações de sessão em
//!   `Control\Winlogon\Notifications`;
//! - o mpr.dll (o net.exe, o explorer) lê a ordem dos provedores de rede em
//!   `Control\NetworkProvider`;
//! - o ResourcePolicyServer.dll que o psmserviceexthost.dll do DcomLaunch
//!   carrega lê as políticas de recursos em `SYSTEM\ResourcePolicyStore`;
//! - o bisrv.dll do BrokerInfrastructure lê a configuração do modelo de
//!   segundo plano em `Windows NT\CurrentVersion\BackgroundModel`: o
//!   BipGlobalTriggerConfigGetRegistryOverrides do BipMain abre
//!   `BackgroundModel\EventSettings` e, sem ela, o PsmBiExtInitialize
//!   devolve 0xC0070002, o servidor RPC do BI (8bfc3be1) não sobe e o
//!   BiNotifyNewSession do sihost dá EPT_S_NOT_REGISTERED.
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
        // Os assinantes das notificações do winlogon (Components: o serviço,
        // os eventos e o nome de cada um) e a ordem deles por evento
        // (Configurations\Default). Sem a chave, o NotifyLoadConfiguration
        // (winlogon 0x18e60) falha, o NotifyCreateSession mostra o erro pelo
        // LogonUI e a máquina de estados termina antes da tela de bloqueio.
        // Um serviço assinante que o convidado não tem só fica no log: o
        // IsServiceExpectedToStart (0x94594) não espera por ele.
        registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Control\\Winlogon\\Notifications"), &format!("{control_set}\\Control\\Winlogon\\Notifications"), true, &mut keys);
        // A ordem dos provedores de rede (HwOrder, Order e ProviderOrder):
        // o _MprDllInit do mpr.dll abre HwOrder e ProviderOrder com
        // KEY_READ e, sem elas, o DllMain volta FALSE e o processo que
        // importa o mpr.dll (o net.exe do `--conta-de-teste`, o explorer)
        // não inicia (0xC0000142). Os provedores só carregam numa chamada
        // WNet.
        registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Control\\NetworkProvider"), &format!("{control_set}\\Control\\NetworkProvider"), true, &mut keys);
        // As políticas de recursos da instalação (ResourceSets e
        // TierThresholds): o CreatePolicyStore do RmRpsInitialize
        // (ResourcePolicyServer.dll) abre `ResourcePolicyStore\ResourceSets`;
        // sem ela o RmRpsInitialize devolve 0x80070002, o RmpStartAllModules
        // do psmserviceexthost.dll falha e os servidores RPC do HAM não sobem.
        registry::copy(registry::LOCAL_MACHINE, "SYSTEM\\ResourcePolicyStore", "ResourcePolicyStore", true, &mut keys);
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
            "Microsoft\\Windows NT\\CurrentVersion\\BackgroundModel",
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
