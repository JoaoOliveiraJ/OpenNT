//! Os serviços Win32 desta instalação que o services.exe real inicia no boot
//! do processo inicial real (`--initial-process=smss`): a cadeia do Local
//! Session Manager.
//!
//! O winlogon.exe da sessão 1 espera o `Global\TermSrvReadyEvent`, que só o
//! LSM liga. O LSM (o lsm.dll) roda num svchost.exe que o services.exe cria
//! no início automático (`svchost.exe -k DcomLaunch -p`), depois das
//! dependências dele: o DcomLaunch (o rpcss.dll no mesmo svchost), o
//! RpcEptMapper e o RpcSs (o RpcEpMap.dll e o rpcss.dll no
//! `svchost.exe -k rpcss -p`).
//!
//! Como os binários de System32, as chaves vêm desta máquina no build, com os
//! valores daqui: as chaves de serviço desses quatro e as do Power, do
//! BrokerInfrastructure e do SystemEventsBroker (com Parameters e
//! Security), a ordem dos grupos de serviço (`Control\ServiceGroupOrder`),
//! a configuração de energia (`Control\Power`), as definições WNF
//! (`Control\Notifications`), as opções do produto (`Control\ProductOptions`)
//! e,
//! na SOFTWARE, os grupos do svchost (`Microsoft\Windows NT\CurrentVersion\
//! Svchost`, os valores com a lista de serviços de cada grupo, e
//! `Microsoft\Rpc\SecurityService`, os provedores de autenticação do RPC, e
//! os valores de `Microsoft\Windows NT\CurrentVersion\WUDF` e da
//! `ProfileList`, só com os perfis das contas de serviço).
//! A SYSTEM leva ainda o `Control\Terminal Server` com as subchaves, que o
//! lsm.dll exige ao subir. E a
//! configuração das extensões do LSA (`Control\LsaExtensionConfig`: o
//! lsasrv.dll, o efslsaext.dll e a interface do dpapisrv.dll), que o
//! LsapLoadRequiredExtensions do lsass.exe lê depois de conectar ao
//! Reference Monitor, e o `Control\Lsa` com as subchaves, menos as da chave
//! de boot. Fora do Windows nada é copiado.

use crate::host_language::HostKey;

/// Os serviços da cadeia do LSM e os do mesmo svchost do DcomLaunch que o
/// início automático sobe com ele: o Power (o umpo.dll, que o
/// ScAutoStartServices inicia pelo nome antes dos outros), o
/// BrokerInfrastructure e o SystemEventsBroker.
const SERVICES: &[&str] = &["DcomLaunch", "RpcEptMapper", "RpcSs", "LSM", "Power", "BrokerInfrastructure", "SystemEventsBroker"];

/// As chaves da hive SYSTEM, já no conjunto de controle que a hive guarda
/// (`control_set`, como `ControlSet001`).
pub fn system_keys(control_set: &str) -> Vec<HostKey> {
    let mut keys = Vec::new();
    #[cfg(windows)]
    {
        use crate::host_language::registry;
        let host = "SYSTEM\\CurrentControlSet";
        for service in SERVICES {
            registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Services\\{service}"), &format!("{control_set}\\Services\\{service}"), true, &mut keys);
        }
        registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Control\\ServiceGroupOrder"), &format!("{control_set}\\Control\\ServiceGroupOrder"), false, &mut keys);
        // As opções do produto: o tipo, a suíte e a política de licença
        // (ProductPolicy) que o NtQueryLicenseValue lê; sem ela toda
        // consulta de licença volta STATUS_DATA_ERROR e o GetProductInfo dá
        // PRODUCT_UNDEFINED.
        registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Control\\ProductOptions"), &format!("{control_set}\\Control\\ProductOptions"), false, &mut keys);
        // A configuração de energia que o serviço Power (o umpo.dll) lê: os
        // esquemas, as configurações e os padrões (o Control\Power com as
        // subchaves que esta conta lê).
        registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Control\\Power"), &format!("{control_set}\\Control\\Power"), true, &mut keys);
        registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Control\\LsaExtensionConfig"), &format!("{control_set}\\Control\\LsaExtensionConfig"), true, &mut keys);
        // As definições dos nomes WNF permanentes e persistentes desta
        // instalação (`Control\Notifications`: um REG_BINARY por nome, com o
        // descritor, o limite de dados e o tipo, sem dados publicados). O
        // ExpWnfLookupNameDefinition do kernel lê a definição para cada
        // NtQueryWnfStateData e NtSubscribeWnfStateChange de um nome bem
        // conhecido ou permanente; sem ela o rpcss (o
        // WNF_UMGR_SESSIONUSER_TOKEN_CHANGE), o CPolicyMonitor do lsm (o
        // WNF_GPOL_SYSTEM_CHANGES), o psmsrv e o brokerlib recebem
        // STATUS_OBJECT_NAME_NOT_FOUND e param.
        registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Control\\Notifications"), &format!("{control_set}\\Control\\Notifications"), false, &mut keys);
        // A configuração dos Serviços de Terminal com as subchaves
        // (WinStations, AddIns, TerminalTypes, RCM e as outras): o
        // CPolicyMonitor do CService::Start do lsm.dll abre `Terminal Server`
        // e `Terminal Server\WinStations` e falha sem elas; o lsm lê ainda o
        // TSAppCompat, o DelayReadyEventTimeout e o TSServerDrainMode.
        registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Control\\Terminal Server"), &format!("{control_set}\\Control\\Terminal Server"), true, &mut keys);
        // Os valores do LSA (os pacotes de autenticação e de notificação que
        // o lsass carrega, o tipo de produto) e as subchaves dele (o MSV1_0,
        // as políticas de acesso central que o LsapOpenCapDb abre, a
        // auditoria, o Kerberos), sem as que guardam a chave de boot da
        // instalação nas classes (JD, Skew1, GBG, Data): o lsasrv do
        // convidado gera a dele no primeiro boot (o WxSaveSysKey). As chaves
        // que esta conta não lê ficam de fora.
        registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Control\\Lsa"), &format!("{control_set}\\Control\\Lsa"), false, &mut keys);
        // O convidado não tem as hives SECURITY e SAM desta instalação (as
        // contas e os segredos daqui ficam fora do volume): o kernel as
        // monta vazias e o lsass cria as dele. O lsasrv e o samsrv só criam
        // os bancos fora da instalação do Windows com o
        // CreatePolicyDatabaseOnFirstBoot diferente de zero (o
        // SampSKUAllowsHiveCreation do SampInitialize e o LsapExpectDomainId
        // do lsasrv leem o valor), o valor das imagens que geram os bancos
        // no primeiro boot.
        let lsa = format!("{control_set}\\Control\\Lsa");
        if let Some(key) = keys.iter_mut().find(|key| key.path == lsa) {
            key.values.retain(|(name, _, _)| !name.eq_ignore_ascii_case("CreatePolicyDatabaseOnFirstBoot"));
            key.values.push((String::from("CreatePolicyDatabaseOnFirstBoot"), 4, 1u32.to_le_bytes().to_vec()));
        }
        for name in registry::list(registry::LOCAL_MACHINE, &format!("{host}\\Control\\Lsa")) {
            if ["JD", "Skew1", "GBG", "Data"].iter().any(|boot_key| boot_key.eq_ignore_ascii_case(&name)) {
                continue;
            }
            registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Control\\Lsa\\{name}"), &format!("{control_set}\\Control\\Lsa\\{name}"), true, &mut keys);
        }
    }
    #[cfg(not(windows))]
    let _ = control_set;
    keys
}

/// As chaves da hive SOFTWARE: os grupos do svchost, os provedores de
/// autenticação do RPC e a configuração do WUDF.
pub fn software_keys() -> Vec<HostKey> {
    let mut keys = Vec::new();
    #[cfg(windows)]
    {
        use crate::host_language::registry;
        registry::copy(registry::LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost", "Microsoft\\Windows NT\\CurrentVersion\\Svchost", false, &mut keys);
        // Os provedores de autenticação do RPC (o número do serviço de
        // autenticação e o DLL dele: 9, 10 e 16 no sspicli.dll, 14 no
        // schannel.dll, 68 no netlogon.dll), que o RpcGetSecurityProviderInfo
        // do rpcrt4.dll lê. Sem a chave, o RpcServerRegisterAuthInfo do lsass
        // volta RPC_S_UNKNOWN_AUTHN_SERVICE.
        registry::copy(registry::LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Rpc\\SecurityService", "Microsoft\\Rpc\\SecurityService", false, &mut keys);
        // A configuração do gerenciador de drivers de modo usuário (os
        // valores do WUDF, sem a lista de drivers UMDF desta máquina): o
        // WdfDriverManager::LoadRegistrySettings do InitWudfDriverManager do
        // services.exe recusa a falta do DefaultHostProcessGUID, e o
        // SvcctrlMain sai antes do início automático.
        registry::copy(registry::LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\WUDF", "Microsoft\\Windows NT\\CurrentVersion\\WUDF", false, &mut keys);
        // A lista de perfis: os diretórios (ProgramData, Public, Default e
        // ProfilesDirectory), que o wininit lê para definir o %ProgramData% e
        // as outras variáveis do sistema, e os perfis das contas de serviço
        // (S-1-5-18, -19 e -20). Os perfis das contas de usuário desta
        // máquina ficam de fora.
        registry::copy(registry::LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", "Microsoft\\Windows NT\\CurrentVersion\\ProfileList", false, &mut keys);
        for account in ["S-1-5-18", "S-1-5-19", "S-1-5-20"] {
            registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{account}"), &format!("Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{account}"), true, &mut keys);
        }
    }
    keys
}
