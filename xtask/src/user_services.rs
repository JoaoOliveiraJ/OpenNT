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
//! valores daqui: as chaves de serviço desses quatro e as do PlugPlay, do
//! Power, do BrokerInfrastructure, do SystemEventsBroker, do registrador
//! do CoreMessaging e da política de vídeo (com Parameters e Security) e a
//! do gerenciador de usuários (UserManager, com Parameters e TriggerInfo e
//! sem Security), a
//! ordem dos grupos de serviço (`Control\ServiceGroupOrder`), os dois
//! valores de `Control` que
//! o services.exe lê no início automático (o `EarlyStartServices`, a lista
//! do conjunto inicial, e o `SvcHostSplitThresholdInKB`, o limite de
//! memória para separar os serviços de um svchost em processos próprios,
//! com o valor de uma instalação nova),
//! o `FullProcessInformationSID` de `Control\Windows`, que o
//! BrokerInfrastructure lê ao subir,
//! a configuração de energia (`Control\Power`, com os esquemas padrão da
//! instalação, `default_power_schemes`, e "Desligar a tela: Nunca" no
//! esquema ativo: `power_policy`), as definições dos nomes WNF bem
//! conhecidos (`Control\Notifications`), as opções do produto (`Control\ProductOptions`,
//! com a política de licença de uma instalação limpa e não ativada desta
//! edição: `product_policy`) e, na SOFTWARE, os grupos do svchost (`Microsoft\Windows NT\CurrentVersion\
//! Svchost`, os valores com a lista de serviços de cada grupo e as subchaves
//! do `LocalServiceNoNetwork` e do `LocalService`), os descritores das
//! portas de nome transitório
//! (`Microsoft\SecurityManager\TransientObjects`),
//! `Microsoft\Rpc\SecurityService`, os provedores de autenticação do RPC, e
//! os valores de `Microsoft\Windows NT\CurrentVersion\WUDF`; a
//! `ProfileList` vem de `user_profiles`).
//! A SYSTEM leva ainda o `Control\Terminal Server` com as subchaves, que o
//! lsm.dll exige ao subir. E a
//! configuração das extensões do LSA (`Control\LsaExtensionConfig`: o
//! lsasrv.dll, o efslsaext.dll e a interface do dpapisrv.dll), que o
//! LsapLoadRequiredExtensions do lsass.exe lê depois de conectar ao
//! Reference Monitor, e o `Control\Lsa` com as subchaves, menos as da chave
//! de boot e o cache dos pacotes de segurança. Fora do Windows nada é
//! copiado.

use crate::host_language::HostKey;

/// Os serviços da cadeia do LSM e os do mesmo svchost do DcomLaunch que o
/// início automático sobe com ele: o PlugPlay (o umpnpmgr.dll) e o Power (o
/// umpo.dll), que o ScAutoStartServices inicia pelo nome, nessa ordem, antes
/// dos outros, o BrokerInfrastructure e o SystemEventsBroker. E o
/// registrador do CoreMessaging (CoreMessagingRegistrar, o coremessaging.dll
/// no `svchost.exe -k LocalServiceNoNetwork -p` com a conta LocalService,
/// início automático depois do rpcss): toda sessão CoreUI do dwm.exe e do
/// LogonUI conecta por ALPC à porta `\BaseNamedObjects\CoreMessagingRegistrar`
/// dele e, sem a porta, abre o serviço pelo SCM para iniciá-lo; um serviço
/// que não existe é um FailFast. E o serviço de política de vídeo
/// (DispBrokerDesktopSvc, o DispBroker.Desktop.dll no
/// `svchost.exe -k LocalService -p` com a conta LocalService, início
/// automático atrasado): o servidor da classe WinRT fora de processo
/// DispBrokerDesktop.GlobalBrokerInstance, que a SessionBrokerInstance do
/// dwm.exe ativa pelo RPCSS na partida (`logon_screen`), o que inicia o
/// serviço antes do atraso. E o gerenciador de usuários (UserManager, o
/// usermgr.dll no `svchost.exe -k netsvcs -p` com a conta LocalSystem,
/// início automático depois do RpcSs e do ProfSvc de `user_profiles`, com o
/// gatilho da interface RPC b18fbab6-56f8-4702-84e0-41053293a869): com ele
/// RUNNING o winlogon faz o logon por ele (UMgrLogonUser), avisa o logon
/// (UMgrInformUserLogon, que manda ao services.exe o controle 0x21 dos
/// serviços por usuário) e pede o sihost.exe
/// (UMgrLaunchShellInfrastructureHost). O próprio usermgr.dll ativa as
/// fábricas Windows.System.User e Windows.System.Internal.UserManager ao
/// subir (o servidor WinRT UserManager de `logon_screen`) e para o serviço
/// sem elas; e marca o svchost dele como crítico (RtlSetProcessIsCritical,
/// com o `ShellInfrastructure` do Winlogon). A chave não tem Security: o
/// services.exe dá ao serviço o descritor padrão (ScCreateScServiceObject).
const SERVICES: &[&str] = &["DcomLaunch", "RpcEptMapper", "RpcSs", "LSM", "PlugPlay", "Power", "BrokerInfrastructure", "SystemEventsBroker", "CoreMessagingRegistrar", "DispBrokerDesktopSvc", "UserManager"];

/// Os valores de `Control` que o services.exe lê: o EarlyStartServices (o
/// ScStartEarlySetOfServices; sem ele todo serviço automático entra no
/// conjunto inicial), copiado desta máquina, e o SvcHostSplitThresholdInKB
/// ([`SVCHOST_SPLIT_THRESHOLD_KB`]).
#[cfg(windows)]
const CONTROL_VALUES: &[&str] = &["EarlyStartServices"];

/// O SvcHostSplitThresholdInKB de uma instalação nova: 0x380000 KB (3,5 GB),
/// o valor que a imagem do Windows traz. Nenhum programa o calcula: o
/// services.exe só o lê (o ScReadSCMConfiguration separa os serviços de um
/// svchost quando a memória física do GlobalMemoryStatusEx chega ao limite;
/// sem o valor não separa), então quem decide é a memória do convidado, e o
/// valor desta máquina, que pode ter sido trocado, não vai.
#[cfg_attr(not(windows), allow(dead_code))]
const SVCHOST_SPLIT_THRESHOLD_KB: u32 = 0x38_0000;

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
        // O UserManager de uma instalação nova não tem Security (o descritor
        // é o padrão do services.exe); uma Security desta máquina teria SIDs
        // daqui.
        keys.retain(|key| !key.path.to_ascii_lowercase().ends_with("\\services\\usermanager\\security"));
        registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Control\\ServiceGroupOrder"), &format!("{control_set}\\Control\\ServiceGroupOrder"), false, &mut keys);
        // Só os valores de CONTROL_VALUES da chave Control.
        let first = keys.len();
        registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Control"), &format!("{control_set}\\Control"), false, &mut keys);
        if let Some(control) = keys.get_mut(first) {
            control.values.retain(|(name, _, _)| CONTROL_VALUES.iter().any(|kept| kept.eq_ignore_ascii_case(name)));
            control.values.push((String::from("SvcHostSplitThresholdInKB"), 4, SVCHOST_SPLIT_THRESHOLD_KB.to_le_bytes().to_vec()));
        }
        // Só o FullProcessInformationSID da chave Control\Windows (um SID de
        // serviço, S-1-5-80-...): o PsmpInitializeQueryDescriptor do
        // psmsrv.dll o acrescenta ao descritor de consulta do
        // BrokerInfrastructure e, sem o valor, o NtQueryValueKey volta
        // STATUS_OBJECT_NAME_NOT_FOUND, o PsmpStartServer falha e o serviço
        // para logo depois de iniciar. O ShutdownTime da chave fica com o
        // kernel.
        let first = keys.len();
        registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Control\\Windows"), &format!("{control_set}\\Control\\Windows"), false, &mut keys);
        if let Some(windows) = keys.get_mut(first) {
            windows.values.retain(|(name, _, _)| name.eq_ignore_ascii_case("FullProcessInformationSID"));
        }
        // As opções do produto: o tipo, a suíte e a política de licença
        // (ProductPolicy) que o NtQueryLicenseValue lê; sem ela toda
        // consulta de licença volta STATUS_DATA_ERROR e o GetProductInfo dá
        // PRODUCT_UNDEFINED.
        let product_options = keys.len();
        registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Control\\ProductOptions"), &format!("{control_set}\\Control\\ProductOptions"), false, &mut keys);
        // Só o tipo, a suíte e a política. A política é a de uma instalação
        // limpa e não ativada desta edição (`product_policy`): as entradas
        // das licenças da edição, com os dados delas, e o estado de ativação
        // de uma instalação nova; sem as licenças, o valor fica de fora.
        if let Some(options) = keys.get_mut(product_options) {
            options.values.retain(|(name, _, _)| PRODUCT_OPTIONS_VALUES.iter().any(|kept| kept.eq_ignore_ascii_case(name)));
            let windows = crate::windows_binaries::windows_directory();
            options.values.retain_mut(|(name, _, data)| {
                if !name.eq_ignore_ascii_case("ProductPolicy") {
                    return true;
                }
                match crate::product_policy::guest_policy(data, &windows) {
                    Some(policy) => {
                        *data = policy;
                        true
                    }
                    None => false,
                }
            });
        }
        // A configuração de energia que o serviço Power (o umpo.dll) lê: os
        // esquemas, as configurações e os padrões (o Control\Power com as
        // subchaves que esta conta lê).
        registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Control\\Power"), &format!("{control_set}\\Control\\Power"), true, &mut keys);
        // Os esquemas de uma instalação nova (`default_power_schemes`) e,
        // neles, "Desligar a tela: Nunca" no esquema ativo (`power_policy`).
        default_power_schemes(control_set, &mut keys);
        power_policy(control_set, &mut keys);
        registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Control\\LsaExtensionConfig"), &format!("{control_set}\\Control\\LsaExtensionConfig"), true, &mut keys);
        // As definições dos nomes WNF bem conhecidos (`Control\Notifications`:
        // um REG_BINARY por nome, com o descritor, o limite de dados e o
        // tipo, sem dados publicados). O ExpWnfLookupNameDefinition do kernel
        // lê a definição para cada NtQueryWnfStateData e
        // NtSubscribeWnfStateChange de um nome bem conhecido; sem ela o rpcss
        // (o WNF_UMGR_SESSIONUSER_TOKEN_CHANGE), o CPolicyMonitor do lsm (o
        // WNF_GPOL_SYSTEM_CHANGES), o psmsrv e o brokerlib recebem
        // STATUS_OBJECT_NAME_NOT_FOUND e param. Só os nomes bem conhecidos
        // (`well_known_wnf`), que os componentes do Windows definem na
        // instalação e nenhum programa cria depois; os descritores levam SIDs
        // de serviço, de capacidade e um domínio S-1-5-21 fixo que os próprios
        // binários do Windows trazem nas cadeias SDDL (o lsasrv.dll, o
        // cdp.dll, o diagtrack.dll), não o desta máquina.
        let notifications = keys.len();
        registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Control\\Notifications"), &format!("{control_set}\\Control\\Notifications"), false, &mut keys);
        if let Some(key) = keys.get_mut(notifications) {
            key.values.retain(|(name, _, _)| well_known_wnf(name));
        }
        // A configuração dos Serviços de Terminal com as subchaves
        // (WinStations, AddIns, TerminalTypes, RCM e as outras): o
        // CPolicyMonitor do CService::Start do lsm.dll abre `Terminal Server`
        // e `Terminal Server\WinStations` e falha sem elas; o lsm lê ainda o
        // TSAppCompat, o DelayReadyEventTimeout e o TSServerDrainMode.
        registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Control\\Terminal Server"), &format!("{control_set}\\Control\\Terminal Server"), true, &mut keys);
        let terminal_server = format!("{control_set}\\Control\\Terminal Server");
        if let Some(key) = keys.iter_mut().find(|key| key.path == terminal_server) {
            // O InstanceID é gerado por instalação.
            key.values.retain(|(name, _, _)| !name.eq_ignore_ascii_case("InstanceID"));
        }
        // Os valores do LSA (os pacotes de autenticação e de notificação que
        // o lsass carrega, o tipo de produto) e as subchaves dele (o MSV1_0,
        // as políticas de acesso central que o LsapOpenCapDb abre, a
        // auditoria, o Kerberos), sem as que guardam a chave de boot da
        // instalação nas classes (JD, Skew1, GBG, Data): o lsasrv do
        // convidado gera a dele no primeiro boot (o WxSaveSysKey). Fica de
        // fora também o cache dos pacotes de segurança (`SspiCache`), que a
        // instalação não traz: o SecCacheSspiPackages do sspicli.dll o cria
        // quando falta, com a hora do arquivo de cada pacote e a hora da
        // gravação (o GetSystemTimeAsFileTime), e o do convidado grava o dele.
        // As chaves que esta conta não lê ficam de fora.
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
            if ["JD", "Skew1", "GBG", "Data", "SspiCache"].iter().any(|excluded| excluded.eq_ignore_ascii_case(&name)) {
                continue;
            }
            registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Control\\Lsa\\{name}"), &format!("{control_set}\\Control\\Lsa\\{name}"), true, &mut keys);
        }
    }
    #[cfg(not(windows))]
    let _ = control_set;
    keys
}

/// SUB_VIDEO e os dois timeouts de tela que o kernel do 19041 usa na tela de
/// logon e no console bloqueado: VIDEOIDLE (GUID_VIDEO_POWERDOWN_TIMEOUT) e
/// VIDEOCONLOCK (GUID_VIDEO_CONSOLE_LOCK_TIMEOUT).
#[cfg_attr(not(windows), allow(dead_code))]
const SUB_VIDEO: &str = "7516b95f-f776-4464-8c53-06167f40cc99";
#[cfg_attr(not(windows), allow(dead_code))]
const VIDEO_TIMEOUTS: [&str; 2] = ["3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e", "8ec4b3a5-6868-48c2-be75-4f3044be88a7"];
/// O esquema Equilibrado, o ativo de uma instalação nova.
#[cfg_attr(not(windows), allow(dead_code))]
const BALANCED: &str = "381b4222-f694-41f0-9685-ff5bb260df2e";

/// "Desligar a tela: Nunca" no esquema ativo, como o `powercfg /change
/// monitor-timeout-ac 0` (e `-dc 0`) e o `powercfg /setacvalueindex
/// SCHEME_CURRENT SUB_VIDEO VIDEOCONLOCK 0` (e o dc) gravam pelo serviço Power:
/// ACSettingIndex e DCSettingIndex zero em
/// `Control\Power\User\PowerSchemes\{esquema}\{SUB_VIDEO}\{setting}`. O umpo
/// manda os valores ao kernel pelo `\PowerPort`. Numa instalação nova a tela
/// de logon apaga depois de 600 s sem entrada (VIDEOIDLE do Equilibrado, AC) e
/// a do console bloqueado depois de 60 s (VIDEOCONLOCK); com os dois em zero
/// o win32k nunca desliga a tela durante os testes, qualquer que seja a
/// configuração desta máquina. O EnforceConsoleLockScreenTimeout desta máquina
/// (que faz o VIDEOCONLOCK valer acima do VIDEOIDLE) não vai ao convidado.
#[cfg_attr(not(windows), allow(dead_code))]
fn power_policy(control_set: &str, keys: &mut Vec<HostKey>) {
    let power = format!("{control_set}\\Control\\Power");
    if let Some(key) = keys.iter_mut().find(|key| key.path.eq_ignore_ascii_case(&power)) {
        key.values.retain(|(name, _, _)| !name.eq_ignore_ascii_case("EnforceConsoleLockScreenTimeout"));
    }
    let schemes = format!("{power}\\User\\PowerSchemes");
    let active = keys
        .iter()
        .find(|key| key.path.eq_ignore_ascii_case(&schemes))
        .and_then(|key| key.values.iter().find(|(name, kind, _)| name.eq_ignore_ascii_case("ActivePowerScheme") && *kind == 1))
        .map(|(_, _, data)| {
            let units: Vec<u16> = data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
            String::from_utf16_lossy(&units)
        })
        .filter(|scheme| !scheme.is_empty())
        .unwrap_or_else(|| String::from(BALANCED));
    for setting in VIDEO_TIMEOUTS {
        let zero = 0u32.to_le_bytes().to_vec();
        // O hive_from_seeds cria as chaves-pai, e o valor que vem depois
        // substitui o copiado desta máquina.
        keys.push(HostKey {
            path: format!("{schemes}\\{active}\\{SUB_VIDEO}\\{setting}"),
            values: vec![(String::from("ACSettingIndex"), 4, zero.clone()), (String::from("DCSettingIndex"), 4, zero)],
        });
    }
}

/// Os esquemas de energia de uma instalação nova: `User\PowerSchemes` passa a
/// ser a cópia de `User\Default\PowerSchemes`, os esquemas padrão que a
/// instalação traz (o que o `powercfg -restoredefaultschemes` refaz), com o
/// ActivePowerScheme padrão. As mudanças desta máquina nos esquemas (os
/// índices trocados, o modo de energia `ActiveOverlay*PowerScheme`, o esquema
/// ativo) não vão ao convidado.
#[cfg_attr(not(windows), allow(dead_code))]
fn default_power_schemes(control_set: &str, keys: &mut Vec<HostKey>) {
    let user = format!("{control_set}\\Control\\Power\\User\\PowerSchemes");
    let defaults = format!("{control_set}\\Control\\Power\\User\\Default\\PowerSchemes");
    let under = |path: &str, root: &str| path.len() >= root.len() && path[..root.len()].eq_ignore_ascii_case(root) && (path.len() == root.len() || path.as_bytes()[root.len()] == b'\\');
    keys.retain(|key| !under(&key.path, &user));
    let copies: Vec<HostKey> = keys.iter().filter(|key| under(&key.path, &defaults)).map(|key| HostKey { path: format!("{user}{}", &key.path[defaults.len()..]), values: key.values.clone() }).collect();
    keys.extend(copies);
}

/// Um valor de `Control\Notifications` cujo nome é o de um nome WNF bem
/// conhecido: o nome é o WNF_STATE_NAME em hexadecimal, e o nome real (com o
/// XOR de 0x41C64E6DA3BC0074) traz o tempo de vida nos bits 4 e 5, zero para
/// os bem conhecidos (WnfWellKnownStateName). Os permanentes, persistentes e
/// temporários são criados depois da instalação.
#[cfg_attr(not(windows), allow(dead_code))]
fn well_known_wnf(value_name: &str) -> bool {
    const STATE_NAME_XOR: u64 = 0x41C6_4E6D_A3BC_0074;
    value_name.len() == 16 && u64::from_str_radix(value_name, 16).is_ok_and(|name| ((name ^ STATE_NAME_XOR) >> 4) & 3 == 0)
}

#[cfg(test)]
mod tests {
    use super::{default_power_schemes, power_policy, well_known_wnf, BALANCED, SUB_VIDEO, VIDEO_TIMEOUTS};
    use crate::host_language::HostKey;

    /// Os esquemas do convidado são os padrão: os de `User\PowerSchemes`
    /// desta máquina saem e entram os de `User\Default\PowerSchemes`, com o
    /// esquema ativo padrão.
    #[test]
    fn power_schemes_come_from_the_defaults() {
        let utf16 = |text: &str| text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect::<Vec<u8>>();
        let power = "ControlSet001\\Control\\Power\\User";
        let key = |path: &str, values: Vec<(String, u32, Vec<u8>)>| HostKey { path: format!("{power}{path}"), values };
        let index = |value: u32| vec![(String::from("ACSettingIndex"), 4, value.to_le_bytes().to_vec())];
        let mut keys = vec![
            key("\\PowerSchemes", vec![(String::from("ActivePowerScheme"), 1, utf16("custom")), (String::from("ActiveOverlayAcPowerScheme"), 1, utf16("custom"))]),
            key("\\PowerSchemes\\custom", vec![(String::from("FriendlyName"), 1, utf16("Meu plano"))]),
            key("\\PowerSchemes\\381b4222\\sub\\setting", index(7)),
            key("\\PowerSchemesOther", vec![]),
            key("\\Default\\PowerSchemes", vec![(String::from("ActivePowerScheme"), 1, utf16("381b4222"))]),
            key("\\Default\\PowerSchemes\\381b4222\\sub\\setting", index(3)),
        ];
        default_power_schemes("ControlSet001", &mut keys);
        let find = |path: &str| keys.iter().find(|key| key.path == format!("{power}{path}"));
        assert!(find("\\PowerSchemes\\custom").is_none());
        assert_eq!(find("\\PowerSchemes").unwrap().values, vec![(String::from("ActivePowerScheme"), 1, utf16("381b4222"))]);
        assert_eq!(find("\\PowerSchemes\\381b4222\\sub\\setting").unwrap().values, index(3));
        assert_eq!(keys.iter().filter(|key| key.path.ends_with("\\PowerSchemes\\381b4222\\sub\\setting")).count(), 2);
        assert!(find("\\PowerSchemesOther").is_some());
        assert!(find("\\Default\\PowerSchemes\\381b4222\\sub\\setting").is_some());
    }

    /// Só os nomes WNF bem conhecidos (tempo de vida zero depois do XOR).
    #[test]
    fn only_well_known_wnf_names() {
        // WNF_GPOL_SYSTEM_CHANGES (0x0D891E2AA3BC0875): bem conhecido.
        assert!(well_known_wnf("0D891E2AA3BC0875"));
        // O mesmo com o tempo de vida 1 (permanente), 2 e 3.
        assert!(!well_known_wnf("0D891E2AA3BC0865"));
        assert!(!well_known_wnf("0D891E2AA3BC0855"));
        assert!(!well_known_wnf("0D891E2AA3BC0845"));
        assert!(!well_known_wnf("Persistent"));
        assert!(!well_known_wnf("0D891E2AA3BC08"));
    }

    /// O plano de energia do convidado: sem o EnforceConsoleLockScreenTimeout
    /// desta máquina e com os dois timeouts de tela em zero no esquema ativo
    /// (o Equilibrado quando a chave não diz qual é).
    #[test]
    fn power_policy_turns_display_off_never() {
        let utf16 = |text: &str| text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect::<Vec<u8>>();
        let mut keys = vec![
            HostKey { path: String::from("ControlSet001\\Control\\Power"), values: vec![(String::from("EnforceConsoleLockScreenTimeout"), 4, 1u32.to_le_bytes().to_vec()), (String::from("HibernateEnabled"), 4, 0u32.to_le_bytes().to_vec())] },
            HostKey { path: String::from("ControlSet001\\Control\\Power\\User\\PowerSchemes"), values: vec![(String::from("ActivePowerScheme"), 1, utf16("8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"))] },
        ];
        power_policy("ControlSet001", &mut keys);
        assert!(keys[0].values.iter().all(|(name, _, _)| name != "EnforceConsoleLockScreenTimeout"));
        assert!(keys[0].values.iter().any(|(name, _, _)| name == "HibernateEnabled"));
        for setting in VIDEO_TIMEOUTS {
            let path = format!("ControlSet001\\Control\\Power\\User\\PowerSchemes\\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c\\{SUB_VIDEO}\\{setting}");
            let key = keys.iter().rev().find(|key| key.path == path).expect("chave do timeout");
            let expected: Vec<(String, u32, Vec<u8>)> = vec![(String::from("ACSettingIndex"), 4, vec![0; 4]), (String::from("DCSettingIndex"), 4, vec![0; 4])];
            assert_eq!(key.values, expected);
        }
        let mut empty = Vec::new();
        power_policy("ControlSet001", &mut empty);
        assert!(empty.iter().any(|key| key.path.contains(BALANCED)));
    }
}

/// As chaves da hive SOFTWARE: os grupos do svchost, os provedores de
/// autenticação do RPC e a configuração do WUDF.
pub fn software_keys() -> Vec<HostKey> {
    let mut keys = Vec::new();
    #[cfg(windows)]
    {
        use crate::host_language::registry;
        registry::copy(registry::LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost", "Microsoft\\Windows NT\\CurrentVersion\\Svchost", false, &mut keys);
        // A configuração do grupo do registrador do CoreMessaging (o
        // CoInitializeSecurityParam e a política de desempacotamento que o
        // svchost lê ao subir o grupo) e os descritores de segurança dos
        // objetos de nome transitório, que o sechost lê ao criar as portas
        // ALPC do registrador (WM_RegistrarServer e WM_SystemWindowIDManager),
        // da API do compositor e da entrada.
        registry::copy(registry::LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost\\LocalServiceNoNetwork", "Microsoft\\Windows NT\\CurrentVersion\\Svchost\\LocalServiceNoNetwork", true, &mut keys);
        // A mesma configuração do grupo do serviço de política de vídeo
        // (`LocalService`: a segurança do COM e a política de
        // desempacotamento do svchost que registra a fábrica da
        // GlobalBrokerInstance).
        registry::copy(registry::LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost\\LocalService", "Microsoft\\Windows NT\\CurrentVersion\\Svchost\\LocalService", true, &mut keys);
        // Os desempacotadores de confiança do sistema
        // (`Classes\Unmarshalers\System\{clsid}`): com a política de
        // desempacotamento forte dos grupos do svchost (`COM_UnmarshalingPolicy`
        // 1 no `Svchost\LocalService` e em mais 18 grupos), o
        // CheckSystemTrustedUnmarshalerKey do combase só aceita um
        // desempacotador personalizado com a chave dele aqui; sem ela, o
        // ActivationPropertiesIn ({00000338-...}) que o RPCSS manda no
        // GetClassObject é recusado com E_ACCESSDENIED antes de a chamada
        // chegar ao servidor (a ativação da GlobalBrokerInstance do dwm.exe e
        // as dos servidores COM dos outros grupos fortes falham).
        registry::copy(registry::LOCAL_MACHINE, "SOFTWARE\\Classes\\Unmarshalers", "Classes\\Unmarshalers", true, &mut keys);
        registry::copy(registry::LOCAL_MACHINE, "SOFTWARE\\Microsoft\\SecurityManager\\TransientObjects", "Microsoft\\SecurityManager\\TransientObjects", true, &mut keys);
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
    }
    keys
}

/// Os valores de `Control\ProductOptions` que vão para o convidado.
#[cfg(windows)]
const PRODUCT_OPTIONS_VALUES: &[&str] = &["ProductType", "ProductSuite", "ProductPolicy"];

#[cfg(all(test, windows))]
mod software_tests {
    /// O desempacotador do ActivationPropertiesIn ({00000338-...}) na lista
    /// de confiança do sistema que o CheckSystemTrustedUnmarshalerKey do
    /// combase abre nos grupos de política forte.
    #[test]
    fn trusted_unmarshalers_are_staged() {
        let keys = super::software_keys();
        assert!(keys.iter().any(|key| key.path.eq_ignore_ascii_case("Classes\\Unmarshalers\\System\\{00000338-0000-0000-C000-000000000046}")));
    }
}

#[cfg(all(test, windows))]
mod service_tests {
    use crate::host_language::HostKey;

    fn key<'a>(keys: &'a [HostKey], path: &str) -> Option<&'a HostKey> {
        keys.iter().find(|key| key.path.eq_ignore_ascii_case(path))
    }

    /// As partes de um REG_SZ, REG_EXPAND_SZ ou REG_MULTI_SZ.
    fn text(key: &HostKey, name: &str) -> Vec<String> {
        key.values
            .iter()
            .find(|(value, _, _)| value.eq_ignore_ascii_case(name))
            .map(|(_, _, data)| {
                let units: Vec<u16> = data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
                String::from_utf16_lossy(&units).split('\0').filter(|part| !part.is_empty()).map(String::from).collect()
            })
            .unwrap_or_default()
    }

    /// O UserManager como numa instalação nova: o usermgr.dll no svchost do
    /// netsvcs com a conta LocalSystem, as dependências RpcSs e ProfSvc, o
    /// gatilho da interface RPC, sem Security; o usermgr.dll no volume e o
    /// servidor WinRT dele com a classe Windows.System.User.
    #[test]
    fn user_manager_as_fresh_install() {
        let keys = super::system_keys("ControlSet001");
        let service = key(&keys, "ControlSet001\\Services\\UserManager").expect("Services\\UserManager");
        assert_eq!(text(service, "DependOnService"), ["RpcSs", "ProfSvc"]);
        assert_eq!(text(service, "ObjectName"), ["LocalSystem"]);
        assert!(text(service, "ImagePath").first().is_some_and(|path| path.to_ascii_lowercase().ends_with("svchost.exe -k netsvcs -p")));
        assert!(key(&keys, "ControlSet001\\Services\\UserManager\\TriggerInfo\\0").is_some());
        let parameters = key(&keys, "ControlSet001\\Services\\UserManager\\Parameters").expect("Services\\UserManager\\Parameters");
        assert!(text(parameters, "ServiceDll").first().is_some_and(|path| path.to_ascii_lowercase().ends_with("usermgr.dll")));
        assert!(!keys.iter().any(|key| key.path.to_ascii_lowercase().ends_with("\\services\\usermanager\\security")));
        assert!(crate::user_profiles::system_keys("ControlSet001").iter().any(|key| key.path.eq_ignore_ascii_case("ControlSet001\\Services\\ProfSvc")), "o UserManager depende do ProfSvc");
        assert!(crate::windows_binaries::user_programs().any(|program| program.eq_ignore_ascii_case("usermgr.dll")));
        let software = crate::logon_screen::software_keys();
        assert!(key(&software, "Microsoft\\WindowsRuntime\\Server\\UserManager").is_some());
        assert!(key(&software, "Microsoft\\WindowsRuntime\\ActivatableClassId\\Windows.System.User").is_some());
    }
}
