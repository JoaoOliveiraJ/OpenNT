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
//! do CoreMessaging e da política de vídeo (com Parameters e Security), a
//! ordem dos grupos de serviço (`Control\ServiceGroupOrder`), os dois
//! valores de `Control` que
//! o services.exe lê no início automático (o `EarlyStartServices`, a lista
//! do conjunto inicial, e o `SvcHostSplitThresholdInKB`, o limite de
//! memória para separar os serviços de um svchost em processos próprios),
//! o `FullProcessInformationSID` de `Control\Windows`, que o
//! BrokerInfrastructure lê ao subir,
//! a configuração de energia (`Control\Power`, com "Desligar a tela: Nunca"
//! no esquema ativo: `power_policy`), as definições WNF
//! (`Control\Notifications`), as opções do produto (`Control\ProductOptions`)
//! e, na SOFTWARE, os grupos do svchost (`Microsoft\Windows NT\CurrentVersion\
//! Svchost`, os valores com a lista de serviços de cada grupo e as subchaves
//! do `LocalServiceNoNetwork` e do `LocalService`), os descritores das
//! portas de nome transitório
//! (`Microsoft\SecurityManager\TransientObjects`),
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
/// serviço antes do atraso.
const SERVICES: &[&str] = &["DcomLaunch", "RpcEptMapper", "RpcSs", "LSM", "PlugPlay", "Power", "BrokerInfrastructure", "SystemEventsBroker", "CoreMessagingRegistrar", "DispBrokerDesktopSvc"];

/// Os valores de `Control` que o services.exe lê: o EarlyStartServices (o
/// ScStartEarlySetOfServices; sem ele todo serviço automático entra no
/// conjunto inicial) e o SvcHostSplitThresholdInKB (o
/// ScReadSCMConfiguration separa os serviços de um svchost quando a memória
/// física chega ao limite; sem ele não separa).
#[cfg(windows)]
const CONTROL_VALUES: &[&str] = &["EarlyStartServices", "SvcHostSplitThresholdInKB"];

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
        // Só os valores de CONTROL_VALUES da chave Control.
        let first = keys.len();
        registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Control"), &format!("{control_set}\\Control"), false, &mut keys);
        if let Some(control) = keys.get_mut(first) {
            control.values.retain(|(name, _, _)| CONTROL_VALUES.iter().any(|kept| kept.eq_ignore_ascii_case(name)));
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
        // Só o tipo, a suíte e a política; na política, as entradas com a
        // última ativação desta instalação ficam zeradas (o blob mantém o
        // tamanho, e o NtQueryLicenseValue não muda).
        if let Some(options) = keys.get_mut(product_options) {
            options.values.retain(|(name, _, _)| PRODUCT_OPTIONS_VALUES.iter().any(|kept| kept.eq_ignore_ascii_case(name)));
            for (name, _, data) in options.values.iter_mut() {
                if name.eq_ignore_ascii_case("ProductPolicy") {
                    scrub_product_policy(data);
                }
            }
        }
        // A configuração de energia que o serviço Power (o umpo.dll) lê: os
        // esquemas, as configurações e os padrões (o Control\Power com as
        // subchaves que esta conta lê).
        registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Control\\Power"), &format!("{control_set}\\Control\\Power"), true, &mut keys);
        // "Desligar a tela: Nunca" no esquema ativo (`power_policy`).
        power_policy(control_set, &mut keys);
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

#[cfg(test)]
mod tests {
    use super::{power_policy, BALANCED, SUB_VIDEO, VIDEO_TIMEOUTS};
    use crate::host_language::HostKey;

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

/// Os valores de `Control\ProductOptions` que vão para o convidado.
#[cfg(windows)]
const PRODUCT_OPTIONS_VALUES: &[&str] = &["ProductType", "ProductSuite", "ProductPolicy"];

/// As entradas do ProductPolicy que guardam a última ativação desta
/// instalação.
const POLICY_HOST_ENTRIES: &[&str] = &["Security-SPP-LastWindowsActivationTime", "Security-SPP-LastWindowsActivationHResult"];

/// Zera os dados das entradas de [`POLICY_HOST_ENTRIES`] no ProductPolicy:
/// cabeçalho de cinco u32 (total, tamanho dos dados, tamanho do marcador de
/// fim, flags, versão 1) e entradas `u16 tamanho, u16 tamanho do nome, u16
/// tipo, u16 tamanho dos dados, u32 flags, u32 reservado, nome (UTF-16),
/// dados`.
fn scrub_product_policy(blob: &mut [u8]) {
    let word = |bytes: &[u8], at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]) as usize;
    let Some(data) = blob.get(4..8).map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize) else { return };
    let (mut at, end) = (0x14, (0x14 + data).min(blob.len()));
    while at + 16 <= end {
        let (size, name_size, data_size) = (word(blob, at), word(blob, at + 2), word(blob, at + 6));
        if size == 0 || at + 16 + name_size + data_size > end {
            break;
        }
        let name: Vec<u16> = blob[at + 16..at + 16 + name_size].chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
        let name = String::from_utf16_lossy(&name);
        if POLICY_HOST_ENTRIES.iter().any(|host| host.eq_ignore_ascii_case(&name)) {
            blob[at + 16 + name_size..at + 16 + name_size + data_size].fill(0);
        }
        at += size;
    }
}

#[cfg(test)]
mod product_policy_tests {
    use super::scrub_product_policy;

    fn entry(name: &str, data: &[u8]) -> Vec<u8> {
        let name: Vec<u8> = name.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
        let size = 16 + name.len() + data.len();
        let mut bytes = Vec::new();
        for value in [size as u16, name.len() as u16, 4, data.len() as u16] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&[0; 8]);
        bytes.extend_from_slice(&name);
        bytes.extend_from_slice(data);
        bytes
    }

    #[test]
    fn activation_entries_are_zeroed() {
        let entries = [entry("Kernel-ProductInfo", &[0x30, 0, 0, 0]), entry("Security-SPP-LastWindowsActivationTime", &[1, 2, 3, 4, 5, 6, 7, 8]), entry("Security-SPP-LastWindowsActivationHResult", &[9, 9, 9, 9])].concat();
        let mut blob = Vec::new();
        for value in [0x14 + entries.len() as u32 + 4, entries.len() as u32, 4, 0, 1] {
            blob.extend_from_slice(&value.to_le_bytes());
        }
        blob.extend_from_slice(&entries);
        blob.extend_from_slice(&[0x45, 0x23, 0x01, 0x00]);
        let before = blob.len();
        scrub_product_policy(&mut blob);
        assert_eq!(blob.len(), before);
        let text = |bytes: &[u8]| bytes.windows(4).any(|window| window == [0x30, 0, 0, 0]);
        assert!(text(&blob));
        assert!(!blob.windows(8).any(|window| window == [1, 2, 3, 4, 5, 6, 7, 8]));
        assert!(!blob.windows(4).any(|window| window == [9, 9, 9, 9]));
    }
}
