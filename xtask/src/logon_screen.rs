//! As chaves desta instalação que o LogonUI.exe usa para ativar a tela de
//! logon no boot do processo inicial real (`--initial-process=smss`):
//!
//! - o wWinMain do LogonUI.exe cria o controlador com
//!   CoCreateInstance(CLSID_LogonUIController
//!   {0bdc6fc7-83e3-46a4-bfa0-1bc14dbf8b38}, CLSCTX_INPROC_SERVER), que o
//!   combase resolve pelo `Classes\CLSID\{...}\InProcServer32` (o
//!   logoncontroller.dll); sem a chave o LogonUI sai;
//! - o logoncontroller.dll ativa as classes WinRT da experiência de logon
//!   (RoActivateInstance de `Windows.Internal.UI.Logon.Controller.LogonUX`,
//!   do `CredProvDataModel`...) e o Windows.UI.Logon.dll as do XAML
//!   (`Windows.UI.Xaml.*`, o `XAMLHostWindow`), que o combase resolve por
//!   `Microsoft\WindowsRuntime\ActivatableClassId\<classe>` (DllPath,
//!   ActivationType, Threading, TrustLevel); a classe que tem um CLSID
//!   aparece também em `Microsoft\WindowsRuntime\CLSID\{...}`;
//! - o CredProvDataModel.dll cria o anfitrião dos provedores (o
//!   credprovhost.dll, CLSID {7a872d34-bc6b-4f83-b199-22e9c0a91ddc}), que
//!   cria sempre o GenericFilter do credprovs.dll
//!   ({DDC0EED2-ADBE-40b6-A217-EDE16A79A0DE}), enumera os provedores de
//!   `Microsoft\Windows\CurrentVersion\Authentication\Credential Providers`
//!   e cria cada um pelo CLSID; o logoncontroller.dll e o LogonUI leem e
//!   gravam o estado da tela em `Authentication\LogonUI`;
//! - as outras classes COM em processo dessas DLLs são criadas pelo CLSID do
//!   mesmo jeito: a fábrica e os codecs do WIC (o WindowsCodecs.dll, que
//!   decodifica a imagem da tela de bloqueio), o XamlRuntimeSiteAggregator e
//!   os repositórios da imagem da tela de bloqueio e dos blocos de usuário
//!   (o Windows.UI.Immersive.dll), o gerenciador de recursos MRT dos `.pri`,
//!   o propsys.dll, o MSCTF.dll...;
//! - uma chamada entre apartamentos (o STA do XAML e as threads do servidor
//!   RPC do logoncontroller.dll) acha o proxy da interface por
//!   `Classes\Interface\{iid}\ProxyStubClsid32`, a classe PSFactoryBuffer da
//!   DLL de proxies;
//! - a SessionBrokerInstance que o uDWM.dll do dwm.exe ativa na partida
//!   ativa a classe fora de processo DispBrokerDesktop.GlobalBrokerInstance
//!   (ActivationType 1, `Server` DispBrokerDesktopSvc): o RPCSS lê
//!   `WindowsRuntime\Server\DispBrokerDesktopSvc` (o serviço, a identidade e
//!   as permissões de ativação) e inicia o serviço;
//! - no logon do usuário, o explorer.exe e o sihost.exe registram as
//!   fábricas das classes COM fora de processo do shell
//!   (CoRegisterClassObject: a barra de tarefas, o papel de parede, o
//!   anfitrião do shell imersivo...), que o RPCSS confere pelo
//!   `Classes\CLSID\{...}` e pelo `Classes\AppID\{...}` da classe (o `RunAs`
//!   "Interactive User" e as permissões), e as classes WinRT do
//!   StateRepository, do UserManager e do WindowManagement que o shell32, o
//!   explorer e o shell imersivo ativam são fora de processo, como a do
//!   DispBrokerDesktopSvc;
//! - a Calendar do relógio da tela de bloqueio lê as regras do fuso em
//!   `Windows NT\CurrentVersion\Time Zones`;
//! - a caixa de senha do XAML ativa o TSF em processo (o MSCTF.dll), que
//!   lê os serviços de texto registrados em `Microsoft\CTF`.
//!
//! As classes COM e WinRT copiadas são as de DLLs de System32 que o volume
//! leva (`windows_binaries::user_programs`), as dos servidores WinRT de
//! `WINRT_SERVERS` e as classes fora de processo do shell de
//! `SHELL_LOCAL_CLASSES` com o AppID delas, e as interfaces, as que têm o
//! proxy numa dessas classes: o convidado é uma instalação com esses
//! componentes. Das chaves dos servidores WinRT, das classes do shell e dos
//! AppIDs sai todo valor com o SID de uma conta (`S-1-5-21-...`) no nome ou
//! nos dados, como num descritor de segurança: a conta é desta máquina, e
//! o convidado não a tem. Do `Authentication\LogonUI` e dos provedores
//! ficam de fora o último logon (o usuário, o provedor e o tempo ocioso
//! dele), o usuário selecionado, os dados de sessão, o estado deste boot e
//! as subchaves e os
//! valores com o SID de um usuário desta máquina: uma instalação nova não
//! os tem, e o convidado não tem as contas daqui (o
//! `SystemProtectedUserData`, também por usuário, não é copiado). Como os
//! binários, as chaves vêm desta máquina no build, com os valores daqui.
//! Fora do Windows nada é copiado.

use crate::host_language::HostKey;

/// Os valores de `Authentication\LogonUI` que descrevem o último logon ou o
/// usuário selecionado desta máquina.
#[cfg(windows)]
const LOGON_UI_LOCAL_VALUES: &[&str] = &["LastLoggedOnUser", "LastLoggedOnSAMUser", "LastLoggedOnDisplayName", "LastLoggedOnUserSID", "LastLoggedOnProvider", "SelectedUserSID", "IdleTime"];

/// As subchaves de `Authentication\LogonUI` com o estado das sessões, o
/// conteúdo por usuário desta máquina e o estado deste boot (a chave volátil
/// `LogonSoundPlayed`, que o LogonUI cria a cada partida).
#[cfg(windows)]
const LOGON_UI_LOCAL_KEYS: &[&str] = &["SessionData", "Creative", "LogonSoundPlayed"];

/// Os servidores WinRT fora de processo (`WindowsRuntime\Server\<nome>`)
/// cujas classes o caminho da tela de logon e o do logon do usuário ativam:
/// o DispBrokerDesktopSvc (um serviço de `user_services`) da
/// DispBrokerDesktop.GlobalBrokerInstance que a SessionBrokerInstance do
/// dwm.exe cria; o StateRepository (as classes
/// Windows.Internal.StateRepository.* que o shell32, o explorer e o
/// AppResolver pedem) e o UserManager (Windows.System.User,
/// Windows.System.UserPicker...), serviços com a identidade SYSTEM; e o
/// WindowManagement, o sihost.exe (`ExePath`) com as classes de janela do
/// shell imersivo. O RPCSS acha o servidor pelo `Server` da classe e inicia
/// o serviço do `ServiceName` ou o programa do `ExePath`; enquanto o
/// serviço ou o programa não está no convidado (a etapa do sihost), a
/// ativação falha ao iniciar o servidor, e não na busca da classe.
#[cfg(windows)]
const WINRT_SERVERS: &[&str] = &["DispBrokerDesktopSvc", "StateRepository", "UserManager", "WindowManagement"];

/// As classes COM fora de processo dos processos do shell, sem
/// `InprocServer32`: o processo que as hospeda registra a fábrica
/// (CoRegisterClassObject) e o RPCSS confere a identidade dele pelo AppID da
/// classe (`RunAs` "Interactive User", o token do usuário da sessão). Do
/// explorer.exe: o ImmersiveShellBroker, o AgileImmersiveShellBroker e o
/// NowPlayingSessionManager (os três no mesmo AppID), o CLSID_TrayNotify,
/// o CLSID_TrayAppIdentityResolver, o CLSID_ImmersiveSplashScreen, o
/// Desktop Wallpaper (IDesktopWallpaper), o CLSID_TrayToastActivator, o
/// CLSID_TrayDesktopBand, o Shell Create Object Handler (`RunAs` SYSTEM) e
/// as fábricas do explorer (`LocalServer32`
/// `%SystemRoot%\explorer.exe /factory,{...}`): o CLSID_DesktopExplorerHost,
/// o CLSID_ControlPanelProcessExplorerHost e o
/// CLSID_SeparateMultipleProcessExplorerHost. Do sihost.exe (a etapa do
/// UserManager): o ShellServiceHost, que o twinui e o
/// TerminateShellApplications do explorer pedem, o
/// ShellServiceHostBrokerProvider, o CLSID_CoreShellServiceProvider e o
/// UiaManager.
#[cfg(windows)]
const SHELL_LOCAL_CLASSES: &[&str] = &[
    // explorer.exe
    "{228826af-02e1-4226-a9e0-99a855e455a6}",
    "{59614133-bfb4-4906-90af-c44f15167f1a}",
    "{BCBB9860-C012-4AD7-A938-6E337AE6ABA5}",
    "{25dead04-1eac-4911-9e3a-ad0a4ab560fd}",
    "{561DF0D0-72EB-46F1-8D0A-5597DBBE6578}",
    "{329B80EC-2230-47B8-905D-A2DCF5171C6F}",
    "{C2CF3110-460E-4fc1-B9D0-8A1C0C9CC4BD}",
    "{7C021C10-E914-4A53-BDC8-315CEBF32B49}",
    "{E6442437-6C68-4f52-94DD-2CFED267EFB9}",
    "{135fd325-45b7-4c30-89f8-4386961669f0}",
    "{682159d9-c321-47ca-b3f1-30e36b2ec8b9}",
    "{5BD95610-9434-43C2-886C-57852CC8A120}",
    "{75dff2b7-6936-4c06-a8bb-676a7b00b24b}",
    // sihost.exe
    "{6B3B8D23-FA8D-40B9-8DBD-B950333E2C52}",
    "{3480A401-BDE9-4407-BC02-798A866AC051}",
    "{39DD352B-7231-4897-BFE0-E7374A1C012E}",
    "{4B7A83D5-CF71-40AD-AB0F-BF6830E95330}",
];

/// Os proxies do oleaut32.dll que empacotam pela biblioteca de tipos
/// registrada da interface (PSOAInterface e PSDispatch), em minúsculas.
#[cfg(windows)]
const TYPE_LIBRARY_MARSHALERS: &[&str] = &["{00020424-0000-0000-c000-000000000046}", "{00020420-0000-0000-c000-000000000046}"];

/// O texto de um valor REG_SZ ou REG_EXPAND_SZ.
#[cfg(windows)]
fn text(values: &[(String, u32, Vec<u8>)], name: &str) -> Option<String> {
    let (_, _, data) = values.iter().find(|(value, kind, _)| value.eq_ignore_ascii_case(name) && matches!(kind, 1 | 2))?;
    let units: Vec<u16> = data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
    Some(String::from_utf16_lossy(&units))
}

/// O nome do arquivo de uma DLL de System32 (`%SystemRoot%\system32\x`,
/// `%windir%\system32\x`, `C:\Windows\System32\x` ou só o nome, que o
/// carregador procura em System32).
#[cfg(windows)]
fn system32_file(path: &str) -> Option<&str> {
    let path = path.trim_matches('"');
    if !path.contains('\\') {
        return Some(path).filter(|name| !name.is_empty());
    }
    ["%systemroot%\\system32\\", "%windir%\\system32\\", "c:\\windows\\system32\\"]
        .iter()
        .find_map(|prefix| path.get(..prefix.len()).filter(|head| head.eq_ignore_ascii_case(prefix)).and_then(|_| path.get(prefix.len()..)))
        .filter(|name| !name.contains('\\'))
}

/// Um caminho com o SID de uma conta local ou de domínio (`S-1-5-21-...`).
#[cfg(windows)]
fn user_sid(name: &str) -> bool {
    name.get(..9).is_some_and(|head| head.eq_ignore_ascii_case("S-1-5-21-"))
}

/// Tira as chaves com o SID de um usuário no caminho e os valores com o SID
/// de um usuário no nome.
#[cfg(windows)]
fn without_users(keys: &mut Vec<HostKey>) {
    keys.retain(|key| !key.path.split('\\').any(user_sid));
    for key in keys.iter_mut() {
        key.values.retain(|(name, _, _)| !user_sid(name));
    }
}

/// Os dados de um valor com o SID de uma conta local ou de domínio: em
/// binário, como num descritor de segurança (revisão 1, de 1 a 15
/// subautoridades, autoridade 5 e a primeira subautoridade 21), ou em texto
/// (`S-1-5-21-` num REG_SZ, REG_EXPAND_SZ ou REG_MULTI_SZ).
#[cfg_attr(not(windows), allow(dead_code))]
fn holds_account_sid(kind: u32, data: &[u8]) -> bool {
    if data.windows(12).any(|window| window[0] == 1 && (1..=15).contains(&window[1]) && window[2..8] == [0, 0, 0, 0, 0, 5] && window[8..12] == [21, 0, 0, 0]) {
        return true;
    }
    if !matches!(kind, 1 | 2 | 7) {
        return false;
    }
    let units: Vec<u16> = data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    String::from_utf16_lossy(&units).to_ascii_lowercase().contains("s-1-5-21-")
}

/// Tira os valores com o SID de uma conta nos dados ([`holds_account_sid`]),
/// com um aviso que dá a chave e o nome do valor, nunca o dado: as
/// permissões de um AppID ou de um servidor WinRT podem ter como dono ou
/// numa ACE uma conta desta máquina, e sem o valor o RPCSS usa as permissões
/// padrão da máquina.
#[cfg_attr(not(windows), allow(dead_code))]
fn without_account_sids(keys: &mut [HostKey]) {
    for HostKey { path, values } in keys.iter_mut() {
        values.retain(|(name, kind, data)| {
            let account = holds_account_sid(*kind, data);
            if account {
                println!("AVISO: {path}\\{name} tem o SID de uma conta (S-1-5-21-...) e fica fora do convidado");
            }
            !account
        });
    }
}

/// As chaves da hive SOFTWARE.
pub fn software_keys() -> Vec<HostKey> {
    let mut keys = Vec::new();
    #[cfg(windows)]
    {
        use crate::host_language::registry;
        let programs: Vec<&str> = crate::windows_binaries::user_programs().collect();
        let staged = |dll: Option<String>| dll.as_deref().and_then(system32_file).is_some_and(|file| programs.iter().any(|program| program.eq_ignore_ascii_case(file)));
        // As classes COM em processo das DLLs do volume.
        let objects = "Classes\\CLSID";
        let mut servers = std::collections::BTreeSet::new();
        for class in registry::list(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{objects}")) {
            let mut server = Vec::new();
            registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{objects}\\{class}\\InprocServer32"), "", false, &mut server);
            if staged(server.first().and_then(|key| text(&key.values, ""))) {
                registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{objects}\\{class}"), &format!("{objects}\\{class}"), true, &mut keys);
                servers.insert(class.to_ascii_lowercase());
            }
        }
        // Os objetos de serviço do shell de início automático: o
        // CShellServiceObjectMgr::LoadObjects do stobject.dll (0x2740) abre
        // `Explorer\ShellServiceObjects` da HKLM e cria cada CLSID com o
        // valor AutoStart, como o ícone de volume do SndVolSSO.dll; sem a
        // chave a área de notificação fica sem ícones de sistema. Só os das
        // classes copiadas acima (a DLL no volume); os valores são o
        // AutoStart vazio e, em alguns, o nome padrão.
        let service_objects = "Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellServiceObjects";
        for class in registry::list(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{service_objects}")) {
            if servers.contains(&class.to_ascii_lowercase()) {
                registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{service_objects}\\{class}"), &format!("{service_objects}\\{class}"), false, &mut keys);
            }
        }
        // As interfaces cujo proxy (`ProxyStubClsid32`) é uma dessas classes,
        // menos as que o oleaut32.dll empacota pela biblioteca de tipos
        // (PSOAInterface e PSDispatch), que pedem o `Classes\TypeLib` delas.
        let interfaces = "Classes\\Interface";
        for interface in registry::list(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{interfaces}")) {
            let mut proxy = Vec::new();
            registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{interfaces}\\{interface}\\ProxyStubClsid32"), "", false, &mut proxy);
            let class = proxy.first().and_then(|key| text(&key.values, "")).map(|class| class.trim().to_ascii_lowercase());
            if class.is_some_and(|class| servers.contains(&class) && !TYPE_LIBRARY_MARSHALERS.contains(&class.as_str())) {
                registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{interfaces}\\{interface}"), &format!("{interfaces}\\{interface}"), true, &mut keys);
            }
        }
        // As classes WinRT das DLLs do volume e as dos servidores fora de
        // processo de WINRT_SERVERS, com as chaves desses servidores.
        let classes = "Microsoft\\WindowsRuntime\\ActivatableClassId";
        let served = |server: Option<String>| server.is_some_and(|server| WINRT_SERVERS.iter().any(|known| known.eq_ignore_ascii_case(&server)));
        let mut identifiers = Vec::new();
        for class in registry::list(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{classes}")) {
            let mut found = Vec::new();
            registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{classes}\\{class}"), &format!("{classes}\\{class}"), true, &mut found);
            let Some(values) = found.first().map(|key| &key.values) else { continue };
            if !staged(text(values, "DllPath")) && !served(text(values, "Server")) {
                continue;
            }
            identifiers.extend(text(values, "CLSID"));
            keys.extend(found);
        }
        for identifier in identifiers {
            let path = format!("Microsoft\\WindowsRuntime\\CLSID\\{identifier}");
            registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{path}"), &path, true, &mut keys);
        }
        // Os servidores e as classes fora de processo do shell, com o AppID
        // de cada classe, sem os valores com o SID de uma conta (as
        // `Permissions` dos servidores, as permissões e o dono dos AppIDs).
        let mut hosted = Vec::new();
        for server in WINRT_SERVERS {
            let path = format!("Microsoft\\WindowsRuntime\\Server\\{server}");
            registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{path}"), &path, true, &mut hosted);
        }
        let mut applications = std::collections::BTreeSet::new();
        for class in SHELL_LOCAL_CLASSES {
            let first = hosted.len();
            registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{objects}\\{class}"), &format!("{objects}\\{class}"), true, &mut hosted);
            let Some(application) = hosted.get(first).and_then(|key| text(&key.values, "AppID")) else { continue };
            let application = application.trim().to_string();
            if applications.insert(application.to_ascii_lowercase()) {
                let path = format!("Classes\\AppID\\{application}");
                registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{path}"), &path, true, &mut hosted);
            }
        }
        without_users(&mut hosted);
        without_account_sids(&mut hosted);
        keys.extend(hosted);
        // Os fusos horários da instalação: o TimeZoneCache e a
        // LegacyWindowsTimeZone do Windows.Globalization.dll (a Calendar do
        // relógio da tela de bloqueio) leem as regras do fuso pelo
        // GetTimeZoneInformationForYear e pelo
        // GetDynamicTimeZoneInformationEffectiveYears, que abrem
        // `Time Zones\<TimeZoneKeyName>` (o TZI e o `Dynamic DST`).
        let zones = "Microsoft\\Windows NT\\CurrentVersion\\Time Zones";
        registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{zones}"), zones, true, &mut keys);
        // Os serviços de texto registrados na instalação (`Microsoft\CTF`:
        // os processadores de entrada de `TIP` com as categorias e os perfis
        // de cada idioma, `SystemShared` e `Modern`), que o MSCTF.dll lê
        // quando o CImeEventHelper do Windows.UI.Xaml.dll ativa o
        // gerenciador de threads do TSF na caixa de senha, e o
        // Windows.UI.Core.TextInput.dll ao listar os perfis de teclado.
        let text_services = "Microsoft\\CTF";
        registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{text_services}"), text_services, true, &mut keys);
        // Os provedores de credencial, os filtros e o estado da tela de
        // logon, sem o que é desta máquina.
        let authentication = "Microsoft\\Windows\\CurrentVersion\\Authentication";
        let mut found = Vec::new();
        for path in ["Credential Providers", "Credential Provider Filters"] {
            registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{authentication}\\{path}"), &format!("{authentication}\\{path}"), true, &mut found);
        }
        let logon_ui = format!("{authentication}\\LogonUI");
        let first = found.len();
        registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{logon_ui}"), &logon_ui, false, &mut found);
        if let Some(state) = found.get_mut(first) {
            state.values.retain(|(name, _, _)| !LOGON_UI_LOCAL_VALUES.iter().any(|local| local.eq_ignore_ascii_case(name)));
        }
        for child in registry::list(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{logon_ui}")).into_iter().filter(|child| !LOGON_UI_LOCAL_KEYS.iter().any(|local| local.eq_ignore_ascii_case(child))) {
            registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{logon_ui}\\{child}"), &format!("{logon_ui}\\{child}"), true, &mut found);
        }
        without_users(&mut found);
        // O `UserSwitch\UserSID` e outros valores que guardam o SID de um
        // usuário nos dados.
        without_account_sids(&mut found);
        keys.extend(found);
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::{holds_account_sid, without_account_sids};
    use crate::host_language::HostKey;

    /// Um SID em binário: revisão 1, o número de subautoridades, a
    /// autoridade 5 (big-endian) e as subautoridades em little-endian.
    fn sid(subauthorities: &[u32]) -> Vec<u8> {
        let mut bytes = vec![1, subauthorities.len() as u8, 0, 0, 0, 0, 0, 5];
        for value in subauthorities {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
    }

    /// O guarda tira o valor com o SID de uma conta, em binário dentro de um
    /// descritor ou em texto, e deixa os SIDs bem conhecidos (SYSTEM,
    /// Administradores, Usuários) e os de serviço (S-1-5-80-...).
    #[test]
    fn account_sids_are_dropped() {
        let header: Vec<u8> = vec![1, 0, 0x04, 0x80, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let account = [header.clone(), sid(&[21, 1000, 2000, 3000, 500])].concat();
        let builtin = [header, sid(&[18]), sid(&[32, 544]), sid(&[80, 1, 2, 3, 4, 5])].concat();
        let mut keys = vec![HostKey {
            path: String::from("Classes\\AppID\\{00000000-0000-0000-0000-000000000000}"),
            values: vec![
                (String::from("LaunchPermission"), 3, account),
                (String::from("AccessPermission"), 3, builtin),
                (String::from("Owner"), 1, utf16("S-1-5-21-1000-2000-3000-1001")),
                (String::from("RunAs"), 1, utf16("Interactive User")),
                (String::from("AppIDFlags"), 4, 21u32.to_le_bytes().to_vec()),
            ],
        }];
        without_account_sids(&mut keys);
        let kept: Vec<&str> = keys[0].values.iter().map(|(name, _, _)| name.as_str()).collect();
        assert_eq!(kept, ["AccessPermission", "RunAs", "AppIDFlags"]);
        assert!(!holds_account_sid(3, &sid(&[32, 545])));
        assert!(holds_account_sid(7, &utf16("x\0s-1-5-21-1000-2000-3000-1001")));
    }

    /// Nenhuma chave que a tela de logon e o logon do usuário levam desta
    /// máquina tem o SID de uma conta: nem no caminho, nem no nome de um
    /// valor, nem nos dados. As definições WNF de `Control\Notifications`
    /// ficam de fora: os descritores delas têm os SIDs fixos do domínio de
    /// build da Microsoft, os mesmos em toda instalação do 19041.
    #[cfg(windows)]
    #[test]
    fn user_logon_keys_carry_no_account_sid() {
        let notifications = "ControlSet001\\Control\\Notifications";
        let keys = super::software_keys()
            .into_iter()
            .chain(crate::user_services::software_keys())
            .chain(crate::user_services::system_keys("ControlSet001").into_iter().filter(|key| !key.path.eq_ignore_ascii_case(notifications)));
        let mut found = Vec::new();
        for key in keys {
            if key.path.split('\\').any(super::user_sid) {
                found.push(key.path);
                continue;
            }
            for (name, kind, data) in &key.values {
                if super::user_sid(name) || holds_account_sid(*kind, data) {
                    found.push(format!("{}\\{name}", key.path));
                }
            }
        }
        assert!(found.is_empty(), "chaves com o SID de uma conta: {found:?}");
    }
}
