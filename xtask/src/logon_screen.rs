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
/// o serviço do `ServiceName` (os de `user_services`) ou o programa do
/// `ExePath` (o sihost.exe de `windows_binaries`).
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
/// CLSID_SeparateMultipleProcessExplorerHost. Do sihost.exe, que o
/// UserManager cria: o ShellServiceHost, que o twinui e o
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
        // As associações do shell da instalação, só com o que é do Windows
        // do volume.
        let mut associations = Vec::new();
        for class in SHELL_ASSOCIATIONS {
            registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\Classes\\{class}"), &format!("Classes\\{class}"), true, &mut associations);
        }
        let mut volume_programs: Vec<&str> = programs.clone();
        volume_programs.extend(crate::windows_binaries::windows_programs());
        let (mut kept, dropped) = volume_associations(associations, &servers, &volume_programs);
        for line in dropped {
            println!("AVISO: associacao do shell fora do convidado: {line}");
        }
        for line in clean_install_defaults(&mut kept) {
            println!("AVISO: associacao do shell com o valor de uma instalacao nova: {line}");
        }
        keys.extend(kept);
        // As zonas de segurança da instalação (`Internet Settings\Zones`, de
        // 0, Meu Computador, a 4, Sites Restritos) e os protocolos padrão do
        // mapa de zonas: o ZoneCheckFile do windows.storage (o
        // CheckSmartScreen do ShellExecute de um programa) pergunta ao
        // ZoneCheckUrlExW do urlmon a política da ação na zona do arquivo, e
        // sem as zonas o urlmon responde E_FAIL com URLPOLICY_DISALLOW: o
        // ShellExecute da caixa Executar volta ERROR_CANCELLED e o programa
        // não abre. O resto de `Internet Settings` (proxy, cache, sites do
        // mapa de zonas, agente de usuário) é desta máquina e fica fora.
        let internet = "Microsoft\\Windows\\CurrentVersion\\Internet Settings";
        for path in ["Zones", "ZoneMap\\ProtocolDefaults"] {
            registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{internet}\\{path}"), &format!("{internet}\\{path}"), true, &mut keys);
        }
    }
    keys
}

/// Os valores das associações que uma instalação nova do 19041 grava e que
/// o convidado leva assim, seja qual for o valor desta máquina: a chave, o
/// nome do valor, o tipo (1 REG_SZ, 2 REG_EXPAND_SZ) e o texto.
#[cfg_attr(not(windows), allow(dead_code))]
const CLEAN_INSTALL_ASSOCIATIONS: &[(&str, &str, u32, &str)] = &[
    ("Classes\\Folder\\shell\\open\\command", "", 2, "%SystemRoot%\\Explorer.exe"),
    ("Classes\\Folder\\shell\\open\\command", "DelegateExecute", 1, "{11dbb47c-a525-400b-9e80-a54615a090c0}"),
    ("Classes\\exefile\\shell\\open\\command", "", 1, "\"%1\" %*"),
    ("Classes\\comfile\\shell\\open\\command", "", 1, "\"%1\" %*"),
    ("Classes\\batfile\\shell\\open\\command", "", 1, "\"%1\" %*"),
    ("Classes\\cmdfile\\shell\\open\\command", "", 1, "\"%1\" %*"),
    ("Classes\\txtfile\\shell\\open\\command", "", 2, "%SystemRoot%\\system32\\NOTEPAD.EXE %1"),
    ("Classes\\.exe", "", 1, "exefile"),
    ("Classes\\.com", "", 1, "comfile"),
    ("Classes\\.bat", "", 1, "batfile"),
    ("Classes\\.cmd", "", 1, "cmdfile"),
    ("Classes\\.txt", "", 1, "txtfile"),
    ("Classes\\.lnk", "", 1, "lnkfile"),
    ("Classes\\lnkfile", "IsShortcut", 1, ""),
];

/// O texto de `text` como dados de um valor de cadeia (UTF-16 com o NUL).
#[cfg_attr(not(windows), allow(dead_code))]
fn utf16_value(text: &str) -> Vec<u8> {
    text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
}

/// Põe nas associações (`keys`) os valores de [`CLEAN_INSTALL_ASSOCIATIONS`]
/// no lugar dos desta máquina, criando a chave ou o valor que faltar.
/// Devolve as trocas, para o aviso.
#[cfg_attr(not(windows), allow(dead_code))]
fn clean_install_defaults(keys: &mut Vec<HostKey>) -> Vec<String> {
    let mut changes = Vec::new();
    for &(path, name, kind, value) in CLEAN_INSTALL_ASSOCIATIONS {
        let data = utf16_value(value);
        let index = match keys.iter().position(|key| key.path.eq_ignore_ascii_case(path)) {
            Some(index) => index,
            None => {
                keys.push(HostKey { path: String::from(path), values: Vec::new() });
                keys.len() - 1
            }
        };
        let values = &mut keys[index].values;
        match values.iter_mut().find(|(existing, _, _)| existing.eq_ignore_ascii_case(name)) {
            Some(existing) if existing.1 == kind && existing.2 == data => {}
            Some(existing) => {
                changes.push(format!("{path}\\{name} = {value:?} (o desta maquina era outro)"));
                *existing = (String::from(name), kind, data);
            }
            None => {
                changes.push(format!("{path}\\{name} = {value:?} (ausente nesta maquina)"));
                values.push((String::from(name), kind, data));
            }
        }
    }
    changes
}

/// Um valor de cadeia que cita um caminho fora do Windows do convidado: os
/// programas instalados nesta máquina (`Program Files`, `ProgramData`), os
/// perfis (`Users`, `%USERPROFILE%`, `%APPDATA%`, `%LOCALAPPDATA%`) ou outra
/// unidade.
#[cfg_attr(not(windows), allow(dead_code))]
fn outside_windows(kind: u32, data: &[u8]) -> bool {
    if !matches!(kind, 1 | 2 | 7) {
        return false;
    }
    let units: Vec<u16> = data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    let text = String::from_utf16_lossy(&units).to_ascii_lowercase();
    let markers = ["program files", "programdata", "\\users\\", "%userprofile%", "%appdata%", "%localappdata%", "%programfiles", "%programdata%"];
    if markers.iter().any(|marker| text.contains(marker)) {
        return true;
    }
    // Um caminho absoluto de unidade que não é o C:\Windows.
    text.char_indices().any(|(at, character)| character.is_ascii_alphabetic() && text[at + 1..].starts_with(":\\") && !text[at..].starts_with("c:\\windows"))
}

/// As classes de associação do shell que uma instalação nova traz em
/// `Classes` e que o shell do convidado usa: as pastas (o `Folder`, de onde
/// vem o verbo `open` de Este Computador e de toda pasta, com o
/// DelegateExecute {11dbb47c-...} do ExplorerFrame.dll; o `Directory`, o
/// `Drive` e o fundo de uma pasta), os programas (`.exe`, `.com`, `.bat`,
/// `.cmd` e as classes deles: o ShellExecute da caixa Executar acha o
/// `notepad` como `notepad.exe` e abre pelo `exefile\shell\open\command`), o
/// texto (`.txt` e `txtfile`) e os atalhos (`.lnk` e `lnkfile`). Sem elas o
/// clique duplo em Este Computador volta ERROR_NO_ASSOCIATION
/// (0x80070483) do SHInvokeCommandOnContextMenu2 do s_DoInvokeVerb do
/// shell32, e nada abre.
#[cfg(windows)]
const SHELL_ASSOCIATIONS: &[&str] = &["Folder", "Directory", "Drive", ".exe", "exefile", ".com", "comfile", ".bat", "batfile", ".cmd", "cmdfile", ".txt", "txtfile", ".lnk", "lnkfile"];

/// O nome do programa (em minúsculas) do começo de uma linha de comando de
/// verbo, entre aspas ou até o primeiro espaço, com o `%SystemRoot%`, o
/// `%windir%` e o `C:\Windows` (e o `System32` deles) tirados; `None` para o
/// próprio arquivo (`"%1"`, o `exefile` e o `comfile`).
#[cfg_attr(not(windows), allow(dead_code))]
fn command_program(command: &str) -> Option<String> {
    let command = command.trim();
    let first = match command.strip_prefix('"') {
        Some(rest) => rest.split('"').next().unwrap_or(rest),
        None => command.split(' ').next().unwrap_or(command),
    };
    if first == "%1" || first.is_empty() {
        return None;
    }
    let lower = first.to_ascii_lowercase();
    let name = ["%systemroot%\\system32\\", "%windir%\\system32\\", "c:\\windows\\system32\\", "%systemroot%\\", "%windir%\\", "c:\\windows\\"]
        .iter()
        .find_map(|prefix| lower.strip_prefix(prefix))
        .unwrap_or(&lower);
    Some(name.to_string())
}

/// As chaves das associações (`keys`, com os caminhos `Classes\<classe>...`)
/// que são do Windows do volume: só as classes de [`SHELL_ASSOCIATIONS`]; um
/// verbo de `shell` fica quando o DelegateExecute ou o
/// ExplorerCommandHandler dele é uma das classes COM copiadas (`servers`, em
/// minúsculas e com chaves) ou quando o comando abre o próprio arquivo
/// (`"%1"`) ou um programa do volume (`programs`); um manipulador de
/// `shellex` fica quando a classe dele (o valor padrão ou o nome) é uma das
/// copiadas; um valor que cita um caminho fora do Windows do convidado
/// ([`outside_windows`]) sai. O resto (os verbos e os manipuladores dos
/// programas de terceiros desta máquina, as listas de `OpenWithProgids` e de
/// `OpenWithList`, que citam os programas daqui) fica fora do convidado.
/// Devolve as chaves que ficam e uma linha para cada coisa que saiu.
#[cfg_attr(not(windows), allow(dead_code))]
fn volume_associations(keys: Vec<HostKey>, servers: &std::collections::BTreeSet<String>, programs: &[&str]) -> (Vec<HostKey>, Vec<String>) {
    let listed = |path: &str| path.split('\\').nth(1).is_some_and(|class| SHELL_ASSOCIATIONS.iter().any(|known| known.eq_ignore_ascii_case(class)));
    let mut log: Vec<String> = keys.iter().filter(|key| !listed(&key.path)).map(|key| format!("{} (classe fora da lista)", key.path)).collect();
    let keys: Vec<HostKey> = keys.into_iter().filter(|key| listed(&key.path)).collect();
    let class_of = |value: Option<String>| value.map(|value| format!("{{{}}}", value.trim().trim_matches(|c| c == '{' || c == '}').to_ascii_lowercase())).filter(|class| servers.contains(class));
    let staged = |program: &str| programs.iter().any(|known| known.eq_ignore_ascii_case(program));
    // Os prefixos que saem: os verbos e os manipuladores de fora.
    let mut dropped: Vec<String> = Vec::new();
    for key in &keys {
        let parts: Vec<&str> = key.path.split('\\').collect();
        let lower: Vec<String> = parts.iter().map(|part| part.to_ascii_lowercase()).collect();
        let Some(at) = lower.iter().position(|part| part == "shell" || part == "shellex" || part == "openwithprogids" || part == "openwithlist") else { continue };
        let prefix = |count: usize| parts[..count].join("\\");
        match lower[at].as_str() {
            "openwithprogids" | "openwithlist" => dropped.push(prefix(at + 1)),
            "shell" if parts.len() == at + 2 => {
                let verb = prefix(at + 2);
                let command = keys.iter().find(|other| other.path.eq_ignore_ascii_case(&format!("{verb}\\command")));
                let handler = class_of(text(&key.values, "ExplorerCommandHandler")).is_some() || command.is_some_and(|command| class_of(text(&command.values, "DelegateExecute")).is_some());
                let launches = command.and_then(|command| text(&command.values, "")).is_some_and(|line| command_program(&line).is_none_or(|program| staged(&program)));
                if !handler && !launches {
                    dropped.push(verb);
                }
            }
            // `shellex\{IID}` com a classe no valor padrão.
            "shellex" if parts.len() == at + 2 && parts[at + 1].starts_with('{') => {
                if class_of(text(&key.values, "")).is_none() {
                    dropped.push(prefix(at + 2));
                }
            }
            // `shellex\<tipo>\<nome>`: a classe no valor padrão ou no nome.
            "shellex" if parts.len() == at + 3 => {
                if class_of(text(&key.values, "")).or_else(|| class_of(Some(parts[at + 2].to_string()))).is_none() {
                    dropped.push(prefix(at + 3));
                }
            }
            _ => {}
        }
    }
    let inside = |path: &str, prefix: &str| path.len() >= prefix.len() && path[..prefix.len()].eq_ignore_ascii_case(prefix) && (path.len() == prefix.len() || path.as_bytes()[prefix.len()] == b'\\');
    dropped.sort();
    dropped.dedup();
    log.extend(dropped.iter().map(|prefix| format!("{prefix} (verbo ou manipulador de fora do volume)")));
    let mut kept: Vec<HostKey> = keys.into_iter().filter(|key| !dropped.iter().any(|prefix| inside(&key.path, prefix))).collect();
    for key in &mut kept {
        let path = key.path.clone();
        key.values.retain(|(name, kind, data)| {
            let outside = outside_windows(*kind, data);
            if outside {
                log.push(format!("{path}\\{name} (caminho fora do Windows do convidado)"));
            }
            !outside
        });
    }
    (kept, log)
}

#[cfg(test)]
mod tests {
    use super::{clean_install_defaults, command_program, holds_account_sid, utf16_value, volume_associations, without_account_sids};
    use crate::host_language::HostKey;

    /// O programa do começo de uma linha de comando de verbo.
    #[test]
    fn command_program_reads_the_first_word() {
        assert_eq!(command_program("\"%1\" %*"), None);
        assert_eq!(command_program("%SystemRoot%\\Explorer.exe").as_deref(), Some("explorer.exe"));
        assert_eq!(command_program("%SystemRoot%\\system32\\NOTEPAD.EXE %1").as_deref(), Some("notepad.exe"));
        assert_eq!(command_program("\"C:\\Program Files\\Editor\\editor.exe\" \"%1\"").as_deref(), Some("c:\\program files\\editor\\editor.exe"));
    }

    /// Das associações ficam os verbos e os manipuladores do Windows do
    /// volume; os de programas de fora e as listas de OpenWith saem.
    #[test]
    fn volume_associations_keep_only_the_windows_of_the_volume() {
        let sz = |name: &str, text: &str| (String::from(name), 1u32, text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect::<Vec<u8>>());
        let key = |path: &str, values: Vec<(String, u32, Vec<u8>)>| HostKey { path: String::from(path), values };
        let keys = vec![
            key("Classes\\Folder", vec![sz("", "Folder")]),
            key("Classes\\Folder\\shell", vec![]),
            key("Classes\\Folder\\shell\\open", vec![sz("MultiSelectModel", "Document")]),
            key("Classes\\Folder\\shell\\open\\command", vec![sz("", "%SystemRoot%\\Explorer.exe"), sz("DelegateExecute", "{11dbb47c-a525-400b-9e80-a54615a090c0}")]),
            key("Classes\\Folder\\shell\\editor", vec![]),
            key("Classes\\Folder\\shell\\editor\\command", vec![sz("", "\"C:\\Program Files\\Editor\\editor.exe\" \"%V\"")]),
            key("Classes\\Folder\\shellex\\ContextMenuHandlers", vec![]),
            key("Classes\\Folder\\shellex\\ContextMenuHandlers\\Library Location", vec![sz("", "{3dad6c5d-2167-4cae-9914-f99e41c12cfa}")]),
            key("Classes\\Folder\\shellex\\ContextMenuHandlers\\Archiver", vec![sz("", "{B41DB860-64E4-11D2-9906-E49FADC173CA}")]),
            key("Classes\\exefile\\shell\\open\\command", vec![sz("", "\"%1\" %*")]),
            key("Classes\\txtfile\\shell\\open\\command", vec![sz("", "%SystemRoot%\\system32\\NOTEPAD.EXE %1")]),
            key("Classes\\.txt\\OpenWithProgids", vec![sz("txtfile", "")]),
            key("Classes\\.txt\\shellex\\{8895b1c6-b41f-4c1c-a562-0d564250836f}", vec![sz("", "{00000000-1111-2222-3333-444444444444}")]),
            key("Classes\\Directory\\DefaultIcon", vec![sz("", "%SystemRoot%\\System32\\imageres.dll,-3")]),
            key("Classes\\Drive\\DefaultIcon", vec![sz("", "\"C:\\Program Files\\Tool\\icons.dll\",0"), sz("Other", "%USERPROFILE%\\icons.dll")]),
            key("Classes\\Applications\\editor.exe\\shell\\open\\command", vec![sz("", "\"%1\"")]),
            key("Classes\\SomeVendor.Document\\DefaultIcon", vec![sz("", "%SystemRoot%\\System32\\shell32.dll,1")]),
        ];
        let servers: std::collections::BTreeSet<String> = ["{11dbb47c-a525-400b-9e80-a54615a090c0}", "{3dad6c5d-2167-4cae-9914-f99e41c12cfa}"].iter().map(|class| class.to_string()).collect();
        let (kept, log) = volume_associations(keys, &servers, &["explorer.exe", "NOTEPAD.EXE"]);
        let drive = kept.iter().find(|key| key.path == "Classes\\Drive\\DefaultIcon").expect("a chave fica, sem os valores de fora");
        assert!(drive.values.is_empty(), "os caminhos fora do Windows do convidado saem: {:?}", drive.values);
        let kept: Vec<String> = kept.into_iter().map(|key| key.path).collect();
        // Nenhum verbo ou manipulador de terceiros e nenhuma classe fora da lista.
        for third_party in ["editor", "Archiver", "OpenWithProgids", "{8895b1c6", "Applications", "SomeVendor"] {
            assert!(!kept.iter().any(|path| path.contains(third_party)), "{third_party} ficou: {kept:?}");
            assert!(log.iter().any(|line| line.contains(third_party)), "{third_party} saiu sem aviso: {log:?}");
        }
        assert!(log.iter().any(|line| line.contains("Program Files") || line.contains("Drive\\DefaultIcon\\")), "{log:?}");
        assert_eq!(
            kept,
            [
                "Classes\\Folder",
                "Classes\\Folder\\shell",
                "Classes\\Folder\\shell\\open",
                "Classes\\Folder\\shell\\open\\command",
                "Classes\\Folder\\shellex\\ContextMenuHandlers",
                "Classes\\Folder\\shellex\\ContextMenuHandlers\\Library Location",
                "Classes\\exefile\\shell\\open\\command",
                "Classes\\txtfile\\shell\\open\\command",
                "Classes\\Directory\\DefaultIcon",
                "Classes\\Drive\\DefaultIcon",
            ]
        );
    }

    /// Os valores conhecidos de uma instalação nova ficam como nela, também
    /// quando esta máquina os mudou ou não os tem.
    #[test]
    fn clean_install_defaults_replace_the_host_values() {
        let mut keys = vec![HostKey { path: String::from("Classes\\exefile\\shell\\open\\command"), values: vec![(String::new(), 1, utf16_value("\"C:\\Tools\\wrapper.exe\" \"%1\" %*"))] }];
        let changes = clean_install_defaults(&mut keys);
        let exefile = keys.iter().find(|key| key.path == "Classes\\exefile\\shell\\open\\command").unwrap();
        assert_eq!(exefile.values, vec![(String::new(), 1, utf16_value("\"%1\" %*"))]);
        assert!(changes.iter().any(|line| line.starts_with("Classes\\exefile") && line.contains("outro")), "{changes:?}");
        let folder = keys.iter().find(|key| key.path == "Classes\\Folder\\shell\\open\\command").expect("a chave que faltava entra");
        assert!(folder.values.contains(&(String::from("DelegateExecute"), 1, utf16_value("{11dbb47c-a525-400b-9e80-a54615a090c0}"))));
        // Uma segunda passada não muda nada.
        assert!(clean_install_defaults(&mut keys).is_empty());
    }

    /// As associações que a hive SOFTWARE do convidado leva desta máquina:
    /// só as classes da lista, nenhum verbo cujo comando abra um programa de
    /// fora do volume, nenhum manipulador cuja classe não esteja copiada,
    /// nenhuma lista de OpenWith e nenhum caminho fora do Windows do
    /// convidado; os verbos open de Folder, exefile e txtfile ficam.
    #[cfg(windows)]
    #[test]
    fn host_associations_carry_only_the_windows_of_the_volume() {
        use super::{command_program, outside_windows, text, SHELL_ASSOCIATIONS};
        let keys = super::software_keys();
        let classes: std::collections::BTreeSet<String> = keys.iter().filter(|key| key.path.starts_with("Classes\\CLSID\\")).filter_map(|key| key.path.split('\\').nth(2).map(str::to_ascii_lowercase)).collect();
        let mut programs: Vec<String> = crate::windows_binaries::user_programs().chain(crate::windows_binaries::windows_programs()).map(str::to_ascii_lowercase).collect();
        programs.sort();
        let associations: Vec<&HostKey> = keys.iter().filter(|key| {
            let mut parts = key.path.split('\\');
            parts.next() == Some("Classes") && parts.next().is_some_and(|class| !class.eq_ignore_ascii_case("CLSID") && !class.eq_ignore_ascii_case("Interface") && !class.eq_ignore_ascii_case("AppID"))
        }).collect();
        for key in &associations {
            let class = key.path.split('\\').nth(1).unwrap_or_default();
            assert!(SHELL_ASSOCIATIONS.iter().any(|known| known.eq_ignore_ascii_case(class)), "classe fora da lista: {}", key.path);
            let lower = key.path.to_ascii_lowercase();
            assert!(!lower.contains("\\openwithprogids") && !lower.contains("\\openwithlist"), "{}", key.path);
            for (name, kind, data) in &key.values {
                assert!(!outside_windows(*kind, data), "{}\\{name} cita um caminho fora do Windows do convidado", key.path);
            }
            if lower.ends_with("\\command") {
                if let Some(line) = text(&key.values, "") {
                    let delegate = text(&key.values, "DelegateExecute").is_some_and(|class| classes.contains(&class.trim().to_ascii_lowercase()));
                    assert!(delegate || command_program(&line).is_none_or(|program| programs.binary_search(&program).is_ok()), "{} abre um programa de fora do volume: {line}", key.path);
                }
            }
            let parts: Vec<&str> = key.path.split('\\').collect();
            if let Some(at) = parts.iter().position(|part| part.eq_ignore_ascii_case("shellex")) {
                if parts.len() == at + 3 {
                    // A classe no valor padrão ou, quando ele é só um nome, no nome da chave.
                    let named = parts[at + 2].trim().to_ascii_lowercase();
                    let handler = text(&key.values, "").map(|value| value.trim().to_ascii_lowercase()).filter(|value| classes.contains(value)).unwrap_or(named);
                    assert!(classes.contains(&handler), "manipulador de fora do volume: {} ({handler})", key.path);
                }
            }
        }
        for open in ["Classes\\Folder\\shell\\open\\command", "Classes\\exefile\\shell\\open\\command", "Classes\\txtfile\\shell\\open\\command"] {
            assert!(associations.iter().any(|key| key.path.eq_ignore_ascii_case(open)), "{open} faltou");
        }
    }

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
