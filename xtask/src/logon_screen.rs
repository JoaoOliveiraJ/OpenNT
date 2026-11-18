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
//! - o logoncontroller.dll enumera os provedores de credencial de
//!   `Microsoft\Windows\CurrentVersion\Authentication\Credential Providers`
//!   (e os filtros de `Credential Provider Filters`) e cria cada um pelo
//!   CLSID, e lê o estado da tela em `Authentication\LogonUI`;
//! - as outras classes COM em processo dessas DLLs são criadas pelo CLSID do
//!   mesmo jeito: a fábrica e os codecs do WIC (o WindowsCodecs.dll, que
//!   decodifica a imagem da tela de bloqueio), o propsys.dll, o MSCTF.dll...
//!
//! As classes COM e WinRT copiadas são as de DLLs de System32 que o volume
//! leva (`windows_binaries::user_programs`): o convidado é uma instalação
//! com esses componentes. Do `Authentication\LogonUI` e dos provedores
//! ficam de fora o último logon, o usuário selecionado, os dados de sessão
//! e as subchaves e os valores com o SID de um usuário desta máquina (o
//! convidado não tem as contas daqui). Como os binários, as chaves vêm desta
//! máquina no build, com os valores daqui. Fora do Windows nada é copiado.

use crate::host_language::HostKey;

/// Os valores de `Authentication\LogonUI` que descrevem o último logon ou o
/// usuário selecionado desta máquina.
#[cfg(windows)]
const LOGON_UI_LOCAL_VALUES: &[&str] = &["LastLoggedOnUser", "LastLoggedOnSAMUser", "LastLoggedOnDisplayName", "LastLoggedOnUserSID", "SelectedUserSID"];

/// As subchaves de `Authentication\LogonUI` com o estado das sessões e o
/// conteúdo por usuário desta máquina.
#[cfg(windows)]
const LOGON_UI_LOCAL_KEYS: &[&str] = &["SessionData", "Creative"];

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
        for class in registry::list(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{objects}")) {
            let mut server = Vec::new();
            registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{objects}\\{class}\\InprocServer32"), "", false, &mut server);
            if staged(server.first().and_then(|key| text(&key.values, ""))) {
                registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{objects}\\{class}"), &format!("{objects}\\{class}"), true, &mut keys);
            }
        }
        // As classes WinRT das DLLs do volume.
        let classes = "Microsoft\\WindowsRuntime\\ActivatableClassId";
        let mut identifiers = Vec::new();
        for class in registry::list(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{classes}")) {
            let mut found = Vec::new();
            registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{classes}\\{class}"), &format!("{classes}\\{class}"), true, &mut found);
            let Some(values) = found.first().map(|key| &key.values) else { continue };
            if !staged(text(values, "DllPath")) {
                continue;
            }
            identifiers.extend(text(values, "CLSID"));
            keys.extend(found);
        }
        for identifier in identifiers {
            let path = format!("Microsoft\\WindowsRuntime\\CLSID\\{identifier}");
            registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{path}"), &path, true, &mut keys);
        }
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
        keys.extend(found);
    }
    keys
}
