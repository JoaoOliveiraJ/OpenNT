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
//!   aparece também em `Microsoft\WindowsRuntime\CLSID\{...}`.
//!
//! As classes WinRT copiadas são as de DLLs de System32 que o volume leva
//! (`windows_binaries::user_programs`): o convidado é uma instalação com
//! esses componentes. Como os binários, as chaves vêm desta máquina no
//! build, com os valores daqui. Fora do Windows nada é copiado.

use crate::host_language::HostKey;

/// O controlador da tela de logon (CLSID_LogonUIController).
#[cfg(windows)]
const LOGON_UI_CONTROLLER: &str = "{0bdc6fc7-83e3-46a4-bfa0-1bc14dbf8b38}";

/// O texto de um valor REG_SZ ou REG_EXPAND_SZ.
#[cfg(windows)]
fn text(values: &[(String, u32, Vec<u8>)], name: &str) -> Option<String> {
    let (_, _, data) = values.iter().find(|(value, kind, _)| value.eq_ignore_ascii_case(name) && matches!(kind, 1 | 2))?;
    let units: Vec<u16> = data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
    Some(String::from_utf16_lossy(&units))
}

/// O nome do arquivo de um DllPath em System32 (`%SystemRoot%\system32\x`,
/// `%windir%\system32\x` ou `C:\Windows\System32\x`).
#[cfg(windows)]
fn system32_file(path: &str) -> Option<&str> {
    ["%systemroot%\\system32\\", "%windir%\\system32\\", "c:\\windows\\system32\\"]
        .iter()
        .find_map(|prefix| path.get(..prefix.len()).filter(|head| head.eq_ignore_ascii_case(prefix)).and_then(|_| path.get(prefix.len()..)))
        .filter(|name| !name.contains('\\'))
}

/// As chaves da hive SOFTWARE.
pub fn software_keys() -> Vec<HostKey> {
    let mut keys = Vec::new();
    #[cfg(windows)]
    {
        use crate::host_language::registry;
        let clsid = format!("Classes\\CLSID\\{LOGON_UI_CONTROLLER}");
        registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{clsid}"), &clsid, true, &mut keys);
        let classes = "Microsoft\\WindowsRuntime\\ActivatableClassId";
        let programs: Vec<&str> = crate::windows_binaries::user_programs().collect();
        let mut identifiers = Vec::new();
        for class in registry::list(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{classes}")) {
            let mut found = Vec::new();
            registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{classes}\\{class}"), &format!("{classes}\\{class}"), true, &mut found);
            let Some(values) = found.first().map(|key| &key.values) else { continue };
            let staged = text(values, "DllPath").as_deref().and_then(system32_file).is_some_and(|file| programs.iter().any(|program| program.eq_ignore_ascii_case(file)));
            if !staged {
                continue;
            }
            identifiers.extend(text(values, "CLSID"));
            keys.extend(found);
        }
        for identifier in identifiers {
            let path = format!("Microsoft\\WindowsRuntime\\CLSID\\{identifier}");
            registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{path}"), &path, true, &mut keys);
        }
    }
    keys
}
