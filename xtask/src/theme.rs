//! O tema visual desta instalação que a sessão gráfica carrega no boot do
//! processo inicial real (`--initial-process=smss`).
//!
//! No Windows 10 19041, o ThemesOnEarlyCreateSession do uxinit.dll que o
//! winlogon chama cria a seção `\Sessions\<n>\Windows\ThemeSection` e, sem o
//! serviço Themes rodando, carrega o tema no próprio processo
//! (InitializeUserTheme → LoadCurrentTheme): o `DllName` de
//! `Software\Microsoft\Windows\CurrentVersion\ThemeManager` do perfil do
//! sistema (o HKCU do SYSTEM é o `\Registry\User\.DEFAULT`), com o
//! ColorName, o SizeName e os valores da última carga; sem o `DllName`
//! nenhum tema é carregado. O `.msstyles` é aberto com
//! LOAD_LIBRARY_AS_DATAFILE (com o `.mui` do idioma de interface na
//! subpasta do idioma), a assinatura é conferida e as seções do tema vão
//! para a sessão. O uDWM do dwm.exe abre os dados do tema (`DWMWindow` e os
//! outros) por essa seção, e um tema que falta derruba o dwm.exe e a sessão.
//! O Remote_InitUserRegistry do uxinit compara antes o `LMVersion` da chave
//! da máquina (`HKLM\...\ThemeManager`) com o do perfil.
//!
//! O volume leva o `aero.msstyles` de `\Windows\Resources\Themes\aero` com o
//! `.mui` dele nos idiomas de interface (ou no primeiro idioma de fallback
//! que o tiver), a SOFTWARE e a DEFAULT as duas chaves `ThemeManager` desta
//! máquina, com os valores daqui. Fora do Windows nada é copiado.

use std::path::{Path, PathBuf};

use crate::host_language::HostKey;

/// A pasta do tema no volume e no diretório do Windows.
const THEME_FOLDER: &str = "Resources/Themes/aero";

/// O estilo visual do tema (o `DllName` da chave `ThemeManager`).
const VISUAL_STYLE: &str = "aero.msstyles";

/// A chave relativa à raiz da SOFTWARE e do perfil.
const THEME_MANAGER: &str = "Microsoft\\Windows\\CurrentVersion\\ThemeManager";

/// Os arquivos do tema: (caminho no volume, arquivo de origem).
pub fn files(windows: &Path, languages: &[String], fallbacks: &[String]) -> Vec<(String, PathBuf)> {
    let folder = windows.join(THEME_FOLDER);
    let mut files = vec![(format!("{THEME_FOLDER}/{VISUAL_STYLE}"), folder.join(VISUAL_STYLE))];
    files.extend(crate::host_language::mui_files(&folder, VISUAL_STYLE, languages, fallbacks).into_iter().map(|(path, source)| (format!("{THEME_FOLDER}/{path}"), source)));
    files
}

/// As chaves da hive SOFTWARE.
pub fn software_keys() -> Vec<HostKey> {
    let mut keys = Vec::new();
    #[cfg(windows)]
    {
        use crate::host_language::registry;
        registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{THEME_MANAGER}"), THEME_MANAGER, false, &mut keys);
    }
    keys
}

/// As chaves do perfil do sistema (a DEFAULT).
pub fn default_keys() -> Vec<HostKey> {
    let mut keys = Vec::new();
    #[cfg(windows)]
    {
        use crate::host_language::registry;
        registry::copy(registry::USERS, &format!(".DEFAULT\\Software\\{THEME_MANAGER}"), &format!("Software\\{THEME_MANAGER}"), false, &mut keys);
    }
    keys
}
