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
//! As janelas de pasta do explorer.exe leem do tema ainda o `shellstyle.dll`,
//! as folhas de estilo do DirectUI do quadro da vista: o
//! GetShellStyleHInstance do shell32 (0x4e0f8) monta o caminho pela pasta e
//! pela cor do tema em uso (`aero\Shell\NormalColor\ShellStyle.dll`) e a
//! carrega como dados. Sem ela o UpdateStyle (0xa6b20) devolve 0x8007000E e
//! o CDUIViewFrame::CreateFrameWindow falha; o _OnConnectionCreated do
//! CShellBrowser (ExplorerFrame 0x78c74) larga então a navegação sem
//! mensagem, e a janela fica com a barra de endereço e a pasta em branco.
//!
//! O volume leva o `aero.msstyles` e o `shellstyle.dll` de
//! `\Windows\Resources\Themes\aero`, cada um com o `.mui` dele nos idiomas de
//! interface (ou no primeiro idioma de fallback que o tiver), e a SOFTWARE e
//! a DEFAULT as duas chaves `ThemeManager` desta máquina, com os valores
//! daqui. Fora do Windows nada é copiado.

use std::path::{Path, PathBuf};

use crate::host_language::HostKey;

/// A pasta do tema no volume e no diretório do Windows.
const THEME_FOLDER: &str = "Resources/Themes/aero";

/// O estilo visual do tema (o `DllName` da chave `ThemeManager`).
const VISUAL_STYLE: &str = "aero.msstyles";

/// A pasta do estilo do shell, dentro da do tema: a da cor dele (o
/// `ColorName` da chave `ThemeManager`), a única que o aero traz.
const SHELL_STYLE_FOLDER: &str = "Resources/Themes/aero/Shell/NormalColor";

/// O estilo do shell do tema (as folhas de estilo do DirectUI).
const SHELL_STYLE: &str = "shellstyle.dll";

/// A chave relativa à raiz da SOFTWARE e do perfil.
const THEME_MANAGER: &str = "Microsoft\\Windows\\CurrentVersion\\ThemeManager";

/// Os arquivos do tema: (caminho no volume, arquivo de origem).
pub fn files(windows: &Path, languages: &[String], fallbacks: &[String]) -> Vec<(String, PathBuf)> {
    let mut files = Vec::new();
    for (folder, name) in [(THEME_FOLDER, VISUAL_STYLE), (SHELL_STYLE_FOLDER, SHELL_STYLE)] {
        let origin = windows.join(folder);
        files.push((format!("{folder}/{name}"), origin.join(name)));
        files.extend(crate::host_language::mui_files(&origin, name, languages, fallbacks).into_iter().map(|(path, source)| (format!("{folder}/{path}"), source)));
    }
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

#[cfg(all(test, windows))]
mod tests {
    /// O volume leva o estilo visual e o estilo do shell nos caminhos de onde
    /// o uxtheme e o shell32 os leem, cada um com o `.mui` de um idioma da
    /// interface ou do fallback.
    #[test]
    fn theme_files_carry_the_visual_style_and_the_shell_style() {
        let languages = crate::host_language::ui_languages();
        let fallbacks = crate::host_language::fallback_languages(&languages);
        let files = super::files(&crate::windows_binaries::windows_directory(), &languages, &fallbacks);
        for (folder, name) in [("Resources/Themes/aero", "aero.msstyles"), ("Resources/Themes/aero/Shell/NormalColor", "shellstyle.dll")] {
            let source = files.iter().find(|(path, _)| *path == format!("{folder}/{name}")).map(|(_, source)| source);
            assert!(source.is_some_and(|source| source.is_file()), "{folder}/{name} fora do volume");
            let resources = format!("/{}.MUI", name.to_uppercase());
            assert!(files.iter().any(|(path, _)| path.strip_prefix(folder).is_some_and(|rest| rest.matches('/').count() == 2 && rest.ends_with(&resources))), "{folder}: sem o .mui de {name}");
        }
    }
}
