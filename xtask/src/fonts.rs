//! As fontes desta instalação que a sessão gráfica usa no boot do processo
//! inicial real (`--initial-process=smss`), em `\SystemRoot\Fonts` (a pasta
//! `Fonts` do volume), e as chaves que as descrevem.
//!
//! No Windows 10 19041:
//! - o win32kfull.sys abre `\SystemRoot\Fonts`
//!   (vInitFontsDirectoryNameInformation) e cria as fontes de estoque no
//!   FinishStockFontInitInternal, depois que o GdiAddInitialFonts do csrss
//!   (o GdiAddInitialFontsThread do winsrvext.dll) espera o anfitrião UMFD:
//!   os valores `FONTS.FON` (SYSTEM_FONT), `OEMFONT.FON` (OEM_FIXED_FONT) e
//!   `FIXEDFON.FON` (SYSTEM_FIXED_FONT) de
//!   `Windows NT\CurrentVersion\GRE_Initialize\SmallFont`, com o prefixo
//!   `\SystemRoot\Fonts\`; uma fonte sem valor não é criada;
//! - o LoadLocalFonts do user32 que o winlogon chama (o xxxLW_LoadFonts do
//!   win32kfull) carrega o marlett.ttf e cada valor de
//!   `Windows NT\CurrentVersion\Fonts`; o HandleFontChangeEvent do
//!   winsrvext.dll acrescenta o ARIAL.TTF;
//! - as caixas de diálogo usam as faces de `FontSubstitutes` (`MS Shell Dlg`
//!   = Microsoft Sans Serif, `MS Shell Dlg 2` = Tahoma), as métricas de
//!   janela e o XAML da tela de logon (pelo DirectWrite), a família Segoe UI
//!   e os ícones do Segoe MDL2 Assets, e o `FontLink\SystemLink` cai no
//!   Segoe UI Symbol;
//! - o conhost.exe usa o Consolas 16 (o `Console\TrueTypeFont` não tem
//!   entrada para a página de código, e o
//!   RetrieveDefaultFontNameForCodepage do conhost cai no Consolas), e o
//!   win32kfull o carrega com as outras fontes de `Fonts` no
//!   AddInitialFonts do csrss, antes do `CmdLine` do winlogon.
//!
//! O DPI vem do perfil de hardware: o win32kfull lê o `LogPixels` de
//! `CurrentControlSet\Hardware Profiles\Current\Software\Fonts` (e o
//! FinishStockFontInitInternal procura as fontes de estoque primeiro ali), e
//! o `Current` é o link volátil que o kernel cria no boot para o perfil de
//! `Control\IDConfigDB\CurrentConfig` (o CmpCreateHardwareProfiles). A
//! SYSTEM leva o `IDConfigDB` e os perfis de `Hardware Profiles` daqui, sem
//! o `Current`.
//!
//! A chave `Fonts` vai só com os valores das fontes do volume: o convidado
//! é uma instalação com estas fontes. As outras chaves vêm inteiras, com os
//! valores daqui. Fora do Windows nada é copiado.

use std::path::{Path, PathBuf};

use crate::host_language::HostKey;

/// As fontes do volume (nomes de `\Windows\Fonts`).
const FONTS: &[&str] = &[
    // As fontes de estoque do GRE_Initialize\SmallFont (96 DPI).
    "vgasys.fon",
    "vga850.fon",
    "vgafix.fon",
    // As do LoadLocalFonts e do HandleFontChangeEvent.
    "marlett.ttf",
    "arial.ttf",
    // As faces das caixas de diálogo (FontSubstitutes).
    "micross.ttf",
    "tahoma.ttf",
    "tahomabd.ttf",
    // A família Segoe UI, o Segoe MDL2 Assets e o Segoe UI Symbol.
    "segoeui.ttf",
    "segoeuib.ttf",
    "segoeuii.ttf",
    "segoeuiz.ttf",
    "segoeuil.ttf",
    "segoeuisl.ttf",
    "seguisb.ttf",
    "seguisbi.ttf",
    "seguili.ttf",
    "seguisli.ttf",
    "seguibl.ttf",
    "seguibli.ttf",
    "segmdl2.ttf",
    "seguisym.ttf",
    // A fonte padrão do console: o conhost.exe pede o Consolas quando a
    // página de código não tem entrada em Console\TrueTypeFont; o Lucida
    // Console é a entrada "0" dessa chave.
    "consola.ttf",
    "consolab.ttf",
    "consolai.ttf",
    "consolaz.ttf",
    "lucon.ttf",
];

/// As fontes: (caminho no volume, arquivo de origem).
pub fn files(windows: &Path) -> Vec<(String, PathBuf)> {
    FONTS.iter().map(|name| (format!("Fonts/{name}"), windows.join("Fonts").join(name))).collect()
}

/// As chaves da hive SYSTEM, já no conjunto de controle que a hive guarda
/// (`control_set`, como `ControlSet001`): o `Control\IDConfigDB` e os
/// perfis de `Hardware Profiles`. O `Current` daqui é o link que o kernel
/// cria (a abertura o segue até o perfil) e fica de fora.
pub fn system_keys(control_set: &str) -> Vec<HostKey> {
    let mut keys = Vec::new();
    #[cfg(windows)]
    {
        use crate::host_language::registry;
        let host = "SYSTEM\\CurrentControlSet";
        registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\Control\\IDConfigDB"), &format!("{control_set}\\Control\\IDConfigDB"), true, &mut keys);
        let profiles = "Hardware Profiles";
        registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\{profiles}"), &format!("{control_set}\\{profiles}"), false, &mut keys);
        for profile in registry::list(registry::LOCAL_MACHINE, &format!("{host}\\{profiles}")).into_iter().filter(|name| !name.eq_ignore_ascii_case("Current")) {
            registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\{profiles}\\{profile}"), &format!("{control_set}\\{profiles}\\{profile}"), true, &mut keys);
        }
        // O HwProfileGuid é gerado na instalação e identifica a máquina (o
        // GetCurrentHwProfile o devolve): fica de fora.
        for key in keys.iter_mut() {
            key.values.retain(|(name, _, _)| !name.eq_ignore_ascii_case("HwProfileGuid"));
        }
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
        let current = "Microsoft\\Windows NT\\CurrentVersion";
        for (path, recursive) in [("GRE_Initialize", true), ("FontSubstitutes", false), ("FontLink\\SystemLink", false), ("Console", true)] {
            registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{current}\\{path}"), &format!("{current}\\{path}"), recursive, &mut keys);
        }
        let first = keys.len();
        registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{current}\\Fonts"), &format!("{current}\\Fonts"), false, &mut keys);
        if let Some(fonts) = keys.get_mut(first) {
            // O dado é o nome do arquivo em `\Windows\Fonts` (ou um caminho).
            fonts.values.retain(|(_, kind, data)| {
                let units: Vec<u16> = data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
                let file = String::from_utf16_lossy(&units);
                let name = file.rsplit(['\\', '/']).next().unwrap_or("");
                matches!(kind, 1 | 2) && FONTS.iter().any(|font| font.eq_ignore_ascii_case(name))
            });
        }
    }
    keys
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::files;

    /// A fonte padrão do console vai para a pasta Fonts do volume.
    #[test]
    fn the_console_font_is_staged() {
        assert!(files(Path::new("C:/Windows")).iter().any(|(path, _)| path == "Fonts/consola.ttf"));
    }

    /// O `Console\TrueTypeFont` desta máquina vem com a SOFTWARE, com o
    /// Consolas em "00", e a chave `Fonts` com o valor do Consolas.
    #[cfg(windows)]
    #[test]
    fn the_console_key_and_the_consolas_value_are_copied() {
        let keys = super::software_keys();
        let consolas: Vec<u8> = "Consolas".encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect();
        let true_type = keys.iter().find(|key| key.path == "Microsoft\\Windows NT\\CurrentVersion\\Console\\TrueTypeFont").expect("Console\\TrueTypeFont");
        assert!(true_type.values.iter().any(|(name, kind, data)| name == "00" && *kind == 1 && *data == consolas), "{:?}", true_type.values.iter().map(|(name, _, _)| name).collect::<Vec<_>>());
        let fonts = keys.iter().find(|key| key.path == "Microsoft\\Windows NT\\CurrentVersion\\Fonts").expect("Fonts");
        assert!(fonts.values.iter().any(|(name, _, _)| name == "Consolas (TrueType)"));
    }
}
