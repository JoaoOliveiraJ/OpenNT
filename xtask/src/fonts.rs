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
//!   Segoe UI Symbol.
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
];

/// As fontes: (caminho no volume, arquivo de origem).
pub fn files(windows: &Path) -> Vec<(String, PathBuf)> {
    FONTS.iter().map(|name| (format!("Fonts/{name}"), windows.join("Fonts").join(name))).collect()
}

/// As chaves da hive SOFTWARE.
pub fn software_keys() -> Vec<HostKey> {
    let mut keys = Vec::new();
    #[cfg(windows)]
    {
        use crate::host_language::registry;
        let current = "Microsoft\\Windows NT\\CurrentVersion";
        for (path, recursive) in [("GRE_Initialize", true), ("FontSubstitutes", false), ("FontLink\\SystemLink", false)] {
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
