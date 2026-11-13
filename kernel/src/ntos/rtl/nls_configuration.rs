//! Configuração da instalação convidada — `system32/ntos/rtl/nls-configuration.js`.
//! Compartilhada pelas consultas NLS e pelo fallback de recursos.

pub const DEFAULT_LOCALE: u32 = 0x409;
pub const DEFAULT_UI_LANGUAGE: u32 = 0x409;
pub const INSTALL_UI_LANGUAGE: u32 = 0x409;
/// Mesma página ANSI instalada pelo carregador de usuário em C_1252.NLS.
pub const ANSI_CODE_PAGE: u32 = 1252;

pub fn resource_languages() -> [u32; 3] {
    [DEFAULT_UI_LANGUAGE, INSTALL_UI_LANGUAGE, DEFAULT_LOCALE & 0xFFFF]
}
