//! Configuração da instalação convidada.
//! Compartilhada pelas consultas NLS e pelo fallback de recursos.
//!
//! As constantes são o padrão sem a configuração de idioma no Registro; com
//! ela (`Control\Nls\Language` da SYSTEM, lido no boot por
//! `ps/locale::initialize_from_registry`), a localidade e os idiomas de
//! interface são os da instalação.

pub const DEFAULT_LOCALE: u32 = 0x409;
pub const DEFAULT_UI_LANGUAGE: u32 = 0x409;
pub const INSTALL_UI_LANGUAGE: u32 = 0x409;
/// Mesma página ANSI instalada pelo carregador de usuário em C_1252.NLS.
pub const ANSI_CODE_PAGE: u32 = 1252;

/// PsMachineUILanguageId (o idioma de interface padrão),
/// PsInstallUILanguageId e o idioma do PsDefaultSystemLocaleId.
pub fn resource_languages() -> [u32; 3] {
    use crate::ntos::ps::locale;
    [locale::default_ui_language(), locale::install_ui_language(), locale::default_system_locale() & 0xFFFF]
}
