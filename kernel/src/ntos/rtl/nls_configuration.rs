//! Configuração da instalação convidada.
//! Compartilhada pelas consultas NLS e pelo fallback de recursos.
//!
//! As constantes são o padrão sem a configuração de idioma no Registro; com
//! ela (`Control\Nls\Language` da SYSTEM, lido no boot por
//! `ps/locale::initialize_from_registry`), a localidade e os idiomas de
//! interface são os da instalação. As páginas ANSI e OEM seguem
//! `Control\Nls\CodePage` da mesma hive
//! ([`initialize_code_pages_from_registry`]), como o CmpFindNLSData do
//! winload escolhe as tabelas que o kernel recebe no bloco do carregador.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::rtl::{KernelError, SpinLock};

pub const DEFAULT_LOCALE: u32 = 0x409;
pub const DEFAULT_UI_LANGUAGE: u32 = 0x409;
pub const INSTALL_UI_LANGUAGE: u32 = 0x409;
/// As páginas sem `Control\Nls\CodePage` (o boot sem as chaves da
/// instalação, como o dos autotestes): ANSI 1252 e OEM 437.
pub const DEFAULT_ANSI_CODE_PAGE: u32 = 1252;
pub const DEFAULT_OEM_CODE_PAGE: u32 = 437;

const CODE_PAGE_KEY: &str = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage";

static ANSI: AtomicU32 = AtomicU32::new(DEFAULT_ANSI_CODE_PAGE);
static OEM: AtomicU32 = AtomicU32::new(DEFAULT_OEM_CODE_PAGE);
/// Os arquivos das tabelas ANSI e OEM (o dado de `CodePage\<página>`); sem
/// configuração, `c_<página>.nls`.
static FILES: SpinLock<Option<(String, String)>> = SpinLock::new(None);

/// A página ANSI instalada (NlsAnsiCodePage).
pub fn ansi_code_page() -> u32 {
    ANSI.load(Ordering::Acquire)
}

/// A página OEM instalada (NlsOemCodePage).
pub fn oem_code_page() -> u32 {
    OEM.load(Ordering::Acquire)
}

/// O arquivo da tabela ANSI ou OEM em System32: o do Registro, ou
/// `c_<página>.nls` sem configuração.
pub fn table_file(oem: bool) -> String {
    let files = FILES.lock().clone();
    match files {
        Some((ansi_file, oem_file)) => {
            if oem {
                oem_file
            } else {
                ansi_file
            }
        }
        None => format!("c_{}.nls", if oem { oem_code_page() } else { ansi_code_page() }),
    }
}

/// Um valor de cadeia (REG_SZ ou REG_EXPAND_SZ) de `CodePage`, até o NUL.
fn code_page_text(name: &str) -> Option<String> {
    let value = crate::ntos::cm::registry::read_value_by_path(CODE_PAGE_KEY, name).filter(|value| value.value_type == 1 || value.value_type == 2)?;
    let units: Vec<u16> = value.data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
    Some(String::from_utf16_lossy(&units))
}

/// O seletor (`ACP` ou `OEMCP`) dá o número da página, e o valor com esse
/// nome dá o arquivo da tabela (CmpFindNLSData, winload 19041 0x134208:
/// "ACP" em 0x134354 e o valor nomeado pelo dado em 0x134462; "OEMCP" em
/// 0x13451a / 0x1345fb).
fn configured_page(selector: &str) -> Option<(u32, String)> {
    let id = code_page_text(selector)?;
    let id = id.trim();
    let file = code_page_text(id)?;
    Some((id.parse().ok()?, file))
}

fn set_code_pages(ansi: u32, oem: u32, files: Option<(String, String)>) {
    ANSI.store(ansi, Ordering::Release);
    OEM.store(oem, Ordering::Release);
    *FILES.lock() = files;
}

/// As tabelas instaladas do Rtl recarregadas das páginas configuradas, com as
/// células NlsAnsiCodePage/NlsOemCodePage/NlsMb*CodePageTag (o papel do
/// RtlResetRtlTranslations).
fn reinstall_tables() -> Result<(), KernelError> {
    crate::ntos::rtl::ansi_code_page::reinstall()?;
    crate::ntos::rtl::oem_code_page::reinstall()
}

/// O CmpFindNLSData do winload sobre a SYSTEM carregada: `CodePage\ACP` e
/// `CodePage\OEMCP` dão o número de cada página, e o valor com esse nome dá
/// o arquivo. Sem a chave (o boot sem as chaves da instalação), as páginas
/// voltam a 1252/437. Quando algo muda, as tabelas instaladas recarregam;
/// uma tabela que não carrega (ausente no volume, ou com outra página no
/// cabeçalho) deixa as páginas anteriores.
pub fn initialize_code_pages_from_registry() {
    let configured = configured_page("ACP").zip(configured_page("OEMCP"));
    let from_registry = configured.is_some();
    let (ansi, oem, files) = match configured {
        Some(((ansi, ansi_file), (oem, oem_file))) => (ansi, oem, Some((ansi_file, oem_file))),
        None => (DEFAULT_ANSI_CODE_PAGE, DEFAULT_OEM_CODE_PAGE, None),
    };
    let previous = (ansi_code_page(), oem_code_page(), FILES.lock().clone());
    if ansi == previous.0 && oem == previous.1 && files == previous.2 {
        return;
    }
    set_code_pages(ansi, oem, files);
    match reinstall_tables() {
        Ok(()) => {
            if from_registry {
                crate::debug_print!("[nls] paginas ANSI {} e OEM {} ({} / {})", ansi, oem, table_file(false), table_file(true));
            }
        }
        Err(error) => {
            crate::debug_print!("[nls] paginas ANSI {} e OEM {} ({} / {}) recusadas: {}", ansi, oem, table_file(false), table_file(true), error);
            set_code_pages(previous.0, previous.1, previous.2);
            if let Err(error) = reinstall_tables() {
                crate::debug_print!("[nls] as tabelas anteriores nao recarregaram: {}", error);
            }
        }
    }
}

/// PsMachineUILanguageId (o idioma de interface padrão),
/// PsInstallUILanguageId e o idioma do PsDefaultSystemLocaleId.
pub fn resource_languages() -> [u32; 3] {
    use crate::ntos::ps::locale;
    [locale::default_ui_language(), locale::install_ui_language(), locale::default_system_locale() & 0xFFFF]
}
