//! Errata Manager (Em*): o banco de errata, os provedores de entradas e
//! callbacks e a avaliação de regras para os drivers clientes.
//!
//! Como no NT, o carregador de boot entrega ao kernel a imagem do
//! `\SystemRoot\INF\errata.inf` (o EmInfFileImage/EmInfFileSize do
//! LOADER_PARAMETER_EXTENSION): o OpenNT a lê do volume de boot assim que
//! ele é montado, antes dos drivers. O EmInitSystem da fase 0 habilita a
//! paginação do Errata Manager, interpreta a imagem
//! (EmpParseInfDatabase, `parse.rs`), guarda a data do BIOS
//! (EmpCacheBiosDate) e registra os callbacks da HAL
//! (HalRegisterErrataCallbacks, `hal/errata.rs`) e os embutidos
//! (`builtin.rs`); os registros enfileiram a atualização das regras, que o
//! work item do Errata Manager processa antes dos drivers. A fase 1 abre
//! `Control\Errata\Dynamic`, que nesta instalação não tem valores (bancos
//! adicionais).

use core::sync::atomic::{AtomicBool, Ordering};

pub mod builtin;
pub mod database;
pub mod evaluate;
pub mod exports;
pub mod parse;
pub mod provider;
pub mod rule;

/// EmpPagingStatus.+8 bit 31 (EmPowerPagingEnabled): o EmInitSystem já
/// rodou e as consultas são atendidas.
static PAGING_ENABLED: AtomicBool = AtomicBool::new(false);
/// EmBuiltinProviderHandle.
static BUILTIN_PROVIDER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// O Errata Manager já foi inicializado (EmpAcquirePagingReference).
pub fn initialized() -> bool {
    PAGING_ENABLED.load(Ordering::Acquire)
}

/// O caminho no volume do INF de errata (`\SystemRoot\INF\errata.inf`).
pub const INF_VOLUME_PATH: &str = "/Windows/INF/errata.inf";

/// A imagem do INF de errata que o carregador entrega (o volume de boot
/// montado); `None` sem o arquivo.
pub fn loader_inf_image() -> Option<alloc::vec::Vec<u8>> {
    crate::drivers::fs::ntfs::mounted()?.read_bytes(INF_VOLUME_PATH).ok().flatten()
}

/// EmInitSystem(0, LoaderBlock) com a imagem do INF de errata.
pub fn initialize_system(image: Option<&[u8]>) -> Result<(), u32> {
    if PAGING_ENABLED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    if let Some(image) = image.filter(|image| !image.is_empty()) {
        let mut database = database::lock();
        let status = parse::parse_database(image, &mut database);
        if status as i32 <= -1 {
            return Err(status);
        }
        crate::debug_print!("[em] banco de errata: {} tipos de entrada, {} callbacks, {} regras, {} cadeias, {} regras-alvo", database.entry_types.len(), database.callbacks.len(), database.rules.len(), database.strings.len(), database.targets.len());
    }
    builtin::cache_bios_date();
    provider::register_records(0, &[], &crate::hal::errata::callbacks())?;
    BUILTIN_PROVIDER.store(provider::register_records(0, &[], &builtin::callbacks())?, Ordering::Release);
    Ok(())
}

/// EmInitSystem(1): `Control\Errata\Dynamic` (criada se faltar) e os bancos
/// adicionais dos valores dela.
pub fn initialize_dynamic() {
    let path = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Errata\\Dynamic";
    let Ok(handle) = crate::ntos::cm::registry::open_or_create(path, None) else { return };
    let values = crate::ntos::cm::registry::get_node(handle).and_then(|node| crate::ntos::cm::registry::with_node(node, |key| key.value_count())).unwrap_or(0);
    crate::ntos::cm::registry::close_handle(handle);
    if values != 0 {
        crate::debug_print!("[em] Control\\Errata\\Dynamic com {} banco(s) adicional(is), que o OpenNT ainda nao mescla", values);
    }
}
