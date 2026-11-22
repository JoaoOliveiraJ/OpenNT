//! A ntdll de 32 bits: a DLL de sistema do WoW64 x86.
//!
//! No 19041 o PspInitializeSystemDlls localiza, além da ntdll nativa, a de
//! SysWOW64 (PspSystemDlls[PsWowX86SystemDll], PspWowX86SystemDllData) e
//! guarda no PsWowX86SharedInformation as entradas que o wow64.dll precisa
//! dela, pelos nomes do NtdllWowX86Exports: LdrInitializeThunk (0),
//! KiUserExceptionDispatcher (1), KiUserApcDispatcher (2),
//! KiUserCallbackDispatcher (3), RtlUserThreadStart (4),
//! RtlpQueryProcessDebugInformationRemote (5), a base da imagem (6),
//! LdrSystemDllInitBlock (7) e RtlpFreezeTimeBias (8). O PsMapSystemDlls
//! mapeia a ntdll de 32 bits num processo WoW64 (e só nele), na mesma base em
//! todos.
//!
//! Aqui a imagem é a mesma do volume, mapeada uma vez na raiz do System, na
//! ImageBase do cabeçalho, e registrada como imagem de sistema
//! ([`TEMPLATE`], pelo `loader::register_system_image` da ntdll nativa): só
//! um processo WoW64 x86 recebe as páginas dela, pelo
//! `loader::map_system_images` (as de código e somente leitura divididas, as
//! graváveis em cópias privadas), e [`map_into_current_process`] põe a
//! imagem na lista de imagens dele. A carga é preguiçosa: na primeira pergunta
//! ([`present`]), que o PsWow64IsMachineSupported e a classe
//! SystemSupportedProcessorArchitectures fazem. Sem o arquivo no volume não
//! há WoW64 x86.
//!
//! [`prepare_init_blocks`] é o PspPrepareSystemDllInitBlock (19041
//! 0x611e28) de um processo WoW64, anexado a ele: no LdrSystemDllInitBlock
//! da cópia da ntdll nativa e no da ntdll de 32 bits (os dois com Size 0xF0;
//! outro tamanho é STATUS_REVISION_MISMATCH), a relocação das duas imagens
//! (a diferença entre a base mapeada e a do cabeçalho), o
//! Wow64SharedInformation, o RngData sorteado e Flags, CfgBitMap e as
//! máscaras de mitigação em zero (este kernel não tem CFG de usuário nem
//! mitigações no pedido de criação). O ProcessInit do wow64.dll lê o
//! Wow64SharedInformation do bloco da ntdll nativa (NtDll32Base, o
//! LdrInitializeThunk e os despachantes de 32 bits); a ntdll de 32 bits usa
//! o RngData do bloco dela no cookie GS. Lacuna: os processos nativos ainda
//! não recebem o bloco.

use alloc::string::String;
use alloc::sync::Arc;

use crate::drivers::fs::volume_files;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_wow64::PsSystemDllInitBlock;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::paging;
use crate::ntos::mm::pe_loader::{self, LoadOptions};
use crate::ntos::ob::objects::file::FileSource;
use crate::ntos::ps::notify::image::{self as image_notify, Image, NotifyOptions};
use crate::ntos::ps::user::loader::ImageRegion;
use crate::ntos::ps::user::memory::{self, Space, TemplatePage};
use crate::ntos::ps::user::state::{self, RegionKind};
use crate::ntos::ps::{process, process_context};
use crate::ntos::rtl::image::pe_exports::Exports;
use crate::rtl::{KernelError, SpinLock};

/// O caminho da ntdll de 32 bits.
pub const NT_PATH: &str = "\\SystemRoot\\SysWOW64\\ntdll.dll";
/// O nome DOS que o loader de 32 bits usa para ela.
pub const DOS_PATH: &str = "C:\\Windows\\SysWOW64\\ntdll.dll";
/// O tamanho do PS_SYSTEM_DLL_INIT_BLOCK que o kernel aceita.
const INIT_BLOCK_SIZE: u32 = 0xF0;
/// STATUS_REVISION_MISMATCH.
const STATUS_REVISION_MISMATCH: u32 = 0xC000_0059;

/// Os nomes do NtdllWowX86Exports, nos índices do Wow64SharedInformation
/// (o 6 é a base da imagem).
const SHARED_EXPORTS: [(usize, &str); 8] = [
    (0, "LdrInitializeThunk"),
    (1, "KiUserExceptionDispatcher"),
    (2, "KiUserApcDispatcher"),
    (3, "KiUserCallbackDispatcher"),
    (4, "RtlUserThreadStart"),
    (5, "RtlpQueryProcessDebugInformationRemote"),
    (7, "LdrSystemDllInitBlock"),
    (8, "RtlpFreezeTimeBias"),
];
/// Índices do Wow64SharedInformation usados pelo kernel.
pub const SHARED_RTL_USER_THREAD_START: usize = 4;
pub const SHARED_BASE_ADDRESS: usize = 6;
pub const SHARED_LDR_SYSTEM_DLL_INIT_BLOCK: usize = 7;

/// A ntdll de 32 bits mapeada na raiz do System.
pub struct Wow64Ntdll {
    pub image_base: u64,
    pub size_of_image: u64,
    /// A ImageBase do cabeçalho (a relocação é a diferença).
    pub preferred_base: u64,
    pub exports: Arc<Exports>,
    /// O PsWowX86SharedInformation.
    pub shared_information: [u64; 16],
    pub notification: Arc<dyn FileSource>,
}

/// O nome da imagem de sistema da ntdll de 32 bits entre as fotografias do
/// loader (`loader::register_system_image`), que só um processo WoW64 x86
/// recebe.
pub const TEMPLATE: &str = "ntdll32";

/// `None` antes da primeira pergunta; `Some(None)` sem a ntdll de 32 bits.
static NTDLL32: SpinLock<Option<Option<Arc<Wow64Ntdll>>>> = SpinLock::new(None);

/// A ntdll de 32 bits, carregada na primeira pergunta.
pub fn ntdll() -> Option<Arc<Wow64Ntdll>> {
    if let Some(known) = NTDLL32.lock().clone() {
        return known;
    }
    let loaded = match load() {
        Ok(loaded) => loaded.map(Arc::new),
        Err(error) => {
            crate::debug_print!("[wow64] ntdll de 32 bits nao carregou: {}", error);
            None
        }
    };
    let mut slot = NTDLL32.lock();
    if let Some(known) = slot.clone() {
        // Outra CPU carregou antes: a cópia desta fica na raiz do System
        // (só a primeira é fotografada e usada).
        return known;
    }
    *slot = Some(loaded.clone());
    loaded
}

/// Há WoW64 x86: a ntdll de SysWOW64 está no volume e carregou.
pub fn present() -> bool {
    ntdll().is_some()
}

/// O PspLocateSystemDll do WoW64 x86: a imagem do volume, mapeada e
/// fotografada na raiz do System, com o PsWowX86SharedInformation.
fn load() -> Result<Option<Wow64Ntdll>, KernelError> {
    let Some(file) = volume_files::lookup_volume_file(NT_PATH).filter(|file| !file.directory()) else { return Ok(None) };
    let name = crate::drivers::fs::ntfs::nt_path(&file.volume_path());
    let (image_source, notification) = crate::ntos::ps::create::volume_image_sources(name.clone(), file.clone());
    let options = LoadOptions { user_space: true, skip_imports: true, skip_security_cookie: true, notify_image: false, ..LoadOptions::default() };
    let loaded = process_context::with_process(process::get_system_process(), || -> Result<Wow64Ntdll, KernelError> {
        let image = pe_loader::load_from_source(image_source, &options)?;
        crate::ntos::ps::user::loader::register_system_image(TEMPLATE, &image)?;
        memory::insert_region(Space::system(), RegionKind::ProcessImages, Arc::new(ImageRegion { base: image.image_base, size: image.size_of_image, name: name.clone(), file: Some(file.clone()), system: 0 }));
        let mut shared_information = [0u64; 16];
        for (index, export) in SHARED_EXPORTS {
            shared_information[index] = image.exports.exports.get(export).copied().ok_or_else(|| KernelError::new(alloc::format!("ntdll de 32 bits sem {export}")))?;
        }
        shared_information[SHARED_BASE_ADDRESS] = image.image_base;
        Ok(Wow64Ntdll { image_base: image.image_base, size_of_image: image.size_of_image, preferred_base: image.preferred_base, exports: image.exports.clone(), shared_information, notification })
    })??;
    crate::debug_print!("[wow64] ntdll de 32 bits em {:#x} ({} exports): LdrInitializeThunk {:#x}, RtlUserThreadStart {:#x}", loaded.image_base, loaded.exports.exports.len(), loaded.shared_information[0], loaded.shared_information[SHARED_RTL_USER_THREAD_START]);
    Ok(Some(loaded))
}

/// O PspMapSystemDll da ntdll de 32 bits no processo em montagem (o
/// corrente, anexado), depois do `loader::map_system_images` que mapeou as
/// páginas dela: a imagem na lista do processo, com o nome do arquivo e o
/// EPROCESS dono das páginas de sistema.
pub fn map_into_current_process(ntdll: &Wow64Ntdll) -> Result<(), KernelError> {
    let file = volume_files::lookup_volume_file(NT_PATH).filter(|file| !file.directory());
    let name = file.as_ref().map_or_else(|| String::from(ntdll.notification.name()), |file| file.nt_path());
    let system = process::get_current_process();
    memory::insert_region(Space::current(), RegionKind::ProcessImages, Arc::new(ImageRegion { base: ntdll.image_base, size: ntdll.size_of_image, name, file, system }));
    Ok(())
}

/// A notificação de carga da ntdll de 32 bits no processo novo (o
/// corrente, anexado), como a da nativa.
pub fn notify_loaded(ntdll: &Wow64Ntdll, process_id: u64) -> Result<(), KernelError> {
    image_notify::notify(Image { image_base: ntdll.image_base, size_of_image: ntdll.size_of_image }, &NotifyOptions { name: Some(String::from(ntdll.notification.name())), source: Some(ntdll.notification.clone()), process_id: Some(process_id), ..NotifyOptions::default() })
}

/// Grava `value` num campo de uma página de imagem do processo corrente pela
/// tradução física: as páginas do .mrdata ficam sem escrita na PTE.
fn write_image_u64(va: u64, value: u64) -> Result<(), KernelError> {
    write_image_bytes(va, &value.to_le_bytes())
}

fn write_image_bytes(va: u64, bytes: &[u8]) -> Result<(), KernelError> {
    let root = Space::current().root();
    for (index, byte) in bytes.iter().enumerate() {
        let address = va + index as u64;
        let physical = paging::translate_in(root, address & !0xFFF);
        if physical == 0 {
            return Err(KernelError::new(alloc::format!("LdrSystemDllInitBlock sem pagina em {address:#x}")));
        }
        crate::hal::physical::write_bytes((physical & !0xFFF) + (address & 0xFFF), &[*byte]);
    }
    Ok(())
}

/// O PspPrepareSystemDllInitBlock de um tipo de DLL de sistema, no bloco em
/// `block` (a VA do LdrSystemDllInitBlock no processo corrente).
fn prepare_block(block: u64, native_relocation: u64, wow_relocation: u64, shared: &[u64; 16]) -> Result<(), KernelError> {
    // SAFETY: o export da imagem mapeada no processo corrente (anexado); a
    // leitura é do bloco que a imagem traz.
    let size = unsafe { PsSystemDllInitBlock::at(block) }.size.get();
    if size != INIT_BLOCK_SIZE {
        return Err(KernelError::with_status(alloc::format!("LdrSystemDllInitBlock com Size {size:#x}"), STATUS_REVISION_MISMATCH));
    }
    let offset = |field: usize| block + field as u64;
    write_image_u64(offset(core::mem::offset_of!(PsSystemDllInitBlock, system_dll_native_relocation)), native_relocation)?;
    write_image_u64(offset(core::mem::offset_of!(PsSystemDllInitBlock, system_dll_wow_relocation)), wow_relocation)?;
    for (index, value) in shared.iter().enumerate() {
        write_image_u64(offset(core::mem::offset_of!(PsSystemDllInitBlock, wow64_shared_information) + index * 8), *value)?;
    }
    write_image_bytes(offset(core::mem::offset_of!(PsSystemDllInitBlock, rng_data)), &super::random().to_le_bytes())?;
    write_image_bytes(offset(core::mem::offset_of!(PsSystemDllInitBlock, flags)), &0u32.to_le_bytes())
}

/// O PspPrepareSystemDllInitBlock de um processo WoW64 x86 (o corrente,
/// anexado): o bloco da ntdll nativa e o da ntdll de 32 bits.
pub fn prepare_init_blocks(ntdll: &Wow64Ntdll) -> Result<(), KernelError> {
    let (native_block, native_base) = state::with(|state| (state.ntdll_exports.as_ref().and_then(|exports| exports.get("LdrSystemDllInitBlock").copied()).unwrap_or(0), state.ntdll_image_base));
    if native_block == 0 {
        return Err(KernelError::new("ntdll nativa sem LdrSystemDllInitBlock"));
    }
    let native_preferred = crate::ntos::ps::user::loader::ntdll_preferred_base().unwrap_or(native_base);
    let native_relocation = native_base.wrapping_sub(native_preferred);
    let wow_relocation = ntdll.image_base.wrapping_sub(ntdll.preferred_base);
    prepare_block(native_block, native_relocation, wow_relocation, &ntdll.shared_information)?;
    // O bloco da ntdll de 32 bits (o tipo PsWowX86SystemDll, achado pelo
    // SharedInformation[LdrSystemDllInitBlock]).
    prepare_block(ntdll.shared_information[SHARED_LDR_SYSTEM_DLL_INIT_BLOCK], native_relocation, wow_relocation, &ntdll.shared_information)
}

/// Uma cópia das páginas de uma faixa de sistema (o NLS ou o apiset) num
/// endereço que o código de 32 bits alcança: uma região do processo
/// corrente abaixo do HighestUserAddress dele, com os mesmos bytes, só de
/// leitura. Devolve (base da faixa original, base da cópia). É o efeito das
/// vistas que o MmCreatePeb e o MmMapApiSetView mapeiam num processo WoW64,
/// sempre abaixo do limite de 32 bits.
pub fn map_low_copy(pages: &[TemplatePage]) -> Result<(u64, u64), KernelError> {
    let (Some(first), Some(last)) = (pages.first(), pages.last()) else { return Err(KernelError::new("faixa de sistema vazia")) };
    let (base, end) = (first.va, last.va + 0x1000);
    let copy = memory::map_user_region(end - base)?;
    for page in pages {
        guest::write_bytes(copy + (page.va - base), &crate::hal::physical::read_bytes(page.frame, 0x1000));
    }
    let cells = guest::alloc_bytes(0x18);
    if cells != 0 {
        guest::write64(cells, copy);
        guest::write64(cells + 8, end - base);
        // PAGE_READONLY, como as vistas de seção do NLS e do apiset.
        let _ = memory::protect_in(Space::current(), cells, cells + 8, 2, cells + 0x10, false);
        guest::free_bytes(cells);
    }
    Ok((base, copy))
}
