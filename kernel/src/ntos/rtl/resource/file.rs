//! Arquivo de recursos (MUI/MUN).
//!
//! Um FILE_OBJECT aberto e uma vista global da SECTION, pelos mesmos
//! caminhos de ZwCreateFile/ZwCreateSection; as referências vivem enquanto o
//! cache publicar ponteiros para os bytes.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::rtl::resource::tree::{self as resource_tree, Image};
use crate::ntos::mm::section::{create as create_section, map_system_view, handles as section_handles};
use crate::ntos::ob::close;
use crate::ntos::ps::user::sections::{self, View};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::inc::types::{Field, ImageOptionalHeader64, IoStatusBlock, NtStruct, ObjectAttributes, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::io::file::zw as zw_files;

/// Parâmetros do ZwCreateFile/ZwCreateSection montados num bloco alocado
/// (layout do OpenNT; as estruturas do NT dentro dele são as reais). O nome
/// do arquivo segue o bloco.
#[repr(C)]
struct OpenParameters {
    file_attributes: ObjectAttributes,
    file_name: UnicodeString,
    file_handle: Field<u64>,
    section_handle: Field<u64>,
    io_status: IoStatusBlock,
    section_attributes: ObjectAttributes,
    _reserved_90: [Field<u64>; 2],
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for OpenParameters {}

const _: () = assert!(core::mem::size_of::<OpenParameters>() == 0xA0);

/// OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE.
const OPEN_ATTRIBUTES: u32 = 0x240;

/// Handles e vista retidos por um arquivo publicado.
pub struct Owner {
    state: SpinLock<OwnerState>,
}

#[derive(Default)]
struct OwnerState {
    file_handle: u64,
    section_handle: u64,
    view: Option<Arc<View>>,
}

/// Arquivo aberto: a vista e o dono que a solta.
#[derive(Clone)]
pub struct Opened {
    pub base: u64,
    pub size: u64,
    pub owner: Arc<Owner>,
}

impl Opened {
    pub fn release(&self) -> Result<(), KernelError> {
        release(&self.owner)
    }
}

/// Se o Mm recusar a retirada, o dono continua rastreável e a próxima
/// operação tenta concluí-la antes de adquirir mais vistas.
static PENDING: SpinLock<Vec<Arc<Owner>>> = SpinLock::new(Vec::new());

fn release(owner: &Arc<Owner>) -> Result<(), KernelError> {
    {
        let mut pending = PENDING.lock();
        if !pending.iter().any(|candidate| Arc::ptr_eq(candidate, owner)) {
            pending.push(owner.clone());
        }
    }
    let view = owner.state.lock().view.take();
    if let Some(view) = view {
        sections::unmap(&view, None)?;
    }
    let section_handle = owner.state.lock().section_handle;
    if section_handle != 0 {
        let status = close::close(section_handle, Some(0))?;
        if status != 0 {
            return Err(KernelError::with_status("resource SECTION close failed", status));
        }
        owner.state.lock().section_handle = 0;
    }
    let file_handle = owner.state.lock().file_handle;
    if file_handle != 0 {
        let status = close::close(file_handle, Some(0))?;
        if status != 0 {
            return Err(KernelError::with_status("resource file close failed", status));
        }
        owner.state.lock().file_handle = 0;
    }
    PENDING.lock().retain(|candidate| !Arc::ptr_eq(candidate, owner));
    Ok(())
}

pub fn drain_releases() -> Result<(), KernelError> {
    let owners: Vec<Arc<Owner>> = PENDING.lock().clone();
    for owner in owners {
        release(&owner)?;
    }
    Ok(())
}

/// Abre o arquivo pelo namespace (SystemRoot e o volume montado), cria a
/// SECTION com a proteção decidida pelo subsistema da imagem dona e mapeia
/// a vista global.
pub fn open(path: &str, primary: &Image) -> Result<Result<Opened, u32>, KernelError> {
    drain_releases()?;
    let units: Vec<u16> = path.encode_utf16().collect();
    let scratch = guest::alloc_bytes(OpenParameters::SIZE + (units.len() as u64 + 1) * 2);
    if scratch == 0 {
        return Ok(Err(0xC000_009A));
    }
    let name_buffer = scratch + OpenParameters::SIZE;
    let owner = Arc::new(Owner { state: SpinLock::new(OwnerState::default()) });
    let mut published = false;
    let result = (|| -> Result<Result<Opened, u32>, KernelError> {
        // OBJECT_ATTRIBUTES/UNICODE_STRING com os tamanhos AMD64 reais.
        guest::write_bytes(scratch, &[0; core::mem::size_of::<OpenParameters>()]);
        // SAFETY: bloco recém-alocado e zerado acima.
        let parameters = unsafe { OpenParameters::at(scratch) };
        parameters.file_attributes.length.set(ObjectAttributes::SIZE as u32);
        parameters.file_attributes.object_name.set(parameters.file_name.address());
        parameters.file_attributes.attributes.set(OPEN_ATTRIBUTES);
        parameters.file_name.length.set(units.len() as u16 * 2);
        parameters.file_name.maximum_length.set((units.len() as u16 + 1) * 2);
        parameters.file_name.buffer.set(name_buffer);
        guest::write_bytes(name_buffer, &crate::ntos::rtl::guest_strings::wide_bytes_with_nul(path));
        let status = zw_files::create_kernel_file(parameters.file_handle.address(), 0x8000_0000, parameters.file_attributes.address(), parameters.io_status.address(), 5, 1, 0)?;
        if status != 0 {
            return Ok(Err(status));
        }
        owner.state.lock().file_handle = parameters.file_handle.get();
        parameters.section_attributes.length.set(ObjectAttributes::SIZE as u32);
        parameters.section_attributes.attributes.set(OPEN_ATTRIBUTES);
        // WRITECOPY para imagens anteriores à versão 6 do subsistema, senão
        // READONLY; nenhum desses mapeamentos executa o arquivo.
        let subsystem_version = guest::read::<u16>(primary.base.wrapping_add(primary.optional_header as u64 + core::mem::offset_of!(ImageOptionalHeader64, major_subsystem_version) as u64));
        let file_handle = owner.state.lock().file_handle;
        let status = create_section::create(parameters.section_handle.address(), 0xF_0005, parameters.section_attributes.address(), 0, if subsystem_version < 6 { 8 } else { 2 }, 0x0800_0000, file_handle, 0, None)?;
        if status != 0 {
            return Ok(Err(status));
        }
        let section_handle = parameters.section_handle.get();
        owner.state.lock().section_handle = section_handle;
        let reference = section_handles::reference(section_handle, section_handles::Kind::Section, 0, 0).map_err(|_| KernelError::new("created resource SECTION has no owner"))?;
        let section = reference.section.clone();
        reference.release()?;
        let Some(section) = section else { return Err(KernelError::new("created resource SECTION has no owner")) };
        let view = match map_system_view::insert(&section, section.size, 0, 0)? {
            Ok(view) => view,
            Err(status) => return Ok(Err(status)),
        };
        let (base, size) = (view.base, view.size);
        owner.state.lock().view = Some(view);
        let status = close::close(section_handle, Some(0))?;
        if status != 0 {
            return Err(KernelError::with_status("resource SECTION close failed", status));
        }
        owner.state.lock().section_handle = 0;
        if let Err(status) = resource_tree::inspect_header(base, size as u128, true, false)? {
            return Ok(Err(status));
        }
        published = true;
        Ok(Ok(Opened { base, size, owner: owner.clone() }))
    })();
    guest::free_bytes(scratch);
    if !published {
        release(&owner)?;
    }
    result
}
