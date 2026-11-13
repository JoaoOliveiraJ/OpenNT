//! Stores WNF na hive.
//!
//! Abre as raízes e os stores permanentes pelo Configuration Manager. Os
//! slots de cache pertencem ao namespace: o chamador seleciona o silo,
//! mantém o dono vivo e fecha os handles na desmontagem.

use alloc::string::String;
use core::sync::atomic::Ordering;
use alloc::vec::Vec;

use crate::ntos::ex::pool_allocation;
use crate::ntos::ex::wnf::definition::{self as wnf_definition, Definition};
use crate::ntos::cm::key::services as key_services;
use crate::ntos::cm::state_separation;
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ob::close;
use crate::ntos::ps::previous_mode;
use crate::ntos::se::sid;
use super::objects::scope_at;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{ObjectAttributes, Sid, UnicodeString};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

/// Moldura de pool do ZwCreateKey: atributos, o caminho, o handle e a
/// disposição devolvidos; o texto (quando não vem de fora) segue a moldura.
#[repr(C)]
struct CreateKeyFrame {
    attributes: ObjectAttributes,
    path: UnicodeString,
    handle: Field<u64>,
    disposition: Field<u32>,
    _pad_4c: Reserved<0x4>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for CreateKeyFrame {}

const _: () = {
    assert!(core::mem::size_of::<CreateKeyFrame>() == 80);
    assert!(core::mem::offset_of!(CreateKeyFrame, path) == 48);
    assert!(core::mem::offset_of!(CreateKeyFrame, handle) == 64);
    assert!(core::mem::offset_of!(CreateKeyFrame, disposition) == 72);
};

/// Uma célula de handle (raiz de definições ou armazém permanente).
fn slot_at(slot: u64) -> &'static Field<u64> {
    // SAFETY: slots do host, do SILO_GLOBALS ou da instância de escopo.
    unsafe { Field::<u64>::at(slot) }
}

const STORE_TAG: u32 = 0x2066_6E57;
const FRAME_TAG: u32 = 0x7266_6E57;
pub const DEFINITION_ROOTS: [&str; 3] = [
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Notifications",
    "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Notifications",
    "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\VolatileNotifications",
];

/// Chave aberta: status informativo, handle e disposição.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opened {
    pub status: u32,
    pub handle: u64,
    pub disposition: u32,
}

type Outcome<T> = Result<Result<T, u32>, KernelError>;

/// ZwCreateKey com estruturas privadas no lugar dos temporários de pilha;
/// a alocação extra pode devolver NO_MEMORY e os erros do CM são mantidos.
#[allow(clippy::too_many_arguments)]
fn create_key(path: &str, root: u64, access: u32, options: u32, disposition_required: bool, path_buffer: u64, path_capacity: u32) -> Outcome<Opened> {
    let units: Vec<u16> = path.encode_utf16().collect();
    let size = CreateKeyFrame::SIZE + if path_buffer != 0 { 0 } else { 2 + units.len() as u64 * 2 };
    let Ok(frame) = kernel_pool::allocate(size, AllocateOptions { zero: true, tag: FRAME_TAG, ..Default::default() }) else { return Ok(Err(0xC000_0017)) };
    // SAFETY: alocação nova da moldura (mais o texto).
    let key = unsafe { CreateKeyFrame::at(frame) };
    let text = if path_buffer != 0 { path_buffer } else { frame + CreateKeyFrame::SIZE };
    key.attributes.length.set(ObjectAttributes::SIZE as u32);
    key.attributes.root_directory.set(root);
    key.attributes.object_name.set(key.path.address());
    key.attributes.attributes.set(0x240);
    key.path.length.set(units.len() as u16 * 2);
    key.path.maximum_length.set(if path_capacity != 0 { path_capacity as u16 } else { units.len() as u16 * 2 + 2 });
    key.path.buffer.set(text);
    let bytes: Vec<u8> = units.iter().chain(core::iter::once(&0)).flat_map(|unit| unit.to_le_bytes()).collect();
    guest::write_bytes(text, &bytes);
    let created = previous_mode::with_kernel(|| key_services::create(key.handle.address(), access, key.attributes.address(), 0, 0, options, if disposition_required { key.disposition.address() } else { 0 }, false));
    let result = match created {
        Ok(Ok(status)) if status & 0x8000_0000 != 0 => Ok(Err(status)),
        Ok(Ok(status)) => Ok(Ok(Opened { status, handle: key.handle.get(), disposition: key.disposition.get() })),
        Ok(Err(error)) | Err(error) => Err(error),
    };
    let _ = kernel_pool::free(frame, Some(FRAME_TAG));
    result
}

/// O slot possui o handle vencedor; o perdedor fecha só o seu.
fn publish_cached_handle(slot: u64, handle: u64) -> Outcome<Opened> {
    let cell = slot_at(slot);
    if cell.atomic().compare_exchange(0, handle, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        let _ = previous_mode::with_kernel(|| close::close(handle, Some(0)));
    }
    Ok(Ok(Opened { status: 0, handle: cell.get(), disposition: 0 }))
}

/// Raiz de definições do tempo de vida. Sem provedor de separação de
/// estado, a abertura real abaixo precisa funcionar.
pub fn get_definition_store(lifetime: u32, slot: u64) -> Outcome<Opened> {
    if lifetime > 2 {
        return Err(KernelError::new("WNF temporary names do not have a definition store"));
    }
    let cached = slot_at(slot).get();
    if cached != 0 {
        return Ok(Ok(Opened { status: 0, handle: cached, disposition: 0 }));
    }
    state_separation::require_supported_boot()?;
    let opened = match create_key(DEFINITION_ROOTS[lifetime as usize], 0, if lifetime == 0 { 0x20019 } else { 0xF003F }, if lifetime == 2 { 1 } else { 0 }, true, 0, 0)? {
        Ok(opened) => opened,
        Err(status) => return Ok(Err(status)),
    };
    publish_cached_handle(slot, opened.handle)
}

/// `\Registry\User\<SID>_Classes\NotificationData`. A capacidade calculada
/// pelo original pode igualar o texto máximo e dar BUFFER_OVERFLOW.
fn open_permanent_user_store(identifier: u64) -> Outcome<Opened> {
    if !sid::valid(identifier) {
        return Ok(Err(0xC000_0078));
    }
    // SAFETY: SID validado acima (cópia de kernel da identidade do escopo).
    let sid_object = unsafe { Sid::at(identifier) };
    let authority = &sid_object.identifier_authority.value;
    let count = sid_object.sub_authority_count.get() as u32;
    let hexadecimal = authority[0].get() != 0 || authority[1].get() != 0;
    let capacity = (if hexadecimal { 36 } else { 28 }) + count * 22;
    let Ok(path_buffer) = pool_allocation::allocate_tagged(1, capacity as u64 + 82, STORE_TAG) else { return Ok(Err(0xC000_009A)) };
    let result = (|| {
        if sid_object.revision.get() != 1 {
            return Ok(Err(0xC000_0078));
        }
        let authority = authority.iter().fold(0u64, |value, byte| value << 8 | byte.get() as u64);
        let mut text = if hexadecimal { alloc::format!("S-1-0x{authority:X}") } else { alloc::format!("S-1-{authority}") };
        // SAFETY: SubAuthorityCount entradas seguem o cabeçalho do SID validado.
        let sub_authorities = unsafe { Field::<u32>::array_at(sid_object.sub_authority.as_ptr() as u64, count as usize) };
        for sub_authority in sub_authorities {
            text.push_str(&alloc::format!("-{}", sub_authority.get()));
        }
        if text.len() as u32 * 2 >= capacity {
            return Ok(Err(0x8000_0005));
        }
        let path = String::from("\\Registry\\User\\") + &text + "_Classes\\NotificationData";
        create_key(&path, 0, 0xF003F, 0, false, path_buffer, capacity + 82)
    })();
    let _ = kernel_pool::free(path_buffer, Some(STORE_TAG));
    result
}

/// O modo create muda o erro das combinações sem store; as suportadas usam
/// ZwCreateKey mesmo com create zero.
pub fn open_permanent_store(scope: u32, lifetime: u32, identity: u64, volatile: u32, create: u32, definition_slot: u64) -> Outcome<Opened> {
    if volatile != 0 || (scope != 0 && scope != 2 && scope != 4) || (scope == 2 && lifetime != 0) {
        return Ok(Err(if create != 0 { 0xC000_0002 } else { 0xC000_0034 }));
    }
    if scope == 2 {
        return open_permanent_user_store(identity);
    }
    let root = match get_definition_store(1, definition_slot)? {
        Ok(root) => root,
        Err(status) => return Ok(Err(status)),
    };
    match create_key("Data", root.handle, 0xF003F, 0, false, 0, 0)? {
        Ok(opened) => Ok(Ok(Opened { status: 0, handle: opened.handle, disposition: 0 })),
        Err(status) => Ok(Err(status)),
    }
}

/// WNF_SCOPE_INSTANCE guarda os caches estável/volátil em +0x40/+0x48; um
/// cache existente precede a validação da abertura.
pub fn get_permanent_store(scope_instance: u64, lifetime: u32, create: u32, definition_slot: u64) -> Outcome<Opened> {
    let volatile = if lifetime.wrapping_sub(2) <= 1 { 1 } else { 0 };
    let instance = scope_at(scope_instance);
    let slot = if volatile != 0 { instance.volatile_permanent_data_store.address() } else { instance.permanent_data_store.address() };
    let cached = slot_at(slot).get();
    if cached != 0 {
        return Ok(Ok(Opened { status: 0, handle: cached, disposition: 0 }));
    }
    let opened = match open_permanent_store(instance.data_scope.get().0 as u32, lifetime, instance.instance_id_data.get(), volatile, create, definition_slot)? {
        Ok(opened) => opened,
        Err(status) => return Ok(Err(status)),
    };
    publish_cached_handle(slot, opened.handle)
}

/// Abre o store do tempo de vida e lê a definição já validada.
pub fn lookup_definition(decoded_name: u64, slot: u64) -> Outcome<Definition> {
    let lifetime = ((decoded_name >> 4) & 3) as u32;
    match get_definition_store(lifetime, slot)? {
        Ok(store) => wnf_definition::read(decoded_name, store.handle),
        Err(status) => Ok(Err(status)),
    }
}
