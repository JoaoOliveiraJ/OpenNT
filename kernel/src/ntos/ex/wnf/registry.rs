//! Stores WNF na hive.
//!
//! Abre as raízes e os stores permanentes pelo Configuration Manager. Os
//! slots de cache pertencem ao namespace: o chamador seleciona o silo,
//! mantém o dono vivo e fecha os handles na desmontagem.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::ex::pool_allocation;
use crate::ntos::ex::wnf::definition::{self as wnf_definition, Definition};
use crate::ntos::cm::key::services as key_services;
use crate::ntos::cm::state_separation;
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ob::close;
use crate::ntos::ps::previous_mode;
use crate::ntos::se::sid;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

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
    let size = if path_buffer != 0 { 80 } else { 82 + units.len() as u64 * 2 };
    let Ok(frame) = kernel_pool::allocate(size, AllocateOptions { zero: true, tag: FRAME_TAG, ..Default::default() }) else { return Ok(Err(0xC000_0017)) };
    let text = if path_buffer != 0 { path_buffer } else { frame + 80 };
    guest::write32(frame, 48);
    guest::write64(frame + 8, root);
    guest::write64(frame + 16, frame + 48);
    guest::write32(frame + 24, 0x240);
    guest::write16(frame + 48, units.len() as u16 * 2);
    guest::write16(frame + 50, if path_capacity != 0 { path_capacity as u16 } else { units.len() as u16 * 2 + 2 });
    guest::write64(frame + 56, text);
    for (index, unit) in units.iter().enumerate() {
        guest::write16(text + index as u64 * 2, *unit);
    }
    guest::write16(text + units.len() as u64 * 2, 0);
    let created = previous_mode::with_kernel(|| key_services::create(frame + 64, access, frame, 0, 0, options, if disposition_required { frame + 72 } else { 0 }, false));
    let result = match created {
        Ok(Ok(status)) if status & 0x8000_0000 != 0 => Ok(Err(status)),
        Ok(Ok(status)) => Ok(Ok(Opened { status, handle: guest::read64(frame + 64), disposition: guest::read32(frame + 72) })),
        Ok(Err(error)) | Err(error) => Err(error),
    };
    let _ = kernel_pool::free(frame, Some(FRAME_TAG));
    result
}

/// O slot possui o handle vencedor; o perdedor fecha só o seu.
fn publish_cached_handle(slot: u64, handle: u64) -> Outcome<Opened> {
    let previous = guest::compare_exchange64(slot, 0, handle)?;
    if previous != 0 {
        let _ = previous_mode::with_kernel(|| close::close(handle, Some(0)));
    }
    Ok(Ok(Opened { status: 0, handle: guest::read64(slot), disposition: 0 }))
}

/// Raiz de definições do tempo de vida. Sem provedor de separação de
/// estado, a abertura real abaixo precisa funcionar.
pub fn get_definition_store(lifetime: u32, slot: u64) -> Outcome<Opened> {
    if lifetime > 2 {
        return Err(KernelError::new("WNF temporary names do not have a definition store"));
    }
    let cached = guest::read64(slot);
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
    let count = guest::read8(identifier + 1) as u32;
    let hexadecimal = guest::read8(identifier + 2) != 0 || guest::read8(identifier + 3) != 0;
    let capacity = (if hexadecimal { 36 } else { 28 }) + count * 22;
    let Ok(path_buffer) = pool_allocation::allocate_tagged(1, capacity as u64 + 82, STORE_TAG) else { return Ok(Err(0xC000_009A)) };
    let result = (|| {
        if guest::read8(identifier) != 1 {
            return Ok(Err(0xC000_0078));
        }
        let authority = (0..6).fold(0u64, |value, index| value << 8 | guest::read8(identifier + 2 + index) as u64);
        let mut text = if hexadecimal { alloc::format!("S-1-0x{authority:X}") } else { alloc::format!("S-1-{authority}") };
        for index in 0..count as u64 {
            text.push_str(&alloc::format!("-{}", guest::read32(identifier + 8 + index * 4)));
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
    let slot = scope_instance + 0x40 + volatile as u64 * 8;
    let cached = guest::read64(slot);
    if cached != 0 {
        return Ok(Ok(Opened { status: 0, handle: cached, disposition: 0 }));
    }
    let opened = match open_permanent_store(guest::read32(scope_instance + 0x10), lifetime, guest::read64(scope_instance + 0x18), volatile, create, definition_slot)? {
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
