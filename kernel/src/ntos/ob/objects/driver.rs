//! Vida de DRIVER_OBJECT.
//!
//! Independe dos dispositivos. A retirada do nome impede novas aberturas; o
//! corpo vive até o fim dos handles e referências existentes.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use crate::ntos::ob::object_manager::{self, NodeId, ObjectData, ObjectHooks};
use crate::ntos::ob::object_types::{self, ObjectType};
use crate::ntos::ob::open_pointer::{self, ObjectOwner, Slot};
use crate::ntos::ob::object_access;
use crate::ntos::se::model::SecurityPolicy;
use crate::rtl::{KernelError, SpinLock};

struct Record {
    node: NodeId,
    references: u32,
    retired: bool,
    destroy: fn(u64),
    security: SecurityPolicy,
}

static DRIVERS: SpinLock<BTreeMap<u64, Record>> = SpinLock::new(BTreeMap::new());

struct DriverHandle {
    pointer: u64,
}

impl ObjectHooks for DriverHandle {
    fn on_handle_open(&self) -> Result<(), KernelError> {
        reference(self.pointer);
        object_types::account("Driver", 0, 1)
    }
    fn on_handle_close(&self) {
        let _ = object_types::account("Driver", 0, -1);
        let _ = dereference(self.pointer);
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

struct DriverOwner;

static OWNER: DriverOwner = DriverOwner;

impl ObjectOwner for DriverOwner {
    fn object_type(&self, _pointer: u64) -> ObjectType {
        object_types::driver_type()
    }
    fn reference(&self, pointer: u64) {
        reference(pointer);
    }
    fn dereference(&self, pointer: u64) {
        let _ = dereference(pointer);
    }
    fn query_record(&self, pointer: u64) -> crate::ntos::ob::open_pointer::QueryRecord {
        let Some((node, references)) = DRIVERS.lock().get(&pointer).map(|record| (record.node, record.references)) else { return crate::ntos::ob::open_pointer::QueryRecord::default() };
        crate::ntos::ob::open_pointer::QueryRecord { handles: None, references, permanent: false, name: object_manager::path_of(node).unwrap_or_default() }
    }
    fn security(&self, pointer: u64) -> SecurityPolicy {
        DRIVERS.lock().get(&pointer).map(|record| record.security.clone()).unwrap_or_default()
    }
    fn data(&self, pointer: u64) -> ObjectData {
        ObjectData::pointer(pointer)
    }
}

/// Captura a segurança e liga os ganchos de handle ao nó do namespace (cujo
/// `native_pointer` é o DRIVER_OBJECT).
pub fn register(node: NodeId, destroy: fn(u64)) -> Result<u64, KernelError> {
    let pointer = object_manager::node(node).and_then(|node| node.data).map_or(0, |data| data.native_pointer);
    if pointer == 0 {
        return Err(KernelError::new("driver node has no DRIVER_OBJECT"));
    }
    if DRIVERS.lock().contains_key(&pointer) {
        return Err(KernelError::new("duplicate driver object"));
    }
    let object_type = object_types::driver_type();
    let security = object_access::capture(object_access::subject());
    DRIVERS.lock().insert(pointer, Record { node, references: 0, retired: false, destroy, security });
    object_types::account(&object_type.name, 1, 0)?;
    object_manager::update_node(node, |node| {
        if let Some(data) = node.data.as_mut() {
            data.hooks = Some(Arc::new(DriverHandle { pointer }));
        }
    });
    open_pointer::register_owner(Slot::Driver, is_driver, &OWNER);
    Ok(pointer)
}

/// A destruição só ocorre depois da retirada e sem referências.
fn collect(pointer: u64) {
    let destroy = {
        let mut drivers = DRIVERS.lock();
        let Some(record) = drivers.get(&pointer) else { return };
        if !record.retired || record.references != 0 {
            return;
        }
        drivers.remove(&pointer).map(|record| record.destroy)
    };
    if let Some(destroy) = destroy {
        let _ = object_types::account("Driver", -1, 0);
        destroy(pointer);
    }
}

pub fn reference(pointer: u64) -> Option<u32> {
    let mut drivers = DRIVERS.lock();
    let record = drivers.get_mut(&pointer)?;
    record.references += 1;
    Some(record.references)
}

pub fn dereference(pointer: u64) -> Result<Option<u32>, KernelError> {
    let count = {
        let mut drivers = DRIVERS.lock();
        let Some(record) = drivers.get_mut(&pointer) else { return Ok(None) };
        if record.references == 0 {
            return Err(KernelError::new("driver object reference underflow"));
        }
        record.references -= 1;
        record.references
    };
    collect(pointer);
    Ok(Some(count))
}

/// Impede novas aberturas; uma segunda retirada é erro de ciclo de vida.
pub fn retire(pointer: u64) -> Result<(), KernelError> {
    {
        let mut drivers = DRIVERS.lock();
        let Some(record) = drivers.get_mut(&pointer).filter(|record| !record.retired) else {
            return Err(KernelError::new("driver object already retired"));
        };
        record.retired = true;
    }
    collect(pointer);
    Ok(())
}

/// Genéricos e MAXIMUM_ALLOWED pelo OBJECT_TYPE; `None` para bits recusados.
pub fn access(requested: u32) -> Option<u32> {
    let object_type = object_types::driver_type();
    let mut mapped = requested;
    for (index, &value) in object_type.mapping.iter().enumerate() {
        if mapped & (0x8000_0000 >> index) != 0 {
            mapped |= value;
        }
    }
    mapped &= 0x0FFF_FFFF;
    if mapped & 0x0200_0000 != 0 {
        mapped = (mapped & !0x0200_0000) | object_type.valid_access;
    }
    if mapped & !object_type.valid_access != 0 { None } else { Some(mapped) }
}

/// Handle com os direitos mapeados; OBJ_KERNEL_HANDLE define a codificação.
pub fn open_handle(pointer: u64, requested: u32, attributes: u32) -> Result<u64, KernelError> {
    let Some(node) = DRIVERS.lock().get(&pointer).filter(|record| !record.retired).map(|record| record.node) else { return Ok(0) };
    let Some(granted) = access(requested) else { return Ok(0) };
    let name = object_manager::name_of(node).unwrap_or_default();
    let data = ObjectData { native_pointer: pointer, access: Some(granted), attributes, hooks: Some(Arc::new(DriverHandle { pointer })), ..ObjectData::default() };
    let handle = object_manager::new_node(&name, "Driver", Some(data));
    let identifier = object_manager::open_object(handle, None)?;
    Ok(if attributes & 0x200 != 0 { 0xFFFF_FFFF_8000_0000 | identifier as u64 } else { identifier as u64 })
}

pub fn is_driver(pointer: u64) -> bool {
    DRIVERS.lock().contains_key(&pointer)
}

pub fn reference_count(pointer: u64) -> Option<u32> {
    DRIVERS.lock().get(&pointer).map(|record| record.references)
}
