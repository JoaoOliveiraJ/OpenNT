//! Descritores de segurança dos DEVICE_OBJECTs e DRIVER_OBJECTs.
//!
//! O IoCreateDevice do ntoskrnl 19041 monta o descritor padrão do
//! dispositivo (IopCreateDefaultDeviceSecurityDescriptor) e o ObInsertObject
//! atribui o descritor final sobre ele (SeAssignSecurity com o token de quem
//! cria: owner e group do token, a DACL explícita com o mapeamento genérico
//! do tipo Device). O DRIVER_OBJECT do IopLoadDriver entra em \Driver sem
//! descritor explícito e recebe a DACL padrão do token. Os dois objetos do
//! OpenNT não têm OBJECT_HEADER, então o descritor fica na tabela lateral do
//! Ob, de onde o ObGetObjectSecurity o devolve (o ndis.sys acrescenta ACEs
//! ao descritor do seu DRIVER_OBJECT e dos seus dispositivos). Todo
//! DEVICE_OBJECT registrado recebe o descritor padrão: os PDOs que o OpenNT
//! monta para os barramentos e o IoReportDetectedDevice saem do IoCreateDevice
//! no NT (o volmgr.sys troca a DACL do seu PDO relatado).
//!
//! Modelos do IopCreateDefaultDeviceSecurityDescriptor, pelo DeviceType:
//! - CD-ROM (2) e disco (7) com FILE_REMOVABLE_MEDIA: a
//!   SePublicDefaultUnrestrictedDacl mais uma ACE de INTERACTIVE com
//!   GENERIC_READ|GENERIC_WRITE|DELETE (produto NtProductWinNt);
//! - os sistemas de arquivos (3, 8, 9), disco (7), rede (0x12, 0x14, 0x20),
//!   disco virtual (0x24) e os tipos 0x2D e 0x35: a
//!   SePublicDefaultUnrestrictedDacl;
//! - os demais: a SePublicOpenUnrestrictedDacl com uma SACL de rótulo Low
//!   (NO_WRITE_UP).

use alloc::collections::BTreeMap;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{object_security, object_types};
use crate::ntos::se::inherit_descriptor::Captured;
use crate::ntos::se::model::{sid, Ace, SecurityPolicy};
use crate::ntos::se::{assign, policy_descriptor, system_dacls};
use crate::rtl::SpinLock;

const FILE_DEVICE_CD_ROM: u32 = 2;
const FILE_DEVICE_DISK: u32 = 7;
const FILE_REMOVABLE_MEDIA: u32 = 1;
/// GENERIC_READ | GENERIC_WRITE | DELETE da ACE de INTERACTIVE.
const INTERACTIVE_REMOVABLE_ACCESS: u32 = 0xC001_0000;
/// SECURITY_MANDATORY_LOW_RID: o rótulo NO_WRITE_UP dos dispositivos abertos.
const LOW_MANDATORY_LEVEL: u32 = 0x1000;

/// Descritores atribuídos aqui, por objeto (só estes voltam ao pool).
static ASSIGNED: SpinLock<BTreeMap<u64, u64>> = SpinLock::new(BTreeMap::new());

/// IopCreateDefaultDeviceSecurityDescriptor: os componentes do descritor
/// padrão (sem owner nem group).
pub fn default_descriptor(device_type: u32, characteristics: u32) -> Captured {
    let removable = device_type == FILE_DEVICE_CD_ROM || (device_type == FILE_DEVICE_DISK && characteristics & FILE_REMOVABLE_MEDIA != 0);
    let unrestricted = matches!(device_type, 3 | 7 | 8 | 9 | 0x12 | 0x14 | 0x20 | 0x24 | 0x2D | 0x35);
    let policy = if removable {
        let mut dacl = system_dacls::public_default_unrestricted();
        dacl.push(Ace::allow(sid(5, &[4]), INTERACTIVE_REMOVABLE_ACCESS));
        SecurityPolicy { dacl: Some(dacl), ..SecurityPolicy::default() }
    } else if unrestricted {
        SecurityPolicy { dacl: Some(system_dacls::public_default_unrestricted()), ..SecurityPolicy::default() }
    } else {
        SecurityPolicy { dacl: Some(system_dacls::public_open_unrestricted()), integrity: Some(LOW_MANDATORY_LEVEL), ..SecurityPolicy::default() }
    };
    let encoded = policy_descriptor::capture(&policy).unwrap_or_default();
    Captured { control: encoded.control, owner: alloc::vec::Vec::new(), group: alloc::vec::Vec::new(), dacl: encoded.dacl, sacl: encoded.sacl }
}

fn publish(object: u64, explicit: Option<&Captured>, mapping: &[u32; 4]) {
    if let Ok(descriptor) = assign::assign_components(None, explicit, mapping, false, 0, 0) {
        let pointer = assign::publish_descriptor(&descriptor);
        object_security::set_security_object_by_pointer(object, pointer);
        ASSIGNED.lock().insert(object, pointer);
    }
}

/// O descritor que o IoCreateDevice + ObInsertObject dão ao dispositivo.
pub fn assign_device(device: u64, device_type: u32, characteristics: u32) {
    publish(device, Some(&default_descriptor(device_type, characteristics)), &object_types::device_type().mapping);
}

/// O descritor do DRIVER_OBJECT inserido em \Driver sem descritor explícito.
pub fn assign_driver(driver: u64) {
    publish(driver, None, &object_types::driver_type().mapping);
}

/// Destruição do objeto: o descritor sai da tabela lateral com ele, e o
/// atribuído aqui volta ao pool se ainda é o do objeto.
pub fn release(object: u64) {
    let assigned = ASSIGNED.lock().remove(&object);
    let current = object_security::forget_security(object);
    if let Some(pointer) = assigned.filter(|&pointer| current == Some(pointer)) {
        guest::free_bytes(pointer);
    }
}
