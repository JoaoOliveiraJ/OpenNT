//! Mapas de devices DOS (DEVICE_MAP): o `\??` de cada processo e de cada
//! sessão de logon, como no ntoskrnl 19041.
//!
//! Um DEVICE_MAP (0x48 bytes de PagedPool, 'ObDm') liga um diretório de
//! devices DOS (DosDevicesDirectory, retido, com um handle de kernel em
//! DosDevicesDirectoryHandle) ao OBJECT_DIRECTORY.DeviceMap dele; o
//! GlobalDosDevicesDirectory aponta o `\GLOBAL??` nos mapas que não são o do
//! sistema. O estado do silo hospedeiro (ObSiloState.SystemDeviceMap e o
//! DeviceMapLock) fica em [`MAPS`]; o OpenNT não cria silos de servidor, e
//! o ServerSilo dos mapas é sempre NULL.
//!
//! - ObpSetDeviceMap (rva 0x6a04e4): referencia o diretório pelo handle
//!   (DIRECTORY_TRAVERSE, no modo pedido); sem a Flag 4, um diretório com
//!   sombra (Flags & 4) dá STATUS_INVALID_PARAMETER. O mapa novo nasce com
//!   ReferenceCount 1 e o handle do ObOpenObjectByPointer (OBJ_KERNEL_HANDLE,
//!   DIRECTORY_ALL_ACCESS); sob o DeviceMapLock, um diretório que já tem mapa
//!   devolve esse (mais uma referência) e o novo é desfeito; senão a Flag 1
//!   o torna o SystemDeviceMap, o diretório passa a apontá-lo e a Flag 2 liga
//!   o GlobalDosDevicesDirectory ao diretório do SystemDeviceMap quando é
//!   outro. Com processo, o mapa troca o EPROCESS.DeviceMap e o anterior é
//!   solto.
//! - ObpSetSiloDeviceMap (rva 0x7a137c): o `\GLOBAL??` com o System
//!   (PsInitialSystemProcess) e as Flags 3, no fim do
//!   ObpCreateDosDevicesDirectory ([`initialize`]).
//! - ObfDereferenceDeviceMap (rva 0x625954): a última referência, sob o
//!   DeviceMapLock, zera o DeviceMap do diretório; depois o ZwClose do handle,
//!   a referência do diretório e o pool.
//! - ObDereferenceDeviceMap (rva 0x693ad4): o PspProcessDelete e o
//!   PspAssignPrimaryToken tiram o mapa do EPROCESS e o soltam.
//! - ObSetCurrentProcessDeviceMap (rva 0x676fe8): o token primário do
//!   processo corrente (STATUS_NO_TOKEN sem ele) escolhe o mapa: o
//!   SystemDeviceMap para o LogonId do SYSTEM (0x3E7), senão o da sessão de
//!   logon (SeGetTokenDeviceMap, `se/logon_session.rs`, que cria o
//!   `\Sessions\0\DosDevices\<LUID>` na primeira vez); sem mapa é
//!   STATUS_OBJECT_PATH_INVALID. O mapa vai ao EPROCESS.DeviceMap.
//! - ObpReferenceDeviceMap (rva 0x625b10): uma thread impersonando (sem
//!   OBJ_IGNORE_IMPERSONATED_DEVICEMAP) usa o mapa da sessão do token de
//!   impersonação, ou o do sistema se o token é do SYSTEM; senão, ou se a
//!   sessão não dá mapa, o EPROCESS.DeviceMap do processo dono da thread
//!   (KTHREAD.Process), preenchido pelo ObSetCurrentProcessDeviceMap quando
//!   vazio. Devolve o mapa com uma referência.
//! - O ObpLookupObjectName (rva 0x641640) começa um nome absoluto `\??\X` no
//!   DosDevicesDirectory desse mapa e devolve o próprio diretório para `\??`
//!   ([`dos_devices_directory`]); um nome que falta num diretório sem sombra
//!   e com DeviceMap é procurado no GlobalDosDevicesDirectory, só na busca
//!   de abertura ([`global_directory`]). Sem mapa, o nome segue da raiz,
//!   onde `\??` não existe. O `\DosDevices` da raiz é um link para `\??`.
//! - ObQueryDeviceMapInformation (rva 0x6254c0): só o processo corrente (outro
//!   processo é STATUS_INVALID_PARAMETER); o mapa do ObpReferenceDeviceMap,
//!   ou o do EPROCESS, ou o do sistema (STATUS_END_OF_FILE sem nenhum); as
//!   letras que faltam no mapa vêm do mapa do GlobalDosDevicesDirectory, a
//!   menos que Flags peça PROCESS_LUID_DOSDEVICES_ONLY.
//! - ObSetProcessDeviceMap (rva 0x8df5fc): o NtSetInformationProcess
//!   (ProcessDeviceMap) chama o ObpSetDeviceMap com o processo, o handle do
//!   diretório, o modo anterior e a Flag 2.
//! - ObIsDosDeviceLocallyMapped (rva 0x7ce210): Index de 1 a 26 (senão
//!   STATUS_INVALID_PARAMETER) e o LocalDeviceCount da letra, a soma dos links
//!   `X:` nos diretórios dos mapas que não são o do sistema.
//!
//! O NT guarda o DriveMap e o DriveType[32] no mapa, atualizados pelo
//! ObpCreateSymbolicLinkName e pelo ObpDeleteSymbolicLinkName de um link
//! `X:` num diretório com DeviceMap; o OpenNT os calcula na consulta pelos
//! links do diretório, com a mesma regra de tipo:
//! - o destino não chega a um DEVICE_OBJECT: DOSDEVICE_DRIVE_CALCULATE (o
//!   kernelbase descobre o tipo abrindo a unidade);
//! - FILE_DEVICE_CD_ROM e o file system de CD-ROM (2, 3): CDROM;
//! - FILE_DEVICE_DISK, o file system de disco e FILE_DEVICE_FILE_SYSTEM
//!   (7 a 9): REMOVABLE com FILE_REMOVABLE_MEDIA nas Characteristics,
//!   senão FIXED;
//! - os devices de rede (0x10, 0x12 a 0x14, 0x28): REMOTE;
//! - FILE_DEVICE_VIRTUAL_DISK (0x24): RAMDISK;
//! - os demais: UNKNOWN.
//!
//! O ObpLUIDDeviceMapsEnabled do 19041 é a constante 1 da imagem: nada o
//! grava (não há valor LUIDDeviceMapsDisabled no Registro) e nada o lê; os
//! mapas por LUID estão sempre ligados, e o ProcessLUIDDeviceMapsEnabled
//! responde 1. O ProtectionMode do Session Manager só muda a DACL do
//! `\GLOBAL??` (ObpGetDosDevicesProtection).

use alloc::collections::BTreeSet;
use alloc::string::String;

use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{DeviceMap, DeviceObject, Eprocess, Ethread};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::ntos::ob::objects::namespace as namespace_objects;
use crate::ntos::ob::{object_types, open_pointer};
use crate::ntos::ps::process;
use crate::ntos::se::logon_session;
use crate::ntos::se::token::{thread as thread_tokens, tokens};
use crate::rtl::{KernelError, SpinLock};

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_END_OF_FILE: u32 = 0xC000_0011;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_OBJECT_PATH_INVALID: u32 = 0xC000_0039;
const STATUS_NO_TOKEN: u32 = 0xC000_007C;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// PROCESS_LUID_DOSDEVICES_ONLY.
const LUID_DOSDEVICES_ONLY: u32 = 1;
/// DOSDEVICE_DRIVE_*.
pub const DRIVE_UNKNOWN: u8 = 0;
pub const DRIVE_CALCULATE: u8 = 1;
pub const DRIVE_REMOVABLE: u8 = 2;
pub const DRIVE_FIXED: u8 = 3;
pub const DRIVE_REMOTE: u8 = 4;
pub const DRIVE_CDROM: u8 = 5;
pub const DRIVE_RAMDISK: u8 = 6;
/// FILE_REMOVABLE_MEDIA.
const FILE_REMOVABLE_MEDIA: u32 = 1;
/// O diretório DOS global.
pub const GLOBAL_DOS_DEVICES: &str = "\\GLOBAL??";
/// Flags do ObpSetDeviceMap: o mapa vira o SystemDeviceMap; o mapa aponta o
/// diretório do SystemDeviceMap como global; o diretório pode ter sombra.
pub const SET_SYSTEM_DEVICE_MAP: u32 = 1;
pub const SET_GLOBAL_DIRECTORY: u32 = 2;
const SET_ALLOW_SHADOW: u32 = 4;
/// DIRECTORY_TRAVERSE e DIRECTORY_ALL_ACCESS.
const DIRECTORY_TRAVERSE: u32 = 2;
const DIRECTORY_ALL_ACCESS: u32 = 0xF000F;
/// OBJ_KERNEL_HANDLE.
const OBJ_KERNEL_HANDLE: u32 = 0x200;
/// PagedPool e 'ObDm'.
const PAGED_POOL: u32 = 1;
const POOL_TAG: u32 = u32::from_le_bytes(*b"ObDm");

/// ObSiloState do silo hospedeiro: o SystemDeviceMap e os mapas vivos, sob
/// o DeviceMapLock (a trava deste estado).
struct Maps {
    system: u64,
    live: BTreeSet<u64>,
}

static MAPS: SpinLock<Maps> = SpinLock::new(Maps { system: 0, live: BTreeSet::new() });

fn map(pointer: u64) -> &'static DeviceMap {
    // SAFETY: DEVICE_MAP de pool vivo enquanto o chamador tem uma referência
    // ou segura o DeviceMapLock com o mapa ligado a um diretório.
    unsafe { DeviceMap::at(pointer) }
}

fn eprocess(process: u64) -> &'static Eprocess {
    // SAFETY: EPROCESS vivo (o corrente, o retido pelo handle ou o que sai no
    // PspProcessDelete).
    unsafe { Eprocess::at(process) }
}

fn add_reference(pointer: u64) {
    map(pointer).reference_count.atomic().fetch_add(1, core::sync::atomic::Ordering::SeqCst);
}

/// O SystemDeviceMap do silo hospedeiro (0 antes do [`initialize`]).
pub fn system_device_map() -> u64 {
    MAPS.lock().system
}

/// O fim do ObpCreateDosDevicesDirectory (ObpSetSiloDeviceMap): o
/// `\GLOBAL??` vira o diretório do SystemDeviceMap, que o System recebe.
pub fn initialize() -> Result<(), KernelError> {
    if system_device_map() != 0 {
        return Ok(());
    }
    let node = object_manager::lookup(GLOBAL_DOS_DEVICES).ok_or_else(|| KernelError::new("\\GLOBAL?? ausente"))?;
    let directory = namespace_objects::ensure(node)?.ok_or_else(|| KernelError::new("\\GLOBAL?? sem corpo de diretorio"))?;
    namespace_objects::reference(directory)?;
    match install(process::get_system_process(), directory, SET_SYSTEM_DEVICE_MAP | SET_GLOBAL_DIRECTORY)? {
        Ok(_) => Ok(()),
        Err(status) => Err(KernelError::with_status(alloc::format!("ObpSetSiloDeviceMap: {status:#x}"), status)),
    }
}

/// ObpSetDeviceMap(Silo, Process, DirectoryHandle, AccessMode, Flags,
/// DeviceMap*): devolve o mapa escolhido (com a referência do processo ou
/// do chamador) ou o NTSTATUS da recusa.
pub fn set_device_map(process: u64, directory_handle: u64, access_mode: u8, flags: u32) -> Result<Result<u64, u32>, KernelError> {
    let opened = match crate::ntos::ob::handles::namespace::resolve(directory_handle, access_mode != 0) {
        Ok(opened) => opened,
        Err(status) => return Ok(Err(status)),
    };
    if !opened.directory {
        return Ok(Err(STATUS_OBJECT_TYPE_MISMATCH));
    }
    if access_mode != 0 && opened.access & DIRECTORY_TRAVERSE == 0 {
        return Ok(Err(STATUS_ACCESS_DENIED));
    }
    namespace_objects::reference(opened.body)?;
    install(process, opened.body, flags)
}

/// O corpo do ObpSetDeviceMap depois do ObReferenceObjectByHandle: a
/// referência do `directory` passa ao mapa novo (ou volta).
fn install(process: u64, directory: u64, flags: u32) -> Result<Result<u64, u32>, KernelError> {
    if flags & SET_ALLOW_SHADOW == 0 && namespace_objects::directory_flags(directory) & namespace_objects::DIRECTORY_SHADOW != 0 {
        namespace_objects::dereference(directory)?;
        return Ok(Err(STATUS_INVALID_PARAMETER));
    }
    let fresh = pool_allocation::allocate_tagged(PAGED_POOL, DeviceMap::SIZE, POOL_TAG).unwrap_or(0);
    if fresh == 0 {
        namespace_objects::dereference(directory)?;
        return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
    }
    guest::write_bytes(fresh, &[0u8; DeviceMap::SIZE as usize]);
    let record = map(fresh);
    record.reference_count.set(1);
    record.dos_devices_directory.set(directory);
    let opened = open_pointer::open_by_pointer(directory, OBJ_KERNEL_HANDLE, 0, DIRECTORY_ALL_ACCESS, object_types::directory_type().pointer, 0, record.dos_devices_directory_handle.address());
    let status = match opened {
        Ok(status) => status,
        Err(error) => {
            namespace_objects::dereference(directory)?;
            pool_allocation::free(fresh, u64::from(POOL_TAG))?;
            return Err(error);
        }
    };
    if status != 0 {
        namespace_objects::dereference(directory)?;
        pool_allocation::free(fresh, u64::from(POOL_TAG))?;
        return Ok(Err(status));
    }
    let (chosen, duplicate, previous) = {
        let mut maps = MAPS.lock();
        let existing = namespace_objects::device_map(directory);
        let chosen = if existing != 0 {
            add_reference(existing);
            existing
        } else {
            if flags & SET_SYSTEM_DEVICE_MAP != 0 {
                maps.system = fresh;
            }
            namespace_objects::set_device_map(directory, fresh)?;
            if flags & SET_GLOBAL_DIRECTORY != 0 && maps.system != 0 {
                let global = map(maps.system).dos_devices_directory.get();
                if global != directory {
                    record.global_dos_devices_directory.set(global);
                }
            }
            maps.live.insert(fresh);
            fresh
        };
        let previous = if process != 0 {
            let previous = eprocess(process).device_map.get();
            eprocess(process).device_map.set(chosen);
            previous
        } else {
            0
        };
        (chosen, if existing != 0 { fresh } else { 0 }, previous)
    };
    if duplicate != 0 {
        release_storage(duplicate);
    }
    if previous != 0 {
        dereference(previous);
    }
    Ok(Ok(chosen))
}

/// O fim do ObfDereferenceDeviceMap: o ZwClose do handle, a referência do
/// diretório e o pool. Uma falha só fica no log: o mapa já saiu do
/// diretório.
fn release_storage(pointer: u64) {
    let record = map(pointer);
    let handle = record.dos_devices_directory_handle.get();
    let directory = record.dos_devices_directory.get();
    let result = (|| -> Result<(), KernelError> {
        if handle != 0 {
            crate::ntos::ob::close::close(handle, Some(0))?;
        }
        if directory != 0 {
            namespace_objects::dereference(directory)?;
        }
        pool_allocation::free(pointer, u64::from(POOL_TAG))
    })();
    if let Err(error) = result {
        crate::debug_print!("[ob] DEVICE_MAP {:#x} nao liberado: {}", pointer, error);
    }
}

/// ObfDereferenceDeviceMap(DeviceMap).
pub fn dereference(pointer: u64) {
    use core::sync::atomic::Ordering;
    let count = map(pointer).reference_count.atomic();
    let mut current = count.load(Ordering::SeqCst);
    while current != 1 {
        match count.compare_exchange(current, current - 1, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
    let last = {
        let mut maps = MAPS.lock();
        if count.fetch_sub(1, Ordering::SeqCst) != 1 {
            false
        } else {
            let _ = namespace_objects::set_device_map(map(pointer).dos_devices_directory.get(), 0);
            maps.live.remove(&pointer);
            true
        }
    };
    if last {
        release_storage(pointer);
    }
}

/// ObDereferenceDeviceMap(Process): o PspProcessDelete e o
/// PspAssignPrimaryToken.
pub fn dereference_process(process: u64) {
    let previous = {
        let _maps = MAPS.lock();
        let previous = eprocess(process).device_map.get();
        eprocess(process).device_map.set(0);
        previous
    };
    if previous != 0 {
        dereference(previous);
    }
}

/// ObSetProcessDeviceMap(Process, DirectoryHandle, AccessMode): devolve o
/// NTSTATUS.
pub fn set_process_device_map(process: u64, directory_handle: u64, access_mode: u8) -> Result<u32, KernelError> {
    Ok(match set_device_map(process, directory_handle, access_mode, SET_GLOBAL_DIRECTORY)? {
        Ok(_) => 0,
        Err(status) => status,
    })
}

/// O LogonId do token (AuthenticationId; 0 sem o token).
fn logon_id_of(token: u64) -> u64 {
    tokens::with(token, |record| record.authentication_id).unwrap_or(0)
}

/// ObSetCurrentProcessDeviceMap(): devolve o NTSTATUS.
pub fn set_current_process_device_map() -> u32 {
    let current = process::get_current_process();
    let Ok(token) = crate::ntos::ps::security::reference_primary_token(current) else { return STATUS_NO_TOKEN };
    let chosen = if logon_id_of(token) == logon_session::SYSTEM_LUID { system_device_map() } else { logon_session::token_device_map(token).unwrap_or(0) };
    if chosen == 0 {
        let _ = crate::ntos::ps::security::dereference_primary_token(token);
        return STATUS_OBJECT_PATH_INVALID;
    }
    let previous = {
        let _maps = MAPS.lock();
        let previous = eprocess(current).device_map.get();
        eprocess(current).device_map.set(chosen);
        add_reference(chosen);
        previous
    };
    let _ = crate::ntos::ps::security::dereference_primary_token(token);
    if previous != 0 {
        dereference(previous);
    }
    0
}

/// ObpReferenceDeviceMap(IgnoreImpersonatedDeviceMap): o mapa de quem
/// procura, com uma referência (0 sem mapa).
pub fn reference(ignore_impersonation: bool) -> u64 {
    let thread = process::get_current_thread();
    let owner = if thread == 0 {
        process::get_system_process()
    } else {
        // SAFETY: a thread corrente.
        unsafe { Ethread::at(thread) }.tcb.process.get()
    };
    if owner == 0 {
        return 0;
    }
    let mut impersonation = 0;
    if !ignore_impersonation && thread != 0 {
        if let Some(state) = thread_tokens::get(thread) {
            if tokens::retain(state.token).is_ok() {
                impersonation = state.token;
            }
        }
    }
    let mut system_request = false;
    let mut found = 0;
    if impersonation != 0 {
        if logon_id_of(impersonation) == logon_session::SYSTEM_LUID {
            system_request = true;
        } else if let Ok(session_map) = logon_session::token_device_map(impersonation) {
            if session_map != 0 {
                add_reference(session_map);
                found = session_map;
            }
        }
    }
    if found == 0 {
        let usable = system_request || eprocess(owner).device_map.get() != 0 || set_current_process_device_map() as i32 >= 0;
        if usable {
            let maps = MAPS.lock();
            found = if system_request { maps.system } else { eprocess(owner).device_map.get() };
            if found != 0 {
                add_reference(found);
            }
        }
    }
    if impersonation != 0 {
        let _ = tokens::release(impersonation);
    }
    found
}

/// O DosDevicesDirectory do mapa de quem procura: onde o ObpLookupObjectName
/// começa um nome `\??\X` (e o próprio `\??`). `None` sem mapa.
pub fn dos_devices_directory(ignore_impersonation: bool) -> Option<NodeId> {
    let found = reference(ignore_impersonation);
    if found == 0 {
        return None;
    }
    let node = namespace_objects::get(map(found).dos_devices_directory.get()).map(|(node, _)| node);
    dereference(found);
    node
}

/// O GlobalDosDevicesDirectory do DeviceMap de um diretório (0 sem mapa ou
/// num mapa sem diretório global): a sombra de um diretório sem
/// ShadowDirectory no ObpLookupObjectName.
pub fn global_directory(directory: u64) -> u64 {
    if directory == 0 {
        return 0;
    }
    let _maps = MAPS.lock();
    let found = namespace_objects::device_map(directory);
    if found == 0 {
        0
    } else {
        map(found).global_dos_devices_directory.get()
    }
}

/// A parte de consulta do PROCESS_DEVICEMAP_INFORMATION.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeviceMapInformation {
    pub drive_map: u32,
    pub drive_type: [u8; 32],
}

/// O tipo de unidade pelo DeviceType e pelas Characteristics do
/// DEVICE_OBJECT final do destino.
pub fn drive_type_of(device_type: u32, characteristics: u32) -> u8 {
    match device_type {
        2 | 3 => DRIVE_CDROM,
        7..=9 => {
            if characteristics & FILE_REMOVABLE_MEDIA != 0 {
                DRIVE_REMOVABLE
            } else {
                DRIVE_FIXED
            }
        }
        0x10 | 0x12..=0x14 | 0x28 => DRIVE_REMOTE,
        0x24 => DRIVE_RAMDISK,
        _ => DRIVE_UNKNOWN,
    }
}

/// A letra de um nome `X:` (A a Z, sem distinção de caixa).
fn drive_letter(name: &str) -> Option<u32> {
    let mut characters = name.chars();
    let (Some(letter), Some(':'), None) = (characters.next(), characters.next(), characters.next()) else { return None };
    let letter = letter.to_ascii_uppercase();
    letter.is_ascii_uppercase().then(|| letter as u32 - 'A' as u32)
}

/// O tipo de unidade de um link: o objeto final do destino.
fn link_drive_type(link_path: &str) -> u8 {
    let (found, rest) = object_manager::resolve(link_path);
    if rest.is_some_and(|rest| !rest.is_empty()) {
        return DRIVE_CALCULATE;
    }
    let Some(node) = found.and_then(object_manager::node) else { return DRIVE_CALCULATE };
    let pointer = node.data.as_ref().map_or(0, |data| data.native_pointer);
    if node.type_name != "Device" || pointer == 0 {
        return DRIVE_CALCULATE;
    }
    // SAFETY: o DEVICE_OBJECT publicado pelo nó do dispositivo.
    let device = unsafe { DeviceObject::at(pointer) };
    drive_type_of(device.device_type.get(), device.characteristics.get())
}

/// Os links `X:` de um diretório de devices DOS (o corpo dele).
fn drive_links(directory: u64) -> alloc::vec::Vec<(u32, String)> {
    let Some((node, true)) = namespace_objects::get(directory) else { return alloc::vec::Vec::new() };
    let Some(snapshot) = object_manager::node(node) else { return alloc::vec::Vec::new() };
    let mut links = alloc::vec::Vec::new();
    for (_, child) in snapshot.children.unwrap_or_default() {
        let Some(child) = object_manager::node(child) else { continue };
        if child.type_name != "SymbolicLink" {
            continue;
        }
        if let Some(index) = drive_letter(&child.name) {
            links.push((index, child.name));
        }
    }
    links
}

/// O DriveMap e o DriveType[32] dos links de um diretório.
fn drives_of(directory: u64) -> DeviceMapInformation {
    let mut information = DeviceMapInformation::default();
    let Some(path) = namespace_objects::get(directory).and_then(|(node, _)| object_manager::path_of(node)) else { return information };
    for (index, name) in drive_links(directory) {
        information.drive_map |= 1 << index;
        information.drive_type[index as usize] = link_drive_type(&alloc::format!("{path}\\{name}"));
    }
    information
}

/// ObQueryDeviceMapInformation(Process, DeviceMapInformation, Flags).
pub fn query(process: u64, flags: u32) -> Result<DeviceMapInformation, u32> {
    if flags & !LUID_DOSDEVICES_ONLY != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if process != 0 && process != process::get_current_process() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let referenced = reference(false);
    // Sem mapa de quem consulta, o do processo ou o do sistema, retido pelo
    // dono enquanto a consulta lê os diretórios (o NT lê sob o
    // DeviceMapLock).
    let (local, global) = {
        let maps = MAPS.lock();
        let chosen = if referenced != 0 {
            referenced
        } else if process != 0 {
            eprocess(process).device_map.get()
        } else {
            maps.system
        };
        if chosen == 0 {
            (0, 0)
        } else {
            let global_directory = map(chosen).global_dos_devices_directory.get();
            let global_map = if global_directory != 0 { namespace_objects::device_map(global_directory) } else { 0 };
            (map(chosen).dos_devices_directory.get(), if global_map != 0 { map(global_map).dos_devices_directory.get() } else { 0 })
        }
    };
    if local == 0 {
        if referenced != 0 {
            dereference(referenced);
        }
        return Err(STATUS_END_OF_FILE);
    }
    let mut information = drives_of(local);
    if flags & LUID_DOSDEVICES_ONLY == 0 && global != 0 && global != local {
        let shared = drives_of(global);
        for index in 0..32 {
            let bit = 1u32 << index;
            if information.drive_map & bit == 0 {
                information.drive_type[index] = shared.drive_type[index];
                information.drive_map |= shared.drive_map & bit;
            }
        }
    }
    if referenced != 0 {
        dereference(referenced);
    }
    Ok(information)
}

/// ObIsDosDeviceLocallyMapped(Index, DosDeviceState*): o BOOLEAN da letra
/// (1 = A) ou STATUS_INVALID_PARAMETER.
pub fn is_dos_device_locally_mapped(index: u32) -> Result<bool, u32> {
    if !(1..=26).contains(&index) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let maps = MAPS.lock();
    let system = maps.system;
    Ok(maps.live.iter().filter(|&&pointer| pointer != system).any(|&pointer| drive_links(map(pointer).dos_devices_directory.get()).iter().any(|(letter, _)| *letter == index - 1)))
}
