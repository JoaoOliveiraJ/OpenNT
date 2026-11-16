//! Minifiltros reais da Microsoft sobre o volume do ntfs.sys, hospedados
//! pelo Filter Manager real (fltmgr.sys).
//!
//! Com `--start-driver=...` listando o ntfs e minifiltros (chaves com
//! `Instances`, `cm/service/file_system_filters.rs`), depois do último
//! driver da lista o teste fala com o próprio FltMgr pelos exports dele,
//! como um cliente do Filter Manager:
//! - FltEnumerateFilters e FltGetFilterInformation: os filtros registrados;
//!   FltEnumerateVolumes e FltGetFileSystemType: o volume NTFS do ntfs.sys.
//! - Os filtros que só aceitam anexação manual (o InstanceSetup deles
//!   recusa a automática: o storqosflt, que o serviço de QoS de
//!   armazenamento anexa, e o bindflt e o wcifs, que os serviços de
//!   contêiner anexam) são anexados ao volume NTFS por FltAttachVolume com a
//!   instância padrão da chave, como esses serviços fazem pelo FilterAttach.
//! - FltEnumerateInstances de cada filtro, com FltGetInstanceInformation
//!   (InstanceFullInformation: instância, altitude, volume e filtro).
//!
//! Cada minifiltro da lista precisa estar em execução, registrado e com uma
//! instância da chave no volume NTFS (FLT_FSTYPE_NTFS) na altitude da
//! chave; a serial mostra `FLT_INSTANCES_OK` com a lista
//! (filtro/instância@altitude) ou `FLT_INSTANCES_FALHOU` com o motivo.
//! Depois o teste repete as operações de arquivo do teste do ntfs.sys pela
//! pilha de filtros (abrir e ler HELLO.TXT, criar, gravar, reabrir e ler de
//! volta um arquivo novo) e confere que o topo da pilha do dispositivo de
//! volume do ntfs.sys é o dispositivo do FltMgr: `FLT_FILE_OPS_OK`. O fim
//! do teste é sempre `FLT_MINIFILTERS_FIM`.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::hal::amd64::native_call;
use crate::ntos::cm::service::file_system_filters;
use crate::ntos::inc::{types as nt, NtStruct};
use crate::ntos::init::boot_config;
use crate::ntos::mm::guest_memory as guest;

const STATUS_SUCCESS: u32 = 0;
/// FILTER_INFORMATION_CLASS.FilterFullInformation.
const FILTER_FULL_INFORMATION: u64 = 0;
/// INSTANCE_INFORMATION_CLASS.InstanceFullInformation.
const INSTANCE_FULL_INFORMATION: u64 = 2;
/// FLT_FILESYSTEM_TYPE.FLT_FSTYPE_NTFS.
const FLT_FSTYPE_NTFS: u32 = 2;
const MAX_OBJECTS: u64 = 32;
/// Os filtros cujo InstanceSetup só aceita FLTFL_INSTANCE_SETUP_MANUAL_ATTACHMENT
/// num volume NTFS: um serviço de modo usuário os anexa.
const MANUAL_ATTACHMENT: &[&str] = &["storqosflt", "bindflt", "wcifs"];

/// Uma instância como o FltMgr a descreve.
struct InstanceReport {
    filter: String,
    instance: String,
    altitude: String,
    volume: String,
    file_system_type: u32,
}

fn started(name: &str) -> bool {
    boot_config::start_driver().split(',').any(|entry| entry.eq_ignore_ascii_case(name))
}

fn running(name: &str) -> bool {
    crate::ntos::cm::service::database::status(name).is_ok_and(|status| status.current_state == 4)
}

/// Depois do início de cada driver pelo `--start-driver` (state=4): o teste
/// roda depois do último da lista, quando ela tem o ntfs e minifiltros.
pub fn after_driver_start(name: &str) {
    let last = boot_config::start_driver().split(',').filter(|entry| !entry.is_empty()).last();
    if !last.is_some_and(|last| last.eq_ignore_ascii_case(name)) || !started("ntfs") {
        return;
    }
    let expected: Vec<(&str, &[(&str, &str, u32)])> = file_system_filters::minifilters().filter(|(filter, _)| started(filter)).collect();
    if expected.is_empty() {
        return;
    }
    if running("FileInfo") {
        match prefetcher_interface() {
            Ok(()) => debug_print!("FLT_PREFETCHER_INTERFACE_OK"),
            Err(message) => debug_print!("FLT_PREFETCHER_INTERFACE_FALHOU {}", message),
        }
    }
    match FilterManager::new().and_then(|manager| manager.instances(&expected)) {
        Ok(listing) => {
            debug_print!("FLT_INSTANCES_OK {}", listing);
            match file_operations() {
                Ok(()) => debug_print!("FLT_FILE_OPS_OK"),
                Err(message) => debug_print!("FLT_FILE_OPS_FALHOU {}", message),
            }
        }
        Err(message) => debug_print!("FLT_INSTANCES_FALHOU {}", message),
    }
    debug_print!("FLT_MINIFILTERS_FIM");
}

/// Os exports do fltmgr.sys carregado e um bloco de trabalho no convidado.
struct FilterManager {
    exports: BTreeMap<String, u64>,
    scratch: u64,
}

impl Drop for FilterManager {
    fn drop(&mut self) {
        guest::free_bytes(self.scratch);
    }
}

/// Texto UTF-16 de `length` bytes no convidado.
fn wide_text(address: u64, length: usize) -> String {
    let units: Vec<u16> = guest::read_bytes(address, length).chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    String::from_utf16_lossy(&units)
}

/// Um nome de INSTANCE_FULL_INFORMATION (comprimento e deslocamento USHORT
/// a partir do início do registro).
fn embedded_string(record: u64, length_offset: u64) -> String {
    let length = guest::read16(record + length_offset) as usize;
    let offset = guest::read16(record + length_offset + 2) as u64;
    wide_text(record + offset, length)
}

impl FilterManager {
    fn new() -> Result<FilterManager, String> {
        let exports = crate::ntos::io::lifecycle::driver_exports("fltmgr").ok_or_else(|| String::from("fltmgr.sys nao carregado"))?;
        let scratch = guest::alloc_bytes(0x3000);
        if scratch == 0 {
            return Err(String::from("sem memoria para o teste"));
        }
        Ok(FilterManager { exports, scratch })
    }

    /// Chama um export do FltMgr; o status NTSTATUS de 32 bits.
    fn call(&self, name: &str, arguments: &[u64]) -> Result<u32, String> {
        let routine = self.exports.get(name).copied().filter(|&address| address != 0).ok_or_else(|| format!("fltmgr.sys sem o export {name}"))?;
        Ok(native_call::call(routine, arguments) as u32)
    }

    /// FltEnumerateFilters: (nome, PFLT_FILTER referenciado).
    fn filters(&self) -> Result<Vec<(String, u64)>, String> {
        let (list, count, information) = (self.scratch, self.scratch + 0x100, self.scratch + 0x400);
        let status = self.call("FltEnumerateFilters", &[list, MAX_OBJECTS, count])?;
        if status != STATUS_SUCCESS {
            return Err(format!("FltEnumerateFilters devolveu {status:#x}"));
        }
        let mut filters = Vec::new();
        for index in 0..guest::read32(count) as u64 {
            let filter = guest::read64(list + index * 8);
            let named = self.call("FltGetFilterInformation", &[filter, FILTER_FULL_INFORMATION, information, 0x1000, count + 8])?;
            // FILTER_FULL_INFORMATION.FilterNameLength (+0xC) e FilterNameBuffer (+0xE).
            let name = if named == STATUS_SUCCESS { wide_text(information + 0xE, guest::read16(information + 0xC) as usize) } else { format!("<{named:#x}>") };
            filters.push((name, filter));
        }
        Ok(filters)
    }

    /// O volume NTFS que o FltMgr conhece (referenciado), com a lista dos
    /// volumes na serial.
    fn ntfs_volume(&self, filter: u64) -> Result<u64, String> {
        let (volumes, count, name, text, kind) = (self.scratch + 0x2000, self.scratch + 0x2100, self.scratch + 0x2110, self.scratch + 0x2200, self.scratch + 0x2108);
        let status = self.call("FltEnumerateVolumes", &[filter, volumes, MAX_OBJECTS, count])?;
        let volume_count = if status == STATUS_SUCCESS { guest::read32(count) as u64 } else { 0 };
        let mut found = 0;
        for index in 0..volume_count {
            let volume = guest::read64(volumes + index * 8);
            crate::ntos::rtl::guest_strings::write_string_fields(name, 0, 0x200, text);
            let named = self.call("FltGetVolumeName", &[volume, name, 0])?;
            guest::write32(kind, 0);
            self.call("FltGetFileSystemType", &[volume, kind])?;
            let label = if named == STATUS_SUCCESS { crate::ntos::rtl::guest_strings::read_unicode_string(name) } else { format!("<{named:#x}>") };
            debug_print!("[flt] volume {} fstype {}", label, guest::read32(kind));
            if found == 0 && guest::read32(kind) == FLT_FSTYPE_NTFS {
                found = volume;
            } else {
                self.call("FltObjectDereference", &[volume])?;
            }
        }
        if found == 0 {
            return Err(format!("nenhum volume NTFS entre os {volume_count} do FltMgr ({status:#x})"));
        }
        Ok(found)
    }

    /// As instâncias de um filtro.
    fn filter_instances(&self, filter: u64, name: &str) -> Result<Vec<InstanceReport>, String> {
        let (list, count, information, volume_cell, kind) = (self.scratch + 0x100, self.scratch + 0x200, self.scratch + 0x400, self.scratch + 0x208, self.scratch + 0x210);
        let status = self.call("FltEnumerateInstances", &[0, filter, list, MAX_OBJECTS, count])?;
        let instance_count = if status == STATUS_SUCCESS { guest::read32(count) as u64 } else { 0 };
        debug_print!("[flt] filtro {}: FltEnumerateInstances -> {:#x}, {} instancias", name, status, instance_count);
        let mut reports = Vec::new();
        for slot in 0..instance_count {
            let instance = guest::read64(list + slot * 8);
            let queried = self.call("FltGetInstanceInformation", &[instance, INSTANCE_FULL_INFORMATION, information, 0x1000, count])?;
            let mut file_system_type = 0;
            if self.call("FltGetVolumeFromInstance", &[instance, volume_cell])? == STATUS_SUCCESS {
                let volume = guest::read64(volume_cell);
                guest::write32(kind, 0);
                if self.call("FltGetFileSystemType", &[volume, kind])? == STATUS_SUCCESS {
                    file_system_type = guest::read32(kind);
                }
                self.call("FltObjectDereference", &[volume])?;
            }
            if queried == STATUS_SUCCESS {
                // INSTANCE_FULL_INFORMATION: instância, altitude, volume e filtro.
                reports.push(InstanceReport { instance: embedded_string(information, 4), altitude: embedded_string(information, 8), volume: embedded_string(information, 0xC), filter: embedded_string(information, 0x10), file_system_type });
            }
            self.call("FltObjectDereference", &[instance])?;
        }
        Ok(reports)
    }

    /// Um filtro abre HELLO.TXT abaixo da sua instância no volume NTFS
    /// (FltCreateFileEx: o FltMgr manda o IRP_MJ_CREATE pelo IoCreateFileEx
    /// com o dispositivo de destino), lê pelo FltReadFile e fecha pelo
    /// FltClose; os bytes são os que o leitor do kernel lê.
    fn create_file_below_instance(&self, filter: u64) -> Result<(), String> {
        let (list, count) = (self.scratch + 0x100, self.scratch + 0x200);
        let volume = self.ntfs_volume(filter)?;
        let status = self.call("FltEnumerateInstances", &[volume, filter, list, 1, count])?;
        self.call("FltObjectDereference", &[volume])?;
        if status != STATUS_SUCCESS || guest::read32(count) == 0 {
            return Err(format!("o filtro nao tem instancia no volume NTFS para o FltCreateFileEx ({status:#x})"));
        }
        let instance = guest::read64(list);
        let expected = crate::drivers::fs::ntfs::mounted().and_then(|volume| volume.read_bytes("/HELLO.TXT").ok().flatten()).unwrap_or_default();
        let block = guest::alloc_bytes(0x400);
        let path: Vec<u8> = "\\Device\\AtaVolume1\\HELLO.TXT".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let text = block + 0x100;
        guest::write_bytes(text, &path);
        crate::ntos::rtl::guest_strings::write_string_fields(block + 0x40, path.len() as u16, path.len() as u16, text);
        // OBJECT_ATTRIBUTES: Length 48, ObjectName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE.
        guest::write_bytes(block, &[0u8; 48]);
        guest::write32(block, 48);
        guest::write64(block + 0x10, block + 0x40);
        guest::write32(block + 0x18, 0x240);
        let (handle, file_object, iosb, offset, bytes_read, buffer) = (block + 0x300, block + 0x308, block + 0x310, block + 0x320, block + 0x328, block + 0x200);
        let result = (|| -> Result<(), String> {
            // GENERIC_READ (FILE_GENERIC_READ), FILE_SHARE_READ, FILE_OPEN,
            // FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT.
            let created = self.call("FltCreateFileEx", &[filter, instance, handle, file_object, 0x0012_0089, block, iosb, 0, 0, 1, 1, 0x60, 0, 0, 0])?;
            debug_print!("[flt] FltCreateFileEx(HELLO.TXT abaixo da instancia {:#x}) -> {:#x}, FILE_OBJECT {:#x}", instance, created, guest::read64(file_object));
            if created != STATUS_SUCCESS {
                return Err(format!("FltCreateFileEx devolveu {created:#x}"));
            }
            guest::write64(offset, 0);
            let read = self.call("FltReadFile", &[instance, guest::read64(file_object), offset, 0x100, buffer, 0, bytes_read, 0, 0])?;
            let count = guest::read32(bytes_read) as usize;
            let bytes = guest::read_bytes(buffer, count.min(0x100));
            crate::ntos::init::exports::invoke_handler("ObfDereferenceObject", &[guest::read64(file_object)]).map_err(|error| error.message)?;
            let closed = self.call("FltClose", &[guest::read64(handle)])?;
            debug_print!("[flt] FltReadFile -> {:#x}, {} bytes; FltClose -> {:#x}", read, count, closed);
            if read != STATUS_SUCCESS || bytes != expected || closed != STATUS_SUCCESS {
                return Err(format!("FltReadFile {read:#x} com {count} bytes, FltClose {closed:#x}"));
            }
            debug_print!("FLT_CREATE_FILE_OK");
            Ok(())
        })();
        self.call("FltObjectDereference", &[instance])?;
        guest::free_bytes(block);
        result
    }

    /// As instâncias que o FltMgr anexou, conferidas contra as chaves: cada
    /// minifiltro da lista precisa estar em execução, registrado no FltMgr e
    /// com uma instância da chave num volume NTFS.
    fn instances(&self, expected: &[(&str, &[(&str, &str, u32)])]) -> Result<String, String> {
        let filters = self.filters()?;
        let result = (|| -> Result<String, String> {
            let first = filters.first().map(|&(_, filter)| filter).ok_or_else(|| String::from("nenhum filtro registrado no FltMgr"))?;
            let volume = self.ntfs_volume(first)?;
            for (name, filter) in &filters {
                if MANUAL_ATTACHMENT.iter().any(|manual| manual.eq_ignore_ascii_case(name)) {
                    let instance = self.scratch + 0x300;
                    guest::write64(instance, 0);
                    // Com `--trace-driver-api`, as APIs do InstanceSetup vão para a serial.
                    crate::ntos::init::exports::set_api_trace(boot_config::trace_driver_api());
                    let status = self.call("FltAttachVolume", &[*filter, volume, 0, instance]);
                    crate::ntos::init::exports::set_api_trace(false);
                    let status = status?;
                    debug_print!("[flt] FltAttachVolume({}, instancia padrao) -> {:#x}", name, status);
                    if status == STATUS_SUCCESS && guest::read64(instance) != 0 {
                        self.call("FltObjectDereference", &[guest::read64(instance)])?;
                    }
                }
            }
            self.call("FltObjectDereference", &[volume])?;
            let mut reports = Vec::new();
            for (name, filter) in &filters {
                reports.extend(self.filter_instances(*filter, name)?);
            }
            for report in &reports {
                debug_print!("[flt] filtro {} instancia {} altitude {} volume {} fstype {}", report.filter, report.instance, report.altitude, report.volume, report.file_system_type);
            }
            let mut listing = Vec::new();
            let mut failures = Vec::new();
            for &(filter, keys) in expected {
                if !running(filter) {
                    failures.push(format!("{filter} nao esta em execucao"));
                } else if !filters.iter().any(|(name, _)| name.eq_ignore_ascii_case(filter)) {
                    failures.push(format!("{filter} nao registrado no FltMgr"));
                } else {
                    let found = reports.iter().find(|report| report.filter.eq_ignore_ascii_case(filter) && report.file_system_type == FLT_FSTYPE_NTFS && keys.iter().any(|&(instance, altitude, _)| report.instance == instance && report.altitude == altitude));
                    match found {
                        Some(report) => listing.push(format!("{}/{}@{}", report.filter, report.instance, report.altitude)),
                        None => failures.push(format!("{filter} sem instancia no volume NTFS")),
                    }
                }
            }
            if !failures.is_empty() {
                return Err(format!("{} ({} filtros, {} instancias no total)", failures.join("; "), filters.len(), reports.len()));
            }
            // O FltCreateFileEx de um filtro, abaixo da sua instância.
            let lowest = expected.iter().filter_map(|&(filter, _)| filters.iter().find(|(name, _)| name.eq_ignore_ascii_case(filter))).next().map(|&(_, filter)| filter);
            if let Some(filter) = lowest {
                self.create_file_below_instance(filter)?;
            }
            Ok(listing.join(" "))
        })();
        for &(_, filter) in &filters {
            self.call("FltObjectDereference", &[filter])?;
        }
        result
    }
}

/// O DriverEntry do FileInfo registrou a sua interface no prefetcher
/// (PfFileInfoNotify Type 0xA); um segundo registro é recusado com
/// STATUS_ALREADY_COMMITTED e a interface continua a do FileInfo.
fn prefetcher_interface() -> Result<(), String> {
    use crate::ntos::mm::prefetcher_file_info;
    let interface = prefetcher_file_info::registered_interface();
    if interface == 0 {
        return Err(String::from("o FileInfo nao registrou a interface"));
    }
    let notify = guest::alloc_bytes(0x20);
    guest::write32(notify, 0xF);
    guest::write32(notify + 4, 0xA);
    guest::write32(notify + 8, 8);
    guest::write64(notify + 0x10, interface);
    let again = prefetcher_file_info::file_info_notify(notify).unwrap_or(0);
    guest::free_bytes(notify);
    debug_print!("[flt] interface do FileInfo no prefetcher {:#x}; segundo registro -> {:#x}", interface, again);
    if again != prefetcher_file_info::STATUS_ALREADY_COMMITTED || prefetcher_file_info::registered_interface() != interface {
        return Err(format!("segundo registro devolveu {again:#x}"));
    }
    Ok(())
}

/// O topo da pilha do dispositivo de volume do ntfs.sys é do FltMgr, e as
/// operações de arquivo do teste do ntfs.sys passam pela pilha de filtros.
fn file_operations() -> Result<(), String> {
    crate::ntos::test::file_system_mount::file_operations("OPENNT-FILTROS.TXT", b"Gravado pela pilha de minifiltros do FltMgr.\r\n")?;
    let device = crate::drivers::storage::ata_volume::create(1).map_err(|error| format!("dispositivo do volume: {error}"))?;
    // SAFETY: o DEVICE_OBJECT do volume ATA e o VPB dele.
    let vpb = unsafe { nt::DeviceObject::at(device) }.vpb.get();
    // SAFETY: o VPB montado do volume.
    let volume = if vpb != 0 { unsafe { nt::Vpb::at(vpb) }.device_object.get() } else { 0 };
    if volume == 0 {
        return Err(String::from("volume sem dispositivo de file system montado"));
    }
    let top = crate::ntos::init::exports::invoke_handler("IoGetAttachedDevice", &[volume]).unwrap_or(0);
    // SAFETY: o dispositivo do topo da pilha do volume.
    let driver = if top != 0 { unsafe { nt::DeviceObject::at(top) }.driver_object.get() } else { 0 };
    // SAFETY: o DRIVER_OBJECT dono do topo da pilha.
    let name = if driver != 0 { crate::ntos::rtl::guest_strings::read_unicode_string(unsafe { nt::DriverObject::at(driver) }.driver_name.address()) } else { String::new() };
    let fltmgr = crate::ntos::io::lifecycle::initialized_driver("fltmgr").unwrap_or(0);
    debug_print!("[flt] volume do ntfs.sys {:#x}, topo da pilha {:#x} ({})", volume, top, name);
    if top == volume || fltmgr == 0 || driver != fltmgr {
        return Err(format!("topo da pilha do volume e {name}, nao o FltMgr"));
    }
    Ok(())
}
