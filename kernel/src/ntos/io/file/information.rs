//! Consultas por FILE_OBJECT — `system32/ntos/io/file-information.js`.
//!
//! Drivers nativos recebem o buffer de kernel original num IRP real; a
//! conclusão é dona do resultado, inclusive no I/O pendente. Para arquivos
//! sem dispositivo o tamanho vem dos serviços de arquivo do kernel (`zw`),
//! que instalam a consulta por objeto (`set_object_query`).

use alloc::collections::BTreeSet;

use crate::ntos::io::io_manager;
use crate::ntos::io::small::thread_io;
use crate::hal::amd64::native_call;
use crate::ntos::ke::{critical_region, dispatcher};
use crate::ntos::ob::objects::file as file_objects;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{io_stack_location, irp};
use crate::ntos::io::irp_builder::{self, BuildOptions};

const RESOURCE: u32 = 0xC000_009A;

/// ZwQueryInformationFile por objeto: (file, classe, tamanho, buffer, retornado).
pub type ObjectQuery = fn(u64, u32, u32, u64, u64) -> Result<u32, KernelError>;

static OBJECT_QUERY: SpinLock<Option<ObjectQuery>> = SpinLock::new(None);

pub fn set_object_query(query: ObjectQuery) {
    *OBJECT_QUERY.lock() = Some(query);
}

/// IoGetRelatedDeviceObject: o dispositivo do VPB (ou o do arquivo, ou o do
/// volume montado) e o topo da pilha, que uma extensão real de arquivo pode
/// mandar parar num filtro abaixo do topo.
pub fn related_device(file: u64) -> Result<u64, KernelError> {
    let vpb = guest::read64(file + 0x10);
    let mut device = if vpb != 0 { guest::read64(vpb + 8) } else { 0 };
    if device == 0 {
        device = guest::read64(file + 8);
        if device != 0 && guest::read32(file + 0x50) & 0x800 == 0 {
            let volume = guest::read64(device + 0x38);
            if volume != 0 {
                let mounted = guest::read64(volume + 8);
                if mounted != 0 {
                    device = mounted;
                }
            }
        }
    }
    if device == 0 {
        return Ok(0);
    }
    let extension = guest::read64(file + 0xD0);
    let filter = if extension != 0 { guest::read64(extension + 0x10) } else { 0 };
    let hint = if filter != 0 { guest::read64(filter) } else { 0 };
    let mut seen = BTreeSet::new();
    let mut top = device;
    while top != 0 {
        if !seen.insert(top) {
            return Err(KernelError::new("cyclic device attachment"));
        }
        if hint != 0 && top == hint {
            return Ok(top);
        }
        let next = guest::read64(top + 0x18);
        if next == 0 {
            return Ok(top);
        }
        top = next;
    }
    Ok(device)
}

/// Trava síncrona do FILE_OBJECT (Busy em +0x74, Waiters em +0x70, Lock em
/// +0x80) dentro de uma região crítica.
pub fn acquire_file(file: u64) -> Result<(), KernelError> {
    critical_region::enter_critical()?;
    if guest::compare_exchange32(file + 0x74, 0, 1)? == 0 {
        return Ok(());
    }
    guest::write32(file + 0x70, guest::read32(file + 0x70).wrapping_add(1));
    let result = (|| -> Result<(), KernelError> {
        while guest::compare_exchange32(file + 0x74, 0, 1)? != 0 {
            dispatcher::wait_for_single_object(file + 0x80, 0, 0, false);
        }
        Ok(())
    })();
    guest::write32(file + 0x70, guest::read32(file + 0x70).wrapping_sub(1));
    result
}

pub fn release_file(file: u64) -> Result<(), KernelError> {
    guest::write32(file + 0x74, 0);
    if guest::read32(file + 0x70) != 0 {
        dispatcher::set_event(file + 0x80);
    }
    critical_region::leave_critical()
}

/// IRP_MJ_QUERY_INFORMATION (ou QUERY_VOLUME_INFORMATION) ao dispositivo
/// relacionado. FsRtlGetFileSize dá precedência a um retorno de despacho com
/// falha; IoQueryFileInformation usa o status imediato ou, depois de
/// STATUS_PENDING, o da conclusão.
#[allow(clippy::too_many_arguments)]
pub fn query_native(file: u64, class: u32, length: u32, buffer: u64, return_length: u64, size_query: bool, volume_query: bool, requestor_mode: u8) -> Result<u32, KernelError> {
    let device = related_device(file)?;
    if device == 0 {
        return Ok(0xC000_0010);
    }
    let scratch = guest::alloc_bytes(48);
    if scratch == 0 {
        return Ok(RESOURCE);
    }
    let mut packet = 0;
    let mut locked = false;
    let mut referenced = false;
    let mut old_hard_error = None;
    let result = (|| -> Result<u32, KernelError> {
        if !size_query {
            referenced = file_objects::reference(file)?.is_some();
            if guest::read32(file + 0x50) & 2 != 0 {
                acquire_file(file)?;
                locked = true;
                dispatcher::clear_event(file + 0x98);
            }
        }
        let event = if locked { file + 0x98 } else { scratch };
        let io_status = scratch + 24;
        if !locked {
            dispatcher::initialize_event(event, if size_query { 0 } else { 1 }, false);
        }
        let count = match guest::read8(device + 0x4C) {
            0 => 1,
            count => count as u32,
        };
        packet = guest::alloc_bytes(irp_builder::size_for(count));
        if packet == 0 {
            return Ok(RESOURCE);
        }
        irp_builder::build(packet, &BuildOptions { major: if volume_query { 10 } else { 5 }, minor: 0, buffer, buffer_length: length, device_object: device, stack_count: count, file_object: file, user_event: event, user_iosb: io_status, thread: process::get_current_thread(), requestor_mode, ..Default::default() });
        let stack = irp_builder::first_stack_location(packet, count);
        let extended = !size_query && requestor_mode == 0 && class == 75;
        guest::write32(stack + 0x10, if extended { 71 } else { class });
        if extended {
            guest::write8(stack + io_stack_location::FLAGS, 1);
        }
        guest::write32(packet + irp::FLAGS, if size_query { 0x42 } else if locked { 0x10 } else { 0x14 });
        if locked {
            guest::write8(packet + 0x47, guest::read8(packet + 0x47) | 2);
        }
        if size_query {
            old_hard_error = Some(thread_io::set_hard_error_mode(0)?);
        }
        let status = io_manager::iof_call_driver(device, packet);
        if status == 0x103 {
            dispatcher::wait_for_single_object(event, 0, 0, false);
        }
        let completed = guest::read32(io_status) as i32;
        let result = if size_query {
            if status < 0 {
                status
            } else {
                completed
            }
        } else if status == 0x103 {
            completed
        } else {
            status
        };
        if locked {
            guest::write32(file + 0x38, completed as u32);
        }
        if return_length != 0 {
            guest::write32(return_length, guest::read32(io_status + 8));
        }
        Ok(result as u32)
    })();
    if let Some(mode) = old_hard_error {
        let _ = thread_io::set_hard_error_mode(mode as u8);
    }
    if packet != 0 {
        guest::free_bytes(packet);
    }
    if locked {
        release_file(file)?;
    }
    if referenced {
        file_objects::dereference(file)?;
    }
    guest::free_bytes(scratch);
    result
}

/// FsRtlGetFileSize: Fast I/O (FastIoQueryStandardInfo) quando o driver tem,
/// senão IRP; diretório devolve STATUS_FILE_IS_A_DIRECTORY.
pub fn get_size(file: u64, output: u64) -> Result<u32, KernelError> {
    let scratch = guest::alloc_bytes(80);
    if scratch == 0 {
        return Ok(RESOURCE);
    }
    let result = (|| -> Result<u32, KernelError> {
        let device = related_device(file)?;
        let status = if device != 0 {
            let driver = guest::read64(device + 8);
            let fast = if driver != 0 { guest::read64(driver + 0x50) } else { 0 };
            let routine = if fast != 0 { guest::read64(fast + 0x28) } else { 0 };
            let handled = routine != 0 && native_call::call(routine, &[file, 1, scratch, scratch + 24, device]) & 0xFF != 0;
            if handled {
                guest::read32(scratch + 24)
            } else {
                query_native(file, 5, 24, scratch, 0, true, false, 0)?
            }
        } else {
            let query = (*OBJECT_QUERY.lock()).ok_or_else(|| KernelError::new("kernel file services unavailable"))?;
            query(file, 5, 24, scratch, scratch + 24)?
        };
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        if guest::read8(scratch + 21) != 0 {
            return Ok(0xC000_00BA);
        }
        guest::write64(output, guest::read64(scratch + 8));
        Ok(status)
    })();
    guest::free_bytes(scratch);
    result
}
