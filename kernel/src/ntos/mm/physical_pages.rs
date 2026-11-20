//! As páginas físicas de usuário (AWE, Address Windowing Extensions) do
//! ntoskrnl 19041: NtAllocateUserPhysicalPages(Ex), NtFreeUserPhysicalPages,
//! NtMapUserPhysicalPages e NtMapUserPhysicalPagesScatter, e a seção de
//! páginas físicas de usuário do NtCreateSectionEx.
//!
//! O OpenNT ainda não tem a AweInfo (as páginas físicas de um processo) nem
//! os VADs AWE (o MEM_PHYSICAL): nenhum processo chega a ter páginas AWE.
//! Os serviços fazem as checagens do 19041 até onde elas dependem disso:
//! - a alocação (MiAllocateUserPhysicalPages 0x8d4c58): os parâmetros
//!   estendidos (só NumaNode e AttributeFlags; os flags fora de 0x2 e 0x8,
//!   ou os dois juntos, e um nó além de KeNumberNodes são
//!   STATUS_INVALID_PARAMETER), o NumberOfPages sondado para escrita (zero é
//!   STATUS_SUCCESS sem nada; acima de 0x1FFFFFFFFFFFFFFF,
//!   STATUS_INVALID_PARAMETER_2), o vetor de PFNs sondado para escrita
//!   (alinhado a 8), o handle (MiReferenceAweHandle: -1 é o processo
//!   corrente; uma seção com SECTION_MAP_WRITE que não é AWE é
//!   STATUS_INVALID_HANDLE; senão um processo com PROCESS_VM_OPERATION) e o
//!   SeLockMemoryPrivilege (STATUS_PRIVILEGE_NOT_HELD). Sem a AweInfo, o
//!   processo que tem o privilégio recebe o mesmo status de quem não o tem
//!   (linha `[awe-boundary]` na serial);
//! - a liberação (0x8d6770): o NumberOfPages sondado, zerado na saída de
//!   modo usuário e recusado quando zero (STATUS_INVALID_PARAMETER_2), o
//!   handle, e o processo sem AweInfo (STATUS_INVALID_PARAMETER_1);
//! - o mapeamento (0x8d6c50) e o espalhado (0x8d6f10): o NumberOfPages
//!   (STATUS_INVALID_PARAMETER_2), os vetores capturados (alinhados a 8 e
//!   sondados) e o endereço fora de um VAD AWE (STATUS_INVALID_PARAMETER_1);
//!   o espalhado com zero páginas é STATUS_SUCCESS.
//!
//! Uma seção de páginas físicas de usuário (o UserPhysicalFlags do
//! NtCreateSectionEx, `mm/section/create`) chega aqui depois das checagens
//! de atributos, proteção e do SeLockMemoryPrivilege: sem o privilégio,
//! STATUS_PRIVILEGE_NOT_HELD, como no MiCreatePagingFileMap (0x61ca30);
//! com ele, a criação para na fronteira (`[awe-boundary]`,
//! STATUS_NOT_SUPPORTED), porque a seção AWE precisa da AweInfo dela.

use alloc::vec::Vec;

use crate::ntos::mm::extended_parameters;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::section::handles::{self as section_handles, Kind};
use crate::ntos::ps::user_probe;
use crate::rtl::KernelError;

const STATUS_SUCCESS: u32 = 0;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
/// O MmUserProbeAddress do 19041.
const USER_PROBE_ADDRESS: u64 = 0x7FFF_FFFF_0000;
/// SECTION_MAP_WRITE e PROCESS_VM_OPERATION, os acessos do
/// MiReferenceAweHandle.
const SECTION_MAP_WRITE: u32 = 0x2;
const PROCESS_VM_OPERATION: u32 = 0x8;
/// SeLockMemoryPrivilege.
const SE_LOCK_MEMORY_PRIVILEGE: u64 = 4;

/// O fim do MiCreatePagingFileMap de uma seção com UserPhysicalFlags:
/// `privileged` é o SeSinglePrivilegeCheck(SeLockMemoryPrivilege).
pub fn user_physical_section(privileged: bool) -> u32 {
    if !privileged {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    debug_print!("[awe-boundary] secao de paginas fisicas de usuario (MiAllocateAweInfo da secao) ainda sem suporte");
    STATUS_NOT_SUPPORTED
}

/// O ProbeForWrite (ou o ProbeForRead) de um vetor de ULONG_PTR de modo
/// usuário: alinhado a 8 e dentro do MmUserProbeAddress.
fn probe_array(address: u64, count: u64, write: bool) -> Result<(), u32> {
    let Some(bytes) = count.checked_mul(8) else { return Err(STATUS_ACCESS_VIOLATION) };
    if bytes == 0 {
        return Ok(());
    }
    if address & 7 != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }
    if address.checked_add(bytes).is_none_or(|end| end > USER_PROBE_ADDRESS) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let present = if write { user_probe::probe_user_write(address, bytes) } else { user_probe::probe_user_read(address, bytes) };
    if !present {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(())
}

/// O MiCaptureUlongPtrArray de um processo de 64 bits: o vetor sondado e
/// copiado.
fn capture_array(address: u64, count: u64) -> Result<Vec<u64>, u32> {
    probe_array(address, count, false)?;
    let bytes = guest::try_read_bytes(address, (count * 8) as usize).map_err(|error| error.status)?;
    Ok(bytes.chunks_exact(8).map(|entry| u64::from_le_bytes(entry.try_into().unwrap_or([0; 8]))).collect())
}

/// O NumberOfPages (PULONG_PTR) de modo usuário: sondado para escrita e lido.
fn read_count(pointer: u64, user: bool) -> Result<u64, u32> {
    if user && !user_probe::probe_user_write(pointer, 8) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    guest::try_read::<u64>(pointer).map_err(|error| error.status)
}

/// MiReferenceAweHandle(Handle, SECTION_MAP_WRITE, PreviousMode): -1 é o
/// processo corrente; uma seção que o handle abre com SECTION_MAP_WRITE e
/// que não é AWE é STATUS_INVALID_HANDLE (o OpenNT não cria seções AWE);
/// senão o processo com PROCESS_VM_OPERATION, ou o status dele.
fn reference_awe_handle(handle: u64, mode: u8) -> Result<(), u32> {
    if handle == u64::MAX {
        return Ok(());
    }
    if let Ok(section) = section_handles::reference(handle, Kind::Section, SECTION_MAP_WRITE, mode) {
        let _ = section.release();
        return Err(STATUS_INVALID_HANDLE);
    }
    let process = section_handles::reference(handle, Kind::Process, PROCESS_VM_OPERATION, mode)?;
    let _ = process.release();
    Ok(())
}

/// NtAllocateUserPhysicalPages(ProcessHandle, NumberOfPages*, UserPfnArray)
/// e o Ex com o vetor de MEM_EXTENDED_PARAMETER.
pub fn allocate(process_handle: u64, count_pointer: u64, pfn_array: u64, parameters: u64, parameter_count: u32, mode: u8) -> Result<u32, KernelError> {
    let user = mode != 0;
    let captured = match extended_parameters::capture_allocate_map(parameters, parameter_count, user, 1 << extended_parameters::NUMA_NODE | 1 << extended_parameters::ATTRIBUTE_FLAGS) {
        Ok(captured) => captured,
        Err(status) => return Ok(status),
    };
    if captured.attribute_flags & !0xA != 0 || captured.attribute_flags & 0xA == 0xA {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if captured.numa_node_plus_one > crate::ntos::ke::processor_group::number_nodes() as u32 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let count = match read_count(count_pointer, user) {
        Ok(count) => count,
        Err(status) => return Ok(status),
    };
    if count == 0 {
        return Ok(STATUS_SUCCESS);
    }
    if count > 0x1FFF_FFFF_FFFF_FFFF {
        return Ok(STATUS_INVALID_PARAMETER_2);
    }
    if user {
        if let Err(status) = probe_array(pfn_array, count, true) {
            return Ok(status);
        }
    }
    if let Err(status) = reference_awe_handle(process_handle, mode) {
        return Ok(status);
    }
    if crate::ntos::se::privilege::single_privilege_check(SE_LOCK_MEMORY_PRIVILEGE, mode as u32) {
        debug_print!("[awe-boundary] NtAllocateUserPhysicalPages de {:#x} paginas: o OpenNT ainda nao tem a AweInfo do processo", count);
    }
    Ok(STATUS_PRIVILEGE_NOT_HELD)
}

/// NtFreeUserPhysicalPages(ProcessHandle, NumberOfPages*, UserPfnArray).
pub fn free(process_handle: u64, count_pointer: u64, _pfn_array: u64, mode: u8) -> Result<u32, KernelError> {
    let user = mode != 0;
    let count = match read_count(count_pointer, user) {
        Ok(count) => count,
        Err(status) => return Ok(status),
    };
    if user {
        let _ = guest::try_write::<u64>(count_pointer, 0);
    }
    if count == 0 {
        return Ok(STATUS_INVALID_PARAMETER_2);
    }
    if let Err(status) = reference_awe_handle(process_handle, mode) {
        return Ok(status);
    }
    // O processo não tem AweInfo (nenhuma alocação AWE no OpenNT).
    Ok(STATUS_INVALID_PARAMETER_1)
}

/// NtMapUserPhysicalPages(VirtualAddress, NumberOfPages, UserPfnArray).
pub fn map(_virtual_address: u64, count: u64, pfn_array: u64) -> Result<u32, KernelError> {
    if count.wrapping_sub(1) > 0xF_FFFF_FFFF_FFFE {
        return Ok(STATUS_INVALID_PARAMETER_2);
    }
    if pfn_array != 0 {
        if let Err(status) = capture_array(pfn_array, count) {
            return Ok(status);
        }
    }
    // MiGetAweNode: nenhum VAD AWE no processo.
    Ok(STATUS_INVALID_PARAMETER_1)
}

/// NtMapUserPhysicalPagesScatter(VirtualAddresses, NumberOfPages,
/// UserPfnArray).
pub fn map_scatter(virtual_addresses: u64, count: u64, pfn_array: u64) -> Result<u32, KernelError> {
    if count > 0xF_FFFF_FFFF_FFFF {
        return Ok(STATUS_INVALID_PARAMETER_2);
    }
    if let Err(status) = capture_array(virtual_addresses, count) {
        return Ok(status);
    }
    if count == 0 {
        return Ok(STATUS_SUCCESS);
    }
    if pfn_array != 0 {
        if let Err(status) = capture_array(pfn_array, count) {
            return Ok(status);
        }
    }
    // MiGetAweNode do primeiro endereço: nenhum VAD AWE no processo.
    Ok(STATUS_INVALID_PARAMETER_1)
}
