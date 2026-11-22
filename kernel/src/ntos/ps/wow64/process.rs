//! O processo WoW64: o EWOW64PROCESS e os parâmetros de 32 bits.
//!
//! - [`machine_supported`] é o PsWow64IsMachineSupported (19041 0x6c7650):
//!   uma máquina WoW64 só é aceita com a DLL de sistema dela presente
//!   (PsQuerySystemDllInfo); aqui, a i386 com a ntdll de SysWOW64.
//! - [`allocate`] é o ramo WoW64 do PspAllocateProcess (0x704c85): para uma
//!   imagem i386 suportada, o EWOW64PROCESS (0x10 bytes do pool, 'WowP'), com
//!   Machine = IMAGE_FILE_MACHINE_I386, NtdllType = PsWowX86SystemDll (o
//!   PspWow64PickBestNtdll da máquina) e Peb = 1 até o MiInitializeWowPeb
//!   gravar a PEB de 32 bits; o PspProcessDelete o devolve ([`delete`]).
//! - [`thunk_process_parameters`] é o PspWow64ThunkProcessParameters
//!   (0x32068c), chamado pelo PspWow64SetupUserProcessAddressSpace depois da
//!   cópia dos parâmetros nativos: um bloco RTL_USER_PROCESS_PARAMETERS32
//!   novo no processo (anexado), abaixo do HighestUserAddress dele, com os
//!   campos escalares truncados para 32 bits, cada UNICODE_STRING copiada
//!   depois da estrutura (Length/MaximumLength e os MaximumLength bytes, na
//!   ordem CurrentDirectory, DllPath, ImagePathName, CommandLine,
//!   WindowTitle, DesktopInfo, ShellInfo, RedirectionDllName e
//!   HeapPartitionName), o RuntimeData convertido (a contagem, os bytes de
//!   flags e os handles de 64 para 32 bits), as máscaras de CPU do pool de
//!   threads e o ambiente no fim; o PEB32.ProcessParameters recebe o bloco.

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_wow64::RtlUserProcessParameters32;
use crate::ntos::inc::types::{Eprocess, Ewow64process, Peb32, RtlUserProcessParameters, String32, SystemDllType, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user::memory;
use crate::rtl::KernelError;

use super::MACHINE_I386;

/// STATUS_INSUFFICIENT_RESOURCES.
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// PsWow64IsMachineSupported: a i386 com a DLL de sistema do WoW64 x86.
pub fn machine_supported(machine: u16) -> bool {
    machine == MACHINE_I386 && super::system_dll::present()
}

/// O EWOW64PROCESS de um processo novo cuja imagem é x86 (o PspAllocateProcess
/// antes do MmInitializeProcessAddressSpace).
pub fn allocate(process: u64) -> Result<(), KernelError> {
    let block = guest::alloc_bytes(Ewow64process::SIZE);
    if block == 0 {
        return Err(KernelError::with_status("EWOW64PROCESS sem pool", STATUS_INSUFFICIENT_RESOURCES));
    }
    guest::write_bytes(block, &[0; Ewow64process::SIZE as usize]);
    // SAFETY: o bloco acabou de sair do pool; o EPROCESS está em montagem.
    let wow64 = unsafe { Ewow64process::at(block) };
    wow64.machine.set(MACHINE_I386);
    wow64.ntdll_type.set(SystemDllType::PS_WOW_X86_SYSTEM_DLL);
    // Peb = 1 marca o processo WoW64 até a PEB de 32 bits existir, como no
    // PspAllocateProcess.
    wow64.peb.set(1);
    // SAFETY: o EPROCESS em montagem, retido pelo chamador.
    unsafe { Eprocess::at(process) }.wo_w64_process.set(block);
    Ok(())
}

/// O PspProcessDelete: o EWOW64PROCESS volta ao pool.
pub fn delete(process: u64) {
    // SAFETY: o EPROCESS no último dereference.
    let eprocess = unsafe { Eprocess::at(process) };
    let block = eprocess.wo_w64_process.get();
    if block != 0 {
        eprocess.wo_w64_process.set(0);
        guest::free_bytes(block);
    }
}

/// Copia `source` para o cursor (o PspWow64CopyUnicodeString): os
/// tamanhos e, com Buffer, os MaximumLength bytes no cursor, que avança.
fn copy_string(cursor: &mut u64, destination: &String32, source: &UnicodeString) {
    destination.length.set(source.length.get());
    destination.maximum_length.set(source.maximum_length.get());
    let buffer = source.buffer.get();
    if buffer == 0 {
        destination.buffer.set(0);
        return;
    }
    destination.buffer.set(*cursor as u32);
    let length = source.maximum_length.get() as u64;
    guest::write_bytes(*cursor, &guest::read_bytes(buffer, length as usize));
    *cursor += length;
}

/// Os bytes que o bloco de 32 bits ocupa a menos que o nativo (os campos de
/// 64 bits): 0x180, ou 0x17C com máscaras de CPU (o alinhamento delas).
fn size_reduction(native: &RtlUserProcessParameters) -> u64 {
    if native.default_threadpool_cpu_set_mask_count.get() != 0 { 0x17C } else { 0x180 }
}

/// O PspWow64ThunkProcessParameters no processo corrente (o novo,
/// anexado): o bloco de 32 bits de `parameters` (o bloco nativo, já
/// normalizado) e o PEB32.ProcessParameters. Devolve a VA do bloco.
pub fn thunk_process_parameters(peb32: u64, parameters: u64) -> Result<u64, KernelError> {
    // SAFETY: o bloco nativo gravado agora no processo corrente.
    let native = unsafe { RtlUserProcessParameters::at(parameters) };
    let environment_offset = native.maximum_length.get() as u64 - size_reduction(native);
    let environment_size = native.environment_size.get();
    let size = environment_offset + environment_size;
    let block = memory::map_user_region(size)?;
    // SAFETY: região recém-comprometida no processo corrente; o código de
    // usuário dele ainda não roda.
    let thunked = unsafe { RtlUserProcessParameters32::at(block) };
    let mut cursor = block + RtlUserProcessParameters32::SIZE;
    let environment = block + environment_offset;
    thunked.maximum_length.set(size as u32);
    thunked.length.set(size as u32);
    thunked.flags.set(native.flags.get());
    thunked.debug_flags.set(native.debug_flags.get());
    thunked.console_handle.set(native.console_handle.get() as u32);
    thunked.console_flags.set(native.console_flags.get());
    thunked.standard_input.set(native.standard_input.get() as u32);
    thunked.standard_output.set(native.standard_output.get() as u32);
    thunked.standard_error.set(native.standard_error.get() as u32);
    thunked.starting_x.set(native.starting_x.get());
    thunked.starting_y.set(native.starting_y.get());
    thunked.count_x.set(native.count_x.get());
    thunked.count_y.set(native.count_y.get());
    thunked.count_chars_x.set(native.count_chars_x.get());
    thunked.count_chars_y.set(native.count_chars_y.get());
    thunked.fill_attribute.set(native.fill_attribute.get());
    thunked.window_flags.set(native.window_flags.get());
    thunked.show_window_flags.set(native.show_window_flags.get());
    thunked.loader_threads.set(native.loader_threads.get());
    thunked.default_threadpool_thread_maximum.set(native.default_threadpool_thread_maximum.get());
    copy_string(&mut cursor, &thunked.current_directory_dos_path, &native.current_directory.dos_path);
    thunked.current_directory_handle.set(native.current_directory.handle.get() as u32);
    copy_string(&mut cursor, &thunked.dll_path, &native.dll_path);
    copy_string(&mut cursor, &thunked.image_path_name, &native.image_path_name);
    copy_string(&mut cursor, &thunked.command_line, &native.command_line);
    copy_string(&mut cursor, &thunked.window_title, &native.window_title);
    copy_string(&mut cursor, &thunked.desktop_info, &native.desktop_info);
    copy_string(&mut cursor, &thunked.shell_info, &native.shell_info);
    copy_string(&mut cursor, &thunked.redirection_dll_name, &native.redirection_dll_name);
    copy_string(&mut cursor, &thunked.heap_partition_name, &native.heap_partition_name);
    thunk_runtime_data(&mut cursor, thunked, native);
    let mask_count = native.default_threadpool_cpu_set_mask_count.get();
    if mask_count != 0 {
        thunked.default_threadpool_cpu_set_mask_count.set(mask_count);
        let masks = (cursor + 3) & !3;
        thunked.default_threadpool_cpu_set_masks.set(masks as u32);
        guest::write_bytes(masks, &guest::read_bytes(native.default_threadpool_cpu_set_masks.get(), mask_count as usize * 8));
    }
    thunked.environment.set(environment as u32);
    thunked.environment_size.set(environment_size as u32);
    thunked.environment_version.set(native.environment_version.get() as u32);
    guest::write_bytes(environment, &guest::read_bytes(native.environment.get(), environment_size as usize));
    thunked.process_group_id.set(native.process_group_id.get());
    // SAFETY: a PEB de 32 bits recém-criada no processo corrente.
    unsafe { Peb32::at(peb32) }.process_parameters.set(block as u32);
    Ok(block)
}

/// O RuntimeData (as informações de handles do CRT): com Length, o ULONG da
/// contagem N, os N bytes de flags e os N handles, de 64 para 32 bits; uma
/// cópia que não cabe no formato fica como os bytes brutos.
fn thunk_runtime_data(cursor: &mut u64, thunked: &RtlUserProcessParameters32, native: &RtlUserProcessParameters) {
    let length = native.runtime_data.length.get() as u64;
    let buffer = native.runtime_data.buffer.get();
    if length == 0 || buffer == 0 {
        return;
    }
    thunked.runtime_data.buffer.set(*cursor as u32);
    let count = if length >= 4 { guest::read32(buffer) as u64 } else { 0 };
    let converted = count * 9 + 4;
    if length < converted {
        guest::write_bytes(*cursor, &guest::read_bytes(buffer, length as usize));
        thunked.runtime_data.length.set(length as u16);
    } else {
        guest::write_bytes(*cursor, &guest::read_bytes(buffer, (count + 4) as usize));
        let handles = buffer + 4 + count;
        let target = *cursor + 4 + count;
        for index in 0..count {
            guest::write32(target + index * 4, guest::read64(handles + index * 8) as u32);
        }
        let rest = length - converted;
        guest::write_bytes(target + count * 4, &guest::read_bytes(handles + count * 8, rest as usize));
        thunked.runtime_data.length.set((count * 5 + 4 + rest) as u16);
    }
    thunked.runtime_data.maximum_length.set(thunked.runtime_data.length.get());
    *cursor += thunked.runtime_data.length.get() as u64;
}
