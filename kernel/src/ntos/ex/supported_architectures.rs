//! SystemSupportedProcessorArchitectures (classe 181 do
//! NtQuerySystemInformationEx).
//!
//! A entrada é um HANDLE de processo (opcional); a saída, o vetor de
//! SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION que o
//! PsWow64GetSupportedArchitectures do NT monta, terminado por um ULONG
//! zero: em cada ULONG, a máquina (IMAGE_FILE_MACHINE_*) nos 16 bits baixos e
//! os bits KernelMode (16), UserMode (17), Native (18) e Process (19, a
//! máquina do processo dado). A primeira entrada é sempre a AMD64 nativa
//! (kernel, usuário e nativa); as de WoW64 (i386, ARM) só entram quando o
//! PsWow64IsMachineSupported as reconhece: aqui a i386 (só UserMode), quando
//! a ntdll de 32 bits de SysWOW64 está no volume (`ps::wow64`). O bit
//! Process vai na entrada da máquina do processo dado (EWOW64PROCESS.Machine,
//! ou a nativa); sem processo, em nenhuma. Um buffer menor recebe
//! STATUS_BUFFER_TOO_SMALL com o tamanho em ReturnLength (o smss pergunta
//! primeiro com buffer nulo).

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user_probe;
use crate::rtl::KernelError;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const IMAGE_FILE_MACHINE_AMD64: u32 = 0x8664;
const IMAGE_FILE_MACHINE_I386: u32 = 0x14C;
const KERNEL_MODE: u32 = 1 << 16;
const USER_MODE: u32 = 1 << 17;
const NATIVE: u32 = 1 << 18;
const PROCESS: u32 = 1 << 19;

/// A consulta de modo usuário: `input`/`input_length` (o HANDLE opcional),
/// o buffer de saída e o PULONG ReturnLength. `process_of` resolve o handle
/// (PROCESS_QUERY_LIMITED_INFORMATION) para o EPROCESS.
pub fn query(input: u64, input_length: u64, output: u64, length: u64, returned: u64, process_of: impl Fn(u64) -> Result<u64, u32>) -> Result<u32, KernelError> {
    let handle = match input_length {
        0 => 0,
        8 => {
            if !user_probe::probe_user_read(input, 8) {
                return Ok(STATUS_ACCESS_VIOLATION);
            }
            guest::try_read::<u64>(input)?
        }
        _ => return Ok(STATUS_INVALID_PARAMETER),
    };
    if (length != 0 && !user_probe::probe_user_write(output, length)) || (returned != 0 && !user_probe::probe_user_write(returned, 4)) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let process = if handle == 0 {
        None
    } else {
        match process_of(handle) {
            Ok(process) => Some(process),
            Err(status) => return Ok(status),
        }
    };
    // A máquina do processo dado (o EWOW64PROCESS.Machine, ou a nativa)
    // recebe o bit Process; sem processo, nenhuma.
    let machine = process.map(|process| crate::ntos::ps::process_accessors::wow64_machine(process) as u32);
    let process_bit = |entry: u32| if machine == Some(entry) { PROCESS } else { 0 };
    let native = IMAGE_FILE_MACHINE_AMD64 | KERNEL_MODE | USER_MODE | NATIVE | process_bit(IMAGE_FILE_MACHINE_AMD64);
    let mut entries = alloc::vec![native];
    // O WoW64 x86 só modo usuário, com a ntdll de 32 bits presente.
    if crate::ntos::ps::wow64::process::machine_supported(IMAGE_FILE_MACHINE_I386 as u16) {
        entries.push(IMAGE_FILE_MACHINE_I386 | USER_MODE | process_bit(IMAGE_FILE_MACHINE_I386));
    }
    entries.push(0);
    let required = (entries.len() * 4) as u64;
    if returned != 0 {
        guest::try_write::<u32>(returned, required as u32)?;
    }
    if length < required {
        return Ok(STATUS_BUFFER_TOO_SMALL);
    }
    let bytes: alloc::vec::Vec<u8> = entries.iter().flat_map(|entry| entry.to_le_bytes()).collect();
    guest::try_write_bytes(output, &bytes)?;
    Ok(0)
}
