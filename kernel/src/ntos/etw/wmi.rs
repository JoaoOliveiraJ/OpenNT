//! Saída de rastreamento WMI do ntoskrnl (WmiTraceMessage e
//! WmiQueryTraceInformation).
//!
//! As limitações estão descritas em cada operação.

use crate::ntos::inc::types::{Field, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

/// WmiTraceMessage(handle, level, guid, msgId, fmt, ...): texto formatado
/// para a serial com os quatro primeiros argumentos variáveis.
pub fn trace_message(format: u64, arguments: [u64; 4]) -> Result<(), KernelError> {
    let format_text = guest_strings::read_c_string(format);
    let text = guest_strings::format_guest_text(&format_text, &mut |index| arguments.get(index).copied().unwrap_or(0), false)?;
    let text = text.strip_suffix('\n').map(|rest| rest.strip_suffix('\r').unwrap_or(rest)).unwrap_or(&text);
    debug_print!("[wmitrace] {}", text);
    Ok(())
}

/// WmiQueryTraceInformation(class, buffer, length, &required, ...): zera até
/// 0x30 bytes em palavras de quatro bytes, sem distinguir classes.
pub fn query_trace_information(buffer: u64, length: u32, required_out: u64) {
    let reported = length.min(0x30);
    // Zera em DWORDs inteiros, como antes (um resto menor que 4 também).
    guest::write_bytes(buffer, &alloc::vec![0u8; reported.div_ceil(4) as usize * 4]);
    if required_out != 0 {
        // SAFETY: PULONG de saída do driver.
        unsafe { Field::<u32>::at(required_out) }.set(reported);
    }
}

// ---- Relógio do WMI/ETW (WmiGetClock, ntoskrnl 19041 0x5a66a0) ----------------
//
// WmiGetClock(ClockType, Context) -> LARGE_INTEGER, Context ignorado:
//   0 WMICT_DEFAULT    : o relógio da sessão 0 no estado ETW do silo
//                        (byte em EtwSiloState + 0x1071): 2 = hora do sistema,
//                        3 = ciclos (rdtsc), qualquer outro = contador de
//                        desempenho. Sem sessão 0 configurada o byte é 0, que
//                        cai no contador de desempenho — o caso do OpenNT, cujo
//                        logger não usa a entrada 0.
//   1 WMICT_SYSTEMTIME : RtlGetSystemTimePrecise (também ClockType < 0 e > 5);
//   2 WMICT_PERFCOUNTER: KeQueryPerformanceCounter(NULL);
//   3 WMICT_PROCESS, 4 WMICT_THREAD: 0;
//   5 WMICT_CPUCYCLE   : rdtsc.

/// Relógio da entrada 0 do estado ETW: nenhuma sessão o configura no OpenNT.
const DEFAULT_SESSION_CLOCK: u8 = 0;

fn wmi_performance_counter() -> u64 {
    // KeQueryPerformanceCounter do OpenNT: o TSC.
    crate::hal::cpu::rdtsc()
}

/// WmiGetClock.
pub fn get_clock(clock_type: u32, _context: u64) -> u64 {
    match clock_type as i32 {
        0 => match DEFAULT_SESSION_CLOCK {
            2 => crate::ntos::ke::clock::system_time_100ns(),
            3 => crate::hal::cpu::rdtsc(),
            _ => wmi_performance_counter(),
        },
        2 => wmi_performance_counter(),
        3 | 4 => 0,
        5 => crate::hal::cpu::rdtsc(),
        _ => crate::ntos::ke::clock::system_time_100ns(),
    }
}
