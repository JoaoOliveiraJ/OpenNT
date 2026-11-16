//! Hora do sistema e hora local do Executive: ExSystemTimeToLocalTime,
//! ExLocalTimeToSystemTime e NtSetSystemTime.
//!
//! NtSetSystemTime(SystemTime, PreviousTime) do ntoskrnl 19041 (rva
//! 0x94bc80):
//!
//! - Com SystemTime: SeSystemtimePrivilege (SeSinglePrivilegeCheck no modo
//!   anterior; o RtlCapabilityCheck do SKU multissessão não se aplica) ou
//!   STATUS_PRIVILEGE_NOT_HELD; do modo usuário, SystemTime com alinhamento 4
//!   e sondado para leitura, PreviousTime com alinhamento 4 e sondado para
//!   escrita (o desalinhamento é a exceção STATUS_DATATYPE_MISALIGNMENT).
//!   Uma hora com o DWORD alto acima de 0x20000000 é
//!   STATUS_INVALID_PARAMETER. Sob o ExpTimeRefreshLock, o ExpSetSystemTime:
//!   KeSetSystemTime (KeBootTime e KeBootTimeBias somam o delta), o
//!   ExpRefreshTimeZoneInformation, o relógio da CMOS com a hora local nova
//!   (sem RealTimeIsUniversal) pelo HalSetRealTimeClock e o
//!   PoNotifySystemTimeSet; PreviousTime recebe a hora anterior.
//! - Sem SystemTime (o pedido de releitura, sem privilégio): o
//!   HalQueryRealTimeClock, o ExpRefreshTimeZoneInformation e, sem
//!   RealTimeIsUniversal, o relógio reescrito com a hora local corrente (ou,
//!   com ExpSystemIsInCmosMode, a hora do sistema refeita pelo relógio);
//!   depois o PoNotifySystemTimeSet. Uma leitura que falha é
//!   STATUS_INVALID_PARAMETER.

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::LargeInteger;
use crate::ntos::ke::clock;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::time;

use super::time_zone;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
/// SeSystemtimePrivilege.
const SE_SYSTEMTIME_PRIVILEGE: u64 = 12;

/// Viés do fuso (UTC − local) em unidades de 100 ns: o ExpTimeZoneBias que o
/// NT guarda nos globais do silo e publica em SYSTEM_TIMEOFDAY_INFORMATION.
pub fn time_zone_bias() -> i64 {
    time_zone::time_zone_bias()
}

/// ExpCurrentTimeZoneId dos globais do silo.
pub fn time_zone_id() -> u32 {
    time_zone::time_zone_id()
}

/// ExSystemTimeToLocalTime (RVA 0x32c4f0): *LocalTime = *SystemTime − viés.
pub fn system_time_to_local_time(system_time: u64, local_time: u64) {
    // SAFETY: os PLARGE_INTEGER do chamador (modo kernel).
    let (universal, local_time) = unsafe { (LargeInteger::at(system_time), LargeInteger::at(local_time)) };
    local_time.quad_part.set(universal.quad_part.get().wrapping_sub(time_zone_bias()));
}

/// ExLocalTimeToSystemTime (RVA 0x30cc80): *SystemTime = *LocalTime + viés.
pub fn local_time_to_system_time(local_time: &LargeInteger, system_time: &LargeInteger) {
    system_time.quad_part.set(local_time.quad_part.get().wrapping_add(time_zone_bias()));
}

/// A hora local de um tempo UTC pelo viés corrente (sem
/// RealTimeIsUniversal) ou o próprio tempo.
fn real_time_of(universal: i64) -> i64 {
    if time_zone::real_time_is_universal() { universal } else { universal.wrapping_sub(time_zone_bias()) }
}

/// O relógio da CMOS com a hora `universal` (HalSetRealTimeClock com os
/// campos da hora local).
fn write_real_time_clock(universal: i64) {
    crate::hal::rtc::set_real_time_clock(&time::time_to_fields(real_time_of(universal)));
}

/// ExpSetSystemTime(Both=TRUE, AdjustInterruptTime=FALSE, Reason=1,
/// NewTime): devolve a hora anterior.
fn exp_set_system_time(new_time: i64) -> i64 {
    let old = clock::set_system_time(new_time as u64, 0) as i64;
    time_zone::refresh();
    if !time_zone::system_is_in_cmos_mode() {
        write_real_time_clock(new_time);
    }
    crate::ntos::po::time_change::notify_system_time_set(new_time, old);
    old
}

/// NtSetSystemTime(NULL, NULL): relê o relógio e o fuso; o NTSTATUS.
pub fn refresh_from_real_time_clock() -> u32 {
    let cmos_mode = time_zone::system_is_in_cmos_mode();
    let Some(fields) = crate::hal::rtc::query_real_time_clock() else { return STATUS_INVALID_PARAMETER };
    let Some(real_time) = time::fields_to_time(&fields) else { return STATUS_INVALID_PARAMETER };
    if !time_zone::refresh() {
        return STATUS_INVALID_PARAMETER;
    }
    let current = clock::shared_system_time();
    let mut new_time = current;
    if !time_zone::real_time_is_universal() {
        if cmos_mode {
            // A CMOS manda: a hora do sistema refeita pela hora local dela.
            new_time = real_time.wrapping_add(time_zone_bias());
            clock::set_system_time(new_time as u64, 0);
        } else {
            write_real_time_clock(current);
        }
    }
    crate::ntos::po::time_change::notify_system_time_set(new_time, current);
    0
}

/// NtSetSystemTime(SystemTime, PreviousTime) com o modo anterior
/// (`from_user_mode`); o NTSTATUS.
pub fn set_system_time(system_time: u64, previous_time: u64, from_user_mode: bool) -> u32 {
    if system_time == 0 {
        return refresh_from_real_time_clock();
    }
    if !crate::ntos::se::privilege::single_privilege_check(SE_SYSTEMTIME_PRIVILEGE, from_user_mode as u32) {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    if from_user_mode {
        if system_time & 3 != 0 || previous_time & 3 != 0 {
            return STATUS_DATATYPE_MISALIGNMENT;
        }
        if !crate::ntos::ps::user_probe::probe_user_read(system_time, 1) || (previous_time != 0 && !crate::ntos::ps::user_probe::probe_user_write(previous_time, 8)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    let Ok(new_time) = guest::try_read::<i64>(system_time) else { return STATUS_ACCESS_VIOLATION };
    if (new_time as u64 >> 32) as u32 > 0x2000_0000 {
        return STATUS_INVALID_PARAMETER;
    }
    let old = exp_set_system_time(new_time);
    if previous_time != 0 && guest::try_write::<i64>(previous_time, old).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }
    0
}
