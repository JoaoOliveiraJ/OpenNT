//! O fuso horário do Executive: o RTL_DYNAMIC_TIME_ZONE_INFORMATION do
//! Registro, ExpTimeZoneBias/ExpCurrentTimeZoneId, os campos de fuso da
//! KUSER_SHARED_DATA e as classes de fuso do Nt{Query,Set}SystemInformation.
//!
//! - A leitura do Registro é o RtlpQueryTimeZoneInformationWorker do
//!   ntoskrnl 19041 (rva 0x714104): em
//!   `\Registry\Machine\System\CurrentControlSet\Control\TimeZoneInformation`,
//!   Bias, StandardName (até 32 WCHARs com o NUL), StandardBias,
//!   StandardStart (TIME_FIELDS binário de 16 bytes), DaylightName,
//!   DaylightBias, DaylightStart e, na forma dinâmica (0x1B0 bytes),
//!   TimeZoneKeyName e DynamicDaylightTimeDisabled (DWORD que vira o
//!   BOOLEAN). A gravação é o RtlpSetTimeZoneInformationWorker (rva
//!   0x91507c): nomes com menos de 32 caracteres (a chave, de 128) ou
//!   STATUS_INVALID_PARAMETER, os mesmos valores e, na forma de 0xAC, um
//!   TimeZoneKeyName vazio.
//! - O ExpRefreshTimeZoneInformation (rva 0x7a98a4): com o fuso lido, a hora
//!   local é SystemTime − o viés corrente; sem StandardStart.Month ou
//!   DaylightStart.Month o fuso não tem horário de verão
//!   (TIME_ZONE_ID_UNKNOWN, viés = Bias); senão as duas datas de troca do ano
//!   (RtlCutoverTimeToSystemTime) dizem se vale o padrão (1, Bias +
//!   StandardBias) ou o de verão (2, Bias + DaylightBias) e qual é a próxima
//!   troca. Um viés novo (em minutos, ExpLastTimeZoneBias) publica
//!   WNF_SEB_TIME_ZONE_CHANGE; ExpTimeZoneBias = minutos × 60 × 10^7;
//!   KUSER_SHARED_DATA.TimeZoneId (RtlSetSystemGlobalData) e, entre dois
//!   incrementos de TimeZoneBiasStamp, TimeZoneBias e
//!   TimeZoneBiasEffectiveStart/End (a hora UTC da atualização e a próxima
//!   troca, ou o primeiro dia do ano seguinte menos 1 ms); sem
//!   RealTimeIsUniversal o viés vai ao valor ActiveTimeBias
//!   (RtlSetActiveTimeBias). Os timers da próxima troca e do ano novo
//!   refazem a leitura quando vencem ([`check_cutover`]). O
//!   RtlpCheckDynamicTimeZoneInformation (regras por ano em SOFTWARE\...\Time
//!   Zones\<chave>\Dynamic DST) não tem a chave na hive SOFTWARE do boot e
//!   não muda nada.
//! - A hora do relógio da CMOS é local (sem RealTimeIsUniversal): o NT lê
//!   ActiveTimeBias e RealTimeIsUniversal pelo CmControlVector já na fase 0
//!   e interpreta o relógio com esse viés; o OpenNT só tem a hive na fase 1,
//!   e [`initialize`] faz ali as duas coisas, na ordem do NT: a hora do boot
//!   pelo relógio com o ActiveTimeBias (KeSetSystemTime com o bit 2, que
//!   refaz KeBootTime) e o ExpRefreshTimeZoneInformation, que, com um viés
//!   diferente do ActiveTimeBias, reescreve o relógio pelo
//!   NtSetSystemTime(NULL, NULL) do Phase1InitializationDiscard.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};

use crate::ntos::cm::registry;
use crate::ntos::inc::types::{Field, NtStruct, RtlDynamicTimeZoneInformation, RtlTimeZoneInformation};
use crate::ntos::ke::clock;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::time::{self, Fields};
use crate::rtl::SpinLock;

/// A chave do fuso.
pub const TIME_ZONE_KEY: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\TimeZoneInformation";
/// Tamanhos do RTL_TIME_ZONE_INFORMATION e do RTL_DYNAMIC_TIME_ZONE_INFORMATION.
pub const TIME_ZONE_INFORMATION_SIZE: usize = 0xAC;
pub const DYNAMIC_TIME_ZONE_INFORMATION_SIZE: usize = 0x1B0;
/// TIME_ZONE_ID_UNKNOWN, _STANDARD e _DAYLIGHT.
pub const TIME_ZONE_ID_UNKNOWN: u32 = 0;
pub const TIME_ZONE_ID_STANDARD: u32 = 1;
pub const TIME_ZONE_ID_DAYLIGHT: u32 = 2;
/// WNF_SEB_TIME_ZONE_CHANGE do ntoskrnl 19041.
pub const WNF_SEB_TIME_ZONE_CHANGE: u64 = 0x4184_0B3E_A3BC_3875;
/// 100 ns por minuto.
const MINUTE: i64 = 60 * 10_000_000;

const REG_SZ: u32 = 1;
const REG_BINARY: u32 = 3;
const REG_DWORD: u32 = 4;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// SeTimeZonePrivilege.
const SE_TIME_ZONE_PRIVILEGE: u64 = 34;

/// ExpTimeZoneBias (100 ns), ExpLastTimeZoneBias (minutos) e
/// ExpCurrentTimeZoneId.
static TIME_ZONE_BIAS: AtomicI64 = AtomicI64::new(0);
static LAST_TIME_ZONE_BIAS: AtomicI64 = AtomicI64::new(0);
static CURRENT_TIME_ZONE_ID: AtomicU32 = AtomicU32::new(TIME_ZONE_ID_UNKNOWN);
/// ExpRealTimeIsUniversal e ExpSystemIsInCmosMode.
static REAL_TIME_IS_UNIVERSAL: AtomicBool = AtomicBool::new(false);
static SYSTEM_IS_IN_CMOS_MODE: AtomicBool = AtomicBool::new(false);
/// A próxima troca e o ano novo em UTC (u64::MAX: sem prazo).
static NEXT_CUTOVER: AtomicU64 = AtomicU64::new(u64::MAX);
static NEXT_YEAR: AtomicU64 = AtomicU64::new(u64::MAX);
/// O fuso em vigor (a cópia do silo, ExpTimeZoneInformation), em bytes.
static INFORMATION: SpinLock<[u8; DYNAMIC_TIME_ZONE_INFORMATION_SIZE]> = SpinLock::new([0; DYNAMIC_TIME_ZONE_INFORMATION_SIZE]);
/// ExpTimeRefreshLock: uma leitura/troca de fuso por vez.
static REFRESH_LOCK: SpinLock<()> = SpinLock::new(());

/// ExpTimeZoneBias: UTC − hora local, em 100 ns.
pub fn time_zone_bias() -> i64 {
    TIME_ZONE_BIAS.load(Ordering::Relaxed)
}

/// ExpCurrentTimeZoneId.
pub fn time_zone_id() -> u32 {
    CURRENT_TIME_ZONE_ID.load(Ordering::Relaxed)
}

/// ExpLastTimeZoneBias, em minutos.
pub fn last_time_zone_bias_minutes() -> i32 {
    LAST_TIME_ZONE_BIAS.load(Ordering::Relaxed) as i32
}

/// ExRealTimeIsUniversal (rva 0x30d030): o relógio da CMOS guarda UTC.
pub fn real_time_is_universal() -> bool {
    REAL_TIME_IS_UNIVERSAL.load(Ordering::Relaxed)
}

/// ExpSystemIsInCmosMode: a última leitura do fuso falhou e o relógio da
/// CMOS manda na hora.
pub fn system_is_in_cmos_mode() -> bool {
    SYSTEM_IS_IN_CMOS_MODE.load(Ordering::Relaxed)
}

/// O fuso em vigor (os 0x1B0 bytes do RTL_DYNAMIC_TIME_ZONE_INFORMATION).
pub fn current_information() -> [u8; DYNAMIC_TIME_ZONE_INFORMATION_SIZE] {
    *INFORMATION.lock()
}

/// A visão tipada de um buffer local do tamanho do fuso dinâmico.
fn view(bytes: &mut [u8; DYNAMIC_TIME_ZONE_INFORMATION_SIZE]) -> &'static RtlDynamicTimeZoneInformation {
    // SAFETY: buffer local de 0x1B0 bytes, vivo enquanto a visão é usada
    // dentro da função chamadora.
    unsafe { RtlDynamicTimeZoneInformation::at(bytes.as_mut_ptr() as u64) }
}

fn dword(data: &[u8]) -> u32 {
    let mut bytes = [0u8; 4];
    for (target, source) in bytes.iter_mut().zip(data) {
        *target = *source;
    }
    u32::from_le_bytes(bytes)
}

/// Um valor do fuso com o tipo exigido (o TYPECHECK do
/// RtlQueryRegistryValues); ausente, `None`.
fn read_value(name: &str, value_type: u32) -> Result<Option<Vec<u8>>, u32> {
    match registry::read_value_by_path(TIME_ZONE_KEY, name) {
        Some(value) if value.value_type != value_type => Err(STATUS_OBJECT_TYPE_MISMATCH),
        Some(value) => Ok(Some(value.data)),
        None => Ok(None),
    }
}

/// Copia um REG_SZ para o vetor de WCHARs (com o NUL; maior que o buffer é
/// STATUS_BUFFER_TOO_SMALL, como a UNICODE_STRING direta).
fn copy_name(target: &[Field<u16>], data: &[u8]) -> Result<(), u32> {
    let mut units: Vec<u16> = data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    while units.last() == Some(&0) {
        units.pop();
    }
    if units.len() + 1 > target.len() {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    for (index, cell) in target.iter().enumerate() {
        cell.set(units.get(index).copied().unwrap_or(0));
    }
    Ok(())
}

/// RtlpQueryTimeZoneInformationWorker: o fuso do Registro (`dynamic`: os
/// 0x1B0 bytes com a chave e o DynamicDaylightTimeDisabled).
pub fn query_registry(dynamic: bool) -> Result<[u8; DYNAMIC_TIME_ZONE_INFORMATION_SIZE], u32> {
    if registry::node_by_path(TIME_ZONE_KEY).is_none() {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    }
    let mut bytes = [0u8; DYNAMIC_TIME_ZONE_INFORMATION_SIZE];
    let information = view(&mut bytes);
    let zone = &information.tzi;
    // Os TIME_FIELDS de valor binário começam com o tamanho negativo (-16)
    // no primeiro ULONG; um valor ausente o deixa lá.
    zone.standard_start.year.set(-16);
    zone.standard_start.month.set(-1);
    zone.daylight_start.year.set(-16);
    zone.daylight_start.month.set(-1);
    if let Some(data) = read_value("Bias", REG_DWORD)? {
        zone.bias.set(dword(&data) as i32);
    }
    if let Some(data) = read_value("StandardName", REG_SZ)? {
        copy_name(&zone.standard_name, &data)?;
    }
    if let Some(data) = read_value("StandardBias", REG_DWORD)? {
        zone.standard_bias.set(dword(&data) as i32);
    }
    if let Some(data) = read_value("StandardStart", REG_BINARY)? {
        Fields::from_bytes(&data[..data.len().min(16)]).write(&zone.standard_start);
    }
    if let Some(data) = read_value("DaylightName", REG_SZ)? {
        copy_name(&zone.daylight_name, &data)?;
    }
    if let Some(data) = read_value("DaylightBias", REG_DWORD)? {
        zone.daylight_bias.set(dword(&data) as i32);
    }
    if let Some(data) = read_value("DaylightStart", REG_BINARY)? {
        Fields::from_bytes(&data[..data.len().min(16)]).write(&zone.daylight_start);
    }
    if dynamic {
        if let Some(data) = read_value("TimeZoneKeyName", REG_SZ)? {
            copy_name(&information.time_zone_key_name, &data)?;
        }
        let disabled = read_value("DynamicDaylightTimeDisabled", REG_DWORD)?.map_or(0, |data| dword(&data));
        information.dynamic_daylight_time_disabled.set((disabled != 0) as u8);
    }
    Ok(bytes)
}

fn name_units(cells: &[Field<u16>]) -> Vec<u16> {
    cells.iter().map(|cell| cell.get()).take_while(|&unit| unit != 0).collect()
}

fn sz(units: &[u16]) -> Vec<u8> {
    units.iter().chain(core::iter::once(&0)).flat_map(|unit| unit.to_le_bytes()).collect()
}

/// RtlpSetTimeZoneInformationWorker: grava o fuso (`size` 0xAC ou 0x1B0) no
/// Registro; o NTSTATUS.
pub fn write_registry(bytes: &[u8; DYNAMIC_TIME_ZONE_INFORMATION_SIZE], size: usize) -> u32 {
    let mut copy = *bytes;
    let information = view(&mut copy);
    let zone = &information.tzi;
    let standard = name_units(&zone.standard_name);
    let daylight = name_units(&zone.daylight_name);
    let key = name_units(&information.time_zone_key_name);
    if standard.len() >= 32 || daylight.len() >= 32 || (size >= DYNAMIC_TIME_ZONE_INFORMATION_SIZE && key.len() >= 128) {
        return STATUS_INVALID_PARAMETER;
    }
    let Ok(handle) = registry::open_or_create(TIME_ZONE_KEY, None) else { return STATUS_OBJECT_NAME_NOT_FOUND };
    let key_name = if size >= DYNAMIC_TIME_ZONE_INFORMATION_SIZE { sz(&key) } else { sz(&[]) };
    let values: [(&str, u32, Vec<u8>); 9] = [
        ("Bias", REG_DWORD, (zone.bias.get() as u32).to_le_bytes().to_vec()),
        ("StandardName", REG_SZ, sz(&standard)),
        ("StandardBias", REG_DWORD, (zone.standard_bias.get() as u32).to_le_bytes().to_vec()),
        ("StandardStart", REG_BINARY, Fields::read(&zone.standard_start).to_bytes().to_vec()),
        ("DaylightName", REG_SZ, sz(&daylight)),
        ("DaylightBias", REG_DWORD, (zone.daylight_bias.get() as u32).to_le_bytes().to_vec()),
        ("DaylightStart", REG_BINARY, Fields::read(&zone.daylight_start).to_bytes().to_vec()),
        ("TimeZoneKeyName", REG_SZ, key_name),
        ("DynamicDaylightTimeDisabled", REG_DWORD, (information.dynamic_daylight_time_disabled.get() as u32).to_le_bytes().to_vec()),
    ];
    let written = values.into_iter().all(|(name, value_type, data)| registry::set_value(handle, name, value_type, data));
    registry::close_handle(handle);
    if written { 0 } else { STATUS_INSUFFICIENT_RESOURCES }
}

/// Publica o viés (WNF_SEB_TIME_ZONE_CHANGE com os 8 bytes 0 e 0xFFFFFFFF
/// que o NT grava).
fn publish_bias_change() {
    let name = guest::alloc_bytes(16);
    if name == 0 {
        return;
    }
    guest::write64(name, WNF_SEB_TIME_ZONE_CHANGE);
    guest::write32(name + 8, 0);
    guest::write32(name + 12, 0xFFFF_FFFF);
    let _ = crate::ntos::ex::wnf::service::update(name, name + 8, 8, 0, 0, 0, false);
    guest::free_bytes(name);
}

/// RtlSetActiveTimeBias: o ActiveTimeBias do Registro, só quando muda.
fn set_active_time_bias(minutes: i32) {
    let current = registry::read_value_by_path(TIME_ZONE_KEY, "ActiveTimeBias").filter(|value| value.value_type == REG_DWORD).map(|value| dword(&value.data) as i32);
    if current == Some(minutes) {
        return;
    }
    if let Ok(handle) = registry::open_or_create(TIME_ZONE_KEY, None) {
        registry::set_value(handle, "ActiveTimeBias", REG_DWORD, (minutes as u32).to_le_bytes().to_vec());
        registry::close_handle(handle);
    }
}

/// O fuso calculado: (TimeZoneId, viés em minutos, próxima troca em hora
/// local ou 0).
fn evaluate(zone: &RtlTimeZoneInformation, local: i64) -> Option<(u32, i32, i64)> {
    let standard_start = Fields::read(&zone.standard_start);
    let daylight_start = Fields::read(&zone.daylight_start);
    if standard_start.month == 0 || daylight_start.month == 0 {
        return Some((TIME_ZONE_ID_UNKNOWN, zone.bias.get(), 0));
    }
    let standard = time::cutover_time_to_system_time(&standard_start, local)?;
    let daylight = time::cutover_time_to_system_time(&daylight_start, local)?;
    let (id, next) = if local >= daylight && local >= standard {
        (if standard <= daylight { TIME_ZONE_ID_DAYLIGHT } else { TIME_ZONE_ID_STANDARD }, 0)
    } else if daylight < standard {
        if local >= daylight && local < standard { (TIME_ZONE_ID_DAYLIGHT, standard) } else { (TIME_ZONE_ID_STANDARD, daylight) }
    } else if local >= standard && local < daylight {
        (TIME_ZONE_ID_STANDARD, daylight)
    } else {
        (TIME_ZONE_ID_DAYLIGHT, standard)
    };
    let extra = if id == TIME_ZONE_ID_DAYLIGHT { zone.daylight_bias.get() } else { zone.standard_bias.get() };
    Some((id, zone.bias.get().wrapping_add(extra), next))
}

/// Protocolo do KSYSTEM_TIME (High2Time, LowPart, High1Time).
fn write_shared_time(time: &crate::ntos::inc::types::KsystemTime, value: i64) {
    let high = (value as u64 >> 32) as i32;
    time.high2_time.set(high);
    time.low_part.set(value as u32);
    time.high1_time.set(high);
}

/// ExpRefreshTimeZoneInformation: TRUE com o fuso lido e aplicado.
pub fn refresh() -> bool {
    let _held = REFRESH_LOCK.lock();
    refresh_locked()
}

fn refresh_locked() -> bool {
    let Ok(mut bytes) = query_registry(true) else {
        SYSTEM_IS_IN_CMOS_MODE.store(true, Ordering::Relaxed);
        return false;
    };
    let information = view(&mut bytes);
    let current_universal = clock::shared_system_time();
    let local = current_universal.wrapping_sub(time_zone_bias());
    let Some((id, minutes, next_local)) = evaluate(&information.tzi, local) else {
        SYSTEM_IS_IN_CMOS_MODE.store(true, Ordering::Relaxed);
        return false;
    };
    if last_time_zone_bias_minutes() != minutes {
        publish_bias_change();
    }
    LAST_TIME_ZONE_BIAS.store(minutes as i64, Ordering::Relaxed);
    TIME_ZONE_BIAS.store(minutes as i64 * MINUTE, Ordering::Relaxed);
    CURRENT_TIME_ZONE_ID.store(id, Ordering::Relaxed);
    *INFORMATION.lock() = bytes;
    SYSTEM_IS_IN_CMOS_MODE.store(false, Ordering::Relaxed);
    let bias = time_zone_bias();
    // ExLocalTimeToSystemTime com o viés novo.
    let next_cutover = (next_local != 0).then(|| next_local.wrapping_add(bias));
    let year = time::time_to_fields(local).year;
    let new_year = |year: i16| time::fields_to_time(&Fields { year, month: 1, day: 1, ..Fields::default() }).map(|local| local.wrapping_add(bias));
    let next_year = new_year(year.saturating_add(1));
    NEXT_CUTOVER.store(next_cutover.map_or(u64::MAX, |due| due as u64), Ordering::Relaxed);
    NEXT_YEAR.store(next_year.map_or(u64::MAX, |due| due as u64), Ordering::Relaxed);
    if let Some(data) = crate::ntos::mm::shared_user_data::data() {
        data.time_zone_id.set(id);
        let stamp = data.time_zone_bias_stamp.atomic();
        stamp.fetch_add(1, Ordering::SeqCst);
        write_shared_time(&data.time_zone_bias, bias);
        let end = next_cutover.unwrap_or_else(|| next_year.unwrap_or(0).wrapping_sub(10_000));
        data.time_zone_bias_effective_start.quad_part.set(current_universal);
        data.time_zone_bias_effective_end.quad_part.set(end);
        stamp.fetch_add(1, Ordering::SeqCst);
    }
    if !real_time_is_universal() {
        set_active_time_bias(minutes);
    }
    true
}

/// Os timers da próxima troca e do ano novo (ExpTimeZoneDpcRoutine e
/// ExpNextYearDpcRoutine): vencidos pela hora do sistema, refazem o fuso e
/// o relógio (NtSetSystemTime(NULL, NULL)). Chamado pelo tick dos timers.
pub fn check_cutover() {
    let now = clock::system_time_100ns();
    let due = NEXT_CUTOVER.load(Ordering::Relaxed).min(NEXT_YEAR.load(Ordering::Relaxed));
    if now < due {
        return;
    }
    // Um vencimento por vez: o refresh grava os prazos seguintes.
    NEXT_CUTOVER.store(u64::MAX, Ordering::Relaxed);
    NEXT_YEAR.store(u64::MAX, Ordering::Relaxed);
    let _ = crate::ntos::ex::system_time::refresh_from_real_time_clock();
}

/// A fase 1 do fuso (o que o NT faz com o CmControlVector na fase 0 e no
/// Phase1InitializationDiscard): RealTimeIsUniversal e ActiveTimeBias do
/// Registro, a hora do boot pelo relógio com esse viés (KeBootTime refeito),
/// o ExpRefreshTimeZoneInformation e, com um viés diferente do
/// ActiveTimeBias, o NtSetSystemTime(NULL, NULL).
pub fn initialize() {
    let universal = registry::read_value_by_path(TIME_ZONE_KEY, "RealTimeIsUniversal").filter(|value| value.value_type == REG_DWORD).is_some_and(|value| dword(&value.data) != 0);
    REAL_TIME_IS_UNIVERSAL.store(universal, Ordering::Relaxed);
    let active = registry::read_value_by_path(TIME_ZONE_KEY, "ActiveTimeBias").filter(|value| value.value_type == REG_DWORD).map_or(0, |value| dword(&value.data) as i32);
    LAST_TIME_ZONE_BIAS.store(active as i64, Ordering::Relaxed);
    TIME_ZONE_BIAS.store(if universal { 0 } else { active as i64 * MINUTE }, Ordering::Relaxed);
    if let Some(universal_time) = crate::hal::rtc::query_universal_time() {
        clock::set_system_time(universal_time as u64, 4);
    }
    let before = last_time_zone_bias_minutes();
    let refreshed = refresh();
    if refreshed && before != last_time_zone_bias_minutes() {
        let _ = crate::ntos::ex::system_time::refresh_from_real_time_clock();
    }
    let universal_ms = crate::rtl::time::nt_time_to_unix_milliseconds(clock::system_time_100ns());
    debug_print!("[time] fuso: vies {} min, id {}, relogio {}; UTC={}", last_time_zone_bias_minutes(), time_zone_id(), if universal { "UTC" } else { "local" }, universal_ms);
}

// ---- Nt{Query,Set}SystemInformation: SystemCurrentTimeZoneInformation (44)
// e SystemDynamicTimeZoneInformation (102) ---------------------------------
//
// ExpQuerySystemInformation 19041: um comprimento menor que a estrutura
// (0xAC ou 0x1B0) é STATUS_INFO_LENGTH_MISMATCH com o tamanho em
// ReturnLength; senão a cópia do fuso do silo, tirada sob o
// ExpTimeRefreshLock, vai inteira ao buffer e ReturnLength recebe o tamanho.
// NtSetSystemInformation: o comprimento tem de ser exatamente o tamanho; do
// modo usuário, SeTimeZonePrivilege (ou a capacidade de fuso); o
// ExpSetTimeZoneInformation captura (alinhamento 4; a forma de 0xAC ganha
// chave vazia e DynamicDaylightTimeDisabled = 1), grava no Registro e chama
// NtSetSystemTime(NULL, NULL); uma falha regrava o fuso anterior.

/// SYSTEM_INFORMATION_CLASS SystemCurrentTimeZoneInformation e
/// SystemDynamicTimeZoneInformation.
pub const SYSTEM_CURRENT_TIME_ZONE_INFORMATION: u32 = 44;
pub const SYSTEM_DYNAMIC_TIME_ZONE_INFORMATION: u32 = 102;

fn class_size(class: u32) -> usize {
    if class == SYSTEM_DYNAMIC_TIME_ZONE_INFORMATION { DYNAMIC_TIME_ZONE_INFORMATION_SIZE } else { TIME_ZONE_INFORMATION_SIZE }
}

/// A consulta: (classe, buffer, capacidade, PULONG ReturnLength, modo de usuário).
pub fn query(class: u32, output: u64, length: u64, returned: u64, from_user_mode: bool) -> u32 {
    let size = class_size(class) as u64;
    let length = length as u32 as u64;
    if from_user_mode {
        if length != 0 && output & 3 != 0 {
            return STATUS_DATATYPE_MISALIGNMENT;
        }
        if (length != 0 && !crate::ntos::ps::user_probe::probe_user_write(output, length)) || (returned != 0 && !crate::ntos::ps::user_probe::probe_user_write(returned, 4)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    let set_returned = |value: u64| if returned != 0 { guest::try_write::<u32>(returned, value as u32) } else { Ok(()) };
    if length < size {
        return set_returned(size).map_or(STATUS_ACCESS_VIOLATION, |()| STATUS_INFO_LENGTH_MISMATCH);
    }
    let bytes = {
        let _held = REFRESH_LOCK.lock();
        current_information()
    };
    guest::try_write_bytes(output, &bytes[..size as usize]).and_then(|()| set_returned(size)).map_or(STATUS_ACCESS_VIOLATION, |()| 0)
}

/// ExpSetTimeZoneInformation: o fuso de `input` (`size` bytes) no Registro e
/// em vigor.
fn set_information(input: &[u8], size: usize) -> u32 {
    let mut bytes = [0u8; DYNAMIC_TIME_ZONE_INFORMATION_SIZE];
    bytes[..size].copy_from_slice(&input[..size]);
    if size == TIME_ZONE_INFORMATION_SIZE {
        view(&mut bytes).dynamic_daylight_time_disabled.set(1);
    }
    let previous = {
        let _held = REFRESH_LOCK.lock();
        current_information()
    };
    let mut status = write_registry(&bytes, DYNAMIC_TIME_ZONE_INFORMATION_SIZE);
    if status & 0x8000_0000 == 0 {
        status = crate::ntos::ex::system_time::refresh_from_real_time_clock();
    }
    if status & 0x8000_0000 != 0 {
        write_registry(&previous, DYNAMIC_TIME_ZONE_INFORMATION_SIZE);
    }
    status
}

/// NtSetSystemInformation(44 ou 102, buffer, comprimento).
pub fn set(class: u32, input: u64, length: u32, from_user_mode: bool) -> u32 {
    let size = class_size(class);
    if length as usize != size {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    if from_user_mode {
        if !crate::ntos::se::privilege::single_privilege_check(SE_TIME_ZONE_PRIVILEGE, 1) {
            return STATUS_PRIVILEGE_NOT_HELD;
        }
        if input & 3 != 0 {
            return STATUS_DATATYPE_MISALIGNMENT;
        }
        if !crate::ntos::ps::user_probe::probe_user_read(input, size as u64) {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    let Ok(captured) = guest::try_read_bytes(input, size) else { return STATUS_ACCESS_VIOLATION };
    set_information(&captured, size)
}

// ---- RtlQuery/Set[Dynamic]TimeZoneInformation (exports) --------------------

/// RtlQueryTimeZoneInformation / RtlQueryDynamicTimeZoneInformation: o fuso
/// do Registro no buffer do chamador.
pub fn query_information_export(output: u64, dynamic: bool) -> u32 {
    match query_registry(dynamic) {
        Ok(bytes) => {
            let size = if dynamic { DYNAMIC_TIME_ZONE_INFORMATION_SIZE } else { TIME_ZONE_INFORMATION_SIZE };
            guest::write_bytes(output, &bytes[..size]);
            0
        }
        Err(status) => status,
    }
}

/// RtlSetTimeZoneInformation / RtlSetDynamicTimeZoneInformation: o fuso do
/// chamador no Registro. A forma de 0xAC lê o DynamicDaylightTimeDisabled
/// no deslocamento 0x1AC do buffer, como o worker do NT.
pub fn set_information_export(input: u64, dynamic: bool) -> u32 {
    let size = if dynamic { DYNAMIC_TIME_ZONE_INFORMATION_SIZE } else { TIME_ZONE_INFORMATION_SIZE };
    let mut bytes = [0u8; DYNAMIC_TIME_ZONE_INFORMATION_SIZE];
    bytes[..size].copy_from_slice(&guest::read_bytes(input, size));
    if !dynamic {
        bytes[0x1AC] = guest::try_read::<u8>(input + 0x1AC).unwrap_or(0);
    }
    write_registry(&bytes, size)
}
