//! Os callbacks embutidos do Errata Manager (a BuiltinCallbackReg do
//! ntoskrnl 19041, registrada pelo EmInitSystem sem DRIVER_OBJECT no
//! EmBuiltinProviderHandle) e a data do BIOS que o EmMatchDate compara.
//!
//! - BiosDate (EmMatchDate): (Op)(Mês, Dia, Ano), números em hexadecimal
//!   como o INF os traz; a data vira 0x19AA_MMDD ou 0x20AA_MMDD (ano abaixo
//!   de 0x80) e é comparada com a do BIOS; a comparação falsa (e a data
//!   desconhecida sem o curinga) é UNKNOWN, não FALSE.
//! - CpuType (EmCpuMatchCallback): o fabricante (`*` casa qualquer um) e
//!   família, modelo e stepping da KPRCB corrente com os operadores dados.
//! - AlwaysTrue e AlwaysFalse.
//! - SystemArchitecture: o número contra PROCESSOR_ARCHITECTURE_AMD64.
//! - RemoveBadS3Pages: guarda a página e devolve TRUE (a gravação da página
//!   na lista de páginas ruins do BCD pela WHEA fica de fora: o OpenNT não
//!   tem BCD).
//!
//! EmpCacheBiosDate: só no boot por BIOS legado, a cadeia "MM/DD/AA" do
//! endereço físico 0xFFFF5 (não o SMBIOS); com UEFI a data é 0.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::ntos::em::database::{Arguments, STATE_FALSE, STATE_TRUE, STATE_UNKNOWN};
use crate::ntos::em::provider::CallbackRequest;
use crate::ntos::inc::types::{Kprcb, NtStruct};
use crate::ntos::mm::guest_memory as guest;

/// EmpCachedBiosDate.
static CACHED_BIOS_DATE: AtomicU32 = AtomicU32::new(0);
/// EmpBadS3Page.
static BAD_S3_PAGE: AtomicU64 = AtomicU64::new(0);
/// PROCESSOR_ARCHITECTURE_AMD64 (o KeProcessorArchitecture do x64).
const PROCESSOR_ARCHITECTURE_AMD64: u32 = 9;

/// Os bytes da cadeia C no endereço (até 256).
pub fn c_string(address: u64) -> alloc::vec::Vec<u8> {
    let mut bytes = alloc::vec::Vec::new();
    if address == 0 {
        return bytes;
    }
    for offset in 0..256 {
        let byte = guest::read8(address + offset);
        if byte == 0 {
            break;
        }
        bytes.push(byte);
    }
    bytes
}

/// EmpCheckOperator (e o HalAcpiEmCheckOperator, idêntico): o valor do
/// sistema contra o da regra, sem sinal.
pub fn check_operator(operator: &[u8], system: u32, rule: u32) -> bool {
    match operator {
        b"=" | b"==" => system == rule,
        b"!=" | b"<>" | b"=!" => system != rule,
        b"<" => system < rule,
        b"<=" | b"=<" => system <= rule,
        b">" => system > rule,
        b">=" | b"=>" => system >= rule,
        b"*" => true,
        _ => false,
    }
}

/// strtoul(texto, NULL, 16) sobre dois caracteres.
fn hex_pair(bytes: &[u8]) -> u32 {
    let mut value = 0;
    for &byte in bytes {
        match (byte as char).to_digit(16) {
            Some(digit) => value = value * 16 + digit,
            None => break,
        }
    }
    value
}

/// A data no formato do Errata Manager.
fn date(year: u32, month: u32, day: u32) -> u32 {
    (if year < 0x80 { 0x2000_0000u32 } else { 0x1900_0000 }).wrapping_add(year << 16).wrapping_add(month << 8).wrapping_add(day)
}

/// EmpCacheBiosDate.
pub fn cache_bios_date() {
    CACHED_BIOS_DATE.store(0, Ordering::Release);
    if crate::hal::firmware_environment::firmware_type().ok() != Some(1) {
        return;
    }
    let text: alloc::vec::Vec<u8> = (0..8).map(|offset| crate::hal::physical::read8(0xFFFF5 + offset)).collect();
    let (month, day, year) = (hex_pair(&text[0..2]), hex_pair(&text[3..5]), hex_pair(&text[6..8]));
    CACHED_BIOS_DATE.store(date(year, month, day), Ordering::Release);
}

/// A data do BIOS guardada.
pub fn cached_bios_date() -> u32 {
    CACHED_BIOS_DATE.load(Ordering::Acquire)
}

/// EmMatchDate.
fn match_date(arguments: &Arguments) -> u32 {
    if arguments.strings.len() != 1 || arguments.strings[0] == 0 || arguments.numerics.len() != 3 {
        return STATE_UNKNOWN;
    }
    let operator = c_string(arguments.strings[0]);
    let rule = date(arguments.numerics[2], arguments.numerics[0], arguments.numerics[1]);
    let bios = cached_bios_date();
    if bios == 0 && operator.first() != Some(&b'*') {
        return STATE_UNKNOWN;
    }
    if check_operator(&operator, bios, rule) { STATE_TRUE } else { STATE_UNKNOWN }
}

/// EmCpuMatchCallback.
fn cpu_match(arguments: &Arguments) -> u32 {
    if arguments.strings.len() != 4 || arguments.numerics.len() != 4 {
        return STATE_UNKNOWN;
    }
    // SAFETY: a KPCR do processador corrente e a KPRCB embutida nela.
    let prcb = unsafe { Kprcb::at(crate::ntos::ke::pcr::current().current_prcb.get()) };
    let vendor = c_string(arguments.strings[0]);
    if vendor.first() != Some(&b'*') {
        let mut current = alloc::vec::Vec::new();
        for byte in prcb.vendor_string.iter().map(|cell| cell.get()) {
            if byte == 0 {
                break;
            }
            current.push(byte);
        }
        if current != vendor {
            return STATE_FALSE;
        }
    }
    let base = prcb.address();
    let family = prcb.cpu_type.get() as i32 as u32;
    let model = guest::read8(base + 0x43) as u32;
    let stepping = guest::read8(base + 0x42) as u32;
    let checks = [(1, family), (2, model), (3, stepping)];
    if checks.iter().all(|&(index, system)| check_operator(&c_string(arguments.strings[index]), system, arguments.numerics[index])) {
        STATE_TRUE
    } else {
        STATE_FALSE
    }
}

fn always_true(_: &Arguments) -> u32 {
    STATE_TRUE
}

fn always_false(_: &Arguments) -> u32 {
    STATE_FALSE
}

/// EmSystemArchitectureCallback.
fn system_architecture(arguments: &Arguments) -> u32 {
    match arguments.numerics.first() {
        Some(&architecture) => {
            if architecture == PROCESSOR_ARCHITECTURE_AMD64 {
                STATE_TRUE
            } else {
                STATE_FALSE
            }
        }
        None => STATE_UNKNOWN,
    }
}

/// EmRemoveBadS3PagesCallback.
fn remove_bad_s3_pages(arguments: &Arguments) -> u32 {
    if arguments.numerics.len() != 1 {
        return STATE_UNKNOWN;
    }
    BAD_S3_PAGE.store(arguments.numerics[0] as u64, Ordering::Release);
    STATE_TRUE
}

fn request(guid: &str, routine: crate::ntos::em::database::NativeCallback) -> CallbackRequest {
    CallbackRequest { guid: crate::ntos::em::database::guid_from_text(guid), routine: Some(crate::ntos::em::database::Routine::Native(routine)), context: 0 }
}

/// A BuiltinCallbackReg[0..6]: BiosDate, CpuType, AlwaysTrue,
/// AlwaysFalse, SystemArchitecture e RemoveBadS3Pages.
pub fn callbacks() -> alloc::vec::Vec<CallbackRequest> {
    alloc::vec![
        request("{182A2B31-D5B8-45EF-BB6D-646EBAEDD8F1}", match_date),
        request("{D2E7862C-B8FA-4274-9BD1-59BA8DA0A7C2}", cpu_match),
        request("{8026FF68-3BD0-4BA4-A1D4-DE724F781B78}", always_true),
        request("{9D991181-C86A-4517-9FE7-32290377B564}", always_false),
        request("{24453286-BDE8-46BC-85D1-1982EDF3E212}", system_architecture),
        request("{59229CA6-17A7-4E11-9EDA-DF0E93D7AF3A}", remove_bad_s3_pages),
    ]
}
