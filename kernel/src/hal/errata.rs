//! Os callbacks de errata da HAL (HalRegisterErrataCallbacks): as
//! comparações das regras do Errata Manager com as tabelas ACPI do
//! firmware, registradas pelo EmInitSystem antes dos callbacks embutidos
//! (a BuiltinCallbackReg[6..12] do ntoskrnl 19041).
//!
//! A tabela é a primeira em cache com a assinatura da primeira cadeia
//! (HalpAcpiGetTable; a FADT é "FACP"); sem ela o termo é UNKNOWN.
//! - AcpiOemId (Tabela, OemId): o OEMID de 6 bytes (cortado no primeiro
//!   NUL) igual à cadeia, sem diferenciar maiúsculas (RtlEqualString); não
//!   há curinga.
//! - AcpiOemTableId (Tabela, OemTableId): `*` casa qualquer uma; senão os 8
//!   bytes do OEM Table ID contra a cadeia completada com NULs.
//! - AcpiOemRevision, AcpiCreatorRevision e AcpiRevision (Op, Tabela)
//!   (Revisão): o operador sobre a revisão OEM (+0x18), a do criador
//!   (+0x20) ou a revisão do cabeçalho (byte +0x08).
//! - AcpiFADTBootArch ()(Máscara): os bits do IAPC_BOOT_ARCH da FADT
//!   (+0x6D) todos presentes; sem máscara ou sem FADT, FALSE.

use alloc::vec::Vec;

use crate::ntos::em::builtin::{c_string, check_operator};
use crate::ntos::em::database::{guid_from_text, Arguments, NativeCallback, Routine, STATE_FALSE, STATE_TRUE, STATE_UNKNOWN};
use crate::ntos::em::provider::CallbackRequest;
use crate::ntos::mm::guest_memory as guest;

/// A assinatura "FACP".
const FADT_SIGNATURE: u32 = u32::from_le_bytes(*b"FACP");

/// HalpAcpiGetTable(NULL, *(ULONG*)Cadeia, NULL, NULL).
fn table_of(signature_string: u64) -> u64 {
    crate::hal::acpi_native::get_table_ex(0, guest::read32(signature_string), 0, 0)
}

fn state(matched: bool) -> u32 {
    if matched { STATE_TRUE } else { STATE_FALSE }
}

/// HalMatchAcpiOemId.
fn match_oem_id(arguments: &Arguments) -> u32 {
    if arguments.strings.len() != 2 || arguments.strings.iter().any(|&string| string == 0) {
        return STATE_UNKNOWN;
    }
    let table = table_of(arguments.strings[0]);
    if table == 0 {
        return STATE_UNKNOWN;
    }
    let oem: Vec<u8> = guest::read_bytes(table + 0xA, 6).into_iter().take_while(|&byte| byte != 0).collect();
    state(c_string(arguments.strings[1]).eq_ignore_ascii_case(&oem))
}

/// HalMatchAcpiOemTableId.
fn match_oem_table_id(arguments: &Arguments) -> u32 {
    if arguments.strings.len() != 2 || arguments.strings.iter().any(|&string| string == 0) {
        return STATE_UNKNOWN;
    }
    let table = table_of(arguments.strings[0]);
    if table == 0 {
        return STATE_UNKNOWN;
    }
    let wanted = c_string(arguments.strings[1]);
    if wanted == b"*" {
        return STATE_TRUE;
    }
    let mut buffer = [0u8; 8];
    let length = wanted.len().min(8);
    buffer[..length].copy_from_slice(&wanted[..length]);
    state(guest::read_bytes(table + 0x10, 8) == buffer)
}

/// HalMatchAcpiOemRevision, HalMatchAcpiCreatorRevision e
/// HalMatchAcpiRevision: (Op, Tabela)(Revisão) sobre o valor do cabeçalho.
fn match_revision(arguments: &Arguments, read: fn(u64) -> u32) -> u32 {
    if arguments.strings.len() != 2 || arguments.numerics.len() != 1 || arguments.strings.iter().any(|&string| string == 0) {
        return STATE_UNKNOWN;
    }
    let table = table_of(arguments.strings[1]);
    if table == 0 {
        return STATE_UNKNOWN;
    }
    state(check_operator(&c_string(arguments.strings[0]), read(table), arguments.numerics[0]))
}

fn match_oem_revision(arguments: &Arguments) -> u32 {
    match_revision(arguments, |table| guest::read32(table + 0x18))
}

fn match_creator_revision(arguments: &Arguments) -> u32 {
    match_revision(arguments, |table| guest::read32(table + 0x20))
}

fn match_acpi_revision(arguments: &Arguments) -> u32 {
    match_revision(arguments, |table| guest::read8(table + 0x08) as u32)
}

/// HalMatchAcpiFADTBootArch.
fn match_fadt_boot_arch(arguments: &Arguments) -> u32 {
    let mask = match arguments.numerics {
        [mask] if *mask != 0 => *mask,
        _ => return STATE_FALSE,
    };
    let fadt = crate::hal::acpi_native::get_table_ex(0, FADT_SIGNATURE, 0, 0);
    if fadt == 0 {
        return STATE_FALSE;
    }
    state(guest::read16(fadt + 0x6D) as u32 & mask == mask)
}

fn request(guid: &str, routine: NativeCallback) -> CallbackRequest {
    CallbackRequest { guid: guid_from_text(guid), routine: Some(Routine::Native(routine)), context: 0 }
}

/// HalRegisterErrataCallbacks: os seis callbacks, na ordem da tabela.
pub fn callbacks() -> Vec<CallbackRequest> {
    alloc::vec![
        request("{BEAE4D5F-2203-4856-94BB-C772A2C7624A}", match_creator_revision),
        request("{7CD2B230-6CEA-4957-B5D7-CFA977C22B18}", match_fadt_boot_arch),
        request("{2960716F-B0D8-41C9-9BB4-EE8BA248F86E}", match_oem_id),
        request("{7E8FAE0F-7591-4EB6-9554-1D0699873111}", match_oem_revision),
        request("{E0E45284-F266-4048-9A5E-7D4007C9C5AB}", match_oem_table_id),
        request("{BF51DEF4-AC9C-44F3-ADE7-26DD13E756D3}", match_acpi_revision),
    ]
}
