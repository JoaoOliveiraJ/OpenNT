//! Exports Rtl*, Interlocked* e da CRT do ntoskrnl — `system32/win32/ntoskrnl/rtl.js`.
//!
//! Semântica do NT sobre a memória do convidado. Divergência: os campos
//! Buffer das UNICODE/ANSI_STRING são lidos e escritos com 64 bits (o
//! original usava 32, suficiente para os endereços baixos dele).

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::init::exports::{signed_status, Call};
use crate::hal::amd64::native_call;
use crate::ntos::cm::key::services as key_services;
use crate::ntos::cm::registry;
use crate::ntos::ke::irql;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;

/// Prefixos RTL_REGISTRY_* por código de raiz.
fn registry_prefix(relative_to: u32) -> Option<&'static str> {
    Some(match relative_to {
        1 => "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\",
        2 => "\\Registry\\Machine\\System\\Control\\",
        3 => "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\",
        4 => "\\Registry\\Machine\\Hardware\\DeviceMap\\",
        5 => "\\Registry\\User\\.CurrentUser\\",
        _ => return None,
    })
}

/// Caminho absoluto (RTL_REGISTRY_ABSOLUTE mantém o texto).
pub fn resolve_registry_path(relative_to: u32, raw: &str) -> String {
    if relative_to == 0 {
        return String::from(raw);
    }
    match registry_prefix(relative_to) {
        Some(prefix) => alloc::format!("{prefix}{}", raw.trim_start_matches('\\')),
        None => String::from(raw),
    }
}

/// Notificações de mudança de feature (RtlRegisterFeatureConfigurationChangeNotification).
static FEATURE_NOTIFICATIONS: SpinLock<Vec<(u64, u64)>> = SpinLock::new(Vec::new());

/// RtlNtStatusToDosError: a tabela real (subconjunto usado por drivers);
/// sem mapeamento = ERROR_MR_MID_NOT_FOUND (317).
pub fn status_to_dos_error(status: u32) -> u32 {
    match status {
        0x0000_0000 => 0,
        0x8000_0005 => 234,
        0xC000_0001 => 31,
        0xC000_0002 => 1,
        0xC000_0004 => 24,
        0xC000_0005 => 998,
        0xC000_0008 => 6,
        0xC000_000D => 87,
        0xC000_0017 => 8,
        0xC000_0022 => 5,
        0xC000_0023 => 122,
        0xC000_0034 => 2,
        0xC000_0035 => 183,
        0xC000_003A => 3,
        0xC000_0043 => 32,
        0xC000_009A => 8,
        0xC000_009D => 1167,
        0xC000_00A5 => 31,
        0xC000_00BB => 50,
        0xC000_0185 => 1117,
        0xC000_0225 => 1168,
        _ => 317,
    }
}

fn utf16(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

/// RtlFree*String: libera o buffer e zera os campos.
fn free_string(pointer: u64) -> u64 {
    let buffer = guest::read64(pointer + 8);
    if buffer != 0 {
        guest::free_bytes(buffer);
    }
    guest::write16(pointer, 0);
    guest::write16(pointer + 2, 0);
    guest::write64(pointer + 8, 0);
    0
}

/// Escreve o texto numa UNICODE_STRING de destino (alocando se pedido ou
/// sem buffer; respeitando MaximumLength).
fn write_converted_string(destination: u64, text: &str, allocate: bool) -> u64 {
    let units = utf16(text);
    let needed = units.len() as u64 * 2 + 2;
    let mut buffer = guest::read64(destination + 8);
    if allocate || buffer == 0 {
        buffer = guest::alloc_bytes(needed);
        guest::write64(destination + 8, buffer);
        guest::write16(destination + 2, needed as u16);
    } else if (guest::read16(destination + 2) as u64) < needed {
        return signed_status(0x8000_0005);
    }
    for (index, unit) in units.iter().enumerate() {
        guest::write16(buffer + index as u64 * 2, *unit);
    }
    guest::write16(buffer + units.len() as u64 * 2, 0);
    guest::write16(destination, units.len() as u16 * 2);
    0
}

/// Concatena no buffer do destino (respeita MaximumLength).
fn append_to_unicode_string(destination: u64, text: &str) -> u64 {
    let units = utf16(text);
    let maximum = guest::read16(destination + 2) as u64 / 2;
    if units.len() as u64 + 1 > maximum {
        return signed_status(0x8000_0005);
    }
    let buffer = guest::read64(destination + 8);
    for (index, unit) in units.iter().enumerate() {
        guest::write16(buffer + index as u64 * 2, *unit);
    }
    guest::write16(buffer + units.len() as u64 * 2, 0);
    guest::write16(destination, units.len() as u16 * 2);
    0
}

/// Spinlock test-and-set em DISPATCH_LEVEL dos ExInterlocked* de lista.
fn spin_lock_acquire(lock: u64) -> u8 {
    let previous = irql::get_irql();
    irql::raise_irql(irql::DISPATCH_LEVEL);
    loop {
        if guest::read32(lock) == 0 {
            guest::write32(lock, 1);
            return previous;
        }
    }
}

fn spin_lock_release(lock: u64, previous: u8) {
    guest::write32(lock, 0);
    irql::lower_irql(previous as u64);
}

/// Flags da RTL_QUERY_REGISTRY_TABLE (wdm.h).
const QUERY_REGISTRY_REQUIRED: u32 = 0x04;
const QUERY_REGISTRY_DIRECT: u32 = 0x20;

/// RtlQueryRegistryValues[Ex]: cada entrada é processada mesmo com a chave
/// ausente (o driver recebe o default); DIRECT escreve em EntryContext; com
/// QueryRoutine a rotina do driver é chamada; REQUIRED sem valor nem
/// default = OBJECT_NAME_NOT_FOUND.
pub fn query_registry_values(_relative_to: u32, path: u64, table: u64, context: u64, _environment: u64) -> Result<u64, KernelError> {
    let key_path = guest_strings::read_wide_string(path);
    debug_print!("[rtl] QueryRegistry path=\"{}\" table=0x{:x}", key_path, table);
    let (open_status, key_handle) = key_services::open_path(&key_path, false)?;
    if open_status != 0 && open_status != 0xC000_0034 {
        return Ok(open_status as u64);
    }
    let mut cursor = table;
    let mut status = 0u64;
    for index in 0..=64 {
        let routine = guest::read64(cursor);
        let flags = guest::read32(cursor + 8);
        let name_pointer = guest::read64(cursor + 0x10);
        let entry_context = guest::read64(cursor + 0x18);
        let default_type = guest::read32(cursor + 0x20);
        let default_data = guest::read64(cursor + 0x28);
        let default_length = guest::read32(cursor + 0x30);
        if routine == 0 && name_pointer == 0 {
            break;
        }
        cursor += 0x38;
        let value_name = if name_pointer != 0 { guest_strings::read_wide_string(name_pointer) } else { String::new() };
        let queried = if key_handle != 0 && !value_name.is_empty() { Some(key_services::named_value(key_services::Kind::QueryValue, key_handle, &value_name, 0, &[])?) } else { None };
        if let Some((query_status, _)) = &queried {
            if *query_status != 0 && *query_status != 0xC000_0034 {
                status = *query_status as u64;
                break;
            }
        }
        let entry = queried.and_then(|(_, value)| value);
        let (value_type, value_bytes) = match &entry {
            Some(value) => (value.value_type, Some(value.data.clone())),
            None if default_type != 0 => (default_type, Some(guest::read_bytes(default_data, default_length as usize))),
            None => (0, None),
        };
        debug_print!("[rtl]   [{}] \"{}\" flags=0x{:x} routine=0x{:x} -> {}", index, value_name, flags, routine, if entry.is_some() { "valor" } else if value_bytes.is_some() { "default" } else { "ausente" });
        let Some(bytes) = value_bytes else {
            if flags & QUERY_REGISTRY_REQUIRED != 0 {
                status = signed_status(0xC000_0034);
                break;
            }
            continue;
        };
        if flags & QUERY_REGISTRY_DIRECT != 0 {
            guest::write_bytes(entry_context, &bytes);
            continue;
        }
        if routine != 0 {
            // QueryRoutine(valueName, valueType, valueData, valueLength, context, entryContext).
            let data = guest::alloc_bytes(bytes.len().max(1) as u64);
            guest::write_bytes(data, &bytes);
            let routine_status = native_call::call(routine, &[name_pointer, value_type as u64, data, bytes.len() as u64, context, entry_context]) as i32;
            guest::free_bytes(data);
            if routine_status < 0 {
                status = routine_status as i64 as u64;
                break;
            }
        }
    }
    if key_handle != 0 {
        registry::close_handle(key_handle as u32);
    }
    Ok(status)
}

// ---- handlers ------------------------------------------------------------

/// RtlInitUnicodeString: só aponta o buffer; origem NULL = campos zerados.
fn init_unicode_string(call: &Call) -> Result<u64, KernelError> {
    let (output, source) = (call.arg(1), call.arg(2));
    if source == 0 {
        guest_strings::write_string_fields(output, 0, 0, 0);
        return Ok(0);
    }
    let count = guest_strings::read_wide_units(source).len() as u16;
    guest_strings::write_string_fields(output, count * 2, count * 2 + 2, source);
    Ok(0)
}
fn compare_unicode_string(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::unicode::compare_string(call.arg(1), call.arg(2), call.arg(3) as u32)? as i64 as u64)
}
fn copy_unicode_string(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::strings_counted::copy(call.arg(1), call.arg(2));
    Ok(0)
}
fn equal_unicode_string(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::unicode::equal_string(call.arg(1), call.arg(2), call.arg(3) as u32)? as u64)
}
fn init_ansi_string(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::strings_counted::initialize_ansi(call.arg(1), call.arg(2));
    Ok(0)
}
fn ansi_string_to_unicode_string(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::ansi_code_page::ansi_to_unicode(call.arg(1), call.arg(2), call.arg(3) & 0xFF != 0)? as u64)
}
/// RtlUnicodeStringToAnsiString: byte baixo de cada unidade.
fn unicode_string_to_ansi_string(call: &Call) -> Result<u64, KernelError> {
    let (ansi, unicode, allocate) = (call.arg(1), call.arg(2), call.arg(3) & 0xFF != 0);
    let units = guest_strings::try_read_unicode_units(unicode)?;
    let mut buffer = guest::read64(ansi + 8);
    if allocate || buffer == 0 {
        buffer = guest::alloc_bytes(units.len() as u64 + 1);
    }
    for (index, unit) in units.iter().enumerate() {
        guest::write8(buffer + index as u64, *unit as u8);
    }
    guest::write8(buffer + units.len() as u64, 0);
    guest_strings::write_string_fields(ansi, units.len() as u16, units.len() as u16 + 1, buffer);
    Ok(0)
}
fn free_ansi_string(call: &Call) -> Result<u64, KernelError> {
    Ok(free_string(call.arg(1)))
}
fn free_unicode_string(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::unicode::free(call.arg(1))?;
    Ok(0)
}
fn equal_string(call: &Call) -> Result<u64, KernelError> {
    let mut left = guest_strings::read_ansi_string(call.arg(1));
    let mut right = guest_strings::read_ansi_string(call.arg(2));
    if call.arg(3) & 0xFF != 0 {
        left = left.to_lowercase();
        right = right.to_lowercase();
    }
    Ok((left == right) as u64)
}
fn interlocked_increment(call: &Call) -> Result<u64, KernelError> {
    let value = guest::read32(call.arg(1)).wrapping_add(1);
    guest::write32(call.arg(1), value);
    Ok(value as u64)
}
fn interlocked_decrement(call: &Call) -> Result<u64, KernelError> {
    let value = guest::read32(call.arg(1)).wrapping_sub(1);
    guest::write32(call.arg(1), value);
    Ok(value as u64)
}
fn interlocked_exchange(call: &Call) -> Result<u64, KernelError> {
    let previous = guest::read32(call.arg(1));
    guest::write32(call.arg(1), call.arg(2) as u32);
    Ok(previous as u64)
}
fn interlocked_compare_exchange(call: &Call) -> Result<u64, KernelError> {
    let previous = guest::read32(call.arg(1));
    if previous == call.arg(3) as u32 {
        guest::write32(call.arg(1), call.arg(2) as u32);
    }
    Ok(previous as u64)
}
fn memset(call: &Call) -> Result<u64, KernelError> {
    let (destination, value, count) = (call.arg(1), call.arg(2) as u8, call.arg(3));
    for offset in 0..count {
        guest::write8(destination + offset, value);
    }
    Ok(destination)
}
/// memcpy/memmove: cópia por um temporário (seguro com sobreposição).
fn copy_through_temporary(destination: u64, source: u64, count: u64) {
    let bytes = guest::read_bytes(source, count as usize);
    guest::write_bytes(destination, &bytes);
}
fn memcpy(call: &Call) -> Result<u64, KernelError> {
    copy_through_temporary(call.arg(1), call.arg(2), call.arg(3));
    Ok(call.arg(1))
}
/// RtlUnicodeStringToInteger: base 0 = automática (0x, 0b, 0o, 0 octal).
fn unicode_string_to_integer(call: &Call) -> Result<u64, KernelError> {
    let text = guest_strings::read_unicode_string(call.arg(1));
    let mut text = text.trim();
    let mut base = call.arg(2) as u32;
    let mut negative = false;
    if let Some(rest) = text.strip_prefix('-') {
        negative = true;
        text = rest;
    }
    let lower = text.to_ascii_lowercase();
    if base == 0 {
        if lower.starts_with("0x") {
            base = 16;
            text = &text[2..];
        } else if lower.starts_with("0b") {
            base = 2;
            text = &text[2..];
        } else if lower.starts_with("0o") {
            base = 8;
            text = &text[2..];
        } else if text.len() > 1 && text.starts_with('0') && text.as_bytes()[1].is_ascii_digit() && text.as_bytes()[1] < b'8' {
            base = 8;
            text = &text[1..];
        } else {
            base = 10;
        }
    }
    // parseInt: o prefixo válido mais longo; nenhum dígito = inválido.
    let digits: String = text.chars().take_while(|character| character.is_digit(base.clamp(2, 36))).collect();
    if digits.is_empty() || !(2..=36).contains(&base) {
        return Ok(signed_status(0xC000_000D));
    }
    let parsed = u64::from_str_radix(&digits, base).unwrap_or(u64::MAX);
    let value = if negative { (parsed as i64).wrapping_neg() as u64 } else { parsed } as u32;
    guest::write32(call.arg(3), value);
    Ok(0)
}
fn format_radix(mut value: u32, base: u32) -> String {
    if value == 0 {
        return String::from("0");
    }
    let mut digits = Vec::new();
    while value > 0 {
        digits.push(core::char::from_digit(value % base, base).unwrap_or('0'));
        value /= base;
    }
    digits.iter().rev().collect()
}
/// RtlIntegerToUnicodeString (bases 2, 8, 10 e 16).
fn integer_to_unicode_string(call: &Call) -> Result<u64, KernelError> {
    let base = match call.arg(2) as u32 {
        0 => 10,
        base => base,
    };
    if ![2, 8, 10, 16].contains(&base) {
        return Ok(signed_status(0xC000_000D));
    }
    let text = format_radix(call.arg(1) as u32, base);
    Ok(append_to_unicode_string(call.arg(3), &text))
}
fn zero_memory(call: &Call) -> Result<u64, KernelError> {
    for offset in 0..call.arg(2) {
        guest::write8(call.arg(1) + offset, 0);
    }
    Ok(0)
}
fn fill_memory(call: &Call) -> Result<u64, KernelError> {
    for offset in 0..call.arg(2) {
        guest::write8(call.arg(1) + offset, call.arg(3) as u8);
    }
    Ok(0)
}
fn copy_memory(call: &Call) -> Result<u64, KernelError> {
    for offset in 0..call.arg(3) {
        guest::write8(call.arg(1) + offset, guest::read8(call.arg(2) + offset));
    }
    Ok(0)
}
fn move_memory(call: &Call) -> Result<u64, KernelError> {
    copy_through_temporary(call.arg(1), call.arg(2), call.arg(3));
    Ok(0)
}
/// RtlCompareMemory: bytes iguais do início.
fn compare_memory(call: &Call) -> Result<u64, KernelError> {
    let (left, right, length) = (call.arg(1), call.arg(2), call.arg(3));
    let mut equal = 0;
    while equal < length && guest::read8(left + equal) == guest::read8(right + equal) {
        equal += 1;
    }
    Ok(equal)
}
fn upcase_unicode_string(call: &Call) -> Result<u64, KernelError> {
    let text = guest_strings::read_unicode_string(call.arg(2)).to_uppercase();
    Ok(write_converted_string(call.arg(1), &text, call.arg(3) & 0xFF != 0))
}
fn downcase_unicode_string(call: &Call) -> Result<u64, KernelError> {
    let text = guest_strings::read_unicode_string(call.arg(2)).to_lowercase();
    Ok(write_converted_string(call.arg(1), &text, call.arg(3) & 0xFF != 0))
}
fn prefix_unicode_string(call: &Call) -> Result<u64, KernelError> {
    let mut prefix = guest_strings::read_unicode_string(call.arg(1));
    let mut text = guest_strings::read_unicode_string(call.arg(2));
    if call.arg(3) & 0xFF != 0 {
        prefix = prefix.to_lowercase();
        text = text.to_lowercase();
    }
    Ok(text.starts_with(&prefix) as u64)
}
fn append_unicode_string_to_string(call: &Call) -> Result<u64, KernelError> {
    let current = guest_strings::read_unicode_string(call.arg(1));
    let suffix = guest_strings::read_unicode_string(call.arg(2));
    Ok(append_to_unicode_string(call.arg(1), &alloc::format!("{current}{suffix}")))
}
fn append_unicode_to_string(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(crate::ntos::rtl::strings_counted::append(call.arg(1), call.arg(2))))
}
/// InterlockedPushEntryList: entry->Next = head->Next; head->Next = entry.
fn interlocked_push_entry_list(call: &Call) -> Result<u64, KernelError> {
    let (head, entry) = (call.arg(1), call.arg(2));
    let old = guest::read64(head);
    guest::write64(entry, old);
    guest::write64(head, entry);
    Ok(old)
}
fn interlocked_pop_entry_list(call: &Call) -> Result<u64, KernelError> {
    let head = call.arg(1);
    let first = guest::read64(head);
    if first == 0 {
        return Ok(0);
    }
    guest::write64(head, guest::read64(first));
    Ok(first)
}
/// ExInterlockedInsertTailList: LIST_ENTRY circular sob spinlock.
fn ex_interlocked_insert_tail_list(call: &Call) -> Result<u64, KernelError> {
    let (head, entry, lock) = (call.arg(1), call.arg(2), call.arg(3));
    let previous = spin_lock_acquire(lock);
    let last = guest::read64(head + 8);
    guest::write64(entry, head);
    guest::write64(entry + 8, last);
    guest::write64(last, entry);
    guest::write64(head + 8, entry);
    spin_lock_release(lock, previous);
    Ok(if last == head { 0 } else { last })
}
fn ex_interlocked_remove_head_list(call: &Call) -> Result<u64, KernelError> {
    let (head, lock) = (call.arg(1), call.arg(2));
    let previous = spin_lock_acquire(lock);
    let first = guest::read64(head);
    let mut removed = 0;
    if first != head {
        removed = first;
        let next = guest::read64(first);
        guest::write64(head, next);
        guest::write64(next + 8, head);
    }
    spin_lock_release(lock, previous);
    Ok(removed)
}
fn strlen(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::crt::strlen(call.arg(1))
}
fn strcmp(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::crt::strcmp(call.arg(1), call.arg(2))? as i64 as u64)
}
fn strncmp(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::crt::strncmp(call.arg(1), call.arg(2), Some(call.arg(3)))? as i64 as u64)
}
fn write_c_text(destination: u64, text: &str, count: Option<u64>) {
    let bytes = text.as_bytes();
    let total = count.unwrap_or(bytes.len() as u64 + 1);
    for index in 0..total {
        guest::write8(destination + index, bytes.get(index as usize).copied().unwrap_or(0));
    }
}
fn strcpy(call: &Call) -> Result<u64, KernelError> {
    write_c_text(call.arg(1), &guest_strings::read_c_string(call.arg(2)), None);
    Ok(call.arg(1))
}
fn strncpy(call: &Call) -> Result<u64, KernelError> {
    write_c_text(call.arg(1), &guest_strings::read_c_string(call.arg(2)), Some(call.arg(3)));
    Ok(call.arg(1))
}
fn strcat(call: &Call) -> Result<u64, KernelError> {
    let combined = alloc::format!("{}{}", guest_strings::read_c_string(call.arg(1)), guest_strings::read_c_string(call.arg(2)));
    write_c_text(call.arg(1), &combined, None);
    Ok(call.arg(1))
}
fn strchr(call: &Call) -> Result<u64, KernelError> {
    let text = guest_strings::read_c_string(call.arg(1));
    Ok(text.bytes().position(|byte| byte == call.arg(2) as u8).map_or(0, |index| call.arg(1) + index as u64))
}
fn strstr(call: &Call) -> Result<u64, KernelError> {
    let text = guest_strings::read_c_string(call.arg(1));
    let needle = guest_strings::read_c_string(call.arg(2));
    Ok(text.find(&needle).map_or(0, |index| call.arg(1) + index as u64))
}
/// sprintf(buf, fmt, ...): o formatador do kernel com seis argumentos.
fn sprintf(call: &Call) -> Result<u64, KernelError> {
    let arguments = [call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7), call.arg(8)];
    let text = guest_strings::format_guest_text(&guest_strings::read_c_string(call.arg(2)), &mut |index| arguments.get(index).copied().unwrap_or(0), false)?;
    write_c_text(call.arg(1), &text, None);
    Ok(text.len() as u64)
}
fn snprintf(call: &Call) -> Result<u64, KernelError> {
    let arguments = [call.arg(4), call.arg(5), call.arg(6), call.arg(7), call.arg(8)];
    let text = guest_strings::format_guest_text(&guest_strings::read_c_string(call.arg(3)), &mut |index| arguments.get(index).copied().unwrap_or(0), false)?;
    Ok(guest_strings::write_formatted_text(call.arg(1), call.arg(2), &text, false, false) as u64)
}
/// RtlRandom/RtlRandomEx: o LCG documentado.
fn random(call: &Call) -> Result<u64, KernelError> {
    let seed = guest::read32(call.arg(1)).wrapping_mul(214_013).wrapping_add(2_531_011);
    guest::write32(call.arg(1), seed);
    Ok(((seed >> 16) & 0x7FFF) as u64)
}
/// Versão publicada (10.0.26100, como no original).
const VERSION: (u32, u32, u32) = (10, 0, 26100);
/// RtlVerifyVersionInfo: blocos de 3 bits da máscara de condição.
fn verify_version_info(call: &Call) -> Result<u64, KernelError> {
    let (info, type_mask, condition) = (call.arg(1), call.arg(2) as u32, call.arg(3));
    let mut checks = Vec::new();
    if type_mask & 1 != 0 {
        checks.push((guest::read32(info + 4), VERSION.0));
    }
    if type_mask & 2 != 0 {
        checks.push((guest::read32(info + 8), VERSION.1));
    }
    if type_mask & 4 != 0 {
        checks.push((guest::read32(info + 12), VERSION.2));
    }
    // O original aplica o operador do bloco baixo a todos os campos.
    let operator = condition & 7;
    for (expected, actual) in checks {
        let matches = match operator {
            1 => actual == expected,
            2 => actual > expected,
            4 => actual < expected,
            3 => actual >= expected,
            5 => actual <= expected,
            _ => true,
        };
        if !matches {
            return Ok(signed_status(0xC000_0428));
        }
    }
    Ok(0)
}
/// VerSetConditionMask: condição deslocada por 3 bits × tipo (a
/// aproximação do original).
fn ver_set_condition_mask(call: &Call) -> Result<u64, KernelError> {
    let shift = (call.arg(2) as u32).saturating_mul(3);
    let increment = if shift < 64 { (call.arg(3) as u32 as u64) << shift } else { 0 };
    Ok(call.arg(1).wrapping_add(increment))
}
/// RtlWriteRegistryValue pelo serviço de chaves (com as notificações de filtro).
fn write_registry_value(call: &Call) -> Result<u64, KernelError> {
    let path = resolve_registry_path(call.arg(1) as u32 & 0xFFFF, &guest_strings::read_wide_string(call.arg(2)));
    let (status, handle) = key_services::open_path(&path, true)?;
    if status != 0 {
        return Ok(status as u64);
    }
    let data = guest::read_bytes(call.arg(5), call.arg(6) as u32 as usize);
    let result = key_services::named_value(key_services::Kind::Set, handle, &guest_strings::read_wide_string(call.arg(3)), call.arg(4) as u32, &data);
    registry::close_handle(handle as u32);
    Ok(result?.0 as u64)
}
fn query_registry_values_handler(call: &Call) -> Result<u64, KernelError> {
    query_registry_values(call.arg(1) as u32, call.arg(2), call.arg(3), call.arg(4), call.arg(5))
}
/// _vsnwprintf(buffer, capacity, format, va_list).
fn vsnwprintf(call: &Call) -> Result<u64, KernelError> {
    let format = guest_strings::read_wide_string(call.arg(3));
    let mut arguments = guest_strings::guest_format_arguments(call.arg(4));
    let text = guest_strings::format_guest_text(&format, &mut arguments, true)?;
    Ok(guest_strings::write_formatted_text(call.arg(1), call.arg(2), &text, true, true) as u64)
}
/// _wcsupr: maiúsculas no lugar, unidade a unidade.
fn wcsupr(call: &Call) -> Result<u64, KernelError> {
    let mut cursor = call.arg(1);
    loop {
        let unit = guest::read16(cursor);
        if unit == 0 {
            break;
        }
        let upper = char::from_u32(unit as u32).and_then(|character| character.to_uppercase().next()).map_or(unit, |character| {
            let mut buffer = [0u16; 2];
            character.encode_utf16(&mut buffer)[0]
        });
        guest::write16(cursor, upper);
        cursor += 2;
    }
    Ok(call.arg(1))
}
fn c_specific_handler(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::exceptions::specific_handler(call.arg(1), call.arg(2), call.arg(3), call.arg(4))
}

fn initialize_bit_map(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::bitmap::initialize(call.arg(1), call.arg(2), call.arg(3) as u32);
    Ok(0)
}
fn set_all_bits(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::bitmap::set_all(call.arg(1));
    Ok(0)
}
fn clear_bits(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::bitmap::clear_bits(call.arg(1), call.arg(2) as u32, call.arg(3) as u32);
    Ok(0)
}
fn clear_bit(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::bitmap::clear_bit(call.arg(1), call.arg(2) as u32);
    Ok(0)
}
fn find_clear_bits_and_set(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::bitmap::find_clear_and_set(call.arg(1), call.arg(2) as u32, call.arg(3) as u32) as u64)
}
/// RtlInitString: o texto não é copiado.
fn init_string(call: &Call) -> Result<u64, KernelError> {
    let (destination, source) = (call.arg(1), call.arg(2));
    let length = if source != 0 { guest_strings::read_c_string(source).len() as u16 } else { 0 };
    guest::write16(destination, length);
    guest::write16(destination + 2, length + 1);
    guest::write64(destination + 8, source);
    Ok(0)
}
/// RtlStringFromGUID: "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}" alocado.
fn string_from_guid(call: &Call) -> Result<u64, KernelError> {
    let (guid, output) = (call.arg(1), call.arg(2));
    let mut text = alloc::format!("{{{:08X}-{:04X}-{:04X}-", guest::read32(guid), guest::read16(guid + 4), guest::read16(guid + 6));
    for index in 0..2 {
        text.push_str(&alloc::format!("{:02X}", guest::read8(guid + 8 + index)));
    }
    text.push('-');
    for index in 2..8 {
        text.push_str(&alloc::format!("{:02X}", guest::read8(guid + 8 + index)));
    }
    text.push('}');
    let length = text.len() as u64 * 2;
    let buffer = guest::alloc_bytes(length + 2);
    guest_strings::write_wide_string(buffer, &text);
    guest::write16(output, length as u16);
    guest::write16(output + 2, length as u16 + 2);
    guest::write64(output + 8, buffer);
    Ok(0)
}
/// RtlDuplicateUnicodeString(flags, source, destination): SEMPRE aloca um
/// buffer novo e copia a origem. `flags` não escolhe alocar — os bits são
/// NULL_TERMINATE (1) e ALLOCATE_NULL_STRING (2); ambos juntos ou outros bits
/// são inválidos. (Antes o OpenNT tratava flags!=0 como "alocar" e, com
/// flags=0, checava a capacidade do destino e devolvia BUFFER_TOO_SMALL.)
fn duplicate_unicode_string(call: &Call) -> Result<u64, KernelError> {
    const NULL_TERMINATE: u32 = 1;
    const ALLOCATE_NULL_STRING: u32 = 2;
    let (flags, source, destination) = (call.arg(1) as u32, call.arg(2), call.arg(3));
    if destination == 0 || flags & !3 != 0 || flags & 3 == 3 {
        return Ok(signed_status(0xC000_000D));
    }
    let length = guest::read16(source) as u64;
    let source_buffer = guest::read64(source + 8);
    // Origem vazia sem ALLOCATE_NULL_STRING: destino vazio e sem buffer.
    if length == 0 && flags & ALLOCATE_NULL_STRING == 0 {
        guest::write16(destination, 0);
        guest::write16(destination + 2, 0);
        guest::write64(destination + 8, 0);
        return Ok(0);
    }
    let terminator = if flags & NULL_TERMINATE != 0 { 2 } else { 0 };
    let buffer = guest::alloc_bytes((length + terminator).max(2));
    guest::write_bytes(buffer, &guest::read_bytes(source_buffer, length as usize));
    if terminator != 0 {
        guest::write16(buffer + length, 0);
    }
    guest::write16(destination, length as u16);
    guest::write16(destination + 2, (length + terminator) as u16);
    guest::write64(destination + 8, buffer);
    Ok(0)
}
fn create_registry_key(call: &Call) -> Result<u64, KernelError> {
    let path = resolve_registry_path(call.arg(1) as u32 & 0xFFFF, &guest_strings::read_wide_string(call.arg(2)));
    let (status, handle) = key_services::open_path(&path, true)?;
    if handle != 0 {
        registry::close_handle(handle as u32);
    }
    Ok(status as u64)
}
fn delete_registry_value(call: &Call) -> Result<u64, KernelError> {
    let path = resolve_registry_path(call.arg(1) as u32 & 0xFFFF, &guest_strings::read_wide_string(call.arg(2)));
    let (status, handle) = key_services::open_path(&path, false)?;
    if status != 0 {
        return Ok(status as u64);
    }
    let result = key_services::named_value(key_services::Kind::DeleteValue, handle, &guest_strings::read_wide_string(call.arg(3)), 0, &[]);
    registry::close_handle(handle as u32);
    Ok(result?.0 as u64)
}
/// RtlGetVersion: 10.0.26100, Win32 NT, estação de trabalho.
fn get_version(call: &Call) -> Result<u64, KernelError> {
    let info = call.arg(1);
    guest::write32(info + 4, VERSION.0);
    guest::write32(info + 8, VERSION.1);
    guest::write32(info + 12, VERSION.2);
    guest::write32(info + 16, 2);
    guest::write16(info + 0x114, 0x100);
    guest::write8(info + 0x116, 1);
    Ok(0)
}
/// Nenhuma configuração de feature publicada.
fn query_feature_configuration(_: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(0xC000_0225))
}
fn zero(_: &Call) -> Result<u64, KernelError> {
    Ok(0)
}
fn register_feature_configuration_change_notification(call: &Call) -> Result<u64, KernelError> {
    FEATURE_NOTIFICATIONS.lock().push((call.arg(1), call.arg(2)));
    if call.arg(3) != 0 {
        guest::write64(call.arg(3), call.arg(1));
    }
    Ok(0)
}
fn unregister_feature_configuration_change_notification(call: &Call) -> Result<u64, KernelError> {
    let mut notifications = FEATURE_NOTIFICATIONS.lock();
    let Some(index) = notifications.iter().position(|(callback, _)| *callback == call.arg(1)) else { return Ok(signed_status(0xC000_0225)) };
    notifications.remove(index);
    Ok(0)
}
/// RtlTimeToTimeFields: calendário civil a partir de 1601 (dia da semana incluso).
fn time_to_time_fields(call: &Call) -> Result<u64, KernelError> {
    let filetime = guest::read64(call.arg(1));
    let total_seconds = (filetime / 10_000_000) as i64;
    let days = total_seconds.div_euclid(86_400);
    let seconds_of_day = total_seconds.rem_euclid(86_400);
    let march_days = days - 134_774 + 719_468;
    let era = march_days.div_euclid(146_097);
    let day_of_era = march_days - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let full_year = year + if month <= 2 { 1 } else { 0 };
    let fields = [full_year, month, day, seconds_of_day / 3600, (seconds_of_day % 3600) / 60, seconds_of_day % 60, ((filetime % 10_000_000) / 10_000) as i64, (days + 1).rem_euclid(7)];
    for (index, value) in fields.iter().enumerate() {
        guest::write16(call.arg(2) + index as u64 * 2, *value as u16);
    }
    Ok(0)
}
/// RtlUpcaseUnicodeChar: ASCII e Latin-1 (exceto ÷).
fn upcase_unicode_char(call: &Call) -> Result<u64, KernelError> {
    let code = call.arg(1) as u16;
    Ok(if (0x61..=0x7A).contains(&code) || ((0xE0..=0xFE).contains(&code) && code != 0xF7) { code - 0x20 } else { code } as u64)
}
fn ansi_string_to_unicode_size(call: &Call) -> Result<u64, KernelError> {
    Ok((guest::read16(call.arg(1)) as u64 + 1) * 2)
}
/// RtlCreateSystemVolumeInformationFolder: abre/cria a pasta oculta de sistema.
fn create_system_volume_information_folder(call: &Call) -> Result<u64, KernelError> {
    let volume = guest_strings::read_unicode_string(call.arg(1));
    let folder = alloc::format!("{volume}{}System Volume Information", if volume.ends_with('\\') { "" } else { "\\" });
    let status = crate::ntos::io::file::zw::create_file_by_name(&folder, 3, 1)?;
    if status != 0 {
        debug_print!("[rtl] System Volume Information em {} -> 0x{:x}", volume, status);
    }
    Ok(status as u64)
}
fn strupr(call: &Call) -> Result<u64, KernelError> {
    let mut cursor = call.arg(1);
    loop {
        let byte = guest::read8(cursor);
        if byte == 0 {
            break;
        }
        if byte.is_ascii_lowercase() {
            guest::write8(cursor, byte - 0x20);
        }
        cursor += 1;
    }
    Ok(call.arg(1))
}
fn vsnprintf(call: &Call) -> Result<u64, KernelError> {
    let mut arguments = guest_strings::guest_format_arguments(call.arg(4));
    let text = guest_strings::format_guest_text(&guest_strings::read_c_string(call.arg(3)), &mut arguments, false)?;
    Ok(guest_strings::write_formatted_text(call.arg(1), call.arg(2), &text, false, true) as u64)
}
/// vDbgPrintExWithPrefix: prefixo + texto formatado na serial.
fn v_dbg_print_ex_with_prefix(call: &Call) -> Result<u64, KernelError> {
    let prefix = if call.arg(1) != 0 { guest_strings::read_c_string(call.arg(1)) } else { String::new() };
    let mut arguments = guest_strings::guest_format_arguments(call.arg(5));
    let text = guest_strings::format_guest_text(&guest_strings::read_c_string(call.arg(4)), &mut arguments, false)?;
    let text = text.strip_suffix('\n').map(|rest| rest.strip_suffix('\r').unwrap_or(rest)).unwrap_or(&text);
    debug_print!("{}{}", prefix, text);
    Ok(0)
}
fn wcsstr(call: &Call) -> Result<u64, KernelError> {
    let haystack = guest_strings::read_wide_units(call.arg(1));
    let needle = guest_strings::read_wide_units(call.arg(2));
    if needle.is_empty() {
        return Ok(call.arg(1));
    }
    Ok(haystack.windows(needle.len()).position(|window| window == needle.as_slice()).map_or(0, |index| call.arg(1) + index as u64 * 2))
}
fn fold(unit: u16) -> u16 {
    char::from_u32(unit as u32).and_then(|character| character.to_uppercase().next()).map_or(unit, |character| {
        let mut buffer = [0u16; 2];
        character.encode_utf16(&mut buffer)[0]
    })
}
/// Comparação WCHAR (com dobra de maiúsculas opcional e limite opcional).
fn compare_wide(left: u64, right: u64, limit: Option<u64>, insensitive: bool) -> u64 {
    let mut index = 0u64;
    loop {
        if limit.is_some_and(|limit| index >= limit) {
            return 0;
        }
        let mut a = guest::read16(left + index * 2);
        let mut b = guest::read16(right + index * 2);
        let zero = a == 0;
        if insensitive {
            a = fold(a);
            b = fold(b);
        }
        if a != b {
            return if a < b { (-1i64) as u64 } else { 1 };
        }
        if zero {
            return 0;
        }
        index += 1;
    }
}
fn wcscmp(call: &Call) -> Result<u64, KernelError> {
    Ok(compare_wide(call.arg(1), call.arg(2), None, false))
}
fn wcsncmp(call: &Call) -> Result<u64, KernelError> {
    Ok(compare_wide(call.arg(1), call.arg(2), Some(call.arg(3) as u32 as u64), false))
}
fn wcsicmp(call: &Call) -> Result<u64, KernelError> {
    Ok(compare_wide(call.arg(1), call.arg(2), None, true))
}
fn wcsnicmp(call: &Call) -> Result<u64, KernelError> {
    Ok(compare_wide(call.arg(1), call.arg(2), Some(call.arg(3) as u32 as u64), true))
}
fn wcslen(call: &Call) -> Result<u64, KernelError> {
    let mut count = 0;
    while guest::read16(call.arg(1) + count * 2) != 0 {
        count += 1;
    }
    Ok(count)
}
fn strnlen(call: &Call) -> Result<u64, KernelError> {
    let mut count = 0;
    while count < call.arg(2) && guest::read8(call.arg(1) + count) != 0 {
        count += 1;
    }
    Ok(count)
}
/// wcscat_s: EINVAL sem NUL no destino, ERANGE sem espaço.
fn wcscat_s(call: &Call) -> Result<u64, KernelError> {
    let (destination, capacity, source) = (call.arg(1), call.arg(2) as u32 as u64, call.arg(3));
    let text = guest_strings::read_wide_string(source);
    let mut length = 0;
    while length < capacity && guest::read16(destination + length * 2) != 0 {
        length += 1;
    }
    if length == capacity {
        return Ok(22);
    }
    if length + text.encode_utf16().count() as u64 + 1 > capacity {
        guest::write16(destination, 0);
        return Ok(34);
    }
    guest_strings::write_wide_string(destination + length * 2, &text);
    Ok(0)
}
fn wcscpy_s(call: &Call) -> Result<u64, KernelError> {
    let text = guest_strings::read_wide_string(call.arg(3));
    if text.encode_utf16().count() as u64 + 1 > call.arg(2) as u32 as u64 {
        guest::write16(call.arg(1), 0);
        return Ok(34);
    }
    guest_strings::write_wide_string(call.arg(1), &text);
    Ok(0)
}
fn strcpy_s(call: &Call) -> Result<u64, KernelError> {
    let text = guest_strings::read_c_string(call.arg(3));
    if text.len() as u64 + 1 > call.arg(2) as u32 as u64 {
        guest::write8(call.arg(1), 0);
        return Ok(34);
    }
    write_c_text(call.arg(1), &text, None);
    Ok(0)
}
/// strncpy_s: _TRUNCATE (-1) trunca; senão ERANGE quando não cabe.
fn strncpy_s(call: &Call) -> Result<u64, KernelError> {
    let (destination, capacity, source, count) = (call.arg(1), call.arg(2) as u32 as u64, call.arg(3), call.arg(4) as u32 as i32);
    let text = guest_strings::read_c_string(source);
    let bytes = text.as_bytes();
    let wanted = if count < 0 { bytes.len() as u64 } else { (count as u64).min(bytes.len() as u64) };
    if wanted >= capacity && count >= 0 {
        guest::write8(destination, 0);
        return Ok(34);
    }
    let writable = wanted.min(capacity.saturating_sub(1));
    for index in 0..writable {
        guest::write8(destination + index, bytes[index as usize]);
    }
    guest::write8(destination + writable, 0);
    Ok(if wanted > writable || (count < 0 && bytes.len() as u64 > writable) { 80 } else { 0 })
}
fn qsort(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::sort::sort_elements(call.arg(1), call.arg(2), call.arg(3), call.arg(4));
    Ok(0)
}
/// _snprintf_s(buffer, size, count, format, ...).
fn snprintf_s(call: &Call) -> Result<u64, KernelError> {
    let arguments = [call.arg(5), call.arg(6), call.arg(7), call.arg(8), call.arg(9), call.arg(10)];
    let text = guest_strings::format_guest_text(&guest_strings::read_c_string(call.arg(4)), &mut |index| arguments.get(index).copied().unwrap_or(0), false)?;
    let (buffer, capacity, count) = (call.arg(1), call.arg(2) as u32 as i64, call.arg(3) as u32 as i32);
    let limit = if count < 0 { capacity - 1 } else { (count as i64).min(capacity - 1) };
    let bytes = text.as_bytes();
    let writable = (bytes.len() as i64).min(limit).max(0);
    for index in 0..writable {
        guest::write8(buffer + index as u64, bytes[index as usize]);
    }
    if capacity > 0 {
        guest::write8(buffer + writable as u64, 0);
    }
    Ok(if writable < bytes.len() as i64 && count >= 0 { (-1i64) as u64 } else { writable as u64 })
}
fn write_wide_bounded(buffer: u64, capacity: u64, text: &str) -> u64 {
    let units = utf16(text);
    let writable = (units.len() as i64).min(capacity as i64 - 1).max(0) as usize;
    for (index, unit) in units.iter().take(writable).enumerate() {
        guest::write16(buffer + index as u64 * 2, *unit);
    }
    if capacity > 0 {
        guest::write16(buffer + writable as u64 * 2, 0);
    }
    if writable < units.len() {
        (-1i64) as u64
    } else {
        writable as u64
    }
}
fn swprintf_s(call: &Call) -> Result<u64, KernelError> {
    let arguments = [call.arg(4), call.arg(5), call.arg(6), call.arg(7), call.arg(8), call.arg(9)];
    let text = guest_strings::format_guest_text(&guest_strings::read_wide_string(call.arg(3)), &mut |index| arguments.get(index).copied().unwrap_or(0), true)?;
    Ok(write_wide_bounded(call.arg(1), call.arg(2) as u32 as u64, &text))
}
fn vswprintf_s(call: &Call) -> Result<u64, KernelError> {
    let mut arguments = guest_strings::guest_format_arguments(call.arg(4));
    let text = guest_strings::format_guest_text(&guest_strings::read_wide_string(call.arg(3)), &mut arguments, true)?;
    Ok(write_wide_bounded(call.arg(1), call.arg(2) as u32 as u64, &text))
}
fn nt_status_to_dos_error(call: &Call) -> Result<u64, KernelError> {
    Ok(status_to_dos_error(call.arg(1) as u32) as u64)
}
/// RtlGetEnabledExtendedFeatures: x87 e SSE.
fn get_enabled_extended_features(call: &Call) -> Result<u64, KernelError> {
    let enabled = 3;
    Ok(if call.arg(1) != 0 { enabled & call.arg(1) } else { enabled })
}
fn get_persisted_state_location(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::cm::persisted_state::query(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5), call.arg(6) as u32, call.arg(7)) as u64)
}
/// RtlMultiByteToUnicodeN: byte → WCHAR.
fn multi_byte_to_unicode_n(call: &Call) -> Result<u64, KernelError> {
    let (destination, maximum, needed, source, length) = (call.arg(1), call.arg(2) as u32 as u64, call.arg(3), call.arg(4), call.arg(5) as u32 as u64);
    let capacity = maximum / 2;
    let mut written = 0;
    while written < length && written < capacity {
        guest::write16(destination + written * 2, guest::read8(source + written) as u16);
        written += 1;
    }
    if needed != 0 {
        guest::write32(needed, (length * 2) as u32);
    }
    Ok(0)
}
fn pc_to_file_header(call: &Call) -> Result<u64, KernelError> {
    let base = crate::ntos::mm::loaded_images::find(call.arg(1)).map_or(0, |image| image.image_base);
    guest::write64(call.arg(2), base);
    Ok(base)
}
/// __chkstk exige a ABI nativa de sondagem de pilha (corpo x64 próprio).
fn chkstk(_: &Call) -> Result<u64, KernelError> {
    Err(KernelError::new("__chkstk requires the native stack-probe ABI"))
}
fn local_unwind(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::exceptions::unwind_ex(call.arg(1), call.arg(2), 0, 0, 0, 0)
}
fn image_nt_header(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::image::nt_header(call.arg(1))
}
fn image_nt_header_ex(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::image::nt_header_ex(call.arg(1) as u32, call.arg(2), call.arg(3), call.arg(4))? as u64)
}
fn image_directory_entry_to_data(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::image::directory_entry(call.arg(1), call.arg(2) & 0xFF != 0, call.arg(3) as u16 as u32, call.arg(4))
}
/// RtlTimeFieldsToTime: campos validados (1601–30827) → 100 ns desde 1601.
fn time_fields_to_time(call: &Call) -> Result<u64, KernelError> {
    let fields: Vec<i64> = (0..7).map(|index| guest::read16(call.arg(1) + index * 2) as i16 as i64).collect();
    let (year, month, day, hour, minute, second, millisecond) = (fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6]);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let months = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1601..=30827).contains(&year) || !(1..=12).contains(&month) || day < 1 || day > months[month as usize - 1] || !(0..=23).contains(&hour) || !(0..=59).contains(&minute) || !(0..=59).contains(&second) || !(0..=999).contains(&millisecond) {
        return Ok(0);
    }
    let previous = year - 1;
    let mut days = previous * 365 + previous / 4 - previous / 100 + previous / 400 - 584_388 + day - 1;
    for length in months.iter().take(month as usize - 1) {
        days += length;
    }
    let seconds = days as u64 * 86_400 + (hour * 3600 + minute * 60 + second) as u64;
    guest::write64(call.arg(2), seconds * 10_000_000 + millisecond as u64 * 10_000);
    Ok(1)
}
fn valid_sid(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::sid::valid(call.arg(1)) as u64)
}
fn check_token_membership(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::token::membership::check(call.arg(1), call.arg(2), call.arg(3))? as u64)
}
fn length_sid(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::sid::length(call.arg(1)) as u64)
}
fn copy_sid(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::sid::copy(call.arg(1) as u32, call.arg(2), call.arg(3)) as u64)
}
fn equal_sid(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::sid::equal(call.arg(1), call.arg(2)) as u64)
}
/// RtlInitializeSidEx: as subautoridades variádicas vêm dos argumentos 4 em diante.
fn initialize_sid_ex(call: &Call) -> Result<u64, KernelError> {
    let sub_authorities: Vec<u32> = (4..=14).map(|index| call.arg(index) as u32).collect();
    Ok(crate::ntos::se::sid::initialize_ex(call.arg(1), call.arg(2), call.arg(3) as u32, &sub_authorities) as u64)
}
fn get_ace(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::descriptor::get_ace(call.arg(1), call.arg(2) as u32, call.arg(3)) as u64)
}
fn get_dacl_security_descriptor(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::descriptor::get_dacl(call.arg(1), call.arg(2), call.arg(3), call.arg(4)) as u64)
}
fn get_owner_security_descriptor(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::descriptor::get_owner(call.arg(1), call.arg(2), call.arg(3)) as u64)
}
fn length_security_descriptor(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::descriptor::length(call.arg(1)) as u64)
}
fn absolute_to_self_relative_sd(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::descriptor::absolute_to_relative(call.arg(1), call.arg(2), call.arg(3)) as u64)
}
fn avl_insert_node(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::avl::insert(call.arg(1), call.arg(2), call.arg(3), call.arg(4))? as u64)
}
fn avl_remove_node(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::avl::remove(call.arg(1), call.arg(2))? as u64)
}
fn utf8_to_unicode_n(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::utf8::utf8_to_unicode(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4), call.arg(5) as u32)? as u64)
}
fn unicode_to_utf8_n(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::utf8::unicode_to_utf8(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4), call.arg(5) as u32)? as u64)
}
fn compare_unicode_strings(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::unicode::compare(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5) as u32)? as i64 as u64)
}
fn find_unicode_substring(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::unicode::find(call.arg(1), call.arg(2), call.arg(3) as u32)
}
fn create_unicode_string(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::unicode::create(call.arg(1), call.arg(2))? as u64)
}
fn guid_from_string(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::unicode::guid_from_string(call.arg(1), call.arg(2))? as u64)
}
/// RtlGetNtSystemRoot: KUSER_SHARED_DATA.NtSystemRoot.
fn get_nt_system_root(_: &Call) -> Result<u64, KernelError> {
    Ok(0xFFFF_F780_0000_0030)
}
fn stricmp(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::crt::stricmp(call.arg(1), call.arg(2))? as i64 as u64)
}
fn atoi(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::crt::atoi(call.arg(1))? as i64 as u64)
}
fn ultow_s(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::crt::ultow(call.arg(1) as u32, call.arg(2), call.arg(3), call.arg(4) as u32 as i32)? as u64)
}
fn bsearch(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::crt::binary_search(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), 0, false)
}
fn bsearch_s(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::crt::binary_search(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6), true)
}
fn isdigit(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::crt::isdigit(call.arg(1) as u32) as u64)
}
fn wcschr(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::crt::wcschr(call.arg(1), call.arg(2) as u32)
}
fn clear_all_bits(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::bitmap::clear_all(call.arg(1));
    Ok(0)
}
fn set_bits(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::bitmap::set_bits(call.arg(1), call.arg(2) as u32, call.arg(3) as u32);
    Ok(0)
}
fn set_bit(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::bitmap::set_bit(call.arg(1), call.arg(2) as u32);
    Ok(0)
}
fn test_bit(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::bitmap::test_bit(call.arg(1), call.arg(2) as u32) as u64)
}
fn find_clear_bits(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::bitmap::find_clear(call.arg(1), call.arg(2) as u32, call.arg(3) as u32) as u64)
}
fn find_set_bits(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::bitmap::find_set(call.arg(1), call.arg(2) as u32, call.arg(3) as u32) as u64)
}
fn find_set_bits_and_clear(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::bitmap::find_set_and_clear(call.arg(1), call.arg(2) as u32, call.arg(3) as u32) as u64)
}
fn are_bits_clear(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::bitmap::are_clear(call.arg(1), call.arg(2) as u32, call.arg(3) as u32) as u64)
}
fn are_bits_set(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::bitmap::are_set(call.arg(1), call.arg(2) as u32, call.arg(3) as u32) as u64)
}
fn number_of_set_bits(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::bitmap::number_set(call.arg(1)) as u64)
}
fn number_of_clear_bits(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::bitmap::number_clear(call.arg(1)) as u64)
}
fn interlocked_clear_bit_run(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::bitmap::interlocked_clear(call.arg(1), call.arg(2) as u32, call.arg(3) as u32);
    Ok(0)
}
fn interlocked_set_bit_run(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::bitmap::interlocked_set(call.arg(1), call.arg(2) as u32, call.arg(3) as u32);
    Ok(0)
}
fn interlocked_set_clear_run(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::bitmap::reserve_clear_run(call.arg(1), call.arg(2) as u32, call.arg(3) as u32) as u64)
}
fn run_once_initialize(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::run_once::initialize(call.arg(1))? as u64)
}
fn run_once_begin_initialize(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::run_once::begin_initialize(call.arg(1), call.arg(2) as u32, call.arg(3))? as u64)
}
fn run_once_complete(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::run_once::complete(call.arg(1), call.arg(2) as u32, call.arg(3))? as u64)
}
fn run_once_execute_once(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::run_once::execute(call.arg(1), call.arg(2), call.arg(3), call.arg(4))? as u64)
}
fn valid_acl(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::acl::valid(call.arg(1)) as u64)
}
fn valid_security_descriptor(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::descriptor::valid(call.arg(1)) as u64)
}
fn valid_relative_security_descriptor(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::descriptor::valid_relative(call.arg(1), call.arg(2) as u32, call.arg(3) as u32) as u64)
}

pub static GROUP: crate::ntos::init::exports::Group = crate::ntos::init::exports::Group {
    name: "rtl",
    names: &[
        "RtlInitUnicodeString", "RtlCompareUnicodeString", "RtlCopyUnicodeString", "RtlEqualUnicodeString", "RtlInitAnsiString", "RtlAnsiStringToUnicodeString", "RtlUnicodeStringToAnsiString", "RtlFreeAnsiString", "RtlFreeUnicodeString", "RtlEqualString", "InterlockedIncrement", "InterlockedDecrement", "InterlockedExchange", "InterlockedCompareExchange", "memset", "memcpy", "memmove", "RtlUnicodeStringToInteger", "RtlIntegerToUnicodeString", "RtlZeroMemory", "RtlFillMemory", "RtlCopyMemory", "RtlMoveMemory", "RtlCompareMemory", "RtlUpcaseUnicodeString", "RtlDowncaseUnicodeString", "RtlPrefixUnicodeString", "RtlAppendUnicodeStringToString", "RtlAppendUnicodeToString", "InterlockedPushEntryList", "InterlockedPopEntryList", "ExInterlockedInsertTailList", "ExInterlockedRemoveHeadList", "strlen", "strcmp", "strncmp", "strcpy", "strncpy", "strcat", "strchr", "strstr", "sprintf", "snprintf", "RtlRandom", "RtlRandomEx", "RtlVerifyVersionInfo", "VerSetConditionMask", "RtlWriteRegistryValue", "RtlQueryRegistryValues", "RtlQueryRegistryValuesEx", "_vsnwprintf", "_wcsupr", "__C_specific_handler", "RtlInitializeBitMap", "RtlSetAllBits", "RtlClearBits", "RtlClearBit", "RtlFindClearBitsAndSet", "RtlInitString", "RtlStringFromGUID", "RtlDuplicateUnicodeString", "RtlCreateRegistryKey", "RtlDeleteRegistryValue", "RtlGetVersion", "RtlQueryFeatureConfiguration", "RtlQueryFeatureConfigurationChangeStamp", "RtlRegisterFeatureConfigurationChangeNotification", "RtlUnregisterFeatureConfigurationChangeNotification", "RtlTimeToTimeFields", "RtlUpcaseUnicodeChar", "RtlxAnsiStringToUnicodeSize", "RtlCreateSystemVolumeInformationFolder", "_strupr", "_vsnprintf", "vDbgPrintExWithPrefix", "wcsstr", "wcscmp", "wcsncmp", "_wcsicmp", "_wcsnicmp", "wcslen", "strnlen", "wcscat_s", "wcscpy_s", "strcpy_s", "strncpy_s", "qsort", "_snprintf_s", "swprintf_s", "vswprintf_s", "RtlNtStatusToDosError", "RtlNtStatusToDosErrorNoTeb", "RtlGetEnabledExtendedFeatures", "RtlGetPersistedStateLocation", "RtlMultiByteToUnicodeN", "RtlPcToFileHeader", "__chkstk", "_local_unwind", "RtlImageNtHeader", "RtlImageNtHeaderEx", "RtlImageDirectoryEntryToData", "RtlTimeFieldsToTime", "RtlValidSid", "RtlCheckTokenMembership", "RtlLengthSid", "RtlCopySid", "RtlEqualSid", "RtlInitializeSidEx", "RtlGetAce", "RtlGetDaclSecurityDescriptor", "RtlGetOwnerSecurityDescriptor", "RtlLengthSecurityDescriptor", "RtlAbsoluteToSelfRelativeSD", "RtlAvlInsertNodeEx", "RtlAvlRemoveNode", "RtlUTF8ToUnicodeN", "RtlUnicodeToUTF8N", "RtlCompareUnicodeStrings", "RtlFindUnicodeSubstring", "RtlCreateUnicodeString", "RtlGUIDFromString", "RtlGetNtSystemRoot", "_stricmp", "atoi", "_ultow_s", "bsearch", "bsearch_s", "isdigit", "wcschr", "RtlClearAllBits", "RtlSetBits", "RtlSetBit", "RtlTestBit", "RtlFindClearBits", "RtlFindSetBits", "RtlFindSetBitsAndClear", "RtlAreBitsClear", "RtlAreBitsSet", "RtlNumberOfSetBits", "RtlNumberOfClearBits", "RtlInterlockedClearBitRun", "RtlInterlockedSetBitRun", "RtlInterlockedSetClearRun", "RtlRunOnceInitialize", "RtlRunOnceBeginInitialize", "RtlRunOnceComplete", "RtlRunOnceExecuteOnce", "RtlValidAcl", "RtlValidSecurityDescriptor", "RtlValidRelativeSecurityDescriptor",
    ],
    handlers: &[
        init_unicode_string, compare_unicode_string, copy_unicode_string, equal_unicode_string, init_ansi_string, ansi_string_to_unicode_string, unicode_string_to_ansi_string, free_ansi_string, free_unicode_string, equal_string, interlocked_increment, interlocked_decrement, interlocked_exchange, interlocked_compare_exchange, memset, memcpy, memcpy, unicode_string_to_integer, integer_to_unicode_string, zero_memory, fill_memory, copy_memory, move_memory, compare_memory, upcase_unicode_string, downcase_unicode_string, prefix_unicode_string, append_unicode_string_to_string, append_unicode_to_string, interlocked_push_entry_list, interlocked_pop_entry_list, ex_interlocked_insert_tail_list, ex_interlocked_remove_head_list, strlen, strcmp, strncmp, strcpy, strncpy, strcat, strchr, strstr, sprintf, snprintf, random, random, verify_version_info, ver_set_condition_mask, write_registry_value, query_registry_values_handler, query_registry_values_handler, vsnwprintf, wcsupr, c_specific_handler, initialize_bit_map, set_all_bits, clear_bits, clear_bit, find_clear_bits_and_set, init_string, string_from_guid, duplicate_unicode_string, create_registry_key, delete_registry_value, get_version, query_feature_configuration, zero, register_feature_configuration_change_notification, unregister_feature_configuration_change_notification, time_to_time_fields, upcase_unicode_char, ansi_string_to_unicode_size, create_system_volume_information_folder, strupr, vsnprintf, v_dbg_print_ex_with_prefix, wcsstr, wcscmp, wcsncmp, wcsicmp, wcsnicmp, wcslen, strnlen, wcscat_s, wcscpy_s, strcpy_s, strncpy_s, qsort, snprintf_s, swprintf_s, vswprintf_s, nt_status_to_dos_error, nt_status_to_dos_error, get_enabled_extended_features, get_persisted_state_location, multi_byte_to_unicode_n, pc_to_file_header, chkstk, local_unwind, image_nt_header, image_nt_header_ex, image_directory_entry_to_data, time_fields_to_time, valid_sid, check_token_membership, length_sid, copy_sid, equal_sid, initialize_sid_ex, get_ace, get_dacl_security_descriptor, get_owner_security_descriptor, length_security_descriptor, absolute_to_self_relative_sd, avl_insert_node, avl_remove_node, utf8_to_unicode_n, unicode_to_utf8_n, compare_unicode_strings, find_unicode_substring, create_unicode_string, guid_from_string, get_nt_system_root, stricmp, atoi, ultow_s, bsearch, bsearch_s, isdigit, wcschr, clear_all_bits, set_bits, set_bit, test_bit, find_clear_bits, find_set_bits, find_set_bits_and_clear, are_bits_clear, are_bits_set, number_of_set_bits, number_of_clear_bits, interlocked_clear_bit_run, interlocked_set_bit_run, interlocked_set_clear_run, run_once_initialize, run_once_begin_initialize, run_once_complete, run_once_execute_once, valid_acl, valid_security_descriptor, valid_relative_security_descriptor,
    ],
    data_exports: &[],
};

pub mod capability_check {
    //! RtlCapabilityCheck — `system32/win32/ntoskrnl/capability-check.js`.
    //!
    //! Falha interna interrompe o sistema; o sinal de transferência do CONTEXT
    //! continua propagando.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::se::capability::check as capability_check;

    fn check(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("capability-check", capability_check::check(call.arg(1), call.arg(2), call.arg(3)))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "capability-check",
        names: &["RtlCapabilityCheck"],
        handlers: &[check],
        data_exports: &[],
    };
}

pub mod check_registry_key {
    //! RtlCheckRegistryKey — `system32/win32/ntoskrnl/check-registry-key.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::cm::check_registry_key;

    fn check(call: &Call) -> Result<u64, KernelError> {
        Ok(check_registry_key::check(call.arg(1) as u32, call.arg(2))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "check-registry-key",
        names: &["RtlCheckRegistryKey"],
        handlers: &[check],
        data_exports: &[],
    };
}

pub mod exceptions {
    //! ExRaiseStatus, RtlRaiseStatus e RtlUnwindEx — `ntos/rtl/exceptions`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::exceptions;
    use crate::rtl::KernelError;

    fn raise_status(call: &Call) -> Result<u64, KernelError> {
        exceptions::raise_status(call.arg(1) as u32, 0, 0, 1)
    }

    fn unwind_ex(call: &Call) -> Result<u64, KernelError> {
        exceptions::unwind_ex(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6))
    }

    pub static GROUP: Group = Group { name: "exceptions", names: &["ExRaiseStatus", "RtlRaiseStatus", "RtlUnwindEx"], handlers: &[raise_status, raise_status, unwind_ex], data_exports: &[] };
}

pub mod feature_usage {
    //! RtlNotifyFeatureUsage — `system32/win32/ntoskrnl/feature-usage.js`.
    //!
    //! Com IF (0x200) ligado no EFLAGS do CONTEXT do chamador vale o IRQL
    //! corrente; com interrupções desligadas o relato é tratado em HIGH_LEVEL.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::cm::feature_usage;
    use crate::ntos::ke::irql;
    use crate::ntos::rtl::native_context;
    use crate::ntos::mm::guest_memory as guest;

    fn notify(call: &Call) -> Result<u64, KernelError> {
        let flags = guest::read32(native_context::current()? + 0x44);
        let level = if flags & 0x200 != 0 { irql::get_irql() } else { 15 };
        match feature_usage::notify(call.arg(1), Some(level)) {
            Err(error) if !native_context::is_transfer(&error) => {
                debug_print!("[feature-usage] fatal kernel report failure: {}", error);
                panic!("[feature-usage] fatal kernel report failure: {error}");
            }
            result => Ok(result? as u64),
        }
    }

    pub static GROUP: Group = Group {
        name: "feature-usage",
        names: &["RtlNotifyFeatureUsage"],
        handlers: &[notify],
        data_exports: &[],
    };
}

pub mod first_slist {
    //! FirstEntrySList — `system32/win32/ntoskrnl/first-slist.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ex::slist;

    fn first_entry_slist(call: &Call) -> Result<u64, KernelError> {
        Ok(slist::first(call.arg(1)))
    }

    pub static GROUP: Group = Group {
        name: "first-slist",
        names: &["FirstEntrySList"],
        handlers: &[first_entry_slist],
        data_exports: &[],
    };
}

pub mod package_claims {
    //! RtlQueryPackageClaims — `system32/win32/ntoskrnl/package-claims.js`.
    //!
    //! Falha interna interrompe o sistema; o sinal de transferência do CONTEXT
    //! continua propagando.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::se::package_claims;

    fn query_package_claims(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("package-claims", package_claims::query(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7), call.arg(8)))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "package-claims",
        names: &["RtlQueryPackageClaims"],
        handlers: &[query_package_claims],
        data_exports: &[],
    };
}

pub mod package_identity {
    //! RtlQueryPackageIdentity — `system32/win32/ntoskrnl/package-identity.js`.
    //!
    //! Falha interna interrompe o sistema; o sinal de transferência do CONTEXT
    //! continua propagando.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::se::package_identity;

    fn query_package_identity(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("package-identity", package_identity::query(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6)))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "package-identity",
        names: &["RtlQueryPackageIdentity"],
        handlers: &[query_package_identity],
        data_exports: &[],
    };
}

pub mod resource_lookup {
    //! LdrResFindResource — `system32/win32/ntoskrnl/resource-lookup.js`.
    //!
    //! Export observado na IAT da CI; o adaptador não modifica recursos nem
    //! política.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::resource::find as find_resource;
    use crate::rtl::KernelError;

    fn find_resource_export(call: &Call) -> Result<u64, KernelError> {
        Ok(find_resource::find(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7), call.arg(8), call.arg(9))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "resource-lookup",
        names: &["LdrResFindResource"],
        handlers: &[find_resource_export],
        data_exports: &[],
    };
}

pub mod resource_search {
    //! LdrResSearchResource — `system32/win32/ntoskrnl/resource-search.js`.
    //!
    //! Entrada contada observada na IAT da CI: compartilha o parser, os arquivos
    //! e os donos com LdrResFindResource, com os seus guardas próprios.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::resource::find as find_resource;
    use crate::rtl::KernelError;

    fn search_resource_export(call: &Call) -> Result<u64, KernelError> {
        Ok(find_resource::search(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7), call.arg(8))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "resource-search",
        names: &["LdrResSearchResource"],
        handlers: &[search_resource_export],
        data_exports: &[],
    };
}

pub mod state_separation {
    //! RtlIsStateSeparationEnabled — `system32/win32/ntoskrnl/state-separation.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::cm::state_separation;

    fn is_state_separation_enabled(_: &Call) -> Result<u64, KernelError> {
        Ok(state_separation::is_enabled()? as u64)
    }

    pub static GROUP: Group = Group {
        name: "state-separation",
        names: &["RtlIsStateSeparationEnabled"],
        handlers: &[is_state_separation_enabled],
        data_exports: &[],
    };
}

pub mod unwind {
    //! RtlLookupFunctionEntry e RtlVirtualUnwind — `ntos/rtl/unwind`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::unwind;
    use crate::rtl::KernelError;

    fn lookup_function_entry(call: &Call) -> Result<u64, KernelError> {
        unwind::lookup_function_entry(call.arg(1), call.arg(2), call.arg(3))
    }

    fn virtual_unwind(call: &Call) -> Result<u64, KernelError> {
        unwind::unwind(call.arg(1) as u32, call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7), call.arg(8))
    }

    pub static GROUP: Group = Group { name: "unwind", names: &["RtlLookupFunctionEntry", "RtlVirtualUnwind"], handlers: &[lookup_function_entry, virtual_unwind], data_exports: &[] };
}

pub mod generic_tables {
    //! Splay links, RTL_GENERIC_TABLE e RTL_AVL_TABLE (`ntos::rtl::{gentable,
    //! avltable}`), com as assinaturas do WDK.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::{avltable, gentable};
    use crate::rtl::KernelError;

    fn splay(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::splay(call.arg(1)))
    }
    fn delete(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::delete(call.arg(1)))
    }
    fn delete_no_splay(call: &Call) -> Result<u64, KernelError> {
        gentable::delete_no_splay(call.arg(1), call.arg(2));
        Ok(0)
    }
    fn subtree_successor(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::subtree_successor(call.arg(1)))
    }
    fn subtree_predecessor(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::subtree_predecessor(call.arg(1)))
    }
    fn real_successor(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::real_successor(call.arg(1)))
    }
    fn real_predecessor(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::real_predecessor(call.arg(1)))
    }

    pub static SPLAY_LINKS_GROUP: Group = Group {
        name: "splay-links",
        names: &["RtlSplay", "RtlDelete", "RtlDeleteNoSplay", "RtlSubtreeSuccessor", "RtlSubtreePredecessor", "RtlRealSuccessor", "RtlRealPredecessor"],
        handlers: &[splay, delete, delete_no_splay, subtree_successor, subtree_predecessor, real_successor, real_predecessor],
        data_exports: &[],
    };

    fn initialize(call: &Call) -> Result<u64, KernelError> {
        gentable::initialize(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5));
        Ok(0)
    }
    fn insert(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::insert(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4)))
    }
    fn insert_full(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::insert_full(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5), call.arg(6) as u32))
    }
    fn lookup(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::lookup(call.arg(1), call.arg(2)))
    }
    fn lookup_full(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::lookup_full(call.arg(1), call.arg(2), call.arg(3), call.arg(4)))
    }
    fn delete_element(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::delete_element(call.arg(1), call.arg(2)) as u64)
    }
    fn enumerate(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::enumerate(call.arg(1), call.arg(2) & 0xFF != 0))
    }
    fn enumerate_without_splaying(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::enumerate_without_splaying(call.arg(1), call.arg(2)))
    }
    fn get_element(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::get_element(call.arg(1), call.arg(2) as u32))
    }
    fn number(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::number(call.arg(1)) as u64)
    }
    fn is_empty(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::is_empty(call.arg(1)) as u64)
    }

    pub static GENERIC_TABLES_GROUP: Group = Group {
        name: "generic-tables",
        names: &[
            "RtlInitializeGenericTable", "RtlInsertElementGenericTable", "RtlInsertElementGenericTableFull", "RtlLookupElementGenericTable",
            "RtlLookupElementGenericTableFull", "RtlDeleteElementGenericTable", "RtlEnumerateGenericTable", "RtlEnumerateGenericTableWithoutSplaying",
            "RtlGetElementGenericTable", "RtlNumberGenericTableElements", "RtlIsGenericTableEmpty",
        ],
        handlers: &[initialize, insert, insert_full, lookup, lookup_full, delete_element, enumerate, enumerate_without_splaying, get_element, number, is_empty],
        data_exports: &[],
    };

    fn initialize_avl(call: &Call) -> Result<u64, KernelError> {
        avltable::initialize(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5));
        Ok(0)
    }
    fn insert_avl(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::insert(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4)))
    }
    fn insert_full_avl(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::insert_full(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5), call.arg(6) as u32))
    }
    fn lookup_avl(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::lookup(call.arg(1), call.arg(2)))
    }
    fn lookup_full_avl(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::lookup_full(call.arg(1), call.arg(2), call.arg(3), call.arg(4)))
    }
    fn delete_avl(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::delete(call.arg(1), call.arg(2)) as u64)
    }
    fn delete_avl_ex(call: &Call) -> Result<u64, KernelError> {
        avltable::delete_node(call.arg(1), call.arg(2));
        Ok(0)
    }
    fn enumerate_avl(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::enumerate(call.arg(1), call.arg(2) & 0xFF != 0))
    }
    fn enumerate_without_splaying_avl(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::enumerate_without_splaying(call.arg(1), call.arg(2)))
    }
    fn get_element_avl(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::get_element(call.arg(1), call.arg(2) as u32))
    }
    fn number_avl(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::number(call.arg(1)) as u64)
    }
    fn is_empty_avl(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::is_empty(call.arg(1)) as u64)
    }
    fn lookup_first_matching_avl(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::lookup_first_matching(call.arg(1), call.arg(2), call.arg(3)))
    }
    fn enumerate_like_a_directory(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::enumerate_like_a_directory(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32 != 0, call.arg(5), call.arg(6), call.arg(7)))
    }

    pub static AVL_TABLES_GROUP: Group = Group {
        name: "avl-tables",
        names: &[
            "RtlInitializeGenericTableAvl", "RtlInsertElementGenericTableAvl", "RtlInsertElementGenericTableFullAvl", "RtlLookupElementGenericTableAvl",
            "RtlLookupElementGenericTableFullAvl", "RtlDeleteElementGenericTableAvl", "RtlDeleteElementGenericTableAvlEx", "RtlEnumerateGenericTableAvl",
            "RtlEnumerateGenericTableWithoutSplayingAvl", "RtlGetElementGenericTableAvl", "RtlNumberGenericTableElementsAvl", "RtlIsGenericTableEmptyAvl",
            "RtlLookupFirstMatchingElementGenericTableAvl", "RtlEnumerateGenericTableLikeADirectory",
        ],
        handlers: &[
            initialize_avl, insert_avl, insert_full_avl, lookup_avl, lookup_full_avl, delete_avl, delete_avl_ex, enumerate_avl,
            enumerate_without_splaying_avl, get_element_avl, number_avl, is_empty_avl, lookup_first_matching_avl, enumerate_like_a_directory,
        ],
        data_exports: &[],
    };
}

pub mod rtl_security {
    //! Descritores de segurança, ACLs e SIDs do Rtl — delegam ao componente
    //! `se`, com as assinaturas e os NTSTATUS do WDK.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::{acl, descriptor, sid};
    use crate::rtl::KernelError;

    fn create_security_descriptor(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(descriptor::create(call.arg(1), call.arg(2) as u32)))
    }
    fn set_dacl(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(descriptor::set_dacl(call.arg(1), call.arg(2) & 0xFF != 0, call.arg(3), call.arg(4) & 0xFF != 0)))
    }
    fn set_sacl(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(descriptor::set_sacl(call.arg(1), call.arg(2) & 0xFF != 0, call.arg(3), call.arg(4) & 0xFF != 0)))
    }
    fn set_owner(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(descriptor::set_owner(call.arg(1), call.arg(2), call.arg(3) & 0xFF != 0)))
    }
    fn create_acl(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(acl::create(call.arg(1), call.arg(2) as u32, call.arg(3) as u32)))
    }
    fn add_access_allowed_ace(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(acl::add_known_ace(call.arg(1), call.arg(2) as u32, 0, call.arg(3) as u32, call.arg(4), 0)))
    }
    fn add_access_allowed_ace_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(acl::add_known_ace(call.arg(1), call.arg(2) as u32, call.arg(3) as u32, call.arg(4) as u32, call.arg(5), 0)))
    }
    fn initialize_sid(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(sid::initialize(call.arg(1), call.arg(2), call.arg(3) as u32)))
    }
    fn sub_authority_sid(call: &Call) -> Result<u64, KernelError> {
        Ok(sid::sub_authority(call.arg(1), call.arg(2)))
    }
    fn length_required_sid(call: &Call) -> Result<u64, KernelError> {
        Ok(sid::length_required(call.arg(1) as u32) as u64)
    }

    pub static GROUP: Group = Group {
        name: "rtl-security",
        names: &[
            "RtlCreateSecurityDescriptor", "RtlSetDaclSecurityDescriptor", "RtlSetSaclSecurityDescriptor",
            "RtlSetOwnerSecurityDescriptor", "RtlCreateAcl", "RtlAddAccessAllowedAce", "RtlAddAccessAllowedAceEx",
            "RtlInitializeSid", "RtlSubAuthoritySid", "RtlLengthRequiredSid",
        ],
        handlers: &[
            create_security_descriptor, set_dacl, set_sacl, set_owner, create_acl, add_access_allowed_ace,
            add_access_allowed_ace_ex, initialize_sid, sub_authority_sid, length_required_sid,
        ],
        data_exports: &[],
    };
}

pub mod rtl_crt_extended {
    //! Rtl + CRT importados pelo dxgkrnl.sys que faltavam ao OpenNT.
    //!
    //! Os 19 Rtl são bit-twiddling/strings/segurança puros ou finos
    //! encaminhamentos a `se::{descriptor,acl}`, `rtl::image` e
    //! `rtl::ansi_code_page`. Os 7 da CRT completam `rtl/crt.rs` para drivers C.

    use alloc::string::String;
    use alloc::vec::Vec;

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::rtl::guest_strings;
    use crate::rtl::KernelError;

    // ---- NTSTATUS usados (iguais aos irmãos de `se::descriptor`) -----------
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
    const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
    const STATUS_UNKNOWN_REVISION: u32 = 0xC000_0058; // convenção do componente `se`
    const STATUS_INVALID_ACL: u32 = 0xC000_0077;
    const STATUS_INVALID_SECURITY_DESCR: u32 = 0xC000_0079;
    const STATUS_REVISION_MISMATCH: u32 = 0xC000_0059;

    // =======================================================================
    // Rtl — segurança (descritores, ACLs, SIDs)
    // =======================================================================

    /// RtlMapGenericMask(PACCESS_MASK, PGENERIC_MAPPING): troca os quatro bits
    /// GENERIC_* pelos direitos específicos do GENERIC_MAPPING e limpa-os. Puro.
    fn map_generic_mask(call: &Call) -> Result<u64, KernelError> {
        let (mask_ptr, mapping) = (call.arg(1), call.arg(2));
        let mut mask = guest::read32(mask_ptr);
        if mask & 0x8000_0000 != 0 {
            mask |= guest::read32(mapping); // GenericRead
        }
        if mask & 0x4000_0000 != 0 {
            mask |= guest::read32(mapping + 4); // GenericWrite
        }
        if mask & 0x2000_0000 != 0 {
            mask |= guest::read32(mapping + 8); // GenericExecute
        }
        if mask & 0x1000_0000 != 0 {
            mask |= guest::read32(mapping + 12); // GenericAll
        }
        mask &= 0x0FFF_FFFF; // zera GENERIC_{READ,WRITE,EXECUTE,ALL}
        guest::write32(mask_ptr, mask);
        Ok(0)
    }

    /// RtlAddAce(PACL, Rev, StartIndex, AceList, AceListLength): insere ACEs
    /// cruas num índice, deslocando a cauda e somando ao AceCount.
    fn add_ace(call: &Call) -> Result<u64, KernelError> {
        let (acl, ace_revision, start_index, ace_list, ace_list_len) =
            (call.arg(1), call.arg(2) as u32, call.arg(3) as u32, call.arg(4), call.arg(5) & 0xFFFF_FFFF);
        if !crate::ntos::se::acl::valid(acl) {
            return Ok(signed_status(STATUS_INVALID_ACL));
        }
        let acl_revision = guest::read8(acl) as u32;
        if !(2..=4).contains(&ace_revision) || acl_revision > 4 {
            return Ok(signed_status(STATUS_REVISION_MISMATCH));
        }
        let acl_size = guest::read16(acl + 2) as u64;
        let count = guest::read16(acl + 4) as u64;
        let start = (start_index as u64).min(count);
        // Offset do ponto de inserção (após `start` ACEs) e do fim usado.
        let mut insert_at = 8u64;
        for _ in 0..start {
            insert_at += guest::read16(acl + insert_at + 2) as u64;
        }
        let mut used_end = insert_at;
        for _ in start..count {
            used_end += guest::read16(acl + used_end + 2) as u64;
        }
        if used_end + ace_list_len > acl_size {
            return Ok(signed_status(STATUS_BUFFER_TOO_SMALL));
        }
        // Abre espaço deslocando a cauda para frente (de trás para frente).
        let tail = used_end - insert_at;
        for k in 0..tail {
            let from = acl + used_end - 1 - k;
            guest::write8(from + ace_list_len, guest::read8(from));
        }
        for k in 0..ace_list_len {
            guest::write8(acl + insert_at + k, guest::read8(ace_list + k));
        }
        // Conta as ACEs inseridas e atualiza o cabeçalho.
        let (mut added, mut p) = (0u64, 0u64);
        while p < ace_list_len {
            let size = guest::read16(ace_list + p + 2) as u64;
            if size == 0 {
                break;
            }
            p += size;
            added += 1;
        }
        guest::write16(acl + 4, (count + added) as u16);
        if ace_revision > acl_revision {
            guest::write8(acl, ace_revision as u8);
        }
        Ok(0)
    }

    /// RtlGetSaclSecurityDescriptor(PSD, PBOOLEAN Present, PACL*, PBOOLEAN Defaulted).
    fn get_sacl_security_descriptor(call: &Call) -> Result<u64, KernelError> {
        use crate::ntos::se::descriptor;
        let (sd, present, acl_out, defaulted) = (call.arg(1), call.arg(2), call.arg(3), call.arg(4));
        if guest::read8(sd) != 1 {
            return Ok(signed_status(STATUS_UNKNOWN_REVISION));
        }
        let control = descriptor::control(sd);
        guest::write8(present, (control & 0x0010 != 0) as u8); // SE_SACL_PRESENT
        if control & 0x0010 != 0 {
            guest::write64(acl_out, descriptor::component(sd, control, 2));
            guest::write8(defaulted, ((control >> 5) & 1) as u8); // SE_SACL_DEFAULTED=0x20
        }
        Ok(0)
    }

    /// RtlGetGroupSecurityDescriptor(PSD, PSID* Group, PBOOLEAN Defaulted).
    fn get_group_security_descriptor(call: &Call) -> Result<u64, KernelError> {
        use crate::ntos::se::descriptor;
        let (sd, group_out, defaulted) = (call.arg(1), call.arg(2), call.arg(3));
        if guest::read8(sd) != 1 {
            return Ok(signed_status(STATUS_UNKNOWN_REVISION));
        }
        let control = descriptor::control(sd);
        guest::write64(group_out, descriptor::component(sd, control, 1));
        guest::write8(defaulted, ((control >> 1) & 1) as u8); // SE_GROUP_DEFAULTED=0x2
        Ok(0)
    }

    /// RtlSetGroupSecurityDescriptor(PSD, PSID Group, BOOLEAN Defaulted). SD absoluto.
    fn set_group_security_descriptor(call: &Call) -> Result<u64, KernelError> {
        let (sd, group, defaulted) = (call.arg(1), call.arg(2), call.arg(3) & 0xFF != 0);
        if guest::read8(sd) != 1 {
            return Ok(signed_status(STATUS_UNKNOWN_REVISION));
        }
        let control = guest::read16(sd + 2);
        if control & 0x8000 != 0 {
            return Ok(signed_status(STATUS_INVALID_SECURITY_DESCR)); // SE_SELF_RELATIVE
        }
        guest::write64(sd + 0x10, group); // Group está em +0x10 (owner +8, group +0x10)
        let mut value = control & !0x0002;
        if defaulted {
            value |= 0x0002;
        }
        guest::write16(sd + 2, value);
        Ok(0)
    }

    /// RtlSubAuthorityCountSid(PSID) = &Sid->SubAuthorityCount (lea rax,[rcx+1]).
    fn sub_authority_count_sid(call: &Call) -> Result<u64, KernelError> {
        Ok(call.arg(1) + 1)
    }

    /// RtlCopyLuid(PLUID Dest, PLUID Src): copia os 8 bytes do LUID.
    fn copy_luid(call: &Call) -> Result<u64, KernelError> {
        guest::write64(call.arg(1), guest::read64(call.arg(2)));
        Ok(0)
    }

    // =======================================================================
    // Rtl — strings / NLS / números
    // =======================================================================

    /// RtlAnsiCharToUnicodeChar(PUCHAR* SourcePtr): traduz um char ANSI pela
    /// página de código instalada e avança *SourcePtr (SBCS = 1 byte).
    fn ansi_char_to_unicode_char(call: &Call) -> Result<u64, KernelError> {
        let pointer_field = call.arg(1);
        let source = guest::read64(pointer_field);
        let byte = guest::read8(source);
        guest::write64(pointer_field, source + 1);
        // ASCII é identidade; o intervalo alto passa pela página instalada,
        // com recuo para identidade se o NLS não estiver disponível.
        let wide = if byte < 0x80 {
            byte as u16
        } else {
            match crate::ntos::rtl::ansi_code_page::current() {
                Ok(code_page) => {
                    let input = guest::alloc_bytes(1);
                    let output = guest::alloc_bytes(2);
                    guest::write8(input, byte);
                    let unit = code_page.write_unicode(input, 1, output, 1).ok().map_or(byte as u16, |_| guest::read16(output));
                    guest::free_bytes(input);
                    guest::free_bytes(output);
                    unit
                }
                Err(_) => byte as u16,
            }
        };
        Ok(wide as u64)
    }

    /// RtlAppendStringToString(PSTRING Dest, const STRING* Src): concatena uma
    /// STRING ANSI contada (sem terminador), respeitando MaximumLength.
    fn append_string_to_string(call: &Call) -> Result<u64, KernelError> {
        let (dest, src) = (call.arg(1), call.arg(2));
        let src_len = guest::read16(src) as u64;
        if src_len == 0 {
            return Ok(0);
        }
        let dest_len = guest::read16(dest) as u64;
        if dest_len + src_len > guest::read16(dest + 2) as u64 {
            return Ok(signed_status(STATUS_BUFFER_TOO_SMALL));
        }
        let (dest_buffer, src_buffer) = (guest::read64(dest + 8), guest::read64(src + 8));
        for index in 0..src_len {
            guest::write8(dest_buffer + dest_len + index, guest::read8(src_buffer + index));
        }
        guest::write16(dest, (dest_len + src_len) as u16);
        Ok(0)
    }

    fn format_radix64(mut value: u64, base: u32) -> String {
        if value == 0 {
            return String::from("0");
        }
        let mut digits = Vec::new();
        while value > 0 {
            digits.push(core::char::from_digit((value % base as u64) as u32, base).unwrap_or('0'));
            value /= base as u64;
        }
        digits.iter().rev().collect()
    }

    /// Grava um texto numa UNICODE_STRING de destino (buffer já alocado),
    /// terminada em NUL; BUFFER_OVERFLOW se não couber.
    fn store_counted_unicode(destination: u64, text: &str) -> u64 {
        let units: Vec<u16> = text.encode_utf16().collect();
        if (units.len() + 1) * 2 > guest::read16(destination + 2) as usize {
            return signed_status(STATUS_BUFFER_OVERFLOW);
        }
        let buffer = guest::read64(destination + 8);
        for (index, unit) in units.iter().enumerate() {
            guest::write16(buffer + index as u64 * 2, *unit);
        }
        guest::write16(buffer + units.len() as u64 * 2, 0);
        guest::write16(destination, (units.len() * 2) as u16);
        0
    }

    /// RtlInt64ToUnicodeString(ULONGLONG, Base, PUNICODE_STRING): formata um
    /// inteiro de 64 bits (bases 2, 8, 10, 16).
    fn int64_to_unicode_string(call: &Call) -> Result<u64, KernelError> {
        let base = match call.arg(2) as u32 {
            0 => 10,
            base => base,
        };
        if ![2, 8, 10, 16].contains(&base) {
            return Ok(signed_status(STATUS_INVALID_PARAMETER));
        }
        Ok(store_counted_unicode(call.arg(3), &format_radix64(call.arg(1), base)))
    }

    /// RtlHashUnicodeString(PCUNICODE_STRING, CaseInsensitive, Alg, PULONG Hash):
    /// hash X65599 (Alg 0=default/1). Alg>1 = STATUS_INVALID_PARAMETER.
    fn hash_unicode_string(call: &Call) -> Result<u64, KernelError> {
        let (string, case_insensitive, algorithm, hash_out) =
            (call.arg(1), call.arg(2) & 0xFF != 0, call.arg(3) as u32, call.arg(4));
        if algorithm > 1 {
            return Ok(signed_status(STATUS_INVALID_PARAMETER));
        }
        let length_units = guest::read16(string) as u64 / 2;
        let buffer = guest::read64(string + 8);
        let upcase = |unit: u16| {
            crate::ntos::rtl::unicode_case::upcase_char(unit).unwrap_or(if (0x61..=0x7A).contains(&unit) { unit - 0x20 } else { unit })
        };
        let mut hash = 0u32;
        for index in 0..length_units {
            let mut unit = guest::read16(buffer + index * 2);
            if case_insensitive {
                unit = upcase(unit);
            }
            hash = hash.wrapping_mul(65599).wrapping_add(unit as u32);
        }
        guest::write32(hash_out, hash);
        Ok(0)
    }

    /// RtlFormatCurrentUserKeyPath(PUNICODE_STRING): monta "\REGISTRY\USER\<SID>"
    /// do token corrente. Sem usuário interativo o kernel roda como SYSTEM.
    fn format_current_user_key_path(call: &Call) -> Result<u64, KernelError> {
        let output = call.arg(1);
        let text = "\\REGISTRY\\USER\\S-1-5-18";
        let bytes = text.encode_utf16().count() as u64 * 2;
        let buffer = guest::alloc_bytes(bytes + 2);
        guest_strings::write_wide_string(buffer, text);
        guest::write16(output, bytes as u16);
        guest::write16(output + 2, (bytes + 2) as u16);
        guest::write64(output + 8, buffer);
        Ok(0)
    }

    // =======================================================================
    // Rtl — informação do sistema (KUSER_SHARED_DATA / produto)
    // =======================================================================

    /// RtlGetNtProductType(PNT_PRODUCT_TYPE): NtProductWinNt(1), TRUE.
    fn get_nt_product_type(call: &Call) -> Result<u64, KernelError> {
        guest::write32(call.arg(1), 1); // NtProductWinNt
        Ok(1)
    }

    /// RtlGetSuiteMask(): KUSER_SHARED_DATA.SuiteMask (estação de trabalho = 0).
    fn get_suite_mask(_: &Call) -> Result<u64, KernelError> {
        Ok(0)
    }

    /// RtlIsMultiSessionSku(): bit 8 de SharedDataFlags — FALSE.
    fn is_multi_session_sku(_: &Call) -> Result<u64, KernelError> {
        Ok(0)
    }

    /// RtlGetProductInfo(OSMajor, OSMinor, SpMajor, SpMinor, PULONG ProductType):
    /// edição fixa PRODUCT_PROFESSIONAL(0x30), TRUE.
    fn get_product_info(call: &Call) -> Result<u64, KernelError> {
        guest::write32(call.arg(5), 0x0000_0030); // PRODUCT_PROFESSIONAL
        Ok(1)
    }

    // =======================================================================
    // Rtl — imagens / backtrace / GUID
    // =======================================================================

    /// RtlFindExportedRoutineByName(PVOID ImageBase, PCCH Name): varre a EDATA
    /// de uma imagem carregada e devolve o VA do export (NULL em forwarder).
    fn find_exported_routine_by_name(call: &Call) -> Result<u64, KernelError> {
        let (base, name_pointer) = (call.arg(1), call.arg(2));
        let target = guest_strings::read_c_string(name_pointer);
        let size_cell = guest::alloc_bytes(4);
        let directory = crate::ntos::rtl::image::directory_entry(base, true, 0, size_cell).unwrap_or(0);
        let directory_size = guest::read32(size_cell) as u64;
        guest::free_bytes(size_cell);
        if directory == 0 {
            return Ok(0);
        }
        let export_rva = directory.wrapping_sub(base); // directory = base + export_rva
        let number_of_names = guest::read32(directory + 0x18) as u64;
        let functions = base + guest::read32(directory + 0x1C) as u64;
        let names = base + guest::read32(directory + 0x20) as u64;
        let ordinals = base + guest::read32(directory + 0x24) as u64;
        for index in 0..number_of_names {
            let name_rva = guest::read32(names + index * 4) as u64;
            if guest_strings::read_c_string(base + name_rva) == target {
                let ordinal = guest::read16(ordinals + index * 2) as u64;
                let function_rva = guest::read32(functions + ordinal * 4) as u64;
                if function_rva >= export_rva && function_rva < export_rva + directory_size {
                    return Ok(0); // forwarder
                }
                return Ok(base + function_rva);
            }
        }
        Ok(0)
    }

    /// RtlCaptureStackBackTrace(Skip, Capture, PVOID* BackTrace, PULONG Hash):
    /// varre a pilha do chamador por endereços de retorno em imagens carregadas.
    /// Seguro (try_read, limitado) e sem UB se nada for reconhecível.
    fn capture_stack_back_trace(call: &Call) -> Result<u64, KernelError> {
        let (skip, want, array, hash_out) =
            (call.arg(1) as usize, (call.arg(2) as usize).min(0xC0), call.arg(3), call.arg(4));
        let (mut captured, mut seen, mut hash, mut slot, mut scanned) = (0usize, 0usize, 0u32, call.frame, 0usize);
        while captured < want && scanned < 1024 {
            if let Ok(value) = guest::try_read64(slot) {
                if value != 0 && crate::ntos::mm::loaded_images::find(value).is_some() {
                    if seen >= skip {
                        guest::write64(array + captured as u64 * 8, value);
                        hash = hash.wrapping_add(value as u32);
                        captured += 1;
                    }
                    seen += 1;
                }
            }
            slot += 8;
            scanned += 1;
        }
        if hash_out != 0 {
            guest::write32(hash_out, hash);
        }
        Ok(captured as u64)
    }

    /// SHA-1 (RFC 3174) — base do GUID v5. Não existia no kernel (só SHA-256).
    fn sha1(data: &[u8]) -> [u8; 20] {
        let mut h: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
        let bit_length = (data.len() as u64) * 8;
        let mut message = data.to_vec();
        message.push(0x80);
        while message.len() % 64 != 56 {
            message.push(0);
        }
        message.extend_from_slice(&bit_length.to_be_bytes());
        for chunk in message.chunks_exact(64) {
            let mut w = [0u32; 80];
            for (index, word) in w.iter_mut().take(16).enumerate() {
                *word = u32::from_be_bytes([chunk[index * 4], chunk[index * 4 + 1], chunk[index * 4 + 2], chunk[index * 4 + 3]]);
            }
            for index in 16..80 {
                w[index] = (w[index - 3] ^ w[index - 8] ^ w[index - 14] ^ w[index - 16]).rotate_left(1);
            }
            let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
            for (index, word) in w.iter().enumerate() {
                let (f, k) = match index {
                    0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                    20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                    _ => (b ^ c ^ d, 0xCA62_C1D6),
                };
                let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*word);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }
            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
        }
        let mut output = [0u8; 20];
        for (index, word) in h.iter().enumerate() {
            output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        output
    }

    /// RtlGenerateClass5Guid(GUID Namespace, const UCHAR* Name, Len, GUID* Out):
    /// UUID v5 (SHA-1, RFC 4122). O GUID por valor (>8 bytes) chega por ponteiro.
    fn generate_class5_guid(call: &Call) -> Result<u64, KernelError> {
        let (namespace, name, name_length, output) = (call.arg(1), call.arg(2), call.arg(3) as usize, call.arg(4));
        if namespace == 0 || output == 0 {
            return Ok(signed_status(STATUS_INVALID_PARAMETER));
        }
        let ns = guest::read_bytes(namespace, 16);
        // Namespace em ordem de rede (big-endian) nos campos Data1/2/3.
        let mut message = Vec::with_capacity(16 + name_length);
        message.extend_from_slice(&[ns[3], ns[2], ns[1], ns[0], ns[5], ns[4], ns[7], ns[6]]);
        message.extend_from_slice(&ns[8..16]);
        if name_length > 0 {
            message.extend_from_slice(&guest::read_bytes(name, name_length));
        }
        let digest = sha1(&message);
        let mut g = [0u8; 16];
        g.copy_from_slice(&digest[0..16]);
        g[6] = (g[6] & 0x0F) | 0x50; // versão 5
        g[8] = (g[8] & 0x3F) | 0x80; // variante RFC 4122
        // Converte de volta ao layout nativo do GUID (Data1/2/3 little-endian).
        let out = [g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6], g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]];
        guest::write_bytes(output, &out);
        Ok(0)
    }

    // =======================================================================
    // CRT (C runtime exportada pelo ntoskrnl)
    // =======================================================================

    /// wcsnlen(const wchar_t*, size_t max).
    fn wcsnlen(call: &Call) -> Result<u64, KernelError> {
        let (source, maximum) = (call.arg(1), call.arg(2));
        let mut count = 0u64;
        while count < maximum && guest::read16(source + count * 2) != 0 {
            count += 1;
        }
        Ok(count)
    }

    /// wcsrchr(const wchar_t*, wchar_t): última ocorrência (o terminador conta).
    fn wcsrchr(call: &Call) -> Result<u64, KernelError> {
        let (source, target) = (call.arg(1), call.arg(2) as u16);
        let (mut index, mut last) = (0u64, 0u64);
        loop {
            let unit = guest::read16(source + index * 2);
            if unit == target {
                last = source + index * 2;
            }
            if unit == 0 {
                break;
            }
            index += 1;
        }
        Ok(last)
    }

    /// wcsncpy_s(wchar_t* d, size_t n, const wchar_t* s, size_t count): cópia
    /// limitada; _TRUNCATE((size_t)-1) trunca com STRUNCATE, senão ERANGE.
    fn wcsncpy_s(call: &Call) -> Result<u64, KernelError> {
        let (destination, capacity, source, count) = (call.arg(1), call.arg(2), call.arg(3), call.arg(4));
        if capacity == 0 {
            return Ok(22); // EINVAL
        }
        let units = guest_strings::read_wide_units(source);
        let truncate = count == u64::MAX;
        let wanted = if truncate { units.len() as u64 } else { count.min(units.len() as u64) };
        if !truncate && wanted + 1 > capacity {
            guest::write16(destination, 0);
            return Ok(34); // ERANGE
        }
        let writable = wanted.min(capacity - 1);
        for index in 0..writable {
            guest::write16(destination + index * 2, units[index as usize]);
        }
        guest::write16(destination + writable * 2, 0);
        Ok(if truncate && units.len() as u64 > writable { 80 } else { 0 }) // STRUNCATE/0
    }

    /// _snwprintf(wchar_t*, size_t, const wchar_t*, ...): formatador largo
    /// (semântica legada: -1 quando a saída não cabe).
    fn snwprintf(call: &Call) -> Result<u64, KernelError> {
        let arguments = [call.arg(4), call.arg(5), call.arg(6), call.arg(7), call.arg(8), call.arg(9)];
        let text = guest_strings::format_guest_text(
            &guest_strings::read_wide_string(call.arg(3)),
            &mut |index| arguments.get(index).copied().unwrap_or(0),
            true,
        )?;
        Ok(guest_strings::write_formatted_text(call.arg(1), call.arg(2), &text, true, true) as u64)
    }

    /// _wcslwr(wchar_t*): minúsculas no lugar, unidade a unidade.
    fn wcslwr(call: &Call) -> Result<u64, KernelError> {
        let mut cursor = call.arg(1);
        loop {
            let unit = guest::read16(cursor);
            if unit == 0 {
                break;
            }
            let lower = char::from_u32(unit as u32).and_then(|character| character.to_lowercase().next()).map_or(unit, |character| {
                let mut buffer = [0u16; 2];
                character.encode_utf16(&mut buffer)[0]
            });
            guest::write16(cursor, lower);
            cursor += 2;
        }
        Ok(call.arg(1))
    }

    /// sqrt(double): argumento e resultado em XMM0. Lê/grava o slot XMM0 do
    /// CONTEXT capturado (CONTEXT+0x1A0, dentro do FXSAVE), pois o trampolim
    /// comum faz FXRSTOR64 na volta — assim o resultado chega ao chamador. O
    /// kernel é soft-float (sem SSE), então a raiz sai de `sqrt_bits`, em
    /// aritmética inteira sobre os bits IEEE-754.
    fn sqrt(call: &Call) -> Result<u64, KernelError> {
        if call.context == 0 {
            return Ok(0); // sem CONTEXT (chamada interna): nada a fazer
        }
        let slot = call.context + 0x1A0;
        guest::write64(slot, sqrt_bits(guest::read64(slot)));
        Ok(0)
    }

    /// Piso da raiz de um u128 por Newton. O palpite inicial 2^ceil(bits/2) é
    /// sempre >= a raiz, então a sequência decresce até o piso.
    fn isqrt_u128(value: u128) -> u128 {
        if value < 2 {
            return value;
        }
        let bits = 128 - value.leading_zeros();
        let mut guess: u128 = 1u128 << bits.div_ceil(2);
        loop {
            let next = (guess + value / guess) >> 1;
            if next >= guess {
                return guess;
            }
            guess = next;
        }
    }

    /// sqrt de binary64 com arredondamento ao mais próximo, como o `sqrtsd`:
    /// ±0 -> ±0, +inf -> +inf, NaN -> NaN silenciado, negativo ou -inf -> o NaN
    /// "indefinido" 0xFFF8_0000_0000_0000. Subnormais são normalizados antes.
    pub fn sqrt_bits(bits: u64) -> u64 {
        const INDEFINITE_NAN: u64 = 0xFFF8_0000_0000_0000;
        let negative = bits >> 63 != 0;
        let exponent = ((bits >> 52) & 0x7FF) as i64;
        let fraction = bits & ((1u64 << 52) - 1);
        if exponent == 0x7FF {
            if fraction != 0 {
                return bits | (1u64 << 51);
            }
            return if negative { INDEFINITE_NAN } else { bits };
        }
        if exponent == 0 && fraction == 0 {
            return bits;
        }
        if negative {
            return INDEFINITE_NAN;
        }
        // valor = mantissa * 2^(power - 52), com a mantissa em [2^52, 2^53).
        let (mut mantissa, mut power) = if exponent == 0 {
            let shift = fraction.leading_zeros() as i64 - 11;
            (fraction << shift, -1022 - shift)
        } else {
            (fraction | (1u64 << 52), exponent - 1023)
        };
        // Expoente par: sqrt(valor) = sqrt(mantissa << 52) * 2^(power/2 - 52).
        if power & 1 != 0 {
            mantissa <<= 1;
            power -= 1;
        }
        let wide = (mantissa as u128) << 52;
        let mut root = isqrt_u128(wide);
        // Arredonda para cima quando sqrt(wide) > root + 1/2 (empate exato
        // é impossível para a raiz de um inteiro).
        if wide - root * root > root {
            root += 1;
        }
        let mut half = power / 2;
        if root == 1u128 << 53 {
            root >>= 1;
            half += 1;
        }
        (((half + 1023) as u64) << 52) | (root as u64 & ((1u64 << 52) - 1))
    }

    /// _purecall(): guarda de chamada a função virtual pura. Nunca deve ocorrer
    /// legitimamente; derruba o sistema (KeBugCheckEx), como no ntoskrnl.
    fn purecall(_: &Call) -> Result<u64, KernelError> {
        crate::ntos::ke::bugcheck::bug_check_ex(0x0000_0139, 0x0000_0005, 0, 0, 0)
    }

    // ---- GROUP ------------------------------------------------------------

    pub static GROUP: Group = Group {
        name: "rtl-crt-extended",
        names: &[
            // --- Rtl (19) ---
            "RtlMapGenericMask",
            "RtlCaptureStackBackTrace",
            "RtlAddAce",
            "RtlAnsiCharToUnicodeChar",
            "RtlAppendStringToString",
            "RtlCopyLuid",
            "RtlFindExportedRoutineByName",
            "RtlFormatCurrentUserKeyPath",
            "RtlGenerateClass5Guid",
            "RtlGetGroupSecurityDescriptor",
            "RtlGetNtProductType",
            "RtlGetProductInfo",
            "RtlGetSaclSecurityDescriptor",
            "RtlGetSuiteMask",
            "RtlHashUnicodeString",
            "RtlInt64ToUnicodeString",
            "RtlIsMultiSessionSku",
            "RtlSetGroupSecurityDescriptor",
            "RtlSubAuthorityCountSid",
            // --- CRT (7) ---
            "_purecall",
            "_snwprintf",
            "_wcslwr",
            "sqrt",
            "wcsncpy_s",
            "wcsnlen",
            "wcsrchr",
        ],
        handlers: &[
            // --- Rtl (19) ---
            map_generic_mask,
            capture_stack_back_trace,
            add_ace,
            ansi_char_to_unicode_char,
            append_string_to_string,
            copy_luid,
            find_exported_routine_by_name,
            format_current_user_key_path,
            generate_class5_guid,
            get_group_security_descriptor,
            get_nt_product_type,
            get_product_info,
            get_sacl_security_descriptor,
            get_suite_mask,
            hash_unicode_string,
            int64_to_unicode_string,
            is_multi_session_sku,
            set_group_security_descriptor,
            sub_authority_count_sid,
            // --- CRT (7) ---
            purecall,
            snwprintf,
            wcslwr,
            sqrt,
            wcsncpy_s,
            wcsnlen,
            wcsrchr,
        ],
        data_exports: &[],
    };
}

// ===========================================================================
