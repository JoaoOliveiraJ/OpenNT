//! Registro pelo Rtl — RtlQueryRegistryValues[Ex], RtlWriteRegistryValue,
//! RtlCreateRegistryKey, RtlDeleteRegistryValue, RtlFormatCurrentUserKeyPath
//! e RtlOpenCurrentUser.
//!
//! Os caminhos relativos (RTL_REGISTRY_*) viram absolutos; as chaves e os
//! valores passam pelo serviço de chaves do Cm (com as notificações de
//! filtro). Os status do Cm voltam como vieram. A consulta segue o
//! RtlpQueryRegistryValues do ntoskrnl 19041 (abertura obrigatória da chave,
//! defaults, DIRECT, SUBKEY/TOPKEY, enumeração, DELETE e as checagens de
//! tipo).

use alloc::string::String;

use crate::hal::amd64::native_call;
use crate::ntos::cm::key::services as key_services;
use crate::ntos::cm::registry as cm_registry;
use crate::ntos::inc::types::{KeyValueFullInformation, NtStruct, ObjectAttributes, RtlQueryRegistryTable, SidAndAttributes, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

/// Caminho absoluto: o prefixo do RelativeTo (RtlpRegistryPaths, o mesmo do
/// RtlCheckRegistryKey), uma barra e o Path; RTL_REGISTRY_ABSOLUTE mantém o
/// texto.
pub fn resolve_registry_path(relative_to: u32, raw: &str) -> String {
    match crate::ntos::cm::check_registry_key::root_path(relative_to as usize) {
        Some(prefix) => alloc::format!("{prefix}\\{}", raw.trim_start_matches('\\')),
        None => String::from(raw),
    }
}

/// Caminho absoluto de um RelativeTo do convidado: os bits altos
/// (RTL_REGISTRY_OPTIONAL/HANDLE) ficam fora do código de raiz.
fn guest_registry_path(relative_to: u32, path: u64) -> String {
    resolve_registry_path(relative_to & 0xFFFF, &guest_strings::read_wide_string(path))
}

/// RTL_REGISTRY_HANDLE (wdm.h): o Path é o HANDLE de uma chave aberta, não
/// um texto.
const REGISTRY_HANDLE: u32 = 0x4000_0000;

/// Flags da RTL_QUERY_REGISTRY_TABLE (wdm.h).
const QUERY_REGISTRY_SUBKEY: u32 = 0x01;
const QUERY_REGISTRY_TOPKEY: u32 = 0x02;
const QUERY_REGISTRY_REQUIRED: u32 = 0x04;
const QUERY_REGISTRY_NOVALUE: u32 = 0x08;
const QUERY_REGISTRY_NOEXPAND: u32 = 0x10;
const QUERY_REGISTRY_DIRECT: u32 = 0x20;
const QUERY_REGISTRY_DELETE: u32 = 0x40;
const QUERY_REGISTRY_NOSTRING: u32 = 0x80;
const QUERY_REGISTRY_TYPECHECK: u32 = 0x100;

const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
const STATUS_NO_MORE_ENTRIES: u32 = 0x8000_001A;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_DATA_OVERRUN: u32 = 0xC000_003C;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_MULTI_SZ: u32 = 7;
/// 'Strg', a etiqueta do ExpAllocateStringRoutine.
const STRING_POOL_TAG: u32 = 0x6772_7453;

/// Um valor lido da chave (KEY_VALUE_FULL_INFORMATION): nome, tipo e dado.
struct RegistryValue {
    name: alloc::vec::Vec<u16>,
    value_type: u32,
    data: alloc::vec::Vec<u8>,
}

fn is_string(value_type: u32) -> bool {
    matches!(value_type, REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ)
}

/// UNICODE_STRING temporária no convidado: (descritor, buffer).
fn guest_unicode(units: &[u16]) -> (u64, u64) {
    let buffer = guest::alloc_bytes(units.len() as u64 * 2 + 2);
    guest::write_bytes(buffer, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<alloc::vec::Vec<u8>>());
    let descriptor = guest::alloc_bytes(UnicodeString::SIZE);
    // SAFETY: descritor recém-alocado.
    let string = unsafe { UnicodeString::at(descriptor) };
    string.length.set(units.len() as u16 * 2);
    string.maximum_length.set(units.len() as u16 * 2 + 2);
    string.buffer.set(buffer);
    (descriptor, buffer)
}

fn free_guest_unicode((descriptor, buffer): (u64, u64)) {
    guest::free_bytes(buffer);
    guest::free_bytes(descriptor);
}

/// Operação Zw sobre a chave aberta: PreviousMode = KernelMode.
fn key_operation(kind: key_services::Kind, key: u64, arguments: &[(&'static str, u64)]) -> Result<u32, KernelError> {
    key_services::key_operation(kind, key, &key_services::fields(arguments), false)
}

/// KEY_VALUE_FULL_INFORMATION de `read` (ZwQueryValueKey ou
/// ZwEnumerateValueKey, classe 1), crescendo o buffer no BUFFER_OVERFLOW.
fn read_full_value(read: &dyn Fn(u64, u64, u64) -> Result<u32, KernelError>) -> Result<(u32, Option<RegistryValue>), KernelError> {
    let returned = guest::alloc_bytes(8);
    let mut length = 0x88u64;
    let result = loop {
        let buffer = guest::alloc_bytes(length);
        let status = read(buffer, length, returned)?;
        if status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL {
            length = (guest::read32(returned) as u64).max(length + 0x80);
            guest::free_bytes(buffer);
            continue;
        }
        if status & 0x8000_0000 != 0 {
            guest::free_bytes(buffer);
            break (status, None);
        }
        // SAFETY: resposta KEY_VALUE_FULL_INFORMATION no buffer próprio.
        let full = unsafe { KeyValueFullInformation::at(buffer) };
        let name_length = full.name_length.get() as usize;
        let name: alloc::vec::Vec<u16> = guest::read_bytes(full.name[0].address(), name_length).chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
        let (offset, data_length) = (full.data_offset.get(), full.data_length.get());
        let mut data = if offset == u32::MAX { alloc::vec::Vec::new() } else { guest::read_bytes(buffer + offset as u64, data_length as usize) };
        let value_type = full.type_.get();
        guest::free_bytes(buffer);
        // O REG_MULTI_SZ ganha um terminador extra no fim do dado.
        if value_type == REG_MULTI_SZ {
            data.extend_from_slice(&[0, 0]);
        }
        break (status, Some(RegistryValue { name, value_type, data }));
    };
    guest::free_bytes(returned);
    Ok(result)
}

fn query_value_by_name(key: u64, name: u64) -> Result<(u32, Option<RegistryValue>), KernelError> {
    let units = guest_strings::read_wide_units(name);
    let string = guest_unicode(&units);
    let result = read_full_value(&|buffer, length, returned| key_operation(key_services::Kind::QueryValue, key, &[("name", string.0), ("klass", 1), ("out", buffer), ("length", length), ("returned", returned)]));
    free_guest_unicode(string);
    result
}

fn enumerate_value(key: u64, index: u32) -> Result<(u32, Option<RegistryValue>), KernelError> {
    read_full_value(&|buffer, length, returned| key_operation(key_services::Kind::EnumerateValue, key, &[("index", index as u64), ("klass", 1), ("out", buffer), ("length", length), ("returned", returned)]))
}

fn delete_value_by_units(key: u64, units: &[u16]) -> Result<u32, KernelError> {
    let string = guest_unicode(units);
    let status = key_operation(key_services::Kind::DeleteValue, key, &[("name", string.0)]);
    free_guest_unicode(string);
    status
}

/// ZwOpenKey(MAXIMUM_ALLOWED) de `name` relativo à chave `root`.
fn open_subkey(root: u64, name: u64) -> Result<(u32, u64), KernelError> {
    let units = guest_strings::read_wide_units(name);
    let string = guest_unicode(&units);
    let block = guest::alloc_bytes(ObjectAttributes::SIZE + 8);
    // SAFETY: bloco recém-alocado (OBJECT_ATTRIBUTES e o handle de saída).
    let attributes = unsafe { ObjectAttributes::at(block) };
    attributes.length.set(ObjectAttributes::SIZE as u32);
    attributes.root_directory.set(root);
    attributes.object_name.set(string.0);
    attributes.attributes.set(0x240);
    let output = block + ObjectAttributes::SIZE;
    let status = key_services::open(output, 0x0200_0000, block, false, 0)?;
    let handle = if status == 0 { guest::read64(output) } else { 0 };
    guest::free_bytes(block);
    free_guest_unicode(string);
    Ok((status, handle))
}

fn close_key(handle: u64) {
    cm_registry::close_handle(handle as u32);
}

/// RtlpQueryRegistryDirect: grava o dado em EntryContext. Strings vão para
/// a UNICODE_STRING (Buffer nulo = alocado do pool paginável com o tamanho do
/// dado, até 0xFFFE bytes, ou STATUS_NO_MEMORY); até 4 bytes, cópia crua;
/// acima disso, o primeiro LONG do destino diz o espaço: negativo = buffer
/// cru de -n bytes, não negativo = {tamanho, tipo, dado}.
fn query_registry_direct(value_type: u32, data: &ValueData, range: core::ops::Range<usize>, destination: u64) -> u32 {
    let length = range.len() as u32;
    if is_string(value_type) {
        let length = length.min(0xFFFE);
        // SAFETY: EntryContext de uma entrada DIRECT de string é uma UNICODE_STRING.
        let string = unsafe { UnicodeString::at(destination) };
        if string.buffer.get() == 0 {
            let buffer = crate::ntos::ex::pool_allocation::allocate_tagged(1, length as u64, STRING_POOL_TAG).unwrap_or(0);
            string.buffer.set(buffer);
            if buffer == 0 {
                return STATUS_NO_MEMORY;
            }
            string.maximum_length.set(length as u16);
        } else if length > string.maximum_length.get() as u32 {
            return STATUS_BUFFER_TOO_SMALL;
        }
        guest::write_bytes(string.buffer.get(), &data.bytes(range.start, length as usize));
        string.length.set((length as u16).wrapping_sub(2));
        return 0;
    }
    if length <= 4 {
        if length != 0 {
            guest::write_bytes(destination, &data.bytes(range.start, length as usize));
        }
        return 0;
    }
    let capacity = guest::read32(destination) as i32;
    if capacity < 0 {
        if capacity.unsigned_abs() < length {
            return STATUS_BUFFER_TOO_SMALL;
        }
        guest::write_bytes(destination, &data.bytes(range.start, length as usize));
        return 0;
    }
    if (capacity as u64) < length as u64 + 8 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    guest::write32(destination, length);
    guest::write32(destination + 4, value_type);
    guest::write_bytes(destination + 8, &data.bytes(range.start, length as usize));
    0
}

/// O dado entregue a uma entrada: o do valor lido da chave (no kernel) ou o
/// default da tabela, que fica onde o driver o pôs (DefaultData,
/// DefaultLength) e só é lido no que uma entrada DIRECT copia.
enum ValueData {
    Read(alloc::vec::Vec<u8>),
    Default { address: u64, length: u32 },
}

impl ValueData {
    fn len(&self) -> usize {
        match self {
            ValueData::Read(data) => data.len(),
            ValueData::Default { length, .. } => *length as usize,
        }
    }

    /// `count` bytes a partir de `start`.
    fn bytes(&self, start: usize, count: usize) -> alloc::vec::Vec<u8> {
        match self {
            ValueData::Read(data) => data[start..start + count].to_vec(),
            ValueData::Default { address, .. } => if count == 0 { alloc::vec::Vec::new() } else { guest::read_bytes(address + start as u64, count) },
        }
    }
}

/// Entrega um trecho do dado (do valor ou do default) à entrada: DIRECT
/// grava em EntryContext, senão a QueryRoutine do driver recebe (ValueName,
/// ValueType, ValueData, ValueLength, Context, EntryContext). Como no
/// RtlpCallQueryRegistryRoutine, o default vai pelo próprio ponteiro
/// DefaultData com o DefaultLength da entrada, sem cópia: a rotina do
/// driver decide quanto lê.
fn deliver(entry: &RtlQueryRegistryTable, value_name: u64, value_type: u32, data: &ValueData, range: core::ops::Range<usize>, context: u64) -> u32 {
    if entry.flags.get() & QUERY_REGISTRY_DIRECT != 0 {
        return query_registry_direct(value_type, data, range, entry.entry_context.get());
    }
    let (pointer, temporary) = match data {
        ValueData::Read(bytes) => {
            let buffer = guest::alloc_bytes(range.len().max(2) as u64);
            guest::write_bytes(buffer, &bytes[range.clone()]);
            (buffer, true)
        }
        ValueData::Default { address, .. } => (address + range.start as u64, false),
    };
    let status = native_call::call(entry.query_routine.get(), &[value_name, value_type as u64, pointer, range.len() as u64, context, entry.entry_context.get()]) as u32;
    if temporary {
        guest::free_bytes(pointer);
    }
    status
}

/// Bytes de uma string (`multi` = REG_MULTI_SZ) do convidado, com o(s)
/// terminador(es).
fn default_string_length(data: u64, multi: bool) -> u32 {
    let mut units = 0u64;
    if multi {
        if guest::read16(data) != 0 {
            loop {
                while guest::read16(data + units * 2) != 0 {
                    units += 1;
                }
                units += 1;
                if guest::read16(data + units * 2) == 0 {
                    break;
                }
            }
        }
        return (units * 2 + 2) as u32;
    }
    while guest::read16(data + units * 2) != 0 {
        units += 1;
    }
    (units * 2 + 2) as u32
}

/// RtlpCallQueryRegistryRoutine: um valor ausente (ou REG_NONE, ou vazio do
/// mesmo tipo do default) usa o default da entrada (DefaultType REG_NONE =
/// nada, ou STATUS_OBJECT_NAME_NOT_FOUND com REQUIRED; DefaultLength 0 numa
/// string = o tamanho dela, DefaultData nulo = STATUS_DATA_OVERRUN); TYPECHECK
/// compara o tipo com o byte alto de DefaultType; NOSTRING pula strings
/// numa entrada DIRECT; sem NOEXPAND, um REG_MULTI_SZ é entregue string a
/// string como REG_SZ e um REG_EXPAND_SZ com '%' é recusado
/// (STATUS_INVALID_PARAMETER: o kernel não expande variáveis). Um
/// STATUS_BUFFER_TOO_SMALL da entrega vira sucesso.
fn call_query_routine(entry: &RtlQueryRegistryTable, value: Option<&RegistryValue>, context: u64) -> u32 {
    let flags = entry.flags.get();
    let default_type = entry.default_type.get() & 0xFF;
    let found = value.filter(|value| value.value_type != 0 && !(value.data.is_empty() && value.value_type == default_type));
    let name_copy;
    let (value_name, value_type, data) = match found {
        Some(value) => {
            let mut units = value.name.clone();
            units.push(0);
            name_copy = guest::alloc_bytes(units.len() as u64 * 2);
            guest::write_bytes(name_copy, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<alloc::vec::Vec<u8>>());
            (if flags & QUERY_REGISTRY_DIRECT != 0 { entry.name.get() } else { name_copy }, value.value_type, ValueData::Read(value.data.clone()))
        }
        None => {
            name_copy = 0;
            if default_type == 0 {
                return if flags & QUERY_REGISTRY_REQUIRED != 0 { STATUS_OBJECT_NAME_NOT_FOUND } else { 0 };
            }
            let default_data = entry.default_data.get();
            let mut length = entry.default_length.get();
            if length == 0 && is_string(default_type) {
                if default_data == 0 {
                    return STATUS_DATA_OVERRUN;
                }
                length = default_string_length(default_data, default_type == REG_MULTI_SZ);
            }
            (entry.name.get(), default_type, ValueData::Default { address: default_data, length })
        }
    };
    let status = (|| {
        if flags & QUERY_REGISTRY_DIRECT != 0 {
            if flags & QUERY_REGISTRY_TYPECHECK != 0 {
                if entry.default_type.get() >> 24 != value_type {
                    return STATUS_OBJECT_TYPE_MISMATCH;
                }
            } else if flags & QUERY_REGISTRY_NOSTRING != 0 && is_string(value_type) {
                return if flags & QUERY_REGISTRY_REQUIRED != 0 { STATUS_OBJECT_NAME_NOT_FOUND } else { 0 };
            }
        }
        if flags & QUERY_REGISTRY_NOEXPAND == 0 {
            if value_type == REG_MULTI_SZ {
                let bytes = data.bytes(0, data.len());
                let end = bytes.len().saturating_sub(4);
                let mut start = 0usize;
                while start < end {
                    let mut stop = start;
                    while stop + 1 < bytes.len() && (bytes[stop] | bytes[stop + 1]) != 0 {
                        stop += 2;
                    }
                    stop = (stop + 2).min(bytes.len());
                    let status = deliver(entry, value_name, REG_SZ, &data, start..stop, context);
                    if status != STATUS_BUFFER_TOO_SMALL && status & 0x8000_0000 != 0 {
                        return status;
                    }
                    start = stop;
                }
                return 0;
            }
            if value_type == REG_EXPAND_SZ && data.len() >= 2 && data.bytes(0, data.len() - 2).chunks_exact(2).any(|pair| pair == [b'%', 0]) {
                return STATUS_INVALID_PARAMETER;
            }
        }
        match deliver(entry, value_name, value_type, &data, 0..data.len(), context) {
            STATUS_BUFFER_TOO_SMALL => 0,
            status => status,
        }
    })();
    if name_copy != 0 {
        guest::free_bytes(name_copy);
    }
    status
}

/// RtlQueryRegistryValues[Ex] (RtlpQueryRegistryValues): a chave do Path
/// (RTL_REGISTRY_HANDLE = handle do chamador) precisa abrir, senão o status
/// da abertura volta (RTL_REGISTRY_OPTIONAL só sai do código de raiz). A
/// tabela termina na entrada sem QueryRoutine e sem SUBKEY/DIRECT. SUBKEY
/// abre o Name relativo à chave do Path (e enumera os valores dela quando há
/// QueryRoutine); TOPKEY volta à chave do Path; Name nulo enumera os valores
/// (NOVALUE chama a rotina sem valor); DIRECT exige Name e nenhuma rotina;
/// DELETE apaga o valor depois de entregue. A primeira falha encerra a
/// consulta com o seu status. Devolve o valor de retorno do export.
pub fn query_registry_values(relative_to: u32, path: u64, table: u64, context: u64, _environment: u64) -> Result<u64, KernelError> {
    let by_handle = relative_to & REGISTRY_HANDLE != 0;
    let key = if by_handle {
        debug_print!("[rtl] QueryRegistry handle=0x{:x} table=0x{:x}", path, table);
        path
    } else {
        let key_path = guest_registry_path(relative_to, path);
        debug_print!("[rtl] QueryRegistry path=\"{}\" table=0x{:x}", key_path, table);
        let (status, handle) = key_services::open_path(&key_path, false)?;
        if status != 0 {
            return Ok(status as i32 as i64 as u64);
        }
        handle
    };
    let mut current = key;
    let mut status = 0u32;
    let mut cursor = table;
    loop {
        // SAFETY: vetor RTL_QUERY_REGISTRY_TABLE do driver, terminado pela entrada nula.
        let entry = unsafe { RtlQueryRegistryTable::at(cursor) };
        let flags = entry.flags.get();
        let (routine, name) = (entry.query_routine.get(), entry.name.get());
        if routine == 0 && flags & (QUERY_REGISTRY_SUBKEY | QUERY_REGISTRY_DIRECT) == 0 {
            break;
        }
        if flags & QUERY_REGISTRY_DIRECT != 0 && (name == 0 || flags & QUERY_REGISTRY_SUBKEY != 0 || routine != 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if flags & (QUERY_REGISTRY_SUBKEY | QUERY_REGISTRY_TOPKEY) != 0 && current != key {
            close_key(current);
            current = key;
        }
        let value_name = if name != 0 { guest_strings::read_wide_string(name) } else { String::new() };
        let mut enumerate = false;
        if flags & QUERY_REGISTRY_SUBKEY != 0 {
            if name == 0 {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            let (open_status, subkey) = open_subkey(key, name)?;
            debug_print!("[rtl]   subchave \"{}\" -> 0x{:x}", value_name, open_status);
            if open_status != 0 {
                status = open_status;
                break;
            }
            current = subkey;
            enumerate = routine != 0;
        } else if name == 0 {
            if flags & QUERY_REGISTRY_NOVALUE != 0 {
                status = native_call::call(routine, &[0, 0, 0, 0, context, entry.entry_context.get()]) as u32;
            } else {
                enumerate = true;
            }
        } else {
            let (query_status, value) = query_value_by_name(current, name)?;
            if query_status != 0 && query_status != STATUS_OBJECT_NAME_NOT_FOUND {
                status = query_status;
                break;
            }
            status = call_query_routine(entry, value.as_ref(), context);
            debug_print!("[rtl]   \"{}\" flags=0x{:x} -> {} 0x{:x}", value_name, flags, if value.is_some() { "valor" } else { "default" }, status);
            if status & 0x8000_0000 == 0 && flags & QUERY_REGISTRY_DELETE != 0 {
                let units = guest_strings::read_wide_units(name);
                let _ = delete_value_by_units(current, &units)?;
            }
        }
        if enumerate {
            let mut index = 0u32;
            loop {
                let (enumerate_status, value) = enumerate_value(current, index)?;
                if enumerate_status == STATUS_NO_MORE_ENTRIES {
                    status = if index == 0 && flags & QUERY_REGISTRY_REQUIRED != 0 { STATUS_OBJECT_NAME_NOT_FOUND } else { 0 };
                    break;
                }
                if enumerate_status & 0x8000_0000 != 0 {
                    status = enumerate_status;
                    break;
                }
                let Some(value) = value else { break };
                status = call_query_routine(entry, Some(&value), context);
                if status & 0x8000_0000 != 0 {
                    break;
                }
                // Apagar o valor desloca os seguintes para o mesmo índice.
                if flags & QUERY_REGISTRY_DELETE != 0 && delete_value_by_units(current, &value.name)? & 0x8000_0000 == 0 {
                    continue;
                }
                index += 1;
            }
        }
        if status & 0x8000_0000 != 0 {
            break;
        }
        cursor += RtlQueryRegistryTable::SIZE;
    }
    if current != key {
        close_key(current);
    }
    if !by_handle {
        close_key(key);
    }
    Ok(status as i32 as i64 as u64)
}

/// RtlWriteRegistryValue pelo serviço de chaves (com as notificações de filtro).
/// Com RTL_REGISTRY_HANDLE o Path é a chave aberta do chamador, que continua
/// dono do handle.
pub fn write_value(relative_to: u32, path: u64, value_name: u64, value_type: u32, data: u64, length: u32) -> Result<u32, KernelError> {
    let by_handle = relative_to & REGISTRY_HANDLE != 0;
    let (status, handle) = if by_handle { (0, path) } else { key_services::open_path(&guest_registry_path(relative_to, path), true)? };
    if status != 0 {
        return Ok(status);
    }
    let data = guest::read_bytes(data, length as usize);
    let result = key_services::named_value(key_services::Kind::Set, handle, &guest_strings::read_wide_string(value_name), value_type, &data);
    if !by_handle {
        cm_registry::close_handle(handle as u32);
    }
    Ok(result?.0)
}

/// RtlWriteRegistryValue com caminho e nome já em texto; Path vazio (o
/// Path NULL do original) é a própria raiz do RelativeTo.
fn write_named_value(relative_to: u32, path: &str, value_name: &str, value_type: u32, data: &[u8]) -> Result<u32, KernelError> {
    let path = match crate::ntos::cm::check_registry_key::root_path(relative_to as usize) {
        Some(prefix) if path.is_empty() => prefix,
        _ => resolve_registry_path(relative_to, path),
    };
    let (status, handle) = key_services::open_path(&path, true)?;
    if status != 0 {
        return Ok(status);
    }
    let result = key_services::named_value(key_services::Kind::Set, handle, value_name, value_type, data);
    cm_registry::close_handle(handle as u32);
    Ok(result?.0)
}

/// RTL_REGISTRY_CONTROL (\Registry\Machine\System\CurrentControlSet\Control).
const REGISTRY_CONTROL: u32 = 2;
/// REG_DWORD.
const REG_DWORD: u32 = 4;

/// RtlSetPortableOperatingSystem(IsPortable) (ntoskrnl 19041 0x5888f0):
/// RtlWriteRegistryValue(RTL_REGISTRY_CONTROL, NULL,
/// "PortableOperatingSystem", REG_DWORD, IsPortable != 0, 4); devolve o
/// NTSTATUS da escrita.
pub fn set_portable_operating_system(portable: bool) -> Result<u32, KernelError> {
    write_named_value(REGISTRY_CONTROL, "", "PortableOperatingSystem", REG_DWORD, &(portable as u32).to_le_bytes())
}

/// RtlCreateRegistryKey: abre criando e fecha o handle. Com
/// RTL_REGISTRY_HANDLE o Path já é a chave aberta do chamador (o
/// RtlpGetRegistryHandle a devolve como está) e nada muda.
pub fn create_key(relative_to: u32, path: u64) -> Result<u32, KernelError> {
    if relative_to & REGISTRY_HANDLE != 0 {
        return Ok(0);
    }
    let path = guest_registry_path(relative_to, path);
    let (status, handle) = key_services::open_path(&path, true)?;
    if handle != 0 {
        cm_registry::close_handle(handle as u32);
    }
    Ok(status)
}

/// RtlDeleteRegistryValue. Com RTL_REGISTRY_HANDLE o Path é a chave aberta
/// do chamador, que continua dono do handle (o volmgr.sys apaga assim o
/// IsDeleted da chave de hardware que o IoOpenDeviceRegistryKey lhe abre).
pub fn delete_value(relative_to: u32, path: u64, value_name: u64) -> Result<u32, KernelError> {
    let by_handle = relative_to & REGISTRY_HANDLE != 0;
    let (status, handle) = if by_handle { (0, path) } else { key_services::open_path(&guest_registry_path(relative_to, path), false)? };
    if status != 0 {
        return Ok(status);
    }
    let result = key_services::named_value(key_services::Kind::DeleteValue, handle, &guest_strings::read_wide_string(value_name), 0, &[]);
    if !by_handle {
        cm_registry::close_handle(handle as u32);
    }
    Ok(result?.0)
}

/// O TOKEN_USER do RtlFormatCurrentUserKeyPath: um buffer de 0x58 bytes.
const TOKEN_USER_BUFFER: u32 = 0x58;
/// TokenUser (TOKEN_INFORMATION_CLASS).
const TOKEN_USER_CLASS: u32 = 1;
/// NtCurrentThreadEffectiveToken(): o token de impersonação da thread ou o
/// primário do processo.
const CURRENT_THREAD_EFFECTIVE_TOKEN: u64 = -6i64 as u64;
/// O prefixo do caminho e o espaço extra que o original soma ao teto do SID
/// (o prefixo e o NUL).
const USER_ROOT: &str = "\\REGISTRY\\USER\\";
const USER_ROOT_RESERVE: u32 = 0x22;
/// Chave do perfil padrão, aberta quando a do usuário não existe.
const DEFAULT_USER_KEY: &str = "\\Registry\\User\\.Default";
/// OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE | OBJ_FORCE_ACCESS_CHECK.
const CURRENT_USER_ATTRIBUTES: u32 = 0x640;

/// RtlFormatCurrentUserKeyPath(CurrentUserKeyPath) (ntoskrnl 19041
/// 0x6ef9e0): o SID do usuário do token efetivo (ZwQueryInformationToken
/// com NtCurrentThreadEffectiveToken e TokenUser, em 0x58 bytes) vira
/// "\REGISTRY\USER\<SID>". MaximumLength = teto do
/// RtlLengthSidAsUnicodeString + 0x22, do pool paginável com a etiqueta
/// 'Strg' (sem memória = STATUS_NO_MEMORY, com Length 0 e MaximumLength já
/// gravados); erro na conversão do SID libera a string. Os erros da consulta
/// e do SID voltam como vieram.
pub fn format_current_user_key_path(output: &UnicodeString) -> Result<u32, KernelError> {
    let information = guest::alloc_bytes(TOKEN_USER_BUFFER as u64 + 8);
    let returned = information + TOKEN_USER_BUFFER as u64;
    let status = crate::ntos::se::token::query::query(CURRENT_THREAD_EFFECTIVE_TOKEN, TOKEN_USER_CLASS, information, TOKEN_USER_BUFFER, returned, 0);
    let result = match status {
        Ok(0) => {
            // SAFETY: TOKEN_USER recém-gravado pela consulta (SID_AND_ATTRIBUTES no início).
            let user = unsafe { SidAndAttributes::at(information) };
            format_user_path(output, user.sid.get())
        }
        other => other,
    };
    guest::free_bytes(information);
    result
}

/// O caminho do usuário de `sid` em `output` (o resto do
/// RtlFormatCurrentUserKeyPath, depois da consulta ao token).
fn format_user_path(output: &UnicodeString, sid: u64) -> Result<u32, KernelError> {
    let length = match crate::ntos::rtl::security::length_sid_as_unicode_string(sid) {
        Ok(length) => length,
        Err(status) => return Ok(status),
    };
    let maximum = (length + USER_ROOT_RESERVE) as u16;
    output.length.set(0);
    output.maximum_length.set(maximum);
    let buffer = crate::ntos::ex::pool_allocation::allocate_tagged(1, maximum as u64, STRING_POOL_TAG).unwrap_or(0);
    output.buffer.set(buffer);
    if buffer == 0 {
        return Ok(STATUS_NO_MEMORY);
    }
    let root = USER_ROOT.encode_utf16().count() as u64 * 2;
    guest_strings::write_wide_string(buffer, USER_ROOT);
    output.length.set(root as u16);
    // A UNICODE_STRING do resto do buffer, com o teto do SID.
    let tail = guest::alloc_bytes(UnicodeString::SIZE);
    // SAFETY: bloco recém-alocado do tamanho de uma UNICODE_STRING.
    let rest = unsafe { UnicodeString::at(tail) };
    rest.length.set(0);
    rest.maximum_length.set(length as u16);
    rest.buffer.set(buffer + root);
    let status = crate::ntos::rtl::security::convert_sid_to_unicode_string(tail, sid, false);
    let converted = rest.length.get();
    guest::free_bytes(tail);
    let status = status?;
    if status != 0 {
        crate::ntos::rtl::unicode::free(output.address())?;
        return Ok(status);
    }
    output.length.set(root as u16 + converted);
    Ok(0)
}

/// ZwOpenKey(KeyHandle, DesiredAccess) de um caminho absoluto, com os
/// atributos do RtlOpenCurrentUser.
fn open_absolute(path: &UnicodeString, desired_access: u32, key_handle: u64) -> Result<u32, KernelError> {
    let block = guest::alloc_bytes(ObjectAttributes::SIZE);
    // SAFETY: bloco recém-alocado do tamanho de um OBJECT_ATTRIBUTES.
    let attributes = unsafe { ObjectAttributes::at(block) };
    attributes.length.set(ObjectAttributes::SIZE as u32);
    attributes.root_directory.set(0);
    attributes.object_name.set(path.address());
    attributes.attributes.set(CURRENT_USER_ATTRIBUTES);
    attributes.security_descriptor.set(0);
    attributes.security_quality_of_service.set(0);
    let status = key_services::open(key_handle, desired_access, block, false, 0);
    guest::free_bytes(block);
    status
}

/// RtlOpenCurrentUser(DesiredAccess, CurrentUserKey) (ntoskrnl 19041
/// 0x78c3a0): abre o caminho do RtlFormatCurrentUserKeyPath (handle de
/// kernel, sem caixa, com checagem de acesso) e libera o texto; se o caminho
/// não existe (STATUS_OBJECT_NAME_NOT_FOUND), abre "\Registry\User\.Default"
/// do mesmo jeito. Devolve o status da última abertura (ou o erro do
/// RtlFormatCurrentUserKeyPath).
pub fn open_current_user(desired_access: u32, key_handle: u64) -> Result<u32, KernelError> {
    let block = guest::alloc_bytes(UnicodeString::SIZE);
    // SAFETY: bloco recém-alocado do tamanho de uma UNICODE_STRING.
    let path = unsafe { UnicodeString::at(block) };
    path.length.set(0);
    path.maximum_length.set(0);
    path.buffer.set(0);
    let mut status = format_current_user_key_path(path)?;
    if status == 0 {
        status = open_absolute(path, desired_access, key_handle)?;
        crate::ntos::rtl::unicode::free(block)?;
    }
    if status == STATUS_OBJECT_NAME_NOT_FOUND {
        let units = DEFAULT_USER_KEY.encode_utf16().count() as u64 * 2;
        let default = guest::alloc_bytes(units + 2);
        guest_strings::write_wide_string(default, DEFAULT_USER_KEY);
        path.length.set(units as u16);
        path.maximum_length.set(units as u16 + 2);
        path.buffer.set(default);
        status = open_absolute(path, desired_access, key_handle)?;
        guest::free_bytes(default);
    }
    guest::free_bytes(block);
    Ok(status)
}
