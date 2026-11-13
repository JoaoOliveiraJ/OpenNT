//! Bloco de dados WNF.
//!
//! Carga e atualização: lock real, pool/quota, carimbo e persistência na
//! hive. Namespace, ACL e TypeId são validados pelo chamador.

use crate::ntos::ex::{pool_allocation, pool_quota, push_lock};
use crate::ntos::ex::wnf::name as wnf_name;
use crate::ntos::cm::key::services::{self as key_services, fields, Kind};
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ps::{previous_mode, process, process_context};
use super::objects::{name_at, state_data_at};
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{KeyValuePartialInformation, UnicodeString, WnfStateData};
use crate::ntos::inc::status::STATUS_ACCESS_VIOLATION;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

/// Moldura de pool do valor da hive: o UNICODE_STRING com os 16 WCHARs do
/// nome logo depois e o ResultLength da consulta.
#[repr(C)]
struct ValueFrame {
    name: UnicodeString,
    _text: Reserved<0x28>,
    result_length: Field<u32>,
    _pad_3c: Reserved<0x4>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for ValueFrame {}

const _: () = {
    assert!(core::mem::size_of::<ValueFrame>() == 64);
    assert!(core::mem::offset_of!(ValueFrame, result_length) == 56);
};

fn value_frame(frame: u64) -> &'static ValueFrame {
    // SAFETY: molduras de 64 bytes alocadas por `frame()`.
    unsafe { ValueFrame::at(frame) }
}

/// Cabeçalho do bloco de dados (NodeTypeCode 0x904, NodeByteSize 0x10).
fn initialize_header(block: &WnfStateData) {
    block.header.node_type_code.set(0x904);
    block.header.node_byte_size.set(WnfStateData::SIZE as u16);
}

pub const DATA_TAG: u32 = 0x2066_6E57;
const FRAME_TAG: u32 = 0x766E_6657;

/// Instância de nome no pool (WNF_NAME_INSTANCE); os acessores leem a
/// memória viva, sem cópias que escondam alterações feitas pelo CM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameState {
    pub pointer: u64,
}

impl NameState {
    pub fn lock_pointer(&self) -> u64 {
        name_at(self.pointer).state_data_lock.address()
    }
    pub fn decoded_name(&self) -> u64 {
        name_at(self.pointer).state_name.bitfield_0.get()
    }
    pub fn maximum_size(&self) -> u32 {
        name_at(self.pointer).state_name_info.max_state_size.get()
    }
    pub fn type_identifier(&self) -> u64 {
        name_at(self.pointer).state_name_info.type_id.get()
    }
    pub fn security_descriptor(&self) -> u64 {
        name_at(self.pointer).state_name_info.security_descriptor.get()
    }
    pub fn creator_process(&self) -> u64 {
        name_at(self.pointer).creator_process.get()
    }
    pub fn permanent_key(&self) -> u64 {
        name_at(self.pointer).permanent_data_store.get()
    }
    pub fn data_pointer(&self) -> u64 {
        name_at(self.pointer).state_data.get()
    }
    pub fn set_data_pointer(&self, value: u64) {
        name_at(self.pointer).state_data.set(value);
    }
    pub fn change_stamp(&self) -> u32 {
        name_at(self.pointer).current_change_stamp.get()
    }
    pub fn set_change_stamp(&self, value: u32) {
        name_at(self.pointer).current_change_stamp.set(value);
    }
    pub fn description(&self) -> wnf_name::Description {
        wnf_name::Description { security_descriptor: self.security_descriptor(), type_identifier: self.type_identifier(), maximum_size: self.maximum_size() }
    }
}

/// memmove: lê o bloco inteiro antes de gravar (sobreposição segura).
fn copy_bytes(destination: u64, source: u64, length: u32) {
    if length != 0 {
        guest::write_bytes(destination, &guest::read_bytes(source, length as usize));
    }
}

/// UNICODE_STRING com os 16 WCHARs do nome (o terminador já é zero).
fn initialize_value_name(frame: u64, decoded_name: u64) {
    let name = wnf_name::value_name(decoded_name);
    let frame = value_frame(frame);
    let text = frame.name.address() + UnicodeString::SIZE;
    frame.name.length.set(32);
    frame.name.maximum_length.set(34);
    frame.name.buffer.set(text);
    let bytes: alloc::vec::Vec<u8> = name.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
    guest::write_bytes(text, &bytes);
}

fn frame() -> Option<u64> {
    kernel_pool::allocate(ValueFrame::SIZE, AllocateOptions { tag: FRAME_TAG, zero: true, ..Default::default() }).ok()
}

/// ZwSetValueKey com REG_BINARY: DWORD do carimbo seguido dos dados.
fn persist(state: &NameState, data: u64, length: u32) -> Result<u32, KernelError> {
    let Some(frame) = frame() else { return Ok(0xC000_0017) };
    initialize_value_name(frame, state.decoded_name());
    // KEY_VALUE de REG_BINARY: ChangeStamp seguido dos dados (WNF_STATE_DATA a partir de +0xC).
    let arguments = fields(&[("name", frame), ("type", 3), ("data", state_data_at(data).change_stamp.address()), ("length", length as u64 + 4)]);
    let status = previous_mode::with_kernel(|| key_services::key_operation(Kind::Set, state.permanent_key(), &arguments, false));
    let _ = kernel_pool::free(frame, None);
    status?
}

/// Estados temporários cobram do criador, mesmo quando outra thread
/// escreve; a anexação restaura o APC_STATE em qualquer saída.
fn allocate_data(state: &NameState, length: u32) -> Result<Result<u64, u32>, KernelError> {
    let temporary = (state.decoded_name() >> 4) & 3 == 3;
    let creator = state.creator_process();
    if temporary && creator != process::get_system_process() {
        if creator == 0 {
            return Ok(Err(0xC000_0034));
        }
        let pointer = process_context::with_process(creator, || pool_quota::allocate(9, length as u64 + WnfStateData::SIZE, DATA_TAG))?.unwrap_or(0);
        return Ok(if pointer != 0 { Ok(pointer) } else { Err(0xC000_009A) });
    }
    let pointer = pool_allocation::allocate_tagged(1, length as u64 + WnfStateData::SIZE, DATA_TAG).unwrap_or(0);
    Ok(if pointer != 0 { Ok(pointer) } else { Err(0xC000_009A) })
}

/// Popula uma instância ainda privada antes de inseri-la no namespace (o
/// chamador conserva a exclusividade). Caminho da hive local.
pub fn load_local(state: &NameState) -> Result<u32, KernelError> {
    if state.data_pointer() != 0 || state.permanent_key() == 0 {
        return Ok(0);
    }
    let Some(frame) = frame() else { return Ok(0xC000_0017) };
    let mut block = 0u64;
    let mut capacity = state.maximum_size();
    let result = (|| -> Result<u32, KernelError> {
        initialize_value_name(frame, state.decoded_name());
        loop {
            // Soma de 32 bits, com estouro; o máximo da definição
            // não muda quando o buffer é realocado.
            let allocation_size = capacity.wrapping_add(WnfStateData::SIZE as u32);
            block = pool_allocation::allocate_tagged(1, allocation_size as u64, DATA_TAG).unwrap_or(0);
            if block == 0 {
                return Ok(0xC000_009A);
            }
            let returned = &value_frame(frame).result_length;
            returned.set(allocation_size);
            let arguments = fields(&[("name", frame), ("klass", 2), ("out", block), ("length", allocation_size as u64), ("returned", returned.address())]);
            let status = previous_mode::with_kernel(|| key_services::key_operation(Kind::QueryValue, state.permanent_key(), &arguments, false))??;
            if status == 0xC000_0023 {
                let _ = kernel_pool::free(block, Some(DATA_TAG));
                block = 0;
                capacity = returned.get().wrapping_sub(WnfStateData::SIZE as u32);
                continue;
            }
            let data = state_data_at(block);
            if status == 0xC000_0034 {
                // Só a ausência do valor é estado inicial vazio.
                data.data_size.set(0);
                data.change_stamp.set(0);
            } else {
                if status & 0x8000_0000 != 0 {
                    return Ok(status);
                }
                // SAFETY: o bloco ainda guarda a KEY_VALUE_PARTIAL_INFORMATION devolvida.
                let information = unsafe { KeyValuePartialInformation::at(block) };
                let stored = information.data_length.get();
                if information.type_.get() != 3 || stored < 4 {
                    return Ok(0xC000_0001);
                }
                // DataLength sem o DWORD do carimbo vira DataSize (mesmo offset).
                data.data_size.set(stored - 4);
            }
            // KEY_VALUE_PARTIAL_INFORMATION e WNF_STATE_DATA alinham o
            // carimbo em +12 e os dados em +16.
            initialize_header(data);
            data.allocated_size.set(capacity);
            state.set_change_stamp(data.change_stamp.get());
            state.set_data_pointer(block);
            block = 0;
            return Ok(0);
        }
    })();
    if block != 0 {
        let _ = kernel_pool::free(block, Some(DATA_TAG));
    }
    let _ = kernel_pool::free(frame, Some(FRAME_TAG));
    result
}

/// Leitura sob lock compartilhado; as saídas são gravadas antes da
/// comparação de capacidade e o tamanho é relido do bloco depois delas.
/// As saídas podem ser ponteiros de modo usuário (NtQueryWnfStateData, já
/// sondados): as escritas são sondadas e a falha vira ACCESS_VIOLATION.
pub fn read(state: &NameState, change_stamp: u64, buffer: u64, capacity: u32, returned_length: u64) -> Result<u32, KernelError> {
    push_lock::acquire_shared(state.lock_pointer(), 0)?;
    let block = state.data_pointer();
    let outputs = (|| -> Result<u32, KernelError> {
        if block > 1 {
            let data = state_data_at(block);
            guest::try_write::<u32>(change_stamp, data.change_stamp.get())?;
            guest::try_write::<u32>(returned_length, data.data_size.get())?;
            let length = data.data_size.get();
            if capacity < length {
                return Ok(0xC000_0023);
            }
            if length != 0 {
                guest::try_write_bytes(buffer, &guest::read_bytes(block + WnfStateData::SIZE, length as usize))?;
            }
            Ok(0)
        } else {
            guest::try_write::<u32>(change_stamp, if block == 1 { state.change_stamp() } else { 0 })?;
            guest::try_write::<u32>(returned_length, 0)?;
            Ok(0)
        }
    })();
    push_lock::release_shared(state.lock_pointer(), 0)?;
    Ok(match outputs {
        Ok(status) => status,
        Err(error) if error.status == STATUS_ACCESS_VIOLATION => STATUS_ACCESS_VIOLATION,
        Err(error) => return Err(error),
    })
}

/// Atualização com carimbo opcional. O ponteiro zero indica cache ausente e
/// o marcador 1 representa dados vazios publicados (carimbo válido sem
/// bloco). A alocação ocorre fora do lock; falha da hive invalida o cache.
pub fn write(state: &NameState, buffer: u64, length: u32, matching_stamp: u32, check_stamp: bool) -> Result<u32, KernelError> {
    let lock = state.lock_pointer();
    let mut replacement = 0u64;
    let mut discarded = 0u64;
    push_lock::acquire_exclusive(lock, 0)?;
    let mut locked = true;
    let result = (|| -> Result<u32, KernelError> {
        let observed = if state.data_pointer() != 0 { state.change_stamp() } else { 0 };
        if check_stamp && observed != matching_stamp {
            return Ok(0xC000_0001);
        }
        let mut block = if state.data_pointer() > 1 { state.data_pointer() } else { 0 };
        if (block == 0 && (state.permanent_key() != 0 || length != 0)) || (block != 0 && state_data_at(block).allocated_size.get() < length) {
            push_lock::release_exclusive(lock, 0)?;
            locked = false;
            replacement = match allocate_data(state, length)? {
                Ok(pointer) => pointer,
                Err(status) => return Ok(status),
            };
            let fresh = state_data_at(replacement);
            initialize_header(fresh);
            fresh.allocated_size.set(length);
            fresh.data_size.set(0);
            fresh.change_stamp.set(0);
            push_lock::acquire_exclusive(lock, 0)?;
            locked = true;
            // Outra escrita pode ter publicado um bloco suficiente.
            block = if state.data_pointer() > 1 { state.data_pointer() } else { 0 };
            if block == 0 || state_data_at(block).allocated_size.get() < length {
                block = replacement;
            }
        }
        // Zero é reservado: o wrap passa de FFFFFFFF para 1.
        let next = state.change_stamp().wrapping_add(1).max(1);
        let mut status = 0;
        if block != 0 {
            copy_bytes(block + WnfStateData::SIZE, buffer, length);
            state_data_at(block).data_size.set(length);
            state_data_at(block).change_stamp.set(next);
            if state.permanent_key() != 0 {
                status = persist(state, block, length)?;
                if status & 0x8000_0000 != 0 {
                    discarded = state.data_pointer();
                    state.set_data_pointer(0);
                    return Ok(status);
                }
            }
            if block == replacement {
                discarded = state.data_pointer();
                state.set_data_pointer(replacement);
                replacement = 0;
            }
        } else {
            state.set_data_pointer(1);
        }
        state.set_change_stamp(next);
        Ok(status)
    })();
    if locked {
        push_lock::release_exclusive(lock, 0)?;
    }
    if discarded > 1 {
        let _ = kernel_pool::free(discarded, Some(DATA_TAG));
    }
    if replacement != 0 {
        let _ = kernel_pool::free(replacement, Some(DATA_TAG));
    }
    result
}
