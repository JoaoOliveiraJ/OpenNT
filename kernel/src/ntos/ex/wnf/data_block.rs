//! Bloco de dados WNF.
//!
//! Carga e atualização: lock real, pool/quota, carimbo e persistência na
//! hive. Namespace, ACL e TypeId são validados pelo chamador.

use crate::ntos::ex::{pool_allocation, pool_quota, push_lock};
use crate::ntos::ex::wnf::name as wnf_name;
use crate::ntos::cm::key::services::{self as key_services, fields, Kind};
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ps::{previous_mode, process, process_context};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

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
        self.pointer + 0x50
    }
    pub fn decoded_name(&self) -> u64 {
        guest::read64(self.pointer + 0x28)
    }
    pub fn maximum_size(&self) -> u32 {
        guest::read32(self.pointer + 0x38)
    }
    pub fn type_identifier(&self) -> u64 {
        guest::read64(self.pointer + 0x40)
    }
    pub fn security_descriptor(&self) -> u64 {
        guest::read64(self.pointer + 0x48)
    }
    pub fn creator_process(&self) -> u64 {
        guest::read64(self.pointer + 0x98)
    }
    pub fn permanent_key(&self) -> u64 {
        guest::read64(self.pointer + 0x68)
    }
    pub fn data_pointer(&self) -> u64 {
        guest::read64(self.pointer + 0x58)
    }
    pub fn set_data_pointer(&self, value: u64) {
        guest::write64(self.pointer + 0x58, value);
    }
    pub fn change_stamp(&self) -> u32 {
        guest::read32(self.pointer + 0x60)
    }
    pub fn set_change_stamp(&self, value: u32) {
        guest::write32(self.pointer + 0x60, value);
    }
    pub fn description(&self) -> wnf_name::Description {
        wnf_name::Description { security_descriptor: self.security_descriptor(), type_identifier: self.type_identifier(), maximum_size: self.maximum_size() }
    }
}

/// memmove: preserva sobreposição sem buffer auxiliar oculto.
fn copy_bytes(destination: u64, source: u64, length: u32) {
    if length == 0 {
        return;
    }
    if destination > source && destination < source + length as u64 {
        for index in (0..length as u64).rev() {
            guest::write8(destination + index, guest::read8(source + index));
        }
    } else {
        for index in 0..length as u64 {
            guest::write8(destination + index, guest::read8(source + index));
        }
    }
}

/// UNICODE_STRING com os 16 WCHARs do nome, terminador e ResultLength (+56).
fn initialize_value_name(frame: u64, decoded_name: u64) {
    let name = wnf_name::value_name(decoded_name);
    guest::write16(frame, 32);
    guest::write16(frame + 2, 34);
    guest::write64(frame + 8, frame + 16);
    for (index, unit) in name.encode_utf16().enumerate() {
        guest::write16(frame + 16 + index as u64 * 2, unit);
    }
}

fn frame() -> Option<u64> {
    kernel_pool::allocate(64, AllocateOptions { tag: FRAME_TAG, zero: true, ..Default::default() }).ok()
}

/// ZwSetValueKey com REG_BINARY: DWORD do carimbo seguido dos dados.
fn persist(state: &NameState, data: u64, length: u32) -> Result<u32, KernelError> {
    let Some(frame) = frame() else { return Ok(0xC000_0017) };
    initialize_value_name(frame, state.decoded_name());
    let arguments = fields(&[("name", frame), ("type", 3), ("data", data + 12), ("length", length as u64 + 4)]);
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
        let pointer = process_context::with_process(creator, || pool_quota::allocate(9, length as u64 + 16, DATA_TAG))?.unwrap_or(0);
        return Ok(if pointer != 0 { Ok(pointer) } else { Err(0xC000_009A) });
    }
    let pointer = pool_allocation::allocate_tagged(1, length as u64 + 16, DATA_TAG).unwrap_or(0);
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
            let allocation_size = capacity.wrapping_add(16);
            block = pool_allocation::allocate_tagged(1, allocation_size as u64, DATA_TAG).unwrap_or(0);
            if block == 0 {
                return Ok(0xC000_009A);
            }
            guest::write32(frame + 56, allocation_size);
            let arguments = fields(&[("name", frame), ("klass", 2), ("out", block), ("length", allocation_size as u64), ("returned", frame + 56)]);
            let status = previous_mode::with_kernel(|| key_services::key_operation(Kind::QueryValue, state.permanent_key(), &arguments, false))??;
            if status == 0xC000_0023 {
                let _ = kernel_pool::free(block, Some(DATA_TAG));
                block = 0;
                capacity = guest::read32(frame + 56).wrapping_sub(16);
                continue;
            }
            if status == 0xC000_0034 {
                // Só a ausência do valor é estado inicial vazio.
                guest::write64(block + 8, 0);
            } else {
                if status & 0x8000_0000 != 0 {
                    return Ok(status);
                }
                let stored = guest::read32(block + 8);
                if guest::read32(block + 4) != 3 || stored < 4 {
                    return Ok(0xC000_0001);
                }
                guest::write32(block + 8, stored - 4);
            }
            // KEY_VALUE_PARTIAL_INFORMATION e WNF_STATE_DATA alinham o
            // carimbo em +12 e os dados em +16.
            guest::write32(block, 0x0010_0904);
            guest::write32(block + 4, capacity);
            state.set_change_stamp(guest::read32(block + 12));
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
pub fn read(state: &NameState, change_stamp: u64, buffer: u64, capacity: u32, returned_length: u64) -> Result<u32, KernelError> {
    push_lock::acquire_shared(state.lock_pointer(), 0)?;
    let block = state.data_pointer();
    let status = if block > 1 {
        guest::write32(change_stamp, guest::read32(block + 12));
        guest::write32(returned_length, guest::read32(block + 8));
        let length = guest::read32(block + 8);
        if capacity < length {
            0xC000_0023
        } else {
            copy_bytes(buffer, block + 16, length);
            0
        }
    } else {
        guest::write32(change_stamp, if block == 1 { state.change_stamp() } else { 0 });
        guest::write32(returned_length, 0);
        0
    };
    push_lock::release_shared(state.lock_pointer(), 0)?;
    Ok(status)
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
        if (block == 0 && (state.permanent_key() != 0 || length != 0)) || (block != 0 && guest::read32(block + 4) < length) {
            push_lock::release_exclusive(lock, 0)?;
            locked = false;
            replacement = match allocate_data(state, length)? {
                Ok(pointer) => pointer,
                Err(status) => return Ok(status),
            };
            guest::write32(replacement, 0x0010_0904);
            guest::write32(replacement + 4, length);
            guest::write64(replacement + 8, 0);
            push_lock::acquire_exclusive(lock, 0)?;
            locked = true;
            // Outra escrita pode ter publicado um bloco suficiente.
            block = if state.data_pointer() > 1 { state.data_pointer() } else { 0 };
            if block == 0 || guest::read32(block + 4) < length {
                block = replacement;
            }
        }
        // Zero é reservado: o wrap passa de FFFFFFFF para 1.
        let next = state.change_stamp().wrapping_add(1).max(1);
        let mut status = 0;
        if block != 0 {
            copy_bytes(block + 16, buffer, length);
            guest::write32(block + 8, length);
            guest::write32(block + 12, next);
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
