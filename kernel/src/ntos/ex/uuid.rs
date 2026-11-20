//! Geração de UUIDs do Executive (ExUuidCreate): versão 4 com variante DCE,
//! a partir de um gerador xorshift32 semeado no TSC.
//!
//! A semente de nó dos UUIDs de tempo (NtSetUuidSeed), medida no ntoskrnl
//! 19041:
//!
//! - ExpUuidCachedValues.NodeId começa com `80 6E 6F 6E 69 63` ("\x80nonic")
//!   e ExpUuidCacheValid com FALSE (o bit de multicast do primeiro byte).
//! - NtSetUuidSeed(Seed) captura o contexto do chamador e faz um
//!   SeAccessCheck em UserMode, com DesiredAccess 1 e o
//!   ExpUuidSeedGenericMapping (0x20001, 0x20001, 0x20000, 0x1F0001),
//!   contra um descritor absoluto só com DACL: uma ACCESS_ALLOWED_ACE de
//!   máscara 1 para o SID de serviço do RpcEptMapper
//!   (S-1-5-80-521322694-906040134-3864710659-1525148216-3451224162). Sem o
//!   acesso, o serviço devolve STATUS_ACCESS_DENIED.
//! - Depois sonda os 6 bytes da semente (sem alinhamento), grava-os em
//!   NodeId sob o ExpUuidLock e liga ExpUuidCacheValid quando o bit 7 do
//!   primeiro byte está zerado.

use crate::hal::cpu;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::Guid;
use crate::ntos::ps::process;
use crate::ntos::ps::user::state::{self, probe_user_read};
use crate::ntos::se::access_evaluation;
use crate::ntos::se::model::sid;
use crate::ntos::se::policy_descriptor::OwnedDescriptor;
use crate::ntos::se::token::thread as thread_tokens;
use crate::rtl::{KernelError, SpinLock};

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
/// SE_DACL_PRESENT.
const SE_DACL_PRESENT: u16 = 0x4;
/// SecurityImpersonation: abaixo dele o SeAccessCheck recusa o cliente.
const SECURITY_IMPERSONATION: u32 = 2;
/// ExpUuidSeedGenericMapping.
const UUID_SEED_MAPPING: [u32; 4] = [0x2_0001, 0x2_0001, 0x2_0000, 0x1F_0001];
/// As subautoridades do SID de serviço do RpcEptMapper (SECURITY_SERVICE_ID_BASE_RID
/// e o SHA-1 do nome em maiúsculas).
const RPC_EPT_MAPPER_SERVICE: [u32; 6] = [80, 0x1F12_C0C6, 0x3601_1346, 0xE65A_CE03, 0x5AE7_EA38, 0xCDB5_8062];

/// O nó dos UUIDs de tempo (ExpUuidCachedValues.NodeId) e o
/// ExpUuidCacheValid.
struct NodeSeed {
    node: [u8; 6],
    valid: bool,
}

static NODE_SEED: SpinLock<NodeSeed> = SpinLock::new(NodeSeed { node: [0x80, b'n', b'o', b'n', b'i', b'c'], valid: false });

/// O NodeId e o ExpUuidCacheValid correntes.
pub fn node_seed() -> ([u8; 6], bool) {
    let seed = NODE_SEED.lock();
    (seed.node, seed.valid)
}

/// O token que o SeCaptureSubjectContext do chamador entrega ao
/// SeAccessCheck: o de impersonação (com SecurityImpersonation ou mais) ou
/// o primário do processo.
fn subject_token() -> Result<u64, u32> {
    let thread = process::get_current_thread();
    if let Some(impersonation) = thread_tokens::get(thread) {
        if impersonation.level < SECURITY_IMPERSONATION {
            return Err(STATUS_ACCESS_DENIED);
        }
        return Ok(impersonation.token);
    }
    process::get_primary_token(process::get_current_process()).ok_or(STATUS_ACCESS_DENIED)
}

/// A DACL do NtSetUuidSeed: ACL revisão 2 com uma ACCESS_ALLOWED_ACE de
/// máscara 1 para o serviço RpcEptMapper.
fn seed_dacl() -> alloc::vec::Vec<u8> {
    let service = sid(5, &RPC_EPT_MAPPER_SERVICE);
    let ace_size = 8 + service.len();
    // RtlCreateAcl com RtlLengthSid + 0x14 bytes.
    let acl_size = service.len() + 0x14;
    let mut acl = alloc::vec![0u8; acl_size];
    acl[0] = 2;
    acl[2..4].copy_from_slice(&(acl_size as u16).to_le_bytes());
    acl[4..6].copy_from_slice(&1u16.to_le_bytes());
    acl[8] = 0;
    acl[9] = 0;
    acl[10..12].copy_from_slice(&(ace_size as u16).to_le_bytes());
    acl[12..16].copy_from_slice(&1u32.to_le_bytes());
    acl[16..16 + service.len()].copy_from_slice(&service);
    acl
}

/// NtSetUuidSeed(Seed) de modo usuário. Devolve o NTSTATUS.
pub fn set_seed_from_user(seed: u64) -> u32 {
    let token = match subject_token() {
        Ok(token) => token,
        Err(status) => return status,
    };
    let Some(subject) = crate::ntos::se::access_check::subject_of_token(token) else { return STATUS_ACCESS_DENIED };
    let descriptor = OwnedDescriptor { control: SE_DACL_PRESENT, owner: None, group: None, dacl: Some(seed_dacl()), sacl: None };
    if access_evaluation::access_check(Some(&descriptor), &subject, 1, 0, &UUID_SEED_MAPPING).is_err() {
        return STATUS_ACCESS_DENIED;
    }
    if !probe_user_read(seed, 6) {
        return STATUS_ACCESS_VIOLATION;
    }
    let mut node = [0u8; 6];
    for (index, byte) in node.iter_mut().enumerate() {
        let Ok(value) = crate::ntos::mm::guest_memory::try_read::<u8>(seed + index as u64) else { return STATUS_ACCESS_VIOLATION };
        *byte = value;
    }
    let mut cached = NODE_SEED.lock();
    cached.node = node;
    cached.valid = node[0] & 0x80 == 0;
    0
}

fn nt_set_uuid_seed(seed: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(set_seed_from_user(seed))
}

/// O estado do ExpAllocateUuids: ExpUuidLastTimeAllocated,
/// ExpUuidSequenceNumber (com o Valid e o NotSaved) e
/// ExpUuidTimeSequenceNumber.
struct TimeAllocation {
    last: u64,
    sequence: u32,
    sequence_valid: bool,
    not_saved: bool,
    time_sequence: u32,
}

static ALLOCATION: SpinLock<TimeAllocation> = SpinLock::new(TimeAllocation { last: 0, sequence: 0, sequence_valid: false, not_saved: false, time_sequence: 0 });

/// A chave do estado persistido do Executive (o RtlGetPersistedStateLocation
/// de "KernelExecutive" sem redirecionamento) e o valor da sequência.
pub const SEQUENCE_KEY: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Executive";
pub const SEQUENCE_VALUE: &str = "UuidSequenceNumber";
/// STATUS_RETRY e RPC_NT_UUID_LOCAL_ONLY.
const STATUS_RETRY: u32 = 0xC000_022D;
const RPC_NT_UUID_LOCAL_ONLY: u32 = 0x4002_0056;
/// Cada pedido cobre até 10000 intervalos de 100 ns e olha no máximo 1 s
/// para trás.
const MAXIMUM_RANGE: u64 = 10_000;
const MAXIMUM_LOOKBACK: u64 = 10_000_000;

/// ExpAllocateUuids (19041 0x69cdd4) no SystemTime `now`: (Time, Range,
/// Sequence) ou STATUS_RETRY.
/// - A primeira vez, o ExpUuidLoadSequenceNumber lê o REG_DWORD da chave do
///   Executive (sem ele, uma mistura do contador de desempenho) e soma 1;
///   a sequência fica por gravar.
/// - O relógio que voltou soma 1 à sequência e recomeça 20000 atrás.
/// - Sem tempo novo desde o último pedido, até 31 repetições recebem os
///   10000 intervalos anteriores com o número da repetição nos bits 23..27
///   da parte alta do Time; a 32ª é STATUS_RETRY.
/// - Senão, a faixa é o tempo passado (no máximo 1 s), Range no máximo
///   10000, e o próximo pedido começa no fim dela.
fn allocate_uuids(now: u64) -> Result<(u64, u32, u32), u32> {
    let mut state = ALLOCATION.lock();
    if !state.sequence_valid {
        let loaded = crate::ntos::cm::registry::read_value_by_path(SEQUENCE_KEY, SEQUENCE_VALUE).filter(|value| value.value_type == 4 && value.data.len() >= 4).map(|value| u32::from_le_bytes([value.data[0], value.data[1], value.data[2], value.data[3]]));
        let base = loaded.unwrap_or_else(|| {
            let counter = cpu::rdtsc();
            (counter >> 32) as u32 ^ state.sequence ^ counter as u32
        });
        state.sequence = base.wrapping_add(1);
        state.sequence_valid = true;
        state.not_saved = true;
    }
    let mut delta = now as i64 - state.last as i64;
    if delta < 0 {
        state.sequence = state.sequence.wrapping_add(1);
        state.last = now.wrapping_sub(2 * MAXIMUM_RANGE);
        delta = 2 * MAXIMUM_RANGE as i64;
        state.not_saved = true;
    }
    if delta == 0 {
        if state.time_sequence >= 31 {
            return Err(STATUS_RETRY);
        }
        state.time_sequence += 1;
        let repeat = state.time_sequence;
        let marks = [(1u32, 27u32), (2, 26), (4, 25), (8, 24), (0x10, 23)].iter().filter(|&&(bit, _)| repeat & bit != 0).fold(0u32, |marks, &(_, position)| marks | 1 << position);
        let time = now.wrapping_sub(MAXIMUM_RANGE) | (marks as u64) << 32;
        return Ok((time, MAXIMUM_RANGE as u32, state.sequence));
    }
    state.time_sequence = 0;
    let delta = (delta as u64).min(MAXIMUM_LOOKBACK);
    let range = delta.min(MAXIMUM_RANGE);
    let time = now - delta;
    state.last = time + range;
    Ok((time, range as u32, state.sequence))
}

/// ExpUuidSaveSequenceNumberIf: grava a sequência por gravar na chave do
/// Executive (o ExpUuidSaveSequenceNumber); só uma gravação bem-sucedida a
/// dá por gravada.
fn save_sequence_if_needed() {
    let (needed, sequence) = {
        let state = ALLOCATION.lock();
        (state.not_saved, state.sequence)
    };
    if !needed {
        return;
    }
    let Ok(handle) = crate::ntos::cm::registry::open_or_create(SEQUENCE_KEY, None) else { return };
    let saved = crate::ntos::cm::registry::set_value(handle, SEQUENCE_VALUE, 4, sequence.to_le_bytes().to_vec());
    crate::ntos::cm::registry::close_handle(handle);
    if saved {
        let mut state = ALLOCATION.lock();
        if state.sequence == sequence {
            state.not_saved = false;
        }
    }
}

/// NtAllocateUuids(Time*, Range*, Sequence*, Seed*) de modo usuário
/// (19041 0x69cbf0): Time, Range e Sequence sondados com alinhamento 4 e
/// os 6 bytes da semente sem alinhamento; o ExpAllocateUuids sob o
/// ExpUuidLock (a falha volta sem escrever nada), a sequência gravada se
/// mudou, e as saídas com o NodeId corrente. Sem ExpUuidCacheValid o
/// status é RPC_NT_UUID_LOCAL_ONLY.
fn nt_allocate_uuids(time: u64, range: u64, sequence: u64, seed: u64, _rsp: u64) -> Result<u32, KernelError> {
    if time & 3 != 0 || range & 3 != 0 || sequence & 3 != 0 {
        return Ok(0x8000_0002);
    }
    if !state::probe_user_write(time, 8) || !state::probe_user_write(range, 4) || !state::probe_user_write(sequence, 4) || !state::probe_user_write(seed, 6) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let (start, count, number) = match allocate_uuids(crate::ntos::ke::clock::system_time_100ns()) {
        Ok(allocated) => allocated,
        Err(status) => return Ok(status),
    };
    save_sequence_if_needed();
    let (node, valid) = node_seed();
    let written = crate::ntos::mm::guest_memory::try_write::<u64>(time, start)
        .and_then(|()| crate::ntos::mm::guest_memory::try_write::<u32>(range, count))
        .and_then(|()| crate::ntos::mm::guest_memory::try_write::<u32>(sequence, number))
        .and_then(|()| crate::ntos::mm::guest_memory::try_write_bytes(seed, &node));
    if written.is_err() {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    Ok(if valid { 0 } else { RPC_NT_UUID_LOCAL_ONLY })
}

/// Os handlers dos serviços NtSetUuidSeed e NtAllocateUuids.
pub fn register_user_services() {
    state::register_handler("NtSetUuidSeed", nt_set_uuid_seed);
    state::register_handler("NtAllocateUuids", nt_allocate_uuids);
}

/// Gerador xorshift32 semeado no TSC (ExUuidCreate).
static IDENTIFIER_STATE: SpinLock<u32> = SpinLock::new(0);

fn next_random32() -> u32 {
    let mut state = IDENTIFIER_STATE.lock();
    if *state == 0 {
        *state = match (cpu::rdtsc() as u32) ^ 0x9E37_79B9 {
            0 => 0x2545_F491,
            seed => seed,
        };
    }
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    *state
}

/// Duas saídas do gerador; os 64 bits saem exatos, sem arredondar os bits
/// baixos.
fn next_random64() -> u64 {
    let low = next_random32() as u64;
    low | (next_random32() as u64) << 32
}

/// UUID versão 4 com variante DCE.
pub fn create(pointer: u64) {
    let low = next_random64();
    let high = next_random64();
    // SAFETY: ExUuidCreate recebe o UUID* de saída do chamador.
    let guid = unsafe { Guid::at(pointer) };
    guid.data1.set(low as u32);
    guid.data2.set((low >> 32) as u16);
    // Versão 4 no nibble alto de Data3 (o byte 7 na memória).
    guid.data3.set(((low >> 48) as u16 & 0x0FFF) | 0x4000);
    for (index, byte) in guid.data4.iter().enumerate() {
        byte.set((high >> (index * 8)) as u8);
    }
    // Variante DCE (10xxxxxx) em Data4[0].
    guid.data4[0].set((guid.data4[0].get() & 0x3F) | 0x80);
}
