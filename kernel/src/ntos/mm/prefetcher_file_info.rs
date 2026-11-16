//! A ligação do prefetcher com o minifiltro FileInfo: PfFileInfoNotify
//! (ntoskrnl 19041, 0x29dc90).
//!
//! O FileInfo.sys informa o prefetcher por um bloco { ULONG Version (0xF);
//! ULONG Type; ULONG Flags; ULONG; payload em +0x10 }. Versão diferente de
//! 0xF é STATUS_INVALID_PARAMETER. Com Flags & 8, o bloco é um pedido de
//! controle:
//! - Type 7: um número de sequência novo (InterlockedIncrement do contador
//!   global), gravado como ULONG em +0x10 — o FileInfo numera cada stream.
//! - Type 0xA: o FileInfo registra a sua interface (o ponteiro em +0x10:
//!   Open, Close, QueryFile, QueryVolume e RegisterGlobalBlockNotify). Sob o
//!   push lock da interface, uma interface já registrada é
//!   STATUS_ALREADY_COMMITTED; senão o prefetcher entrega ao
//!   RegisterGlobalBlockNotify (a quinta rotina) a sua
//!   PfpPrefetchSharedConflictNotifyStart e guarda a tabela.
//! - Type 0xB: retira a interface; sem interface, STATUS_NOT_FOUND. O NT
//!   ainda acorda as aberturas de pré-busca em curso, que o OpenNT não tem.
//! - Type 0xC: a consulta do estado do prefetcher, sucesso enquanto ele
//!   aceita o FileInfo (o bit 2 do estado global desligado).
//! - Os demais: STATUS_NOT_SUPPORTED.
//!
//! Os demais blocos (Flags & 4: criação e remoção de nomes de stream;
//! Flags & 1: E/S, renomeações, exclusões e volumes) só alimentam os
//! traços de cenário do prefetcher e o log que o serviço de Superfetch lê.
//! O OpenNT não tem traços ativos nem esse log: o bloco é aceito sem
//! efeito.
//!
//! A PfpPrefetchSharedConflictNotifyStart que o FileInfo chama quando uma
//! abertura conflita com uma pré-busca devolve em Output[0] a rotina de
//! fim (PfpPrefetchSharedConflictNotifyEnd) e em Output[1] a entrada de
//! prioridade da espera; sem pré-buscas nem rastreamento de prioridade de
//! locks no OpenNT, a entrada é NULL e o fim não tem o que desfazer.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::hal::amd64::native_call;
use crate::hal::amd64::routine_stubs::{self, Routine};
use crate::ntos::init::exports::Call;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::{KernelError, SpinLock};

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_ALREADY_COMMITTED: u32 = 0xC000_0021;
pub const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
pub const STATUS_TOO_LATE: u32 = 0xC000_0189;
pub const STATUS_NOT_FOUND: u32 = 0xC000_0225;

/// PF_FILE_INFO_NOTIFY.Version aceita.
const VERSION: u32 = 0xF;
const FLAG_CONTROL: u32 = 8;
const TYPE_SEQUENCE: u32 = 7;
const TYPE_REGISTER_INTERFACE: u32 = 0xA;
const TYPE_UNREGISTER_INTERFACE: u32 = 0xB;
const TYPE_QUERY_STATE: u32 = 0xC;
/// Interface do FileInfo: a quinta rotina, RegisterGlobalBlockNotify.
const REGISTER_GLOBAL_BLOCK_NOTIFY: u64 = 0x20;
/// Estado do prefetcher: o bit que recusa o FileInfo (nunca ligado aqui).
const STATE_REFUSES_FILE_INFO: u32 = 2;

/// O contador dos números de sequência.
static SEQUENCE: AtomicU32 = AtomicU32::new(0);
/// A interface registrada pelo FileInfo (0 sem registro), sob o lock.
static INTERFACE: SpinLock<u64> = SpinLock::new(0);
/// O estado global do prefetcher consultado pelo Type 0xC.
static STATE: AtomicU32 = AtomicU32::new(0);
/// Quantos conflitos de compartilhamento o FileInfo relatou.
static SHARED_CONFLICTS: AtomicU64 = AtomicU64::new(0);

/// PfFileInfoNotify(Notify) -> NTSTATUS.
pub fn file_info_notify(notify: u64) -> Result<u32, KernelError> {
    if guest::try_read32(notify)? != VERSION {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let kind = guest::try_read32(notify + 4)?;
    let flags = guest::try_read32(notify + 8)?;
    if flags & FLAG_CONTROL == 0 {
        return Ok(STATUS_SUCCESS);
    }
    match kind {
        TYPE_SEQUENCE => {
            let sequence = SEQUENCE.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
            guest::try_write32(notify + 0x10, sequence)?;
            Ok(STATUS_SUCCESS)
        }
        TYPE_REGISTER_INTERFACE => register_interface(guest::try_read64(notify + 0x10)?),
        TYPE_UNREGISTER_INTERFACE => {
            let mut interface = INTERFACE.lock();
            if *interface == 0 {
                return Ok(STATUS_NOT_FOUND);
            }
            *interface = 0;
            Ok(STATUS_SUCCESS)
        }
        TYPE_QUERY_STATE => Ok(if STATE.load(Ordering::SeqCst) & STATE_REFUSES_FILE_INFO != 0 { STATUS_TOO_LATE } else { STATUS_SUCCESS }),
        _ => Ok(STATUS_NOT_SUPPORTED),
    }
}

/// Type 0xA: entrega a rotina de conflito ao FileInfo e guarda a tabela.
fn register_interface(table: u64) -> Result<u32, KernelError> {
    if *INTERFACE.lock() != 0 {
        return Ok(STATUS_ALREADY_COMMITTED);
    }
    let register = guest::try_read64(table + REGISTER_GLOBAL_BLOCK_NOTIFY)?;
    let start = routine_stubs::address("PfpPrefetchSharedConflictNotifyStart")?;
    // A rotina do FileInfo roda fora do lock do OpenNT (o NT a chama com o
    // push lock da interface retido, que o FileInfo não toma).
    native_call::call(register, &[start]);
    let mut interface = INTERFACE.lock();
    if *interface != 0 {
        return Ok(STATUS_ALREADY_COMMITTED);
    }
    *interface = table;
    Ok(STATUS_SUCCESS)
}

/// A interface registrada pelo FileInfo (0 sem registro).
pub fn registered_interface() -> u64 {
    *INTERFACE.lock()
}

/// PfpPrefetchSharedConflictNotifyStart(Context, Reserved, Output).
fn shared_conflict_start(call: &Call) -> Result<u64, KernelError> {
    SHARED_CONFLICTS.fetch_add(1, Ordering::SeqCst);
    let output = call.arg(3);
    guest::try_write64(output, routine_stubs::address("PfpPrefetchSharedConflictNotifyEnd")?)?;
    guest::try_write64(output + 8, 0)?;
    Ok(STATUS_SUCCESS as u64)
}

/// PfpPrefetchSharedConflictNotifyEnd(Entry): sem entrada de prioridade.
fn shared_conflict_end(_call: &Call) -> Result<u64, KernelError> {
    Ok(0)
}

/// As rotinas que o prefetcher entrega ao FileInfo por ponteiro.
pub const ROUTINES: &[Routine] = &[
    Routine { name: "PfpPrefetchSharedConflictNotifyStart", handler: shared_conflict_start },
    Routine { name: "PfpPrefetchSharedConflictNotifyEnd", handler: shared_conflict_end },
];
