//! MmCopyVirtualMemory: a cópia de memória virtual entre dois processos, o
//! núcleo do NtReadVirtualMemory e do NtWriteVirtualMemory.
//!
//! Como o método por pool do MmCopyVirtualMemory do NT, a cópia anda em
//! blocos de até 64 KB por um buffer de kernel: anexada ao processo de
//! origem (`ps::process_context::with_process`, o KeStackAttachProcess),
//! lê o bloco; anexada ao de destino, grava o que leu. Cada lado passa
//! pelas sondas de `guest_memory` no espaço anexado: página ausente, sem
//! acesso ou somente leitura (numa gravação) param a cópia, e o modo
//! estrito confere que a página é do processo anexado. Os blocos andam para
//! a frente: faixas sobrepostas no mesmo processo só saem certas dentro de
//! um bloco, como no NT.
//!
//! - Tamanho zero: sucesso, nada copiado.
//! - O processo "outro" (a origem, ou o destino quando a origem é o
//!   corrente) precisa ainda ter espaço de endereçamento: terminado ou
//!   saindo, STATUS_PROCESS_IS_TERMINATING (a rundown protection do NT).
//! - As faixas não dão a volta e, com PreviousMode UserMode, ficam inteiras
//!   abaixo de MmUserProbeAddress (o ProbeForRead/ProbeForWrite do primeiro
//!   bloco); senão STATUS_ACCESS_VIOLATION, nada copiado.
//! - A primeira página inacessível, de qualquer lado, encerra a cópia com
//!   STATUS_PARTIAL_COPY. A contagem é exatamente o que chegou ao destino: o
//!   prefixo legível de um bloco é gravado antes de a cópia parar, então
//!   ela vai até o primeiro byte inacessível da origem ou do destino.

use alloc::vec::Vec;

use crate::ntos::ke::irql;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::memory_map as map;
use crate::ntos::ps::user::process_state;
use crate::ntos::ps::{process, process_context};
use crate::rtl::KernelError;

const PAGE: u64 = map::PAGE_SIZE;
/// O bloco de cada ida e volta pelo buffer de kernel (MAX_MOVE_SIZE).
const MAX_MOVE_SIZE: u64 = 0x1_0000;
const KERNEL_MODE: u8 = 0;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_PARTIAL_COPY: u32 = 0x8000_000D;
const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;

/// MmCopyVirtualMemory(FromProcess, FromAddress, ToProcess, ToAddress,
/// BufferSize, PreviousMode): o NTSTATUS e os bytes que chegaram ao destino
/// (o NumberOfBytesCopied). Os dois EPROCESS são do chamador, que os mantém
/// referenciados. Um attach recusado (raiz que não pode ser carregada) é
/// erro do sistema, não um status.
pub fn copy_virtual_memory(from_process: u64, from: u64, to_process: u64, to: u64, size: u64, previous_mode: u8) -> Result<(u32, u64), KernelError> {
    if size == 0 {
        return Ok((0, 0));
    }
    if irql::get_irql() > irql::APC_LEVEL {
        return Err(KernelError::new("MmCopyVirtualMemory requires IRQL <= APC_LEVEL"));
    }
    let other = if from_process == process::get_current_process() { to_process } else { from_process };
    if !has_address_space(other) {
        return Ok((STATUS_PROCESS_IS_TERMINATING, 0));
    }
    if !fits(from, size, previous_mode) || !fits(to, size, previous_mode) {
        return Ok((STATUS_ACCESS_VIOLATION, 0));
    }
    let mut buffer = Vec::with_capacity(size.min(MAX_MOVE_SIZE) as usize);
    let mut copied = 0;
    while copied < size {
        let amount = (size - copied).min(MAX_MOVE_SIZE);
        buffer.clear();
        process_context::with_process(from_process, || read_accessible(from + copied, amount, &mut buffer))?;
        let written = process_context::with_process(to_process, || write_accessible(to + copied, &buffer))?;
        copied += written;
        if written < amount {
            return Ok((STATUS_PARTIAL_COPY, copied));
        }
    }
    Ok((0, copied))
}

/// O processo ainda tem espaço de endereçamento: vivo, sem término em
/// curso, com o estado (e o VAD) de pé.
fn has_address_space(process: u64) -> bool {
    process::with_record(process, |record| !record.terminated && !record.exiting).unwrap_or(false) && process_state::get(process).is_some()
}

/// A faixa não dá a volta e, vinda de UserMode, fica inteira abaixo de
/// MmUserProbeAddress.
fn fits(address: u64, size: u64, previous_mode: u8) -> bool {
    address.checked_add(size).is_some_and(|end| previous_mode == KERNEL_MODE || end <= map::USER_PROBE_ADDRESS)
}

/// Lê para `into` até `length` bytes de `address`, no espaço carregado,
/// página a página; para no primeiro byte inacessível.
fn read_accessible(address: u64, length: u64, into: &mut Vec<u8>) {
    while (into.len() as u64) < length {
        let at = address + into.len() as u64;
        let piece = (length - into.len() as u64).min(PAGE - at % PAGE);
        match guest::try_read_bytes(at, piece as usize) {
            Ok(bytes) => into.extend_from_slice(&bytes),
            Err(_) => break,
        }
    }
}

/// Grava `bytes` em `address`, no espaço carregado, página a página; para
/// no primeiro byte inacessível e devolve quantos gravou. Cada pedaço fica
/// numa página, que a sonda aceita ou recusa antes de gravar.
fn write_accessible(address: u64, bytes: &[u8]) -> u64 {
    let mut written = 0usize;
    while written < bytes.len() {
        let at = address + written as u64;
        let piece = (bytes.len() - written).min((PAGE - at % PAGE) as usize);
        if guest::try_write_bytes(at, &bytes[written..written + piece]).is_err() {
            break;
        }
        written += piece;
    }
    written as u64
}
