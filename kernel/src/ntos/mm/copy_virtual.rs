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

// ---- MmCopyMemory (ntoskrnl 19041 rva 0x30c030) ---------------------------------
//
// MmCopyMemory(TargetAddress, SourceAddress, NumberOfBytes, Flags,
// NumberOfBytesTransferred): *NumberOfBytesTransferred começa em zero; Flags
// precisa ser exatamente MM_COPY_MEMORY_PHYSICAL (1) ou MM_COPY_MEMORY_VIRTUAL
// (2), com IRQL <= APC_LEVEL, senão STATUS_INVALID_PARAMETER_4.
// - Física: MiCheckPhysicalAddressRange recusa (STATUS_CONFLICTING_ADDRESSES)
//   a faixa vazia ou que dá a volta, a que passa da largura física das MTRRs
//   (KiMtrrMaskBase) e, num processador AMD, a que toca a janela do
//   HyperTransport (0xFD_0000_0000..0xFF_FFFF_FFFF).
// - Virtual: a faixa vazia ou que dá a volta é STATUS_CONFLICTING_ADDRESSES;
//   inteira abaixo de MM_HIGHEST_USER_ADDRESS (o fim exclusivo também), é o
//   ZwReadVirtualMemory do processo corrente; uma VA não canônica, ou que
//   cruza a fronteira do usuário, é STATUS_CONFLICTING_ADDRESSES.
// - Física e virtual de sistema andam página a página (mais de 2^32 páginas
//   é STATUS_INVALID_PARAMETER_2): a página de sistema sem tradução
//   (MiTranslatePageForCopy) é STATUS_INVALID_ADDRESS, um destino que falha
//   na cópia (o __except do MiCopySinglePage) é STATUS_ACCESS_VIOLATION; a
//   contagem é o que foi copiado antes da página que parou. A página física
//   é lida pelo mapa de I/O do OpenNT (`io_space`); uma que ele não mapeia
//   fica sem tradução.

const MM_COPY_MEMORY_PHYSICAL: u32 = 1;
const MM_COPY_MEMORY_VIRTUAL: u32 = 2;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F1;
const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;
const STATUS_CONFLICTING_ADDRESSES: u32 = 0xC000_0018;
const STATUS_INVALID_ADDRESS: u32 = 0xC000_0141;
const MM_HIGHEST_USER_ADDRESS: u64 = 0x7FFF_FFFE_FFFF;
const SYSTEM_RANGE_START: u64 = 0xFFFF_8000_0000_0000;
/// A janela do HyperTransport que os processadores AMD reservam.
const HYPERTRANSPORT_START: u64 = 0xFD_0000_0000;
const HYPERTRANSPORT_END: u64 = 0xFF_FFFF_FFFF;

/// KiMtrrMaskBase: a máscara do endereço físico das MTRRs (a largura do
/// CPUID 0x80000008, 36 bits sem a folha), zero sem MTRR.
fn mtrr_mask_base() -> u64 {
    use crate::hal::cpu;
    if cpu::cpuid(1)[3] & (1 << 12) == 0 {
        return 0;
    }
    let width = if cpu::cpuid(0x8000_0000)[0] >= 0x8000_0008 { cpu::cpuid(0x8000_0008)[0] & 0xFF } else { 36 };
    ((1u64 << width.clamp(12, 63)) - 1) & !(PAGE - 1)
}

/// MiCheckPhysicalAddressRange(Start, Length).
fn physical_range_allowed(start: u64, length: u64) -> bool {
    let Some(end) = start.checked_add(length).filter(|&end| end > start) else { return false };
    let last = end - 1;
    let mask = mtrr_mask_base();
    if mask != 0 && last & !(PAGE - 1) > mask {
        return false;
    }
    let amd = crate::ntos::ke::pcr::current().prcb.cpu_vendor.get() == crate::ntos::ke::processor_identity::vendor::AMD;
    !(amd && last >= HYPERTRANSPORT_START && start <= HYPERTRANSPORT_END)
}

/// Lê um pedaço (dentro de uma página) da origem física ou virtual de sistema.
fn read_piece(source: u64, length: usize, physical: bool) -> Option<Vec<u8>> {
    if !physical {
        return guest::try_read_bytes(source, length).ok();
    }
    let mapped = crate::ntos::mm::io_space::map_ex(source, length as u64);
    if mapped == 0 {
        return None;
    }
    let bytes = guest::read_bytes(mapped, length);
    crate::ntos::mm::io_space::unmap(mapped, length as u64);
    Some(bytes)
}

/// MmCopyMemory: (NTSTATUS, bytes copiados).
pub fn copy_memory(target: u64, source: u64, length: u64, flags: u32) -> Result<(u32, u64), KernelError> {
    if !matches!(flags, MM_COPY_MEMORY_PHYSICAL | MM_COPY_MEMORY_VIRTUAL) || irql::get_irql() > irql::APC_LEVEL {
        return Ok((STATUS_INVALID_PARAMETER_4, 0));
    }
    let physical = flags == MM_COPY_MEMORY_PHYSICAL;
    if physical {
        if !physical_range_allowed(source, length) {
            return Ok((STATUS_CONFLICTING_ADDRESSES, 0));
        }
    } else {
        let Some(end) = source.checked_add(length).filter(|&end| end > source) else { return Ok((STATUS_CONFLICTING_ADDRESSES, 0)) };
        if source <= MM_HIGHEST_USER_ADDRESS {
            if end > MM_HIGHEST_USER_ADDRESS {
                return Ok((STATUS_CONFLICTING_ADDRESSES, 0));
            }
            let current = process::get_current_process();
            return copy_virtual_memory(current, source, current, target, length, KERNEL_MODE);
        }
        if source < SYSTEM_RANGE_START {
            return Ok((STATUS_CONFLICTING_ADDRESSES, 0));
        }
    }
    if (length + (PAGE - 1) + (source & (PAGE - 1))) >> 12 >= 1 << 32 {
        return Ok((STATUS_INVALID_PARAMETER_2, 0));
    }
    let mut copied = 0u64;
    while copied < length {
        let at = source + copied;
        let piece = (length - copied).min(PAGE - at % PAGE);
        let Some(bytes) = read_piece(at, piece as usize, physical) else { return Ok((STATUS_INVALID_ADDRESS, copied)) };
        if guest::try_write_bytes(target + copied, &bytes).is_err() {
            return Ok((STATUS_ACCESS_VIOLATION, copied));
        }
        copied += piece;
    }
    Ok((0, copied))
}
