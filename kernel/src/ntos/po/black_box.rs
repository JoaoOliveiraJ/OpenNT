//! Gravador black box (classe 94 de ZwPowerInformation).
//!
//! Cada categoria tem até 4096 bytes próprios de pool não paginado,
//! independentes do buffer do chamador. As categorias seguem PopBlackBoxEntries
//! do kernel de referência; o índice faz parte da ABI da classe 94.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::ex::push_lock;
use crate::ntos::ke::critical_region;
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INTEGER_OVERFLOW: u32 = 0xC000_0095;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const MAXIMUM_STORED_LENGTH: u64 = 4096;
const SHARED_INTERRUPT_TIME: u64 = 0xFFFF_F780_0000_0008;
const SHARED_INTERRUPT_TIME_BIAS: u64 = 0xFFFF_F780_0000_03B0;

/// (nome, GUID nos 16 bytes nativos, flags). A marca de SCM restringe
/// chamadas UserMode no NT; Zw executa em KernelMode.
pub const CATEGORIES: [(&str, &str, u32); 22] = [
    ("SCM", "9188d0e1a3d5f945b811ad711dfb2607", 1),
    ("BSD", "df0873f545cc014ead7629a4ebb010ec", 0),
    ("PNP", "411963b72a53d64cb1b1edb5917d4557", 0),
    ("ACPI", "8ba92e3b55f79f4280c131a18106528c", 0),
    ("POIRP", "46db2325db4d654aa839910e3f985cc6", 0),
    ("WINLOGON-NOTIFY", "933e2d6b07aa3e4ea41a916d0e3cc63b", 0),
    ("PDCLOCK", "bbdddb336e2a914e9e425de1997b8a84", 0),
    ("PEPWORKORDER", "555ae8e0880e7542963f133ffb5a34d0", 0),
    ("POWERWATCHDOG", "9ef7455526536744ae6981633ae33155", 0),
    ("PNPEVENTWORKER", "10f3ef8b6c383141b1b10a44fa1e684a", 0),
    ("DEVICECOMPLETIONQUEUE", "5e4d29c190852e45bc717f45f700ca68", 0),
    ("PNPDELAYEDREMOVEWORKER", "3ba492733aff9c4dba3150aa65cded08", 0),
    ("DXG-DISPLAY", "eeb7beb300edd644ad60c1a92df80f1c", 0),
    ("CrashedProcess", "51d684be50a567438e63ab792b631f94", 0),
    ("UsoCommit", "5ac8e46df357da4c82fec8855a58f8e4", 0),
    ("WHEA", "49ead3322a917d45b7e6dd2929ef53fc", 0),
    ("NTFS", "c4e9af000d9413428016cd3719b5bc20", 0),
    ("Winlogon", "cf79cc8019a7f14abf97fe29ff76ebc1", 0),
    ("Explorer logon tasks", "17659aaaacb9934d8bd02666e63639a0", 0),
    ("Explorer core startup", "e1b2a6f52316124e803948a89b8280fa", 0),
    ("User mode LKD API caller data", "df41b9c1a5b1be449d5cdaf166bc5e22", 0),
    ("CI", "d86be74ef43ca044a0ac3937643e37a3", 0),
];

/// Comprimento pedido e conservado diferem: atualizações além de 4096 bytes
/// podem ser válidas, mas não copiam dados.
#[derive(Clone, Copy, Default)]
struct Record {
    buffer: u64,
    stored_length: u32,
    requested_length: u64,
    timestamp: u64,
    updating: bool,
}

static RECORDS: SpinLock<[Record; 22]> = SpinLock::new([Record { buffer: 0, stored_length: 0, requested_length: 0, timestamp: 0, updating: false }; 22]);
static LOCK: AtomicU64 = AtomicU64::new(0);

/// Publicado uma vez na fase 0, depois do pool e da thread System.
pub fn init() -> Result<(), KernelError> {
    if LOCK.load(Ordering::Acquire) != 0 {
        return Ok(());
    }
    let allocation = kernel_pool::allocate(8, AllocateOptions { paged: false, nx: true, zero: true, tag: 0x4C72_4242, ..Default::default() }).map_err(|_| KernelError::new("black-box recorder lock allocation failed"))?;
    LOCK.store(allocation, Ordering::Release);
    Ok(())
}

/// Repete a leitura se o desconto de suspensão mudar durante a amostragem.
fn unbiased_interrupt_time() -> u64 {
    loop {
        let bias = guest::read64_single(SHARED_INTERRUPT_TIME_BIAS);
        let time = guest::read64_single(SHARED_INTERRUPT_TIME);
        if bias == guest::read64_single(SHARED_INTERRUPT_TIME_BIAS) {
            return time.wrapping_sub(bias);
        }
    }
}

/// memmove limitado ao registro; uma falha de endereço interrompe a cópia.
fn move_payload(destination: u64, source: u64, length: u64) -> Result<(), KernelError> {
    let copy = |offset: u64| guest::try_read8(source + offset).and_then(|byte| guest::try_write8(destination + offset, byte));
    if destination > source && destination < source + length {
        for offset in (0..length).rev() {
            copy(offset)?;
        }
    } else {
        for offset in 0..length {
            copy(offset)?;
        }
    }
    Ok(())
}

fn with_record<T>(index: usize, body: impl FnOnce(&mut Record) -> T) -> T {
    body(&mut RECORDS.lock()[index])
}

/// Núcleo do pedido KernelMode; só o bit 0 de Flags altera o comportamento.
fn update_kernel_request(request: u64) -> Result<u32, KernelError> {
    let index = guest::read32(request + 24) as usize;
    if index >= CATEGORIES.len() {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let flags = guest::read32(request + 28);
    let lock = LOCK.load(Ordering::Acquire);
    if lock == 0 {
        return Err(KernelError::new("black-box recorder used before phase 0"));
    }
    critical_region::enter_critical()?;
    let result = (|| {
        push_lock::acquire_exclusive(lock, 0)?;
        with_record(index, |record| record.updating = true);
        let status = (|| -> Result<u32, KernelError> {
            let length = guest::read64(request + 8);
            let mut offset = 0u64;
            let copy_length;
            if flags & 1 != 0 {
                if length == 0 {
                    return Ok(STATUS_INVALID_PARAMETER);
                }
                offset = guest::read64(request + 16);
                let Some(end) = offset.checked_add(length) else { return Ok(STATUS_INTEGER_OVERFLOW) };
                if end > with_record(index, |record| record.requested_length) {
                    return Ok(STATUS_INVALID_PARAMETER);
                }
                copy_length = if offset >= MAXIMUM_STORED_LENGTH { 0 } else if end > MAXIMUM_STORED_LENGTH { MAXIMUM_STORED_LENGTH - offset } else { length };
            } else {
                copy_length = length.min(MAXIMUM_STORED_LENGTH);
                // O NT publica os comprimentos antes da alocação; falta de
                // memória conserva os comprimentos novos e o timestamp antigo.
                with_record(index, |record| {
                    record.requested_length = length;
                    record.stored_length = copy_length as u32;
                });
            }
            if with_record(index, |record| record.buffer) == 0 {
                let Ok(buffer) = kernel_pool::allocate(4096, AllocateOptions { paged: false, nx: true, zero: false, tag: 0x206D_654D, ..Default::default() }) else {
                    return Ok(STATUS_INSUFFICIENT_RESOURCES);
                };
                with_record(index, |record| record.buffer = buffer);
            }
            let buffer = with_record(index, |record| {
                record.timestamp = unbiased_interrupt_time();
                record.buffer
            });
            if copy_length == 0 {
                return Ok(0);
            }
            // O alias físico da página zero não torna Buffer=NULL válido.
            let source = guest::read64(request);
            if source != 0 && move_payload(buffer + offset, source, copy_length).is_ok() {
                return Ok(0);
            }
            // Origem NULL ou cópia interrompida invalida os comprimentos;
            // buffer e timestamp ficam.
            with_record(index, |record| {
                record.stored_length = 0;
                record.requested_length = 0;
            });
            Ok(STATUS_ACCESS_VIOLATION)
        })();
        with_record(index, |record| record.updating = false);
        push_lock::release_exclusive(lock, 0)?;
        status
    })();
    critical_region::leave_critical()?;
    result
}

/// Ponteiro sem comprimento e comprimento sem ponteiro equivalem à
/// ausência; a entrada exige exatamente 32 bytes e nenhuma saída.
pub fn update_from_kernel(input: u64, input_length: u32, output: u64, output_length: u32) -> Result<u32, KernelError> {
    let input_capacity = if input != 0 { input_length } else { 0 };
    let output_capacity = if output != 0 { output_length } else { 0 };
    if input_capacity == 0 || output_capacity != 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if input_capacity != 32 {
        return Ok(STATUS_BUFFER_TOO_SMALL);
    }
    update_kernel_request(input)
}

/// Cópia possuída pelo consumidor.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub index: usize,
    pub name: &'static str,
    pub buffer: u64,
    pub stored_length: u32,
    pub requested_length: u64,
    pub timestamp: u64,
    pub bytes: Vec<u8>,
}

fn copy_record(index: usize, record: &Record) -> Snapshot {
    let bytes = if record.buffer != 0 { guest::read_bytes(record.buffer, record.stored_length as usize) } else { Vec::new() };
    Snapshot { index, name: CATEGORIES[index].0, buffer: record.buffer, stored_length: record.stored_length, requested_length: record.requested_length, timestamp: record.timestamp, bytes }
}

/// Diagnóstico em execução normal, sob o mesmo lock dos escritores.
pub fn snapshot(index: usize) -> Result<Snapshot, KernelError> {
    if index >= CATEGORIES.len() {
        return Err(KernelError::new("invalid black-box category"));
    }
    let lock = LOCK.load(Ordering::Acquire);
    if lock == 0 {
        return Err(KernelError::new("black-box recorder used before phase 0"));
    }
    critical_region::enter_critical()?;
    let result = push_lock::acquire_shared(lock, 0).map(|_| {
        let record = RECORDS.lock()[index];
        let copy = copy_record(index, &record);
        let _ = push_lock::release_shared(lock, 0);
        copy
    });
    critical_region::leave_critical()?;
    result
}

/// Consumidor de parada do kernel: metadados e bytes pela serial, sem
/// esperar locks; registros em alteração são marcados como incompletos.
pub fn publish_crash_records() {
    let records = *RECORDS.lock();
    for (index, record) in records.iter().enumerate() {
        if record.updating {
            debug_print!("KERNEL_BLACKBOX_INCOMPLETE {}", index);
            continue;
        }
        if record.buffer == 0 || record.stored_length == 0 {
            continue;
        }
        debug_print!("KERNEL_BLACKBOX_RECORD {{\"index\":{},\"name\":\"blackbox - {}\",\"guidBytes\":\"{}\",\"flags\":{},\"storedLength\":{},\"requestedLength\":\"0x{:x}\",\"timestamp\":\"0x{:x}\"}}", index, CATEGORIES[index].0, CATEGORIES[index].1, CATEGORIES[index].2, record.stored_length, record.requested_length, record.timestamp);
        let mut offset = 0u32;
        while offset < record.stored_length {
            let end = (offset + 128).min(record.stored_length);
            let mut hex = alloc::string::String::new();
            for position in offset..end {
                hex.push_str(&alloc::format!("{:02x}", guest::read8(record.buffer + position as u64)));
            }
            debug_print!("KERNEL_BLACKBOX_BYTES {{\"index\":{},\"offset\":{},\"bytes\":\"{}\"}}", index, offset, hex);
            offset += 128;
        }
    }
}
