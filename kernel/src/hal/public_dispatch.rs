//! HalDispatchTable — o HAL_DISPATCH público do ntoskrnl.
//!
//! Export de dados de 0xC0 bytes (versão 4 e 23 ponteiros de função) que o NT
//! expõe aos drivers e que a HAL preenche na inicialização. É a tabela PÚBLICA
//! — distinta da HalPrivateDispatchTable (privada, 0x4B0) — que drivers como o
//! BasicDisplay e o dxgkrnl indexam para alcançar HalQuerySystemInformation
//! (slot 1, offset 0x08), HalSetSystemInformation (slot 2), HalQueryBusSlots
//! (slot 3) etc. Tamanho e versão conferidos no `.data` do ntoskrnl 19041
//! (HalDispatchTable no RVA 0xc00a60, seguida do KdDebuggerDataBlock em 0xc00b20).
//!
//! Esta plataforma não oferece nenhuma rotina do HAL_DISPATCH público
//! (consulta de sistema legada, tabela de partição MBR, espelhamento de
//! memória, arbitragem de barramento), então todos os slots de função apontam
//! para o mesmo corpo nativo `hal_default_not_supported` (`mov eax,
//! 0xC00000BB; ret` = STATUS_NOT_SUPPORTED): qualquer slot que um driver
//! indexe é um ponteiro válido que falha de forma limpa.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::amd64::private_entries;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::{kernel_address, kernel_data};
use crate::rtl::KernelError;

/// HAL_DISPATCH_VERSION do ntoskrnl de referência (constante desde o Win2000).
pub const VERSION: u32 = 4;
/// Ponteiros de função depois do campo Version (offsets 0x08..0xB8).
pub const SLOT_COUNT: usize = 23;

static TABLE: AtomicU64 = AtomicU64::new(0);

fn native(symbol: &str) -> Result<u64, KernelError> {
    let entry = private_entries::entry(symbol).ok_or_else(|| KernelError::new(alloc::format!("corpo nativo ausente: {symbol}")))?;
    kernel_address::virtual_address(entry)
}

/// HalInitSystem: grava a versão e aponta todos os slots de função para o
/// stub seguro, como a HAL preenche a tabela no boot do NT.
pub fn initialize() -> Result<(), KernelError> {
    let table = kernel_data::address("HalDispatchTable")?;
    let stub = native("hal_default_not_supported")?;
    guest::write32(table, VERSION);
    for slot in 0..SLOT_COUNT as u64 {
        guest::write64(table + 0x08 + slot * 8, stub);
    }
    TABLE.store(table, Ordering::SeqCst);
    crate::debug_print!("[hal] HalDispatchTable versao {} em {:#x}: {} slots -> STATUS_NOT_SUPPORTED", VERSION, table, SLOT_COUNT);
    Ok(())
}

/// Endereço da tabela publicada (0 antes da inicialização da HAL).
pub fn table_address() -> u64 {
    TABLE.load(Ordering::SeqCst)
}
