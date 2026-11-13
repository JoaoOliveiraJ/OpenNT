//! Descritores KSERVICE_TABLE_DESCRIPTOR.
//!
//! Dono dos descritores e das tabelas compactadas nativas. Os endereços
//! executáveis vêm dos provedores registrados pelo dispatcher de serviços.

use alloc::vec::Vec;

use crate::hal::amd64::service_table as storage;
use crate::ntos::mm::{kernel_address, paging};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

/// 4096 entradas por tabela; 32 bytes por descritor.
pub const CAPACITY: usize = 4096;
pub const DESCRIPTOR_SIZE: u64 = 32;

/// Endereços publicados (no alias da imagem do kernel).
#[derive(Clone, Copy, Debug)]
pub struct Addresses {
    pub lookup: u64,
    pub descriptor: u64,
    pub shadow: u64,
    pub tables: [u64; 2],
    pub argument_tables: [u64; 2],
}

/// Descrição imutável de uma tabela publicada.
#[derive(Clone, Debug)]
pub struct Installed {
    pub index: usize,
    pub limit: usize,
    pub table: u64,
    pub argument_table: u64,
    pub values: Vec<u32>,
    pub descriptors: Vec<u64>,
}

static ADDRESSES: SpinLock<Option<Addresses>> = SpinLock::new(None);
static INSTALLED: SpinLock<[Option<Installed>; 2]> = SpinLock::new([None, None]);

/// Deslocamento com sinal de 28 bits relativo à tabela e quatro bits de
/// argumentos na pilha.
pub fn encode_entry(table: u64, target: u64, stack_arguments: u32) -> Result<u32, KernelError> {
    let relative = target.wrapping_sub(table) as i64;
    if target == 0 || !(-0x800_0000..=0x7FF_FFFF).contains(&relative) || stack_arguments > 15 {
        return Err(KernelError::new("invalid native service entry"));
    }
    Ok(((relative << 4) as u32) | stack_arguments)
}

/// (endereço, argumentos na pilha) de uma entrada compactada.
pub fn decode_entry(table: u64, encoded: u32) -> (u64, u32) {
    (table.wrapping_add(((encoded as i32) >> 4) as i64 as u64), encoded & 15)
}

/// Endereços nativos dos descritores, tabelas e argumentos, uma única vez.
pub fn init() -> Result<Addresses, KernelError> {
    let mut addresses = ADDRESSES.lock();
    if let Some(addresses) = *addresses {
        return Ok(addresses);
    }
    let entries = storage::entries();
    let entry = |index: usize| kernel_address::virtual_address(entries[index]);
    let published = Addresses {
        lookup: entry(0)?,
        descriptor: entry(1)?,
        shadow: entry(2)?,
        tables: [entry(3)?, entry(4)?],
        argument_tables: [entry(5)?, entry(6)?],
    };
    *addresses = Some(published);
    Ok(published)
}

/// Valida a solicitação inteira e as páginas executáveis antes de escrever.
/// A tabela é imutável no boot; uma nova solicitação só confirma a mesma ABI.
pub fn install(index: usize, targets: &[u64], stack_arguments: &[u32]) -> Result<Installed, KernelError> {
    let addresses = init()?;
    if index > 1 || targets.len() != stack_arguments.len() || targets.len() > CAPACITY {
        return Err(KernelError::new("invalid native service table"));
    }
    let table = addresses.tables[index];
    let argument_table = addresses.argument_tables[index];
    let encoded = targets.iter().zip(stack_arguments).map(|(&target, &arguments)| encode_entry(table, target, arguments)).collect::<Result<Vec<u32>, _>>()?;
    let mut installed = INSTALLED.lock();
    // Uma biblioteca carregada depois verifica a ABI, mas não a substitui.
    if let Some(previous) = &installed[index] {
        if previous.values != encoded {
            return Err(KernelError::new("cannot replace a live native service ABI"));
        }
        return Ok(previous.clone());
    }
    // Cada destino: executável e supervisor, sem acesso de usuário.
    for &target in targets {
        match paging::query_page(target, false) {
            Some(page) if !page.nx && page.access & 1 != 0 && page.access & 4 == 0 => {}
            _ => return Err(KernelError::new("native service provider must be supervisor executable memory")),
        }
    }
    for (entry, (&value, &arguments)) in encoded.iter().zip(stack_arguments).enumerate() {
        guest::write32(table + entry as u64 * 4, value);
        guest::write8(argument_table + entry as u64, (arguments * 4) as u8);
    }
    let descriptors = if index == 0 { alloc::vec![addresses.descriptor, addresses.shadow] } else { alloc::vec![addresses.shadow + 32] };
    for &descriptor in &descriptors {
        guest::write64(descriptor, table);
        // Sem o vetor opcional de contadores de profiling.
        guest::write64(descriptor + 8, 0);
        guest::write64(descriptor + 24, argument_table);
        // O limite sai por último, depois dos endereços e metadados.
        guest::write64(descriptor + 16, targets.len() as u64);
    }
    let record = Installed { index, limit: targets.len(), table, argument_table, values: encoded, descriptors };
    installed[index] = Some(record.clone());
    Ok(record)
}

/// (endereço, argumentos na pilha) vigentes para o número de serviço;
/// `use_shadow` seleciona os descritores que incluem a tabela gráfica.
pub fn inspect(service_number: u32, use_shadow: bool) -> Result<(u64, u32), KernelError> {
    let addresses = init()?;
    let descriptor = if use_shadow { addresses.shadow } else { addresses.descriptor } + ((service_number >> 7) & 32) as u64;
    let index = service_number & 0xFFF;
    if index >= guest::read32(descriptor + 16) {
        return Ok((0, 0));
    }
    let table = guest::read64(descriptor);
    Ok(decode_entry(table, guest::read32(table + index as u64 * 4)))
}

/// Só para o self-test: desfaz uma publicação para que o boot real ainda
/// possa instalar a ABI medida.
/// A descrição imutável da tabela instalada, se houver.
pub fn installed(index: usize) -> Option<Installed> {
    INSTALLED.lock().get(index).cloned().flatten()
}

pub fn self_test_reset(index: usize) -> Result<(), KernelError> {
    let addresses = init()?;
    let Some(record) = INSTALLED.lock()[index.min(1)].take() else { return Ok(()) };
    for &descriptor in &record.descriptors {
        guest::write64(descriptor + 16, 0);
        guest::write64(descriptor, 0);
        guest::write64(descriptor + 24, 0);
    }
    for entry in 0..record.limit as u64 {
        guest::write32(addresses.tables[record.index] + entry * 4, 0);
        guest::write8(addresses.argument_tables[record.index] + entry, 0);
    }
    Ok(())
}
