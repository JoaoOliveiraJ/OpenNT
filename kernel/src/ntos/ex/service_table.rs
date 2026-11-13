//! Descritores KSERVICE_TABLE_DESCRIPTOR.
//!
//! Dono dos descritores e da tabela compactada nativa (KiServiceTable), cujos
//! endereços executáveis vêm dos provedores registrados pelo dispatcher de
//! serviços. A entrada 1 dos descritores é a tabela gráfica: só o win32k a
//! publica no KeServiceDescriptorTableShadow, com as tabelas dele; até lá ela
//! fica vazia (Limit zero) e um serviço gráfico segue o caminho do
//! KiSystemCall64 sem o win32k (`out_of_range`).

use alloc::vec::Vec;

use crate::hal::amd64::service_table as storage;
use crate::ntos::mm::{kernel_address, paging};
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::ps::win32_callouts;
use crate::rtl::{KernelError, SpinLock};

const STATUS_INVALID_SYSTEM_SERVICE: u32 = 0xC000_001C;

/// KSERVICE_TABLE_DESCRIPTOR (KeServiceDescriptorTable[Shadow]): base da
/// tabela codificada, contadores, limite e a tabela de bytes de argumentos.
#[repr(C)]
struct ServiceDescriptor {
    /// -> tabela de entradas `(relativo << 4) | argumentos`.
    base: Field<u64>,
    count: Field<u64>,
    /// ULONG Limit (gravado com o preenchimento como 64 bits).
    limit: Field<u64>,
    /// -> bytes de argumentos de pilha por serviço.
    number: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for ServiceDescriptor {}

const _: () = assert!(core::mem::size_of::<ServiceDescriptor>() as u64 == DESCRIPTOR_SIZE);

impl ServiceDescriptor {
    fn limit(&self) -> u64 {
        self.limit.get() & 0xFFFF_FFFF
    }
}

fn descriptor_at(address: u64) -> &'static ServiceDescriptor {
    // SAFETY: os descritores são células fixas da imagem do kernel.
    unsafe { ServiceDescriptor::at(address) }
}

/// A tabela codificada e a de argumentos da imagem.
fn tables(table: u64, argument_table: u64, count: usize) -> (&'static [Field<u32>], &'static [Field<u8>]) {
    // SAFETY: as tabelas da imagem têm CAPACITY entradas.
    unsafe { (Field::<u32>::array_at(table, count), Field::<u8>::array_at(argument_table, count)) }
}

/// 4096 entradas por tabela; 32 bytes por descritor.
pub const CAPACITY: usize = 4096;
pub const DESCRIPTOR_SIZE: u64 = 32;

/// Endereços publicados (no alias da imagem do kernel).
#[derive(Clone, Copy, Debug)]
pub struct Addresses {
    pub lookup: u64,
    pub descriptor: u64,
    pub shadow: u64,
    pub table: u64,
    pub argument_table: u64,
}

/// Descrição imutável da tabela nativa publicada.
#[derive(Clone, Debug)]
pub struct Installed {
    pub limit: usize,
    pub table: u64,
    pub argument_table: u64,
    pub values: Vec<u32>,
    pub descriptors: Vec<u64>,
}

static ADDRESSES: SpinLock<Option<Addresses>> = SpinLock::new(None);
static INSTALLED: SpinLock<Option<Installed>> = SpinLock::new(None);

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

/// Endereços nativos dos descritores, da tabela e dos argumentos, uma única vez.
pub fn init() -> Result<Addresses, KernelError> {
    let mut addresses = ADDRESSES.lock();
    if let Some(addresses) = *addresses {
        return Ok(addresses);
    }
    let entries = storage::entries();
    let entry = |index: usize| kernel_address::virtual_address(entries[index]);
    let published = Addresses { lookup: entry(0)?, descriptor: entry(1)?, shadow: entry(2)?, table: entry(3)?, argument_table: entry(4)? };
    *addresses = Some(published);
    Ok(published)
}

/// Publica a KiServiceTable na entrada 0 dos dois descritores. Valida a
/// solicitação inteira e as páginas executáveis antes de escrever; a tabela
/// é imutável no boot e uma nova solicitação só confirma a mesma ABI.
pub fn install(targets: &[u64], stack_arguments: &[u32]) -> Result<Installed, KernelError> {
    let addresses = init()?;
    if targets.len() != stack_arguments.len() || targets.len() > CAPACITY {
        return Err(KernelError::new("invalid native service table"));
    }
    let (table, argument_table) = (addresses.table, addresses.argument_table);
    let encoded = targets.iter().zip(stack_arguments).map(|(&target, &arguments)| encode_entry(table, target, arguments)).collect::<Result<Vec<u32>, _>>()?;
    let mut installed = INSTALLED.lock();
    // Uma biblioteca carregada depois verifica a ABI, mas não a substitui.
    if let Some(previous) = &*installed {
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
    let (entries, argument_bytes) = tables(table, argument_table, encoded.len());
    for ((entry, bytes), (&value, &arguments)) in entries.iter().zip(argument_bytes).zip(encoded.iter().zip(stack_arguments)) {
        entry.set(value);
        bytes.set((arguments * 4) as u8);
    }
    let descriptors = alloc::vec![addresses.descriptor, addresses.shadow];
    for &descriptor in &descriptors {
        let descriptor = descriptor_at(descriptor);
        descriptor.base.set(table);
        // Sem o vetor opcional de contadores de profiling.
        descriptor.count.set(0);
        descriptor.number.set(argument_table);
        // O limite sai por último, depois dos endereços e metadados.
        descriptor.limit.set(targets.len() as u64);
    }
    let record = Installed { limit: targets.len(), table, argument_table, values: encoded, descriptors };
    *installed = Some(record.clone());
    Ok(record)
}

/// (endereço, argumentos na pilha) vigentes para o número de serviço;
/// `use_shadow` seleciona os descritores que incluem a tabela gráfica.
pub fn inspect(service_number: u32, use_shadow: bool) -> Result<(u64, u32), KernelError> {
    let addresses = init()?;
    let descriptor = descriptor_at(if use_shadow { addresses.shadow } else { addresses.descriptor } + ((service_number >> 7) & 32) as u64);
    let index = service_number & 0xFFF;
    if u64::from(index) >= descriptor.limit() {
        return Ok((0, 0));
    }
    let table = descriptor.base.get();
    // SAFETY: `index` está abaixo do Limit publicado para esta tabela.
    let entry = unsafe { Field::<u32>::array_at(table, index as usize + 1) }[index as usize].get();
    Ok(decode_entry(table, entry))
}

/// Status de uma syscall gráfica cuja conversão em thread GUI falhou: abaixo
/// do Limit da tabela 1 do Shadow, o byte de erro do serviço guardado depois
/// das entradas da tabela (0 ou -1, estendido com sinal); acima dele, ou com
/// byte positivo, STATUS_INVALID_SYSTEM_SERVICE.
fn win32_failure_status(addresses: &Addresses, service_number: u32) -> u32 {
    let descriptor = descriptor_at(addresses.shadow + DESCRIPTOR_SIZE);
    let (limit, index) = (descriptor.limit(), u64::from(service_number & 0xFFF));
    if index >= limit {
        return STATUS_INVALID_SYSTEM_SERVICE;
    }
    // SAFETY: a tabela publicada pelo win32k tem Limit entradas de quatro
    // bytes seguidas dos Limit bytes de erro.
    let error = unsafe { Field::<i8>::at(descriptor.base.get() + limit * 4 + index) }.get();
    if error <= 0 { error as i32 as u32 } else { STATUS_INVALID_SYSTEM_SERVICE }
}

/// Syscall de usuário fora do Limit do descritor da thread, como no
/// KiSystemCall64 do ntoskrnl 19041: um número da tabela nativa devolve
/// STATUS_INVALID_SYSTEM_SERVICE; um da tabela 1 converte a thread em GUI e
/// repete a busca no Shadow, e uma conversão que falha termina no status de
/// `win32_failure_status`. Devolve a rotina e os argumentos de pilha, ou o
/// NTSTATUS para o modo usuário.
pub fn out_of_range(service_number: u32) -> Result<Result<(u64, u32), u32>, KernelError> {
    if service_number & 0x1000 == 0 {
        return Ok(Err(STATUS_INVALID_SYSTEM_SERVICE));
    }
    let addresses = init()?;
    while win32_callouts::convert_to_gui_thread() == 0 {
        let (target, arguments) = inspect(service_number, true)?;
        if target != 0 {
            return Ok(Ok((target, arguments)));
        }
    }
    Ok(Err(win32_failure_status(&addresses, service_number)))
}

/// A descrição imutável da tabela nativa instalada, se houver.
pub fn installed() -> Option<Installed> {
    INSTALLED.lock().clone()
}

/// Só para o self-test: desfaz a publicação para que o boot real ainda
/// possa instalar a ABI medida.
pub fn self_test_reset() -> Result<(), KernelError> {
    let addresses = init()?;
    let Some(record) = INSTALLED.lock().take() else { return Ok(()) };
    for &descriptor in &record.descriptors {
        let descriptor = descriptor_at(descriptor);
        descriptor.limit.set(0);
        descriptor.base.set(0);
        descriptor.number.set(0);
    }
    let (entries, argument_bytes) = tables(addresses.table, addresses.argument_table, record.limit);
    for (entry, bytes) in entries.iter().zip(argument_bytes) {
        entry.set(0);
        bytes.set(0);
    }
    Ok(())
}
