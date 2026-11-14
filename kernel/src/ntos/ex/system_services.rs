//! Números de serviço e seus provedores.
//!
//! Vincula os números lidos da ntdll aos provedores da tabela nativa: os
//! metadados de `service_abi` descrevem a convenção de chamada e a
//! disponibilidade depende de uma implementação de usuário (handler
//! registrado) ou de kernel (export Nt/Zw). Slots sem provedor apontam para
//! a falha explícita do runtime; os demais recebem o gateway do número. A
//! tabela gráfica (números a partir de 0x1000) é do win32k, não daqui.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::{service_abi, service_table};
use crate::hal;
use crate::ntos::mm::kernel_address;
use crate::ntos::ps::previous_mode;
use crate::ntos::ps::user::{loader, state, syscall_scan};
use crate::ntos::inc::field::{Field, NtStruct};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::{ntos::init::export_names as abi_names, ntos::init::exports};

/// Bloco de argumentos brutos de um serviço de usuário: o número, os 14
/// argumentos, o endereço de retorno e a pilha do chamador.
#[repr(C)]
struct RawArguments {
    service: Field<u64>,
    arguments: [Field<u64>; 14],
    return_address: Field<u64>,
    stack_pointer: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for RawArguments {}

const _: () = assert!(core::mem::size_of::<RawArguments>() == 17 * 8);

/// Um identificador privado por posição da tabela nativa.
pub const PRIVATE_SERVICE_BASE: u64 = 0x4000_0000;
pub const PRIVATE_SERVICE_COUNT: u64 = service_table::CAPACITY as u64;

#[derive(Clone)]
struct Binding {
    name: String,
    kernel: Option<usize>,
    user: bool,
}

static BINDINGS: SpinLock<BTreeMap<u32, Binding>> = SpinLock::new(BTreeMap::new());
static REGISTERED: SpinLock<Option<BTreeMap<u32, String>>> = SpinLock::new(None);
/// `invoke_service(name, a1..a4, retorno, rsp)` de `ps/user/index`.
static USER_INVOKER: SpinLock<Option<fn(&str, [u64; 4], u64, u64) -> Result<u32, KernelError>>> = SpinLock::new(None);

pub fn set_user_invoker(invoker: fn(&str, [u64; 4], u64, u64) -> Result<u32, KernelError>) {
    *USER_INVOKER.lock() = Some(invoker);
}

fn export_index(name: &str) -> Option<usize> {
    abi_names::EXPORT_NAMES.iter().position(|&candidate| candidate == name)
}

/// Valida o mapa lido da ntdll e publica a tabela nativa antes de
/// confirmar os vínculos; registros repetidos precisam conservar a ABI ativa.
pub fn register(input: &BTreeMap<u32, String>) -> Result<(), KernelError> {
    let mut names = input.clone();
    // NtQuerySystemTime não tem a rotina canônica nesta imagem: o slot só
    // entra quando todos os demais nomes e números correspondem.
    let canonical: Vec<&(u32, &str, u32)> = service_abi::NATIVE.entries.iter().filter(|row| row.1 != "NtQuerySystemTime").collect();
    if names.len() == canonical.len() && canonical.iter().all(|row| names.get(&row.0).is_some_and(|name| name == row.1)) {
        for &(number, name, _) in service_abi::NATIVE.entries {
            names.insert(number, String::from(name));
        }
    }
    if names.is_empty() || names.keys().any(|&number| u64::from(number) >= PRIVATE_SERVICE_COUNT) {
        return Err(KernelError::new("invalid library service numbers"));
    }
    for name in names.values() {
        if service_abi::stack_arguments(name).is_none() {
            return Err(KernelError::new(alloc::format!("unmeasured service calling convention: {name}")));
        }
    }
    let existing = REGISTERED.lock().clone();
    if let Some(existing) = existing {
        if existing != names {
            return Err(KernelError::new("loaded library changes the live service ABI"));
        }
        state::with(|state| state.name_by_number.extend(names));
        return Ok(());
    }
    let entries = hal::amd64::service_table::entries();
    let gateway_base = kernel_address::image_address(entries[5])?;
    let unavailable = kernel_address::image_address(entries[6])?;
    let limit = names.keys().max().copied().unwrap_or(0) as usize + 1;
    let mut targets = vec![unavailable; limit];
    let mut stack_arguments = vec![0u32; limit];
    let mut pending: Vec<(u32, Binding)> = Vec::new();
    for (&number, name) in &names {
        let slot = number as usize;
        // Primeiro o nome Nt, depois a variante Zw: conserva o índice do
        // export realmente disponível.
        let kernel = export_index(name).or_else(|| export_index(&alloc::format!("Zw{}", &name[2..])));
        stack_arguments[slot] = service_abi::stack_arguments(name).unwrap_or(0);
        let user = state::handler(name).is_some();
        if !user && kernel.is_none() {
            continue;
        }
        targets[slot] = gateway_base + number as u64 * 10;
        pending.push((number, Binding { name: name.clone(), kernel, user }));
    }
    service_table::install(&targets, &stack_arguments)?;
    let providers = pending.len();
    BINDINGS.lock().extend(pending);
    *REGISTERED.lock() = Some(names.clone());
    state::with(|state| state.name_by_number.extend(names));
    crate::debug_print!("[services] table=0 slots={} providers={} unavailable={}", limit, providers, limit - providers);
    Ok(())
}

/// Lê a ntdll e registra os números das rotinas de syscall; os provedores
/// de usuário já foram registrados pelos módulos de `ps/user`.
pub fn initialize() -> Result<(), KernelError> {
    let (bytes, _) = loader::read_ntdll_input()?;
    register(&syscall_scan::scan_syscall_image(&bytes)?)
}

/// Sonda a pilha de usuário e copia `count` valores de 64 bits para depois
/// dos quatro registradores do destino.
pub fn copy_arguments(destination: u64, user_rsp: u64, count: u64) -> u32 {
    if count > 15 {
        return 0xC000_000D;
    }
    if count == 0 {
        return 0;
    }
    // O primeiro argumento de pilha fica depois do retorno e dos 32 bytes
    // reservados aos registradores.
    let first = user_rsp.wrapping_add(0x28);
    if user_rsp > i64::MAX as u64 || !state::probe_user_read(first, count * 8) {
        return 0xC000_0005;
    }
    // A pilha de usuário pode perder o mapeamento entre a sonda e a cópia:
    // a leitura sondada devolve STATUS_ACCESS_VIOLATION, como o SEH nativo.
    for index in 0..count {
        let Ok(value) = guest::try_read::<u64>(first + index * 8) else { return 0xC000_0005 };
        guest::write64(destination + (index + 4) * 8, value);
    }
    0
}

pub fn owns(id: u64) -> bool {
    (PRIVATE_SERVICE_BASE..PRIVATE_SERVICE_BASE + PRIVATE_SERVICE_COUNT).contains(&id)
}

/// Nome efetivamente despachado conforme o PreviousMode.
pub fn private_name(id: u64) -> Option<String> {
    if !owns(id) {
        return None;
    }
    let Some(binding) = BINDINGS.lock().get(&((id - PRIVATE_SERVICE_BASE) as u32)).cloned() else { return Some(String::from("UnavailableSystemService")) };
    Some(match binding.kernel {
        Some(kernel) if previous_mode::get().is_ok_and(|mode| mode == 0) => String::from(abi_names::EXPORT_NAMES[kernel]),
        _ => binding.name,
    })
}

/// Encaminha ao provedor do modo correto. O vetor bruto (registradores em
/// +8..+0x20, retorno em +0x78 e pilha em +0x80) e a pilha sondada ficam
/// visíveis à chamada de usuário e são restaurados ao final.
pub fn dispatch(id: u64, args: &[u64; 14], return_address: u64, frame: u64, context: u64) -> Result<u64, KernelError> {
    let Some(binding) = BINDINGS.lock().get(&((id - PRIVATE_SERVICE_BASE) as u32)).cloned() else { return Ok(0xC000_0002) };
    if previous_mode::get()? == 0 {
        let Some(kernel) = binding.kernel else { return Ok(0xC000_0002) };
        return exports::handle(32 + kernel as u64, args, return_address, frame, context);
    }
    if !binding.user {
        crate::debug_print!("[usermode] syscall {} sem implementacao de modo usuario", binding.name);
        return Ok(0xC000_0002);
    }
    let Some(invoker) = *USER_INVOKER.lock() else { return Ok(0xC000_0002) };
    let raw = guest::alloc_bytes(RawArguments::SIZE);
    if raw == 0 {
        return Ok(0xC000_009A);
    }
    // SAFETY: alocação nova do tamanho do bloco.
    let block = unsafe { RawArguments::at(raw) };
    block.service.set(id);
    for (cell, &value) in block.arguments.iter().zip(args) {
        cell.set(value);
    }
    block.return_address.set(return_address);
    block.stack_pointer.set(frame);
    // Os quatro registradores voltam com o sinal de 32 bits dos pseudo-handles.
    let values = core::array::from_fn(|index| {
        let value = block.arguments[index].get();
        if value >= 0xFFFF_FFFF_8000_0000 { value as i32 as i64 as u64 } else { value }
    });
    let stack_pointer = block.stack_pointer.get();
    // O retorno é o RIP do usuário salvo pela entrada de syscall, quando há.
    let service_frame = crate::hal::amd64::usermode::user_service_frame();
    // O quadro de serviço guarda o retorno do stub em +8.
    let return_address = if service_frame != 0 { guest::read64(service_frame + 8) } else { block.return_address.get() };
    // O registro é da thread que entrou no serviço; um serviço aninhado
    // devolve o de fora ao sair.
    let record = state::SyscallRecord { raw_arguments: raw, stack: Some(state::ServiceStack { rsp: stack_pointer, bytes: service_abi::stack_arguments(&binding.name).unwrap_or(0) as u64 * 8 }) };
    let result = state::with_syscall_record(record, || invoker(&binding.name, values, return_address, stack_pointer));
    guest::free_bytes(raw);
    result.map(|status| status as u64)
}
