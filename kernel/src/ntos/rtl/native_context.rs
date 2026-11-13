//! CONTEXT nativo do Windows x64 — `system32/ntos/rtl/native-context.js`.
//!
//! Liga o gateway nativo ao CONTEXT. Uma transferência de controle é
//! sinalizada durante o despacho (um `KernelError` marcado, propagado pelos
//! `?` como o sinal do original) e só se efetiva depois que os frames Rust
//! retornam ao trampolim. Os callbacks nativos rodam em contexto e pilha
//! próprios (`hal::amd64::win32_thunk::run_kernel_context`), com o despachante
//! registrado depois da montagem da tabela de exports.

use alloc::format;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::lapic;
use crate::hal::amd64::win32_thunk;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

/// O CONTEXT ocupa 0x4D0 bytes; a célula de ação pertence ao gateway e fica
/// fora da estrutura Windows (alocação completa de 0x4E0).
pub const SIZE: u64 = 0x4D0;
pub const ACTION: u64 = 0x4D0;
/// Status interno que marca o sinal de transferência (nunca um NTSTATUS
/// devolvido a um chamador).
const TRANSFER_STATUS: u32 = 0xFFFF_FFFF;

/// Despachante registrado: (id absoluto, 14 argumentos, retorno, frame,
/// CONTEXT) e a validação de ids públicos/privados.
#[derive(Clone, Copy)]
pub struct KernelProvider {
    pub handle: fn(u64, &[u64; 14], u64, u64, u64) -> Result<u64, KernelError>,
    pub valid: fn(u64) -> bool,
}

static PROVIDER: SpinLock<Option<KernelProvider>> = SpinLock::new(None);

/// Recusa uma segunda identidade diferente.
pub fn register_kernel_provider(provider: KernelProvider) -> Result<(), KernelError> {
    let mut current = PROVIDER.lock();
    if let Some(existing) = *current {
        if existing.handle as usize != provider.handle as usize || existing.valid as usize != provider.valid as usize {
            return Err(KernelError::new("native kernel dispatcher already registered"));
        }
    }
    *current = Some(provider);
    Ok(())
}

/// Despachante registrado (as threads de sistema despacham por ele).
pub fn provider() -> Option<KernelProvider> {
    *PROVIDER.lock()
}

/// Invocação ativa: contexto e identidade exclusiva do sinal, por CPU.
struct Invocation {
    cpu: u32,
    context: u64,
    signal: u64,
}

static INVOCATIONS: SpinLock<Vec<Invocation>> = SpinLock::new(Vec::new());
static NEXT_SIGNAL: AtomicU64 = AtomicU64::new(1);

fn current_cpu() -> u32 {
    lapic::read(0x20) >> 24
}

fn top_invocation() -> Option<(u64, u64)> {
    let cpu = current_cpu();
    INVOCATIONS.lock().iter().rev().find(|invocation| invocation.cpu == cpu).map(|invocation| (invocation.context, invocation.signal))
}

fn signal_error(signal: u64) -> KernelError {
    KernelError::with_status(format!("native context transfer #{signal}"), TRANSFER_STATUS)
}

/// Copia blocos de oito bytes (o padrão é o CONTEXT inteiro).
pub fn copy(destination: u64, source: u64, length: u64) {
    let mut offset = 0;
    while offset < length {
        guest::write64(destination + offset, guest::read64(source + offset));
        offset += 8;
    }
}

/// Empilha o contexto de uma chamada e sua identidade de transferência;
/// captura só o sinal dela e restaura a anterior em qualquer saída.
pub fn invoke<T: Default>(context: u64, body: impl FnOnce() -> Result<T, KernelError>) -> Result<T, KernelError> {
    let cpu = current_cpu();
    let signal = NEXT_SIGNAL.fetch_add(1, Ordering::Relaxed);
    INVOCATIONS.lock().push(Invocation { cpu, context, signal });
    let result = body();
    let mut invocations = INVOCATIONS.lock();
    if let Some(index) = invocations.iter().rposition(|invocation| invocation.signal == signal) {
        invocations.remove(index);
    }
    drop(invocations);
    match result {
        Err(error) if error.status == TRANSFER_STATUS && error.message == signal_error(signal).message => Ok(T::default()),
        other => other,
    }
}

/// Exige uma invocação ativa com CONTEXT; não fabrica um contexto.
pub fn current() -> Result<u64, KernelError> {
    match top_invocation() {
        Some((context, _)) if context != 0 => Ok(context),
        _ => Err(KernelError::new("native CONTEXT unavailable")),
    }
}

/// Copia o contexto desejado para o frame ativo, marca a ação e devolve o
/// sinal a propagar; o gateway observa a ação depois da limpeza das camadas.
pub fn transfer(context: u64) -> KernelError {
    let target = match current() {
        Ok(target) => target,
        Err(error) => return error,
    };
    copy(target, context, SIZE);
    guest::write32(target + ACTION, 1);
    signal_error(top_invocation().map_or(0, |(_, signal)| signal))
}

/// Reconhece só o sinal da invocação ativa (erros comuns não se confundem).
pub fn is_transfer(error: &KernelError) -> bool {
    error.status == TRANSFER_STATUS && top_invocation().is_some_and(|(_, signal)| error.message == signal_error(signal).message)
}

/// Zera o frame estendido e converte registradores, segmentos, flags,
/// depuração e estado FX do formato da CPU para os offsets do CONTEXT.
pub fn from_cpu(destination: u64, processor: u64) {
    let mut offset = 0;
    while offset < 0x4E0 {
        guest::write64(destination + offset, 0);
        offset += 8;
    }
    guest::write32(destination + 0x30, 0x10_001B);
    guest::write32(destination + 0x34, guest::read32(processor + 0x118));
    for segment in (0..12).step_by(2) {
        guest::write16(destination + 0x38 + segment, guest::read16(processor + 0x90 + segment));
    }
    guest::write32(destination + 0x44, guest::read64(processor + 0x88) as u32);
    copy(destination + 0x78, processor, 128);
    guest::write64(destination + 0xF8, guest::read64(processor + 0x80));
    copy(destination + 0x48, processor + 0xA0, 48);
    copy(destination + 0x100, processor + 0x100, 512);
}

/// Aplica inteiros, RIP, flags, depuração e FX ao formato da CPU; os campos
/// não copiados conservam o valor do frame de destino.
pub fn to_cpu(processor: u64, source: u64) {
    copy(processor, source + 0x78, 128);
    guest::write64(processor + 0x80, guest::read64(source + 0xF8));
    guest::write64(processor + 0x88, guest::read32(source + 0x44) as u64);
    copy(processor + 0xA0, source + 0x48, 48);
    copy(processor + 0x100, source + 0x100, 512);
}

const ARGUMENT_REGISTERS: [u64; 4] = [8, 16, 0x40, 0x48];

/// Captura os 14 argumentos, cria um CONTEXT temporário e chama o provedor;
/// aplica a transferência pedida ou grava o retorno em RAX. O frame bruto
/// usa id em +0, argumentos em +8..+112, RIP em +120 e RSP anterior em +128.
pub fn dispatch_cpu(processor: u64, id: u64, provider: KernelProvider) -> Result<u64, KernelError> {
    let raw = processor + 0x300;
    let stack = guest::read64(processor + 0x20);
    guest::write64(raw, id - 32);
    let mut arguments = [0u64; 14];
    for (index, slot) in arguments.iter_mut().enumerate() {
        let value = guest::read64(if index < 4 { processor + ARGUMENT_REGISTERS[index] } else { stack + 32 + (index as u64 - 4) * 8 });
        guest::write64(raw + (index as u64 + 1) * 8, value);
        *slot = value;
    }
    let return_address = guest::read64(processor + 0x80);
    guest::write64(raw + 120, return_address);
    guest::write64(raw + 128, stack - 8);
    let context = guest::alloc_bytes(0x4E0);
    if context == 0 {
        return Err(KernelError::new("native dispatch CONTEXT allocation failed"));
    }
    from_cpu(context, processor);
    let result = (provider.handle)(id, &arguments, return_address, stack - 8, context);
    if let Ok(value) = result {
        if guest::read32(context + ACTION) != 0 {
            to_cpu(processor, context);
        } else {
            guest::write64(processor, value);
        }
    }
    guest::free_bytes(context);
    result
}

/// Executa um handler ou funclet em contexto e pilha (64 KiB) próprios. Cada
/// saída para uma API passa pelo despachante e pode pedir transferência sem
/// saltar sobre frames Rust ativos.
pub fn call(handler: u64, arguments: &[u64], source_context: u64) -> Result<u64, KernelError> {
    let processor = guest::alloc_bytes(0x400);
    if processor == 0 {
        return Err(KernelError::new("native callback CONTEXT allocation failed"));
    }
    let stack = guest::alloc_bytes(0x10000);
    let result = (|| {
        if stack == 0 {
            return Err(KernelError::new("native callback stack allocation failed"));
        }
        if source_context != 0 {
            to_cpu(processor, source_context);
        } else {
            win32_thunk::init_kernel_context_fx(processor);
            guest::write64(processor + 0x88, 0x202);
        }
        // Retorno, shadow space e argumentos; entrada alinhada como na ABI MS x64.
        let stack_pointer = stack + 0x10000 - 0x98;
        if arguments.len() > 14 {
            return Err(KernelError::new("native callback argument count"));
        }
        guest::write64(processor + 0x20, stack_pointer);
        guest::write64(processor + 0x80, handler);
        // Flags de origem sem TF, RF e VM.
        guest::write64(processor + 0x88, guest::read64(processor + 0x88) & !0x10500);
        guest::write64(stack_pointer, win32_thunk::kernel_thread_return());
        for (index, &value) in arguments.iter().enumerate() {
            guest::write64(if index < 4 { processor + ARGUMENT_REGISTERS[index] } else { stack_pointer + 40 + (index as u64 - 4) * 8 }, value);
        }
        // Só a tabela registrada; nenhum resolvedor alternativo.
        let provider = (*PROVIDER.lock()).ok_or_else(|| KernelError::new("native kernel dispatcher unavailable"))?;
        loop {
            let id = win32_thunk::run_kernel_context(processor) as u64;
            // A saída terminal devolve o resultado preservado em R10.
            if id == 0xFFFF_FFFF {
                return Ok(guest::read64(processor + 0x50));
            }
            if id < 32 || !(provider.valid)(id) {
                return Err(KernelError::new(format!("invalid native handler API {id}")));
            }
            dispatch_cpu(processor, id, provider)?;
        }
    })();
    if stack != 0 {
        guest::free_bytes(stack);
    }
    guest::free_bytes(processor);
    result
}

/// Tamanho do CONTEXT x64 do Windows e ContextFlags de CONTEXT_FULL.
const CONTEXT_SIZE: u64 = 0x4D0;
const CONTEXT_FULL: u32 = 0x0010_000B;

/// RtlCaptureContext: copia o CONTEXT nativo ativo (o estado do chamador no
/// gateway, isto é, logo após o `call` ao export) para o buffer do
/// convidado e fixa ContextFlags = CONTEXT_FULL, como o ntoskrnl.
pub fn capture_context(target: u64) {
    if target != 0 {
        if let Ok(source) = current() {
            copy(target, source, CONTEXT_SIZE);
        }
        guest::write32(target + 0x30, CONTEXT_FULL);
    }
}
