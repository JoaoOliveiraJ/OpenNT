//! CONTEXT nativo do Windows x64.
//!
//! Liga o gateway nativo ao CONTEXT. Uma transferência de controle é
//! sinalizada durante o despacho (um `KernelError` marcado, propagado pelos
//! `?`) e só se efetiva depois que os frames Rust retornam ao trampolim. Os
//! callbacks nativos rodam em contexto e pilha próprios
//! (`hal::amd64::win32_thunk::run_kernel_context`), com o despachante
//! registrado depois da montagem da tabela de exports.

use alloc::format;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use core::mem::{offset_of, size_of};

use crate::hal::amd64::win32_thunk;
use crate::hal::lapic;
use crate::ntos::inc::types::{Context, Field, NtStruct, XsaveFormat};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::{KernelError, SpinLock};

/// O CONTEXT ocupa 0x4D0 bytes; a célula de ação pertence ao gateway e fica
/// fora da estrutura Windows (alocação completa de 0x4E0).
pub const SIZE: u64 = Context::SIZE;
pub const ACTION: u64 = Context::SIZE;
/// CONTEXT + célula de ação.
const GATEWAY_CONTEXT_BYTES: u64 = Context::SIZE + 0x10;

/// O quadro de CPU do `win32_thunk` (formato do OpenNT, não do NT): os 16
/// inteiros na ordem do x64, RIP, RFLAGS, seletores, depuração, a área FX e o
/// quadro bruto da chamada interceptada.
#[repr(C)]
struct CpuFrame {
    registers: [Field<u64>; 16],
    rip: Field<u64>,
    rflags: Field<u64>,
    /// CS, DS, ES, FS, GS, SS (a ordem dos SegXx do CONTEXT).
    segments: [Field<u16>; 6],
    _pad_9c: [Field<u32>; 1],
    /// Dr0..Dr3, Dr6, Dr7 (a ordem do CONTEXT).
    debug: [Field<u64>; 6],
    _pad_d0: [Field<u64>; 6],
    fx: XsaveFormat,
    /// Quadro bruto: id em +0, argumentos em +8..+112, RIP em +120 e RSP
    /// anterior em +128.
    raw: [Field<u64>; 17],
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for CpuFrame {}

const _: () = {
    assert!(offset_of!(CpuFrame, rip) == 0x80);
    assert!(offset_of!(CpuFrame, rflags) == 0x88);
    assert!(offset_of!(CpuFrame, segments) == 0x90);
    assert!(offset_of!(CpuFrame, debug) == 0xA0);
    assert!(offset_of!(CpuFrame, fx) == 0x100);
    assert!(offset_of!(CpuFrame, raw) == 0x300);
    assert!(size_of::<CpuFrame>() <= 0x400);
};

/// RSP, R10 e os quatro registradores de argumento (RCX, RDX, R8, R9).
const RSP: usize = 4;
const R10: usize = 10;
const ARGUMENT_REGISTERS: [usize; 4] = [1, 2, 8, 9];

fn frame_at(processor: u64) -> &'static CpuFrame {
    // SAFETY: quadro de CPU alocado pelo gateway (0x400 bytes, alinhado).
    unsafe { CpuFrame::at(processor) }
}

fn context_at(context: u64) -> &'static Context {
    // SAFETY: CONTEXT vivo e alinhado (do chamador ou alocado pelo gateway).
    unsafe { Context::at(context) }
}

/// Inteiros Rax..R15 do CONTEXT, na ordem dos números de registrador.
fn integer_registers(context: &Context) -> &'static [Field<u64>] {
    // SAFETY: os 16 inteiros são campos consecutivos do CONTEXT, a partir de Rax.
    unsafe { Field::<u64>::array_at(context.rax.address(), 16) }
}

/// Dr0..Dr3, Dr6, Dr7 do CONTEXT (campos consecutivos).
fn debug_registers(context: &Context) -> &'static [Field<u64>] {
    // SAFETY: os 6 registradores de depuração são consecutivos no CONTEXT.
    unsafe { Field::<u64>::array_at(context.dr0.address(), 6) }
}

/// SegCs..SegSs do CONTEXT (campos consecutivos).
fn segment_registers(context: &Context) -> &'static [Field<u16>] {
    // SAFETY: os 6 seletores são consecutivos no CONTEXT.
    unsafe { Field::<u16>::array_at(context.seg_cs.address(), 6) }
}

/// A célula de ação do gateway, logo depois do CONTEXT.
fn action(context: u64) -> &'static Field<u32> {
    // SAFETY: os CONTEXTs do gateway são alocados com a célula (0x4E0 bytes).
    unsafe { Field::<u32>::at(context + ACTION) }
}
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

/// Copia um bloco (o padrão é o CONTEXT inteiro).
pub fn copy(destination: u64, source: u64, length: u64) {
    guest::write_bytes(destination, &guest::read_bytes(source, length as usize));
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
    action(target).set(1);
    signal_error(top_invocation().map_or(0, |(_, signal)| signal))
}

/// Reconhece só o sinal da invocação ativa (erros comuns não se confundem).
pub fn is_transfer(error: &KernelError) -> bool {
    error.status == TRANSFER_STATUS && top_invocation().is_some_and(|(_, signal)| error.message == signal_error(signal).message)
}

/// Zera o frame estendido e converte registradores, segmentos, flags,
/// depuração e estado FX do formato da CPU para os offsets do CONTEXT.
pub fn from_cpu(destination: u64, processor: u64) {
    guest::write_bytes(destination, &[0; GATEWAY_CONTEXT_BYTES as usize]);
    let (context, frame) = (context_at(destination), frame_at(processor));
    context.context_flags.set(0x10_001B);
    context.mx_csr.set(frame.fx.mx_csr.get());
    for (target, source) in segment_registers(context).iter().zip(&frame.segments) {
        target.set(source.get());
    }
    context.e_flags.set(frame.rflags.get() as u32);
    for (target, source) in integer_registers(context).iter().zip(&frame.registers) {
        target.set(source.get());
    }
    context.rip.set(frame.rip.get());
    for (target, source) in debug_registers(context).iter().zip(&frame.debug) {
        target.set(source.get());
    }
    copy(context.flt_save.address(), frame.fx.address(), XsaveFormat::SIZE);
}

/// Aplica inteiros, RIP, flags, depuração e FX ao formato da CPU; os campos
/// não copiados conservam o valor do frame de destino.
pub fn to_cpu(processor: u64, source: u64) {
    let (frame, context) = (frame_at(processor), context_at(source));
    for (target, source) in frame.registers.iter().zip(integer_registers(context)) {
        target.set(source.get());
    }
    frame.rip.set(context.rip.get());
    frame.rflags.set(context.e_flags.get() as u64);
    for (target, source) in frame.debug.iter().zip(debug_registers(context)) {
        target.set(source.get());
    }
    copy(frame.fx.address(), context.flt_save.address(), XsaveFormat::SIZE);
}

/// Captura os 14 argumentos, cria um CONTEXT temporário e chama o provedor;
/// aplica a transferência pedida ou grava o retorno em RAX. O frame bruto
/// usa id em +0, argumentos em +8..+112, RIP em +120 e RSP anterior em +128.
pub fn dispatch_cpu(processor: u64, id: u64, provider: KernelProvider) -> Result<u64, KernelError> {
    let frame = frame_at(processor);
    let stack = frame.registers[RSP].get();
    frame.raw[0].set(id - 32);
    let mut arguments = [0u64; 14];
    for (index, slot) in arguments.iter_mut().enumerate() {
        // Quatro em registradores; o resto na pilha, depois do shadow space.
        let value = if index < 4 { frame.registers[ARGUMENT_REGISTERS[index]].get() } else { guest::read64(stack + 32 + (index as u64 - 4) * 8) };
        frame.raw[index + 1].set(value);
        *slot = value;
    }
    let return_address = frame.rip.get();
    frame.raw[15].set(return_address);
    frame.raw[16].set(stack - 8);
    let context = guest::alloc_bytes(GATEWAY_CONTEXT_BYTES);
    if context == 0 {
        return Err(KernelError::new("native dispatch CONTEXT allocation failed"));
    }
    from_cpu(context, processor);
    let result = (provider.handle)(id, &arguments, return_address, stack - 8, context);
    if let Ok(value) = result {
        if action(context).get() != 0 {
            to_cpu(processor, context);
        } else {
            frame.registers[0].set(value);
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
        let frame = frame_at(processor);
        if source_context != 0 {
            to_cpu(processor, source_context);
        } else {
            win32_thunk::init_kernel_context_fx(processor);
            frame.rflags.set(0x202);
        }
        // Retorno, shadow space e argumentos; entrada alinhada como na ABI MS x64.
        let stack_pointer = stack + 0x10000 - 0x98;
        if arguments.len() > 14 {
            return Err(KernelError::new("native callback argument count"));
        }
        frame.registers[RSP].set(stack_pointer);
        frame.rip.set(handler);
        // Flags de origem sem TF, RF e VM.
        frame.rflags.set(frame.rflags.get() & !0x10500);
        guest::write64(stack_pointer, win32_thunk::kernel_thread_return());
        for (index, &value) in arguments.iter().enumerate() {
            if index < 4 {
                frame.registers[ARGUMENT_REGISTERS[index]].set(value);
            } else {
                guest::write64(stack_pointer + 40 + (index as u64 - 4) * 8, value);
            }
        }
        // Só a tabela registrada; nenhum resolvedor alternativo.
        let provider = (*PROVIDER.lock()).ok_or_else(|| KernelError::new("native kernel dispatcher unavailable"))?;
        loop {
            let id = win32_thunk::run_kernel_context(processor) as u64;
            // A saída terminal devolve o resultado preservado em R10.
            if id == 0xFFFF_FFFF {
                return Ok(frame.registers[R10].get());
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

/// ContextFlags de CONTEXT_FULL.
const CONTEXT_FULL: u32 = 0x0010_000B;

/// RtlCaptureContext: copia o CONTEXT nativo ativo (o estado do chamador no
/// gateway, isto é, logo após o `call` ao export) para o buffer do
/// convidado e fixa ContextFlags = CONTEXT_FULL, como o ntoskrnl.
pub fn capture_context(target: u64) {
    if target != 0 {
        if let Ok(source) = current() {
            copy(target, source, Context::SIZE);
        }
        context_at(target).context_flags.set(CONTEXT_FULL);
    }
}
