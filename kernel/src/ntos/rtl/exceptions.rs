//! Despacho e desenrolamento de exceções AMD64 — `system32/ntos/rtl/exceptions.js`.
//!
//! Pesquisa handlers e executa o desenrolamento; os handlers nativos rodam
//! em contexto próprio e a transferência de pilha/contexto só ocorre depois
//! que os frames Rust retornam ao trampolim (sinal de `native_context`). Um
//! pedido de unwind feito de dentro de um handler (RtlUnwindEx, filtro do
//! __C_specific_handler) sobe como um erro marcado até o despachante.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use super::native_context;
use super::unwind;
use crate::hal::amd64::win32_thunk;
use crate::ntos::ke::irql;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ke::bugcheck as ke;

const UNWINDING: u32 = 2;
const EXIT_UNWIND: u32 = 4;
const TARGET_UNWIND: u32 = 0x20;
/// Status do erro marcado que transporta um pedido de unwind.
const UNWIND_STATUS: u32 = 0xFFFF_FFFE;

/// Frame alvo, RIP destino, registro e valor de retorno.
#[derive(Clone, Copy, Debug)]
struct UnwindRequest {
    frame: u64,
    ip: u64,
    record: u64,
    value: u64,
}

static PENDING_UNWIND: SpinLock<Option<UnwindRequest>> = SpinLock::new(None);
/// Invocações de handler em curso: (registro, DISPATCHER_CONTEXT).
static HANDLER_INVOCATIONS: SpinLock<Vec<(u64, u64)>> = SpinLock::new(Vec::new());
/// Até 16 entregas aninhadas.
static NESTING: AtomicU32 = AtomicU32::new(0);

fn unwind_signal(request: UnwindRequest) -> KernelError {
    *PENDING_UNWIND.lock() = Some(request);
    KernelError::with_status("kernel unwind request", UNWIND_STATUS)
}

fn is_unwind(error: &KernelError) -> bool {
    error.status == UNWIND_STATUS
}

fn take_unwind(error: &KernelError) -> Option<UnwindRequest> {
    if is_unwind(error) {
        PENDING_UNWIND.lock().take()
    } else {
        None
    }
}

/// Memória do despacho liberada em toda saída, inclusive sinais.
fn with_workspace<T>(length: u64, operation: impl FnOnce(u64) -> Result<T, KernelError>) -> Result<T, KernelError> {
    let workspace = guest::alloc_bytes(length);
    if workspace == 0 {
        return Err(KernelError::new("kernel SEH workspace allocation failed"));
    }
    let result = operation(workspace);
    guest::free_bytes(workspace);
    result
}

/// Exceção não tratada: KMODE_EXCEPTION_NOT_HANDLED pelo KeBugCheckEx real.
fn stop_for_unhandled_exception(record: u64, context: u64, message: &str) -> ! {
    debug_print!("[kernel-seh] {} code=0x{:x} pc=0x{:x}", message, guest::read32(record), guest::read64(context + 0xF8));
    ke::raise_bug_check(0x1E, guest::read32(record) as u64, guest::read64(record + 0x10), 0, 0)
}

#[allow(clippy::too_many_arguments)]
fn write_dispatcher_context(dispatcher: u64, ip: u64, base: u64, entry: u64, frame: u64, target: u64, context: u64, handler: u64, data: u64) {
    for (offset, value) in [(0u64, ip), (8, base), (16, entry), (24, frame), (32, target), (40, context), (48, handler), (56, data), (64, 0), (72, 0)] {
        guest::write64(dispatcher + offset, value);
    }
}

/// Reconstrói o chamador por metadados ou retorno de folha; para no limite
/// com frames sem tabelas e recusa pilha que não avança ou frame inválido.
fn unwind_one_frame(walking: u64, frame_context: u64, dispatcher: u64, output: u64, handler_type: u32, target: u64) -> Result<Option<(u64, u64)>, KernelError> {
    native_context::copy(frame_context, walking, native_context::SIZE);
    let ip = guest::read64(walking + 0xF8);
    let sp = guest::read64(walking + 0x98);
    if ip == 0 || ip == win32_thunk::kernel_thread_return() {
        return Ok(None);
    }
    let (base, entry) = unwind::lookup(ip)?;
    if base == 0 && entry.is_none() {
        // Folha da ABI x64: o retorno está em [RSP]; o chamador precisa de
        // metadados próprios (fronteira com frames sem tabelas NT).
        if unwind::lookup(guest::read64(sp))?.1.is_none() {
            return Ok(None);
        }
    }
    let mut handler = 0;
    let mut frame = sp;
    let mut data = 0;
    if let Some(entry) = entry {
        handler = unwind::unwind(handler_type, entry.base, ip, entry.address, walking, output, output + 8, 0)?;
        frame = guest::read64(output + 8);
        if handler != 0 {
            data = guest::read64(output);
        }
    } else {
        guest::write64(walking + 0xF8, guest::read64(sp));
        guest::write64(walking + 0x98, sp + 8);
    }
    let caller_sp = guest::read64(walking + 0x98);
    if caller_sp <= sp || frame < sp || frame & 7 != 0 {
        return Err(KernelError::new("invalid kernel exception stack frame"));
    }
    write_dispatcher_context(dispatcher, ip, entry.map_or(base, |entry| entry.base), entry.map_or(0, |entry| entry.address), frame, target, frame_context, handler, data);
    Ok(Some((frame, handler)))
}

/// Executa o handler (registro, frame, CONTEXT original, dispatcher); a
/// disposição é um inteiro de 32 bits com sinal.
fn invoke_handler(record: u64, frame: u64, original: u64, dispatcher: u64, frame_context: u64) -> Result<i32, KernelError> {
    HANDLER_INVOCATIONS.lock().push((record, dispatcher));
    let result = native_context::call(guest::read64(dispatcher + 48), &[record, frame, original, dispatcher], frame_context);
    HANDLER_INVOCATIONS.lock().pop();
    result.map(|value| value as i32)
}

/// Até 1024 frames com os handlers de término; no alvo, transfere o
/// contexto do próprio frame de destino. As flags do registro voltam ao fim.
fn unwind_to_target(request: UnwindRequest, source: u64, exception_context: u64, output_context: u64) -> Result<u64, KernelError> {
    with_workspace(0xB00, |workspace| {
        let walking = workspace;
        let frame_context = workspace + 0x500;
        let dispatcher = workspace + 0xA00;
        let output = workspace + 0xA80;
        native_context::copy(walking, source, native_context::SIZE);
        let saved_flags = guest::read32(request.record + 4);
        let result = (|| -> Result<u64, KernelError> {
            for _ in 0..1024 {
                let Some((frame, handler)) = unwind_one_frame(walking, frame_context, dispatcher, output, 2, request.ip)? else { break };
                if request.frame != 0 && frame > request.frame {
                    return Err(KernelError::new("kernel unwind target not on stack"));
                }
                let is_target = frame == request.frame;
                guest::write32(request.record + 4, saved_flags | UNWINDING | if request.frame == 0 { EXIT_UNWIND } else { 0 } | if is_target { TARGET_UNWIND } else { 0 });
                if handler != 0 {
                    let disposition = invoke_handler(request.record, frame, exception_context, dispatcher, frame_context)?;
                    if disposition != 1 {
                        return Err(KernelError::new(alloc::format!("unsupported kernel unwind disposition {disposition}")));
                    }
                }
                // O alvo conserva seus registradores; RSP, RIP e RAX vêm do pedido.
                if is_target {
                    guest::write64(frame_context + 0x98, frame);
                    guest::write64(frame_context + 0xF8, request.ip);
                    guest::write64(frame_context + 0x78, request.value);
                    if output_context != 0 {
                        native_context::copy(output_context, frame_context, native_context::SIZE);
                    }
                    return Err(native_context::transfer(frame_context));
                }
            }
            stop_for_unhandled_exception(request.record, source, "unwind target unavailable")
        })();
        guest::write32(request.record + 4, saved_flags);
        result
    })
}

/// Busca de handler: ContinueExecution transfere quando permitido; pedidos
/// de unwind entram na fase de término.
fn search_exception_handlers(record: u64, context: u64, maximum_irql: u8) -> Result<u64, KernelError> {
    with_workspace(0xB00, |workspace| {
        let walking = workspace;
        let frame_context = workspace + 0x500;
        let dispatcher = workspace + 0xA00;
        let output = workspace + 0xA80;
        native_context::copy(walking, context, native_context::SIZE);
        for _ in 0..1024 {
            let Some((frame, handler)) = unwind_one_frame(walking, frame_context, dispatcher, output, 1, 0)? else { break };
            if handler == 0 {
                continue;
            }
            let disposition = match invoke_handler(record, frame, context, dispatcher, frame_context) {
                Ok(disposition) => disposition,
                Err(error) => match take_unwind(&error) {
                    Some(request) => return unwind_to_target(request, context, context, 0),
                    None => return Err(error),
                },
            };
            if disposition == 0 {
                // Continuar uma exceção não continuável cria uma nova encadeada.
                if guest::read32(record + 4) & 1 != 0 {
                    return raise_status(0xC000_0025, record, context, maximum_irql);
                }
                return Err(native_context::transfer(context));
            }
            if disposition != 1 {
                return Err(KernelError::new(alloc::format!("unsupported kernel search disposition {disposition}")));
            }
        }
        stop_for_unhandled_exception(record, context, "unhandled software exception")
    })
}

/// Sinais de transferência e pedidos de unwind propagam; qualquer outra
/// falha para o sistema (a API não tem retorno comum).
fn run_nonreturning_operation(operation: impl FnOnce() -> Result<u64, KernelError>, status: u32) -> Result<u64, KernelError> {
    match operation() {
        Err(error) if !native_context::is_transfer(&error) && !is_unwind(&error) => {
            debug_print!("[kernel-seh] fatal dispatcher failure: {}", error);
            ke::raise_bug_check(0x1E, status as u64, 0, 0, 0)
        }
        other => other,
    }
}

/// ExRaiseStatus/RtlRaiseStatus.
pub fn raise_status(status: u32, linked: u64, source: u64, maximum_irql: u8) -> Result<u64, KernelError> {
    run_nonreturning_operation(|| raise_status_core(status, linked, source, maximum_irql), status)
}

/// EXCEPTION_RECORD não continuável, CONTEXT de origem, IRQL e limite de
/// recursão validados antes da busca.
fn raise_status_core(status: u32, linked: u64, source: u64, maximum_irql: u8) -> Result<u64, KernelError> {
    with_workspace(0x600, |workspace| {
        let context = workspace + 0x100;
        let source = if source != 0 { source } else { native_context::current()? };
        native_context::copy(context, source, native_context::SIZE);
        for offset in (0..0x98).step_by(8) {
            guest::write64(workspace + offset, 0);
        }
        guest::write32(workspace, status);
        guest::write32(workspace + 4, 1);
        guest::write64(workspace + 8, linked);
        guest::write64(workspace + 0x10, guest::read64(context + 0xF8));
        if irql::get_irql() > maximum_irql {
            stop_for_unhandled_exception(workspace, context, "software exception at invalid IRQL");
        }
        if NESTING.load(Ordering::Acquire) >= 16 {
            stop_for_unhandled_exception(workspace, context, "recursive noncontinuable exception");
        }
        NESTING.fetch_add(1, Ordering::AcqRel);
        let result = search_exception_handlers(workspace, context, maximum_irql);
        NESTING.fetch_sub(1, Ordering::AcqRel);
        match result {
            Err(error) if !native_context::is_transfer(&error) => {
                let message = if is_unwind(&error) { alloc::string::String::from("nested unwind request") } else { error.message.clone() };
                stop_for_unhandled_exception(workspace, context, &alloc::format!("exception dispatch failed: {message}"))
            }
            other => other,
        }
    })
}

/// RtlUnwindEx (a tabela de histórico não é usada).
pub fn unwind_ex(frame: u64, target: u64, record: u64, value: u64, context: u64, _history: u64) -> Result<u64, KernelError> {
    run_nonreturning_operation(|| unwind_ex_core(frame, target, record, value, context), 0xC000_0027)
}

/// De dentro do handler corrente o pedido sobe ao despachante; fora dele o
/// contexto é copiado e um registro temporário é criado se preciso.
fn unwind_ex_core(frame: u64, target: u64, record: u64, value: u64, context: u64) -> Result<u64, KernelError> {
    let mut request = UnwindRequest { frame, ip: target, record, value };
    if HANDLER_INVOCATIONS.lock().last().is_some_and(|(current, _)| *current == record) {
        return Err(unwind_signal(request));
    }
    with_workspace(0x600, |workspace| {
        let source = workspace + 0x100;
        native_context::copy(source, native_context::current()?, native_context::SIZE);
        if context != 0 {
            native_context::copy(context, source, native_context::SIZE);
        }
        if record == 0 {
            for offset in (0..0x98).step_by(8) {
                guest::write64(workspace + offset, 0);
            }
            guest::write32(workspace, 0xC000_0027);
            guest::write64(workspace + 0x10, guest::read64(source + 0xF8));
            request.record = workspace;
        }
        unwind_to_target(request, source, source, context)
    })
}

/// __C_specific_handler: a tabela de escopos escolhe filtros ou
/// finalizadores pelo RIP, flags e destino.
pub fn specific_handler(record: u64, frame: u64, context: u64, dispatcher: u64) -> Result<u64, KernelError> {
    let image_base = guest::read64(dispatcher + 8);
    let scope_table = guest::read64(dispatcher + 56);
    let instruction = guest::read64(dispatcher).wrapping_sub(image_base);
    let target = guest::read64(dispatcher + 32).wrapping_sub(image_base);
    let count = guest::read32(scope_table);
    let flags = guest::read32(record + 4);
    if count > 0x10_0000 {
        return Err(KernelError::new("invalid kernel scope count"));
    }
    // Registros de 16 bytes: início, fim, handler e salto (RVAs).
    let scopes: Vec<(u64, u64, u32, u32)> = (0..count as u64)
        .map(|index| {
            let at = scope_table + 4 + index * 16;
            (guest::read32(at) as u64, guest::read32(at + 4) as u64, guest::read32(at + 8), guest::read32(at + 12))
        })
        .collect();
    let mut index = guest::read32(dispatcher + 72) as usize;
    while index < count as usize {
        let (begin, end, handler, jump) = scopes[index];
        if instruction < begin || instruction >= end {
            index += 1;
            continue;
        }
        if flags & 0x66 != 0 {
            // Escopo que também contém o destino com o mesmo handler/salto não é encerrado.
            if flags & TARGET_UNWIND != 0 && scopes.iter().any(|candidate| target >= candidate.0 && target < candidate.1 && candidate.2 == handler && candidate.3 == jump) {
                return Ok(1);
            }
            if jump != 0 && target == jump as u64 {
                return Ok(1);
            }
            if jump == 0 {
                // O próximo ScopeIndex é publicado antes do finalizador (reentrada).
                guest::write32(dispatcher + 72, index as u32 + 1);
                native_context::call(image_base + handler as u64, &[1, frame], guest::read64(dispatcher + 40))?;
            }
        } else if jump != 0 {
            // Filtro: negativo continua a execução, zero continua a busca,
            // positivo pede transferência ao bloco de tratamento.
            let filter = if handler == 1 {
                1
            } else {
                with_workspace(16, |pointers| {
                    guest::write64(pointers, record);
                    guest::write64(pointers + 8, context);
                    Ok(native_context::call(image_base + handler as u64, &[pointers, frame], guest::read64(dispatcher + 40))? as i32)
                })?
            };
            if filter < 0 {
                return Ok(0);
            }
            if filter > 0 {
                return Err(unwind_signal(UnwindRequest { frame, ip: image_base + jump as u64, record, value: guest::read32(record) as i32 as i64 as u64 }));
            }
        }
        index += 1;
    }
    Ok(1)
}

/// Entrega um registro existente no IRQL corrente (exceções de hardware).
pub fn dispatch_exception(record: u64, context: u64) -> Result<u64, KernelError> {
    run_nonreturning_operation(
        || {
            if NESTING.load(Ordering::Acquire) >= 16 {
                stop_for_unhandled_exception(record, context, "recursive hardware exception");
            }
            NESTING.fetch_add(1, Ordering::AcqRel);
            let result = search_exception_handlers(record, context, irql::get_irql());
            NESTING.fetch_sub(1, Ordering::AcqRel);
            result
        },
        guest::read32(record),
    )
}
