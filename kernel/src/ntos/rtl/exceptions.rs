//! Despacho e desenrolamento de exceções AMD64.
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
use crate::ntos::inc::types::{Context, DispatcherContext, ExceptionPointers, ExceptionRecord, NtStruct, ScopeTableAmd64, ScopeTableAmd64ScopeRecord};
use crate::ntos::ke::bugcheck as ke;
use crate::ntos::ke::irql;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::{KernelError, SpinLock};

/// EXCEPTION_NONCONTINUABLE.
const NONCONTINUABLE: u32 = 1;
/// STATUS_UNWIND.
const STATUS_UNWIND: u32 = 0xC000_0027;

// SAFETY (conversões deste arquivo): registros, CONTEXTs e DISPATCHER_CONTEXT
// vivos e alinhados — do chamador, do despachante de hardware ou montados
// pelo próprio despacho num bloco de trabalho alocado (layout do NT, pois
// vão para handlers reais).
fn record_at(record: u64) -> &'static ExceptionRecord {
    unsafe { ExceptionRecord::at(record) }
}
fn context_at(context: u64) -> &'static Context {
    unsafe { Context::at(context) }
}
fn dispatcher_at(dispatcher: u64) -> &'static DispatcherContext {
    unsafe { DispatcherContext::at(dispatcher) }
}

/// EXCEPTION_RECORD não continuável montado pelo despacho, zerado antes.
fn build_record(record: u64, status: u32, flags: u32, linked: u64, address: u64) {
    guest::write_bytes(record, &[0; core::mem::size_of::<ExceptionRecord>()]);
    let record = record_at(record);
    record.exception_code.set(status as i32);
    record.exception_flags.set(flags);
    record.exception_record.set(linked);
    record.exception_address.set(address);
}

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
    let (exception, frame) = (record_at(record), context_at(context));
    let code = exception.exception_code.get() as u32;
    debug_print!("[kernel-seh] {} code=0x{:x} pc=0x{:x}", message, code, frame.rip.get());
    ke::raise_bug_check(0x1E, code as u64, exception.exception_address.get(), 0, 0)
}

#[allow(clippy::too_many_arguments)]
fn write_dispatcher_context(dispatcher: u64, ip: u64, base: u64, entry: u64, frame: u64, target: u64, context: u64, handler: u64, data: u64) {
    let dispatcher = dispatcher_at(dispatcher);
    dispatcher.control_pc.set(ip);
    dispatcher.image_base.set(base);
    dispatcher.function_entry.set(entry);
    dispatcher.establisher_frame.set(frame);
    dispatcher.target_ip.set(target);
    dispatcher.context_record.set(context);
    dispatcher.language_handler.set(handler);
    dispatcher.handler_data.set(data);
    dispatcher.history_table.set(0);
    dispatcher.scope_index.set(0);
    dispatcher.fill0.set(0);
}

/// Reconstrói o chamador por metadados ou retorno de folha; para no limite
/// com frames sem tabelas e recusa pilha que não avança ou frame inválido.
fn unwind_one_frame(walking: u64, frame_context: u64, dispatcher: u64, output: u64, handler_type: u32, target: u64) -> Result<Option<(u64, u64)>, KernelError> {
    native_context::copy(frame_context, walking, native_context::SIZE);
    let walking_context = context_at(walking);
    let ip = walking_context.rip.get();
    let sp = walking_context.rsp.get();
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
        walking_context.rip.set(guest::read64(sp));
        walking_context.rsp.set(sp + 8);
    }
    let caller_sp = walking_context.rsp.get();
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
    let result = native_context::call(dispatcher_at(dispatcher).language_handler.get(), &[record, frame, original, dispatcher], frame_context);
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
        let record = record_at(request.record);
        let saved_flags = record.exception_flags.get();
        let result = (|| -> Result<u64, KernelError> {
            for _ in 0..1024 {
                let Some((frame, handler)) = unwind_one_frame(walking, frame_context, dispatcher, output, 2, request.ip)? else { break };
                if request.frame != 0 && frame > request.frame {
                    return Err(KernelError::new("kernel unwind target not on stack"));
                }
                let is_target = frame == request.frame;
                record.exception_flags.set(saved_flags | UNWINDING | if request.frame == 0 { EXIT_UNWIND } else { 0 } | if is_target { TARGET_UNWIND } else { 0 });
                if handler != 0 {
                    let disposition = invoke_handler(request.record, frame, exception_context, dispatcher, frame_context)?;
                    if disposition != 1 {
                        return Err(KernelError::new(alloc::format!("unsupported kernel unwind disposition {disposition}")));
                    }
                }
                // O alvo conserva seus registradores; RSP, RIP e RAX vêm do pedido.
                if is_target {
                    let target = context_at(frame_context);
                    target.rsp.set(frame);
                    target.rip.set(request.ip);
                    target.rax.set(request.value);
                    if output_context != 0 {
                        native_context::copy(output_context, frame_context, native_context::SIZE);
                    }
                    return Err(native_context::transfer(frame_context));
                }
            }
            stop_for_unhandled_exception(request.record, source, "unwind target unavailable")
        })();
        record.exception_flags.set(saved_flags);
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
                if record_at(record).exception_flags.get() & NONCONTINUABLE != 0 {
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
        build_record(workspace, status, NONCONTINUABLE, linked, context_at(context).rip.get());
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

/// RtlRaiseException(ExceptionRecord) no ntoskrnl 19041 (0x33d230): o
/// CONTEXT é o de quem chamou (o retorno da chamada), o ExceptionAddress do
/// registro recebe esse RIP e o despacho segue com o registro do chamador.
/// Um handler que continua a exceção volta ao chamador com RAX =
/// `return_value` (o RtlAllocateHeap que levanta STATUS_NO_MEMORY e é
/// continuado devolve NULL); sem handler, o sistema para, como a segunda
/// chance do ZwRaiseException em modo kernel.
pub fn raise_exception(record: u64, return_value: u64) -> Result<u64, KernelError> {
    run_nonreturning_operation(
        || {
            with_workspace(0x600, |workspace| {
                let context = workspace + 0x100;
                native_context::copy(context, native_context::current()?, native_context::SIZE);
                context_at(context).rax.set(return_value);
                record_at(record).exception_address.set(context_at(context).rip.get());
                search_exception_handlers(record, context, irql::HIGH_LEVEL)
            })
        },
        record_at(record).exception_code.get() as u32,
    )
}

/// Levanta uma exceção continuável de software com o código e os
/// parâmetros dados (o EXCEPTION_RECORD montado como o
/// RtlpAllocateHeapRaiseException: ExceptionRecord nulo e NumberParameters
/// = parâmetros), pelo mesmo caminho de [`raise_exception`].
pub fn raise_software_exception(code: u32, parameters: &[u64], return_value: u64) -> Result<u64, KernelError> {
    with_workspace(0x100, |record| {
        build_record(record, code, 0, 0, 0);
        let fields = record_at(record);
        fields.number_parameters.set(parameters.len() as u32);
        for (slot, &value) in fields.exception_information.iter().zip(parameters) {
            slot.set(value);
        }
        raise_exception(record, return_value)
    })
}

/// RtlUnwindEx (a tabela de histórico não é usada).
pub fn unwind_ex(frame: u64, target: u64, record: u64, value: u64, context: u64, _history: u64) -> Result<u64, KernelError> {
    run_nonreturning_operation(|| unwind_ex_core(frame, target, record, value, context), STATUS_UNWIND)
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
            build_record(workspace, STATUS_UNWIND, 0, 0, context_at(source).rip.get());
            request.record = workspace;
        }
        unwind_to_target(request, source, source, context)
    })
}

/// __C_specific_handler: a tabela de escopos escolhe filtros ou
/// finalizadores pelo RIP, flags e destino.
pub fn specific_handler(record: u64, frame: u64, context: u64, dispatcher: u64) -> Result<u64, KernelError> {
    let dispatcher_context = dispatcher_at(dispatcher);
    let image_base = dispatcher_context.image_base.get();
    // HandlerData do __C_specific_handler: a SCOPE_TABLE da imagem.
    // SAFETY: dados do handler na .xdata da imagem, alinhados a DWORD.
    let scope_table = unsafe { ScopeTableAmd64::at(dispatcher_context.handler_data.get()) };
    let instruction = dispatcher_context.control_pc.get().wrapping_sub(image_base);
    let target = dispatcher_context.target_ip.get().wrapping_sub(image_base);
    let count = scope_table.count.get();
    let flags = record_at(record).exception_flags.get();
    if count > 0x10_0000 {
        return Err(KernelError::new("invalid kernel scope count"));
    }
    // ScopeRecord[Count]: início, fim, handler e salto (RVAs).
    // SAFETY: Count registros seguem o contador na mesma tabela.
    let records = unsafe { ScopeTableAmd64ScopeRecord::array_at(scope_table.scope_record[0].address(), count as usize) };
    let scopes: Vec<(u64, u64, u32, u32)> =
        records.iter().map(|scope| (scope.begin_address.get() as u64, scope.end_address.get() as u64, scope.handler_address.get(), scope.jump_target.get())).collect();
    let mut index = dispatcher_context.scope_index.get() as usize;
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
                dispatcher_context.scope_index.set(index as u32 + 1);
                native_context::call(image_base + handler as u64, &[1, frame], dispatcher_context.context_record.get())?;
            }
        } else if jump != 0 {
            // Filtro: negativo continua a execução, zero continua a busca,
            // positivo pede transferência ao bloco de tratamento.
            let filter = if handler == 1 {
                1
            } else {
                with_workspace(ExceptionPointers::SIZE, |pointers| {
                    // SAFETY: EXCEPTION_POINTERS no bloco de trabalho recém-alocado.
                    let exception_pointers = unsafe { ExceptionPointers::at(pointers) };
                    exception_pointers.exception_record.set(record);
                    exception_pointers.context_record.set(context);
                    Ok(native_context::call(image_base + handler as u64, &[pointers, frame], dispatcher_context.context_record.get())? as i32)
                })?
            };
            if filter < 0 {
                return Ok(0);
            }
            if filter > 0 {
                return Err(unwind_signal(UnwindRequest { frame, ip: image_base + jump as u64, record, value: record_at(record).exception_code.get() as i64 as u64 }));
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
        record_at(record).exception_code.get() as u32,
    )
}
