//! Identidade corrente de um escopo WNF.
//!
//! Não cria instâncias nem nomes: consulta EPROCESS, KTHREAD e tokens dos
//! provedores reais; a resolução posterior usa os bytes como chave.

use crate::ntos::ke::critical_region;
use crate::ntos::ps::{process, session};
use crate::ntos::se::token::{thread as thread_tokens, tokens};
use crate::rtl::KernelError;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::Kthread;
use crate::ntos::mm::guest_memory as guest;

fn thread_at(thread: u64) -> &'static Kthread {
    // SAFETY: threads vivas (a corrente ou a referenciada pelo chamador).
    unsafe { Kthread::at(thread) }
}

/// Saída ULONG das molduras do namespace (tamanho e indicador de cache).
fn ulong_at(address: u64) -> &'static Field<u32> {
    // SAFETY: células da moldura de identidade do namespace.
    unsafe { Field::<u32>::at(address) }
}

/// SID da identidade efetiva. Sem thread explícita, o token primário do
/// processo dado; para outra thread, o processo dono dela; para a thread
/// corrente, o processo do APC_STATE (que pode estar anexado).
fn query_current_user_identifier(process: u64, thread: u64, buffer: u64, length_pointer: u64, cache_pointer: u64) -> Result<u32, KernelError> {
    let current = process::get_current_thread();
    let impersonation = if thread != 0 { thread_tokens::get(thread) } else { None };
    let primary_process = match thread {
        0 => process,
        thread if thread == current => thread_at(thread).apc_state.process.get(),
        thread => thread_at(thread).process.get(),
    };
    let token = match impersonation {
        Some(impersonation) => impersonation.token,
        None => process::get_primary_token(primary_process).ok_or_else(|| KernelError::new("WNF scope identity without primary token"))?,
    };
    // A referência protege o token mesmo se uma APC trocar a identidade ao
    // sair da região crítica.
    tokens::retain(token)?;
    let result = (|| -> Result<u32, KernelError> {
        if impersonation.is_some_and(|impersonation| impersonation.level < 2) {
            return Ok(0xC000_00A5);
        }
        let capacity = ulong_at(length_pointer).get();
        critical_region::enter_critical()?;
        let identifier = tokens::with(token, |token| token.user.clone()).unwrap_or_default();
        let length = 8 + identifier.get(1).copied().unwrap_or(0) as u32 * 4;
        let status = if capacity < length {
            0xC000_0023
        } else {
            guest::write_bytes(buffer, &identifier[..(length as usize).min(identifier.len())]);
            0
        };
        critical_region::leave_critical()?;
        // O tamanho exigido é publicado também em BUFFER_TOO_SMALL.
        ulong_at(length_pointer).set(length);
        Ok(status)
    })();
    tokens::release(token)?;
    let status = result?;
    if status & 0x8000_0000 == 0 {
        ulong_at(cache_pointer).set(if impersonation.is_some() { 0 } else { 1 });
    }
    Ok(status)
}

/// ExpWnfGetCurrentScopeInstance: sistema, máquina e máquina física não
/// têm identificador adicional; o silo é selecionado pelo namespace.
pub fn query_current(process: u64, thread: u64, scope: u32, buffer: u64, length_pointer: u64, cache_pointer: u64) -> Result<u32, KernelError> {
    if scope == 2 {
        return query_current_user_identifier(process, thread, buffer, length_pointer, cache_pointer);
    }
    if scope == 1 || scope == 3 {
        let current = thread_at(process::get_current_thread());
        // ApcStateIndex 1 = thread anexada a outro processo.
        let attached = current.apc_state_index.get() == 1;
        ulong_at(cache_pointer).set(if attached { 0 } else { 1 });
        let selected = if attached { current.apc_state.process.get() } else { process };
        if scope == 1 {
            ulong_at(buffer).set(session::query(selected));
            ulong_at(length_pointer).set(4);
        } else {
            // SAFETY: identidade de 8 bytes da moldura (ou alocação) do namespace.
            unsafe { Field::<u64>::at(buffer) }.set(selected);
            ulong_at(length_pointer).set(8);
        }
        return Ok(0);
    }
    ulong_at(length_pointer).set(0);
    ulong_at(cache_pointer).set(1);
    Ok(0)
}
