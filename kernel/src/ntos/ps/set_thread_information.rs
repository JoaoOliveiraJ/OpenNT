//! Zw/NtSetInformationThread.
//!
//! ThreadBreakOnTermination liga ou desliga a thread crítica.
//! ThreadImpersonationToken impersona um token (ou encerra a impersonação).
//! ThreadIoPriority troca a prioridade de E/S da thread (o
//! PsSetIoPriorityThread).
//! ThreadPagePriority altera só os três bits medidos na ETHREAD original. A
//! ordem medida é sondagem, tamanho, captura/valor, referência, alteração
//! atômica e liberação. A variante de syscall de usuário (`set_user`) entra
//! com o estado de modo usuário (fase 7).

use super::query_thread::{kernel_range_valid, STATUS_ACCESS_VIOLATION, USER_PROBE_LIMIT};
use super::user_probe;
use crate::ntos::ke::irql;
use crate::ntos::mm::{page_residency, paging};
use crate::ntos::ob::handles::thread as thread_handles;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::Ethread;

const THREAD_PAGE_PRIORITY: u32 = 24;
pub const THREAD_BREAK_ON_TERMINATION: u32 = 18;
/// ThreadIoPriority, IoPriorityHigh, IoPriorityCritical e
/// SeIncreaseBasePriorityPrivilege.
const THREAD_IO_PRIORITY: u32 = 22;
const IO_PRIORITY_HIGH: u32 = 3;
const IO_PRIORITY_CRITICAL: u32 = 4;
const SE_INCREASE_BASE_PRIORITY_PRIVILEGE: u64 = 14;
/// SeDebugPrivilege.
const DEBUG_PRIVILEGE: u64 = 20;
const THREAD_SET_INFORMATION: u32 = 0x20;
/// ThreadImpersonationToken, THREAD_SET_THREAD_TOKEN, TOKEN_IMPERSONATE,
/// TokenImpersonation e SecurityImpersonation.
const THREAD_IMPERSONATION_TOKEN: u32 = 5;
const THREAD_SET_THREAD_TOKEN: u32 = 0x80;
const TOKEN_IMPERSONATE: u32 = 4;
const TOKEN_TYPE_IMPERSONATION: u32 = 2;
const SECURITY_IMPERSONATION: u32 = 2;
const REJECTED_SET_CLASSES: [u32; 17] = [0, 6, 8, 11, 12, 16, 20, 21, 23, 26, 27, 28, 35, 37, 40, 41, 45];

/// A captura aceita memória só de leitura e endereços desalinhados em
/// KernelMode.
fn can_read_page_priority(address: u64, from_user_mode: bool) -> bool {
    if from_user_mode {
        return address < USER_PROBE_LIMIT && user_probe::probe_user_read(address, 4);
    }
    if !kernel_range_valid(address, 4) {
        return false;
    }
    let end = address.wrapping_add(4);
    let mut page = address & !4095;
    loop {
        if paging::access_flags(page) & 1 == 0 && (!page_residency::fault(page, 0) || paging::access_flags(page) & 1 == 0) {
            return false;
        }
        page = page.wrapping_add(4096);
        if page == 0 || page >= end {
            return true;
        }
    }
}

pub fn set(thread_handle: u64, information_class: u32, input: u64, input_length: u32, access_mode: u8) -> Result<u32, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("thread information set requires PASSIVE_LEVEL"));
    }
    let from_user_mode = access_mode != 0;
    if from_user_mode && input_length != 0 {
        // Qualquer comprimento não nulo exige alinhamento de quatro bytes.
        if input & 3 != 0 {
            return Ok(0x8000_0002);
        }
        if input.wrapping_add(input_length as u64) > USER_PROBE_LIMIT {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    if information_class > 50 || REJECTED_SET_CLASSES.contains(&information_class) {
        return Ok(0xC000_0003);
    }
    if information_class == THREAD_BREAK_ON_TERMINATION {
        return set_break_on_termination(thread_handle, input, input_length, access_mode);
    }
    if information_class == THREAD_IMPERSONATION_TOKEN {
        return impersonation_token(thread_handle, input, input_length, access_mode);
    }
    if information_class == THREAD_IO_PRIORITY {
        return set_io_priority(thread_handle, input, input_length, access_mode);
    }
    if information_class != THREAD_PAGE_PRIORITY {
        return Ok(0xC000_0002);
    }
    if input_length != 4 {
        return Ok(0xC000_0004);
    }
    if !can_read_page_priority(input, from_user_mode) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    // Captura uma vez: outra thread pode mudar o buffer enquanto o handle é resolvido.
    let Ok(page_priority) = guest::try_read::<u32>(input) else { return Ok(STATUS_ACCESS_VIOLATION) };
    if !(1..=5).contains(&page_priority) {
        return Ok(0xC000_000D);
    }
    let mut reference = match thread_handles::reference(thread_handle, THREAD_SET_INFORMATION, access_mode)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let result = (|| -> Result<u32, KernelError> {
        // CAS em CrossThreadFlags.ThreadPagePriority, preservando mudanças
        // concorrentes dos outros bits.
        // SAFETY: ETHREAD referenciado pelo handle.
        unsafe { Ethread::at(reference.pointer) }.set_thread_page_priority(page_priority);
        Ok(0)
    })();
    reference.release()?;
    result
}

/// ThreadImpersonationToken: o HANDLE do token (8 bytes, senão
/// STATUS_INFO_LENGTH_MISMATCH), capturado uma vez; a thread com
/// THREAD_SET_THREAD_TOKEN e o PsAssignImpersonationToken. NULL encerra a
/// impersonação; senão o token, referenciado com TOKEN_IMPERSONATE no modo
/// do chamador (um handle de kernel na entrada Zw: o msrpc.sys impersona o
/// cliente na thread de trabalho dele), precisa ser de impersonação
/// (STATUS_BAD_TOKEN_TYPE) e a thread passa a impersoná-lo no nível dele.
fn impersonation_token(thread_handle: u64, input: u64, input_length: u32, access_mode: u8) -> Result<u32, KernelError> {
    use crate::ntos::se::token::{reference as token_reference, tokens};
    if input_length != 8 {
        return Ok(0xC000_0004);
    }
    if access_mode != 0 && !user_probe::probe_user_read(input, 8) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let Ok(token_handle) = guest::try_read::<u64>(input) else { return Ok(STATUS_ACCESS_VIOLATION) };
    let mut thread = match thread_handles::reference(thread_handle, THREAD_SET_THREAD_TOKEN, access_mode)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let result = (|| -> Result<u32, KernelError> {
        if token_handle == 0 {
            return crate::ntos::ps::security::impersonate_client(thread.pointer, 0, false, false, SECURITY_IMPERSONATION);
        }
        let mut token = match token_reference::reference(token_handle, TOKEN_IMPERSONATE, access_mode, false)? {
            Ok(reference) => reference,
            Err(status) => return Ok(status),
        };
        let assigned = (|| -> Result<u32, KernelError> {
            let Some((kind, level)) = tokens::with(token.token, |record| (record.kind, record.impersonation_level)) else { return Ok(0xC000_0008) };
            if kind != TOKEN_TYPE_IMPERSONATION {
                return Ok(0xC000_00A8);
            }
            crate::ntos::ps::security::impersonate_client(thread.pointer, token.token, false, false, level)
        })();
        token.release()?;
        assigned
    })();
    thread.release()?;
    result
}

/// ThreadBreakOnTermination (ntoskrnl 19041, rva 0x64b41e; o
/// RtlSetThreadIsCritical): um ULONG (outro tamanho dá
/// STATUS_INFO_LENGTH_MISMATCH), SeDebugPrivilege no modo anterior
/// (STATUS_PRIVILEGE_NOT_HELD), o handle com THREAD_SET_INFORMATION, e o
/// valor liga ou desliga ETHREAD.CrossThreadFlags.BreakOnTermination (o fim
/// da thread derruba o sistema).
fn set_break_on_termination(thread_handle: u64, input: u64, input_length: u32, access_mode: u8) -> Result<u32, KernelError> {
    if input_length != 4 {
        return Ok(0xC000_0004);
    }
    if access_mode != 0 && !user_probe::probe_user_read(input, 4) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let Ok(value) = guest::try_read::<u32>(input) else { return Ok(STATUS_ACCESS_VIOLATION) };
    if !crate::ntos::se::privilege::single_privilege_check(DEBUG_PRIVILEGE, u32::from(access_mode)) {
        return Ok(0xC000_0061);
    }
    let mut reference = match thread_handles::reference(thread_handle, THREAD_SET_INFORMATION, access_mode)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    // SAFETY: ETHREAD referenciado pelo handle; o bit muda por CAS atômico.
    unsafe { Ethread::at(reference.pointer) }.set_break_on_termination((value != 0) as u32);
    reference.release()?;
    Ok(0)
}

/// ThreadIoPriority (o ramo da classe 22 do NtSetInformationThread 19041,
/// rva 0x64aa67): 4 bytes (o IO_PRIORITY_HINT) ou 8 (o valor e, no ULONG de
/// cima, o pedido de reforço); outro tamanho dá STATUS_INFO_LENGTH_MISMATCH.
/// O valor é capturado uma vez: IoPriorityCritical (4) ou acima é
/// STATUS_INVALID_PARAMETER, IoPriorityHigh (3) exige o
/// SeIncreaseBasePriorityPrivilege (SeCheckPrivilegedObject, senão
/// STATUS_PRIVILEGE_NOT_HELD); o handle com THREAD_SET_INFORMATION e o
/// PsSetIoPriorityThread troca os bits do CrossThreadFlags por CAS. O
/// reforço da forma de 8 bytes (IoBoostThreadIoPriority) eleva a prioridade
/// dos IRPs pendentes da thread, e o I/O Manager do OpenNT não guarda
/// prioridade por IRP: nada a elevar.
fn set_io_priority(thread_handle: u64, input: u64, input_length: u32, access_mode: u8) -> Result<u32, KernelError> {
    if input_length.wrapping_sub(4) & !4 != 0 {
        return Ok(0xC000_0004);
    }
    if access_mode != 0 && !user_probe::probe_user_read(input, input_length as u64) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let captured = if input_length == 8 { guest::try_read::<u64>(input) } else { guest::try_read::<u32>(input).map(u64::from) };
    let Ok(captured) = captured else { return Ok(STATUS_ACCESS_VIOLATION) };
    let priority = captured as u32;
    if priority >= IO_PRIORITY_CRITICAL {
        return Ok(0xC000_000D);
    }
    if priority == IO_PRIORITY_HIGH && !crate::ntos::se::privilege::single_privilege_check(SE_INCREASE_BASE_PRIORITY_PRIVILEGE, u32::from(access_mode)) {
        return Ok(0xC000_0061);
    }
    let mut reference = match thread_handles::reference(thread_handle, THREAD_SET_INFORMATION, access_mode)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    // SAFETY: ETHREAD referenciado pelo handle; os bits mudam por CAS atômico.
    unsafe { Ethread::at(reference.pointer) }.set_thread_io_priority(priority);
    reference.release()?;
    Ok(0)
}

/// Variante de syscall: recupera os argumentos originais, inclusive o lixo
/// nos bits altos de ULONG.
pub fn set_user(user_rsp: u64) -> Result<u32, KernelError> {
    let argument = |index: u64| {
        let words = crate::ntos::ps::user::state::syscall_arg_words(user_rsp, index);
        words[0] as u64 | ((words[1] as u64) << 32)
    };
    let low = |index: u64| crate::ntos::ps::user::state::syscall_arg_words(user_rsp, index)[0];
    set(argument(1), low(2), argument(3), low(4), 1)
}
