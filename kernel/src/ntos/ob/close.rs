//! NtClose / ZwClose.
//!
//! Libera o handle pelo subsistema dono do objeto. Classificação, processo
//! dono e proteção contra fechamento são verificados antes da liberação.
//!
//! Donos de módulos posteriores se registram aqui: a tabela de handles de
//! usuário (fase 7), os donos de handles de kernel `ex/callbacks` e
//! `se/token/handles` (nessa ordem) e o provedor Zw (fase 6).

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::{object_manager, open_pointer};
use crate::ntos::ke::{bugcheck, irql};
use crate::ntos::ps::{previous_mode, process};
use crate::rtl::{KernelError, SpinLock};

pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_HANDLE_NOT_CLOSABLE: u32 = 0xC000_0235;

/// Tabelas de handles de usuário por processo (`ps/user/state`). Atributos
/// e fechamento agem na tabela do processo corrente, o anexado quando há
/// attach, como o ObReferenceObjectByHandle do NT.
#[derive(Clone, Copy)]
pub struct UserHandleTable {
    /// O processo tem tabela de handles de usuário (todo processo vivo, o
    /// System inclusive).
    pub owns: fn(u64) -> bool,
    /// Atributos do handle de usuário do processo corrente, se existir.
    pub attributes: fn(u64) -> Option<u32>,
    /// Fecha o handle do processo corrente (`force` ignora a proteção
    /// individual).
    pub close: fn(u64, bool) -> u32,
}

/// Dono de handles de kernel próprios (`ex/callbacks`, `se/token/handles`).
#[derive(Clone, Copy)]
pub struct KernelHandleOwner {
    pub attributes: fn(u64) -> Option<u32>,
    pub close: fn(u64) -> u32,
}

/// Registro devolvido pelo provedor Zw (`io/file/zw`).
pub struct ZwRecord {
    pub kernel_handle: bool,
    pub owner_process: u64,
    pub attributes: u32,
    pub close: Box<dyn FnOnce() -> u32>,
}

struct Providers {
    user: Option<UserHandleTable>,
    kernel_owners: Vec<KernelHandleOwner>,
    zw: Option<fn(u32) -> Option<ZwRecord>>,
}

static PROVIDERS: SpinLock<Providers> = SpinLock::new(Providers { user: None, kernel_owners: Vec::new(), zw: None });

pub fn set_user_handle_table(table: UserHandleTable) {
    PROVIDERS.lock().user = Some(table);
}

pub fn register_kernel_handle_owner(owner: KernelHandleOwner) {
    PROVIDERS.lock().kernel_owners.push(owner);
}

pub fn set_zw_provider(provider: fn(u32) -> Option<ZwRecord>) {
    PROVIDERS.lock().zw = Some(provider);
}

/// Provedor provisório (só chaves) enquanto o Zw completo não existe.
pub fn set_zw_provider_if_absent(provider: fn(u32) -> Option<ZwRecord>) {
    let mut providers = PROVIDERS.lock();
    if providers.zw.is_none() {
        providers.zw = Some(provider);
    }
}

/// Modo usuário: STATUS_HANDLE_NOT_CLOSABLE. Kernel: bugcheck 0x93
/// (INVALID_KERNEL_HANDLE) com o identificador diagnóstico.
fn reject_protected_close(handle: u64, from_user_mode: bool) -> u32 {
    if from_user_mode {
        return STATUS_HANDLE_NOT_CLOSABLE;
    }
    bugcheck::bug_check_ex(0x93, handle, 0, 0, 0)
}

/// Fecha um handle de usuário do processo corrente; pseudohandles de -1 a
/// -6 são aceitos.
pub fn close_user(handle: u64, force: bool) -> u32 {
    let signed = handle as i64;
    if (-6..=-1).contains(&signed) {
        return 0;
    }
    if handle > 0x7FFF_FFFF {
        return STATUS_INVALID_HANDLE;
    }
    match PROVIDERS.lock().user {
        Some(table) => (table.close)(handle & !3, force),
        None => STATUS_INVALID_HANDLE,
    }
}

/// NtClose: seleciona o dono pelo handle e pelo modo; nada é fechado antes
/// de validar propriedade e proteção. `None` usa o PreviousMode da thread.
/// Um handle sem o prefixo de kernel é procurado na tabela do processo
/// corrente (o anexado); os de kernel ficam na tabela do System e valem em
/// qualquer processo.
pub fn close(handle: u64, previous_mode: Option<u8>) -> Result<u32, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("NtClose requires PASSIVE_LEVEL"));
    }
    let from_user_mode = match previous_mode {
        Some(mode) => mode != 0,
        None => previous_mode::get()? != 0,
    };
    let signed = handle as i64;
    // -1/-2 ficam fora dos handles de kernel; em modo usuário, de -1 a -6.
    if signed <= -1 && signed >= if from_user_mode { -6 } else { -2 } {
        return Ok(0);
    }
    let kernel_handle = handle & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000;
    if (kernel_handle && from_user_mode) || (!kernel_handle && handle > 0x7FFF_FFFF) {
        return Ok(STATUS_INVALID_HANDLE);
    }
    // O bugcheck recebe o identificador sem o prefixo de kernel.
    let reported = if kernel_handle { handle ^ 0xFFFF_FFFF_8000_0000 } else { handle };
    let value = handle & !3;
    let current = process::get_current_process();
    let user = PROVIDERS.lock().user;
    if let Some(table) = user.filter(|table| !kernel_handle && (table.owns)(current)) {
        if let Some(attributes) = (table.attributes)(value) {
            if attributes & 1 != 0 {
                return Ok(reject_protected_close(reported, from_user_mode));
            }
            return Ok((table.close)(value, false));
        }
    }
    // Objetos abertos por ponteiro conservam seu caminho de retenção.
    match open_pointer::resolve(value, from_user_mode) {
        Some(Err(status)) => return Ok(status),
        Some(Ok(opened)) => {
            if opened.attributes & 1 != 0 {
                return Ok(reject_protected_close(reported, from_user_mode));
            }
            return Ok(open_pointer::close(value).unwrap_or(STATUS_INVALID_HANDLE));
        }
        None => {}
    }
    if kernel_handle {
        let owners = PROVIDERS.lock().kernel_owners.clone();
        for owner in owners {
            if let Some(attributes) = (owner.attributes)(value) {
                if attributes & 1 != 0 {
                    return Ok(reject_protected_close(reported, false));
                }
                return Ok((owner.close)(value));
            }
        }
        let identifier = (value & 0x7FFF_FFFF) as u32;
        if let Some(record) = object_manager::handle_record(identifier).filter(|record| record.options.kernel_handle) {
            if record.attributes & 1 != 0 {
                return Ok(reject_protected_close(reported, false));
            }
            return Ok(if matches!(object_manager::close(identifier), Ok(true)) { 0 } else { STATUS_INVALID_HANDLE });
        }
        return Ok(STATUS_INVALID_HANDLE);
    }
    // O provedor Zw devolve o registro dono e sua operação real de fechamento.
    let provider = PROVIDERS.lock().zw;
    let Some(record) = provider.and_then(|provider| provider(value as u32)) else {
        return Ok(STATUS_INVALID_HANDLE);
    };
    if (from_user_mode && record.kernel_handle) || (!record.kernel_handle && record.owner_process != current) {
        return Ok(STATUS_INVALID_HANDLE);
    }
    if record.attributes & 1 != 0 {
        return Ok(reject_protected_close(reported, from_user_mode));
    }
    Ok((record.close)())
}

/// Atributos do handle (OBJ_PROTECT_CLOSE 1, OBJ_INHERIT 2,
/// OBJ_AUDIT_OBJECT_CLOSE 4) no mesmo dono que `close` escolheria, com a
/// regra de ObpIsKernelHandle: o prefixo de kernel só vale vindo de
/// KernelMode. `None` = handle inválido para o chamador.
pub fn handle_attributes(handle: u64, from_user_mode: bool) -> Option<u32> {
    let kernel_handle = !from_user_mode && handle & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000;
    if !kernel_handle && handle > 0x7FFF_FFFF {
        return None;
    }
    let value = handle & !3;
    let current = process::get_current_process();
    let user = PROVIDERS.lock().user;
    if let Some(table) = user.filter(|table| !kernel_handle && (table.owns)(current)) {
        if let Some(attributes) = (table.attributes)(value) {
            return Some(attributes);
        }
    }
    match open_pointer::resolve(value, from_user_mode) {
        Some(Ok(opened)) => return Some(opened.attributes),
        Some(Err(_)) => return None,
        None => {}
    }
    if kernel_handle {
        let owners = PROVIDERS.lock().kernel_owners.clone();
        if let Some(attributes) = owners.iter().find_map(|owner| (owner.attributes)(value)) {
            return Some(attributes);
        }
        let identifier = (value & 0x7FFF_FFFF) as u32;
        return object_manager::handle_record(identifier).filter(|record| record.options.kernel_handle).map(|record| record.attributes);
    }
    let provider = PROVIDERS.lock().zw;
    let record = provider.and_then(|provider| provider(value as u32))?;
    let foreign = (from_user_mode && record.kernel_handle) || (!record.kernel_handle && record.owner_process != current);
    (!foreign).then_some(record.attributes)
}
