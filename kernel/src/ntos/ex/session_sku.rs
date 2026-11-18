//! A configuração de sessões do SKU: o ExIsMultiSessionSku e o
//! InitSkuSessionParameters do ntoskrnl 19041, que publicam o
//! DbgMultiSessionSku (bit 8) do KUSER_SHARED_DATA.SharedDataFlags. A ntdll
//! (RtlIsMultiSessionSku 0x40210) e o RtlIsMultiSessionSku do kernel
//! (0x6816a0) leem esse bit; o DispBroker.dll do dwm escolhe por ele o
//! diretório da DispBrokerPort que o dxgkrnl procura.

use core::sync::atomic::Ordering;

use crate::ntos::cm::registry;
use crate::ntos::mm::shared_user_data;

const SESSION_MANAGER: &str = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager";
const REG_DWORD: u32 = 4;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
/// SharedDataFlags.DbgMultiSessionSku.
const DBG_MULTI_SESSION_SKU: u32 = 1 << 8;

/// ExIsMultiSessionSku (0x7d19e8): Session Manager\NumberOfInitialSessions
/// pelo ExpGetNumberOfInitialSessionsFromRegistry (0x7d1a58: DIRECT |
/// TYPECHECK REG_DWORD). Sem o valor, o erro da consulta; mais de uma
/// sessão inicial é SKU multissessão. Com 0 ou 1 o binário pergunta pelo API
/// set ext-ms-win-session-wtsapi32-l1-1-0 com host (0x861dc0), que o kernel
/// do OpenNT não resolve: FALSE.
pub fn is_multi_session_sku() -> Result<bool, u32> {
    let value = registry::read_value_by_path(SESSION_MANAGER, "NumberOfInitialSessions").ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    if value.value_type != REG_DWORD || value.data.len() != 4 {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    Ok(u32::from_le_bytes([value.data[0], value.data[1], value.data[2], value.data[3]]) > 1)
}

/// InitSkuSessionParameters (0xa71d04, Phase1InitializationDiscard+0xad7,
/// depois do CmInitSystem1): liga o bit 8 quando o ExIsMultiSessionSku
/// devolve sucesso e TRUE. O bit 9 (RtlpMultiUsersInSessionSupported) fica
/// desligado, como nesta instalação; o bit 10 já vem de
/// `shared_user_data::init`.
pub fn initialize() {
    if is_multi_session_sku() == Ok(true) {
        if let Some(shared) = shared_user_data::data() {
            shared.shared_data_flags.atomic().fetch_or(DBG_MULTI_SESSION_SKU, Ordering::SeqCst);
        }
    }
}
