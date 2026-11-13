//! Contadores de desempenho (PCW) vistos do ntoskrnl — PcwRegister 0x781700,
//! PcwUnregister 0x956d00, PcwAddInstance 0x667bc0, ExpPcwDisabledStatus
//! 0x956c28 (ntoskrnl 19041).
//!
//! No Windows 10 a implementação dos conjuntos de contadores não mora no
//! ntoskrnl: ela é o pcw.sys, que se registra no host de extensão
//! ExpPcwExtensionHost (criado no ExpInitSystemPhase1 por ExRegisterHost com
//! ExtensionId 1, ExtensionVersion 1, FunctionCount 5 e a notificação
//! ExpPcwHostCallback). Cada export Pcw* é só um despachante:
//!     table = ExGetExtensionTable(ExpPcwExtensionHost)
//!     table != NULL -> table[i](...) e ExReleaseExtensionTable
//!     table == NULL -> ExpPcwDisabledStatus()
//! com i = 0 Register, 1 Unregister, 2 CreateInstance, 3 CloseInstance,
//! 4 AddInstance. Sem extensão, PcwRegister/PcwCreateInstance zeram o handle
//! de saída e PcwUnregister/PcwCloseInstance não fazem nada.
//!
//! O OpenNT não carrega pcw.sys nem tem hosts de extensão, então este assunto
//! é exatamente o ramo "sem extensão" do Windows; reimplementar os conjuntos
//! de contadores aqui seria reescrever o pcw.sys.
//!
//! ExpPcwDisabledStatus calcula uma vez ExpPcwEnableState a partir de
//! HKLM\...\Services\pcw\Start (RtlQueryRegistryValues RTL_REGISTRY_SERVICES,
//! DIRECT|TYPECHECK, REG_DWORD, default 0xFFFFFFFF quando só o valor falta;
//! chave ausente = OBJECT_NAME_NOT_FOUND tratado como sucesso com 0):
//!     Start != 0 -> estado 1: o pcw foi desligado de propósito, e os Pcw*
//!                   devolvem STATUS_SUCCESS com handle NULL;
//!     Start == 0 -> estado 2: o pcw deveria estar carregado (boot), e os Pcw*
//!                   devolvem STATUS_NOT_IMPLEMENTED.
//! Um erro da consulta (tipo errado) volta sem gravar o estado.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::ntos::cm::registry;
use crate::ntos::inc::types::Field;

const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const REG_DWORD: u32 = 4;
const PCW_SERVICE_KEY: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\pcw";

/// ExpPcwEnableState: 0 = ainda não consultado, 1 = desligado, 2 = esperado.
static ENABLE_STATE: AtomicU32 = AtomicU32::new(0);

/// Valor de Start como o RtlQueryRegistryValues DIRECT o deixaria no DWORD.
fn query_start() -> Result<u32, u32> {
    if registry::node_by_path(PCW_SERVICE_KEY).is_none() {
        return Ok(0);
    }
    match registry::read_value_by_path(PCW_SERVICE_KEY, "Start") {
        None => Ok(0xFFFF_FFFF),
        Some(value) if value.value_type != REG_DWORD => Err(STATUS_OBJECT_TYPE_MISMATCH),
        Some(value) => {
            let mut start = 0u32;
            for (index, &byte) in value.data.iter().take(4).enumerate() {
                start |= (byte as u32) << (index * 8);
            }
            Ok(start)
        }
    }
}

/// ExpPcwDisabledStatus.
pub fn disabled_status() -> u32 {
    let mut state = ENABLE_STATE.load(Ordering::Acquire);
    if state == 0 {
        state = match query_start() {
            Ok(start) => if start != 0 { 1 } else { 2 },
            Err(status) => return status,
        };
        ENABLE_STATE.store(state, Ordering::Release);
    }
    if state == 1 { 0 } else { STATUS_NOT_IMPLEMENTED }
}

/// PcwRegister(Registration*, Info): sem tabela de extensão, *Registration
/// = NULL e o status de ExpPcwDisabledStatus.
pub fn register(registration: &Field<u64>, _info: u64) -> u32 {
    registration.set(0);
    disabled_status()
}

/// PcwUnregister(Registration): sem tabela de extensão, nada a desfazer.
pub fn unregister(_registration: u64) {}

/// PcwAddInstance(Buffer, Name, Id, Count, Data): sem tabela de extensão, o
/// status de ExpPcwDisabledStatus (os argumentos não são lidos).
pub fn add_instance(_buffer: u64, _name: u64, _id: u32, _count: u32, _data: u64) -> u32 {
    disabled_status()
}

/// Esquece o estado calculado (o teste de fase 6 reconsulta o Registro).
pub fn reset_enable_state_for_test() {
    ENABLE_STATE.store(0, Ordering::Release);
}
