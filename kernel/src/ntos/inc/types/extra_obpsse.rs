//! Os parâmetros dos callouts do Win32k, os registros internos dos
//! atributos de segurança do token e as mensagens e itens entre o Reference
//! Monitor e o LSA, que os símbolos do ntoskrnl não têm (layouts lidos de
//! PspExitThread/PsConvertToGuiThread, dos callouts de energia do Po e do
//! W32CalloutDispatch do win32kbase, de
//! AuthzBasepCopyoutInternalSecurityAttributes e das rotinas SepRm* do
//! ntoskrnl 19041).
//!
//! Mantido à mão, no estilo de `types`: `#[repr(C)]`, folhas `Field<T>`,
//! `size_of`/`offset_of!` conferidos em compilação. O contexto de segurança
//! do cliente, o `_TOKEN_CONTROL` e o `_TEB32` constam dos símbolos e são
//! gerados (`types/se.rs`, `ps.rs`); ficam reexportados aqui.

use super::*;

pub use super::{SecurityClientContext, Teb32, TokenControl};

/// Parâmetro do callout de thread do Win32k (PsW32ThreadCallout, tipo 1):
/// a ETHREAD e o PSW32THREADCALLOUTTYPE (0 = inicialização em
/// PsConvertToGuiThread, 1 = saída em PspExitThread). 0x10 bytes.
#[repr(C)]
pub struct Win32ThreadCalloutParameters {
    pub thread: Field<u64>,
    pub callout_type: Field<u32>,
    _reserved_0c: Reserved<4>,
}

unsafe impl NtStruct for Win32ThreadCalloutParameters {}

/// Parâmetro do callout de processo do Win32k (PsW32ProcessCallout, tipo 0):
/// o EPROCESS e Initialize (FALSE na saída do último thread em
/// PspExitThread). 0x10 bytes.
#[repr(C)]
pub struct Win32ProcessCalloutParameters {
    pub process: Field<u64>,
    pub initialize: Field<u32>,
    _reserved_0c: Reserved<4>,
}

unsafe impl NtStruct for Win32ProcessCalloutParameters {}

/// Parâmetro do callout de evento de energia do Win32k (PsW32PowerEvent,
/// tipo 3; o WIN32_POWEREVENT_PARAMETERS que o PopEventCalloutDispatch
/// 0x3a707c monta na pilha e o QueuePowerRequest do win32kbase enfileira):
/// o PSPOWEREVENTTYPE e o código do evento. 0x10 bytes.
#[repr(C)]
pub struct Win32PowerEventParameters {
    pub event_number: Field<u32>,
    _reserved_04: Reserved<4>,
    pub code: Field<u64>,
}

unsafe impl NtStruct for Win32PowerEventParameters {}

/// Parâmetro do callout de estado de energia do Win32k (PsW32PowerState,
/// tipo 4; o WIN32_POWERSTATE_PARAMETERS do PopDispatchStateCallout
/// 0x7259b4, que o UserPowerStateCallout do win32kbase lê): Promotion, a
/// POWER_ACTION, o SYSTEM_POWER_STATE mínimo, as flags e a tarefa
/// (POWERSTATETASK). 0x18 bytes no bloco de pilha do NT.
#[repr(C)]
pub struct Win32PowerStateParameters {
    pub promotion: Field<u8>,
    _reserved_01: Reserved<3>,
    pub system_action: Field<u32>,
    pub min_system_state: Field<u32>,
    pub flags: Field<u32>,
    pub power_state_task: Field<u32>,
    _reserved_14: Reserved<4>,
}

unsafe impl NtStruct for Win32PowerStateParameters {}

/// Parâmetro do callout de informação de energia do Win32k (PsW32PowerInfo,
/// tipo 5; o bloco do PopNotifyConsoleUserPresent 0x772ce0, que o
/// W32CalloutDispatch do win32kbase passa campo a campo ao
/// UserPowerInfoCallout): o tipo da informação, um BOOLEAN, a entrada e a
/// saída com os comprimentos. 0x28 bytes.
#[repr(C)]
pub struct Win32PowerInfoParameters {
    pub information_type: Field<u32>,
    pub flag: Field<u8>,
    _reserved_05: Reserved<3>,
    pub input_length: Field<u32>,
    _reserved_0c: Reserved<4>,
    pub input: Field<u64>,
    pub output_length: Field<u32>,
    _reserved_1c: Reserved<4>,
    pub output: Field<u64>,
}

unsafe impl NtStruct for Win32PowerInfoParameters {}

/// A entrada da informação 1 (presença do usuário no console) do callout de
/// informação de energia: o BOOLEAN de presença e o motivo. 8 bytes.
#[repr(C)]
pub struct Win32ConsoleUserPresent {
    pub present: Field<u8>,
    _reserved_01: Reserved<3>,
    pub reason: Field<u32>,
}

unsafe impl NtStruct for Win32ConsoleUserPresent {}

const _: () = {
    assert!(core::mem::size_of::<Win32ThreadCalloutParameters>() == 0x10);
    assert!(core::mem::offset_of!(Win32ThreadCalloutParameters, callout_type) == 0x08);
    assert!(core::mem::size_of::<Win32ProcessCalloutParameters>() == 0x10);
    assert!(core::mem::offset_of!(Win32ProcessCalloutParameters, initialize) == 0x08);
    assert!(core::mem::size_of::<Win32PowerEventParameters>() == 0x10);
    assert!(core::mem::offset_of!(Win32PowerEventParameters, code) == 0x08);
    assert!(core::mem::size_of::<Win32PowerStateParameters>() == 0x18);
    assert!(core::mem::offset_of!(Win32PowerStateParameters, min_system_state) == 0x08);
    assert!(core::mem::offset_of!(Win32PowerStateParameters, power_state_task) == 0x10);
    assert!(core::mem::size_of::<Win32PowerInfoParameters>() == 0x28);
    assert!(core::mem::offset_of!(Win32PowerInfoParameters, flag) == 0x04);
    assert!(core::mem::offset_of!(Win32PowerInfoParameters, input_length) == 0x08);
    assert!(core::mem::offset_of!(Win32PowerInfoParameters, input) == 0x10);
    assert!(core::mem::offset_of!(Win32PowerInfoParameters, output_length) == 0x18);
    assert!(core::mem::offset_of!(Win32PowerInfoParameters, output) == 0x20);
    assert!(core::mem::size_of::<Win32ConsoleUserPresent>() == 0x08);
    assert!(core::mem::offset_of!(Win32ConsoleUserPresent, reason) == 0x04);
};

/// Registro de um atributo de segurança no formato interno do token, que
/// segue o `_AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION` (layout lido de
/// AuthzBasepCopyoutInternalSecurityAttributes do ntoskrnl 19041). 0x70
/// bytes.
#[repr(C)]
pub struct AuthzbasepSecurityAttribute {
    /// Elo na SecurityAttributesList do cabeçalho.
    pub list_link: ListEntry,
    _reserved_10: Reserved<0x10>,
    pub name: UnicodeString,
    pub value_type: Field<u16>,
    _pad_32: Reserved<0x2>,
    pub flags: Field<u32>,
    _reserved_38: Reserved<0x4>,
    pub value_count: Field<u32>,
    _reserved_40: Reserved<0x8>,
    /// Lista dos AuthzbasepSecurityAttributeValue.
    pub values: ListEntry,
    _reserved_58: Reserved<0x8>,
    /// Segunda lista do registro, vazia na cópia.
    pub list_60: ListEntry,
}

unsafe impl NtStruct for AuthzbasepSecurityAttribute {}

/// Valor de um atributo no formato interno (0x40 bytes): o elo na lista de
/// valores do atributo e, a partir de `value`, o inteiro, a UNICODE_STRING
/// de um STRING, a versão de um FQBN (com o nome em `name`) ou o ponteiro
/// dos bytes de um SID/OCTET_STRING (com o tamanho no ULONG de `name`).
#[repr(C)]
pub struct AuthzbasepSecurityAttributeValue {
    pub list_link: ListEntry,
    _reserved_10: Reserved<0x18>,
    pub value: Field<u64>,
    pub name: UnicodeString,
}

unsafe impl NtStruct for AuthzbasepSecurityAttributeValue {}

const _: () = {
    assert!(core::mem::size_of::<AuthzbasepSecurityAttribute>() == 0x70);
    assert!(core::mem::offset_of!(AuthzbasepSecurityAttribute, name) == 0x20);
    assert!(core::mem::offset_of!(AuthzbasepSecurityAttribute, value_type) == 0x30);
    assert!(core::mem::offset_of!(AuthzbasepSecurityAttribute, flags) == 0x34);
    assert!(core::mem::offset_of!(AuthzbasepSecurityAttribute, value_count) == 0x3c);
    assert!(core::mem::offset_of!(AuthzbasepSecurityAttribute, values) == 0x48);
    assert!(core::mem::offset_of!(AuthzbasepSecurityAttribute, list_60) == 0x60);
    assert!(core::mem::size_of::<AuthzbasepSecurityAttributeValue>() == 0x40);
    assert!(core::mem::offset_of!(AuthzbasepSecurityAttributeValue, value) == 0x28);
    assert!(core::mem::offset_of!(AuthzbasepSecurityAttributeValue, name) == 0x30);
};

/// `RM_COMMAND_MESSAGE`: o comando que o LSA manda ao Reference Monitor pela
/// `\SeRmCommandPort` (o layout que o SepRmCommandServerThread do ntoskrnl
/// 19041 lê): o PORT_MESSAGE, o CommandNumber e os parâmetros. 0x200 bytes.
#[repr(C)]
pub struct RmCommandMessage {
    pub message_header: PortMessage,
    pub command_number: Field<u32>,
    pub command_params: [Field<u8>; 0x1D4],
}

unsafe impl NtStruct for RmCommandMessage {}

/// `RM_REPLY_MESSAGE`: a resposta do Reference Monitor, com o PORT_MESSAGE,
/// o ReturnedStatus que o trabalhador do comando grava e o buffer de
/// resposta. 0x200 bytes.
#[repr(C)]
pub struct RmReplyMessage {
    pub message_header: PortMessage,
    pub returned_status: Field<u32>,
    pub reply_buffer: [Field<u8>; 0x1D4],
}

unsafe impl NtStruct for RmReplyMessage {}

const _: () = {
    assert!(core::mem::size_of::<RmCommandMessage>() == 0x200);
    assert!(core::mem::offset_of!(RmCommandMessage, command_number) == 0x28);
    assert!(core::mem::offset_of!(RmCommandMessage, command_params) == 0x2C);
    assert!(core::mem::size_of::<RmReplyMessage>() == 0x200);
    assert!(core::mem::offset_of!(RmReplyMessage, returned_status) == 0x28);
    assert!(core::mem::offset_of!(RmReplyMessage, reply_buffer) == 0x2C);
};

/// `LSA_COMMAND_MESSAGE`: o comando que o Reference Monitor manda ao LSA pela
/// `\SeLsaCommandPort` (o layout que o SepRmDispatchDataToLsa do ntoskrnl
/// 19041, rva 0x34d558, monta e o LsapRmServerThread do lsass.exe recebe): o
/// PORT_MESSAGE, o CommandNumber, o tipo de memória dos parâmetros (1 =
/// imediatos, na própria mensagem; 2 = na vista de 4 KB da conexão; 3 = na
/// memória alocada no processo do LSA) e os parâmetros imediatos (até 0x1D0
/// bytes). 0x200 bytes.
#[repr(C)]
pub struct LsaCommandMessage {
    pub message_header: PortMessage,
    pub command_number: Field<u32>,
    pub command_params_memory_type: Field<u32>,
    pub command_params: [Field<u8>; 0x1D0],
}

unsafe impl NtStruct for LsaCommandMessage {}

/// `SEP_WORK_ITEM`: um item das filas do SepRmCallLsa (layout lido do
/// SepInformLsaOfDeletedLogon, do SepQueueWorkItem, do SepRmCallLsa e do
/// SepRmDispatchDataToLsa do ntoskrnl 19041): o elo da lista, o tipo de
/// memória dos parâmetros (1 = imediatos em CommandParams; 4 e 5 = um bloco
/// de pool apontado por CommandParams, liberado depois do envio), o
/// CommandNumber, o comprimento dos parâmetros, o buffer e o comprimento da
/// resposta (sem buffer, o comando 3 vai como datagrama), o número de
/// sequência que o SepQueueWorkItem dá e o silo de servidor. 0x40 bytes.
#[repr(C)]
pub struct SepWorkItem {
    pub list: ListEntry,
    pub command_params_memory_type: Field<u32>,
    /// Zerado pelo SepInformLsaOfDeletedLogon; nenhuma rotina da fila o lê.
    pub reserved: Field<u32>,
    /// Os 8 bytes dos parâmetros imediatos (o LUID da sessão apagada) ou o
    /// ponteiro para eles.
    pub command_params: Field<u64>,
    pub command_number: Field<u32>,
    pub command_params_length: Field<u32>,
    pub reply_buffer: Field<u64>,
    pub reply_buffer_length: Field<u32>,
    pub sequence_number: Field<u32>,
    /// -> `_EJOB`
    pub server_silo: Field<u64>,
}

unsafe impl NtStruct for SepWorkItem {}

const _: () = {
    assert!(core::mem::size_of::<LsaCommandMessage>() == 0x200);
    assert!(core::mem::offset_of!(LsaCommandMessage, command_number) == 0x28);
    assert!(core::mem::offset_of!(LsaCommandMessage, command_params_memory_type) == 0x2C);
    assert!(core::mem::offset_of!(LsaCommandMessage, command_params) == 0x30);
    assert!(core::mem::size_of::<SepWorkItem>() == 0x40);
    assert!(core::mem::offset_of!(SepWorkItem, command_params_memory_type) == 0x10);
    assert!(core::mem::offset_of!(SepWorkItem, command_params) == 0x18);
    assert!(core::mem::offset_of!(SepWorkItem, command_number) == 0x20);
    assert!(core::mem::offset_of!(SepWorkItem, command_params_length) == 0x24);
    assert!(core::mem::offset_of!(SepWorkItem, reply_buffer) == 0x28);
    assert!(core::mem::offset_of!(SepWorkItem, reply_buffer_length) == 0x30);
    assert!(core::mem::offset_of!(SepWorkItem, sequence_number) == 0x34);
    assert!(core::mem::offset_of!(SepWorkItem, server_silo) == 0x38);
};
