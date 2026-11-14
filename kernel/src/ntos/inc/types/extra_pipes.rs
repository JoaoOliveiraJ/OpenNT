//! Estruturas públicas dos pipes nomeados (ntifs.h) que não constam dos
//! símbolos do ntoskrnl 19041: as classes de informação de pipe
//! (FilePipeInformation, FilePipeLocalInformation) e os buffers dos FSCTLs
//! de pipe (FSCTL_PIPE_PEEK, FSCTL_PIPE_WAIT,
//! FSCTL_PIPE_QUERY_CLIENT_PROCESS). Os parâmetros de criação
//! (NAMED_PIPE_CREATE_PARAMETERS e MAILSLOT_CREATE_PARAMETERS) constam e
//! são gerados com os outros tipos do Io. Layout x64 do cabeçalho,
//! conferido em compilação.

use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::LargeInteger;

/// `_FILE_PIPE_INFORMATION` (ntifs.h; FilePipeInformation, 8 bytes).
#[repr(C)]
pub struct FilePipeInformation {
    pub read_mode: Field<u32>,
    pub completion_mode: Field<u32>,
}

unsafe impl NtStruct for FilePipeInformation {}

const _: () = {
    assert!(core::mem::size_of::<FilePipeInformation>() == 0x8);
    assert!(core::mem::offset_of!(FilePipeInformation, read_mode) == 0x0);
    assert!(core::mem::offset_of!(FilePipeInformation, completion_mode) == 0x4);
};

/// `_FILE_PIPE_LOCAL_INFORMATION` (ntifs.h; FilePipeLocalInformation,
/// 0x28 bytes).
#[repr(C)]
pub struct FilePipeLocalInformation {
    pub named_pipe_type: Field<u32>,
    pub named_pipe_configuration: Field<u32>,
    pub maximum_instances: Field<u32>,
    pub current_instances: Field<u32>,
    pub inbound_quota: Field<u32>,
    pub read_data_available: Field<u32>,
    pub outbound_quota: Field<u32>,
    pub write_quota_available: Field<u32>,
    pub named_pipe_state: Field<u32>,
    pub named_pipe_end: Field<u32>,
}

unsafe impl NtStruct for FilePipeLocalInformation {}

const _: () = {
    assert!(core::mem::size_of::<FilePipeLocalInformation>() == 0x28);
    assert!(core::mem::offset_of!(FilePipeLocalInformation, named_pipe_type) == 0x0);
    assert!(core::mem::offset_of!(FilePipeLocalInformation, named_pipe_configuration) == 0x4);
    assert!(core::mem::offset_of!(FilePipeLocalInformation, maximum_instances) == 0x8);
    assert!(core::mem::offset_of!(FilePipeLocalInformation, current_instances) == 0xC);
    assert!(core::mem::offset_of!(FilePipeLocalInformation, inbound_quota) == 0x10);
    assert!(core::mem::offset_of!(FilePipeLocalInformation, read_data_available) == 0x14);
    assert!(core::mem::offset_of!(FilePipeLocalInformation, outbound_quota) == 0x18);
    assert!(core::mem::offset_of!(FilePipeLocalInformation, write_quota_available) == 0x1C);
    assert!(core::mem::offset_of!(FilePipeLocalInformation, named_pipe_state) == 0x20);
    assert!(core::mem::offset_of!(FilePipeLocalInformation, named_pipe_end) == 0x24);
};

/// `_FILE_PIPE_PEEK_BUFFER` (ntifs.h; o cabeçalho de 0x10 bytes antes dos
/// dados do FSCTL_PIPE_PEEK).
#[repr(C)]
pub struct FilePipePeekBuffer {
    pub named_pipe_state: Field<u32>,
    pub read_data_available: Field<u32>,
    pub number_of_messages: Field<u32>,
    pub message_length: Field<u32>,
}

unsafe impl NtStruct for FilePipePeekBuffer {}

const _: () = {
    assert!(core::mem::size_of::<FilePipePeekBuffer>() == 0x10);
    assert!(core::mem::offset_of!(FilePipePeekBuffer, read_data_available) == 0x4);
    assert!(core::mem::offset_of!(FilePipePeekBuffer, number_of_messages) == 0x8);
    assert!(core::mem::offset_of!(FilePipePeekBuffer, message_length) == 0xC);
};

/// `_FILE_PIPE_WAIT_FOR_BUFFER` (ntifs.h; o cabeçalho de 0x0E bytes antes do
/// nome do FSCTL_PIPE_WAIT).
#[repr(C)]
pub struct FilePipeWaitForBuffer {
    pub timeout: LargeInteger,
    pub name_length: Field<u32>,
    pub timeout_specified: Field<u8>,
    _pad_d: Reserved<0x1>,
    pub name: Field<u16>,
}

unsafe impl NtStruct for FilePipeWaitForBuffer {}

const _: () = {
    assert!(core::mem::size_of::<FilePipeWaitForBuffer>() == 0x10);
    assert!(core::mem::offset_of!(FilePipeWaitForBuffer, name_length) == 0x8);
    assert!(core::mem::offset_of!(FilePipeWaitForBuffer, timeout_specified) == 0xC);
    assert!(core::mem::offset_of!(FilePipeWaitForBuffer, name) == 0xE);
};

/// `_FILE_PIPE_CLIENT_PROCESS_BUFFER` (ntifs.h; a saída de 0x10 bytes do
/// FSCTL_PIPE_QUERY_CLIENT_PROCESS).
#[repr(C)]
pub struct FilePipeClientProcessBuffer {
    pub client_session: Field<u64>,
    pub client_process: Field<u64>,
}

unsafe impl NtStruct for FilePipeClientProcessBuffer {}

const _: () = {
    assert!(core::mem::size_of::<FilePipeClientProcessBuffer>() == 0x10);
    assert!(core::mem::offset_of!(FilePipeClientProcessBuffer, client_process) == 0x8);
};
