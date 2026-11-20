//! NtTraceControl e NtTraceEvent vindos do modo usuário: os serviços de
//! `logger` e `user_registration` com PreviousMode UserMode.

use crate::ntos::ps::user::state;
use crate::rtl::KernelError;

/// NtTraceControl(FunctionCode, InBuffer, InBufferLen, OutBuffer,
/// OutBufferLen, ReturnLength).
fn nt_trace_control(code: u64, input: u64, input_length: u64, output: u64, rsp: u64) -> Result<u32, KernelError> {
    super::logger::trace_control(code as u32, input, input_length as u32, output, state::stack_arg32(rsp, 5), state::stack_arg(rsp, 6), 1)
}

/// NtTraceEvent(TraceHandle, Flags, FieldSize, Fields).
fn nt_trace_event(handle: u64, flags: u64, field_size: u64, fields: u64, _rsp: u64) -> Result<u32, KernelError> {
    super::user_registration::trace_event(handle, flags as u32, field_size as u32, fields, 1)
}

/// Registra os serviços e os tipos EtwRegistration e EtwConsumer.
pub fn init() {
    super::user_registration::initialize_type();
    super::realtime::initialize_type();
    state::register_handler("NtTraceControl", nt_trace_control);
    state::register_handler("NtTraceEvent", nt_trace_event);
}
