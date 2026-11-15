//! Os serviços de job do modo usuário: adaptadores do PreviousMode UserMode
//! para a lógica de `ps/job` (NtCreateJobObject, NtOpenJobObject,
//! NtAssignProcessToJobObject, NtTerminateJobObject, NtIsProcessInJob,
//! NtQueryInformationJobObject e NtSetInformationJobObject).

use super::state;
use crate::ntos::ps::job::{information, membership, object};
use crate::rtl::KernelError;

const USER_MODE: u8 = 1;

/// NtCreateJobObject(JobHandle*, DesiredAccess, ObjectAttributes*).
fn nt_create_job_object(handle: u64, access: u64, attributes: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    object::create(handle, access as u32, attributes, USER_MODE)
}

/// NtOpenJobObject(JobHandle*, DesiredAccess, ObjectAttributes*).
fn nt_open_job_object(handle: u64, access: u64, attributes: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    object::open(handle, access as u32, attributes, USER_MODE)
}

/// NtAssignProcessToJobObject(JobHandle, ProcessHandle).
fn nt_assign_process_to_job_object(job: u64, process: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    membership::assign_by_handles(job, process, USER_MODE)
}

/// NtTerminateJobObject(JobHandle, ExitStatus).
fn nt_terminate_job_object(job: u64, exit_status: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(membership::terminate_job(job, exit_status as u32, USER_MODE))
}

/// NtIsProcessInJob(ProcessHandle, JobHandle).
fn nt_is_process_in_job(process: u64, job: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(membership::is_process_in_job_by_handles(process, job, USER_MODE))
}

/// NtQueryInformationJobObject(JobHandle, Class, Information, Length,
/// ReturnLength* na pilha).
fn nt_query_information_job_object(job: u64, class: u64, buffer: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 8) {
        return Ok(0xC000_0005);
    }
    information::query(job, class as u32, buffer, length as u32, state::stack_arg(rsp, 5), USER_MODE)
}

/// NtSetInformationJobObject(JobHandle, Class, Information, Length).
fn nt_set_information_job_object(job: u64, class: u64, buffer: u64, length: u64, _rsp: u64) -> Result<u32, KernelError> {
    information::set(job, class as u32, buffer, length as u32, USER_MODE)
}

pub fn init() {
    state::register_handler("NtCreateJobObject", nt_create_job_object);
    state::register_handler("NtOpenJobObject", nt_open_job_object);
    state::register_handler("NtAssignProcessToJobObject", nt_assign_process_to_job_object);
    state::register_handler("NtTerminateJobObject", nt_terminate_job_object);
    state::register_handler("NtIsProcessInJob", nt_is_process_in_job);
    state::register_handler("NtQueryInformationJobObject", nt_query_information_job_object);
    state::register_handler("NtSetInformationJobObject", nt_set_information_job_object);
}
