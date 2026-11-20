//! Jobs (`ps/job`) com processos de usuário reais:
//!
//! - O gerente, em anel 3, cria uma IOCP e um job, associa a porta (uma
//!   segunda associação é STATUS_INVALID_PARAMETER), põe
//!   JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 2 (BasicLimit de tamanho errado é
//!   STATUS_INFO_LENGTH_MISMATCH) e atribui três processos criados pelo
//!   teste: o terceiro é recusado com STATUS_QUOTA_EXCEEDED. Ele confere a
//!   contabilidade (2 processos, 2 ativos), a lista de PIDs (inteira e, com
//!   espaço para um só, STATUS_BUFFER_OVERFLOW com a contagem parcial), os
//!   limites lidos de volta, a classe 7 na consulta
//!   (STATUS_INVALID_INFO_CLASS) e o NtIsProcessInJob (com e sem handle de
//!   job); da porta saem NEW_PROCESS (contexto = PID) para cada membro e
//!   ACTIVE_PROCESS_LIMIT. Ele termina os dois membros (um com
//!   STATUS_ACCESS_VIOLATION) e recebe EXIT_PROCESS, ABNORMAL_EXIT_PROCESS e
//!   ACTIVE_PROCESS_ZERO; a contabilidade fica com 0 ativos.
//! - KILL_ON_JOB_CLOSE (recusado na BasicLimit, aceito na ExtendedLimit):
//!   fechar o último handle do job termina o membro com STATUS_SUCCESS; o
//!   NtTerminateJobObject termina o membro de outro job com o status pedido.
//! - Um segundo gerente se atribui a um job (NEW_PROCESS com o próprio PID),
//!   lê o uso de memória dele e põe JOB_OBJECT_LIMIT_JOB_MEMORY 64 KB acima:
//!   comitar 128 KB é STATUS_COMMITMENT_LIMIT com JOB_OBJECT_MSG_JOB_MEMORY_LIMIT,
//!   32 KB cabem. Um job vazio vira filho do dele (NtIsProcessInJob nos dois,
//!   contabilidade dos dois), a reatribuição ao pai é sucesso, e
//!   JOB_OBJECT_LIMIT_PROCESS_MEMORY recusa o commit acima do teto.
//! - Com o segundo gerente parado em cada etapa, o teste chama o
//!   NtCreateUserProcess com ele como ParentProcess: com o limite de
//!   processos ativos do job filho a criação é STATUS_QUOTA_EXCEEDED; o
//!   filho herda o job; CREATE_BREAKAWAY_FROM_JOB de um job sem BREAKAWAY_OK
//!   é STATUS_ACCESS_DENIED e, com ele, o filho fica só no job pai; com
//!   SILENT_BREAKAWAY_OK nos dois o filho fica sem job; PS_ATTRIBUTE_JOB_LIST
//!   põe o filho no job da lista.
//! - Os Zw* de job e o PsAssignProcessToJobObject, de modo kernel.
//!
//! No código anterior os serviços de job não existem: a primeira chamada do
//! gerente devolve STATUS_NOT_IMPLEMENTED e ele sai com esse status.

use alloc::format;
use alloc::vec::Vec;
use core::mem::offset_of;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

use super::create_user_process::{attribute_list, call_create, create_info, remove_volume_file, wide, write_volume_file, Scratch};
use super::pipes::Arg::{Addr, Imm, Load};
use super::pipes::{absolute, image, terminate_number, Asm, Data};
use crate::hal::amd64::usermode;
use crate::ntos::ex::{service_abi, service_table};
use crate::ntos::inc::types::extra_jobs::{JobobjectAssociateCompletionPort, JobobjectBasicAccountingInformation, JobobjectBasicLimitInformation, JobobjectBasicProcessIdList, JobobjectExtendedLimitInformation, JobobjectMemoryUsageInformation};
use crate::ntos::inc::types::{Eprocess, Ethread, IoStatusBlock, NtStruct, ObjectAttributes, PsCreateInfo, UnicodeString};
use crate::ntos::ke::{clock, pcr};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_stack;
use crate::ntos::ps::create::{self, CreatedProcess, ImageOrigin};
use crate::ntos::ps::job;
use crate::ntos::ps::user::handles::UserProcess;
use crate::ntos::ps::user::process::{self as user_process, RunOptions, StartedProcess};
use crate::ntos::ps::user::{csr, index, process_state, state, threads};
use crate::ntos::ps::{process, process_context};
use crate::ntos::test::phase6::call_export;

type Assert = fn(bool, &str);

const MANAGER_CODE: u32 = 0x71;
const SECOND_CODE: u32 = 0x72;
const CLOSER_CODE: u32 = 0x74;
const CHILD_CODE: u32 = 0x73;
const TERMINATE_JOB_CODE: u32 = 0x77;
const MEMBER_CODE: u32 = 0x55;
const KEY_FIRST: u64 = 0x4A0B;
const KEY_SECOND: u64 = 0x4A0C;
const STAGE_DEADLINE_MS: u64 = 20_000;

const STATUS_TIMEOUT: u32 = 0x102;
const STATUS_PROCESS_NOT_IN_JOB: u32 = 0x123;
const STATUS_PROCESS_IN_JOB: u32 = 0x124;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_QUOTA_EXCEEDED: u32 = 0xC000_0044;
const STATUS_COMMITMENT_LIMIT: u32 = 0xC000_012D;

const JOB_ALL_ACCESS: u64 = 0x1F_003F;
const IO_COMPLETION_ALL_ACCESS: u64 = 0x1F_0003;
const PROCESS_ALL_ACCESS: u32 = 0x1F_FFFF;
const PROCESS_CREATE_PROCESS: u32 = 0x80;
const MEM_COMMIT_RESERVE: u64 = 0x3000;
const PAGE_READWRITE: u64 = 4;
/// PROCESS_CREATE_FLAGS_BREAKAWAY.
const CREATE_BREAKAWAY: u32 = 1;
/// PS_ATTRIBUTE_IMAGE_NAME, PS_ATTRIBUTE_PARENT_PROCESS e PS_ATTRIBUTE_JOB_LIST.
const ATTRIBUTE_IMAGE_NAME: u64 = 0x2_0005;
const ATTRIBUTE_PARENT_PROCESS: u64 = 0x6_0000;
const ATTRIBUTE_JOB_LIST: u64 = 0x2_0013;
const CHILD_NT_PATH: &str = "\\??\\D:\\FILHOJOB.EXE";

/// JOB_OBJECT_LIMIT_* e JOB_OBJECT_MSG_*.
const LIMIT_ACTIVE_PROCESS: u32 = 0x8;
const LIMIT_PROCESS_MEMORY: u32 = 0x100;
const LIMIT_JOB_MEMORY: u32 = 0x200;
const LIMIT_BREAKAWAY_OK: u32 = 0x800;
const LIMIT_SILENT_BREAKAWAY_OK: u32 = 0x1000;
const LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;
const MSG_ACTIVE_PROCESS_LIMIT: u32 = 3;
const MSG_ACTIVE_PROCESS_ZERO: u32 = 4;
const MSG_NEW_PROCESS: u32 = 6;
const MSG_EXIT_PROCESS: u32 = 7;
const MSG_ABNORMAL_EXIT_PROCESS: u32 = 8;
const MSG_JOB_MEMORY_LIMIT: u32 = 10;

// Condições dos saltos (0F 8x).
const JE: u8 = 0x84;
const JAE: u8 = 0x83;

/// Os serviços encaminhados, na ordem da tabela de teste (índices 0x1000..).
const FORWARDED: [&str; 11] = [
    "NtCreateIoCompletion",
    "NtRemoveIoCompletion",
    "NtCreateJobObject",
    "NtSetInformationJobObject",
    "NtQueryInformationJobObject",
    "NtAssignProcessToJobObject",
    "NtIsProcessInJob",
    "NtTerminateJobObject",
    "NtAllocateVirtualMemory",
    "NtClose",
    "NtYieldExecution",
];
const CREATE_IO_COMPLETION: u32 = 0x1000;
const REMOVE_IO_COMPLETION: u32 = 0x1001;
const CREATE_JOB: u32 = 0x1002;
const SET_INFORMATION: u32 = 0x1003;
const QUERY_INFORMATION: u32 = 0x1004;
const ASSIGN_PROCESS: u32 = 0x1005;
const IS_PROCESS_IN_JOB: u32 = 0x1006;
const TERMINATE_JOB: u32 = 0x1007;
const ALLOCATE_VIRTUAL_MEMORY: u32 = 0x1008;
const CLOSE: u32 = 0x1009;
const YIELD_EXECUTION: u32 = 0x100A;

static SERVICE_TABLE: [AtomicU32; 11] = [const { AtomicU32::new(0) }; 11];
static SERVICE_ARGUMENTS: [AtomicU8; 11] = [const { AtomicU8::new(0) }; 11];

/// Encaminha ao handler real, como o portão nativo.
fn forward(name: &'static str, arguments: [u64; 4]) -> u64 {
    let rsp = pcr::current().user_rsp.get();
    let record = state::SyscallRecord { raw_arguments: 0, stack: Some(state::ServiceStack { rsp, bytes: service_abi::stack_arguments(name).unwrap_or(0) as u64 * 8 }), user_stack: 0 };
    let result = state::with_syscall_record(record, || index::invoke_service(name, arguments, 0, rsp));
    result.unwrap_or_else(|error| if error.status != 0 { error.status } else { 0xC000_0001 }) as u64
}

macro_rules! forwarders {
    ($($routine:ident = $index:expr;)*) => {
        $(
            extern "win64" fn $routine(a: u64, b: u64, c: u64, d: u64) -> u64 {
                forward(FORWARDED[$index], [a, b, c, d])
            }
        )*
        const ROUTINES: [extern "win64" fn(u64, u64, u64, u64) -> u64; 11] = [$($routine),*];
    };
}

forwarders! {
    create_io_completion_service = 0;
    remove_io_completion_service = 1;
    create_job_service = 2;
    set_information_service = 3;
    query_information_service = 4;
    assign_process_service = 5;
    is_process_in_job_service = 6;
    terminate_job_service = 7;
    allocate_virtual_memory_service = 8;
    close_service = 9;
    yield_execution_service = 10;
}

fn publish_services() -> Option<[u64; 4]> {
    let saved = service_table::shadow_second_table().ok()?;
    let table = SERVICE_TABLE.as_ptr() as u64;
    for (slot, routine) in SERVICE_TABLE.iter().zip(ROUTINES) {
        match service_table::encode_entry(table, routine as usize as u64, 0) {
            Ok(entry) => slot.store(entry, Ordering::Release),
            Err(_) => return None,
        }
    }
    if service_table::publish_shadow_second_table(table, SERVICE_TABLE.len() as u32, SERVICE_ARGUMENTS.as_ptr() as u64).is_err() {
        let _ = service_table::restore_shadow_second_table(saved);
        return None;
    }
    Some(saved)
}

fn restore_services(saved: [u64; 4]) {
    let _ = service_table::restore_shadow_second_table(saved);
    for slot in &SERVICE_TABLE {
        slot.store(0, Ordering::Release);
    }
}

// ---- auxiliares do montador ----------------------------------------------------

/// `mov rax, [src]; mov [dst], rax`.
fn copy_qword(asm: &mut Asm, destination: usize, source: usize) {
    asm.rip(&[0x48, 0x8B, 0x05], source);
    asm.rip(&[0x48, 0x89, 0x05], destination);
}

/// `mov rax, [src]; add rax, imm32; mov [dst], rax`.
fn add_qword(asm: &mut Asm, destination: usize, source: usize, value: u32) {
    asm.rip(&[0x48, 0x8B, 0x05], source);
    asm.put(&[0x48, 0x05]);
    asm.imm32(value);
    asm.rip(&[0x48, 0x89, 0x05], destination);
}

/// O qword da célula não é zero.
fn check_nonzero(asm: &mut Asm, cell: usize, step: u32) {
    asm.rip(&[0x48, 0x8B, 0x05], cell);
    asm.put(&[0x48, 0x85, 0xC0]);
    asm.step_on(JE, step);
}

/// `mov eax, valor; mov [cell], eax`.
fn store_u32(asm: &mut Asm, cell: usize, value: u32) {
    asm.put(&[0xB8]);
    asm.imm32(value);
    asm.rip(&[0x89, 0x05], cell);
}

/// Publica a etapa e cede a CPU até o teste liberá-la (GO >= etapa).
fn wait_stage(asm: &mut Asm, stage_cell: usize, go_cell: usize, stage: u32) {
    store_u32(asm, stage_cell, stage);
    let spin = asm.here();
    asm.rip(&[0x8B, 0x05], go_cell);
    asm.put(&[0x3D]);
    asm.imm32(stage);
    let done = asm.forward(JAE);
    asm.call(YIELD_EXECUTION, &[]);
    asm.put(&[0xE9]);
    let offset = spin as i64 - (asm.here() as i64 + 4);
    asm.imm32(offset as u32);
    asm.bind(done);
}

/// Os campos de uma estrutura num deslocamento dos dados.
fn field(base: usize, offset: usize) -> usize {
    base + offset
}

/// A retirada de um pacote da porta: a mensagem (Information), a chave e o
/// contexto (a célula de PID, ou 0).
struct Removal {
    port: usize,
    key: usize,
    context: usize,
    iosb: usize,
    zero: usize,
}

impl Removal {
    fn new(data: &mut Data, port: usize) -> Self {
        Self { port, key: data.u64(0), context: data.u64(0), iosb: data.alloc(IoStatusBlock::SIZE as usize, 8), zero: data.u64(0) }
    }

    fn expect(&self, asm: &mut Asm, message: u32, key: u64, context: Option<usize>, step: u32) {
        asm.checked(REMOVE_IO_COMPLETION, &[Load(self.port), Addr(self.key), Addr(self.context), Addr(self.iosb), Addr(self.zero)], 0);
        asm.check_u32(self.iosb + offset_of!(IoStatusBlock, information), message, step);
        asm.check_u32(self.key, key as u32, step + 1);
        match context {
            Some(pid) => asm.check_cells(self.context, pid, step + 2),
            None => asm.check_u32(self.context, 0, step + 2),
        }
    }

    fn expect_empty(&self, asm: &mut Asm) {
        asm.checked(REMOVE_IO_COMPLETION, &[Load(self.port), Addr(self.key), Addr(self.context), Addr(self.iosb), Addr(self.zero)], STATUS_TIMEOUT);
    }
}

// ---- o primeiro gerente --------------------------------------------------------

/// As células do primeiro gerente que o teste preenche antes de ele rodar.
struct ManagerCells {
    handles: [usize; 3],
    pids: [usize; 2],
}

fn manager_program(terminate: u32) -> (Vec<u8>, ManagerCells) {
    let mut data = Data::new();
    let handles = [data.u64(0), data.u64(0), data.u64(0)];
    let pids = [data.u64(0), data.u64(0)];
    let (port, job, returned) = (data.u64(0), data.u64(0), data.u64(0));
    let association = data.alloc(JobobjectAssociateCompletionPort::SIZE as usize, 8);
    data.put(association, &KEY_FIRST.to_le_bytes());
    let limits = data.alloc(JobobjectBasicLimitInformation::SIZE as usize, 8);
    data.put(field(limits, offset_of!(JobobjectBasicLimitInformation, limit_flags)), &LIMIT_ACTIVE_PROCESS.to_le_bytes());
    data.put(field(limits, offset_of!(JobobjectBasicLimitInformation, active_process_limit)), &2u32.to_le_bytes());
    let limits_read = data.alloc(JobobjectBasicLimitInformation::SIZE as usize, 8);
    let accounting = data.alloc(JobobjectBasicAccountingInformation::SIZE as usize, 8);
    let list = data.alloc(0x20, 8);
    let removal = Removal::new(&mut data, port);
    let (a, b, c) = (handles[0], handles[1], handles[2]);

    let mut asm = Asm::new(terminate);
    asm.checked(CREATE_IO_COMPLETION, &[Addr(port), Imm(IO_COMPLETION_ALL_ACCESS), Imm(0), Imm(0)], 0);
    asm.checked(CREATE_JOB, &[Addr(job), Imm(JOB_ALL_ACCESS), Imm(0)], 0);
    copy_qword(&mut asm, association + offset_of!(JobobjectAssociateCompletionPort, completion_port), port);
    asm.checked(SET_INFORMATION, &[Load(job), Imm(7), Addr(association), Imm(JobobjectAssociateCompletionPort::SIZE)], 0);
    asm.checked(SET_INFORMATION, &[Load(job), Imm(7), Addr(association), Imm(JobobjectAssociateCompletionPort::SIZE)], STATUS_INVALID_PARAMETER);
    asm.checked(SET_INFORMATION, &[Load(job), Imm(2), Addr(limits), Imm(0x3C)], STATUS_INFO_LENGTH_MISMATCH);
    asm.checked(SET_INFORMATION, &[Load(job), Imm(2), Addr(limits), Imm(JobobjectBasicLimitInformation::SIZE)], 0);
    asm.checked(ASSIGN_PROCESS, &[Load(job), Load(a)], 0);
    asm.checked(ASSIGN_PROCESS, &[Load(job), Load(b)], 0);
    asm.checked(ASSIGN_PROCESS, &[Load(job), Load(c)], STATUS_QUOTA_EXCEEDED);
    // A contabilidade e a lista de PIDs.
    asm.checked(QUERY_INFORMATION, &[Load(job), Imm(1), Addr(accounting), Imm(JobobjectBasicAccountingInformation::SIZE), Addr(returned)], 0);
    asm.check_u32(field(accounting, offset_of!(JobobjectBasicAccountingInformation, total_processes)), 2, 1);
    asm.check_u32(field(accounting, offset_of!(JobobjectBasicAccountingInformation, active_processes)), 2, 2);
    asm.check_u32(returned, JobobjectBasicAccountingInformation::SIZE as u32, 3);
    asm.checked(QUERY_INFORMATION, &[Load(job), Imm(3), Addr(list), Imm(0x20), Addr(returned)], 0);
    asm.check_u32(field(list, offset_of!(JobobjectBasicProcessIdList, number_of_assigned_processes)), 2, 4);
    asm.check_u32(field(list, offset_of!(JobobjectBasicProcessIdList, number_of_process_ids_in_list)), 2, 5);
    asm.check_cells(field(list, 8), pids[0], 6);
    asm.check_cells(field(list, 0x10), pids[1], 7);
    asm.check_u32(returned, 0x18, 8);
    asm.checked(QUERY_INFORMATION, &[Load(job), Imm(3), Addr(list), Imm(0x10), Addr(returned)], STATUS_BUFFER_OVERFLOW);
    asm.check_u32(field(list, offset_of!(JobobjectBasicProcessIdList, number_of_process_ids_in_list)), 1, 9);
    asm.check_u32(returned, 0x18, 10);
    asm.checked(QUERY_INFORMATION, &[Load(job), Imm(7), Addr(list), Imm(0x10), Imm(0)], STATUS_INVALID_INFO_CLASS);
    asm.checked(QUERY_INFORMATION, &[Load(job), Imm(2), Addr(limits_read), Imm(JobobjectBasicLimitInformation::SIZE), Imm(0)], 0);
    asm.check_u32(field(limits_read, offset_of!(JobobjectBasicLimitInformation, limit_flags)), LIMIT_ACTIVE_PROCESS, 11);
    asm.check_u32(field(limits_read, offset_of!(JobobjectBasicLimitInformation, active_process_limit)), 2, 12);
    // NtIsProcessInJob.
    asm.checked(IS_PROCESS_IN_JOB, &[Load(a), Load(job)], STATUS_PROCESS_IN_JOB);
    asm.checked(IS_PROCESS_IN_JOB, &[Load(c), Load(job)], STATUS_PROCESS_NOT_IN_JOB);
    asm.checked(IS_PROCESS_IN_JOB, &[Load(a), Imm(0)], STATUS_PROCESS_IN_JOB);
    asm.checked(IS_PROCESS_IN_JOB, &[Imm(u64::MAX), Imm(0)], STATUS_PROCESS_NOT_IN_JOB);
    // As mensagens das atribuições.
    removal.expect(&mut asm, MSG_NEW_PROCESS, KEY_FIRST, Some(pids[0]), 20);
    removal.expect(&mut asm, MSG_NEW_PROCESS, KEY_FIRST, Some(pids[1]), 23);
    removal.expect(&mut asm, MSG_ACTIVE_PROCESS_LIMIT, KEY_FIRST, None, 26);
    removal.expect_empty(&mut asm);
    // Os membros terminam: um normal, um com uma exceção.
    asm.checked(terminate, &[Load(a), Imm(MEMBER_CODE as u64)], 0);
    asm.checked(terminate, &[Load(b), Imm(STATUS_ACCESS_VIOLATION as u64)], 0);
    removal.expect(&mut asm, MSG_EXIT_PROCESS, KEY_FIRST, Some(pids[0]), 30);
    removal.expect(&mut asm, MSG_ABNORMAL_EXIT_PROCESS, KEY_FIRST, Some(pids[1]), 33);
    removal.expect(&mut asm, MSG_ACTIVE_PROCESS_ZERO, KEY_FIRST, None, 36);
    asm.checked(QUERY_INFORMATION, &[Load(job), Imm(1), Addr(accounting), Imm(JobobjectBasicAccountingInformation::SIZE), Imm(0)], 0);
    asm.check_u32(field(accounting, offset_of!(JobobjectBasicAccountingInformation, active_processes)), 0, 40);
    asm.check_u32(field(accounting, offset_of!(JobobjectBasicAccountingInformation, total_processes)), 2, 41);
    asm.check_u32(field(accounting, offset_of!(JobobjectBasicAccountingInformation, total_terminated_processes)), 0, 42);
    for handle in [job, port] {
        asm.checked(CLOSE, &[Load(handle)], 0);
    }
    asm.exit(MANAGER_CODE);
    (image(&asm.finish(&data)), ManagerCells { handles, pids })
}

/// O terceiro programa: KILL_ON_JOB_CLOSE (recusado na BasicLimit) e o
/// NtTerminateJobObject, com os membros D e E. Devolve as células dos
/// handles deles.
fn closer_program(terminate: u32) -> (Vec<u8>, [usize; 2]) {
    let mut data = Data::new();
    let handles = [data.u64(0), data.u64(0)];
    let (kill_job, terminate_job) = (data.u64(0), data.u64(0));
    let kill = data.alloc(JobobjectExtendedLimitInformation::SIZE as usize, 8);
    data.put(field(kill, offset_of!(JobobjectBasicLimitInformation, limit_flags)), &LIMIT_KILL_ON_JOB_CLOSE.to_le_bytes());
    let mut asm = Asm::new(terminate);
    asm.checked(CREATE_JOB, &[Addr(kill_job), Imm(JOB_ALL_ACCESS), Imm(0)], 0);
    asm.checked(ASSIGN_PROCESS, &[Load(kill_job), Load(handles[0])], 0);
    asm.checked(SET_INFORMATION, &[Load(kill_job), Imm(2), Addr(kill), Imm(JobobjectBasicLimitInformation::SIZE)], STATUS_INVALID_PARAMETER);
    asm.checked(SET_INFORMATION, &[Load(kill_job), Imm(9), Addr(kill), Imm(0x90)], 0);
    asm.checked(CLOSE, &[Load(kill_job)], 0);
    asm.checked(CREATE_JOB, &[Addr(terminate_job), Imm(JOB_ALL_ACCESS), Imm(0)], 0);
    asm.checked(ASSIGN_PROCESS, &[Load(terminate_job), Load(handles[1])], 0);
    asm.checked(TERMINATE_JOB, &[Load(terminate_job), Imm(TERMINATE_JOB_CODE as u64)], 0);
    asm.checked(CLOSE, &[Load(terminate_job)], 0);
    asm.exit(CLOSER_CODE);
    (image(&asm.finish(&data)), handles)
}

// ---- o segundo gerente ---------------------------------------------------------

/// As células do segundo gerente.
struct SecondCells {
    pid: usize,
    stage: usize,
    go: usize,
    parent_job: usize,
    child_job: usize,
}

fn second_program(terminate: u32) -> (Vec<u8>, SecondCells) {
    let mut data = Data::new();
    let pid = data.u64(0);
    let stage = data.u64(0);
    let go = data.u64(0);
    let (port, parent_job, child_job) = (data.u64(0), data.u64(0), data.u64(0));
    let association = data.alloc(JobobjectAssociateCompletionPort::SIZE as usize, 8);
    data.put(association, &KEY_SECOND.to_le_bytes());
    let usage = data.alloc(JobobjectMemoryUsageInformation::SIZE as usize, 8);
    let memory = data.alloc(JobobjectExtendedLimitInformation::SIZE as usize, 8);
    data.put(field(memory, offset_of!(JobobjectBasicLimitInformation, limit_flags)), &LIMIT_JOB_MEMORY.to_le_bytes());
    let memory_read = data.alloc(JobobjectExtendedLimitInformation::SIZE as usize, 8);
    let ceiling = data.alloc(JobobjectExtendedLimitInformation::SIZE as usize, 8);
    data.put(field(ceiling, offset_of!(JobobjectBasicLimitInformation, limit_flags)), &(LIMIT_PROCESS_MEMORY | LIMIT_ACTIVE_PROCESS).to_le_bytes());
    data.put(field(ceiling, offset_of!(JobobjectBasicLimitInformation, active_process_limit)), &1u32.to_le_bytes());
    let breakaway = data.alloc(JobobjectExtendedLimitInformation::SIZE as usize, 8);
    data.put(field(breakaway, offset_of!(JobobjectBasicLimitInformation, limit_flags)), &LIMIT_BREAKAWAY_OK.to_le_bytes());
    let silent = data.alloc(JobobjectExtendedLimitInformation::SIZE as usize, 8);
    data.put(field(silent, offset_of!(JobobjectBasicLimitInformation, limit_flags)), &LIMIT_SILENT_BREAKAWAY_OK.to_le_bytes());
    let accounting = data.alloc(JobobjectBasicAccountingInformation::SIZE as usize, 8);
    let (base, large, small) = (data.u64(0), data.u64(0x2_0000), data.u64(0x8000));
    let removal = Removal::new(&mut data, port);
    let job_memory_limit = memory + offset_of!(JobobjectExtendedLimitInformation, job_memory_limit);

    let mut asm = Asm::new(terminate);
    asm.checked(CREATE_IO_COMPLETION, &[Addr(port), Imm(IO_COMPLETION_ALL_ACCESS), Imm(0), Imm(0)], 0);
    asm.checked(CREATE_JOB, &[Addr(parent_job), Imm(JOB_ALL_ACCESS), Imm(0)], 0);
    copy_qword(&mut asm, association + offset_of!(JobobjectAssociateCompletionPort, completion_port), port);
    asm.checked(SET_INFORMATION, &[Load(parent_job), Imm(7), Addr(association), Imm(JobobjectAssociateCompletionPort::SIZE)], 0);
    asm.checked(ASSIGN_PROCESS, &[Load(parent_job), Imm(u64::MAX)], 0);
    removal.expect(&mut asm, MSG_NEW_PROCESS, KEY_SECOND, Some(pid), 1);
    // O limite de memória do job: o uso atual + 64 KB.
    asm.checked(QUERY_INFORMATION, &[Load(parent_job), Imm(28), Addr(usage), Imm(0x10), Imm(0)], 0);
    check_nonzero(&mut asm, usage + offset_of!(JobobjectMemoryUsageInformation, job_memory), 4);
    add_qword(&mut asm, job_memory_limit, usage + offset_of!(JobobjectMemoryUsageInformation, job_memory), 0x1_0000);
    asm.checked(SET_INFORMATION, &[Load(parent_job), Imm(9), Addr(memory), Imm(0x90)], 0);
    asm.checked(ALLOCATE_VIRTUAL_MEMORY, &[Imm(u64::MAX), Addr(base), Imm(0), Addr(large), Imm(MEM_COMMIT_RESERVE), Imm(PAGE_READWRITE)], STATUS_COMMITMENT_LIMIT);
    removal.expect(&mut asm, MSG_JOB_MEMORY_LIMIT, KEY_SECOND, Some(pid), 5);
    asm.put(&[0x48, 0x31, 0xC0]);
    asm.rip(&[0x48, 0x89, 0x05], base);
    asm.checked(ALLOCATE_VIRTUAL_MEMORY, &[Imm(u64::MAX), Addr(base), Imm(0), Addr(small), Imm(MEM_COMMIT_RESERVE), Imm(PAGE_READWRITE)], 0);
    asm.checked(QUERY_INFORMATION, &[Load(parent_job), Imm(9), Addr(memory_read), Imm(0x90), Imm(0)], 0);
    asm.check_u32(field(memory_read, offset_of!(JobobjectBasicLimitInformation, limit_flags)), LIMIT_JOB_MEMORY, 8);
    asm.check_cells(memory_read + offset_of!(JobobjectExtendedLimitInformation, job_memory_limit), job_memory_limit, 9);
    // O job vazio vira filho do job do processo.
    asm.checked(CREATE_JOB, &[Addr(child_job), Imm(JOB_ALL_ACCESS), Imm(0)], 0);
    asm.checked(ASSIGN_PROCESS, &[Load(child_job), Imm(u64::MAX)], 0);
    asm.checked(IS_PROCESS_IN_JOB, &[Imm(u64::MAX), Load(child_job)], STATUS_PROCESS_IN_JOB);
    asm.checked(IS_PROCESS_IN_JOB, &[Imm(u64::MAX), Load(parent_job)], STATUS_PROCESS_IN_JOB);
    for (job, step) in [(child_job, 10), (parent_job, 12)] {
        asm.checked(QUERY_INFORMATION, &[Load(job), Imm(1), Addr(accounting), Imm(JobobjectBasicAccountingInformation::SIZE), Imm(0)], 0);
        asm.check_u32(field(accounting, offset_of!(JobobjectBasicAccountingInformation, total_processes)), 1, step);
        asm.check_u32(field(accounting, offset_of!(JobobjectBasicAccountingInformation, active_processes)), 1, step + 1);
    }
    asm.checked(ASSIGN_PROCESS, &[Load(parent_job), Imm(u64::MAX)], 0);
    // O teto de commit do processo (o uso no job filho + 64 KB) e um processo
    // ativo no máximo.
    asm.checked(QUERY_INFORMATION, &[Load(child_job), Imm(28), Addr(usage), Imm(0x10), Imm(0)], 0);
    add_qword(&mut asm, ceiling + offset_of!(JobobjectExtendedLimitInformation, process_memory_limit), usage + offset_of!(JobobjectMemoryUsageInformation, job_memory), 0x1_0000);
    asm.checked(SET_INFORMATION, &[Load(child_job), Imm(9), Addr(ceiling), Imm(0x90)], 0);
    asm.put(&[0x48, 0x31, 0xC0]);
    asm.rip(&[0x48, 0x89, 0x05], base);
    asm.checked(ALLOCATE_VIRTUAL_MEMORY, &[Imm(u64::MAX), Addr(base), Imm(0), Addr(large), Imm(MEM_COMMIT_RESERVE), Imm(PAGE_READWRITE)], STATUS_COMMITMENT_LIMIT);
    // Etapa 1: a criação com o limite de processos ativos.
    wait_stage(&mut asm, stage, go, 1);
    asm.checked(SET_INFORMATION, &[Load(child_job), Imm(9), Addr(breakaway), Imm(0x90)], 0);
    // Etapa 2: herança e breakaway.
    wait_stage(&mut asm, stage, go, 2);
    asm.checked(SET_INFORMATION, &[Load(child_job), Imm(9), Addr(silent), Imm(0x90)], 0);
    asm.checked(SET_INFORMATION, &[Load(parent_job), Imm(9), Addr(silent), Imm(0x90)], 0);
    // Etapa 3: breakaway silencioso e a JobList.
    wait_stage(&mut asm, stage, go, 3);
    for handle in [child_job, parent_job, port] {
        asm.checked(CLOSE, &[Load(handle)], 0);
    }
    asm.exit(SECOND_CODE);
    (image(&asm.finish(&data)), SecondCells { pid, stage, go, parent_job, child_job })
}

/// O exe dos membros criados pelo teste: sai com CHILD_CODE.
fn child_program(terminate: u32) -> Vec<u8> {
    let data = Data::new();
    let mut asm = Asm::new(terminate);
    asm.exit(CHILD_CODE);
    image(&asm.finish(&data))
}

// ---- o teste -------------------------------------------------------------------

static FAILED: AtomicBool = AtomicBool::new(false);

fn check(assert: Assert, condition: bool, message: &str) {
    if !condition {
        FAILED.store(true, Ordering::SeqCst);
    }
    assert(condition, message);
}

fn eprocess(process: u64) -> &'static Eprocess {
    // SAFETY: EPROCESS retido pelo teste.
    unsafe { Eprocess::at(process) }
}

fn exit_status(process: u64) -> u32 {
    eprocess(process).exit_status.get() as u32
}

fn process_id(process: u64) -> u64 {
    eprocess(process).unique_process_id.get()
}

/// O teste inteiro; `JOBS_OK` sai só se todas as conferências passarem.
pub fn run(assert: Assert) {
    FAILED.store(false, Ordering::SeqCst);
    body(assert);
    if !FAILED.load(Ordering::SeqCst) {
        crate::debug_print!("JOBS_OK");
    }
}

fn body(assert: Assert) {
    if !usermode::ready() || process::get_current_thread() == 0 {
        check(assert, false, "jobs: anel 3 armado e thread corrente");
        return;
    }
    if state::with(|state| state.ntdll_exports.as_ref().is_none_or(|exports| !exports.contains_key("LdrInitializeThunk"))) {
        check(assert, false, "jobs: ntdll com LdrInitializeThunk mapeada");
        return;
    }
    let Some(terminate) = terminate_number() else {
        check(assert, false, "jobs: numero do NtTerminateProcess");
        return;
    };
    let _ = csr::initialize();
    kernel_exports(assert, terminate);
    let Some(saved) = publish_services() else {
        check(assert, false, "jobs: tabela 1 de teste com os servicos encaminhados");
        return;
    };
    first_manager(assert, terminate);
    second_manager(assert, terminate);
    restore_services(saved);
    kernel_stack::reap();
}

/// Um processo de usuário parado (o membro que o teste entrega ao gerente).
fn member(terminate: u32, name: &str) -> Option<CreatedProcess> {
    let request = user_process::windows_process_request(ImageOrigin::Bytes(child_program(terminate)), name, &format!("C:\\{name}"), &RunOptions::default());
    create::create_user_process(&request).ok()
}

/// Um handle de processo com acesso total na tabela de `owner`.
fn process_handle_in(owner: u64, target: u64, access: u32) -> u64 {
    process_state::get(owner).and_then(|table| state::alloc_user_handle_in(&table, alloc::sync::Arc::new(UserProcess { pointer: target, process_id: process_id(target) }), access, 0, None).ok()).map_or(0, u64::from)
}

/// Põe um gerente no despachante (a thread principal GUI: os serviços de
/// teste entram pela tabela 1 do Shadow).
fn launch(created: CreatedProcess) -> Option<StartedProcess> {
    // SAFETY: a ETHREAD da thread principal, viva enquanto o processo vive.
    unsafe { Ethread::at(created.thread_pointer) }.tcb.set_gui_thread(1);
    user_process::start_created(created).ok()
}

fn first_manager(assert: Assert, terminate: u32) {
    let (program, cells) = manager_program(terminate);
    let request = user_process::windows_process_request(ImageOrigin::Bytes(program), "gerente-job.exe", "C:\\gerente-job.exe", &RunOptions::default());
    let Ok(manager) = create::create_user_process(&request) else {
        check(assert, false, "jobs: gerente criado");
        return;
    };
    let manager_pointer = manager.process_pointer;
    process::reference(manager_pointer);
    let members: Vec<CreatedProcess> = ["membro-a.exe", "membro-b.exe", "membro-c.exe", "membro-d.exe", "membro-e.exe"].iter().filter_map(|name| member(terminate, name)).collect();
    if members.len() != 5 {
        check(assert, false, "jobs: membros criados");
        drop(manager);
        let _ = process::dereference(manager_pointer);
        return;
    }
    let pointers: Vec<u64> = members.iter().map(|created| created.process_pointer).collect();
    for &pointer in &pointers {
        process::reference(pointer);
    }
    let _ = process_context::with_process(manager_pointer, || {
        for (cell, &pointer) in cells.handles.iter().zip(&pointers[..3]) {
            guest::write64(absolute(*cell), process_handle_in(manager_pointer, pointer, PROCESS_ALL_ACCESS));
        }
        for (cell, &pointer) in cells.pids.iter().zip(&pointers) {
            guest::write64(absolute(*cell), process_id(pointer));
        }
    });
    let started = launch(manager);
    let exit = started.map(user_process::wait_started);
    check(assert, matches!(exit, Some(Ok(MANAGER_CODE))), "jobs: o gerente cria job e IOCP, limita os processos ativos (o terceiro membro e recusado com STATUS_QUOTA_EXCEEDED), le contabilidade, PIDs e limites, recebe NEW_PROCESS, ACTIVE_PROCESS_LIMIT, EXIT_PROCESS, ABNORMAL_EXIT_PROCESS e ACTIVE_PROCESS_ZERO");
    let (program, closer_cells) = closer_program(terminate);
    let request = user_process::windows_process_request(ImageOrigin::Bytes(program), "fecha-job.exe", "C:\\fecha-job.exe", &RunOptions::default());
    let closer_exit = create::create_user_process(&request).ok().and_then(|closer| {
        let closer_pointer = closer.process_pointer;
        let _ = process_context::with_process(closer_pointer, || {
            for (cell, &member) in closer_cells.iter().zip(&pointers[3..]) {
                guest::write64(absolute(*cell), process_handle_in(closer_pointer, member, PROCESS_ALL_ACCESS));
            }
        });
        launch(closer).map(user_process::wait_started)
    });
    crate::debug_print!("[jobs] gerente: {:x?}; fecha: {:x?}; membros {:x?}", exit.as_ref().map(|exit| exit.as_ref().map_err(|error| format!("{error}"))), closer_exit.as_ref().map(|exit| exit.as_ref().map_err(|error| format!("{error}"))), pointers.iter().map(|&pointer| exit_status(pointer)).collect::<Vec<u32>>());
    check(assert, matches!(closer_exit, Some(Ok(CLOSER_CODE))), "jobs: KILL_ON_JOB_CLOSE e recusado na BasicLimit e aceito na ExtendedLimit; NtTerminateJobObject devolve sucesso");
    check(assert, exit_status(pointers[0]) == MEMBER_CODE && exit_status(pointers[1]) == STATUS_ACCESS_VIOLATION, "jobs: os membros terminados pelo gerente saem com os codigos dele");
    check(assert, exit_status(pointers[3]) == 0 && process_state::get(pointers[3]).is_none(), "jobs: KILL_ON_JOB_CLOSE termina o membro com STATUS_SUCCESS no fechamento do ultimo handle");
    check(assert, exit_status(pointers[4]) == TERMINATE_JOB_CODE && process_state::get(pointers[4]).is_none(), "jobs: NtTerminateJobObject termina o membro com o status pedido");
    check(assert, eprocess(pointers[2]).job.get() == 0, "jobs: o membro recusado fica sem job");
    drop(members);
    for pointer in pointers {
        let _ = process::dereference(pointer);
    }
    let _ = process::dereference(manager_pointer);
}

/// Uma célula de 32 bits do gerente, lida anexado; `None` se ele já saiu.
fn cell(process: u64, offset: usize) -> Option<u32> {
    process_state::get(process)?;
    process_context::with_process(process, || guest::read32(absolute(offset))).ok()
}

/// Despacha até a célula de etapa do gerente chegar a `stage`.
fn drive_until_stage(process: u64, offset: usize, stage: u32) -> bool {
    let started = clock::uptime_ms();
    let deadline = started + STAGE_DEADLINE_MS;
    loop {
        match cell(process, offset) {
            Some(value) if value == stage => return true,
            Some(_) => {}
            None => {
                crate::debug_print!("[jobs] o gerente saiu antes da etapa {} com {:#x} ({} ms)", stage, exit_status(process), clock::uptime_ms() - started);
                return false;
            }
        }
        if clock::uptime_ms() >= deadline {
            crate::debug_print!("[jobs] etapa {} nao alcancada em {} ms (celula {:?})", stage, STAGE_DEADLINE_MS, cell(process, offset));
            return false;
        }
        if let Err(error) = threads::dispatch_round() {
            crate::debug_print!("[jobs] despacho falhou esperando a etapa {}: {}", stage, error);
            return false;
        }
    }
}

/// O EJOB de um handle do gerente (referenciado; solto com `release_job`).
fn job_of_handle(process: u64, offset: usize) -> u64 {
    process_context::with_process(process, || {
        let handle = guest::read64(absolute(offset));
        job::object::reference_by_handle(handle, 4, 0).unwrap_or(0)
    })
    .unwrap_or(0)
}

/// O NtCreateUserProcess direto, do System, com o gerente como
/// ParentProcess (e uma JobList opcional): o status e o filho (suspenso).
fn create_child(parent_handle: u64, process_flags: u32, job_list: Option<u64>) -> (u32, u64) {
    let Some(scratch) = Scratch::new(0x2000) else { return (1, 0) };
    let name = scratch.block + 0x600;
    let text = wide(CHILD_NT_PATH);
    guest::write_bytes(name, &text);
    let list = scratch.block + 0x700;
    let mut entries = alloc::vec![(ATTRIBUTE_IMAGE_NAME, text.len() as u64, name, 0), (ATTRIBUTE_PARENT_PROCESS, 8, parent_handle, 0)];
    if let Some(handle) = job_list {
        guest::write64(list, handle);
        entries.push((ATTRIBUTE_JOB_LIST, 8, list, 0));
    }
    let (status, handle) = call_create(&scratch, process_flags, &create_info(PsCreateInfo::SIZE), &attribute_list(&entries));
    let thread_handle = guest::read64(scratch.block + 8);
    let child = if status == 0 { state::get_user_handle(handle).and_then(|entry| entry.downcast::<UserProcess>().map(|object| object.pointer)).unwrap_or(0) } else { 0 };
    if child != 0 {
        process::reference(child);
    }
    for value in [thread_handle, handle] {
        if value != 0 {
            let _ = state::close_user_handle(value, true, false);
        }
    }
    (status, child)
}

/// Termina e solta um filho da criação direta.
fn discard_child(child: u64) {
    if child != 0 {
        create::exit_process(child, CHILD_CODE);
        let _ = process::dereference(child);
    }
}

fn second_manager(assert: Assert, terminate: u32) {
    check(assert, write_volume_file(CHILD_NT_PATH, &child_program(terminate)), "jobs: exe do filho gravado no volume");
    let (program, cells) = second_program(terminate);
    let request = user_process::windows_process_request(ImageOrigin::Bytes(program), "gerente2-job.exe", "C:\\gerente2-job.exe", &RunOptions::default());
    let Ok(manager) = create::create_user_process(&request) else {
        check(assert, false, "jobs: segundo gerente criado");
        return;
    };
    let pointer = manager.process_pointer;
    process::reference(pointer);
    let _ = process_context::with_process(pointer, || guest::write64(absolute(cells.pid), process_id(pointer)));
    // O ParentProcess das criações diretas: um handle do System para o gerente.
    let parent_handle = process_handle_in(process::get_system_process(), pointer, PROCESS_CREATE_PROCESS);
    let Some(started) = launch(manager) else {
        check(assert, false, "jobs: segundo gerente posto no despachante");
        let _ = process::dereference(pointer);
        return;
    };
    let mut stage_ok = drive_until_stage(pointer, cells.stage, 1);
    check(assert, stage_ok, "jobs: o segundo gerente se poe num job, recebe NEW_PROCESS, estoura JOB_OBJECT_LIMIT_JOB_MEMORY (STATUS_COMMITMENT_LIMIT e JOB_MEMORY_LIMIT), aninha um job vazio e estoura o teto de commit do processo");
    if stage_ok {
        let (parent_job, child_job) = (job_of_handle(pointer, cells.parent_job), job_of_handle(pointer, cells.child_job));
        // Etapa 1: o job filho aceita um processo ativo só e não deixa sair.
        let (quota, refused) = create_child(parent_handle, 0, None);
        check(assert, quota == STATUS_QUOTA_EXCEEDED && refused == 0, "jobs: o filho de um membro herda o job, e o limite de processos ativos recusa a criacao com STATUS_QUOTA_EXCEEDED");
        let (denied, kept) = create_child(parent_handle, CREATE_BREAKAWAY, None);
        check(assert, denied == STATUS_ACCESS_DENIED && kept == 0, "jobs: CREATE_BREAKAWAY_FROM_JOB de um job sem BREAKAWAY_OK e STATUS_ACCESS_DENIED");
        let _ = process_context::with_process(pointer, || guest::write32(absolute(cells.go), 1));
        stage_ok = drive_until_stage(pointer, cells.stage, 2);
        check(assert, stage_ok, "jobs: o segundo gerente chega a etapa 2");
        if stage_ok {
            let (status, inherited) = create_child(parent_handle, 0, None);
            let in_child = inherited != 0 && job::membership::is_process_in_job(inherited, child_job) == STATUS_PROCESS_IN_JOB && job::membership::is_process_in_job(inherited, parent_job) == STATUS_PROCESS_IN_JOB;
            check(assert, status == 0 && in_child, "jobs: o filho de um membro fica no job dele (e no pai)");
            discard_child(inherited);
            let (status, broke) = create_child(parent_handle, CREATE_BREAKAWAY, None);
            let only_parent = broke != 0 && job::membership::is_process_in_job(broke, child_job) == STATUS_PROCESS_NOT_IN_JOB && job::membership::is_process_in_job(broke, parent_job) == STATUS_PROCESS_IN_JOB;
            check(assert, status == 0 && only_parent, "jobs: CREATE_BREAKAWAY_FROM_JOB com BREAKAWAY_OK sai so do job que deixa");
            discard_child(broke);
        }
        let _ = process_context::with_process(pointer, || guest::write32(absolute(cells.go), 2));
        stage_ok = stage_ok && drive_until_stage(pointer, cells.stage, 3);
        check(assert, stage_ok, "jobs: o segundo gerente chega a etapa 3");
        if stage_ok {
            let (status, silent) = create_child(parent_handle, 0, None);
            check(assert, status == 0 && silent != 0 && eprocess(silent).job.get() == 0, "jobs: com SILENT_BREAKAWAY_OK em toda a cadeia o filho fica sem job");
            discard_child(silent);
            // A JobList: um handle do System para o job filho.
            let list_handle = system_job_handle(child_job);
            let (status, listed) = create_child(parent_handle, 0, Some(list_handle));
            check(assert, status == 0 && listed != 0 && eprocess(listed).job.get() == child_job, "jobs: PS_ATTRIBUTE_JOB_LIST poe o filho no job da lista");
            discard_child(listed);
            if list_handle != 0 {
                let _ = call_export("ZwClose", &[list_handle]);
            }
        }
        for job in [parent_job, child_job] {
            if job != 0 {
                job::dereference_job(job);
            }
        }
        let _ = process_context::with_process(pointer, || guest::write32(absolute(cells.go), 3));
    } else {
        create::exit_process(pointer, 0xC000_0001);
    }
    let exit = user_process::wait_started(started);
    crate::debug_print!("[jobs] segundo gerente: {:x?}", exit.as_ref().map_err(|error| format!("{error}")));
    check(assert, matches!(exit, Ok(SECOND_CODE)), "jobs: o segundo gerente sai com o proprio codigo");
    if parent_handle != 0 {
        let _ = state::close_user_handle(parent_handle, true, false);
    }
    let _ = process::dereference(pointer);
    remove_volume_file(CHILD_NT_PATH);
}

/// Um handle de kernel do System para o job (ObOpenObjectByPointer).
fn system_job_handle(job: u64) -> u64 {
    let cell = guest::alloc_bytes(8);
    if cell == 0 {
        return 0;
    }
    guest::write64(cell, 0);
    let status = crate::ntos::ob::open_pointer::open(job, 0, 0, JOB_ALL_ACCESS as u32, job::job_type(), 0, cell);
    let handle = guest::read64(cell);
    guest::free_bytes(cell);
    if matches!(status, Ok(0)) { handle } else { 0 }
}

// ---- os exports de modo kernel ---------------------------------------------------

fn kernel_exports(assert: Assert, terminate: u32) {
    let status = |value: Option<u64>| value.map_or(1, |value| value as u32);
    let Some(created) = member(terminate, "membro-k.exe") else {
        check(assert, false, "jobs: membro de modo kernel criado");
        return;
    };
    let target = created.process_pointer;
    let process_handle = process_handle_in(process::get_system_process(), target, PROCESS_ALL_ACCESS);
    let block = guest::alloc_bytes(0x200);
    guest::write_bytes(block, &[0u8; 0x200]);
    let (out, information, name, attributes, text) = (block, block + 0x10, block + 0x80, block + 0xA0, block + 0x100);
    let path = wide("\\KernelObjects\\OpenNtJobTest");
    guest::write_bytes(text, &path);
    // SAFETY: o bloco do kernel recém-alocado.
    let (string, object) = unsafe { (UnicodeString::at(name), ObjectAttributes::at(attributes)) };
    string.length.set(path.len() as u16);
    string.maximum_length.set(path.len() as u16);
    string.buffer.set(text);
    object.length.set(ObjectAttributes::SIZE as u32);
    object.object_name.set(name);
    let created_status = status(call_export("ZwCreateJobObject", &[out, JOB_ALL_ACCESS, attributes]));
    let handle = guest::read64(out);
    let opened_status = status(call_export("ZwOpenJobObject", &[out + 8, JOB_ALL_ACCESS, attributes]));
    let opened = guest::read64(out + 8);
    check(assert, created_status == 0 && handle != 0 && opened_status == 0 && opened != 0 && opened != handle, "jobs: ZwCreateJobObject com nome e ZwOpenJobObject pelo nome");
    let outside = status(call_export("ZwIsProcessInJob", &[process_handle, handle]));
    let assigned = status(call_export("ZwAssignProcessToJobObject", &[handle, process_handle]));
    let inside = status(call_export("ZwIsProcessInJob", &[process_handle, opened]));
    check(assert, outside == STATUS_PROCESS_NOT_IN_JOB && assigned == 0 && inside == STATUS_PROCESS_IN_JOB, "jobs: ZwAssignProcessToJobObject e ZwIsProcessInJob");
    let again = status(call_export("PsAssignProcessToJobObject", &[eprocess(target).job.get(), target, 0]));
    check(assert, again == 0, "jobs: PsAssignProcessToJobObject de um processo ja no job e sucesso");
    let queried = status(call_export("ZwQueryInformationJobObject", &[handle, 1, information, JobobjectBasicAccountingInformation::SIZE, out + 0x18]));
    // SAFETY: a saída de 0x30 bytes no bloco do kernel.
    let accounting = unsafe { JobobjectBasicAccountingInformation::at(information) };
    check(assert, queried == 0 && accounting.total_processes.get() == 1 && accounting.active_processes.get() == 1 && guest::read32(out + 0x18) == 0x30, "jobs: ZwQueryInformationJobObject devolve a contabilidade");
    guest::write32(block + 0x60, 1);
    let action = status(call_export("ZwSetInformationJobObject", &[handle, 6, block + 0x60, 4]));
    guest::write32(block + 0x60, 2);
    let bad_action = status(call_export("ZwSetInformationJobObject", &[handle, 6, block + 0x60, 4]));
    let read = status(call_export("ZwQueryInformationJobObject", &[handle, 6, block + 0x64, 4, 0]));
    check(assert, action == 0 && bad_action == STATUS_INVALID_PARAMETER && read == 0 && guest::read32(block + 0x64) == 1, "jobs: ZwSetInformationJobObject (fim de tempo: 1 aceito, 2 recusado)");
    let terminated = status(call_export("ZwTerminateJobObject", &[handle, TERMINATE_JOB_CODE as u64]));
    check(assert, terminated == 0 && exit_status(target) == TERMINATE_JOB_CODE, "jobs: ZwTerminateJobObject termina o membro");
    let wrong = status(call_export("ZwIsProcessInJob", &[process_handle, 0x7FF0]));
    check(assert, wrong == 0xC000_0008, "jobs: ZwIsProcessInJob com handle de job invalido");
    for value in [opened, handle] {
        let _ = call_export("ZwClose", &[value]);
    }
    let _ = state::close_user_handle(process_handle, true, false);
    guest::free_bytes(block);
    drop(created);
}
