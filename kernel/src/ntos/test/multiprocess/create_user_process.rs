//! NtCreateUserProcess como syscall real (`ps/user/process.rs` sobre
//! `ps/create_context.rs` e o caminho único de `ps/create.rs`):
//!
//! - Um processo pai de teste, real e no anel 3, chama o handler pelo nome
//!   (a tabela 1 de teste do Shadow encaminha ao handler registrado), com o
//!   RTL_USER_PROCESS_PARAMETERS (auto-relativo, com capacidade extra no
//!   diretório corrente, RuntimeData binário de tamanho ímpar e campos do
//!   STARTUPINFO), o PS_CREATE_INFO e a PS_ATTRIBUTE_LIST na memória de
//!   usuário DELE (a seção gravável da própria imagem). O ImageName aponta
//!   para um exe mínimo gravado no volume, que sai com 0x42; a thread é
//!   criada suspensa; o ParentProcess é um handle do pai para o System
//!   (PROCESS_CREATE_PROCESS), com PROCESS_CREATE_FLAGS_INHERIT_HANDLES, e
//!   ErrorMode entra como atributo aceito sem efeito.
//! - Com o pai parado depois da criação, o teste confere: PsCreateSuccess com
//!   a PEB e o bloco de parâmetros do filho; o CLIENT_ID (e o ReturnLength),
//!   a TEB e o SECTION_IMAGE_INFORMATION (entry na base real, subsistema,
//!   máquina) nas saídas; os dois handles válidos na tabela do pai (processo
//!   e thread do filho, com o acesso pedido) e não na do System; o pai
//!   declarado no filho (InheritedFromUniqueProcessId e o registro); a
//!   herança vinda dele (o handle herdável do System no filho com o mesmo
//!   valor, e não o handle herdável do pai que chamou); os
//!   parâmetros entregues ao filho, lidos anexado; e o filho no despachante
//!   sem ter rodado (thread suspensa, ainda STATUS_PENDING) depois de várias
//!   voltas do despachante.
//! - O pai segue: NtResumeThread (contagem anterior 1), NtWaitForSingleObject
//!   no handle do processo (o KPROCESS sinalizado no término), e o filho
//!   saiu com 0x42. Uma imagem inexistente dá STATUS_OBJECT_NAME_NOT_FOUND
//!   com PsCreateFailOnFileOpen, sem handles. O pai sai com o código dele.
//! - Direto no handler, do System: um número de atributo desconhecido, a
//!   ausência do ImageName e um Size errado no PS_CREATE_INFO dão
//!   STATUS_INVALID_PARAMETER; DebugObject e PROCESS_CREATE_FLAGS_SUSPENDED,
//!   STATUS_NOT_SUPPORTED; nenhum cria processo. Com INHERIT_HANDLES e sem
//!   ParentProcess, a criação direta herda os handles de quem chama.
//! - `process_parameters::capture` de um bloco normalizado (Buffers
//!   absolutos) devolve os textos, as capacidades, o RuntimeData, os
//!   escalares e o ambiente; Length > MaximumLength num texto dá
//!   INVALID_PARAMETER e um Buffer desmapeado, ACCESS_VIOLATION.
//!
//! No código anterior o NtCreateUserProcess não tem handler: a chamada do pai
//! devolve STATUS_NOT_IMPLEMENTED e a primeira asserção falha.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::mem::offset_of;
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use crate::hal::amd64::usermode;
use crate::ntos::ex::{service_abi, service_table};
use crate::ntos::inc::types::{ClientId, Eprocess, Ethread, NtStruct, Peb, PsAttribute, PsAttributeList, PsCreateInfo, RtlUserProcessParameters, SectionImageInformation, UnicodeString};
use crate::ntos::ke::{clock, pcr};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::create::{self, CreatedProcess, ImageOrigin};
use crate::ntos::ps::process_parameters;
use crate::ntos::ps::user::file_io::{self, OpenRequest};
use crate::ntos::ps::user::handles::UserProcess;
use crate::ntos::ps::user::process::{self as user_process, RunOptions};
use crate::ntos::ps::user::threads::ThreadHandleObject;
use crate::ntos::ps::user::{index, memory, process_state, state, threads};
use crate::ntos::ps::{process, process_context};

type Assert = fn(bool, &str);

const IMAGE_BASE: u64 = 0x1_4000_0000;
const CHILD_CODE: u32 = 0x42;
const PARENT_CODE: u32 = 0x50;
const CHILD_DOS_PATH: &str = "D:\\FILHOC2.EXE";
const CHILD_NT_PATH: &str = "\\??\\D:\\FILHOC2.EXE";
const MISSING_NT_PATH: &str = "\\??\\D:\\NAOEXISTEC2.EXE";
const COMMAND_LINE: &str = "\"D:\\FILHOC2.EXE\" -c2 argumento";
const CURRENT_DIRECTORY: &str = "D:\\";
/// O MaximumLength do diretório corrente (MAX_PATH WCHARs e o NUL), maior
/// que o texto.
const DIRECTORY_CAPACITY: u16 = 0x20A;
const DLL_PATH: &str = "D:\\;C:\\Windows\\System32";
const WINDOW_TITLE: &str = "janela C2";
const DESKTOP_INFO: &str = "WinSta0\\Default";
/// RuntimeData binário, de tamanho ímpar (o lpReserved2 do STARTUPINFO).
const RUNTIME_DATA: [u8; 5] = [0x05, 0x00, 0x00, 0x00, 0xAB];
const RUNTIME_CAPACITY: u16 = 6;
const ENVIRONMENT: [&str; 2] = ["C2=sim", "PATH=D:\\"];
/// Um pseudo-handle de console, que passa direto.
const CONSOLE_HANDLE: u64 = u64::MAX - 2;
const SHOW_WINDOW: u32 = 5;
const WINDOW_FLAGS: u32 = 1;
const STARTING_X: u32 = 11;
const COUNT_CHARS_X: u32 = 80;
const ALL_ACCESS: u32 = 0x1F_FFFF;
const PROCESS_CREATE_PROCESS: u32 = 0x80;
/// PROCESS_QUERY_LIMITED_INFORMATION: o acesso dos handles herdáveis.
const PROCESS_QUERY_LIMITED: u32 = 0x1000;
/// PROCESS_CREATE_FLAGS_INHERIT_HANDLES e OBJ_INHERIT.
const INHERIT_HANDLES: u32 = 0x4;
const OBJ_INHERIT: u32 = 2;
const SYSTEM_PROCESS_ID: u64 = 4;
/// O código com que o teste termina o filho da criação direta.
const DIRECT_CHILD_CODE: u32 = 0x77;
const STATUS_PENDING: u32 = 0x103;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
/// Valor das células de status antes de o programa escrevê-las.
const UNSET: u32 = 0xFFFF_FFFF;
/// Prazo de cada etapa do pai.
const STAGE_DEADLINE_MS: u64 = 20_000;
/// Voltas extras do despachante com o filho suspenso.
const SUSPENDED_ROUNDS: usize = 64;

// O conteúdo da seção da imagem do pai: o código e, depois, os dados (as
// estruturas que ele passa ao serviço e as células que o teste lê).
const CODE_LIMIT: usize = 0x200;
const PROCESS_HANDLE: usize = 0x200;
const THREAD_HANDLE: usize = 0x208;
const MISSING_PROCESS_HANDLE: usize = 0x210;
const MISSING_THREAD_HANDLE: usize = 0x218;
const CREATE_STATUS: usize = 0x220;
const RESUME_STATUS: usize = 0x224;
const WAIT_STATUS: usize = 0x228;
const MISSING_STATUS: usize = 0x22C;
const PREVIOUS_SUSPEND: usize = 0x230;
/// A etapa liberada pelo teste (0, 1 e 2).
const GO: usize = 0x234;
const CLIENT_ID: usize = 0x240;
const CLIENT_ID_LENGTH: usize = 0x250;
const TEB_ADDRESS: usize = 0x258;
const IMAGE_INFO: usize = 0x260;
const CREATE_INFO: usize = 0x2A0;
const MISSING_INFO: usize = 0x2F8;
const ATTRIBUTES: usize = 0x350;
const MISSING_ATTRIBUTES: usize = 0x418;
const IMAGE_TEXT: usize = 0x440;
const MISSING_TEXT: usize = 0x480;
const ENVIRONMENT_BLOCK: usize = 0x4C0;
const PARAMETERS: usize = 0x500;
/// A entrada do ParentProcess na lista (a quarta).
const PARENT_ENTRY: usize = 3;

// PS_ATTRIBUTE_* (`PsAttributeValue(número, thread, entrada, aditivo)`).
const ATTRIBUTE_PARENT_PROCESS: u64 = 0x6_0000;
const ATTRIBUTE_DEBUG_OBJECT: u64 = 0x6_0001;
const ATTRIBUTE_CLIENT_ID: u64 = 0x1_0003;
const ATTRIBUTE_TEB_ADDRESS: u64 = 0x1_0004;
const ATTRIBUTE_IMAGE_NAME: u64 = 0x2_0005;
const ATTRIBUTE_IMAGE_INFO: u64 = 0x6;
const ATTRIBUTE_ERROR_MODE: u64 = 0x2_0009;
const ATTRIBUTE_UNKNOWN: u64 = 0x2_003F;

// Condições dos saltos (0F 8x).
const JAE: u8 = 0x83;
const JNZ: u8 = 0x85;

/// Os serviços que o pai usa: o NtTerminateProcess pelo número nativo da
/// ntdll de bring-up (que só publica ele entre estes) e os outros pela
/// tabela 1 do Shadow (a thread principal do pai é GUI), numa tabela de
/// teste cujas entradas encaminham ao handler registrado de cada um.
struct Services {
    create_user_process: u32,
    yield_execution: u32,
    resume_thread: u32,
    wait_for_single_object: u32,
    terminate_process: u32,
}

/// Os serviços encaminhados, na ordem da tabela de teste (índices 0x1000..).
const FORWARDED: [&str; 4] = ["NtCreateUserProcess", "NtYieldExecution", "NtResumeThread", "NtWaitForSingleObject"];

/// A tabela compactada dos encaminhadores, na imagem do kernel (a entrada é
/// relativa à tabela e só alcança ±128 MB).
static SERVICE_TABLE: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];
static SERVICE_ARGUMENTS: [AtomicU8; 4] = [const { AtomicU8::new(0) }; 4];

/// Encaminha ao handler pelo nome, como o portão nativo: a pilha do usuário
/// (KPCR.UserRsp, de onde saem os argumentos 5 em diante, sete no
/// NtCreateUserProcess) e o registro de serviço da thread.
fn forward(name: &'static str, arguments: [u64; 4]) -> u64 {
    let rsp = pcr::current().user_rsp.get();
    let record = state::SyscallRecord { raw_arguments: 0, stack: Some(state::ServiceStack { rsp, bytes: service_abi::stack_arguments(name).unwrap_or(0) as u64 * 8 }) };
    let result = state::with_syscall_record(record, || index::invoke_service(name, arguments, 0, rsp));
    result.unwrap_or_else(|error| if error.status != 0 { error.status } else { 0xC000_0001 }) as u64
}

extern "win64" fn create_service(a: u64, b: u64, c: u64, d: u64) -> u64 {
    forward(FORWARDED[0], [a, b, c, d])
}

extern "win64" fn yield_service(a: u64, b: u64, c: u64, d: u64) -> u64 {
    forward(FORWARDED[1], [a, b, c, d])
}

extern "win64" fn resume_service(a: u64, b: u64, c: u64, d: u64) -> u64 {
    forward(FORWARDED[2], [a, b, c, d])
}

extern "win64" fn wait_service(a: u64, b: u64, c: u64, d: u64) -> u64 {
    forward(FORWARDED[3], [a, b, c, d])
}

/// Publica a tabela 1 de teste; devolve a anterior, para restaurar.
fn publish_services() -> Option<[u64; 4]> {
    let saved = service_table::shadow_second_table().ok()?;
    let table = SERVICE_TABLE.as_ptr() as u64;
    let routines: [extern "win64" fn(u64, u64, u64, u64) -> u64; 4] = [create_service, yield_service, resume_service, wait_service];
    for (slot, routine) in SERVICE_TABLE.iter().zip(routines) {
        match service_table::encode_entry(table, routine as usize as u64, 0) {
            Ok(entry) => slot.store(entry, Ordering::Release),
            Err(_) => return None,
        }
    }
    if service_table::publish_shadow_second_table(table, 4, SERVICE_ARGUMENTS.as_ptr() as u64).is_err() {
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

fn services() -> Option<Services> {
    let live = state::with(|state| state.name_by_number.iter().find(|(_, candidate)| candidate.as_str() == "NtTerminateProcess").map(|(&number, _)| number));
    let terminate_process = live.or_else(|| service_abi::NATIVE.entries.iter().find(|entry| entry.1 == "NtTerminateProcess").map(|entry| entry.0))?;
    Some(Services { create_user_process: 0x1000, yield_execution: 0x1001, resume_thread: 0x1002, wait_for_single_object: 0x1003, terminate_process })
}

/// Registradores usados pelo montador.
#[derive(Clone, Copy)]
enum Register {
    Rax = 0,
    Rcx = 1,
    Rdx = 2,
}

/// Montador mínimo de x64 para o pai; rbx guarda a base do conteúdo da
/// seção e os dados são endereçados por `[rbx+deslocamento]`.
struct Code {
    bytes: Vec<u8>,
    /// Saltos para o caminho de falha, remendados no fim.
    failures: Vec<usize>,
}

impl Code {
    fn new() -> Self {
        Self { bytes: Vec::new(), failures: Vec::new() }
    }

    fn put(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn imm32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn here(&self) -> usize {
        self.bytes.len()
    }

    /// `mov r10, rcx; mov eax, número; syscall`.
    fn syscall(&mut self, number: u32) {
        self.put(&[0x49, 0x89, 0xCA, 0xB8]);
        self.imm32(number);
        self.put(&[0x0F, 0x05]);
    }

    fn rel32(&mut self, target: usize) {
        let next = self.here() as i64 + 4;
        self.imm32((target as i64 - next) as i32 as u32);
    }

    fn jmp_to(&mut self, target: usize) {
        self.put(&[0xE9]);
        self.rel32(target);
    }

    fn fail_if_nonzero(&mut self) {
        // test eax, eax; jnz falha
        self.put(&[0x85, 0xC0, 0x0F, JNZ]);
        self.failures.push(self.here());
        self.imm32(0);
    }

    /// `op reg, [rbx+deslocamento]` (REX.W, ModRM com disp32).
    fn rbx_relative(&mut self, opcode: u8, register: Register, offset: usize) {
        self.put(&[0x48, opcode, 0x80 | (register as u8) << 3 | 3]);
        self.imm32(offset as u32);
    }

    fn lea(&mut self, register: Register, offset: usize) {
        self.rbx_relative(0x8D, register, offset);
    }

    fn load(&mut self, register: Register, offset: usize) {
        self.rbx_relative(0x8B, register, offset);
    }

    /// `mov [rbx+deslocamento], eax`.
    fn store_status(&mut self, offset: usize) {
        self.put(&[0x89, 0x83]);
        self.imm32(offset as u32);
    }

    /// `mov qword [rsp+slot], imm32`.
    fn stack_value(&mut self, slot: u8, value: u32) {
        self.put(&[0x48, 0xC7, 0x44, 0x24, slot]);
        self.imm32(value);
    }

    /// `lea rax, [rbx+deslocamento]; mov [rsp+slot], rax`.
    fn stack_address(&mut self, slot: u8, offset: usize) {
        self.lea(Register::Rax, offset);
        self.put(&[0x48, 0x89, 0x44, 0x24, slot]);
    }

    /// Cede a CPU até a etapa `stage` ser liberada pelo teste.
    fn wait_stage(&mut self, services: &Services, stage: u8) {
        let spin = self.here();
        // cmp dword [rbx+GO], stage; jae segue
        self.put(&[0x83, 0xBB]);
        self.imm32(GO as u32);
        self.put(&[stage, 0x0F, JAE]);
        let forward = self.here();
        self.imm32(0);
        self.syscall(services.yield_execution);
        self.jmp_to(spin);
        let offset = (self.here() as i64 - (forward as i64 + 4)) as i32;
        self.bytes[forward..forward + 4].copy_from_slice(&offset.to_le_bytes());
    }

    /// NtCreateUserProcess(&handles, ALL_ACCESS, ALL_ACCESS, NULL, NULL,
    /// flags de processo, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, parâmetros,
    /// info, atributos), com os argumentos 5 a 11 em [rsp+0x28..0x58].
    fn create_user_process(&mut self, services: &Services, handles: (usize, usize), process_flags: u32, info: usize, attributes: usize) {
        self.lea(Register::Rcx, handles.0);
        self.lea(Register::Rdx, handles.1);
        // mov r8d, ALL_ACCESS; mov r9d, ALL_ACCESS
        self.put(&[0x41, 0xB8]);
        self.imm32(ALL_ACCESS);
        self.put(&[0x41, 0xB9]);
        self.imm32(ALL_ACCESS);
        self.stack_value(0x28, 0);
        self.stack_value(0x30, 0);
        self.stack_value(0x38, process_flags);
        self.stack_value(0x40, create::THREAD_CREATE_SUSPENDED);
        self.stack_address(0x48, PARAMETERS);
        self.stack_address(0x50, info);
        self.stack_address(0x58, attributes);
        self.syscall(services.create_user_process);
    }

    /// NtTerminateProcess(-1, código); `jmp $`.
    fn exit(&mut self, services: &Services, code: u32) {
        self.put(&[0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0xBA]);
        self.imm32(code);
        self.syscall(services.terminate_process);
        self.put(&[0xEB, 0xFE]);
    }

    /// O caminho de falha: o processo sai com o NTSTATUS do serviço que
    /// falhou.
    fn failure_path(&mut self, services: &Services) {
        for at in core::mem::take(&mut self.failures) {
            let offset = (self.here() as i64 - (at as i64 + 4)) as i32;
            self.bytes[at..at + 4].copy_from_slice(&offset.to_le_bytes());
        }
        // mov edx, eax; mov rcx, -1
        self.put(&[0x89, 0xC2, 0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF]);
        self.syscall(services.terminate_process);
        self.put(&[0xEB, 0xFE]);
    }
}

/// O endereço de um deslocamento do conteúdo da imagem do pai (a seção
/// começa no RVA 0x1000 e o exe fica na ImageBase preferida, na raiz dele).
fn absolute(offset: usize) -> u64 {
    IMAGE_BASE + 0x1000 + offset as u64
}

fn wide(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// O bloco de ambiente: as variáveis com NUL e o NUL final.
fn environment_block() -> Vec<u8> {
    let mut bytes = Vec::new();
    for variable in ENVIRONMENT {
        bytes.extend(wide(variable));
        bytes.extend([0, 0]);
    }
    bytes.extend([0, 0]);
    bytes
}

/// Monta em `at` (zerado) um RTL_USER_PROCESS_PARAMETERS com os textos logo
/// depois da estrutura; os Buffers valem para quem vê o bloco em `base`
/// (VAs se `normalized`, senão deslocamentos desde a base). O Environment é
/// sempre a VA dada. Devolve o Length.
fn build_parameters(at: u64, base: u64, normalized: bool, environment: u64) -> u64 {
    // SAFETY: memória zerada do chamador (kernel ou região de usuário do
    // processo corrente) com espaço para o bloco.
    let block = unsafe { RtlUserProcessParameters::at(at) };
    let mut offset = RtlUserProcessParameters::SIZE;
    let mut place = |string: &UnicodeString, bytes: &[u8], maximum: u16| {
        guest::write_bytes(at + offset, bytes);
        string.length.set(bytes.len() as u16);
        string.maximum_length.set(maximum);
        string.buffer.set(if normalized { base + offset } else { offset });
        offset += (maximum as u64).next_multiple_of(8);
    };
    let text = |text: &str| (wide(text), text.encode_utf16().count() as u16 * 2 + 2);
    for (string, value) in [(&block.image_path_name, CHILD_DOS_PATH), (&block.command_line, COMMAND_LINE), (&block.dll_path, DLL_PATH), (&block.window_title, WINDOW_TITLE), (&block.desktop_info, DESKTOP_INFO)] {
        let (bytes, maximum) = text(value);
        place(string, &bytes, maximum);
    }
    place(&block.current_directory.dos_path, &wide(CURRENT_DIRECTORY), DIRECTORY_CAPACITY);
    place(&block.runtime_data, &RUNTIME_DATA, RUNTIME_CAPACITY);
    block.flags.set(u32::from(normalized));
    block.environment.set(environment);
    block.environment_size.set(environment_block().len() as u64);
    block.console_handle.set(CONSOLE_HANDLE);
    block.show_window_flags.set(SHOW_WINDOW);
    block.window_flags.set(WINDOW_FLAGS);
    block.starting_x.set(STARTING_X);
    block.count_chars_x.set(COUNT_CHARS_X);
    block.length.set(offset as u32);
    block.maximum_length.set(offset as u32);
    offset
}

/// Uma PS_ATTRIBUTE_LIST em bytes: (atributo, Size, Value, ReturnLength).
fn attribute_list(entries: &[(u64, u64, u64, u64)]) -> Vec<u8> {
    let header = offset_of!(PsAttributeList, attributes);
    let total = header + entries.len() * PsAttribute::SIZE as usize;
    let mut bytes = alloc::vec![0u8; total];
    bytes[..8].copy_from_slice(&(total as u64).to_le_bytes());
    for (index, &(attribute, size, value, return_length)) in entries.iter().enumerate() {
        let at = header + index * PsAttribute::SIZE as usize;
        for (field, word) in [(offset_of!(PsAttribute, attribute), attribute), (offset_of!(PsAttribute, size), size), (offset_of!(PsAttribute, value), value), (offset_of!(PsAttribute, return_length), return_length)] {
            bytes[at + field..at + field + 8].copy_from_slice(&word.to_le_bytes());
        }
    }
    bytes
}

/// Um PS_CREATE_INFO de entrada: Size, PsCreateInitialState e o InitState
/// que o kernel32 passa (WriteOutputOnExit; DLL proibida; leitura extra).
fn create_info(size: u64) -> Vec<u8> {
    let mut bytes = alloc::vec![0u8; PsCreateInfo::SIZE as usize];
    bytes[offset_of!(PsCreateInfo, size)..][..8].copy_from_slice(&size.to_le_bytes());
    bytes[0x10..0x14].copy_from_slice(&0x2000_0001u32.to_le_bytes());
    bytes[0x14..0x18].copy_from_slice(&0x81u32.to_le_bytes());
    bytes
}

/// O exe mínimo do filho: NtTerminateProcess(-1, 0x42).
fn child_image(services: &Services) -> Vec<u8> {
    let mut code = Code::new();
    code.exit(services, CHILD_CODE);
    crate::ntos::test::phase7::single_section_image(IMAGE_BASE, 0x0022, b".text", 0x6000_0020, 0x1000, &code.bytes)
}

/// O pai: cria o filho suspenso, espera a etapa 1, retoma a thread dele,
/// espera o processo, tenta a imagem inexistente, espera a etapa 2 e sai com
/// o código dele. Os dados (estruturas e células) vêm depois do código, numa
/// seção gravável.
fn parent_image(services: &Services) -> Vec<u8> {
    let mut asm = Code::new();
    // sub rsp, 0x88; mov rbx, base do conteúdo
    asm.put(&[0x48, 0x81, 0xEC, 0x88, 0x00, 0x00, 0x00, 0x48, 0xBB]);
    asm.bytes.extend_from_slice(&absolute(0).to_le_bytes());
    asm.create_user_process(services, (PROCESS_HANDLE, THREAD_HANDLE), INHERIT_HANDLES, CREATE_INFO, ATTRIBUTES);
    asm.store_status(CREATE_STATUS);
    asm.fail_if_nonzero();
    asm.wait_stage(services, 1);
    // NtResumeThread(thread, &anterior)
    asm.load(Register::Rcx, THREAD_HANDLE);
    asm.lea(Register::Rdx, PREVIOUS_SUSPEND);
    asm.syscall(services.resume_thread);
    asm.store_status(RESUME_STATUS);
    asm.fail_if_nonzero();
    // NtWaitForSingleObject(processo, FALSE, NULL): xor edx, edx; xor r8d, r8d
    asm.load(Register::Rcx, PROCESS_HANDLE);
    asm.put(&[0x31, 0xD2, 0x45, 0x31, 0xC0]);
    asm.syscall(services.wait_for_single_object);
    asm.store_status(WAIT_STATUS);
    asm.fail_if_nonzero();
    asm.create_user_process(services, (MISSING_PROCESS_HANDLE, MISSING_THREAD_HANDLE), 0, MISSING_INFO, MISSING_ATTRIBUTES);
    asm.store_status(MISSING_STATUS);
    asm.wait_stage(services, 2);
    asm.exit(services, PARENT_CODE);
    asm.failure_path(services);
    assert!(asm.here() <= CODE_LIMIT, "programa do pai maior que a area de codigo");

    let mut content = asm.bytes;
    content.resize(PARAMETERS, 0);
    let put = |content: &mut Vec<u8>, at: usize, bytes: &[u8]| content[at..at + bytes.len()].copy_from_slice(bytes);
    for cell in [CREATE_STATUS, RESUME_STATUS, WAIT_STATUS, MISSING_STATUS, PREVIOUS_SUSPEND] {
        put(&mut content, cell, &UNSET.to_le_bytes());
    }
    put(&mut content, CREATE_INFO, &create_info(PsCreateInfo::SIZE));
    put(&mut content, MISSING_INFO, &create_info(PsCreateInfo::SIZE));
    let image_text = wide(CHILD_NT_PATH);
    let missing_text = wide(MISSING_NT_PATH);
    put(&mut content, IMAGE_TEXT, &image_text);
    put(&mut content, MISSING_TEXT, &missing_text);
    // O ParentProcess é preenchido pelo teste com um handle do pai, antes
    // de ele rodar.
    let attributes = attribute_list(&[
        (ATTRIBUTE_IMAGE_NAME, image_text.len() as u64, absolute(IMAGE_TEXT), 0),
        (ATTRIBUTE_CLIENT_ID, ClientId::SIZE, absolute(CLIENT_ID), absolute(CLIENT_ID_LENGTH)),
        (ATTRIBUTE_IMAGE_INFO, SectionImageInformation::SIZE, absolute(IMAGE_INFO), 0),
        (ATTRIBUTE_PARENT_PROCESS, 8, u64::MAX, 0),
        (ATTRIBUTE_TEB_ADDRESS, 8, absolute(TEB_ADDRESS), 0),
        (ATTRIBUTE_ERROR_MODE, 4, 1, 0),
    ]);
    assert!(ATTRIBUTES + attributes.len() <= MISSING_ATTRIBUTES);
    put(&mut content, ATTRIBUTES, &attributes);
    put(&mut content, MISSING_ATTRIBUTES, &attribute_list(&[(ATTRIBUTE_IMAGE_NAME, missing_text.len() as u64, absolute(MISSING_TEXT), 0)]));
    put(&mut content, ENVIRONMENT_BLOCK, &environment_block());
    // O bloco de parâmetros auto-relativo, montado numa cópia de kernel.
    let scratch = guest::alloc_bytes(0x1000);
    let length = build_parameters(scratch, absolute(PARAMETERS), false, absolute(ENVIRONMENT_BLOCK));
    let block = guest::try_read_bytes(scratch, length as usize).unwrap_or_default();
    guest::free_bytes(scratch);
    content.extend(block);
    crate::ntos::test::phase7::single_section_image(IMAGE_BASE, 0x0022, b".text", 0xE000_0020, 0x1000, &content)
}

/// Uma região do processo corrente (o System) para as chamadas diretas.
struct Scratch {
    block: u64,
}

impl Scratch {
    fn new(size: u64) -> Option<Self> {
        memory::map_user_region(size).ok().map(|block| Self { block })
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Some(region) = memory::find_region(self.block) {
            memory::release_private_region(&region);
        }
    }
}

/// Grava (ou remove) um arquivo na raiz do volume, do System.
fn write_volume_file(path: &str, bytes: &[u8]) -> bool {
    let Some(scratch) = Scratch::new(0x4000) else { return false };
    let (out, iosb, rsp, data) = (scratch.block, scratch.block + 0x20, scratch.block + 0x800, scratch.block + 0x1000);
    let created = file_io::open(out, path, iosb, 5, &OpenRequest { access: 0x4010_0000, share: 0, options: 0x20, ..OpenRequest::default() }).unwrap_or(1);
    let writer = guest::read64(out);
    guest::write_bytes(data, bytes);
    guest::write64(rsp + 0x28, iosb);
    guest::write64(rsp + 0x30, data);
    guest::write32(rsp + 0x38, bytes.len() as u32);
    guest::write64(rsp + 0x40, 0);
    let written = if created == 0 { state::handler("NtWriteFile").map_or(1, |handler| handler(writer, 0, 0, 0, rsp).unwrap_or(1)) } else { 1 };
    if created == 0 {
        let _ = state::close_user_handle(writer, true, false);
    }
    created == 0 && written == 0
}

fn remove_volume_file(path: &str) {
    let Some(scratch) = Scratch::new(0x1000) else { return };
    let _ = file_io::open(scratch.block, path, scratch.block + 0x20, 1, &OpenRequest { access: 0x8011_0000, share: 7, options: 0x1020, ..OpenRequest::default() });
    let _ = state::close_user_handle(guest::read64(scratch.block), true, false);
}

/// Uma célula de 32 bits do pai, lida anexado; `None` se ele já saiu.
fn parent_cell(parent: u64, offset: usize) -> Option<u32> {
    process_state::get(parent)?;
    process_context::with_process(parent, || guest::read32(absolute(offset))).ok()
}

/// Despacha até a célula `offset` do pai deixar de ser [`UNSET`]; devolve o
/// valor, ou `None` se o pai saiu ou o prazo acabou.
fn drive_until(parent: u64, offset: usize) -> Option<u32> {
    let deadline = clock::uptime_ms() + STAGE_DEADLINE_MS;
    loop {
        match parent_cell(parent, offset) {
            Some(value) if value != UNSET => return Some(value),
            Some(_) => {}
            None => return None,
        }
        if clock::uptime_ms() >= deadline || threads::dispatch_one().is_err() {
            return None;
        }
    }
}

/// O que se lê anexado ao filho: o bloco de parâmetros e os campos dele.
struct ChildParameters {
    block: u64,
    flags: u32,
    image_path_name: String,
    command_line: String,
    current_directory: String,
    directory_capacity: u16,
    dll_path: String,
    window_title: String,
    desktop_info: String,
    shell_info_buffer: u64,
    runtime_data: Vec<u8>,
    environment: Vec<String>,
    console_handle: u64,
    scalars: (u32, u32, u32, u32),
}

fn child_parameters(child: u64) -> Option<ChildParameters> {
    // SAFETY: EPROCESS retido pelo teste.
    let peb = unsafe { Eprocess::at(child) }.peb.get();
    process_context::with_process(child, || {
        // SAFETY: a PEB e o bloco são do filho, anexado, montados pelo
        // kernel.
        let block = unsafe { Peb::at(peb) }.process_parameters.get();
        // SAFETY: como acima.
        let parameters = unsafe { RtlUserProcessParameters::at(block) };
        let text = |string: &UnicodeString| state::read_user_wide_string(block + string.buffer.get(), string.length.get() as u64 / 2);
        let runtime = &parameters.runtime_data;
        let environment_bytes = guest::try_read_bytes(parameters.environment.get(), parameters.environment_size.get() as usize).unwrap_or_default();
        let units: Vec<u16> = environment_bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
        ChildParameters {
            block,
            flags: parameters.flags.get(),
            image_path_name: text(&parameters.image_path_name),
            command_line: text(&parameters.command_line),
            current_directory: text(&parameters.current_directory.dos_path),
            directory_capacity: parameters.current_directory.dos_path.maximum_length.get(),
            dll_path: text(&parameters.dll_path),
            window_title: text(&parameters.window_title),
            desktop_info: text(&parameters.desktop_info),
            shell_info_buffer: parameters.shell_info.buffer.get(),
            runtime_data: guest::try_read_bytes(block + runtime.buffer.get(), runtime.length.get() as usize).unwrap_or_default(),
            environment: units.split(|&unit| unit == 0).take_while(|variable| !variable.is_empty()).map(String::from_utf16_lossy).collect(),
            console_handle: parameters.console_handle.get(),
            scalars: (parameters.show_window_flags.get(), parameters.window_flags.get(), parameters.starting_x.get(), parameters.count_chars_x.get()),
        }
    })
    .ok()
}

fn exit_status(process: u64) -> u32 {
    // SAFETY: EPROCESS retido pelo teste.
    unsafe { Eprocess::at(process) }.exit_status.get() as u32
}

pub fn run(assert: Assert) {
    if !usermode::ready() || process::get_current_thread() == 0 {
        assert(false, "ntcreateuserprocess: anel 3 armado e thread corrente");
        return;
    }
    if state::with(|state| state.ntdll_exports.as_ref().is_none_or(|exports| !exports.contains_key("LdrInitializeThunk"))) {
        assert(false, "ntcreateuserprocess: ntdll com LdrInitializeThunk mapeada");
        return;
    }
    let Some(services) = services() else {
        assert(false, "ntcreateuserprocess: numeros de servico da ntdll");
        return;
    };
    assert(write_volume_file(CHILD_NT_PATH, &child_image(&services)), "ntcreateuserprocess: exe do filho gravado no volume");
    // Um handle herdável do System para ele mesmo: o pai declarado do filho
    // do pai real e quem cria na chamada direta.
    let system = process::list_active_processes().into_iter().find(|entry| entry.pid == SYSTEM_PROCESS_ID).map_or(0, |entry| entry.address);
    let system_inheritable = state::alloc_user_handle(alloc::sync::Arc::new(UserProcess { pointer: system, process_id: SYSTEM_PROCESS_ID }), PROCESS_QUERY_LIMITED, OBJ_INHERIT).map_or(0, u64::from);
    assert(system != 0 && system_inheritable != 0, "ntcreateuserprocess: handle herdavel na tabela do System");
    let Some(saved) = publish_services() else {
        assert(false, "ntcreateuserprocess: tabela 1 de teste com os servicos encaminhados");
        return;
    };
    parent_creates_child(assert, &services, system, system_inheritable);
    restore_services(saved);
    rejections(assert);
    creator_inheritance(assert, system, system_inheritable);
    let _ = state::close_user_handle(system_inheritable, true, false);
    capture_normalized(assert);
    remove_volume_file(CHILD_NT_PATH);
    assert(crate::drivers::fs::volume_files::lookup_volume_file(CHILD_NT_PATH).is_none(), "ntcreateuserprocess: exe do filho removido do volume");
    crate::debug_print!("MULTIPROCESS_OK");
}

/// O handle `handle` do processo `child`, lido anexado: um handle de
/// processo para `target`, herdado (OBJ_INHERIT e o acesso dos handles
/// herdáveis); `None` se o valor não existe na tabela dele.
fn inherited(child: u64, handle: u64, target: u64) -> Option<bool> {
    process_context::with_process(child, || state::get_user_handle(handle).map(|entry| entry.kind() == "process" && entry.access() == PROCESS_QUERY_LIMITED && entry.attributes() & OBJ_INHERIT != 0 && entry.downcast::<UserProcess>().is_some_and(|object| object.pointer == target))).ok().flatten()
}

/// O pai real cria o filho pelo NtCreateUserProcess com tudo na memória dele.
fn parent_creates_child(assert: Assert, services: &Services, system: u64, system_inheritable: u64) {
    let request = user_process::windows_process_request(ImageOrigin::Bytes(parent_image(services)), "paic2.exe", "C:\\paic2.exe", &RunOptions::default());
    let created: CreatedProcess = match create::create_user_process(&request) {
        Ok(created) => created,
        Err(failure) => {
            crate::debug_print!("[ntcreateuserprocess] pai nao criado: {}", failure);
            assert(false, "ntcreateuserprocess: processo pai criado");
            return;
        }
    };
    let parent = created.process_pointer;
    process::reference(parent);
    // SAFETY: EPROCESS retido pelo teste.
    let parent_id = unsafe { Eprocess::at(parent) }.unique_process_id.get();
    // O ParentProcess: um handle do pai para o System, com
    // PROCESS_CREATE_PROCESS, na tabela do pai e na lista dele. E um handle
    // herdável do próprio pai, que o filho NÃO recebe: com o ParentProcess,
    // a herança vem do pai declarado.
    let declared = process_context::with_process(parent, || {
        let handle = state::alloc_user_handle(alloc::sync::Arc::new(UserProcess { pointer: system, process_id: SYSTEM_PROCESS_ID }), PROCESS_CREATE_PROCESS, 0).ok()? as u64;
        guest::write64(absolute(ATTRIBUTES + offset_of!(PsAttributeList, attributes) + PARENT_ENTRY * PsAttribute::SIZE as usize + offset_of!(PsAttribute, value)), handle);
        let own = state::alloc_user_handle(alloc::sync::Arc::new(UserProcess { pointer: system, process_id: SYSTEM_PROCESS_ID }), PROCESS_QUERY_LIMITED, OBJ_INHERIT).ok()? as u64;
        Some((handle, own))
    });
    let parent_inheritable = declared.as_ref().ok().copied().flatten().map_or(0, |(_, own)| own);
    assert(system != 0 && parent_inheritable != 0, "ntcreateuserprocess: handle do pai para o System (o ParentProcess declarado) e um handle herdavel do pai");
    // A thread principal do pai é GUI: os serviços encaminhados entram pela
    // tabela 1 do Shadow.
    // SAFETY: a ETHREAD da thread principal, viva enquanto o processo vive.
    unsafe { Ethread::at(created.thread_pointer) }.tcb.set_gui_thread(1);
    let started = match user_process::start_created(created) {
        Ok(started) => started,
        Err(error) => {
            crate::debug_print!("[ntcreateuserprocess] pai nao partiu: {}", error);
            assert(false, "ntcreateuserprocess: processo pai posto no despachante");
            let _ = process::dereference(parent);
            return;
        }
    };

    // Etapa 1: o pai criou o filho e espera.
    let create_status = drive_until(parent, CREATE_STATUS);
    if create_status != Some(0) {
        crate::debug_print!("[ntcreateuserprocess] NtCreateUserProcess do pai: {:x?}", create_status);
    }
    assert(create_status == Some(0), "ntcreateuserprocess: o pai chama o handler pelo nome com parametros, PS_CREATE_INFO e atributos na memoria dele e recebe STATUS_SUCCESS");
    if create_status != Some(0) {
        let _ = create::exit_process(parent, 0xC000_0001);
        let _ = user_process::wait_started(started);
        let _ = process::dereference(parent);
        return;
    }
    // As saídas, lidas na memória do pai.
    let read_parent = |offset: usize| process_context::with_process(parent, || guest::read64(absolute(offset))).unwrap_or(0);
    let (process_handle, thread_handle) = (read_parent(PROCESS_HANDLE), read_parent(THREAD_HANDLE));
    let (child_id, child_thread_id, client_length, teb) = (read_parent(CLIENT_ID + offset_of!(ClientId, unique_process)), read_parent(CLIENT_ID + offset_of!(ClientId, unique_thread)), read_parent(CLIENT_ID_LENGTH), read_parent(TEB_ADDRESS));
    let child = process::list_active_processes().into_iter().find(|entry| entry.pid == child_id).map_or(0, |entry| entry.address);
    if child == 0 {
        assert(false, "ntcreateuserprocess: o filho do CLIENT_ID esta na lista de processos");
        return;
    }
    process::reference(child);
    let main = threads::of_process(child).first().cloned();
    // Voltas do despachante com o pai cedendo a CPU: o filho suspenso não roda.
    for _ in 0..SUSPENDED_ROUNDS {
        let _ = threads::dispatch_one();
    }
    let suspended = main.as_ref().map(|thread| thread.with(|thread| (thread.suspend_count, thread.dead, thread.teb_va)));
    let started_child = process_state::get(child).is_some_and(|state| state.started.load(Ordering::Acquire));
    // SAFETY: EPROCESS retido pelo teste.
    let child_peb = unsafe { Eprocess::at(child) }.peb.get();
    let parameters = child_parameters(child);
    crate::debug_print!("[ntcreateuserprocess] filho pid={:#x} tid={:#x} handles {:#x}/{:#x} suspensa {:?}", child_id, child_thread_id, process_handle, thread_handle, suspended);

    // PS_CREATE_INFO: PsCreateSuccess com a PEB e o bloco do filho.
    let info = process_context::with_process(parent, || {
        // SAFETY: o PS_CREATE_INFO do pai, anexado.
        let info = unsafe { PsCreateInfo::at(absolute(CREATE_INFO)) };
        let success = info.success_state();
        (info.size.get(), info.state.get(), success.peb_address_native.get(), success.user_process_parameters_native.get(), success.current_parameter_flags.get(), success.output_flags.get())
    })
    .ok();
    assert(info.is_some_and(|(size, state, peb, block, flags, output)| size == PsCreateInfo::SIZE && state == PsCreateInfo::SUCCESS && peb == child_peb && peb != 0 && parameters.as_ref().is_some_and(|parameters| parameters.block == block) && flags == 0 && output == 0), "ntcreateuserprocess: PS_CREATE_INFO volta PsCreateSuccess com a PEB e o bloco de parametros do filho");
    // CLIENT_ID, TEB e SECTION_IMAGE_INFORMATION.
    let image = process_context::with_process(parent, || {
        // SAFETY: o SECTION_IMAGE_INFORMATION do pai, anexado.
        let image = unsafe { SectionImageInformation::at(absolute(IMAGE_INFO)) };
        (image.transfer_address.get(), image.sub_system_type.get(), image.machine.get(), image.image_characteristics.get())
    })
    .ok();
    let thread_matches = main.as_ref().is_some_and(|thread| thread.thread_id == child_thread_id) && child_thread_id != child_id;
    assert(thread_matches && client_length == ClientId::SIZE && suspended.is_some_and(|(_, _, own_teb)| own_teb == teb && teb != 0), "ntcreateuserprocess: CLIENT_ID (PID e TID do filho, ReturnLength 16) e a TEB da thread principal nas saidas");
    assert(image == Some((IMAGE_BASE + 0x1000, 3, 0x8664, 0x0022)), "ntcreateuserprocess: SECTION_IMAGE_INFORMATION da imagem do filho (entry na base real, subsistema CUI, AMD64)");
    // Os handles: na tabela do pai, com o acesso pedido; não na do System.
    let in_parent = process_context::with_process(parent, || {
        let process_entry = state::get_user_handle(process_handle);
        let thread_entry = state::get_user_handle(thread_handle);
        let process_ok = process_entry.as_ref().is_some_and(|entry| entry.kind() == "process" && entry.access() == ALL_ACCESS && entry.downcast::<UserProcess>().is_some_and(|object| object.pointer == child));
        let thread_ok = thread_entry.as_ref().is_some_and(|entry| entry.kind() == "thread" && entry.access() == ALL_ACCESS && entry.downcast::<ThreadHandleObject>().is_some_and(|object| object.thread.thread_id == child_thread_id));
        process_ok && thread_ok
    })
    .unwrap_or(false);
    assert(in_parent && state::get_user_handle(process_handle).is_none() && state::get_user_handle(thread_handle).is_none(), "ntcreateuserprocess: handles do processo e da thread do filho validos na tabela do pai, com o acesso pedido, e nao na do System");
    // O pai declarado.
    // SAFETY: EPROCESS retido pelo teste.
    let inherited_from = unsafe { Eprocess::at(child) }.inherited_from_unique_process_id.get();
    let recorded = process::with_record(child, |record| record.parent_id);
    assert(inherited_from == SYSTEM_PROCESS_ID && recorded == Some(SYSTEM_PROCESS_ID) && parent_id != SYSTEM_PROCESS_ID, "ntcreateuserprocess: o ParentProcess declarado vira o pai do filho (InheritedFromUniqueProcessId e o registro)");
    // INHERIT_HANDLES com o ParentProcess: o filho recebe o handle herdável
    // do pai declarado, com o mesmo valor, e não o de quem chamou.
    let from_declared = inherited(child, system_inheritable, system);
    let from_caller = inherited(child, parent_inheritable, system);
    assert(from_declared == Some(true) && from_caller.is_none(), "ntcreateuserprocess: com INHERIT_HANDLES e ParentProcess, o filho herda o handle do pai declarado com o mesmo valor, e nao o de quem chamou");
    // Os parâmetros do pai, entregues ao filho.
    let delivered = parameters.as_ref().is_some_and(|parameters| {
        parameters.flags == 0
            && parameters.image_path_name == CHILD_DOS_PATH
            && parameters.command_line == COMMAND_LINE
            && parameters.current_directory == CURRENT_DIRECTORY
            && parameters.directory_capacity == DIRECTORY_CAPACITY
            && parameters.dll_path == DLL_PATH
            && parameters.window_title == WINDOW_TITLE
            && parameters.desktop_info == DESKTOP_INFO
            && parameters.shell_info_buffer == 0
            && parameters.runtime_data == RUNTIME_DATA
            && parameters.environment.iter().map(String::as_str).eq(ENVIRONMENT)
            && parameters.console_handle == CONSOLE_HANDLE
            && parameters.scalars == (SHOW_WINDOW, WINDOW_FLAGS, STARTING_X, COUNT_CHARS_X)
    });
    if !delivered {
        crate::debug_print!("[ntcreateuserprocess] parametros do filho: {:?}", parameters.as_ref().map(|parameters| (parameters.image_path_name.clone(), parameters.command_line.clone(), parameters.current_directory.clone(), parameters.directory_capacity, parameters.runtime_data.clone(), parameters.environment.clone(), parameters.scalars)));
    }
    assert(delivered, "ntcreateuserprocess: os parametros auto-relativos do pai chegam ao filho (textos, capacidade do diretorio, RuntimeData binario, ambiente, console e STARTUPINFO)");
    assert(started_child && suspended.is_some_and(|(count, dead, _)| count == 1 && !dead) && exit_status(child) == STATUS_PENDING && process_state::get(child).is_some(), "ntcreateuserprocess: o filho entra no despachante com a thread principal suspensa e nao roda");

    // Etapa 2: retomada, espera no handle do processo e a imagem inexistente.
    let _ = process_context::with_process(parent, || guest::write32(absolute(GO), 1));
    let missing_status = drive_until(parent, MISSING_STATUS);
    let cells = [RESUME_STATUS, WAIT_STATUS, PREVIOUS_SUSPEND].map(|cell| parent_cell(parent, cell).unwrap_or(UNSET));
    crate::debug_print!("[ntcreateuserprocess] retomada={:#x} espera={:#x} anterior={} filho saiu com {:#x}; inexistente {:x?}", cells[0], cells[1], cells[2], exit_status(child), missing_status);
    assert(cells == [0, 0, 1], "ntcreateuserprocess: NtResumeThread no handle da thread (contagem anterior 1) e NtWaitForSingleObject no handle do processo voltam STATUS_SUCCESS");
    // SAFETY: EPROCESS retido pelo teste.
    let signalled = unsafe { Eprocess::at(child) }.pcb.header.signal_state.get() == 1;
    assert(exit_status(child) == CHILD_CODE && signalled && process_state::get(child).is_none(), "ntcreateuserprocess: o filho retomado roda, sai com 0x42 e o KPROCESS fica sinalizado");
    let missing = process_context::with_process(parent, || {
        // SAFETY: o PS_CREATE_INFO do pai, anexado.
        let info = unsafe { PsCreateInfo::at(absolute(MISSING_INFO)) };
        (info.state.get(), guest::read64(absolute(MISSING_PROCESS_HANDLE)), guest::read64(absolute(MISSING_THREAD_HANDLE)))
    })
    .ok();
    assert(missing_status == Some(STATUS_OBJECT_NAME_NOT_FOUND) && missing == Some((PsCreateInfo::FAIL_ON_FILE_OPEN, 0, 0)), "ntcreateuserprocess: imagem inexistente da STATUS_OBJECT_NAME_NOT_FOUND com PsCreateFailOnFileOpen e sem handles");

    // O pai sai com o código dele.
    let _ = process_context::with_process(parent, || guest::write32(absolute(GO), 2));
    let parent_exit = user_process::wait_started(started);
    assert(matches!(parent_exit, Ok(PARENT_CODE)) && exit_status(parent) == PARENT_CODE, "ntcreateuserprocess: o pai sai com o proprio codigo");
    drop(main);
    let _ = process::dereference(child);
    let _ = process::dereference(parent);
    crate::ntos::mm::kernel_stack::reap();
}

/// Chama o handler direto, do System, com os buffers em `scratch`; devolve o
/// status e o handle de processo de saída.
fn call_create(scratch: &Scratch, process_flags: u32, info: &[u8], attributes: &[u8]) -> (u32, u64) {
    let (out, info_at, list_at, rsp) = (scratch.block, scratch.block + 0x100, scratch.block + 0x200, scratch.block + 0x800);
    guest::write_bytes(out, &[0u8; 16]);
    guest::write_bytes(info_at, info);
    guest::write_bytes(list_at, attributes);
    for (index, value) in [0u64, 0, process_flags as u64, create::THREAD_CREATE_SUSPENDED as u64, 0, info_at, list_at].into_iter().enumerate() {
        guest::write64(rsp + 0x28 + index as u64 * 8, value);
    }
    let status = state::handler("NtCreateUserProcess").map_or(1, |handler| handler(out, out + 8, ALL_ACCESS as u64, ALL_ACCESS as u64, rsp).unwrap_or(1));
    (status, guest::read64(out))
}

/// Recusas do handler sem criar processo.
fn rejections(assert: Assert) {
    let Some(scratch) = Scratch::new(0x2000) else {
        assert(false, "ntcreateuserprocess: memoria para as recusas");
        return;
    };
    let name = scratch.block + 0x600;
    let text = wide(CHILD_NT_PATH);
    guest::write_bytes(name, &text);
    let image_name = (ATTRIBUTE_IMAGE_NAME, text.len() as u64, name, 0);
    let before = process::list_active_processes().len();
    let valid = create_info(PsCreateInfo::SIZE);
    let unknown = call_create(&scratch, 0, &valid, &attribute_list(&[image_name, (ATTRIBUTE_UNKNOWN, 4, 0, 0)]));
    let debug = call_create(&scratch, 0, &valid, &attribute_list(&[image_name, (ATTRIBUTE_DEBUG_OBJECT, 8, 0, 0)]));
    let nameless = call_create(&scratch, 0, &valid, &attribute_list(&[(ATTRIBUTE_ERROR_MODE, 4, 0, 0)]));
    let short_info = call_create(&scratch, 0, &create_info(0x50), &attribute_list(&[image_name]));
    let suspended_process = call_create(&scratch, 0x200, &valid, &attribute_list(&[image_name]));
    crate::debug_print!("[ntcreateuserprocess] recusas: {:x?} {:x?} {:x?} {:x?} {:x?}", unknown, debug, nameless, short_info, suspended_process);
    assert(unknown == (STATUS_INVALID_PARAMETER, 0) && nameless == (STATUS_INVALID_PARAMETER, 0) && short_info == (STATUS_INVALID_PARAMETER, 0), "ntcreateuserprocess: atributo desconhecido, ImageName ausente e PS_CREATE_INFO de tamanho errado dao STATUS_INVALID_PARAMETER");
    assert(debug == (STATUS_NOT_SUPPORTED, 0) && suspended_process == (STATUS_NOT_SUPPORTED, 0), "ntcreateuserprocess: DebugObject e PROCESS_CREATE_FLAGS_SUSPENDED dao STATUS_NOT_SUPPORTED");
    assert(process::list_active_processes().len() == before, "ntcreateuserprocess: nenhuma recusa cria processo");
}

/// INHERIT_HANDLES sem ParentProcess, direto no handler: quem chama (o
/// System) é a fonte da herança. O filho, suspenso, é terminado pelo teste.
fn creator_inheritance(assert: Assert, system: u64, system_inheritable: u64) {
    let Some(scratch) = Scratch::new(0x2000) else {
        assert(false, "ntcreateuserprocess: memoria para a heranca de quem chama");
        return;
    };
    let name = scratch.block + 0x600;
    let text = wide(CHILD_NT_PATH);
    guest::write_bytes(name, &text);
    let (status, process_handle) = call_create(&scratch, INHERIT_HANDLES, &create_info(PsCreateInfo::SIZE), &attribute_list(&[(ATTRIBUTE_IMAGE_NAME, text.len() as u64, name, 0)]));
    let thread_handle = guest::read64(scratch.block + 8);
    let child = state::get_user_handle(process_handle).and_then(|entry| entry.downcast::<UserProcess>().map(|object| object.pointer)).unwrap_or(0);
    let from_creator = if child != 0 { inherited(child, system_inheritable, system) } else { None };
    crate::debug_print!("[ntcreateuserprocess] criacao direta: {:#x}, handles {:#x}/{:#x}, heranca {:?}", status, process_handle, thread_handle, from_creator);
    assert(status == 0 && child != 0 && from_creator == Some(true), "ntcreateuserprocess: com INHERIT_HANDLES sem ParentProcess, o filho herda os handles herdaveis de quem chama, com o mesmo valor");
    if child != 0 {
        create::exit_process(child, DIRECT_CHILD_CODE);
        assert(exit_status(child) == DIRECT_CHILD_CODE && process_state::get(child).is_none(), "ntcreateuserprocess: o filho suspenso da criacao direta termina com o codigo pedido");
    }
    for handle in [thread_handle, process_handle] {
        if handle != 0 {
            let _ = state::close_user_handle(handle, true, false);
        }
    }
    crate::ntos::mm::kernel_stack::reap();
}

/// A captura de um bloco normalizado (Buffers absolutos).
fn capture_normalized(assert: Assert) {
    let Some(scratch) = Scratch::new(0x2000) else {
        assert(false, "ntcreateuserprocess: memoria para a captura");
        return;
    };
    let environment = scratch.block + 0x1800;
    guest::write_bytes(environment, &environment_block());
    build_parameters(scratch.block, scratch.block, true, environment);
    let captured = process_parameters::capture(scratch.block);
    let ok = captured.as_ref().is_ok_and(|parameters| {
        parameters.image_path_name == CHILD_DOS_PATH
            && parameters.command_line == COMMAND_LINE
            && parameters.current_directory == CURRENT_DIRECTORY
            && parameters.capacities.current_directory == DIRECTORY_CAPACITY
            && parameters.dll_path == DLL_PATH
            && parameters.window_title.as_deref() == Some(WINDOW_TITLE)
            && parameters.desktop_info.as_deref() == Some(DESKTOP_INFO)
            && parameters.shell_info.is_none()
            && parameters.runtime_data.as_deref() == Some(&RUNTIME_DATA[..])
            && parameters.capacities.runtime_data == RUNTIME_CAPACITY
            && parameters.environment.iter().map(String::as_str).eq(ENVIRONMENT)
            && parameters.console_handle == CONSOLE_HANDLE
            && (parameters.settings.show_window_flags, parameters.settings.window_flags, parameters.settings.starting_x, parameters.settings.count_chars_x) == (SHOW_WINDOW, WINDOW_FLAGS, STARTING_X, COUNT_CHARS_X)
    });
    if !ok {
        crate::debug_print!("[ntcreateuserprocess] captura normalizada: {:?}", captured.as_ref().map(|parameters| format!("{parameters:?}")));
    }
    assert(ok, "ntcreateuserprocess: captura de um bloco normalizado (Buffers absolutos): textos, capacidades, RuntimeData, ambiente, console e STARTUPINFO");
    // SAFETY: o bloco montado acima, na região do System.
    let block = unsafe { RtlUserProcessParameters::at(scratch.block) };
    let length = block.command_line.length.get();
    block.command_line.length.set(block.command_line.maximum_length.get() + 2);
    let oversized = process_parameters::capture(scratch.block).err();
    block.command_line.length.set(length);
    block.window_title.buffer.set(0x7FFF_FFFE_0000);
    let unmapped = process_parameters::capture(scratch.block).err();
    assert(oversized == Some(STATUS_INVALID_PARAMETER) && unmapped == Some(STATUS_ACCESS_VIOLATION), "ntcreateuserprocess: texto com Length maior que MaximumLength da INVALID_PARAMETER e Buffer desmapeado da ACCESS_VIOLATION");
}
