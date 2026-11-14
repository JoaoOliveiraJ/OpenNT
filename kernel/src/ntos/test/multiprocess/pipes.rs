//! Pipes nomeados e mailslots entre dois processos, pelos npfs.sys e
//! msfs.sys reais (`io/file/irp_service.rs`, `io/file/pipe_mailslot.rs`, a
//! abertura de `ps/user/files.rs`):
//!
//! - Antes de rodar, chamados no contexto do servidor: a validação do
//!   IopCreateFile no NtCreateNamedPipeFile (ReadMode 2, FILE_SHARE_DELETE,
//!   FILE_SUPERSEDE, opção síncrona sem SYNCHRONIZE, DefaultTimeout
//!   desalinhado) e no NtCreateMailslotFile (FILE_DIRECTORY_FILE) recusa
//!   sem chegar ao driver, com os status do ntoskrnl real.
//! - O servidor, em anel 3, cria um pipe de mensagens e um de bytes
//!   (NtCreateNamedPipeFile em `\??\pipe\...`, síncronos) e um mailslot
//!   (NtCreateMailslotFile em `\??\MAILSLOT\...`) e escuta no primeiro
//!   (FSCTL_PIPE_LISTEN). O teste confere que ele está bloqueado no kernel,
//!   com o IRP do LISTEN pendente no npfs.sys, antes de pôr o cliente no
//!   despachante.
//! - O cliente abre a raiz `\??\pipe\` e espera o pipe (FSCTL_PIPE_WAIT),
//!   abre o pipe de mensagens (NtCreateFile), passa a leitura para modo
//!   mensagem (FilePipeInformation) e confere pela consulta, e faz um
//!   FSCTL_PIPE_TRANSCEIVE ("ping" e a resposta). O servidor, acordado pela
//!   conexão, confere a FilePipeLocalInformation (mensagens, uma instância de
//!   uma, conectado, lado servidor), espera a mensagem pelo FSCTL_PIPE_PEEK
//!   (uma mensagem de 4 bytes, "ping"), lê, consulta o processo do cliente
//!   (o atributo de conexão "ClientProcessId" pelo
//!   FSCTL_PIPE_GET_CONNECTION_ATTRIBUTE = o PID dele, e a resposta do
//!   FSCTL_PIPE_QUERY_CLIENT_PROCESS) e responde "pong".
//! - No pipe de bytes o cliente espera o LISTEN (FSCTL_PIPE_WAIT), abre um
//!   handle assíncrono e escreve "hello world" de uma vez com um evento; o
//!   servidor lê 5 e depois 6 bytes (modo byte) e responde "ok", que o
//!   cliente lê de forma assíncrona: STATUS_PENDING e NtWaitForSingleObject
//!   no evento, sinalizado pela conclusão vinda do outro processo.
//! - O cliente abre o mailslot e escreve "mail"; o servidor o lê (leitura
//!   sem prazo, que espera a mensagem). O servidor desconecta os dois pipes
//!   (FSCTL_PIPE_DISCONNECT), os dois fecham os handles e saem com os
//!   próprios códigos; nenhum IRP dos dois fica vivo.
//!
//! Cada programa confere o que recebe e, num status ou dado inesperado, sai
//! com o NTSTATUS do serviço ou com o código da etapa. As esperas do LISTEN,
//! do TRANSCEIVE, do FSCTL_PIPE_WAIT e da leitura do mailslot bloqueiam de
//! verdade: o anel 3 só roda no processador de boot, então uma espera que
//! girasse dentro do serviço nunca deixaria o outro processo andar.
//!
//! Os programas fazem syscalls de verdade: o NtTerminateProcess pelo número
//! nativo da ntdll de bring-up e os outros pela tabela 1 do Shadow, com a
//! thread principal GUI, numa tabela de teste que encaminha ao handler real.

use alloc::format;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

use crate::hal::amd64::usermode;
use crate::ntos::cm::service::database as service_database;
use crate::ntos::ex::{service_abi, service_table};
use crate::ntos::inc::types::extra_pipes::{FilePipeClientProcessBuffer, FilePipeInformation, FilePipeLocalInformation, FilePipePeekBuffer, FilePipeWaitForBuffer};
use crate::ntos::inc::types::{Eprocess, Ethread, IoStatusBlock, NtStruct, ObjectAttributes, UnicodeString};
use crate::ntos::io::file::irp_service;
use crate::ntos::ke::{clock, pcr};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_stack;
use crate::ntos::ob::object_manager;
use crate::ntos::ps::create::{self, CreatedProcess, ImageOrigin};
use crate::ntos::ps::user::process::{self as user_process, RunOptions, StartedProcess};
use crate::ntos::ps::user::{csr, index, memory, process_state, state, threads};
use crate::ntos::ps::{process, process_context, scheduler};

type Assert = fn(bool, &str);

const IMAGE_BASE: u64 = 0x1_4000_0000;
/// Onde começam os dados no conteúdo da seção (o código vem antes).
const DATA: usize = 0x1000;

const SERVER_CODE: u32 = 0x61;
const CLIENT_CODE: u32 = 0x62;
/// Código de saída de uma etapa que falhou (o NTSTATUS do serviço sai como
/// veio).
const STEP: u32 = 0xE000_0100;
const WAIT_DEADLINE_MS: u64 = 10_000;
/// Voltas do FSCTL_PIPE_PEEK até a mensagem chegar.
const PEEK_ROUNDS: u32 = 2000;

const STATUS_SUCCESS: u32 = 0;
const STATUS_PENDING: u32 = 0x103;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// Direitos e opções (wdm.h/ntifs.h).
const GENERIC_READ: u64 = 0x8000_0000;
const GENERIC_WRITE: u64 = 0x4000_0000;
const SYNCHRONIZE: u64 = 0x10_0000;
const FILE_READ_ATTRIBUTES: u64 = 0x80;
const EVENT_ALL_ACCESS: u64 = 0x1F_0003;
const FILE_SHARE_READ_WRITE: u64 = 3;
const FILE_OPEN: u64 = 1;
const FILE_OPEN_IF: u64 = 3;
const FILE_SUPERSEDE: u64 = 0;
const FILE_SYNCHRONOUS_IO_NONALERT: u64 = 0x20;
const FILE_NON_DIRECTORY_FILE: u64 = 0x40;
const FILE_DIRECTORY_FILE: u64 = 0x1;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
/// Tipos e modos de pipe.
const FILE_PIPE_BYTE_STREAM: u64 = 0;
const FILE_PIPE_MESSAGE: u64 = 1;
const FILE_PIPE_QUEUE_OPERATION: u64 = 0;
const FILE_PIPE_CONNECTED_STATE: u32 = 3;
const FILE_PIPE_SERVER_END: u32 = 1;
/// FSCTLs de pipe (ntifs.h).
const FSCTL_PIPE_DISCONNECT: u64 = 0x11_0004;
const FSCTL_PIPE_LISTEN: u64 = 0x11_0008;
const FSCTL_PIPE_PEEK: u64 = 0x11_400C;
const FSCTL_PIPE_TRANSCEIVE: u64 = 0x11_C017;
const FSCTL_PIPE_WAIT: u64 = 0x11_0018;
const FSCTL_PIPE_QUERY_CLIENT_PROCESS: u64 = 0x11_0024;
const FSCTL_PIPE_GET_CONNECTION_ATTRIBUTE: u64 = 0x11_0030;
/// O nome do atributo de conexão do PID do cliente, ANSI com o NUL.
const CLIENT_PROCESS_ID: &[u8] = b"ClientProcessId\0";
/// Classes de informação.
const FILE_PIPE_INFORMATION: u64 = 23;
const FILE_PIPE_LOCAL_INFORMATION: u64 = 24;

const PIPE_MESSAGES: &str = "opennt-mensagens";
const PIPE_BYTES: &str = "opennt-bytes";
const MAILSLOT: &str = "opennt-correio";

/// Os serviços encaminhados, na ordem da tabela de teste (índices 0x1000..).
const FORWARDED: [&str; 13] = [
    "NtCreateNamedPipeFile",
    "NtCreateMailslotFile",
    "NtFsControlFile",
    "NtReadFile",
    "NtWriteFile",
    "NtCreateFile",
    "NtOpenFile",
    "NtQueryInformationFile",
    "NtSetInformationFile",
    "NtYieldExecution",
    "NtClose",
    "NtCreateEvent",
    "NtWaitForSingleObject",
];
const CREATE_NAMED_PIPE: u32 = 0x1000;
const CREATE_MAILSLOT: u32 = 0x1001;
const FS_CONTROL: u32 = 0x1002;
const READ_FILE: u32 = 0x1003;
const WRITE_FILE: u32 = 0x1004;
const CREATE_FILE: u32 = 0x1005;
const OPEN_FILE: u32 = 0x1006;
const QUERY_INFORMATION: u32 = 0x1007;
const SET_INFORMATION: u32 = 0x1008;
const YIELD_EXECUTION: u32 = 0x1009;
const CLOSE: u32 = 0x100A;
const CREATE_EVENT: u32 = 0x100B;
const WAIT_SINGLE: u32 = 0x100C;

static SERVICE_TABLE: [AtomicU32; 13] = [const { AtomicU32::new(0) }; 13];
static SERVICE_ARGUMENTS: [AtomicU8; 13] = [const { AtomicU8::new(0) }; 13];

/// Encaminha ao handler real, como o portão nativo: a pilha do usuário
/// (KPCR.UserRsp, de onde saem os argumentos 5 em diante) e o registro de
/// serviço da thread.
fn forward(name: &'static str, arguments: [u64; 4]) -> u64 {
    let rsp = pcr::current().user_rsp.get();
    let record = state::SyscallRecord { raw_arguments: 0, stack: Some(state::ServiceStack { rsp, bytes: service_abi::stack_arguments(name).unwrap_or(0) as u64 * 8 }) };
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
        const ROUTINES: [extern "win64" fn(u64, u64, u64, u64) -> u64; 13] = [$($routine),*];
    };
}

forwarders! {
    create_named_pipe_service = 0;
    create_mailslot_service = 1;
    fs_control_service = 2;
    read_file_service = 3;
    write_file_service = 4;
    create_file_service = 5;
    open_file_service = 6;
    query_information_service = 7;
    set_information_service = 8;
    yield_execution_service = 9;
    close_service = 10;
    create_event_service = 11;
    wait_single_service = 12;
}

/// Publica a tabela 1 de teste; devolve a anterior, para restaurar.
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

/// O NtTerminateProcess pelo número nativo da ntdll carregada (o da tabela
/// medida, se ela não o publicou).
fn terminate_number() -> Option<u32> {
    let live = state::with(|state| state.name_by_number.iter().find(|(_, candidate)| candidate.as_str() == "NtTerminateProcess").map(|(&number, _)| number));
    live.or_else(|| service_abi::NATIVE.entries.iter().find(|entry| entry.1 == "NtTerminateProcess").map(|entry| entry.0))
}

/// O endereço de um deslocamento do conteúdo da seção (RVA 0x1000, na
/// ImageBase preferida).
fn absolute(offset: usize) -> u64 {
    IMAGE_BASE + 0x1000 + offset as u64
}

// ---- dados dos programas -------------------------------------------------------

/// A área de dados de um programa, a partir de DATA.
struct Data {
    bytes: Vec<u8>,
}

impl Data {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn alloc(&mut self, size: usize, align: usize) -> usize {
        let at = self.bytes.len().div_ceil(align) * align;
        self.bytes.resize(at + size, 0);
        DATA + at
    }

    fn put(&mut self, offset: usize, bytes: &[u8]) {
        let at = offset - DATA;
        self.bytes[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn bytes(&mut self, bytes: &[u8]) -> usize {
        let at = self.alloc(bytes.len().max(1), 8);
        self.put(at, bytes);
        at
    }

    fn u64(&mut self, value: u64) -> usize {
        self.bytes(&value.to_le_bytes())
    }

    fn wide(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// UNICODE_STRING com o texto logo depois.
    fn unicode(&mut self, text: &str) -> usize {
        let wide = Self::wide(text);
        let header = self.alloc(UnicodeString::SIZE as usize, 8);
        let buffer = self.bytes(&wide);
        let mut string = [0u8; 16];
        string[0..2].copy_from_slice(&(wide.len() as u16).to_le_bytes());
        string[2..4].copy_from_slice(&(wide.len() as u16).to_le_bytes());
        string[8..16].copy_from_slice(&absolute(buffer).to_le_bytes());
        self.put(header, &string);
        header
    }

    /// OBJECT_ATTRIBUTES do nome, sem caixa.
    fn attributes(&mut self, name: &str) -> usize {
        let string = self.unicode(name);
        let at = self.alloc(ObjectAttributes::SIZE as usize, 8);
        let mut block = [0u8; 48];
        block[0..4].copy_from_slice(&(ObjectAttributes::SIZE as u32).to_le_bytes());
        block[16..24].copy_from_slice(&absolute(string).to_le_bytes());
        block[24..28].copy_from_slice(&OBJ_CASE_INSENSITIVE.to_le_bytes());
        self.put(at, &block);
        at
    }

    /// FILE_PIPE_WAIT_FOR_BUFFER do nome (sem a barra), com prazo: o
    /// deslocamento e o tamanho da entrada.
    fn wait_for(&mut self, name: &str, timeout: i64) -> (usize, u64) {
        let wide = Self::wide(name);
        let header = core::mem::offset_of!(FilePipeWaitForBuffer, name);
        let at = self.alloc(header + wide.len(), 8);
        let mut block = alloc::vec![0u8; header + wide.len()];
        block[0..8].copy_from_slice(&timeout.to_le_bytes());
        block[8..12].copy_from_slice(&(wide.len() as u32).to_le_bytes());
        block[12] = 1;
        block[header..].copy_from_slice(&wide);
        self.put(at, &block);
        (at, (header + wide.len()) as u64)
    }
}

// ---- montador dos programas ----------------------------------------------------

/// Um argumento de serviço: imediato, endereço de dado ou o valor (qword)
/// de uma célula.
#[derive(Clone, Copy)]
enum Arg {
    Imm(u64),
    Addr(usize),
    Load(usize),
}

use Arg::{Addr, Imm, Load};

/// Montador mínimo de x64, com endereços de dados relativos ao RIP.
struct Asm {
    code: Vec<u8>,
    /// Saltos para o caminho de falha (o rel32 a remendar).
    failures: Vec<usize>,
    terminate: u32,
}

impl Asm {
    fn new(terminate: u32) -> Self {
        let mut asm = Self { code: Vec::new(), failures: Vec::new(), terminate };
        // sub rsp, 0x98
        asm.put(&[0x48, 0x81, 0xEC, 0x98, 0x00, 0x00, 0x00]);
        asm
    }

    fn put(&mut self, bytes: &[u8]) {
        self.code.extend_from_slice(bytes);
    }

    fn imm32(&mut self, value: u32) {
        self.code.extend_from_slice(&value.to_le_bytes());
    }

    /// `prefixo` seguido do disp32 relativo ao RIP até `target`.
    fn rip(&mut self, prefix: &[u8], target: usize) {
        self.put(prefix);
        let next = self.code.len() + 4;
        self.code.extend_from_slice(&((target as i64 - next as i64) as i32).to_le_bytes());
    }

    /// Argumento de registrador (0 = rcx, 1 = rdx, 2 = r8, 3 = r9).
    fn register(&mut self, index: usize, arg: Arg) {
        const IMM32: [&[u8]; 4] = [&[0xB9], &[0xBA], &[0x41, 0xB8], &[0x41, 0xB9]];
        const SIGNED: [&[u8]; 4] = [&[0x48, 0xC7, 0xC1], &[0x48, 0xC7, 0xC2], &[0x49, 0xC7, 0xC0], &[0x49, 0xC7, 0xC1]];
        const IMM64: [&[u8]; 4] = [&[0x48, 0xB9], &[0x48, 0xBA], &[0x49, 0xB8], &[0x49, 0xB9]];
        const LEA: [&[u8]; 4] = [&[0x48, 0x8D, 0x0D], &[0x48, 0x8D, 0x15], &[0x4C, 0x8D, 0x05], &[0x4C, 0x8D, 0x0D]];
        const LOAD: [&[u8]; 4] = [&[0x48, 0x8B, 0x0D], &[0x48, 0x8B, 0x15], &[0x4C, 0x8B, 0x05], &[0x4C, 0x8B, 0x0D]];
        match arg {
            Imm(value) if value <= u32::MAX as u64 => {
                self.put(IMM32[index]);
                self.imm32(value as u32);
            }
            Imm(value) if (value as i64) >= i32::MIN as i64 && (value as i64) < 0 => {
                self.put(SIGNED[index]);
                self.imm32(value as u32);
            }
            Imm(value) => {
                self.put(IMM64[index]);
                self.code.extend_from_slice(&value.to_le_bytes());
            }
            Addr(offset) => self.rip(LEA[index], offset),
            Load(offset) => self.rip(LOAD[index], offset),
        }
    }

    /// Argumento de pilha `number` (5 em diante, em [rsp + 8 * number]).
    fn stack(&mut self, number: usize, arg: Arg) {
        let displacement = (number * 8) as u8;
        match arg {
            Imm(value) if value <= i32::MAX as u64 || ((value as i64) < 0 && (value as i64) >= i32::MIN as i64) => {
                self.put(&[0x48, 0xC7, 0x44, 0x24, displacement]);
                self.imm32(value as u32);
                return;
            }
            Imm(value) => {
                self.put(&[0x48, 0xB8]);
                self.code.extend_from_slice(&value.to_le_bytes());
            }
            Addr(offset) => self.rip(&[0x48, 0x8D, 0x05], offset),
            Load(offset) => self.rip(&[0x48, 0x8B, 0x05], offset),
        }
        self.put(&[0x48, 0x89, 0x44, 0x24, displacement]);
    }

    /// Um serviço com os argumentos dados; o status fica em eax.
    fn call(&mut self, number: u32, args: &[Arg]) {
        for (index, &arg) in args.iter().enumerate().skip(4) {
            self.stack(index + 1, arg);
        }
        for (index, &arg) in args.iter().enumerate().take(4).rev() {
            self.register(index, arg);
        }
        // mov r10, rcx; mov eax, número; syscall
        self.put(&[0x49, 0x89, 0xCA, 0xB8]);
        self.imm32(number);
        self.put(&[0x0F, 0x05]);
    }

    /// `jcc rel32` para o caminho de falha.
    fn fail_on(&mut self, condition: u8) {
        self.put(&[0x0F, condition]);
        self.failures.push(self.code.len());
        self.imm32(0);
    }

    /// O serviço devolveu `status` (senão o processo sai com o que veio).
    fn expect(&mut self, status: u32) {
        if status == 0 {
            self.put(&[0x85, 0xC0]);
        } else {
            self.put(&[0x3D]);
            self.imm32(status);
        }
        self.fail_on(0x85);
    }

    /// `call` e `expect`.
    fn checked(&mut self, number: u32, args: &[Arg], status: u32) {
        self.call(number, args);
        self.expect(status);
    }

    /// `mov eax, código` (não mexe nas flags) e o salto condicional.
    fn step_on(&mut self, condition: u8, step: u32) {
        self.put(&[0xB8]);
        self.imm32(STEP + step);
        self.fail_on(condition);
    }

    /// A célula de 32 bits vale `value`.
    fn check_u32(&mut self, cell: usize, value: u32, step: u32) {
        self.rip(&[0x8B, 0x05], cell);
        self.put(&[0x3D]);
        self.imm32(value);
        self.step_on(0x85, step);
    }

    /// As células de 64 bits são iguais.
    fn check_cells(&mut self, left: usize, right: usize, step: u32) {
        self.rip(&[0x48, 0x8B, 0x05], left);
        self.rip(&[0x48, 0x3B, 0x05], right);
        self.step_on(0x85, step);
    }

    /// Os `length` bytes em `left` e `right` são iguais (repe cmpsb).
    fn check_bytes(&mut self, left: usize, right: usize, length: u32, step: u32) {
        self.rip(&[0x48, 0x8D, 0x35], left);
        self.rip(&[0x48, 0x8D, 0x3D], right);
        self.put(&[0xB9]);
        self.imm32(length);
        self.put(&[0xF3, 0xA6]);
        self.step_on(0x85, step);
    }

    fn here(&self) -> usize {
        self.code.len()
    }

    /// `jcc rel32` adiante; devolve o ponto a remendar com `bind`.
    fn forward(&mut self, condition: u8) -> usize {
        self.put(&[0x0F, condition]);
        let at = self.code.len();
        self.imm32(0);
        at
    }

    fn bind(&mut self, at: usize) {
        let offset = (self.code.len() as i64 - (at as i64 + 4)) as i32;
        self.code[at..at + 4].copy_from_slice(&offset.to_le_bytes());
    }

    /// `jcc rel32` para trás, até `target`.
    fn back(&mut self, condition: u8, target: usize) {
        self.put(&[0x0F, condition]);
        let offset = (target as i64 - (self.code.len() as i64 + 4)) as i32;
        self.imm32(offset as u32);
    }

    /// NtTerminateProcess(-1, código); `jmp $`.
    fn exit(&mut self, code: u32) {
        self.put(&[0xBA]);
        self.imm32(code);
        self.put(&[0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0x49, 0x89, 0xCA, 0xB8]);
        self.imm32(self.terminate);
        self.put(&[0x0F, 0x05, 0xEB, 0xFE]);
    }

    /// O caminho de falha (sai com eax) e o conteúdo da seção.
    fn finish(mut self, data: &Data) -> Vec<u8> {
        let here = self.code.len();
        for at in core::mem::take(&mut self.failures) {
            let offset = (here as i64 - (at as i64 + 4)) as i32;
            self.code[at..at + 4].copy_from_slice(&offset.to_le_bytes());
        }
        // mov edx, eax; NtTerminateProcess(-1, edx); jmp $
        self.put(&[0x89, 0xC2, 0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0x49, 0x89, 0xCA, 0xB8]);
        self.imm32(self.terminate);
        self.put(&[0x0F, 0x05, 0xEB, 0xFE]);
        assert!(self.code.len() <= DATA, "programa de teste maior que a area de codigo");
        let mut content = self.code;
        content.resize(DATA, 0xCC);
        content.extend_from_slice(&data.bytes);
        content
    }
}

/// PE x64 de uma seção gravável e executável com o conteúdo em 0x1000.
fn image(content: &[u8]) -> Vec<u8> {
    let raw = content.len().div_ceil(0x200) * 0x200;
    let virtual_size = content.len().div_ceil(0x1000) * 0x1000;
    let mut image = alloc::vec![0u8; 0x400 + raw];
    let put16 = |image: &mut [u8], at: usize, value: u16| image[at..at + 2].copy_from_slice(&value.to_le_bytes());
    let put32 = |image: &mut [u8], at: usize, value: u32| image[at..at + 4].copy_from_slice(&value.to_le_bytes());
    put16(&mut image, 0, 0x5A4D);
    put32(&mut image, 0x3C, 0x40);
    put32(&mut image, 0x40, 0x4550);
    put16(&mut image, 0x44, 0x8664);
    put16(&mut image, 0x46, 1);
    put16(&mut image, 0x54, 240);
    put16(&mut image, 0x56, 0x0022);
    let optional = 0x58;
    put16(&mut image, optional, 0x20B);
    put32(&mut image, optional + 16, 0x1000);
    image[optional + 24..optional + 32].copy_from_slice(&IMAGE_BASE.to_le_bytes());
    put32(&mut image, optional + 32, 0x1000);
    put32(&mut image, optional + 36, 0x200);
    put16(&mut image, optional + 48, 6);
    put32(&mut image, optional + 56, (0x1000 + virtual_size) as u32);
    put32(&mut image, optional + 60, 0x400);
    put16(&mut image, optional + 68, 3);
    put32(&mut image, optional + 108, 16);
    let section = optional + 240;
    image[section..section + 5].copy_from_slice(b".text");
    put32(&mut image, section + 8, virtual_size as u32);
    put32(&mut image, section + 12, 0x1000);
    put32(&mut image, section + 16, raw as u32);
    put32(&mut image, section + 20, 0x400);
    // IMAGE_SCN_CNT_CODE | MEM_EXECUTE | MEM_READ | MEM_WRITE.
    put32(&mut image, section + 36, 0xE000_0020);
    image[0x400..0x400 + content.len()].copy_from_slice(content);
    image
}

// ---- o servidor ----------------------------------------------------------------

/// As células do servidor que o teste preenche antes de ele rodar.
struct ServerCells {
    /// O PID do cliente, que o atributo de conexão ClientProcessId deve dar.
    client_id: usize,
}

fn server_program(terminate: u32) -> (Vec<u8>, ServerCells) {
    let mut data = Data::new();
    let messages = data.attributes(&format!("\\??\\pipe\\{PIPE_MESSAGES}"));
    let bytes = data.attributes(&format!("\\??\\pipe\\{PIPE_BYTES}"));
    let mailslot = data.attributes(&format!("\\??\\MAILSLOT\\{MAILSLOT}"));
    let iosb = data.alloc(IoStatusBlock::SIZE as usize, 8);
    let information = iosb + core::mem::offset_of!(IoStatusBlock, information);
    // DefaultTimeout de 50 ms; o mailslot espera sem prazo (-1).
    let pipe_timeout = data.u64((-500_000i64) as u64);
    let forever = data.u64(u64::MAX);
    let handle_messages = data.u64(0);
    let handle_bytes = data.u64(0);
    let handle_mailslot = data.u64(0);
    let peek = data.alloc(FilePipePeekBuffer::SIZE as usize + 16, 8);
    let buffer = data.alloc(64, 8);
    let client = data.alloc(FilePipeClientProcessBuffer::SIZE as usize, 8);
    let local = data.alloc(FilePipeLocalInformation::SIZE as usize, 8);
    let client_id = data.u64(0);
    let client_pid = data.u64(0);
    let attribute = data.bytes(CLIENT_PROCESS_ID);
    let rounds = data.bytes(&PEEK_ROUNDS.to_le_bytes());
    let ping = data.bytes(b"ping");
    let pong = data.bytes(b"pong");
    let hello = data.bytes(b"hello");
    let world = data.bytes(b" world");
    let ok = data.bytes(b"ok");
    let mail = data.bytes(b"mail");

    let mut asm = Asm::new(terminate);
    let access = GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE;
    // Os dois pipes, síncronos, uma instância cada.
    for (handle, attributes, kind) in [(handle_messages, messages, FILE_PIPE_MESSAGE), (handle_bytes, bytes, FILE_PIPE_BYTE_STREAM)] {
        asm.checked(
            CREATE_NAMED_PIPE,
            &[Addr(handle), Imm(access), Addr(attributes), Addr(iosb), Imm(FILE_SHARE_READ_WRITE), Imm(FILE_OPEN_IF), Imm(FILE_SYNCHRONOUS_IO_NONALERT), Imm(kind), Imm(kind), Imm(FILE_PIPE_QUEUE_OPERATION), Imm(1), Imm(0x1000), Imm(0x1000), Addr(pipe_timeout)],
            STATUS_SUCCESS,
        );
    }
    // O mailslot, de leitura síncrona e sem prazo.
    asm.checked(CREATE_MAILSLOT, &[Addr(handle_mailslot), Imm(GENERIC_READ | SYNCHRONIZE), Addr(mailslot), Addr(iosb), Imm(FILE_SYNCHRONOUS_IO_NONALERT), Imm(0), Imm(0), Addr(forever)], STATUS_SUCCESS);
    // Escuta no pipe de mensagens: bloqueia até o cliente conectar.
    let fs_control = |asm: &mut Asm, handle: usize, code: u64, input: Arg, input_length: u64, output: Arg, output_length: u64| {
        asm.call(FS_CONTROL, &[Load(handle), Imm(0), Imm(0), Imm(0), Addr(iosb), Imm(code), input, Imm(input_length), output, Imm(output_length)]);
    };
    fs_control(&mut asm, handle_messages, FSCTL_PIPE_LISTEN, Imm(0), 0, Imm(0), 0);
    asm.expect(STATUS_SUCCESS);
    // FilePipeLocalInformation: mensagens, uma instância de uma, conectado,
    // lado servidor.
    asm.checked(QUERY_INFORMATION, &[Load(handle_messages), Addr(iosb), Addr(local), Imm(FilePipeLocalInformation::SIZE), Imm(FILE_PIPE_LOCAL_INFORMATION)], STATUS_SUCCESS);
    asm.check_u32(local + core::mem::offset_of!(FilePipeLocalInformation, named_pipe_type), 1, 1);
    asm.check_u32(local + core::mem::offset_of!(FilePipeLocalInformation, maximum_instances), 1, 2);
    asm.check_u32(local + core::mem::offset_of!(FilePipeLocalInformation, current_instances), 1, 3);
    asm.check_u32(local + core::mem::offset_of!(FilePipeLocalInformation, named_pipe_state), FILE_PIPE_CONNECTED_STATE, 4);
    asm.check_u32(local + core::mem::offset_of!(FilePipeLocalInformation, named_pipe_end), FILE_PIPE_SERVER_END, 5);
    // FSCTL_PIPE_PEEK até a mensagem do cliente chegar (cedendo a CPU).
    let top = asm.here();
    fs_control(&mut asm, handle_messages, FSCTL_PIPE_PEEK, Imm(0), 0, Addr(peek), FilePipePeekBuffer::SIZE + 16);
    asm.expect(STATUS_SUCCESS);
    asm.rip(&[0x8B, 0x05], peek + core::mem::offset_of!(FilePipePeekBuffer, read_data_available));
    asm.put(&[0x85, 0xC0]);
    let arrived = asm.forward(0x85);
    asm.call(YIELD_EXECUTION, &[]);
    // dec dword [rounds]; jnz top
    asm.rip(&[0xFF, 0x0D], rounds);
    asm.back(0x85, top);
    asm.put(&[0xB8]);
    asm.imm32(STEP + 6);
    asm.fail_on(0x84);
    asm.bind(arrived);
    asm.check_u32(peek + core::mem::offset_of!(FilePipePeekBuffer, number_of_messages), 1, 7);
    asm.check_u32(peek + core::mem::offset_of!(FilePipePeekBuffer, message_length), 4, 8);
    asm.check_bytes(peek + FilePipePeekBuffer::SIZE as usize, ping, 4, 9);
    // A mensagem, a consulta do processo do cliente e a resposta.
    asm.checked(READ_FILE, &[Load(handle_messages), Imm(0), Imm(0), Imm(0), Addr(iosb), Addr(buffer), Imm(64), Imm(0), Imm(0)], STATUS_SUCCESS);
    asm.check_u32(information, 4, 10);
    asm.check_bytes(buffer, ping, 4, 11);
    // O PID do cliente pelo atributo de conexão "ClientProcessId" (o
    // caminho do GetNamedPipeClientProcessId): um ULONG no SystemBuffer.
    fs_control(&mut asm, handle_messages, FSCTL_PIPE_GET_CONNECTION_ATTRIBUTE, Addr(attribute), CLIENT_PROCESS_ID.len() as u64, Addr(client_pid), 4);
    asm.expect(STATUS_SUCCESS);
    asm.check_u32(information, 4, 12);
    asm.check_cells(client_pid, client_id, 20);
    // A consulta antiga (FSCTL_PIPE_QUERY_CLIENT_PROCESS) devolve os 16
    // bytes do FILE_PIPE_CLIENT_PROCESS_BUFFER; o npfs.sys só copia nele um
    // atributo de 8 bytes, e o do cliente local tem 4.
    fs_control(&mut asm, handle_messages, FSCTL_PIPE_QUERY_CLIENT_PROCESS, Imm(0), 0, Addr(client), FilePipeClientProcessBuffer::SIZE);
    asm.expect(STATUS_SUCCESS);
    asm.check_u32(information, FilePipeClientProcessBuffer::SIZE as u32, 21);
    asm.checked(WRITE_FILE, &[Load(handle_messages), Imm(0), Imm(0), Imm(0), Addr(iosb), Addr(pong), Imm(4), Imm(0), Imm(0)], STATUS_SUCCESS);
    asm.check_u32(information, 4, 13);
    // O pipe de bytes: escuta, lê 5 e 6 bytes de uma escrita só e responde.
    fs_control(&mut asm, handle_bytes, FSCTL_PIPE_LISTEN, Imm(0), 0, Imm(0), 0);
    asm.expect(STATUS_SUCCESS);
    for (expected, length, step) in [(hello, 5u32, 14u32), (world, 6, 16)] {
        asm.checked(READ_FILE, &[Load(handle_bytes), Imm(0), Imm(0), Imm(0), Addr(iosb), Addr(buffer), Imm(length as u64), Imm(0), Imm(0)], STATUS_SUCCESS);
        asm.check_u32(information, length, step);
        asm.check_bytes(buffer, expected, length, step + 1);
    }
    asm.checked(WRITE_FILE, &[Load(handle_bytes), Imm(0), Imm(0), Imm(0), Addr(iosb), Addr(ok), Imm(2), Imm(0), Imm(0)], STATUS_SUCCESS);
    // O mailslot: espera a mensagem do cliente.
    asm.checked(READ_FILE, &[Load(handle_mailslot), Imm(0), Imm(0), Imm(0), Addr(iosb), Addr(buffer), Imm(64), Imm(0), Imm(0)], STATUS_SUCCESS);
    asm.check_u32(information, 4, 18);
    asm.check_bytes(buffer, mail, 4, 19);
    // Desconecta os dois pipes e fecha tudo.
    for handle in [handle_messages, handle_bytes] {
        fs_control(&mut asm, handle, FSCTL_PIPE_DISCONNECT, Imm(0), 0, Imm(0), 0);
        asm.expect(STATUS_SUCCESS);
    }
    for handle in [handle_messages, handle_bytes, handle_mailslot] {
        asm.checked(CLOSE, &[Load(handle)], STATUS_SUCCESS);
    }
    asm.exit(SERVER_CODE);
    (image(&asm.finish(&data)), ServerCells { client_id })
}

// ---- o cliente -----------------------------------------------------------------

fn client_program(terminate: u32) -> Vec<u8> {
    let mut data = Data::new();
    let root = data.attributes("\\??\\pipe\\");
    let messages = data.attributes(&format!("\\??\\pipe\\{PIPE_MESSAGES}"));
    let bytes = data.attributes(&format!("\\??\\pipe\\{PIPE_BYTES}"));
    let mailslot = data.attributes(&format!("\\??\\MAILSLOT\\{MAILSLOT}"));
    let (wait_messages, wait_messages_length) = data.wait_for(PIPE_MESSAGES, -50_000_000);
    let (wait_bytes, wait_bytes_length) = data.wait_for(PIPE_BYTES, -50_000_000);
    let iosb = data.alloc(IoStatusBlock::SIZE as usize, 8);
    let information = iosb + core::mem::offset_of!(IoStatusBlock, information);
    let status = iosb + core::mem::offset_of!(IoStatusBlock, status);
    let handle_root = data.u64(0);
    let handle_messages = data.u64(0);
    let handle_bytes = data.u64(0);
    let handle_mailslot = data.u64(0);
    let event = data.u64(0);
    let mode = data.bytes(&[1, 0, 0, 0, 0, 0, 0, 0]);
    let queried = data.alloc(FilePipeInformation::SIZE as usize, 8);
    let buffer = data.alloc(64, 8);
    let ping = data.bytes(b"ping");
    let pong = data.bytes(b"pong");
    let hello = data.bytes(b"hello world");
    let ok = data.bytes(b"ok");
    let mail = data.bytes(b"mail");

    let mut asm = Asm::new(terminate);
    let fs_control = |asm: &mut Asm, handle: usize, code: u64, input: Arg, input_length: u64, output: Arg, output_length: u64| {
        asm.call(FS_CONTROL, &[Load(handle), Imm(0), Imm(0), Imm(0), Addr(iosb), Imm(code), input, Imm(input_length), output, Imm(output_length)]);
    };
    // A raiz do npfs e a espera do pipe de mensagens (já escutando).
    asm.checked(OPEN_FILE, &[Addr(handle_root), Imm(FILE_READ_ATTRIBUTES | SYNCHRONIZE), Addr(root), Addr(iosb), Imm(FILE_SHARE_READ_WRITE), Imm(FILE_SYNCHRONOUS_IO_NONALERT)], STATUS_SUCCESS);
    fs_control(&mut asm, handle_root, FSCTL_PIPE_WAIT, Addr(wait_messages), wait_messages_length, Imm(0), 0);
    asm.expect(STATUS_SUCCESS);
    let open = |asm: &mut Asm, handle: usize, attributes: usize, access: u64, share: u64, options: u64| {
        asm.checked(CREATE_FILE, &[Addr(handle), Imm(access), Addr(attributes), Addr(iosb), Imm(0), Imm(0), Imm(share), Imm(FILE_OPEN), Imm(options), Imm(0), Imm(0)], STATUS_SUCCESS);
    };
    open(&mut asm, handle_messages, messages, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, 0, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    // Leitura em modo mensagem, conferida pela consulta.
    asm.checked(SET_INFORMATION, &[Load(handle_messages), Addr(iosb), Addr(mode), Imm(FilePipeInformation::SIZE), Imm(FILE_PIPE_INFORMATION)], STATUS_SUCCESS);
    asm.checked(QUERY_INFORMATION, &[Load(handle_messages), Addr(iosb), Addr(queried), Imm(FilePipeInformation::SIZE), Imm(FILE_PIPE_INFORMATION)], STATUS_SUCCESS);
    asm.check_u32(queried + core::mem::offset_of!(FilePipeInformation, read_mode), 1, 1);
    asm.check_u32(information, FilePipeInformation::SIZE as u32, 2);
    // "ping" e a resposta num FSCTL_PIPE_TRANSCEIVE (espera o servidor).
    fs_control(&mut asm, handle_messages, FSCTL_PIPE_TRANSCEIVE, Addr(ping), 4, Addr(buffer), 64);
    asm.expect(STATUS_SUCCESS);
    asm.check_u32(information, 4, 3);
    asm.check_bytes(buffer, pong, 4, 4);
    // O pipe de bytes: espera o LISTEN, abre assíncrono e escreve com evento.
    fs_control(&mut asm, handle_root, FSCTL_PIPE_WAIT, Addr(wait_bytes), wait_bytes_length, Imm(0), 0);
    asm.expect(STATUS_SUCCESS);
    open(&mut asm, handle_bytes, bytes, GENERIC_READ | GENERIC_WRITE, 0, FILE_NON_DIRECTORY_FILE);
    asm.checked(CREATE_EVENT, &[Addr(event), Imm(EVENT_ALL_ACCESS), Imm(0), Imm(0), Imm(0)], STATUS_SUCCESS);
    asm.call(WRITE_FILE, &[Load(handle_bytes), Load(event), Imm(0), Imm(0), Addr(iosb), Addr(hello), Imm(11), Imm(0), Imm(0)]);
    // STATUS_SUCCESS ou STATUS_PENDING; a conclusão sinaliza o evento.
    asm.put(&[0x85, 0xC0]);
    let written = asm.forward(0x84);
    asm.expect(STATUS_PENDING);
    asm.bind(written);
    asm.checked(WAIT_SINGLE, &[Load(event), Imm(0), Imm(0)], STATUS_SUCCESS);
    asm.check_u32(status, STATUS_SUCCESS, 5);
    asm.check_u32(information, 11, 6);
    // A resposta: a leitura fica pendente até o servidor escrever.
    asm.call(READ_FILE, &[Load(handle_bytes), Load(event), Imm(0), Imm(0), Addr(iosb), Addr(buffer), Imm(64), Imm(0), Imm(0)]);
    asm.put(&[0x85, 0xC0]);
    let read = asm.forward(0x84);
    asm.expect(STATUS_PENDING);
    asm.bind(read);
    asm.checked(WAIT_SINGLE, &[Load(event), Imm(0), Imm(0)], STATUS_SUCCESS);
    asm.check_u32(status, STATUS_SUCCESS, 7);
    asm.check_u32(information, 2, 8);
    asm.check_bytes(buffer, ok, 2, 9);
    // O mailslot.
    open(&mut asm, handle_mailslot, mailslot, GENERIC_WRITE | SYNCHRONIZE, FILE_SHARE_READ_WRITE, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    asm.checked(WRITE_FILE, &[Load(handle_mailslot), Imm(0), Imm(0), Imm(0), Addr(iosb), Addr(mail), Imm(4), Imm(0), Imm(0)], STATUS_SUCCESS);
    asm.check_u32(information, 4, 10);
    for handle in [handle_mailslot, handle_bytes, handle_messages, handle_root, event] {
        asm.checked(CLOSE, &[Load(handle)], STATUS_SUCCESS);
    }
    asm.exit(CLIENT_CODE);
    image(&asm.finish(&data))
}

// ---- validação no contexto do servidor -----------------------------------------

/// Chama `name` anexado a `process` com os quatro primeiros argumentos e
/// os de pilha (5 em diante) num bloco de usuário dele.
fn call_in(process: u64, block: u64, name: &str, arguments: [u64; 4], stack: &[u64]) -> u32 {
    let rsp = block + 0x1000;
    process_context::with_process(process, || {
        for (index, value) in stack.iter().enumerate() {
            guest::write64(rsp + 0x28 + index as u64 * 8, *value);
        }
        state::handler(name).map_or(1, |handler| handler(arguments[0], arguments[1], arguments[2], arguments[3], rsp).unwrap_or(1))
    })
    .unwrap_or(1)
}

/// O IopCreateFile recusa os parâmetros inválidos antes do driver.
fn validation(assert: Assert, process: u64) {
    let Some(block) = process_context::with_process(process, || memory::map_user_region(0x2000).ok()).ok().flatten() else {
        check(assert, false, "pipes: memoria de usuario no servidor");
        return;
    };
    let (out, iosb, attributes, name, timeout) = (block, block + 0x10, block + 0x40, block + 0x80, block + 0x100);
    let _ = process_context::with_process(process, || {
        let wide: Vec<u8> = "\\??\\pipe\\opennt-invalido".encode_utf16().flat_map(u16::to_le_bytes).collect();
        guest::write_bytes(name + 0x10, &wide);
        // SAFETY: UNICODE_STRING e OBJECT_ATTRIBUTES no bloco de usuário do
        // processo anexado.
        let (string, object) = unsafe { (UnicodeString::at(name), ObjectAttributes::at(attributes)) };
        string.length.set(wide.len() as u16);
        string.maximum_length.set(wide.len() as u16);
        string.buffer.set(name + 0x10);
        object.length.set(ObjectAttributes::SIZE as u32);
        object.object_name.set(name);
        object.attributes.set(OBJ_CASE_INSENSITIVE);
        guest::write64(timeout, (-500_000i64) as u64);
    });
    let access = GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE;
    let pipe = |access: u64, share: u64, disposition: u64, options: u64, read_mode: u64, default_timeout: u64| {
        call_in(process, block, "NtCreateNamedPipeFile", [out, access, attributes, iosb], &[share, disposition, options, FILE_PIPE_MESSAGE, read_mode, FILE_PIPE_QUEUE_OPERATION, 1, 0x1000, 0x1000, default_timeout])
    };
    check(assert, pipe(access, FILE_SHARE_READ_WRITE, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, 2, timeout) == STATUS_INVALID_PARAMETER, "pipes: NtCreateNamedPipeFile com ReadMode 2 recusado (IopCreateFile)");
    check(assert, pipe(access, FILE_SHARE_READ_WRITE | 4, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, 1, timeout) == STATUS_INVALID_PARAMETER, "pipes: NtCreateNamedPipeFile com FILE_SHARE_DELETE recusado");
    check(assert, pipe(access, FILE_SHARE_READ_WRITE, FILE_SUPERSEDE, FILE_SYNCHRONOUS_IO_NONALERT, 1, timeout) == STATUS_INVALID_PARAMETER, "pipes: NtCreateNamedPipeFile com FILE_SUPERSEDE recusado");
    check(assert, pipe(GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ_WRITE, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, 1, timeout) == STATUS_INVALID_PARAMETER, "pipes: NtCreateNamedPipeFile sincrono sem SYNCHRONIZE recusado");
    check(assert, pipe(access, FILE_SHARE_READ_WRITE, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, 1, timeout + 1) == STATUS_DATATYPE_MISALIGNMENT, "pipes: DefaultTimeout desalinhado da STATUS_DATATYPE_MISALIGNMENT");
    let mailslot = call_in(process, block, "NtCreateMailslotFile", [out, GENERIC_READ | SYNCHRONIZE, attributes, iosb], &[FILE_DIRECTORY_FILE, 0, 0, timeout]);
    check(assert, mailslot == STATUS_INVALID_PARAMETER, "pipes: NtCreateMailslotFile com FILE_DIRECTORY_FILE recusado");
    let opened = process_context::with_process(process, || guest::read64(out)).unwrap_or(1);
    check(assert, opened == 0, "pipes: nenhuma das recusas abriu handle");
    let _ = process_context::with_process(process, || {
        if let Some(region) = memory::find_region(block) {
            memory::release_private_region(&region);
        }
    });
}

// ---- o teste -------------------------------------------------------------------

fn process_id(process: u64) -> u64 {
    // SAFETY: EPROCESS retido pelo teste.
    unsafe { Eprocess::at(process) }.unique_process_id.get()
}

fn exit_status(process: u64) -> u32 {
    // SAFETY: EPROCESS retido pelo teste.
    unsafe { Eprocess::at(process) }.exit_status.get() as u32
}

/// Põe um processo criado no despachante, com a thread principal GUI (os
/// serviços de teste entram pela tabela 1 do Shadow).
fn launch(created: CreatedProcess) -> Option<StartedProcess> {
    // SAFETY: a ETHREAD da thread principal, viva enquanto o processo vive.
    unsafe { Ethread::at(created.thread_pointer) }.tcb.set_gui_thread(1);
    match user_process::start_created(created) {
        Ok(started) => Some(started),
        Err(error) => {
            crate::debug_print!("[pipes] nao partiu: {}", error);
            None
        }
    }
}

/// Alguma conferência deste teste falhou.
static FAILED: AtomicBool = AtomicBool::new(false);

/// `assert`, anotando a falha para o marcador do teste.
fn check(assert: Assert, condition: bool, message: &str) {
    if !condition {
        FAILED.store(true, Ordering::SeqCst);
    }
    assert(condition, message);
}

/// O teste inteiro; `PIPES_OK` sai só se todas as conferências passarem.
pub fn run(assert: Assert) {
    FAILED.store(false, Ordering::SeqCst);
    body(assert);
    if !FAILED.load(Ordering::SeqCst) {
        crate::debug_print!("PIPES_OK");
    }
}

fn body(assert: Assert) {
    if !usermode::ready() || process::get_current_thread() == 0 {
        check(assert, false, "pipes: anel 3 armado e thread corrente");
        return;
    }
    // Os file systems reais iniciados no boot, com os dispositivos DOS.
    let running = |service: &str| service_database::status(service).is_ok_and(|status| status.current_state == 4);
    let devices = object_manager::lookup("\\Device\\NamedPipe").is_some() && object_manager::lookup("\\Device\\Mailslot").is_some();
    let links = object_manager::lookup("\\GLOBAL??\\PIPE").is_some() && object_manager::lookup("\\GLOBAL??\\MAILSLOT").is_some();
    check(assert, running("Npfs") && running("Msfs") && devices && links, "pipes: npfs.sys e msfs.sys iniciados no boot (\\Device\\NamedPipe, \\Device\\Mailslot, \\??\\PIPE, \\??\\MAILSLOT)");
    if !devices {
        return;
    }
    if state::with(|state| state.ntdll_exports.as_ref().is_none_or(|exports| !exports.contains_key("LdrInitializeThunk"))) {
        check(assert, false, "pipes: ntdll com LdrInitializeThunk mapeada");
        return;
    }
    let Some(terminate) = terminate_number() else {
        check(assert, false, "pipes: numero do NtTerminateProcess");
        return;
    };
    let _ = csr::initialize();
    let Some(saved) = publish_services() else {
        check(assert, false, "pipes: tabela 1 de teste com os servicos encaminhados");
        return;
    };
    scenario(assert, terminate);
    restore_services(saved);
    kernel_stack::reap();
}

fn scenario(assert: Assert, terminate: u32) {
    let (server_image, cells) = server_program(terminate);
    let request = user_process::windows_process_request(ImageOrigin::Bytes(server_image), "servidor-pipe.exe", "C:\\servidor-pipe.exe", &RunOptions::default());
    let server = match create::create_user_process(&request) {
        Ok(created) => created,
        Err(failure) => {
            check(assert, false, &format!("pipes: servidor criado ({failure})"));
            return;
        }
    };
    let server_pointer = server.process_pointer;
    process::reference(server_pointer);
    validation(assert, server_pointer);

    let request = user_process::windows_process_request(ImageOrigin::Bytes(client_program(terminate)), "cliente-pipe.exe", "C:\\cliente-pipe.exe", &RunOptions::default());
    let client = match create::create_user_process(&request) {
        Ok(created) => created,
        Err(failure) => {
            check(assert, false, &format!("pipes: cliente criado ({failure})"));
            drop(server);
            let _ = process::dereference(server_pointer);
            return;
        }
    };
    let client_pointer = client.process_pointer;
    process::reference(client_pointer);
    let client_id = process_id(client_pointer);
    let _ = process_context::with_process(server_pointer, || guest::write64(absolute(cells.client_id), client_id));

    let Some(server_started) = launch(server) else {
        check(assert, false, "pipes: servidor posto no despachante");
        drop(client);
        let _ = process::dereference(client_pointer);
        let _ = process::dereference(server_pointer);
        return;
    };
    // O servidor anda só pelo tick até bloquear no LISTEN, com o IRP
    // pendente no npfs.sys.
    let main = threads::of_process(server_pointer).first().cloned();
    let listening = || main.as_ref().is_some_and(|thread| thread.waiting() && thread.blocked_in_kernel() && irp_service::pending_for_thread(thread.pointer()) == 1);
    let deadline = clock::uptime_ms() + WAIT_DEADLINE_MS;
    while clock::uptime_ms() < deadline && process_state::get(server_pointer).is_some() && !listening() {
        scheduler::tick(-1);
    }
    let blocked = listening();
    crate::debug_print!("[pipes] servidor bloqueado no LISTEN={} (saida {:#x})", blocked, exit_status(server_pointer));
    check(assert, blocked, "pipes: o servidor cria os pipes e o mailslot em anel 3 e bloqueia no kernel em FSCTL_PIPE_LISTEN, com o IRP pendente no npfs.sys");

    let client_started = if blocked {
        launch(client)
    } else {
        drop(client);
        None
    };
    if client_started.is_none() {
        let _ = create::exit_process(server_pointer, 0xC000_0001);
    }
    let server_thread = main.as_ref().map_or(0, |thread| thread.pointer());
    let client_thread = threads::of_process(client_pointer).first().map_or(0, |thread| thread.pointer());
    let server_exit = user_process::wait_started(server_started);
    let client_exit = client_started.map(user_process::wait_started);
    crate::debug_print!("[pipes] saidas: servidor {:?} cliente {:?}", server_exit.as_ref().map_err(|error| format!("{error}")), client_exit.as_ref().map(|exit| exit.as_ref().map_err(|error| format!("{error}"))));
    check(assert, matches!(client_exit, Some(Ok(CLIENT_CODE))) && exit_status(client_pointer) == CLIENT_CODE, "pipes: o cliente espera o pipe, conecta, troca mensagens (TRANSCEIVE) e bytes (escrita e leitura assincronas com evento) e escreve no mailslot");
    check(assert, matches!(server_exit, Ok(SERVER_CODE)) && exit_status(server_pointer) == SERVER_CODE, "pipes: o servidor confere a conexao, a mensagem (PEEK e leitura), o PID do cliente, os bytes e o mailslot, e desconecta");
    let drained = irp_service::pending_for_thread(server_thread) == 0 && (client_thread == 0 || irp_service::pending_for_thread(client_thread) == 0);
    let released = process_state::get(server_pointer).is_none() && process_state::get(client_pointer).is_none();
    check(assert, drained && released, "pipes: nenhum IRP dos dois fica vivo e nada deles fica no estado");
    let _ = process::dereference(client_pointer);
    let _ = process::dereference(server_pointer);
}
