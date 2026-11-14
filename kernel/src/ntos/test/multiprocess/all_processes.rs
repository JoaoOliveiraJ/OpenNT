//! Um despachante para as threads de todos os processos
//! (`ps/user/threads.rs` `dispatch_one`/`wait_for_process`, o
//! `scheduler::tick`, `ps/create.rs` `exit_process` e o
//! NtTerminateProcess com handle):
//!
//! - Dois processos de usuário reais, criados pelo caminho único e postos no
//!   despachante (`create_user_process` + `start_created`) antes de qualquer
//!   espera.
//!   Cada um abre pelo nome uma seção que o teste criou, mapeia uma vista,
//!   anuncia a chegada e espera a do outro (cedendo a CPU, com limite), e
//!   então, N vezes, incrementa o contador da seção (`lock xadd`), anota no
//!   próprio diário o valor que viu e cede a CPU (NtYieldExecution); depois
//!   sai com o próprio código. Os diários provam a alternância: os dois
//!   avançam antes de qualquer um sair (o último valor de cada um é maior que
//!   o primeiro do outro), e os 2N valores são exatamente 0..2N. Os dois saem
//!   com códigos distintos. No laço de um processo só, o primeiro roda
//!   inteiro antes de o segundo começar (a espera pela chegada esgota o
//!   limite): os diários ficam contíguos, 0..N-1 e N..2N-1.
//! - Um processo termina o outro por handle. A vítima só gira no anel 3
//!   (incrementa um contador da seção, sem syscall nenhuma: só o timer a
//!   tira da CPU); o matador lê o PID dela na seção, espera o contador dela
//!   andar, abre o processo (NtOpenProcess por CLIENT_ID, PROCESS_TERMINATE),
//!   o termina (NtTerminateProcess(handle, 0x77)) e segue incrementando o
//!   próprio contador antes de sair com o código dele. Ninguém espera os
//!   dois: eles andam só pelo `scheduler::tick`. Logo depois do término,
//!   com o matador ainda vivo e no meio das voltas, a vítima já não tem
//!   estado, threads no índice nem vista na raiz dela (que fica só com a
//!   KUSER), e a pilha de kernel da thread dela voltou ao Mm; a vista do
//!   matador segue mapeada. No fim a vítima saiu com 0x77, o contador dela
//!   parou no valor do término, e o matador fez todas as voltas e saiu com o
//!   código dele. No código anterior o tick não despacha usuário: nenhum dos
//!   dois anda.
//!
//! - NtTerminateProcess(NULL) termina as outras threads do processo e quem
//!   chamou segue: com uma segunda thread viva (criada pelo NtCreateThreadEx
//!   do kernel, girando no anel 3), a principal chama NtTerminateProcess(NULL,
//!   0x5E), recebe STATUS_SUCCESS e sai depois com 0x64; a segunda morreu com
//!   0x5E. No código anterior o NULL encerrava o processo inteiro com 0x5E.
//!
//! Os programas fazem syscalls de verdade: o NtTerminateProcess pelo número
//! nativo da ntdll de bring-up, e NtOpenSection, NtMapViewOfSection,
//! NtYieldExecution e NtOpenProcess (que ela não publica) pela tabela 1 do
//! Shadow, com a thread principal GUI, numa tabela de teste que encaminha ao
//! handler real de cada um.

use alloc::format;
use alloc::vec::Vec;
use core::mem::offset_of;
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use crate::hal::amd64::usermode;
use crate::ntos::ex::{service_abi, service_table};
use crate::ntos::inc::types::{Eprocess, Ethread, Kthread, LargeInteger, NtStruct, ObjectAttributes, UnicodeString};
use crate::ntos::ke::{clock, pcr};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::process_address_space as address_space;
use crate::ntos::mm::section::views;
use crate::ntos::mm::shared_user_data::MM_SHARED_USER_DATA_VA;
use crate::ntos::mm::{kernel_stack, memory_map as map, paging};
use crate::ntos::ps::create::{self, CreatedProcess, ImageOrigin};
use crate::ntos::ps::user::process::{self as user_process, RunOptions, StartedProcess};
use crate::ntos::ps::user::{csr, index, memory, process_state, state, threads};
use crate::ntos::ps::{process, process_context, scheduler};

type Assert = fn(bool, &str);

/// A seção nomeada que os processos abrem.
const SECTION_NAME: &str = "\\BaseNamedObjects\\OpenNtDespachanteT4";
const IMAGE_BASE: u64 = 0x1_4000_0000;

// Campos da seção (deslocamentos na vista).
const VICTIM_PID: u8 = 0x08;
const VICTIM_COUNTER: u8 = 0x10;
const KILLER_COUNTER: u8 = 0x14;
const KILL_STATUS: u8 = 0x18;
const OPEN_STATUS: u8 = 0x1C;
const VICTIM_AT_KILL: u8 = 0x20;
const VICTIM_VIEW: u8 = 0x28;
const KILLER_VIEW: u8 = 0x30;
const ARRIVED: u8 = 0x40;
/// Os diários: um por processo, `ROUNDS` valores de 32 bits.
const LOG: u32 = 0x100;
const LOG_STRIDE: u32 = 0x100;

/// Voltas de cada processo que alterna; voltas do matador depois do término.
const ROUNDS: u32 = 8;
const KILLER_ROUNDS: u32 = 64;
/// Quantas vezes um processo cede a CPU esperando a chegada do outro.
const ARRIVAL_SPINS: u32 = 4000;
const FIRST_CODE: u32 = 0x61;
const SECOND_CODE: u32 = 0x62;
const KILLER_CODE: u32 = 0x63;
const KILL_CODE: u32 = 0x77;
/// Valor das células de status antes de o programa escrevê-las.
const UNSET: u32 = 0xFFFF_FFFF;
/// Prazo da fase movida só pelo tick.
const TICK_DEADLINE_MS: u64 = 20_000;

/// Os dados do programa, depois do código, na mesma seção da imagem.
const DATA: usize = 0x400;
const NAMED_ATTRIBUTES: usize = DATA;
const NAME_STRING: usize = DATA + 0x30;
const PLAIN_ATTRIBUTES: usize = DATA + 0x40;
const NAME_TEXT: usize = DATA + 0x80;

// Condições dos saltos (0F 8x).
const JB: u8 = 0x82;
const JAE: u8 = 0x83;
const JNZ: u8 = 0x85;

/// Os números de serviço que os programas usam. A ntdll de bring-up da
/// suíte só publica o NtTerminateProcess na tabela nativa; os outros
/// serviços entram pela tabela 1 do Shadow (threads GUI), numa tabela de
/// teste cujas entradas encaminham ao handler real do serviço, com a pilha
/// do usuário e o registro de serviço da thread, como o portão nativo.
struct Services {
    open_section: u32,
    map_view: u32,
    yield_execution: u32,
    terminate_process: u32,
    open_process: u32,
}

/// Os serviços encaminhados, na ordem da tabela de teste (índices 0x1000..).
const FORWARDED: [&str; 4] = ["NtOpenSection", "NtMapViewOfSection", "NtYieldExecution", "NtOpenProcess"];

/// A tabela compactada dos encaminhadores, na imagem do kernel (a entrada é
/// relativa à tabela e só alcança ±128 MB).
static SERVICE_TABLE: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];
static SERVICE_ARGUMENTS: [AtomicU8; 4] = [const { AtomicU8::new(0) }; 4];

/// Encaminha ao handler real, como o portão nativo: a pilha do usuário
/// (KPCR.UserRsp, de onde saem os argumentos 5 em diante) e o registro de
/// serviço da thread.
fn forward(name: &'static str, arguments: [u64; 4]) -> u64 {
    let rsp = pcr::current().user_rsp.get();
    let record = state::SyscallRecord { raw_arguments: 0, stack: Some(state::ServiceStack { rsp, bytes: service_abi::stack_arguments(name).unwrap_or(0) as u64 * 8 }) };
    let result = state::with_syscall_record(record, || index::invoke_service(name, arguments, 0, rsp));
    result.unwrap_or_else(|error| if error.status != 0 { error.status } else { 0xC000_0001 }) as u64
}

extern "win64" fn open_section_service(a: u64, b: u64, c: u64, d: u64) -> u64 {
    forward(FORWARDED[0], [a, b, c, d])
}

extern "win64" fn map_view_service(a: u64, b: u64, c: u64, d: u64) -> u64 {
    forward(FORWARDED[1], [a, b, c, d])
}

extern "win64" fn yield_service(a: u64, b: u64, c: u64, d: u64) -> u64 {
    forward(FORWARDED[2], [a, b, c, d])
}

extern "win64" fn open_process_service(a: u64, b: u64, c: u64, d: u64) -> u64 {
    forward(FORWARDED[3], [a, b, c, d])
}

/// Publica a tabela 1 de teste; devolve a anterior, para restaurar.
fn publish_services() -> Option<[u64; 4]> {
    let saved = service_table::shadow_second_table().ok()?;
    let table = SERVICE_TABLE.as_ptr() as u64;
    let routines: [extern "win64" fn(u64, u64, u64, u64) -> u64; 4] = [open_section_service, map_view_service, yield_service, open_process_service];
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

/// O NtTerminateProcess pelo número nativo da ntdll carregada (o da tabela
/// medida da ntdll de referência, se ela não o publicou); os outros pela
/// tabela 1 de teste.
fn services() -> Option<Services> {
    let live = state::with(|state| state.name_by_number.iter().find(|(_, candidate)| candidate.as_str() == "NtTerminateProcess").map(|(&number, _)| number));
    let terminate_process = live.or_else(|| service_abi::NATIVE.entries.iter().find(|entry| entry.1 == "NtTerminateProcess").map(|entry| entry.0))?;
    Some(Services { open_section: 0x1000, map_view: 0x1001, yield_execution: 0x1002, terminate_process, open_process: 0x1003 })
}

/// Montador mínimo de x64 para os programas de teste.
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

    /// Salto condicional para trás.
    fn jcc_to(&mut self, condition: u8, target: usize) {
        self.put(&[0x0F, condition]);
        self.rel32(target);
    }

    fn jmp_to(&mut self, target: usize) {
        self.put(&[0xE9]);
        self.rel32(target);
    }

    /// Salto condicional para frente; devolve a posição a remendar.
    fn jcc_forward(&mut self, condition: u8) -> usize {
        self.put(&[0x0F, condition]);
        let at = self.here();
        self.imm32(0);
        at
    }

    /// O salto em `at` cai aqui.
    fn bind(&mut self, at: usize) {
        let offset = (self.here() as i64 - (at as i64 + 4)) as i32;
        self.bytes[at..at + 4].copy_from_slice(&offset.to_le_bytes());
    }

    fn fail_if_nonzero(&mut self) {
        self.put(&[0x85, 0xC0]);
        let at = self.jcc_forward(JNZ);
        self.failures.push(at);
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
            self.bind(at);
        }
        self.put(&[0x89, 0xC2, 0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF]);
        self.syscall(services.terminate_process);
        self.put(&[0xEB, 0xFE]);
    }

    /// Abre a seção pelo nome (NtOpenSection, SECTION_MAP_READ|WRITE) e
    /// mapeia uma vista no próprio processo (NtMapViewOfSection, ViewUnmap,
    /// PAGE_READWRITE); a base da vista fica em rbx.
    fn map_section(&mut self, services: &Services) {
        // sub rsp, 0x88
        self.put(&[0x48, 0x81, 0xEC, 0x88, 0x00, 0x00, 0x00]);
        // lea rcx, [rsp+0x70]; mov edx, 6; mov r8, OBJECT_ATTRIBUTES
        self.put(&[0x48, 0x8D, 0x4C, 0x24, 0x70, 0xBA, 0x06, 0x00, 0x00, 0x00, 0x49, 0xB8]);
        self.bytes.extend_from_slice(&absolute(NAMED_ATTRIBUTES).to_le_bytes());
        self.syscall(services.open_section);
        self.fail_if_nonzero();
        // xor eax, eax; base = 0; tamanho = 0; commit = 0; offset = NULL
        self.put(&[0x31, 0xC0]);
        self.put(&[0x48, 0x89, 0x44, 0x24, 0x78]);
        self.put(&[0x48, 0x89, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00]);
        self.put(&[0x48, 0x89, 0x44, 0x24, 0x28]);
        self.put(&[0x48, 0x89, 0x44, 0x24, 0x30]);
        // lea rdx, [rsp+0x80]; mov [rsp+0x38], rdx (o ponteiro do tamanho)
        self.put(&[0x48, 0x8D, 0x94, 0x24, 0x80, 0x00, 0x00, 0x00, 0x48, 0x89, 0x54, 0x24, 0x38]);
        // ViewUnmap (2); tipo de alocação 0; PAGE_READWRITE (4)
        self.put(&[0x48, 0xC7, 0x44, 0x24, 0x40, 0x02, 0x00, 0x00, 0x00]);
        self.put(&[0x48, 0x89, 0x44, 0x24, 0x48]);
        self.put(&[0x48, 0xC7, 0x44, 0x24, 0x50, 0x04, 0x00, 0x00, 0x00]);
        // mov rcx, [rsp+0x70]; mov rdx, -1; lea r8, [rsp+0x78]; xor r9d, r9d
        self.put(&[0x48, 0x8B, 0x4C, 0x24, 0x70, 0x48, 0xC7, 0xC2, 0xFF, 0xFF, 0xFF, 0xFF, 0x4C, 0x8D, 0x44, 0x24, 0x78, 0x45, 0x31, 0xC9]);
        self.syscall(services.map_view);
        self.fail_if_nonzero();
        // mov rbx, [rsp+0x78]
        self.put(&[0x48, 0x8B, 0x5C, 0x24, 0x78]);
    }
}

/// O endereço de um deslocamento do conteúdo da imagem (a seção começa no
/// RVA 0x1000 e o exe fica na ImageBase preferida, na raiz própria).
fn absolute(offset: usize) -> u64 {
    IMAGE_BASE + 0x1000 + offset as u64
}

/// O código seguido dos dados (OBJECT_ATTRIBUTES com o nome da seção, o
/// UNICODE_STRING, um OBJECT_ATTRIBUTES sem nome e o texto do nome), numa
/// imagem de uma seção.
fn image(code: Code) -> Vec<u8> {
    assert!(code.here() <= DATA, "programa de teste maior que a area de codigo");
    let mut content = code.bytes;
    let name: Vec<u8> = SECTION_NAME.encode_utf16().flat_map(u16::to_le_bytes).collect();
    content.resize(NAME_TEXT + name.len() + 2, 0);
    let put32 = |content: &mut Vec<u8>, at: usize, value: u32| content[at..at + 4].copy_from_slice(&value.to_le_bytes());
    let put64 = |content: &mut Vec<u8>, at: usize, value: u64| content[at..at + 8].copy_from_slice(&value.to_le_bytes());
    for attributes in [NAMED_ATTRIBUTES, PLAIN_ATTRIBUTES] {
        put32(&mut content, attributes + offset_of!(ObjectAttributes, length), ObjectAttributes::SIZE as u32);
    }
    put64(&mut content, NAMED_ATTRIBUTES + offset_of!(ObjectAttributes, object_name), absolute(NAME_STRING));
    // OBJ_CASE_INSENSITIVE.
    put32(&mut content, NAMED_ATTRIBUTES + offset_of!(ObjectAttributes, attributes), 0x40);
    let length = name.len() as u16;
    content[NAME_STRING + offset_of!(UnicodeString, length)..][..2].copy_from_slice(&length.to_le_bytes());
    content[NAME_STRING + offset_of!(UnicodeString, maximum_length)..][..2].copy_from_slice(&(length + 2).to_le_bytes());
    put64(&mut content, NAME_STRING + offset_of!(UnicodeString, buffer), absolute(NAME_TEXT));
    content[NAME_TEXT..NAME_TEXT + name.len()].copy_from_slice(&name);
    crate::ntos::test::phase7::single_section_image(IMAGE_BASE, 0x0022, b".text", 0x6000_0020, 0x1000, &content)
}

/// O processo que alterna: chega, espera o outro (com limite) e, `ROUNDS`
/// vezes, incrementa o contador, anota o valor visto no diário `slot` e cede
/// a CPU; sai com `code`.
fn alternating_program(services: &Services, slot: u32, code: u32) -> Vec<u8> {
    let mut asm = Code::new();
    asm.map_section(services);
    // lock inc dword [rbx+ARRIVED]; mov edi, ARRIVAL_SPINS
    asm.put(&[0xF0, 0xFF, 0x43, ARRIVED, 0xBF]);
    asm.imm32(ARRIVAL_SPINS);
    let spin = asm.here();
    // cmp dword [rbx+ARRIVED], 2; jae go
    asm.put(&[0x83, 0x7B, ARRIVED, 0x02]);
    let arrived = asm.jcc_forward(JAE);
    asm.syscall(services.yield_execution);
    // dec edi; jnz spin
    asm.put(&[0xFF, 0xCF]);
    asm.jcc_to(JNZ, spin);
    asm.bind(arrived);
    // xor esi, esi
    asm.put(&[0x31, 0xF6]);
    let round = asm.here();
    // mov eax, 1; lock xadd [rbx], eax; mov [rbx+rsi*4+diário], eax
    asm.put(&[0xB8, 0x01, 0x00, 0x00, 0x00, 0xF0, 0x0F, 0xC1, 0x03, 0x89, 0x84, 0xB3]);
    asm.imm32(LOG + slot * LOG_STRIDE);
    asm.syscall(services.yield_execution);
    // inc esi; cmp esi, ROUNDS; jb round
    asm.put(&[0xFF, 0xC6, 0x81, 0xFE]);
    asm.imm32(ROUNDS);
    asm.jcc_to(JB, round);
    asm.exit(services, code);
    asm.failure_path(services);
    image(asm)
}

/// A vítima: publica a vista e gira para sempre incrementando o contador
/// dela, sem syscall.
fn victim_program(services: &Services) -> Vec<u8> {
    let mut asm = Code::new();
    asm.map_section(services);
    // mov [rbx+VICTIM_VIEW], rbx
    asm.put(&[0x48, 0x89, 0x5B, VICTIM_VIEW]);
    let spin = asm.here();
    // lock inc dword [rbx+VICTIM_COUNTER]; jmp spin
    asm.put(&[0xF0, 0xFF, 0x43, VICTIM_COUNTER]);
    asm.jmp_to(spin);
    asm.failure_path(services);
    image(asm)
}

/// O matador: espera o contador da vítima andar, abre o processo dela pelo
/// PID publicado, o termina com `KILL_CODE`, anota os status e o contador da
/// vítima naquele instante, faz `KILLER_ROUNDS` voltas (incremento e
/// cessão) e sai com `KILLER_CODE`.
fn killer_program(services: &Services) -> Vec<u8> {
    let mut asm = Code::new();
    asm.map_section(services);
    // mov [rbx+KILLER_VIEW], rbx
    asm.put(&[0x48, 0x89, 0x5B, KILLER_VIEW]);
    let wait = asm.here();
    // mov eax, [rbx+VICTIM_COUNTER]; test eax, eax; jnz go
    asm.put(&[0x8B, 0x43, VICTIM_COUNTER, 0x85, 0xC0]);
    let advanced = asm.jcc_forward(JNZ);
    asm.syscall(services.yield_execution);
    asm.jmp_to(wait);
    asm.bind(advanced);
    // CLIENT_ID em [rsp+0x60] = { PID da vítima, 0 }; handle de saída em [rsp+0x58]
    asm.put(&[0x48, 0x8B, 0x43, VICTIM_PID, 0x48, 0x89, 0x44, 0x24, 0x60, 0x31, 0xC0, 0x48, 0x89, 0x44, 0x24, 0x68, 0x48, 0x89, 0x44, 0x24, 0x58]);
    // lea rcx, [rsp+0x58]; mov edx, PROCESS_TERMINATE; mov r8, OBJECT_ATTRIBUTES sem nome; lea r9, [rsp+0x60]
    asm.put(&[0x48, 0x8D, 0x4C, 0x24, 0x58, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x49, 0xB8]);
    asm.bytes.extend_from_slice(&absolute(PLAIN_ATTRIBUTES).to_le_bytes());
    asm.put(&[0x4C, 0x8D, 0x4C, 0x24, 0x60]);
    asm.syscall(services.open_process);
    // mov [rbx+OPEN_STATUS], eax
    asm.put(&[0x89, 0x43, OPEN_STATUS]);
    asm.fail_if_nonzero();
    // mov rcx, [rsp+0x58]; mov edx, KILL_CODE
    asm.put(&[0x48, 0x8B, 0x4C, 0x24, 0x58, 0xBA]);
    asm.imm32(KILL_CODE);
    asm.syscall(services.terminate_process);
    // mov [rbx+KILL_STATUS], eax; mov eax, [rbx+VICTIM_COUNTER]; mov [rbx+VICTIM_AT_KILL], eax
    asm.put(&[0x89, 0x43, KILL_STATUS, 0x8B, 0x43, VICTIM_COUNTER, 0x89, 0x43, VICTIM_AT_KILL]);
    // xor esi, esi
    asm.put(&[0x31, 0xF6]);
    let round = asm.here();
    // lock inc dword [rbx+KILLER_COUNTER]
    asm.put(&[0xF0, 0xFF, 0x43, KILLER_COUNTER]);
    asm.syscall(services.yield_execution);
    // inc esi; cmp esi, KILLER_ROUNDS; jb round
    asm.put(&[0xFF, 0xC6, 0x81, 0xFE]);
    asm.imm32(KILLER_ROUNDS);
    asm.jcc_to(JB, round);
    asm.exit(services, KILLER_CODE);
    asm.failure_path(services);
    image(asm)
}

/// Onde a thread auxiliar gira (`jmp $`) no programa do
/// NtTerminateProcess(NULL).
const HELPER_SPIN: usize = 0x3F0;
const NULL_CODE: u32 = 0x5E;
const AFTER_NULL_CODE: u32 = 0x64;

/// NtTerminateProcess(NULL, NULL_CODE): as outras threads terminam e esta
/// segue para sair com AFTER_NULL_CODE (ou com o status, se a chamada
/// falhou). A thread auxiliar gira em HELPER_SPIN.
fn null_handle_program(services: &Services) -> Vec<u8> {
    let mut asm = Code::new();
    // xor ecx, ecx; mov edx, NULL_CODE
    asm.put(&[0x31, 0xC9, 0xBA]);
    asm.imm32(NULL_CODE);
    asm.syscall(services.terminate_process);
    asm.fail_if_nonzero();
    asm.exit(services, AFTER_NULL_CODE);
    asm.failure_path(services);
    asm.bytes.resize(HELPER_SPIN, 0xCC);
    asm.put(&[0xEB, 0xFE]);
    image(asm)
}

/// A seção nomeada do teste (SEC_COMMIT, uma página) e uma vista dela no
/// System, por onde o teste lê e escreve os campos.
struct Shared {
    block: u64,
    handle: u64,
    view: u64,
}

impl Shared {
    fn create() -> Option<Self> {
        let block = memory::map_user_region(0x1000).ok()?;
        let (attributes, string, text, out, size, base, view_size, rsp) = (block, block + 0x30, block + 0x40, block + 0x100, block + 0x108, block + 0x110, block + 0x118, block + 0x800);
        let name: Vec<u8> = SECTION_NAME.encode_utf16().flat_map(u16::to_le_bytes).collect();
        guest::write_bytes(text, &name);
        // SAFETY: estruturas no bloco de usuário recém-mapeado do processo corrente.
        let (object, unicode, maximum) = unsafe { (ObjectAttributes::at(attributes), UnicodeString::at(string), LargeInteger::at(size)) };
        unicode.length.set(name.len() as u16);
        unicode.maximum_length.set(name.len() as u16 + 2);
        unicode.buffer.set(text);
        object.length.set(ObjectAttributes::SIZE as u32);
        object.root_directory.set(0);
        object.object_name.set(string);
        object.attributes.set(0x40);
        object.security_descriptor.set(0);
        object.security_quality_of_service.set(0);
        maximum.quad_part.set(0x1000);
        let call = |name: &str, a: u64, b: u64, c: u64, d: u64| state::handler(name).map_or(1, |handler| handler(a, b, c, d, rsp).unwrap_or(1));
        // PAGE_READWRITE, SEC_COMMIT, sem arquivo.
        guest::write64(rsp + 0x28, 4);
        guest::write64(rsp + 0x30, 0x0800_0000);
        guest::write64(rsp + 0x38, 0);
        let created = call("NtCreateSection", out, 0xF_001F, attributes, size);
        let handle = guest::read64(out);
        guest::write64(base, 0);
        guest::write64(view_size, 0);
        for (index, value) in [0u64, 0, view_size, 2, 0, 4].into_iter().enumerate() {
            guest::write64(rsp + 0x28 + index as u64 * 8, value);
        }
        let mapped = if created == 0 { call("NtMapViewOfSection", handle, u64::MAX, base, 0) } else { 1 };
        let view = guest::read64(base);
        let shared = Self { block, handle: if created == 0 { handle } else { 0 }, view: if mapped == 0 { view } else { 0 } };
        (created == 0 && mapped == 0 && view != 0).then_some(shared)
    }

    fn read32(&self, offset: u32) -> u32 {
        guest::read32(self.view + offset as u64)
    }

    fn read64(&self, offset: u32) -> u64 {
        guest::read64(self.view + offset as u64)
    }

    fn write32(&self, offset: u32, value: u32) {
        guest::write32(self.view + offset as u64, value);
    }

    fn write64(&self, offset: u32, value: u64) {
        guest::write64(self.view + offset as u64, value);
    }

    fn clear(&self) {
        guest::write_bytes(self.view, &[0u8; 0x1000]);
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        if self.view != 0 {
            let _ = state::handler("NtUnmapViewOfSection").map(|handler| handler(u64::MAX, self.view, 0, 0, 0));
        }
        if self.handle != 0 {
            let _ = state::close_user_handle(self.handle, true, false);
        }
        if let Some(region) = memory::find_region(self.block) {
            memory::release_private_region(&region);
        }
    }
}

/// Cria um processo do programa pelo caminho único; o EPROCESS fica retido
/// pelo teste.
fn create_program(name: &str, bytes: Vec<u8>) -> Option<CreatedProcess> {
    let request = user_process::windows_process_request(ImageOrigin::Bytes(bytes), name, &format!("C:\\{name}"), &RunOptions::default());
    match create::create_user_process(&request) {
        Ok(created) => {
            process::reference(created.process_pointer);
            Some(created)
        }
        Err(failure) => {
            crate::debug_print!("[despacho] {} nao criado: {}", name, failure);
            None
        }
    }
}

/// Cria e põe no despachante.
fn launch(name: &str, bytes: Vec<u8>) -> Option<(u64, StartedProcess)> {
    let created = create_program(name, bytes)?;
    let pointer = created.process_pointer;
    // A thread principal é GUI: os serviços de teste entram pela tabela 1
    // do Shadow.
    // SAFETY: a ETHREAD da thread principal, viva enquanto o processo vive.
    unsafe { Ethread::at(created.thread_pointer) }.tcb.set_gui_thread(1);
    match user_process::start_created(created) {
        Ok(started) => Some((pointer, started)),
        Err(error) => {
            crate::debug_print!("[despacho] {} nao partiu: {}", name, error);
            let _ = process::dereference(pointer);
            None
        }
    }
}

fn exit_status(process: u64) -> u32 {
    // SAFETY: EPROCESS retido pelo teste.
    unsafe { Eprocess::at(process) }.exit_status.get() as u32
}

/// A metade de usuário da raiz só tem a visão da KUSER_SHARED_DATA.
fn only_kuser(root: u64) -> bool {
    let kuser_end = MM_SHARED_USER_DATA_VA + 0x1000;
    root != 0 && paging::find_mapping_in(root, map::LOWEST_USER_ADDRESS, MM_SHARED_USER_DATA_VA - map::LOWEST_USER_ADDRESS).is_none() && paging::find_mapping_in(root, kuser_end, map::USER_ADDRESS_LIMIT - kuser_end).is_none() && paging::translate_in(root, MM_SHARED_USER_DATA_VA) != 0
}

/// Nada do processo sobra nas tabelas do despacho.
fn no_threads(process: u64) -> bool {
    threads::of_process(process).is_empty() && !threads::all().iter().any(|thread| thread.with(|thread| thread.process_pointer) == process)
}

pub fn run(assert: Assert) {
    if !usermode::ready() || process::get_current_thread() == 0 {
        assert(false, "despacho: anel 3 armado e thread corrente");
        return;
    }
    if state::with(|state| state.ntdll_exports.as_ref().is_none_or(|exports| !exports.contains_key("LdrInitializeThunk"))) {
        assert(false, "despacho: ntdll com LdrInitializeThunk mapeada");
        return;
    }
    let Some(services) = services() else {
        assert(false, "despacho: numeros de servico da ntdll");
        return;
    };
    let _ = csr::initialize();
    let Some(shared) = Shared::create() else {
        assert(false, "despacho: secao nomeada e vista do teste");
        return;
    };
    let Some(saved) = publish_services() else {
        assert(false, "despacho: tabela 1 de teste com os servicos encaminhados");
        return;
    };
    alternation(assert, &services, &shared);
    termination(assert, &services, &shared);
    null_handle(assert, &services);
    restore_services(saved);
    drop(shared);
    kernel_stack::reap();
}

/// Dois processos postos no despachante antes de qualquer espera alternam
/// no contador da seção e saem com os próprios códigos.
fn alternation(assert: Assert, services: &Services, shared: &Shared) {
    shared.clear();
    let first = launch("alterna-a.exe", alternating_program(services, 0, FIRST_CODE));
    let second = launch("alterna-b.exe", alternating_program(services, 1, SECOND_CODE));
    let (Some((a, first)), Some((b, second))) = (first, second) else {
        assert(false, "despacho: dois processos criados e postos no despachante");
        return;
    };
    let first_exit = user_process::wait_started(first);
    let second_exit = user_process::wait_started(second);
    let logs: [Vec<u32>; 2] = core::array::from_fn(|slot| (0..ROUNDS).map(|round| shared.read32(LOG + slot as u32 * LOG_STRIDE + round * 4)).collect());
    let counter = shared.read32(0);
    crate::debug_print!("[despacho] diarios {:?} {:?} contador {} saidas {:?} {:?}", logs[0], logs[1], counter, first_exit.as_ref().map_err(|error| format!("{error}")), second_exit.as_ref().map_err(|error| format!("{error}")));
    let exited = matches!(first_exit, Ok(FIRST_CODE)) && matches!(second_exit, Ok(SECOND_CODE)) && exit_status(a) == FIRST_CODE && exit_status(b) == SECOND_CODE;
    assert(exited, "despacho: os dois processos saem com os proprios codigos, distintos");
    let mut all: Vec<u32> = logs.iter().flatten().copied().collect();
    all.sort_unstable();
    let complete = counter == 2 * ROUNDS && all.iter().copied().eq(0..2 * ROUNDS) && logs.iter().all(|log| log.windows(2).all(|pair| pair[0] < pair[1]));
    assert(complete, "despacho: os 2N incrementos ficam no contador da secao, cada diario em ordem");
    let interleaved = logs[0][ROUNDS as usize - 1] > logs[1][0] && logs[1][ROUNDS as usize - 1] > logs[0][0];
    assert(interleaved, "despacho: os dois processos avancam no contador antes de qualquer um sair (diarios intercalados)");
    let gone = process_state::get(a).is_none() && process_state::get(b).is_none() && no_threads(a) && no_threads(b);
    assert(gone, "despacho: nada dos dois fica no estado nem no indice de threads");
    let _ = process::dereference(a);
    let _ = process::dereference(b);
}

/// Um processo termina o outro por handle; os dois andam só pelo tick.
fn termination(assert: Assert, services: &Services, shared: &Shared) {
    shared.clear();
    for status in [KILL_STATUS, OPEN_STATUS] {
        shared.write32(status as u32, UNSET);
    }
    let Some((victim, victim_started)) = launch("vitima.exe", victim_program(services)) else {
        assert(false, "despacho: vitima criada e posta no despachante");
        return;
    };
    // SAFETY: EPROCESS retido pelo teste.
    shared.write64(VICTIM_PID as u32, unsafe { Eprocess::at(victim) }.unique_process_id.get());
    let victim_thread = threads::of_process(victim).first().map_or(0, |thread| thread.pointer());
    // SAFETY: a KTHREAD da thread principal da vítima, viva até o término.
    let victim_stack = if victim_thread != 0 { unsafe { Kthread::at(victim_thread) }.stack_base.get() } else { 0 };
    let victim_root = address_space::root_of(victim).unwrap_or(0);
    let Some((killer, killer_started)) = launch("matador.exe", killer_program(services)) else {
        let _ = create::exit_process(victim, 0xC000_0001);
        let _ = user_process::wait_started(victim_started);
        let _ = process::dereference(victim);
        assert(false, "despacho: matador criado e posto no despachante");
        return;
    };
    let killer_root = address_space::root_of(killer).unwrap_or(0);

    // Só o tick: ninguém espera os dois. No instante em que o término da
    // vítima aparece, o matador ainda está no meio das voltas.
    let deadline = clock::uptime_ms() + TICK_DEADLINE_MS;
    let mut during_kill = None;
    while clock::uptime_ms() < deadline && process_state::get(killer).is_some() {
        scheduler::tick(-1);
        if during_kill.is_none() && shared.read32(KILL_STATUS as u32) != UNSET {
            kernel_stack::reap();
            let victim_view = shared.read64(VICTIM_VIEW as u32);
            let killer_view = shared.read64(KILLER_VIEW as u32);
            let released = process_state::get(victim).is_none() && no_threads(victim) && victim_view != 0 && views::find(victim, victim_view).is_none() && only_kuser(victim_root) && (victim_stack == 0 || kernel_stack::find(victim_stack).is_none());
            let killer_alive = process_state::get(killer).is_some() && shared.read32(KILLER_COUNTER as u32) < KILLER_ROUNDS && killer_view != 0 && paging::translate_in(killer_root, killer_view) != 0;
            during_kill = Some((released, killer_alive, shared.read32(VICTIM_COUNTER as u32)));
        }
    }
    let ticked = process_state::get(killer).is_none();
    if !ticked {
        crate::debug_print!("[despacho] o matador nao terminou pelo tick: vitima={} matador={} abertura={:#x} termino={:#x}", shared.read32(VICTIM_COUNTER as u32), shared.read32(KILLER_COUNTER as u32), shared.read32(OPEN_STATUS as u32), shared.read32(KILL_STATUS as u32));
        // Encerra o que ainda roda, para as esperas abaixo acabarem.
        let _ = create::exit_process(victim, 0xC000_0001);
        let _ = create::exit_process(killer, 0xC000_0001);
    }
    assert(ticked, "despacho: a vitima e o matador andam so pelo scheduler::tick, sem ninguem espera-los, e o matador acaba");
    let victim_exit = user_process::wait_started(victim_started);
    let killer_exit = user_process::wait_started(killer_started);
    let (open_status, kill_status) = (shared.read32(OPEN_STATUS as u32), shared.read32(KILL_STATUS as u32));
    let (victim_counter, at_kill, killer_counter) = (shared.read32(VICTIM_COUNTER as u32), shared.read32(VICTIM_AT_KILL as u32), shared.read32(KILLER_COUNTER as u32));
    crate::debug_print!("[despacho] termino: abertura={:#x} termino={:#x} vitima={} no termino={} matador={} durante={:?} saidas {:?} {:?}", open_status, kill_status, victim_counter, at_kill, killer_counter, during_kill, victim_exit.as_ref().map_err(|error| format!("{error}")), killer_exit.as_ref().map_err(|error| format!("{error}")));
    assert(open_status == 0 && kill_status == 0 && matches!(victim_exit, Ok(KILL_CODE)) && exit_status(victim) == KILL_CODE, "despacho: o matador abre a vitima pelo CLIENT_ID e a termina pelo handle; ela sai com o codigo pedido");
    assert(during_kill.is_some_and(|(released, _, _)| released), "despacho: logo depois do termino a vitima ja nao tem estado, threads, vista nem pilha de kernel, e a raiz dela fica so com a KUSER");
    assert(during_kill.is_some_and(|(_, alive, _)| alive), "despacho: o matador segue vivo e no meio das voltas quando a vitima ja foi liberada, com a vista dele mapeada");
    assert(victim_counter != 0 && victim_counter == at_kill && during_kill.is_some_and(|(_, _, seen)| seen == at_kill), "despacho: a vitima girou (so o timer a tirou da CPU) e o contador dela parou no termino");
    assert(matches!(killer_exit, Ok(KILLER_CODE)) && exit_status(killer) == KILLER_CODE && killer_counter == KILLER_ROUNDS, "despacho: o matador faz todas as voltas depois do termino e sai com o proprio codigo");
    let gone = no_threads(victim) && no_threads(killer) && process_state::get(killer).is_none();
    assert(gone, "despacho: nada dos dois fica no indice de threads");
    let _ = process::dereference(victim);
    let _ = process::dereference(killer);
    assert(address_space::root_of(victim).is_none() && address_space::root_of(killer).is_none(), "despacho: as raizes dos dois voltam no ultimo dereference");
}

/// NtTerminateProcess(NULL) termina as outras threads e quem chamou segue.
fn null_handle(assert: Assert, services: &Services) {
    let Some((pointer, started)) = launch("nulo.exe", null_handle_program(services)) else {
        assert(false, "despacho: processo do NtTerminateProcess(NULL) criado e posto no despachante");
        return;
    };
    // A segunda thread, pelo caminho do NtCreateThreadEx, anexado ao
    // processo antes de ele rodar.
    let request = threads::CreateRequest { start: absolute(HELPER_SPIN), argument_words: [0, 0], flags: 0, zero_bits: 0, commit: 0, reserve: 0 };
    let helper = process_context::with_process(pointer, || threads::create_user_thread(&request)).ok().and_then(|created| created.ok());
    let exit = user_process::wait_started(started);
    let helper_status = helper.as_ref().map(|thread| thread.with(|thread| (thread.dead, thread.exit_status)));
    crate::debug_print!("[despacho] NULL: saida {:?}, segunda thread {:?}", exit.as_ref().map_err(|error| format!("{error}")), helper_status);
    assert(matches!(exit, Ok(AFTER_NULL_CODE)) && exit_status(pointer) == AFTER_NULL_CODE, "despacho: NtTerminateProcess(NULL) nao encerra quem chamou: a chamada devolve sucesso e o processo sai depois com o proprio codigo");
    assert(helper_status == Some((true, NULL_CODE)), "despacho: NtTerminateProcess(NULL) termina a outra thread do processo com o status pedido");
    let gone = process_state::get(pointer).is_none() && no_threads(pointer);
    assert(gone, "despacho: nada do processo fica no estado nem no indice de threads");
    drop(helper);
    let _ = process::dereference(pointer);
}
