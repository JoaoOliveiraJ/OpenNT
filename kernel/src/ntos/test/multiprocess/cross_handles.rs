//! Handles e informações entre processos (`ps/user/handles.rs`
//! NtDuplicateObject, NtOpenProcess e NtOpenThread; a herança de
//! `state::inherit_user_handles` pelo `inherit_handles_from` de
//! `ps/create.rs`; o NtQueryInformationProcess/Thread de outro processo):
//!
//! - Um processo pai real, criado pelo caminho único, ganha dois eventos de
//!   notificação: um comum e um com OBJ_INHERIT. O filho é criado pelo pai
//!   (anexado a ele) com a herança de handles e fica parado. Antes de
//!   qualquer um rodar:
//!   - o handle inherit está na tabela do filho com o MESMO valor, o mesmo
//!     acesso e os mesmos atributos, sobre o mesmo objeto, com a linha na
//!     ObjectTable do filho; o comum não foi herdado; o
//!     InheritedFromUniqueProcessId do filho é o PID do pai;
//!   - o pai abre o filho por CLIENT_ID (NtOpenProcess) e a
//!     ProcessBasicInformation pelo handle traz a PEB, o PID e o pai do
//!     filho; o NtOpenThread pelo CLIENT_ID da thread principal dá a
//!     ThreadBasicInformation dela (TEB e CLIENT_ID); a thread não é do PID
//!     do pai (STATUS_INVALID_CID);
//!   - acessos negados são recusados: o NtOpenProcess e o NtOpenThread de
//!     uma thread que impersona o token anônimo (a DACL do filho só concede
//!     ao SYSTEM), a ProcessBasicInformation e a duplicação por um handle
//!     do filho só com SYNCHRONIZE (sem PROCESS_QUERY_LIMITED_INFORMATION nem
//!     PROCESS_DUP_HANDLE) e uma duplicação que pede direitos que a origem não
//!     tem; nada entra na tabela do filho;
//!   - o pai duplica para o filho um handle só com SYNCHRONIZE e o traz de
//!     volta com DUPLICATE_CLOSE_SOURCE: some do filho (tabela e ObjectTable)
//!     e reaparece no pai com o mesmo acesso; o pseudo-handle de processo na
//!     origem é o próprio filho; com destino nulo, DUPLICATE_CLOSE_SOURCE só
//!     fecha a origem no filho.
//! - Os dois rodam. O pai, em anel 3, duplica o evento comum para o filho
//!   (NtDuplicateObject(-1, evento, filho, ..., OBJ_INHERIT,
//!   DUPLICATE_SAME_ACCESS)) e espera nele (NtWaitForSingleObject). Com o pai
//!   já bloqueado na espera, a cópia está na tabela do filho com o mesmo
//!   acesso e OBJ_INHERIT, e o filho parte: sinaliza o evento herdado pelo
//!   valor que o pai usa e o evento duplicado pelo valor que recebeu
//!   (NtSetEvent), e sai. O pai acorda, confere que o evento herdado está
//!   sinalizado (espera com prazo zero) e sai com o código dele.
//!
//! No código anterior a duplicação para outro processo e a consulta de
//! outro processo devolvem STATUS_NOT_SUPPORTED, não há herança, e o
//! NtOpenThread aceita OBJECT_ATTRIBUTES nulo e não confere acesso.
//!
//! Os programas fazem syscalls de verdade: o NtTerminateProcess pelo número
//! nativo da ntdll de bring-up, e NtDuplicateObject, NtWaitForSingleObject e
//! NtSetEvent (que ela não publica) pela tabela 1 do Shadow, com a thread
//! principal GUI, numa tabela de teste que encaminha ao handler real.

use alloc::format;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use crate::hal::amd64::usermode;
use crate::ntos::ex::{service_abi, service_table};
use crate::ntos::inc::types::{ClientId, Eprocess, Ethread, NtStruct, ObjectAttributes, ProcessBasicInformation, ThreadBasicInformation};
use crate::ntos::ke::pcr;
use crate::ntos::ke::clock;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_stack;
use crate::ntos::ob::handle_table;
use crate::ntos::ob::handles::process as process_handles;
use crate::ntos::ps::create::{self, CreatedProcess, ImageOrigin};
use crate::ntos::ps::user::handles::UserProcess;
use crate::ntos::ps::user::process::{self as user_process, RunOptions, StartedProcess};
use crate::ntos::ps::user::{csr, index, memory, process_state, state, threads};
use crate::ntos::ps::{process, process_context, scheduler};
use crate::ntos::se::token::{impersonate_anonymous, thread as thread_tokens};

type Assert = fn(bool, &str);

const IMAGE_BASE: u64 = 0x1_4000_0000;

// Células de dados dos programas (deslocamentos no conteúdo da imagem).
const DATA: usize = 0x400;
/// O handle do evento comum, no pai.
const EVENT: usize = DATA;
/// O handle do filho, no pai.
const CHILD: usize = DATA + 0x08;
/// O handle do evento herdado: o mesmo valor no pai e no filho.
const INHERITED: usize = DATA + 0x10;
/// Onde o NtDuplicateObject do pai escreve o valor da cópia no filho.
const DUPLICATED_OUT: usize = DATA + 0x18;
/// LARGE_INTEGER zero: a espera sem prazo.
const ZERO: usize = DATA + 0x20;
/// O valor da cópia, no filho.
const DUPLICATED: usize = DATA + 0x28;
/// Fim das células.
const DATA_END: usize = DATA + 0x30;

const PARENT_CODE: u32 = 0x71;
const CHILD_CODE: u32 = 0x72;
/// Prazo para o pai chegar à espera.
const WAIT_DEADLINE_MS: u64 = 10_000;

const STATUS_PENDING: i32 = 0x103;
const INVALID_CID: u32 = 0xC000_000B;
const ACCESS_DENIED: u32 = 0xC000_0022;
/// Direitos de evento.
const EVENT_ALL_ACCESS: u32 = 0x1F_0003;
const EVENT_MODIFY_STATE: u32 = 2;
const SYNCHRONIZE: u32 = 0x10_0000;
/// Direitos de processo e de thread.
const PROCESS_DUP_HANDLE: u32 = 0x40;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const THREAD_QUERY_INFORMATION: u32 = 0x40;
/// Atributo e opções de duplicação.
const OBJ_INHERIT: u32 = 2;
const DUPLICATE_CLOSE_SOURCE: u32 = 1;
const DUPLICATE_SAME_ACCESS: u32 = 2;

// Condição de salto (0F 8x).
const JNZ: u8 = 0x85;

/// Os números de serviço que os programas usam.
struct Services {
    duplicate_object: u32,
    wait_single: u32,
    set_event: u32,
    terminate_process: u32,
}

/// Os serviços encaminhados, na ordem da tabela de teste (índices 0x1000..).
const FORWARDED: [&str; 3] = ["NtDuplicateObject", "NtWaitForSingleObject", "NtSetEvent"];

/// A tabela compactada dos encaminhadores, na imagem do kernel (a entrada é
/// relativa à tabela e só alcança ±128 MB).
static SERVICE_TABLE: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];
static SERVICE_ARGUMENTS: [AtomicU8; 3] = [const { AtomicU8::new(0) }; 3];

/// Encaminha ao handler real, como o portão nativo: a pilha do usuário
/// (KPCR.UserRsp, de onde saem os argumentos 5 em diante) e o registro de
/// serviço da thread.
fn forward(name: &'static str, arguments: [u64; 4]) -> u64 {
    let rsp = pcr::current().user_rsp.get();
    let record = state::SyscallRecord { raw_arguments: 0, stack: Some(state::ServiceStack { rsp, bytes: service_abi::stack_arguments(name).unwrap_or(0) as u64 * 8 }) };
    let result = state::with_syscall_record(record, || index::invoke_service(name, arguments, 0, rsp));
    result.unwrap_or_else(|error| if error.status != 0 { error.status } else { 0xC000_0001 }) as u64
}

extern "win64" fn duplicate_object_service(a: u64, b: u64, c: u64, d: u64) -> u64 {
    forward(FORWARDED[0], [a, b, c, d])
}

extern "win64" fn wait_single_service(a: u64, b: u64, c: u64, d: u64) -> u64 {
    forward(FORWARDED[1], [a, b, c, d])
}

extern "win64" fn set_event_service(a: u64, b: u64, c: u64, d: u64) -> u64 {
    forward(FORWARDED[2], [a, b, c, d])
}

/// Publica a tabela 1 de teste; devolve a anterior, para restaurar.
fn publish_services() -> Option<[u64; 4]> {
    let saved = service_table::shadow_second_table().ok()?;
    let table = SERVICE_TABLE.as_ptr() as u64;
    let routines: [extern "win64" fn(u64, u64, u64, u64) -> u64; 3] = [duplicate_object_service, wait_single_service, set_event_service];
    for (slot, routine) in SERVICE_TABLE.iter().zip(routines) {
        match service_table::encode_entry(table, routine as usize as u64, 0) {
            Ok(entry) => slot.store(entry, Ordering::Release),
            Err(_) => return None,
        }
    }
    if service_table::publish_shadow_second_table(table, 3, SERVICE_ARGUMENTS.as_ptr() as u64).is_err() {
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
    Some(Services { duplicate_object: 0x1000, wait_single: 0x1001, set_event: 0x1002, terminate_process })
}

/// O endereço de um deslocamento do conteúdo da imagem (a seção começa no
/// RVA 0x1000 e o exe fica na ImageBase preferida, na raiz própria).
fn absolute(offset: usize) -> u64 {
    IMAGE_BASE + 0x1000 + offset as u64
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

    fn imm64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// `mov r10, rcx; mov eax, número; syscall`.
    fn syscall(&mut self, number: u32) {
        self.put(&[0x49, 0x89, 0xCA, 0xB8]);
        self.imm32(number);
        self.put(&[0x0F, 0x05]);
    }

    /// `mov rax, endereço; mov <registrador>, [rax]`, com o ModRM/REX do
    /// registrador de destino (`load` = os três bytes do mov).
    fn load(&mut self, load: [u8; 3], offset: usize) {
        self.put(&[0x48, 0xB8]);
        self.imm64(absolute(offset));
        self.put(&load);
    }

    /// `test eax, eax; jnz falha`.
    fn fail_if_nonzero(&mut self) {
        self.put(&[0x85, 0xC0, 0x0F, JNZ]);
        self.failures.push(self.bytes.len());
        self.imm32(0);
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
        let here = self.bytes.len();
        for at in core::mem::take(&mut self.failures) {
            let offset = (here as i64 - (at as i64 + 4)) as i32;
            self.bytes[at..at + 4].copy_from_slice(&offset.to_le_bytes());
        }
        self.put(&[0x89, 0xC2, 0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF]);
        self.syscall(services.terminate_process);
        self.put(&[0xEB, 0xFE]);
    }
}

// `mov <registrador>, [rax]`.
const RCX_FROM_RAX: [u8; 3] = [0x48, 0x8B, 0x08];
const RDX_FROM_RAX: [u8; 3] = [0x48, 0x8B, 0x10];
const R8_FROM_RAX: [u8; 3] = [0x4C, 0x8B, 0x00];

/// O código e as células de dados (zeradas), numa imagem de uma seção
/// gravável.
fn image(code: Code) -> Vec<u8> {
    assert!(code.bytes.len() <= DATA, "programa de teste maior que a area de codigo");
    let mut content = code.bytes;
    content.resize(DATA_END, 0);
    // IMAGE_SCN_CNT_CODE | MEM_EXECUTE | MEM_READ | MEM_WRITE.
    crate::ntos::test::phase7::single_section_image(IMAGE_BASE, 0x0022, b".text", 0xE000_0020, 0x1000, &content)
}

/// O pai: duplica o evento comum para o filho (OBJ_INHERIT,
/// DUPLICATE_SAME_ACCESS, o valor da cópia em DUPLICATED_OUT), espera nele,
/// confere que o evento herdado está sinalizado (prazo zero) e sai com
/// PARENT_CODE (ou com o status do serviço que falhou).
fn parent_program(services: &Services) -> Vec<u8> {
    let mut asm = Code::new();
    // sub rsp, 0x48
    asm.put(&[0x48, 0x83, 0xEC, 0x48]);
    // NtDuplicateObject(-1, [EVENT], [CHILD], DUPLICATED_OUT, 0, OBJ_INHERIT, DUPLICATE_SAME_ACCESS)
    asm.load(RDX_FROM_RAX, EVENT);
    asm.load(R8_FROM_RAX, CHILD);
    asm.put(&[0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0x49, 0xB9]);
    asm.imm64(absolute(DUPLICATED_OUT));
    asm.put(&[0x48, 0xC7, 0x44, 0x24, 0x28]);
    asm.imm32(0);
    asm.put(&[0x48, 0xC7, 0x44, 0x24, 0x30]);
    asm.imm32(OBJ_INHERIT);
    asm.put(&[0x48, 0xC7, 0x44, 0x24, 0x38]);
    asm.imm32(DUPLICATE_SAME_ACCESS);
    asm.syscall(services.duplicate_object);
    asm.fail_if_nonzero();
    // NtWaitForSingleObject([EVENT], FALSE, NULL)
    asm.load(RCX_FROM_RAX, EVENT);
    asm.put(&[0x31, 0xD2, 0x45, 0x31, 0xC0]);
    asm.syscall(services.wait_single);
    asm.fail_if_nonzero();
    // NtWaitForSingleObject([INHERITED], FALSE, &ZERO)
    asm.load(RCX_FROM_RAX, INHERITED);
    asm.put(&[0x31, 0xD2, 0x49, 0xB8]);
    asm.imm64(absolute(ZERO));
    asm.syscall(services.wait_single);
    asm.fail_if_nonzero();
    asm.exit(services, PARENT_CODE);
    asm.failure_path(services);
    image(asm)
}

/// O filho: sinaliza o evento herdado (pelo valor do pai) e o duplicado
/// (NtSetEvent) e sai com CHILD_CODE (ou com o status do que falhou).
fn child_program(services: &Services) -> Vec<u8> {
    let mut asm = Code::new();
    // sub rsp, 0x28
    asm.put(&[0x48, 0x83, 0xEC, 0x28]);
    for cell in [INHERITED, DUPLICATED] {
        // NtSetEvent([cell], NULL)
        asm.load(RCX_FROM_RAX, cell);
        asm.put(&[0x31, 0xD2]);
        asm.syscall(services.set_event);
        asm.fail_if_nonzero();
    }
    asm.exit(services, CHILD_CODE);
    asm.failure_path(services);
    image(asm)
}

/// Um bloco de usuário do processo de onde o teste chama os serviços (o
/// anexado): saídas, estruturas e a pilha dos argumentos 5 em diante.
struct Caller {
    process: u64,
    block: u64,
}

impl Caller {
    fn new(process: u64) -> Option<Self> {
        let block = process_context::with_process(process, || memory::map_user_region(0x2000).ok()).ok().flatten()?;
        Some(Self { process, block })
    }

    fn out(&self) -> u64 {
        self.block
    }

    fn buffer(&self) -> u64 {
        self.block + 0x40
    }

    fn returned(&self) -> u64 {
        self.block + 0x80
    }

    fn client_id(&self) -> u64 {
        self.block + 0x90
    }

    /// OBJECT_ATTRIBUTES sem nome.
    fn attributes(&self) -> u64 {
        self.block + 0xC0
    }

    fn rsp(&self) -> u64 {
        self.block + 0x1000
    }

    /// Anexado ao processo do bloco.
    fn with<T>(&self, body: impl FnOnce() -> T) -> Option<T> {
        process_context::with_process(self.process, body).ok()
    }

    /// Chama o handler `name` anexado, com os argumentos de pilha `stack`
    /// (5 em diante); devolve o status e o que ficou na saída.
    fn call(&self, name: &str, arguments: [u64; 4], stack: &[u64]) -> (u32, u64) {
        self.with(|| {
            for (index, value) in stack.iter().enumerate() {
                guest::write64(self.rsp() + 0x28 + index as u64 * 8, *value);
            }
            let status = state::handler(name).map_or(1, |handler| handler(arguments[0], arguments[1], arguments[2], arguments[3], self.rsp()).unwrap_or(1));
            (status, guest::read64(self.out()))
        })
        .unwrap_or((1, 0))
    }

    /// Um evento de notificação não sinalizado com os atributos de handle
    /// `attributes`.
    fn create_event(&self, attributes: u32) -> u64 {
        self.prepare(|| {
            // SAFETY: estrutura no bloco de usuário do processo anexado.
            let object = unsafe { ObjectAttributes::at(self.attributes()) };
            object.attributes.set(attributes);
        });
        let (status, handle) = self.call("NtCreateEvent", [self.out(), EVENT_ALL_ACCESS as u64, self.attributes(), 0], &[0]);
        if status == 0 { handle } else { 0 }
    }

    /// Zera a saída e o OBJECT_ATTRIBUTES e roda `body` anexado.
    fn prepare(&self, body: impl FnOnce()) {
        let _ = self.with(|| {
            guest::write64(self.out(), 0);
            // SAFETY: estrutura no bloco de usuário do processo anexado.
            let object = unsafe { ObjectAttributes::at(self.attributes()) };
            object.length.set(ObjectAttributes::SIZE as u32);
            object.root_directory.set(0);
            object.object_name.set(0);
            object.attributes.set(0);
            object.security_descriptor.set(0);
            object.security_quality_of_service.set(0);
            body();
        });
    }

    fn set_client_id(&self, process_id: u64, thread_id: u64) {
        self.prepare(|| {
            // SAFETY: estrutura no bloco de usuário do processo anexado.
            let client = unsafe { ClientId::at(self.client_id()) };
            client.unique_process.set(process_id);
            client.unique_thread.set(thread_id);
        });
    }

    /// NtOpenProcess por CLIENT_ID.
    fn open_process(&self, process_id: u64, access: u32) -> (u32, u64) {
        self.set_client_id(process_id, 0);
        self.call("NtOpenProcess", [self.out(), access as u64, self.attributes(), self.client_id()], &[])
    }

    /// NtOpenThread por CLIENT_ID.
    fn open_thread(&self, process_id: u64, thread_id: u64, access: u32) -> (u32, u64) {
        self.set_client_id(process_id, thread_id);
        self.call("NtOpenThread", [self.out(), access as u64, self.attributes(), self.client_id()], &[])
    }

    /// NtDuplicateObject; devolve o status e o handle novo.
    fn duplicate(&self, source_process: u64, source: u64, target_process: u64, access: u32, attributes: u32, options: u32) -> (u32, u64) {
        self.prepare(|| {});
        self.call("NtDuplicateObject", [source_process, source, target_process, self.out()], &[access as u64, attributes as u64, options as u64])
    }

    /// ProcessBasicInformation pelo handle: (status, PEB, PID, pai, saída).
    fn process_basic(&self, handle: u64) -> (u32, u64, u64, u64, i32) {
        let (status, _) = self.call("NtQueryInformationProcess", [handle, 0, self.buffer(), ProcessBasicInformation::SIZE], &[self.returned()]);
        self.with(|| {
            // SAFETY: a saída no bloco de usuário do processo anexado.
            let basic = unsafe { ProcessBasicInformation::at(self.buffer()) };
            (status, basic.peb_base_address.get(), basic.unique_process_id.get(), basic.inherited_from_unique_process_id.get(), basic.exit_status.get())
        })
        .unwrap_or((1, 0, 0, 0, 0))
    }

    /// ThreadBasicInformation pelo handle: (status, TEB, PID, TID, saída).
    fn thread_basic(&self, handle: u64) -> (u32, u64, u64, u64, i32) {
        let (status, _) = self.call("NtQueryInformationThread", [handle, 0, self.buffer(), ThreadBasicInformation::SIZE], &[self.returned()]);
        self.with(|| {
            // SAFETY: a saída no bloco de usuário do processo anexado.
            let basic = unsafe { ThreadBasicInformation::at(self.buffer()) };
            (status, basic.teb_base_address.get(), basic.client_id.unique_process.get(), basic.client_id.unique_thread.get(), basic.exit_status.get())
        })
        .unwrap_or((1, 0, 0, 0, 0))
    }

    fn close(&self, handle: u64) {
        let _ = self.with(|| state::close_user_handle(handle, true, false));
    }
}

/// O que se sabe de um handle na tabela de `process`: (objeto como ponteiro
/// opaco da descrição aberta, corpo nativo, acesso, atributos).
type Seen = (usize, u64, u32, u32);

fn seen(process: u64, handle: u64) -> Option<Seen> {
    process_context::with_process(process, || {
        state::get_user_handle(handle).map(|entry| {
            let object = alloc::sync::Arc::as_ptr(&entry.object) as *const u8 as usize;
            (object, entry.object.native_body().map_or(0, |body| body.pointer), entry.access(), entry.attributes())
        })
    })
    .ok()
    .flatten()
}

/// A linha da HANDLE_TABLE nativa (EPROCESS.ObjectTable) de `process`:
/// (corpo, acesso, atributos).
fn row(process: u64, handle: u64) -> Option<(u64, u32, u32)> {
    process_handles::get(process).and_then(|table| handle_table::row(table, handle as u32)).map(|row| (row.pointer, row.access, row.attributes))
}

fn process_id(process: u64) -> u64 {
    // SAFETY: EPROCESS retido pelo teste.
    unsafe { Eprocess::at(process) }.unique_process_id.get()
}

fn exit_status(process: u64) -> u32 {
    // SAFETY: EPROCESS retido pelo teste.
    unsafe { Eprocess::at(process) }.exit_status.get() as u32
}

/// Quantos handles a tabela de `process` tem.
fn handle_count(process: u64) -> usize {
    process_context::with_process(process, state::user_handle_values).map_or(0, |values| values.len())
}

/// Põe um processo criado no despachante, com a thread principal GUI (os
/// serviços de teste entram pela tabela 1 do Shadow).
fn launch(created: CreatedProcess) -> Option<StartedProcess> {
    // SAFETY: a ETHREAD da thread principal, viva enquanto o processo vive.
    unsafe { Ethread::at(created.thread_pointer) }.tcb.set_gui_thread(1);
    match user_process::start_created(created) {
        Ok(started) => Some(started),
        Err(error) => {
            crate::debug_print!("[entre-processos] nao partiu: {}", error);
            None
        }
    }
}

pub fn run(assert: Assert) {
    if !usermode::ready() || process::get_current_thread() == 0 {
        assert(false, "entre-processos: anel 3 armado e thread corrente");
        return;
    }
    if state::with(|state| state.ntdll_exports.as_ref().is_none_or(|exports| !exports.contains_key("LdrInitializeThunk"))) {
        assert(false, "entre-processos: ntdll com LdrInitializeThunk mapeada");
        return;
    }
    let Some(services) = services() else {
        assert(false, "entre-processos: numeros de servico da ntdll");
        return;
    };
    let _ = csr::initialize();
    let Some(saved) = publish_services() else {
        assert(false, "entre-processos: tabela 1 de teste com os servicos encaminhados");
        return;
    };
    scenario(assert, &services);
    restore_services(saved);
    kernel_stack::reap();
}

fn scenario(assert: Assert, services: &Services) {
    // O pai, parado, com os dois eventos.
    let request = user_process::windows_process_request(ImageOrigin::Bytes(parent_program(services)), "pai-c4.exe", "C:\\pai-c4.exe", &RunOptions::default());
    let parent = match create::create_user_process(&request) {
        Ok(created) => created,
        Err(failure) => {
            assert(false, &format!("entre-processos: pai criado ({failure})"));
            return;
        }
    };
    let parent_pointer = parent.process_pointer;
    process::reference(parent_pointer);
    let parent_id = process_id(parent_pointer);
    let Some(caller) = Caller::new(parent_pointer) else {
        assert(false, "entre-processos: memoria de usuario no pai");
        let _ = process::dereference(parent_pointer);
        return;
    };
    let event = caller.create_event(0);
    let inheritable = caller.create_event(OBJ_INHERIT);
    assert(event != 0 && inheritable != 0 && seen(parent_pointer, inheritable).is_some_and(|(_, _, access, attributes)| access == EVENT_ALL_ACCESS && attributes == OBJ_INHERIT), "entre-processos: o pai tem um evento comum e um com OBJ_INHERIT");

    // O filho, criado pelo pai com a herança de handles, parado.
    let mut request = user_process::windows_process_request(ImageOrigin::Bytes(child_program(services)), "filho-c4.exe", "C:\\filho-c4.exe", &RunOptions::default());
    request.inherit_handles_from = Some(parent_pointer);
    let child = match process_context::with_process(parent_pointer, || create::create_user_process(&request)) {
        Ok(Ok(created)) => created,
        Ok(Err(failure)) => {
            assert(false, &format!("entre-processos: filho criado pelo pai com heranca ({failure})"));
            let _ = process::dereference(parent_pointer);
            return;
        }
        Err(error) => {
            assert(false, &format!("entre-processos: anexar ao pai para criar o filho ({error})"));
            let _ = process::dereference(parent_pointer);
            return;
        }
    };
    let child_pointer = child.process_pointer;
    process::reference(child_pointer);
    let (child_id, child_thread_id, child_peb, child_teb) = (child.process_id, child.thread_id, child.peb, child.teb);

    // A herança: o mesmo valor, acesso e atributos, sobre o mesmo objeto.
    let in_parent = seen(parent_pointer, inheritable);
    let in_child = seen(child_pointer, inheritable);
    let same = in_parent.zip(in_child).is_some_and(|(parent, child)| parent == child && child.1 != 0);
    assert(same, "entre-processos: o handle inherit esta no filho com o mesmo valor, acesso, atributos e objeto");
    let native = in_child.is_some_and(|(_, body, _, _)| row(child_pointer, inheritable) == Some((body, EVENT_ALL_ACCESS, OBJ_INHERIT)));
    assert(native, "entre-processos: a linha do handle herdado na ObjectTable do filho, no mesmo valor");
    assert(seen(child_pointer, event).is_none() && row(child_pointer, event).is_none(), "entre-processos: o handle sem OBJ_INHERIT nao e herdado");
    // SAFETY: EPROCESS retido pelo teste.
    let inherited_from = unsafe { Eprocess::at(child_pointer) }.inherited_from_unique_process_id.get();
    assert(inherited_from == parent_id, "entre-processos: o InheritedFromUniqueProcessId do filho e o PID do pai");

    // NtOpenProcess e NtOpenThread por CLIENT_ID, e as consultas pelos
    // handles.
    let (opened, child_handle) = caller.open_process(child_id, PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION);
    assert(opened == 0 && child_handle != 0 && seen(parent_pointer, child_handle).is_some_and(|(_, body, access, _)| body == child_pointer && access == PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION), "entre-processos: o pai abre o filho por CLIENT_ID");
    let basic = caller.process_basic(child_handle);
    crate::debug_print!("[entre-processos] filho pid={} peb={:#x}; ProcessBasicInformation {:?}", child_id, child_peb, basic);
    assert(basic == (0, child_peb, child_id, parent_id, STATUS_PENDING), "entre-processos: ProcessBasicInformation do filho (PEB, PID, pai, vivo)");
    let (opened_thread, thread_handle) = caller.open_thread(child_id, child_thread_id, THREAD_QUERY_INFORMATION);
    let thread_basic = caller.thread_basic(thread_handle);
    assert(opened_thread == 0 && thread_basic == (0, child_teb, child_id, child_thread_id, STATUS_PENDING), "entre-processos: NtOpenThread por CLIENT_ID e ThreadBasicInformation da thread do filho (TEB, CLIENT_ID)");
    assert(caller.open_thread(parent_id, child_thread_id, THREAD_QUERY_INFORMATION).0 == INVALID_CID, "entre-processos: a thread do filho nao e do PID do pai");

    // Acessos negados.
    let baseline = handle_count(child_pointer);
    let thread = process::get_current_thread();
    let impersonated = matches!(impersonate_anonymous::impersonate(u64::MAX - 1, 0), Ok(0));
    let anonymous = (caller.open_process(child_id, PROCESS_QUERY_LIMITED_INFORMATION), caller.open_thread(child_id, child_thread_id, THREAD_QUERY_INFORMATION));
    let _ = thread_tokens::assign(thread, None, 0, false, false);
    assert(impersonated && anonymous == ((ACCESS_DENIED, 0), (ACCESS_DENIED, 0)), "entre-processos: com o token anonimo, NtOpenProcess e NtOpenThread do filho sao negados pela DACL");
    let (synchronize_opened, synchronize_only) = caller.open_process(child_id, SYNCHRONIZE);
    let denied_query = caller.process_basic(synchronize_only).0;
    let denied_target = caller.duplicate(u64::MAX, event, synchronize_only, 0, 0, DUPLICATE_SAME_ACCESS).0;
    assert(synchronize_opened == 0 && denied_query == ACCESS_DENIED && denied_target == ACCESS_DENIED, "entre-processos: handle do filho so com SYNCHRONIZE nao consulta nem recebe duplicata");
    let (narrowed, event_synchronize) = caller.duplicate(u64::MAX, event, u64::MAX, SYNCHRONIZE, 0, 0);
    let widened = caller.duplicate(u64::MAX, event_synchronize, child_handle, EVENT_MODIFY_STATE, 0, 0).0;
    assert(narrowed == 0 && seen(parent_pointer, event_synchronize).is_some_and(|(_, _, access, _)| access == SYNCHRONIZE) && widened == ACCESS_DENIED, "entre-processos: a duplicacao estreita o acesso e nao concede direitos que a origem nao tem");
    assert(handle_count(child_pointer) == baseline, "entre-processos: nada negado entra na tabela do filho");

    // Para o filho e de volta com DUPLICATE_CLOSE_SOURCE.
    let (sent, in_child_handle) = caller.duplicate(u64::MAX, event_synchronize, child_handle, 0, 0, DUPLICATE_SAME_ACCESS);
    let event_object = seen(parent_pointer, event).map_or(0, |(object, _, _, _)| object);
    let arrived = seen(child_pointer, in_child_handle);
    assert(sent == 0 && arrived.is_some_and(|(object, body, access, attributes)| object == event_object && access == SYNCHRONIZE && attributes == 0 && row(child_pointer, in_child_handle) == Some((body, SYNCHRONIZE, 0))), "entre-processos: NtDuplicateObject do pai para o filho, com a linha na ObjectTable do filho");
    let (returned, back) = caller.duplicate(child_handle, in_child_handle, u64::MAX, 0, 0, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
    let gone = seen(child_pointer, in_child_handle).is_none() && row(child_pointer, in_child_handle).is_none();
    assert(returned == 0 && gone && seen(parent_pointer, back).is_some_and(|(object, _, access, _)| object == event_object && access == SYNCHRONIZE), "entre-processos: DUPLICATE_CLOSE_SOURCE fecha a origem no filho e a copia fica no pai");
    let (pseudo, child_again) = caller.duplicate(child_handle, u64::MAX, u64::MAX, PROCESS_QUERY_LIMITED_INFORMATION, 0, 0);
    let names_child = caller.with(|| state::get_user_handle(child_again).and_then(|entry| entry.downcast::<UserProcess>().map(|object| object.pointer))).flatten();
    assert(pseudo == 0 && names_child == Some(child_pointer), "entre-processos: o pseudo-handle de processo na origem e o proprio processo de origem");
    let (_, closing) = caller.duplicate(u64::MAX, event_synchronize, child_handle, 0, 0, DUPLICATE_SAME_ACCESS);
    let close_only = caller.duplicate(child_handle, closing, 0, 0, 0, DUPLICATE_CLOSE_SOURCE).0;
    assert(closing != 0 && close_only == 0 && seen(child_pointer, closing).is_none() && handle_count(child_pointer) == baseline, "entre-processos: com destino nulo, DUPLICATE_CLOSE_SOURCE so fecha a origem no filho");
    for handle in [thread_handle, synchronize_only, event_synchronize, back, child_again] {
        caller.close(handle);
    }

    // Os programas: o pai recebe os handles; o filho, o valor herdado.
    let _ = caller.with(|| {
        guest::write64(absolute(EVENT), event);
        guest::write64(absolute(CHILD), child_handle);
        guest::write64(absolute(INHERITED), inheritable);
    });
    let _ = process_context::with_process(child_pointer, || guest::write64(absolute(INHERITED), inheritable));

    let Some(parent_started) = launch(parent) else {
        assert(false, "entre-processos: pai posto no despachante");
        drop(child);
        let _ = process::dereference(child_pointer);
        let _ = process::dereference(parent_pointer);
        return;
    };
    // O pai anda só pelo tick até bloquear na espera.
    let deadline = clock::uptime_ms() + WAIT_DEADLINE_MS;
    let main = threads::of_process(parent_pointer).first().cloned();
    // O valor que o NtDuplicateObject do pai escreveu, lido anexado enquanto
    // ele vive (um pai que já saiu não tem mais a imagem).
    let duplicated_out = || if process_state::get(parent_pointer).is_some() { caller.with(|| guest::try_read::<u64>(absolute(DUPLICATED_OUT)).unwrap_or(0)).unwrap_or(0) } else { 0 };
    let blocked = || main.as_ref().is_some_and(|thread| thread.waiting()) && duplicated_out() != 0;
    while clock::uptime_ms() < deadline && process_state::get(parent_pointer).is_some() && !blocked() {
        scheduler::tick(-1);
    }
    let waiting = blocked();
    let duplicated = duplicated_out();
    let copy = seen(child_pointer, duplicated);
    crate::debug_print!("[entre-processos] pai bloqueado={} copia no filho={:#x} {:?}", waiting, duplicated, copy);
    assert(waiting, "entre-processos: o pai duplica o evento para o filho em anel 3 e bloqueia esperando nele");
    let copied = copy.is_some_and(|(object, body, access, attributes)| object == event_object && access == EVENT_ALL_ACCESS && attributes == OBJ_INHERIT && row(child_pointer, duplicated) == Some((body, EVENT_ALL_ACCESS, OBJ_INHERIT)));
    assert(copied, "entre-processos: a copia esta no filho com o mesmo acesso (DUPLICATE_SAME_ACCESS) e OBJ_INHERIT, na ObjectTable dele");
    let _ = process_context::with_process(child_pointer, || guest::write64(absolute(DUPLICATED), duplicated));

    // O filho sinaliza e sai; o pai acorda e sai.
    let child_started = if waiting {
        launch(child)
    } else {
        drop(child);
        None
    };
    if child_started.is_none() {
        let _ = create::exit_process(parent_pointer, 0xC000_0001);
    }
    let parent_exit = user_process::wait_started(parent_started);
    let child_exit = child_started.map(user_process::wait_started);
    crate::debug_print!("[entre-processos] saidas: pai {:?} filho {:?}", parent_exit.as_ref().map_err(|error| format!("{error}")), child_exit.as_ref().map(|exit| exit.as_ref().map_err(|error| format!("{error}"))));
    assert(matches!(child_exit, Some(Ok(CHILD_CODE))) && exit_status(child_pointer) == CHILD_CODE, "entre-processos: o filho sinaliza o evento herdado pelo valor do pai e o duplicado, e sai");
    assert(matches!(parent_exit, Ok(PARENT_CODE)) && exit_status(parent_pointer) == PARENT_CODE, "entre-processos: o sinal do filho acorda o pai, que ve o evento herdado sinalizado e sai");
    let released = process_state::get(parent_pointer).is_none() && process_state::get(child_pointer).is_none();
    assert(released, "entre-processos: nada dos dois fica no estado");
    let _ = process::dereference(child_pointer);
    let _ = process::dereference(parent_pointer);
}
