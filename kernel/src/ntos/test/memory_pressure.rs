//! Pressão de memória sobre o arquivo de paginação (`--memory-pressure`,
//! no boot do smss real com pouca RAM).
//!
//! Depois que o smss.exe real cria o arquivo de paginação do Registro (o
//! `PAGEFILE_OK` do NtCreatePagingFile), uma thread de sistema cria um
//! programa de usuário gerado aqui, de subsistema nativo e sem imports, que
//! só usa as chamadas de sistema do Windows:
//!
//! - NtQuerySystemInformation(SystemBasicInformation e
//!   SystemPerformanceInformation) no começo;
//! - comita, em blocos de 4 MB (NtAllocateVirtualMemory, MEM_COMMIT |
//!   MEM_RESERVE, PAGE_READWRITE), mais memória privada que toda a RAM dada
//!   à máquina, e grava em cada quadword o próprio endereço misturado com
//!   uma constante; os blocos anteriores saem do working set para o arquivo
//!   de paginação enquanto os seguintes são comitados;
//! - relê todos os blocos e confere cada quadword (as faltas de página
//!   trazem as páginas de volta do arquivo);
//! - consulta SystemPageFileInformation e de novo SystemPerformanceInformation
//!   e espera (NtDelayExecution) o teste ler os resultados antes de sair
//!   com 0x600D.
//!
//! O teste confere o resultado, a entrada do arquivo de paginação (nome,
//! tamanho e páginas em uso), que houve escrita e leitura do arquivo de
//! paginação (DirtyPagesWriteCount e PageReadCount) e que o commit passou
//! da RAM. A serial mostra `MEMORY_PRESSURE_OK` ou o motivo da falha.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::ke::{clock, thread_priority, wait};
use crate::ntos::ps::process;
use crate::hal::physical;
use crate::ntos::mm::process_address_space as address_space;
use crate::ntos::mm::{commit, paging, paging_file};
use crate::ntos::ps::create::{self, ImageOrigin};
use crate::ntos::ps::user::process::{self as user_process, RunOptions};
use crate::ntos::ps::user::{process_state, state};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::Eprocess;

const IMAGE_BASE: u64 = 0x1_4000_0000;
const SECTION_RVA: u64 = 0x1000;
/// Bloco de cada NtAllocateVirtualMemory.
const CHUNK_BYTES: u64 = 4 << 20;
/// Além da RAM, quanto o programa comita.
const BEYOND_RAM: u64 = 8 << 20;
/// O valor misturado a cada endereço.
const MAGIC: u64 = 0x5A17_C0DE_0BAD_F00D;
const EXIT_CODE: u32 = 0x600D;
const UNSET: u32 = 0xFFFF_FFFF;
/// Prazos.
const PAGE_FILE_DEADLINE_MS: u64 = 600_000;
const PROGRAM_DEADLINE_MS: u64 = 1_200_000;
/// LOW_REALTIME_PRIORITY.
const LOW_REALTIME_PRIORITY: u64 = 16;

// O conteúdo da seção: código até CODE_LIMIT e depois os dados.
const CODE_LIMIT: usize = 0x400;
const STATUS_BASIC: usize = 0x400;
const STATUS_PERFORMANCE: usize = 0x404;
const STATUS_ALLOCATE: usize = 0x408;
const STATUS_PAGE_FILE: usize = 0x40C;
/// UNSET até o fim; 0 = tudo certo, senão a etapa que falhou.
const RESULT: usize = 0x410;
const GO: usize = 0x414;
const CHUNKS: usize = 0x418;
const BASE_CELL: usize = 0x420;
const SIZE_CELL: usize = 0x428;
const BAD_ADDRESS: usize = 0x430;
const RETURN_LENGTH: usize = 0x438;
const STATUS_PERFORMANCE_AFTER: usize = 0x43C;
const BASIC: usize = 0x440;
const PERFORMANCE: usize = 0x480;
/// O intervalo relativo da espera (-10 ms em 100 ns).
const INTERVAL: usize = 0x5D8;
const PERFORMANCE_AFTER: usize = 0x5E0;
const PAGE_FILE: usize = 0x740;
const PAGE_FILE_SIZE: usize = 0x200;
const BASES: usize = 0x940;
const MAXIMUM_CHUNKS: u64 = 160;
const CONTENT_SIZE: usize = BASES + MAXIMUM_CHUNKS as usize * 8;

// As etapas que o RESULT pode nomear.
const FAILED_BASIC: u32 = 1;
const FAILED_PERFORMANCE: u32 = 2;
const FAILED_ALLOCATE: u32 = 3;
const FAILED_VERIFY: u32 = 4;
const FAILED_PAGE_FILE: u32 = 5;

/// Os números de serviço da ntdll mapeada.
struct Services {
    allocate: u32,
    query: u32,
    terminate: u32,
    delay_execution: u32,
}

fn service(name: &str) -> Option<u32> {
    state::with(|state| state.name_by_number.iter().find(|(_, candidate)| candidate.as_str() == name).map(|(&number, _)| number))
}

fn services() -> Option<Services> {
    Some(Services { allocate: service("NtAllocateVirtualMemory")?, query: service("NtQuerySystemInformation")?, terminate: service("NtTerminateProcess")?, delay_execution: service("NtDelayExecution")? })
}

/// Montador mínimo; rbx guarda a base do conteúdo da seção.
struct Code {
    bytes: Vec<u8>,
    /// Saltos para o caminho de falha (deslocamento do rel32, etapa).
    failures: Vec<(usize, u32)>,
}

impl Code {
    fn put(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn imm32(&mut self, value: u32) {
        self.put(&value.to_le_bytes());
    }

    fn here(&self) -> usize {
        self.bytes.len()
    }

    /// Um rel32 para `target` no fim da instrução corrente.
    fn rel32(&mut self, target: usize) {
        let next = self.here() as i64 + 4;
        self.imm32((target as i64 - next) as i32 as u32);
    }

    /// `mov r10, rcx; mov eax, número; syscall`.
    fn syscall(&mut self, number: u32) {
        self.put(&[0x49, 0x89, 0xCA, 0xB8]);
        self.imm32(number);
        self.put(&[0x0F, 0x05]);
    }

    /// `mov [rbx+disp32], eax`.
    fn store_status(&mut self, offset: usize) {
        self.put(&[0x89, 0x83]);
        self.imm32(offset as u32);
    }

    /// `test eax, eax; jnz falha(etapa)`.
    fn fail_if_nonzero(&mut self, stage: u32) {
        self.put(&[0x85, 0xC0, 0x0F, 0x85]);
        self.failures.push((self.here(), stage));
        self.imm32(0);
    }

    /// `lea reg, [rbx+disp32]` (rdx = 2, r9 = 9).
    fn lea(&mut self, register: u8, offset: usize) {
        self.put(&[if register >= 8 { 0x4C } else { 0x48 }, 0x8D, 0x80 | (register & 7) << 3 | 3]);
        self.imm32(offset as u32);
    }

    /// `mov qword [rbx+disp32], imm32`.
    fn store_qword(&mut self, offset: usize, value: u32) {
        self.put(&[0x48, 0xC7, 0x83]);
        self.imm32(offset as u32);
        self.imm32(value);
    }

    /// NtQuerySystemInformation(classe, [rbx+saída], tamanho, [rbx+retorno]).
    fn query(&mut self, services: &Services, class: u32, output: usize, length: u32, returned: Option<usize>) {
        self.put(&[0xB9]);
        self.imm32(class);
        self.lea(2, output);
        self.put(&[0x41, 0xB8]);
        self.imm32(length);
        match returned {
            Some(offset) => self.lea(9, offset),
            None => self.put(&[0x45, 0x31, 0xC9]),
        }
        self.syscall(services.query);
    }

    /// NtTerminateProcess(NtCurrentProcess(), código).
    fn exit(&mut self, services: &Services, code: u32) {
        self.put(&[0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0xBA]);
        self.imm32(code);
        self.syscall(services.terminate);
    }

    /// Espera o teste ligar GO: NtDelayExecution(FALSE, 10 ms) entre as
    /// leituras, que tira a thread da CPU para a thread do teste rodar.
    fn wait_go(&mut self, services: &Services) {
        let top = self.here();
        // cmp dword [rbx+GO], 0; jne fim
        self.put(&[0x83, 0xBB]);
        self.imm32(GO as u32);
        self.put(&[0x00, 0x0F, 0x85]);
        let done = self.here();
        self.imm32(0);
        // xor ecx, ecx; lea rdx, [rbx+INTERVAL]
        self.put(&[0x31, 0xC9]);
        self.lea(2, INTERVAL);
        self.syscall(services.delay_execution);
        self.put(&[0xE9]);
        self.rel32(top);
        let end = self.here();
        self.bytes[done..done + 4].copy_from_slice(&((end as i64 - (done as i64 + 4)) as i32 as u32).to_le_bytes());
    }
}

fn absolute(offset: usize) -> u64 {
    IMAGE_BASE + SECTION_RVA + offset as u64
}

/// O programa: consultas, commit e gravação, releitura, consultas, espera
/// e saída.
fn program(services: &Services, chunks: u64) -> Vec<u8> {
    let mut code = Code { bytes: Vec::new(), failures: Vec::new() };
    // sub rsp, 0x88; mov rbx, base; mov rsi, MAGIC
    code.put(&[0x48, 0x81, 0xEC, 0x88, 0x00, 0x00, 0x00, 0x48, 0xBB]);
    code.put(&absolute(0).to_le_bytes());
    code.put(&[0x48, 0xBE]);
    code.put(&MAGIC.to_le_bytes());
    code.query(services, 0, BASIC, 0x40, None);
    code.store_status(STATUS_BASIC);
    code.fail_if_nonzero(FAILED_BASIC);
    code.query(services, 2, PERFORMANCE, 0x158, None);
    code.store_status(STATUS_PERFORMANCE);
    code.fail_if_nonzero(FAILED_PERFORMANCE);
    // xor r12d, r12d
    code.put(&[0x45, 0x31, 0xE4]);
    let allocate_loop = code.here();
    code.store_qword(BASE_CELL, 0);
    code.store_qword(SIZE_CELL, CHUNK_BYTES as u32);
    // NtAllocateVirtualMemory(-1, &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    code.put(&[0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF]);
    code.lea(2, BASE_CELL);
    code.put(&[0x45, 0x31, 0xC0]);
    code.lea(9, SIZE_CELL);
    code.put(&[0x48, 0xC7, 0x44, 0x24, 0x28, 0x00, 0x30, 0x00, 0x00]);
    code.put(&[0x48, 0xC7, 0x44, 0x24, 0x30, 0x04, 0x00, 0x00, 0x00]);
    code.syscall(services.allocate);
    code.store_status(STATUS_ALLOCATE);
    code.fail_if_nonzero(FAILED_ALLOCATE);
    // mov rdi, [rbx+BASE_CELL]; mov [rbx+r12*8+BASES], rdi
    code.put(&[0x48, 0x8B, 0xBB]);
    code.imm32(BASE_CELL as u32);
    code.put(&[0x4A, 0x89, 0xBC, 0xE3]);
    code.imm32(BASES as u32);
    // mov r13, quadwords
    code.put(&[0x49, 0xC7, 0xC5]);
    code.imm32((CHUNK_BYTES / 8) as u32);
    // fill: mov rax, rdi; xor rax, rsi; mov [rdi], rax; add rdi, 8; dec r13; jnz fill
    let fill = code.here();
    code.put(&[0x48, 0x89, 0xF8, 0x48, 0x31, 0xF0, 0x48, 0x89, 0x07, 0x48, 0x83, 0xC7, 0x08, 0x49, 0xFF, 0xCD, 0x0F, 0x85]);
    code.rel32(fill);
    // inc r12; cmp r12, [rbx+CHUNKS]; jb allocate_loop
    code.put(&[0x49, 0xFF, 0xC4, 0x4C, 0x3B, 0xA3]);
    code.imm32(CHUNKS as u32);
    code.put(&[0x0F, 0x82]);
    code.rel32(allocate_loop);
    // A releitura: xor r12d, r12d
    code.put(&[0x45, 0x31, 0xE4]);
    let verify_loop = code.here();
    // mov rdi, [rbx+r12*8+BASES]; mov r13, quadwords
    code.put(&[0x4A, 0x8B, 0xBC, 0xE3]);
    code.imm32(BASES as u32);
    code.put(&[0x49, 0xC7, 0xC5]);
    code.imm32((CHUNK_BYTES / 8) as u32);
    // check: mov rax, rdi; xor rax, rsi; cmp [rdi], rax; jne ruim
    let check = code.here();
    code.put(&[0x48, 0x89, 0xF8, 0x48, 0x31, 0xF0, 0x48, 0x39, 0x07, 0x0F, 0x85]);
    let bad = code.here();
    code.imm32(0);
    // add rdi, 8; dec r13; jnz check
    code.put(&[0x48, 0x83, 0xC7, 0x08, 0x49, 0xFF, 0xCD, 0x0F, 0x85]);
    code.rel32(check);
    // inc r12; cmp r12, [rbx+CHUNKS]; jb verify_loop
    code.put(&[0x49, 0xFF, 0xC4, 0x4C, 0x3B, 0xA3]);
    code.imm32(CHUNKS as u32);
    code.put(&[0x0F, 0x82]);
    code.rel32(verify_loop);
    code.query(services, 18, PAGE_FILE, PAGE_FILE_SIZE as u32, Some(RETURN_LENGTH));
    code.store_status(STATUS_PAGE_FILE);
    code.fail_if_nonzero(FAILED_PAGE_FILE);
    code.query(services, 2, PERFORMANCE_AFTER, 0x158, None);
    code.store_status(STATUS_PERFORMANCE_AFTER);
    // mov dword [rbx+RESULT], 0
    code.put(&[0xC7, 0x83]);
    code.imm32(RESULT as u32);
    code.imm32(0);
    code.wait_go(services);
    code.exit(services, EXIT_CODE);
    // A quadword errada: mov [rbx+BAD_ADDRESS], rdi; e a falha da etapa.
    let bad_target = code.here();
    code.bytes[bad..bad + 4].copy_from_slice(&((bad_target as i64 - (bad as i64 + 4)) as i32 as u32).to_le_bytes());
    code.put(&[0x48, 0x89, 0xBB]);
    code.imm32(BAD_ADDRESS as u32);
    code.put(&[0xB8]);
    code.imm32(FAILED_VERIFY);
    let failure_tail = code.here();
    // mov [rbx+RESULT], eax; espera GO; sai com a etapa.
    code.put(&[0x89, 0x83]);
    code.imm32(RESULT as u32);
    code.wait_go(services);
    // mov edx, [rbx+RESULT]; mov rcx, -1; syscall NtTerminateProcess
    code.put(&[0x8B, 0x93]);
    code.imm32(RESULT as u32);
    code.put(&[0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF]);
    code.syscall(services.terminate);
    // Cada falha de etapa: mov eax, etapa; jmp failure_tail.
    let failures = core::mem::take(&mut code.failures);
    for (at, stage) in failures {
        let target = code.here();
        code.bytes[at..at + 4].copy_from_slice(&((target as i64 - (at as i64 + 4)) as i32 as u32).to_le_bytes());
        code.put(&[0xB8]);
        code.imm32(stage);
        code.put(&[0xE9]);
        code.rel32(failure_tail);
    }
    assert!(code.here() <= CODE_LIMIT, "programa de pressao maior que a area de codigo");
    let mut content = code.bytes;
    content.resize(CONTENT_SIZE, 0);
    let put = |content: &mut Vec<u8>, at: usize, bytes: &[u8]| content[at..at + bytes.len()].copy_from_slice(bytes);
    for cell in [STATUS_BASIC, STATUS_PERFORMANCE, STATUS_ALLOCATE, STATUS_PAGE_FILE, RESULT, STATUS_PERFORMANCE_AFTER] {
        put(&mut content, cell, &UNSET.to_le_bytes());
    }
    put(&mut content, CHUNKS, &chunks.to_le_bytes());
    put(&mut content, INTERVAL, &(-100_000i64).to_le_bytes());
    let mut image = crate::ntos::test::phase7::single_section_image(IMAGE_BASE, 0x0022, b".text", 0xE000_0020, 0x1000, &content);
    // IMAGE_SUBSYSTEM_NATIVE: a ntdll real não carrega o kernel32.
    image[0x58 + 68..0x58 + 70].copy_from_slice(&1u16.to_le_bytes());
    image
}

/// O endereço físico de `offset` na seção do programa, pela raiz do
/// processo: a seção da imagem não é paginável, e a thread do teste não se
/// anexa ao processo.
fn physical_address(process: u64, offset: usize) -> Option<u64> {
    process_state::get(process)?;
    let root = address_space::root_of(process)?;
    let address = paging::translate_in(root, absolute(offset));
    (address != 0).then_some(address)
}

fn cell32(process: u64, offset: usize) -> Option<u32> {
    physical_address(process, offset).map(physical::read32)
}

fn bytes(process: u64, offset: usize, length: usize) -> Option<Vec<u8>> {
    let mut content = Vec::with_capacity(length);
    while content.len() < length {
        let at = offset + content.len();
        let in_page = (0x1000 - (absolute(at) & 0xFFF) as usize).min(length - content.len());
        content.extend(physical::read_bytes(physical_address(process, at)?, in_page));
    }
    Some(content)
}

/// Espera de kernel (KeDelayExecutionThread) por `milliseconds`.
fn pause(milliseconds: u64) {
    wait::delay(wait::Deadline::after(Some(milliseconds * 10_000)), 0, false);
}

fn read32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

fn raise_priority() {
    let _ = thread_priority::set_priority(process::get_current_thread(), LOW_REALTIME_PRIORITY);
}

/// A thread do teste. Roda em LOW_REALTIME_PRIORITY, como as threads de
/// sistema que vigiam a memória: as esperas dela vencem enquanto o
/// programa, de prioridade normal, ocupa a CPU com as faltas de página.
extern "win64" fn pressure_thread(_context: u64) {
    raise_priority();
    match run() {
        Ok(summary) => crate::debug_print!("MEMORY_PRESSURE_OK {}", summary),
        Err(reason) => crate::debug_print!("MEMORY_PRESSURE FALHOU: {}", reason),
    }
}

fn run() -> Result<String, String> {
    let start = clock::uptime_ms();
    while paging_file::count() == 0 {
        if clock::uptime_ms() - start > PAGE_FILE_DEADLINE_MS {
            return Err(String::from("nenhum arquivo de paginacao criado"));
        }
        pause(200);
    }
    let services = services().ok_or_else(|| String::from("numeros de servico da ntdll"))?;
    let ram = crate::ntos::mm::physical_layout::number_of_physical_pages() * 0x1000;
    let chunks = (ram + BEYOND_RAM).div_ceil(CHUNK_BYTES);
    if chunks > MAXIMUM_CHUNKS {
        return Err(alloc::format!("RAM de {} MB grande demais para o teste", ram >> 20));
    }
    let before = commit::snapshot();
    let wanted = chunks * CHUNK_BYTES / 0x1000;
    if before.committed + wanted > before.limit {
        return Err(alloc::format!("commit insuficiente: {} paginas pedidas, {} cobradas, limite {}", wanted, before.committed, before.limit));
    }
    crate::debug_print!("[pressao] RAM {} MB: {} blocos de 4 MB ({} MB), commit {} de {} paginas", ram >> 20, chunks, chunks * 4, before.committed, before.limit);
    let started = {
        let request = user_process::windows_process_request(ImageOrigin::Bytes(program(&services, chunks)), "pressao.exe", "C:\\pressao.exe", &RunOptions::default());
        let created = create::create_user_process(&request).map_err(|failure| alloc::format!("processo nao criado: {failure}"))?;
        user_process::start_created(created).map_err(|error| alloc::format!("processo nao iniciado: {error}"))?
    };
    let process = started.process_pointer;
    // A criação anexa esta thread ao processo novo (ps::process_context),
    // e a anexação de lá refaz o KAPC_STATE inteiro, Priority incluída.
    raise_priority();
    crate::debug_print!("[pressao] pressao.exe iniciado (pid {})", started.process_id);
    let deadline = clock::uptime_ms() + PROGRAM_DEADLINE_MS;
    let mut report = clock::uptime_ms() + 30_000;
    let result = loop {
        let cell = cell32(process, RESULT);
        if clock::uptime_ms() >= report {
            report += 30_000;
            crate::debug_print!("[pressao] aguardando: resultado {:x?}, {} paginas livres, {} fora do working set", cell, crate::ntos::mm::pfn::free_count(), crate::ntos::mm::working_set::nonresident_pages());
        }
        match cell {
            Some(value) if value != UNSET => break value,
            Some(_) => {}
            None => return Err(String::from("o programa saiu antes do resultado")),
        }
        if clock::uptime_ms() >= deadline {
            return Err(String::from("prazo do programa"));
        }
        pause(100);
    };
    let statuses: Vec<u32> = [STATUS_BASIC, STATUS_PERFORMANCE, STATUS_ALLOCATE, STATUS_PAGE_FILE, STATUS_PERFORMANCE_AFTER].iter().map(|&cell| cell32(process, cell).unwrap_or(UNSET)).collect();
    let page_file = bytes(process, PAGE_FILE, PAGE_FILE_SIZE).unwrap_or_default();
    let performance = bytes(process, PERFORMANCE_AFTER, 0x158).unwrap_or_default();
    let returned = cell32(process, RETURN_LENGTH).unwrap_or(0);
    let bad = bytes(process, BAD_ADDRESS, 8).map_or(0, |bytes| u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8])));
    if let Some(address) = physical_address(process, GO) {
        physical::write32(address, 1);
    }
    while process_state::get(process).is_some() && clock::uptime_ms() < deadline {
        pause(50);
    }
    // SAFETY: o EPROCESS retido por `started`.
    let exit_status = unsafe { Eprocess::at(process) }.exit_status.get() as u32;
    drop(started);
    if result != 0 {
        return Err(alloc::format!("etapa {} falhou: status {:x?}, quadword errada em {:#x}", result, statuses, bad));
    }
    if page_file.len() < 0x20 || performance.len() < 0x158 {
        return Err(String::from("resultados ilegiveis"));
    }
    // SYSTEM_PAGEFILE_INFORMATION: NextEntryOffset, TotalSize, TotalInUse,
    // PeakUsage, PageFileName (Length, MaximumLength, Buffer).
    let (next, total, in_use, peak) = (read32(&page_file, 0), read32(&page_file, 4), read32(&page_file, 8), read32(&page_file, 0xC));
    let name_length = u16::from_le_bytes([page_file[0x10], page_file[0x11]]) as usize;
    let name_units: Vec<u16> = page_file[0x20..(0x20 + name_length).min(page_file.len())].chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    let name = String::from_utf16_lossy(&name_units);
    let files = paging_file::information();
    let expected = files.first().ok_or_else(|| String::from("lista de arquivos de paginacao vazia"))?;
    let entry_ok = next == 0 && total as u64 == expected.total_size && name.eq_ignore_ascii_case(&expected.name) && returned == 0x20 + ((name_length as u32 + 2 + 7) & !7) && peak > 0 && peak >= in_use;
    if !entry_ok {
        return Err(alloc::format!("SystemPageFileInformation: proxima {next}, tamanho {total}, em uso {in_use}, pico {peak}, nome {name}, ReturnLength {returned}"));
    }
    let (committed_peak, limit, written, read, transitions) = (read32(&performance, 0x38), read32(&performance, 0x34), read32(&performance, 0x60), read32(&performance, 0x50), read32(&performance, 0x44));
    if written == 0 || read == 0 {
        return Err(alloc::format!("sem paginacao: {written} paginas gravadas, {read} lidas"));
    }
    // O pico conta o commit do programa inteiro; os outros processos podem
    // ter devolvido parte do deles nesse meio tempo.
    if (committed_peak as u64) < wanted || committed_peak as u64 * 0x1000 <= ram {
        return Err(alloc::format!("pico de commit {committed_peak} paginas nao passou da RAM ({} MB)", ram >> 20));
    }
    if exit_status != EXIT_CODE {
        return Err(alloc::format!("codigo de saida {exit_status:#x}"));
    }
    Ok(alloc::format!("comitados {} MB com {} MB de RAM; arquivo {} de {} paginas (minimo {}, maximo {}), pico {} em uso; {} paginas gravadas, {} lidas, {} de transicao; limite de commit {} paginas", chunks * 4, ram >> 20, name, total, expected.minimum, expected.maximum, peak, written, read, transitions, limit))
}

/// Inicia a thread do teste (`--memory-pressure`).
pub fn start() {
    let entry: extern "win64" fn(u64) = pressure_thread;
    let started = crate::ntos::mm::kernel_address::image_address(entry as usize as u64).and_then(|start| crate::ntos::ps::kernel_threads::create_system_thread(0, start, 0, 0x1F_FFFF, 0, None));
    match started {
        Ok(handle) => {
            let _ = crate::ntos::ob::object_manager::close(handle as u32);
        }
        Err(error) => crate::debug_print!("MEMORY_PRESSURE FALHOU: thread nao criada: {}", error),
    }
}
