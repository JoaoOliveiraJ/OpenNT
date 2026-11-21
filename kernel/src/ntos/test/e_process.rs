//! Processos e mapeamentos de arquivo compartilhados a partir do volume E:
//! do ntfs.sys real (`--storage=nvme --kernel-test-scope=e-process`):
//!
//! - o teste grava no E:, pelo cache do ntfs.sys (ZwWriteFile), uma DLL
//!   (EPROCDLL.DLL, que exporta `Valor`), dois executáveis que a importam
//!   (EPROCA.EXE e EPROCB.EXE, com imports da ntdll e da DLL) e um arquivo
//!   de dados de duas páginas (EPROC.DAT);
//! - os dois processos nascem pelo caminho único de criação
//!   (`ps::create::create_user_process`) com o caminho NT do executável no
//!   E:: o executável é aberto pelo I/O Manager e lido pela E/S de paginação
//!   (`mm/section/fsd_file`), e o loader da ntdll real acha a DLL na pasta do
//!   aplicativo e a mapeia por NtOpenFile + NtCreateSection(SEC_IMAGE) +
//!   NtMapViewOfSection, sobre o ntfs.sys;
//! - os dois rodam ao mesmo tempo: cada um abre EPROC.DAT, cria uma seção
//!   de dados (PAGE_READWRITE, SEC_COMMIT) e mapeia uma vista. O A grava um
//!   valor e liga uma marca na vista; o B espera a marca, confere o valor,
//!   grava outro e liga a resposta; o A espera a resposta, confere e faz o
//!   NtFlushVirtualMemory. Só funciona se as duas vistas usam a mesma
//!   página (a control area do stream, pelos SECTION_OBJECT_POINTERS);
//! - depois dos dois saírem, o arquivo é lido pelo cache (ZwReadFile) e sem
//!   cache (FILE_NO_INTERMEDIATE_BUFFERING, do disco): as marcas e os dois
//!   valores estão nele.
//!
//! A serial mostra `[e-process]` em cada passo e `E_PROCESS_OK` no fim.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::create::{self, CreateFailure, CreateProcessRequest, ImageOrigin};
use crate::ntos::ps::process_parameters::ProcessParameters;
use crate::ntos::ps::user::process as user_process;
use crate::ntos::test::file_system_mount::object_attributes;
use crate::ntos::test::phase6::call_export;

type Assert = fn(bool, &str);

const VOLUME: &str = "\\??\\E:";
const DLL_NAME: &str = "EPROCDLL.DLL";
const DATA_NAME: &str = "EPROC.DAT";
const EXE_BASE: u64 = 0x1_4000_0000;
const DLL_BASE: u64 = 0x1_8E00_0000;
/// O que `Valor` devolve, e o código de saída do A.
const VALUE: u32 = 0x51;
/// O código de saída do B.
const READER_EXIT: u32 = 0x52;
/// Os dois valores trocados pela vista.
const WRITER_VALUE: u64 = 0x4F50_454E_4E54_4131;
const READER_VALUE: u64 = 0x4F50_454E_4E54_4232;
const PAGE: u64 = 0x1000;
const FILE_GENERIC_READ: u64 = 0x0012_0089;
const FILE_GENERIC_WRITE: u64 = 0x0012_0116;
const FILE_SHARE_ALL: u64 = 7;
const FILE_OPEN: u64 = 1;
const FILE_OVERWRITE_IF: u64 = 5;
const FILE_SYNCHRONOUS_IO_NONALERT: u64 = 0x20;
const FILE_NON_DIRECTORY_FILE: u64 = 0x40;
const FILE_NO_INTERMEDIATE_BUFFERING: u64 = 0x08;

// O programa dos dois executáveis: o papel (1 grava primeiro, 2 responde)
// está na área de dados. A área de dados começa com as IATs (a da ntdll em
// +0x00 e a da DLL em +0x40) e segue com os handles, a vista, o intervalo
// de espera, os valores e os OBJECT_ATTRIBUTES do arquivo de dados.
core::arch::global_asm!(
    r#"
.pushsection .rodata.opennt_e_process_program, "a"
.balign 16
.global opennt_eproc_start
opennt_eproc_start:
    sub rsp, 0x68
    lea rbx, [rip + opennt_eproc_data]
    mov r12d, 20000
    call qword ptr [rbx + 0x40]
    mov edx, 0xE1
    cmp eax, 0x51
    jne opennt_eproc_exit
    lea rcx, [rbx + 0x60]
    mov edx, 0x0012019F
    lea r8, [rbx + 0xB0]
    lea r9, [rbx + 0x80]
    mov qword ptr [rsp + 0x20], 7
    mov qword ptr [rsp + 0x28], 0x60
    call qword ptr [rbx + 0x00]
    mov edx, 0xE2
    test eax, eax
    jnz opennt_eproc_exit
    lea rcx, [rbx + 0x68]
    mov edx, 0x000F001F
    xor r8d, r8d
    xor r9d, r9d
    mov qword ptr [rsp + 0x20], 4
    mov qword ptr [rsp + 0x28], 0x08000000
    mov rax, qword ptr [rbx + 0x60]
    mov qword ptr [rsp + 0x30], rax
    call qword ptr [rbx + 0x08]
    mov edx, 0xE3
    test eax, eax
    jnz opennt_eproc_exit
    mov rcx, qword ptr [rbx + 0x68]
    mov rdx, -1
    lea r8, [rbx + 0x70]
    xor r9d, r9d
    mov qword ptr [rsp + 0x20], 0
    mov qword ptr [rsp + 0x28], 0
    lea rax, [rbx + 0x78]
    mov qword ptr [rsp + 0x30], rax
    mov qword ptr [rsp + 0x38], 2
    mov qword ptr [rsp + 0x40], 0
    mov qword ptr [rsp + 0x48], 4
    call qword ptr [rbx + 0x10]
    mov edx, 0xE4
    test eax, eax
    jnz opennt_eproc_exit
    mov rsi, qword ptr [rbx + 0x70]
    cmp dword ptr [rbx + 0x98], 2
    je opennt_eproc_reader
    mov rax, qword ptr [rbx + 0xA0]
    mov qword ptr [rsi + 0x10], rax
    mov dword ptr [rsi], 1
opennt_eproc_writer_wait:
    cmp dword ptr [rsi + 8], 2
    je opennt_eproc_writer_check
    call opennt_eproc_delay
    mov edx, 0xE5
    test r12d, r12d
    jz opennt_eproc_exit
    jmp opennt_eproc_writer_wait
opennt_eproc_writer_check:
    mov rax, qword ptr [rsi + 0x18]
    mov edx, 0xE6
    cmp rax, qword ptr [rbx + 0xA8]
    jne opennt_eproc_exit
    mov rcx, -1
    lea rdx, [rbx + 0x70]
    lea r8, [rbx + 0x78]
    lea r9, [rbx + 0x80]
    call qword ptr [rbx + 0x20]
    mov edx, 0xE7
    test eax, eax
    jnz opennt_eproc_exit
    mov edx, 0x51
    jmp opennt_eproc_exit
opennt_eproc_reader:
    cmp dword ptr [rsi], 1
    je opennt_eproc_reader_check
    call opennt_eproc_delay
    mov edx, 0xE8
    test r12d, r12d
    jz opennt_eproc_exit
    jmp opennt_eproc_reader
opennt_eproc_reader_check:
    mov rax, qword ptr [rsi + 0x10]
    mov edx, 0xE9
    cmp rax, qword ptr [rbx + 0xA0]
    jne opennt_eproc_exit
    mov rax, qword ptr [rbx + 0xA8]
    mov qword ptr [rsi + 0x18], rax
    mov dword ptr [rsi + 8], 2
    mov edx, 0x52
    jmp opennt_eproc_exit
opennt_eproc_delay:
    sub rsp, 0x28
    xor ecx, ecx
    lea rdx, [rbx + 0x90]
    call qword ptr [rbx + 0x18]
    add rsp, 0x28
    dec r12d
    ret
opennt_eproc_exit:
    mov rcx, -1
    call qword ptr [rbx + 0x28]
opennt_eproc_hang:
    jmp opennt_eproc_hang
.balign 16
.global opennt_eproc_data
opennt_eproc_data:
    .space 0x200
.global opennt_eproc_end
opennt_eproc_end:
.popsection
"#
);

extern "C" {
    static opennt_eproc_start: u8;
    static opennt_eproc_data: u8;
    static opennt_eproc_end: u8;
}

/// O programa (código e a área de dados zerada) e o deslocamento dos dados.
fn program() -> (Vec<u8>, usize) {
    // SAFETY: os rótulos delimitam o bloco somente leitura acima.
    unsafe {
        let start = &opennt_eproc_start as *const u8;
        let data = &opennt_eproc_data as *const u8 as usize - start as usize;
        let length = &opennt_eproc_end as *const u8 as usize - start as usize;
        (core::slice::from_raw_parts(start, length).to_vec(), data)
    }
}

/// Os imports da ntdll na ordem da IAT do programa.
const NTDLL_IMPORTS: [&str; 6] = ["NtOpenFile", "NtCreateSection", "NtMapViewOfSection", "NtDelayExecution", "NtFlushVirtualMemory", "NtTerminateProcess"];
const SECTION_RVA: u32 = 0x1000;

pub(super) fn put16(image: &mut [u8], at: usize, value: u16) {
    image[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn put32(image: &mut [u8], at: usize, value: u32) {
    image[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn put64(image: &mut [u8], at: usize, value: u64) {
    image[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// PE x64 de uma seção (código, dados e diretórios em RVA 0x1000, gravável
/// e executável), do subsistema dado, com os diretórios dados (índice, RVA,
/// tamanho).
pub(super) fn pe_image(image_base: u64, characteristics: u16, subsystem: u16, entry: u32, content: &[u8], directories: &[(usize, u32, u32)]) -> Vec<u8> {
    let raw = content.len().div_ceil(0x200) * 0x200;
    let virtual_size = (content.len() as u32).div_ceil(0x1000) * 0x1000;
    let mut image = alloc::vec![0u8; 0x400 + raw];
    put16(&mut image, 0, 0x5A4D);
    put32(&mut image, 0x3C, 0x40);
    put32(&mut image, 0x40, 0x4550);
    put16(&mut image, 0x44, 0x8664);
    put16(&mut image, 0x46, 1);
    put16(&mut image, 0x54, 240);
    put16(&mut image, 0x56, characteristics);
    let optional = 0x58;
    put16(&mut image, optional, 0x20B);
    put32(&mut image, optional + 4, virtual_size);
    put32(&mut image, optional + 16, entry);
    put32(&mut image, optional + 20, SECTION_RVA);
    put64(&mut image, optional + 24, image_base);
    put32(&mut image, optional + 32, 0x1000);
    put32(&mut image, optional + 36, 0x200);
    put16(&mut image, optional + 40, 6);
    put16(&mut image, optional + 48, 6);
    put32(&mut image, optional + 56, SECTION_RVA + virtual_size);
    put32(&mut image, optional + 60, 0x400);
    put16(&mut image, optional + 68, subsystem);
    put64(&mut image, optional + 72, 0x10_0000);
    put64(&mut image, optional + 80, 0x1000);
    put64(&mut image, optional + 88, 0x10_0000);
    put64(&mut image, optional + 96, 0x1000);
    put32(&mut image, optional + 108, 16);
    for &(index, rva, size) in directories {
        put32(&mut image, optional + 112 + index * 8, rva);
        put32(&mut image, optional + 116 + index * 8, size);
    }
    let section = optional + 240;
    image[section..section + 5].copy_from_slice(b".text");
    put32(&mut image, section + 8, virtual_size);
    put32(&mut image, section + 12, SECTION_RVA);
    put32(&mut image, section + 16, raw as u32);
    put32(&mut image, section + 20, 0x400);
    put32(&mut image, section + 36, 0xE000_0060);
    image[0x400..0x400 + content.len()].copy_from_slice(content);
    image
}

fn wide(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// A DLL: DllMain devolve TRUE e `Valor` devolve [`VALUE`]; o diretório de
/// exports tem o nome da DLL e o export por nome.
fn dll_image() -> Vec<u8> {
    let mut content = alloc::vec![0u8; 0x200];
    // DllMain: mov eax, 1; ret. Valor: mov eax, VALUE; ret.
    content[0..6].copy_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]);
    content[0x10] = 0xB8;
    content[0x11..0x15].copy_from_slice(&VALUE.to_le_bytes());
    content[0x15] = 0xC3;
    let rva = |offset: usize| SECTION_RVA + offset as u32;
    let (directory, functions, names, ordinals, dll_name, export_name) = (0x40usize, 0x80usize, 0x88usize, 0x90usize, 0xA0usize, 0xC0usize);
    content[dll_name..dll_name + DLL_NAME.len()].copy_from_slice(DLL_NAME.as_bytes());
    content[export_name..export_name + 5].copy_from_slice(b"Valor");
    put32(&mut content, directory + 12, rva(dll_name));
    put32(&mut content, directory + 16, 1);
    put32(&mut content, directory + 20, 1);
    put32(&mut content, directory + 24, 1);
    put32(&mut content, directory + 28, rva(functions));
    put32(&mut content, directory + 32, rva(names));
    put32(&mut content, directory + 36, rva(ordinals));
    put32(&mut content, functions, rva(0x10));
    put32(&mut content, names, rva(export_name));
    put16(&mut content, ordinals, 0);
    // IMAGE_SUBSYSTEM_NATIVE: a ntdll não carrega o kernel32 (como no smss).
    pe_image(DLL_BASE, 0x2022, 1, rva(0), &content, &[(0, rva(directory), 0x40)])
}

/// Um executável com o programa no papel `role` (1 ou 2): a área de dados
/// recebe o caminho do arquivo de dados, os valores e o intervalo; os
/// imports (ntdll e a DLL) apontam as IATs para a área de dados.
fn exe_image(role: u32) -> Vec<u8> {
    let (mut content, data) = program();
    let rva = |offset: usize| SECTION_RVA + offset as u32;
    let va = |offset: usize| EXE_BASE + rva(offset) as u64;
    // Interval -1 ms, papel, valores.
    put64(&mut content, data + 0x90, (-10_000i64) as u64);
    put32(&mut content, data + 0x98, role);
    put64(&mut content, data + 0xA0, WRITER_VALUE);
    put64(&mut content, data + 0xA8, READER_VALUE);
    // OBJECT_ATTRIBUTES (+0xB0) com o UNICODE_STRING (+0xE0) do nome (+0x100).
    let name = wide(&format!("{VOLUME}\\{DATA_NAME}"));
    content[data + 0x100..data + 0x100 + name.len()].copy_from_slice(&name);
    put32(&mut content, data + 0xB0, 48);
    put64(&mut content, data + 0xC0, va(data + 0xE0));
    put32(&mut content, data + 0xC8, 0x40);
    put16(&mut content, data + 0xE0, name.len() as u16);
    put16(&mut content, data + 0xE2, name.len() as u16);
    put64(&mut content, data + 0xE8, va(data + 0x100));
    // Diretório de imports depois do programa: descritores, ILTs, nomes.
    let base = content.len().next_multiple_of(16);
    content.resize(base + 0x300, 0);
    let descriptors = base;
    let ntdll_ilt = base + 0x40;
    let dll_ilt = ntdll_ilt + 8 * (NTDLL_IMPORTS.len() + 1);
    let mut names = dll_ilt + 0x10;
    let mut name_at = |content: &mut Vec<u8>, text: &str, hint: bool| -> usize {
        let at = names;
        let start = if hint { at + 2 } else { at };
        content[start..start + text.len()].copy_from_slice(text.as_bytes());
        names = (start + text.len() + 1).next_multiple_of(2);
        at
    };
    for (index, import) in NTDLL_IMPORTS.iter().enumerate() {
        let entry = name_at(&mut content, import, true);
        put64(&mut content, ntdll_ilt + index * 8, rva(entry) as u64);
        put64(&mut content, data + index * 8, rva(entry) as u64);
    }
    let value_entry = name_at(&mut content, "Valor", true);
    put64(&mut content, dll_ilt, rva(value_entry) as u64);
    put64(&mut content, data + 0x40, rva(value_entry) as u64);
    let ntdll_name = name_at(&mut content, "ntdll.dll", false);
    let dll_name = name_at(&mut content, DLL_NAME, false);
    for (slot, (ilt, iat, name)) in [(ntdll_ilt, data, ntdll_name), (dll_ilt, data + 0x40, dll_name)].into_iter().enumerate() {
        let descriptor = descriptors + slot * 20;
        put32(&mut content, descriptor, rva(ilt));
        put32(&mut content, descriptor + 12, rva(name));
        put32(&mut content, descriptor + 16, rva(iat));
    }
    pe_image(EXE_BASE, 0x0022, 1, rva(0), &content, &[(1, rva(descriptors), 60), (12, rva(data), 0x50)])
}

/// Blocos do convidado do teste.
pub(super) struct Scratch {
    block: u64,
    buffer: u64,
    aligned: u64,
}

impl Scratch {
    pub(super) fn new(size: u64) -> Option<Self> {
        let block = guest::alloc_bytes(0x800);
        let buffer = guest::alloc_bytes(size);
        let aligned = crate::ntos::mm::independent_pages::allocate(2 * PAGE, 0).unwrap_or(0);
        (block != 0 && buffer != 0 && aligned != 0).then_some(Self { block, buffer, aligned })
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        guest::free_bytes(self.block);
        guest::free_bytes(self.buffer);
        let _ = crate::ntos::mm::independent_pages::free(self.aligned);
    }
}

fn export(name: &str, arguments: &[u64]) -> u32 {
    call_export(name, arguments).unwrap_or(u64::MAX) as u32
}

fn open(scratch: &Scratch, name: &str, access: u64, disposition: u64, options: u64) -> Result<u64, String> {
    let path = format!("{VOLUME}\\{name}");
    let attributes = object_attributes(scratch.block, &path);
    let (handle, iosb) = (scratch.block + 0x300, scratch.block + 0x310);
    let status = export("ZwCreateFile", &[handle, access, attributes, iosb, 0, 0x80, FILE_SHARE_ALL, disposition, options | FILE_NON_DIRECTORY_FILE, 0, 0]);
    if status != 0 {
        return Err(format!("ZwCreateFile({path}) devolveu {status:#x}"));
    }
    Ok(guest::read64(handle))
}

fn transfer(scratch: &Scratch, handle: u64, write: bool, buffer: u64, length: u64) -> Result<u64, String> {
    let (iosb, offset) = (scratch.block + 0x310, scratch.block + 0x320);
    guest::write64(offset, 0);
    let status = export(if write { "ZwWriteFile" } else { "ZwReadFile" }, &[handle, 0, 0, 0, iosb, buffer, length, offset, 0]);
    if status != 0 {
        return Err(format!("{} devolveu {status:#x}", if write { "ZwWriteFile" } else { "ZwReadFile" }));
    }
    Ok(guest::read64(iosb + 8))
}

/// Grava o arquivo inteiro pelo cache do ntfs.sys.
pub(super) fn write_file(scratch: &Scratch, name: &str, bytes: &[u8]) -> Result<(), String> {
    let handle = open(scratch, name, FILE_GENERIC_READ | FILE_GENERIC_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT)?;
    guest::write_bytes(scratch.buffer, bytes);
    let written = transfer(scratch, handle, true, scratch.buffer, bytes.len() as u64);
    export("ZwClose", &[handle]);
    match written? {
        count if count == bytes.len() as u64 => Ok(()),
        count => Err(format!("{name}: {count} de {} bytes gravados", bytes.len())),
    }
}

/// O arquivo de dados: pelo cache e, sem cache, do disco.
fn read_data(scratch: &Scratch, cached: bool) -> Result<Vec<u8>, String> {
    let options = FILE_SYNCHRONOUS_IO_NONALERT | if cached { 0 } else { FILE_NO_INTERMEDIATE_BUFFERING };
    let handle = open(scratch, DATA_NAME, FILE_GENERIC_READ, FILE_OPEN, options)?;
    let buffer = if cached { scratch.buffer } else { scratch.aligned };
    crate::ntos::cc::vacb::zero_bytes(buffer, 2 * PAGE);
    let read = transfer(scratch, handle, false, buffer, 2 * PAGE);
    export("ZwClose", &[handle]);
    let read = read?;
    Ok(guest::read_bytes(buffer, read.min(2 * PAGE) as usize))
}

/// As marcas e os valores que os dois processos deixaram no arquivo.
fn exchanged(bytes: &[u8]) -> bool {
    let word32 = |at: usize| bytes.get(at..at + 4).map(|slice| u32::from_le_bytes(slice.try_into().unwrap_or([0; 4])));
    let word64 = |at: usize| bytes.get(at..at + 8).map(|slice| u64::from_le_bytes(slice.try_into().unwrap_or([0; 8])));
    word32(0) == Some(1) && word32(8) == Some(2) && word64(0x10) == Some(WRITER_VALUE) && word64(0x18) == Some(READER_VALUE)
}

fn request(image: &str, image_name: &'static str) -> CreateProcessRequest<'static> {
    let mut parameters = ProcessParameters::for_image(&format!("E:\\{image}"));
    parameters.current_directory = String::from("E:\\");
    // A pasta do aplicativo primeiro, como o DllPath do BaseComputeProcessDllPath.
    parameters.dll_path = String::from("E:\\;C:\\Windows\\System32");
    CreateProcessRequest { image: ImageOrigin::NtPath(format!("{VOLUME}\\{image}")), image_name, parameters, parent: None, thread_flags: 0, inherit_handles_from: None, on_created: None, protection: 0, create_session: false, primary_token: None, image_request: Default::default() }
}

fn created(image: &str, image_name: &'static str) -> Result<create::CreatedProcess, String> {
    match create::create_user_process(&request(image, image_name)) {
        Ok(created) => Ok(created),
        Err(CreateFailure::FileOpen(status)) => Err(format!("{image}: abertura do executavel {status:#x}")),
        Err(failure) => Err(format!("{image}: {failure}")),
    }
}

pub fn run(assert: Assert) {
    let Some(scratch) = Scratch::new(0x4000) else {
        assert(false, "e-process: memoria do teste");
        return;
    };
    let (writer_exe, reader_exe, dll) = (exe_image(1), exe_image(2), dll_image());
    let installed = write_file(&scratch, DLL_NAME, &dll).and_then(|()| write_file(&scratch, "EPROCA.EXE", &writer_exe)).and_then(|()| write_file(&scratch, "EPROCB.EXE", &reader_exe)).and_then(|()| write_file(&scratch, DATA_NAME, &alloc::vec![0u8; 2 * PAGE as usize]));
    if let Err(error) = &installed {
        debug_print!("[e-process] {}", error);
    }
    assert(installed.is_ok(), "e-process: DLL, executaveis e arquivo de dados gravados no E: pelo ntfs.sys");
    debug_print!("[e-process] {} ({} bytes), EPROCA.EXE e EPROCB.EXE ({} bytes) e {} gravados no E:", DLL_NAME, dll.len(), writer_exe.len(), DATA_NAME);

    // O loader real da ntdll (a cópia de Windows\System32 do volume do
    // kernel, que o boot deste escopo registra na tabela nativa), que acha a
    // DLL no E: e a mapeia.
    let real_ntdll = crate::ntos::ps::user::loader::ensure_ntdll();
    let has_loader = crate::ntos::ps::user::state::with(|state| state.ntdll_exports.as_ref().is_some_and(|exports| exports.contains_key("LdrLoadDll") && exports.contains_key("LdrInitializeThunk")));
    if !has_loader {
        debug_print!("[e-process] ntdll real: {:?}", real_ntdll.as_ref().map_err(|error| alloc::format!("{error}")));
    }
    assert(has_loader, "e-process: a ntdll real mapeada, com o loader");
    let writer = created("EPROCA.EXE", "eproca.exe");
    let reader = created("EPROCB.EXE", "eprocb.exe");
    for outcome in [&writer, &reader] {
        if let Err(error) = outcome {
            debug_print!("[e-process] {}", error);
        }
    }
    assert(writer.is_ok() && reader.is_ok(), "e-process: os dois processos criados com o executavel do E:");
    let (Ok(writer), Ok(reader)) = (writer, reader) else { return };
    debug_print!("[e-process] processos {:#x} e {:#x} criados com a imagem do E: (base {:#x})", writer.process_id, reader.process_id, writer.image_base);
    let started = (user_process::start_created(writer), user_process::start_created(reader));
    let (writer_exit, reader_exit) = match started {
        (Ok(writer), Ok(reader)) => (user_process::wait_started(writer), user_process::wait_started(reader)),
        (writer, reader) => {
            let describe = |result: &Result<user_process::StartedProcess, crate::rtl::KernelError>| result.as_ref().err().map(|error| alloc::format!("{error}"));
            debug_print!("[e-process] partida: {:?} {:?}", describe(&writer), describe(&reader));
            assert(false, "e-process: os dois processos postos para rodar");
            return;
        }
    };
    debug_print!("[e-process] saidas: A {:?}, B {:?}", writer_exit.as_ref().map_err(|error| alloc::format!("{error}")), reader_exit.as_ref().map_err(|error| alloc::format!("{error}")));
    assert(matches!(reader_exit, Ok(READER_EXIT)), "e-process: o B chamou a DLL do E:, viu na vista o valor que o A gravou e respondeu");
    assert(matches!(writer_exit, Ok(VALUE)), "e-process: o A chamou a DLL do E:, viu na vista a resposta do B e fez o NtFlushVirtualMemory");

    let cached = read_data(&scratch, true);
    let disk = read_data(&scratch, false);
    debug_print!("[e-process] {}: pelo cache {}, do disco {}", DATA_NAME, cached.as_ref().map_or_else(|error| error.clone(), |bytes| String::from(if exchanged(bytes) { "com as marcas" } else { "SEM as marcas" })), disk.as_ref().map_or_else(|error| error.clone(), |bytes| String::from(if exchanged(bytes) { "com as marcas" } else { "SEM as marcas" })));
    assert(cached.as_ref().is_ok_and(|bytes| exchanged(bytes)), "e-process: o ZwReadFile pelo cache le o que as vistas gravaram");
    assert(disk.as_ref().is_ok_and(|bytes| exchanged(bytes)), "e-process: a leitura sem cache acha no disco o que as vistas gravaram");
}
