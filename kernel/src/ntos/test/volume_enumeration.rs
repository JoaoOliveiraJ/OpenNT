//! A enumeração de volumes do modo usuário vê o volume E: da pilha PnP real
//! do disco NVMe (`--storage=nvme --kernel-test-scope=e-process`, depois do
//! E_PROCESS_OK): um programa Win32 (subsistema GUI, com o kernel32 e o
//! cfgmgr32 reais do System32) gravado no E: pelo cache do ntfs.sys roda
//! pelo caminho único de criação, numa sessão nova, e confere, pelas APIs
//! que o Explorer e o ShellHWDetection usam:
//!
//! - FindFirstVolumeW/FindNextVolumeW (o IOCTL_MOUNTMGR_QUERY_POINTS do
//!   mountmgr.sys) acham um volume `\\?\Volume{...}\` cujo
//!   GetVolumePathNamesForVolumeNameW (o IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATHS)
//!   começa por `E:` (bit 0);
//! - GetLogicalDrives (o mapa de devices DOS do processo,
//!   ProcessDeviceMap) tem o bit do E: (bit 1);
//! - CM_Get_Device_Interface_List_SizeW e CM_Get_Device_Interface_ListW de
//!   GUID_DEVINTERFACE_VOLUME (o `\Device\DeviceApi\CMApi` do PnP manager)
//!   devolvem a interface `\\?\STORAGE#Volume#...` que o volmgr.sys
//!   registrou no devnode STORAGE\Volume (bit 2).
//!
//! O código de saída é 0x100 com os bits; o teste espera 0x107. A serial
//! mostra `[e-volume]` e `E_VOLUMES_OK`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::e_process;
use crate::ntos::ps::create::{self, CreateProcessRequest, ImageOrigin};
use crate::ntos::ps::process_parameters::ProcessParameters;
use crate::ntos::ps::user::process as user_process;

const IMAGE_NAME: &str = "EVOLUME.EXE";
const IMAGE_BASE: u64 = 0x1_4000_0000;
const SECTION_RVA: u32 = 0x1000;
/// O código de saída com as três conferências certas.
const EXPECTED_EXIT: u32 = 0x107;
/// IMAGE_SUBSYSTEM_WINDOWS_GUI: o kernel32 não abre console.
const SUBSYSTEM_WINDOWS_GUI: u16 = 2;
/// GUID_DEVINTERFACE_VOLUME {53F5630D-B6BF-11D0-94F2-00A0C91EFB8B}.
const GUID_DEVINTERFACE_VOLUME: [u8; 16] = [0x0D, 0x63, 0xF5, 0x53, 0xBF, 0xB6, 0xD0, 0x11, 0x94, 0xF2, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x8B];
/// As DLLs e as rotinas importadas, na ordem das IATs da área de dados (a
/// do kernel32 em +0x00, a do cfgmgr32 em +0x40).
const IMPORTS: [(&str, usize, &[&str]); 2] = [
    ("kernel32.dll", 0x00, &["FindFirstVolumeW", "FindNextVolumeW", "FindVolumeClose", "GetVolumePathNamesForVolumeNameW", "GetLogicalDrives", "ExitProcess"]),
    ("cfgmgr32.dll", 0x40, &["CM_Get_Device_Interface_List_SizeW", "CM_Get_Device_Interface_ListW"]),
];
/// O GUID na área de dados.
const GUID_OFFSET: usize = 0x80;

// O programa. A área de dados: as IATs, o handle da busca (+0x60), o
// tamanho devolvido (+0x68), o tamanho da lista (+0x70), o GUID (+0x80), o
// nome do volume (+0x100), os caminhos (+0x310) e a lista de interfaces
// (+0x520, 0x400 caracteres).
core::arch::global_asm!(
    r#"
.pushsection .rodata.opennt_volume_enumeration_program, "a"
.balign 16
.global opennt_volenum_start
opennt_volenum_start:
    sub rsp, 0x68
    lea rbx, [rip + opennt_volenum_data]
    xor r12d, r12d
    lea rcx, [rbx + 0x100]
    mov edx, 260
    call qword ptr [rbx + 0x00]
    cmp rax, -1
    je opennt_volenum_drives
    mov qword ptr [rbx + 0x60], rax
opennt_volenum_volume:
    lea rcx, [rbx + 0x100]
    lea rdx, [rbx + 0x310]
    mov r8d, 260
    lea r9, [rbx + 0x68]
    call qword ptr [rbx + 0x18]
    test eax, eax
    jz opennt_volenum_next
    cmp dword ptr [rbx + 0x310], 0x003A0045
    jne opennt_volenum_next
    or r12d, 1
opennt_volenum_next:
    mov rcx, qword ptr [rbx + 0x60]
    lea rdx, [rbx + 0x100]
    mov r8d, 260
    call qword ptr [rbx + 0x08]
    test eax, eax
    jnz opennt_volenum_volume
    mov rcx, qword ptr [rbx + 0x60]
    call qword ptr [rbx + 0x10]
opennt_volenum_drives:
    call qword ptr [rbx + 0x20]
    test eax, 0x10
    jz opennt_volenum_interfaces
    or r12d, 2
opennt_volenum_interfaces:
    lea rcx, [rbx + 0x70]
    lea rdx, [rbx + 0x80]
    xor r8d, r8d
    xor r9d, r9d
    call qword ptr [rbx + 0x40]
    test eax, eax
    jnz opennt_volenum_exit
    cmp dword ptr [rbx + 0x70], 0x400
    ja opennt_volenum_exit
    lea rcx, [rbx + 0x80]
    xor edx, edx
    lea r8, [rbx + 0x520]
    mov r9d, 0x400
    mov qword ptr [rsp + 0x20], 0
    call qword ptr [rbx + 0x48]
    test eax, eax
    jnz opennt_volenum_exit
    mov rax, qword ptr [rbx + 0x528]
    movabs rcx, 0x0052004F00540053
    cmp rax, rcx
    jne opennt_volenum_exit
    or r12d, 4
opennt_volenum_exit:
    mov ecx, r12d
    or ecx, 0x100
    call qword ptr [rbx + 0x28]
opennt_volenum_hang:
    jmp opennt_volenum_hang
.balign 16
.global opennt_volenum_data
opennt_volenum_data:
    .space 0xD20
.global opennt_volenum_end
opennt_volenum_end:
.popsection
"#
);

extern "C" {
    static opennt_volenum_start: u8;
    static opennt_volenum_data: u8;
    static opennt_volenum_end: u8;
}

/// O programa (código e a área de dados zerada) e o deslocamento dos dados.
fn program() -> (Vec<u8>, usize) {
    // SAFETY: os rótulos delimitam o bloco somente leitura acima.
    unsafe {
        let start = &opennt_volenum_start as *const u8;
        let data = &opennt_volenum_data as *const u8 as usize - start as usize;
        let length = &opennt_volenum_end as *const u8 as usize - start as usize;
        (core::slice::from_raw_parts(start, length).to_vec(), data)
    }
}

/// O executável: o programa, o GUID na área de dados e o diretório de
/// imports depois dele (descritores, ILTs e nomes), com as IATs na área de
/// dados.
fn image() -> Vec<u8> {
    let (mut content, data) = program();
    let rva = |offset: usize| SECTION_RVA + offset as u32;
    content[data + GUID_OFFSET..data + GUID_OFFSET + 16].copy_from_slice(&GUID_DEVINTERFACE_VOLUME);
    let base = content.len().next_multiple_of(16);
    content.resize(base + 0x400, 0);
    let descriptors = base;
    let mut ilt = base + 0x40;
    let mut names = ilt + IMPORTS.iter().map(|(_, _, functions)| (functions.len() + 1) * 8).sum::<usize>();
    let mut name_at = |content: &mut Vec<u8>, text: &str, hint: bool| -> usize {
        let at = names;
        let start = if hint { at + 2 } else { at };
        content[start..start + text.len()].copy_from_slice(text.as_bytes());
        names = (start + text.len() + 1).next_multiple_of(2);
        at
    };
    for (slot, (library, iat, functions)) in IMPORTS.iter().enumerate() {
        let first_thunk = ilt;
        for (index, function) in functions.iter().enumerate() {
            let entry = name_at(&mut content, function, true);
            e_process::put64(&mut content, ilt + index * 8, rva(entry) as u64);
            e_process::put64(&mut content, data + iat + index * 8, rva(entry) as u64);
        }
        ilt += (functions.len() + 1) * 8;
        let library_name = name_at(&mut content, library, false);
        let descriptor = descriptors + slot * 20;
        e_process::put32(&mut content, descriptor, rva(first_thunk));
        e_process::put32(&mut content, descriptor + 12, rva(library_name));
        e_process::put32(&mut content, descriptor + 16, rva(data + iat));
    }
    e_process::pe_image(IMAGE_BASE, 0x0022, SUBSYSTEM_WINDOWS_GUI, rva(0), &content, &[(1, rva(descriptors), (IMPORTS.len() as u32 + 1) * 20), (12, rva(data), 0x58)])
}

fn describe(exit: u32) -> String {
    format!(
        "volume com E: pelo mountmgr {}, GetLogicalDrives com E: {}, interface STORAGE#Volume {}",
        if exit & 1 != 0 { "sim" } else { "NAO" },
        if exit & 2 != 0 { "sim" } else { "NAO" },
        if exit & 4 != 0 { "sim" } else { "NAO" }
    )
}

/// O que o boot da cadeia deixa para o loader da ntdll e que este boot sem
/// smss não tem: o `\GLOBAL??\C:` do volume do sistema, para onde leva o
/// `\KnownDlls\KnownDllPath` (C:\Windows\System32), a pasta do sistema em
/// que o loader procura o kernel32, o kernelbase e o cfgmgr32 de um
/// programa que mora em outra pasta.
fn prepare_loader() -> Result<(), String> {
    use crate::ntos::ob::object_manager;
    if object_manager::lookup("\\GLOBAL??\\C:").is_none() {
        object_manager::create_symlink("\\GLOBAL??\\C:", "\\Device\\KernelVolume1").map_err(|error| format!("\\GLOBAL??\\C: {error}"))?;
    }
    Ok(())
}

pub fn run(assert: fn(bool, &str)) {
    let Some(scratch) = e_process::Scratch::new(0x4000) else {
        assert(false, "e-volume: memoria do teste");
        return;
    };
    let executable = image();
    let installed = e_process::write_file(&scratch, IMAGE_NAME, &executable).and_then(|()| prepare_loader());
    if let Err(error) = &installed {
        debug_print!("[e-volume] {}", error);
    }
    assert(installed.is_ok(), "e-volume: o programa Win32 gravado no E: pelo ntfs.sys");
    let mut parameters = ProcessParameters::for_image(&format!("E:\\{IMAGE_NAME}"));
    parameters.current_directory = String::from("E:\\");
    // Numa sessão nova, a 0 neste boot sem smss, como o smss de sessão do
    // boot real.
    let request = CreateProcessRequest {
        image: ImageOrigin::NtPath(format!("\\??\\E:\\{IMAGE_NAME}")),
        image_name: "evolume.exe",
        parameters,
        parent: None,
        thread_flags: 0,
        inherit_handles_from: None,
        on_created: None,
        protection: 0,
        create_session: true,
        primary_token: None,
        image_request: Default::default(),
    };
    let process = match create::create_user_process(&request) {
        Ok(process) => process,
        Err(failure) => {
            debug_print!("[e-volume] {}: {}", IMAGE_NAME, failure);
            assert(false, "e-volume: o processo Win32 criado");
            return;
        }
    };
    let exit = user_process::start_created(process).and_then(user_process::wait_started);
    match &exit {
        Ok(code) if code & !7 == 0x100 => debug_print!("[e-volume] evolume.exe saiu com {:#x}: {}", code, describe(*code)),
        Ok(code) => debug_print!("[e-volume] evolume.exe saiu com {:#x} antes das conferencias", code),
        Err(error) => debug_print!("[e-volume] evolume.exe: {}", error),
    }
    assert(matches!(exit, Ok(EXPECTED_EXIT)), "e-volume: FindFirstVolumeW, GetLogicalDrives e CM_Get_Device_Interface_ListW veem o volume E: da pilha PnP");
}
