//! Os diretórios raiz do I/O Manager (o IopCreateRootDirectories do
//! IoInitSystem): `\Driver`, `\FileSystem`, `\FileSystem\Filters` e o
//! `\UMDFCommunicationPorts` do IopCreateUmdfDirectory.
//!
//! O `\UMDFCommunicationPorts` guarda as portas ALPC do UMDF (a
//! `ProcessManagement` e a `WUDF` do WUDFPlatform.dll e do WUDFRd.sys). O
//! kernel o cria permanente, por um NtCreateDirectoryObject de modo kernel
//! (OBJ_PERMANENT | OBJ_KERNEL_HANDLE), com uma DACL de duas ACEs
//! GENERIC_ALL: o SYSTEM (o SeLocalSystemSid do SeExports) e o SID do
//! serviço WudfSvc (S-1-5-80-2652678385-582572993-1835434367-1344795993-
//! 749280709). O gerenciador de drivers de modo usuário do services.exe
//! (o InitWudfDriverManager) cria o diretório dele lá dentro e sai sem o
//! pai.

use alloc::vec;

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::ObjectAttributes;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::handles::namespace as namespace_handles;
use crate::ntos::ob::object_manager;
use crate::ntos::rtl::guest_strings;
use crate::ntos::se::model::{sid, Ace, SecurityPolicy};
use crate::rtl::KernelError;

pub const UMDF_DIRECTORY: &str = "\\UMDFCommunicationPorts";

const GENERIC_ALL: u32 = 0x1000_0000;
const DIRECTORY_ALL_ACCESS: u32 = 0xF000F;
const OBJ_PERMANENT: u32 = 0x10;
const OBJ_KERNEL_HANDLE: u32 = 0x200;
const DACL_SECURITY_INFORMATION: u32 = 4;

/// O SID do serviço WudfSvc (NT SERVICE\WudfSvc), o segundo da DACL.
pub fn wudf_service_sid() -> crate::ntos::se::model::Sid {
    sid(5, &[80, 2_652_678_385, 582_572_993, 1_835_434_367, 1_344_795_993, 749_280_709])
}

/// IopCreateRootDirectories.
pub fn create() -> Result<(), KernelError> {
    object_manager::create_directory("\\Driver")?;
    object_manager::create_directory("\\FileSystem")?;
    object_manager::create_directory("\\FileSystem\\Filters")?;
    let status = create_umdf_directory();
    if status != 0 {
        crate::debug_print!("[iom] {} nao criado: {:#x}", UMDF_DIRECTORY, status);
    }
    Ok(())
}

/// IopCreateUmdfDirectory: o descritor só com a DACL, o
/// NtCreateDirectoryObject de modo kernel e o fechamento do handle. O
/// SeAssignSecurity do ObInsertObject completa dono e grupo pelo token do
/// System e mapeia o GENERIC_ALL das ACEs pelo tipo Directory.
fn create_umdf_directory() -> u32 {
    if object_manager::lookup(UMDF_DIRECTORY).is_some() {
        return 0;
    }
    let policy = SecurityPolicy { dacl: Some(vec![Ace::allow(sid(5, &[18]), GENERIC_ALL), Ace::allow(wudf_service_sid(), GENERIC_ALL)]), ..SecurityPolicy::default() };
    let descriptor = crate::ntos::se::object_security::encode(&policy, DACL_SECURITY_INFORMATION);
    let units = UMDF_DIRECTORY.encode_utf16().count() as u64;
    let name_size = 16 + units * 2 + 2;
    let size = ObjectAttributes::SIZE + 8 + name_size + descriptor.len() as u64;
    let block = guest::alloc_bytes(size);
    if block == 0 {
        return 0xC000_009A;
    }
    guest::write_bytes(block, &vec![0u8; size as usize]);
    let attributes_address = block;
    let handle_cell = block + ObjectAttributes::SIZE;
    let name = handle_cell + 8;
    let descriptor_address = name + name_size;
    guest_strings::write_wide_string(name + 16, UMDF_DIRECTORY);
    guest_strings::write_string_fields(name, (units * 2) as u16, (units * 2 + 2) as u16, name + 16);
    guest::write_bytes(descriptor_address, &descriptor);
    // SAFETY: bloco de kernel zerado com o tamanho do OBJECT_ATTRIBUTES.
    let attributes = unsafe { ObjectAttributes::at(attributes_address) };
    attributes.length.set(ObjectAttributes::SIZE as u32);
    attributes.object_name.set(name);
    attributes.attributes.set(OBJ_PERMANENT | OBJ_KERNEL_HANDLE);
    attributes.security_descriptor.set(descriptor_address);
    let status = namespace_handles::open(handle_cell, DIRECTORY_ALL_ACCESS, attributes_address, "Directory", false, true);
    if status == 0 {
        let handle = guest::read64(handle_cell);
        let _ = crate::ntos::ob::close::close(handle, Some(0));
    }
    guest::free_bytes(block);
    status
}
