//! O console do Windows (condrv.sys real) depois do `--start-driver=condrv`.
//!
//! O teste faz pelo ZwCreateFile e pelo ZwDeviceIoControlFile o que o
//! conhost e a kernelbase fazem para abrir um console, com as estruturas
//! que o condrv.sys lê (conferidas no binário):
//!
//! - o servidor abre `\Device\ConDrv\Server` (sem EA; o condrv cria o objeto
//!   servidor e, como a abertura é de modo kernel, o dono é o System);
//! - a referência abre `\Reference` relativo ao handle do servidor (o
//!   FILE_OBJECT relacionado tem de ser um servidor do condrv);
//! - o cliente abre `\Connect` relativo à referência: o condrv põe uma
//!   mensagem CONSOLE_IO_CONNECT (Function 1) na fila do servidor e deixa o
//!   IRP_MJ_CREATE pendente até a resposta;
//! - o servidor, numa thread de sistema, lê a mensagem pelo
//!   IOCTL_CONDRV_READ_IO (0x500006, METHOD_OUT_DIRECT, assíncrono com
//!   evento): o CD_IO_DESCRIPTOR de 0x28 bytes com Identifier, Process,
//!   Object, Function, InputSize e OutputSize;
//! - o servidor conclui pelo IOCTL_CONDRV_COMPLETE_IO (0x50000B,
//!   METHOD_NEITHER, pelo FastIoDeviceControl do condrv): o CD_IO_COMPLETE
//!   (Identifier, IO_STATUS_BLOCK e o buffer de escrita em +0x18/+0x20) com o
//!   CD_CONNECTION_INFORMATION (Process, Input, Output) de 0x18 bytes; o
//!   IRP_MJ_CREATE do cliente conclui com sucesso;
//! - o fechamento do cliente chega ao servidor como CONSOLE_IO_DISCONNECT
//!   (Function 2), lido por outro IOCTL_CONDRV_READ_IO.
//!
//! A serial mostra `CONDRV_OK` no fim, ou `CONDRV_FALHOU` com o passo.
//!
//! Depois, com todos os handles fechados, o SystemConsoleInformation (132)
//! do ZwSetSystemInformation, que o kernelbase chama quando o servidor ainda
//! não existe: Length 3 dá STATUS_INFO_LENGTH_MISMATCH e o bit DriverLoaded
//! com o condrv já carregado dá STATUS_IMAGE_ALREADY_LOADED (o ZwLoadDriver
//! da chave do serviço). A serial mostra `CONSOLE_INFORMATION_OK`, ou
//! `CONSOLE_INFORMATION_FALHOU` com o status.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::inc::{types as nt, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::test::phase6::call_export;

const IOCTL_CONDRV_READ_IO: u64 = 0x50_0006;
const IOCTL_CONDRV_COMPLETE_IO: u64 = 0x50_000B;
const CONSOLE_IO_CONNECT: u64 = 1;
const CONSOLE_IO_DISCONNECT: u64 = 2;
const GENERIC_ALL: u64 = 0x1000_0000;
const GENERIC_READ_WRITE_SYNCHRONIZE: u64 = 0x8000_0000 | 0x4000_0000 | 0x0010_0000;
const FILE_SHARE_READ_WRITE: u64 = 3;
const FILE_CREATE: u64 = 2;
const FILE_OPEN: u64 = 1;
const FILE_SYNCHRONOUS_IO_NONALERT: u64 = 0x20;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const OBJ_KERNEL_HANDLE: u32 = 0x200;
const STATUS_PENDING: u64 = 0x103;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_IMAGE_ALREADY_LOADED: u32 = 0xC000_010E;
/// SystemConsoleInformation.
const SYSTEM_CONSOLE_INFORMATION: u64 = 132;
/// Prazo das esperas do teste: 10 s relativos.
const TIMEOUT_100NS: i64 = -100_000_000;

/// O servidor: o status, a Function e o Identifier da primeira leitura, o
/// status do COMPLETE_IO, o status e a Function da segunda leitura, e o fim.
static SERVER: [AtomicU64; 7] = [const { AtomicU64::new(u64::MAX) }; 7];

fn at<T: NtStruct>(address: u64) -> &'static T {
    // SAFETY: blocos do convidado alocados por este teste.
    unsafe { T::at(address) }
}

/// OBJECT_ATTRIBUTES com o nome (UNICODE_STRING em +0x40, texto em +0x80) e
/// o RootDirectory, no bloco dado.
fn object_attributes(block: u64, name: &str, root: u64) -> u64 {
    let units: Vec<u16> = name.encode_utf16().collect();
    let text = block + 0x80;
    guest::write_bytes(text, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    let unicode = at::<nt::UnicodeString>(block + 0x40);
    unicode.length.set(units.len() as u16 * 2);
    unicode.maximum_length.set(units.len() as u16 * 2);
    unicode.buffer.set(text);
    let attributes = at::<nt::ObjectAttributes>(block);
    attributes.length.set(48);
    attributes.root_directory.set(root);
    attributes.object_name.set(if units.is_empty() { 0 } else { unicode.address() });
    attributes.attributes.set(OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE);
    block
}

/// ZwCreateFile; devolve (status, handle).
fn create(block: u64, name: &str, root: u64, access: u64, disposition: u64, options: u64) -> (u64, u64) {
    let attributes = object_attributes(block, name, root);
    let (handle, iosb) = (block + 0x180, block + 0x190);
    guest::write64(handle, 0);
    let status = call_export("ZwCreateFile", &[handle, access, attributes, iosb, 0, 0, FILE_SHARE_READ_WRITE, disposition, options, 0, 0]).unwrap_or(1);
    (status, guest::read64(handle))
}

/// IOCTL_CONDRV_READ_IO assíncrono no servidor, esperado pelo evento:
/// (status, CD_IO_DESCRIPTOR.Function, Identifier, Information).
fn read_io(server: u64, event: u64, block: u64) -> (u64, u64, u64, u64) {
    let (iosb, timeout, output) = (block, block + 0x30, block + 0x40);
    guest::write_bytes(output, &[0u8; 0x100]);
    let mut status = call_export("ZwDeviceIoControlFile", &[server, event, 0, 0, iosb, IOCTL_CONDRV_READ_IO, 0, 0, output, 0x100]).unwrap_or(1);
    if status == STATUS_PENDING {
        guest::write64(timeout, TIMEOUT_100NS as u64);
        let waited = call_export("ZwWaitForSingleObject", &[event, 0, timeout]).unwrap_or(1);
        status = if waited == 0 { guest::read32(iosb) as u64 } else { waited };
    }
    (status, guest::read32(output + 0x18) as u64, guest::read64(output), guest::read64(iosb + 8))
}

/// O servidor numa thread de sistema: lê a conexão, conclui com o
/// CD_CONNECTION_INFORMATION e lê a desconexão.
extern "win64" fn console_server(block: u64) {
    let (server, event) = (guest::read64(block + 0x1F0), guest::read64(block + 0x1F8));
    let (status, function, identifier, information) = read_io(server, event, block);
    debug_print!("[condrv] servidor: READ_IO status={:#x} function={} identifier={:#x} information={:#x}", status, function, identifier, information);
    SERVER[0].store(status, Ordering::SeqCst);
    SERVER[1].store(function, Ordering::SeqCst);
    SERVER[2].store(identifier, Ordering::SeqCst);
    if status == 0 && function == CONSOLE_IO_CONNECT {
        let (complete, connection_information) = (block + 0x150, block + 0x180);
        guest::write_bytes(complete, &[0u8; 0x28]);
        guest::write64(complete, identifier);
        guest::write64(complete + 0x10, 0x18);
        guest::write64(complete + 0x18, connection_information);
        guest::write32(complete + 0x20, 0x18);
        for (index, value) in [0x1111u64, 0x2222, 0x3333].iter().enumerate() {
            guest::write64(connection_information + index as u64 * 8, *value);
        }
        let completed = call_export("ZwDeviceIoControlFile", &[server, 0, 0, 0, block + 0x1C0, IOCTL_CONDRV_COMPLETE_IO, complete, 0x28, 0, 0]).unwrap_or(1);
        debug_print!("[condrv] servidor: COMPLETE_IO status={:#x}", completed);
        SERVER[3].store(completed, Ordering::SeqCst);
        if completed == 0 {
            let (status, function, identifier, _) = read_io(server, event, block);
            debug_print!("[condrv] servidor: READ_IO status={:#x} function={} identifier={:#x}", status, function, identifier);
            SERVER[4].store(status, Ordering::SeqCst);
            SERVER[5].store(function, Ordering::SeqCst);
            // Como o conhost, toda mensagem lida é concluída.
            if status == 0 {
                guest::write_bytes(complete, &[0u8; 0x28]);
                guest::write64(complete, identifier);
                let acknowledged = call_export("ZwDeviceIoControlFile", &[server, 0, 0, 0, block + 0x1C0, IOCTL_CONDRV_COMPLETE_IO, complete, 0x28, 0, 0]).unwrap_or(1);
                debug_print!("[condrv] servidor: COMPLETE_IO da desconexao status={:#x}", acknowledged);
            }
        }
    }
    SERVER[6].store(1, Ordering::SeqCst);
}

/// Depois do início de um driver pelo `--start-driver`.
pub fn after_driver_start(name: &str) {
    if !name.eq_ignore_ascii_case("condrv") {
        return;
    }
    match exercise() {
        Ok(()) => debug_print!("CONDRV_OK"),
        Err(message) => {
            debug_print!("CONDRV_FALHOU: {}", message);
            return;
        }
    }
    match console_information() {
        Ok(()) => debug_print!("CONSOLE_INFORMATION_OK"),
        Err(message) => debug_print!("CONSOLE_INFORMATION_FALHOU: {}", message),
    }
}

/// ZwSetSystemInformation(SystemConsoleInformation) com o condrv carregado
/// pelo `--start-driver`: Length 3 e depois o bit DriverLoaded com Length 4.
fn console_information() -> Result<(), String> {
    use alloc::format;
    let information = guest::alloc_bytes(8);
    guest::write64(information, 1);
    // O NTSTATUS volta estendido com sinal (`signed_status`).
    let short = call_export("ZwSetSystemInformation", &[SYSTEM_CONSOLE_INFORMATION, information, 3]).unwrap_or(1) as u32;
    let load = call_export("ZwSetSystemInformation", &[SYSTEM_CONSOLE_INFORMATION, information, 4]).unwrap_or(1) as u32;
    guest::free_bytes(information);
    debug_print!("[condrv] SystemConsoleInformation: Length 3 -> {:#x}, carga com o condrv carregado -> {:#x}", short, load);
    if short != STATUS_INFO_LENGTH_MISMATCH {
        return Err(format!("Length 3: {short:#x} (esperado {STATUS_INFO_LENGTH_MISMATCH:#x})"));
    }
    if load != STATUS_IMAGE_ALREADY_LOADED {
        return Err(format!("carga com o condrv carregado: {load:#x} (esperado {STATUS_IMAGE_ALREADY_LOADED:#x})"));
    }
    Ok(())
}

fn exercise() -> Result<(), String> {
    use alloc::format;
    for slot in &SERVER {
        slot.store(u64::MAX, Ordering::SeqCst);
    }
    let block = guest::alloc_bytes(0x400);
    let server_block = guest::alloc_bytes(0x400);
    guest::write_bytes(block, &[0; 0x400]);
    guest::write_bytes(server_block, &[0; 0x400]);
    // O servidor (o conhost abre com GENERIC_ALL e FILE_CREATE) e a referência.
    let (status, server) = create(block, "\\Device\\ConDrv\\Server", 0, GENERIC_ALL, FILE_CREATE, 0);
    debug_print!("[condrv] Server: status={:#x} handle={:#x}", status, server);
    if status != 0 {
        return Err(format!("abrir \\Device\\ConDrv\\Server: {status:#x}"));
    }
    let (status, reference) = create(block, "\\Reference", server, GENERIC_READ_WRITE_SYNCHRONIZE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT);
    debug_print!("[condrv] Reference: status={:#x} handle={:#x}", status, reference);
    if status != 0 {
        return Err(format!("abrir \\Reference relativo ao servidor: {status:#x}"));
    }
    // O evento do IOCTL assíncrono e a thread do servidor.
    let event_attributes = object_attributes(block + 0x200, "", 0);
    let event_out = block + 0x1F0;
    if call_export("ZwCreateEvent", &[event_out, 0x1F_0003, event_attributes, 0, 0]) != Some(0) {
        return Err(String::from("ZwCreateEvent"));
    }
    let event = guest::read64(event_out);
    guest::write64(server_block + 0x1F0, server);
    guest::write64(server_block + 0x1F8, event);
    let thread = crate::ntos::ps::kernel_threads::create_system_thread(0, console_server as extern "win64" fn(u64) as usize as u64, server_block, 0x1F_FFFF, 0, None).map_err(|_| String::from("thread do servidor"))?;
    // O cliente: o IRP_MJ_CREATE fica pendente até o servidor concluir a conexão.
    let (status, connection) = create(block, "\\Connect", reference, GENERIC_READ_WRITE_SYNCHRONIZE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT);
    debug_print!("[condrv] Connect: status={:#x} handle={:#x}", status, connection);
    if status != 0 {
        return Err(format!("abrir \\Connect relativo a referencia: {status:#x}"));
    }
    // O fechamento chega ao servidor como desconexão; espera a thread dele.
    let _ = call_export("ZwClose", &[connection]);
    guest::write64(block + 0x1E0, TIMEOUT_100NS as u64);
    let waited = call_export("ZwWaitForSingleObject", &[thread, 0, block + 0x1E0]).unwrap_or(1);
    let results: Vec<u64> = SERVER.iter().map(|slot| slot.load(Ordering::SeqCst)).collect();
    debug_print!("[condrv] servidor terminou: espera={:#x} resultados={:x?}", waited, results);
    for handle in [event, reference, server] {
        let _ = call_export("ZwClose", &[handle]);
    }
    let _ = crate::ntos::ob::object_manager::close(thread as u32);
    guest::free_bytes(block);
    if results[6] != 1 {
        return Err(String::from("a thread do servidor nao terminou"));
    }
    guest::free_bytes(server_block);
    if results[0] != 0 || results[1] != CONSOLE_IO_CONNECT {
        return Err(format!("READ_IO da conexao: status={:#x} function={}", results[0], results[1]));
    }
    if results[3] != 0 {
        return Err(format!("COMPLETE_IO da conexao: {:#x}", results[3]));
    }
    if results[4] != 0 || results[5] != CONSOLE_IO_DISCONNECT {
        return Err(format!("READ_IO da desconexao: status={:#x} function={}", results[4], results[5]));
    }
    Ok(())
}
