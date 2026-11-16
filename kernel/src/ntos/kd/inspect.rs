//! Consultas do OpenNT sobre objetos do NT (`qRcmd`, ao lado de `monitor`):
//! processo, thread, IRP, objeto de dispositivo, objeto de driver e handle.
//!
//! Tudo lê a memória do alvo parado pelo leitor do depurador (as tabelas de
//! páginas do CR3 do dono da parada, sem travas nem faltas) com os layouts
//! gerados do PDB do ntoskrnl (`inc::types`): um ponteiro estragado só
//! encerra a listagem. A busca de um objeto pelo nome usa o Object Manager
//! e só roda quando nenhum processador parado tinha trava.

use core::fmt::Write;
use core::mem::offset_of;

use super::packet::Payload;
use super::{memory, stop};
use crate::ntos::inc::types::{
    ClientId, DeviceObject, DevobjExtension, DriverExtension, DriverObject, Eprocess, Ethread, EthreadView1, HandleTable, HandleTableEntry, IoStackLocation, Irp, KapcState, Kpcr, Kprcb, Kprocess, Kthread, KthreadView1, ObjectHeader, UnicodeString,
};
use crate::ntos::mm::memory_map::MAX_CPUS;
use crate::ntos::ps::process;

const LIST_LIMIT: usize = 1024;

const MAJOR_FUNCTIONS: [&str; 28] = [
    "IRP_MJ_CREATE",
    "IRP_MJ_CREATE_NAMED_PIPE",
    "IRP_MJ_CLOSE",
    "IRP_MJ_READ",
    "IRP_MJ_WRITE",
    "IRP_MJ_QUERY_INFORMATION",
    "IRP_MJ_SET_INFORMATION",
    "IRP_MJ_QUERY_EA",
    "IRP_MJ_SET_EA",
    "IRP_MJ_FLUSH_BUFFERS",
    "IRP_MJ_QUERY_VOLUME_INFORMATION",
    "IRP_MJ_SET_VOLUME_INFORMATION",
    "IRP_MJ_DIRECTORY_CONTROL",
    "IRP_MJ_FILE_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CONTROL",
    "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    "IRP_MJ_SHUTDOWN",
    "IRP_MJ_LOCK_CONTROL",
    "IRP_MJ_CLEANUP",
    "IRP_MJ_CREATE_MAILSLOT",
    "IRP_MJ_QUERY_SECURITY",
    "IRP_MJ_SET_SECURITY",
    "IRP_MJ_POWER",
    "IRP_MJ_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CHANGE",
    "IRP_MJ_QUERY_QUOTA",
    "IRP_MJ_SET_QUOTA",
    "IRP_MJ_PNP",
];

const PNP_MINOR: [&str; 0x19] = [
    "START_DEVICE",
    "QUERY_REMOVE_DEVICE",
    "REMOVE_DEVICE",
    "CANCEL_REMOVE_DEVICE",
    "STOP_DEVICE",
    "QUERY_STOP_DEVICE",
    "CANCEL_STOP_DEVICE",
    "QUERY_DEVICE_RELATIONS",
    "QUERY_INTERFACE",
    "QUERY_CAPABILITIES",
    "QUERY_RESOURCES",
    "QUERY_RESOURCE_REQUIREMENTS",
    "QUERY_DEVICE_TEXT",
    "FILTER_RESOURCE_REQUIREMENTS",
    "?",
    "READ_CONFIG",
    "WRITE_CONFIG",
    "EJECT",
    "SET_LOCK",
    "QUERY_ID",
    "QUERY_PNP_DEVICE_STATE",
    "QUERY_BUS_INFORMATION",
    "DEVICE_USAGE_NOTIFICATION",
    "SURPRISE_REMOVAL",
    "?",
];

const POWER_MINOR: [&str; 4] = ["WAIT_WAKE", "POWER_SEQUENCE", "SET_POWER", "QUERY_POWER"];

/// KWAIT_REASON.
const WAIT_REASONS: [&str; 41] = [
    "Executive",
    "FreePage",
    "PageIn",
    "PoolAllocation",
    "DelayExecution",
    "Suspended",
    "UserRequest",
    "WrExecutive",
    "WrFreePage",
    "WrPageIn",
    "WrPoolAllocation",
    "WrDelayExecution",
    "WrSuspended",
    "WrUserRequest",
    "WrSpare0",
    "WrQueue",
    "WrLpcReceive",
    "WrLpcReply",
    "WrVirtualMemory",
    "WrPageOut",
    "WrRendezvous",
    "WrKeyedEvent",
    "WrTerminated",
    "WrProcessInSwap",
    "WrCpuRateControl",
    "WrCalloutStack",
    "WrKernel",
    "WrResource",
    "WrPushLock",
    "WrMutex",
    "WrQuantumEnd",
    "WrDispatchInt",
    "WrPreempted",
    "WrYieldExecution",
    "WrFastMutex",
    "WrGuardedMutex",
    "WrRundown",
    "WrAlertByThreadId",
    "WrDeferredPreempt",
    "WrPhysicalFault",
    "WrIoRing",
];

const THREAD_STATES: [&str; 10] = ["Initialized", "Ready", "Running", "Standby", "Terminated", "Waiting", "Transition", "DeferredReady", "GateWait", "WaitingForProcessInSwap"];

/// DEVICE_TYPE dos dispositivos mais comuns.
fn device_type_name(value: u32) -> &'static str {
    match value {
        0x02 => "FILE_DEVICE_CD_ROM_FILE_SYSTEM",
        0x03 => "FILE_DEVICE_CONTROLLER",
        0x07 => "FILE_DEVICE_DISK",
        0x08 => "FILE_DEVICE_DISK_FILE_SYSTEM",
        0x09 => "FILE_DEVICE_FILE_SYSTEM",
        0x0B => "FILE_DEVICE_KEYBOARD",
        0x0F => "FILE_DEVICE_MOUSE",
        0x11 => "FILE_DEVICE_NAMED_PIPE",
        0x12 => "FILE_DEVICE_NETWORK",
        0x14 => "FILE_DEVICE_NETWORK_FILE_SYSTEM",
        0x15 => "FILE_DEVICE_NULL",
        0x17 => "FILE_DEVICE_PRINTER",
        0x1B => "FILE_DEVICE_SERIAL_PORT",
        0x22 => "FILE_DEVICE_UNKNOWN",
        0x23 => "FILE_DEVICE_VIDEO",
        0x29 => "FILE_DEVICE_NETWORK_REDIRECTOR",
        0x2A => "FILE_DEVICE_BATTERY",
        0x2B => "FILE_DEVICE_BUS_EXTENDER",
        0x32 => "FILE_DEVICE_ACPI",
        0x39 => "FILE_DEVICE_KSEC",
        _ => "",
    }
}

fn read_u64(cr3: u64, address: u64) -> u64 {
    memory::read_u64(cr3, address).unwrap_or(0)
}

fn read_u32(cr3: u64, address: u64) -> u32 {
    memory::read_u32(cr3, address).unwrap_or(0)
}

fn read_u8(cr3: u64, address: u64) -> u8 {
    memory::read_u8(cr3, address).unwrap_or(0)
}

/// Um número de um argumento (`0x...` ou decimal).
fn parse_value(text: &str) -> Option<u64> {
    let text = text.trim();
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// Um UNICODE_STRING em `address`, em ASCII (os outros caracteres viram `?`).
fn push_unicode_string(cr3: u64, address: u64, out: &mut Payload) {
    let length = memory::read_u16(cr3, address + offset_of!(UnicodeString, length) as u64).unwrap_or(0) as u64;
    let buffer = read_u64(cr3, address + offset_of!(UnicodeString, buffer) as u64);
    if length == 0 || buffer == 0 {
        out.push_str("(sem nome)");
        return;
    }
    for index in 0..(length / 2).min(128) {
        let unit = memory::read_u16(cr3, buffer + index * 2).unwrap_or(b'?' as u16);
        out.push(if (0x20..0x7F).contains(&unit) { unit as u8 } else { b'?' });
    }
}

/// O ImageFileName de um EPROCESS.
fn push_process_name(cr3: u64, eprocess: u64, out: &mut Payload) {
    let mut name = [0u8; 15];
    let length = memory::read(cr3, eprocess + offset_of!(Eprocess, image_file_name) as u64, &mut name);
    for &byte in name[..length].iter().take_while(|&&byte| byte != 0) {
        out.push(if (0x20..0x7F).contains(&byte) { byte } else { b'?' });
    }
}

/// Percorre uma LIST_ENTRY circular a partir da cabeça, até o limite.
fn walk_list(cr3: u64, head: u64, mut each: impl FnMut(u64) -> bool) {
    let mut entry = read_u64(cr3, head);
    let mut count = 0;
    while entry != head && entry != 0 && count < LIST_LIMIT {
        if !each(entry) {
            return;
        }
        entry = read_u64(cr3, entry);
        count += 1;
    }
}

/// A thread corrente do processador `number` (pela KPCR dele).
fn current_thread(number: usize) -> u64 {
    let pcr = stop::processor_control_region(number);
    if pcr == 0 {
        return 0;
    }
    read_u64(stop::address_space(number), pcr + (offset_of!(Kpcr, prcb) + offset_of!(Kprcb, current_thread)) as u64)
}

fn thread_process(cr3: u64, thread: u64) -> u64 {
    read_u64(cr3, thread + (offset_of!(Kthread, apc_state) + offset_of!(KapcState, process)) as u64)
}

/// O EPROCESS de um PID (pela lista ativa).
fn process_by_id(cr3: u64, pid: u64) -> Option<u64> {
    let head = process::try_active_process_head()?;
    let mut found = None;
    walk_list(cr3, head, |entry| {
        let eprocess = entry - offset_of!(Eprocess, active_process_links) as u64;
        if read_u64(cr3, eprocess + offset_of!(Eprocess, unique_process_id) as u64) == pid {
            found = Some(eprocess);
            return false;
        }
        true
    });
    found
}

/// Um EPROCESS a partir do argumento: vazio = o processo corrente do dono
/// da parada; um número pequeno = PID; o resto = endereço.
fn resolve_process(owner: usize, cr3: u64, argument: &str, out: &mut Payload) -> Option<u64> {
    if argument.trim().is_empty() {
        let thread = current_thread(owner);
        return (thread != 0).then(|| thread_process(cr3, thread)).filter(|&process| process != 0);
    }
    let Some(value) = parse_value(argument) else {
        out.push_str("uso: process [pid|eprocess]\n");
        return None;
    };
    if value < 0x1_0000_0000 {
        let found = process_by_id(cr3, value);
        if found.is_none() {
            let _ = writeln!(out, "PID {} nao esta na lista de processos", value);
        }
        return found;
    }
    Some(value)
}

fn push_thread_line(cr3: u64, thread: u64, out: &mut Payload) {
    let tid = read_u64(cr3, thread + (offset_of!(Ethread, cid) + offset_of!(ClientId, unique_thread)) as u64);
    let state = read_u8(cr3, thread + offset_of!(KthreadView1, state) as u64);
    let reason = read_u8(cr3, thread + offset_of!(KthreadView1, wait_reason) as u64);
    let priority = memory::read_u8(cr3, thread + offset_of!(KthreadView1, priority) as u64).unwrap_or(0) as i8;
    let start = read_u64(cr3, thread + offset_of!(EthreadView1, start_address) as u64);
    let state_name = THREAD_STATES.get(state as usize).copied().unwrap_or("?");
    let _ = write!(out, "    ETHREAD {:#x} TID {} {:<8}", thread, tid, state_name);
    if state == 5 {
        let _ = write!(out, " espera {}", WAIT_REASONS.get(reason as usize).copied().unwrap_or("?"));
    }
    let _ = writeln!(out, " prioridade {} inicio {:#x}", priority, start);
}

/// `process [pid|eprocess]`.
pub fn process(owner: usize, argument: &str, out: &mut Payload) {
    let cr3 = stop::address_space(owner);
    let Some(eprocess) = resolve_process(owner, cr3, argument, out) else {
        if argument.trim().is_empty() {
            out.push_str("sem processo corrente\n");
        }
        return;
    };
    let field = |offset: usize| read_u64(cr3, eprocess + offset as u64);
    let _ = write!(out, "EPROCESS {:#x} PID {} ", eprocess, field(offset_of!(Eprocess, unique_process_id)));
    push_process_name(cr3, eprocess, out);
    out.push(b'\n');
    let _ = writeln!(out, "  pai (InheritedFromUniqueProcessId) {}", field(offset_of!(Eprocess, inherited_from_unique_process_id)));
    let _ = writeln!(out, "  DirectoryTableBase {:#x}", field(offset_of!(Kprocess, directory_table_base)));
    let _ = writeln!(out, "  ObjectTable {:#x}", field(offset_of!(Eprocess, object_table)));
    let _ = writeln!(out, "  Peb {:#x}", field(offset_of!(Eprocess, peb)));
    let _ = writeln!(out, "  SectionBaseAddress {:#x}", field(offset_of!(Eprocess, section_base_address)));
    let _ = writeln!(out, "  ActiveThreads {}", read_u32(cr3, eprocess + offset_of!(Eprocess, active_threads) as u64));
    out.push_str("  threads:\n");
    walk_list(cr3, eprocess + offset_of!(Eprocess, thread_list_head) as u64, |link| {
        push_thread_line(cr3, link - offset_of!(Ethread, thread_list_entry) as u64, out);
        true
    });
}

/// `thread [ethread]` (vazio = a thread corrente do dono da parada).
pub fn thread(owner: usize, argument: &str, out: &mut Payload) {
    let cr3 = stop::address_space(owner);
    let thread = match parse_value(argument) {
        Some(value) if value != 0 => value,
        _ => current_thread(owner),
    };
    if thread == 0 {
        out.push_str("uso: thread <ethread>\n");
        return;
    }
    let field = |offset: usize| read_u64(cr3, thread + offset as u64);
    let byte = |offset: usize| read_u8(cr3, thread + offset as u64);
    let process = thread_process(cr3, thread);
    let _ = write!(
        out,
        "ETHREAD {:#x} TID {} PID {} ",
        thread,
        field(offset_of!(Ethread, cid) + offset_of!(ClientId, unique_thread)),
        field(offset_of!(Ethread, cid) + offset_of!(ClientId, unique_process))
    );
    if process != 0 {
        push_process_name(cr3, process, out);
    }
    out.push(b'\n');
    let state = byte(offset_of!(KthreadView1, state));
    let _ = write!(out, "  estado {}", THREAD_STATES.get(state as usize).copied().unwrap_or("?"));
    if state == 5 {
        let reason = byte(offset_of!(KthreadView1, wait_reason));
        let mode = byte(offset_of!(KthreadView1, wait_mode));
        let _ = write!(out, ", motivo da espera {} ({}), modo {}, IRQL da espera {}", WAIT_REASONS.get(reason as usize).copied().unwrap_or("?"), reason, if mode == 0 { "Kernel" } else { "User" }, byte(offset_of!(KthreadView1, wait_irql)));
    }
    out.push(b'\n');
    let _ = writeln!(
        out,
        "  prioridade {} base {}  WaitTime {}  KernelTime {}",
        byte(offset_of!(KthreadView1, priority)) as i8,
        byte(offset_of!(KthreadView1, base_priority)) as i8,
        read_u32(cr3, thread + offset_of!(KthreadView1, wait_time) as u64),
        read_u32(cr3, thread + offset_of!(KthreadView1, kernel_time) as u64)
    );
    let _ = writeln!(
        out,
        "  pilha de kernel: InitialStack {:#x} StackBase {:#x} StackLimit {:#x} KernelStack {:#x}",
        field(offset_of!(Kthread, initial_stack)),
        field(offset_of!(Kthread, stack_base)),
        field(offset_of!(Kthread, stack_limit)),
        field(offset_of!(Kthread, kernel_stack))
    );
    let _ = writeln!(out, "  StartAddress {:#x}", field(offset_of!(EthreadView1, start_address)));
    let _ = writeln!(out, "  Win32StartAddress {:#x}", field(offset_of!(Ethread, win32_start_address)));
    let _ = writeln!(out, "  Teb {:#x}  Process {:#x}", field(offset_of!(Kthread, teb)), process);
    let mut running = false;
    for number in 0..MAX_CPUS {
        if stop::processor_stopped(number) && current_thread(number) == thread {
            let _ = writeln!(out, "  roda na CPU {} (IRQL {})", number, stop::processor_irql(number));
            running = true;
        }
    }
    if !running {
        out.push_str("  fora da CPU (registradores no quadro de troca: context/btt)\n");
    }
    let mut count = 0;
    walk_list(cr3, thread + offset_of!(Ethread, irp_list) as u64, |link| {
        if count == 0 {
            out.push_str("  IRPs pendentes:\n");
        }
        let _ = writeln!(out, "    irp {:#x}", link - offset_of!(Irp, thread_list_entry) as u64);
        count += 1;
        count < 16
    });
}

/// O nome do driver de um objeto de dispositivo.
fn push_driver_of(cr3: u64, device: u64, out: &mut Payload) {
    let driver = read_u64(cr3, device + offset_of!(DeviceObject, driver_object) as u64);
    if driver == 0 {
        out.push_str("(sem driver)");
        return;
    }
    push_unicode_string(cr3, driver + offset_of!(DriverObject, driver_name) as u64, out);
}

fn major_name(major: u8) -> &'static str {
    MAJOR_FUNCTIONS.get(major as usize).copied().unwrap_or("IRP_MJ_?")
}

/// `irp <endereço>`.
pub fn irp(owner: usize, argument: &str, out: &mut Payload) {
    let cr3 = stop::address_space(owner);
    let Some(irp) = parse_value(argument).filter(|&value| value != 0) else {
        out.push_str("uso: irp <endereco>\n");
        return;
    };
    let field = |offset: usize| read_u64(cr3, irp + offset as u64);
    let byte = |offset: usize| read_u8(cr3, irp + offset as u64);
    let kind = memory::read_u16(cr3, irp + offset_of!(Irp, type_) as u64).unwrap_or(0);
    let stack_count = byte(offset_of!(Irp, stack_count)) as i8;
    let current = byte(offset_of!(Irp, current_location)) as i8;
    let _ = writeln!(out, "IRP {:#x} Type {}{} Size {:#x} StackCount {} CurrentLocation {} Flags {:#x}", irp, kind, if kind == 6 { "" } else { " (nao e IRP: Type deveria ser 6)" }, memory::read_u16(cr3, irp + offset_of!(Irp, size) as u64).unwrap_or(0), stack_count, current, read_u32(cr3, irp + offset_of!(Irp, flags) as u64));
    let _ = writeln!(out, "  MdlAddress {:#x}", field(offset_of!(Irp, mdl_address)));
    let _ = writeln!(out, "  AssociatedIrp (SystemBuffer) {:#x}", field(offset_of!(Irp, associated_irp)));
    let _ = writeln!(out, "  UserBuffer {:#x}", field(offset_of!(Irp, user_buffer)));
    let _ = writeln!(out, "  UserIosb {:#x}  UserEvent {:#x}", field(offset_of!(Irp, user_iosb)), field(offset_of!(Irp, user_event)));
    let _ = writeln!(out, "  IoStatus Status {:#010x} Information {:#x}", read_u32(cr3, irp + offset_of!(Irp, io_status) as u64), field(offset_of!(Irp, io_status) + 8));
    let _ = writeln!(out, "  RequestorMode {} PendingReturned {} Cancel {} CancelIrql {}", if byte(offset_of!(Irp, requestor_mode)) == 0 { "Kernel" } else { "User" }, byte(offset_of!(Irp, pending_returned)), byte(offset_of!(Irp, cancel)), byte(offset_of!(Irp, cancel_irql)));
    let _ = writeln!(out, "  CancelRoutine {:#x}", field(offset_of!(Irp, cancel_routine)));
    let _ = writeln!(out, "  Thread {:#x}", field(offset_of!(Irp, tail.overlay.thread)));
    let _ = writeln!(out, "  OriginalFileObject {:#x}", field(offset_of!(Irp, tail.overlay.original_file_object)));
    let _ = writeln!(out, "  CurrentStackLocation {:#x}", field(offset_of!(Irp, tail.overlay.current_stack_location)));
    if !(1..=32).contains(&stack_count) {
        out.push_str("  StackCount invalido: pilha nao listada\n");
        return;
    }
    out.push_str("  pilha de E/S (> = a corrente):\n");
    let first = irp + core::mem::size_of::<Irp>() as u64;
    let size = core::mem::size_of::<IoStackLocation>() as u64;
    for index in (0..stack_count as u64).rev() {
        let location = first + index * size;
        let at = |offset: usize| read_u64(cr3, location + offset as u64);
        let major = read_u8(cr3, location + offset_of!(IoStackLocation, major_function) as u64);
        let minor = read_u8(cr3, location + offset_of!(IoStackLocation, minor_function) as u64);
        let marker = if index as i8 + 1 == current { ">" } else { " " };
        let _ = write!(out, "  {}[{}] {:#x} {} ({:#x}) menor {:#x}", marker, index + 1, location, major_name(major), major, minor);
        let minor_name = match major {
            0x1B => PNP_MINOR.get(minor as usize).copied(),
            0x16 => POWER_MINOR.get(minor as usize).copied(),
            _ => None,
        };
        if let Some(name) = minor_name {
            let _ = write!(out, " ({})", name);
        }
        let _ = writeln!(out, " flags {:#x} controle {:#x}", read_u8(cr3, location + offset_of!(IoStackLocation, flags) as u64), read_u8(cr3, location + offset_of!(IoStackLocation, control) as u64));
        let device = at(offset_of!(IoStackLocation, device_object));
        let _ = write!(out, "       device {:#x} ", device);
        if device != 0 {
            push_driver_of(cr3, device, out);
        }
        let _ = writeln!(out, " file {:#x}", at(offset_of!(IoStackLocation, file_object)));
        let _ = writeln!(out, "       conclusao {:#x}", at(offset_of!(IoStackLocation, completion_routine)));
        let parameters = location + offset_of!(IoStackLocation, parameters) as u64;
        let _ = writeln!(out, "       contexto {:#x} parametros {:#x} {:#x} {:#x} {:#x}", at(offset_of!(IoStackLocation, context)), read_u64(cr3, parameters), read_u64(cr3, parameters + 8), read_u64(cr3, parameters + 16), read_u64(cr3, parameters + 24));
    }
}

/// O corpo de um objeto do namespace pelo nome (como o `obj`).
fn object_body(path: &str, out: &mut Payload) -> Option<u64> {
    if stop::locks_held() {
        out.push_str("namespace indisponivel: um processador parado tinha trava do kernel\n");
        return None;
    }
    use crate::ntos::ob::object_manager;
    let node = object_manager::lookup(path).and_then(object_manager::node);
    let Some(node) = node else {
        let _ = writeln!(out, "{}: nao encontrado", path);
        return None;
    };
    let body = node.data.as_ref().map_or(0, |data| if data.native_pointer != 0 { data.native_pointer } else { data.native_body });
    let body = if body != 0 { body } else { node.native_namespace };
    if body == 0 {
        let _ = writeln!(out, "{}: sem corpo nativo", path);
        return None;
    }
    Some(body)
}

fn resolve_object(argument: &str, out: &mut Payload) -> Option<u64> {
    let argument = argument.trim();
    if argument.starts_with('\\') {
        return object_body(argument, out);
    }
    parse_value(argument).filter(|&value| value != 0)
}

/// `devobj <endereço|\Device\Nome>`.
pub fn device_object(owner: usize, argument: &str, out: &mut Payload) {
    let cr3 = stop::address_space(owner);
    let Some(device) = resolve_object(argument, out) else {
        if argument.trim().is_empty() {
            out.push_str("uso: devobj <endereco|\\Device\\Nome>\n");
        }
        return;
    };
    let field = |offset: usize| read_u64(cr3, device + offset as u64);
    let kind = memory::read_u16(cr3, device + offset_of!(DeviceObject, type_) as u64).unwrap_or(0);
    let _ = write!(out, "DEVICE_OBJECT {:#x} Type {}{} driver {:#x} ", device, kind, if kind == 3 { "" } else { " (nao e DEVICE_OBJECT: Type deveria ser 3)" }, field(offset_of!(DeviceObject, driver_object)));
    push_driver_of(cr3, device, out);
    out.push(b'\n');
    let device_type = read_u32(cr3, device + offset_of!(DeviceObject, device_type) as u64);
    let _ = writeln!(out, "  DeviceType {:#x} {}", device_type, device_type_name(device_type));
    let _ = writeln!(out, "  Flags {:#x} Characteristics {:#x} StackSize {} ReferenceCount {}", read_u32(cr3, device + offset_of!(DeviceObject, flags) as u64), read_u32(cr3, device + offset_of!(DeviceObject, characteristics) as u64), read_u8(cr3, device + offset_of!(DeviceObject, stack_size) as u64) as i8, read_u32(cr3, device + offset_of!(DeviceObject, reference_count) as u64) as i32);
    let _ = writeln!(out, "  DeviceExtension {:#x}", field(offset_of!(DeviceObject, device_extension)));
    let _ = writeln!(out, "  Vpb {:#x}  CurrentIrp {:#x}", field(offset_of!(DeviceObject, vpb)), field(offset_of!(DeviceObject, current_irp)));
    let _ = writeln!(out, "  NextDevice {:#x}  AttachedDevice {:#x}", field(offset_of!(DeviceObject, next_device)), field(offset_of!(DeviceObject, attached_device)));
    let extension = field(offset_of!(DeviceObject, device_object_extension));
    if extension != 0 {
        let _ = writeln!(out, "  DeviceObjectExtension {:#x} AttachedTo {:#x} DeviceNode {:#x}", extension, read_u64(cr3, extension + offset_of!(DevobjExtension, attached_to) as u64), read_u64(cr3, extension + offset_of!(DevobjExtension, device_node) as u64));
    }
    // A pilha de dispositivos: sobe pelos AttachedDevice até o topo e desce
    // pelos AttachedTo.
    let mut top = device;
    for _ in 0..32 {
        let above = read_u64(cr3, top + offset_of!(DeviceObject, attached_device) as u64);
        if above == 0 || above == top {
            break;
        }
        top = above;
    }
    out.push_str("  pilha de dispositivos (do topo para baixo, > = este):\n");
    let mut current = top;
    for _ in 0..32 {
        let _ = write!(out, "  {} {:#x} ", if current == device { ">" } else { " " }, current);
        push_driver_of(cr3, current, out);
        out.push(b'\n');
        let extension = read_u64(cr3, current + offset_of!(DeviceObject, device_object_extension) as u64);
        let below = if extension != 0 { read_u64(cr3, extension + offset_of!(DevobjExtension, attached_to) as u64) } else { 0 };
        if below == 0 || below == current {
            break;
        }
        current = below;
    }
}

/// `drvobj <endereço|\Driver\Nome>`.
pub fn driver_object(owner: usize, argument: &str, out: &mut Payload) {
    let cr3 = stop::address_space(owner);
    let Some(driver) = resolve_object(argument, out) else {
        if argument.trim().is_empty() {
            out.push_str("uso: drvobj <endereco|\\Driver\\Nome>\n");
        }
        return;
    };
    let field = |offset: usize| read_u64(cr3, driver + offset as u64);
    let kind = memory::read_u16(cr3, driver + offset_of!(DriverObject, type_) as u64).unwrap_or(0);
    let _ = write!(out, "DRIVER_OBJECT {:#x} Type {}{} ", driver, kind, if kind == 4 { "" } else { " (nao e DRIVER_OBJECT: Type deveria ser 4)" });
    push_unicode_string(cr3, driver + offset_of!(DriverObject, driver_name) as u64, out);
    out.push(b'\n');
    let _ = writeln!(out, "  DriverStart {:#x} DriverSize {:#x}", field(offset_of!(DriverObject, driver_start)), read_u32(cr3, driver + offset_of!(DriverObject, driver_size) as u64));
    let _ = writeln!(out, "  DriverSection {:#x}  Flags {:#x}", field(offset_of!(DriverObject, driver_section)), read_u32(cr3, driver + offset_of!(DriverObject, flags) as u64));
    let extension = field(offset_of!(DriverObject, driver_extension));
    let _ = writeln!(out, "  DriverExtension {:#x}", extension);
    if extension != 0 {
        let _ = writeln!(out, "  AddDevice {:#x}", read_u64(cr3, extension + offset_of!(DriverExtension, add_device) as u64));
        out.push_str("  ServiceKeyName ");
        push_unicode_string(cr3, extension + offset_of!(DriverExtension, service_key_name) as u64, out);
        out.push(b'\n');
    }
    let _ = writeln!(out, "  DriverInit {:#x}", field(offset_of!(DriverObject, driver_init)));
    let _ = writeln!(out, "  DriverStartIo {:#x}", field(offset_of!(DriverObject, driver_start_io)));
    let _ = writeln!(out, "  DriverUnload {:#x}", field(offset_of!(DriverObject, driver_unload)));
    let _ = writeln!(out, "  FastIoDispatch {:#x}", field(offset_of!(DriverObject, fast_io_dispatch)));
    out.push_str("  dispositivos:");
    let mut device = field(offset_of!(DriverObject, device_object));
    let mut count = 0;
    while device != 0 && count < 64 {
        let _ = write!(out, " {:#x}", device);
        device = read_u64(cr3, device + offset_of!(DeviceObject, next_device) as u64);
        count += 1;
    }
    if count == 0 {
        out.push_str(" nenhum");
    }
    out.push_str("\n  tabela de despacho:\n");
    for (index, name) in MAJOR_FUNCTIONS.iter().enumerate() {
        let routine = field(offset_of!(DriverObject, major_function) + index * 8);
        let _ = writeln!(out, "    [{:02x}] {:<34} {:#x}", index, name, routine);
    }
}

/// `handle <pid|eprocess> <handle>`: a entrada na HANDLE_TABLE nativa do
/// processo (o mesmo caminho do ExpLookupHandleTableEntry).
pub fn handle(owner: usize, argument: &str, out: &mut Payload) {
    let cr3 = stop::address_space(owner);
    let mut words = argument.split_whitespace();
    let (Some(process_text), Some(handle)) = (words.next(), words.next().and_then(parse_value)) else {
        out.push_str("uso: handle <pid|eprocess> <handle>\n");
        return;
    };
    let Some(eprocess) = resolve_process(owner, cr3, process_text, out) else { return };
    let table = read_u64(cr3, eprocess + offset_of!(Eprocess, object_table) as u64);
    if table == 0 {
        let _ = writeln!(out, "EPROCESS {:#x} sem ObjectTable", eprocess);
        return;
    }
    let code = read_u64(cr3, table + offset_of!(HandleTable, table_code) as u64);
    let base = code & !3;
    let index = handle / 4;
    let entry_size = core::mem::size_of::<HandleTableEntry>() as u64;
    let per_page = 0x1000 / entry_size;
    let entry = match code & 3 {
        0 => base + index * entry_size,
        1 => {
            let leaf = read_u64(cr3, base + (index / per_page) * 8);
            if leaf == 0 { 0 } else { leaf + (index % per_page) * entry_size }
        }
        _ => {
            let middle = read_u64(cr3, base + (index / (per_page * 512)) * 8);
            let leaf = if middle == 0 { 0 } else { read_u64(cr3, middle + ((index / per_page) % 512) * 8) };
            if leaf == 0 { 0 } else { leaf + (index % per_page) * entry_size }
        }
    };
    let _ = writeln!(out, "handle {:#x} do EPROCESS {:#x}: HANDLE_TABLE {:#x} TableCode {:#x} (nivel {})", handle, eprocess, table, code, code & 3);
    if entry == 0 {
        out.push_str("  fora da tabela\n");
        return;
    }
    let low = read_u64(cr3, entry + offset_of!(HandleTableEntry, volatile_low_value) as u64);
    let high = read_u64(cr3, entry + offset_of!(HandleTableEntry, high_value) as u64);
    if low == 0 {
        let _ = writeln!(out, "  entrada {:#x} livre", entry);
        return;
    }
    let header = (((low as i64) >> 16) as u64) & !0xF;
    let body = header + offset_of!(ObjectHeader, body) as u64;
    let _ = writeln!(out, "  entrada {:#x} LowValue {:#x} GrantedAccess {:#x}", entry, low, high & 0x1FF_FFFF);
    let _ = writeln!(out, "  OBJECT_HEADER {:#x} corpo {:#x} PointerCount {} HandleCount {}", header, body, read_u64(cr3, header + offset_of!(ObjectHeader, pointer_count) as u64) as i64, read_u64(cr3, header + offset_of!(ObjectHeader, handle_count) as u64) as i64);
    let _ = writeln!(out, "  atributos: {}{}{}", if low & (1 << 17) != 0 { "Inherit " } else { "" }, if low & (1 << 18) != 0 { "AuditOnClose " } else { "" }, if low & (1 << 19) != 0 { "ProtectFromClose" } else { "" });
}
