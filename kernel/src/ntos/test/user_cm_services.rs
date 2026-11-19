//! Autotestes de serviços de modo usuário que o csrss.exe real pede no
//! caminho do winsrv: NtNotifyChangeKey/NtNotifyChangeMultipleKeys
//! (`cm/notify`), NtQueryLicenseValue (`ex/license/values`) e o
//! NtDeviceIoControlFile que vai ao FastIoDeviceControl do driver antes do
//! IRP (o `\Device\DeviceApi\CMApi` do cfgmgr32).

use crate::ntos::cm::registry;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types as nt;
use crate::ntos::io::pnp::cm_api;
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user::{memory, state};

type Assert = fn(bool, &str);

const STATUS_PENDING: u32 = 0x103;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_NOTIFY_ENUM_DIR: u32 = 0x10C;
const STATUS_NOTIFY_CLEANUP: u32 = 0x10B;
const STATUS_NO_SUCH_DEVICE: u32 = 0xC000_000E;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const NOTIFY_KEY: &str = "\\Registry\\Machine\\Software\\OpenNtNotifyUser";

/// OBJECT_ATTRIBUTES de usuário em `block` com o nome em `block + 0x100`.
fn attributes(block: u64, name: &str) -> u64 {
    state::write_user_wide(block + 0x100, name);
    state::write_unicode_string(block + 0x40, block + 0x100, name);
    // SAFETY: memória de usuário do teste, mapeada pelo kernel.
    let object = unsafe { nt::ObjectAttributes::at(block) };
    object.length.set(nt::ObjectAttributes::SIZE as u32);
    object.root_directory.set(0);
    object.object_name.set(block + 0x40);
    object.attributes.set(0x40);
    object.security_descriptor.set(0);
    object.security_quality_of_service.set(0);
    block
}

pub fn run(assert: Assert) {
    let Ok(block) = memory::map_user_region(0x4000) else {
        assert(false, "usercm: memoria de usuario");
        return;
    };
    let rsp = block + 0x3000;
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map_or(u32::MAX, |handler| handler(a1, a2, a3, a4, rsp).unwrap_or(u32::MAX));
    let stack = |values: &[u64]| {
        for (index, &value) in values.iter().enumerate() {
            guest::write64(rsp + 0x28 + index as u64 * 8, value);
        }
    };
    notify(assert, block, &call, &stack);
    license(assert, block, &call, &stack);
    device_control(assert, block, &call, &stack);
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

type Call<'a> = &'a dyn Fn(&str, u64, u64, u64, u64) -> u32;
type Stack<'a> = &'a dyn Fn(&[u64]);

fn notify(assert: Assert, block: u64, call: Call, stack: Stack) {
    let kernel_key = registry::open_or_create(NOTIFY_KEY, None);
    let (output, iosb, event_out) = (block + 0x800, block + 0x810, block + 0x820);
    let open = |access: u64| -> u64 {
        guest::write64(output, 0);
        let opened = call("NtOpenKey", output, access, attributes(block, NOTIFY_KEY), 0);
        if opened == 0 { guest::read64(output) } else { 0 }
    };
    let key = open(0x2_0019);
    let query_only = open(0x2_0001);
    stack(&[0, 0, 0]);
    let created = call("NtCreateEvent", event_out, 0x1F_0003, 0, 0);
    let event = guest::read64(event_out);
    // SAFETY: o IO_STATUS_BLOCK de usuário do teste.
    let io_status = unsafe { nt::IoStatusBlock::at(iosb) };
    // Count acima de 1, filtro fora do legal (o IOSB já recebeu
    // STATUS_PENDING) e REG_NOTIFY_THREAD_AGNOSTIC sem evento.
    stack(&[0, 0, iosb, 5, 0, 0, 0, 1]);
    let too_many = call("NtNotifyChangeMultipleKeys", key, 2, 0, 0);
    io_status.status.set(0);
    // NtNotifyChangeKey: IoStatusBlock, Filter, WatchTree, Buffer, BufferSize, Asynchronous.
    stack(&[iosb, 0x20, 0, 0, 0, 1]);
    let bad_filter = call("NtNotifyChangeKey", key, 0, 0, 0);
    let iosb_pending = io_status.status.get() as u32;
    stack(&[iosb, 0x1000_0001, 0, 0, 0, 1]);
    let agnostic = call("NtNotifyChangeKey", key, 0, 0, 0);
    stack(&[iosb, 1, 0, 0, 0, 1]);
    let denied = call("NtNotifyChangeKey", query_only, 0, 0, 0);
    assert(
        key != 0 && query_only != 0 && created == 0 && too_many == STATUS_INVALID_PARAMETER && bad_filter == STATUS_INVALID_PARAMETER && iosb_pending == STATUS_PENDING && agnostic == STATUS_INVALID_PARAMETER && denied == STATUS_ACCESS_DENIED,
        "usercm: NtNotifyChangeKey recusa Count > 1, filtro ilegal (depois de pôr STATUS_PENDING no IOSB), thread-agnostic sem evento e handle sem KEY_NOTIFY",
    );
    // Assíncrono com evento: STATUS_PENDING; a mudança grava o IOSB no
    // processo e sinaliza o evento; o pedido sai da lista.
    let event_pointer = state::get_user_handle(event).and_then(|entry| entry.object.native_body()).map_or(0, |body| body.pointer);
    if event_pointer != 0 {
        dispatcher::set_event(event_pointer);
    }
    io_status.status.set(0);
    io_status.information.set(0x55);
    stack(&[iosb, 0xF, 0, 0, 0, 1]);
    let pid = crate::ntos::ps::process::get_current_process_id();
    let pending = call("NtNotifyChangeKey", key, event, 0, 0);
    let reset = event_pointer != 0 && dispatcher::read_state(event_pointer) == 0;
    let queued = crate::ntos::cm::notify::pending_count(pid);
    if let Ok(handle) = kernel_key {
        registry::set_value(handle, "Touched", 4, alloc::vec![1, 0, 0, 0]);
    }
    let fired = event_pointer != 0 && dispatcher::read_state(event_pointer) != 0;
    assert(
        pending == STATUS_PENDING && reset && queued == 1 && fired && io_status.status.get() as u32 == STATUS_NOTIFY_ENUM_DIR && io_status.information.get() == 0 && crate::ntos::cm::notify::pending_count(pid) == 0,
        "usercm: NtNotifyChangeKey assincrono devolve STATUS_PENDING, zera o evento e a mudanca na chave grava STATUS_NOTIFY_ENUM_DIR e sinaliza",
    );
    // A filha criada sem pedido esperando (REG_NOTIFY_CHANGE_NAME na chave)
    // fica pendente no bloco do handle: o próximo pedido completa na hora,
    // com STATUS_SUCCESS (CmpNotifyChangeKey com NotifyPending).
    let child_handle = registry::open_or_create(&alloc::format!("{NOTIFY_KEY}\\A"), None);
    if let Ok(handle) = child_handle {
        registry::close_handle(handle);
    }
    stack(&[iosb, 0xF, 0, 0, 0, 1]);
    io_status.status.set(0);
    let kept = call("NtNotifyChangeKey", key, event, 0, 0);
    let kept_fired = event_pointer != 0 && dispatcher::read_state(event_pointer) != 0;
    assert(kept == 0 && kept_fired && io_status.status.get() as u32 == STATUS_NOTIFY_ENUM_DIR && crate::ntos::cm::notify::pending_count(pid) == 0, "usercm: a mudanca entre a conclusao e o novo pedido completa o pedido na hora");
    // Sem WatchTree, uma subchave neta não dispara; a mudança direta na
    // chave dispara.
    stack(&[iosb, 0xF, 0, 0, 0, 1]);
    io_status.status.set(0);
    let shallow = call("NtNotifyChangeKey", key, event, 0, 0);
    let deep = alloc::format!("{NOTIFY_KEY}\\A\\B");
    let deep_handle = registry::open_or_create(&deep, None);
    let shallow_fired = event_pointer != 0 && dispatcher::read_state(event_pointer) != 0;
    if let Ok(handle) = kernel_key {
        registry::set_value(handle, "Touched", 4, alloc::vec![2, 0, 0, 0]);
    }
    assert(shallow == STATUS_PENDING && !shallow_fired && io_status.status.get() as u32 == STATUS_NOTIFY_ENUM_DIR, "usercm: sem WatchTree a neta nao dispara e a mudanca direta sim");
    // O filtro do bloco: REG_NOTIFY_CHANGE_LAST_SET não dispara na criação
    // de subchave (nem a guarda como pendente) e dispara no valor.
    let last_set = open(0x2_0019);
    stack(&[iosb, 4, 0, 0, 0, 1]);
    io_status.status.set(0);
    let armed = call("NtNotifyChangeKey", last_set, event, 0, 0);
    let named = registry::open_or_create(&alloc::format!("{NOTIFY_KEY}\\C"), None);
    if let Ok(handle) = named {
        registry::close_handle(handle);
    }
    let name_fired = event_pointer != 0 && dispatcher::read_state(event_pointer) != 0;
    if let Ok(handle) = kernel_key {
        registry::set_value(handle, "Touched", 4, alloc::vec![3, 0, 0, 0]);
    }
    let value_fired = event_pointer != 0 && dispatcher::read_state(event_pointer) != 0;
    assert(last_set != 0 && armed == STATUS_PENDING && !name_fired && value_fired && io_status.status.get() as u32 == STATUS_NOTIFY_ENUM_DIR, "usercm: o filtro REG_NOTIFY_CHANGE_LAST_SET ignora a subchave nova e dispara no valor");
    // Fechar o handle completa o pedido com STATUS_NOTIFY_CLEANUP.
    stack(&[iosb, 4, 0, 0, 0, 1]);
    io_status.status.set(0);
    let rearmed = call("NtNotifyChangeKey", last_set, event, 0, 0);
    let closed = call("NtClose", last_set, 0, 0, 0);
    let cleanup_fired = event_pointer != 0 && dispatcher::read_state(event_pointer) != 0;
    assert(rearmed == STATUS_PENDING && closed == 0 && cleanup_fired && io_status.status.get() as u32 == STATUS_NOTIFY_CLEANUP && crate::ntos::cm::notify::pending_count(pid) == 0, "usercm: o fechamento do handle completa o pedido com STATUS_NOTIFY_CLEANUP");
    if let Ok(handle) = deep_handle {
        registry::delete_key(handle);
        registry::close_handle(handle);
    }
    for child in ["A", "C"] {
        if let Some(handle) = registry::open(&alloc::format!("{NOTIFY_KEY}\\{child}")).ok() {
            registry::delete_key(handle);
            registry::close_handle(handle);
        }
    }
    for handle in [key, query_only, event] {
        let _ = call("NtClose", handle, 0, 0, 0);
    }
    if let Ok(handle) = kernel_key {
        registry::delete_key(handle);
        registry::close_handle(handle);
    }
}

fn license(assert: Assert, block: u64, call: Call, stack: Stack) {
    let (name, type_out, data, result) = (block + 0x900, block + 0x940, block + 0xA00, block + 0x948);
    state::write_user_wide(name + 0x20, "Kernel-OneCore-DeviceFamilyID");
    state::write_unicode_string(name, name + 0x20, "Kernel-OneCore-DeviceFamilyID");
    // Validação: sem nome, sem ResultDataSize, Data nulo com tamanho e
    // DataSize acima de 8 MB.
    stack(&[result]);
    let no_name = call("NtQueryLicenseValue", 0, type_out, data, 4);
    stack(&[0]);
    let no_result = call("NtQueryLicenseValue", name, type_out, data, 4);
    stack(&[result]);
    let null_data = call("NtQueryLicenseValue", name, type_out, 0, 4);
    let huge = call("NtQueryLicenseValue", name, type_out, data, 0x80_0001);
    // O mesmo nome pela consulta de modo kernel: status, tipo e tamanho iguais.
    guest::write32(type_out, 0);
    guest::write32(result, 0);
    let user = call("NtQueryLicenseValue", name, type_out, data, 0x40);
    let (user_type, user_size) = (guest::read32(type_out), guest::read32(result));
    let kernel = guest::alloc_bytes(0x100);
    crate::ntos::rtl::guest_strings::write_wide_string(kernel + 0x40, "Kernel-OneCore-DeviceFamilyID");
    crate::ntos::rtl::guest_strings::write_string_fields(kernel, 58, 60, kernel + 0x40);
    let kernel_status = crate::ntos::ex::license::values::query(kernel, kernel + 0x20, kernel + 0x80, 0x40, kernel + 0x24).unwrap_or(u32::MAX);
    let same = kernel_status == user && guest::read32(kernel + 0x24) == user_size && (user & 0x8000_0000 != 0 || (guest::read32(kernel + 0x20) == user_type && guest::read_bytes(kernel + 0x80, user_size as usize) == guest::read_bytes(data, user_size as usize)));
    guest::free_bytes(kernel);
    assert(
        no_name == STATUS_INVALID_PARAMETER && no_result == STATUS_INVALID_PARAMETER && null_data == STATUS_INVALID_PARAMETER && huge == STATUS_NO_MEMORY && same,
        "usercm: NtQueryLicenseValue valida os parametros como o NT e devolve o mesmo que a consulta de modo kernel",
    );
}

fn device_control(assert: Assert, block: u64, call: Call, stack: Stack) {
    let (handle_out, iosb) = (block + 0x1000, block + 0x1010);
    // NtCreateFile(\Device\DeviceApi\CMApi, GENERIC_READ, FILE_OPEN, sem opções).
    stack(&[0, 0, 0, 1, 0, 0, 0]);
    let opened = call("NtCreateFile", handle_out, 0x8000_0000, attributes(block + 0x1100, "\\Device\\DeviceApi\\CMApi"), iosb);
    let handle = guest::read64(handle_out);
    // SAFETY: o IO_STATUS_BLOCK de usuário do teste.
    let io_status = unsafe { nt::IoStatusBlock::at(iosb) };
    let (input, output) = (block + 0x1400, block + 0x1800);
    let name = "OPENNT\\NAO_EXISTE\\0";
    guest::write_bytes(input, &[0u8; 0x100]);
    guest::write32(input, 0x28);
    guest::write32(input + 8, 1);
    guest::write32(input + 0x20, 0x14);
    state::write_user_wide(input + 0x40, name);
    guest::write64(input + 0x10, input + 0x40);
    guest::write32(input + 0x18, (name.len() as u32 + 1) * 2);
    // NtDeviceIoControlFile: IoStatusBlock, Code, Input, InputLength, Output,
    // OutputLength; com PreviousMode = UserMode, como numa syscall real (o
    // \CMApi sonda e exige o alinhamento só para quem vem do modo usuário).
    // O Prcb.CurrentThread, de onde o ExGetPreviousMode lê.
    let thread = crate::ntos::ke::pcr::current().prcb.current_thread.get();
    // SAFETY: o ETHREAD corrente, vivo durante o teste.
    let previous_mode = &unsafe { nt::Ethread::at(thread) }.tcb.previous_mode;
    let saved = previous_mode.get();
    previous_mode.set(1);
    stack(&[iosb, cm_api::code::GET_DEVICE_STATUS as u64, input, 0x28, output, 0x14]);
    let controlled = call("NtDeviceIoControlFile", handle, 0, 0, 0);
    let information = io_status.information.get();
    let result = (guest::read32(output), guest::read32(output + 4));
    stack(&[iosb, cm_api::code::GET_DEVICE_STATUS as u64, input + 4, 0x28, output, 0x14]);
    let misaligned = call("NtDeviceIoControlFile", handle, 0, 0, 0);
    // O mesmo FILE_OBJECT aberto por ponteiro em UserMode no processo (o
    // ObOpenObjectByPointer com que o CdpLaunchServerProcess do condrv.sys
    // põe o servidor do console no conhost.exe): um `device` sem handle do
    // I/O manager, cujo IOCTL segue o IopXxxControlFile de `irp_service`, que
    // tenta o FastIoDeviceControl antes do IRP (o IRP_MJ_DEVICE_CONTROL do
    // \CMApi é STATUS_NOT_SUPPORTED).
    let file_object = state::get_user_handle(handle).and_then(|entry| entry.downcast::<crate::ntos::ps::user::files::UserDevice>().map(|device| device.file_object)).unwrap_or(0);
    let pointer_out = block + 0x1020;
    let by_pointer = crate::ntos::ob::open_pointer::open_by_pointer(file_object, 0, 0, 0x1000_0000, crate::ntos::ob::object_types::file_type().pointer, 1, pointer_out).unwrap_or(u32::MAX);
    let pointer_handle = guest::read64(pointer_out);
    guest::write_bytes(output, &[0u8; 0x14]);
    io_status.information.set(0);
    stack(&[iosb, cm_api::code::GET_DEVICE_STATUS as u64, input, 0x28, output, 0x14]);
    let fast = call("NtDeviceIoControlFile", pointer_handle, 0, 0, 0);
    let fast_information = io_status.information.get();
    let fast_result = (guest::read32(output), guest::read32(output + 4));
    previous_mode.set(saved);
    assert(
        by_pointer == 0 && pointer_handle != 0 && pointer_handle < 0x8000_0000 && fast == 0 && fast_information == 0x14 && fast_result == (0x14, STATUS_NO_SUCH_DEVICE),
        &alloc::format!("usercm: o handle de usuario do ObOpenObjectByPointer (o servidor do console no conhost) vai ao FastIoDeviceControl antes do IRP: aberto {by_pointer:#x} handle {pointer_handle:#x}, ioctl {fast:#x}, Information {fast_information:#x}, resultado {:#x}/{:#x}", fast_result.0, fast_result.1),
    );
    if by_pointer == 0 {
        let _ = call("NtClose", pointer_handle, 0, 0, 0);
    }
    assert(
        opened == 0 && controlled == 0 && information == 0x14 && result == (0x14, STATUS_NO_SUCH_DEVICE) && misaligned == STATUS_DATATYPE_MISALIGNMENT,
        &alloc::format!("usercm: NtDeviceIoControlFile de usuario vai ao FastIoDeviceControl do \\CMApi (resultado no buffer, entrada desalinhada recusada): aberto {opened:#x}, ioctl {controlled:#x}, Information {information:#x}, resultado {:#x}/{:#x}, desalinhado {misaligned:#x}", result.0, result.1),
    );
    if opened == 0 {
        let _ = call("NtClose", handle, 0, 0, 0);
    }
}
