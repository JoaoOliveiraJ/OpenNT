//! O desligamento do sistema.
//!
//! `run` (fase 6) confere as peças que não desligam a máquina: as filas do
//! IoRegisterShutdownNotification e do IoUnregisterShutdownNotification
//! (cabeça da fila, DO_SHUTDOWN_REGISTERED, retirada das duas filas), o
//! IRP_MJ_SHUTDOWN de uma entrada entregue ao topo da pilha, o valor do
//! PM1_CNT do S5 e o HalpShutdownContext do HaliAcpiMachineStateInit, o
//! ShutdownTime do ExShutdownSystem(0), a política DontPowerOffAfterShutdown,
//! o PoCleanShutdownFlags e o PopShutdownEvent que só ele libera e, de um
//! processo de teste (modo usuário), a validação e o SeShutdownPrivilege do
//! NtShutdownSystem e do NtSetSystemPowerState.
//!
//! `run_boot_scenario` é o teste de boot do `--shutdown-test`, depois do
//! `--start-driver=ntfs`: cada boot deixa uma thread do
//! PoRequestShutdownEvent esperando o evento para sempre (o desligamento
//! comum não a espera); no primeiro boot grava `OPENNT-DESLIGAMENTO.TXT`
//! pelo ntfs.sys real no volume do segundo disco e um valor na hive SYSTEM
//! (`SHUTDOWN_PREPARED`) e chama o NtShutdownSystem com a ação pedida
//! (ShutdownPowerOff ou ShutdownReboot). No boot seguinte (o QEMU religado,
//! ou o reinício), o arquivo existe: o conteúdo é lido pelo ntfs.sys e pelo
//! leitor NTFS do kernel, que lê o disco direto, o valor do Registro e o
//! ShutdownTime voltaram da hive do volume (`SHUTDOWN_PERSISTED_OK`), e o
//! sistema desliga (ShutdownPowerOff).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::drivers::storage::ata_volume;
use crate::ntos::inc::{types as nt, NtStruct};
use crate::ntos::init::boot_config;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user::{memory, state};
use crate::ntos::test::file_system_mount::object_attributes;
use crate::ntos::test::multiprocess::identity::with_test_process;
use crate::ntos::test::phase6::call_export;

type Assert = fn(bool, &str);

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const IRP_MJ_SHUTDOWN: u8 = 0x10;
const DO_SHUTDOWN_REGISTERED: u32 = 0x800;
const REG_BINARY: u32 = 3;
const REG_DWORD: u32 = 4;
const REG_SZ: u64 = 1;

fn at<T: NtStruct>(address: u64) -> &'static T {
    // SAFETY: blocos do convidado alocados por este teste.
    unsafe { T::at(address) }
}

fn status(name: &str, arguments: &[u64]) -> u32 {
    call_export(name, arguments).unwrap_or(u64::MAX) as u32
}

// ---- fase 6 ----------------------------------------------------------------

/// IRP_MJ_SHUTDOWN recebidos pelo dispositivo de teste e o dispositivo que
/// recebeu o último.
static SHUTDOWN_IRPS: AtomicU32 = AtomicU32::new(0);
static LAST_TARGET: crate::rtl::SpinLock<u64> = crate::rtl::SpinLock::new(0);

extern "win64" fn shutdown_dispatch(device: u64, irp: u64) -> i32 {
    let request = at::<nt::Irp>(irp);
    let stack = at::<nt::IoStackLocation>(request.tail.overlay.current_stack_location.get());
    if stack.major_function.get() == IRP_MJ_SHUTDOWN && request.associated_irp.system_buffer.get() == 0 {
        SHUTDOWN_IRPS.fetch_add(1, Ordering::SeqCst);
        *LAST_TARGET.lock() = device;
    }
    request.io_status.status.set(0);
    request.io_status.information.set(0);
    crate::ntos::io::io_manager::iof_complete_request(irp);
    0
}

/// DRIVER_OBJECT sintético com a rotina em todas as funções e um
/// FILE_DEVICE_UNKNOWN dele.
fn test_device() -> (u64, u64) {
    let routine: extern "win64" fn(u64, u64) -> i32 = shutdown_dispatch;
    let pointer = routine as usize as u64;
    let routine = crate::ntos::mm::kernel_address::image_address(pointer).unwrap_or(pointer);
    let driver = guest::alloc_bytes(nt::DriverObject::SIZE);
    let object = at::<nt::DriverObject>(driver);
    object.type_.set(4);
    object.driver_init.set(1);
    for cell in &object.major_function {
        cell.set(routine);
    }
    let output = guest::alloc_bytes(8);
    let created = status("IoCreateDevice", &[driver, 0, 0, 0x22, 0, 0, output]);
    let device = if created == 0 { guest::read64(output) } else { 0 };
    guest::free_bytes(output);
    (driver, device)
}

fn io_queues(assert: Assert) {
    use crate::ntos::io::shutdown;
    let (_, lower) = test_device();
    let (_, upper) = test_device();
    if lower == 0 || upper == 0 {
        assert(false, "shutdown: dispositivos de teste criados");
        return;
    }
    let attached = call_export("IoAttachDeviceToDeviceStack", &[upper, lower]).unwrap_or(0);
    let first = status("IoRegisterShutdownNotification", &[lower]);
    let second = status("IoRegisterShutdownNotification", &[upper]);
    let queue = shutdown::shutdown_devices();
    let flags = at::<nt::DeviceObject>(lower).flags.get() & DO_SHUTDOWN_REGISTERED != 0 && at::<nt::DeviceObject>(upper).flags.get() & DO_SHUTDOWN_REGISTERED != 0;
    assert(attached == lower && first == 0 && second == 0 && flags && queue.first() == Some(&upper) && queue.get(1) == Some(&lower), "shutdown: IoRegisterShutdownNotification poe o dispositivo na cabeca da fila (o ultimo e avisado primeiro) com DO_SHUTDOWN_REGISTERED");
    // A entrada do dispositivo de baixo entrega o IRP no topo da pilha.
    SHUTDOWN_IRPS.store(0, Ordering::SeqCst);
    let delivered = shutdown::notify_device(lower);
    assert(delivered.as_ref().is_ok_and(|&status| status == 0) && SHUTDOWN_IRPS.load(Ordering::SeqCst) == 1 && *LAST_TARGET.lock() == upper, "shutdown: o IRP_MJ_SHUTDOWN sincrono de uma entrada vai ao topo da pilha (IoGetAttachedDeviceReference)");
    // O registro de última chance também sai pelo IoUnregisterShutdownNotification.
    let last = status("IoRegisterLastChanceShutdownNotification", &[lower]);
    let _ = call_export("IoUnregisterShutdownNotification", &[lower]);
    let _ = call_export("IoUnregisterShutdownNotification", &[upper]);
    let gone = !shutdown::shutdown_devices().iter().any(|&device| device == lower || device == upper) && !shutdown::last_chance_devices().contains(&lower);
    let cleared = at::<nt::DeviceObject>(lower).flags.get() & DO_SHUTDOWN_REGISTERED == 0 && at::<nt::DeviceObject>(upper).flags.get() & DO_SHUTDOWN_REGISTERED == 0;
    assert(last == 0 && gone && cleared, "shutdown: IoUnregisterShutdownNotification tira o dispositivo das duas filas e limpa DO_SHUTDOWN_REGISTERED");
    let _ = call_export("IoDetachDevice", &[lower]);
    let _ = call_export("IoDeleteDevice", &[upper]);
    let _ = call_export("IoDeleteDevice", &[lower]);
}

fn hal_power_off(assert: Assert) {
    use crate::hal::{acpi_pm, firmware_return};
    // HalpShutdown: SLP_TYP do nibble | SLP_EN, preservando os bits 0x203.
    assert(firmware_return::sleep_control(0x0201, 0x8575) == 0x3601 && firmware_return::sleep_control(0xFFFF, 0x8570) == 0x2203 && firmware_return::sleep_control(0, 0x8575 >> 4) == 0x3C00, "shutdown: PM1_CNT do S5 = (SLP_TYP & 7 | 8) << 10 com os bits 0x203 preservados");
    assert(acpi_pm::shutdown_context(5, 7) == 0x8575 && acpi_pm::shutdown_context(0x15, 0x17) == 0x8575, "shutdown: HalpShutdownContext = (Pm1b & 0xF | 0x850) << 4 | Pm1a & 0xF");
    // HalpPlatformFlags: 7 numa FADT de revisão < 5; na 5, o IAPC_BOOT_ARCH
    // e as flags estreitam.
    let fadt = |revision: u8, flags: u32, architecture: u16| {
        let mut bytes = alloc::vec![0u8; 0x114];
        bytes[8] = revision;
        bytes[0x6D..0x6F].copy_from_slice(&architecture.to_le_bytes());
        bytes[0x70..0x74].copy_from_slice(&flags.to_le_bytes());
        bytes
    };
    let real = crate::hal::acpi::get_table("FACP", 0, false).map(|table| firmware_return::platform_flags(&table.bytes));
    assert(
        firmware_return::platform_flags(&fadt(3, 0x10_0000, 0)) == 7 && firmware_return::platform_flags(&fadt(5, 0, 2)) == 7 && firmware_return::platform_flags(&fadt(5, 0, 0)) == 5 && firmware_return::platform_flags(&fadt(5, 0x10_0000, 0x22)) == 2 && firmware_return::platform_flags(&fadt(6, 0x20_0000, 2)) == 0xF && real.is_some_and(|flags| flags & 2 != 0),
        "shutdown: HalpPlatformFlags da FADT (o reinicio pelo 8042 no QEMU)",
    );
    // HaliAcpiMachineStateInit com o S5 que a DSDT do QEMU declara.
    let real = crate::hal::acpi::get_table("DSDT", 0, false).and_then(|table| firmware_return::s5_sleep_type(&table.bytes));
    let values = guest::alloc_bytes(0x20);
    let model = guest::alloc_bytes(8);
    if let Some(sleep_type) = real {
        guest::write_bytes(values + 0xC, &[1, sleep_type, sleep_type]);
        acpi_pm::machine_state_init(values, model);
    }
    let expected = real.map(|sleep_type| acpi_pm::shutdown_context(sleep_type as u32, sleep_type as u32));
    assert(expected.is_some() && Some(acpi_pm::acpi_shutdown_context()) == expected && Some(firmware_return::shutdown_context()) == expected && guest::read32(model) == 1, "shutdown: HaliAcpiMachineStateInit guarda o contexto do S5 do HAL_SLEEP_VAL[4]");
    guest::free_bytes(values);
    guest::free_bytes(model);
}

fn shutdown_time(assert: Assert) {
    use crate::ntos::cm::registry;
    use crate::ntos::ex::shutdown as executive;
    let recorded = executive::record_shutdown_time();
    let value = registry::read_value_by_path(executive::WINDOWS_KEY, executive::SHUTDOWN_TIME_VALUE);
    let matches = match (&recorded, &value) {
        (Ok(Some(time)), Some(value)) => value.value_type == REG_BINARY && value.data == time.to_le_bytes(),
        _ => false,
    };
    assert(matches, "shutdown: ExpRecordShutdownTime grava o SystemTime em Control\\Windows\\ShutdownTime (REG_BINARY de 8 bytes)");
}

fn policy(assert: Assert) {
    use crate::ntos::po::shutdown;
    let block = guest::alloc_bytes(0x400);
    let (handle, name, data) = (block + 0x300, block + 0x320, block + 0x340);
    // A SOFTWARE semeada não tem Policies: cada nível é criado.
    let mut created = 0;
    for path in ["\\Registry\\Machine\\Software\\Policies", "\\Registry\\Machine\\Software\\Policies\\Microsoft", "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows NT"] {
        let attributes = object_attributes(block, path);
        if created == 0 {
            created = status("ZwCreateKey", &[handle, 0xF003F, attributes, 0, 0, 0, 0]);
        }
        if created == 0 && !path.ends_with("Windows NT") {
            let _ = status("ZwClose", &[guest::read64(handle)]);
        }
    }
    let key = guest::read64(handle);
    let text = block + 0x360;
    crate::ntos::rtl::guest_strings::write_wide_string(text, "DontPowerOffAfterShutdown");
    let units = "DontPowerOffAfterShutdown".len() as u16 * 2;
    guest::write16(name, units);
    guest::write16(name + 2, units + 2);
    guest::write64(name + 8, text);
    let mut observed = Vec::new();
    for (value_type, value) in [(REG_DWORD as u64, 1u32), (REG_DWORD as u64, 2), (REG_SZ, 1), (REG_DWORD as u64, 1)] {
        guest::write32(data, value);
        let set = status("ZwSetValueKey", &[key, name, 0, value_type, data, 4]);
        shutdown::read_shutdown_policy();
        observed.push((set, shutdown::power_off_policy()));
    }
    // De volta ao padrão: sem o valor a política fica como está, então o 0
    // explícito a desliga.
    guest::write32(data, 0);
    let _ = status("ZwSetValueKey", &[key, name, 0, REG_DWORD as u64, data, 4]);
    shutdown::read_shutdown_policy();
    let restored = !shutdown::power_off_policy();
    let _ = status("ZwDeleteValueKey", &[key, name]);
    let _ = status("ZwClose", &[key]);
    guest::free_bytes(block);
    assert(created == 0 && observed == [(0, true), (0, false), (0, false), (0, true)] && restored, "shutdown: DontPowerOffAfterShutdown REG_DWORD com o primeiro byte 1 liga a politica; outro tipo a deixa como estava");
}

/// NtAdjustPrivilegesToken do token do processo com um TOKEN_PRIVILEGES
/// (SeShutdownPrivilege e os atributos dados) na memória de usuário `block`.
fn adjust_shutdown_privilege(block: u64, attributes: u32) -> bool {
    let Some(token) = crate::ntos::ob::object_access::subject() else { return false };
    guest::write32(block, 1);
    guest::write64(block + 4, 19);
    guest::write32(block + 12, attributes);
    let adjusted = crate::ntos::se::token::adjust::adjust_privileges(token, false, block, 16, 0, 0);
    adjusted.is_ok_and(|status| status == 0)
}

fn user_mode_services(assert: Assert) {
    use crate::ntos::po::shutdown;
    let outcome = with_test_process("desligamento-teste", None, |_| {
        let region = memory::map_user_region(0x1000).unwrap_or(0);
        let rsp = region + 0x800;
        let call = |name: &str, arguments: [u64; 4]| state::handler(name).and_then(|handler| handler(arguments[0], arguments[1], arguments[2], arguments[3], rsp).ok()).unwrap_or(u32::MAX);
        let mode = crate::ntos::ps::previous_mode::get().unwrap_or(0);
        let held_before = shutdown::holds_shutdown_privilege(1);
        // Só sem o privilégio as chamadas válidas voltam: com ele, a máquina
        // desligaria no meio do autoteste.
        if mode != 1 || held_before {
            return (mode, [0; 4], [0; 4], held_before, false, false, 0, false);
        }
        let invalid = [call("NtShutdownSystem", [4, 0, 0, 0]), call("NtSetSystemPowerState", [6, 0, 0xC000_0004, 0]), call("NtSetSystemPowerState", [8, 4, 0, 0]), call("NtSetSystemPowerState", [6, 4, 0x40, 0])];
        let unprivileged = [call("NtShutdownSystem", [2, 0, 0, 0]), call("NtShutdownSystem", [1, 0, 0, 0]), call("NtShutdownSystem", [3, 0, 0, 0]), call("NtSetSystemPowerState", [6, 4, 0xC000_0004, 0])];
        let enabled = adjust_shutdown_privilege(region + 0x100, 2);
        let held = shutdown::holds_shutdown_privilege(1);
        // Com o privilégio, a suspensão não é suportada (e não desliga).
        let sleep = call("NtSetSystemPowerState", [2, 4, 0, 0]);
        let disabled = adjust_shutdown_privilege(region + 0x100, 0);
        (mode, invalid, unprivileged, held_before, enabled, held, sleep, disabled && !shutdown::holds_shutdown_privilege(1))
    });
    let Some((mode, invalid, unprivileged, held_before, enabled, held, sleep, disabled)) = outcome else {
        assert(false, "shutdown: processo de teste");
        return;
    };
    assert(mode == 1 && invalid == [STATUS_INVALID_PARAMETER; 4], "shutdown: NtShutdownSystem e NtSetSystemPowerState do modo usuario recusam acao, estado e flags invalidos");
    assert(unprivileged == [STATUS_PRIVILEGE_NOT_HELD; 4] && !held_before, "shutdown: sem o SeShutdownPrivilege habilitado o modo usuario recebe STATUS_PRIVILEGE_NOT_HELD");
    assert(enabled && held && sleep == STATUS_NOT_SUPPORTED && disabled, "shutdown: com o SeShutdownPrivilege habilitado pelo NtAdjustPrivilegesToken a checagem passa (a suspensao nao e suportada)");
}

/// O PoCleanShutdownFlags do CmControlVector e o começo do
/// PopGracefulShutdown que depende dele.
fn clean_shutdown_gate(assert: Assert) {
    use crate::ntos::po::{shutdown, system_state};
    let default = shutdown::clean_shutdown_flags();
    let block = guest::alloc_bytes(0x400);
    let (handle, name, data) = (block + 0x300, block + 0x320, block + 0x340);
    let attributes = object_attributes(block, "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel");
    let created = status("ZwCreateKey", &[handle, 0xF003F, attributes, 0, 0, 0, 0]);
    let key = guest::read64(handle);
    let text = block + 0x360;
    crate::ntos::rtl::guest_strings::write_wide_string(text, "PoCleanShutdownFlags");
    let units = "PoCleanShutdownFlags".len() as u16 * 2;
    guest::write16(name, units);
    guest::write16(name + 2, units + 2);
    guest::write64(name + 8, text);
    // Até quatro bytes de qualquer tipo, sobre o 0 da imagem.
    let mut observed = Vec::new();
    for (value_type, bytes) in [(REG_BINARY as u64, &[0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66][..]), (REG_DWORD as u64, &[0x10, 0][..]), (REG_SZ, &[0x31, 0][..])] {
        guest::write_bytes(data, bytes);
        let set = status("ZwSetValueKey", &[key, name, 0, value_type, data, bytes.len() as u64]);
        shutdown::initialize_control_values();
        observed.push((set, shutdown::clean_shutdown_flags()));
    }
    let deleted = status("ZwDeleteValueKey", &[key, name]);
    shutdown::initialize_control_values();
    let restored = shutdown::clean_shutdown_flags();
    let _ = status("ZwClose", &[key]);
    assert(default == 0 && created == 0 && observed == [(0, 0x4433_2211), (0, 0x10), (0, 0x31)] && deleted == 0 && restored == 0, "shutdown: PoCleanShutdownFlags vem de Session Manager\\Kernel com ate 4 bytes do valor sobre o 0 da imagem");
    // Com o valor 0 (o boot comum), o PopGracefulShutdown não sinaliza o
    // PopShutdownEvent nem espera as threads: a do teste está na lista e não
    // termina, e o passo volta na hora com a lista ainda aberta.
    let event_out = block + 0x3F0;
    let thread = crate::ntos::ps::process::get_current_thread();
    let requested = status("PoRequestShutdownEvent", &[event_out]);
    let event = guest::read64(event_out);
    let waited = if restored == 0 { shutdown::shutdown_event_step() } else { usize::MAX };
    let again = status("PoRequestShutdownEvent", &[event_out]);
    let signalled = event != 0 && at::<nt::Kevent>(event).header.signal_state.get() != 0;
    assert(requested == 0 && event != 0 && waited == 0 && !signalled && again == 0 && system_state::shutdown_waiters().contains(&thread), "shutdown: sem PoCleanShutdownFlags o PopGracefulShutdown nao sinaliza o PopShutdownEvent nem espera as threads do PoRequestShutdownEvent");
    guest::free_bytes(block);
}

/// O IRP_MJ_SHUTDOWN do NTFS do kernel numa montagem própria do segundo
/// disco (outra instância do writer: o volume de boot segue gravando).
fn ntfs_shut_down(assert: Assert) {
    use crate::drivers::fs::ntfs;
    let Ok(volume) = ntfs::mount(1) else {
        assert(false, "shutdown: montagem propria do volume NTFS");
        return;
    };
    let before = volume.read("/HELLO.TXT").ok().flatten();
    let readable = before.is_some();
    let same = |text: Result<Option<String>, crate::rtl::KernelError>| text.ok().flatten() == before;
    let closed = volume.shut_down().is_ok() && volume.is_shut_down();
    let too_late = |status: Option<u32>| status == Some(0xC000_0189);
    let create = volume.create_with_security("/OPENNT-TARDE.TXT", false, 0x20, 0, None).err().map(|error| error.status);
    let write = volume.write("/HELLO.TXT", 0, b"x").err().map(|error| error.status);
    let rename = volume.rename("/HELLO.TXT", "/HELLO2.TXT", false).err().map(|error| error.status);
    let security = volume.set_security("/HELLO.TXT", &[1, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).err().map(|error| error.status);
    let paging = volume.paging_write("/HELLO.TXT", 0, &[0; 512]).err().map(|error| error.status);
    let still_readable = same(volume.read("/HELLO.TXT"));
    // Nada chegou ao disco: outra montagem não vê o arquivo nem a mudança.
    let disk = ntfs::mount(1).ok();
    let untouched = disk.as_ref().is_some_and(|disk| matches!(disk.exists("/OPENNT-TARDE.TXT"), Ok(false)) && matches!(disk.exists("/HELLO2.TXT"), Ok(false)) && same(disk.read("/HELLO.TXT")));
    assert(readable && closed && too_late(create) && too_late(write) && too_late(rename) && too_late(security) && too_late(paging) && still_readable && untouched, "shutdown: depois do desligamento o NTFS recusa criacao, escrita, renomeacao, descritor e paginacao com STATUS_TOO_LATE e segue lendo");
}

/// Corpo da thread do segundo pedido de desligamento: fica para sempre no
/// PopTransitionLock.
extern "win64" fn second_shutdown_request(_context: u64) {
    crate::ntos::po::shutdown::wait_behind_running_shutdown();
}

/// O segundo pedido espera o primeiro sem parar a CPU dele.
fn second_request(assert: Assert) {
    use crate::ntos::ke::{clock, thread_dispatch};
    use crate::ntos::ps::{kernel_threads, scheduler};
    let routine: extern "win64" fn(u64) = second_shutdown_request;
    let handle = kernel_threads::create_system_thread(0, routine as usize as u64, 0, 0x1F_FFFF, 0, None).unwrap_or(0);
    let thread = kernel_threads::of_handle(handle).unwrap_or(0);
    let waiting = || thread != 0 && thread_dispatch::thread_state(thread) == thread_dispatch::state::WAITING;
    let deadline = clock::uptime_ms() + 5000;
    while clock::uptime_ms() < deadline && !waiting() {
        scheduler::tick(-1);
    }
    // A CPU segue: o relógio anda e a thread continua na espera.
    let ticks = clock::uptime_ms();
    while clock::uptime_ms() < ticks + 50 {
        scheduler::tick(-1);
    }
    let kthread = (thread != 0).then(|| at::<nt::Kthread>(thread));
    assert(waiting() && kthread.is_some_and(|kthread| kthread.wait_mode.get() == 0), "shutdown: o segundo pedido de desligamento espera o PopTransitionLock em KernelMode sem parar a CPU");
    if handle != 0 {
        let _ = status("ZwClose", &[handle]);
    }
}

/// O PowerInformationInternal TransitionCheckpoint do NtPowerInformation de
/// modo usuário.
fn transition_checkpoint(assert: Assert) {
    use crate::ntos::po::{power_information, transition_checkpoint as checkpoints};
    let outcome = with_test_process("checkpoint-teste", None, |_| {
        let region = memory::map_user_region(0x1000).unwrap_or(0);
        let (input, output) = (region, region + 0x100);
        guest::write32(input, checkpoints::TRANSITION_CHECKPOINT);
        guest::write32(input + 4, 0);
        let call = |id: u32, kind: u32, length: u32, output_length: u32| {
            guest::write32(input + 8, id);
            guest::write32(input + 0xC, kind);
            power_information::query_user(87, input, length, if output_length != 0 { output } else { 0 }, output_length).unwrap_or(u32::MAX)
        };
        let short = call(0x55, 7, 0xC, 0);
        let with_output = call(0x55, 7, 0x10, 4);
        let first = call(0x55, 7, 0x10, 0);
        let after_first = checkpoints::latest();
        let second = call(1, 2, 0x10, 0);
        (short, with_output, first, after_first, second, checkpoints::latest(), checkpoints::checkpoints().last().copied())
    });
    let Some((short, with_output, first, after_first, second, latest, last)) = outcome else {
        assert(false, "shutdown: processo de teste do TransitionCheckpoint");
        return;
    };
    assert(short == 0xC000_0023 && with_output == 0xC000_000D, "shutdown: TransitionCheckpoint recusa entrada curta (STATUS_BUFFER_TOO_SMALL) e saida (STATUS_INVALID_PARAMETER)");
    let sequence = after_first.0;
    assert(first == 0 && after_first.1 == 0x55 && after_first.2 == 7 && second == 0 && latest == (sequence.wrapping_add(1), 1, 2) && last.is_some_and(|entry| entry.sequence == latest.0 && entry.id == 1 && entry.kind == 2 && entry.interrupt_time != 0), "shutdown: TransitionCheckpoint grava o ultimo Id e Type e o Id 1 abre a lista com o InterruptTime");
}

pub fn run(assert: Assert) {
    io_queues(assert);
    hal_power_off(assert);
    shutdown_time(assert);
    policy(assert);
    clean_shutdown_gate(assert);
    ntfs_shut_down(assert);
    second_request(assert);
    transition_checkpoint(assert);
    user_mode_services(assert);
}

// ---- o teste de boot do --shutdown-test --------------------------------------

/// O arquivo gravado pelo ntfs.sys antes do desligamento e o conteúdo.
const PERSISTED_FILE: &str = "OPENNT-DESLIGAMENTO.TXT";
const PERSISTED_CONTENT: &[u8] = b"Gravado pelo ntfs.sys antes do desligamento do OpenNT.\r\n";
/// A chave e o valor do Registro gravados antes do desligamento.
const TEST_KEY: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\OpenNT";
const TEST_VALUE: &str = "Desligamento";
const TEST_MARK: u32 = 0x5EED_0FF5;
const FILE_GENERIC_READ: u64 = 0x0012_0089;
const FILE_GENERIC_WRITE: u64 = 0x0012_0116;
const FILE_SYNCHRONOUS_NON_DIRECTORY: u64 = 0x60;
const FILE_OPEN: u64 = 1;
const FILE_CREATE: u64 = 2;

fn volume_path(name: &str) -> String {
    format!("\\Device\\{}\\{}", ata_volume::DEVICE_NAME, name)
}

/// Lê o arquivo pelo file system do volume: Ok(None) se ele não existe.
fn read_volume_file(name: &str) -> Result<Option<Vec<u8>>, String> {
    let block = guest::alloc_bytes(0x400);
    let buffer = guest::alloc_bytes(0x1000);
    let attributes = object_attributes(block, &volume_path(name));
    let (handle, iosb, offset) = (block + 0x300, block + 0x310, block + 0x320);
    let opened = status("ZwCreateFile", &[handle, FILE_GENERIC_READ, attributes, iosb, 0, 0, 1, FILE_OPEN, FILE_SYNCHRONOUS_NON_DIRECTORY, 0, 0]);
    let result = if opened == STATUS_OBJECT_NAME_NOT_FOUND {
        Ok(None)
    } else if opened != 0 {
        Err(format!("abertura de {name}: {opened:#x}"))
    } else {
        let file = guest::read64(handle);
        guest::write64(offset, 0);
        let read = status("ZwReadFile", &[file, 0, 0, 0, iosb, buffer, 0x1000, offset, 0]);
        let count = guest::read64(iosb + 8) as usize;
        let bytes = guest::read_bytes(buffer, count.min(0x1000));
        let _ = status("ZwClose", &[file]);
        if read == 0 { Ok(Some(bytes)) } else { Err(format!("leitura de {name}: {read:#x}")) }
    };
    guest::free_bytes(buffer);
    guest::free_bytes(block);
    result
}

/// Cria o arquivo pelo file system do volume e grava o conteúdo.
fn write_volume_file(name: &str, content: &[u8]) -> Result<(), String> {
    let block = guest::alloc_bytes(0x400);
    let buffer = guest::alloc_bytes(0x1000);
    let attributes = object_attributes(block, &volume_path(name));
    let (handle, iosb, offset) = (block + 0x300, block + 0x310, block + 0x320);
    let created = status("ZwCreateFile", &[handle, FILE_GENERIC_READ | FILE_GENERIC_WRITE, attributes, iosb, 0, 0x80, 1, FILE_CREATE, FILE_SYNCHRONOUS_NON_DIRECTORY, 0, 0]);
    let result = if created != 0 {
        Err(format!("criacao de {name}: {created:#x}"))
    } else {
        let file = guest::read64(handle);
        guest::write_bytes(buffer, content);
        guest::write64(offset, 0);
        let written = status("ZwWriteFile", &[file, 0, 0, 0, iosb, buffer, content.len() as u64, offset, 0]);
        let count = guest::read64(iosb + 8);
        let closed = status("ZwClose", &[file]);
        if written == 0 && count == content.len() as u64 && closed == 0 { Ok(()) } else { Err(format!("escrita de {name}: {written:#x} ({count} bytes), fechamento {closed:#x}")) }
    };
    guest::free_bytes(buffer);
    guest::free_bytes(block);
    result
}

/// ZwCreateKey (REG_OPTION_NON_VOLATILE) e ZwSetValueKey REG_DWORD.
fn write_test_value(value: u32) -> Result<(), String> {
    let block = guest::alloc_bytes(0x400);
    let attributes = object_attributes(block, TEST_KEY);
    let (handle, name, data) = (block + 0x300, block + 0x320, block + 0x340);
    let created = status("ZwCreateKey", &[handle, 0xF003F, attributes, 0, 0, 0, 0]);
    let result = if created != 0 {
        Err(format!("ZwCreateKey: {created:#x}"))
    } else {
        let key = guest::read64(handle);
        let text = block + 0x360;
        crate::ntos::rtl::guest_strings::write_wide_string(text, TEST_VALUE);
        guest::write16(name, TEST_VALUE.len() as u16 * 2);
        guest::write16(name + 2, TEST_VALUE.len() as u16 * 2 + 2);
        guest::write64(name + 8, text);
        guest::write32(data, value);
        let set = status("ZwSetValueKey", &[key, name, 0, REG_DWORD as u64, data, 4]);
        let _ = status("ZwClose", &[key]);
        if set == 0 { Ok(()) } else { Err(format!("ZwSetValueKey: {set:#x}")) }
    };
    guest::free_bytes(block);
    result
}

fn dword(value: &crate::ntos::cm::registry::Value) -> Option<u32> {
    (value.value_type == REG_DWORD && value.data.len() == 4).then(|| u32::from_le_bytes([value.data[0], value.data[1], value.data[2], value.data[3]]))
}

/// O boot que encontra o arquivo: o que sobreviveu ao desligamento.
fn check_persisted(through_driver: &[u8]) -> Result<String, String> {
    use crate::ntos::cm::registry;
    use crate::ntos::ex::shutdown as executive;
    if through_driver != PERSISTED_CONTENT {
        return Err(format!("o ntfs.sys leu {} bytes diferentes do que foi gravado", through_driver.len()));
    }
    // O leitor NTFS do kernel lê o disco, não a sobreposição do volume.
    let on_disk = crate::drivers::fs::ntfs::mounted().and_then(|volume| volume.read_bytes(&format!("/{PERSISTED_FILE}")).ok().flatten());
    if on_disk.as_deref() != Some(PERSISTED_CONTENT) {
        return Err(format!("o leitor NTFS do kernel nao achou o arquivo no disco ({:?} bytes)", on_disk.map(|bytes| bytes.len())));
    }
    let mark = registry::read_value_by_path(TEST_KEY, TEST_VALUE).as_ref().and_then(dword);
    if mark != Some(TEST_MARK) {
        return Err(format!("o valor {TEST_VALUE} da hive SYSTEM voltou como {mark:?}"));
    }
    let time = registry::read_value_by_path(executive::WINDOWS_KEY, executive::SHUTDOWN_TIME_VALUE).filter(|value| value.value_type == REG_BINARY && value.data.len() == 8).map(|value| u64::from_le_bytes(value.data[..8].try_into().unwrap_or([0; 8])));
    let now = guest::read64(0xFFFF_F780_0000_0014);
    match time {
        Some(time) if time != 0 && time <= now => Ok(format!("arquivo={} bytes registro={:#x} ShutdownTime={:#x}", through_driver.len(), TEST_MARK, time)),
        _ => Err(format!("ShutdownTime ausente ou invalido: {time:?}")),
    }
}

/// Corpo da thread que pede o PopShutdownEvent e o espera para sempre, como
/// o RawInputThread da sessão 0 do win32kfull: o evento só é sinalizado com
/// o PoCleanShutdownFlags, e o desligamento comum não espera por ela.
extern "win64" fn shutdown_event_waiter(event_out: u64) {
    if matches!(crate::ntos::po::system_state::request_shutdown_event(event_out), Ok(0)) {
        let event = guest::read64(event_out);
        crate::ntos::ke::dispatcher::wait_for_single_object(event, 0, 0, false);
    }
}

/// Cria a thread do PoRequestShutdownEvent e roda o escalonador até ela
/// entrar na lista de espera de desligamento.
fn start_shutdown_event_waiter() -> bool {
    use crate::ntos::ke::clock;
    use crate::ntos::po::system_state;
    let before = system_state::shutdown_waiters().len();
    let event_out = guest::alloc_bytes(8);
    let routine: extern "win64" fn(u64) = shutdown_event_waiter;
    if event_out == 0 || crate::ntos::ps::kernel_threads::create_system_thread(0, routine as usize as u64, event_out, 0x1F_FFFF, 0, None).is_err() {
        return false;
    }
    let deadline = clock::uptime_ms() + 5000;
    while clock::uptime_ms() < deadline && system_state::shutdown_waiters().len() == before {
        crate::ntos::ps::scheduler::tick(-1);
    }
    system_state::shutdown_waiters().len() > before
}

/// O teste de boot do `--shutdown-test`: só volta se não puder desligar.
pub fn run_boot_scenario() {
    let action = match boot_config::shutdown_test() {
        "poweroff" => 2,
        "reboot" => 1,
        // O desligamento da cadeia sai do gancho de primeiro boot do
        // winlogon; aqui só a conferência do boot seguinte.
        "cadeia" => return chain_boot_check(),
        other => {
            debug_print!("SELFTEST FALHOU: --shutdown-test={} (poweroff ou reboot)", other);
            return;
        }
    };
    if ata_volume::device().is_none() {
        debug_print!("SELFTEST FALHOU: desligamento: o volume do ntfs.sys nao foi montado (--start-driver=ntfs)");
        return;
    }
    // Uma thread do PoRequestShutdownEvent que nunca termina: o desligamento
    // comum (PoCleanShutdownFlags = 0) não a espera.
    if !start_shutdown_event_waiter() {
        debug_print!("SELFTEST FALHOU: desligamento: a thread do PoRequestShutdownEvent nao entrou na lista");
        return;
    }
    match read_volume_file(PERSISTED_FILE) {
        Ok(Some(bytes)) => {
            match check_persisted(&bytes) {
                Ok(summary) => debug_print!("SHUTDOWN_PERSISTED_OK {}", summary),
                Err(message) => debug_print!("SELFTEST FALHOU: desligamento: {}", message),
            }
            let refused = crate::ntos::po::shutdown::shutdown_system(2);
            debug_print!("SELFTEST FALHOU: NtShutdownSystem(ShutdownPowerOff) voltou: {:?}", refused.map_err(|error| format!("{error}")));
        }
        Ok(None) => {
            let prepared = write_volume_file(PERSISTED_FILE, PERSISTED_CONTENT).and_then(|_| write_test_value(TEST_MARK));
            if let Err(message) = prepared {
                debug_print!("SELFTEST FALHOU: desligamento: {}", message);
                return;
            }
            debug_print!("SHUTDOWN_PREPARED arquivo={} setores_pendentes={} acao={} esperando_evento={}", PERSISTED_FILE, ata_volume::pending_sectors(), boot_config::shutdown_test(), crate::ntos::po::system_state::shutdown_waiters().len());
            let refused = crate::ntos::po::shutdown::shutdown_system(action);
            debug_print!("SELFTEST FALHOU: NtShutdownSystem({}) voltou: {:?}", action, refused.map_err(|error| format!("{error}")));
        }
        Err(message) => debug_print!("SELFTEST FALHOU: desligamento: {}", message),
    }
}

// ---- o teste do --shutdown-test=cadeia ---------------------------------------

/// O arquivo que o gancho de primeiro boot grava antes do shutdown.exe (o
/// `test_account::CHAIN_FILE` do xtask), no caminho do volume C:.
const CHAIN_FILE: &str = "/OPENNT-CADEIA.TXT";
const SETUP_KEY: &str = "\\Registry\\Machine\\SYSTEM\\Setup";
/// Os nomes das contas do domínio de contas no SAM e a conta de teste.
const SAM_NAMES: &str = "\\Registry\\Machine\\SAM\\SAM\\Domains\\Account\\Users\\Names";
const TEST_ACCOUNT: &str = "Usuario";
/// O RID da primeira conta criada (o NextRid de um banco novo).
const FIRST_ACCOUNT_RID: u32 = 1000;

/// O `--shutdown-test=cadeia` no boot, com as hives de máquina carregadas
/// do volume e antes do smss. Sem o arquivo é o primeiro boot: o gancho de
/// primeiro boot do winlogon ainda vai criar a conta, desfazer o gancho,
/// gravar o arquivo e desligar a cadeia pelo shutdown.exe. Com ele, esse
/// desligamento passou pelo disco: o arquivo (pelo leitor NTFS, que lê o
/// disco), a conta que o samsrv do lsass gravou no SAM (o tipo do valor
/// padrão do nome é o RID), o gancho desfeito pelo reg.exe na SYSTEM e o
/// ShutdownTime do ExShutdownSystem(0) precisam ter voltado
/// (`SHUTDOWN_CHAIN_PERSISTED_OK`).
fn chain_boot_check() {
    use crate::ntos::cm::registry;
    use crate::ntos::ex::shutdown as executive;
    let Some(volume) = crate::drivers::fs::ntfs::mounted() else {
        debug_print!("SELFTEST FALHOU: cadeia: volume C: sem o leitor NTFS");
        return;
    };
    let file = match volume.read_bytes(CHAIN_FILE) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            debug_print!("[desligamento] cadeia: primeiro boot ({} ausente)", CHAIN_FILE);
            return;
        }
        Err(error) => {
            debug_print!("SELFTEST FALHOU: cadeia: leitura de {}: {}", CHAIN_FILE, error);
            return;
        }
    };
    let account = registry::list_keys(SAM_NAMES).into_iter().find(|name| registry::same_name(name, TEST_ACCOUNT)).and_then(|name| registry::read_value_by_path(&format!("{SAM_NAMES}\\{name}"), "")).map(|value| value.value_type);
    let setup_type = registry::read_value_by_path(SETUP_KEY, "SetupType").as_ref().and_then(dword);
    let time = registry::read_value_by_path(executive::WINDOWS_KEY, executive::SHUTDOWN_TIME_VALUE).filter(|value| value.value_type == REG_BINARY && value.data.len() == 8).map(|value| u64::from_le_bytes(value.data[..8].try_into().unwrap_or([0; 8])));
    let now = guest::read64(0xFFFF_F780_0000_0014);
    let time_ok = time.is_some_and(|time| time != 0 && time <= now);
    if file.starts_with(b"cadeia") && account.is_some_and(|rid| rid >= FIRST_ACCOUNT_RID) && setup_type == Some(0) && time_ok {
        debug_print!("SHUTDOWN_CHAIN_PERSISTED_OK arquivo={} bytes conta={} rid={} SetupType=0 ShutdownTime={:#x}", file.len(), TEST_ACCOUNT, account.unwrap_or(0), time.unwrap_or(0));
    } else {
        debug_print!("SELFTEST FALHOU: cadeia: arquivo {:?}, conta {} rid {:?}, SetupType = {:?}, ShutdownTime = {:?}", core::str::from_utf8(&file).unwrap_or("?"), TEST_ACCOUNT, account, setup_type, time);
    }
}
