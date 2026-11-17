//! Rastreador de IRPs: a vida de cada IRP pelas pilhas de dispositivos em
//! registros do fluxo (`stream`). Ganchos, todos desligados com um só
//! booleano lido:
//!
//! - a criação por um driver (IoAllocateIrp, IoBuild*Request,
//!   IoMakeAssociatedIrp) pelo despacho dos exports (`after_export`), com o
//!   endereço de retorno no driver;
//! - cada IofCallDriver (`call_driver`, antes da rotina de despacho), com o
//!   dispositivo, o driver, a rotina, major/minor, a posição na pilha e o
//!   chamador; e a volta da rotina (`returned`) com o status devolvido;
//! - o IofCompleteRequest (`completing`) com IoStatus.Status e Information;
//! - cada rotina de conclusão chamada (`completion_routine`) com o
//!   resultado (STATUS_MORE_PROCESSING_REQUIRED interrompe a subida);
//! - o IoFreeIrp (`freed`).
//!
//! O registro (depois do cabeçalho do fluxo): IRP u64 | dispositivo u64 |
//! driver u64 | ETHREAD u64 | chamador u64 | rotina u64 | valor u64 |
//! Information u64 | major u8 | minor u8 | posição u8 | pilha u8 | PID u32.
//! O tipo do registro diz o evento (`stream::KIND_IRP_*`).

use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::api_monitor;
use super::packet::Payload;
use super::stream::{self, Record};
use crate::ntos::inc::types::{DeviceObject, DriverObject, Irp, IoStackLocation, NtStruct};
use crate::ntos::init::exports::Call;
use crate::rtl::KernelError;

static ENABLED: AtomicBool = AtomicBool::new(false);
static RECORDED: AtomicU64 = AtomicU64::new(0);

/// Os exports que criam um IRP (os ids da tabela, achados ao ligar).
const CREATORS: [&str; 7] = ["IoAllocateIrp", "IoAllocateIrpEx", "IoBuildDeviceIoControlRequest", "IoBuildSynchronousFsdRequest", "IoBuildAsynchronousFsdRequest", "IoMakeAssociatedIrp", "IoMakeAssociatedIrpEx"];
static CREATOR_IDS: [AtomicU64; 7] = [const { AtomicU64::new(0) }; 7];
static FREE_ID: AtomicU64 = AtomicU64::new(0);

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

fn id_of(name: &str) -> u64 {
    crate::ntos::init::exports::export_names().iter().position(|&candidate| candidate == name).map_or(0, |index| index as u64 + 32)
}

/// Os campos de um evento.
#[derive(Default)]
struct Event {
    irp: u64,
    device: u64,
    driver: u64,
    caller: u64,
    routine: u64,
    value: u64,
    information: u64,
    major: u8,
    minor: u8,
    location: u8,
    stack: u8,
}

fn emit(kind: u8, event: Event) {
    let thread = crate::ntos::ke::pcr::current_thread();
    let (pid, _) = api_monitor::thread_ids(thread);
    let mut record = Record::new(kind, 0, stream::now());
    for value in [event.irp, event.device, event.driver, thread, event.caller, event.routine, event.value, event.information] {
        record.push_u64(value);
    }
    record.push_bytes(&[event.major, event.minor, event.location, event.stack]);
    record.push_u32(pid as u32);
    RECORDED.fetch_add(1, Ordering::Relaxed);
    stream::commit(record);
}

fn irp(packet: u64) -> &'static Irp {
    // SAFETY: os ganchos recebem IRPs vivos do I/O Manager.
    unsafe { Irp::at(packet) }
}

/// A stack location corrente do IRP (major, minor, posição, pilha).
fn location_of(packet: u64) -> (u8, u8, u8, u8) {
    let irp = irp(packet);
    let current = irp.tail.overlay.current_stack_location.get();
    let (major, minor) = if current != 0 {
        // SAFETY: a stack location corrente de um IRP vivo.
        let location = unsafe { IoStackLocation::at(current) };
        (location.major_function.get(), location.minor_function.get())
    } else {
        (0, 0)
    };
    (major, minor, irp.current_location.get() as u8, irp.stack_count.get() as u8)
}

fn driver_of(device: u64) -> u64 {
    if device == 0 {
        return 0;
    }
    // SAFETY: DEVICE_OBJECT vivo do chamador.
    unsafe { DeviceObject::at(device) }.driver_object.get()
}

/// IofCallDriver, depois de descer a posição e antes da rotina.
#[inline]
pub fn call_driver(packet: u64, device: u64) {
    if enabled() {
        call_driver_slow(packet, device);
    }
}

#[cold]
fn call_driver_slow(packet: u64, device: u64) {
    let (major, minor, location, stack) = location_of(packet);
    let driver = driver_of(device);
    let routine = if driver != 0 {
        // SAFETY: DeviceObject->DriverObject de um dispositivo vivo.
        unsafe { DriverObject::at(driver) }.major_function.get(major as usize).map_or(0, |field| field.get())
    } else {
        0
    };
    emit(stream::KIND_IRP_CALL, Event { irp: packet, device, driver, caller: api_monitor::current_caller(), routine, major, minor, location, stack, ..Event::default() });
}

/// A volta da rotina de despacho, com o status que ela devolveu.
#[inline]
pub fn returned(packet: u64, device: u64, status: i32) {
    if enabled() {
        returned_slow(packet, device, status);
    }
}

#[cold]
fn returned_slow(packet: u64, device: u64, status: i32) {
    emit(stream::KIND_IRP_RETURN, Event { irp: packet, device, driver: driver_of(device), value: status as i64 as u64, ..Event::default() });
}

/// IofCompleteRequest na entrada.
#[inline]
pub fn completing(packet: u64) {
    if enabled() {
        completing_slow(packet);
    }
}

#[cold]
fn completing_slow(packet: u64) {
    let (major, minor, location, stack) = location_of(packet);
    let irp = irp(packet);
    emit(
        stream::KIND_IRP_COMPLETE,
        Event { irp: packet, caller: api_monitor::current_caller(), value: irp.io_status.status.get() as i64 as u64, information: irp.io_status.information.get(), major, minor, location, stack, ..Event::default() },
    );
}

/// Uma rotina de conclusão chamada, com o resultado.
#[inline]
pub fn completion_routine(packet: u64, routine: u64, device: u64, result: i32) {
    if enabled() {
        completion_routine_slow(packet, routine, device, result);
    }
}

#[cold]
fn completion_routine_slow(packet: u64, routine: u64, device: u64, result: i32) {
    // A rotina pode ter liberado o IRP (o padrão do STATUS_MORE_PROCESSING_REQUIRED
    // com IoFreeIrp): a posição sai pelo leitor do depurador, sem faltas.
    let location = super::memory::read_u8(crate::hal::cpu::read_cr3(), packet + core::mem::offset_of!(Irp, current_location) as u64).unwrap_or(0);
    emit(stream::KIND_IRP_ROUTINE, Event { irp: packet, device, driver: driver_of(device), routine, value: result as i64 as u64, location, ..Event::default() });
}

/// IoFreeIrp.
#[inline]
pub fn freed(packet: u64) {
    if enabled() && packet != 0 {
        freed_slow(packet);
    }
}

#[cold]
fn freed_slow(packet: u64) {
    emit(stream::KIND_IRP_FREE, Event { irp: packet, caller: api_monitor::current_caller(), ..Event::default() });
}

/// Depois de um export: a criação de um IRP por um driver.
pub fn after_export(id: u64, call: &Call, result: &Result<u64, KernelError>) {
    let Ok(packet) = result else { return };
    if *packet == 0 || id == FREE_ID.load(Ordering::Relaxed) {
        return;
    }
    let Some(index) = CREATOR_IDS.iter().position(|candidate| candidate.load(Ordering::Relaxed) == id) else { return };
    // O dispositivo alvo dos IoBuild*Request (o segundo argumento).
    let device = match index {
        2..=4 => call.arg(2),
        _ => 0,
    };
    let stack = irp(*packet).stack_count.get() as u8;
    emit(stream::KIND_IRP_ALLOCATE, Event { irp: *packet, device, driver: driver_of(device), caller: call.return_address, value: id, stack, ..Event::default() });
}

/// O `irptrace` do monitor.
pub fn command(line: &str, out: &mut Payload) {
    match line.split_whitespace().next().unwrap_or("status") {
        "on" => {
            if !stream::available() {
                out.push_str("irp: sem o anel do fluxo\n");
                return;
            }
            for (cell, name) in CREATOR_IDS.iter().zip(CREATORS) {
                cell.store(id_of(name), Ordering::Relaxed);
            }
            FREE_ID.store(id_of("IoFreeIrp"), Ordering::Relaxed);
            ENABLED.store(true, Ordering::Release);
            api_monitor::update_active();
            out.push_str("irp: rastreador ligado\n");
        }
        "off" => {
            ENABLED.store(false, Ordering::Release);
            api_monitor::update_active();
            out.push_str("irp: rastreador desligado\n");
        }
        _ => {
            let _ = writeln!(out, "irptrace: {}, {} registros", if enabled() { "ligado" } else { "desligado" }, RECORDED.load(Ordering::Relaxed));
            stream::status(out);
        }
    }
}
