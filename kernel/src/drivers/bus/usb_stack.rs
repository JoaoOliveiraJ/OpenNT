//! A pilha USB 3 e HID real do Windows (`--usb`).
//!
//! Com a opção, a máquina tem a controladora xHCI do QEMU (qemu-xhci,
//! PCI\VEN_1B36&DEV_000D, classe 0C.03.30) com um teclado e um tablet USB,
//! e o fim da fase 1 sobe pelo PnP manager a pilha da caixa: o usbxhci.inf
//! dá à controladora o usbxhci.sys (KMDF, com a extensão de classe
//! ucx01000.sys); o hub raiz que ela relata (USB\ROOT_HUB30) recebe o
//! usbhub3.sys; os dispositivos que o hub acha nas portas recebem o
//! hidusb.sys com o hidclass.sys (input.inf, USB\Class_03); e as coleções
//! HID de teclado e mouse recebem o kbdhid.sys e o mouhid.sys, com os
//! filtros de classe kbdclass e mouclass.
//!
//! A enumeração das portas é assíncrona (o hub trata as mudanças de estado
//! das portas quando a controladora as entrega por interrupção e relata os
//! filhos pelo IoInvalidateDeviceRelations), e o PnP manager processa essas
//! reenumerações enquanto esperamos. Os marcos saem na serial:
//! `USB_HUB_OK` (o hub raiz iniciado com um dispositivo nas portas) e
//! `USB_HID_OK` (o kbdhid e o mouhid iniciados).
//!
//! Com o teclado USB na máquina, o QEMU entrega a ele as teclas (o usb-kbd
//! fica com a entrada), e o serviço de teclado lê do FDO do kbdclass sobre
//! o kbdhid: a tecla vai do relatório HID que o usbxhci.sys recebe por
//! interrupção ao hidclass/hidusb, ao kbdhid (que traduz os usages em
//! scancodes) e ao kbdclass. A primeira tecla 'a' sai como `USB_KEY_OK`.
//!
//! Sem a opção nada disto roda.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::ntos::inc::types::{LargeInteger, NtStruct};
use crate::ntos::io::io_manager;
use crate::ntos::io::pnp::{self, devnode};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager;
use crate::rtl::SpinLock;

/// `--usb`: a pilha USB sobe pelo PnP na controladora xHCI.
pub fn enabled() -> bool {
    crate::ntos::init::boot_config::usb()
}

/// Tempo máximo de espera pela enumeração das portas e da pilha HID.
const SETTLE_MS: u64 = 60_000;
/// Passo da espera (KeDelayExecutionThread).
const STEP_MS: i64 = 100;

/// Espera `milliseconds` como uma thread do sistema (as interrupções, os
/// DPCs, os timers e os work items dos drivers rodam durante a espera).
fn delay(milliseconds: i64) {
    let interval = guest::alloc_bytes(LargeInteger::SIZE);
    // SAFETY: LARGE_INTEGER recém-alocado (tempo relativo).
    unsafe { LargeInteger::at(interval) }.quad_part.set(-milliseconds * 10_000);
    let _ = crate::ntos::ke::timer::delay_execution_thread(interval, 0, false);
    guest::free_bytes(interval);
}

/// O nó iniciado com o serviço dado.
fn started(service: &str) -> Option<devnode::DeviceNode> {
    devnode::all().into_iter().find(|node| node.state == devnode::State::Started && node.service.as_deref().is_some_and(|name| name.eq_ignore_ascii_case(service)))
}

/// O hub raiz iniciado com o usbhub3 e um dispositivo relatado por ele.
fn hub_with_device() -> Option<(String, String)> {
    let hub = devnode::all().into_iter().find(|node| node.state == devnode::State::Started && node.device_id.eq_ignore_ascii_case("USB\\ROOT_HUB30") && node.service.as_deref().is_some_and(|name| name.eq_ignore_ascii_case("USBHUB3")))?;
    let child = devnode::all().into_iter().find(|node| node.parent == hub.pdo)?;
    Some((hub.instance_path, child.instance_path))
}

/// O dispositivo de classe do teclado USB: o FDO do kbdclass no topo da
/// pilha do kbdhid (`\Device\KeyboardClassN`).
static KEYBOARD_CLASS: SpinLock<Option<String>> = SpinLock::new(None);
static KEY_REPORTED: AtomicBool = AtomicBool::new(false);

/// O nome do FDO do kbdclass sobre a coleção de teclado do kbdhid.
fn keyboard_class_of(keyboard: &devnode::DeviceNode) -> Option<String> {
    let top = crate::ntos::ob::objects::device::top(keyboard.pdo);
    let (node, _) = io_manager::devices().into_iter().find(|(_, entry)| entry.native_device == top)?;
    object_manager::path_of(node)
}

/// O teclado do sistema neste boot: com a pilha USB, o QEMU entrega as
/// teclas ao teclado USB (o usb-kbd recebe a entrada da máquina), e o
/// serviço de teclado lê do kbdclass sobre o kbdhid.
pub fn keyboard_class_device() -> Option<String> {
    KEYBOARD_CLASS.lock().clone()
}

/// Uma tecla lida do kbdclass do teclado USB pelo serviço de teclado.
pub fn key_received(make_code: u16, flags: u16) {
    let device = keyboard_class_device().unwrap_or_default();
    debug_print!("[usb] tecla do kbdhid em {}: MakeCode {:#x} flags {:#x}", device, make_code, flags);
    // 'a' (scancode 0x1E), a tecla que o teste manda pelo monitor do QEMU.
    if make_code == 0x1E && flags & 1 == 0 && !KEY_REPORTED.swap(true, Ordering::AcqRel) {
        debug_print!("USB_KEY_OK");
    }
}

fn log_tree() {
    for (path, state, problem, service) in pnp::tree::summary() {
        debug_print!("[usb] devnode {} estado {:?} problema {:#x} servico {}", path, state, problem, service.as_deref().unwrap_or("-"));
    }
}

/// Prazo do contexto de boot pela thread da pilha (a enumeração e a
/// espera pelos marcos, com folga).
const THREAD_TIMEOUT_MS: i64 = SETTLE_MS as i64 + 120_000;

/// Sobe a pilha e confere os marcos. Só com `--usb`.
///
/// Como as ações do PnP manager do NT, que rodam numa worker thread do
/// sistema, o processamento da árvore (os AddDevice e os START_DEVICE, que
/// esperam o hardware e os work items dos drivers) roda numa thread de
/// sistema; o contexto de boot espera o fim dela, girando as interrupções,
/// os DPCs, os work items e o escalonador. Um work item que o contexto de
/// boot roda durante essa espera não fica empilhado sobre um START que
/// segura as travas do framework do driver (o KMDF guarda a máquina de
/// estados PnP do dispositivo durante o START inteiro).
pub fn initialize() {
    debug_print!("[usb] pilha USB 3 e HID real pelo PnP");
    if let Err(error) = crate::drivers::bus::device_tree::prepare() {
        debug_print!("[usb] raiz do PnP: {}", error);
        return;
    }
    let done = guest::alloc_bytes(crate::ntos::inc::types::Kevent::SIZE);
    crate::ntos::ke::dispatcher::initialize_event(done, 0, false);
    let entry: extern "win64" fn(u64) = stack_thread;
    let started = crate::ntos::mm::kernel_address::image_address(entry as usize as u64).ok().and_then(|start| crate::ntos::ps::kernel_threads::create_system_thread(0, start, done, 0x1F_FFFF, 0, None).ok());
    match started {
        Some(handle) => {
            let _ = object_manager::close(handle as u32);
            let timeout = guest::alloc_bytes(LargeInteger::SIZE);
            // SAFETY: LARGE_INTEGER recém-alocado (tempo relativo).
            unsafe { LargeInteger::at(timeout) }.quad_part.set(-THREAD_TIMEOUT_MS * 10_000);
            if crate::ntos::ke::dispatcher::wait_for_single_object(done, timeout, 0, false) != 0 {
                debug_print!("[usb] a thread da pilha nao terminou em {} ms", THREAD_TIMEOUT_MS);
            }
            guest::free_bytes(timeout);
        }
        None => {
            debug_print!("[usb] sem thread de sistema; a pilha sobe no contexto de boot");
            run();
        }
    }
}

/// A thread da pilha: `run` e o sinal para o contexto de boot.
extern "win64" fn stack_thread(done: u64) {
    run();
    crate::ntos::ke::dispatcher::set_event(done);
}

/// A árvore do PnP, a espera pela enumeração das portas e os marcos.
fn run() {
    crate::ntos::init::exports::set_api_trace(crate::ntos::init::boot_config::trace_driver_api());
    if let Err(error) = pnp::tree::process() {
        debug_print!("[usb] arvore do PnP: {}", error);
    }
    let (mut hub_ok, mut hid_ok) = (false, false);
    let mut waited = 0;
    while waited < SETTLE_MS && !(hub_ok && hid_ok) {
        delay(STEP_MS);
        waited += STEP_MS as u64;
        if let Err(error) = pnp::tree::process_pending() {
            debug_print!("[usb] arvore do PnP: {}", error);
        }
        if !hub_ok {
            if let Some((hub, device)) = hub_with_device() {
                debug_print!("[usb] {}: hub raiz do usbhub3.sys com o dispositivo {} nas portas", hub, device);
                debug_print!("USB_HUB_OK");
                hub_ok = true;
            }
        }
        if !hid_ok {
            if let (Some(keyboard), Some(mouse)) = (started("kbdhid"), started("mouhid")) {
                let class = keyboard_class_of(&keyboard);
                debug_print!("[usb] {}: kbdhid.sys iniciado (kbdclass em {}); {}: mouhid.sys iniciado", keyboard.instance_path, class.as_deref().unwrap_or("?"), mouse.instance_path);
                debug_print!("USB_HID_OK");
                *KEYBOARD_CLASS.lock() = class;
                hid_ok = true;
            }
        }
    }
    crate::ntos::init::exports::set_api_trace(false);
    log_tree();
    if !(hub_ok && hid_ok) {
        // Os nomes dos marcos não aparecem aqui: o teste os procura na serial.
        let missing: Vec<&str> = [(!hub_ok).then_some("o hub raiz com um dispositivo"), (!hid_ok).then_some("o kbdhid e o mouhid iniciados")].into_iter().flatten().collect();
        debug_print!("[usb] {} ms sem {}", waited, missing.join(" nem "));
    }
}
