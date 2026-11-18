//! Inicialização da pilha PS/2 usada pelo shell e pelo teste de teclado.
//!
//! Carrega o kbdclass.sys e o i8042prt.sys reais, monta pelo PnP as pilhas
//! dos PDOs da placa-mãe (PNP0303 e PNP0F13, com os filtros de classe
//! kbdclass/mouclass) e, para o shell e o teste, abre a porta do teclado: o
//! CREATE do i8042prt habilita a entrega dos scancodes. O handle fica aberto
//! enquanto o serviço de teclado estiver em uso (o close dispararia o
//! disable da porta).
//!
//! No boot do processo inicial real (`--initial-process=smss`) a pilha só é
//! montada ([`start`]): ninguém no kernel abre a porta nem a classe. Como no
//! Windows, quem habilita a porta é o kbdclass, quando o RIT do win32k abre o
//! dispositivo de classe (o KeyboardClassCreate repassa o CREATE ao port
//! driver no KbdEnableDisablePort).

use alloc::format;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::drivers::bus::motherboard;
use crate::ntos::io::{io_manager, pnp};
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::io::lifecycle::{self, DriverOptions};

/// `None` = ainda não montada; `Some(pilha)` = resultado guardado.
static KEYBOARD_STACK: SpinLock<Option<Option<NodeId>>> = SpinLock::new(None);
/// A porta do teclado já foi aberta pelo kernel ([`initialize`]).
static PORT_OPENED: AtomicBool = AtomicBool::new(false);

/// Os binários do teclado vieram no bundle do build?
pub fn binaries_present() -> bool {
    crate::hal::bundle::read("apps/kbdclass.sys").is_some() && crate::hal::bundle::read("apps/i8042prt.sys").is_some()
}

/// Monta as pilhas do teclado e do mouse PS/2 e devolve o FDO da pilha do
/// teclado iniciada (`None` se o PnP não a iniciou), sem abrir a porta.
/// Idempotente.
pub fn start() -> Result<Option<NodeId>, KernelError> {
    if let Some(stack) = *KEYBOARD_STACK.lock() {
        return Ok(stack);
    }
    let stack = if crate::drivers::bus::acpi_stack::enabled() { acpi_keyboard_stack() } else { motherboard_keyboard_stack()? };
    *KEYBOARD_STACK.lock() = Some(stack);
    Ok(stack)
}

/// [`start`] e a abertura da porta do teclado (o shell e o teste de
/// teclado). Idempotente.
pub fn initialize() -> Result<Option<NodeId>, KernelError> {
    let stack = start()?;
    if let Some(fdo) = stack {
        if !PORT_OPENED.swap(true, Ordering::AcqRel) {
            if let Err(error) = open_port(fdo) {
                PORT_OPENED.store(false, Ordering::Release);
                return Err(error);
            }
        }
    }
    Ok(stack)
}

/// Sem a raiz ACPI: carrega os drivers e monta as pilhas dos PDOs da
/// placa-mãe pelo orquestrador do PnP.
fn motherboard_keyboard_stack() -> Result<Option<NodeId>, KernelError> {
    let _ = lifecycle::load_driver("/kbdclass.sys", &DriverOptions::default());
    let _ = lifecycle::load_driver("/i8042prt.sys", &DriverOptions::default());
    if object_manager::lookup("\\Driver\\kbdclass").is_none() || object_manager::lookup("\\Driver\\i8042prt").is_none() {
        return Err(KernelError::new("drivers de teclado nao publicaram seus objetos"));
    }
    // Os PDOs da placa-mãe são criados uma vez; quem chega depois reusa.
    let pdos = if motherboard::created().is_empty() { motherboard::enumerate()? } else { motherboard::created() };
    // Teclado e mouse dividem o controlador 8042: os dois recebem o
    // AddDevice antes do primeiro START, como no PnP manager do NT.
    let nodes: alloc::vec::Vec<NodeId> = pdos.iter().map(|entry| entry.node).collect();
    let stacks = pnp::enumerate_sibling_stacks(&nodes);
    let mut keyboard_stack = None;
    for (entry, stack) in pdos.iter().zip(stacks) {
        if entry.descriptor.name == "I8042Kbd" {
            if let Some(fdo) = stack.filter(|&fdo| io_manager::device(fdo).is_some_and(|device| device.pnp_started)) {
                keyboard_stack = Some(fdo);
            }
        }
    }
    Ok(keyboard_stack)
}

/// Abre a porta do teclado (o CREATE do i8042prt habilita os scancodes).
fn open_port(fdo: NodeId) -> Result<(), KernelError> {
    let path = object_manager::path_of(fdo).unwrap_or_default();
    let opened = io_manager::open_device(&path, false)?;
    if opened.status != 0 {
        return Err(KernelError::new(format!("CREATE na porta i8042 falhou: 0x{:x}", opened.status as u32)));
    }
    Ok(())
}

/// Com a raiz ACPI (`--pnp-root=acpi`) a pilha do teclado é a que o PnP
/// montou no ACPI\PNP0303 que o filtro do acpi.sys relata sob a ponte
/// PCI-ISA (o i8042prt pelo keyboard.inf, com o kbdclass da classe): o FDO
/// do i8042prt do nó iniciado.
fn acpi_keyboard_stack() -> Option<NodeId> {
    use crate::ntos::io::pnp::devnode;
    let node = devnode::all().into_iter().find(|node| node.device_id.eq_ignore_ascii_case("ACPI\\PNP0303") && node.state == devnode::State::Started && node.service.as_deref() == Some("i8042prt"))?;
    io_manager::devices().into_iter().find(|(_, entry)| entry.native_device == node.function_device && node.function_device != 0).map(|(device, _)| device)
}
