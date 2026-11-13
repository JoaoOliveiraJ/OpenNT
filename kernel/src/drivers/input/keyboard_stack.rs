//! Inicialização da pilha PS/2 usada pelo shell e pelo teste de teclado.
//!
//! Carrega o kbdclass.sys e o i8042prt.sys reais, monta pelo PnP as pilhas
//! dos PDOs da placa-mãe (PNP0303 e PNP0F13, com os filtros de classe
//! kbdclass/mouclass) e abre a porta do teclado: o CREATE do i8042prt
//! habilita a entrega dos scancodes. O handle fica aberto enquanto o serviço
//! de teclado estiver em uso (o close dispararia o disable da porta).

use alloc::format;

use crate::drivers::bus::motherboard;
use crate::ntos::io::{io_manager, pnp};
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::io::lifecycle::{self, DriverOptions};

/// `None` = ainda não inicializada; `Some(pilha)` = resultado guardado.
static KEYBOARD_STACK: SpinLock<Option<Option<NodeId>>> = SpinLock::new(None);

/// Os binários do teclado vieram no bundle do build?
pub fn binaries_present() -> bool {
    crate::hal::bundle::read("apps/kbdclass.sys").is_some() && crate::hal::bundle::read("apps/i8042prt.sys").is_some()
}

/// Devolve o FDO da pilha do teclado iniciada (`None` se o PnP não a
/// iniciou). Idempotente, como o original.
pub fn initialize() -> Result<Option<NodeId>, KernelError> {
    if let Some(stack) = *KEYBOARD_STACK.lock() {
        return Ok(stack);
    }
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
    if let Some(fdo) = keyboard_stack {
        let path = object_manager::path_of(fdo).unwrap_or_default();
        let opened = io_manager::open_device(&path, false)?;
        if opened.status != 0 {
            return Err(KernelError::new(format!("CREATE na porta i8042 falhou: 0x{:x}", opened.status as u32)));
        }
    }
    *KEYBOARD_STACK.lock() = Some(keyboard_stack);
    Ok(keyboard_stack)
}
