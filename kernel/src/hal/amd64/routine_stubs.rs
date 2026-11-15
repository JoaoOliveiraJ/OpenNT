//! Rotinas do kernel entregues aos drivers por ponteiro.
//!
//! No NT, as interfaces que um barramento devolve no IRP_MN_QUERY_INTERFACE
//! (BUS_INTERFACE_STANDARD, PCI_BUS_INTERFACE_STANDARD) e a tabela
//! DMA_OPERATIONS do adaptador que a HAL cria são ponteiros para funções do
//! próprio ntoskrnl/pci.sys. Aqui cada rotina tem um stub nativo de dez
//! bytes na imagem do kernel (id privado `BASE + slot`, no formato dos
//! trampolins públicos) que cai no despachante comum; o despacho vai para a
//! função do assunto pela tabela `ROUTINES`. Os ids nunca entram na EAT.

use crate::ntos::init::exports::Call;
use crate::ntos::mm::kernel_address;
use crate::rtl::KernelError;

/// Primeiro id privado das rotinas por ponteiro.
pub const BASE: u64 = 0x8000_0400;
/// Stubs reservados na imagem.
pub const CAPACITY: usize = 64;

core::arch::global_asm!(
    r#"
.pushsection .text.win32_private, "ax", @progbits
.balign 16
.global opennt_kernel_routine_stubs
opennt_kernel_routine_stubs:
.set opennt_routine_slot, 0
.rept 64
    .byte 0xB8
    .long 0x80000400 + opennt_routine_slot
    .byte 0xE9
    .long opennt_win32_common - . - 4
    .set opennt_routine_slot, opennt_routine_slot + 1
.endr
.popsection
"#
);

extern "C" {
    static opennt_kernel_routine_stubs: u8;
}

type Handler = fn(&Call) -> Result<u64, KernelError>;

/// Rotina por ponteiro: nome (o da rotina do NT) e o adaptador.
pub struct Routine {
    pub name: &'static str,
    pub handler: Handler,
}

/// Tabela das rotinas, na ordem dos slots. Cada assunto expõe as suas
/// (`hal::dma`, `drivers::bus::pci_interface`) e só entra aqui pela lista.
fn routines() -> &'static [&'static [Routine]] {
    &[crate::hal::dma::ROUTINES, crate::drivers::bus::pci_interface::ROUTINES, crate::hal::system_information::ROUTINES]
}

/// Slot global da rotina `name` (busca linear: chamada na montagem das tabelas).
fn slot_of(name: &str) -> Option<usize> {
    let mut slot = 0;
    for group in routines() {
        for routine in group.iter() {
            if routine.name == name {
                return Some(slot);
            }
            slot += 1;
        }
    }
    None
}

fn routine(slot: usize) -> Option<&'static Routine> {
    let mut base = 0;
    for group in routines() {
        if slot < base + group.len() {
            return group.get(slot - base);
        }
        base += group.len();
    }
    None
}

/// Endereço nativo (na imagem do kernel) da rotina `name`.
pub fn address(name: &str) -> Result<u64, KernelError> {
    let slot = slot_of(name).ok_or_else(|| KernelError::new(alloc::format!("rotina por ponteiro sem slot: {name}")))?;
    assert!(slot < CAPACITY, "rotinas por ponteiro excedem os {CAPACITY} stubs");
    let stubs = core::ptr::addr_of!(opennt_kernel_routine_stubs) as u64;
    kernel_address::image_address(stubs + slot as u64 * 10)
}

/// O id pertence a esta faixa.
pub fn owns(id: u64) -> bool {
    (BASE..BASE + CAPACITY as u64).contains(&id) && routine((id - BASE) as usize).is_some()
}

/// Nome da rotina do id.
pub fn name(id: u64) -> Option<&'static str> {
    if !owns(id) {
        return None;
    }
    routine((id - BASE) as usize).map(|routine| routine.name)
}

/// Despacho de uma chamada nativa a uma rotina por ponteiro.
pub fn dispatch(id: u64, call: &Call) -> Result<u64, KernelError> {
    let routine = routine((id - BASE) as usize).ok_or_else(|| KernelError::new("rotina por ponteiro desconhecida"))?;
    (routine.handler)(call)
}
