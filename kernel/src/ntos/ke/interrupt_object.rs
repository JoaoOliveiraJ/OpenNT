//! Objetos KINTERRUPT ligados por vetor ao despacho do runtime.
//!
//! Caminho legado com endereços físicos baixos. A sincronização usa leitura
//! e escrita separadas da palavra de lock, como no original (não estabelece
//! exclusão atômica entre várias CPUs).

use alloc::collections::BTreeMap;

use super::{irql, spin_lock};
use crate::hal::amd64::native_call;
use crate::hal::{physical, port};
use crate::nano::interrupts;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::kinterrupt as layout;

/// Com a flag ativa, o stub de IRQ1 não lê a porta 0x60 antes da ISR nativa.
const NATIVE_KEYBOARD_INTERRUPT_FLAG: u64 = 0x81510;
/// Tabela de níveis consultada pelo caminho nativo de interrupção imediata.
const INTERRUPT_LEVEL_TABLE: u64 = 0x81600;

static CHAINS: SpinLock<BTreeMap<u32, u64>> = SpinLock::new(BTreeMap::new());

/// Vetores do PIC legado: drena estado residual do IDE, envia EOI e libera a
/// máscara da linha.
fn clear_and_unmask_controller(vector: u32) {
    let Some(irq) = vector.checked_sub(0x20).filter(|&irq| irq <= 15) else { return };
    if irq == 14 {
        drain_legacy_disk_interrupt(0x1F0, 0x1F7);
    }
    if irq == 15 {
        drain_legacy_disk_interrupt(0x170, 0x177);
    }
    port::write8(0x20, 0x20);
    if irq >= 8 {
        port::write8(0xA0, 0x20);
        port::write8(0xA1, port::read8(0xA1) & !(1u8 << (irq - 8)));
    } else {
        port::write8(0x21, port::read8(0x21) & !(1u8 << irq));
    }
}

/// Reconhece a interrupção antiga; com DRQ ativo consome 256 palavras.
fn drain_legacy_disk_interrupt(data_port: u16, status_port: u16) {
    if port::read8(status_port) & 0x08 != 0 {
        for _ in 0..256 {
            port::read16(data_port);
        }
    }
}

/// O bit 0 do KSPIN_LOCK trocado atomicamente: dois processadores nunca
/// saem com o mesmo lock.
fn acquire_lock(lock: u64) {
    loop {
        let value = physical::read64(lock);
        if value & 1 == 0 && physical::compare_exchange64(lock, value, value | 1) == value {
            return;
        }
        core::hint::spin_loop();
    }
}

fn release_lock(lock: u64) {
    physical::write64(lock, 0);
}

/// Percorre os objetos do vetor chamando as ISRs nativas. Para quando uma
/// ISR trata a interrupção e Mode vale zero (latched).
fn dispatch_chain(vector: u8, _count: u32) {
    let mut pointer = CHAINS.lock().get(&(vector as u32)).copied().unwrap_or(0);
    while pointer != 0 {
        let routine = physical::read64(pointer + layout::SERVICE_ROUTINE);
        let context = physical::read64(pointer + layout::SERVICE_CONTEXT);
        let mode = physical::read32(pointer + layout::MODE);
        // BOOLEAN de retorno: só AL é significativo.
        let handled = native_call::call(routine, &[pointer, context]) & 0xFF != 0;
        if handled && mode == 0 {
            return;
        }
        pointer = physical::read64(pointer + layout::LIST_ENTRY);
    }
}

/// IoConnectInterrupt: aloca corpo e lock opcional, publica campos e liga o
/// objeto à cabeça da cadeia. Afinidade e FloatingSave ainda não se aplicam.
#[allow(clippy::too_many_arguments)]
pub fn io_connect_interrupt(
    output: u64,
    service_routine: u64,
    service_context: u64,
    spin_lock: u64,
    vector: u32,
    level: u8,
    synchronize_level: u8,
    mode: u32,
    share_vector: bool,
) -> Result<u32, KernelError> {
    let object = guest::alloc_bytes(layout::SIZE);
    // Lock do chamador reutilizado; senão, oito bytes para o lock interno.
    let actual_lock = if spin_lock != 0 { spin_lock } else { guest::alloc_bytes(8) };
    if object == 0 || actual_lock == 0 {
        return Err(KernelError::new("KINTERRUPT allocation failed"));
    }
    if spin_lock == 0 {
        physical::write32(actual_lock, 0);
    }
    physical::write32(object + layout::TYPE, layout::TYPE_INTERRUPT as u32 | (layout::SIZE as u32) << 16);
    physical::write64(object + layout::LIST_ENTRY, 0);
    physical::write64(object + layout::LIST_ENTRY + 8, 0);
    physical::write64(object + layout::SERVICE_ROUTINE, service_routine);
    physical::write64(object + layout::SERVICE_CONTEXT, service_context);
    physical::write64(object + layout::SPIN_LOCK, spin_lock & 0xFFFF_FFFF);
    physical::write64(object + layout::ACTUAL_LOCK, actual_lock);
    physical::write32(object + layout::VECTOR, vector);
    physical::write8(object + layout::IRQL, level);
    physical::write8(object + layout::SYNCHRONIZE_IRQL, synchronize_level);
    physical::write8(object + layout::CONNECTED, 1);
    physical::write32(object + layout::MODE, mode);
    physical::write8(object + layout::SHARE_VECTOR, share_vector as u8);

    // Insere na cabeça da cadeia antes de habilitar a linha do controlador.
    let previous_head = CHAINS.lock().insert(vector, object).unwrap_or(0);
    physical::write64(object + layout::LIST_ENTRY, previous_head);
    physical::write32(INTERRUPT_LEVEL_TABLE + vector as u64 * 4, level as u32);
    clear_and_unmask_controller(vector);
    if previous_head == 0 {
        interrupts::register_irq_handler(vector as u8, dispatch_chain);
        if vector == interrupts::VECTOR_KEYBOARD as u32 {
            physical::write8(NATIVE_KEYBOARD_INTERRUPT_FLAG, 1);
        }
        debug_print!("[intobj] vetor {:#x} conectado a ISR nativa {:#x}", vector, service_routine as u32);
    }
    guest::write32(output, object as u32);
    guest::write32(output + 4, 0);
    Ok(0)
}

/// IoDisconnectInterrupt. O lock interno alocado separadamente não é
/// recuperado (como no original).
pub fn io_disconnect_interrupt(object: u64) {
    let vector = physical::read32(object + layout::VECTOR);
    let mut previous_link = 0;
    let mut pointer = CHAINS.lock().get(&vector).copied().unwrap_or(0);
    while pointer != 0 {
        let next = physical::read64(pointer + layout::LIST_ENTRY);
        if pointer == object {
            {
                let mut chains = CHAINS.lock();
                if previous_link != 0 {
                    physical::write64(previous_link + layout::LIST_ENTRY, next);
                } else if next != 0 {
                    chains.insert(vector, next);
                } else {
                    chains.remove(&vector);
                }
            }
            physical::write8(object + layout::CONNECTED, 0);
            guest::free_bytes(object);
            if next == 0 && previous_link == 0 && !CHAINS.lock().contains_key(&vector) {
                physical::write32(INTERRUPT_LEVEL_TABLE + vector as u64 * 4, 0);
                if vector == interrupts::VECTOR_KEYBOARD as u32 {
                    physical::write8(NATIVE_KEYBOARD_INTERRUPT_FLAG, 0);
                }
            }
            return;
        }
        previous_link = pointer;
        pointer = next;
    }
}

/// KeSynchronizeExecution: eleva ao nível do objeto, pega o ActualLock,
/// chama a rotina e restaura lock e IRQL.
pub fn ke_synchronize_execution(object: u64, routine: u64, context: u64) -> u64 {
    let lock = physical::read64(object + layout::ACTUAL_LOCK);
    let synchronize_level = physical::read8(object + layout::SYNCHRONIZE_IRQL);
    let previous = irql::get_irql();
    irql::raise_irql(synchronize_level);
    acquire_lock(lock);
    let result = native_call::call(routine, &[context, 0]);
    release_lock(lock);
    irql::lower_irql(previous as u64);
    result
}

/// KeAcquireInterruptSpinLock: sobe ao SynchronizeIrql do objeto (nunca
/// desce), pega o lock apontado por ActualLock e devolve o IRQL anterior.
pub fn acquire_interrupt_spin_lock(object: u64) -> u8 {
    let lock = guest::read64(object + layout::ACTUAL_LOCK);
    let previous = irql::raise_at_least(guest::read8(object + layout::SYNCHRONIZE_IRQL));
    spin_lock::acquire_at_dpc_level(lock);
    previous
}

/// KeReleaseInterruptSpinLock: solta o ActualLock e volta ao IRQL dado.
pub fn release_interrupt_spin_lock(object: u64, old_irql: u64) {
    spin_lock::release(guest::read64(object + layout::ACTUAL_LOCK), old_irql);
}

pub fn is_vector_connected(vector: u32) -> bool {
    CHAINS.lock().contains_key(&vector)
}
