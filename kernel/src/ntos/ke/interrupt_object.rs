//! Objetos KINTERRUPT ligados por vetor ao despacho do runtime.
//!
//! O corpo do objeto é do OpenNT ([`InterruptObject`]): os drivers tratam o
//! PKINTERRUPT como opaco e só o devolvem aos serviços do kernel. O
//! ActualLock é um KSPIN_LOCK comum (bit 0 trocado atomicamente).

use alloc::collections::BTreeMap;

use super::{irql, spin_lock};
use crate::hal::amd64::native_call;
use crate::hal::{physical, port};
use crate::nano::interrupts;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::{KernelError, SpinLock};

/// Corpo do objeto de interrupção (layout do OpenNT, 0x100 bytes; os drivers
/// não o enxergam). A cadeia de um vetor usa o primeiro ponteiro da antiga
/// InterruptListEntry como "próximo objeto".
#[repr(C)]
pub struct InterruptObject {
    /// InterruptObject (0x16).
    pub type_: Field<i16>,
    pub size: Field<i16>,
    _pad_04: Reserved<4>,
    /// Próximo objeto da cadeia do vetor (0 no fim).
    pub chain_next: Field<u64>,
    pub chain_reserved: Field<u64>,
    pub service_routine: Field<u64>,
    pub service_context: Field<u64>,
    /// O KSPIN_LOCK passado pelo driver (0 = lock interno).
    pub spin_lock: Field<u64>,
    pub tick_count: Field<u32>,
    _pad_34: Reserved<4>,
    /// O KSPIN_LOCK efetivo (o do driver ou o interno).
    pub actual_lock: Field<u64>,
    pub vector: Field<u32>,
    pub irql: Field<u8>,
    pub synchronize_irql: Field<u8>,
    pub floating_save: Field<u8>,
    pub connected: Field<u8>,
    /// Processador do objeto (lido por `io::interrupt`).
    pub number: Field<u16>,
    pub share_vector: Field<u8>,
    _pad_4b: Reserved<1>,
    /// KINTERRUPT_MODE (0 = LevelSensitive, 1 = Latched).
    pub mode: Field<u32>,
    pub share_disposition: Field<u32>,
    _pad_54: Reserved<4>,
    pub dispatch_address: Field<u64>,
    _pad_60: Reserved<0xA0>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for InterruptObject {}

const _: () = {
    assert!(core::mem::size_of::<InterruptObject>() == 0x100);
    assert!(core::mem::offset_of!(InterruptObject, chain_next) == 0x08);
    assert!(core::mem::offset_of!(InterruptObject, service_routine) == 0x18);
    assert!(core::mem::offset_of!(InterruptObject, service_context) == 0x20);
    assert!(core::mem::offset_of!(InterruptObject, spin_lock) == 0x28);
    assert!(core::mem::offset_of!(InterruptObject, actual_lock) == 0x38);
    assert!(core::mem::offset_of!(InterruptObject, vector) == 0x40);
    assert!(core::mem::offset_of!(InterruptObject, synchronize_irql) == 0x45);
    assert!(core::mem::offset_of!(InterruptObject, number) == 0x48);
    assert!(core::mem::offset_of!(InterruptObject, mode) == 0x4C);
    assert!(core::mem::offset_of!(InterruptObject, dispatch_address) == 0x58);
};

/// KOBJECTS InterruptObject.
const INTERRUPT_OBJECT_TYPE: i16 = 0x16;

fn interrupt_object(object: u64) -> &'static InterruptObject {
    // SAFETY: objetos criados por `io_connect_interrupt` (pool do kernel).
    unsafe { InterruptObject::at(object) }
}

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

/// Interrupções de dispositivo durante uma espera. No NT a IRQ interrompe
/// qualquer código abaixo do IRQL do dispositivo, inclusive uma thread
/// parada no KeWaitForSingleObject ou no KeDelayExecutionThread: um driver
/// que espera o próprio hardware (o i8042prt segura o controlador até o
/// mouse responder ao reset pela IRQ12) recebe a ISR enquanto espera. Aqui
/// as ISRs rodam quando as IRQs registradas são despachadas, e as esperas
/// abaixo de DISPATCH_LEVEL chamam esta rotina a cada volta.
pub fn service_during_wait() {
    if super::irql::get_irql() < super::irql::DISPATCH_LEVEL {
        interrupts::dispatch_pending_devices();
    }
}

/// Percorre os objetos do vetor chamando as ISRs nativas. Para quando uma
/// ISR trata a interrupção e Mode vale zero (latched).
fn dispatch_chain(vector: u8, _count: u32) {
    let mut pointer = CHAINS.lock().get(&(vector as u32)).copied().unwrap_or(0);
    while pointer != 0 {
        let object = interrupt_object(pointer);
        let routine = object.service_routine.get();
        let context = object.service_context.get();
        let mode = object.mode.get();
        // BOOLEAN de retorno: só AL é significativo.
        let handled = native_call::call(routine, &[pointer, context]) & 0xFF != 0;
        if handled && mode == 0 {
            return;
        }
        pointer = object.chain_next.get();
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
    let object = guest::alloc_bytes(InterruptObject::SIZE);
    // Lock do chamador reutilizado; senão, oito bytes para o lock interno.
    let actual_lock = if spin_lock != 0 { spin_lock } else { guest::alloc_bytes(8) };
    if object == 0 || actual_lock == 0 {
        return Err(KernelError::new("KINTERRUPT allocation failed"));
    }
    if spin_lock == 0 {
        spin_lock::initialize(actual_lock);
    }
    let body = interrupt_object(object);
    body.type_.set(INTERRUPT_OBJECT_TYPE);
    body.size.set(InterruptObject::SIZE as i16);
    body.chain_next.set(0);
    body.chain_reserved.set(0);
    body.service_routine.set(service_routine);
    body.service_context.set(service_context);
    body.spin_lock.set(spin_lock);
    body.actual_lock.set(actual_lock);
    body.vector.set(vector);
    body.irql.set(level);
    body.synchronize_irql.set(synchronize_level);
    body.connected.set(1);
    body.mode.set(mode);
    body.share_vector.set(share_vector as u8);

    // Insere na cabeça da cadeia antes de habilitar a linha do controlador.
    let previous_head = CHAINS.lock().insert(vector, object).unwrap_or(0);
    body.chain_next.set(previous_head);
    physical::write32(INTERRUPT_LEVEL_TABLE + vector as u64 * 4, level as u32);
    clear_and_unmask_controller(vector);
    if previous_head == 0 {
        interrupts::register_irq_handler(vector as u8, dispatch_chain);
        if vector == interrupts::VECTOR_KEYBOARD as u32 {
            physical::write8(NATIVE_KEYBOARD_INTERRUPT_FLAG, 1);
        }
        debug_print!("[intobj] vetor {:#x} conectado a ISR nativa {:#x}", vector, service_routine as u32);
    }
    // PKINTERRUPT* InterruptObject: um store do ponteiro inteiro.
    // SAFETY: parâmetro de saída do driver.
    unsafe { Field::<u64>::at(output) }.set(object);
    Ok(0)
}

/// IoDisconnectInterrupt. O lock interno alocado separadamente não é
/// recuperado.
pub fn io_disconnect_interrupt(object: u64) {
    let vector = interrupt_object(object).vector.get();
    let mut previous_link = 0;
    let mut pointer = CHAINS.lock().get(&vector).copied().unwrap_or(0);
    while pointer != 0 {
        let next = interrupt_object(pointer).chain_next.get();
        if pointer == object {
            {
                let mut chains = CHAINS.lock();
                if previous_link != 0 {
                    interrupt_object(previous_link).chain_next.set(next);
                } else if next != 0 {
                    chains.insert(vector, next);
                } else {
                    chains.remove(&vector);
                }
            }
            interrupt_object(object).connected.set(0);
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
    let body = interrupt_object(object);
    let lock = body.actual_lock.get();
    let synchronize_level = body.synchronize_irql.get();
    let previous = irql::get_irql();
    irql::raise_irql(synchronize_level);
    spin_lock::acquire_at_dpc_level(lock);
    let result = native_call::call(routine, &[context, 0]);
    spin_lock::release_from_dpc_level(lock);
    irql::lower_irql(previous as u64);
    result
}

/// KeAcquireInterruptSpinLock: sobe ao SynchronizeIrql do objeto (nunca
/// desce), pega o lock apontado por ActualLock e devolve o IRQL anterior.
pub fn acquire_interrupt_spin_lock(object: u64) -> u8 {
    let body = interrupt_object(object);
    let lock = body.actual_lock.get();
    let previous = irql::raise_at_least(body.synchronize_irql.get());
    spin_lock::acquire_at_dpc_level(lock);
    previous
}

/// KeReleaseInterruptSpinLock: solta o ActualLock e volta ao IRQL dado.
pub fn release_interrupt_spin_lock(object: u64, old_irql: u64) {
    spin_lock::release(interrupt_object(object).actual_lock.get(), old_irql);
}

pub fn is_vector_connected(vector: u32) -> bool {
    CHAINS.lock().contains_key(&vector)
}

// ---- IoReportInterruptActive / IoReportInterruptInactive ---------------------
//
// ntoskrnl 19041: IoReportInterruptActive rva 0x38be20, IoReportInterruptInactive
// rva 0x38c790 -> IopUnmaskInterrupt/IopMaskInterrupt -> KeUnmaskInterrupt /
// KeMaskInterrupt. O parâmetro é IO_REPORT_INTERRUPT_ACTIVE_STATE_PARAMETERS
// { ULONG Version; union ConnectionContext } com a versão do IoConnectInterruptEx:
// 1/4 (FULLY_SPECIFIED[_GROUP]) e 2 (LINE_BASED) trazem o objeto de interrupção,
// 3 (MESSAGE_BASED) a IO_INTERRUPT_MESSAGE_INFO (MessageCount entradas, cada uma
// com InterruptObject). Versão inválida é KeBugCheckEx(PNP_DETECTED_FATAL_ERROR
// 0xCA, 0xC, Version, 0, 0).
//
// No OpenNT o contexto de 1/2/4 é o próprio objeto da cadeia do vetor (o
// IoConnectInterruptEx grava o `InterruptObject`). Mascarar é o que o
// KeMaskInterrupt faz no controlador: a linha do PIC legado fica mascarada
// enquanto todos os objetos conectados ao vetor estiverem inativos, e volta a
// ser entregue quando um deles é reportado ativo.

static INACTIVE_INTERRUPTS: SpinLock<alloc::collections::BTreeSet<u64>> = SpinLock::new(alloc::collections::BTreeSet::new());

const CONNECT_FULLY_SPECIFIED: u32 = 1;
const CONNECT_LINE_BASED: u32 = 2;
const CONNECT_MESSAGE_BASED: u32 = 3;
const CONNECT_FULLY_SPECIFIED_GROUP: u32 = 4;

/// Máscara da linha do PIC legado de um vetor 0x20..0x2F (portas de I/O).
fn set_legacy_line_masked(vector: u32, masked: bool) {
    let Some(irq) = vector.checked_sub(0x20).filter(|&irq| irq <= 15) else { return };
    let (data_port, bit) = if irq >= 8 { (0xA1u16, 1u8 << (irq - 8)) } else { (0x21u16, 1u8 << irq) };
    let current = port::read8(data_port);
    port::write8(data_port, if masked { current | bit } else { current & !bit });
}

/// Estado ativo/inativo de um objeto de interrupção e a máscara resultante da linha.
fn report_object_active(object: u64, active: bool) {
    if object == 0 {
        return;
    }
    let vector = interrupt_object(object).vector.get();
    let all_inactive = {
        let mut inactive = INACTIVE_INTERRUPTS.lock();
        if active {
            inactive.remove(&object);
        } else {
            inactive.insert(object);
        }
        // Linha sem objetos conectados: o controlador não é tocado.
        let mut pointer = CHAINS.lock().get(&vector).copied().unwrap_or(0);
        if pointer == 0 {
            return;
        }
        let mut all = true;
        while pointer != 0 {
            if !inactive.contains(&pointer) {
                all = false;
                break;
            }
            pointer = interrupt_object(pointer).chain_next.get();
        }
        all
    };
    set_legacy_line_masked(vector, all_inactive);
}

/// Objeto reportado inativo (IoReportInterruptInactive sem Active posterior).
pub fn interrupt_reported_inactive(object: u64) -> bool {
    INACTIVE_INTERRUPTS.lock().contains(&object)
}

/// IoReportInterruptActive (active = true) / IoReportInterruptInactive.
pub fn report_interrupt_active_state(parameters: &crate::ntos::inc::types::extra_storage::IoReportInterruptActiveStateParameters, active: bool) {
    let version = parameters.version.get();
    let context = parameters.connection_context.get();
    match version {
        CONNECT_FULLY_SPECIFIED | CONNECT_LINE_BASED | CONNECT_FULLY_SPECIFIED_GROUP => report_object_active(context, active),
        CONNECT_MESSAGE_BASED => {
            // SAFETY: IO_INTERRUPT_MESSAGE_INFO devolvida pelo IoConnectInterruptEx ao driver.
            let table = unsafe { crate::ntos::inc::types::extra_storage::IoInterruptMessageInfo::at(context) };
            let count = table.message_count.get() as usize;
            // SAFETY: o vetor MessageInfo tem MessageCount entradas.
            let entries = unsafe { crate::ntos::inc::types::extra_storage::IoInterruptMessageInfoEntry::array_at(table.message_info[0].address(), count) };
            for entry in entries {
                report_object_active(entry.interrupt_object.get(), active);
            }
        }
        _ => crate::ntos::ke::bugcheck::bug_check_ex(0xCA, 0xC, version as u64, 0, 0),
    }
}
