//! Multiprocessador.
//!
//! Descobre processadores pela MADT e inicia APs com INIT-SIPI-SIPI
//! direcionado via xAPIC. O trampolim faz a troca de modos e consome
//! trabalhos nativos numa mailbox física compartilhada. Os offsets devem
//! coincidir com `hal::amd64::aptrampoline`.

use alloc::vec::Vec;

use crate::hal::amd64::aptrampoline;
use crate::hal::{cpu, lapic, physical};
use crate::hal::acpi;
use crate::ntos::ke::clock;
use crate::ntos::mm::memory_map as map;
use crate::rtl::{KernelError, SpinLock};

const MAILBOX: u64 = map::SMP_MAILBOX_PHYS;
const TRAMPOLINE: u64 = map::AP_TRAMPOLINE_PHYS;

const MAILBOX_MAGIC: u64 = 0x00;
const MAILBOX_ACKNOWLEDGEMENT: u64 = 0x08;
const MAILBOX_BOOT_SLOT: u64 = 0x0C;
const MAILBOX_BOOT_STACK: u64 = 0x10;
const MAILBOX_PAGE_TABLE: u64 = 0x18;
const MAILBOX_EXPECTED_IDENTIFIER: u64 = 0x2C;
const MAILBOX_SLOTS: u64 = 0x100;

const SLOT_SIZE: u64 = 64;
const SLOT_CONTROLLER_IDENTIFIER: u64 = 0x00;
const SLOT_ONLINE: u64 = 0x04;
const SLOT_JOB_ROUTINE: u64 = 0x08;
const SLOT_FIRST_ARGUMENT: u64 = 0x10;
const SLOT_JOB_RESULT: u64 = 0x30;
const SLOT_JOB_COMPLETED: u64 = 0x38;
const MAILBOX_SIGNATURE: u32 = 0x4A53_4D50;

const LAPIC_SPURIOUS: u32 = 0xF0;
const LAPIC_COMMAND_LOW: u32 = 0x300;
const LAPIC_COMMAND_HIGH: u32 = 0x310;
const INIT_ASSERT: u32 = 0xC500;
const INIT_DEASSERT: u32 = 0x8500;
const STARTUP_INTERRUPT: u32 = 0x4600;

struct Smp {
    bootstrap_identifier: u32,
    discovered: Vec<u32>,
    online_slots: Vec<usize>,
    initialized: bool,
    prepare_job: Option<fn()>,
    invalidation_active: bool,
}

static STATE: SpinLock<Smp> = SpinLock::new(Smp {
    bootstrap_identifier: 0,
    discovered: Vec::new(),
    online_slots: Vec::new(),
    initialized: false,
    prepare_job: None,
    invalidation_active: false,
});

/// Espera a entrega do comando anterior (bit DeliveryStatus).
fn wait_for_interrupt_delivery() -> bool {
    (0..100_000).any(|_| lapic::read(LAPIC_COMMAND_LOW) & 0x1000 == 0)
}

/// Um identificador x2APIC acima de 255 não pode ser truncado e enviado a
/// outro processador pelo xAPIC.
fn send_processor_interrupt(identifier: u32, command_low: u32) -> bool {
    if identifier > 255 || !wait_for_interrupt_delivery() {
        return false;
    }
    lapic::write(LAPIC_COMMAND_HIGH, identifier << 24);
    lapic::write(LAPIC_COMMAND_LOW, command_low);
    wait_for_interrupt_delivery()
}

/// Entradas Local APIC e Local x2APIC habilitadas da MADT.
fn parse_interrupt_controller_table(bytes: &[u8]) -> Vec<u32> {
    let mut identifiers = Vec::new();
    if bytes.len() < 44 {
        return identifiers;
    }
    let u32_at = |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let mut cursor = 44;
    while cursor < bytes.len() {
        if cursor + 2 > bytes.len() {
            return Vec::new();
        }
        let (kind, size) = (bytes[cursor], bytes[cursor + 1] as usize);
        if size < 2 || cursor + size > bytes.len() {
            return Vec::new();
        }
        if kind == 0 && size >= 8 {
            if u32_at(cursor + 4) & 1 != 0 {
                identifiers.push(bytes[cursor + 3] as u32);
            }
        } else if kind == 9 && size >= 16 && u32_at(cursor + 8) & 1 != 0 {
            identifiers.push(u32_at(cursor + 4));
        }
        cursor += size;
    }
    identifiers
}

fn discover_processors() -> Vec<u32> {
    acpi::get_table("APIC", 0, false).map(|table| parse_interrupt_controller_table(&table.bytes)).unwrap_or_default()
}

/// Copia e relê o trampolim, zera a mailbox e publica assinatura e CR3.
fn install_trampoline() -> Result<(), KernelError> {
    let bytes = aptrampoline::bytes();
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(KernelError::new("invalid AP trampoline size"));
    }
    physical::write_bytes(TRAMPOLINE, bytes);
    if !physical::equal_bytes(TRAMPOLINE, bytes) {
        return Err(KernelError::new("AP trampoline copy mismatch"));
    }
    physical::zero(MAILBOX, 0x1000);
    physical::write32(MAILBOX + MAILBOX_MAGIC, MAILBOX_SIGNATURE);
    physical::write64(MAILBOX + MAILBOX_PAGE_TABLE, map::PML4_PHYS);
    Ok(())
}

fn slot_address(slot: usize) -> u64 {
    MAILBOX + MAILBOX_SLOTS + slot as u64 * SLOT_SIZE
}

/// Publica slot, identidade e pilha antes de INIT-SIPI-SIPI. Só aceita a
/// confirmação consistente do modo 64 bits; reinicia o alvo num timeout.
fn start_application_processor(slot: usize, identifier: u32) -> Result<bool, KernelError> {
    if identifier > 255 {
        return Ok(false);
    }
    let vector = STARTUP_INTERRUPT | (TRAMPOLINE >> 12) as u32;
    let record = slot_address(slot);
    physical::write32(MAILBOX + MAILBOX_ACKNOWLEDGEMENT, 0);
    physical::write32(MAILBOX + MAILBOX_BOOT_SLOT, slot as u32);
    physical::write32(MAILBOX + MAILBOX_EXPECTED_IDENTIFIER, identifier);
    physical::zero(record, SLOT_SIZE as usize);
    physical::write32(record + SLOT_CONTROLLER_IDENTIFIER, identifier);
    for offset in [0x20, 0x24, 0x28] {
        physical::write32(MAILBOX + offset, 0);
    }
    physical::write64(MAILBOX + MAILBOX_BOOT_STACK, map::AP_STACK_BASE + (slot as u64 + 1) * map::AP_STACK_SIZE);

    if !send_processor_interrupt(identifier, INIT_ASSERT) {
        return Err(KernelError::new("AP INIT delivery failed"));
    }
    clock::spin_ms(10);
    if !send_processor_interrupt(identifier, INIT_DEASSERT) {
        return Err(KernelError::new("AP INIT completion failed"));
    }
    clock::spin_ms(1);
    if !send_processor_interrupt(identifier, vector) {
        return Err(KernelError::new("AP SIPI delivery failed"));
    }
    clock::spin_ms(1);
    if !send_processor_interrupt(identifier, vector) {
        return Err(KernelError::new("AP second SIPI delivery failed"));
    }
    let deadline = clock::now_ms() + 500;
    while clock::now_ms() < deadline {
        if physical::read32(MAILBOX + MAILBOX_ACKNOWLEDGEMENT) == slot as u32 + 1
            && physical::read32(record + SLOT_ONLINE) == 1
            && physical::read32(record + SLOT_CONTROLLER_IDENTIFIER) == identifier
            && physical::read32(MAILBOX + 0x28) == 0x64
        {
            return Ok(true);
        }
    }
    if !send_processor_interrupt(identifier, INIT_ASSERT) {
        return Err(KernelError::new("AP reset delivery failed after startup timeout"));
    }
    clock::spin_ms(10);
    if !send_processor_interrupt(identifier, INIT_DEASSERT) {
        return Err(KernelError::new("AP reset completion failed after startup timeout"));
    }
    clock::spin_ms(1);
    Ok(false)
}

/// Descobre identidades, identifica o BSP, verifica o APIC e inicia os
/// demais individualmente. Só slots confirmados entram na lista online.
pub fn init() -> Result<(), KernelError> {
    if STATE.lock().initialized {
        return Ok(());
    }
    let mut discovered = discover_processors();
    let bootstrap = (lapic::read(0x20) >> 24) & 0xFF;
    if discovered.is_empty() {
        discovered.push(bootstrap);
    }
    if !discovered.contains(&bootstrap) {
        discovered.insert(0, bootstrap);
    }
    // Versão somente leitura: uma escrita não pode mudá-la.
    let version = lapic::read(0x30);
    lapic::write(0x30, 0xDEAD_BEEF);
    let detected = lapic::read(0x30) == version && version & 0xFF >= 0x10;
    debug_print!("[smp] LAPIC version={:#x}{}", version, if detected { "" } else { " REGIAO NAO INTERCEPTADA (RAM)" });
    let application_count = discovered.len() - 1;
    debug_print!("[smp] CPUs na MADT: {} (BSP apicId={}, APs={})", discovered.len(), bootstrap, application_count);
    {
        let mut state = STATE.lock();
        state.discovered = discovered.clone();
        state.bootstrap_identifier = bootstrap;
    }
    if application_count == 0 {
        STATE.lock().initialized = true;
        return Ok(());
    }
    install_trampoline()?;
    lapic::write(LAPIC_SPURIOUS, lapic::read(LAPIC_SPURIOUS) | 0x100);

    let mut identifiers: Vec<u32> = Vec::new();
    for identifier in discovered {
        if identifier != bootstrap && !identifiers.contains(&identifier) {
            identifiers.push(identifier);
        }
    }
    identifiers.truncate(map::MAX_CPUS - 1);
    let flags = cpu::save_and_disable_interrupts();
    let mut online = Vec::new();
    let mut failure = None;
    for (slot, &identifier) in identifiers.iter().enumerate() {
        match start_application_processor(slot, identifier) {
            Ok(true) => {
                let reported = physical::read32(slot_address(slot) + SLOT_CONTROLLER_IDENTIFIER);
                debug_print!("[smp] CPU {} online (apicId={})", slot + 1, reported);
                online.push(slot);
            }
            Ok(false) => debug_print!(
                "[smp] AP apicId={} NAO respondeu ao SIPI (marcadores 16/32/64: {}/{}/{})",
                identifier,
                physical::read32(MAILBOX + 0x20),
                physical::read32(MAILBOX + 0x24),
                physical::read32(MAILBOX + 0x28)
            ),
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
    }
    cpu::restore_interrupts(flags);
    let mut state = STATE.lock();
    state.online_slots = online;
    state.initialized = true;
    failure.map_or(Ok(()), Err)
}

fn wait_job_free(slot: usize, timeout_ms: u64) -> bool {
    let deadline = clock::now_ms() + timeout_ms;
    while clock::now_ms() < deadline {
        if physical::read32(slot_address(slot) + SLOT_JOB_COMPLETED) != 0 {
            return true;
        }
    }
    false
}

/// Publica quatro argumentos antes do endereço da rotina.
pub fn start_job(slot: usize, routine: u64, arguments: [u64; 4]) -> Result<bool, KernelError> {
    let prepare = {
        let state = STATE.lock();
        if !state.online_slots.contains(&slot) {
            return Err(KernelError::new(alloc::format!("AP slot {slot} offline")));
        }
        state.prepare_job
    };
    if !wait_job_free(slot, 5000) {
        return Ok(false);
    }
    if let Some(prepare) = prepare {
        prepare();
    }
    let record = slot_address(slot);
    for (index, &argument) in arguments.iter().enumerate() {
        physical::write64(record + SLOT_FIRST_ARGUMENT + index as u64 * 8, argument);
    }
    physical::write32(record + SLOT_JOB_COMPLETED, 0);
    // A rotina é publicada por último.
    physical::write64(record + SLOT_JOB_ROUTINE, routine);
    Ok(true)
}

/// Prazo zero seleciona 30 segundos.
pub fn wait_job(slot: usize, timeout_ms: u64) -> Result<u64, KernelError> {
    let record = slot_address(slot);
    let deadline = clock::now_ms() + if timeout_ms == 0 { 30_000 } else { timeout_ms };
    while clock::now_ms() < deadline {
        if physical::read32(record + SLOT_JOB_COMPLETED) != 0 {
            return Ok(physical::read64(record + SLOT_JOB_RESULT));
        }
    }
    Err(KernelError::new(alloc::format!("timeout esperando job do AP slot {slot}")))
}

/// Postagem + espera síncrona (como no original, o `false` de `start_job`
/// não é tratado separadamente).
pub fn run_on_ap(slot: usize, routine: u64, arguments: [u64; 4]) -> Result<u64, KernelError> {
    start_job(slot, routine, arguments)?;
    wait_job(slot, 0)
}

/// APIC ids da MADT, na ordem dos índices de processador.
pub fn discovered_apic_ids() -> Vec<u32> {
    STATE.lock().discovered.clone()
}

pub fn discovered_cpu_count() -> usize {
    STATE.lock().discovered.len().max(1)
}

pub fn online_cpu_count() -> usize {
    1 + STATE.lock().online_slots.len()
}

pub fn ap_slot_count() -> usize {
    STATE.lock().online_slots.len()
}

pub fn ap_slot(index: usize) -> Option<usize> {
    STATE.lock().online_slots.get(index).copied()
}

pub fn bsp_apic_id() -> u32 {
    STATE.lock().bootstrap_identifier
}

pub fn set_prepare_job(callback: Option<fn()>) {
    STATE.lock().prepare_job = callback;
}

pub fn has_active_jobs() -> bool {
    STATE.lock().online_slots.iter().any(|&slot| physical::read32(slot_address(slot) + SLOT_JOB_COMPLETED) == 0)
}

/// NMI direcionada aos processadores online e espera da confirmação da
/// geração de invalidação; `flush_caches` pede WBINVD também.
pub fn flush_remote_tlb(flush_caches: bool) -> Result<(), KernelError> {
    let slots = {
        let mut state = STATE.lock();
        if state.online_slots.is_empty() {
            return Ok(());
        }
        if state.invalidation_active {
            return Err(KernelError::new("nested TLB shootdown"));
        }
        state.invalidation_active = true;
        state.online_slots.clone()
    };
    let flags = cpu::save_and_disable_interrupts();
    let result = (|| {
        let generation = physical::read32(MAILBOX + 0x30).wrapping_add(1);
        physical::write32(MAILBOX + 0x34, flush_caches as u32);
        physical::write32(MAILBOX + 0x30, generation);
        for &slot in &slots {
            if !send_processor_interrupt(physical::read32(slot_address(slot) + SLOT_CONTROLLER_IDENTIFIER), 0x4400) {
                return Err(KernelError::new("TLB shootdown delivery failed"));
            }
        }
        let deadline = clock::now_ms() + 5000;
        while slots.iter().any(|&slot| physical::read32(slot_address(slot) + 0x3C) != generation) {
            if clock::now_ms() >= deadline {
                return Err(KernelError::new("TLB shootdown acknowledgement timed out"));
            }
            cpu::pause();
        }
        Ok(())
    })();
    cpu::restore_interrupts(flags);
    STATE.lock().invalidation_active = false;
    result
}
