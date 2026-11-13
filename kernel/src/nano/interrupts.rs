//! Gerente de interrupções do nanokernel — `system32/nano/interrupts.js`.
//!
//! Constrói a IDT na memória física (0x82000), programa o PIC 8259 e o
//! timer do LAPIC (100 Hz) pelas portas e carrega a tabela. Os trampolins
//! (`hal::amd64::irqstubs`) só registram o evento em memória compartilhada, no ring
//! do teclado, e fazem EOI; a leitura e a política são daqui.
//!
//! DISPATCH: cada vetor tem um handler registrado; [`dispatch_pending`]
//! (chamado no laço principal) compara os contadores do hardware e chama os
//! handlers — o modelo ISR(conta) -> DPC(despacha) do NT.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::hal::{cpu, lapic, physical, port};
use crate::hal::amd64::irqstubs;
use crate::ntos::ke::clock;
use crate::rtl::text::fixed1;
use crate::rtl::SpinLock;

const IDT_ADDRESS: u64 = 0x82000;

const CODE64_SELECTOR: u16 = 0x10; // CS do kernel NT, igual às GDTs do BSP/APs
const INTERRUPT_GATE: u8 = 0x8E; // presente, ring 0, interrupt gate

pub const VECTOR_TIMER: u8 = 0x20; // IRQ0 (PIT — legado, mascarado)
pub const VECTOR_KEYBOARD: u8 = 0x21; // IRQ1 (PS/2)
pub const VECTOR_LAPIC_TIMER: u8 = 0x40; // timer do LAPIC (o quantum real)

// registros do LAPIC (xAPIC MMIO)
const LAPIC_SPURIOUS: u32 = 0x0F0;
const LAPIC_TPR: u32 = 0x080;
const LAPIC_LVT_TIMER: u32 = 0x320;
const LAPIC_LVT_LINT0: u32 = 0x350;
const LAPIC_LVT_LINT1: u32 = 0x360;
const LAPIC_TIMER_DIVIDE: u32 = 0x3E0;
const LAPIC_TIMER_INITIAL: u32 = 0x380;
const LAPIC_TIMER_CURRENT: u32 = 0x390;

/// Handler de vetor: recebe o vetor e o número de ocorrências pendentes.
pub type IrqHandler = fn(vector: u8, count: u32);

struct DispatchTable {
    handler_by_vector: BTreeMap<u8, IrqHandler>,
    last_count_by_vector: BTreeMap<u8, u32>,
}

static TABLE: SpinLock<DispatchTable> = SpinLock::new(DispatchTable {
    handler_by_vector: BTreeMap::new(),
    last_count_by_vector: BTreeMap::new(),
});

static IDT_LOADED: AtomicBool = AtomicBool::new(false);

fn set_gate(vector: u16, handler_address: u64) {
    let base = IDT_ADDRESS + vector as u64 * 16;
    physical::write16(base, (handler_address & 0xFFFF) as u16);
    physical::write16(base + 2, CODE64_SELECTOR);
    physical::write8(base + 4, 0);
    // INT3 e a interrupção de fast-fail do NT podem ser chamadas do ring 3.
    let dpl = if vector == 3 || vector == 0x29 { 0x60 } else { 0 };
    physical::write8(base + 5, INTERRUPT_GATE | dpl);
    physical::write16(base + 6, ((handler_address >> 16) & 0xFFFF) as u16);
    physical::write32(base + 8, (handler_address >> 32) as u32);
    physical::write32(base + 12, 0);
}

// ---- detecção de plataforma (CPUID, só para log) ----
fn hypervisor_vendor() -> String {
    let registers = cpu::cpuid(0x4000_0000);
    let mut vendor = String::new();
    for value in [registers[1], registers[2], registers[3]] {
        for index in 0..4 {
            vendor.push(((value >> (index * 8)) & 0xFF) as u8 as char);
        }
    }
    vendor
}

pub fn init() {
    let hypervisor_bit = (cpu::cpuid(1)[2] >> 31) & 1 == 1;
    let vendor = if hypervisor_bit { hypervisor_vendor() } else { String::from("hardware real?") };
    debug_print!("[irq] plataforma: {}", vendor);

    // ORDEM IMPORTA: nenhuma fonte de IRQ pode estar ativa antes da IDT.

    // 1. PIC 8259: master -> 0x20, slave -> 0x28; só IRQ1 (teclado) + cascade
    //    IRQ2 habilitadas no boot — as demais são desmascaradas na conexão
    //    do KINTERRUPT (como o HAL faz).
    port::write8(0x20, 0x11);
    port::write8(0xA0, 0x11);
    port::write8(0x21, 0x20);
    port::write8(0xA1, 0x28);
    port::write8(0x21, 0x04);
    port::write8(0xA1, 0x02);
    port::write8(0x21, 0x01);
    port::write8(0xA1, 0x01);
    port::write8(0x21, 0xF9);
    port::write8(0xA1, 0xFF);

    // 2. constrói a IDT na memória física — TODOS os 256 vetores (o LAPIC
    //    pode entregar o spurious 0xFF; vetor sem gate = crash)
    let stubs = irqstubs::stub_table();
    for vector in 0..256u16 {
        set_gate(vector, stubs + vector as u64 * irqstubs::STUB_SIZE);
    }

    // 3. carrega a IDT e liga interrupções (sti dentro do load_idt)
    cpu::load_idt(IDT_ADDRESS, 256 * 16);
    IDT_LOADED.store(true, Ordering::Release);

    // 4. LAPIC timer: quantum periódico de 100 Hz (calibrado de verdade)
    start_lapic_timer();
    debug_print!("[irq] IDT carregada; LAPIC timer 100Hz + IRQ1 teclado");
}

/// LAPIC timer one-shot para medir a frequência do bus, depois periódico.
fn start_lapic_timer() {
    // habilita o LAPIC PRIMEIRO (SVR: spurious 0xFF + software enable)
    lapic::write(LAPIC_SPURIOUS, 0x1FF);
    lapic::write(LAPIC_TPR, 0); // TPR = 0 (nada mascarado)
    // LINT0 = ExtINT (0x700, NÃO mascarado): o caminho do PIC 8259 -> CPU
    // (virtual wire mode) — sem isso a IRQ1 do teclado não chega no LAPIC
    lapic::write(LAPIC_LVT_LINT0, 0x700);
    lapic::write(LAPIC_LVT_LINT1, 0x400); // LINT1 = NMI (não mascarado)
    lapic::write(LAPIC_LVT_TIMER, 0x10000); // timer mascarado para medir
    lapic::write(LAPIC_TIMER_DIVIDE, 0x3); // divide por 16

    // mede a frequência do timer do LAPIC com o relógio TSC (50 ms one-shot)
    lapic::write(LAPIC_TIMER_CURRENT, 0);
    lapic::write(LAPIC_TIMER_INITIAL, 0xFFFF_FFFF);
    let measure_end = clock::uptime_ms() + 50;
    while clock::uptime_ms() < measure_end {
        cpu::pause();
    }
    let elapsed_ticks = 0xFFFF_FFFFu32 - lapic::read(LAPIC_TIMER_CURRENT);
    lapic::write(LAPIC_LVT_TIMER, 0x10000); // para (máscara)
    lapic::write(LAPIC_TIMER_CURRENT, 0);
    let ticks_per_second = elapsed_ticks as u64 * 20; // 50 ms -> 1 s
    let ticks_per_quantum = (ticks_per_second / 100).max(1000) as u32;

    // liga o timer periódico no vetor 0x40 a 100 Hz
    lapic::write(LAPIC_LVT_TIMER, VECTOR_LAPIC_TIMER as u32 | 0x20000);
    lapic::write(LAPIC_TIMER_INITIAL, ticks_per_quantum);
    debug_print!(
        "[irq] LAPIC timer: {} MHz de bus, {} ticks/quantum",
        fixed1(ticks_per_second, 1_000_000),
        ticks_per_quantum
    );
}

// ---- registro e dispatch de handlers (o modelo ISR->DPC do NT) ------------

/// Registra o handler de um vetor; devolve o anterior.
pub fn register_irq_handler(vector: u8, handler: IrqHandler) -> Option<IrqHandler> {
    TABLE.lock().handler_by_vector.insert(vector, handler)
}

pub fn unregister_irq_handler(vector: u8, handler: IrqHandler) -> bool {
    let mut table = TABLE.lock();
    match table.handler_by_vector.get(&vector) {
        Some(&current) if current as usize == handler as usize => {
            table.handler_by_vector.remove(&vector);
            table.last_count_by_vector.remove(&vector);
            true
        }
        _ => false,
    }
}

/// Despacha as IRQs pendentes: para cada vetor com contagem nova no
/// hardware, chama o handler com o número de ocorrências pendentes.
pub fn dispatch_pending() {
    // Os handlers rodam sem o lock da tabela: podem registrar outros vetores.
    let mut due: Vec<(u8, IrqHandler, u32)> = Vec::new();
    {
        let mut table = TABLE.lock();
        let vectors: Vec<(u8, IrqHandler)> =
            table.handler_by_vector.iter().map(|(&vector, &handler)| (vector, handler)).collect();
        for (vector, handler) in vectors {
            let count = irq_count(vector);
            let last_count = table.last_count_by_vector.get(&vector).copied().unwrap_or(0);
            if count == last_count {
                continue;
            }
            table.last_count_by_vector.insert(vector, count);
            due.push((vector, handler, count.wrapping_sub(last_count)));
        }
    }
    for (vector, handler, pending) in due {
        handler(vector, pending);
    }
}

/// IRQs estão chegando de verdade? (hardware/emulador entregando)
pub fn irqs_arriving() -> bool {
    irq_count(VECTOR_LAPIC_TIMER) > 0
}

pub fn is_available() -> bool {
    IDT_LOADED.load(Ordering::Acquire)
}

pub fn tick_count() -> u32 {
    irq_count(VECTOR_LAPIC_TIMER)
}

pub fn irq_count(vector: u8) -> u32 {
    physical::read32(irqstubs::IRQ_COUNT_BASE + vector as u64 * 4)
}

/// Scancode cru do ring buffer alimentado pela IRQ1 (`None` se vazio).
pub fn poll_scancode() -> Option<u8> {
    let head = physical::read32(irqstubs::KEYBOARD_HEAD);
    let tail = physical::read32(irqstubs::KEYBOARD_TAIL);
    if head == tail {
        return None;
    }
    let value = physical::read8(irqstubs::KEYBOARD_DATA + tail as u64);
    physical::write32(irqstubs::KEYBOARD_TAIL, (tail + 1) & 0xFF);
    Some(value)
}
