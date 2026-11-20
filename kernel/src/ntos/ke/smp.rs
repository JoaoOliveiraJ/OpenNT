//! Multiprocessador.
//!
//! Descobre processadores pela MADT e inicia APs com INIT-SIPI-SIPI
//! direcionado via xAPIC. O trampolim faz a troca de modos e salta para a
//! imagem do kernel, onde o AP consome trabalhos nativos numa mailbox física
//! compartilhada, que o BSP lê e grava pelo mapa direto (`hal::physical`).
//! Cada AP recebe antes do SIPI uma KPCR própria (`pcr::init_processor`),
//! com o número de processador que vai ocupar (1 + sua posição entre os
//! online), e a publica no próprio GS; e uma pilha de kernel do
//! MmCreateKernelStack (`mm::kernel_stack`, com a página de guarda), a pilha
//! da thread ociosa que o KeStartAllProcessors do 19041 cria para cada
//! processador, onde o AP roda o laço e os trabalhos.
//! A página do trampolim só fica mapeada em identidade enquanto os APs
//! partem; depois a metade de usuário volta a não ter nada do kernel. Os
//! offsets devem coincidir com `hal::amd64::aptrampoline`.

use alloc::vec::Vec;

use crate::hal::amd64::aptrampoline;
use crate::hal::{cpu, lapic, physical};
use crate::hal::acpi;
use crate::ntos::ke::{clock, pcr};
use crate::ntos::mm::kernel_stack::{self, KernelStack};
use crate::ntos::mm::memory_map as map;
use crate::ntos::mm::paging::{self, MapOptions};
use crate::ntos::mm::pfn;
use crate::rtl::{KernelError, SpinLock};

const MAILBOX: u64 = map::SMP_MAILBOX_PHYS;
const TRAMPOLINE: u64 = map::AP_TRAMPOLINE_PHYS;

const MAILBOX_MAGIC: u64 = 0x00;
const MAILBOX_ACKNOWLEDGEMENT: u64 = 0x08;
const MAILBOX_BOOT_SLOT: u64 = 0x0C;
const MAILBOX_BOOT_STACK: u64 = 0x10;
const MAILBOX_PAGE_TABLE: u64 = 0x18;
const MAILBOX_EXPECTED_IDENTIFIER: u64 = 0x2C;
/// KPCR do AP em partida (VA), carregada em IA32_GS_BASE por `ap_kernel_entry`.
const MAILBOX_BOOT_PCR: u64 = 0x38;
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
    /// A pilha de boot (a da thread ociosa) de cada slot que recebeu SIPI.
    boot_stacks: Vec<(usize, KernelStack)>,
    /// O que cada AP com o anel 3 armado guarda para sempre
    /// ([`start_scheduling`]).
    armed: Vec<ArmedProcessor>,
}

/// As pilhas e a IDT de um AP com o anel 3 armado.
struct ArmedProcessor {
    slot: usize,
    fallback: KernelStack,
    double_fault: KernelStack,
    idt_frame: u64,
}

static STATE: SpinLock<Smp> = SpinLock::new(Smp {
    bootstrap_identifier: 0,
    discovered: Vec::new(),
    online_slots: Vec::new(),
    initialized: false,
    prepare_job: None,
    invalidation_active: false,
    boot_stacks: Vec::new(),
    armed: Vec::new(),
});

/// Os slots cujos APs deixaram o laço de trabalhos do trampolim pelo laço
/// ocioso com o anel 3 armado ([`start_scheduling`]): as interrupções
/// ligadas, a IDT, a GDT e a TSS próprias e o timer local.
static SCHEDULING_SLOTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Os slots cujo AP não conseguiu armar o anel 3.
static ARM_FAILED_SLOTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Prazo para o ICR voltar a ocioso (DeliveryStatus) na partida dos APs,
/// medido em tempo, em hardware e sob hipervisor. Os IPIs do sistema em
/// funcionamento esperam o ICR sem prazo, como o HalpApic1WriteIcr do 19041
/// (0x2efaf2..0x2efb05, `bt [ICR], 12` em laço).
const INTERRUPT_DELIVERY_TIMEOUT_MS: u64 = 100;
/// Quanto um IPI do sistema em funcionamento (a NMI de shootdown, a de um
/// trabalho de AP) espera antes do diagnóstico na serial, em hardware e sob
/// hipervisor. Não é prazo: o 19041 espera as confirmações de um flush de
/// TLB sem limite, girando no PacketBarrier da KPRCB (KeFlushMultipleRangeTb
/// 0x2bbdce..0x2bbdf8, KeFlushProcessWriteBuffers 0x343dbd..0x343dc9, só com
/// o aviso de espera longa ao hipervisor, HvlNotifyLongSpinWait), e o único
/// IPI_WATCHDOG_TIMEOUT dele é a barreira do KeIpiGenericCall
/// (KiIpiGenericCallTarget 0x3a49c2..0x3a4a07: 300 s a partir do
/// BaselineInterruptTimeQpc, e nenhum com KiBarrierWait ou com o tempo
/// relaxado que o hipervisor recomenda, HvlEnlightenments bit 5). Sob um
/// hipervisor com o hospedeiro carregado, a CPU virtual de um alvo fica
/// segundos sem rodar (o hospedeiro só promove uma thread faminta depois de
/// uns 4 s), e nada no convidado o evita.
const SLOW_INTERRUPT_REPORT_MS: u64 = 5_000;
/// Num emulador (o TCG do QEMU) os prazos e o diagnóstico valem este
/// múltiplo: cada CPU virtual é uma thread comum do hospedeiro, e a entrega
/// de uma NMI e a execução do tratador dela passam pela trava global do
/// emulador, que as voltas de `pause` das outras CPUs virtuais disputam.
const EMULATED_TIMEOUT_SCALE: u64 = 12;

/// O múltiplo dos prazos de IPI desta plataforma (0 = ainda não decidido).
static TIMEOUT_SCALE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn timeout_scale() -> u64 {
    use core::sync::atomic::Ordering;
    let scale = TIMEOUT_SCALE.load(Ordering::Relaxed);
    if scale != 0 {
        return scale;
    }
    let scale = if crate::hal::hypervisor::is_emulator() { EMULATED_TIMEOUT_SCALE } else { 1 };
    TIMEOUT_SCALE.store(scale, Ordering::Relaxed);
    scale
}

/// O prazo do ICR na partida dos APs nesta plataforma (100 ms em hardware e
/// sob hipervisor).
pub fn interrupt_delivery_timeout_ms() -> u64 {
    INTERRUPT_DELIVERY_TIMEOUT_MS * timeout_scale()
}

/// Depois de quanto tempo um IPI do sistema em funcionamento sem resposta
/// vai à serial (5 s em hardware e sob hipervisor); a espera continua.
pub fn slow_interrupt_report_ms() -> u64 {
    SLOW_INTERRUPT_REPORT_MS * timeout_scale()
}

/// Uma espera de IPI com prazo que venceu: a frequência do contador de
/// desempenho (a do KeQueryPerformanceCounter, 10 MHz), o valor corrente do
/// contador, o do início da espera e a máscara dos processadores (pelo
/// número) que não responderam.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpiStall {
    pub frequency: u64,
    pub current: u64,
    pub start: u64,
    pub pending: u64,
}

impl IpiStall {
    /// Milissegundos transcorridos entre o início e a detecção.
    pub fn elapsed_ms(&self) -> u64 {
        (self.current.wrapping_sub(self.start) as u128 * 1000 / self.frequency.max(1) as u128) as u64
    }
}

/// O prazo de `timeout_ms` venceu depois de `elapsed` unidades de um
/// contador de `frequency` Hz: o contador passou do início mais a frequência
/// vezes o prazo, a comparação estrita do KiIpiGenericCallTarget do 19041
/// (`ja` do contador contra o BaselineInterruptTimeQpc mais Frequency ×
/// 300). A conta é exata, em 128 bits:
/// um prazo que não é um número inteiro de unidades do contador (o TSC a
/// 3 393 623 006 Hz dá 101 808 690,18 unidades em 30 ms) não vence na
/// unidade de baixo, um pedaço de unidade antes da hora, com 29 ms
/// transcorridos.
pub fn deadline_passed(elapsed: u64, frequency: u64, timeout_ms: u64) -> bool {
    elapsed as u128 * 1000 > frequency as u128 * timeout_ms as u128
}

/// Espera, pelo contador de desempenho (o KeQueryPerformanceCounter, a
/// 10 MHz, que o KiIpiGenericCallTarget do 19041 lê), até `pending` devolver
/// 0: a máscara dos processadores que ainda não responderam. Vencido
/// `timeout_ms` ([`deadline_passed`]), devolve o atraso com o que ainda
/// faltava. A espera compara o contador com a frequência vezes o prazo em
/// vez de contar voltas: o prazo é o mesmo em qualquer CPU, hipervisor ou
/// emulador.
pub fn stall_on_targets(timeout_ms: u64, mut pending: impl FnMut() -> u64) -> Result<(), IpiStall> {
    let frequency = clock::QPC_FREQUENCY;
    let start = clock::query_performance_counter_value();
    loop {
        let waiting = pending();
        if waiting == 0 {
            return Ok(());
        }
        let current = clock::query_performance_counter_value();
        if deadline_passed(current.wrapping_sub(start), frequency, timeout_ms) {
            return Err(IpiStall { frequency, current, start, pending: waiting });
        }
        cpu::pause();
    }
}

/// Como terminou uma espera sem prazo de IPI ([`wait_on_targets`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpiWait {
    /// Milissegundos até o último alvo responder.
    pub elapsed_ms: u64,
    /// A máscara dos que ainda faltavam quando a espera passou do tempo do
    /// diagnóstico (0 se todos responderam antes).
    pub slow: u64,
}

/// Espera, sem prazo, até `pending` devolver 0 (os processadores que ainda
/// não responderam), como o 19041 espera o PacketBarrier de um flush de TLB:
/// girando com `pause`. Passado `report_ms`, a serial recebe uma linha com
/// os pendentes (`what` diz o quê) e a espera continua; a resposta tardia
/// também vai à serial, com o tempo total.
pub fn wait_on_targets(report_ms: u64, what: &str, mut pending: impl FnMut() -> u64) -> IpiWait {
    let frequency = clock::QPC_FREQUENCY;
    let start = clock::query_performance_counter_value();
    let mut slow = 0;
    loop {
        let waiting = pending();
        let current = clock::query_performance_counter_value();
        let elapsed = current.wrapping_sub(start);
        if waiting == 0 {
            let elapsed_ms = (elapsed as u128 * 1000 / frequency as u128) as u64;
            if slow != 0 {
                debug_print!("[smp] {}: os processadores {:#x} responderam depois de {} ms", what, slow, elapsed_ms);
            }
            return IpiWait { elapsed_ms, slow };
        }
        if slow == 0 && deadline_passed(elapsed, frequency, report_ms) {
            slow = waiting;
            debug_print!("[smp] {}: processadores {:#x} sem resposta ha {} ms; a espera continua (sem prazo, como o flush de TLB do 19041)", what, waiting, report_ms);
        }
        cpu::pause();
    }
}

/// O bit deste processador (o número da KPRCB; 0 antes da KPCR do BSP).
fn own_processor_bit() -> u64 {
    let number = if pcr::get_pcr_address() != 0 { pcr::current().prcb.number.get() } else { 0 };
    1 << (number & 63)
}

/// O bit DeliveryStatus do ICR deste processador (o comando anterior ainda
/// não saiu), como a máscara deste processador.
fn interrupt_delivery_pending() -> u64 {
    if lapic::read(LAPIC_COMMAND_LOW) & 0x1000 != 0 { own_processor_bit() } else { 0 }
}

/// A partida de um AP: um ICR que não fica ocioso no prazo é o atraso, e um
/// identificador x2APIC acima de 255 não pode ser truncado e enviado a outro
/// processador pelo xAPIC (`Ok(false)`).
fn send_startup_command(identifier: u32, command_low: u32) -> Result<bool, IpiStall> {
    if identifier > 255 {
        return Ok(false);
    }
    stall_on_targets(interrupt_delivery_timeout_ms(), interrupt_delivery_pending)?;
    lapic::write(LAPIC_COMMAND_HIGH, identifier << 24);
    lapic::write(LAPIC_COMMAND_LOW, command_low);
    stall_on_targets(interrupt_delivery_timeout_ms(), interrupt_delivery_pending)?;
    Ok(true)
}

/// Envio da partida dos APs: a falha vira erro do boot.
fn send_startup_interrupt(identifier: u32, command_low: u32) -> bool {
    matches!(send_startup_command(identifier, command_low), Ok(true))
}

/// Um IPI do sistema em funcionamento (a NMI de shootdown, a de um trabalho,
/// a do depurador): o ICR é esperado sem prazo antes e depois da escrita,
/// como o HalpApic1WriteIcr do 19041. `false` só para um identificador
/// x2APIC acima de 255, que o xAPIC não alcança.
fn send_processor_interrupt(identifier: u32, command_low: u32) -> bool {
    if identifier > 255 {
        return false;
    }
    let what = "entrega de IPI pelo ICR";
    wait_on_targets(slow_interrupt_report_ms(), what, interrupt_delivery_pending);
    lapic::write(LAPIC_COMMAND_HIGH, identifier << 24);
    lapic::write(LAPIC_COMMAND_LOW, command_low);
    wait_on_targets(slow_interrupt_report_ms(), what, interrupt_delivery_pending);
    true
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

/// Copia e relê o trampolim, prepara a IDT dos APs, zera a mailbox,
/// publica assinatura e CR3 e mapeia a página do trampolim em identidade
/// (supervisor, executável): o AP busca instruções nela entre ligar a
/// paginação e saltar para a imagem do kernel.
fn install_trampoline() -> Result<(), KernelError> {
    let bytes = aptrampoline::bytes();
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(KernelError::new("invalid AP trampoline size"));
    }
    physical::write_bytes(TRAMPOLINE, bytes);
    if !physical::equal_bytes(TRAMPOLINE, bytes) {
        return Err(KernelError::new("AP trampoline copy mismatch"));
    }
    aptrampoline::prepare_kernel_entry();
    physical::zero(MAILBOX, 0x1000);
    physical::write32(MAILBOX + MAILBOX_MAGIC, MAILBOX_SIGNATURE);
    physical::write64(MAILBOX + MAILBOX_PAGE_TABLE, map::PML4_PHYS);
    if !paging::map_page(TRAMPOLINE, TRAMPOLINE, paging::PAGE_PRESENT | paging::PAGE_RW, MapOptions::default()) {
        return Err(KernelError::new("cannot map the AP trampoline page"));
    }
    Ok(())
}

/// Desfaz o mapeamento de identidade do trampolim e as tabelas que ele criou
/// na metade de usuário: os APs já executam na imagem do kernel. As tabelas
/// só voltam ao PFN depois que todas as CPUs invalidaram as traduções.
fn remove_trampoline() -> Result<(), KernelError> {
    let mut tables = Vec::new();
    if !paging::unmap_page(TRAMPOLINE, MapOptions { deferred_tables: Some(&mut tables), ..Default::default() }) {
        return Err(KernelError::new("cannot unmap the AP trampoline page"));
    }
    cpu::reload_cr3();
    flush_remote_tlb(false)?;
    for frame in tables {
        if !pfn::free_page(frame) {
            return Err(KernelError::new("AP trampoline page table lost PFN ownership"));
        }
    }
    Ok(())
}

fn slot_address(slot: usize) -> u64 {
    MAILBOX + MAILBOX_SLOTS + slot as u64 * SLOT_SIZE
}

/// Publica slot, identidade e pilha (`stack`, o InitialStack da pilha de
/// kernel do AP) antes de INIT-SIPI-SIPI. Só aceita a confirmação
/// consistente do modo 64 bits; reinicia o alvo num timeout.
fn start_application_processor(slot: usize, identifier: u32, stack: u64) -> Result<bool, KernelError> {
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
    // A pilha de boot do AP (o AP já está em 64 bits, com o CR3 do BSP,
    // quando a carrega).
    physical::write64(MAILBOX + MAILBOX_BOOT_STACK, stack);

    if !send_startup_interrupt(identifier, INIT_ASSERT) {
        return Err(KernelError::new("AP INIT delivery failed"));
    }
    clock::spin_ms(10);
    if !send_startup_interrupt(identifier, INIT_DEASSERT) {
        return Err(KernelError::new("AP INIT completion failed"));
    }
    clock::spin_ms(1);
    if !send_startup_interrupt(identifier, vector) {
        return Err(KernelError::new("AP SIPI delivery failed"));
    }
    clock::spin_ms(1);
    if !send_startup_interrupt(identifier, vector) {
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
    if !send_startup_interrupt(identifier, INIT_ASSERT) {
        return Err(KernelError::new("AP reset delivery failed after startup timeout"));
    }
    clock::spin_ms(10);
    if !send_startup_interrupt(identifier, INIT_DEASSERT) {
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
    super::processor_group::initialize_boot_processor_count();
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
    let mut identifiers: Vec<u32> = Vec::new();
    for identifier in discovered {
        if identifier != bootstrap && !identifiers.contains(&identifier) {
            identifiers.push(identifier);
        }
    }
    identifiers.truncate(map::MAX_CPUS - 1);
    // As KPCRs saem antes das interrupções desligadas: a de número N vai para
    // o AP que ficar online em N-ésimo lugar; as que sobrarem voltam no fim.
    let mut processor_blocks = Vec::new();
    for number in 1..=identifiers.len() as u32 {
        match pcr::init_processor(number) {
            Ok(block) => processor_blocks.push(block),
            Err(error) => {
                (1..number).for_each(pcr::release_processor);
                return Err(error);
            }
        }
    }
    // As pilhas de boot também: o KeStartAllProcessors cria, para cada
    // processador, a pilha de kernel da thread ociosa pelo
    // MmCreateKernelStack (e a do DPC e as das ISRs, que os APs daqui não
    // usam). Com a guarda, um estouro falta em vez de escrever na pilha
    // vizinha.
    let mut boot_stacks = Vec::new();
    for _ in 0..identifiers.len() {
        match kernel_stack::create(false) {
            Ok(stack) => boot_stacks.push(stack),
            Err(error) => {
                boot_stacks.into_iter().for_each(kernel_stack::delete);
                (1..=identifiers.len() as u32).for_each(pcr::release_processor);
                return Err(error);
            }
        }
    }
    if let Err(error) = install_trampoline() {
        boot_stacks.into_iter().for_each(kernel_stack::delete);
        (1..=identifiers.len() as u32).for_each(pcr::release_processor);
        return Err(error);
    }
    lapic::write(LAPIC_SPURIOUS, lapic::read(LAPIC_SPURIOUS) | 0x100);

    let flags = cpu::save_and_disable_interrupts();
    let mut online = Vec::new();
    let mut failure = None;
    let mut started = 0;
    for (slot, &identifier) in identifiers.iter().enumerate() {
        physical::write64(MAILBOX + MAILBOX_BOOT_PCR, processor_blocks[online.len()]);
        started = slot + 1;
        match start_application_processor(slot, identifier, boot_stacks[slot].initial) {
            Ok(true) => {
                let reported = physical::read32(slot_address(slot) + SLOT_CONTROLLER_IDENTIFIER);
                debug_print!("[smp] CPU {} online (apicId={})", slot + 1, reported);
                online.push(slot);
                super::processor_group::update_processor_count();
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
    for number in online.len() as u32 + 1..=identifiers.len() as u32 {
        pcr::release_processor(number);
    }
    // A pilha de um AP que recebeu SIPI fica com ele, mesmo sem resposta (um
    // AP atrasado ainda pode carregá-la); as dos slots que nem partiram
    // voltam ao Mm.
    let unused = boot_stacks.split_off(started);
    unused.into_iter().for_each(kernel_stack::delete);
    {
        let mut state = STATE.lock();
        state.online_slots = online;
        state.boot_stacks = boot_stacks.into_iter().enumerate().collect();
        state.initialized = true;
    }
    let removed = remove_trampoline();
    failure.map_or(removed, Err)
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
    // O AP ocioso dorme no HLT do laço de trabalhos com o IF desligado: a
    // NMI o acorda (a que chega antes do HLT volta ao teste do trabalho, no
    // `ap_nmi_done` do trampolim).
    let identifier = physical::read32(record + SLOT_CONTROLLER_IDENTIFIER);
    if !send_processor_interrupt(identifier, 0x4400) {
        return Err(KernelError::new(alloc::format!("NMI de trabalho ao AP slot {slot}: identificador {identifier} fora do xAPIC")));
    }
    // O AP armado dorme no HLT com as interrupções ligadas: a NMI que chega
    // entre o teste do trabalho e o HLT não o acorda de novo, e o IPI de
    // reescalonamento, que fica pendente no IRR até o `sti; hlt`, sim.
    if is_scheduling(slot) {
        send_processor_interrupt(identifier, 0x4000 | crate::nano::interrupts::VECTOR_RESCHEDULE as u32);
    }
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

/// Postagem + espera síncrona (o `false` de `start_job`
/// não é tratado separadamente).
pub fn run_on_ap(slot: usize, routine: u64, arguments: [u64; 4]) -> Result<u64, KernelError> {
    start_job(slot, routine, arguments)?;
    wait_job(slot, 0)
}

/// O AP do `slot` está no laço ocioso com o anel 3 armado.
pub fn is_scheduling(slot: usize) -> bool {
    slot < 64 && SCHEDULING_SLOTS.load(core::sync::atomic::Ordering::Acquire) & (1 << slot) != 0
}

/// Arma o anel 3 no AP do `slot` (o KiInitializeProcessor do 19041 dá a
/// cada processador a GDT, a TSS, a IDT, as pilhas e os MSRs de syscall): a
/// pilha reserva e a da falta dupla dele, a cópia da IDT do BSP (com a NMI
/// dos APs no vetor 2) e o trabalho [`ap_scheduler_entry`], que se desprende
/// do laço de trabalhos do trampolim e fica no laço ocioso
/// ([`processor_loop`]), com as interrupções ligadas e o timer local. Os
/// trabalhos seguintes continuam pela mesma mailbox. Espera o AP confirmar.
/// Exige o anel 3 do BSP já armado (a IDT copiada tem o vetor 8 na IST1).
pub fn start_scheduling(slot: usize) -> Result<(), KernelError> {
    use core::sync::atomic::Ordering;
    if is_scheduling(slot) {
        return Ok(());
    }
    if !crate::hal::amd64::usermode::ready() {
        return Err(KernelError::new("anel 3 do BSP ainda nao armado"));
    }
    let fallback = kernel_stack::create(false)?;
    let double_fault = match kernel_stack::create(false) {
        Ok(stack) => stack,
        Err(error) => {
            kernel_stack::delete(fallback);
            return Err(error);
        }
    };
    let Some((idt, idt_frame)) = crate::nano::interrupts::processor_idt(aptrampoline::nmi_handler()) else {
        kernel_stack::delete(fallback);
        kernel_stack::delete(double_fault);
        return Err(KernelError::new("sem frame para a IDT do AP"));
    };
    let routine = ap_scheduler_entry as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64;
    let posted = start_job(slot, routine, [slot as u64, fallback.initial, double_fault.initial, idt]);
    if !matches!(posted, Ok(true)) {
        kernel_stack::delete(fallback);
        kernel_stack::delete(double_fault);
        pfn::free_page(idt_frame);
        return Err(posted.err().unwrap_or_else(|| KernelError::new(alloc::format!("AP slot {slot} ocupado"))));
    }
    // As pilhas e a IDT passam a ser do AP, armado ou não.
    STATE.lock().armed.push(ArmedProcessor { slot, fallback, double_fault, idt_frame });
    let deadline = clock::now_ms() + 5_000;
    while clock::now_ms() < deadline {
        if is_scheduling(slot) {
            return Ok(());
        }
        if ARM_FAILED_SLOTS.load(Ordering::Acquire) & (1 << slot) != 0 {
            return Err(KernelError::new(alloc::format!("AP slot {slot} nao armou o anel 3")));
        }
        cpu::pause();
    }
    Err(KernelError::new(alloc::format!("AP slot {slot} sem confirmar o anel 3 em 5 s")))
}

/// As pilhas que o AP armado do `slot` guarda nas entradas da TSS dele: o
/// topo da pilha reserva (RSP0 fora de um intervalo) e o da falta dupla
/// (IST1), e o frame da IDT dele.
pub fn scheduling_resources(slot: usize) -> Option<(u64, u64, u64)> {
    STATE.lock().armed.iter().find(|armed| armed.slot == slot).map(|armed| (armed.fallback.initial, armed.double_fault.initial, armed.idt_frame))
}

/// [`start_scheduling`] em todo AP online, com o resultado na serial.
pub fn start_scheduling_all() {
    for index in 0..ap_slot_count() {
        let Some(slot) = ap_slot(index) else { continue };
        match start_scheduling(slot) {
            Ok(()) => debug_print!("[smp] CPU {}: anel 3 armado, laco ocioso com o timer local", index + 1),
            Err(error) => debug_print!("[smp] CPU {}: anel 3 nao armado: {}", index + 1, error),
        }
    }
}

/// O trabalho que arma um AP ([`start_scheduling`]), no próprio AP: marca o
/// trabalho concluído na hora (o laço do trampolim nunca volta a vê-lo),
/// carrega a IDT própria (KPCR.IdtBase), arma o anel 3
/// (`usermode::processor_user_mode_init`: GDT, TSS, MSRs, RspBase), liga o
/// timer local e entra no laço ocioso com as interrupções ligadas.
extern "win64" fn ap_scheduler_entry(slot: u64, fallback: u64, double_fault: u64, idt: u64) -> u64 {
    use core::sync::atomic::Ordering;
    let slot = slot as usize;
    let record = slot_address(slot);
    physical::write64(record + SLOT_JOB_RESULT, 0);
    physical::write32(record + SLOT_JOB_COMPLETED, 1);
    crate::nano::interrupts::load_processor_idt(idt);
    pcr::current().idt_base.set(idt);
    match crate::hal::amd64::usermode::processor_user_mode_init(fallback, double_fault) {
        Ok(_) => {
            crate::nano::interrupts::start_processor_timer();
            SCHEDULING_SLOTS.fetch_or(1 << slot, Ordering::AcqRel);
        }
        Err(error) => {
            debug_print!("[smp] AP slot {} nao armou o anel 3: {}", slot, error);
            ARM_FAILED_SLOTS.fetch_or(1 << slot, Ordering::AcqRel);
        }
    }
    processor_loop(slot)
}

/// O laço ocioso de um AP armado, como o KiIdleLoop do 19041 (0x402020):
/// atende os trabalhos da mailbox (a rotina publicada por último, os quatro
/// argumentos, o resultado e a conclusão, como o laço do trampolim) e, sem
/// trabalho, dorme no HLT com as interrupções ligadas (`sti; hlt`, o
/// HalProcessorIdle); o timer local, uma NMI ou o IPI de reescalonamento o
/// acordam. Cada trabalho começa com o mesmo `mov cr3, cr3` do laço do
/// trampolim (o BSP pode remapear imagens com os APs ociosos).
fn processor_loop(slot: usize) -> ! {
    let record = slot_address(slot);
    loop {
        let routine = physical::read64(record + SLOT_JOB_ROUTINE);
        if routine != 0 {
            cpu::write_cr3(cpu::read_cr3());
            let arguments: [u64; 4] = core::array::from_fn(|index| physical::read64(record + SLOT_FIRST_ARGUMENT + index as u64 * 8));
            physical::write64(record + SLOT_JOB_ROUTINE, 0);
            // SAFETY: a rotina MS x64 que `start_job` publicou.
            let job: extern "win64" fn(u64, u64, u64, u64) -> u64 = unsafe { core::mem::transmute(routine as usize) };
            let result = job(arguments[0], arguments[1], arguments[2], arguments[3]);
            physical::write64(record + SLOT_JOB_RESULT, result);
            physical::write32(record + SLOT_JOB_COMPLETED, 1);
            continue;
        }
        let flags = cpu::save_and_disable_interrupts();
        if physical::read64(record + SLOT_JOB_ROUTINE) == 0 {
            cpu::processor_idle();
        } else {
            cpu::restore_interrupts(flags);
        }
    }
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

/// KeStartDynamicProcessor(.., ProcessorNumber*): o ntoskrnl recusa com
/// STATUS_UNSUCCESSFUL, sem tocar na saída, fora do processo System ou sem
/// KeDynamicPartitioningSupported. O OpenNT não acrescenta processadores
/// depois do boot (só os da MADT partem no SMP), então a partição dinâmica
/// nunca está disponível e a resposta é sempre essa.
pub fn start_dynamic_processor() -> u32 {
    0xC000_0001
}

/// KiSystemFullyCoherent: começa 1 e cai para 0 no primeiro
/// KeReportCacheIncoherentDevice.
static SYSTEM_FULLY_COHERENT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);

/// KeReportCacheIncoherentDevice: um dispositivo de DMA sem coerência de
/// cache existe no sistema.
pub fn report_cache_incoherent_device() {
    SYSTEM_FULLY_COHERENT.store(0, core::sync::atomic::Ordering::SeqCst);
}

/// O KiSystemFullyCoherent corrente.
pub fn system_fully_coherent() -> bool {
    SYSTEM_FULLY_COHERENT.load(core::sync::atomic::Ordering::SeqCst) != 0
}

pub fn ap_slot(index: usize) -> Option<usize> {
    STATE.lock().online_slots.get(index).copied()
}

/// A pilha de kernel em que o AP do `slot` online roda o laço e os
/// trabalhos.
pub fn ap_boot_stack(slot: usize) -> Option<KernelStack> {
    let state = STATE.lock();
    if !state.online_slots.contains(&slot) {
        return None;
    }
    state.boot_stacks.iter().find(|&&(owner, _)| owner == slot).map(|&(_, stack)| stack)
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

/// NMI a cada processador de aplicação online, lido direto dos slots da
/// mailbox, sem a trava do estado (o depurador do kernel congela os outros
/// processadores com a máquina parada, e o código interrompido pode ser o
/// dono dela). Devolve quantos foram sinalizados.
pub fn send_nmi_to_application_processors() -> u32 {
    let own = lapic::read(0x20) >> 24;
    let mut sent = 0;
    for slot in 0..map::MAX_CPUS - 1 {
        let record = slot_address(slot);
        if physical::read32(record + SLOT_ONLINE) != 1 {
            continue;
        }
        let identifier = physical::read32(record + SLOT_CONTROLLER_IDENTIFIER);
        if identifier != own && send_processor_interrupt(identifier, 0x4400) {
            sent += 1;
        }
    }
    sent
}

/// NMI direcionada aos processadores online e espera da confirmação da
/// geração de invalidação; `flush_caches` pede WBINVD também. A espera não
/// tem prazo ([`wait_on_targets`]), como a do PacketBarrier no flush de TLB
/// do 19041: um alvo que demora mais que [`slow_interrupt_report_ms`] vai à
/// serial e a espera segue.
pub fn flush_remote_tlb(flush_caches: bool) -> Result<(), KernelError> {
    shootdown(u64::MAX, flush_caches, false)
}

/// O bit do processador de número N é o do AP da N-ésima posição entre os
/// online (o BSP é o 0 e não tem slot).
fn processor_bit(online_index: usize) -> u64 {
    1u64.checked_shl(online_index as u32 + 1).unwrap_or(0)
}

/// A NMI de shootdown aos APs online cujo bit (pelo número do processador)
/// está em `targets`, e a espera das confirmações deles. Outro shootdown em
/// curso é um erro, ou, com `wait_busy`, espera a vez: a confirmação vem pela
/// NMI, que nem o IF nem o IRQL retêm, então quem está em curso termina.
fn shootdown(targets: u64, flush_caches: bool, wait_busy: bool) -> Result<(), KernelError> {
    let selected: Vec<(usize, usize)> = loop {
        let mut state = STATE.lock();
        let selected: Vec<(usize, usize)> = state.online_slots.iter().copied().enumerate().filter(|&(index, _)| targets & processor_bit(index) != 0).collect();
        if selected.is_empty() {
            return Ok(());
        }
        if !state.invalidation_active {
            state.invalidation_active = true;
            break selected;
        }
        if !wait_busy {
            return Err(KernelError::new("nested TLB shootdown"));
        }
        drop(state);
        cpu::pause();
    };
    let flags = cpu::save_and_disable_interrupts();
    let result = (|| {
        let generation = physical::read32(MAILBOX + 0x30).wrapping_add(1);
        physical::write32(MAILBOX + 0x34, flush_caches as u32);
        physical::write32(MAILBOX + 0x30, generation);
        for &(_, slot) in &selected {
            if !send_processor_interrupt(physical::read32(slot_address(slot) + SLOT_CONTROLLER_IDENTIFIER), 0x4400) {
                return Err(KernelError::new("TLB shootdown delivery failed"));
            }
        }
        let pending = || selected.iter().filter(|&&(_, slot)| physical::read32(slot_address(slot) + 0x3C) != generation).fold(0u64, |mask, &(index, _)| mask | processor_bit(index));
        wait_on_targets(slow_interrupt_report_ms(), "confirmacao do shootdown de TLB", pending);
        Ok(())
    })();
    cpu::restore_interrupts(flags);
    STATE.lock().invalidation_active = false;
    result
}

/// Interrompe os APs online de `targets` (pelo número do processador) e
/// espera as confirmações; outro shootdown em curso espera a vez.
pub fn interrupt_processors(targets: u64) -> Result<(), KernelError> {
    shootdown(targets, false, true)
}

/// A geração de invalidação corrente e a última que o AP da posição
/// `online_index` confirmou (o autoteste confere quem a NMI alcançou).
pub fn shootdown_generations(online_index: usize) -> Option<(u32, u32)> {
    let slot = STATE.lock().online_slots.get(online_index).copied()?;
    Some((physical::read32(MAILBOX + 0x30), physical::read32(slot_address(slot) + 0x3C)))
}

/// Os processadores (pelo número) que o KeFlushProcessWriteBuffers
/// interrompe: os de `active` (KPROCESS.ActiveProcessors, ou todos os
/// online com AllProcessors) menos o corrente (`own`).
pub fn write_buffer_targets(active: u64, own: u64) -> u64 {
    active & !own
}

/// KeFlushProcessWriteBuffers(AllProcessors) do ntoskrnl 19041 (rva
/// 0x343d14): em SYNCH_LEVEL, copia o KPROCESS.ActiveProcessors do processo
/// corrente da thread (ApcState.Process; com AllProcessors, todos os
/// processadores), tira o processador corrente e, sobrando algum, manda a
/// eles um IPI com alvo vazio (KiIpiSendPacket) e espera todos confirmarem.
/// Interromper a CPU serializa o que ela já escreveu: depois da volta, toda
/// escrita que uma thread do processo fez em outro processador já é visível
/// aqui (a trava assimétrica do CDDISync::CFreeThreadedLock do d3d11 depende
/// disso). No OpenNT o IPI é a NMI de shootdown dos APs (o alvo também
/// recarrega o CR3, o que não muda o efeito). O BSP não tem essa NMI; no M0
/// só o BSP executa o anel 3, então o chamador do serviço é ele mesmo.
pub fn flush_process_write_buffers(all_processors: bool) -> Result<(), KernelError> {
    use crate::ntos::inc::types::{Kprocess, Kthread, NtStruct};
    use crate::ntos::ke::irql;
    let previous = irql::raise_at_least(irql::SYNCH_LEVEL);
    let active = if all_processors {
        u64::MAX
    } else {
        let thread = crate::ntos::ps::process::get_current_thread();
        // SAFETY: a KTHREAD corrente e o processo corrente dela, vivos
        // enquanto a thread roda.
        let process = if thread != 0 { unsafe { Kthread::at(thread) }.apc_state.process.get() } else { 0 };
        if process != 0 { unsafe { Kprocess::at(process) }.active_processors.bitmap[0].atomic().load(core::sync::atomic::Ordering::SeqCst) } else { 0 }
    };
    let targets = write_buffer_targets(active, own_processor_bit());
    let result = if targets != 0 { interrupt_processors(targets) } else { Ok(()) };
    irql::lower_irql(previous as u64);
    result
}
