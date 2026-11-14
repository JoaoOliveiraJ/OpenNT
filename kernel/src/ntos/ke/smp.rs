//! Multiprocessador.
//!
//! Descobre processadores pela MADT e inicia APs com INIT-SIPI-SIPI
//! direcionado via xAPIC. O trampolim faz a troca de modos e salta para a
//! imagem do kernel, onde o AP consome trabalhos nativos numa mailbox física
//! compartilhada, que o BSP lê e grava pelo mapa direto (`hal::physical`).
//! Cada AP recebe antes do SIPI uma KPCR própria (`pcr::init_processor`),
//! com o número de processador que vai ocupar (1 + sua posição entre os
//! online), e a publica no próprio GS.
//! A página do trampolim só fica mapeada em identidade enquanto os APs
//! partem; depois a metade de usuário volta a não ter nada do kernel. Os
//! offsets devem coincidir com `hal::amd64::aptrampoline`.

use alloc::vec::Vec;

use crate::hal::amd64::aptrampoline;
use crate::hal::{cpu, lapic, physical};
use crate::hal::acpi;
use crate::ntos::ke::{bugcheck, clock, pcr};
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
}

static STATE: SpinLock<Smp> = SpinLock::new(Smp {
    bootstrap_identifier: 0,
    discovered: Vec::new(),
    online_slots: Vec::new(),
    initialized: false,
    prepare_job: None,
    invalidation_active: false,
});

/// IPI_WATCHDOG_TIMEOUT: um processador esperou tempo demais pela resposta
/// a um IPI.
pub const IPI_WATCHDOG_TIMEOUT: u32 = 0x1DB;
/// Prazo para o ICR voltar a ocioso (DeliveryStatus), medido em tempo.
const INTERRUPT_DELIVERY_TIMEOUT_MS: u64 = 100;
/// Prazo das confirmações de um shootdown de TLB.
const SHOOTDOWN_TIMEOUT_MS: u64 = 5_000;

/// Uma espera de IPI que venceu o prazo. Leva os parâmetros do
/// IPI_WATCHDOG_TIMEOUT do KiIpiGenericCallTarget do 19041 (a frequência do
/// contador de desempenho, o valor corrente e o do início da espera) e a
/// máscara dos processadores (pelo número) que não responderam.
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

/// Espera, pelo tempo do contador de desempenho (o TSC, o mesmo do
/// KeQueryPerformanceCounter), até `pending` devolver 0: a máscara dos
/// processadores que ainda não responderam. Vencido `timeout_ms`, devolve o
/// atraso com o que ainda faltava, como a detecção de IPI parado do NT, que
/// compara o contador com a frequência vezes o prazo em vez de contar
/// voltas: o prazo é o mesmo em qualquer CPU, hipervisor ou emulador.
pub fn stall_on_targets(timeout_ms: u64, mut pending: impl FnMut() -> u64) -> Result<(), IpiStall> {
    let frequency = clock::tsc_frequency_hz().max(1);
    let limit = (frequency as u128 * timeout_ms as u128 / 1000) as u64;
    let start = cpu::rdtsc();
    loop {
        let waiting = pending();
        if waiting == 0 {
            return Ok(());
        }
        let current = cpu::rdtsc();
        if current.wrapping_sub(start) >= limit {
            return Err(IpiStall { frequency, current, start, pending: waiting });
        }
        cpu::pause();
    }
}

/// O diagnóstico de um IPI sem resposta: imprime quem não respondeu e em
/// quanto tempo e para o sistema com IPI_WATCHDOG_TIMEOUT (frequência,
/// contador corrente, contador do início, 0), os parâmetros do NT.
pub fn ipi_stall_bug_check(stall: &IpiStall, what: &str) -> ! {
    debug_print!(
        "*** IPI SEM RESPOSTA ({}): processadores {:#x} pendentes depois de {} ms (contador {:#x} -> {:#x}, {} Hz)",
        what,
        stall.pending,
        stall.elapsed_ms(),
        stall.start,
        stall.current,
        stall.frequency
    );
    bugcheck::bug_check_ex(IPI_WATCHDOG_TIMEOUT, stall.frequency, stall.current, stall.start, 0)
}

/// O bit deste processador (o número da KPRCB; 0 antes da KPCR do BSP).
fn own_processor_bit() -> u64 {
    let number = if pcr::get_pcr_address() != 0 { pcr::current().prcb.number.get() } else { 0 };
    1 << (number & 63)
}

/// Espera, em tempo, a entrega do comando anterior (o bit DeliveryStatus
/// do ICR deste processador volta a ocioso).
fn wait_for_interrupt_delivery() -> Result<(), IpiStall> {
    stall_on_targets(INTERRUPT_DELIVERY_TIMEOUT_MS, || if lapic::read(LAPIC_COMMAND_LOW) & 0x1000 != 0 { own_processor_bit() } else { 0 })
}

/// Um identificador x2APIC acima de 255 não pode ser truncado e enviado a
/// outro processador pelo xAPIC (`Ok(false)`); um ICR que não fica ocioso no
/// prazo é o atraso.
fn send_processor_interrupt(identifier: u32, command_low: u32) -> Result<bool, IpiStall> {
    if identifier > 255 {
        return Ok(false);
    }
    wait_for_interrupt_delivery()?;
    lapic::write(LAPIC_COMMAND_HIGH, identifier << 24);
    lapic::write(LAPIC_COMMAND_LOW, command_low);
    wait_for_interrupt_delivery()?;
    Ok(true)
}

/// Envio da partida dos APs: a falha vira erro do boot.
fn send_startup_interrupt(identifier: u32, command_low: u32) -> bool {
    matches!(send_processor_interrupt(identifier, command_low), Ok(true))
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
    // Topo da pilha de boot do AP pela VA do mapa direto (o AP já está em
    // 64 bits quando a carrega).
    physical::write64(MAILBOX + MAILBOX_BOOT_STACK, map::direct_map(map::AP_STACK_BASE + (slot as u64 + 1) * map::AP_STACK_SIZE));

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
    if let Err(error) = install_trampoline() {
        (1..=identifiers.len() as u32).for_each(pcr::release_processor);
        return Err(error);
    }
    lapic::write(LAPIC_SPURIOUS, lapic::read(LAPIC_SPURIOUS) | 0x100);

    let flags = cpu::save_and_disable_interrupts();
    let mut online = Vec::new();
    let mut failure = None;
    for (slot, &identifier) in identifiers.iter().enumerate() {
        physical::write64(MAILBOX + MAILBOX_BOOT_PCR, processor_blocks[online.len()]);
        match start_application_processor(slot, identifier) {
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
    {
        let mut state = STATE.lock();
        state.online_slots = online;
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
/// geração de invalidação; `flush_caches` pede WBINVD também. A espera é
/// medida em tempo ([`stall_on_targets`]): um processador que não confirma
/// em [`SHOOTDOWN_TIMEOUT_MS`] (ou um ICR que não fica ocioso) para o sistema
/// com o diagnóstico de IPI sem resposta, como o IPI_WATCHDOG_TIMEOUT do NT.
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
            match send_processor_interrupt(physical::read32(slot_address(slot) + SLOT_CONTROLLER_IDENTIFIER), 0x4400) {
                Ok(true) => {}
                Ok(false) => return Err(KernelError::new("TLB shootdown delivery failed")),
                Err(stall) => ipi_stall_bug_check(&stall, "entrega do shootdown de TLB"),
            }
        }
        // O processador de número N é o AP da N-ésima posição entre os online.
        let pending = || slots.iter().enumerate().filter(|&(_, &slot)| physical::read32(slot_address(slot) + 0x3C) != generation).fold(0u64, |mask, (index, _)| mask | 1 << (index + 1));
        if let Err(stall) = stall_on_targets(SHOOTDOWN_TIMEOUT_MS, pending) {
            ipi_stall_bug_check(&stall, "confirmacao do shootdown de TLB");
        }
        Ok(())
    })();
    cpu::restore_interrupts(flags);
    STATE.lock().invalidation_active = false;
    result
}
