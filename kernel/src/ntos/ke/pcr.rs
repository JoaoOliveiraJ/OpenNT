//! PCR do processador de boot.
//!
//! Memória virtual do kernel com páginas físicas próprias, publicada em
//! IA32_GS_BASE. Os campos são os da `Kpcr` gerada dos símbolos (a KPRCB
//! embutida em +0x180, a LockQueue dentro dela) e seu CurrentThread
//! acompanha as trocas de thread do runtime.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::{cpu, physical};
use crate::hal::amd64::native_call;
use crate::ntos::inc::types::{Kpcr, NtStruct};
use crate::ntos::mm::paging::{self, MapOptions};
use crate::ntos::mm::{kernel_address, memory_map as map, pfn};
use crate::rtl::{KernelError, SpinLock};

/// Offsets da KPCR/KPRCB (derivados dos tipos gerados) para quem ainda lê
/// por deslocamento; a reserva de 0xC000 bytes cobre a KPCR de 0xB080.
pub mod layout {
    use core::mem::offset_of;

    use crate::ntos::inc::types::{Kpcr, KpcrView1, Kprcb};

    pub const GDT_BASE: u64 = offset_of!(KpcrView1, gdt_base) as u64;
    pub const TSS_BASE: u64 = offset_of!(KpcrView1, tss_base) as u64;
    pub const USER_RSP: u64 = offset_of!(KpcrView1, user_rsp) as u64;
    pub const SELF: u64 = offset_of!(KpcrView1, self_) as u64;
    pub const CURRENT_PRCB: u64 = offset_of!(KpcrView1, current_prcb) as u64;
    pub const LOCK_ARRAY: u64 = offset_of!(KpcrView1, lock_array) as u64;
    pub const USED_SELF: u64 = offset_of!(KpcrView1, used_self) as u64;
    pub const IDT_BASE: u64 = offset_of!(Kpcr, idt_base) as u64;
    pub const IRQL: u64 = offset_of!(Kpcr, irql) as u64;
    pub const MAJOR_VERSION: u64 = offset_of!(Kpcr, major_version) as u64;
    pub const MINOR_VERSION: u64 = offset_of!(Kpcr, minor_version) as u64;
    pub const STALL_SCALE_FACTOR: u64 = offset_of!(Kpcr, stall_scale_factor) as u64;
    pub const PRCB: u64 = offset_of!(Kpcr, prcb) as u64;
    pub const PRCB_MXCSR: u64 = PRCB + offset_of!(Kprcb, mx_csr) as u64;
    pub const PRCB_CURRENT_THREAD: u64 = PRCB + offset_of!(Kprcb, current_thread) as u64;
    pub const PRCB_NEXT_THREAD: u64 = PRCB + offset_of!(Kprcb, next_thread) as u64;
    pub const PRCB_IDLE_THREAD: u64 = PRCB + offset_of!(Kprcb, idle_thread) as u64;
    pub const PRCB_NESTING_LEVEL: u64 = PRCB + offset_of!(Kprcb, nesting_level) as u64;
    pub const PRCB_NUMBER: u64 = PRCB + offset_of!(Kprcb, number) as u64;
    pub const LOCK_QUEUE_ARRAY: u64 = PRCB + offset_of!(Kprcb, lock_queue) as u64;
    pub const PRCB_DPC_ROUTINE_ACTIVE: u64 = PRCB + offset_of!(Kprcb, dpc_routine_active) as u64;
    pub const PRCB_DPC_REQUEST_SUMMARY: u64 = PRCB + offset_of!(Kprcb, dpc_request_summary) as u64;
    pub const SIZE: u64 = 0xC000;

    const _: () = assert!(core::mem::size_of::<Kpcr>() as u64 <= SIZE);
}

/// KSPIN_LOCK_QUEUE_NUMBER das entradas com lock próprio.
const LOCK_QUEUE_NON_PAGED_POOL: usize = 6;
const LOCK_QUEUE_IO_VPB: usize = 9;
const LOCK_QUEUE_IO_DATABASE: usize = 10;

const GS_BASE_MSR: u32 = 0xC000_0101;
/// GDTR do stage2 publicado no handoff (limite em +0, base de 32 bits em +2).
const DESCRIPTOR_TABLE_REGISTER_CELL: u64 = map::BOOT_GDTR_PHYS;

struct Pcr {
    address: u64,
    backing_pages: Vec<u64>,
    io_database_lock: u64,
    vpb_lock: u64,
}

static PCR: SpinLock<Pcr> = SpinLock::new(Pcr { address: 0, backing_pages: Vec::new(), io_database_lock: 0, vpb_lock: 0 });
static ADDRESS: AtomicU64 = AtomicU64::new(0);

/// A KPCR publicada (nenhuma antes de `init`).
fn kpcr() -> Option<&'static Kpcr> {
    let address = PCR.lock().address;
    // SAFETY: as páginas da KPCR ficam mapeadas em PCR_VIRTUAL_BASE desde `init`.
    (address != 0).then(|| unsafe { Kpcr::at(address) })
}

/// Aloca e mapeia as páginas da PCR (com rollback), publica as referências
/// próprias, os campos iniciais e a GS base.
pub fn init() -> Result<(), KernelError> {
    let mut pcr = PCR.lock();
    if pcr.address != 0 {
        return Ok(());
    }
    let mut mapped = Vec::new();
    for offset in (0..layout::SIZE).step_by(0x1000) {
        let page = pfn::alloc_page();
        let address = map::PCR_VIRTUAL_BASE + offset;
        let ok = page != 0 && {
            pcr.backing_pages.push(page);
            physical::zero(page, 0x1000);
            paging::map_page(address, page, paging::PAGE_PRESENT | paging::PAGE_RW, MapOptions::default())
        };
        if !ok {
            for &address in &mapped {
                paging::unmap_page(address, MapOptions::default());
            }
            for &page in &pcr.backing_pages {
                pfn::free_page(page);
            }
            pcr.backing_pages.clear();
            return Err(KernelError::new(if page == 0 { "sem frames p/ a KPCR" } else { "mapeamento da KPCR falhou" }));
        }
        mapped.push(address);
    }
    pcr.address = map::PCR_VIRTUAL_BASE;
    let base = pcr.address;
    // SAFETY: as páginas recém-zeradas acabaram de ser mapeadas em `base`.
    let kpcr = unsafe { Kpcr::at(base) };

    // A GDT do stage2 continua a mesma; o GDTR (que o stage2 já carregou
    // assim) e a KPCR a alcançam pela VA do mapa direto.
    let gdt_limit = physical::read16(DESCRIPTOR_TABLE_REGISTER_CELL);
    let gdt_base = physical::to_virtual(physical::read32(DESCRIPTOR_TABLE_REGISTER_CELL + 2) as u64);
    cpu::load_gdt(gdt_base, gdt_limit);
    kpcr.gdt_base.set(gdt_base);
    // TssBase fica zerado; isso não descreve a TSS configurada em outras camadas.
    kpcr.tss_base.set(0);
    kpcr.self_.set(base);
    kpcr.current_prcb.set(kpcr.prcb.address());
    let lock_queue = &kpcr.prcb.lock_queue;
    kpcr.lock_array.set(lock_queue[0].address());
    // Como o KiInitSpinLocks: toda entrada da LockQueue aponta para um
    // KSPIN_LOCK global; as do pool, da VPB e da base de I/O vêm em seguida.
    for (number, entry) in lock_queue.iter().enumerate() {
        let lock = kernel_address::image_address(QUEUED_SPIN_LOCKS.as_ptr() as u64 + number as u64 * 8)?;
        entry.next.set(0);
        entry.lock.set(lock);
    }
    // LockQueueNonPagedPoolLock recebe o lock real do alocador.
    let pool_lock = kernel_address::image_address(native_call::non_paged_pool_lock_address())?;
    lock_queue[LOCK_QUEUE_NON_PAGED_POOL].lock.set(pool_lock);
    if pcr.io_database_lock != 0 {
        lock_queue[LOCK_QUEUE_IO_DATABASE].lock.set(pcr.io_database_lock);
    }
    if pcr.vpb_lock != 0 {
        lock_queue[LOCK_QUEUE_IO_VPB].lock.set(pcr.vpb_lock);
    }
    kpcr.used_self.set(base);
    kpcr.idt_base.set(crate::nano::interrupts::IDT_VIRTUAL_ADDRESS);
    kpcr.irql.set(0);
    kpcr.major_version.set(1);
    kpcr.minor_version.set(1);
    kpcr.prcb.mx_csr.set(0x1F80);
    kpcr.prcb.number.set(0);
    drop(pcr);

    // Só depois de materializar os campos ativa a PCR como base de GS.
    cpu::write_msr(GS_BASE_MSR, base);
    ADDRESS.store(base, Ordering::Release);
    debug_print!("[pcr] KPCR em {:#x} — GS base ativa (IA32_GS_BASE)", base);
    Ok(())
}

pub fn set_current_thread(thread: u64) {
    if let Some(kpcr) = kpcr() {
        kpcr.prcb.current_thread.set(thread);
    }
}

pub fn set_irql(level: u8) {
    if let Some(kpcr) = kpcr() {
        kpcr.irql.set(level);
    }
}

pub fn get_pcr_address() -> u64 {
    ADDRESS.load(Ordering::Acquire)
}

/// KeQueryPrcbAddress: entrada de KiProcessorBlock — a KPRCB embutida na
/// KPCR de cada processador que tem uma (o OpenNT publica a do processador
/// de boot); sem KPRCB, NULL.
pub fn query_prcb_address(number: u32) -> u64 {
    let base = get_pcr_address();
    if number == 0 && base != 0 { base + layout::PRCB } else { 0 }
}

pub fn set_io_database_lock(pointer: u64) {
    PCR.lock().io_database_lock = pointer;
    if let Some(kpcr) = kpcr() {
        kpcr.prcb.lock_queue[LOCK_QUEUE_IO_DATABASE].lock.set(pointer);
    }
}

/// LockQueueMaximumLock.
pub const LOCK_QUEUE_MAXIMUM: u64 = 17;

/// Os KSPIN_LOCK globais das entradas da LockQueue sem lock de dono.
static QUEUED_SPIN_LOCKS: [AtomicU64; LOCK_QUEUE_MAXIMUM as usize] = [const { AtomicU64::new(0) }; LOCK_QUEUE_MAXIMUM as usize];

/// O KSPIN_LOCK da entrada `number` da LockQueue (sem os bits de dono e de
/// espera).
pub fn queued_spin_lock(number: u64) -> Option<u64> {
    if number >= LOCK_QUEUE_MAXIMUM {
        return None;
    }
    kpcr().map(|kpcr| kpcr.prcb.lock_queue[number as usize].lock.get() & !3).filter(|&lock| lock != 0)
}

pub fn set_io_vpb_lock(pointer: u64) {
    PCR.lock().vpb_lock = pointer;
    if let Some(kpcr) = kpcr() {
        kpcr.prcb.lock_queue[LOCK_QUEUE_IO_VPB].lock.set(pointer);
    }
}

pub fn get_nesting_level() -> u8 {
    kpcr().map_or(0, |kpcr| kpcr.prcb.nesting_level.get())
}

pub fn get_dpc_request_summary() -> u32 {
    kpcr().map_or(0, |kpcr| kpcr.prcb.dpc_request_summary.get() as u32)
}

/// Campos que `enter_dpc` altera, para restaurar depois do callback.
#[derive(Clone, Copy, Debug)]
pub struct DpcState {
    pub nesting: u8,
    pub active: u32,
    pub routine: u8,
}

/// Publica que uma DPC está em execução.
pub fn enter_dpc() -> Result<DpcState, KernelError> {
    if get_pcr_address() == 0 {
        return Err(KernelError::new("DPC dispatch requires initialized PCR"));
    }
    let Some(kpcr) = kpcr() else { return Err(KernelError::new("DPC dispatch requires initialized PCR")) };
    let prcb = &kpcr.prcb;
    let previous = DpcState {
        nesting: prcb.nesting_level.get(),
        active: prcb.dpc_request_summary.get() as u32 & 1,
        routine: prcb.dpc_routine_active.get(),
    };
    prcb.nesting_level.set(1);
    // DpcRequestSummary bit 0 (DpcNormalProcessingActive): LOCK OR, como o
    // NT, porque outras CPUs pedem DPCs no mesmo DWORD.
    prcb.dpc_request_summary.atomic().fetch_or(1, Ordering::SeqCst);
    prcb.dpc_routine_active.set(1);
    Ok(previous)
}

/// Restaura rotina ativa, bit de atividade e aninhamento.
pub fn leave_dpc(previous: DpcState) {
    let Some(kpcr) = kpcr() else { return };
    let prcb = &kpcr.prcb;
    prcb.dpc_routine_active.set(previous.routine);
    if previous.active == 0 {
        prcb.dpc_request_summary.atomic().fetch_and(!1, Ordering::SeqCst);
    } else {
        prcb.dpc_request_summary.atomic().fetch_or(1, Ordering::SeqCst);
    }
    prcb.nesting_level.set(previous.nesting);
}
