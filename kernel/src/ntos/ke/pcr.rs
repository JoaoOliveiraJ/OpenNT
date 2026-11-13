//! PCR do processador de boot — `system32/ntos/ke/pcr.js`.
//!
//! Memória virtual do kernel com páginas físicas próprias, publicada em
//! IA32_GS_BASE. A PRCB embutida começa em +0x180 e seu CurrentThread
//! acompanha as trocas de thread do runtime.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::{cpu, physical};
use crate::hal::amd64::native_call;
use crate::ntos::mm::paging::{self, MapOptions};
use crate::ntos::mm::{kernel_address, memory_map as map, pfn};
use crate::rtl::{KernelError, SpinLock};

/// Offsets do layout x64 (a reserva de 0xC000 bytes cobre a PCR e a KPRCB 19041).
pub mod layout {
    pub const GDT_BASE: u64 = 0x00;
    pub const TSS_BASE: u64 = 0x08;
    pub const USER_RSP: u64 = 0x10;
    pub const SELF: u64 = 0x18;
    pub const CURRENT_PRCB: u64 = 0x20;
    pub const LOCK_ARRAY: u64 = 0x28;
    pub const USED_SELF: u64 = 0x30;
    pub const IDT_BASE: u64 = 0x38;
    pub const IRQL: u64 = 0x50;
    pub const MAJOR_VERSION: u64 = 0x60;
    pub const MINOR_VERSION: u64 = 0x62;
    pub const STALL_SCALE_FACTOR: u64 = 0x64;
    pub const PRCB: u64 = 0x180;
    pub const PRCB_MXCSR: u64 = PRCB;
    pub const PRCB_CURRENT_THREAD: u64 = PRCB + 0x08;
    pub const PRCB_NEXT_THREAD: u64 = PRCB + 0x10;
    pub const PRCB_IDLE_THREAD: u64 = PRCB + 0x18;
    pub const PRCB_NESTING_LEVEL: u64 = PRCB + 0x20;
    pub const PRCB_NUMBER: u64 = PRCB + 0x24;
    pub const LOCK_QUEUE_ARRAY: u64 = PRCB + 0x300;
    pub const PRCB_DPC_ROUTINE_ACTIVE: u64 = PRCB + 0x312A;
    pub const PRCB_DPC_REQUEST_SUMMARY: u64 = PRCB + 0x312C;
    pub const SIZE: u64 = 0xC000;
}

const GS_BASE_MSR: u32 = 0xC000_0101;
const INTERRUPT_TABLE_PHYSICAL_ADDRESS: u64 = 0x82000;
const DESCRIPTOR_TABLE_BASE_CELL: u64 = 0x4FEA;

struct Pcr {
    address: u64,
    backing_pages: Vec<u64>,
    io_database_lock: u64,
    vpb_lock: u64,
}

static PCR: SpinLock<Pcr> = SpinLock::new(Pcr { address: 0, backing_pages: Vec::new(), io_database_lock: 0, vpb_lock: 0 });
static ADDRESS: AtomicU64 = AtomicU64::new(0);

/// Offset do corpo -> endereço físico na página de respaldo.
fn field(pages: &[u64], offset: u64) -> u64 {
    pages[(offset / 0x1000) as usize] + offset % 0x1000
}

fn with_field<T>(offset: u64, body: impl FnOnce(u64) -> T) -> Option<T> {
    let pcr = PCR.lock();
    if pcr.address == 0 {
        return None;
    }
    let at = field(&pcr.backing_pages, offset);
    drop(pcr);
    Some(body(at))
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
    let pages = pcr.backing_pages.clone();
    let at = |offset: u64| field(&pages, offset);

    physical::write64(at(layout::GDT_BASE), physical::read32(DESCRIPTOR_TABLE_BASE_CELL) as u64);
    // TssBase fica zerado; isso não descreve a TSS configurada em outras camadas.
    physical::write64(at(layout::TSS_BASE), 0);
    physical::write64(at(layout::SELF), base);
    physical::write64(at(layout::CURRENT_PRCB), base + layout::PRCB);
    physical::write64(at(layout::LOCK_ARRAY), base + layout::LOCK_QUEUE_ARRAY);
    // Como o KiInitSpinLocks: toda entrada da LockQueue aponta para um
    // KSPIN_LOCK global; as do pool, da VPB e da base de I/O vêm em seguida.
    for number in 0..LOCK_QUEUE_MAXIMUM {
        let lock = kernel_address::virtual_address(QUEUED_SPIN_LOCKS.as_ptr() as u64 + number * 8)?;
        physical::write64(at(layout::LOCK_QUEUE_ARRAY + number * 16), 0);
        physical::write64(at(layout::LOCK_QUEUE_ARRAY + number * 16 + 8), lock);
    }
    // LockQueueNonPagedPoolLock é a entrada seis; seu Lock (+8) recebe o lock
    // real do alocador.
    let pool_lock = kernel_address::virtual_address(native_call::non_paged_pool_lock_address())?;
    physical::write64(at(layout::LOCK_QUEUE_ARRAY + 6 * 16 + 8), pool_lock);
    if pcr.io_database_lock != 0 {
        physical::write64(at(layout::LOCK_QUEUE_ARRAY + 10 * 16 + 8), pcr.io_database_lock);
    }
    if pcr.vpb_lock != 0 {
        physical::write64(at(layout::LOCK_QUEUE_ARRAY + 9 * 16 + 8), pcr.vpb_lock);
    }
    physical::write64(at(layout::USED_SELF), base);
    physical::write64(at(layout::IDT_BASE), INTERRUPT_TABLE_PHYSICAL_ADDRESS);
    physical::write8(at(layout::IRQL), 0);
    physical::write16(at(layout::MAJOR_VERSION), 1);
    physical::write16(at(layout::MINOR_VERSION), 1);
    physical::write32(at(layout::PRCB_MXCSR), 0x1F80);
    physical::write32(at(layout::PRCB_NUMBER), 0);
    drop(pcr);

    // Só depois de materializar os campos ativa a PCR como base de GS.
    cpu::write_msr(GS_BASE_MSR, base);
    ADDRESS.store(base, Ordering::Release);
    debug_print!("[pcr] KPCR em {:#x} — GS base ativa (IA32_GS_BASE)", base);
    Ok(())
}

pub fn set_current_thread(thread: u64) {
    with_field(layout::PRCB_CURRENT_THREAD, |at| physical::write64(at, thread));
}

pub fn set_irql(level: u8) {
    with_field(layout::IRQL, |at| physical::write8(at, level));
}

pub fn get_pcr_address() -> u64 {
    ADDRESS.load(Ordering::Acquire)
}

pub fn set_io_database_lock(pointer: u64) {
    PCR.lock().io_database_lock = pointer;
    with_field(layout::LOCK_QUEUE_ARRAY + 10 * 16 + 8, |at| physical::write64(at, pointer));
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
    with_field(layout::LOCK_QUEUE_ARRAY + number * 16 + 8, physical::read64).map(|lock| lock & !3).filter(|&lock| lock != 0)
}

pub fn set_io_vpb_lock(pointer: u64) {
    PCR.lock().vpb_lock = pointer;
    with_field(layout::LOCK_QUEUE_ARRAY + 9 * 16 + 8, |at| physical::write64(at, pointer));
}

pub fn get_nesting_level() -> u8 {
    with_field(layout::PRCB_NESTING_LEVEL, physical::read8).unwrap_or(0)
}

pub fn get_dpc_request_summary() -> u32 {
    with_field(layout::PRCB_DPC_REQUEST_SUMMARY, physical::read32).unwrap_or(0)
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
    let previous = DpcState {
        nesting: get_nesting_level(),
        active: get_dpc_request_summary() & 1,
        routine: with_field(layout::PRCB_DPC_ROUTINE_ACTIVE, physical::read8).unwrap_or(0),
    };
    let summary = get_dpc_request_summary();
    with_field(layout::PRCB_NESTING_LEVEL, |at| physical::write8(at, 1));
    with_field(layout::PRCB_DPC_REQUEST_SUMMARY, |at| physical::write32(at, summary | 1));
    with_field(layout::PRCB_DPC_ROUTINE_ACTIVE, |at| physical::write8(at, 1));
    Ok(previous)
}

/// Restaura rotina ativa, bit de atividade e aninhamento.
pub fn leave_dpc(previous: DpcState) {
    let summary = get_dpc_request_summary();
    with_field(layout::PRCB_DPC_ROUTINE_ACTIVE, |at| physical::write8(at, previous.routine));
    with_field(layout::PRCB_DPC_REQUEST_SUMMARY, |at| physical::write32(at, (summary & !1) | previous.active));
    with_field(layout::PRCB_NESTING_LEVEL, |at| physical::write8(at, previous.nesting));
}
