//! O escritor preguiçoso do Registro (o CmpLazyFlush do NT) e a descarga do
//! desligamento (CmShutdownSystem).
//!
//! Como no ntoskrnl 19041:
//! - uma hive que fica suja (HvpMarkDirty / HvMarkBaseBlockDirty) arma o
//!   escritor de descarga (CmpArmLazyWriter, rva 0x2d87f0, com o índice 0):
//!   se ele está parado, o KTIMER dele vence em CmpLazyFlushIntervalInSeconds
//!   (60 s); armado expedito, em 2 s. O escritor só arma depois de
//!   inicializado (CmpWorkerDataInitialized) e sem retenção
//!   (CmpHoldLazyFlush);
//! - a DPC do timer (CmpLazyFlushDpcRoutine) acorda o trabalhador, que
//!   descarrega as hives sujas (CmpDoFlushNextHive), menos as carregadas
//!   com REG_NO_LAZY_FLUSH, e volta a armar se ainda há hive suja
//!   (CmpCompleteLazyWrite);
//! - o CmpCmdInit inicializa os escritores e arma o timer do atraso do boot
//!   (CmpEnableLazyFlushBootDelayInterval, 60 s), cuja DPC
//!   (CmpEnableLazyFlushDpcRoutine) tira a retenção do boot
//!   (CmpEnableLazyFlush com o bit 1, que arma o escritor expedito);
//! - o CmShutdownSystem para os trabalhadores (CmpShutdownWorkers) e
//!   descarrega cada hive ativa (CmpFlushHive).
//!
//! No 19041 cada escritor tem uma thread do Registro que espera o evento
//! que a DPC sinaliza (CmpLazyWriteWorker); aqui o trabalhador é um work
//! item do sistema (DelayedWorkQueue), que só roda com nenhuma outra
//! descarga em curso. Nenhuma thread fica girando: entre uma descarga e o
//! próximo prazo nada roda.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::ntos::cm::{hive_list, registry};
use crate::ntos::inc::types::{Kdpc, Ktimer, NtStruct};
use crate::ntos::io::work_items;
use crate::ntos::ke::{dpc, timer};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

/// CmpLazyFlushIntervalInSeconds e o prazo do escritor expedito.
pub const LAZY_FLUSH_INTERVAL_SECONDS: u64 = 60;
const EXPEDITED_100NS: i64 = 20_000_000;
/// CmpEnableLazyFlushBootDelayInterval.
pub const BOOT_DELAY_SECONDS: u64 = 60;
/// O bit de retenção do boot em CmpHoldLazyFlush.
pub const HOLD_BOOT: u32 = 1;
/// A retenção pedida por CmSetLazyFlushState(FALSE).
pub const HOLD_DISABLED: u32 = 2;

#[derive(Clone, Copy, PartialEq, Eq)]
enum WriterState {
    Idle,
    Armed,
    Running,
}

struct Writer {
    initialized: bool,
    /// CmpHoldLazyFlush.
    hold: u32,
    state: WriterState,
    /// KTIMER, KDPC e o work item do escritor; KTIMER e KDPC do atraso do
    /// boot.
    timer: u64,
    dpc: u64,
    work_item: u64,
    boot_timer: u64,
    boot_dpc: u64,
}

static WRITER: SpinLock<Writer> = SpinLock::new(Writer { initialized: false, hold: HOLD_BOOT, state: WriterState::Idle, timer: 0, dpc: 0, work_item: 0, boot_timer: 0, boot_dpc: 0 });
/// Passadas completas do trabalhador.
static PASSES: AtomicU32 = AtomicU32::new(0);

/// CmpCmdInit: os objetos do escritor e o timer do atraso do boot. Uma
/// segunda chamada não faz nada.
pub fn initialize() {
    let (boot_timer, boot_dpc) = {
        let mut writer = WRITER.lock();
        if writer.initialized {
            return;
        }
        let blocks = [Ktimer::SIZE, Kdpc::SIZE, work_items::work_item_size(), Ktimer::SIZE, Kdpc::SIZE].map(guest::alloc_bytes);
        if blocks.contains(&0) {
            for block in blocks.into_iter().filter(|&block| block != 0) {
                guest::free_bytes(block);
            }
            return;
        }
        let [lazy_timer, lazy_dpc, work_item, boot_timer, boot_dpc] = blocks;
        timer::initialize_notification_timer(lazy_timer);
        dpc::initialize_kernel_dpc(lazy_dpc, lazy_flush_dpc, 0);
        work_items::create_work_item(0, work_item);
        timer::initialize_notification_timer(boot_timer);
        dpc::initialize_kernel_dpc(boot_dpc, enable_lazy_flush_dpc, 0);
        writer.timer = lazy_timer;
        writer.dpc = lazy_dpc;
        writer.work_item = work_item;
        writer.boot_timer = boot_timer;
        writer.boot_dpc = boot_dpc;
        writer.initialized = true;
        (boot_timer, boot_dpc)
    };
    registry::set_dirty_observer(Some(hive_dirtied));
    timer::set_timer(boot_timer, -((BOOT_DELAY_SECONDS * 10_000_000) as i64), boot_dpc, 0);
}

/// HvpMarkDirty: uma hive limpa ficou suja.
fn hive_dirtied() {
    arm(false);
}

/// CmpArmLazyWriter do escritor de descarga.
pub fn arm(expedited: bool) {
    let mut writer = WRITER.lock();
    if !writer.initialized || writer.hold != 0 {
        return;
    }
    let due = if expedited { -EXPEDITED_100NS } else { -((LAZY_FLUSH_INTERVAL_SECONDS * 10_000_000) as i64) };
    match writer.state {
        WriterState::Idle => {
            writer.state = WriterState::Armed;
            timer::set_timer(writer.timer, due, writer.dpc, 0);
        }
        // Expedito sobre um prazo longo: o timer é refeito com 2 s.
        WriterState::Armed if expedited => {
            timer::set_timer(writer.timer, due, writer.dpc, 0);
        }
        _ => {}
    }
}

/// CmpLazyFlushDpcRoutine: o trabalhador entra na fila do sistema.
fn lazy_flush_dpc(_dpc: u64, _context: u64, _first: u64, _second: u64) {
    let work_item = WRITER.lock().work_item;
    if work_item != 0 {
        work_items::queue_kernel_work_item(work_item, lazy_flush_worker, 0, Some(no_flush_in_progress));
    }
}

fn no_flush_in_progress() -> bool {
    !hive_list::flush_in_progress()
}

/// CmpLazyWriteWorker / CmpDoFlushNextHive / CmpCompleteLazyWrite.
fn lazy_flush_worker(_device: u64, _context: u64) {
    {
        let mut writer = WRITER.lock();
        if writer.state != WriterState::Armed {
            return;
        }
        writer.state = WriterState::Running;
    }
    let pass = hive_list::lazy_flush_pass();
    WRITER.lock().state = WriterState::Idle;
    match pass {
        // Outra descarga estava em curso: tenta de novo logo.
        None => arm(true),
        Some(_) => {
            PASSES.fetch_add(1, Ordering::AcqRel);
            // Uma hive que sujou durante a passada arma de novo.
            if hive_list::lazy_flush_pending() {
                arm(false);
            }
        }
    }
}

/// CmpEnableLazyFlushDpcRoutine: o fim do atraso do boot.
fn enable_lazy_flush_dpc(_dpc: u64, _context: u64, _first: u64, _second: u64) {
    enable(HOLD_BOOT);
}

/// CmpEnableLazyFlush: tira os bits de retenção; a última retenção que sai
/// arma o escritor expedito.
pub fn enable(mask: u32) {
    let released = {
        let mut writer = WRITER.lock();
        let before = writer.hold;
        writer.hold &= !mask;
        before != 0 && writer.hold == 0
    };
    if released {
        arm(true);
    }
}

/// CmpDisableLazyFlush: põe a retenção e cancela o prazo armado.
pub fn disable(mask: u32) {
    let mut writer = WRITER.lock();
    writer.hold |= mask;
    if writer.state == WriterState::Armed {
        timer::cancel_timer(writer.timer);
        writer.state = WriterState::Idle;
    }
}

/// Passadas completas do trabalhador desde o boot.
pub fn passes() -> u32 {
    PASSES.load(Ordering::Acquire)
}

/// O escritor está armado (o timer corre).
pub fn armed() -> bool {
    WRITER.lock().state == WriterState::Armed
}

/// CmShutdownSystem: o escritor para (CmpShutdownWorkers) e cada hive de
/// arquivo vai para o disco (CmpFlushHive).
pub fn shutdown() -> u32 {
    {
        let mut writer = WRITER.lock();
        writer.hold |= HOLD_DISABLED;
        if writer.initialized {
            timer::cancel_timer(writer.timer);
            timer::cancel_timer(writer.boot_timer);
        }
        writer.state = WriterState::Idle;
    }
    let status = hive_list::flush_all();
    crate::debug_print!("[cm] desligamento: hives descarregadas ({:#x})", status);
    status
}
