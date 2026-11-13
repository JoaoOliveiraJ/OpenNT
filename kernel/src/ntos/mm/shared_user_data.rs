//! A página KUSER_SHARED_DATA.
//!
//! O Windows mapeia 0xFFFFF78000000000 em todo espaço de endereço; o kernel
//! atualiza SystemTime, InterruptTime e TickCount. Drivers do WDK
//! leem ali direto (KeQuerySystemTime/KeQueryTickCount são macros inline).

use core::sync::atomic::{AtomicU64, Ordering};

use super::paging::{self, MapOptions};
use super::pfn;
use crate::hal::{kmalloc, physical};
use crate::ntos::cm::state_separation;
use crate::ntos::ke::{clock, processor_information, smp};
use crate::rtl::time::UNIX_TO_NT_EPOCH_MILLISECONDS;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{KsystemTime, KuserSharedData, NtProductType};

pub const SHARED_USER_DATA_VA: u64 = 0xFFFF_F780_0000_0000;
/// Célula lida pela atualização preemptiva no caminho nativo do timer.
const SHARED_FRAME_CELL: u64 = 0x81530;
/// SharedDataFlags.DbgStateSeparationEnabled.
const DBG_STATE_SEPARATION_ENABLED_SHIFT: u32 = 10;

static SHARED_FRAME: AtomicU64 = AtomicU64::new(0);

pub fn frame() -> u64 {
    SHARED_FRAME.load(Ordering::Relaxed)
}

/// A KUSER_SHARED_DATA pelo frame (alias de identidade da página).
fn shared(frame: u64) -> &'static KuserSharedData {
    // SAFETY: frame próprio da página compartilhada, mapeado por identidade.
    unsafe { KuserSharedData::at(frame) }
}

/// Protocolo do KSYSTEM_TIME: High2Time, LowPart e por último High1Time;
/// leitores repetem enquanto High1Time != High2Time.
fn write_shared_time(time: &KsystemTime, value: u64) {
    let high = (value >> 32) as i32;
    time.high2_time.set(high);
    time.low_part.set(value as u32);
    time.high1_time.set(high);
}

pub fn init() -> bool {
    let frame = pfn::alloc_page();
    if frame == 0 {
        debug_print!("[mm] FALHA: sem frame p/ shared user data");
        return false;
    }
    physical::zero(frame, 0x1000);
    SHARED_FRAME.store(frame, Ordering::Relaxed);
    if !paging::map_page(SHARED_USER_DATA_VA, frame, paging::PAGE_PRESENT | paging::PAGE_RW, MapOptions::default()) {
        debug_print!("[mm] FALHA: map shared user data");
        return false;
    }
    physical::write32(SHARED_FRAME_CELL, frame as u32);
    let data = shared(frame);
    data.tick_count_multiplier.set(0x100_0000); // ticks em ms, multiplicador 1.0
    // O Ldr da ntdll forma caminhos a partir de NtSystemRoot.
    for (character, unit) in data.nt_system_root.iter().zip("C:\\Windows".encode_utf16()) {
        character.set(unit);
    }
    // Versão compatível com o Windows 10 que o kernel implementa.
    data.nt_build_number.set(26100);
    data.nt_major_version.set(10);
    data.nt_minor_version.set(0);
    data.nt_product_type.set(NtProductType::NT_PRODUCT_WIN_NT);
    data.product_type_is_valid.set(1);
    data.native_processor_architecture.set(9); // PROCESSOR_ARCHITECTURE_AMD64
    // Nível e revisão do processador não fazem parte desta página no 19041
    // (vêm de SystemProcessorInformation); só os recursos são publicados.
    if let Ok(cpu) = processor_information::snapshot() {
        guest::write_bytes(data.processor_features[0].address(), &cpu.features);
    }
    data.suite_mask.set(0x110);
    data.number_of_physical_pages.set((kmalloc::ram_top() / 0x1000) as u32);
    data.active_processor_count.set(smp::online_cpu_count() as u32);
    data.active_group_count.set(1); // um grupo de processadores
    data.qpc_frequency.set(clock::tsc_frequency_hz() as i64);
    data.kd_debugger_enabled.set(0);
    data.safe_boot_mode.set(0); // boot normal
    // A ntdll consulta este bit pelo alias somente leitura em 0x7FFE0000.
    let separation = state_separation::is_enabled().unwrap_or(false) as u32;
    data.shared_data_flags.set(separation << DBG_STATE_SEPARATION_ENABLED_SHIFT);
    update_system_times();
    debug_print!("[mm] KUSER_SHARED_DATA mapeada (frame {:#x})", frame);
    true
}

/// Chamado a cada volta do kernel: mantém o relógio compartilhado.
pub fn update_system_times() {
    let frame = frame();
    if frame == 0 {
        return;
    }
    let data = shared(frame);
    let uptime = clock::uptime_ms();
    write_shared_time(&data.interrupt_time, uptime * 10_000);
    write_shared_time(&data.system_time, (clock::now_ms() + UNIX_TO_NT_EPOCH_MILLISECONDS) * 10_000);
    write_shared_time(&data.tick_count, uptime);
}
