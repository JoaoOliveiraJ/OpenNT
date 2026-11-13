//! A página KUSER_SHARED_DATA.
//!
//! O Windows mapeia 0xFFFFF78000000000 em todo espaço de endereço; o kernel
//! atualiza SharedSystemTime (+0x14) e TickCount (+0x320). Drivers do WDK
//! leem ali direto (KeQuerySystemTime/KeQueryTickCount são macros inline).

use core::sync::atomic::{AtomicU64, Ordering};

use super::paging::{self, MapOptions};
use super::pfn;
use crate::hal::{kmalloc, physical};
use crate::ntos::cm::state_separation;
use crate::ntos::ke::{clock, processor_information, smp};
use crate::rtl::time::UNIX_TO_NT_EPOCH_MILLISECONDS;
use crate::ntos::mm::guest_memory as guest;

pub const SHARED_USER_DATA_VA: u64 = 0xFFFF_F780_0000_0000;
const OFFSET_SYSTEM_TIME: u64 = 0x14;
const OFFSET_TICK_COUNT: u64 = 0x320;
const OFFSET_NT_BUILD_NUMBER: u64 = 0x260;
const OFFSET_NT_MAJOR_VERSION: u64 = 0x26C;
const OFFSET_NT_MINOR_VERSION: u64 = 0x270;
const OFFSET_OS_PRODUCT_TYPE: u64 = 0x264;
const OFFSET_SUITE_MASK: u64 = 0x2D0;
const OFFSET_KD_DEBUGGER_ENABLED: u64 = 0x2D4;
const OFFSET_SAFE_BOOT_MODE: u64 = 0x2EC;
const OFFSET_SHARED_DATA_FLAGS: u64 = 0x2F0; // bit 10 = DbgStateSeparationEnabled
/// Célula lida pela atualização preemptiva no caminho nativo do timer.
const SHARED_FRAME_CELL: u64 = 0x81530;

static SHARED_FRAME: AtomicU64 = AtomicU64::new(0);

pub fn frame() -> u64 {
    SHARED_FRAME.load(Ordering::Relaxed)
}

fn write_shared_time(offset: u64, value: u64) {
    let frame = frame();
    let high = (value >> 32) as u32;
    guest::write32(frame + offset + 8, high);
    guest::write32(frame + offset, value as u32);
    guest::write32(frame + offset + 4, high);
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
    guest::write32(frame + 4, 0x100_0000); // ticks em ms, multiplicador 1.0
    // O Ldr da ntdll forma caminhos a partir de NtSystemRoot.
    for (index, unit) in "C:\\Windows".encode_utf16().enumerate() {
        guest::write16(frame + 0x30 + index as u64 * 2, unit);
    }
    // Versão compatível com o Windows 10 que o kernel implementa.
    guest::write32(frame + OFFSET_NT_BUILD_NUMBER, 26100);
    guest::write32(frame + OFFSET_NT_MAJOR_VERSION, 10);
    guest::write32(frame + OFFSET_NT_MINOR_VERSION, 0);
    guest::write32(frame + OFFSET_OS_PRODUCT_TYPE, 1); // WinNt
    guest::write8(frame + 0x268, 1); // ProductTypeIsValid
    guest::write16(frame + 0x26A, 9); // PROCESSOR_ARCHITECTURE_AMD64
    if let Ok(cpu) = processor_information::snapshot() {
        guest::write16(frame + 0x24A, cpu.level);
        guest::write16(frame + 0x24C, cpu.revision);
        guest::write_bytes(frame + 0x274, &cpu.features);
    }
    guest::write32(frame + OFFSET_SUITE_MASK, 0x110);
    guest::write32(frame + 0x2E8, (kmalloc::ram_top() / 0x1000) as u32);
    guest::write32(frame + 0x3C0, smp::online_cpu_count() as u32);
    guest::write8(frame + 0x3C4, 1); // um grupo de processadores
    guest::write64(frame + 0x300, clock::tsc_frequency_hz());
    guest::write8(frame + OFFSET_KD_DEBUGGER_ENABLED, 0);
    guest::write8(frame + OFFSET_SAFE_BOOT_MODE, 0); // boot normal
    // A ntdll consulta este bit pelo alias somente leitura em 0x7FFE0000.
    let separation = state_separation::is_enabled().unwrap_or(false) as u32;
    guest::write32(frame + OFFSET_SHARED_DATA_FLAGS, separation << 10);
    update_system_times();
    debug_print!("[mm] KUSER_SHARED_DATA mapeada (frame {:#x})", frame);
    true
}

/// Chamado a cada volta do kernel: mantém o relógio compartilhado.
pub fn update_system_times() {
    if frame() == 0 {
        return;
    }
    let uptime = clock::uptime_ms();
    write_shared_time(0x08, uptime * 10_000);
    write_shared_time(OFFSET_SYSTEM_TIME, (clock::now_ms() + UNIX_TO_NT_EPOCH_MILLISECONDS) * 10_000);
    write_shared_time(OFFSET_TICK_COUNT, uptime);
}
