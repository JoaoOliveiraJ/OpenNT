//! Vista NT de um frame de interrupção de kernel real.
//!
//! Cada registrador gravável tem uma posição restaurada pelos stubs de IRQ
//! (IRETQ). Não é o CONTEXT do chamador do gateway e não inventa um PC
//! interrompido.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::ntos::ps::context::registers;
use crate::hal::cpu;
use crate::ntos::ke::irql;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::kthread::TRAP_FRAME;

/// HAL: seis empilhamentos não voláteis, nove voláteis, vetor e cinco
/// palavras de hardware. O RSP é o salvo pelo hardware.
const RAW: [u64; 16] = [112, 104, 96, 40, 152, 32, 88, 80, 72, 64, 56, 48, 24, 16, 8, 0];
const VOLATILE: [(u64, u64); 7] = [(0x78, 0x30), (0x80, 0x38), (0x88, 0x40), (0xB8, 0x48), (0xC0, 0x50), (0xC8, 0x58), (0xD0, 0x60)];
/// (offset no CONTEXT, slot de ponteiro, campo do trap quando houver).
const NONVOLATILE: [(u64, u64, Option<u64>); 8] = [(0x90, 0x98, Some(0x140)), (0xA0, 0xA8, Some(0x158)), (0xA8, 0xB0, Some(0x150)), (0xB0, 0xB8, Some(0x148)), (0xD8, 0xE0, None), (0xE0, 0xE8, None), (0xE8, 0xF0, None), (0xF0, 0xF8, None)];
const DEBUG: [u64; 6] = [0xD8, 0xE0, 0xE8, 0xF0, 0xF8, 0x100];

#[derive(Clone, Copy)]
struct Entry {
    thread: u64,
    trap: u64,
    context: u64,
    pointers: u64,
    controls: u64,
}

static ACTIVE: SpinLock<BTreeMap<u64, Vec<Entry>>> = SpinLock::new(BTreeMap::new());

fn copy(to: u64, from: u64, size: u64) {
    registers::copy(to, from, size);
}

fn control(to: u64, from: u64, reading: bool) {
    for (context, trap, size) in [(0xF8u64, 0x168u64, 8u64), (0x98, 0x180, 8), (0x38, 0x170, 2), (0x42, 0x188, 2), (0x44, 0x178, 4), (0x34, 0x2C, 4)] {
        let target = to + if reading { context } else { trap };
        let source = from + if reading { trap } else { context };
        match size {
            8 => copy(target, source, 8),
            4 => guest::write32(target, guest::read32(source)),
            _ => guest::write16(target, guest::read16(source)),
        }
    }
}

fn from_trap(entry: &Entry) {
    let Entry { context, trap, pointers, .. } = *entry;
    control(context, trap, true);
    for (offset, field) in VOLATILE {
        copy(context + offset, trap + field, 8);
    }
    for (offset, slot, _) in NONVOLATILE {
        copy(context + offset, guest::read64(pointers + slot), 8);
    }
    for index in 0..16u64 {
        copy(context + 0x1A0 + index * 16, if index < 6 { trap + 0x70 + index * 16 } else { guest::read64(pointers + index * 8) }, 16);
    }
    for (index, field) in DEBUG.iter().enumerate() {
        copy(context + 0x48 + index as u64 * 8, trap + field, 8);
    }
    guest::write32(context + 0x118, guest::read32(context + 0x34));
}

fn to_trap(entry: &Entry) {
    let Entry { context, trap, pointers, .. } = *entry;
    control(trap, context, false);
    for (offset, field) in VOLATILE {
        copy(trap + field, context + offset, 8);
    }
    for (offset, slot, _) in NONVOLATILE {
        copy(guest::read64(pointers + slot), context + offset, 8);
    }
    for index in 0..16u64 {
        copy(if index < 6 { trap + 0x70 + index * 16 } else { guest::read64(pointers + index * 8) }, context + 0x1A0 + index * 16, 16);
    }
    for (index, field) in DEBUG.iter().enumerate() {
        copy(trap + field, context + 0x48 + index as u64 * 8, 8);
    }
}

/// Expõe o frame de uma interrupção de kernel como KTRAP_FRAME/CONTEXT
/// durante `action` e devolve ao frame o que a ação alterou.
pub fn with_interrupt<R>(registers_frame: u64, fx: u64, cpu_state: u64, workspace: u64, action: impl FnOnce() -> R, hardware_offset: u64) -> Result<R, KernelError> {
    if hardware_offset != 0 && hardware_offset != 8 {
        return Err(KernelError::new("invalid hardware exception frame"));
    }
    let extra = hardware_offset;
    let raw: Vec<u64> = RAW.iter().enumerate().map(|(index, &offset)| offset + if index == 4 { hardware_offset } else { 0 }).collect();
    // Frames de usuário pertencem ao escalonador de usuário; o bootstrap
    // pode rodar antes de existir um ETHREAD.
    if guest::read16(registers_frame + 136 + extra) != 0x10 {
        return Ok(action());
    }
    let thread = process::get_current_thread();
    if thread == 0 {
        return Ok(action());
    }
    let old_trap = guest::read64(thread + TRAP_FRAME);
    let entry = Entry { thread, trap: workspace, context: workspace + 0x190, pointers: workspace + 0x680, controls: workspace + 0x780 };
    let Entry { context, trap, pointers, .. } = entry;
    guest::write32(context + 0x30, 0x10_001F);
    for (index, &offset) in raw.iter().enumerate() {
        copy(context + 0x78 + index as u64 * 8, registers_frame + offset, 8);
    }
    copy(context + 0xF8, registers_frame + 128 + extra, 8);
    copy(context + 0x100, fx, 512);
    guest::write16(context + 0x38, guest::read16(registers_frame + 136 + extra));
    guest::write16(context + 0x42, guest::read16(registers_frame + 160 + extra));
    guest::write32(context + 0x44, guest::read32(registers_frame + 144 + extra));
    guest::write32(context + 0x34, guest::read32(fx + 0x18));
    for index in 0..4u64 {
        guest::write16(context + 0x3A + index * 2, guest::read16(cpu_state + 56 + index * 2));
    }
    copy(context + 0x48, cpu_state, 48);
    copy(trap + 0x68, cpu_state + 48, 8);
    guest::write8(trap + 0x28, 0);
    guest::write8(trap + 0x29, irql::get_irql());
    copy(trap + 0x130, cpu_state + 56, 8);
    guest::write64(trap + 0x138, old_trap);
    for (offset, slot, field) in NONVOLATILE {
        guest::write64(pointers + slot, field.map_or(context + offset, |field| trap + field));
    }
    for index in 6..16u64 {
        guest::write64(pointers + index * 8, context + 0x1A0 + index * 16);
    }
    to_trap(&entry);
    ACTIVE.lock().entry(thread).or_default().push(entry);
    guest::write64(thread + TRAP_FRAME, trap);
    let result = action();
    let owned = guest::read64(thread + TRAP_FRAME) == trap;
    if owned {
        from_trap(&entry);
        for (index, &offset) in raw.iter().enumerate() {
            copy(registers_frame + offset, context + 0x78 + index as u64 * 8, 8);
        }
        copy(registers_frame + 128 + extra, context + 0xF8, 8);
        guest::write64(registers_frame + 136 + extra, guest::read16(context + 0x38) as u64);
        guest::write64(registers_frame + 144 + extra, guest::read32(context + 0x44) as u64);
        guest::write64(registers_frame + 160 + extra, guest::read16(context + 0x42) as u64);
        copy(fx, context + 0x100, 512);
        copy(cpu_state, context + 0x48, 48);
    }
    guest::write64(thread + TRAP_FRAME, old_trap);
    {
        let mut active = ACTIVE.lock();
        if let Some(stack) = active.get_mut(&thread) {
            stack.pop();
            if stack.is_empty() {
                active.remove(&thread);
            }
        }
    }
    if !owned {
        return Err(KernelError::new("kernel interrupt trap ownership changed"));
    }
    Ok(result)
}

fn current() -> Option<Entry> {
    ACTIVE.lock().get(&process::get_current_thread()).and_then(|stack| stack.last().copied())
}

/// CONTEXT do frame de interrupção vivo da thread corrente.
pub fn current_context() -> Option<u64> {
    current().map(|entry| entry.context)
}

/// Aplica um CONTEXT de KernelMode ao frame de interrupção vivo.
pub fn apply_kernel(source: u64) -> Result<u32, KernelError> {
    if irql::get_irql() > 1 {
        return Err(KernelError::new("kernel context operation requires IRQL <= APC_LEVEL"));
    }
    let Some(entry) = current().filter(|entry| guest::read64(entry.thread + TRAP_FRAME) == entry.trap && guest::read16(entry.trap + 0x170) == 0x10) else { return Ok(0xC000_0001) };
    from_trap(&entry);
    cpu::fxsave(entry.controls);
    let mask = match guest::read32(entry.controls + 0x1C) {
        0 => 0xFFBF,
        mask => mask,
    };
    registers::write_saved_context(entry.context, source, 0, mask, guest::read32(entry.controls + 0x18))?;
    to_trap(&entry);
    Ok(0)
}

pub fn commit_current() -> Result<(), KernelError> {
    let Some(entry) = current() else { return Err(KernelError::new("no live kernel trap")) };
    to_trap(&entry);
    Ok(())
}
