//! Visão de memória do kernel (heap + RAM do E820) —
//! `system32/ntos/mm/memory.js`.

use alloc::format;
use alloc::string::String;

use crate::drivers::console;
use crate::hal::kmalloc;

pub fn fmt(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{} MB", bytes / 1_048_576)
    } else {
        format!("{} KB", bytes / 1024)
    }
}

pub fn cmd_mem() {
    let (total, used) = kmalloc::info();
    console::print(&format!("RAM total : {} (via E820)", fmt(kmalloc::ram_top())));
    console::print(&format!("heap      : {} usados / {} total", fmt(used as u64), fmt(total as u64)));
    console::print(&format!("livre     : {}", fmt(total.saturating_sub(used) as u64)));
}
