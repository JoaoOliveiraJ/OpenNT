//! Console do kernel (tela VGA + espelho serial) —
//! `system32/drivers/console/console.js`.
//!
//! O `DriverEntry` estilo NT, que registra `\Driver\Console` e
//! `\Device\Console` com um handler de IRP_MJ_WRITE, entra junto com o I/O
//! Manager (`ntos/io`).
//!
//! Com `--console-mirror` no build (usado pelo `cargo xtask test-boot`), todo
//! texto da tela também vai para a serial, para os testes automatizados
//! conferirem a saída dos comandos.

use crate::drivers::video::vga;
use crate::hal::serial;
use crate::ntos::init::boot_config;

pub fn write(text: &str) {
    vga::write(text);
    if boot_config::CONSOLE_SERIAL_MIRROR {
        serial::puts(text);
    }
}

pub fn print(text: &str) {
    write(text);
    write("\n");
}

/// Tela + serial.
pub fn log(text: &str) {
    print(text);
    if !boot_config::CONSOLE_SERIAL_MIRROR {
        debug_print!("{}", text);
    }
}

pub fn clear() {
    vga::clear();
}
