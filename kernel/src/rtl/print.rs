//! Canal de depuração do kernel (o `os.debugPrint` do original): texto na COM1,
//! sempre terminado por quebra de linha.

use core::fmt::{self, Write};

use crate::hal::serial;

/// Escritor sem estado sobre a serial. Não aloca e não usa locks, para que
/// pânicos e exceções possam imprimir em qualquer ponto.
pub struct SerialWriter;

impl Write for SerialWriter {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        serial::write(text.as_bytes());
        Ok(())
    }
}

/// Escreve argumentos formatados na serial, sem quebra de linha.
pub fn write_args(arguments: fmt::Arguments<'_>) {
    let _ = SerialWriter.write_fmt(arguments);
}

/// Escreve argumentos formatados seguidos de `\n` (debugPrint).
pub fn debug_print_args(arguments: fmt::Arguments<'_>) {
    let _ = SerialWriter.write_fmt(arguments);
    serial::write(b"\n");
}

/// `debug_print!("[irq] plataforma: {}", vendor)` — equivalente a
/// `os.debugPrint('[irq] plataforma: ' + vendor)`.
#[macro_export]
macro_rules! debug_print {
    ($($argument:tt)*) => {
        $crate::rtl::print::debug_print_args(format_args!($($argument)*))
    };
}
