//! Canal de depuração do kernel: texto na COM1, sempre terminado por quebra
//! de linha.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, Ordering};

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

/// A linha em escrita na serial: com o anel 3 em várias CPUs, duas linhas
/// ao mesmo tempo se misturariam e os marcadores do xtask deixariam de
/// casar. Não é uma trava comum: quem não a consegue em
/// [`LINE_SPIN_LIMIT`] voltas escreve assim mesmo (um pânico, uma NMI ou
/// uma linha impressa de dentro de outra, na mesma CPU, nunca param aqui).
static LINE: AtomicBool = AtomicBool::new(false);
/// As voltas de espera pela linha (alguns milissegundos de serial).
const LINE_SPIN_LIMIT: u32 = 1 << 20;

/// Escreve argumentos formatados seguidos de `\n`, a linha inteira de uma
/// vez em relação às outras CPUs ([`LINE`]).
pub fn debug_print_args(arguments: fmt::Arguments<'_>) {
    let mut owned = false;
    for _ in 0..LINE_SPIN_LIMIT {
        if LINE.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            owned = true;
            break;
        }
        core::hint::spin_loop();
    }
    let _ = SerialWriter.write_fmt(arguments);
    serial::write(b"\n");
    if owned {
        LINE.store(false, Ordering::Release);
    }
}

/// `debug_print!("[irq] plataforma: {}", vendor)`: texto formatado na COM1,
/// seguido de quebra de linha.
#[macro_export]
macro_rules! debug_print {
    ($($argument:tt)*) => {
        $crate::rtl::print::debug_print_args(format_args!($($argument)*))
    };
}
