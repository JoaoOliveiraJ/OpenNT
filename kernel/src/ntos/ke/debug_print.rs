//! Saída de depuração dos drivers (DbgPrint, DbgPrintEx).
//!
//! O formato printf do convidado é expandido com os argumentos variáveis da
//! chamada e vai para o log do kernel com um prefixo; a quebra de linha
//! final (`\n` ou `\r\n`) sai. O nível do DbgPrintEx chega pela ABI, mas
//! ainda não filtra.

use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

fn print_formatted(prefix: &str, format_pointer: u64, arguments: &[u64]) -> Result<(), KernelError> {
    let format_text = guest_strings::read_c_string(format_pointer);
    let text = guest_strings::format_guest_text(&format_text, &mut |index| arguments.get(index).copied().unwrap_or(0), false)?;
    let text = text.strip_suffix('\n').map(|rest| rest.strip_suffix('\r').unwrap_or(rest)).unwrap_or(&text);
    debug_print!("{}{}", prefix, text);
    Ok(())
}

/// DbgPrint(Format, ...): `arguments` começa no primeiro argumento variável.
pub fn dbg_print(format: u64, arguments: &[u64]) -> Result<(), KernelError> {
    print_formatted("[driver] ", format, arguments)
}

/// DbgPrintEx(ComponentId, Level, Format, ...): o componente vai no prefixo.
pub fn dbg_print_ex(component_id: u32, format: u64, arguments: &[u64]) -> Result<(), KernelError> {
    print_formatted(&alloc::format!("[driver:{}] ", component_id), format, arguments)
}
