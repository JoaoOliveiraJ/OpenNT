//! RtlFormatMessage: o formatador de mensagens do Rtl (as inserções %1..%99
//! com o formato opcional `!fmt!`, os escapes %0 %r %n %t %b e a quebra de
//! linhas por largura máxima).
//!
//! ntoskrnl 10.0.19041: RtlFormatMessage 0x910db0 chama RtlFormatMessageEx
//! 0x910e08 com o décimo parâmetro nulo. O texto é gravado no Buffer do
//! chamador conforme anda; `Length` vem em bytes e só WCHARs inteiros contam.
//!
//! - `%n` (1 a 3 dígitos, o primeiro de 1 a 9; um quarto dígito é
//!   STATUS_INVALID_PARAMETER) insere o argumento n com `%s`, ou com o formato
//!   entre pontos de exclamação (até 30 caracteres e 2 `*`); com
//!   ArgumentsAreAnsi, o `c`/`s` final vira `hc`/`hs` (salvo depois de h, l ou
//!   w) e `C`/`S` viram `c`/`s`. O texto sai do RtlStringCchPrintfExW sobre o
//!   que resta do buffer, com o argumento n e os dos `*` em seguida, nessa
//!   ordem. Os argumentos vêm em ordem: os de índice ainda não lido são
//!   capturados até n (no máximo 200, contando os `*`); os de `*` são os
//!   seguintes. Com uma va_list, o primeiro `*` é lido sem entrar na tabela
//!   de capturados (o segundo entra), como no original.
//! - IgnoreInserts copia `%n` (ou `%n!fmt!`, salvo `!s!`) e os outros `%x`
//!   como estão.
//! - `%0` encerra; `%r` é CR; `%n` CR LF; `%t` tabulação (coluna na próxima
//!   parada de 8, mais 1); `%b` espaço; `%` com outro caractere copia o
//!   caractere.
//! - CR, LF, CR LF e LF CR viram CR LF com MaximumWidth 0; com largura, viram
//!   espaço. Passando de MaximumWidth (nem 0 nem -1), a linha quebra no último
//!   espaço ou tabulação (os brancos em volta viram um CR LF) ou, sem nenhum,
//!   no ponto atual.
//! - Falta de espaço é STATUS_BUFFER_OVERFLOW (o que coube fica no buffer);
//!   no sucesso o texto termina em NUL e ReturnLength recebe os bytes com o
//!   NUL.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

const PERCENT: u16 = b'%' as u16;
const SPACE: u16 = b' ' as u16;
const TAB: u16 = 9;
const CR: u16 = 0xD;
const LF: u16 = 0xA;
/// Inserções capturadas (o vetor de 200 ULONG_PTR na pilha do original).
const MAXIMUM_INSERTS: u32 = 200;
/// O formato de uma inserção cabe em 32 WCHARs: '%', até 30 e o NUL.
const MAXIMUM_FORMAT: usize = 30;

/// Origem dos argumentos: vetor de ULONG_PTR ou `va_list *`.
struct Arguments {
    cursor: u64,
    array: bool,
}

impl Arguments {
    /// O próximo argumento; a va_list do chamador avança, o vetor não.
    fn next(&mut self) -> u64 {
        if self.array {
            let value = guest::read64(self.cursor);
            self.cursor += 8;
            value
        } else {
            let list = guest::read64(self.cursor) + 8;
            guest::write64(self.cursor, list);
            guest::read64(list - 8)
        }
    }
}

/// O texto em formação e o espaço restante (em WCHARs), como o par
/// Buffer/Length do original.
struct Output {
    text: Vec<u16>,
    remaining: i64,
    /// O printf truncado deixou um NUL depois do texto.
    terminated: bool,
}

impl Output {
    /// Reserva `count` WCHARs (o `sub r14d, n; js` do original).
    fn reserve(&mut self, count: i64) -> Result<(), u32> {
        self.remaining -= count;
        if self.remaining < 0 { Err(STATUS_BUFFER_OVERFLOW) } else { Ok(()) }
    }
}

/// RtlStringCchPrintfExW sobre o resto do buffer: cabe se o texto deixa
/// lugar para o NUL; senão grava o que cabe e falha.
fn print_into(output: &mut Output, text: &str) -> Result<(), u32> {
    let units: Vec<u16> = text.encode_utf16().collect();
    let capacity = output.remaining;
    if capacity <= 0 || capacity - 1 > 0x7FFF_FFFE {
        return Err(STATUS_BUFFER_OVERFLOW);
    }
    if units.len() as i64 > capacity - 1 {
        output.text.extend_from_slice(&units[..(capacity - 1) as usize]);
        output.terminated = true;
        return Err(STATUS_BUFFER_OVERFLOW);
    }
    output.text.extend_from_slice(&units);
    output.remaining -= units.len() as i64;
    Ok(())
}

/// Formatação de uma inserção pelo formatador comum (largo).
fn printf(format: &[u16], values: &[u64]) -> Result<String, KernelError> {
    let format = String::from_utf16_lossy(format);
    guest_strings::format_guest_text(&format, &mut |index| values.get(index).copied().unwrap_or(0), true)
}

/// Os parâmetros de RtlFormatMessage, na ordem do protótipo.
pub struct Request {
    pub format: u64,
    pub maximum_width: u32,
    pub ignore_inserts: bool,
    pub arguments_are_ansi: bool,
    pub arguments_are_an_array: bool,
    pub arguments: u64,
    pub buffer: u64,
    pub length: u32,
    pub return_length: u64,
}

/// RtlFormatMessage(...) -> NTSTATUS.
pub fn format_message(request: &Request) -> Result<u32, KernelError> {
    let mut output = Output { text: Vec::new(), remaining: (request.length >> 1) as i64, terminated: false };
    let status = run(request, &mut output);
    let bytes: Vec<u8> = output.text.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    guest::write_bytes(request.buffer, &bytes);
    let status = match status {
        Ok(()) => {
            guest::write16(request.buffer + bytes.len() as u64, 0);
            if request.return_length != 0 {
                guest::write32(request.return_length, bytes.len() as u32 + 2);
            }
            STATUS_SUCCESS
        }
        Err(Failure::Status(status)) => {
            if output.terminated {
                guest::write16(request.buffer + bytes.len() as u64, 0);
            }
            status
        }
        Err(Failure::Kernel(error)) => return Err(error),
    };
    Ok(status)
}

enum Failure {
    Status(u32),
    Kernel(KernelError),
}

impl From<u32> for Failure {
    fn from(status: u32) -> Self {
        Failure::Status(status)
    }
}

impl From<KernelError> for Failure {
    fn from(error: KernelError) -> Self {
        Failure::Kernel(error)
    }
}

/// O laço do RtlFormatMessageEx; Ok(()) no fim da mensagem com espaço para
/// o NUL.
fn run(request: &Request, output: &mut Output) -> Result<(), Failure> {
    let mut source = request.format;
    let mut arguments = Arguments { cursor: request.arguments, array: request.arguments_are_an_array };
    let mut inserts = [0u64; MAXIMUM_INSERTS as usize];
    let mut captured = 0u32;
    let mut column = 0u32;
    let mut last_space: Option<usize> = None;
    let width = request.maximum_width;
    let read = |address: u64| guest::read16(address);
    loop {
        let unit = read(source);
        if unit == 0 {
            break;
        }
        source += 2;
        if unit == PERCENT {
            let next = read(source);
            let start = output.text.len();
            if (b'1' as u16..=b'9' as u16).contains(&next) {
                source += 2;
                let mut number = (next - b'0' as u16) as u32;
                for digit in 0..3 {
                    let unit = read(source);
                    if !(b'0' as u16..=b'9' as u16).contains(&unit) {
                        break;
                    }
                    if digit == 2 {
                        return Err(STATUS_INVALID_PARAMETER.into());
                    }
                    number = number * 10 + (unit - b'0' as u16) as u32;
                    source += 2;
                }
                // Formato da inserção: "%" + o texto entre '!' ou "%s".
                let mut format: Vec<u16> = alloc::vec![PERCENT];
                let mut stars = 0u32;
                let explicit = read(source) == b'!' as u16;
                if explicit {
                    source += 2;
                    loop {
                        let unit = read(source);
                        if unit == b'!' as u16 {
                            source += 2;
                            break;
                        }
                        if unit == 0 || format.len() > MAXIMUM_FORMAT {
                            return Err(STATUS_INVALID_PARAMETER.into());
                        }
                        if unit == b'*' as u16 {
                            stars += 1;
                            if stars > 2 {
                                return Err(STATUS_INVALID_PARAMETER.into());
                            }
                        }
                        format.push(unit);
                        source += 2;
                    }
                } else {
                    format.push(b's' as u16);
                }
                if request.ignore_inserts {
                    let text = if !explicit || format == [PERCENT, b's' as u16] {
                        alloc::format!("%{}", number)
                    } else {
                        alloc::format!("%{}!{}!", number, String::from_utf16_lossy(&format[1..]))
                    };
                    print_into(output, &text)?;
                } else {
                    if request.arguments == 0 || stars + number - 1 >= MAXIMUM_INSERTS {
                        return Err(STATUS_INVALID_PARAMETER.into());
                    }
                    if request.arguments_are_ansi {
                        ansi_format(&mut format);
                    }
                    let index = number - 1;
                    while captured <= index {
                        inserts[captured as usize] = arguments.next();
                        captured += 1;
                    }
                    let mut values = alloc::vec![inserts[index as usize], 0, 0];
                    // Os argumentos de `*` também entram no vetor (o original
                    // não confere o limite aqui; além dele, nada é guardado).
                    let keep = |inserts: &mut [u64; MAXIMUM_INSERTS as usize], captured: &mut u32, value: u64| {
                        if let Some(slot) = inserts.get_mut(*captured as usize) {
                            *slot = value;
                        }
                        *captured += 1;
                    };
                    if stars != 0 {
                        values[1] = arguments.next();
                        if arguments.array {
                            keep(&mut inserts, &mut captured, values[1]);
                        }
                        if stars > 1 {
                            values[2] = arguments.next();
                            keep(&mut inserts, &mut captured, values[2]);
                        }
                    }
                    let text = printf(&format, &values)?;
                    print_into(output, &text)?;
                }
                column += (output.text.len() - start) as u32;
            } else {
                match next {
                    0x30 => break,
                    0 => return Err(STATUS_INVALID_PARAMETER.into()),
                    0x72 => {
                        output.reserve(1)?;
                        output.text.push(CR);
                        source += 2;
                        last_space = None;
                        column = 0;
                    }
                    0x6E => {
                        output.reserve(2)?;
                        output.text.extend_from_slice(&[CR, LF]);
                        source += 2;
                        last_space = None;
                        column = 0;
                    }
                    0x74 => {
                        output.reserve(1)?;
                        column = if column & 7 != 0 { (column + 7) & !7 } else { column + 8 };
                        last_space = Some(output.text.len());
                        output.text.push(TAB);
                        source += 2;
                        column += 1;
                    }
                    0x62 => {
                        output.reserve(1)?;
                        last_space = Some(output.text.len());
                        output.text.push(SPACE);
                        source += 2;
                        column += 1;
                    }
                    other if request.ignore_inserts => {
                        output.reserve(2)?;
                        output.text.extend_from_slice(&[PERCENT, other]);
                        source += 2;
                        column += 2;
                    }
                    other => {
                        output.reserve(1)?;
                        output.text.push(other);
                        source += 2;
                        column += 1;
                    }
                }
            }
        } else {
            let mut unit = unit;
            if unit == CR || unit == LF {
                let following = read(source);
                if (unit == LF && following == CR) || (unit == CR && following == LF) {
                    source += 2;
                }
                if width == 0 {
                    output.reserve(2)?;
                    output.text.extend_from_slice(&[CR, LF]);
                    column = 0;
                    last_space = None;
                    continue;
                }
                unit = SPACE;
            }
            output.reserve(1)?;
            if unit == SPACE {
                last_space = Some(output.text.len());
            }
            output.text.push(unit);
            column += 1;
        }
        if width == 0 || width == u32::MAX || column < width {
            continue;
        }
        // A linha passou da largura: quebra no último branco ou aqui.
        match last_space {
            None => {
                output.reserve(2)?;
                output.text.extend_from_slice(&[CR, LF]);
                column = 0;
            }
            Some(mut space) => {
                let blank = |unit: u16| unit == SPACE || unit == TAB;
                let mut after = space;
                while blank(output.text[after]) {
                    after += 1;
                    if after == output.text.len() {
                        break;
                    }
                }
                while space > 0 && blank(output.text[space - 1]) {
                    space -= 1;
                }
                let removed = (after - space) as i64;
                if removed == 1 {
                    output.reserve(1)?;
                } else if removed > 2 {
                    output.remaining += removed - 2;
                }
                let rest: Vec<u16> = output.text[after..].to_vec();
                column = rest.len() as u32;
                output.text.truncate(space);
                output.text.extend_from_slice(&[CR, LF]);
                output.text.extend_from_slice(&rest);
            }
        }
        last_space = None;
    }
    if output.remaining < 1 {
        return Err(STATUS_BUFFER_OVERFLOW.into());
    }
    Ok(())
}

/// Argumentos ANSI: `c`/`s` finais viram `hc`/`hs` (salvo depois de h, l ou
/// w); `C`/`S` viram `c`/`s`.
fn ansi_format(format: &mut Vec<u16>) {
    let Some(&last) = format.last() else { return };
    let previous = if format.len() >= 2 { format[format.len() - 2] } else { 0 };
    let sized = matches!(previous, 0x68 | 0x6C | 0x77);
    let position = format.len() - 1;
    match last {
        0x63 | 0x73 if !sized => format.insert(position, b'h' as u16),
        0x53 => format[position] = b's' as u16,
        0x43 => format[position] = b'c' as u16,
        _ => {}
    }
}
