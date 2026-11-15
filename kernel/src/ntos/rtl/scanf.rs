//! Leitura formatada da CRT do kernel — sscanf_s e swscanf_s (ntoskrnl
//! 19041: sscanf_s 0x3d7570 -> sinput_s -> input_s 0x3d9814; swscanf_s
//! 0x3d7a70 -> swinput_s -> winput_s 0x3da708; ReadString e
//! ReadStringDelimited nas duas larguras).
//!
//! O texto de entrada vai até o NUL (o sscanf_s mede com strlen/wcslen e o
//! fluxo de cadeia devolve EOF depois disso). Comportamento do original:
//! - Formato NULL: -1 (o tratador de parâmetro inválido do kernel é `ret`).
//! - Espaço no formato (`pctype` _SPACE no estreito, `iswctype` no largo)
//!   consome os espaços da entrada; um literal (ou "%%") precisa casar com o
//!   próximo caractere, senão a leitura para.
//! - Diretivas: '*' suprime a atribuição, a largura em decimal, 'h' (curto;
//!   "hh" volta a ser 32 bits), 'l' (32 bits e caractere largo), "ll", "I64",
//!   'j' (64 bits), "I32", 'w' (caractere largo), 'L', 'F' e 'N' (ignorados);
//!   'I', 't' e 'z' marcam 64 bits — se o próximo caractere não for
//!   X/d/i/o/u/x, a própria letra vira a conversão.
//! - Conversões c, s e '[' recebem (ponteiro, tamanho); tamanho 0 grava NUL
//!   no primeiro elemento e para. d, u, o, x, i (prefixos 0x e 0 de base), p
//!   (64 bits) e n (contagem de caracteres; sem 64 bits de verdade: "%lln"
//!   grava o acumulador de 64 bits, zerado pelo modificador). Não há ponto
//!   flutuante: 'e', 'f', 'g' e toda letra desconhecida casam literalmente
//!   com a entrada sem consumir argumento.
//! - Uma cadeia que não cabe grava NUL no início e para; c não termina com
//!   NUL. No sscanf_s, %lc/%ls/%C/%S gravam o word baixo de um endereço da
//!   pilha (o original não converte o caractere); no swscanf_s, %hc/%hs/%C/
//!   %S gravam o byte baixo e avançam o destino pelo próprio valor do byte
//!   (o wctomb do kernel não existe: _mb_cur_max = 1 e o "comprimento" é o
//!   byte gravado).
//! - Resultado: atribuições feitas; EOF antes de qualquer conversão dá -1 no
//!   sscanf_s e 0 no swscanf_s (o WEOF largo devolve o registrador zerado).
//!   Um conjunto '[' sem ']' é lido pelo original além do fim do formato;
//!   aqui a leitura para.

use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::{crt, guest_strings};
use crate::rtl::KernelError;

const CLASS_DIGIT: u16 = 0x004;
const CLASS_SPACE: u16 = 0x008;
const CLASS_HEX: u16 = 0x080;

/// Flags do ReadString.
const READ_WIDTH: u32 = 0x01;
const READ_WIDE: u32 = 0x02;
const READ_SUPPRESS: u32 = 0x04;
const READ_NEGATED: u32 = 0x08;
const READ_CHARACTERS: u32 = 0x10;
const READ_STRING: u32 = 0x20;
const READ_SET: u32 = 0x40;

/// Fluxo de cadeia: posição e o EOF da largura.
struct Stream {
    units: Vec<u16>,
    position: usize,
    eof: u32,
}

impl Stream {
    fn next(&mut self) -> u32 {
        let unit = self.units.get(self.position).map(|&unit| unit as u32);
        self.position += 1;
        unit.unwrap_or(self.eof)
    }

    fn unget(&mut self, character: u32) {
        if character != self.eof {
            self.position -= 1;
        }
    }
}

/// Estado de uma chamada do input_s/winput_s.
struct Scanner<'a> {
    wide: bool,
    eof: u32,
    stream: Stream,
    format: Vec<u16>,
    position: usize,
    argument: &'a mut dyn FnMut(usize) -> u64,
    next_argument: usize,
    count: u32,
    matched: u8,
    characters: u32,
    current: u32,
    number64: u64,
}

/// Diretiva corrente.
struct Directive {
    suppress: u8,
    width: u32,
    width_set: u32,
    long: i8,
    wide_char: i8,
    int64: u32,
    pointer: u64,
    saved_argument: usize,
}

/// Fim da leitura, já com o valor de retorno.
struct Finished(i32);

impl Scanner<'_> {
    fn format_at(&self, index: usize) -> u16 {
        self.format.get(index).copied().unwrap_or(0)
    }

    /// Classe `pctype` do estreito (no largo, só unidades abaixo de 0x100).
    fn narrow_class(&self, character: u32) -> u16 {
        if self.wide && character & 0xFF00 != 0 {
            return 0;
        }
        crt::narrow_class(character & 0xFF)
    }

    /// _SPACE: `pctype` no estreito, `iswctype` (pwctype) no largo.
    fn space(&self, character: u32) -> bool {
        if character == self.eof {
            return false;
        }
        if self.wide { crt::wide_class(character as u16) & CLASS_SPACE != 0 } else { crt::narrow_class(character & 0xFF) & CLASS_SPACE != 0 }
    }

    fn read(&mut self) -> u32 {
        self.characters = self.characters.wrapping_add(1);
        self.stream.next()
    }

    /// EOF: no sscanf_s, -1 se nada foi atribuído nem casado; o swscanf_s
    /// devolve a contagem.
    fn at_eof(&self) -> Finished {
        if self.wide || self.count != 0 || self.matched != 0 { Finished(self.count as i32) } else { Finished(-1) }
    }

    /// Leitura interrompida: com o caractere em EOF, a regra do EOF.
    fn stop(&self) -> Finished {
        if self.current == self.eof { self.at_eof() } else { Finished(self.count as i32) }
    }

    /// Depois de uma diretiva: EOF só segue para um "%n" logo adiante.
    fn after_directive(&self) -> Option<Finished> {
        if self.current == self.eof && !(self.format_at(self.position) == b'%' as u16 && self.format_at(self.position + 1) == b'n' as u16) {
            return Some(self.at_eof());
        }
        None
    }

    fn write(&self, address: u64, size: u32, value: u64) {
        match size {
            1 => guest::write8(address, value as u8),
            2 => guest::write16(address, value as u16),
            4 => guest::write32(address, value as u32),
            _ => guest::write64(address, value),
        }
    }

    fn run(&mut self) -> i32 {
        match self.scan() {
            Ok(()) => self.stop().0,
            Err(Finished(result)) => result,
        }
    }

    fn scan(&mut self) -> Result<(), Finished> {
        if self.format_at(0) == 0 {
            return Err(Finished(0));
        }
        loop {
            let character = self.format_at(self.position) as u32;
            let format_space = if self.wide { crt::wide_class(character as u16) & CLASS_SPACE != 0 } else { crt::narrow_class(character & 0xFF) & CLASS_SPACE != 0 };
            if format_space {
                // O caractere lido aqui não vira o "corrente" do original.
                self.characters = self.characters.wrapping_sub(1);
                let skipped = loop {
                    let unit = self.read();
                    if unit == self.eof || !self.space(unit) {
                        break unit;
                    }
                };
                self.stream.unget(skipped);
                self.position += 1;
                while {
                    let next = self.format_at(self.position) as u32;
                    if self.wide { crt::wide_class(next as u16) & CLASS_SPACE != 0 } else { crt::narrow_class(next & 0xFF) & CLASS_SPACE != 0 }
                } {
                    self.position += 1;
                }
            } else if character == b'%' as u32 && self.format_at(self.position + 1) != b'%' as u16 {
                self.directive()?;
            } else {
                if character == b'%' as u32 {
                    self.position += 1;
                }
                self.current = self.read();
                let expected = self.format_at(self.position) as u32;
                self.position += 1;
                if expected != self.current {
                    if self.current == self.eof {
                        return Err(self.at_eof());
                    }
                    self.stream.unget(self.current);
                    return Err(Finished(self.count as i32));
                }
                if let Some(finished) = self.after_directive() {
                    return Err(finished);
                }
            }
            if self.format_at(self.position) == 0 {
                return Ok(());
            }
        }
    }

    /// Modificadores até a letra da conversão.
    fn modifiers(&mut self) -> Directive {
        let mut directive = Directive { suppress: 0, width: 0, width_set: 0, long: 1, wide_char: 0, int64: 0, pointer: 0, saved_argument: 0 };
        loop {
            self.position += 1;
            let character = self.format_at(self.position);
            if self.narrow_class(character as u32) & CLASS_DIGIT != 0 {
                directive.width = directive.width.wrapping_mul(10).wrapping_add(character as u32).wrapping_sub(0x30);
                directive.width_set += 1;
                continue;
            }
            let lookahead = match character {
                0x68 => {
                    // 'h'
                    directive.long = directive.long.wrapping_sub(1);
                    directive.wide_char = directive.wide_char.wrapping_sub(1);
                    continue;
                }
                0x2A => {
                    // '*'
                    directive.suppress = directive.suppress.wrapping_add(1);
                    continue;
                }
                0x46 | 0x4E => continue, // 'F', 'N'
                0x49 => {
                    // 'I'
                    let (next, after) = (self.format_at(self.position + 1), self.format_at(self.position + 2));
                    if next == b'6' as u16 && after == b'4' as u16 {
                        self.position += 2;
                        directive.int64 += 1;
                        self.number64 = 0;
                        continue;
                    }
                    if next == b'3' as u16 && after == b'2' as u16 {
                        self.position += 2;
                        continue;
                    }
                    true
                }
                0x4C => {
                    // 'L'
                    directive.long = directive.long.wrapping_add(1);
                    continue;
                }
                0x6A => {
                    // 'j'
                    directive.int64 += 1;
                    self.number64 = 0;
                    continue;
                }
                0x6C => {
                    // 'l' ou "ll"
                    if self.format_at(self.position + 1) == b'l' as u16 {
                        self.position += 1;
                        directive.int64 += 1;
                        self.number64 = 0;
                    } else {
                        directive.long = directive.long.wrapping_add(1);
                        directive.wide_char = directive.wide_char.wrapping_add(1);
                    }
                    continue;
                }
                0x74 | 0x7A => true, // 't', 'z'
                0x77 => {
                    // 'w'
                    directive.wide_char = directive.wide_char.wrapping_add(1);
                    continue;
                }
                _ => return directive,
            };
            if lookahead {
                // 'I'/'t'/'z': 64 bits; sem X/d/i/o/u/x adiante, a letra é a conversão.
                let offset = self.format_at(self.position + 1).wrapping_sub(0x58) as u8;
                directive.int64 += 1;
                self.number64 = 0;
                if offset <= 0x20 && (0x1_2082_1001u64 >> offset) & 1 != 0 {
                    continue;
                }
                return directive;
            }
        }
    }

    fn directive(&mut self) -> Result<(), Finished> {
        let mut directive = self.modifiers();
        if directive.suppress == 0 {
            directive.saved_argument = self.next_argument;
            directive.pointer = (self.argument)(self.next_argument);
            self.next_argument += 1;
        }
        let letter = self.format_at(self.position);
        if directive.wide_char == 0 {
            let capital = letter == b'C' as u16 || letter == b'S' as u16;
            directive.wide_char = if self.wide == capital { -1 } else { 1 };
        }
        let mut conversion = (letter | 0x20) as u8;
        if conversion != b'n' {
            if conversion == b'c' || conversion == b'{' {
                self.current = self.read();
            } else {
                loop {
                    self.current = self.read();
                    if self.current == self.eof || !self.space(self.current) {
                        break;
                    }
                }
            }
            if self.current == self.eof {
                return Err(self.at_eof());
            }
        }
        if directive.width_set != 0 && directive.width == 0 {
            if self.current == self.eof {
                return Err(self.at_eof());
            }
            self.stream.unget(self.current);
            return Err(Finished(self.count as i32));
        }
        let mut size = 0u64;
        if directive.suppress == 0 && matches!(conversion, b'c' | b's' | b'{') {
            size = (self.argument)(self.next_argument) as u32 as u64;
            self.next_argument += 1;
            if size == 0 {
                self.write(directive.pointer, if directive.wide_char > 0 { 2 } else { 1 }, 0);
                return Err(Finished(self.count as i32));
            }
        }
        let flags = match conversion {
            b'c' => {
                if directive.width_set == 0 {
                    directive.width = 1;
                    directive.width_set = 1;
                }
                READ_CHARACTERS
            }
            b's' => READ_STRING,
            b'{' => READ_SET,
            b'n' => {
                if directive.suppress == 0 {
                    if directive.int64 != 0 {
                        self.write(directive.pointer, 8, self.number64);
                    } else {
                        self.write(directive.pointer, if directive.long != 0 { 4 } else { 2 }, self.characters as u64);
                    }
                }
                return self.next_directive();
            }
            b'd' | b'o' | b'u' | b'p' | b'i' | b'x' => {
                if conversion == b'p' {
                    directive.int64 += 1;
                    directive.long = 1;
                    self.number64 = 0;
                }
                return self.number(&mut directive, &mut conversion);
            }
            _ => {
                // Sem conversão: a letra casa literalmente, o argumento volta
                // e a diretiva não conta como casada.
                if letter as u32 == self.current {
                    if directive.suppress == 0 {
                        self.next_argument = directive.saved_argument;
                    }
                    self.position += 1;
                    return match self.after_directive() {
                        Some(finished) => Err(finished),
                        None => Ok(()),
                    };
                }
                self.stream.unget(self.current);
                return Err(self.stop());
            }
        };
        let mut flags = flags;
        if directive.width_set != 0 {
            flags |= READ_WIDTH;
        }
        if directive.wide_char > 0 {
            flags |= READ_WIDE;
        }
        if directive.suppress != 0 {
            flags |= READ_SUPPRESS;
        }
        let mut set = Vec::new();
        if conversion == b'{' {
            match self.scan_set() {
                Some((negated, table)) => {
                    if negated {
                        flags |= READ_NEGATED;
                    }
                    set = table;
                }
                None => return Err(self.stop()),
            }
        }
        if !self.read_string(flags, &set, directive.width, directive.pointer, size) {
            return Err(self.stop());
        }
        self.next_directive()
    }

    /// Conta a diretiva como casada e passa à próxima posição do formato.
    fn next_directive(&mut self) -> Result<(), Finished> {
        self.matched = self.matched.wrapping_add(1);
        self.position += 1;
        match self.after_directive() {
            Some(finished) => Err(finished),
            None => Ok(()),
        }
    }

    /// Sinal consumido pela largura: a largura esgotada encerra os dígitos.
    fn sign(&mut self, directive: &mut Directive, negative: &mut bool, done: &mut bool) {
        if self.current == b'-' as u32 || self.current == b'+' as u32 {
            *negative |= self.current == b'-' as u32;
            directive.width = directive.width.wrapping_sub(1);
            if directive.width == 0 && directive.width_set != 0 {
                *done = true;
            } else {
                self.current = self.read();
            }
        }
    }

    fn number(&mut self, directive: &mut Directive, conversion: &mut u8) -> Result<(), Finished> {
        let (mut negative, mut done, mut started) = (false, false, 0u32);
        if *conversion == b'i' || *conversion == b'x' {
            if *conversion == b'i' {
                *conversion = b'd';
            }
            self.sign(directive, &mut negative, &mut done);
            if self.current == b'0' as u32 {
                self.current = self.read();
                if (self.current.wrapping_sub(0x58) as u8) & 0xDF == 0 {
                    self.current = self.read();
                    if directive.width_set != 0 {
                        directive.width = directive.width.wrapping_sub(2);
                        if (directive.width as i32) < 1 {
                            done = true;
                        }
                    }
                    *conversion = b'x';
                } else {
                    started = 1;
                    if *conversion == b'x' {
                        self.characters = self.characters.wrapping_sub(1);
                        self.stream.unget(self.current);
                        self.current = b'0' as u32;
                    } else {
                        if directive.width_set != 0 {
                            directive.width = directive.width.wrapping_sub(1);
                            if directive.width == 0 {
                                done = true;
                            }
                        }
                        *conversion = b'o';
                    }
                }
            }
        } else {
            self.sign(directive, &mut negative, &mut done);
        }
        let mask = if directive.int64 != 0 { u64::MAX } else { u32::MAX as u64 };
        let mut number = if directive.int64 != 0 { self.number64 } else { 0 };
        if !done {
            let mut width_exhausted = false;
            loop {
                let class = if self.current == self.eof { 0 } else { self.narrow_class(self.current) };
                let digit = if *conversion == b'x' || *conversion == b'p' {
                    if class & CLASS_HEX == 0 {
                        break;
                    }
                    if class & CLASS_DIGIT != 0 {
                        self.current - 0x30
                    } else {
                        let folded = if self.wide { self.current & 0xFFDF } else { (self.current as u8 as i8 as i32 as u32) & 0xFFFF_FFDF };
                        folded.wrapping_sub(7).wrapping_sub(0x30)
                    }
                } else if class & CLASS_DIGIT != 0 {
                    if *conversion == b'o' && self.current >= b'8' as u32 {
                        break;
                    }
                    self.current - 0x30
                } else {
                    break;
                };
                let base = match *conversion {
                    b'x' | b'p' => 16,
                    b'o' => 8,
                    _ => 10,
                };
                number = number.wrapping_mul(base).wrapping_add(digit as i32 as i64 as u64) & mask;
                started += 1;
                if directive.width_set != 0 {
                    directive.width = directive.width.wrapping_sub(1);
                    if directive.width == 0 {
                        width_exhausted = true;
                        break;
                    }
                }
                self.current = self.read();
            }
            if !width_exhausted {
                self.characters = self.characters.wrapping_sub(1);
                self.stream.unget(self.current);
            }
        }
        if negative {
            number = number.wrapping_neg() & mask;
        }
        if directive.int64 != 0 {
            self.number64 = number;
        }
        if started == 0 {
            return Err(self.stop());
        }
        if directive.suppress == 0 {
            self.count += 1;
            let size = if directive.int64 != 0 {
                8
            } else if directive.long != 0 {
                4
            } else {
                2
            };
            self.write(directive.pointer, size, number);
        }
        self.next_directive()
    }

    /// ReadStringDelimited: o conjunto depois de '[' (com '^', ']' inicial e
    /// faixas a-b); a posição fica no ']'. None sem ']'.
    fn scan_set(&mut self) -> Option<(bool, Vec<u8>)> {
        let mut table = alloc::vec![0u8; if self.wide { 0x2000 } else { 0x20 }];
        let set = |table: &mut Vec<u8>, unit: u16| table[(unit >> 3) as usize] |= 1 << (unit & 7);
        self.position += 1;
        let negated = self.format_at(self.position) == b'^' as u16;
        if negated {
            self.position += 1;
        }
        let mut previous = 0u16;
        if self.format_at(self.position) == b']' as u16 {
            previous = b']' as u16;
            set(&mut table, previous);
            self.position += 1;
        }
        loop {
            let unit = self.format_at(self.position);
            if unit == b']' as u16 {
                return Some((negated, table));
            }
            if unit == 0 {
                return None;
            }
            let next = self.format_at(self.position + 1);
            if unit == b'-' as u16 && previous != 0 && next != b']' as u16 {
                let (low, high) = if previous >= next { (next, previous) } else { (previous, next) };
                for member in low..=high {
                    set(&mut table, member);
                }
                previous = 0;
                self.position += 2;
            } else {
                set(&mut table, unit);
                previous = unit;
                self.position += 1;
            }
        }
    }

    /// ReadString: devolve false na falha (nada lido ou destino pequeno).
    fn read_string(&mut self, flags: u32, set: &[u8], mut width: u32, pointer: u64, size: u64) -> bool {
        self.characters = self.characters.wrapping_sub(1);
        self.stream.unget(self.current);
        let mut start = pointer;
        let mut cursor = pointer;
        let mut remaining = if flags & READ_CHARACTERS != 0 { size } else { size.wrapping_sub(1) };
        let mut stopped = false;
        loop {
            if flags & READ_WIDTH != 0 {
                if width == 0 {
                    break;
                }
                width -= 1;
            }
            self.current = self.read();
            if self.current == self.eof {
                stopped = true;
                break;
            }
            if flags & READ_CHARACTERS == 0 {
                let blank = (9..=13).contains(&self.current) || self.current == 32;
                if !(flags & READ_STRING != 0 && !blank) {
                    if flags & READ_SET == 0 {
                        stopped = true;
                        break;
                    }
                    let member = set.get((self.current >> 3) as usize).is_some_and(|byte| byte & (1 << (self.current & 7)) != 0);
                    if member == (flags & READ_NEGATED != 0) {
                        stopped = true;
                        break;
                    }
                }
            }
            if flags & READ_SUPPRESS != 0 {
                start = start.wrapping_add(1);
                continue;
            }
            if remaining == 0 {
                self.write(start, if flags & READ_WIDE != 0 { 2 } else { 1 }, 0);
                return false;
            }
            if flags & READ_WIDE != 0 {
                remaining -= 1;
                let value = if self.wide {
                    self.current as u64
                } else {
                    // O word baixo de um endereço da pilha, como no original.
                    let local = 0u64;
                    &local as *const u64 as u64
                };
                self.write(cursor, 2, value);
                cursor = cursor.wrapping_add(2);
            } else if self.wide {
                // Estreito no largo: o byte baixo, e o destino anda pelo valor dele.
                let byte = self.current as u8;
                self.write(cursor, 1, byte as u64);
                if (byte as i8) > 0 {
                    cursor = cursor.wrapping_add(byte as u64);
                    remaining = remaining.wrapping_sub(byte as u64);
                }
            } else {
                remaining -= 1;
                self.write(cursor, 1, self.current as u64);
                cursor = cursor.wrapping_add(1);
            }
        }
        if stopped {
            self.characters = self.characters.wrapping_sub(1);
            self.stream.unget(self.current);
        }
        if start == cursor {
            return false;
        }
        if flags & READ_SUPPRESS == 0 {
            self.count += 1;
            if flags & READ_CHARACTERS == 0 {
                self.write(cursor, if flags & READ_WIDE != 0 { 2 } else { 1 }, 0);
            }
        }
        true
    }
}

fn scan(wide: bool, input: Vec<u16>, format: Vec<u16>, argument: &mut dyn FnMut(usize) -> u64) -> i32 {
    let eof = if wide { 0xFFFF } else { u32::MAX };
    let mut scanner = Scanner {
        wide,
        eof,
        stream: Stream { units: input, position: 0, eof },
        format,
        position: 0,
        argument,
        next_argument: 0,
        count: 0,
        matched: 0,
        characters: 0,
        current: 0,
        number64: 0,
    };
    scanner.run()
}

/// sscanf_s(Buffer, Format, ...): os argumentos variádicos pelo índice.
pub fn sscanf_s(buffer: u64, format: u64, argument: &mut dyn FnMut(usize) -> u64) -> Result<i32, KernelError> {
    if format == 0 {
        return Ok(-1);
    }
    let input = guest_strings::read_c_string(buffer).chars().map(|character| character as u16).collect();
    let format = guest_strings::read_c_string(format).chars().map(|character| character as u16).collect();
    Ok(scan(false, input, format, argument))
}

/// swscanf_s(Buffer, Format, ...).
pub fn swscanf_s(buffer: u64, format: u64, argument: &mut dyn FnMut(usize) -> u64) -> Result<i32, KernelError> {
    if format == 0 {
        return Ok(-1);
    }
    Ok(scan(true, guest_strings::read_wide_units(buffer), guest_strings::read_wide_units(format), argument))
}
