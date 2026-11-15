//! Nomes de símbolo do Rust legíveis: o esquema v0 (`_R...`, o que o
//! toolchain do kernel gera) e o legado (`_ZN...E`).
//!
//! O v0 segue a gramática pública do esquema: caminhos (`C` raiz de crate,
//! `N` aninhado, `M`/`X`/`Y` impls, `I` argumentos genéricos, `B`
//! referências para trás), tipos, constantes e assinaturas de função. Os
//! hashes das crates e os desambiguadores saem do texto.

/// Nome legível, ou `None` se não for um símbolo do Rust.
pub fn demangle(symbol: &str) -> Option<String> {
    if let Some(rest) = symbol.strip_prefix("_R") {
        let mut parser = Parser { bytes: rest.as_bytes(), position: 0, depth: 0 };
        // Versão opcional (dígitos decimais).
        while parser.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            parser.position += 1;
        }
        let mut output = String::new();
        parser.path(&mut output, false).ok()?;
        return Some(output);
    }
    let rest = symbol.strip_prefix("_ZN").or_else(|| symbol.strip_prefix("__ZN"))?;
    legacy(rest)
}

fn legacy(mut rest: &str) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    while !rest.starts_with('E') {
        let digits = rest.bytes().take_while(|byte| byte.is_ascii_digit()).count();
        let length: usize = rest[..digits].parse().ok()?;
        let part = rest.get(digits..digits + length)?;
        rest = &rest[digits + length..];
        parts.push(part.to_string());
    }
    if parts.last().is_some_and(|last| last.len() == 17 && last.starts_with('h') && last[1..].bytes().all(|byte| byte.is_ascii_hexdigit())) {
        parts.pop();
    }
    let text = parts.join("::");
    let replacements = [("$LT$", "<"), ("$GT$", ">"), ("$RF$", "&"), ("$BP$", "*"), ("$u20$", " "), ("$u27$", "'"), ("$u5b$", "["), ("$u5d$", "]"), ("$u7b$", "{"), ("$u7d$", "}"), ("$u7e$", "~"), ("$C$", ","), ("..", "::")];
    let mut output = text;
    for (from, to) in replacements {
        output = output.replace(from, to);
    }
    Some(output)
}

struct Parser<'a> {
    bytes: &'a [u8],
    position: usize,
    depth: u32,
}

type Result = std::result::Result<(), ()>;

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn next(&mut self) -> std::result::Result<u8, ()> {
        let byte = self.peek().ok_or(())?;
        self.position += 1;
        Ok(byte)
    }

    fn eat(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    /// `{0-9a-zA-Z} _`: o valor é o número + 1 (`_` sozinho = 0).
    fn base62(&mut self) -> std::result::Result<u64, ()> {
        if self.eat(b'_') {
            return Ok(0);
        }
        let mut value: u64 = 0;
        loop {
            let byte = self.next()?;
            if byte == b'_' {
                return value.checked_add(1).ok_or(());
            }
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'z' => byte - b'a' + 10,
                b'A'..=b'Z' => byte - b'A' + 36,
                _ => return Err(()),
            } as u64;
            value = value.checked_mul(62).and_then(|value| value.checked_add(digit)).ok_or(())?;
        }
    }

    fn decimal(&mut self) -> std::result::Result<usize, ()> {
        let start = self.position;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.position += 1;
        }
        std::str::from_utf8(&self.bytes[start..self.position]).map_err(|_| ())?.parse().map_err(|_| ())
    }

    fn disambiguator(&mut self) -> std::result::Result<u64, ()> {
        if self.eat(b's') { self.base62().map(|value| value + 1) } else { Ok(0) }
    }

    /// `[u] <decimal> [_] <bytes>`.
    fn identifier(&mut self) -> std::result::Result<String, ()> {
        let punycode = self.eat(b'u');
        let length = self.decimal()?;
        self.eat(b'_');
        let bytes = self.bytes.get(self.position..self.position + length).ok_or(())?;
        self.position += length;
        let text = String::from_utf8_lossy(bytes).into_owned();
        Ok(if punycode { format!("{{punycode:{text}}}") } else { text })
    }

    /// Reinterpreta a partir de uma referência para trás.
    fn backref<T>(&mut self, body: impl FnOnce(&mut Self) -> std::result::Result<T, ()>) -> std::result::Result<T, ()> {
        let target = self.base62()? as usize;
        if target >= self.position || self.depth > 64 {
            return Err(());
        }
        let saved = self.position;
        self.position = target;
        self.depth += 1;
        let result = body(self);
        self.depth -= 1;
        self.position = saved;
        result
    }

    fn path(&mut self, output: &mut String, in_type: bool) -> Result {
        if self.depth > 200 {
            return Err(());
        }
        match self.next()? {
            b'C' => {
                self.disambiguator()?;
                output.push_str(&self.identifier()?);
            }
            b'M' => {
                self.disambiguator()?;
                let mut ignored = String::new();
                self.path(&mut ignored, false)?;
                output.push('<');
                self.type_(output)?;
                output.push('>');
            }
            b'X' => {
                self.disambiguator()?;
                let mut ignored = String::new();
                self.path(&mut ignored, false)?;
                output.push('<');
                self.type_(output)?;
                output.push_str(" as ");
                self.path(output, true)?;
                output.push('>');
            }
            b'Y' => {
                output.push('<');
                self.type_(output)?;
                output.push_str(" as ");
                self.path(output, true)?;
                output.push('>');
            }
            b'N' => {
                let namespace = self.next()?;
                self.path(output, in_type)?;
                let disambiguator = self.disambiguator()?;
                let name = self.identifier()?;
                match namespace {
                    b'C' => {
                        output.push_str("::{closure");
                        if !name.is_empty() {
                            output.push(':');
                            output.push_str(&name);
                        }
                        output.push_str(&format!("#{disambiguator}}}"));
                    }
                    b'S' => {
                        output.push_str("::{shim");
                        if !name.is_empty() {
                            output.push(':');
                            output.push_str(&name);
                        }
                        output.push_str(&format!("#{disambiguator}}}"));
                    }
                    b'A'..=b'Z' => {
                        output.push_str(&format!("::{{{}:{}#{}}}", namespace as char, name, disambiguator));
                    }
                    _ => {
                        if !name.is_empty() {
                            output.push_str("::");
                            output.push_str(&name);
                        }
                    }
                }
            }
            b'I' => {
                self.path(output, in_type)?;
                if !in_type {
                    output.push_str("::");
                }
                output.push('<');
                let mut first = true;
                while !self.eat(b'E') {
                    if !first {
                        output.push_str(", ");
                    }
                    first = false;
                    self.generic_argument(output)?;
                }
                output.push('>');
            }
            b'B' => {
                let mut text = String::new();
                self.backref(|parser| parser.path(&mut text, in_type))?;
                output.push_str(&text);
            }
            _ => return Err(()),
        }
        Ok(())
    }

    fn generic_argument(&mut self, output: &mut String) -> Result {
        if self.eat(b'L') {
            self.base62()?;
            output.push_str("'_");
            Ok(())
        } else if self.eat(b'K') {
            self.constant(output)
        } else {
            self.type_(output)
        }
    }

    fn basic_type(byte: u8) -> Option<&'static str> {
        Some(match byte {
            b'a' => "i8",
            b'b' => "bool",
            b'c' => "char",
            b'd' => "f64",
            b'e' => "str",
            b'f' => "f32",
            b'h' => "u8",
            b'i' => "isize",
            b'j' => "usize",
            b'l' => "i32",
            b'm' => "u32",
            b'n' => "i128",
            b'o' => "u128",
            b's' => "i16",
            b't' => "u16",
            b'u' => "()",
            b'v' => "...",
            b'x' => "i64",
            b'y' => "u64",
            b'z' => "!",
            b'p' => "_",
            _ => return None,
        })
    }

    fn type_(&mut self, output: &mut String) -> Result {
        if self.depth > 200 {
            return Err(());
        }
        let byte = self.peek().ok_or(())?;
        if let Some(name) = Self::basic_type(byte) {
            self.position += 1;
            output.push_str(name);
            return Ok(());
        }
        match byte {
            b'R' | b'Q' => {
                self.position += 1;
                if self.eat(b'L') {
                    self.base62()?;
                }
                output.push_str(if byte == b'R' { "&" } else { "&mut " });
                self.type_(output)
            }
            b'P' | b'O' => {
                self.position += 1;
                output.push_str(if byte == b'P' { "*const " } else { "*mut " });
                self.type_(output)
            }
            b'A' => {
                self.position += 1;
                output.push('[');
                self.type_(output)?;
                output.push_str("; ");
                self.constant(output)?;
                output.push(']');
                Ok(())
            }
            b'S' => {
                self.position += 1;
                output.push('[');
                self.type_(output)?;
                output.push(']');
                Ok(())
            }
            b'T' => {
                self.position += 1;
                output.push('(');
                let mut count = 0;
                while !self.eat(b'E') {
                    if count > 0 {
                        output.push_str(", ");
                    }
                    self.type_(output)?;
                    count += 1;
                }
                if count == 1 {
                    output.push(',');
                }
                output.push(')');
                Ok(())
            }
            b'F' => {
                self.position += 1;
                if self.eat(b'G') {
                    self.base62()?;
                }
                let unsafe_ = self.eat(b'U');
                let mut abi = None;
                if self.eat(b'K') {
                    abi = Some(if self.eat(b'C') { "C".to_string() } else { self.identifier()?.replace('_', "-") });
                }
                if unsafe_ {
                    output.push_str("unsafe ");
                }
                if let Some(abi) = abi {
                    output.push_str(&format!("extern \"{abi}\" "));
                }
                output.push_str("fn(");
                let mut first = true;
                while !self.eat(b'E') {
                    if !first {
                        output.push_str(", ");
                    }
                    first = false;
                    self.type_(output)?;
                }
                output.push(')');
                if self.peek() != Some(b'u') {
                    output.push_str(" -> ");
                    self.type_(output)?;
                } else {
                    self.position += 1;
                }
                Ok(())
            }
            b'D' => {
                self.position += 1;
                if self.eat(b'G') {
                    self.base62()?;
                }
                output.push_str("dyn ");
                let mut first = true;
                while !self.eat(b'E') {
                    if !first {
                        output.push_str(" + ");
                    }
                    first = false;
                    self.path(output, true)?;
                    while self.eat(b'p') {
                        let name = self.identifier()?;
                        output.push_str(&format!("<{name} = "));
                        self.type_(output)?;
                        output.push('>');
                    }
                }
                if self.eat(b'L') {
                    self.base62()?;
                }
                Ok(())
            }
            b'B' => {
                self.position += 1;
                let mut text = String::new();
                self.backref(|parser| parser.type_(&mut text))?;
                output.push_str(&text);
                Ok(())
            }
            _ => self.path(output, true),
        }
    }

    fn constant(&mut self, output: &mut String) -> Result {
        let byte = self.next()?;
        match byte {
            b'p' => {
                output.push('_');
                Ok(())
            }
            b'B' => {
                let mut text = String::new();
                self.backref(|parser| parser.constant(&mut text))?;
                output.push_str(&text);
                Ok(())
            }
            _ if Self::basic_type(byte).is_some() => {
                let negative = self.eat(b'n');
                let start = self.position;
                while self.peek().is_some_and(|byte| byte != b'_') {
                    self.position += 1;
                }
                let digits = std::str::from_utf8(&self.bytes[start..self.position]).map_err(|_| ())?;
                self.position += 1;
                let value = u128::from_str_radix(if digits.is_empty() { "0" } else { digits }, 16).map_err(|_| ())?;
                match byte {
                    b'b' => output.push_str(if value != 0 { "true" } else { "false" }),
                    b'c' => output.push(char::from_u32(value as u32).unwrap_or('?')),
                    _ => output.push_str(&format!("{}{}", if negative { "-" } else { "" }, value)),
                }
                Ok(())
            }
            // Constantes compostas (str, referências, arrays, tuplas, ADTs).
            b'e' | b'R' | b'Q' | b'A' | b'T' | b'V' => {
                output.push_str("{const}");
                self.skip_constant(byte)
            }
            _ => Err(()),
        }
    }

    fn skip_constant(&mut self, kind: u8) -> Result {
        let mut ignored = String::new();
        match kind {
            b'e' => {
                while self.next()? != b'_' {}
                Ok(())
            }
            b'R' | b'Q' => self.constant(&mut ignored),
            b'A' | b'T' => {
                while !self.eat(b'E') {
                    self.constant(&mut ignored)?;
                }
                Ok(())
            }
            b'V' => {
                self.path(&mut ignored, true)?;
                match self.next()? {
                    b'U' => Ok(()),
                    b'T' => {
                        while !self.eat(b'E') {
                            self.constant(&mut ignored)?;
                        }
                        Ok(())
                    }
                    b'S' => {
                        while !self.eat(b'E') {
                            self.disambiguator()?;
                            self.identifier()?;
                            self.constant(&mut ignored)?;
                        }
                        Ok(())
                    }
                    _ => Err(()),
                }
            }
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::demangle;

    #[test]
    fn caminhos_v0() {
        assert_eq!(demangle("_RNvNtNtCs25FJyThIJz6_6kernel4ntos2ke16run_kernel_tasks").as_deref(), Some("kernel::ntos::ke::run_kernel_tasks"));
        assert_eq!(demangle("_RNvNtNtNtCs25FJyThIJz6_6kernel4ntos4init4main5kmain").as_deref(), Some("kernel::ntos::init::main::kmain"));
        let generic = demangle("_RINvNtNtCs25FJyThIJz6_6kernel4nano10interrupts22dispatch_pending_whereNCNvB2_16dispatch_pending0EB6_").unwrap();
        assert!(generic.starts_with("kernel::nano::interrupts::dispatch_pending_where::<"), "{generic}");
    }

    #[test]
    fn legado() {
        assert_eq!(demangle("_ZN6kernel4ntos2ke16run_kernel_tasks17h0123456789abcdefE").as_deref(), Some("kernel::ntos::ke::run_kernel_tasks"));
    }
}
