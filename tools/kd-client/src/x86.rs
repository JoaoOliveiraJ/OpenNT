//! O mínimo de x86-64 que o cliente decodifica sozinho: o tamanho de um
//! `call` (o passo por cima para na instrução seguinte) e onde está o
//! endereço de retorno quando o RIP está no prólogo ou no `ret` (a pilha e
//! o passo para fora). A desmontagem completa fica com a interface gráfica.

/// Prefixos legados (grupos 1 a 4).
fn is_legacy_prefix(byte: u8) -> bool {
    matches!(byte, 0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65)
}

/// Bytes do ModRM em diante (ModRM, SIB e deslocamento) no modo de 64 bits.
fn modrm_length(code: &[u8]) -> Option<usize> {
    let modrm = *code.first()?;
    let mode = modrm >> 6;
    let rm = modrm & 7;
    if mode == 3 {
        return Some(1);
    }
    let mut length = 1;
    if rm == 4 {
        let sib = *code.get(1)?;
        length += 1;
        if mode == 0 && sib & 7 == 5 {
            length += 4;
        }
    } else if mode == 0 && rm == 5 {
        // Relativo ao RIP.
        length += 4;
    }
    length += match mode {
        1 => 1,
        2 => 4,
        _ => 0,
    };
    Some(length)
}

/// Tamanho da instrução se ela é um `call` (direto `E8 rel32`, indireto
/// `FF /2` ou distante `FF /3`); `None` para qualquer outra.
pub fn call_length(code: &[u8]) -> Option<usize> {
    let mut index = 0;
    while index < code.len() && index < 14 && is_legacy_prefix(code[index]) {
        index += 1;
    }
    if code.get(index).is_some_and(|byte| byte & 0xF0 == 0x40) {
        index += 1;
    }
    match *code.get(index)? {
        0xE8 => Some(index + 5),
        0xFF => {
            let reg = (code.get(index + 1)? >> 3) & 7;
            if reg == 2 || reg == 3 {
                Some(index + 1 + modrm_length(&code[index + 1..])?)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// O que a instrução faz com o fluxo: `call` (com o tamanho), `ret` ou
/// outra.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    Call(usize),
    Return,
    Other,
}

pub fn flow(code: &[u8]) -> Flow {
    if let Some(length) = call_length(code) {
        return Flow::Call(length);
    }
    let mut index = 0;
    while index < code.len() && index < 14 && is_legacy_prefix(code[index]) {
        index += 1;
    }
    if code.get(index).is_some_and(|byte| byte & 0xF0 == 0x40) {
        index += 1;
    }
    match code.get(index) {
        Some(0xC3 | 0xC2 | 0xCB | 0xCA) => Flow::Return,
        _ => Flow::Other,
    }
}

/// Onde está o endereço de retorno da função quando o RIP aponta para
/// `code`: no topo da pilha antes do `push rbp` e no `ret`, logo acima dele
/// entre o `push rbp` e o `mov rbp, rsp`; `None` quando o quadro já está
/// montado (o retorno fica em RBP + 8).
pub fn prologue_return_slot(code: &[u8], rsp: u64) -> Option<u64> {
    match code {
        [0x55, ..] | [0xC3, ..] | [0xC2, ..] => Some(rsp),
        [0x48, 0x89, 0xE5, ..] | [0x48, 0x8B, 0xEC, ..] => Some(rsp + 8),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_lengths() {
        // call rel32
        assert_eq!(call_length(&[0xE8, 1, 2, 3, 4, 0x90]), Some(5));
        // call rax / call r11 (REX.B)
        assert_eq!(call_length(&[0xFF, 0xD0]), Some(2));
        assert_eq!(call_length(&[0x41, 0xFF, 0xD3]), Some(3));
        // call qword ptr [rip+disp32]
        assert_eq!(call_length(&[0xFF, 0x15, 0, 0, 0, 0]), Some(6));
        // call qword ptr [rax+8]
        assert_eq!(call_length(&[0xFF, 0x50, 0x08]), Some(3));
        // call qword ptr [rsp+rcx*8+0x100] (SIB + disp32)
        assert_eq!(call_length(&[0xFF, 0x94, 0xCC, 0, 1, 0, 0]), Some(7));
        // call qword ptr [disp32] via SIB sem base
        assert_eq!(call_length(&[0xFF, 0x14, 0x25, 0, 0, 0, 0]), Some(7));
        // call qword ptr gs:[rax]
        assert_eq!(call_length(&[0x65, 0xFF, 0x10]), Some(3));
        // jmp rax e push qword ptr [rax] não são chamadas.
        assert_eq!(call_length(&[0xFF, 0xE0]), None);
        assert_eq!(call_length(&[0xFF, 0x30]), None);
        assert_eq!(call_length(&[0x90]), None);
        assert_eq!(call_length(&[]), None);
    }

    #[test]
    fn prologue() {
        assert_eq!(prologue_return_slot(&[0x55, 0x48, 0x89, 0xE5], 0x1000), Some(0x1000));
        assert_eq!(prologue_return_slot(&[0x48, 0x89, 0xE5], 0x1000), Some(0x1008));
        assert_eq!(prologue_return_slot(&[0xC3], 0x1000), Some(0x1000));
        assert_eq!(prologue_return_slot(&[0x48, 0x83, 0xEC, 0x20], 0x1000), None);
    }

    #[test]
    fn classifies_flow() {
        assert_eq!(flow(&[0xE8, 0, 0, 0, 0]), Flow::Call(5));
        assert_eq!(flow(&[0xC3]), Flow::Return);
        assert_eq!(flow(&[0xF3, 0xC3]), Flow::Return);
        assert_eq!(flow(&[0xC2, 0x08, 0x00]), Flow::Return);
        assert_eq!(flow(&[0x48, 0x89, 0xE5]), Flow::Other);
    }
}
