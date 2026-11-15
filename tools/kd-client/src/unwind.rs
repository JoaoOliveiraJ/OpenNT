//! A pilha pelos frame pointers (o kernel é compilado com
//! `force-frame-pointers`): cada quadro guarda o RBP do chamador em [RBP] e
//! o endereço de retorno em [RBP + 8]. No prólogo (`push rbp` ou `mov rbp,
//! rsp` ainda por executar) e no `ret`, o endereço de retorno está no topo
//! da pilha e o RBP ainda é o do chamador.
//!
//! O desenrolar só lê memória por `ReadMemory`: o alvo pela sessão, ou uma
//! pilha capturada nos testes.

use super::x86;

/// Leitor de memória do alvo.
pub trait ReadMemory {
    /// Lê até `length` bytes (menos quando a leitura para numa página
    /// inacessível); erro se nem o primeiro byte pôde ser lido.
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String>;

    fn read_u64(&mut self, address: u64) -> Option<u64> {
        let bytes = self.read(address, 8).ok()?;
        Some(u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?))
    }
}

/// Um quadro da pilha.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    pub address: u64,
    /// O endereço é de retorno (a instrução depois de um `call`): o símbolo
    /// certo é o do byte anterior.
    pub is_return: bool,
}

/// Onde está o endereço de retorno da função em que o RIP está: no prólogo
/// e no `ret`, no topo da pilha; com o quadro montado, em RBP + 8.
pub fn return_slot(memory: &mut dyn ReadMemory, rip: u64, rsp: u64, rbp: u64) -> u64 {
    let code = memory.read(rip, 3).unwrap_or_default();
    x86::prologue_return_slot(&code, rsp).unwrap_or(rbp.wrapping_add(8))
}

/// A pilha a partir dos registradores de um processador parado.
pub fn unwind(memory: &mut dyn ReadMemory, rip: u64, rsp: u64, rbp: u64, limit: usize) -> Vec<Frame> {
    let mut frames = vec![Frame { address: rip, is_return: false }];
    let code = memory.read(rip, 3).unwrap_or_default();
    if let Some(slot) = x86::prologue_return_slot(&code, rsp) {
        if let Some(address) = memory.read_u64(slot) {
            frames.push(Frame { address, is_return: true });
        }
    }
    follow_chain(memory, frames, rbp, limit)
}

/// Segue a cadeia de RBP a partir dos quadros já conhecidos.
pub fn follow_chain(memory: &mut dyn ReadMemory, mut frames: Vec<Frame>, mut rbp: u64, limit: usize) -> Vec<Frame> {
    while frames.len() < limit && rbp != 0 && rbp & 7 == 0 {
        let Ok(frame) = memory.read(rbp, 16) else { break };
        if frame.len() < 16 {
            break;
        }
        let next = u64::from_le_bytes(frame[..8].try_into().unwrap());
        let address = u64::from_le_bytes(frame[8..16].try_into().unwrap());
        if address == 0 {
            break;
        }
        frames.push(Frame { address, is_return: true });
        if next <= rbp {
            break;
        }
        rbp = next;
    }
    frames
}

/// Uma pilha capturada: bytes a partir de um endereço (os testes, e o
/// código em volta do RIP).
pub struct Captured {
    pub regions: Vec<(u64, Vec<u8>)>,
}

impl ReadMemory for Captured {
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
        for (base, bytes) in &self.regions {
            if address >= *base && address < base + bytes.len() as u64 {
                let start = (address - base) as usize;
                let end = (start + length).min(bytes.len());
                return Ok(bytes[start..end].to_vec());
            }
        }
        Err(format!("memoria em {address:#x} inacessivel"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Uma pilha de kernel de verdade, como o `x %rsp 0x60` a mostra num
    /// breakpoint dentro de uma função com o quadro montado: três quadros
    /// encadeados e um RBP zerado no fim.
    fn captured_stack() -> Captured {
        let base = 0xffff_8000_0010_0f00u64;
        let mut stack = vec![0u8; 0x100];
        let mut put = |offset: usize, value: u64| stack[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        // Quadro 1 (RBP = base + 0x20): RBP salvo -> base + 0x60, retorno.
        put(0x20, base + 0x60);
        put(0x28, 0xfffff800_4012_3456);
        // Quadro 2 (base + 0x60) -> base + 0xa0.
        put(0x60, base + 0xa0);
        put(0x68, 0xfffff800_4000_2222);
        // Quadro 3 (base + 0xa0): fim da cadeia.
        put(0xa0, 0);
        put(0xa8, 0xfffff800_4000_1111);
        let code_base = 0xfffff800_4010_0000u64;
        // O RIP aponta para `sub rsp, 0x20` (depois do prólogo) e, num
        // segundo cenário, para o `push rbp`.
        let code = vec![0x48, 0x83, 0xEC, 0x20, 0x55, 0x48, 0x89, 0xE5];
        Captured { regions: vec![(base, stack), (code_base, code)] }
    }

    #[test]
    fn unwinds_framed_function() {
        let mut memory = captured_stack();
        let base = 0xffff_8000_0010_0f00u64;
        let frames = unwind(&mut memory, 0xfffff800_4010_0000, base, base + 0x20, 32);
        let addresses: Vec<u64> = frames.iter().map(|frame| frame.address).collect();
        assert_eq!(addresses, vec![0xfffff800_4010_0000, 0xfffff800_4012_3456, 0xfffff800_4000_2222, 0xfffff800_4000_1111]);
        assert!(!frames[0].is_return);
        assert!(frames[1..].iter().all(|frame| frame.is_return));
        assert_eq!(return_slot(&mut memory, 0xfffff800_4010_0000, base, base + 0x20), base + 0x28);
    }

    #[test]
    fn unwinds_at_push_rbp() {
        // No `push rbp`, o retorno está em [RSP] (base + 0x18 aqui) e o RBP
        // ainda é o do chamador (o quadro 1).
        let mut memory = captured_stack();
        let base = 0xffff_8000_0010_0f00u64;
        if let Some((_, stack)) = memory.regions.first_mut() {
            stack[0x18..0x20].copy_from_slice(&0xfffff800_4013_0000u64.to_le_bytes());
        }
        let frames = unwind(&mut memory, 0xfffff800_4010_0004, base + 0x18, base + 0x20, 32);
        let addresses: Vec<u64> = frames.iter().map(|frame| frame.address).collect();
        assert_eq!(addresses, vec![0xfffff800_4010_0004, 0xfffff800_4013_0000, 0xfffff800_4012_3456, 0xfffff800_4000_2222, 0xfffff800_4000_1111]);
        assert_eq!(return_slot(&mut memory, 0xfffff800_4010_0004, base + 0x18, base + 0x20), base + 0x18);
    }

    #[test]
    fn stops_on_limit_and_bad_frames() {
        let mut memory = captured_stack();
        let base = 0xffff_8000_0010_0f00u64;
        assert_eq!(unwind(&mut memory, 0xfffff800_4010_0000, base, base + 0x20, 2).len(), 2);
        // RBP desalinhado ou fora da memória: só o RIP.
        assert_eq!(unwind(&mut memory, 0xfffff800_4010_0000, base, base + 0x21, 32).len(), 1);
        assert_eq!(unwind(&mut memory, 0xfffff800_4010_0000, base, 0x1000, 32).len(), 1);
    }
}
