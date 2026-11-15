//! Registradores de um processador parado na ordem do GDB para x86-64 (a
//! descrição padrão do i386:x86-64: núcleo e SSE).
//!
//! | n.º    | registradores                        | bytes |
//! |--------|--------------------------------------|-------|
//! | 0-15   | rax rbx rcx rdx rsi rdi rbp rsp r8-r15 | 8   |
//! | 16     | rip                                  | 8     |
//! | 17     | eflags                               | 4     |
//! | 18-23  | cs ss ds es fs gs                    | 4     |
//! | 24-31  | st0-st7 (80 bits)                    | 10    |
//! | 32-39  | fctrl fstat ftag fiseg fioff foseg fooff fop | 4 |
//! | 40-55  | xmm0-xmm15                           | 16    |
//! | 56     | mxcsr                                | 4     |
//! | 57-58  | fs_base gs_base (só por `p`)         | 8     |
//!
//! Os inteiros vêm do quadro de trap (`TrapFrame`, com o quadro do hardware
//! depois do vetor); x87 e SSE da área FXSAVE64 da entrada do depurador (um
//! processador congelado pela NMI não tem essa área: os registradores ficam
//! indisponíveis, `xx` no pacote). O FXSAVE64 guarda FIP e FDP de 64 bits:
//! fioff/fooff recebem os 32 bits baixos e fiseg/foseg os altos, e a
//! palavra de tags completa sai da abreviada pela classe de cada registrador.

use crate::hal::amd64::irqstubs::TrapFrame;

/// Registradores do pacote `g`.
pub const PACKET_REGISTERS: usize = 57;
/// Último número aceito por `p`/`P`.
pub const LAST_REGISTER: usize = 58;

const RIP: usize = 16;
const EFLAGS: usize = 17;

/// Tamanho do registrador `number` no protocolo.
pub fn size(number: usize) -> usize {
    match number {
        0..=16 => 8,
        17..=23 => 4,
        24..=31 => 10,
        32..=39 => 4,
        40..=55 => 16,
        56 => 4,
        57 | 58 => 8,
        _ => 0,
    }
}

/// Posição (em u64) de cada inteiro do GDB no `TrapFrame`; `None` = quadro
/// do hardware.
fn frame_slot(number: usize) -> Option<usize> {
    Some(match number {
        0 => 14,
        1 => 5,
        2 => 13,
        3 => 12,
        4 => 11,
        5 => 10,
        6 => 4,
        8 => 9,
        9 => 8,
        10 => 7,
        11 => 6,
        12 => 3,
        13 => 2,
        14 => 1,
        15 => 0,
        _ => return None,
    })
}

/// O estado de um processador parado: o quadro, a área FXSAVE64 (0 sem
/// ela), os seletores de dados e as bases de FS e GS.
#[derive(Clone, Copy, Default)]
pub struct View {
    pub frame: u64,
    pub error_code: bool,
    pub fx: u64,
    pub segments: [u16; 4],
    pub fs_base: u64,
    pub gs_base: u64,
}

impl View {
    fn word(&self, index: usize) -> u64 {
        // SAFETY: célula do quadro de trap vivo do processador parado.
        unsafe { core::ptr::read_volatile((self.frame + index as u64 * 8) as *const u64) }
    }

    fn set_word(&self, index: usize, value: u64) {
        // SAFETY: como em `word`; o quadro volta para a CPU no IRETQ.
        unsafe { core::ptr::write_volatile((self.frame + index as u64 * 8) as *mut u64, value) }
    }

    /// Índice (em u64) da entrada `offset` do quadro do hardware (0 = RIP,
    /// 1 = CS, 2 = RFLAGS, 3 = RSP, 4 = SS).
    fn hardware(&self, offset: usize) -> usize {
        core::mem::size_of::<TrapFrame>() / 8 - 6 + self.error_code as usize + offset
    }

    pub fn rip(&self) -> u64 {
        self.word(self.hardware(0))
    }

    pub fn set_rip(&self, value: u64) {
        self.set_word(self.hardware(0), value)
    }

    pub fn rflags(&self) -> u64 {
        self.word(self.hardware(2))
    }

    pub fn set_rflags(&self, value: u64) {
        self.set_word(self.hardware(2), value)
    }

    pub fn rsp(&self) -> u64 {
        self.word(self.hardware(3))
    }

    pub fn rbp(&self) -> u64 {
        self.word(4)
    }

    pub fn cs(&self) -> u64 {
        self.word(self.hardware(1))
    }

    fn fx_bytes(&self, offset: u64, output: &mut [u8]) {
        for (index, byte) in output.iter_mut().enumerate() {
            // SAFETY: área FXSAVE64 da entrada do depurador, na pilha da parada.
            *byte = unsafe { core::ptr::read_volatile((self.fx + offset + index as u64) as *const u8) };
        }
    }

    fn set_fx_bytes(&self, offset: u64, input: &[u8]) {
        for (index, &byte) in input.iter().enumerate() {
            // SAFETY: como em `fx_bytes`; o FXRSTOR da saída a recarrega.
            unsafe { core::ptr::write_volatile((self.fx + offset + index as u64) as *mut u8, byte) };
        }
    }

    fn fx_u16(&self, offset: u64) -> u16 {
        let mut bytes = [0u8; 2];
        self.fx_bytes(offset, &mut bytes);
        u16::from_le_bytes(bytes)
    }

    fn fx_u32(&self, offset: u64) -> u32 {
        let mut bytes = [0u8; 4];
        self.fx_bytes(offset, &mut bytes);
        u32::from_le_bytes(bytes)
    }

    /// Palavra de tags completa a partir da abreviada do FXSAVE.
    fn full_tag_word(&self) -> u16 {
        let abridged = self.fx_bytes_one(4);
        let top = (self.fx_u16(2) >> 11) & 7;
        let mut tags = 0u16;
        for physical in 0..8u16 {
            let tag = if abridged & (1 << physical) == 0 {
                3
            } else {
                let mut value = [0u8; 10];
                self.fx_bytes(32 + ((physical.wrapping_sub(top)) & 7) as u64 * 16, &mut value);
                let exponent = u16::from_le_bytes([value[8], value[9]]) & 0x7FFF;
                let integer = value[7] & 0x80 != 0;
                let fraction_zero = value[..8].iter().all(|&byte| byte == 0);
                if exponent == 0x7FFF {
                    2
                } else if exponent == 0 {
                    if fraction_zero { 1 } else { 2 }
                } else if integer {
                    0
                } else {
                    2
                }
            };
            tags |= tag << (physical * 2);
        }
        tags
    }

    fn fx_bytes_one(&self, offset: u64) -> u8 {
        let mut byte = [0u8];
        self.fx_bytes(offset, &mut byte);
        byte[0]
    }

    /// Valor do registrador `number` em `output` (pelo menos `size` bytes);
    /// `false` se indisponível.
    pub fn read(&self, number: usize, output: &mut [u8]) -> bool {
        let width = size(number);
        if width == 0 || output.len() < width {
            return false;
        }
        let output = &mut output[..width];
        output.fill(0);
        match number {
            0..=15 => {
                let value = match frame_slot(number) {
                    Some(slot) => self.word(slot),
                    None => self.rsp(),
                };
                output.copy_from_slice(&value.to_le_bytes());
            }
            RIP => output.copy_from_slice(&self.rip().to_le_bytes()),
            EFLAGS => output.copy_from_slice(&(self.rflags() as u32).to_le_bytes()),
            18 => output.copy_from_slice(&(self.cs() as u32).to_le_bytes()),
            19 => output.copy_from_slice(&(self.word(self.hardware(4)) as u32).to_le_bytes()),
            20..=23 => output.copy_from_slice(&(self.segments[number - 20] as u32).to_le_bytes()),
            57 => output.copy_from_slice(&self.fs_base.to_le_bytes()),
            58 => output.copy_from_slice(&self.gs_base.to_le_bytes()),
            _ if self.fx == 0 => return false,
            24..=31 => self.fx_bytes(32 + (number - 24) as u64 * 16, output),
            32 => output[..2].copy_from_slice(&self.fx_u16(0).to_le_bytes()),
            33 => output[..2].copy_from_slice(&self.fx_u16(2).to_le_bytes()),
            34 => output[..2].copy_from_slice(&self.full_tag_word().to_le_bytes()),
            35 => output.copy_from_slice(&self.fx_u32(12).to_le_bytes()),
            36 => output.copy_from_slice(&self.fx_u32(8).to_le_bytes()),
            37 => output.copy_from_slice(&self.fx_u32(20).to_le_bytes()),
            38 => output.copy_from_slice(&self.fx_u32(16).to_le_bytes()),
            39 => output[..2].copy_from_slice(&(self.fx_u16(6) & 0x7FF).to_le_bytes()),
            40..=55 => self.fx_bytes(160 + (number - 40) as u64 * 16, output),
            56 => output.copy_from_slice(&self.fx_u32(24).to_le_bytes()),
            _ => return false,
        }
        true
    }

    /// Grava o registrador `number`. Seletores e bases de segmento não
    /// mudam (o GS do anel 0 é a KPCR); o RFLAGS mantém o bit 1 ligado.
    pub fn write(&self, number: usize, input: &[u8]) -> bool {
        let width = size(number);
        if width == 0 || input.len() < width {
            return false;
        }
        let input = &input[..width];
        let quad = |bytes: &[u8]| {
            let mut value = [0u8; 8];
            value[..bytes.len().min(8)].copy_from_slice(&bytes[..bytes.len().min(8)]);
            u64::from_le_bytes(value)
        };
        match number {
            0..=15 => match frame_slot(number) {
                Some(slot) => self.set_word(slot, quad(input)),
                None => self.set_word(self.hardware(3), quad(input)),
            },
            RIP => self.set_rip(quad(input)),
            EFLAGS => self.set_rflags((self.rflags() & !0xFFFF_FFFF) | (quad(input) & 0xFFFF_FFFF) | 2),
            18..=23 | 57 | 58 => {}
            _ if self.fx == 0 => {}
            24..=31 => self.set_fx_bytes(32 + (number - 24) as u64 * 16, input),
            32 => self.set_fx_bytes(0, &input[..2]),
            33 => self.set_fx_bytes(2, &input[..2]),
            34 => {
                // Tag 3 (vazio) apaga o bit abreviado; as outras o ligam.
                let full = u16::from_le_bytes([input[0], input[1]]);
                let mut abridged = 0u8;
                for physical in 0..8 {
                    if (full >> (physical * 2)) & 3 != 3 {
                        abridged |= 1 << physical;
                    }
                }
                self.set_fx_bytes(4, &[abridged]);
            }
            35 => self.set_fx_bytes(12, input),
            36 => self.set_fx_bytes(8, input),
            37 => self.set_fx_bytes(20, input),
            38 => self.set_fx_bytes(16, input),
            39 => self.set_fx_bytes(6, &input[..2]),
            40..=55 => self.set_fx_bytes(160 + (number - 40) as u64 * 16, input),
            56 => self.set_fx_bytes(24, input),
            _ => return false,
        }
        true
    }
}
