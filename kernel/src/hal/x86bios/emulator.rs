//! Emulador de x86 em modo real: o processador que executa o BIOS de vídeo
//! da máquina para as chamadas x86Bios*.
//!
//! Emula o conjunto inteiro do 386 em modo real — operandos e endereços de
//! 16 e 32 bits (prefixos 66h e 67h, SIB), prefixos de segmento, REP/REPNE —
//! com o mesmo contrato do emulador da HAL do Windows 10 19041:
//! - limites de segmento de 64 KB: um operando que passa de FFFFh (ou uma
//!   busca de código além de FFFFh) encerra a emulação com
//!   [`Status::SegmentLimit`]; a pilha usa o ESP inteiro e transbordar ou
//!   esvaziar além do limite dá [`Status::StackOverflow`] /
//!   [`Status::StackUnderflow`];
//! - o mapa de opcodes é o do emulador da HAL: sem x87, sem as instruções de
//!   sistema (0F 01 só tem o SMSW, que lê 2Dh), RDTSC lê o contador de
//!   desempenho, 82h, D6h, F1h, os sinônimos dos grupos (F6/F7 /1, grupo 2
//!   /6, FF /7) e os 0F não listados são ilegais; FE usa só o bit baixo do
//!   campo reg; BSWAP é só o 0F C8 e toma o registrador de um ModRM; ENTER
//!   aceita nível 0 ou 1;
//! - os desvios curtos (Jcc rel8, JMP rel8, LOOP, JCXZ) e os Jcc rel16/rel32
//!   guardam o destino em 16 bits, mesmo com o prefixo 66h; LOOP conta pela
//!   largura do endereço e JCXZ testa CX ou ECX pela largura do operando;
//! - INT n empilha FLAGS, CS e IP na largura do operando, sem mexer em IF e
//!   TF, e lê o vetor da IVT; INT 42h é ignorada e INT 1Ah passa antes pela
//!   emulação do PCI BIOS ([`Bus::pci_bios`]);
//! - IRET, RET e RETF que chegam a FFFF:FFFF (o quadro falso que a chamada
//!   empilha) terminam a emulação com [`Status::Success`].
//!
//! A memória e as portas são as do [`Bus`]: o emulador só calcula o par
//! (segmento, deslocamento) de cada acesso, e quem o implementa traduz para
//! a memória da máquina (`hal::x86bios`).

use super::operations::{self as alu, Shift, CF, DF, IF, OF, ZF};

/// Registradores de segmento, na ordem da codificação do x86.
pub const ES: usize = 0;
pub const CS: usize = 1;
pub const SS: usize = 2;
pub const DS: usize = 3;
pub const FS: usize = 4;
pub const GS: usize = 5;

/// Registradores gerais, na ordem da codificação do x86.
pub const EAX: usize = 0;
pub const ECX: usize = 1;
pub const EDX: usize = 2;
pub const EBX: usize = 3;
pub const ESP: usize = 4;
pub const EBP: usize = 5;
pub const ESI: usize = 6;
pub const EDI: usize = 7;

/// Limite dos segmentos em modo real.
const SEGMENT_LIMIT: u32 = 0xFFFF;

/// Resultado de uma emulação (o código que a HAL do Windows usa para cada
/// motivo de parada).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Status {
    /// Voltou ao quadro falso FFFF:FFFF.
    Success = 1,
    DivideByZero = 2,
    DivideOverflow = 3,
    /// Interface sem inicialização (devolvido pela camada x86Bios).
    NotInitialized = 4,
    Halt = 5,
    /// ENTER com nível de aninhamento maior que 1.
    EnterLevel = 8,
    /// Porta de I/O + largura além de FFFFh.
    PortRange = 9,
    /// Instrução que exige operando em registrador recebeu memória.
    RegisterRequired = 0xA,
    /// Instrução que exige operando em memória recebeu registrador.
    MemoryRequired = 0xB,
    IllegalInstruction = 0xC,
    BoundRange = 0xD,
    SegmentLimit = 0xE,
    StackOverflow = 0xF,
    StackUnderflow = 0x10,
}

/// Memória e portas vistas pelo processador emulado.
pub trait Bus {
    /// Lê `size` bytes (1, 2 ou 4) em `segment:offset` (offset dentro do
    /// limite do segmento).
    fn read(&mut self, segment: u16, offset: u32, size: u32) -> u32;
    fn write(&mut self, segment: u16, offset: u32, size: u32, value: u32);
    fn read_port(&mut self, port: u16, size: u32) -> u32;
    fn write_port(&mut self, port: u16, size: u32, value: u32);
    /// INT 1Ah: `true` se o PCI BIOS emulado atendeu a função (AH = B1h).
    fn pci_bios(&mut self, cpu: &mut Cpu) -> bool;
    /// Valor que o RDTSC devolve.
    fn performance_counter(&mut self) -> u64;
}

/// Estado do processador emulado. Persiste entre as chamadas, como o
/// contexto único do emulador da HAL (FS, GS e EFLAGS seguem de uma chamada
/// para a outra).
#[derive(Clone, Copy, Debug, Default)]
pub struct Cpu {
    pub gpr: [u32; 8],
    pub segment: [u16; 6],
    pub eip: u32,
    pub eflags: u32,
}

impl Cpu {
    pub const fn new() -> Self {
        Self { gpr: [0; 8], segment: [0; 6], eip: 0, eflags: 0 }
    }
}

/// Prefixo de repetição.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Repeat {
    None,
    /// F3: REP/REPE.
    Equal,
    /// F2: REPNE.
    NotEqual,
}

/// Operando de um ModRM.
#[derive(Clone, Copy)]
enum Operand {
    Register(usize),
    Memory { segment: usize, offset: u32 },
}

type Step = Result<(), Status>;

/// Executa a partir de CS:EIP até um status de parada.
pub fn run<B: Bus>(cpu: &mut Cpu, bus: &mut B) -> Status {
    loop {
        if let Err(status) = step(cpu, bus) {
            return status;
        }
    }
}

/// Executa uma instrução (com os prefixos); `Err` traz o status de parada.
pub fn step<B: Bus>(cpu: &mut Cpu, bus: &mut B) -> Result<(), Status> {
    Machine { cpu, bus, operand32: false, address32: false, segment_override: None, repeat: Repeat::None }.step()
}

struct Machine<'a, B: Bus> {
    cpu: &'a mut Cpu,
    bus: &'a mut B,
    operand32: bool,
    address32: bool,
    segment_override: Option<usize>,
    repeat: Repeat,
}

impl<B: Bus> Machine<'_, B> {
    // ---- registradores ----------------------------------------------------

    fn operand_size(&self) -> u32 {
        if self.operand32 { 4 } else { 2 }
    }

    fn register(&self, index: usize, size: u32) -> u32 {
        match size {
            1 if index < 4 => self.cpu.gpr[index] & 0xFF,
            1 => (self.cpu.gpr[index - 4] >> 8) & 0xFF,
            2 => self.cpu.gpr[index] & 0xFFFF,
            _ => self.cpu.gpr[index],
        }
    }

    fn set_register(&mut self, index: usize, size: u32, value: u32) {
        match size {
            1 if index < 4 => self.cpu.gpr[index] = (self.cpu.gpr[index] & !0xFF) | (value & 0xFF),
            1 => self.cpu.gpr[index - 4] = (self.cpu.gpr[index - 4] & !0xFF00) | ((value & 0xFF) << 8),
            2 => self.cpu.gpr[index] = (self.cpu.gpr[index] & !0xFFFF) | (value & 0xFFFF),
            _ => self.cpu.gpr[index] = value,
        }
    }

    fn flag(&self, bit: u32) -> bool {
        self.cpu.eflags & bit != 0
    }

    fn set_flag(&mut self, bit: u32, on: bool) {
        if on {
            self.cpu.eflags |= bit;
        } else {
            self.cpu.eflags &= !bit;
        }
    }

    // ---- memória ----------------------------------------------------------

    fn check_limit(offset: u32, size: u32) -> Step {
        if offset > SEGMENT_LIMIT || offset + (size - 1) > SEGMENT_LIMIT {
            return Err(Status::SegmentLimit);
        }
        Ok(())
    }

    fn read_memory(&mut self, segment: usize, offset: u32, size: u32) -> Result<u32, Status> {
        Self::check_limit(offset, size)?;
        Ok(self.bus.read(self.cpu.segment[segment], offset, size) & alu::mask(size))
    }

    fn write_memory(&mut self, segment: usize, offset: u32, size: u32, value: u32) -> Step {
        Self::check_limit(offset, size)?;
        self.bus.write(self.cpu.segment[segment], offset, size, value & alu::mask(size));
        Ok(())
    }

    fn read_operand(&mut self, operand: Operand, size: u32) -> Result<u32, Status> {
        match operand {
            Operand::Register(index) => Ok(self.register(index, size)),
            Operand::Memory { segment, offset } => self.read_memory(segment, offset, size),
        }
    }

    fn write_operand(&mut self, operand: Operand, size: u32, value: u32) -> Step {
        match operand {
            Operand::Register(index) => {
                self.set_register(index, size, value);
                Ok(())
            }
            Operand::Memory { segment, offset } => self.write_memory(segment, offset, size, value),
        }
    }

    // ---- busca de código --------------------------------------------------

    fn fetch8(&mut self) -> Result<u32, Status> {
        let eip = self.cpu.eip;
        if eip > SEGMENT_LIMIT {
            return Err(Status::SegmentLimit);
        }
        // O IP avança em 16 bits.
        self.cpu.eip = (eip & 0xFFFF_0000) | (eip.wrapping_add(1) & 0xFFFF);
        Ok(self.bus.read(self.cpu.segment[CS], eip, 1) & 0xFF)
    }

    fn fetch16(&mut self) -> Result<u32, Status> {
        Ok(self.fetch8()? | (self.fetch8()? << 8))
    }

    fn fetch32(&mut self) -> Result<u32, Status> {
        Ok(self.fetch16()? | (self.fetch16()? << 16))
    }

    /// Imediato na largura `size`.
    fn fetch_immediate(&mut self, size: u32) -> Result<u32, Status> {
        match size {
            1 => self.fetch8(),
            2 => self.fetch16(),
            _ => self.fetch32(),
        }
    }

    // ---- pilha ------------------------------------------------------------

    fn push(&mut self, value: u32, size: u32) -> Step {
        let top = self.cpu.gpr[ESP].wrapping_sub(size);
        if top > SEGMENT_LIMIT - (size - 1) {
            return Err(Status::StackOverflow);
        }
        self.cpu.gpr[ESP] = top;
        self.bus.write(self.cpu.segment[SS], top, size, value & alu::mask(size));
        Ok(())
    }

    fn pop(&mut self, size: u32) -> Result<u32, Status> {
        let top = self.cpu.gpr[ESP];
        if top > SEGMENT_LIMIT - (size - 1) {
            return Err(Status::StackUnderflow);
        }
        let value = self.bus.read(self.cpu.segment[SS], top, size) & alu::mask(size);
        self.cpu.gpr[ESP] = top + size;
        Ok(value)
    }

    // ---- ModRM ------------------------------------------------------------

    fn data_segment(&self, default: usize) -> usize {
        self.segment_override.unwrap_or(default)
    }

    /// Decodifica o ModRM: (campo reg, operando).
    fn modrm(&mut self) -> Result<(usize, Operand), Status> {
        let byte = self.fetch8()?;
        let (mode, reg, rm) = (byte >> 6, ((byte >> 3) & 7) as usize, (byte & 7) as usize);
        if mode == 3 {
            return Ok((reg, Operand::Register(rm)));
        }
        let operand = if self.address32 { self.address32(mode, rm)? } else { self.address16(mode, rm)? };
        Ok((reg, operand))
    }

    fn address16(&mut self, mode: u32, rm: usize) -> Result<Operand, Status> {
        let gpr = |machine: &Self, index: usize| machine.cpu.gpr[index] & 0xFFFF;
        let (base, default) = match rm {
            0 => (gpr(self, EBX) + gpr(self, ESI), DS),
            1 => (gpr(self, EBX) + gpr(self, EDI), DS),
            2 => (gpr(self, EBP) + gpr(self, ESI), SS),
            3 => (gpr(self, EBP) + gpr(self, EDI), SS),
            4 => (gpr(self, ESI), DS),
            5 => (gpr(self, EDI), DS),
            6 if mode == 0 => (0, DS),
            6 => (gpr(self, EBP), SS),
            _ => (gpr(self, EBX), DS),
        };
        let displacement = match mode {
            0 if rm == 6 => self.fetch16()?,
            0 => 0,
            1 => alu::sign_extend(self.fetch8()?, 1),
            _ => self.fetch16()?,
        };
        Ok(Operand::Memory { segment: self.data_segment(default), offset: base.wrapping_add(displacement) & 0xFFFF })
    }

    fn address32(&mut self, mode: u32, rm: usize) -> Result<Operand, Status> {
        let mut default = DS;
        let base = if rm == 4 {
            let sib = self.fetch8()?;
            let (scale, index, base) = (sib >> 6, ((sib >> 3) & 7) as usize, (sib & 7) as usize);
            let index_value = if index == 4 { 0 } else { self.cpu.gpr[index] << scale };
            let base_value = if base == 5 && mode == 0 {
                self.fetch32()?
            } else {
                if base == ESP || base == EBP {
                    default = SS;
                }
                self.cpu.gpr[base]
            };
            base_value.wrapping_add(index_value)
        } else if rm == 5 && mode == 0 {
            self.fetch32()?
        } else {
            if rm == EBP {
                default = SS;
            }
            self.cpu.gpr[rm]
        };
        let displacement = match mode {
            0 => 0,
            1 => alu::sign_extend(self.fetch8()?, 1),
            _ => self.fetch32()?,
        };
        Ok(Operand::Memory { segment: self.data_segment(default), offset: base.wrapping_add(displacement) })
    }

    fn memory_operand(operand: Operand) -> Result<(usize, u32), Status> {
        match operand {
            Operand::Memory { segment, offset } => Ok((segment, offset)),
            Operand::Register(_) => Err(Status::MemoryRequired),
        }
    }

    // ---- desvios ------------------------------------------------------------

    /// JMP/CALL rel16/rel32: o IP novo na largura do operando.
    fn jump_relative(&mut self, displacement: u32) {
        let target = self.cpu.eip.wrapping_add(displacement);
        self.cpu.eip = if self.operand32 { target } else { target & 0xFFFF };
    }

    /// Desvios curtos (Jcc rel8, JMP rel8, LOOP, JCXZ) e Jcc rel16/rel32: o
    /// emulador da HAL guarda o destino em 16 bits, mesmo com o prefixo 66h.
    fn jump_short(&mut self, displacement: u32) {
        self.cpu.eip = self.cpu.eip.wrapping_add(displacement) & 0xFFFF;
    }

    fn jump_near(&mut self, target: u32) {
        self.cpu.eip = if self.operand32 { target } else { target & 0xFFFF };
    }

    /// RET/RETF/IRET em FFFF:FFFF: o quadro falso da chamada.
    fn returned_to_caller(&self) -> Step {
        if self.cpu.eip == 0xFFFF && self.cpu.segment[CS] == 0xFFFF {
            return Err(Status::Success);
        }
        Ok(())
    }

    // ---- laço ---------------------------------------------------------------

    fn step(&mut self) -> Step {
        self.operand32 = false;
        self.address32 = false;
        self.segment_override = None;
        self.repeat = Repeat::None;
        loop {
            let opcode = self.fetch8()? as u8;
            match opcode {
                0x26 => self.segment_override = Some(ES),
                0x2E => self.segment_override = Some(CS),
                0x36 => self.segment_override = Some(SS),
                0x3E => self.segment_override = Some(DS),
                0x64 => self.segment_override = Some(FS),
                0x65 => self.segment_override = Some(GS),
                0x66 => self.operand32 = true,
                0x67 => self.address32 = true,
                0xF0 => {}
                0xF2 => self.repeat = Repeat::NotEqual,
                0xF3 => self.repeat = Repeat::Equal,
                _ => return self.execute(opcode),
            }
        }
    }

    fn execute(&mut self, opcode: u8) -> Step {
        let size = self.operand_size();
        match opcode {
            // ALU: op r/m,r / r,r/m / acumulador,imediato.
            0x00..=0x3F if opcode & 7 < 6 => {
                let operation = opcode >> 3;
                let width = if opcode & 1 == 0 { 1 } else { size };
                match opcode & 7 {
                    0 | 1 => {
                        let (reg, operand) = self.modrm()?;
                        let (a, b) = (self.read_operand(operand, width)?, self.register(reg, width));
                        if let Some(result) = self.alu(operation, a, b, width) {
                            self.write_operand(operand, width, result)?;
                        }
                    }
                    2 | 3 => {
                        let (reg, operand) = self.modrm()?;
                        let (a, b) = (self.register(reg, width), self.read_operand(operand, width)?);
                        if let Some(result) = self.alu(operation, a, b, width) {
                            self.set_register(reg, width, result);
                        }
                    }
                    _ => {
                        let b = self.fetch_immediate(width)?;
                        let a = self.register(EAX, width);
                        if let Some(result) = self.alu(operation, a, b, width) {
                            self.set_register(EAX, width, result);
                        }
                    }
                }
            }
            0x06 | 0x0E | 0x16 | 0x1E => self.push(self.cpu.segment[(opcode >> 3) as usize] as u32, size)?,
            0x07 | 0x17 | 0x1F => self.cpu.segment[(opcode >> 3) as usize] = self.pop(size)? as u16,
            0x0F => return self.execute_two_byte(),
            0x27 => {
                let operand = self.register(EAX, 1) as u8;
                let al = alu::decimal_adjust_add(&mut self.cpu.eflags, operand);
                self.set_register(EAX, 1, al as u32);
            }
            0x2F => {
                let operand = self.register(EAX, 1) as u8;
                let al = alu::decimal_adjust_subtract(&mut self.cpu.eflags, operand);
                self.set_register(EAX, 1, al as u32);
            }
            0x37 | 0x3F => {
                let operand = self.register(EAX, 2) as u16;
                let ax = alu::ascii_adjust(&mut self.cpu.eflags, operand, opcode == 0x3F);
                self.set_register(EAX, 2, ax as u32);
            }
            0x40..=0x4F => {
                let index = (opcode & 7) as usize;
                let operand = self.register(index, size);
                let value = alu::increment(&mut self.cpu.eflags, operand, opcode >= 0x48, size);
                self.set_register(index, size, value);
            }
            0x50..=0x57 => {
                // PUSH SP empilha o valor de antes do decremento.
                let value = self.register((opcode & 7) as usize, size);
                self.push(value, size)?;
            }
            0x58..=0x5F => {
                let value = self.pop(size)?;
                self.set_register((opcode & 7) as usize, size, value);
            }
            0x60 => {
                let original = self.register(ESP, size);
                for index in [EAX, ECX, EDX, EBX] {
                    self.push(self.register(index, size), size)?;
                }
                self.push(original, size)?;
                for index in [EBP, ESI, EDI] {
                    self.push(self.register(index, size), size)?;
                }
            }
            0x61 => {
                for index in [EDI, ESI, EBP] {
                    let value = self.pop(size)?;
                    self.set_register(index, size, value);
                }
                self.pop(size)?;
                for index in [EBX, EDX, ECX, EAX] {
                    let value = self.pop(size)?;
                    self.set_register(index, size, value);
                }
            }
            0x62 => {
                let (reg, operand) = self.modrm()?;
                let (segment, offset) = Self::memory_operand(operand)?;
                let lower = alu::sign_extend(self.read_memory(segment, offset, size)?, size) as i32;
                let upper = alu::sign_extend(self.read_memory(segment, offset.wrapping_add(size), size)?, size) as i32;
                let index = alu::sign_extend(self.register(reg, size), size) as i32;
                if index < lower || index > upper {
                    return Err(Status::BoundRange);
                }
            }
            0x68 => {
                let value = self.fetch_immediate(size)?;
                self.push(value, size)?;
            }
            0x6A => {
                let value = alu::sign_extend(self.fetch8()?, 1);
                self.push(value, size)?;
            }
            0x69 | 0x6B => {
                let (reg, operand) = self.modrm()?;
                let source = self.read_operand(operand, size)?;
                let immediate = if opcode == 0x6B { alu::sign_extend(self.fetch8()?, 1) } else { self.fetch_immediate(size)? };
                let (low, _) = alu::signed_multiply(&mut self.cpu.eflags, source, immediate, size);
                self.set_register(reg, size, low);
            }
            0x6C..=0x6F => return self.string_io(opcode),
            0x70..=0x7F => {
                let displacement = alu::sign_extend(self.fetch8()?, 1);
                if alu::condition(self.cpu.eflags, opcode & 0xF) {
                    self.jump_short(displacement);
                }
            }
            0x80 | 0x81 | 0x83 => {
                let width = if opcode == 0x80 { 1 } else { size };
                let (reg, operand) = self.modrm()?;
                let b = if opcode == 0x83 { alu::sign_extend(self.fetch8()?, 1) } else { self.fetch_immediate(width)? };
                let a = self.read_operand(operand, width)?;
                if let Some(result) = self.alu(reg as u8, a, b, width) {
                    self.write_operand(operand, width, result)?;
                }
            }
            0x84 | 0x85 => {
                let width = if opcode == 0x84 { 1 } else { size };
                let (reg, operand) = self.modrm()?;
                let value = self.read_operand(operand, width)? & self.register(reg, width);
                alu::logic(&mut self.cpu.eflags, value, width);
            }
            0x86 | 0x87 => {
                let width = if opcode == 0x86 { 1 } else { size };
                let (reg, operand) = self.modrm()?;
                let (a, b) = (self.read_operand(operand, width)?, self.register(reg, width));
                self.write_operand(operand, width, b)?;
                self.set_register(reg, width, a);
            }
            0x88..=0x8B => {
                let width = if opcode & 1 == 0 { 1 } else { size };
                let (reg, operand) = self.modrm()?;
                if opcode & 2 == 0 {
                    self.write_operand(operand, width, self.register(reg, width))?;
                } else {
                    let value = self.read_operand(operand, width)?;
                    self.set_register(reg, width, value);
                }
            }
            0x8C => {
                let (reg, operand) = self.modrm()?;
                if reg > GS {
                    return Err(Status::IllegalInstruction);
                }
                let value = self.cpu.segment[reg] as u32;
                match operand {
                    Operand::Register(index) => self.set_register(index, size, value),
                    memory => self.write_operand(memory, 2, value)?,
                }
            }
            0x8D => {
                let (reg, operand) = self.modrm()?;
                let (_, offset) = Self::memory_operand(operand)?;
                self.set_register(reg, size, offset);
            }
            0x8E => {
                let (reg, operand) = self.modrm()?;
                if reg > GS {
                    return Err(Status::IllegalInstruction);
                }
                self.cpu.segment[reg] = self.read_operand(operand, 2)? as u16;
            }
            0x8F => {
                let (_, operand) = self.modrm()?;
                let value = self.pop(size)?;
                self.write_operand(operand, size, value)?;
            }
            // NOP e WAIT.
            0x90 | 0x9B => {}
            0x91..=0x97 => {
                let index = (opcode & 7) as usize;
                let (a, b) = (self.register(EAX, size), self.register(index, size));
                self.set_register(EAX, size, b);
                self.set_register(index, size, a);
            }
            0x98 => {
                let value = if self.operand32 { alu::sign_extend(self.register(EAX, 2), 2) } else { alu::sign_extend(self.register(EAX, 1), 1) };
                self.set_register(EAX, size, value);
            }
            0x99 => {
                let negative = self.register(EAX, size) & alu::sign_bit(size) != 0;
                self.set_register(EDX, size, if negative { 0xFFFF_FFFF } else { 0 });
            }
            0x9A => {
                let offset = self.fetch_immediate(size)?;
                let segment = self.fetch16()?;
                self.push(self.cpu.segment[CS] as u32, size)?;
                self.push(self.cpu.eip, size)?;
                self.cpu.segment[CS] = segment as u16;
                self.cpu.eip = offset;
            }
            0x9C => self.push(self.cpu.eflags, size)?,
            0x9D => {
                let value = self.pop(size)?;
                self.cpu.eflags = if self.operand32 { value } else { (self.cpu.eflags & 0xFFFF_0000) | value };
            }
            0x9E => {
                let ah = self.register(4, 1);
                self.cpu.eflags = (self.cpu.eflags & !0xFF) | ah;
            }
            0x9F => self.set_register(4, 1, self.cpu.eflags & 0xFF),
            0xA0..=0xA3 => {
                let width = if opcode & 1 == 0 { 1 } else { size };
                let offset = if self.address32 { self.fetch32()? } else { self.fetch16()? };
                let segment = self.data_segment(DS);
                if opcode & 2 == 0 {
                    let value = self.read_memory(segment, offset, width)?;
                    self.set_register(EAX, width, value);
                } else {
                    self.write_memory(segment, offset, width, self.register(EAX, width))?;
                }
            }
            0xA4..=0xA7 | 0xAA..=0xAF => return self.string(opcode),
            0xA8 | 0xA9 => {
                let width = if opcode == 0xA8 { 1 } else { size };
                let value = self.fetch_immediate(width)? & self.register(EAX, width);
                alu::logic(&mut self.cpu.eflags, value, width);
            }
            0xB0..=0xB7 => {
                let value = self.fetch8()?;
                self.set_register((opcode & 7) as usize, 1, value);
            }
            0xB8..=0xBF => {
                let value = self.fetch_immediate(size)?;
                self.set_register((opcode & 7) as usize, size, value);
            }
            0xC0 | 0xC1 | 0xD0..=0xD3 => {
                let width = if opcode & 1 == 0 { 1 } else { size };
                let (reg, operand) = self.modrm()?;
                let kind = match reg {
                    0 => Shift::Rol,
                    1 => Shift::Ror,
                    2 => Shift::Rcl,
                    3 => Shift::Rcr,
                    4 => Shift::Shl,
                    5 => Shift::Shr,
                    7 => Shift::Sar,
                    _ => return Err(Status::IllegalInstruction),
                };
                let count = match opcode {
                    0xC0 | 0xC1 => self.fetch8()?,
                    0xD0 | 0xD1 => 1,
                    _ => self.register(ECX, 1),
                } & 0x1F;
                let value = self.read_operand(operand, width)?;
                let result = alu::shift(&mut self.cpu.eflags, kind, value, count, width);
                self.write_operand(operand, width, result)?;
            }
            0xC2 | 0xC3 => {
                let release = if opcode == 0xC2 { self.fetch16()? } else { 0 };
                self.cpu.eip = self.pop(size)?;
                self.cpu.gpr[ESP] = self.cpu.gpr[ESP].wrapping_add(release);
                return self.returned_to_caller();
            }
            0xC4 | 0xC5 => return self.load_far_pointer(if opcode == 0xC4 { ES } else { DS }),
            0xC6 | 0xC7 => {
                let width = if opcode == 0xC6 { 1 } else { size };
                let (_, operand) = self.modrm()?;
                let value = self.fetch_immediate(width)?;
                self.write_operand(operand, width, value)?;
            }
            0xC8 => {
                let frame = self.fetch16()?;
                let level = self.fetch8()?;
                self.push(self.register(EBP, size), size)?;
                let frame_pointer = self.register(ESP, size);
                match level {
                    0 => {}
                    1 => self.push(frame_pointer, size)?,
                    _ => return Err(Status::EnterLevel),
                }
                self.set_register(ESP, size, self.register(ESP, size).wrapping_sub(frame));
                self.set_register(EBP, size, frame_pointer);
            }
            0xC9 => {
                self.set_register(ESP, size, self.register(EBP, size));
                let value = self.pop(size)?;
                self.set_register(EBP, size, value);
            }
            0xCA | 0xCB => {
                let release = if opcode == 0xCA { self.fetch16()? } else { 0 };
                self.cpu.eip = self.pop(size)?;
                self.cpu.segment[CS] = self.pop(size)? as u16;
                self.cpu.gpr[ESP] = self.cpu.gpr[ESP].wrapping_add(release);
                return self.returned_to_caller();
            }
            0xCC => return self.interrupt(3),
            0xCD => {
                let vector = self.fetch8()? as u8;
                return self.interrupt(vector);
            }
            0xCE => {
                if self.flag(OF) {
                    return self.interrupt(4);
                }
            }
            0xCF => {
                self.cpu.eip = self.pop(size)?;
                self.cpu.segment[CS] = self.pop(size)? as u16;
                let flags = self.pop(size)?;
                self.cpu.eflags = if self.operand32 { flags } else { (self.cpu.eflags & 0xFFFF_0000) | flags };
                return self.returned_to_caller();
            }
            0xD4 => {
                let base = self.fetch8()? as u8;
                let operand = self.register(EAX, 1) as u8;
                let ax = alu::ascii_adjust_multiply(&mut self.cpu.eflags, operand, base).ok_or(Status::DivideByZero)?;
                self.set_register(EAX, 2, ax as u32);
            }
            0xD5 => {
                let base = self.fetch8()? as u8;
                let operand = self.register(EAX, 2) as u16;
                let ax = alu::ascii_adjust_divide(&mut self.cpu.eflags, operand, base);
                self.set_register(EAX, 2, ax as u32);
            }
            0xD7 => {
                let base = if self.address32 { self.cpu.gpr[EBX] } else { self.cpu.gpr[EBX] & 0xFFFF };
                let offset = base.wrapping_add(self.register(EAX, 1));
                let offset = if self.address32 { offset } else { offset & 0xFFFF };
                let value = self.read_memory(self.data_segment(DS), offset, 1)?;
                self.set_register(EAX, 1, value);
            }
            0xE0..=0xE3 => {
                let displacement = alu::sign_extend(self.fetch8()?, 1);
                // LOOP conta em CX/ECX pela largura do endereço; o JCXZ do
                // emulador da HAL testa CX/ECX pela largura do operando.
                let counter = if self.address32 { 4 } else { 2 };
                let taken = if opcode == 0xE3 {
                    self.register(ECX, size) == 0
                } else {
                    let count = self.register(ECX, counter).wrapping_sub(1);
                    self.set_register(ECX, counter, count);
                    let zero = self.flag(ZF);
                    count & alu::mask(counter) != 0
                        && match opcode {
                            0xE0 => !zero,
                            0xE1 => zero,
                            _ => true,
                        }
                };
                if taken {
                    self.jump_short(displacement);
                }
            }
            0xE4 | 0xE5 | 0xEC | 0xED => {
                let width = if opcode & 1 == 0 { 1 } else { size };
                let port = if opcode < 0xEC { self.fetch8()? } else { self.register(EDX, 2) };
                let value = self.port_in(port, width)?;
                self.set_register(EAX, width, value);
            }
            0xE6 | 0xE7 | 0xEE | 0xEF => {
                let width = if opcode & 1 == 0 { 1 } else { size };
                let port = if opcode < 0xEE { self.fetch8()? } else { self.register(EDX, 2) };
                self.port_out(port, width, self.register(EAX, width))?;
            }
            0xE8 => {
                let displacement = self.fetch_immediate(size)?;
                self.push(self.cpu.eip, size)?;
                self.jump_relative(displacement);
            }
            0xE9 => {
                let displacement = self.fetch_immediate(size)?;
                self.jump_relative(displacement);
            }
            0xEA => {
                let offset = self.fetch_immediate(size)?;
                let segment = self.fetch16()?;
                self.cpu.segment[CS] = segment as u16;
                self.cpu.eip = offset;
            }
            0xEB => {
                let displacement = alu::sign_extend(self.fetch8()?, 1);
                self.jump_short(displacement);
            }
            0xF4 => return Err(Status::Halt),
            0xF5 => self.cpu.eflags ^= CF,
            0xF6 | 0xF7 => return self.group3(if opcode == 0xF6 { 1 } else { size }),
            0xF8 => self.set_flag(CF, false),
            0xF9 => self.set_flag(CF, true),
            0xFA => self.set_flag(IF, false),
            0xFB => self.set_flag(IF, true),
            0xFC => self.set_flag(DF, false),
            0xFD => self.set_flag(DF, true),
            0xFE => {
                // Só o bit baixo do campo reg conta: INC ou DEC de byte.
                let (reg, operand) = self.modrm()?;
                let value = self.read_operand(operand, 1)?;
                let result = alu::increment(&mut self.cpu.eflags, value, reg & 1 != 0, 1);
                self.write_operand(operand, 1, result)?;
            }
            0xFF => return self.group5(size),
            // 63h, 82h, D6h, D8h-DFh (x87) e F1h.
            _ => return Err(Status::IllegalInstruction),
        }
        Ok(())
    }

    /// Operação da ALU de índice `operation` (ADD, OR, ADC, SBB, AND, SUB,
    /// XOR, CMP); `None` para o CMP, que não grava.
    fn alu(&mut self, operation: u8, a: u32, b: u32, size: u32) -> Option<u32> {
        let flags = &mut self.cpu.eflags;
        let carry = *flags & CF != 0;
        Some(match operation & 7 {
            0 => alu::add(flags, a, b, false, size),
            1 => alu::logic(flags, a | b, size),
            2 => alu::add(flags, a, b, carry, size),
            3 => alu::sub(flags, a, b, carry, size),
            4 => alu::logic(flags, a & b, size),
            5 => alu::sub(flags, a, b, false, size),
            6 => alu::logic(flags, a ^ b, size),
            _ => {
                alu::sub(flags, a, b, false, size);
                return None;
            }
        })
    }

    fn port_in(&mut self, port: u32, size: u32) -> Result<u32, Status> {
        if port + (size - 1) > 0xFFFF {
            return Err(Status::PortRange);
        }
        Ok(self.bus.read_port(port as u16, size) & alu::mask(size))
    }

    fn port_out(&mut self, port: u32, size: u32, value: u32) -> Step {
        if port + (size - 1) > 0xFFFF {
            return Err(Status::PortRange);
        }
        self.bus.write_port(port as u16, size, value & alu::mask(size));
        Ok(())
    }

    /// INT n: 42h não faz nada; 1Ah passa pelo PCI BIOS emulado; os demais
    /// vetores vêm da IVT, com FLAGS, CS e IP empilhados na largura do operando.
    fn interrupt(&mut self, vector: u8) -> Step {
        if vector == 0x42 {
            return Ok(());
        }
        if vector == 0x1A && self.bus.pci_bios(self.cpu) {
            return Ok(());
        }
        let size = self.operand_size();
        self.push(self.cpu.eflags, size)?;
        self.push(self.cpu.segment[CS] as u32, size)?;
        self.push(self.cpu.eip, size)?;
        let offset = self.bus.read(0, vector as u32 * 4, 2) & 0xFFFF;
        let segment = self.bus.read(0, vector as u32 * 4 + 2, 2) & 0xFFFF;
        self.cpu.segment[CS] = segment as u16;
        self.cpu.eip = offset;
        Ok(())
    }

    /// LDS/LES/LSS/LFS/LGS: deslocamento e segmento da memória.
    fn load_far_pointer(&mut self, segment_register: usize) -> Step {
        let size = self.operand_size();
        let (reg, operand) = self.modrm()?;
        let (segment, offset) = Self::memory_operand(operand)?;
        let value = self.read_memory(segment, offset, size)?;
        let selector = self.read_memory(segment, offset.wrapping_add(size), 2)?;
        self.set_register(reg, size, value);
        self.cpu.segment[segment_register] = selector as u16;
        Ok(())
    }

    fn group3(&mut self, size: u32) -> Step {
        let (reg, operand) = self.modrm()?;
        match reg {
            0 => {
                let immediate = self.fetch_immediate(size)?;
                let value = self.read_operand(operand, size)? & immediate;
                alu::logic(&mut self.cpu.eflags, value, size);
            }
            2 => {
                let value = !self.read_operand(operand, size)?;
                self.write_operand(operand, size, value)?;
            }
            3 => {
                let value = self.read_operand(operand, size)?;
                let result = alu::sub(&mut self.cpu.eflags, 0, value, false, size);
                self.write_operand(operand, size, result)?;
            }
            4 | 5 => {
                let source = self.read_operand(operand, size)?;
                let accumulator = self.register(EAX, size);
                let (low, high) = if reg == 4 {
                    alu::multiply(&mut self.cpu.eflags, accumulator, source, size)
                } else {
                    alu::signed_multiply(&mut self.cpu.eflags, accumulator, source, size)
                };
                if size == 1 {
                    self.set_register(EAX, 2, low | (high << 8));
                } else {
                    self.set_register(EAX, size, low);
                    self.set_register(EDX, size, high);
                }
            }
            6 | 7 => {
                let divisor = self.read_operand(operand, size)?;
                let (high, low) = if size == 1 {
                    (self.register(4, 1), self.register(EAX, 1))
                } else {
                    (self.register(EDX, size), self.register(EAX, size))
                };
                let divided = if reg == 6 { alu::divide(high, low, divisor, size) } else { alu::signed_divide(high, low, divisor, size) };
                let (quotient, remainder) = divided.map_err(|error| match error {
                    alu::DivideError::ByZero => Status::DivideByZero,
                    alu::DivideError::Overflow => Status::DivideOverflow,
                })?;
                if size == 1 {
                    self.set_register(EAX, 1, quotient);
                    self.set_register(4, 1, remainder);
                } else {
                    self.set_register(EAX, size, quotient);
                    self.set_register(EDX, size, remainder);
                }
            }
            _ => return Err(Status::IllegalInstruction),
        }
        Ok(())
    }

    fn group5(&mut self, size: u32) -> Step {
        let (reg, operand) = self.modrm()?;
        match reg {
            0 | 1 => {
                let value = self.read_operand(operand, size)?;
                let result = alu::increment(&mut self.cpu.eflags, value, reg == 1, size);
                self.write_operand(operand, size, result)?;
            }
            2 => {
                let target = self.read_operand(operand, size)?;
                self.push(self.cpu.eip, size)?;
                self.jump_near(target);
            }
            3 | 5 => {
                let (segment, offset) = Self::memory_operand(operand)?;
                let target = self.read_memory(segment, offset, size)?;
                let selector = self.read_memory(segment, offset.wrapping_add(size), 2)?;
                if reg == 3 {
                    self.push(self.cpu.segment[CS] as u32, size)?;
                    self.push(self.cpu.eip, size)?;
                }
                self.cpu.segment[CS] = selector as u16;
                self.cpu.eip = target;
            }
            4 => {
                let target = self.read_operand(operand, size)?;
                self.jump_near(target);
            }
            6 => {
                let value = self.read_operand(operand, size)?;
                self.push(value, size)?;
            }
            _ => return Err(Status::IllegalInstruction),
        }
        Ok(())
    }

    // ---- instruções de cadeia ------------------------------------------------

    /// Índice de cadeia (SI/DI ou ESI/EDI pela largura do endereço).
    fn string_index(&self, register: usize) -> u32 {
        if self.address32 { self.cpu.gpr[register] } else { self.cpu.gpr[register] & 0xFFFF }
    }

    fn advance_index(&mut self, register: usize, size: u32) {
        let delta = if self.flag(DF) { size.wrapping_neg() } else { size };
        let value = self.cpu.gpr[register].wrapping_add(delta);
        if self.address32 {
            self.cpu.gpr[register] = value;
        } else {
            self.cpu.gpr[register] = (self.cpu.gpr[register] & 0xFFFF_0000) | (value & 0xFFFF);
        }
    }

    fn counter(&self) -> u32 {
        if self.address32 { self.cpu.gpr[ECX] } else { self.cpu.gpr[ECX] & 0xFFFF }
    }

    fn decrement_counter(&mut self) {
        let value = self.counter().wrapping_sub(1);
        if self.address32 {
            self.cpu.gpr[ECX] = value;
        } else {
            self.cpu.gpr[ECX] = (self.cpu.gpr[ECX] & 0xFFFF_0000) | (value & 0xFFFF);
        }
    }

    /// MOVS, CMPS, STOS, LODS e SCAS, com REP/REPE/REPNE.
    fn string(&mut self, opcode: u8) -> Step {
        let size = if opcode & 1 == 0 { 1 } else { self.operand_size() };
        let source_segment = self.data_segment(DS);
        let repeated = self.repeat != Repeat::None;
        let compares = matches!(opcode, 0xA6 | 0xA7 | 0xAE | 0xAF);
        loop {
            if repeated && self.counter() == 0 {
                break;
            }
            match opcode {
                0xA4 | 0xA5 => {
                    let value = self.read_memory(source_segment, self.string_index(ESI), size)?;
                    self.write_memory(ES, self.string_index(EDI), size, value)?;
                    self.advance_index(ESI, size);
                    self.advance_index(EDI, size);
                }
                0xA6 | 0xA7 => {
                    let a = self.read_memory(source_segment, self.string_index(ESI), size)?;
                    let b = self.read_memory(ES, self.string_index(EDI), size)?;
                    alu::sub(&mut self.cpu.eflags, a, b, false, size);
                    self.advance_index(ESI, size);
                    self.advance_index(EDI, size);
                }
                0xAA | 0xAB => {
                    self.write_memory(ES, self.string_index(EDI), size, self.register(EAX, size))?;
                    self.advance_index(EDI, size);
                }
                0xAC | 0xAD => {
                    let value = self.read_memory(source_segment, self.string_index(ESI), size)?;
                    self.set_register(EAX, size, value);
                    self.advance_index(ESI, size);
                }
                _ => {
                    let b = self.read_memory(ES, self.string_index(EDI), size)?;
                    let operand = self.register(EAX, size);
                    alu::sub(&mut self.cpu.eflags, operand, b, false, size);
                    self.advance_index(EDI, size);
                }
            }
            if !repeated {
                break;
            }
            self.decrement_counter();
            if compares {
                let zero = self.flag(ZF);
                if (self.repeat == Repeat::Equal && !zero) || (self.repeat == Repeat::NotEqual && zero) {
                    break;
                }
            }
        }
        Ok(())
    }

    /// INS e OUTS, com REP.
    fn string_io(&mut self, opcode: u8) -> Step {
        let size = if opcode & 1 == 0 { 1 } else { self.operand_size() };
        let port = self.register(EDX, 2);
        let source_segment = self.data_segment(DS);
        let repeated = self.repeat != Repeat::None;
        loop {
            if repeated && self.counter() == 0 {
                break;
            }
            if opcode < 0x6E {
                let value = self.port_in(port, size)?;
                self.write_memory(ES, self.string_index(EDI), size, value)?;
                self.advance_index(EDI, size);
            } else {
                let value = self.read_memory(source_segment, self.string_index(ESI), size)?;
                self.port_out(port, size, value)?;
                self.advance_index(ESI, size);
            }
            if !repeated {
                break;
            }
            self.decrement_counter();
        }
        Ok(())
    }

    // ---- 0F xx --------------------------------------------------------------

    fn execute_two_byte(&mut self) -> Step {
        let opcode = self.fetch8()? as u8;
        let size = self.operand_size();
        match opcode {
            0x01 => {
                // Grupo 7: só o SMSW (/4), que lê 2Dh.
                let (reg, operand) = self.modrm()?;
                if reg != 4 {
                    return Err(Status::IllegalInstruction);
                }
                self.write_operand(operand, 2, 0x2D)?;
            }
            0x31 => {
                let counter = self.bus.performance_counter();
                self.cpu.gpr[EAX] = counter as u32;
                self.cpu.gpr[EDX] = (counter >> 32) as u32;
            }
            0x80..=0x8F => {
                let displacement = self.fetch_immediate(size)?;
                if alu::condition(self.cpu.eflags, opcode & 0xF) {
                    self.jump_short(displacement);
                }
            }
            0x90..=0x9F => {
                let (_, operand) = self.modrm()?;
                let value = alu::condition(self.cpu.eflags, opcode & 0xF) as u32;
                self.write_operand(operand, 1, value)?;
            }
            0xA0 | 0xA8 => self.push(self.cpu.segment[if opcode == 0xA0 { FS } else { GS }] as u32, size)?,
            0xA1 | 0xA9 => self.cpu.segment[if opcode == 0xA1 { FS } else { GS }] = self.pop(size)? as u16,
            0xA3 | 0xAB | 0xB3 | 0xBB => {
                let (reg, operand) = self.modrm()?;
                let offset = self.register(reg, size);
                let operation = (opcode >> 3) & 3;
                return self.bit_test(operand, offset, true, operation, size);
            }
            0xBA => {
                let (reg, operand) = self.modrm()?;
                if reg < 4 {
                    return Err(Status::IllegalInstruction);
                }
                let offset = self.fetch8()?;
                return self.bit_test(operand, offset, false, (reg - 4) as u8, size);
            }
            0xA4 | 0xA5 | 0xAC | 0xAD => {
                let (reg, operand) = self.modrm()?;
                let count = if opcode & 1 == 0 { self.fetch8()? } else { self.register(ECX, 1) } & 0x1F;
                let dest = self.read_operand(operand, size)?;
                let source = self.register(reg, size);
                let result = alu::shift_double(&mut self.cpu.eflags, opcode < 0xA8, dest, source, count, size);
                self.write_operand(operand, size, result)?;
            }
            0xAF => {
                let (reg, operand) = self.modrm()?;
                let source = self.read_operand(operand, size)?;
                let operand = self.register(reg, size);
                let (low, _) = alu::signed_multiply(&mut self.cpu.eflags, operand, source, size);
                self.set_register(reg, size, low);
            }
            0xB0 | 0xB1 => {
                let width = if opcode == 0xB0 { 1 } else { size };
                let (reg, operand) = self.modrm()?;
                let dest = self.read_operand(operand, width)?;
                let accumulator = self.register(EAX, width);
                alu::sub(&mut self.cpu.eflags, accumulator, dest, false, width);
                if self.flag(ZF) {
                    self.write_operand(operand, width, self.register(reg, width))?;
                } else {
                    self.set_register(EAX, width, dest);
                }
            }
            0xB2 => return self.load_far_pointer(SS),
            0xB4 => return self.load_far_pointer(FS),
            0xB5 => return self.load_far_pointer(GS),
            0xB6 | 0xB7 | 0xBE | 0xBF => {
                let width = if opcode & 1 == 0 { 1 } else { 2 };
                let (reg, operand) = self.modrm()?;
                let value = self.read_operand(operand, width)?;
                let value = if opcode >= 0xBE { alu::sign_extend(value, width) } else { value };
                self.set_register(reg, size, value);
            }
            0xBC | 0xBD => {
                let (reg, operand) = self.modrm()?;
                let value = self.read_operand(operand, size)?;
                if value == 0 {
                    self.set_flag(ZF, true);
                } else {
                    self.set_flag(ZF, false);
                    let index = if opcode == 0xBC { value.trailing_zeros() } else { 31 - value.leading_zeros() };
                    self.set_register(reg, size, index);
                }
            }
            0xC0 | 0xC1 => {
                let width = if opcode == 0xC0 { 1 } else { size };
                let (reg, operand) = self.modrm()?;
                let (dest, source) = (self.read_operand(operand, width)?, self.register(reg, width));
                let sum = alu::add(&mut self.cpu.eflags, dest, source, false, width);
                self.set_register(reg, width, dest);
                self.write_operand(operand, width, sum)?;
            }
            0xC8 => {
                // BSWAP: o registrador vem do campo reg de um ModRM de registrador.
                let (reg, operand) = self.modrm()?;
                if !matches!(operand, Operand::Register(_)) {
                    return Err(Status::RegisterRequired);
                }
                let value = self.register(reg, size);
                let swapped = if size == 4 { value.swap_bytes() } else { (value as u16).swap_bytes() as u32 };
                self.set_register(reg, size, swapped);
            }
            _ => return Err(Status::IllegalInstruction),
        }
        Ok(())
    }

    /// BT/BTS/BTR/BTC (`operation` 0..3). Com deslocamento de registrador e
    /// operando em memória, o deslocamento com sinal escolhe a palavra.
    fn bit_test(&mut self, operand: Operand, offset: u32, register_offset: bool, operation: u8, size: u32) -> Step {
        let bits = size * 8;
        let (operand, bit) = match operand {
            Operand::Memory { segment, offset: address } if register_offset => {
                let signed = alu::sign_extend(offset, size) as i32;
                let word = signed.div_euclid(bits as i32);
                let address = address.wrapping_add((word * size as i32) as u32);
                let address = if self.address32 { address } else { address & 0xFFFF };
                (Operand::Memory { segment, offset: address }, signed.rem_euclid(bits as i32) as u32)
            }
            other => (other, offset % bits),
        };
        let value = self.read_operand(operand, size)?;
        self.set_flag(CF, value & (1 << bit) != 0);
        let result = match operation {
            0 => return Ok(()),
            1 => value | (1 << bit),
            2 => value & !(1 << bit),
            _ => value ^ (1 << bit),
        };
        self.write_operand(operand, size, result)
    }
}
