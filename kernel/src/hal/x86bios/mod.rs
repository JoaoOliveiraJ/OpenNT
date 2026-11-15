//! A interface x86 BIOS da HAL: x86BiosCall, x86BiosAllocateBuffer,
//! x86BiosFreeBuffer, x86BiosReadMemory e x86BiosWriteMemory, com que os
//! drivers de vídeo (o BasicDisplay.sys, o dxgkrnl.sys) chamam o BIOS de
//! vídeo da máquina — as funções VBE do INT 10h — num processador x86 de
//! modo real emulado (`emulator.rs`, `operations.rs`).
//!
//! Como no Windows 10 19041 (HalInitializeBios, x86BiosInitializeBiosEx,
//! XmInitializeEmulator, x86BiosTranslateAddress), a inicialização
//! ([`initialize`]) monta o espaço de endereços de 1 MB que o BIOS vê:
//!
//! | Endereço linear | O que é |
//! | --- | --- |
//! | 00000-00800 | cópia privada da IVT e da BDA, lida da memória física na inicialização |
//! | 00801-1FFFF | memória de rascunho: lê 0, a escrita se perde |
//! | 20000-21FFF | o buffer de transferência (segmento 2000h, 8 KB), memória do kernel |
//! | 30000-31FFF | o mesmo buffer (o endereço só usa os 16 bits baixos) |
//! | 22000-8FFFF | rascunho (o que sobra de 20000-3FFFF e 40000-8FFFF) |
//! | 90000-9FFFF | a memória física, menos a RAM do sistema (EBDA e o que o firmware reservou) |
//! | A0000-BFFFF | a janela VGA física (memória de vídeo) |
//! | C0000-FFFFF | a memória física: a ROM do BIOS de vídeo, a do sistema e o que houver entre elas |
//!
//! Nas faixas físicas, cada página do primeiro megabyte é a sua própria
//! moldura, menos a janela VGA e as páginas de RAM que o sistema usa (as que
//! o E820 dá inteiras como RAM), trocadas pela página F0000h da ROM do
//! sistema: o BIOS nunca enxerga nem altera a memória do sistema operacional.
//! A pilha da emulação começa em 0000:0800, dentro da cópia da BDA, e a IVT
//! começa com todo vetor apontando para um IRET em 0000:0500 antes da cópia.
//!
//! Uma chamada ([`call`]) empilha um quadro falso de IRET (IP = FFFFh,
//! CS = FFFFh, FLAGS = 0), carrega CS:IP do vetor na IVT copiada, os
//! registradores do X86_BIOS_REGISTERS (EAX, ECX, EDX, EBX, EBP, ESI, EDI,
//! DS e ES; FS, GS e EFLAGS seguem do estado do emulador) e roda até o BIOS
//! voltar ao quadro falso; devolve os sete registradores e TRUE só nesse
//! caso. As portas vão ao hardware, com o espaço de configuração PCI e a
//! CMOS mediados (`io_space.rs`). Uma chamada por vez: o estado do emulador
//! é um só, atrás de um lock.

pub mod emulator;
mod io_space;
pub mod operations;

use core::sync::atomic::{AtomicBool, Ordering};

use emulator::{Bus, Cpu, Status, CS, DS, EAX, EBP, EBX, ECX, EDI, EDX, ES, ESI, ESP, SS};
use io_space::IoSpace;

use crate::hal::physical;
use crate::ntos::inc::status::{STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use crate::ntos::inc::types::extra_hal::X86BiosRegisters;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::{io_space as mm_io_space, physical_layout};
use crate::rtl::{KernelError, SpinLock};

/// Segmento do buffer de transferência (x86BiosAllocateBuffer).
pub const TRANSFER_SEGMENT: u16 = 0x2000;
/// x86BiosTransferLength.
pub const TRANSFER_LENGTH: u32 = 0x2000;
/// Último endereço da cópia da IVT e da BDA.
const LOW_MEMORY_LIMIT: u32 = 0x800;
/// x86BiosLowMemory: os 0x801 bytes da cópia e uma folga para o acesso de
/// várias bytes que começa no fim dela.
const LOW_MEMORY_SIZE: usize = 0x810;
/// Pilha inicial de toda chamada: 0000:0800.
const INITIAL_SS: u16 = 0;
const INITIAL_SP: u32 = 0x800;
/// Onde o XmInitializeEmulator põe o IRET para o qual a IVT inicial aponta.
const DEFAULT_HANDLER: u32 = 0x500;
const IRET: u8 = 0xCF;
/// Páginas do primeiro megabyte.
const FIRST_MEGABYTE_PAGES: usize = 0x100;
/// Página da ROM do sistema que substitui a janela VGA e a RAM do sistema.
const SUBSTITUTE_PAGE: u32 = 0xF0;
/// Janela VGA (o x86BiosFrameBuffer).
const FRAME_BUFFER_BASE: u64 = 0xA_0000;
const FRAME_BUFFER_SIZE: u64 = 0x2_0000;
/// HAL_DISPLAY_BIOS_INFORMATION.
pub const HAL_DISPLAY_EMULATED_BIOS: u32 = 1;
pub const HAL_DISPLAY_NO_BIOS: u32 = 2;

/// O estado do emulador (o XmContext e as variáveis x86Bios* do NT).
struct X86Bios {
    cpu: Cpu,
    /// x86BiosLowMemory.
    low_memory: [u8; LOW_MEMORY_SIZE],
    /// A visão física do primeiro megabyte (o MDL do HalpIoMemoryBase):
    /// moldura de cada página.
    page_frames: [u32; FIRST_MEGABYTE_PAGES],
    /// x86BiosTransferMemory (VA de kernel).
    transfer: u64,
    /// x86BiosBufferAllocated.
    buffer_allocated: bool,
    io: IoSpace,
}

static BIOS: SpinLock<Option<X86Bios>> = SpinLock::new(None);

/// HalpVideoBiosPresent.
static VIDEO_BIOS_PRESENT: AtomicBool = AtomicBool::new(false);

/// Para onde um endereço linear leva.
#[derive(Clone, Copy)]
enum Target {
    /// Índice na cópia da IVT/BDA.
    LowMemory(usize),
    /// Deslocamento no buffer de transferência.
    Transfer(u64),
    /// Memória de rascunho.
    Scratch,
    /// A visão física do primeiro megabyte, a partir deste endereço linear.
    IoMemory(u32),
    /// A janela VGA, a partir deste endereço linear.
    FrameBuffer(u32),
}

impl X86Bios {
    /// x86BiosTranslateAddress.
    fn translate(linear: u32) -> Target {
        let linear = linear & 0xF_FFFF;
        if linear <= 0x8_FFFF || (0xA_0000..=0xB_FFFF).contains(&linear) {
            if linear >= 0xA_0000 {
                return Target::FrameBuffer(linear);
            }
            let (high, low) = (linear >> 16, linear & 0xFFFF);
            return match high {
                0 if low <= LOW_MEMORY_LIMIT => Target::LowMemory(low as usize),
                2 | 3 if low < TRANSFER_LENGTH => Target::Transfer(low as u64),
                _ => Target::Scratch,
            };
        }
        Target::IoMemory(linear)
    }

    /// Endereço físico do byte `linear` numa faixa física.
    fn physical_address(&self, target: Target, delta: u32) -> u64 {
        match target {
            Target::IoMemory(linear) => {
                let at = (linear + delta) & 0xF_FFFF;
                (self.page_frames[(at >> 12) as usize] as u64) << 12 | (at & 0xFFF) as u64
            }
            Target::FrameBuffer(linear) => (linear + delta) as u64,
            _ => unreachable!("faixa sem endereço físico"),
        }
    }

    /// Lê `size` bytes a partir de `linear`: traduz o primeiro byte e lê os
    /// seguintes na mesma faixa, como o ponteiro único do NT.
    fn read_linear(&self, linear: u32, size: u32) -> u32 {
        let target = Self::translate(linear);
        match target {
            Target::LowMemory(index) => {
                let mut bytes = [0u8; 4];
                bytes[..size as usize].copy_from_slice(&self.low_memory[index..index + size as usize]);
                u32::from_le_bytes(bytes)
            }
            Target::Transfer(offset) => {
                let mut bytes = [0u8; 4];
                bytes[..size as usize].copy_from_slice(&guest::read_bytes(self.transfer + offset, size as usize));
                u32::from_le_bytes(bytes)
            }
            Target::Scratch => 0,
            Target::IoMemory(_) | Target::FrameBuffer(_) => {
                let start = self.physical_address(target, 0);
                if start & 0xFFF <= 0x1000 - size as u64 {
                    return match size {
                        1 => physical::read8(start) as u32,
                        2 => physical::read16(start) as u32,
                        _ => physical::read32(start),
                    };
                }
                (0..size).fold(0, |value, index| value | (physical::read8(self.physical_address(target, index)) as u32) << (8 * index))
            }
        }
    }

    fn write_linear(&mut self, linear: u32, size: u32, value: u32) {
        let target = Self::translate(linear);
        let bytes = value.to_le_bytes();
        match target {
            Target::LowMemory(index) => self.low_memory[index..index + size as usize].copy_from_slice(&bytes[..size as usize]),
            Target::Transfer(offset) => guest::write_bytes(self.transfer + offset, &bytes[..size as usize]),
            Target::Scratch => {}
            Target::IoMemory(_) | Target::FrameBuffer(_) => {
                let start = self.physical_address(target, 0);
                if start & 0xFFF <= 0x1000 - size as u64 {
                    return match size {
                        1 => physical::write8(start, value as u8),
                        2 => physical::write16(start, value as u16),
                        _ => physical::write32(start, value),
                    };
                }
                for (index, &byte) in bytes[..size as usize].iter().enumerate() {
                    physical::write8(self.physical_address(target, index as u32), byte);
                }
            }
        }
    }

    /// XmEmulateInterrupt + XmEmulateStream.
    fn emulate_interrupt(&mut self, vector: u8, registers: &X86BiosRegisters) -> Status {
        // Pilha inicial e o quadro falso de IRET: IP = FFFFh, CS = FFFFh,
        // FLAGS = 0 (o retorno a ele encerra a emulação).
        self.cpu.segment[SS] = INITIAL_SS;
        self.cpu.gpr[ESP] = INITIAL_SP;
        let top = ((INITIAL_SS as u32) << 4) + INITIAL_SP;
        self.write_linear(top - 6, 2, 0xFFFF);
        self.write_linear(top - 4, 4, 0xFFFF);
        self.cpu.gpr[ESP] = (self.cpu.gpr[ESP] & !0xFFFF) | (self.cpu.gpr[ESP].wrapping_sub(6) & 0xFFFF);
        let vector_address = vector as u32 * 4;
        let offset = self.read_linear(vector_address, 2);
        let segment = self.read_linear(vector_address + 2, 2);
        self.cpu.gpr[EAX] = registers.eax.get();
        self.cpu.gpr[ECX] = registers.ecx.get();
        self.cpu.gpr[EDX] = registers.edx.get();
        self.cpu.gpr[EBX] = registers.ebx.get();
        self.cpu.gpr[EBP] = registers.ebp.get();
        self.cpu.gpr[ESI] = registers.esi.get();
        self.cpu.gpr[EDI] = registers.edi.get();
        self.cpu.segment[DS] = registers.seg_ds.get();
        self.cpu.segment[ES] = registers.seg_es.get();
        self.cpu.segment[CS] = segment as u16;
        self.cpu.eip = offset;
        let mut cpu = self.cpu;
        let status = emulator::run(&mut cpu, self);
        self.cpu = cpu;
        registers.eax.set(self.cpu.gpr[EAX]);
        registers.ecx.set(self.cpu.gpr[ECX]);
        registers.edx.set(self.cpu.gpr[EDX]);
        registers.ebx.set(self.cpu.gpr[EBX]);
        registers.ebp.set(self.cpu.gpr[EBP]);
        registers.esi.set(self.cpu.gpr[ESI]);
        registers.edi.set(self.cpu.gpr[EDI]);
        status
    }
}

impl Bus for X86Bios {
    fn read(&mut self, segment: u16, offset: u32, size: u32) -> u32 {
        self.read_linear(((segment as u32) << 4).wrapping_add(offset), size)
    }

    fn write(&mut self, segment: u16, offset: u32, size: u32, value: u32) {
        self.write_linear(((segment as u32) << 4).wrapping_add(offset), size, value)
    }

    fn read_port(&mut self, port: u16, size: u32) -> u32 {
        self.io.read(port, size)
    }

    fn write_port(&mut self, port: u16, size: u32, value: u32) {
        self.io.write(port, size, value)
    }

    fn pci_bios(&mut self, cpu: &mut Cpu) -> bool {
        self.io.pci_bios(cpu)
    }

    fn performance_counter(&mut self) -> u64 {
        crate::ntos::ke::clock::query_performance_counter(0)
    }
}

/// Último número de barramento PCI da máquina: o maior barramento
/// subordinado das pontes PCI-PCI do barramento 0 (0 sem pontes).
fn last_pci_bus() -> u32 {
    let mut last = 0;
    for device in 0..32 {
        for function in 0..8 {
            let Ok(id) = crate::hal::pci_config::read(0, device, function, 0, 4) else { continue };
            if id & 0xFFFF == 0xFFFF {
                if function == 0 {
                    break;
                }
                continue;
            }
            let header = crate::hal::pci_config::read(0, device, function, 0x0E, 1).unwrap_or(0);
            if header & 0x7F == 1 {
                last = last.max(crate::hal::pci_config::read(0, device, function, 0x1A, 1).unwrap_or(0));
            }
            if function == 0 && header & 0x80 == 0 {
                break;
            }
        }
    }
    last
}

/// HalInitializeBios (fase 0, depois do Mm): a visão do primeiro megabyte,
/// a janela VGA, o buffer de transferência, o emulador e a cópia da IVT e da
/// BDA; depois disso o BIOS de vídeo está disponível (HalpVideoBiosPresent).
pub fn initialize() -> Result<(), KernelError> {
    // O MDL do HalpIoMemoryBase: identidade, com a janela VGA e a RAM do
    // sistema trocadas pela página F0000h.
    let mut page_frames = [0u32; FIRST_MEGABYTE_PAGES];
    for (page, frame) in page_frames.iter_mut().enumerate() {
        let address = page as u64 * 0x1000;
        let vga = (0xA0..0xC0).contains(&page);
        *frame = if vga || physical_layout::contains_ram_range(address, 0x1000) { SUBSTITUTE_PAGE } else { page as u32 };
    }
    // HalpFrameBufferBase: MmMapIoSpaceEx(A0000h, 128 KB, sem cache).
    if mm_io_space::map_ex(FRAME_BUFFER_BASE, FRAME_BUFFER_SIZE) == 0 {
        return Err(KernelError::new("x86 BIOS: janela VGA fora do mapa fisico"));
    }
    // HalpMmAllocCtxAlloc(0x2000): o buffer de transferência.
    let transfer = guest::alloc_bytes(TRANSFER_LENGTH as u64 + 4);
    if transfer == 0 {
        return Err(KernelError::new("x86 BIOS: sem memoria para o buffer de transferencia"));
    }
    guest::write_bytes(transfer, &[0u8; TRANSFER_LENGTH as usize + 4]);
    // XmInitializeEmulator: contexto zerado, pilha em 0000:0800 e toda a IVT
    // apontando para um IRET em 0000:0500.
    let mut low_memory = [0u8; LOW_MEMORY_SIZE];
    low_memory[DEFAULT_HANDLER as usize] = IRET;
    for vector in 0..256 {
        low_memory[vector * 4..vector * 4 + 4].copy_from_slice(&DEFAULT_HANDLER.to_le_bytes());
    }
    // A IVT e a BDA da máquina: MmMapIoSpaceEx(0, 0x800) e a cópia.
    let source = mm_io_space::map_ex(0, LOW_MEMORY_LIMIT as u64);
    if source == 0 {
        return Err(KernelError::new("x86 BIOS: primeira pagina fora do mapa fisico"));
    }
    for (index, byte) in low_memory[..LOW_MEMORY_LIMIT as usize].iter_mut().enumerate() {
        *byte = physical::read8(index as u64);
    }
    mm_io_space::unmap(source, LOW_MEMORY_LIMIT as u64);
    let mut cpu = Cpu::new();
    cpu.segment[SS] = INITIAL_SS;
    cpu.gpr[ESP] = INITIAL_SP;
    // XmPciBiosPresent: a HalPrivateDispatchTable tem o KdGetPciDataByOffset.
    let pci_bios_present = crate::hal::private_dispatch::has_routine("KdGetPciDataByOffset");
    let io = IoSpace::new(pci_bios_present, last_pci_bus());
    *BIOS.lock() = Some(X86Bios { cpu, low_memory, page_frames, transfer, buffer_allocated: false, io });
    VIDEO_BIOS_PRESENT.store(true, Ordering::SeqCst);
    let substituted = page_frames.iter().enumerate().filter(|&(page, &frame)| frame != page as u32).count();
    let int10 = u32::from_le_bytes([low_memory[0x40], low_memory[0x41], low_memory[0x42], low_memory[0x43]]);
    debug_print!(
        "[hal] BIOS x86: INT 10h em {:04x}:{:04x}, buffer de transferencia em {:04x}:0000 ({} bytes), {} paginas do primeiro megabyte trocadas pela ROM",
        int10 >> 16,
        int10 & 0xFFFF,
        TRANSFER_SEGMENT,
        TRANSFER_LENGTH,
        substituted
    );
    Ok(())
}

/// HalpGetDisplayBiosInformation: HalDisplayEmulatedBios com o BIOS de vídeo
/// presente, HalDisplayNoBios sem ele.
pub fn display_bios_information() -> u32 {
    if VIDEO_BIOS_PRESENT.load(Ordering::SeqCst) { HAL_DISPLAY_EMULATED_BIOS } else { HAL_DISPLAY_NO_BIOS }
}

/// x86BiosCall(InterruptNumber, Registers): TRUE se o BIOS voltou ao quadro
/// da chamada.
pub fn call(interrupt: u32, registers: &X86BiosRegisters) -> bool {
    if !VIDEO_BIOS_PRESENT.load(Ordering::SeqCst) {
        return false;
    }
    let mut bios = BIOS.lock();
    let Some(state) = bios.as_mut() else { return false };
    let status = state.emulate_interrupt(interrupt as u8, registers);
    if status != Status::Success {
        debug_print!("[hal] x86BiosCall: a emulacao da interrupcao {:#x} falhou, status {:x} em {:04x}:{:04x}", interrupt as u8, status as u32, state.cpu.segment[CS], state.cpu.eip);
    }
    status == Status::Success
}

/// x86BiosAllocateBuffer(Size, Segment, Offset): o buffer de transferência
/// inteiro (2000:0000, 8 KB), se cabe e está livre.
pub fn allocate_buffer(size: &crate::ntos::inc::types::Field<u32>, segment: &crate::ntos::inc::types::Field<u16>, offset: &crate::ntos::inc::types::Field<u16>) -> u32 {
    let mut bios = BIOS.lock();
    let Some(state) = bios.as_mut() else { return STATUS_INSUFFICIENT_RESOURCES };
    if state.buffer_allocated || size.get() > TRANSFER_LENGTH {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    state.buffer_allocated = true;
    segment.set(TRANSFER_SEGMENT);
    offset.set(0);
    size.set(TRANSFER_LENGTH);
    STATUS_SUCCESS
}

/// x86BiosFreeBuffer(Segment, Offset): só o endereço linear 20000h.
pub fn free_buffer(segment: u16, offset: u16) -> u32 {
    let mut bios = BIOS.lock();
    let Some(state) = bios.as_mut() else { return STATUS_INVALID_PARAMETER };
    let linear = (((segment as u32) << 4) + offset as u32) & 0xF_FFFF;
    if !state.buffer_allocated || linear != (TRANSFER_SEGMENT as u32) << 4 {
        return STATUS_INVALID_PARAMETER;
    }
    state.buffer_allocated = false;
    STATUS_SUCCESS
}

/// Faixa de x86BiosRead/WriteMemory: segmento * 16 + deslocamento + tamanho
/// até 1 MB (na aritmética de 32 bits do NT).
fn memory_range_valid(segment: u16, offset: u16, size: u32) -> bool {
    ((segment as u32) << 4).wrapping_add(size).wrapping_add(offset as u32) <= 0x10_0000
}

/// x86BiosReadMemory(Segment, Offset, Buffer, Size): byte a byte, com o
/// deslocamento de 16 bits.
pub fn read_memory(segment: u16, offset: u16, buffer: u64, size: u32) -> u32 {
    if !memory_range_valid(segment, offset, size) {
        return STATUS_INVALID_PARAMETER;
    }
    let bios = BIOS.lock();
    let mut bytes = alloc::vec::Vec::with_capacity(size as usize);
    for index in 0..size {
        let at = ((segment as u32) << 4) + offset.wrapping_add(index as u16) as u32;
        bytes.push(bios.as_ref().map_or(0, |state| state.read_linear(at, 1) as u8));
    }
    drop(bios);
    guest::write_bytes(buffer, &bytes);
    STATUS_SUCCESS
}

/// x86BiosWriteMemory(Segment, Offset, Buffer, Size).
pub fn write_memory(segment: u16, offset: u16, buffer: u64, size: u32) -> u32 {
    if !memory_range_valid(segment, offset, size) {
        return STATUS_INVALID_PARAMETER;
    }
    let bytes = guest::read_bytes(buffer, size as usize);
    let mut bios = BIOS.lock();
    if let Some(state) = bios.as_mut() {
        for (index, &byte) in bytes.iter().enumerate() {
            let at = ((segment as u32) << 4) + offset.wrapping_add(index as u16) as u32;
            state.write_linear(at, 1, byte as u32);
        }
    }
    STATUS_SUCCESS
}
