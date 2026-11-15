//! Informação do vídeo de boot (BgkQueryBootGraphicsInformation), que o
//! NtQuerySystemInformation devolve na classe SystemBootGraphicsInformation
//! (126) e de que o dxgkrnl.sys tira a tela de POST de um adaptador
//! (DpiAcquirePostDisplayInfoFromBgfx).
//!
//! Como no ntoskrnl 19041: o BgkQueryBootGraphicsInformation (rva 0x9f248c)
//! devolve STATUS_UNSUCCESSFUL se a biblioteca gráfica de boot não foi
//! inicializada; senão o BgQueryBootGraphicsInformation (rva 0x39b714)
//! recusa IRQL acima de PASSIVE e níveis fora de 0..3, e devolve
//! STATUS_UNSUCCESSFUL se o firmware não deixou um framebuffer de boot (bit 0
//! das flags do BGFX). O ExpQuerySystemInformation exige o tamanho exato de
//! SYSTEM_BOOT_GRAPHICS_INFORMATION (0x20, senão
//! STATUS_INFO_LENGTH_MISMATCH), pede o nível 0 e grava 0x20 no
//! ReturnLength em todos os casos.
//!
//! O OpenNT é o próprio carregador. No boot comum o vídeo de boot é o modo
//! texto VGA do console do kernel: não há biblioteca gráfica de boot nem
//! framebuffer, então a consulta devolve STATUS_UNSUCCESSFUL, como o NT num
//! boot sem tela gráfica. Numa máquina com adaptador de vídeo
//! (`--display=basic`) o boot faz o que o BGFX do carregador do Windows faz
//! num boot por BIOS ([`initialize_firmware_display`]): liga pelo BIOS de
//! vídeo (VBE) um modo de 1024x768 com 32 bits por pixel e framebuffer
//! linear e entrega ao kernel a descrição do framebuffer, que o
//! BgQueryBootGraphicsInformation copia no nível 0 (FrameBuffer, Width,
//! Height, PixelStride, Format; Flags e DisplayRotation zerados).

use core::sync::atomic::{AtomicBool, Ordering};

use crate::hal::x86bios;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::extra_hal::X86BiosRegisters;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::{KernelError, SpinLock};

const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// sizeof(SYSTEM_BOOT_GRAPHICS_INFORMATION): FrameBuffer, Width, Height,
/// PixelStride, Flags, Format e DisplayRotation.
pub const BOOT_GRAPHICS_INFORMATION_SIZE: u32 = 0x20;

/// SystemPixelFormatB8G8R8X8: o modo direto de 32 bits do VBE (vermelho em
/// 16, verde em 8, azul em 0).
const PIXEL_FORMAT_B8G8R8X8: u32 = 4;
/// A resolução que o carregador procura na lista de modos do VBE.
const WIDTH: u32 = 1024;
const HEIGHT: u32 = 768;

/// O framebuffer de boot (o BGFX do carregador): endereço físico, largura,
/// altura, pixels por linha e formato.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootFrameBuffer {
    pub frame_buffer: u64,
    pub width: u32,
    pub height: u32,
    pub pixel_stride: u32,
    pub format: u32,
}

/// BgkpInitialized: a biblioteca gráfica de boot recebeu um framebuffer.
static INITIALIZED: AtomicBool = AtomicBool::new(false);
static FRAME_BUFFER: SpinLock<Option<BootFrameBuffer>> = SpinLock::new(None);

/// O framebuffer de boot entregue pelo carregador, se houver.
pub fn boot_frame_buffer() -> Option<BootFrameBuffer> {
    *FRAME_BUFFER.lock()
}

/// INT 10h pelo BIOS de vídeo emulado: (ok, EAX, EBX).
fn video_bios(eax: u32, ebx: u32, ecx: u32, edi: u32, es: u16) -> (bool, u32) {
    let block = guest::alloc_bytes(X86BiosRegisters::SIZE);
    if block == 0 {
        return (false, 0);
    }
    // SAFETY: bloco zerado do tamanho de X86_BIOS_REGISTERS.
    let registers = unsafe { X86BiosRegisters::at(block) };
    registers.eax.set(eax);
    registers.ebx.set(ebx);
    registers.ecx.set(ecx);
    registers.edi.set(edi);
    registers.seg_es.set(es);
    let ok = x86bios::call(0x10, registers);
    let result = registers.eax.get();
    guest::free_bytes(block);
    (ok && result & 0xFFFF == 0x004F, result)
}

fn read_bios(segment: u16, offset: u16, size: u32) -> alloc::vec::Vec<u8> {
    let buffer = guest::alloc_bytes(size as u64);
    if buffer == 0 {
        return alloc::vec::Vec::new();
    }
    x86bios::read_memory(segment, offset, buffer, size);
    let bytes = guest::read_bytes(buffer, size as usize);
    guest::free_bytes(buffer);
    bytes
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    bytes.get(offset..offset + 2).map_or(0, |pair| u16::from_le_bytes([pair[0], pair[1]]) as u32)
}

fn dword(bytes: &[u8], offset: usize) -> u64 {
    bytes.get(offset..offset + 4).map_or(0, |quad| u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]]) as u64)
}

/// O vídeo de boot de um boot por BIOS: o BGFX do carregador lê a lista de
/// modos do VBE (4F00h), escolhe o modo 1024x768 de 32 bits com framebuffer
/// linear (4F01h: atributos de modo suportado, gráfico e linear) e o liga
/// (4F02h com o bit do framebuffer linear). Devolve
/// a descrição entregue ao kernel, ou None sem BIOS de vídeo ou sem o modo.
pub fn initialize_firmware_display() -> Option<BootFrameBuffer> {
    if x86bios::display_bios_information() == 2 {
        return None;
    }
    let cells = guest::alloc_bytes(8);
    if cells == 0 {
        return None;
    }
    guest::write32(cells, 0x400);
    // SAFETY: três células do bloco recém-alocado (ULONG, USHORT, USHORT).
    let allocated = unsafe { x86bios::allocate_buffer(Field::<u32>::at(cells), Field::<u16>::at(cells + 4), Field::<u16>::at(cells + 6)) };
    let (segment, offset) = (guest::read16(cells + 4), guest::read16(cells + 6));
    guest::free_bytes(cells);
    if allocated != 0 {
        return None;
    }
    let chosen = (|| {
        let signature = guest::alloc_bytes(4);
        guest::write_bytes(signature, b"VBE2");
        x86bios::write_memory(segment, offset, signature, 4);
        guest::free_bytes(signature);
        if !video_bios(0x4F00, 0, 0, offset as u32, segment).0 {
            return None;
        }
        let information = read_bios(segment, offset, 0x200);
        if information.get(..4) != Some(b"VESA") {
            return None;
        }
        let list = read_bios(word(&information, 0x10) as u16, word(&information, 0x0E) as u16, 0x200);
        for mode in (0..0x100).map(|index| word(&list, index * 2)).take_while(|&mode| mode != 0xFFFF) {
            if !video_bios(0x4F01, 0, mode, offset as u32 + 0x200, segment).0 {
                continue;
            }
            let mode_information = read_bios(segment, offset + 0x200, 0x100);
            let attributes = word(&mode_information, 0);
            if word(&mode_information, 0x12) == WIDTH && word(&mode_information, 0x14) == HEIGHT && mode_information.get(0x19) == Some(&32) && attributes & 0x91 == 0x91 {
                let pitch = if word(&information, 4) >= 0x300 { word(&mode_information, 0x32) } else { word(&mode_information, 0x10) };
                return Some((mode, BootFrameBuffer { frame_buffer: dword(&mode_information, 0x28), width: WIDTH, height: HEIGHT, pixel_stride: pitch / 4, format: PIXEL_FORMAT_B8G8R8X8 }));
            }
        }
        None
    })();
    x86bios::free_buffer(segment, offset);
    let (mode, frame_buffer) = chosen?;
    if frame_buffer.frame_buffer == 0 || !video_bios(0x4F02, mode | 0x4000, 0, 0, 0).0 {
        return None;
    }
    *FRAME_BUFFER.lock() = Some(frame_buffer);
    INITIALIZED.store(true, Ordering::Release);
    crate::debug_print!("[bgk] video de boot: modo VBE {:#x} {}x{}x32, framebuffer {:#x}, {} pixels por linha", mode, frame_buffer.width, frame_buffer.height, frame_buffer.frame_buffer, frame_buffer.pixel_stride);
    Some(frame_buffer)
}

/// BgkQueryBootGraphicsInformation(Level, Buffer): sem biblioteca gráfica de
/// boot inicializada, STATUS_UNSUCCESSFUL sem tocar o buffer; senão o
/// BgQueryBootGraphicsInformation recusa IRQL acima de PASSIVE, buffer nulo
/// e níveis acima de 3, e o nível 0 copia a descrição do framebuffer.
pub fn query_boot_graphics_information(level: u32, buffer: u64) -> u32 {
    if !INITIALIZED.load(Ordering::Acquire) {
        return STATUS_UNSUCCESSFUL;
    }
    if crate::ntos::ke::irql::get_irql() != 0 {
        return STATUS_UNSUCCESSFUL;
    }
    if buffer == 0 || level >= 4 {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(frame_buffer) = boot_frame_buffer() else { return STATUS_UNSUCCESSFUL };
    if level != 0 {
        // Os níveis 1 a 3 descrevem o logotipo e o progresso do boot, que o
        // vídeo de boot do OpenNT não desenha.
        return STATUS_UNSUCCESSFUL;
    }
    // SAFETY: o SYSTEM_BOOT_GRAPHICS_INFORMATION de 0x20 bytes do chamador.
    unsafe {
        Field::<u64>::at(buffer).set(frame_buffer.frame_buffer);
        Field::<u32>::at(buffer + 8).set(frame_buffer.width);
        Field::<u32>::at(buffer + 0xC).set(frame_buffer.height);
        Field::<u32>::at(buffer + 0x10).set(frame_buffer.pixel_stride);
        Field::<u32>::at(buffer + 0x14).set(0);
        Field::<u32>::at(buffer + 0x18).set(frame_buffer.format);
        Field::<u32>::at(buffer + 0x1C).set(0);
    }
    0
}

/// O ramo SystemBootGraphicsInformation do NtQuerySystemInformation (modo
/// kernel).
pub fn query_system_information(output: u64, length: u32, returned: u64) -> Result<u32, KernelError> {
    let status = if length != BOOT_GRAPHICS_INFORMATION_SIZE { STATUS_INFO_LENGTH_MISMATCH } else { query_boot_graphics_information(0, output) };
    if returned != 0 {
        // SAFETY: o PULONG ReturnLength do chamador (modo kernel).
        unsafe { Field::<u32>::at(returned) }.set(BOOT_GRAPHICS_INFORMATION_SIZE);
    }
    Ok(status)
}
