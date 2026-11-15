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
//! O OpenNT sobe por BIOS e o vídeo de boot é o modo texto VGA do console do
//! kernel: não há biblioteca gráfica de boot nem framebuffer, então a
//! consulta devolve STATUS_UNSUCCESSFUL, como o NT num boot sem tela
//! gráfica.

use crate::ntos::inc::field::{Field, NtStruct};
use crate::rtl::KernelError;

const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;

/// sizeof(SYSTEM_BOOT_GRAPHICS_INFORMATION): FrameBuffer, Width, Height,
/// PixelStride, Flags, Format e DisplayRotation.
pub const BOOT_GRAPHICS_INFORMATION_SIZE: u32 = 0x20;

/// BgkQueryBootGraphicsInformation(Level, Buffer): a biblioteca gráfica de
/// boot nunca é inicializada no OpenNT (o BgkpInitialized do NT fica 0),
/// então a consulta não toca o buffer e devolve STATUS_UNSUCCESSFUL.
pub fn query_boot_graphics_information(_level: u32, _buffer: u64) -> u32 {
    STATUS_UNSUCCESSFUL
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
