//! Configuração do Mm publicada aos drivers (o `mminit.c` do NT):
//! MmQuerySystemSize, MmIsThisAnNtAsSystem e os dados MmSystemRangeStart e
//! MmBadPointer.
//!
//! Contrato do ntoskrnl 19041:
//! - MmIsThisAnNtAsSystem: `mov al, [byte do tipo de produto]; ret` — não zero
//!   só para LanmanNt/Server. O OpenNT publica NtProductWinNt (SharedUserData
//!   NtProductType = 1, RtlGetNtProductType), então FALSE.
//! - MmQuerySystemSize: `mov eax, 2; ret` (MmLargeSystem).
//! - MmSystemRangeStart: constante da .rdata, 0xFFFF800000000000.
//! - MmBadPointer: o MiInitSystem reserva uma PTE de sistema (MiReservePtes) e
//!   publica a VA que ela mapeia, que nunca fica válida.
//!
//! O equivalente da PTE reservada no OpenNT é a primeira página depois da
//! janela do pool de kernel (`memory_map::KERNEL_POOL_TOP`, fim exclusivo de
//! 0xFFFF_A000_0000_0000..0xFFFF_A001_0000_0000; a janela seguinte,
//! KERNEL_DUMP_VIRTUAL_BASE, começa em 0xFFFF_A002_0000_0000): nada no mapa de
//! memória a mapeia. As células são entradas de `kernel_data_layout` com o
//! valor inicial; o autoteste confere que o valor de MmBadPointer continua
//! igual a KERNEL_POOL_TOP.

use super::kernel_data;

/// MM_SYSTEMSIZE: MmLargeSystem.
const LARGE_SYSTEM: u32 = 2;

/// MmIsThisAnNtAsSystem: produto WinNt (estação de trabalho).
pub fn is_this_an_nt_as_system() -> bool {
    false
}

/// MmQuerySystemSize.
pub fn query_system_size() -> u32 {
    LARGE_SYSTEM
}

/// Endereço da célula MmSystemRangeStart (export de dados).
pub fn system_range_start_cell() -> u64 {
    kernel_data::required_address("MmSystemRangeStart")
}

/// Endereço da célula MmBadPointer (export de dados).
pub fn bad_pointer_cell() -> u64 {
    kernel_data::required_address("MmBadPointer")
}
