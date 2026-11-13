//! O mapa de memória do OpenNT.
//! Única fonte de verdade para o layout físico/virtual.
//!
//! ```text
//!   0x000000-0x07FFF     tabelas do boot, IDT, memória compartilhada IRQ
//!   0x009000-0x009FFF    trampolim de AP (SMP, SIPI vetor 0x09)
//!   0x00A000-0x00AFFF    mailbox SMP (handshake + fila de jobs por CPU)
//!   0x060000-0x06FFFF    pilhas dos APs (4KB por CPU, até 16 CPUs)
//!   0x100000-0xDFFFFF    imagem do kernel (cap de build: 13MB)
//!   0xF80008 (topo)      pilha do kernel de boot (cresce para baixo)
//!   0x1000000-0x1FFFFFF  sem uso (as imagens de drivers moram no espaço de sistema)
//!   0x2000000-0x5FFFFFF  heap do kernel (kmalloc), com a arena de 16MB
//!   0x6000000-0xFFFFFFF  primeira arena PFN (160MB)
//!   0x10000000-0x1FFFFFFF espaço de VA para VirtualAlloc (fora do PFN)
//!   0x20000000-0x2FFFFFFF segunda arena PFN (256MB)
//!   0x30000000-0x33FFFFFF ring do tracer FULL (64MB)
//!   0x34000000-0x6FFFFFFF terceira arena PFN (960MB)
//!   0x70000000-0xAFFFFFFF reservado (KUSER_SHARED_DATA em 0x7FFE0000)
//!   0xB0000000-0xBEFFFFFF sem uso
//! ```
//!
//! Na metade de sistema, as imagens de kernel (drivers .sys, hal.dll,
//! ci.dll, bibliotecas de export) ficam na janela `SYSTEM_IMAGE_BASE..TOP`
//! (bloco "Imagens de sistema" abaixo).
#![allow(dead_code)]

pub const PAGE_SIZE: u64 = 0x1000;
pub const LARGE_PAGE_SIZE: u64 = 0x20_0000;
pub const KERNEL_IMAGE_BASE: u64 = 0x10_0000;
pub const KERNEL_IMAGE_MAX: u64 = 13 * 1024 * 1024;
pub const BOOT_STACK_TOP: u64 = 0xF8_0008;
pub const KERNEL_VIRTUAL_BASE: u64 = 0xFFFF_F800_4000_0000;
/// Limite exclusivo da VA de usuário; os 64KB finais abaixo da divisão
/// canônica são reservados.
pub const USER_ADDRESS_LIMIT: u64 = 0x7FFF_FFFF_0000;

/// Candidatas, não declaração de RAM: o PFN intersecta estas faixas com a
/// RAM utilizável do E820 e subtrai entradas reservadas.
pub const PFN_RANGES: [(u64, u64); 3] =
    [(0x0600_0000, 0x1000_0000), (0x2000_0000, 0x3000_0000), (0x3400_0000, 0x7000_0000)];
pub const BOOT_FIRMWARE_PHYS: u64 = 0x4FE0;
pub const BOOT_FLAGS_PHYS: u64 = 0x4FD0;
pub const E820_COUNT_PHYS: u64 = 0x4FF0;
pub const E820_TABLE_PHYS: u64 = 0x5000;
pub const E820_MAX_ENTRIES: u64 = 170;
/// O stage2 mapeia 4GB em identidade; RAM acima não é admitida ainda.
pub const PHYSICAL_MEMORY_LIMIT: u64 = 0x1_0000_0000;

pub const VA_ALLOC_BASE: u64 = 0x1000_0000;
pub const VA_ALLOC_TOP: u64 = 0x2000_0000;

// ---- Imagens de sistema ------------------------------------------------------
//
// Toda imagem de kernel carregada pelo `pe_loader` (drivers .sys, hal.dll,
// ci.dll, kdcom, msrpc, cng, WppRecorder, wmilib, as pilhas de teclado e
// disco...) recebe uma faixa desta janela, como no MiLoadSystemImage do NT:
// a VA vem do espaço de sistema, as páginas são frames do PFN (não
// contíguos) mapeados em PTEs de 4 KB de supervisor, e a imagem é relocada
// pela diferença entre essa VA e a ImageBase do cabeçalho. Nenhuma imagem
// carregada fica na metade de usuário nem na identidade abaixo de 4 GB (o
// ntoskrnl não passa pelo loader: é listado pelo alias em
// `KERNEL_VIRTUAL_BASE`). A janela ocupa o slot 496 da PML4 (o mesmo da PCR e
// do alias do kernel), sem cruzar nenhuma outra faixa daqui.

/// Primeira VA da janela de imagens de sistema.
pub const SYSTEM_IMAGE_BASE: u64 = 0xFFFF_F801_0000_0000;
/// Limite exclusivo da janela de imagens de sistema (4 GB).
pub const SYSTEM_IMAGE_TOP: u64 = 0xFFFF_F802_0000_0000;
/// Granularidade das faixas da janela (a de alocação de VA do NT, 64 KB).
pub const SYSTEM_IMAGE_ALIGN: u64 = 0x1_0000;

// ---- fim das imagens de sistema ----------------------------------------------

pub const PCR_VIRTUAL_BASE: u64 = 0xFFFF_F800_0000_0000;
pub const KERNEL_DATA_POOL_BASE: u64 = 0xFFFF_F800_1000_0000;
pub const KERNEL_DATA_POOL_TOP: u64 = 0xFFFF_F800_2000_0000;
pub const KERNEL_POOL_BASE: u64 = 0xFFFF_A000_0000_0000;
pub const KERNEL_POOL_TOP: u64 = 0xFFFF_A001_0000_0000;
pub const KERNEL_DUMP_VIRTUAL_BASE: u64 = 0xFFFF_A002_0000_0000;
pub const KERNEL_CONTIGUOUS_BASE: u64 = 0xFFFF_A003_0000_0000;
pub const KERNEL_CONTIGUOUS_TOP: u64 = 0xFFFF_A004_0000_0000;
pub const KERNEL_INDEPENDENT_BASE: u64 = 0xFFFF_A004_0000_0000;
pub const KERNEL_INDEPENDENT_TOP: u64 = 0xFFFF_A005_0000_0000;
pub const KERNEL_SECTION_BASE: u64 = 0xFFFF_A005_0000_0000;
pub const KERNEL_SECTION_TOP: u64 = 0xFFFF_A006_0000_0000;

/// Primeira janela da metade supervisora: as tabelas reais (mapeamento
/// recursivo), sem alocações comuns.
pub const PAGE_TABLE_RECURSIVE_INDEX: u64 = 256;
/// Array nativo de descritores dos frames e célula MmPfnDatabase (slot 257).
pub const PFN_DATABASE_BASE: u64 = 0xFFFF_8080_0000_0000;
pub const PFN_DATABASE_TOP: u64 = 0xFFFF_8080_0400_0000;
pub const PML4_PHYS: u64 = 0x70000;
pub const PDPT_PHYS: u64 = 0x71000;
pub const PD_PHYS: u64 = 0x72000;

pub const AP_TRAMPOLINE_PHYS: u64 = 0x9000;
pub const SMP_MAILBOX_PHYS: u64 = 0xA000;
pub const AP_STACK_BASE: u64 = 0x60000;
pub const AP_STACK_SIZE: u64 = 0x1000;
pub const MAX_CPUS: usize = 16;
pub const LAPIC_PHYS: u64 = 0xFEE0_0000;
