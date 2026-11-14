//! O mapa de memória do OpenNT.
//! Única fonte de verdade para o layout físico/virtual (o stage2 e o xtask
//! incluem este arquivo).
//!
//! Frames físicos fixos (alcançados só pelo mapa direto, nunca como VA):
//!
//! ```text
//!   0x000000-0x005FFF    IVT/BDA, handoff do stage2 (0x4FD0-0x4FFF), E820 (0x5000)
//!   0x009000-0x009FFF    trampolim de AP (SMP, SIPI vetor 0x09)
//!   0x00A000-0x00AFFF    mailbox SMP (handshake + fila de jobs por CPU)
//!   0x060000-0x06FFFF    pilhas dos APs (4KB por CPU, até 16 CPUs)
//!   0x070000-0x072FFF    PML4 e tabelas da identidade transitória do stage2
//!   0x076000-0x07AFFF    tabelas do mapa direto (PDPT, 4 PDs)
//!   0x07B000-0x07CFFF    tabelas da janela do heap (PDPT, PD)
//!   0x081000-0x081FFF    contagem de IRQs, ring do teclado, células de IRQL
//!   0x082000-0x082FFF    IDT (carregada pela VA do mapa direto)
//!   0x083000-0x08CFFF    tabelas da imagem do kernel e da pilha de boot
//!   0x100000-0xDFFFFF    frames da imagem do kernel (cap de build: 13MB)
//!   0xE01000-0xF7FFFF    frames da pilha de boot
//!   0x1000000-0x1FFFFFF  sem uso
//!   0x2000000-0x5FFFFFF  frames do heap do kernel (kmalloc) e da arena de 16MB
//!   0x6000000-0xFFFFFFF  primeira arena PFN (160MB)
//!   0x20000000-0x2FFFFFFF segunda arena PFN (256MB)
//!   0x30000000-0x33FFFFFF ring do tracer FULL (64MB)
//!   0x34000000-0x6FFFFFFF terceira arena PFN (960MB)
//! ```
//!
//! Espaço virtual. A metade de usuário, PML4[0..256), é só dos processos:
//! nada do kernel fica abaixo de MmSystemRangeStart (`mm/user_half.rs`
//! confere no fim da fase 0). Como no Windows 10 19041 x64, ela vai de
//! MM_LOWEST_USER_ADDRESS (64 KB; os primeiros 64 KB nunca são mapeáveis) a
//! MmHighestUserAddress, sem nenhuma janela fixa: imagens, pilhas, PEB/TEB,
//! vistas de seção e alocações recebem a VA que o alocador escolhe sobre
//! frames do PFN. O único endereço fixo é a visão de usuário, somente
//! leitura, da KUSER_SHARED_DATA:
//!
//! ```text
//!   0x00000000_00000000  64 KB nunca mapeáveis (base abaixo: CONFLICTING_ADDRESSES)
//!   0x00000000_00010000  MM_LOWEST_USER_ADDRESS: a primeira alocação de baixo
//!                        para cima (granularidade de 64 KB)
//!   0x00000000_7FFE0000  KUSER_SHARED_DATA (visão de usuário, somente leitura)
//!   0x00000001_40000000  ImageBase típica de um .exe (carregado nela quando livre)
//!   0x00007FFF_FFFDFFFF  MM_HIGHEST_VAD_ADDRESS: topo das alocações (MEM_TOP_DOWN)
//!   0x00007FFF_FFFEFFFF  MmHighestUserAddress
//!   0x00007FFF_FFFF0000  MmUserProbeAddress
//! ```
//!
//! O que é do kernel mora na metade de sistema:
//!
//! ```text
//!   0xFFFF8000_00000000  (256) tabelas de páginas (mapeamento recursivo)
//!   0xFFFF8080_00000000  (257) banco de PFNs nativo
//!   0xFFFFA000_00000000  (320) pool executivo, dump, contígua, independente,
//!                              visões de sistema, VirtualAlloc de kernel,
//!                              pilhas de kernel das threads (0xFFFFA007_...)
//!   0xFFFFB000_00000000  (352) mapa direto de [0, 4GB): DIRECT_MAP_BASE + PA
//!   0xFFFFC000_C0000000  (384) janela do heap do kernel e da arena dos convidados
//!   0xFFFFF780_00000000  (495) KUSER_SHARED_DATA (visão do kernel)
//!   0xFFFFF800_00000000  (496) KPCRs (0xC000 bytes por CPU) e pool de dados
//!   0xFFFFF800_40000000  (496) imagem do kernel (ImageBase do ntoskrnl)
//!   0xFFFFF800_41081000  (496) pilha de boot (até 0xFFFFF800_41200000)
//!   0xFFFFF801_00000000  (496) janela de imagens de sistema (drivers, hal.dll...)
//! ```
#![allow(dead_code)]

pub const PAGE_SIZE: u64 = 0x1000;
pub const LARGE_PAGE_SIZE: u64 = 0x20_0000;
// ---- Metade de usuário (Windows 10 19041 x64) -------------------------------

/// MM_LOWEST_USER_ADDRESS: nenhuma VA de usuário abaixo de 64 KB; um pedido
/// com base fixa abaixo daqui falha com STATUS_CONFLICTING_ADDRESSES, como
/// no MiIsVaRangeAvailable do NT.
pub const LOWEST_USER_ADDRESS: u64 = 0x1_0000;
/// MmHighestUserAddress.
pub const HIGHEST_USER_ADDRESS: u64 = 0x7FFF_FFFE_FFFF;
/// MmUserProbeAddress: o ProbeForRead/ProbeForWrite recusa daqui para cima.
pub const USER_PROBE_ADDRESS: u64 = 0x7FFF_FFFF_0000;
/// Limite exclusivo da VA de usuário (MmUserProbeAddress); os 64 KB finais
/// abaixo da divisão canônica são reservados.
pub const USER_ADDRESS_LIMIT: u64 = USER_PROBE_ADDRESS;
/// MM_HIGHEST_VAD_ADDRESS: a última VA que uma alocação de usuário pode
/// cobrir, 64 KB abaixo do MmHighestUserAddress (o topo do MEM_TOP_DOWN).
pub const HIGHEST_VAD_ADDRESS: u64 = HIGHEST_USER_ADDRESS - 0x1_0000;
/// Granularidade de alocação de VA de usuário (SYSTEM_BASIC_INFORMATION).
pub const ALLOCATION_GRANULARITY: u64 = 0x1_0000;

const _: () = assert!(HIGHEST_USER_ADDRESS + 1 == USER_PROBE_ADDRESS && HIGHEST_VAD_ADDRESS == 0x7FFF_FFFD_FFFF);
const _: () = assert!(LOWEST_USER_ADDRESS == ALLOCATION_GRANULARITY && (USER_PROBE_ADDRESS >> 39) == USER_PML4_ENTRIES - 1);

/// A faixa [base, base + size) cabe na metade de usuário alocável.
pub const fn is_user_range(base: u64, size: u64) -> bool {
    base >= LOWEST_USER_ADDRESS && size != 0 && base <= HIGHEST_VAD_ADDRESS && size - 1 <= HIGHEST_VAD_ADDRESS - base
}

// ---- Imagem do kernel e pilha de boot (metade de sistema) -------------------
//
// O ntoskrnl é ligado na sua VA de sistema, como no NT (0xFFFFF80x_xxxxxxxx):
// `KERNEL_VIRTUAL_BASE` é a ImageBase do PE (cabeçalhos na primeira página,
// `.text` em +0x1000, `kernel/link.ld`), e é essa a base que a lista de
// módulos carregados e o KDDEBUGGER_DATA64 publicam. O stage2 carrega o
// arquivo linearmente em `KERNEL_IMAGE_PHYS` (offsets do arquivo == RVAs) e
// mapeia exatamente SizeOfImage páginas de 4 KB de supervisor, RW e
// executáveis, de `KERNEL_VIRTUAL_BASE` para `KERNEL_IMAGE_PHYS`, com tabelas
// fixas abaixo de 1 MB (uma PDPT, uma PD e sete PTs contíguas). O endereço
// de link fica fora dos 2 GB do topo, então o código do kernel é gerado
// independente de posição (`relocation-model=pic` em `.cargo/config.toml`)
// e ligado como executável estático (`--no-pie`): toda referência do código
// é relativa a RIP, os ponteiros absolutos (vtables, tabelas) são resolvidos
// pelo linker, e não sobra relocação para processar no boot.
//
// A pilha de boot (a do BSP até o escalonador assumir) também é uma VA de
// sistema, na mesma PD da imagem: 383 páginas de RW e NX que terminam em
// `BOOT_STACK_TOP`, sobre os frames físicos logo abaixo de 15,5 MB, com uma
// página de guarda sem mapeamento embaixo. O stage2 entra no kernel com
// RSP = BOOT_STACK_TOP - 8 (alinhamento de quem acabou de receber um CALL).

/// Endereço físico onde o stage2 carrega o PE do kernel.
pub const KERNEL_IMAGE_PHYS: u64 = 0x10_0000;
/// Teto do SizeOfImage do kernel (frames físicos 1 MB a 14 MB).
pub const KERNEL_IMAGE_MAX: u64 = 13 * 1024 * 1024;
/// ImageBase do kernel: o endereço em que ele é ligado e executa.
pub const KERNEL_VIRTUAL_BASE: u64 = 0xFFFF_F800_4000_0000;
/// Slot da PML4 da imagem (o mesmo da KPCR e da janela de imagens de sistema).
pub const KERNEL_PML4_INDEX: u64 = 496;
/// Tabelas do mapeamento da imagem e da pilha de boot montadas pelo stage2.
pub const KERNEL_PDPT_PHYS: u64 = 0x8_3000;
pub const KERNEL_PD_PHYS: u64 = 0x8_4000;
/// Primeira das PTs contíguas da imagem (cada uma cobre 2 MB de VA).
pub const KERNEL_PT_PHYS: u64 = 0x8_5000;
pub const KERNEL_PT_COUNT: u64 = KERNEL_IMAGE_MAX.div_ceil(LARGE_PAGE_SIZE);
pub const BOOT_STACK_PT_PHYS: u64 = KERNEL_PT_PHYS + KERNEL_PT_COUNT * PAGE_SIZE;

/// Topo (exclusivo) da pilha de boot e InitialStack da thread do boot.
pub const BOOT_STACK_TOP: u64 = KERNEL_VIRTUAL_BASE + 0x120_0000;
pub const BOOT_STACK_SIZE: u64 = 0x17_F000;
/// Página mais baixa da pilha; a de baixo dela é a guarda.
pub const BOOT_STACK_LIMIT: u64 = BOOT_STACK_TOP - BOOT_STACK_SIZE;
/// Frames físicos da pilha: [BOOT_STACK_PHYS_TOP - BOOT_STACK_SIZE, BOOT_STACK_PHYS_TOP).
pub const BOOT_STACK_PHYS_TOP: u64 = 0xF8_0000;
pub const BOOT_STACK_PHYS_BASE: u64 = BOOT_STACK_PHYS_TOP - BOOT_STACK_SIZE;

/// A VA pertence à faixa reservada da imagem do kernel.
pub const fn is_kernel_image(address: u64) -> bool {
    address >= KERNEL_VIRTUAL_BASE && address < KERNEL_VIRTUAL_BASE + KERNEL_IMAGE_MAX
}

const _: () = assert!((KERNEL_VIRTUAL_BASE >> 39) & 511 == KERNEL_PML4_INDEX && KERNEL_VIRTUAL_BASE % 0x4000_0000 == 0);
// Uma PD cobre a imagem (PDEs 0..KERNEL_PT_COUNT) e a pilha (uma PT própria,
// fora das da imagem), sem cruzar a KPCR nem a janela de imagens de sistema.
const _: () = assert!(KERNEL_IMAGE_PHYS + KERNEL_IMAGE_MAX <= BOOT_STACK_PHYS_BASE - PAGE_SIZE && BOOT_STACK_PHYS_TOP <= 0x100_0000);
const _: () = assert!(KERNEL_IMAGE_MAX % PAGE_SIZE == 0 && BOOT_STACK_SIZE % PAGE_SIZE == 0 && BOOT_STACK_TOP % LARGE_PAGE_SIZE == 0);
const _: () = assert!((BOOT_STACK_LIMIT - PAGE_SIZE) / LARGE_PAGE_SIZE == (BOOT_STACK_TOP - 1) / LARGE_PAGE_SIZE);
const _: () = assert!((BOOT_STACK_TOP - 1 - KERNEL_VIRTUAL_BASE) / LARGE_PAGE_SIZE >= KERNEL_PT_COUNT && BOOT_STACK_TOP - KERNEL_VIRTUAL_BASE <= 0x4000_0000);
const _: () = assert!(KERNEL_PDPT_PHYS >= 0x8_3000 && BOOT_STACK_PT_PHYS + PAGE_SIZE <= 0x8_F000 && KERNEL_PD_PHYS == KERNEL_PDPT_PHYS + PAGE_SIZE && KERNEL_PT_PHYS == KERNEL_PD_PHYS + PAGE_SIZE);

/// Candidatas, não declaração de RAM: o PFN intersecta estas faixas com a
/// RAM utilizável do E820 e subtrai entradas reservadas.
pub const PFN_RANGES: [(u64, u64); 3] =
    [(0x0600_0000, 0x1000_0000), (0x2000_0000, 0x3000_0000), (0x3400_0000, 0x7000_0000)];
pub const BOOT_FIRMWARE_PHYS: u64 = 0x4FE0;
/// GDTR do stage2 gravado por SGDT no modo real (limite em +0, base de 32
/// bits em +2).
pub const BOOT_GDTR_PHYS: u64 = 0x4FE8;
pub const BOOT_FLAGS_PHYS: u64 = 0x4FD0;
pub const E820_COUNT_PHYS: u64 = 0x4FF0;
pub const E820_TABLE_PHYS: u64 = 0x5000;
pub const E820_MAX_ENTRIES: u64 = 170;
/// O stage2 mapeia 4GB no mapa direto; RAM acima não é admitida ainda.
pub const PHYSICAL_MEMORY_LIMIT: u64 = 0x1_0000_0000;

// ---- Imagens de sistema ------------------------------------------------------
//
// Toda imagem de kernel carregada pelo `pe_loader` (drivers .sys, hal.dll,
// ci.dll, kdcom, msrpc, cng, WppRecorder, wmilib, as pilhas de teclado e
// disco...) recebe uma faixa desta janela, como no MiLoadSystemImage do NT:
// a VA vem do espaço de sistema, as páginas são frames do PFN (não
// contíguos) mapeados em PTEs de 4 KB de supervisor, e a imagem é relocada
// pela diferença entre essa VA e a ImageBase do cabeçalho. Nenhuma imagem
// carregada fica na metade de usuário (o ntoskrnl não passa pelo loader: o
// stage2 já o mapeia na sua ImageBase, `KERNEL_VIRTUAL_BASE`). A janela ocupa
// o slot 496 da PML4 (o mesmo da KPCR e da imagem do kernel), sem cruzar
// nenhuma outra faixa daqui.

/// Primeira VA da janela de imagens de sistema.
pub const SYSTEM_IMAGE_BASE: u64 = 0xFFFF_F801_0000_0000;
/// Limite exclusivo da janela de imagens de sistema (4 GB).
pub const SYSTEM_IMAGE_TOP: u64 = 0xFFFF_F802_0000_0000;
/// Granularidade das faixas da janela (a de alocação de VA do NT, 64 KB).
pub const SYSTEM_IMAGE_ALIGN: u64 = 0x1_0000;

// ---- fim das imagens de sistema ----------------------------------------------

/// KPCR do processador N em PCR_VIRTUAL_BASE + N * `pcr::layout::SIZE`.
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
/// Janela do VirtualAlloc de kernel (`mm/virtual_memory.rs`): páginas do PFN
/// em PTEs de supervisor, fora da metade de usuário.
pub const KERNEL_VIRTUAL_ALLOC_BASE: u64 = 0xFFFF_A006_0000_0000;
pub const KERNEL_VIRTUAL_ALLOC_TOP: u64 = 0xFFFF_A006_1000_0000;
/// Janela das pilhas de kernel das threads (`mm/kernel_stack.rs`, o
/// MmCreateKernelStack): uma reserva fixa por pilha, com a pilha no topo e a
/// página de guarda sem PTE logo abaixo do StackLimit.
pub const KERNEL_STACK_BASE: u64 = 0xFFFF_A007_0000_0000;
pub const KERNEL_STACK_TOP: u64 = 0xFFFF_A008_0000_0000;

/// A VA pertence à janela das pilhas de kernel das threads.
pub const fn is_kernel_stack(address: u64) -> bool {
    address >= KERNEL_STACK_BASE && address < KERNEL_STACK_TOP
}

const _: () = assert!(KERNEL_VIRTUAL_ALLOC_TOP <= KERNEL_STACK_BASE && (KERNEL_STACK_BASE >> 39) & 511 == (KERNEL_POOL_BASE >> 39) & 511 && (KERNEL_STACK_TOP - 1) >> 39 == KERNEL_STACK_BASE >> 39);

/// Primeira janela da metade supervisora: as tabelas reais (mapeamento
/// recursivo), sem alocações comuns.
pub const PAGE_TABLE_RECURSIVE_INDEX: u64 = 256;
/// Array nativo de descritores dos frames e célula MmPfnDatabase (slot 257).
pub const PFN_DATABASE_BASE: u64 = 0xFFFF_8080_0000_0000;
pub const PFN_DATABASE_TOP: u64 = 0xFFFF_8080_0400_0000;
pub const PML4_PHYS: u64 = 0x70000;
/// Identidade transitória do stage2: PML4[0] -> esta PDPT -> esta PD, com uma
/// única página de 2 MB em [0, 2 MB) (o código do stage2 enquanto liga a
/// paginação). O kernel desfaz PML4[0] na entrada
/// (`paging::remove_boot_identity`); as quatro páginas seguintes (o espaço das
/// PDs da antiga identidade de 4 GB) ficam sem uso.
pub const BOOT_IDENTITY_PDPT_PHYS: u64 = 0x71000;
pub const BOOT_IDENTITY_PD_PHYS: u64 = 0x72000;
/// Fim da metade de usuário em índices da PML4: [0, 256) é só de usuário.
pub const USER_PML4_ENTRIES: u64 = 256;

pub const AP_TRAMPOLINE_PHYS: u64 = 0x9000;
pub const SMP_MAILBOX_PHYS: u64 = 0xA000;
pub const AP_STACK_BASE: u64 = 0x60000;
pub const AP_STACK_SIZE: u64 = 0x1000;
pub const MAX_CPUS: usize = 16;
pub const LAPIC_PHYS: u64 = 0xFEE0_0000;

// ---- Mapa direto da memória física (metade de sistema) ---------------------
//
// Toda a faixa física [0, PHYSICAL_MEMORY_LIMIT) — RAM, firmware e MMIO
// (LAPIC, framebuffer de texto, BARs) — aparece uma vez em
// DIRECT_MAP_BASE + PA, com páginas de 2 MB de supervisor, RW e NX. O stage2
// monta as tabelas (uma PDPT e quatro PDs, frames fixos abaixo de 1 MB, fora
// do PFN) e liga a entrada DIRECT_MAP_PML4_INDEX da PML4 antes de entrar no
// kernel; daí em diante todo acesso por endereço físico (`hal::physical`,
// tabelas de páginas, descritores de PFN, cabeçalhos do heap e da arena,
// células de baixo nível, dados do trampolim dos APs, tabelas ACPI) passa
// por aqui. O slot inteiro da PML4 (512 GB) é reservado; nenhuma outra
// janela do OpenNT usa o índice 352. O rastreador de frames não conta
// referências deste mapa, como não contava as da identidade baixa.
pub const DIRECT_MAP_BASE: u64 = 0xFFFF_B000_0000_0000;
pub const DIRECT_MAP_PML4_INDEX: u64 = 352;
/// Fim exclusivo da parte mapeada (o slot reservado vai até +512 GB).
pub const DIRECT_MAP_TOP: u64 = DIRECT_MAP_BASE + PHYSICAL_MEMORY_LIMIT;
pub const DIRECT_MAP_SLOT_TOP: u64 = DIRECT_MAP_BASE + 0x80_0000_0000;
/// Tabelas do mapa direto montadas pelo stage2 (PDPT e PDs contíguas).
pub const DIRECT_MAP_PDPT_PHYS: u64 = 0x76000;
pub const DIRECT_MAP_PD_PHYS: u64 = 0x77000;

/// VA do mapa direto do endereço físico `physical_address`.
pub const fn direct_map(physical_address: u64) -> u64 {
    DIRECT_MAP_BASE + physical_address
}

/// A VA está na parte mapeada do mapa direto.
pub const fn is_direct_map(address: u64) -> bool {
    address >= DIRECT_MAP_BASE && address < DIRECT_MAP_TOP
}

const _: () = assert!((DIRECT_MAP_BASE >> 39) & 511 == DIRECT_MAP_PML4_INDEX);
const _: () = assert!(DIRECT_MAP_PML4_INDEX != PAGE_TABLE_RECURSIVE_INDEX && DIRECT_MAP_PML4_INDEX != (PFN_DATABASE_BASE >> 39) & 511);
const _: () = assert!(DIRECT_MAP_PML4_INDEX != (KERNEL_POOL_BASE >> 39) & 511 && DIRECT_MAP_PML4_INDEX != (PCR_VIRTUAL_BASE >> 39) & 511);
// Logo depois das tabelas da identidade de boot do stage2 (0x70000-0x75FFF,
// com as PDs da antiga identidade de 4 GB sem uso) e antes da página de
// contagem de IRQs (0x81000).
const _: () = assert!(DIRECT_MAP_PDPT_PHYS == BOOT_IDENTITY_PD_PHYS + 4 * PAGE_SIZE && DIRECT_MAP_PD_PHYS == DIRECT_MAP_PDPT_PHYS + PAGE_SIZE);
const _: () = assert!(DIRECT_MAP_PD_PHYS + 4 * PAGE_SIZE <= 0x8_1000 && PHYSICAL_MEMORY_LIMIT == 4 * 0x4000_0000);

// ---- Janela do heap do kernel (metade de sistema) --------------------------
//
// O heap do kernel (`hal::kmalloc`, também o alocador global do Rust) e a
// arena de 16 MB dos convidados, reservada dele no boot (IRPs,
// DEVICE_OBJECTs, MDLs, ExAllocatePool2 e as demais estruturas NT que os
// drivers recebem), moram nos frames físicos KERNEL_HEAP_PHYS_BASE..TOP, fora
// do PFN. Esses frames são endereçados só por esta janela, o papel do pool
// não paginado inicial do NT: KERNEL_HEAP_BASE + (PA - KERNEL_HEAP_PHYS_BASE),
// em páginas de 2 MB de supervisor, RW e executáveis (o pool não paginado
// comum do NT executa; a arena também guarda pequenas rotinas de conclusão
// geradas em tempo de execução). Toda alocação do heap e da arena é,
// portanto, uma VA >= MmSystemRangeStart. `paging::map_kernel_heap_window`
// monta a janela no boot, antes da primeira alocação, com tabelas fixas
// abaixo de 1 MB. Como o mapa direto, é um alias físico do kernel: o
// rastreador de frames não acompanha o slot (índice 384 da PML4, reservado
// inteiro), e nenhuma outra janela do OpenNT o usa. Os 32 bits baixos da base
// (0xC0000000) caem no buraco de MMIO acima de 3 GB; como a metade de usuário
// não tem nada do kernel, um ponteiro do heap truncado para 32 bits falta.
pub const KERNEL_HEAP_PHYS_BASE: u64 = 0x200_0000;
/// Fim exclusivo dos frames do heap (início da primeira arena do PFN).
pub const KERNEL_HEAP_PHYS_TOP: u64 = 0x600_0000;
pub const KERNEL_HEAP_BASE: u64 = 0xFFFF_C000_C000_0000;
pub const KERNEL_HEAP_TOP: u64 = KERNEL_HEAP_BASE + (KERNEL_HEAP_PHYS_TOP - KERNEL_HEAP_PHYS_BASE);
pub const KERNEL_HEAP_PML4_INDEX: u64 = 384;
/// Tabelas da janela (PDPT e uma PD), logo depois das do mapa direto.
pub const KERNEL_HEAP_PDPT_PHYS: u64 = 0x7B000;
pub const KERNEL_HEAP_PD_PHYS: u64 = 0x7C000;

/// VA da janela do heap do frame `physical_address` (dentro da faixa do heap).
pub const fn kernel_heap_virtual(physical_address: u64) -> u64 {
    KERNEL_HEAP_BASE + (physical_address - KERNEL_HEAP_PHYS_BASE)
}

/// Endereço físico de uma VA da janela do heap.
pub const fn kernel_heap_physical(address: u64) -> u64 {
    KERNEL_HEAP_PHYS_BASE + (address - KERNEL_HEAP_BASE)
}

/// A VA pertence à janela do heap.
pub const fn is_kernel_heap(address: u64) -> bool {
    address >= KERNEL_HEAP_BASE && address < KERNEL_HEAP_TOP
}

const _: () = assert!((KERNEL_HEAP_BASE >> 39) & 511 == KERNEL_HEAP_PML4_INDEX && KERNEL_HEAP_BASE % 0x4000_0000 == 0);
const _: () = assert!(KERNEL_HEAP_BASE & 0xFFFF_FFFF >= 0xC000_0000 && (KERNEL_HEAP_TOP - 1) & 0xFFFF_FFFF < 0xFEC0_0000);
const _: () = assert!(KERNEL_HEAP_PML4_INDEX != PAGE_TABLE_RECURSIVE_INDEX && KERNEL_HEAP_PML4_INDEX != (PFN_DATABASE_BASE >> 39) & 511 && KERNEL_HEAP_PML4_INDEX != DIRECT_MAP_PML4_INDEX);
const _: () = assert!(KERNEL_HEAP_PML4_INDEX != (KERNEL_POOL_BASE >> 39) & 511 && KERNEL_HEAP_PML4_INDEX != (PCR_VIRTUAL_BASE >> 39) & 511 && KERNEL_HEAP_PML4_INDEX != (SYSTEM_IMAGE_BASE >> 39) & 511);
// Uma PD (1 GB) cobre a faixa inteira, em páginas de 2 MB; os frames ficam
// abaixo da primeira arena do PFN.
const _: () = assert!(KERNEL_HEAP_PHYS_BASE % LARGE_PAGE_SIZE == 0 && KERNEL_HEAP_PHYS_TOP % LARGE_PAGE_SIZE == 0);
const _: () = assert!(KERNEL_HEAP_PHYS_TOP - KERNEL_HEAP_PHYS_BASE <= 0x4000_0000 && KERNEL_HEAP_PHYS_TOP <= PFN_RANGES[0].0);
const _: () = assert!(KERNEL_HEAP_PDPT_PHYS == DIRECT_MAP_PD_PHYS + 4 * PAGE_SIZE && KERNEL_HEAP_PD_PHYS == KERNEL_HEAP_PDPT_PHYS + PAGE_SIZE && KERNEL_HEAP_PD_PHYS + PAGE_SIZE <= 0x8_1000);
