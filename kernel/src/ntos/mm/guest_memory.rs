//! Arena de memória dos convidados (drivers .sys e structs NT) e acesso a
//! endereços de convidado.
//!
//! Arena de 16MB reservada do heap do kernel no boot; blocos livres
//! separados por tamanho, com split e coalescência. Header de bloco (16B):
//! +0 size, +4 previous, +8 next, +12 free (u32). Os links das listas livres
//! ocupam os primeiros 8 bytes do payload livre. Como o heap, a arena mora na
//! janela do heap da metade de sistema (`KERNEL_HEAP_BASE`): toda alocação é
//! uma VA >= MmSystemRangeStart, os cabeçalhos são lidos e gravados por essa
//! VA e os links são offsets a partir da base da arena.
//!
//! # O mapa de memória que o acesso pressupõe (conferido no código)
//!
//! - **Um só espaço de endereços.** Há uma PML4 (`PML4_PHYS`, 0x70000): os
//!   APs carregam o CR3 do BSP e a anexação de processo recusa qualquer
//!   DirectoryTableBase diferente e só recarrega o mesmo CR3. Quando o
//!   kernel toca um buffer de modo usuário, o CR3 ativo é sempre esse: a
//!   VA de usuário é desreferenciável direto.
//! - **Proteção.** CR0.WP=1 em todas as CPUs (escritas de supervisor
//!   respeitam PTEs somente leitura), EFER.NXE=1, CR4 sem SMEP/SMAP.
//! - **Metade de usuário** (PML4[0..256)): só páginas de usuário (imagens,
//!   pilhas, TEB/PEB, seções, a visão de usuário da KUSER_SHARED_DATA). Não
//!   há identidade: a memória física aparece no mapa direto
//!   (`DIRECT_MAP_BASE + PA`, supervisor e NX), e todo acesso por endereço
//!   físico (PTEs, descritores de PFN, células de baixo nível) passa por ele.
//! - **Metade de sistema** (a imagem do kernel e a pilha de boot em
//!   `KERNEL_VIRTUAL_BASE` 0xFFFFF800_40000000..., o heap do kernel e esta
//!   arena na janela do heap 0xFFFFC000..., não pagináveis; imagens de
//!   kernel na janela de sistema 0xFFFFF801..., pool executivo
//!   0xFFFFA000..., PCR 0xFFFFF800..., banco de PFNs, visões de sistema,
//!   memória contígua/independente): tudo nas mesmas tabelas de páginas,
//!   com as entradas de sistema da PML4 pré-alocadas e congeladas no boot
//!   (`paging::freeze_kernel_half`).
//! - **Páginas pagináveis** (imagens de drivers, pool paginado, visões de
//!   seção de sistema, cópia na escrita de seções) têm PTE ausente quando
//!   despejadas. Os provedores ficam em `page_residency`; `fault` recusa IRQL
//!   acima de APC_LEVEL. Até aqui só o modo usuário (`ps::user::exceptions`)
//!   e algumas sondas explícitas chamavam `fault`; uma falta do anel 0 ia
//!   direto ao SEH (código nativo) ou ao diagnóstico (código Rust). A falta
//!   de página do anel 0 agora passa pelos provedores antes (o
//!   `rs_kernel_page_fault` dos trampolins, o papel do MmAccessFault).
//!
//! # Acesso
//!
//! - [`read`]/[`write`] (e `read8..64`/`write8..64`): memória confiável do
//!   kernel. Um MOV volátil da largura exata no endereço virtual, sem
//!   tradução e sem dividir (o x86 aceita desalinhado); 64 bits alinhados são
//!   atômicos para as outras CPUs, como os drivers esperam. Página ausente
//!   entra no tratador de faltas; falta irrecuperável para o sistema, como o
//!   bugcheck do NT.
//! - [`try_read`]/[`try_write`]/[`try_read_bytes`]/[`try_write_bytes`]:
//!   ponteiro não confiável. A sonda (o `__try { ProbeFor*; *p }` do NT)
//!   traz páginas pagináveis de volta, exige PTE presente (e gravável numa
//!   escrita, depois de dar a chance ao tratador de cópia na escrita) e
//!   devolve `STATUS_ACCESS_VIOLATION`; depois faz UM acesso. Só um acesso
//!   que cruza página é dividido, byte a byte em ordem crescente.
//! - [`atomic_u32`]/[`atomic_u64`]: a célula do convidado como atômico de
//!   verdade (Interlocked*, spin locks, push locks, contagens de referência);
//!   [`try_atomic_u32`]/[`try_atomic_u64`] e `compare_exchange32/64/128`
//!   sondam antes e exigem alinhamento natural.
//!
//! Nenhum acesso do kernel passa mais pelo alias de identidade do frame: uma
//! escrita confiável numa página somente leitura falta, como no NT.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::hal::{host, volatile};
use crate::ntos::mm::{page_residency, paging, physical_layout};
use crate::rtl::{KernelError, SpinLock};

pub const ARENA_SIZE: u64 = 0x100_0000; // 16MB
const BLOCK_HEADER_SIZE: u64 = 16;
pub const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const PAGE_SIZE: u64 = 0x1000;

/// Resolvedor de páginas pagináveis (imagens paginadas), instalado depois.
static PAGEABLE_RESOLVER: SpinLock<Option<PageableResolver>> = SpinLock::new(None);

/// Resolvedor de página paginável: `Ok(None)` = não pertence a provedor algum.
pub type PageableResolver = fn(u64) -> Result<Option<u64>, KernelError>;
/// Lock nativo do pool (acquire -> estado anterior, release(estado)).
static POOL_LOCK: SpinLock<Option<(fn() -> u64, fn(u64))>> = SpinLock::new(None);

struct GuestHeap {
    arena_base: u64,
    ready: bool,
    allocations: BTreeSet<u64>,
    /// Primeiro bloco livre de cada classe (VA; 0 = vazia).
    free_bins: [u64; 25],
}

static HEAP: SpinLock<GuestHeap> =
    SpinLock::new(GuestHeap { arena_base: 0, ready: false, allocations: BTreeSet::new(), free_bins: [0; 25] });

/// Falha de sonda conhecida: serviços com SEH devolvem ACCESS_VIOLATION.
pub fn address_fault(address: u64) -> KernelError {
    KernelError::with_status(format!("unmapped guest VA {address:#x}"), STATUS_ACCESS_VIOLATION)
}

pub fn set_pageable_resolver(resolver: Option<PageableResolver>) {
    *PAGEABLE_RESOLVER.lock() = resolver;
}

pub fn set_pool_lock(lock: Option<(fn() -> u64, fn(u64))>) {
    *POOL_LOCK.lock() = lock;
}

// ---- escalares ---------------------------------------------------------------

/// Valor de 1, 2, 4 ou 8 bytes acessado numa única instrução MOV. Os bits
/// são o valor little-endian da célula; tipos `#[repr(transparent)]` sobre um
/// inteiro (ponteiros tipados, por exemplo) implementam pela representação.
pub trait GuestScalar: Copy {
    /// Largura da célula: 1, 2, 4 ou 8.
    const SIZE: u64;
    fn from_bits(bits: u64) -> Self;
    fn to_bits(self) -> u64;
}

macro_rules! guest_scalar {
    ($($type:ty => $unsigned:ty),* $(,)?) => {$(
        impl GuestScalar for $type {
            const SIZE: u64 = core::mem::size_of::<$type>() as u64;
            #[inline(always)]
            fn from_bits(bits: u64) -> Self {
                bits as $unsigned as $type
            }
            #[inline(always)]
            fn to_bits(self) -> u64 {
                self as $unsigned as u64
            }
        }
    )*};
}

guest_scalar!(u8 => u8, u16 => u16, u32 => u32, u64 => u64, i8 => u8, i16 => u16, i32 => u32, i64 => u64);

/// O MOV de `T::SIZE` bytes (o `*(volatile T *)` do C): nunca elidido nem
/// dividido; o asm de `hal::volatile` usa o endereço virtual como ponteiro.
#[inline(always)]
fn load<T: GuestScalar>(address: u64) -> T {
    const { assert!(matches!(T::SIZE, 1 | 2 | 4 | 8), "GuestScalar: largura invalida") };
    T::from_bits(match T::SIZE {
        1 => volatile::read8(address) as u64,
        2 => volatile::read16(address) as u64,
        4 => volatile::read32(address) as u64,
        _ => volatile::read64(address),
    })
}

#[inline(always)]
fn store<T: GuestScalar>(address: u64, value: T) {
    const { assert!(matches!(T::SIZE, 1 | 2 | 4 | 8), "GuestScalar: largura invalida") };
    let bits = value.to_bits();
    match T::SIZE {
        1 => volatile::write8(address, bits as u8),
        2 => volatile::write16(address, bits as u16),
        4 => volatile::write32(address, bits as u32),
        _ => volatile::write64(address, bits),
    }
}

/// Leitura confiável: um MOV no endereço virtual, sem tradução.
#[inline]
pub fn read<T: GuestScalar>(address: u64) -> T {
    load(address)
}

/// Escrita confiável: um MOV no endereço virtual, sem tradução.
#[inline]
pub fn write<T: GuestScalar>(address: u64, value: T) {
    store(address, value)
}

// ---- sonda (ponteiros não confiáveis) -----------------------------------------

fn canonical(address: u64) -> bool {
    matches!(address >> 47, 0 | 0x1_FFFF)
}

fn crosses_page(address: u64, width: u64) -> bool {
    (address & 0xFFF) + width > PAGE_SIZE
}

/// Sonda da página de `address`: o resolvedor traz páginas pagináveis de
/// volta (em qualquer IRQL que o provedor aceite); depois a PTE precisa estar
/// presente e, numa escrita, gravável — uma página copy-on-write ganha uma
/// chance no tratador de faltas. Devolve o endereço físico da página.
fn probe(address: u64, write: bool) -> Result<u64, KernelError> {
    if !canonical(address) {
        return Err(address_fault(address));
    }
    let resolver = *PAGEABLE_RESOLVER.lock();
    if let Some(resolver) = resolver {
        resolver(address)?;
    }
    let page = address & !0xFFF;
    let writable = |mapping: &paging::PageQuery| !write || mapping.access & paging::PAGE_RW != 0;
    let mut mapping = paging::query_page(page, false);
    if mapping.as_ref().is_some_and(|mapping| !writable(mapping)) && page_residency::fault(page, 3) {
        mapping = paging::query_page(page, false);
    }
    match mapping {
        Some(mapping) if writable(&mapping) => Ok(mapping.physical_address),
        _ => Err(address_fault(address)),
    }
}

/// Sonda as páginas tocadas por `width` bytes em `address`.
fn probe_range(address: u64, width: u64, write: bool) -> Result<(), KernelError> {
    probe(address, write)?;
    if crosses_page(address, width) {
        probe(address.wrapping_add(width - 1), write)?;
    }
    Ok(())
}

/// Leitura de ponteiro não confiável: sonda e UM acesso; só um acesso que
/// cruza página vira bytes em ordem crescente.
pub fn try_read<T: GuestScalar>(address: u64) -> Result<T, KernelError> {
    probe_range(address, T::SIZE, false)?;
    if !crosses_page(address, T::SIZE) {
        return Ok(load(address));
    }
    let mut bits = 0u64;
    for index in 0..T::SIZE {
        bits |= (load::<u8>(address.wrapping_add(index)) as u64) << (index * 8);
    }
    Ok(T::from_bits(bits))
}

/// Escrita em ponteiro não confiável: sonda e UM acesso (bytes só quando
/// cruza página).
pub fn try_write<T: GuestScalar>(address: u64, value: T) -> Result<(), KernelError> {
    probe_range(address, T::SIZE, true)?;
    if !crosses_page(address, T::SIZE) {
        store(address, value);
        return Ok(());
    }
    let bits = value.to_bits();
    for index in 0..T::SIZE {
        store(address.wrapping_add(index), (bits >> (index * 8)) as u8);
    }
    Ok(())
}

/// Copia bytes sem presumir continuidade entre páginas virtuais. RAM
/// admitida recebe cópia em bloco; MMIO e reservas conservam a largura e a
/// ordem de cada acesso.
pub fn try_write_bytes(address: u64, bytes: &[u8]) -> Result<(), KernelError> {
    let mut copied = 0usize;
    while copied < bytes.len() {
        let destination = address.wrapping_add(copied as u64);
        let physical_address = probe(destination, true)?;
        let block = ((PAGE_SIZE - (destination & 0xFFF)) as usize).min(bytes.len() - copied);
        let source = &bytes[copied..copied + block];
        if physical_layout::contains_ram_range(physical_address + (destination & 0xFFF), block as u64) {
            // Página de RAM sondada; o buffer de origem pode ser alias dela.
            unsafe { core::ptr::copy(source.as_ptr(), destination as *mut u8, block) }
        } else {
            for (index, &byte) in source.iter().enumerate() {
                store(destination.wrapping_add(index as u64), byte);
            }
        }
        copied += block;
    }
    Ok(())
}

pub fn try_read_bytes(address: u64, length: usize) -> Result<Vec<u8>, KernelError> {
    let mut bytes: Vec<u8> = Vec::with_capacity(length);
    while bytes.len() < length {
        let source = address.wrapping_add(bytes.len() as u64);
        let physical_address = probe(source, false)?;
        let block = ((PAGE_SIZE - (source & 0xFFF)) as usize).min(length - bytes.len());
        if physical_layout::contains_ram_range(physical_address + (source & 0xFFF), block as u64) {
            let start = bytes.len();
            // Página de RAM sondada; `start + block <= capacity`.
            unsafe {
                core::ptr::copy(source as *const u8, bytes.as_mut_ptr().add(start), block);
                bytes.set_len(start + block);
            }
        } else {
            bytes.extend((0..block as u64).map(|index| load::<u8>(source.wrapping_add(index))));
        }
    }
    Ok(bytes)
}

// ---- nomes por largura (as chamadas existentes) --------------------------------

pub fn try_read8(address: u64) -> Result<u8, KernelError> {
    try_read(address)
}
pub fn try_read16(address: u64) -> Result<u16, KernelError> {
    try_read(address)
}
pub fn try_read32(address: u64) -> Result<u32, KernelError> {
    try_read(address)
}
/// Uma carga de qword (64 bits alinhados nunca são observados pela metade).
pub fn try_read64(address: u64) -> Result<u64, KernelError> {
    try_read(address)
}
pub fn try_write8(address: u64, value: u8) -> Result<(), KernelError> {
    try_write(address, value)
}
pub fn try_write16(address: u64, value: u16) -> Result<(), KernelError> {
    try_write(address, value)
}
pub fn try_write32(address: u64, value: u32) -> Result<(), KernelError> {
    try_write(address, value)
}
/// Um store de qword.
pub fn try_write64(address: u64, value: u64) -> Result<(), KernelError> {
    try_write(address, value)
}

#[inline]
pub fn read8(address: u64) -> u8 {
    read(address)
}
#[inline]
pub fn read16(address: u64) -> u16 {
    read(address)
}
#[inline]
pub fn read32(address: u64) -> u32 {
    read(address)
}
/// Uma carga de qword.
#[inline]
pub fn read64(address: u64) -> u64 {
    read(address)
}
/// Mesmo que [`read64`]: toda leitura de qword já é uma carga única.
#[inline]
pub fn read64_single(address: u64) -> u64 {
    read(address)
}
#[inline]
pub fn write8(address: u64, value: u8) {
    write(address, value)
}
#[inline]
pub fn write16(address: u64, value: u16) {
    write(address, value)
}
#[inline]
pub fn write32(address: u64, value: u32) {
    write(address, value)
}
/// Um store de qword.
#[inline]
pub fn write64(address: u64, value: u64) {
    write(address, value)
}

fn kernel_fault(error: KernelError) -> ! {
    panic!("acesso de kernel a memoria de convidado: {}", error)
}

/// Cópia de memória do kernel: a sonda por página escolhe entre bloco (RAM)
/// e bytes (MMIO); a falha para o sistema.
pub fn write_bytes(address: u64, bytes: &[u8]) {
    try_write_bytes(address, bytes).unwrap_or_else(|error| kernel_fault(error))
}
pub fn read_bytes(address: u64, length: usize) -> Vec<u8> {
    try_read_bytes(address, length).unwrap_or_else(|error| kernel_fault(error))
}

// ---- operações atômicas ----------------------------------------------------

/// A célula de 32 bits do convidado como atômico (memória confiável, sem
/// sonda). Exige alinhamento natural, como as operações interlocked.
#[inline]
pub fn atomic_u32(address: u64) -> &'static AtomicU32 {
    debug_assert!(address & 3 == 0, "AtomicU32 desalinhado em {address:#x}");
    unsafe { AtomicU32::from_ptr(address as *mut u32) }
}

/// A célula de 64 bits do convidado como atômico (memória confiável).
#[inline]
pub fn atomic_u64(address: u64) -> &'static AtomicU64 {
    debug_assert!(address & 7 == 0, "AtomicU64 desalinhado em {address:#x}");
    unsafe { AtomicU64::from_ptr(address as *mut u64) }
}

/// Sonda de escrita e alinhamento natural de uma célula interlocked.
fn probe_atomic(address: u64, width: u64) -> Result<(), KernelError> {
    if address & (width - 1) != 0 {
        return Err(KernelError::with_status(format!("misaligned interlocked guest VA {address:#x}"), STATUS_DATATYPE_MISALIGNMENT));
    }
    probe(address, true).map(|_| ())
}

/// [`atomic_u32`] de um ponteiro não confiável.
pub fn try_atomic_u32(address: u64) -> Result<&'static AtomicU32, KernelError> {
    probe_atomic(address, 4)?;
    Ok(atomic_u32(address))
}

/// [`atomic_u64`] de um ponteiro não confiável.
pub fn try_atomic_u64(address: u64) -> Result<&'static AtomicU64, KernelError> {
    probe_atomic(address, 8)?;
    Ok(atomic_u64(address))
}

/// LOCK CMPXCHG: devolve o valor anterior.
pub fn compare_exchange32(address: u64, expected: u32, replacement: u32) -> Result<u32, KernelError> {
    let cell = try_atomic_u32(address)?;
    Ok(match cell.compare_exchange(expected, replacement, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(previous) | Err(previous) => previous,
    })
}

/// LOCK CMPXCHG de 64 bits: devolve o valor anterior.
pub fn compare_exchange64(address: u64, expected: u64, replacement: u64) -> Result<u64, KernelError> {
    let cell = try_atomic_u64(address)?;
    Ok(match cell.compare_exchange(expected, replacement, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(previous) | Err(previous) => previous,
    })
}

/// Cabeçalho SLIST alinhado: compara as duas palavras numa instrução.
/// Devolve o valor anterior (baixo, alto).
pub fn compare_exchange128(
    address: u64,
    expected: (u64, u64),
    replacement: (u64, u64),
) -> Result<(u64, u64), KernelError> {
    probe_atomic(address, 16)?;
    Ok(volatile::compare_exchange128(address, expected, replacement))
}

// ---- heap da arena ---------------------------------------------------------
//
// Cabeçalho de bloco (16 bytes, pela VA da arena): +0 size, +4 previous,
// +8 next, +12 free (u32). previous/next (vizinhos de endereço) e os links
// das listas livres, nos primeiros 8 bytes do payload livre (+16 next,
// +20 previous), são offsets a partir da base da arena: a arena tem 16 MB e
// mora na janela do heap, acima de 4 GB. Os primeiros 16 bytes da arena nunca
// são bloco, então o offset 0 quer dizer "nenhum".

/// Offset do primeiro bloco: o link 0 fica livre para "nenhum".
const FIRST_BLOCK: u64 = 16;

fn free_bin(size: u64) -> usize {
    (63 - size.leading_zeros()) as usize
}

impl GuestHeap {
    fn address(&self, link: u32) -> u64 {
        if link == 0 { 0 } else { self.arena_base + link as u64 }
    }

    fn link(&self, address: u64) -> u32 {
        if address == 0 { 0 } else { (address - self.arena_base) as u32 }
    }

    fn size(&self, block: u64) -> u64 {
        volatile::read32(block) as u64
    }

    fn previous(&self, block: u64) -> u64 {
        self.address(volatile::read32(block + 4))
    }

    fn next(&self, block: u64) -> u64 {
        self.address(volatile::read32(block + 8))
    }

    fn is_free(&self, block: u64) -> bool {
        volatile::read32(block + 12) != 0
    }

    fn set_previous(&self, block: u64, previous: u64) {
        volatile::write32(block + 4, self.link(previous));
    }

    fn write_block(&self, block: u64, size: u64, next: u64, free: bool, previous: Option<u64>) {
        volatile::write32(block, size as u32);
        if let Some(previous) = previous {
            self.set_previous(block, previous);
        }
        volatile::write32(block + 8, self.link(next));
        volatile::write32(block + 12, free as u32);
    }

    fn free_next(&self, block: u64) -> u64 {
        self.address(volatile::read32(block + 16))
    }

    fn free_previous(&self, block: u64) -> u64 {
        self.address(volatile::read32(block + 20))
    }

    fn set_free_next(&self, block: u64, next: u64) {
        volatile::write32(block + 16, self.link(next));
    }

    fn set_free_previous(&self, block: u64, previous: u64) {
        volatile::write32(block + 20, self.link(previous));
    }

    fn insert_free(&mut self, block: u64) {
        let bin = free_bin(self.size(block));
        let next = self.free_bins[bin];
        self.set_free_next(block, next);
        self.set_free_previous(block, 0);
        if next != 0 {
            self.set_free_previous(next, block);
        }
        self.free_bins[bin] = block;
    }

    fn remove_free(&mut self, block: u64) {
        let next = self.free_next(block);
        let previous = self.free_previous(block);
        if previous != 0 {
            self.set_free_next(previous, next);
        } else {
            self.free_bins[free_bin(self.size(block))] = next;
        }
        if next != 0 {
            self.set_free_previous(next, previous);
        }
    }

    fn init(&mut self) {
        self.arena_base = host::guest_arena();
        let first = self.arena_base + FIRST_BLOCK;
        self.write_block(first, ARENA_SIZE - FIRST_BLOCK - BLOCK_HEADER_SIZE, 0, true, Some(0));
        self.insert_free(first);
        self.ready = true;
    }

    fn allocate_aligned(&mut self, size: u64, align: u64, zero: bool) -> u64 {
        if size == 0 || size > ARENA_SIZE - FIRST_BLOCK - BLOCK_HEADER_SIZE {
            return 0;
        }
        let size = size.div_ceil(16) * 16;
        if !self.ready {
            self.init();
        }
        for bin in free_bin(size)..self.free_bins.len() {
            let mut block = self.free_bins[bin];
            while block != 0 {
                let next = self.next(block);
                let corrupt = block < self.arena_base + FIRST_BLOCK
                    || block + BLOCK_HEADER_SIZE > self.arena_base + ARENA_SIZE
                    || (next != 0 && (next != block + BLOCK_HEADER_SIZE + self.size(block) || next <= block));
                assert!(!corrupt, "Guest heap header corrupt at {block:#x}, next={next:#x}");
                let following = self.free_next(block);
                if self.is_free(block) {
                    let data_start = block + BLOCK_HEADER_SIZE;
                    let mut aligned = (data_start + align - 1) & !(align - 1);
                    let mut padding = aligned - data_start;
                    while padding > 0 && padding < BLOCK_HEADER_SIZE + 16 {
                        aligned += align;
                        padding += align;
                    }
                    let available = self.size(block);
                    if available >= padding + size {
                        return self.carve(block, aligned, padding, available, size, zero);
                    }
                }
                block = following;
            }
        }
        0 // sem memória
    }

    fn carve(&mut self, block_address: u64, aligned: u64, padding: u64, available: u64, size: u64, zero: bool) -> u64 {
        let mut block = block_address;
        let old_next = self.next(block);
        self.remove_free(block);
        if padding >= BLOCK_HEADER_SIZE + 16 {
            let header = aligned - BLOCK_HEADER_SIZE;
            self.write_block(block, padding - BLOCK_HEADER_SIZE, header, true, None);
            self.write_block(header, available - padding, old_next, true, Some(block));
            if old_next != 0 {
                self.set_previous(old_next, header);
            }
            self.insert_free(block);
            block = header;
        }
        let remaining = self.size(block) - size;
        if remaining >= BLOCK_HEADER_SIZE + 16 {
            let next_block = block + BLOCK_HEADER_SIZE + size;
            self.write_block(next_block, remaining - BLOCK_HEADER_SIZE, self.next(block), true, Some(block));
            if old_next != 0 {
                self.set_previous(old_next, next_block);
            }
            self.write_block(block, size, next_block, false, None);
            self.insert_free(next_block);
        } else {
            self.write_block(block, self.size(block), self.next(block), false, None);
        }
        if zero {
            // Arena residente e não paginável: limpa só o payload.
            volatile::zero(block + BLOCK_HEADER_SIZE, size as usize);
        }
        self.allocations.insert(block + BLOCK_HEADER_SIZE);
        block + BLOCK_HEADER_SIZE
    }

    fn free_bytes(&mut self, pointer: u64) {
        if pointer == 0 {
            return;
        }
        assert!(self.allocations.remove(&pointer), "Invalid guest pool free at {pointer:#x}");
        let mut block = pointer - BLOCK_HEADER_SIZE;
        volatile::write32(block + 12, 1);
        let previous = self.previous(block);
        if previous != 0 && self.is_free(previous) {
            self.remove_free(previous);
            let merged = self.size(previous) + BLOCK_HEADER_SIZE + self.size(block);
            self.write_block(previous, merged, self.next(block), true, None);
            if self.next(block) != 0 {
                self.set_previous(self.next(block), previous);
            }
            block = previous;
        }
        let mut next = self.next(block);
        while next != 0 && self.is_free(next) && block + BLOCK_HEADER_SIZE + self.size(block) == next {
            self.remove_free(next);
            let merged = self.size(block) + BLOCK_HEADER_SIZE + self.size(next);
            self.write_block(block, merged, self.next(next), true, None);
            next = self.next(block);
            if next != 0 {
                self.set_previous(next, block);
            }
        }
        self.insert_free(block);
    }

    /// A VA cai dentro da arena (alocada ou não).
    fn contains(&self, address: u64) -> bool {
        self.ready && address >= self.arena_base && address < self.arena_base + ARENA_SIZE
    }
}

fn with_pool_lock<T>(body: impl FnOnce() -> T) -> T {
    let lock = *POOL_LOCK.lock();
    let previous = lock.map(|(acquire, _)| acquire());
    let result = body();
    if let (Some((_, release)), Some(previous)) = (lock, previous) {
        release(previous);
    }
    result
}

/// `size` bytes alinhados a `align`: VA da arena (na janela do heap, acima
/// de MmSystemRangeStart) ou 0. `zero=false` devolve o conteúdo antigo
/// (ExAllocatePoolUninitialized).
pub fn alloc_aligned(size: u64, align: u64, zero: bool) -> u64 {
    with_pool_lock(|| HEAP.lock().allocate_aligned(size, align, zero))
}

pub fn alloc_page() -> u64 {
    alloc_aligned(0x1000, 0x1000, true)
}

pub fn alloc_bytes(size: u64) -> u64 {
    alloc_aligned(size, 16, true)
}

pub fn alloc_raw(size: u64) -> u64 {
    alloc_aligned(size, 16, false)
}

pub fn free_bytes(pointer: u64) {
    with_pool_lock(|| HEAP.lock().free_bytes(pointer))
}

pub fn owns_allocation(pointer: u64) -> bool {
    HEAP.lock().allocations.contains(&pointer)
}

/// A VA cai dentro da arena dos convidados (alocada ou não).
pub fn in_arena(address: u64) -> bool {
    HEAP.lock().contains(address)
}
