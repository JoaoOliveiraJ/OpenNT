//! Arena de memória dos convidados (drivers .sys e structs NT) e acesso a
//! endereços de convidado — `system32/win32/guest-memory.js`.
//!
//! Arena de 16MB reservada do heap do kernel no boot; blocos livres
//! separados por tamanho, com split e coalescência. Header de bloco (16B):
//! +0 size, +4 previous, +8 next, +12 free (u32). Os links das listas livres
//! ocupam os primeiros 8 bytes do payload livre.
//!
//! Abaixo de 4GB tudo é identity (VA == PA). Endereços altos (imagens na
//! base preferida, VA do kernel) passam pelas tabelas de páginas. As
//! variantes `try_*` devolvem `STATUS_ACCESS_VIOLATION` para ponteiros sem
//! mapeamento (o `guestAddressFault` do original); as demais são para memória
//! do próprio kernel e param o sistema numa falha.

use alloc::collections::BTreeSet;
use alloc::format;

use crate::hal::{host, physical};
use crate::ntos::mm::{kernel_address, paging, physical_layout};
use crate::rtl::{KernelError, SpinLock};

pub const ARENA_SIZE: u64 = 0x100_0000; // 16MB
const BLOCK_HEADER_SIZE: u64 = 16;
pub const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const FOUR_GB: u64 = 0x1_0000_0000;

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
    free_bins: [u32; 25],
}

static HEAP: SpinLock<GuestHeap> =
    SpinLock::new(GuestHeap { arena_base: 0, ready: false, allocations: BTreeSet::new(), free_bins: [0; 25] });

/// Falha de tradução conhecida: serviços com SEH devolvem ACCESS_VIOLATION.
pub fn address_fault(address: u64) -> KernelError {
    KernelError::with_status(format!("unmapped guest VA {address:#x}"), STATUS_ACCESS_VIOLATION)
}

pub fn set_pageable_resolver(resolver: Option<PageableResolver>) {
    *PAGEABLE_RESOLVER.lock() = resolver;
}

pub fn set_pool_lock(lock: Option<(fn() -> u64, fn(u64))>) {
    *POOL_LOCK.lock() = lock;
}

/// Tradução VA -> físico do convidado.
pub fn to_physical(address: u64) -> Result<u64, KernelError> {
    let resolver = *PAGEABLE_RESOLVER.lock();
    if let Some(resolver) = resolver {
        if let Some(page) = resolver(address)? {
            return Ok(page);
        }
    }
    if address < FOUR_GB {
        return Ok(address);
    }
    if let Some(mapped) = kernel_address::physical_address(address) {
        return Ok(mapped);
    }
    let page = address & !0xFFF;
    let translated = paging::translate(page);
    if translated == 0 && paging::access_flags(page) & paging::PAGE_PRESENT == 0 {
        return Err(address_fault(address));
    }
    Ok(translated + (address & 0xFFF))
}

fn crosses_page(address: u64, width: u64) -> bool {
    (address & 0xFFF) + width > 4096
}

// ---- leituras -------------------------------------------------------------

pub fn try_read8(address: u64) -> Result<u8, KernelError> {
    let physical_address = to_physical(address)?;
    Ok(physical::read8(if physical_address < FOUR_GB { physical_address } else { address }))
}

fn read_split(address: u64, width: u64) -> Result<u64, KernelError> {
    let mut value = 0u64;
    for index in 0..width {
        value |= (try_read8(address.wrapping_add(index))? as u64) << (index * 8);
    }
    Ok(value)
}

pub fn try_read16(address: u64) -> Result<u16, KernelError> {
    if crosses_page(address, 2) {
        return read_split(address, 2).map(|value| value as u16);
    }
    let physical_address = to_physical(address)?;
    Ok(physical::read16(if physical_address < FOUR_GB { physical_address } else { address }))
}

pub fn try_read32(address: u64) -> Result<u32, KernelError> {
    if crosses_page(address, 4) {
        return read_split(address, 4).map(|value| value as u32);
    }
    let physical_address = to_physical(address)?;
    Ok(physical::read32(if physical_address < FOUR_GB { physical_address } else { address }))
}

/// Duas leituras de DWORD, na ordem original (`readGuest64`/`Exact`).
pub fn try_read64(address: u64) -> Result<u64, KernelError> {
    if crosses_page(address, 8) {
        let low = try_read32(address)? as u64;
        return Ok(low | (try_read32(address.wrapping_add(4))? as u64) << 32);
    }
    let physical_address = to_physical(address)?;
    let at = if physical_address < FOUR_GB { physical_address } else { address };
    Ok(physical::read32(at) as u64 | (physical::read32(at.wrapping_add(4)) as u64) << 32)
}

/// Uma única carga de qword nativa, sem duas observações de DWORD.
pub fn try_read64_single(address: u64) -> Result<u64, KernelError> {
    let physical_address = to_physical(address)?;
    if crosses_page(address, 8) {
        to_physical(address.wrapping_add(7))?;
        return Ok(physical::read64(address));
    }
    Ok(physical::read64(if physical_address < FOUR_GB { physical_address } else { address }))
}

// ---- escritas -------------------------------------------------------------

pub fn try_write8(address: u64, value: u8) -> Result<(), KernelError> {
    let physical_address = to_physical(address)?;
    physical::write8(if physical_address < FOUR_GB { physical_address } else { address }, value);
    Ok(())
}

fn write_split(address: u64, value: u64, width: u64) -> Result<(), KernelError> {
    for index in 0..width {
        try_write8(address.wrapping_add(index), (value >> (index * 8)) as u8)?;
    }
    Ok(())
}

pub fn try_write16(address: u64, value: u16) -> Result<(), KernelError> {
    if crosses_page(address, 2) {
        return write_split(address, value as u64, 2);
    }
    let physical_address = to_physical(address)?;
    physical::write16(if physical_address < FOUR_GB { physical_address } else { address }, value);
    Ok(())
}

pub fn try_write32(address: u64, value: u32) -> Result<(), KernelError> {
    if crosses_page(address, 4) {
        return write_split(address, value as u64, 4);
    }
    let physical_address = to_physical(address)?;
    physical::write32(if physical_address < FOUR_GB { physical_address } else { address }, value);
    Ok(())
}

/// Duas escritas de DWORD na ordem original, inclusive em MMIO.
pub fn try_write64(address: u64, value: u64) -> Result<(), KernelError> {
    let (low, high) = (value as u32, (value >> 32) as u32);
    if crosses_page(address, 8) {
        try_write32(address, low)?;
        return try_write32(address.wrapping_add(4), high);
    }
    let physical_address = to_physical(address)?;
    let at = if physical_address < FOUR_GB { physical_address } else { address };
    physical::write32(at, low);
    physical::write32(at.wrapping_add(4), high);
    Ok(())
}

/// Copia bytes sem presumir continuidade entre páginas virtuais. RAM
/// admitida recebe cópia em bloco; MMIO e reservas conservam a largura e a
/// ordem de cada acesso.
pub fn try_write_bytes(address: u64, bytes: &[u8]) -> Result<(), KernelError> {
    let mut copied = 0usize;
    while copied < bytes.len() {
        let destination = address.wrapping_add(copied as u64);
        let physical_address = to_physical(destination)?;
        let page_offset = (destination & 0xFFF) as usize;
        let block = (4096 - page_offset).min(bytes.len() - copied);
        if physical_address < FOUR_GB && physical_layout::contains_ram_range(physical_address, block as u64) {
            physical::write_bytes(physical_address, &bytes[copied..copied + block]);
        } else {
            for index in 0..block {
                try_write8(destination.wrapping_add(index as u64), bytes[copied + index])?;
            }
        }
        copied += block;
    }
    Ok(())
}

pub fn try_read_bytes(address: u64, length: usize) -> Result<alloc::vec::Vec<u8>, KernelError> {
    (0..length as u64).map(|offset| try_read8(address.wrapping_add(offset))).collect()
}

// ---- variantes infalíveis (memória do kernel) -------------------------------

fn kernel_fault(error: KernelError) -> ! {
    panic!("acesso de kernel a memoria de convidado: {}", error)
}

pub fn read8(address: u64) -> u8 {
    try_read8(address).unwrap_or_else(|error| kernel_fault(error))
}
pub fn read16(address: u64) -> u16 {
    try_read16(address).unwrap_or_else(|error| kernel_fault(error))
}
pub fn read32(address: u64) -> u32 {
    try_read32(address).unwrap_or_else(|error| kernel_fault(error))
}
pub fn read64(address: u64) -> u64 {
    try_read64(address).unwrap_or_else(|error| kernel_fault(error))
}
pub fn read64_single(address: u64) -> u64 {
    try_read64_single(address).unwrap_or_else(|error| kernel_fault(error))
}
pub fn write8(address: u64, value: u8) {
    try_write8(address, value).unwrap_or_else(|error| kernel_fault(error))
}
pub fn write16(address: u64, value: u16) {
    try_write16(address, value).unwrap_or_else(|error| kernel_fault(error))
}
pub fn write32(address: u64, value: u32) {
    try_write32(address, value).unwrap_or_else(|error| kernel_fault(error))
}
pub fn write64(address: u64, value: u64) {
    try_write64(address, value).unwrap_or_else(|error| kernel_fault(error))
}
pub fn write_bytes(address: u64, bytes: &[u8]) {
    try_write_bytes(address, bytes).unwrap_or_else(|error| kernel_fault(error))
}
pub fn read_bytes(address: u64, length: usize) -> alloc::vec::Vec<u8> {
    try_read_bytes(address, length).unwrap_or_else(|error| kernel_fault(error))
}

// ---- operações atômicas ----------------------------------------------------

pub fn compare_exchange32(address: u64, expected: u32, replacement: u32) -> Result<u32, KernelError> {
    let physical_address = to_physical(address)?;
    let at = if physical_address < FOUR_GB { physical_address } else { address };
    Ok(physical::compare_exchange32(at, expected, replacement))
}

pub fn compare_exchange64(address: u64, expected: u64, replacement: u64) -> Result<u64, KernelError> {
    let physical_address = to_physical(address)?;
    let at = if physical_address < FOUR_GB { physical_address } else { address };
    Ok(physical::compare_exchange64(at, expected, replacement))
}

/// Cabeçalho SLIST alinhado: compara as duas palavras numa instrução.
/// Devolve o valor anterior (baixo, alto).
pub fn compare_exchange128(
    address: u64,
    expected: (u64, u64),
    replacement: (u64, u64),
) -> Result<(u64, u64), KernelError> {
    let physical_address = to_physical(address)?;
    let at = if physical_address < FOUR_GB { physical_address } else { address };
    Ok(physical::compare_exchange128(at, expected, replacement))
}

// ---- heap da arena ---------------------------------------------------------

fn block_size(address: u64) -> u32 {
    physical::read32(address)
}
fn block_next(address: u64) -> u32 {
    physical::read32(address + 8)
}
fn block_free(address: u64) -> u32 {
    physical::read32(address + 12)
}

fn write_block(address: u64, size: u32, next: u32, free: u32, previous: Option<u32>) {
    physical::write32(address, size);
    if let Some(previous) = previous {
        physical::write32(address + 4, previous);
    }
    physical::write32(address + 8, next);
    physical::write32(address + 12, free);
}

fn free_bin(size: u32) -> usize {
    (31 - size.leading_zeros()) as usize
}

impl GuestHeap {
    fn insert_free(&mut self, block: u32) {
        let bin = free_bin(block_size(block as u64));
        let next = self.free_bins[bin];
        physical::write32(block as u64 + 16, next);
        physical::write32(block as u64 + 20, 0);
        if next != 0 {
            physical::write32(next as u64 + 20, block);
        }
        self.free_bins[bin] = block;
    }

    fn remove_free(&mut self, block: u32) {
        let next = physical::read32(block as u64 + 16);
        let previous = physical::read32(block as u64 + 20);
        if previous != 0 {
            physical::write32(previous as u64 + 16, next);
        } else {
            self.free_bins[free_bin(block_size(block as u64))] = next;
        }
        if next != 0 {
            physical::write32(next as u64 + 20, previous);
        }
    }

    fn init(&mut self) {
        self.arena_base = host::guest_arena();
        write_block(self.arena_base, (ARENA_SIZE - BLOCK_HEADER_SIZE) as u32, 0, 1, Some(0));
        self.insert_free(self.arena_base as u32);
        self.ready = true;
    }

    fn allocate_aligned(&mut self, size: u64, align: u64, zero: bool) -> u64 {
        if size == 0 || size > ARENA_SIZE - BLOCK_HEADER_SIZE {
            return 0;
        }
        let size = size.div_ceil(16) * 16;
        if !self.ready {
            self.init();
        }
        for bin in free_bin(size as u32)..self.free_bins.len() {
            let mut block = self.free_bins[bin];
            while block != 0 {
                let block_address = block as u64;
                let next = block_next(block_address) as u64;
                let corrupt = block_address < self.arena_base
                    || block_address + 16 > self.arena_base + ARENA_SIZE
                    || (next != 0 && (next != block_address + 16 + block_size(block_address) as u64 || next <= block_address));
                assert!(!corrupt, "Guest heap header corrupt at {block_address:#x}, next={next:#x}");
                let following = physical::read32(block_address + 16);
                if block_free(block_address) != 0 {
                    let data_start = block_address + BLOCK_HEADER_SIZE;
                    let mut aligned = (data_start + align - 1) & !(align - 1);
                    let mut padding = aligned - data_start;
                    while padding > 0 && padding < BLOCK_HEADER_SIZE + 16 {
                        aligned += align;
                        padding += align;
                    }
                    let available = block_size(block_address) as u64;
                    if available >= padding + size {
                        return self.carve(block_address, aligned, padding, available, size, zero);
                    }
                }
                block = following;
            }
        }
        0 // sem memória
    }

    fn carve(&mut self, block_address: u64, aligned: u64, padding: u64, available: u64, size: u64, zero: bool) -> u64 {
        let mut block = block_address;
        let old_next = block_next(block);
        self.remove_free(block as u32);
        if padding >= BLOCK_HEADER_SIZE + 16 {
            let header = aligned - BLOCK_HEADER_SIZE;
            write_block(block, (padding - BLOCK_HEADER_SIZE) as u32, header as u32, 1, None);
            write_block(header, (available - padding) as u32, old_next, 1, Some(block as u32));
            if old_next != 0 {
                physical::write32(old_next as u64 + 4, header as u32);
            }
            self.insert_free(block as u32);
            block = header;
        }
        let remaining = block_size(block) as u64 - size;
        if remaining >= BLOCK_HEADER_SIZE + 16 {
            let next_block = block + BLOCK_HEADER_SIZE + size;
            write_block(next_block, (remaining - BLOCK_HEADER_SIZE) as u32, block_next(block), 1, Some(block as u32));
            if old_next != 0 {
                physical::write32(old_next as u64 + 4, next_block as u32);
            }
            write_block(block, size as u32, next_block as u32, 0, None);
            self.insert_free(next_block as u32);
        } else {
            write_block(block, block_size(block), block_next(block), 0, None);
        }
        if zero {
            // Arena física contígua e não paginável: limpa só o payload.
            physical::zero(block + BLOCK_HEADER_SIZE, size as usize);
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
        physical::write32(block + 12, 1);
        let previous = physical::read32(block + 4) as u64;
        if previous != 0 && block_free(previous) != 0 {
            self.remove_free(previous as u32);
            let merged = block_size(previous) + BLOCK_HEADER_SIZE as u32 + block_size(block);
            write_block(previous, merged, block_next(block), 1, None);
            if block_next(block) != 0 {
                physical::write32(block_next(block) as u64 + 4, previous as u32);
            }
            block = previous;
        }
        let mut next = block_next(block) as u64;
        while next != 0 && block_free(next) != 0 && block + BLOCK_HEADER_SIZE + block_size(block) as u64 == next {
            self.remove_free(next as u32);
            let merged = block_size(block) + BLOCK_HEADER_SIZE as u32 + block_size(next);
            write_block(block, merged, block_next(next), 1, None);
            next = block_next(block) as u64;
            if next != 0 {
                physical::write32(next + 4, block as u32);
            }
        }
        self.insert_free(block as u32);
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

/// `size` bytes alinhados a `align`; endereço físico ou 0. `zero=false`
/// devolve o conteúdo antigo (ExAllocatePoolUninitialized).
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
