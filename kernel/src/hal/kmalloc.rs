//! Heap do kernel.
//!
//! Blocos livres agrupados por tamanho sobre a RAM detectada pelo E820.
//! Heap exclusivo de 32 MB até 96 MB, conforme `ntos/mm/memory_map`; os
//! frames do PFN começam em 96 MB. Também é o `#[global_allocator]` do Rust.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{self, null_mut};

use crate::rtl::SpinLock;

const HEAP_START: u64 = 0x200_0000; // 32 MB (acima de imagens PE + drivers)
const HEAP_END: u64 = 0x600_0000; // 96 MB: início dos frames PFN
const RAM_CAP: u64 = 0x1_0000_0000; // cap de 4 GB (o identity map cobre 4 GB)
const E820_COUNT_ADDRESS: u64 = 0x4FF0;
const E820_TABLE_ADDRESS: u64 = 0x5000;

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct E820Entry {
    base: u64,
    length: u64,
    kind: u32,
    acpi: u32,
}

fn e820_count() -> usize {
    unsafe { ptr::read_volatile(E820_COUNT_ADDRESS as *const u16) as usize }
}

fn e820_entry(index: usize) -> E820Entry {
    unsafe { ptr::read_unaligned((E820_TABLE_ADDRESS as *const E820Entry).add(index)) }
}

#[repr(C)]
struct Block {
    size: usize,            // bytes de dados (sem o header)
    next: *mut Block,       // vizinho físico; a busca não percorre blocos ocupados
    free: i32,
    bin: i32,               // classe em que o bloco livre está inserido
    previous: *mut Block,
}

const HDR_SIZE: usize = 32;
const _: () = assert!(core::mem::size_of::<Block>() <= HDR_SIZE);

/// Links só ocupam o payload de blocos livres. O header e a capacidade do
/// heap não crescem; alocações de até 1 KiB têm classes exatas de 16 bytes.
#[repr(C)]
struct FreeLinks {
    next: *mut Block,
    previous: *mut Block,
}

const HEAP_SMALL_BINS: usize = 64;
const HEAP_BIN_COUNT: usize = 118;

struct Heap {
    free_bins: [*mut Block; HEAP_BIN_COUNT],
    free_list: *mut Block,
    total: usize,
    used: usize,
    ram_top: u64,
}

// Os ponteiros só são tocados com o lock do heap adquirido.
unsafe impl Send for Heap {}

static HEAP: SpinLock<Heap> = SpinLock::new(Heap {
    free_bins: [null_mut(); HEAP_BIN_COUNT],
    free_list: null_mut(),
    total: 0,
    used: 0,
    ram_top: 0,
});

fn bin_index(size: usize) -> usize {
    if size <= HEAP_SMALL_BINS * 16 {
        return size / 16 - 1;
    }
    HEAP_SMALL_BINS + (63 - size.leading_zeros() as usize) - 10
}

unsafe fn free_links(block: *mut Block) -> *mut FreeLinks {
    (block as *mut u8).add(HDR_SIZE) as *mut FreeLinks
}

impl Heap {
    unsafe fn insert_free(&mut self, block: *mut Block) {
        let index = bin_index((*block).size);
        let links = free_links(block);
        (*block).bin = index as i32;
        (*links).previous = null_mut();
        (*links).next = self.free_bins[index];
        if !(*links).next.is_null() {
            (*free_links((*links).next)).previous = block;
        }
        self.free_bins[index] = block;
    }

    unsafe fn remove_free(&mut self, block: *mut Block) {
        let links = free_links(block);
        if !(*links).previous.is_null() {
            (*free_links((*links).previous)).next = (*links).next;
        } else {
            self.free_bins[(*block).bin as usize] = (*links).next;
        }
        if !(*links).next.is_null() {
            (*free_links((*links).next)).previous = (*links).previous;
        }
    }

    fn detect_ram(&mut self) {
        let count = e820_count();
        self.ram_top = 0;
        for index in 0..count.min(64) {
            let entry = e820_entry(index);
            let (kind, length, base) = (entry.kind, entry.length, entry.base);
            if kind == 1 && length != 0 {
                let top = base.wrapping_add(length);
                if top > self.ram_top {
                    self.ram_top = top;
                }
            }
        }
        if self.ram_top == 0 || self.ram_top > RAM_CAP {
            self.ram_top = RAM_CAP;
        }
    }

    unsafe fn init(&mut self) {
        self.detect_ram();
        let count = e820_count();
        let mut heap_end = HEAP_START;
        // Somente o descritor utilizável que contém HEAP_START pode sustentar o heap.
        for index in 0..count.min(170) {
            let entry = e820_entry(index);
            let (base, length, kind, acpi) = (entry.base, entry.length, entry.kind, entry.acpi);
            let top = base.wrapping_add(length);
            if acpi & 1 == 0 || top < base {
                continue;
            }
            if kind == 1 && base <= HEAP_START && top > heap_end {
                heap_end = top.min(HEAP_END);
            }
        }
        // Sobreposições reservadas vencem, inclusive no início do heap.
        for index in 0..count.min(170) {
            let entry = e820_entry(index);
            let (base, length, kind, acpi) = (entry.base, entry.length, entry.kind, entry.acpi);
            let top = base.wrapping_add(length);
            if acpi & 1 == 0 || kind == 1 || length == 0 || top < base || top <= HEAP_START {
                continue;
            }
            if base < heap_end {
                heap_end = base.max(HEAP_START);
            }
        }
        heap_end &= !15;
        self.total = 0;
        self.used = 0;
        self.free_list = null_mut();
        self.free_bins = [null_mut(); HEAP_BIN_COUNT];
        if heap_end < HEAP_START + HDR_SIZE as u64 + 16 {
            return;
        }
        let first = HEAP_START as *mut Block;
        (*first).size = (heap_end - HEAP_START) as usize - HDR_SIZE;
        (*first).next = null_mut();
        (*first).previous = null_mut();
        (*first).free = 1;
        self.free_list = first;
        self.insert_free(first);
        self.total = (*first).size;
        self.used = 0;
    }

    unsafe fn allocate(&mut self, size: usize) -> *mut u8 {
        if size > usize::MAX - 15 {
            return null_mut();
        }
        let mut size = (size + 15) & !15;
        if size == 0 {
            size = 16;
        }
        for index in bin_index(size)..HEAP_BIN_COUNT {
            let mut block = self.free_bins[index];
            while !block.is_null() && (*block).size < size {
                block = (*free_links(block)).next;
            }
            if block.is_null() {
                continue;
            }
            self.remove_free(block);
            if (*block).size >= size + HDR_SIZE + 16 {
                let split = (block as *mut u8).add(HDR_SIZE + size) as *mut Block;
                (*split).size = (*block).size - size - HDR_SIZE;
                (*split).next = (*block).next;
                (*split).previous = block;
                if !(*split).next.is_null() {
                    (*(*split).next).previous = split;
                }
                (*split).free = 1;
                (*block).size = size;
                (*block).next = split;
                self.insert_free(split);
            }
            (*block).free = 0;
            self.used += (*block).size;
            return (block as *mut u8).add(HDR_SIZE);
        }
        null_mut()
    }

    unsafe fn release(&mut self, pointer: *mut u8) {
        if pointer.is_null() {
            return;
        }
        let mut block = pointer.sub(HDR_SIZE) as *mut Block;
        self.used -= (*block).size;
        (*block).free = 1;
        // Os dois vizinhos são conhecidos. Coalescer ao liberar evita a
        // fragmentação dependente da ordem e não move dados vivos.
        let left = (*block).previous;
        if !left.is_null() && (*left).free != 0 {
            self.remove_free(left);
            (*left).size += HDR_SIZE + (*block).size;
            (*left).next = (*block).next;
            if !(*left).next.is_null() {
                (*(*left).next).previous = left;
            }
            block = left;
        }
        let right = (*block).next;
        if !right.is_null()
            && (*right).free != 0
            && (block as *mut u8).add(HDR_SIZE + (*block).size) == right as *mut u8
        {
            self.remove_free(right);
            (*block).size += HDR_SIZE + (*right).size;
            (*block).next = (*right).next;
            if !(*block).next.is_null() {
                (*(*block).next).previous = block;
            }
        }
        self.insert_free(block);
    }

    /// Diagnóstico somente leitura; nunca aloca com o heap cheio.
    unsafe fn free_info(&self) -> (usize, usize, usize) {
        let (mut bytes, mut maximum, mut joined, mut run) = (0usize, 0usize, 0usize, 0usize);
        let mut run_end: *const u8 = ptr::null();
        let mut block = self.free_list as *const Block;
        while !block.is_null() {
            if (*block).free == 0 {
                run = 0;
                run_end = ptr::null();
                block = (*block).next;
                continue;
            }
            bytes += (*block).size;
            maximum = maximum.max((*block).size);
            run = if run_end == block as *const u8 { run + HDR_SIZE } else { 0 } + (*block).size;
            joined = joined.max(run);
            run_end = (block as *const u8).add(HDR_SIZE + (*block).size);
            block = (*block).next;
        }
        (bytes, maximum, joined)
    }
}

pub fn init() {
    unsafe { HEAP.lock().init() }
}

/// `kmalloc`: bloco alinhado a 16 bytes ou nulo.
pub fn kmalloc(size: usize) -> *mut u8 {
    unsafe { HEAP.lock().allocate(size) }
}

/// `kfree`.
pub fn kfree(pointer: *mut u8) {
    unsafe { HEAP.lock().release(pointer) }
}

/// Ocupação do heap: (total, usado).
pub fn info() -> (usize, usize) {
    let heap = HEAP.lock();
    (heap.total, heap.used)
}

/// Topo da RAM utilizável (limitado a 4 GB).
pub fn ram_top() -> u64 {
    HEAP.lock().ram_top
}

fn report_failure(requested: usize) {
    let heap = HEAP.lock();
    let (available, largest, coalescible) = unsafe { heap.free_info() };
    crate::rtl::print::debug_print_args(format_args!(
        "[kernel-heap-failure] requested={:#x} used={:#x} total={:#x} free={:#x} largest={:#x} coalescible={:#x}",
        requested, heap.used, heap.total, available, largest, coalescible
    ));
}

/// Alocador global do Rust sobre o kmalloc. Alinhamentos maiores que 16
/// reservam folga e guardam o ponteiro original logo antes do bloco.
pub struct KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = if layout.align() <= 16 {
            kmalloc(layout.size())
        } else {
            let raw = kmalloc(layout.size() + layout.align() + 16);
            if raw.is_null() {
                null_mut()
            } else {
                let aligned = (raw as usize + 16 + layout.align() - 1) & !(layout.align() - 1);
                ((aligned - 8) as *mut usize).write(raw as usize);
                aligned as *mut u8
            }
        };
        if pointer.is_null() {
            report_failure(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if layout.align() <= 16 {
            kfree(pointer)
        } else {
            kfree(((pointer as usize - 8) as *const usize).read() as *mut u8)
        }
    }
}

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;
