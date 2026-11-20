//! Heap do kernel.
//!
//! Blocos livres agrupados por tamanho sobre a RAM detectada pelo E820.
//! Heap exclusivo nos frames de 32 MB até 96 MB, conforme `ntos/mm/memory_map`;
//! os frames do PFN começam em 96 MB. Também é o `#[global_allocator]` do Rust.
//!
//! Cada bloco ocupado guarda o local que o pediu (`heap_census`): o censo
//! dos bytes vivos por local vai para a serial na falha e, com a opção
//! HEAPCENSUS, a cada 4 MB a mais de uso.
//!
//! Os frames do heap são endereçados só pela janela do heap na metade de
//! sistema (`KERNEL_HEAP_BASE + PA - KERNEL_HEAP_PHYS_BASE`), montada por
//! `init` antes do primeiro bloco: cabeçalhos, listas livres e os ponteiros
//! entregues aos chamadores são VAs dessa janela, todas >= MmSystemRangeStart.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{self, null_mut};

use super::heap_census::{self, Chain};
use super::physical;
use crate::ntos::mm::memory_map as map;
use crate::ntos::mm::paging;
use crate::rtl::SpinLock;

const HEAP_START: u64 = map::KERNEL_HEAP_PHYS_BASE; // 32 MB
const HEAP_END: u64 = map::KERNEL_HEAP_PHYS_TOP; // 96 MB: início dos frames PFN
const RAM_CAP: u64 = map::PHYSICAL_MEMORY_LIMIT; // cap de 4 GB (o mapa direto cobre 4 GB)

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct E820Entry {
    base: u64,
    length: u64,
    kind: u32,
    acpi: u32,
}

fn e820_count() -> usize {
    physical::read16(map::E820_COUNT_PHYS) as usize
}

fn e820_entry(index: usize) -> E820Entry {
    let at = map::E820_TABLE_PHYS + index as u64 * core::mem::size_of::<E820Entry>() as u64;
    E820Entry { base: physical::read64(at), length: physical::read64(at + 8), kind: physical::read32(at + 16), acpi: physical::read32(at + 20) }
}

#[repr(C)]
struct Block {
    size: usize,            // bytes de dados (sem o header)
    next: *mut Block,       // vizinho físico; a busca não percorre blocos ocupados
    free: u16,
    bin: u16,               // classe em que o bloco livre está inserido
    site: u32,              // local do bloco ocupado no censo (`heap_census`)
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
    /// Blocos ocupados (cada um com o cabeçalho de HDR_SIZE bytes, que
    /// `used` não conta).
    blocks: usize,
    ram_top: u64,
    /// Próximo uso que imprime o censo (opção HEAPCENSUS); 0 sem a opção.
    next_census: usize,
}

// Os ponteiros só são tocados com o lock do heap adquirido.
unsafe impl Send for Heap {}

static HEAP: SpinLock<Heap> = SpinLock::new(Heap {
    free_bins: [null_mut(); HEAP_BIN_COUNT],
    free_list: null_mut(),
    total: 0,
    used: 0,
    blocks: 0,
    ram_top: 0,
    next_census: 0,
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
        (*block).bin = index as u16;
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

    /// A faixa física [base, top) está inteira num descritor utilizável do
    /// E820 e nenhum descritor reservado a toca.
    fn usable_range(base: u64, top: u64) -> bool {
        let count = e820_count().min(map::E820_MAX_ENTRIES as usize);
        let mut inside = false;
        for index in 0..count {
            let entry = e820_entry(index);
            let (start, length, kind, acpi) = (entry.base, entry.length, entry.kind, entry.acpi);
            let end = start.wrapping_add(length);
            if acpi & 1 == 0 || length == 0 || end < start {
                continue;
            }
            if kind == 1 {
                inside |= start <= base && end >= top;
            } else if start < top && end > base {
                return false;
            }
        }
        inside
    }

    unsafe fn init(&mut self) {
        self.detect_ram();
        heap_census::init(Self::usable_range(map::KERNEL_HEAP_CENSUS_PHYS, map::KERNEL_HEAP_CENSUS_PHYS + map::KERNEL_HEAP_CENSUS_SIZE));
        self.next_census = if crate::ntos::init::boot_config::heap_census() { heap_census::WATERMARK_STEP } else { 0 };
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
        self.blocks = 0;
        self.free_list = null_mut();
        self.free_bins = [null_mut(); HEAP_BIN_COUNT];
        if heap_end < HEAP_START + HDR_SIZE as u64 + 16 {
            return;
        }
        let first = map::kernel_heap_virtual(HEAP_START) as *mut Block;
        (*first).size = (heap_end - HEAP_START) as usize - HDR_SIZE;
        (*first).next = null_mut();
        (*first).previous = null_mut();
        (*first).free = 1;
        (*first).site = 0;
        self.free_list = first;
        self.insert_free(first);
        self.total = (*first).size;
        self.used = 0;
    }

    unsafe fn allocate(&mut self, size: usize, chain: &Chain) -> *mut u8 {
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
                (*split).site = 0;
                (*block).size = size;
                (*block).next = split;
                self.insert_free(split);
            }
            (*block).free = 0;
            (*block).site = heap_census::record(chain, (*block).size);
            self.used += (*block).size;
            self.blocks += 1;
            if self.next_census != 0 && self.used >= self.next_census {
                self.next_census = (self.used / heap_census::WATERMARK_STEP + 1) * heap_census::WATERMARK_STEP;
                heap_census::print("marca de uso", self.used, self.total, 25, 0x1_0000);
            }
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
        self.blocks -= 1;
        heap_census::forget((*block).site, (*block).size);
        (*block).site = 0;
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

/// Monta a janela do heap e o bloco livre inicial.
pub fn init() {
    paging::map_kernel_heap_window();
    unsafe { HEAP.lock().init() }
}

/// `kmalloc`: bloco alinhado a 16 bytes (VA da janela do heap) ou nulo.
pub fn kmalloc(size: usize) -> *mut u8 {
    let chain = heap_census::capture();
    unsafe { HEAP.lock().allocate(size, &chain) }
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

/// O heap ocupado com os cabeçalhos: os bytes dos blocos vivos mais
/// HDR_SIZE por bloco (o que `info` conta como usado deixa os cabeçalhos
/// de fora).
pub fn occupied() -> usize {
    let heap = HEAP.lock();
    heap.used + heap.blocks * HDR_SIZE
}

/// Topo da RAM utilizável (limitado a 4 GB).
pub fn ram_top() -> u64 {
    HEAP.lock().ram_top
}

/// O local do censo do bloco vivo `pointer` (um ponteiro devolvido por este
/// heap com alinhamento de até 16 bytes).
pub fn census_of(pointer: *const u8) -> Option<heap_census::Entry> {
    let _heap = HEAP.lock();
    // SAFETY: o cabeçalho fica logo antes do bloco vivo; lido com o lock.
    let site = unsafe { (*(pointer.sub(HDR_SIZE) as *const Block)).site };
    heap_census::entry(site)
}

/// O local `index` do censo, lido com o lock do heap.
pub fn census_entry(index: u32) -> Option<heap_census::Entry> {
    let _heap = HEAP.lock();
    heap_census::entry(index)
}

/// O censo do heap na serial agora (os maiores locais vivos), com o motivo.
pub fn print_census(reason: &str) {
    let heap = HEAP.lock();
    heap_census::print(reason, heap.used, heap.total, 60, 0x4000);
}

fn report_failure(requested: usize) {
    let heap = HEAP.lock();
    let (available, largest, coalescible) = unsafe { heap.free_info() };
    crate::rtl::print::debug_print_args(format_args!(
        "[kernel-heap-failure] requested={:#x} used={:#x} total={:#x} free={:#x} largest={:#x} coalescible={:#x}",
        requested, heap.used, heap.total, available, largest, coalescible
    ));
    heap_census::print("falha do heap", heap.used, heap.total, 200, 0x4000);
}

/// Alocador global do Rust sobre o kmalloc. Alinhamentos maiores que 16
/// reservam folga e guardam o ponteiro original logo antes do bloco.
pub struct KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let chain = heap_census::capture();
        let pointer = if layout.align() <= 16 {
            HEAP.lock().allocate(layout.size(), &chain)
        } else {
            let raw = HEAP.lock().allocate(layout.size() + layout.align() + 16, &chain);
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
