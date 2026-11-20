//! MDLs do Mm (o `iosup` do NT): sondar e travar as páginas de um buffer,
//! descrever pool não paginado, mapear as páginas travadas no espaço do
//! sistema (por identidade ou numa VA reservada por MmAllocateMappingAddress)
//! e alocar/devolver páginas físicas descritas por um MDL.
//!
//! O MDL é o `_MDL` do NT; o vetor de PFNs logo depois do cabeçalho guarda
//! os frames reais das tabelas de página.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::{io_pins, memory_map, paging, pfn};
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::Mdl;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

/// MdlFlags.
const MDL_MAPPED_TO_SYSTEM_VA: i16 = 0x0001;
const MDL_PAGES_LOCKED: i16 = 0x0002;
const MDL_SOURCE_IS_NONPAGED_POOL: i16 = 0x0004;
const MDL_PARTIAL: i16 = 0x0010;
const MDL_PARTIAL_HAS_BEEN_MAPPED: i16 = 0x0020;
const MDL_WRITE_OPERATION: i16 = 0x0080;

fn mdl(descriptor: u64) -> &'static Mdl {
    // SAFETY: os exports recebem um PMDL válido do driver, como no NT.
    unsafe { Mdl::at(descriptor) }
}

/// O vetor de PFNs logo depois do cabeçalho (MmGetMdlPfnArray).
fn pfn_array(mdl: &Mdl, count: u64) -> &'static [Field<u64>] {
    // SAFETY: o MDL foi dimensionado para `count` PFNs (Size).
    unsafe { Field::<u64>::array_at(mdl.address() + Mdl::SIZE, count as usize) }
}

/// Regiões reservadas por MmAllocateMappingAddress: tamanho e tag.
static RESERVED_MAPPINGS: SpinLock<BTreeMap<u64, (u64, u32)>> = SpinLock::new(BTreeMap::new());

/// Preenche o PFN array do MDL andando as tabelas de página (um PFN por
/// página coberta pelo buffer).
fn fill_pfn_array(descriptor: &Mdl) {
    let first = descriptor.start_va.get() + descriptor.byte_offset.get() as u64;
    let count = descriptor.byte_count.get() as u64;
    let pages = ((first & 0xFFF) + count).div_ceil(0x1000);
    for (index, entry) in pfn_array(descriptor, pages).iter().enumerate() {
        let physical = paging::translate((first & !0xFFF) + index as u64 * 0x1000);
        entry.set(physical / 0x1000);
    }
}

/// MdlFlags pertence ao dono do MDL (como o `Mdl->MdlFlags |= ...` do NT).
fn set_flags(descriptor: &Mdl, set: i16, clear: i16) {
    descriptor.mdl_flags.set((descriptor.mdl_flags.get() | set) & !clear);
}

/// MmGetSystemAddressForMdlSafe: a VA de sistema gravada no MDL.
pub fn system_address(descriptor: u64) -> u64 {
    mdl(descriptor).mapped_system_va.get()
}

/// MmMapLockedPagesSpecifyCache(Mdl, AccessMode, CacheType, RequestedAddress).
///
/// Em KernelMode, as páginas travadas de um buffer de usuário ganham VAs de
/// sistema (`system_ptes`, o MiReserveSystemPtes do NT) sobre os PFNs do
/// MDL: a VA de usuário só vale no processo dono, e um driver que completa o
/// pedido no contexto de outro processo grava pela VA de sistema. Um buffer
/// de kernel (pool, pilha de kernel) já está no espaço de sistema e é
/// devolvido como está (StartVa + ByteOffset). Em UserMode, a VA de usuário
/// do buffer (ou a pedida) no processo corrente.
pub fn map_locked_pages(descriptor: u64, access_mode: u8, requested_address: u64) -> u64 {
    let descriptor = mdl(descriptor);
    let flags = descriptor.mdl_flags.get();
    if access_mode == 0 && flags & MDL_MAPPED_TO_SYSTEM_VA != 0 && super::system_ptes::contains(descriptor.mapped_system_va.get()) {
        return descriptor.mapped_system_va.get();
    }
    let mapped = if access_mode == 0 && flags & MDL_SOURCE_IS_NONPAGED_POOL == 0 && user_buffer(descriptor) {
        let (_, pages) = covered_pages(descriptor);
        let frames: Vec<u64> = pfn_array(descriptor, pages).iter().map(|entry| entry.get() * 0x1000).collect();
        let base = super::system_ptes::map_frames(&frames, 0);
        if base == 0 {
            return 0;
        }
        // Um MDL parcial com mapeamento próprio (não o herdado da origem).
        if flags & MDL_PARTIAL != 0 {
            set_flags(descriptor, MDL_PARTIAL_HAS_BEEN_MAPPED, 0);
        }
        base + descriptor.byte_offset.get() as u64
    } else if access_mode != 0 && requested_address != 0 {
        requested_address
    } else {
        descriptor.start_va.get() + descriptor.byte_offset.get() as u64
    };
    if access_mode == 0 {
        descriptor.mapped_system_va.set(mapped);
        set_flags(descriptor, MDL_MAPPED_TO_SYSTEM_VA, 0);
    }
    mapped
}

/// MmUnmapLockedPages: as PTEs de sistema de um mapeamento em KernelMode
/// voltam à janela. Um MDL parcial que herdou a VA da origem
/// (IoBuildPartialMdl) não solta as PTEs dela.
pub fn unmap_locked_pages(descriptor: u64) {
    let header = mdl(descriptor);
    let flags = header.mdl_flags.get();
    let inherited = flags & MDL_PARTIAL != 0 && flags & MDL_PARTIAL_HAS_BEEN_MAPPED == 0;
    if flags & MDL_MAPPED_TO_SYSTEM_VA != 0 && !inherited && super::system_ptes::contains(header.mapped_system_va.get()) {
        super::system_ptes::unmap(header.mapped_system_va.get());
    }
    set_flags(header, 0, MDL_MAPPED_TO_SYSTEM_VA | MDL_PARTIAL_HAS_BEEN_MAPPED);
}

/// As páginas cobertas pelo buffer do MDL: (primeira VA, quantidade).
fn covered_pages(descriptor: &Mdl) -> (u64, u64) {
    let first = descriptor.start_va.get() + descriptor.byte_offset.get() as u64;
    let count = descriptor.byte_count.get() as u64;
    (first & !0xFFF, ((first & 0xFFF) + count).div_ceil(0x1000))
}

/// O buffer do MDL é de usuário (páginas pagináveis).
fn user_buffer(descriptor: &Mdl) -> bool {
    descriptor.start_va.get() < memory_map::USER_ADDRESS_LIMIT
}

/// As retenções de residência das páginas de kernel travadas pelo
/// MmProbeAndLockPages, por MDL, até o MmUnlockPages.
static KERNEL_PINS: SpinLock<BTreeMap<u64, io_pins::Pin>> = SpinLock::new(BTreeMap::new());

/// IoReadAccess: a única operação do MmProbeAndLockPages que não escreve.
const IO_READ_ACCESS: u32 = 0;

/// MmProbeAndLockPages(Mdl, AccessMode, Operation). Como o
/// MiProbeAndLockPrepare (rva 0x20A39B), a operação de escrita (qualquer uma
/// além de IoReadAccess) liga MDL_WRITE_OPERATION e a de leitura a desliga;
/// o MDL de um buffer de usuário guarda o processo cujo espaço foi sondado
/// (rva 0x20A3CB: ApcState.Process, o anexado durante um
/// KeStackAttachProcess) e o de sistema fica com Process nulo: o BasicRender
/// (WARPKMALLOCATION::Map) anexa ao Process do MDL para travar de novo a
/// vista de usuário de uma alocação. Num buffer de usuário as páginas voltam
/// ao working set pela sonda e os frames ficam travados contra o corte do
/// working set até o MmUnlockPages. Num endereço de sistema, como no 19041,
/// cada página é trazida pela falta (o provedor de residência dono: vistas
/// de sistema, imagens e pool paginável) e retida contra a expulsão até o
/// MmUnlockPages (o cdd trava assim a vista de sessão da seção que desenha).
/// O vetor de PFNs recebe os frames reais.
pub fn probe_and_lock_pages(descriptor: u64, operation: u32) {
    let address = descriptor;
    let descriptor = mdl(descriptor);
    if operation != IO_READ_ACCESS {
        set_flags(descriptor, MDL_WRITE_OPERATION, 0);
    } else {
        set_flags(descriptor, 0, MDL_WRITE_OPERATION);
    }
    let user = user_buffer(descriptor);
    descriptor.process.set(if user { crate::ntos::ps::process::get_current_process() } else { 0 });
    let (first, pages) = covered_pages(descriptor);
    if user {
        for page in 0..pages {
            let _ = guest::try_read::<u8>(first + page * 0x1000);
        }
        fill_pfn_array(descriptor);
        for entry in pfn_array(descriptor, pages) {
            super::working_set::lock_frame(entry.get() * 0x1000);
        }
    } else {
        match io_pins::pin(first, pages * 0x1000, operation != IO_READ_ACCESS) {
            Ok(pin) => {
                for (entry, page) in pfn_array(descriptor, pages).iter().zip(pin.pages.iter()) {
                    entry.set(page.frame / 0x1000);
                }
                if let Some(mut previous) = KERNEL_PINS.lock().insert(address, pin) {
                    let _ = previous.release();
                }
            }
            Err(error) => {
                // O NT levanta a exceção da sonda; sem SEH de kernel, os PFNs
                // saem das PTEs como estão.
                debug_print!("[mm] MmProbeAndLockPages {:#x} ({:#x} paginas, operacao {}): {}", first, pages, operation, error);
                fill_pfn_array(descriptor);
            }
        }
    }
    set_flags(descriptor, MDL_PAGES_LOCKED, 0);
}

/// MmProbeAndLockSelectedPages(Mdl, SegmentArray, AccessMode, Operation):
/// o MDL de um buffer de usuário espalhado em páginas inteiras (o
/// FILE_SEGMENT_ELEMENT do NtReadFileScatter/NtWriteFileGather), com
/// StartVa = a primeira página. Cada página da lista volta ao working set
/// pela sonda, o vetor de PFNs recebe o frame dela na ordem da lista e o
/// frame fica travado até o MmUnlockPages, como numa sonda contígua; o MDL
/// guarda o processo sondado. Quem chama já conferiu as páginas.
pub fn probe_and_lock_selected_pages(descriptor: u64, segments: &[u64], operation: u32) {
    let descriptor = mdl(descriptor);
    if operation != IO_READ_ACCESS {
        set_flags(descriptor, MDL_WRITE_OPERATION, 0);
    } else {
        set_flags(descriptor, 0, MDL_WRITE_OPERATION);
    }
    descriptor.process.set(crate::ntos::ps::process::get_current_process());
    let (_, pages) = covered_pages(descriptor);
    for (entry, &page) in pfn_array(descriptor, pages).iter().zip(segments.iter()) {
        let page = page & !0xFFF;
        let _ = guest::try_read::<u8>(page);
        let frame = paging::translate(page) / 0x1000;
        entry.set(frame);
        super::working_set::lock_frame(frame * 0x1000);
    }
    set_flags(descriptor, MDL_PAGES_LOCKED, 0);
}

/// MmUnlockPages: como no NT, um mapeamento de sistema do MDL sai antes.
pub fn unlock_pages(descriptor: u64) {
    if mdl(descriptor).mdl_flags.get() & MDL_MAPPED_TO_SYSTEM_VA != 0 && super::system_ptes::contains(mdl(descriptor).mapped_system_va.get()) {
        unmap_locked_pages(descriptor);
    }
    let address = descriptor;
    let descriptor = mdl(descriptor);
    if descriptor.mdl_flags.get() & MDL_PAGES_LOCKED != 0 {
        if user_buffer(descriptor) {
            let (_, pages) = covered_pages(descriptor);
            for entry in pfn_array(descriptor, pages) {
                super::working_set::unlock_frame(entry.get() * 0x1000);
            }
        } else if let Some(mut pin) = KERNEL_PINS.lock().remove(&address) {
            let _ = pin.release();
        }
    }
    set_flags(descriptor, 0, MDL_PAGES_LOCKED);
}

// ---- MmAdvanceMdl ------------------------------------------------------------
//
// Como no ntoskrnl 19041 (rva 0x531010): NumberOfBytes a partir de
// ByteCount é STATUS_INVALID_PARAMETER_2. O início do MDL anda: dentro da
// primeira página só ByteOffset/ByteCount (e MappedSystemVa, se mapeado)
// mudam; cruzando páginas, StartVa avança as páginas inteiras e o vetor de
// PFNs gira uma posição por página consumida — o PFN que sai vai para o fim,
// marcado no bit 63, e o MDL ganha MDL_FREE_EXTRA_PTES (0x200); num MDL já
// avançado, as entradas extras até a marcada também giram. Assim as páginas
// consumidas continuam no vetor para o MmUnlockPages.

const MDL_FREE_EXTRA_PTES: i16 = 0x0200;
const PFN_EXTRA_END: u64 = 1 << 63;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;

/// MmAdvanceMdl(Mdl, NumberOfBytes): devolve o NTSTATUS.
pub fn advance(descriptor: &Mdl, bytes: u32) -> u32 {
    let mut byte_count = descriptor.byte_count.get();
    if bytes >= byte_count {
        return STATUS_INVALID_PARAMETER_2;
    }
    let mut remaining = bytes;
    let byte_offset = descriptor.byte_offset.get();
    // ADDRESS_AND_SIZE_TO_SPAN_PAGES antes de andar.
    let mut entries = ((((descriptor.start_va.get() as u32).wrapping_add(byte_offset) & 0xFFF) as u64) + byte_count as u64 + 0xFFF) >> 12;
    let mut rotations = 0u64;
    if byte_offset != 0 {
        let mapped = descriptor.mdl_flags.get() & MDL_MAPPED_TO_SYSTEM_VA != 0;
        let room = 0x1000 - byte_offset;
        if remaining < room {
            descriptor.byte_count.set(byte_count - remaining);
            descriptor.byte_offset.set(byte_offset + remaining);
            if mapped {
                descriptor.mapped_system_va.set(descriptor.mapped_system_va.get().wrapping_add(remaining as u64));
            }
            return 0;
        }
        descriptor.start_va.set(descriptor.start_va.get() + 0x1000);
        byte_count -= room;
        remaining -= room;
        descriptor.byte_offset.set(0);
        descriptor.byte_count.set(byte_count);
        if mapped {
            descriptor.mapped_system_va.set(descriptor.mapped_system_va.get().wrapping_add(room as u64));
        }
        rotations = 1;
    }
    if remaining != 0 {
        byte_count -= remaining;
        descriptor.byte_count.set(byte_count);
        descriptor.byte_offset.set(remaining & 0xFFF);
        let pages = (remaining >> 12) as u64;
        rotations += pages;
        descriptor.start_va.set(descriptor.start_va.get() + (pages << 12));
        if descriptor.mdl_flags.get() & MDL_MAPPED_TO_SYSTEM_VA != 0 {
            descriptor.mapped_system_va.set(descriptor.mapped_system_va.get().wrapping_add(remaining as u64));
        }
    }
    if rotations == 0 {
        return 0;
    }
    let base = descriptor.address() + Mdl::SIZE;
    // SAFETY: a entrada `index` do vetor de PFNs do MDL (dimensionado pelo
    // dono para as páginas e as extras já giradas).
    let entry = |index: u64| unsafe { Field::<u64>::at(base + index * 8) };
    if descriptor.mdl_flags.get() & MDL_FREE_EXTRA_PTES != 0 {
        loop {
            let value = entry(entries).get();
            entries += 1;
            if value & PFN_EXTRA_END != 0 {
                break;
            }
        }
    }
    for _ in 0..rotations {
        let first = entry(0).get();
        for index in 1..=entries {
            let value = if index == entries { first | PFN_EXTRA_END } else { entry(index).get() & !PFN_EXTRA_END };
            entry(index - 1).set(value);
        }
    }
    set_flags(descriptor, MDL_FREE_EXTRA_PTES, 0);
    0
}

/// MmBuildMdlForNonPagedPool: como o do ntoskrnl 19041 (rva 0x264870),
/// Process = NULL e MappedSystemVa = StartVa + ByteOffset (o pool já está no
/// espaço do sistema; um mapeamento anterior do MDL deixa de valer), os PFNs
/// e só MDL_SOURCE_IS_NONPAGED_POOL: as páginas do pool não são travadas.
pub fn build_for_non_paged_pool(descriptor: u64) {
    let descriptor = mdl(descriptor);
    descriptor.process.set(0);
    descriptor.mapped_system_va.set(descriptor.start_va.get() + descriptor.byte_offset.get() as u64);
    fill_pfn_array(descriptor);
    set_flags(descriptor, MDL_SOURCE_IS_NONPAGED_POOL, 0);
}

/// MmAllocateMappingAddress — VA reservada em páginas inteiras da arena
/// (janela do heap, sem execução), alinhada à página e fora do alcance de
/// outras alocações; 0 sem memória.
pub fn allocate_mapping_address(size: u64, tag: u32) -> u64 {
    let bytes = (size as u32 as u64).div_ceil(0x1000) * 0x1000;
    let address = guest::alloc_aligned(bytes, 0x1000, true);
    if address == 0 {
        return 0;
    }
    RESERVED_MAPPINGS.lock().insert(address, (bytes, tag));
    address
}

/// MmFreeMappingAddress — a faixa volta à arena com as páginas da janela do
/// heap republicadas sobre os frames dela (um mapeamento reservado as trocou
/// pelas do MDL, e MmUnmapReservedMapping as deixou ausentes).
pub fn free_mapping_address(address: u64) {
    if let Some((bytes, _)) = RESERVED_MAPPINGS.lock().remove(&address) {
        for page in (address..address + bytes).step_by(0x1000) {
            let frame = memory_map::kernel_heap_physical(page);
            if memory_map::is_kernel_heap(page) && paging::translate(page) != frame {
                paging::map_page(page, frame, paging::PAGE_PRESENT | paging::PAGE_RW, paging::MapOptions { nx: true, ..paging::MapOptions::default() });
            }
        }
    }
    guest::free_bytes(address);
}

/// A faixa [address, address + bytes) cabe numa reserva viva de
/// MmAllocateMappingAddress.
pub fn reserved_mapping_covers(address: u64, bytes: u64) -> bool {
    let Some(end) = address.checked_add(bytes) else { return false };
    let reservations = RESERVED_MAPPINGS.lock();
    reservations.range(..=address).next_back().is_some_and(|(&base, &(size, _))| end <= base + size)
}

/// MmMapLockedPagesWithReservedMapping — exige a VA reservada e remapeia as
/// páginas dela para as do MDL; 0 em falha.
pub fn map_locked_pages_with_reserved_mapping(address: u64, descriptor: u64) -> u64 {
    let Some((reserved, _)) = RESERVED_MAPPINGS.lock().get(&address).copied() else { return 0 };
    let descriptor = mdl(descriptor);
    let count = descriptor.byte_count.get() as u64;
    let offset = descriptor.byte_offset.get() as u64;
    // Só as páginas da reserva: as seguintes pertencem a outros blocos da arena.
    if (offset + count).div_ceil(0x1000) * 0x1000 > reserved {
        return 0;
    }
    for (index, frame) in pfn_array(descriptor, (offset + count).div_ceil(0x1000)).iter().enumerate() {
        if !paging::map_page(address + index as u64 * 0x1000, frame.get() * 0x1000, paging::PAGE_PRESENT | paging::PAGE_RW, paging::MapOptions { nx: true, ..paging::MapOptions::default() }) {
            return 0;
        }
    }
    let mapped = address + offset;
    descriptor.mapped_system_va.set(mapped);
    set_flags(descriptor, MDL_MAPPED_TO_SYSTEM_VA, 0);
    mapped
}

/// MmUnmapReservedMapping.
pub fn unmap_reserved_mapping(descriptor: u64) {
    let descriptor = mdl(descriptor);
    let count = descriptor.byte_count.get() as u64;
    let offset = descriptor.byte_offset.get() as u64;
    let base = descriptor.mapped_system_va.get() - offset;
    for index in 0..(offset + count).div_ceil(0x1000) {
        paging::unmap_page(base + index * 0x1000, paging::MapOptions::default());
    }
    set_flags(descriptor, 0, MDL_MAPPED_TO_SYSTEM_VA);
}

/// MmAllocatePagesForMdl — páginas físicas reais da arena PFN descritas num
/// MDL novo (sem mapear); 0 em falha.
pub fn allocate_pages(byte_count: u64) -> u64 {
    if byte_count == 0 || byte_count > 0x7FFF_FFFF {
        return 0;
    }
    let page_count = byte_count.div_ceil(0x1000);
    let mut frames = Vec::new();
    for _ in 0..page_count {
        let frame = pfn::alloc_page();
        if frame == 0 {
            for frame in frames {
                pfn::free_page(frame);
            }
            return 0;
        }
        frames.push(frame);
    }
    let address = guest::alloc_bytes(Mdl::SIZE + page_count * 8);
    let descriptor = mdl(address);
    descriptor.next.set(0);
    descriptor.size.set((Mdl::SIZE + page_count * 8) as i16);
    descriptor.mdl_flags.set(0);
    descriptor.start_va.set(0);
    descriptor.byte_count.set(byte_count as u32);
    descriptor.byte_offset.set(0);
    for (entry, frame) in pfn_array(descriptor, page_count).iter().zip(&frames) {
        entry.set(frame / 0x1000);
    }
    address
}

/// MmFreePagesFromMdl — devolve as páginas físicas; o MDL continua vivo
/// (quem alocou libera).
pub fn free_pages(descriptor: u64) {
    let descriptor = mdl(descriptor);
    let size = descriptor.size.get() as u16 as u64;
    for entry in pfn_array(descriptor, size.saturating_sub(Mdl::SIZE) / 8) {
        let frame = entry.get();
        if frame != 0 {
            pfn::free_page(frame * 0x1000);
        }
    }
}

// ---- MmFreePagesFromMdlEx e MmMapMdl -----------------------------------------
//
// Como no ntoskrnl 19041:
// - MmFreePagesFromMdlEx(Mdl, Flags) (rva 0x381a10): Flags além de
//   MM_FREE_MDL_PAGES_ZERO (1) ou ByteCount fora de página é o bugcheck
//   MEMORY_MANAGEMENT (0x1A) com 0x1302, Mdl, Flags e ByteCount. O
//   MiFreePagesFromMdl zera as páginas antes de devolvê-las quando a flag
//   pede (salvo num MDL com MDL_FREE_EXTRA_PTES, que não zera), desfaz o
//   mapeamento de sistema do MDL e devolve as páginas.
// - MmMapMdl(Mdl, Protection, DriverRoutine, DriverContext) (rva 0x5374f0):
//   a proteção passa pelo MiMakeProtectionMask e só leitura ou leitura e
//   escrita, com ou sem PAGE_NOCACHE/PAGE_WRITECOMBINE, servem (inválida,
//   NOACCESS, WRITECOPY, executável ou PAGE_GUARD é
//   STATUS_INVALID_PAGE_PROTECTION). Um MDL já mapeado ou de pool não
//   paginado chama DriverRoutine(DriverContext, MappedSystemVa) direto;
//   senão as páginas do MDL ganham PTEs de sistema novos com a proteção
//   pedida (sem PTEs é STATUS_INSUFFICIENT_RESOURCES), a rotina recebe a VA
//   (+ ByteOffset) e os PTEs são liberados na volta, sem tocar no MDL. No
//   OpenNT os PTEs de sistema são uma faixa reservada da janela do heap,
//   como a do MmAllocateMappingAddress.

const MM_FREE_MDL_PAGES_ZERO: u32 = 1;
const STATUS_INVALID_PAGE_PROTECTION: u32 = 0xC000_0045;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// Tag do MiReservePtes do OpenNT para os PTEs do MmMapMdl ('MmMd').
const MAP_MDL_TAG: u32 = 0x644D_6D4D;

/// ADDRESS_AND_SIZE_TO_SPAN_PAGES(StartVa + ByteOffset, ByteCount).
fn span_pages(descriptor: &Mdl) -> u64 {
    let start = (descriptor.start_va.get() as u32).wrapping_add(descriptor.byte_offset.get()) & 0xFFF;
    (descriptor.byte_count.get() as u64 + 0xFFF + start as u64) >> 12
}

/// O zeramento do MiFreePagesFromMdl: cada página que o MDL abrange.
pub fn zero_pages(descriptor: u64) {
    let header = mdl(descriptor);
    for frame in pfn_array(header, span_pages(header)) {
        crate::hal::physical::zero(frame.get() * 0x1000, 0x1000);
    }
}

/// MmFreePagesFromMdlEx(Mdl, Flags).
pub fn free_pages_ex(descriptor: u64, flags: u32) {
    let header = mdl(descriptor);
    let byte_count = header.byte_count.get();
    if flags & !MM_FREE_MDL_PAGES_ZERO != 0 || byte_count & 0xFFF != 0 {
        crate::ntos::ke::bugcheck::bug_check_ex(0x1A, 0x1302, descriptor, flags as u64, byte_count as u64);
    }
    if flags & MM_FREE_MDL_PAGES_ZERO != 0 && header.mdl_flags.get() & MDL_FREE_EXTRA_PTES == 0 {
        zero_pages(descriptor);
    }
    if header.mdl_flags.get() & MDL_MAPPED_TO_SYSTEM_VA != 0 {
        unmap_locked_pages(descriptor);
    }
    free_pages(descriptor);
}

/// Bits de cache da folha para a máscara de proteção (`mask >> 3`: 0
/// cacheado, 1 não cacheado, 3 write-combine).
fn mask_cache_flags(mask: u32) -> u64 {
    match mask >> 3 {
        1 => 0x18,
        3 => 0x80,
        _ => 0,
    }
}

/// MmMapMdl: devolve o NTSTATUS.
pub fn map_mdl(descriptor: u64, protection: u32, routine: u64, context: u64) -> u32 {
    let Some(mask) = super::protection::make_mask(protection) else { return STATUS_INVALID_PAGE_PROTECTION };
    // 0x18 sozinho é a máscara de PAGE_NOACCESS.
    if mask == 0x18 || mask & 7 == 5 || mask & 2 != 0 || mask & !7 == super::protection::MASK_GUARD {
        return STATUS_INVALID_PAGE_PROTECTION;
    }
    let header = mdl(descriptor);
    if header.mdl_flags.get() & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL) != 0 {
        crate::hal::amd64::native_call::call(routine, &[context, header.mapped_system_va.get()]);
        return 0;
    }
    let pages = span_pages(header);
    let base = allocate_mapping_address(pages * 0x1000, MAP_MDL_TAG);
    if base == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let flags = paging::PAGE_PRESENT | if mask & 7 == 4 { paging::PAGE_RW } else { 0 } | mask_cache_flags(mask);
    let mapped = pfn_array(header, pages).iter().enumerate().all(|(index, frame)| paging::map_page(base + index as u64 * 0x1000, frame.get() * 0x1000, flags, paging::MapOptions { nx: true, ..paging::MapOptions::default() }));
    if mapped {
        crate::hal::amd64::native_call::call(routine, &[context, base + header.byte_offset.get() as u64]);
    }
    free_mapping_address(base);
    if mapped { 0 } else { STATUS_INSUFFICIENT_RESOURCES }
}

// ---- MDL Ex: alocação por faixa/nó, MmCreateMdl, estado do conteúdo e
// ---- sondagem em outro processo (mm-mdl-ex) ---------------------------------
//
// Contrato do ntoskrnl 19041:
// - MmAllocatePagesForMdlEx(Low, High, Skip, Total, CacheType, Flags) =
//   MmAllocatePartitionNodePagesForMdlEx(..., nó corrente, Flags, NULL);
//   MmAllocateNodePagesForMdlEx(..., IdealNode, Flags) o mesmo com o nó do
//   chamador. Nó >= KeNumberNodes -> NULL; CacheType -1 ou > 2 -> 3;
//   Flags & 0xFFFFF800 -> NULL; REQUIRE_CONTIGUOUS_CHUNKS sem FAST_LARGE_PAGES
//   liga PREFER_CONTIGUOUS e exige Skip 0 (-> FULLY_REQUIRED) ou potência de
//   dois >= 4 KiB que divida Total; AND_HOT_REMOVE recusa FULLY_REQUIRED e
//   IRQL != 0. MiValidateMdlAllocationRequest: Skip desalinhado -> NULL, Skip
//   não potência de dois -> 0 (NULL com FAST_LARGE_PAGES), Total > 0xFFFFE000
//   é limitado (NULL com FULLY_REQUIRED), zero páginas -> NULL, mais páginas
//   que as disponíveis é limitado (NULL com FULLY_REQUIRED). MiObtainMdlCharges
//   monta o MDL ('Mmdi', Size = (páginas + 6) * 8, ByteCount = páginas << 12,
//   StartVa/ByteOffset/MappedSystemVa = 0); MiInitializeMdlPages liga
//   MDL_PAGES_LOCKED e zera Process; as páginas são zeradas salvo
//   MM_DONT_ZERO_ALLOCATION.
// - MmCreateMdl(Mdl, Base, Length): Length >= 4 GiB -> NULL; Mdl NULL -> pool
//   'Mmdl' de páginas*8 + 0x30; grava Next, MdlFlags = 0, StartVa, ByteCount,
//   ByteOffset e Size = ((páginas + 6) << 3) como USHORT; Process e
//   MappedSystemVa ficam intocados.
// - MmMdlPageContentsState(Mdl, State): 2 consulta o bit 14
//   (MDL_PAGE_CONTENTS_INVARIANT), 1 liga, os demais desligam; devolve State.
// - MmProbeAndLockProcessPages(Mdl, Process, AccessMode, Operation):
//   Operation 0 = IoReadAccess, qualquer outra = IoWriteAccess;
//   KeStackAttachProcess quando Process != ApcState.Process,
//   MmProbeAndLockPages, KeUnstackDetachProcess.
//
// Lacunas: o CacheType só é validado (o atributo de cache pertence ao
// mapeamento de MmMapLockedPagesSpecifyCache); MM_ALLOCATE_FAST_LARGE_PAGES
// devolve NULL (sem alocador de blocos de 2 MiB; o NT também devolve NULL sem
// páginas grandes); PREFER_CONTIGUOUS é dica e não é honrada; a flag 0x400 é
// só validada.

const MDL_ALLOCATION_PAGE: u64 = 0x1000;
const MDL_ALLOCATION_PFN_LIMIT: u64 = 0xF_FFFF_FFFF;
const MDL_ALLOCATION_MAX_BYTES: u64 = 0xFFFF_E000;
/// KeNumberNodes: um nó NUMA.
const MDL_ALLOCATION_NODES: u32 = 1;
/// MDL_PAGE_CONTENTS_INVARIANT (bit 14 de MdlFlags).
const CONTENTS_INVARIANT_FLAG: u16 = 0x4000;

const MM_DONT_ZERO_ALLOCATION: u32 = 0x1;
const MM_ALLOCATE_FULLY_REQUIRED: u32 = 0x4;
const MM_ALLOCATE_PREFER_CONTIGUOUS: u32 = 0x10;
const MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS: u32 = 0x20;
const MM_ALLOCATE_FAST_LARGE_PAGES: u32 = 0x40;
const MM_ALLOCATE_AND_HOT_REMOVE: u32 = 0x100;
/// Bit interno que MiValidateMdlAllocationRequest liga quando a faixa pedida
/// começa no PFN 0 e alcança o maior PFN físico (o limite de 4 GiB do OpenNT).
const MM_ALLOCATE_WHOLE_RANGE: u32 = 0x1_0000;

fn free_allocated_frames(frames: &[u64]) {
    for &frame in frames {
        pfn::free_page(frame);
    }
}

/// MmAllocatePartitionNodePagesForMdlEx sobre a partição do sistema; 0 = NULL.
pub fn allocate_pages_ex(low: u64, high: u64, skip: u64, total: u64, cache_type: u32, node: u32, flags: u32) -> u64 {
    if node >= MDL_ALLOCATION_NODES {
        return 0;
    }
    let cache_type = if cache_type == u32::MAX || (cache_type as i32) > 2 { 3 } else { cache_type };
    if flags & 0xFFFF_F800 != 0 {
        return 0;
    }
    let mut flags = flags;
    if flags & (MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS | MM_ALLOCATE_FAST_LARGE_PAGES) == MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS {
        flags |= MM_ALLOCATE_PREFER_CONTIGUOUS;
        if skip == 0 {
            flags |= MM_ALLOCATE_FULLY_REQUIRED;
        } else if skip & skip.wrapping_sub(1) != 0 || (skip as i64) < 0x1000 || total % skip != 0 {
            return 0;
        }
    }
    if flags & MM_ALLOCATE_AND_HOT_REMOVE != 0 && (flags & MM_ALLOCATE_FULLY_REQUIRED != 0 || crate::ntos::ke::irql::get_irql() != 0) {
        return 0;
    }

    // MiValidateMdlAllocationRequest.
    let low_pfn = low >> 12;
    let high_pfn = (high >> 12).min(MDL_ALLOCATION_PFN_LIMIT);
    // Até o MmHighestPhysicalPage, a faixa pedida cobre o bloco inteiro.
    if low_pfn == 0 && high_pfn >= super::physical_layout::highest_physical_page() {
        flags |= MM_ALLOCATE_WHOLE_RANGE;
    }
    if skip & (MDL_ALLOCATION_PAGE - 1) != 0 {
        return 0;
    }
    let mut skip_pages = skip >> 12;
    if skip_pages & skip_pages.wrapping_sub(1) != 0 {
        if flags & MM_ALLOCATE_FAST_LARGE_PAGES != 0 {
            return 0;
        }
        skip_pages = 0;
    }
    if flags & 0x400 != 0 && (flags & 0x362 != 0 || flags & (MM_ALLOCATE_WHOLE_RANGE | MM_DONT_ZERO_ALLOCATION) == 0 || cache_type.wrapping_sub(1) & !2 != 0) {
        return 0;
    }
    let mut total = total;
    if total > MDL_ALLOCATION_MAX_BYTES {
        if flags & MM_ALLOCATE_FULLY_REQUIRED != 0 {
            return 0;
        }
        total = MDL_ALLOCATION_MAX_BYTES;
        if flags & 0x60 != 0 && skip_pages != 0 {
            total &= !((skip_pages << 12) - 1);
        }
    }
    let mut pages = (total + MDL_ALLOCATION_PAGE - 1) >> 12;
    if flags & MM_ALLOCATE_FAST_LARGE_PAGES != 0 {
        return 0;
    }
    let available = pfn::free_count();
    if available == 0 || pages == 0 {
        return 0;
    }
    if pages > available {
        if flags & MM_ALLOCATE_FULLY_REQUIRED != 0 {
            return 0;
        }
        pages = available;
    }

    // Frames reais da faixa pedida (o alocador comum quando a faixa é toda a RAM).
    let mut frames = Vec::new();
    while (frames.len() as u64) < pages {
        let frame = if flags & MM_ALLOCATE_WHOLE_RANGE != 0 { pfn::alloc_page() } else { pfn::alloc_contiguous(1, 1, high_pfn, low_pfn, 0) };
        if frame == 0 {
            break;
        }
        frames.push(frame);
    }
    if frames.is_empty() || ((frames.len() as u64) < pages && flags & MM_ALLOCATE_FULLY_REQUIRED != 0) {
        free_allocated_frames(&frames);
        return 0;
    }
    let address = guest::alloc_bytes(Mdl::SIZE + pages * 8);
    if address == 0 {
        free_allocated_frames(&frames);
        return 0;
    }
    if flags & MM_DONT_ZERO_ALLOCATION == 0 {
        for &frame in &frames {
            crate::hal::physical::zero(frame, MDL_ALLOCATION_PAGE as usize);
        }
    }
    let descriptor = mdl(address);
    descriptor.next.set(0);
    descriptor.size.set(((pages + 6) << 3) as i16);
    descriptor.mdl_flags.set(MDL_PAGES_LOCKED);
    descriptor.process.set(0);
    descriptor.mapped_system_va.set(0);
    descriptor.start_va.set(0);
    descriptor.byte_count.set((frames.len() as u64 * MDL_ALLOCATION_PAGE) as u32);
    descriptor.byte_offset.set(0);
    // PFNs não obtidos ficam 0 (MmFreePagesFromMdl os ignora).
    for (index, entry) in pfn_array(descriptor, pages).iter().enumerate() {
        entry.set(frames.get(index).copied().unwrap_or(0) / MDL_ALLOCATION_PAGE);
    }
    address
}

/// MmCreateMdl: o MDL inicializado (alocado quando `descriptor` é 0) ou 0.
pub fn create(descriptor: u64, base: u64, length: u64) -> u64 {
    if length >= 0x1_0000_0000 {
        return 0;
    }
    let offset = base & (MDL_ALLOCATION_PAGE - 1);
    let pages = (length + (MDL_ALLOCATION_PAGE - 1) + offset) >> 12;
    let address = if descriptor != 0 { descriptor } else { guest::alloc_bytes(pages * 8 + Mdl::SIZE) };
    if address == 0 {
        return 0;
    }
    let descriptor = mdl(address);
    descriptor.next.set(0);
    descriptor.mdl_flags.set(0);
    descriptor.byte_count.set(length as u32);
    descriptor.start_va.set(base & !(MDL_ALLOCATION_PAGE - 1));
    descriptor.size.set(((pages as u16).wrapping_add(6)).wrapping_shl(3) as i16);
    descriptor.byte_offset.set(offset as u32);
    address
}

/// MmMdlPageContentsState: consulta (2) ou troca o bit e devolve State.
pub fn page_contents_state(descriptor: u64, state: u32) -> u32 {
    let descriptor = mdl(descriptor);
    let flags = descriptor.mdl_flags.get() as u16;
    if state == 2 {
        return ((flags >> 14) & 1) as u32;
    }
    let updated = if state == 1 { flags | CONTENTS_INVARIANT_FLAG } else { flags & !CONTENTS_INVARIANT_FLAG };
    descriptor.mdl_flags.set(updated as i16);
    state
}

/// MmProbeAndLockProcessPages: sonda no espaço de `target`, anexando quando
/// ele não é o processo corrente. A operação chega à sonda (o
/// MDL_WRITE_OPERATION e a página gravável); o modo não muda o caminho do
/// OpenNT.
pub fn probe_and_lock_process_pages(descriptor: u64, target: u64, _access_mode: u8, operation: u32) -> Result<(), crate::rtl::KernelError> {
    if target == crate::ntos::ps::process::get_current_process() {
        probe_and_lock_pages(descriptor, operation);
        return Ok(());
    }
    let state = guest::alloc_bytes(0x30);
    if state == 0 {
        return Err(crate::rtl::KernelError::with_status("MmProbeAndLockProcessPages: KAPC_STATE allocation failed", 0xC000_009A));
    }
    if let Err(error) = crate::ntos::ke::process_attachment::attach(target, state) {
        guest::free_bytes(state);
        return Err(error);
    }
    probe_and_lock_pages(descriptor, operation);
    let detached = crate::ntos::ke::process_attachment::detach(state);
    guest::free_bytes(state);
    detached.map(|_| ())
}

// ---- MmMdlPagesAreZero (mm-file-system-support) -------------------------------
//
// Usa `pfn_array`, `MDL_PAGES_LOCKED` e `CONTENTS_INVARIANT_FLAG` deste arquivo.

/// PFN da página zero compartilhada do sistema — o global que o NT compara
/// em 0x322a5d e que MiZeroPageFile/MiCaptureSparsePages põem nos MDLs de
/// leitura de faixas zeradas. O OpenNT não tem essa página compartilhada:
/// nenhum PFN de MDL pode ser igual a ela.
fn system_zero_page_frame() -> Option<u64> {
    None
}

/// MmMdlPagesAreZero(Mdl) (RVA 0x322a20): exige MDL_PAGES_LOCKED e
/// MDL_PAGE_CONTENTS_INVARIANT e todos os PFNs iguais à página zero do
/// sistema (um MDL de zero páginas é verdadeiro).
pub fn pages_are_zero(descriptor: &Mdl) -> bool {
    let required = MDL_PAGES_LOCKED as u16 | CONTENTS_INVARIANT_FLAG;
    if descriptor.mdl_flags.get() as u16 & required != required {
        return false;
    }
    let start = (descriptor.byte_offset.get().wrapping_add(descriptor.start_va.get() as u32) & 0xFFF) as u64;
    let pages = (descriptor.byte_count.get() as u64 + 0xFFF + start) >> 12;
    let zero = system_zero_page_frame();
    pfn_array(descriptor, pages).iter().all(|frame| Some(frame.get()) == zero)
}

// ---- MmAreMdlPagesCached (ntoskrnl 19041 rva 0x3046b0) --------------------------
//
// Anda os PFNs das páginas que o MDL cobre (ByteOffset + StartVa e
// ByteCount; o primeiro PFN é sempre lido, mesmo com zero páginas) e só
// devolve TRUE se cada um é um frame possível (até 0xF_FFFF_FFFF), com
// MMPFN.u4.PfnExists e MMPFN.u3.e1.CacheAttribute = MiCached. O MMPFN é o do
// banco de PFNs publicado (`native_pfn_database`); um frame além dele não
// tem descritor, como um frame sem PfnExists.

/// O maior número de frame que o banco de PFNs do NT pode descrever.
const HIGHEST_POSSIBLE_FRAME: u64 = 0xF_FFFF_FFFF;
/// MI_PFN_CACHE_ATTRIBUTE: MiCached.
const PFN_CACHED: u8 = 1;

/// O MMPFN publicado de `frame`, se existe.
fn existing_pfn(frame: u64) -> Option<&'static crate::ntos::inc::types::Mmpfn> {
    let database = super::native_pfn_database::information()?;
    if frame >= database.frame_count {
        return None;
    }
    // SAFETY: descritor do banco publicado, pela VA do mapa direto.
    let entry = unsafe { crate::ntos::inc::types::Mmpfn::at(crate::hal::physical::range_to_virtual(database.physical_base + frame * database.descriptor_size, database.descriptor_size)) };
    (entry.u4.pfn_exists() != 0).then_some(entry)
}

/// MmAreMdlPagesCached(Mdl) -> BOOLEAN.
pub fn are_pages_cached(descriptor: &Mdl) -> bool {
    let start = (descriptor.byte_offset.get().wrapping_add(descriptor.start_va.get() as u32) & 0xFFF) as u64;
    let pages = ((descriptor.byte_count.get() as u64 + 0xFFF + start) >> 12).max(1);
    pfn_array(descriptor, pages).iter().all(|frame| {
        let frame = frame.get();
        frame <= HIGHEST_POSSIBLE_FRAME && existing_pfn(frame).is_some_and(|entry| entry.u3.e1.cache_attribute() == PFN_CACHED)
    })
}
