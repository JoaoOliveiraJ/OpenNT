//! Registradores de mapa e buffers de passagem da HAL: o caminho V2 do
//! ntoskrnl 19041 para os bus masters que não alcançam toda a RAM.
//!
//! Quando um adaptador precisa de registradores de mapa (HalGetAdapterV2):
//! todo bus master sem scatter/gather, e o com scatter/gather sem
//! Dma64BitAddresses numa máquina cuja RAM vai além de 4 GB
//! (HalpMaximumPhysicalMemoryAddress, aqui o topo do bloco de memória
//! física). Um registrador de mapa é uma entrada de tradução
//! (_HALP_DMA_TRANSLATION_ENTRY, 0x48 bytes) com uma página de buffer de
//! passagem abaixo do limite do adaptador (0xFFFFFFFF); o MapRegisterBase que
//! o driver recebe é a primeira entrada de uma cadeia (Next) de N entradas.
//!
//! - Pools: o contíguo é um bitmap (bit ligado = indisponível; uma página
//!   que não segue a anterior deixa uma lacuna ligada para sempre, então todo
//!   trecho livre é contíguo na memória física) e o de scatter é uma pilha
//!   LIFO. O adaptador mestre de 32 bits começa com o buffer de boot (64 KB,
//!   ou 192 KB com RAM acima de 4 GB, abaixo de 2 GB e senão de 4 GB, a
//!   metade dele reservada ao mestre); cada adaptador monta o pool próprio
//!   no HalGetAdapter (HalpDmaAllocateLocalContiguousPool, que divide o
//!   pedido ao meio até conseguir, ou HalpDmaAllocateLocalScatterPool, pelo
//!   MmAllocatePagesForMdl abaixo do limite).
//! - HalpDmaAllocateMapRegisters: um adaptador contíguo pede N bits livres
//!   seguidos (o pool próprio, o do mestre e, por fim, N páginas contíguas
//!   novas para o mestre); um de scatter junta N páginas quaisquer (a pilha
//!   própria, a do mestre, páginas do pool contíguo do mestre e páginas
//!   novas abaixo de 4 GB). Sem N, tudo volta e o adaptador espera na fila
//!   do mestre (FIFO, por tipo de pool) até um FreeMapRegisters
//!   (HalpDmaProcessMapRegisterQueueV2).
//! - O canal do adaptador (AllocateAdapterChannel, IoFreeAdapterChannel)
//!   serializa os donos: um WAIT_CONTEXT_BLOCK por vez, a rotina em
//!   DISPATCH_LEVEL, e o IO_ALLOCATION_ACTION dela (KeepObject,
//!   DeallocateObject, DeallocateObjectKeepRegisters).
//! - MapTransfer: um adaptador contíguo passa a transferência inteira pelo
//!   buffer (a partir da primeira entrada) a menos que ela seja um trecho
//!   contíguo abaixo do limite; um de scatter separa trechos diretos (abaixo
//!   do limite) e de passagem, estes nas entradas a partir do cursor
//!   (NextMapping da primeira). Numa escrita para o dispositivo os dados vão
//!   ao buffer na hora; FlushAdapterBuffers os traz de volta numa leitura e
//!   devolve o cursor ao começo.
//! - Listas de scatter/gather: com registradores de mapa, a lista é montada
//!   pelo MapTransfer dentro de um contexto (a lista em +0x30, sobre o
//!   WAIT_CONTEXT_BLOCK) quando o canal sai, os dados de uma escrita já no
//!   buffer antes da rotina do driver; o PutScatterGatherList esvazia os
//!   buffers de uma leitura e solta os registradores.
//!
//! Diferenças declaradas: a cópia entre o buffer do driver e o de passagem
//! vai pelo mapa direto, pelas páginas do MDL (o NT usa a VA de sistema do
//! MDL e o mapeia quando falta); a fila do canal fica no estado da HAL, não no
//! KDEVICE_QUEUE do objeto; não há o trabalhador que cresce o pool do mestre
//! em PASSIVE_LEVEL (o crescimento síncrono do alocador o cobre, e quem não
//! consegue espera um FreeMapRegisters); um WAIT_CONTEXT_BLOCK que espera
//! no canal de um adaptador sem registradores de mapa recebe MapRegisterBase
//! NULL; o DMA de 24 bits (limite de 16 MB) não tem buffer de boot nem
//! frames abaixo de 16 MB, então esses adaptadores não são criados, como
//! num NT cujo buffer de 24 bits não coube.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{DeviceObject, Mdl, ScatterGatherElement, ScatterGatherList, WaitContextBlock};
use crate::ntos::ke::irql;
use crate::ntos::mm::{guest_memory as guest, pfn, physical_layout};
use crate::hal::amd64::native_call;
use crate::hal::physical;
use crate::rtl::SpinLock;

const PAGE: u64 = 0x1000;
const FOUR_GB: u64 = 0x1_0000_0000;
const SIXTEEN_MB_PFN: u64 = 0x1000;
const STATUS_SUCCESS: u32 = 0;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
/// IO_ALLOCATION_ACTION.
const KEEP_OBJECT: u64 = 1;
const DEALLOCATE_OBJECT_KEEP_REGISTERS: u64 = 3;
/// O limite de um adaptador de 32 bits com registradores de mapa.
pub const LIMIT_32: u64 = 0xFFFF_FFFF;
/// O bitmap do pool contíguo do mestre de 32 bits.
const MASTER_BITMAP_BITS: usize = 0x4000;
/// O teto de registradores por canal: 64 sem scatter/gather, 512 com.
const CAP_CONTIGUOUS: u32 = 64;
const CAP_SCATTER: u32 = 512;

/// _HALP_DMA_TRANSLATION_ENTRY: um registrador de mapa, com a página de
/// passagem dele.
#[repr(C)]
struct TranslationEntry {
    /// O endereço físico da página de passagem (o que o dispositivo vê).
    physical_address: Field<u64>,
    /// A próxima entrada da cadeia de um MapRegisterBase.
    next: Field<u64>,
    /// A posição no bitmap de um pool contíguo (o NT a calcula pela cadeia
    /// dos arrays de entradas).
    index: Field<u64>,
    _reserved_18: Reserved<0x18>,
    /// VA da página (bits 12..63) e os donos (bits 0..3).
    u: Field<u64>,
    /// Na primeira entrada de um MapRegisterBase de scatter, a próxima a
    /// usar; nas outras, ela mesma.
    next_mapping: Field<u64>,
    _reserved_40: Reserved<0x8>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for TranslationEntry {}

const _: () = {
    assert!(core::mem::size_of::<TranslationEntry>() == 0x48);
    assert!(core::mem::offset_of!(TranslationEntry, u) == 0x30);
    assert!(core::mem::offset_of!(TranslationEntry, next_mapping) == 0x38);
};

const BOUND_TO_MASTER: u64 = 1;
const BOUND_TO_SCATTER_POOL: u64 = 2;
const OWNED_BY_MASTER: u64 = 4;
const OWNED_BY_SCATTER_POOL: u64 = 8;

fn entry(address: u64) -> &'static TranslationEntry {
    // SAFETY: entrada criada por `new_entry` (nunca liberada).
    unsafe { TranslationEntry::at(address) }
}

/// Uma entrada nova para a página `physical_address`, com os donos dados.
fn new_entry(physical_address: u64, owners: u64) -> u64 {
    let address = guest::alloc_bytes(TranslationEntry::SIZE);
    if address == 0 {
        return 0;
    }
    let item = entry(address);
    item.physical_address.set(physical_address);
    item.next.set(0);
    item.u.set(physical::to_virtual(physical_address) & !0xFFF | owners);
    item.next_mapping.set(address);
    address
}

/// Pool contíguo: a entrada de cada bit (0 numa lacuna) e o bitmap.
struct ContiguousPool {
    entries: Vec<u64>,
    capacity: usize,
    used: Vec<bool>,
}

impl ContiguousPool {
    fn new(capacity: usize) -> Self {
        Self { entries: Vec::new(), capacity, used: Vec::new() }
    }

    /// HalpDmaCommitContiguousMapBuffers: cada página na próxima entrada; uma
    /// página que não segue a anterior pula uma (a lacuna fica ligada).
    /// Devolve as páginas que não couberam.
    fn commit(&mut self, pages: &[u64], owners: u64) -> Vec<u64> {
        let mut left = Vec::new();
        for &page in pages {
            let previous = self.entries.iter().rev().find(|&&item| item != 0).map(|&item| entry(item).physical_address.get());
            let gap = previous.is_some_and(|previous| previous + PAGE != page) && self.entries.last().is_some_and(|&item| item != 0);
            if self.entries.len() + usize::from(gap) >= self.capacity {
                left.push(page);
                continue;
            }
            if gap {
                self.entries.push(0);
                self.used.push(true);
            }
            let item = new_entry(page, owners);
            if item == 0 {
                left.push(page);
                continue;
            }
            entry(item).index.set(self.entries.len() as u64);
            self.entries.push(item);
            self.used.push(false);
        }
        left
    }

    /// RtlFindClearBitsAndSet do primeiro bit: `count` entradas livres
    /// seguidas, marcadas e encadeadas na ordem dos bits.
    fn take_run(&mut self, count: usize) -> Option<Vec<u64>> {
        let mut start = 0;
        while start + count <= self.used.len() {
            match (start..start + count).find(|&index| self.used[index]) {
                Some(busy) => start = busy + 1,
                None => {
                    for index in start..start + count {
                        self.used[index] = true;
                    }
                    return Some(self.entries[start..start + count].to_vec());
                }
            }
        }
        None
    }

    /// Uma entrada livre qualquer (o pool contíguo do mestre emprestado a um
    /// pedido de scatter, uma página por vez).
    fn take_one(&mut self) -> Option<u64> {
        let index = self.used.iter().position(|&used| !used)?;
        self.used[index] = true;
        Some(self.entries[index])
    }

    fn release(&mut self, item: u64) {
        let index = entry(item).index.get() as usize;
        if self.entries.get(index) == Some(&item) {
            self.used[index] = false;
        }
    }

    fn free_count(&self) -> usize {
        self.used.iter().filter(|&&used| !used).count()
    }
}

/// O adaptador mestre de 32 bits (MasterAdapterV2).
struct Master {
    contiguous: ContiguousPool,
    scatter: Vec<u64>,
    maximum_physical_address: u64,
    /// ContiguousPageLimit: as páginas do pool contíguo que nenhum
    /// adaptador toma para o pool próprio.
    contiguous_page_limit: usize,
    /// ContiguousAdapterQueue e ScatterAdapterQueue: adaptadores sem
    /// registradores bastantes.
    queues: [VecDeque<u64>; 2],
}

/// Quem roda quando o canal sai para um WAIT_CONTEXT_BLOCK.
#[derive(Clone, Copy)]
enum Callback {
    /// A rotina de execução do driver (o DeviceRoutine do WCB).
    Native(u64),
    /// HalpAllocateAdapterCallbackV2: monta a lista de scatter/gather do
    /// contexto.
    ScatterGather(u64),
}

/// O estado de um adaptador: o pool próprio e o canal.
struct Adapter {
    needs_map_registers: bool,
    scatter_gather: bool,
    maximum_physical_address: u64,
    /// MapRegistersPerChannel.
    per_channel: u32,
    private_contiguous: ContiguousPool,
    private_scatter: Vec<u64>,
    /// O canal: o WCB dono e os que esperam.
    busy: bool,
    waiting: VecDeque<u64>,
    current_wcb: u64,
    map_register_base: u64,
    number_of_map_registers: u32,
}

struct State {
    master: Option<Master>,
    adapters: BTreeMap<u64, Adapter>,
    callbacks: BTreeMap<u64, Callback>,
}

static STATE: SpinLock<State> = SpinLock::new(State { master: None, adapters: BTreeMap::new(), callbacks: BTreeMap::new() });

/// O teto de MapRegistersPerChannel de um adaptador de 32 bits com
/// registradores de mapa (HalGetAdapterV2, bloco frio 0x8381dd).
pub fn cap(scatter_gather: bool) -> u32 {
    if scatter_gather { CAP_SCATTER } else { CAP_CONTIGUOUS }
}

/// HalpMaximumPhysicalMemoryAddress: o último byte do bloco de memória
/// física.
pub fn maximum_physical_memory_address() -> u64 {
    ((physical_layout::highest_physical_page() + 1) << 12) - 1
}

/// Um adaptador bus master com scatter/gather (ou sem) e Dma64 precisa de
/// registradores de mapa (HalGetAdapterV2 0x763e09 e o bloco frio 0x8381d9).
pub fn needs_map_registers(scatter_gather: bool, dma64: bool) -> bool {
    !scatter_gather || (maximum_physical_memory_address() >= FOUR_GB && !dma64)
}

/// HalpDmaInitMemory e HalpDmaInitializeMasterAdapter: o mestre de 32 bits
/// com o buffer de boot, montado no primeiro adaptador que o usa.
fn master(state: &mut State) -> &mut Master {
    state.master.get_or_insert_with(|| {
        let size = if maximum_physical_memory_address() < FOUR_GB { 0x1_0000 } else { 0x3_0000 };
        let pages = size / PAGE;
        let mut limit = (1u64 << 31) - 1;
        let mut base = pfn::alloc_contiguous(pages, 16, limit >> 12, 0, 0);
        if base == 0 {
            limit = LIMIT_32;
            base = pfn::alloc_contiguous(pages, 16, limit >> 12, 0, 0);
        }
        let mut master = Master {
            contiguous: ContiguousPool::new(MASTER_BITMAP_BITS),
            scatter: Vec::new(),
            maximum_physical_address: if base == 0 { (1 << 33) - 1 } else { limit },
            contiguous_page_limit: 0,
            queues: [VecDeque::new(), VecDeque::new()],
        };
        if base != 0 {
            let frames: Vec<u64> = (0..pages).map(|page| base + page * PAGE).collect();
            master.contiguous.commit(&frames, BOUND_TO_MASTER | OWNED_BY_MASTER);
            master.contiguous_page_limit = (size >> 13) as usize;
        }
        master
    })
}

/// HalpDmaAllocateContiguousMemory: `count` páginas contíguas abaixo de
/// `limit`, a partir de 16 MB quando o limite é o de 32 bits.
fn contiguous_pages(count: u64, limit: u64) -> u64 {
    let lowest = if limit & 0xFFFF_FFFF == 0xFFFF_FFFF { SIXTEEN_MB_PFN } else { 0 };
    let base = pfn::alloc_contiguous(count, 1, limit >> 12, lowest, 0);
    if base != 0 {
        return base;
    }
    pfn::alloc_contiguous(count, 1, limit >> 12, 0, 0)
}

/// O adaptador `address` foi criado por HalGetAdapterV2 com estes flags:
/// monta o pool próprio quando ele precisa de registradores de mapa e
/// devolve MapRegistersPerChannel (0 = o adaptador não pode ser criado).
pub fn register(address: u64, needs: bool, scatter_gather: bool, requested: u32) -> u32 {
    let mut adapter = Adapter {
        needs_map_registers: needs,
        scatter_gather,
        maximum_physical_address: if needs { LIMIT_32 } else { u64::MAX },
        per_channel: requested,
        private_contiguous: ContiguousPool::new(0),
        private_scatter: Vec::new(),
        busy: false,
        waiting: VecDeque::new(),
        current_wcb: 0,
        map_register_base: 0,
        number_of_map_registers: 0,
    };
    if needs {
        let mut state = STATE.lock();
        let master = master(&mut state);
        if adapter.maximum_physical_address < master.maximum_physical_address {
            return 0;
        }
        let count = if scatter_gather { local_scatter_pool(master, &mut adapter, requested) } else { local_contiguous_pool(master, &mut adapter, requested) };
        if count == 0 {
            return 0;
        }
        adapter.per_channel = count;
        state.adapters.insert(address, adapter);
        return count;
    }
    STATE.lock().adapters.insert(address, adapter);
    requested
}

/// HalpDmaAllocateLocalContiguousPool: `n` páginas contíguas para o pool do
/// adaptador (ou emprestadas do mestre além da reserva), dividindo `n` ao
/// meio até conseguir.
fn local_contiguous_pool(master: &mut Master, adapter: &mut Adapter, requested: u32) -> u32 {
    let mut count = requested;
    while count >= 1 {
        adapter.private_contiguous = ContiguousPool::new((count as usize).next_multiple_of(32));
        let base = contiguous_pages(count as u64, adapter.maximum_physical_address);
        if base != 0 {
            let frames: Vec<u64> = (0..count as u64).map(|page| base + page * PAGE).collect();
            for page in adapter.private_contiguous.commit(&frames, 0) {
                pfn::free_page(page);
            }
            return count;
        }
        // Emprestadas do mestre: só as páginas além da reserva dele, que
        // passam a ser do adaptador.
        let spare = master.contiguous.free_count().saturating_sub(master.contiguous_page_limit);
        if spare >= count as usize {
            if let Some(run) = master.contiguous.take_run(count as usize) {
                let frames: Vec<u64> = run.iter().map(|&item| entry(item).physical_address.get()).collect();
                adapter.private_contiguous.commit(&frames, 0);
                return count;
            }
        }
        if count == 1 {
            break;
        }
        count /= 2;
    }
    0
}

/// HalpDmaAllocateLocalScatterPool: até `n` páginas abaixo do limite
/// (MmAllocatePagesForMdl), o resto da pilha e do pool contíguo do mestre;
/// pelo menos uma. MapRegistersPerChannel continua `n`.
fn local_scatter_pool(master: &mut Master, adapter: &mut Adapter, requested: u32) -> u32 {
    let limit_pfn = adapter.maximum_physical_address >> 12;
    let mut obtained = 0;
    while obtained < requested {
        let mut frame = pfn::alloc_contiguous(1, 1, limit_pfn, SIXTEEN_MB_PFN, 0);
        if frame == 0 {
            frame = pfn::alloc_contiguous(1, 1, limit_pfn, 0, 0);
        }
        if frame == 0 {
            break;
        }
        let item = new_entry(frame, BOUND_TO_SCATTER_POOL | OWNED_BY_SCATTER_POOL);
        if item == 0 {
            pfn::free_page(frame);
            break;
        }
        adapter.private_scatter.push(item);
        obtained += 1;
    }
    while obtained < requested {
        let Some(item) = master.scatter.pop().or_else(|| master.contiguous.take_one()) else { break };
        let flags = entry(item).u.get() & !(OWNED_BY_MASTER | OWNED_BY_SCATTER_POOL);
        entry(item).u.set(flags | OWNED_BY_SCATTER_POOL);
        adapter.private_scatter.push(item);
        obtained += 1;
    }
    if obtained == 0 {
        return 0;
    }
    requested
}

/// Encadeia `items` (Next) e devolve a primeira, com o cursor nela mesma.
fn link(items: &[u64]) -> u64 {
    for (index, &item) in items.iter().enumerate() {
        let following = items.get(index + 1).copied().unwrap_or(0);
        entry(item).next.set(following);
        entry(item).next_mapping.set(item);
    }
    items.first().copied().unwrap_or(0)
}

/// HalpDmaAllocateMapRegisters: a cadeia de `count` entradas do adaptador,
/// ou 0.
fn allocate(state: &mut State, address: u64, count: u32) -> u64 {
    let State { master, adapters, .. } = state;
    let Some(adapter) = adapters.get_mut(&address) else { return 0 };
    let Some(master) = master.as_mut() else { return 0 };
    let count = count as usize;
    if !adapter.scatter_gather {
        if let Some(run) = adapter.private_contiguous.take_run(count) {
            return link(&run);
        }
        if let Some(run) = master.contiguous.take_run(count) {
            return link(&run);
        }
        // Crescimento síncrono: `count` páginas contíguas novas para o mestre.
        let base = contiguous_pages(count as u64, adapter.maximum_physical_address);
        if base != 0 {
            let frames: Vec<u64> = (0..count as u64).map(|page| base + page * PAGE).collect();
            for page in master.contiguous.commit(&frames, BOUND_TO_MASTER | OWNED_BY_MASTER) {
                pfn::free_page(page);
            }
            if let Some(run) = master.contiguous.take_run(count) {
                return link(&run);
            }
        }
        return 0;
    }
    let mut items = Vec::with_capacity(count);
    while items.len() < count {
        let Some(item) = adapter.private_scatter.pop() else { break };
        items.push(item);
    }
    while items.len() < count {
        let Some(item) = master.scatter.pop().or_else(|| master.contiguous.take_one()) else { break };
        items.push(item);
    }
    while items.len() < count {
        // Páginas novas abaixo de 4 GB, do mestre (os quatro donos).
        let frame = pfn::alloc_contiguous(1, 1, (FOUR_GB >> 12) - 1, 0, 0);
        if frame == 0 {
            break;
        }
        let item = new_entry(frame, BOUND_TO_MASTER | BOUND_TO_SCATTER_POOL | OWNED_BY_MASTER | OWNED_BY_SCATTER_POOL);
        if item == 0 {
            pfn::free_page(frame);
            break;
        }
        items.push(item);
    }
    if items.len() < count {
        for item in items {
            return_to_owner(master, adapter, item);
        }
        return 0;
    }
    link(&items)
}

/// HalpDmaReturnPageToOwner.
fn return_to_owner(master: &mut Master, adapter: &mut Adapter, item: u64) {
    let flags = entry(item).u.get();
    entry(item).next_mapping.set(item);
    entry(item).next.set(0);
    if flags & OWNED_BY_MASTER != 0 {
        if flags & OWNED_BY_SCATTER_POOL != 0 { master.scatter.push(item) } else { master.contiguous.release(item) }
    } else if adapter.scatter_gather {
        adapter.private_scatter.push(item);
    } else {
        adapter.private_contiguous.release(item);
    }
}

/// O adaptador tem registradores de mapa.
pub fn uses_map_registers(address: u64) -> bool {
    STATE.lock().adapters.get(&address).is_some_and(|adapter| adapter.needs_map_registers)
}

/// MapRegistersPerChannel do adaptador (0 sem estado).
pub fn per_channel(address: u64) -> u32 {
    STATE.lock().adapters.get(&address).map_or(0, |adapter| adapter.per_channel)
}

/// O adaptador saiu (PutDmaAdapter): o estado dele some; as páginas do pool
/// próprio ficam com as entradas (o NT também não as devolve aqui).
pub fn unregister(address: u64) {
    STATE.lock().adapters.remove(&address);
}

// ---- O canal ------------------------------------------------------------------

/// HalRealAllocateAdapterChannelV2: o WCB do DeviceObject preenchido e o
/// HalAllocateAdapterChannelV2.
pub fn allocate_adapter_channel(address: u64, device: u64, count: u32, routine: u64, context: u64) -> u32 {
    // SAFETY: DEVICE_OBJECT do driver chamador; o WCB é o Queue.Wcb dele.
    let device_object = unsafe { DeviceObject::at(device) };
    let wcb = &device_object.queue.wcb;
    wcb.device_object.set(device);
    wcb.current_irp.set(device_object.current_irp.get());
    wcb.device_context.set(context);
    let wcb_address = wcb as *const WaitContextBlock as u64;
    allocate_channel(address, wcb_address, count, Callback::Native(routine))
}

/// HalAllocateAdapterChannelV2(adapter, Wcb, n, rotina).
fn allocate_channel(address: u64, wcb_address: u64, count: u32, callback: Callback) -> u32 {
    // SAFETY: WCB do DEVICE_OBJECT ou do contexto de scatter/gather.
    let wcb = unsafe { WaitContextBlock::at(wcb_address) };
    wcb.bitfield_14.set(wcb.bitfield_14.get() & !4);
    wcb.device_routine.set(if let Callback::Native(routine) = callback { routine } else { 0 });
    wcb.number_of_map_registers.set(count);
    let previous = irql::raise_at_least(irql::DISPATCH_LEVEL);
    let mut state = STATE.lock();
    state.callbacks.insert(wcb_address, callback);
    let Some(adapter) = state.adapters.get_mut(&address) else {
        state.callbacks.remove(&wcb_address);
        drop(state);
        irql::lower_irql(previous as u64);
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    if adapter.busy {
        adapter.waiting.push_back(wcb_address);
        drop(state);
        irql::lower_irql(previous as u64);
        return STATUS_SUCCESS;
    }
    adapter.busy = true;
    adapter.current_wcb = wcb_address;
    adapter.number_of_map_registers = count;
    let base = if count == 0 || !adapter.needs_map_registers {
        adapter.number_of_map_registers = 0;
        0
    } else if count > adapter.per_channel {
        adapter.number_of_map_registers = 0;
        drop(state);
        free_adapter_channel(address);
        irql::lower_irql(previous as u64);
        return STATUS_INSUFFICIENT_RESOURCES;
    } else {
        let scatter = adapter.scatter_gather;
        let base = allocate(&mut state, address, count);
        if base == 0 {
            if let Some(master) = state.master.as_mut() {
                master.queues[usize::from(scatter)].push_back(address);
            }
            drop(state);
            irql::lower_irql(previous as u64);
            return STATUS_SUCCESS;
        }
        base
    };
    if let Some(adapter) = state.adapters.get_mut(&address) {
        adapter.map_register_base = base;
    }
    drop(state);
    let action = run(address, wcb_address, base);
    finish(address, action);
    irql::lower_irql(previous as u64);
    STATUS_SUCCESS
}

/// A rotina do WCB com o MapRegisterBase, em DISPATCH_LEVEL.
fn run(address: u64, wcb_address: u64, base: u64) -> u64 {
    let callback = STATE.lock().callbacks.remove(&wcb_address);
    // SAFETY: WCB registrado no allocate_channel.
    let wcb = unsafe { WaitContextBlock::at(wcb_address) };
    match callback {
        Some(Callback::Native(routine)) if routine != 0 => {
            let previous = irql::raise_at_least(irql::DISPATCH_LEVEL);
            let action = native_call::call(routine, &[wcb.device_object.get(), wcb.current_irp.get(), base, wcb.device_context.get()]);
            irql::lower_irql(previous as u64);
            action
        }
        Some(Callback::ScatterGather(context)) => scatter_gather_callback(address, context, base),
        _ => KEEP_OBJECT,
    }
}

/// O IO_ALLOCATION_ACTION de uma rotina que recebeu o canal.
fn finish(address: u64, action: u64) {
    if action == KEEP_OBJECT {
        return;
    }
    if action == DEALLOCATE_OBJECT_KEEP_REGISTERS {
        if let Some(adapter) = STATE.lock().adapters.get_mut(&address) {
            adapter.number_of_map_registers = 0;
        }
    }
    free_adapter_channel(address);
}

/// IoFreeAdapterChannelV2: solta os registradores do dono e passa o canal ao
/// próximo WCB da fila.
pub fn free_adapter_channel(address: u64) {
    let previous = irql::raise_at_least(irql::DISPATCH_LEVEL);
    loop {
        let held = STATE.lock().adapters.get(&address).map(|adapter| (adapter.map_register_base, adapter.number_of_map_registers));
        let Some((base, count)) = held else { break };
        if count != 0 {
            free_map_registers(address, base, count);
        }
        let mut state = STATE.lock();
        let Some(adapter) = state.adapters.get_mut(&address) else { break };
        let Some(wcb_address) = adapter.waiting.pop_front() else {
            adapter.busy = false;
            adapter.current_wcb = 0;
            adapter.map_register_base = 0;
            adapter.number_of_map_registers = 0;
            break;
        };
        // SAFETY: WCB que esperava na fila do canal.
        let wanted = unsafe { WaitContextBlock::at(wcb_address) }.number_of_map_registers.get();
        adapter.current_wcb = wcb_address;
        adapter.number_of_map_registers = wanted;
        let (needs, scatter) = (adapter.needs_map_registers, adapter.scatter_gather);
        let base = if wanted == 0 || !needs {
            adapter.number_of_map_registers = 0;
            0
        } else {
            let base = allocate(&mut state, address, wanted);
            if base == 0 {
                if let Some(master) = state.master.as_mut() {
                    master.queues[usize::from(scatter)].push_back(address);
                }
                break;
            }
            base
        };
        if let Some(adapter) = state.adapters.get_mut(&address) {
            adapter.map_register_base = base;
        }
        drop(state);
        let action = run(address, wcb_address, base);
        if action == KEEP_OBJECT {
            break;
        }
        if action == DEALLOCATE_OBJECT_KEEP_REGISTERS {
            if let Some(adapter) = STATE.lock().adapters.get_mut(&address) {
                adapter.number_of_map_registers = 0;
            }
        }
    }
    irql::lower_irql(previous as u64);
}

/// IoFreeMapRegistersV2: as `count` entradas da cadeia voltam aos donos e os
/// adaptadores que esperavam registradores do mesmo tipo de pool tentam de
/// novo (as rotinas deles rodam aqui).
pub fn free_map_registers(address: u64, base: u64, count: u32) {
    if base == 0 {
        return;
    }
    let previous = irql::raise_at_least(irql::DISPATCH_LEVEL);
    let scatter = {
        let mut state = STATE.lock();
        let State { master, adapters, .. } = &mut *state;
        let (Some(master), Some(adapter)) = (master.as_mut(), adapters.get_mut(&address)) else {
            drop(state);
            irql::lower_irql(previous as u64);
            return;
        };
        let mut item = base;
        for _ in 0..count {
            if item == 0 {
                break;
            }
            let following = entry(item).next.get();
            return_to_owner(master, adapter, item);
            item = following;
        }
        adapter.scatter_gather
    };
    process_queue(scatter);
    irql::lower_irql(previous as u64);
}

/// HalpDmaProcessMapRegisterQueueV2: os adaptadores da fila do mestre, em
/// ordem, recebem os registradores que esperavam.
fn process_queue(scatter: bool) {
    loop {
        let mut state = STATE.lock();
        let Some(address) = state.master.as_mut().and_then(|master| master.queues[usize::from(scatter)].pop_front()) else { break };
        let wanted = state.adapters.get(&address).map_or(0, |adapter| adapter.number_of_map_registers);
        let base = allocate(&mut state, address, wanted);
        if base == 0 {
            if let Some(master) = state.master.as_mut() {
                master.queues[usize::from(scatter)].push_front(address);
            }
            break;
        }
        let Some(adapter) = state.adapters.get_mut(&address) else { continue };
        adapter.map_register_base = base;
        let wcb_address = adapter.current_wcb;
        drop(state);
        let action = run(address, wcb_address, base);
        if action == KEEP_OBJECT {
            continue;
        }
        let (held_base, held) = {
            let mut state = STATE.lock();
            let Some(adapter) = state.adapters.get_mut(&address) else { continue };
            if action == DEALLOCATE_OBJECT_KEEP_REGISTERS {
                adapter.number_of_map_registers = 0;
            }
            (adapter.map_register_base, adapter.number_of_map_registers)
        };
        if held != 0 {
            free_map_registers(address, held_base, held);
            if let Some(adapter) = STATE.lock().adapters.get_mut(&address) {
                adapter.number_of_map_registers = 0;
            }
        }
        free_adapter_channel(address);
    }
}

// ---- MapTransfer e FlushAdapterBuffers ---------------------------------------------

/// O frame da página do MDL que contém `va` (o vetor de PFNs a partir do
/// StartVa).
fn mdl_frame(mdl: u64, va: u64) -> u64 {
    // SAFETY: MDL do driver chamador.
    let descriptor = unsafe { Mdl::at(mdl) };
    let index = (va - descriptor.start_va.get()) / PAGE;
    // SAFETY: vetor de PFNs do MDL, dimensionado para o buffer dele.
    unsafe { Field::<u64>::at(mdl + Mdl::SIZE + index * 8) }.get()
}

/// Os pedaços de [va, va + length) do MDL: (endereço físico, bytes), um por
/// página.
fn mdl_chunks(mdl: u64, va: u64, length: u32) -> Vec<(u64, u64)> {
    let mut chunks = Vec::new();
    let (mut cursor, end) = (va, va + length as u64);
    while cursor < end {
        let chunk = (PAGE - (cursor & (PAGE - 1))).min(end - cursor);
        chunks.push((mdl_frame(mdl, cursor) * PAGE + (cursor & (PAGE - 1)), chunk));
        cursor += chunk;
    }
    chunks
}

/// O trecho direto a partir de `va`: páginas abaixo do limite, seguidas na
/// memória física e na mesma região de 4 GB (HalpDmaNextContiguousPieceV2).
fn direct_piece(mdl: u64, va: u64, length: u32, limit: u64) -> u64 {
    let mut piece = 0;
    let mut expected = 0;
    for (physical, chunk) in mdl_chunks(mdl, va, length) {
        if physical >> 12 > limit >> 12 || (piece != 0 && (physical != expected || physical / FOUR_GB != (expected - 1) / FOUR_GB)) {
            break;
        }
        piece += chunk;
        expected = physical + chunk;
    }
    piece
}

/// O trecho de passagem de um adaptador de scatter: o menor entre as páginas
/// seguidas acima do limite e os buffers contíguos a partir de `cursor`.
fn bounce_piece(mdl: u64, va: u64, length: u32, limit: u64, cursor: u64) -> u64 {
    let mut above = 0;
    for (physical, chunk) in mdl_chunks(mdl, va, length) {
        if physical >> 12 <= limit >> 12 {
            break;
        }
        above += chunk;
    }
    let mut buffers = PAGE - (va & (PAGE - 1));
    let mut item = cursor;
    while buffers < above {
        let following = entry(item).next.get();
        let address = entry(item).physical_address.get();
        if following == 0 || entry(following).physical_address.get() != address + PAGE || (address + PAGE) % FOUR_GB == 0 {
            break;
        }
        buffers += PAGE;
        item = following;
    }
    above.min(buffers)
}

/// Copia entre as páginas do MDL em [va, va + length) e as páginas de
/// passagem da cadeia a partir de `first` (o primeiro pedaço no mesmo
/// deslocamento da página, os outros no começo das seguintes).
fn sync_buffers(mdl: u64, va: u64, length: u64, first: u64, to_buffer: bool) {
    let mut item = first;
    for (physical, chunk) in mdl_chunks(mdl, va, length as u32) {
        if item == 0 {
            break;
        }
        let buffer = entry(item).physical_address.get() + (physical & (PAGE - 1));
        let (source, target) = if to_buffer { (physical, buffer) } else { (buffer, physical) };
        physical::write_bytes(target, &physical::read_bytes(source, chunk as usize));
        item = entry(item).next.get();
    }
}

/// Avança `count` entradas pela cadeia.
fn advance(mut item: u64, count: u64) -> u64 {
    for _ in 0..count {
        if item == 0 {
            break;
        }
        item = entry(item).next.get();
    }
    item
}

fn span_pages(va: u64, length: u64) -> u64 {
    ((va & (PAGE - 1)) + length).div_ceil(PAGE)
}

/// HalpMapTransferV2 de um bus master (MapRegisterBase não nulo): o
/// endereço lógico e o *Length.
pub fn map_transfer(address: u64, mdl: u64, base: u64, va: u64, length: u32, write: bool) -> (u64, u32) {
    if length == 0 {
        return (0, 0);
    }
    let Some((scatter, limit)) = STATE.lock().adapters.get(&address).map(|adapter| (adapter.scatter_gather, adapter.maximum_physical_address)) else { return (0, length) };
    let direct = direct_piece(mdl, va, length, limit);
    if !scatter {
        // HalpDmaMapContiguousTransferV2: direto só a transferência inteira
        // contígua abaixo do limite; senão toda ela passa pelo buffer.
        let physical = mdl_frame(mdl, va) * PAGE + (va & (PAGE - 1));
        if direct == length as u64 && physical + length as u64 - 1 <= limit {
            return (physical, length);
        }
        if write {
            sync_buffers(mdl, va, length as u64, base, true);
        }
        return (entry(base).physical_address.get() + (va & (PAGE - 1)), length);
    }
    // HalpDmaMapScatterTransferV2.
    if direct != 0 {
        return (mdl_frame(mdl, va) * PAGE + (va & (PAGE - 1)), direct as u32);
    }
    let cursor = entry(base).next_mapping.get();
    let piece = bounce_piece(mdl, va, length, limit, cursor);
    if write {
        sync_buffers(mdl, va, piece, cursor, true);
    }
    entry(base).next_mapping.set(advance(cursor, span_pages(va, piece)));
    (entry(cursor).physical_address.get() + (va & (PAGE - 1)), piece as u32)
}

/// IoFlushAdapterBuffersV2 com MapRegisterBase: traz de volta o que passou
/// pelo buffer numa leitura e devolve o cursor ao começo. Devolve quantas
/// entradas os trechos de passagem usaram.
pub fn flush_adapter_buffers(address: u64, mdl: u64, base: u64, va: u64, length: u32, write: bool) -> u64 {
    if length == 0 || base == 0 {
        return 0;
    }
    let Some((scatter, limit)) = STATE.lock().adapters.get(&address).map(|adapter| (adapter.scatter_gather, adapter.maximum_physical_address)) else { return 0 };
    if !scatter {
        // HalpDmaFlushContiguousTransferV2: a mesma decisão do MapTransfer.
        let physical = mdl_frame(mdl, va) * PAGE + (va & (PAGE - 1));
        if direct_piece(mdl, va, length, limit) == length as u64 && physical + length as u64 - 1 <= limit {
            return 0;
        }
        if !write {
            sync_buffers(mdl, va, length as u64, base, false);
        }
        return span_pages(va, length as u64);
    }
    // HalpDmaFlushScatterTransferV2: os trechos de novo, a partir do começo.
    entry(base).next_mapping.set(base);
    let (mut cursor, mut used) = (base, 0);
    let (mut position, end) = (va, va + length as u64);
    while position < end {
        let remaining = (end - position) as u32;
        let direct = direct_piece(mdl, position, remaining, limit);
        if direct != 0 {
            position += direct;
            continue;
        }
        let piece = bounce_piece(mdl, position, remaining, limit, cursor);
        if piece == 0 {
            break;
        }
        if !write {
            sync_buffers(mdl, position, piece, cursor, false);
        }
        let pages = span_pages(position, piece);
        cursor = advance(cursor, pages);
        used += pages;
        position += piece;
    }
    entry(base).next_mapping.set(base);
    used
}

// ---- Listas de scatter/gather com registradores de mapa -----------------------------

/// O contexto da lista (HalBuildScatterGatherListV2, bloco frio 0x45f889):
/// a lista fica em +0x30, sobre o WAIT_CONTEXT_BLOCK.
#[repr(C)]
struct ListContext {
    /// Bit 0: o buffer é do chamador (BuildScatterGatherList).
    flags: Field<u32>,
    _pad_04: Reserved<0x4>,
    mdl: Field<u64>,
    extra_mdl: Field<u64>,
    map_register_base: Field<u64>,
    current_va: Field<u64>,
    length: Field<u32>,
    map_register_count: Field<u32>,
    wcb: WaitContextBlock,
    execution_routine: Field<u64>,
    context: Field<u64>,
    _reserved_88: Reserved<0x8>,
    adapter: Field<u64>,
    write_to_device: Field<u8>,
    _pad_99: Reserved<0x7>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for ListContext {}

const _: () = {
    assert!(core::mem::size_of::<ListContext>() == 0xA0);
    assert!(core::mem::offset_of!(ListContext, wcb) == 0x30);
    assert!(core::mem::offset_of!(ListContext, execution_routine) == 0x78);
    assert!(core::mem::offset_of!(ListContext, adapter) == 0x90);
};

/// O deslocamento da lista no contexto.
const LIST_OFFSET: u64 = 0x30;
const LIST_ELEMENTS: u64 = core::mem::offset_of!(ScatterGatherList, elements) as u64;

/// O tamanho do contexto com a lista de `pages` elementos.
pub fn list_context_size(pages: u64) -> u64 {
    (0x40 + 0x18 * pages).max(0xA0)
}

/// Os segmentos da cadeia de MDLs em [va, va + length): (MDL, VA, bytes); o
/// último leva o resto inteiro.
fn segments(mdl: u64, va: u64, length: u32) -> Vec<(u64, u64, u32)> {
    let mut list = Vec::new();
    let (mut descriptor_address, mut cursor, mut remaining) = (mdl, va, length as u64);
    while remaining > 0 && descriptor_address != 0 {
        // SAFETY: MDL da cadeia do chamador.
        let descriptor = unsafe { Mdl::at(descriptor_address) };
        let start = descriptor.start_va.get() + descriptor.byte_offset.get() as u64;
        let end = start + descriptor.byte_count.get() as u64;
        let next = descriptor.next.get();
        if cursor < start || cursor >= end {
            descriptor_address = next;
            if next != 0 {
                // SAFETY: MDL seguinte da cadeia.
                let following = unsafe { Mdl::at(next) };
                cursor = cursor.max(following.start_va.get() + following.byte_offset.get() as u64);
            }
            continue;
        }
        let bytes = if next == 0 { remaining } else { (end - cursor).min(remaining) };
        list.push((descriptor_address, cursor, bytes as u32));
        remaining -= bytes;
        descriptor_address = next;
        if next != 0 {
            // SAFETY: MDL seguinte da cadeia.
            let following = unsafe { Mdl::at(next) };
            cursor = following.start_va.get() + following.byte_offset.get() as u64;
        }
    }
    list
}

/// Get/BuildScatterGatherList de um adaptador com registradores de mapa: o
/// contexto (no `buffer` do chamador ou alocado) e o canal pedido com
/// `pages` registradores; a rotina do driver recebe a lista quando o canal
/// e os registradores saem.
#[allow(clippy::too_many_arguments)]
pub fn scatter_gather_list(address: u64, device: u64, mdl: u64, va: u64, length: u32, routine: u64, context: u64, write: bool, buffer: u64, buffer_length: u32, pages: u64) -> u32 {
    let size = list_context_size(pages);
    let owned = buffer == 0;
    if !owned && (buffer_length as u64) < size {
        return STATUS_BUFFER_TOO_SMALL;
    }
    let block = if owned { guest::alloc_bytes(size) } else { buffer };
    if block == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // SAFETY: bloco de pelo menos 0xA0 bytes, do contexto.
    let list_context = unsafe { ListContext::at(block) };
    list_context.flags.set(u32::from(!owned));
    list_context.mdl.set(mdl);
    list_context.extra_mdl.set(0);
    list_context.map_register_base.set(0);
    list_context.current_va.set(va);
    list_context.length.set(length);
    list_context.map_register_count.set(pages as u32);
    list_context.wcb.device_context.set(block);
    list_context.wcb.device_object.set(device);
    // SAFETY: DEVICE_OBJECT do driver chamador.
    list_context.wcb.current_irp.set(if device != 0 { unsafe { DeviceObject::at(device) }.current_irp.get() } else { 0 });
    list_context.execution_routine.set(routine);
    list_context.context.set(context);
    list_context.adapter.set(address);
    list_context.write_to_device.set(u8::from(write));
    let status = allocate_channel(address, block + LIST_OFFSET, pages as u32, Callback::ScatterGather(block));
    if status != STATUS_SUCCESS && owned {
        guest::free_bytes(block);
    }
    status
}

/// HalpAllocateAdapterCallbackV2: monta a lista em +0x30 pelo MapTransfer de
/// cada segmento (as escritas já copiadas), chama a rotina do driver e
/// devolve DeallocateObjectKeepRegisters (os registradores ficam com a lista).
fn scatter_gather_callback(address: u64, block: u64, base: u64) -> u64 {
    // SAFETY: contexto montado por `scatter_gather_list`.
    let list_context = unsafe { ListContext::at(block) };
    let (mdl, va, length, routine, context, write) = (list_context.mdl.get(), list_context.current_va.get(), list_context.length.get(), list_context.execution_routine.get(), list_context.context.get(), list_context.write_to_device.get() != 0);
    let (device, irp) = (list_context.wcb.device_object.get(), list_context.wcb.current_irp.get());
    list_context.map_register_base.set(base);
    let mut elements: Vec<(u64, u32)> = Vec::new();
    for (segment, start, bytes) in segments(mdl, va, length) {
        let (mut position, end) = (start, start + bytes as u64);
        while position < end {
            let remaining = (end - position) as u32;
            let (logical, piece) = if base == 0 { (mdl_frame(segment, position) * PAGE + (position & (PAGE - 1)), direct_piece(segment, position, remaining, u64::MAX) as u32) } else { map_transfer(address, segment, base, position, remaining, write) };
            if piece == 0 {
                break;
            }
            elements.push((logical, piece));
            position += piece as u64;
        }
    }
    let list = block + LIST_OFFSET;
    // SAFETY: a lista cabe no contexto (dimensionado pelas páginas).
    let header = unsafe { ScatterGatherList::at(list) };
    header.number_of_elements.set(elements.len() as u32);
    header.reserved.set(block);
    for (index, &(logical, piece)) in elements.iter().enumerate() {
        // SAFETY: elemento dentro do contexto.
        let element = unsafe { ScatterGatherElement::at(list + LIST_ELEMENTS + index as u64 * ScatterGatherElement::SIZE) };
        element.address.quad_part.set(logical as i64);
        element.length.set(piece);
        element.reserved.set(0);
    }
    if routine != 0 {
        native_call::call(routine, &[device, irp, list, context]);
    }
    DEALLOCATE_OBJECT_KEEP_REGISTERS
}

/// O contexto de uma lista montada com registradores de mapa (o Reserved da
/// lista), ou 0.
pub fn list_context_of(list: u64) -> u64 {
    // SAFETY: SCATTER_GATHER_LIST do driver.
    let reserved = unsafe { ScatterGatherList::at(list) }.reserved.get();
    if reserved > 1 && reserved + LIST_OFFSET == list { reserved } else { 0 }
}

/// PutScatterGatherList de uma lista com contexto: esvazia os buffers de
/// cada segmento (as leituras voltam), solta os registradores e o contexto.
pub fn put_scatter_gather_list(address: u64, block: u64, write: bool) {
    // SAFETY: contexto montado por `scatter_gather_list`.
    let list_context = unsafe { ListContext::at(block) };
    let (mdl, va, length, base, count, flags) = (list_context.mdl.get(), list_context.current_va.get(), list_context.length.get(), list_context.map_register_base.get(), list_context.map_register_count.get(), list_context.flags.get());
    let mut cursor = base;
    for (segment, start, bytes) in segments(mdl, va, length) {
        let used = flush_adapter_buffers(address, segment, cursor, start, bytes, write);
        cursor = advance(cursor, used);
    }
    free_map_registers(address, base, count);
    if flags & 1 == 0 {
        guest::free_bytes(block);
    }
}
