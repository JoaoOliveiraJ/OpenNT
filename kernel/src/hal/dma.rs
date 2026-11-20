//! Adaptadores de DMA da HAL (o HalGetAdapterV2 com o HalpDmaOperationsV2 e
//! o HalGetAdapterV3 com o HalpDmaOperationsV3 do ntoskrnl 19041).
//!
//! O IoGetDmaAdapter pede ao barramento (BUS_INTERFACE_STANDARD.GetDmaAdapter)
//! e o barramento PCI chega aqui com a DEVICE_DESCRIPTION do driver. Esta
//! plataforma não tem IOMMU: um dispositivo bus master enxerga a memória pelo
//! endereço físico, e o endereço lógico de um buffer é o físico. Um bus
//! master sem scatter/gather, ou um de 32 bits numa máquina com RAM acima de
//! 4 GB, recebe registradores de mapa e buffers de passagem abaixo de 4 GB
//! (`dma_map_registers`, o caminho V2 do NT). O adaptador é um DMA_ADAPTER
//! (Version 1, Size do objeto). Uma DEVICE_DESCRIPTION das versões 0 a 2 recebe a tabela V2
//! (Size 0x138; as rotinas da versão 3 ficam nulas, como na tabela V2 do
//! NT); a versão 3 (o HalGetAdapterV3, pedido pelo storport.sys quando o
//! miniport prefere o DMA v3) recebe a tabela V3, com a largura de endereço
//! do DmaAddressWidth (`dma_v3`). Só adaptadores bus master de pelo menos 32 bits são
//! atendidos (sem o controlador 8237 nem buffers abaixo de 16 MB); os outros
//! pedidos devolvem NULL.
//!
//! - NumberOfMapRegisters = MaximumLength / 4 KB + 1 (+1 com resto), a conta
//!   do HalGetAdapterV2 e do HalGetAdapterV3 (o bit 31 do MaximumLength é
//!   ignorado); com registradores de mapa, no máximo 64 (sem scatter/gather)
//!   ou 512, e o que o pool próprio do adaptador conseguiu. O HalGetAdapterV2
//!   liga o Dma32BitAddresses da DEVICE_DESCRIPTION do chamador num bus
//!   master com scatter/gather ou com Dma64BitAddresses.
//! - AllocateCommonBuffer: memória contígua da arena do kernel (abaixo de
//!   272 MB), alinhada à página; LogicalAddress = endereço físico.
//! - AllocateAdapterChannel: o canal do adaptador, um WAIT_CONTEXT_BLOCK por
//!   vez (o Queue.Wcb do DeviceObject), e o ExecutionRoutine(DeviceObject,
//!   DeviceObject->CurrentIrp, MapRegisterBase, Context) em DISPATCH_LEVEL;
//!   sem registradores de mapa, MapRegisterBase NULL (`dma_map_registers`).
//! - MapTransfer sem MapRegisterBase: o endereço físico de CurrentVa e o
//!   trecho fisicamente contíguo (na mesma região de 4 GB) dentro de
//!   *Length; com ele, o buffer de passagem quando a página não alcança o
//!   limite do adaptador. FlushAdapterBuffers traz de volta uma leitura.
//! - GetScatterGatherList/BuildScatterGatherList: sem registradores de mapa,
//!   SCATTER_GATHER_LIST com um elemento por trecho físico contíguo do MDL
//!   (as páginas do vetor de PFNs a partir de CurrentVa), entregue ao
//!   ExecutionRoutine(DeviceObject, CurrentIrp, lista, Context) no IRQL de
//!   quem chamou, com Reserved 0 (lista da HAL) ou 1 (buffer do chamador);
//!   com eles, a lista do contexto montada pelo MapTransfer quando o canal
//!   sai. PutScatterGatherList esvazia os buffers e devolve o que a HAL
//!   alocou. CalculateScatterGatherList conta as páginas (acima de
//!   MapRegistersPerChannel, STATUS_INSUFFICIENT_RESOURCES). Um trecho acima
//!   da largura de endereço de um adaptador V3 é recusado.
//!
//! A tabela V3 inteira (as variantes V3 das rotinas da V2 e as rotinas novas
//! da versão 3) fica em `dma_v3`, sobre este mesmo objeto adaptador.

use alloc::collections::BTreeSet;

use crate::hal::amd64::native_call;
use crate::hal::amd64::routine_stubs::{self, Routine};
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::extra_storage::{DeviceDescription, DmaAdapter, DmaOperations, ScatterGatherElement, ScatterGatherList};
use crate::ntos::inc::types::{DeviceObject, Mdl};
use crate::ntos::init::exports::Call;
use crate::ntos::ke::irql;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::paging;
use crate::rtl::{KernelError, SpinLock};

const PAGE_SIZE: u64 = 0x1000;
const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const FOUR_GB: u64 = 0x1_0000_0000;

/// O objeto adaptador (privado da HAL; os drivers só veem o DMA_ADAPTER).
#[repr(C)]
pub(super) struct AdapterObject {
    header: DmaAdapter,
    pub(super) map_registers: Field<u32>,
    pub(super) maximum_length: Field<u32>,
    pub(super) master: Field<u8>,
    scatter_gather: Field<u8>,
    pub(super) dma32: Field<u8>,
    pub(super) dma64: Field<u8>,
    _pad_1c: Reserved<4>,
    device_object: Field<u64>,
    /// Largura de endereço do dispositivo (DmaAddressWidth da versão 3;
    /// 32 ou 64 bits pelos flags das anteriores).
    pub(super) address_width: Field<u32>,
    /// NeedsMapRegisters.
    pub(super) needs_map_registers: Field<u8>,
    _pad_2d: Reserved<0x3>,
    /// MaximumPhysicalAddress: o limite dos buffers de passagem e comuns
    /// (u64::MAX sem registradores de mapa).
    pub(super) maximum_physical_address: Field<u64>,
    _reserved: Reserved<0x8>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for AdapterObject {}

const _: () = {
    assert!(core::mem::size_of::<AdapterObject>() == 0x40);
    assert!(core::mem::offset_of!(AdapterObject, map_registers) == 0x10);
    assert!(core::mem::offset_of!(AdapterObject, device_object) == 0x20);
    assert!(core::mem::offset_of!(AdapterObject, address_width) == 0x28);
    assert!(core::mem::offset_of!(AdapterObject, maximum_physical_address) == 0x30);
};

/// Tabela V2 (alocada uma vez; a V3 é a de `dma_v3`) e os adaptadores vivos.
static OPERATIONS: SpinLock<u64> = SpinLock::new(0);
static ADAPTERS: SpinLock<BTreeSet<u64>> = SpinLock::new(BTreeSet::new());
/// Listas alocadas pelo GetScatterGatherList (devolvidas no Put).
static OWNED_LISTS: SpinLock<BTreeSet<u64>> = SpinLock::new(BTreeSet::new());

/// Rotinas por ponteiro, na ordem dos slots desta faixa.
pub const ROUTINES: &[Routine] = &[
    Routine { name: "HalPutDmaAdapter", handler: put_dma_adapter },
    Routine { name: "HalAllocateCommonBuffer", handler: allocate_common_buffer },
    Routine { name: "HalFreeCommonBuffer", handler: free_common_buffer },
    Routine { name: "HalRealAllocateAdapterChannelV2", handler: allocate_adapter_channel },
    Routine { name: "IoFlushAdapterBuffers", handler: flush_adapter_buffers },
    Routine { name: "IoFreeAdapterChannel", handler: free_adapter_channel },
    Routine { name: "IoFreeMapRegisters", handler: free_map_registers },
    Routine { name: "IoMapTransfer", handler: map_transfer },
    Routine { name: "HalGetDmaAlignment", handler: get_dma_alignment },
    Routine { name: "HalReadDmaCounter", handler: read_dma_counter },
    Routine { name: "HalGetScatterGatherList", handler: get_scatter_gather_list },
    Routine { name: "HalPutScatterGatherList", handler: put_scatter_gather_list },
    Routine { name: "HalCalculateScatterGatherListSizeV2", handler: calculate_scatter_gather_list },
    Routine { name: "HalBuildScatterGatherListV2", handler: build_scatter_gather_list },
    Routine { name: "HalBuildMdlFromScatterGatherListV2", handler: build_mdl_from_scatter_gather_list },
    Routine { name: "HalAllocateCommonBufferExV2", handler: allocate_common_buffer_ex },
];

pub(super) fn adapter(address: u64) -> &'static AdapterObject {
    // SAFETY: adaptador criado por `get_adapter` (o chamador o recebeu daqui).
    unsafe { AdapterObject::at(address) }
}

/// A tabela HalpDmaOperationsV2 (Size 0x138, rotinas V3 nulas).
fn operations() -> Result<u64, KernelError> {
    let mut table = OPERATIONS.lock();
    if *table != 0 {
        return Ok(*table);
    }
    let address = guest::alloc_bytes(DmaOperations::SIZE);
    // SAFETY: bloco zerado recém-alocado do tamanho da tabela.
    let operations = unsafe { DmaOperations::at(address) };
    operations.size.set(DmaOperations::SIZE as u32);
    operations.put_dma_adapter.set(routine_stubs::address("HalPutDmaAdapter")?);
    operations.allocate_common_buffer.set(routine_stubs::address("HalAllocateCommonBuffer")?);
    operations.free_common_buffer.set(routine_stubs::address("HalFreeCommonBuffer")?);
    operations.allocate_adapter_channel.set(routine_stubs::address("HalRealAllocateAdapterChannelV2")?);
    operations.flush_adapter_buffers.set(routine_stubs::address("IoFlushAdapterBuffers")?);
    operations.free_adapter_channel.set(routine_stubs::address("IoFreeAdapterChannel")?);
    operations.free_map_registers.set(routine_stubs::address("IoFreeMapRegisters")?);
    operations.map_transfer.set(routine_stubs::address("IoMapTransfer")?);
    operations.get_dma_alignment.set(routine_stubs::address("HalGetDmaAlignment")?);
    operations.read_dma_counter.set(routine_stubs::address("HalReadDmaCounter")?);
    operations.get_scatter_gather_list.set(routine_stubs::address("HalGetScatterGatherList")?);
    operations.put_scatter_gather_list.set(routine_stubs::address("HalPutScatterGatherList")?);
    operations.calculate_scatter_gather_list.set(routine_stubs::address("HalCalculateScatterGatherListSizeV2")?);
    operations.build_scatter_gather_list.set(routine_stubs::address("HalBuildScatterGatherListV2")?);
    operations.build_mdl_from_scatter_gather_list.set(routine_stubs::address("HalBuildMdlFromScatterGatherListV2")?);
    operations.allocate_common_buffer_ex.set(routine_stubs::address("HalAllocateCommonBufferExV2")?);
    *table = address;
    Ok(address)
}

/// HalGetAdapterV2/HalGetAdapterV3 para o dispositivo `device` (o PDO): o
/// adaptador e o número de registradores de mapa em *NumberOfMapRegisters.
/// NULL para uma DEVICE_DESCRIPTION que esta HAL não atende.
pub fn get_adapter(device: u64, description: u64, map_registers: u64) -> u64 {
    if description == 0 {
        return 0;
    }
    // SAFETY: DEVICE_DESCRIPTION do driver chamador.
    let description = unsafe { DeviceDescription::at(description) };
    let version = description.version.get();
    if version > 3 {
        debug_print!("[dma] DEVICE_DESCRIPTION versao {} sem suporte", version);
        return 0;
    }
    if description.master.get() == 0 {
        // DMA de sistema (controlador 8237) não existe nesta plataforma.
        debug_print!("[dma] adaptador de DMA de sistema pedido (canal {})", description.dma_channel.get());
        return 0;
    }
    // A largura de endereço: o DmaAddressWidth da versão 3 (zero: pelos
    // flags, como nas anteriores); 64 bits com Dma64BitAddresses e 32 bits
    // senão.
    let address_width = match description.dma_address_width.get() {
        width if version == 3 && width != 0 => width,
        _ if description.dma64_bit_addresses.get() != 0 => 64,
        _ => 32,
    };
    if address_width < 32 {
        // Abaixo de 32 bits a HAL precisaria de buffers abaixo de 16 MB.
        debug_print!("[dma] adaptador bus master de {} bits sem suporte", address_width);
        return 0;
    }
    // HalGetAdapterV2: Dma32BitAddresses ligado na DEVICE_DESCRIPTION do
    // chamador num bus master com scatter/gather ou com Dma64; sem ele, um
    // bus master que precisa de registradores de mapa é de 24 bits.
    let scatter_gather = description.scatter_gather.get() != 0;
    let dma64 = description.dma64_bit_addresses.get() != 0;
    let needs = version < 3 && super::dma_map_registers::needs_map_registers(scatter_gather, dma64);
    if version < 3 && (scatter_gather || dma64) {
        description.dma32_bit_addresses.set(1);
    }
    if needs && description.dma32_bit_addresses.get() == 0 {
        debug_print!("[dma] adaptador bus master de 24 bits sem buffers abaixo de 16 MB");
        return 0;
    }
    let Ok(table) = (if version == 3 { super::dma_v3::operations() } else { operations() }) else { return 0 };
    let maximum = description.maximum_length.get() & 0x7FFF_FFFF;
    let pages = (maximum >> 12) + 1 + u32::from(maximum & 0xFFF != 0);
    let requested = if needs { pages.min(super::dma_map_registers::cap(scatter_gather)) } else { pages };
    let address = guest::alloc_bytes(AdapterObject::SIZE);
    let count = super::dma_map_registers::register(address, needs, scatter_gather, requested);
    if count == 0 {
        guest::free_bytes(address);
        debug_print!("[dma] sem buffers de passagem para o adaptador ({} registradores pedidos)", requested);
        return 0;
    }
    let object = adapter(address);
    object.header.version.set(1);
    object.header.size.set(AdapterObject::SIZE as u16);
    object.header.dma_operations.set(table);
    object.map_registers.set(count);
    object.maximum_length.set(maximum);
    object.master.set(description.master.get());
    // Bus master de 32 bits que também faz scatter/gather.
    object.scatter_gather.set(description.scatter_gather.get() | description.dma32_bit_addresses.get() | description.dma64_bit_addresses.get());
    object.dma32.set(description.dma32_bit_addresses.get());
    object.dma64.set(description.dma64_bit_addresses.get() | u8::from(address_width >= 64));
    object.device_object.set(device);
    object.address_width.set(address_width);
    object.needs_map_registers.set(u8::from(needs));
    object.maximum_physical_address.set(if needs { super::dma_map_registers::LIMIT_32 } else { u64::MAX });
    ADAPTERS.lock().insert(address);
    if version == 3 {
        super::dma_v3::register(address);
    }
    if map_registers != 0 {
        // SAFETY: PULONG de saída do driver.
        unsafe { Field::<u32>::at(map_registers) }.set(count);
    }
    debug_print!("[dma] adaptador {:#x} (versao {}, master de {} bits, max {:#x}, {} registradores de mapa{})", address, version, address_width, maximum, count, if needs { ", com buffers de passagem" } else { "" });
    address
}

/// Adaptador vivo (autotestes).
pub fn is_adapter(address: u64) -> bool {
    ADAPTERS.lock().contains(&address)
}

pub(super) fn put_dma_adapter(call: &Call) -> Result<u64, KernelError> {
    if ADAPTERS.lock().remove(&call.arg(1)) {
        super::dma_v3::unregister(call.arg(1));
        super::dma_map_registers::unregister(call.arg(1));
        guest::free_bytes(call.arg(1));
    }
    Ok(0)
}

/// Memória comum contígua, alinhada à página; o endereço lógico é o físico.
pub(super) fn common_buffer(length: u32, logical: u64) -> u64 {
    if length == 0 || logical == 0 {
        return 0;
    }
    let size = (length as u64).div_ceil(PAGE_SIZE) * PAGE_SIZE;
    let va = guest::alloc_aligned(size, PAGE_SIZE, true);
    if va == 0 {
        return 0;
    }
    // SAFETY: PPHYSICAL_ADDRESS de saída do driver.
    unsafe { Field::<u64>::at(logical) }.set(paging::translate(va));
    va
}

/// AllocateCommonBuffer(Adapter, Length, LogicalAddress*, CacheEnabled).
pub(super) fn allocate_common_buffer(call: &Call) -> Result<u64, KernelError> {
    Ok(common_buffer(call.arg(2) as u32, call.arg(3)))
}

/// AllocateCommonBufferEx(Adapter, MaximumAddress*, Length, LogicalAddress*,
/// CacheEnabled, PreferredNode): a arena fica abaixo de qualquer limite a
/// partir do fim físico dela.
pub(super) fn allocate_common_buffer_ex(call: &Call) -> Result<u64, KernelError> {
    let limit = call.arg(2);
    if limit != 0 {
        // SAFETY: PPHYSICAL_ADDRESS do driver.
        let maximum = unsafe { Field::<u64>::at(limit) }.get();
        if maximum < crate::hal::host::guest_arena_physical_top() {
            return Ok(0);
        }
    }
    Ok(common_buffer(call.arg(3) as u32, call.arg(4)))
}

/// FreeCommonBuffer(Adapter, Length, LogicalAddress, VirtualAddress, CacheEnabled).
pub(super) fn free_common_buffer(call: &Call) -> Result<u64, KernelError> {
    if call.arg(4) != 0 {
        guest::free_bytes(call.arg(4));
    }
    Ok(0)
}

/// O IRP corrente do dispositivo (o segundo argumento das rotinas de
/// execução).
pub(super) fn current_irp(device: u64) -> u64 {
    if device == 0 {
        return 0;
    }
    // SAFETY: DEVICE_OBJECT do driver chamador.
    unsafe { DeviceObject::at(device) }.current_irp.get()
}

/// Chama a rotina do driver em DISPATCH_LEVEL (como a HAL entrega as
/// rotinas de execução de canal e de scatter/gather).
pub(super) fn call_at_dispatch(routine: u64, arguments: &[u64]) -> u64 {
    let previous = irql::raise_at_least(irql::DISPATCH_LEVEL);
    let result = native_call::call(routine, arguments);
    irql::lower_irql(previous as u64);
    result
}

/// AllocateAdapterChannel(Adapter, DeviceObject, NumberOfMapRegisters,
/// ExecutionRoutine, Context): o canal do adaptador (`dma_map_registers`).
pub(super) fn allocate_adapter_channel(call: &Call) -> Result<u64, KernelError> {
    let (object, device, count, routine, context) = (call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5));
    if !is_adapter(object) || device == 0 || routine == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES as u64);
    }
    Ok(super::dma_map_registers::allocate_adapter_channel(object, device, count, routine, context) as u64)
}

/// FlushAdapterBuffers(Adapter, Mdl, MapRegisterBase, CurrentVa, Length,
/// WriteToDevice): TRUE sempre; com MapRegisterBase, uma leitura volta do
/// buffer de passagem.
pub(super) fn flush_adapter_buffers(call: &Call) -> Result<u64, KernelError> {
    let (object, mdl, base, va, length, write) = (call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5) as u32, call.arg(6) as u8 != 0);
    if is_adapter(object) && mdl != 0 && base != 0 {
        super::dma_map_registers::flush_adapter_buffers(object, mdl, base, va, length, write);
    }
    Ok(1)
}

/// FreeAdapterChannel(Adapter).
pub(super) fn free_adapter_channel(call: &Call) -> Result<u64, KernelError> {
    if is_adapter(call.arg(1)) {
        super::dma_map_registers::free_adapter_channel(call.arg(1));
    }
    Ok(0)
}

/// FreeMapRegisters(Adapter, MapRegisterBase, NumberOfMapRegisters).
pub(super) fn free_map_registers(call: &Call) -> Result<u64, KernelError> {
    if is_adapter(call.arg(1)) {
        super::dma_map_registers::free_map_registers(call.arg(1), call.arg(2), call.arg(3) as u32);
    }
    Ok(0)
}

pub(super) fn get_dma_alignment(_: &Call) -> Result<u64, KernelError> {
    Ok(1)
}

pub(super) fn read_dma_counter(_: &Call) -> Result<u64, KernelError> {
    Ok(0)
}

/// Trechos fisicamente contíguos de [CurrentVa, CurrentVa + Length) no MDL
/// (encadeado por Next), pelo vetor de PFNs de cada MDL.
pub(super) fn physical_runs(mdl_address: u64, current_va: u64, length: u32) -> Option<alloc::vec::Vec<(u64, u32)>> {
    let mut runs: alloc::vec::Vec<(u64, u32)> = alloc::vec::Vec::new();
    let mut remaining = length as u64;
    let mut cursor = current_va;
    let mut descriptor_address = mdl_address;
    while remaining > 0 {
        if descriptor_address == 0 {
            return None;
        }
        // SAFETY: MDL do driver chamador.
        let descriptor = unsafe { Mdl::at(descriptor_address) };
        let start = descriptor.start_va.get() + descriptor.byte_offset.get() as u64;
        let end = start + descriptor.byte_count.get() as u64;
        if cursor < start || cursor >= end {
            // CurrentVa fora deste MDL: segue para o próximo da cadeia.
            descriptor_address = descriptor.next.get();
            if descriptor_address != 0 {
                // SAFETY: MDL encadeado do mesmo pedido.
                let next = unsafe { Mdl::at(descriptor_address) };
                cursor = cursor.max(next.start_va.get() + next.byte_offset.get() as u64);
            }
            continue;
        }
        let pages = descriptor_address + Mdl::SIZE;
        while remaining > 0 && cursor < end {
            let index = (cursor - descriptor.start_va.get()) / PAGE_SIZE;
            // SAFETY: vetor de PFNs do MDL, dimensionado para o buffer dele.
            let frame = unsafe { Field::<u64>::at(pages + index * 8) }.get();
            let in_page = cursor & (PAGE_SIZE - 1);
            let chunk = (PAGE_SIZE - in_page).min(remaining).min(end - cursor);
            let physical = frame * PAGE_SIZE + in_page;
            match runs.last_mut() {
                Some((base, size)) if *base + *size as u64 == physical && *base / FOUR_GB == physical / FOUR_GB && (*size as u64 + chunk) <= u32::MAX as u64 => *size += chunk as u32,
                _ => runs.push((physical, chunk as u32)),
            }
            cursor += chunk;
            remaining -= chunk;
        }
        descriptor_address = descriptor.next.get();
        if descriptor_address != 0 && remaining > 0 {
            // SAFETY: MDL encadeado do mesmo pedido.
            let next = unsafe { Mdl::at(descriptor_address) };
            cursor = next.start_va.get() + next.byte_offset.get() as u64;
        }
    }
    Some(runs)
}

/// Os trechos ficam dentro da largura de endereço do adaptador. Um adaptador
/// V2 que não alcança toda a RAM tem registradores de mapa; um V3 recusa o
/// trecho além da largura em vez de entregá-lo truncado ao dispositivo.
pub(super) fn reachable(object: u64, runs: &[(u64, u32)]) -> bool {
    let width = adapter(object).address_width.get();
    width >= 64 || runs.iter().all(|&(physical, size)| physical + size as u64 <= 1u64 << width)
}

/// MapTransfer(Adapter, Mdl, MapRegisterBase, CurrentVa, Length*, WriteToDevice).
pub(super) fn map_transfer(call: &Call) -> Result<u64, KernelError> {
    let length_pointer = call.arg(5);
    if length_pointer == 0 {
        return Ok(0);
    }
    // SAFETY: PULONG Length do driver.
    let length = unsafe { Field::<u32>::at(length_pointer) };
    if call.arg(3) != 0 && is_adapter(call.arg(1)) && call.arg(2) != 0 {
        let (logical, piece) = super::dma_map_registers::map_transfer(call.arg(1), call.arg(2), call.arg(3), call.arg(4), length.get(), call.arg(6) as u8 != 0);
        length.set(piece);
        return Ok(logical);
    }
    let Some(runs) = physical_runs(call.arg(2), call.arg(4), length.get()) else { return Ok(0) };
    if !is_adapter(call.arg(1)) || !reachable(call.arg(1), &runs) {
        return Ok(0);
    }
    let Some(&(physical, size)) = runs.first() else { return Ok(0) };
    length.set(size);
    Ok(physical)
}

/// Deslocamento de Elements[0] na SCATTER_GATHER_LIST.
const LIST_ELEMENTS: u64 = core::mem::offset_of!(ScatterGatherList, elements) as u64;

/// Bytes de uma SCATTER_GATHER_LIST com `elements` elementos.
pub(super) fn list_size(elements: usize) -> u64 {
    LIST_ELEMENTS + elements as u64 * ScatterGatherElement::SIZE
}

/// Escreve a lista em `buffer` (Reserved 0: a lista é da HAL).
pub(super) fn write_list(buffer: u64, runs: &[(u64, u32)]) {
    write_list_marked(buffer, runs, 0);
}

/// Escreve a lista em `buffer` com o Reserved dado (0 = alocada pela HAL,
/// 1 = no buffer do chamador).
fn write_list_marked(buffer: u64, runs: &[(u64, u32)], reserved: u64) {
    // SAFETY: buffer do tamanho de `list_size(runs.len())`.
    let list = unsafe { ScatterGatherList::at(buffer) };
    list.number_of_elements.set(runs.len() as u32);
    list.reserved.set(reserved);
    for (index, &(physical, size)) in runs.iter().enumerate() {
        // SAFETY: elemento dentro do mesmo buffer.
        let element = unsafe { ScatterGatherElement::at(buffer + LIST_ELEMENTS + index as u64 * ScatterGatherElement::SIZE) };
        element.address.quad_part.set(physical as i64);
        element.length.set(size);
        element.reserved.set(0);
    }
}

/// HalpCalculateScatterGatherListSize: as páginas que [CurrentVa,
/// CurrentVa + Length) cobre em cada MDL da cadeia (sem MDL, as do
/// endereço), ou o status de uma cadeia curta demais.
fn list_pages(mdl: u64, current_va: u64, length: u32) -> Result<u64, u32> {
    if mdl == 0 {
        return Ok(((current_va & (PAGE_SIZE - 1)) + length as u64).div_ceil(PAGE_SIZE));
    }
    let mut pages = 0;
    let (mut descriptor_address, mut cursor, mut remaining) = (mdl, current_va, length as u64);
    while remaining > 0 {
        if descriptor_address == 0 {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        // SAFETY: MDL da cadeia do chamador.
        let descriptor = unsafe { Mdl::at(descriptor_address) };
        let end = descriptor.start_va.get() + descriptor.byte_offset.get() as u64 + descriptor.byte_count.get() as u64;
        let bytes = end.saturating_sub(cursor).min(remaining);
        pages += ((cursor & (PAGE_SIZE - 1)) + bytes).div_ceil(PAGE_SIZE);
        remaining -= bytes;
        descriptor_address = descriptor.next.get();
        if descriptor_address != 0 {
            // SAFETY: MDL seguinte da cadeia.
            let next = unsafe { Mdl::at(descriptor_address) };
            cursor = next.start_va.get() + next.byte_offset.get() as u64;
        }
    }
    Ok(pages)
}

/// O tamanho da lista de um adaptador (com registradores de mapa, o
/// contexto com a lista em +0x30) e as páginas, ou o status.
fn list_size_for(object: u64, mdl: u64, current_va: u64, length: u32) -> Result<(u64, u64), u32> {
    let pages = list_pages(mdl, current_va, length)?;
    if pages > super::dma_map_registers::per_channel(object) as u64 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let size = if adapter(object).needs_map_registers.get() != 0 { super::dma_map_registers::list_context_size(pages) } else { list_size(pages as usize) };
    Ok((size, pages))
}

/// GetScatterGatherList(Adapter, DeviceObject, Mdl, CurrentVa, Length,
/// ExecutionRoutine, Context, WriteToDevice).
pub(super) fn get_scatter_gather_list(call: &Call) -> Result<u64, KernelError> {
    let (object, device, mdl, current_va, length, routine, context, write) = (call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5) as u32, call.arg(6), call.arg(7), call.arg(8) as u8 != 0);
    if !is_adapter(object) || mdl == 0 || routine == 0 {
        return Ok(STATUS_INVALID_PARAMETER as u64);
    }
    let pages = match list_size_for(object, mdl, current_va, length) {
        Ok((_, pages)) => pages,
        Err(status) => return Ok(status as u64),
    };
    if adapter(object).needs_map_registers.get() != 0 {
        return Ok(super::dma_map_registers::scatter_gather_list(object, device, mdl, current_va, length, routine, context, write, 0, 0, pages) as u64);
    }
    let Some(runs) = physical_runs(mdl, current_va, length) else { return Ok(STATUS_INVALID_PARAMETER as u64) };
    if !reachable(object, &runs) {
        return Ok(STATUS_INSUFFICIENT_RESOURCES as u64);
    }
    let buffer = guest::alloc_bytes(list_size(runs.len()));
    if buffer == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES as u64);
    }
    write_list(buffer, &runs);
    OWNED_LISTS.lock().insert(buffer);
    native_call::call(routine, &[device, current_irp(device), buffer, context]);
    Ok(STATUS_SUCCESS)
}

/// Uma lista que a HAL alocou (devolvida no PutScatterGatherList).
pub(super) fn own_list(list: u64) {
    OWNED_LISTS.lock().insert(list);
}

/// Devolve uma lista que a HAL alocou e que não chegou ao driver.
pub(super) fn release_list(list: u64) {
    if OWNED_LISTS.lock().remove(&list) {
        guest::free_bytes(list);
    }
}

/// PutScatterGatherList(Adapter, ScatterGather, WriteToDevice): uma lista
/// com contexto esvazia os buffers de passagem e solta os registradores.
pub(super) fn put_scatter_gather_list(call: &Call) -> Result<u64, KernelError> {
    let (object, list, write) = (call.arg(1), call.arg(2), call.arg(3) as u8 != 0);
    if list == 0 {
        return Ok(0);
    }
    let context = super::dma_map_registers::list_context_of(list);
    if context != 0 && is_adapter(object) {
        super::dma_map_registers::put_scatter_gather_list(object, context, write);
        return Ok(0);
    }
    if OWNED_LISTS.lock().remove(&list) {
        guest::free_bytes(list);
    }
    Ok(0)
}

/// CalculateScatterGatherList(Adapter, Mdl, CurrentVa, Length,
/// ScatterGatherListSize*, NumberOfMapRegisters*): uma entrada por página
/// coberta (HalpCalculateScatterGatherListSize); mais páginas que
/// MapRegistersPerChannel é STATUS_INSUFFICIENT_RESOURCES.
pub(super) fn calculate_scatter_gather_list(call: &Call) -> Result<u64, KernelError> {
    let (object, mdl, current_va, length, size_output, registers_output) = (call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5), call.arg(6));
    if !is_adapter(object) {
        return Ok(STATUS_INVALID_PARAMETER as u64);
    }
    let (size, pages) = match list_size_for(object, mdl, current_va, length) {
        Ok(result) => result,
        Err(status) => return Ok(status as u64),
    };
    if size_output != 0 {
        // SAFETY: PULONG de saída do driver.
        unsafe { Field::<u32>::at(size_output) }.set(size as u32);
    }
    if registers_output != 0 {
        // SAFETY: PULONG de saída do driver.
        unsafe { Field::<u32>::at(registers_output) }.set(pages as u32);
    }
    Ok(STATUS_SUCCESS)
}

/// BuildScatterGatherList(Adapter, DeviceObject, Mdl, CurrentVa, Length,
/// ExecutionRoutine, Context, WriteToDevice, Buffer, BufferLength).
pub(super) fn build_scatter_gather_list(call: &Call) -> Result<u64, KernelError> {
    let (object, device, mdl, current_va, length, routine, context, write, buffer, buffer_length) = (call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5) as u32, call.arg(6), call.arg(7), call.arg(8) as u8 != 0, call.arg(9), call.arg(10) as u32);
    if !is_adapter(object) || mdl == 0 || routine == 0 || buffer == 0 {
        return Ok(STATUS_INVALID_PARAMETER as u64);
    }
    let (size, pages) = match list_size_for(object, mdl, current_va, length) {
        Ok(result) => result,
        Err(status) => return Ok(status as u64),
    };
    if adapter(object).needs_map_registers.get() != 0 {
        return Ok(super::dma_map_registers::scatter_gather_list(object, device, mdl, current_va, length, routine, context, write, buffer, buffer_length, pages) as u64);
    }
    let Some(runs) = physical_runs(mdl, current_va, length) else { return Ok(STATUS_INVALID_PARAMETER as u64) };
    if !reachable(object, &runs) {
        return Ok(STATUS_INSUFFICIENT_RESOURCES as u64);
    }
    if size > buffer_length as u64 || list_size(runs.len()) > buffer_length as u64 {
        return Ok(STATUS_BUFFER_TOO_SMALL as u64);
    }
    write_list_marked(buffer, &runs, 1);
    native_call::call(routine, &[device, current_irp(device), buffer, context]);
    Ok(STATUS_SUCCESS)
}

/// BuildMdlFromScatterGatherList(Adapter, ScatterGather, OriginalMdl,
/// TargetMdl*): sem buffers de passagem, o MDL de destino é o original.
pub(super) fn build_mdl_from_scatter_gather_list(call: &Call) -> Result<u64, KernelError> {
    let (original, target) = (call.arg(3), call.arg(4));
    if original == 0 || target == 0 {
        return Ok(STATUS_INVALID_PARAMETER as u64);
    }
    // SAFETY: PMDL* de saída do driver.
    unsafe { Field::<u64>::at(target) }.set(original);
    Ok(STATUS_SUCCESS)
}
