//! Os adaptadores de DMA da versão 3 (o HalGetAdapterV3 e o
//! HalpDmaOperationsV3 do ntoskrnl 19041).
//!
//! Uma DEVICE_DESCRIPTION da versão 3 (a que o KMDF pede desde o Windows 8)
//! recebe o mesmo objeto adaptador de `dma` com a tabela HalpDmaOperationsV3:
//! as rotinas da V2 (nas variantes V3 do NT, com o mesmo comportamento nesta
//! plataforma) e as da versão 3. Sem IOMMU e sem memória acima de 4 GB, um
//! bus master enxerga a memória pelo endereço físico: não há registradores
//! de mapa, buffers de passagem nem controlador de DMA de sistema, e as
//! rotinas seguem o caminho de bus master do NT:
//! - GetDmaAdapterInfo: só a DMA_ADAPTER_INFO versão 1 (senão
//!   STATUS_NOT_SUPPORTED); a largura de endereço do adaptador, sem
//!   ReadDmaCounter, ScatterGatherLimit 0xFFFFFFFF, MinimumTransferUnit 1 e
//!   as flags ADAPTER_INFO_SYNCHRONOUS_CALLBACK | ADAPTER_INFO_API_BYPASS (o
//!   adaptador sem registradores de mapa);
//! - GetDmaTransferInfo: DMA_TRANSFER_INFO versões 1 e 2 (senão
//!   STATUS_NOT_SUPPORTED) com as páginas da transferência, os elementos e o
//!   tamanho da SCATTER_GATHER_LIST que o BuildScatterGatherListEx monta; um
//!   MapRegisterCount zero vira 1 (o HalGetDmaTransferInfo);
//! - InitializeDmaTransferContext: o DMA_TRANSFER_CONTEXT (0x80 bytes)
//!   zerado com Version 1 e o bit 1 de +0x24, como o NT;
//! - GetScatterGatherListEx/BuildScatterGatherListEx: o trecho [Offset,
//!   Offset + Length) da cadeia de MDLs vira a lista de trechos físicos; com
//!   ExecutionRoutine ela vai à rotina em DISPATCH_LEVEL (DeviceObject,
//!   CurrentIrp, lista, Context); sem rotina, com DMA_SYNCHRONOUS_CALLBACK, a
//!   lista volta em *ScatterGatherList;
//! - AllocateAdapterChannelEx: o canal está sempre livre; sem rotina (com
//!   DMA_SYNCHRONOUS_CALLBACK) *MapRegisterBase = NULL, senão a rotina de
//!   execução recebe MapRegisterBase NULL em DISPATCH_LEVEL;
//!   CancelAdapterChannel não tem pedido pendente a cancelar (FALSE);
//! - MapTransferEx: o trecho físico do Offset (ou a lista inteira num
//!   ScatterGatherBuffer); FlushAdapterBuffersEx não tem buffers a esvaziar
//!   (MDL nulo ou Offset além do ByteCount é STATUS_INVALID_PARAMETER) e o
//!   FreeAdapterObject com DeallocateObject(KeepRegisters) libera o canal;
//! - CancelMappedTransfer e ConfigureAdapterChannel são do DMA de sistema:
//!   num bus master, STATUS_INVALID_PARAMETER e, sem controlador com rotina
//!   de configuração, STATUS_NOT_IMPLEMENTED;
//! - FlushDmaBuffer: ByteCount e ByteOffset do MDL alinhados ao alinhamento
//!   de DMA; memória coerente, nada a esvaziar;
//! - domínios de DMA: o JoinDmaDomain com o handle nulo cria um domínio
//!   (sem IOMMU, só o agrupamento: o endereço lógico segue o físico) e o
//!   adaptador entra nele; GetDmaDomain o devolve, LeaveDmaDomain o solta
//!   (STATUS_UNSUCCESSFUL fora de um domínio), e o
//!   AllocateDomainCommonBuffer aloca como o buffer comum, só para um
//!   adaptador do domínio dado;
//! - AllocateCommonBufferWithBounds e os vetores de buffers comuns
//!   (AllocateCommonBufferVector, GetCommonBufferFromVectorByIndex,
//!   FreeCommonBufferFromVector, FreeCommonBufferVector) usam a mesma
//!   memória contígua da arena do kernel (abaixo de 96 MB).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::amd64::routine_stubs::{self, Routine};
use super::dma;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{DmaAdapterInfo, DmaOperations, Mdl};
use crate::ntos::init::exports::Call;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::{KernelError, SpinLock};

const STATUS_SUCCESS: u64 = 0;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
/// DMA_SYNCHRONOUS_CALLBACK.
const DMA_SYNCHRONOUS_CALLBACK: u32 = 1;
/// ADAPTER_INFO_SYNCHRONOUS_CALLBACK | ADAPTER_INFO_API_BYPASS.
const ADAPTER_INFO_BUS_MASTER_FLAGS: u32 = 3;
/// DMA_TRANSFER_CONTEXT_SIZE_V1.
const TRANSFER_CONTEXT_SIZE: u64 = 0x80;
/// Limite da arena dos buffers comuns (`dma::common_buffer`).
const COMMON_BUFFER_LIMIT: u64 = 0x0600_0000;

/// O estado V3 de um adaptador: o domínio de DMA (a largura de endereço
/// fica no objeto de `dma`).
#[derive(Clone, Copy)]
struct Adapter {
    domain: u64,
}

static ADAPTERS: SpinLock<BTreeMap<u64, Adapter>> = SpinLock::new(BTreeMap::new());
/// Domínios criados pelo JoinDmaDomain (handles opacos).
static DOMAINS: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());
/// Vetores de buffers comuns: handle -> (VA, endereço lógico) de cada um.
static VECTORS: SpinLock<BTreeMap<u64, Vec<(u64, u64)>>> = SpinLock::new(BTreeMap::new());

/// Rotinas por ponteiro da tabela V3, na ordem dos slots desta faixa (as
/// rotinas comuns à V2 já estão na faixa de `dma`).
pub const ROUTINES: &[Routine] = &[
    Routine { name: "HalFreeCommonBufferV3", handler: dma::free_common_buffer },
    Routine { name: "HalRealAllocateAdapterChannelV3", handler: dma::allocate_adapter_channel },
    Routine { name: "HalReadDmaCounterV3", handler: dma::read_dma_counter },
    Routine { name: "HalCalculateScatterGatherListSizeV3", handler: dma::calculate_scatter_gather_list },
    Routine { name: "HalBuildScatterGatherListV3", handler: dma::build_scatter_gather_list },
    Routine { name: "HalBuildMdlFromScatterGatherListV3", handler: dma::build_mdl_from_scatter_gather_list },
    Routine { name: "HalGetDmaAdapterInfo", handler: get_dma_adapter_info },
    Routine { name: "HalGetDmaTransferInfo", handler: get_dma_transfer_info },
    Routine { name: "HalInitializeDmaTransferContext", handler: initialize_dma_transfer_context },
    Routine { name: "HalAllocateCommonBufferExV3", handler: dma::allocate_common_buffer_ex },
    Routine { name: "HalAllocateAdapterChannelEx", handler: allocate_adapter_channel_ex },
    Routine { name: "HalConfigureAdapterChannel", handler: configure_adapter_channel },
    Routine { name: "HalCancelAdapterChannel", handler: cancel_adapter_channel },
    Routine { name: "HalMapTransferEx", handler: map_transfer_ex },
    Routine { name: "HalGetScatterGatherListEx", handler: get_scatter_gather_list_ex },
    Routine { name: "HalBuildScatterGatherListEx", handler: build_scatter_gather_list_ex },
    Routine { name: "HalFlushAdapterBuffersEx", handler: flush_adapter_buffers_ex },
    Routine { name: "HalFreeAdapterObject", handler: free_adapter_object },
    Routine { name: "HalCancelMappedTransfer", handler: cancel_mapped_transfer },
    Routine { name: "HalAllocateDomainCommonBuffer", handler: allocate_domain_common_buffer },
    Routine { name: "HalFlushDmaBuffer", handler: flush_dma_buffer },
    Routine { name: "HalJoinDmaDomain", handler: join_dma_domain },
    Routine { name: "HalLeaveDmaDomain", handler: leave_dma_domain },
    Routine { name: "HalGetDmaDomain", handler: get_dma_domain },
    Routine { name: "HalAllocateCommonBufferWithBounds", handler: allocate_common_buffer_with_bounds },
    Routine { name: "HalAllocateCommonBufferVector", handler: allocate_common_buffer_vector },
    Routine { name: "HalGetCommonBufferFromVectorByIndex", handler: get_common_buffer_from_vector_by_index },
    Routine { name: "HalFreeCommonBufferFromVector", handler: free_common_buffer_from_vector },
    Routine { name: "HalFreeCommonBufferVector", handler: free_common_buffer_vector },
];

/// A tabela HalpDmaOperationsV3 (alocada uma vez).
static OPERATIONS: SpinLock<u64> = SpinLock::new(0);

pub fn operations() -> Result<u64, KernelError> {
    let mut table = OPERATIONS.lock();
    if *table != 0 {
        return Ok(*table);
    }
    let address = guest::alloc_bytes(DmaOperations::SIZE);
    // SAFETY: bloco zerado recém-alocado do tamanho da tabela.
    let operations = unsafe { DmaOperations::at(address) };
    let slots: [(&Field<u64>, &str); 38] = [
        (&operations.put_dma_adapter, "HalPutDmaAdapter"),
        (&operations.allocate_common_buffer, "HalAllocateCommonBuffer"),
        (&operations.free_common_buffer, "HalFreeCommonBufferV3"),
        (&operations.allocate_adapter_channel, "HalRealAllocateAdapterChannelV3"),
        (&operations.flush_adapter_buffers, "IoFlushAdapterBuffers"),
        (&operations.free_adapter_channel, "IoFreeAdapterChannel"),
        (&operations.free_map_registers, "IoFreeMapRegisters"),
        (&operations.map_transfer, "IoMapTransfer"),
        (&operations.get_dma_alignment, "HalGetDmaAlignment"),
        (&operations.read_dma_counter, "HalReadDmaCounterV3"),
        (&operations.get_scatter_gather_list, "HalGetScatterGatherList"),
        (&operations.put_scatter_gather_list, "HalPutScatterGatherList"),
        (&operations.calculate_scatter_gather_list, "HalCalculateScatterGatherListSizeV3"),
        (&operations.build_scatter_gather_list, "HalBuildScatterGatherListV3"),
        (&operations.build_mdl_from_scatter_gather_list, "HalBuildMdlFromScatterGatherListV3"),
        (&operations.get_dma_adapter_info, "HalGetDmaAdapterInfo"),
        (&operations.get_dma_transfer_info, "HalGetDmaTransferInfo"),
        (&operations.initialize_dma_transfer_context, "HalInitializeDmaTransferContext"),
        (&operations.allocate_common_buffer_ex, "HalAllocateCommonBufferExV3"),
        (&operations.allocate_adapter_channel_ex, "HalAllocateAdapterChannelEx"),
        (&operations.configure_adapter_channel, "HalConfigureAdapterChannel"),
        (&operations.cancel_adapter_channel, "HalCancelAdapterChannel"),
        (&operations.map_transfer_ex, "HalMapTransferEx"),
        (&operations.get_scatter_gather_list_ex, "HalGetScatterGatherListEx"),
        (&operations.build_scatter_gather_list_ex, "HalBuildScatterGatherListEx"),
        (&operations.flush_adapter_buffers_ex, "HalFlushAdapterBuffersEx"),
        (&operations.free_adapter_object, "HalFreeAdapterObject"),
        (&operations.cancel_mapped_transfer, "HalCancelMappedTransfer"),
        (&operations.allocate_domain_common_buffer, "HalAllocateDomainCommonBuffer"),
        (&operations.flush_dma_buffer, "HalFlushDmaBuffer"),
        (&operations.join_dma_domain, "HalJoinDmaDomain"),
        (&operations.leave_dma_domain, "HalLeaveDmaDomain"),
        (&operations.get_dma_domain, "HalGetDmaDomain"),
        (&operations.allocate_common_buffer_with_bounds, "HalAllocateCommonBufferWithBounds"),
        (&operations.allocate_common_buffer_vector, "HalAllocateCommonBufferVector"),
        (&operations.get_common_buffer_from_vector_by_index, "HalGetCommonBufferFromVectorByIndex"),
        (&operations.free_common_buffer_from_vector, "HalFreeCommonBufferFromVector"),
        (&operations.free_common_buffer_vector, "HalFreeCommonBufferVector"),
    ];
    operations.size.set(DmaOperations::SIZE as u32);
    for (slot, name) in slots {
        slot.set(routine_stubs::address(name)?);
    }
    *table = address;
    Ok(address)
}

/// Um adaptador criado com a DEVICE_DESCRIPTION da versão 3.
pub fn register(adapter: u64) {
    ADAPTERS.lock().insert(adapter, Adapter { domain: 0 });
}

pub fn unregister(adapter: u64) {
    ADAPTERS.lock().remove(&adapter);
}

fn state(adapter: u64) -> Option<Adapter> {
    ADAPTERS.lock().get(&adapter).copied()
}

fn out32(address: u64) -> &'static Field<u32> {
    // SAFETY: ULONG de saída de um chamador de modo kernel.
    unsafe { Field::<u32>::at(address) }
}

fn out64(address: u64) -> &'static Field<u64> {
    // SAFETY: ponteiro/PHYSICAL_ADDRESS de saída de um chamador de modo kernel.
    unsafe { Field::<u64>::at(address) }
}

/// O endereço virtual do byte `offset` da cadeia de MDLs (o Offset das
/// rotinas Ex conta a partir do início do primeiro MDL).
fn offset_address(mdl: u64, offset: u64) -> Option<u64> {
    let mut remaining = offset;
    let mut current = mdl;
    while current != 0 {
        // SAFETY: MDL da cadeia do chamador.
        let descriptor = unsafe { Mdl::at(current) };
        let count = descriptor.byte_count.get() as u64;
        if remaining < count || (remaining == count && descriptor.next.get() == 0) {
            return Some(descriptor.start_va.get() + descriptor.byte_offset.get() as u64 + remaining);
        }
        remaining -= count;
        current = descriptor.next.get();
    }
    None
}

/// Trechos físicos de [Offset, Offset + Length) da cadeia.
fn runs_at(adapter: u64, mdl: u64, offset: u64, length: u32) -> Result<Vec<(u64, u32)>, u32> {
    let address = offset_address(mdl, offset).ok_or(STATUS_INVALID_PARAMETER)?;
    let runs = dma::physical_runs(mdl, address, length).ok_or(STATUS_INVALID_PARAMETER)?;
    if !dma::reachable(adapter, &runs) {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    Ok(runs)
}

/// GetDmaAdapterInfo(Adapter, *DMA_ADAPTER_INFO) do HalGetDmaAdapterInfo.
fn get_dma_adapter_info(call: &Call) -> Result<u64, KernelError> {
    let (adapter, information) = (call.arg(1), call.arg(2));
    if state(adapter).is_none() || information == 0 {
        return Ok(STATUS_INVALID_PARAMETER as u64);
    }
    // SAFETY: DMA_ADAPTER_INFO do driver chamador.
    let information = unsafe { DmaAdapterInfo::at(information) };
    if information.version.get() > 1 {
        return Ok(STATUS_NOT_SUPPORTED as u64);
    }
    let v1 = &information.v1;
    v1.read_dma_counter_available.set(0);
    v1.scatter_gather_limit.set(u32::MAX);
    v1.dma_address_width.set(dma::adapter(adapter).address_width.get());
    v1.flags.set(ADAPTER_INFO_BUS_MASTER_FLAGS);
    v1.minimum_transfer_unit.set(1);
    Ok(STATUS_SUCCESS)
}

/// GetDmaTransferInfo(Adapter, Mdl, Offset, Length, WriteOnly,
/// *DMA_TRANSFER_INFO).
fn get_dma_transfer_info(call: &Call) -> Result<u64, KernelError> {
    let (adapter, mdl, offset, length, information) = (call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(6));
    let version = out32(information).get();
    if version > 2 {
        return Ok(STATUS_NOT_SUPPORTED as u64);
    }
    if mdl == 0 || state(adapter).is_none() {
        return Ok(STATUS_INVALID_PARAMETER as u64);
    }
    let Some(address) = offset_address(mdl, offset) else { return Ok(STATUS_INVALID_PARAMETER as u64) };
    let runs = match runs_at(adapter, mdl, offset, length) {
        Ok(runs) => runs,
        Err(status) => return Ok(status as u64),
    };
    let pages = ((address & 0xFFF) + length as u64).div_ceil(0x1000) as u32;
    // V1: MapRegisterCount, ScatterGatherElementCount, ScatterGatherListSize;
    // V2 acrescenta LogicalPageCount.
    out32(information + 4).set(pages.max(1));
    out32(information + 8).set(runs.len() as u32);
    out32(information + 0xC).set(dma::list_size(runs.len().max(1)) as u32);
    if version == 2 {
        out32(information + 0x10).set(pages);
    }
    Ok(STATUS_SUCCESS)
}

/// InitializeDmaTransferContext(Adapter, DmaTransferContext).
fn initialize_dma_transfer_context(call: &Call) -> Result<u64, KernelError> {
    let context = call.arg(2);
    guest::write_bytes(context + 4, &[0u8; (TRANSFER_CONTEXT_SIZE - 4) as usize]);
    out32(context + 0x24).set(out32(context + 0x24).get() | 2);
    out32(context).set(1);
    Ok(STATUS_SUCCESS)
}

/// AllocateAdapterChannelEx(Adapter, DeviceObject, DmaTransferContext,
/// NumberOfMapRegisters, Flags, ExecutionRoutine, ExecutionContext,
/// *MapRegisterBase).
fn allocate_adapter_channel_ex(call: &Call) -> Result<u64, KernelError> {
    let (adapter, device, count, flags, routine, context, base) = (call.arg(1), call.arg(2), call.arg(4) as u32, call.arg(5) as u32, call.arg(6), call.arg(7), call.arg(8));
    if state(adapter).is_none() || count > dma::adapter(adapter).map_registers.get() {
        return Ok(STATUS_INSUFFICIENT_RESOURCES as u64);
    }
    if routine == 0 {
        if flags & DMA_SYNCHRONOUS_CALLBACK == 0 || base == 0 {
            return Ok(STATUS_INVALID_PARAMETER as u64);
        }
        out64(base).set(0);
        return Ok(STATUS_SUCCESS);
    }
    dma::call_at_dispatch(routine, &[device, dma::current_irp(device), 0, context]);
    Ok(STATUS_SUCCESS)
}

/// ConfigureAdapterChannel(Adapter, FunctionNumber, Context): só um
/// controlador de DMA de sistema tem canais a configurar.
fn configure_adapter_channel(_: &Call) -> Result<u64, KernelError> {
    Ok(STATUS_NOT_IMPLEMENTED as u64)
}

/// CancelAdapterChannel(Adapter, DeviceObject, DmaTransferContext): a
/// alocação é sempre imediata, nada fica pendente.
fn cancel_adapter_channel(_: &Call) -> Result<u64, KernelError> {
    Ok(0)
}

/// MapTransferEx(Adapter, Mdl, MapRegisterBase, Offset, DeviceOffset,
/// *Length, WriteToDevice, ScatterGatherBuffer, ScatterGatherBufferLength,
/// DmaCompletionRoutine, CompletionContext).
fn map_transfer_ex(call: &Call) -> Result<u64, KernelError> {
    let (adapter, mdl, offset, length_pointer, buffer, buffer_length) = (call.arg(1), call.arg(2), call.arg(4), call.arg(6), call.arg(8), call.arg(9) as u32);
    if mdl == 0 || length_pointer == 0 || state(adapter).is_none() {
        return Ok(STATUS_INVALID_PARAMETER as u64);
    }
    let length = out32(length_pointer);
    let runs = match runs_at(adapter, mdl, offset, length.get()) {
        Ok(runs) => runs,
        Err(status) => return Ok(status as u64),
    };
    if buffer == 0 {
        // Sem lista: o primeiro trecho físico, como o MapTransfer.
        length.set(runs.first().map_or(0, |&(_, size)| size));
        return Ok(STATUS_SUCCESS);
    }
    if dma::list_size(runs.len()) > buffer_length as u64 {
        return Ok(STATUS_BUFFER_TOO_SMALL as u64);
    }
    dma::write_list(buffer, &runs);
    Ok(STATUS_SUCCESS)
}

/// A lista de [Offset, Offset + Length) entregue como o NT entrega: à
/// rotina de execução em DISPATCH_LEVEL, ou em *ScatterGatherList.
fn deliver_list(device: u64, flags: u32, routine: u64, context: u64, list: u64, output: u64) -> u64 {
    if routine != 0 {
        dma::call_at_dispatch(routine, &[device, dma::current_irp(device), list, context]);
        return STATUS_SUCCESS;
    }
    if flags & DMA_SYNCHRONOUS_CALLBACK == 0 || output == 0 {
        return STATUS_INVALID_PARAMETER as u64;
    }
    out64(output).set(list);
    STATUS_SUCCESS
}

/// GetScatterGatherListEx(Adapter, DeviceObject, DmaTransferContext, Mdl,
/// Offset, Length, Flags, ExecutionRoutine, Context, WriteToDevice,
/// DmaCompletionRoutine, CompletionContext, *ScatterGatherList).
fn get_scatter_gather_list_ex(call: &Call) -> Result<u64, KernelError> {
    let (adapter, device, mdl, offset, length, flags, routine, context, output) = (call.arg(1), call.arg(2), call.arg(4), call.arg(5), call.arg(6) as u32, call.arg(7) as u32, call.arg(8), call.arg(9), call.arg(13));
    if mdl == 0 || state(adapter).is_none() {
        return Ok(STATUS_INVALID_PARAMETER as u64);
    }
    let runs = match runs_at(adapter, mdl, offset, length) {
        Ok(runs) => runs,
        Err(status) => return Ok(status as u64),
    };
    let list = guest::alloc_bytes(dma::list_size(runs.len()));
    if list == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES as u64);
    }
    dma::write_list(list, &runs);
    dma::own_list(list);
    let status = deliver_list(device, flags, routine, context, list, output);
    if status != STATUS_SUCCESS {
        dma::release_list(list);
    }
    Ok(status)
}

/// BuildScatterGatherListEx(Adapter, DeviceObject, DmaTransferContext, Mdl,
/// Offset, Length, Flags, ExecutionRoutine, Context, WriteToDevice,
/// ScatterGatherBuffer, ScatterGatherLength, DmaCompletionRoutine,
/// CompletionContext, *ScatterGatherList).
fn build_scatter_gather_list_ex(call: &Call) -> Result<u64, KernelError> {
    let (adapter, device, mdl, offset, length, flags, routine, context, buffer, buffer_length, output) =
        (call.arg(1), call.arg(2), call.arg(4), call.arg(5), call.arg(6) as u32, call.arg(7) as u32, call.arg(8), call.arg(9), call.arg(11), call.arg(12) as u32, call.arg(15));
    if mdl == 0 || buffer == 0 || state(adapter).is_none() {
        return Ok(STATUS_INVALID_PARAMETER as u64);
    }
    let runs = match runs_at(adapter, mdl, offset, length) {
        Ok(runs) => runs,
        Err(status) => return Ok(status as u64),
    };
    if dma::list_size(runs.len()) > buffer_length as u64 {
        return Ok(STATUS_BUFFER_TOO_SMALL as u64);
    }
    dma::write_list(buffer, &runs);
    Ok(deliver_list(device, flags, routine, context, buffer, output))
}

/// FlushAdapterBuffersEx(Adapter, Mdl, MapRegisterBase, Offset, Length,
/// WriteToDevice): sem registradores de mapa nem buffers de passagem, nada
/// a copiar; MDL nulo ou Offset além do ByteCount é STATUS_INVALID_PARAMETER.
fn flush_adapter_buffers_ex(call: &Call) -> Result<u64, KernelError> {
    let (mdl, offset) = (call.arg(2), call.arg(4));
    if mdl == 0 {
        return Ok(STATUS_INVALID_PARAMETER as u64);
    }
    // SAFETY: MDL do driver chamador.
    if offset >= unsafe { Mdl::at(mdl) }.byte_count.get() as u64 {
        return Ok(STATUS_INVALID_PARAMETER as u64);
    }
    Ok(STATUS_SUCCESS)
}

/// FreeAdapterObject(Adapter, AllocationAction): DeallocateObject (2) e
/// DeallocateObjectKeepRegisters (3) liberam o canal.
fn free_adapter_object(call: &Call) -> Result<u64, KernelError> {
    if matches!(call.arg(2), 2 | 3) {
        return dma::free_adapter_channel(call);
    }
    Ok(0)
}

/// CancelMappedTransfer(Adapter, DmaTransferContext): só DMA de sistema.
fn cancel_mapped_transfer(call: &Call) -> Result<u64, KernelError> {
    Ok(if dma::adapter(call.arg(1)).master.get() != 0 { STATUS_INVALID_PARAMETER as u64 } else { STATUS_SUCCESS })
}

/// FlushDmaBuffer(Adapter, Mdl, ReadOperation): ByteCount e ByteOffset
/// alinhados ao alinhamento de DMA (HalGetDmaAlignment); o x64 é coerente, o
/// KeFlushIoBuffers não tem o que fazer.
fn flush_dma_buffer(call: &Call) -> Result<u64, KernelError> {
    let (adapter, mdl) = (call.arg(1), call.arg(2));
    if adapter == 0 || mdl == 0 {
        return Ok(STATUS_INVALID_PARAMETER as u64);
    }
    let mask = dma::get_dma_alignment(call)? as u32 - 1;
    // SAFETY: MDL do driver chamador.
    let descriptor = unsafe { Mdl::at(mdl) };
    if descriptor.byte_count.get() & mask != 0 || descriptor.byte_offset.get() & mask != 0 {
        return Ok(STATUS_INVALID_PARAMETER as u64);
    }
    Ok(STATUS_SUCCESS)
}

/// JoinDmaDomain(Adapter, DomainHandle): o handle nulo cria um domínio.
fn join_dma_domain(call: &Call) -> Result<u64, KernelError> {
    let (adapter, handle) = (call.arg(1), call.arg(2));
    let mut adapters = ADAPTERS.lock();
    let Some(state) = adapters.get_mut(&adapter) else { return Ok(STATUS_INVALID_PARAMETER as u64) };
    if state.domain != 0 {
        return Ok(STATUS_INVALID_PARAMETER as u64);
    }
    let domain = if handle == 0 || handle == u64::MAX {
        let created = guest::alloc_bytes(0x10);
        DOMAINS.lock().push(created);
        created
    } else if DOMAINS.lock().contains(&handle) {
        handle
    } else {
        return Ok(STATUS_INVALID_PARAMETER as u64);
    };
    state.domain = domain;
    Ok(STATUS_SUCCESS)
}

/// LeaveDmaDomain(Adapter).
fn leave_dma_domain(call: &Call) -> Result<u64, KernelError> {
    let mut adapters = ADAPTERS.lock();
    let Some(state) = adapters.get_mut(&call.arg(1)) else { return Ok(STATUS_INVALID_PARAMETER as u64) };
    if state.domain == 0 {
        return Ok(STATUS_UNSUCCESSFUL as u64);
    }
    state.domain = 0;
    Ok(STATUS_SUCCESS)
}

/// GetDmaDomain(Adapter): o domínio do adaptador ou NULL.
fn get_dma_domain(call: &Call) -> Result<u64, KernelError> {
    Ok(state(call.arg(1)).map_or(0, |state| state.domain))
}

/// AllocateDomainCommonBuffer(Adapter, DomainHandle, MaximumAddress*,
/// Length, Flags, CacheType*, PreferredNode, LogicalAddress*,
/// VirtualAddress*).
fn allocate_domain_common_buffer(call: &Call) -> Result<u64, KernelError> {
    let (adapter, domain, maximum, length, logical, virtual_address) = (call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(8), call.arg(9));
    if domain == 0 || state(adapter).map(|state| state.domain) != Some(domain) || logical == 0 || virtual_address == 0 {
        return Ok(STATUS_INVALID_PARAMETER as u64);
    }
    if maximum != 0 && out64(maximum).get() < COMMON_BUFFER_LIMIT {
        return Ok(STATUS_INSUFFICIENT_RESOURCES as u64);
    }
    let va = dma::common_buffer(length, logical);
    out64(virtual_address).set(va);
    Ok(if va == 0 { STATUS_INSUFFICIENT_RESOURCES as u64 } else { STATUS_SUCCESS })
}

/// AllocateCommonBufferWithBounds(Adapter, MinimumAddress*, MaximumAddress*,
/// Length, Flags, CacheType*, PreferredNode, LogicalAddress*).
fn allocate_common_buffer_with_bounds(call: &Call) -> Result<u64, KernelError> {
    let (minimum, maximum, length, logical) = (call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(8));
    let low = if minimum != 0 { out64(minimum).get() } else { 0 };
    let high = if maximum != 0 { out64(maximum).get() } else { u64::MAX };
    if low >= COMMON_BUFFER_LIMIT || high < COMMON_BUFFER_LIMIT {
        return Ok(0);
    }
    Ok(dma::common_buffer(length, logical))
}

/// AllocateCommonBufferVector(Adapter, LowAddress, HighAddress, CacheType,
/// IdealNode, Flags, NumberOfElements, SizeOfElements, *VectorOut).
fn allocate_common_buffer_vector(call: &Call) -> Result<u64, KernelError> {
    let (low, high, count, size, output) = (call.arg(2), call.arg(3), call.arg(7) as u32, call.arg(8), call.arg(9));
    if output == 0 || count == 0 || size == 0 || size > u32::MAX as u64 {
        return Ok(STATUS_INVALID_PARAMETER as u64);
    }
    if low >= COMMON_BUFFER_LIMIT || high < COMMON_BUFFER_LIMIT {
        return Ok(STATUS_INSUFFICIENT_RESOURCES as u64);
    }
    let logical = guest::alloc_bytes(8);
    let mut buffers = Vec::new();
    for _ in 0..count {
        let va = dma::common_buffer(size as u32, logical);
        if va == 0 {
            for (va, _) in buffers {
                guest::free_bytes(va);
            }
            guest::free_bytes(logical);
            return Ok(STATUS_INSUFFICIENT_RESOURCES as u64);
        }
        buffers.push((va, out64(logical).get()));
    }
    guest::free_bytes(logical);
    let handle = guest::alloc_bytes(0x10);
    VECTORS.lock().insert(handle, buffers);
    out64(output).set(handle);
    Ok(STATUS_SUCCESS)
}

/// GetCommonBufferFromVectorByIndex(Adapter, Vector, Index, *VirtualAddress,
/// *LogicalAddress).
fn get_common_buffer_from_vector_by_index(call: &Call) -> Result<u64, KernelError> {
    let (vector, index, virtual_address, logical) = (call.arg(2), call.arg(3) as usize, call.arg(4), call.arg(5));
    let entry = VECTORS.lock().get(&vector).and_then(|buffers| buffers.get(index).copied());
    let (va, address) = entry.unwrap_or((0, 0));
    if virtual_address != 0 {
        out64(virtual_address).set(va);
    }
    if logical != 0 {
        out64(logical).set(address);
    }
    Ok(0)
}

/// FreeCommonBufferFromVector(Adapter, Vector, Index).
fn free_common_buffer_from_vector(call: &Call) -> Result<u64, KernelError> {
    let (vector, index) = (call.arg(2), call.arg(3) as usize);
    let freed = VECTORS.lock().get_mut(&vector).and_then(|buffers| buffers.get_mut(index).map(|entry| core::mem::replace(entry, (0, 0))));
    if let Some((va, _)) = freed.filter(|&(va, _)| va != 0) {
        guest::free_bytes(va);
    }
    Ok(0)
}

/// FreeCommonBufferVector(Adapter, Vector).
fn free_common_buffer_vector(call: &Call) -> Result<u64, KernelError> {
    let vector = call.arg(2);
    if let Some(buffers) = VECTORS.lock().remove(&vector) {
        for (va, _) in buffers.into_iter().filter(|&(va, _)| va != 0) {
            guest::free_bytes(va);
        }
        guest::free_bytes(vector);
    }
    Ok(0)
}
