//! Processadores, grupos e nós vistos pelos drivers.
//!
//! O código dos drivers roda no processador de boot (KeGetCurrentProcessorNumber
//! é 0). Os processadores ativos são os da MADT que subiram, todos no grupo 0
//! e no nó NUMA 0 (sem SRAT). KeNumberProcessors é uma célula u32 gravada no
//! primeiro acesso, depois do SMP.

use core::sync::atomic::{AtomicU64, Ordering};

use super::smp;
use crate::ntos::inc::status::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use crate::ntos::inc::types::{Field, GroupAffinity, NtStruct, ProcessorNumber};
use crate::ntos::mm::guest_memory as guest;

/// ALL_PROCESSOR_GROUPS.
const ALL_PROCESSOR_GROUPS: u32 = 0xFFFF;

/// KeNumberProcessors: célula u32 gravada no primeiro acesso (depois do SMP).
static NUMBER_PROCESSORS: AtomicU64 = AtomicU64::new(0);

/// KeNumberProcessors: endereço da célula do export de dados.
pub fn number_processors_cell() -> u64 {
    let current = NUMBER_PROCESSORS.load(Ordering::Acquire);
    if current != 0 {
        return current;
    }
    let pointer = guest::alloc_bytes(4);
    // SAFETY: célula recém-alocada do export de dados.
    unsafe { Field::<u32>::at(pointer) }.set(smp::online_cpu_count() as u32);
    match NUMBER_PROCESSORS.compare_exchange(0, pointer, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => pointer,
        Err(existing) => {
            guest::free_bytes(pointer);
            existing
        }
    }
}

/// Bit N = processador N ativo (o BSP sempre).
pub fn active_mask() -> u64 {
    let mut mask = 1u64;
    for slot in 0..smp::ap_slot_count().min(63) as u32 {
        mask |= 1u64 << (slot + 1);
    }
    mask
}

/// GROUP_AFFINITY zerada com a máscara pedida.
pub fn write_group_affinity(pointer: u64, mask: u64) {
    // SAFETY: PGROUP_AFFINITY de saída do chamador.
    let affinity = unsafe { GroupAffinity::at(pointer) };
    affinity.mask.set(mask);
    affinity.group.set(0);
    for reserved in &affinity.reserved {
        reserved.set(0);
    }
}

/// KeGetCurrentProcessorNumber: todo código de driver roda no BSP.
pub fn current_processor_number() -> u32 {
    0
}

/// KeGetCurrentProcessorNumberEx: PROCESSOR_NUMBER do BSP (grupo 0, número 0)
/// na saída opcional; devolve o índice 0.
pub fn current_processor_number_ex(processor_number: u64) -> u32 {
    if processor_number != 0 {
        write_processor_number(processor_number, 0);
    }
    0
}

/// PROCESSOR_NUMBER de saída do chamador: grupo 0, número e Reserved zero.
fn write_processor_number(pointer: u64, number: u8) {
    // SAFETY: PPROCESSOR_NUMBER de saída do chamador.
    let target = unsafe { ProcessorNumber::at(pointer) };
    target.group.set(0);
    target.number.set(number);
    target.reserved.set(0);
}

/// KeQueryActiveProcessorCount.
pub fn active_processor_count() -> u64 {
    smp::online_cpu_count() as u64
}

/// KeQueryActiveProcessorCountEx: CPUs online; grupo inexistente devolve 0.
pub fn active_processor_count_ex(group: u32) -> u64 {
    if group != 0 && group != ALL_PROCESSOR_GROUPS {
        return 0;
    }
    smp::online_cpu_count() as u64
}

/// KeQueryActiveProcessors: bit N = CPU N online (o BSP sempre), em 32 bits
/// estendidos com sinal.
pub fn active_processors() -> u64 {
    let mut mask = 1u32;
    for slot in 0..smp::ap_slot_count() as u32 {
        mask |= 1u32.wrapping_shl(slot + 1);
    }
    mask as i32 as i64 as u64
}

/// KeGetProcessorNumberFromIndex: PROCESSOR_NUMBER (grupo 0) do índice na
/// saída opcional; índice fora dos processadores online é inválido.
/// Devolve o NTSTATUS.
pub fn processor_number_from_index(index: u64, processor_number: u64) -> u32 {
    if index >= smp::online_cpu_count() as u64 {
        return STATUS_INVALID_PARAMETER;
    }
    if processor_number != 0 {
        write_processor_number(processor_number, index as u8);
    }
    STATUS_SUCCESS
}

/// KeQueryMaximumProcessorCount: CPUs da MADT.
pub fn maximum_processor_count() -> u64 {
    smp::discovered_cpu_count() as u64
}

/// KeQueryMaximumProcessorCountEx: CPUs da MADT no grupo 0 (ou ALL_GROUPS).
pub fn maximum_processor_count_ex(group: u32) -> u64 {
    if group != 0 && group != ALL_PROCESSOR_GROUPS {
        return 0;
    }
    smp::discovered_cpu_count() as u64
}

/// KeQueryActiveGroupCount / KeQueryMaximumGroupCount: só o grupo 0.
pub fn group_count() -> u64 {
    1
}

/// KeQueryGroupAffinity: os processadores ativos no grupo 0; outro grupo, 0.
pub fn group_affinity(group: u16) -> u64 {
    if group == 0 { active_mask() } else { 0 }
}

/// KeGetCurrentNodeNumber / KeQueryHighestNodeNumber: sem SRAT, tudo no nó 0.
pub fn node_number() -> u64 {
    0
}

/// KeQueryNodeActiveAffinity: nó 0 com todos os processadores ativos; outro
/// nó volta vazio. As duas saídas são opcionais.
pub fn query_node_active_affinity(node: u16, affinity: u64, count: u64) {
    let (mask, processors) = if node == 0 { (active_mask(), smp::online_cpu_count() as u16) } else { (0, 0) };
    if affinity != 0 {
        write_group_affinity(affinity, mask);
    }
    if count != 0 {
        // SAFETY: PUSHORT Count opcional do chamador.
        unsafe { Field::<u16>::at(count) }.set(processors);
    }
}

/// KeQueryNodeMaximumProcessorCount: CPUs da MADT no nó 0; outro nó, 0.
pub fn node_maximum_processor_count(node: u16) -> u64 {
    if node == 0 { smp::discovered_cpu_count() as u64 } else { 0 }
}

// ---- índice de processador e notificações de troca de processadores -------
//
// (append de `ke-processors` ao ke/processor_group.rs. Usa o que o arquivo
// já importa — `smp`, `guest`, `Field`, `NtStruct`, `ProcessorNumber` — e
// caminhos completos para o resto, sem linhas `use` novas.)

/// INVALID_PROCESSOR_INDEX.
const INVALID_PROCESSOR_INDEX: u64 = 0xFFFF_FFFF;
/// MAXIMUM_PROC_PER_GROUP.
const MAXIMUM_PROCESSORS_PER_GROUP: u8 = 64;
/// Objeto aberto pelo KeRegisterProcessorChangeCallback real (criado no
/// boot por `ex::callbacks::init`).
const PROCESSOR_ADD_CALLBACK: &str = "\\Callback\\ProcessorAdd";
/// OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, como no binário.
const PROCESSOR_ADD_ATTRIBUTES: u32 = 0x240;

/// KeGetProcessorIndexFromNumber: Reserved != 0, grupo >= KiMaximumGroups ou
/// número >= 64 são inválidos; (0, 0) é o índice 0; senão a
/// KiProcessorNumberToIndexMappingTable do grupo 0 (número = índice dos
/// processadores ativos; entrada vazia = inválido).
pub fn processor_index_from_number(number: &ProcessorNumber) -> u64 {
    let (group, processor) = (number.group.get(), number.number.get());
    if number.reserved.get() != 0 {
        return INVALID_PROCESSOR_INDEX;
    }
    if group == 0 && processor == 0 {
        return 0;
    }
    if group as u64 >= group_count() || processor >= MAXIMUM_PROCESSORS_PER_GROUP {
        return INVALID_PROCESSOR_INDEX;
    }
    if (processor as usize) < smp::online_cpu_count() { processor as u64 } else { INVALID_PROCESSOR_INDEX }
}

/// O OBJECT_ATTRIBUTES + UNICODE_STRING + saída que o binário monta na pilha
/// para o ExCreateCallback (layout do OpenNT, só dentro deste arquivo).
#[repr(C)]
struct CallbackOpenBlock {
    attributes: crate::ntos::inc::types::ObjectAttributes,
    name: crate::ntos::inc::types::UnicodeString,
    callback_object: Field<u64>,
}

// SAFETY: #[repr(C)] só de células e estruturas do NT.
unsafe impl NtStruct for CallbackOpenBlock {}

const _: () = {
    assert!(core::mem::size_of::<CallbackOpenBlock>() == 0x48);
    assert!(core::mem::offset_of!(CallbackOpenBlock, name) == 0x30);
    assert!(core::mem::offset_of!(CallbackOpenBlock, callback_object) == 0x40);
};

/// Contexto entregue ao callback: o KE_PROCESSOR_CHANGE_NOTIFY_CONTEXT
/// público, o id do HAL que o binário grava logo depois
/// (HalGetProcessorIdByNtNumber: o APIC id) e o NTSTATUS de saída do callback
/// (layout do OpenNT, só dentro deste arquivo).
#[repr(C)]
struct ProcessorChangeBlock {
    context: crate::ntos::inc::types::extra_keex::KeProcessorChangeNotifyContext,
    hal_processor_id: Field<u32>,
    _pad_14: crate::ntos::inc::field::Reserved<4>,
    operation_status: Field<i32>,
    _pad_1c: crate::ntos::inc::field::Reserved<4>,
}

// SAFETY: #[repr(C)] só de células e estruturas do NT.
unsafe impl NtStruct for ProcessorChangeBlock {}

const _: () = {
    assert!(core::mem::size_of::<ProcessorChangeBlock>() == 0x20);
    assert!(core::mem::offset_of!(ProcessorChangeBlock, hal_processor_id) == 0x10);
    assert!(core::mem::offset_of!(ProcessorChangeBlock, operation_status) == 0x18);
};

/// ExCreateCallback(\Callback\ProcessorAdd, OBJ 0x240, Create=FALSE,
/// AllowMultiple=FALSE): o objeto referenciado ou None.
fn open_processor_add_callback() -> Result<Option<u64>, crate::rtl::KernelError> {
    let text: alloc::vec::Vec<u16> = PROCESSOR_ADD_CALLBACK.encode_utf16().chain(core::iter::once(0)).collect();
    let text_bytes: alloc::vec::Vec<u8> = text.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    let size = CallbackOpenBlock::SIZE + text_bytes.len() as u64;
    let address = guest::alloc_bytes(size);
    if address == 0 {
        return Ok(None);
    }
    guest::write_bytes(address, &alloc::vec![0u8; CallbackOpenBlock::SIZE as usize]);
    let buffer = address + CallbackOpenBlock::SIZE;
    guest::write_bytes(buffer, &text_bytes);
    // SAFETY: bloco recém-alocado do tamanho do layout.
    let block = unsafe { CallbackOpenBlock::at(address) };
    let length = ((text.len() - 1) * 2) as u16;
    block.name.length.set(length);
    block.name.maximum_length.set(length + 2);
    block.name.buffer.set(buffer);
    block.attributes.length.set(crate::ntos::inc::types::ObjectAttributes::SIZE as u32);
    block.attributes.object_name.set(block.name.address());
    block.attributes.attributes.set(PROCESSOR_ADD_ATTRIBUTES);
    let status = crate::ntos::ex::callbacks::create(block.callback_object.address(), block.attributes.address(), false, false);
    let object = block.callback_object.get();
    guest::free_bytes(address);
    Ok((status? == 0 && object != 0).then_some(object))
}

/// Preenche o contexto de notificação do processador `index`.
fn fill_processor_change(block: &ProcessorChangeBlock, state: i32, index: usize, status: i32, apic: &[u32]) {
    block.context.state.set(state);
    block.context.nt_number.set(index as u32);
    block.context.status.set(status);
    block.context.proc_number.group.set(0);
    block.context.proc_number.number.set(index as u8);
    block.context.proc_number.reserved.set(0);
    block.hal_processor_id.set(apic.get(index).copied().unwrap_or(0));
}

/// KeRegisterProcessorChangeCallback: registra no \Callback\ProcessorAdd e,
/// com KE_PROCESSOR_CHANGE_ADD_EXISTING, repete AddStart e depois
/// AddComplete para cada processador ativo. Um status negativo num AddStart
/// manda AddFailure aos já notificados, desfaz o registro e devolve NULL.
pub fn register_processor_change_callback(routine: u64, context: u64, flags: u32) -> Result<u64, crate::rtl::KernelError> {
    use crate::ntos::ex::callbacks;
    use crate::ntos::inc::types::extra_keex::{processor_change_state, KE_PROCESSOR_CHANGE_ADD_EXISTING};
    let Some(object) = open_processor_add_callback()? else { return Ok(0) };
    let registration = callbacks::register(object, routine, context);
    callbacks::dereference(object)?;
    let mut handle = registration?;
    if handle == 0 || flags & KE_PROCESSOR_CHANGE_ADD_EXISTING == 0 {
        return Ok(handle);
    }
    let apic = super::processor_topology::processor_apic_ids();
    let address = guest::alloc_bytes(ProcessorChangeBlock::SIZE);
    if address == 0 {
        return Ok(handle);
    }
    guest::write_bytes(address, &alloc::vec![0u8; ProcessorChangeBlock::SIZE as usize]);
    // SAFETY: bloco recém-alocado do tamanho do layout.
    let block = unsafe { ProcessorChangeBlock::at(address) };
    let arguments = [context, block.context.state.address(), block.operation_status.address()];
    let (mut notified, mut status, mut state) = (0usize, 0i32, processor_change_state::ADD_COMPLETE_NOTIFY);
    while notified < apic.len() {
        fill_processor_change(block, processor_change_state::ADD_START_NOTIFY, notified, 0, &apic);
        block.operation_status.set(0);
        crate::hal::amd64::native_call::call(routine, &arguments);
        status = block.operation_status.get();
        if status < 0 {
            state = processor_change_state::ADD_FAILURE_NOTIFY;
            callbacks::unregister(handle)?;
            handle = 0;
            break;
        }
        notified += 1;
    }
    // AddComplete (ou AddFailure) para os que já receberam AddStart.
    for index in 0..notified {
        fill_processor_change(block, state, index, status, &apic);
        crate::hal::amd64::native_call::call(routine, &arguments);
    }
    guest::free_bytes(address);
    Ok(handle)
}

/// KeDeregisterProcessorChangeCallback = ExUnregisterCallback.
pub fn deregister_processor_change_callback(handle: u64) -> Result<(), crate::rtl::KernelError> {
    crate::ntos::ex::callbacks::unregister(handle).map(|_| ())
}
