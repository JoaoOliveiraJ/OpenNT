//! IRPs do PnP manager (o IopSynchronousCall do NT).
//!
//! Todo pedido PnP vai ao topo da pilha do dispositivo
//! (IoGetAttachedDeviceReference): um IRP de IoAllocateIrp com o tamanho de
//! pilha do topo, IoStatus.Status = STATUS_NOT_SUPPORTED e Information com o
//! valor inicial do pedido (zero), RequestorMode KernelMode,
//! Tail.Overlay.Thread a thread corrente, UserIosb/UserEvent locais; o
//! STATUS_PENDING espera o evento. Os drivers que não tratam um pedido o
//! repassam sem tocar no status, e o barramento que também não o trata
//! completa com o status recebido: o STATUS_NOT_SUPPORTED inicial chega de
//! volta. O FILTER_RESOURCE_REQUIREMENTS é o do IopFilterResourceRequirementsCall:
//! com uma lista, o IRP parte com STATUS_SUCCESS e a lista em Information
//! (sem lista, STATUS_NOT_SUPPORTED), e o barramento que não trata o pedido
//! (o PciIrpNotSupported do pci.sys) devolve esse sucesso a quem o repassou:
//! o storport.sys só chama o filtro de recursos do miniport depois de um
//! repasse bem-sucedido. O NT segura a árvore de devnodes durante os pedidos
//! (`with_device_tree_lock`).

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{BusQueryIdType, DeviceRelationType, DeviceRelations, DeviceTextType, IoStackLocation, IoStatusBlock, Irp, Kevent, NtStruct};
use crate::ntos::io::io_manager::{self, irp_mj, irp_mn};
use crate::ntos::io::irp_builder;
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::objects::device as device_objects;
use crate::ntos::ps::kernel_threads;
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

pub const STATUS_SUCCESS: i32 = 0;
pub const STATUS_PENDING: i32 = 0x103;
pub const STATUS_NOT_SUPPORTED: i32 = 0xC000_00BBu32 as i32;
pub const STATUS_INSUFFICIENT_RESOURCES: i32 = 0xC000_009Au32 as i32;

/// IRP_MN_QUERY_PNP_DEVICE_STATE e IRP_MN_DEVICE_USAGE_NOTIFICATION (wdm.h).
pub const IRP_MN_QUERY_PNP_DEVICE_STATE: u8 = 0x14;
pub const IRP_MN_DEVICE_USAGE_NOTIFICATION: u8 = 0x16;
pub const IRP_MN_READ_CONFIG: u8 = 0x0F;
pub const IRP_MN_WRITE_CONFIG: u8 = 0x10;
pub const IRP_MN_QUERY_LEGACY_BUS_INFORMATION: u8 = 0x18;

/// Resultado de um pedido: o status final e o IoStatus.Information.
#[derive(Clone, Copy, Debug)]
pub struct Outcome {
    pub status: i32,
    pub information: u64,
}

impl Outcome {
    pub fn succeeded(&self) -> bool {
        self.status >= 0
    }
}

/// IopSynchronousCall: `fill` preenche Parameters da posição do primeiro
/// driver (a do topo); `information` é o IoStatus.Information inicial.
pub fn synchronous_call(device: u64, minor: u8, information: u64, fill: impl FnOnce(&IoStackLocation)) -> Result<Outcome, KernelError> {
    call_with_status(device, minor, STATUS_NOT_SUPPORTED, information, fill)
}

/// O pedido com o IoStatus inicial dado (Status e Information).
fn call_with_status(device: u64, minor: u8, initial_status: i32, information: u64, fill: impl FnOnce(&IoStackLocation)) -> Result<Outcome, KernelError> {
    let top = device_objects::attached_reference(device, false)?;
    // SAFETY: DEVICE_OBJECT do topo, referenciado acima.
    let stack_size = unsafe { crate::ntos::inc::types::DeviceObject::at(top) }.stack_size.get();
    let packet = irp_builder::allocate_irp(stack_size);
    if packet == 0 {
        device_objects::dereference(top)?;
        return Ok(Outcome { status: STATUS_INSUFFICIENT_RESOURCES, information: 0 });
    }
    let event = guest::alloc_bytes(Kevent::SIZE);
    let io_status = guest::alloc_bytes(IoStatusBlock::SIZE);
    dispatcher::initialize_event(event, 0, false);
    // SAFETY: IRP recém-alocado pelo IoAllocateIrp.
    let irp = unsafe { Irp::at(packet) };
    irp.io_status.status.set(initial_status);
    irp.io_status.information.set(information);
    irp.requestor_mode.set(0);
    irp.user_iosb.set(io_status);
    irp.user_event.set(event);
    irp.tail.overlay.thread.set(kernel_threads::get_current_thread_handle() as u64);
    // IoGetNextIrpStackLocation: a posição logo abaixo da corrente.
    // SAFETY: posição dentro do IRP alocado com StackSize posições.
    let location = unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get() - IoStackLocation::SIZE) };
    location.major_function.set(irp_mj::PNP);
    location.minor_function.set(minor);
    fill(location);
    let mut status = super::with_device_tree_lock(|| io_manager::iof_call_driver(top, packet));
    if status == STATUS_PENDING {
        dispatcher::wait_for_single_object(event, 0, 0, false);
    }
    // SAFETY: IO_STATUS_BLOCK local, gravado na conclusão do IRP.
    let final_status = unsafe { IoStatusBlock::at(io_status) };
    status = final_status.status.get();
    let information = final_status.information.get();
    irp_builder::free_irp(packet);
    guest::free_bytes(event);
    guest::free_bytes(io_status);
    device_objects::dereference(top)?;
    Ok(Outcome { status, information })
}

/// ExFreePool de um bloco que o driver alocou para o PnP manager.
fn free_pool(block: u64) {
    if let Err(error) = crate::ntos::ex::pool_allocation::free(block, 0) {
        debug_print!("[pnp] ExFreePool({:#x}): {}", block, error);
    }
}

/// Lista de strings UTF-16 (MULTI_SZ ou uma string só) devolvida em pool
/// pelo driver; o pool volta ao dono (ExFreePool).
fn take_id_list(buffer: u64, multi: bool) -> Vec<String> {
    let mut ids = Vec::new();
    let mut cursor = buffer;
    loop {
        let text = guest_strings::read_wide_string(cursor);
        if text.is_empty() {
            break;
        }
        cursor += (text.encode_utf16().count() as u64 + 1) * 2;
        ids.push(text);
        if !multi {
            break;
        }
    }
    free_pool(buffer);
    ids
}

/// IRP_MN_QUERY_ID: as strings do tipo pedido (vazio = sem resposta).
pub fn query_id(device: u64, id_type: BusQueryIdType) -> Result<Vec<String>, KernelError> {
    let outcome = synchronous_call(device, irp_mn::QUERY_ID, 0, |location| location.parameters.query_id.id_type.set(id_type))?;
    if !outcome.succeeded() || outcome.information == 0 {
        return Ok(Vec::new());
    }
    let multi = id_type == BusQueryIdType::BUS_QUERY_HARDWARE_I_DS || id_type == BusQueryIdType::BUS_QUERY_COMPATIBLE_I_DS;
    Ok(take_id_list(outcome.information, multi))
}

/// IRP_MN_QUERY_DEVICE_TEXT (LocaleId 0x409, como o PnP do NT pede).
pub fn query_device_text(device: u64, text_type: DeviceTextType) -> Result<Option<String>, KernelError> {
    let outcome = synchronous_call(device, irp_mn::QUERY_DEVICE_TEXT, 0, |location| {
        location.parameters.query_device_text.device_text_type.set(text_type);
        location.parameters.query_device_text.locale_id.set(0x409);
    })?;
    if !outcome.succeeded() || outcome.information == 0 {
        return Ok(None);
    }
    Ok(take_id_list(outcome.information, false).into_iter().next())
}

/// IRP_MN_QUERY_CAPABILITIES com um DEVICE_CAPABILITIES do PnP manager
/// (Size 0x40, Version 1, Address e UINumber 0xFFFFFFFF); devolve os 0x40
/// bytes depois do pedido.
pub fn query_capabilities(device: u64) -> Result<Option<Vec<u8>>, KernelError> {
    use crate::ntos::inc::types::DeviceCapabilities;
    let buffer = guest::alloc_bytes(DeviceCapabilities::SIZE);
    // SAFETY: bloco zerado recém-alocado do tamanho da estrutura.
    let capabilities = unsafe { DeviceCapabilities::at(buffer) };
    capabilities.size.set(DeviceCapabilities::SIZE as u16);
    capabilities.version.set(1);
    capabilities.address.set(0xFFFF_FFFF);
    capabilities.ui_number.set(0xFFFF_FFFF);
    let outcome = synchronous_call(device, irp_mn::QUERY_CAPABILITIES, 0, |location| location.parameters.device_capabilities.capabilities.set(buffer))?;
    let result = outcome.succeeded().then(|| guest::read_bytes(buffer, DeviceCapabilities::SIZE as usize));
    guest::free_bytes(buffer);
    Ok(result)
}

/// IRP_MN_QUERY_BUS_INFORMATION: (GUID do barramento, tipo legado, número).
pub fn query_bus_information(device: u64) -> Result<Option<([u8; 16], i32, u32)>, KernelError> {
    use crate::ntos::inc::types::extra_storage::PnpBusInformation;
    let outcome = synchronous_call(device, irp_mn::QUERY_BUS_INFORMATION, 0, |_| {})?;
    if !outcome.succeeded() || outcome.information == 0 {
        return Ok(None);
    }
    // SAFETY: PNP_BUS_INFORMATION em pool devolvido pelo barramento.
    let information = unsafe { PnpBusInformation::at(outcome.information) };
    let mut guid = [0u8; 16];
    guid.copy_from_slice(&guest::read_bytes(information.bus_type_guid.address(), 16));
    let result = (guid, information.legacy_bus_type.get().0, information.bus_number.get());
    free_pool(outcome.information);
    Ok(Some(result))
}

/// IRP_MN_QUERY_RESOURCES: a configuração de boot (CM_RESOURCE_LIST em pool,
/// que passa a ser do chamador).
pub fn query_resources(device: u64) -> Result<u64, KernelError> {
    let outcome = synchronous_call(device, irp_mn::QUERY_RESOURCES, 0, |_| {})?;
    Ok(if outcome.succeeded() { outcome.information } else { 0 })
}

/// IRP_MN_QUERY_RESOURCE_REQUIREMENTS: IO_RESOURCE_REQUIREMENTS_LIST em pool.
pub fn query_resource_requirements(device: u64) -> Result<u64, KernelError> {
    let outcome = synchronous_call(device, irp_mn::QUERY_RESOURCE_REQUIREMENTS, 0, |_| {})?;
    Ok(if outcome.succeeded() { outcome.information } else { 0 })
}

/// IRP_MN_FILTER_RESOURCE_REQUIREMENTS: Information e o parâmetro começam com
/// a lista corrente, e o Status com STATUS_SUCCESS (STATUS_NOT_SUPPORTED sem
/// lista), como o IopFilterResourceRequirementsCall; um filtro pode trocá-la
/// por outra em Information. Devolve a lista resultante (a mesma, se
/// ninguém a trocou).
pub fn filter_resource_requirements(device: u64, requirements: u64) -> Result<u64, KernelError> {
    let outcome = filter_resource_requirements_call(device, requirements)?;
    if outcome.succeeded() && outcome.information != 0 {
        return Ok(outcome.information);
    }
    Ok(requirements)
}

/// O pedido de FILTER_RESOURCE_REQUIREMENTS e o resultado dele.
pub fn filter_resource_requirements_call(device: u64, requirements: u64) -> Result<Outcome, KernelError> {
    let initial_status = if requirements != 0 { STATUS_SUCCESS } else { STATUS_NOT_SUPPORTED };
    call_with_status(device, irp_mn::FILTER_RESOURCE_REQUIREMENTS, initial_status, requirements, |location| location.parameters.filter_resource_requirements.io_resource_requirement_list.set(requirements))
}

/// IRP_MN_START_DEVICE com as listas bruta e traduzida.
pub fn start_device(device: u64, raw: u64, translated: u64) -> Result<i32, KernelError> {
    let outcome = synchronous_call(device, irp_mn::START_DEVICE, 0, |location| {
        location.parameters.start_device.allocated_resources.set(raw);
        location.parameters.start_device.allocated_resources_translated.set(translated);
    })?;
    Ok(outcome.status)
}

/// IRP_MN_QUERY_DEVICE_RELATIONS: os DEVICE_OBJECTs (já referenciados pelo
/// driver, como no NT) da DEVICE_RELATIONS devolvida.
pub fn query_device_relations(device: u64, relation: DeviceRelationType) -> Result<Option<Vec<u64>>, KernelError> {
    let outcome = synchronous_call(device, irp_mn::QUERY_DEVICE_RELATIONS, 0, |location| location.parameters.query_device_relations.type_.set(relation))?;
    if !outcome.succeeded() {
        return Ok(None);
    }
    if outcome.information == 0 {
        return Ok(Some(Vec::new()));
    }
    // SAFETY: DEVICE_RELATIONS em pool devolvida em Information.
    let relations = unsafe { DeviceRelations::at(outcome.information) };
    let count = relations.count.get() as usize;
    // SAFETY: Objects[Count] segue o cabeçalho na mesma alocação.
    let objects = unsafe { Field::<u64>::array_at(relations.objects[0].address(), count) };
    let devices = objects.iter().map(Field::get).collect();
    free_pool(outcome.information);
    Ok(Some(devices))
}

/// IRP_MN_QUERY_PNP_DEVICE_STATE: PNP_DEVICE_STATE (0 sem resposta).
pub fn query_pnp_device_state(device: u64) -> Result<u32, KernelError> {
    let outcome = synchronous_call(device, IRP_MN_QUERY_PNP_DEVICE_STATE, 0, |_| {})?;
    Ok(if outcome.succeeded() { outcome.information as u32 } else { 0 })
}
