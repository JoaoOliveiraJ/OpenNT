//! IRPs reais na memória do convidado.
//!
//! Layout oficial do WDK (`ntos::inc::types::Irp`/`IoStackLocation`) com N
//! stack locations: a primeira usada fica no endereço mais alto (slot
//! StackCount-1), CurrentLocation = StackCount+1 e CurrentStackLocation
//! aponta uma acima do topo, como o IopAllocateIrp do NT; cada IofCallDriver
//! desce um nível. Também a alocação, a reinicialização e a liberação dos
//! exports (IoAllocateIrp, IoInitializeIrp, IoReuseIrp, IoFreeIrp,
//! IoSetMasterIrpStatus).

use crate::ntos::inc::types::{IoStackLocation, Irp, NtStruct, PowerStateType, DevicePowerState, DeviceRelationType};
use crate::ntos::io::irp_extension;
use crate::ntos::mm::guest_memory as guest;

/// IO_TYPE_IRP.
const IO_TYPE_IRP: i16 = 6;

/// Cabeçalho mais os slots (sempre pelo menos um).
pub fn size_for(stack_count: u32) -> u64 {
    Irp::SIZE + stack_count.max(1) as u64 * IoStackLocation::SIZE
}

/// Primeira stack location a ser usada (topo da pilha).
pub fn first_stack_location(address: u64, stack_count: u32) -> u64 {
    address + Irp::SIZE + (stack_count.max(1) as u64 - 1) * IoStackLocation::SIZE
}

/// Parâmetros de IRP_MJ_DEVICE_CONTROL.
#[derive(Clone, Copy, Default)]
pub struct DeviceControl {
    pub code: u32,
    pub input_length: u32,
    /// METHOD_NEITHER: entrada crua em Type3InputBuffer.
    pub type3_buffer: u64,
}

/// Parâmetros de IRP_MJ_POWER.
#[derive(Clone, Copy, Default)]
pub struct Power {
    pub power_state_type: u32,
    pub device_state: u32,
}

/// Opções de `build`; energia, controle e PnP ocupam a mesma união nativa.
#[derive(Clone, Copy, Default)]
pub struct BuildOptions {
    pub major: u8,
    pub minor: u8,
    pub buffer: u64,
    pub buffer_length: u32,
    pub device_object: u64,
    pub power: Option<Power>,
    pub ioctl: Option<DeviceControl>,
    pub stack_count: u32,
    pub file_object: u64,
    pub byte_offset: u64,
    pub user_event: u64,
    pub user_iosb: u64,
    pub user_buffer: u64,
    pub resources: u64,
    pub relations_type: Option<u32>,
    pub pnp_slot_pointer: u64,
    pub requestor_mode: u8,
    pub thread: u64,
}

/// Cabeçalho do IRP recém-zerado: Type, Size, StackCount, CurrentLocation e
/// CurrentStackLocation uma acima do topo (IofCallDriver decrementa antes de
/// despachar).
fn initialize_header(irp: &Irp, size: u16, stack_count: u8) {
    irp.type_.set(IO_TYPE_IRP);
    irp.size.set(size);
    irp.stack_count.set(stack_count as i8);
    irp.current_location.set(stack_count.wrapping_add(1) as i8);
    irp.tail.overlay.current_stack_location.set(first_stack_location(irp.address(), stack_count as u32) + IoStackLocation::SIZE);
}

/// Zera e preenche o IRP em `address` para o primeiro IofCallDriver.
pub fn build(address: u64, options: &BuildOptions) {
    let stack_count = options.stack_count.max(1);
    let size = size_for(stack_count);
    guest::write_bytes(address, &alloc::vec![0u8; size as usize]);
    // SAFETY: `address` é a alocação de `size_for(stack_count)` bytes do chamador.
    let irp = unsafe { Irp::at(address) };
    initialize_header(irp, size as u16, stack_count as u8);
    irp.associated_irp.system_buffer.set(options.buffer);
    if options.user_event != 0 {
        irp.user_event.set(options.user_event);
    }
    if options.user_iosb != 0 {
        irp.user_iosb.set(options.user_iosb);
    }
    if options.user_buffer != 0 {
        irp.user_buffer.set(options.user_buffer);
    }
    // O slot do topo é o do primeiro driver a receber o IRP.
    // SAFETY: o slot do topo está dentro da mesma alocação.
    let location = unsafe { IoStackLocation::at(first_stack_location(address, stack_count)) };
    let parameters = &location.parameters;
    location.major_function.set(options.major);
    location.minor_function.set(options.minor);
    parameters.read.length.set(options.buffer_length);
    parameters.read.byte_offset.quad_part.set(options.byte_offset as i64);
    location.device_object.set(options.device_object);
    location.file_object.set(options.file_object);
    irp.requestor_mode.set(options.requestor_mode as i8);
    irp.tail.overlay.thread.set(options.thread);
    irp.tail.overlay.original_file_object.set(options.file_object);
    // Parameters.Power.{Type,State}, por cima de Read/Write como no wdm.h.
    if let Some(power) = options.power {
        parameters.power.type_.set(PowerStateType(power.power_state_type as i32));
        parameters.power.state.device_state.set(DevicePowerState(power.device_state as i32));
    }
    // Parameters.DeviceIoControl.
    if let Some(control) = options.ioctl {
        let ioctl = &parameters.device_io_control;
        ioctl.io_control_code.set(control.code);
        ioctl.input_buffer_length.set(control.input_length);
        ioctl.output_buffer_length.set(options.buffer_length);
        if control.type3_buffer != 0 {
            ioctl.type3_input_buffer.set(control.type3_buffer);
        }
    }
    // Parameters.StartDevice.AllocatedResources[Translated].
    if options.resources != 0 {
        parameters.start_device.allocated_resources.set(options.resources);
        parameters.start_device.allocated_resources_translated.set(options.resources);
    }
    // Parameters.QueryDeviceRelations.Type.
    if let Some(relations) = options.relations_type {
        parameters.query_device_relations.type_.set(DeviceRelationType(relations as i32));
    }
    // Ponteiro da união Parameters (+0x08) para QUERY_CAPABILITIES e
    // FILTER_RESOURCE_REQUIREMENTS (Capabilities / IoResourceRequirementList).
    if options.pnp_slot_pointer != 0 {
        parameters.device_capabilities.capabilities.set(options.pnp_slot_pointer);
    }
}

/// IoStatus depois da execução do driver: (NTSTATUS com sinal, Information).
pub fn read_io_status(address: u64) -> (i32, u64) {
    // SAFETY: `address` é um IRP vivo do chamador.
    let irp = unsafe { Irp::at(address) };
    (irp.io_status.status.get(), irp.io_status.information.get())
}

/// IoAllocateIrp: IRP zerado posicionado acima do topo da pilha.
pub fn allocate_irp(stack_size: i8) -> u64 {
    let count = stack_size.max(1) as u64;
    let size = Irp::SIZE + count * IoStackLocation::SIZE;
    let address = guest::alloc_bytes(size);
    if address == 0 {
        return 0;
    }
    // SAFETY: alocação zerada de `size` bytes.
    initialize_header(unsafe { Irp::at(address) }, size as u16, count as u8);
    address
}

/// IoFreeIrp: a extensão pertence ao IRP e não sobrevive ao reuso.
pub fn free_irp(packet: u64) {
    irp_extension::release(packet);
    guest::free_bytes(packet);
}

/// IoReuseIrp: reinicializa mantendo o tamanho e a pilha alocados.
pub fn reuse_irp(packet: u64, status: u32) {
    // SAFETY: `packet` é um IRP vivo do chamador.
    let irp = unsafe { Irp::at(packet) };
    let count = irp.stack_count.get() as u8;
    irp.flags.set(0);
    irp.mdl_address.set(0);
    irp.associated_irp.system_buffer.set(0);
    irp.io_status.status.set(status as i32);
    irp.io_status.information.set(0);
    irp.current_location.set(count.wrapping_add(1) as i8);
    irp.cancel.set(0);
    irp.user_event.set(0);
    irp.tail.overlay.current_stack_location.set(first_stack_location(packet, count as u32) + IoStackLocation::SIZE);
}

/// IoInitializeIrp: a forma do IopAllocateIrp, sem a alocação.
pub fn initialize_irp(packet: u64, size: u16, count: u8) {
    guest::write_bytes(packet, &alloc::vec![0u8; size as usize]);
    // SAFETY: `packet` aponta para `size` bytes do chamador.
    initialize_header(unsafe { Irp::at(packet) }, size, count);
}

/// IoSetMasterIrpStatus: grava o status no IRP mestre e o devolve.
pub fn set_master_irp_status(packet: u64, status: u64) -> u64 {
    // SAFETY: `packet` é o IRP mestre vivo do chamador.
    unsafe { Irp::at(packet) }.io_status.status.set(status as i32);
    status
}
