//! IRPs reais na memória do convidado — `system32/win32/ntoskrnl/irp-builder.js`.
//!
//! Layout oficial do WDK (offsets em `ntos::inc::nt_abi`) com N stack locations:
//! a primeira usada fica no endereço mais alto (slot StackCount-1),
//! CurrentLocation = StackCount+1 e CurrentStackLocation aponta uma acima
//! do topo, como o IopAllocateIrp do NT; cada IofCallDriver desce um nível.

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{io_stack_location as stack, irp};

/// Cabeçalho mais os slots (sempre pelo menos um).
pub fn size_for(stack_count: u32) -> u64 {
    irp::STRUCT_SIZE + stack_count.max(1) as u64 * stack::SIZE
}

/// Primeira stack location a ser usada (topo da pilha).
pub fn first_stack_location(address: u64, stack_count: u32) -> u64 {
    address + irp::STRUCT_SIZE + (stack_count.max(1) as u64 - 1) * stack::SIZE
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

/// Zera e preenche o IRP em `address` para o primeiro IofCallDriver.
pub fn build(address: u64, options: &BuildOptions) {
    let stack_count = options.stack_count.max(1);
    let size = size_for(stack_count);
    let mut offset = 0;
    while offset < size {
        guest::write32(address + offset, 0);
        offset += 4;
    }
    // CurrentStackLocation fica acima do primeiro slot: IofCallDriver
    // decrementa o ponteiro antes de despachar.
    guest::write16(address + irp::TYPE, irp::IO_TYPE);
    guest::write16(address + irp::SIZE_FIELD, size as u16);
    guest::write64(address + irp::SYSTEM_BUFFER, options.buffer);
    guest::write8(address + irp::STACK_COUNT, stack_count as u8);
    guest::write8(address + irp::CURRENT_LOCATION, stack_count as u8 + 1);
    guest::write64(address + irp::CURRENT_STACK_LOCATION, first_stack_location(address, stack_count) + stack::SIZE);
    if options.user_event != 0 {
        guest::write64(address + irp::USER_EVENT, options.user_event);
    }
    if options.user_iosb != 0 {
        guest::write64(address + irp::USER_IOSB, options.user_iosb);
    }
    if options.user_buffer != 0 {
        guest::write64(address + irp::USER_BUFFER, options.user_buffer);
    }
    // O slot do topo é o do primeiro driver a receber o IRP.
    let location = first_stack_location(address, stack_count);
    guest::write8(location + stack::MAJOR, options.major);
    guest::write8(location + stack::MINOR, options.minor);
    guest::write32(location + stack::READ_LENGTH, options.buffer_length);
    guest::write64(location + stack::READ_OFFSET, options.byte_offset);
    guest::write64(location + stack::DEVICE_OBJECT, options.device_object);
    guest::write64(location + stack::FILE_OBJECT, options.file_object);
    guest::write8(address + irp::REQUESTOR_MODE, options.requestor_mode);
    guest::write64(address + irp::THREAD, options.thread);
    guest::write64(address + irp::ORIGINAL_FILE_OBJECT, options.file_object);
    // Parameters.Power.{Type,State}, por cima de Read/Write como no wdm.h.
    if let Some(power) = options.power {
        guest::write32(location + stack::POWER_TYPE, power.power_state_type);
        guest::write32(location + stack::POWER_STATE, power.device_state);
    }
    // Parameters.DeviceIoControl.
    if let Some(control) = options.ioctl {
        guest::write32(location + stack::IOCTL_CODE, control.code);
        guest::write32(location + stack::IOCTL_IN_LENGTH, control.input_length);
        guest::write32(location + stack::IOCTL_OUT_LENGTH, options.buffer_length);
        if control.type3_buffer != 0 {
            guest::write64(location + stack::IOCTL_TYPE3_BUFFER, control.type3_buffer);
        }
    }
    // Parameters.StartDevice.AllocatedResources[Translated].
    if options.resources != 0 {
        guest::write64(location + stack::PNP_ALLOCATED_RESOURCES, options.resources);
        guest::write64(location + stack::PNP_ALLOCATED_RESOURCES_TRANSLATED, options.resources);
    }
    // Parameters.QueryDeviceRelations.Type.
    if let Some(relations) = options.relations_type {
        guest::write32(location + stack::READ_LENGTH, relations);
    }
    // Ponteiro da união Parameters (+0x08) para QUERY_CAPABILITIES e
    // FILTER_RESOURCE_REQUIREMENTS.
    if options.pnp_slot_pointer != 0 {
        guest::write64(location + stack::READ_LENGTH, options.pnp_slot_pointer);
    }
}

/// IoStatus depois da execução do driver: (NTSTATUS com sinal, Information).
pub fn read_io_status(address: u64) -> (i32, u64) {
    (guest::read32(address + irp::IO_STATUS) as i32, guest::read64(address + irp::IO_STATUS_INFORMATION))
}
