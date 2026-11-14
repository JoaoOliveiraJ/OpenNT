//! Exports Io* do ntoskrnl — adaptadores.
//!
//! Cada handler lê os argumentos do `Call`, chama a rotina do arquivo do
//! assunto no I/O Manager e converte o resultado (NTSTATUS, ponteiro,
//! BOOLEAN). Os dispositivos e pilhas ficam em `device`; IRPs em
//! `irp_builder`, `irp_extension` e `cancel`; MDLs em `mdl`; remove locks em
//! `remove_lock`; interrupções em `interrupt`; interfaces de dispositivo,
//! notificações PnP e propriedades em `device_interface`, `pnp_notify`,
//! `device_property` e `pnp`; os módulos pequenos (log de erros, listas de
//! desligamento/prioridade, WMI...) em `small`.

use crate::ntos::init::exports::{signed_status, Call, Group};
use crate::ntos::io::{cancel, device, device_interface, device_property, interrupt, io_manager, irp_builder, irp_extension, lifecycle, mdl, object_types, pnp, pnp_notify, remove_lock, work_items};
use crate::ntos::io::file::zw as zw_files;
use crate::ntos::cm::hw_description;
use crate::ntos::io::controller::{controller, start_io};
use crate::ntos::io::small::{configuration_information, delete_device, error_log, partition_table, priority_callbacks, sfio_stream, shutdown_notification, thread_io, wmi_registration};
use crate::ntos::io::small::initial_stack as kernel_stack;
use crate::ntos::io::threads::{io_timer, thread_activity};
use crate::ntos::io::file::information as file_information;
use crate::ntos::ke::interrupt_object;
use crate::ntos::ob::objects::device as device_objects;
use crate::ntos::ps::{kernel_threads, process};
use crate::rtl::KernelError;

/// IoGetDeviceObjectPointer: topo da pilha e um FILE_OBJECT real retido.
fn get_device_object_pointer_export(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(device::get_device_object_pointer(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4))?))
}

fn io_create_device(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(device::create_device(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32, call.arg(5) as u32, call.arg(7))?))
}
fn io_create_symbolic_link(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(device::create_symbolic_link(call.arg(1), call.arg(2))?))
}
fn io_delete_device(call: &Call) -> Result<u64, KernelError> {
    Ok(delete_device::delete_device(call.arg(1))? as u64)
}
fn io_delete_symbolic_link(call: &Call) -> Result<u64, KernelError> {
    Ok(device::delete_symbolic_link(call.arg(1)) as u64)
}
fn io_allocate_irp(call: &Call) -> Result<u64, KernelError> {
    Ok(irp_builder::allocate_irp(call.arg(1) as u8 as i8))
}
fn io_free_irp(call: &Call) -> Result<u64, KernelError> {
    irp_builder::free_irp(call.arg(1));
    Ok(0)
}
fn io_complete_request(call: &Call) -> Result<u64, KernelError> {
    Ok(io_manager::iof_complete_request(call.arg(1)) as i64 as u64)
}
fn io_allocate_work_item(call: &Call) -> Result<u64, KernelError> {
    Ok(work_items::allocate_work_item(call.arg(1)))
}
fn io_queue_work_item(call: &Call) -> Result<u64, KernelError> {
    work_items::queue_work_item(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4));
    Ok(0)
}
fn io_free_work_item(call: &Call) -> Result<u64, KernelError> {
    work_items::free_work_item(call.arg(1));
    Ok(0)
}
fn io_call_driver(call: &Call) -> Result<u64, KernelError> {
    Ok(io_manager::iof_call_driver(call.arg(1), call.arg(2)) as i64 as u64)
}
fn io_attach_device_to_device_stack(call: &Call) -> Result<u64, KernelError> {
    device::attach_device_to_device_stack(call.arg(1), call.arg(2), 0)
}
fn io_detach_device(call: &Call) -> Result<u64, KernelError> {
    device::detach_device(call.arg(1))?;
    Ok(0)
}
fn io_build_synchronous_fsd_request(call: &Call) -> Result<u64, KernelError> {
    Ok(io_manager::build_synchronous_fsd_request(call.arg(1) as u8, call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5), call.arg(6), call.arg(7)))
}
fn io_build_device_io_control_request(call: &Call) -> Result<u64, KernelError> {
    Ok(io_manager::build_device_io_control_request(call.arg(1) as u32, call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5), call.arg(6) as u32, call.arg(7), call.arg(8), call.arg(9), None))
}
fn io_initialize_timer(call: &Call) -> Result<u64, KernelError> {
    Ok(io_timer::initialize_timer(call.arg(1), call.arg(2), call.arg(3)) as u64)
}
fn io_start_timer(call: &Call) -> Result<u64, KernelError> {
    Ok(io_timer::start_timer(call.arg(1)) as u64)
}
fn io_stop_timer(call: &Call) -> Result<u64, KernelError> {
    Ok(io_timer::stop_timer(call.arg(1)) as u64)
}
/// IoQueueWorkItemEx: a rotina recebe (ioObject, context, ioWorkItem).
fn io_queue_work_item_ex(call: &Call) -> Result<u64, KernelError> {
    work_items::queue_work_item_ex(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4), true);
    Ok(0)
}
fn io_allocate_mdl(call: &Call) -> Result<u64, KernelError> {
    Ok(mdl::allocate_mdl(call.arg(1), call.arg(2) as u32))
}
fn io_free_mdl(call: &Call) -> Result<u64, KernelError> {
    mdl::free_mdl(call.arg(1));
    Ok(0)
}
fn io_get_current_thread(_: &Call) -> Result<u64, KernelError> {
    Ok(kernel_threads::get_current_thread_handle() as u64)
}
fn io_set_cancel_routine(call: &Call) -> Result<u64, KernelError> {
    Ok(cancel::set_cancel_routine(call.arg(1), call.arg(2)))
}
fn io_cancel_irp(call: &Call) -> Result<u64, KernelError> {
    Ok(cancel::irp(call.arg(1))? as u64)
}
fn io_allocate_driver_object_extension(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(lifecycle::allocate_driver_object_extension(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4))))
}
fn io_get_driver_object_extension(call: &Call) -> Result<u64, KernelError> {
    Ok(lifecycle::driver_object_extension(call.arg(1), call.arg(2)))
}
fn io_get_current_process(_: &Call) -> Result<u64, KernelError> {
    Ok(process::get_current_process())
}
/// IoCreateFile/IoCreateFileEx: a abertura completa do ZwCreateFile.
fn io_create_file(call: &Call) -> Result<u64, KernelError> {
    Ok(zw_files::create_kernel_file(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4), call.arg(7) as u32, call.arg(8) as u32, call.arg(9) as u32)? as u64)
}
fn io_get_related_device_object(call: &Call) -> Result<u64, KernelError> {
    file_information::related_device(call.arg(1))
}
fn io_get_device_property(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(device_property::get_device_property(call.arg(1), call.arg(2) as u32, call.arg(3) as u32, call.arg(4), call.arg(5))))
}
fn io_get_stack_limits(call: &Call) -> Result<u64, KernelError> {
    kernel_stack::limits(call.arg(1), call.arg(2));
    Ok(0)
}
fn io_initialize_remove_lock(call: &Call) -> Result<u64, KernelError> {
    remove_lock::initialize(call.arg(1));
    Ok(0)
}
fn io_acquire_remove_lock(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(remove_lock::acquire(call.arg(1))))
}
fn io_release_remove_lock(call: &Call) -> Result<u64, KernelError> {
    remove_lock::release(call.arg(1));
    Ok(0)
}
fn io_release_remove_lock_and_wait(call: &Call) -> Result<u64, KernelError> {
    remove_lock::release_and_wait(call.arg(1));
    Ok(0)
}
fn io_allocate_error_log_entry(call: &Call) -> Result<u64, KernelError> {
    Ok(error_log::allocate_entry(call.arg(2) as u8))
}
fn io_write_error_log_entry(call: &Call) -> Result<u64, KernelError> {
    error_log::write_entry(call.arg(1));
    Ok(0)
}
fn io_acquire_cancel_spin_lock(call: &Call) -> Result<u64, KernelError> {
    cancel::acquire_into(call.arg(1))?;
    Ok(0)
}
fn io_release_cancel_spin_lock(call: &Call) -> Result<u64, KernelError> {
    cancel::release(call.arg(1) as u8)?;
    Ok(0)
}
fn io_register_device_interface(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(device_interface::register_device_interface(call.arg(1), call.arg(2), call.arg(4))?))
}
fn io_set_device_interface_state(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(device_interface::set_device_interface_state(call.arg(1), call.arg(2) & 0xFF != 0)))
}
fn io_register_plug_play_notification(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(pnp_notify::register(call.arg(1) as u32, call.arg(2) as u32, call.arg(3), call.arg(5), call.arg(6), call.arg(7))))
}
fn io_unregister_plug_play_notification(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(pnp_notify::unregister(call.arg(1))))
}
fn io_register_driver_reinitialization(call: &Call) -> Result<u64, KernelError> {
    lifecycle::register_reinitialization(call.arg(2), call.arg(3));
    Ok(0)
}
fn io_open_device_registry_key(call: &Call) -> Result<u64, KernelError> {
    device_property::open_device_registry_key(call.arg(1), call.arg(3))
}
fn io_wmi_registration_control(call: &Call) -> Result<u64, KernelError> {
    wmi_registration::registration_control(call.arg(1), call.arg(2) as u32);
    Ok(0)
}
fn io_connect_interrupt(call: &Call) -> Result<u64, KernelError> {
    Ok(interrupt_object::io_connect_interrupt(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5) as u32, call.arg(6) as u8, call.arg(7) as u8, call.arg(8) as u32, call.arg(9) & 0xFF != 0)? as u64)
}
fn io_disconnect_interrupt(call: &Call) -> Result<u64, KernelError> {
    interrupt_object::io_disconnect_interrupt(call.arg(1));
    Ok(0)
}
fn io_create_controller(call: &Call) -> Result<u64, KernelError> {
    Ok(controller::create(call.arg(1) as u32))
}
fn io_delete_controller(call: &Call) -> Result<u64, KernelError> {
    controller::delete(call.arg(1));
    Ok(0)
}
fn io_allocate_controller(call: &Call) -> Result<u64, KernelError> {
    controller::allocate(call.arg(1), call.arg(2), call.arg(3), call.arg(4));
    Ok(0)
}
fn io_free_controller(call: &Call) -> Result<u64, KernelError> {
    controller::free(call.arg(1));
    Ok(0)
}
fn io_start_packet(call: &Call) -> Result<u64, KernelError> {
    start_io::start_packet(call.arg(1), call.arg(2), call.arg(3), call.arg(4));
    Ok(0)
}
fn io_start_next_packet(call: &Call) -> Result<u64, KernelError> {
    start_io::start_next_packet(call.arg(1), call.arg(2) & 0xFF != 0);
    Ok(0)
}
fn io_set_start_io_attributes(call: &Call) -> Result<u64, KernelError> {
    start_io::set_start_io_attributes(call.arg(1), call.arg(2) & 0xFF != 0, call.arg(3) & 0xFF != 0);
    Ok(0)
}
/// Retém o topo pela posse do OB, não pela contagem de arquivos abertos.
fn io_get_attached_device_reference(call: &Call) -> Result<u64, KernelError> {
    device_objects::attached_reference(call.arg(1), false)
}
fn io_invalidate_device_state(call: &Call) -> Result<u64, KernelError> {
    pnp::invalidate_device_state(call.arg(1));
    Ok(0)
}
fn io_query_device_description(call: &Call) -> Result<u64, KernelError> {
    Ok(hw_description::query_device_description(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7), call.arg(8)) as u64)
}
fn io_connect_interrupt_ex(call: &Call) -> Result<u64, KernelError> {
    interrupt::connect_interrupt_ex(call.arg(1))
}
fn io_disconnect_interrupt_ex(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(interrupt::disconnect_interrupt_ex(call.arg(1))))
}
fn io_read_partition_table_ex(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(partition_table::read_partition_table_ex(call.arg(1), call.arg(2))?))
}
fn io_get_configuration_information(_: &Call) -> Result<u64, KernelError> {
    Ok(configuration_information::get())
}
fn io_invalidate_device_relations(call: &Call) -> Result<u64, KernelError> {
    pnp::invalidate_device_relations(call.arg(1), call.arg(2) as u32);
    Ok(0)
}
fn io_get_generic_irp_extension(call: &Call) -> Result<u64, KernelError> {
    Ok(irp_extension::generic(call.arg(1)))
}
fn io_set_generic_irp_extension(call: &Call) -> Result<u64, KernelError> {
    irp_extension::set_generic(call.arg(1), call.arg(2), call.arg(3) & 0xFF != 0);
    Ok(0)
}
fn io_propagate_irp_extension(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(irp_extension::propagate(call.arg(1), call.arg(2))))
}
fn io_get_activity_id_irp(call: &Call) -> Result<u64, KernelError> {
    Ok(irp_extension::activity_id(call.arg(1), call.arg(2)) as u64)
}
fn io_set_activity_id_irp(call: &Call) -> Result<u64, KernelError> {
    irp_extension::set_activity_id(call.arg(1), call.arg(2));
    Ok(0)
}
/// Devolve o LPCGUID da thread (não copia para um buffer).
fn io_get_activity_id_thread(_: &Call) -> Result<u64, KernelError> {
    Ok(thread_activity::get())
}
fn io_clear_activity_id_thread(call: &Call) -> Result<u64, KernelError> {
    thread_activity::clear(call.arg(1));
    Ok(0)
}
fn io_propagate_activity_id_to_thread(call: &Call) -> Result<u64, KernelError> {
    Ok(irp_extension::propagate_activity_id_to_thread(call.arg(1), call.arg(2), call.arg(3)) as u64)
}
/// Nenhuma sessão de trace ETW ativa.
fn zero(_: &Call) -> Result<u64, KernelError> {
    Ok(0)
}
fn io_reuse_irp(call: &Call) -> Result<u64, KernelError> {
    irp_builder::reuse_irp(call.arg(1), call.arg(2) as u32);
    Ok(0)
}
fn io_initialize_irp(call: &Call) -> Result<u64, KernelError> {
    irp_builder::initialize_irp(call.arg(1), call.arg(2) as u16, call.arg(3) as u8);
    Ok(0)
}
fn io_set_master_irp_status(call: &Call) -> Result<u64, KernelError> {
    Ok(irp_builder::set_master_irp_status(call.arg(1), call.arg(2)))
}
fn io_build_partial_mdl(call: &Call) -> Result<u64, KernelError> {
    mdl::build_partial_mdl(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32);
    Ok(0)
}
/// IoGetIoPriorityHint: a prioridade gravada em Irp->Flags (a mesma que o
/// IoSetIoPriorityHint escreve).
fn io_get_io_priority_hint(call: &Call) -> Result<u64, KernelError> {
    use crate::ntos::inc::types::{Irp, NtStruct};
    // SAFETY: PIRP de um chamador de modo kernel.
    let irp = unsafe { Irp::at(call.arg(1)) };
    Ok(crate::ntos::io::irp_support::get_io_priority_hint(irp) as u64)
}

fn io_sizeof_work_item(_: &Call) -> Result<u64, KernelError> {
    Ok(work_items::work_item_size())
}
/// IoAllocateSfioStreamIdentifier(FileObject, Length, Signature, StreamIdentifier).
fn io_allocate_sfio_stream_identifier(call: &Call) -> Result<u64, KernelError> {
    sfio_stream::allocate_identifier(call.arg(4));
    Ok(0)
}
/// Os IRPs nascem de código de kernel: o dono é o System.
fn io_get_requestor_process(_: &Call) -> Result<u64, KernelError> {
    Ok(process::get_system_process())
}
fn io_get_device_attachment_base_ref(call: &Call) -> Result<u64, KernelError> {
    device_objects::attached_reference(call.arg(1), true)
}
fn io_get_device_property_data(call: &Call) -> Result<u64, KernelError> {
    use crate::ntos::inc::field::{Field, NtStruct};
    // SAFETY: DEVPROPKEY e as saídas PULONG/DEVPROPTYPE de um chamador de modo kernel.
    let (key, required, kind) = unsafe { (crate::ntos::inc::types::Devpropkey::at(call.arg(2)), Field::<u32>::at(call.arg(7)), Field::<u32>::at(call.arg(8))) };
    Ok(signed_status(device_property::query_device_property_data(call.arg(1), key, call.arg(3) as u32, call.arg(4) as u32, call.arg(5) as u32, call.arg(6), required, kind)))
}
fn io_set_hard_error_or_verify_device(call: &Call) -> Result<u64, KernelError> {
    irp_extension::set_hard_error_device(call.arg(1), call.arg(2));
    Ok(0)
}
fn io_set_thread_hard_error_mode(call: &Call) -> Result<u64, KernelError> {
    Ok(thread_io::set_hard_error_mode(call.arg(1) as u8)? as u64)
}
fn io_register_shutdown_notification(call: &Call) -> Result<u64, KernelError> {
    shutdown_notification::register(call.arg(1));
    Ok(0)
}
fn io_unregister_shutdown_notification(call: &Call) -> Result<u64, KernelError> {
    shutdown_notification::unregister(call.arg(1));
    Ok(0)
}
/// IoReportTargetDeviceChangeAsynchronous(PhysicalDeviceObject,
/// NotificationStructure, Callback, Context).
fn io_report_target_device_change_asynchronous(call: &Call) -> Result<u64, KernelError> {
    pnp_notify::report_target_device_change_asynchronous(call.arg(2), call.arg(3), call.arg(4));
    Ok(0)
}
fn io_register_priority_callback(call: &Call) -> Result<u64, KernelError> {
    priority_callbacks::register(call.arg(1));
    Ok(0)
}
fn io_unregister_priority_callback(call: &Call) -> Result<u64, KernelError> {
    priority_callbacks::unregister(call.arg(1));
    Ok(0)
}
fn io_wmi_device_object_to_provider_id(call: &Call) -> Result<u64, KernelError> {
    Ok(wmi_registration::provider_id(call.arg(1)))
}
fn io_initialize_work_item(call: &Call) -> Result<u64, KernelError> {
    work_items::create_work_item(call.arg(1), call.arg(2));
    Ok(0)
}
fn io_query_file_information(call: &Call) -> Result<u64, KernelError> {
    Ok(zw_files::query_file_information_by_object(call.arg(1), call.arg(2) as u32, call.arg(3) as u32, call.arg(4), call.arg(5))? as u64)
}

fn io_driver_object_type() -> u64 {
    object_types::driver_object_type()
}
fn io_file_object_type() -> u64 {
    object_types::file_object_type()
}

pub static GROUP: Group = Group {
    name: "io",
    names: &[
        "IoCreateDevice", "IoCreateSymbolicLink", "IoDeleteDevice", "IoDeleteSymbolicLink", "IoAllocateIrp", "IoFreeIrp", "IoCompleteRequest", "IofCompleteRequest", "IoAllocateWorkItem", "IoQueueWorkItem", "IoFreeWorkItem", "IoCallDriver", "IofCallDriver", "IoAttachDeviceToDeviceStack", "IoDetachDevice", "IoGetDeviceObjectPointer", "IoBuildSynchronousFsdRequest", "IoBuildDeviceIoControlRequest", "IoInitializeTimer", "IoStartTimer", "IoStopTimer", "IoQueueWorkItemEx", "IoAllocateMdl", "IoFreeMdl", "IoGetCurrentThread", "IoSetCancelRoutine", "IoCancelIrp", "IoAllocateDriverObjectExtension", "IoGetDriverObjectExtension", "IoGetCurrentProcess", "IoCreateFile", "IoGetRelatedDeviceObject", "IoGetDeviceProperty", "IoGetStackLimits", "IoInitializeRemoveLockEx", "IoAcquireRemoveLockEx", "IoReleaseRemoveLockEx", "IoReleaseRemoveLockAndWaitEx", "IoAllocateErrorLogEntry", "IoWriteErrorLogEntry", "IoAcquireCancelSpinLock", "IoReleaseCancelSpinLock", "IoRegisterDeviceInterface", "IoSetDeviceInterfaceState", "IoRegisterPlugPlayNotification", "IoUnregisterPlugPlayNotification", "IoRegisterDriverReinitialization", "IoOpenDeviceRegistryKey", "IoWMIRegistrationControl", "IoConnectInterrupt", "IoDisconnectInterrupt", "IoCreateController", "IoDeleteController", "IoAllocateController", "IoFreeController", "IoStartPacket", "IoStartNextPacket", "IoSetStartIoAttributes", "IoGetAttachedDeviceReference", "IoInvalidateDeviceState", "IoQueryDeviceDescription", "IoConnectInterruptEx", "IoDisconnectInterruptEx", "IoReadPartitionTableEx", "IoGetConfigurationInformation", "IoInvalidateDeviceRelations", "IoGetGenericIrpExtension", "IoSetGenericIrpExtension", "IoPropagateIrpExtensionEx", "IoGetActivityIdIrp", "IoSetActivityIdIrp", "IoGetActivityIdThread", "IoClearActivityIdThread", "IoPropagateActivityIdToThread", "IoIsActivityTracingEnabled", "IoReuseIrp", "IoInitializeIrp", "IoSetMasterIrpStatus", "IoBuildPartialMdl", "IoSizeofWorkItem", "IoAllocateSfioStreamIdentifier", "IoGetSfioStreamIdentifier", "IoFreeSfioStreamIdentifier", "IoGetIoAttributionHandle", "IoRecordIoAttribution", "IoGetIoPriorityHint", "IoGetPagingIoPriority", "IoGetRequestorProcess", "IoIs32bitProcess", "IoGetDeviceAttachmentBaseRef", "IoGetDevicePropertyData", "IoSetHardErrorOrVerifyDevice", "IoSetThreadHardErrorMode", "IoRegisterShutdownNotification", "IoUnregisterShutdownNotification", "IoReportTargetDeviceChangeAsynchronous", "IoRegisterPriorityCallback", "IoUnregisterPriorityCallback", "IoWMIDeviceObjectToProviderId", "IoWMIWriteEvent", "IoCreateFileEx", "IoInitializeWorkItem", "IoQueryFileInformation", "IoUnregisterPlugPlayNotificationEx",
    ],
    handlers: &[
        io_create_device, io_create_symbolic_link, io_delete_device, io_delete_symbolic_link, io_allocate_irp, io_free_irp, io_complete_request, io_complete_request, io_allocate_work_item, io_queue_work_item, io_free_work_item, io_call_driver, io_call_driver, io_attach_device_to_device_stack, io_detach_device, get_device_object_pointer_export, io_build_synchronous_fsd_request, io_build_device_io_control_request, io_initialize_timer, io_start_timer, io_stop_timer, io_queue_work_item_ex, io_allocate_mdl, io_free_mdl, io_get_current_thread, io_set_cancel_routine, io_cancel_irp, io_allocate_driver_object_extension, io_get_driver_object_extension, io_get_current_process, io_create_file, io_get_related_device_object, io_get_device_property, io_get_stack_limits, io_initialize_remove_lock, io_acquire_remove_lock, io_release_remove_lock, io_release_remove_lock_and_wait, io_allocate_error_log_entry, io_write_error_log_entry, io_acquire_cancel_spin_lock, io_release_cancel_spin_lock, io_register_device_interface, io_set_device_interface_state, io_register_plug_play_notification, io_unregister_plug_play_notification, io_register_driver_reinitialization, io_open_device_registry_key, io_wmi_registration_control, io_connect_interrupt, io_disconnect_interrupt, io_create_controller, io_delete_controller, io_allocate_controller, io_free_controller, io_start_packet, io_start_next_packet, io_set_start_io_attributes, io_get_attached_device_reference, io_invalidate_device_state, io_query_device_description, io_connect_interrupt_ex, io_disconnect_interrupt_ex, io_read_partition_table_ex, io_get_configuration_information, io_invalidate_device_relations, io_get_generic_irp_extension, io_set_generic_irp_extension, io_propagate_irp_extension, io_get_activity_id_irp, io_set_activity_id_irp, io_get_activity_id_thread, io_clear_activity_id_thread, io_propagate_activity_id_to_thread, zero, io_reuse_irp, io_initialize_irp, io_set_master_irp_status, io_build_partial_mdl, io_sizeof_work_item, io_allocate_sfio_stream_identifier, zero, zero, zero, zero, io_get_io_priority_hint, zero, io_get_requestor_process, zero, io_get_device_attachment_base_ref, io_get_device_property_data, io_set_hard_error_or_verify_device, io_set_thread_hard_error_mode, io_register_shutdown_notification, io_unregister_shutdown_notification, io_report_target_device_change_asynchronous, io_register_priority_callback, io_unregister_priority_callback, io_wmi_device_object_to_provider_id, zero, io_create_file, io_initialize_work_item, io_query_file_information, io_unregister_plug_play_notification,
    ],
    data_exports: &[("IoDriverObjectType", io_driver_object_type), ("IoFileObjectType", io_file_object_type)],
};

pub mod attach_device_safe {
    //! IoAttachDeviceToDeviceStackSafe — o encadeamento do grupo `io`; a ausência
    //! de dispositivo vira STATUS_NO_SUCH_DEVICE.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::device;
    use crate::rtl::KernelError;

    fn attach(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(device::attach_device_to_device_stack_safe(call.arg(1), call.arg(2), call.arg(3))?))
    }

    pub static GROUP: Group = Group { name: "attach-device-safe", names: &["IoAttachDeviceToDeviceStackSafe"], handlers: &[attach], data_exports: &[] };
}

pub mod attached_device {
    //! IoGetAttachedDevice.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ob::objects::device as device_objects;

    fn get_attached_device(call: &Call) -> Result<u64, KernelError> {
        Ok(device_objects::top(call.arg(1)))
    }

    pub static GROUP: Group = Group {
        name: "attached-device",
        names: &["IoGetAttachedDevice"],
        handlers: &[get_attached_device],
        data_exports: &[],
    };
}

pub mod convert_file_handle {
    //! IoConvertFileHandleToKernelHandle — `ntos/io/file/convert_handle`; falha
    //! interna interrompe o sistema.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::init::exports::fatal_unless_transfer;
    use crate::ntos::io::file::convert_handle as convert_file_handle;
    use crate::rtl::KernelError;

    fn convert(call: &Call) -> Result<u64, KernelError> {
        fatal_unless_transfer("convert-file-handle", convert_file_handle::convert(call.arg(1), call.arg(2) as u8, call.arg(3) as u32, call.arg(4) & 0xFF != 0, call.arg(5))).map(|status| status as u64)
    }

    pub static GROUP: Group = Group { name: "convert-file-handle", names: &["IoConvertFileHandleToKernelHandle"], handlers: &[convert], data_exports: &[] };
}

fn acquire_vpb_spin_lock(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::ke::spin_lock::acquire_vpb_spin_lock(call.arg(1))
}
fn release_vpb_spin_lock(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::ke::spin_lock::release_vpb_spin_lock(call.arg(1))
}

/// IoGetAffinityInterrupt: o processador que recebe a interrupção, no grupo 0.
fn get_affinity_interrupt(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(interrupt::affinity_interrupt(call.arg(1), call.arg(2))))
}

pub static INTERRUPT_AFFINITY_GROUP: Group = Group {
    name: "interrupt-affinity",
    names: &["IoGetAffinityInterrupt"],
    handlers: &[get_affinity_interrupt],
    data_exports: &[],
};

pub static VPB_SPIN_LOCK_GROUP: Group = Group {
    name: "vpb-spin-lock",
    names: &["IoAcquireVpbSpinLock", "IoReleaseVpbSpinLock"],
    handlers: &[acquire_vpb_spin_lock, release_vpb_spin_lock],
    data_exports: &[],
};

pub mod disk_device {
    //! IoGetDiskDeviceObject — `ntos/io/volume_parameters`; falha interna
    //! interrompe o sistema.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::init::exports::fatal_unless_transfer;
    use crate::ntos::io::volume_parameters;
    use crate::rtl::KernelError;

    fn get_disk_device(call: &Call) -> Result<u64, KernelError> {
        fatal_unless_transfer("disk-device", volume_parameters::get_disk_device(call.arg(1), call.arg(2))).map(|status| status as u64)
    }

    pub static GROUP: Group = Group { name: "disk-device", names: &["IoGetDiskDeviceObject"], handlers: &[get_disk_device], data_exports: &[] };
}

pub mod enumerate_devices {
    //! IoEnumerateDeviceObjectList.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ob::objects::device as device_objects;

    fn enumerate_device_object_list(call: &Call) -> Result<u64, KernelError> {
        Ok(device_objects::enumerate(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "enumerate-devices",
        names: &["IoEnumerateDeviceObjectList"],
        handlers: &[enumerate_device_object_list],
        data_exports: &[],
    };
}

pub mod initial_stack {
    //! IoGetInitialStack — `ntos/io/small`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::io::small::initial_stack;
    use crate::rtl::KernelError;

    fn get(_: &Call) -> Result<u64, KernelError> {
        Ok(initial_stack::get())
    }

    pub static GROUP: Group = Group { name: "initial-stack", names: &["IoGetInitialStack"], handlers: &[get], data_exports: &[] };
}

pub mod lower_device {
    //! IoGetLowerDeviceObject.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ob::objects::device as device_objects;

    fn get_lower_device_object(call: &Call) -> Result<u64, KernelError> {
        device_objects::get_lower(call.arg(1))
    }

    pub static GROUP: Group = Group {
        name: "lower-device",
        names: &["IoGetLowerDeviceObject"],
        handlers: &[get_lower_device_object],
        data_exports: &[],
    };
}

pub mod set_completion {
    //! IoSetIoCompletionEx: publica na fila
    //! real e interrompe usos inválidos de ponteiros de kernel.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::ntos::io::completion::set as set_completion;
    use crate::rtl::KernelError;

    fn post(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("set-completion", set_completion::post(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5), call.arg(6), call.arg(7)))? as u64)
    }

    pub static GROUP: Group = Group { name: "set-completion", names: &["IoSetIoCompletionEx"], handlers: &[post], data_exports: &[] };
}

pub mod thread_activity_exports {
    //! IoSetActivityIdThread — `ntos/io/threads`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::io::threads::thread_activity;
    use crate::rtl::KernelError;

    fn set(call: &Call) -> Result<u64, KernelError> {
        Ok(thread_activity::set(call.arg(1)))
    }

    pub static GROUP: Group = Group { name: "thread-activity", names: &["IoSetActivityIdThread"], handlers: &[set], data_exports: &[] };
}

pub mod volume_dos_name {
    //! IoVolumeDeviceToDosName — `ntos/io/volume_dos_name`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::io::volume_dos_name;
    use crate::rtl::KernelError;

    fn volume_device_to_dos_name(call: &Call) -> Result<u64, KernelError> {
        Ok(volume_dos_name::volume_device_to_dos_name(call.arg(1), call.arg(2))? as u64)
    }

    pub static GROUP: Group = Group { name: "volume-dos-name", names: &["IoVolumeDeviceToDosName"], handlers: &[volume_device_to_dos_name], data_exports: &[] };
}

pub mod create_completion {
    //! ZwCreateIoCompletion: KernelMode,
    //! handles de kernel quando pedidos e a ABI de 64 bits.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::ntos::io::completion::create as create_completion;
    use crate::rtl::KernelError;

    fn create(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("create-completion", create_completion::create(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32, 0))? as u64)
    }

    pub static GROUP: Group = Group { name: "create-completion", names: &["ZwCreateIoCompletion"], handlers: &[create], data_exports: &[] };
}

pub mod remove_completion {
    //! ZwRemoveIoCompletionEx: entrada
    //! Zw de seis argumentos, com espera cooperativa sem contexto suspenso.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::completion::remove as remove_completion;
    use crate::rtl::KernelError;

    fn remove(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(remove_completion::remove_cooperative(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5), call.arg(6) & 0xFF != 0)?))
    }

    pub static GROUP: Group = Group { name: "remove-completion", names: &["ZwRemoveIoCompletionEx"], handlers: &[remove], data_exports: &[] };
}

pub mod read_file {
    //! NtReadFile — adaptador da ABI nativa de `ntos/io/file/read`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::io::file::read as read_file;
    use crate::rtl::KernelError;

    fn read(call: &Call) -> Result<u64, KernelError> {
        Ok(read_file::read(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7) as u32, call.arg(8), call.arg(9))? as u64)
    }

    pub static GROUP: Group = Group { name: "read-file", names: &["NtReadFile"], handlers: &[read], data_exports: &[] };
}

pub mod write_file {
    //! NtWriteFile — adaptador da ABI nativa de `ntos/io/file/write`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::io::file::write as write_file;
    use crate::rtl::KernelError;

    fn write(call: &Call) -> Result<u64, KernelError> {
        Ok(write_file::write(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7) as u32, call.arg(8), call.arg(9))? as u64)
    }

    pub static GROUP: Group = Group { name: "write-file", names: &["NtWriteFile"], handlers: &[write], data_exports: &[] };
}

pub mod query_file {
    //! NtQueryInformationFile — adaptador da ABI nativa de `ntos/io/file/query`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::io::file::query as query_file;
    use crate::rtl::KernelError;

    fn query(call: &Call) -> Result<u64, KernelError> {
        Ok(query_file::query(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5) as u32)? as u64)
    }

    pub static GROUP: Group = Group { name: "query-file", names: &["NtQueryInformationFile"], handlers: &[query], data_exports: &[] };
}

pub mod delete_file {
    //! ZwDeleteFile — `ntos/io/file/delete`; o Zw força KernelMode durante todo o
    //! serviço e conserva o PreviousMode anterior.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::io::file::delete as delete_file;
    use crate::ntos::ps::previous_mode;
    use crate::rtl::KernelError;

    fn remove(call: &Call) -> Result<u64, KernelError> {
        Ok(previous_mode::with_kernel(|| delete_file::remove(call.arg(1)))?? as u64)
    }

    pub static GROUP: Group = Group { name: "delete-file", names: &["ZwDeleteFile"], handlers: &[remove], data_exports: &[] };
}

pub mod device_control {
    //! ZwDeviceIoControlFile — `ntos/io/device_control`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::io::device_control;
    use crate::rtl::KernelError;

    fn control(call: &Call) -> Result<u64, KernelError> {
        Ok(device_control::control(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6) as u32, call.arg(7), call.arg(8) as u32, call.arg(9), call.arg(10) as u32)? as u64)
    }

    pub static GROUP: Group = Group { name: "device-control", names: &["ZwDeviceIoControlFile"], handlers: &[control], data_exports: &[] };
}

pub mod driver_helpers {
    //! Auxiliares que vários drivers reais importam e que o OpenNT atende com
    //! a semântica real do ntoskrnl: referência segura/adiada de objetos, o
    //! mapeamento genérico do FILE_OBJECT e consultas de energia/boot que não
    //! se aplicam a esta plataforma.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::object_types;
    use crate::ntos::io::small::portable_operating_system;
    use crate::ntos::ob::object_reference::{dereference_with_tag, reference_with_tag};
    use crate::ntos::ob::reference_trace::DEFAULT_TAG;
    use crate::rtl::KernelError;

    /// ObReferenceObjectSafe: TRUE se a referência foi adquirida (objeto vivo).
    fn reference_object_safe(call: &Call) -> Result<u64, KernelError> {
        Ok(reference_with_tag(call.arg(1), DEFAULT_TAG, true).is_ok() as u64)
    }
    fn reference_object_safe_with_tag(call: &Call) -> Result<u64, KernelError> {
        Ok(reference_with_tag(call.arg(1), call.arg(2) as u32, true).is_ok() as u64)
    }
    /// ObDereferenceObjectDeferDelete: a coleta do OpenNT já é feita fora da
    /// linha do chamador, então o "defer" não muda nada.
    fn dereference_object_defer_delete(call: &Call) -> Result<u64, KernelError> {
        dereference_with_tag(call.arg(1), DEFAULT_TAG, true)?;
        Ok(0)
    }
    fn dereference_object_defer_delete_with_tag(call: &Call) -> Result<u64, KernelError> {
        dereference_with_tag(call.arg(1), call.arg(2) as u32, true)?;
        Ok(0)
    }

    /// IoGetFileObjectGenericMapping: &IopFileMapping.
    fn get_file_object_generic_mapping(_: &Call) -> Result<u64, KernelError> {
        Ok(object_types::file_object_generic_mapping())
    }

    /// Sem estimador de energia, sem soft boot e sem Windows-To-Go aqui.
    fn energy_estimation_enabled(_: &Call) -> Result<u64, KernelError> {
        Ok(0)
    }
    fn update_component_power(_: &Call) -> Result<u64, KernelError> {
        Ok(0)
    }
    fn is_soft_boot(_: &Call) -> Result<u64, KernelError> {
        Ok(0)
    }
    fn check_portable_operating_system(call: &Call) -> Result<u64, KernelError> {
        portable_operating_system::check(call.arg(1));
        Ok(0)
    }
    /// ZwFlushKey: o Registry do OpenNT é em memória; nada a descarregar.
    fn flush_key(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(0))
    }

    pub static GROUP: Group = Group {
        name: "driver-helpers",
        names: &[
            "ObReferenceObjectSafe", "ObReferenceObjectSafeWithTag", "ObDereferenceObjectDeferDelete",
            "ObDereferenceObjectDeferDeleteWithTag", "IoGetFileObjectGenericMapping", "PoEnergyEstimationEnabled",
            "PsUpdateComponentPower", "ExIsSoftBoot", "RtlCheckPortableOperatingSystem", "ZwFlushKey",
        ],
        handlers: &[
            reference_object_safe, reference_object_safe_with_tag, dereference_object_defer_delete,
            dereference_object_defer_delete_with_tag, get_file_object_generic_mapping, energy_estimation_enabled,
            update_component_power, is_soft_boot, check_portable_operating_system, flush_key,
        ],
        data_exports: &[],
    };
}

pub mod io_diagnostics {
    //! Exports que o `watchdog.sys` real (e, abaixo dele, todo o stack de
    //! vídeo) importa do ntoskrnl e que o OpenNT ainda não oferecia: captura de
    //! contexto, consultas de console/WMI e os Zw que o watchdog usa no início.
    //! São atendidos com a semântica do NT; onde o subsistema não existe nesta
    //! plataforma (WMI, hard-error de usuário, depuração de kernel) devolvem o
    //! status que a inicialização do watchdog tolera, como o próprio Windows.

    use crate::ntos::inc::status::STATUS_NOT_IMPLEMENTED;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::file::zw as zw_files;
    use crate::ntos::io::small::wmi_registration;
    use crate::ntos::rtl::native_context;
    use crate::rtl::KernelError;

    /// IoRaiseInformationalHardError: sem porta de hard-error de usuário neste
    /// host; o uso do watchdog é não-fatal, então nenhum popup sobe (FALSE).
    fn raise_informational_hard_error(_: &Call) -> Result<u64, KernelError> {
        Ok(0)
    }

    /// IoWMIOpenBlock / IoWMIQueryAllData: sem provedor WMI, o GUID não existe.
    fn wmi_open_block(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(wmi_registration::guid_not_found()))
    }
    fn wmi_query_all_data(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(wmi_registration::guid_not_found()))
    }

    /// RtlCaptureContext: o CONTEXT nativo ativo, com ContextFlags = CONTEXT_FULL.
    fn capture_context(call: &Call) -> Result<u64, KernelError> {
        native_context::capture_context(call.arg(1));
        Ok(0)
    }

    /// RtlGetActiveConsoleId: a sessão de console ativa é a 0.
    fn get_active_console_id(_: &Call) -> Result<u64, KernelError> {
        Ok(0)
    }

    /// ZwFlushBuffersFileEx: as escritas do OpenNT já são síncronas; valida o
    /// handle e escreve o IO_STATUS_BLOCK como o ZwFlushBuffersFile (o
    /// IO_STATUS_BLOCK é o 5º argumento no NtFlushBuffersFileEx).
    fn flush_buffers_file_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(zw_files::flush_buffers_file(call.arg(1), call.arg(5))))
    }

    /// ZwSystemDebugControl: depuração de kernel não é suportada neste host.
    fn system_debug_control(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(STATUS_NOT_IMPLEMENTED))
    }

    pub static GROUP: Group = Group {
        name: "io-diagnostics",
        names: &[
            "IoRaiseInformationalHardError", "IoWMIOpenBlock", "IoWMIQueryAllData",
            "RtlCaptureContext", "RtlGetActiveConsoleId", "ZwFlushBuffersFileEx", "ZwSystemDebugControl",
        ],
        handlers: &[
            raise_informational_hard_error, wmi_open_block, wmi_query_all_data,
            capture_context, get_active_console_id, flush_buffers_file_ex, system_debug_control,
        ],
        data_exports: &[],
    };
}

pub mod x86bios_sleep_misc {
    //! Exports que o BasicDisplay.sys real (Microsoft Basic Display, driver de
    //! vídeo display-only) importa e que faltavam: o bit-scan e a comparação da
    //! CRT, o bloqueio de sono do Po e os x86Bios. Não há emulador de VBIOS de
    //! 16 bits aqui, então a chamada de BIOS falha de modo tolerado, como numa
    //! máquina sem VGA BIOS legado.

    use crate::ntos::inc::status::STATUS_NOT_IMPLEMENTED;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::po::power_manager;
    use crate::ntos::rtl::{bitmap, crt};
    use crate::rtl::KernelError;

    /// RtlFindLeastSignificantBit: CCHAR (-1 estendido para 0xFF..FF).
    fn find_least_significant_bit(call: &Call) -> Result<u64, KernelError> {
        Ok(bitmap::find_least_significant_bit(call.arg(1)) as i64 as u64)
    }

    fn strnicmp(call: &Call) -> Result<u64, KernelError> {
        Ok(crt::strnicmp(call.arg(1), call.arg(2), call.arg(3)) as i64 as u64)
    }

    fn disable_sleep_states(_: &Call) -> Result<u64, KernelError> {
        Ok(power_manager::disable_sleep_states())
    }
    fn reenable_sleep_states(_: &Call) -> Result<u64, KernelError> {
        Ok(0)
    }

    /// x86BiosCall: sem VBIOS emulado, devolve FALSE; o BasicDisplay tolera.
    fn x86_bios_call(_: &Call) -> Result<u64, KernelError> {
        Ok(0)
    }
    /// x86BiosFreeBuffer: nada a liberar — STATUS_SUCCESS.
    fn x86_bios_free_buffer(_: &Call) -> Result<u64, KernelError> {
        Ok(0)
    }
    /// x86BiosAllocateBuffer/ReadMemory/WriteMemory: recurso de VBIOS ausente.
    fn x86_bios_not_implemented(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(STATUS_NOT_IMPLEMENTED))
    }

    pub static GROUP: Group = Group {
        name: "x86bios-sleep-misc",
        names: &[
            "RtlFindLeastSignificantBit", "_strnicmp", "PoDisableSleepStates", "PoReenableSleepStates",
            "x86BiosAllocateBuffer", "x86BiosCall", "x86BiosFreeBuffer", "x86BiosReadMemory", "x86BiosWriteMemory",
        ],
        handlers: &[
            find_least_significant_bit, strnicmp, disable_sleep_states, reenable_sleep_states,
            x86_bios_not_implemented, x86_bios_call, x86_bios_free_buffer, x86_bios_not_implemented, x86_bios_not_implemented,
        ],
        data_exports: &[],
    };
}

// =============================================================================

pub mod io_csq {
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::csq::{self, CsqRoutines};
    use crate::rtl::KernelError;

    fn initialize(call: &Call) -> Result<u64, KernelError> {
        let routines = CsqRoutines { insert: call.arg(2), remove: call.arg(3), peek_next: call.arg(4), acquire_lock: call.arg(5), release_lock: call.arg(6), complete_canceled: call.arg(7) };
        Ok(csq::initialize(call.arg(1), &routines, false) as u64)
    }
    fn initialize_ex(call: &Call) -> Result<u64, KernelError> {
        let routines = CsqRoutines { insert: call.arg(2), remove: call.arg(3), peek_next: call.arg(4), acquire_lock: call.arg(5), release_lock: call.arg(6), complete_canceled: call.arg(7) };
        Ok(csq::initialize(call.arg(1), &routines, true) as u64)
    }
    fn insert_irp(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(csq::insert_irp(call.arg(1), call.arg(2), call.arg(3), 0)?))
    }
    fn insert_irp_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(csq::insert_irp(call.arg(1), call.arg(2), call.arg(3), call.arg(4))?))
    }
    fn remove_irp(call: &Call) -> Result<u64, KernelError> {
        csq::remove_irp(call.arg(1), call.arg(2))
    }
    fn remove_next_irp(call: &Call) -> Result<u64, KernelError> {
        csq::remove_next_irp(call.arg(1), call.arg(2))
    }

    pub static GROUP: Group = Group {
        name: "io-csq",
        names: &["IoCsqInitialize", "IoCsqInitializeEx", "IoCsqInsertIrp", "IoCsqInsertIrpEx", "IoCsqRemoveIrp", "IoCsqRemoveNextIrp"],
        handlers: &[initialize, initialize_ex, insert_irp, insert_irp_ex, remove_irp, remove_next_irp],
        data_exports: &[],
    };
}

pub mod io_irp_request {
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::irp_request::{self, InvokeOn};
    use crate::rtl::KernelError;

    fn synchronous_call_driver(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(irp_request::synchronous_call(call.arg(1), call.arg(2))?))
    }
    fn forward_irp_synchronously(call: &Call) -> Result<u64, KernelError> {
        Ok(irp_request::forward_irp_synchronously(call.arg(1), call.arg(2))? as u64)
    }
    fn build_asynchronous_fsd_request(call: &Call) -> Result<u64, KernelError> {
        irp_request::build_asynchronous_fsd_request(call.arg(1) as u32, call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5), call.arg(6))
    }
    fn allocate_irp_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(irp_request::allocate_irp_ex(call.arg(1), call.arg(2) as u8, call.arg(3) as u8 != 0))
    }
    fn set_completion_routine_ex(call: &Call) -> Result<u64, KernelError> {
        let invoke = InvokeOn { success: call.arg(5) as u8 != 0, error: call.arg(6) as u8 != 0, cancel: call.arg(7) as u8 != 0 };
        Ok(signed_status(irp_request::set_completion_routine_ex(call.arg(1), call.arg(2), call.arg(3), call.arg(4), invoke)?))
    }
    fn is_operation_synchronous(call: &Call) -> Result<u64, KernelError> {
        Ok(irp_request::is_operation_synchronous(call.arg(1)) as u64)
    }
    fn propagate_irp_extension(call: &Call) -> Result<u64, KernelError> {
        irp_request::propagate_irp_extension(call.arg(1), call.arg(2), call.arg(3) as u32);
        Ok(0)
    }
    fn get_requestor_process_id(call: &Call) -> Result<u64, KernelError> {
        Ok(irp_request::requestor_process_id(call.arg(1))? as u64)
    }
    fn get_requestor_session_id(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(irp_request::requestor_session_id(call.arg(1), call.arg(2))))
    }
    fn get_initiator_process(call: &Call) -> Result<u64, KernelError> {
        Ok(irp_request::initiator_process(call.arg(1)))
    }

    pub static GROUP: Group = Group {
        name: "io-irp-request",
        names: &[
            "IoSynchronousCallDriver", "IoForwardIrpSynchronously", "IoBuildAsynchronousFsdRequest", "IoAllocateIrpEx",
            "IoSetCompletionRoutineEx", "IoIsOperationSynchronous", "IoPropagateIrpExtension", "IoGetRequestorProcessId",
            "IoGetRequestorSessionId", "IoGetInitiatorProcess",
        ],
        handlers: &[
            synchronous_call_driver, forward_irp_synchronously, build_asynchronous_fsd_request, allocate_irp_ex,
            set_completion_routine_ex, is_operation_synchronous, propagate_irp_extension, get_requestor_process_id,
            get_requestor_session_id, get_initiator_process,
        ],
        data_exports: &[],
    };
}

pub mod io_pnp_interface {
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::pnp_interfaces;
    use crate::rtl::KernelError;

    fn get_device_interfaces(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(pnp_interfaces::device_interface_list(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4))?))
    }
    fn get_iommu_interface(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(pnp_interfaces::iommu_interface(call.arg(1), call.arg(2))))
    }

    pub static GROUP: Group = Group {
        name: "io-pnp-interface",
        names: &["IoGetDeviceInterfaces", "IoGetIommuInterface"],
        handlers: &[get_device_interfaces, get_iommu_interface],
        data_exports: &[],
    };
}

pub mod io_builtin_driver {
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::builtin_driver;
    use crate::rtl::KernelError;

    fn create_driver(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(builtin_driver::create(call.arg(1), call.arg(2))?))
    }

    pub static GROUP: Group = Group { name: "io-builtin-driver", names: &["IoCreateDriver"], handlers: &[create_driver], data_exports: &[] };
}

pub mod io_named_event {
    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::io::named_event;
    use crate::rtl::KernelError;

    fn create_notification_event(call: &Call) -> Result<u64, KernelError> {
        named_event::create(call.arg(1), named_event::NOTIFICATION_EVENT, call.arg(2))
    }
    fn create_synchronization_event(call: &Call) -> Result<u64, KernelError> {
        named_event::create(call.arg(1), named_event::SYNCHRONIZATION_EVENT, call.arg(2))
    }

    pub static GROUP: Group = Group {
        name: "io-named-event",
        names: &["IoCreateNotificationEvent", "IoCreateSynchronizationEvent"],
        handlers: &[create_notification_event, create_synchronization_event],
        data_exports: &[],
    };
}

pub mod io_wmi_data_block {
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::wmi_data_block;
    use crate::rtl::KernelError;

    fn query_single_instance(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(wmi_data_block::query_single_instance(call.arg(1), call.arg(2), call.arg(3), call.arg(4))))
    }
    fn handle_to_instance_name(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(wmi_data_block::handle_to_instance_name(call.arg(1), call.arg(2), call.arg(3))))
    }

    pub static GROUP: Group = Group {
        name: "io-wmi-data-block",
        names: &["IoWMIQuerySingleInstance", "IoWMIHandleToInstanceName"],
        handlers: &[query_single_instance, handle_to_instance_name],
        data_exports: &[],
    };
}

pub mod io_work_item_queue {
    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::io::work_items;
    use crate::rtl::KernelError;

    fn try_queue_work_item(call: &Call) -> Result<u64, KernelError> {
        work_items::queue_work_item_ex(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4), true);
        Ok(1)
    }

    pub static GROUP: Group = Group { name: "io-work-item-queue", names: &["IoTryQueueWorkItem"], handlers: &[try_queue_work_item], data_exports: &[] };
}

pub mod io_driver_registry {
    //! Adaptadores de IoOpenDriverRegistryKey (`io/driver_registry.rs`) e
    //! IoGetDeviceNumaNode (`io/pnp.rs`).

    use crate::ntos::inc::types::{DriverObject, Field, NtStruct};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::{driver_registry, pnp};
    use crate::rtl::KernelError;

    /// (PDRIVER_OBJECT, DRIVER_REGKEY_TYPE, ACCESS_MASK, ULONG Flags, PHANDLE).
    fn open_driver_registry_key(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: DRIVER_OBJECT vivo e PHANDLE de saída do driver chamador
        // (NULL vira None e é recusado pela rotina, como no NT).
        let driver = (call.arg(1) != 0).then(|| unsafe { DriverObject::at(call.arg(1)) });
        let output = (call.arg(5) != 0).then(|| unsafe { Field::<u64>::at(call.arg(5)) });
        Ok(signed_status(driver_registry::open_driver_registry_key(driver, call.arg(2) as u32, call.arg(3) as u32, call.arg(4) as u32, output)?))
    }

    /// (PDEVICE_OBJECT Pdo, PUSHORT NodeNumber).
    fn get_device_numa_node(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PUSHORT de saída do driver, gravado só em sucesso.
        let node = unsafe { Field::<u16>::at(call.arg(2)) };
        Ok(signed_status(pnp::device_numa_node(call.arg(1), node)))
    }

    pub static GROUP: Group = Group {
        name: "io-driver-registry",
        names: &["IoOpenDriverRegistryKey", "IoGetDeviceNumaNode"],
        handlers: &[open_driver_registry_key, get_device_numa_node],
        data_exports: &[],
    };
}

pub mod io_top_level_irp {
    //! Adaptadores de Io{Get,Set}TopLevelIrp e IoThreadToProcess (lógica em
    //! `io/threads.rs`, `top_level_irp`).

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::io::threads::top_level_irp;
    use crate::rtl::KernelError;

    fn get_top_level_irp(_: &Call) -> Result<u64, KernelError> {
        Ok(top_level_irp::get())
    }

    fn set_top_level_irp(call: &Call) -> Result<u64, KernelError> {
        top_level_irp::set(call.arg(1));
        Ok(0)
    }

    fn thread_to_process(call: &Call) -> Result<u64, KernelError> {
        Ok(top_level_irp::thread_to_process(call.arg(1)))
    }

    pub static GROUP: Group = Group {
        name: "io-top-level-irp",
        names: &["IoGetTopLevelIrp", "IoSetTopLevelIrp", "IoThreadToProcess"],
        handlers: &[get_top_level_irp, set_top_level_irp, thread_to_process],
        data_exports: &[],
    };
}

pub mod io_file_object_extensions {
    //! Extensões de IRP (zeroing/track offset, copy information) e de
    //! FILE_OBJECT (transação, silo): a lógica mora em `io/extensions.rs`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::inc::field::Field;
    use crate::ntos::inc::types::{FileObject, NtStruct};
    use crate::ntos::io::extensions;
    use crate::rtl::KernelError;

    fn get_zeroing_offset(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PULONG de saída do FS.
        Ok(signed_status(extensions::fs_zeroing_offset(call.arg(1), unsafe { Field::<u32>::at(call.arg(2)) })))
    }
    fn set_zeroing_offset(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(extensions::set_fs_zeroing_offset(call.arg(1), call.arg(2) as u32)))
    }
    fn set_zeroing_offset_required(call: &Call) -> Result<u64, KernelError> {
        extensions::set_fs_zeroing_offset_required(call.arg(1)).map(signed_status)
    }
    fn set_track_offset_state(call: &Call) -> Result<u64, KernelError> {
        extensions::set_fs_track_offset_state(call.arg(1), call.arg(2), call.arg(3)).map(signed_status)
    }
    fn get_copy_information(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(extensions::copy_information(call.arg(1), call.arg(2))))
    }
    fn get_transaction_parameter_block(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: FILE_OBJECT vivo do chamador.
        Ok(extensions::transaction_parameter_block(unsafe { FileObject::at(call.arg(1)) }))
    }
    fn get_silo(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: FILE_OBJECT vivo do chamador.
        Ok(extensions::file_object_silo(unsafe { FileObject::at(call.arg(1)) }))
    }

    pub static GROUP: Group = Group {
        name: "io-file-object-extensions",
        names: &[
            "IoGetFsZeroingOffset",
            "IoSetFsZeroingOffset",
            "IoSetFsZeroingOffsetRequired",
            "IoSetFsTrackOffsetState",
            "IoGetCopyInformationExtension",
            "IoGetTransactionParameterBlock",
            "IoGetSilo",
        ],
        handlers: &[
            get_zeroing_offset,
            set_zeroing_offset,
            set_zeroing_offset_required,
            set_track_offset_state,
            get_copy_information,
            get_transaction_parameter_block,
            get_silo,
        ],
        data_exports: &[],
    };
}

pub mod io_priority {
    //! Prioridade de I/O: a lógica mora em `io/priority.rs` e `io/extensions.rs`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::inc::types::extra_fs_fat::IoPriorityInfo;
    use crate::ntos::inc::types::{Ethread, FileObject, Irp, NtStruct};
    use crate::ntos::io::{extensions, priority};
    use crate::rtl::KernelError;

    // SAFETY (todas): o chamador passa IRP/FILE_OBJECT/ETHREAD vivos (ou NULL onde o
    // NT aceita NULL) e um IO_PRIORITY_INFO de kernel.
    fn retrieve(call: &Call) -> Result<u64, KernelError> {
        let irp = (call.arg(1) != 0).then(|| unsafe { Irp::at(call.arg(1)) });
        let file = (call.arg(2) != 0).then(|| unsafe { FileObject::at(call.arg(2)) });
        let thread = (call.arg(3) != 0).then(|| unsafe { Ethread::at(call.arg(3)) });
        Ok(signed_status(priority::retrieve_priority_info(irp, file, thread, unsafe { IoPriorityInfo::at(call.arg(4)) })))
    }
    fn apply(call: &Call) -> Result<u64, KernelError> {
        let output = (call.arg(2) != 0).then(|| unsafe { IoPriorityInfo::at(call.arg(2)) });
        priority::apply_priority_info(unsafe { IoPriorityInfo::at(call.arg(1)) }, output, unsafe { Ethread::at(call.arg(3)) }).map(signed_status)
    }
    fn hint_into_thread(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(priority::set_thread_priority_hint(unsafe { Ethread::at(call.arg(1)) }, call.arg(2) as u32)))
    }
    fn hint_into_file_object(call: &Call) -> Result<u64, KernelError> {
        extensions::set_file_object_priority_hint(unsafe { FileObject::at(call.arg(1)) }, call.arg(2) as u32).map(signed_status)
    }

    pub static GROUP: Group = Group {
        name: "io-priority",
        names: &["IoRetrievePriorityInfo", "IoApplyPriorityInfoThread", "IoSetIoPriorityHintIntoThread", "IoSetIoPriorityHintIntoFileObject"],
        handlers: &[retrieve, apply, hint_into_thread, hint_into_file_object],
        data_exports: &[],
    };
}

pub mod io_file_system {
    //! Registro de file systems, notificações, verificação de volume, stream
    //! file objects: a lógica mora em `io/file_system.rs`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::inc::field::Field;
    use crate::ntos::inc::types::{DeviceObject, Ethread, FileObject, Irp, Kthread, NtStruct};
    use crate::ntos::io::file_system;
    use crate::ntos::io::threads::thread_queries;
    use crate::rtl::KernelError;

    // SAFETY (todas): os FSs e filtros passam DEVICE_OBJECT/FILE_OBJECT/IRP/ETHREAD vivos.
    fn device(address: u64) -> &'static DeviceObject {
        unsafe { DeviceObject::at(address) }
    }
    fn file(address: u64) -> &'static FileObject {
        unsafe { FileObject::at(address) }
    }
    fn thread(address: u64) -> &'static Ethread {
        unsafe { Ethread::at(address) }
    }

    fn register(call: &Call) -> Result<u64, KernelError> {
        file_system::register_file_system(device(call.arg(1))).map(|_| 0)
    }
    fn unregister(call: &Call) -> Result<u64, KernelError> {
        file_system::unregister_file_system(device(call.arg(1))).map(|_| 0)
    }
    fn register_change_mount_aware(call: &Call) -> Result<u64, KernelError> {
        file_system::register_fs_registration_change(call.arg(1), call.arg(2), call.arg(3) & 0xFF != 0).map(signed_status)
    }
    fn enumerate_filters(call: &Call) -> Result<u64, KernelError> {
        file_system::enumerate_registered_filters(call.arg(1), call.arg(2) as u32, unsafe { Field::<u32>::at(call.arg(3)) }).map(signed_status)
    }
    fn base_file_system_device(call: &Call) -> Result<u64, KernelError> {
        Ok(file_system::base_file_system_device(file(call.arg(1))))
    }
    fn verify_volume(call: &Call) -> Result<u64, KernelError> {
        file_system::verify_volume(device(call.arg(1)), call.arg(2) & 0xFF != 0).map(signed_status)
    }
    fn get_device_to_verify(call: &Call) -> Result<u64, KernelError> {
        Ok(file_system::device_to_verify(thread(call.arg(1))))
    }
    fn set_device_to_verify(call: &Call) -> Result<u64, KernelError> {
        file_system::set_device_to_verify(thread(call.arg(1)), call.arg(2));
        Ok(0)
    }
    fn create_stream(call: &Call) -> Result<u64, KernelError> {
        file_system::create_stream_file_object(call.arg(1), call.arg(2), false)
    }
    fn create_stream_lite(call: &Call) -> Result<u64, KernelError> {
        file_system::create_stream_file_object(call.arg(1), call.arg(2), true)
    }
    fn cancel_file_open(call: &Call) -> Result<u64, KernelError> {
        file_system::cancel_file_open(device(call.arg(1)), file(call.arg(2))).map(|_| 0)
    }
    fn replace_name(call: &Call) -> Result<u64, KernelError> {
        file_system::replace_file_object_name(file(call.arg(1)), call.arg(2), call.arg(3) as u16).map(signed_status)
    }
    fn raise_hard_error(call: &Call) -> Result<u64, KernelError> {
        file_system::raise_hard_error(unsafe { Irp::at(call.arg(1)) }).map(|_| 0)
    }
    fn is_system_thread(call: &Call) -> Result<u64, KernelError> {
        Ok(thread_queries::is_system_thread(unsafe { Kthread::at(call.arg(1)) }) as u64)
    }
    fn within_stack_limits(call: &Call) -> Result<u64, KernelError> {
        Ok(thread_queries::within_stack_limits(call.arg(1), call.arg(2)) as u64)
    }

    pub static GROUP: Group = Group {
        name: "io-file-system",
        names: &[
            "IoRegisterFileSystem",
            "IoUnregisterFileSystem",
            "IoRegisterFsRegistrationChangeMountAware",
            "IoEnumerateRegisteredFiltersList",
            "IoGetBaseFileSystemDeviceObject",
            "IoVerifyVolume",
            "IoGetDeviceToVerify",
            "IoSetDeviceToVerify",
            "IoCreateStreamFileObject",
            "IoCreateStreamFileObjectLite",
            "IoCancelFileOpen",
            "IoReplaceFileObjectName",
            "IoRaiseHardError",
            "IoIsSystemThread",
            "IoWithinStackLimits",
        ],
        handlers: &[
            register,
            unregister,
            register_change_mount_aware,
            enumerate_filters,
            base_file_system_device,
            verify_volume,
            get_device_to_verify,
            set_device_to_verify,
            create_stream,
            create_stream_lite,
            cancel_file_open,
            replace_name,
            raise_hard_error,
            is_system_thread,
            within_stack_limits,
        ],
        data_exports: &[],
    };
}

pub mod io_irp_support {
    use crate::ntos::inc::types::{Irp, NtStruct};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::irp_support;
    use crate::rtl::KernelError;

    fn make_associated_irp(call: &Call) -> Result<u64, KernelError> {
        Ok(irp_support::make_associated_irp(call.arg(1), call.arg(2) as u8))
    }

    fn adjust_stack_size_for_redirection(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(irp_support::adjust_stack_size_for_redirection(call.arg(1), call.arg(2), call.arg(3))?))
    }

    fn set_io_priority_hint(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PIRP de um chamador de modo kernel.
        let irp = unsafe { Irp::at(call.arg(1)) };
        Ok(signed_status(irp_support::set_io_priority_hint(irp, call.arg(2) as u32)))
    }

    fn get_adapter_crypto_engine_extension(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PIRP de um chamador de modo kernel.
        let irp = unsafe { Irp::at(call.arg(1)) };
        Ok(signed_status(irp_support::get_adapter_crypto_engine_extension(irp, call.arg(2))))
    }

    pub static GROUP: Group = Group {
        name: "io-irp-support",
        names: &["IoMakeAssociatedIrp", "IoAdjustStackSizeForRedirection", "IoSetIoPriorityHint", "IoGetAdapterCryptoEngineExtension"],
        handlers: &[make_associated_irp, adjust_stack_size_for_redirection, set_io_priority_hint, get_adapter_crypto_engine_extension],
        data_exports: &[],
    };
}

pub mod io_file_system_support {
    //! Validação de EA/cota, confiança de redirecionamento, dica de
    //! dispositivo, stream file object com handle, IoSetInformation, nome DOS
    //! do arquivo e transferência de ActivityId: a lógica mora nos assuntos.

    use crate::ntos::inc::field::{Field, NtStruct};
    use crate::ntos::inc::types::{FileObject, SecuritySubjectContext};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::file::{information, zw as zw_files};
    use crate::ntos::io::{buffer_validation, extensions, file_system, redirection_trust, threads};
    use crate::rtl::KernelError;

    /// IoCheckEaBufferValidity(EaBuffer, EaLength, *ErrorOffset).
    fn check_ea_buffer_validity(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PULONG ErrorOffset do FS chamador (modo kernel).
        let error_offset = unsafe { Field::<u32>::at(call.arg(3)) };
        Ok(signed_status(buffer_validation::check_ea_buffer_validity(call.arg(1), call.arg(2) as u32, error_offset)))
    }

    /// IoCheckQuotaBufferValidity(QuotaBuffer, QuotaLength, *ErrorOffset).
    fn check_quota_buffer_validity(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PULONG ErrorOffset do FS chamador (modo kernel).
        let error_offset = unsafe { Field::<u32>::at(call.arg(3)) };
        Ok(signed_status(buffer_validation::check_quota_buffer_validity(call.arg(1), call.arg(2) as u32, error_offset)))
    }

    /// IoCheckRedirectionTrustLevel(TrustLevel, UserMode, SubjectContext, Flags, Context).
    fn check_redirection_trust_level(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: SECURITY_SUBJECT_CONTEXT opcional do chamador de modo kernel.
        let subject = (call.arg(3) != 0).then(|| unsafe { SecuritySubjectContext::at(call.arg(3)) });
        redirection_trust::check_trust_level(call.arg(2) as u8 != 0, subject, call.arg(4) as u32).map(signed_status)
    }

    /// IoComputeRedirectionTrustLevel(Reserved, UserMode, SubjectContext, *TrustLevel).
    fn compute_redirection_trust_level(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: SECURITY_SUBJECT_CONTEXT opcional e PULONG TrustLevel do chamador de modo kernel.
        let (subject, output) = unsafe { ((call.arg(3) != 0).then(|| SecuritySubjectContext::at(call.arg(3))), Field::<u32>::at(call.arg(4))) };
        redirection_trust::compute_trust_level(call.arg(2) as u8 != 0, subject, output).map(signed_status)
    }

    /// IoCopyDeviceObjectHint(SourceFileObject, TargetFileObject).
    fn copy_device_object_hint(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: FILE_OBJECTs vivos do FS chamador.
        let (source, target) = unsafe { (FileObject::at(call.arg(1)), FileObject::at(call.arg(2))) };
        extensions::copy_device_object_hint(source, target).map(signed_status)
    }

    /// IoCreateFileSpecifyDeviceObjectHint(FileHandle, DesiredAccess,
    /// ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
    /// ShareAccess, Disposition, CreateOptions, EaBuffer, EaLength,
    /// CreateFileType, InternalParameters, Options, DeviceObject) = IoCreateFileEx
    /// com IO_DRIVER_CREATE_CONTEXT{DeviceObjectHint}: o mesmo caminho do
    /// IoCreateFileEx do OpenNT (que não modela DriverContext; o 15º argumento
    /// fica além dos 14 do trampolim).
    fn create_file_specify_device_object_hint(call: &Call) -> Result<u64, KernelError> {
        zw_files::create_kernel_file(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4), call.arg(7) as u32, call.arg(8) as u32, call.arg(9) as u32).map(signed_status)
    }

    /// IoCreateStreamFileObjectEx(FileObject, DeviceObject, *FileHandle) -> PFILE_OBJECT.
    fn create_stream_file_object_ex(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PHANDLE opcional do FS chamador (modo kernel).
        let handle = (call.arg(3) != 0).then(|| unsafe { Field::<u64>::at(call.arg(3)) });
        file_system::create_stream_file_object_ex(call.arg(1), call.arg(2), handle)
    }

    /// IoSetInformation(FileObject, FileInformationClass, Length, FileInformation).
    fn set_information(call: &Call) -> Result<u64, KernelError> {
        information::set_native(call.arg(1), call.arg(2) as u32, call.arg(3) as u32, call.arg(4)).map(signed_status)
    }

    /// IoQueryFileDosDeviceName(FileObject, *ObjectNameInformation).
    fn query_file_dos_device_name(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: POBJECT_NAME_INFORMATION* de saída do FS chamador (modo kernel).
        let output = unsafe { Field::<u64>::at(call.arg(2)) };
        information::query_dos_device_name(call.arg(1), output).map(signed_status)
    }

    /// IoTransferActivityId(ActivityId, RelatedActivityId) -> VOID.
    fn transfer_activity_id(call: &Call) -> Result<u64, KernelError> {
        threads::activity_transfer::transfer(call.arg(1), call.arg(2));
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "io-file-system-support",
        names: &[
            "IoCheckEaBufferValidity",
            "IoCheckQuotaBufferValidity",
            "IoCheckRedirectionTrustLevel",
            "IoComputeRedirectionTrustLevel",
            "IoCopyDeviceObjectHint",
            "IoCreateFileSpecifyDeviceObjectHint",
            "IoCreateStreamFileObjectEx",
            "IoSetInformation",
            "IoQueryFileDosDeviceName",
            "IoTransferActivityId",
        ],
        handlers: &[
            check_ea_buffer_validity,
            check_quota_buffer_validity,
            check_redirection_trust_level,
            compute_redirection_trust_level,
            copy_device_object_hint,
            create_file_specify_device_object_hint,
            create_stream_file_object_ex,
            set_information,
            query_file_dos_device_name,
            transfer_activity_id,
        ],
        data_exports: &[],
    };
}

pub mod io_paging {
    //! IoPageRead/IoSynchronousPageWrite (LFS e TxF do ntfs.sys),
    //! IoMakeAssociatedIrpEx (I/O não cacheado em várias extensões) e o par
    //! FsTrackOffset que o NtfsCommonRead/Write limpa em todo IRP.

    use crate::ntos::inc::field::NtStruct;
    use crate::ntos::inc::types::{DeviceObject, FileObject, IoStatusBlock, Irp, LargeInteger, Mdl};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::paging_io::{self, PagingRequest};
    use crate::ntos::io::{extensions, irp_support};
    use crate::rtl::KernelError;

    /// IoPageRead(FileObject, Mdl, StartingOffset, Event, IoStatusBlock) -> NTSTATUS.
    /// Os dois bits baixos do FileObject e do MDL são marcas do Mm.
    fn page_read(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: FILE_OBJECT, MDL, LARGE_INTEGER e IO_STATUS_BLOCK do Mm/FS (modo kernel).
        let request = unsafe { PagingRequest { file: FileObject::at(call.arg(1) & !3), descriptor: Mdl::at(call.arg(2) & !3), offset: LargeInteger::at(call.arg(3)), event: call.arg(4), io_status: IoStatusBlock::at(call.arg(5)) } };
        paging_io::page_read(&request, call.arg(1) & 3, call.arg(2) & 3).map(signed_status)
    }

    /// IoSynchronousPageWrite(FileObject, Mdl, FileOffset, Event, IoStatusBlock) -> NTSTATUS.
    fn synchronous_page_write(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: FILE_OBJECT, MDL, LARGE_INTEGER e IO_STATUS_BLOCK do Mm/FS (modo kernel).
        let request = unsafe { PagingRequest { file: FileObject::at(call.arg(1)), descriptor: Mdl::at(call.arg(2)), offset: LargeInteger::at(call.arg(3)), event: call.arg(4), io_status: IoStatusBlock::at(call.arg(5)) } };
        paging_io::synchronous_page_write(&request).map(signed_status)
    }

    /// IoMakeAssociatedIrpEx(Irp, DeviceObject, StackSize) -> PIRP.
    fn make_associated_irp_ex(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: IRP mestre vivo e DEVICE_OBJECT opcional do FS.
        let (master, device) = unsafe { (Irp::at(call.arg(1)), (call.arg(2) != 0).then(|| DeviceObject::at(call.arg(2)))) };
        Ok(irp_support::make_associated_irp_ex(master, device, call.arg(3) as u8))
    }

    /// IoIrpHasFsTrackOffsetExtensionType(Irp) -> BOOLEAN.
    fn irp_has_fs_track_offset_extension_type(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: IRP vivo do FS.
        Ok(extensions::irp_has_fs_track_offset(unsafe { Irp::at(call.arg(1)) }) as u64)
    }

    /// IoClearFsTrackOffsetState(Irp) -> NTSTATUS.
    fn clear_fs_track_offset_state(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: IRP vivo do FS.
        Ok(signed_status(extensions::clear_fs_track_offset_state(unsafe { Irp::at(call.arg(1)) })))
    }

    pub static GROUP: Group = Group {
        name: "io-paging",
        names: &["IoPageRead", "IoSynchronousPageWrite", "IoMakeAssociatedIrpEx", "IoIrpHasFsTrackOffsetExtensionType", "IoClearFsTrackOffsetState"],
        handlers: &[page_read, synchronous_page_write, make_associated_irp_ex, irp_has_fs_track_offset_extension_type, clear_fs_track_offset_state],
        data_exports: &[],
    };
}

pub mod io_share_access {
    //! SHARE_ACCESS: a lógica mora em `io/share_access.rs`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::inc::types::extra_fs_ntfs::ShareAccess;
    use crate::ntos::inc::types::{FileObject, NtStruct};
    use crate::ntos::io::share_access;
    use crate::rtl::KernelError;

    fn objects(file: u64, share: u64) -> (&'static FileObject, &'static ShareAccess) {
        // SAFETY: o FS passa o FILE_OBJECT do IRP_MJ_CREATE e o SHARE_ACCESS do seu FCB.
        unsafe { (FileObject::at(file), ShareAccess::at(share)) }
    }

    fn check(call: &Call) -> Result<u64, KernelError> {
        let (file, share) = objects(call.arg(3), call.arg(4));
        Ok(signed_status(share_access::check(call.arg(1) as u32, call.arg(2) as u32, file, share, call.arg(5) & 0xFF != 0)))
    }
    fn set(call: &Call) -> Result<u64, KernelError> {
        let (file, share) = objects(call.arg(3), call.arg(4));
        share_access::set(call.arg(1) as u32, call.arg(2) as u32, file, share);
        Ok(0)
    }
    fn remove(call: &Call) -> Result<u64, KernelError> {
        let (file, share) = objects(call.arg(1), call.arg(2));
        share_access::remove(file, share);
        Ok(0)
    }
    fn update(call: &Call) -> Result<u64, KernelError> {
        let (file, share) = objects(call.arg(1), call.arg(2));
        share_access::update(file, share);
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "io-share-access",
        names: &["IoCheckShareAccess", "IoSetShareAccess", "IoRemoveShareAccess", "IoUpdateShareAccess"],
        handlers: &[check, set, remove, update],
        data_exports: &[],
    };
}

pub mod io_share_access_link {
    //! Io*LinkShareAccess*: o SHARE_ACCESS do arquivo mais a contagem de
    //! exclusão por hard link (LINK_SHARE_ACCESS) que o ntfs.sys mantém.

    use crate::ntos::inc::field::NtStruct;
    use crate::ntos::inc::types::extra_fs_ntfs::{LinkShareAccess, ShareAccess};
    use crate::ntos::inc::types::FileObject;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::share_access;
    use crate::rtl::KernelError;

    /// IoCheckLinkShareAccess(DesiredAccess, DesiredShareAccess, FileObject,
    /// ShareAccess, LinkShareAccess, IoShareAccessFlags) -> NTSTATUS.
    fn check_link_share_access(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: estruturas do FS chamador; NULL só onde as flags permitem.
        let (file, share, link) = unsafe {
            (
                (call.arg(3) != 0).then(|| FileObject::at(call.arg(3))),
                (call.arg(4) != 0).then(|| ShareAccess::at(call.arg(4))),
                (call.arg(5) != 0).then(|| LinkShareAccess::at(call.arg(5))),
            )
        };
        Ok(signed_status(share_access::check_link(call.arg(1) as u32, call.arg(2) as u32, file, share, link, call.arg(6) as u32)))
    }

    /// IoSetLinkShareAccess(DesiredAccess, DesiredShareAccess, FileObject,
    /// ShareAccess, LinkShareAccess, IoShareAccessFlags) -> VOID.
    fn set_link_share_access(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: FILE_OBJECT e SHARE_ACCESS do FS; LinkShareAccess opcional.
        let (file, share, link) = unsafe { (FileObject::at(call.arg(3)), ShareAccess::at(call.arg(4)), (call.arg(5) != 0).then(|| LinkShareAccess::at(call.arg(5)))) };
        share_access::set_link(call.arg(1) as u32, call.arg(2) as u32, file, share, link, call.arg(6) as u32);
        Ok(0)
    }

    /// IoRemoveLinkShareAccessEx(FileObject, ShareAccess, LinkShareAccess, IoShareAccessFlags) -> VOID.
    fn remove_link_share_access_ex(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: FILE_OBJECT e SHARE_ACCESS do FS; LinkShareAccess opcional.
        let (file, share, link) = unsafe { (FileObject::at(call.arg(1)), ShareAccess::at(call.arg(2)), (call.arg(3) != 0).then(|| LinkShareAccess::at(call.arg(3)))) };
        share_access::remove_link(file, share, link, call.arg(4) as u32);
        Ok(0)
    }

    /// IoUpdateLinkShareAccessEx(FileObject, ShareAccess, LinkShareAccess, IoShareAccessFlags) -> VOID.
    fn update_link_share_access_ex(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: FILE_OBJECT e SHARE_ACCESS do FS; LinkShareAccess opcional.
        let (file, share, link) = unsafe { (FileObject::at(call.arg(1)), ShareAccess::at(call.arg(2)), (call.arg(3) != 0).then(|| LinkShareAccess::at(call.arg(3)))) };
        share_access::update_link(file, share, link, call.arg(4) as u32);
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "io-share-access-link",
        names: &["IoCheckLinkShareAccess", "IoSetLinkShareAccess", "IoRemoveLinkShareAccessEx", "IoUpdateLinkShareAccessEx"],
        handlers: &[check_link_share_access, set_link_share_access, remove_link_share_access_ex, update_link_share_access_ex],
        data_exports: &[],
    };
}

pub mod io_volume_information {
    //! GUID de volume pelo Mount Manager, consulta por nome e definição de
    //! informação de volume: a lógica mora em `io/volume_dos_name.rs` e
    //! `io/file/zw.rs`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::inc::types::{DeviceObject, NtStruct, UnicodeString};
    use crate::ntos::io::file::zw;
    use crate::ntos::io::volume_dos_name;
    use crate::rtl::KernelError;

    // SAFETY (ambas): o FS/filtro passa o DEVICE_OBJECT do volume e uma UNICODE_STRING/GUID de kernel.
    fn device_to_guid(call: &Call) -> Result<u64, KernelError> {
        volume_dos_name::volume_device_to_guid(unsafe { DeviceObject::at(call.arg(1)) }, call.arg(2)).map(signed_status)
    }
    fn device_to_guid_path(call: &Call) -> Result<u64, KernelError> {
        volume_dos_name::volume_device_to_guid_path(unsafe { DeviceObject::at(call.arg(1)) }, unsafe { UnicodeString::at(call.arg(2)) }).map(signed_status)
    }
    fn query_by_name(call: &Call) -> Result<u64, KernelError> {
        zw::query_information_by_name(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5) as u32, call.arg(6) as u32).map(signed_status)
    }
    fn set_volume_information(call: &Call) -> Result<u64, KernelError> {
        zw::set_volume_information_file(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5) as u32).map(signed_status)
    }

    pub static GROUP: Group = Group {
        name: "io-volume-information",
        names: &["IoVolumeDeviceToGuid", "IoVolumeDeviceToGuidPath", "IoQueryInformationByName", "ZwSetVolumeInformationFile"],
        handlers: &[device_to_guid, device_to_guid_path, query_by_name, set_volume_information],
        data_exports: &[],
    };
}

pub mod io_boot_disk {
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::arc_name;
    use crate::rtl::KernelError;

    fn create_arc_name(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(arc_name::create_arc_name(call.arg(1))?))
    }

    fn get_boot_disk_information_lite(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(arc_name::get_boot_disk_information_lite(call.arg(1))))
    }

    pub static GROUP: Group = Group {
        name: "io-boot-disk",
        names: &["IoCreateArcName", "IoGetBootDiskInformationLite"],
        handlers: &[create_arc_name, get_boot_disk_information_lite],
        data_exports: &[],
    };
}

pub mod io_driver_notification {
    use crate::ntos::inc::types::{DriverObject, NtStruct, UnicodeString};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::{lifecycle, shutdown};
    use crate::rtl::KernelError;

    fn register_boot_driver_reinitialization(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PDRIVER_OBJECT do driver chamador.
        lifecycle::register_boot_driver_reinitialization(unsafe { DriverObject::at(call.arg(1)) }, call.arg(2), call.arg(3));
        Ok(0)
    }

    fn register_last_chance_shutdown_notification(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(shutdown::register_last_chance(call.arg(1))?))
    }

    fn query_full_driver_path(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PDRIVER_OBJECT e PUNICODE_STRING de saída de um chamador de modo kernel.
        let (driver, path) = unsafe { (DriverObject::at(call.arg(1)), UnicodeString::at(call.arg(2))) };
        Ok(signed_status(lifecycle::query_full_driver_path(driver, path)))
    }

    pub static GROUP: Group = Group {
        name: "io-driver-notification",
        names: &["IoRegisterBootDriverReinitialization", "IoRegisterLastChanceShutdownNotification", "IoQueryFullDriverPath"],
        handlers: &[register_boot_driver_reinitialization, register_last_chance_shutdown_notification, query_full_driver_path],
        data_exports: &[],
    };
}

pub mod io_interrupt_state {
    use crate::ntos::inc::types::extra_storage::IoReportInterruptActiveStateParameters;
    use crate::ntos::inc::types::NtStruct;
    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::ke::interrupt_object;
    use crate::rtl::KernelError;

    fn report_interrupt_active(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: parâmetros de um driver de modo kernel.
        interrupt_object::report_interrupt_active_state(unsafe { IoReportInterruptActiveStateParameters::at(call.arg(1)) }, true);
        Ok(0)
    }

    fn report_interrupt_inactive(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: parâmetros de um driver de modo kernel.
        interrupt_object::report_interrupt_active_state(unsafe { IoReportInterruptActiveStateParameters::at(call.arg(1)) }, false);
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "io-interrupt-state",
        names: &["IoReportInterruptActive", "IoReportInterruptInactive"],
        handlers: &[report_interrupt_active, report_interrupt_inactive],
        data_exports: &[],
    };
}

pub mod io_pnp_device {
    use crate::ntos::inc::types::{Devpropkey, Field, NtStruct};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::{device_property, pnp};
    use crate::rtl::KernelError;

    fn report_detected_device(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PDEVICE_OBJECT* de entrada/saída de um chamador de modo kernel.
        let output = unsafe { Field::<u64>::at(call.arg(8)) };
        Ok(signed_status(pnp::report_detected_device(call.arg(1), call.arg(2) as u32, call.arg(3) as u32, call.arg(4) as u32, call.arg(5), call.arg(6), call.arg(7) & 0xFF != 0, output)?))
    }

    fn get_dma_adapter(call: &Call) -> Result<u64, KernelError> {
        pnp::get_dma_adapter(call.arg(1), call.arg(2), call.arg(3))
    }

    fn set_device_property_data(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: DEVPROPKEY de um chamador de modo kernel.
        let key = unsafe { Devpropkey::at(call.arg(2)) };
        Ok(signed_status(device_property::set_device_property(call.arg(1), key, call.arg(3) as u32, call.arg(4) as u32, call.arg(5) as u32, call.arg(6) as u32, call.arg(7))))
    }

    fn set_device_interface_property_data(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: DEVPROPKEY de um chamador de modo kernel.
        let key = unsafe { Devpropkey::at(call.arg(2)) };
        Ok(signed_status(device_property::set_interface_property(call.arg(1), key, call.arg(3) as u32, call.arg(4) as u32, call.arg(5) as u32, call.arg(6) as u32, call.arg(7))))
    }

    pub static GROUP: Group = Group {
        name: "io-pnp-device",
        names: &["IoReportDetectedDevice", "IoGetDmaAdapter", "IoSetDevicePropertyData", "IoSetDeviceInterfacePropertyData"],
        handlers: &[report_detected_device, get_dma_adapter, set_device_property_data, set_device_interface_property_data],
        data_exports: &[],
    };
}

pub mod io_wdm_headless {
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::small::{headless, wdm_version};
    use crate::rtl::KernelError;

    fn headless_dispatch(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(headless::dispatch(call.arg(1) as u32, call.arg(2), call.arg(3), call.arg(4), call.arg(5))))
    }

    fn is_wdm_version_available(call: &Call) -> Result<u64, KernelError> {
        Ok(wdm_version::is_available(call.arg(1) as u8, call.arg(2) as u8) as u64)
    }

    pub static GROUP: Group = Group {
        name: "io-wdm-headless",
        names: &["HeadlessDispatch", "IoIsWdmVersionAvailable"],
        handlers: &[headless_dispatch, is_wdm_version_available],
        data_exports: &[],
    };
}

pub mod io_work_item {
    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::io::work_items;
    use crate::rtl::KernelError;

    fn uninitialize_work_item(call: &Call) -> Result<u64, KernelError> {
        work_items::uninitialize_work_item(call.arg(1));
        Ok(0)
    }

    pub static GROUP: Group = Group { name: "io-work-item", names: &["IoUninitializeWorkItem"], handlers: &[uninitialize_work_item], data_exports: &[] };
}

pub mod io_thread_irp {
    //! IoQueueThreadIrp; a lógica mora em `io/threads` (thread_requests).

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::inc::types::{Irp, NtStruct};
    use crate::ntos::io::threads::thread_requests;
    use crate::rtl::KernelError;

    /// IoQueueThreadIrp(Irp): a IRP entra na lista da thread dela
    /// (Irp->Tail.Overlay.Thread).
    fn queue_thread_irp(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: o PIRP do chamador de kernel.
        let thread = unsafe { Irp::at(call.arg(1)) }.tail.overlay.thread.get();
        thread_requests::insert(call.arg(1), thread)?;
        Ok(0)
    }

    pub static GROUP: Group = Group { name: "io-thread-irp", names: &["IoQueueThreadIrp"], handlers: &[queue_thread_irp], data_exports: &[] };
}

pub mod nt_device_control {
    //! NtDeviceIoControlFile — `ntos/io/device_control`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::io::device_control;
    use crate::ntos::ps::previous_mode;
    use crate::rtl::KernelError;

    fn control(call: &Call) -> Result<u64, KernelError> {
        Ok(device_control::nt_control(previous_mode::get()?, call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6) as u32, call.arg(7), call.arg(8) as u32, call.arg(9), call.arg(10) as u32)? as u64)
    }

    pub static GROUP: Group = Group { name: "nt-device-control", names: &["NtDeviceIoControlFile"], handlers: &[control], data_exports: &[] };
}

pub mod zw_wait_completion_packets {
    //! ZwCreateWaitCompletionPacket, ZwAssociateWaitCompletionPacket,
    //! ZwCancelWaitCompletionPacket e ZwSetIoCompletionEx, em modo kernel;
    //! a lógica mora em `ps/user/wait_packets` e `io/completion/set`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::inc::field::{Field, NtStruct};
    use crate::ntos::io::completion::set;
    use crate::ntos::ps::user::wait_packets;
    use crate::rtl::KernelError;

    fn words(value: u64) -> [u32; 2] {
        [value as u32, (value >> 32) as u32]
    }

    /// ZwCreateWaitCompletionPacket(Handle*, DesiredAccess, ObjectAttributes).
    fn create(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(wait_packets::create(call.arg(1), call.arg(2) as u32, call.arg(3))?))
    }

    /// ZwAssociateWaitCompletionPacket(Packet, IoCompletion, Target, Key,
    /// ApcContext, IoStatus, IoStatusInformation, AlreadySignaled*).
    fn associate(call: &Call) -> Result<u64, KernelError> {
        let completion = (words(call.arg(4)), words(call.arg(5)), call.arg(6) as u32, words(call.arg(7)));
        Ok(signed_status(match wait_packets::associate(call.arg(1), call.arg(2), call.arg(3), completion) {
            Ok(signaled) => {
                if call.arg(8) != 0 {
                    // SAFETY: o BOOLEAN* opcional do chamador de kernel.
                    unsafe { Field::<u8>::at(call.arg(8)) }.set(signaled as u8);
                }
                0
            }
            Err(status) => status,
        }))
    }

    /// ZwCancelWaitCompletionPacket(Packet, RemoveSignaledPacket).
    fn cancel(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(wait_packets::cancel(call.arg(1), call.arg(2) as u8 != 0)))
    }

    /// ZwSetIoCompletionEx(IoCompletion, Reserve, Key, ApcContext, IoStatus,
    /// IoStatusInformation).
    fn set_io_completion_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(set::set_io_completion_ex(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5) as u32, call.arg(6))))
    }

    pub static GROUP: Group = Group {
        name: "zw-wait-completion-packets",
        names: &["ZwAssociateWaitCompletionPacket", "ZwCreateWaitCompletionPacket", "ZwCancelWaitCompletionPacket", "ZwSetIoCompletionEx"],
        handlers: &[associate, create, cancel, set_io_completion_ex],
        data_exports: &[],
    };
}

pub mod zw_cancel_io {
    //! ZwCancelIoFile; a lógica mora em `io/cancel`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::cancel;
    use crate::rtl::KernelError;

    fn cancel_io_file(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(cancel::cancel_io_file(call.arg(1), call.arg(2))?.0))
    }

    pub static GROUP: Group = Group { name: "zw-cancel-io", names: &["ZwCancelIoFile"], handlers: &[cancel_io_file], data_exports: &[] };
}
