//! Tabela de exports do ntoskrnl.
//!
//! A ordem completa da ABI fica em `abi_names` (ids = 32 + índice; os ordinais
//! seguem a mesma ordem, com os dados de `kernel_data_layout` no fim). Cada
//! grupo (`ntos/<componente>/exports.rs`) preenche a sua fatia; um export cujo
//! grupo ainda não tem provedor não resolve (o import falha). O IAT dos drivers
//! recebe o trampolim do id (`hal::amd64::win32_thunk`) ou, para exports de
//! dado, o endereço real do símbolo.
//!
//! Os handlers recebem os argumentos como `u64` exatos.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::hal::amd64::win32_thunk::{self, STUB_SIZE};
use crate::ntos::init::export_names as abi_names;
use crate::ntos::mm::{kernel_address, kernel_data_layout};
use crate::ntos::ps::previous_mode;
use crate::ntos::rtl::native_context;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::init::native_export_layout;
use crate::ntos::rtl::image::pe_exports::Exports;
use crate::ntos::mm::pe_loader::{self, ImportSymbol, ResolvedImport};
use crate::ntos::mm::sysload::pe_resolver::ExportedModule;

/// Chamada vinda do trampolim: os 14 argumentos MS x64, o endereço de
/// retorno, o frame original (pilha do chamador) e o CONTEXT capturado.
pub struct Call {
    pub args: [u64; 14],
    pub return_address: u64,
    pub frame: u64,
    pub context: u64,
}

impl Call {
    /// Argumento 1-based, como na assinatura do export.
    pub fn arg(&self, index: usize) -> u64 {
        self.args[index - 1]
    }

    /// Argumento 1-based de uma rotina variádica: além dos 14 copiados, a
    /// pilha do chamador (o quinto em frame + 40); sem frame (chamada
    /// interna), zero.
    pub fn variadic_arg(&self, index: usize) -> u64 {
        if index <= self.args.len() {
            self.args[index - 1]
        } else if self.frame != 0 {
            crate::ntos::mm::guest_memory::read64(self.frame + 40 + (index as u64 - 5) * 8)
        } else {
            0
        }
    }
}

pub type Handler = fn(&Call) -> Result<u64, KernelError>;

/// Grupo de exports: nomes e handlers alinhados, e exports de dado. Os
/// nomes precisam coincidir com a fatia do grupo em `abi_names`.
pub struct Group {
    pub name: &'static str,
    pub names: &'static [&'static str],
    pub handlers: &'static [Handler],
    pub data_exports: &'static [(&'static str, fn() -> u64)],
}

/// Grupos implementados (qualquer ordem: a posição vem de `GROUP_LAYOUT`).
fn groups() -> [&'static Group; 508] {
    [
        &crate::ntos::ps::exports::ps_jobs::GROUP,
        &crate::ntos::alpc::exports::zw_alpc_server::GROUP,
        &crate::ntos::alpc::exports::lpc::GROUP,
        &crate::ntos::ex::exports::zw_timer::GROUP,
        &crate::ntos::ex::exports::zw_wnf_name_information::GROUP,
        &crate::ntos::ps::exports::zw_reserve_object::GROUP,
        &crate::ntos::ps::exports::zw_set_information_process::GROUP,
        &crate::ntos::ex::exports::zw::SYSTEM_INFORMATION_EX_GROUP,
        &crate::ntos::ps::exports::ps_pool_quota::GROUP,
        &crate::hal::exports::hal_bus_translation::GROUP,
        &crate::ntos::io::exports::nt_create_file::GROUP,
        &crate::ntos::rtl::exports::rtl_unicode_prefix::GROUP,
        &crate::ntos::rtl::exports::rtl_app_container::GROUP,
        &crate::ntos::ps::exports::ps_paged_pool_quota::GROUP,
        &crate::ntos::cm::exports::cm_hive::GROUP,
        &crate::ntos::cm::exports::cm_callback_objects::GROUP,
        &crate::ntos::rtl::exports::resource_lookup::GROUP,
        &crate::ntos::rtl::exports::resource_search::GROUP,
        &crate::ntos::ps::exports::GROUP,
        &crate::ntos::fsrtl::exports::file_information::GROUP,
        &crate::ntos::kd::exports::debug_prompt::GROUP,
        &crate::ntos::ps::exports::thread_context::GROUP,
        &crate::ntos::alpc::exports::GROUP,
        &crate::ntos::io::exports::remove_completion::GROUP,
        &crate::ntos::ob::exports::query_object::GROUP,
        &crate::ntos::io::exports::set_completion::GROUP,
        &crate::ntos::io::exports::create_completion::GROUP,
        &crate::ntos::mm::exports::query_virtual::GROUP,
        &crate::ntos::mm::exports::map_section_in_system_space::GROUP,
        &crate::ntos::mm::exports::unmap_system_view::GROUP,
        &crate::ntos::mm::exports::map_system_view::GROUP,
        &crate::ntos::mm::exports::unmap_view::GROUP,
        &crate::ntos::mm::exports::map_view::GROUP,
        &crate::ntos::mm::exports::open_section::GROUP,
        &crate::ntos::mm::exports::create_section_object::GROUP,
        &crate::ntos::mm::exports::create_section::GROUP,
        &crate::ntos::rtl::exports::GROUP,
        &crate::ntos::rtl::exports::exceptions::GROUP,
        &crate::ntos::ex::exports::datatype_misalignment::GROUP,
        &crate::ntos::rtl::exports::unwind::GROUP,
        &crate::ntos::se::exports::image_verification::GROUP,
        &crate::ntos::se::exports::image_verification_remove::GROUP,
        &crate::ntos::ke::exports::persistent_thread_state::GROUP,
        &crate::ntos::ob::exports::query_security::GROUP,
        &crate::ntos::ob::exports::tagged_reference::GROUP,
        &crate::ntos::ob::exports::tagged_dereference::GROUP,
        &crate::ntos::se::exports::token_handles::GROUP,
        &crate::ntos::io::exports::convert_file_handle::GROUP,
        &crate::ntos::io::exports::disk_device::GROUP,
        &crate::ntos::io::exports::device_control::GROUP,
        &crate::ntos::io::exports::delete_file::GROUP,
        &crate::ntos::io::exports::volume_dos_name::GROUP,
        &crate::ntos::io::exports::query_file::GROUP,
        &crate::ntos::io::exports::read_file::GROUP,
        &crate::ntos::io::exports::write_file::GROUP,
        &crate::ntos::io::exports::initial_stack::GROUP,
        &crate::ntos::io::exports::thread_activity_exports::GROUP,
        &crate::ntos::io::exports::attach_device_safe::GROUP,
        &crate::ntos::ob::exports::find_handle::GROUP,
        &crate::ntos::ob::exports::GROUP,
        &crate::ntos::io::exports::GROUP,
        &crate::ntos::ex::exports::zw::GROUP,
        &crate::hal::exports::GROUP,
        &crate::ntos::ps::exports::silo_query_exports::GROUP,
        &crate::ntos::ps::exports::thread_id::GROUP,
        &crate::ntos::ps::exports::previous_mode::GROUP,
        &crate::ntos::ex::exports::firmware_environment::GROUP,
        &crate::ntos::ps::exports::process_session::GROUP,
        &crate::ntos::ex::exports::enum_handles::GROUP,
        &crate::ntos::io::exports::enumerate_devices::GROUP,
        &crate::ntos::etw::exports::event_enabled::GROUP,
        &crate::ntos::ps::exports::lookup_thread::GROUP,
        &crate::ntos::io::exports::lower_device::GROUP,
        &crate::ntos::ex::exports::unblock_push_lock::GROUP,
        &crate::ntos::ex::exports::pool_allocation_exports::GROUP,
        &crate::ntos::io::exports::attached_device::GROUP,
        &crate::ntos::ps::exports::process_exit::GROUP,
        &crate::ntos::ps::exports::process_peb::GROUP,
        &crate::ntos::rtl::exports::check_registry_key::GROUP,
        &crate::ntos::fsrtl::exports::file_name_information::GROUP,
        &crate::ntos::ps::exports::process_image_name::GROUP,
        &crate::ntos::fsrtl::exports::release_file_name_information::GROUP,
        &crate::ntos::rtl::exports::state_separation::GROUP,
        &crate::ntos::se::exports::open_process_token::GROUP,
        &crate::ntos::ps::exports::process_exit_called::GROUP,
        &crate::ntos::ps::exports::process_win32::GROUP,
        &crate::ntos::ex::exports::system_exception_filter::GROUP,
        &crate::ntos::cm::exports::registry_callbacks::GROUP,
        &crate::ntos::ex::exports::callbacks::GROUP,
        &crate::ntos::ob::exports::close::GROUP,
        &crate::ntos::mm::exports::dump_mdl::GROUP,
        &crate::ntos::ob::exports::open_pointer_exports::GROUP,
        &crate::ntos::se::exports::impersonate_anonymous::GROUP,
        &crate::ntos::ps::exports::process_notify_exports::GROUP,
        &crate::ntos::ps::exports::image_notify::GROUP,
        &crate::ntos::ps::exports::thread_notify::GROUP,
        &crate::ntos::ob::exports::object_callbacks::GROUP,
        &crate::ntos::ps::exports::silo_monitors::GROUP,
        &crate::ntos::ps::exports::thread_process::GROUP,
        &crate::ntos::ps::exports::thread_exit::GROUP,
        &crate::ntos::fsrtl::exports::GROUP,
        &crate::ntos::se::exports::duplicate_token::GROUP,
        &crate::ntos::ps::exports::silo_contexts_exports::GROUP,
        &crate::hal::exports::hal_platform::GROUP,
        &crate::ntos::ps::exports::process_wow64::GROUP,
        &crate::ntos::mm::exports::free_contiguous::GROUP,
        &crate::ntos::ke::exports::alert_thread::GROUP,
        &crate::ntos::se::exports::query_token::GROUP,
        &crate::ntos::se::exports::secure_boot_policy::GROUP,
        &crate::ntos::rtl::exports::capability_check::GROUP,
        &crate::ntos::ex::exports::license_values::GROUP,
        &crate::ntos::se::exports::platform_manifest::GROUP,
        &crate::ntos::ex::exports::pool_quota::GROUP,
        &crate::ntos::rtl::exports::feature_usage::GROUP,
        &crate::ntos::ex::exports::wnf_query::GROUP,
        &crate::ntos::ps::exports::process_query::GROUP,
        &crate::ntos::kd::exports::GROUP,
        &crate::ntos::etw::exports::wmi::GROUP,
        &crate::hal::exports::hvi::GROUP,
        &crate::ntos::po::exports::GROUP,
        &crate::ntos::etw::exports::GROUP,
        &crate::ntos::ps::exports::security_tokens::GROUP,
        &crate::ntos::se::exports::GROUP,
        &crate::ntos::ex::exports::wnf_update::GROUP,
        &crate::ntos::ps::exports::process_debug::GROUP,
        &crate::ntos::mm::exports::mdl_size::GROUP,
        &crate::ntos::mm::exports::address_validity::GROUP,
        &crate::ntos::rtl::exports::first_slist::GROUP,
        &crate::ntos::ob::exports::get_object_type::GROUP,
        &crate::ntos::mm::exports::physical_ranges::GROUP,
        &crate::ntos::ke::exports::test_alert::GROUP,
        &crate::ntos::mm::exports::protect_mdl::GROUP,
        &crate::ntos::ke::exports::thread_priority::GROUP,
        &crate::ntos::ke::exports::thread_base_priority::GROUP,
        &crate::ntos::ex::exports::zw::DISPLAY_STRING_GROUP,
        &crate::ntos::ke::exports::PROCESSOR_QUERIES_GROUP,
        &crate::ntos::ex::exports::TRY_SPIN_LOCKS_GROUP,
        &crate::ntos::io::exports::VPB_SPIN_LOCK_GROUP,
        &crate::ntos::ke::exports::QUEUED_SPIN_LOCKS_GROUP,
        &crate::ntos::ke::exports::AFFINITY_GROUP,
        &crate::ntos::io::exports::INTERRUPT_AFFINITY_GROUP,
        &crate::ntos::ps::exports::open_process_thread::GROUP,
        &crate::ntos::ps::exports::next_process_thread::GROUP,
        &crate::ntos::ke::exports::GENERIC_CALL_DPC_GROUP,
        &crate::ntos::mm::exports::view_of_section::GROUP,
        &crate::ntos::rtl::exports::generic_tables::SPLAY_LINKS_GROUP,
        &crate::ntos::rtl::exports::generic_tables::GENERIC_TABLES_GROUP,
        &crate::ntos::rtl::exports::generic_tables::AVL_TABLES_GROUP,
        &crate::ntos::mm::exports::virtual_memory_services::GROUP,
        &crate::ntos::se::exports::locally_unique_id::GROUP,
        &crate::ntos::ps::exports::exit_synchronization::GROUP,
        &crate::ntos::ps::exports::thread_process_queries::GROUP,
        &crate::ntos::etw::exports::trace_control::GROUP,
        &crate::ntos::etw::exports::trace_control::ENABLE_TRACE_GROUP,
        &crate::ntos::rtl::exports::rtl_security::GROUP,
        &crate::ntos::io::exports::driver_helpers::GROUP,
        &crate::ntos::io::exports::io_diagnostics::GROUP,
        &crate::ntos::io::exports::x86bios_sleep_misc::GROUP,
        &crate::ntos::se::exports::se_descriptor::GROUP,
        &crate::ntos::ps::exports::process_image::GROUP,
        &crate::ntos::rtl::exports::package_claims::GROUP,
        &crate::ntos::rtl::exports::package_identity::GROUP,
        &crate::ntos::ps::exports::query_thread::GROUP,
        &crate::ntos::ps::exports::nt_query_thread::GROUP,
        &crate::ntos::ps::exports::set_thread_information::GROUP,
        &crate::ntos::ps::exports::nt_set_thread_information::GROUP,
        &crate::ntos::ex::exports::GROUP,
        &crate::ntos::ke::exports::GROUP,
        &crate::ntos::mm::exports::GROUP,
        &crate::ntos::mm::exports::image_paging_exports::GROUP,
        &crate::ntos::se::exports::se_token_info::GROUP,
        &crate::ntos::po::exports::po_fx::GROUP,
        &crate::ntos::se::exports::se_assign::GROUP,
        &crate::ntos::se::exports::se_access::GROUP,
        &crate::ntos::rtl::exports::rtl_crt_extended::GROUP,
        &crate::ntos::ke::exports::ke_ex_sync::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_core::GROUP,
        &crate::ntos::ob::exports::ob_object_lifecycle::GROUP,
        &crate::ntos::ex::exports::ex_lookaside_wnf::GROUP,
        &crate::ntos::mm::exports::mm_verifier::GROUP,
        &crate::ntos::mm::exports::mm_session_views::GROUP,
        &crate::ntos::mm::exports::mm_system_image::GROUP,
        &crate::ntos::mm::exports::mm_mdl_ex::GROUP,
        &crate::ntos::mm::exports::mm_secure_memory::GROUP,
        &crate::ntos::mm::exports::mm_physical_memory::GROUP,
        &crate::ntos::mm::exports::mm_system_info::GROUP,
        &crate::ntos::rtl::exports::rtl_hash_tables::GROUP,
        &crate::ntos::rtl::exports::rtl_strings::GROUP,
        &crate::ntos::rtl::exports::rtl_bit_ops::GROUP,
        &crate::ntos::rtl::exports::crt_strings::GROUP,
        &crate::ntos::rtl::exports::crt_formatting::GROUP,
        &crate::ntos::io::exports::io_csq::GROUP,
        &crate::ntos::io::exports::io_irp_request::GROUP,
        &crate::ntos::io::exports::io_pnp_interface::GROUP,
        &crate::ntos::io::exports::io_builtin_driver::GROUP,
        &crate::ntos::io::exports::io_named_event::GROUP,
        &crate::ntos::io::exports::io_wmi_data_block::GROUP,
        &crate::ntos::io::exports::io_work_item_queue::GROUP,
        &crate::ntos::dbgk::exports::GROUP,
        &crate::ntos::rtl::exports::rtl_bitmap_ex::GROUP,
        &crate::ntos::ex::exports::ex_interlocked::GROUP,
        &crate::ntos::ex::exports::ex_processor_usage::GROUP,
        &crate::ntos::io::exports::io_driver_registry::GROUP,
        &crate::ntos::ps::exports::ps_property_sets::GROUP,
        &crate::ntos::ex::exports::pcw_counters::GROUP,
        &crate::ntos::rtl::exports::rtl_self_relative_sd::GROUP,
        &crate::ntos::kd::exports::kd_debug_filter::GROUP,
        &crate::ntos::etw::exports::etw_wmi_clock::GROUP,
        &crate::ntos::kse::exports::kse_shim_engine::GROUP,
        &crate::ntos::ex::exports::ex_access_violation::GROUP,
        &crate::ntos::rtl::exports::rtl_network_address::GROUP,
        &crate::ntos::rtl::exports::rtl_crt_wide::GROUP,
        &crate::ntos::io::exports::io_top_level_irp::GROUP,
        &crate::ntos::se::exports::se_access_from_state::GROUP,
        &crate::ntos::cc::exports::cc_cache_map::GROUP,
        &crate::ntos::cc::exports::cc_copy::GROUP,
        &crate::ntos::cc::exports::cc_pin::GROUP,
        &crate::ntos::cc::exports::cc_flush::GROUP,
        &crate::ntos::cc::exports::cc_mdl::GROUP,
        &crate::ntos::cc::exports::cc_log::GROUP,
        &crate::ntos::ps::exports::ps_win32_callouts::GROUP,
        &crate::ntos::ps::exports::ps_process_info::GROUP,
        &crate::ntos::ps::exports::ps_job_info::GROUP,
        &crate::ntos::ps::exports::ps_priority::GROUP,
        &crate::ntos::ps::exports::ps_impersonation::GROUP,
        &crate::ntos::se::exports::se_client_security::GROUP,
        &crate::ntos::se::exports::se_access_state::GROUP,
        &crate::ntos::se::exports::se_appcontainer::GROUP,
        &crate::ntos::alpc::exports::alpc_message_attributes::GROUP,
        &crate::ntos::ob::exports::ob_security_cache::GROUP,
        &crate::ntos::tm::exports::tm_transaction_manager::GROUP,
        &crate::ntos::tm::exports::tm_extension::GROUP,
        &crate::ntos::vf::exports::vf_verifier::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_file_locks::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_oplocks::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_ecp::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_filter_contexts::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_file_system_support::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_misc::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_base_mcb::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_large_mcb::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_eof_lock::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_fast_io::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_heat::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_oplock_ex::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_per_file_teardown::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_tunnel_cache::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_tunnel::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_file_lock_irp::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_notify::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_volume_support::GROUP,
        &crate::ntos::ex::exports::ex_auto_expand_push_lock::GROUP,
        &crate::ntos::ex::exports::ex_resource_owner::GROUP,
        &crate::ntos::ex::exports::ex_resource_owner_and_local_time::GROUP,
        &crate::ntos::ex::exports::ex_cache_aware_push_locks::GROUP,
        &crate::ntos::io::exports::io_file_object_extensions::GROUP,
        &crate::ntos::io::exports::io_priority::GROUP,
        &crate::ntos::io::exports::io_file_system::GROUP,
        &crate::ntos::io::exports::io_irp_support::GROUP,
        &crate::ntos::io::exports::io_file_system_support::GROUP,
        &crate::ntos::io::exports::io_paging::GROUP,
        &crate::ntos::io::exports::io_share_access::GROUP,
        &crate::ntos::io::exports::io_share_access_link::GROUP,
        &crate::ntos::io::exports::io_volume_information::GROUP,
        &crate::ntos::mm::exports::mm_file_system_support::GROUP,
        &crate::ntos::ob::exports::ob_audit::GROUP,
        &crate::ntos::ob::exports::ob_temporary_object::GROUP,
        &crate::ntos::ps::exports::ps_io_boost::GROUP,
        &crate::ntos::ps::exports::ps_disk_counters::GROUP,
        &crate::ntos::rtl::exports::rtl_bitmap_ranges::GROUP,
        &crate::ntos::rtl::exports::rtl_compression::GROUP,
        &crate::ntos::rtl::exports::rtl_nonvolatile_memory::GROUP,
        &crate::ntos::rtl::exports::rtl_security_descriptor_ops::GROUP,
        &crate::ntos::rtl::exports::rtl_support_routines::GROUP,
        &crate::ntos::rtl::exports::rtl_oem_strings::GROUP,
        &crate::ntos::rtl::exports::rtl_8dot3_names::GROUP,
        &crate::ntos::rtl::exports::rtl_altitudes_and_time::GROUP,
        &crate::ntos::rtl::exports::rtl_acl_trust_label::GROUP,
        &crate::ntos::se::exports::se_access_check_ex::GROUP,
        &crate::ntos::se::exports::se_audit_alarms::GROUP,
        &crate::ntos::se::exports::se_set_security::GROUP,
        &crate::hal::exports::hvi_hardware::GROUP,
        &crate::ntos::ke::exports::ke_processors::GROUP,
        &crate::ntos::ke::exports::ke_kernel_stacks::GROUP,
        &crate::ntos::ke::exports::ke_service_tables::GROUP,
        &crate::ntos::ke::exports::ke_queues::GROUP,
        &crate::ntos::ex::exports::ex_resource_priority::GROUP,
        &crate::ntos::ex::exports::ex_pool_block_size::GROUP,
        &crate::ntos::cm::exports::cm_key_notify::GROUP,
        &crate::ntos::ex::exports::ex_legacy_support::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_status::GROUP,
        &crate::ntos::io::exports::io_boot_disk::GROUP,
        &crate::ntos::io::exports::io_driver_notification::GROUP,
        &crate::ntos::io::exports::io_interrupt_state::GROUP,
        &crate::ntos::io::exports::io_pnp_device::GROUP,
        &crate::ntos::io::exports::io_wdm_headless::GROUP,
        &crate::ntos::io::exports::io_work_item::GROUP,
        &crate::ntos::kse::exports::kse_shim_registration::GROUP,
        &crate::ntos::ob::exports::ob_duplicate_object::GROUP,
        &crate::ntos::ob::exports::ob_set_security::GROUP,
        &crate::ntos::po::exports::po_coalescing::GROUP,
        &crate::ntos::po::exports::po_device_wake::GROUP,
        &crate::ntos::rtl::exports::rtl_crt_rand::GROUP,
        &crate::ntos::mm::exports::vf_device_verification::GROUP,
        &crate::hal::exports::vsl_secure_pci::GROUP,
        &crate::ntos::whea::exports::whea_error_source::GROUP,
        &crate::ntos::mm::exports::copy_virtual::GROUP,
        &crate::ntos::rtl::exports::rtl_atom_tables::GROUP,
        &crate::ntos::rtl::exports::rtl_heap::GROUP,
        &crate::ntos::rtl::exports::rtl_code_pages::GROUP,
        &crate::ntos::rtl::exports::rtl_resource_messages::GROUP,
        &crate::ntos::rtl::exports::rtl_integer_to_char::GROUP,
        &crate::ntos::rtl::exports::rtl_system_state::GROUP,
        &crate::ntos::rtl::exports::rtl_access_masks::GROUP,
        &crate::ntos::rtl::exports::rtl_capability_single_session::GROUP,
        &crate::ntos::rtl::exports::rtl_raise_exception::GROUP,
        &crate::ntos::rtl::exports::crt_sqrtf::GROUP,
        &crate::ntos::rtl::exports::rtl_debug_print_va::GROUP,
        &crate::ntos::ke::exports::ke_user_callback::GROUP,
        &crate::ntos::ob::exports::ob_name_info::GROUP,
        &crate::ntos::ob::exports::ob_handle_attributes::GROUP,
        &crate::ntos::ob::exports::ob_assign_security::GROUP,
        &crate::ntos::ob::exports::ob_wait::GROUP,
        &crate::ntos::ps::exports::ps_wake_counters::GROUP,
        &crate::ntos::ps::exports::ps_kernel_stack::GROUP,
        &crate::ntos::ps::exports::ps_process_state::GROUP,
        &crate::ntos::ex::exports::ex_hard_error::GROUP,
        &crate::ntos::io::exports::io_thread_irp::GROUP,
        &crate::ntos::io::exports::nt_device_control::GROUP,
        &crate::ntos::mm::exports::mm_prefetch::GROUP,
        &crate::ntos::po::exports::po_system_state::GROUP,
        &crate::ntos::se::exports::se_privilege_audit::GROUP,
        &crate::ntos::etw::exports::etw_coverage::GROUP,
        &crate::ntos::dbgk::exports::dbgk_live_dump::GROUP,
        &crate::ntos::ps::exports::zw_locale::GROUP,
        &crate::ntos::ps::exports::zw_job_query::GROUP,
        &crate::ntos::io::exports::zw_wait_completion_packets::GROUP,
        &crate::ntos::io::exports::zw_cancel_io::GROUP,
        &crate::ntos::mm::exports::zw_virtual_memory_information::GROUP,
        &crate::ntos::ex::exports::zw_event::GROUP,
        &crate::ntos::ex::exports::ex_wnf_subscription::GROUP,
        &crate::ntos::io::exports::io_device_eject::GROUP,
        &crate::ntos::ex::exports::ex_push_lock_convert::GROUP,
        &crate::ntos::ex::exports::ex_extension_unregister::GROUP,
        &crate::ntos::ex::exports::ex_timer_resolution::GROUP,
        &crate::ntos::rtl::exports::rtl_security_error::GROUP,
        &crate::ntos::rtl::exports::rtl_crt_vsnprintf_s::GROUP,
        &crate::ntos::ps::exports::ps_resume_process::GROUP,
        &crate::ntos::ps::exports::ps_silo_identifier::GROUP,
        &crate::ntos::ps::exports::ps_process_notify_ex2::GROUP,
        &crate::ntos::ps::exports::ps_container_id::GROUP,
        &crate::ntos::ps::exports::ps_command_line::GROUP,
        &crate::ntos::se::exports::se_logon_session::GROUP,
        &crate::ntos::se::exports::se_non_ob_audit::GROUP,
        &crate::ntos::se::exports::se_srp_access_check::GROUP,
        &crate::ntos::cm::exports::cm_machine_hive_notify::GROUP,
        &crate::ntos::io::exports::io_mini_completion::GROUP,
        &crate::ntos::mm::exports::mm_advance_mdl::GROUP,
        &crate::ntos::mm::exports::mm_nt_free_virtual_memory::GROUP,
        &crate::ntos::ob::exports::ob_nt_duplicate_object::GROUP,
        &crate::ntos::bgk::exports::bgk_console::GROUP,
        &crate::ntos::rtl::exports::rtl_capability_sids::GROUP,
        &crate::ntos::etw::exports::etw_stack_walk::GROUP,
        &crate::ntos::inbv::exports::inbv_display_ownership::GROUP,
        &crate::ntos::io::exports::io_root_device::GROUP,
        &crate::ntos::mm::exports::physical_view::GROUP,
        &crate::ntos::mm::exports::query_section::GROUP,
        &crate::ntos::po::exports::po_shutdown::GROUP,
        &crate::ntos::po::exports::po_vsync::GROUP,
        &crate::ntos::ttm::exports::ttm_device_notifications::GROUP,
        &crate::ntos::ob::exports::zw_wait_multiple::GROUP,
        &crate::ntos::ke::exports::zw_yield_execution::GROUP,
        &crate::ntos::rtl::exports::rtl_bitmap_ex_ranges::GROUP,
        &crate::ntos::rtl::exports::rtl_copy_non_temporal::GROUP,
        &crate::ntos::ke::exports::ke_cache_flush::GROUP,
        &crate::ntos::ke::exports::ke_semaphore_state::GROUP,
        &crate::ntos::ex::exports::ex_processor_feature::GROUP,
        &crate::ntos::ex::exports::pcw_instances::GROUP,
        &crate::ntos::ps::exports::ps_partition_commit::GROUP,
        &crate::ntos::mm::exports::physical_ranges_ex::GROUP,
        &crate::ntos::mm::exports::io_space_activity::GROUP,
        &crate::ntos::mm::exports::partition_services::GROUP,
        &crate::ntos::mm::exports::virtual_memory_lock::GROUP,
        &crate::ntos::rtl::exports::rtl_range_lists::GROUP,
        &crate::ntos::rtl::exports::rtl_resource_encoding::GROUP,
        &crate::ntos::rtl::exports::rtl_bitmap_copy::GROUP,
        &crate::ntos::rtl::exports::crt_string_conversion::GROUP,
        &crate::ntos::ke::exports::ke_timer2::GROUP,
        &crate::ntos::ke::exports::ke_processor_support::GROUP,
        &crate::ntos::kd::exports::kd_power::GROUP,
        &crate::ntos::em::exports::em_errata::GROUP,
        &crate::ntos::ex::exports::ex_try_queue_work_item::GROUP,
        &crate::ntos::po::exports::po_thermal_requests::GROUP,
        &crate::ntos::po::exports::po_power_actions::GROUP,
        &crate::ntos::po::exports::po_fx_drips_watchdog::GROUP,
        &crate::ntos::io::exports::io_dependencies::GROUP,
        &crate::ntos::io::exports::io_device_reset_resources::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_cached_fast_io::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_volume_event::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_device_queries::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_oplock_filter::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_notify_filter::GROUP,
        &crate::ntos::rtl::exports::rtl_bitmap_runs::GROUP,
        &crate::ntos::rtl::exports::rtl_8dot3_generate::GROUP,
        &crate::ntos::rtl::exports::rtl_format_message::GROUP,
        &crate::ntos::rtl::exports::rtl_crt_snwprintf_s::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_dbcs_expression::GROUP,
        &crate::ntos::io::exports::io_error_log_free::GROUP,
        &crate::ntos::io::exports::io_extra_create_parameter::GROUP,
        &crate::ntos::mm::exports::mm_file_sections::GROUP,
        &crate::ntos::mm::exports::mm_prefetch_pages::GROUP,
        &crate::ntos::se::exports::se_filter_token::GROUP,
        &crate::ntos::se::exports::query_security_attributes::GROUP,
        &crate::ntos::ob::exports::ob_object_type_ex::GROUP,

        &crate::ntos::se::exports::zw_adjust_privileges_token::GROUP,
        &crate::ntos::rtl::exports::rtl_self_relative_sd2::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_ecp_initialize::GROUP,
        &crate::ntos::kd::exports::kd_break_point::GROUP,
        &crate::ntos::ke::exports::ke_device_queue::GROUP,
        &crate::ntos::io::exports::io_start_packet_by_key::GROUP,
        &crate::ntos::ob::exports::zw_set_information_object::GROUP,
        &crate::ntos::rtl::exports::rtl_crt_towupper::GROUP,
        &crate::hal::exports::hvi_enlightenment::GROUP,
        &crate::ntos::io::exports::io_interface_property_data::GROUP,
        &crate::ntos::io::exports::zw_query_ea_file::GROUP,
        &crate::ntos::mm::exports::mm_change_image_protection::GROUP,
        &crate::ntos::ex::exports::ex_update_license_data::GROUP,
        &crate::hal::exports::hal_interrupt_targets::GROUP,
        &crate::ntos::ke::exports::ke_flush_write_buffer::GROUP,
        &crate::hal::exports::hal_firmware_errors::GROUP,
        &crate::ntos::ex::exports::ex_environment_variable_ex::GROUP,
        &crate::ntos::ke::exports::ke_effective_irql::GROUP,
        &crate::ntos::rtl::exports::rtl_pc_to_file_name::GROUP,
        &crate::ntos::whea::exports::whea_log_internal_event::GROUP,
        &crate::ntos::rtl::exports::rtl_ddi_assert::GROUP,
        &crate::ntos::rtl::exports::rtl_rb_tree::GROUP,
        &crate::ntos::rtl::exports::crt_scanf::GROUP,
        &crate::ntos::rtl::exports::crt_integer_strings::GROUP,
        &crate::ntos::rtl::exports::rtl_network_address_ansi::GROUP,
        &crate::ntos::rtl::exports::rtl_memory_nls_small::GROUP,
        &crate::ntos::po::exports::po_legacy_system_state::GROUP,
        &crate::ntos::po::exports::po_fx_primary_device::GROUP,
        &crate::ntos::etw::exports::etw_provider_enabled::GROUP,
        &crate::ntos::ke::exports::ke_sweep_local_caches::GROUP,
        &crate::ntos::whea::exports::whea_remove_device_driver::GROUP,
        &crate::ntos::ps::exports::ps_suspend_process::GROUP,
        &crate::ntos::mm::exports::mm_flush_add_physical::GROUP,
        &crate::ntos::mm::exports::ps_loaded_module_list::GROUP,
        &crate::ntos::io::exports::io_interface_key_keep_alive::GROUP,
        &crate::ntos::ex::exports::zw_create_wnf_state_name::GROUP,
        &crate::ntos::etw::exports::etw_write_ex::GROUP,
        &crate::ntos::ke::exports::ke_affinity_ex::GROUP,
        &crate::ntos::rtl::exports::crt_memory_ctype::GROUP,
        &crate::ntos::rtl::exports::crt_string_append::GROUP,
        &crate::ntos::rtl::exports::rtl_oem_upcase::GROUP,
        &crate::ntos::rtl::exports::rtl_network_string_ansi::GROUP,
        &crate::ntos::rtl::exports::rtl_rb_replace::GROUP,
        &crate::ntos::rtl::exports::rtl_sd_control::GROUP,
        &crate::ntos::rtl::exports::rtl_cloud_files::GROUP,
        &crate::ntos::rtl::exports::ldr_resource::GROUP,
        &crate::ntos::se::exports::se_sddl_strings::GROUP,
        &crate::ntos::se::exports::se_signing_levels::GROUP,
        &crate::ntos::rtl::exports::rtl_token_checks::GROUP,
        &crate::ntos::se::exports::zw_open_process_token::GROUP,
        &crate::ntos::se::exports::lsa_return_buffer::GROUP,
        &crate::ntos::ob::exports::ob_nt_set_security_object::GROUP,
        &crate::ntos::alpc::exports::alpc_kernel_security::GROUP,
        &crate::ntos::io::exports::io_file_object_origin::GROUP,
        &crate::ntos::io::exports::io_work_item_node::GROUP,
        &crate::ntos::io::exports::io_delete_driver::GROUP,
        &crate::ntos::io::exports::io_tracking::GROUP,
        &crate::ntos::io::exports::io_device_directory::GROUP,
        &crate::ntos::io::exports::io_interface_alias::GROUP,
        &crate::ntos::rtl::exports::rtl_volume_dos_name::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_file_acquire::GROUP,
        &crate::ntos::fsrtl::exports::fsrtl_mup_provider::GROUP,
        &crate::ntos::ps::exports::ps_parent_silo::GROUP,
        &crate::ntos::ps::exports::ps_thread_notify_ex::GROUP,
        &crate::ntos::ps::exports::ps_wow64_apc::GROUP,
        &crate::ntos::ps::exports::nt_query_information_process::GROUP,
        &crate::ntos::ke::exports::ke_alert_thread::GROUP,
        &crate::ntos::ke::exports::ke_triage_dump_data::GROUP,
        &crate::ntos::kd::exports::kd_poll_break_in::GROUP,
        &crate::ntos::mm::exports::mm_mdl_maps::GROUP,
        &crate::ntos::mm::exports::mm_nonpaged_address::GROUP,
        &crate::ntos::mm::exports::mm_physical_remove_cache::GROUP,
        &crate::ntos::ex::exports::ex_lookaside_flush::GROUP,
        &crate::ntos::ex::exports::ex_boot_device::GROUP,
        &crate::ntos::ex::exports::ex_set_firmware_variable::GROUP,
        &crate::ntos::etw::exports::etw_send_trace_buffer::GROUP,
        &crate::ntos::inbv::exports::inbv_boot_driver::GROUP,
        &crate::hal::exports::hvl_hypervisor_queries::GROUP,
        &crate::ntos::ex::exports::ex_nt_create_event::GROUP,
        &crate::ntos::ob::exports::ob_nt_wait_single::GROUP,
        &crate::ntos::tm::exports::tm_query_transaction::GROUP,
        &crate::ntos::io::exports::io_report_resource_usage::GROUP,
        &crate::ntos::ex::exports::ex_push_lock_fast::GROUP,
        &crate::ntos::ps::exports::ps_thread_prefetching::GROUP,
        &crate::ntos::io::exports::io_silo_parameters::GROUP,
        &crate::ntos::rtl::exports::crt_i64tow_s::GROUP,
        &crate::ntos::mm::exports::pf_file_info_notify::GROUP,
        &crate::ntos::rtl::exports::rtl_decompression::GROUP,
        &crate::hal::exports::vsl_secure_section::GROUP,
        &crate::ntos::po::exports::po_system_wake_device::GROUP,
        &crate::ntos::se::exports::se_query_session_id_token::GROUP,
        &crate::ntos::ke::exports::nt_build_number::GROUP,
        &crate::ntos::ex::exports::time_keeping::GROUP,
        &crate::ntos::ke::exports::ke_processor_profile::GROUP,
    ]
}

struct Table {
    handlers: Vec<Option<Handler>>,
    data: BTreeMap<&'static str, fn() -> u64>,
    public_names: Vec<&'static str>,
}

static TABLE: SpinLock<Option<Arc<Table>>> = SpinLock::new(None);

fn table() -> Arc<Table> {
    let mut table = TABLE.lock();
    table
        .get_or_insert_with(|| {
            // Cada export usa o trampolim de id `32 + índice`: se a ABI crescer
            // além dos stubs, os ids altos apontariam para fora da tabela (e o
            // loader os recusaria). Falha alto aqui, nunca em silêncio.
            assert!(
                32 + abi_names::EXPORT_NAMES.len() <= crate::hal::amd64::win32_thunk::MAX_WIN32 as usize,
                "ntoskrnl: {} exports excedem os {} trampolins (aumente MAX_WIN32)",
                abi_names::EXPORT_NAMES.len(),
                crate::hal::amd64::win32_thunk::MAX_WIN32,
            );
            let mut handlers = alloc::vec![None; abi_names::EXPORT_NAMES.len()];
            let mut data = BTreeMap::new();
            for group in groups() {
                // Nome sem handler (ou fora da ordem) desalinha os ids.
                let &(_, start, count) = abi_names::GROUP_LAYOUT.iter().find(|entry| entry.0 == group.name).expect("ntoskrnl: grupo fora da ABI");
                assert!(group.names.len() == count && group.handlers.len() == count && abi_names::EXPORT_NAMES[start..start + count] == *group.names, "ntoskrnl: grupo desalinhado");
                for (slot, &handler) in handlers[start..start + count].iter_mut().zip(group.handlers) {
                    *slot = Some(handler);
                }
                for &(name, getter) in group.data_exports {
                    data.insert(name, getter);
                }
            }
            let mut public_names = abi_names::EXPORT_NAMES.to_vec();
            for entry in kernel_data_layout::DEFINITIONS {
                if !public_names.contains(&entry.name) {
                    public_names.push(entry.name);
                }
            }
            Arc::new(Table { handlers, data, public_names })
        })
        .clone()
}

pub fn export_names() -> &'static [&'static str] {
    abi_names::EXPORT_NAMES
}

/// Exports com provedor implementado.
pub fn implemented() -> usize {
    table().handlers.iter().filter(|handler| handler.is_some()).count()
}

/// Endereço virtual do trampolim do id.
pub fn thunk_address(id: u64) -> Result<u64, KernelError> {
    let (base, _) = win32_thunk::thunk_table();
    kernel_address::image_address(base + id * STUB_SIZE)
}

/// Resolvedor do loader: dado real, corpo nativo próprio ou trampolim.
pub fn lookup(_dll: &str, name: &str) -> Option<ResolvedImport> {
    let table = table();
    if let Some(getter) = table.data.get(name) {
        return Some(ResolvedImport::Address { address: getter(), dependencies: Vec::new() });
    }
    let index = abi_names::EXPORT_NAMES.iter().position(|&candidate| candidate == name)?;
    table.handlers[index]?;
    if let Some((symbol, _, _)) = native_export_layout::lookup(name) {
        // Corpo x64 próprio; os que ainda não existem entram com seus módulos.
        let entry = crate::hal::amd64::private_entries::entry(symbol)?;
        return Some(ResolvedImport::Address { address: kernel_address::image_address(entry).ok()?, dependencies: Vec::new() });
    }
    Some(ResolvedImport::Thunk(32 + index as u32))
}

/// Ordinal N do .def = índice N-1 da tabela pública.
pub fn lookup_ordinal(dll: &str, ordinal: u32) -> Option<ResolvedImport> {
    let name = *table().public_names.get((ordinal as usize).checked_sub(1)?)?;
    lookup(dll, name)
}

/// Visão de resolvedor dos provedores reais (encaminhamentos da HAL).
/// Endereço público de um export (o mesmo que a EAT entrega aos drivers).
fn public_export_address(name: &str) -> Option<u64> {
    export_module().ok()?.exports.exports.get(name).copied()
}

pub fn export_module() -> Result<ExportedModule, KernelError> {
    let table = table();
    let mut exports = Exports::default();
    for (index, &name) in table.public_names.iter().enumerate() {
        let address = match table.data.get(name) {
            Some(getter) => getter(),
            None if index < abi_names::EXPORT_NAMES.len() => thunk_address(32 + index as u64)?,
            None => continue,
        };
        exports.exports.insert(name.to_string(), address);
        exports.exports_by_ordinal.insert(index as u32 + 1, address);
    }
    Ok(ExportedModule { name: String::from("ntoskrnl.exe"), exports })
}

/// Liga a tabela ao loader (resolvedor de `ntoskrnl.exe` e trampolins).
pub fn init() {
    pe_loader::set_thunk_table(Some(win32_thunk::thunk_table()));
    crate::ntos::ke::bugcheck::init();
    crate::ntos::io::file::zw::init();
    crate::ntos::ps::user::state::init();
    crate::ntos::ps::user::sections::init();
    crate::ntos::ps::user::memory::init();
    crate::ntos::ps::user::registry::init();
    crate::ntos::ps::user::file_io::init();
    crate::ntos::ps::user::files::init();
    crate::ntos::ps::user::handles::init();
    crate::ntos::ps::user::events::init();
    crate::ntos::ps::user::semaphore::init();
    crate::ntos::ps::user::mutants::init();
    crate::ntos::ps::user::timer_objects::init();
    crate::ntos::ob::objects::completion::init();
    crate::ntos::ob::objects::port::init();
    crate::ntos::ps::termination_ports::init();
    crate::ntos::ps::set_process_information::init();
    // O fallback LPC registra antes da camada ALPC.
    crate::ntos::ps::user::lpc::init();
    crate::ntos::ps::user::alpc::init();
    crate::ntos::ps::user::csr::init();
    crate::ntos::cm::service::rpc::init();
    crate::ntos::ps::user::worker_factory::init();
    crate::ntos::ps::user::wnf::init();
    crate::ntos::ps::user::exceptions::init();
    crate::ntos::ps::user::device_io::init();
    crate::ntos::ps::user::instrumentation::init();
    crate::ntos::ps::user::tls::init();
    crate::ntos::ps::user::process_debug::init();
    crate::ntos::ps::user::call_capture::init();
    crate::ntos::ps::user::io_completion::init();
    crate::ntos::ps::user::jobs::init();
    crate::ntos::ps::user::threads::init();
    crate::ntos::ps::user::process::init();
    crate::ntos::ps::user::user_apc::init();
    crate::ntos::ke::user_callback::init();
    crate::ntos::kd::debug_filter::register_user_services();
    crate::ntos::etw::syscalls::init();
    // Os tipos de objeto que o executive cria no boot (idempotente).
    crate::ntos::ex::win32::initialize();
    crate::ntos::ex::timer::initialize_type();
    crate::ntos::ps::job::initialize_type();
    crate::ntos::ps::memory_reserve::initialize_types();
    crate::ntos::ex::timer_object::initialize();
    crate::ntos::ps::win32::init();
    crate::ntos::ps::user::wait_packets::init();
    crate::ntos::ps::user::nls::init();
    crate::ntos::ps::user::syscalls_core::init();
    crate::ntos::ps::user::time_services::init();
    crate::ntos::ex::timer_resolution::initialize();
    crate::ntos::ps::user::tokens::init();
    crate::ntos::po::shutdown::register_user_services();
    crate::ntos::ps::user::index::register();
    crate::ntos::ps::process_image::init();
    crate::ntos::ps::user::index::set_user_mode_init(crate::hal::amd64::usermode::user_mode_init);
    crate::ntos::ps::user::threads::set_executor(crate::hal::amd64::usermode::exec_user_context);
    crate::ntos::ps::user::syscalls_core::set_user_debug_registers(crate::hal::amd64::usermode::set_user_debug_registers);
    crate::ntos::io::file::request::init();
    // Armazenamento do triage dump reservado no boot (sem alocar em IRQL alto).
    if let Err(error) = crate::ntos::ke::persistent_thread_state::init() {
        debug_print!("[ntoskrnl] triage dump: {}", error);
    }
    static REGISTERED: SpinLock<bool> = SpinLock::new(false);
    let mut registered = REGISTERED.lock();
    if *registered {
        return;
    }
    *registered = true;
    native_context::register_kernel_provider(native_context::KernelProvider { handle, valid: valid_id }).unwrap_or_else(|error| panic!("{error}"));
    // As lookasides sem rotinas próprias usam os exports públicos de pool.
    crate::ntos::ex::lookaside::register_kernel_provider(public_export_address).unwrap_or_else(|error| panic!("{error}"));
    pe_loader::register_resolver(
        |dll| dll.eq_ignore_ascii_case("ntoskrnl.exe"),
        Arc::new(|dll: &str, symbol: &ImportSymbol| match symbol {
            ImportSymbol::Name(name) => lookup(dll, name),
            ImportSymbol::Ordinal(ordinal) => lookup_ordinal(dll, *ordinal),
        }),
    );
    // hal.dll e os .sys (drivers de export e drivers importados).
    crate::ntos::mm::sysload::register_resolvers();
}

/// `handle`: a faixa de serviços vai para `ex::system_services`; o
/// resto roda sob a invocação do CONTEXT capturado (transferências pedidas
/// pelo handler viram retorno zero com a ação marcada).
pub fn handle(id: u64, args: &[u64; 14], return_address: u64, frame: u64, context: u64) -> Result<u64, KernelError> {
    let call = Call { args: *args, return_address, frame, context };
    if crate::ntos::init::exports::private_routines::name(id).is_some() {
        return native_context::invoke(context, || crate::ntos::init::exports::private_routines::dispatch(id, &call));
    }
    if crate::ntos::ex::system_services::owns(id) {
        return crate::ntos::ex::system_services::dispatch(id, args, return_address, frame, context);
    }
    native_context::invoke(context, || dispatch(id, &call))
}

/// Rastreio das chamadas de API: cada export despachado imprime nome, quatro
/// primeiros argumentos, resultado e retorno.
static TRACE_API: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn set_api_trace(enabled: bool) {
    TRACE_API.store(enabled, core::sync::atomic::Ordering::SeqCst);
}

pub fn api_trace_enabled() -> bool {
    TRACE_API.load(core::sync::atomic::Ordering::Relaxed)
}

/// Detalhes legíveis do rastreamento: o nome do objeto aberto (pelos
/// OBJECT_ATTRIBUTES), o nome pedido ao MmGetSystemRoutineAddress, o nome
/// do valor do Registry e o texto que o driver grava num arquivo.
fn trace_details(name: &str, call: &Call) {
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::rtl::guest_strings;
    let unicode = |pointer: u64| if pointer == 0 { None } else { guest_strings::try_read_unicode_string(pointer).ok() };
    let object_attributes = match name {
        "ZwCreateFile" | "ZwOpenFile" | "IoCreateFile" | "IoCreateFileEx" | "IoCreateFileSpecifyDeviceObjectHint" | "ZwCreateKey" | "ZwOpenKey" | "ZwOpenKeyEx" | "ZwCreateSection" | "ZwOpenSection" | "ZwOpenSymbolicLinkObject" | "ZwOpenDirectoryObject" | "ZwCreateDirectoryObject" | "ZwCreateEvent" | "ZwOpenEvent" | "ZwOpenProcess" | "ZwOpenThread" | "ZwDeleteFile" | "ZwQueryAttributesFile" | "ZwQueryFullAttributesFile" => Some(3),
        _ => None,
    };
    if let Some(index) = object_attributes {
        use crate::ntos::inc::types::{NtStruct, ObjectAttributes};
        // OBJECT_ATTRIBUTES do chamador (pode vir do modo usuário): sondado.
        let (name_pointer, root) = match ObjectAttributes::try_at(call.arg(index)) {
            Ok(attributes) => (attributes.object_name.probe_get().unwrap_or(0), attributes.root_directory.probe_get().unwrap_or(0)),
            Err(_) => (0, 0),
        };
        if let Some(text) = unicode(name_pointer) {
            debug_print!("[api]   nome: {} (raiz {:#x})", text, root);
        }
    }
    match name {
        // O nome procurado (primeiro argumento) quando muda: as buscas
        // binárias de um driver na EAT aparecem como uma linha por nome.
        "strcmp" | "_stricmp" | "strncmp" | "_strnicmp" => {
            static LAST: crate::rtl::SpinLock<alloc::string::String> = crate::rtl::SpinLock::new(alloc::string::String::new());
            let mut text = alloc::string::String::new();
            for index in 0..128u64 {
                match guest::try_read8(call.arg(1) + index) {
                    Ok(0) | Err(_) => break,
                    Ok(byte) => text.push(byte as char),
                }
            }
            let mut last = LAST.lock();
            if *last != text {
                debug_print!("[api]   procura: {}", text);
                *last = text;
            }
        }
        "MmGetSystemRoutineAddress" => {
            if let Some(text) = unicode(call.arg(1)) {
                debug_print!("[api]   rotina: {}", text);
            }
        }
        // A thread que espera ou sinaliza e, numa espera múltipla, cada
        // objeto com o SignalState do DISPATCHER_HEADER.
        "KeWaitForMultipleObjects" | "KeWaitForSingleObject" | "KeSetEvent" | "KePulseEvent" => {
            let objects: alloc::vec::Vec<u64> = if name == "KeWaitForMultipleObjects" { (0..call.arg(1).min(64)).map(|index| guest::try_read::<u64>(call.arg(2) + index * 8).unwrap_or(0)).collect() } else { alloc::vec![call.arg(1)] };
            let states: alloc::vec::Vec<alloc::string::String> = objects.iter().map(|&object| alloc::format!("{object:#x}={}", guest::try_read::<i32>(object + 4).map_or(-1, |state| state))).collect();
            debug_print!("[api]   tid {} objetos {}", crate::ntos::ps::process::get_current_thread_id(), states.join(" "));
        }
        "ZwQueryValueKey" | "ZwSetValueKey" | "ZwDeleteValueKey" => {
            if let Some(text) = unicode(call.arg(2)) {
                debug_print!("[api]   valor: {}", text);
            }
        }
        "ZwWriteFile" => {
            let (buffer, length) = (call.arg(6), call.arg(7) as u32 as usize);
            if let Ok(bytes) = guest::try_read_bytes(buffer, length.min(1024)) {
                let wide = bytes.len() >= 2 && bytes.chunks(2).take(16).all(|pair| pair.len() == 2 && pair[1] == 0);
                let text: alloc::string::String = if wide {
                    char::decode_utf16(bytes.chunks(2).map(|pair| u16::from_le_bytes([pair[0], *pair.get(1).unwrap_or(&0)]))).map(|c| c.unwrap_or('?')).collect()
                } else {
                    bytes.iter().map(|&byte| byte as char).collect()
                };
                debug_print!("[api]   dados ({} bytes): {}", length, text.replace('\r', "").replace('\n', " | "));
            }
        }
        _ => {}
    }
}

/// O texto que as rotinas de formatação da CRT acabaram de produzir no
/// buffer do driver (o primeiro argumento).
fn trace_formatted_text(name: &str, call: &Call, result: &Result<u64, KernelError>) {
    use crate::ntos::mm::guest_memory as guest;
    if result.is_err() || call.arg(1) == 0 {
        return;
    }
    let wide = match name {
        "_vsnwprintf" | "_snwprintf" | "swprintf_s" | "vswprintf_s" | "swprintf" | "_swprintf" | "_vswprintf" | "wcscpy_s" | "wcscat_s" => true,
        "_vsnprintf" | "_snprintf" | "sprintf_s" | "vsprintf_s" | "sprintf" | "vsprintf" | "_vsnprintf_s" | "_snprintf_s" => false,
        _ => return,
    };
    let mut text = alloc::string::String::new();
    for index in 0..512u64 {
        let unit = if wide { guest::try_read16(call.arg(1) + index * 2).map(|unit| unit as u32) } else { guest::try_read8(call.arg(1) + index).map(|byte| byte as u32) };
        match unit {
            Ok(0) | Err(_) => break,
            Ok(unit) => text.push(char::from_u32(unit).unwrap_or('?')),
        }
    }
    debug_print!("[api]   texto: {}", text.replace('\r', "").replace('\n', " | "));
}

fn dispatch(id: u64, call: &Call) -> Result<u64, KernelError> {
    let traced = TRACE_API.load(core::sync::atomic::Ordering::Relaxed);
    if traced {
        let name = id.checked_sub(32).and_then(|index| abi_names::EXPORT_NAMES.get(index as usize)).copied().unwrap_or("?");
        debug_print!("[api] {}({:#x}, {:#x}, {:#x}, {:#x}) @{:#x}", name, call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.return_address);
        trace_details(name, call);
    }
    let result = dispatch_export(id, call);
    if traced {
        let name = id.checked_sub(32).and_then(|index| abi_names::EXPORT_NAMES.get(index as usize)).copied().unwrap_or("?");
        trace_formatted_text(name, call, &result);
        match &result {
            Ok(value) => debug_print!("[api]   -> {:#x}", value),
            Err(error) => debug_print!("[api]   -> erro {}", error),
        }
    }
    result
}

fn dispatch_export(id: u64, call: &Call) -> Result<u64, KernelError> {
    if id < 32 {
        debug_print!("[ntoskrnl] export de modo usuario id={} sem provedor", id);
        return Ok(0);
    }
    let table = table();
    let index = (id - 32) as usize;
    let (Some(&name), Some(&Some(handler))) = (abi_names::EXPORT_NAMES.get(index), table.handlers.get(index)) else {
        debug_print!("[ntoskrnl] export desconhecido id={}", id - 32);
        return Ok(0);
    };
    if name.starts_with("Zw") {
        previous_mode::with_kernel(|| handler(call)).and_then(|result| result)
    } else {
        handler(call)
    }
}

/// Provedor de um export chamado pelo nome a partir do próprio kernel, sem
/// o trampolim nativo.
pub fn invoke_handler(name: &str, arguments: &[u64]) -> Result<u64, KernelError> {
    let table = table();
    let handler = abi_names::EXPORT_NAMES.iter().position(|&candidate| candidate == name).and_then(|index| table.handlers.get(index).copied().flatten()).ok_or_else(|| KernelError::new(alloc::format!("export sem provedor: {name}")))?;
    let mut args = [0u64; 14];
    args[..arguments.len()].copy_from_slice(arguments);
    handler(&Call { args, return_address: 0, frame: 0, context: 0 })
}

/// Ids aceitos numa saída de contexto nativo: exports públicos e a faixa de
/// serviços (as rotinas privadas entram com o seu módulo).
fn valid_id(id: u64) -> bool {
    id >= 32 && ((id - 32) < abi_names::EXPORT_NAMES.len() as u64 || crate::ntos::ex::system_services::owns(id) || crate::ntos::init::exports::private_routines::name(id).is_some())
}

/// NTSTATUS devolvido como inteiro de 32 bits com sinal: RAX recebe o valor
/// estendido.
pub fn signed_status(status: u32) -> u64 {
    status as i32 as i64 as u64
}

/// Falha fatal dos grupos que interrompem o sistema em erro interno; o
/// sinal de transferência continua propagando.
pub fn fatal_unless_transfer<T>(tag: &str, result: Result<T, KernelError>) -> Result<T, KernelError> {
    match result {
        Err(error) if !native_context::is_transfer(&error) => {
            debug_print!("[{}] fatal kernel failure: {}", tag, error);
            panic!("[{tag}] fatal kernel failure: {error}");
        }
        other => other,
    }
}

/// Despachante chamado pelo trampolim comum (id, frame original, CONTEXT).
/// Uma falha interna não tem resultado nativo válido: interrompe o sistema
/// em vez de devolver zero e pular a operação.
#[no_mangle]
pub extern "win64" fn opennt_ntoskrnl_dispatch(id: u64, frame: u64, context: u64) -> u64 {
    // Uma thread de kernel que gastou o quantum cede a vez antes do serviço
    // (e recebe as APCs de kernel pendentes), como no fim de quantum do NT.
    crate::ntos::ke::context_switch::quantum_end_at_service_entry();
    // O CONTEXT e o frame estão na pilha do chamador (kernel).
    let read = |address: u64| unsafe { core::ptr::read_volatile(address as *const u64) };
    let mut args = [0u64; 14];
    args[0] = read(context + 0x80);
    args[1] = read(context + 0x88);
    args[2] = read(context + 0xB8);
    args[3] = read(context + 0xC0);
    for (index, slot) in args.iter_mut().enumerate().skip(4) {
        *slot = read(frame + 40 + (index as u64 - 4) * 8);
    }
    // Durante o retorno ao kernel, esta CPU deixa de executar a chamada
    // nativa síncrona; a saída restaura o dono anterior.
    let previous = crate::hal::amd64::native_call::set_sync_active(0);
    let result = handle(id, &args, read(frame), frame, context);
    crate::hal::amd64::native_call::set_sync_active(previous);
    match result {
        Ok(value) => value,
        Err(error) => panic!("excecao no dispatcher nativo (id {id}, retorno {:#x}): {error}", read(frame)),
    }
}

pub mod private_routines {
    //! Rotinas nativas privadas.
    //!
    //! Têm espaço de ids próprio (0x80000000+), nunca entram na EAT e preservam
    //! os ordinais públicos.

    use crate::hal::amd64::private_entries;
    use crate::ntos::mm::{independent_pages, kernel_address};
    use crate::ntos::ob::find_handle;
    use crate::ntos::ob::handles::process as process_handles;
    use crate::ntos::ps::enum_process_threads;
    use crate::rtl::KernelError;
    use crate::ntos::init::exports::Call;

    pub const ID: u64 = 0x8000_0000;
    pub const FREE_ID: u64 = ID + 1;
    pub const ENUM_THREADS_ID: u64 = ID + 2;
    pub const NEXT_THREAD_ID: u64 = ID + 3;
    pub const CONTEXT_APC_ID: u64 = ID + 4;
    pub const CONTEXT_RUNDOWN_ID: u64 = ID + 5;
    pub const SET_CONTEXT_ID: u64 = ID + 6;
    pub const REFERENCE_TABLE_ID: u64 = ID + 7;
    pub const FIND_HANDLE_FILTER_ID: u64 = ID + 8;
    pub const IMAGE_FILE_SIGNATURE_ID: u64 = ID + 9;
    pub const CSQ_CANCEL_ID: u64 = ID + 10;
    pub const UNLOAD_SAFE_COMPLETION_ID: u64 = ID + 11;
    pub const RESERVE_PACKET_CALLBACK_ID: u64 = ID + 12;
    pub const TIMER_APC_ID: u64 = ID + 13;
    pub const DELETE_TIMER_ID: u64 = ID + 14;
    pub const JOB_CLOSE_ID: u64 = ID + 15;
    pub const JOB_DELETE_ID: u64 = ID + 16;
    pub const WIN32_OPEN_ID: u64 = ID + 17;
    pub const WIN32_OKAY_TO_CLOSE_ID: u64 = ID + 18;
    pub const WIN32_CLOSE_ID: u64 = ID + 19;
    pub const WIN32_DELETE_ID: u64 = ID + 20;
    pub const WIN32_PARSE_ID: u64 = ID + 21;
    pub const THREAD_HETERO_POLICIES_ID: u64 = ID + 22;
    pub const ETW_THREAD_ENUM_ID: u64 = ID + 23;
    pub const RELEASE_GUARD_PAGE_ID: u64 = ID + 24;

    pub fn name(id: u64) -> Option<&'static str> {
        use crate::hal::private_dispatch;
        if (private_dispatch::BASE..private_dispatch::BASE + private_dispatch::SLOT_COUNT as u64).contains(&id) {
            return private_dispatch::routine_name((id - private_dispatch::BASE) as usize);
        }
        if crate::hal::amd64::routine_stubs::owns(id) {
            return crate::hal::amd64::routine_stubs::name(id);
        }
        Some(match id {
            ID => "MmAllocateIndependentPages",
            FREE_ID => "MmFreeIndependentPages",
            ENUM_THREADS_ID => "PsEnumProcessThreads",
            NEXT_THREAD_ID => "PsGetNextProcessThread",
            CONTEXT_APC_ID => "PspContextOperationApc",
            CONTEXT_RUNDOWN_ID => "PspContextOperationRundown",
            SET_CONTEXT_ID => "PspSetContextThreadInternal",
            REFERENCE_TABLE_ID => "ObReferenceProcessHandleTable",
            FIND_HANDLE_FILTER_ID => "ObpFindHandleForObject",
            IMAGE_FILE_SIGNATURE_ID => "MmGetImageFileSignatureInformation",
            CSQ_CANCEL_ID => "IopCsqCancelRoutine",
            UNLOAD_SAFE_COMPLETION_ID => "IopUnloadSafeCompletion",
            RESERVE_PACKET_CALLBACK_ID => "PspIoMiniPacketCallbackRoutine",
            TIMER_APC_ID => "ExpTimerApcRoutine",
            DELETE_TIMER_ID => "ExpDeleteTimer",
            JOB_CLOSE_ID => "PspJobClose",
            JOB_DELETE_ID => "PspJobDelete",
            WIN32_OPEN_ID => "ExpWin32OpenProcedure",
            WIN32_OKAY_TO_CLOSE_ID => "ExpWin32OkayToCloseProcedure",
            WIN32_CLOSE_ID => "ExpWin32CloseProcedure",
            WIN32_DELETE_ID => "ExpWin32DeleteProcedure",
            WIN32_PARSE_ID => "ExpWin32ParseProcedure",
            THREAD_HETERO_POLICIES_ID => "PopUpdateSingleThreadHeteroPolicies",
            ETW_THREAD_ENUM_ID => "EtwpThreadEnumCallback",
            RELEASE_GUARD_PAGE_ID => "MiReleaseBootGuardPage",
            _ => return None,
        })
    }

    /// Despacho de uma saída privada.
    pub fn dispatch(id: u64, call: &Call) -> Result<u64, KernelError> {
        use crate::hal::private_dispatch;
        if (private_dispatch::BASE..private_dispatch::BASE + private_dispatch::SLOT_COUNT as u64).contains(&id) {
            return private_dispatch::dispatch((id - private_dispatch::BASE) as usize, call);
        }
        if crate::hal::amd64::routine_stubs::owns(id) {
            return crate::hal::amd64::routine_stubs::dispatch(id, call);
        }
        match id {
            ID => independent_pages::allocate(call.arg(1), call.arg(2) as u32),
            FREE_ID => {
                independent_pages::free_pages(call.arg(1), call.arg(2))?;
                Ok(0)
            }
            ENUM_THREADS_ID => Ok(enum_process_threads::enumerate(call.arg(1), call.arg(2), call.arg(3))? as u64),
            NEXT_THREAD_ID => enum_process_threads::get_next(call.arg(1), call.arg(2)),
            REFERENCE_TABLE_ID => process_handles::reference(call.arg(1)),
            FIND_HANDLE_FILTER_ID => find_handle::filter(call.arg(1), call.arg(2), call.arg(3), call.arg(4)),
            CONTEXT_APC_ID => crate::ntos::ps::context::apc::deliver(call.arg(1)),
            CONTEXT_RUNDOWN_ID => crate::ntos::ps::context::apc::rundown(call.arg(1)),
            IMAGE_FILE_SIGNATURE_ID => Ok(crate::ntos::mm::image_file_signature::query(call.arg(1))),
            SET_CONTEXT_ID => crate::ntos::ps::context::set::execute(call.arg(1), call.arg(2), call.arg(3) as u8, call.arg(4) as u8, call.arg(5) as u32).map(|status| status as i32 as i64 as u64),
            CSQ_CANCEL_ID => crate::ntos::io::csq::cancel_routine(call.arg(1), call.arg(2)).map(|()| 0),
            UNLOAD_SAFE_COMPLETION_ID => crate::ntos::io::irp_request::unload_safe_completion(call.arg(1), call.arg(2), call.arg(3)).map(|status| status as i32 as i64 as u64),
            RESERVE_PACKET_CALLBACK_ID => crate::ntos::ps::memory_reserve::completion_packet_returned(call.arg(1), call.arg(2)),
            TIMER_APC_ID => crate::ntos::ex::timer_object::timer_apc_routine(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5)).map(|()| 0),
            DELETE_TIMER_ID => crate::ntos::ex::timer_object::delete_timer(call.arg(1)).map(|()| 0),
            // PspJobClose(Process, Job, ProcessHandleCount, SystemHandleCount).
            JOB_CLOSE_ID => {
                crate::ntos::ps::job::object::close_procedure(call.arg(2), call.arg(4));
                Ok(0)
            }
            JOB_DELETE_ID => {
                crate::ntos::ps::job::object::delete_procedure(call.arg(1));
                Ok(0)
            }
            // As rotinas dos tipos Win32 (ex/win32.rs), na ABI do OBJECT_TYPE_INITIALIZER.
            WIN32_OPEN_ID => Ok(super::signed_status(crate::ntos::ex::win32::open_procedure(call.arg(1) as u32, call.arg(3), call.arg(4), call.arg(5), call.arg(6) as u32))),
            WIN32_OKAY_TO_CLOSE_ID => Ok(crate::ntos::ex::win32::okay_to_close_procedure(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u8) as u64),
            WIN32_CLOSE_ID => {
                crate::ntos::ex::win32::close_procedure(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4) as u32);
                Ok(0)
            }
            WIN32_DELETE_ID => {
                crate::ntos::ex::win32::delete_procedure(call.arg(1));
                Ok(0)
            }
            WIN32_PARSE_ID => Ok(super::signed_status(crate::ntos::ex::win32::parse_procedure(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u8, call.arg(5) as u32, call.arg(6), call.arg(7), call.arg(8), call.arg(9), call.arg(10)))),
            // PopUpdateSingleThreadHeteroPolicies(Process, Thread, Context).
            THREAD_HETERO_POLICIES_ID => {
                crate::ntos::ke::hetero_policy::update_single_thread(call.arg(2));
                Ok(0)
            }
            ETW_THREAD_ENUM_ID => Ok(crate::ntos::etw::rundown::thread_enum_callback(call.arg(2), call.arg(3)) as u64),
            RELEASE_GUARD_PAGE_ID => independent_pages::release_guard_page(call.arg(1)).map(|()| 0),
            _ => Err(KernelError::new(alloc::format!("private routine {} enters with its module", name(id).unwrap_or("?")))),
        }
    }

    /// Endereço virtual de kernel de um símbolo privado (0 = sem entrada).
    pub fn address(symbol: &str) -> u64 {
        if symbol == "SepSetRuntimeUpdatableSigningLevel" {
            return crate::ntos::se::runtime_signing_policy::callback_address().unwrap_or(0);
        }
        private_entries::entry(symbol).and_then(|entry| kernel_address::image_address(entry).ok()).unwrap_or(0)
    }
}
