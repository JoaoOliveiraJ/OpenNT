//! Exports Rtl*, Interlocked* e da CRT do ntoskrnl.
//!
//! Semântica do NT sobre a memória do convidado. Divergência: os campos
//! Buffer das UNICODE/ANSI_STRING são lidos e escritos com 64 bits (o
//! original usava 32, suficiente para os endereços baixos dele).
//!
//! Só adaptadores: cada handler lê os argumentos do `Call`, chama a rotina
//! do arquivo de assunto do Rtl e converte o resultado (NTSTATUS, ponteiro,
//! BOOLEAN).

use alloc::vec::Vec;

use crate::ntos::init::exports::{signed_status, Call};
use crate::ntos::rtl::{
    crt, error, feature_configuration, guid, image, integer_conversion, interlocked, math, memory, nls_translation, printf, registry,
    strings_counted, system_volume, time, unicode, version,
};
use crate::rtl::KernelError;

// ---- handlers ------------------------------------------------------------

fn init_unicode_string(call: &Call) -> Result<u64, KernelError> {
    unicode::init(call.arg(1), call.arg(2));
    Ok(0)
}
fn compare_unicode_string(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::unicode::compare_string(call.arg(1), call.arg(2), call.arg(3) as u32)? as i64 as u64)
}
fn copy_unicode_string(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::strings_counted::copy(call.arg(1), call.arg(2));
    Ok(0)
}
fn equal_unicode_string(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::unicode::equal_string(call.arg(1), call.arg(2), call.arg(3) as u32)? as u64)
}
fn init_ansi_string(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::strings_counted::initialize_ansi(call.arg(1), call.arg(2));
    Ok(0)
}
fn ansi_string_to_unicode_string(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::ansi_code_page::ansi_to_unicode(call.arg(1), call.arg(2), call.arg(3) & 0xFF != 0)? as u64)
}
fn unicode_string_to_ansi_string(call: &Call) -> Result<u64, KernelError> {
    nls_translation::unicode_string_to_ansi_string(call.arg(1), call.arg(2), call.arg(3) & 0xFF != 0)?;
    Ok(0)
}
fn free_ansi_string(call: &Call) -> Result<u64, KernelError> {
    strings_counted::free_string(call.arg(1));
    Ok(0)
}
fn free_unicode_string(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::unicode::free(call.arg(1))?;
    Ok(0)
}
fn equal_string(call: &Call) -> Result<u64, KernelError> {
    Ok(strings_counted::equal_ansi(call.arg(1), call.arg(2), call.arg(3) & 0xFF != 0) as u64)
}
fn interlocked_increment(call: &Call) -> Result<u64, KernelError> {
    Ok(interlocked::increment(call.arg(1)) as u64)
}
fn interlocked_decrement(call: &Call) -> Result<u64, KernelError> {
    Ok(interlocked::decrement(call.arg(1)) as u64)
}
fn interlocked_exchange(call: &Call) -> Result<u64, KernelError> {
    Ok(interlocked::exchange(call.arg(1), call.arg(2) as u32) as u64)
}
fn interlocked_compare_exchange(call: &Call) -> Result<u64, KernelError> {
    Ok(interlocked::compare_exchange(call.arg(1), call.arg(2) as u32, call.arg(3) as u32) as u64)
}
fn memset(call: &Call) -> Result<u64, KernelError> {
    memory::fill(call.arg(1), call.arg(3), call.arg(2) as u8);
    Ok(call.arg(1))
}
fn memcpy(call: &Call) -> Result<u64, KernelError> {
    memory::move_memory(call.arg(1), call.arg(2), call.arg(3));
    Ok(call.arg(1))
}
fn unicode_string_to_integer(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(integer_conversion::unicode_string_to_integer(call.arg(1), call.arg(2) as u32, call.arg(3))))
}
fn integer_to_unicode_string(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(integer_conversion::integer_to_unicode_string(call.arg(1) as u32, call.arg(2) as u32, call.arg(3))))
}
fn zero_memory(call: &Call) -> Result<u64, KernelError> {
    memory::fill(call.arg(1), call.arg(2), 0);
    Ok(0)
}
fn fill_memory(call: &Call) -> Result<u64, KernelError> {
    memory::fill(call.arg(1), call.arg(2), call.arg(3) as u8);
    Ok(0)
}
fn copy_memory(call: &Call) -> Result<u64, KernelError> {
    memory::copy_memory(call.arg(1), call.arg(2), call.arg(3));
    Ok(0)
}
fn move_memory(call: &Call) -> Result<u64, KernelError> {
    memory::move_memory(call.arg(1), call.arg(2), call.arg(3));
    Ok(0)
}
fn compare_memory(call: &Call) -> Result<u64, KernelError> {
    Ok(memory::compare(call.arg(1), call.arg(2), call.arg(3)))
}
fn upcase_unicode_string(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(unicode::upcase_string(call.arg(1), call.arg(2), call.arg(3) & 0xFF != 0)))
}
fn downcase_unicode_string(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(unicode::downcase_string(call.arg(1), call.arg(2), call.arg(3) & 0xFF != 0)))
}
fn prefix_unicode_string(call: &Call) -> Result<u64, KernelError> {
    Ok(unicode::prefix(call.arg(1), call.arg(2), call.arg(3) & 0xFF != 0) as u64)
}
fn append_unicode_string_to_string(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(unicode::append_string(call.arg(1), call.arg(2))))
}
fn append_unicode_to_string(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(crate::ntos::rtl::strings_counted::append(call.arg(1), call.arg(2))))
}
fn interlocked_push_entry_list(call: &Call) -> Result<u64, KernelError> {
    Ok(interlocked::push_entry_list(call.arg(1), call.arg(2)))
}
fn interlocked_pop_entry_list(call: &Call) -> Result<u64, KernelError> {
    Ok(interlocked::pop_entry_list(call.arg(1)))
}
fn ex_interlocked_insert_tail_list(call: &Call) -> Result<u64, KernelError> {
    Ok(interlocked::insert_tail_list(call.arg(1), call.arg(2), call.arg(3)))
}
fn ex_interlocked_remove_head_list(call: &Call) -> Result<u64, KernelError> {
    Ok(interlocked::remove_head_list(call.arg(1), call.arg(2)))
}
fn strlen(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::crt::strlen(call.arg(1))
}
fn strcmp(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::crt::strcmp(call.arg(1), call.arg(2))? as i64 as u64)
}
fn strncmp(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::crt::strncmp(call.arg(1), call.arg(2), Some(call.arg(3)))? as i64 as u64)
}
fn strcpy(call: &Call) -> Result<u64, KernelError> {
    Ok(crt::strcpy(call.arg(1), call.arg(2)))
}
fn strncpy(call: &Call) -> Result<u64, KernelError> {
    Ok(crt::strncpy(call.arg(1), call.arg(2), call.arg(3)))
}
fn strcat(call: &Call) -> Result<u64, KernelError> {
    Ok(crt::strcat(call.arg(1), call.arg(2)))
}
fn strchr(call: &Call) -> Result<u64, KernelError> {
    Ok(crt::strchr(call.arg(1), call.arg(2) as u8))
}
fn strstr(call: &Call) -> Result<u64, KernelError> {
    Ok(crt::strstr(call.arg(1), call.arg(2)))
}
/// sprintf(buf, fmt, ...): seis argumentos variádicos.
fn sprintf(call: &Call) -> Result<u64, KernelError> {
    printf::sprintf(call.arg(1), call.arg(2), &[call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7), call.arg(8)])
}
fn snprintf(call: &Call) -> Result<u64, KernelError> {
    printf::snprintf(call.arg(1), call.arg(2), call.arg(3), &[call.arg(4), call.arg(5), call.arg(6), call.arg(7), call.arg(8)])
}
fn random(call: &Call) -> Result<u64, KernelError> {
    Ok(math::random(call.arg(1)) as u64)
}
fn verify_version_info(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(version::verify(call.arg(1), call.arg(2) as u32, call.arg(3))))
}
fn ver_set_condition_mask(call: &Call) -> Result<u64, KernelError> {
    Ok(version::set_condition_mask(call.arg(1), call.arg(2) as u32, call.arg(3) as u32))
}
fn write_registry_value(call: &Call) -> Result<u64, KernelError> {
    Ok(registry::write_value(call.arg(1) as u32, call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5), call.arg(6) as u32)? as u64)
}
fn query_registry_values_handler(call: &Call) -> Result<u64, KernelError> {
    registry::query_registry_values(call.arg(1) as u32, call.arg(2), call.arg(3), call.arg(4), call.arg(5))
}
fn vsnwprintf(call: &Call) -> Result<u64, KernelError> {
    printf::vsnwprintf(call.arg(1), call.arg(2), call.arg(3), call.arg(4))
}
fn wcsupr(call: &Call) -> Result<u64, KernelError> {
    Ok(crt::wcsupr(call.arg(1)))
}
fn c_specific_handler(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::exceptions::specific_handler(call.arg(1), call.arg(2), call.arg(3), call.arg(4))
}

fn initialize_bit_map(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::bitmap::initialize(call.arg(1), call.arg(2), call.arg(3) as u32);
    Ok(0)
}
fn set_all_bits(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::bitmap::set_all(call.arg(1));
    Ok(0)
}
fn clear_bits(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::bitmap::clear_bits(call.arg(1), call.arg(2) as u32, call.arg(3) as u32);
    Ok(0)
}
fn clear_bit(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::bitmap::clear_bit(call.arg(1), call.arg(2) as u32);
    Ok(0)
}
fn find_clear_bits_and_set(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::bitmap::find_clear_and_set(call.arg(1), call.arg(2) as u32, call.arg(3) as u32) as u64)
}
fn init_string(call: &Call) -> Result<u64, KernelError> {
    strings_counted::init_string(call.arg(1), call.arg(2));
    Ok(0)
}
fn string_from_guid(call: &Call) -> Result<u64, KernelError> {
    guid::string_from_guid(call.arg(1), call.arg(2));
    Ok(0)
}
fn duplicate_unicode_string(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(unicode::duplicate(call.arg(1) as u32, call.arg(2), call.arg(3))))
}
fn create_registry_key(call: &Call) -> Result<u64, KernelError> {
    Ok(registry::create_key(call.arg(1) as u32, call.arg(2))? as u64)
}
fn delete_registry_value(call: &Call) -> Result<u64, KernelError> {
    Ok(registry::delete_value(call.arg(1) as u32, call.arg(2), call.arg(3))? as u64)
}
fn get_version(call: &Call) -> Result<u64, KernelError> {
    version::write_version_information(call.arg(1));
    Ok(0)
}
fn query_feature_configuration(_: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(feature_configuration::query()))
}
fn zero(_: &Call) -> Result<u64, KernelError> {
    Ok(0)
}
fn register_feature_configuration_change_notification(call: &Call) -> Result<u64, KernelError> {
    feature_configuration::register_change_notification(call.arg(1), call.arg(2), call.arg(3));
    Ok(0)
}
fn unregister_feature_configuration_change_notification(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(feature_configuration::unregister_change_notification(call.arg(1))))
}
fn time_to_time_fields(call: &Call) -> Result<u64, KernelError> {
    time::time_to_time_fields(call.arg(1), call.arg(2));
    Ok(0)
}
fn upcase_unicode_char(call: &Call) -> Result<u64, KernelError> {
    Ok(nls_translation::upcase_unicode_char(call.arg(1) as u16) as u64)
}
fn ansi_string_to_unicode_size(call: &Call) -> Result<u64, KernelError> {
    Ok(nls_translation::ansi_string_to_unicode_size(call.arg(1)))
}
fn create_system_volume_information_folder(call: &Call) -> Result<u64, KernelError> {
    Ok(system_volume::create_information_folder(call.arg(1))? as u64)
}
fn strupr(call: &Call) -> Result<u64, KernelError> {
    Ok(crt::strupr(call.arg(1)))
}
fn vsnprintf(call: &Call) -> Result<u64, KernelError> {
    printf::vsnprintf(call.arg(1), call.arg(2), call.arg(3), call.arg(4))
}
fn v_dbg_print_ex_with_prefix(call: &Call) -> Result<u64, KernelError> {
    printf::debug_print_with_prefix(call.arg(1), call.arg(4), call.arg(5))?;
    Ok(0)
}
fn wcsstr(call: &Call) -> Result<u64, KernelError> {
    Ok(crt::wcsstr(call.arg(1), call.arg(2)))
}
fn wcscmp(call: &Call) -> Result<u64, KernelError> {
    Ok(crt::compare_wide(call.arg(1), call.arg(2), None, false))
}
fn wcsncmp(call: &Call) -> Result<u64, KernelError> {
    Ok(crt::compare_wide(call.arg(1), call.arg(2), Some(call.arg(3) as u32 as u64), false))
}
fn wcsicmp(call: &Call) -> Result<u64, KernelError> {
    Ok(crt::compare_wide(call.arg(1), call.arg(2), None, true))
}
fn wcsnicmp(call: &Call) -> Result<u64, KernelError> {
    Ok(crt::compare_wide(call.arg(1), call.arg(2), Some(call.arg(3) as u32 as u64), true))
}
fn wcslen(call: &Call) -> Result<u64, KernelError> {
    Ok(crt::wcslen(call.arg(1)))
}
fn strnlen(call: &Call) -> Result<u64, KernelError> {
    Ok(crt::strnlen(call.arg(1), call.arg(2)))
}
fn wcscat_s(call: &Call) -> Result<u64, KernelError> {
    Ok(crt::wcscat_s(call.arg(1), call.arg(2) as u32 as u64, call.arg(3)))
}
fn wcscpy_s(call: &Call) -> Result<u64, KernelError> {
    Ok(crt::wcscpy_s(call.arg(1), call.arg(2) as u32 as u64, call.arg(3)))
}
fn strcpy_s(call: &Call) -> Result<u64, KernelError> {
    Ok(crt::strcpy_s(call.arg(1), call.arg(2) as u32 as u64, call.arg(3)))
}
fn strncpy_s(call: &Call) -> Result<u64, KernelError> {
    Ok(crt::strncpy_s(call.arg(1), call.arg(2) as u32 as u64, call.arg(3), call.arg(4) as u32 as i32))
}
fn qsort(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::sort::sort_elements(call.arg(1), call.arg(2), call.arg(3), call.arg(4));
    Ok(0)
}
/// _snprintf_s(buffer, size, count, format, ...).
fn snprintf_s(call: &Call) -> Result<u64, KernelError> {
    printf::snprintf_s(call.arg(1), call.arg(2) as u32, call.arg(3) as u32 as i32, call.arg(4), &[call.arg(5), call.arg(6), call.arg(7), call.arg(8), call.arg(9), call.arg(10)])
}
fn swprintf_s(call: &Call) -> Result<u64, KernelError> {
    printf::swprintf_s(call.arg(1), call.arg(2) as u32 as u64, call.arg(3), &[call.arg(4), call.arg(5), call.arg(6), call.arg(7), call.arg(8), call.arg(9)])
}
fn vswprintf_s(call: &Call) -> Result<u64, KernelError> {
    printf::vswprintf_s(call.arg(1), call.arg(2) as u32 as u64, call.arg(3), call.arg(4))
}
fn nt_status_to_dos_error(call: &Call) -> Result<u64, KernelError> {
    Ok(error::status_to_dos_error(call.arg(1) as u32) as u64)
}
fn get_enabled_extended_features(call: &Call) -> Result<u64, KernelError> {
    Ok(version::enabled_extended_features(call.arg(1)))
}
fn get_persisted_state_location(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::cm::persisted_state::query(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5), call.arg(6) as u32, call.arg(7)) as u64)
}
fn multi_byte_to_unicode_n(call: &Call) -> Result<u64, KernelError> {
    nls_translation::multi_byte_to_unicode_n(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4), call.arg(5) as u32);
    Ok(0)
}
fn pc_to_file_header(call: &Call) -> Result<u64, KernelError> {
    Ok(image::pc_to_file_header(call.arg(1), call.arg(2)))
}
/// __chkstk exige a ABI nativa de sondagem de pilha (corpo x64 próprio).
fn chkstk(_: &Call) -> Result<u64, KernelError> {
    Err(KernelError::new("__chkstk requires the native stack-probe ABI"))
}
fn local_unwind(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::exceptions::unwind_ex(call.arg(1), call.arg(2), 0, 0, 0, 0)
}
fn image_nt_header(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::image::nt_header(call.arg(1))
}
fn image_nt_header_ex(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::image::nt_header_ex(call.arg(1) as u32, call.arg(2), call.arg(3), call.arg(4))? as u64)
}
fn image_directory_entry_to_data(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::image::directory_entry(call.arg(1), call.arg(2) & 0xFF != 0, call.arg(3) as u16 as u32, call.arg(4))
}
fn time_fields_to_time(call: &Call) -> Result<u64, KernelError> {
    Ok(time::time_fields_to_time(call.arg(1), call.arg(2)) as u64)
}
fn valid_sid(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::sid::valid(call.arg(1)) as u64)
}
fn check_token_membership(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::token::membership::check(call.arg(1), call.arg(2), call.arg(3))? as u64)
}
fn length_sid(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::sid::length(call.arg(1)) as u64)
}
fn copy_sid(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::sid::copy(call.arg(1) as u32, call.arg(2), call.arg(3)) as u64)
}
fn equal_sid(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::sid::equal(call.arg(1), call.arg(2)) as u64)
}
/// RtlInitializeSidEx: as subautoridades variádicas vêm dos argumentos 4 em diante.
fn initialize_sid_ex(call: &Call) -> Result<u64, KernelError> {
    let sub_authorities: Vec<u32> = (4..=14).map(|index| call.arg(index) as u32).collect();
    Ok(crate::ntos::se::sid::initialize_ex(call.arg(1), call.arg(2), call.arg(3) as u32, &sub_authorities) as u64)
}
fn get_ace(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::descriptor::get_ace(call.arg(1), call.arg(2) as u32, call.arg(3)) as u64)
}
fn get_dacl_security_descriptor(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::descriptor::get_dacl(call.arg(1), call.arg(2), call.arg(3), call.arg(4)) as u64)
}
fn get_owner_security_descriptor(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::descriptor::get_owner(call.arg(1), call.arg(2), call.arg(3)) as u64)
}
fn length_security_descriptor(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::descriptor::length(call.arg(1)) as u64)
}
fn absolute_to_self_relative_sd(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::descriptor::absolute_to_relative(call.arg(1), call.arg(2), call.arg(3)) as u64)
}
fn avl_insert_node(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::avl::insert(call.arg(1), call.arg(2), call.arg(3), call.arg(4))? as u64)
}
fn avl_remove_node(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::avl::remove(call.arg(1), call.arg(2))? as u64)
}
fn utf8_to_unicode_n(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::utf8::utf8_to_unicode(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4), call.arg(5) as u32)? as u64)
}
fn unicode_to_utf8_n(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::utf8::unicode_to_utf8(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4), call.arg(5) as u32)? as u64)
}
fn compare_unicode_strings(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::unicode::compare(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5) as u32)? as i64 as u64)
}
fn find_unicode_substring(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::unicode::find(call.arg(1), call.arg(2), call.arg(3) as u32)
}
fn create_unicode_string(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::unicode::create(call.arg(1), call.arg(2))? as u64)
}
fn guid_from_string(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::unicode::guid_from_string(call.arg(1), call.arg(2))? as u64)
}
fn get_nt_system_root(_: &Call) -> Result<u64, KernelError> {
    Ok(version::nt_system_root())
}
fn stricmp(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::crt::stricmp(call.arg(1), call.arg(2))? as i64 as u64)
}
fn atoi(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::crt::atoi(call.arg(1))? as i64 as u64)
}
fn ultow_s(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::crt::ultow(call.arg(1) as u32, call.arg(2), call.arg(3), call.arg(4) as u32 as i32)? as u64)
}
fn bsearch(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::crt::binary_search(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), 0, false)
}
fn bsearch_s(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::crt::binary_search(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6), true)
}
fn isdigit(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::crt::isdigit(call.arg(1) as u32) as u64)
}
fn wcschr(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::crt::wcschr(call.arg(1), call.arg(2) as u32)
}
fn clear_all_bits(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::bitmap::clear_all(call.arg(1));
    Ok(0)
}
fn set_bits(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::bitmap::set_bits(call.arg(1), call.arg(2) as u32, call.arg(3) as u32);
    Ok(0)
}
fn set_bit(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::bitmap::set_bit(call.arg(1), call.arg(2) as u32);
    Ok(0)
}
fn test_bit(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::bitmap::test_bit(call.arg(1), call.arg(2) as u32) as u64)
}
fn find_clear_bits(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::bitmap::find_clear(call.arg(1), call.arg(2) as u32, call.arg(3) as u32) as u64)
}
fn find_set_bits(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::bitmap::find_set(call.arg(1), call.arg(2) as u32, call.arg(3) as u32) as u64)
}
fn find_set_bits_and_clear(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::bitmap::find_set_and_clear(call.arg(1), call.arg(2) as u32, call.arg(3) as u32) as u64)
}
fn are_bits_clear(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::bitmap::are_clear(call.arg(1), call.arg(2) as u32, call.arg(3) as u32) as u64)
}
fn are_bits_set(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::bitmap::are_set(call.arg(1), call.arg(2) as u32, call.arg(3) as u32) as u64)
}
fn number_of_set_bits(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::bitmap::number_set(call.arg(1)) as u64)
}
fn number_of_clear_bits(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::bitmap::number_clear(call.arg(1)) as u64)
}
fn interlocked_clear_bit_run(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::bitmap::interlocked_clear(call.arg(1), call.arg(2) as u32, call.arg(3) as u32);
    Ok(0)
}
fn interlocked_set_bit_run(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::rtl::bitmap::interlocked_set(call.arg(1), call.arg(2) as u32, call.arg(3) as u32);
    Ok(0)
}
fn interlocked_set_clear_run(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::bitmap::reserve_clear_run(call.arg(1), call.arg(2) as u32, call.arg(3) as u32) as u64)
}
fn run_once_initialize(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::run_once::initialize(call.arg(1))? as u64)
}
fn run_once_begin_initialize(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::run_once::begin_initialize(call.arg(1), call.arg(2) as u32, call.arg(3))? as u64)
}
fn run_once_complete(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::run_once::complete(call.arg(1), call.arg(2) as u32, call.arg(3))? as u64)
}
fn run_once_execute_once(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::rtl::run_once::execute(call.arg(1), call.arg(2), call.arg(3), call.arg(4))? as u64)
}
fn valid_acl(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::acl::valid(call.arg(1)) as u64)
}
fn valid_security_descriptor(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::descriptor::valid(call.arg(1)) as u64)
}
fn valid_relative_security_descriptor(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::se::descriptor::valid_relative(call.arg(1), call.arg(2) as u32, call.arg(3) as u32) as u64)
}

pub static GROUP: crate::ntos::init::exports::Group = crate::ntos::init::exports::Group {
    name: "rtl",
    names: &[
        "RtlInitUnicodeString", "RtlCompareUnicodeString", "RtlCopyUnicodeString", "RtlEqualUnicodeString", "RtlInitAnsiString", "RtlAnsiStringToUnicodeString", "RtlUnicodeStringToAnsiString", "RtlFreeAnsiString", "RtlFreeUnicodeString", "RtlEqualString", "InterlockedIncrement", "InterlockedDecrement", "InterlockedExchange", "InterlockedCompareExchange", "memset", "memcpy", "memmove", "RtlUnicodeStringToInteger", "RtlIntegerToUnicodeString", "RtlZeroMemory", "RtlFillMemory", "RtlCopyMemory", "RtlMoveMemory", "RtlCompareMemory", "RtlUpcaseUnicodeString", "RtlDowncaseUnicodeString", "RtlPrefixUnicodeString", "RtlAppendUnicodeStringToString", "RtlAppendUnicodeToString", "InterlockedPushEntryList", "InterlockedPopEntryList", "ExInterlockedInsertTailList", "ExInterlockedRemoveHeadList", "strlen", "strcmp", "strncmp", "strcpy", "strncpy", "strcat", "strchr", "strstr", "sprintf", "snprintf", "RtlRandom", "RtlRandomEx", "RtlVerifyVersionInfo", "VerSetConditionMask", "RtlWriteRegistryValue", "RtlQueryRegistryValues", "RtlQueryRegistryValuesEx", "_vsnwprintf", "_wcsupr", "__C_specific_handler", "RtlInitializeBitMap", "RtlSetAllBits", "RtlClearBits", "RtlClearBit", "RtlFindClearBitsAndSet", "RtlInitString", "RtlStringFromGUID", "RtlDuplicateUnicodeString", "RtlCreateRegistryKey", "RtlDeleteRegistryValue", "RtlGetVersion", "RtlQueryFeatureConfiguration", "RtlQueryFeatureConfigurationChangeStamp", "RtlRegisterFeatureConfigurationChangeNotification", "RtlUnregisterFeatureConfigurationChangeNotification", "RtlTimeToTimeFields", "RtlUpcaseUnicodeChar", "RtlxAnsiStringToUnicodeSize", "RtlCreateSystemVolumeInformationFolder", "_strupr", "_vsnprintf", "vDbgPrintExWithPrefix", "wcsstr", "wcscmp", "wcsncmp", "_wcsicmp", "_wcsnicmp", "wcslen", "strnlen", "wcscat_s", "wcscpy_s", "strcpy_s", "strncpy_s", "qsort", "_snprintf_s", "swprintf_s", "vswprintf_s", "RtlNtStatusToDosError", "RtlNtStatusToDosErrorNoTeb", "RtlGetEnabledExtendedFeatures", "RtlGetPersistedStateLocation", "RtlMultiByteToUnicodeN", "RtlPcToFileHeader", "__chkstk", "_local_unwind", "RtlImageNtHeader", "RtlImageNtHeaderEx", "RtlImageDirectoryEntryToData", "RtlTimeFieldsToTime", "RtlValidSid", "RtlCheckTokenMembership", "RtlLengthSid", "RtlCopySid", "RtlEqualSid", "RtlInitializeSidEx", "RtlGetAce", "RtlGetDaclSecurityDescriptor", "RtlGetOwnerSecurityDescriptor", "RtlLengthSecurityDescriptor", "RtlAbsoluteToSelfRelativeSD", "RtlAvlInsertNodeEx", "RtlAvlRemoveNode", "RtlUTF8ToUnicodeN", "RtlUnicodeToUTF8N", "RtlCompareUnicodeStrings", "RtlFindUnicodeSubstring", "RtlCreateUnicodeString", "RtlGUIDFromString", "RtlGetNtSystemRoot", "_stricmp", "atoi", "_ultow_s", "bsearch", "bsearch_s", "isdigit", "wcschr", "RtlClearAllBits", "RtlSetBits", "RtlSetBit", "RtlTestBit", "RtlFindClearBits", "RtlFindSetBits", "RtlFindSetBitsAndClear", "RtlAreBitsClear", "RtlAreBitsSet", "RtlNumberOfSetBits", "RtlNumberOfClearBits", "RtlInterlockedClearBitRun", "RtlInterlockedSetBitRun", "RtlInterlockedSetClearRun", "RtlRunOnceInitialize", "RtlRunOnceBeginInitialize", "RtlRunOnceComplete", "RtlRunOnceExecuteOnce", "RtlValidAcl", "RtlValidSecurityDescriptor", "RtlValidRelativeSecurityDescriptor",
    ],
    handlers: &[
        init_unicode_string, compare_unicode_string, copy_unicode_string, equal_unicode_string, init_ansi_string, ansi_string_to_unicode_string, unicode_string_to_ansi_string, free_ansi_string, free_unicode_string, equal_string, interlocked_increment, interlocked_decrement, interlocked_exchange, interlocked_compare_exchange, memset, memcpy, memcpy, unicode_string_to_integer, integer_to_unicode_string, zero_memory, fill_memory, copy_memory, move_memory, compare_memory, upcase_unicode_string, downcase_unicode_string, prefix_unicode_string, append_unicode_string_to_string, append_unicode_to_string, interlocked_push_entry_list, interlocked_pop_entry_list, ex_interlocked_insert_tail_list, ex_interlocked_remove_head_list, strlen, strcmp, strncmp, strcpy, strncpy, strcat, strchr, strstr, sprintf, snprintf, random, random, verify_version_info, ver_set_condition_mask, write_registry_value, query_registry_values_handler, query_registry_values_handler, vsnwprintf, wcsupr, c_specific_handler, initialize_bit_map, set_all_bits, clear_bits, clear_bit, find_clear_bits_and_set, init_string, string_from_guid, duplicate_unicode_string, create_registry_key, delete_registry_value, get_version, query_feature_configuration, zero, register_feature_configuration_change_notification, unregister_feature_configuration_change_notification, time_to_time_fields, upcase_unicode_char, ansi_string_to_unicode_size, create_system_volume_information_folder, strupr, vsnprintf, v_dbg_print_ex_with_prefix, wcsstr, wcscmp, wcsncmp, wcsicmp, wcsnicmp, wcslen, strnlen, wcscat_s, wcscpy_s, strcpy_s, strncpy_s, qsort, snprintf_s, swprintf_s, vswprintf_s, nt_status_to_dos_error, nt_status_to_dos_error, get_enabled_extended_features, get_persisted_state_location, multi_byte_to_unicode_n, pc_to_file_header, chkstk, local_unwind, image_nt_header, image_nt_header_ex, image_directory_entry_to_data, time_fields_to_time, valid_sid, check_token_membership, length_sid, copy_sid, equal_sid, initialize_sid_ex, get_ace, get_dacl_security_descriptor, get_owner_security_descriptor, length_security_descriptor, absolute_to_self_relative_sd, avl_insert_node, avl_remove_node, utf8_to_unicode_n, unicode_to_utf8_n, compare_unicode_strings, find_unicode_substring, create_unicode_string, guid_from_string, get_nt_system_root, stricmp, atoi, ultow_s, bsearch, bsearch_s, isdigit, wcschr, clear_all_bits, set_bits, set_bit, test_bit, find_clear_bits, find_set_bits, find_set_bits_and_clear, are_bits_clear, are_bits_set, number_of_set_bits, number_of_clear_bits, interlocked_clear_bit_run, interlocked_set_bit_run, interlocked_set_clear_run, run_once_initialize, run_once_begin_initialize, run_once_complete, run_once_execute_once, valid_acl, valid_security_descriptor, valid_relative_security_descriptor,
    ],
    data_exports: &[],
};

pub mod capability_check {
    //! RtlCapabilityCheck.
    //!
    //! Falha interna interrompe o sistema; o sinal de transferência do CONTEXT
    //! continua propagando.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::se::capability::check as capability_check;

    fn check(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("capability-check", capability_check::check(call.arg(1), call.arg(2), call.arg(3)))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "capability-check",
        names: &["RtlCapabilityCheck"],
        handlers: &[check],
        data_exports: &[],
    };
}

pub mod check_registry_key {
    //! RtlCheckRegistryKey.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::cm::check_registry_key;

    fn check(call: &Call) -> Result<u64, KernelError> {
        Ok(check_registry_key::check(call.arg(1) as u32, call.arg(2))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "check-registry-key",
        names: &["RtlCheckRegistryKey"],
        handlers: &[check],
        data_exports: &[],
    };
}

pub mod exceptions {
    //! ExRaiseStatus, RtlRaiseStatus e RtlUnwindEx — `ntos/rtl/exceptions`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::exceptions;
    use crate::rtl::KernelError;

    fn raise_status(call: &Call) -> Result<u64, KernelError> {
        exceptions::raise_status(call.arg(1) as u32, 0, 0, 1)
    }

    fn unwind_ex(call: &Call) -> Result<u64, KernelError> {
        exceptions::unwind_ex(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6))
    }

    pub static GROUP: Group = Group { name: "exceptions", names: &["ExRaiseStatus", "RtlRaiseStatus", "RtlUnwindEx"], handlers: &[raise_status, raise_status, unwind_ex], data_exports: &[] };
}

pub mod feature_usage {
    //! RtlNotifyFeatureUsage.
    //!
    //! O IRQL efetivo do chamador e a falha fatal ficam em
    //! `rtl::feature_configuration`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::feature_configuration;
    use crate::rtl::KernelError;

    fn notify(call: &Call) -> Result<u64, KernelError> {
        Ok(feature_configuration::notify_usage(call.arg(1))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "feature-usage",
        names: &["RtlNotifyFeatureUsage"],
        handlers: &[notify],
        data_exports: &[],
    };
}

pub mod first_slist {
    //! FirstEntrySList.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ex::slist;

    fn first_entry_slist(call: &Call) -> Result<u64, KernelError> {
        Ok(slist::first(call.arg(1)))
    }

    pub static GROUP: Group = Group {
        name: "first-slist",
        names: &["FirstEntrySList"],
        handlers: &[first_entry_slist],
        data_exports: &[],
    };
}

pub mod package_claims {
    //! RtlQueryPackageClaims.
    //!
    //! Falha interna interrompe o sistema; o sinal de transferência do CONTEXT
    //! continua propagando.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::se::package_claims;

    fn query_package_claims(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("package-claims", package_claims::query(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7), call.arg(8)))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "package-claims",
        names: &["RtlQueryPackageClaims"],
        handlers: &[query_package_claims],
        data_exports: &[],
    };
}

pub mod package_identity {
    //! RtlQueryPackageIdentity.
    //!
    //! Falha interna interrompe o sistema; o sinal de transferência do CONTEXT
    //! continua propagando.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::se::package_identity;

    fn query_package_identity(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("package-identity", package_identity::query(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6)))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "package-identity",
        names: &["RtlQueryPackageIdentity"],
        handlers: &[query_package_identity],
        data_exports: &[],
    };
}

pub mod resource_lookup {
    //! LdrResFindResource.
    //!
    //! Export observado na IAT da CI; o adaptador não modifica recursos nem
    //! política.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::resource::find as find_resource;
    use crate::rtl::KernelError;

    fn find_resource_export(call: &Call) -> Result<u64, KernelError> {
        Ok(find_resource::find(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7), call.arg(8), call.arg(9))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "resource-lookup",
        names: &["LdrResFindResource"],
        handlers: &[find_resource_export],
        data_exports: &[],
    };
}

pub mod resource_search {
    //! LdrResSearchResource.
    //!
    //! Entrada contada observada na IAT da CI: compartilha o parser, os arquivos
    //! e os donos com LdrResFindResource, com os seus guardas próprios.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::resource::find as find_resource;
    use crate::rtl::KernelError;

    fn search_resource_export(call: &Call) -> Result<u64, KernelError> {
        Ok(find_resource::search(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7), call.arg(8))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "resource-search",
        names: &["LdrResSearchResource"],
        handlers: &[search_resource_export],
        data_exports: &[],
    };
}

pub mod state_separation {
    //! RtlIsStateSeparationEnabled.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::cm::state_separation;

    fn is_state_separation_enabled(_: &Call) -> Result<u64, KernelError> {
        Ok(state_separation::is_enabled()? as u64)
    }

    pub static GROUP: Group = Group {
        name: "state-separation",
        names: &["RtlIsStateSeparationEnabled"],
        handlers: &[is_state_separation_enabled],
        data_exports: &[],
    };
}

pub mod unwind {
    //! RtlLookupFunctionEntry e RtlVirtualUnwind — `ntos/rtl/unwind`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::unwind;
    use crate::rtl::KernelError;

    fn lookup_function_entry(call: &Call) -> Result<u64, KernelError> {
        unwind::lookup_function_entry(call.arg(1), call.arg(2), call.arg(3))
    }

    fn virtual_unwind(call: &Call) -> Result<u64, KernelError> {
        unwind::unwind(call.arg(1) as u32, call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7), call.arg(8))
    }

    pub static GROUP: Group = Group { name: "unwind", names: &["RtlLookupFunctionEntry", "RtlVirtualUnwind"], handlers: &[lookup_function_entry, virtual_unwind], data_exports: &[] };
}

pub mod generic_tables {
    //! Splay links, RTL_GENERIC_TABLE e RTL_AVL_TABLE (`ntos::rtl::{gentable,
    //! avltable}`), com as assinaturas do WDK.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::{avltable, gentable};
    use crate::rtl::KernelError;

    fn splay(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::splay(call.arg(1)))
    }
    fn delete(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::delete(call.arg(1)))
    }
    fn delete_no_splay(call: &Call) -> Result<u64, KernelError> {
        gentable::delete_no_splay(call.arg(1), call.arg(2));
        Ok(0)
    }
    fn subtree_successor(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::subtree_successor(call.arg(1)))
    }
    fn subtree_predecessor(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::subtree_predecessor(call.arg(1)))
    }
    fn real_successor(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::real_successor(call.arg(1)))
    }
    fn real_predecessor(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::real_predecessor(call.arg(1)))
    }

    pub static SPLAY_LINKS_GROUP: Group = Group {
        name: "splay-links",
        names: &["RtlSplay", "RtlDelete", "RtlDeleteNoSplay", "RtlSubtreeSuccessor", "RtlSubtreePredecessor", "RtlRealSuccessor", "RtlRealPredecessor"],
        handlers: &[splay, delete, delete_no_splay, subtree_successor, subtree_predecessor, real_successor, real_predecessor],
        data_exports: &[],
    };

    fn initialize(call: &Call) -> Result<u64, KernelError> {
        gentable::initialize(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5));
        Ok(0)
    }
    fn insert(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::insert(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4)))
    }
    fn insert_full(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::insert_full(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5), call.arg(6) as u32))
    }
    fn lookup(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::lookup(call.arg(1), call.arg(2)))
    }
    fn lookup_full(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::lookup_full(call.arg(1), call.arg(2), call.arg(3), call.arg(4)))
    }
    fn delete_element(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::delete_element(call.arg(1), call.arg(2)) as u64)
    }
    fn enumerate(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::enumerate(call.arg(1), call.arg(2) & 0xFF != 0))
    }
    fn enumerate_without_splaying(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::enumerate_without_splaying(call.arg(1), call.arg(2)))
    }
    fn get_element(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::get_element(call.arg(1), call.arg(2) as u32))
    }
    fn number(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::number(call.arg(1)) as u64)
    }
    fn is_empty(call: &Call) -> Result<u64, KernelError> {
        Ok(gentable::is_empty(call.arg(1)) as u64)
    }

    pub static GENERIC_TABLES_GROUP: Group = Group {
        name: "generic-tables",
        names: &[
            "RtlInitializeGenericTable", "RtlInsertElementGenericTable", "RtlInsertElementGenericTableFull", "RtlLookupElementGenericTable",
            "RtlLookupElementGenericTableFull", "RtlDeleteElementGenericTable", "RtlEnumerateGenericTable", "RtlEnumerateGenericTableWithoutSplaying",
            "RtlGetElementGenericTable", "RtlNumberGenericTableElements", "RtlIsGenericTableEmpty",
        ],
        handlers: &[initialize, insert, insert_full, lookup, lookup_full, delete_element, enumerate, enumerate_without_splaying, get_element, number, is_empty],
        data_exports: &[],
    };

    fn initialize_avl(call: &Call) -> Result<u64, KernelError> {
        avltable::initialize(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5));
        Ok(0)
    }
    fn insert_avl(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::insert(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4)))
    }
    fn insert_full_avl(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::insert_full(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5), call.arg(6) as u32))
    }
    fn lookup_avl(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::lookup(call.arg(1), call.arg(2)))
    }
    fn lookup_full_avl(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::lookup_full(call.arg(1), call.arg(2), call.arg(3), call.arg(4)))
    }
    fn delete_avl(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::delete(call.arg(1), call.arg(2)) as u64)
    }
    fn delete_avl_ex(call: &Call) -> Result<u64, KernelError> {
        avltable::delete_node(call.arg(1), call.arg(2));
        Ok(0)
    }
    fn enumerate_avl(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::enumerate(call.arg(1), call.arg(2) & 0xFF != 0))
    }
    fn enumerate_without_splaying_avl(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::enumerate_without_splaying(call.arg(1), call.arg(2)))
    }
    fn get_element_avl(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::get_element(call.arg(1), call.arg(2) as u32))
    }
    fn number_avl(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::number(call.arg(1)) as u64)
    }
    fn is_empty_avl(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::is_empty(call.arg(1)) as u64)
    }
    fn lookup_first_matching_avl(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::lookup_first_matching(call.arg(1), call.arg(2), call.arg(3)))
    }
    fn enumerate_like_a_directory(call: &Call) -> Result<u64, KernelError> {
        Ok(avltable::enumerate_like_a_directory(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32 != 0, call.arg(5), call.arg(6), call.arg(7)))
    }

    pub static AVL_TABLES_GROUP: Group = Group {
        name: "avl-tables",
        names: &[
            "RtlInitializeGenericTableAvl", "RtlInsertElementGenericTableAvl", "RtlInsertElementGenericTableFullAvl", "RtlLookupElementGenericTableAvl",
            "RtlLookupElementGenericTableFullAvl", "RtlDeleteElementGenericTableAvl", "RtlDeleteElementGenericTableAvlEx", "RtlEnumerateGenericTableAvl",
            "RtlEnumerateGenericTableWithoutSplayingAvl", "RtlGetElementGenericTableAvl", "RtlNumberGenericTableElementsAvl", "RtlIsGenericTableEmptyAvl",
            "RtlLookupFirstMatchingElementGenericTableAvl", "RtlEnumerateGenericTableLikeADirectory",
        ],
        handlers: &[
            initialize_avl, insert_avl, insert_full_avl, lookup_avl, lookup_full_avl, delete_avl, delete_avl_ex, enumerate_avl,
            enumerate_without_splaying_avl, get_element_avl, number_avl, is_empty_avl, lookup_first_matching_avl, enumerate_like_a_directory,
        ],
        data_exports: &[],
    };
}

pub mod rtl_security {
    //! Descritores de segurança, ACLs e SIDs do Rtl — delegam ao componente
    //! `se`, com as assinaturas e os NTSTATUS do WDK.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::{acl, descriptor, sid};
    use crate::rtl::KernelError;

    fn create_security_descriptor(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(descriptor::create(call.arg(1), call.arg(2) as u32)))
    }
    fn set_dacl(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(descriptor::set_dacl(call.arg(1), call.arg(2) & 0xFF != 0, call.arg(3), call.arg(4) & 0xFF != 0)))
    }
    fn set_sacl(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(descriptor::set_sacl(call.arg(1), call.arg(2) & 0xFF != 0, call.arg(3), call.arg(4) & 0xFF != 0)))
    }
    fn set_owner(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(descriptor::set_owner(call.arg(1), call.arg(2), call.arg(3) & 0xFF != 0)))
    }
    fn create_acl(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(acl::create(call.arg(1), call.arg(2) as u32, call.arg(3) as u32)))
    }
    fn add_access_allowed_ace(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(acl::add_known_ace(call.arg(1), call.arg(2) as u32, 0, call.arg(3) as u32, call.arg(4), 0)))
    }
    fn add_access_allowed_ace_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(acl::add_known_ace(call.arg(1), call.arg(2) as u32, call.arg(3) as u32, call.arg(4) as u32, call.arg(5), 0)))
    }
    fn initialize_sid(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(sid::initialize(call.arg(1), call.arg(2), call.arg(3) as u32)))
    }
    fn sub_authority_sid(call: &Call) -> Result<u64, KernelError> {
        Ok(sid::sub_authority(call.arg(1), call.arg(2)))
    }
    fn length_required_sid(call: &Call) -> Result<u64, KernelError> {
        Ok(sid::length_required(call.arg(1) as u32) as u64)
    }

    pub static GROUP: Group = Group {
        name: "rtl-security",
        names: &[
            "RtlCreateSecurityDescriptor", "RtlSetDaclSecurityDescriptor", "RtlSetSaclSecurityDescriptor",
            "RtlSetOwnerSecurityDescriptor", "RtlCreateAcl", "RtlAddAccessAllowedAce", "RtlAddAccessAllowedAceEx",
            "RtlInitializeSid", "RtlSubAuthoritySid", "RtlLengthRequiredSid",
        ],
        handlers: &[
            create_security_descriptor, set_dacl, set_sacl, set_owner, create_acl, add_access_allowed_ace,
            add_access_allowed_ace_ex, initialize_sid, sub_authority_sid, length_required_sid,
        ],
        data_exports: &[],
    };
}

pub mod rtl_crt_extended {
    //! Rtl + CRT complementares importados pelos drivers.
    //!
    //! Os 19 Rtl delegam a `rtl::{security, nls_translation, strings_counted,
    //! integer_conversion, unicode, registry, version, image, stack_trace,
    //! guid}`; os 7 da CRT a `rtl::{crt, printf, math}`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::rtl::{
        crt, guid, image, integer_conversion, math, nls_translation, printf, registry, security, stack_trace, strings_counted, unicode,
        version,
    };
    use crate::rtl::KernelError;

    // ---- Rtl — segurança (descritores, ACLs, SIDs) ---------------------------

    fn map_generic_mask(call: &Call) -> Result<u64, KernelError> {
        security::map_generic_mask(call.arg(1), call.arg(2));
        Ok(0)
    }
    fn add_ace(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(security::add_ace(call.arg(1), call.arg(2) as u32, call.arg(3) as u32, call.arg(4), call.arg(5) as u32)))
    }
    fn get_sacl_security_descriptor(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(security::get_sacl(call.arg(1), call.arg(2), call.arg(3), call.arg(4))))
    }
    fn get_group_security_descriptor(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(security::get_group(call.arg(1), call.arg(2), call.arg(3))))
    }
    fn set_group_security_descriptor(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(security::set_group(call.arg(1), call.arg(2), call.arg(3) & 0xFF != 0)))
    }
    fn sub_authority_count_sid(call: &Call) -> Result<u64, KernelError> {
        Ok(security::sub_authority_count(call.arg(1)))
    }
    fn copy_luid(call: &Call) -> Result<u64, KernelError> {
        security::copy_luid(call.arg(1), call.arg(2));
        Ok(0)
    }

    // ---- Rtl — strings / NLS / números ---------------------------------------

    fn ansi_char_to_unicode_char(call: &Call) -> Result<u64, KernelError> {
        Ok(nls_translation::ansi_char_to_unicode_char(call.arg(1)) as u64)
    }
    fn append_string_to_string(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(strings_counted::append_string(call.arg(1), call.arg(2))))
    }
    fn int64_to_unicode_string(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(integer_conversion::int64_to_unicode_string(call.arg(1), call.arg(2) as u32, call.arg(3))))
    }
    fn hash_unicode_string(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(unicode::hash(call.arg(1), call.arg(2) & 0xFF != 0, call.arg(3) as u32, call.arg(4))))
    }
    fn format_current_user_key_path(call: &Call) -> Result<u64, KernelError> {
        registry::format_current_user_key_path(call.arg(1));
        Ok(0)
    }

    // ---- Rtl — informação do sistema (KUSER_SHARED_DATA / produto) ----------

    fn get_nt_product_type(call: &Call) -> Result<u64, KernelError> {
        Ok(version::nt_product_type(call.arg(1)) as u64)
    }
    fn get_suite_mask(_: &Call) -> Result<u64, KernelError> {
        Ok(version::suite_mask() as u64)
    }
    fn is_multi_session_sku(_: &Call) -> Result<u64, KernelError> {
        Ok(version::is_multi_session_sku() as u64)
    }
    fn get_product_info(call: &Call) -> Result<u64, KernelError> {
        Ok(version::product_info(call.arg(5)) as u64)
    }

    // ---- Rtl — imagens / backtrace / GUID ------------------------------------

    fn find_exported_routine_by_name(call: &Call) -> Result<u64, KernelError> {
        Ok(image::find_exported_routine_by_name(call.arg(1), call.arg(2)))
    }
    fn capture_stack_back_trace(call: &Call) -> Result<u64, KernelError> {
        Ok(stack_trace::capture_back_trace(call.frame, call.arg(1) as usize, call.arg(2) as usize, call.arg(3), call.arg(4)))
    }
    fn generate_class5_guid(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(guid::generate_class5(call.arg(1), call.arg(2), call.arg(3) as usize, call.arg(4))))
    }

    // ---- CRT (C runtime exportada pelo ntoskrnl) ------------------------------

    fn wcsnlen(call: &Call) -> Result<u64, KernelError> {
        Ok(crt::wcsnlen(call.arg(1), call.arg(2)))
    }
    fn wcsrchr(call: &Call) -> Result<u64, KernelError> {
        Ok(crt::wcsrchr(call.arg(1), call.arg(2) as u16))
    }
    fn wcsncpy_s(call: &Call) -> Result<u64, KernelError> {
        Ok(crt::wcsncpy_s(call.arg(1), call.arg(2), call.arg(3), call.arg(4)))
    }
    fn snwprintf(call: &Call) -> Result<u64, KernelError> {
        printf::snwprintf(call.arg(1), call.arg(2), call.arg(3), &[call.arg(4), call.arg(5), call.arg(6), call.arg(7), call.arg(8), call.arg(9)])
    }
    fn wcslwr(call: &Call) -> Result<u64, KernelError> {
        Ok(crt::wcslwr(call.arg(1)))
    }
    /// sqrt(double): argumento e resultado em XMM0, pelo CONTEXT capturado.
    fn sqrt(call: &Call) -> Result<u64, KernelError> {
        math::sqrt_in_context(call.context);
        Ok(0)
    }
    fn purecall(_: &Call) -> Result<u64, KernelError> {
        crt::purecall()
    }

    // ---- GROUP ------------------------------------------------------------

    pub static GROUP: Group = Group {
        name: "rtl-crt-extended",
        names: &[
            // --- Rtl (19) ---
            "RtlMapGenericMask",
            "RtlCaptureStackBackTrace",
            "RtlAddAce",
            "RtlAnsiCharToUnicodeChar",
            "RtlAppendStringToString",
            "RtlCopyLuid",
            "RtlFindExportedRoutineByName",
            "RtlFormatCurrentUserKeyPath",
            "RtlGenerateClass5Guid",
            "RtlGetGroupSecurityDescriptor",
            "RtlGetNtProductType",
            "RtlGetProductInfo",
            "RtlGetSaclSecurityDescriptor",
            "RtlGetSuiteMask",
            "RtlHashUnicodeString",
            "RtlInt64ToUnicodeString",
            "RtlIsMultiSessionSku",
            "RtlSetGroupSecurityDescriptor",
            "RtlSubAuthorityCountSid",
            // --- CRT (7) ---
            "_purecall",
            "_snwprintf",
            "_wcslwr",
            "sqrt",
            "wcsncpy_s",
            "wcsnlen",
            "wcsrchr",
        ],
        handlers: &[
            // --- Rtl (19) ---
            map_generic_mask,
            capture_stack_back_trace,
            add_ace,
            ansi_char_to_unicode_char,
            append_string_to_string,
            copy_luid,
            find_exported_routine_by_name,
            format_current_user_key_path,
            generate_class5_guid,
            get_group_security_descriptor,
            get_nt_product_type,
            get_product_info,
            get_sacl_security_descriptor,
            get_suite_mask,
            hash_unicode_string,
            int64_to_unicode_string,
            is_multi_session_sku,
            set_group_security_descriptor,
            sub_authority_count_sid,
            // --- CRT (7) ---
            purecall,
            snwprintf,
            wcslwr,
            sqrt,
            wcsncpy_s,
            wcsnlen,
            wcsrchr,
        ],
        data_exports: &[],
    };
}

// ===========================================================================
