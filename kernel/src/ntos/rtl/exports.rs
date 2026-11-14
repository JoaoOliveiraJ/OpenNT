//! Exports Rtl*, Interlocked* e da CRT do ntoskrnl.
//!
//! Semântica do NT sobre a memória do convidado. Os campos Buffer das
//! UNICODE/ANSI_STRING são lidos e escritos com 64 bits.
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
    Ok(interlocked::increment(call.arg(1))? as u64)
}
fn interlocked_decrement(call: &Call) -> Result<u64, KernelError> {
    Ok(interlocked::decrement(call.arg(1))? as u64)
}
fn interlocked_exchange(call: &Call) -> Result<u64, KernelError> {
    Ok(interlocked::exchange(call.arg(1), call.arg(2) as u32)? as u64)
}
fn interlocked_compare_exchange(call: &Call) -> Result<u64, KernelError> {
    Ok(interlocked::compare_exchange(call.arg(1), call.arg(2) as u32, call.arg(3) as u32)? as u64)
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
    interlocked::push_entry_list(call.arg(1), call.arg(2))
}
fn interlocked_pop_entry_list(call: &Call) -> Result<u64, KernelError> {
    interlocked::pop_entry_list(call.arg(1))
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

pub mod rtl_hash_tables {
    //! RTL_DYNAMIC_HASH_TABLE: adaptadores de `rtl::hash_table`. As variantes
    //! Weak usam os mesmos handlers da enumeração normal (no ntoskrnl elas só
    //! encaminham).

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::hash_table;
    use crate::rtl::KernelError;

    fn create_hash_table(call: &Call) -> Result<u64, KernelError> {
        Ok(hash_table::create(call.arg(1), call.arg(2) as u32, call.arg(3) as u32)? as u64)
    }
    fn create_hash_table_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(hash_table::create_ex(call.arg(1), call.arg(2) as u32, call.arg(3) as u32, call.arg(4) as u32)? as u64)
    }
    fn delete_hash_table(call: &Call) -> Result<u64, KernelError> {
        hash_table::delete(call.arg(1))?;
        Ok(0)
    }
    fn insert_entry(call: &Call) -> Result<u64, KernelError> {
        Ok(hash_table::insert(call.arg(1), call.arg(2), call.arg(3), call.arg(4)) as u64)
    }
    fn remove_entry(call: &Call) -> Result<u64, KernelError> {
        Ok(hash_table::remove(call.arg(1), call.arg(2), call.arg(3)) as u64)
    }
    fn lookup_entry(call: &Call) -> Result<u64, KernelError> {
        Ok(hash_table::lookup(call.arg(1), call.arg(2), call.arg(3)))
    }
    fn get_next_entry(call: &Call) -> Result<u64, KernelError> {
        Ok(hash_table::get_next(call.arg(1), call.arg(2)))
    }
    fn init_enumeration(call: &Call) -> Result<u64, KernelError> {
        Ok(hash_table::init_enumeration(call.arg(1), call.arg(2)) as u64)
    }
    fn enumerate_entry(call: &Call) -> Result<u64, KernelError> {
        Ok(hash_table::enumerate(call.arg(1), call.arg(2)))
    }
    fn end_enumeration(call: &Call) -> Result<u64, KernelError> {
        hash_table::end_enumeration(call.arg(1), call.arg(2));
        Ok(0)
    }
    fn init_strong_enumeration(call: &Call) -> Result<u64, KernelError> {
        Ok(hash_table::init_strong_enumeration(call.arg(1), call.arg(2)) as u64)
    }
    fn strongly_enumerate_entry(call: &Call) -> Result<u64, KernelError> {
        Ok(hash_table::strongly_enumerate(call.arg(1), call.arg(2)))
    }
    fn end_strong_enumeration(call: &Call) -> Result<u64, KernelError> {
        hash_table::end_strong_enumeration(call.arg(1), call.arg(2));
        Ok(0)
    }
    fn expand_hash_table(call: &Call) -> Result<u64, KernelError> {
        Ok(hash_table::expand(call.arg(1))? as u64)
    }
    fn contract_hash_table(call: &Call) -> Result<u64, KernelError> {
        Ok(hash_table::contract(call.arg(1))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "rtl-hash-tables",
        names: &[
            "RtlCreateHashTable",
            "RtlCreateHashTableEx",
            "RtlDeleteHashTable",
            "RtlInsertEntryHashTable",
            "RtlRemoveEntryHashTable",
            "RtlLookupEntryHashTable",
            "RtlGetNextEntryHashTable",
            "RtlInitEnumerationHashTable",
            "RtlEnumerateEntryHashTable",
            "RtlEndEnumerationHashTable",
            "RtlInitWeakEnumerationHashTable",
            "RtlWeaklyEnumerateEntryHashTable",
            "RtlEndWeakEnumerationHashTable",
            "RtlInitStrongEnumerationHashTable",
            "RtlStronglyEnumerateEntryHashTable",
            "RtlEndStrongEnumerationHashTable",
            "RtlExpandHashTable",
            "RtlContractHashTable",
        ],
        handlers: &[
            create_hash_table,
            create_hash_table_ex,
            delete_hash_table,
            insert_entry,
            remove_entry,
            lookup_entry,
            get_next_entry,
            init_enumeration,
            enumerate_entry,
            end_enumeration,
            init_enumeration,
            enumerate_entry,
            end_enumeration,
            init_strong_enumeration,
            strongly_enumerate_entry,
            end_strong_enumeration,
            expand_hash_table,
            contract_hash_table,
        ],
        data_exports: &[],
    };
}

pub mod rtl_strings {
    //! Strings contadas, texto de inteiros/SIDs e Unicode -> ANSI: adaptadores
    //! de `rtl::{unicode, strings_counted, integer_conversion, security,
    //! nls_translation}`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::rtl::{integer_conversion, nls_translation, security, strings_counted, unicode};
    use crate::rtl::KernelError;

    fn init_unicode_string_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(unicode::init_ex(call.arg(1), call.arg(2))))
    }
    fn free_oem_string(call: &Call) -> Result<u64, KernelError> {
        strings_counted::free_oem_string(call.arg(1))?;
        Ok(0)
    }
    fn compare_string(call: &Call) -> Result<u64, KernelError> {
        Ok(strings_counted::compare_ansi(call.arg(1), call.arg(2), call.arg(3) & 0xFF != 0) as i64 as u64)
    }
    fn prefix_string(call: &Call) -> Result<u64, KernelError> {
        Ok(strings_counted::prefix_ansi(call.arg(1), call.arg(2), call.arg(3) & 0xFF != 0) as u64)
    }
    fn char_to_integer(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(integer_conversion::char_to_integer(call.arg(1), call.arg(2) as u32, call.arg(3))))
    }
    fn integer_to_unicode(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(integer_conversion::integer_to_unicode(call.arg(1) as u32, call.arg(2) as u32, call.arg(3) as u32 as i32, call.arg(4))))
    }
    fn convert_sid_to_unicode_string(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(security::convert_sid_to_unicode_string(call.arg(1), call.arg(2), call.arg(3) & 0xFF != 0)?))
    }
    fn unicode_to_multi_byte_n(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(nls_translation::unicode_to_multi_byte_n(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4), call.arg(5) as u32)?))
    }
    fn unicode_to_multi_byte_size(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(nls_translation::unicode_to_multi_byte_size(call.arg(1), call.arg(2), call.arg(3) as u32)?))
    }

    pub static GROUP: Group = Group {
        name: "rtl-strings",
        names: &[
            "RtlInitUnicodeStringEx",
            "RtlFreeOemString",
            "RtlCompareString",
            "RtlPrefixString",
            "RtlCharToInteger",
            "RtlIntegerToUnicode",
            "RtlConvertSidToUnicodeString",
            "RtlUnicodeToMultiByteN",
            "RtlUnicodeToMultiByteSize",
        ],
        handlers: &[
            init_unicode_string_ex,
            free_oem_string,
            compare_string,
            prefix_string,
            char_to_integer,
            integer_to_unicode,
            convert_sid_to_unicode_string,
            unicode_to_multi_byte_n,
            unicode_to_multi_byte_size,
        ],
        data_exports: &[],
    };
}

pub mod rtl_bit_ops {
    //! Bits do Rtl: adaptadores de `rtl::bitmap` e `rtl::checksum`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::{bitmap, checksum};
    use crate::rtl::KernelError;

    fn find_next_forward_run_clear(call: &Call) -> Result<u64, KernelError> {
        Ok(bitmap::find_next_forward_run_clear(call.arg(1), call.arg(2) as u32, call.arg(3)) as u64)
    }
    fn number_of_set_bits_ulong_ptr(call: &Call) -> Result<u64, KernelError> {
        Ok(bitmap::number_of_set_bits_ulong_ptr(call.arg(1)) as u64)
    }
    /// CCHAR em EAX: -1 sai como 0xFFFFFFFF, como no original.
    fn find_most_significant_bit(call: &Call) -> Result<u64, KernelError> {
        Ok(bitmap::find_most_significant_bit(call.arg(1)) as i32 as u32 as u64)
    }
    fn compute_crc32(call: &Call) -> Result<u64, KernelError> {
        Ok(checksum::compute_crc32(call.arg(1) as u32, call.arg(2), call.arg(3) as u32) as u64)
    }

    pub static GROUP: Group = Group {
        name: "rtl-bit-ops",
        names: &["RtlFindNextForwardRunClear", "RtlNumberOfSetBitsUlongPtr", "RtlFindMostSignificantBit", "RtlComputeCrc32"],
        handlers: &[find_next_forward_run_clear, number_of_set_bits_ulong_ptr, find_most_significant_bit, compute_crc32],
        data_exports: &[],
    };
}

pub mod crt_strings {
    //! CRT do ntoskrnl: adaptadores de `rtl::crt`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::crt;
    use crate::rtl::KernelError;

    fn memcpy_s(call: &Call) -> Result<u64, KernelError> {
        Ok(crt::memcpy_s(call.arg(1), call.arg(2), call.arg(3), call.arg(4)) as u64)
    }
    fn strrchr(call: &Call) -> Result<u64, KernelError> {
        Ok(crt::strrchr(call.arg(1), call.arg(2) as u8))
    }
    fn wcsspn(call: &Call) -> Result<u64, KernelError> {
        Ok(crt::wcsspn(call.arg(1), call.arg(2)))
    }
    fn wcscspn(call: &Call) -> Result<u64, KernelError> {
        Ok(crt::wcscspn(call.arg(1), call.arg(2)))
    }
    fn wcstoul(call: &Call) -> Result<u64, KernelError> {
        Ok(crt::wcstoul(call.arg(1), call.arg(2), call.arg(3) as u32) as u64)
    }
    fn isspace(call: &Call) -> Result<u64, KernelError> {
        Ok(crt::isspace(call.arg(1) as u32) as u64)
    }
    fn tolower(call: &Call) -> Result<u64, KernelError> {
        Ok(crt::tolower(call.arg(1) as u32) as i64 as u64)
    }
    fn toupper(call: &Call) -> Result<u64, KernelError> {
        Ok(crt::toupper(call.arg(1) as u32)? as i64 as u64)
    }
    fn iswdigit(call: &Call) -> Result<u64, KernelError> {
        Ok(crt::iswdigit(call.arg(1) as u16) as u64)
    }

    pub static GROUP: Group = Group {
        name: "crt-strings",
        names: &["memcpy_s", "strrchr", "wcsspn", "wcscspn", "wcstoul", "isspace", "tolower", "toupper", "iswdigit"],
        handlers: &[memcpy_s, strrchr, wcsspn, wcscspn, wcstoul, isspace, tolower, toupper, iswdigit],
        data_exports: &[],
    };
}

pub mod crt_formatting {
    //! sprintf_s/vsprintf_s: adaptadores de `rtl::printf`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::printf;
    use crate::rtl::KernelError;

    fn vsprintf_s(call: &Call) -> Result<u64, KernelError> {
        printf::vsprintf_s(call.arg(1), call.arg(2), call.arg(3), call.arg(4))
    }
    /// Variádicos: do quarto argumento em diante.
    fn sprintf_s(call: &Call) -> Result<u64, KernelError> {
        printf::sprintf_s(call.arg(1), call.arg(2), call.arg(3), &call.args[3..])
    }

    pub static GROUP: Group = Group {
        name: "crt-formatting",
        names: &["vsprintf_s", "sprintf_s"],
        handlers: &[vsprintf_s, sprintf_s],
        data_exports: &[],
    };
}

pub mod rtl_bitmap_ex {
    //! Adaptadores dos bitmaps de 64 bits (lógica em `rtl/bitmap.rs`).

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::inc::types::{NtStruct, RtlBitmapEx};
    use crate::ntos::rtl::bitmap;
    use crate::rtl::KernelError;

    /// PRTL_BITMAP_EX do chamador.
    fn header(address: u64) -> &'static RtlBitmapEx {
        // SAFETY: o export recebe um RTL_BITMAP_EX vivo e alinhado, como no NT.
        unsafe { RtlBitmapEx::at(address) }
    }

    fn initialize_bitmap_ex(call: &Call) -> Result<u64, KernelError> {
        bitmap::initialize_ex(header(call.arg(1)), call.arg(2), call.arg(3));
        Ok(0)
    }

    fn set_bit_ex(call: &Call) -> Result<u64, KernelError> {
        bitmap::set_bit_ex(header(call.arg(1)), call.arg(2));
        Ok(0)
    }

    fn clear_bit_ex(call: &Call) -> Result<u64, KernelError> {
        bitmap::clear_bit_ex(header(call.arg(1)), call.arg(2));
        Ok(0)
    }

    fn test_bit_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(bitmap::test_bit_ex(header(call.arg(1)), call.arg(2)) as u64)
    }

    fn find_clear_bits_and_set_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(bitmap::find_clear_bits_and_set_ex(header(call.arg(1)), call.arg(2), call.arg(3)))
    }

    pub static GROUP: Group = Group {
        name: "rtl-bitmap-ex",
        names: &["RtlInitializeBitMapEx", "RtlSetBitEx", "RtlClearBitEx", "RtlTestBitEx", "RtlFindClearBitsAndSetEx"],
        handlers: &[initialize_bitmap_ex, set_bit_ex, clear_bit_ex, test_bit_ex, find_clear_bits_and_set_ex],
        data_exports: &[],
    };
}

pub mod rtl_self_relative_sd {
    //! Adaptador de RtlSelfRelativeToAbsoluteSD (lógica em `se/descriptor.rs`).

    use crate::ntos::inc::types::{Field, NtStruct, SecurityDescriptor};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::descriptor::{self, AbsoluteBuffers};
    use crate::rtl::KernelError;

    /// PULONG in/out do chamador.
    fn size(address: u64) -> &'static Field<u32> {
        // SAFETY: os cinco PULONG de capacidade são obrigatórios no NT.
        unsafe { Field::<u32>::at(address) }
    }

    /// (SelfRelativeSD, AbsoluteSD, AbsoluteSDSize, Dacl, DaclSize, Sacl,
    /// SaclSize, Owner, OwnerSize, PrimaryGroup, PrimaryGroupSize).
    fn self_relative_to_absolute_sd(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: buffer do SD absoluto do chamador (NULL = só consulta tamanhos).
        let absolute = (call.arg(2) != 0).then(|| unsafe { SecurityDescriptor::at(call.arg(2)) });
        let buffers = AbsoluteBuffers {
            descriptor: absolute,
            descriptor_size: size(call.arg(3)),
            dacl: call.arg(4),
            dacl_size: size(call.arg(5)),
            sacl: call.arg(6),
            sacl_size: size(call.arg(7)),
            owner: call.arg(8),
            owner_size: size(call.arg(9)),
            group: call.arg(10),
            group_size: size(call.arg(11)),
        };
        Ok(signed_status(descriptor::self_relative_to_absolute(call.arg(1), &buffers)))
    }

    pub static GROUP: Group = Group {
        name: "rtl-self-relative-sd",
        names: &["RtlSelfRelativeToAbsoluteSD"],
        handlers: &[self_relative_to_absolute_sd],
        data_exports: &[],
    };
}

pub mod rtl_network_address {
    //! Adaptadores de RtlIpv{4,6}StringToAddressW e RtlIpv{4,6}AddressToString{,Ex}W
    //! (lógica em `rtl/network_address.rs`).

    use crate::ntos::inc::types::{Field, NtStruct};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::rtl::network_address;
    use crate::rtl::KernelError;

    /// Célula de saída do chamador (PWSTR*, IN_ADDR, PULONG): memória do
    /// kernel ou de drivers, como no NT.
    fn cell<T: Copy>(address: u64) -> &'static Field<T> {
        // SAFETY: ponteiro de saída vivo e alinhado do chamador.
        unsafe { Field::<T>::at(address) }
    }

    /// (S, Strict BOOLEAN, Terminator, Addr).
    fn ipv4_string_to_address(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(network_address::ipv4_string_to_address(call.arg(1), call.arg(2) & 0xFF != 0, cell(call.arg(3)), cell(call.arg(4)))))
    }

    /// (S, Terminator, Addr).
    fn ipv6_string_to_address(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(network_address::ipv6_string_to_address(call.arg(1), cell(call.arg(2)), call.arg(3))))
    }

    /// (Addr, S) -> fim da string.
    fn ipv4_address_to_string(call: &Call) -> Result<u64, KernelError> {
        Ok(network_address::ipv4_address_to_string(call.arg(1), call.arg(2)))
    }

    /// (Addr, Port, Buffer, Length); Length NULL é recusado pela rotina.
    fn ipv4_address_to_string_ex(call: &Call) -> Result<u64, KernelError> {
        let length = (call.arg(4) != 0).then(|| cell::<u32>(call.arg(4)));
        Ok(signed_status(network_address::ipv4_address_to_string_ex(call.arg(1), call.arg(2) as u16, call.arg(3), length)))
    }

    /// (Addr, S) -> fim da string.
    fn ipv6_address_to_string(call: &Call) -> Result<u64, KernelError> {
        Ok(network_address::ipv6_address_to_string(call.arg(1), call.arg(2)))
    }

    /// (Addr, ScopeId, Port, Buffer, Length).
    fn ipv6_address_to_string_ex(call: &Call) -> Result<u64, KernelError> {
        let length = (call.arg(5) != 0).then(|| cell::<u32>(call.arg(5)));
        Ok(signed_status(network_address::ipv6_address_to_string_ex(call.arg(1), call.arg(2) as u32, call.arg(3) as u16, call.arg(4), length)))
    }

    pub static GROUP: Group = Group {
        name: "rtl-network-address",
        names: &[
            "RtlIpv4StringToAddressW", "RtlIpv6StringToAddressW", "RtlIpv4AddressToStringW",
            "RtlIpv4AddressToStringExW", "RtlIpv6AddressToStringW", "RtlIpv6AddressToStringExW",
        ],
        handlers: &[ipv4_string_to_address, ipv6_string_to_address, ipv4_address_to_string, ipv4_address_to_string_ex, ipv6_address_to_string, ipv6_address_to_string_ex],
        data_exports: &[],
    };
}

pub mod rtl_crt_wide {
    //! Adaptadores de _wtoi/towlower/RtlPrefetchMemoryNonTemporal (lógica em
    //! `rtl/crt.rs`).

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::crt;
    use crate::rtl::KernelError;

    /// int em eax (sinal estendido para o registrador inteiro).
    fn wtoi(call: &Call) -> Result<u64, KernelError> {
        Ok(crt::wtoi(call.arg(1)) as i64 as u64)
    }

    /// wint_t em ax.
    fn towlower(call: &Call) -> Result<u64, KernelError> {
        Ok(crt::towlower(call.arg(1) as u16) as u64)
    }

    fn prefetch_memory_non_temporal(call: &Call) -> Result<u64, KernelError> {
        crt::prefetch_memory_non_temporal(call.arg(1), call.arg(2));
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "rtl-crt-wide",
        names: &["_wtoi", "towlower", "RtlPrefetchMemoryNonTemporal"],
        handlers: &[wtoi, towlower, prefetch_memory_non_temporal],
        data_exports: &[],
    };
}

pub mod rtl_bitmap_ranges {
    //! Adaptadores das contagens por faixa, extração e runs livres do RTL_BITMAP.

    use crate::ntos::inc::types::{NtStruct, RtlBitmap};
    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::bitmap;
    use crate::rtl::KernelError;

    /// PRTL_BITMAP do chamador.
    fn bitmap_at(address: u64) -> &'static RtlBitmap {
        // SAFETY: cabeçalho RTL_BITMAP vivo e alinhado do chamador.
        unsafe { RtlBitmap::at(address) }
    }

    /// RtlNumberOfSetBitsInRange(BitMap, StartingIndex, Length) -> ULONG.
    fn number_set_in_range(call: &Call) -> Result<u64, KernelError> {
        Ok(bitmap::number_set_in_range(bitmap_at(call.arg(1)), call.arg(2) as u32, call.arg(3) as u32) as u64)
    }

    /// RtlNumberOfClearBitsInRange(BitMap, StartingIndex, Length) -> ULONG.
    fn number_clear_in_range(call: &Call) -> Result<u64, KernelError> {
        Ok(bitmap::number_clear_in_range(bitmap_at(call.arg(1)), call.arg(2) as u32, call.arg(3) as u32) as u64)
    }

    /// RtlExtractBitMap(Source, Destination, TargetBit, NumberOfBits).
    fn extract(call: &Call) -> Result<u64, KernelError> {
        bitmap::extract(bitmap_at(call.arg(1)), bitmap_at(call.arg(2)), call.arg(3) as u32, call.arg(4) as u32);
        Ok(0)
    }

    /// RtlFindClearRuns(BitMap, RunArray, SizeOfRunArray, LocateLongestRuns) -> ULONG.
    fn find_clear_runs(call: &Call) -> Result<u64, KernelError> {
        Ok(bitmap::find_clear_runs(bitmap_at(call.arg(1)), call.arg(2), call.arg(3) as u32, call.arg(4) as u8 != 0) as u64)
    }

    pub static GROUP: Group = Group {
        name: "rtl-bitmap-ranges",
        names: &["RtlNumberOfSetBitsInRange", "RtlNumberOfClearBitsInRange", "RtlExtractBitMap", "RtlFindClearRuns"],
        handlers: &[number_set_in_range, number_clear_in_range, extract, find_clear_runs],
        data_exports: &[],
    };
}

pub mod rtl_compression {
    //! Adaptadores da compressão do Rtl: argumentos do `Call` → `rtl::compression`.

    use crate::ntos::inc::types::{Field, NtStruct};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::rtl::compression;
    use crate::rtl::KernelError;

    /// PULONG de saída do chamador.
    fn out(address: u64) -> &'static Field<u32> {
        // SAFETY: parâmetro de saída obrigatório (kernel/driver), vivo e alinhado.
        unsafe { Field::<u32>::at(address) }
    }

    /// RtlGetCompressionWorkSpaceSize(FormatAndEngine, *BufferSize, *FragmentSize).
    fn work_space_size(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(compression::work_space_size(call.arg(1) as u16, out(call.arg(2)), out(call.arg(3)))))
    }

    /// RtlCompressBuffer(FormatAndEngine, Uncompressed, UncompressedSize,
    /// Compressed, CompressedSize, UncompressedChunkSize, *FinalSize, WorkSpace).
    fn compress_buffer(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(compression::compress_buffer(call.arg(1) as u16, call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5) as u32, out(call.arg(7)), call.arg(8))))
    }

    /// RtlDecompressBufferEx2(Format, Uncompressed, UncompressedSize, Compressed,
    /// CompressedSize, UncompressedChunkSize, *FinalSize, WorkSpace).
    fn decompress_buffer(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(compression::decompress_buffer(call.arg(1) as u16, call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5) as u32, call.arg(6) as u32, out(call.arg(7)), call.arg(8))))
    }

    /// RtlDecompressFragmentEx(Format, Fragment, FragmentSize, Compressed,
    /// CompressedSize, FragmentOffset, UncompressedChunkSize, *FinalSize, WorkSpace).
    fn decompress_fragment(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(compression::decompress_fragment(call.arg(1) as u16, call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5) as u32, call.arg(6) as u32, call.arg(7) as u32, out(call.arg(8)), call.arg(9))))
    }

    pub static GROUP: Group = Group {
        name: "rtl-compression",
        names: &["RtlGetCompressionWorkSpaceSize", "RtlCompressBuffer", "RtlDecompressBufferEx2", "RtlDecompressFragmentEx"],
        handlers: &[work_space_size, compress_buffer, decompress_buffer, decompress_fragment],
        data_exports: &[],
    };
}

pub mod rtl_nonvolatile_memory {
    //! Adaptadores da memória não volátil do Rtl.

    use crate::ntos::inc::types::{Field, NtStruct};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::rtl::non_volatile;
    use crate::rtl::KernelError;

    /// RtlGetNonVolatileToken(NvBuffer, Size, *NvToken) -> NTSTATUS.
    fn get_token(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PNV_TOKEN de saída obrigatório do chamador.
        Ok(signed_status(non_volatile::get_token(unsafe { Field::<u64>::at(call.arg(3)) })))
    }

    /// RtlFreeNonVolatileToken(NvToken) -> NTSTATUS.
    fn free_token(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(non_volatile::free_token(call.arg(1))))
    }

    /// RtlFillNonVolatileMemory(NvToken, NvDestination, Size, Value, Flags) -> NTSTATUS.
    fn fill_memory(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(non_volatile::fill_memory(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u8)))
    }

    pub static GROUP: Group = Group {
        name: "rtl-nonvolatile-memory",
        names: &["RtlGetNonVolatileToken", "RtlFreeNonVolatileToken", "RtlFillNonVolatileMemory"],
        handlers: &[get_token, free_token, fill_memory],
        data_exports: &[],
    };
}

pub mod rtl_security_descriptor_ops {
    //! Adaptadores das rotinas de ACE/SD do Rtl e do teste de sandbox.

    use crate::ntos::inc::types::{Field, NtStruct};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::rtl::security;
    use crate::rtl::KernelError;

    /// RtlFindAceByType(Acl, AceType, *Index) -> PVOID.
    fn find_ace_by_type(call: &Call) -> Result<u64, KernelError> {
        Ok(security::find_ace_by_type(call.arg(1), call.arg(2) as u32, call.arg(3)))
    }

    /// RtlOwnerAcesPresent(Acl) -> BOOLEAN.
    fn owner_aces_present(call: &Call) -> Result<u64, KernelError> {
        Ok(security::owner_aces_present(call.arg(1)) as u64)
    }

    /// RtlReplaceSidInSd(Sd, OldSid, NewSid, *NumChanges) -> NTSTATUS.
    fn replace_sid_in_sd(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PULONG NumChanges obrigatório do chamador.
        let changes = unsafe { Field::<u32>::at(call.arg(4)) };
        Ok(signed_status(security::replace_sid_in_sd(call.arg(1), call.arg(2), call.arg(3), changes)))
    }

    /// RtlNormalizeSecurityDescriptor(*Sd, Length, *NewSd, *NewLength, CheckOnly) -> BOOLEAN.
    fn normalize_security_descriptor(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PSECURITY_DESCRIPTOR* obrigatório do chamador.
        let descriptor = unsafe { Field::<u64>::at(call.arg(1)) };
        Ok(security::normalize_security_descriptor(descriptor, call.arg(2) as u32, call.arg(3), call.arg(4), call.arg(5) as u8 != 0)? as u64)
    }

    /// RtlIsSandboxedToken(SubjectContext, PreviousMode) -> BOOLEAN.
    fn is_sandboxed_token(call: &Call) -> Result<u64, KernelError> {
        Ok(security::is_sandboxed_token(call.arg(1), call.arg(2) as u8)? as u64)
    }

    pub static GROUP: Group = Group {
        name: "rtl-security-descriptor-ops",
        names: &["RtlFindAceByType", "RtlOwnerAcesPresent", "RtlReplaceSidInSd", "RtlNormalizeSecurityDescriptor", "RtlIsSandboxedToken"],
        handlers: &[find_ace_by_type, owner_aces_present, replace_sid_in_sd, normalize_security_descriptor, is_sandboxed_token],
        data_exports: &[],
    };
}

pub mod rtl_support_routines {
    //! Adaptadores de rotinas de apoio do Rtl e da CRT.

    use crate::ntos::inc::types::{Field, NtStruct, String as AnsiString};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::rtl::{checksum, crt, module_information, reparse, stack_trace, strings_counted};
    use crate::rtl::KernelError;

    /// RtlCopyString(Destination, Source).
    fn copy_string(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PSTRING DestinationString obrigatório do chamador.
        strings_counted::copy_string(unsafe { AnsiString::at(call.arg(1)) }, call.arg(2));
        Ok(0)
    }

    /// RtlCrc64(Buffer, Size, InitialCrc) -> ULONGLONG.
    fn crc64(call: &Call) -> Result<u64, KernelError> {
        Ok(checksum::crc64(call.arg(1), call.arg(2), call.arg(3)))
    }

    /// isprint(c) -> int.
    fn isprint(call: &Call) -> Result<u64, KernelError> {
        Ok(crt::isprint(call.arg(1) as u32) as u64)
    }

    /// RtlIsNonEmptyDirectoryReparsePointAllowed(ReparseTag) -> BOOLEAN.
    fn is_non_empty_directory_reparse_point_allowed(call: &Call) -> Result<u64, KernelError> {
        Ok(reparse::is_non_empty_directory_reparse_point_allowed(call.arg(1) as u32) as u64)
    }

    /// RtlQueryModuleInformation(*InformationLength, SizePerModule, Buffer) -> NTSTATUS.
    fn query_module_information(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PULONG InformationLength obrigatório do chamador.
        let length = unsafe { Field::<u32>::at(call.arg(1)) };
        Ok(signed_status(module_information::query(length, call.arg(2) as u32, call.arg(3))?))
    }

    /// RtlWalkFrameChain(Callers, Count, Flags) -> ULONG.
    fn walk_frame_chain(call: &Call) -> Result<u64, KernelError> {
        Ok(stack_trace::walk_frame_chain(call.frame, call.arg(1), call.arg(2) as u32, call.arg(3) as u32) as u64)
    }

    pub static GROUP: Group = Group {
        name: "rtl-support-routines",
        names: &["RtlCopyString", "RtlCrc64", "isprint", "RtlIsNonEmptyDirectoryReparsePointAllowed", "RtlQueryModuleInformation", "RtlWalkFrameChain"],
        handlers: &[copy_string, crc64, isprint, is_non_empty_directory_reparse_point_allowed, query_module_information, walk_frame_chain],
        data_exports: &[],
    };
}

pub mod rtl_oem_strings {
    //! Strings OEM e os dados NLS da página OEM: a lógica mora em `rtl/oem_code_page.rs`.

    use crate::ntos::inc::field::Field;
    use crate::ntos::inc::types::{NtStruct, String as AnsiString, UnicodeString};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::rtl::oem_code_page as oem;
    use crate::rtl::KernelError;

    // SAFETY (todas): strings e células de kernel do chamador (as rotinas Rtl
    // não sondam ponteiros).
    fn unicode(address: u64) -> &'static UnicodeString {
        unsafe { UnicodeString::at(address) }
    }
    fn ansi(address: u64) -> &'static AnsiString {
        unsafe { AnsiString::at(address) }
    }

    fn oem_to_unicode_n(call: &Call) -> Result<u64, KernelError> {
        let written = (call.arg(3) != 0).then(|| unsafe { Field::<u32>::at(call.arg(3)) });
        oem::oem_to_unicode_n(call.arg(1), call.arg(2) as u32, written, call.arg(4), call.arg(5) as u32).map(signed_status)
    }
    fn oem_string_to_unicode_string(call: &Call) -> Result<u64, KernelError> {
        oem::oem_string_to_unicode(unicode(call.arg(1)), ansi(call.arg(2)), call.arg(3) & 0xFF != 0, false).map(signed_status)
    }
    fn oem_string_to_counted_unicode_string(call: &Call) -> Result<u64, KernelError> {
        oem::oem_string_to_unicode(unicode(call.arg(1)), ansi(call.arg(2)), call.arg(3) & 0xFF != 0, true).map(signed_status)
    }
    fn unicode_string_to_oem_string(call: &Call) -> Result<u64, KernelError> {
        oem::unicode_string_to_oem(ansi(call.arg(1)), unicode(call.arg(2)), call.arg(3) & 0xFF != 0, false, false).map(signed_status)
    }
    fn unicode_string_to_counted_oem_string(call: &Call) -> Result<u64, KernelError> {
        oem::unicode_string_to_oem(ansi(call.arg(1)), unicode(call.arg(2)), call.arg(3) & 0xFF != 0, true, false).map(signed_status)
    }
    fn upcase_unicode_string_to_counted_oem_string(call: &Call) -> Result<u64, KernelError> {
        oem::unicode_string_to_oem(ansi(call.arg(1)), unicode(call.arg(2)), call.arg(3) & 0xFF != 0, true, true).map(signed_status)
    }
    fn oem_string_to_unicode_size(call: &Call) -> Result<u64, KernelError> {
        oem::oem_string_to_unicode_size(ansi(call.arg(1))).map(u64::from)
    }
    fn upper_string(call: &Call) -> Result<u64, KernelError> {
        oem::upper_string(ansi(call.arg(1)), ansi(call.arg(2))).map(|_| 0)
    }

    pub static GROUP: Group = Group {
        name: "rtl-oem-strings",
        names: &[
            "RtlOemToUnicodeN",
            "RtlOemStringToUnicodeString",
            "RtlOemStringToCountedUnicodeString",
            "RtlUnicodeStringToOemString",
            "RtlUnicodeStringToCountedOemString",
            "RtlUpcaseUnicodeStringToCountedOemString",
            "RtlxOemStringToUnicodeSize",
            "RtlUpperString",
        ],
        handlers: &[
            oem_to_unicode_n,
            oem_string_to_unicode_string,
            oem_string_to_counted_unicode_string,
            unicode_string_to_oem_string,
            unicode_string_to_counted_oem_string,
            upcase_unicode_string_to_counted_oem_string,
            oem_string_to_unicode_size,
            upper_string,
        ],
        data_exports: &[("NlsMbOemCodePageTag", oem::mb_oem_code_page_tag_address), ("NlsOemLeadByteInfo", oem::oem_lead_byte_info_address)],
    };
}

pub mod rtl_8dot3_names {
    //! RtlIsNameLegalDOS8Dot3: a lógica mora em `rtl/gen8dot3.rs`.

    use crate::ntos::inc::field::Field;
    use crate::ntos::inc::types::{NtStruct, String as AnsiString, UnicodeString};
    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::gen8dot3;
    use crate::rtl::KernelError;

    fn is_name_legal(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PCUNICODE_STRING Name, POEM_STRING OemName e PBOOLEAN opcionais do FS.
        let name = unsafe { UnicodeString::at(call.arg(1)) };
        let oem_name = (call.arg(2) != 0).then(|| unsafe { AnsiString::at(call.arg(2)) });
        let spaces = (call.arg(3) != 0).then(|| unsafe { Field::<u8>::at(call.arg(3)) });
        gen8dot3::is_name_legal_dos_8dot3(name, oem_name, spaces).map(|legal| legal as u64)
    }

    pub static GROUP: Group = Group { name: "rtl-8dot3-names", names: &["RtlIsNameLegalDOS8Dot3"], handlers: &[is_name_legal], data_exports: &[] };
}

pub mod rtl_altitudes_and_time {
    //! RtlCompareAltitudes, RtlSecondsSince1970ToTime, RtlSystemTimeToLocalTime:
    //! a lógica mora em `rtl/altitude.rs` e `rtl/time.rs`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::inc::types::{LargeInteger, NtStruct, UnicodeString};
    use crate::ntos::rtl::{altitude, time};
    use crate::rtl::KernelError;

    fn compare_altitudes(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: as PCUNICODE_STRING de altitude do chamador.
        Ok(altitude::compare_altitudes(unsafe { UnicodeString::at(call.arg(1)) }, unsafe { UnicodeString::at(call.arg(2)) }) as i64 as u64)
    }
    fn seconds_since_1970_to_time(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PLARGE_INTEGER de saída do chamador.
        time::seconds_since_1970_to_time(call.arg(1) as u32, unsafe { LargeInteger::at(call.arg(2)) });
        Ok(0)
    }
    fn system_time_to_local_time(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: os PLARGE_INTEGER do chamador.
        Ok(signed_status(time::system_time_to_local_time(unsafe { LargeInteger::at(call.arg(1)) }, unsafe { LargeInteger::at(call.arg(2)) })))
    }

    pub static GROUP: Group = Group {
        name: "rtl-altitudes-and-time",
        names: &["RtlCompareAltitudes", "RtlSecondsSince1970ToTime", "RtlSystemTimeToLocalTime"],
        handlers: &[compare_altitudes, seconds_since_1970_to_time, system_time_to_local_time],
        data_exports: &[],
    };
}

pub mod rtl_acl_trust_label {
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::acl;
    use crate::rtl::KernelError;

    fn add_process_trust_label_ace(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(acl::add_process_trust_label_ace(call.arg(1), call.arg(2) as u32, call.arg(3) as u32, call.arg(4), call.arg(5) as u8, call.arg(6) as u32)))
    }

    pub static GROUP: Group = Group { name: "rtl-acl-trust-label", names: &["RtlAddProcessTrustLabelAce"], handlers: &[add_process_trust_label_ace], data_exports: &[] };
}

pub mod rtl_crt_rand {
    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::crt;
    use crate::rtl::KernelError;

    fn rand(_: &Call) -> Result<u64, KernelError> {
        Ok(crt::rand() as u64)
    }

    pub static GROUP: Group = Group { name: "rtl-crt-rand", names: &["rand"], handlers: &[rand], data_exports: &[] };
}

pub mod rtl_atom_tables {
    //! Tabelas de átomos; a lógica mora em `rtl/atom.rs`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::inc::field::{Field, NtStruct};
    use crate::ntos::rtl::atom;
    use crate::rtl::KernelError;

    // Os ponteiros opcionais (NULL = sem saída) são as saídas do chamador
    // de kernel; o PVOID* AtomTableHandle é obrigatório, como no NT.
    fn create_atom_table(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(atom::create_table(call.arg(1) as u32, 0, unsafe { Field::<u64>::at(call.arg(2)) })))
    }
    fn create_atom_table_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(atom::create_table(call.arg(1) as u32, call.arg(2) as u32, unsafe { Field::<u64>::at(call.arg(3)) })))
    }
    fn add_atom(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(atom::add(call.arg(1), call.arg(2), (call.arg(3) != 0).then(|| unsafe { Field::<u16>::at(call.arg(3)) }), 0)?))
    }
    fn add_atom_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(atom::add(call.arg(1), call.arg(2), (call.arg(3) != 0).then(|| unsafe { Field::<u16>::at(call.arg(3)) }), call.arg(4) as u32)?))
    }
    fn delete_atom(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(atom::delete(call.arg(1), call.arg(2) as u16)?))
    }
    fn destroy_atom_table(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(atom::destroy_table(call.arg(1))?))
    }
    fn lookup_atom(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(atom::lookup(call.arg(1), call.arg(2), (call.arg(3) != 0).then(|| unsafe { Field::<u16>::at(call.arg(3)) }))?))
    }
    fn pin_atom(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(atom::pin(call.arg(1), call.arg(2) as u16)?))
    }
    fn query_atom(call: &Call) -> Result<u64, KernelError> {
        let outputs = atom::QueryOutputs { reference_count: (call.arg(3) != 0).then(|| unsafe { Field::<u32>::at(call.arg(3)) }), pin_count: (call.arg(4) != 0).then(|| unsafe { Field::<u32>::at(call.arg(4)) }), name: call.arg(5), name_length: (call.arg(6) != 0).then(|| unsafe { Field::<u32>::at(call.arg(6)) }) };
        Ok(signed_status(atom::query(call.arg(1), call.arg(2) as u16, &outputs)?))
    }
    fn get_integer_atom(call: &Call) -> Result<u64, KernelError> {
        Ok(atom::integer_atom(call.arg(1), (call.arg(2) != 0).then(|| unsafe { Field::<u16>::at(call.arg(2)) })) as u64)
    }

    pub static GROUP: Group = Group {
        name: "rtl-atom-tables",
        names: &["RtlCreateAtomTable", "RtlCreateAtomTableEx", "RtlAddAtomToAtomTable", "RtlAddAtomToAtomTableEx", "RtlDeleteAtomFromAtomTable", "RtlDestroyAtomTable", "RtlLookupAtomInAtomTable", "RtlPinAtomInAtomTable", "RtlQueryAtomInAtomTable", "RtlGetIntegerAtom"],
        handlers: &[create_atom_table, create_atom_table_ex, add_atom, add_atom_ex, delete_atom, destroy_atom_table, lookup_atom, pin_atom, query_atom, get_integer_atom],
        data_exports: &[],
    };
}

pub mod rtl_heap {
    //! RtlCreateHeap/RtlAllocateHeap/RtlFreeHeap/RtlDestroyHeap; a lógica
    //! mora em `rtl/heap.rs`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::heap;
    use crate::rtl::KernelError;

    fn create_heap(call: &Call) -> Result<u64, KernelError> {
        heap::create(call.arg(1) as u32, call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6))
    }
    fn allocate_heap(call: &Call) -> Result<u64, KernelError> {
        heap::allocate(call.arg(1), call.arg(2) as u32, call.arg(3))
    }
    fn free_heap(call: &Call) -> Result<u64, KernelError> {
        Ok(heap::free(call.arg(1), call.arg(2) as u32, call.arg(3))? as u64)
    }
    fn destroy_heap(call: &Call) -> Result<u64, KernelError> {
        heap::destroy(call.arg(1))
    }

    pub static GROUP: Group = Group {
        name: "rtl-heap",
        names: &["RtlCreateHeap", "RtlAllocateHeap", "RtlFreeHeap", "RtlDestroyHeap"],
        handlers: &[create_heap, allocate_heap, free_heap, destroy_heap],
        data_exports: &[],
    };
}

pub mod rtl_code_pages {
    //! Páginas de código: a instalada (`rtl/ansi_code_page.rs`,
    //! `rtl/nls_translation.rs`) e as do chamador (`rtl/code_page_table.rs`),
    //! com os dados NlsAnsiCodePage, NlsOemCodePage e NlsMbCodePageTag.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::inc::field::{Field, NtStruct};
    use crate::ntos::rtl::{ansi_code_page, code_page_table, nls_translation};
    use crate::rtl::KernelError;

    fn get_default_code_page(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: os PUSHORT de saída do chamador.
        let (ansi, oem) = unsafe { (Field::<u16>::at(call.arg(1)), Field::<u16>::at(call.arg(2))) };
        ansi_code_page::get_default_code_page(ansi, oem);
        Ok(0)
    }
    fn upcase_unicode_to_multi_byte_n(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(nls_translation::upcase_unicode_to_multi_byte_n(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4), call.arg(5) as u32)?))
    }
    fn custom_cp_to_unicode_n(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(code_page_table::custom_cp_to_unicode_n(code_page_table::info_at(call.arg(1)), call.arg(2), call.arg(3) as u32, (call.arg(4) != 0).then(|| unsafe { Field::<u32>::at(call.arg(4)) }), call.arg(5), call.arg(6) as u32)?))
    }
    fn unicode_to_custom_cp_n(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(code_page_table::unicode_to_custom_cp_n(code_page_table::info_at(call.arg(1)), call.arg(2), call.arg(3) as u32, (call.arg(4) != 0).then(|| unsafe { Field::<u32>::at(call.arg(4)) }), call.arg(5), call.arg(6) as u32)?))
    }
    fn init_code_page_table(call: &Call) -> Result<u64, KernelError> {
        code_page_table::init_code_page_table(call.arg(1), code_page_table::info_at(call.arg(2)));
        Ok(0)
    }
    fn multi_byte_to_unicode_size(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(nls_translation::multi_byte_to_unicode_size(call.arg(1), call.arg(2), call.arg(3) as u32)?))
    }

    pub static GROUP: Group = Group {
        name: "rtl-code-pages",
        names: &["RtlGetDefaultCodePage", "RtlUpcaseUnicodeToMultiByteN", "RtlCustomCPToUnicodeN", "RtlUnicodeToCustomCPN", "RtlInitCodePageTable", "RtlMultiByteToUnicodeSize"],
        handlers: &[get_default_code_page, upcase_unicode_to_multi_byte_n, custom_cp_to_unicode_n, unicode_to_custom_cp_n, init_code_page_table, multi_byte_to_unicode_size],
        data_exports: &[("NlsAnsiCodePage", ansi_code_page::ansi_code_page_address), ("NlsOemCodePage", ansi_code_page::oem_code_page_address), ("NlsMbCodePageTag", ansi_code_page::mb_code_page_tag_address)],
    };
}

pub mod rtl_resource_messages {
    //! LdrResFindResourceDirectory, RtlFindMessage e RtlGetThreadLangIdByIndex;
    //! a lógica mora em `rtl/resource/{find,message,languages}.rs`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::inc::field::{Field, NtStruct};
    use crate::ntos::rtl::resource::{find, languages, message};
    use crate::rtl::KernelError;

    fn find_resource_directory(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(find::find_directory(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7))?))
    }
    fn find_message(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PMESSAGE_RESOURCE_ENTRY* de saída do chamador.
        let entry = unsafe { Field::<u64>::at(call.arg(5)) };
        Ok(signed_status(message::find_message(call.arg(1), call.arg(2) as u32, call.arg(3) as u32, call.arg(4) as u32, entry)?))
    }
    fn get_thread_lang_id_by_index(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(languages::thread_lang_id_by_index(call.arg(1) as u32, call.arg(2) as u32, call.arg(3), call.arg(4))))
    }

    pub static GROUP: Group = Group {
        name: "rtl-resource-messages",
        names: &["LdrResFindResourceDirectory", "RtlFindMessage", "RtlGetThreadLangIdByIndex"],
        handlers: &[find_resource_directory, find_message, get_thread_lang_id_by_index],
        data_exports: &[],
    };
}

pub mod rtl_integer_to_char {
    //! RtlIntegerToChar; a lógica mora em `rtl/integer_conversion.rs`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::rtl::integer_conversion;
    use crate::rtl::KernelError;

    fn integer_to_char(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(integer_conversion::integer_to_char(call.arg(1) as u32, call.arg(2) as u32, call.arg(3) as i32, call.arg(4))))
    }

    pub static GROUP: Group = Group { name: "rtl-integer-to-char", names: &["RtlIntegerToChar"], handlers: &[integer_to_char], data_exports: &[] };
}

pub mod rtl_system_state {
    //! NtGlobalFlag, flags de elevação, console ativo e sessão de serviço;
    //! a lógica mora em `rtl/shared_data.rs`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::inc::field::{Field, NtStruct};
    use crate::ntos::rtl::shared_data;
    use crate::rtl::KernelError;

    fn get_nt_global_flags(_: &Call) -> Result<u64, KernelError> {
        Ok(shared_data::nt_global_flag() as u64)
    }
    fn query_elevation_flags(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PRTL_ELEVATION_FLAGS (ULONG) de saída do chamador.
        Ok(shared_data::query_elevation_flags(unsafe { Field::<u32>::at(call.arg(1)) }) as u64)
    }
    fn set_active_console_id(call: &Call) -> Result<u64, KernelError> {
        shared_data::set_active_console_id(call.arg(1) as u32)?;
        Ok(0)
    }
    fn set_console_session_foreground_process_id(call: &Call) -> Result<u64, KernelError> {
        shared_data::set_console_session_foreground_process_id(call.arg(1))?;
        Ok(0)
    }
    fn get_current_service_session_id(_: &Call) -> Result<u64, KernelError> {
        Ok(shared_data::current_service_session_id() as u64)
    }

    pub static GROUP: Group = Group {
        name: "rtl-system-state",
        names: &["RtlGetNtGlobalFlags", "RtlQueryElevationFlags", "RtlSetActiveConsoleId", "RtlSetConsoleSessionForegroundProcessId", "RtlGetCurrentServiceSessionId"],
        handlers: &[get_nt_global_flags, query_elevation_flags, set_active_console_id, set_console_session_foreground_process_id, get_current_service_session_id],
        data_exports: &[],
    };
}

pub mod rtl_access_masks {
    //! RtlAreAllAccessesGranted/RtlAreAnyAccessesGranted; a lógica mora em
    //! `rtl/security.rs`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::security;
    use crate::rtl::KernelError;

    fn are_all_accesses_granted(call: &Call) -> Result<u64, KernelError> {
        Ok(security::are_all_accesses_granted(call.arg(1) as u32, call.arg(2) as u32) as u64)
    }
    fn are_any_accesses_granted(call: &Call) -> Result<u64, KernelError> {
        Ok(security::are_any_accesses_granted(call.arg(1) as u32, call.arg(2) as u32) as u64)
    }

    pub static GROUP: Group = Group { name: "rtl-access-masks", names: &["RtlAreAllAccessesGranted", "RtlAreAnyAccessesGranted"], handlers: &[are_all_accesses_granted, are_any_accesses_granted], data_exports: &[] };
}

pub mod rtl_capability_single_session {
    //! RtlCapabilityCheckForSingleSessionSku; a lógica mora em
    //! `se/capability/check.rs`.

    use crate::ntos::init::exports::{fatal_unless_transfer, signed_status, Call, Group};
    use crate::ntos::se::capability::check as capability_check;
    use crate::rtl::KernelError;

    fn check(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(fatal_unless_transfer("capability-single-session", capability_check::check_for_single_session_sku(call.arg(1), call.arg(2), call.arg(3)))?))
    }

    pub static GROUP: Group = Group { name: "rtl-capability-single-session", names: &["RtlCapabilityCheckForSingleSessionSku"], handlers: &[check], data_exports: &[] };
}

pub mod rtl_raise_exception {
    //! RtlRaiseException; a lógica mora em `rtl/exceptions.rs`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::exceptions;
    use crate::rtl::KernelError;

    fn raise_exception(call: &Call) -> Result<u64, KernelError> {
        exceptions::raise_exception(call.arg(1), 0)
    }

    pub static GROUP: Group = Group { name: "rtl-raise-exception", names: &["RtlRaiseException"], handlers: &[raise_exception], data_exports: &[] };
}

pub mod crt_sqrtf {
    //! sqrtf: o export público é o corpo nativo; pela tabela, o slot XMM0 do
    //! CONTEXT (`rtl/math.rs`).

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::math;
    use crate::rtl::KernelError;

    fn sqrtf(call: &Call) -> Result<u64, KernelError> {
        math::sqrtf_in_context(call.context);
        Ok(0)
    }

    pub static GROUP: Group = Group { name: "crt-sqrtf", names: &["sqrtf"], handlers: &[sqrtf], data_exports: &[] };
}

pub mod rtl_debug_print_va {
    //! vDbgPrintEx; a lógica mora em `rtl/printf.rs`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::printf;
    use crate::rtl::KernelError;

    fn v_dbg_print_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(printf::debug_print_ex_va(call.arg(1) as u32, call.arg(3), call.arg(4))? as u64)
    }

    pub static GROUP: Group = Group { name: "rtl-debug-print-va", names: &["vDbgPrintEx"], handlers: &[v_dbg_print_ex], data_exports: &[] };
}

pub mod rtl_security_error {
    //! RtlMapSecurityErrorToNtStatus; a tabela mora em `rtl/error`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::rtl::error;
    use crate::rtl::KernelError;

    /// RtlMapSecurityErrorToNtStatus(SECURITY_STATUS) -> NTSTATUS.
    fn map_security_error_to_status(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(error::map_security_error_to_status(call.arg(1) as u32)))
    }

    pub static GROUP: Group = Group { name: "rtl-security-error", names: &["RtlMapSecurityErrorToNtStatus"], handlers: &[map_security_error_to_status], data_exports: &[] };
}

pub mod rtl_crt_vsnprintf_s {
    //! _vsnprintf_s; a lógica mora em `rtl/printf`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::printf;
    use crate::rtl::KernelError;

    /// _vsnprintf_s(Buffer, SizeOfBuffer, Count, Format, ArgList) -> int.
    fn vsnprintf_s(call: &Call) -> Result<u64, KernelError> {
        printf::vsnprintf_s(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5))
    }

    pub static GROUP: Group = Group { name: "rtl-crt-vsnprintf-s", names: &["_vsnprintf_s"], handlers: &[vsnprintf_s], data_exports: &[] };
}

pub mod rtl_capability_sids {
    //! RtlDeriveCapabilitySidsFromName; a lógica mora em
    //! `se/capability/identifiers` (a mesma derivação do RtlCapabilityCheck).

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::capability::identifiers;
    use crate::rtl::KernelError;

    /// RtlDeriveCapabilitySidsFromName(CapabilityName, CapabilityGroupSid, CapabilitySid).
    fn derive_capability_sids_from_name(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(identifiers::derive(call.arg(1), call.arg(2), call.arg(3))?))
    }

    pub static GROUP: Group = Group { name: "rtl-capability-sids", names: &["RtlDeriveCapabilitySidsFromName"], handlers: &[derive_capability_sids_from_name], data_exports: &[] };
}

pub mod rtl_bitmap_ex_ranges {
    //! RtlAreBitsClearEx, RtlClearAllBitsEx, RtlCopyBitMapEx, RtlFindSetBitsEx
    //! e RtlIntersectBitMapsEx sobre RTL_BITMAP_EX; a lógica mora em
    //! `rtl/bitmap.rs`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::inc::types::{NtStruct, RtlBitmapEx};
    use crate::ntos::rtl::bitmap;
    use crate::rtl::KernelError;

    /// PRTL_BITMAP_EX do chamador.
    fn header(address: u64) -> &'static RtlBitmapEx {
        // SAFETY: o export recebe um RTL_BITMAP_EX vivo e alinhado, como no NT.
        unsafe { RtlBitmapEx::at(address) }
    }

    fn are_bits_clear_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(bitmap::are_bits_clear_ex(header(call.arg(1)), call.arg(2), call.arg(3)) as u64)
    }

    fn clear_all_bits_ex(call: &Call) -> Result<u64, KernelError> {
        bitmap::clear_all_bits_ex(header(call.arg(1)));
        Ok(0)
    }

    fn copy_bitmap_ex(call: &Call) -> Result<u64, KernelError> {
        bitmap::copy_bitmap_ex(header(call.arg(1)), header(call.arg(2)), call.arg(3));
        Ok(0)
    }

    fn find_set_bits_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(bitmap::find_set_bits_ex(header(call.arg(1)), call.arg(2), call.arg(3)))
    }

    fn intersect_bitmaps_ex(call: &Call) -> Result<u64, KernelError> {
        bitmap::intersect_bitmaps_ex(header(call.arg(1)), header(call.arg(2)));
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "rtl-bitmap-ex-ranges",
        names: &["RtlAreBitsClearEx", "RtlClearAllBitsEx", "RtlCopyBitMapEx", "RtlFindSetBitsEx", "RtlIntersectBitMapsEx"],
        handlers: &[are_bits_clear_ex, clear_all_bits_ex, copy_bitmap_ex, find_set_bits_ex, intersect_bitmaps_ex],
        data_exports: &[],
    };
}

pub mod rtl_copy_non_temporal {
    //! RtlCopyMemoryNonTemporal; a lógica mora em `rtl/memory.rs`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::memory;
    use crate::rtl::KernelError;

    /// (Destination, Source, Length).
    fn copy_memory_non_temporal(call: &Call) -> Result<u64, KernelError> {
        memory::copy_memory_non_temporal(call.arg(1), call.arg(2), call.arg(3));
        Ok(0)
    }

    pub static GROUP: Group = Group { name: "rtl-copy-non-temporal", names: &["RtlCopyMemoryNonTemporal"], handlers: &[copy_memory_non_temporal], data_exports: &[] };
}

pub mod rtl_range_lists {
    //! Listas de faixas; a lógica mora em `rtl/range_list.rs`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::inc::field::{Field, NtStruct};
    use crate::ntos::inc::types::extra_rtl::{RtlRangeList, RtlRangeListIterator};
    use crate::ntos::rtl::range_list::{self, Availability, FindRequest, InvertedRange, NewRange};
    use crate::rtl::KernelError;

    fn list(address: u64) -> &'static RtlRangeList {
        // SAFETY: a RTL_RANGE_LIST do chamador de kernel.
        unsafe { RtlRangeList::at(address) }
    }
    fn iterator(address: u64) -> &'static RtlRangeListIterator {
        // SAFETY: o RTL_RANGE_LIST_ITERATOR do chamador.
        unsafe { RtlRangeListIterator::at(address) }
    }
    fn out<T: Copy + 'static>(address: u64) -> &'static Field<T> {
        // SAFETY: parâmetro de saída do chamador de kernel.
        unsafe { Field::<T>::at(address) }
    }

    fn initialize_range_list(call: &Call) -> Result<u64, KernelError> {
        range_list::initialize(list(call.arg(1)));
        Ok(0)
    }
    fn free_range_list(call: &Call) -> Result<u64, KernelError> {
        range_list::free(list(call.arg(1)));
        Ok(0)
    }
    fn copy_range_list(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(range_list::copy(list(call.arg(1)), list(call.arg(2)))))
    }
    fn add_range(call: &Call) -> Result<u64, KernelError> {
        let request = NewRange { start: call.arg(2), end: call.arg(3), attributes: call.arg(4) as u8, flags: call.arg(5) as u32, user_data: call.arg(6), owner: call.arg(7) };
        Ok(signed_status(range_list::add(list(call.arg(1)), &request)))
    }
    fn delete_range(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(range_list::delete(list(call.arg(1)), call.arg(2), call.arg(3), call.arg(4))))
    }
    fn delete_owners_ranges(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(range_list::delete_owners(list(call.arg(1)), call.arg(2))))
    }
    // Length e Alignment são lidos com os 64 bits do registrador e do slot,
    // como no original.
    fn find_range(call: &Call) -> Result<u64, KernelError> {
        let request = FindRequest { minimum: call.arg(2), maximum: call.arg(3), length: call.arg(4), alignment: call.arg(5) };
        let criteria = Availability::new(call.arg(6) as u8 as u32, call.arg(7) as u8, call.arg(8), call.arg(9));
        Ok(signed_status(range_list::find(list(call.arg(1)), &request, &criteria, out::<u64>(call.arg(10)))))
    }
    fn is_range_available(call: &Call) -> Result<u64, KernelError> {
        let criteria = Availability::new(call.arg(4) as u8 as u32, call.arg(5) as u8, call.arg(6), call.arg(7));
        Ok(signed_status(range_list::is_range_available(list(call.arg(1)), call.arg(2), call.arg(3), &criteria, out::<u8>(call.arg(8)))))
    }
    fn get_first_range(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(range_list::get_first(list(call.arg(1)), iterator(call.arg(2)), out::<u64>(call.arg(3)))))
    }
    fn get_next_range(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(range_list::get_next(iterator(call.arg(1)), out::<u64>(call.arg(2)), call.arg(3) as u8 != 0)))
    }
    fn invert_range_list(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(range_list::invert(list(call.arg(1)), list(call.arg(2)), &InvertedRange { attributes: 0, user_data: 0, owner: 0 })))
    }
    fn invert_range_list_ex(call: &Call) -> Result<u64, KernelError> {
        let fill = InvertedRange { attributes: call.arg(3) as u8, user_data: call.arg(4), owner: call.arg(5) };
        Ok(signed_status(range_list::invert(list(call.arg(1)), list(call.arg(2)), &fill)))
    }

    pub static GROUP: Group = Group {
        name: "rtl-range-lists",
        names: &["RtlInitializeRangeList", "RtlFreeRangeList", "RtlCopyRangeList", "RtlAddRange", "RtlDeleteRange", "RtlDeleteOwnersRanges", "RtlFindRange", "RtlIsRangeAvailable", "RtlGetFirstRange", "RtlGetNextRange", "RtlInvertRangeList", "RtlInvertRangeListEx"],
        handlers: &[initialize_range_list, free_range_list, copy_range_list, add_range, delete_range, delete_owners_ranges, find_range, is_range_available, get_first_range, get_next_range, invert_range_list, invert_range_list_ex],
        data_exports: &[],
    };
}

pub mod rtl_resource_encoding {
    //! Descritores de memória e porta; a lógica mora em
    //! `rtl/resource_encoding.rs`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::inc::field::{Field, NtStruct};
    use crate::ntos::inc::types::{CmPartialResourceDescriptor, IoResourceDescriptor};
    use crate::ntos::rtl::resource_encoding::{self, IoDecodeOutputs, IoEncodeRequest};
    use crate::rtl::KernelError;

    fn cm_descriptor(address: u64) -> &'static CmPartialResourceDescriptor {
        // SAFETY: o CM_PARTIAL_RESOURCE_DESCRIPTOR do chamador.
        unsafe { CmPartialResourceDescriptor::at(address) }
    }
    fn io_descriptor(address: u64) -> &'static IoResourceDescriptor {
        // SAFETY: o IO_RESOURCE_DESCRIPTOR do chamador.
        unsafe { IoResourceDescriptor::at(address) }
    }
    fn optional(address: u64) -> Option<&'static Field<u64>> {
        // SAFETY: PULONGLONG opcional do chamador.
        (address != 0).then(|| unsafe { Field::<u64>::at(address) })
    }

    fn cm_decode(call: &Call) -> Result<u64, KernelError> {
        Ok(resource_encoding::cm_decode(cm_descriptor(call.arg(1)), optional(call.arg(2))))
    }
    fn cm_encode(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(resource_encoding::cm_encode(cm_descriptor(call.arg(1)), call.arg(2) as u8, call.arg(3), call.arg(4))))
    }
    fn io_decode(call: &Call) -> Result<u64, KernelError> {
        let outputs = IoDecodeOutputs { alignment: optional(call.arg(2)), minimum: optional(call.arg(3)), maximum: optional(call.arg(4)) };
        Ok(resource_encoding::io_decode(io_descriptor(call.arg(1)), &outputs))
    }
    fn io_encode(call: &Call) -> Result<u64, KernelError> {
        let request = IoEncodeRequest { kind: call.arg(2) as u8, length: call.arg(3), alignment: call.arg(4), minimum: call.arg(5), maximum: call.arg(6) };
        Ok(signed_status(resource_encoding::io_encode(io_descriptor(call.arg(1)), &request)))
    }
    fn find_closest_encodable_length(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PULONGLONG de saída do chamador.
        let rounded = unsafe { Field::<u64>::at(call.arg(2)) };
        Ok(signed_status(resource_encoding::find_closest_encodable_length(call.arg(1), rounded)))
    }

    pub static GROUP: Group = Group {
        name: "rtl-resource-encoding",
        names: &["RtlCmDecodeMemIoResource", "RtlCmEncodeMemIoResource", "RtlIoDecodeMemIoResource", "RtlIoEncodeMemIoResource", "RtlFindClosestEncodableLength"],
        handlers: &[cm_decode, cm_encode, io_decode, io_encode, find_closest_encodable_length],
        data_exports: &[],
    };
}

pub mod rtl_bitmap_copy {
    //! RtlCopyBitMap; a lógica mora em `rtl/bitmap.rs`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::inc::types::{NtStruct, RtlBitmap};
    use crate::ntos::rtl::bitmap;
    use crate::rtl::KernelError;

    fn copy_bit_map(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: os cabeçalhos RTL_BITMAP do chamador.
        let (source, destination) = unsafe { (RtlBitmap::at(call.arg(1)), RtlBitmap::at(call.arg(2))) };
        bitmap::copy(source, destination, call.arg(3) as u32);
        Ok(0)
    }

    pub static GROUP: Group = Group { name: "rtl-bitmap-copy", names: &["RtlCopyBitMap"], handlers: &[copy_bit_map], data_exports: &[] };
}

pub mod crt_string_conversion {
    //! _strtoui64 e strtok_s; a lógica mora em `rtl/crt.rs`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::crt;
    use crate::rtl::KernelError;

    fn strtoui64(call: &Call) -> Result<u64, KernelError> {
        Ok(crt::strtoui64(call.arg(1), call.arg(2), call.arg(3) as u32))
    }
    fn strtok_s(call: &Call) -> Result<u64, KernelError> {
        Ok(crt::strtok_s(call.arg(1), call.arg(2), call.arg(3)))
    }

    pub static GROUP: Group = Group { name: "crt-string-conversion", names: &["_strtoui64", "strtok_s"], handlers: &[strtoui64, strtok_s], data_exports: &[] };
}

pub mod rtl_bitmap_runs {
    //! RtlFindFirstRunClear, RtlFindLastBackwardRunClear e
    //! RtlFindLongestRunClear; a lógica mora em `rtl/bitmap`.

    use crate::ntos::inc::types::{Field, NtStruct, RtlBitmap};
    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::bitmap;
    use crate::rtl::KernelError;

    /// RtlFindFirstRunClear(BitMap, StartingIndex*) -> ULONG.
    fn find_first_run_clear(call: &Call) -> Result<u64, KernelError> {
        Ok(bitmap::find_first_run_clear(call.arg(1), call.arg(2)) as u64)
    }

    /// RtlFindLastBackwardRunClear(BitMap, FromIndex, StartingRunIndex*) -> ULONG.
    fn find_last_backward_run_clear(call: &Call) -> Result<u64, KernelError> {
        Ok(bitmap::find_last_backward_run_clear(call.arg(1), call.arg(2) as u32, call.arg(3)) as u64)
    }

    /// RtlFindLongestRunClear(BitMap, StartingIndex*) -> ULONG.
    fn find_longest_run_clear(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: RTL_BITMAP e PULONG do chamador.
        let (header, start) = unsafe { (RtlBitmap::at(call.arg(1)), Field::<u32>::at(call.arg(2))) };
        Ok(bitmap::find_longest_run_clear(header, start) as u64)
    }

    pub static GROUP: Group = Group {
        name: "rtl-bitmap-runs",
        names: &["RtlFindFirstRunClear", "RtlFindLastBackwardRunClear", "RtlFindLongestRunClear"],
        handlers: &[find_first_run_clear, find_last_backward_run_clear, find_longest_run_clear],
        data_exports: &[],
    };
}

pub mod rtl_8dot3_generate {
    //! RtlGenerate8dot3Name; a lógica mora em `rtl/gen8dot3`.

    use crate::ntos::inc::types::{NtStruct, UnicodeString};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::rtl::gen8dot3::{self, GenerateNameContext};
    use crate::rtl::KernelError;

    /// RtlGenerate8dot3Name(Name, AllowExtendedCharacters, Context, Name8dot3) -> NTSTATUS.
    fn generate_8dot3_name(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: as estruturas do chamador.
        let (name, context, short_name) = unsafe { (UnicodeString::at(call.arg(1)), GenerateNameContext::at(call.arg(3)), UnicodeString::at(call.arg(4))) };
        Ok(signed_status(gen8dot3::generate_8dot3_name(name, call.arg(2) as u8 != 0, context, short_name)?))
    }

    pub static GROUP: Group = Group { name: "rtl-8dot3-generate", names: &["RtlGenerate8dot3Name"], handlers: &[generate_8dot3_name], data_exports: &[] };
}

pub mod rtl_format_message {
    //! RtlFormatMessage; a lógica mora em `rtl/format_message`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::rtl::format_message::{self, Request};
    use crate::rtl::KernelError;

    /// RtlFormatMessage(MessageFormat, MaximumWidth, IgnoreInserts,
    /// ArgumentsAreAnsi, ArgumentsAreAnArray, Arguments, Buffer, Length,
    /// ReturnLength) -> NTSTATUS.
    fn format(call: &Call) -> Result<u64, KernelError> {
        let request = Request {
            format: call.arg(1),
            maximum_width: call.arg(2) as u32,
            ignore_inserts: call.arg(3) as u8 != 0,
            arguments_are_ansi: call.arg(4) as u8 != 0,
            arguments_are_an_array: call.arg(5) as u8 != 0,
            arguments: call.arg(6),
            buffer: call.arg(7),
            length: call.arg(8) as u32,
            return_length: call.arg(9),
        };
        Ok(signed_status(format_message::format_message(&request)?))
    }

    pub static GROUP: Group = Group { name: "rtl-format-message", names: &["RtlFormatMessage"], handlers: &[format], data_exports: &[] };
}

pub mod rtl_crt_snwprintf_s {
    //! _snwprintf_s; a lógica mora em `rtl/printf`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::printf;
    use crate::rtl::KernelError;

    /// _snwprintf_s(buffer, sizeOfBuffer, count, format, ...) -> int.
    fn snwprintf_s(call: &Call) -> Result<u64, KernelError> {
        printf::snwprintf_s(call.arg(1), call.arg(2), call.arg(3), call.arg(4), &[call.arg(5), call.arg(6), call.arg(7), call.arg(8), call.arg(9), call.arg(10)])
    }

    pub static GROUP: Group = Group { name: "rtl-crt-snwprintf-s", names: &["_snwprintf_s"], handlers: &[snwprintf_s], data_exports: &[] };
}

pub mod rtl_unicode_prefix {
    //! Tabelas de prefixos Unicode: a lógica mora em `rtl/unicode_prefix`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::unicode_prefix;
    use crate::rtl::KernelError;

    /// RtlInitializeUnicodePrefix(PrefixTable).
    fn initialize(call: &Call) -> Result<u64, KernelError> {
        unicode_prefix::initialize(call.arg(1));
        Ok(0)
    }

    /// RtlInsertUnicodePrefix(PrefixTable, Prefix, PrefixTableEntry) -> BOOLEAN.
    fn insert(call: &Call) -> Result<u64, KernelError> {
        Ok(unicode_prefix::insert(call.arg(1), call.arg(2), call.arg(3))? as u64)
    }

    /// RtlRemoveUnicodePrefix(PrefixTable, PrefixTableEntry).
    fn remove(call: &Call) -> Result<u64, KernelError> {
        unicode_prefix::remove(call.arg(1), call.arg(2));
        Ok(0)
    }

    /// RtlFindUnicodePrefix(PrefixTable, FullName, CaseInsensitiveIndex) -> PUNICODE_PREFIX_TABLE_ENTRY.
    fn find(call: &Call) -> Result<u64, KernelError> {
        unicode_prefix::find(call.arg(1), call.arg(2), call.arg(3) as u32)
    }

    pub static GROUP: Group = Group {
        name: "rtl-unicode-prefix",
        names: &["RtlInitializeUnicodePrefix", "RtlInsertUnicodePrefix", "RtlRemoveUnicodePrefix", "RtlFindUnicodePrefix"],
        handlers: &[initialize, insert, remove, find],
        data_exports: &[],
    };
}

pub mod rtl_app_container {
    //! SIDs de pacote (AppContainer): a lógica mora em `rtl/security`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::rtl::security;
    use crate::rtl::KernelError;

    /// RtlGetAppContainerSidType(Sid, SidType*) -> NTSTATUS.
    fn sid_type(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(security::get_app_container_sid_type(call.arg(1), call.arg(2))))
    }

    /// RtlGetAppContainerParent(AppContainerSid, AppContainerSidParent*) -> NTSTATUS.
    fn parent(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(security::get_app_container_parent(call.arg(1), call.arg(2))?))
    }

    pub static GROUP: Group = Group { name: "rtl-app-container", names: &["RtlGetAppContainerSidType", "RtlGetAppContainerParent"], handlers: &[sid_type, parent], data_exports: &[] };
}

pub mod rtl_self_relative_sd2 {
    //! RtlSelfRelativeToAbsoluteSD2; a lógica mora em `se/descriptor`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::descriptor;
    use crate::rtl::KernelError;

    /// RtlSelfRelativeToAbsoluteSD2(SelfRelativeSecurityDescriptor, BufferSize*).
    fn self_relative_to_absolute_sd2(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(descriptor::self_relative_to_absolute_in_place(call.arg(1), call.arg(2))))
    }

    pub static GROUP: Group = Group { name: "rtl-self-relative-sd2", names: &["RtlSelfRelativeToAbsoluteSD2"], handlers: &[self_relative_to_absolute_sd2], data_exports: &[] };
}
