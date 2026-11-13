//! RtlCapabilityCheck.
//!
//! Identifica a capability, avalia token e políticas e conserva o NTSTATUS
//! da primeira operação que falhar.

use crate::ntos::se::capability::{appcontainer as capability_appcontainer, identifiers as capability_identifiers, policy as policy, telemetry as capability_telemetry, token_checks as capability_token_checks};
use crate::ntos::se::token::membership as token_membership;
use crate::hal::cpu;
use crate::ntos::cm::key::services::{self as key_services, fields, Kind};
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ob::close;
use crate::ntos::ps::previous_mode;
use crate::ntos::ps::silo::query as silo_query;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{NtStruct, ObjectAttributes, UnicodeString};
use crate::ntos::se::{out, sid};

const ADMIN_CAPABILITIES: &str = "\\Registry\\Machine\\Software\\Microsoft\\SecurityManager\\AdminCapabilities";
const CHECK_TAG: u32 = 0x6B43_7043;

/// SID temporário de autoridade NT (5) com as subautoridades dadas.
fn write_identifier(pointer: u64, sub_authorities: &[u32]) {
    let identifier = sid::at(pointer);
    identifier.revision.set(1);
    identifier.sub_authority_count.set(sub_authorities.len() as u8);
    for (index, byte) in identifier.identifier_authority.value.iter().enumerate() {
        byte.set(if index == 5 { 5 } else { 0 });
    }
    for (cell, value) in sid::sub_authorities(identifier, sub_authorities.len()).iter().zip(sub_authorities) {
        cell.set(*value);
    }
}

/// Política do sistema para a capability: "DO" (Device Owner) ou "IU"
/// (Interactive User) restringem o resultado; ausência o conserva.
pub fn apply_system_policy(handle: u64, name: u64, output: u64) -> Result<u32, KernelError> {
    let Ok(frame) = kernel_pool::allocate(64, AllocateOptions { tag: CHECK_TAG, zero: true, ..Default::default() }) else {
        out::<u8>(output).set(0);
        return Ok(0xC000_0017);
    };
    let result = (|| -> Result<u32, KernelError> {
        let status = policy::query_system_policy(name, frame)?;
        if status == 0xC000_0034 {
            return Ok(0);
        }
        out::<u8>(output).set(0);
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        // SAFETY: UNICODE_STRING da política no início do frame privado.
        let policy_text = unsafe { UnicodeString::at(frame) };
        let length = policy_text.length.get();
        let text = if length == 4 { guest::read_bytes(policy_text.buffer.get(), 4) } else { alloc::vec::Vec::new() };
        if text == b"D\0O\0" {
            write_identifier(frame + 16, &[32, 583]);
        } else if text == b"I\0U\0" {
            write_identifier(frame + 16, &[4]);
        } else {
            return Ok(0xC000_0001);
        }
        let status = capability_token_checks::check_membership(handle, frame + 16, 2, frame + 48)?;
        if status & 0x8000_0000 != 0 || guest::read8(frame + 48) == 0 {
            return Ok(status);
        }
        let status = capability_appcontainer::check(handle, frame + 49)?;
        if status & 0x8000_0000 == 0 && guest::read8(frame + 49) != 0 {
            out::<u8>(output).set(1);
        }
        Ok(status)
    })();
    policy::release_string(frame);
    let _ = kernel_pool::free(frame, None);
    result
}

fn initialize_key_attributes(frame: u64) -> u64 {
    let attributes = frame + 160;
    let name = frame + 208;
    let units: alloc::vec::Vec<u16> = ADMIN_CAPABILITIES.encode_utf16().collect();
    // SAFETY: OBJECT_ATTRIBUTES e UNICODE_STRING no frame privado (zerado).
    let (descriptor, object) = unsafe { (UnicodeString::at(name), ObjectAttributes::at(attributes)) };
    let text = name + UnicodeString::SIZE;
    descriptor.length.set(units.len() as u16 * 2);
    descriptor.maximum_length.set(units.len() as u16 * 2 + 2);
    descriptor.buffer.set(text);
    guest::write_bytes(text, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<alloc::vec::Vec<u8>>());
    object.length.set(ObjectAttributes::SIZE as u32);
    object.object_name.set(name);
    object.attributes.set(0x240);
    attributes
}

#[derive(Default)]
struct State {
    administrator: u8,
    system: u8,
    interactive: u8,
    admin_capability: u8,
}

/// RtlCapabilityCheck(TokenHandle, CapabilityName, &HasCapability).
pub fn check(handle: u64, name: u64, output: u64) -> Result<u32, KernelError> {
    let start = cpu::rdtsc();
    let mut state = State::default();
    let mut frame = 0u64;
    let mut key_handle = 0u64;
    let evaluated = (|| -> Result<u32, KernelError> {
        if name == 0 || output == 0 {
            return Ok(0xC000_000D);
        }
        out::<u8>(output).set(0);
        frame = kernel_pool::allocate(1024, AllocateOptions { tag: CHECK_TAG, zero: true, ..Default::default() }).unwrap_or(0);
        if frame == 0 {
            return Ok(0xC000_0017);
        }
        let mut status = capability_identifiers::derive(name, frame, frame + 48)?;
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        if policy::is_multi_session() != 0 {
            status = previous_mode::with_kernel(|| key_services::open(frame + 136, 0x8000_0000, initialize_key_attributes(frame), false, 0))??;
            key_handle = guest::read64(frame + 136);
            if status & 0x8000_0000 == 0 {
                let arguments = fields(&[("name", name), ("klass", 2), ("out", frame + 512), ("length", 16), ("returned", frame + 528)]);
                status = previous_mode::with_kernel(|| key_services::key_operation(Kind::QueryValue, key_handle, &arguments, false))??;
                if status & 0x8000_0000 == 0 {
                    state.admin_capability = 1;
                }
            }
        }
        let mut permitted = false;
        if state.admin_capability == 0 {
            status = capability_token_checks::check_membership(handle, frame, 2, frame + 128)?;
            if status & 0x8000_0000 != 0 {
                return Ok(status);
            }
            permitted = guest::read8(frame + 128) != 0;
        }
        if !permitted {
            write_identifier(frame + 96, &[18]);
            status = token_membership::check(handle, frame + 96, frame + 129)?;
            state.system = guest::read8(frame + 129);
            if status & 0x8000_0000 != 0 {
                return Ok(status);
            }
            permitted = state.system != 0;
        }
        if !permitted {
            write_identifier(frame + 96, &[32, 544]);
            status = token_membership::check(handle, frame + 96, frame + 130)?;
            state.administrator = guest::read8(frame + 130);
            if status & 0x8000_0000 != 0 {
                return Ok(status);
            }
            permitted = state.administrator != 0;
        }
        if !permitted && state.admin_capability == 0 {
            write_identifier(frame + 96, &[4]);
            status = capability_token_checks::check_membership(handle, frame + 96, 2, frame + 131)?;
            state.interactive = guest::read8(frame + 131);
            if status & 0x8000_0000 != 0 {
                return Ok(status);
            }
            permitted = state.interactive != 0;
        }
        if permitted {
            status = capability_token_checks::check_capability(handle, frame + 48, frame + 132)?;
            if status & 0x8000_0000 != 0 {
                return Ok(status);
            }
            out::<u8>(output).set(guest::read8(frame + 132));
        }
        if out::<u8>(output).get() != 0 && state.administrator == 0 && state.system == 0 {
            status = apply_system_policy(handle, name, output)?;
        }
        Ok(status)
    })();
    if key_handle != 0 {
        let _ = previous_mode::with_kernel(|| close::close(key_handle, Some(0)));
    }
    let end = cpu::rdtsc();
    let telemetry = (|| -> Result<(), KernelError> {
        if state.system == 0 && silo_query::current_server_silo() == 0 {
            // O cleanup original lê esse byte mesmo no erro inicial; NULL é falha terminal.
            if output == 0 {
                return Err(KernelError::new("RtlCapabilityCheck: null output read during telemetry"));
            }
            capability_telemetry::record(start, end, state.administrator, state.interactive, state.admin_capability, out::<u8>(output).get());
        }
        Ok(())
    })();
    if frame != 0 {
        let _ = kernel_pool::free(frame, None);
    }
    let status = evaluated?;
    telemetry?;
    Ok(status)
}
