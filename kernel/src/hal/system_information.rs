//! HaliQuerySystemInformation — a rotina que a HAL grava no slot
//! HalQuerySystemInformation da HalDispatchTable pública.
//!
//! Como no ntoskrnl 19041, a rotina zera o *ReturnedLength e despacha pela
//! classe (HAL_QUERY_INFORMATION_CLASS). A classe atendida aqui é a
//! HalDisplayBiosInformation (9), que o BasicDisplay.sys consulta para saber
//! se pode usar o BIOS de vídeo: o HalpGetDisplayBiosInformation devolve
//! HalDisplayEmulatedBios (1) com o BIOS de vídeo inicializado
//! (`hal::x86bios`) e HalDisplayNoBios (2) sem ele; o valor de 4 bytes é
//! copiado até o tamanho do buffer, que também vai para o *ReturnedLength, e
//! o status é STATUS_SUCCESS. As outras classes continuam com
//! STATUS_NOT_SUPPORTED, o que o slot devolvia antes de a rotina existir.

use crate::hal::amd64::routine_stubs::Routine;
use crate::hal::x86bios;
use crate::ntos::inc::status::{STATUS_NOT_SUPPORTED, STATUS_SUCCESS};
use crate::ntos::inc::types::{Field, NtStruct};
use crate::ntos::init::exports::{signed_status, Call};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

/// HAL_QUERY_INFORMATION_CLASS::HalDisplayBiosInformation.
pub const HAL_DISPLAY_BIOS_INFORMATION: u32 = 9;

/// HaliQuerySystemInformation(InformationClass, BufferSize, Buffer,
/// ReturnedLength) -> NTSTATUS.
pub fn query(class: u32, buffer_size: u32, buffer: u64, returned_length: u64) -> u32 {
    // SAFETY: PULONG ReturnedLength opcional do chamador de modo kernel.
    let returned = (returned_length != 0).then(|| unsafe { Field::<u32>::at(returned_length) });
    if let Some(returned) = returned {
        returned.set(0);
    }
    match class {
        HAL_DISPLAY_BIOS_INFORMATION => {
            let value = x86bios::display_bios_information().to_le_bytes();
            let length = buffer_size.min(value.len() as u32);
            if let Some(returned) = returned {
                returned.set(length);
            }
            guest::write_bytes(buffer, &value[..length as usize]);
            STATUS_SUCCESS
        }
        _ => STATUS_NOT_SUPPORTED,
    }
}

fn query_system_information(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(query(call.arg(1) as u32, call.arg(2) as u32, call.arg(3), call.arg(4))))
}

/// A rotina por ponteiro da HalDispatchTable.
pub const ROUTINES: &[Routine] = &[Routine { name: "HaliQuerySystemInformation", handler: query_system_information }];
