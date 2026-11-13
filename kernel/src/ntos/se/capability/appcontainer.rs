//! RtlpIsAppContainer.
//!
//! No ramo explícito recebe o endereço de TOKEN usado por
//! SeQueryInformationToken. Sem token, abre o da thread (ou duplica o
//! primário) e passa o *handle* adiante, como a rotina original; a leitura
//! de TokenFlags num handle não mapeado é uma falha de memória.

use core::mem::offset_of;

use crate::ntos::se::out;
use crate::ntos::se::token::tokens::TokenBody;
use crate::ntos::se::token::{handles as token_handles, tokens};
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ps::{previous_mode, process};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

const STATUS_NO_TOKEN: u32 = 0xC000_007C;
const TOKEN_LOWBOX: u32 = 0x4000;

/// Abre o token da thread corrente ou uma cópia de impersonação do
/// primário; `Ok(Err(status))` são falhas NTSTATUS dos serviços.
fn open_temporary(frame: u64, handle: &mut u64) -> Result<u32, KernelError> {
    let status = previous_mode::with_kernel(|| token_handles::open_thread(u64::MAX - 1, 8, true, 0x200, frame, false))??;
    *handle = guest::read64(frame);
    if status != STATUS_NO_TOKEN {
        return Ok(status);
    }
    previous_mode::with_kernel(|| -> Result<u32, KernelError> {
        let Some(primary) = process::get_primary_token(process::get_current_process()) else {
            return Ok(STATUS_NO_TOKEN);
        };
        let primary_handle = token_handles::create(primary, 0xA, 0x200, false)?;
        let result = tokens::duplicate(primary, 2, false, 2).and_then(|duplicate| {
            let created = token_handles::create(duplicate, 8, 0x200, false);
            let _ = tokens::release(duplicate);
            created
        });
        token_handles::close_native(primary_handle);
        *handle = result?;
        Ok(0)
    })?
}

pub fn check(token_or_handle: u64, output: u64) -> Result<u32, KernelError> {
    out::<u8>(output).set(0);
    let mut token = token_or_handle;
    let mut temporary = 0u64;
    let mut frame = 0u64;
    let result = (|| {
        if token == 0 {
            frame = match kernel_pool::allocate(8, AllocateOptions { tag: 0x7041_7043, zero: true, ..Default::default() }) {
                Ok(pointer) => pointer,
                Err(_) => return Ok(0xC000_0017),
            };
            let status = match open_temporary(frame, &mut temporary) {
                Ok(status) => status,
                // Só as falhas dos serviços de abertura/duplicação viram NTSTATUS.
                Err(error) if error.status != 0 => return Ok(error.status),
                Err(error) => return Err(error),
            };
            if status & 0x8000_0000 != 0 {
                return Ok(status);
            }
            token = temporary;
        }
        // Classe 29 de SeQueryInformationToken: TokenFlags direto do corpo
        // (sondado: no ramo sem token o valor ainda é um handle).
        let flags = guest::try_read::<u32>(token + offset_of!(TokenBody, token_flags) as u64)?;
        out::<u8>(output).set((flags & TOKEN_LOWBOX != 0) as u8);
        Ok(0)
    })();
    if temporary != 0 {
        let _ = previous_mode::with_kernel(|| token_handles::close_native(temporary));
    }
    if frame != 0 {
        let _ = kernel_pool::free(frame, None);
    }
    result
}

/// SeIsParentOfChildAppContainer(SessionId, ParentLowboxNumber,
/// ChildLowboxNumber) (ntoskrnl 19041, 0x91c7c0 -> SepIsParentOfChildAppContainer
/// 0x9255ec): com qualquer número LowBox zero devolve FALSE; senão procura as
/// duas entradas no mapa de números LowBox da sessão (g_SessionLowboxArray /
/// SepGetTokenSessionMapEntry + SepFindMatchingLowBoxNumberEntries) e compara
/// os SIDs de pacote com RtlIsParentOfChildAppContainer
/// (`rtl::security::is_parent_of_child_app_container`).
///
/// Stub honesto: o OpenNT não atribui números LowBox (NtCreateLowBoxToken
/// não existe), então o mapa da sessão é vazio, a busca falha e o resultado é
/// FALSE — o mesmo que o NT devolve para números sem entrada.
pub fn is_parent_of_child_lowbox(_session_id: u32, parent_lowbox_number: u32, child_lowbox_number: u32) -> bool {
    if parent_lowbox_number == 0 || child_lowbox_number == 0 {
        return false;
    }
    // Mapa LowBox da sessão vazio: nenhuma das duas entradas é encontrada.
    false
}
