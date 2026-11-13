//! RtlpIsAppContainer.
//!
//! No ramo explícito recebe o endereço de TOKEN usado por
//! SeQueryInformationToken. Sem token, abre o da thread (ou duplica o
//! primário) e passa o *handle* adiante, como a rotina original; a leitura
//! de TokenFlags num handle não mapeado é uma falha de memória.

use crate::ntos::se::token::{handles as token_handles, tokens};
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ps::{previous_mode, process};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

const STATUS_NO_TOKEN: u32 = 0xC000_007C;
const TOKEN_FLAGS: u64 = 0xC8;
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
    guest::write8(output, 0);
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
        // Classe 29 de SeQueryInformationToken: TOKEN.TokenFlags direto.
        let flags = guest::try_read32(token + TOKEN_FLAGS)?;
        guest::write8(output, (flags & TOKEN_LOWBOX != 0) as u8);
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
