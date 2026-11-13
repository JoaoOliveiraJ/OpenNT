//! IoConvertFileHandleToKernelHandle.
//!
//! Converte um handle de arquivo sem reabrir o caminho nem ampliar os
//! direitos concedidos; a duplicação cria uma entrada real na tabela do
//! System e a identidade do FILE_OBJECT é conferida antes de publicar.

use crate::ntos::ke::irql;
use crate::ntos::ob::handles::file as file_handles;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

pub fn convert(source: u64, access_mode: u8, desired_access: u32, skip_access_precheck: bool, output: u64) -> Result<u32, KernelError> {
    // Esperas do Object Manager exigem até APC_LEVEL.
    if irql::get_irql() > 1 {
        return Err(KernelError::new("file handle conversion above APC_LEVEL"));
    }
    // A saída fica nula mesmo quando a origem não é válida.
    guest::write64(output, 0);
    if source == 0 {
        return Ok(0);
    }
    let mut source_reference = match file_handles::reference(source, access_mode)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let mut duplicated: Option<u64> = None;
    let mut target_reference = None;
    let result = (|| -> Result<u32, KernelError> {
        // A pré-checagem precede o mapeamento dos direitos genéricos.
        if !skip_access_precheck && source_reference.access & desired_access != desired_access {
            return Ok(0xC000_0022);
        }
        let handle = match file_handles::duplicate_to_kernel(source, desired_access)? {
            Ok(handle) => handle,
            Err(status) => return Ok(status),
        };
        duplicated = Some(handle);
        let target = match file_handles::reference(handle, 0)? {
            Ok(target) => target,
            Err(status) => return Ok(status),
        };
        let same = target.pointer == source_reference.pointer;
        target_reference = Some(target);
        if !same {
            return Ok(0xC000_0024);
        }
        guest::write64(output, handle);
        // A propriedade passa ao chamador só depois de publicar a saída.
        duplicated = None;
        Ok(0)
    })();
    if let Some(handle) = duplicated {
        file_handles::close_kernel(handle)?;
    }
    if let Some(mut target) = target_reference {
        target.release()?;
    }
    source_reference.release()?;
    result
}
