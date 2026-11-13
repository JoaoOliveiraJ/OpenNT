//! Tabelas de serviço adicionais: KeAddSystemServiceTable,
//! KeRemoveSystemServiceTable e a compactação KeCompactServiceTable.
//!
//! Segue o ntoskrnl 19041:
//! - KeAddSystemServiceTable(Base, Count, Limit, Number, Index): o índice tem
//!   de ser 1 ou 2. O índice 1 vai para KeServiceDescriptorTableShadow[1]
//!   { Base, Limit (ULONG), Number }, recusado se KeServiceDescriptorTable[1]
//!   ou Shadow[1] já têm Base; o Count é ignorado. O índice 2 vai para
//!   KeServiceDescriptorTableFilter[1], recusado se ocupado. A soma de
//!   KiTableInformation (PatchGuard) não tem equivalente no OpenNT.
//! - KeRemoveSystemServiceTable só age na sessão 0: MmGetSessionIdEx != 0
//!   (inclusive -1, sem sessão ou processo de sistema) devolve TRUE sem mudar
//!   nada; índice fora de 1..2 ou as três entradas [1] vazias devolvem FALSE.
//! - A tabela que o win32k.sys passa já está no formato de memória: no disco
//!   a W32pServiceTable guarda RVAs e a W32pArgumentTable bytes de argumentos
//!   (4 por argumento de pilha), e o loader as converte ao carregar o
//!   win32k.sys pela SystemExtendServiceTableInformation
//!   (MmLoadSystemImageEx com o bit 4 -> MiCompactServiceTable, em
//!   `mm::sysload`), que chama [`compact_entries`] — o KeCompactServiceTable:
//!   `((RVA + ImageBase - Table) << 4) | (bytes >> 2)` em 32 bits, o formato
//!   que o KiSystemCall64 (e o `nt_service_lookup` do OpenNT) decodifica. O
//!   KiLockServiceTable que o segue é PatchGuard e não tem equivalente.
//!
//! Os descritores são os vivos do `ex::service_table`, decodificados em toda
//! syscall: uma tabela adicionada aqui é a que a syscall despacha. A tabela
//! filtro não tem armazenamento no OpenNT e fica aqui. Num sistema novo o
//! Shadow[1] está vazio e o win32k o recebe.

use alloc::vec::Vec;

use crate::ntos::ex::service_table;
use crate::ntos::inc::types::{Eprocess, Field, MmSessionSpace, NtStruct};
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};

/// KeServiceDescriptorTableFilter[1]: Base, Limit, Number.
static FILTER: SpinLock<[u64; 3]> = SpinLock::new([0; 3]);

/// MmGetSessionIdEx: -1 sem sessão ou para o processo de sistema.
fn session_id(process: &Eprocess) -> u32 {
    let session = process.session.get();
    if session == 0 || process.system_process() != 0 {
        return u32::MAX;
    }
    // SAFETY: EPROCESS.Session aponta para a MM_SESSION_SPACE viva.
    unsafe { MmSessionSpace::at(session) }.session_id.get()
}

/// KeAddSystemServiceTable: TRUE quando a entrada estava livre e foi publicada.
pub fn add(base: u64, limit: u32, number: u64, index: u32) -> Result<bool, KernelError> {
    if index.wrapping_sub(1) > 1 {
        return Ok(false);
    }
    if index == 2 {
        let mut filter = FILTER.lock();
        if filter[0] != 0 {
            return Ok(false);
        }
        *filter = [base, limit as u64, number];
        return Ok(true);
    }
    let (normal, shadow) = service_table::second_table_bases()?;
    if normal != 0 || shadow != 0 {
        return Ok(false);
    }
    service_table::publish_shadow_second_table(base, limit, number)?;
    Ok(true)
}

/// KeRemoveSystemServiceTable(Index).
pub fn remove(index: u32) -> Result<bool, KernelError> {
    // SAFETY: o processo corrente está vivo.
    if session_id(unsafe { Eprocess::at(process::get_current_process()) }) != 0 {
        return Ok(true);
    }
    if index.wrapping_sub(1) > 1 {
        return Ok(false);
    }
    let (normal, shadow) = service_table::second_table_bases()?;
    let mut filter = FILTER.lock();
    if normal == 0 && shadow == 0 && filter[0] == 0 {
        return Ok(false);
    }
    if index == 1 {
        service_table::clear_shadow_second_table()?;
    } else {
        *filter = [0; 3];
    }
    Ok(true)
}

/// KeCompactServiceTable: as entradas de memória de uma tabela de disco.
/// `routines` são os RVAs (relativos a `image_base`), `arguments` os bytes
/// de argumentos; a tabela fica em `table`. Aritmética de 32 bits, como no
/// binário.
pub fn compact_entries(table: u64, image_base: u64, routines: &[Field<u32>], arguments: &[Field<u8>]) -> Vec<u32> {
    routines
        .iter()
        .zip(arguments)
        .map(|(routine, bytes)| (routine.get().wrapping_sub(table as u32).wrapping_add(image_base as u32) << 4) | (bytes.get() >> 2) as u32)
        .collect()
}

/// A entrada filtro registrada (Base, Limit, Number).
pub fn filter_entry() -> [u64; 3] {
    *FILTER.lock()
}

/// Só para o self-test: a tabela filtro volta vazia para que o win32k real
/// ainda possa registrá-la (como `ex::service_table::self_test_reset`).
pub fn self_test_reset() {
    *FILTER.lock() = [0; 3];
}
