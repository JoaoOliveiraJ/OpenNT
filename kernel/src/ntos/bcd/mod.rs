//! A biblioteca BCD do kernel: o mutante de sincronização do repositório.
//!
//! BcdInitializeBcdSyncMutant (ntoskrnl 19041 rva 0xa73808), chamado pelo
//! Phase1InitializationDiscard logo depois do DbgkInitialize: um
//! ZwCreateMutant(MUTANT_ALL_ACCESS, `\KernelObjects\BcdSyncMutant`,
//! OBJ_PERMANENT | OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, sem dono) com o
//! descritor BiBcdMutantDescriptor, cujo handle fica no BcdMutantHandle.
//!
//! O BiBcdMutantDescriptor é um descritor self-relative só com DACL:
//! SYSTEM e Administrators com 0x120001 (SYNCHRONIZE | READ_CONTROL |
//! MUTANT_QUERY_STATE). A biblioteca BCD estática do wininit, o bcd.dll e o
//! reagent o abrem com ZwOpenMutant(SYNCHRONIZE) (BiGetCurrentBcdMutantHandle)
//! e esperam nele antes de abrir o repositório.

use alloc::vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager;
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::ntos::se::model::{sid, Ace, SecurityPolicy};
use crate::rtl::KernelError;

pub const BCD_SYNC_MUTANT: &str = "\\KernelObjects\\BcdSyncMutant";

/// SYNCHRONIZE | READ_CONTROL | MUTANT_QUERY_STATE.
const QUERY_AND_SYNCHRONIZE: u32 = 0x12_0001;
const DACL_SECURITY_INFORMATION: u32 = 4;

/// BcdInitializeBcdSyncMutant: cria o mutante uma vez. O descritor do objeto
/// sai do SeAssignSecurity do ObInsertObject com o BiBcdMutantDescriptor
/// explícito.
pub fn initialize_sync_mutant() -> Result<(), KernelError> {
    if object_manager::lookup(BCD_SYNC_MUTANT).is_some() {
        return Ok(());
    }
    let explicit = SecurityPolicy { dacl: Some(vec![Ace::allow(sid(5, &[18]), QUERY_AND_SYNCHRONIZE), Ace::allow(sid(5, &[32, 544]), QUERY_AND_SYNCHRONIZE)]), ..SecurityPolicy::default() };
    let bytes = crate::ntos::se::object_security::encode(&explicit, DACL_SECURITY_INFORMATION);
    let descriptor = guest::alloc_bytes(bytes.len() as u64);
    if descriptor == 0 {
        return Err(KernelError::with_status("BcdSyncMutant: sem memoria", 0xC000_009A));
    }
    guest::write_bytes(descriptor, &bytes);
    let parent = object_manager::lookup("\\KernelObjects");
    let mutant_type = crate::ntos::ob::object_types::user_type("mutant").ok_or_else(|| KernelError::new("tipo Mutant ausente"))?;
    let assigned = crate::ntos::ob::object_security::assign_new(&mutant_type, parent, descriptor, false);
    guest::free_bytes(descriptor);
    let policy = assigned.map_err(|status| KernelError::with_status("BcdSyncMutant: SeAssignSecurity", status))?;
    let mutant = crate::ntos::ps::user::mutants::create_kernel_mutant(BCD_SYNC_MUTANT)?;
    dispatcher_objects::set_security(mutant.pointer, policy);
    Ok(())
}
