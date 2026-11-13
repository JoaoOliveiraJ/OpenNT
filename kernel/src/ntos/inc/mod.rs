//! Cabeçalhos do NT — o `inc` da árvore do kernel: os layouts das estruturas
//! (gerados dos símbolos do ntoskrnl, em `types`), o acesso tipado a elas
//! (`field`), as constantes de offset legadas (`nt_abi`) e os NTSTATUS.

pub mod field;
pub mod nt_abi;
pub mod status;
pub mod types;

pub use field::{Field, NtStruct};
