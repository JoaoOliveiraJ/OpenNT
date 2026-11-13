//! Estruturas do NT — layouts do Windows 10 19041 gerados a partir dos
//! símbolos do ntoskrnl (`build/symbols/ntkrnlmp.pdb`).
//!
//! Gerado; não editar à mão. Para regenerar, rode o gerador (leitor de PDB
//! em Python, mantido fora da árvore) a partir da raiz do repositório:
//!
//! ```text
//! python -P gen_nt_types.py build/symbols/ntkrnlmp.pdb .
//! ```
//!
//! Ele reescreve este diretório (menos `wdk.rs`, mantido à mão: estruturas
//! públicas do WDK/SDK que não constam dos símbolos) e o bloco de provas no
//! fim de `nt_abi.rs`. Cada struct é `#[repr(C)]` com o tamanho e os offsets exatos do kernel
//! real — conferidos em compilação por `size_of`/`offset_of!` — e folhas
//! escalares `Field<T>` (uma célula volátil por campo; ponteiros são
//! `Field<u64>`, com o tipo apontado no comentário). Membros que o C
//! sobrepõe (uniões e structs anônimas) ficam em vistas `<Tipo>ViewN`
//! encadeadas por `Deref`, então todo nome do NT é acessado direto:
//! `irp.io_status.status`, `thread.state`, `header.type_`. Bitfields são o
//! inteiro de armazenamento mais `<NOME>_SHIFT`/`<NOME>_MASK` e os métodos
//! `<nome>()`/`set_<nome>()`. Enums são newtypes inteiros com as constantes
//! do NT. Membros `...Fill` que só posicionam outros campos são omitidos.
//!
//! `dead_code` fica liberado aqui como em `nt_abi.rs`: é um cabeçalho — a
//! maior parte dos layouts só passa a ser usada conforme o código migra.
#![allow(dead_code)]

pub use crate::ntos::inc::field::{Field, NtStruct, Reserved, UnalignedField};
use crate::ntos::mm::guest_memory::GuestScalar;

mod alpc;
mod cm;
mod etw;
mod ex;
mod hal;
mod io;
mod ke;
mod mm;
mod ob;
mod po;
mod ps;
mod rtl;
mod se;
mod wdk;

pub use alpc::*;
pub use cm::*;
pub use etw::*;
pub use ex::*;
pub use hal::*;
pub use io::*;
pub use ke::*;
pub use mm::*;
pub use ob::*;
pub use po::*;
pub use ps::*;
pub use rtl::*;
pub use se::*;
pub use wdk::*;
