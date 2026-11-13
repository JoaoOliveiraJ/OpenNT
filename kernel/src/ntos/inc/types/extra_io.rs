//! Complementos de layout do I/O Manager ausentes dos símbolos do 19041.
//!
//! - `_IRP` + 0xC8: o ponteiro `IrpExtension` (a `_IOP_IRP_EXTENSION` do
//!   IRP). O kernel 19041 o grava logo depois de
//!   `Tail.Overlay.OriginalFileObject` (IoAllocateIrpEx, IoGetActivityIdIrp);
//!   nos símbolos o intervalo só aparece coberto pela união `Tail.Apc`
//!   (`_KAPC.ApcStateIndex`..), então a struct gerada o deixa como
//!   preenchimento. O acesso aqui é a mesma célula `Field<u64>`.

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::Irp;

/// Offset do `IrpExtension` no `_IRP` (últimos 8 bytes do `Tail`).
const IRP_EXTENSION_OFFSET: usize = 0xC8;

const _: () = {
    assert!(IRP_EXTENSION_OFFSET + 8 == core::mem::size_of::<Irp>());
    assert!(core::mem::offset_of!(Irp, tail) + 0x50 == IRP_EXTENSION_OFFSET);
};

/// `Irp->Tail.Overlay.IrpExtension` (sem membro nomeado nos símbolos).
pub trait IrpExtensionField {
    fn irp_extension(&self) -> &Field<u64>;
}

impl IrpExtensionField for Irp {
    #[inline(always)]
    fn irp_extension(&self) -> &Field<u64> {
        // SAFETY: os 8 bytes em +0xC8 pertencem ao próprio `_IRP` (asserção acima)
        // e `Field<u64>` é uma célula de layout fixo, alinhada a 8 como o IRP.
        unsafe { Field::<u64>::at(self.address() + IRP_EXTENSION_OFFSET as u64) }
    }
}
