//! Acesso tipado às estruturas do NT — o equivalente de `Irp->IoStatus.Status`.
//!
//! Drivers e kernel dividem um espaço de endereçamento e o C acessa as
//! estruturas direto, com o layout dos cabeçalhos. Aqui é igual: as structs
//! de [`crate::ntos::inc::types`] (geradas dos símbolos do ntoskrnl) têm o
//! layout exato do kernel real e cada folha escalar é uma célula [`Field<T>`]
//! sobre a própria memória do objeto. Uma referência `&Irp` é o `PIRP`:
//!
//! ```ignore
//! use core::sync::atomic::Ordering;
//! use crate::ntos::inc::types::*;
//!
//! // Fronteira (adaptador de export): o endereço vira referência uma vez.
//! let irp = unsafe { Irp::at(call.arg(1)) };
//! complete(irp, STATUS_SUCCESS);
//!
//! // Rotina de assunto: recebe `&Irp`, como as do NT recebem PIRP.
//! fn complete(irp: &Irp, status: i32) {
//!     irp.io_status.status.set(status);                 // um `mov` volátil
//!     let bytes = irp.io_status.information.get();       // um `mov` volátil
//!     let stack = irp.tail.overlay.current_stack_location.get();
//!     driver.major_function[IRP_MJ_CREATE].set(routine);
//! }
//!
//! // Contadores e locks compartilhados: atômicos de verdade.
//! header.pointer_count.atomic().fetch_add(1, Ordering::SeqCst);
//!
//! // Bitfields: o inteiro de armazenamento mais helpers gerados.
//! if thread.system_thread() != 0 { /* ... */ }
//! thread.set_alertable(1);                               // CAS atômico no MiscFlags
//!
//! // Ponteiro não confiável (vindo do modo usuário): sonda antes, como o
//! // ProbeForRead/__try do NT.
//! let iosb = IoStatusBlock::try_at(user_iosb)?;
//! iosb.status.probe_set(status)?;
//! ```
//!
//! Regras:
//! - `get`/`set` são exatamente um acesso volátil da largura do campo
//!   (`read_volatile`/`write_volatile` no próprio endereço — sem tradução
//!   por acesso e sem dividir 64 bits em dois);
//! - contadores, locks e flags compartilhados usam `atomic()` (instruções
//!   `lock`), nunca ler-modificar-escrever em duas chamadas;
//! - `probe_get`/`probe_set`/`try_at` só para ponteiros não confiáveis: passam
//!   pelos acessos `try_*` de `guest_memory`, que devolvem
//!   `STATUS_ACCESS_VIOLATION` numa página sem mapeamento;
//! - o `unsafe` fica na fronteira ([`NtStruct::at`]): quem converte o
//!   endereço garante que ele aponta para um objeto vivo daquele tipo.
//!
//! Membros que o C sobrepõe (uniões anônimas, `Fill`s) ficam em vistas
//! encadeadas por `Deref` nas structs geradas, então `thread.state`,
//! `iosb.pointer` e `header.type_` resolvem direto pelo nome do NT.
//!
//! De onde vêm os tipos:
//! - layouts do NT presentes nos símbolos do ntoskrnl: `inc/types/*.rs`
//!   (gerados; não editar);
//! - estruturas públicas do WDK/SDK ausentes dos símbolos (OB_CALLBACK_*,
//!   classes de informação, atributos ALPC...): `inc/types/wdk.rs`, mantido à
//!   mão no mesmo estilo;
//! - corpos de objeto e registros próprios do OpenNT (que não são layouts do
//!   NT): structs privadas no componente dono, com a mesma receita:
//!
//! ```ignore
//! // ntos/<componente>/<assunto>.rs
//! use crate::ntos::inc::field::{Field, NtStruct, Reserved};
//! use crate::ntos::inc::types::{Kqueue, ListEntry};
//!
//! /// Corpo do objeto (layout do OpenNT; drivers não o enxergam).
//! #[repr(C)]
//! struct CompletionBody {
//!     queue: Kqueue,               // estruturas do NT entram por valor
//!     pending: Field<u32>,
//!     _pad_44: Reserved<4>,        // padding explícito, também célula
//!     waiters: ListEntry,
//! }
//!
//! // SAFETY: #[repr(C)] só de células (Field/Reserved/NtStruct).
//! unsafe impl NtStruct for CompletionBody {}
//!
//! const _: () = {
//!     assert!(core::mem::size_of::<CompletionBody>() == 0x58);
//!     assert!(core::mem::offset_of!(CompletionBody, waiters) == 0x48);
//! };
//!
//! let body = unsafe { CompletionBody::at(object) };
//! body.pending.atomic().fetch_add(1, Ordering::SeqCst);
//! ```
//!
//! Para membros sobrepostos numa struct própria, siga o padrão das geradas:
//! uma segunda struct do mesmo tamanho e alinhamento com os campos
//! alternativos e um `impl Deref` que reinterpreta `&self`.

use core::cell::UnsafeCell;
use core::mem::{align_of, size_of};
use core::ptr;
use core::sync::atomic::{
    AtomicI16, AtomicI32, AtomicI64, AtomicI8, AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering,
};

use crate::ntos::inc::status::STATUS_ACCESS_VIOLATION;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

/// `STATUS_DATATYPE_MISALIGNMENT` (o que o ProbeForRead levanta).
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const PAGE_SIZE: u64 = 0x1000;

// ---- Field<T> ---------------------------------------------------------------

/// Um campo escalar de uma estrutura do NT, na memória do próprio objeto.
///
/// Mesmo tamanho e alinhamento de `T`. É uma célula: a memória é escrita
/// também por drivers e por outras CPUs, então toda leitura e escrita é um
/// acesso volátil explícito.
#[repr(transparent)]
pub struct Field<T>(UnsafeCell<T>);

// SAFETY: o acesso é sempre por operações voláteis ou atômicas de uma
// instrução; a sincronização entre CPUs é a do protocolo do NT (locks,
// interlocked), exatamente como no C.
unsafe impl<T> Sync for Field<T> {}

impl<T: Copy> Field<T> {
    /// Lê o campo: um único `mov` da largura de `T`.
    #[inline(always)]
    pub fn get(&self) -> T {
        // SAFETY: a referência veio de `NtStruct::at`, que garante o objeto.
        unsafe { ptr::read_volatile(self.0.get()) }
    }

    /// Escreve o campo: um único `mov` da largura de `T`.
    #[inline(always)]
    pub fn set(&self, value: T) {
        // SAFETY: idem `get`.
        unsafe { ptr::write_volatile(self.0.get(), value) }
    }

    /// Endereço do campo (para passar adiante a quem espera um ponteiro).
    #[inline(always)]
    pub fn address(&self) -> u64 {
        self.0.get() as u64
    }

    /// Leitura sondada (ponteiro não confiável): ACCESS_VIOLATION se a
    /// página não estiver mapeada.
    pub fn probe_get(&self) -> Result<T, KernelError> {
        probe_read(self.address())
    }

    /// Escrita sondada (ponteiro não confiável).
    pub fn probe_set(&self, value: T) -> Result<(), KernelError> {
        probe_write(self.address(), value)
    }
}

macro_rules! atomic_fields {
    ($($value:ty => $atomic:ty),* $(,)?) => {$(
        impl Field<$value> {
            /// O campo como atômico (`lock xadd`, `lock cmpxchg`, ...): para
            /// contadores de referência, locks e flags compartilhados.
            #[inline(always)]
            pub fn atomic(&self) -> &$atomic {
                // SAFETY: mesmo tamanho e alinhamento; a célula vive tanto quanto `self`.
                unsafe { <$atomic>::from_ptr(self.0.get()) }
            }
        }
    )*};
}

atomic_fields!(
    u8 => AtomicU8, i8 => AtomicI8, u16 => AtomicU16, i16 => AtomicI16,
    u32 => AtomicU32, i32 => AtomicI32, u64 => AtomicU64, i64 => AtomicI64,
);

#[inline(always)]
const fn low_mask(width: u32) -> u64 {
    if width >= 64 { u64::MAX } else { (1u64 << width) - 1 }
}

macro_rules! bit_storage {
    ($($value:ty => $unsigned:ty),* $(,)?) => {$(
        impl Field<$value> {
            /// Bits `[shift, shift + width)` do armazenamento de um bitfield.
            #[inline(always)]
            pub fn bits(&self, shift: u32, width: u32) -> u64 {
                ((self.get() as $unsigned as u64) >> shift) & low_mask(width)
            }

            /// Grava `value` nos bits `[shift, shift + width)` com um CAS
            /// atômico: bits vizinhos alterados por outra CPU não se perdem.
            #[inline]
            pub fn set_bits(&self, shift: u32, width: u32, value: u64) {
                let mask = (low_mask(width) << shift) as $unsigned;
                let bits = ((value << shift) as $unsigned) & mask;
                let atomic = self.atomic();
                let mut old = atomic.load(Ordering::Relaxed);
                loop {
                    let new = (((old as $unsigned) & !mask) | bits) as $value;
                    match atomic.compare_exchange_weak(old, new, Ordering::SeqCst, Ordering::Relaxed) {
                        Ok(_) => break,
                        Err(current) => old = current,
                    }
                }
            }
        }

        impl UnalignedField<$value> {
            /// Bits `[shift, shift + width)` do armazenamento de um bitfield.
            #[inline(always)]
            pub fn bits(&self, shift: u32, width: u32) -> u64 {
                ((self.get() as $unsigned as u64) >> shift) & low_mask(width)
            }

            /// Como em `Field`, mas sem atomicidade (campo de estrutura empacotada).
            #[inline]
            pub fn set_bits(&self, shift: u32, width: u32, value: u64) {
                let mask = (low_mask(width) << shift) as $unsigned;
                let old = self.get() as $unsigned;
                self.set(((old & !mask) | (((value << shift) as $unsigned) & mask)) as $value);
            }
        }
    )*};
}

bit_storage!(
    u8 => u8, i8 => u8, u16 => u16, i16 => u16, u32 => u32, i32 => u32, u64 => u64, i64 => u64,
);

// ---- UnalignedField<T> --------------------------------------------------------

/// Campo fora do alinhamento natural — só existe nas estruturas que o NT
/// declara com `#pragma pack` (as listas de recursos `CM_*`). Alinhamento 1;
/// os acessos são `read_unaligned`/`write_unaligned` (no x64, um `mov`).
#[repr(C, packed)]
pub struct UnalignedField<T>(UnsafeCell<T>);

// SAFETY: como em `Field`.
unsafe impl<T> Sync for UnalignedField<T> {}

impl<T: Copy> UnalignedField<T> {
    #[inline(always)]
    fn pointer(&self) -> *mut T {
        UnsafeCell::raw_get(ptr::addr_of!(self.0))
    }

    #[inline(always)]
    pub fn get(&self) -> T {
        // SAFETY: a referência veio de `NtStruct::at`.
        unsafe { ptr::read_unaligned(self.pointer()) }
    }

    #[inline(always)]
    pub fn set(&self, value: T) {
        // SAFETY: idem `get`.
        unsafe { ptr::write_unaligned(self.pointer(), value) }
    }

    #[inline(always)]
    pub fn address(&self) -> u64 {
        self.pointer() as u64
    }

    pub fn probe_get(&self) -> Result<T, KernelError> {
        probe_read(self.address())
    }

    pub fn probe_set(&self, value: T) -> Result<(), KernelError> {
        probe_write(self.address(), value)
    }
}

// ---- Reserved<N> --------------------------------------------------------------

/// Bytes de preenchimento explícito do layout (também células: outras vistas
/// do mesmo objeto podem escrever ali).
#[repr(transparent)]
pub struct Reserved<const N: usize>(UnsafeCell<[u8; N]>);

// SAFETY: nunca acessado pelo Rust; só ocupa espaço.
unsafe impl<const N: usize> Sync for Reserved<N> {}

// ---- NtStruct ---------------------------------------------------------------

/// Estrutura do NT com layout exato: a fronteira endereço -> referência.
///
/// # Safety
/// Só para tipos `#[repr(C)]` compostos de células (`Field`, `UnalignedField`,
/// `Reserved` e outras `NtStruct`), como os gerados em `inc::types`.
pub unsafe trait NtStruct: Sized + Sync {
    /// `sizeof` do tipo no NT.
    const SIZE: u64 = size_of::<Self>() as u64;

    /// O objeto em `address`, como o C faz com um `PIRP`.
    ///
    /// # Safety
    /// `address` aponta para um objeto vivo deste tipo, alinhado, em memória
    /// mapeada para o kernel (memória do próprio kernel ou de drivers).
    #[inline(always)]
    unsafe fn at(address: u64) -> &'static Self {
        debug_assert!(address != 0 && address % align_of::<Self>() as u64 == 0);
        // SAFETY: garantido pelo chamador.
        unsafe { &*(address as *const Self) }
    }

    /// `count` objetos consecutivos a partir de `address` (vetores do NT).
    ///
    /// # Safety
    /// Como em [`NtStruct::at`], para o vetor inteiro.
    #[inline(always)]
    unsafe fn array_at(address: u64, count: usize) -> &'static [Self] {
        debug_assert!(address != 0 && address % align_of::<Self>() as u64 == 0);
        // SAFETY: garantido pelo chamador.
        unsafe { core::slice::from_raw_parts(address as *const Self, count) }
    }

    /// Ponteiro não confiável: sonda `[address, address + SIZE)` (nulo,
    /// alinhamento e cada página) antes de criar a referência — o
    /// `ProbeForRead` do NT. Os acessos seguintes a um objeto de modo usuário
    /// devem continuar usando `probe_get`/`probe_set`.
    fn try_at(address: u64) -> Result<&'static Self, KernelError> {
        probe_range(address, size_of::<Self>() as u64, align_of::<Self>() as u64)?;
        // SAFETY: o intervalo inteiro está mapeado e alinhado.
        Ok(unsafe { &*(address as *const Self) })
    }

    /// Endereço do objeto (o `PVOID` para passar adiante).
    #[inline(always)]
    fn address(&self) -> u64 {
        self as *const Self as u64
    }
}

// SAFETY: uma célula é ela mesma um objeto válido de layout fixo: um
// parâmetro de saída escalar (`PULONG`, `PHANDLE`, `PKSPIN_LOCK`...) vira
// `Field::<u32>::at(endereço)` / `Field::<u64>::try_at(endereço)`.
unsafe impl<T: Copy> NtStruct for Field<T> {}

// ---- sondas -------------------------------------------------------------------

fn probe_range(address: u64, length: u64, alignment: u64) -> Result<(), KernelError> {
    if address == 0 {
        return Err(guest::address_fault(address));
    }
    if address % alignment != 0 {
        return Err(KernelError::with_status(
            alloc::format!("datatype misalignment at {address:#x}"),
            STATUS_DATATYPE_MISALIGNMENT,
        ));
    }
    let Some(end) = address.checked_add(length) else {
        return Err(KernelError::with_status("probe range overflow", STATUS_ACCESS_VIOLATION));
    };
    let mut page = address;
    while page < end {
        guest::try_read8(page)?;
        page = (page & !(PAGE_SIZE - 1)) + PAGE_SIZE;
    }
    if length > 0 {
        guest::try_read8(end - 1)?;
    }
    Ok(())
}

/// Leitura sondada de um `T` por largura (um acesso quando a largura é
/// 1/2/4/8 e o valor não cruza página).
fn probe_read<T: Copy>(address: u64) -> Result<T, KernelError> {
    let raw: u64 = match size_of::<T>() {
        1 => guest::try_read8(address)? as u64,
        2 => guest::try_read16(address)? as u64,
        4 => guest::try_read32(address)? as u64,
        8 => guest::try_read64_single(address)?,
        length => {
            let bytes = guest::try_read_bytes(address, length)?;
            // SAFETY: `bytes` tem exatamente `size_of::<T>()` bytes; `T: Copy`
            // é um tipo de campo (inteiro, enum newtype ou vetor deles).
            return Ok(unsafe { ptr::read_unaligned(bytes.as_ptr() as *const T) });
        }
    };
    // SAFETY: `T` tem 1/2/4/8 bytes; os bytes baixos de `raw` (little-endian) são o valor.
    Ok(unsafe { ptr::read_unaligned(&raw as *const u64 as *const T) })
}

/// Escrita sondada de um `T` por largura.
fn probe_write<T: Copy>(address: u64, value: T) -> Result<(), KernelError> {
    let length = size_of::<T>();
    let mut raw = 0u64;
    if length <= 8 {
        // SAFETY: copia `length <= 8` bytes do valor para os bytes baixos de `raw`.
        unsafe { ptr::copy_nonoverlapping(&value as *const T as *const u8, &mut raw as *mut u64 as *mut u8, length) };
    }
    match length {
        1 => guest::try_write8(address, raw as u8),
        2 => guest::try_write16(address, raw as u16),
        4 => guest::try_write32(address, raw as u32),
        8 => guest::try_write64(address, raw),
        _ => {
            // SAFETY: vista em bytes do próprio valor.
            let bytes = unsafe { core::slice::from_raw_parts(&value as *const T as *const u8, length) };
            guest::try_write_bytes(address, bytes)
        }
    }
}
