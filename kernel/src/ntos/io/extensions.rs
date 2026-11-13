//! Extensões de FILE_OBJECT e de IRP — io\iomgr (IopAllocateFileObjectExtension,
//! IopAllocateIrpExtension, IopIrpHasExtensionType...).
//!
//! FILE_OBJECT.FileObjectExtension aponta para um IOP_FILE_OBJECT_EXTENSION
//! (FoExtFlags, FoExtPerTypeExtension[9] — [0] parâmetros de transação, [7]
//! contexto do silo — e FoIoPriorityHint = IO_PRIORITY_HINT + 1).
//!
//! `Irp->IrpExtension` (`IrpExtensionField`, +0xC8) aponta para um
//! IOP_IRP_EXTENSION ('IrpX', NonPagedPoolNx) quando IRP.AllocationFlags tem
//! 0x40; TypesAllocated é o bitmap dos tipos. A união de +0x28 serve os tipos
//! 1 (Timestamp), 4 (ZeroingOffset), 5 (FsTrackOffset) e 7
//! (AdapterCryptoParameters); CopyInformation (tipo 9) fica em +0x40. O OpenNT
//! guarda a genérica e o ActivityId (tipos 0..2) na tabela de
//! `io/irp_extension.rs`, então o bit 0x80 (genérica embutida) nunca é ligado
//! por ele; a migração do NT continua aqui por fidelidade.
//!
//! As funções públicas recebem endereços (o FILE_OBJECT/IRP do driver) porque
//! outros assuntos (io-file-system-support, io-paging) as chamam assim; a
//! conversão para o tipo é feita uma vez na entrada.

use core::sync::atomic::Ordering;

use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::types::extra_io::IrpExtensionField;
use crate::ntos::inc::types::extra_fs_ntfs::IopIrpExtension;
use crate::ntos::inc::types::{Field, FileObject, IopFileObjectExtension, IopPriorityHint, Irp, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_pool;
use crate::rtl::KernelError;

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_ALREADY_COMMITTED: u32 = 0xC000_0021;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
pub const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
pub const STATUS_NOT_FOUND: u32 = 0xC000_0225;

const IRP_EXTENSION_INLINE: u8 = 0x80;
const IRP_EXTENSION_ALLOCATED: u8 = 0x40;
const IRP_EXTENSION_TAG: u32 = 0x5870_7249; // 'IrpX'
pub const IRP_EXTENSION_GENERIC: u32 = 2;
pub const IRP_EXTENSION_ZEROING_OFFSET: u32 = 4;
pub const IRP_EXTENSION_TRACK_OFFSET: u32 = 5;
pub const IRP_EXTENSION_COPY_INFORMATION: u32 = 9;
/// Tipos que dividem a união em +0x28 (1, 4, 5, 7).
const UNION_TYPES: u16 = 0xB2;
const COPY_TYPES: u16 = 0x200;
const FO_EXT_TRANSACTION_PARAMETERS: usize = 0;
const FO_EXT_SILO: usize = 7;

fn file_object(file: u64) -> &'static FileObject {
    // SAFETY: os chamadores passam um FILE_OBJECT vivo (do driver ou do I/O Manager).
    unsafe { FileObject::at(file) }
}

fn irp_at(irp: u64) -> &'static Irp {
    // SAFETY: os chamadores passam um IRP vivo.
    unsafe { Irp::at(irp) }
}

fn existing_file_extension(file: &FileObject) -> Option<&'static IopFileObjectExtension> {
    let extension = file.file_object_extension.get();
    // SAFETY: FileObjectExtension, quando presente, é um IOP_FILE_OBJECT_EXTENSION.
    (extension != 0).then(|| unsafe { IopFileObjectExtension::at(extension) })
}

// ---- FILE_OBJECT ---------------------------------------------------------------

/// IopAllocateFileObjectExtension (RVA 0x22bb40): devolve a extensão
/// existente ou instala uma nova zerada; `None` = sem memória. O NT instala
/// sob o IrpListLock; a troca atômica de 0 publica o mesmo resultado.
pub fn file_object_extension(file: u64) -> Result<Option<u64>, KernelError> {
    let file = file_object(file);
    let current = file.file_object_extension.get();
    if current != 0 {
        return Ok(Some(current));
    }
    // A arena do convidado: o IopDeleteFile do OpenNT a libera com o corpo.
    let extension = guest::alloc_bytes(IopFileObjectExtension::SIZE);
    if extension == 0 {
        return Ok(None);
    }
    match file.file_object_extension.atomic().compare_exchange(0, extension, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(_) => Ok(Some(extension)),
        Err(previous) => {
            guest::free_bytes(extension);
            Ok(Some(previous))
        }
    }
}

/// Libera a extensão de um FILE_OBJECT destruído (IopDeleteFile).
pub fn free_file_object_extension(file: u64) {
    let extension = file_object(file).file_object_extension.atomic().swap(0, Ordering::SeqCst);
    if extension != 0 {
        guest::free_bytes(extension);
    }
}

/// IoSetIoPriorityHintIntoFileObject (RVA 0x505fa0).
pub fn set_file_object_priority_hint(file: &FileObject, hint: u32) -> Result<u32, KernelError> {
    if hint >= 5 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let Some(extension) = file_object_extension(file.address())? else { return Ok(STATUS_INSUFFICIENT_RESOURCES) };
    // SAFETY: devolvida acima, viva enquanto o FILE_OBJECT viver.
    unsafe { IopFileObjectExtension::at(extension) }.fo_io_priority_hint.set(IopPriorityHint(hint as i32 + 1));
    Ok(STATUS_SUCCESS)
}

/// FoIoPriorityHint (0 = nenhum; senão IO_PRIORITY_HINT + 1).
pub fn file_object_priority_hint(file: &FileObject) -> u32 {
    existing_file_extension(file).map_or(0, |extension| extension.fo_io_priority_hint.get().0 as u32)
}

/// IoGetTransactionParameterBlock (RVA 0x2e6b70): FoExtPerTypeExtension[0].
pub fn transaction_parameter_block(file: &FileObject) -> u64 {
    existing_file_extension(file).map_or(0, |extension| extension.fo_ext_per_type_extension[FO_EXT_TRANSACTION_PARAMETERS].get())
}

/// IoGetSilo (RVA 0x3618f0): FoExtPerTypeExtension[7]->Silo (o segundo ponteiro do bloco).
pub fn file_object_silo(file: &FileObject) -> u64 {
    let context = existing_file_extension(file).map_or(0, |extension| extension.fo_ext_per_type_extension[FO_EXT_SILO].get());
    if context == 0 {
        return 0;
    }
    // SAFETY: o bloco do silo é { PVOID; PESILO Silo; ... } do I/O Manager.
    let block = unsafe { Field::<u64>::array_at(context, 2) };
    block[1].get()
}

// ---- IRP -----------------------------------------------------------------------

fn irp_extension(irp: u64) -> u64 {
    irp_at(irp).irp_extension().get()
}

fn extension_at(extension: u64) -> &'static IopIrpExtension {
    // SAFETY: Irp->IrpExtension com AllocationFlags & 0x40 aponta para um IOP_IRP_EXTENSION.
    unsafe { IopIrpExtension::at(extension) }
}

/// `ZeroingOffset` (ULONG) da união de +0x28 da extensão (vizinha de
/// `FsTrackOffsetBlob`; o tipo 4 exclui o 5 em `irp_extension_combination_valid`).
fn zeroing_offset(extension: &IopIrpExtension) -> &'static Field<u32> {
    // SAFETY: os 4 bytes baixos da célula de 8 bytes da união, na mesma extensão.
    unsafe { Field::<u32>::at(extension.fs_track_offset_blob.address()) }
}

/// IopIrpHasExtensionType (RVA 0x2e6690).
pub fn irp_has_extension_type(irp: u64, kind: u32) -> bool {
    let packet = irp_at(irp);
    if (packet.allocation_flags.get() as i8) < 0 {
        return kind == IRP_EXTENSION_GENERIC;
    }
    let extension = packet.irp_extension().get();
    extension != 0 && (extension_at(extension).types_allocated.get() >> kind) & 1 != 0
}

/// IopAllocateIrpExtension (RVA 0x2e6980), para os tipos alocados (não o 2).
pub fn allocate_irp_extension(irp: u64, kind: u32) -> Result<u64, KernelError> {
    let packet = irp_at(irp);
    let flags = packet.allocation_flags.get();
    let current = packet.irp_extension().get();
    if current != 0 && flags & IRP_EXTENSION_INLINE == 0 {
        let types = &extension_at(current).types_allocated;
        types.set(types.get() | (1 << kind));
        return Ok(current);
    }
    let address = pool_allocation::allocate_tagged(0x200, IopIrpExtension::SIZE, IRP_EXTENSION_TAG)?;
    if address == 0 {
        return Ok(0);
    }
    guest::write_bytes(address, &[0u8; IopIrpExtension::SIZE as usize]);
    let extension = extension_at(address);
    let mut types = 1u16 << kind;
    if flags & IRP_EXTENSION_INLINE != 0 {
        // A genérica embutida (dword em +0xC8) migra para a extensão.
        types |= 1 << IRP_EXTENSION_GENERIC;
        extension.generic_extension.set(current as u32);
        packet.allocation_flags.set((flags & 0x3F) | IRP_EXTENSION_ALLOCATED);
    } else {
        packet.allocation_flags.set(flags | IRP_EXTENSION_ALLOCATED);
    }
    extension.types_allocated.set(types);
    packet.irp_extension().set(address);
    extension.extension_flags.set(extension.extension_flags.get() | 1);
    Ok(address)
}

/// IopIrpHasValidCombinationOfExtensionTypes (RVA 0x5079e0).
pub fn irp_extension_combination_valid(irp: u64, kind: u32) -> bool {
    let address = irp_extension(irp);
    if (irp_at(irp).allocation_flags.get() as i8) < 0 || address == 0 {
        return true;
    }
    let extension = extension_at(address);
    let bit = 1u16 << kind;
    let types = extension.types_allocated.get();
    if UNION_TYPES & bit == 0 {
        return COPY_TYPES & bit == 0 || types & COPY_TYPES == 0 || types & COPY_TYPES == bit;
    }
    if types & UNION_TYPES == 0 || types & UNION_TYPES == bit {
        return true;
    }
    if kind == 1 || types & 2 == 0 {
        return false;
    }
    // O Timestamp (tipo 1) cede a união: o NT limpa o bit 0 e zera +0x28.
    extension.fs_track_offset_blob.set(0);
    extension.types_allocated.set(types & 0xFFFE);
    true
}

/// IopFreeIrpExtension(Irp, -1, TRUE) no IoFreeIrp: limpa a genérica
/// embutida ou libera a extensão alocada.
pub fn free_irp_extension(irp: u64) -> Result<(), KernelError> {
    let packet = irp_at(irp);
    let flags = packet.allocation_flags.get();
    if flags & IRP_EXTENSION_INLINE != 0 {
        packet.irp_extension().set(0);
        packet.allocation_flags.set(flags & 0x7F);
        return Ok(());
    }
    let address = packet.irp_extension().get();
    if address == 0 {
        return Ok(());
    }
    extension_at(address).types_allocated.set(0);
    if flags & IRP_EXTENSION_ALLOCATED != 0 {
        kernel_pool::free(address, Some(IRP_EXTENSION_TAG))?;
        packet.allocation_flags.set(flags & !IRP_EXTENSION_ALLOCATED);
        packet.irp_extension().set(0);
    }
    Ok(())
}

/// IoGetFsZeroingOffset(Irp, *ZeroingOffset) (RVA 0x507830).
pub fn fs_zeroing_offset(irp: u64, output: &Field<u32>) -> u32 {
    if !irp_has_extension_type(irp, IRP_EXTENSION_ZEROING_OFFSET) {
        return STATUS_NOT_FOUND;
    }
    output.set(zeroing_offset(extension_at(irp_extension(irp))).get());
    STATUS_SUCCESS
}

/// IoSetFsZeroingOffset(Irp, ZeroingOffset) (RVA 0x507930).
pub fn set_fs_zeroing_offset(irp: u64, offset: u32) -> u32 {
    if !irp_has_extension_type(irp, IRP_EXTENSION_ZEROING_OFFSET) {
        return STATUS_NOT_FOUND;
    }
    zeroing_offset(extension_at(irp_extension(irp))).set(offset);
    STATUS_SUCCESS
}

/// IoSetFsZeroingOffsetRequired(Irp) (RVA 0x507970).
pub fn set_fs_zeroing_offset_required(irp: u64) -> Result<u32, KernelError> {
    if irp_has_extension_type(irp, IRP_EXTENSION_ZEROING_OFFSET) {
        return Ok(STATUS_ALREADY_COMMITTED);
    }
    if !irp_extension_combination_valid(irp, IRP_EXTENSION_ZEROING_OFFSET) {
        return Ok(STATUS_NOT_SUPPORTED);
    }
    let extension = allocate_irp_extension(irp, IRP_EXTENSION_ZEROING_OFFSET)?;
    if extension == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    zeroing_offset(extension_at(extension)).set(0);
    Ok(STATUS_SUCCESS)
}

/// IoSetFsTrackOffsetState(Irp, TrackOffsetBlob, TrackedOffset) (RVA 0x5078d0).
pub fn set_fs_track_offset_state(irp: u64, blob: u64, tracked_offset: u64) -> Result<u32, KernelError> {
    if !irp_extension_combination_valid(irp, IRP_EXTENSION_TRACK_OFFSET) {
        return Ok(STATUS_NOT_SUPPORTED);
    }
    let address = allocate_irp_extension(irp, IRP_EXTENSION_TRACK_OFFSET)?;
    if address == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    let extension = extension_at(address);
    extension.fs_track_offset_blob.set(blob);
    extension.fs_tracked_offset.set(tracked_offset);
    Ok(STATUS_SUCCESS)
}

/// IoGetCopyInformationExtension(Irp, *CopyInformation) (RVA 0x3f0ba0): copia
/// os 16 bytes do COPY_INFORMATION.
pub fn copy_information(irp: u64, output: u64) -> u32 {
    if !irp_has_extension_type(irp, IRP_EXTENSION_COPY_INFORMATION) {
        return STATUS_NOT_FOUND;
    }
    let source = &extension_at(irp_extension(irp)).copy_information;
    guest::write_bytes(output, &guest::read_bytes(source[0].address(), 16));
    STATUS_SUCCESS
}

// ---- Dica de dispositivo do FILE_OBJECT (io-file-system-support) -----------
//
// FoExtPerTypeExtension[1] da _IOP_FILE_OBJECT_EXTENSION aponta para um bloco
// de 0x20 bytes, privado do kernel e sem tipo nos símbolos: o primeiro qword é
// o DEVICE_OBJECT onde o IoGetRelatedDeviceObject para (lido por
// `file::information::related_device`) e +8 é o processo iniciador (lido por
// `irp_request::initiator_process`). Autocontido: tipos por caminho
// qualificado, nomes com prefixo `hint_`/`HINT_`; usa só o
// `file_object_extension` deste módulo (IopAllocateFileObjectExtension).

const HINT_STATUS_SUCCESS: u32 = 0;
const HINT_STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const HINT_STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// Slot do tipo 1 (dica de dispositivo / iniciador) em FoExtPerTypeExtension.
const HINT_EXTENSION_SLOT: usize = 1;

/// O bloco do tipo 1 (layout privado do kernel, 0x20 bytes).
#[repr(C)]
struct DeviceHintExtension {
    /// -> `_DEVICE_OBJECT`
    device_object_hint: crate::ntos::inc::field::Field<u64>,
    /// -> `_EPROCESS`
    _initiator_process: crate::ntos::inc::field::Field<u64>,
    _reserved_10: crate::ntos::inc::field::Reserved<0x10>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl crate::ntos::inc::field::NtStruct for DeviceHintExtension {}

const _: () = {
    assert!(core::mem::size_of::<DeviceHintExtension>() == 0x20);
    assert!(core::mem::offset_of!(DeviceHintExtension, _initiator_process) == 0x8);
};

/// IopGetFileObjectExtension(File, 1, NULL): o bloco da dica, se houver.
fn hint_extension(file: &crate::ntos::inc::types::FileObject) -> Option<&'static DeviceHintExtension> {
    use crate::ntos::inc::field::NtStruct;
    let extension = file.file_object_extension.get();
    if extension == 0 {
        return None;
    }
    // SAFETY: a extensão de um FILE_OBJECT vivo.
    let block = unsafe { crate::ntos::inc::types::IopFileObjectExtension::at(extension) }.fo_ext_per_type_extension[HINT_EXTENSION_SLOT].get();
    // SAFETY: o slot 1 só guarda blocos DeviceHintExtension.
    (block != 0).then(|| unsafe { DeviceHintExtension::at(block) })
}

/// IoCopyDeviceObjectHint(SourceFileObject, TargetFileObject) (RVA 0x8937e0):
/// destino que já tem dica -> STATUS_UNSUCCESSFUL; origem sem dica -> sucesso
/// sem mudança; senão o destino ganha a extensão (IopGetSetSpecificExtension
/// com alocação) e uma cópia do DEVICE_OBJECT da origem (só o primeiro qword,
/// como o NT).
pub fn copy_device_object_hint(source: &crate::ntos::inc::types::FileObject, target: &crate::ntos::inc::types::FileObject) -> Result<u32, crate::rtl::KernelError> {
    use crate::ntos::inc::field::NtStruct;
    if hint_extension(target).is_some() {
        return Ok(HINT_STATUS_UNSUCCESSFUL);
    }
    let Some(hint) = hint_extension(source) else { return Ok(HINT_STATUS_SUCCESS) };
    let Some(extension) = file_object_extension(target.address())? else { return Ok(HINT_STATUS_INSUFFICIENT_RESOURCES) };
    let block = crate::ntos::mm::guest_memory::alloc_bytes(DeviceHintExtension::SIZE);
    if block == 0 {
        return Ok(HINT_STATUS_INSUFFICIENT_RESOURCES);
    }
    // SAFETY: extensão instalada no FILE_OBJECT de destino.
    let slot = &unsafe { crate::ntos::inc::types::IopFileObjectExtension::at(extension) }.fo_ext_per_type_extension[HINT_EXTENSION_SLOT];
    // IopSetTypeSpecificFoExtension: cmpxchg do slot vazio, senão STATUS_UNSUCCESSFUL.
    if slot.atomic().compare_exchange(0, block, core::sync::atomic::Ordering::SeqCst, core::sync::atomic::Ordering::SeqCst).is_err() {
        crate::ntos::mm::guest_memory::free_bytes(block);
        return Ok(HINT_STATUS_UNSUCCESSFUL);
    }
    // SAFETY: bloco recém-alocado com o tamanho de DeviceHintExtension.
    unsafe { DeviceHintExtension::at(block) }.device_object_hint.set(hint.device_object_hint.get());
    Ok(HINT_STATUS_SUCCESS)
}

// ---- FsTrackOffset do IRP (io-paging) ---------------------------------------
//
// Autocontido: a extensão do IRP é a `_IOP_IRP_EXTENSION` tipada
// (`inc::types::extra_fs_ntfs::IopIrpExtension`) no `Irp->IrpExtension`
// (`extra_io::IrpExtensionField`); nomes com prefixo `track_`/`TRACK_`.

const TRACK_STATUS_SUCCESS: u32 = 0;
const TRACK_STATUS_NOT_FOUND: u32 = 0xC000_0225;
/// IRP_EXTENSION_GENERIC_ONLY: a genérica embutida em IrpExtension (bit 7 de AllocationFlags).
const TRACK_GENERIC_ONLY: u8 = 0x80;
/// IopFsTrackOffsetType.
const TRACK_OFFSET_TYPE: u32 = 5;

/// IopIrpHasExtensionType para os tipos alocados (não o 2, a genérica): a
/// extensão quando o bit do tipo está ligado em TypesAllocated.
pub fn irp_extension_of_type(irp: &crate::ntos::inc::types::Irp, kind: u32) -> Option<&'static crate::ntos::inc::types::extra_fs_ntfs::IopIrpExtension> {
    use crate::ntos::inc::field::NtStruct;
    use crate::ntos::inc::types::extra_io::IrpExtensionField;
    if irp.allocation_flags.get() & TRACK_GENERIC_ONLY != 0 {
        return None;
    }
    let pointer = irp.irp_extension().get();
    if pointer == 0 {
        return None;
    }
    // SAFETY: sem GENERIC_ONLY, IrpExtension aponta para a _IOP_IRP_EXTENSION do IRP.
    let extension = unsafe { crate::ntos::inc::types::extra_fs_ntfs::IopIrpExtension::at(pointer) };
    ((extension.types_allocated.get() >> kind) & 1 != 0).then_some(extension)
}

/// IoIrpHasFsTrackOffsetExtensionType(Irp) (RVA 0x2faf30).
pub fn irp_has_fs_track_offset(irp: &crate::ntos::inc::types::Irp) -> bool {
    irp_extension_of_type(irp, TRACK_OFFSET_TYPE).is_some()
}

/// IoClearFsTrackOffsetState(Irp) (RVA 0x5077c0): sem o tipo 5 ->
/// STATUS_NOT_FOUND; senão IopFreeIrpExtension(Irp, 5, FALSE) zera o blob
/// (+0x28), mantém FsTrackedOffset e tira o bit, deixando a extensão alocada
/// para o IoFreeIrp.
pub fn clear_fs_track_offset_state(irp: &crate::ntos::inc::types::Irp) -> u32 {
    let Some(extension) = irp_extension_of_type(irp, TRACK_OFFSET_TYPE) else { return TRACK_STATUS_NOT_FOUND };
    extension.fs_track_offset_blob.set(0);
    extension.types_allocated.set(extension.types_allocated.get() & !(1u16 << TRACK_OFFSET_TYPE));
    TRACK_STATUS_SUCCESS
}
