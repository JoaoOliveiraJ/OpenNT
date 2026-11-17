//! Extensões de FILE_OBJECT e de IRP — I/O Manager (IopAllocateFileObjectExtension,
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
pub const IRP_EXTENSION_TIMESTAMP: u32 = 1;
pub const IRP_EXTENSION_GENERIC: u32 = 2;
pub const IRP_EXTENSION_ZEROING_OFFSET: u32 = 4;
pub const IRP_EXTENSION_TRACK_OFFSET: u32 = 5;
/// Tipo 6: DiskIoAttributionHandle (o bit 0x40 do byte baixo de TypesAllocated).
pub const IRP_EXTENSION_DISK_IO_ATTRIBUTION: u32 = 6;
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

/// IoGetSiloParameters (RVA 0x302f30): o bloco de parâmetros do silo em
/// FoExtPerTypeExtension[7] (NULL sem extensão), o mesmo de que o IoGetSilo
/// lê o silo.
pub fn silo_parameters(file: &FileObject) -> u64 {
    existing_file_extension(file).map_or(0, |extension| extension.fo_ext_per_type_extension[FO_EXT_SILO].get())
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

/// IoGetIoAttributionHandle (RVA 0x2f3dd0): só um IRP com IOP_IRP_EXTENSION
/// alocada (AllocationFlags sem o bit 7) e o tipo 6 (atribuição de I/O de
/// disco) em TypesAllocated tem o handle; senão STATUS_NOT_FOUND.
pub fn io_attribution_handle(irp: u64, output: &Field<u64>) -> u32 {
    let packet = irp_at(irp);
    let extension = packet.irp_extension().get();
    if (packet.allocation_flags.get() as i8) < 0 || extension == 0 || extension_at(extension).types_allocated.get() & (1 << IRP_EXTENSION_DISK_IO_ATTRIBUTION) == 0 {
        return 0xC000_0225;
    }
    output.set(extension_at(extension).disk_io_attribution_handle.get());
    0
}

/// IoRecordIoAttribution (RVA 0x2e0580): versão 1 da estrutura; o handle
/// precisa ser de uma atribuição de disco viva (IopFindDiskIoAttribution).
/// O OpenNT não cria atribuições de I/O de disco: STATUS_INVALID_HANDLE.
pub fn record_io_attribution(_handle: u64, version: u32) -> u32 {
    if version != 1 {
        return 0xC000_0059;
    }
    0xC000_0008
}

// ---- IoSetIoAttributionIrp (RVA 0x505f60) --------------------------------------
//
// Flags: IO_ATTRIBUTION_FROM_THREAD (1) ou IO_ATTRIBUTION_FROM_PROCESS (2),
// exatamente um; outro valor é STATUS_INVALID_PARAMETER.
// - Pela thread (IoSetDiskIoAttributionFromThread 0x29c670): a thread que
//   trabalha em nome de outra (ETHREAD.WorkOnBehalfThread) atribui ao
//   processo dela; senão a thread corrente anexada a outro processo tenta o
//   processo anexado (KTHREAD.ApcState.Process) e, sem atribuição lá, cai no
//   próprio (KTHREAD.Process).
// - Pelo processo (IopSetDiskIoAttributionFromProcess 0x31d458).
// Um processo sem EPROCESS.DiskIoAttribution dá STATUS_NOT_FOUND; com ela, o
// handle (o qword +0x18 da atribuição, lido sob o IopDiskIoAttributionLock)
// vai para a extensão de tipo 6 do IRP (IopSetDiskIoAttributionExtension
// 0x2e66dc; sem memória, STATUS_INSUFFICIENT_RESOURCES). O OpenNT ainda não
// cria atribuições de disco (nenhum processo tem DiskIoAttribution), então o
// desvio do 19041 para a atribuição do job do chamador (Flags3 bit 12) não
// tem de onde ler e fica de fora.

const IO_ATTRIBUTION_FROM_THREAD: u32 = 1;
const IO_ATTRIBUTION_FROM_PROCESS: u32 = 2;

/// O começo da atribuição de I/O de disco do processo (layout privado do
/// kernel, lido na desmontagem): o handle em +0x18 e o contador em +0x20.
#[repr(C)]
struct DiskIoAttribution {
    _reserved_0: crate::ntos::inc::field::Reserved<0x18>,
    handle: Field<u64>,
    _reference_count: Field<i64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for DiskIoAttribution {}

const _: () = assert!(core::mem::offset_of!(DiskIoAttribution, handle) == 0x18);

/// IopReferenceIoAttributionFromProcess(Process, TRUE): o handle da
/// atribuição do processo, ou `None`.
fn process_attribution_handle(process: u64) -> Option<u64> {
    // SAFETY: EPROCESS vivo do chamador.
    let attribution = unsafe { crate::ntos::inc::types::Eprocess::at(process) }.disk_io_attribution.atomic().load(Ordering::Acquire);
    // SAFETY: DiskIoAttribution, quando presente, aponta para a atribuição viva.
    (attribution != 0).then(|| unsafe { DiskIoAttribution::at(attribution) }.handle.get())
}

/// IopSetDiskIoAttributionFromProcess / o fim do IoSetDiskIoAttributionFromThread.
fn attribute_to_process(irp: u64, process: u64) -> Result<u32, KernelError> {
    let Some(handle) = process_attribution_handle(process) else { return Ok(STATUS_NOT_FOUND) };
    let extension = allocate_irp_extension(irp, IRP_EXTENSION_DISK_IO_ATTRIBUTION)?;
    if extension == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    extension_at(extension).disk_io_attribution_handle.set(handle);
    Ok(STATUS_SUCCESS)
}

/// IoSetDiskIoAttributionFromThread(Irp, Thread).
fn attribute_from_thread(irp: u64, thread: u64) -> Result<u32, KernelError> {
    use crate::ntos::inc::types::Ethread;
    // SAFETY: ETHREAD viva do chamador.
    let ethread = unsafe { Ethread::at(thread) };
    let on_behalf = ethread.work_on_behalf_thread.get();
    if on_behalf != 0 {
        // SAFETY: a thread em nome de quem esta trabalha (retida pelo NT).
        return attribute_to_process(irp, unsafe { Ethread::at(on_behalf) }.tcb.process.get());
    }
    let tcb = &ethread.tcb;
    let attached = tcb.apc_state.process.get();
    if thread == crate::ntos::ps::process::get_current_thread() && attached != tcb.process.get() {
        let status = attribute_to_process(irp, attached)?;
        if status & 0x8000_0000 == 0 {
            return Ok(STATUS_SUCCESS);
        }
    }
    attribute_to_process(irp, tcb.process.get())
}

/// IoSetIoAttributionIrp(Irp, AttributionSource, Flags).
pub fn set_io_attribution_irp(irp: u64, source: u64, flags: u32) -> Result<u32, KernelError> {
    match flags {
        IO_ATTRIBUTION_FROM_THREAD => attribute_from_thread(irp, source),
        IO_ATTRIBUTION_FROM_PROCESS => attribute_to_process(irp, source),
        _ => Ok(STATUS_INVALID_PARAMETER),
    }
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
        for (cell, byte) in extension.generic_extension.iter().zip((current as u32).to_le_bytes()) {
            cell.set(byte);
        }
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

/// Timestamp da extensão de tipo 1 (a união de +0x28), ou `None` sem ela.
pub fn irp_timestamp(irp: u64) -> Option<&'static Field<i64>> {
    if !irp_has_extension_type(irp, IRP_EXTENSION_TIMESTAMP) {
        return None;
    }
    Some(&extension_at(irp_extension(irp)).timestamp.quad_part)
}

/// IopFreeIrpExtension(Irp, Type, TRUE) para um tipo da união sem estado
/// externo (o Timestamp): limpa o bit do tipo e, sem outro tipo, devolve a
/// extensão alocada ao pool. O tipo 5 (FsTrackOffset) e o 9 (cópia) têm
/// limpeza própria no NT e não passam por aqui.
pub fn free_irp_extension_type(irp: u64, kind: u32) -> Result<(), KernelError> {
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
    let types = &extension_at(address).types_allocated;
    types.set(types.get() & !(1u16 << kind));
    if types.get() == 0 && flags & IRP_EXTENSION_ALLOCATED != 0 {
        kernel_pool::free(address, Some(IRP_EXTENSION_TAG))?;
        packet.allocation_flags.set(flags & !IRP_EXTENSION_ALLOCATED);
        packet.irp_extension().set(0);
    }
    Ok(())
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
    extension.fs_tracked_offset.set(tracked_offset as i64);
    Ok(STATUS_SUCCESS)
}

/// IoGetCopyInformationExtension(Irp, *CopyInformation) (RVA 0x3f0ba0): copia
/// os 16 bytes do COPY_INFORMATION.
pub fn copy_information(irp: u64, output: u64) -> u32 {
    if !irp_has_extension_type(irp, IRP_EXTENSION_COPY_INFORMATION) {
        return STATUS_NOT_FOUND;
    }
    let source = &extension_at(irp_extension(irp)).copy_information;
    guest::write_bytes(output, &guest::read_bytes(source.address(), 16));
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

/// IopSetFileObjectExtension(File, 1, Hint) da abertura com
/// DeviceObjectHint: o FILE_OBJECT ganha o bloco da dica com o dispositivo.
pub fn set_device_object_hint(file: &crate::ntos::inc::types::FileObject, device: u64) -> Result<u32, crate::rtl::KernelError> {
    use crate::ntos::inc::field::NtStruct;
    let Some(extension) = file_object_extension(file.address())? else { return Ok(HINT_STATUS_INSUFFICIENT_RESOURCES) };
    let block = crate::ntos::mm::guest_memory::alloc_bytes(DeviceHintExtension::SIZE);
    if block == 0 {
        return Ok(HINT_STATUS_INSUFFICIENT_RESOURCES);
    }
    crate::ntos::mm::guest_memory::write_bytes(block, &[0u8; DeviceHintExtension::SIZE as usize]);
    // SAFETY: bloco recém-alocado com o tamanho de DeviceHintExtension.
    unsafe { DeviceHintExtension::at(block) }.device_object_hint.set(device);
    // SAFETY: extensão instalada no FILE_OBJECT.
    let slot = &unsafe { crate::ntos::inc::types::IopFileObjectExtension::at(extension) }.fo_ext_per_type_extension[HINT_EXTENSION_SLOT];
    if slot.atomic().compare_exchange(0, block, core::sync::atomic::Ordering::SeqCst, core::sync::atomic::Ordering::SeqCst).is_err() {
        crate::ntos::mm::guest_memory::free_bytes(block);
        return Ok(HINT_STATUS_UNSUCCESSFUL);
    }
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

/// IoGetFsTrackOffsetState(Irp, *RetFsTrackOffsetBlob, *RetTrackedOffset)
/// (RVA 0x2e63d0, cauda 0x46032a): sem o tipo 5 (IopIrpHasExtensionType) ->
/// STATUS_NOT_FOUND sem tocar nas saídas; senão o blob (+0x28) e o
/// FsTrackedOffset (+0x30), nessa ordem.
pub fn fs_track_offset_state(irp: &crate::ntos::inc::types::Irp, blob: &Field<u64>, tracked_offset: &Field<i64>) -> u32 {
    let Some(extension) = irp_extension_of_type(irp, TRACK_OFFSET_TYPE) else { return TRACK_STATUS_NOT_FOUND };
    blob.set(extension.fs_track_offset_blob.get());
    tracked_offset.set(extension.fs_tracked_offset.get());
    TRACK_STATUS_SUCCESS
}
