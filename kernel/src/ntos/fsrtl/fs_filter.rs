//! Callbacks de filtro de sistema de arquivos e a sincronização de seção do
//! FsRtl — FsRtlAcquireFileExclusive e FsRtlReleaseFile, com o despacho dos
//! FS_FILTER_CALLBACKS (registrados por FsRtlRegisterFileSystemFilterCallbacks)
//! pela pilha de dispositivos do arquivo.
//!
//! Comportamento conferido contra o ntoskrnl 19041:
//!   FsRtlAcquireFileExclusive          rva 0x6550d0 -> FsRtlAcquireFileExclusiveCommon
//!                                      0x6552d0 (SyncTypeOther, PageProtection 0, Flags 0)
//!   FsRtlReleaseFile                   rva 0x655100
//!   FsFilterCtrlInit                   rva 0x2d77e0 (FsFilterAllocateCompletionStack 0x4f0d3c)
//!   FsFilterPerformCallbacks           rva 0x2d74c0 (FsFilterGetCallbacks 0x2d7640)
//!   FsFilterPerformCompletionCallbacks rva 0x2d7430
//!   FsFilterCtrlFree                   rva 0x2d7408
//!
//! O controle (a estrutura do NT na pilha do chamador, 0x238 bytes) leva o
//! FS_FILTER_CALLBACK_DATA, as flags e a pilha de conclusões: cada
//! dispositivo da pilha (do topo, o IoGetRelatedDeviceObject, até o file
//! system de base) cujo driver tem a rotina Post da operação empilha
//! (dispositivo, arquivo, contexto, Post) antes da rotina Pre, que recebe o
//! endereço do contexto. Uma Pre que devolve sucesso informativo encerra a
//! descida; a falha de um filtro só encerra quando a operação aceita falhar,
//! e a falha do file system de base é fatal (FILE_SYSTEM, 0x38c) se nem isso
//! for aceito. A entrada do próprio file system de base sai da pilha no
//! fim da descida. Depois as rotinas Post rodam de baixo para cima com o
//! status final. Sem filtros nem callbacks no file system de base, a
//! aquisição usa o Fast I/O AcquireFileForNtCreateSection (ou
//! ReleaseFileForNtCreateSection) do file system; sem ele, o ERESOURCE
//! principal do cabeçalho do FCB (FsContext->Resource) em modo exclusivo.
//! A aquisição entra numa região crítica que a liberação desfaz (e uma
//! falha da aquisição também).
//!
//! Diferença do OpenNT: com a pilha de conclusões maior que as 15 entradas
//! embutidas e o pool esgotado, o NT espera a reserva estática de uma
//! operação de aquisição ou liberação; aqui o resultado é
//! STATUS_INSUFFICIENT_RESOURCES.

use crate::hal::amd64::native_call;
use crate::ntos::ex::{pool_allocation, resource};
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::extra_fsrtl::FsrtlCommonFcbHeader;
use crate::ntos::inc::types::{DeviceObject, DevobjExtension, DriverExtension, DriverObject, FastIoDispatch, FileObject, FsFilterCallbackData, FsFilterCallbacks, FsFilterSectionSyncType};
use crate::ntos::io::file::information;
use crate::ntos::io::file_system;
use crate::ntos::ke::{bugcheck, critical_region};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::objects::device as device_objects;
use crate::ntos::ob::{object_reference, reference_trace};
use crate::rtl::KernelError;

/// FS_FILTER_ACQUIRE_FOR_SECTION_SYNCHRONIZATION e
/// FS_FILTER_RELEASE_FOR_SECTION_SYNCHRONIZATION (ntifs.h).
const ACQUIRE_FOR_SECTION_SYNCHRONIZATION: u8 = 0xFF;
const RELEASE_FOR_SECTION_SYNCHRONIZATION: u8 = 0xFE;
const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY: u32 = 0x126;
/// Bugcheck FILE_SYSTEM.
const FILE_SYSTEM: u32 = 0x22;
/// Entradas embutidas no controle.
const INLINE_ENTRIES: u16 = 15;
/// Flags do controle: pilha de conclusões do pool e alvo trocado por um filtro.
const CTRL_POOL_STACK: u32 = 1;
const CTRL_REDIRECTED: u32 = 4;
/// Estado devolvido pela descida: falha do file system de base aceita; a
/// aquisição o reutiliza para "aquisição padrão feita".
const STATE_BASE_FAILURE_OR_DEFAULT: u32 = 1;
const STATE_BASE_HAS_CALLBACKS: u32 = 2;
/// 'FSmg', a tag da pilha de conclusões alocada.
const TAG_FSMG: u32 = 0x676D_5346;
const NON_PAGED_POOL_NX: u32 = 0x200;

/// Entrada da pilha de conclusões (0x20 bytes).
#[repr(C)]
struct CompletionEntry {
    device_object: Field<u64>,
    file_object: Field<u64>,
    completion_context: Field<u64>,
    post_routine: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for CompletionEntry {}

/// O controle de uma operação de filtro (0x238 bytes).
#[repr(C)]
struct FilterCtrl {
    data: FsFilterCallbackData,
    flags: Field<u32>,
    _pad_44: Reserved<0x4>,
    capacity: Field<u16>,
    count: Field<u16>,
    _pad_4c: Reserved<0x4>,
    /// -> a primeira CompletionEntry (as embutidas ou as do pool).
    stack: Field<u64>,
    inline: [CompletionEntry; INLINE_ENTRIES as usize],
}

// SAFETY: #[repr(C)] de células e de uma estrutura do NT.
unsafe impl NtStruct for FilterCtrl {}

const _: () = {
    assert!(core::mem::size_of::<CompletionEntry>() == 0x20);
    assert!(core::mem::size_of::<FilterCtrl>() == 0x238);
    assert!(core::mem::offset_of!(FilterCtrl, flags) == 0x40);
    assert!(core::mem::offset_of!(FilterCtrl, capacity) == 0x48);
    assert!(core::mem::offset_of!(FilterCtrl, count) == 0x4A);
    assert!(core::mem::offset_of!(FilterCtrl, stack) == 0x50);
    assert!(core::mem::offset_of!(FilterCtrl, inline) == 0x58);
};

fn device_object(device: u64) -> &'static DeviceObject {
    // SAFETY: dispositivos vivos da pilha do arquivo.
    unsafe { DeviceObject::at(device) }
}

fn file_object(file: u64) -> &'static FileObject {
    // SAFETY: o FILE_OBJECT vivo do chamador (ou o trocado por um filtro).
    unsafe { FileObject::at(file) }
}

/// O dispositivo abaixo na pilha (DEVOBJ_EXTENSION.AttachedTo).
fn attached_to(device: u64) -> u64 {
    let extension = device_object(device).device_object_extension.get();
    // SAFETY: DeviceObjectExtension de um dispositivo vivo.
    if extension == 0 { 0 } else { unsafe { DevobjExtension::at(extension) }.attached_to.get() }
}

/// DriverObject->FastIoDispatch e DriverExtension->FsFilterCallbacks do
/// driver dono do dispositivo (os dispositivos internos do OpenNT sem
/// DRIVER_OBJECT não têm nenhum dos dois).
fn driver_tables(device: u64) -> (u64, u64) {
    let driver = device_object(device).driver_object.get();
    if driver == 0 {
        return (0, 0);
    }
    // SAFETY: DriverObject e DriverExtension de um dispositivo vivo.
    let driver = unsafe { DriverObject::at(driver) };
    let extension = driver.driver_extension.get();
    let filters = if extension == 0 { 0 } else { unsafe { DriverExtension::at(extension) }.fs_filter_callbacks.get() };
    (driver.fast_io_dispatch.get(), filters)
}

fn callbacks_at(table: u64) -> &'static FsFilterCallbacks {
    // SAFETY: a cópia da tabela que FsRtlRegisterFileSystemFilterCallbacks guardou.
    unsafe { FsFilterCallbacks::at(table) }
}

/// FsFilterGetCallbacks (as duas operações de sincronização de seção): a
/// rotina só conta se o SizeOfFsFilterCallbacks a cobre.
fn operation_callbacks(operation: u8, table: u64) -> (u64, u64) {
    if table == 0 {
        return (0, 0);
    }
    let callbacks = callbacks_at(table);
    let size = callbacks.size_of_fs_filter_callbacks.get();
    match operation {
        ACQUIRE_FOR_SECTION_SYNCHRONIZATION => (
            if size >= 0x10 { callbacks.pre_acquire_for_section_synchronization.get() } else { 0 },
            if size >= 0x18 { callbacks.post_acquire_for_section_synchronization.get() } else { 0 },
        ),
        RELEASE_FOR_SECTION_SYNCHRONIZATION => (
            if size >= 0x20 { callbacks.pre_release_for_section_synchronization.get() } else { 0 },
            if size >= 0x28 { callbacks.post_release_for_section_synchronization.get() } else { 0 },
        ),
        _ => (0, 0),
    }
}

/// O file system de base registrou alguma rotina da operação.
fn has_callbacks(operation: u8, table: u64) -> bool {
    let (pre, post) = operation_callbacks(operation, table);
    pre != 0 || post != 0
}

fn entry_at(ctrl: &FilterCtrl, index: u16) -> &'static CompletionEntry {
    // SAFETY: `stack` aponta para `capacity` entradas (embutidas ou do pool).
    unsafe { CompletionEntry::at(ctrl.stack.get() + index as u64 * CompletionEntry::SIZE) }
}

/// FsFilterCtrlInit: o controle novo (zerado), com a pilha de conclusões
/// do tamanho da pilha de dispositivos do topo (StackSize), embutida até 15.
fn ctrl_init(operation: u8, device: u64, file: u64) -> Result<(u64, u32), KernelError> {
    let address = guest::alloc_bytes(FilterCtrl::SIZE);
    if address == 0 {
        return Ok((0, STATUS_INSUFFICIENT_RESOURCES));
    }
    guest::write_bytes(address, &[0u8; FilterCtrl::SIZE as usize]);
    // SAFETY: bloco zerado recém-alocado com o tamanho do controle.
    let ctrl = unsafe { FilterCtrl::at(address) };
    ctrl.data.size_of_fs_filter_callback_data.set(FsFilterCallbackData::SIZE as u32);
    ctrl.data.operation.set(operation);
    ctrl.data.device_object.set(device);
    ctrl.data.file_object.set(file);
    let stack_size = device_object(device).stack_size.get() as i8 as i16 as u16;
    ctrl.capacity.set(stack_size);
    if stack_size <= INLINE_ENTRIES {
        ctrl.stack.set(ctrl.inline[0].address());
        ctrl.capacity.set(INLINE_ENTRIES);
        return Ok((address, 0));
    }
    let bytes = stack_size as u64 * CompletionEntry::SIZE;
    let pool = pool_allocation::allocate_tagged(NON_PAGED_POOL_NX, bytes, TAG_FSMG)?;
    if pool == 0 {
        return Ok((address, STATUS_INSUFFICIENT_RESOURCES));
    }
    guest::write_bytes(pool, &alloc::vec![0u8; bytes as usize]);
    ctrl.flags.set(ctrl.flags.get() | CTRL_POOL_STACK);
    ctrl.stack.set(pool);
    Ok((address, 0))
}

/// FsFilterCtrlFree: a pilha do pool e o próprio controle.
fn ctrl_free(address: u64) -> Result<(), KernelError> {
    // SAFETY: controle criado por `ctrl_init`.
    let ctrl = unsafe { FilterCtrl::at(address) };
    if ctrl.flags.get() & CTRL_POOL_STACK != 0 {
        pool_allocation::free(ctrl.stack.get(), TAG_FSMG as u64)?;
    }
    guest::free_bytes(address);
    Ok(())
}

/// Tira a última entrada da pilha de conclusões.
fn pop(ctrl: &FilterCtrl, pushed: bool) {
    if pushed {
        ctrl.count.set(ctrl.count.get().wrapping_sub(1));
    }
}

/// FsFilterPerformCallbacks(Ctrl, AllowFailure, AllowBaseFailure, &State):
/// desce a pilha chamando as rotinas Pre; devolve o status que encerrou a
/// descida (0 quando chegou ao file system de base).
fn perform_callbacks(ctrl: &FilterCtrl, allow_failure: bool, allow_base_failure: bool, state: &mut u32) -> u32 {
    *state = STATE_BASE_HAS_CALLBACKS;
    let mut device = ctrl.data.device_object.get();
    while device != 0 {
        let lower = attached_to(device);
        ctrl.data.device_object.set(device);
        let (pre, post) = operation_callbacks(ctrl.data.operation.get(), driver_tables(device).1);
        if pre == 0 && post == 0 {
            if lower == 0 {
                *state &= !STATE_BASE_HAS_CALLBACKS;
            }
            device = lower;
            continue;
        }
        let mut context = 0u64;
        let pushed = post != 0;
        if pushed {
            let count = ctrl.count.get();
            if count >= ctrl.capacity.get() || ctrl.stack.get() == 0 {
                if allow_failure {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                bugcheck::bug_check_ex(FILE_SYSTEM, 0, 0, 0, 0);
            }
            let entry = entry_at(ctrl, count);
            ctrl.count.set(count + 1);
            entry.device_object.set(device);
            entry.file_object.set(ctrl.data.file_object.get());
            entry.completion_context.set(0);
            entry.post_routine.set(post);
            context = entry.completion_context.address();
        }
        if pre != 0 {
            let status = native_call::call(pre, &[ctrl.data.address(), context]) as u32;
            if status & 0x8000_0000 != 0 {
                if allow_failure && lower != 0 {
                    pop(ctrl, pushed);
                    return status;
                }
                if lower == 0 {
                    if !allow_base_failure {
                        bugcheck::bug_check_ex(FILE_SYSTEM, status as i32 as i64 as u64, 0, 0x38C, 0);
                    }
                    *state |= STATE_BASE_FAILURE_OR_DEFAULT;
                    pop(ctrl, pushed);
                    return status;
                }
            } else if status != 0 {
                pop(ctrl, pushed);
                return status;
            }
        }
        if device != ctrl.data.device_object.get() {
            // Um filtro trocou o alvo: a descida segue pelo dispositivo novo.
            ctrl.flags.set(ctrl.flags.get() | CTRL_REDIRECTED);
            device = ctrl.data.device_object.get();
            continue;
        }
        if lower == 0 {
            pop(ctrl, pushed);
        }
        device = attached_to(device);
    }
    0
}

/// FsFilterPerformCompletionCallbacks: as rotinas Post de baixo para cima,
/// com o dispositivo e o arquivo de cada entrada.
fn perform_completion_callbacks(ctrl: &FilterCtrl, status: u32) {
    while ctrl.count.get() != 0 {
        let entry = entry_at(ctrl, ctrl.count.get() - 1);
        ctrl.data.device_object.set(entry.device_object.get());
        ctrl.data.file_object.set(entry.file_object.get());
        native_call::call(entry.post_routine.get(), &[ctrl.data.address(), status as u64, entry.completion_context.get()]);
        ctrl.count.set(ctrl.count.get() - 1);
    }
}

/// O ERESOURCE principal do cabeçalho do FCB (FsContext->Resource), ou 0.
fn main_resource(file: u64) -> u64 {
    let fcb = file_object(file).fs_context.get();
    // SAFETY: o FsContext de um FILE_OBJECT de file system começa pelo cabeçalho comum.
    if fcb == 0 { 0 } else { unsafe { FsrtlCommonFcbHeader::at(fcb) }.resource.get() }
}

/// Uma rotina do Fast I/O coberta por SizeOfFastIoDispatch, ou 0.
fn fast_io_routine(dispatch: u64, minimum: u32, routine: impl Fn(&FastIoDispatch) -> u64) -> u64 {
    if dispatch == 0 {
        return 0;
    }
    // SAFETY: FAST_IO_DISPATCH do driver do file system de base.
    let table = unsafe { FastIoDispatch::at(dispatch) };
    if table.size_of_fast_io_dispatch.get() < minimum { 0 } else { routine(table) }
}

/// Parâmetros de AcquireForSectionSynchronization.
pub struct SectionSync {
    pub sync_type: u32,
    pub page_protection: u32,
    pub flags: u32,
    pub output_information: u64,
}

/// FsRtlAcquireFileExclusiveCommon: devolve o NTSTATUS; em sucesso o
/// arquivo fica adquirido dentro de uma região crítica.
pub fn acquire_file_exclusive_common(file: u64, parameters: &SectionSync) -> Result<u32, KernelError> {
    let top = information::related_device_object(file)?;
    let mut base = file_system::base_file_system_device(file_object(file));
    let (mut fast_io, mut table) = driver_tables(base);
    // Na criação de seção a operação aceita falhar.
    let allow = parameters.sync_type == FsFilterSectionSyncType::SYNC_TYPE_CREATE_SECTION.0 as u32;
    let mut state = 0u32;
    let mut status = 0u32;
    let mut ctrl_address = 0u64;
    if top == base && !has_callbacks(ACQUIRE_FOR_SECTION_SYNCHRONIZATION, table) {
        critical_region::enter_critical()?;
    } else {
        let (address, initialized) = ctrl_init(ACQUIRE_FOR_SECTION_SYNCHRONIZATION, top, file)?;
        if initialized != 0 {
            if address != 0 {
                ctrl_free(address)?;
            }
            return Ok(initialized);
        }
        ctrl_address = address;
        // SAFETY: controle criado acima.
        let ctrl = unsafe { FilterCtrl::at(address) };
        let section = &ctrl.data.parameters.acquire_for_section_synchronization;
        section.sync_type.set(FsFilterSectionSyncType(parameters.sync_type as i32));
        section.page_protection.set(parameters.page_protection);
        section.output_information.set(parameters.output_information);
        section.flags.set(parameters.flags);
        critical_region::enter_critical()?;
        status = perform_callbacks(ctrl, allow, allow, &mut state);
        if status != 0 && status & 0x8000_0000 == 0 {
            status = if status == STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY { 0 } else { status };
        }
    }
    let mut target = file;
    if status == 0 {
        let mut referenced_base = 0u64;
        if ctrl_address != 0 {
            // SAFETY: controle criado acima.
            let ctrl = unsafe { FilterCtrl::at(ctrl_address) };
            if ctrl.flags.get() & CTRL_REDIRECTED != 0 {
                target = ctrl.data.file_object.get();
                base = device_objects::attached_reference(ctrl.data.device_object.get(), true)?;
                referenced_base = base;
                (fast_io, table) = driver_tables(base);
            }
        }
        if !has_callbacks(ACQUIRE_FOR_SECTION_SYNCHRONIZATION, table) {
            let routine = fast_io_routine(fast_io, 0x60, |dispatch| dispatch.acquire_file_for_nt_create_section.get());
            if routine != 0 {
                native_call::call(routine, &[target]);
            } else {
                status = STATUS_INVALID_DEVICE_REQUEST;
            }
            state |= STATE_BASE_FAILURE_OR_DEFAULT;
        }
        if referenced_base != 0 {
            object_reference::dereference_with_tag(referenced_base, reference_trace::DEFAULT_TAG, true)?;
        }
    }
    if status == STATUS_INVALID_DEVICE_REQUEST && state & STATE_BASE_FAILURE_OR_DEFAULT != 0 {
        let lock = main_resource(target);
        if lock != 0 {
            resource::acquire_exclusive(lock, true)?;
        }
        status = 0;
    }
    if ctrl_address != 0 {
        // SAFETY: controle criado acima.
        let ctrl = unsafe { FilterCtrl::at(ctrl_address) };
        if ctrl.count.get() != 0 {
            perform_completion_callbacks(ctrl, status);
        }
        ctrl_free(ctrl_address)?;
    }
    if status & 0x8000_0000 != 0 {
        critical_region::leave_critical()?;
    }
    Ok(status)
}

/// FsRtlAcquireFileExclusive(FileObject): a aquisição para sincronização
/// de seção com SyncTypeOther, sem proteção de página nem flags.
pub fn acquire_file_exclusive(file: u64) -> Result<u32, KernelError> {
    acquire_file_exclusive_common(file, &SectionSync { sync_type: FsFilterSectionSyncType::SYNC_TYPE_OTHER.0 as u32, page_protection: 0, flags: 0, output_information: 0 })
}

/// FS_FILTER_ACQUIRE_FOR_MOD_WRITE e FS_FILTER_RELEASE_FOR_MOD_WRITE.
const ACQUIRE_FOR_MOD_WRITE: u8 = 0xFD;
const RELEASE_FOR_MOD_WRITE: u8 = 0xFC;
pub const STATUS_CANT_WAIT: u32 = 0xC000_00D8;
/// FSRTL_COMMON_FCB_HEADER.Flags: FSRTL_FLAG_ACQUIRE_MAIN_RSRC_EX e _SH.
const FSRTL_FLAG_ACQUIRE_MAIN_RSRC_EX: u8 = 0x08;
const FSRTL_FLAG_ACQUIRE_MAIN_RSRC_SH: u8 = 0x10;

/// As rotinas Pre/Post das operações do modified page writer, cobertas por
/// SizeOfFsFilterCallbacks.
fn mod_write_callbacks(operation: u8, table: u64) -> (u64, u64) {
    if table == 0 {
        return (0, 0);
    }
    let callbacks = callbacks_at(table);
    let size = callbacks.size_of_fs_filter_callbacks.get();
    match operation {
        ACQUIRE_FOR_MOD_WRITE => (
            if size >= 0x50 { callbacks.pre_acquire_for_modified_page_writer.get() } else { 0 },
            if size >= 0x58 { callbacks.post_acquire_for_modified_page_writer.get() } else { 0 },
        ),
        _ => (
            if size >= 0x60 { callbacks.pre_release_for_modified_page_writer.get() } else { 0 },
            if size >= 0x68 { callbacks.post_release_for_modified_page_writer.get() } else { 0 },
        ),
    }
}

/// Algum filtro da pilha (ou o file system de base) registrou rotinas da
/// operação.
fn stack_has_mod_write_callbacks(operation: u8, top: u64) -> bool {
    let mut device = top;
    while device != 0 {
        let (pre, post) = mod_write_callbacks(operation, driver_tables(device).1);
        if pre != 0 || post != 0 {
            return true;
        }
        device = attached_to(device);
    }
    false
}

/// As rotinas Pre de cima para baixo e as Post de baixo para cima, como o
/// FsFilterPerformCallbacks das operações do writer (a falha de uma Pre
/// encerra a descida com o status).
fn perform_mod_write_callbacks(operation: u8, top: u64, file: u64, ending_offset: u64, resource_cell: u64) -> Result<u32, KernelError> {
    let (address, initialized) = ctrl_init(operation, top, file)?;
    if initialized != 0 {
        if address != 0 {
            ctrl_free(address)?;
        }
        return Ok(initialized);
    }
    // SAFETY: controle criado acima.
    let ctrl = unsafe { FilterCtrl::at(address) };
    if operation == ACQUIRE_FOR_MOD_WRITE {
        let parameters = &ctrl.data.parameters.acquire_for_modified_page_writer;
        parameters.ending_offset.set(ending_offset);
        parameters.resource_to_release.set(resource_cell);
    } else {
        ctrl.data.parameters.release_for_modified_page_writer.resource_to_release.set(resource_cell);
    }
    let mut status = 0u32;
    let mut device = top;
    let mut posts: alloc::vec::Vec<(u64, u64)> = alloc::vec::Vec::new();
    while device != 0 {
        ctrl.data.device_object.set(device);
        let (pre, post) = mod_write_callbacks(operation, driver_tables(device).1);
        if pre != 0 {
            let context = guest::alloc_bytes(8);
            let result = native_call::call(pre, &[ctrl.data.address(), context]) as u32;
            let saved = if context != 0 { guest::read64(context) } else { 0 };
            if context != 0 {
                guest::free_bytes(context);
            }
            if result != 0 {
                status = if result == STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY { 0 } else { result };
                if post != 0 && result & 0x8000_0000 == 0 {
                    posts.push((post, saved));
                }
                break;
            }
            if post != 0 {
                posts.push((post, saved));
            }
        } else if post != 0 {
            posts.push((post, 0));
        }
        device = attached_to(device);
    }
    for (post, context) in posts.into_iter().rev() {
        native_call::call(post, &[ctrl.data.address(), status as u64, context]);
    }
    ctrl_free(address)?;
    Ok(status)
}

/// FsRtlAcquireFileForModWriteEx(FileObject, EndingOffset, ResourceToRelease)
/// do modified page writer: os filtros, o Fast I/O AcquireForModWrite do
/// file system (sem espera; o do ntfs.sys devolve STATUS_CANT_WAIT com o
/// arquivo ocupado) e, sem ele, o recurso do cabeçalho do FCB que as flags
/// dele pedem (o principal com FSRTL_FLAG_ACQUIRE_MAIN_RSRC_EX/_SH, senão o
/// de paginação compartilhado; exclusivo quando a escrita passa do
/// ValidDataLength), sem espera. Devolve (status, recurso a soltar).
pub fn acquire_for_mod_write(file: u64, ending_offset: u64) -> Result<(u32, u64), KernelError> {
    let top = information::related_device_object(file)?;
    let base = file_system::base_file_system_device(file_object(file));
    let cells = guest::alloc_bytes(16);
    if cells == 0 {
        return Ok((STATUS_INSUFFICIENT_RESOURCES, 0));
    }
    let (offset_cell, resource_cell) = (cells, cells + 8);
    guest::write64(offset_cell, ending_offset);
    guest::write64(resource_cell, 0);
    let mut status = if stack_has_mod_write_callbacks(ACQUIRE_FOR_MOD_WRITE, top) { perform_mod_write_callbacks(ACQUIRE_FOR_MOD_WRITE, top, file, offset_cell, resource_cell)? } else { 0 };
    if status == 0 {
        let routine = fast_io_routine(driver_tables(base).0, 0x80, |dispatch| dispatch.acquire_for_mod_write.get());
        status = if routine != 0 { native_call::call(routine, &[file, offset_cell, resource_cell, base]) as u32 } else { default_acquire_for_mod_write(file, ending_offset, resource_cell)? };
    }
    let resource = guest::read64(resource_cell);
    guest::free_bytes(cells);
    Ok((status, resource))
}

fn default_acquire_for_mod_write(file: u64, ending_offset: u64, resource_cell: u64) -> Result<u32, KernelError> {
    let fcb = file_object(file).fs_context.get();
    if fcb == 0 {
        return Ok(0);
    }
    // SAFETY: o FsContext de um FILE_OBJECT de file system começa pelo cabeçalho comum.
    let header = unsafe { FsrtlCommonFcbHeader::at(fcb) };
    let flags = header.flags.get();
    let (lock, exclusive) = if flags & FSRTL_FLAG_ACQUIRE_MAIN_RSRC_EX != 0 {
        (header.resource.get(), true)
    } else if flags & FSRTL_FLAG_ACQUIRE_MAIN_RSRC_SH != 0 {
        (header.resource.get(), false)
    } else {
        (header.paging_io_resource.get(), ending_offset > header.valid_data_length.quad_part.get() as u64)
    };
    if lock == 0 {
        return Ok(0);
    }
    let acquired = if exclusive { resource::acquire_exclusive(lock, false)? } else { resource::acquire_shared(lock, false)? };
    if acquired == 0 {
        return Ok(STATUS_CANT_WAIT);
    }
    guest::write64(resource_cell, lock);
    Ok(0)
}

/// FsRtlReleaseFileForModWrite(FileObject, ResourceToRelease): os filtros, o
/// Fast I/O ReleaseForModWrite do file system e, sem ele, o recurso.
pub fn release_for_mod_write(file: u64, resource_to_release: u64) -> Result<(), KernelError> {
    let top = information::related_device_object(file)?;
    let base = file_system::base_file_system_device(file_object(file));
    let mut status = if stack_has_mod_write_callbacks(RELEASE_FOR_MOD_WRITE, top) { perform_mod_write_callbacks(RELEASE_FOR_MOD_WRITE, top, file, 0, resource_to_release)? } else { 0 };
    if status == 0 {
        let routine = fast_io_routine(driver_tables(base).0, 0xD0, |dispatch| dispatch.release_for_mod_write.get());
        if routine != 0 {
            status = native_call::call(routine, &[file, resource_to_release, base]) as u32;
        } else if resource_to_release != 0 {
            resource::release(resource_to_release)?;
        }
    }
    let _ = status;
    Ok(())
}

/// FsRtlReleaseFile(FileObject): desfaz a aquisição (filtros, Fast I/O
/// ReleaseFileForNtCreateSection ou o ERESOURCE do FCB) e sai da região
/// crítica.
pub fn release_file(file: u64) -> Result<(), KernelError> {
    let top = information::related_device_object(file)?;
    let mut base = file_system::base_file_system_device(file_object(file));
    let (mut fast_io, mut table) = driver_tables(base);
    let mut state = 0u32;
    let mut status = 0u32;
    let mut ctrl_address = 0u64;
    if top != base || has_callbacks(RELEASE_FOR_SECTION_SYNCHRONIZATION, table) {
        // O NT segue mesmo se a pilha de conclusões não pôde ser alocada.
        let (address, _) = ctrl_init(RELEASE_FOR_SECTION_SYNCHRONIZATION, top, file)?;
        ctrl_address = address;
        if address != 0 {
            // SAFETY: controle criado acima.
            status = perform_callbacks(unsafe { FilterCtrl::at(address) }, false, false, &mut state);
            if status != 0 && status & 0x8000_0000 == 0 {
                status = if status == STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY { 0 } else { status };
            }
        }
    }
    let mut target = file;
    if status == 0 {
        let mut referenced_base = 0u64;
        if ctrl_address != 0 {
            // SAFETY: controle criado acima.
            let ctrl = unsafe { FilterCtrl::at(ctrl_address) };
            if ctrl.flags.get() & CTRL_REDIRECTED != 0 {
                target = ctrl.data.file_object.get();
                base = device_objects::attached_reference(ctrl.data.device_object.get(), true)?;
                referenced_base = base;
                (fast_io, table) = driver_tables(base);
            }
        }
        if !has_callbacks(RELEASE_FOR_SECTION_SYNCHRONIZATION, table) {
            let routine = fast_io_routine(fast_io, 0x68, |dispatch| dispatch.release_file_for_nt_create_section.get());
            if routine != 0 {
                native_call::call(routine, &[target]);
            } else {
                status = STATUS_INVALID_DEVICE_REQUEST;
            }
            state |= STATE_BASE_FAILURE_OR_DEFAULT;
        }
        if referenced_base != 0 {
            object_reference::dereference_with_tag(referenced_base, reference_trace::DEFAULT_TAG, true)?;
        }
    }
    if status == STATUS_INVALID_DEVICE_REQUEST && state & STATE_BASE_FAILURE_OR_DEFAULT != 0 {
        let lock = main_resource(target);
        if lock != 0 {
            resource::release(lock)?;
        }
        status = 0;
    }
    if ctrl_address != 0 {
        // SAFETY: controle criado acima.
        let ctrl = unsafe { FilterCtrl::at(ctrl_address) };
        if ctrl.count.get() != 0 {
            perform_completion_callbacks(ctrl, status);
        }
        ctrl_free(ctrl_address)?;
    }
    critical_region::leave_critical()
}
