//! Oplocks do FsRtl, no estado
//! "nenhum oplock é concedido".
//!
//! O OpenNT não tem o motor de oplocks. Este assunto reproduz EXATAMENTE o
//! que o ntoskrnl 10.0.19045 faz quando o handle opaco `*Oplock` é NULL (um
//! estado legal do NT: qualquer FS pode recusar oplocks), derivado da
//! desmontagem:
//!
//! * FsRtlInitializeOplock 0x725fa0 é `ret 0` (o FS zera o handle).
//! * Uninitialize 0x306650: NULL -> nada; senão zera o handle.
//! * Current 0x394660 / CurrentOplockH 0x6a6650: NULL -> FALSE.
//! * CurrentBatch 0x6784e0: NULL -> FALSE; senão estado(+0x90) & 0xC.
//! * IsFastIoPossible 0x6745f0: NULL -> TRUE; senão estado == 1 ou
//!   (estado & 0x1F00F40) == 0x40.
//! * KeysEqual 0x394e60 -> FsRtlpOplockKeysEqual 0x2d6290 (flags 0).
//! * IsSharedRequest 0x67f700: predicado puro do IRP.
//! * CheckOplock 0x2d54b0 / CheckOplockEx 0x2d6540 / BreakH 0x69b610 /
//!   BreakToNone 0x4efed0: NULL -> STATUS_SUCCESS (inclusive no create).
//! * BreakToNoneEx 0x4eff30: Flags & 0x10 -> STATUS_INVALID_PARAMETER.
//! * CheckOplockForFsFilterCallback 0x5cd900: Flags além de 8 ->
//!   STATUS_INVALID_PARAMETER; NULL -> STATUS_SUCCESS (seção própria).
//! * FsctrlEx 0x68f3b0 -> FsRtlpOplockFsctrlInternal 0x5ea170: todo pedido
//!   segue o caminho real "não pode conceder" (0x5ea702).
//!
//! O handle (POPLOCK = PVOID*) é um `Field<u64>` e nunca deixa de ser NULL,
//! porque só o caminho de concessão (ausente) aloca o bloco interno
//! (FsRtlpAllocateOplock); os dois leitores puros do estado interno (+0x90)
//! continuam reproduzidos sobre [`OplockStatePrefix`].
//! STUB (sinalizado): a concessão (todo pedido -> STATUS_OPLOCK_NOT_GRANTED,
//! concluído como o real) e a gravação das chaves de oplock dos ECPs do
//! create. O BreakToNoneEx do NT com handle NULL faz falta de página (toma o
//! mutex incondicionalmente); aqui devolve STATUS_SUCCESS.
//!
//! Motor estável para os file systems (FAT/NTFS): `initialize_oplock`,
//! `uninitialize_oplock`, `current_oplock`, `current_batch_oplock`,
//! `current_oplock_h`, `oplock_is_fast_io_possible`, `oplock_keys_equal`,
//! `oplock_is_shared_request`, `check_oplock`, `check_oplock_ex`,
//! `oplock_break_h`, `oplock_break_to_none`, `oplock_break_to_none_ex`,
//! `oplock_fsctrl_ex`. (O anexo `fsrtl-oplock-ex` acrescenta
//! `check_oplock_ex2` e `any_break_owner_process` a este arquivo.)

use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::extra_fsrtl::{OplockKeyContext, RequestOplockInputBuffer};
use crate::ntos::inc::types::{FileObject, IoStackLocation, IopFileObjectExtension, Irp};
use crate::ntos::io::io_manager;
use crate::ntos::mm::guest_memory as guest;

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
pub const STATUS_OPLOCK_NOT_GRANTED: u32 = 0xC000_00E2;
pub const STATUS_INVALID_OPLOCK_PROTOCOL: u32 = 0xC000_00E3;

const IRP_MJ_CREATE: u8 = 0;

// Create.Options.
const FILE_OPEN_REQUIRING_OPLOCK: u32 = 0x0001_0000;
const FILE_RESERVE_OPFILTER: u32 = 0x0010_0000;

// FSCTLs de oplock (tabela de salto em 0x5ea710/0x5ea734).
const FSCTL_REQUEST_OPLOCK_LEVEL_1: u32 = 0x0009_0000;
const FSCTL_REQUEST_OPLOCK_LEVEL_2: u32 = 0x0009_0004;
const FSCTL_REQUEST_BATCH_OPLOCK: u32 = 0x0009_0008;
const FSCTL_OPLOCK_BREAK_ACKNOWLEDGE: u32 = 0x0009_000C;
const FSCTL_OPBATCH_ACK_CLOSE_PENDING: u32 = 0x0009_0010;
const FSCTL_OPLOCK_BREAK_NOTIFY: u32 = 0x0009_0014;
const FSCTL_OPLOCK_BREAK_ACK_NO_2: u32 = 0x0009_0050;
const FSCTL_REQUEST_FILTER_OPLOCK: u32 = 0x0009_005C;
const FSCTL_REQUEST_OPLOCK: u32 = 0x0009_0240;

// REQUEST_OPLOCK_INPUT_BUFFER.
const REQUEST_OPLOCK_INPUT_FLAG_REQUEST: u32 = 1;
const REQUEST_OPLOCK_INPUT_FLAG_ACK: u32 = 2;
const OPLOCK_LEVEL_CACHE_READ: u32 = 1;
const OPLOCK_LEVEL_CACHE_HANDLE: u32 = 2;
const OPLOCK_LEVEL_CACHE_WRITE: u32 = 4;
const OPLOCK_FLAG_BREAKING_FOR_SHARING_VIOLATION_ONLY: u32 = 0x10;
const REQUEST_OPLOCK_INPUT_LENGTH: u32 = 0x0C;
const REQUEST_OPLOCK_OUTPUT_LENGTH: u32 = 0x18;

/// FoExtPerTypeExtension[6]: o OPLOCK_KEY_CONTEXT do FILE_OBJECT (+0x38).
const OPLOCK_KEY_EXTENSION_SLOT: usize = 6;
const OPLOCK_KEY_FLAG_PARENT_KEY: u16 = 1;
const OPLOCK_KEY_FLAG_TARGET_KEY: u16 = 2;

/// Prefixo do bloco interno de oplock do NT (privado do FsRtl): só o estado
/// em +0x90 é lido pelos predicados.
#[repr(C)]
struct OplockStatePrefix {
    _reserved: Reserved<0x90>,
    oplock_state: Field<u32>,
    _pad_94: Reserved<0x4>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for OplockStatePrefix {}

const _: () = {
    assert!(core::mem::offset_of!(OplockStatePrefix, oplock_state) == 0x90);
};

fn state_flags(oplock: &Field<u64>) -> Option<u32> {
    let state = oplock.get();
    // SAFETY: um handle não nulo aponta para o bloco interno do FsRtl.
    (state != 0).then(|| unsafe { OplockStatePrefix::at(state) }.oplock_state.get())
}

fn current_stack(irp: &Irp) -> &'static IoStackLocation {
    // SAFETY: o slot corrente de um IRP vivo.
    unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get()) }
}

/// Conclusão como o real: IoStatus.Status = status; IofCompleteRequest.
fn complete(irp: &Irp, status: u32) -> u32 {
    irp.io_status.status.set(status as i32);
    io_manager::iof_complete_request(irp.address());
    status
}

/// FsRtlInitializeOplock: `ret 0`.
pub fn initialize_oplock(_oplock: &Field<u64>) {}

/// FsRtlUninitializeOplock: nenhum bloco interno é alocado neste modelo; um
/// handle não nulo só pode vir de fora e é apenas zerado (o real zera antes
/// de liberar).
pub fn uninitialize_oplock(oplock: &Field<u64>) {
    if oplock.get() != 0 {
        oplock.set(0);
    }
}

// ---- FsRtlCheckOplockForFsFilterCallback ---------------------------------------------
//
// ntoskrnl 10.0.19041, RVA 0x5cd900: Flags com algo além de
// OPLOCK_FLAG_IGNORE_OPLOCK_KEYS (8) -> STATUS_INVALID_PARAMETER; handle NULL
// -> STATUS_SUCCESS. Com bloco interno: o FAST_MUTEX* em +0x98 é tomado
// (ExAcquireFastMutexUnsafe); estado (+0x90) sem os níveis 0x7000 -> sucesso;
// a FS_FILTER_CALLBACK_DATA só interessa se for
// FS_FILTER_ACQUIRE_FOR_SECTION_SYNCHRONIZATION (Operation 0xFF) com SyncType
// SyncTypeCreateSection (1) e PageProtection com PAGE_READWRITE ou
// PAGE_EXECUTE_READWRITE (0x44); só então o NT quebra o oplock pelos níveis
// de cache (FsRtlpOplockBreakByCacheFlags, alvo 0x5000). Neste modelo nenhum
// oplock é concedido e o handle nunca deixa de ser NULL, então o caminho de
// quebra não é alcançável; se for, a chamada falha alto.

/// OPLOCK_FLAG_IGNORE_OPLOCK_KEYS, a única flag aceita.
const OPLOCK_FLAG_IGNORE_OPLOCK_KEYS: u32 = 0x08;
/// Níveis de cache concedidos (o que a criação de seção gravável quebraria).
const OPLOCK_STATE_CACHE_LEVELS: u32 = 0x7000;
const FS_FILTER_ACQUIRE_FOR_SECTION_SYNCHRONIZATION: u8 = 0xFF;
const SYNC_TYPE_CREATE_SECTION: u32 = 1;
const PAGE_WRITABLE_PROTECTIONS: u32 = 0x44;

/// O bloco interno até o FAST_MUTEX* que protege o estado.
#[repr(C)]
struct OplockSyncPrefix {
    _reserved: Reserved<0x90>,
    oplock_state: Field<u32>,
    _pad_94: Reserved<0x4>,
    fast_mutex: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for OplockSyncPrefix {}

/// FS_FILTER_CALLBACK_DATA (ntifs.h) até os parâmetros de
/// AcquireForSectionSynchronization.
#[repr(C)]
pub struct FsFilterCallbackData {
    pub size_of_fs_filter_callback_data: Field<u32>,
    pub operation: Field<u8>,
    pub reserved: Field<u8>,
    _pad_6: Reserved<0x2>,
    pub device_object: Field<u64>,
    pub file_object: Field<u64>,
    pub sync_type: Field<u32>,
    pub page_protection: Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for FsFilterCallbackData {}

const _: () = {
    assert!(core::mem::offset_of!(OplockSyncPrefix, fast_mutex) == 0x98);
    assert!(core::mem::offset_of!(FsFilterCallbackData, operation) == 0x4);
    assert!(core::mem::offset_of!(FsFilterCallbackData, file_object) == 0x10);
    assert!(core::mem::offset_of!(FsFilterCallbackData, sync_type) == 0x18);
    assert!(core::mem::offset_of!(FsFilterCallbackData, page_protection) == 0x1C);
};

/// FsRtlCheckOplockForFsFilterCallback(Oplock, CallbackData, Flags) -> NTSTATUS.
pub fn check_oplock_for_fs_filter_callback(oplock: &Field<u64>, callback_data: &FsFilterCallbackData, flags: u32) -> Result<u32, crate::rtl::KernelError> {
    if flags & !OPLOCK_FLAG_IGNORE_OPLOCK_KEYS != 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let state = oplock.get();
    if state == 0 {
        return Ok(STATUS_SUCCESS);
    }
    // SAFETY: um handle não nulo aponta para o bloco interno do FsRtl.
    let block = unsafe { OplockSyncPrefix::at(state) };
    let mutex = block.fast_mutex.get();
    crate::ntos::ke::fast_mutex::acquire_unsafe(mutex)?;
    let needs_break = block.oplock_state.get() & OPLOCK_STATE_CACHE_LEVELS != 0
        && callback_data.operation.get() == FS_FILTER_ACQUIRE_FOR_SECTION_SYNCHRONIZATION
        && callback_data.sync_type.get() == SYNC_TYPE_CREATE_SECTION
        && callback_data.page_protection.get() & PAGE_WRITABLE_PROTECTIONS != 0;
    crate::ntos::ke::fast_mutex::release_unsafe(mutex)?;
    if needs_break {
        return Err(crate::rtl::KernelError::new("FsRtlCheckOplockForFsFilterCallback: oplock break without an oplock engine"));
    }
    Ok(STATUS_SUCCESS)
}

/// FsRtlCurrentOplock: sem bloco interno, FALSE.
pub fn current_oplock(oplock: &Field<u64>) -> bool {
    let _ = oplock.get();
    false
}

/// FsRtlCurrentBatchOplock: estado & (BATCH | FILTER).
pub fn current_batch_oplock(oplock: &Field<u64>) -> bool {
    state_flags(oplock).is_some_and(|flags| flags & 0x0C != 0)
}

/// FsRtlCurrentOplockH: sem bloco interno, FALSE.
pub fn current_oplock_h(oplock: &Field<u64>) -> bool {
    let _ = oplock.get();
    false
}

/// FsRtlOplockIsFastIoPossible.
pub fn oplock_is_fast_io_possible(oplock: &Field<u64>) -> bool {
    match state_flags(oplock) {
        None => true,
        Some(flags) => flags == 1 || flags & 0x01F0_0F40 == 0x40,
    }
}

/// OPLOCK_KEY_CONTEXT presente (Flags & 3) na extensão do FILE_OBJECT.
fn oplock_key(file_object: &FileObject) -> Option<&'static OplockKeyContext> {
    let extension = file_object.file_object_extension.get();
    if extension == 0 {
        return None;
    }
    // SAFETY: a extensão de um FILE_OBJECT vivo.
    let key = unsafe { IopFileObjectExtension::at(extension) }.fo_ext_per_type_extension[OPLOCK_KEY_EXTENSION_SLOT].get();
    if key == 0 {
        return None;
    }
    // SAFETY: o slot guarda um OPLOCK_KEY_CONTEXT.
    let key = unsafe { OplockKeyContext::at(key) };
    (key.flags.get() & (OPLOCK_KEY_FLAG_PARENT_KEY | OPLOCK_KEY_FLAG_TARGET_KEY) != 0).then_some(key)
}

/// FsRtlOplockKeysEqual(Fo1, Fo2) = FsRtlpOplockKeysEqual(Fo1, Fo2, 0):
/// mesmo objeto -> TRUE; senão os dois precisam do TargetOplockKey e os 16
/// bytes devem coincidir.
pub fn oplock_keys_equal(first: Option<&FileObject>, second: Option<&FileObject>) -> bool {
    let (Some(first), Some(second)) = (first, second) else { return false };
    if first.address() == second.address() {
        return true;
    }
    let (Some(left), Some(right)) = (oplock_key(first), oplock_key(second)) else { return false };
    if right.flags.get() & OPLOCK_KEY_FLAG_TARGET_KEY == 0 || left.flags.get() & OPLOCK_KEY_FLAG_TARGET_KEY == 0 {
        return false;
    }
    guest::read_bytes(left.target_oplock_key.address(), 16) == guest::read_bytes(right.target_oplock_key.address(), 16)
}

fn request_buffer(irp: &Irp) -> &'static RequestOplockInputBuffer {
    // SAFETY: o SystemBuffer do I/O Manager para FSCTL_REQUEST_OPLOCK
    // (METHOD_BUFFERED, tamanho conferido pelo chamador).
    unsafe { RequestOplockInputBuffer::at(irp.associated_irp.system_buffer.get()) }
}

/// FsRtlOplockIsSharedRequest(Irp): FSCTL_REQUEST_OPLOCK sem
/// OPLOCK_LEVEL_CACHE_WRITE, ou FSCTL_REQUEST_OPLOCK_LEVEL_2.
pub fn oplock_is_shared_request(irp: &Irp) -> bool {
    match current_stack(irp).parameters.file_system_control.fs_control_code.get() {
        FSCTL_REQUEST_OPLOCK => request_buffer(irp).requested_oplock_level.get() & OPLOCK_LEVEL_CACHE_WRITE == 0,
        FSCTL_REQUEST_OPLOCK_LEVEL_2 => true,
        _ => false,
    }
}

/// FsRtlCheckOplock(Oplock, Irp, ...): sem oplock nada conflita.
pub fn check_oplock(_oplock: &Field<u64>, _irp: Option<&Irp>) -> u32 {
    STATUS_SUCCESS
}

/// FsRtlCheckOplockEx(Oplock, Irp, Flags, ...): idem para qualquer Flags.
pub fn check_oplock_ex(_oplock: &Field<u64>, _irp: Option<&Irp>, _flags: u32) -> u32 {
    STATUS_SUCCESS
}

/// FsRtlOplockBreakH(Oplock, Irp, Flags, ...): nada a quebrar.
pub fn oplock_break_h(_oplock: &Field<u64>, _irp: Option<&Irp>) -> u32 {
    STATUS_SUCCESS
}

/// FsRtlOplockBreakToNone(Oplock, IrpSp, Irp, ...): nada a quebrar.
pub fn oplock_break_to_none(_oplock: &Field<u64>) -> u32 {
    STATUS_SUCCESS
}

/// FsRtlOplockBreakToNoneEx(Oplock, Irp, Flags, ...).
pub fn oplock_break_to_none_ex(_oplock: &Field<u64>, _irp: Option<&Irp>, flags: u32) -> u32 {
    if flags & OPLOCK_FLAG_BREAKING_FOR_SHARING_VIOLATION_ONLY != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_SUCCESS
}

/// Nível pedido (R=1, H=2, W=4) no formato interno: válidos só R, RH, RW, RWH.
fn valid_shareable_level(level: u32) -> bool {
    let mut internal = 0;
    if level & OPLOCK_LEVEL_CACHE_READ != 0 {
        internal |= 0x1000;
    }
    if level & OPLOCK_LEVEL_CACHE_HANDLE != 0 {
        internal |= 0x2000;
    }
    if level & OPLOCK_LEVEL_CACHE_WRITE != 0 {
        internal |= 0x4000;
    }
    matches!(internal, 0x1000 | 0x3000 | 0x5000 | 0x7000)
}

/// FSCTL_REQUEST_OPLOCK com handle NULL.
fn request_oplock(irp: &Irp, stack: &IoStackLocation) -> u32 {
    let control = &stack.parameters.file_system_control;
    if control.input_buffer_length.get() < REQUEST_OPLOCK_INPUT_LENGTH || control.output_buffer_length.get() < REQUEST_OPLOCK_OUTPUT_LENGTH {
        return complete(irp, STATUS_BUFFER_TOO_SMALL);
    }
    let buffer = request_buffer(irp);
    if buffer.structure_version.get() > 1 {
        return complete(irp, STATUS_INVALID_PARAMETER);
    }
    let (level, flags) = (buffer.requested_oplock_level.get(), buffer.flags.get());
    if flags & REQUEST_OPLOCK_INPUT_FLAG_REQUEST != 0 {
        if level & 7 == 0 {
            // Pedir "nível nenhum" sem oplock existente: concluído com sucesso (0x7edc79).
            return complete(irp, STATUS_SUCCESS);
        }
        if !valid_shareable_level(level) {
            return complete(irp, STATUS_INVALID_PARAMETER);
        }
        complete(irp, STATUS_OPLOCK_NOT_GRANTED)
    } else if flags & REQUEST_OPLOCK_INPUT_FLAG_ACK != 0 {
        if level & 7 != 0 && !valid_shareable_level(level) {
            return complete(irp, STATUS_INVALID_PARAMETER);
        }
        complete(irp, STATUS_INVALID_OPLOCK_PROTOCOL)
    } else {
        complete(irp, STATUS_INVALID_PARAMETER)
    }
}

/// FsRtlOplockFsctrlEx(Oplock, Irp, OpenCount, Flags). Create com
/// FILE_RESERVE_OPFILTER / FILE_OPEN_REQUIRING_OPLOCK -> NOT_GRANTED sem
/// concluir (o FS falha o create); outro create -> SUCCESS. FSCTLs: pedidos
/// -> NOT_GRANTED concluído; reconhecimentos sem oplock ->
/// INVALID_OPLOCK_PROTOCOL concluído (FsRtlpAcknowledgeOplockBreak 0x4f0144);
/// break notify sem oplock -> SUCCESS concluído (0x88bf08); código
/// desconhecido -> INVALID_PARAMETER concluído.
pub fn oplock_fsctrl_ex(_oplock: &Field<u64>, irp: &Irp, _open_count: u32, _flags: u32) -> u32 {
    let stack = current_stack(irp);
    if stack.major_function.get() == IRP_MJ_CREATE {
        if stack.parameters.create.options.get() & (FILE_RESERVE_OPFILTER | FILE_OPEN_REQUIRING_OPLOCK) != 0 {
            return STATUS_OPLOCK_NOT_GRANTED;
        }
        return STATUS_SUCCESS;
    }
    match stack.parameters.file_system_control.fs_control_code.get() {
        FSCTL_REQUEST_OPLOCK => request_oplock(irp, stack),
        FSCTL_REQUEST_OPLOCK_LEVEL_1 | FSCTL_REQUEST_OPLOCK_LEVEL_2 | FSCTL_REQUEST_BATCH_OPLOCK | FSCTL_REQUEST_FILTER_OPLOCK => complete(irp, STATUS_OPLOCK_NOT_GRANTED),
        FSCTL_OPLOCK_BREAK_ACKNOWLEDGE | FSCTL_OPLOCK_BREAK_ACK_NO_2 | FSCTL_OPBATCH_ACK_CLOSE_PENDING => complete(irp, STATUS_INVALID_OPLOCK_PROTOCOL),
        FSCTL_OPLOCK_BREAK_NOTIFY => complete(irp, STATUS_SUCCESS),
        _ => complete(irp, STATUS_INVALID_PARAMETER),
    }
}

// ---- FsRtlCheckOplockEx2 / FsRtlOplockGetAnyBreakOwnerProcess ----
//
// Anexado ao arquivo de assunto `fsrtl/oplock.rs` do grupo irmão
// fsrtl-oplocks, no mesmo modelo "nenhum oplock é concedido" (o handle opaco
// `*Oplock` nunca deixa de ser NULL porque só o caminho de concessão,
// ausente, aloca o bloco interno). Usa `check_oplock_ex` e os `use` do
// arquivo (Field, NtStruct, Reserved, Irp); os campos do bloco interno do NT
// que só esta rotina lê ficam em structs locais à função.

/// FsRtlCheckOplockEx2(Oplock, Irp, Flags, FlagsEx2, CompletionRoutineContext,
/// CompletionRoutine, PostIrpRoutine, Timeout, NotifyContext, NotifyRoutine)
/// -> NTSTATUS (RVA 0x2d44d0). FsRtlCheckOplockEx (0x2d6540) é este mesmo
/// corpo com FlagsEx2 = 0; o que a Ex2 acrescenta é a validação de FlagsEx2:
/// qualquer bit é STATUS_INVALID_PARAMETER antes de tudo (0x45b960). O resto
/// é o `check_oplock_ex` deste arquivo (com `*Oplock == NULL` o NT devolve
/// STATUS_SUCCESS em todos os ramos).
pub fn check_oplock_ex2(oplock: &Field<u64>, irp: Option<&Irp>, flags: u32, flags_ex2: u32) -> u32 {
    const STATUS_INVALID_PARAMETER_EX2: u32 = 0xC000_000D;
    if flags_ex2 != 0 {
        return STATUS_INVALID_PARAMETER_EX2;
    }
    check_oplock_ex(oplock, irp, flags)
}

/// FsRtlOplockGetAnyBreakOwnerProcess(Oplock) -> PEPROCESS referenciado ou
/// NULL (RVA 0x4f00d0). Com o bloco interno: sob o FAST_MUTEX dele (variante
/// unsafe), o processo dono do oplock exclusivo ou, sem ele, o do primeiro
/// oplock compartilhado da lista, referenciado com a tag 'Dflt'. Handle ou
/// bloco NULL -> NULL.
pub fn any_break_owner_process(oplock: Option<&Field<u64>>) -> Result<u64, crate::rtl::KernelError> {
    use crate::ntos::inc::types::ListEntry;

    /// Bloco interno do oplock (NONOPAQUE_OPLOCK), só os campos lidos aqui.
    #[repr(C)]
    struct OplockState {
        _pad_0: Reserved<0x10>,
        /// -> `_EPROCESS` do oplock exclusivo.
        exclusive_owner_process: Field<u64>,
        _pad_18: Reserved<0x30>,
        /// Oplocks compartilhados ([`SharedOplock`]).
        shared_list: ListEntry,
        _pad_58: Reserved<0x40>,
        /// -> `_FAST_MUTEX`
        mutex: Field<u64>,
    }
    // SAFETY: #[repr(C)] só de células.
    unsafe impl NtStruct for OplockState {}

    /// Entrada da lista de oplocks compartilhados.
    #[repr(C)]
    struct SharedOplock {
        links: ListEntry,
        _pad_10: Reserved<0x10>,
        /// -> `_EPROCESS`
        owner_process: Field<u64>,
    }
    // SAFETY: #[repr(C)] só de células.
    unsafe impl NtStruct for SharedOplock {}

    const _: () = {
        assert!(core::mem::offset_of!(OplockState, exclusive_owner_process) == 0x10);
        assert!(core::mem::offset_of!(OplockState, shared_list) == 0x48);
        assert!(core::mem::offset_of!(OplockState, mutex) == 0x98);
        assert!(core::mem::offset_of!(SharedOplock, owner_process) == 0x20);
    };
    /// 'Dflt'.
    const TAG: u32 = 0x746C_6644;

    let Some(oplock) = oplock else { return Ok(0) };
    let state_address = oplock.get();
    if state_address == 0 {
        return Ok(0);
    }
    // SAFETY: bloco interno alocado pelo pacote de oplocks.
    let state = unsafe { OplockState::at(state_address) };
    let mutex = state.mutex.get();
    crate::ntos::ke::fast_mutex::acquire_unsafe(mutex)?;
    let mut owner = state.exclusive_owner_process.get();
    if owner == 0 {
        let first = state.shared_list.flink.get();
        if first != state.shared_list.address() {
            // SAFETY: entradas da lista de oplocks compartilhados.
            owner = unsafe { SharedOplock::at(first) }.owner_process.get();
        }
    }
    if owner != 0 {
        crate::ntos::ob::object_reference::reference_with_tag(owner, TAG, false)?;
    }
    crate::ntos::ke::fast_mutex::release_unsafe(mutex)?;
    Ok(owner)
}
