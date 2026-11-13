//! Gerenciador de transações do kernel (KTM) visto do ntoskrnl: o slot de
//! extensão `ext-ms-win-ntos-tm-l1-1-0` e o seu comportamento sem tm.sys.
//!
//! No Windows 10 19045 o KTM não mora no ntoskrnl. Cada export Tm* e cada
//! serviço Nt* do KTM é um thunk de uma instrução
//!     TmCurrentTransaction       RVA 0x3d0500: jmp [_imp_TmCurrentTransaction]
//!     NtOpenEnlistment           RVA 0x3d0140: jmp [_imp_NtOpenEnlistment]
//! pela tabela de importação do host de extensão, que o tm.sys preenche ao
//! se registrar. Sem tm.sys os slots ficam nos stubs padrão gravados no PE
//! (valores iniciais dos `_imp_*`, lidos com pefile):
//!     0x36d0e0  `mov eax, 0xC00000BB; ret`  -> STATUS_NOT_SUPPORTED (quase todos)
//!     0x2d6de0  `xor al, al; ret`           -> FALSE (TmIsTransactionActive,
//!                                              TmIsKTMCommitCoordinator)
//!     0x39a2f0  `ret`                       -> nada (TmGetTransactionId,
//!                                              TmInitSystemPhase2, TmShutdownSystem)
//! O Phase1InitializationDiscard (0xa3b3b7) chama
//! `TmInitSystem(&TmResourceManagerObjectType, &TmEnlistmentObjectType,
//! &TmTransactionManagerObjectType, &TmTransactionObjectType)` pelo slot e
//! aceita explicitamente 0xC00000BB (`cmp eax, 0xc00000bb`): o boot segue e as
//! células POBJECT_TYPE (seção ALMOSTRO, valor inicial 0) ficam NULL.
//!
//! O OpenNT não carrega tm.sys — o KTM está genuinamente ausente — então este
//! assunto é exatamente essa configuração do Windows, e nunca existe uma
//! transação, um resource manager ou um enlistment. É a configuração que o
//! ntfs.sys detecta no DriverEntry (0x292d6e): `TmCurrentTransaction(&t) ==
//! 0xC00000BB` liga o bit 0x1000000 nas flags globais do NTFS, e com ele
//! TxfInitializeVolume (0x190bf7), TxfFsctl, NtfsQueryFsAttributeInfo,
//! NtfsInitializeDevice e o checkpoint pulam todo o TxF: nenhum
//! ZwCreateTransactionManager/ZwCreateResourceManager/TmEnableCallbacks é
//! chamado e o caminho não transacionado roda como no Windows sem KTM. O
//! mesmo fato define FsRtlIsMobileOS.
//!
//! Os argumentos nunca são tocados (os stubs padrão não leem nada): handles
//! de saída e buffers continuam com o que o chamador pôs.

use crate::ntos::mm::kernel_data;
use crate::rtl::KernelError;

/// Status de todo slot do KTM sem tm.sys (stub padrão 0x36d0e0).
pub const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;

// ---- Exports Tm* que devolvem NTSTATUS (stub 0x36d0e0) -----------------------

/// TmCurrentTransaction(PKTRANSACTION *Transaction): o chamador inicializa
/// `*Transaction`; sem KTM nada é escrito.
pub fn current_transaction(_transaction_out: u64) -> u32 {
    STATUS_NOT_SUPPORTED
}

/// TmReferenceEnlistmentKey(PKENLISTMENT Enlistment, PVOID *Key).
pub fn reference_enlistment_key(_enlistment: u64, _key_out: u64) -> u32 {
    STATUS_NOT_SUPPORTED
}

/// TmDereferenceEnlistmentKey(PKENLISTMENT Enlistment, PBOOLEAN LastReference).
pub fn dereference_enlistment_key(_enlistment: u64, _last_reference_out: u64) -> u32 {
    STATUS_NOT_SUPPORTED
}

/// TmRecoverResourceManager(PKRESOURCEMANAGER ResourceManager).
pub fn recover_resource_manager(_resource_manager: u64) -> u32 {
    STATUS_NOT_SUPPORTED
}

/// TmRequestOutcomeEnlistment(PKENLISTMENT Enlistment, PLARGE_INTEGER TmVirtualClock).
pub fn request_outcome_enlistment(_enlistment: u64, _virtual_clock: u64) -> u32 {
    STATUS_NOT_SUPPORTED
}

// As três seguintes são o assunto dos exports de `impl-tm-extension.rs`
// (irmão); ficam em uso quando aquele grupo for re-apontado para cá na
// integração (ver REGISTRATION de impl-tm-transaction-manager.rs, passo 5).

/// TmCommitComplete / TmPrepareComplete / TmPrePrepareComplete /
/// TmRollbackComplete / TmReadOnlyEnlistment / TmRollbackEnlistment
/// (PKENLISTMENT, PLARGE_INTEGER): as notificações de enlistment, que nunca
/// chegam porque nenhum enlistment existe.
pub fn enlistment_notification_complete(_enlistment: u64, _virtual_clock: u64) -> u32 {
    STATUS_NOT_SUPPORTED
}

/// TmCreateEnlistment(PHANDLE, KPROCESSOR_MODE, ACCESS_MASK, POBJECT_ATTRIBUTES,
/// PRKRESOURCEMANAGER, PKTRANSACTION, ULONG, NOTIFICATION_MASK, PVOID).
pub fn create_enlistment(_handle_out: u64, _resource_manager: u64, _transaction: u64) -> u32 {
    STATUS_NOT_SUPPORTED
}

/// TmEnableCallbacks(PKRESOURCEMANAGER, PTM_RM_NOTIFICATION, PVOID).
pub fn enable_callbacks(_resource_manager: u64, _callback: u64, _context: u64) -> u32 {
    STATUS_NOT_SUPPORTED
}

// ---- Exports Tm* BOOLEAN (stub 0x2d6de0) e VOID (stub 0x39a2f0) --------------

/// TmIsTransactionActive(PKTRANSACTION): sem KTM nenhuma transação existe.
pub fn is_transaction_active(_transaction: u64) -> bool {
    false
}

/// TmIsKTMCommitCoordinator(PKTRANSACTION).
pub fn is_ktm_commit_coordinator(_transaction: u64) -> bool {
    false
}

/// TmGetTransactionId(PKTRANSACTION, PUOW TransactionId): o stub padrão é um
/// `ret` — o GUID de saída NÃO é escrito.
pub fn get_transaction_id(_transaction: u64, _transaction_id_out: u64) {}

// ---- Serviços Nt* do KTM (Zw* -> KiServiceInternal -> thunk Nt* -> slot) ----

/// NtCreateTransactionManager / NtCreateResourceManager / NtOpenEnlistment /
/// NtOpenResourceManager: o handle de saída não é escrito.
pub fn open_or_create_object(_handle_out: u64) -> u32 {
    STATUS_NOT_SUPPORTED
}

/// NtQueryInformationTransactionManager(HANDLE, CLASS, PVOID, ULONG, PULONG):
/// nem o buffer nem o ReturnLength são escritos.
pub fn query_information_transaction_manager(_handle: u64, _class: u32, _buffer: u64, _length: u32, _return_length: u64) -> u32 {
    STATUS_NOT_SUPPORTED
}

/// NtRecoverEnlistment(HANDLE, PVOID EnlistmentKey) / NtRecoverTransactionManager(HANDLE).
pub fn recover_object(_handle: u64) -> u32 {
    STATUS_NOT_SUPPORTED
}

// ---- Tipos de objeto (dados exportados) --------------------------------------

/// As células POBJECT_TYPE que o TmInitSystem preencheria (8 bytes cada,
/// `pointer(..)` em kernel_data_layout, valor inicial 0 como no PE). Ficam 0:
/// o slot devolveu STATUS_NOT_SUPPORTED no Phase 1 e nenhum tipo Tm* existe.
pub const OBJECT_TYPE_CELLS: [&str; 3] = ["TmTransactionObjectType", "TmResourceManagerObjectType", "TmEnlistmentObjectType"];

fn cell(name: &str) -> u64 {
    kernel_data::address(name).unwrap_or_else(|error: KernelError| panic!("{name}: {error}"))
}

/// Endereço público de `TmTransactionObjectType` (o IAT recebe o endereço).
pub fn transaction_object_type_cell() -> u64 {
    cell(OBJECT_TYPE_CELLS[0])
}

/// Endereço público de `TmResourceManagerObjectType`.
pub fn resource_manager_object_type_cell() -> u64 {
    cell(OBJECT_TYPE_CELLS[1])
}

/// Endereço público de `TmEnlistmentObjectType`.
pub fn enlistment_object_type_cell() -> u64 {
    cell(OBJECT_TYPE_CELLS[2])
}

/// Valor publicado numa célula: o POBJECT_TYPE, NULL sem KTM.
pub fn object_type(name: &str) -> u64 {
    kernel_data::read(name)
}
