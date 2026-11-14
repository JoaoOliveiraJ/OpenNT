//! Partição de memória do sistema.
//!
//! A partição do sistema é o alocador físico real, retida pela vida do
//! boot. O corpo de 0x20 bytes é privado do OpenNT (não é a MM_PARTITION do
//! Windows): referências (+0), handles (+8), total (+16) e disponível (+24),
//! espelhados do objeto e do banco de PFNs.

use alloc::string::String;
use alloc::vec;

use super::{kernel_data, pfn};
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::ntos::ob::handles::namespace as namespace_handles;
use crate::ntos::ob::{object_access, object_manager, object_types, open_pointer};
use crate::ntos::ps::user::state;
use crate::ntos::se::model::{sid, Ace, SecurityPolicy};
use crate::ntos::inc::status::STATUS_UNSUCCESSFUL;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::section::create::{caller_read, caller_units};
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{ObjectAttributes, UnicodeString};

/// Corpo da partição do sistema (layout do OpenNT, não a MM_PARTITION):
/// contagens espelhadas do objeto e do banco de PFNs.
#[repr(C)]
pub(crate) struct PartitionBody {
    pub(crate) references: Field<u64>,
    pub(crate) handles: Field<u32>,
    _pad_c: Reserved<4>,
    pub(crate) total: Field<u64>,
    pub(crate) available: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for PartitionBody {}

const _: () = assert!(core::mem::size_of::<PartitionBody>() == 0x20);

pub const SIZE: u64 = PartitionBody::SIZE;

impl PartitionBody {
    /// O corpo publicado (ou em publicação) em `pointer`.
    pub(crate) fn of(pointer: u64) -> &'static PartitionBody {
        // SAFETY: corpo alocado por `init` e vivo até `dispose`.
        unsafe { PartitionBody::at(pointer) }
    }
}

/// Corpo da partição do sistema (0 = ainda não publicado).
static BODY: SpinLock<u64> = SpinLock::new(0);

pub fn get() -> Option<u64> {
    let body = *BODY.lock();
    (body != 0).then_some(body)
}

fn dispose(pointer: u64) {
    pfn::unbind_partition(pointer);
    guest::free_bytes(pointer);
}

/// Publica o corpo depois da inicialização do PFN.
pub fn init() -> Result<u64, KernelError> {
    if let Some(body) = get() {
        return Ok(body);
    }
    let record = pfn::partition();
    if record.total == 0 {
        return Err(KernelError::new("partition published before PFN initialization"));
    }
    let pointer = guest::alloc_bytes(SIZE);
    if pointer == 0 {
        return Err(KernelError::new("system partition allocation failed"));
    }
    // A vida é mantida pela referência do alocador, não por OBJ_PERMANENT:
    // o NtQueryObject da partição nativa não informa a flag permanente.
    let body = PartitionBody::of(pointer);
    body.references.set(0);
    body.handles.set(0);
    pfn::bind_partition(pointer);
    let result = (|| -> Result<(), KernelError> {
        dispatcher_objects::create(pointer, "partition", dispose, None, 0, false, dispatcher_objects::DispatcherHooks::default())?;
        dispatcher_objects::mirror_counts(pointer);
        let administrators = sid(5, &[32, 544]);
        dispatcher_objects::set_security(pointer, SecurityPolicy { owner: administrators.clone(), group: Some(sid(5, &[18])), dacl: Some(vec![Ace { sid: Some(administrators), mask: 0x1F_0003, deny: false, flags: 0, raw: None }]), ..SecurityPolicy::default() });
        object_manager::create_directory("\\KernelObjects")?;
        object_manager::create_object("\\KernelObjects", "MemoryPartition0", "Partition", Some(object_manager::ObjectData::pointer(pointer)))?;
        // Dono permanente: o próprio alocador físico.
        dispatcher_objects::reference(pointer)?;
        Ok(())
    })();
    if let Err(error) = result {
        if dispatcher_objects::get(pointer).is_some() {
            dispatcher_objects::collect(pointer);
        } else {
            pfn::unbind_partition(pointer);
            guest::free_bytes(pointer);
        }
        return Err(error);
    }
    *BODY.lock() = pointer;
    // PsPartitionType: o OBJECT_TYPE "Partition" que a criação acima publicou.
    if let Some(partition_type) = object_types::user_type("partition") {
        kernel_data::write("PsPartitionType", partition_type.pointer);
    }
    Ok(pointer)
}

/// OBJECT_ATTRIBUTES capturados: corpo e atributos efetivos.
fn capture(attributes: u64, user: bool) -> Result<Result<(u64, u32), u32>, KernelError> {
    if attributes == 0 {
        return Ok(Err(0xC000_000D));
    }
    if user && !state::probe_user_read(attributes, 48) {
        return Ok(Err(0xC000_0005));
    }
    let mode = user as u8;
    let read_attributes = || -> Result<(u32, u32, u64, u64), u32> {
        let at = |offset: usize| attributes + offset as u64;
        Ok((
            caller_read(at(core::mem::offset_of!(ObjectAttributes, length)), mode)?,
            caller_read(at(core::mem::offset_of!(ObjectAttributes, attributes)), mode)?,
            caller_read(at(core::mem::offset_of!(ObjectAttributes, root_directory)), mode)?,
            caller_read(at(core::mem::offset_of!(ObjectAttributes, object_name)), mode)?,
        ))
    };
    let (length, flags, root, unicode) = match read_attributes() {
        Ok(fields) => fields,
        Err(status) => return Ok(Err(status)),
    };
    if length != ObjectAttributes::SIZE as u32 {
        return Ok(Err(0xC000_000D));
    }
    if flags & !0x1FE2 != 0 {
        return Ok(Err(0xC000_000D));
    }
    if unicode == 0 {
        return Ok(Err(0xC000_003B));
    }
    if user && !state::probe_user_read(unicode, 16) {
        return Ok(Err(0xC000_0005));
    }
    let read_name = || -> Result<(u64, u64, u64), u32> {
        let at = |offset: usize| unicode + offset as u64;
        Ok((
            caller_read::<u16>(at(core::mem::offset_of!(UnicodeString, length)), mode)? as u64,
            caller_read::<u16>(at(core::mem::offset_of!(UnicodeString, maximum_length)), mode)? as u64,
            caller_read(at(core::mem::offset_of!(UnicodeString, buffer)), mode)?,
        ))
    };
    let (length, maximum, buffer) = match read_name() {
        Ok(fields) => fields,
        Err(status) => return Ok(Err(status)),
    };
    if length & 1 != 0 || length > maximum {
        return Ok(Err(0xC000_0033));
    }
    if length != 0 && (buffer == 0 || (user && !state::probe_user_read(buffer, length))) {
        return Ok(Err(0xC000_0005));
    }
    let units = match caller_units(buffer, length, mode) {
        Ok(units) => units,
        Err(status) => return Ok(Err(status)),
    };
    let name: String = units.iter().map(|&unit| char::from_u32(unit as u32).unwrap_or('\u{FFFD}')).collect();
    let mut start = object_manager::ROOT;
    if root != 0 {
        let opened = match namespace_handles::resolve(root, user) {
            Ok(opened) => opened,
            Err(status) => return Ok(Err(status)),
        };
        if !opened.directory {
            return Ok(Err(0xC000_0024));
        }
        if name.starts_with('\\') {
            return Ok(Err(0xC000_003B));
        }
        start = opened.node;
    } else if !name.starts_with('\\') {
        return Ok(Err(0xC000_003B));
    }
    let insensitive = flags & 0x40 != 0;
    let (found, rest) = object_manager::resolve_from(&name, 0, insensitive, false, start);
    if rest.is_some() {
        return Ok(Err(0xC000_003A));
    }
    let Some(found) = found.and_then(object_manager::node) else {
        let parent_path = name.rfind('\\').map_or("", |at| &name[..at]);
        let parent = object_manager::resolve_from(parent_path, 0, insensitive, false, start).0.and_then(object_manager::node);
        return Ok(Err(if parent.is_none_or(|parent| parent.type_name != "Directory") { 0xC000_003A } else { 0xC000_0034 }));
    };
    if found.type_name != "Partition" {
        return Ok(Err(0xC000_0024));
    }
    let resolved = found.data.map_or(0, |data| data.native_pointer);
    if resolved == 0 || Some(resolved) != get() {
        return Err(KernelError::new("partition namespace has no allocator owner"));
    }
    Ok(Ok((resolved, if user { flags & !0x200 } else { flags })))
}

/// NtOpenPartition / ZwOpenPartition.
pub fn open(output: u64, access: u32, attributes: u64, user: bool) -> Result<u32, KernelError> {
    if user && !state::probe_user_write(output, 8) {
        return Ok(0xC000_0005);
    }
    let (body, flags) = match capture(attributes, user)? {
        Ok(input) => input,
        Err(status) => return Ok(status),
    };
    // O tipo nativo exige segurança e recusa máscara de acesso zero.
    if user && access == 0 {
        return Ok(0xC000_0022);
    }
    let Some(object_type) = object_types::user_type("partition") else { return Ok(0xC000_0024) };
    if user && flags & 0x20 != 0 {
        let policy = dispatcher_objects::security(body).unwrap_or_default();
        if let Err(status) = object_access::check(&policy, object_access::subject(), access, &object_type, false) {
            return Ok(status);
        }
    }
    let scratch = guest::alloc_bytes(8);
    if scratch == 0 {
        return Ok(0xC000_009A);
    }
    let result = (|| -> Result<u32, KernelError> {
        let status = open_pointer::open(body, flags, 0, access, object_type.pointer, if user { 1 } else { 0 }, scratch)?;
        if status != 0 {
            return Ok(status);
        }
        // SAFETY: a célula de 8 bytes alocada acima.
        let handle = unsafe { Field::<u64>::at(scratch) }.get();
        if guest::try_write64(output, handle).is_err() {
            let _ = open_pointer::close(handle);
            return Ok(0xC000_0005);
        }
        Ok(0)
    })();
    guest::free_bytes(scratch);
    match result {
        Err(error) if error.status != STATUS_UNSUCCESSFUL => Ok(error.status),
        other => other,
    }
}

fn user_open(output: u64, access: u32, attributes: u64) -> Result<u32, KernelError> {
    open(output, access, attributes, true)
}

/// Handle de partição com o acesso pedido (em modo usuário).
pub fn resolve(handle: u64, access: u32, mode: u8) -> Result<u64, u32> {
    let resolved = match open_pointer::resolve(handle, mode != 0) {
        None => return Err(0xC000_0008),
        Some(Err(status)) => return Err(if status != 0 { status } else { 0xC000_0008 }),
        Some(Ok(resolved)) => resolved,
    };
    let Some(body) = get().filter(|&body| body == resolved.item.pointer) else { return Err(0xC000_0024) };
    if mode != 0 && resolved.access & access != access {
        return Err(0xC000_0022);
    }
    Ok(body)
}

// ---- NtManagePartition / ZwManagePartition -----------------------------------
//
// Contrato do ntoskrnl 19041 (NtManagePartition 0x6762c0):
// - Classe >= 9 -> STATUS_INVALID_INFO_CLASS; Length diferente do tamanho da
//   classe em PspPartitionInfoDetails -> STATUS_INFO_LENGTH_MISMATCH.
// - Flags da classe: 1 = a entrada é copiada para um buffer local (em
//   UserMode, sondada com o alinhamento da classe), 2 = o buffer volta ao
//   chamador depois do sucesso, 4 = exige a partição de origem.
// - O alvo é referenciado com o acesso da classe (PsReferencePartitionByHandle:
//   -1 = a partição do processo corrente, -2 = a do sistema, senão um handle de
//   Partition); com a flag 4 a origem também, e origem igual ao alvo dá
//   STATUS_INVALID_PARAMETER; sem a flag 4, uma origem não nula dá
//   STATUS_INVALID_PARAMETER_2.
// - Classe 0 (MmManagePartitionMemoryInformation), 6 (atributos) e as demais
//   (mover memória, arquivo de paginação, combinar páginas, memória inicial,
//   eventos de memória, informação de nó, páginas grandes).
//
// O OpenNT tem só a partição do sistema: a classe 1 sempre termina na
// recusa de origem igual ao alvo, a 6 é a regra da partição do sistema e a
// 0 descreve o alocador físico. As classes 2, 3, 4, 5, 7 e 8 dependem de
// partições filhas, de combinação de páginas, de páginas grandes ou de
// arquivo de paginação por partição, que o Mm do OpenNT não tem:
// STATUS_NOT_SUPPORTED.

const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;

/// Entrada de PspPartitionInfoDetails: acesso pedido ao alvo, tamanho exato
/// do buffer e flags (1 entrada, 2 saída, 4 origem).
struct ClassDetails {
    access: u32,
    size: u32,
    flags: u8,
}

/// PspPartitionInfoDetails do ntoskrnl 19041 (o alinhamento é 8 em todas).
const CLASS_DETAILS: [ClassDetails; 9] = [
    ClassDetails { access: 1, size: 0xF0, flags: 0xB },
    ClassDetails { access: 2, size: 0x10, flags: 0x5 },
    ClassDetails { access: 2, size: 0x28, flags: 0x1 },
    ClassDetails { access: 2, size: 0x18, flags: 0x3 },
    ClassDetails { access: 2, size: 0x20, flags: 0x3 },
    ClassDetails { access: 1, size: 0x28, flags: 0xB },
    ClassDetails { access: 2, size: 0x8, flags: 0x1 },
    ClassDetails { access: 1, size: 0x10, flags: 0xB },
    ClassDetails { access: 2, size: 0x20, flags: 0x3 },
];

/// O buffer da classe 0 (MEMORY_PARTITION_CONFIGURATION_INFORMATION do
/// 19041, 0xF0 bytes): os offsets são os que o
/// MmManagePartitionMemoryInformation grava.
#[repr(C)]
struct MemoryPartitionConfiguration {
    flags: Field<u32>,
    numa_node: Field<u32>,
    channel: Field<u32>,
    number_of_numa_nodes: Field<u32>,
    resident_available_pages: Field<u64>,
    committed_pages: Field<u64>,
    commit_limit: Field<u64>,
    peak_commitment: Field<u64>,
    total_number_of_pages: Field<u64>,
    available_pages: Field<u64>,
    zero_pages: Field<u64>,
    free_pages: Field<u64>,
    standby_pages: Field<u64>,
    standby_page_count_by_priority: [Field<u64>; 8],
    repurposed_pages_by_priority: [Field<u64>; 8],
    maximum_commit_limit: Field<u64>,
    /// +0xE0: só a partição do sistema o preenche, de um contador do MiState
    /// ligado às outras partições; com partição única fica 0.
    system_partition_count: Field<u64>,
    partition_id: Field<u32>,
    _pad_ec: Reserved<4>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for MemoryPartitionConfiguration {}

const _: () = {
    assert!(core::mem::size_of::<MemoryPartitionConfiguration>() == 0xF0);
    assert!(core::mem::offset_of!(MemoryPartitionConfiguration, total_number_of_pages) == 0x30);
    assert!(core::mem::offset_of!(MemoryPartitionConfiguration, standby_page_count_by_priority) == 0x58);
    assert!(core::mem::offset_of!(MemoryPartitionConfiguration, repurposed_pages_by_priority) == 0x98);
    assert!(core::mem::offset_of!(MemoryPartitionConfiguration, maximum_commit_limit) == 0xD8);
    assert!(core::mem::offset_of!(MemoryPartitionConfiguration, partition_id) == 0xE8);
};

/// KeNumberNodes no OpenNT (um nó, `ke/processor_topology`).
const NUMBER_OF_NODES: u32 = 1;

/// Maior uso de páginas já informado (o PeakCommitment da partição).
static PEAK_COMMITMENT: SpinLock<u64> = SpinLock::new(0);

/// PsReferencePartitionByHandle em KernelMode: -1 (processo corrente) e -2
/// (sistema) são a partição do sistema; um handle precisa ser de Partition.
fn reference_partition(handle: u64, access: u32) -> Result<u64, u32> {
    if handle as i64 == -1 || handle as i64 == -2 {
        return get().ok_or(STATUS_INVALID_HANDLE);
    }
    resolve(handle, access, 0)
}

/// MmManagePartitionMemoryInformation sobre a partição do sistema: Flags 0,
/// NumaNode -1 (todos) ou um nó existente e Channel -1, senão
/// STATUS_INVALID_PARAMETER. O alocador físico do OpenNT tem só a lista
/// livre (sem páginas zeradas nem standby) e não contabiliza commit: as
/// páginas em uso são o commit, o limite é a RAM gerida e o pico é o maior
/// uso já informado. Com um nó pedido, os totais do sistema ficam 0 e
/// sobram as listas daquele nó.
fn memory_information(information: &MemoryPartitionConfiguration) -> u32 {
    let node = information.numa_node.get();
    if information.flags.get() != 0 || (node != u32::MAX && node >= NUMBER_OF_NODES) || information.channel.get() != u32::MAX {
        return STATUS_INVALID_PARAMETER;
    }
    let (total, free) = (pfn::total_count(), pfn::free_count());
    for index in 0..8 {
        information.standby_page_count_by_priority[index].set(0);
        information.repurposed_pages_by_priority[index].set(0);
    }
    if node == u32::MAX {
        let committed = total - free.min(total);
        let peak = {
            let mut peak = PEAK_COMMITMENT.lock();
            *peak = (*peak).max(committed);
            *peak
        };
        information.number_of_numa_nodes.set(NUMBER_OF_NODES);
        information.resident_available_pages.set(free);
        information.committed_pages.set(committed);
        information.commit_limit.set(total);
        information.peak_commitment.set(peak);
        information.maximum_commit_limit.set(total);
    } else {
        information.number_of_numa_nodes.set(0);
        information.resident_available_pages.set(0);
        information.committed_pages.set(0);
        information.commit_limit.set(0);
        information.peak_commitment.set(0);
        information.maximum_commit_limit.set(0);
    }
    information.system_partition_count.set(0);
    information.total_number_of_pages.set(total);
    information.zero_pages.set(0);
    information.free_pages.set(free);
    information.standby_pages.set(0);
    information.available_pages.set(free);
    // A partição do sistema é a de id 0.
    information.partition_id.set(0);
    0
}

/// SystemMemoryPartitionSetAttributes: 0 é aceito sem efeito; bits fora de
/// 0..1 ou a partição do sistema são recusados.
fn set_attributes(attributes: u64) -> u32 {
    if attributes == 0 { 0 } else { STATUS_INVALID_PARAMETER }
}

/// ZwManagePartition(TargetHandle, SourceHandle, Class, Information, Length)
/// em KernelMode: os ponteiros do chamador não são sondados.
pub fn manage(target: u64, source: u64, class: u32, information: u64, length: u32) -> Result<u32, KernelError> {
    let Some(details) = CLASS_DETAILS.get(class as usize) else { return Ok(STATUS_INVALID_INFO_CLASS) };
    if length != details.size {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    let buffer = guest::alloc_bytes(MemoryPartitionConfiguration::SIZE);
    if buffer == 0 {
        return Err(KernelError::new("ZwManagePartition: sem memoria para o buffer local"));
    }
    let result = (|| -> u32 {
        guest::write_bytes(buffer, &[0; MemoryPartitionConfiguration::SIZE as usize]);
        if details.flags & 1 != 0 {
            guest::write_bytes(buffer, &guest::read_bytes(information, length as usize));
        }
        let target_body = match reference_partition(target, details.access) {
            Ok(body) => body,
            Err(status) => return status,
        };
        if details.flags & 4 != 0 {
            match reference_partition(source, details.access) {
                Ok(body) if body == target_body => return STATUS_INVALID_PARAMETER,
                Ok(_) => {}
                Err(status) => return status,
            }
        } else if source != 0 {
            return STATUS_INVALID_PARAMETER_2;
        }
        let status = match class {
            0 => memory_information(MemoryPartitionConfiguration::of(buffer)),
            // SAFETY: buffer local de 0xF0 bytes; a classe 6 usa o primeiro ULONG64.
            6 => set_attributes(unsafe { Field::<u64>::at(buffer) }.get()),
            _ => STATUS_NOT_SUPPORTED,
        };
        if status & 0x8000_0000 == 0 && details.flags & 2 != 0 {
            guest::write_bytes(information, &guest::read_bytes(buffer, length as usize));
        }
        status
    })();
    guest::free_bytes(buffer);
    Ok(result)
}

impl MemoryPartitionConfiguration {
    /// O buffer local de `manage`.
    fn of(pointer: u64) -> &'static MemoryPartitionConfiguration {
        // SAFETY: bloco de 0xF0 bytes alocado por `manage`, vivo durante a classe.
        unsafe { MemoryPartitionConfiguration::at(pointer) }
    }
}

/// Liga o NtOpenPartition de usuário.
pub fn install() {
    crate::ntos::ps::user::syscalls_core::set_partition_opener(user_open);
}
