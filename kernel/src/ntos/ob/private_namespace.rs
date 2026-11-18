//! Namespaces privados e descritores de fronteira: NtCreatePrivateNamespace,
//! NtOpenPrivateNamespace e NtDeletePrivateNamespace (ntoskrnl 19041).
//!
//! Um namespace privado é um diretório sem nome achado pelo descritor de
//! fronteira (nome, SIDs e rótulo de integridade) numa tabela de hash do
//! silo, a OBJECT_NAMESPACE_LOOKUPTABLE do ESERVERSILO_GLOBALS (+0x80; o
//! host usa uma tabela própria, alocada no primeiro uso). O kernelbase passa
//! o handle do diretório como RootDirectory dos objetos `Alias\Nome`.
//!
//! - ObpCaptureBoundaryDescriptor (rva 0x718a8c): o cabeçalho de 16 bytes
//!   lido uma vez; TotalSize de 0x10 a 0x7FFF (senão
//!   STATUS_INVALID_PARAMETER); em UserMode o ProbeForRead do TotalSize com
//!   alinhamento 4. A cópia vai para um bloco do pool paginável ('ObNS') no
//!   formato do OBJECT_NAMESPACE_ENTRY, com a fronteira em +0x30. Com o flag
//!   BOUNDARY_DESCRIPTOR_ADD_APPCONTAINER_SID (1) e um token de AppContainer,
//!   o SID do pacote entra no fim como mais uma entrada de SID. TotalSize e
//!   Items da cópia voltam aos valores capturados; o
//!   RtlEnumerateBoundaryDescriptorEntries valida a cópia (Version 1, cada
//!   entrada com pelo menos o cabeçalho e dentro do TotalSize, no máximo um
//!   nome — senão STATUS_DUPLICATE_NAME — e um rótulo — senão 0xC000022A —,
//!   SIDs válidos, Items igual ao número de entradas visitadas) e o
//!   ObpCheckDuplicateEntries recusa entradas repetidas
//!   (STATUS_INVALID_PARAMETER). O hash é a soma dos bytes de dados das
//!   entradas, num byte, módulo 37.
//! - ObpVerifyCreatorAccessCheck (rva 0x7188b0): token de personificação
//!   abaixo de SecurityImpersonation é STATUS_ACCESS_DENIED; cada SID que
//!   não é de pacote passa por um SeAccessCheck de DIRECTORY_ALL_ACCESS
//!   contra uma DACL que concede 0xF000F só a ele (e ao SID do AppContainer
//!   de quem chama), com o rótulo do próprio token; o rótulo da fronteira
//!   passa pelo mesmo access check só com o rótulo dele (NO_WRITE_UP |
//!   NO_READ_UP | NO_EXECUTE_UP). Um SID de pacote precisa ser o do
//!   AppContainer de quem chama (senão STATUS_ACCESS_DENIED) e aparecer uma
//!   vez só (senão STATUS_INVALID_PARAMETER); um chamador de AppContainer
//!   precisa do seu SID na fronteira (STATUS_ACCESS_DENIED).
//! - NtCreatePrivateNamespace (rva 0x718640): captura, verificação, o
//!   diretório sem nome (OBJECT_ATTRIBUTES com nome é
//!   STATUS_OBJECT_NAME_INVALID) com Flags = 1 e SessionId -1; o
//!   ObpRegisterPrivateNamespace o põe no fim do balde do hash (uma fronteira
//!   igual já registrada é STATUS_OBJECT_NAME_COLLISION). A tabela guarda uma
//!   referência ao diretório; o handle sai do ObInsertObjectEx (o acesso
//!   pedido sem verificação) e só depois a entrada aponta o diretório e o
//!   diretório a entrada.
//! - NtOpenPrivateNamespace (rva 0x718470): atributos filtrados (0x1DF2 em
//!   UserMode, 0x11FF2 em KernelMode), fronteira capturada, busca na tabela
//!   (fronteira igual: mesmo tamanho, mesmo Items e cada entrada registrada
//!   presente uma vez na pedida) e o ObOpenObjectByPointer com o acesso
//!   verificado contra o descritor do diretório; sem entrada (ou entrada
//!   ainda sem diretório), STATUS_OBJECT_PATH_NOT_FOUND.
//! - NtDeletePrivateNamespace (rva 0x8df560): handle de diretório com
//!   DELETE; sem NamespaceEntry é STATUS_INVALID_HANDLE; o
//!   ObpVerifyCreatorAccessCheck com a fronteira registrada e o
//!   ObpRemoveNamespaceFromTable.
//! - ObpRemoveNamespaceFromTable (rva 0x68aeec): Flags |= 2; com
//!   NamespaceEntry, a entrada sai do balde e a tabela solta a referência;
//!   sem, 0xC0190021. O ObpCloseDirectoryObject chama a mesma rotina no
//!   último handle de um diretório com Flags & 1.
//!
//! No OpenNT o diretório é um nó sem pai da árvore do Object Manager. Os
//! serviços que levam o RootDirectory a um caminho usam o caminho ancorado
//! de [`anchor_name`] (um primeiro componente com o nó e um segredo que só o
//! kernel conhece), que a busca do namespace resolve de volta ao nó.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::ex::{list_entry, pool_allocation};
use crate::ntos::inc::types::extra_ob_namespace::{ObjectBoundaryDescriptor, ObjectBoundaryEntry, ObjectNamespaceEntry};
use crate::ntos::inc::types::{Ejob, EserversiloGlobals, NtStruct, ObjectAttributes, ObjectNamespaceLookuptable, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::handles::namespace as namespace_handles;
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::ntos::ob::objects::namespace::{self as namespace_objects, DIRECTORY_NAMESPACE_REMOVED, DIRECTORY_PRIVATE_NAMESPACE};
use crate::ntos::ob::{object_access, object_types, open_pointer};
use crate::ntos::ps::user_probe;
use crate::ntos::se::model::{Ace, SecurityPolicy};
use crate::ntos::se::token::tokens;
use crate::rtl::SpinLock;

const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_DUPLICATE_NAME: u32 = 0xC000_00BD;
const STATUS_INTERNAL_ERROR: u32 = 0xC000_00E5;
/// O segundo rótulo de integridade numa fronteira.
const STATUS_DUPLICATE_LABEL: u32 = 0xC000_022A;
/// ObpRemoveNamespaceFromTable de um diretório que já saiu da tabela.
const STATUS_NAMESPACE_NOT_REGISTERED: u32 = 0xC019_0021;

/// 'ObNS', a tag da captura e da tabela.
const POOL_TAG: u32 = 0x534E_624F;
const PAGED_POOL: u32 = 1;
/// O tamanho do OBJECT_NAMESPACE_ENTRY antes da cópia da fronteira.
const ENTRY_HEADER: u64 = ObjectNamespaceEntry::SIZE;
const BUCKETS: u8 = 37;

/// Tipos de entrada da fronteira.
const ENTRY_NAME: u32 = 1;
const ENTRY_SID: u32 = 2;
const ENTRY_LABEL: u32 = 3;
/// BOUNDARY_DESCRIPTOR_ADD_APPCONTAINER_SID.
const ADD_APPCONTAINER_SID: u32 = 1;

const DIRECTORY_ALL_ACCESS: u32 = 0xF_000F;
const DELETE: u32 = 0x1_0000;
const OBJ_PERMANENT: u32 = 0x10;
const OBJ_KERNEL_HANDLE: u32 = 0x200;
/// OBJ_VALID_KERNEL_ATTRIBUTES, os atributos que o ObCreateObjectEx aceita.
const VALID_ATTRIBUTES: u32 = 0x1_1FF2;
/// Os atributos que o NtOpenPrivateNamespace mantém de UserMode e de
/// KernelMode.
const OPEN_USER_ATTRIBUTES: u32 = 0x1DF2;
const OPEN_KERNEL_ATTRIBUTES: u32 = 0x1_1FF2;
/// SeCreatePermanentPrivilege.
const SE_CREATE_PERMANENT_PRIVILEGE: u64 = 16;
/// Mandatory policy do rótulo do access check: NO_WRITE_UP | NO_READ_UP |
/// NO_EXECUTE_UP.
const LABEL_POLICY: u32 = 7;

/// Um namespace privado vivo: o bloco da entrada (dono até o diretório ser
/// coletado), o nó do diretório, o segredo do caminho ancorado e a tabela em
/// que a entrada foi registrada (0 fora dela).
struct Namespace {
    entry: u64,
    node: NodeId,
    secret: u64,
    table: u64,
}

struct State {
    /// A OBJECT_NAMESPACE_LOOKUPTABLE do host (0 antes do primeiro uso).
    host_table: u64,
    /// Corpo do diretório -> namespace.
    namespaces: BTreeMap<u64, Namespace>,
}

/// O registro dos namespaces e, como a trava da tabela (o push lock do
/// OBJECT_NAMESPACE_LOOKUPTABLE), a serialização de todo vínculo de balde.
static STATE: SpinLock<State> = SpinLock::new(State { host_table: 0, namespaces: BTreeMap::new() });

fn entry_at(block: u64) -> &'static ObjectNamespaceEntry {
    // SAFETY: blocos de captura alocados por `capture_boundary`.
    unsafe { ObjectNamespaceEntry::at(block) }
}

fn boundary_at(address: u64) -> &'static ObjectBoundaryDescriptor {
    // SAFETY: a cópia da fronteira dentro de um bloco de captura.
    unsafe { ObjectBoundaryDescriptor::at(address) }
}

fn boundary_entry_at(address: u64) -> &'static ObjectBoundaryEntry {
    // SAFETY: uma entrada já conferida contra o TotalSize da cópia.
    unsafe { ObjectBoundaryEntry::at(address) }
}

fn table_at(table: u64) -> &'static ObjectNamespaceLookuptable {
    // SAFETY: a tabela do host ou a do ESERVERSILO_GLOBALS do silo.
    unsafe { ObjectNamespaceLookuptable::at(table) }
}

fn free_block(block: u64) {
    if block != 0 {
        let _ = pool_allocation::free(block, POOL_TAG as u64);
    }
}

/// Os baldes ainda zerados de uma tabela recebem InitializeListHead.
fn initialize_table(table: u64) {
    let lookup = table_at(table);
    for bucket in &lookup.hash_buckets {
        if bucket.flink.get() == 0 {
            list_entry::initialize(bucket);
        }
    }
}

/// PsGetCurrentServerSiloGlobals()->ObSiloState.PrivateNamespaceLookupTable,
/// com o estado já travado.
fn current_table(state: &mut State) -> Result<u64, u32> {
    let silo = crate::ntos::ps::silo::query::current_server_silo();
    if silo != 0 {
        // SAFETY: o silo de servidor da thread corrente, vivo enquanto ela roda.
        let globals = unsafe { Ejob::at(silo) }.server_silo_globals.get();
        if globals != 0 {
            // SAFETY: os ESERVERSILO_GLOBALS do silo vivo.
            let table = unsafe { EserversiloGlobals::at(globals) }.ob_silo_state.private_namespace_lookup_table.address();
            initialize_table(table);
            return Ok(table);
        }
    }
    if state.host_table == 0 {
        let table = pool_allocation::allocate_tagged(PAGED_POOL, ObjectNamespaceLookuptable::SIZE, POOL_TAG).unwrap_or(0);
        if table == 0 {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        guest::write_bytes(table, &alloc::vec![0u8; ObjectNamespaceLookuptable::SIZE as usize]);
        initialize_table(table);
        state.host_table = table;
    }
    Ok(state.host_table)
}

// --- RtlEnumerateBoundaryDescriptorEntries -----------------------------------

/// RtlpValidateSidBuffer: espaço para o cabeçalho e as subautoridades, e o
/// RtlValidSid (revisão 1, até 15 subautoridades).
fn valid_sid_buffer(sid: u64, length: u32) -> bool {
    if length < 8 {
        return false;
    }
    let (revision, count) = (guest::read::<u8>(sid), guest::read::<u8>(sid + 1));
    length >= 8 + 4 * count as u32 && revision == 1 && count <= 15
}

/// RtlEnumerateBoundaryDescriptorEntries(Boundary, Callback, Context): o
/// cabeçalho (TotalSize >= 0x10, Version 1), cada entrada dentro do
/// TotalSize e o Items igual ao número de entradas visitadas (o callback que
/// devolve `false` para a varredura ali). Devolve o NTSTATUS.
fn enumerate(boundary: u64, callback: &mut dyn FnMut(u64) -> bool) -> u32 {
    let header = boundary_at(boundary);
    let total = header.total_size.get() as u64;
    if total < 0x10 || header.version.get() != 1 {
        return STATUS_INVALID_PARAMETER;
    }
    let end = boundary + total;
    let mut entry = boundary + 0x10;
    let (mut names, mut labels, mut visited) = (0u32, 0u32, 0u32);
    while entry + 8 < end {
        let record = boundary_entry_at(entry);
        let size = record.entry_data_size.get();
        visited += 1;
        if size < 8 || entry + size as u64 > end {
            return STATUS_INVALID_PARAMETER;
        }
        match record.entry_type.get() {
            ENTRY_NAME => {
                names += 1;
                if names > 1 {
                    return STATUS_DUPLICATE_NAME;
                }
            }
            ENTRY_SID => {
                if !valid_sid_buffer(entry + 8, size - 8) {
                    return STATUS_INVALID_PARAMETER;
                }
            }
            ENTRY_LABEL => {
                labels += 1;
                if labels > 1 {
                    return STATUS_DUPLICATE_LABEL;
                }
                if !valid_sid_buffer(entry + 8, size - 8) {
                    return STATUS_INVALID_PARAMETER;
                }
            }
            _ => return STATUS_INVALID_PARAMETER,
        }
        if !callback(entry) {
            break;
        }
        entry = (entry + size as u64 + 7) & !7;
    }
    if header.items.get() != visited {
        return STATUS_INVALID_PARAMETER;
    }
    0
}

/// As entradas de uma fronteira já validada, cada uma com o cabeçalho.
fn entries(boundary: u64) -> Vec<Vec<u8>> {
    let mut list = Vec::new();
    enumerate(boundary, &mut |entry| {
        list.push(guest::read_bytes(entry, boundary_entry_at(entry).entry_data_size.get() as usize));
        true
    });
    list
}

/// ObpCompareEntryLevel1/2: cada entrada de `stored` aparece exatamente uma
/// vez em `candidate`.
fn each_present_once(stored: &[Vec<u8>], candidate: &[Vec<u8>]) -> bool {
    stored.iter().all(|entry| candidate.iter().filter(|other| *other == entry).count() == 1)
}

/// ObpHashBoundaryFunction: a soma dos bytes de dados das entradas.
fn hash(boundary: u64) -> u8 {
    let mut sum = 0u8;
    enumerate(boundary, &mut |entry| {
        let size = boundary_entry_at(entry).entry_data_size.get() as usize;
        for byte in guest::read_bytes(entry + 8, size.saturating_sub(8)) {
            sum = sum.wrapping_add(byte);
        }
        true
    });
    sum % BUCKETS
}

// --- ObpCaptureBoundaryDescriptor ---------------------------------------------

/// O token de quem chama: o de personificação ou o primário.
fn subject_token() -> Option<tokens::Token> {
    object_access::subject().and_then(tokens::get)
}

/// ObpCaptureBoundaryDescriptor(Boundary, Captured*): o bloco da captura.
fn capture_boundary(boundary: u64, mode: u8) -> Result<u64, u32> {
    let from_user_mode = mode != 0;
    if from_user_mode && !user_probe::probe_user_read(boundary, ObjectBoundaryDescriptor::SIZE) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let header = guest::try_read_bytes(boundary, ObjectBoundaryDescriptor::SIZE as usize).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    let word = |offset: usize| u32::from_le_bytes([header[offset], header[offset + 1], header[offset + 2], header[offset + 3]]);
    let (mut items, mut total, flags) = (word(4), word(8), word(12));
    if total.wrapping_sub(0x10) > 0x7FEF {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if from_user_mode {
        if boundary & 3 != 0 {
            return Err(STATUS_DATATYPE_MISALIGNMENT);
        }
        if !user_probe::probe_user_read(boundary, total as u64) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
    }
    // O SID do AppContainer de quem chama, quando a fronteira o pede.
    let package = if flags & ADD_APPCONTAINER_SID != 0 { subject_token().and_then(|token| token.app_container) } else { None };
    let extra = package.as_ref().map_or(0, |sid| ((sid.len() as u64 + 7) & !7) + 8);
    let size = total as u64 + ENTRY_HEADER + extra;
    let block = pool_allocation::allocate_tagged(PAGED_POOL, size, POOL_TAG).unwrap_or(0);
    if block == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write_bytes(block, &[0u8; ENTRY_HEADER as usize]);
    entry_at(block).size_of_boundary_information.set(size - ENTRY_HEADER);
    let copy = block + ENTRY_HEADER;
    match guest::try_read_bytes(boundary, total as usize) {
        Ok(bytes) => guest::write_bytes(copy, &bytes),
        Err(_) => {
            free_block(block);
            return Err(STATUS_ACCESS_VIOLATION);
        }
    }
    if let Some(sid) = package {
        let at = copy + total as u64;
        if at & 7 != 0 {
            free_block(block);
            return Err(STATUS_INVALID_PARAMETER);
        }
        let entry_size = extra as u32;
        let mut bytes = alloc::vec![0u8; entry_size as usize];
        bytes[..4].copy_from_slice(&ENTRY_SID.to_le_bytes());
        bytes[4..8].copy_from_slice(&entry_size.to_le_bytes());
        bytes[8..8 + sid.len()].copy_from_slice(&sid);
        guest::write_bytes(at, &bytes);
        total += entry_size;
        items += 1;
    }
    let copied = boundary_at(copy);
    copied.total_size.set(total);
    copied.items.set(items);
    let mut status = enumerate(copy, &mut |_| true);
    if status == 0 {
        let list = entries(copy);
        if !each_present_once(&list, &list) {
            status = STATUS_INVALID_PARAMETER;
        }
    }
    entry_at(block).hash_value.set(hash(copy));
    if status != 0 {
        free_block(block);
        return Err(status);
    }
    Ok(block)
}

// --- ObpVerifyCreatorAccessCheck ----------------------------------------------

/// SACL com um único rótulo obrigatório (`label`, um SID S-1-16-x) e a
/// política NO_WRITE_UP | NO_READ_UP | NO_EXECUTE_UP.
fn label_sacl(label: &[u8]) -> Vec<u8> {
    let ace_size = 8 + label.len();
    let size = 8 + ace_size;
    let mut acl = alloc::vec![0u8; 8];
    acl[0] = 2;
    acl[2..4].copy_from_slice(&(size as u16).to_le_bytes());
    acl[4..6].copy_from_slice(&1u16.to_le_bytes());
    acl.extend_from_slice(&[0x11, 0]);
    acl.extend_from_slice(&(ace_size as u16).to_le_bytes());
    acl.extend_from_slice(&LABEL_POLICY.to_le_bytes());
    acl.extend_from_slice(label);
    acl
}

/// RtlIsPackageSid: revisão 1, ao menos duas subautoridades, autoridade
/// SECURITY_APP_PACKAGE_AUTHORITY (15) e a primeira subautoridade 2.
fn is_package_sid(sid: &[u8]) -> bool {
    sid.len() >= 12 && sid[0] == 1 && sid[1] >= 2 && sid[2..8] == [0, 0, 0, 0, 0, 15] && u32::from_le_bytes([sid[8], sid[9], sid[10], sid[11]]) == 2
}

/// ObpVerifyCreatorAccessCheck(Boundary): a identidade de quem chama contra
/// cada entrada da fronteira em `boundary`.
fn verify_creator_access(boundary: u64, mode: u8) -> u32 {
    let Some(token) = subject_token() else { return if mode == 0 { 0 } else { STATUS_ACCESS_DENIED } };
    if token.kind == 2 && token.impersonation_level < 2 {
        return STATUS_ACCESS_DENIED;
    }
    let directory_type = object_types::directory_type();
    let package = token.app_container.clone();
    // O TokenIntegrityLevel do token (sem rótulo, Medium, como no resto do Se).
    let own_label = if token.integrity.len() >= 12 { label_sacl(&token.integrity) } else { label_sacl(&crate::ntos::se::model::sid(16, &[0x2000])) };
    let mut status = 0u32;
    let mut package_found = false;
    let enumerated = enumerate(boundary, &mut |entry| {
        let record = boundary_entry_at(entry);
        let data = guest::read_bytes(entry + 8, record.entry_data_size.get() as usize - 8);
        let sid_length = 8 + 4 * data.get(1).copied().unwrap_or(0) as usize;
        let sid = &data[..sid_length.min(data.len())];
        let policy = match record.entry_type.get() {
            ENTRY_NAME => return true,
            ENTRY_SID if is_package_sid(sid) => {
                if package.as_ref().is_some_and(|package| package.as_slice() != sid) {
                    status = STATUS_ACCESS_DENIED;
                    return false;
                }
                if package_found {
                    status = STATUS_INVALID_PARAMETER;
                    return false;
                }
                package_found = true;
                return true;
            }
            ENTRY_SID => {
                let mut dacl = alloc::vec![Ace::allow(sid.to_vec(), DIRECTORY_ALL_ACCESS)];
                if let Some(package) = &package {
                    dacl.push(Ace::allow(package.clone(), DIRECTORY_ALL_ACCESS));
                }
                SecurityPolicy { dacl: Some(dacl), sacl: Some(own_label.clone()), ..SecurityPolicy::default() }
            }
            ENTRY_LABEL => SecurityPolicy { sacl: Some(label_sacl(sid)), ..SecurityPolicy::default() },
            _ => {
                status = STATUS_INTERNAL_ERROR;
                return false;
            }
        };
        // SeAccessCheckWithHint no modo de quem chama: KernelMode concede.
        if mode == 0 {
            return true;
        }
        match object_access::check_token(&policy, &token, DIRECTORY_ALL_ACCESS, &directory_type) {
            Ok(_) => true,
            Err(denied) => {
                status = denied;
                false
            }
        }
    });
    if status == 0 && enumerated != 0 {
        status = enumerated;
    }
    if status == 0 && package.is_some() && !package_found {
        status = STATUS_ACCESS_DENIED;
    }
    status
}

// --- ObpLookupNamespaceEntry / ObpRegisterPrivateNamespace ------------------

/// ObpLookupNamespaceEntry(Table, Captured): a entrada registrada com a
/// mesma fronteira, ou 0.
fn lookup(table: u64, captured: u64) -> u64 {
    let wanted = entry_at(captured);
    let bucket = &table_at(table).hash_buckets[wanted.hash_value.get() as usize % BUCKETS as usize];
    let wanted_entries = entries(captured + ENTRY_HEADER);
    let wanted_items = boundary_at(captured + ENTRY_HEADER).items.get();
    let mut link = bucket.flink.get();
    while link != bucket.address() {
        let candidate = entry_at(link);
        if candidate.size_of_boundary_information.get() == wanted.size_of_boundary_information.get() && boundary_at(link + ENTRY_HEADER).items.get() == wanted_items && each_present_once(&entries(link + ENTRY_HEADER), &wanted_entries) {
            return link;
        }
        link = candidate.list_entry.flink.get();
    }
    0
}

/// ObpRegisterPrivateNamespace(Entry): no fim do balde, ou
/// STATUS_OBJECT_NAME_COLLISION com uma fronteira igual já registrada.
fn register(directory: u64, entry: u64) -> u32 {
    let mut state = STATE.lock();
    let table = match current_table(&mut state) {
        Ok(table) => table,
        Err(status) => return status,
    };
    if lookup(table, entry) != 0 {
        return STATUS_OBJECT_NAME_COLLISION;
    }
    let lookup_table = table_at(table);
    let record = entry_at(entry);
    list_entry::insert_tail(&lookup_table.hash_buckets[record.hash_value.get() as usize % BUCKETS as usize], &record.list_entry);
    lookup_table.number_of_private_spaces.set(lookup_table.number_of_private_spaces.get() + 1);
    if let Some(namespace) = state.namespaces.get_mut(&directory) {
        namespace.table = table;
    }
    0
}

/// Tira a entrada do diretório do balde da tabela em que ela está (o
/// chamador tem a trava).
fn unlink(state: &mut State, directory: u64) {
    let Some(namespace) = state.namespaces.get_mut(&directory) else { return };
    let table = core::mem::replace(&mut namespace.table, 0);
    if table != 0 && list_entry::remove(&entry_at(namespace.entry).list_entry).is_some() {
        let lookup_table = table_at(table);
        lookup_table.number_of_private_spaces.set(lookup_table.number_of_private_spaces.get().saturating_sub(1));
    }
}

/// ObpRemoveNamespaceFromTable(Directory): Flags |= 2; a entrada sai do
/// balde e a referência da tabela é solta.
pub fn remove_from_table(directory: u64) -> u32 {
    let removed = {
        let mut state = STATE.lock();
        let _ = namespace_objects::set_directory_flags(directory, DIRECTORY_NAMESPACE_REMOVED);
        let entry = namespace_objects::namespace_entry(directory);
        if entry != 0 {
            let _ = namespace_objects::set_namespace_entry(directory, 0);
            entry_at(entry).namespace.set(0);
            unlink(&mut state, directory);
        }
        entry != 0
    };
    if !removed {
        return STATUS_NAMESPACE_NOT_REGISTERED;
    }
    let _ = namespace_objects::detach(directory);
    0
}

/// A coleta do diretório (o fim do objeto no NT): o bloco da entrada vai
/// embora com ele.
pub fn release_directory(directory: u64) {
    let released = {
        let mut state = STATE.lock();
        unlink(&mut state, directory);
        state.namespaces.remove(&directory)
    };
    if let Some(namespace) = released {
        free_block(namespace.entry);
    }
}

// --- O caminho ancorado ---------------------------------------------------------

/// O primeiro componente de um caminho ancorado no diretório `node`.
pub fn anchor_name(node: NodeId) -> Option<String> {
    let state = STATE.lock();
    let namespace = state.namespaces.values().find(|namespace| namespace.node == node)?;
    Some(alloc::format!("\0{:x}:{:016x}", node, namespace.secret))
}

/// O diretório de um componente produzido por [`anchor_name`].
pub fn anchor_node(component: &str) -> Option<NodeId> {
    let rest = component.strip_prefix('\0')?;
    let (node, secret) = rest.split_once(':')?;
    let (node, secret) = (u64::from_str_radix(node, 16).ok()?, u64::from_str_radix(secret, 16).ok()?);
    let state = STATE.lock();
    state.namespaces.values().any(|namespace| namespace.node == node && namespace.secret == secret).then_some(node)
}

// --- Os serviços --------------------------------------------------------------

/// O ObpCaptureObjectCreateInformation do diretório: (atributos, descritor,
/// tem nome).
fn capture_attributes(attributes: u64, from_user_mode: bool) -> Result<(u32, u64, bool), u32> {
    if attributes == 0 {
        return Ok((0, 0, false));
    }
    if from_user_mode && (attributes & 7 != 0 || !user_probe::probe_user_read(attributes, ObjectAttributes::SIZE)) {
        return Err(if attributes & 7 != 0 { STATUS_DATATYPE_MISALIGNMENT } else { STATUS_ACCESS_VIOLATION });
    }
    let read = |offset: usize| guest::try_read::<u64>(attributes + offset as u64).map_err(|_| STATUS_ACCESS_VIOLATION);
    let length = guest::try_read::<u32>(attributes + core::mem::offset_of!(ObjectAttributes, length) as u64).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    if length != ObjectAttributes::SIZE as u32 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let root = read(core::mem::offset_of!(ObjectAttributes, root_directory))?;
    let mut flags = guest::try_read::<u32>(attributes + core::mem::offset_of!(ObjectAttributes, attributes) as u64).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    if from_user_mode {
        flags &= !OBJ_KERNEL_HANDLE;
    }
    if flags & !VALID_ATTRIBUTES != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let name = read(core::mem::offset_of!(ObjectAttributes, object_name))?;
    let descriptor = read(core::mem::offset_of!(ObjectAttributes, security_descriptor))?;
    let named = if name != 0 {
        if from_user_mode && !user_probe::probe_user_read(name, UnicodeString::SIZE) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        guest::try_read::<u16>(name + core::mem::offset_of!(UnicodeString, length) as u64).map_err(|_| STATUS_ACCESS_VIOLATION)? != 0
    } else {
        false
    };
    if name == 0 && root != 0 {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    if flags & OBJ_PERMANENT != 0 && from_user_mode && !crate::ntos::se::privilege::single_privilege_check(SE_CREATE_PERMANENT_PRIVILEGE, 1) {
        return Err(STATUS_PRIVILEGE_NOT_HELD);
    }
    Ok((flags, descriptor, named))
}

/// O segredo do caminho ancorado de um diretório novo.
fn secret(directory: u64, node: NodeId) -> u64 {
    crate::hal::cpu::hardware_random_u64().unwrap_or_else(|| crate::hal::cpu::rdtsc().rotate_left(29) ^ directory.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ node)
}

/// NtCreatePrivateNamespace(NamespaceHandle*, DesiredAccess,
/// ObjectAttributes, BoundaryDescriptor).
pub fn create(output: u64, access: u32, attributes: u64, boundary: u64, mode: u8) -> u32 {
    let from_user_mode = mode != 0;
    if from_user_mode && !user_probe::probe_user_write(output, 8) {
        return STATUS_ACCESS_VIOLATION;
    }
    let captured = match capture_boundary(boundary, mode) {
        Ok(captured) => captured,
        Err(status) => return status,
    };
    let status = verify_creator_access(captured + ENTRY_HEADER, mode);
    if status != 0 {
        free_block(captured);
        return status;
    }
    let (flags, descriptor, named) = match capture_attributes(attributes, from_user_mode) {
        Ok(captured_attributes) => captured_attributes,
        Err(status) => {
            free_block(captured);
            return status;
        }
    };
    if named {
        free_block(captured);
        return STATUS_OBJECT_NAME_INVALID;
    }
    // O diretório sem nome: a referência inicial do corpo é a da tabela.
    let node = object_manager::new_node("", "Directory", None);
    let directory = match namespace_objects::ensure(node) {
        Ok(Some(directory)) => directory,
        Ok(None) => {
            free_block(captured);
            return STATUS_OBJECT_TYPE_MISMATCH;
        }
        Err(error) => {
            free_block(captured);
            return if error.status != 0 { error.status } else { STATUS_INSUFFICIENT_RESOURCES };
        }
    };
    STATE.lock().namespaces.insert(directory, Namespace { entry: captured, node, secret: secret(directory, node), table: 0 });
    let _ = namespace_objects::set_directory_flags(directory, DIRECTORY_PRIVATE_NAMESPACE);
    let assigned = crate::ntos::ob::object_security::assign_named(directory, None, descriptor, from_user_mode);
    if assigned != 0 {
        let _ = namespace_objects::detach(directory);
        return assigned;
    }
    let status = register(directory, captured);
    if status != 0 {
        let _ = namespace_objects::detach(directory);
        return status;
    }
    // ObInsertObjectEx: o handle de quem cria, sem verificação de acesso.
    let directory_type = object_types::directory_type().pointer;
    let status = match open_pointer::open(directory, flags, 0, access, directory_type, 0, output) {
        Ok(status) => status,
        Err(error) => {
            if error.status != 0 {
                error.status
            } else {
                STATUS_INSUFFICIENT_RESOURCES
            }
        }
    };
    let keep = {
        let mut state = STATE.lock();
        if status != 0 || namespace_objects::directory_flags(directory) & DIRECTORY_NAMESPACE_REMOVED != 0 {
            unlink(&mut state, directory);
            false
        } else {
            entry_at(captured).namespace.set(directory);
            let _ = namespace_objects::set_namespace_entry(directory, captured);
            true
        }
    };
    if !keep {
        let _ = namespace_objects::detach(directory);
    }
    status
}

/// NtOpenPrivateNamespace(NamespaceHandle*, DesiredAccess,
/// ObjectAttributes, BoundaryDescriptor).
pub fn open(output: u64, access: u32, attributes: u64, boundary: u64, mode: u8) -> u32 {
    let from_user_mode = mode != 0;
    if from_user_mode && !user_probe::probe_user_write(output, 8) {
        return STATUS_ACCESS_VIOLATION;
    }
    let mut flags = 0;
    if attributes != 0 {
        if from_user_mode && attributes & 7 != 0 {
            return STATUS_DATATYPE_MISALIGNMENT;
        }
        if from_user_mode && !user_probe::probe_user_read(attributes, ObjectAttributes::SIZE) {
            return STATUS_ACCESS_VIOLATION;
        }
        flags = match guest::try_read::<u32>(attributes + core::mem::offset_of!(ObjectAttributes, attributes) as u64) {
            Ok(flags) => flags,
            Err(_) => return STATUS_ACCESS_VIOLATION,
        };
    }
    flags &= if from_user_mode { OPEN_USER_ATTRIBUTES } else { OPEN_KERNEL_ATTRIBUTES };
    let captured = match capture_boundary(boundary, mode) {
        Ok(captured) => captured,
        Err(status) => return status,
    };
    let directory = {
        let mut state = STATE.lock();
        let found = current_table(&mut state).map_or(0, |table| lookup(table, captured));
        let directory = if found != 0 { entry_at(found).namespace.get() } else { 0 };
        if directory != 0 {
            let _ = namespace_objects::reference(directory);
        }
        directory
    };
    free_block(captured);
    if directory == 0 {
        return STATUS_OBJECT_PATH_NOT_FOUND;
    }
    let directory_type = object_types::directory_type().pointer;
    let status = match open_pointer::open(directory, flags, 0, access, directory_type, mode, output) {
        Ok(status) => status,
        Err(error) => {
            if error.status != 0 {
                error.status
            } else {
                STATUS_INSUFFICIENT_RESOURCES
            }
        }
    };
    let _ = namespace_objects::dereference(directory);
    status
}

/// NtDeletePrivateNamespace(NamespaceHandle).
pub fn delete(handle: u64, mode: u8) -> u32 {
    let from_user_mode = mode != 0;
    let opened = match namespace_handles::resolve(handle, from_user_mode) {
        Ok(opened) => opened,
        Err(status) => return status,
    };
    if !opened.directory {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if from_user_mode && opened.access & DELETE == 0 {
        return STATUS_ACCESS_DENIED;
    }
    let directory = opened.body;
    if namespace_objects::reference(directory).is_err() {
        return STATUS_INVALID_HANDLE;
    }
    let entry = STATE.lock().namespaces.get(&directory).map_or(0, |namespace| namespace.entry);
    let status = if namespace_objects::namespace_entry(directory) == 0 || entry == 0 {
        STATUS_INVALID_HANDLE
    } else {
        match verify_creator_access(entry + ENTRY_HEADER, mode) {
            0 => remove_from_table(directory),
            denied => denied,
        }
    };
    let _ = namespace_objects::dereference(directory);
    status
}
