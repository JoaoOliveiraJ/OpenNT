//! Tokens LowBox (AppContainer): o NtCreateLowBoxToken e o estado que o
//! token LowBox referencia.
//!
//! Conferido contra o ntoskrnl 19041 (rvas): NtCreateLowBoxToken 0x6ef290,
//! SepCheckCreateLowBox 0x6a2224, SepCaptureHandles 0x328708,
//! SepCheckCapabilities 0x68aa90, SepSetTokenCapabilities 0x5dd33c,
//! SepSetTokenLowboxNumber 0x70f01c (SepGetLowBoxNumberEntry 0x70f178,
//! SepInitializeLowBoxNumberTable 0x78e378, SepDereferenceLowBoxNumberEntry
//! 0x6355dc), SepSetTokenCachedHandles 0x70ecc4
//! (SepReferenceCachedTokenHandles 0x35f8e4,
//! SepValidateReferencedCachedHandles 0x70f360, SepDereferenceCachedHandlesEntry
//! 0x635720), SepSetTokenPackage 0x710860, SepAppendAceToTokenDefaultDacl
//! 0x3226d4 e SepAppendAceToTokenObjectAcl 0x6d8120.
//!
//! NtCreateLowBoxToken(TokenHandle*, ExistingTokenHandle, DesiredAccess,
//! ObjectAttributes, PackageSid, CapabilityCount, Capabilities, HandleCount,
//! Handles), na ordem do NT:
//! 1. de UserMode o TokenHandle é sondado para escrita e o vetor de Handles
//!    (HandleCount * 8 bytes) alinhado a 8 (STATUS_DATATYPE_MISALIGNMENT) e
//!    sondado; PackageSid nulo é STATUS_INVALID_PARAMETER e HandleCount e
//!    Handles têm de ser os dois nulos ou os dois não nulos
//!    (STATUS_INVALID_PARAMETER_MIX);
//! 2. o token existente com TOKEN_DUPLICATE; o pacote pelo SeCaptureSid; o
//!    SepCheckCreateLowBox: o token efetivo de quem chama precisa ter
//!    TOKEN_NOT_LOW (integridade Medium ou acima) ou ser um LowBox pai do
//!    pacote pedido (um token de impersonação abaixo de
//!    SecurityImpersonation nunca passa): senão STATUS_ACCESS_DENIED;
//! 3. um token existente de impersonação abaixo de SecurityImpersonation é
//!    STATUS_BAD_IMPERSONATION_LEVEL; o acesso do handle novo é o pedido ou,
//!    com zero, o do handle do token existente;
//! 4. as capacidades pelo SeCaptureSidAndAttributesArray e os handles pelo
//!    SepCaptureHandles (mais de 10 é STATUS_INVALID_PARAMETER_1); o pacote
//!    precisa ser S-1-15-2-... (STATUS_INVALID_PARAMETER) com 8 subautoridades
//!    (pacote pai) ou 12 (filho), senão STATUS_INVALID_PACKAGE_SID_LENGTH;
//!    cada capacidade precisa ser S-1-15-3-... e não repetir nenhuma anterior
//!    (STATUS_INVALID_PARAMETER); um pacote filho só leva capacidades que o
//!    token existente tem (SepCheckCapabilities, STATUS_ACCESS_DENIED);
//! 5. o token novo é a cópia primária do existente (SepDuplicateToken), com
//!    TOKEN_MANDATORY_POLICY_NO_WRITE_UP, o rótulo Low (sem grupo de
//!    integridade, STATUS_INVALID_LABEL), só SeChangeNotifyPrivilege e
//!    SeIncreaseWorkingSetPrivilege entre os privilégios, sem TOKEN_NOT_LOW
//!    e com TOKEN_LOWBOX; as capacidades (um token que já tinha capacidades
//!    só as troca por um pacote filho do dele), o número LowBox da sessão, a
//!    entrada de handles guardados, o pacote (de novo, só um filho troca o
//!    pacote de um LowBox) e uma ACE GENERIC_ALL do pacote no fim da DACL
//!    padrão (quando há DACL padrão e o pacote ainda não está nela), com
//!    ModifiedId novo;
//! 6. o handle novo; a DACL do objeto token ganha TOKEN_ALL_ACCESS para o
//!    pacote e o SepFinalizeTokenAcls.
//!
//! O número LowBox: por sessão, uma entrada por pacote com contagem de
//! referências; o número é o primeiro bit livre de um bitmap de 0x400 bits
//! mais um, e o bitmap dobra (até 0x10000 bits) quando enche. Um token copiado
//! (SepDuplicateToken, SepFilterToken) referencia a mesma entrada.
//!
//! Os handles guardados: o SepReferenceCachedTokenHandles copia cada handle
//! para a tabela do kernel (o ZwDuplicateObject com OBJ_KERNEL_HANDLE), e
//! esses handles mantêm vivos os diretórios
//! `\Sessions\<n>\AppContainerNamedObjects\<pacote>` (com o `RPC Control` e
//! os links `Global`, `Local` e `Session`) e o diretório do NPFS que o
//! kernelbase cria para o AppContainer, objetos temporários que perderiam o
//! nome no fechamento dos handles de quem os criou. Cada objeto precisa ser
//! um diretório, um link simbólico ou um arquivo do NPFS, com nome debaixo de
//! `\Sessions\<sessão do token>` (o último componente o nome do pacote, ou
//! Local, Global, RPC Control, Session ou AppContainerNamedObjects) ou de
//! `\Device\NamedPipe`; senão STATUS_INVALID_PARAMETER. A entrada é da
//! sessão de logon do token e do pacote: o primeiro token que a cria com
//! handles fica com eles; os seguintes só a referenciam e fecham as cópias.
//!
//! Lacunas: o SepIsLpacCapabilitySid usa uma tabela de capacidades
//! derivadas de nomes que o OpenNT não monta, então um pacote filho de um
//! AppContainer comum só recebe as capacidades do pai e a do próprio pacote;
//! o compartilhamento de SIDs de capacidade (SepTokenCapabilitySidSharing)
//! não existe no OpenNT.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{close as ob_close, object_reference, open_pointer, query_object, reference_trace};
use crate::ntos::ps::process;
use crate::ntos::ps::user_probe;
use crate::ntos::rtl::security as rtl_security;
use crate::ntos::se::capture;
use crate::ntos::se::model::{sid, Ace, Group, Sid};
use crate::ntos::se::token::{duplicate, handles as token_handles, reference as token_reference, thread as thread_tokens, tokens};
use crate::rtl::{KernelError, SpinLock};

const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_INVALID_PARAMETER_MIX: u32 = 0xC000_0030;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_BAD_IMPERSONATION_LEVEL: u32 = 0xC000_00A5;
const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
const STATUS_INVALID_LABEL: u32 = 0xC000_0446;
const STATUS_INVALID_PACKAGE_SID_LENGTH: u32 = 0xC000_A202;

/// TokenFlags: TOKEN_NOT_LOW e TOKEN_LOWBOX.
const TOKEN_NOT_LOW: u32 = 0x2000;
const TOKEN_LOWBOX: u32 = 0x4000;
/// TOKEN_DUPLICATE, TOKEN_ALL_ACCESS e GENERIC_ALL.
const TOKEN_DUPLICATE: u32 = 2;
const TOKEN_ALL_ACCESS: u32 = 0xF_01FF;
const GENERIC_ALL: u32 = 0x1000_0000;
/// TokenPrimary e SecurityImpersonation.
const TOKEN_PRIMARY: u32 = 1;
const SECURITY_IMPERSONATION: u32 = 2;
const TOKEN_MANDATORY_POLICY_NO_WRITE_UP: u32 = 1;
const SECURITY_MANDATORY_LOW_RID: u32 = 0x1000;
/// Os privilégios que um token LowBox conserva (Present, Enabled e
/// EnabledByDefault &= 0x200800000): SeChangeNotifyPrivilege (23) e
/// SeIncreaseWorkingSetPrivilege (33).
const LOWBOX_PRIVILEGES: u64 = 0x2_0080_0000;
/// O limite do SepCaptureHandles.
const MAXIMUM_CACHED_HANDLES: u32 = 10;
const OBJ_KERNEL_HANDLE: u32 = 0x200;
const OBJ_PERMANENT: u32 = 0x10;
const OBJ_EXCLUSIVE: u32 = 0x20;
const FILE_DEVICE_NAMED_PIPE: u32 = 0x11;
/// O número de subautoridades de um pacote pai e de um filho.
const PARENT_PACKAGE_SUB_AUTHORITIES: u8 = 8;
const CHILD_PACKAGE_SUB_AUTHORITIES: u8 = 12;
/// O bitmap inicial do SepInitializeLowBoxNumberTable e o maior.
const INITIAL_NUMBER_BITS: u32 = 0x400;
const MAXIMUM_NUMBER_BITS: u32 = 0x1_0000;
/// Os últimos componentes aceitos debaixo de `\Sessions\<n>`, além do nome
/// do pacote (AllowedCachedObjectNames).
const ALLOWED_CACHED_OBJECT_NAMES: [&str; 5] = ["Local", "Global", "RPC Control", "Session", "AppContainerNamedObjects"];

// ---- SIDs de pacote e de capacidade ----------------------------------------

fn sub_authority(identifier: &[u8], index: usize) -> u32 {
    let at = 8 + 4 * index;
    identifier.get(at..at + 4).map_or(0, |bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Revisão 1, ao menos duas subautoridades, a autoridade
/// SECURITY_APP_PACKAGE_AUTHORITY (15) e a primeira subautoridade `first`.
fn app_package_identifier(identifier: &[u8], first: u32) -> bool {
    identifier.len() >= 12 && identifier[1] >= 2 && identifier[0] == 1 && identifier[2..8] == [0, 0, 0, 0, 0, 15] && sub_authority(identifier, 0) == first
}

/// RtlIsPackageSid (ntoskrnl 19041, 0x5dad60): S-1-15-2-...
pub fn is_package_sid(identifier: &[u8]) -> bool {
    app_package_identifier(identifier, 2)
}

/// RtlIsCapabilitySid (ntoskrnl 19041, 0x6ef8a0): S-1-15-3-...
pub fn is_capability_sid(identifier: &[u8]) -> bool {
    app_package_identifier(identifier, 3)
}

/// O texto do RtlConvertSidToUnicodeString de um SID já copiado.
fn sid_text(identifier: &[u8]) -> String {
    let authority = identifier.get(2..8).unwrap_or(&[0; 6]);
    let mut text = String::from("S-1-");
    if authority[0] != 0 || authority[1] != 0 {
        let value = authority.iter().fold(0u64, |value, &byte| value << 8 | byte as u64);
        text.push_str(&alloc::format!("0x{value:X}"));
    } else {
        let value = authority[2..].iter().fold(0u32, |value, &byte| value << 8 | byte as u32);
        text.push_str(&alloc::format!("{value}"));
    }
    for index in 0..identifier.get(1).copied().unwrap_or(0) as usize {
        text.push_str(&alloc::format!("-{}", sub_authority(identifier, index)));
    }
    text
}

/// O nome do objeto de um pacote debaixo de AppContainerNamedObjects (o do
/// SepValidateReferencedCachedHandles e do kernelbase): o texto do SID de um
/// pacote pai; as quatro últimas subautoridades `%u-%u-%u-%u` de um filho.
pub fn package_object_name(package: &[u8]) -> String {
    if package.get(1).copied() == Some(CHILD_PACKAGE_SUB_AUTHORITIES) {
        return alloc::format!("{}-{}-{}-{}", sub_authority(package, 8), sub_authority(package, 9), sub_authority(package, 10), sub_authority(package, 11));
    }
    sid_text(package)
}

// ---- números LowBox ---------------------------------------------------------

struct NumberEntry {
    package: Sid,
    number: u32,
    references: u64,
}

/// A tabela de uma sessão (g_SessionLowboxArray[n] ou g_SessionLowboxMap):
/// o bitmap dos números e as entradas.
struct SessionNumbers {
    bits: u32,
    bitmap: Vec<u64>,
    entries: Vec<NumberEntry>,
}

impl SessionNumbers {
    fn new() -> Self {
        Self { bits: INITIAL_NUMBER_BITS, bitmap: alloc::vec![0; (INITIAL_NUMBER_BITS / 64) as usize], entries: Vec::new() }
    }

    /// RtlFindClearBitsAndSet(Bitmap, 1, 0): o primeiro bit livre, marcado.
    fn find_clear_and_set(&mut self) -> Option<u32> {
        for (word_index, word) in self.bitmap.iter_mut().enumerate() {
            if *word != u64::MAX {
                let bit = (!*word).trailing_zeros();
                let index = word_index as u32 * 64 + bit;
                if index >= self.bits {
                    return None;
                }
                *word |= 1 << bit;
                return Some(index);
            }
        }
        None
    }

    fn set_bits(&self) -> u32 {
        self.bitmap.iter().map(|word| word.count_ones()).sum()
    }

    fn clear(&mut self, index: u32) {
        if let Some(word) = self.bitmap.get_mut((index / 64) as usize) {
            *word &= !(1u64 << (index % 64));
        }
    }

    /// O bitmap cheio dobra: RtlNumberOfSetBits * 2 bits (no máximo
    /// 0x10000), os já usados marcados no começo.
    fn grow(&mut self) -> bool {
        let used = self.set_bits();
        let bits = used * 2;
        if bits > MAXIMUM_NUMBER_BITS {
            return false;
        }
        let mut bitmap = alloc::vec![0u64; bits.div_ceil(64) as usize];
        for index in 0..used {
            bitmap[(index / 64) as usize] |= 1 << (index % 64);
        }
        self.bits = bits;
        self.bitmap = bitmap;
        true
    }
}

static NUMBERS: SpinLock<BTreeMap<u32, SessionNumbers>> = SpinLock::new(BTreeMap::new());

/// SepSetTokenLowboxNumber/SepGetLowBoxNumberEntry: o número LowBox do
/// pacote na sessão, com mais uma referência na entrada (criada com o
/// primeiro número livre quando não existe). Sem número livre,
/// STATUS_INSUFFICIENT_RESOURCES.
pub fn reference_number(session: u32, package: &[u8]) -> Result<u32, u32> {
    let mut numbers = NUMBERS.lock();
    let table = numbers.entry(session).or_insert_with(SessionNumbers::new);
    if let Some(entry) = table.entries.iter_mut().find(|entry| entry.package == package) {
        entry.references += 1;
        return Ok(entry.number);
    }
    let index = match table.find_clear_and_set() {
        Some(index) => index,
        None => {
            if !table.grow() {
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
            table.find_clear_and_set().ok_or(STATUS_INSUFFICIENT_RESOURCES)?
        }
    };
    if index == 0xFFFF {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    table.entries.push(NumberEntry { package: package.to_vec(), number: index + 1, references: 1 });
    Ok(index + 1)
}

/// SepReferenceLowBoxNumberEntry: mais uma referência (a cópia de um token).
pub fn retain_number(session: u32, number: u32) {
    if let Some(entry) = NUMBERS.lock().get_mut(&session).and_then(|table| table.entries.iter_mut().find(|entry| entry.number == number)) {
        entry.references += 1;
    }
}

/// SepDereferenceLowBoxNumberEntry: a última referência tira a entrada e
/// libera o número.
pub fn release_number(session: u32, number: u32) {
    let mut numbers = NUMBERS.lock();
    let Some(table) = numbers.get_mut(&session) else { return };
    let Some(position) = table.entries.iter().position(|entry| entry.number == number) else { return };
    table.entries[position].references -= 1;
    if table.entries[position].references == 0 {
        table.entries.remove(position);
        table.clear(number - 1);
    }
}

/// O pacote da entrada do número LowBox `number` na sessão (o
/// SepFindMatchingLowBoxNumberEntries).
pub fn package_of_number(session: u32, number: u32) -> Option<Sid> {
    NUMBERS.lock().get(&session).and_then(|table| table.entries.iter().find(|entry| entry.number == number)).map(|entry| entry.package.clone())
}

/// As referências da entrada do número LowBox `number` na sessão (0 sem a
/// entrada).
pub fn number_references(session: u32, number: u32) -> u64 {
    NUMBERS.lock().get(&session).and_then(|table| table.entries.iter().find(|entry| entry.number == number)).map_or(0, |entry| entry.references)
}

// ---- handles guardados ------------------------------------------------------

/// A chave de uma entrada de handles guardados: a sessão de logon do token
/// (o SEP_LOGON_SESSION_REFERENCES em TOKEN+0xD8) e o pacote.
#[derive(Clone, Debug, PartialEq)]
pub struct HandlesKey {
    pub logon_id: u64,
    pub server_silo: u64,
    pub package: Sid,
}

struct HandlesEntry {
    key: HandlesKey,
    /// Os handles de kernel (SepReferenceCachedTokenHandles).
    handles: Vec<u64>,
    references: u64,
}

static HANDLES: SpinLock<Vec<HandlesEntry>> = SpinLock::new(Vec::new());

/// SepReferenceCachedHandlesEntry: mais uma referência (a cópia de um token).
pub fn retain_handles(key: &HandlesKey) {
    if let Some(entry) = HANDLES.lock().iter_mut().find(|entry| entry.key == *key) {
        entry.references += 1;
    }
}

/// SepDereferenceCachedHandlesEntry: a última referência tira a entrada e
/// fecha os handles de kernel dela (SepCloseCachedTokenHandles).
pub fn release_handles(key: &HandlesKey) {
    let closed = {
        let mut entries = HANDLES.lock();
        let Some(position) = entries.iter().position(|entry| entry.key == *key) else { return };
        entries[position].references -= 1;
        if entries[position].references != 0 {
            return;
        }
        entries.remove(position).handles
    };
    close_kernel_handles(&closed);
}

/// (referências, handles) da entrada de `key`.
pub fn handles_entry(key: &HandlesKey) -> Option<(u64, usize)> {
    HANDLES.lock().iter().find(|entry| entry.key == *key).map(|entry| (entry.references, entry.handles.len()))
}

fn close_kernel_handles(handles: &[u64]) {
    for &handle in handles {
        let _ = ob_close::close(handle, Some(0));
    }
}

/// O ObReferenceObjectByHandle(Handle, 0, NULL, KernelMode): o corpo
/// referenciado ou o NTSTATUS.
fn reference_object(handle: u64) -> Result<u64, u32> {
    let cell = guest::alloc_bytes(8);
    if cell == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write64(cell, 0);
    let status = object_reference::reference_by_handle(handle, 0, 0, 0, cell, 0).map(|status| status as u32).unwrap_or(STATUS_INVALID_HANDLE);
    let pointer = guest::read64(cell);
    guest::free_bytes(cell);
    if status != 0 || pointer == 0 {
        return Err(if status != 0 { status } else { STATUS_INVALID_HANDLE });
    }
    Ok(pointer)
}

fn dereference_object(pointer: u64) {
    let _ = object_reference::dereference_with_tag(pointer, reference_trace::DEFAULT_TAG, false);
}

/// O ZwDuplicateObject(NtCurrentProcess, Handle, NtCurrentProcess, ..., 0,
/// OBJ_KERNEL_HANDLE, DUPLICATE_SAME_ACCESS) do SepReferenceCachedTokenHandles:
/// um handle de kernel para o objeto do handle de quem chama.
fn kernel_handle_copy(handle: u64) -> Result<u64, u32> {
    let pointer = reference_object(handle)?;
    let cell = guest::alloc_bytes(8);
    if cell == 0 {
        dereference_object(pointer);
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let opened = open_pointer::open_by_pointer(pointer, OBJ_KERNEL_HANDLE, 0, 0, 0, 0, cell);
    let copy = guest::read64(cell);
    guest::free_bytes(cell);
    dereference_object(pointer);
    match opened {
        Ok(0) if copy != 0 => Ok(copy),
        Ok(0) => Err(STATUS_INVALID_HANDLE),
        Ok(status) => Err(status),
        Err(error) => Err(if error.status != 0 { error.status } else { STATUS_INVALID_HANDLE }),
    }
}

/// SepReferenceCachedTokenHandles: as cópias de kernel de todos os handles;
/// uma falha fecha as já feitas.
fn reference_cached_handles(handles: &[u64]) -> Result<Vec<u64>, u32> {
    let mut copies = Vec::with_capacity(handles.len());
    for &handle in handles {
        match kernel_handle_copy(handle) {
            Ok(copy) => copies.push(copy),
            Err(status) => {
                close_kernel_handles(&copies);
                return Err(status);
            }
        }
    }
    Ok(copies)
}

/// Comparação sem caixa de UTF-16 (a tabela de maiúsculas do NLS; antes
/// dela, ASCII).
fn upcase(unit: u16) -> u16 {
    crate::ntos::rtl::unicode_case::upcase_char(unit).unwrap_or(if (b'a' as u16..=b'z' as u16).contains(&unit) { unit - 32 } else { unit })
}

fn equal_insensitive(left: &str, right: &str) -> bool {
    let (left, right): (Vec<u16>, Vec<u16>) = (left.encode_utf16().collect(), right.encode_utf16().collect());
    left.len() == right.len() && left.iter().zip(&right).all(|(&a, &b)| a == b || upcase(a) == upcase(b))
}

/// RtlPrefixUnicodeString(Prefix, Name, TRUE).
fn prefix_insensitive(prefix: &str, name: &str) -> bool {
    let (prefix, name): (Vec<u16>, Vec<u16>) = (prefix.encode_utf16().collect(), name.encode_utf16().collect());
    prefix.len() <= name.len() && prefix.iter().zip(&name).all(|(&a, &b)| a == b || upcase(a) == upcase(b))
}

/// O SepQueryNameString de um corpo: o nome do arquivo (IopQueryName), o
/// caminho do nó de um diretório ou link (vazio depois que um objeto
/// temporário perdeu o nome) ou o caminho de outro objeto nomeado.
fn object_name(pointer: u64) -> Option<String> {
    if crate::ntos::ob::objects::file::is_file(pointer) {
        return crate::ntos::io::file::information::query_object_name(pointer).ok()?.ok().map(|units| String::from_utf16_lossy(&units));
    }
    if let Some((node, _)) = crate::ntos::ob::objects::namespace::get(pointer) {
        return crate::ntos::ob::object_manager::path_of(node);
    }
    query_object::native_object_path(pointer)
}

/// O tipo aceito pelo SepValidateReferencedCachedHandles: diretório, link
/// simbólico ou arquivo de um dispositivo FILE_DEVICE_NAMED_PIPE.
fn cacheable_type(pointer: u64) -> bool {
    let Some(item) = open_pointer::describe(pointer) else { return false };
    match item.object_type.name.as_str() {
        "Directory" | "SymbolicLink" => true,
        "File" => {
            use crate::ntos::inc::types::{DeviceObject, FileObject, NtStruct};
            // SAFETY: FILE_OBJECT vivo, referenciado por quem chama.
            let device = unsafe { FileObject::at(pointer) }.device_object.get();
            // SAFETY: o DEVICE_OBJECT do arquivo aberto.
            device != 0 && unsafe { DeviceObject::at(device) }.device_type.get() == FILE_DEVICE_NAMED_PIPE
        }
        _ => false,
    }
}

/// SepValidateReferencedCachedHandles (o tipo 0, LowBox): cada handle de
/// kernel aponta um objeto aceito, com nome debaixo de `\Sessions\<sessão>`
/// (o último componente o nome do pacote ou um dos permitidos) ou de
/// `\Device\NamedPipe`.
fn validate_cached_handles(session: u32, package: &[u8], copies: &[u64]) -> Result<(), u32> {
    let package_name = package_object_name(package);
    let sessions = alloc::format!("\\Sessions\\{session}");
    for &copy in copies {
        let pointer = reference_object(copy)?;
        let valid = (|| {
            if !cacheable_type(pointer) {
                return false;
            }
            let Some(name) = object_name(pointer).filter(|name| !name.is_empty()) else { return false };
            if prefix_insensitive(&sessions, &name) {
                let leaf = name.rsplit('\\').next().unwrap_or("");
                return !leaf.is_empty() && (equal_insensitive(leaf, &package_name) || ALLOWED_CACHED_OBJECT_NAMES.iter().any(|allowed| equal_insensitive(leaf, allowed)));
            }
            prefix_insensitive("\\Device\\NamedPipe", &name)
        })();
        dereference_object(pointer);
        if !valid {
            return Err(STATUS_INVALID_PARAMETER);
        }
    }
    Ok(())
}

/// SepSetTokenCachedHandles: as cópias de kernel dos handles validadas e a
/// entrada da sessão de logon e do pacote referenciada (criada quando não
/// existe). A entrada sem handles fica com as cópias; senão elas são
/// fechadas.
fn set_cached_handles(key: &HandlesKey, session: u32, handles: &[u64]) -> Result<(), u32> {
    let copies = if handles.is_empty() { Vec::new() } else { reference_cached_handles(handles)? };
    if let Err(status) = validate_cached_handles(session, &key.package, &copies) {
        close_kernel_handles(&copies);
        return Err(status);
    }
    let surplus = {
        let mut entries = HANDLES.lock();
        match entries.iter_mut().find(|entry| entry.key == *key) {
            Some(entry) => {
                entry.references += 1;
                if !copies.is_empty() && entry.handles.is_empty() {
                    entry.handles = copies;
                    Vec::new()
                } else {
                    copies
                }
            }
            None => {
                entries.push(HandlesEntry { key: key.clone(), handles: copies, references: 1 });
                Vec::new()
            }
        }
    };
    close_kernel_handles(&surplus);
    Ok(())
}

// ---- NtCreateLowBoxToken ----------------------------------------------------

/// O token efetivo de quem chama e se ele pode servir de pai de um
/// AppContainer (o SeCaptureSubjectContext do SepCheckCreateLowBox: o token
/// de impersonação abaixo de SecurityImpersonation não pode).
fn creator() -> (Option<u64>, bool) {
    match thread_tokens::get(process::get_current_thread()) {
        Some(impersonation) => (Some(impersonation.token), impersonation.level >= SECURITY_IMPERSONATION),
        None => (process::get_primary_token(process::get_current_process()), true),
    }
}

/// SepCheckCreateLowBox: quem chama tem TOKEN_NOT_LOW ou é o LowBox pai do
/// pacote.
fn check_create_lowbox(package: &[u8]) -> Result<(), u32> {
    let (Some(token), usable) = creator() else { return Err(STATUS_ACCESS_DENIED) };
    if !usable {
        return Err(STATUS_ACCESS_DENIED);
    }
    let flags = tokens::token_flags(token);
    if flags & TOKEN_NOT_LOW != 0 {
        return Ok(());
    }
    let parent = flags & TOKEN_LOWBOX != 0 && tokens::with(token, |record| record.app_container.as_ref().is_some_and(|parent| rtl_security::is_parent_of_child_app_container(parent, package))).unwrap_or(false);
    if parent { Ok(()) } else { Err(STATUS_ACCESS_DENIED) }
}

/// SepCheckCapabilities do pacote filho: um token existente que não é
/// AppContainer aceita qualquer capacidade; um AppContainer só as dele (com
/// os mesmos atributos) e a capacidade do próprio pacote (9 subautoridades,
/// a primeira 3, as subautoridades 1 a 7 iguais às do pacote dele).
fn check_capabilities(existing: u64, requested: &[Group]) -> bool {
    if tokens::token_flags(existing) & TOKEN_LOWBOX == 0 {
        return true;
    }
    tokens::with(existing, |token| {
        requested.iter().all(|capability| {
            if token.capabilities.iter().any(|own| own.sid == capability.sid && own.attributes == capability.attributes) {
                return true;
            }
            let package_capability = capability.sid.get(1).copied() == Some(9) && sub_authority(&capability.sid, 0) == 3;
            package_capability && token.app_container.as_ref().is_some_and(|package| package.get(1).copied().unwrap_or(0) >= PARENT_PACKAGE_SUB_AUTHORITIES && (1..8).all(|index| sub_authority(package, index) == sub_authority(&capability.sid, index)))
        })
    })
    .unwrap_or(false)
}

/// SepCaptureHandles: até 10 handles copiados do vetor (já sondado).
fn capture_handles(count: u32, handles: u64) -> Result<Vec<u64>, u32> {
    if count > MAXIMUM_CACHED_HANDLES {
        return Err(STATUS_INVALID_PARAMETER_1);
    }
    (0..count as u64).map(|index| guest::try_read::<u64>(handles + index * 8).map_err(|_| STATUS_ACCESS_VIOLATION)).collect()
}

/// Os argumentos do NtCreateLowBoxToken.
pub struct Request {
    pub token_handle: u64,
    pub existing_token: u64,
    pub desired_access: u32,
    pub object_attributes: u64,
    pub package_sid: u64,
    pub capability_count: u32,
    pub capabilities: u64,
    pub handle_count: u32,
    pub handles: u64,
}

/// O estado LowBox validado que o token novo recebe.
struct Configuration {
    package: Sid,
    capabilities: Vec<Group>,
    handles: Vec<u64>,
}

/// NtCreateLowBoxToken com PreviousMode `mode`.
pub fn create(request: &Request, mode: u8) -> Result<u32, KernelError> {
    let user = mode != 0;
    if user {
        if !user_probe::probe_user_write(request.token_handle, 8) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        let handles_size = request.handle_count as u64 * 8;
        if handles_size != 0 {
            if request.handles & 7 != 0 {
                return Ok(STATUS_DATATYPE_MISALIGNMENT);
            }
            // O ProbeForRead (0x6ef338) confere só alinhamento e faixa: um
            // Handles nulo com contagem chega à checagem de mistura abaixo.
            if request.handles != 0 && !user_probe::probe_user_read(request.handles, handles_size) {
                return Ok(STATUS_ACCESS_VIOLATION);
            }
        }
    }
    if request.package_sid == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if (request.handle_count == 0) != (request.handles == 0) {
        return Ok(STATUS_INVALID_PARAMETER_MIX);
    }
    let mut reference = match token_reference::reference(request.existing_token, TOKEN_DUPLICATE, mode, false)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let result = create_referenced(request, mode, reference.token, reference.granted_access);
    reference.release()?;
    result
}

/// O resto do NtCreateLowBoxToken com o token existente referenciado.
fn create_referenced(request: &Request, mode: u8, existing: u64, existing_access: u32) -> Result<u32, KernelError> {
    let package = match capture::sid(request.package_sid, mode) {
        Ok(package) => package,
        Err(status) => return Ok(status),
    };
    if let Err(status) = check_create_lowbox(&package) {
        return Ok(status);
    }
    let Some((kind, level)) = tokens::with(existing, |token| (token.kind, token.impersonation_level)) else { return Ok(STATUS_INVALID_HANDLE) };
    if kind != TOKEN_PRIMARY && level < SECURITY_IMPERSONATION {
        return Ok(STATUS_BAD_IMPERSONATION_LEVEL);
    }
    let requested_access = if request.desired_access != 0 { request.desired_access } else { existing_access };
    // O NT só captura as capacidades com o vetor presente (uma contagem sem
    // vetor seria lida de um ponteiro nulo).
    let capabilities = if request.capabilities != 0 {
        match capture::sid_and_attributes_array(request.capabilities, request.capability_count, mode) {
            Ok(capabilities) => capabilities,
            Err(status) => return Ok(status),
        }
    } else if request.capability_count != 0 {
        return Ok(STATUS_ACCESS_VIOLATION);
    } else {
        Vec::new()
    };
    let handles = match capture_handles(request.handle_count, request.handles) {
        Ok(handles) => handles,
        Err(status) => return Ok(status),
    };
    if !is_package_sid(&package) {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let sub_authorities = package[1];
    if sub_authorities != PARENT_PACKAGE_SUB_AUTHORITIES && sub_authorities != CHILD_PACKAGE_SUB_AUTHORITIES {
        return Ok(STATUS_INVALID_PACKAGE_SID_LENGTH);
    }
    for (index, capability) in capabilities.iter().enumerate() {
        if !is_capability_sid(&capability.sid) || capabilities[..index].iter().any(|earlier| earlier.sid == capability.sid) {
            return Ok(STATUS_INVALID_PARAMETER);
        }
    }
    if sub_authorities == CHILD_PACKAGE_SUB_AUTHORITIES && !check_capabilities(existing, &capabilities) {
        return Ok(STATUS_ACCESS_DENIED);
    }
    let Some(subject) = thread_tokens::effective(process::get_current_thread(), false) else { return Ok(STATUS_ACCESS_DENIED) };
    let (creation, _) = match duplicate::capture_creation_policy(request.object_attributes, mode, subject) {
        Ok(creation) => creation,
        Err(status) => return Ok(status),
    };
    let granted = match duplicate::creation_access(requested_access, subject, mode) {
        Ok(granted) => granted,
        Err(status) => return Ok(status),
    };
    // SepDuplicateToken: a cópia primária, sem EffectiveOnly.
    let created = tokens::duplicate(existing, 0, false, TOKEN_PRIMARY)?;
    let configuration = Configuration { package, capabilities, handles };
    let result = (|| -> Result<u32, KernelError> {
        if let Err(status) = make_lowbox(created, &configuration) {
            return Ok(status);
        }
        // O descritor do objeto: o capturado ou o padrão de quem cria, com
        // TOKEN_ALL_ACCESS para o pacote e o SepFinalizeTokenAcls.
        let mut policy = creation.policy.clone();
        duplicate::append_object_ace(&mut policy, &configuration.package, TOKEN_ALL_ACCESS);
        duplicate::finalize_token_acls(&mut policy);
        let current = process::get_current_process();
        tokens::update(created, |token| {
            token.security = policy;
            if creation.flags & OBJ_EXCLUSIVE != 0 {
                token.exclusive_process = current;
            }
        });
        let handle = match token_handles::create(created, granted, creation.flags, mode != 0) {
            Ok(handle) => handle,
            Err(error) if error.status != 0 => return Ok(error.status),
            Err(error) => return Err(error),
        };
        if creation.flags & OBJ_PERMANENT != 0 {
            tokens::retain(created)?;
            tokens::update(created, |token| token.permanent = true);
        }
        if (mode != 0 && !user_probe::probe_user_write(request.token_handle, 8)) || guest::try_write::<u64>(request.token_handle, handle).is_err() {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        Ok(0)
    })();
    tokens::release(created)?;
    result
}

/// O corpo do NtCreateLowBoxToken sobre a cópia: política obrigatória,
/// rótulo Low, privilégios, TokenFlags, capacidades, número LowBox, handles
/// guardados, pacote, DACL padrão e ModifiedId.
fn make_lowbox(created: u64, configuration: &Configuration) -> Result<(), u32> {
    let package = &configuration.package;
    let Some((session, logon_id, server_silo, current_package, has_capabilities, integrity, previous_number, previous_handles)) =
        tokens::with(created, |token| (token.session_id, token.authentication_id, token.server_silo, token.app_container.clone(), !token.capabilities.is_empty(), token.integrity.clone(), token.lowbox_number, token.lowbox_handles.clone()))
    else {
        return Err(STATUS_INVALID_HANDLE);
    };
    if integrity.is_empty() {
        return Err(STATUS_INVALID_LABEL);
    }
    // SepSetTokenCapabilities e SepSetTokenPackage: um token que já é de um
    // pacote só passa a um filho dele.
    let child_of_current = current_package.as_ref().is_none_or(|current| rtl_security::is_parent_of_child_app_container(current, package));
    if (has_capabilities || current_package.is_some()) && !child_of_current {
        return Err(STATUS_ACCESS_DENIED);
    }
    let number = reference_number(session, package)?;
    let key = HandlesKey { logon_id, server_silo, package: package.clone() };
    if let Err(status) = set_cached_handles(&key, session, &configuration.handles) {
        release_number(session, number);
        return Err(status);
    }
    let modified = tokens::allocate_luid();
    tokens::update(created, |token| {
        token.mandatory_policy = TOKEN_MANDATORY_POLICY_NO_WRITE_UP;
        let count = token.integrity[1] as usize;
        if count != 0 && token.integrity.len() >= 8 + 4 * count {
            let at = 8 + 4 * (count - 1);
            token.integrity[at..at + 4].copy_from_slice(&SECURITY_MANDATORY_LOW_RID.to_le_bytes());
        }
        token.privileges.retain(|privilege| privilege.id < 64 && LOWBOX_PRIVILEGES >> privilege.id & 1 != 0);
        token.capabilities = configuration.capabilities.clone();
        token.lowbox_number = Some((session, number));
        token.lowbox_handles = Some(key.clone());
        token.app_container = Some(package.clone());
        if let Some(dacl) = token.default_dacl.as_mut() {
            if !dacl.iter().any(|ace| ace.sid.as_ref() == Some(package)) {
                dacl.push(Ace::allow(package.clone(), GENERIC_ALL));
            }
        }
        token.modified_id = modified;
    });
    tokens::body(created).token_flags.atomic().fetch_and(!TOKEN_NOT_LOW, core::sync::atomic::Ordering::SeqCst);
    // A cópia do token existente referenciava as entradas dele (o NT só
    // sobrescreve os ponteiros); aqui a referência herdada é largada.
    if let Some((previous_session, previous)) = previous_number {
        release_number(previous_session, previous);
    }
    if let Some(previous) = previous_handles {
        release_handles(&previous);
    }
    Ok(())
}

/// O SeSubProcessToken de um token LowBox levado a outra sessão: o número
/// LowBox passa à tabela da sessão nova.
pub fn move_to_session(token: u64, session: u32) -> Result<(), u32> {
    let Some((Some(package), Some((previous_session, previous)))) = tokens::with(token, |record| (record.app_container.clone(), record.lowbox_number)) else { return Ok(()) };
    if previous_session == session {
        return Ok(());
    }
    release_number(previous_session, previous);
    tokens::update(token, |record| record.lowbox_number = None);
    let number = reference_number(session, &package)?;
    tokens::update(token, |record| record.lowbox_number = Some((session, number)));
    Ok(())
}

/// O teardown do estado LowBox (o TokenIntegrityLevel de Medium para cima e
/// o SepTokenDeleteMethod): as referências do número e da entrada de handles.
pub fn release_state(number: Option<(u32, u32)>, handles: Option<HandlesKey>) {
    if let Some((session, number)) = number {
        release_number(session, number);
    }
    if let Some(key) = handles {
        release_handles(&key);
    }
}

/// SepCanTokenMatchAllPackageSid sobre os atributos de segurança de um
/// token: o atributo WIN://NOALLAPPPKG com o primeiro valor não nulo tira o
/// token de ALL APPLICATION PACKAGES (o AppContainer de privilégio menor).
pub fn can_match_all_packages(attributes: &[crate::ntos::se::security_attributes::SecurityAttribute]) -> bool {
    use crate::ntos::se::security_attributes::AttributeValue;
    let Some(attribute) = attributes.iter().find(|attribute| equal_insensitive(&attribute.name, "WIN://NOALLAPPPKG")) else { return true };
    match attribute.values.first() {
        Some(AttributeValue::Integer(value)) => *value == 0,
        Some(_) => false,
        None => true,
    }
}

/// ALL APPLICATION PACKAGES (S-1-15-2-1) e ALL RESTRICTED APPLICATION
/// PACKAGES (S-1-15-2-2).
pub fn all_application_packages() -> Sid {
    sid(15, &[2, 1])
}

pub fn all_restricted_application_packages() -> Sid {
    sid(15, &[2, 2])
}
