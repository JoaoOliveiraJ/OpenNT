//! Inspeção de objetos do NT pelos tipos do PDB do ntoskrnl, como o kernel
//! os põe na memória: processos, threads e as esperas delas, a tabela de
//! handles, o OBJECT_HEADER (tipo, contagens, cabeçalhos opcionais e o
//! descritor de segurança), o WNF e as hives. O que vive só nas coleções do
//! kernel (o registro do token, as portas de conclusão, os pacotes de espera
//! e as portas ALPC) vem das consultas do stub (`kd/objects.rs`).
//!
//! ```text
//! !procs                        processos: EPROCESS, PID, pai, sessao, handles, threads, token, PEB, CR3
//! !threads [pid|eprocess]       threads: estado, motivo da espera, prioridade, objeto esperado, inicio, Win32Thread
//! !waits <ethread>              os blocos de espera de uma thread e os objetos esperados
//! !handles <pid|eprocess> [txt] a tabela de handles (todas as paginas), filtrada por tipo ou nome
//! !obj <end|\caminho>           OBJECT_HEADER, tipo, contagens, nome, criador e descritor de seguranca
//! !obtypes                      a ObTypeIndexTable e o ObHeaderCookie
//! !token <pid|end>              o token: usuario, sessao, integridade, grupos, privilegios
//! !iocp <pid|end>               portas de conclusao (pacotes, consumidores, threads)
//! !waitpkt <pid|end>            pacotes de espera (WaitCompletionPacket)
//! !alpc <pid|end|\caminho>      portas ALPC (papel, conexao, filas, a mensagem do topo)
//! !wnf [pid|eprocess | nome <valor>]   nomes de estado WNF e assinantes
//! !hives                        as hives carregadas (a chave hivelist)
//! ```
//!
//! Os offsets saem todos do PDB (`Layouts`); uma struct é lida de uma vez
//! só na faixa dos campos pedidos (`Record`). As tabelas têm uma linha de
//! cabeçalho em maiúsculas e colunas fixas separadas por espaço; o valor
//! ausente é `-`, então a coluna N de um `save-word` é sempre a mesma. Os
//! nomes de tipo com espaço (`ALPC Port`) saem com `_` na coluna.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::client::Client;
use super::monitor::Process;
use super::parse_number;
use super::types::{self, Kind, TypeDb};
use super::unwind::ReadMemory;
use super::user::Handle;

/// O valor ausente numa coluna.
const NONE: &str = "-";

/// Elementos no máximo de cada lista andada pela memória (LIST_ENTRY e
/// árvore AVL): um ponteiro estragado só encerra a lista.
const WALK_LIMIT: usize = 4096;

/// Objetos consultados no máximo quando o argumento é um processo.
const OBJECTS_PER_PROCESS: usize = 32;

/// O XOR que o WNF aplica ao nome de estado (o valor visto pelo modo usuário
/// é o nome interno XOR esta constante).
pub const WNF_NAME_MASK: u64 = 0x41C6_4E6D_A3BC_0074;

/// Códigos de nó do WNF (WNF_NODE_HEADER.NodeTypeCode).
const WNF_SCOPE_MAP: u16 = 0x901;
const WNF_SCOPE_INSTANCE: u16 = 0x902;
const WNF_PROCESS_CONTEXT: u16 = 0x906;

/// Os cabeçalhos opcionais do OBJECT_HEADER na ordem dos bits do InfoMask,
/// com o tamanho do 19041 quando o PDB não tiver o tipo.
const INFO_HEADERS: [(u8, &str, u64); 8] = [
    (0x01, "_OBJECT_HEADER_CREATOR_INFO", 0x20),
    (0x02, "_OBJECT_HEADER_NAME_INFO", 0x20),
    (0x04, "_OBJECT_HEADER_HANDLE_INFO", 0x10),
    (0x08, "_OBJECT_HEADER_QUOTA_INFO", 0x20),
    (0x10, "_OBJECT_HEADER_PROCESS_INFO", 0x10),
    (0x20, "_OBJECT_HEADER_AUDIT_INFO", 0x10),
    (0x40, "_OBJECT_HEADER_EXTENDED_INFO", 0x10),
    (0x80, "_OBJECT_HEADER_PADDING_INFO", 0x4),
];

const THREAD_STATES: [&str; 10] = ["Initialized", "Ready", "Running", "Standby", "Terminated", "Waiting", "Transition", "DeferredReady", "GateWaitObsolete", "WaitingForProcessInSwap"];
const WAIT_TYPES: [&str; 5] = ["WaitAll", "WaitAny", "WaitNotification", "WaitDequeue", "WaitDpc"];
const BLOCK_STATES: [&str; 8] = ["WaitBlockBypassStart", "WaitBlockBypassComplete", "WaitBlockSuspendBypassStart", "WaitBlockSuspendBypassComplete", "WaitBlockActive", "WaitBlockInactive", "WaitBlockSuspended", "WaitBlockAllStates"];
const THREAD_WAITING: u64 = 5;
const BLOCK_ACTIVE: u64 = 4;

// ---------------------------------------------------------------------------
// Layouts pelo PDB.

/// Um campo resolvido: o deslocamento desde o início da struct e o tipo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Place {
    pub offset: u64,
    pub ty: u32,
}

/// Resolve `Campo.Sub[2].Outro` dentro de `structure` (os membros das
/// uniões anônimas do C já vêm achatados na lista do pai).
pub fn locate(db: &TypeDb, structure: &str, path: &str) -> Result<Place, String> {
    let mut ty = db.find(structure).ok_or_else(|| format!("tipo {structure} nao esta no PDB do ntoskrnl"))?;
    let mut offset = 0;
    for part in path.split('.') {
        let (name, index) = match part.split_once('[') {
            Some((name, rest)) => (name, Some(rest.trim_end_matches(']').trim().parse::<u64>().map_err(|_| format!("{structure}.{path}: indice invalido"))?)),
            None => (part, None),
        };
        let member = db.member(ty, name).ok_or_else(|| format!("{}: sem o campo {name}", db.name(ty)))?;
        offset += member.offset;
        ty = member.ty;
        if let Some(index) = index {
            match db.kind(ty) {
                Kind::Array { element, .. } => {
                    offset += index * db.size(element).max(1);
                    ty = element;
                }
                _ => return Err(format!("{structure}.{path}: {name} nao e array")),
            }
        }
    }
    Ok(Place { offset, ty })
}

/// O tamanho de um campo em bytes (o da base num bitfield).
pub fn field_size(db: &TypeDb, ty: u32) -> u64 {
    match db.kind(ty) {
        Kind::Bitfield { base, .. } => db.size(base).max(1),
        Kind::Pointer { .. } => 8,
        _ => db.size(ty).max(1),
    }
}

/// Os campos já resolvidos de uma sessão de comando.
pub struct Layouts {
    db: Arc<TypeDb>,
    cache: HashMap<(String, String), Option<Place>>,
}

impl Layouts {
    pub fn new(db: Arc<TypeDb>) -> Self {
        Self { db, cache: HashMap::new() }
    }

    pub fn db(&self) -> &TypeDb {
        &self.db
    }

    pub fn place(&mut self, structure: &str, path: &str) -> Option<Place> {
        let key = (structure.to_string(), path.to_string());
        if let Some(found) = self.cache.get(&key) {
            return *found;
        }
        let found = locate(&self.db, structure, path).ok();
        self.cache.insert(key, found);
        found
    }

    pub fn offset(&mut self, structure: &str, path: &str) -> Result<u64, String> {
        self.place(structure, path).map(|place| place.offset).ok_or_else(|| format!("{structure}.{path} nao esta no PDB do ntoskrnl"))
    }

    /// O tamanho de uma struct (`None` se o PDB não a tiver).
    pub fn size(&self, structure: &str) -> Option<u64> {
        self.db.find(structure).map(|index| self.db.size(index)).filter(|&size| size != 0)
    }

    /// O nome do enumerador do PDB, ou o da tabela, ou o número.
    pub fn enum_text(&self, enumeration: &str, value: u64, fallback: &[&str]) -> String {
        if let Some(name) = self.db.find(enumeration).and_then(|index| self.db.enumerator(index, value as i128)) {
            return name;
        }
        fallback.get(value as usize).map_or_else(|| value.to_string(), |name| name.to_string())
    }
}

/// Uma leitura de memória limitada a um buffer (a faixa de um `Record`).
struct Slice<'a> {
    base: u64,
    bytes: &'a [u8],
}

impl ReadMemory for Slice<'_> {
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
        let start = address.checked_sub(self.base).filter(|&start| (start as usize) < self.bytes.len()).ok_or_else(|| format!("{address:#x} fora da leitura"))? as usize;
        let end = (start + length).min(self.bytes.len());
        Ok(self.bytes[start..end].to_vec())
    }
}

/// Os bytes de uma struct lidos de uma vez (só a faixa dos campos pedidos).
pub struct Record {
    structure: String,
    address: u64,
    /// O deslocamento do primeiro byte lido.
    start: u64,
    bytes: Vec<u8>,
}

impl Record {
    pub fn new(structure: &str, address: u64, start: u64, bytes: Vec<u8>) -> Self {
        Self { structure: structure.to_string(), address, start, bytes }
    }

    pub fn address(&self) -> u64 {
        self.address
    }

    /// O valor escalar do campo (com sinal estendido nos tipos com sinal).
    pub fn get(&self, layouts: &mut Layouts, path: &str) -> Option<u64> {
        let place = layouts.place(&self.structure, path)?;
        let db = Arc::clone(&layouts.db);
        let mut slice = Slice { base: self.address + self.start, bytes: &self.bytes };
        db.read_scalar(&mut slice, place.ty, self.address + place.offset).ok()
    }

    /// Os bytes crus do campo (arrays e structs pequenas).
    pub fn bytes(&self, layouts: &mut Layouts, path: &str, length: usize) -> Option<Vec<u8>> {
        let place = layouts.place(&self.structure, path)?;
        let start = place.offset.checked_sub(self.start)? as usize;
        let end = (start + length).min(self.bytes.len());
        (start < end).then(|| self.bytes[start..end].to_vec())
    }

    /// Os primeiros 8 bytes do campo como inteiro, qualquer que seja o tipo.
    pub fn raw_u64(&self, layouts: &mut Layouts, path: &str) -> Option<u64> {
        let bytes = self.bytes(layouts, path, 8)?;
        let mut raw = [0u8; 8];
        raw[..bytes.len()].copy_from_slice(&bytes);
        (bytes.len() == 8).then(|| u64::from_le_bytes(raw))
    }
}

// ---------------------------------------------------------------------------
// Formatação.

fn hex_or_none(value: Option<u64>) -> String {
    match value {
        Some(value) if value != 0 => format!("{value:#x}"),
        _ => NONE.to_string(),
    }
}

fn number_or_none(value: Option<u64>) -> String {
    value.map_or_else(|| NONE.to_string(), |value| value.to_string())
}

fn signed_or_none(value: Option<u64>) -> String {
    value.map_or_else(|| NONE.to_string(), |value| (value as i64).to_string())
}

/// Um nome de tipo numa coluna: os espaços viram `_`.
pub fn type_column(name: &str) -> String {
    if name.is_empty() {
        NONE.to_string()
    } else {
        name.replace(' ', "_")
    }
}

/// O texto depois das `count` primeiras palavras da linha.
fn rest_after(line: &str, count: usize) -> String {
    let mut rest = line.trim_start();
    for _ in 0..count {
        rest = rest.split_once(char::is_whitespace).map_or("", |(_, tail)| tail.trim_start());
    }
    rest.trim().to_string()
}

/// O ImageFileName (até 15 bytes, até o NUL) em ASCII.
fn image_name(bytes: &[u8]) -> String {
    bytes.iter().take_while(|&&byte| byte != 0).map(|&byte| if (0x20..0x7F).contains(&byte) { byte as char } else { '?' }).collect()
}

/// O tipo de handle `ALPC Port` sai do `handles` do stub em duas palavras
/// (`ALPC` e o resto no nome): junta de volta.
pub fn normalize_handle(mut handle: Handle) -> Handle {
    if handle.kind == "ALPC" {
        if let Some(rest) = handle.name.strip_prefix("Port") {
            handle.kind = "ALPC Port".to_string();
            handle.name = rest.trim().to_string();
        }
    }
    handle
}

/// O stub não deu o nome do tipo do handle.
pub fn unnamed_type(kind: &str) -> bool {
    kind.is_empty() || kind == "?"
}

/// O corpo que o `obj <caminho>` do stub devolve (`tipo X corpo 0x...`).
pub fn parse_object_body(text: &str) -> Option<(String, u64)> {
    let line = text.lines().find(|line| line.contains(" corpo "))?;
    let kind = line.split_once(": tipo ").and_then(|(_, rest)| rest.split_once(" corpo ")).map(|(kind, _)| kind.trim().to_string()).unwrap_or_default();
    let body = line.split_once(" corpo ").and_then(|(_, rest)| rest.split_whitespace().next()).and_then(parse_number)?;
    (body != 0).then_some((kind, body))
}

// ---------------------------------------------------------------------------
// Tipos de objeto.

/// A ObTypeIndexTable do `obtypes` do stub.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObjectTypes {
    pub cookie: u8,
    /// (índice, OBJECT_TYPE, nome).
    pub types: Vec<(u8, u64, String)>,
}

impl ObjectTypes {
    /// O tipo do cabeçalho em `header` com o TypeIndex embaralhado.
    pub fn decode(&self, header: u64, encoded: u8) -> Option<&(u8, u64, String)> {
        let index = encoded ^ self.cookie ^ (header >> 8) as u8;
        self.types.iter().find(|entry| entry.0 == index)
    }
}

pub fn parse_object_types(text: &str) -> Option<ObjectTypes> {
    let mut table = ObjectTypes::default();
    let mut cookie = None;
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.first() == Some(&"ObHeaderCookie") {
            cookie = fields.get(1).and_then(|text| parse_number(text));
            continue;
        }
        if fields.len() >= 5 && fields[1].starts_with("0x") {
            if let (Ok(index), Some(address)) = (fields[0].parse::<u8>(), parse_number(fields[1])) {
                table.types.push((index, address, rest_after(line, 4)));
            }
        }
    }
    table.cookie = cookie? as u8;
    Some(table)
}

/// O deslocamento (para trás, a partir do OBJECT_HEADER) do cabeçalho
/// opcional do bit `bit`: a soma dos presentes com bit menor ou igual (o
/// ObpInfoMaskToOffset).
pub fn info_offset(mask: u8, bit: u8, sizes: &[u64; 8]) -> Option<u64> {
    if mask & bit == 0 {
        return None;
    }
    Some(INFO_HEADERS.iter().zip(sizes).filter(|((flag, _, _), _)| *flag <= bit && mask & flag != 0).map(|(_, size)| *size).sum())
}

/// OBJECT_HEADER.Flags em nomes.
pub fn header_flags(flags: u8) -> String {
    const NAMES: [&str; 8] = ["NewObject", "KernelObject", "KernelOnlyAccess", "ExclusiveObject", "PermanentObject", "DefaultSecurityQuota", "SingleHandleEntry", "DeletedInline"];
    let names: Vec<&str> = NAMES.iter().enumerate().filter(|(bit, _)| flags & (1 << bit) != 0).map(|(_, name)| *name).collect();
    if names.is_empty() {
        NONE.to_string()
    } else {
        names.join("|")
    }
}

/// O que o `!obj` mostra de um OBJECT_HEADER.
#[derive(Clone, Debug, Default)]
pub struct HeaderInfo {
    pub header: u64,
    pub body: u64,
    pub pointer_count: Option<u64>,
    pub handle_count: Option<u64>,
    pub type_index: Option<u8>,
    pub type_address: u64,
    pub type_name: String,
    pub info_mask: u8,
    pub flags: u8,
    pub create_info: u64,
    pub security: u64,
    pub name: Option<String>,
    pub directory: u64,
    pub creator_process: Option<u64>,
    pub exclusive_process: Option<u64>,
    pub quota: Option<(u64, u64)>,
}

// ---------------------------------------------------------------------------
// Descritores de segurança.

/// Um SID em `bytes`: o texto S-R-A-... e o tamanho.
pub fn sid_text(bytes: &[u8]) -> Option<(String, usize)> {
    if bytes.len() < 8 || bytes[0] != 1 {
        return None;
    }
    let count = bytes[1] as usize;
    let length = 8 + 4 * count;
    if count > 15 || bytes.len() < length {
        return None;
    }
    let authority = bytes[2..8].iter().fold(0u64, |value, &byte| (value << 8) | byte as u64);
    let mut text = format!("S-1-{authority}");
    for index in 0..count {
        let at = 8 + index * 4;
        text.push_str(&format!("-{}", u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])));
    }
    Some((text, length))
}

/// O nome dos SIDs mais comuns (`-` para os outros).
pub fn well_known_sid(text: &str) -> &'static str {
    match text {
        "S-1-0-0" => "Nobody",
        "S-1-1-0" => "Everyone",
        "S-1-2-0" => "Local",
        "S-1-3-0" => "CreatorOwner",
        "S-1-3-1" => "CreatorGroup",
        "S-1-3-4" => "OwnerRights",
        "S-1-5-2" => "Network",
        "S-1-5-4" => "Interactive",
        "S-1-5-6" => "Service",
        "S-1-5-7" => "Anonymous",
        "S-1-5-11" => "AuthenticatedUsers",
        "S-1-5-12" => "Restricted",
        "S-1-5-18" => "System",
        "S-1-5-19" => "LocalService",
        "S-1-5-20" => "NetworkService",
        "S-1-5-32-544" => "Administrators",
        "S-1-5-32-545" => "Users",
        "S-1-5-32-546" => "Guests",
        "S-1-15-2-1" => "AllAppPackages",
        "S-1-15-2-2" => "AllRestrictedAppPackages",
        "S-1-16-0" => "UntrustedMandatoryLevel",
        "S-1-16-4096" => "LowMandatoryLevel",
        "S-1-16-8192" => "MediumMandatoryLevel",
        "S-1-16-8448" => "MediumPlusMandatoryLevel",
        "S-1-16-12288" => "HighMandatoryLevel",
        "S-1-16-16384" => "SystemMandatoryLevel",
        _ if text.starts_with("S-1-5-90-0-") => "DWM",
        _ if text.starts_with("S-1-5-96-0-") => "UMFD",
        _ if text.starts_with("S-1-5-5-") => "LogonSession",
        _ => NONE,
    }
}

/// Uma ACE: o tipo, as flags, a máscara e o SID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AceEntry {
    pub kind: u8,
    pub flags: u8,
    pub mask: u32,
    pub sid: Option<String>,
}

pub fn ace_type_name(kind: u8) -> &'static str {
    match kind {
        0 => "ALLOW",
        1 => "DENY",
        2 => "AUDIT",
        3 => "ALARM",
        4 => "COMPOUND",
        5 => "ALLOW_OBJECT",
        6 => "DENY_OBJECT",
        7 => "AUDIT_OBJECT",
        8 => "ALARM_OBJECT",
        9 => "ALLOW_CALLBACK",
        10 => "DENY_CALLBACK",
        11 => "ALLOW_CALLBACK_OBJECT",
        12 => "DENY_CALLBACK_OBJECT",
        13 => "AUDIT_CALLBACK",
        14 => "ALARM_CALLBACK",
        15 => "AUDIT_CALLBACK_OBJECT",
        16 => "ALARM_CALLBACK_OBJECT",
        0x11 => "MANDATORY_LABEL",
        0x12 => "RESOURCE_ATTRIBUTE",
        0x13 => "SCOPED_POLICY_ID",
        0x14 => "PROCESS_TRUST_LABEL",
        0x15 => "ACCESS_FILTER",
        _ => "?",
    }
}

/// Uma ACL (cabeçalho de 8 bytes e as ACEs).
pub fn parse_acl(bytes: &[u8]) -> Option<Vec<AceEntry>> {
    if bytes.len() < 8 {
        return None;
    }
    let size = (u16::from_le_bytes([bytes[2], bytes[3]]) as usize).min(bytes.len());
    let count = u16::from_le_bytes([bytes[4], bytes[5]]) as usize;
    let mut aces = Vec::new();
    let mut at = 8;
    for _ in 0..count.min(256) {
        if at + 8 > size {
            break;
        }
        let kind = bytes[at];
        let flags = bytes[at + 1];
        let ace_size = u16::from_le_bytes([bytes[at + 2], bytes[at + 3]]) as usize;
        if ace_size < 8 || at + ace_size > size {
            break;
        }
        let mask = u32::from_le_bytes([bytes[at + 4], bytes[at + 5], bytes[at + 6], bytes[at + 7]]);
        let ace = &bytes[at..at + ace_size];
        // As ACEs de objeto têm Flags (4 bytes) e até dois GUIDs antes do SID.
        let sid_at = match kind {
            5..=8 | 11 | 12 | 15 | 16 if ace.len() >= 12 => {
                let object_flags = u32::from_le_bytes([ace[8], ace[9], ace[10], ace[11]]);
                12 + 16 * (object_flags & 1) as usize + 16 * ((object_flags >> 1) & 1) as usize
            }
            _ => 8,
        };
        let sid = ace.get(sid_at..).and_then(sid_text).map(|(text, _)| text);
        aces.push(AceEntry { kind, flags, mask, sid });
        at += ace_size;
    }
    Some(aces)
}

/// Um descritor de segurança lido: o Control, o dono, o grupo e as ACLs
/// (`None` = ausente; a DACL presente e nula vira `dacl_null`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecurityDescriptor {
    pub control: u16,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub dacl: Option<Vec<AceEntry>>,
    pub dacl_null: bool,
    pub sacl: Option<Vec<AceEntry>>,
}

const SE_DACL_PRESENT: u16 = 0x0004;
const SE_SACL_PRESENT: u16 = 0x0010;
const SE_SELF_RELATIVE: u16 = 0x8000;

/// Um SECURITY_DESCRIPTOR_RELATIVE inteiro em `bytes`.
pub fn parse_self_relative(bytes: &[u8]) -> Option<SecurityDescriptor> {
    if bytes.len() < 20 || bytes[0] != 1 {
        return None;
    }
    let control = u16::from_le_bytes([bytes[2], bytes[3]]);
    let offset = |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]) as usize;
    let sid_at = |at: usize| if at == 0 { None } else { bytes.get(at..).and_then(sid_text).map(|(text, _)| text) };
    let acl_at = |at: usize| if at == 0 { None } else { bytes.get(at..).and_then(parse_acl) };
    let (owner, group, sacl, dacl) = (offset(4), offset(8), offset(12), offset(16));
    Some(SecurityDescriptor {
        control,
        owner: sid_at(owner),
        group: sid_at(group),
        dacl: if control & SE_DACL_PRESENT != 0 { acl_at(dacl) } else { None },
        dacl_null: control & SE_DACL_PRESENT != 0 && dacl == 0,
        sacl: if control & SE_SACL_PRESENT != 0 { acl_at(sacl) } else { None },
    })
}

/// As linhas de um descritor (DONO, GRUPO, DACL, ACE...).
pub fn format_security_descriptor(address: u64, descriptor: &SecurityDescriptor) -> String {
    let mut output = format!("DESCRITOR {address:#x} controle {:#06x}\n", descriptor.control);
    for (label, sid) in [("DONO", &descriptor.owner), ("GRUPO", &descriptor.group)] {
        match sid {
            Some(sid) => output.push_str(&format!("{label} {sid} {}\n", well_known_sid(sid))),
            None => output.push_str(&format!("{label} -\n")),
        }
    }
    let acl = |output: &mut String, label: &str, aces: &[AceEntry]| {
        output.push_str(&format!("{label} {} entradas\n", aces.len()));
        for (index, ace) in aces.iter().enumerate() {
            let sid = ace.sid.as_deref().unwrap_or(NONE);
            output.push_str(&format!("ACE {label} {index} {} flags {:#04x} mascara {:#010x} {sid} {}\n", ace_type_name(ace.kind), ace.flags, ace.mask, well_known_sid(sid)));
        }
    };
    match (&descriptor.dacl, descriptor.dacl_null) {
        (_, true) => output.push_str("DACL nula (acesso total)\n"),
        (Some(aces), _) => acl(&mut output, "DACL", aces.as_slice()),
        (None, _) => output.push_str("DACL ausente\n"),
    }
    if let Some(aces) = &descriptor.sacl {
        acl(&mut output, "SACL", aces.as_slice());
    }
    output
}

// ---------------------------------------------------------------------------
// WNF.

/// Os campos do nome de estado interno (WNF_STATE_NAME_STRUCT).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateName {
    pub version: u8,
    pub lifetime: u8,
    pub scope: u8,
    pub permanent: bool,
    pub sequence: u64,
}

/// Version:4, NameLifetime:2, DataScope:4, PermanentData:1, Sequence:53.
pub fn decode_state_name(internal: u64) -> StateName {
    StateName { version: (internal & 0xF) as u8, lifetime: ((internal >> 4) & 3) as u8, scope: ((internal >> 6) & 0xF) as u8, permanent: (internal >> 10) & 1 != 0, sequence: internal >> 11 }
}

pub fn lifetime_name(lifetime: u8) -> &'static str {
    ["WellKnown", "Permanent", "Persistent", "Temporary"].get(lifetime as usize).copied().unwrap_or("?")
}

pub fn scope_name(scope: u8) -> &'static str {
    ["System", "Session", "User", "Process", "Machine", "PhysicalMachine"].get(scope as usize).copied().unwrap_or("?")
}

/// Uma linha de nome WNF.
#[derive(Clone, Debug, Default)]
struct WnfName {
    instance: u64,
    internal: u64,
    stamp: Option<u64>,
    size: Option<u64>,
    subscribers: usize,
    creator: u64,
    scope_instance: u64,
}

// ---------------------------------------------------------------------------
// Os comandos.

impl Client {
    fn layouts(&mut self) -> Result<Layouts, String> {
        let db = self.type_database().ok_or_else(|| self.types_note.clone())?;
        Ok(Layouts::new(db))
    }

    /// Lê de `address` a faixa que cobre os campos pedidos da struct; um
    /// endereço ilegível dá um registro vazio (todos os campos `None`).
    pub fn fetch(&mut self, layouts: &mut Layouts, structure: &str, address: u64, paths: &[&str]) -> Record {
        let mut low = u64::MAX;
        let mut high = 0u64;
        for path in paths {
            if let Some(place) = layouts.place(structure, path) {
                low = low.min(place.offset);
                high = high.max(place.offset + field_size(layouts.db(), place.ty));
            }
        }
        if low == u64::MAX || address == 0 {
            return Record::new(structure, address, 0, Vec::new());
        }
        let bytes = self.read_memory(address + low, (high - low) as usize).unwrap_or_default();
        Record::new(structure, address, low, bytes)
    }

    fn pointer_at(&mut self, address: u64) -> Option<u64> {
        if address == 0 {
            return None;
        }
        self.read_integer(address, 8).ok()
    }

    /// Os elementos de uma LIST_ENTRY circular (os endereços dos elos, sem a
    /// cabeça), até o limite.
    fn list_links(&mut self, head: u64, limit: usize) -> Vec<u64> {
        let mut links = Vec::new();
        let mut seen = HashSet::new();
        let mut link = self.pointer_at(head).unwrap_or(0);
        while link != head && link != 0 && links.len() < limit && seen.insert(link) {
            links.push(link);
            link = self.pointer_at(link).unwrap_or(0);
        }
        links
    }

    /// Um processo do argumento: PID (decimal ou `0x`), EPROCESS ou uma
    /// expressão (`$nome`).
    fn object_process(&mut self, text: &str) -> Result<Process, String> {
        let value = match parse_number(text) {
            Some(value) => value,
            None => self.evaluate(text)?,
        };
        let processes = self.processes()?;
        processes.into_iter().find(|process| if value < 0x1_0000_0000 { process.pid == value } else { process.eprocess == value }).ok_or_else(|| format!("{text}: processo nao encontrado (ps)"))
    }

    fn object_types(&mut self) -> Option<ObjectTypes> {
        self.monitor("obtypes").ok().and_then(|text| parse_object_types(&text))
    }

    /// O OBJECT_HEADER de um corpo, com os cabeçalhos opcionais.
    pub fn object_header(&mut self, layouts: &mut Layouts, object_types: Option<&ObjectTypes>, body: u64) -> Result<HeaderInfo, String> {
        let header = body.wrapping_sub(layouts.offset("_OBJECT_HEADER", "Body")?);
        let record = self.fetch(layouts, "_OBJECT_HEADER", header, &["PointerCount", "HandleCount", "TypeIndex", "InfoMask", "Flags", "ObjectCreateInfo", "SecurityDescriptor"]);
        let mut info = HeaderInfo { header, body, ..HeaderInfo::default() };
        info.pointer_count = record.get(layouts, "PointerCount");
        if info.pointer_count.is_none() {
            return Err(format!("OBJECT_HEADER {header:#x} ilegivel"));
        }
        info.handle_count = record.get(layouts, "HandleCount");
        info.type_index = record.get(layouts, "TypeIndex").map(|value| value as u8);
        info.info_mask = record.get(layouts, "InfoMask").unwrap_or(0) as u8;
        info.flags = record.get(layouts, "Flags").unwrap_or(0) as u8;
        info.create_info = record.get(layouts, "ObjectCreateInfo").unwrap_or(0);
        info.security = record.get(layouts, "SecurityDescriptor").unwrap_or(0);
        if let (Some(table), Some(encoded)) = (object_types, info.type_index) {
            if let Some((_, address, name)) = table.decode(header, encoded) {
                info.type_address = *address;
                info.type_name = name.clone();
            }
        }
        let sizes: [u64; 8] = std::array::from_fn(|index| layouts.size(INFO_HEADERS[index].1).unwrap_or(INFO_HEADERS[index].2));
        if let Some(offset) = info_offset(info.info_mask, 0x02, &sizes) {
            let name_info = header - offset;
            if let Ok(at) = layouts.offset("_OBJECT_HEADER_NAME_INFO", "Name") {
                info.name = types::read_unicode_string(self, name_info + at);
            }
            if let Ok(at) = layouts.offset("_OBJECT_HEADER_NAME_INFO", "Directory") {
                info.directory = self.pointer_at(name_info + at).unwrap_or(0);
            }
        }
        if let Some(offset) = info_offset(info.info_mask, 0x01, &sizes) {
            let record = self.fetch(layouts, "_OBJECT_HEADER_CREATOR_INFO", header - offset, &["CreatorUniqueProcess"]);
            info.creator_process = record.get(layouts, "CreatorUniqueProcess");
        }
        if let Some(offset) = info_offset(info.info_mask, 0x10, &sizes) {
            let record = self.fetch(layouts, "_OBJECT_HEADER_PROCESS_INFO", header - offset, &["ExclusiveProcess"]);
            info.exclusive_process = record.get(layouts, "ExclusiveProcess");
        }
        if let Some(offset) = info_offset(info.info_mask, 0x08, &sizes) {
            let record = self.fetch(layouts, "_OBJECT_HEADER_QUOTA_INFO", header - offset, &["PagedPoolCharge", "NonPagedPoolCharge"]);
            if let (Some(paged), Some(nonpaged)) = (record.get(layouts, "PagedPoolCharge"), record.get(layouts, "NonPagedPoolCharge")) {
                info.quota = Some((paged, nonpaged));
            }
        }
        Ok(info)
    }

    /// Um descritor de segurança na memória (relativo ou absoluto).
    pub fn read_security_descriptor(&mut self, address: u64) -> Result<SecurityDescriptor, String> {
        let head = self.read_memory(address, 0x28)?;
        if head.len() < 20 {
            return Err(format!("descritor em {address:#x} ilegivel"));
        }
        let control = u16::from_le_bytes([head[2], head[3]]);
        if control & SE_SELF_RELATIVE != 0 {
            let bytes = self.read_memory(address, 0x800)?;
            return parse_self_relative(&bytes).ok_or_else(|| format!("descritor em {address:#x} invalido"));
        }
        // Absoluto: Owner, Group, Sacl e Dacl são ponteiros.
        if head.len() < 0x28 {
            return Err(format!("descritor absoluto em {address:#x} ilegivel"));
        }
        let pointer = |at: usize| u64::from_le_bytes(head[at..at + 8].try_into().unwrap_or([0; 8]));
        let mut descriptor = SecurityDescriptor { control, ..SecurityDescriptor::default() };
        for (at, slot) in [(8usize, 0usize), (0x10, 1)] {
            let target = pointer(at);
            if target == 0 {
                continue;
            }
            let sid = self.read_memory(target, 68).ok().and_then(|bytes| sid_text(&bytes)).map(|(text, _)| text);
            if slot == 0 {
                descriptor.owner = sid;
            } else {
                descriptor.group = sid;
            }
        }
        let read_acl = |client: &mut Client, target: u64| -> Option<Vec<AceEntry>> {
            let header = client.read_memory(target, 8).ok()?;
            let size = u16::from_le_bytes([*header.get(2)?, *header.get(3)?]) as usize;
            parse_acl(&client.read_memory(target, size.clamp(8, 0x10000)).ok()?)
        };
        if control & SE_DACL_PRESENT != 0 {
            let dacl = pointer(0x20);
            descriptor.dacl_null = dacl == 0;
            if dacl != 0 {
                descriptor.dacl = read_acl(self, dacl);
            }
        }
        if control & SE_SACL_PRESENT != 0 && pointer(0x18) != 0 {
            descriptor.sacl = read_acl(self, pointer(0x18));
        }
        Ok(descriptor)
    }

    /// `!procs`.
    fn procs_command(&mut self) -> Result<String, String> {
        let mut layouts = self.layouts()?;
        let processes = self.processes()?;
        let session_id = layouts.offset("_MM_SESSION_SPACE", "SessionId").ok();
        let handle_count = layouts.offset("_HANDLE_TABLE", "FreeLists[0].HandleCount").ok();
        let mut output = format!("{:>18} {:>6} {:>6} {:>4} {:>7} {:>7} {:>18} {:>18} {:>18}  NOME\n", "EPROCESS", "PID", "PPID", "SESS", "HANDLES", "THREADS", "TOKEN", "PEB", "CR3");
        for process in processes {
            let record = self.fetch(&mut layouts, "_EPROCESS", process.eprocess, &["UniqueProcessId", "InheritedFromUniqueProcessId", "Session", "ObjectTable", "ActiveThreads", "Token.Value", "Peb", "Pcb.DirectoryTableBase", "ImageFileName"]);
            let session = match (record.get(&mut layouts, "Session"), session_id) {
                (Some(space), Some(at)) if space != 0 => self.read_integer(space + at, 4).ok(),
                _ => None,
            };
            let handles = match (record.get(&mut layouts, "ObjectTable"), handle_count) {
                (Some(table), Some(at)) if table != 0 => self.read_integer(table + at, 4).ok().map(|count| count as u32 as i32 as i64 as u64),
                _ => None,
            };
            let name = record.bytes(&mut layouts, "ImageFileName", 15).map(|bytes| image_name(&bytes)).filter(|name| !name.is_empty()).unwrap_or(process.name.clone());
            output.push_str(&format!(
                "{:#018x} {:>6} {:>6} {:>4} {:>7} {:>7} {:>18} {:>18} {:>18}  {}\n",
                process.eprocess,
                number_or_none(record.get(&mut layouts, "UniqueProcessId").or(Some(process.pid))),
                number_or_none(record.get(&mut layouts, "InheritedFromUniqueProcessId")),
                number_or_none(session),
                signed_or_none(handles),
                number_or_none(record.get(&mut layouts, "ActiveThreads")),
                hex_or_none(record.get(&mut layouts, "Token.Value").map(|value| value & !0xF)),
                hex_or_none(record.get(&mut layouts, "Peb")),
                hex_or_none(record.get(&mut layouts, "Pcb.DirectoryTableBase")),
                name
            ));
        }
        Ok(output)
    }

    /// `!threads [pid|eprocess]`.
    fn threads_command(&mut self, argument: &str) -> Result<String, String> {
        let mut layouts = self.layouts()?;
        let pid = if argument.is_empty() { None } else { Some(self.object_process(argument)?.pid) };
        let threads = self.threads(pid)?;
        let block_object = layouts.offset("_KWAIT_BLOCK", "Object").ok();
        let mut output = format!(
            "{:>18} {:>6} {:>6} {:<13} {:<18} {:<4} {:>3} {:>4} {:>3} {:>4} {:>18} {:>18} {:>18} {:>18}  PROCESSO\n",
            "ETHREAD", "PID", "TID", "ESTADO", "MOTIVO", "MODO", "PRI", "BASE", "DEC", "NOBJ", "OBJETO0", "INICIO", "INICIO_WIN32", "WIN32THREAD"
        );
        for thread in threads {
            let record = self.fetch(
                &mut layouts,
                "_ETHREAD",
                thread.ethread,
                &["Cid.UniqueThread", "Tcb.State", "Tcb.WaitReason", "Tcb.WaitMode", "Tcb.Priority", "Tcb.BasePriority", "Tcb.PriorityDecrement", "Tcb.WaitBlockCount", "Tcb.WaitBlockList", "Tcb.Win32Thread", "StartAddress", "Win32StartAddress"],
            );
            let state = record.get(&mut layouts, "Tcb.State");
            let waiting = state == Some(THREAD_WAITING);
            let count = record.get(&mut layouts, "Tcb.WaitBlockCount").unwrap_or(0);
            let first_object = match (waiting && count > 0, record.get(&mut layouts, "Tcb.WaitBlockList"), block_object) {
                (true, Some(list), Some(at)) if list != 0 => self.pointer_at(list + at),
                _ => None,
            };
            let state_text = state.map_or_else(|| NONE.to_string(), |state| layouts.enum_text("_KTHREAD_STATE", state, &THREAD_STATES));
            let reason = match (waiting, record.get(&mut layouts, "Tcb.WaitReason")) {
                (true, Some(reason)) => layouts.enum_text("_KWAIT_REASON", reason, &[]),
                _ => NONE.to_string(),
            };
            let mode = match (waiting, record.get(&mut layouts, "Tcb.WaitMode")) {
                (true, Some(0)) => "K",
                (true, Some(_)) => "U",
                _ => NONE,
            };
            output.push_str(&format!(
                "{:#018x} {:>6} {:>6} {:<13} {:<18} {:<4} {:>3} {:>4} {:>3} {:>4} {:>18} {:>18} {:>18} {:>18}  {}\n",
                thread.ethread,
                thread.pid,
                number_or_none(record.get(&mut layouts, "Cid.UniqueThread").or(Some(thread.tid))),
                state_text,
                reason,
                mode,
                signed_or_none(record.get(&mut layouts, "Tcb.Priority")),
                signed_or_none(record.get(&mut layouts, "Tcb.BasePriority")),
                signed_or_none(record.get(&mut layouts, "Tcb.PriorityDecrement")),
                if waiting { count.to_string() } else { NONE.to_string() },
                hex_or_none(first_object),
                hex_or_none(record.get(&mut layouts, "StartAddress")),
                hex_or_none(record.get(&mut layouts, "Win32StartAddress")),
                hex_or_none(record.get(&mut layouts, "Tcb.Win32Thread")),
                if thread.process.is_empty() { NONE } else { thread.process.as_str() }
            ));
        }
        Ok(output)
    }

    /// Uma linha sobre um objeto esperado: o tipo do despachante, o
    /// SignalState, o tipo do Ob e o nome.
    fn waited_object(&mut self, layouts: &mut Layouts, object_types: Option<&ObjectTypes>, object: u64) -> String {
        let record = self.fetch(layouts, "_DISPATCHER_HEADER", object, &["Type", "SignalState"]);
        let dispatcher = record.get(layouts, "Type").map_or_else(|| NONE.to_string(), |kind| layouts.enum_text("_KOBJECTS", kind, &[]));
        let signal = signed_or_none(record.get(layouts, "SignalState"));
        let (kind, name) = match self.object_header(layouts, object_types, object) {
            Ok(info) if !info.type_name.is_empty() => (type_column(&info.type_name), info.name.unwrap_or_default()),
            _ => (NONE.to_string(), String::new()),
        };
        format!("{object:#018x} {dispatcher:<28} {signal:>6} {kind:<20} {name}")
    }

    /// `!waits <ethread>`.
    fn waits_command(&mut self, argument: &str) -> Result<String, String> {
        if argument.is_empty() {
            return Err("uso: !waits <ethread>".into());
        }
        let thread = self.evaluate(argument)?;
        let mut layouts = self.layouts()?;
        let table = self.object_types();
        let record = self.fetch(
            &mut layouts,
            "_ETHREAD",
            thread,
            &["Cid.UniqueProcess", "Cid.UniqueThread", "Tcb.State", "Tcb.WaitReason", "Tcb.WaitMode", "Tcb.WaitIrql", "Tcb.WaitTime", "Tcb.WaitStatus", "Tcb.WaitBlockCount", "Tcb.WaitBlockList", "Tcb.Alertable", "Tcb.Queue", "Tcb.Priority"],
        );
        let state = record.get(&mut layouts, "Tcb.State").ok_or_else(|| format!("ETHREAD {thread:#x} ilegivel"))?;
        let mut output = format!(
            "ETHREAD {thread:#x} PID {} TID {} estado {} motivo {} modo {} alertavel {} IRQL {} WaitTime {} WaitStatus {} fila {}\n",
            number_or_none(record.get(&mut layouts, "Cid.UniqueProcess")),
            number_or_none(record.get(&mut layouts, "Cid.UniqueThread")),
            layouts.enum_text("_KTHREAD_STATE", state, &THREAD_STATES),
            record.get(&mut layouts, "Tcb.WaitReason").map_or_else(|| NONE.to_string(), |reason| layouts.enum_text("_KWAIT_REASON", reason, &[])),
            match record.get(&mut layouts, "Tcb.WaitMode") {
                Some(0) => "Kernel",
                Some(_) => "User",
                None => NONE,
            },
            number_or_none(record.get(&mut layouts, "Tcb.Alertable")),
            number_or_none(record.get(&mut layouts, "Tcb.WaitIrql")),
            number_or_none(record.get(&mut layouts, "Tcb.WaitTime")),
            hex_or_none(record.get(&mut layouts, "Tcb.WaitStatus")).replace(NONE, "0x0"),
            hex_or_none(record.get(&mut layouts, "Tcb.Queue")),
        );
        let count = record.get(&mut layouts, "Tcb.WaitBlockCount").unwrap_or(0);
        let list = record.get(&mut layouts, "Tcb.WaitBlockList").unwrap_or(0);
        let block_size = layouts.size("_KWAIT_BLOCK").unwrap_or(0x30);
        let timer_block = thread + layouts.offset("_ETHREAD", "Tcb.WaitBlock[3]").unwrap_or(0);
        output.push_str(&format!("blocos {count} lista {}\n", hex_or_none(Some(list))));
        output.push_str(&format!("{:<5} {:<16} {:<24} {:>6} {:>18} {:<28} {:>6} {:<20} NOME\n", "BLOCO", "TIPO", "ESTADO", "CHAVE", "OBJETO", "DESPACHO", "SINAL", "TIPO_OB"));
        let mut blocks: Vec<(String, u64)> = (0..count.min(64)).map(|index| (index.to_string(), list + index * block_size)).collect();
        // Uma espera só com prazo (KeDelayExecutionThread) aponta a lista
        // para o próprio bloco do timer, com zero objetos.
        if count == 0 || list != timer_block {
            blocks.push(("timer".to_string(), timer_block));
        }
        for (label, block) in blocks {
            let record = self.fetch(&mut layouts, "_KWAIT_BLOCK", block, &["WaitType", "BlockState", "WaitKey", "Object"]);
            let block_state = record.get(&mut layouts, "BlockState");
            // O bloco do timer só conta quando a espera tem prazo (ativo).
            if label == "timer" && block_state != Some(BLOCK_ACTIVE) {
                continue;
            }
            let object = record.get(&mut layouts, "Object").unwrap_or(0);
            let described = if object == 0 { NONE.to_string() } else { self.waited_object(&mut layouts, table.as_ref(), object) };
            output.push_str(&format!(
                "{:<5} {:<16} {:<24} {:>6} {}\n",
                label,
                record.get(&mut layouts, "WaitType").map_or_else(|| NONE.to_string(), |kind| layouts.enum_text("_WAIT_TYPE", kind, &WAIT_TYPES)),
                block_state.map_or_else(|| NONE.to_string(), |value| layouts.enum_text("_KWAIT_BLOCK_STATE", value, &BLOCK_STATES)),
                hex_or_none(record.get(&mut layouts, "WaitKey")).replace(NONE, "0x0"),
                described
            ));
        }
        if state == THREAD_WAITING && count == 0 && record.get(&mut layouts, "Tcb.WaitMode") == Some(1) {
            output.push_str("espera de modo usuario sem blocos: o despacho de usuario do OpenNT sonda o objeto (veja uthreads)\n");
        }
        Ok(output)
    }

    /// Os handles de um processo pelo `handles` do stub. O tipo que o stub
    /// não nomeia (`?`, um objeto criado sem o nome do tipo nas coleções
    /// dele) sai do TypeIndex do OBJECT_HEADER pela ObTypeIndexTable.
    fn process_handles(&mut self, eprocess: u64) -> Result<Vec<Handle>, String> {
        let mut handles: Vec<Handle> = self.handles(&format!("{eprocess:#x}"))?.into_iter().map(normalize_handle).collect();
        if !handles.iter().any(|handle| unnamed_type(&handle.kind)) {
            return Ok(handles);
        }
        let (Ok(mut layouts), Some(table)) = (self.layouts(), self.object_types()) else { return Ok(handles) };
        let (Ok(body), Ok(index)) = (layouts.offset("_OBJECT_HEADER", "Body"), layouts.offset("_OBJECT_HEADER", "TypeIndex")) else { return Ok(handles) };
        for handle in handles.iter_mut().filter(|handle| unnamed_type(&handle.kind) && handle.object != 0) {
            let header = handle.object.wrapping_sub(body);
            let Ok(bytes) = self.read_memory(header + index, 1) else { continue };
            if let Some((_, _, name)) = table.decode(header, bytes[0]) {
                handle.kind = name.clone();
            }
        }
        Ok(handles)
    }

    /// `!handles <pid|eprocess> [texto]`.
    fn handles_command(&mut self, words: &[&str]) -> Result<String, String> {
        let first = words.first().ok_or("uso: !handles <pid|eprocess> [texto do tipo ou do nome]")?;
        let process = self.object_process(first)?;
        let filter = words[1..].join(" ").to_ascii_lowercase();
        let handles = self.process_handles(process.eprocess)?;
        let shown: Vec<&Handle> = handles.iter().filter(|handle| filter.is_empty() || handle.kind.to_ascii_lowercase().contains(&filter) || handle.name.to_ascii_lowercase().contains(&filter)).collect();
        let mut output = format!("EPROCESS {:#x} PID {} {} handles {} mostrados {}\n", process.eprocess, process.pid, process.name, handles.len(), shown.len());
        output.push_str(&format!("{:>8} {:>18} {:>10} {:<24} NOME\n", "HANDLE", "OBJETO", "ACESSO", "TIPO"));
        for handle in shown {
            output.push_str(&format!("{:>#8x} {:#018x} {:#010x} {:<24} {}\n", handle.handle, handle.object, handle.access, type_column(&handle.kind), if handle.name.is_empty() { NONE } else { handle.name.as_str() }));
        }
        Ok(output)
    }

    /// O corpo de um argumento de objeto: `\caminho` pelo `obj` do stub ou
    /// uma expressão.
    fn object_body(&mut self, argument: &str) -> Result<u64, String> {
        if argument.starts_with('\\') {
            let text = self.monitor(&format!("obj {argument}"))?;
            return parse_object_body(&text).map(|(_, body)| body).ok_or_else(|| {
                if text.contains(" corpo 0x0") {
                    // Um diretório ou link só do namespace do kernel: sem
                    // OBJECT_HEADER na memória.
                    format!("{argument}: sem corpo nativo (o objeto so existe no namespace do kernel; veja obj {argument})")
                } else {
                    text.trim().to_string()
                }
            });
        }
        self.evaluate(argument)
    }

    /// `!obj <endereço|\caminho>`.
    fn obj_command(&mut self, argument: &str) -> Result<String, String> {
        if argument.is_empty() {
            return Err("uso: !obj <corpo do objeto|\\caminho>".into());
        }
        let body = self.object_body(argument)?;
        let mut layouts = self.layouts()?;
        let table = self.object_types();
        let info = self.object_header(&mut layouts, table.as_ref(), body)?;
        if table.is_some() && info.type_name.is_empty() {
            // Um objeto que o OpenNT cria sem o cabeçalho do Ob (um
            // DRIVER_OBJECT, um diretório do namespace): os bytes antes do
            // corpo não são um OBJECT_HEADER.
            return Err(format!("{body:#x}: sem OBJECT_HEADER (o TypeIndex {} do cabecalho em {:#x} nao decodifica pela ObTypeIndexTable)", info.type_index.map_or_else(|| NONE.to_string(), |index| format!("{index:#04x}")), info.header));
        }
        let mut output = format!(
            "OBJETO {:#x} cabecalho {:#x} tipo {} OBJECT_TYPE {} TypeIndex {}\n",
            info.body,
            info.header,
            type_column(&info.type_name),
            hex_or_none(Some(info.type_address)),
            info.type_index.map_or_else(|| NONE.to_string(), |index| format!("{index:#04x}"))
        );
        output.push_str(&format!("PointerCount {} HandleCount {}\n", signed_or_none(info.pointer_count), signed_or_none(info.handle_count)));
        output.push_str(&format!("Flags {:#04x} {} InfoMask {:#04x}\n", info.flags, header_flags(info.flags), info.info_mask));
        let label = if info.flags & 1 != 0 { "ObjectCreateInfo" } else { "QuotaBlockCharged" };
        output.push_str(&format!("{label} {}\n", hex_or_none(Some(info.create_info))));
        output.push_str(&format!("nome {} diretorio {}\n", info.name.as_deref().filter(|name| !name.is_empty()).unwrap_or(NONE), hex_or_none(Some(info.directory))));
        output.push_str(&format!("criador PID {}\n", number_or_none(info.creator_process)));
        output.push_str(&format!("processo-exclusivo {}\n", hex_or_none(info.exclusive_process)));
        if let Some((paged, nonpaged)) = info.quota {
            output.push_str(&format!("cota paginada {paged:#x} nao-paginada {nonpaged:#x}\n"));
        }
        let descriptor = info.security & !0xF;
        if descriptor == 0 {
            output.push_str("descritor ausente no cabecalho\n");
        } else {
            match self.read_security_descriptor(descriptor) {
                Ok(parsed) => output.push_str(&format_security_descriptor(descriptor, &parsed)),
                Err(error) => output.push_str(&format!("descritor {descriptor:#x}: {error}\n")),
            }
        }
        Ok(output)
    }

    /// Os objetos de um tipo nos handles de um processo, consultados no
    /// stub um a um; ou o objeto do endereço (ou do caminho).
    fn stub_object_query(&mut self, query: &str, type_name: &str, argument: &str) -> Result<String, String> {
        if argument.is_empty() {
            return Err(format!("uso: !{query} <pid|endereco>"));
        }
        let small = parse_number(argument).is_some_and(|value| value < 0x1_0000_0000);
        if !small || argument.starts_with('\\') {
            let body = self.object_body(argument)?;
            return self.monitor(&format!("{query} {body:#x}"));
        }
        let process = self.object_process(argument)?;
        let handles: Vec<Handle> = self.process_handles(process.eprocess)?.into_iter().filter(|handle| handle.kind == type_name).collect();
        let mut output = format!("EPROCESS {:#x} PID {} {}: {} handles {}\n", process.eprocess, process.pid, process.name, handles.len(), type_column(type_name));
        for handle in handles.iter().take(OBJECTS_PER_PROCESS) {
            output.push_str(&format!("HANDLE {:#x} objeto {:#x} acesso {:#x} nome {}\n", handle.handle, handle.object, handle.access, if handle.name.is_empty() { NONE } else { handle.name.as_str() }));
            output.push_str(&self.monitor(&format!("{query} {:#x}", handle.object))?);
        }
        if handles.len() > OBJECTS_PER_PROCESS {
            output.push_str(&format!("mais objetos: {}\n", handles.len() - OBJECTS_PER_PROCESS));
        }
        Ok(output)
    }

    /// `!token <pid|endereço>`.
    fn token_command(&mut self, argument: &str) -> Result<String, String> {
        if argument.is_empty() {
            return Err("uso: !token <pid|eprocess|endereco do token>".into());
        }
        let value = match parse_number(argument) {
            Some(value) => value,
            None => self.evaluate(argument)?,
        };
        let process = if value < 0x1_0000_0000 { Some(self.object_process(argument)?) } else { self.processes()?.into_iter().find(|process| process.eprocess == value) };
        let token = match &process {
            Some(process) => {
                let mut layouts = self.layouts()?;
                let record = self.fetch(&mut layouts, "_EPROCESS", process.eprocess, &["Token.Value"]);
                record.get(&mut layouts, "Token.Value").map(|value| value & !0xF).filter(|&token| token != 0).ok_or_else(|| format!("EPROCESS {:#x} sem token", process.eprocess))?
            }
            None => value,
        };
        let mut output = process.map(|process| format!("EPROCESS {:#x} PID {} {}\n", process.eprocess, process.pid, process.name)).unwrap_or_default();
        output.push_str(&self.monitor(&format!("token {token:#x}"))?);
        Ok(output)
    }

    /// `!hives`: a chave hivelist (a lista que o CmpAddToHiveFileList mantém).
    fn hives_command(&mut self) -> Result<String, String> {
        let mut found = Err(String::new());
        for path in ["\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\hivelist", "\\Registry\\Machine\\SYSTEM\\ControlSet001\\Control\\hivelist"] {
            found = self.registry_values(path).map(|values| (path, values));
            if found.is_ok() {
                break;
            }
        }
        let (path, values) = found.map_err(|error| format!("hivelist: {error}"))?;
        let mut output = format!("{path}: {} hives\n{:<64} ARQUIVO\n", values.len(), "CHAVE");
        for value in values {
            let file = value.display();
            let file = file.trim().trim_matches('"');
            output.push_str(&format!("{:<64} {}\n", value.name, if file.is_empty() { NONE } else { file }));
        }
        Ok(output)
    }

    // -- WNF ----------------------------------------------------------------

    /// O WNF_SCOPE_MAP a partir de uma instância de escopo: anda a
    /// ResolverListEntry até a cabeça ByDataScope[DataScope].MapEntryHead
    /// do mapa (reconhecida pelo cabeçalho de nó 0x901).
    fn wnf_map_from_instance(&mut self, layouts: &mut Layouts, instance: u64) -> Option<u64> {
        let record = self.fetch(layouts, "_WNF_SCOPE_INSTANCE", instance, &["Header.NodeTypeCode", "DataScope"]);
        if record.get(layouts, "Header.NodeTypeCode") != Some(WNF_SCOPE_INSTANCE as u64) {
            return None;
        }
        let scope = record.get(layouts, "DataScope")?;
        let head_offset = layouts.offset("_WNF_SCOPE_MAP", &format!("ByDataScope[{scope}].MapEntryHead")).ok()?;
        let link_offset = layouts.offset("_WNF_SCOPE_INSTANCE", "ResolverListEntry").ok()?;
        let map_size = layouts.size("_WNF_SCOPE_MAP")?;
        let start = instance + link_offset;
        let mut link = self.pointer_at(start)?;
        for _ in 0..256 {
            if link == start || link == 0 {
                break;
            }
            let candidate = link.wrapping_sub(head_offset);
            let header = self.read_integer(candidate, 4).unwrap_or(0);
            if header & 0xFFFF == WNF_SCOPE_MAP as u64 && header >> 16 == map_size {
                return Some(candidate);
            }
            link = self.pointer_at(link)?;
        }
        None
    }

    /// O mapa de escopos: pelos escopos implícitos dos contextos WNF dos
    /// processos ou pelo escopo do nome da primeira assinatura.
    fn wnf_scope_map(&mut self, layouts: &mut Layouts, processes: &[Process]) -> Result<u64, String> {
        let context_offset = layouts.offset("_EPROCESS", "WnfContext")?;
        let subscriptions = layouts.offset("_WNF_PROCESS_CONTEXT", "ProcessSubscriptionListHead")?;
        let entry = layouts.offset("_WNF_SUBSCRIPTION", "ProcessSubscriptionListEntry")?;
        let name_instance = layouts.offset("_WNF_SUBSCRIPTION", "NameInstance")?;
        let scope_instance = layouts.offset("_WNF_NAME_INSTANCE", "ScopeInstance")?;
        for process in processes {
            let context = self.pointer_at(process.eprocess + context_offset).unwrap_or(0);
            if context == 0 || self.read_integer(context, 2).ok() != Some(WNF_PROCESS_CONTEXT as u64) {
                continue;
            }
            let mut candidates = Vec::new();
            for index in 0..3 {
                if let Ok(at) = layouts.offset("_WNF_PROCESS_CONTEXT", &format!("ImplicitScopeInstances[{index}]")) {
                    candidates.push(self.pointer_at(context + at).unwrap_or(0));
                }
            }
            if let Some(&link) = self.list_links(context + subscriptions, 1).first() {
                let name = self.pointer_at(link - entry + name_instance).unwrap_or(0);
                candidates.push(self.pointer_at(name + scope_instance).unwrap_or(0));
            }
            for instance in candidates.into_iter().filter(|&instance| instance != 0) {
                if let Some(map) = self.wnf_map_from_instance(layouts, instance) {
                    return Ok(map);
                }
            }
        }
        Err("WNF: nenhum contexto de processo leva ao mapa de escopos (nenhum escopo criado ainda?)".into())
    }

    /// Os nós de uma árvore AVL (RTL_BALANCED_NODE) em ordem.
    fn avl_nodes(&mut self, layouts: &mut Layouts, root: u64, limit: usize) -> Vec<u64> {
        let left = layouts.offset("_RTL_BALANCED_NODE", "Children[0]").unwrap_or(0);
        let right = layouts.offset("_RTL_BALANCED_NODE", "Children[1]").unwrap_or(8);
        let mut nodes = Vec::new();
        let mut stack = Vec::new();
        let mut visited = HashSet::new();
        let mut current = root;
        loop {
            while current != 0 && stack.len() < 128 {
                if !visited.insert(current) {
                    break;
                }
                stack.push(current);
                current = self.pointer_at(current + left).unwrap_or(0);
            }
            let Some(node) = stack.pop() else { break };
            nodes.push(node);
            if nodes.len() >= limit {
                break;
            }
            current = self.pointer_at(node + right).unwrap_or(0);
        }
        nodes
    }

    /// Todas as instâncias de nome do mapa (por escopo de dados, por
    /// instância de escopo, pela árvore NameSet).
    fn wnf_names(&mut self, layouts: &mut Layouts, map: u64) -> Result<Vec<WnfName>, String> {
        let link_offset = layouts.offset("_WNF_SCOPE_INSTANCE", "ResolverListEntry")?;
        let root_offset = layouts.offset("_WNF_SCOPE_INSTANCE", "NameSet.Root")?;
        let tree_offset = layouts.offset("_WNF_NAME_INSTANCE", "TreeLinks")?;
        let subscription_head = layouts.offset("_WNF_NAME_INSTANCE", "StateSubscriptionListHead")?;
        let data_size = layouts.offset("_WNF_STATE_DATA", "DataSize").ok();
        let mut names = Vec::new();
        for scope in 0..6 {
            let Ok(head) = layouts.offset("_WNF_SCOPE_MAP", &format!("ByDataScope[{scope}].MapEntryHead")) else { continue };
            for link in self.list_links(map + head, 256) {
                let instance = link - link_offset;
                let root = self.pointer_at(instance + root_offset).unwrap_or(0);
                for node in self.avl_nodes(layouts, root, WALK_LIMIT.saturating_sub(names.len())) {
                    let address = node - tree_offset;
                    let record = self.fetch(layouts, "_WNF_NAME_INSTANCE", address, &["StateName", "StateData", "CurrentChangeStamp", "CreatorProcess"]);
                    let state_data = record.get(layouts, "StateData").unwrap_or(0);
                    let size = match data_size {
                        Some(at) if state_data > 1 => self.read_integer(state_data + at, 4).ok(),
                        _ => None,
                    };
                    let subscribers = self.list_links(address + subscription_head, 1024).len();
                    names.push(WnfName {
                        instance: address,
                        internal: record.raw_u64(layouts, "StateName").unwrap_or(0),
                        stamp: record.get(layouts, "CurrentChangeStamp"),
                        size,
                        subscribers,
                        creator: record.get(layouts, "CreatorProcess").unwrap_or(0),
                        scope_instance: instance,
                    });
                }
                if names.len() >= WALK_LIMIT {
                    return Ok(names);
                }
            }
        }
        Ok(names)
    }

    fn wnf_name_line(name: &WnfName, pids: &HashMap<u64, u64>) -> String {
        let decoded = decode_state_name(name.internal);
        let creator = match pids.get(&name.creator) {
            Some(pid) => pid.to_string(),
            None => hex_or_none(Some(name.creator)),
        };
        format!(
            "{:#018x} {:#018x} {:>3} {:<10} {:<15} {:>14} {:>4} {:>8} {:>8} {:>5} {:>8} {:#018x}\n",
            name.instance,
            name.internal ^ WNF_NAME_MASK,
            decoded.version,
            lifetime_name(decoded.lifetime),
            scope_name(decoded.scope),
            format!("{:#x}", decoded.sequence),
            decoded.permanent as u8,
            number_or_none(name.stamp),
            number_or_none(name.size),
            name.subscribers,
            creator,
            name.scope_instance
        )
    }

    fn wnf_name_header() -> String {
        format!("{:>18} {:>18} {:>3} {:<10} {:<15} {:>14} {:>4} {:>8} {:>8} {:>5} {:>8} {:>18}\n", "NAME_INSTANCE", "STATENAME", "VER", "VIDA", "ESCOPO", "SEQ", "PERM", "STAMP", "TAMANHO", "ASSIN", "CRIADOR", "ESCOPO_INST")
    }

    /// As linhas das assinaturas de uma lista (de processo ou de nome).
    fn wnf_subscriptions(&mut self, layouts: &mut Layouts, head: u64, entry_path: &str, pids: &HashMap<u64, u64>) -> Result<String, String> {
        let entry = layouts.offset("_WNF_SUBSCRIPTION", entry_path)?;
        let mut output = format!("{:>18} {:>6} {:>10} {:>18} {:<10} {:<15} {:<32} {:>8} {:>8} {:>18} {:>18} {:>18}\n", "SUBSCRIPTION", "PID", "ID", "STATENAME", "VIDA", "ESCOPO", "ESTADO", "EVENTOS", "STAMP", "NAME_INSTANCE", "CALLBACK", "CONTEXTO");
        for link in self.list_links(head, WALK_LIMIT) {
            let address = link - entry;
            let record = self.fetch(layouts, "_WNF_SUBSCRIPTION", address, &["SubscriptionId", "Process", "NameInstance", "StateName", "CallbackRoutine", "CallbackContext", "CurrentChangeStamp", "SubscribedEventSet", "SubscriptionState"]);
            let internal = record.raw_u64(layouts, "StateName").unwrap_or(0);
            let decoded = decode_state_name(internal);
            let process = record.get(layouts, "Process").unwrap_or(0);
            output.push_str(&format!(
                "{:#018x} {:>6} {:>10} {:#018x} {:<10} {:<15} {:<32} {:>8} {:>8} {:>18} {:>18} {:>18}\n",
                address,
                pids.get(&process).map_or_else(|| NONE.to_string(), |pid| pid.to_string()),
                hex_or_none(record.get(layouts, "SubscriptionId")),
                internal ^ WNF_NAME_MASK,
                lifetime_name(decoded.lifetime),
                scope_name(decoded.scope),
                record.get(layouts, "SubscriptionState").map_or_else(|| NONE.to_string(), |value| layouts.enum_text("_WNF_SUBSCRIPTION_STATE", value, &[])),
                hex_or_none(record.get(layouts, "SubscribedEventSet")).replace(NONE, "0x0"),
                number_or_none(record.get(layouts, "CurrentChangeStamp")),
                hex_or_none(record.get(layouts, "NameInstance")),
                hex_or_none(record.get(layouts, "CallbackRoutine")),
                hex_or_none(record.get(layouts, "CallbackContext")),
            ));
        }
        Ok(output)
    }

    /// `!wnf`, `!wnf <pid|eprocess>` e `!wnf nome <valor>`.
    fn wnf_command(&mut self, words: &[&str]) -> Result<String, String> {
        let mut layouts = self.layouts()?;
        let processes = self.processes()?;
        let pids: HashMap<u64, u64> = processes.iter().map(|process| (process.eprocess, process.pid)).collect();
        match words {
            [] | ["nome" | "name", _] => {
                let map = self.wnf_scope_map(&mut layouts, &processes)?;
                let names = self.wnf_names(&mut layouts, map)?;
                if let ["nome" | "name", value] = words {
                    let wanted = parse_number(value).ok_or_else(|| format!("nome de estado invalido: {value}"))? ^ WNF_NAME_MASK;
                    let name = names.iter().find(|name| name.internal == wanted).ok_or_else(|| format!("{value}: nome de estado nao encontrado ({} nomes no mapa {map:#x})", names.len()))?;
                    let head = name.instance + layouts.offset("_WNF_NAME_INSTANCE", "StateSubscriptionListHead")?;
                    let mut output = Self::wnf_name_header();
                    output.push_str(&Self::wnf_name_line(name, &pids));
                    output.push_str("assinantes:\n");
                    output.push_str(&self.wnf_subscriptions(&mut layouts, head, "StateSubscriptionListEntry", &pids)?);
                    return Ok(output);
                }
                let mut output = format!("WNF_SCOPE_MAP {map:#x}: {} nomes\n", names.len());
                output.push_str(&Self::wnf_name_header());
                for name in &names {
                    output.push_str(&Self::wnf_name_line(name, &pids));
                }
                Ok(output)
            }
            [process] => {
                let process = self.object_process(process)?;
                let context = self.pointer_at(process.eprocess + layouts.offset("_EPROCESS", "WnfContext")?).unwrap_or(0);
                if context == 0 {
                    return Ok(format!("EPROCESS {:#x} PID {} {}: sem contexto WNF\n", process.eprocess, process.pid, process.name));
                }
                let head = context + layouts.offset("_WNF_PROCESS_CONTEXT", "ProcessSubscriptionListHead")?;
                let mut output = format!("EPROCESS {:#x} PID {} {} WNF_PROCESS_CONTEXT {context:#x}\n", process.eprocess, process.pid, process.name);
                output.push_str(&self.wnf_subscriptions(&mut layouts, head, "ProcessSubscriptionListEntry", &pids)?);
                Ok(output)
            }
            _ => Err("uso: !wnf | !wnf <pid|eprocess> | !wnf nome <valor>".into()),
        }
    }

    /// Os comandos deste módulo (`commands.rs` despacha os nomes).
    pub fn objects_command(&mut self, command: &str, rest: &str) -> Result<String, String> {
        let words: Vec<&str> = rest.split_whitespace().collect();
        match command {
            "!procs" => self.procs_command(),
            "!threads" => self.threads_command(rest),
            "!waits" => self.waits_command(rest),
            "!handles" => self.handles_command(&words),
            "!obj" => self.obj_command(rest),
            "!obtypes" => self.monitor("obtypes"),
            "!token" => self.token_command(rest),
            "!iocp" => self.stub_object_query("iocp", "IoCompletion", rest),
            "!waitpkt" => self.stub_object_query("waitpkt", "WaitCompletionPacket", rest),
            "!alpc" => self.stub_object_query("alpc", "ALPC Port", rest),
            "!wnf" => self.wnf_command(&words),
            "!hives" => self.hives_command(),
            other => Err(format!("comando desconhecido: {other}")),
        }
    }
}

/// Os nomes dos comandos deste módulo (o despacho e o autocompletar).
pub const COMMANDS: [&str; 12] = ["!procs", "!threads", "!waits", "!handles", "!obj", "!obtypes", "!token", "!iocp", "!waitpkt", "!alpc", "!wnf", "!hives"];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::tests::sample;

    #[test]
    fn locates_fields_by_path() {
        let db = sample();
        assert_eq!(locate(&db, "_DEVICE_OBJECT", "DriverObject").unwrap().offset, 8);
        // Name é WCHAR[4] em +0x14.
        assert_eq!(locate(&db, "_DEVICE_OBJECT", "Name[2]").unwrap().offset, 0x18);
        assert!(locate(&db, "_DEVICE_OBJECT", "Missing").is_err());
        assert!(locate(&db, "_DEVICE_OBJECT", "Type[1]").is_err());
        assert!(locate(&db, "_NOPE", "Type").is_err());
        // Pelo ponteiro não se anda: DriverObject.Type não é um caminho.
        assert!(locate(&db, "_DEVICE_OBJECT", "DriverObject.Type").is_err());
    }

    #[test]
    fn reads_records_in_a_window() {
        let db = Arc::new(sample());
        let mut layouts = Layouts::new(db);
        let mut bytes = vec![0u8; 0x20];
        bytes[0..2].copy_from_slice(&(-3i16).to_le_bytes());
        bytes[4..8].copy_from_slice(&0b1000u32.to_le_bytes());
        bytes[8..16].copy_from_slice(&0xffffc000_00001000u64.to_le_bytes());
        bytes[0x14..0x18].copy_from_slice(&[b'N', 0, b't', 0]);
        let record = Record::new("_DEVICE_OBJECT", 0x5000, 0, bytes.clone());
        assert_eq!(record.get(&mut layouts, "Type").map(|value| value as i64), Some(-3));
        assert_eq!(record.get(&mut layouts, "Initialized"), Some(1));
        assert_eq!(record.get(&mut layouts, "DriverObject"), Some(0xffffc000_00001000));
        assert_eq!(record.bytes(&mut layouts, "Name", 4), Some(vec![b'N', 0, b't', 0]));
        assert_eq!(record.get(&mut layouts, "Missing"), None);
        // Só a faixa de +8 a +0x10 lida: os campos fora dela ficam None.
        let partial = Record::new("_DEVICE_OBJECT", 0x5000, 8, bytes[8..16].to_vec());
        assert_eq!(partial.get(&mut layouts, "DriverObject"), Some(0xffffc000_00001000));
        assert_eq!(partial.raw_u64(&mut layouts, "DriverObject"), Some(0xffffc000_00001000));
        assert_eq!(partial.get(&mut layouts, "Type"), None);
        assert_eq!(layouts.enum_text("_DEVICE_POWER_STATE", 4, &[]), "PowerDeviceD3");
        assert_eq!(layouts.enum_text("_KTHREAD_STATE", 5, &THREAD_STATES), "Waiting");
        assert_eq!(layouts.enum_text("_KTHREAD_STATE", 77, &THREAD_STATES), "77");
    }

    #[test]
    fn decodes_wnf_state_names() {
        let internal = 1 | (2 << 4) | (4 << 6) | (1 << 10) | (0x1234 << 11);
        let decoded = decode_state_name(internal);
        assert_eq!(decoded, StateName { version: 1, lifetime: 2, scope: 4, permanent: true, sequence: 0x1234 });
        assert_eq!(lifetime_name(decoded.lifetime), "Persistent");
        assert_eq!(scope_name(decoded.scope), "Machine");
        // O valor do modo usuário volta ao interno pelo mesmo XOR.
        assert_eq!((internal ^ WNF_NAME_MASK) ^ WNF_NAME_MASK, internal);
        assert_eq!(scope_name(9), "?");
    }

    fn sid_bytes(authority: u8, subauthorities: &[u32]) -> Vec<u8> {
        let mut bytes = vec![1, subauthorities.len() as u8, 0, 0, 0, 0, 0, authority];
        for value in subauthorities {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn formats_sids_and_acls() {
        let (text, length) = sid_text(&sid_bytes(5, &[32, 544])).unwrap();
        assert_eq!((text.as_str(), length), ("S-1-5-32-544", 16));
        assert_eq!(well_known_sid(&text), "Administrators");
        assert_eq!(well_known_sid("S-1-5-90-0-1"), "DWM");
        assert!(sid_text(&[1, 3, 0, 0, 0, 0, 0, 5]).is_none());
        // ACL com uma ACE ALLOW (System, 0x1f0001) e uma de objeto sem GUIDs.
        let system = sid_bytes(5, &[18]);
        let mut ace = vec![0u8, 0x02, 0, 0];
        ace.extend_from_slice(&0x1F_0001u32.to_le_bytes());
        ace.extend_from_slice(&system);
        let ace_size = ace.len() as u16;
        ace[2..4].copy_from_slice(&ace_size.to_le_bytes());
        let mut object = vec![5u8, 0, 0, 0];
        object.extend_from_slice(&0x10u32.to_le_bytes());
        object.extend_from_slice(&0u32.to_le_bytes());
        object.extend_from_slice(&system);
        let object_size = object.len() as u16;
        object[2..4].copy_from_slice(&object_size.to_le_bytes());
        let mut acl = vec![2u8, 0, 0, 0, 2, 0, 0, 0];
        acl.extend_from_slice(&ace);
        acl.extend_from_slice(&object);
        let acl_size = acl.len() as u16;
        acl[2..4].copy_from_slice(&acl_size.to_le_bytes());
        let aces = parse_acl(&acl).unwrap();
        assert_eq!(aces.len(), 2);
        assert_eq!(aces[0], AceEntry { kind: 0, flags: 2, mask: 0x1F_0001, sid: Some("S-1-5-18".into()) });
        assert_eq!(aces[1].sid.as_deref(), Some("S-1-5-18"));
        assert_eq!(ace_type_name(aces[1].kind), "ALLOW_OBJECT");
        // O descritor relativo: dono, grupo e a DACL.
        let mut descriptor = vec![1u8, 0, 0x04, 0x80];
        let owner_at = 20u32;
        let group_at = owner_at + 16;
        let dacl_at = group_at + system.len() as u32;
        for value in [owner_at, group_at, 0, dacl_at] {
            descriptor.extend_from_slice(&value.to_le_bytes());
        }
        descriptor.extend_from_slice(&sid_bytes(5, &[32, 544]));
        descriptor.extend_from_slice(&system);
        descriptor.extend_from_slice(&acl);
        let parsed = parse_self_relative(&descriptor).unwrap();
        assert_eq!(parsed.owner.as_deref(), Some("S-1-5-32-544"));
        assert_eq!(parsed.group.as_deref(), Some("S-1-5-18"));
        assert_eq!(parsed.dacl.as_ref().map(Vec::len), Some(2));
        assert!(!parsed.dacl_null);
        let text = format_security_descriptor(0x1000, &parsed);
        assert!(text.contains("DONO S-1-5-32-544 Administrators"));
        assert!(text.contains("ACE DACL 0 ALLOW flags 0x02 mascara 0x001f0001 S-1-5-18 System"));
        // DACL presente com offset zero: nula.
        let mut null = descriptor.clone();
        null[16..20].copy_from_slice(&0u32.to_le_bytes());
        assert!(parse_self_relative(&null).unwrap().dacl_null);
    }

    #[test]
    fn object_header_helpers() {
        let sizes = [0x20, 0x20, 0x10, 0x20, 0x10, 0x10, 0x10, 0x4];
        // Criador e nome: o criador fica junto do cabeçalho, o nome antes.
        assert_eq!(info_offset(0x03, 0x01, &sizes), Some(0x20));
        assert_eq!(info_offset(0x03, 0x02, &sizes), Some(0x40));
        assert_eq!(info_offset(0x02, 0x02, &sizes), Some(0x20));
        assert_eq!(info_offset(0x02, 0x01, &sizes), None);
        assert_eq!(info_offset(0x1B, 0x10, &sizes), Some(0x20 + 0x20 + 0x20 + 0x10));
        assert_eq!(header_flags(0x12), "KernelObject|PermanentObject");
        assert_eq!(header_flags(0), "-");
        let table = parse_object_types("ObHeaderCookie 0x5a\nINDICE        OBJECT_TYPE  OBJETOS  HANDLES NOME\n     7 0xffffc00000100000       12        3 Process\n    46 0xffffc00000200000        2        1 ALPC Port\n").unwrap();
        assert_eq!(table.cookie, 0x5a);
        assert_eq!(table.types.len(), 2);
        assert_eq!(table.types[1], (46, 0xffffc000_00200000, "ALPC Port".to_string()));
        // TypeIndex = índice ^ cookie ^ byte 1 do endereço do cabeçalho.
        let header = 0xffffc000_12345600u64;
        let encoded = 7 ^ 0x5a ^ 0x56;
        assert_eq!(table.decode(header, encoded).map(|entry| entry.2.as_str()), Some("Process"));
        assert_eq!(table.decode(header, 0), None);
        assert!(parse_object_types("sem cookie").is_none());
    }

    #[test]
    fn parses_stub_texts() {
        assert_eq!(parse_object_body("\\Windows\\ApiPort: tipo ALPC Port corpo 0xffffc00012340000\n"), Some(("ALPC Port".to_string(), 0xffffc000_12340000)));
        assert_eq!(parse_object_body("\\X: nao encontrado\n"), None);
        let handle = normalize_handle(Handle { handle: 4, object: 0x10, access: 0x1F0001, kind: "ALPC".into(), name: "Port \\RPC Control\\x".into() });
        assert_eq!((handle.kind.as_str(), handle.name.as_str()), ("ALPC Port", "\\RPC Control\\x"));
        let other = normalize_handle(Handle { handle: 8, object: 0x20, access: 1, kind: "Event".into(), name: String::new() });
        assert_eq!(other.kind, "Event");
        assert_eq!(type_column("ALPC Port"), "ALPC_Port");
        assert_eq!(type_column(""), "-");
        assert_eq!(rest_after("  7 0xff 1 2 ALPC Port", 4), "ALPC Port");
        assert_eq!(image_name(b"csrss.exe\0\0\0\0\0\0"), "csrss.exe");
    }
}
