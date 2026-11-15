//! O banco do Errata Manager e a trava dele (o EmpDatabaseLock).
//!
//! Os registros do ntoskrnl 19041, em listas do módulo na ordem de busca
//! deles (as listas simplesmente encadeadas do NT empilham na cabeça; as
//! buscas comparam o GUID e o primeiro que casa vence, e os GUIDs do banco
//! são únicos):
//! - o tipo de entrada (EmpEntryListHead): quantos provedores o registraram
//!   (+0x10), os callbacks preguiçosos (+0x38) e as regras que o listam no
//!   [RuleDef] (+0x48);
//! - o callback (EmpCallbackListHead): a rotina e o contexto do provedor que
//!   o registrou (+0x10, +0x20), quantos registros (+0x18), as regras que o
//!   usam (+0x30) e as contagens de argumentos do [CallbackDef] (+0x38..);
//! - a regra (EmpRuleListHead): o estado (+0x10, começa UNKNOWN), se está
//!   pronta (+0x14), as regras que dependem dela (+0x20), as contagens de
//!   argumentos e os tipos de entrada do [RuleDef], os callbacks e as regras
//!   referenciados pela expressão (+0x40, +0x48) e a árvore da expressão
//!   (+0x60);
//! - a regra-alvo (EmpTargetRuleListHead): a regra, quantos clientes a
//!   consultam e os conjuntos de índices de argumentos do [TargetRuleDef];
//! - a tabela de cadeias (EmpStringTable): os valores do [Strings], cada um
//!   numa cópia em pool ('EMit'), cujos endereços os callbacks recebem.
//!
//! O EmpDatabaseLock é um push lock exclusivo, que a avaliação segura
//! enquanto chama os callbacks dos provedores: aqui é um [`SharedLock`]
//! exclusivo (que pode ser segurado numa espera), e o banco só é acessado
//! com ele.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};

use crate::ntos::inc::types::Guid;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::sync::SharedLockGuard;
use crate::rtl::SharedLock;

/// EM_RULE_STATE.
pub const STATE_FALSE: u32 = 0;
pub const STATE_UNKNOWN: u32 = 1;
pub const STATE_TRUE: u32 = 2;

/// A rotina de um callback registrado: a de um driver (no endereço) ou uma
/// do próprio kernel (as da HAL e as embutidas).
#[derive(Clone, Copy)]
pub enum Routine {
    Guest(u64),
    Native(NativeCallback),
}

impl PartialEq for Routine {
    fn eq(&self, other: &Routine) -> bool {
        match (self, other) {
            (Routine::Guest(left), Routine::Guest(right)) => left == right,
            (Routine::Native(left), Routine::Native(right)) => *left as usize == *right as usize,
            _ => false,
        }
    }
}

/// Os argumentos de um callback (a ABI do EM_CALLBACK_ROUTINE): as entradas
/// (ponteiros para {Data, DataSize}), as cadeias (endereços das cópias da
/// tabela) e os números.
pub struct Arguments<'a> {
    pub entries: &'a [u64],
    pub strings: &'a [u64],
    pub numerics: &'a [u32],
    pub context: u64,
}

pub type NativeCallback = fn(&Arguments) -> u32;

pub struct EntryType {
    pub guid: [u8; 16],
    /// ProviderCount (+0x10).
    pub provider_count: i32,
    /// LazyCallbacks (+0x38): (rotina, contexto, provedor).
    pub lazy: Vec<(u64, u64, u64)>,
    /// As regras que listam o tipo no [RuleDef] (+0x48, sem repetição).
    pub rules: Vec<usize>,
    /// Uma cópia em pool do GUID: o LPCGUID que o callback preguiçoso
    /// recebe (o registro do tipo começa pelo GUID).
    pub guid_address: u64,
}

pub struct Callback {
    pub guid: [u8; 16],
    pub routine: Option<Routine>,
    pub registrations: i32,
    pub context: u64,
    /// As regras que usam o callback (+0x30, sem repetição).
    pub rules: Vec<usize>,
    pub strings: u32,
    pub numerics: u32,
    pub entry_types: Vec<usize>,
}

/// Um termo da expressão: o callback (`?`) ou a regra (`%`) e os índices
/// de argumentos do termo (cadeias, números e entradas, nessa ordem);
/// `None` quando o chamado não tem argumentos (a avaliação repassa os do
/// chamador).
pub enum Node {
    Callback { index: usize, arguments: Option<Vec<u32>> },
    Rule { index: usize, arguments: Option<Vec<u32>> },
    Operator { operator: u8, left: Box<Node>, right: Box<Node> },
}

pub struct Rule {
    pub guid: [u8; 16],
    pub state: u32,
    pub ready: bool,
    /// As regras que referenciam esta com `%` (+0x20, sem repetição).
    pub dependents: Vec<usize>,
    pub strings: u32,
    pub numerics: u32,
    pub entry_types: Vec<usize>,
    /// Os callbacks e as regras da expressão (+0x40 e +0x48, com repetição).
    pub callbacks: Vec<usize>,
    pub referenced: Vec<usize>,
    pub root: Node,
}

pub struct TargetRule {
    pub references: i32,
    pub rule: usize,
    /// Os conjuntos, cada um com NumStrings + NumNumerics índices.
    pub arguments: Vec<u32>,
}

/// O banco interpretado do INF de errata.
pub struct Database {
    pub entry_types: Vec<EntryType>,
    pub callbacks: Vec<Callback>,
    pub rules: Vec<Rule>,
    /// Os valores do [Strings] e o endereço da cópia de cada um.
    pub strings: Vec<(String, u64)>,
    pub targets: Vec<TargetRule>,
    /// A fila do EmpQueueRuleUpdateState: (regra, âncora).
    pub update_queue: Vec<(usize, Option<usize>)>,
}

struct Protected(UnsafeCell<Database>);

// SAFETY: o banco só é acessado com o EmpDatabaseLock exclusivo
// (`DatabaseGuard`).
unsafe impl Sync for Protected {}

static DATABASE_LOCK: SharedLock = SharedLock::new();
static DATABASE: Protected = Protected(UnsafeCell::new(Database { entry_types: Vec::new(), callbacks: Vec::new(), rules: Vec::new(), strings: Vec::new(), targets: Vec::new(), update_queue: Vec::new() }));

/// O banco com o EmpDatabaseLock exclusivo.
pub struct DatabaseGuard {
    _guard: SharedLockGuard<'static>,
}

impl Deref for DatabaseGuard {
    type Target = Database;
    fn deref(&self) -> &Database {
        // SAFETY: posse exclusiva do EmpDatabaseLock.
        unsafe { &*DATABASE.0.get() }
    }
}

impl DerefMut for DatabaseGuard {
    fn deref_mut(&mut self) -> &mut Database {
        // SAFETY: posse exclusiva do EmpDatabaseLock.
        unsafe { &mut *DATABASE.0.get() }
    }
}

/// O EmpDatabaseLock exclusivo.
pub fn lock() -> DatabaseGuard {
    DatabaseGuard { _guard: DATABASE_LOCK.acquire_exclusive() }
}

/// Os 16 bytes do GUID em `address`.
pub fn guid_at(address: u64) -> [u8; 16] {
    let mut guid = [0u8; 16];
    guid.copy_from_slice(&guest::read_bytes(address, core::mem::size_of::<Guid>()));
    guid
}

/// O GUID de um texto no formato do RtlGUIDFromString
/// (`{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`).
pub fn guid_from_text(text: &str) -> Option<[u8; 16]> {
    let bytes = text.as_bytes();
    if bytes.len() != 38 || bytes[0] != b'{' || bytes[37] != b'}' || [9, 14, 19, 24].iter().any(|&index| bytes[index] != b'-') {
        return None;
    }
    let hex = |index: usize| -> Option<u8> {
        let digit = |byte: u8| (byte as char).to_digit(16).map(|value| value as u8);
        Some(digit(bytes[index])? << 4 | digit(bytes[index + 1])?)
    };
    let mut guid = [0u8; 16];
    // Data1, Data2 e Data3 little-endian; Data4 na ordem do texto.
    for (target, source) in [(3, 1), (2, 3), (1, 5), (0, 7), (5, 10), (4, 12), (7, 15), (6, 17), (8, 20), (9, 22)] {
        guid[target] = hex(source)?;
    }
    for index in 0..6 {
        guid[10 + index] = hex(25 + index * 2)?;
    }
    Some(guid)
}

impl Database {
    /// EmpSearchEntryDatabase.
    pub fn search_entry(&self, guid: &[u8; 16]) -> Option<usize> {
        self.entry_types.iter().position(|record| record.guid == *guid)
    }

    /// EmpSearchCallbackDatabase.
    pub fn search_callback(&self, guid: &[u8; 16]) -> Option<usize> {
        self.callbacks.iter().position(|record| record.guid == *guid)
    }

    /// EmpSearchRuleDatabase.
    pub fn search_rule(&self, guid: &[u8; 16]) -> Option<usize> {
        self.rules.iter().position(|record| record.guid == *guid)
    }

    /// EmpSearchTargetRuleList: a primeira regra-alvo da regra.
    pub fn search_target(&self, rule: usize) -> Option<usize> {
        self.targets.iter().position(|target| target.rule == rule)
    }
}
