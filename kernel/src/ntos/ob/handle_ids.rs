//! Os números de handle: a numeração de cada tabela de handles de usuário
//! (uma por processo, como a ObjectTable do NT) e o espaço dos provedores
//! que indexam os registros só pelo valor (o Object Manager, os arquivos do
//! zw e o registro, com os handles de kernel deles).
//!
//! - Tabela de usuário ([`Numbers`], uma por `ProcessState`): como o
//!   ExpAllocateHandleTableEntry e o ExpFreeHandleTableEntry do ntoskrnl
//!   19041 numa tabela sem StrictFIFO (HANDLE_TABLE.Flags bit 0), que é o caso
//!   das tabelas de processo: o valor liberado vai para a cabeça da lista
//!   livre (FirstFreeHandleEntry) e é o próximo a sair; sem livre, a tabela
//!   cresce pelo menor valor ainda não usado, de 4 em 4, pulando a entrada 0
//!   de cada folha (os múltiplos de 0x400, reservados na HANDLE_TABLE, cuja
//!   entrada guarda a base da folha). O primeiro handle de um processo novo
//!   é 4.
//! - Provedores globais ([`allocate`]/[`release`]): os registros deles são
//!   achados só pelo valor, então o valor é único entre eles no sistema
//!   inteiro; o liberado vai para o fim de uma fila e o mais antigo sai
//!   primeiro, para um valor fechado demorar a voltar. Os valores novos
//!   começam em [`GLOBAL_BASE`], deixando os baixos às tabelas de usuário,
//!   como os handles de kernel do NT, que moram em outra tabela e não
//!   ocupam valores das tabelas dos processos.
//! - Disjunção: um valor vivo numa tabela de usuário não sai para um
//!   provedor global, e um valor vivo num provedor global não sai para uma
//!   tabela de usuário, então um valor nunca aponta dois donos no processo
//!   corrente. Diferença declarada: no NT todo handle de um processo mora na
//!   tabela dele (e os de kernel na do System, com o prefixo), sem essa
//!   disjunção; aqui um processo pula os valores que os provedores globais
//!   ocupam naquele momento.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

use crate::ntos::inc::status::STATUS_INSUFFICIENT_RESOURCES;
use crate::rtl::{KernelError, SpinLock};

/// O maior valor de handle (MAX_HANDLES - 4 do NT, 2^31 - 4).
const MAXIMUM: u32 = 0x7FFF_FFFC;
/// O primeiro valor novo dos provedores globais (o começo da quinta folha
/// de uma HANDLE_TABLE).
pub const GLOBAL_BASE: u32 = 0x1004;

struct Global {
    /// Valores vivos nos provedores globais.
    live: BTreeSet<u32>,
    /// Valores vivos em tabelas de usuário, com quantas tabelas os têm (a
    /// herança põe o mesmo valor no filho).
    user: BTreeMap<u32, u32>,
    /// Valores que os provedores globais liberaram, do mais antigo ao mais
    /// novo.
    free: VecDeque<u32>,
    /// O menor valor que os provedores globais nunca usaram.
    next: u32,
}

static GLOBAL: SpinLock<Global> = SpinLock::new(Global { live: BTreeSet::new(), user: BTreeMap::new(), free: VecDeque::new(), next: GLOBAL_BASE });

fn exhausted() -> KernelError {
    KernelError::with_status("handle ID space exhausted", STATUS_INSUFFICIENT_RESOURCES)
}

/// O valor é um handle que uma tabela pode dar: múltiplo de 4, fora da
/// entrada 0 de uma folha e dentro do limite.
fn assignable(value: u32) -> bool {
    value >= 4 && value <= MAXIMUM && value & 3 == 0 && value & 0x3FF != 0
}

/// Um valor para um provedor global, a partir de `minimum` (múltiplo de 4,
/// pelo menos 4).
pub fn allocate(minimum: u32) -> Result<u32, KernelError> {
    if minimum < 4 || minimum & 3 != 0 {
        return Err(KernelError::new("invalid handle allocation floor"));
    }
    let mut global = GLOBAL.lock();
    for _ in 0..global.free.len() {
        let Some(value) = global.free.pop_front() else { break };
        if value < minimum || global.user.contains_key(&value) {
            global.free.push_back(value);
            continue;
        }
        global.live.insert(value);
        return Ok(value);
    }
    let mut value = global.next.max(minimum);
    while !assignable(value) || global.user.contains_key(&value) {
        if value >= MAXIMUM {
            return Err(exhausted());
        }
        value += 4;
    }
    global.next = value + 4;
    global.live.insert(value);
    Ok(value)
}

/// Devolve um valor de provedor global (o fechamento do registro dono).
pub fn release(value: u32) {
    let mut global = GLOBAL.lock();
    if global.live.remove(&value) {
        global.free.push_back(value);
    }
}

/// A numeração de uma tabela de handles de usuário.
pub struct Numbers {
    /// Os valores liberados da tabela; o último é a cabeça da lista livre.
    free: Vec<u32>,
    /// O menor valor que a tabela nunca deu.
    next: u32,
}

impl Numbers {
    pub const fn new() -> Self {
        Self { free: Vec::new(), next: 4 }
    }
}

impl Default for Numbers {
    fn default() -> Self {
        Self::new()
    }
}

/// O próximo valor da tabela (o ExpAllocateHandleTableEntry): a cabeça da
/// lista livre, ou o menor valor novo; um valor ocupado agora por um
/// provedor global fica para depois.
pub fn allocate_user(numbers: &mut Numbers) -> Result<u32, KernelError> {
    let mut global = GLOBAL.lock();
    if let Some(position) = numbers.free.iter().rposition(|value| !global.live.contains(value)) {
        let value = numbers.free.remove(position);
        *global.user.entry(value).or_insert(0) += 1;
        return Ok(value);
    }
    loop {
        let value = numbers.next;
        if value > MAXIMUM {
            return Err(exhausted());
        }
        numbers.next += 4;
        if !assignable(value) {
            continue;
        }
        if global.live.contains(&value) {
            // Livre para a tabela assim que o provedor global o soltar.
            numbers.free.insert(0, value);
            continue;
        }
        *global.user.entry(value).or_insert(0) += 1;
        return Ok(value);
    }
}

/// Um valor dado de antemão (a herança, que repete no filho o valor do
/// pai): sai da lista livre ou, acima do que a tabela já deu, os valores do
/// meio entram livres. `false` se a tabela já o usa.
pub fn reserve_user(numbers: &mut Numbers, value: u32) -> Result<bool, KernelError> {
    if !assignable(value) {
        return Err(KernelError::new("invalid handle value"));
    }
    if let Some(position) = numbers.free.iter().position(|&free| free == value) {
        numbers.free.remove(position);
    } else if value >= numbers.next {
        let mut skipped = numbers.next;
        while skipped < value {
            if assignable(skipped) {
                numbers.free.insert(0, skipped);
            }
            skipped += 4;
        }
        numbers.next = value + 4;
    } else {
        return Ok(false);
    }
    *GLOBAL.lock().user.entry(value).or_insert(0) += 1;
    Ok(true)
}

/// Devolve o valor à cabeça da lista livre da tabela (o
/// ExpFreeHandleTableEntry).
pub fn release_user(numbers: &mut Numbers, value: u32) {
    let mut global = GLOBAL.lock();
    if let Some(count) = global.user.get_mut(&value) {
        *count -= 1;
        if *count == 0 {
            global.user.remove(&value);
        }
    }
    numbers.free.push(value);
}
