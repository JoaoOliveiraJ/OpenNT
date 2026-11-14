//! Tabela de ids de cliente: o papel da PspCidTable do NT.
//!
//! PIDs e TIDs saem de um só espaço de valores, então um id nunca é ao mesmo
//! tempo de um processo e de uma thread. Cada valor fica com o objeto até o
//! EPROCESS/ETHREAD ser recolhido (não no término), como no NT: um processo
//! terminado e ainda retido por um handle continua dono do seu PID.
//!
//! Os valores seguem as regras dos ids de handle do NT: múltiplos de 4, até
//! 32 bits, nunca com o slot zero de uma página da tabela (`id & 0x3FC == 0`,
//! o que o PsLookupThreadByThreadId recusa). O cursor só avança e pula os
//! valores em uso, então um id solto não volta logo a outro objeto.
//!
//! Um id pode ser reservado antes de o objeto existir (`allocate`), quando o
//! processo precisa dele para montar a TEB antes de criar a thread, e depois
//! ligado ao objeto por `create_process`/`create_kernel_thread`.

use alloc::collections::BTreeMap;
use alloc::format;

use crate::rtl::{KernelError, SpinLock};

/// O id pedido a `create_process`/`create_kernel_thread` quando o objeto
/// recebe o próximo id livre da tabela.
pub const ALLOCATE: u64 = 0;
/// O primeiro valor depois do System (PID 4).
const FIRST_ID: u64 = 8;
/// Ids de cliente cabem em 32 bits.
const LIMIT: u64 = 0x1_0000_0000;

/// O dono de um id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Process,
    Thread,
}

/// Uma entrada da tabela: o tipo e o objeto (0 enquanto só reservado).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub kind: Kind,
    pub object: u64,
}

struct Table {
    entries: BTreeMap<u64, Entry>,
    next: u64,
}

static TABLE: SpinLock<Table> = SpinLock::new(Table { entries: BTreeMap::new(), next: FIRST_ID });

/// Um valor que o NT aceitaria como id de cliente.
pub fn valid(id: u64) -> bool {
    id != 0 && id % 4 == 0 && id < LIMIT && id & 0x3FC != 0
}

fn following(id: u64) -> u64 {
    let mut next = id + 4;
    if next >= LIMIT {
        next = FIRST_ID;
    }
    if next & 0x3FC == 0 {
        next += 4;
    }
    next
}

/// Reserva o próximo id livre para um objeto de `kind` ainda sem endereço.
pub fn allocate(kind: Kind) -> Result<u64, KernelError> {
    let mut table = TABLE.lock();
    let start = table.next;
    let mut id = start;
    while table.entries.contains_key(&id) {
        id = following(id);
        if id == start {
            return Err(KernelError::with_status("tabela de ids de cliente cheia", 0xC000_0017));
        }
    }
    table.entries.insert(id, Entry { kind, object: 0 });
    table.next = following(id);
    Ok(id)
}

/// Prepara o id de um objeto em criação: `ALLOCATE` reserva o próximo livre;
/// um id já reservado por `allocate` para o mesmo tipo e ainda sem objeto é
/// aceito; um id livre é reservado. Um id com dono, de outro tipo ou fora das
/// regras do NT é recusado.
pub fn claim(id: u64, kind: Kind) -> Result<u64, KernelError> {
    if id == ALLOCATE {
        return allocate(kind);
    }
    if !valid(id) {
        return Err(KernelError::with_status(format!("id de cliente invalido {id:#x}"), 0xC000_000B));
    }
    let mut table = TABLE.lock();
    match table.entries.get(&id) {
        Some(entry) if entry.kind == kind && entry.object == 0 => Ok(id),
        Some(_) => Err(KernelError::with_status(format!("id de cliente {id:#x} em uso"), 0xC000_000B)),
        None => {
            table.entries.insert(id, Entry { kind, object: 0 });
            Ok(id)
        }
    }
}

/// Liga o objeto ao id reservado.
pub fn bind(id: u64, kind: Kind, object: u64) -> Result<(), KernelError> {
    match TABLE.lock().entries.get_mut(&id) {
        Some(entry) if entry.kind == kind && entry.object == 0 && object != 0 => {
            entry.object = object;
            Ok(())
        }
        _ => Err(KernelError::with_status(format!("id de cliente {id:#x} sem reserva"), 0xC000_000B)),
    }
}

/// Solta o id do objeto recolhido (ou da reserva desfeita, com `object` 0);
/// um id que já é de outro objeto fica onde está.
pub fn release(id: u64, object: u64) {
    let mut table = TABLE.lock();
    if table.entries.get(&id).is_some_and(|entry| entry.object == object) {
        table.entries.remove(&id);
    }
}

/// O dono do id, se houver.
pub fn lookup(id: u64) -> Option<Entry> {
    TABLE.lock().entries.get(&id).copied()
}
