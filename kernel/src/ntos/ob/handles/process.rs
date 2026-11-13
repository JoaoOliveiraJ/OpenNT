//! Tabela de handles por processo — `system32/ntos/ob/process-handles.js`.
//!
//! Publica a HANDLE_TABLE em EPROCESS.ObjectTable e controla empréstimos com
//! rundown. A tabela descreve os handles vivos; os provedores continuam
//! responsáveis pelos corpos e pelo fechamento.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::ntos::ob::handle_table::{self, HandleDescription, Row};
use crate::ntos::ex::rundown;
use crate::ntos::ke::critical_region;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::eprocess;

/// Fechamento pelo provedor dono: (processo, handle).
pub type Closer = fn(u64, u32);

/// Vínculo entre um handle publicado e seu provedor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    pub process: u64,
    pub table: u64,
    pub handle: u32,
    pub serial: u64,
}

struct ProcessTable {
    table: u64,
    draining: bool,
    closers: BTreeMap<u32, Closer>,
    removing: Vec<u64>,
}

static TABLES: SpinLock<BTreeMap<u64, ProcessTable>> = SpinLock::new(BTreeMap::new());

/// Cria a tabela e grava seu ponteiro no EPROCESS.
pub fn create(process: u64, process_id: u64) -> Result<u64, KernelError> {
    if TABLES.lock().contains_key(&process) {
        return Err(KernelError::new("process already owns a handle table"));
    }
    let table = handle_table::create(process, process_id)?;
    if let Err(error) = guest::try_write64(process + eprocess::OBJECT_TABLE, table) {
        let _ = handle_table::destroy(table);
        return Err(error);
    }
    TABLES.lock().insert(process, ProcessTable { table, draining: false, closers: BTreeMap::new(), removing: Vec::new() });
    Ok(table)
}

/// Adquire o rundown antes de ler ObjectTable. Um ponteiro não nulo
/// transfere a referência ao chamador.
pub fn reference(process: u64) -> Result<u64, KernelError> {
    let rundown_pointer = process + eprocess::RUNDOWN_PROTECT;
    if !rundown::acquire(rundown_pointer)? {
        return Ok(0);
    }
    let table = guest::try_read64(process + eprocess::OBJECT_TABLE).unwrap_or(0);
    if table == 0 {
        rundown::release(rundown_pointer)?;
    }
    Ok(table)
}

pub fn release(process: u64) -> Result<(), KernelError> {
    rundown::release(process + eprocess::RUNDOWN_PROTECT)
}

fn row_is_current(binding: &Binding) -> bool {
    handle_table::row(binding.table, binding.handle).is_some_and(|row| row.serial == binding.serial)
}

/// Insere a descrição e executa o commit do provedor dentro da região
/// crítica; uma falha no commit remove a linha antes de devolver o erro.
pub fn publish(process: u64, handle: u64, description: &HandleDescription, closer: Closer, commit: Option<&mut dyn FnMut(&Binding) -> Result<(), KernelError>>) -> Result<Binding, KernelError> {
    critical_region::with_critical(|| {
        let pointer = reference(process)?;
        if pointer == 0 {
            return Err(KernelError::with_status("process handle table is closing", 0xC000_010A));
        }
        let result = (|| {
            let table = TABLES.lock().get(&process).map(|owner| owner.table);
            if table != Some(pointer) {
                return Err(KernelError::new("process handle table ownership mismatch"));
            }
            let row: Row = handle_table::insert(pointer, handle, description)?;
            if let Some(owner) = TABLES.lock().get_mut(&process) {
                owner.closers.insert(row.handle, closer);
            }
            let binding = Binding { process, table: pointer, handle: row.handle, serial: row.serial };
            if let Some(commit) = commit {
                if let Err(error) = commit(&binding) {
                    if let Some(owner) = TABLES.lock().get_mut(&process) {
                        owner.closers.remove(&row.handle);
                    }
                    handle_table::remove(pointer, handle)?;
                    return Err(error);
                }
            }
            Ok(binding)
        })();
        release(process)?;
        result
    })
}

/// Reivindica a remoção da linha e executa o commit uma única vez. Durante
/// a drenagem final, admite a remoção depois do fechamento do rundown.
pub fn remove(binding: &Binding, commit: Option<&mut dyn FnMut()>) -> Result<bool, KernelError> {
    {
        let tables = TABLES.lock();
        if tables.get(&binding.process).is_some_and(|owner| owner.removing.contains(&binding.serial)) {
            return Ok(false);
        }
    }
    if !row_is_current(binding) {
        return Ok(false);
    }
    critical_region::with_critical(|| {
        let referenced = rundown::acquire(binding.process + eprocess::RUNDOWN_PROTECT)?;
        let draining = TABLES.lock().get(&binding.process).is_some_and(|owner| owner.draining);
        if !referenced && !draining {
            return Ok(false);
        }
        if let Some(owner) = TABLES.lock().get_mut(&binding.process) {
            owner.removing.push(binding.serial);
        }
        let result = handle_table::remove(binding.table, binding.handle as u64);
        let removed = matches!(&result, Ok(Some(row)) if row.serial == binding.serial);
        {
            let mut tables = TABLES.lock();
            if let Some(owner) = tables.get_mut(&binding.process) {
                owner.removing.retain(|&serial| serial != binding.serial);
                if removed {
                    owner.closers.remove(&binding.handle);
                }
            }
        }
        if removed {
            if let Some(commit) = commit {
                commit();
            }
        }
        if referenced {
            release(binding.process)?;
        }
        result.map(|_| removed)
    })
}

/// Altera atributos e acesso de uma linha ainda pertencente à tabela.
pub fn change(binding: &Binding, attributes: u32, access: u32, commit: Option<&mut dyn FnMut()>) -> Result<bool, KernelError> {
    let removing = TABLES.lock().get(&binding.process).is_some_and(|owner| owner.removing.contains(&binding.serial));
    if removing || !row_is_current(binding) {
        return Ok(false);
    }
    critical_region::with_critical(|| {
        let referenced = rundown::acquire(binding.process + eprocess::RUNDOWN_PROTECT)?;
        let changed = referenced && handle_table::change(binding.table, binding.handle as u64, attributes, access)?;
        if changed {
            if let Some(commit) = commit {
                commit();
            }
        }
        if referenced {
            release(binding.process)?;
        }
        Ok(changed)
    })
}

/// Exige rundown concluído e fecha cada handle pelo proprietário.
pub fn destroy(process: u64) -> Result<(), KernelError> {
    let Some(table) = TABLES.lock().get(&process).map(|owner| owner.table) else {
        return Ok(());
    };
    if guest::compare_exchange64(process + eprocess::RUNDOWN_PROTECT, 0, 0)? != 1 {
        return Err(KernelError::new("process handle table rundown is not complete"));
    }
    // Só esta fase remove linhas depois do rundown.
    if let Some(owner) = TABLES.lock().get_mut(&process) {
        owner.draining = true;
    }
    while let Some(row) = handle_table::rows(table).into_iter().next() {
        let closer = TABLES.lock().get(&process).and_then(|owner| owner.closers.get(&row.handle).copied());
        let Some(closer) = closer else {
            return Err(KernelError::new("handle has no owning closer"));
        };
        closer(process, row.handle);
        if handle_table::row(table, row.handle).is_some_and(|current| current.serial == row.serial) {
            return Err(KernelError::new("provider did not close its process handle"));
        }
    }
    guest::write64(process + eprocess::OBJECT_TABLE, 0);
    handle_table::destroy(table)?;
    TABLES.lock().remove(&process);
    Ok(())
}

/// Abandona uma tabela recém-criada somente se ainda estiver vazia.
pub fn abort(process: u64) -> Result<(), KernelError> {
    let Some(table) = TABLES.lock().get(&process).map(|owner| owner.table) else {
        return Ok(());
    };
    if !handle_table::rows(table).is_empty() {
        return Err(KernelError::new("cannot abandon an inhabited process table"));
    }
    guest::write64(process + eprocess::OBJECT_TABLE, 0);
    handle_table::destroy(table)?;
    TABLES.lock().remove(&process);
    Ok(())
}

/// A tabela está na drenagem final (remoções depois do rundown fechado).
pub fn draining(process: u64) -> bool {
    TABLES.lock().get(&process).is_some_and(|owner| owner.draining)
}

pub fn get(process: u64) -> Option<u64> {
    TABLES.lock().get(&process).map(|owner| owner.table)
}
