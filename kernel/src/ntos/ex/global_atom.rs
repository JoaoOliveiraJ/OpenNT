//! Átomos globais: NtAddAtom, NtAddAtomEx, NtFindAtom, NtDeleteAtom e
//! NtQueryInformationAtom, como no ntoskrnl 19041 (NtAddAtomEx 0x684130,
//! NtAddAtom 0x956c10, NtFindAtom 0x61b130, NtDeleteAtom 0x686070,
//! NtQueryInformationAtom 0x683e50).
//!
//! A tabela é a do win32k: cada serviço pede ao callout 2 do subsistema
//! (PsInvokeWin32Callout(2, &AtomTable), no NtFindAtom o
//! ExCallCallBack(MmSessionGetWin32Callouts(), 2, &AtomTable), o mesmo bloco
//! da sessão corrente) a tabela global da window station do processo; sem
//! win32k na sessão ou sem tabela, STATUS_ACCESS_DENIED. As operações são as
//! do Rtl sobre essa tabela (`rtl/atom.rs`). É o que o GlobalAddAtom, o
//! GlobalFindAtom, o SetProp com nome (GlobalAddAtomW e depois NtUserSetProp)
//! e o RegisterDragDrop do ole32 usam.
//!
//! Em UserMode o NtAddAtomEx e o NtFindAtom sondam o Atom (uma palavra, sem
//! alinhamento) e, com Length diferente de zero, o Name (alinhado a 2, senão
//! STATUS_DATATYPE_MISALIGNMENT; a faixa contra o MmUserProbeAddress) e copiam
//! Length bytes para um buffer de 0x200 com o NUL em Length/2; em KernelMode o
//! Name do chamador vai direto ao Rtl. Uma falha de acesso devolve o código
//! da exceção, como o __except do original.

use alloc::vec::Vec;

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::memory_map::USER_PROBE_ADDRESS;
use crate::ntos::ps::user::state;
use crate::ntos::ps::{previous_mode, win32};
use crate::ntos::rtl::atom;
use crate::rtl::KernelError;

const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// O callout do win32k que devolve a tabela de átomos global.
const ATOM_TABLE_CALLOUT: i32 = 2;
/// Maior Length aceito e o buffer da cópia do nome.
const MAXIMUM_NAME_BYTES: u32 = 0x1FE;
const NAME_BUFFER: u64 = 0x200;
/// Do Flags do NtAddAtomEx só este bit é aceito.
const ADD_FLAGS_VALID: u32 = 2;
/// AtomBasicInformation: UsageCount, Flags e NameLength antes do nome.
const BASIC_HEADER: u32 = 6;
/// AtomTableInformation: NumberOfAtoms antes do vetor.
const TABLE_HEADER: u32 = 4;
/// O maior nome com o NUL: o buffer de nome do kernel nunca passa disto.
const LONGEST_NAME: u32 = 0x202;

/// A tabela global do subsistema (o callout 2), ou 0.
fn global_table() -> u64 {
    let cell = guest::alloc_bytes(8);
    if cell == 0 {
        return 0;
    }
    guest::write64(cell, 0);
    let _ = win32::invoke_callout(ATOM_TABLE_CALLOUT, cell);
    let table = guest::read64(cell);
    guest::free_bytes(cell);
    table
}

/// A chamada veio de UserMode (KTHREAD.PreviousMode).
fn from_user() -> bool {
    previous_mode::get().unwrap_or(1) != 0
}

/// Sonda de escrita de um ponteiro de usuário de `T`: um endereço no
/// MmUserProbeAddress ou acima dele é o próprio MmUserProbeAddress (que
/// falha); lê e regrava o valor.
fn probe_write<T: guest::GuestScalar>(address: u64) -> Result<(), u32> {
    if address >= USER_PROBE_ADDRESS {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let value = guest::try_read::<T>(address).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    guest::try_write::<T>(address, value).map_err(|_| STATUS_ACCESS_VIOLATION)
}

/// O nome que vai ao Rtl e o buffer do kernel a liberar depois (0 sem cópia).
struct CapturedName {
    pointer: u64,
    buffer: u64,
}

impl Drop for CapturedName {
    fn drop(&mut self) {
        if self.buffer != 0 {
            guest::free_bytes(self.buffer);
        }
    }
}

/// O nome do NtAddAtomEx/NtFindAtom já com o Length conferido.
fn capture_name(name: u64, length: u32, user: bool) -> Result<CapturedName, u32> {
    if !user || name == 0 {
        return Ok(CapturedName { pointer: name, buffer: 0 });
    }
    if length != 0 {
        if name & 1 != 0 {
            return Err(STATUS_DATATYPE_MISALIGNMENT);
        }
        if !name.checked_add(length as u64).is_some_and(|end| end <= USER_PROBE_ADDRESS) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
    }
    let bytes = if length == 0 { Vec::new() } else { guest::try_read_bytes(name, length as usize).map_err(|_| STATUS_ACCESS_VIOLATION)? };
    let buffer = guest::alloc_bytes(NAME_BUFFER);
    if buffer == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write_bytes(buffer, &bytes);
    guest::write16(buffer + (length as u64 / 2) * 2, 0);
    Ok(CapturedName { pointer: buffer, buffer })
}

/// O corpo comum do NtAddAtomEx e do NtFindAtom depois do callout: sonda o
/// Atom e captura o nome, roda `operation(tabela, nome, &átomo)` e, com
/// sucesso, grava o átomo.
fn named_operation(table: u64, name: u64, length: u32, output: u64, operation: impl FnOnce(u64, u64, &Field<u16>) -> Result<u32, KernelError>) -> Result<u32, KernelError> {
    if length > MAXIMUM_NAME_BYTES {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let user = from_user();
    if user && output != 0 {
        if let Err(status) = probe_write::<u16>(output) {
            return Ok(status);
        }
    }
    let captured = match capture_name(name, length, user) {
        Ok(captured) => captured,
        Err(status) => return Ok(status),
    };
    let cell = guest::alloc_bytes(8);
    if cell == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write64(cell, 0);
    // SAFETY: célula recém-alocada do kernel.
    let local = unsafe { Field::<u16>::at(cell) };
    let status = operation(table, captured.pointer, local);
    let atom = local.get();
    guest::free_bytes(cell);
    let status = status?;
    if output != 0 && (status as i32) >= 0 {
        if user {
            if guest::try_write::<u16>(output, atom).is_err() {
                return Ok(STATUS_ACCESS_VIOLATION);
            }
        } else {
            // SAFETY: PRTL_ATOM do chamador de modo kernel.
            unsafe { Field::<u16>::at(output) }.set(atom);
        }
    }
    Ok(status)
}

/// NtAddAtomEx(AtomName, Length, Atom, Flags).
pub fn add_atom(name: u64, length: u32, output: u64, flags: u32) -> Result<u32, KernelError> {
    if flags & !ADD_FLAGS_VALID != 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let table = global_table();
    if table == 0 {
        return Ok(STATUS_ACCESS_DENIED);
    }
    named_operation(table, name, length, output, |table, name, atom| atom::add(table, name, Some(atom), flags))
}

/// NtFindAtom(AtomName, Length, Atom): sem Flags.
pub fn find_atom(name: u64, length: u32, output: u64) -> Result<u32, KernelError> {
    let table = global_table();
    if table == 0 {
        return Ok(STATUS_ACCESS_DENIED);
    }
    named_operation(table, name, length, output, |table, name, atom| atom::lookup(table, name, Some(atom)))
}

/// NtDeleteAtom(Atom).
pub fn delete_atom(value: u16) -> Result<u32, KernelError> {
    let table = global_table();
    if table == 0 {
        return Ok(STATUS_ACCESS_DENIED);
    }
    atom::delete(table, value)
}

/// Grava `bytes` na saída do chamador (sondada em UserMode).
fn write_output(address: u64, bytes: &[u8], user: bool) -> Result<(), u32> {
    if user {
        return guest::try_write_bytes(address, bytes).map_err(|_| STATUS_ACCESS_VIOLATION);
    }
    guest::write_bytes(address, bytes);
    Ok(())
}

/// NtQueryInformationAtom(Atom, AtomInformationClass, AtomInformation,
/// AtomInformationLength, ReturnLength). Em UserMode o buffer é sondado
/// para escrita (alinhamento 4) e o ReturnLength também. Classe 0
/// (AtomBasicInformation: UsageCount, Flags, NameLength e o nome, a partir
/// do RtlQueryAtomInAtomTable): menos de 6 bytes dá
/// STATUS_INFO_LENGTH_MISMATCH sem ReturnLength; o ReturnLength é
/// NameLength + 8 no sucesso e 6 na falha. Classe 1 (AtomTableInformation:
/// NumberOfAtoms e o vetor, o RtlQueryAtomsInAtomTable): menos de 4 bytes dá
/// STATUS_INFO_LENGTH_MISMATCH sem ReturnLength; NumberOfAtoms é gravado
/// mesmo quando o vetor não cabe, e o ReturnLength é 2 * NumberOfAtoms + 4
/// no sucesso e 4 na falha. Outra classe: STATUS_INVALID_INFO_CLASS com
/// ReturnLength 0.
pub fn query_information(value: u16, class: u32, information: u64, length: u32, return_length: u64) -> Result<u32, KernelError> {
    let table = global_table();
    if table == 0 {
        return Ok(STATUS_ACCESS_DENIED);
    }
    let user = from_user();
    if user {
        // ProbeForWrite(AtomInformation, Length, 4).
        if length != 0 {
            if information & 3 != 0 {
                return Ok(STATUS_DATATYPE_MISALIGNMENT);
            }
            if !information.checked_add(length as u64).is_some_and(|end| end <= USER_PROBE_ADDRESS) || !state::probe_user_write(information, length as u64) {
                return Ok(STATUS_ACCESS_VIOLATION);
            }
        }
        if return_length != 0 {
            if let Err(status) = probe_write::<u32>(return_length) {
                return Ok(status);
            }
        }
    }
    let (status, written) = match class {
        0 => match query_basic(table, value, information, length, user)? {
            Ok(result) => result,
            Err(status) => return Ok(status),
        },
        1 => match query_table(table, information, length, user)? {
            Ok(result) => result,
            Err(status) => return Ok(status),
        },
        _ => (STATUS_INVALID_INFO_CLASS, 0),
    };
    if return_length != 0 {
        if user {
            if guest::try_write::<u32>(return_length, written).is_err() {
                return Ok(STATUS_ACCESS_VIOLATION);
            }
        } else {
            // SAFETY: PULONG ReturnLength do chamador de modo kernel.
            unsafe { Field::<u32>::at(return_length) }.set(written);
        }
    }
    Ok(status)
}

/// AtomBasicInformation: (status, ReturnLength), ou o status que encerra o
/// serviço sem ReturnLength.
fn query_basic(table: u64, value: u16, information: u64, length: u32, user: bool) -> Result<Result<(u32, u32), u32>, KernelError> {
    if length < BASIC_HEADER {
        return Ok(Err(STATUS_INFO_LENGTH_MISMATCH));
    }
    // O nome vai a um buffer do kernel do tamanho pedido; um nome nunca
    // passa de LONGEST_NAME bytes, então o corte é o mesmo.
    let capacity = (length - BASIC_HEADER).min(LONGEST_NAME);
    let scratch = guest::alloc_bytes(16 + capacity as u64);
    if scratch == 0 {
        return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
    }
    // Zerado inteiro: o que vai ao chamador nunca é memória antiga do pool.
    guest::write_bytes(scratch, &alloc::vec![0u8; 16 + capacity as usize]);
    // SAFETY: células recém-alocadas do kernel.
    let (count, pins, name_length) = unsafe { (Field::<u32>::at(scratch), Field::<u32>::at(scratch + 4), Field::<u32>::at(scratch + 8)) };
    name_length.set(capacity);
    let name = scratch + 16;
    let outputs = atom::QueryOutputs { reference_count: Some(count), pin_count: Some(pins), name, name_length: Some(name_length) };
    let status = atom::query(table, value, &outputs);
    let result = match status {
        Ok(status) if (status as i32) >= 0 => {
            let bytes = name_length.get();
            let mut output: Vec<u8> = Vec::with_capacity(BASIC_HEADER as usize + bytes as usize + 2);
            output.extend_from_slice(&(count.get() as u16).to_le_bytes());
            output.extend_from_slice(&(pins.get() as u16).to_le_bytes());
            output.extend_from_slice(&(bytes as u16).to_le_bytes());
            // O nome e o NUL que o Rtl grava depois dele.
            output.extend_from_slice(&guest::read_bytes(name, (bytes + 2).min(capacity) as usize));
            match write_output(information, &output, user) {
                Ok(()) => Ok(Ok((status, bytes + 8))),
                Err(fault) => Ok(Err(fault)),
            }
        }
        Ok(status) => Ok(Ok((status, BASIC_HEADER))),
        Err(error) => Err(error),
    };
    guest::free_bytes(scratch);
    result
}

/// AtomTableInformation: (status, ReturnLength), ou o status que encerra o
/// serviço sem ReturnLength.
fn query_table(table: u64, information: u64, length: u32, user: bool) -> Result<Result<(u32, u32), u32>, KernelError> {
    if length < TABLE_HEADER {
        return Ok(Err(STATUS_INFO_LENGTH_MISMATCH));
    }
    let Some(list) = atom::list(table, (length - TABLE_HEADER) / 2)? else { return Ok(Ok((STATUS_INVALID_PARAMETER, TABLE_HEADER))) };
    let mut output: Vec<u8> = Vec::with_capacity(TABLE_HEADER as usize + list.atoms.len() * 2);
    output.extend_from_slice(&list.count.to_le_bytes());
    for value in &list.atoms {
        output.extend_from_slice(&value.to_le_bytes());
    }
    if let Err(fault) = write_output(information, &output, user) {
        return Ok(Err(fault));
    }
    let written = if (list.status as i32) >= 0 { list.count * 2 + TABLE_HEADER } else { TABLE_HEADER };
    Ok(Ok((list.status, written)))
}

fn nt_add_atom(name: u64, length: u64, output: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    add_atom(name, length as u32, output, 0)
}

fn nt_add_atom_ex(name: u64, length: u64, output: u64, flags: u64, _rsp: u64) -> Result<u32, KernelError> {
    add_atom(name, length as u32, output, flags as u32)
}

fn nt_find_atom(name: u64, length: u64, output: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    find_atom(name, length as u32, output)
}

fn nt_delete_atom(value: u64, _: u64, _: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    delete_atom(value as u16)
}

fn nt_query_information_atom(value: u64, class: u64, information: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 8) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    query_information(value as u16, class as u32, information, length as u32, state::stack_arg(rsp, 5))
}

/// Os handlers dos serviços de átomos globais.
pub fn register_user_services() {
    state::register_handler("NtAddAtom", nt_add_atom);
    state::register_handler("NtAddAtomEx", nt_add_atom_ex);
    state::register_handler("NtFindAtom", nt_find_atom);
    state::register_handler("NtDeleteAtom", nt_delete_atom);
    state::register_handler("NtQueryInformationAtom", nt_query_information_atom);
}
