//! Autoteste dos argumentos BOOLEAN dos serviços de modo usuário (fase 7,
//! no contexto dos outros testes de serviços): o compilador grava um
//! BOOLEAN com um `mov byte` (na pilha) ou num registrador de byte (`mov
//! r8b, 1`, `setcc`), e o resto da posição é o que já estava lá. O serviço
//! do NT só testa o byte baixo.
//!
//! - os auxiliares `state::boolean` (registrador) e `state::stack_boolean`
//!   (pilha) leem só o byte baixo;
//! - NtCreateMutant com o InitialOwner (registrador) 0x...00 cria o mutante
//!   livre e com 0x...01 o cria possuído pela thread;
//! - NtCreateEvent com o InitialState (quinto argumento, na pilha) 0x...00
//!   cria o evento não sinalizado e com 0x...01, sinalizado;
//! - NtQueryDirectoryFile com o RestartScan (11.º argumento, na pilha)
//!   0x...00 não recomeça a enumeração: as entradas que a primeira chamada
//!   já entregou não voltam, e a seguinte acaba em STATUS_NO_MORE_FILES.

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user::{memory, state};

type Assert = fn(bool, &str);

const MUTANT_ALL_ACCESS: u64 = 0x1F_0001;
const EVENT_ALL_ACCESS: u64 = 0x1F_0003;
/// O lixo das posições: tudo ligado fora do byte baixo.
const GARBAGE: u64 = 0xDEAD_BEEF_CAFE_0000 | 0xFF00;

pub fn run(assert: Assert) {
    assert(!state::boolean(GARBAGE) && state::boolean(GARBAGE | 1) && state::boolean(1) && !state::boolean(0), "boolean: registrador pelo byte baixo");
    let Ok(user) = memory::map_user_region(0x1000) else {
        assert(false, "boolean: memoria de usuario");
        return;
    };
    let (out, rsp) = (user, user + 0x800);
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map(|handler| handler(a1, a2, a3, a4, rsp).unwrap_or(1)).unwrap_or(0xC000_0002);
    // A pilha: o quinto argumento em rsp + 0x28.
    guest::write64(rsp + 0x28, GARBAGE);
    let stack = !state::stack_boolean(rsp, 5) && {
        guest::write64(rsp + 0x28, GARBAGE | 1);
        state::stack_boolean(rsp, 5)
    };
    assert(stack, "boolean: pilha pelo byte baixo (state::stack_boolean)");
    let mut handles = alloc::vec::Vec::new();
    let info = user + 0x40;
    // NtCreateMutant: InitialOwner no quarto registrador; o estado pelo
    // NtQueryMutant (MutantBasicInformation: CurrentCount e OwnedByCaller).
    let mut mutant = |owner: u64| {
        if call("NtCreateMutant", out, MUTANT_ALL_ACCESS, 0, owner) != 0 {
            return None;
        }
        let handle = guest::read64(out);
        handles.push(handle);
        guest::write64(rsp + 0x28, 0);
        (call("NtQueryMutant", handle, 0, info, 8) == 0).then(|| (guest::read32(info) as i32, guest::read8(info + 4)))
    };
    let mutants = mutant(GARBAGE) == Some((1, 0)) && mutant(GARBAGE | 1) == Some((0, 1));
    assert(mutants, "boolean: NtCreateMutant com lixo acima do byte do InitialOwner");
    // NtCreateEvent: InitialState na pilha (NotificationEvent); o estado
    // pelo NtQueryEvent (EventBasicInformation: EventType e EventState).
    let mut event = |initial: u64| {
        guest::write64(rsp + 0x28, initial);
        if call("NtCreateEvent", out, EVENT_ALL_ACCESS, 0, 0) != 0 {
            return None;
        }
        let handle = guest::read64(out);
        handles.push(handle);
        guest::write64(rsp + 0x28, 0);
        (call("NtQueryEvent", handle, 0, info, 8) == 0).then(|| guest::read32(info + 4) as i32)
    };
    let events = event(GARBAGE) == Some(0) && event(GARBAGE | 1) == Some(1);
    assert(events, "boolean: NtCreateEvent com lixo acima do byte do InitialState (pilha)");
    let scan = directory_scan(user, rsp, &call, &mut handles);
    assert(scan, "boolean: NtQueryDirectoryFile com lixo acima do byte do RestartScan nao recomeca");
    for handle in handles {
        let _ = call("NtClose", handle, 0, 0, 0);
    }
    if let Some(region) = memory::find_region(user) {
        memory::release_private_region(&region);
    }
}

/// Abre a raiz do volume de dados (D:) e enumera com o RestartScan 0x...00: a segunda
/// chamada continua de onde a primeira parou (nenhuma entrada repetida) e a
/// enumeração acaba em STATUS_NO_MORE_FILES.
fn directory_scan(user: u64, rsp: u64, call: &dyn Fn(&str, u64, u64, u64, u64) -> u32, handles: &mut alloc::vec::Vec<u64>) -> bool {
    use crate::ntos::inc::field::NtStruct;
    use crate::ntos::inc::types::ObjectAttributes;
    let (out, iosb, attributes, string, text, buffer) = (user, user + 0x10, user + 0x40, user + 0x80, user + 0xA0, user + 0x100);
    let path = "\\??\\D:\\";
    state::write_user_wide(text, path);
    state::write_unicode_string(string, text, path);
    // SAFETY: OBJECT_ATTRIBUTES na região de usuário do teste.
    let object = unsafe { ObjectAttributes::at(attributes) };
    object.length.set(ObjectAttributes::SIZE as u32);
    object.root_directory.set(0);
    object.object_name.set(string);
    object.attributes.set(0x40);
    object.security_descriptor.set(0);
    object.security_quality_of_service.set(0);
    // NtOpenFile(out, FILE_LIST_DIRECTORY | SYNCHRONIZE, oa, iosb, share,
    // FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT).
    guest::write64(rsp + 0x28, 7);
    guest::write64(rsp + 0x30, 0x21);
    if call("NtOpenFile", out, 0x10_0001, attributes, iosb) != 0 {
        return false;
    }
    let handle = guest::read64(out);
    handles.push(handle);
    // NtQueryDirectoryFile(handle, 0, 0, 0, iosb, buffer, 0x200,
    // FileNamesInformation, ReturnSingleEntry, FileName NULL, RestartScan):
    // uma entrada por chamada.
    let query = |single: u64, restart: u64| {
        guest::write64(rsp + 0x28, iosb);
        guest::write64(rsp + 0x30, buffer);
        guest::write64(rsp + 0x38, 0x200);
        guest::write64(rsp + 0x40, 12);
        guest::write64(rsp + 0x48, single);
        guest::write64(rsp + 0x50, 0);
        guest::write64(rsp + 0x58, restart);
        let status = call("NtQueryDirectoryFile", handle, 0, 0, 0);
        // FILE_NAMES_INFORMATION: o nome em +12, o tamanho em +8.
        let length = guest::read32(buffer + 8).min(0x1F0) as usize;
        (status, guest::read_bytes(buffer + 12, length))
    };
    let (first_status, first) = query(GARBAGE | 1, GARBAGE | 1);
    let mut seen = alloc::vec![first];
    let mut finished = false;
    for _ in 0..4096 {
        let (status, name) = query(GARBAGE | 1, GARBAGE);
        if status == 0x8000_0006 {
            finished = true;
            break;
        }
        if status != 0 || seen.contains(&name) {
            return false;
        }
        seen.push(name);
    }
    first_status == 0 && finished && seen.len() > 1
}
