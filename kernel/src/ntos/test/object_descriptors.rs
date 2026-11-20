//! Autotestes do descritor de segurança dos objetos de despacho como o
//! ntoskrnl 19041 o guarda (`ob/objects/dispatcher.rs`,
//! `ob/shared_policy.rs`):
//!
//! - um evento sem nome criado sem descritor não guarda descritor nenhum (o
//!   atalho do ObInsertObjectEx, 0x6521bd, sem SeAssignSecurity): o
//!   NtQuerySecurityObject devolve o descritor vazio de 0x14 bytes
//!   (SeQuerySecurityDescriptorInfo, 0x6de652), o NtSetSecurityObject dá
//!   STATUS_NO_SECURITY_ON_OBJECT (SeSetSecurityDescriptorInfoEx, 0x695cfa)
//!   e o SecurityDescriptorSize do ObjectBasicInformation é zero mesmo com
//!   READ_CONTROL (NtQueryObject, 0x70fd86);
//! - descritores iguais dividem uma cópia contada, como as entradas do
//!   ObLogSecurityDescriptor (0x6d8b90): dois objetos nomeados pelo mesmo
//!   sujeito apontam a mesma cópia, um descritor diferente separa os dois e
//!   a cópia sai da tabela com o último objeto que a usa;
//! - 256 pacotes de espera sem nome (o TP_WAIT da ntdll) não guardam
//!   descritor e custam menos de 1200 bytes de heap cada (com a política
//!   guardada eram uns 1700).

use alloc::vec;
use alloc::vec::Vec;

use crate::hal::kmalloc;
use crate::ntos::inc::types::{NtStruct, ObjectBasicInformation, SecurityDescriptorRelative};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::objects::dispatcher::{self as dispatcher_objects, DispatcherHooks, UserDispatcher};
use crate::ntos::ob::shared_policy;
use crate::ntos::ps::user::{memory, state};
use crate::ntos::se::model::{sid, Ace, SecurityPolicy};
use crate::ntos::test::multiprocess::identity::with_test_process;

type Assert = fn(bool, &str);

const STATUS_SUCCESS: u32 = 0;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_NO_SECURITY_ON_OBJECT: u32 = 0xC000_00D7;
/// OWNER, GROUP e DACL_SECURITY_INFORMATION.
const OWNER_GROUP_DACL: u64 = 7;
const DACL_SECURITY_INFORMATION: u64 = 4;
const READ_CONTROL: u32 = 0x2_0000;
/// Pacotes de espera da medida do custo por objeto.
const PACKETS: usize = 256;
/// Teto do heap do kernel por pacote de espera sem nome.
const PACKET_HEAP_LIMIT: usize = 1200;

pub fn run(assert: Assert) {
    let ran = with_test_process("descritor.exe", None, |_| run_in(assert));
    assert(ran.is_some(), "descritores: processo de usuario do teste");
}

fn dispose(pointer: u64) {
    guest::free_bytes(pointer);
}

/// Um evento de kernel registrado sem nome e sem descritor.
fn kernel_event() -> u64 {
    let event = guest::alloc_bytes(0x18);
    if event == 0 {
        return 0;
    }
    dispatcher::initialize_event(event, 0, false);
    if dispatcher_objects::create(event, "event", dispose, None, 0, false, DispatcherHooks::default()).is_err() {
        guest::free_bytes(event);
        return 0;
    }
    event
}

fn run_in(assert: Assert) {
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "descritores: memoria de usuario");
        return;
    };
    let (out, needed, buffer, descriptor, rsp) = (block, block + 0x40, block + 0x100, block + 0x400, block + 0x1000);
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map(|handler| handler(a1, a2, a3, a4, rsp).unwrap_or(1)).unwrap_or(1);
    let body_of = |handle: u64| state::get_user_handle(handle).and_then(|entry| entry.downcast::<UserDispatcher>().map(|dispatcher| dispatcher.pointer)).unwrap_or(0);

    // O evento sem nome criado sem descritor.
    guest::write64(rsp + 0x28, 0);
    let created = call("NtCreateEvent", out, 0x1F_0003, 0, 0) == STATUS_SUCCESS;
    let event = guest::read64(out);
    let pointer = body_of(event);
    assert(created && pointer != 0 && !dispatcher_objects::has_descriptor(pointer) && dispatcher_objects::security(pointer).is_none(), "descritores: o evento sem nome criado sem descritor nao guarda descritor");
    guest::write64(rsp + 0x28, needed);
    let queried = call("NtQuerySecurityObject", event, OWNER_GROUP_DACL, buffer, 0x100) == STATUS_SUCCESS && guest::read32(needed) == 0x14;
    // SAFETY: buffer de usuário do teste com o descritor devolvido.
    let relative = unsafe { SecurityDescriptorRelative::at(buffer) };
    let empty = relative.revision.get() == 1 && relative.control.get() == 0x8000 && relative.owner.get() == 0 && relative.group.get() == 0 && relative.dacl.get() == 0 && relative.sacl.get() == 0;
    let short = call("NtQuerySecurityObject", event, OWNER_GROUP_DACL, buffer, 8) == STATUS_BUFFER_TOO_SMALL && guest::read32(needed) == 0x14;
    assert(queried && empty && short, "descritores: NtQuerySecurityObject sem descritor devolve o descritor vazio de 0x14 bytes");
    // Revision 1, SE_SELF_RELATIVE | SE_DACL_PRESENT, DACL nula.
    guest::write_bytes(descriptor, &[0u8; 0x14]);
    // SAFETY: bloco de usuário do teste.
    let explicit = unsafe { SecurityDescriptorRelative::at(descriptor) };
    explicit.revision.set(1);
    explicit.control.set(0x8004);
    assert(call("NtSetSecurityObject", event, DACL_SECURITY_INFORMATION, descriptor, 0) == STATUS_NO_SECURITY_ON_OBJECT && dispatcher_objects::security(pointer).is_none(), "descritores: NtSetSecurityObject sem descritor da STATUS_NO_SECURITY_ON_OBJECT");
    guest::write64(rsp + 0x28, needed);
    let basic = call("NtQueryObject", event, 0, buffer, ObjectBasicInformation::SIZE) == STATUS_SUCCESS && {
        // SAFETY: buffer de usuário do teste com a ObjectBasicInformation.
        let information = unsafe { ObjectBasicInformation::at(buffer) };
        information.granted_access.get() & READ_CONTROL != 0 && information.security_descriptor_size.get() == 0
    };
    assert(basic, "descritores: SecurityDescriptorSize zero sem descritor, mesmo com READ_CONTROL");
    let _ = call("NtClose", event, 0, 0, 0);

    // Descritores iguais dividem a cópia.
    let (first, second, third) = (kernel_event(), kernel_event(), kernel_event());
    assert(first != 0 && second != 0 && third != 0 && !dispatcher_objects::has_descriptor(first), "descritores: tres eventos de kernel sem descritor");
    dispatcher_objects::mark_named(first);
    dispatcher_objects::mark_named(second);
    assert(dispatcher_objects::has_descriptor(first) && dispatcher_objects::same_security(first, second), "descritores: dois objetos nomeados pelo mesmo sujeito dividem a copia do descritor");
    // Uma política que ninguém mais usa: um SID de domínio próprio do teste.
    let owner = sid(5, &[21, 0x4F70_656E, 0x4E54_4465, 0x7363_7269, 1001]);
    let unique = SecurityPolicy { owner: owner.clone(), group: Some(owner.clone()), dacl: Some(vec![Ace::allow(owner, 0x1F_0003)]), ..SecurityPolicy::default() };
    dispatcher_objects::set_security(second, unique.clone());
    dispatcher_objects::set_security(third, unique.clone());
    let split = !dispatcher_objects::same_security(first, second) && dispatcher_objects::same_security(second, third) && shared_policy::copies_of(&unique) == 1 && dispatcher_objects::security(third).as_ref() == Some(&unique);
    assert(split, "descritores: um descritor diferente separa os objetos e o igual volta a dividir");
    dispatcher_objects::collect(second);
    let kept = shared_policy::copies_of(&unique) == 1;
    dispatcher_objects::collect(third);
    dispatcher_objects::collect(first);
    assert(kept && shared_policy::copies_of(&unique) == 0, "descritores: a copia sai da tabela com o ultimo objeto que a usa");

    // O custo de um pacote de espera sem nome.
    let before = kmalloc::info().1;
    let mut handles = Vec::with_capacity(PACKETS);
    for _ in 0..PACKETS {
        if call("NtCreateWaitCompletionPacket", out, 0xF_0001, 0, 0) != STATUS_SUCCESS {
            break;
        }
        handles.push(guest::read64(out));
    }
    let after = kmalloc::info().1;
    let unprotected = handles.iter().all(|&handle| !dispatcher_objects::has_descriptor(body_of(handle)));
    let per_packet = after.saturating_sub(before) / PACKETS;
    crate::debug_print!("[descritores] {} pacotes de espera sem nome: heap {} -> {} bytes, {} bytes por pacote", handles.len(), before, after, per_packet);
    for handle in &handles {
        let _ = call("NtClose", *handle, 0, 0, 0);
    }
    assert(handles.len() == PACKETS && unprotected, "descritores: os pacotes de espera sem nome nao guardam descritor");
    assert(per_packet < PACKET_HEAP_LIMIT, "descritores: um pacote de espera sem nome custa menos de 1200 bytes de heap");
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}
