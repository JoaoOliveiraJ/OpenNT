//! Controle de acesso do Security Reference Monitor com processos de
//! usuário reais de identidades diferentes: cada processo de teste recebe
//! no token primário um usuário, grupos, nível de integridade e privilégios
//! próprios (como um token de logon), e os serviços Nt rodam como ele.
//!
//! - Criação por nome: A não cria objetos na raiz do namespace
//!   (DIRECTORY_CREATE_OBJECT só do SYSTEM); os testes criam num diretório
//!   em que Everyone pode criar.
//! - Integridade obrigatória: o processo Low do usuário A não abre para
//!   escrita (EVENT_MODIFY_STATE, WRITE_DAC) o evento sem rótulo do processo
//!   Medium de A (o rótulo padrão é Medium com NO_WRITE_UP), abre com
//!   SYNCHRONIZE, e o MAXIMUM_ALLOWED dele é só GenericRead, GenericExecute,
//!   READ_CONTROL e SYNCHRONIZE (0x120001).
//! - OWNER RIGHTS: uma ACE de S-1-3-4 tira do dono os direitos implícitos
//!   (WRITE_DAC negado, MAXIMUM_ALLOWED sem WRITE_DAC).
//! - Herança: um evento criado sem descritor por B num diretório com uma
//!   ACE herdável (inherit-only no diretório) para A recebe a DACL
//!   herdada, com a ACE de A efetiva no evento; A abre, B (o dono) não.
//! - SeTakeOwnershipPrivilege: WRITE_OWNER pedido é concedido pelo
//!   privilégio (o MAXIMUM_ALLOWED não o usa); o NtSetSecurityObject troca o
//!   dono e depois a DACL, e as aberturas seguintes seguem o descritor novo
//!   (o novo dono abre com WRITE_DAC e EVENT_MODIFY_STATE, o antigo não).
//! - Processo: o NtSetSecurityObject no pseudo-handle muda a DACL que o
//!   NtOpenProcess seguinte usa; o handle com PROCESS_QUERY_INFORMATION
//!   ganha PROCESS_QUERY_LIMITED_INFORMATION (PspProcessOpen), o
//!   NtQuerySecurityObject do processo devolve o descritor e outro usuário
//!   é recusado; uma thread aberta com THREAD_QUERY_INFORMATION ganha
//!   THREAD_QUERY_LIMITED_INFORMATION (PspThreadOpen).
//!
//! No código anterior o rótulo padrão não existia (a escrita passava), o
//! dono sempre recebia WRITE_DAC, o MAXIMUM_ALLOWED incluía o WRITE_OWNER
//! do privilégio, nada era herdado, o NtSetSecurityObject só guardava o
//! descritor numa tabela lateral que as aberturas não liam, o
//! NtQuerySecurityObject de um processo devolvia STATUS_NOT_SUPPORTED e os
//! direitos implícitos de processo e thread não existiam.

use alloc::vec::Vec;

use crate::ntos::inc::types::{ClientId, NtStruct, ObjectAttributes, ObjectBasicInformation};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::process;
use crate::ntos::ps::user::{memory, state};
use crate::ntos::se::model::{sid, Ace, Group, Privilege, Sid};
use crate::ntos::se::token::tokens;
use crate::ntos::test::multiprocess::identity::with_test_process;

type Assert = fn(bool, &str);

const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const EVENT_QUERY_STATE: u32 = 0x0001;
const EVENT_MODIFY_STATE: u32 = 0x0002;
const EVENT_ALL_ACCESS: u32 = 0x001F_0003;
const DIRECTORY_ALL_ACCESS: u32 = 0x000F_000F;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const THREAD_QUERY_INFORMATION: u32 = 0x0040;
const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;
const OWNER_SECURITY_INFORMATION: u32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 4;
const OBJECT_INHERIT_ACE: u8 = 0x01;
const CONTAINER_INHERIT_ACE: u8 = 0x02;
const INHERIT_ONLY_ACE: u8 = 0x08;
const LOW_INTEGRITY: u32 = 0x1000;
const MEDIUM_INTEGRITY: u32 = 0x2000;
const SE_TAKE_OWNERSHIP_PRIVILEGE: u64 = 9;
const SE_CHANGE_NOTIFY_PRIVILEGE: u64 = 23;

fn user_a() -> Sid {
    sid(5, &[21, 0x0A11, 0x0B22, 0x0C33, 1001])
}

fn user_b() -> Sid {
    sid(5, &[21, 0x0A11, 0x0B22, 0x0C33, 1002])
}

fn system() -> Sid {
    sid(5, &[18])
}

/// Uma ACE (tipo, flags, máscara, SID) de uma ACL a montar.
type Entry = (u8, u8, u32, Sid);

fn allow(mask: u32, sid: Sid) -> Entry {
    (0, 0, mask, sid)
}

/// SECURITY_DESCRIPTOR_RELATIVE com o dono e a DACL pedidos.
fn relative_descriptor(owner: Option<&Sid>, dacl: Option<&[Entry]>) -> Vec<u8> {
    let mut bytes = alloc::vec![0u8; 20];
    bytes[0] = 1;
    let mut control = 0x8000u16;
    if let Some(entries) = dacl {
        control |= 0x0004;
        let size = 8 + entries.iter().map(|(_, _, _, sid)| 8 + sid.len()).sum::<usize>();
        let at = bytes.len() as u32;
        bytes[16..20].copy_from_slice(&at.to_le_bytes());
        bytes.extend_from_slice(&[2, 0]);
        bytes.extend_from_slice(&(size as u16).to_le_bytes());
        bytes.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&[0, 0]);
        for (kind, flags, mask, sid) in entries {
            bytes.extend_from_slice(&[*kind, *flags]);
            bytes.extend_from_slice(&((8 + sid.len()) as u16).to_le_bytes());
            bytes.extend_from_slice(&mask.to_le_bytes());
            bytes.extend_from_slice(sid);
        }
    }
    if let Some(owner) = owner {
        let at = bytes.len() as u32;
        bytes[4..8].copy_from_slice(&at.to_le_bytes());
        bytes.extend_from_slice(owner);
    }
    bytes[2..4].copy_from_slice(&control.to_le_bytes());
    bytes
}

/// As ACEs (flags, máscara, SID) de uma DACL de um descritor relativo.
fn dacl_entries(descriptor: &[u8]) -> Vec<(u8, u32, Sid)> {
    let offset = u32::from_le_bytes([descriptor[16], descriptor[17], descriptor[18], descriptor[19]]) as usize;
    if offset == 0 || offset + 8 > descriptor.len() {
        return Vec::new();
    }
    let count = u16::from_le_bytes([descriptor[offset + 4], descriptor[offset + 5]]) as usize;
    let mut cursor = offset + 8;
    let mut list = Vec::new();
    for _ in 0..count {
        let size = u16::from_le_bytes([descriptor[cursor + 2], descriptor[cursor + 3]]) as usize;
        let mask = u32::from_le_bytes([descriptor[cursor + 4], descriptor[cursor + 5], descriptor[cursor + 6], descriptor[cursor + 7]]);
        list.push((descriptor[cursor + 1], mask, descriptor[cursor + 8..cursor + size].to_vec()));
        cursor += size;
    }
    list
}

/// O dono de um descritor relativo.
fn owner_of(descriptor: &[u8]) -> Sid {
    let offset = u32::from_le_bytes([descriptor[4], descriptor[5], descriptor[6], descriptor[7]]) as usize;
    if offset == 0 || offset + 8 > descriptor.len() {
        return Vec::new();
    }
    let count = descriptor[offset + 1] as usize;
    descriptor[offset..offset + 8 + 4 * count].to_vec()
}

/// Os serviços Nt de um processo de teste. Cada chamada monta os buffers
/// numa região de usuário própria e a devolve no fim: os processos de teste
/// sem raiz própria dividem a metade de usuário da raiz do System, então um
/// bloco do processo de fora não pode viver enquanto um processo aninhado
/// mapeia e devolve a mesma VA.
struct Calls;

const ATTRIBUTES: u64 = 0x000;
const NAME: u64 = 0x040;
const TEXT: u64 = 0x080;
const DESCRIPTOR: u64 = 0x200;
const HANDLE: u64 = 0x400;
const CLIENT: u64 = 0x420;
const BUFFER: u64 = 0x500;
const RETURNED: u64 = 0x900;
const STACK: u64 = 0x2000;

/// `body` com um bloco de usuário de 0x3000 bytes do processo corrente.
fn with_block<R>(body: impl FnOnce(u64) -> R) -> Option<R> {
    let block = memory::map_user_region(0x3000).ok()?;
    let result = body(block);
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
    Some(result)
}

fn call(block: u64, name: &str, a1: u64, a2: u64, a3: u64, a4: u64) -> u32 {
    state::handler(name).map_or(1, |handler| handler(a1, a2, a3, a4, block + STACK).unwrap_or(1))
}

/// OBJECT_ATTRIBUTES no bloco com o nome (vazio = sem nome) e o descritor.
fn attributes(block: u64, name: &str, descriptor: Option<&[u8]>) -> u64 {
    let attributes = block + ATTRIBUTES;
    guest::write_bytes(attributes, &[0u8; ObjectAttributes::SIZE as usize]);
    // SAFETY: OBJECT_ATTRIBUTES no bloco do processo de teste.
    let object = unsafe { ObjectAttributes::at(attributes) };
    object.length.set(ObjectAttributes::SIZE as u32);
    if !name.is_empty() {
        state::write_user_wide(block + TEXT, name);
        state::write_unicode_string(block + NAME, block + TEXT, name);
        object.object_name.set(block + NAME);
        object.attributes.set(0x40);
    }
    if let Some(descriptor) = descriptor {
        guest::write_bytes(block + DESCRIPTOR, descriptor);
        object.security_descriptor.set(block + DESCRIPTOR);
    }
    attributes
}

/// Um serviço que devolve um handle em block+HANDLE: `Ok(handle)` ou o
/// NTSTATUS.
fn handle_result(block: u64, status: u32) -> Result<u64, u32> {
    match status {
        0 => Ok(guest::read64(block + HANDLE)),
        status => Err(status),
    }
}

impl Calls {
    /// NtCreateEvent de um evento de notificação nomeado.
    fn create_event(&self, name: &str, descriptor: Option<&[u8]>) -> Result<u64, u32> {
        with_block(|block| {
            let attributes = attributes(block, name, descriptor);
            guest::write64(block + STACK + 0x28, 0);
            let status = call(block, "NtCreateEvent", block + HANDLE, EVENT_ALL_ACCESS as u64, attributes, 0);
            if status != 0 {
                crate::debug_print!("[acl] NtCreateEvent({}) -> {:#x}", name, status);
            }
            handle_result(block, status)
        })
        .unwrap_or(Err(1))
    }

    /// NtCreateDirectoryObject com o descritor.
    fn create_directory(&self, name: &str, descriptor: &[u8]) -> Result<u64, u32> {
        with_block(|block| {
            let attributes = attributes(block, name, Some(descriptor));
            handle_result(block, call(block, "NtCreateDirectoryObject", block + HANDLE, DIRECTORY_ALL_ACCESS as u64, attributes, 0))
        })
        .unwrap_or(Err(1))
    }

    /// NtOpenEvent: `Ok(handle)` ou o NTSTATUS.
    fn open_event(&self, name: &str, access: u32) -> Result<u64, u32> {
        with_block(|block| {
            let attributes = attributes(block, name, None);
            handle_result(block, call(block, "NtOpenEvent", block + HANDLE, access as u64, attributes, 0))
        })
        .unwrap_or(Err(1))
    }

    /// O acesso concedido de um handle (ObjectBasicInformation).
    fn granted(&self, handle: u64) -> u32 {
        with_block(|block| {
            guest::write64(block + STACK + 0x28, block + RETURNED);
            if call(block, "NtQueryObject", handle, 0, block + BUFFER, ObjectBasicInformation::SIZE) != 0 {
                return 0;
            }
            // SAFETY: saída recém-escrita no bloco do processo.
            unsafe { ObjectBasicInformation::at(block + BUFFER) }.granted_access.get()
        })
        .unwrap_or(0)
    }

    /// NtOpenEvent com o acesso pedido; o acesso concedido, fechando o handle.
    fn open_granted(&self, name: &str, access: u32) -> Result<u32, u32> {
        let handle = self.open_event(name, access)?;
        let granted = self.granted(handle);
        self.close(handle);
        Ok(granted)
    }

    fn close(&self, handle: u64) {
        with_block(|block| call(block, "NtClose", handle, 0, 0, 0));
    }

    /// NtSetSecurityObject com um descritor relativo.
    fn set_security(&self, handle: u64, information: u32, descriptor: &[u8]) -> u32 {
        with_block(|block| {
            guest::write_bytes(block + DESCRIPTOR, descriptor);
            call(block, "NtSetSecurityObject", handle, information as u64, block + DESCRIPTOR, 0)
        })
        .unwrap_or(1)
    }

    /// NtQuerySecurityObject: o descritor relativo devolvido.
    fn query_security(&self, handle: u64, information: u32) -> Result<Vec<u8>, u32> {
        with_block(|block| {
            guest::write64(block + STACK + 0x28, block + RETURNED);
            match call(block, "NtQuerySecurityObject", handle, information as u64, block + BUFFER, 0x400) {
                0 => Ok(guest::read_bytes(block + BUFFER, guest::read32(block + RETURNED) as usize)),
                status => Err(status),
            }
        })
        .unwrap_or(Err(1))
    }

    /// NtOpenProcess por CLIENT_ID.
    fn open_process(&self, process_id: u64, access: u32) -> Result<u64, u32> {
        with_block(|block| {
            let attributes = attributes(block, "", None);
            // SAFETY: CLIENT_ID no bloco do processo.
            let client = unsafe { ClientId::at(block + CLIENT) };
            client.unique_process.set(process_id);
            client.unique_thread.set(0);
            handle_result(block, call(block, "NtOpenProcess", block + HANDLE, access as u64, attributes, block + CLIENT))
        })
        .unwrap_or(Err(1))
    }
}

/// Executa `body` como um processo de usuário real do usuário `user`, com o
/// nível de integridade `integrity` e os privilégios `privileges` (mais
/// SeChangeNotifyPrivilege), habilitados, no token primário: os grupos
/// Everyone, Users e Authenticated Users, o dono e o grupo primário sendo o
/// usuário, a DACL padrão do usuário e do SYSTEM e a política
/// NO_WRITE_UP.
fn as_identity<R>(name: &str, user: &Sid, integrity: u32, privileges: &[u64], body: impl FnOnce(&Calls, u64) -> R) -> Option<R> {
    with_test_process(name, None, |test| {
        let token = process::get_primary_token(test.process)?;
        tokens::update(token, |token| {
            token.user = user.clone();
            token.user_attributes = 0;
            token.owner = user.clone();
            token.primary_group = user.clone();
            token.groups = alloc::vec![Group { sid: sid(1, &[0]), attributes: 7 }, Group { sid: sid(5, &[32, 545]), attributes: 7 }, Group { sid: sid(5, &[11]), attributes: 7 }];
            token.integrity = sid(16, &[integrity]);
            token.privileges = privileges.iter().chain(core::iter::once(&SE_CHANGE_NOTIFY_PRIVILEGE)).map(|&id| Privilege { id, attributes: 3 }).collect();
            token.default_dacl = Some(alloc::vec![Ace::allow(user.clone(), GENERIC_ALL), Ace::allow(system(), GENERIC_ALL)]);
            token.mandatory_policy = 1;
            token.restricted_sids.clear();
            token.app_container = None;
        })?;
        Some(body(&Calls, test.process_id))
    })
    .flatten()
}

/// Integridade obrigatória e OWNER RIGHTS.
fn integrity_and_owner_rights(assert: Assert) {
    let ran = as_identity("acl-medium.exe", &user_a(), MEDIUM_INTEGRITY, &[], |medium, _| {
        let event = medium.create_event("\\OpenNtAcl\\Medium", None);
        assert(event.is_ok(), "acl: o processo Medium de A cria o evento sem descritor");
        assert(medium.open_granted("\\OpenNtAcl\\Medium", EVENT_MODIFY_STATE) == Ok(EVENT_MODIFY_STATE), "acl: o proprio processo Medium abre para escrita");
        let low = as_identity("acl-low.exe", &user_a(), LOW_INTEGRITY, &[], |low, _| {
            (
                low.open_event("\\OpenNtAcl\\Medium", EVENT_MODIFY_STATE).err(),
                low.open_event("\\OpenNtAcl\\Medium", READ_CONTROL | WRITE_DAC).err(),
                low.open_granted("\\OpenNtAcl\\Medium", SYNCHRONIZE),
                low.open_granted("\\OpenNtAcl\\Medium", MAXIMUM_ALLOWED),
            )
        });
        assert(low.as_ref().is_some_and(|(modify, write_dac, _, _)| *modify == Some(STATUS_ACCESS_DENIED) && *write_dac == Some(STATUS_ACCESS_DENIED)), "acl: o processo Low do mesmo usuario nao abre para escrita (EVENT_MODIFY_STATE, WRITE_DAC) o evento sem rotulo (Medium, NO_WRITE_UP)");
        assert(low.as_ref().is_some_and(|(_, _, synchronize, maximum)| *synchronize == Ok(SYNCHRONIZE) && *maximum == Ok(0x12_0001)), "acl: o Low abre com SYNCHRONIZE e o MAXIMUM_ALLOWED dele e so leitura, execucao, READ_CONTROL e SYNCHRONIZE");
        // OWNER RIGHTS: o dono só tem o que a ACE de S-1-3-4 dá.
        let owner_rights = relative_descriptor(Some(&user_a()), Some(&[allow(READ_CONTROL, sid(3, &[4])), allow(SYNCHRONIZE | EVENT_QUERY_STATE, user_a())]));
        let restricted = medium.create_event("\\OpenNtAcl\\OwnerRights", Some(&owner_rights));
        assert(restricted.is_ok(), "acl: evento com ACE de OWNER RIGHTS criado");
        assert(medium.open_event("\\OpenNtAcl\\OwnerRights", WRITE_DAC).err() == Some(STATUS_ACCESS_DENIED) && medium.open_granted("\\OpenNtAcl\\OwnerRights", MAXIMUM_ALLOWED) == Ok(READ_CONTROL | SYNCHRONIZE | EVENT_QUERY_STATE), "acl: a ACE de OWNER RIGHTS tira do dono o WRITE_DAC implicito (aberto e no MAXIMUM_ALLOWED)");
        for handle in [event, restricted].into_iter().flatten() {
            medium.close(handle);
        }
    });
    assert(ran.is_some(), "acl: processos Medium e Low");
}

/// Herança das ACEs de um diretório para um objeto nomeado novo.
fn directory_inheritance(assert: Assert) {
    let ran = as_identity("acl-dir.exe", &system(), 0x4000, &[], |owner, _| {
        let directory_descriptor = relative_descriptor(None, Some(&[(0, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, GENERIC_ALL, system()), (0, OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE, EVENT_ALL_ACCESS, user_a()), allow(0x0007, sid(1, &[0]))]));
        let directory = owner.create_directory("\\OpenNtAcl\\Inherit", &directory_descriptor);
        assert(directory.is_ok(), "acl: diretorio com ACE herdavel para A");
        let inner = as_identity("acl-b.exe", &user_b(), MEDIUM_INTEGRITY, &[], |b, _| {
            let child = b.create_event("\\OpenNtAcl\\Inherit\\Filho", None);
            let dacl = child.ok().and_then(|handle| b.query_security(handle, DACL_SECURITY_INFORMATION).ok()).map(|descriptor| dacl_entries(&descriptor)).unwrap_or_default();
            let a_opens = as_identity("acl-a.exe", &user_a(), MEDIUM_INTEGRITY, &[], |a, _| a.open_granted("\\OpenNtAcl\\Inherit\\Filho", EVENT_MODIFY_STATE));
            let b_opens = b.open_event("\\OpenNtAcl\\Inherit\\Filho", EVENT_MODIFY_STATE).err();
            if let Ok(handle) = child {
                b.close(handle);
            }
            (child.is_ok(), dacl, a_opens, b_opens)
        });
        let Some((child_created, dacl, a_opens, b_opens)) = inner else {
            assert(false, "acl: processo de B");
            return;
        };
        assert(child_created, "acl: B cria o evento no diretorio sem descritor");
        let inherited_a = dacl.iter().any(|(flags, mask, sid)| *sid == user_a() && flags & INHERIT_ONLY_ACE == 0 && *mask == EVENT_ALL_ACCESS);
        let has_b = dacl.iter().any(|(_, _, sid)| *sid == user_b());
        assert(inherited_a && !has_b, "acl: a DACL do evento e a herdada do diretorio (a ACE herdavel de A, efetiva no evento), nao a padrao de B");
        assert(a_opens == Some(Ok(EVENT_MODIFY_STATE)) && b_opens == Some(STATUS_ACCESS_DENIED), "acl: A abre o evento pela ACE herdada; B, o dono, nao");
        if let Ok(directory) = directory {
            owner.close(directory);
        }
    });
    assert(ran.is_some(), "acl: processo do diretorio");
}

/// SeTakeOwnershipPrivilege e o NtSetSecurityObject que muda as aberturas.
fn take_ownership(assert: Assert) {
    let ran = as_identity("acl-dono.exe", &user_a(), MEDIUM_INTEGRITY, &[], |a, _| {
        let descriptor = relative_descriptor(Some(&user_a()), Some(&[allow(EVENT_ALL_ACCESS, user_a())]));
        let event = a.create_event("\\OpenNtAcl\\Take", Some(&descriptor));
        assert(event.is_ok(), "acl: evento de A so com a ACE de A");
        let without = as_identity("acl-b-sem.exe", &user_b(), MEDIUM_INTEGRITY, &[], |b, _| b.open_event("\\OpenNtAcl\\Take", WRITE_OWNER).err());
        assert(without == Some(Some(STATUS_ACCESS_DENIED)), "acl: B sem SeTakeOwnershipPrivilege nao abre com WRITE_OWNER");
        let taker = as_identity("acl-b-tomador.exe", &user_b(), MEDIUM_INTEGRITY, &[SE_TAKE_OWNERSHIP_PRIVILEGE], |b, _| {
            let maximum = b.open_event("\\OpenNtAcl\\Take", MAXIMUM_ALLOWED).err();
            let owner_handle = b.open_event("\\OpenNtAcl\\Take", WRITE_OWNER);
            let granted_owner = owner_handle.map(|handle| b.granted(handle));
            let set_owner = owner_handle.map(|handle| b.set_security(handle, OWNER_SECURITY_INFORMATION, &relative_descriptor(Some(&user_b()), None)));
            let dac_handle = b.open_event("\\OpenNtAcl\\Take", WRITE_DAC | READ_CONTROL);
            let set_dacl = dac_handle.map(|handle| b.set_security(handle, DACL_SECURITY_INFORMATION, &relative_descriptor(None, Some(&[allow(EVENT_ALL_ACCESS, user_b())]))));
            let owner_now = dac_handle.ok().and_then(|handle| b.query_security(handle, OWNER_SECURITY_INFORMATION).ok()).map(|descriptor| owner_of(&descriptor));
            let modify = b.open_granted("\\OpenNtAcl\\Take", EVENT_MODIFY_STATE);
            for handle in [owner_handle, dac_handle].into_iter().flatten() {
                b.close(handle);
            }
            (maximum, granted_owner, set_owner, dac_handle.is_ok(), set_dacl, owner_now, modify)
        });
        let Some((maximum, granted_owner, set_owner, dac_opened, set_dacl, owner_now, modify)) = taker else {
            assert(false, "acl: processo de B com SeTakeOwnershipPrivilege");
            return;
        };
        assert(maximum == Some(STATUS_ACCESS_DENIED) && granted_owner == Ok(WRITE_OWNER), "acl: SeTakeOwnershipPrivilege concede o WRITE_OWNER pedido, nao no MAXIMUM_ALLOWED");
        assert(set_owner == Ok(0) && dac_opened && owner_now == Some(user_b()), "acl: o NtSetSecurityObject troca o dono e o novo dono abre em seguida com WRITE_DAC");
        assert(set_dacl == Ok(0) && modify == Ok(EVENT_MODIFY_STATE), "acl: a DACL trocada pelo NtSetSecurityObject vale na abertura seguinte");
        assert(a.open_event("\\OpenNtAcl\\Take", EVENT_MODIFY_STATE).err() == Some(STATUS_ACCESS_DENIED), "acl: o antigo dono perde o acesso depois da troca da DACL");
        if let Ok(handle) = event {
            a.close(handle);
        }
    });
    assert(ran.is_some(), "acl: processo de A");
}

/// O descritor do processo e os direitos implícitos de processo e thread.
fn process_and_thread(assert: Assert) {
    let ran = as_identity("acl-processo.exe", &user_a(), MEDIUM_INTEGRITY, &[], |a, process_id| {
        let before = a.open_process(process_id, PROCESS_QUERY_INFORMATION).err();
        let descriptor = relative_descriptor(None, Some(&[allow(GENERIC_ALL, user_a()), allow(GENERIC_ALL, system())]));
        let set = a.set_security(u64::MAX, DACL_SECURITY_INFORMATION, &descriptor);
        let opened = a.open_process(process_id, PROCESS_QUERY_INFORMATION);
        let granted = opened.map(|handle| a.granted(handle));
        let reader = a.open_process(process_id, READ_CONTROL);
        let queried = reader.ok().and_then(|handle| a.query_security(handle, DACL_SECURITY_INFORMATION).ok()).map(|descriptor| dacl_entries(&descriptor));
        for handle in [opened, reader].into_iter().flatten() {
            a.close(handle);
        }
        assert(before == Some(STATUS_ACCESS_DENIED) && set == 0 && opened.is_ok(), "acl: o NtSetSecurityObject no pseudo-handle muda a DACL que o NtOpenProcess seguinte usa");
        assert(granted == Ok(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION), "acl: PROCESS_QUERY_INFORMATION implica PROCESS_QUERY_LIMITED_INFORMATION no handle (PspProcessOpen)");
        assert(queried.is_some_and(|dacl| dacl.iter().any(|(_, mask, sid)| *sid == user_a() && *mask == 0x1F_FFFF)), "acl: o NtQuerySecurityObject do processo devolve a DACL com o GENERIC_ALL mapeado");
        let other = as_identity("acl-outro.exe", &user_b(), MEDIUM_INTEGRITY, &[], |b, _| (b.open_process(process_id, PROCESS_QUERY_LIMITED_INFORMATION).err(), b.open_process(process_id, MAXIMUM_ALLOWED).err()));
        assert(other == Some((Some(STATUS_ACCESS_DENIED), Some(STATUS_ACCESS_DENIED))), "acl: outro usuario nao abre o processo (pedido explicito e MAXIMUM_ALLOWED)");
        // A thread corrente por ponteiro (ObOpenObjectByPointer em KernelMode).
        let output = guest::alloc_bytes(8);
        let thread_type = crate::ntos::ob::object_types::thread_type().pointer;
        let status = crate::ntos::test::phase6::call_export("ObOpenObjectByPointer", &[process::get_current_thread(), 0, 0, THREAD_QUERY_INFORMATION as u64, thread_type, 0, output]);
        let thread_handle = guest::read64(output);
        guest::free_bytes(output);
        let basic = guest::alloc_bytes(ObjectBasicInformation::SIZE);
        let queried = status == Some(0) && crate::ntos::ob::query_object::query(thread_handle, 0, basic, ObjectBasicInformation::SIZE as u32, 0).ok() == Some(0);
        // SAFETY: saída recém-escrita pelo ZwQueryObject.
        let thread_granted = unsafe { ObjectBasicInformation::at(basic) }.granted_access.get();
        guest::free_bytes(basic);
        if status == Some(0) {
            let _ = crate::ntos::ob::handles::inserted::close(thread_handle, 0);
        }
        assert(queried && thread_granted == THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, "acl: THREAD_QUERY_INFORMATION implica THREAD_QUERY_LIMITED_INFORMATION no handle (PspThreadOpen)");
    });
    assert(ran.is_some(), "acl: processo de A para o descritor do processo");
}

/// Um evento do ZwCreateEvent de modo kernel (OBJ_KERNEL_HANDLE, com o
/// nome e o descritor pedidos) e o KEVENT retido; `None` na falha.
fn kernel_event(name: &str, descriptor: Option<&[u8]>) -> Option<(u64, u64)> {
    use crate::ntos::inc::types::UnicodeString;
    let block = guest::alloc_bytes(0x400);
    if block == 0 {
        return None;
    }
    guest::write_bytes(block, &[0u8; 0x400]);
    // SAFETY: OBJECT_ATTRIBUTES e UNICODE_STRING no bloco de kernel recém-alocado.
    let (object, text) = unsafe { (ObjectAttributes::at(block), UnicodeString::at(block + 0x40)) };
    object.length.set(ObjectAttributes::SIZE as u32);
    object.attributes.set(0x240);
    if !name.is_empty() {
        let units: Vec<u8> = name.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
        guest::write_bytes(block + 0x100, &units);
        text.length.set(units.len() as u16);
        text.maximum_length.set(units.len() as u16);
        text.buffer.set(block + 0x100);
        object.object_name.set(text.address());
    }
    if let Some(descriptor) = descriptor {
        guest::write_bytes(block + 0x200, descriptor);
        object.security_descriptor.set(block + 0x200);
    }
    let created = crate::ntos::ex::event::create(block + 0x380, EVENT_ALL_ACCESS, block, 0, false).ok() == Some(0);
    let handle = guest::read64(block + 0x380);
    let event_type = crate::ntos::ob::object_types::event_type().pointer;
    let referenced = created && crate::ntos::ob::object_reference::reference_by_handle(handle, 0, event_type, 0, block + 0x388, 0).ok() == Some(0);
    let pointer = guest::read64(block + 0x388);
    guest::free_bytes(block);
    if !referenced {
        if created {
            let _ = crate::ntos::ob::close::close(handle, Some(0));
        }
        return None;
    }
    Some((handle, pointer))
}

/// ObOpenObjectByPointer(evento, 0, NULL, SYNCHRONIZE | EVENT_MODIFY_STATE,
/// ExEventObjectType, UserMode) no processo corrente (o
/// DxgkGetDWMVerticalBlankEvent do dxgkrnl): o status, fechando o handle.
fn open_for_user(calls: &Calls, pointer: u64) -> u32 {
    let output = guest::alloc_bytes(8);
    let event_type = crate::ntos::ob::object_types::event_type().pointer;
    let status = crate::ntos::ob::open_pointer::open(pointer, 0, 0, SYNCHRONIZE | EVENT_MODIFY_STATE, event_type, 1, output).unwrap_or(1);
    if status == 0 {
        calls.close(guest::read64(output));
    }
    guest::free_bytes(output);
    status
}

/// Objetos sem descritor (o ObInsertObjectEx do 19041): o evento sem nome
/// e sem descritor que o SYSTEM cria com o ZwCreateEvent (o da vertical
/// blank do dxgkrnl) abre por ponteiro em UserMode para A sem SeAccessCheck;
/// com descritor explícito (que o ZwCreateEvent passa adiante) ou com nome
/// (a DACL padrão do criador), a abertura é checada e A é recusado.
fn kernel_events_without_descriptor(assert: Assert) {
    let only_system = relative_descriptor(Some(&system()), Some(&[allow(EVENT_ALL_ACCESS, system())]));
    let events = [kernel_event("", None), kernel_event("", Some(only_system.as_slice())), kernel_event("\\OpenNtAcl\\KernelNamed", None)];
    assert(events.iter().all(Option::is_some), "acl: o SYSTEM cria os eventos de kernel (sem nome, com descritor explicito e nomeado)");
    let pointers = events.map(|event| event.map_or(0, |(_, pointer)| pointer));
    let unnamed = crate::ntos::ob::objects::dispatcher::has_descriptor(pointers[0]);
    let explicit = crate::ntos::ob::objects::dispatcher::has_descriptor(pointers[1]);
    let named = crate::ntos::ob::objects::dispatcher::has_descriptor(pointers[2]);
    assert(!unnamed && explicit && named, "acl: so o evento sem nome e sem descritor fica sem descritor");
    let opened = as_identity("acl-vblank.exe", &user_a(), MEDIUM_INTEGRITY, &[], |a, _| pointers.map(|pointer| if pointer != 0 { open_for_user(a, pointer) } else { 1 }));
    assert(
        opened == Some([0, STATUS_ACCESS_DENIED, STATUS_ACCESS_DENIED]),
        "acl: ObOpenObjectByPointer UserMode de A abre o evento sem descritor e e recusado no de descritor explicito e no nomeado",
    );
    for (handle, pointer) in events.into_iter().flatten() {
        let _ = crate::ntos::ob::close::close(handle, Some(0));
        let _ = crate::ntos::ob::object_reference::dereference_with_tag(pointer, 0, false);
    }
}

pub fn run(assert: Assert) {
    // O diretório dos testes, em que Everyone pode criar (a raiz só deixa o
    // SYSTEM criar), aberto pelo processo do SYSTEM durante os testes.
    let ran = as_identity("acl-raiz.exe", &system(), 0x4000, &[], |root, _| {
        let descriptor = relative_descriptor(None, Some(&[allow(DIRECTORY_ALL_ACCESS, sid(1, &[0]))]));
        let directory = root.create_directory("\\OpenNtAcl", &descriptor);
        assert(directory.is_ok(), "acl: diretorio dos testes criado pelo SYSTEM");
        let denied = as_identity("acl-sem-criacao.exe", &user_a(), MEDIUM_INTEGRITY, &[], |a, _| a.create_event("\\OpenNtAclRaiz", None).err());
        assert(denied == Some(Some(STATUS_ACCESS_DENIED)), "acl: A nao cria objetos na raiz (DIRECTORY_CREATE_OBJECT so do SYSTEM)");
        integrity_and_owner_rights(assert);
        directory_inheritance(assert);
        take_ownership(assert);
        process_and_thread(assert);
        kernel_events_without_descriptor(assert);
        if let Ok(directory) = directory {
            root.close(directory);
        }
    });
    assert(ran.is_some(), "acl: processo do SYSTEM com o diretorio dos testes");
}
