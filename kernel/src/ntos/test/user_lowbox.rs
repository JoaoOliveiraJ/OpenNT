//! Autoteste do token LowBox (AppContainer) pelos serviços de modo usuário,
//! contra o NtCreateLowBoxToken, o SepAccessCheck e o SeSubProcessToken do
//! ntoskrnl 19041:
//!
//! - o NtCreateLowBoxToken de um token que descende do System (com
//!   TOKEN_NOT_LOW, na sessão 0): o pacote, as capacidades, o número LowBox
//!   da sessão, o rótulo Low com NO_WRITE_UP, só o SeChangeNotifyPrivilege e
//!   o SeIncreaseWorkingSetPrivilege, a ACE do pacote na DACL padrão, o
//!   TOKEN_LOWBOX sem o TOKEN_NOT_LOW, e os handles guardados (o diretório
//!   do pacote, o `RPC Control` dele e o link `Global`), que seguram os
//!   nomes depois de quem chama fechar os dele;
//! - o mesmo pacote divide o número e a entrada de handles; outro pacote
//!   ganha outro número;
//! - as recusas do NtCreateLowBoxToken, na ordem das checagens do NT;
//! - o pai LowBox: impersonando o LowBox, só um pacote filho passa;
//! - o passe LowBox da checagem de acesso: a ACE de ALL APPLICATION PACKAGES,
//!   do pacote, de uma capacidade ou de ALL RESTRICTED APPLICATION PACKAGES
//!   concede, uma ACE de negação para eles não conta, e quem não é LowBox
//!   não passa por ele;
//! - o TokenIntegrityLevel de Medium para cima desfaz o LowBox e larga o
//!   número; o SeSubProcessToken leva o número na mesma sessão e um novo na
//!   outra;
//! - fechados os tokens, o número e a entrada de handles somem e os nomes
//!   do pacote também.

use alloc::vec;
use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager;
use crate::ntos::ps::process;
use crate::ntos::ps::user::{memory, state};
use crate::ntos::se::access_evaluation::{access_check, Subject};
use crate::ntos::se::policy_descriptor::OwnedDescriptor;
use crate::ntos::se::token::handles::UserToken;
use crate::ntos::se::token::lowbox::{self, HandlesKey};
use crate::ntos::se::token::{thread as thread_tokens, tokens};
use crate::ntos::test::multiprocess::identity::with_test_process;

type Assert = fn(bool, &str);

/// O mapeamento genérico dos arquivos (FILE_GENERIC_READ, WRITE, EXECUTE,
/// FILE_ALL_ACCESS).
const FILE_MAPPING: [u32; 4] = [0x12_0089, 0x12_0116, 0x12_00A0, 0x1F_01FF];
const FILE_ALL: u32 = 0x1F_01FF;
const READ_EXECUTE: u32 = 0x12_00A9;
const FILE_READ: u32 = 0x12_0089;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const WRITE_DAC: u32 = 0x4_0000;
const PACKAGE_PATH: &str = "\\Sessions\\0\\AppContainerNamedObjects\\S-1-15-2-1-2-3-4-5-6-7";

/// SID com a autoridade e as subautoridades dadas.
fn sid(authority: u8, sub_authorities: &[u32]) -> Vec<u8> {
    let mut bytes = vec![1, sub_authorities.len() as u8, 0, 0, 0, 0, 0, authority];
    for value in sub_authorities {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

/// ACE simples (tipo, máscara, SID).
fn ace(kind: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
    let mut bytes = vec![kind, 0];
    bytes.extend_from_slice(&((8 + sid.len()) as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes
}

fn acl(aces: &[Vec<u8>]) -> Vec<u8> {
    let size = 8 + aces.iter().map(Vec::len).sum::<usize>();
    let mut bytes = vec![2u8, 0];
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&(aces.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&[0, 0]);
    for entry in aces {
        bytes.extend_from_slice(entry);
    }
    bytes
}

/// Descritor com a DACL dada e o rótulo Low com NO_WRITE_UP na SACL (o
/// rótulo dos objetos de um AppContainer): a integridade deixa o token Low
/// escrever, e o que concede ou recusa é o passe LowBox. O dono são os
/// Administradores, que o token LowBox (cópia do System) ainda tem: os
/// direitos do dono também passam pelas ACEs de pacote.
fn low_object(aces: &[Vec<u8>]) -> OwnedDescriptor {
    let label = ace(0x11, 1, &sid(16, &[0x1000]));
    OwnedDescriptor { control: 0x8014, owner: Some(sid(5, &[32, 544])), group: Some(sid(5, &[18])), dacl: Some(acl(aces)), sacl: Some(acl(&[label])) }
}

/// As ACEs de uma ACL: (tipo, máscara, SID).
fn entries(acl: &[u8]) -> Vec<(u8, u32, Vec<u8>)> {
    let count = u16::from_le_bytes([acl[4], acl[5]]) as usize;
    let mut list = Vec::new();
    let mut offset = 8;
    for _ in 0..count {
        if offset + 8 > acl.len() {
            break;
        }
        let size = u16::from_le_bytes([acl[offset + 2], acl[offset + 3]]) as usize;
        if size < 8 || offset + size > acl.len() {
            break;
        }
        let mask = u32::from_le_bytes([acl[offset + 4], acl[offset + 5], acl[offset + 6], acl[offset + 7]]);
        list.push((acl[offset], mask, acl[offset + 8..offset + size].to_vec()));
        offset += size;
    }
    list
}

/// O ponteiro do token de um handle de token da tabela do processo.
fn token_of(handle: u64) -> u64 {
    state::get_user_handle(handle).and_then(|entry| entry.downcast::<UserToken>().map(|object| object.token)).unwrap_or(0)
}

/// A memória de usuário do teste: um cursor de escrita e as chamadas.
struct Harness {
    out: u64,
    returned: u64,
    buffer: u64,
    rsp: u64,
    cursor: core::cell::Cell<u64>,
}

impl Harness {
    fn call(&self, name: &str, a1: u64, a2: u64, a3: u64, a4: u64, stack: &[u64]) -> u32 {
        for (index, &value) in stack.iter().enumerate() {
            guest::write64(self.rsp + 0x28 + index as u64 * 8, value);
        }
        state::handler(name).map(|handler| handler(a1, a2, a3, a4, self.rsp).unwrap_or(1)).unwrap_or(1)
    }

    /// `bytes` na área de dados (alinhados a 16); devolve a VA.
    fn put(&self, bytes: &[u8]) -> u64 {
        let at = self.cursor.get();
        guest::write_bytes(at, bytes);
        self.cursor.set((at + bytes.len() as u64 + 15) & !15);
        at
    }

    /// Um UNICODE_STRING com o texto; devolve a VA da estrutura.
    fn unicode(&self, text: &str) -> u64 {
        let units: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let buffer = self.put(&units);
        let mut string = Vec::new();
        string.extend_from_slice(&(units.len() as u16).to_le_bytes());
        string.extend_from_slice(&(units.len() as u16).to_le_bytes());
        string.extend_from_slice(&[0; 4]);
        string.extend_from_slice(&buffer.to_le_bytes());
        self.put(&string)
    }

    /// OBJECT_ATTRIBUTES com o nome (absoluto) e os atributos dados.
    fn attributes(&self, name: &str, flags: u32) -> u64 {
        let name = self.unicode(name);
        let mut bytes = vec![0u8; 0x30];
        bytes[0..4].copy_from_slice(&0x30u32.to_le_bytes());
        bytes[0x10..0x18].copy_from_slice(&name.to_le_bytes());
        bytes[0x18..0x1C].copy_from_slice(&flags.to_le_bytes());
        self.put(&bytes)
    }

    /// NtCreateDirectoryObjectEx com OBJ_OPENIF | OBJ_CASE_INSENSITIVE.
    fn directory(&self, name: &str) -> Option<u64> {
        let attributes = self.attributes(name, 0xC0);
        let status = self.call("NtCreateDirectoryObjectEx", self.out, 0xF_000F, attributes, 0, &[0]);
        (status & 0x8000_0000 == 0).then(|| guest::read64(self.out))
    }

    /// NtCreateSymbolicLinkObject.
    fn link(&self, name: &str, target: &str) -> Option<u64> {
        let attributes = self.attributes(name, 0x40);
        let target = self.unicode(target);
        let status = self.call("NtCreateSymbolicLinkObject", self.out, 0xF_0001, attributes, target, &[]);
        (status == 0).then(|| guest::read64(self.out))
    }

    /// SID_AND_ATTRIBUTES[] com os SIDs e os atributos dados.
    fn groups(&self, list: &[(&[u8], u32)]) -> u64 {
        let mut bytes = Vec::new();
        for (sid, attributes) in list {
            let at = self.put(sid);
            bytes.extend_from_slice(&at.to_le_bytes());
            bytes.extend_from_slice(&attributes.to_le_bytes());
            bytes.extend_from_slice(&[0; 4]);
        }
        if bytes.is_empty() {
            return 0;
        }
        self.put(&bytes)
    }

    /// NtCreateLowBoxToken(out, existing, 0, NULL, package, capabilities,
    /// handles); devolve o status e o handle novo.
    fn create(&self, existing: u64, package: u64, capabilities: (u32, u64), handles: (u32, u64)) -> (u32, u64) {
        guest::write64(self.out + 0x18, 0);
        let status = self.call("NtCreateLowBoxToken", self.out + 0x18, existing, 0, 0, &[package, capabilities.0 as u64, capabilities.1, handles.0 as u64, handles.1]);
        (status, guest::read64(self.out + 0x18))
    }

    fn query(&self, token: u64, class: u64, length: u64) -> u32 {
        self.call("NtQueryInformationToken", token, class, self.buffer, length, &[self.returned])
    }

    fn query32(&self, token: u64, class: u64) -> Option<u32> {
        (self.query(token, class, 4) == 0).then(|| guest::read32(self.buffer))
    }

    fn close(&self, handle: u64) {
        let _ = self.call("NtClose", handle, 0, 0, 0, &[]);
    }
}

pub fn run(assert: Assert) {
    let ran = with_test_process("lowbox-teste.exe", None, |_| {
        let Ok(block) = memory::map_user_region(0x6000) else {
            assert(false, "lowbox: memoria de usuario");
            return;
        };
        let test = Harness { out: block, returned: block + 0x80, buffer: block + 0x100, rsp: block + 0x5800, cursor: core::cell::Cell::new(block + 0x1000) };
        body(assert, &test);
        if let Some(region) = memory::find_region(block) {
            memory::release_private_region(&region);
        }
    });
    assert(ran.is_some(), "lowbox: processo de teste");
}

fn body(assert: Assert, test: &Harness) {
    let _ = test.call("NtOpenProcessToken", u64::MAX, 0xF_01FF, test.out + 8, 0, &[]);
    let own = guest::read64(test.out + 8);
    let own_pointer = token_of(own);
    // 1. Os diretórios do pacote, como o winlogon os cria para o UMFD.
    let sessions: Vec<Option<u64>> = ["\\Sessions", "\\Sessions\\0", "\\Sessions\\0\\AppContainerNamedObjects"].iter().map(|name| test.directory(name)).collect();
    let package_directory = test.directory(PACKAGE_PATH);
    let rpc = test.directory(&alloc::format!("{PACKAGE_PATH}\\RPC Control"));
    let global = test.link(&alloc::format!("{PACKAGE_PATH}\\Global"), "\\BaseNamedObjects");
    let (Some(session_zero), Some(package_directory), Some(rpc), Some(global)) = (sessions[1], package_directory, rpc, global) else {
        assert(false, "lowbox: diretorios do pacote e o link Global");
        return;
    };
    assert(own_pointer != 0 && tokens::token_flags(own_pointer) & 0x2000 != 0, "lowbox: o token do processo de teste tem TOKEN_NOT_LOW");
    // 2. O LowBox com duas capacidades e os três handles.
    let package = sid(15, &[2, 1, 2, 3, 4, 5, 6, 7]);
    let package_at = test.put(&package);
    let (internet, location) = (sid(15, &[3, 1]), sid(15, &[3, 8]));
    let capabilities = test.groups(&[(&internet, 4), (&location, 4)]);
    let handles: Vec<u8> = [package_directory, rpc, global].iter().flat_map(|handle| handle.to_le_bytes()).collect();
    let handles_at = test.put(&handles);
    let (status, first) = test.create(own, package_at, (2, capabilities), (3, handles_at));
    let pointer = token_of(first);
    assert(status == 0 && pointer != 0, "lowbox: NtCreateLowBoxToken com pacote, duas capacidades e tres handles");
    if pointer == 0 {
        return;
    }
    let is_app_container = test.query32(first, 29) == Some(1);
    let package_ok = test.query(first, 31, 0x100) == 0 && guest::read_bytes(guest::read64(test.buffer), package.len()) == package;
    let capabilities_ok = test.query(first, 30, 0x200) == 0 && guest::read32(test.buffer) == 2 && guest::read32(test.buffer + 16) == 4 && guest::read32(test.buffer + 32) == 4 && guest::read_bytes(guest::read64(test.buffer + 8), internet.len()) == internet;
    let number = test.query32(first, 32).unwrap_or(0);
    let label_ok = test.query(first, 25, 0x100) == 0 && guest::read_bytes(guest::read64(test.buffer), 12) == sid(16, &[0x1000]);
    let policy_ok = test.query32(first, 27) == Some(1);
    let privileges: Vec<u64> = if test.query(first, 3, 0x200) == 0 { (0..guest::read32(test.buffer) as u64).map(|index| guest::read64(test.buffer + 4 + index * 12)).collect() } else { Vec::new() };
    let dacl_ok = test.query(first, 6, 0x400) == 0 && {
        let acl_at = guest::read64(test.buffer);
        let size = guest::read16(acl_at + 2) as usize;
        entries(&guest::read_bytes(acl_at, size)).last().is_some_and(|(kind, mask, sid)| *kind == 0 && *mask == 0x1000_0000 && *sid == package)
    };
    assert(is_app_container && package_ok && capabilities_ok && number >= 1, "lowbox: TokenIsAppContainer 1, TokenAppContainerSid o pacote, TokenCapabilities com as duas e atributos 4, TokenAppContainerNumber >= 1");
    assert(label_ok && policy_ok && privileges == [23, 33] && dacl_ok, "lowbox: rotulo Low, NO_WRITE_UP, so SeChangeNotify e SeIncreaseWorkingSet, a ACE GENERIC_ALL do pacote no fim da DACL padrao");
    let (logon_id, server_silo) = tokens::with(pointer, |token| (token.authentication_id, token.server_silo)).unwrap_or((0, 0));
    let key = HandlesKey { logon_id, server_silo, package: package.clone() };
    assert(tokens::token_flags(pointer) & 0x6000 == 0x4000 && lowbox::number_references(0, number) == 1 && lowbox::handles_entry(&key) == Some((1, 3)), "lowbox: TOKEN_LOWBOX sem TOKEN_NOT_LOW, o numero com uma referencia e a entrada com os tres handles");
    // 3. Os handles guardados seguram os nomes.
    for handle in [package_directory, rpc, global] {
        test.close(handle);
    }
    assert(object_manager::lookup(PACKAGE_PATH).is_some(), "lowbox: o diretorio do pacote continua vivo pelos handles guardados");
    // 4. O mesmo pacote divide o número e a entrada; outro pacote, outro número.
    let (status, second) = test.create(own, package_at, (0, 0), (0, 0));
    let second_pointer = token_of(second);
    let shared = status == 0 && test.query32(second, 32) == Some(number) && lowbox::number_references(0, number) == 2 && lowbox::handles_entry(&key) == Some((2, 3));
    let other_package = test.put(&sid(15, &[2, 1, 2, 3, 4, 5, 6, 8]));
    let (status, other) = test.create(own, other_package, (0, 0), (0, 0));
    let other_number = test.query32(other, 32).unwrap_or(0);
    assert(shared && status == 0 && other_number >= 1 && other_number != number, "lowbox: o mesmo pacote divide o numero e a entrada de handles; outro pacote ganha outro numero");
    // 5. As recusas.
    let system = test.put(&sid(5, &[18]));
    let long_package = test.put(&sid(15, &[2, 1, 2, 3, 4, 5, 6, 7, 8]));
    let system_capability = test.groups(&[(&sid(5, &[18]), 4)]);
    let repeated = test.groups(&[(&internet, 4), (&internet, 4)]);
    let zone_handle = test.put(&session_zero.to_le_bytes());
    let eleven = test.put(&[0u8; 88]);
    let refusals = [
        (test.create(own, 0, (0, 0), (0, 0)).0, 0xC000_000D),
        (test.create(own, package_at, (0, 0), (0, handles_at)).0, 0xC000_0030),
        (test.create(own, package_at, (0, 0), (1, 0)).0, 0xC000_0030),
        (test.create(own, system, (0, 0), (0, 0)).0, 0xC000_000D),
        (test.create(own, long_package, (0, 0), (0, 0)).0, 0xC000_A202),
        (test.create(own, package_at, (1, system_capability), (0, 0)).0, 0xC000_000D),
        (test.create(own, package_at, (2, repeated), (0, 0)).0, 0xC000_000D),
        (test.create(own, package_at, (0, 0), (11, eleven)).0, 0xC000_00EF),
        (test.create(own, package_at, (0, 0), (1, handles_at + 4)).0, 0x8000_0002),
        (test.create(own, package_at, (0, 0), (1, zone_handle)).0, 0xC000_000D),
    ];
    for (index, (status, expected)) in refusals.iter().enumerate() {
        if status != expected {
            crate::debug_print!("lowbox: recusa {} deu {:#x}, esperado {:#x}", index, status, expected);
        }
    }
    assert(refusals.iter().all(|(status, expected)| status == expected), "lowbox: recusas (pacote nulo, mistura de handles, SID que nao e pacote, pacote de 9 subautoridades, capacidade invalida ou repetida, 11 handles, vetor desalinhado, handle fora do pacote)");
    // 6. O pai LowBox: impersonando o LowBox, outro pacote de 8
    // subautoridades é recusado e um filho dele passa.
    let thread = process::get_current_thread();
    let impersonation = tokens::duplicate(pointer, 2, false, 2).ok();
    let parent_ok = impersonation.is_some_and(|copy| thread_tokens::assign(thread, Some(copy), 2, false, false).is_ok()) && {
        let unrelated = test.put(&sid(15, &[2, 9, 9, 9, 9, 9, 9, 9]));
        let child_package = test.put(&sid(15, &[2, 1, 2, 3, 4, 5, 6, 7, 1, 2, 3, 4]));
        let refused = test.create(own, unrelated, (0, 0), (0, 0)).0 == 0xC000_0022;
        let (status, child) = test.create(own, child_package, (0, 0), (0, 0));
        let child_number = test.query32(child, 32).unwrap_or(0);
        let related = status == 0 && crate::ntos::se::capability::appcontainer::is_parent_of_child_lowbox(0, number, child_number);
        let _ = thread_tokens::assign(thread, None, 0, false, false);
        if status == 0 {
            test.close(child);
        }
        refused && related
    };
    if let Some(copy) = impersonation {
        let _ = tokens::release(copy);
    }
    assert(parent_ok, "lowbox: impersonando o LowBox, so um pacote filho dele passa (e o numero dele e filho do pai)");
    // 7. O passe LowBox da checagem de acesso.
    let everyone = sid(1, &[0]);
    let (all_packages, restricted_packages) = (sid(15, &[2, 1]), sid(15, &[2, 2]));
    let subject = tokens::with(pointer, Subject::from_token).unwrap_or_default();
    let check = |descriptor: &OwnedDescriptor, desired: u32| access_check(Some(descriptor), &subject, desired, 0, &FILE_MAPPING);
    let readable = low_object(&[ace(0, FILE_ALL, &everyone), ace(0, READ_EXECUTE, &all_packages)]);
    let all_packages_ok = check(&readable, FILE_READ) == Ok(FILE_READ) && check(&readable, 2) == Err(0xC000_0022) && check(&readable, MAXIMUM_ALLOWED) == Ok(READ_EXECUTE) && check(&readable, WRITE_DAC) == Err(0xC000_0022);
    let denied = low_object(&[ace(0, FILE_ALL, &everyone), ace(1, FILE_ALL, &all_packages), ace(0, FILE_ALL, &package)]);
    let deny_ignored = check(&denied, 2) == Ok(2);
    let by_capability = check(&low_object(&[ace(0, FILE_ALL, &everyone), ace(0, FILE_READ, &internet)]), FILE_READ) == Ok(FILE_READ);
    let other_capability = check(&low_object(&[ace(0, FILE_ALL, &everyone), ace(0, FILE_READ, &sid(15, &[3, 99]))]), FILE_READ) == Err(0xC000_0022);
    let by_restricted = check(&low_object(&[ace(0, FILE_ALL, &everyone), ace(0, FILE_READ, &restricted_packages)]), FILE_READ) == Ok(FILE_READ);
    let not_lowbox = tokens::with(own_pointer, Subject::from_token).is_some_and(|own_subject| access_check(Some(&readable), &own_subject, 2, 0, &FILE_MAPPING) == Ok(2));
    assert(all_packages_ok && deny_ignored, "lowbox: ALL APPLICATION PACKAGES concede so o que a ACE dele da (MAXIMUM_ALLOWED 0x1200A9, sem o WRITE_DAC do dono), e a negacao para ele nao conta no passe LowBox");
    assert(by_capability && other_capability && by_restricted && not_lowbox, "lowbox: a capacidade do token e ALL RESTRICTED APPLICATION PACKAGES concedem, outra capacidade nao, e quem nao e LowBox nao passa pelo passe");
    // 8. TokenIntegrityLevel Medium desfaz o LowBox e larga o número.
    let medium = test.put(&sid(16, &[0x2000]));
    let mut label = Vec::new();
    label.extend_from_slice(&medium.to_le_bytes());
    label.extend_from_slice(&0x20u32.to_le_bytes());
    label.extend_from_slice(&[0; 4]);
    let label_at = test.put(&label);
    let raised = test.call("NtSetInformationToken", first, 25, label_at, 16, &[]) == 0;
    assert(raised && test.query32(first, 29) == Some(0) && test.query32(first, 32) == Some(0) && lowbox::number_references(0, number) == 1, "lowbox: TokenIntegrityLevel Medium tira o AppContainer e larga o numero");
    // 9. O SeSubProcessToken leva o número na sessão dele e um novo na
    // outra.
    let same_session = tokens::sub_process_token(second_pointer, 0, true).ok();
    let same_ok = same_session.is_some_and(|copy| tokens::with(copy, |token| token.lowbox_number) == Some(Some((0, number)))) && lowbox::number_references(0, number) == 2;
    let other_session = tokens::sub_process_token(second_pointer, 1, true).ok();
    let moved = other_session.and_then(|copy| tokens::with(copy, |token| token.lowbox_number)).flatten();
    let moved_ok = moved.is_some_and(|(session, value)| session == 1 && lowbox::package_of_number(1, value).as_deref() == Some(package.as_slice()));
    for copy in [same_session, other_session].into_iter().flatten() {
        let _ = tokens::release(copy);
    }
    let restored = lowbox::number_references(0, number) == 1 && moved.is_none_or(|(_, value)| lowbox::number_references(1, value) == 0);
    assert(same_ok && moved_ok && restored, "lowbox: SeSubProcessToken leva o numero na mesma sessao e cria um na sessao 1, e as copias o devolvem");
    // 10. Fechados os tokens, o número, a entrada e os nomes saem.
    for handle in [first, second, other] {
        test.close(handle);
    }
    assert(lowbox::number_references(0, number) == 0 && lowbox::handles_entry(&key).is_none() && object_manager::lookup(PACKAGE_PATH).is_none(), "lowbox: sem tokens, o numero e a entrada de handles saem e os nomes do pacote tambem");
    for handle in sessions.into_iter().flatten().rev() {
        test.close(handle);
    }
    test.close(own);
}
