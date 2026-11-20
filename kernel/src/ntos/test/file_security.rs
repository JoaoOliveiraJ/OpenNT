//! Autotestes da segurança dos arquivos do volume de boot (o NTFS do
//! kernel, `drivers/fs/ntfs_security.rs`), pelos serviços de modo usuário
//! no D: (o mesmo volume do C: no boot do smss), contra o ntfs.sys 19041:
//!
//! - o $Secure: um descritor novo ganha o SecurityId seguinte ao último do
//!   $SII e um igual reaproveita o id (o $SDH pelo NtfsHashSecurityDescriptor);
//!   a entrada do $SDS alinhada a 16, com a cópia 0x40000 adiante, nunca
//!   cortada por um bloco de 256 KB (a que não cabe vai ao bloco seguinte);
//! - a herança no NtCreateFile (NtfsCacheSharedSecurityForCreate): as ACEs
//!   herdáveis do pai com INHERITED_ACE e SE_DACL_AUTO_INHERITED, o
//!   CREATOR OWNER de um diretório, o descritor explícito dos
//!   OBJECT_ATTRIBUTES protegido como veio, o FILE_SUPERSEDE e o
//!   FILE_OVERWRITE com o SecurityId antigo;
//! - o NtQuerySecurityObject com o descritor guardado, o buffer curto e o
//!   handle sem READ_CONTROL;
//! - o NtSetSecurityObject (NtfsModifySecurity): a DACL trocada inteira
//!   (AutoInheritFlags 0) e guardada depois do fechamento, o ChangeTime, o
//!   dono que o token não tem (STATUS_INVALID_OWNER, ou o SeRestorePrivilege)
//!   e o descritor da raiz.

use alloc::vec;
use alloc::vec::Vec;

use crate::drivers::fs::ntfs::Ntfs;
use crate::drivers::fs::ntfs_security::{self, Header, SDS_MIRROR, SECURE_RECORD};
use crate::drivers::fs::volume_files;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types as nt;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::process;
use crate::ntos::ps::user::{memory, state};
use crate::ntos::se::model::{sid, Group, Privilege, Sid};
use crate::ntos::se::policy_descriptor::OwnedDescriptor;
use crate::ntos::se::query_descriptor;
use crate::ntos::se::set_security;
use crate::ntos::se::token::{thread as thread_tokens, tokens};

type Assert = fn(bool, &str);

const ROOT: &str = "/OPENNTFS";
const PARENT: &str = "/OPENNTFS/PAI";
const FILE: &str = "/OPENNTFS/PAI/F.TXT";
const DIRECTORY: &str = "/OPENNTFS/PAI/D";
const PROTECTED: &str = "/OPENNTFS/PAI/P.TXT";
const BIG: usize = 5;
/// Descritores pequenos e diferentes, mais do que as raízes do $SII e do
/// $SDH guardam no registro do $Secure.
const MANY: usize = 60;
/// FILE_ALL_ACCESS e FILE_GENERIC_READ | FILE_GENERIC_EXECUTE.
const FILE_ALL: u32 = 0x1F_01FF;
const READ_EXECUTE: u32 = 0x12_00A9;

/// Uma ACE de acesso permitido (tipo 0): flags, máscara e SID.
fn ace(flags: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8, flags];
    bytes.extend_from_slice(&((8 + sid.len()) as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes
}

/// ACL de revisão 2 com as ACEs dadas.
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

/// Descritor self-relative com DACL (owner e group vazios ficam ausentes).
fn descriptor(control: u16, owner: &[u8], group: &[u8], aces: &[Vec<u8>]) -> Vec<u8> {
    let owned = OwnedDescriptor { control: control | 0x8004, owner: (!owner.is_empty()).then(|| owner.to_vec()), group: (!group.is_empty()).then(|| group.to_vec()), dacl: Some(acl(aces)), sacl: None };
    set_security::serialize_owned(&owned)
}

/// As ACEs de uma ACL: (tipo, flags, máscara, SID).
fn entries(acl: &[u8]) -> Vec<(u8, u8, u32, Vec<u8>)> {
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
        list.push((acl[offset], acl[offset + 1], mask, acl[offset + 8..offset + size].to_vec()));
        offset += size;
    }
    list
}

/// O descritor guardado de um arquivo, em componentes.
fn stored(volume: &Ntfs, path: &str) -> Option<OwnedDescriptor> {
    volume.file_security(path).ok().flatten().and_then(|bytes| query_descriptor::from_relative(&bytes))
}

fn security_id(volume: &Ntfs, path: &str) -> u32 {
    volume.stat(path).ok().flatten().map_or(0, |stat| stat.security_id)
}

/// As chaves do $SII (SecurityIds) e do $SDH ((Hash, SecurityId)).
fn secure_keys(volume: &Ntfs) -> (Vec<u32>, Vec<(u32, u32)>) {
    let Ok(record) = volume.read_record(SECURE_RECORD) else { return (Vec::new(), Vec::new()) };
    let key = |entry: &crate::drivers::fs::ntfs::RawIndexEntry, at: usize| u32::from_le_bytes([entry.key()[at], entry.key()[at + 1], entry.key()[at + 2], entry.key()[at + 3]]);
    let sii = volume.view_entries(&record, "$SII").unwrap_or_default().iter().filter(|entry| entry.key().len() == 4).map(|entry| key(entry, 0)).collect();
    let sdh = volume.view_entries(&record, "$SDH").unwrap_or_default().iter().filter(|entry| entry.key().len() == 8).map(|entry| (key(entry, 0), key(entry, 4))).collect();
    (sii, sdh)
}

/// O SecurityId de um descritor já no $Secure (pelo $SDH e os bytes).
fn known_id(volume: &Ntfs, bytes: &[u8]) -> Option<u32> {
    let hash = ntfs_security::hash(bytes);
    secure_keys(volume).1.into_iter().filter(|&(key, _)| key == hash).map(|(_, id)| id).find(|&id| volume.security_descriptor(id).ok().flatten().is_some_and(|found| found[..] == *bytes))
}

/// A entrada do $SDS de um SecurityId está bem posta: o cabeçalho com o id,
/// o hash e o tamanho do descritor; alinhada a 16 na metade principal de um
/// bloco de 256 KB sem passar dela; a cópia igual 0x40000 adiante.
fn sds_entry_ok(volume: &Ntfs, id: u32, bytes: &[u8]) -> Option<Header> {
    let record = volume.read_record(SECURE_RECORD).ok()?;
    let header = volume.security_header(&record, id).ok()??;
    let sds = crate::drivers::fs::ntfs::find_named_attribute(&record, 0x80, "$SDS").ok()??;
    let length = header.length as u64;
    let placed = header.offset % 16 == 0 && header.offset & SDS_MIRROR == 0 && (header.offset & (SDS_MIRROR - 1)) + length <= SDS_MIRROR;
    let expected = [&header.bytes()[..], bytes].concat();
    let primary = volume.read_attribute_range(&record, &sds, header.offset, length).ok()?;
    let mirror = volume.read_attribute_range(&record, &sds, header.offset + SDS_MIRROR, length).ok()?;
    (placed && header.id == id && header.hash == ntfs_security::hash(bytes) && length as usize == Header::SIZE + bytes.len() && primary == expected && mirror == expected).then_some(header)
}

/// O usuário dos tokens do teste.
fn test_user() -> Sid {
    sid(5, &[21, 1, 2, 3, 1001])
}

/// Token de impersonação do teste: o usuário S-1-5-21-1-2-3-1001, dono de
/// si, com Todos e BUILTIN\Users e os privilégios dados habilitados.
fn test_token(privileges: &[u64]) -> u64 {
    let user = test_user();
    let own = process::get_primary_token(process::get_current_process()).unwrap_or(0);
    let privileges: Vec<Privilege> = privileges.iter().map(|&id| Privilege { id, attributes: 3 }).collect();
    tokens::create(
        Some(own),
        Some(&|token: &mut tokens::Token| {
            token.user = user.clone();
            token.owner = user.clone();
            token.groups = vec![Group { sid: sid(1, &[0]), attributes: 7 }, Group { sid: sid(5, &[32, 545]), attributes: 7 }];
            token.privileges = privileges.clone();
            token.kind = 2;
            token.impersonation_level = 2;
        }),
    )
    .unwrap_or(0)
}

/// O bloco de usuário do teste: handle, IOSB, OBJECT_ATTRIBUTES, os
/// argumentos de pilha, o descritor dos OA e a saída.
struct Harness {
    block: u64,
}

impl Harness {
    const HANDLE: u64 = 0;
    const IOSB: u64 = 0x10;
    const NEEDED: u64 = 0x20;
    const ATTRIBUTES: u64 = 0x100;
    const STRING: u64 = 0x140;
    const TEXT: u64 = 0x180;
    const STACK: u64 = 0x1000;
    const DESCRIPTOR: u64 = 0x2000;
    const OUTPUT: u64 = 0x3000;

    fn at(&self, offset: u64) -> u64 {
        self.block + offset
    }

    fn call(&self, name: &str, a1: u64, a2: u64, a3: u64, a4: u64) -> u32 {
        state::handler(name).map(|handler| handler(a1, a2, a3, a4, self.at(Self::STACK)).unwrap_or(1)).unwrap_or(1)
    }

    fn arguments(&self, values: &[u64]) {
        for (index, value) in values.iter().enumerate() {
            guest::write64(self.at(Self::STACK) + 0x28 + index as u64 * 8, *value);
        }
    }

    /// OBJECT_ATTRIBUTES de `name` (OBJ_CASE_INSENSITIVE) com o descritor
    /// dado copiado no bloco.
    fn name(&self, name: &str, security: Option<&[u8]>) -> u64 {
        state::write_user_wide(self.at(Self::TEXT), name);
        state::write_unicode_string(self.at(Self::STRING), self.at(Self::TEXT), name);
        if let Some(bytes) = security {
            guest::write_bytes(self.at(Self::DESCRIPTOR), bytes);
        }
        // SAFETY: OBJECT_ATTRIBUTES no bloco de usuário do teste.
        let attributes = unsafe { nt::ObjectAttributes::at(self.at(Self::ATTRIBUTES)) };
        attributes.length.set(nt::ObjectAttributes::SIZE as u32);
        attributes.root_directory.set(0);
        attributes.object_name.set(self.at(Self::STRING));
        attributes.attributes.set(0x40);
        attributes.security_descriptor.set(if security.is_some() { self.at(Self::DESCRIPTOR) } else { 0 });
        attributes.security_quality_of_service.set(0);
        self.at(Self::ATTRIBUTES)
    }

    /// NtCreateFile de um caminho do volume no D:: (status, handle).
    fn open(&self, path: &str, access: u32, disposition: u32, options: u32, security: Option<&[u8]>) -> (u32, u64) {
        let attributes = self.name(&alloc::format!("\\??\\D:{}", path.replace('/', "\\")), security);
        guest::write64(self.at(Self::HANDLE), 0);
        self.arguments(&[0, 0, 7, disposition as u64, options as u64, 0, 0]);
        let status = self.call("NtCreateFile", self.at(Self::HANDLE), access as u64, attributes, self.at(Self::IOSB));
        (status, guest::read64(self.at(Self::HANDLE)))
    }

    fn close(&self, handle: u64) {
        let _ = self.call("NtClose", handle, 0, 0, 0);
    }

    /// NtQuerySecurityObject: (status, LengthNeeded, descritor devolvido).
    fn query(&self, handle: u64, information: u32, length: u32) -> (u32, u32, Option<OwnedDescriptor>) {
        guest::write_bytes(self.at(Self::OUTPUT), &[0u8; 0x400]);
        guest::write32(self.at(Self::NEEDED), 0);
        self.arguments(&[self.at(Self::NEEDED)]);
        let status = self.call("NtQuerySecurityObject", handle, information as u64, self.at(Self::OUTPUT), length as u64);
        let needed = guest::read32(self.at(Self::NEEDED));
        let returned = (status == 0).then(|| query_descriptor::from_relative(&guest::read_bytes(self.at(Self::OUTPUT), (needed as usize).min(0x400)))).flatten();
        (status, needed, returned)
    }

    /// NtSetSecurityObject com o descritor copiado no bloco.
    fn set(&self, handle: u64, information: u32, bytes: &[u8]) -> u32 {
        guest::write_bytes(self.at(Self::DESCRIPTOR), bytes);
        self.call("NtSetSecurityObject", handle, information as u64, self.at(Self::DESCRIPTOR), 0)
    }
}

fn cleanup(volume: &Ntfs) {
    let mut paths = vec![FILE, DIRECTORY, PROTECTED, PARENT, "/OPENNTFS/A", "/OPENNTFS/B", "/OPENNTFS/DC/R.TXT", "/OPENNTFS/DC/E.TXT", "/OPENNTFS/ND/R.TXT", "/OPENNTFS/DC", "/OPENNTFS/ND", "/OPENNTFS/AD"];
    let big: Vec<alloc::string::String> = (0..BIG).map(|index| alloc::format!("/OPENNTFS/G{index}")).collect();
    paths.extend(big.iter().map(|path| path.as_str()));
    let many: Vec<alloc::string::String> = (0..MANY).map(|index| alloc::format!("/OPENNTFS/M{index}")).collect();
    paths.extend(many.iter().map(|path| path.as_str()));
    paths.push(ROOT);
    for path in paths {
        let _ = volume.remove(path);
        volume_files::forget(path);
    }
}

/// O $Secure: ids, reaproveitamento, a entrada do $SDS e a troca de bloco.
fn storage(assert: Assert, volume: &Ntfs) {
    let (system, administrators, users) = (sid(5, &[18]), sid(5, &[32, 544]), sid(5, &[32, 545]));
    let sd_a = descriptor(0, &administrators, &system, &[ace(0, FILE_ALL, &system), ace(0, READ_EXECUTE, &users)]);
    let sd_b = descriptor(0, &administrators, &system, &[ace(0, FILE_ALL, &system), ace(0, READ_EXECUTE, &users), ace(0, FILE_ALL, &administrators)]);
    let id_a = volume.create_with_security(ROOT, true, 0x10, 0, Some(&sd_a)).ok().flatten().map_or(0, |stat| stat.security_id);
    assert(id_a >= 0x100 && volume.file_security(ROOT).ok().flatten().is_some_and(|found| *found == sd_a), "filesec: diretorio criado com o descritor dado (SecurityId >= 0x100 no $STANDARD_INFORMATION)");
    let before = secure_keys(volume).0.len();
    let reused = volume.create_with_security("/OPENNTFS/A", false, 0x20, 0, Some(&sd_a)).ok().flatten().map_or(0, |stat| stat.security_id);
    assert(reused == id_a && secure_keys(volume).0.len() == before, "filesec: o mesmo descritor reaproveita o SecurityId (o $SDH acha o igual) sem entrada nova no $SII");
    let next = secure_keys(volume).0.into_iter().max().map_or(0x100, |last| last + 1);
    let expected_b = known_id(volume, &sd_b).unwrap_or(next);
    let id_b = volume.create_with_security("/OPENNTFS/B", false, 0x20, 0, Some(&sd_b)).ok().flatten().map_or(0, |stat| stat.security_id);
    assert(id_b == expected_b && id_b != id_a, "filesec: descritor novo ganha o ultimo SecurityId do $SII mais 1");
    let (sii, sdh) = secure_keys(volume);
    assert(sii.contains(&id_b) && sdh.contains(&(ntfs_security::hash(&sd_b), id_b)), "filesec: $SII com o id e $SDH com (NtfsHashSecurityDescriptor, id)");
    assert(sds_entry_ok(volume, id_b, &sd_b).is_some(), "filesec: entrada do $SDS alinhada a 16 com a copia 0x40000 adiante");
    // Descritores de ~60 KB: cinco passam de um bloco de 256 KB, e a
    // entrada que não cabe vai para o começo do bloco seguinte.
    let mut headers = Vec::new();
    for index in 0..BIG {
        let principal = sid(5, &[21, 1000 + index as u32, 2, 3, 4]);
        let aces: Vec<Vec<u8>> = (0..1700).map(|_| ace(0, READ_EXECUTE, &principal)).collect();
        let bytes = descriptor(0, &administrators, &system, &aces);
        let path = alloc::format!("/OPENNTFS/G{index}");
        let id = volume.create_with_security(&path, false, 0x20, 0, Some(&bytes)).ok().flatten().map_or(0, |stat| stat.security_id);
        headers.push(sds_entry_ok(volume, id, &bytes));
    }
    assert(headers.iter().all(Option::is_some), "filesec: entradas grandes do $SDS sem cortar a metade principal do bloco");
    assert(headers.iter().flatten().any(|header| header.offset >= 2 * SDS_MIRROR), "filesec: a entrada que nao cabe vai ao bloco seguinte (+0x80000)");
    // Muitos descritores pequenos: o $SII e o $SDH passam da raiz no
    // registro e cabem num bloco INDX só, que fica como folha com a raiz
    // apontando para ele (o PushIndexRoot do ntfs.sys); cada um ganha um id
    // novo e os dois índices acham todos.
    let mut ids = Vec::new();
    for index in 0..MANY {
        let principal = sid(5, &[21, 2000 + index as u32, 5, 6, 7]);
        let bytes = descriptor(0, &administrators, &system, &[ace(0, FILE_ALL, &system), ace(0, READ_EXECUTE, &principal)]);
        let path = alloc::format!("/OPENNTFS/M{index}");
        let id = volume.create_with_security(&path, false, 0x20, 0, Some(&bytes)).ok().flatten().map_or(0, |stat| stat.security_id);
        ids.push((id, ntfs_security::hash(&bytes)));
    }
    let (sii, sdh) = secure_keys(volume);
    let distinct = ids.iter().all(|&(id, _)| id >= 0x100) && ids.windows(2).all(|pair| pair[1].0 == pair[0].0 + 1);
    assert(distinct && ids.iter().all(|&(id, hash)| sii.contains(&id) && sdh.contains(&(hash, id))), "filesec: 60 descritores novos com ids seguidos, o $SII e o $SDH numa folha INDX abaixo da raiz");
}

/// A herança no NtCreateFile, o descritor explícito e o FILE_SUPERSEDE e o
/// FILE_OVERWRITE.
fn inheritance(assert: Assert, volume: &Ntfs, test: &Harness) {
    let (system, administrators, users, creator) = (sid(5, &[18]), sid(5, &[32, 544]), sid(5, &[32, 545]), sid(3, &[0]));
    let owner = test_user();
    // D:AI(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;CIIO;GA;;;CO)
    let parent = descriptor(0x0400, &administrators, &system, &[ace(0x03, FILE_ALL, &system), ace(0x03, READ_EXECUTE, &users), ace(0x0A, 0x1000_0000, &creator)]);
    assert(volume.create_with_security(PARENT, true, 0x10, 0, Some(&parent)).is_ok(), "filesec: diretorio pai com ACEs herdaveis");

    let (created, handle) = test.open(FILE, 0xC010_0000, 2, 0x60, None);
    test.close(handle);
    let file = stored(volume, FILE);
    let file_aces = file.as_ref().and_then(|file| file.dacl.as_deref()).map(entries).unwrap_or_default();
    assert(created == 0 && file_aces == vec![(0, 0x10, FILE_ALL, system.clone()), (0, 0x10, READ_EXECUTE, users.clone())], "filesec: arquivo novo herda (A;ID;FA;;;SY)(A;ID;0x1200a9;;;BU)");
    assert(file.as_ref().is_some_and(|file| file.control & 0x0400 != 0 && file.owner.as_deref() == Some(&owner[..])), "filesec: SE_DACL_AUTO_INHERITED e o dono do token de quem cria");

    let (created, handle) = test.open(DIRECTORY, 0x0010_0001, 2, 0x21, None);
    test.close(handle);
    let directory_aces = stored(volume, DIRECTORY).and_then(|directory| directory.dacl).map(|dacl| entries(&dacl)).unwrap_or_default();
    let has = |flags: u8, mask: u32, who: &[u8]| directory_aces.iter().any(|entry| entry.1 & flags == flags && entry.2 == mask && entry.3 == who);
    assert(created == 0 && has(0x13, FILE_ALL, &system[..]) && has(0x13, READ_EXECUTE, &users[..]), "filesec: diretorio novo herda as ACEs OICI com INHERITED_ACE");
    assert(has(0x10, FILE_ALL, &owner[..]) && has(0x1A, 0x1000_0000, &creator[..]), "filesec: CREATOR OWNER vira o dono no diretorio novo e fica herdavel (CIIOID)");

    // D:P(A;;FA;;;BA) nos OBJECT_ATTRIBUTES.
    let explicit = descriptor(0x1000, &[], &[], &[ace(0, FILE_ALL, &administrators)]);
    let (created, handle) = test.open(PROTECTED, 0xC010_0000, 2, 0x60, Some(&explicit));
    test.close(handle);
    let protected = stored(volume, PROTECTED);
    let protected_aces = protected.as_ref().and_then(|protected| protected.dacl.as_deref()).map(entries).unwrap_or_default();
    assert(created == 0 && protected_aces == vec![(0, 0, FILE_ALL, administrators.clone())] && protected.as_ref().is_some_and(|protected| protected.control & 0x1000 != 0 && protected.owner.as_deref() == Some(&owner[..])), "filesec: descritor explicito dos OA guardado como veio (protegido, dono do token)");

    let id = security_id(volume, FILE);
    let (superseded, handle) = test.open(FILE, 0xC011_0000, 0, 0x60, None);
    test.close(handle);
    assert(superseded == 0 && id >= 0x100 && security_id(volume, FILE) == id, "filesec: FILE_SUPERSEDE mantem o SecurityId");
    let (overwritten, handle) = test.open(FILE, 0x4010_0000, 4, 0x60, None);
    test.close(handle);
    assert(overwritten == 0 && security_id(volume, FILE) == id, "filesec: FILE_OVERWRITE mantem o SecurityId");
}

/// NtQuerySecurityObject e NtSetSecurityObject num arquivo do volume.
fn query_and_set(assert: Assert, volume: &Ntfs, test: &Harness, token: u64) {
    let thread = process::get_current_thread();
    let (administrators, users) = (sid(5, &[32, 544]), sid(5, &[32, 545]));
    let (opened, reader) = test.open(FILE, 0x0012_0000, 1, 0x60, None);
    let (status, needed, returned) = test.query(reader, 7, 0x400);
    let current = stored(volume, FILE);
    let same = |left: &Option<OwnedDescriptor>, right: &Option<OwnedDescriptor>| match (left, right) {
        (Some(left), Some(right)) => left.owner == right.owner && left.group == right.group && left.dacl == right.dacl,
        _ => false,
    };
    assert(opened == 0 && status == 0 && needed > 20 && same(&returned, &current), "filesec: NtQuerySecurityObject devolve o descritor do $Secure");
    let (short, short_needed, _) = test.query(reader, 7, 8);
    assert(short == 0xC000_0023 && short_needed == needed, "filesec: buffer curto -> STATUS_BUFFER_TOO_SMALL com o tamanho");
    test.close(reader);
    let (opened, attributes_only) = test.open(FILE, 0x0010_0080, 1, 0x60, None);
    assert(opened == 0 && test.query(attributes_only, 7, 0x400).0 == 0xC000_0022, "filesec: handle sem READ_CONTROL -> STATUS_ACCESS_DENIED");
    test.close(attributes_only);

    // A DACL trocada inteira, com o ChangeTime de agora.
    let mut times = [0u8; 32];
    times[16] = 1;
    let _ = volume.set_basic(FILE, Some(&times), 0);
    let (opened, writer) = test.open(FILE, 0x001E_0000, 1, 0x60, None);
    let replacement = descriptor(0, &[], &[], &[ace(0, READ_EXECUTE, &users)]);
    let set = test.set(writer, 4, &replacement);
    test.close(writer);
    let after = stored(volume, FILE);
    let change = volume.stat(FILE).ok().flatten().map_or(0, |stat| u64::from_le_bytes(stat.times[16..24].try_into().unwrap_or([0; 8])));
    assert(opened == 0 && set == 0 && after.as_ref().and_then(|after| after.dacl.as_deref()).map(entries) == Some(vec![(0, 0, READ_EXECUTE, users.clone())]) && after.as_ref().is_some_and(|after| after.control & 0x0400 == 0 && after.owner == current.as_ref().and_then(|current| current.owner.clone())), "filesec: NtSetSecurityObject troca a DACL inteira e mantem o dono");
    assert(change > 1, "filesec: NtSetSecurityObject atualiza o ChangeTime");
    let (opened, reader) = test.open(FILE, 0x0012_0000, 1, 0x60, None);
    let (status, _, returned) = test.query(reader, 4, 0x400);
    test.close(reader);
    assert(opened == 0 && status == 0 && returned.and_then(|returned| returned.dacl).map(|dacl| entries(&dacl)) == Some(vec![(0, 0, READ_EXECUTE, users.clone())]), "filesec: a DACL nova fica depois do fechamento");

    // O dono: um SID que o token não tem, e o mesmo com o SeRestorePrivilege.
    let ownership = descriptor(0, &administrators, &[], &[]);
    let (opened, writer) = test.open(FILE, 0x001E_0000, 1, 0x60, None);
    assert(opened == 0 && test.set(writer, 1, &ownership) == 0xC000_005A, "filesec: dono que o token nao tem -> STATUS_INVALID_OWNER");
    let restorer = test_token(&[23, 18]);
    let restored = restorer != 0 && thread_tokens::assign(thread, Some(restorer), 2, false, false).is_ok() && test.set(writer, 1, &ownership) == 0;
    let _ = thread_tokens::assign(thread, Some(token), 2, false, false);
    if restorer != 0 {
        let _ = tokens::release(restorer);
    }
    test.close(writer);
    assert(restored && stored(volume, FILE).is_some_and(|after| after.owner.as_deref() == Some(&administrators[..])), "filesec: com o SeRestorePrivilege o dono vira Administradores");

    // A raiz (registro 5) troca de descritor e volta ao dela.
    let original = volume.file_security("/").ok().flatten().map(|bytes| bytes.to_vec());
    let root = descriptor(0, &administrators, &sid(5, &[18]), &[ace(0x03, FILE_ALL, &administrators), ace(0x03, READ_EXECUTE, &users)]);
    let changed = volume.set_security("/", &root).is_ok() && volume.file_security("/").ok().flatten().is_some_and(|found| *found == root);
    let back = original.as_ref().is_some_and(|original| volume.set_security("/", original).is_ok() && volume.file_security("/").ok().flatten().is_some_and(|found| *found == *original));
    assert(changed && back, "filesec: o descritor da raiz (registro 5) troca e volta");
}

/// Roda `action` com outro token de impersonação do teste (os privilégios e
/// o nível dados) e volta ao token `main`.
fn as_token(main: u64, privileges: &[u64], level: u32, action: impl FnOnce() -> bool) -> bool {
    let thread = process::get_current_thread();
    let other = test_token(privileges);
    let done = other != 0 && thread_tokens::assign(thread, Some(other), level, false, false).is_ok() && action();
    let _ = thread_tokens::assign(thread, Some(main), 2, false, false);
    if other != 0 {
        let _ = tokens::release(other);
    }
    done
}

/// [Q-FILESEC etapa 2] As decisões do NtfsAccessCheck. A abertura ainda só
/// as registra (`[filesec] negaria`), então o teste confere a decisão das
/// checagens e que o NtCreateFile segue concedendo.
fn access_checks(assert: Assert, volume: &Ntfs, test: &Harness, token: u64) {
    use crate::ntos::io::parse::volume_open_security;
    let (system, administrators, users) = (sid(5, &[18]), sid(5, &[32, 544]), sid(5, &[32, 545]));
    let sd = |aces: Vec<Vec<u8>>| descriptor(0, &administrators, &system, &aces);
    let all = ace(0, FILE_ALL, &system);
    // DC: FILE_LIST_DIRECTORY e FILE_DELETE_CHILD para BU; ND: só
    // FILE_LIST_DIRECTORY (sem FILE_TRAVERSE); AD: FILE_LIST_DIRECTORY e
    // FILE_ADD_FILE. E.TXT tem a DACL vazia.
    let made = [
        ("/OPENNTFS/DC", true, sd(vec![all.clone(), ace(0, 0x41, &users)])),
        ("/OPENNTFS/DC/R.TXT", false, sd(vec![all.clone(), ace(0, READ_EXECUTE, &users)])),
        ("/OPENNTFS/DC/E.TXT", false, sd(Vec::new())),
        ("/OPENNTFS/ND", true, sd(vec![all.clone(), ace(0, 0x1, &users)])),
        ("/OPENNTFS/ND/R.TXT", false, sd(vec![all.clone(), ace(0, READ_EXECUTE, &users)])),
        ("/OPENNTFS/AD", true, sd(vec![all.clone(), ace(0, 0x3, &users)])),
    ];
    let prepared = made.iter().all(|(path, directory, bytes)| volume.create_with_security(path, *directory, if *directory { 0x10 } else { 0x20 }, 0, Some(bytes)).is_ok());
    assert(prepared, "filesec: arquivos com os descritores das checagens");
    let open = |desired: u32, options: u32| volume_open_security(true, desired, options, 1, None);
    let decide = |path: &str, desired: u32| open(desired, 0).and_then(|security| ntfs_security::check(volume, path, &security, desired));
    let read = "/OPENNTFS/DC/R.TXT";
    let empty = "/OPENNTFS/DC/E.TXT";
    assert(decide(read, 0x1).is_ok() && decide(read, 0x2) == Err(0xC000_0022) && decide(read, 0x0200_0000) == Ok(READ_EXECUTE), "filesec: (A;;0x1200a9;;;BU) concede leitura, nega escrita e MAXIMUM_ALLOWED da 0x1200a9");
    assert(decide(read, 0x1_0000).is_ok_and(|granted| granted & 0x1_0000 != 0) && decide("/OPENNTFS/ND/R.TXT", 0x1_0000) == Err(0xC000_0022), "filesec: DELETE pelo FILE_DELETE_CHILD do pai, e negado sem ele");
    assert(decide(empty, 0x80).is_ok() && decide(empty, 0x2_0000) == Err(0xC000_0022), "filesec: DACL vazia com FILE_LIST_DIRECTORY no pai: FILE_READ_ATTRIBUTES sim, READ_CONTROL nao");
    let create = |parent: &str, desired: u32| open(desired, 0).and_then(|security| ntfs_security::check_create(volume, parent, &security, false, desired));
    assert(create("/OPENNTFS/ND", 0x0012_0116) == Err(0xC000_0022) && create("/OPENNTFS/AD", 0x0012_0116) == Ok(0x0012_0116) && create("/OPENNTFS/AD", 0x0200_0000) == Ok(FILE_ALL), "filesec: criacao pede FILE_ADD_FILE no pai e concede o pedido (MAXIMUM_ALLOWED vira FILE_ALL_ACCESS)");
    assert(decide(read, 0x0012_0089 | 0x2) == Err(0xC000_0022), "filesec: FILE_OVERWRITE com GENERIC_READ pede FILE_WRITE_DATA e e negado");
    let traverse = |security: Result<crate::ntos::io::parse::VolumeOpenSecurity, u32>| security.and_then(|security| ntfs_security::check_traverse(volume, "/OPENNTFS/ND/R.TXT", &security));
    let privileged = traverse(open(0x1, 0)).is_ok();
    let unprivileged = as_token(token, &[], 2, || traverse(open(0x1, 0)) == Err(0xC000_0022));
    assert(privileged && unprivileged, "filesec: sem SeChangeNotifyPrivilege o diretorio sem FILE_TRAVERSE nega o filho; com ele, passa");
    let backup = as_token(token, &[23, 17], 2, || open(0x1, 0x4000).is_ok_and(|security| security.previously_granted == 0x1 && ntfs_security::check(volume, empty, &security, 0x1).is_ok()) && decide(empty, 0x1) == Err(0xC000_0022));
    let restore = as_token(token, &[23, 18], 2, || open(0x4_0000, 0x4000).is_ok_and(|security| security.restore && ntfs_security::check(volume, empty, &security, 0x4_0000).is_ok()));
    let neither = open(0x1, 0x4000).is_ok_and(|security| security.options & 0x4000 == 0 && ntfs_security::check(volume, empty, &security, 0x1) == Err(0xC000_0022));
    assert(backup && restore && neither, "filesec: FILE_OPEN_FOR_BACKUP_INTENT com SeBackupPrivilege le e com SeRestorePrivilege da WRITE_DAC; sem os dois a opcao cai e nega");
    let identification = as_token(token, &[23], 1, || open(0x1, 0).err() == Some(0xC000_00A5));
    assert(identification, "filesec: impersonacao Identification -> STATUS_BAD_IMPERSONATION_LEVEL");
    let kernel = volume_open_security(false, 0x2, 0, 1, None).and_then(|security| ntfs_security::check(volume, empty, &security, 0x2));
    assert(kernel == Ok(0x2), "filesec: abertura de modo kernel sem OBJ_FORCE_ACCESS_CHECK nao confere o descritor");
    let (opened, handle) = test.open(read, 0x0010_0002, 1, 0x60, None);
    test.close(handle);
    assert(opened == 0, "filesec: etapa 2 so registra: o NtCreateFile negado pelo descritor ainda abre");
}

pub fn run(assert: Assert) {
    let Some(volume) = volume_files::volume() else {
        assert(false, "filesec: volume de boot");
        return;
    };
    let Ok(block) = memory::map_user_region(0x4000) else {
        assert(false, "filesec: memoria de usuario");
        return;
    };
    let test = Harness { block };
    cleanup(&volume);
    storage(assert, &volume);
    let thread = process::get_current_thread();
    let token = test_token(&[23]);
    if token != 0 && thread_tokens::assign(thread, Some(token), 2, false, false).is_ok() {
        inheritance(assert, &volume, &test);
        query_and_set(assert, &volume, &test, token);
        access_checks(assert, &volume, &test, token);
        let _ = thread_tokens::assign(thread, None, 0, false, false);
    } else {
        assert(false, "filesec: token de impersonacao do teste");
    }
    if token != 0 {
        let _ = tokens::release(token);
    }
    cleanup(&volume);
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}
