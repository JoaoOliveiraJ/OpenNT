//! A segurança dos arquivos do NTFS do kernel, como o ntfs.sys 10.0.19041:
//!
//! - o $Secure (registro 9): o SecurityId do $STANDARD_INFORMATION (+0x34)
//!   é a chave do $SII, que dá o SECURITY_DESCRIPTOR_HEADER { Hash,
//!   SecurityId, Offset, Length } do descritor; o $SDH indexa o mesmo
//!   cabeçalho por (Hash, SecurityId), para achar um descritor igual; o $SDS
//!   guarda cada cabeçalho seguido do descritor, alinhado a 16, com a cópia
//!   0x40000 bytes adiante, em blocos de 256 KB que uma entrada nunca corta
//!   (NtfsCacheSharedSecurityBySecurityId 0xf08d8,
//!   MapSecurityIdToSecurityDescriptorHeaderUnsafe 0xde8f8,
//!   GetSecurityIdFromSecurityDescriptorUnsafe 0xe0290 e NtfsInitializeSecurity
//!   0x19d98c). SecurityId 0, ou um que o $SII não tem, vale o primeiro do
//!   volume (0x100), que é o que o NtfsVerifyAndFixSecurityId (0x24f23c) põe
//!   no registro;
//! - o descritor de um arquivo novo (NtfsCacheSharedSecurityForCreate
//!   0x138aa4): o SeAssignSecurityEx com o descritor do pai, o explícito dos
//!   OBJECT_ATTRIBUTES (o AccessState->SecurityDescriptor), as flags do
//!   SeComputeAutoInheritByObjectType e o mapeamento genérico de arquivo; em
//!   UserMode (SEF_FORCE_USER_MODE) o dono explícito precisa ser atribuível
//!   pelo token e uma SACL de auditoria pede o SeSecurityPrivilege, em
//!   KernelMode (SEF_AVOID_PRIVILEGE_CHECK | SEF_AVOID_OWNER_CHECK) não;
//! - a troca do descritor (NtfsModifySecurity 0xdf2d4): o
//!   SeSetSecurityDescriptorInfoEx com AutoInheritFlags 0 sobre o descritor
//!   atual; a propagação aos filhos é do ntmarta, em modo usuário.
//!
//! A gravação no $Secure mora em `ntfs_write` (`Tx::security_id_for`).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::ntfs::{find_named_attribute, u32_at, u64_at, Ntfs, RawIndexEntry};
use super::volume::FileSystem;
use crate::ntos::io::parse::VolumeOpenSecurity;
use crate::ntos::ob::{object_access, object_security};
use crate::ntos::ps::process;
use crate::ntos::se::access_check::subject_of_token;
use crate::ntos::se::inherit_descriptor::Captured;
use crate::ntos::se::policy_descriptor::OwnedDescriptor;
use crate::ntos::se::token::tokens;
use crate::ntos::se::{access_evaluation, assign, query_descriptor, set_security};
use crate::rtl::KernelError;

/// O registro do $Secure.
pub const SECURE_RECORD: u64 = 9;
/// O primeiro SecurityId de um volume (o NextSecurityId de um $SII vazio).
pub const FIRST_SECURITY_ID: u32 = 0x100;
/// A distância entre uma entrada do $SDS e a cópia dela (e o tamanho de
/// cada metade de um bloco de 256 KB).
pub const SDS_MIRROR: u64 = 0x40000;
/// O GENERIC_MAPPING do IoFileObjectType (IopFileMapping 0x9838a0):
/// FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE e
/// FILE_ALL_ACCESS.
pub const FILE_MAPPING: [u32; 4] = [0x0012_0089, 0x0012_0116, 0x0012_00A0, 0x001F_01FF];

/// NtfsHashSecurityDescriptor (0x4f498): `rol(hash, 3) + dword` sobre os
/// dwords inteiros do descritor.
pub fn hash(descriptor: &[u8]) -> u32 {
    descriptor.chunks_exact(4).fold(0u32, |hash, word| hash.rotate_left(3).wrapping_add(u32::from_le_bytes([word[0], word[1], word[2], word[3]])))
}

/// SECURITY_DESCRIPTOR_HEADER: os dados das entradas do $SII e do $SDH e o
/// começo de cada entrada do $SDS. `length` conta os 20 bytes dele.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub hash: u32,
    pub id: u32,
    pub offset: u64,
    pub length: u32,
}

impl Header {
    pub const SIZE: usize = 20;

    pub fn parse(bytes: &[u8]) -> Option<Self> {
        (bytes.len() >= Self::SIZE).then(|| Self { hash: u32_at(bytes, 0), id: u32_at(bytes, 4), offset: u64_at(bytes, 8), length: u32_at(bytes, 16) })
    }

    pub fn bytes(&self) -> [u8; 20] {
        let mut bytes = [0u8; 20];
        bytes[0..4].copy_from_slice(&self.hash.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.id.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.offset.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.length.to_le_bytes());
        bytes
    }
}

impl Ntfs {
    /// As entradas do índice de visão `name` do registro (o $SII ou o $SDH
    /// do $Secure): a raiz residente e os blocos INDX do $INDEX_ALLOCATION
    /// de mesmo nome.
    pub fn view_entries(&self, record: &[u8], name: &str) -> Result<Vec<RawIndexEntry>, KernelError> {
        let root = find_named_attribute(record, 0x90, name)?.filter(|root| !root.non_resident).ok_or_else(|| KernelError::with_status("NTFS: indice de visao sem $INDEX_ROOT residente", 0xC000_0032))?;
        let allocation = find_named_attribute(record, 0xA0, name)?;
        self.index_entries(record, &root, allocation.as_ref())
    }

    /// O cabeçalho do SecurityId no $SII do registro do $Secure.
    pub fn security_header(&self, record: &[u8], id: u32) -> Result<Option<Header>, KernelError> {
        Ok(self.view_entries(record, "$SII")?.iter().filter(|entry| entry.key().len() == 4 && u32_at(entry.key(), 0) == id).find_map(|entry| entry.view_data().and_then(Header::parse)))
    }

    /// O descritor self-relative de um SecurityId: o cabeçalho do $SII e o
    /// descritor do $SDS depois dele. `Ok(None)` sem o id no $SII.
    pub fn security_descriptor(&self, id: u32) -> Result<Option<Arc<Vec<u8>>>, KernelError> {
        if let Some(found) = self.secure_cache.lock().get(&id) {
            return Ok(Some(found.clone()));
        }
        let _shared = self.resource().acquire_shared();
        let record = self.read_record(SECURE_RECORD)?;
        let Some(header) = self.security_header(&record, id)?.filter(|header| header.length as usize > Header::SIZE) else { return Ok(None) };
        let sds = find_named_attribute(&record, 0x80, "$SDS")?.ok_or_else(|| KernelError::with_status("NTFS: $Secure sem $SDS", 0xC000_0032))?;
        let length = header.length as u64 - Header::SIZE as u64;
        let bytes = self.read_attribute_range(&record, &sds, header.offset + Header::SIZE as u64, length)?;
        if bytes.len() as u64 != length {
            return Err(KernelError::with_status("NTFS: entrada do $SDS curta", 0xC000_0032));
        }
        let bytes = Arc::new(bytes);
        self.secure_cache.lock().insert(id, bytes.clone());
        Ok(Some(bytes))
    }

    /// O tamanho do $Secure: os descritores do $SII, o próximo SecurityId
    /// (o NextSecurityId do NtfsInitializeSecurity) e o tamanho do $SDS.
    pub fn secure_summary(&self) -> Result<(usize, u32, u64), KernelError> {
        let record = self.read_record(SECURE_RECORD)?;
        let ids: Vec<u32> = self.view_entries(&record, "$SII")?.iter().filter(|entry| entry.key().len() == 4).map(|entry| u32_at(entry.key(), 0)).collect();
        let next = ids.iter().max().map_or(FIRST_SECURITY_ID, |last| last + 1);
        let sds = find_named_attribute(&record, 0x80, "$SDS")?.map_or(0, |sds| if sds.non_resident { sds.real_size } else { sds.value.len() as u64 });
        Ok((ids.len(), next, sds))
    }

    /// O descritor de um arquivo pelo SecurityId do $STANDARD_INFORMATION;
    /// 0, ou um id que o $SII não tem, dá o primeiro do volume. `Ok(None)`
    /// sem o arquivo ou sem descritor nenhum no $Secure.
    pub fn file_security(&self, path: &str) -> Result<Option<Arc<Vec<u8>>>, KernelError> {
        let Some(stat) = self.stat(path)? else { return Ok(None) };
        if stat.security_id != 0 {
            if let Some(found) = self.security_descriptor(stat.security_id)? {
                return Ok(Some(found));
            }
        }
        self.security_descriptor(FIRST_SECURITY_ID)
    }
}

/// A linha do $Secure na montagem do volume de boot.
pub fn log_summary(volume: &Ntfs) {
    match volume.secure_summary() {
        Ok((count, next, sds)) => debug_print!("[ntfs] $Secure: {} descritores ($SII), proximo SecurityId {:#x}, $SDS {} bytes", count, next, sds),
        Err(error) => debug_print!("[ntfs] $Secure ilegivel: {}", error),
    }
}

/// O diretório pai de um caminho do volume (`/` para a raiz e os filhos dela).
pub fn parent_of(path: &str) -> &str {
    match path.trim_end_matches('/').rfind('/') {
        Some(0) | None => "/",
        Some(index) => &path[..index],
    }
}

/// O NTSTATUS de um erro do volume (STATUS_FILE_CORRUPT_ERROR sem um).
pub fn status_of(error: &KernelError) -> u32 {
    if error.status != 0 { error.status } else { 0xC000_0102 }
}

/// O token do SECURITY_SUBJECT_CONTEXT de quem abre: o efetivo da thread (o
/// de impersonação, quando há), ou o primário do processo corrente.
pub fn creator_token() -> u64 {
    object_access::subject().or_else(|| process::get_primary_token(process::get_current_process())).unwrap_or(0)
}

/// Os componentes de um descritor na forma do SeAssignSecurity.
fn captured(descriptor: &OwnedDescriptor) -> Captured {
    Captured { control: descriptor.control, owner: descriptor.owner.clone().unwrap_or_default(), group: descriptor.group.clone().unwrap_or_default(), dacl: descriptor.dacl.clone(), sacl: descriptor.sacl.clone() }
}

/// NtfsCacheSharedSecurityForCreate (0x138aa4) sobre componentes já lidos:
/// o descritor self-relative de um arquivo novo sob `parent`, com o
/// explícito dos OBJECT_ATTRIBUTES e o token de quem cria. `Err(NTSTATUS)`.
pub fn assign_for_create(parent: Option<&OwnedDescriptor>, explicit: Option<&OwnedDescriptor>, directory: bool, user_mode: bool, token: u64) -> Result<Vec<u8>, u32> {
    // SEF_FORCE_USER_MODE (0x2000) do NtfsCacheSharedSecurityForCreate
    // (0x138b19..0x138b3b); em KernelMode, SEF_AVOID_PRIVILEGE_CHECK |
    // SEF_AVOID_OWNER_CHECK.
    if user_mode {
        if let Some(explicit) = explicit {
            object_security::check_explicit_for_user(explicit, token)?;
        }
    }
    let flags = set_security::auto_inherit_flags(explicit, parent);
    let parent = parent.map(captured);
    let explicit = explicit.map(captured);
    let assigned = assign::assign_components_for_token(parent.as_ref(), explicit.as_ref(), &FILE_MAPPING, directory, flags, token)?;
    Ok(set_security::serialize_owned(&OwnedDescriptor { control: assigned.control, owner: Some(assigned.owner), group: Some(assigned.group), dacl: assigned.dacl, sacl: assigned.sacl }))
}

/// O descritor de um arquivo novo em `path` de um volume (o pai pelo
/// `query_security` dele, o token pelo [`creator_token`]); `None` quando o
/// volume não guarda segurança.
pub fn descriptor_for_create(volume: &dyn FileSystem, path: &str, explicit: Option<&OwnedDescriptor>, directory: bool, user_mode: bool) -> Option<Result<Vec<u8>, u32>> {
    let parent = match volume.query_security(parent_of(path))? {
        Ok(bytes) => query_descriptor::from_relative(&bytes),
        Err(error) => return Some(Err(status_of(&error))),
    };
    Some(assign_for_create(parent.as_ref(), explicit, directory, user_mode, creator_token()))
}

/// O descritor guardado de um caminho: `None` quando o volume não guarda
/// segurança, `Some(None)` num descritor ilegível (o SeAccessCheck nega).
fn descriptor_of(volume: &dyn FileSystem, path: &str) -> Result<Option<Option<OwnedDescriptor>>, u32> {
    match volume.query_security(path) {
        None => Ok(None),
        Some(Ok(bytes)) => Ok(Some(query_descriptor::from_relative(&bytes))),
        Some(Err(error)) => Err(status_of(&error)),
    }
}

/// NtfsAccessCheck (0x114af0): o acesso `desired` (mapeado) ao arquivo,
/// menos o já concedido, pelo SeAccessCheck em UserMode com o token da
/// abertura; sem conferência (KernelMode sem SL_FORCE_ACCESS_CHECK) ou num
/// volume sem segurança, o pedido inteiro. Uma recusa com DELETE ou
/// FILE_READ_ATTRIBUTES no pedido (0x114f45) ainda passa pelo pai:
/// FILE_LIST_DIRECTORY concede FILE_READ_ATTRIBUTES (0x1150b0) e
/// FILE_DELETE_CHILD concede DELETE (0x115251); o resto volta ao arquivo.
/// `Ok(acesso concedido)` ou `Err(NTSTATUS)`.
pub fn check(volume: &dyn FileSystem, path: &str, open: &VolumeOpenSecurity, desired: u32) -> Result<u32, u32> {
    let grant_all = || access_evaluation::kernel_mode_grant(desired, open.previously_granted, &FILE_MAPPING);
    if !open.check {
        return Ok(grant_all());
    }
    let Some(file) = descriptor_of(volume, path)? else { return Ok(grant_all()) };
    let remaining = desired & !open.previously_granted;
    if remaining == 0 {
        return Ok(open.previously_granted | desired);
    }
    let subject = subject_of_token(open.token).ok_or(0xC000_007Cu32)?;
    match access_evaluation::access_check(file.as_ref(), &subject, remaining, open.previously_granted, &FILE_MAPPING) {
        Ok(granted) => Ok(granted),
        Err(0xC000_0022) if remaining & 0x1_0080 != 0 && path != "/" => {
            let parent = descriptor_of(volume, parent_of(path))?.flatten();
            let mut extra = 0;
            if remaining & 0x80 != 0 && access_evaluation::access_check(parent.as_ref(), &subject, 0x1, 0, &FILE_MAPPING).is_ok() {
                extra |= 0x80;
            }
            if remaining & 0x1_0000 != 0 && access_evaluation::access_check(parent.as_ref(), &subject, 0x40, 0, &FILE_MAPPING).is_ok() {
                extra |= 0x1_0000;
            }
            if extra == 0 {
                return Err(0xC000_0022);
            }
            let rest = remaining & !extra;
            let granted = if rest == 0 { open.previously_granted } else { access_evaluation::access_check(file.as_ref(), &subject, rest, open.previously_granted, &FILE_MAPPING)? };
            Ok(granted | extra)
        }
        Err(status) => Err(status),
    }
}

/// CREATE_FLAG_TRAVERSE_CHECK do NtfsCommonCreate (0x10743c): sem
/// TOKEN_HAS_TRAVERSE_PRIVILEGE, FILE_TRAVERSE na raiz e em cada diretório
/// do caminho até o pai (0x1076bd → 0x108be3..0x108c13).
pub fn check_traverse(volume: &dyn FileSystem, path: &str, open: &VolumeOpenSecurity) -> Result<(), u32> {
    if !open.check || open.traverse {
        return Ok(());
    }
    let walked = VolumeOpenSecurity { previously_granted: 0, ..open.clone() };
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    let mut directory = String::new();
    for part in parts {
        let current = if directory.is_empty() { "/" } else { directory.as_str() };
        check(volume, current, &walked, 0x20)?;
        directory.push('/');
        directory.push_str(part);
    }
    Ok(())
}

/// NtfsCreateNewFile (0x135310..0x1353b4): FILE_ADD_SUBDIRECTORY (diretório)
/// ou FILE_ADD_FILE no pai, com ACCESS_SYSTEM_SECURITY quando pedido (nada
/// com TOKEN_HAS_RESTORE_PRIVILEGE); depois o pedido inteiro é concedido
/// (MAXIMUM_ALLOWED vira FILE_ALL_ACCESS), sem conferir o descritor do
/// arquivo novo. `Ok(acesso concedido)` ou `Err(NTSTATUS)`.
pub fn check_create(volume: &dyn FileSystem, parent: &str, open: &VolumeOpenSecurity, directory: bool, desired: u32) -> Result<u32, u32> {
    let mut parent_desired = (if directory { 4 } else { 2 }) | (desired & 0x0100_0000);
    if open.restore {
        parent_desired = 0;
    }
    if parent_desired != 0 {
        check(volume, parent, &VolumeOpenSecurity { previously_granted: 0, ..open.clone() }, parent_desired)?;
    }
    let mut granted = desired | open.previously_granted;
    if granted & 0x0200_0000 != 0 {
        granted = (granted | 0x1F_01FF) & !0x0200_0000;
    }
    Ok(granted)
}

/// O processo corrente para as linhas do `[filesec]`: pid:tid e o
/// ImageFileName.
fn caller() -> String {
    let process = process::get_current_process();
    let name: String = crate::ntos::mm::guest_memory::read_bytes(crate::ntos::ps::process_accessors::image_file_name(process), 15).into_iter().take_while(|&byte| byte != 0).map(|byte| byte as char).collect();
    alloc::format!("{}:{} {}", process::get_current_process_id(), process::get_current_thread_id(), name)
}

/// [Q-FILESEC etapa 2] A decisão do NtfsAccessCheck só registrada: a
/// abertura segue com o acesso `granted` de hoje. Uma recusa dá
/// `[filesec] negaria <pid:tid processo> <SID do usuário> <caminho>
/// desired=… granted=… status=…`.
pub fn audit(path: &str, open: &VolumeOpenSecurity, desired: u32, granted: u32, decision: Result<u32, u32>) {
    if let Err(status) = decision {
        let user = tokens::with(open.token, |token| crate::ntos::se::token::lowbox::sid_text(&token.user)).unwrap_or_default();
        debug_print!("[filesec] negaria {} {} {} desired={:#x} granted={:#x} status={:#x}", caller(), user, path, desired, granted, status);
    }
}

/// [`audit`] de uma abertura recusada antes da checagem (o
/// STATUS_BAD_IMPERSONATION_LEVEL do contexto de segurança).
pub fn audit_status(path: &str, granted: u32, status: u32) {
    debug_print!("[filesec] negaria {} - {} desired={:#x} granted={:#x} status={:#x}", caller(), path, granted, granted, status);
}

/// NtfsModifySecurity (0xdf2d4) do IRP_MJ_SET_SECURITY: as partes de
/// `information` do descritor capturado `captured` trocam as do descritor
/// atual do arquivo (o SeSetSecurityDescriptorInfoEx com AutoInheritFlags 0,
/// o dono validado pelo token efetivo, as ACLs mapeadas pelo mapeamento de
/// arquivo) e o resultado ganha o seu SecurityId. `None` quando o volume não
/// guarda segurança; senão o NTSTATUS.
pub fn modify(volume: &dyn FileSystem, path: &str, information: u32, captured: u64) -> Option<u32> {
    let current = match volume.query_security(path)? {
        Ok(bytes) => query_descriptor::from_relative(&bytes).unwrap_or_default(),
        Err(error) => return Some(status_of(&error)),
    };
    let modification = query_descriptor::read_descriptor(captured).unwrap_or_default();
    let merged = match set_security::merge(&current, information, &modification, 0, Some(FILE_MAPPING)) {
        Ok(merged) => merged,
        Err(status) => return Some(status),
    };
    Some(match volume.set_security(path, &set_security::serialize_owned(&merged))? {
        Ok(()) => 0,
        Err(error) => status_of(&error),
    })
}
