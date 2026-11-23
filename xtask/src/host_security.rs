//! Os descritores de segurança desta máquina para o volume NTFS e as hives
//! do convidado: a leitura (o descritor de um arquivo ou pasta, com o
//! rótulo obrigatório, e o de uma chave), o formato autorrelativo
//! ([`descriptor`]), a herança do NTFS e das chaves e a retirada dos SIDs de
//! conta (de domínio, de sessão de logon e do Azure AD), que nenhum
//! descritor do convidado leva.
//!
//! Os arquivos do Windows que o volume leva ([`system_nodes`]) ganham o
//! descritor que têm aqui (o dono TrustedInstaller e as ACEs de SYSTEM,
//! Administradores, Usuários, ALL APPLICATION PACKAGES e ALL RESTRICTED
//! APPLICATION PACKAGES de um arquivo de System32), sem SID de conta. A
//! raiz do volume, que no convidado responde por `C:\`, `C:\Windows` e
//! `C:\Windows\System32` (o achatamento do `nt_path_to_volume_path`), leva
//! o descritor de `C:\Windows\System32`, o pai de quase tudo o que o volume
//! leva. Uma pasta do volume casa com a pasta daqui subindo pelos dois
//! caminhos enquanto os nomes batem (`Fonts` com `C:\Windows\Fonts`,
//! `pt-BR` com `C:\Windows\System32\pt-BR`); uma pasta sem par, um arquivo
//! gerado (as hives, o PE do kernel) e um descritor ilegível daqui herdam
//! do pai no volume, com o dono Administradores e o grupo SYSTEM que o
//! SeAssignSecurity dá a um criador SYSTEM. Um descritor daqui com ACEs
//! herdadas é herdado de novo quando o pai no volume tem outro descritor
//! que o pai daqui.
//!
//! Fora do Windows nada é lido e o volume fica com o descritor comum.

use crate::ntfs_image::Node;
#[cfg(windows)]
use std::path::Path;
use std::path::PathBuf;

pub mod descriptor {
    //! Descritores de segurança autorrelativos: leitura, gravação, a herança
    //! das ACEs e a retirada dos SIDs de conta.

    /// SE_DACL_PRESENT, SE_DACL_AUTO_INHERITED, SE_DACL_PROTECTED e
    /// SE_SELF_RELATIVE.
    pub const DACL_PRESENT: u16 = 0x0004;
    pub const DACL_AUTO_INHERITED: u16 = 0x0400;
    pub const DACL_PROTECTED: u16 = 0x1000;
    pub const SELF_RELATIVE: u16 = 0x8000;
    /// Flags de herança das ACEs.
    pub const OBJECT_INHERIT: u8 = 0x01;
    pub const CONTAINER_INHERIT: u8 = 0x02;
    const NO_PROPAGATE: u8 = 0x04;
    pub const INHERIT_ONLY: u8 = 0x08;
    pub const INHERITED: u8 = 0x10;

    /// O mapeamento genérico de arquivo (IopFileMapping: FILE_GENERIC_READ,
    /// _WRITE, _EXECUTE e FILE_ALL_ACCESS) e o de chave (o KEY_MAPPING do
    /// Cm: KEY_READ, KEY_WRITE, KEY_EXECUTE | KEY_CREATE_LINK e
    /// KEY_ALL_ACCESS).
    pub const FILE_MAPPING: [u32; 4] = [0x0012_0089, 0x0012_0116, 0x0012_00A0, 0x001F_01FF];
    pub const KEY_MAPPING: [u32; 4] = [0x0002_0019, 0x0002_0006, 0x0002_0039, 0x000F_003F];

    /// Uma ACE: tipo, flags, máscara e SID nos tipos com o SID logo depois
    /// da máscara (permitir, negar, auditar, alarme, os de callback, o
    /// rótulo obrigatório, o atributo de recurso e a política de escopo),
    /// e os bytes depois do SID; nos outros tipos os bytes inteiros.
    #[derive(Clone, Debug, PartialEq)]
    pub struct Ace {
        pub kind: u8,
        pub flags: u8,
        pub mask: u32,
        pub sid: Option<Vec<u8>>,
        pub tail: Vec<u8>,
    }

    impl Ace {
        pub fn new(kind: u8, flags: u8, mask: u32, sid: Vec<u8>) -> Ace {
            Ace { kind, flags, mask, sid: Some(sid), tail: Vec::new() }
        }

        fn with(&self, flags: u8, mask: u32, sid: Option<Vec<u8>>) -> Ace {
            Ace { kind: self.kind, flags, mask, sid, tail: self.tail.clone() }
        }

        fn to_bytes(&self) -> Vec<u8> {
            let mut body = Vec::new();
            match &self.sid {
                Some(sid) => {
                    body.extend_from_slice(&self.mask.to_le_bytes());
                    body.extend_from_slice(sid);
                    body.extend_from_slice(&self.tail);
                }
                None => body.extend_from_slice(&self.tail),
            }
            let size = 4 + body.len();
            let mut bytes = vec![self.kind, self.flags];
            bytes.extend_from_slice(&(size as u16).to_le_bytes());
            bytes.extend_from_slice(&body);
            bytes
        }
    }

    /// Um descritor: o controle, o dono, o grupo, a SACL (bytes) e a DACL
    /// (revisão e ACEs).
    #[derive(Clone, Debug, PartialEq)]
    pub struct Descriptor {
        pub control: u16,
        pub owner: Option<Vec<u8>>,
        pub group: Option<Vec<u8>>,
        pub sacl: Option<Vec<u8>>,
        pub dacl: Option<(u8, Vec<Ace>)>,
    }

    fn word(bytes: &[u8], offset: usize) -> Option<u16> {
        Some(u16::from_le_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?))
    }

    fn dword(bytes: &[u8], offset: usize) -> Option<u32> {
        Some(u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?))
    }

    /// O SID que começa em `offset` (revisão 1, até 15 subautoridades).
    pub fn sid_at(bytes: &[u8], offset: usize) -> Option<Vec<u8>> {
        let count = *bytes.get(offset + 1)? as usize;
        if *bytes.get(offset)? != 1 || count > 15 {
            return None;
        }
        Some(bytes.get(offset..offset + 8 + count * 4)?.to_vec())
    }

    /// Se o tipo de ACE tem o SID logo depois da máscara: permitir, negar,
    /// auditar e alarme (0..3), os de callback sem objeto (9, 0xA, 0xD,
    /// 0xE), o rótulo obrigatório, o atributo de recurso, a política de
    /// escopo e o rótulo de confiança (0x11..0x14).
    fn has_sid(kind: u8) -> bool {
        matches!(kind, 0..=3 | 9 | 0x0A | 0x0D | 0x0E | 0x11..=0x14)
    }

    fn parse_acl(bytes: &[u8], offset: usize) -> Option<(u8, Vec<Ace>)> {
        let revision = *bytes.get(offset)?;
        let size = word(bytes, offset + 2)? as usize;
        let count = word(bytes, offset + 4)? as usize;
        let acl = bytes.get(offset..offset + size)?;
        let mut aces = Vec::new();
        let mut at = 8;
        for _ in 0..count {
            let kind = *acl.get(at)?;
            let flags = *acl.get(at + 1)?;
            let ace_size = word(acl, at + 2)? as usize;
            let ace = acl.get(at..at + ace_size)?;
            if ace_size < 4 {
                return None;
            }
            if has_sid(kind) {
                let sid = sid_at(ace, 8)?;
                let tail = ace.get(8 + sid.len()..)?.to_vec();
                aces.push(Ace { kind, flags, mask: dword(ace, 4)?, sid: Some(sid), tail });
            } else {
                aces.push(Ace { kind, flags, mask: 0, sid: None, tail: ace[4..].to_vec() });
            }
            at += ace_size;
        }
        Some((revision, aces))
    }

    fn acl_bytes(revision: u8, aces: &[Ace]) -> Vec<u8> {
        let body: Vec<u8> = aces.iter().flat_map(Ace::to_bytes).collect();
        let mut bytes = vec![revision, 0];
        bytes.extend_from_slice(&((8 + body.len()) as u16).to_le_bytes());
        bytes.extend_from_slice(&(aces.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&body);
        bytes
    }

    impl Descriptor {
        /// Lê um descritor autorrelativo.
        pub fn parse(bytes: &[u8]) -> Option<Descriptor> {
            let control = word(bytes, 2)?;
            if *bytes.first()? != 1 || control & SELF_RELATIVE == 0 {
                return None;
            }
            let at = |offset: usize| dword(bytes, offset).map(|value| value as usize).filter(|&value| value != 0);
            let owner = match at(4) {
                Some(offset) => Some(sid_at(bytes, offset)?),
                None => None,
            };
            let group = match at(8) {
                Some(offset) => Some(sid_at(bytes, offset)?),
                None => None,
            };
            let sacl = match at(12).filter(|_| control & 0x10 != 0) {
                Some(offset) => Some(bytes.get(offset..offset + word(bytes, offset + 2)? as usize)?.to_vec()),
                None => None,
            };
            let dacl = match at(16).filter(|_| control & DACL_PRESENT != 0) {
                Some(offset) => Some(parse_acl(bytes, offset)?),
                None => None,
            };
            Some(Descriptor { control, owner, group, sacl, dacl })
        }

        /// O descritor autorrelativo: o cabeçalho, a SACL, a DACL, o dono e
        /// o grupo, nessa ordem.
        pub fn to_bytes(&self) -> Vec<u8> {
            let mut bytes = vec![0u8; 20];
            bytes[0] = 1;
            let mut control = self.control | SELF_RELATIVE;
            let place = |bytes: &mut Vec<u8>, field: usize, part: Option<Vec<u8>>| {
                if let Some(part) = part {
                    let offset = bytes.len() as u32;
                    bytes[field..field + 4].copy_from_slice(&offset.to_le_bytes());
                    bytes.extend_from_slice(&part);
                }
            };
            place(&mut bytes, 12, self.sacl.clone());
            match &self.dacl {
                Some((revision, aces)) => {
                    control |= DACL_PRESENT;
                    place(&mut bytes, 16, Some(acl_bytes(*revision, aces)));
                }
                None => control &= !DACL_PRESENT,
            }
            place(&mut bytes, 4, self.owner.clone());
            place(&mut bytes, 8, self.group.clone());
            bytes[2..4].copy_from_slice(&control.to_le_bytes());
            bytes
        }

        pub fn dacl_protected(&self) -> bool {
            self.control & DACL_PROTECTED != 0
        }

        pub fn protect_dacl(&mut self) {
            self.control |= DACL_PROTECTED;
        }

        /// Se a DACL tem alguma ACE explícita (sem INHERITED_ACE).
        pub fn has_explicit_aces(&self) -> bool {
            self.dacl.as_ref().is_some_and(|(_, aces)| aces.iter().any(|ace| ace.flags & INHERITED == 0))
        }

        /// Todos os SIDs: dono, grupo e os das ACEs da DACL.
        pub fn sids(&self) -> impl Iterator<Item = &Vec<u8>> {
            self.owner.iter().chain(self.group.iter()).chain(self.dacl.iter().flat_map(|(_, aces)| aces.iter().filter_map(|ace| ace.sid.as_ref())))
        }

        /// Tira as ACEs com SID de conta e troca o dono ou o grupo de conta
        /// por Administradores ou SYSTEM; diz se mudou algo.
        pub fn remove_accounts(&mut self) -> bool {
            let mut changed = false;
            if let Some((_, aces)) = &mut self.dacl {
                let before = aces.len();
                aces.retain(|ace| !ace.sid.as_deref().is_some_and(is_account));
                changed |= aces.len() != before;
            }
            if self.owner.as_deref().is_some_and(is_account) {
                self.owner = Some(sid(5, &[32, 544]));
                changed = true;
            }
            if self.group.as_deref().is_some_and(is_account) {
                self.group = Some(sid(5, &[18]));
                changed = true;
            }
            // A SACL (só o rótulo obrigatório, que tem SID bem conhecido)
            // com um SID de conta sai inteira (SE_SACL_PRESENT, 0x10).
            if self.sacl.as_deref().is_some_and(|sacl| (0..sacl.len()).any(|at| sid_at(sacl, at).is_some_and(|sid| is_account(&sid)))) {
                self.sacl = None;
                self.control &= !0x0010;
                changed = true;
            }
            changed
        }
    }

    /// Um SID com a autoridade e as subautoridades dadas.
    pub fn sid(authority: u8, subauthorities: &[u32]) -> Vec<u8> {
        let mut bytes = vec![1, subauthorities.len() as u8, 0, 0, 0, 0, 0, authority];
        for value in subauthorities {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    /// O SID binário de `S-1-<autoridade>-<sub>…`.
    pub fn sid_from_text(text: &str) -> Option<Vec<u8>> {
        let mut parts = text.strip_prefix("S-1-").or_else(|| text.strip_prefix("s-1-"))?.split('-');
        let authority: u8 = parts.next()?.parse().ok()?;
        let subauthorities: Vec<u32> = parts.map(|part| part.parse().ok()).collect::<Option<_>>()?;
        (subauthorities.len() <= 15).then(|| sid(authority, &subauthorities))
    }

    /// `S-1-…` de um SID binário.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn sid_text(sid: &[u8]) -> String {
        let mut text = format!("S-1-{}", sid.get(7).copied().unwrap_or(0));
        for chunk in sid.get(8..).unwrap_or_default().chunks_exact(4) {
            text.push_str(&format!("-{}", u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])));
        }
        text
    }

    /// SID de conta: de domínio (S-1-5-21-…, as contas e os grupos de uma
    /// máquina ou domínio), de sessão de logon (S-1-5-5-…) ou do Azure AD
    /// (autoridade 12, S-1-12-1-…, o usuário de uma máquina ligada ao Azure
    /// AD). Os outros (os bem conhecidos, os de serviço S-1-5-80-… e os de
    /// capacidade S-1-15-…) são derivados de nomes e iguais em toda
    /// instalação.
    pub fn is_account(sid: &[u8]) -> bool {
        sid.len() >= 12 && sid[1] >= 1 && (sid[2..8] == [0, 0, 0, 0, 0, 5] && matches!(u32::from_le_bytes([sid[8], sid[9], sid[10], sid[11]]), 21 | 5) || sid[2..8] == [0, 0, 0, 0, 0, 12])
    }

    /// CREATOR OWNER, CREATOR GROUP, CREATOR OWNER SERVER e CREATOR GROUP
    /// SERVER (S-1-3-0..3): `Some(true)` para os de dono, `Some(false)` para
    /// os de grupo.
    fn creator(sid: &[u8]) -> Option<bool> {
        if sid.len() == 12 && sid[1] == 1 && sid[2..8] == [0, 0, 0, 0, 0, 3] {
            return match u32::from_le_bytes([sid[8], sid[9], sid[10], sid[11]]) {
                0 | 2 => Some(true),
                1 | 3 => Some(false),
                _ => None,
            };
        }
        None
    }

    /// Os direitos genéricos trocados pelos específicos de `mapping`
    /// (leitura, escrita, execução e tudo).
    fn map_generic(mask: u32, mapping: &[u32; 4]) -> u32 {
        let mut mapped = mask & 0x0FFF_FFFF;
        for (generic, specific) in [0x8000_0000u32, 0x4000_0000, 0x2000_0000, 0x1000_0000].into_iter().zip(mapping) {
            if mask & generic != 0 {
                mapped |= specific;
            }
        }
        mapped
    }

    /// As ACEs que um filho (pasta se `directory`) com o dono e o grupo
    /// dados herda da DACL do pai: num arquivo, cada ACE de herança de
    /// objeto vira efetiva; numa pasta, cada ACE de herança de contêiner
    /// vira efetiva e, se não for NO_PROPAGATE, segue para os netos. A ACE
    /// efetiva tem os direitos genéricos mapeados (o mapeamento de
    /// arquivo) e o CREATOR OWNER/GROUP trocado pelo dono/grupo; quando nada
    /// disso muda a ACE, uma só serve para o filho e os netos, senão a
    /// efetiva vem seguida da cópia só de herança com os flags do pai. Todas
    /// levam INHERITED_ACE.
    pub fn inherited_aces(parent: &[Ace], directory: bool, owner: &[u8], group: &[u8]) -> Vec<Ace> {
        inherited_aces_with(parent, directory, owner, group, &FILE_MAPPING, true)
    }

    /// [`inherited_aces`] com o mapeamento genérico dado; sem `creators`, uma
    /// ACE de CREATOR OWNER/GROUP não dá ACE efetiva no filho, só a cópia
    /// só de herança (a forma das chaves de uma instalação nova:
    /// `(A;CIIOID;KA;;;CO)` sem a efetiva do dono).
    pub fn inherited_aces_with(parent: &[Ace], directory: bool, owner: &[u8], group: &[u8], mapping: &[u32; 4], creators: bool) -> Vec<Ace> {
        let mut aces = Vec::new();
        for ace in parent {
            let inheritance = ace.flags & (OBJECT_INHERIT | CONTAINER_INHERIT);
            if inheritance == 0 {
                continue;
            }
            let applies = if directory { ace.flags & CONTAINER_INHERIT != 0 } else { ace.flags & OBJECT_INHERIT != 0 };
            let propagates = directory && ace.flags & NO_PROPAGATE == 0;
            let substitute = ace.sid.as_deref().and_then(creator);
            let generic = ace.sid.is_some() && ace.mask & 0xF000_0000 != 0;
            if applies && (creators || substitute.is_none()) {
                if propagates && substitute.is_none() && !generic {
                    aces.push(ace.with(inheritance | INHERITED, ace.mask, ace.sid.clone()));
                    continue;
                }
                let sid = match substitute {
                    Some(true) => Some(owner.to_vec()),
                    Some(false) => Some(group.to_vec()),
                    None => ace.sid.clone(),
                };
                let mask = if ace.sid.is_some() { map_generic(ace.mask, mapping) } else { ace.mask };
                aces.push(ace.with(INHERITED, mask, sid));
            }
            if propagates {
                aces.push(ace.with(inheritance | INHERIT_ONLY | INHERITED, ace.mask, ace.sid.clone()));
            }
        }
        aces
    }

    /// O descritor de um arquivo ou pasta (`directory`) criado por um
    /// processo do SYSTEM sem descritor próprio dentro de `parent`, como o
    /// SeAssignSecurity de um criador SYSTEM dá (dono Administradores, grupo
    /// SYSTEM): a DACL herdada pela herança do NTFS e
    /// SE_DACL_AUTO_INHERITED quando o pai o tem.
    pub fn inherited(parent: &Descriptor, directory: bool) -> Descriptor {
        let (owner, group) = (sid(5, &[32, 544]), sid(5, &[18]));
        let (revision, dacl) = match &parent.dacl {
            Some((revision, aces)) => (*revision, inherited_aces(aces, directory, &owner, &group)),
            None => (2, Vec::new()),
        };
        Descriptor { control: SELF_RELATIVE | DACL_PRESENT | (parent.control & DACL_AUTO_INHERITED), owner: Some(owner), group: Some(group), sacl: None, dacl: Some((revision, dacl)) }
    }

    /// O descritor de uma subchave sem descritor próprio dentro de
    /// `parent`, na forma das chaves de uma instalação nova: dono
    /// Administradores, grupo SYSTEM, a DACL herdada com o mapeamento de
    /// chave e sem a ACE efetiva do CREATOR OWNER, e SE_DACL_AUTO_INHERITED
    /// quando o pai o tem.
    pub fn inherited_key(parent: &Descriptor) -> Descriptor {
        let (owner, group) = (sid(5, &[32, 544]), sid(5, &[18]));
        let (revision, dacl) = match &parent.dacl {
            Some((revision, aces)) => (*revision, inherited_aces_with(aces, true, &owner, &group, &KEY_MAPPING, false)),
            None => (2, Vec::new()),
        };
        Descriptor { control: SELF_RELATIVE | DACL_PRESENT | (parent.control & DACL_AUTO_INHERITED), owner: Some(owner), group: Some(group), sacl: None, dacl: Some((revision, dacl)) }
    }

    /// Refaz a parte herdada da DACL de `child` a partir da DACL do pai:
    /// as ACEs explícitas ficam, as herdadas são as de [`inherited_aces`].
    /// Uma DACL protegida não herda.
    pub fn reinherit(child: &mut Descriptor, parent: &[Ace], directory: bool) {
        if child.dacl_protected() {
            return;
        }
        let owner = child.owner.clone().unwrap_or_else(|| sid(5, &[32, 544]));
        let group = child.group.clone().unwrap_or_else(|| sid(5, &[18]));
        let (revision, aces) = child.dacl.take().unwrap_or((2, Vec::new()));
        let mut kept: Vec<Ace> = aces.into_iter().filter(|ace| ace.flags & INHERITED == 0).collect();
        kept.extend(inherited_aces(parent, directory, &owner, &group));
        child.dacl = Some((revision, kept));
    }
}

/// O descritor final de uma entrada a partir do desta máquina: o DACL da
/// pasta conhecida (`known_dacl`), ou a herança refeita quando o pai mudou,
/// e sem SID de conta. Devolve o descritor e se ele mudou.
pub fn settle(host: &[u8], known_dacl: Option<&descriptor::Descriptor>, parent: Option<(&descriptor::Descriptor, bool)>, directory: bool) -> Option<(descriptor::Descriptor, bool)> {
    let mut settled = descriptor::Descriptor::parse(host)?;
    let mut changed = false;
    if let Some(known) = known_dacl {
        settled.dacl = known.dacl.clone();
        settled.protect_dacl();
        changed = true;
    } else if let Some((parent, true)) = parent {
        if let Some((_, aces)) = &parent.dacl {
            descriptor::reinherit(&mut settled, aces, directory);
            changed = true;
        }
    }
    changed |= settled.remove_accounts();
    Some((settled, changed))
}

#[cfg(windows)]
mod native {
    #[link(name = "advapi32")]
    extern "system" {
        pub fn GetKernelObjectSecurity(handle: isize, information: u32, descriptor: *mut u8, length: u32, needed: *mut u32) -> i32;
        pub fn ConvertStringSecurityDescriptorToSecurityDescriptorW(text: *const u16, revision: u32, descriptor: *mut *mut u8, length: *mut u32) -> i32;
        pub fn RegOpenKeyExW(key: isize, sub_key: *const u16, options: u32, desired: u32, result: *mut isize) -> i32;
        pub fn RegGetKeySecurity(key: isize, information: u32, descriptor: *mut u8, length: *mut u32) -> i32;
        pub fn RegCloseKey(key: isize) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        pub fn LocalFree(memory: *mut u8) -> *mut u8;
    }
}

/// O descritor (dono, grupo, DACL e rótulo obrigatório) do próprio caminho,
/// arquivo ou pasta, sem seguir uma junção. O rótulo
/// (LABEL_SECURITY_INFORMATION) não pede privilégio e mantém os rótulos de
/// integridade baixa, como o do LocalLow; sem SACL_SECURITY_INFORMATION as
/// ACEs de auditoria ficam fora.
#[cfg(windows)]
pub fn security_of(path: &Path) -> Option<Vec<u8>> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    /// READ_CONTROL; FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT.
    const READ_CONTROL: u32 = 0x0002_0000;
    const OPEN_FLAGS: u32 = 0x0200_0000 | 0x0020_0000;
    /// OWNER_, GROUP_, DACL_ e LABEL_SECURITY_INFORMATION.
    const INFORMATION: u32 = 1 | 2 | 4 | 0x10;
    let file = std::fs::OpenOptions::new().access_mode(READ_CONTROL).custom_flags(OPEN_FLAGS).open(path).ok()?;
    let handle = file.as_raw_handle() as isize;
    let mut needed = 0u32;
    // SAFETY: consulta de tamanho com buffer nulo.
    unsafe { native::GetKernelObjectSecurity(handle, INFORMATION, core::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return None;
    }
    let mut buffer = vec![0u8; needed as usize];
    // SAFETY: buffer com o tamanho pedido.
    let ok = unsafe { native::GetKernelObjectSecurity(handle, INFORMATION, buffer.as_mut_ptr(), needed, &mut needed) };
    (ok != 0).then(|| {
        buffer.truncate(needed as usize);
        buffer
    })
}

/// O descritor autorrelativo de um texto SDDL.
#[cfg(windows)]
pub fn from_sddl(text: &str) -> Option<Vec<u8>> {
    let wide: Vec<u16> = text.encode_utf16().chain([0]).collect();
    let mut pointer = core::ptr::null_mut();
    let mut length = 0u32;
    // SAFETY: texto terminado em NUL; a saída é liberada por LocalFree.
    if unsafe { native::ConvertStringSecurityDescriptorToSecurityDescriptorW(wide.as_ptr(), 1, &mut pointer, &mut length) } == 0 || pointer.is_null() {
        return None;
    }
    // SAFETY: `length` bytes alocados pela função.
    let bytes = unsafe { core::slice::from_raw_parts(pointer, length as usize) }.to_vec();
    // SAFETY: memória de LocalAlloc devolvida pela função.
    unsafe { native::LocalFree(pointer) };
    Some(bytes)
}

/// O descritor (dono, grupo e DACL) da chave `path` de `root` (HKLM ou
/// HKU) desta máquina, na visão de 64 bits.
#[cfg(windows)]
pub fn key_security_of(root: isize, path: &str) -> Option<Vec<u8>> {
    /// READ_CONTROL | KEY_WOW64_64KEY.
    const ACCESS: u32 = 0x0002_0000 | 0x100;
    /// OWNER_, GROUP_ e DACL_SECURITY_INFORMATION.
    const INFORMATION: u32 = 1 | 2 | 4;
    const ERROR_INSUFFICIENT_BUFFER: i32 = 122;
    let name: Vec<u16> = path.encode_utf16().chain([0]).collect();
    let mut key = 0isize;
    // SAFETY: nome terminado em NUL e saída válida.
    if unsafe { native::RegOpenKeyExW(root, name.as_ptr(), 0, ACCESS, &mut key) } != 0 {
        return None;
    }
    let mut length = 256u32;
    let mut buffer = vec![0u8; length as usize];
    // SAFETY: buffer com `length` bytes.
    let mut status = unsafe { native::RegGetKeySecurity(key, INFORMATION, buffer.as_mut_ptr(), &mut length) };
    if status == ERROR_INSUFFICIENT_BUFFER {
        buffer = vec![0u8; length as usize];
        // SAFETY: buffer com o tamanho pedido.
        status = unsafe { native::RegGetKeySecurity(key, INFORMATION, buffer.as_mut_ptr(), &mut length) };
    }
    // SAFETY: handle aberto acima e fechado uma vez.
    unsafe { native::RegCloseKey(key) };
    (status == 0).then(|| {
        buffer.truncate(length as usize);
        buffer
    })
}

/// O que o volume leva de segurança dos arquivos desta máquina: os nós
/// (arquivos e pastas com o descritor daqui ou o herdado) e o descritor da
/// raiz.
#[derive(Default)]
pub struct SystemSecurity {
    pub nodes: Vec<Node>,
    pub root: Option<Vec<u8>>,
}

/// De onde vem o descritor de uma pasta vazia do volume: da pasta daqui,
/// relativa ao `%SystemRoot%`, ao `%ProgramData%` ou ao `%ProgramFiles%`
/// (vazia: a própria pasta), ou o padrão do 19041, em SDDL (a pasta existe
/// numa instalação nova, e não depende de esta máquina a ter).
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Clone, Copy)]
enum Folder {
    Windows(&'static str),
    ProgramData(&'static str),
    ProgramFiles(&'static str),
    Stock(&'static str),
}

/// O descritor da raiz da unidade do sistema numa instalação nova do
/// Windows 10: a DACL e o rótulo obrigatório são os da regra
/// WN10-00-000095 do STIG do Windows 10 da DISA, que os dá como os padrão
/// (o `icacls c:\`): Administradores e SYSTEM com tudo, Usuários com leitura
/// e execução, Usuários autenticados com a alteração só nas subpastas e nos
/// arquivos e com a criação de pastas só na raiz, e o nível alto nos
/// arquivos. O dono é o TrustedInstaller, o mesmo da `\Windows` da imagem.
/// As quatro identidades são as do ClientRootAcl que o
/// CANNED_SECURITY::GenerateCannedClientRootAcl do ifsutil.dll 19041 (0x70a4)
/// põe na raiz de um volume novo formatado; a instalação troca a ACE de
/// Usuários autenticados da raiz.
#[cfg_attr(not(windows), allow(dead_code))]
const STOCK_ROOT: &str = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;OICIIO;0x1301bf;;;AU)(A;;LC;;;AU)S:(ML;OINPIO;NW;;;HI)";

/// O descritor de `System32\winevt\Logs` numa instalação nova: SYSTEM,
/// Administradores e o serviço EventLog (NT SERVICE\EventLog) com tudo e
/// Usuários autenticados com a leitura das pastas.
#[cfg_attr(not(windows), allow(dead_code))]
const STOCK_EVENT_LOGS: &str = "O:SYG:SYD:PAI(A;CI;FR;;;AU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-80-880578595-1860270145-482643319-2788375705-1540778122)";

/// As pastas vazias de uma instalação nova que a cadeia usa: o caminho da
/// instalação e de onde vem o descritor. O ProgramData, o AppRepository dele
/// (os bancos do StateRepository, que o serviço cria só dentro de uma pasta
/// que já existe; o conteúdo daqui não vai) com o `Packages` vazio (o AppXSvc
/// cria nele a pasta de metadados de cada pacote que registra, e não cria o
/// `Packages`), o Temp do Windows, os perfis do LocalService e do
/// NetworkService, o perfil do SYSTEM, o LogFiles e o `winevt\Logs` de
/// System32 (o wevtsvc.dll cria nele os `.evtx` dos canais), o Logs do
/// Windows e o `Program Files\WindowsApps` do volume de pacotes padrão (o
/// `SISPath` de `Appx\PackageVolumes`, que o AppXSvc confere em cada registro
/// pelo sistema de arquivos dele; os pacotes desta máquina não vão). A lista
/// certa sai do log de auditoria do passo 2 (as negações de pasta que falta).
#[cfg_attr(not(windows), allow(dead_code))]
const EMPTY_DIRECTORIES: &[(&str, Folder)] = &[
    ("ProgramData", Folder::ProgramData("")),
    ("ProgramData/Microsoft/Windows/AppRepository", Folder::ProgramData("Microsoft/Windows/AppRepository")),
    ("ProgramData/Microsoft/Windows/AppRepository/Packages", Folder::ProgramData("Microsoft/Windows/AppRepository/Packages")),
    ("Windows/Temp", Folder::Windows("Temp")),
    ("Windows/ServiceProfiles/LocalService", Folder::Windows("ServiceProfiles/LocalService")),
    ("Windows/ServiceProfiles/NetworkService", Folder::Windows("ServiceProfiles/NetworkService")),
    ("Windows/System32/config/systemprofile", Folder::Windows("System32/config/systemprofile")),
    ("Windows/System32/LogFiles", Folder::Windows("System32/LogFiles")),
    ("Windows/System32/winevt/Logs", Folder::Stock(STOCK_EVENT_LOGS)),
    ("Windows/Logs", Folder::Windows("Logs")),
    ("Program Files", Folder::ProgramFiles("")),
    ("Program Files/WindowsApps", Folder::ProgramFiles("WindowsApps")),
];

/// FILE_ATTRIBUTE_DIRECTORY e FILE_ATTRIBUTE_ARCHIVE: os atributos que o
/// volume já dá a uma pasta e a um arquivo sem nó (o nó só muda o
/// descritor).
#[cfg_attr(not(windows), allow(dead_code))]
const DIRECTORY_ATTRIBUTES: u32 = 0x10;
#[cfg_attr(not(windows), allow(dead_code))]
const FILE_ATTRIBUTES: u32 = 0x20;

/// O pai de um caminho do volume (`""` para a raiz).
#[cfg_attr(not(windows), allow(dead_code))]
fn parent_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

/// O caminho de uma pasta da instalação na raiz achatada do volume (o
/// conteúdo de System32 e o de `\Windows` na raiz).
#[cfg_attr(not(windows), allow(dead_code))]
fn flat_path(path: &str) -> &str {
    path.strip_prefix("Windows/System32/").or_else(|| path.strip_prefix("Windows/")).unwrap_or(path)
}

/// Os descritores dos arquivos que o volume leva: `files` são os caminhos
/// no volume com a origem daqui (`None` para um arquivo gerado; um caminho
/// terminado em '/' é uma pasta vazia, com a pasta daqui), `existing`
/// os nós que já têm descritor (os perfis de usuário, que ficam como
/// estão), `real` diz que o volume guarda cada arquivo no caminho da
/// instalação (a raiz com o descritor de [`STOCK_ROOT`]; na achatada, a raiz
/// faz o papel de System32 e fica com o descritor dele) e
/// `empty_directories` põe no volume as pastas vazias de
/// [`EMPTY_DIRECTORIES`] (o boot do smss).
pub fn system_nodes(files: &[(String, Option<PathBuf>)], existing: &[Node], real: bool, empty_directories: bool) -> SystemSecurity {
    #[cfg(windows)]
    {
        host::system_nodes(files, existing, real, empty_directories)
    }
    #[cfg(not(windows))]
    {
        let _ = (files, existing, real, empty_directories);
        SystemSecurity::default()
    }
}

#[cfg(windows)]
mod host {
    use super::descriptor::{self, Descriptor};
    use super::{flat_path, from_sddl, parent_of, security_of, settle, Folder, Node, SystemSecurity, DIRECTORY_ATTRIBUTES, EMPTY_DIRECTORIES, FILE_ATTRIBUTES, STOCK_ROOT};
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};

    /// O descritor daqui de `path`, sem SID de conta e herdado de novo de
    /// `volume_parent` quando o pai daqui (em `parents`, lido uma vez) tem
    /// outro descritor; `None` se ilegível.
    fn host_descriptor(path: &Path, volume_parent: &Descriptor, directory: bool, parents: &mut BTreeMap<PathBuf, Option<Descriptor>>) -> Option<Descriptor> {
        let raw = security_of(path)?;
        let host_parent = path.parent().and_then(|parent| parents.entry(parent.to_path_buf()).or_insert_with(|| security_of(parent).and_then(|raw| settle(&raw, None, None, true)).map(|(settled, _)| settled)).clone());
        let changed = host_parent.as_ref() != Some(volume_parent);
        settle(&raw, None, Some((volume_parent, changed)), directory).map(|(settled, _)| settled)
    }

    pub fn system_nodes(files: &[(String, Option<PathBuf>)], existing: &[Node], real: bool, empty_directories: bool) -> SystemSecurity {
        let windows = crate::windows_binaries::windows_directory();
        let stock = |sddl: &str| from_sddl(sddl).as_deref().and_then(Descriptor::parse);
        let system32 = windows.join("System32");
        let root = if real { stock(STOCK_ROOT) } else { security_of(&system32).and_then(|raw| settle(&raw, None, None, true)).map(|(settled, _)| settled) };
        let Some(root) = root else {
            println!("AVISO: descritor de {} ilegivel; o volume fica com o descritor comum", if real { String::from("raiz da unidade do sistema") } else { system32.display().to_string() });
            return SystemSecurity::default();
        };
        // As entradas: (caminho no volume, se é pasta, origem daqui); um nome
        // terminado em '/' é uma pasta vazia do volume.
        let mut entries: Vec<(String, bool, Option<PathBuf>)> = files.iter().map(|(path, host)| (String::from(path.trim_end_matches('/')), path.ends_with('/'), host.clone())).collect();
        // O descritor padrão do 19041 das pastas que o têm, pelo caminho em
        // maiúsculas.
        let mut stocked: BTreeMap<String, Descriptor> = BTreeMap::new();
        if empty_directories {
            let program_data = std::env::var("ProgramData").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("C:/ProgramData"));
            let program_files = std::env::var("ProgramW6432").or_else(|_| std::env::var("ProgramFiles")).map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("C:/Program Files"));
            for (installed, origin) in EMPTY_DIRECTORIES {
                let path = if real { *installed } else { flat_path(installed) };
                let host = match *origin {
                    Folder::Windows(relative) => Some(windows.join(relative)),
                    Folder::ProgramData("") => Some(program_data.clone()),
                    Folder::ProgramData(relative) => Some(program_data.join(relative)),
                    Folder::ProgramFiles("") => Some(program_files.clone()),
                    Folder::ProgramFiles(relative) => Some(program_files.join(relative)),
                    Folder::Stock(sddl) => {
                        stocked.extend(stock(sddl).map(|descriptor| (path.to_uppercase(), descriptor)));
                        None
                    }
                };
                // Uma pasta que esta máquina não deixa ver vai com o
                // descritor herdado do pai no volume.
                entries.push((String::from(path), true, host.filter(|host| host.is_dir())));
            }
        }
        let taken = |path: &str| existing.iter().any(|node| node.path.eq_ignore_ascii_case(path));
        // As pastas, cada pai antes dos filhos, e o par daqui de cada uma:
        // sobe pelos dois caminhos enquanto os nomes batem.
        let mut directories: Vec<String> = Vec::new();
        let mut pairs: BTreeMap<String, PathBuf> = BTreeMap::new();
        for (path, directory, host) in &entries {
            let components: Vec<&str> = path.split('/').collect();
            let depth = if *directory { components.len() } else { components.len() - 1 };
            for count in 1..=depth {
                let folder = components[..count].join("/");
                if !directories.iter().any(|known| known.eq_ignore_ascii_case(&folder)) {
                    directories.push(folder);
                }
            }
            let Some(host) = host else { continue };
            let mut volume = if *directory { path.as_str() } else { parent_of(path) };
            let mut folder = if *directory { Some(host.as_path()) } else { host.parent() };
            while let Some(current) = folder.filter(|_| !volume.is_empty()) {
                let leaf = volume.rsplit('/').next().unwrap_or(volume);
                if !current.file_name().and_then(|name| name.to_str()).is_some_and(|name| name.eq_ignore_ascii_case(leaf)) {
                    break;
                }
                pairs.entry(volume.to_uppercase()).or_insert_with(|| current.to_path_buf());
                volume = parent_of(volume);
                folder = current.parent();
            }
        }
        // O descritor final de cada pasta, pelo caminho em maiúsculas: a
        // raiz, as pastas dos perfis e as que saem daqui.
        let mut settled: BTreeMap<String, Descriptor> = BTreeMap::new();
        settled.insert(String::new(), root.clone());
        for node in existing.iter().filter(|node| node.directory) {
            if let Some(parsed) = node.security.as_deref().and_then(Descriptor::parse) {
                settled.insert(node.path.to_uppercase(), parsed);
            }
        }
        let mut parents = BTreeMap::new();
        let mut nodes = Vec::new();
        for folder in &directories {
            if taken(folder.as_str()) {
                continue;
            }
            let Some(parent) = settled.get(&parent_of(folder).to_uppercase()).cloned() else { continue };
            let upper = folder.to_uppercase();
            let own = stocked.get(&upper).cloned().or_else(|| pairs.get(&upper).and_then(|host| host_descriptor(host, &parent, true, &mut parents)));
            let security = own.unwrap_or_else(|| descriptor::inherited(&parent, true));
            nodes.push(Node { path: folder.clone(), directory: true, attributes: DIRECTORY_ATTRIBUTES, security: Some(security.to_bytes()) });
            settled.insert(upper, security);
        }
        let mut seen = BTreeSet::new();
        for (path, directory, host) in &entries {
            if *directory || taken(path.as_str()) || !seen.insert(path.to_uppercase()) {
                continue;
            }
            let Some(parent) = settled.get(&parent_of(path).to_uppercase()) else { continue };
            let own = host.as_ref().and_then(|host| host_descriptor(host, parent, false, &mut parents));
            let security = own.unwrap_or_else(|| descriptor::inherited(parent, false));
            nodes.push(Node { path: path.clone(), directory: false, attributes: FILE_ATTRIBUTES, security: Some(security.to_bytes()) });
        }
        SystemSecurity { nodes, root: Some(root.to_bytes()) }
    }
}

#[cfg(test)]
mod tests {
    use super::descriptor::{self, sid, Ace, Descriptor};

    const ALLOWED: u8 = 0;
    const OI: u8 = descriptor::OBJECT_INHERIT;
    const CI: u8 = descriptor::CONTAINER_INHERIT;
    const IO: u8 = descriptor::INHERIT_ONLY;
    const ID: u8 = descriptor::INHERITED;
    const KR: u32 = 0x0002_0019;
    const KA: u32 = 0x000F_003F;

    /// Os filhos da raiz de uma hive de máquina ficam na forma das chaves de
    /// uma instalação nova (`D:AI(A;CIID;KR;;;BU)…(A;CIIOID;KA;;;CO)…`), e os
    /// netos herdam o mesmo.
    #[test]
    fn key_children_inherit_like_a_fresh_install() {
        let (bu, ba, sy, co, ac) = (sid(5, &[32, 545]), sid(5, &[32, 544]), sid(5, &[18]), sid(3, &[0]), sid(15, &[2, 1]));
        let root = Descriptor {
            control: 0x1404,
            owner: Some(ba.clone()),
            group: Some(sy.clone()),
            sacl: None,
            dacl: Some((2, vec![Ace::new(ALLOWED, CI, KR, bu.clone()), Ace::new(ALLOWED, CI, KA, ba.clone()), Ace::new(ALLOWED, CI, KA, sy.clone()), Ace::new(ALLOWED, CI, KA, co.clone()), Ace::new(ALLOWED, CI, KR, ac.clone())])),
        };
        let child = descriptor::inherited_key(&root);
        assert_eq!(child.control, 0x8404);
        assert_eq!((child.owner.clone(), child.group.clone()), (Some(ba.clone()), Some(sy.clone())));
        assert_eq!(child.dacl, Some((2, vec![Ace::new(ALLOWED, CI | ID, KR, bu), Ace::new(ALLOWED, CI | ID, KA, ba), Ace::new(ALLOWED, CI | ID, KA, sy), Ace::new(ALLOWED, CI | IO | ID, KA, co), Ace::new(ALLOWED, CI | ID, KR, ac)])));
        assert_eq!(descriptor::inherited_key(&child).dacl, child.dacl);
    }

    /// Um arquivo gerado numa pasta de System32 herda as ACEs de objeto,
    /// com os genéricos mapeados e o CREATOR OWNER trocado pelo dono
    /// Administradores; as ACEs só da pasta não passam.
    #[test]
    fn a_generated_file_inherits_from_its_folder() {
        let (ba, sy, bu, co) = (sid(5, &[32, 544]), sid(5, &[18]), sid(5, &[32, 545]), sid(3, &[0]));
        let folder = Descriptor {
            control: 0x1404,
            owner: Some(sy.clone()),
            group: Some(sy.clone()),
            sacl: None,
            dacl: Some((2, vec![Ace::new(ALLOWED, OI | CI | IO, 0x1000_0000, co), Ace::new(ALLOWED, 0, 0x0013_01BF, sy.clone()), Ace::new(ALLOWED, OI | CI | IO, 0xA000_0000, bu.clone()), Ace::new(ALLOWED, 0, 0x0012_00A9, bu.clone())])),
        };
        let file = descriptor::inherited(&folder, false);
        assert_eq!((file.control, file.owner.clone(), file.group.clone()), (0x8404, Some(ba.clone()), Some(sy)));
        assert_eq!(file.dacl, Some((2, vec![Ace::new(ALLOWED, ID, 0x001F_01FF, ba), Ace::new(ALLOWED, ID, 0x0012_00A9, bu)])));
    }

    /// Os arquivos do Windows desta máquina: a raiz com o descritor de
    /// System32, nenhum descritor com SID de conta, e um arquivo gerado (uma
    /// hive) herdado do pai no volume.
    #[cfg(windows)]
    #[test]
    fn host_system_files_carry_no_account_sid() {
        let windows = crate::windows_binaries::windows_directory();
        let files = vec![
            (String::from("NTDLL.DLL"), Some(windows.join("System32/ntdll.dll"))),
            (String::from("Windows/System32/kernel32.dll"), Some(windows.join("System32/kernel32.dll"))),
            (String::from("Windows/System32/config/SYSTEM"), None),
        ];
        let security = super::system_nodes(&files, &[], false, false);
        let root = security.root.as_deref().and_then(Descriptor::parse).expect("raiz com o descritor de System32");
        assert!(root.sids().all(|sid| !descriptor::is_account(sid)));
        for node in &security.nodes {
            let parsed = node.security.as_deref().and_then(Descriptor::parse).expect("descritor legivel");
            assert!(parsed.sids().all(|sid| !descriptor::is_account(sid)), "{}: SID de conta", node.path);
        }
        let hive = security.nodes.iter().find(|node| node.path == "Windows/System32/config/SYSTEM").and_then(|node| node.security.as_deref()).and_then(Descriptor::parse).expect("no da hive");
        assert_eq!(hive.owner, Some(sid(5, &[32, 544])));
        assert!(hive.dacl.as_ref().is_some_and(|(_, aces)| !aces.is_empty() && aces.iter().all(|ace| ace.flags & ID != 0)));
        assert!(security.nodes.iter().any(|node| node.directory && node.path == "Windows/System32/config"));
    }

    /// No leiaute real a raiz tem o descritor padrão da unidade do sistema e
    /// as pastas vazias ficam nos caminhos da instalação, o `winevt\Logs` com
    /// o padrão do 19041 (o serviço EventLog), sem depender desta máquina; na
    /// raiz achatada, sem o `\Windows` e o System32 na frente.
    #[cfg(windows)]
    #[test]
    fn real_layout_folders_have_the_stock_descriptors() {
        let security = super::system_nodes(&[], &[], true, true);
        let root = security.root.as_deref().and_then(Descriptor::parse).expect("raiz padrao");
        let (authenticated, users) = (sid(5, &[11]), sid(5, &[32, 545]));
        let aces = &root.dacl.as_ref().expect("DACL da raiz").1;
        assert!(root.dacl_protected() && aces.len() == 5 && root.sids().all(|sid| !descriptor::is_account(sid)));
        assert!(aces.iter().any(|ace| ace.sid.as_ref() == Some(&authenticated) && ace.flags == 0 && ace.mask == 4));
        assert!(aces.iter().any(|ace| ace.sid.as_ref() == Some(&users) && ace.flags == OI | CI && ace.mask == 0x0012_00A9));
        let node = |path: &str| security.nodes.iter().find(|node| node.directory && node.path == path).unwrap_or_else(|| panic!("{path} fora do volume"));
        for path in ["Windows", "Windows/Temp", "Windows/System32", "Windows/System32/LogFiles", "Windows/System32/config/systemprofile", "Windows/ServiceProfiles/LocalService", "ProgramData", "Program Files/WindowsApps"] {
            let parsed = node(path).security.as_deref().and_then(Descriptor::parse).expect("descritor legivel");
            assert!(parsed.sids().all(|sid| !descriptor::is_account(sid)), "{path}: SID de conta");
        }
        let logs = node("Windows/System32/winevt/Logs").security.as_deref().and_then(Descriptor::parse).expect("winevt/Logs");
        let event_log = descriptor::sid_from_text("S-1-5-80-880578595-1860270145-482643319-2788375705-1540778122");
        assert!(logs.dacl_protected() && logs.dacl.as_ref().is_some_and(|(_, aces)| aces.len() == 4 && aces.iter().any(|ace| ace.sid == event_log)));
        let flat = super::system_nodes(&[], &[], false, true);
        for path in ["Temp", "config/systemprofile", "LogFiles", "Logs", "winevt/Logs", "ServiceProfiles/LocalService"] {
            assert!(flat.nodes.iter().any(|node| node.directory && node.path == path), "{path} fora da raiz achatada");
        }
        assert!(flat.nodes.iter().all(|node| !node.path.starts_with("Windows")));
    }
}
