//! STATUS_REPARSE de um file system na abertura de um arquivo: o que o
//! IopParseDevice e o ObpLookupObjectName do ntoskrnl 19041 fazem com o
//! reparse point que o file system encontrou no caminho.
//!
//! - IopSymlinkProcessReparse (0x683108) → IopGraftName (0x683164): só as
//!   tags IO_REPARSE_TAG_MOUNT_POINT, IO_REPARSE_TAG_SYMLINK e
//!   IO_REPARSE_TAG_GLOBAL_REPARSE chegam aqui; o buffer (o
//!   Irp->Tail.Overlay.AuxiliaryBuffer) precisa existir, com Reserved (o
//!   comprimento em bytes do nome que o file system não analisou, com a
//!   barra inicial) e ReparseDataLength abaixo de 0x4000, a tag do buffer
//!   no mesmo conjunto e um FILE_OBJECT.FileName não vazio — senão
//!   STATUS_IO_REPARSE_DATA_INVALID. GLOBAL_REPARSE dá
//!   STATUS_IO_REPARSE_TAG_INVALID.
//! - Junção (MOUNT_POINT) e link simbólico absoluto: o nome novo é o
//!   SubstituteName seguido do resto do nome (IopCopyOverNewPathSecure
//!   0x5cdc80: um Reserved maior que o FileName é
//!   STATUS_REPARSE_POINT_NOT_RESOLVED; a barra repetida na emenda some).
//!   A junção fica lembrada (IopSymlinkRememberJunction 0x682c94).
//! - Link simbólico relativo (SYMLINK_FLAG_RELATIVE; IopSymlinkApplyToOpenedName
//!   0x895430 e IopReplaceSymlinkPath 0x895120): o nome novo é o do
//!   dispositivo seguido do diretório do link — no nome como foi aberto,
//!   através das junções atravessadas — com o SubstituteName (ou o
//!   SubstituteName a partir da raiz do volume, quando começa por `\`) e o
//!   resto do nome, sem `.` nem `..` (FsRtlRemoveDotsFromPath 0x75f7c0: um
//!   `..` acima da raiz é STATUS_IO_REPARSE_DATA_INVALID).
//! - Uma junção no último componente faz a abertura reparsada pedir
//!   FILE_DIRECTORY_FILE quando ela não pede FILE_DIRECTORY_FILE nem
//!   FILE_NON_DIRECTORY_FILE (o `or ecx, 1` em OpenPacket->CreateOptions
//!   do IopParseDevice, 0x64fba9).
//! - ObpLookupObjectName (0x641640): cada STATUS_REPARSE gasta uma das 0x40
//!   voltas (o contador em `[rbp-0x50]`); ao chegar a zero,
//!   STATUS_OBJECT_NAME_NOT_FOUND. OBJ_DONT_REPARSE dá
//!   STATUS_REPARSE_POINT_ENCOUNTERED. O nome novo recomeça na raiz e
//!   precisa começar por `\` (senão STATUS_OBJECT_NAME_INVALID).
//! - O IopParseDevice seguinte (o OPEN_PACKET marcado com 0x10, e 0x08
//!   quando o dispositivo que devolveu o reparse é local) confere o
//!   dispositivo alvo: uma junção só cai num tipo local (CD_ROM, DISK,
//!   NAMED_PIPE, TAPE, VIRTUAL_DISK; máscara 0x1080020084); um link
//!   simbólico num local ou remoto (DFS, MULTI_UNC_PROVIDER,
//!   NETWORK_FILE_SYSTEM...; 0x60010000110040), senão
//!   STATUS_IO_REPARSE_DATA_INVALID; e o link passa pela política de
//!   avaliação (IopSymlinkEnforceEnabledTypes 0x6a64e4).
//! - A política (IopSymlinkQueryEnabledClasses 0x7cda3c, chamada pelo
//!   IopSymlinkRegistryCallback a cada mudança das chaves): os valores
//!   SymlinkLocalToLocalEvaluation (bit 1), SymlinkLocalToRemoteEvaluation
//!   (2), SymlinkRemoteToRemoteEvaluation (8) e
//!   SymlinkRemoteToLocalEvaluation (4) de
//!   `Software\Policies\Microsoft\Windows\FileSystems\NTFS`, ou, se ela
//!   falha, de `System\CurrentControlSet\Control\FileSystem`; os quatro
//!   valores precisam ser lidos, senão o valor anterior fica (de início, 0:
//!   nenhuma classe). Com as quatro ligadas (0xF) nada é conferido. Um
//!   link num volume local exige L2L ou L2R ligado e, com alvo local, L2L
//!   (STATUS_SYMLINK_CLASS_DISABLED); com alvo remoto a decisão segue para
//!   o redirector no ECP de abertura de rede. Um link num volume remoto
//!   precisa desse ECP, que só um redirector põe: sem ele,
//!   STATUS_SYMLINK_CLASS_DISABLED. O OpenNT relê os valores a cada
//!   avaliação, o que dá o mesmo resultado que a releitura a cada mudança.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::ntos::cm::registry;

pub const STATUS_REPARSE: u32 = 0x104;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_IO_REPARSE_TAG_INVALID: u32 = 0xC000_0276;
const STATUS_IO_REPARSE_DATA_INVALID: u32 = 0xC000_0278;
const STATUS_REPARSE_POINT_NOT_RESOLVED: u32 = 0xC000_0280;
const STATUS_REPARSE_POINT_ENCOUNTERED: u32 = 0xC000_050B;
const STATUS_SYMLINK_CLASS_DISABLED: u32 = 0xC000_0715;
pub const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
pub const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
const IO_REPARSE_TAG_GLOBAL_REPARSE: u32 = 0xA000_0019;
const SYMLINK_FLAG_RELATIVE: u32 = 1;
const OBJ_DONT_REPARSE: u32 = 0x1000;
pub const FILE_DEVICE_DISK: u32 = 7;
const FILE_DIRECTORY_FILE: u32 = 0x1;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
/// As voltas do ObpLookupObjectName (`mov dword [rbp-0x50], 0x40`).
pub const MAXIMUM_REPARSE: u32 = 0x40;
/// Limite de Reserved e de ReparseDataLength no IopGraftName.
const MAXIMUM_REPARSE_LENGTH: usize = 0x4000;
/// Tipos de dispositivo locais e remotos do IopParseDevice.
const LOCAL_DEVICE_TYPES: u64 = 0x0010_8002_0084;
const REMOTE_DEVICE_TYPES: u64 = 0x0060_0100_0011_0040;

/// Os valores da política e o bit de cada um, na ordem do
/// IopSymlinkQueryEnabledClasses.
const SYMLINK_CLASSES: [(&str, u32); 4] = [("SymlinkLocalToLocalEvaluation", 1), ("SymlinkLocalToRemoteEvaluation", 2), ("SymlinkRemoteToRemoteEvaluation", 8), ("SymlinkRemoteToLocalEvaluation", 4)];
const POLICY_KEY: &str = "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\FileSystems\\NTFS";
const CONTROL_KEY: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\FileSystem";

/// IopSymlinkEnabledTypes.
static ENABLED_TYPES: AtomicU32 = AtomicU32::new(0);

fn in_mask(mask: u64, device_type: u32) -> bool {
    device_type < 64 && (mask >> device_type) & 1 != 0
}

/// O dispositivo é local para o I/O Manager (a máscara do IopParseDevice).
pub fn is_local_device_type(device_type: u32) -> bool {
    in_mask(LOCAL_DEVICE_TYPES, device_type)
}

/// Os quatro valores de uma chave (o ZwQueryValueKey de
/// KeyValuePartialInformation com 0x14 bytes: até 8 bytes de dados).
fn query_enabled_classes(key: &str) -> Option<u32> {
    let mut enabled = 0;
    for (name, bit) in SYMLINK_CLASSES {
        let value = registry::read_value_by_path(key, name)?;
        if value.data.len() > 8 {
            return None;
        }
        let mut word = [0u8; 4];
        let count = value.data.len().min(4);
        word[..count].copy_from_slice(&value.data[..count]);
        if u32::from_le_bytes(word) != 0 {
            enabled += bit;
        }
    }
    Some(enabled)
}

/// IopSymlinkRegistryCallback: a política da chave de diretivas ou, sem
/// ela, a do Control\FileSystem; uma leitura que falha deixa o valor
/// anterior.
pub fn refresh_enabled_types() -> u32 {
    if let Some(enabled) = query_enabled_classes(POLICY_KEY).or_else(|| query_enabled_classes(CONTROL_KEY)) {
        ENABLED_TYPES.store(enabled, Ordering::Release);
    }
    ENABLED_TYPES.load(Ordering::Acquire)
}

/// IopSymlinkEnforceEnabledTypes sem ECP de abertura de rede (nenhum
/// redirector o põe no OpenNT): `source_local` = o link estava num
/// dispositivo local; `target_local` = o nome reparsado chegou a um.
pub fn enforce_enabled_types(source_local: bool, target_local: bool) -> Result<(), u32> {
    let enabled = refresh_enabled_types();
    if enabled == 0xF {
        return Ok(());
    }
    if !source_local || enabled & 3 == 0 || (target_local && enabled & 1 == 0) {
        return Err(STATUS_SYMLINK_CLASS_DISABLED);
    }
    Ok(())
}

/// O que o file system devolveu com STATUS_REPARSE e o que o
/// IopParseDevice sabe da abertura.
pub struct FsReparse<'a> {
    /// O REPARSE_DATA_BUFFER do Irp->Tail.Overlay.AuxiliaryBuffer.
    pub buffer: &'a [u8],
    /// Componentes do nome depois do reparse point (o Reserved, contado em
    /// componentes do FileName).
    pub tail_components: usize,
    /// O nome inteiro desta volta, como o ObpLookupObjectName o tem.
    pub opened_name: &'a str,
    /// O FILE_OBJECT.FileName: o nome relativo ao dispositivo (`\Users\x`).
    pub file_name: &'a str,
    /// O nome do dispositivo (ObQueryNameStringMode do DeviceObject).
    pub device_name: &'a str,
    /// O DeviceType do dispositivo que devolveu o reparse.
    pub device_type: u32,
    /// O nome relativo a esse dispositivo de um nome inteiro do mesmo
    /// volume (para lembrar as junções), `None` fora dele.
    pub device_relative: fn(&str) -> Option<String>,
}

/// O nome que a próxima volta abre.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reparsed {
    pub name: String,
    pub tag: u32,
    /// O reparse point era o último componente (Reserved == 0).
    pub final_component: bool,
}

impl Reparsed {
    /// As opções de criação da abertura reparsada: uma junção no último
    /// componente pede um diretório.
    pub fn create_options(&self, options: u32) -> u32 {
        if self.final_component && self.tag == IO_REPARSE_TAG_MOUNT_POINT && options & (FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE) == 0 {
            options | FILE_DIRECTORY_FILE
        } else {
            options
        }
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes.get(offset..offset + 2).map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes.get(offset..offset + 4).map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
}

/// Um nome UTF-16 do PathBuffer.
fn path_name(buffer: &[u8], start: usize, offset: u16, length: u16) -> Option<String> {
    let from = start + offset as usize;
    let bytes = buffer.get(from..from + length as usize)?;
    let units: Vec<u16> = bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    Some(String::from_utf16_lossy(&units))
}

/// Os últimos `count` componentes de `name`, com a barra inicial (o
/// trecho que o file system não analisou).
fn tail_of(name: &str, count: usize) -> String {
    if count == 0 {
        return String::new();
    }
    let parts: Vec<&str> = name.split('\\').filter(|part| !part.is_empty()).collect();
    let start = parts.len().saturating_sub(count);
    parts[start..].iter().map(|part| alloc::format!("\\{part}")).collect()
}

/// `name` sem os últimos `tail` bytes de texto (`tail` é sufixo dele).
fn without_tail<'a>(name: &'a str, tail: &str) -> &'a str {
    let lower = name.to_lowercase();
    if !tail.is_empty() && lower.ends_with(&tail.to_lowercase()) {
        &name[..name.len() - tail.len()]
    } else {
        name
    }
}

/// O começo de `name` é `prefix` inteiro, num limite de componente.
fn component_prefix(name: &str, prefix: &str) -> Option<usize> {
    let prefix = prefix.trim_end_matches('\\');
    if name.len() < prefix.len() || !name[..prefix.len()].eq_ignore_ascii_case(prefix) {
        return None;
    }
    (name.len() == prefix.len() || name.as_bytes()[prefix.len()] == b'\\').then_some(prefix.len())
}

/// A emenda do IopCopyOverNewPathSecure: `head` e `tail`, sem a barra
/// repetida.
fn join(head: &str, tail: &str) -> String {
    if head.ends_with('\\') && tail.starts_with('\\') {
        alloc::format!("{head}{}", &tail[1..])
    } else {
        alloc::format!("{head}{tail}")
    }
}

/// FsRtlRemoveDotsFromPath: barras repetidas e `.` somem, `..` volta um
/// componente (acima da raiz, STATUS_IO_REPARSE_DATA_INVALID); a barra
/// final fica.
pub fn remove_dots(path: &str) -> Result<String, u32> {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('\\') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(STATUS_IO_REPARSE_DATA_INVALID);
                }
            }
            part => parts.push(part),
        }
    }
    let mut result: String = parts.iter().map(|part| alloc::format!("\\{part}")).collect();
    if result.is_empty() || (path.ends_with('\\') && path.len() > 1) {
        result.push('\\');
    }
    Ok(result)
}

// ---- o volume de boot (o NTFS do kernel, sem pilha de IRP) ------------------

/// O STATUS_REPARSE do volume de boot: o buffer do reparse point, os
/// componentes do nome depois dele e o FILE_OBJECT.FileName da abertura
/// (o nome relativo ao dispositivo, `\Users\x`).
pub struct VolumeReparse {
    pub buffer: Vec<u8>,
    pub tail_components: usize,
    pub file_name: String,
}

impl VolumeReparse {
    /// O IopGraftName do reparse em `walk`; `opened` é o nome desta volta.
    /// O dispositivo é o do volume (`\Device\KernelVolume1`, FILE_DEVICE_DISK).
    pub fn graft(&self, walk: &mut NameWalk, opened: &str) -> Result<Reparsed, u32> {
        let device_name = crate::drivers::fs::volume_device::device_path(crate::drivers::fs::ntfs::DEVICE_INDEX);
        walk.graft(&FsReparse { buffer: &self.buffer, tail_components: self.tail_components, opened_name: opened, file_name: &self.file_name, device_name: &device_name, device_type: FILE_DEVICE_DISK, device_relative: crate::drivers::fs::volume_files::nt_path_to_device_name })
    }
}

/// O reparse point que uma abertura de `name` (caminho `path` no volume de
/// boot) encontra: um intermediário, ou o último sem
/// FILE_OPEN_REPARSE_POINT (`Ntfs::find_reparse`).
pub fn boot_volume_reparse(volume: &crate::drivers::fs::ntfs::Ntfs, name: &str, path: &str, open_reparse_point: bool) -> Result<Option<VolumeReparse>, crate::rtl::KernelError> {
    let Some(hit) = volume.find_reparse(path, open_reparse_point)? else { return Ok(None) };
    let file_name = crate::drivers::fs::volume_files::nt_path_to_device_name(name).unwrap_or_else(|| path.replace('/', "\\"));
    Ok(Some(VolumeReparse { buffer: hit.buffer, tail_components: hit.tail_components, file_name }))
}

/// A busca de um nome entre os reparses: o contador do
/// ObpLookupObjectName, os OBJ_* da abertura, o reparse pendente do
/// OPEN_PACKET (tag e se o dispositivo de origem é local) e as junções já
/// atravessadas (nome visível, nome substituto, ambos relativos ao
/// dispositivo).
pub struct NameWalk {
    remaining: u32,
    attributes: u32,
    pending: Option<(u32, bool)>,
    junctions: Vec<(String, String)>,
}

impl NameWalk {
    pub fn new(object_attributes: u32) -> NameWalk {
        NameWalk { remaining: MAXIMUM_REPARSE, attributes: object_attributes, pending: None, junctions: Vec::new() }
    }

    /// O começo do IopParseDevice que recebe o nome reparsado: o tipo do
    /// dispositivo alvo contra a tag e a política de links.
    pub fn arrive(&mut self, device_type: u32) -> Result<(), u32> {
        let Some((tag, source_local)) = self.pending.take() else { return Ok(()) };
        let local = is_local_device_type(device_type);
        if tag == IO_REPARSE_TAG_MOUNT_POINT {
            return if local { Ok(()) } else { Err(STATUS_IO_REPARSE_DATA_INVALID) };
        }
        if !local && !in_mask(REMOTE_DEVICE_TYPES, device_type) {
            return Err(STATUS_IO_REPARSE_DATA_INVALID);
        }
        enforce_enabled_types(source_local, local)
    }

    /// IopGraftName: o nome novo pelo reparse point que o file system
    /// devolveu.
    pub fn graft(&mut self, reparse: &FsReparse) -> Result<Reparsed, u32> {
        let buffer = reparse.buffer;
        let tail = tail_of(reparse.file_name, reparse.tail_components);
        let reserved = tail.encode_utf16().count() * 2;
        let (Some(tag), Some(data_length)) = (u32_at(buffer, 0), u16_at(buffer, 4)) else { return Err(STATUS_IO_REPARSE_DATA_INVALID) };
        if reserved >= MAXIMUM_REPARSE_LENGTH || data_length as usize >= MAXIMUM_REPARSE_LENGTH || !matches!(tag, IO_REPARSE_TAG_MOUNT_POINT | IO_REPARSE_TAG_SYMLINK | IO_REPARSE_TAG_GLOBAL_REPARSE) || reparse.file_name.is_empty() {
            return Err(STATUS_IO_REPARSE_DATA_INVALID);
        }
        let (substitute, relative) = match tag {
            IO_REPARSE_TAG_MOUNT_POINT => (u16_at(buffer, 8).zip(u16_at(buffer, 10)).and_then(|(offset, length)| path_name(buffer, 0x10, offset, length)), false),
            IO_REPARSE_TAG_SYMLINK => (u16_at(buffer, 8).zip(u16_at(buffer, 10)).and_then(|(offset, length)| path_name(buffer, 0x14, offset, length)), u32_at(buffer, 0x10).is_some_and(|flags| flags & SYMLINK_FLAG_RELATIVE != 0)),
            _ => return Err(STATUS_IO_REPARSE_TAG_INVALID),
        };
        let substitute = substitute.ok_or(STATUS_IO_REPARSE_DATA_INVALID)?;
        let name = if relative {
            self.relative_name(reparse, &substitute, &tail)?
        } else {
            if reserved > reparse.file_name.encode_utf16().count() * 2 {
                return Err(STATUS_REPARSE_POINT_NOT_RESOLVED);
            }
            join(&substitute, &tail)
        };
        if tag == IO_REPARSE_TAG_MOUNT_POINT {
            let visible = without_tail(reparse.file_name, &tail);
            if let Some(substituted) = (reparse.device_relative)(&substitute) {
                self.junctions.push((String::from(visible), substituted));
            }
        }
        self.pending = Some((tag, is_local_device_type(reparse.device_type)));
        Ok(Reparsed { name, tag, final_component: tail.is_empty() })
    }

    /// IopSymlinkApplyToOpenedName/IopReplaceSymlinkPath: o diretório do
    /// link no nome aberto (a junção atravessada por último que cobre o
    /// caminho devolve o nome visível dele), o SubstituteName e o resto.
    fn relative_name(&self, reparse: &FsReparse, substitute: &str, tail: &str) -> Result<String, u32> {
        let mut link = String::from(without_tail(reparse.file_name, tail));
        for (visible, substituted) in self.junctions.iter().rev() {
            if let Some(length) = component_prefix(&link, substituted) {
                link = alloc::format!("{}{}", visible.trim_end_matches('\\'), &link[length..]);
                break;
            }
        }
        let path = if substitute.starts_with('\\') {
            String::from(substitute)
        } else {
            let Some(separator) = link.rfind('\\') else { return Err(STATUS_IO_REPARSE_DATA_INVALID) };
            alloc::format!("{}{}", &link[..=separator], substitute)
        };
        let path = remove_dots(&join(&path, tail))?;
        Ok(alloc::format!("{}{}", reparse.device_name.trim_end_matches('\\'), path))
    }

    /// O ObpLookupObjectName diante de STATUS_REPARSE: OBJ_DONT_REPARSE, uma
    /// volta a menos e o nome novo, que recomeça na raiz.
    pub fn restart(&mut self, name: &str) -> Result<(), u32> {
        if self.attributes & OBJ_DONT_REPARSE != 0 {
            return Err(STATUS_REPARSE_POINT_ENCOUNTERED);
        }
        self.remaining -= 1;
        if self.remaining == 0 {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        if !name.starts_with('\\') {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        Ok(())
    }
}
