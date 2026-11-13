//! Tunneling de nomes — fsrtl\tunnel.c (FsRtl*TunnelCache*[Ex]).
//!
//! Motor compartilhado: as rotinas Ex (grupo "fsrtl-tunnel", ntfs.sys) e as
//! clássicas (grupo "fsrtl-tunnel-cache": Initialize/Add/Find/DeleteKey/Delete,
//! fastfat/exfat/ntfs), que no NT são invólucros das Ex.
//!
//! ntoskrnl 10.0.19045: FsRtlInitializeTunnelCache 0x6a1540; FsRtlAddToTunnelCache
//! 0x88b660 -> FsRtlAddToTunnelCacheEx 0x6689e0 (Flags = KeyByShortName ? 2 : 0);
//! FsRtlFindInTunnelCache 0x88b6a0 -> FsRtlFindInTunnelCacheEx 0x668870
//! (Flags 0); FsRtlDeleteKeyFromTunnelCache 0x6687a0; FsRtlDeleteTunnelCache
//! 0x76e8a0; FsRtlCompareNodeAndKey 0x2f81f8; FsRtlPruneTunnelCache 0x668d04;
//! FsRtlInitializeTunnels 0xa6c04c (FsRtlGetTunnelParameterValue).
//!
//! TUNNEL (`extra_fs_fat::Tunnel`, 0x58): Mutex, Cache, TimerQueue,
//! NumEntries. A API pública recebe endereços (TUNNEL, UNICODE_STRINGs,
//! dados), como os adaptadores dos dois grupos a chamam. Os TUNNEL_NODE
//! (DirKey, Flags, LongName, ShortName, dados, CreateTime) são privados do
//! FsRtl: aqui ficam numa tabela por TUNNEL em ordem de criação (a ordem da
//! TimerQueue); a cabeça da TimerQueue fica vazia e NumEntries é publicado.
//!
//! Chave de um nó: (DirKey, ShortName se Flags & 2 senão LongName). A
//! comparação é RtlCompareUnicodeString sem caixa e, com Flags & 1 do
//! chamador, também com caixa. A poda tira nós com CreateTime fora de
//! [agora - TunnelMaxAge, agora] e os mais antigos acima de TunnelMaxEntries.
//! Parâmetros de HKLM\System\CurrentControlSet\Control\FileSystem
//! (MaximumTunnelEntries, MaximumTunnelEntryAgeInSeconds); sem as chaves:
//! 256 entradas (o ramo de 1024 do NT depende de MmRegistryState, que o
//! OpenNT não tem) e 15 s; idade 0 desliga o tunelamento.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::ntos::cm::registry;
use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::extra_fs_fat::Tunnel;
use crate::ntos::inc::types::UnicodeString;
use crate::ntos::ke::{clock, fast_mutex};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::unicode_case;
use crate::rtl::{KernelError, SpinLock};

const DEFAULT_MAX_ENTRIES: u32 = 256;
const DEFAULT_MAX_AGE_SECONDS: u32 = 15;
const PARAMETERS_PATH: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\FileSystem";
const LONG_NAME_TAG: u32 = 0x346E_7554; // 'Tun4'
pub const FLAG_CASE_SENSITIVE: u32 = 1;
pub const FLAG_KEY_BY_SHORT_NAME: u32 = 2;

struct Node {
    directory: u64,
    key_by_short_name: bool,
    short_name: Vec<u16>,
    long_name: Vec<u16>,
    data: Vec<u8>,
    created: u64,
}

impl Node {
    fn key(&self) -> &[u16] {
        if self.key_by_short_name { &self.short_name } else { &self.long_name }
    }
}

static CACHES: SpinLock<BTreeMap<u64, Vec<Node>>> = SpinLock::new(BTreeMap::new());
static PARAMETERS: SpinLock<Option<(u32, u64)>> = SpinLock::new(None);

fn registry_dword(name: &str) -> Option<u32> {
    let value = registry::read_value_by_path(PARAMETERS_PATH, name)?;
    (value.value_type == 4 && value.data.len() >= 4).then(|| u32::from_le_bytes([value.data[0], value.data[1], value.data[2], value.data[3]]))
}

/// (TunnelMaxEntries, TunnelMaxAge em 100 ns), como FsRtlInitializeTunnels.
pub fn parameters() -> (u32, u64) {
    let mut slot = PARAMETERS.lock();
    if let Some(values) = *slot {
        return values;
    }
    let mut entries = registry_dword("MaximumTunnelEntries").unwrap_or(DEFAULT_MAX_ENTRIES);
    let age = registry_dword("MaximumTunnelEntryAgeInSeconds").unwrap_or(DEFAULT_MAX_AGE_SECONDS);
    if age == 0 {
        entries = 0;
    }
    let values = (entries, (age as u64).wrapping_mul(10_000_000) & 0xFFFF_FFFF);
    *slot = Some(values);
    values
}

fn tunnel_at(cache: u64) -> &'static Tunnel {
    // SAFETY: o TUNNEL do FS (inicializado por FsRtlInitializeTunnelCache).
    unsafe { Tunnel::at(cache) }
}

fn string_at(string: u64) -> &'static UnicodeString {
    // SAFETY: as PUNICODE_STRING de kernel passadas pelo FS.
    unsafe { UnicodeString::at(string) }
}

fn read_string(string: &UnicodeString) -> Vec<u16> {
    let bytes = guest::read_bytes(string.buffer.get(), (string.length.get() & !1) as usize);
    bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect()
}

fn units_to_bytes(units: &[u16]) -> Vec<u8> {
    units.iter().flat_map(|unit| unit.to_le_bytes()).collect()
}

fn reset_header(cache: &Tunnel) {
    cache.cache.set(0);
    cache.timer_queue.flink.set(cache.timer_queue.address());
    cache.timer_queue.blink.set(cache.timer_queue.address());
    cache.num_entries.set(0);
}

/// FsRtlCompareNodeAndKey: igualdade sem caixa e, com Flags & 1, com caixa.
fn same_key(node_key: &[u16], key: &[u16], case_sensitive: bool) -> Result<bool, KernelError> {
    if node_key.len() != key.len() || unicode_case::upcase_units(node_key)? != unicode_case::upcase_units(key)? {
        return Ok(false);
    }
    Ok(!case_sensitive || node_key == key)
}

/// FsRtlPruneTunnelCache.
fn prune(nodes: &mut Vec<Node>, now: u64, max_entries: u32, max_age: u64) {
    let oldest = now.wrapping_sub(max_age) as i64;
    while nodes.first().is_some_and(|node| (node.created as i64) < oldest || (node.created as i64) > now as i64) {
        nodes.remove(0);
    }
    while nodes.len() > max_entries as usize {
        nodes.remove(0);
    }
}

fn with_cache<T>(cache: &Tunnel, body: impl FnOnce(&mut Vec<Node>) -> Result<T, KernelError>) -> Result<T, KernelError> {
    let mutex = cache.mutex.address();
    fast_mutex::acquire(mutex)?;
    let result = {
        let mut caches = CACHES.lock();
        let nodes = caches.entry(cache.address()).or_default();
        let result = body(nodes);
        cache.num_entries.set(nodes.len() as u16);
        result
    };
    fast_mutex::release(mutex)?;
    result
}

/// FsRtlInitializeTunnelCache(Cache).
pub fn initialize(cache: u64) {
    let tunnel = tunnel_at(cache);
    fast_mutex::initialize(tunnel.mutex.address());
    reset_header(tunnel);
    CACHES.lock().insert(cache, Vec::new());
}

/// FsRtlAddToTunnelCacheEx(Cache, DirectoryKey, ShortName, LongName, Flags,
/// DataLength, Data): substitui o nó de mesma chave; sem tunelamento
/// (TunnelMaxEntries 0) não faz nada.
#[allow(clippy::too_many_arguments)]
pub fn add_ex(cache: u64, directory: u64, short_name: u64, long_name: u64, flags: u32, data_length: u32, data: u64) -> Result<(), KernelError> {
    let (max_entries, max_age) = parameters();
    if max_entries == 0 {
        return Ok(());
    }
    let created = clock::system_time_100ns();
    let node = Node {
        directory,
        key_by_short_name: flags & FLAG_KEY_BY_SHORT_NAME != 0,
        short_name: read_string(string_at(short_name)),
        long_name: read_string(string_at(long_name)),
        data: guest::read_bytes(data, data_length as usize),
        created,
    };
    let case_sensitive = flags & FLAG_CASE_SENSITIVE != 0;
    with_cache(tunnel_at(cache), |nodes| {
        let mut index = 0;
        while index < nodes.len() {
            if nodes[index].directory == node.directory && same_key(nodes[index].key(), node.key(), case_sensitive)? {
                nodes.remove(index);
            } else {
                index += 1;
            }
        }
        nodes.push(node);
        prune(nodes, created, max_entries, max_age);
        Ok(())
    })
}

/// RtlCopyUnicodeString: até MaximumLength, com NUL quando cabe.
fn copy_string(string: &UnicodeString, units: &[u16]) {
    let capacity = string.maximum_length.get() as usize / 2;
    let count = units.len().min(capacity);
    let mut bytes = units_to_bytes(&units[..count]);
    if count < capacity {
        bytes.extend_from_slice(&[0, 0]);
    }
    guest::write_bytes(string.buffer.get(), &bytes);
    string.length.set(count as u16 * 2);
}

/// FsRtlFindInTunnelCacheEx(Cache, DirectoryKey, Name, ShortName, LongName,
/// Flags, *DataLength, Data): nome curto por RtlCopyUnicodeString; o longo
/// num buffer novo ('Tun4', PagedPool|RAISE) do tamanho exato se não couber.
#[allow(clippy::too_many_arguments)]
pub fn find_ex(cache: u64, directory: u64, name: u64, short_name: u64, long_name: u64, flags: u32, data_length: u64, data: u64) -> Result<bool, KernelError> {
    let (max_entries, max_age) = parameters();
    if max_entries == 0 {
        return Ok(false);
    }
    let key = read_string(string_at(name));
    let case_sensitive = flags & FLAG_CASE_SENSITIVE != 0;
    let now = clock::system_time_100ns();
    let found = with_cache(tunnel_at(cache), |nodes| {
        prune(nodes, now, max_entries, max_age);
        for node in nodes.iter() {
            if node.directory == directory && same_key(node.key(), &key, case_sensitive)? {
                return Ok(Some((node.short_name.clone(), node.long_name.clone(), node.data.clone())));
            }
        }
        Ok(None)
    })?;
    let Some((short, long, bytes)) = found else { return Ok(false) };
    copy_string(string_at(short_name), &short);
    let long_name = string_at(long_name);
    let long_bytes = long.len() as u64 * 2;
    if (long_name.maximum_length.get() as u64) < long_bytes {
        let buffer = pool_allocation::allocate_tagged(0x11, long_bytes, LONG_NAME_TAG)?;
        long_name.buffer.set(buffer);
        long_name.maximum_length.set(long_bytes as u16);
        long_name.length.set(long_bytes as u16);
        guest::write_bytes(buffer, &units_to_bytes(&long));
    } else {
        copy_string(long_name, &long);
    }
    guest::write_bytes(data, &bytes);
    // SAFETY: o PULONG DataLength do chamador.
    unsafe { Field::<u32>::at(data_length) }.set(bytes.len() as u32);
    Ok(true)
}

/// FsRtlDeleteKeyFromTunnelCache(Cache, DirectoryKey).
pub fn delete_key(cache: u64, directory: u64) -> Result<(), KernelError> {
    if parameters().0 == 0 {
        return Ok(());
    }
    with_cache(tunnel_at(cache), |nodes| {
        nodes.retain(|node| node.directory != directory);
        Ok(())
    })
}

/// FsRtlDeleteTunnelCache(Cache): esvazia sem tocar na mutex.
pub fn delete_cache(cache: u64) {
    if parameters().0 == 0 {
        return;
    }
    CACHES.lock().remove(&cache);
    reset_header(tunnel_at(cache));
}

/// FsRtlAddToTunnelCache: FsRtlAddToTunnelCacheEx com Flags = KeyByShortName ? 2 : 0.
#[allow(clippy::too_many_arguments)]
pub fn add(cache: u64, directory: u64, short_name: u64, long_name: u64, key_by_short_name: bool, data_length: u32, data: u64) -> Result<(), KernelError> {
    let flags = if key_by_short_name { FLAG_KEY_BY_SHORT_NAME } else { 0 };
    add_ex(cache, directory, short_name, long_name, flags, data_length, data)
}

/// FsRtlFindInTunnelCache: FsRtlFindInTunnelCacheEx com Flags 0.
#[allow(clippy::too_many_arguments)]
pub fn find(cache: u64, directory: u64, name: u64, short_name: u64, long_name: u64, data_length: u64, data: u64) -> Result<bool, KernelError> {
    find_ex(cache, directory, name, short_name, long_name, 0, data_length, data)
}
