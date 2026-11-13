//! Profundidade máxima de discos virtuais aninhados —
//! FsRtlQueryMaximumVirtualDiskNestingLevel (0x39a4f0) e
//! FsRtlpGetMaxVirtualDiskNestingLevel (0x3ccdac) do ntoskrnl 19045.
//!
//! O valor é calculado uma vez e guardado em FsRtlVirtualDiskMaxTreeDepth
//! (inicial -1 em .data). Padrão 2; `VirtualDiskMaxTreeDepth` é lido de
//! `...\Services\FsDepends\Parameters` e depois de
//! `...\Control\FileSystem\GroupPolicyKeys` (a política vence), e cada valor
//! só é aceito quando <= 2. O NT consulta KeyValuePartialInformation com um
//! buffer de 0x14 bytes e não confere o tipo: aqui o dword é aceito para
//! dados de 4 a 8 bytes (com mais de 8 o NT recebe STATUS_BUFFER_OVERFLOW e
//! não copia os dados; com menos de 4 os bytes restantes seriam lixo de
//! pilha — ambos ignorados).

use core::sync::atomic::{AtomicU32, Ordering};

use crate::ntos::cm::registry;

const DEFAULT_LEVEL: u32 = 2;
const UNCOMPUTED: u32 = u32::MAX;
const SOURCES: [&str; 2] = [
    "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\FsDepends\\Parameters",
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\FileSystem\\GroupPolicyKeys",
];
const VALUE_NAME: &str = "VirtualDiskMaxTreeDepth";

/// FsRtlVirtualDiskMaxTreeDepth.
static MAX_TREE_DEPTH: AtomicU32 = AtomicU32::new(UNCOMPUTED);

fn compute() -> u32 {
    let mut level = DEFAULT_LEVEL;
    for path in SOURCES {
        let Some(value) = registry::read_value_by_path(path, VALUE_NAME) else {
            continue;
        };
        if (4..=8).contains(&value.data.len()) {
            let configured = u32::from_le_bytes([value.data[0], value.data[1], value.data[2], value.data[3]]);
            if configured <= DEFAULT_LEVEL {
                level = configured;
            }
        }
    }
    level
}

/// FsRtlQueryMaximumVirtualDiskNestingLevel() -> ULONG.
pub fn query_maximum_nesting_level() -> u32 {
    let cached = MAX_TREE_DEPTH.load(Ordering::Acquire);
    if cached != UNCOMPUTED {
        return cached;
    }
    let level = compute();
    MAX_TREE_DEPTH.store(level, Ordering::Release);
    level
}
