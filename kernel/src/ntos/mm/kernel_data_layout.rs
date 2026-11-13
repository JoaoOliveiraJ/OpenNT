//! Globais do kernel pertencentes ao PE — `system32/ntos/mm/kernel-data-layout.js`.
//!
//! Os valores iniciais descrevem este boot: não há transporte/sessão KD.
//! Este arquivo também é incluído pelo `xtask` (via `#[path]`), que gera a
//! seção `.kdata` e os exports de dados do `ntoskrnl.exe`; por isso não usa
//! nada além de `core`.

pub struct KernelDataEntry {
    pub name: &'static str,
    pub size: u64,
    /// Armazenamento reservado (alguns exports reservam mais que a leitura).
    pub storage_size: u64,
    pub alignment: u64,
    pub initial: &'static [u8],
}

const ZERO8: &[u8] = &[0; 8];

/// HAL_PRIVATE_DISPATCH (0x4B0 bytes): versão 51; os ponteiros são gravados
/// na inicialização da HAL (`ntos::hal::private_dispatch`).
const HAL_PRIVATE_DISPATCH_INITIAL: [u8; 0x4B0] = {
    let mut bytes = [0u8; 0x4B0];
    bytes[0] = 51;
    bytes
};

const fn pointer(name: &'static str) -> KernelDataEntry {
    KernelDataEntry { name, size: 8, storage_size: 8, alignment: 8, initial: ZERO8 }
}

pub const DEFINITIONS: &[KernelDataEntry] = &[
    KernelDataEntry { name: "KdDebuggerEnabled", size: 1, storage_size: 1, alignment: 1, initial: &[0] },
    KernelDataEntry { name: "KdDebuggerNotPresent", size: 1, storage_size: 1, alignment: 1, initial: &[1] },
    // KdEnteredDebugger é ULONG (KdEnter/ExitDebugger nativos usam dwords).
    KernelDataEntry { name: "KdEnteredDebugger", size: 4, storage_size: 4, alignment: 4, initial: &[0; 4] },
    // Preenchido depois que o escalonador cria o EPROCESS do System.
    pointer("PsInitialSystemProcess"),
    pointer("PsProcessType"),
    pointer("PsThreadType"),
    pointer("IoDriverObjectType"),
    pointer("IoFileObjectType"),
    pointer("MmSectionObjectType"),
    pointer("MmUserProbeAddress"),
    pointer("MmHighestUserAddress"),
    pointer("SeTokenObjectType"),
    // Ponteiro seguido do SE_EXPORTS/SIDs privados na mesma seção (layout
    // 19041 completo: 70 campos e 35 SIDs, 1064 bytes). Só o ponteiro é
    // exportado.
    KernelDataEntry { name: "SeExports", size: 8, storage_size: 1064, alignment: 8, initial: ZERO8 },
    KernelDataEntry { name: "HalPrivateDispatchTable", size: 0x4B0, storage_size: 0x4B0, alignment: 8, initial: &HAL_PRIVATE_DISPATCH_INITIAL },
];

/// Offset de cada entrada dentro da seção, na ordem de `DEFINITIONS`.
pub fn offset_of(index: usize) -> u64 {
    let mut offset = 0u64;
    for (position, entry) in DEFINITIONS.iter().enumerate() {
        offset = offset.div_ceil(entry.alignment) * entry.alignment;
        if position == index {
            return offset;
        }
        offset += entry.storage_size;
    }
    offset
}

/// Bytes necessários para toda a seção.
pub fn required_byte_length() -> u64 {
    let last = DEFINITIONS.len() - 1;
    offset_of(last) + DEFINITIONS[last].storage_size
}

pub fn find(name: &str) -> Option<(usize, &'static KernelDataEntry)> {
    DEFINITIONS.iter().enumerate().find(|(_, entry)| entry.name == name)
}
