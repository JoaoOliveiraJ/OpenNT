//! Globais do kernel pertencentes ao PE.
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

/// HAL_DISPATCH público (0xC0 bytes = Version + 23 ponteiros): versão 4; os
/// ponteiros são gravados na inicialização da HAL (`hal::public_dispatch`).
/// É a tabela que drivers como o BasicDisplay e o dxgkrnl indexam para chegar
/// a HalQuerySystemInformation (slot 1) — distinta da HalPrivateDispatchTable.
const HAL_DISPATCH_INITIAL: [u8; 0xC0] = {
    let mut bytes = [0u8; 0xC0];
    bytes[0] = 4;
    bytes
};

/// MmSystemRangeStart: a constante da .rdata do ntoskrnl 19041 (RVA 0x223a8).
const MM_SYSTEM_RANGE_START_INITIAL: [u8; 8] = 0xFFFF_8000_0000_0000u64.to_le_bytes();
/// MmBadPointer: a primeira página depois da janela do pool de kernel
/// (`memory_map::KERNEL_POOL_TOP`), que nada mapeia. O valor é literal porque o
/// `xtask` também lê este arquivo.
const MM_BAD_POINTER_INITIAL: [u8; 8] = 0xFFFF_A001_0000_0000u64.to_le_bytes();

/// FsRtlLegalAnsiCharacterArray: classe de cada byte ANSI (FAT/HPFS/NTFS/OLE e
/// curinga). 0x00–0x7F são os bytes exatos do ntoskrnl 19041 (tabela de 128
/// bytes no RVA 0x11b20, conferida contra o binário); 0x80–0xFF = 0x17 (legal,
/// não-curinga), o padrão para ANSI alto — os testes de curinga só indexam < 0x40.
pub const FSRTL_LEGAL_ANSI_CHARACTER_ARRAY: [u8; 256] = {
    let mut table = [0x17u8; 256];
    let low: [u8; 128] = [
        0x00, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, // 0x00
        0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, // 0x10
        0x17, 0x07, 0x18, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x18, 0x16, 0x16, 0x17, 0x07, 0x00, // 0x20
        0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x04, 0x16, 0x18, 0x16, 0x18, 0x18, // 0x30
        0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, // 0x40
        0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x16, 0x00, 0x16, 0x17, 0x17, // 0x50
        0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, // 0x60
        0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x10, 0x17, 0x17, 0x17, // 0x70
    ];
    let mut index = 0;
    while index < 128 {
        table[index] = low[index];
        index += 1;
    }
    table
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
    pointer("IoDeviceObjectType"),
    pointer("ExSemaphoreObjectType"),
    pointer("LpcPortObjectType"),
    pointer("MmUserProbeAddress"),
    pointer("MmHighestUserAddress"),
    pointer("SeTokenObjectType"),
    // Ponteiro seguido do SE_EXPORTS/SIDs privados na mesma seção (layout
    // 19041 completo: 70 campos e 35 SIDs, 1064 bytes). Só o ponteiro é
    // exportado.
    KernelDataEntry { name: "SeExports", size: 8, storage_size: 1064, alignment: 8, initial: ZERO8 },
    KernelDataEntry { name: "HalPrivateDispatchTable", size: 0x4B0, storage_size: 0x4B0, alignment: 8, initial: &HAL_PRIVATE_DISPATCH_INITIAL },
    KernelDataEntry { name: "HalDispatchTable", size: 0xC0, storage_size: 0xC0, alignment: 8, initial: &HAL_DISPATCH_INITIAL },
    KernelDataEntry { name: "FsRtlLegalAnsiCharacterArray", size: 256, storage_size: 256, alignment: 16, initial: &FSRTL_LEGAL_ANSI_CHARACTER_ARRAY },
    // BOOLEAN; o MiMemoryLicense do x64 grava 1 incondicionalmente.
    KernelDataEntry { name: "Mm64BitPhysicalAddress", size: 1, storage_size: 1, alignment: 1, initial: &[1] },
    KernelDataEntry { name: "MmSystemRangeStart", size: 8, storage_size: 8, alignment: 8, initial: &MM_SYSTEM_RANGE_START_INITIAL },
    KernelDataEntry { name: "MmBadPointer", size: 8, storage_size: 8, alignment: 8, initial: &MM_BAD_POINTER_INITIAL },
    // POBJECT_TYPE do KTM (ALMOSTRO, NULL até o TmInitSystem do tm.sys, que
    // o OpenNT não tem).
    pointer("TmTransactionObjectType"),
    pointer("TmResourceManagerObjectType"),
    pointer("TmEnlistmentObjectType"),
    // Página OEM 437 (SBCS): NlsMbOemCodePageTag = FALSE e NlsOemLeadByteInfo
    // aponta para os 512 bytes zerados guardados logo depois da célula.
    KernelDataEntry { name: "NlsMbOemCodePageTag", size: 1, storage_size: 1, alignment: 1, initial: &[0] },
    KernelDataEntry { name: "NlsOemLeadByteInfo", size: 8, storage_size: 8 + 512, alignment: 8, initial: ZERO8 },
    // As páginas instaladas: USHORT NlsAnsiCodePage = 1252, USHORT
    // NlsOemCodePage = 437 e BOOLEAN NlsMbCodePageTag = FALSE (1252 é SBCS).
    KernelDataEntry { name: "NlsAnsiCodePage", size: 2, storage_size: 2, alignment: 2, initial: &[0xE4, 0x04] },
    KernelDataEntry { name: "NlsOemCodePage", size: 2, storage_size: 2, alignment: 2, initial: &[0xB5, 0x01] },
    KernelDataEntry { name: "NlsMbCodePageTag", size: 1, storage_size: 1, alignment: 1, initial: &[0] },
    // POBJECT_TYPE que o executive cria no boot: os do subsistema Win32 (o
    // ExpWin32Initialization), o Timer e o Job.
    pointer("ExWindowStationObjectType"),
    pointer("ExDesktopObjectType"),
    pointer("ExCompositionObjectType"),
    pointer("ExRawInputManagerObjectType"),
    pointer("ExCoreMessagingObjectType"),
    pointer("ExActivationObjectType"),
    pointer("ExTimerObjectType"),
    pointer("PsJobType"),
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
