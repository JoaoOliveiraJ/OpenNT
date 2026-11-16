//! Regras de reparse points do Rtl (ntoskrnl 19045).

/// Bit de tag "diretório" (IsReparseTagDirectory) e a tag 0x80000018 que
/// também admite diretório não vazio.
const REPARSE_TAG_DIRECTORY_BIT: u32 = 1 << 28;
const REPARSE_TAG_NON_EMPTY_DIRECTORY: u32 = 0x8000_0018;

/// RtlIsNonEmptyDirectoryReparsePointAllowed(ReparseTag) -> BOOLEAN
/// (0x322420: `bt ecx, 0x1c` ou `cmp ecx, 0x80000018`).
pub fn is_non_empty_directory_reparse_point_allowed(tag: u32) -> bool {
    tag & REPARSE_TAG_DIRECTORY_BIT != 0 || tag == REPARSE_TAG_NON_EMPTY_DIRECTORY
}

/// FILE_ATTRIBUTE_REPARSE_POINT e IO_REPARSE_TAG_CLOUD (0x9000001A), com os
/// quatro bits do número do provedor (0xF000) ignorados.
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const IO_REPARSE_TAG_CLOUD: u32 = 0x9000_001A;
const REPARSE_TAG_CLOUD_PROVIDER_MASK: u32 = 0x0000_F000;

/// RtlIsCloudFilesPlaceholder(FileAttributes, ReparseTag) -> BOOLEAN
/// (19041 0x58d800: `bt ecx, 0xa` e a tag mascarada com 0xFFFF0FFF).
pub fn is_cloud_files_placeholder(attributes: u32, tag: u32) -> bool {
    attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 && tag & !REPARSE_TAG_CLOUD_PROVIDER_MASK == IO_REPARSE_TAG_CLOUD
}
