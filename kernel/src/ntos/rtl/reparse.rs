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
