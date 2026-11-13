//! Pasta de sistema de um volume — RtlCreateSystemVolumeInformationFolder.
//!
//! Abre ou cria "<volume>\System Volume Information" pelo Io (ZwCreateFile
//! por nome); o status do Io volta como veio.

use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

/// FILE_OPEN_IF.
const FILE_OPEN_IF: u32 = 3;
/// FILE_DIRECTORY_FILE.
const FILE_DIRECTORY_FILE: u32 = 1;

/// RtlCreateSystemVolumeInformationFolder(PCUNICODE_STRING VolumeRootPath).
pub fn create_information_folder(volume_root: u64) -> Result<u32, KernelError> {
    let volume = guest_strings::read_unicode_string(volume_root);
    let folder = alloc::format!("{volume}{}System Volume Information", if volume.ends_with('\\') { "" } else { "\\" });
    let status = crate::ntos::io::file::zw::create_file_by_name(&folder, FILE_OPEN_IF, FILE_DIRECTORY_FILE)?;
    if status != 0 {
        debug_print!("[rtl] System Volume Information em {} -> 0x{:x}", volume, status);
    }
    Ok(status)
}
