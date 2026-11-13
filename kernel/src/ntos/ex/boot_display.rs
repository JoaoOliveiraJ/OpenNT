//! Texto no vídeo de boot em modo kernel (ZwDisplayString).
//!
//! O vídeo de texto de boot, no OpenNT, é o console; a string chega como
//! UNICODE_STRING e sai em ANSI.

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::previous_mode;
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

/// NtDisplayString: modo usuário precisa do SeTcbPrivilege; a string vira
/// ANSI (fora do Latin-1 vira `?`) e vai para o vídeo de texto de boot, que
/// no OpenNT é o console. Devolve o NTSTATUS.
pub fn display_string(string: u64) -> Result<u32, KernelError> {
    if previous_mode::get()? != 0 {
        return Ok(0xC000_0061);
    }
    if string == 0 {
        return Ok(0xC000_0005);
    }
    let length = guest::read16(string);
    if length & 1 != 0 || (length != 0 && guest::read64(string + 8) == 0) {
        return Ok(0xC000_000D);
    }
    let text: alloc::string::String = guest_strings::read_unicode_string(string).chars().map(|character| if (character as u32) < 0x100 { character } else { '?' }).collect();
    crate::drivers::console::write(&text);
    Ok(0)
}
