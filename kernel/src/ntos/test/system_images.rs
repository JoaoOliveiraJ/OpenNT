//! Autoteste das imagens de kernel no espaço de sistema.
//!
//! Roda no fim da fase 6, com os drivers reais do boot já carregados: toda
//! entrada da lista de imagens carregadas (a que PsLoadedModuleList enumera)
//! fica em MmSystemRangeStart ou acima, e cada imagem que o loader PE mapeou
//! ocupa a janela de imagens de sistema, com o cabeçalho em PTE de supervisor.
//! O teste do teclado real confere o mesmo para i8042prt e kbdclass, que só
//! carregam depois da fase 7.

use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::loaded_images::{self, LoadedImage};
use crate::ntos::mm::memory_map::{SYSTEM_IMAGE_BASE, SYSTEM_IMAGE_TOP};
use crate::ntos::mm::{paging, pe_loader, system_info};

type Assert = fn(bool, &str);

/// Imagem do loader PE na janela de sistema, com o cabeçalho MZ legível pela
/// VA em PTE de supervisor.
fn in_system_window(image: &LoadedImage) -> bool {
    image.image_base >= SYSTEM_IMAGE_BASE
        && image.image_base + image.size_of_image <= SYSTEM_IMAGE_TOP
        && pe_loader::native_image(image.image_base).is_some()
        && paging::query_page(image.image_base, false).is_some_and(|page| page.flags & paging::PAGE_USER == 0)
        && guest::read16(image.image_base) == 0x5A4D
}

/// Cada nome (sufixo do caminho, minúsculas) está na lista de imagens e na
/// janela de sistema.
pub fn listed_in_system_window(names: &[&str]) -> bool {
    let images = loaded_images::list();
    names.iter().all(|name| images.iter().any(|image| image.name.to_ascii_lowercase().ends_with(name) && in_system_window(image)))
}

pub fn run(assert: Assert) {
    let system_range_start = guest::read64(system_info::system_range_start_cell());
    let images = loaded_images::list();
    let kernel = loaded_images::kernel().map(|kernel| kernel.id);
    for image in &images {
        crate::debug_print!("[sysimg] {:#x}+{:#x} {}", image.image_base, image.size_of_image, image.name);
    }
    assert(
        system_range_start == 0xFFFF_8000_0000_0000 && images.len() > 1 && images.iter().all(|image| image.image_base >= system_range_start),
        "sysimg: toda imagem carregada fica em MmSystemRangeStart ou acima",
    );
    let loaded: Vec<&LoadedImage> = images.iter().filter(|image| Some(image.id) != kernel).collect();
    assert(loaded.iter().all(|image| in_system_window(image)), "sysimg: drivers e bibliotecas de kernel na janela de imagens de sistema, em PTEs de supervisor");
    assert(
        listed_in_system_window(&["hal.dll", "cng.sys", "wmilib.sys", "ataport.sys", "atapi.sys", "classpnp.sys", "disk.sys", "mountmgr.sys"]),
        "sysimg: hal.dll, cng.sys e a pilha de disco reais entre as imagens de sistema",
    );
}
