//! Imagens de kernel que importam uma da outra (o caso do netio.sys e do
//! ndis.sys).
//!
//! Como no MmLoadSystemImageEx, a entrada de uma imagem entra na lista de
//! imagens carregadas antes de os imports dela serem resolvidos, com
//! LOAD_IN_PROGRESS ligado; o importador que volta a ela no meio da
//! resolução (o fim do ciclo) usa os exports dessa entrada sem reter
//! referência, e a DLL carregada pelo import recebe DRIVER_DEPENDENT_DLL e o
//! DllInitialize logo depois da própria carga, antes do importador.
//!
//! `run` (fase 6) cobre o caminho com duas DLLs sintéticas no sistema de
//! arquivos em memória: A importa B e B importa A. B só consegue resolver o
//! seu import com a entrada de A já listada; o DllInitialize de B grava um
//! marcador, e o DllInitialize de A salta pela própria IAT para uma rotina de
//! B que devolve esse marcador, então o status de A só é 1 se a IAT de A já
//! aponta para B e o DllInitialize de B rodou antes. `after_driver_start`
//! confere o mesmo com o par real depois do `--start-driver=NDIS`: as fatias
//! da IAT de cada um que importam do outro apontam para os exports dele, o
//! netio.sys é DLL dependente com o DllInitialize bem-sucedido, cada imagem
//! está na lista uma vez só e com o FullDllName de \SystemRoot.

use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::loaded_images::{self, LoadedImage};
use crate::ntos::mm::sysload;

type Assert = fn(bool, &str);

const IMAGE_BASE: u64 = 0x1_4000_0000;
const CYCLE_A: &str = "opennt-cycle-a.sys";
const CYCLE_B: &str = "opennt-cycle-b.sys";

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// DLL nativa de 4 páginas: `.text` (DllInitialize em 0x1000, a rotina
/// exportada `export` em 0x1020, DllUnload em 0x1040), `.edata` (com o
/// export CycleFwd encaminhado para `peer`!`peer_export`, no formato dos
/// encaminhamentos de kernel: o módulo sem a extensão) e `.idata` com um
/// import (`peer`!`peer_export`, IAT em 0x3060). O resto de `.idata` (a
/// partir de 0x3100) é dado gravável.
fn cycle_dll(export: &str, peer: &str, peer_export: &str, initialize: &[u8], routine: &[u8]) -> Vec<u8> {
    let mut image = alloc::vec![0u8; 0x4000];
    put16(&mut image, 0, 0x5A4D);
    put32(&mut image, 0x3C, 0x40);
    put32(&mut image, 0x40, 0x4550);
    let coff = 0x44;
    put16(&mut image, coff, 0x8664);
    put16(&mut image, coff + 2, 3);
    put16(&mut image, coff + 16, 0xF0);
    put16(&mut image, coff + 18, 0x2022);
    let optional = 0x58;
    put16(&mut image, optional, 0x20B);
    put32(&mut image, optional + 16, 0x1000);
    put32(&mut image, optional + 24, IMAGE_BASE as u32);
    put32(&mut image, optional + 28, (IMAGE_BASE >> 32) as u32);
    put32(&mut image, optional + 32, 0x1000);
    put32(&mut image, optional + 36, 0x1000);
    put16(&mut image, optional + 40, 10);
    put16(&mut image, optional + 48, 6);
    put16(&mut image, optional + 50, 1);
    put32(&mut image, optional + 56, 0x4000);
    put32(&mut image, optional + 60, 0x1000);
    put16(&mut image, optional + 68, 1);
    put16(&mut image, optional + 70, 0x0160);
    put32(&mut image, optional + 72, 0x10_0000);
    put32(&mut image, optional + 80, 0x1000);
    put32(&mut image, optional + 108, 16);
    put32(&mut image, optional + 112, 0x2000);
    put32(&mut image, optional + 116, 0xC0);
    put32(&mut image, optional + 120, 0x3000);
    put32(&mut image, optional + 124, 40);
    let sections = optional + 0xF0;
    for (index, (name, virtual_address, characteristics)) in [(b".text\0\0\0", 0x1000u32, 0x6000_0020u32), (b".edata\0\0", 0x2000, 0x4000_0040), (b".idata\0\0", 0x3000, 0xC000_0040)].iter().enumerate() {
        let header = sections + index * 40;
        image[header..header + 8].copy_from_slice(*name);
        put32(&mut image, header + 8, 0x1000);
        put32(&mut image, header + 12, *virtual_address);
        put32(&mut image, header + 16, 0x1000);
        put32(&mut image, header + 20, *virtual_address);
        put32(&mut image, header + 36, *characteristics);
    }
    image[0x1000..0x1000 + initialize.len()].copy_from_slice(initialize);
    image[0x1020..0x1020 + routine.len()].copy_from_slice(routine);
    image[0x1040..0x1043].copy_from_slice(&[0x31, 0xC0, 0xC3]);
    // Exports: base 1, quatro funções (a última um encaminhamento, dentro do
    // diretório) e quatro nomes em ordem lexical.
    put32(&mut image, 0x2000 + 16, 1);
    put32(&mut image, 0x2000 + 20, 4);
    put32(&mut image, 0x2000 + 24, 4);
    put32(&mut image, 0x2000 + 28, 0x2028);
    put32(&mut image, 0x2000 + 32, 0x2038);
    put32(&mut image, 0x2000 + 36, 0x2048);
    for (index, rva) in [0x1000u32, 0x1020, 0x1040, 0x20A0].iter().enumerate() {
        put32(&mut image, 0x2028 + index * 4, *rva);
    }
    for (index, (name_rva, ordinal)) in [(0x2050u32, 1u16), (0x2060, 3), (0x2070, 0), (0x2080, 2)].iter().enumerate() {
        put32(&mut image, 0x2038 + index * 4, *name_rva);
        put16(&mut image, 0x2048 + index * 2, *ordinal);
    }
    image[0x2050..0x2050 + export.len()].copy_from_slice(export.as_bytes());
    image[0x2060..0x2068].copy_from_slice(b"CycleFwd");
    image[0x2070..0x207D].copy_from_slice(b"DllInitialize");
    image[0x2080..0x2089].copy_from_slice(b"DllUnload");
    let forwarder = alloc::format!("{}.{}", peer.trim_end_matches(".sys"), peer_export);
    image[0x20A0..0x20A0 + forwarder.len()].copy_from_slice(forwarder.as_bytes());
    // Import: descritor -> ILT 0x3040, nome 0x3080, IAT 0x3060.
    put32(&mut image, 0x3000, 0x3040);
    put32(&mut image, 0x300C, 0x3080);
    put32(&mut image, 0x3010, 0x3060);
    for table in [0x3040usize, 0x3060] {
        put32(&mut image, table, 0x30A0);
    }
    image[0x3080..0x3080 + peer.len()].copy_from_slice(peer.as_bytes());
    image[0x30A2..0x30A2 + peer_export.len()].copy_from_slice(peer_export.as_bytes());
    image
}

/// A: o DllInitialize salta pela IAT (jmp [rip+0x205A] -> 0x3060) para a
/// rotina de B.
fn image_a() -> Vec<u8> {
    cycle_dll("CycleA", CYCLE_B, "CycleB", &[0xFF, 0x25, 0x5A, 0x20, 0x00, 0x00], &[0x31, 0xC0, 0xC3])
}

/// B: o DllInitialize grava 1 no marcador (mov dword [rip+0x20F6], 1 ->
/// 0x3100) e devolve 0; CycleB devolve o marcador (mov eax, [rip+0x20DA]).
fn image_b() -> Vec<u8> {
    cycle_dll("CycleB", CYCLE_A, "CycleA", &[0xC7, 0x05, 0xF6, 0x20, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x31, 0xC0, 0xC3], &[0x8B, 0x05, 0xDA, 0x20, 0x00, 0x00, 0xC3])
}

fn listed(name: &str) -> Option<LoadedImage> {
    loaded_images::find_by_base_name(name)
}

pub fn run(assert: Assert) {
    use crate::drivers::fs::memory_file_system;
    let written = memory_file_system::write_bytes(&alloc::format!("/{CYCLE_A}"), image_a()).is_ok() && memory_file_system::write_bytes(&alloc::format!("/{CYCLE_B}"), image_b()).is_ok();
    assert(written, "importcycle: as duas DLLs no sistema de arquivos em memoria");
    let acquired = sysload::acquire(CYCLE_A);
    let Ok(mut acquired) = acquired else {
        debug_print!("[importcycle] carga de {}: {:?}", CYCLE_A, acquired.err().map(|error| error.message));
        assert(false, "importcycle: A carrega com o ciclo A -> B -> A");
        return;
    };
    let (a, b) = (listed(CYCLE_A), listed(CYCLE_B));
    let (Some(a), Some(b)) = (a, b) else {
        assert(false, "importcycle: A e B na lista de imagens carregadas");
        let _ = acquired.release();
        return;
    };
    debug_print!("[importcycle] A={:#x} flags={:#x} B={:#x} flags={:#x} IAT de B={:#x} IAT de A={:#x}", a.image_base, a.loader_flags, b.image_base, b.loader_flags, guest::read64(b.image_base + 0x3060), guest::read64(a.image_base + 0x3060));
    assert(guest::read64(b.image_base + 0x3060) == a.image_base + 0x1020 && guest::read64(a.image_base + 0x3060) == b.image_base + 0x1020, "importcycle: B resolve o import pela entrada de A em carga, e A pelo B carregado");
    assert(a.loader_flags & loaded_images::LOAD_IN_PROGRESS == 0 && b.loader_flags & loaded_images::LOAD_IN_PROGRESS == 0, "importcycle: LOAD_IN_PROGRESS desligado no fim da resolucao");
    assert(a.name == "\\SystemRoot\\System32\\drivers\\opennt-cycle-a.sys" && b.name == "\\SystemRoot\\System32\\drivers\\opennt-cycle-b.sys", "importcycle: FullDllName com o caminho NT de System32\\drivers");
    assert(b.loader_flags & loaded_images::DRIVER_DEPENDENT_DLL != 0 && a.loader_flags & loaded_images::DRIVER_DEPENDENT_DLL == 0, "importcycle: so a DLL carregada pelo import e DRIVER_DEPENDENT_DLL");
    // Encaminhamento de kernel sem extensão: "opennt-cycle-b.CycleB" casa
    // com a imagem carregada cujo BaseDllName começa com "opennt-cycle-b.".
    let forwarded = sysload::lookup(CYCLE_A, &crate::ntos::mm::pe_loader::ImportSymbol::Name(alloc::string::String::from("CycleFwd"))).map(|(address, _)| address);
    assert(forwarded.as_ref().is_ok_and(|&address| address == b.image_base + 0x1020), "importcycle: encaminhamento sem extensao resolvido pela imagem carregada de mesmo prefixo");
    let (state_a, state_b) = (sysload::state(CYCLE_A), sysload::state(CYCLE_B));
    debug_print!("[importcycle] estado A={:?} B={:?}", state_a, state_b);
    assert(state_b.as_ref().is_some_and(|state| state.4 == Some(0)) && state_a.as_ref().is_some_and(|state| state.4 == Some(1)), "importcycle: DllInitialize de B antes do de A, com a IAT de A ja resolvida");
    // A retém B (import comum); o fim do ciclo (B -> A) não retém A, então
    // a única referência de A é a deste teste.
    assert(state_a.as_ref().is_some_and(|state| state.2 == 1) && state_b.as_ref().is_some_and(|state| state.2 == 1), "importcycle: o fim do ciclo nao retem referencia");
    assert(acquired.release().is_ok() && listed(CYCLE_A).is_none() && listed(CYCLE_B).is_none(), "importcycle: a liberacao de A descarrega A e depois B");
    let _ = memory_file_system::remove(&alloc::format!("/{CYCLE_A}"));
    let _ = memory_file_system::remove(&alloc::format!("/{CYCLE_B}"));
}

/// Fatias da IAT de `importer` que importam de `dll`: (nome, valor).
fn imports_from(importer: &LoadedImage, dll: &str) -> Vec<(alloc::string::String, u64)> {
    let base = importer.image_base;
    let pe = base + guest::read32(base + 0x3C) as u64;
    let directory = guest::read32(pe + 24 + 120) as u64;
    let mut slots = Vec::new();
    if directory == 0 {
        return slots;
    }
    let mut descriptor = base + directory;
    loop {
        let (original, name, first) = (guest::read32(descriptor) as u64, guest::read32(descriptor + 12) as u64, guest::read32(descriptor + 16) as u64);
        if original == 0 && name == 0 && first == 0 {
            break;
        }
        if crate::ntos::rtl::guest_strings::read_c_string(base + name).eq_ignore_ascii_case(dll) {
            let mut slot = 0u64;
            loop {
                let thunk = guest::read64(base + original + slot * 8);
                if thunk == 0 {
                    break;
                }
                let label = if thunk >> 63 != 0 { alloc::format!("#{}", thunk & 0xFFFF) } else { crate::ntos::rtl::guest_strings::read_c_string(base + thunk + 2) };
                slots.push((label, guest::read64(base + first + slot * 8)));
                slot += 1;
            }
        }
        descriptor += 20;
    }
    slots
}

/// Toda fatia de `importer` vinda de `exporter` aponta para o export de
/// mesmo nome dentro da imagem de `exporter`; devolve a quantidade.
fn snapped_to(importer: &LoadedImage, exporter: &LoadedImage, dll: &str) -> Result<usize, alloc::string::String> {
    let slots = imports_from(importer, dll);
    if slots.is_empty() {
        return Err(alloc::format!("{} sem imports de {}", importer.name, dll));
    }
    for (name, value) in &slots {
        let mut text: Vec<u8> = name.as_bytes().to_vec();
        text.push(0);
        let pointer = guest::alloc_bytes(text.len() as u64);
        guest::write_bytes(pointer, &text);
        let export = crate::ntos::rtl::image::find_exported_routine_by_name(exporter.image_base, pointer);
        guest::free_bytes(pointer);
        let inside = *value >= exporter.image_base && *value < exporter.image_base + exporter.size_of_image;
        if export == 0 || *value != export || !inside {
            return Err(alloc::format!("{}!{} = {:#x}, export {:#x}", dll, name, value, export));
        }
    }
    Ok(slots.len())
}

fn check_real_pair() -> Result<(usize, usize), alloc::string::String> {
    let images = loaded_images::list();
    let count = |name: &str| images.iter().filter(|image| image.name.rsplit(['\\', '/']).next().is_some_and(|base| base.eq_ignore_ascii_case(name))).count();
    if count("ndis.sys") != 1 || count("netio.sys") != 1 {
        return Err(alloc::format!("ndis.sys listado {} vez(es), netio.sys {}", count("ndis.sys"), count("netio.sys")));
    }
    let (ndis, netio) = (listed("ndis.sys").ok_or("ndis.sys ausente")?, listed("netio.sys").ok_or("netio.sys ausente")?);
    // FullDllName: o ImagePath do serviço NDIS e o diretório do importador
    // mais o nome da DLL.
    if !ndis.name.eq_ignore_ascii_case("\\SystemRoot\\system32\\drivers\\ndis.sys") || !netio.name.eq_ignore_ascii_case("\\SystemRoot\\System32\\drivers\\netio.sys") {
        return Err(alloc::format!("nomes {} e {}", ndis.name, netio.name));
    }
    if (ndis.loader_flags | netio.loader_flags) & loaded_images::LOAD_IN_PROGRESS != 0 {
        return Err(alloc::string::String::from("LOAD_IN_PROGRESS ainda ligado"));
    }
    if netio.loader_flags & loaded_images::DRIVER_DEPENDENT_DLL == 0 || ndis.loader_flags & loaded_images::DRIVER_DEPENDENT_DLL != 0 {
        return Err(alloc::format!("flags ndis={:#x} netio={:#x}", ndis.loader_flags, netio.loader_flags));
    }
    match sysload::state("netio.sys") {
        Some((kind, _, references, _, Some(status), _)) if kind == "ExportDriver" && status & 0x8000_0000 == 0 && references >= 1 => {}
        other => return Err(alloc::format!("estado do netio.sys: {other:?}")),
    }
    Ok((snapped_to(&netio, &ndis, "NDIS.SYS")?, snapped_to(&ndis, &netio, "NETIO.SYS")?))
}

/// Depois do início de um driver pelo `--start-driver`: com o NDIS, o par
/// real netio.sys <-> ndis.sys.
pub fn after_driver_start(name: &str) {
    if !name.eq_ignore_ascii_case("NDIS") {
        return;
    }
    match check_real_pair() {
        Ok((netio_slots, ndis_slots)) => debug_print!("IMPORT_CYCLE_OK ndis.sys<->netio.sys netio->ndis={} ndis->netio={}", netio_slots, ndis_slots),
        Err(message) => debug_print!("IMPORT_CYCLE_FALHOU: {}", message),
    }
}
