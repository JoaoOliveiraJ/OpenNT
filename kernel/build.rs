// O kernel é ligado na sua VA de sistema (0xFFFFF800_40001000) pelo script
// `link.ld`. As opções de boot (init/boot_config.rs) chegam como variáveis de
// ambiente.
//
// Nos builds com testes, o build também gera a ntdll.dll de bring-up do
// bundle a partir da tabela única de syscalls (`src/ntos/ke/services.rs`):
// um PE32+ com o DllMain e os stubs `mov r10, rcx; mov eax, N; syscall; ret`,
// exportados por nome. O caminho final usa a ntdll real do volume.

include!("src/ntos/ke/services.rs");

const FILE_ALIGNMENT: usize = 0x200;
const SECTION_ALIGNMENT: u32 = 0x1000;
const IMAGE_BASE: u64 = 0x1_8000_0000;

fn align(value: usize, to: usize) -> usize {
    value.div_ceil(to) * to
}

fn put16(image: &mut [u8], at: usize, value: u16) {
    image[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(image: &mut [u8], at: usize, value: u32) {
    image[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(image: &mut [u8], at: usize, value: u64) {
    image[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// Cabeçalho de seção (40 bytes).
fn section_header(image: &mut [u8], at: usize, name: &[u8], virtual_size: usize, rva: u32, raw_size: usize, raw_offset: usize, characteristics: u32) {
    image[at..at + name.len()].copy_from_slice(name);
    put32(image, at + 8, virtual_size as u32);
    put32(image, at + 12, rva);
    put32(image, at + 16, raw_size as u32);
    put32(image, at + 20, raw_offset as u32);
    put32(image, at + 36, characteristics);
}

/// A ntdll.dll de bring-up: .text com o DllMain e os stubs, .rdata com o
/// diretório de exports (nomes em ordem binária, base de ordinais 1).
fn bring_up_ntdll() -> Vec<u8> {
    // Código: DllMain devolve TRUE; cada stub tem 11 bytes, em sequência.
    let mut code = vec![0xB8, 1, 0, 0, 0, 0xC3];
    let mut symbols: Vec<(&str, u32)> = vec![("DllMain", 0)];
    for &(name, number) in SYSCALLS {
        symbols.push((name, code.len() as u32));
        code.extend_from_slice(&[0x4C, 0x8B, 0xD1, 0xB8]);
        code.extend_from_slice(&number.to_le_bytes());
        code.extend_from_slice(&[0x0F, 0x05, 0xC3]);
    }
    let text_rva = SECTION_ALIGNMENT;
    let rdata_rva = text_rva + align(code.len(), SECTION_ALIGNMENT as usize) as u32;
    symbols.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    // Exports: diretório, endereços, nomes, ordinais, nome da DLL e strings.
    let count = symbols.len();
    let functions = 40;
    let names = functions + count * 4;
    let ordinals = names + count * 4;
    let dll_name = ordinals + count * 2;
    let mut rdata = vec![0u8; dll_name];
    rdata.extend_from_slice(b"ntdll.dll\0");
    let mut name_offsets = Vec::with_capacity(count);
    for (name, _) in &symbols {
        name_offsets.push(rdata.len());
        rdata.extend_from_slice(name.as_bytes());
        rdata.push(0);
    }
    put32(&mut rdata, 12, rdata_rva + dll_name as u32);
    put32(&mut rdata, 16, 1);
    put32(&mut rdata, 20, count as u32);
    put32(&mut rdata, 24, count as u32);
    put32(&mut rdata, 28, rdata_rva + functions as u32);
    put32(&mut rdata, 32, rdata_rva + names as u32);
    put32(&mut rdata, 36, rdata_rva + ordinals as u32);
    for (index, (_, offset)) in symbols.iter().enumerate() {
        put32(&mut rdata, functions + index * 4, text_rva + offset);
        put32(&mut rdata, names + index * 4, rdata_rva + name_offsets[index] as u32);
        put16(&mut rdata, ordinals + index * 2, index as u16);
    }
    // Cabeçalhos: DOS, PE, COFF, opcional PE32+ e duas seções.
    let headers = 0x400;
    let text_raw = headers;
    let text_size = align(code.len(), FILE_ALIGNMENT);
    let rdata_raw = text_raw + text_size;
    let rdata_size = align(rdata.len(), FILE_ALIGNMENT);
    let size_of_image = rdata_rva as usize + align(rdata.len(), SECTION_ALIGNMENT as usize);
    let mut image = vec![0u8; rdata_raw + rdata_size];
    put16(&mut image, 0, 0x5A4D);
    put32(&mut image, 0x3C, 0x80);
    put32(&mut image, 0x80, 0x4550);
    let coff = 0x84;
    put16(&mut image, coff, 0x8664);
    put16(&mut image, coff + 2, 2);
    put16(&mut image, coff + 16, 240);
    // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DLL.
    put16(&mut image, coff + 18, 0x2022);
    let optional = coff + 20;
    put16(&mut image, optional, 0x20B);
    image[optional + 2] = 14;
    put32(&mut image, optional + 4, text_size as u32);
    put32(&mut image, optional + 8, rdata_size as u32);
    put32(&mut image, optional + 16, text_rva);
    put32(&mut image, optional + 20, text_rva);
    put64(&mut image, optional + 24, IMAGE_BASE);
    put32(&mut image, optional + 32, SECTION_ALIGNMENT);
    put32(&mut image, optional + 36, FILE_ALIGNMENT as u32);
    put16(&mut image, optional + 40, 6);
    put16(&mut image, optional + 48, 6);
    put32(&mut image, optional + 56, size_of_image as u32);
    put32(&mut image, optional + 60, headers as u32);
    // IMAGE_SUBSYSTEM_WINDOWS_GUI; NX_COMPAT (sem .reloc, sem DYNAMIC_BASE).
    put16(&mut image, optional + 68, 2);
    put16(&mut image, optional + 70, 0x100);
    put64(&mut image, optional + 72, 0x10_0000);
    put64(&mut image, optional + 80, 0x1000);
    put64(&mut image, optional + 88, 0x10_0000);
    put64(&mut image, optional + 96, 0x1000);
    put32(&mut image, optional + 108, 16);
    put32(&mut image, optional + 112, rdata_rva);
    put32(&mut image, optional + 116, rdata.len() as u32);
    let sections = optional + 240;
    section_header(&mut image, sections, b".text", code.len(), text_rva, text_size, text_raw, 0x6000_0020);
    section_header(&mut image, sections + 40, b".rdata", rdata.len(), rdata_rva, rdata_size, rdata_raw, 0x4000_0040);
    image[text_raw..text_raw + code.len()].copy_from_slice(&code);
    image[rdata_raw..rdata_raw + rdata.len()].copy_from_slice(&rdata);
    image
}

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg-bins=-T{manifest}/link.ld");
    // Código PIC (`.cargo/config.toml`) num executável estático: o rustc
    // pediria um PIE, com relocações para processar no boot.
    println!("cargo:rustc-link-arg-bins=--no-pie");
    println!("cargo:rerun-if-changed=link.ld");
    println!("cargo:rerun-if-changed=../apps");
    println!("cargo:rerun-if-changed=src/ntos/ke/services.rs");
    for variable in ["OPENNT_USER_PROGRAM", "OPENNT_KERNEL_TEST_SCOPE", "OPENNT_CONSOLE_MIRROR"] {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    // Binários reais do Windows copiados pelo xtask (hal.dll e as pilhas de
    // teclado/mouse e armazenamento): a lista gerada os embute no bundle.
    println!("cargo:rerun-if-env-changed=OPENNT_WINDOWS_BINARIES");
    let mut binaries = String::from("pub static WINDOWS_BINARIES: &[BundleFile] = &[\n");
    if let Ok(directory) = std::env::var("OPENNT_WINDOWS_BINARIES") {
        println!("cargo:rerun-if-changed={directory}");
        let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(&directory).map(|entries| entries.filter_map(|entry| entry.ok()).map(|entry| entry.path()).filter(|path| path.is_file()).collect()).unwrap_or_default();
        entries.sort();
        for path in entries {
            println!("cargo:rerun-if-changed={}", path.display());
            let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default().to_lowercase();
            binaries.push_str(&format!("    BundleFile {{ name: \"apps/{name}\", data: include_bytes!(r\"{}\") }},\n", path.display()));
        }
    }
    binaries.push_str("];\n");
    std::fs::write(std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("windows_binaries.rs"), binaries).expect("lista de binarios do Windows");
    // Só os builds com testes levam a ntdll de bring-up no bundle.
    println!("cargo::rustc-check-cfg=cfg(opennt_test_bundle)");
    let scope = std::env::var("OPENNT_KERNEL_TEST_SCOPE").unwrap_or_default();
    if !scope.is_empty() && scope != "none" {
        let output = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("ntdll.dll");
        std::fs::write(output, bring_up_ntdll()).expect("ntdll de bring-up");
        println!("cargo:rustc-cfg=opennt_test_bundle");
    }
}
