//! Arquivos embutidos na imagem do kernel.
//!
//! Os módulos do sistema são compilados; restam os arquivos de dados de
//! `apps/`, que a fase 0 copia para o MemoryFileSystem, e a ntdll.dll de
//! bring-up gerada pelo build, que só os boots com autoteste
//! (`KERNELTESTSCOPE`) enxergam: no boot comum o bundle é o mesmo de um
//! kernel sem ela.

pub struct BundleFile {
    pub name: &'static str,
    pub data: &'static [u8],
}

static FILES: &[BundleFile] = &[BundleFile {
    name: "apps/programs/README",
    data: include_bytes!("../../../apps/programs/README"),
}];

/// Os binários de teste: a lista explícita os deixa fora do boot comum.
static TEST_FILES: &[BundleFile] = &[BundleFile { name: "apps/ntdll.dll", data: include_bytes!(concat!(env!("OUT_DIR"), "/ntdll.dll")) }];

// Binários reais do Windows copiados pelo build (hal.dll e as pilhas de
// teclado/mouse e de armazenamento); nunca ficam no repositório.
include!(concat!(env!("OUT_DIR"), "/windows_binaries.rs"));

fn all() -> impl Iterator<Item = &'static BundleFile> {
    let tests: &'static [BundleFile] = if crate::ntos::init::boot_config::kernel_tests() { TEST_FILES } else { &[] };
    FILES.iter().chain(tests).chain(WINDOWS_BINARIES.iter())
}

/// Bytes de um arquivo embutido, pelo nome.
pub fn read(name: &str) -> Option<&'static [u8]> {
    all().find(|file| file.name == name).map(|file| file.data)
}

/// Nomes dos arquivos embutidos.
pub fn list() -> impl Iterator<Item = &'static str> {
    all().map(|file| file.name)
}
