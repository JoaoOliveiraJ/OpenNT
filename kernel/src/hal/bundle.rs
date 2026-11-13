//! Arquivos embutidos na imagem do kernel.
//!
//! Os módulos do sistema são compilados; restam os arquivos de dados de
//! `apps/`, que a fase 0 copia para o MemoryFileSystem, e, nos builds com
//! testes, a ntdll.dll de bring-up gerada pelo build.

pub struct BundleFile {
    pub name: &'static str,
    pub data: &'static [u8],
}

#[cfg(not(opennt_test_bundle))]
static FILES: &[BundleFile] = &[BundleFile {
    name: "apps/programs/README",
    data: include_bytes!("../../../apps/programs/README"),
}];

/// A lista explícita impede que binários de teste entrem no build normal.
#[cfg(opennt_test_bundle)]
static FILES: &[BundleFile] = &[
    BundleFile { name: "apps/programs/README", data: include_bytes!("../../../apps/programs/README") },
    BundleFile { name: "apps/ntdll.dll", data: include_bytes!(concat!(env!("OUT_DIR"), "/ntdll.dll")) },
];

// Binários reais do Windows copiados pelo build (hal.dll e as pilhas de
// teclado/mouse e de armazenamento); nunca ficam no repositório.
include!(concat!(env!("OUT_DIR"), "/windows_binaries.rs"));

fn all() -> impl Iterator<Item = &'static BundleFile> {
    FILES.iter().chain(WINDOWS_BINARIES.iter())
}

/// `os.readBundleBytes(nome)`.
pub fn read(name: &str) -> Option<&'static [u8]> {
    all().find(|file| file.name == name).map(|file| file.data)
}

/// `os.listBundleFiles()`.
pub fn list() -> impl Iterator<Item = &'static str> {
    all().map(|file| file.name)
}
