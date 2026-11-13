//! Self-test da fase 6 — loader PE e ntoskrnl.
//!
//! Exercita os primitivos PE (metadados, exports, encaminhamentos, API sets,
//! fontes de imagem) e, conforme entram, o loader, os exports do kernel e os
//! drivers nativos.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;


type Assert = fn(bool, &str);

const IMAGE_BASE: u64 = 0x1_4000_0000;

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_wide(bytes: &mut [u8], offset: usize, text: &str) -> u32 {
    let mut length = 0;
    for (index, unit) in text.encode_utf16().enumerate() {
        put16(bytes, offset + index * 2, unit);
        length += 2;
    }
    length
}

/// Schema API_SET_NAMESPACE v6 com três contratos.
fn api_set_schema() -> Vec<u8> {
    let mut bytes = alloc::vec![0u8; 0x400];
    let entries = 0x40usize;
    // (nome, comprimento hash em caracteres, valores (alias, host)).
    let contracts: [(&str, usize, &[(&str, &str)]); 3] = [
        ("api-ms-win-core-apiquery-l1-1-1", "api-ms-win-core-apiquery-l1-1".len(), &[("", "ntdll.dll")]),
        ("ext-ms-win-test-l1-1-0", "ext-ms-win-test-l1-1".len(), &[("", "kernel32.dll"), ("kernelbase.dll", "kernel.appcore.dll")]),
        ("ext-ms-win-absent-l1-1-0", "ext-ms-win-absent-l1-1".len(), &[("", "")]),
    ];
    let mut cursor = 0x100usize;
    for (index, (name, hashed, values)) in contracts.iter().enumerate() {
        let entry = entries + index * 24;
        let name_offset = cursor;
        let name_length = put_wide(&mut bytes, cursor, name);
        cursor += name_length as usize + 2;
        put32(&mut bytes, entry + 4, name_offset as u32);
        put32(&mut bytes, entry + 8, name_length);
        put32(&mut bytes, entry + 12, *hashed as u32 * 2);
        let value_table = cursor;
        cursor += values.len() * 20;
        put32(&mut bytes, entry + 16, value_table as u32);
        put32(&mut bytes, entry + 20, values.len() as u32);
        for (value_index, (alias, host)) in values.iter().enumerate() {
            let value = value_table + value_index * 20;
            let alias_offset = cursor;
            let alias_length = put_wide(&mut bytes, cursor, alias);
            cursor += alias_length as usize + 2;
            let host_offset = cursor;
            let host_length = put_wide(&mut bytes, cursor, host);
            cursor += host_length as usize + 2;
            put32(&mut bytes, value + 4, alias_offset as u32);
            put32(&mut bytes, value + 8, alias_length);
            put32(&mut bytes, value + 12, host_offset as u32);
            put32(&mut bytes, value + 16, host_length);
        }
    }
    put32(&mut bytes, 0, 6);
    put32(&mut bytes, 4, cursor as u32);
    put32(&mut bytes, 12, contracts.len() as u32);
    put32(&mut bytes, 16, entries as u32);
    bytes.truncate(cursor.max(0x100));
    bytes
}

/// PE32+ com `.text` (executável), `.edata` e `.apiset`; alinhamento de
/// arquivo igual ao de seção (o arquivo é também a imagem mapeada).
fn synthetic_pe() -> Vec<u8> {
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
    put16(&mut image, optional + 42, 0);
    put16(&mut image, optional + 48, 6);
    put16(&mut image, optional + 50, 1);
    put32(&mut image, optional + 56, 0x4000);
    put32(&mut image, optional + 60, 0x1000);
    put32(&mut image, optional + 64, 0xC0DE);
    put16(&mut image, optional + 68, 1);
    put16(&mut image, optional + 70, 0x0160);
    put32(&mut image, optional + 72, 0x10_0000);
    put32(&mut image, optional + 80, 0x1000);
    put32(&mut image, optional + 104, 0);
    put32(&mut image, optional + 108, 16);
    put32(&mut image, optional + 112, 0x2000);
    put32(&mut image, optional + 116, 0x70);
    let sections = optional + 0xF0;
    for (index, (name, virtual_address, characteristics)) in [(b".text\0\0\0", 0x1000u32, 0x6000_0020u32), (b".edata\0\0", 0x2000, 0x4000_0040), (b".apiset\0", 0x3000, 0x4000_0040)].iter().enumerate() {
        let header = sections + index * 40;
        image[header..header + 8].copy_from_slice(*name);
        put32(&mut image, header + 8, 0x1000);
        put32(&mut image, header + 12, *virtual_address);
        put32(&mut image, header + 16, 0x1000);
        put32(&mut image, header + 20, *virtual_address);
        put32(&mut image, header + 36, *characteristics);
    }
    // Diretório de exports em 0x2000: base 1, três funções, dois nomes.
    put32(&mut image, 0x2000 + 16, 1);
    put32(&mut image, 0x2000 + 20, 3);
    put32(&mut image, 0x2000 + 24, 2);
    put32(&mut image, 0x2000 + 28, 0x2028);
    put32(&mut image, 0x2000 + 32, 0x2034);
    put32(&mut image, 0x2000 + 36, 0x203C);
    put32(&mut image, 0x2028, 0x1010);
    put32(&mut image, 0x202C, 0x1020);
    put32(&mut image, 0x2030, 0x2060);
    put32(&mut image, 0x2034, 0x2040);
    put32(&mut image, 0x2038, 0x2048);
    put16(&mut image, 0x203C, 0);
    put16(&mut image, 0x203E, 2);
    image[0x2040..0x2046].copy_from_slice(b"Alpha\0");
    image[0x2048..0x2050].copy_from_slice(b"Forward\0");
    image[0x2060..0x206B].copy_from_slice(b"other.Beta\0");
    let schema = api_set_schema();
    image[0x3000..0x3000 + schema.len()].copy_from_slice(&schema);
    put32(&mut image, sections + 2 * 40 + 8, schema.len() as u32);
    put32(&mut image, sections + 2 * 40 + 16, schema.len() as u32);
    image
}

fn pe_primitives(assert: Assert) {
    use crate::ntos::mm::sysload::kernel_image_source::{self as sources, ImageSource, MemorySource};
    use crate::ntos::mm::sysload::pe_resolver::{self as resolver, ExportedModule, Symbol};
    use crate::ntos::{init::native_export_layout, mm::sysload::kernel_api_set, rtl::{api_set, image::{pe_exports, pe_image_information, pe_metadata_reader::MetadataReader}}};
    let image = synthetic_pe();
    let source = MemorySource { name: String::from("\\FS\\opennt-test.dll"), bytes: image.clone() };
    // Leitor de metadados com cache de páginas.
    let metadata = MetadataReader::new(&source);
    assert(matches!(metadata.read_u16(0), Ok(0x5A4D)) && matches!(metadata.read_u32(0x40), Ok(0x4550)) && matches!(metadata.read_u8(0x2040), Ok(0x41)), "pemetadata: leituras escalares");
    assert(matches!(metadata.read_u32(0xFFE), Ok(value) if value == u32::from_le_bytes([image[0xFFE], image[0xFFF], image[0x1000], image[0x1001]])) && metadata.read_u32(0x3FFE).is_err() && metadata.read_u8(0x4000).is_err(), "pemetadata: campo entre paginas e faixa do arquivo");
    // SECTION_IMAGE_INFORMATION.
    let information = pe_image_information::capture(&metadata, image.len() as u64, 0x44, 0x58, IMAGE_BASE);
    assert(information.as_ref().is_ok_and(|bytes| u64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0; 8])) == IMAGE_BASE + 0x1000 && u16::from_le_bytes([bytes[36], bytes[37]]) == 1 && u16::from_le_bytes([bytes[38], bytes[39]]) == 6 && bytes[50] == 1 && bytes[51] == 0 && u16::from_le_bytes([bytes[48], bytes[49]]) == 0x8664 && u32::from_le_bytes(bytes[60..64].try_into().unwrap_or([0; 4])) == 0xC0DE), "peinfo: transferencia, versoes, codigo e checksum");
    let relocated = pe_image_information::capture(&metadata, image.len() as u64, 0x44, 0x58, IMAGE_BASE + 0x1000_0000);
    assert(relocated.is_ok_and(|bytes| bytes[51] == 4 && u64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0; 8])) == IMAGE_BASE + 0x1000_1000), "peinfo: imagem relocada com DYNAMIC_BASE");
    // EAT: nomes, ordinal sem nome e encaminhamento.
    let read_rva = |rva: u64, length: u64| source.read_bytes(rva, length);
    let exports = pe_exports::read_exports(&read_rva, IMAGE_BASE, 0x4000, 0x2000, 0x70).unwrap_or_default();
    assert(exports.exports.get("Alpha") == Some(&(IMAGE_BASE + 0x1010)) && exports.exports_by_ordinal.get(&2) == Some(&(IMAGE_BASE + 0x1020)) && exports.forwarders.get("Forward").map(String::as_str) == Some("other.Beta") && exports.forwarders_by_ordinal.contains_key(&3) && !exports.exports.contains_key("Forward"), "peexports: nomes, ordinal sem nome e encaminhamento");
    assert(pe_exports::read_exports(&read_rva, IMAGE_BASE, 0x4000, 0x2000, 20).is_err() && pe_exports::read_exports(&read_rva, IMAGE_BASE, 0x4000, 0, 0).is_ok_and(|empty| empty.exports.is_empty()), "peexports: diretorio invalido ou ausente");
    // Encaminhamentos entre módulos e ciclos.
    let module = ExportedModule { name: String::from("opennt-test.dll"), exports: exports.clone() };
    let mut other = pe_exports::Exports::default();
    other.exports.insert(String::from("Beta"), 0x9999);
    let other = Arc::new(ExportedModule { name: String::from("other.dll"), exports: other });
    let mut loader = |dll: &str, _importer: &str| if dll == "other.dll" { Ok(other.clone()) } else { Err(crate::rtl::KernelError::new("modulo ausente")) };
    let mut chain = alloc::collections::BTreeSet::new();
    assert(matches!(resolver::resolve_export(&module, &Symbol::Name(String::from("Forward")), &mut loader, &mut chain), Ok(0x9999)) && matches!(resolver::resolve_export(&module, &Symbol::Ordinal(2), &mut loader, &mut chain), Ok(address) if address == IMAGE_BASE + 0x1020) && resolver::resolve_export(&module, &Symbol::Name(String::from("Ausente")), &mut loader, &mut chain).is_err() && chain.is_empty(), "peresolver: encaminhamento, ordinal e ausente");
    let mut looping = pe_exports::Exports::default();
    looping.forwarders.insert(String::from("Loop"), String::from("loop.Loop"));
    let looping = Arc::new(ExportedModule { name: String::from("loop.dll"), exports: looping });
    let mut cyclic = |_dll: &str, _importer: &str| Ok(looping.clone());
    assert(resolver::resolve_export(&looping, &Symbol::Name(String::from("Loop")), &mut cyclic, &mut chain).is_err_and(|error| error.message.contains("ciclo")), "peresolver: ciclo de encaminhamentos detectado");
    // API set v6 pela seção .apiset.
    let schema = api_set::parse_image(&source);
    assert(schema.as_ref().is_ok_and(|schema| schema.size() == 3), "apiset: schema v6 lido da secao .apiset");
    if let Ok(schema) = schema {
        assert(schema.resolve("API-MS-WIN-CORE-APIQUERY-L1-1-0.DLL", "").as_deref() == Some("ntdll.dll") && schema.resolve("api-ms-win-core-apiquery-l1-1-1", "").as_deref() == Some("ntdll.dll"), "apiset: nome hash sem a revisao final");
        assert(schema.resolve("ext-ms-win-test-l1-1-0", "C:\\Windows\\System32\\KernelBase.dll").as_deref() == Some("kernel.appcore.dll") && schema.resolve("ext-ms-win-test-l1-1-0", "advapi32.dll").as_deref() == Some("kernel32.dll"), "apiset: alias por importador");
        assert(schema.resolve("ext-ms-win-absent-l1-1-0", "").as_deref() == Some("") && schema.resolve("ext-ms-win-desconhecido-l1-1-0", "").is_none(), "apiset: host ausente e contrato desconhecido");
    }
    assert(api_set::parse(&[0u8; 32]).is_err(), "apiset: versao de schema invalida");
    // Fonte de imagens: VFS em memória e volume NTFS montado.
    let _ = crate::drivers::fs::memory_file_system::write_bytes("/opennt-test.dll", image.clone());
    let found = sources::source_for("OpenNT-Test.DLL");
    assert(found.as_ref().is_ok_and(|found| found.name() == "\\FS\\opennt-test.dll" && found.size() == 0x4000), "kernelimagesource: imagem do VFS");
    assert(sources::source_for("nao valido.dll").is_err() && sources::source_for("semextensao").is_err() && sources::source_for("ausente-opennt.sys").is_err(), "kernelimagesource: nome invalido e imagem ausente");
    assert(crate::drivers::fs::ntfs::mounted().is_some(), "kernelimagesource: volume NTFS montado em D:");
    // O apisetschema.dll real da instalação, no volume, quando o build o leva.
    let schema_present = sources::source_for("apisetschema.dll").is_ok();
    let resolved = kernel_api_set::resolve("api-ms-win-core-apiquery-l1-1-0", "");
    assert(if schema_present { matches!(resolved, Ok(Some(ref host)) if host.eq_ignore_ascii_case("ntdll.dll")) } else { resolved.is_err() }, "kernelapiset: schema real da instalacao (ou ausencia reportada)");
    assert(native_export_layout::lookup("__chkstk") == Some(("probe_kernel_stack", "getKernelStackProbeEntry", 0)) && native_export_layout::lookup("DbgPrint").is_none(), "nativeexportlayout: exports com corpo proprio");
}

/// Imagem carregável: a sintética com `.idata` (imports por nome e ordinal),
/// `.reloc` (um DIR64), um ponteiro absoluto e o cookie GS padrão do link.
fn loadable_pe() -> Vec<u8> {
    let mut image = synthetic_pe();
    image.resize(0x6000, 0);
    let coff = 0x44;
    let optional = 0x58;
    put16(&mut image, coff + 2, 5);
    put32(&mut image, optional + 56, 0x6000);
    put32(&mut image, optional + 120, 0x4000); // DataDirectory[1] import
    put32(&mut image, optional + 124, 40);
    put32(&mut image, optional + 152, 0x5000); // DataDirectory[5] reloc
    put32(&mut image, optional + 156, 12);
    let sections = optional + 0xF0;
    for (index, (name, virtual_address)) in [(b".idata\0\0", 0x4000u32), (b".reloc\0\0", 0x5000)].iter().enumerate() {
        let header = sections + (3 + index) * 40;
        image[header..header + 8].copy_from_slice(*name);
        put32(&mut image, header + 8, 0x1000);
        put32(&mut image, header + 12, *virtual_address);
        put32(&mut image, header + 16, 0x1000);
        put32(&mut image, header + 20, *virtual_address);
        put32(&mut image, header + 36, 0xC000_0040);
    }
    // .text: ponteiro absoluto (alvo do DIR64) e o cookie padrão.
    image[0x1100..0x1108].copy_from_slice(&(IMAGE_BASE + 0x1010).to_le_bytes());
    put32(&mut image, 0x1200, 0x2DDF_A232);
    put32(&mut image, 0x1204, 0x2B99);
    // Import descriptor -> ILT 0x4040, nome 0x4080, IAT 0x4060.
    put32(&mut image, 0x4000, 0x4040);
    put32(&mut image, 0x400C, 0x4080);
    put32(&mut image, 0x4010, 0x4060);
    for table in [0x4040usize, 0x4060] {
        image[table..table + 8].copy_from_slice(&0x40A0u64.to_le_bytes());
        image[table + 8..table + 16].copy_from_slice(&0x8000_0000_0000_0007u64.to_le_bytes());
    }
    image[0x4080..0x4095].copy_from_slice(b"opennt-test-host.dll\0");
    image[0x40A2..0x40AF].copy_from_slice(b"TestFunction\0");
    // .reloc: bloco da página 0x1000 com um DIR64 em +0x100 e padding.
    put32(&mut image, 0x5000, 0x1000);
    put32(&mut image, 0x5004, 12);
    put16(&mut image, 0x5008, (10 << 12) | 0x100);
    image
}

static DEPENDENCY_RETAINS: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);

struct TestDependency;

impl crate::ntos::mm::pe_loader::ImageDependency for TestDependency {
    fn retain(&self) {
        DEPENDENCY_RETAINS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    }
    fn release(&self) -> Result<(), crate::rtl::KernelError> {
        DEPENDENCY_RETAINS.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

fn pe_loader_kernel_images(assert: Assert) {
    use crate::hal::physical;
    use crate::ntos::mm::pe_loader::{self as loader, ImportSymbol, LoadOptions, ResolvedImport};
    use core::sync::atomic::Ordering;
    let dependency: Arc<dyn loader::ImageDependency> = Arc::new(TestDependency);
    let held = dependency.clone();
    loader::register_resolver(
        |dll| dll.eq_ignore_ascii_case("opennt-test-host.dll"),
        Arc::new(move |_dll: &str, symbol: &ImportSymbol| match symbol {
            ImportSymbol::Name(name) if name == "TestFunction" => Some(ResolvedImport::Address { address: 0x1234_5678_9ABC, dependencies: alloc::vec![held.clone()] }),
            ImportSymbol::Ordinal(7) => Some(ResolvedImport::Address { address: 0x7777, dependencies: alloc::vec![held.clone()] }),
            _ => None,
        }),
    );
    DEPENDENCY_RETAINS.store(0, Ordering::SeqCst);
    let options = LoadOptions { image_name: Some(String::from("opennt-loader-test.sys")), ..Default::default() };
    let loaded = loader::load(loadable_pe(), &options);
    let Ok(mut image) = loaded else {
        assert(false, "peloader: imagem carregada");
        return;
    };
    let base = image.image_base;
    assert(base >= 0x190_0000 && base < 0x1F0_0000 && image.physical_base == base && image.preferred_base == IMAGE_BASE && image.size_of_image == 0x6000 && image.entry_point == base + 0x1000, "peloader: imagem relocada para a arena de runtime");
    assert(physical::read64(base + 0x1100) == base + 0x1010, "peloader: fixup DIR64 aplicado");
    let cookie = physical::read64(base + 0x1200);
    assert(cookie != 0x2B99_2DDF_A232 && cookie != 0 && cookie >> 48 == 0, "peloader: cookie GS semeado (48 bits, nunca o padrao)");
    assert(physical::read64(base + 0x4060) == 0x1234_5678_9ABC && physical::read64(base + 0x4068) == 0x7777 && image.resolved_imports.len() == 2 && image.resolved_imports[1].name == "ordinal #7", "peloader: IAT por nome e por ordinal");
    assert(DEPENDENCY_RETAINS.load(Ordering::SeqCst) == 1, "peloader: dependencia retida uma vez");
    assert(image.exports.exports.get("Alpha") == Some(&(base + 0x1010)) && image.sections.len() == 5 && image.sections[0].name == ".text", "peloader: exports lidos da imagem mapeada");
    assert(image.loaded_image.as_ref().is_some_and(|loaded| loaded.name == "opennt-loader-test.sys" && loaded.image_base == base) && crate::ntos::mm::loaded_images::find(base + 0x1000).is_some(), "peloader: imagem registrada nas imagens carregadas");
    assert(image.image_information[51] == 4 && image.loader_flags == 0, "peloader: informacao da secao relocada e sem bit de CI");
    assert(image.release().is_ok() && crate::ntos::mm::loaded_images::find(base + 0x1000).is_none() && DEPENDENCY_RETAINS.load(Ordering::SeqCst) == 0 && physical::read64(base + 0x1100) == 0, "peloader: liberacao desfaz registro, dependencia e arena");
    // A arena devolvida é reutilizada; erros desfazem a carga.
    let again = loader::load(loadable_pe(), &options);
    assert(again.as_ref().is_ok_and(|image| image.image_base == base), "peloader: slot devolvido reutilizado");
    if let Ok(mut again) = again {
        let _ = again.release();
    }
    let mut broken = loadable_pe();
    broken[0x40A2..0x40AF].copy_from_slice(b"Ausentefunc\0\0");
    assert(loader::load(broken, &options).is_err_and(|error| error.message.contains("API nao suportada")) && DEPENDENCY_RETAINS.load(Ordering::SeqCst) == 0, "peloader: import nao resolvido desfaz a carga");
    let next = loader::load(loadable_pe(), &options);
    assert(next.as_ref().is_ok_and(|image| image.image_base == base), "peloader: falha nao vaza a arena");
    if let Ok(mut next) = next {
        let _ = next.release();
    }
    let mut not_pe = loadable_pe();
    not_pe[0] = b'X';
    assert(loader::load(not_pe, &options).is_err_and(|error| error.message.contains("MZ")), "peloader: imagem sem MZ recusada");
}

/// Imagem que importa do `ntoskrnl.exe` (nomes e um ordinal da ABI).
fn ntoskrnl_importer(first_import: &[u8]) -> Vec<u8> {
    let mut image = loadable_pe();
    put32(&mut image, 0x4000, 0x4100);
    put32(&mut image, 0x400C, 0x4300);
    put32(&mut image, 0x4010, 0x4200);
    image[0x4300..0x430D].copy_from_slice(b"ntoskrnl.exe\0");
    let names: [&[u8]; 4] = [first_import, b"WRITE_PORT_UCHAR\0", b"PsGetCurrentThreadPreviousMode\0", b"ZwQuerySystemEnvironmentValueEx\0"];
    let mut entries = Vec::new();
    for (index, name) in names.iter().enumerate() {
        let hint = 0x4400 + index * 0x40;
        image[hint + 2..hint + 2 + name.len()].copy_from_slice(name);
        entries.push(hint as u64);
    }
    // READ_PORT_UCHAR pelo ordinal da ABI (grupo hal, índice 546).
    entries.insert(1, 0x8000_0000_0000_0000 | 547);
    for table in [0x4100usize, 0x4200] {
        for (index, entry) in entries.iter().enumerate() {
            image[table + index * 8..table + index * 8 + 8].copy_from_slice(&entry.to_le_bytes());
        }
    }
    image
}

fn ntoskrnl_exports(assert: Assert) {
    use crate::hal::amd64::{native_call, win32_thunk};
    use crate::ntos::mm::kernel_address;
    use crate::{ntos::init::export_names as abi_names, ntos::init::exports};
    use crate::ntos::mm::pe_loader::{self as loader, LoadOptions, ResolvedImport};
    exports::init();
    assert(abi_names::EXPORT_NAMES.len() == 893 && abi_names::GROUP_LAYOUT.len() == 150 && abi_names::EXPORT_NAMES[0] == "DbgPrint" && abi_names::EXPORT_NAMES[546] == "READ_PORT_UCHAR" && abi_names::EXPORT_NAMES[779] == "ZwDisplayString" && abi_names::EXPORT_NAMES[787] == "KeAcquireQueuedSpinLock", "ntoskrnl: ordem da ABI com 893 exports em 150 grupos");
    // Ordinais públicos: os slots de função seguidos dos dados sem nome repetido.
    let public_count = abi_names::EXPORT_NAMES.len() + crate::ntos::mm::kernel_data_layout::DEFINITIONS.iter().filter(|entry| !abi_names::EXPORT_NAMES.contains(&entry.name)).count();
    assert(matches!(exports::lookup_ordinal("ntoskrnl.exe", 547), Some(ResolvedImport::Thunk(578))) && exports::lookup("ntoskrnl.exe", "LdrResSearchResource").is_some() && exports::lookup("ntoskrnl.exe", "NaoExisteNoKernel").is_none() && exports::lookup_ordinal("ntoskrnl.exe", 0).is_none() && exports::lookup_ordinal("ntoskrnl.exe", public_count as u32).is_some() && exports::lookup_ordinal("ntoskrnl.exe", public_count as u32 + 1).is_none(), "ntoskrnl: ordinais, todos os exports com provedor e nome desconhecido");
    let options = LoadOptions { image_name: Some(String::from("opennt-ntoskrnl-test.sys")), ..Default::default() };
    let loaded = loader::load(ntoskrnl_importer(b"PsGetThreadId\0"), &options);
    let Ok(mut image) = loaded else {
        assert(false, "ntoskrnl: driver de teste carregado");
        return;
    };
    let base = image.image_base;
    let iat = |slot: u64| crate::hal::physical::read64(base + 0x4200 + slot * 8);
    let (table, count) = win32_thunk::thunk_table();
    let thunk = |id: u64| kernel_address::virtual_address(table + id * win32_thunk::STUB_SIZE).unwrap_or(0);
    assert(count == 1024 && iat(0) == thunk(32 + 658) && iat(1) == thunk(32 + 546) && iat(0) != 0 && image.resolved_imports.len() == 5, "ntoskrnl: IAT recebe os trampolins dos ids");
    // Chamadas reais pelos trampolins (ABI MS x64 -> despachante Rust).
    let thread = guest::alloc_bytes(0x500);
    guest::write64(thread + 0x480, 0xFEDC_BA98_7654_3210);
    assert(native_call::call(iat(0), &[thread]) == 0xFEDC_BA98_7654_3210, "ntoskrnl: PsGetThreadId devolve os 64 bits exatos");
    guest::free_bytes(thread);
    native_call::call(iat(2), &[0x3FF, 0x1A5]);
    assert(native_call::call(iat(1), &[0x3FF]) == 0xA5, "ntoskrnl: WRITE/READ_PORT_UCHAR no registrador de rascunho da COM1");
    assert(crate::ntos::ps::previous_mode::get().is_ok_and(|mode| native_call::call(iat(3), &[]) == mode as u64), "ntoskrnl: PsGetCurrentThreadPreviousMode pelo trampolim");
    let firmware = crate::hal::firmware_environment::firmware_type();
    assert(firmware.is_err() || firmware.is_ok_and(|kind| kind != 1) || native_call::call(iat(4), &[0, 0, 0, 0, 0]) == 0xC000_0002, "ntoskrnl: Zw com cinco argumentos (BIOS legado)");
    assert(image.release().is_ok(), "ntoskrnl: driver de teste liberado");
    assert(loader::load(ntoskrnl_importer(b"NaoExisteNoKernel\0"), &options).is_err_and(|error| error.message.contains("NaoExisteNoKernel")), "ntoskrnl: import sem provedor recusa a carga");
}

/// Chama um export pelo seu trampolim (como um driver chamaria pela IAT).
fn call_export(name: &str, arguments: &[u64]) -> Option<u64> {
    use crate::hal::amd64::{native_call, win32_thunk};
    use crate::ntos::init::exports;
    use crate::ntos::mm::pe_loader::ResolvedImport;
    let Some(ResolvedImport::Thunk(id)) = exports::lookup("ntoskrnl.exe", name) else { return None };
    let (table, _) = win32_thunk::thunk_table();
    let address = crate::ntos::mm::kernel_address::virtual_address(table + id as u64 * win32_thunk::STUB_SIZE).ok()?;
    Some(native_call::call(address, arguments))
}

fn ntoskrnl_small_groups(assert: Assert) {
    use crate::ntos::inc::nt_abi::{eprocess, kthread};
    // Acessores de EPROCESS/ETHREAD sobre objetos sintéticos.
    let process = guest::alloc_bytes(eprocess::SIZE);
    guest::write64(process + eprocess::PEB, 0x7FF6_1234_5000);
    guest::write64(process + eprocess::WIN32_PROCESS, 0xFFFF_9000_0000_1230);
    guest::write32(process + eprocess::EXIT_STATUS, 0xC000_013A);
    guest::write32(process + eprocess::FLAGS, 1 << 2);
    assert(call_export("PsGetProcessPeb", &[process]) == Some(0x7FF6_1234_5000) && call_export("PsGetProcessWin32Process", &[process]) == Some(0xFFFF_9000_0000_1230), "ntoskrnl: PEB e Win32Process do EPROCESS");
    assert(call_export("PsGetProcessExitStatus", &[process]) == Some(0xC000_013A) && call_export("PsGetProcessExitProcessCalled", &[process]) == Some(1) && call_export("PsGetProcessImageFileName", &[process]) == Some(process + eprocess::IMAGE_FILE_NAME), "ntoskrnl: saida e nome da imagem do EPROCESS");
    assert(call_export("PsGetProcessWow64Process", &[process]) == Some(0), "ntoskrnl: processo sem EWOW64PROCESS");
    let wow64 = guest::alloc_bytes(16);
    guest::write64(wow64, 0x7E_F000);
    guest::write64(process + eprocess::WOW64_PROCESS, wow64);
    assert(call_export("PsGetProcessWow64Process", &[process]) == Some(0x7E_F000), "ntoskrnl: PEB do EWOW64PROCESS");
    let thread = guest::alloc_bytes(0x800);
    guest::write64(thread + kthread::PROCESS, process);
    guest::write64(thread + kthread::CID_UNIQUE_PROCESS, 0x1F4);
    guest::write32(thread + kthread::EXIT_STATUS, 0x4000_0000);
    assert(call_export("PsGetThreadProcess", &[thread]) == Some(process) && call_export("PsGetThreadProcessId", &[thread]) == Some(0x1F4), "ntoskrnl: processo e PID da thread");
    assert(call_export("PsGetThreadExitStatus", &[thread]) == Some(0x103) && guest::read64(thread + kthread::RUNDOWN_PROTECT) == 0, "ntoskrnl: thread viva devolve STATUS_PENDING");
    guest::write64(thread + kthread::RUNDOWN_PROTECT, 1);
    assert(call_export("PsGetThreadExitStatus", &[thread]) == Some(0x4000_0000), "ntoskrnl: thread em rundown devolve o status de saida");
    guest::free_bytes(thread);
    guest::free_bytes(wow64);
    guest::free_bytes(process);
    // Consultas simples, pool e memória contígua.
    let mode = crate::ntos::ps::previous_mode::get().unwrap_or(0xFF);
    assert(call_export("ExSystemExceptionFilter", &[]) == Some((mode != 0) as u64) && call_export("FsRtlIsSystemPagingFile", &[0]) == Some(0) && call_export("FsRtlGetVirtualDiskNestingLevel", &[0, 0, 0]) == Some(0), "ntoskrnl: filtro de excecao e consultas do FsRtl");
    let pool = call_export("ExAllocatePoolWithTagPriority", &[0, 64, u32::from_le_bytes(*b"Tst6") as u64, 16]).unwrap_or(0);
    assert(pool != 0 && crate::ntos::mm::kernel_pool::free(pool, None).is_ok(), "ntoskrnl: ExAllocatePoolWithTagPriority");
    let contiguous = call_export("MmAllocateContiguousMemorySpecifyCache", &[0x2000, 0, 0xFFFF_FFFF, 0, 1]).unwrap_or(0);
    assert(contiguous != 0 && call_export("MmFreeContiguousMemory", &[contiguous]) == Some(0), "ntoskrnl: memoria contigua aloca e libera");
    assert(call_export("NtClose", &[0x7FFF_0004]).is_some_and(|status| status & 0x8000_0000 != 0), "ntoskrnl: NtClose de handle invalido falha");
    // DbgPrompt resolve para o corpo nativo próprio, que conta o prompt,
    // normaliza os comprimentos USHORT e executa o serviço 2 do int 0x2D.
    let entry = crate::hal::amd64::private_entries::entry("dbg_prompt").unwrap_or(0);
    let resolved = crate::ntos::init::exports::lookup("ntoskrnl.exe", "DbgPrompt");
    let published = matches!(resolved, Some(crate::ntos::mm::pe_loader::ResolvedImport::Address { address, .. }) if entry != 0 && crate::ntos::mm::kernel_address::virtual_address(entry).ok() == Some(address));
    let body = crate::hal::physical::read_bytes(entry, 48);
    let service = body.windows(9).any(|window| window == [0xB8, 2, 0, 0, 0, 0xCD, 0x2D, 0xCC, 0xC3]);
    assert(published && service && body.starts_with(&[0x45, 0x89, 0xC1, 0x49, 0x89, 0xD0, 0x31, 0xD2]), "ntoskrnl: DbgPrompt publica o corpo nativo do servico de depuracao");
}

fn kernel_trap_dispatch(assert: Assert) {
    use crate::hal::amd64::native_call;
    use crate::ntos::mm::pe_loader::{self as loader, LoadOptions};
    // .text em 0x1300: mov eax, 1; int 0x2D; int3; mov eax, 0x42; ret. O
    // serviço de depuração 1 com KD inativo avança o RIP por cima do int3.
    let mut bytes = ntoskrnl_importer(b"PsGetThreadId\0");
    bytes[0x1300..0x130E].copy_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00, 0xCD, 0x2D, 0xCC, 0xB8, 0x42, 0x00, 0x00, 0x00, 0xC3]);
    let options = LoadOptions { image_name: Some(String::from("opennt-kernel-trap.sys")), ..Default::default() };
    let Ok(mut image) = loader::load(bytes, &options) else {
        assert(false, "kerneltrap: imagem com codigo carregada");
        return;
    };
    let before = native_call::set_sync_active(0);
    native_call::set_sync_active(before);
    let result = native_call::call(image.image_base + 0x1300, &[]);
    let after = native_call::set_sync_active(0);
    native_call::set_sync_active(after);
    assert(result as u32 == 0x42 && before == 0 && after == 0, "kerneltrap: int 0x2D do servico 1 continua pelo despacho de excecao de kernel");
    let _ = image.release();
}

fn file_information_group(assert: Assert) {
    use crate::drivers::fs::extended_attributes::{self as ea, Entry};
    use crate::drivers::fs::{memory_file_system, ntfs, volume::FileSystem};
    use crate::ntos::io::io_manager;
    use crate::ntos::ob::close;
    use crate::ntos::inc::nt_abi::{device_object, driver_object};
    use crate::ntos::io::lifecycle;
    use crate::ntos::io::file::zw as zw_files;
    let dirty = |value: u64| 0xF123_4567_0000_0000 | value;
    // Driver nativo: Status 0, Information 4, "ABCD" no SystemBuffer quando
    // houver e IofCompleteRequest(irp, 0) pela IAT.
    let mut image = ntoskrnl_importer(b"IofCompleteRequest\0");
    let displacement = (0x4200u32 - (0x1300 + 0x31)).to_le_bytes();
    let mut dispatch = alloc::vec![0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0xD3, 0xC7, 0x43, 0x30, 0, 0, 0, 0, 0x48, 0xC7, 0x43, 0x38, 4, 0, 0, 0, 0x48, 0x8B, 0x43, 0x18, 0x48, 0x85, 0xC0, 0x74, 0x06, 0xC7, 0x00, 0x41, 0x42, 0x43, 0x44, 0x48, 0x89, 0xD9, 0x31, 0xD2, 0xFF, 0x15];
    dispatch.extend_from_slice(&displacement);
    dispatch.extend_from_slice(&[0x31, 0xC0, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3]);
    image[0x1300..0x1300 + dispatch.len()].copy_from_slice(&dispatch);
    image[0x1340..0x1343].copy_from_slice(&[0x31, 0xC0, 0xC3]);
    put32(&mut image, 0x58 + 16, 0x1340);
    let _ = memory_file_system::write_bytes("/opennt-fsinfo.sys", image);
    let loaded = lifecycle::load_driver("/opennt-fsinfo.sys", &lifecycle::DriverOptions::default());
    let driver = crate::ntos::ob::object_manager::lookup("\\Driver\\opennt-fsinfo").and_then(crate::ntos::ob::object_manager::node).and_then(|node| node.data).map_or(0, |data| data.native_pointer);
    if loaded.is_err() || driver == 0 {
        assert(false, "fsinfo: driver nativo carregado");
        return;
    }
    let base = guest::read64(driver + driver_object::DRIVER_START);
    for major in [0u64, 2, 7, 8, 13] {
        guest::write64(driver + driver_object::MAJOR_FUNCTION + major * 8, base + 0x1300);
    }
    let kernel = guest::alloc_bytes(0x1000);
    let name = unicode_at(kernel, "\\Device\\OpenNtFsInfo");
    let _ = call_export("IoCreateDevice", &[driver, 0, name, 0x22, 0, 0, kernel + 0x100]);
    let device = guest::read64(kernel + 0x100);
    guest::write32(device + device_object::FLAGS, guest::read32(device + device_object::FLAGS) & !0x80);
    let opened = io_manager::open_device("\\Device\\OpenNtFsInfo", false);
    let Some(opened) = opened.ok().filter(|opened| opened.status == 0) else {
        assert(false, "fsinfo: dispositivo aberto");
        return;
    };
    let file = opened.file_object;
    let (input, output, returned) = (kernel + 0x200, kernel + 0x300, kernel + 0x400);
    // FSCTL bufferizado: entrada menor que a saída, o SystemBuffer é a saída.
    guest::write32(input, 0x3333_2222);
    guest::write64(output, 0);
    let buffered = call_export("FsRtlKernelFsControlFile", &[file, dirty(0x92000), input, dirty(4), output, dirty(8), returned]);
    let buffered_ok = buffered == Some(0) && guest::read32(returned) == 4 && guest::read32(output) == 0x4443_4241;
    // METHOD_NEITHER: sem SystemBuffer; METHOD_IN_DIRECT: a entrada é o SystemBuffer e a saída vai por MDL.
    guest::write64(output, 0x55);
    let neither = call_export("FsRtlKernelFsControlFile", &[file, dirty(0x92003), input, dirty(4), output, dirty(8), returned]);
    let neither_ok = neither == Some(0) && guest::read64(output) == 0x55;
    guest::write32(input, 0);
    let direct = call_export("FsRtlKernelFsControlFile", &[file, dirty(0x92001), input, dirty(4), output, dirty(8), returned]);
    let direct_ok = direct == Some(0) && guest::read32(input) == 0x4443_4241 && guest::read32(returned) == 4;
    assert(buffered_ok && neither_ok && direct_ok, "fsinfo: FsRtlKernelFsControlFile pelo IRP retido nos metodos bufferizado, neither e direto");
    // EA nativos: consulta (IRP_MJ_QUERY_EA) e escrita (IRP_MJ_SET_EA).
    let query = call_export("FsRtlQueryKernelEaFile", &[file, output, dirty(8), dirty(0x100), 0, dirty(0), 0, dirty(0x100), returned]);
    let set = call_export("FsRtlSetKernelEaFile", &[file, input, dirty(8)]);
    assert(query == Some(0) && guest::read32(returned) == 4 && set == Some(0), "fsinfo: EA de kernel pelos IRPs nativos");
    let _ = close::close(opened.handle, Some(0));
    // Arquivo real do NTFS: tamanho, volume, FSCTL do volume e EAs persistentes.
    let block = guest::alloc_bytes(0x400);
    let attributes = object_attributes_for(block, "\\DosDevices\\D:\\OPENNT-EA.DAT", 0x240);
    let created = zw_files::create_kernel_file(block + 0x300, 0x12019F, attributes, block + 0x310, 0, 3, 0x20);
    let handle = guest::read64(block + 0x300);
    let ntfs_file = zw_files::file_object_of_handle(handle);
    let volume = ntfs::mounted();
    if created.is_err() || ntfs_file == 0 || volume.is_none() {
        assert(false, "fsinfo: arquivo do NTFS aberto");
        return;
    }
    let volume = volume.unwrap();
    let _ = FileSystem::write_at(volume.as_ref(), "/OPENNT-EA.DAT", 0, b"OpenNT");
    let size = call_export("FsRtlGetFileSize", &[ntfs_file, output]);
    let volume_size = call_export("IoQueryVolumeInformation", &[ntfs_file, dirty(3), dirty(24), output + 0x20, returned]);
    let size_ok = size == Some(0) && guest::read64(output) == 6 && volume_size == Some(0) && guest::read32(returned) == 24 && guest::read32(output + 0x20 + 20) == 512;
    let data = call_export("FsRtlKernelFsControlFile", &[ntfs_file, dirty(0x90064), 0, dirty(0), kernel + 0x500, dirty(104), returned]);
    let data_ok = data == Some(0) && guest::read32(returned) == 104 && guest::read32(kernel + 0x500 + 40) == 512;
    assert(size_ok && data_ok, "fsinfo: tamanho, informacao de volume e FSCTL do volume NTFS");
    let empty = call_export("FsRtlQueryKernelEaFile", &[ntfs_file, kernel + 0x600, dirty(128), dirty(0), 0, dirty(0), 0, dirty(1), returned]);
    let encoded = ea::encode(&[Entry { name: b"USER.TEST".to_vec(), flags: 0, value: alloc::vec![1, 2] }, Entry { name: b"OPENNT.KERNEL".to_vec(), flags: 0, value: alloc::vec![3] }], false);
    guest::write_bytes(kernel + 0x700, &encoded);
    let stored = call_export("FsRtlSetKernelEaFile", &[ntfs_file, kernel + 0x700, dirty(encoded.len() as u64)]);
    let listed = call_export("FsRtlQueryKernelEaFile", &[ntfs_file, kernel + 0x600, dirty(256), dirty(0), 0, dirty(0), 0, dirty(1), returned]);
    let length = guest::read32(returned) as usize;
    let parsed = ea::parse(&guest::read_bytes(kernel + 0x600, length), false, false).map(|entries| entries.len());
    let short = call_export("FsRtlQueryKernelEaFile", &[ntfs_file, kernel + 0x600, dirty(2), dirty(0), 0, dirty(0), 0, dirty(1), returned]);
    assert(empty == Some(0xC000_0052) && stored == Some(0) && listed == Some(0) && parsed.is_ok_and(|count| count == 2) && short == Some(0xC000_0023) && guest::read32(returned) == 0, "fsinfo: EAs persistentes no NTFS, lista vazia e saida curta");
    let _ = close::close(handle, Some(0));
    let _ = FileSystem::remove(volume.as_ref(), "/OPENNT-EA.DAT");
    guest::free_bytes(block);
    guest::free_bytes(kernel);
}

fn ps_group(assert: Assert) {
    use crate::ntos::mm::kernel_data;
    use crate::ntos::ps::process;
    use crate::ntos::ps::silo::contexts as silo_contexts;
    use crate::ntos::inc::nt_abi::eprocess;
    use crate::ntos::init::exports;
    use crate::ntos::mm::pe_loader::ResolvedImport;
    // Identidade do processo e da thread correntes.
    let system = process::get_system_process();
    let current = call_export("PsGetCurrentProcess", &[]);
    let ids = (call_export("PsGetCurrentProcessId", &[]), call_export("PsGetCurrentThreadId", &[]));
    assert(current == Some(process::get_current_process()) && ids == (Some(process::get_current_process_id()), Some(process::get_current_thread_id())), "ps: processo e thread correntes pelo KTHREAD");
    let pid = guest::read64(system + eprocess::UNIQUE_PROCESS_ID);
    let created = call_export("PsGetProcessCreateTimeQuadPart", &[system]);
    assert(call_export("PsGetProcessId", &[system]) == Some(pid) && created == Some(guest::read64(system + eprocess::CREATE_TIME)), "ps: PID e CreateTime da EPROCESS");
    // PsLookupProcessByProcessId devolve uma referência.
    let output = guest::alloc_bytes(0x40);
    let before = process::reference_count(system);
    let found = call_export("PsLookupProcessByProcessId", &[pid, output]);
    let referenced = guest::read64(output) == system && process::reference_count(system) == before.map(|count| count + 1);
    let _ = process::dereference(system);
    let missing = call_export("PsLookupProcessByProcessId", &[0x7FF0, output]);
    assert(found == Some(0) && referenced && missing == Some(0xC000_000B), "ps: PsLookupProcessByProcessId referencia o processo e recusa PID ausente");
    // Silo hospedeiro e erros graves.
    assert(call_export("PsGetHostSilo", &[]) == Some(0) && call_export("PsIsHostSilo", &[0]) == Some(1) && call_export("PsIsHostSilo", &[0x1000]) == Some(0), "ps: silo hospedeiro NULL");
    let hard = (call_export("PsGetThreadHardErrorsAreDisabled", &[]), call_export("PsSetThreadHardErrorsAreDisabled", &[1]), call_export("PsGetThreadHardErrorsAreDisabled", &[]), call_export("PsSetThreadHardErrorsAreDisabled", &[0]));
    assert(hard == (Some(0), Some(0), Some(1), Some(1)), "ps: erros graves com o valor anterior");
    // Slot e contexto de silo: alocação, criação, liberação pela contagem.
    let slot = call_export("PsAllocSiloContextSlot", &[0, output]);
    let index = guest::read32(output);
    let context = call_export("PsCreateSiloContext", &[0, 32, 0x200, 0, output + 8]);
    let pointer = guest::read64(output + 8);
    let alive = silo_contexts::exists(pointer);
    let released = call_export("PsDereferenceSiloContext", &[pointer]) == Some(0) && !silo_contexts::exists(pointer);
    let freed = call_export("PsFreeSiloContextSlot", &[index as u64]);
    assert(slot == Some(0) && context == Some(0) && alive && released && freed == Some(0), "ps: slot e contexto de silo pelos exports");
    // Remover um callback de criação nunca registrado falha.
    assert(call_export("PsRemoveCreateProcessNotifyRoutine", &[0x1234]).is_some_and(|status| status & 0x8000_0000 != 0), "ps: remocao de callback ausente recusada");
    // Células de dado.
    let data = |name: &str| match exports::lookup("ntoskrnl.exe", name) {
        Some(ResolvedImport::Address { address, .. }) => address,
        _ => 0,
    };
    let initial = data("PsInitialSystemProcess");
    let job = data("PsJobType");
    let cells = initial != 0 && kernel_data::address("PsInitialSystemProcess").ok() == Some(initial) && guest::read64(initial) == system && data("PsProcessType") == kernel_data::address("PsProcessType").unwrap_or(1) && data("PsThreadType") == kernel_data::address("PsThreadType").unwrap_or(1);
    let types = guest::read64(data("PsProcessType")) == crate::ntos::ob::object_types::process_type().pointer && guest::read64(data("PsThreadType")) == crate::ntos::ob::object_types::thread_type().pointer;
    let others = ["IoDriverObjectType", "IoFileObjectType", "MmSectionObjectType", "SeTokenObjectType"].iter().all(|name| kernel_data::address(name).is_ok_and(|cell| guest::read64(cell) != 0));
    assert(cells && types && others && job != 0 && data("PsJobType") == job && guest::read64(job) != 0, "ps: celulas PsInitialSystemProcess, PsProcessType, PsThreadType e PsJobType e os tipos publicados no boot");
    guest::free_bytes(output);
}

fn resource_search_exports(assert: Assert) {
    use super::resource_search_fixtures::{self as fixtures, ImageFixture};
    use crate::drivers::fs::{ntfs, volume::FileSystem};
    use crate::ntos::io::small::boot_drivers_state;
    use crate::ntos::mm::{kernel_pool, loaded_images, paging};
    use crate::ntos::ps::user::sections;
    use crate::ntos::rtl::resource::satellites as resource_satellites;
    const UNCHANGED: u64 = 0xA5A5_A5A5_A5A5_A5A5;
    const UNMAPPED: u64 = 0xFFFF_8888_7777_6000;
    let options = kernel_pool::AllocateOptions { tag: 0x7352_7354, zero: true, ..kernel_pool::AllocateOptions::default() };
    let (Ok(image), Ok(scratch)) = (kernel_pool::allocate(0x4000, options), kernel_pool::allocate(0x1000, options)) else {
        assert(false, "ressearch: alocacoes do teste");
        return;
    };
    let initial_views = sections::system_views().len();
    let initial_modules = loaded_images::list().len();
    let (data_output, size_output, path, culture, culture_length) = (scratch + 0x100, scratch + 0x110, scratch + 0x200, scratch + 0x300, scratch + 0x380);
    let populate = |fixture: &ImageFixture| {
        for offset in (0..0x4000).step_by(8) {
            guest::write64(image + offset, 0);
        }
        for &(offset, value) in fixture.words {
            guest::write32(image + offset as u64, value);
        }
    };
    // Resíduos altos não podem arredondar Count nem Flags antes da extração ULONG.
    let invoke = |base: u64, count: u64, flags: u64, keys: &[u64], with_culture: bool, path_override: Option<u64>, size_override: Option<u64>, capacity: Option<u64>| -> u32 {
        for offset in (0x100..0x400).step_by(8) {
            guest::write64(scratch + offset, UNCHANGED);
        }
        for (index, value) in keys.iter().enumerate() {
            guest::write64(path + index as u64 * 8, *value);
        }
        if with_culture {
            guest::write32(culture_length, 32);
        }
        if let Some(capacity) = capacity {
            guest::write64(size_output, capacity);
        }
        let arguments = [base, path_override.unwrap_or(path), count | 1 << 60, flags | 1 << 60, data_output, size_override.unwrap_or(size_output), if with_culture { culture } else { 0 }, if with_culture { culture_length } else { 0 }];
        call_export("LdrResSearchResource", &arguments).map_or(u32::MAX, |status| status as u32)
    };
    // Casos básicos com status, ponteiro e tamanho das instruções originais.
    let mut failure = None;
    for (index, row) in fixtures::BASIC.iter().enumerate() {
        populate(if row.tag & 1 != 0 || row.flags & 0x200 != 0 { &fixtures::RAW } else { &fixtures::MAPPED });
        let status = invoke(image | row.tag, row.count, row.flags, &[16, 1, 0, 0], false, None, None, (row.flags & 0x8_0000 != 0).then_some(row.capacity));
        let pointer = guest::read64(data_output);
        let expected = if row.pointer == UNCHANGED { UNCHANGED } else { image + row.pointer };
        let payload = status != 0 || row.flags & 2 != 0 || guest::read32(image + row.pointer) == 0x656E_776F;
        if failure.is_none() && (status != row.status || pointer != expected || guest::read64(size_output) != row.size || !payload) {
            failure = Some((index, status, pointer, guest::read64(size_output)));
        }
    }
    if let Some((index, status, pointer, size)) = failure {
        crate::debug_print!("[ressearch] caso {} status={:#x} ponteiro={:#x} tamanho={:#x}", index, status, pointer, size);
    }
    assert(failure.is_none(), "ressearch: casos basicos com status, ponteiro e tamanho do original");
    // Contagem recusada antes de tocar o caminho; caminho não mapeado; saídas sobrepostas.
    populate(&fixtures::MAPPED);
    let unmapped = paging::access_flags(UNMAPPED) & 1 == 0;
    let count_first = invoke(image, 5, 0, &[16, 1, 0, 0], false, Some(UNMAPPED), None, None);
    let fault = invoke(image, 3, 0, &[16, 1, 0, 0], false, Some(UNMAPPED), None, None);
    let overlapping = invoke(image, 3, 0, &[16, 1, 0, 0], false, None, Some(data_output), None);
    assert(unmapped && count_first == 0xC000_00F1 && fault == 0xC000_0005 && overlapping == 0 && guest::read64(data_output) == 16, "ressearch: contagem antes do caminho, caminho nao mapeado e saidas sobrepostas");
    // LdrResFindResource: mesma pesquisa pela entrada de nove argumentos.
    populate(&fixtures::MAPPED);
    for offset in (0x100..0x400).step_by(8) {
        guest::write64(scratch + offset, UNCHANGED);
    }
    let found = call_export("LdrResFindResource", &[image, 16, 1, 0, data_output, size_output, 0, 0, 0]).map(|status| status as u32);
    let bad_flags = call_export("LdrResFindResource", &[image, 16, 1, 0, data_output, size_output, 0, 0, 2]).map(|status| status as u32);
    assert(found == Some(0) && guest::read64(data_output) == image + 0x1800 && guest::read32(guest::read64(data_output)) == 0x656E_776F && bad_flags == Some(0xC000_000D), "resfind: LdrResFindResource publica o payload e recusa flags invalidas");
    // MUI: arquivos reais no NTFS, SECTION e vista global por dono.
    let Some(volume) = ntfs::mounted() else {
        assert(false, "ressearch: volume NTFS montado");
        return;
    };
    assert(boot_drivers_state::is_initialized(), "ressearch: fase dos drivers de boot concluida");
    // A validação do satélite compara o LanguageName com a tabela de caixa do
    // volume (l_intl.nls); sem ela a parte MUI não pode rodar neste boot.
    if crate::ntos::rtl::unicode_case::upcase("en-US").is_err() {
        assert(call_export("LdrResSearchResource", &[0, path, 3, 0, data_output, size_output, 0, 0]) == Some(0xC000_000D), "ressearch: MUI depende da tabela de caixa do volume (ausencia reportada)");
        let _ = kernel_pool::free(scratch, None);
        let _ = kernel_pool::free(image, None);
        return;
    }
    let mut index = 0;
    let directory = loop {
        index += 1;
        let candidate = alloc::format!("/$opennt-resource-search-{index}");
        if !FileSystem::exists(volume.as_ref(), &candidate) {
            break candidate;
        }
    };
    let mut created: alloc::vec::Vec<String> = alloc::vec::Vec::new();
    for directory_path in [directory.clone(), alloc::format!("{directory}/en-US")] {
        let _ = volume.create(&directory_path, true, 0x10, 0);
        created.push(directory_path);
    }
    let mut mui_ok = true;
    let mut views_ok = true;
    for (name, fixture) in fixtures::FILES {
        let basename = alloc::format!("{name}.dll");
        let file_path = alloc::format!("{directory}/en-US/{basename}.mui");
        let mut bytes = alloc::vec![0u8; fixture.length];
        for &(offset, value) in fixture.words {
            bytes[offset as usize..offset as usize + 4].copy_from_slice(&value.to_le_bytes());
        }
        let _ = volume.create(&file_path, false, 0x20, bytes.len() as u64);
        created.push(file_path.clone());
        let _ = FileSystem::resize(volume.as_ref(), &file_path, bytes.len() as u64);
        mui_ok &= FileSystem::write_at(volume.as_ref(), &file_path, 0, &bytes).is_ok_and(|written| written == bytes.len() as u64);
        populate(&fixtures::PRIMARY);
        let entry = loaded_images::register(loaded_images::ImageDescription { image_base: image, size_of_image: 0x4000, ..Default::default() }, &alloc::format!("\\??\\D:{}\\{}", directory.replace('/', "\\"), basename));
        for row in fixtures::MUI.iter().filter(|row| row.file == *name) {
            let status = invoke(image, 4, 0x40, &[3, 1, 0x409, row.identifier], true, None, None, None);
            let pointer = guest::read64(data_output);
            let mut ok = status == row.status && guest::read64(size_output) == row.size;
            if status != 0 {
                ok &= pointer == 0 && guest::read32(culture_length) == 32;
            } else {
                let from_primary = pointer >= image && pointer < image + 0x4000;
                ok &= from_primary == row.primary && guest::read32(pointer) == if from_primary { 0x6D69_7270 } else { 2 } && guest::read32(culture_length) == 6;
            }
            if !ok && mui_ok {
                crate::debug_print!("[ressearch] MUI {} id={} status={:#x} ponteiro={:#x} tamanho={:#x}", name, row.identifier, status, pointer, guest::read64(size_output));
            }
            mui_ok &= ok;
        }
        views_ok &= sections::system_views().len() == initial_views + 1;
        if let Ok(entry) = entry {
            let _ = loaded_images::unregister(entry.id);
        }
        views_ok &= sections::system_views().len() == initial_views;
    }
    assert(mui_ok, "ressearch: MUI com a tabela de intervalos, o dono certo e a cultura en-US");
    assert(views_ok, "ressearch: uma vista MUI por dono, solta no descarregamento");
    let _ = resource_satellites::unload(image);
    for file_path in created.iter().rev() {
        let _ = FileSystem::remove(volume.as_ref(), file_path);
    }
    let _ = kernel_pool::free(scratch, None);
    let _ = kernel_pool::free(image, None);
    assert(sections::system_views().len() == initial_views && loaded_images::list().len() == initial_modules, "ressearch: vistas e donos de modulo liberados");
}

fn user_device_io(assert: Assert) {
    use crate::drivers::fs::memory_file_system;
    use crate::ntos::ps::user::{memory, state};
    use crate::ntos::inc::nt_abi::{device_object, driver_object};
    use crate::ntos::io::lifecycle;
    // Despacho nativo (rcx = DEVICE_OBJECT, rdx = IRP): Status 0,
    // Information 4, "ABCD" no SystemBuffer quando houver e
    // IofCompleteRequest(irp, 0) pela IAT. A entrada só devolve sucesso.
    let mut image = ntoskrnl_importer(b"IofCompleteRequest\0");
    let displacement = (0x4200u32 - (0x1300 + 0x31)).to_le_bytes();
    let mut dispatch = alloc::vec![0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0xD3, 0xC7, 0x43, 0x30, 0, 0, 0, 0, 0x48, 0xC7, 0x43, 0x38, 4, 0, 0, 0, 0x48, 0x8B, 0x43, 0x18, 0x48, 0x85, 0xC0, 0x74, 0x06, 0xC7, 0x00, 0x41, 0x42, 0x43, 0x44, 0x48, 0x89, 0xD9, 0x31, 0xD2, 0xFF, 0x15];
    dispatch.extend_from_slice(&displacement);
    dispatch.extend_from_slice(&[0x31, 0xC0, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3]);
    image[0x1300..0x1300 + dispatch.len()].copy_from_slice(&dispatch);
    image[0x1340..0x1343].copy_from_slice(&[0x31, 0xC0, 0xC3]);
    put32(&mut image, 0x58 + 16, 0x1340);
    let _ = memory_file_system::write_bytes("/opennt-devio.sys", image);
    let loaded = lifecycle::load_driver("/opennt-devio.sys", &lifecycle::DriverOptions::default());
    let driver = crate::ntos::ob::object_manager::lookup("\\Driver\\opennt-devio").and_then(crate::ntos::ob::object_manager::node).and_then(|node| node.data).map_or(0, |data| data.native_pointer);
    if loaded.is_err() || driver == 0 {
        assert(false, "devio: driver nativo carregado");
        return;
    }
    let base = guest::read64(driver + driver_object::DRIVER_START);
    for major in [0u64, 2, 3, 4] {
        guest::write64(driver + driver_object::MAJOR_FUNCTION + major * 8, base + 0x1300);
    }
    let kernel = guest::alloc_bytes(0x200);
    let name = unicode_at(kernel, "\\Device\\OpenNtDevIo");
    let _ = call_export("IoCreateDevice", &[driver, 0, name, 0x22, 0, 0, kernel + 0x100]);
    let device = guest::read64(kernel + 0x100);
    guest::write32(device + device_object::FLAGS, (guest::read32(device + device_object::FLAGS) | 4) & !0x80);
    // Abertura síncrona pelo NtCreateFile em memória de usuário.
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "devio: memoria de usuario");
        return;
    };
    let rsp = block + 0x800;
    let stack = |args: &[u64]| {
        for (index, value) in args.iter().enumerate() {
            guest::write64(rsp + 0x28 + index as u64 * 8, *value);
        }
    };
    let call = |name: &str, a: u64, b: u64, c: u64, d: u64| state::handler(name).map(|handler| handler(a, b, c, d, rsp)).and_then(|result| result.ok());
    let path = unicode_at(block + 0x100, "\\Device\\OpenNtDevIo");
    let attributes = block + 0x200;
    for offset in (0..48).step_by(8) {
        guest::write64(attributes + offset, 0);
    }
    guest::write32(attributes, 48);
    guest::write64(attributes + 16, path);
    let iosb = block + 0x300;
    stack(&[0, 0, 3, 1, 0x20, 0, 0]);
    let opened = call("NtCreateFile", block + 0x10, 0xC010_0000, attributes, iosb);
    let handle = guest::read64(block + 0x10);
    let kind = state::get_user_handle(handle).map(|entry| entry.kind());
    assert(opened == Some(0) && kind == Some("device"), "devio: dispositivo aberto pelo NtCreateFile");
    // Leitura e escrita bufferizadas por IRPs nativos.
    let buffer = block + 0x400;
    guest::write64(buffer, 0);
    stack(&[iosb, buffer, 16, 0, 0]);
    let read = call("NtReadFile", handle, 0, 0, 0);
    let read_ok = read == Some(0) && guest::read64(iosb) == 0 && guest::read64(iosb + 8) == 4 && guest::read32(buffer) == 0x4443_4241 && guest::read32(buffer + 4) == 0;
    guest::write64(buffer, 0x1111_2222_3333_4444);
    let written = call("NtWriteFile", handle, 0, 0, 0);
    let write_ok = written == Some(0) && guest::read64(iosb + 8) == 4 && guest::read64(buffer) == 0x1111_2222_3333_4444;
    assert(read_ok && write_ok, "devio: NtReadFile/NtWriteFile pelo IRP bufferizado nativo");
    // Sem DO_BUFFERED_IO o caminho não é suportado; cancelamentos sem pendência.
    guest::write32(device + device_object::FLAGS, guest::read32(device + device_object::FLAGS) & !4);
    let unbuffered = call("NtReadFile", handle, 0, 0, 0);
    guest::write32(device + device_object::FLAGS, guest::read32(device + device_object::FLAGS) | 4);
    let cancel_thread = call("NtCancelIoFile", handle, iosb, 0, 0);
    let cancel_any = call("NtCancelIoFileEx", handle, 0, iosb, 0);
    let cancel_bad = call("NtCancelIoFile", 0x7FF0, iosb, 0, 0);
    assert(unbuffered == Some(0xC000_00BB) && cancel_thread == Some(0) && cancel_any == Some(0xC000_0225) && cancel_bad == Some(0xC000_0008), "devio: dispositivo sem I/O bufferizado e cancelamentos");
    let _ = call("NtClose", handle, 0, 0, 0);
    guest::free_bytes(kernel);
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn native_context_execution(assert: Assert) {
    use crate::hal::amd64::native_call;
    use crate::ntos::rtl::native_context;
    use crate::ntos::mm::pe_loader::{self as loader, LoadOptions};
    // .text: soma (mov rax, rcx; add rax, rdx; ret) em 0x1300 e, em 0x1310,
    // sub rsp, 28h; call [rip -> IAT[0] = PsGetThreadId]; add rsp, 28h; ret.
    let mut bytes = ntoskrnl_importer(b"PsGetThreadId\0");
    bytes[0x1300..0x1307].copy_from_slice(&[0x48, 0x89, 0xC8, 0x48, 0x01, 0xD0, 0xC3]);
    let displacement = (0x4200u32 - (0x1310 + 10)).to_le_bytes();
    let call_thunk = [0x48, 0x83, 0xEC, 0x28, 0xFF, 0x15, displacement[0], displacement[1], displacement[2], displacement[3], 0x48, 0x83, 0xC4, 0x28, 0xC3];
    bytes[0x1310..0x1310 + call_thunk.len()].copy_from_slice(&call_thunk);
    let options = LoadOptions { image_name: Some(String::from("opennt-native-context.sys")), ..Default::default() };
    let Ok(mut image) = loader::load(bytes, &options) else {
        assert(false, "ctxnativo: imagem com codigo carregada");
        return;
    };
    let add = image.image_base + 0x1300;
    let through_thunk = image.image_base + 0x1310;
    assert(native_call::call(add, &[40, 2]) == 42, "ctxnativo: chamada sincrona ao codigo carregado");
    assert(native_context::call(add, &[0xFFFF_0000_0000_0000, 0x1234], 0).is_ok_and(|value| value == 0xFFFF_0000_0000_1234), "ctxnativo: callback em contexto e pilha proprios devolve 64 bits");
    let thread = guest::alloc_bytes(0x500);
    guest::write64(thread + 0x480, 0x8765_4321_0FED_CBA9);
    assert(native_call::call(through_thunk, &[thread]) == 0x8765_4321_0FED_CBA9, "ctxnativo: export chamado pelo IAT no caminho sincrono");
    assert(native_context::call(through_thunk, &[thread], 0).is_ok_and(|value| value == 0x8765_4321_0FED_CBA9), "ctxnativo: export chamado de dentro do contexto agendado (trap + despacho)");
    guest::free_bytes(thread);
    let _ = image.release();
    // Transferência: só o sinal da invocação ativa é reconhecido.
    let frame = guest::alloc_bytes(0x4E0);
    let desired = guest::alloc_bytes(0x4E0);
    guest::write64(desired + 0xF8, 0xFFFF_F800_1234_5678);
    guest::write64(desired + 0x98, 0xFFFF_F800_0000_8000);
    let transferred = native_context::invoke(frame, || -> Result<u64, crate::rtl::KernelError> {
        let signal = native_context::transfer(desired);
        let recognized = native_context::is_transfer(&signal);
        if !recognized {
            return Ok(99);
        }
        Err(signal)
    });
    assert(transferred.is_ok_and(|value| value == 0) && guest::read32(frame + native_context::ACTION) == 1 && guest::read64(frame + 0xF8) == 0xFFFF_F800_1234_5678 && guest::read64(frame + 0x98) == 0xFFFF_F800_0000_8000, "ctxnativo: transferencia copia o contexto, marca a acao e encerra a invocacao");
    assert(native_context::current().is_err() && !native_context::is_transfer(&native_context::transfer(desired)), "ctxnativo: sem invocacao ativa nao ha contexto nem sinal");
    let nested = native_context::invoke(frame, || native_context::invoke(desired, || Err::<u64, _>(native_context::transfer(frame))).map(|_| 7));
    assert(nested.is_ok_and(|value| value == 7), "ctxnativo: sinal capturado so pela invocacao que o emitiu");
    guest::free_bytes(desired);
    guest::free_bytes(frame);
}

fn ntoskrnl_medium_groups(assert: Assert) {
    use crate::ntos::mm::kernel_data;
    use crate::ntos::inc::nt_abi::eprocess;
    use crate::ntos::init::exports;
    use crate::ntos::mm::pe_loader::ResolvedImport;
    // kd: dados reais no EAT, slots históricos e respostas sem depurador.
    let data = |name: &str| match exports::lookup("ntoskrnl.exe", name) {
        Some(ResolvedImport::Address { address, .. }) => address,
        _ => 0,
    };
    assert(data("KdDebuggerEnabled") == kernel_data::address("KdDebuggerEnabled").unwrap_or(1) && data("KdEnteredDebugger") == kernel_data::address("KdEnteredDebugger").unwrap_or(1), "kd: KdDebuggerEnabled e KdEnteredDebugger resolvem para os dados reais");
    assert(call_export("KdEnableDebugger", &[]) == Some(0xFFFF_FFFF_C000_0022) && call_export("KdChangeOption", &[0, 0, 0, 0, 0]) == Some(0xFFFF_FFFF_C000_0354) && call_export("KdRefreshDebuggerNotPresent", &[]) == Some(1), "kd: sem depurador (ACCESS_DENIED, DEBUGGER_INACTIVE, nao presente)");
    // process-query: proteção e níveis de assinatura.
    let process = guest::alloc_bytes(eprocess::SIZE);
    guest::write64(process + eprocess::SECTION_BASE_ADDRESS, 0x7FF7_0000_0000);
    guest::write8(process + eprocess::PROTECTION, 0x31);
    guest::write8(process + eprocess::SIGNATURE_LEVEL, 0x0C);
    guest::write8(process + eprocess::SECTION_SIGNATURE_LEVEL, 0x08);
    let level = guest::alloc_bytes(8);
    assert(call_export("PsGetProcessSectionBaseAddress", &[process]) == Some(0x7FF7_0000_0000) && call_export("PsGetProcessProtection", &[process]) == Some(0x31), "psquery: base da secao e PS_PROTECTION completo");
    assert(call_export("PsGetProcessSignatureLevel", &[process, level]) == Some(0x0C) && guest::read8(level) == 0x08 && call_export("PsGetProcessSignatureLevel", &[process, 0]) == Some(0x0C), "psquery: niveis de assinatura da imagem e da secao");
    assert(call_export("PsIsProtectedProcess", &[process]) == Some(1) && call_export("PsIsProtectedProcessLight", &[process]) == Some(1), "psquery: processo protegido leve");
    guest::write8(process + eprocess::PROTECTION, 0x62);
    assert(call_export("PsIsProtectedProcess", &[process]) == Some(1) && call_export("PsIsProtectedProcessLight", &[process]) == Some(0), "psquery: protecao completa nao e leve");
    guest::free_bytes(level);
    guest::free_bytes(process);
    // hvi: CPUID real e push lock sem Secure Kernel.
    let present = crate::hal::cpu::cpuid(1)[2] >> 31;
    assert(call_export("HviIsAnyHypervisorPresent", &[]) == Some(present as u64) && call_export("SkIsSecureKernel", &[]) == Some(0xC000_0002) && call_export("VslExchangeEntropy", &[]) == Some(0xFFFF_FFFF_C000_00BB), "hvi: hypervisor pelo CPUID e Secure Kernel ausente");
    let lock = guest::alloc_bytes(16);
    guest::write64(lock, 0xFF);
    let features = guest::alloc_bytes(16);
    assert(call_export("SkInitializePushLock", &[lock]) == Some(0) && guest::read64(lock) == 0 && call_export("SkAcquirePushLockExclusive", &[lock]) == Some(0) && guest::read64(lock) == 1 && call_export("SkReleasePushLockExclusive", &[lock]) == Some(0) && guest::read64(lock) == 0, "hvi: push lock exclusivo do SkInitialize/Acquire/Release");
    assert(call_export("HviGetHypervisorFeatures", &[features]) == Some(0), "hvi: features da interface de hypervisor");
    guest::free_bytes(features);
    guest::free_bytes(lock);
    // wpp: sessões reais com buffer circular.
    let handle = guest::alloc_bytes(8);
    assert(call_export("WppAutoLogStart", &[0, handle, 0]) == Some(0) && guest::read64(handle) != 0, "wpp: sessao de trace iniciada");
    let session = guest::read64(handle);
    assert(call_export("WppAutoLogTrace", &[session, 4, 0, 0, 7]) == Some(0) && call_export("imp_WppRecorderReplay", &[session]) == Some(0) && call_export("WppAutoLogStop", &[session, 0]) == Some(0) && call_export("imp_WppRecorderReplay", &[session]) == Some(0xFFFF_FFFF_C000_0008), "wpp: trace, replay e encerramento da sessao");
    guest::free_bytes(handle);
    // wmi: informação de trace zerada até 0x30 bytes.
    let buffer = guest::alloc_bytes(0x40);
    let length = guest::alloc_bytes(8);
    guest::write_bytes(buffer, &[0xFF; 0x40]);
    assert(call_export("WmiQueryTraceInformation", &[1, buffer, 0x40, length, 0]) == Some(0) && guest::read32(length) == 0x30 && guest::read64(buffer + 0x28) == 0 && guest::read32(buffer + 0x30) == 0xFFFF_FFFF, "wmi: WmiQueryTraceInformation zera ate 0x30 bytes");
    let format = guest::alloc_bytes(32);
    guest::write_bytes(format, b"valor=%d\n\0");
    assert(call_export("WmiTraceMessage", &[0, 0, 0, 0, format, 42]) == Some(0) && call_export("WmiTraceMessageVa", &[0, 0, 0, 0, 0]) == Some(0xFFFF_FFFF_C000_0008), "wmi: trace formatado e logger inexistente");
    guest::free_bytes(format);
    guest::free_bytes(length);
    guest::free_bytes(buffer);
    // po: watchdog, ociosidade e callbacks de power setting.
    let seconds = guest::alloc_bytes(8);
    guest::write32(seconds, 77);
    assert(call_export("PoQueryWatchdogTime", &[0, seconds]) == Some(0) && guest::read32(seconds) == 0, "po: nenhum watchdog armado");
    let counter = call_export("PoRegisterDeviceForIdleDetection", &[0x1234, 10, 10, 4]).unwrap_or(0);
    if counter != 0 {
        guest::write32(counter, 9);
    }
    assert(counter != 0 && call_export("PoSetDeviceBusyEx", &[counter]) == Some(0) && guest::read32(counter) == 0, "po: contador de ociosidade zerado pelo PoSetDeviceBusyEx");
    let registration = guest::alloc_bytes(8);
    assert(call_export("PoUnregisterPowerSettingCallback", &[0xABC0]) == Some(0xFFFF_FFFF_C000_0225) && call_export("PoRegisterPowerSettingCallback", &[0, 0, 0xABC0, 0, registration]) == Some(0) && guest::read64(registration) == 0xABC0 && call_export("PoUnregisterPowerSettingCallback", &[0xABC0]) == Some(0), "po: registro e remocao de callback de power setting");
    guest::free_bytes(registration);
    guest::free_bytes(seconds);
}

fn ntoskrnl_security_groups(assert: Assert) {
    use crate::ntos::mm::kernel_data;
    use crate::ntos::ps::process;
    use crate::ntos::se::token::tokens;
    use crate::{ntos::init::exports, ntos::se::exports as se};
    use crate::ntos::mm::pe_loader::ResolvedImport;
    // etw: registro, traits e atividade corrente.
    let guid = guest::alloc_bytes(16);
    guest::write_bytes(guid, &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF0, 0x0F]);
    let handle = guest::alloc_bytes(8);
    let traits = guest::alloc_bytes(8);
    guest::write32(traits, 8);
    let descriptor = guest::alloc_bytes(16);
    assert(call_export("EtwRegister", &[guid, 0, 0, handle]) == Some(0) && guest::read64(handle) != 0, "etw: EtwRegister devolve o REGHANDLE");
    let registration = guest::read64(handle);
    assert(call_export("EtwSetInformation", &[registration, 1, traits, 4]) == Some(0) && call_export("EtwSetInformation", &[0xDEAD_0000, 1, traits, 4]) == Some(0xFFFF_FFFF_C000_0008), "etw: traits do registro e handle invalido");
    assert(call_export("EtwWrite", &[registration, descriptor, 0, 0, 0]).is_some_and(|status| status as u32 & 0x8000_0000 == 0), "etw: EtwWrite sem sessao ativa");
    let first = guest::alloc_bytes(16);
    let second = guest::alloc_bytes(16);
    assert(call_export("EtwActivityIdControl", &[3, first]) == Some(0) && guest::read8(first + 6) >> 4 == 4 && guest::read8(first + 8) >> 6 == 2, "etw: CREATE_ID gera uuid v4");
    assert(call_export("EtwActivityIdControl", &[2, first]) == Some(0) && call_export("EtwActivityIdControl", &[1, second]) == Some(0) && guest::read64(first) == guest::read64(second) && guest::read64(first + 8) == guest::read64(second + 8), "etw: SET_ID e GET_ID da atividade corrente");
    assert(call_export("EtwActivityIdControl", &[9, first]) == Some(0xFFFF_FFFF_C000_000D) && call_export("EtwUnregister", &[registration]) == Some(0), "etw: codigo invalido e EtwUnregister");
    for buffer in [guid, handle, traits, descriptor, first, second] {
        guest::free_bytes(buffer);
    }
    // security-tokens: token primário referenciado e atributos.
    let data = |name: &str| match exports::lookup("ntoskrnl.exe", name) {
        Some(ResolvedImport::Address { address, .. }) => address,
        _ => 0,
    };
    assert(data("SeExports") == kernel_data::address("SeExports").unwrap_or(1) && data("SeTokenObjectType") == kernel_data::address("SeTokenObjectType").unwrap_or(1), "setokens: SeExports e SeTokenObjectType resolvem para os dados reais");
    let current = process::get_current_process();
    let primary = process::get_primary_token(current).unwrap_or(0);
    let refs = |token: u64| tokens::get(token).map_or(0, |token| token.refs);
    let before = refs(primary);
    assert(primary != 0 && call_export("PsReferencePrimaryToken", &[current]) == Some(primary) && refs(primary) == before + 1, "setokens: PsReferencePrimaryToken retem o token primario");
    let returned = guest::alloc_bytes(8);
    let flags = guest::alloc_bytes(8);
    guest::write64(flags, 0xFFFF);
    let needed = call_export("SeQuerySecurityAttributesToken", &[primary, 0, 0, 0, 0, returned]);
    let size = guest::read32(returned) as u64;
    let buffer = guest::alloc_bytes(size.max(16));
    assert(needed == Some(0xC000_0023) && size >= 16 && call_export("SeQuerySecurityAttributesToken", &[primary, 0, 0, buffer, size, returned]) == Some(0) && guest::read32(returned) as u64 == size, "setokens: SeQuerySecurityAttributesToken mede e copia");
    assert(call_export("SeQuerySecurityAttributesToken", &[primary, 0, 0, buffer, 0, returned]) == Some(0xC000_000D), "setokens: buffer e tamanho inconsistentes");
    assert(call_export("PsQueryProcessAttributesByToken", &[primary, flags, flags + 1]) == Some(0) && guest::read16(flags) == 0, "setokens: token do sistema sem SYSAPPID nem PKG");
    assert(call_export("PsDereferencePrimaryToken", &[primary]) == Some(0) && refs(primary) == before, "setokens: PsDereferencePrimaryToken devolve a referencia");
    guest::free_bytes(buffer);
    guest::free_bytes(flags);
    guest::free_bytes(returned);
    // se: subject context, privilégio, LUID e auditoria.
    let context = guest::alloc_bytes(0x20);
    assert(call_export("SeCaptureSubjectContext", &[context]) == Some(0) && guest::read64(context + 0x10) == primary && guest::read64(context + 0x18) == process::get_current_process_id() && refs(primary) == before + 1, "se: SeCaptureSubjectContext retem o token primario");
    assert(call_export("SeReleaseSubjectContext", &[context]) == Some(0) && guest::read64(context + 0x10) == 0 && refs(primary) == before, "se: SeReleaseSubjectContext devolve as referencias");
    let luid = guest::alloc_bytes(8);
    assert(call_export("SeQueryAuthenticationIdToken", &[primary, luid]) == Some(0) && guest::read64(luid) == guest::read64(primary) && call_export("SeQueryAuthenticationIdToken", &[0x1000, luid]) == Some(0xFFFF_FFFF_C000_0008), "se: AuthenticationId lido do token");
    assert(call_export("SeSinglePrivilegeCheck", &[luid, 0]) == Some(1) && call_export("SeSinglePrivilegeCheck", &[luid, 1]) == Some(0), "se: privilegio no modo kernel");
    call_export("SeLockSubjectContext", &[context]);
    call_export("SeLockSubjectContext", &[context]);
    call_export("SeUnlockSubjectContext", &[context]);
    let still_locked = se::subject_context_locked();
    call_export("SeUnlockSubjectContext", &[context]);
    assert(still_locked && !se::subject_context_locked(), "se: bloqueio aninhado do subject context");
    assert(call_export("SeAuditFipsCryptoSelftests", &[1, 2, 0x30]) == Some(0) && se::audit_events().last().is_some_and(|event| event.kind == "FipsCryptoSelftest" && event.detail == "general=1 causing=2 extra=0x30"), "se: auditoria gravada no anel");
    guest::free_bytes(luid);
    guest::free_bytes(context);
}

fn ntoskrnl_small_modules(assert: Assert) {
    use crate::ntos::mm::{kernel_pool, paging, physical_layout};
    use crate::ntos::ob::get_object_type;
    use crate::ntos::inc::nt_abi::{eprocess, kthread};
    // MmSizeOfMdl: cabeçalho de 48 bytes e um PFN por página, somas de 64 bits.
    assert(call_export("MmSizeOfMdl", &[0x1234, 0x2000]) == Some(0x48) && call_export("MmSizeOfMdl", &[0, 0]) == Some(0x30) && call_export("MmSizeOfMdl", &[0x1, u64::MAX]) == Some(0x30 + ((u64::MAX).wrapping_add(0x1000) >> 12) * 8), "mdlsize: paginas abrangidas e transbordamento de 64 bits");
    // MmIsAddressValid: só mapeamentos residentes e endereços canônicos.
    let buffer = guest::alloc_bytes(64);
    assert(call_export("MmIsAddressValid", &[buffer]) == Some(1) && call_export("MmIsAddressValid", &[0x0000_8000_0000_0000]) == Some(0), "addrvalid: endereco residente e nao canonico");
    // FirstEntrySList: segunda palavra do cabeçalho sem os bits de marcação.
    guest::write64(buffer + 8, 0x1234_5678_9ABC_DEF7);
    assert(call_export("FirstEntrySList", &[buffer]) == Some(0x1234_5678_9ABC_DEF0) && guest::read64(buffer + 8) == 0x1234_5678_9ABC_DEF7, "firstslist: primeiro elemento sem alterar o cabecalho");
    guest::free_bytes(buffer);
    // PsGetProcessDebugPort e ObGetObjectType.
    let process = guest::alloc_bytes(eprocess::SIZE);
    guest::write64(process + eprocess::DEBUG_PORT, 0xFFFF_9100_0000_0040);
    assert(call_export("PsGetProcessDebugPort", &[process]) == Some(0xFFFF_9100_0000_0040), "debugport: campo DebugPort do EPROCESS");
    guest::free_bytes(process);
    let current = crate::ntos::ps::process::get_current_process();
    let process_type = get_object_type::get(current).unwrap_or(0);
    assert(process_type != 0 && call_export("ObGetObjectType", &[current]) == Some(process_type) && get_object_type::get(0x1234).is_err(), "objtype: tipo pelo dono registrado e ponteiro desconhecido recusado");
    // MmGetPhysicalMemoryRanges: vetor do layout terminado por zeros.
    let ranges = physical_layout::ranges();
    let vector = call_export("MmGetPhysicalMemoryRanges", &[]).unwrap_or(0);
    let terminator = vector + ranges.len() as u64 * 16;
    assert(vector != 0 && !ranges.is_empty() && guest::read64(vector) == ranges[0].0 && guest::read64(vector + 8) == ranges[0].1 - ranges[0].0 && guest::read64(terminator) == 0 && guest::read64(terminator + 8) == 0, "physranges: faixas fisicas com terminador");
    if vector != 0 {
        let _ = kernel_pool::free(vector, None);
    }
    // KeTestAlertThread: consome o alerta do modo kernel da thread corrente.
    let region = crate::ntos::ke::pcr::get_pcr_address();
    let thread = guest::read64(region + crate::ntos::ke::pcr::layout::PRCB_CURRENT_THREAD);
    let saved = guest::read8(thread + kthread::ALERTED);
    guest::write8(thread + kthread::ALERTED, 1);
    assert(call_export("KeTestAlertThread", &[0]) == Some(1) && guest::read8(thread + kthread::ALERTED) == 0 && call_export("KeTestAlertThread", &[0]) == Some(0), "testalert: alerta do modo kernel consumido");
    guest::write8(thread + kthread::ALERTED, saved);
    // MmProtectMdlSystemAddress sobre um mapeamento supervisor 4K real.
    let mdl = guest::alloc_bytes(0x40);
    assert(call_export("MmProtectMdlSystemAddress", &[mdl, 2]) == Some(0xC000_0019), "protectmdl: MDL sem mapeamento de sistema");
    let va = 0xFFFF_F800_0300_0000u64;
    let backing = guest::alloc_page();
    let mapped = paging::map_page(va, backing, paging::PAGE_PRESENT | paging::PAGE_RW, paging::MapOptions::default());
    guest::write16(mdl + 0xA, 1);
    guest::write64(mdl + 0x18, va + 0x10);
    guest::write32(mdl + 0x28, 0x100);
    let flags = || paging::query_page(va, true).map_or((0, false), |page| (guest::read64(page.entry_address), page.nx));
    let readonly = call_export("MmProtectMdlSystemAddress", &[mdl, 2]);
    let (readonly_entry, readonly_nx) = flags();
    let noaccess = call_export("MmProtectMdlSystemAddress", &[mdl, 1]);
    let (noaccess_entry, _) = flags();
    let readwrite_execute = call_export("MmProtectMdlSystemAddress", &[mdl, 0x40]);
    let (rwx_entry, _) = flags();
    assert(mapped && readonly == Some(0) && readonly_entry & 3 == 1 && readonly_nx && readonly_entry & 0xF_FFFF_FFFF_F000 == backing, "protectmdl: PAGE_READONLY tira a escrita e liga NX");
    assert(noaccess == Some(0) && noaccess_entry & 1 == 0 && noaccess_entry & 0x800 != 0 && noaccess_entry & 0xF_FFFF_FFFF_F000 == backing, "protectmdl: PAGE_NOACCESS conserva o PFN com o bit de software");
    assert(readwrite_execute == Some(0) && rwx_entry & 3 == 3 && rwx_entry & (1 << 63) == 0 && call_export("MmProtectMdlSystemAddress", &[mdl, 3]) == Some(0xC000_0045), "protectmdl: PAGE_EXECUTE_READWRITE e protecao invalida");
    paging::unmap_page(va, paging::MapOptions::default());
    guest::free_bytes(backing);
    guest::free_bytes(mdl);
}

fn ntoskrnl_priority_and_image(assert: Assert) {
    use crate::ntos::mm::data_pool;
    use crate::ntos::ob::objects::section::{self as section_objects, SectionState};
    use crate::ntos::inc::nt_abi::{eprocess, kthread};
    // KeSetPriorityThread/KeSetBasePriorityThread sobre um KTHREAD fora das filas.
    let process = guest::alloc_bytes(eprocess::SIZE);
    let thread = guest::alloc_bytes(0x800);
    guest::write8(process + eprocess::BASE_PRIORITY, 8);
    guest::write64(thread + kthread::PROCESS, process);
    guest::write8(thread + kthread::PRIORITY, 8);
    guest::write8(thread + kthread::BASE_PRIORITY, 8);
    guest::write8(thread + kthread::QUANTUM_RESET, 6);
    assert(call_export("KeSetPriorityThread", &[thread, 12]) == Some(8) && guest::read8(thread + kthread::PRIORITY) == 12 && guest::read64(thread + kthread::QUANTUM_TARGET) != 0, "prioridade: KeSetPriorityThread devolve a anterior e renova o quantum");
    guest::write32(thread + kthread::PRIORITY_FLOOR_SUMMARY, 1 << 13);
    assert(call_export("KeSetPriorityThread", &[thread, 10]) == Some(12) && guest::read8(thread + kthread::PRIORITY) == 13, "prioridade: o piso ativo eleva a prioridade efetiva");
    guest::write32(thread + kthread::PRIORITY_FLOOR_SUMMARY, 0);
    assert(call_export("KeSetPriorityThread", &[thread, 0]) == Some(13) && guest::read8(thread + kthread::PRIORITY) == 1, "prioridade: zero com base nao nula vira 1");
    guest::write8(thread + kthread::PRIORITY, 8);
    assert(call_export("KeSetBasePriorityThread", &[thread, 2]) == Some(0) && guest::read8(thread + kthread::BASE_PRIORITY) == 10 && guest::read8(thread + kthread::PRIORITY) == 10, "prioridade: incremento de base relativo ao processo");
    assert(call_export("KeSetBasePriorityThread", &[thread, 16]) == Some(2) && guest::read8(thread + kthread::SATURATION) == 1 && guest::read8(thread + kthread::BASE_PRIORITY) == 15 && guest::read8(thread + kthread::PRIORITY) == 15, "prioridade: incremento saturado leva a base ao teto");
    assert(call_export("KeSetBasePriorityThread", &[thread, 0]) == Some(16) && guest::read8(thread + kthread::SATURATION) == 0, "prioridade: incremento anterior saturado vale 16");
    guest::free_bytes(thread);
    // PsReferenceProcessFilePointer e SeLocateProcessImageName.
    let output = guest::alloc_bytes(8);
    assert(call_export("PsReferenceProcessFilePointer", &[process, output]) == Some(0xFFFF_FFFF_C000_0001) && call_export("SeLocateProcessImageName", &[process, output]) == Some(0xFFFF_FFFF_C000_0225), "psimage: processo sem secao nem nome de auditoria");
    fn destroy_section(_: u64) -> Result<(), crate::rtl::KernelError> {
        Ok(())
    }
    let section = section_objects::register(SectionState { size: 0x1000, ..Default::default() }, destroy_section).unwrap_or(0);
    guest::write64(process + eprocess::SECTION_OBJECT, section);
    guest::write64(output, 0xFFFF);
    assert(section != 0 && call_export("PsReferenceProcessFilePointer", &[process, output]) == Some(0) && guest::read64(output) == 0, "psimage: secao sem FILE_OBJECT de imagem");
    guest::write64(process + eprocess::RUNDOWN_PROTECT, 1);
    assert(call_export("PsReferenceProcessFilePointer", &[process, output]) == Some(0xFFFF_FFFF_C000_0001), "psimage: processo em rundown");
    let name: alloc::vec::Vec<u16> = "\\Device\\HarddiskVolume1\\teste.exe".encode_utf16().collect();
    let cache = guest::alloc_bytes(16 + name.len() as u64 * 2 + 2);
    guest::write16(cache, name.len() as u16 * 2);
    guest::write16(cache + 2, name.len() as u16 * 2 + 2);
    guest::write64(cache + 8, cache + 16);
    for (index, unit) in name.iter().enumerate() {
        guest::write16(cache + 16 + index as u64 * 2, *unit);
    }
    guest::write64(process + eprocess::AUDIT_IMAGE_NAME, cache);
    let located = call_export("SeLocateProcessImageName", &[process, output]);
    let copy = guest::read64(output);
    assert(located == Some(0) && copy != cache && guest::read16(copy) == name.len() as u16 * 2 && guest::read64(copy + 8) == copy + 16 && crate::ntos::rtl::guest_strings::read_unicode_string(copy) == "\\Device\\HarddiskVolume1\\teste.exe", "psimage: copia do nome de auditoria em pool");
    let _ = data_pool::free(copy);
    let _ = section_objects::collect(section);
    guest::free_bytes(cache);
    guest::free_bytes(output);
    guest::free_bytes(process);
}

fn ntoskrnl_thread_information(assert: Assert) {
    use crate::ntos::ps::process;
    use crate::ntos::inc::nt_abi::kthread;
    // Claims de pacote: o token do sistema não tem SYSAPPID.
    let primary = process::get_primary_token(process::get_current_process()).unwrap_or(0);
    let claim = guest::alloc_bytes(16);
    assert(call_export("RtlQueryPackageClaims", &[primary, 0, 0, 0, 0, 0, claim, claim + 8]) == Some(0xC000_0225) && call_export("RtlQueryPackageIdentity", &[primary, 0, 0, 0, 0, claim]) == Some(0xC000_0225), "pacote: token sem identidade de pacote");
    guest::free_bytes(claim);
    // ThreadPagePriority da thread corrente (-2) por Zw e Nt.
    let thread = process::get_current_thread();
    let flags = thread + kthread::CROSS_THREAD_FLAGS;
    let saved = guest::read32(flags);
    let buffer = guest::alloc_bytes(16);
    let current_handle = (-2i64) as u64;
    assert(call_export("ZwQueryInformationThread", &[current_handle, 24, buffer, 4, buffer + 8]) == Some(0) && guest::read32(buffer) == (saved >> 12) & 7 && guest::read32(buffer + 8) == 4, "threadinfo: ZwQueryInformationThread le ThreadPagePriority");
    assert(call_export("ZwQueryInformationThread", &[current_handle, 2, buffer, 4, 0]) == Some(0xC000_0003) && call_export("ZwQueryInformationThread", &[current_handle, 0, buffer, 4, 0]) == Some(0xC000_0002) && call_export("ZwQueryInformationThread", &[current_handle, 24, buffer, 8, 0]) == Some(0xC000_0004), "threadinfo: classe rejeitada, sem provedor e tamanho errado");
    guest::write32(buffer, 3);
    assert(call_export("ZwSetInformationThread", &[current_handle, 24, buffer, 4]) == Some(0) && (guest::read32(flags) >> 12) & 7 == 3 && guest::read32(flags) & !0x7000 == saved & !0x7000, "threadinfo: ZwSetInformationThread troca so os tres bits");
    guest::write32(buffer + 4, 0xFFFF);
    assert(call_export("NtQueryInformationThread", &[current_handle, 24, buffer + 4, 4, 0]) == Some(0) && guest::read32(buffer + 4) == 3, "threadinfo: NtQueryInformationThread em modo kernel");
    guest::write32(buffer, 0);
    assert(call_export("NtSetInformationThread", &[current_handle, 24, buffer, 4]) == Some(0xC000_000D) && call_export("ZwSetInformationThread", &[current_handle, 0, buffer, 4]) == Some(0xC000_0003), "threadinfo: prioridade invalida e classe rejeitada");
    guest::write32(flags, saved);
    guest::free_bytes(buffer);
}

fn ntoskrnl_ex_group(assert: Assert) {
    use crate::ntos::ke::irql;
    use crate::ntos::ps::process;
    use crate::ntos::init::exports;
    use crate::ntos::mm::pe_loader::ResolvedImport;
    let tag = u32::from_le_bytes(*b"ExT6") as u64;
    // Pool.
    let pool = call_export("ExAllocatePoolWithTag", &[0, 64, tag]).unwrap_or(0);
    assert(pool != 0 && call_export("ExFreePoolWithTag", &[pool, tag]) == Some(0), "ex: ExAllocatePoolWithTag/ExFreePoolWithTag");
    let modern = call_export("ExAllocatePool2", &[0x40, 32, tag]).unwrap_or(0);
    assert(modern != 0 && guest::read64(modern) == 0 && call_export("ExFreePool2", &[modern, tag]) == Some(0), "ex: ExAllocatePool2 zerado e ExFreePool2");
    // Fast mutex: dono, APC_LEVEL e liberação.
    let block = guest::alloc_bytes(0x200);
    let mutex = block;
    assert(call_export("ExInitializeFastMutex", &[mutex]) == Some(0) && guest::read32(mutex) == 1, "ex: ExInitializeFastMutex disponivel");
    let entry_irql = irql::get_irql();
    call_export("ExAcquireFastMutex", &[mutex]);
    let held = guest::read32(mutex) == 0 && guest::read64(mutex + 8) == process::get_current_thread() && irql::get_irql() == 1;
    call_export("ExReleaseFastMutex", &[mutex]);
    assert(held && guest::read32(mutex) == 1 && guest::read64(mutex + 8) == 0 && irql::get_irql() == entry_irql, "ex: fast mutex adquirido em APC_LEVEL e liberado");
    assert(call_export("ExTryToAcquireFastMutex", &[mutex]) == Some(1) && call_export("ExReleaseFastMutex", &[mutex]) == Some(0), "ex: ExTryToAcquireFastMutex");
    // ERESOURCE.
    let eresource = block + 0x40;
    assert(call_export("ExInitializeResourceLite", &[eresource]) == Some(0) && call_export("ExAcquireResourceExclusiveLite", &[eresource, 1]) == Some(1) && call_export("ExIsResourceAcquiredExclusiveLite", &[eresource]) == Some(1), "ex: ERESOURCE exclusivo");
    assert(call_export("ExReleaseResourceLite", &[eresource]) == Some(0) && call_export("ExIsResourceAcquiredExclusiveLite", &[eresource]) == Some(0) && call_export("ExDeleteResourceLite", &[eresource]) == Some(0), "ex: ERESOURCE liberado e removido");
    // Rundown.
    let rundown = block + 0x100;
    call_export("ExInitializeRundownProtection", &[rundown]);
    assert(call_export("ExAcquireRundownProtection", &[rundown]) == Some(1) && call_export("ExReleaseRundownProtection", &[rundown]) == Some(0) && call_export("ExRundownCompleted", &[rundown]) == Some(0) && call_export("ExAcquireRundownProtection", &[rundown]) == Some(0), "ex: rundown adquirido, liberado e completado");
    // SLIST e SINGLE_LIST com spin lock.
    let head = block + 0x120;
    let (first, second) = (block + 0x140, block + 0x150);
    call_export("InitializeSListHead", &[head]);
    call_export("ExpInterlockedPushEntrySList", &[head, first]);
    call_export("ExpInterlockedPushEntrySList", &[head, second]);
    assert(call_export("ExQueryDepthSList", &[head]) == Some(2) && call_export("ExpInterlockedPopEntrySList", &[head]) == Some(second) && call_export("ExpInterlockedFlushSList", &[head]) == Some(first) && call_export("ExQueryDepthSList", &[head]) == Some(0), "ex: SLIST push, pop, flush e profundidade");
    let list = block + 0x160;
    let lock = block + 0x180;
    assert(call_export("ExInterlockedPushEntryList", &[list, first, lock]) == Some(0) && call_export("ExInterlockedPopEntryList", &[list, lock]) == Some(first) && guest::read32(lock) == 0 && irql::get_irql() == entry_irql, "ex: lista simples sob spin lock");
    // Push lock e spin lock executivo.
    let push = block + 0x190;
    assert(call_export("ExInitializePushLock", &[push]) == Some(0) && call_export("ExAcquirePushLockExclusiveEx", &[push, 0]) == Some(0) && guest::read64(push) & 1 == 1 && call_export("ExReleasePushLockExclusiveEx", &[push, 0]) == Some(0) && guest::read64(push) == 0, "ex: push lock exclusivo");
    let spin = block + 0x198;
    let old = call_export("ExAcquireSpinLockExclusive", &[spin]).unwrap_or(0xFF);
    let at_dispatch = irql::get_irql() == 2;
    call_export("ExReleaseSpinLockExclusive", &[spin, old]);
    assert(old == entry_irql as u64 && at_dispatch && irql::get_irql() == entry_irql, "ex: spin lock executivo em DISPATCH_LEVEL");
    // UUID, extensões, hora local e Error Management.
    let uuid = block + 0x1A0;
    assert(call_export("ExUuidCreate", &[uuid]) == Some(0) && guest::read8(uuid + 6) >> 4 == 4 && guest::read8(uuid + 8) >> 6 == 2, "ex: ExUuidCreate versao 4");
    let output = block + 0x1B0;
    assert(call_export("ExRegisterExtension", &[output, 1, 0xFFFF_F800_DEAD_0000]) == Some(0) && guest::read16(guest::read64(output)) == 1 && guest::read64(guest::read64(output) + 8) == 0xFFFF_F800_DEAD_0000, "ex: ExRegisterExtension");
    guest::write64(block + 0x1B8, 0x01DA_0000_1234_5678);
    assert(call_export("ExSystemTimeToLocalTime", &[block + 0x1B8, block + 0x1C0]) == Some(0) && guest::read64(block + 0x1C0) == 0x01DA_0000_1234_5678 && call_export("EmClientQueryRuleState", &[0, 0]) == Some(0xFFFF_FFFF_C000_0225), "ex: hora local sem fuso e regra inexistente");
    // EX_TIMER e ExEventObjectType.
    let timer = call_export("ExAllocateTimer", &[0x1234, 0x5678, 0]).unwrap_or(0);
    assert(timer != 0 && guest::read64(timer + 0x80) == 0x1234 && call_export("ExCancelTimer", &[timer]) == Some(0) && call_export("ExDeleteTimer", &[timer, 1, 0, 0]) == Some(0), "ex: EX_TIMER alocado, cancelado e removido");
    let cell = match exports::lookup("ntoskrnl.exe", "ExEventObjectType") {
        Some(ResolvedImport::Address { address, .. }) => address,
        _ => 0,
    };
    assert(cell != 0 && guest::read64(cell) != 0, "ex: ExEventObjectType aponta para a celula do tipo");
    guest::free_bytes(block);
}

fn ke_process_attachment(assert: Assert) {
    use crate::ntos::ke::{bugcheck_reason, process_attachment};
    use crate::ntos::ps::process;
    use crate::ntos::inc::nt_abi::kthread;
    // Processo gerenciado de destino na PML4 compartilhada.
    let Ok(target) = process::create_process(0x7D10, "phase6-attach.exe", 0, None) else {
        assert(false, "attach: processo de destino criado");
        return;
    };
    let thread = process::get_current_thread();
    let original = guest::read64(thread + kthread::APC_STATE + 0x20);
    let stack_count = guest::read32(target + 0x348);
    let state = guest::alloc_bytes(0x30);
    let attached = process_attachment::attach(target, state);
    let during = (guest::read64(thread + kthread::APC_STATE + 0x20), guest::read8(thread + 0x24A), guest::read32(target + 0x348), guest::read64(target + 0x178) != 0);
    assert(attached.is_ok() && during.0 == target && during.1 == 1 && during.2 == stack_count + 8 && during.3, "attach: KeStackAttachProcess troca o ApcState e publica a CPU no destino");
    let detached = process_attachment::detach(state);
    assert(detached.is_ok() && guest::read64(thread + kthread::APC_STATE + 0x20) == original && guest::read8(thread + 0x24A) == 0 && guest::read32(target + 0x348) == stack_count, "attach: KeUnstackDetachProcess restaura o processo e a contagem de pilhas");
    // Anexar ao processo corrente só grava o marcador.
    assert(process_attachment::attach(original, state).is_ok() && guest::read64(state + 0x20) == 1 && process_attachment::detach(state).is_ok(), "attach: processo corrente usa o marcador 1");
    assert(process_attachment::detach(guest::alloc_bytes(0x30)).is_err(), "attach: desanexacao sem anexacao recusada");
    guest::free_bytes(state);
    let _ = process::terminate_process(target, 0);
    // Sem callbacks KbCallbackSecondaryDumpData nada é publicado.
    assert(bugcheck_reason::publish_secondary_data(0).is_ok(), "bugcheck2: coleta sem callbacks registrados");
}

fn ntoskrnl_ke_group(assert: Assert) {
    use crate::ntos::ke::{clock, irql, smp};
    use crate::ntos::ps::process;
    use crate::ntos::init::exports;
    use crate::ntos::mm::pe_loader::ResolvedImport;
    let block = guest::alloc_bytes(0x400);
    // DbgPrint formatado.
    guest::write_bytes(block, b"ke:%d-%s\n\0");
    guest::write_bytes(block + 0x20, b"abc\0");
    assert(call_export("DbgPrint", &[block, 7, block + 0x20]) == Some(0), "ke: DbgPrint formatado");
    // IRQL e spin locks.
    let entry = irql::get_irql();
    let previous = call_export("KfRaiseIrql", &[2]).unwrap_or(0xFF);
    let raised = call_export("KeGetCurrentIrql", &[]);
    call_export("KeLowerIrql", &[previous | 0xFF00]);
    assert(previous == entry as u64 && raised == Some(2) && irql::get_irql() == entry, "ke: KfRaiseIrql/KeLowerIrql com KIRQL de um byte");
    let lock = block + 0x40;
    call_export("KeInitializeSpinLock", &[lock]);
    let old = call_export("KeAcquireSpinLockRaiseToDpc", &[lock]).unwrap_or(0xFF);
    let held = guest::read32(lock) == 1 && irql::get_irql() == 2;
    call_export("KeReleaseSpinLock", &[lock, old]);
    assert(held && old == entry as u64 && guest::read32(lock) == 0 && irql::get_irql() == entry, "ke: spin lock em DISPATCH_LEVEL");
    let handle = block + 0x48;
    call_export("KeAcquireInStackQueuedSpinLock", &[lock, handle]);
    let queued = guest::read64(handle + 8) == lock && guest::read32(lock) == 1;
    call_export("KeReleaseInStackQueuedSpinLock", &[handle]);
    assert(queued && guest::read32(lock) == 0 && irql::get_irql() == entry, "ke: in-stack queued spin lock");
    // Eventos e esperas com timeout zero.
    let event = block + 0x80;
    let zero_timeout = block + 0x60;
    guest::write64(zero_timeout, 0);
    call_export("KeInitializeEvent", &[event, 0, 0]);
    assert(call_export("KeReadStateEvent", &[event]) == Some(0) && call_export("KeWaitForSingleObject", &[event, 0, 0, 0, zero_timeout]) == Some(0x102), "ke: evento nao sinalizado expira com timeout zero");
    assert(call_export("KeSetEvent", &[event, 0, 0]) == Some(0) && call_export("KeWaitForSingleObject", &[event, 0, 0, 0, zero_timeout]) == Some(0) && call_export("KeResetEvent", &[event]) == Some(1) && call_export("KeReadStateEvent", &[event]) == Some(0), "ke: KeSetEvent, espera satisfeita e KeResetEvent");
    // Semáforo, timer e consultas.
    let semaphore = block + 0xA0;
    call_export("KeInitializeSemaphore", &[semaphore, 1, 3]);
    assert(call_export("KeReleaseSemaphore", &[semaphore, 0, 2, 0]) == Some(1) && call_export("KeReleaseSemaphore", &[semaphore, 0, 5, 0]) == Some(3) && guest::read32(semaphore + 4) == 3, "ke: semaforo limitado");
    let timer = block + 0xC0;
    call_export("KeInitializeTimer", &[timer]);
    assert(call_export("KeReadStateTimer", &[timer]) == Some(0) && call_export("KeSetTimer", &[timer, (-10_000_000i64) as u64, 0]) == Some(0) && call_export("KeCancelTimer", &[timer]) == Some(1), "ke: timer agendado e cancelado");
    assert(call_export("PsGetVersion", &[block + 0x100, block + 0x104, block + 0x108, 0]) == Some(1) && guest::read32(block + 0x100) == 10 && guest::read32(block + 0x108) == 26100 && call_export("KeQueryTimeIncrement", &[]) == Some(100_000), "ke: PsGetVersion e KeQueryTimeIncrement");
    assert(call_export("KeQueryActiveProcessorCount", &[]) == Some(smp::online_cpu_count() as u64) && call_export("KeGetProcessorNumberFromIndex", &[999, block + 0x110]) == Some(0xFFFF_FFFF_C000_000D), "ke: processadores ativos");
    assert(call_export("KeQueryPerformanceCounter", &[block + 0x118]).is_some_and(|counter| counter != 0) && guest::read64(block + 0x118) == clock::tsc_frequency_hz() && call_export("KeStallExecutionProcessor", &[10]) == Some(0), "ke: contador de desempenho e espera ocupada");
    // Regiões críticas e guardadas.
    call_export("KeEnterCriticalRegion", &[]);
    let critical = call_export("KeAreApcsDisabled", &[]);
    call_export("KeLeaveCriticalRegion", &[]);
    call_export("KeEnterGuardedRegion", &[]);
    let guarded = call_export("KeAreAllApcsDisabled", &[]);
    call_export("KeLeaveGuardedRegion", &[]);
    assert(critical == Some(1) && guarded == Some(1) && call_export("KeAreApcsDisabled", &[]) == Some(0), "ke: regioes critica e guardada");
    // DPC, guarded mutex, estado estendido e bugcheck callbacks.
    let dpc = block + 0x140;
    call_export("KeInitializeDpc", &[dpc, 0x1234, 0x5678]);
    call_export("KeSetImportanceDpc", &[dpc, 2]);
    call_export("KeSetTargetProcessorDpc", &[dpc, 0x301]);
    assert(guest::read8(dpc + 1) == 2 && guest::read16(dpc + 2) == 1 && call_export("KeRemoveQueueDpc", &[dpc]) == Some(0), "ke: KDPC importancia, processador alvo e remocao");
    let mutex = block + 0x200;
    call_export("KeInitializeGuardedMutex", &[mutex]);
    assert(call_export("KeTryToAcquireGuardedMutex", &[mutex]) == Some(1) && call_export("KeReleaseGuardedMutex", &[mutex]) == Some(0) && guest::read32(mutex) == 1, "ke: guarded mutex");
    let saved = call_export("KeSaveExtendedProcessorState", &[3, block + 0x240]);
    let state = guest::read64(block + 0x240);
    assert(saved == Some(0) && guest::read32(state) == 0x5358 && call_export("KeRestoreExtendedProcessorState", &[state]) == Some(0) && call_export("KeRestoreExtendedProcessorState", &[0]) == Some(0xFFFF_FFFF_C000_000D), "ke: estado estendido salvo e restaurado");
    assert(call_export("KeDeregisterBugCheckCallback", &[0x1234]) == Some(0), "ke: registro de bugcheck desconhecido");
    // Dados KiBugCheckData/KeNumberProcessors e anexação pelo export.
    let data = |name: &str| match exports::lookup("ntoskrnl.exe", name) {
        Some(ResolvedImport::Address { address, .. }) => address,
        _ => 0,
    };
    assert(data("KiBugCheckData") != 0 && guest::read32(data("KeNumberProcessors")) == smp::online_cpu_count() as u32, "ke: dados KiBugCheckData e KeNumberProcessors");
    if let Ok(target) = process::create_process(0x7D20, "phase6-ke.exe", 0, None) {
        let apc_state = block + 0x300;
        let attached = call_export("KeStackAttachProcess", &[target, apc_state]) == Some(0) && guest::read64(process::get_current_thread() + crate::ntos::inc::nt_abi::kthread::APC_STATE + 0x20) == target;
        assert(attached && call_export("KeUnstackDetachProcess", &[apc_state]) == Some(0), "ke: KeStackAttachProcess/KeUnstackDetachProcess pelo trampolim");
        let _ = process::terminate_process(target, 0);
    }
    guest::free_bytes(block);
}

fn ntoskrnl_mm_group(assert: Assert) {
    use crate::hal::amd64::native_call;
    use crate::hal::physical;
    use crate::ntos::mm::{image_paging, paging};
    use crate::ntos::init::exports;
    use crate::ntos::mm::pe_loader::{self as loader, LoadOptions};
    assert(exports::implemented() == 893 && exports::export_names().len() == 893, "ntoskrnl: 150 grupos com os 893 exports implementados");
    let block = guest::alloc_bytes(0x200);
    // MmGetSystemRoutineAddress: trampolim chamável e nome desconhecido.
    let name: alloc::vec::Vec<u16> = "KeGetCurrentIrql".encode_utf16().collect();
    let text = block + 0x40;
    for (index, unit) in name.iter().enumerate() {
        guest::write16(text + index as u64 * 2, *unit);
    }
    guest::write16(block, name.len() as u16 * 2);
    guest::write16(block + 2, name.len() as u16 * 2);
    guest::write64(block + 8, text);
    let routine = call_export("MmGetSystemRoutineAddress", &[block]).unwrap_or(0);
    assert(routine != 0 && native_call::call(routine, &[]) == crate::ntos::ke::irql::get_irql() as u64, "mm: MmGetSystemRoutineAddress devolve o trampolim chamavel");
    guest::write16(block, 4);
    guest::write16(text, b'Z' as u16);
    assert(call_export("MmGetSystemRoutineAddress", &[block]) == Some(0), "mm: rotina desconhecida devolve NULL");
    // MDL de pool não paginado: PFNs reais, flags e mapeamento identidade.
    let buffer = guest::alloc_aligned(0x2000, 0x1000, true);
    let descriptor = guest::alloc_bytes(0x40);
    guest::write64(descriptor + 0x20, buffer);
    guest::write32(descriptor + 0x2C, 0x10);
    guest::write32(descriptor + 0x28, 0x1800);
    assert(call_export("MmBuildMdlForNonPagedPool", &[descriptor]) == Some(0) && guest::read64(descriptor + 0x30) == paging::translate(buffer) >> 12 && guest::read64(descriptor + 0x38) == paging::translate(buffer + 0x1000) >> 12 && guest::read16(descriptor + 0xA) & 6 == 6, "mm: MmBuildMdlForNonPagedPool com PFNs reais");
    assert(call_export("MmMapLockedPagesSpecifyCache", &[descriptor, 0, 1, 0, 0, 16]) == Some(buffer + 0x10) && guest::read16(descriptor + 0xA) & 1 == 1 && call_export("MmUnmapLockedPages", &[buffer + 0x10, descriptor]) == Some(0) && guest::read16(descriptor + 0xA) & 1 == 0, "mm: mapeamento do MDL marcado e desfeito");
    assert(call_export("MmGetPhysicalAddress", &[buffer]) == Some(paging::translate(buffer)) && call_export("MmMapLockedPagesWithReservedMapping", &[buffer, 0, descriptor, 1]) == Some(0), "mm: endereco fisico e VA nao reservada recusada");
    let pages = call_export("MmAllocatePagesForMdl", &[0, u64::MAX, 0, 0x2000]).unwrap_or(0);
    assert(pages != 0 && guest::read16(pages + 8) == 0x40 && guest::read64(pages + 0x30) != 0 && guest::read64(pages + 0x38) != 0 && call_export("MmFreePagesFromMdl", &[pages]) == Some(0), "mm: MmAllocatePagesForMdl com frames reais");
    guest::free_bytes(pages);
    guest::free_bytes(descriptor);
    guest::free_bytes(buffer);
    guest::free_bytes(block);
    // Residência de imagem: trava de seção, migração, despejo no NTFS e recarga.
    let options = LoadOptions { image_name: Some(alloc::string::String::from("opennt-paging-test.sys")), ..Default::default() };
    let Ok(mut image) = loader::load(loadable_pe(), &options) else {
        assert(false, "imgpaging: driver de teste carregado");
        return;
    };
    let base = image.image_base;
    let original = physical::read_bytes(paging::translate(base + 0x1000), 64);
    let handle = call_export("MmLockPagableCodeSection", &[base + 0x1100]).unwrap_or(0);
    let locked = image_paging::state(base).map_or(0, |state| state.locked);
    assert(handle != 0 && locked == 1 && call_export("MmUnlockPagableImageSection", &[handle]) == Some(0) && image_paging::state(base).is_some_and(|state| state.locked == 0), "imgpaging: trava e destrava a secao .text");
    assert(call_export("MmPageEntireDriver", &[base + 0x1000]) == Some(base) && image_paging::state(base).is_some_and(|state| state.migrated && state.entire), "imgpaging: MmPageEntireDriver migra para frames PFN");
    let evicted = image_paging::trim(16, Some(base), false);
    let after_trim = image_paging::state(base);
    assert(evicted.as_ref().is_ok_and(|&count| count == 6) && after_trim.as_ref().is_some_and(|state| state.resident == 0 && state.evictions == 6 && state.path.is_some()), "imgpaging: imagem inteira despejada no NTFS");
    let relocked = call_export("MmLockPagableSectionByHandle", &[handle]);
    let restored = physical::read_bytes(paging::translate(base + 0x1000), 64);
    assert(relocked == Some(0) && restored == original && image_paging::state(base).is_some_and(|state| state.faults == 1 && state.locked == 1), "imgpaging: secao recarregada do NTFS com o conteudo original");
    call_export("MmUnlockPagableImageSection", &[handle]);
    let reset_result = call_export("MmResetDriverPaging", &[base]);
    assert(reset_result == Some(0) && image_paging::state(base).is_some_and(|state| !state.entire && state.resident == 5 && state.pageable == 1), "imgpaging: MmResetDriverPaging traz de volta as paginas nao paginaveis (a .edata continua no NTFS)");
    assert(image.release().is_ok() && image_paging::state(base).is_none(), "imgpaging: liberacao do driver remove a residencia");
}

/// Driver com DriverEntry em 0x1300 (código dado) sobre a imagem carregável.
pub(crate) fn driver_image(entry_code: &[u8], extra: &[(usize, &[u8])]) -> Vec<u8> {
    let mut image = loadable_pe();
    put32(&mut image, 0x58 + 16, 0x1300);
    image[0x1300..0x1300 + entry_code.len()].copy_from_slice(entry_code);
    for (offset, bytes) in extra {
        image[*offset..*offset + bytes.len()].copy_from_slice(bytes);
    }
    image
}

fn ntoskrnl_driver_lifecycle(assert: Assert) {
    use crate::drivers::fs::memory_file_system;
    use crate::ntos::mm::loaded_images;
    use crate::ntos::ob::object_manager;
    use crate::ntos::io::lifecycle::{self, DriverOptions};
    let counter = guest::alloc_bytes(8);
    // DriverEntry: lea rax,[rip+unload]; mov [rcx+68h],rax; xor eax,eax; ret.
    // DriverUnload (0x1320): mov rax, counter; inc dword [rax]; ret.
    let entry = [0x48, 0x8D, 0x05, 0x19, 0x00, 0x00, 0x00, 0x48, 0x89, 0x41, 0x68, 0x31, 0xC0, 0xC3];
    let mut unload = alloc::vec![0x48, 0xB8];
    unload.extend_from_slice(&counter.to_le_bytes());
    unload.extend_from_slice(&[0xFF, 0x00, 0xC3]);
    let good = driver_image(&entry, &[(0x1320, &unload)]);
    // DriverEntry que falha: mov eax, 0xC0000001; ret.
    let failing = driver_image(&[0xB8, 0x01, 0x00, 0x00, 0xC0, 0xC3], &[]);
    let _ = memory_file_system::write_bytes("/opennt-lc-a.sys", good);
    let _ = memory_file_system::write_bytes("/opennt-lc-b.sys", failing);
    let options = DriverOptions::default();
    let loaded = lifecycle::load_driver("/opennt-lc-a.sys", &options);
    let node = object_manager::lookup("\\Driver\\opennt-lc-a");
    let driver = node.and_then(|node| object_manager::node(node)).and_then(|node| node.data).map_or(0, |data| data.native_pointer);
    let base = if driver != 0 { guest::read64(driver + 0x18) } else { 0 };
    assert(loaded.as_ref().is_ok_and(|&value| value) && driver != 0 && guest::read16(driver) == 4 && base != 0, "lifecycle: DriverEntry executado e \\Driver publicado com o DRIVER_OBJECT");
    assert(guest::read64(driver + 0x68) == base + 0x1320 && guest_strings_read(driver + 0x38) == "opennt-lc-a" && lifecycle::get_driver_export("opennt-lc-a", "Alpha") == base + 0x1010, "lifecycle: DriverUnload registrado, DriverName e export do driver");
    assert(lifecycle::load_driver("/opennt-lc-a.sys", &options).is_err_and(|error| error.win32_error == 1056), "lifecycle: driver ja carregado (1056)");
    assert(lifecycle::unload_driver("opennt-lc-a") && guest::read32(counter) == 1 && object_manager::lookup("\\Driver\\opennt-lc-a").is_none() && loaded_images::find(base + 0x1000).is_none(), "lifecycle: unload chama DriverUnload e libera a imagem");
    let failed = lifecycle::load_driver("/opennt-lc-b.sys", &options);
    assert(failed.as_ref().is_err_and(|error| error.win32_error == 31 && error.ntstatus == Some(0xC000_0001)) && object_manager::lookup("\\Driver\\opennt-lc-b").is_none() && loaded_images::find(base + 0x1000).is_none(), "lifecycle: DriverEntry com erro desfaz o driver e a imagem");
    assert(lifecycle::load_driver("/opennt-nao-existe.sys", &options).is_err_and(|error| error.win32_error == 2) && lifecycle::call_add_device("opennt-nao-existe", 0) == 0xFFFF_FFFF_C000_0034 && !lifecycle::unload_driver("opennt-nao-existe"), "lifecycle: driver inexistente");
    guest::free_bytes(counter);
}

fn guest_strings_read(unicode: u64) -> alloc::string::String {
    crate::ntos::rtl::guest_strings::read_unicode_string(unicode)
}

fn system_information_leaves(assert: Assert) {
    use crate::ntos::ex::{boot_environment, boot_environment_information};
    use crate::hal::firmware_environment;
    use crate::ntos::se::{code_integrity_information, secure_boot_information, secure_boot_policy};
    // Identidade do boot: UUID v4 por RDRAND, firmware e flags do loader.
    let information = boot_environment::get_information();
    let firmware = firmware_environment::firmware_type().unwrap_or(0);
    assert(information.is_ok_and(|bytes| bytes[7] >> 4 == 4 && bytes[8] >> 6 == 2 && u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) == firmware) && boot_environment::init().is_err(), "bootenv: identidade UUID v4, tipo de firmware e inicializacao unica");
    let bytes = boot_environment::get_information().unwrap_or([0; 32]);
    let buffer = guest::alloc_bytes(64);
    let length = guest::alloc_bytes(8);
    guest::write_bytes(buffer, &[0xAA; 40]);
    assert(boot_environment_information::query(buffer, 32, length, false).is_ok_and(|status| status == 0) && guest::read32(length) == 32 && guest::read64(buffer) == u64::from_le_bytes(bytes[..8].try_into().unwrap()) && guest::read32(buffer + 20) == 0xAAAA_AAAA && guest::read64(buffer + 24) == u64::from_le_bytes(bytes[24..32].try_into().unwrap()), "bootenvinfo: 32 bytes preservando o padding do chamador");
    guest::write_bytes(buffer, &[0xAA; 40]);
    assert(boot_environment_information::query(buffer, 24, length, false).is_ok_and(|status| status == 0) && guest::read32(length) == 20 && guest::read64(buffer + 24) == 0xAAAA_AAAA_AAAA_AAAA, "bootenvinfo: formato antigo de 20 bytes");
    assert(boot_environment_information::query(buffer, 10, length, false).is_ok_and(|status| status == 0xC000_0004) && guest::read32(length) == 32, "bootenvinfo: buffer curto informa 32 bytes");
    // Integridade de código antes da CI: opções zeradas.
    guest::write32(buffer, 8);
    guest::write32(buffer + 4, 0xFFFF);
    assert(code_integrity_information::query(buffer, 8, length, false).is_ok_and(|status| status == 0) && guest::read32(buffer + 4) == 0 && guest::read32(length) == 8, "ciinfo: CodeIntegrityOptions zerado antes da CI");
    guest::write32(buffer, 4);
    assert(code_integrity_information::query(buffer, 4, length, false).is_ok_and(|status| status == 0xC000_0004) && code_integrity_information::query(buffer, 8, length, false).is_ok_and(|status| status == 0xC000_0004), "ciinfo: tamanho e Length do cabecalho conferidos");
    // Secure Boot: sem política entregue pelo loader.
    let policy = secure_boot_policy::get_information().ok().flatten();
    guest::write32(length, 0xFFFF);
    let status = secure_boot_information::query(buffer, 24, length, false);
    assert(match policy {
        None => status.is_ok_and(|status| status == 0x8043_0006) && guest::read32(length) == 0,
        Some(expected) => status.is_ok_and(|status| status == 0) && guest::read32(length) == 24 && guest::read8(buffer) == expected[0],
    }, "sbinfo: politica de Secure Boot do loader");
    guest::free_bytes(length);
    guest::free_bytes(buffer);
}

fn process_information_and_driver_services(assert: Assert) {
    use crate::ntos::cm::service::driver as driver_services;
    use crate::ntos::cm::service::database::{self as service_database, ConfigurationInput};
    use crate::drivers::fs::memory_file_system;
    use crate::ntos::ps::{process, system_process_information};
    // SystemProcessInformation: dimensionamento, lista completa e nomes relocados.
    let returned = guest::alloc_bytes(8);
    assert(system_process_information::query(0, 0, returned, false).is_ok_and(|status| status == 0xC000_0004) && guest::read32(returned) > 256, "spi: buffer curto informa o tamanho necessario");
    let needed = guest::read32(returned) as u64;
    let buffer = guest::alloc_aligned(needed + 0x100, 8, true);
    let processes = process::list_active_processes();
    let queried = system_process_information::query(buffer, needed + 0x100, returned, false);
    let mut cursor = buffer;
    let mut count = 0;
    let mut names_inside = true;
    loop {
        count += 1;
        let name = guest::read64(cursor + 64);
        names_inside &= name >= buffer && name < buffer + needed;
        let next = guest::read32(cursor) as u64;
        if next == 0 || count > 64 {
            break;
        }
        cursor += next;
    }
    assert(queried.is_ok_and(|status| status == 0) && count == processes.len() && names_inside && guest::read64(buffer + 80) == processes[0].pid && guest::read32(buffer + 4) as usize == processes[0].threads.len(), "spi: um registro por processo ativo com nome no buffer do chamador");
    assert(system_process_information::query(buffer + 4, needed + 0x100, 0, false).is_ok_and(|status| status == 0x8000_0002), "spi: saida desalinhada");
    guest::free_bytes(buffer);
    guest::free_bytes(returned);
    // Caminhos instalados de drivers.
    let configuration = |path: &str| service_database::Configuration { name: alloc::string::String::from("x"), display_name: alloc::string::String::new(), image_path: alloc::string::String::from(path), service_type: 1, start: 3, error_control: 1, object_name: alloc::string::String::new(), dependencies: alloc::vec::Vec::new() };
    assert(driver_services::image_path(&configuration("\\SystemRoot\\System32\\Drivers\\a.sys")).is_ok_and(|path| path == "/a.sys") && driver_services::image_path(&configuration("\"C:\\Windows\\System32\\Drivers\\b.sys\"")).is_ok_and(|path| path == "/b.sys") && driver_services::image_path(&configuration("system32\\drivers\\c.sys")).is_ok_and(|path| path == "/system32/drivers/c.sys"), "drvsvc: caminhos de System32\\Drivers normalizados");
    assert(driver_services::image_path(&configuration("D:\\d.sys")).is_err_and(|error| error.win32 == 3) && driver_services::image_path(&configuration("a\\..\\b.sys")).is_err_and(|error| error.win32 == 123), "drvsvc: unidade indisponivel e travessia recusadas");
    // Serviço de driver real: start/stop e ZwLoadDriver/ZwUnloadDriver.
    let counter = guest::alloc_bytes(8);
    let entry = [0x48, 0x8D, 0x05, 0x19, 0x00, 0x00, 0x00, 0x48, 0x89, 0x41, 0x68, 0x31, 0xC0, 0xC3];
    let mut unload = alloc::vec![0x48, 0xB8];
    unload.extend_from_slice(&counter.to_le_bytes());
    unload.extend_from_slice(&[0xFF, 0x00, 0xC3]);
    let _ = memory_file_system::write_bytes("/opennt-svc.sys", driver_image(&entry, &[(0x1320, &unload)]));
    driver_services::init();
    let installed = service_database::install(&ConfigurationInput { name: alloc::string::String::from("OpenNtSvcTest"), image_path: Some(alloc::string::String::from("\\SystemRoot\\System32\\Drivers\\opennt-svc.sys")), service_type: Some(1), start: Some(3), ..Default::default() }, false);
    assert(installed.is_ok() && driver_services::start("OpenNtSvcTest").is_ok_and(|status| status == 0) && service_database::status("OpenNtSvcTest").is_ok_and(|status| status.current_state == 4 && status.controls_accepted == 1), "drvsvc: start carrega o driver e o estado vem do DRIVER_OBJECT");
    assert(driver_services::start("OpenNtSvcTest").is_err_and(|error| error.win32 == 1056) && driver_services::stop("OpenNtSvcTest").is_ok() && guest::read32(counter) == 1 && service_database::status("OpenNtSvcTest").is_ok_and(|status| status.current_state == 1), "drvsvc: stop chama o DriverUnload e o servico para");
    let key = alloc::format!("{}\\OpenNtSvcTest", service_database::ROOT);
    assert(driver_services::nt_request(&key, false) == 0 && driver_services::nt_request(&key, false) == 0xC000_010E && driver_services::nt_request(&key, true) == 0 && guest::read32(counter) == 2, "drvsvc: ZwLoadDriver/ZwUnloadDriver pelo caminho da chave");
    assert(driver_services::nt_request("\\Registry\\Machine\\Software\\X", false) == 0xC000_003A && driver_services::nt_request(&alloc::format!("{}\\NaoExiste", service_database::ROOT), false) == 0xC000_0034, "drvsvc: chave fora de Services e servico inexistente");
    let _ = service_database::remove("OpenNtSvcTest");
    guest::free_bytes(counter);
}

fn io_file_information(assert: Assert) {
    use crate::ntos::io::file::information as file_information;
    let block = guest::alloc_bytes(0x800);
    let file = block;
    let lower = block + 0x200;
    let upper = block + 0x400;
    let extension = block + 0x600;
    let filter = block + 0x640;
    // FILE_OBJECT sem VPB, no dispositivo de baixo (sem desvio de volume).
    guest::write64(file + 8, lower);
    guest::write32(file + 0x50, 0x800);
    guest::write64(lower + 0x18, upper);
    assert(file_information::related_device(file).is_ok_and(|device| device == upper), "fileinfo: IoGetRelatedDeviceObject sobe ate o topo da pilha");
    // Extensão de arquivo com filtro que fixa o dispositivo abaixo do topo.
    guest::write64(file + 0xD0, extension);
    guest::write64(extension + 0x10, filter);
    guest::write64(filter, lower);
    assert(file_information::related_device(file).is_ok_and(|device| device == lower), "fileinfo: filtro da extensao seleciona o dispositivo indicado");
    guest::write64(file + 0xD0, 0);
    guest::write64(upper + 0x18, lower);
    assert(file_information::related_device(file).is_err(), "fileinfo: anexacao ciclica recusada");
    guest::write64(upper + 0x18, 0);
    guest::write64(file + 8, 0);
    assert(file_information::related_device(file).is_ok_and(|device| device == 0) && file_information::query_native(file, 5, 24, block + 0x700, 0, false, false, 0).is_ok_and(|status| status == 0xC000_0010), "fileinfo: arquivo sem dispositivo");
    // Trava síncrona do FILE_OBJECT.
    let acquired = file_information::acquire_file(file).is_ok() && guest::read32(file + 0x74) == 1;
    assert(acquired && file_information::release_file(file).is_ok() && guest::read32(file + 0x74) == 0, "fileinfo: trava sincrona do FILE_OBJECT");
    guest::free_bytes(block);
}

struct ReadOnlyVolume;

impl crate::drivers::fs::volume::FileSystem for ReadOnlyVolume {
    fn name(&self) -> &str {
        "ro"
    }
    fn exists(&self, _path: &str) -> bool {
        false
    }
    fn list(&self) -> Vec<String> {
        Vec::new()
    }
}

fn volume_file_operations(assert: Assert) {
    use crate::drivers::fs::volume::FileSystem;
    use crate::drivers::fs::{memory_file_system, ntfs};
    // Disco em memória montado em \FS.
    let memory: &dyn FileSystem = &memory_file_system::VOLUME;
    let path = "/opennt-volume.txt";
    assert(memory.writable() && memory.truncate(path).is_ok() && memory.exists(path) && memory.write_at(path, 0, b"hello").is_ok_and(|written| written == 5), "volume: disco em memoria cria e escreve");
    assert(memory.read_range(path, 1, 3).is_ok_and(|bytes| bytes.as_deref() == Some(b"ell".as_slice())) && memory.size(path) == Some(5) && memory.remove(path).is_some_and(|removed| removed.is_ok_and(|removed| removed)) && !memory.exists(path), "volume: disco em memoria le faixa, mede e remove");
    // Volume NTFS montado em \NTFS (D:).
    if let Some(volume) = ntfs::mounted() {
        let ntfs_volume: &dyn FileSystem = volume.as_ref();
        let path = "/opennt-volume.bin";
        let created = ntfs_volume.truncate(path).is_ok() && ntfs_volume.write_at(path, 0, &[1, 2, 3, 4]).is_ok_and(|written| written == 4);
        let stat = ntfs_volume.stat(path);
        assert(created && stat.as_ref().is_some_and(|stat| stat.size == 4 && !stat.directory && stat.reference.is_some()) && ntfs_volume.read_bytes(path).as_deref() == Some([1u8, 2, 3, 4].as_slice()), "volume: NTFS cria, escreve e informa stat");
        assert(ntfs_volume.truncate(path).is_ok() && ntfs_volume.size(path) == Some(0) && ntfs_volume.remove(path).is_some_and(|removed| removed.is_ok()) && !ntfs_volume.exists(path), "volume: NTFS trunca e remove");
    } else {
        assert(false, "volume: NTFS montado");
    }
    // Volume sem escrita usa o padrão protegido.
    let read_only = ReadOnlyVolume;
    assert(!read_only.writable() && read_only.write_at("/x", 0, b"x").is_err_and(|error| error.status == 0xC000_00A2) && read_only.remove("/x").is_none() && read_only.stat("/x").is_none(), "volume: padrao somente leitura");
}

/// OBJECT_ATTRIBUTES (48 bytes) com UNICODE_STRING do nome, no bloco dado.
fn object_attributes_for(block: u64, name: &str, flags: u32) -> u64 {
    let units: Vec<u16> = name.encode_utf16().collect();
    let text = block + 0x80;
    for (index, unit) in units.iter().enumerate() {
        guest::write16(text + index as u64 * 2, *unit);
    }
    let unicode = block + 0x40;
    guest::write16(unicode, units.len() as u16 * 2);
    guest::write16(unicode + 2, units.len() as u16 * 2);
    guest::write64(unicode + 8, text);
    guest::write32(block, 48);
    guest::write64(block + 8, 0);
    guest::write64(block + 16, unicode);
    guest::write32(block + 24, flags);
    block
}

fn zw_kernel_files(assert: Assert) {
    use crate::drivers::fs::{memory_file_system, ntfs, volume::FileSystem};
    use crate::ntos::ob::close;
    use crate::ntos::io::file::zw as zw_files;
    let block = guest::alloc_bytes(0x400);
    let output = block + 0x300;
    let io_status = block + 0x310;
    // Disco em memória (\FS): FILE_CREATE cria, a segunda vez informa FILE_EXISTS.
    let attributes = object_attributes_for(block, "\\FS\\opennt-zw.txt", 0x240);
    let created = zw_files::create_kernel_file(output, 0x12019F, attributes, io_status, 3, 2, 0x20);
    let handle = guest::read64(output);
    let file = zw_files::file_object_of_handle(handle);
    assert(created.is_ok_and(|status| status == 0) && guest::read64(io_status + 8) == 2 && memory_file_system::exists("/opennt-zw.txt") && file != 0 && guest::read32(file + 0x50) & 2 != 0, "zwfile: ZwCreateFile cria no disco em memoria com FILE_OBJECT sincrono");
    assert(zw_files::file_backing(file).is_some_and(|(_, path)| path == "/opennt-zw.txt") && zw_files::query_file_handle(handle, false).is_some_and(|entry| entry.is_ok_and(|(pointer, _, options)| pointer == file && options == 0x20)), "zwfile: backing do FILE_OBJECT e consulta do handle");
    let again = zw_files::create_kernel_file(output, 0x12019F, attributes, io_status, 3, 2, 0x20);
    let second = guest::read64(output);
    assert(again.is_ok_and(|status| status == 0) && guest::read64(io_status + 8) == 4 && close::close(second, Some(0)).is_ok_and(|status| status == 0), "zwfile: FILE_CREATE de arquivo existente informa FILE_EXISTS");
    assert(close::close(handle, Some(0)).is_ok_and(|status| status == 0) && close::close(handle, Some(0)).is_ok_and(|status| status == 0xC000_0008) && zw_files::file_object_of_handle(handle) == 0, "zwfile: ZwClose fecha o handle de arquivo uma vez");
    let missing = object_attributes_for(block, "\\FS\\opennt-nao-existe.txt", 0x240);
    assert(zw_files::create_kernel_file(output, 0x120089, missing, io_status, 1, 1, 0).is_ok_and(|status| status == 0xC000_0034) && guest::read32(io_status) == 0xC000_0034, "zwfile: FILE_OPEN de arquivo inexistente");
    let relative = object_attributes_for(block, "sem-raiz.txt", 0x240);
    assert(zw_files::create_kernel_file(output, 0x120089, relative, io_status, 1, 1, 0).is_ok_and(|status| status == 0xC000_003B), "zwfile: nome relativo sem RootDirectory");
    let _ = memory_file_system::remove("/opennt-zw.txt");
    // NTFS pelo link \DosDevices\D: com FILE_OPEN_IF.
    let attributes = object_attributes_for(block, "\\DosDevices\\D:\\opennt-zw.bin", 0x240);
    let created = zw_files::create_kernel_file(output, 0x12019F, attributes, io_status, 0, 3, 0x20);
    let handle = guest::read64(output);
    let on_ntfs = ntfs::mounted().is_some_and(|volume| FileSystem::exists(volume.as_ref(), "/opennt-zw.bin"));
    assert(created.is_ok_and(|status| status == 0) && guest::read64(io_status + 8) == 2 && on_ntfs && close::close(handle, Some(0)).is_ok_and(|status| status == 0), "zwfile: ZwCreateFile pelo link \\DosDevices\\D: cria no NTFS");
    if let Some(volume) = ntfs::mounted() {
        let _ = FileSystem::remove(volume.as_ref(), "/opennt-zw.bin");
    }
    guest::free_bytes(block);
}

fn zw_query_file(assert: Assert) {
    use crate::drivers::fs::memory_file_system;
    use crate::ntos::io::file::query as query_file;
    use crate::ntos::ob::close;
    use crate::ntos::io::file::zw as zw_files;
    let block = guest::alloc_bytes(0x500);
    let output = block + 0x300;
    let io_status = block + 0x310;
    let buffer = block + 0x400;
    let _ = memory_file_system::write_bytes("/opennt-q.txt", b"0123456789".to_vec());
    let attributes = object_attributes_for(block, "\\FS\\opennt-q.txt", 0x240);
    let opened = zw_files::create_kernel_file(output, 0x120089, attributes, io_status, 1, 1, 0x20);
    let handle = guest::read64(output);
    let file = zw_files::file_object_of_handle(handle);
    assert(opened.is_ok_and(|status| status == 0) && file != 0, "queryfile: arquivo aberto pelo ZwCreateFile");
    // FileStandardInformation e FileNameInformation.
    assert(query_file::query(handle, io_status, buffer, 24, 5).is_ok_and(|status| status == 0) && guest::read64(buffer + 8) == 10 && guest::read64(io_status + 8) == 24 && guest::read8(buffer + 21) == 0, "queryfile: FileStandardInformation com o tamanho do arquivo");
    assert(query_file::query(handle, io_status, buffer, 64, 9).is_ok_and(|status| status == 0) && guest::read32(buffer) == 26 && guest::read16(buffer + 4) == b'\\' as u16 && guest::read16(buffer + 6) == b'o' as u16, "queryfile: FileNameInformation com o caminho no volume");
    assert(query_file::query(handle, io_status, buffer, 8, 9).is_ok_and(|status| status == 0x8000_0005) && guest::read32(buffer) == 26 && guest::read64(io_status + 8) == 8, "queryfile: nome truncado devolve BUFFER_OVERFLOW");
    assert(query_file::query(handle, io_status, buffer, 4, 8).is_ok_and(|status| status == 0) && guest::read32(buffer) == 0x120089 && query_file::query(handle, io_status, buffer, 8, 14).is_ok_and(|status| status == 0) && guest::read64(buffer) == 0, "queryfile: acesso concedido e posicao corrente");
    assert(query_file::query(handle, io_status, buffer, 64, 2).is_ok_and(|status| status == 0xC000_0003) && query_file::query(handle, io_status, buffer, 64, 99).is_ok_and(|status| status == 0xC000_0003) && query_file::query(0x7FF0, io_status, buffer, 24, 5).is_ok_and(|status| status == 0xC000_0008), "queryfile: classe invalida e handle invalido");
    // Consulta por objeto (IoQueryFileInformation) e criação por nome.
    let length = block + 0x320;
    assert(zw_files::query_file_information_by_object(file, 5, 24, buffer, length).is_ok_and(|status| status == 0) && guest::read64(buffer + 8) == 10 && guest::read32(length) == 0x18, "queryfile: IoQueryFileInformation por FILE_OBJECT");
    assert(close::close(handle, Some(0)).is_ok_and(|status| status == 0), "queryfile: handle fechado");
    assert(zw_files::create_file_by_name("\\FS\\opennt-byname.txt", 3, 0).is_ok_and(|status| status == 0) && memory_file_system::exists("/opennt-byname.txt"), "queryfile: criacao por nome (RtlCreateSystemVolumeInformationFolder)");
    let _ = memory_file_system::remove("/opennt-q.txt");
    let _ = memory_file_system::remove("/opennt-byname.txt");
    guest::free_bytes(block);
}

fn zw_read_file(assert: Assert) {
    use crate::drivers::fs::{memory_file_system, ntfs, volume::FileSystem};
    use crate::ntos::io::file::read as read_file;
    use crate::ntos::ob::close;
    use crate::ntos::io::file::zw as zw_files;
    let block = guest::alloc_bytes(0x600);
    let output = block + 0x300;
    let io_status = block + 0x310;
    let offset = block + 0x320;
    let buffer = block + 0x400;
    // Disco em memória, arquivo síncrono: a posição corrente avança.
    let _ = memory_file_system::write_bytes("/opennt-read.txt", b"abcdefghij".to_vec());
    let attributes = object_attributes_for(block, "\\FS\\opennt-read.txt", 0x240);
    let _ = zw_files::create_kernel_file(output, 0x120089, attributes, io_status, 1, 1, 0x20);
    let handle = guest::read64(output);
    let file = zw_files::file_object_of_handle(handle);
    let first = read_file::read(handle, 0, 0, 0, io_status, buffer, 4, 0, 0);
    assert(first.is_ok_and(|status| status == 0) && guest::read64(io_status + 8) == 4 && guest::read32(buffer) == u32::from_le_bytes(*b"abcd") && guest::read64(file + 0x68) == 4, "readfile: leitura sincrona na posicao corrente");
    assert(read_file::read(handle, 0, 0, 0, io_status, buffer, 4, 0, 0).is_ok_and(|status| status == 0) && guest::read32(buffer) == u32::from_le_bytes(*b"efgh") && guest::read64(file + 0x68) == 8, "readfile: segunda leitura continua de onde parou");
    guest::write64(offset, 8);
    assert(read_file::read(handle, 0, 0, 0, io_status, buffer, 10, offset, 0).is_ok_and(|status| status == 0) && guest::read64(io_status + 8) == 2 && guest::read16(buffer) == u16::from_le_bytes(*b"ij"), "readfile: leitura curta no fim do arquivo");
    guest::write64(offset, 20);
    assert(read_file::read(handle, 0, 0, 0, io_status, buffer, 4, offset, 0).is_ok_and(|status| status == 0xC000_0011), "readfile: offset alem do fim devolve END_OF_FILE");
    let _ = close::close(handle, Some(0));
    // Arquivo assíncrono sem offset é recusado.
    let _ = zw_files::create_kernel_file(output, 0x120089, attributes, io_status, 1, 1, 0);
    let asynchronous = guest::read64(output);
    assert(read_file::read(asynchronous, 0, 0, 0, io_status, buffer, 4, 0, 0).is_ok_and(|status| status == 0xC000_000D), "readfile: arquivo assincrono exige offset");
    let _ = close::close(asynchronous, Some(0));
    let _ = memory_file_system::remove("/opennt-read.txt");
    // NTFS (cópia física direta dos bytes do volume).
    if let Some(volume) = ntfs::mounted() {
        let ntfs_volume: &dyn FileSystem = volume.as_ref();
        let _ = ntfs_volume.truncate("/opennt-read.bin");
        let pattern: Vec<u8> = (0..300u32).map(|value| (value * 7) as u8).collect();
        let _ = ntfs_volume.write_at("/opennt-read.bin", 0, &pattern);
        let attributes = object_attributes_for(block, "\\NTFS\\opennt-read.bin", 0x240);
        let _ = zw_files::create_kernel_file(output, 0x120089, attributes, io_status, 1, 1, 0x20);
        let handle = guest::read64(output);
        let read = read_file::read(handle, 0, 0, 0, io_status, buffer, 300, 0, 0);
        let bytes: Vec<u8> = (0..300u64).map(|index| guest::read8(buffer + index)).collect();
        assert(read.is_ok_and(|status| status == 0) && guest::read64(io_status + 8) == 300 && bytes == pattern, "readfile: leitura de arquivo NTFS com os bytes do volume");
        let _ = close::close(handle, Some(0));
        let _ = ntfs_volume.remove("/opennt-read.bin");
    }
    guest::free_bytes(block);
}

fn zw_write_file(assert: Assert) {
    use crate::drivers::fs::{memory_file_system, ntfs, volume::FileSystem};
    use crate::ntos::io::file::{read as read_file, write as write_file};
    use crate::ntos::ob::close;
    use crate::ntos::io::file::zw as zw_files;
    let block = guest::alloc_bytes(0x600);
    let output = block + 0x300;
    let io_status = block + 0x310;
    let offset = block + 0x320;
    let buffer = block + 0x400;
    let _ = memory_file_system::write_bytes("/opennt-write.txt", b"0123456789".to_vec());
    let attributes = object_attributes_for(block, "\\FS\\opennt-write.txt", 0x240);
    // Leitura apenas: a escrita é negada mesmo em KernelMode.
    let _ = zw_files::create_kernel_file(output, 0x120089, attributes, io_status, 1, 1, 0x20);
    let reader = guest::read64(output);
    guest::write_bytes(buffer, b"XY");
    assert(write_file::write(reader, 0, 0, 0, io_status, buffer, 2, 0, 0).is_ok_and(|status| status == 0xC000_0022), "writefile: handle so de leitura recusa escrita");
    let _ = close::close(reader, Some(0));
    // Leitura e escrita síncronas: a posição corrente avança.
    let _ = zw_files::create_kernel_file(output, 0x12019F, attributes, io_status, 3, 1, 0x20);
    let handle = guest::read64(output);
    let file = zw_files::file_object_of_handle(handle);
    guest::write_bytes(buffer, b"ABC");
    let first = write_file::write(handle, 0, 0, 0, io_status, buffer, 3, 0, 0);
    assert(first.is_ok_and(|status| status == 0) && guest::read64(io_status + 8) == 3 && guest::read64(file + 0x68) == 3 && memory_file_system::read_bytes("/opennt-write.txt").is_some_and(|bytes| bytes == b"ABC3456789"), "writefile: escrita sincrona na posicao corrente");
    guest::write64(offset, 8);
    guest::write_bytes(buffer, b"zzzz");
    assert(write_file::write(handle, 0, 0, 0, io_status, buffer, 4, offset, 0).is_ok_and(|status| status == 0) && guest::read64(file + 0x68) == 12 && memory_file_system::read_bytes("/opennt-write.txt").is_some_and(|bytes| bytes == b"ABC34567zzzz"), "writefile: escrita com offset estende o arquivo");
    guest::write64(offset, u64::MAX);
    guest::write_bytes(buffer, b"!");
    assert(write_file::write(handle, 0, 0, 0, io_status, buffer, 1, offset, 0).is_ok_and(|status| status == 0) && memory_file_system::read_bytes("/opennt-write.txt").is_some_and(|bytes| bytes == b"ABC34567zzzz!"), "writefile: offset -1 escreve no fim do arquivo");
    guest::write64(offset, 0);
    assert(read_file::read(handle, 0, 0, 0, io_status, buffer + 0x80, 13, offset, 0).is_ok_and(|status| status == 0) && guest::read64(io_status + 8) == 13 && guest::read8(buffer + 0x80 + 12) == b'!', "writefile: leitura devolve o conteudo escrito");
    let _ = close::close(handle, Some(0));
    // Só FILE_APPEND_DATA: toda escrita vai para o fim.
    let _ = zw_files::create_kernel_file(output, 0x100005, attributes, io_status, 3, 1, 0x20);
    let append = guest::read64(output);
    guest::write64(offset, 0);
    guest::write_bytes(buffer, b"+");
    assert(write_file::write(append, 0, 0, 0, io_status, buffer, 1, offset, 0).is_ok_and(|status| status == 0) && memory_file_system::read_bytes("/opennt-write.txt").is_some_and(|bytes| bytes == b"ABC34567zzzz!+"), "writefile: acesso so de acrescimo escreve no fim");
    let _ = close::close(append, Some(0));
    let _ = memory_file_system::remove("/opennt-write.txt");
    // NTFS: escreve e relê pelo volume.
    if let Some(volume) = ntfs::mounted() {
        let ntfs_volume: &dyn FileSystem = volume.as_ref();
        let _ = ntfs_volume.truncate("/opennt-write.bin");
        let attributes = object_attributes_for(block, "\\NTFS\\opennt-write.bin", 0x240);
        let _ = zw_files::create_kernel_file(output, 0x12019F, attributes, io_status, 3, 1, 0x20);
        let handle = guest::read64(output);
        let pattern: Vec<u8> = (0..200u32).map(|value| (value * 13 + 1) as u8).collect();
        guest::write_bytes(buffer, &pattern);
        let written = write_file::write(handle, 0, 0, 0, io_status, buffer, 200, 0, 0);
        assert(written.is_ok_and(|status| status == 0) && guest::read64(io_status + 8) == 200 && ntfs_volume.read_bytes("/opennt-write.bin").is_some_and(|bytes| bytes == pattern), "writefile: escrita em arquivo NTFS");
        let _ = close::close(handle, Some(0));
        let _ = ntfs_volume.remove("/opennt-write.bin");
    }
    guest::free_bytes(block);
}

fn kernel_system_threads(assert: Assert) {
    use crate::ntos::ke::dispatcher;
    use crate::ntos::ob::{close, object_manager};
    use crate::ntos::ps::{kernel_threads, scheduler};
    use crate::ntos::io::file::zw as zw_files;
    use crate::ntos::mm::pe_loader::{self as loader, LoadOptions};
    // 0x1300: mov dword [rcx], 0x1234; xor eax, eax; ret.
    // 0x1320: espera o evento em [rcx] por KeWaitForSingleObject (IAT[0]),
    // grava o status em [rcx+8] e o marcador 0x77 em [rcx+16].
    let mut bytes = ntoskrnl_importer(b"KeWaitForSingleObject\0");
    bytes[0x1300..0x1309].copy_from_slice(&[0xC7, 0x01, 0x34, 0x12, 0x00, 0x00, 0x31, 0xC0, 0xC3]);
    let displacement = (0x4200u32 - 0x1342).to_le_bytes();
    let waiter = [
        0x53, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x89, 0xCB, 0x48, 0x8B, 0x0B, 0x31, 0xD2, 0x45, 0x31, 0xC0, 0x45, 0x31, 0xC9, 0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x15, displacement[0], displacement[1], displacement[2], displacement[3], 0x89, 0x43, 0x08, 0xC7, 0x43, 0x10, 0x77, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x30, 0x5B, 0x31, 0xC0, 0xC3,
    ];
    bytes[0x1320..0x1320 + waiter.len()].copy_from_slice(&waiter);
    let options = LoadOptions { image_name: Some(String::from("opennt-kernel-threads.sys")), ..Default::default() };
    let Ok(mut image) = loader::load(bytes, &options) else {
        assert(false, "kthreads: imagem com codigo carregada");
        return;
    };
    // Os OBJECT_ATTRIBUTES do evento em +0xA0 usam até +0x140.
    let block = guest::alloc_bytes(0x200);
    let pump = |done: &dyn Fn() -> bool| {
        for _ in 0..64 {
            if done() {
                return true;
            }
            scheduler::tick(-1);
        }
        done()
    };
    // Thread que escreve e retorna: objeto sinalizado e CLIENT_ID publicado.
    let client_id = block + 0x80;
    let created = kernel_threads::create_system_thread(0, image.image_base + 0x1300, block, 0x1F_FFFF, client_id, None);
    let handle = *created.as_ref().unwrap_or(&0);
    let pointer = kernel_threads::of_handle(handle).unwrap_or(0);
    assert(created.is_ok() && pointer != 0 && guest::read64(client_id + 8) >= 0x804 && guest::read8(pointer) == 6 && kernel_threads::get_current_thread_handle() == 0, "kthreads: PsCreateSystemThread publica handle, KTHREAD e CLIENT_ID");
    let finished = pump(&|| guest::read32(block) == 0x1234 && guest::read32(pointer + 4) == 1);
    assert(finished && kernel_threads::is_terminated(pointer), "kthreads: thread roda o codigo nativo, retorna e sinaliza o objeto");
    let _ = object_manager::close(handle as u32);
    // Thread que espera um evento: só prossegue depois do KeSetEvent.
    let event = block + 0x40;
    dispatcher::initialize_event(event, 0, false);
    guest::write64(block, event);
    guest::write64(block + 8, 0xFFFF);
    guest::write32(block + 16, 0);
    let waiting = kernel_threads::create_system_thread(0, image.image_base + 0x1320, block, 0x1F_FFFF, 0, None).unwrap_or(0);
    let waiting_pointer = kernel_threads::of_handle(waiting).unwrap_or(0);
    pump(&|| false);
    assert(waiting_pointer != 0 && guest::read32(block + 16) == 0 && !kernel_threads::is_terminated(waiting_pointer), "kthreads: KeWaitForSingleObject suspende a thread no escalonador");
    dispatcher::set_event(event);
    let resumed = pump(&|| guest::read32(block + 16) == 0x77 && guest::read32(waiting_pointer + 4) == 1);
    assert(resumed && guest::read32(block + 8) == 0, "kthreads: KeSetEvent acorda a thread com STATUS_SUCCESS");
    let _ = object_manager::close(waiting as u32);
    // Handles de eventos do zw: espera por handle e NtClose.
    let node = object_manager::new_node("opennt-zw-event", "Event", Some(object_manager::ObjectData::pointer(event)));
    let output = block + 0x90;
    let attributes = object_attributes_for(block + 0xA0, "\\opennt-zw-event", 0x200);
    let opened = zw_files::open_kernel_object(output, node, 0x1F_0003, attributes);
    let event_handle = guest::read64(output);
    assert(opened.is_ok_and(|status| status == 0) && event_handle & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000 && zw_files::wait_object_of_handle(event_handle) == event && zw_files::wait_object_of_handle(event_handle & 0x7FFF_FFFF) == 0, "kthreads: handle de evento do zw resolve o KEVENT so pela forma de kernel");
    assert(close::close(event_handle, Some(0)).is_ok_and(|status| status == 0) && zw_files::wait_object_of_handle(event_handle) == 0, "kthreads: NtClose do handle de evento do zw");
    guest::free_bytes(block);
    let _ = image.release();
}

fn zw_group_exports(assert: Assert) {
    use crate::drivers::fs::memory_file_system;
    use crate::ntos::ke::dispatcher;
    use crate::ntos::ob::object_manager;
    use crate::ntos::ex::exports::zw;
    let block = guest::alloc_bytes(0x1000);
    let output = block + 0x300;
    let io_status = block + 0x310;
    let buffer = block + 0x400;
    let status = |value: Option<u64>| value.map_or(0xFFFF_FFFF, |value| value as u32);
    // Registro: cria a chave, grava e lê um valor, fecha.
    let key_attributes = object_attributes_for(block, "\\Registry\\Machine\\Software\\OpenNT-zw", 0x240);
    let created = call_export("ZwCreateKey", &[output, 0xF003F, key_attributes, 0, 0, 0, 0]);
    let key = guest::read64(output);
    let value_name = block + 0x200;
    let units: Vec<u16> = "Answer".encode_utf16().collect();
    for (index, unit) in units.iter().enumerate() {
        guest::write16(block + 0x220 + index as u64 * 2, *unit);
    }
    guest::write16(value_name, 12);
    guest::write16(value_name + 2, 12);
    guest::write64(value_name + 8, block + 0x220);
    guest::write32(block + 0x2F0, 42);
    let set = call_export("ZwSetValueKey", &[key, value_name, 0, 4, block + 0x2F0, 4]);
    let query = call_export("ZwQueryValueKey", &[key, value_name, 2, buffer, 0x100, block + 0x2F8]);
    assert(status(created) == 0 && status(set) == 0 && status(query) == 0 && guest::read32(buffer + 4) == 4 && guest::read32(buffer + 12) == 42, "zw: ZwCreateKey, ZwSetValueKey e ZwQueryValueKey (partial)");
    assert(status(call_export("ZwDeleteKey", &[key])) == 0 && status(call_export("ZwClose", &[key])) == 0, "zw: ZwDeleteKey e ZwClose da chave");
    // Arquivos: cria, escreve, relê, consulta tamanho e volume, apaga.
    let file_attributes = object_attributes_for(block, "\\FS\\opennt-zw.txt", 0x240);
    let created = call_export("ZwCreateFile", &[output, 0x12019F, file_attributes, io_status, 0, 0x80, 3, 3, 0x20, 0, 0]);
    let file = guest::read64(output);
    guest::write_bytes(buffer, b"OpenNT zw");
    let written = call_export("ZwWriteFile", &[file, 0, 0, 0, io_status, buffer, 9, 0, 0]);
    guest::write64(block + 0x2F0, 0);
    let read = call_export("ZwReadFile", &[file, 0, 0, 0, io_status, buffer + 0x100, 9, block + 0x2F0, 0]);
    assert(status(created) == 0 && status(written) == 0 && status(read) == 0 && guest::read_bytes(buffer + 0x100, 9) == b"OpenNT zw", "zw: ZwCreateFile, ZwWriteFile e ZwReadFile");
    let standard = call_export("ZwQueryInformationFile", &[file, io_status, buffer, 24, 5]);
    assert(status(standard) == 0 && guest::read64(buffer + 8) == 9, "zw: ZwQueryInformationFile (FileStandardInformation)");
    let volume = call_export("ZwQueryVolumeInformationFile", &[file, io_status, buffer, 0x100, 1]);
    assert(status(volume) == 0 && guest::read32(buffer + 12) == 12 && guest::read16(buffer + 18) == b'O' as u16 && guest::read64(io_status + 8) == 30, "zw: ZwQueryVolumeInformationFile (rotulo do volume)");
    assert(status(call_export("ZwFlushBuffersFile", &[file, io_status])) == 0 && status(call_export("ZwFlushBuffersFile", &[0x7FF0, io_status])) == 0xC000_0008, "zw: ZwFlushBuffersFile valida o handle");
    guest::write8(block + 0x2F0, 1);
    let deleted = call_export("ZwSetInformationFile", &[file, io_status, block + 0x2F0, 1, 13]);
    assert(status(deleted) == 0 && !memory_file_system::exists("/opennt-zw.txt") && status(call_export("ZwClose", &[file])) == 0, "zw: ZwSetInformationFile apaga o arquivo e ZwClose fecha");
    let missing = object_attributes_for(block, "\\FS\\opennt-ausente.txt", 0x240);
    assert(status(call_export("ZwQueryFullAttributesFile", &[missing, buffer])) == 0xC000_0034 && status(call_export("ZwOpenFile", &[output, 0x120089, missing, io_status, 1, 0])) & 0x8000_0000 != 0, "zw: arquivo ausente em ZwQueryFullAttributesFile e ZwOpenFile");
    // Consultas e configuração do sistema.
    guest::write32(block + 0x2F0, 0);
    let processes = call_export("ZwQuerySystemInformation", &[5, buffer, 8, block + 0x2F0]);
    assert(status(processes) == 0xC000_0004 && guest::read32(block + 0x2F0) > 256 && status(call_export("NtQuerySystemInformation", &[999, buffer, 8, 0])) == 0xC000_000D, "zw: ZwQuerySystemInformation dimensiona a lista de processos");
    guest::write_bytes(buffer, &[0xAA; 16]);
    assert(status(call_export("ZwQuerySystemInformation", &[117, buffer, 16, block + 0x2F0])) == 0 && guest::read64(buffer) == 0 && guest::read32(block + 0x2F0) == 16, "zw: classe 117 sem operacoes de certificado pendentes");
    assert(status(call_export("ZwPowerInformation", &[4, 0, 0, buffer, 0x40])) == 0 && guest::read8(buffer) == 1 && guest::read8(buffer + 2) == 0 && status(call_export("ZwPowerInformation", &[4, 0, 0, buffer, 8])) == 0xC000_0023, "zw: ZwPowerInformation (SystemPowerCapabilities)");
    let before = zw::entropy_registrations().len();
    guest::write64(buffer, 0x1111);
    guest::write64(buffer + 8, 0x2222);
    guest::write64(buffer + 16, 0x3333);
    assert(status(call_export("ZwSetSystemInformation", &[131, buffer, 24])) == 0 && zw::entropy_registrations().len() == before + 1 && status(call_export("ZwSetSystemInformation", &[999, buffer, 24])) == 0xC000_0003, "zw: ZwSetSystemInformation registra as rotinas de entropia");
    let basic = call_export("ZwQueryInformationProcess", &[u64::MAX, 0, buffer, 0x30, block + 0x2F0]);
    assert(status(basic) == 0 && guest::read32(buffer) == 0x103 && guest::read64(buffer + 0x20) == process_id_of_current() && guest::read32(block + 0x2F0) == 0x30, "zw: ZwQueryInformationProcess (ProcessBasicInformation)");
    // Evento nomeado: ZwOpenEvent + ZwWaitForSingleObject.
    let event = block + 0x380;
    dispatcher::initialize_event(event, 0, false);
    let node = object_manager::create_object("\\KernelObjects", "OpenNTZwEvent", "Event", Some(object_manager::ObjectData::pointer(event)));
    let event_attributes = object_attributes_for(block, "\\KernelObjects\\OpenNTZwEvent", 0x200);
    let opened = call_export("ZwOpenEvent", &[output, 0x1F0003, event_attributes]);
    let event_handle = guest::read64(output);
    guest::write64(block + 0x2F0, 0);
    let timeout = call_export("ZwWaitForSingleObject", &[event_handle, 0, block + 0x2F0]);
    dispatcher::set_event(event);
    let signaled = call_export("ZwWaitForSingleObject", &[event_handle, 0, block + 0x2F0]);
    assert(node.is_ok() && status(opened) == 0 && status(timeout) == 0x102 && status(signaled) == 0, "zw: ZwOpenEvent e ZwWaitForSingleObject (timeout e sinalizado)");
    assert(status(call_export("ZwClose", &[event_handle])) == 0, "zw: ZwClose do evento");
    // Diretório de objetos: abre a raiz e lista uma entrada.
    let root = object_attributes_for(block, "\\", 0x200);
    let directory = call_export("ZwOpenDirectoryObject", &[output, 1, root]);
    let directory_handle = guest::read64(output);
    guest::write32(block + 0x2F0, 0);
    let listed = call_export("ZwQueryDirectoryObject", &[directory_handle, buffer, 0x400, 1, 1, block + 0x2F0, block + 0x2F8]);
    assert(status(directory) == 0 && status(listed) == 0 && guest::read16(buffer) != 0 && status(call_export("ZwClose", &[directory_handle])) == 0, "zw: ZwOpenDirectoryObject e ZwQueryDirectoryObject");
    guest::free_bytes(block);
}

fn process_id_of_current() -> u64 {
    use crate::ntos::inc::nt_abi::kthread;
    let thread = crate::ntos::ps::process::get_current_thread();
    if thread == 0 { 4 } else { guest::read64(thread + kthread::CID_UNIQUE_PROCESS) }
}

fn pnp_and_boot_services(assert: Assert) {
    use crate::ntos::cm::service::database::{self as service_database, ConfigurationInput};
    use crate::ntos::cm::service::{driver as driver_services, system_drivers as services};
    use crate::ntos::cm::registry;
    use crate::drivers::fs::memory_file_system;
    use crate::ntos::io::{io_manager, pnp, small::boot_drivers_state};
    use crate::ntos::ob::object_manager;
    use alloc::string::String;
    let ids = |list: &[&str]| list.iter().map(|id| String::from(*id)).collect::<Vec<String>>();
    assert(pnp::find_function_driver(&ids(&["PNP0303"])) == Some("i8042prt") && pnp::find_function_driver(&ids(&["IDE\\DiskQEMU_HARDDISK"])) == Some("disk") && pnp::find_function_driver(&ids(&["XYZ", "PCI\\VEN_8086&DEV_7010"])) == Some("atapi") && pnp::find_function_driver(&ids(&["ACPI\\PNP0A03"])).is_none(), "pnp: driver funcional por id exato e por prefixo");
    // UpperFilters da classe (REG_MULTI_SZ UTF-16LE).
    let class = "\\Registry\\Machine\\System\\Control\\Class\\{OPENNT-TEST-CLASS}";
    let handle = registry::open_or_create(class, None).unwrap_or(0);
    let mut multi = Vec::new();
    for name in ["filtroA", "filtroB"] {
        multi.extend(registry::encode_wide(name));
    }
    multi.extend([0, 0]);
    registry::set_value(handle, "UpperFilters", 7, multi);
    registry::close_handle(handle);
    assert(pnp::read_class_upper_filters("{OPENNT-TEST-CLASS}") == ids(&["filtroA", "filtroB"]) && pnp::read_class_upper_filters("{NAO-EXISTE}").is_empty(), "pnp: UpperFilters lidos da classe na hive");
    // PDO sem driver casado: a pilha é marcada e não monta FDO.
    let node = object_manager::create_object("\\Device", "OpenNtPnpPdo", "Device", None).ok();
    if let Some(node) = node {
        io_manager::register_device(node, io_manager::DeviceEntry { hardware_ids: Some(ids(&["OPENNT\\SEM-DRIVER"])), ..Default::default() });
        assert(pnp::enumerate_pdo_stack(node).is_none() && io_manager::device(node).is_some_and(|entry| entry.stack_enumerated && entry.function_stack.is_none()) && pnp::enumerate_pdo_stack(node).is_none(), "pnp: PDO sem driver funcional marca a pilha sem FDO");
    }
    assert(pnp::attach_function_driver(node.unwrap_or(0), "opennt-nao-carregado").is_none(), "pnp: AddDevice exige o driver carregado");
    // Carga sob demanda idempotente e o laço de drivers de boot (Start <= 1).
    let counter = guest::alloc_bytes(8);
    let entry = [0x48, 0x8D, 0x05, 0x19, 0x00, 0x00, 0x00, 0x48, 0x89, 0x41, 0x68, 0x31, 0xC0, 0xC3];
    let mut unload = alloc::vec![0x48, 0xB8];
    unload.extend_from_slice(&counter.to_le_bytes());
    unload.extend_from_slice(&[0xFF, 0x00, 0xC3]);
    let _ = memory_file_system::write_bytes("/opennt-pnp-svc.sys", driver_image(&entry, &[(0x1320, &unload)]));
    driver_services::init();
    let install = |name: &str, start: u32| service_database::install(&ConfigurationInput { name: String::from(name), image_path: Some(String::from("\\SystemRoot\\System32\\Drivers\\opennt-pnp-svc.sys")), service_type: Some(1), start: Some(start), ..Default::default() }, false);
    let _ = install("OpenNtDemand", 3);
    let first = services::load_service_driver("OpenNtDemand");
    let second = services::load_service_driver("OpenNtDemand");
    assert(first && second && service_database::status("OpenNtDemand").is_ok_and(|status| status.current_state == 4) && !services::load_service_driver("OpenNtNaoInstalado"), "services: carga sob demanda idempotente e servico ausente recusado");
    let _ = driver_services::stop("OpenNtDemand");
    let _ = service_database::remove("OpenNtDemand");
    let _ = install("OpenNtBoot", 1);
    let loaded = services::start_boot_drivers();
    assert(loaded >= 1 && service_database::status("OpenNtBoot").is_ok_and(|status| status.current_state == 4) && boot_drivers_state::is_initialized(), "services: drivers de boot (Start <= 1) carregados e fase concluida");
    let _ = driver_services::stop("OpenNtBoot");
    let _ = service_database::remove("OpenNtBoot");
    assert(guest::read32(counter) == 2, "services: os dois drivers descarregados pelo DriverUnload");
    guest::free_bytes(counter);
}

fn unicode_at(block: u64, text: &str) -> u64 {
    let units: Vec<u16> = text.encode_utf16().collect();
    for (index, unit) in units.iter().enumerate() {
        guest::write16(block + 16 + index as u64 * 2, *unit);
    }
    guest::write16(block, units.len() as u16 * 2);
    guest::write16(block + 2, units.len() as u16 * 2);
    guest::write64(block + 8, block + 16);
    block
}

fn io_group_exports(assert: Assert) {
    use crate::drivers::fs::memory_file_system;
    use crate::ntos::io::io_manager;
    use crate::ntos::mm::paging;
    use crate::ntos::ob::object_manager;
    use crate::ntos::inc::nt_abi::{device_object, io_workitem, irp};
    use crate::{ntos::io::exports as io, ntos::io::lifecycle};
    let status = |value: Option<u64>| value.map_or(0xFFFF_FFFF, |value| value as u32);
    let counter = guest::alloc_bytes(8);
    let entry = [0x48, 0x8D, 0x05, 0x19, 0x00, 0x00, 0x00, 0x48, 0x89, 0x41, 0x68, 0x31, 0xC0, 0xC3];
    let mut unload = alloc::vec![0x48, 0xB8];
    unload.extend_from_slice(&counter.to_le_bytes());
    unload.extend_from_slice(&[0xFF, 0x00, 0xC3]);
    // 0x1340: callback PnP (notificacao, contexto): mov dword [rdx], 0x55; xor eax, eax; ret.
    let callback = [0xC7, 0x02, 0x55, 0x00, 0x00, 0x00, 0x31, 0xC0, 0xC3];
    let _ = memory_file_system::write_bytes("/opennt-io.sys", driver_image(&entry, &[(0x1320, &unload), (0x1340, &callback)]));
    let loaded = lifecycle::load_driver("/opennt-io.sys", &lifecycle::DriverOptions::default());
    let driver_node = object_manager::lookup("\\Driver\\opennt-io");
    let driver = driver_node.and_then(object_manager::node).and_then(|node| node.data).map_or(0, |data| data.native_pointer);
    let base = if driver != 0 { guest::read64(driver + 0x18) } else { 0 };
    assert(loaded.is_ok() && driver != 0, "io: driver de teste carregado");
    let block = guest::alloc_bytes(0x1000);
    let output = block + 0xF00;
    // IoCreateDevice: DEVICE_OBJECT com extensão, no namespace e na lista do driver.
    let name = unicode_at(block, "\\Device\\OpenNtIoTest");
    let created = call_export("IoCreateDevice", &[driver, 0x20, name, 0x22, 0, 0, output]);
    let first = guest::read64(output);
    let node = object_manager::lookup("\\Device\\OpenNtIoTest");
    assert(status(created) == 0 && first != 0 && guest::read64(driver + 8) == first && guest::read64(first + device_object::DEVICE_EXTENSION) == first + device_object::STRUCT_SIZE && guest::read32(first + device_object::DEVICE_TYPE) == 0x22 && node.and_then(io_manager::device).is_some_and(|entry| entry.native_device == first), "io: IoCreateDevice publica o dispositivo no namespace e na lista do driver");
    let unnamed = call_export("IoCreateDevice", &[driver, 0, 0, 0x22, 0, 0, output]);
    let second = guest::read64(output);
    assert(status(unnamed) == 0 && second != 0 && guest::read64(driver + 8) == second && guest::read64(second + device_object::NEXT_DEVICE) == first, "io: dispositivo sem nome entra na cabeca da lista");
    // Pilha: attach, topo, referência do topo, propriedade do PDO e detach.
    let lower = call_export("IoAttachDeviceToDeviceStack", &[second, first]);
    assert(lower == Some(first) && guest::read64(first + device_object::ATTACHED_DEVICE) == second && node.and_then(io_manager::device).is_some_and(|entry| entry.stack_top == second), "io: IoAttachDeviceToDeviceStack empilha e atualiza a rota de despacho");
    let top = call_export("IoGetAttachedDeviceReference", &[first]);
    let _ = crate::ntos::ob::objects::device::dereference(second);
    let property = call_export("IoGetDeviceProperty", &[first, 0xB, 0x200, block + 0x400, block + 0xF10]);
    let property_name: alloc::string::String = (0..20).map(|index| char::from_u32(guest::read16(block + 0x400 + index * 2) as u32).unwrap_or('?')).collect();
    assert(top == Some(second) && status(property) == 0 && property_name == "\\Device\\OpenNtIoTest" && guest::read32(block + 0xF10) == 42, "io: topo da pilha e PhysicalDeviceObjectName");
    assert(status(call_export("IoGetDeviceProperty", &[first, 0xB, 4, block + 0x400, block + 0xF10])) == 0xC000_0023 && status(call_export("IoGetDeviceProperty", &[first, 7, 0x200, block + 0x400, block + 0xF10])) == 0xC000_000D, "io: buffer curto e propriedade desconhecida");
    assert(status(call_export("IoDetachDevice", &[first])) == 0 && guest::read64(first + device_object::ATTACHED_DEVICE) == 0 && node.and_then(io_manager::device).is_some_and(|entry| entry.stack_top == first), "io: IoDetachDevice desfaz a pilha");
    // Links simbólicos.
    let link = unicode_at(block + 0x100, "\\DosDevices\\OpenNtIoTest");
    assert(status(call_export("IoCreateSymbolicLink", &[link, name])) == 0 && object_manager::lookup("\\DosDevices\\OpenNtIoTest").is_some() && status(call_export("IoDeleteSymbolicLink", &[link])) == 0 && status(call_export("IoDeleteSymbolicLink", &[link])) == 0xC000_0009, "io: IoCreateSymbolicLink e IoDeleteSymbolicLink");
    // IRP, extensões e atividade.
    let packet = call_export("IoAllocateIrp", &[2, 0]).unwrap_or(0);
    assert(packet != 0 && guest::read16(packet + irp::TYPE) == irp::IO_TYPE && guest::read8(packet + irp::STACK_COUNT) == 2 && guest::read8(packet + irp::CURRENT_LOCATION) == 3, "io: IoAllocateIrp posiciona a pilha acima do topo");
    call_export("IoSetGenericIrpExtension", &[packet, 0x1234_5678, 1]);
    guest::write_bytes(block + 0x500, &[7u8; 16]);
    call_export("IoSetActivityIdIrp", &[packet, block + 0x500]);
    let activity = call_export("IoGetActivityIdIrp", &[packet, block + 0x520]);
    assert(call_export("IoGetGenericIrpExtension", &[packet]) == Some(0x1234_5678) && status(activity) == 0 && guest::read_bytes(block + 0x520, 16) == [7u8; 16] && call_export("IoSetCancelRoutine", &[packet, 0xABC]) == Some(0) && call_export("IoSetCancelRoutine", &[packet, 0]) == Some(0xABC), "io: extensao generica, activity id e cancel routine do IRP");
    assert(status(call_export("IoFreeIrp", &[packet])) == 0, "io: IoFreeIrp");
    // MDL com os PFNs reais.
    let mdl = call_export("IoAllocateMdl", &[block + 0x800, 0x1000, 0, 0, 0]).unwrap_or(0);
    assert(mdl != 0 && guest::read64(mdl + 0x30) == paging::translate((block + 0x800) & !0xFFF) / 0x1000 && guest::read32(mdl + 0x28) == 0x1000 && guest::read32(mdl + 0x2C) == ((block + 0x800) & 0xFFF) as u32, "io: IoAllocateMdl com os PFNs das tabelas de pagina");
    call_export("IoFreeMdl", &[mdl]);
    // Remove lock.
    let lock = block + 0x600;
    call_export("IoInitializeRemoveLockEx", &[lock, 0, 0, 0, 0x58]);
    let acquired = call_export("IoAcquireRemoveLockEx", &[lock, 0, 0, 0, 0x58]);
    call_export("IoAcquireRemoveLockEx", &[lock, 0, 0, 0, 0x58]);
    call_export("IoReleaseRemoveLockEx", &[lock, 0, 0x58]);
    call_export("IoReleaseRemoveLockAndWaitEx", &[lock, 0, 0x58]);
    assert(status(acquired) == 0 && guest::read32(lock + 4) == 0 && status(call_export("IoAcquireRemoveLockEx", &[lock, 0, 0, 0, 0x58])) == 0xC000_0056, "io: remove lock conta e recusa depois da remocao");
    // Extensão de driver object.
    let extension = call_export("IoAllocateDriverObjectExtension", &[driver, 0x4F70, 0x40, output]);
    let extension_pointer = guest::read64(output);
    assert(status(extension) == 0 && status(call_export("IoAllocateDriverObjectExtension", &[driver, 0x4F70, 0x40, output])) == 0xC000_0035 && call_export("IoGetDriverObjectExtension", &[driver, 0x4F70]) == Some(extension_pointer), "io: extensao de driver object unica por tag");
    // Interface de dispositivo com notificação PnP nativa.
    let context = block + 0x700;
    guest::write32(context, 0);
    // Assinatura do WDK: categoria, flags, GUID da classe, driver, callback,
    // contexto e o registro de saída.
    for (index, byte) in [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF0, 0x01].iter().enumerate() {
        guest::write8(block + 0x720 + index as u64, *byte);
    }
    let registered = call_export("IoRegisterPlugPlayNotification", &[2, 0, block + 0x720, driver, base + 0x1340, context, block + 0x710]);
    let registration = guest::read64(block + 0x710);
    let interface = call_export("IoRegisterDeviceInterface", &[first, block + 0x720, 0, block + 0x740]);
    let link_name = guest_strings_read(block + 0x740);
    let enabled = call_export("IoSetDeviceInterfaceState", &[block + 0x740, 1]);
    assert(status(registered) == 0 && status(interface) == 0 && link_name == "\\DosDevices\\#{112233445566778899aabbccddeef001}" && status(enabled) == 0 && guest::read32(context) == 0x55 && io::interface_enabled(&link_name) == Some(true), "io: interface de dispositivo habilitada notifica o callback PnP nativo");
    assert(status(call_export("IoUnregisterPlugPlayNotification", &[registration])) == 0 && status(call_export("IoUnregisterPlugPlayNotification", &[registration])) == 0xC000_0034, "io: IoUnregisterPlugPlayNotification");
    let configuration = call_export("IoGetConfigurationInformation", &[]);
    assert(configuration.is_some_and(|pointer| pointer != 0) && call_export("IoGetConfigurationInformation", &[]) == configuration && call_export("IoSizeofWorkItem", &[]) == Some(io_workitem::SIZE) && call_export("IoGetRequestorProcess", &[0]) == Some(crate::ntos::ps::process::get_system_process()), "io: configuracao global, tamanho do work item e processo do IRP");
    // Exclusão dos dispositivos e descarga do driver.
    let deleted = (status(call_export("IoDeleteDevice", &[second])), status(call_export("IoDeleteDevice", &[first])));
    assert(deleted == (0, 0) && object_manager::lookup("\\Device\\OpenNtIoTest").is_none() && guest::read64(driver + 8) == 0, "io: IoDeleteDevice retira o dispositivo do namespace e da lista");
    assert(lifecycle::unload_driver("opennt-io") && guest::read32(counter) == 1, "io: driver descarregado");
    guest::free_bytes(block);
    guest::free_bytes(counter);
}

fn ob_group_exports(assert: Assert) {
    use crate::drivers::fs::memory_file_system;
    use crate::ntos::ob::{close, object_manager, object_types, reference_trace};
    use crate::ntos::ob::objects::{device as device_objects, driver as driver_objects};
    use crate::ntos::ps::process;
    use crate::{ntos::io::lifecycle, ntos::ob::exports as ob};
    let status = |value: Option<u64>| value.map_or(0xFFFF_FFFF, |value| value as u32);
    let counter = guest::alloc_bytes(8);
    let entry = [0x48, 0x8D, 0x05, 0x19, 0x00, 0x00, 0x00, 0x48, 0x89, 0x41, 0x68, 0x31, 0xC0, 0xC3];
    let mut unload = alloc::vec![0x48, 0xB8];
    unload.extend_from_slice(&counter.to_le_bytes());
    unload.extend_from_slice(&[0xFF, 0x00, 0xC3]);
    let _ = memory_file_system::write_bytes("/opennt-ob.sys", driver_image(&entry, &[(0x1320, &unload)]));
    let _ = lifecycle::load_driver("/opennt-ob.sys", &lifecycle::DriverOptions::default());
    let driver = object_manager::lookup("\\Driver\\opennt-ob").and_then(object_manager::node).and_then(|node| node.data).map_or(0, |data| data.native_pointer);
    let block = guest::alloc_bytes(0x1000);
    let output = block + 0xF00;
    let name = unicode_at(block, "\\Device\\OpenNtObTest");
    let _ = call_export("IoCreateDevice", &[driver, 0, name, 0x22, 0, 0, output]);
    let device = guest::read64(output);
    assert(driver != 0 && device != 0, "ob: driver e dispositivo de teste");
    // Referência por nome e por ponteiro, contadas pelo dono do dispositivo.
    let before = device_objects::reference_count(device).unwrap_or(0);
    let by_name = call_export("ObReferenceObjectByName", &[name, 0x40, 0, 0, 0, 0, 0, output]);
    assert(status(by_name) == 0 && guest::read64(output) == device && device_objects::reference_count(device) == Some(before + 1), "ob: ObReferenceObjectByName referencia o dispositivo pelo dono");
    call_export("ObfDereferenceObject", &[device]);
    call_export("ObReferenceObject", &[device]);
    call_export("ObDereferenceObject", &[device]);
    assert(device_objects::reference_count(device) == Some(before) && status(call_export("ObReferenceObjectByName", &[unicode_at(block + 0x200, "\\Device\\NaoExiste"), 0x40, 0, 0, 0, 0, 0, output])) == 0xC000_0034, "ob: referencias equilibradas e nome ausente");
    // Nome do objeto.
    let unicode = block + 0x300;
    guest::write64(unicode + 8, block + 0x400);
    let queried = call_export("ObQueryNameString", &[device, unicode, 0x200, block + 0xF10]);
    assert(status(queried) == 0 && guest_strings_read(unicode) == "\\Device\\OpenNtObTest" && guest::read32(block + 0xF10) == 42 && status(call_export("ObQueryNameString", &[device, unicode, 8, block + 0xF10])) == 0xC000_0004, "ob: ObQueryNameString devolve o caminho completo");
    // Driver por nome: referência e handle pelo dono dos drivers.
    let driver_name = unicode_at(block + 0x500, "\\Driver\\opennt-ob");
    let driver_reference = call_export("ObReferenceObjectByName", &[driver_name, 0x40, 0, 0, 0, 0, 0, output]);
    let driver_count = driver_objects::reference_count(driver);
    assert(status(driver_reference) == 0 && guest::read64(output) == driver && driver_count.is_some() && status(call_export("ObReferenceObjectByName", &[driver_name, 0x40, 0, 0, object_types::process_type().pointer, 0, 0, output])) == 0xC000_0024, "ob: driver por nome e tipo errado recusado");
    call_export("ObDereferenceObject", &[driver]);
    let attributes = object_attributes_for(block + 0x600, "\\Driver\\opennt-ob", 0x240);
    let opened = call_export("ObOpenObjectByName", &[attributes, 0, 0, 0, 0x1F01FF, 0, output]);
    let driver_handle = guest::read64(output);
    let by_handle = call_export("ObReferenceObjectByHandle", &[driver_handle, 0, object_types::driver_type().pointer, 0, block + 0xF20, block + 0xF30]);
    assert(status(opened) == 0 && driver_handle != 0 && status(by_handle) == 0 && guest::read64(block + 0xF20) == driver, "ob: ObOpenObjectByName e ObReferenceObjectByHandle do driver");
    call_export("ObDereferenceObject", &[driver]);
    let _ = close::close(driver_handle, Some(0));
    // Pseudo-handles de processo e thread.
    let current = process::get_current_process();
    let pseudo = call_export("ObReferenceObjectByHandle", &[u64::MAX, 0, object_types::process_type().pointer, 0, block + 0xF20, block + 0xF30]);
    assert(status(pseudo) == 0 && guest::read64(block + 0xF20) == current && guest::read32(block + 0xF34) == object_types::process_type().valid_access, "ob: pseudo-handle -1 resolve o processo corrente");
    call_export("ObDereferenceObject", &[current]);
    let thread = call_export("ObReferenceObjectByHandle", &[u64::MAX - 1, 0, 0, 0, block + 0xF20, 0]);
    let thread_mismatch = call_export("ObReferenceObjectByHandle", &[u64::MAX - 1, 0, object_types::event_type().pointer, 1, block + 0xF20, 0]);
    assert(status(thread) == 0 && guest::read64(block + 0xF20) == process::get_current_thread() && status(thread_mismatch) == 0xC000_0024 && status(call_export("ObReferenceObjectByHandle", &[u64::MAX - 5, 0, 0, 0, block + 0xF20, 0])) == 0xC000_0008, "ob: pseudo-handle -2, tipo validado antes do acesso e handle negativo");
    call_export("ObDereferenceObject", &[process::get_current_thread()]);
    // Por ponteiro: tipo exigido em modo usuário.
    assert(status(call_export("ObReferenceObjectByPointer", &[current, 0, object_types::process_type().pointer, 1])) == 0 && status(call_export("ObReferenceObjectByPointer", &[current, 0, object_types::thread_type().pointer, 1])) == 0xC000_0024 && status(call_export("ObReferenceObjectByPointer", &[0, 0, 0, 0])) == 0xC000_000D, "ob: ObReferenceObjectByPointer confere o tipo em modo usuario");
    call_export("ObDereferenceObject", &[current]);
    // Segurança, device maps e histórico de referências.
    assert(status(call_export("ObSetSecurityObjectByPointer", &[device, 0x5000, 4])) == 0 && ob::security_descriptor(device) == Some(0x5000) && call_export("ObIsDosDeviceLocallyMapped", &[0]) == Some(0), "ob: descritor de seguranca e device maps");
    reference_trace::clear();
    reference_trace::set_enabled(true);
    let _ = ob::reference_with_tag(device, 0x4142_4344, false);
    let _ = ob::dereference_with_tag(device, 0x4142_4344, false);
    reference_trace::set_enabled(false);
    let trace = reference_trace::snapshot();
    assert(trace.len() == 2 && trace[0].pointer == device && trace[0].delta == 1 && trace[1].delta == -1 && trace[1].tag == 0x4142_4344 && ob::reference_with_tag(block, 1, false).is_err(), "ob: historico de referencias com tag e corpo sem dono recusado");
    reference_trace::clear();
    let _ = call_export("IoDeleteDevice", &[device]);
    assert(object_manager::lookup("\\Device\\OpenNtObTest").is_none() && lifecycle::unload_driver("opennt-ob"), "ob: dispositivo excluido e driver descarregado");
    guest::free_bytes(block);
    guest::free_bytes(counter);
}

fn private_routines_and_small_groups(assert: Assert) {
    use crate::hal::amd64::{native_call, private_entries};
    use crate::drivers::fs::memory_file_system;
    use crate::ntos::io::small::initial_stack;
    use crate::ntos::ob::{close, object_manager};
    use crate::ntos::ps::process;
    use crate::ntos::init::{export_names as abi_names, exports};
    use crate::ntos::io::lifecycle;
    use crate::ntos::io::file::zw as zw_files;
    use crate::ntos::mm::pe_loader::ResolvedImport;
    use crate::ntos::init::exports::private_routines;
    let status = |value: Option<u64>| value.map_or(0xFFFF_FFFF, |value| value as u32);
    assert(abi_names::EXPORT_NAMES[private_entries::ENUM_HANDLES_ID as usize - 32] == "ExEnumHandleTable" && abi_names::EXPORT_NAMES[private_entries::RELEASE_RUNDOWN_ID as usize - 32] == "ExReleaseRundownProtection" && abi_names::EXPORT_NAMES[private_entries::ACQUIRE_RUNDOWN_ID as usize - 32] == "ExAcquireRundownProtection" && private_routines::name(private_routines::FIND_HANDLE_FILTER_ID) == Some("ObpFindHandleForObject") && private_routines::address("ObpFindHandleForObject") != 0, "privadas: ids fixados no corpo nativo e entradas privadas");
    // Driver com dois dispositivos: handle por nome e busca do handle.
    let counter = guest::alloc_bytes(8);
    let entry = [0x48, 0x8D, 0x05, 0x19, 0x00, 0x00, 0x00, 0x48, 0x89, 0x41, 0x68, 0x31, 0xC0, 0xC3];
    let mut unload = alloc::vec![0x48, 0xB8];
    unload.extend_from_slice(&counter.to_le_bytes());
    unload.extend_from_slice(&[0xFF, 0x00, 0xC3]);
    let _ = memory_file_system::write_bytes("/opennt-priv.sys", driver_image(&entry, &[(0x1320, &unload)]));
    let _ = lifecycle::load_driver("/opennt-priv.sys", &lifecycle::DriverOptions::default());
    let driver = object_manager::lookup("\\Driver\\opennt-priv").and_then(object_manager::node).and_then(|node| node.data).map_or(0, |data| data.native_pointer);
    let block = guest::alloc_bytes(0x1000);
    let output = block + 0xF00;
    let attributes = object_attributes_for(block, "\\Driver\\opennt-priv", 0x240);
    let opened = call_export("ObOpenObjectByName", &[attributes, 0, 0, 0, 0x1F01FF, 0, output]);
    let handle = guest::read64(output);
    let current = process::get_current_process();
    // Corpo nativo resolvido pelo loader.
    let native = match exports::lookup("ntoskrnl.exe", "ObFindHandleForObject") {
        Some(ResolvedImport::Address { address, .. }) => address,
        _ => 0,
    };
    guest::write64(block + 0xF10, 0);
    let found = if native != 0 { native_call::call(native, &[current, driver, 0, 0, block + 0xF10]) & 0xFF } else { 0 };
    assert(status(opened) == 0 && native != 0 && found == 1 && guest::read64(block + 0xF10) & 0x7FFF_FFFC == handle & 0x7FFF_FFFC, "privadas: ObFindHandleForObject nativo encontra o handle do driver (indice da tabela do System)");
    let missing = if native != 0 { native_call::call(native, &[current, block, 0, 0, block + 0xF10]) & 0xFF } else { 1 };
    assert(missing == 0, "privadas: objeto sem handle nao e encontrado");
    // Caminho do trampolim (busca do kernel).
    let thunk = exports::thunk_address(744).unwrap_or(0);
    guest::write64(block + 0xF10, 0);
    let by_thunk = native_call::call(thunk, &[current, driver, 0, 0, block + 0xF10]) & 0xFF;
    assert(by_thunk == 1 && guest::read64(block + 0xF10) & 0x7FFF_FFFC == handle & 0x7FFF_FFFC, "privadas: ObFindHandleForObject pelo trampolim");
    let _ = close::close(handle, Some(0));
    // IoAttachDeviceToDeviceStackSafe com a saída do dispositivo abaixo.
    let name = unicode_at(block + 0x200, "\\Device\\OpenNtSafe");
    let _ = call_export("IoCreateDevice", &[driver, 0, name, 0x22, 0, 0, output]);
    let lower = guest::read64(output);
    let _ = call_export("IoCreateDevice", &[driver, 0, 0, 0x22, 0, 0, output]);
    let upper = guest::read64(output);
    guest::write64(block + 0xF20, 0);
    let safe = call_export("IoAttachDeviceToDeviceStackSafe", &[upper, lower, block + 0xF20]);
    assert(status(safe) == 0 && guest::read64(block + 0xF20) == lower, "pequenos: IoAttachDeviceToDeviceStackSafe devolve o dispositivo abaixo");
    call_export("IoDetachDevice", &[lower]);
    call_export("IoDeleteDevice", &[upper]);
    call_export("IoDeleteDevice", &[lower]);
    let _ = lifecycle::unload_driver("opennt-priv");
    // Nt* de arquivo, pilha inicial e atividade da thread.
    let _ = memory_file_system::write_bytes("/opennt-nt.txt", b"OpenNT".to_vec());
    let file_attributes = object_attributes_for(block + 0x400, "\\FS\\opennt-nt.txt", 0x240);
    let _ = zw_files::create_kernel_file(output, 0x12019F, file_attributes, block + 0xF30, 3, 1, 0x20);
    let file = guest::read64(output);
    let queried = call_export("NtQueryInformationFile", &[file, block + 0xF30, block + 0x600, 24, 5]);
    guest::write_bytes(block + 0x700, b"XY");
    guest::write64(block + 0xF40, 0);
    let written = call_export("NtWriteFile", &[file, 0, 0, 0, block + 0xF30, block + 0x700, 2, block + 0xF40, 0]);
    let read = call_export("NtReadFile", &[file, 0, 0, 0, block + 0xF30, block + 0x780, 6, block + 0xF40, 0]);
    assert(status(queried) == 0 && guest::read64(block + 0x608) == 6 && status(written) == 0 && status(read) == 0 && guest::read_bytes(block + 0x780, 6) == b"XYenNT", "pequenos: NtQueryInformationFile, NtWriteFile e NtReadFile");
    let _ = close::close(file, Some(0));
    let _ = memory_file_system::remove("/opennt-nt.txt");
    let previous = call_export("IoSetActivityIdThread", &[block + 0x800]);
    let restored = call_export("IoSetActivityIdThread", &[previous.unwrap_or(0)]);
    assert(call_export("IoGetInitialStack", &[]) == Some(initial_stack::get()) && previous.is_some() && restored == Some(block + 0x800), "pequenos: IoGetInitialStack e IoSetActivityIdThread");
    guest::free_bytes(block);
    guest::free_bytes(counter);
}

fn device_control_and_delete_file(assert: Assert) {
    use crate::drivers::fs::memory_file_system;
    use crate::ntos::ob::{close, object_manager};
    use crate::ntos::inc::nt_abi::{driver_object, irp};
    use crate::ntos::io::lifecycle;
    use crate::ntos::mm::pe_loader::{self as loader, LoadOptions};
    let status = |value: Option<u64>| value.map_or(0xFFFF_FFFF, |value| value as u32);
    let block = guest::alloc_bytes(0x1000);
    let output = block + 0xF00;
    // ZwDeleteFile no disco em memória.
    let _ = memory_file_system::write_bytes("/opennt-del.txt", b"x".to_vec());
    let attributes = object_attributes_for(block, "\\FS\\opennt-del.txt", 0x240);
    assert(status(call_export("ZwDeleteFile", &[attributes])) == 0 && !memory_file_system::exists("/opennt-del.txt"), "deletefile: ZwDeleteFile apaga o arquivo do volume");
    assert(status(call_export("ZwDeleteFile", &[attributes])) == 0xC000_0034, "deletefile: arquivo ausente");
    let relative = object_attributes_for(block, "sem-barra", 0x240);
    assert(status(call_export("ZwDeleteFile", &[relative])) == 0xC000_003B && status(call_export("ZwDeleteFile", &[0])) == 0xC000_000D, "deletefile: nome relativo sem raiz e atributos nulos");
    guest::write32(block, 40);
    assert(status(call_export("ZwDeleteFile", &[block])) == 0xC000_000D, "deletefile: OBJECT_ATTRIBUTES com Length errado");
    // Rotinas de despacho nativas: 0x1300 conclui com sucesso; 0x1340 grava
    // "OKAY" no SystemBuffer com Information 4. Ambas chamam IofCompleteRequest (IAT[0]).
    let code = |at: usize, ioctl: bool| -> Vec<u8> {
        let mut bytes = Vec::new();
        if ioctl {
            bytes.extend_from_slice(&[0x48, 0x8B, 0x42, irp::SYSTEM_BUFFER as u8]); // mov rax, [rdx+SystemBuffer]
            bytes.extend_from_slice(&[0xC7, 0x00, b'O', b'K', b'A', b'Y']); // mov dword [rax], "OKAY"
        }
        bytes.extend_from_slice(&[0xC7, 0x42, irp::IO_STATUS as u8, 0, 0, 0, 0]); // mov dword [rdx+IoStatus], 0
        bytes.extend_from_slice(&[0x48, 0xC7, 0x42, irp::IO_STATUS_INFORMATION as u8, if ioctl { 4 } else { 0 }, 0, 0, 0]); // mov qword [rdx+Information], n
        bytes.extend_from_slice(&[0x48, 0x89, 0xD1, 0x31, 0xD2, 0x48, 0x83, 0xEC, 0x28]); // mov rcx, rdx; xor edx, edx; sub rsp, 28h
        let after_call = at + bytes.len() + 6;
        bytes.extend_from_slice(&[0xFF, 0x15]);
        bytes.extend_from_slice(&((0x4200 - after_call) as u32).to_le_bytes());
        bytes.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28, 0x31, 0xC0, 0xC3]);
        bytes
    };
    let mut image_bytes = ntoskrnl_importer(b"IofCompleteRequest\0");
    let complete = code(0x1300, false);
    let ioctl = code(0x1340, true);
    image_bytes[0x1300..0x1300 + complete.len()].copy_from_slice(&complete);
    image_bytes[0x1340..0x1340 + ioctl.len()].copy_from_slice(&ioctl);
    let Ok(mut image) = loader::load(image_bytes, &LoadOptions { image_name: Some(String::from("opennt-devctl-code.sys")), ..Default::default() }) else {
        assert(false, "devctl: rotinas de despacho carregadas");
        return;
    };
    let counter = guest::alloc_bytes(8);
    let entry = [0x48, 0x8D, 0x05, 0x19, 0x00, 0x00, 0x00, 0x48, 0x89, 0x41, 0x68, 0x31, 0xC0, 0xC3];
    let mut unload = alloc::vec![0x48, 0xB8];
    unload.extend_from_slice(&counter.to_le_bytes());
    unload.extend_from_slice(&[0xFF, 0x00, 0xC3]);
    let _ = memory_file_system::write_bytes("/opennt-devctl.sys", driver_image(&entry, &[(0x1320, &unload)]));
    let _ = lifecycle::load_driver("/opennt-devctl.sys", &lifecycle::DriverOptions::default());
    let driver = object_manager::lookup("\\Driver\\opennt-devctl").and_then(object_manager::node).and_then(|node| node.data).map_or(0, |data| data.native_pointer);
    for major in [0u64, 2, 18] {
        guest::write64(driver + driver_object::MAJOR_FUNCTION + major * 8, image.image_base + 0x1300);
    }
    guest::write64(driver + driver_object::MAJOR_FUNCTION + 14 * 8, image.image_base + 0x1340);
    let name = unicode_at(block + 0x200, "\\Device\\OpenNtIoctl");
    let _ = call_export("IoCreateDevice", &[driver, 0, name, 0x22, 0, 0, output]);
    let device = guest::read64(output);
    // Abertura do dispositivo e IOCTL METHOD_BUFFERED (0x222000).
    let file_attributes = object_attributes_for(block + 0x300, "\\Device\\OpenNtIoctl", 0x240);
    let opened = call_export("ZwCreateFile", &[output, 0x12019F, file_attributes, block + 0xF10, 0, 0, 3, 1, 0x20, 0, 0]);
    let handle = guest::read64(output);
    guest::write32(block + 0x500, 0);
    let controlled = call_export("ZwDeviceIoControlFile", &[handle, 0, 0, 0, block + 0xF20, 0x22_2000, 0, 0, block + 0x500, 16]);
    assert(device != 0 && status(opened) == 0 && status(controlled) == 0 && guest::read_bytes(block + 0x500, 4) == b"OKAY" && guest::read32(block + 0xF20) == 0 && guest::read64(block + 0xF28) == 4, "devctl: ZwDeviceIoControlFile entrega o IRP ao driver nativo e copia a saida buffered");
    assert(status(call_export("ZwDeviceIoControlFile", &[0x7FF0, 0, 0, 0, block + 0xF20, 0x22_2000, 0, 0, block + 0x500, 16])) == 0xC000_0008, "devctl: handle invalido");
    // IoVolumeDeviceToDosName recusa dispositivos que não são volumes.
    assert(status(call_export("IoVolumeDeviceToDosName", &[device, block + 0x600])) == 0xC000_000D, "volumedos: dispositivo que nao e volume");
    let _ = close::close(handle, Some(0));
    call_export("IoDeleteDevice", &[device]);
    let _ = lifecycle::unload_driver("opennt-devctl");
    let _ = image.release();
    guest::free_bytes(counter);
    guest::free_bytes(block);
}

fn tagged_token_convert_disk(assert: Assert) {
    use crate::drivers::fs::memory_file_system;
    use crate::ntos::ob::close;
    use crate::ntos::ps::process;
    use crate::ntos::inc::nt_abi::{devobj_extension, device_object, vpb};
    use crate::ntos::io::file::zw as zw_files;
    let status = |value: Option<u64>| value.map_or(0xFFFF_FFFF, |value| value as u32);
    // Referência com tag pelo dono do processo.
    let current = process::get_current_process();
    let referenced = call_export("ObfReferenceObjectWithTag", &[current, 0x4F70_4E54]).unwrap_or(0);
    let dereferenced = call_export("ObfDereferenceObjectWithTag", &[current, 0x4F70_4E54]).unwrap_or(0);
    assert(referenced >= 1 && dereferenced == referenced - 1, "tagged: ObfReference/ObfDereferenceObjectWithTag contam pelo dono do processo");
    // Token da thread corrente: a thread de kernel não está impersonando.
    let block = guest::alloc_bytes(0x800);
    let output = block + 0x700;
    assert(status(call_export("ZwOpenThreadTokenEx", &[u64::MAX - 1, 8, 1, 0x200, output])) == 0xC000_007C, "tokenhandles: ZwOpenThreadTokenEx sem impersonacao devolve STATUS_NO_TOKEN");
    // Conversão de handle de arquivo para handle de kernel.
    let _ = memory_file_system::write_bytes("/opennt-convert.txt", b"c".to_vec());
    let attributes = object_attributes_for(block, "\\FS\\opennt-convert.txt", 0x240);
    let _ = zw_files::create_kernel_file(output, 0x12019F, attributes, block + 0x710, 3, 1, 0x20);
    let source = guest::read64(output);
    let converted = call_export("IoConvertFileHandleToKernelHandle", &[source, 0, 1, 0, block + 0x720]);
    let target = guest::read64(block + 0x720);
    assert(status(converted) == 0 && target != 0 && target != source && zw_files::file_object_of_handle(source) != 0, "convert: IoConvertFileHandleToKernelHandle duplica para a tabela do System");
    guest::write64(block + 0x720, 0xFFFF);
    assert(status(call_export("IoConvertFileHandleToKernelHandle", &[0, 0, 1, 0, block + 0x720])) == 0 && guest::read64(block + 0x720) == 0, "convert: origem nula zera a saida");
    let _ = close::close(target, Some(0));
    let _ = close::close(source, Some(0));
    let _ = memory_file_system::remove("/opennt-convert.txt");
    // IoGetDiskDeviceObject sobre DEVICE_OBJECTs sintéticos.
    let device = block + 0x100;
    let extension = block + 0x300;
    let block_vpb = block + 0x400;
    guest::write64(device + device_object::VPB, block_vpb);
    assert(status(call_export("IoGetDiskDeviceObject", &[device, output])) == 0xC000_000D, "diskdevice: dispositivo de armazenamento com VPB proprio recusado");
    guest::write64(device + device_object::VPB, 0);
    guest::write64(device + device_object::DEVICE_OBJECT_EXTENSION, extension);
    guest::write64(extension + devobj_extension::VPB, 0);
    assert(status(call_export("IoGetDiskDeviceObject", &[device, output])) == 0xC000_000D, "diskdevice: volume sem VPB");
    guest::write64(extension + devobj_extension::VPB, block_vpb);
    guest::write32(block_vpb + vpb::REFERENCE_COUNT, 0);
    guest::write16(block_vpb + vpb::FLAGS, vpb::MOUNTED as u16);
    assert(status(call_export("IoGetDiskDeviceObject", &[device, output])) == 0xC000_026E, "diskdevice: VPB sem referencias = volume desmontado");
    guest::free_bytes(block);
}

fn query_security_object(assert: Assert) {
    use crate::drivers::fs::memory_file_system;
    use crate::ntos::ob::close;
    use crate::ntos::io::file::zw as zw_files;
    let status = |value: Option<u64>| value.map_or(0xFFFF_FFFF, |value| value as u32);
    let block = guest::alloc_bytes(0x800);
    let output = block + 0x700;
    let needed = block + 0x710;
    let buffer = block + 0x400;
    // Arquivo de volume sem ACLs: o descritor mundial do SeAssignWorldSecurityDescriptor.
    let _ = memory_file_system::write_bytes("/opennt-qsec.txt", b"s".to_vec());
    let attributes = object_attributes_for(block, "\\FS\\opennt-qsec.txt", 0x240);
    let _ = zw_files::create_kernel_file(output, 0x12019F, attributes, block + 0x720, 3, 1, 0x20);
    let file = guest::read64(output);
    let world = call_export("ZwQuerySecurityObject", &[file, 1, buffer, 0x100, needed]);
    assert(status(world) == 0 && guest::read32(needed) == 44 && guest::read8(buffer) == 1 && guest::read32(buffer + 4) == 20 && guest::read8(buffer + 20) == 1 && guest::read8(buffer + 27) == 1 && guest::read16(buffer + 2) & 0x8000 != 0, "querysecurity: arquivo de volume recebe o descritor mundial");
    assert(status(call_export("ZwQuerySecurityObject", &[file, 1, buffer, 8, needed])) == 0xC000_0023 && guest::read32(needed) == 44, "querysecurity: buffer curto informa os 44 bytes");
    let _ = close::close(file, Some(0));
    let _ = memory_file_system::remove("/opennt-qsec.txt");
    // Processo corrente: descritor da política do dono.
    guest::write32(needed, 0);
    let process = call_export("ZwQuerySecurityObject", &[u64::MAX, 1, buffer, 0, needed]);
    let process_needed = guest::read32(needed);
    let process_full = call_export("ZwQuerySecurityObject", &[u64::MAX, 1, buffer, process_needed as u64, needed]);
    assert(status(process) == 0xC000_0023 && process_needed > 20 && status(process_full) == 0 && guest::read8(buffer) == 1 && guest::read32(buffer + 4) != 0, "querysecurity: processo corrente pelo descritor da politica do dono");
    guest::write32(needed, 0xABCD);
    assert(status(call_export("ZwQuerySecurityObject", &[0x7FF0, 1, buffer, 0x100, needed])) == 0xC000_0008 && guest::read32(needed) == 0xABCD, "querysecurity: handle invalido nao toca a saida");
    guest::free_bytes(block);
}

fn persistent_thread_state_capture(assert: Assert) {
    use crate::ntos::init::exports;
    let output = guest::alloc_bytes(0x40000);
    let context = guest::alloc_bytes(0x500);
    for offset in (0..0x4D0u64).step_by(8) {
        guest::write64(context + offset, 0x5A5A_0000_0000_0000 | offset);
    }
    // RIP num trampolim real (página de código legível) e RSP qualquer.
    let rip = exports::thunk_address(100).unwrap_or(0);
    guest::write64(context + 0xF8, rip);
    let returned = call_export("KeCapturePersistentThreadState", &[context, 0, 0xDEAD, 1, 2, 3, 4, output]);
    let flags = guest::read32(output + 0x1038);
    assert(returned == Some(0x40000) && guest::read32(output + 4) == 0x3436_5544 && guest::read32(output + 0x30) == 0x8664 && guest::read32(output + 0x38) == 0xDEAD && guest::read64(output + 0x40) == 1 && guest::read64(output + 0x58) == 4, "triage: cabecalho DU64 com o bugcheck e os parametros");
    assert(guest::read64(output + 0x348 + 8) == 0x5A5A_0000_0000_0008 && guest::read64(output + 0xF10) == rip && guest::read32(output + 0x2080 + 0x10) == 0x4742_444B && guest::read32(output + 0x3FFFC) == 0x4447_5254, "triage: CONTEXT copiado, KDBG e o verificador TRGD");
    assert(flags & 0x49F == 0x49F && guest::read32(output + 0x201C) != 0 && guest::read32(output + 0x2024) != 0, "triage: PRCB, processo, thread e modulos registrados nas flags");
    assert(call_export("KeCapturePersistentThreadState", &[context, 0, 0xDEAD, 1, 2, 3, 4, 0]) == Some(0), "triage: saida nula recusada");
    guest::free_bytes(context);
    guest::free_bytes(output);
}

fn image_verification_callbacks(assert: Assert) {
    use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
    use crate::ntos::ps::scheduler;
    use crate::ntos::se::image_verification;
    use crate::ntos::mm::pe_loader::{self as loader, LoadOptions};
    let status = |value: Option<u64>| value.map_or(0xFFFF_FFFF, |value| value as u32);
    // Callback (context, 1, cópia): mov [rcx], rdx; mov [rcx+8], r8; xor eax, eax; ret.
    let mut bytes = ntoskrnl_importer(b"KeSetEvent\0");
    bytes[0x1300..0x130B].copy_from_slice(&[0x48, 0x89, 0x11, 0x4C, 0x89, 0x41, 0x08, 0x31, 0xC0, 0xC3, 0x90]);
    let Ok(mut image) = loader::load(bytes, &LoadOptions { image_name: Some(String::from("opennt-imgver.sys")), ..Default::default() }) else {
        assert(false, "imgver: callback carregado");
        return;
    };
    let block = guest::alloc_bytes(0x100);
    let context = block;
    guest::write64(context, 0);
    guest::write64(context + 8, 0);
    let output = block + 0x80;
    assert(status(call_export("SeRegisterImageVerificationCallback", &[2, 0, image.image_base + 0x1300, context, 0, output])) == 0xC000_00EF && status(call_export("SeRegisterImageVerificationCallback", &[1, 1, image.image_base + 0x1300, context, 0, output])) == 0xC000_00F0 && status(call_export("SeRegisterImageVerificationCallback", &[1, 0, image.image_base + 0x1300, context, 8, output])) == 0xC000_00F3, "imgver: tipo de imagem, tipo de callback e token recusados");
    let registered = call_export("SeRegisterImageVerificationCallback", &[1, 0, image.image_base + 0x1300, context, 0, output]);
    let handle = guest::read64(output);
    assert(status(registered) == 0 && handle != 0 && image_verification::count() == 1, "imgver: inscricao registrada");
    // Pacote do pool com os ponteiros internos apontando para o próprio pacote.
    let packet = kernel_pool::allocate(0x80, AllocateOptions { tag: 0x7473_6554, ..Default::default() }).unwrap_or(0);
    for offset in (0..0x80u64).step_by(8) {
        guest::write64(packet + offset, 0);
    }
    for offset in [0x10u64, 0x30, 0x40, 0x48, 0x50] {
        guest::write64(packet + offset, packet + 0x60 + offset / 8);
    }
    let queued = image_verification::queue_owned_information(packet, 0x80);
    for _ in 0..64 {
        if image_verification::pending() == 0 {
            break;
        }
        scheduler::tick(-1);
    }
    let copy = guest::read64(context + 8);
    assert(queued.is_ok_and(|status| status == 0) && image_verification::pending() == 0 && guest::read64(context) == 1 && copy != 0 && copy != packet, "imgver: o callback recebe a copia do pacote pela thread de sistema");
    assert(guest::read64(copy + 0x10) == copy + 0x62 && guest::read64(copy + 0x50) == copy + 0x6A, "imgver: ponteiros internos ajustados a base da copia");
    assert(status(call_export("SeUnregisterImageVerificationCallback", &[handle])) == 0 && image_verification::count() == 0, "imgver: inscricao removida");
    guest::free_bytes(block);
    let _ = image.release();
}

fn rtl_unwind_dynamic_table(assert: Assert) {
    use crate::ntos::rtl::unwind;
    let block = guest::alloc_bytes(0x2000);
    let base = (block + 0xFFF) & !0xFFF;
    // Código: prólogo push rbx; sub rsp, 20h; corpo de NOPs; epílogo em 0x130.
    for offset in 0x100..0x140u64 {
        guest::write8(base + offset, 0x90);
    }
    guest::write_bytes(base + 0x100, &[0x53, 0x48, 0x83, 0xEC, 0x20]);
    guest::write_bytes(base + 0x130, &[0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3]);
    // UNWIND_INFO v1: prólogo de 5 bytes, 2 slots (ALLOC_SMALL 0x20 em 5, PUSH_NONVOL rbx em 1).
    guest::write_bytes(base + 0x200, &[0x01, 0x05, 0x02, 0x00]);
    guest::write16(base + 0x204, 5 | (2 << 8) | (3 << 12));
    guest::write16(base + 0x206, 1 | (3 << 12));
    // RUNTIME_FUNCTION.
    guest::write32(base + 0x300, 0x100);
    guest::write32(base + 0x304, 0x140);
    guest::write32(base + 0x308, 0x200);
    let table = base + 0x300;
    assert(unwind::add_function_table(table, 1, base).is_ok_and(|added| added == 1) && unwind::add_function_table(table, 1, base).is_ok_and(|added| added == 0), "unwind: RtlAddFunctionTable registra uma vez");
    let image_base_output = base + 0x400;
    let found = unwind::lookup_function_entry(base + 0x110, image_base_output, 0);
    assert(found.is_ok_and(|entry| entry == table) && guest::read64(image_base_output) == base && unwind::lookup_function_entry(base + 0x150, image_base_output, 0).is_ok_and(|entry| entry == 0), "unwind: RtlLookupFunctionEntry pela tabela dinamica");
    // Pilha: locais [0, 20h), rbx salvo em 20h, retorno em 28h.
    let stack = base + 0x800;
    guest::write64(stack + 0x20, 0xB0B0);
    guest::write64(stack + 0x28, 0xCAFE);
    let context = base + 0xA00;
    let run = |rip: u64| {
        for offset in (0..0x4D0u64).step_by(8) {
            guest::write64(context + offset, 0);
        }
        guest::write64(context + 0x78 + 4 * 8, stack);
        guest::write64(context + 0xF8, rip);
        let handler = unwind::unwind(0, base, rip, table, context, base + 0x410, base + 0x418, 0);
        handler.is_ok_and(|handler| handler == 0) && guest::read64(context + 0x78 + 3 * 8) == 0xB0B0 && guest::read64(context + 0xF8) == 0xCAFE && guest::read64(context + 0x78 + 4 * 8) == stack + 0x30
    };
    assert(run(base + 0x110) && guest::read64(base + 0x418) == stack, "unwind: RtlVirtualUnwind pelos codigos (rbx, retorno e RSP reconstruidos)");
    assert(run(base + 0x130), "unwind: RtlVirtualUnwind decodifica o epilogo real");
    assert(unwind::delete_function_table(table) == 1 && unwind::delete_function_table(table) == 0, "unwind: RtlDeleteFunctionTable");
    guest::free_bytes(block);
}

fn kernel_seh_raise_and_unwind(assert: Assert) {
    use crate::ntos::rtl::{native_context, unwind};
    use crate::ntos::mm::pe_loader::{self as loader, LoadOptions};
    // IAT[0] = ExRaiseStatus; IAT[2] (0x4210) = RtlUnwindEx no lugar do WRITE_PORT_UCHAR.
    let mut bytes = ntoskrnl_importer(b"ExRaiseStatus\0");
    for byte in &mut bytes[0x4442..0x4480] {
        *byte = 0;
    }
    bytes[0x4442..0x444E].copy_from_slice(b"RtlUnwindEx\0");
    let rel = |from_next: usize, to: usize| ((to as i64 - from_next as i64) as i32).to_le_bytes();
    // F (0x1300): sub rsp,28h; mov ecx,0C0001234h; call [ExRaiseStatus]; add rsp,28h; xor eax,eax; ret.
    // Bloco de tratamento (0x1316): add rsp,28h; ret (RAX = valor do RtlUnwindEx).
    let mut f = alloc::vec![0x48, 0x83, 0xEC, 0x28, 0xB9, 0x34, 0x12, 0x00, 0xC0, 0xFF, 0x15];
    f.extend_from_slice(&rel(0x130F, 0x4200));
    f.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28, 0x31, 0xC0, 0xC3, 0x48, 0x83, 0xC4, 0x28, 0xC3]);
    bytes[0x1300..0x1300 + f.len()].copy_from_slice(&f);
    // Handler de linguagem (0x1330): RtlUnwindEx(frame, 0x1316, record, *record, NULL, NULL).
    let mut handler = alloc::vec![0x48, 0x83, 0xEC, 0x38, 0x48, 0x89, 0xC8, 0x48, 0x89, 0xD1, 0x48, 0x8D, 0x15];
    handler.extend_from_slice(&rel(0x1341, 0x1316));
    handler.extend_from_slice(&[0x49, 0x89, 0xC0, 0x44, 0x8B, 0x08, 0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0, 0x48, 0xC7, 0x44, 0x24, 0x28, 0, 0, 0, 0, 0xFF, 0x15]);
    handler.extend_from_slice(&rel(0x135F, 0x4210));
    handler.extend_from_slice(&[0x48, 0x83, 0xC4, 0x38, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]);
    bytes[0x1330..0x1330 + handler.len()].copy_from_slice(&handler);
    // UNWIND_INFO v1 com UNW_FLAG_EHANDLER: prólogo de 4 bytes, ALLOC_SMALL 28h, handler 0x1330.
    bytes[0x1400..0x1404].copy_from_slice(&[0x09, 0x04, 0x01, 0x00]);
    bytes[0x1404..0x1406].copy_from_slice(&(4u16 | (2 << 8) | (4 << 12)).to_le_bytes());
    bytes[0x1408..0x140C].copy_from_slice(&0x1330u32.to_le_bytes());
    // RUNTIME_FUNCTION de F.
    bytes[0x1500..0x1504].copy_from_slice(&0x1300u32.to_le_bytes());
    bytes[0x1504..0x1508].copy_from_slice(&0x1320u32.to_le_bytes());
    bytes[0x1508..0x150C].copy_from_slice(&0x1400u32.to_le_bytes());
    let Ok(mut image) = loader::load(bytes, &LoadOptions { image_name: Some(String::from("opennt-seh.sys")), ..Default::default() }) else {
        assert(false, "seh: imagem de teste carregada");
        return;
    };
    let base = image.image_base;
    let added = unwind::add_function_table(base + 0x1500, 1, base);
    let result = native_context::call(base + 0x1300, &[], 0);
    assert(added.is_ok_and(|added| added == 1) && result.as_ref().is_ok_and(|value| *value as u32 == 0xC000_1234), "seh: ExRaiseStatus despacha ao handler e o RtlUnwindEx transfere ao bloco de tratamento");
    let _ = unwind::delete_function_table(base + 0x1500);
    let _ = image.release();
}

fn rtl_support_modules(assert: Assert) {
    use crate::ntos::ps::{kernel_threads, scheduler};
    use crate::ntos::rtl::{ansi_code_page, run_once, strings_counted};
    use crate::ntos::mm::pe_loader::{self as loader, LoadOptions};
    let block = guest::alloc_bytes(0x800);
    // Strings contadas.
    let destination = block;
    let buffer = block + 0x100;
    guest::write16(destination, 0);
    guest::write16(destination + 2, 16);
    guest::write64(destination + 8, buffer);
    let text = block + 0x200;
    for (index, unit) in "OpenNT".encode_utf16().chain([0]).enumerate() {
        guest::write16(text + index as u64 * 2, unit);
    }
    assert(strings_counted::append(destination, text) == 0 && guest::read16(destination) == 12 && guest::read16(buffer + 12) == 0 && guest::read16(buffer) == b'O' as u16 && strings_counted::append(destination, text) == 0xC000_0023, "rtlstrings: RtlAppendUnicodeToString com NUL e buffer cheio");
    let copy = block + 0x20;
    guest::write16(copy, 0);
    guest::write16(copy + 2, 8);
    guest::write64(copy + 8, block + 0x300);
    strings_counted::copy(copy, destination);
    assert(guest::read16(copy) == 8 && guest::read16(block + 0x300 + 6) == b'n' as u16, "rtlstrings: RtlCopyUnicodeString trunca em MaximumLength");
    guest::write_bytes(block + 0x400, b"ansi\0");
    strings_counted::initialize_ansi(block + 0x40, block + 0x400);
    assert(guest::read16(block + 0x40) == 4 && guest::read16(block + 0x42) == 5 && guest::read64(block + 0x48) == block + 0x400, "rtlstrings: RtlInitAnsiString");
    // RTL_RUN_ONCE: inicializador nativo publica o contexto 0x1000.
    // 0x1300: mov qword [r8], 1000h; mov eax, 1; ret.
    let mut bytes = ntoskrnl_importer(b"KeSetEvent\0");
    bytes[0x1300..0x130D].copy_from_slice(&[0x49, 0xC7, 0x00, 0x00, 0x10, 0x00, 0x00, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]);
    let Ok(mut image) = loader::load(bytes, &LoadOptions { image_name: Some(String::from("opennt-runonce.sys")), ..Default::default() }) else {
        assert(false, "runonce: inicializador carregado");
        return;
    };
    let once = block + 0x500;
    let context = block + 0x508;
    let _ = run_once::initialize(once);
    guest::write64(context, 0);
    let first = run_once::execute(once, image.image_base + 0x1300, 0, context);
    assert(first.is_ok_and(|status| status == 0) && guest::read64(once) == 0x1002 && guest::read64(context) == 0x1000, "runonce: RtlRunOnceExecuteOnce chama o inicializador e publica o contexto");
    guest::write64(context, 0);
    assert(run_once::execute(once, 0xDEAD, 0, context).is_ok_and(|status| status == 0) && guest::read64(context) == 0x1000, "runonce: segunda execucao devolve o contexto sem chamar");
    let _ = run_once::initialize(once);
    assert(run_once::begin_initialize(once, 0, context).is_ok_and(|status| status == 0x103) && run_once::complete(once, 0, 0x2000).is_ok_and(|status| status == 0) && run_once::begin_initialize(once, 1, context).is_ok_and(|status| status == 0) && guest::read64(context) == 0x2000 && run_once::complete(once, 0, 0x3001).is_ok_and(|status| status == 0xC000_00F1), "runonce: BeginInitialize/Complete e contexto desalinhado recusado");
    // Pela thread de sistema (interceptação do RtlRunOnceExecuteOnce).
    let _ = run_once::initialize(once);
    guest::write64(context, 0);
    let request = run_once::execute_request(once, image.image_base + 0x1300, 0, context).map(|request| kernel_threads::create_system_request(alloc::boxed::Box::new(request)));
    for _ in 0..32 {
        if guest::read64(once) & 3 == 2 {
            break;
        }
        scheduler::tick(-1);
    }
    assert(request.is_ok_and(|created| created.is_ok()) && guest::read64(once) == 0x1002 && guest::read64(context) == 0x1000, "runonce: execucao pela requisicao de thread de sistema");
    // Página ANSI: tabela real do volume ou erro honesto.
    let table = ansi_code_page::current();
    let ansi_ok = match &table {
        Ok(table) => table.code_page == 1252,
        Err(error) => error.message.contains("NLS"),
    };
    assert(ansi_ok, "ansi: tabela c_1252.nls do volume ou ausencia reportada");
    guest::free_bytes(block);
    let _ = image.release();
}

/// Grupo `rtl` pelos trampolins: strings, inteiros, interlocked, memória,
/// listas, CRT, formatação, LCG, versão, bitmap, GUID, tempo, registro e SID.
fn rtl_group_exports(assert: Assert) {
    use crate::ntos::rtl::guest_strings;
    let block = guest::alloc_bytes(0x1000);
    guest::write_bytes(block, &[0u8; 0x1000]);
    let call = |name: &str, arguments: &[u64]| call_export(name, arguments).unwrap_or(u64::MAX);
    // UNICODE_STRING.
    let text = block + 0x800;
    guest_strings::write_wide_string(text, "OpenNT");
    let first = block;
    call("RtlInitUnicodeString", &[first, text]);
    assert(guest::read16(first) == 12 && guest::read16(first + 2) == 14 && guest::read64(first + 8) == text, "rtl: RtlInitUnicodeString aponta o buffer sem copiar");
    let second = unicode_at(block + 0x40, "OPENNT");
    assert(call("RtlEqualUnicodeString", &[first, second, 0]) == 0 && (call("RtlCompareUnicodeString", &[first, second, 0]) as i32) > 0, "rtl: RtlEqual/CompareUnicodeString sensiveis a caixa");
    // Sem caixa só com a tabela NLS do volume (a ausência é erro, não fallback).
    let casing = crate::ntos::rtl::unicode_case::upcase_char(b'a' as u16);
    assert(casing.as_ref().map_or_else(|error| error.message.contains("l_intl"), |&upper| upper == b'A' as u16 && call("RtlEqualUnicodeString", &[first, second, 1]) == 1), "rtl: RtlEqualUnicodeString sem caixa pela tabela l_intl.nls (ou ausencia reportada)");
    let lower = block + 0x80;
    assert(call("RtlDowncaseUnicodeString", &[lower, second, 1]) == 0 && guest_strings_read(lower) == "opennt" && call("RtlFreeUnicodeString", &[lower]) == 0 && guest::read64(lower + 8) == 0, "rtl: RtlDowncaseUnicodeString aloca e RtlFreeUnicodeString libera");
    // Inteiros.
    let value = block + 0x100;
    let number = unicode_at(block + 0xC0, "0x1F");
    assert(call("RtlUnicodeStringToInteger", &[number, 0, value]) == 0 && guest::read32(value) == 31, "rtl: RtlUnicodeStringToInteger com base automatica");
    let invalid = unicode_at(block + 0xC0, "zz");
    assert(call("RtlUnicodeStringToInteger", &[invalid, 10, value]) as u32 == 0xC000_000D, "rtl: RtlUnicodeStringToInteger recusa texto sem digitos");
    let digits = block + 0x110;
    guest::write16(digits + 2, 16);
    guest::write64(digits + 8, block + 0x120);
    assert(call("RtlIntegerToUnicodeString", &[255, 16, digits]) == 0 && guest_strings_read(digits) == "ff", "rtl: RtlIntegerToUnicodeString em hexadecimal");
    // Interlocked de 32 bits.
    let counter = block + 0x140;
    guest::write32(counter, 41);
    assert(call("InterlockedIncrement", &[counter]) == 42 && call("InterlockedCompareExchange", &[counter, 7, 42]) == 42 && guest::read32(counter) == 7 && call("InterlockedExchange", &[counter, 9]) == 7 && guest::read32(counter) == 9, "rtl: InterlockedIncrement/CompareExchange/Exchange");
    // Memória.
    let bytes = block + 0x180;
    guest::write_bytes(bytes, b"abcdef");
    call("memmove", &[bytes + 2, bytes, 4]);
    assert(guest::read_bytes(bytes, 6) == b"ababcd", "rtl: memmove com sobreposicao");
    call("memset", &[bytes, b'x' as u64, 2]);
    guest::write_bytes(block + 0x190, b"xxabZZ");
    assert(call("RtlCompareMemory", &[bytes, block + 0x190, 6]) == 4, "rtl: memset e RtlCompareMemory");
    // ExInterlocked*List sob spinlock.
    let (head, lock, entry_a, entry_b) = (block + 0x1A0, block + 0x1B0, block + 0x1C0, block + 0x1D0);
    guest::write64(head, head);
    guest::write64(head + 8, head);
    call("ExInterlockedInsertTailList", &[head, entry_a, lock]);
    call("ExInterlockedInsertTailList", &[head, entry_b, lock]);
    assert(call("ExInterlockedRemoveHeadList", &[head, lock]) == entry_a && call("ExInterlockedRemoveHeadList", &[head, lock]) == entry_b && call("ExInterlockedRemoveHeadList", &[head, lock]) == 0 && guest::read32(lock) == 0, "rtl: ExInterlockedInsertTail/RemoveHeadList em ordem FIFO");
    // CRT.
    let c_text = block + 0x200;
    guest::write_bytes(c_text, b"kernel opennt\0");
    guest::write_bytes(block + 0x220, b"open\0");
    assert(call("strlen", &[c_text]) == 13 && call("strstr", &[c_text, block + 0x220]) == c_text + 7, "rtl: strlen e strstr");
    let small = block + 0x240;
    assert(call("strncpy_s", &[small, 5, c_text, u32::MAX as u64]) == 80 && guest::read_bytes(small, 5) == b"kern\0", "rtl: strncpy_s com _TRUNCATE devolve STRUNCATE");
    guest::write_bytes(block + 0x260, b"%d-%x\0");
    assert(call("sprintf", &[block + 0x280, block + 0x260, 42, 255]) == 5 && guest_strings::read_c_string(block + 0x280) == "42-ff", "rtl: sprintf");
    guest::write_bytes(block + 0x270, b"%d\0");
    assert(call("_snprintf_s", &[block + 0x290, 4, u32::MAX as u64, block + 0x270, 123_456]) == 3 && guest_strings::read_c_string(block + 0x290) == "123", "rtl: _snprintf_s trunca com _TRUNCATE");
    guest_strings::write_wide_string(block + 0x2A0, "%u-%X");
    assert(call("swprintf_s", &[block + 0x2C0, 16, block + 0x2A0, 7, 255]) == 4 && guest_strings::read_wide_string(block + 0x2C0) == "7-FF", "rtl: swprintf_s");
    guest_strings::write_wide_string(block + 0x2E0, "AbC");
    guest_strings::write_wide_string(block + 0x2F0, "abc");
    assert(call("_wcsicmp", &[block + 0x2E0, block + 0x2F0]) == 0 && call("wcscmp", &[block + 0x2E0, block + 0x2F0]) as i64 == -1 && call("wcslen", &[block + 0x2E0]) == 3, "rtl: _wcsicmp, wcscmp e wcslen");
    // RtlRandom: seed*214013+2531011.
    let seed = block + 0x340;
    guest::write32(seed, 1);
    assert(call("RtlRandom", &[seed]) == 41 && guest::read32(seed) == 2_745_024, "rtl: RtlRandom (LCG)");
    // Versão.
    let info = block + 0x400;
    call("RtlGetVersion", &[info]);
    assert(guest::read32(info + 4) == 10 && guest::read32(info + 12) == 26100 && guest::read32(info + 16) == 2 && guest::read16(info + 0x114) == 0x100 && guest::read8(info + 0x116) == 1, "rtl: RtlGetVersion 10.0.26100 estacao de trabalho");
    assert(call("RtlVerifyVersionInfo", &[info, 1, 1]) == 0, "rtl: RtlVerifyVersionInfo aceita a versao igual");
    guest::write32(info + 4, 11);
    assert(call("RtlVerifyVersionInfo", &[info, 1, 1]) as u32 == 0xC000_0428 && call("VerSetConditionMask", &[0, 2, 3]) == 192, "rtl: RtlVerifyVersionInfo recusa e VerSetConditionMask desloca 3 bits por tipo");
    assert(call("RtlNtStatusToDosError", &[0xC000_0034]) == 2 && call("RtlNtStatusToDosErrorNoTeb", &[0xC0DE_0001]) == 317 && call("RtlUpcaseUnicodeChar", &[0xE9]) == 0xC9 && call("RtlUpcaseUnicodeChar", &[0xF7]) == 0xF7, "rtl: NTSTATUS para Win32 e RtlUpcaseUnicodeChar");
    // Bitmap de 64 bits.
    let (header, bits) = (block + 0x540, block + 0x560);
    call("RtlInitializeBitMap", &[header, bits, 64]);
    call("RtlSetBits", &[header, 0, 5]);
    assert(call("RtlFindClearBits", &[header, 3, 0]) == 5 && call("RtlNumberOfSetBits", &[header]) == 5 && call("RtlTestBit", &[header, 4]) == 1 && call("RtlAreBitsClear", &[header, 5, 59]) == 1, "rtl: RtlSetBits, FindClearBits, TestBit e AreBitsClear");
    assert(call("RtlFindClearBitsAndSet", &[header, 2, 0]) == 5 && call("RtlNumberOfSetBits", &[header]) == 7 && guest::read8(bits) == 0x7F, "rtl: RtlFindClearBitsAndSet");
    // GUID.
    let guid = block + 0x580;
    guest::write_bytes(guid, &[0x78, 0x56, 0x34, 0x12, 0xCD, 0xAB, 0x01, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
    let guid_text = block + 0x5A0;
    assert(call("RtlStringFromGUID", &[guid, guid_text]) == 0 && guest_strings_read(guid_text) == "{12345678-ABCD-EF01-0123-456789ABCDEF}", "rtl: RtlStringFromGUID");
    let parsed = block + 0x5C0;
    assert(call("RtlGUIDFromString", &[guid_text, parsed]) == 0 && guest::read_bytes(parsed, 16) == guest::read_bytes(guid, 16), "rtl: RtlGUIDFromString inverte RtlStringFromGUID");
    // TIME_FIELDS.
    let (fields, time, back) = (block + 0x600, block + 0x620, block + 0x640);
    for (index, field) in [2024u16, 2, 29, 12, 34, 56, 789].iter().enumerate() {
        guest::write16(fields + index as u64 * 2, *field);
    }
    assert(call("RtlTimeFieldsToTime", &[fields, time]) == 1 && guest::read64(time) == 133_536_836_967_890_000, "rtl: RtlTimeFieldsToTime em 100 ns desde 1601");
    call("RtlTimeToTimeFields", &[time, back]);
    let decoded: Vec<u16> = (0..8).map(|index| guest::read16(back + index * 2)).collect();
    assert(decoded == [2024, 2, 29, 12, 34, 56, 789, 4], "rtl: RtlTimeToTimeFields com dia da semana (quinta)");
    guest::write16(fields + 4, 30);
    assert(call("RtlTimeFieldsToTime", &[fields, time]) == 0, "rtl: RtlTimeFieldsToTime recusa 30 de fevereiro");
    // Registro: escrita relativa a RTL_REGISTRY_SERVICES e consulta DIRECT absoluta.
    let path = block + 0x680;
    guest_strings::write_wide_string(path, "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\OpenNtRtlTest");
    let relative = block + 0x7C0;
    guest_strings::write_wide_string(relative, "OpenNtRtlTest");
    let (value_name, missing_name, data) = (block + 0x760, block + 0x780, block + 0x7A0);
    guest_strings::write_wide_string(value_name, "Valor");
    guest_strings::write_wide_string(missing_name, "Ausente");
    guest::write32(data, 0x1234);
    assert(call("RtlWriteRegistryValue", &[1, relative, value_name, 4, data, 4]) == 0, "rtl: RtlWriteRegistryValue relativo a Services");
    let table = block + 0x900;
    let (direct, defaulted, default_data) = (block + 0x9C0, block + 0x9C8, block + 0x9D0);
    guest::write32(default_data, 0x55);
    guest::write32(table + 8, 0x20);
    guest::write64(table + 0x10, value_name);
    guest::write64(table + 0x18, direct);
    guest::write32(table + 0x38 + 8, 0x20);
    guest::write64(table + 0x38 + 0x10, missing_name);
    guest::write64(table + 0x38 + 0x18, defaulted);
    guest::write32(table + 0x38 + 0x20, 4);
    guest::write64(table + 0x38 + 0x28, default_data);
    guest::write32(table + 0x38 + 0x30, 4);
    assert(call("RtlQueryRegistryValues", &[0, path, table, 0, 0]) == 0 && guest::read32(direct) == 0x1234 && guest::read32(defaulted) == 0x55, "rtl: RtlQueryRegistryValues DIRECT com valor e default");
    guest::write32(table + 0x38 + 8, 0x24);
    guest::write32(table + 0x38 + 0x20, 0);
    assert(call("RtlQueryRegistryValues", &[0, path, table, 0, 0]) as u32 == 0xC000_0034, "rtl: RtlQueryRegistryValues REQUIRED sem valor nem default");
    assert(call("RtlDeleteRegistryValue", &[1, relative, value_name]) == 0 && call("RtlDeleteRegistryValue", &[1, relative, value_name]) as u32 == 0xC000_0034, "rtl: RtlDeleteRegistryValue remove o valor");
    // SID S-1-5-32-544.
    let (sid, authority, copy) = (block + 0xA00, block + 0xA40, block + 0xA60);
    guest::write_bytes(authority, &[0, 0, 0, 0, 0, 5]);
    assert(call("RtlInitializeSidEx", &[sid, authority, 2, 32, 544]) == 0 && call("RtlValidSid", &[sid]) == (sid > 0x7FFF_FFFF_0000) as u64 && call("RtlLengthSid", &[sid]) == 16 && guest::read32(sid + 12) == 544, "rtl: RtlInitializeSidEx com subautoridades variadicas (RtlValidSid recusa a faixa de usuario)");
    assert(call("RtlCopySid", &[8, copy, sid]) as u32 == 0xC000_0023 && call("RtlCopySid", &[16, copy, sid]) == 0 && call("RtlEqualSid", &[sid, copy]) == 1, "rtl: RtlCopySid e RtlEqualSid");
    guest::free_bytes(block);
}

/// Spin locks numerados, ForDpc, RaiseToSynch, Test/TryTo, os try do
/// EX_SPIN_LOCK e o lock da VPB.
fn ntoskrnl_spin_lock_family(assert: Assert) {
    use crate::ntos::ke::{irql, pcr};
    let vpb = pcr::queued_spin_lock(9).unwrap_or(0);
    let old = call_export("KeAcquireQueuedSpinLock", &[9]);
    let held = (irql::get_irql(), call_export("KeTestSpinLock", &[vpb]));
    call_export("KeReleaseQueuedSpinLock", &[9, old.unwrap_or(0)]);
    assert(vpb != 0 && old == Some(0) && held == (2, Some(0)) && irql::get_irql() == 0 && call_export("KeTestSpinLock", &[vpb]) == Some(1), "ke: KeAcquire/ReleaseQueuedSpinLock na LockQueue da PRCB");
    assert((0..17).all(|number| pcr::queued_spin_lock(number).is_some()), "ke: todas as entradas da LockQueue com lock");
    let out = guest::alloc_bytes(8);
    let tried = call_export("KeTryToAcquireQueuedSpinLock", &[9, out]);
    let busy = call_export("KeTryToAcquireSpinLockAtDpcLevel", &[vpb]);
    call_export("KeReleaseQueuedSpinLock", &[9, guest::read8(out) as u64]);
    assert(tried == Some(1) && busy == Some(0) && irql::get_irql() == 0, "ke: KeTryToAcquireQueuedSpinLock e tentativa com o lock ocupado");
    let old = call_export("KeAcquireQueuedSpinLockRaiseToSynch", &[5]);
    let synch = irql::get_irql();
    call_export("KeReleaseQueuedSpinLock", &[5, old.unwrap_or(0)]);
    assert(old == Some(0) && synch == 12 && irql::get_irql() == 0, "ke: RaiseToSynch sobe ao SYNCH_LEVEL");
    let spin = guest::alloc_bytes(8);
    guest::write64(spin, 0);
    let handle = guest::alloc_bytes(24);
    call_export("KeAcquireInStackQueuedSpinLockRaiseToSynch", &[spin, handle]);
    let level = irql::get_irql();
    call_export("KeReleaseInStackQueuedSpinLockForDpc", &[handle]);
    assert(level == 12 && guest::read64(handle + 8) == spin && guest::read64(spin) == 0 && irql::get_irql() == 0, "ke: in-stack RaiseToSynch e liberacao ForDpc");
    let previous = call_export("KeAcquireSpinLockForDpc", &[spin]);
    let taken = guest::read64(spin);
    call_export("KeReleaseSpinLockForDpc", &[spin, previous.unwrap_or(0)]);
    assert(previous == Some(0) && taken == 1 && guest::read64(spin) == 0 && irql::get_irql() == 0, "ke: KeAcquire/ReleaseSpinLockForDpc");
    let ex = guest::alloc_bytes(8);
    guest::write32(ex, 0);
    let before = irql::raise_irql(2);
    let exclusive = call_export("ExTryAcquireSpinLockExclusiveAtDpcLevel", &[ex]);
    let shared_blocked = call_export("ExTryAcquireSpinLockSharedAtDpcLevel", &[ex]);
    guest::write32(ex, 0);
    let shared = call_export("ExTryAcquireSpinLockSharedAtDpcLevel", &[ex]);
    let exclusive_blocked = call_export("ExTryAcquireSpinLockExclusiveAtDpcLevel", &[ex]);
    irql::lower_irql(before as u64);
    assert(exclusive == Some(1) && shared_blocked == Some(0) && shared == Some(1) && exclusive_blocked == Some(0) && guest::read32(ex) == 1, "ex: ExTryAcquireSpinLock exclusivo e compartilhado");
    call_export("IoAcquireVpbSpinLock", &[out]);
    let vpb_busy = call_export("KeTestSpinLock", &[vpb]);
    call_export("IoReleaseVpbSpinLock", &[guest::read8(out) as u64]);
    assert(vpb_busy == Some(0) && irql::get_irql() == 0 && call_export("KeTestSpinLock", &[vpb]) == Some(1), "io: IoAcquire/ReleaseVpbSpinLock usa o LockQueueIoVpbLock");
}

/// Afinidade, grupos e nós, KeGenericCallDpc e ZwOpen/GetNext de processos
/// e threads.
fn ntoskrnl_affinity_and_processes(assert: Assert) {
    use crate::ntos::inc::nt_abi::kthread;
    let first = call_export("KeSetSystemAffinityThreadEx", &[1]);
    let second = call_export("KeSetSystemAffinityThreadEx", &[1]);
    call_export("KeRevertToUserAffinityThreadEx", &[0]);
    let group = guest::alloc_bytes(32);
    guest::write_bytes(group, &[0; 32]);
    guest::write64(group, 1);
    call_export("KeSetSystemGroupAffinityThread", &[group, group + 16]);
    let previous_mask = guest::read64(group + 16);
    call_export("KeRevertToUserGroupAffinityThread", &[group + 16]);
    assert(first == Some(0) && second == Some(1) && previous_mask == 0, "ke: afinidade de sistema com a anterior e a volta para a de usuario");
    let groups = (call_export("KeQueryActiveGroupCount", &[]), call_export("KeQueryMaximumGroupCount", &[]));
    assert(groups == (Some(1), Some(1)) && call_export("KeQueryGroupAffinity", &[0]).is_some_and(|mask| mask & 1 == 1) && call_export("KeQueryGroupAffinity", &[1]) == Some(0) && call_export("KeQueryNodeMaximumProcessorCount", &[0]) == call_export("KeQueryMaximumProcessorCount", &[]), "ke: grupos e nos de processadores");
    let dpc = guest::alloc_bytes(0x40);
    let number = guest::alloc_bytes(8);
    guest::write64(number, 0);
    let valid = call_export("KeSetTargetProcessorDpcEx", &[dpc, number]);
    guest::write8(number + 2, 200);
    let invalid = call_export("KeSetTargetProcessorDpcEx", &[dpc, number]);
    assert(valid == Some(0) && invalid == Some(0xFFFF_FFFF_C000_000D), "ke: KeSetTargetProcessorDpcEx valida o PROCESSOR_NUMBER");
    // KeGenericCallDpc: a rotina avisa o fim e passa pela barreira.
    let counter = guest::alloc_bytes(8);
    guest::write64(counter, 0);
    let routine = generic_call_routine();
    let called = call_export("KeGenericCallDpc", &[routine, counter]);
    assert(called == Some(0) && guest::read64(counter) == 1, "ke: KeGenericCallDpc com KeSignalCallDpcSynchronize e KeSignalCallDpcDone");
    // ZwOpenProcess/ZwOpenThread e ZwGetNextProcess/ZwGetNextThread.
    let block = guest::alloc_bytes(0x100);
    guest::write_bytes(block, &[0; 0x100]);
    let (handle, cid, attributes) = (block, block + 0x10, block + 0x40);
    guest::write32(attributes, 0x30);
    guest::write32(attributes + 0x18, 0x200);
    let processes = crate::ntos::ps::process::list_active_processes();
    let target = processes.iter().find(|entry| !entry.threads.is_empty());
    let (pid, thread) = target.map_or((0, 0), |entry| (entry.pid, entry.threads[0]));
    guest::write64(cid, pid);
    let opened = call_export("ZwOpenProcess", &[handle, 0x1000, attributes, cid]);
    let process_handle = guest::read64(handle);
    assert(target.is_some() && opened == Some(0) && process_handle != 0, "ps: ZwOpenProcess pelo CLIENT_ID");
    let mixed = call_export("ZwOpenProcess", &[handle, 0x1000, 0, 0]);
    guest::write64(cid, 0x7FFF_FFF0);
    let missing = call_export("ZwOpenProcess", &[handle, 0x1000, attributes, cid]);
    assert(mixed == Some(0xFFFF_FFFF_C000_0030) && missing == Some(0xFFFF_FFFF_C000_000B), "ps: ZwOpenProcess sem nome nem CLIENT_ID e com CLIENT_ID inexistente");
    guest::write64(cid, pid);
    guest::write64(cid + 8, guest::read64(thread + kthread::CID_UNIQUE_THREAD));
    let opened_thread = call_export("ZwOpenThread", &[handle, 0x800, attributes, cid]);
    let thread_handle = guest::read64(handle);
    guest::write64(cid, pid + 4);
    let wrong_process = call_export("ZwOpenThread", &[handle + 8, 0x800, attributes, cid]);
    assert(opened_thread == Some(0) && thread_handle != 0 && wrong_process == Some(0xFFFF_FFFF_C000_000B), "ps: ZwOpenThread confere a thread contra o processo pedido");
    let next = call_export("ZwGetNextProcess", &[0, 0x1000, 0x200, 0, handle]);
    let first_process = guest::read64(handle);
    let bad_flags = call_export("ZwGetNextProcess", &[0, 0x1000, 0x200, 2, handle + 8]);
    assert(next == Some(0) && first_process != 0 && bad_flags == Some(0xFFFF_FFFF_C000_00F2), "ps: ZwGetNextProcess abre o primeiro processo e recusa Flags invalidos");
    let next_thread = call_export("ZwGetNextThread", &[process_handle, 0, 0x800, 0x200, 0, handle + 8]);
    let next_thread_handle = guest::read64(handle + 8);
    assert(next_thread == Some(0) && next_thread_handle != 0, "ps: ZwGetNextThread abre a primeira thread do processo");
    for opened_handle in [process_handle, thread_handle, first_process, next_thread_handle] {
        call_export("ZwClose", &[opened_handle]);
    }
}

/// Rotina nativa da DPC genérica: conta, sincroniza e avisa o fim.
fn generic_call_routine() -> u64 {
    extern "win64" fn routine(_dpc: u64, context: u64, done: u64, barrier: u64) {
        guest::write64(context, guest::read64(context) + 1);
        call_export("KeSignalCallDpcSynchronize", &[barrier]);
        call_export("KeSignalCallDpcDone", &[done]);
    }
    let pointer = routine as extern "win64" fn(u64, u64, u64, u64) as usize as u64;
    crate::ntos::mm::kernel_address::virtual_address(pointer).unwrap_or(pointer)
}

extern "win64" fn table_compare(_table: u64, first: u64, second: u64) -> u32 {
    let (left, right) = (guest::read32(first), guest::read32(second));
    if left < right { 0 } else if left > right { 1 } else { 2 }
}

extern "win64" fn table_allocate(_table: u64, size: u32) -> u64 {
    guest::alloc_bytes(size as u64)
}

extern "win64" fn table_free(_table: u64, buffer: u64) {
    guest::free_bytes(buffer);
}

/// Altura de uma subárvore AVL, conferindo |Balance| <= 1 e o campo Balance.
fn avl_height(node: u64) -> Option<i32> {
    if node == 0 {
        return Some(0);
    }
    let (left, right) = (avl_height(guest::read64(node + 8))?, avl_height(guest::read64(node + 0x10))?);
    let balance = guest::read8(node + 0x18) as i8 as i32;
    (balance == right - left && balance.abs() <= 1).then_some(1 + left.max(right))
}

/// RTL_GENERIC_TABLE (splay) e RTL_AVL_TABLE com rotinas nativas do chamador.
fn rtl_generic_tables(assert: Assert) {
    let native = |pointer: u64| crate::ntos::mm::kernel_address::virtual_address(pointer).unwrap_or(pointer);
    let compare = native(table_compare as extern "win64" fn(u64, u64, u64) -> u32 as usize as u64);
    let allocate = native(table_allocate as extern "win64" fn(u64, u32) -> u64 as usize as u64);
    let free = native(table_free as extern "win64" fn(u64, u64) as usize as u64);
    for avl in [false, true] {
        let suffix = if avl { "Avl" } else { "" };
        let export = |name: &str| alloc::format!("{name}{suffix}");
        let label = if avl { "avl" } else { "splay" };
        let table = guest::alloc_bytes(0x80);
        let (key, new_element, restart) = (guest::alloc_bytes(8), guest::alloc_bytes(8), guest::alloc_bytes(8));
        call_export(&export("RtlInitializeGenericTable"), &[table, compare, allocate, free, 0]);
        let keys: Vec<u32> = (0..50u32).map(|index| (index * 37) % 50).collect();
        let mut stored = Vec::new();
        let mut all_new = true;
        for &value in &keys {
            guest::write32(key, value);
            let pointer = call_export(&export("RtlInsertElementGenericTable"), &[table, key, 4, new_element]).unwrap_or(0);
            all_new &= pointer != 0 && guest::read8(new_element) == 1 && guest::read32(pointer) == value;
            stored.push((value, pointer));
        }
        guest::write32(key, 17);
        let again = call_export(&export("RtlInsertElementGenericTable"), &[table, key, 4, new_element]);
        let seventeen = stored.iter().find(|entry| entry.0 == 17).map(|entry| entry.1);
        assert(all_new && again == seventeen && guest::read8(new_element) == 0 && call_export(&export("RtlNumberGenericTableElements"), &[table]) == Some(50), &alloc::format!("rtl: {label}: insercao e duplicata"));
        let mut ordered = Vec::new();
        let mut element = call_export(&export("RtlEnumerateGenericTable"), &[table, 1]).unwrap_or(0);
        while element != 0 && ordered.len() < 60 {
            ordered.push(guest::read32(element));
            element = call_export(&export("RtlEnumerateGenericTable"), &[table, 0]).unwrap_or(0);
        }
        assert(ordered == (0..50).collect::<Vec<u32>>(), &alloc::format!("rtl: {label}: enumeracao em ordem"));
        guest::write32(key, 99);
        let missing = call_export(&export("RtlLookupElementGenericTable"), &[table, key]);
        guest::write32(key, 17);
        assert(call_export(&export("RtlLookupElementGenericTable"), &[table, key]) == seventeen && missing == Some(0), &alloc::format!("rtl: {label}: busca"));
        // AVL: o I-ésimo em ordem; splay: na ordem de inserção.
        let tenth = call_export(&export("RtlGetElementGenericTable"), &[table, 10]).map(|pointer| guest::read32(pointer));
        assert(tenth == Some(if avl { 10 } else { keys[10] }) && call_export(&export("RtlGetElementGenericTable"), &[table, 50]) == Some(0), &alloc::format!("rtl: {label}: elemento por indice"));
        let mut deleted = true;
        for value in (0..50u32).filter(|value| value % 2 == 0) {
            guest::write32(key, value);
            deleted &= call_export(&export("RtlDeleteElementGenericTable"), &[table, key]) == Some(1);
        }
        let survivors = stored.iter().filter(|entry| entry.0 % 2 == 1).all(|&(value, pointer)| {
            guest::write32(key, value);
            guest::read32(pointer) == value && call_export(&export("RtlLookupElementGenericTable"), &[table, key]) == Some(pointer)
        });
        guest::write64(restart, 0);
        let mut odd = Vec::new();
        let mut element = call_export(&export("RtlEnumerateGenericTableWithoutSplaying"), &[table, restart]).unwrap_or(0);
        while element != 0 && odd.len() < 60 {
            odd.push(guest::read32(element));
            element = call_export(&export("RtlEnumerateGenericTableWithoutSplaying"), &[table, restart]).unwrap_or(0);
        }
        assert(deleted && survivors && odd == (0..50).filter(|value| value % 2 == 1).collect::<Vec<u32>>() && call_export(&export("RtlNumberGenericTableElements"), &[table]) == Some(25), &alloc::format!("rtl: {label}: remocao preserva os outros elementos"));
        if avl {
            assert(avl_height(guest::read64(table + 0x10)).is_some(), "rtl: avl: arvore equilibrada depois de insercoes e remocoes");
        }
        for value in (0..50u32).filter(|value| value % 2 == 1) {
            guest::write32(key, value);
            call_export(&export("RtlDeleteElementGenericTable"), &[table, key]);
        }
        assert(call_export(&export("RtlIsGenericTableEmpty"), &[table]) == Some(1) && call_export(&export("RtlNumberGenericTableElements"), &[table]) == Some(0), &alloc::format!("rtl: {label}: tabela vazia no fim"));
    }
}

/// Sincronização de saída de processo e referências fortes de silo.
fn process_exit_synchronization(assert: Assert) {
    use crate::ntos::inc::nt_abi::eprocess;
    let processes = crate::ntos::ps::process::list_active_processes();
    let process = processes.first().map_or(0, |entry| entry.address);
    let acquired = call_export("PsAcquireProcessExitSynchronization", &[process]);
    let held = guest::read64(process + eprocess::RUNDOWN_PROTECT);
    call_export("PsReleaseProcessExitSynchronization", &[process]);
    assert(process != 0 && acquired == Some(0) && held >= 2 && guest::read64(process + eprocess::RUNDOWN_PROTECT) == held - 2, "ps: PsAcquire/ReleaseProcessExitSynchronization na RundownProtect");
    let host = call_export("PsAcquireSiloHardReference", &[0]);
    call_export("PsReleaseSiloHardReference", &[0]);
    let not_silo = call_export("PsAcquireSiloHardReference", &[process]);
    assert(host == Some(0) && not_silo == Some(0xFFFF_FFFF_C000_000D), "ps: referencia forte do silo host e recusa de ponteiro que nao e silo");
}

/// Zw*VirtualMemory de kernel no processo corrente e ZwAllocateLocallyUniqueId.
fn zw_virtual_memory(assert: Assert) {
    let current = u64::MAX;
    let block = guest::alloc_bytes(0x80);
    guest::write_bytes(block, &[0; 0x80]);
    let (base, size, old, info) = (block, block + 8, block + 0x10, block + 0x20);
    guest::write64(size, 0x3000);
    let allocated = call_export("ZwAllocateVirtualMemory", &[current, base, 0, size, 0x3000, 4]);
    let address = guest::read64(base);
    let usable = address != 0 && address < 0x8000_0000_0000 && guest::read64(size) == 0x3000 && guest::try_write64(address + 0x2FF8, 0x0123_4567_89AB_CDEF).is_ok() && guest::try_read64(address + 0x2FF8).is_ok_and(|value| value == 0x0123_4567_89AB_CDEF);
    assert(allocated == Some(0) && usable, "mm: ZwAllocateVirtualMemory reserva e comita paginas utilizaveis");
    let queried = call_export("ZwQueryVirtualMemory", &[current, address, 0, info, 48, 0]);
    assert(queried == Some(0) && guest::read64(info) == address && guest::read32(info + 0x20) == 0x1000 && guest::read32(info + 0x24) == 4, "mm: ZwQueryVirtualMemory ve a regiao comitada");
    guest::write64(base, address);
    guest::write64(size, 0x1000);
    let protected = call_export("ZwProtectVirtualMemory", &[current, base, size, 2, old]);
    assert(protected == Some(0) && guest::read32(old) == 4, "mm: ZwProtectVirtualMemory devolve a protecao anterior");
    guest::write64(base, address + 0x1000);
    guest::write64(size, 0x1000);
    let decommitted = call_export("ZwFreeVirtualMemory", &[current, base, size, 0x4000]);
    guest::write64(base, address);
    guest::write64(size, 0);
    let released = call_export("ZwFreeVirtualMemory", &[current, base, size, 0x8000]);
    let again = call_export("ZwFreeVirtualMemory", &[current, base, size, 0x8000]);
    assert(decommitted == Some(0) && released == Some(0) && guest::read64(size) == 0x3000 && again != Some(0), "mm: ZwFreeVirtualMemory com MEM_DECOMMIT e MEM_RELEASE");
    // Reserva sem commit e commit de uma subfaixa.
    guest::write64(base, 0);
    guest::write64(size, 0x10000);
    let reserved = call_export("ZwAllocateVirtualMemory", &[current, base, 0, size, 0x2000, 4]);
    let region = guest::read64(base);
    guest::write64(base, region + 0x4000);
    guest::write64(size, 0x1000);
    let committed = call_export("ZwAllocateVirtualMemory", &[current, base, 0, size, 0x1000, 4]);
    let written = guest::try_write32(region + 0x4000, 7).is_ok();
    guest::write64(base, region);
    guest::write64(size, 0);
    call_export("ZwFreeVirtualMemory", &[current, base, size, 0x8000]);
    assert(reserved == Some(0) && committed == Some(0) && written, "mm: reserva e commit de subfaixa");
    guest::write64(base, 0);
    guest::write64(size, 0x1000);
    let no_type = call_export("ZwAllocateVirtualMemory", &[current, base, 0, size, 0, 4]);
    let large = call_export("ZwAllocateVirtualMemory", &[current, base, 0, size, 0x2000_3000, 4]);
    assert(no_type == Some(0xFFFF_FFFF_C000_00F3) && large == Some(0xFFFF_FFFF_C000_0061), "mm: tipos de alocacao invalidos");
    let luid = guest::alloc_bytes(16);
    let first = call_export("ZwAllocateLocallyUniqueId", &[luid]).map(|_| guest::read64(luid));
    let second = call_export("ZwAllocateLocallyUniqueId", &[luid]).map(|_| guest::read64(luid));
    assert(first.is_some_and(|value| value != 0) && first != second, "se: ZwAllocateLocallyUniqueId nunca repete");
}

/// Acessores de ETHREAD/EPROCESS e os campos que a criação preenche.
fn thread_process_queries(assert: Assert) {
    use crate::ntos::inc::nt_abi::{eprocess, kthread};
    let thread = crate::ntos::ps::process::get_current_thread();
    let process = crate::ntos::ps::process::get_current_process();
    assert(call_export("PsGetCurrentThread", &[]) == Some(thread) && call_export("PsGetCurrentThreadProcess", &[]) == Some(guest::read64(thread + kthread::PROCESS)) && call_export("PsGetCurrentThreadProcessId", &[]) == Some(guest::read64(thread + kthread::CID_UNIQUE_PROCESS)), "ps: thread corrente, processo e PID");
    assert(call_export("PsIsThreadTerminating", &[thread]) == Some(0) && call_export("PsGetThreadCreateTime", &[thread]).is_some_and(|time| time != 0) && call_export("PsGetThreadTeb", &[thread]) == Some(guest::read64(thread + kthread::TEB)), "ps: thread viva com CreateTime e Teb do KTHREAD");
    let processes = crate::ntos::ps::process::list_active_processes();
    let system = processes.iter().find(|entry| entry.pid == 4).map_or(0, |entry| entry.address);
    let other = processes.iter().find(|entry| entry.pid != 4).map_or(0, |entry| entry.address);
    assert(system != 0 && call_export("PsIsSystemProcess", &[system]) == Some(1) && call_export("PsGetProcessSessionIdEx", &[system]) == Some(0xFFFF_FFFF) && call_export("PsGetProcessInheritedFromUniqueProcessId", &[system]) == Some(0), "ps: o System nao tem sessao nem criador");
    assert(other == 0 || (call_export("PsIsSystemProcess", &[other]) == Some(0) && call_export("PsGetProcessSequenceNumber", &[other]).is_some_and(|number| number > guest::read64(system + eprocess::SEQUENCE_NUMBER)) && call_export("PsGetProcessPriorityClass", &[other]) == Some(2)), "ps: numero de sequencia crescente e classe de prioridade normal");
    assert(call_export("PsIsProcessBeingDebugged", &[process]) == Some((guest::read64(process + eprocess::DEBUG_PORT) != 0) as u64), "ps: processo depurado segue a DebugPort");
}

/// ZwTraceControl: início, consulta, duplicata, parada e validações das
/// sessões de log.
fn etw_trace_control(assert: Assert) {
    let block = guest::alloc_bytes(0x200);
    guest::write_bytes(block, &[0; 0x200]);
    let (properties, returned, name) = (block, block + 0x180, block + 0x100);
    let text: Vec<u16> = "OpenNT-Teste".encode_utf16().collect();
    for (index, unit) in text.iter().enumerate() {
        guest::write16(name + index as u64 * 2, *unit);
    }
    let prepare = |flags: u32| {
        guest::write_bytes(properties, &[0; 0xB0]);
        guest::write32(properties, 0xB0);
        guest::write32(properties + 0x2C, flags);
        guest::write16(properties + 0x90, (text.len() * 2) as u16);
        guest::write16(properties + 0x92, (text.len() * 2) as u16);
        guest::write64(properties + 0x98, name);
    };
    let control = |code: u64| call_export("ZwTraceControl", &[code, properties, 0xB0, properties, 0xB0, returned]);
    prepare(0x2_0000);
    let started = control(1);
    let id = guest::read64(properties + 8) & 0xFFFF;
    assert(started == Some(0) && id != 0 && guest::read32(returned) == 0xB0 && guest::read32(properties + 0x30) == 64, "etw: ZwTraceControl inicia a sessao com LoggerId e buffers padrao");
    prepare(0x2_0000);
    let again = control(1);
    prepare(0x2_0000);
    let queried = control(3);
    assert(again == Some(0xFFFF_FFFF_C000_0035) && queried == Some(0) && guest::read64(properties + 8) & 0xFFFF == id, "etw: nome repetido recusado e consulta pelo nome");
    prepare(0x2_0000);
    let stopped = control(2);
    prepare(0x2_0000);
    let gone = control(3);
    assert(stopped == Some(0) && gone == Some(0xFFFF_FFFF_C000_0296), "etw: parada e sessao inexistente");
    // EtwEnableTrace numa sessão nova: habilita um GUID e recusa LoggerId inexistente.
    prepare(0x2_0000);
    let restarted = control(1);
    let logger_id = guest::read64(properties + 8) & 0xFFFF;
    let provider = block + 0x1C0;
    guest::write_bytes(provider, &[0x4F, 0x70, 0x65, 0x6E, 0x4E, 0x54, 0x2D, 0x45, 0x54, 0x57, 0x2D, 0x54, 0x65, 0x73, 0x74, 0x65]);
    let enabled = call_export("EtwEnableTrace", &[provider, 0, logger_id, 1, 4, u64::MAX, 0, 0]);
    let disabled = call_export("EtwEnableTrace", &[provider, 0, logger_id, 0, 0, 0, 0, 0]);
    let missing = call_export("EtwEnableTrace", &[provider, 0, 63, 1, 0, 0, 0, 0]);
    prepare(0x2_0000);
    control(2);
    assert(restarted == Some(0) && enabled == Some(0) && disabled == Some(0) && missing == Some(0xFFFF_FFFF_C000_0296), "etw: EtwEnableTrace habilita e desabilita o provedor na sessao");
    prepare(0);
    let no_flag = control(1);
    let small = call_export("ZwTraceControl", &[1, properties, 0x40, properties, 0x40, returned]);
    let max_loggers = call_export("ZwTraceControl", &[42, 0, 0, properties, 4, returned]);
    let invalid = call_export("ZwTraceControl", &[8, 0, 0, 0, 0, returned]);
    assert(no_flag == Some(0xFFFF_FFFF_C000_000D) && small == Some(0xFFFF_FFFF_C000_0206) && max_loggers == Some(0) && guest::read32(properties) == 64 && invalid == Some(0xFFFF_FFFF_C000_0010), "etw: validacoes e MaxLoggers");
}

pub fn run(assert: Assert) {
    pe_primitives(assert);
    pe_loader_kernel_images(assert);
    ntoskrnl_exports(assert);
    ntoskrnl_small_groups(assert);
    native_context_execution(assert);
    kernel_trap_dispatch(assert);
    user_device_io(assert);
    file_information_group(assert);
    ps_group(assert);
    resource_search_exports(assert);
    ntoskrnl_medium_groups(assert);
    ntoskrnl_security_groups(assert);
    ntoskrnl_small_modules(assert);
    ntoskrnl_priority_and_image(assert);
    ntoskrnl_thread_information(assert);
    ntoskrnl_ex_group(assert);
    ke_process_attachment(assert);
    ntoskrnl_ke_group(assert);
    ntoskrnl_mm_group(assert);
    ntoskrnl_driver_lifecycle(assert);
    system_information_leaves(assert);
    process_information_and_driver_services(assert);
    io_file_information(assert);
    volume_file_operations(assert);
    zw_kernel_files(assert);
    zw_query_file(assert);
    zw_read_file(assert);
    zw_write_file(assert);
    kernel_system_threads(assert);
    zw_group_exports(assert);
    pnp_and_boot_services(assert);
    io_group_exports(assert);
    ob_group_exports(assert);
    private_routines_and_small_groups(assert);
    device_control_and_delete_file(assert);
    tagged_token_convert_disk(assert);
    query_security_object(assert);
    persistent_thread_state_capture(assert);
    image_verification_callbacks(assert);
    rtl_unwind_dynamic_table(assert);
    kernel_seh_raise_and_unwind(assert);
    rtl_support_modules(assert);
    rtl_group_exports(assert);
    ntoskrnl_spin_lock_family(assert);
    ntoskrnl_affinity_and_processes(assert);
    rtl_generic_tables(assert);
    zw_virtual_memory(assert);
    process_exit_synchronization(assert);
    thread_process_queries(assert);
    etw_trace_control(assert);
    debug_print!("PHASE6_SELFTEST_OK");
}
