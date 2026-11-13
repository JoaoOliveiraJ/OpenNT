//! Self-test da fase 6 — loader PE e ntoskrnl.
//!
//! Exercita os primitivos PE (metadados, exports, encaminhamentos, API sets,
//! fontes de imagem) e, conforme entram, o loader, os exports do kernel e os
//! drivers nativos.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::inc::{types as nt, NtStruct};
use crate::ntos::mm::guest_memory as guest;


type Assert = fn(bool, &str);

const IMAGE_BASE: u64 = 0x1_4000_0000;

/// Estrutura do NT num endereço de convidado: bloco que o próprio teste
/// alocou com o tamanho do tipo ou objeto vivo devolvido pelo kernel.
fn at<T: NtStruct>(address: u64) -> &'static T {
    // SAFETY: os autotestes só convertem blocos alocados por eles com o
    // tamanho do tipo (zerados e alinhados) ou objetos vivos do kernel.
    unsafe { T::at(address) }
}

/// LUID de convidado como inteiro de 64 bits (LowPart | HighPart << 32).
fn luid_at(address: u64) -> u64 {
    let luid = at::<nt::Luid>(address);
    luid.low_part.get() as u64 | (luid.high_part.get() as u32 as u64) << 32
}

/// PFN `index` do vetor que segue o cabeçalho do MDL (MmGetMdlPfnArray).
fn mdl_pfn(mdl: u64, index: u64) -> u64 {
    at::<nt::Field<u64>>(mdl + nt::Mdl::SIZE + index * 8).get()
}

/// SubAuthority[index] do SID (o vetor do NT é ANYSIZE_ARRAY).
fn sub_authority(sid: u64, index: u64) -> &'static nt::Field<u32> {
    at::<nt::Field<u32>>(at::<nt::Sid>(sid).sub_authority[0].address() + index * 4)
}

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
    assert(abi_names::EXPORT_NAMES.len() == 1151 && abi_names::GROUP_LAYOUT.len() == 198 && abi_names::EXPORT_NAMES[0] == "DbgPrint" && abi_names::EXPORT_NAMES[546] == "READ_PORT_UCHAR" && abi_names::EXPORT_NAMES[773] == "ZwDisplayString" && abi_names::EXPORT_NAMES[781] == "KeAcquireQueuedSpinLock", "ntoskrnl: ordem da ABI com 1151 exports em 198 grupos");
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
    assert(count == win32_thunk::MAX_WIN32 && 32 + abi_names::EXPORT_NAMES.len() as u32 <= count && iat(0) == thunk(32 + 652) && iat(1) == thunk(32 + 546) && iat(0) != 0 && image.resolved_imports.len() == 5, "ntoskrnl: IAT recebe os trampolins dos ids");
    // Chamadas reais pelos trampolins (ABI MS x64 -> despachante Rust).
    let thread = guest::alloc_bytes(nt::Ethread::SIZE);
    at::<nt::Ethread>(thread).cid.unique_thread.set(0xFEDC_BA98_7654_3210);
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
    // Acessores de EPROCESS/ETHREAD sobre objetos sintéticos.
    let process = guest::alloc_bytes(nt::Eprocess::SIZE);
    let eprocess = at::<nt::Eprocess>(process);
    eprocess.peb.set(0x7FF6_1234_5000);
    eprocess.win32_process.set(0xFFFF_9000_0000_1230);
    eprocess.exit_status.set(0xC000_013Au32 as i32);
    eprocess.flags.set(1 << 2);
    assert(call_export("PsGetProcessPeb", &[process]) == Some(0x7FF6_1234_5000) && call_export("PsGetProcessWin32Process", &[process]) == Some(0xFFFF_9000_0000_1230), "ntoskrnl: PEB e Win32Process do EPROCESS");
    assert(call_export("PsGetProcessExitStatus", &[process]) == Some(0xC000_013A) && call_export("PsGetProcessExitProcessCalled", &[process]) == Some(1) && call_export("PsGetProcessImageFileName", &[process]) == Some(eprocess.image_file_name[0].address()), "ntoskrnl: saida e nome da imagem do EPROCESS");
    assert(call_export("PsGetProcessWow64Process", &[process]) == Some(0), "ntoskrnl: processo sem EWOW64PROCESS");
    let wow64 = guest::alloc_bytes(16);
    at::<nt::Ewow64process>(wow64).peb.set(0x7E_F000);
    eprocess.wo_w64_process.set(wow64);
    assert(call_export("PsGetProcessWow64Process", &[process]) == Some(0x7E_F000), "ntoskrnl: PEB do EWOW64PROCESS");
    let thread = guest::alloc_bytes(nt::Ethread::SIZE);
    let ethread = at::<nt::Ethread>(thread);
    ethread.tcb.process.set(process);
    ethread.cid.unique_process.set(0x1F4);
    ethread.exit_status.set(0x4000_0000);
    assert(call_export("PsGetThreadProcess", &[thread]) == Some(process) && call_export("PsGetThreadProcessId", &[thread]) == Some(0x1F4), "ntoskrnl: processo e PID da thread");
    assert(call_export("PsGetThreadExitStatus", &[thread]) == Some(0x103) && ethread.rundown_protect.count.get() == 0, "ntoskrnl: thread viva devolve STATUS_PENDING");
    ethread.rundown_protect.count.set(1);
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
    let driver_object = at::<nt::DriverObject>(driver);
    let base = driver_object.driver_start.get();
    for major in [0u64, 2, 7, 8, 13] {
        driver_object.major_function[major as usize].set(base + 0x1300);
    }
    let kernel = guest::alloc_bytes(0x1000);
    let name = unicode_at(kernel, "\\Device\\OpenNtFsInfo");
    let _ = call_export("IoCreateDevice", &[driver, 0, name, 0x22, 0, 0, kernel + 0x100]);
    let device = guest::read64(kernel + 0x100);
    let device_flags = &at::<nt::DeviceObject>(device).flags;
    device_flags.set(device_flags.get() & !0x80);
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
    let size_ok = size == Some(0) && at::<nt::LargeInteger>(output).quad_part.get() == 6 && volume_size == Some(0) && guest::read32(returned) == 24 && at::<nt::FileFsSizeInformation>(output + 0x20).bytes_per_sector.get() == 512;
    let data = call_export("FsRtlKernelFsControlFile", &[ntfs_file, dirty(0x90064), 0, dirty(0), kernel + 0x500, dirty(104), returned]);
    let data_ok = data == Some(0) && guest::read32(returned) == 104 && at::<nt::NtfsVolumeDataBuffer>(kernel + 0x500).bytes_per_sector.get() == 512;
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
    use crate::ntos::init::exports;
    use crate::ntos::mm::pe_loader::ResolvedImport;
    // Identidade do processo e da thread correntes.
    let system = process::get_system_process();
    let current = call_export("PsGetCurrentProcess", &[]);
    let ids = (call_export("PsGetCurrentProcessId", &[]), call_export("PsGetCurrentThreadId", &[]));
    assert(current == Some(process::get_current_process()) && ids == (Some(process::get_current_process_id()), Some(process::get_current_thread_id())), "ps: processo e thread correntes pelo KTHREAD");
    let system_process = at::<nt::Eprocess>(system);
    let pid = system_process.unique_process_id.get();
    let created = call_export("PsGetProcessCreateTimeQuadPart", &[system]);
    assert(call_export("PsGetProcessId", &[system]) == Some(pid) && created == Some(system_process.create_time.quad_part.get() as u64), "ps: PID e CreateTime da EPROCESS");
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
            guest::write_bytes(image, &[0u8; 0x4000]);
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
    let driver_object = at::<nt::DriverObject>(driver);
    let base = driver_object.driver_start.get();
    for major in [0u64, 2, 3, 4] {
        driver_object.major_function[major as usize].set(base + 0x1300);
    }
    let kernel = guest::alloc_bytes(0x200);
    let name = unicode_at(kernel, "\\Device\\OpenNtDevIo");
    let _ = call_export("IoCreateDevice", &[driver, 0, name, 0x22, 0, 0, kernel + 0x100]);
    let device = guest::read64(kernel + 0x100);
    let device_flags = &at::<nt::DeviceObject>(device).flags;
    device_flags.set((device_flags.get() | 4) & !0x80);
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
        guest::write_bytes(attributes, &[0u8; 0x30]);
    let object_attributes = at::<nt::ObjectAttributes>(attributes);
    object_attributes.length.set(48);
    object_attributes.object_name.set(path);
    let iosb = block + 0x300;
    let io_status = at::<nt::IoStatusBlock>(iosb);
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
    let read_ok = read == Some(0) && io_status.status.get() == 0 && io_status.information.get() == 4 && guest::read32(buffer) == 0x4443_4241 && guest::read32(buffer + 4) == 0;
    guest::write64(buffer, 0x1111_2222_3333_4444);
    let written = call("NtWriteFile", handle, 0, 0, 0);
    let write_ok = written == Some(0) && io_status.information.get() == 4 && guest::read64(buffer) == 0x1111_2222_3333_4444;
    assert(read_ok && write_ok, "devio: NtReadFile/NtWriteFile pelo IRP bufferizado nativo");
    // Sem DO_BUFFERED_IO o caminho não é suportado; cancelamentos sem pendência.
    device_flags.set(device_flags.get() & !4);
    let unbuffered = call("NtReadFile", handle, 0, 0, 0);
    device_flags.set(device_flags.get() | 4);
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
    let thread = guest::alloc_bytes(nt::Ethread::SIZE);
    at::<nt::Ethread>(thread).cid.unique_thread.set(0x8765_4321_0FED_CBA9);
    assert(native_call::call(through_thunk, &[thread]) == 0x8765_4321_0FED_CBA9, "ctxnativo: export chamado pelo IAT no caminho sincrono");
    assert(native_context::call(through_thunk, &[thread], 0).is_ok_and(|value| value == 0x8765_4321_0FED_CBA9), "ctxnativo: export chamado de dentro do contexto agendado (trap + despacho)");
    guest::free_bytes(thread);
    let _ = image.release();
    // Transferência: só o sinal da invocação ativa é reconhecido.
    let frame = guest::alloc_bytes(0x4E0);
    let desired = guest::alloc_bytes(0x4E0);
    let (frame_context, desired_context) = (at::<nt::Context>(frame), at::<nt::Context>(desired));
    desired_context.rip.set(0xFFFF_F800_1234_5678);
    desired_context.rsp.set(0xFFFF_F800_0000_8000);
    let transferred = native_context::invoke(frame, || -> Result<u64, crate::rtl::KernelError> {
        let signal = native_context::transfer(desired);
        let recognized = native_context::is_transfer(&signal);
        if !recognized {
            return Ok(99);
        }
        Err(signal)
    });
    assert(transferred.is_ok_and(|value| value == 0) && guest::read32(frame + native_context::ACTION) == 1 && frame_context.rip.get() == 0xFFFF_F800_1234_5678 && frame_context.rsp.get() == 0xFFFF_F800_0000_8000, "ctxnativo: transferencia copia o contexto, marca a acao e encerra a invocacao");
    assert(native_context::current().is_err() && !native_context::is_transfer(&native_context::transfer(desired)), "ctxnativo: sem invocacao ativa nao ha contexto nem sinal");
    let nested = native_context::invoke(frame, || native_context::invoke(desired, || Err::<u64, _>(native_context::transfer(frame))).map(|_| 7));
    assert(nested.is_ok_and(|value| value == 7), "ctxnativo: sinal capturado so pela invocacao que o emitiu");
    guest::free_bytes(desired);
    guest::free_bytes(frame);
}

fn ntoskrnl_medium_groups(assert: Assert) {
    use crate::ntos::mm::kernel_data;
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
    let process = guest::alloc_bytes(nt::Eprocess::SIZE);
    let eprocess = at::<nt::Eprocess>(process);
    eprocess.section_base_address.set(0x7FF7_0000_0000);
    eprocess.protection.level.set(0x31);
    eprocess.signature_level.set(0x0C);
    eprocess.section_signature_level.set(0x08);
    let level = guest::alloc_bytes(8);
    assert(call_export("PsGetProcessSectionBaseAddress", &[process]) == Some(0x7FF7_0000_0000) && call_export("PsGetProcessProtection", &[process]) == Some(0x31), "psquery: base da secao e PS_PROTECTION completo");
    assert(call_export("PsGetProcessSignatureLevel", &[process, level]) == Some(0x0C) && guest::read8(level) == 0x08 && call_export("PsGetProcessSignatureLevel", &[process, 0]) == Some(0x0C), "psquery: niveis de assinatura da imagem e da secao");
    assert(call_export("PsIsProtectedProcess", &[process]) == Some(1) && call_export("PsIsProtectedProcessLight", &[process]) == Some(1), "psquery: processo protegido leve");
    eprocess.protection.level.set(0x62);
    assert(call_export("PsIsProtectedProcess", &[process]) == Some(1) && call_export("PsIsProtectedProcessLight", &[process]) == Some(0), "psquery: protecao completa nao e leve");
    guest::free_bytes(level);
    guest::free_bytes(process);
    // hvi: CPUID real e push lock sem Secure Kernel.
    let present = crate::hal::cpu::cpuid(1)[2] >> 31;
    assert(call_export("HviIsAnyHypervisorPresent", &[]) == Some(present as u64) && call_export("SkIsSecureKernel", &[]) == Some(0xC000_0002) && call_export("VslExchangeEntropy", &[]) == Some(0xFFFF_FFFF_C000_00BB), "hvi: hypervisor pelo CPUID e Secure Kernel ausente");
    let lock = guest::alloc_bytes(16);
    let push_lock = at::<nt::ExPushLock>(lock);
    push_lock.value.set(0xFF);
    let features = guest::alloc_bytes(16);
    assert(call_export("SkInitializePushLock", &[lock]) == Some(0) && push_lock.value.get() == 0 && call_export("SkAcquirePushLockExclusive", &[lock]) == Some(0) && push_lock.value.get() == 1 && call_export("SkReleasePushLockExclusive", &[lock]) == Some(0) && push_lock.value.get() == 0, "hvi: push lock exclusivo do SkInitialize/Acquire/Release");
    assert(call_export("HviGetHypervisorFeatures", &[features]) == Some(0), "hvi: features da interface de hypervisor");
    guest::free_bytes(features);
    guest::free_bytes(lock);
    // A WppRecorder.sys e a wmilib.sys reais exportam os próprios nomes.
    assert(["WppAutoLogStart", "WppAutoLogTrace", "WppAutoLogStop", "imp_WppRecorderReplay", "WmiSystemControl", "WmiCompleteRequest"].iter().all(|name| exports::lookup("ntoskrnl.exe", name).is_none()), "wpp/wmilib: exports das bibliotecas reais fora do ntoskrnl");
    // dbgk: sem host do werkernel, a captura ao vivo falha com o status do stub.
    let component = guest::alloc_bytes(64);
    let capture = |name: u64| call_export("DbgkWerCaptureLiveKernelDump", &[name, 0x161, 1, 2, 3, 4, 0, 0, 0]);
    crate::ntos::rtl::guest_strings::write_wide_string(component, "OpenNtTeste");
    let unsupported = capture(component);
    crate::ntos::rtl::guest_strings::write_wide_string(component, "ComponenteLongoDemais");
    let too_long = capture(component);
    assert(unsupported == Some(0xFFFF_FFFF_C000_00BB) && too_long == Some(0xFFFF_FFFF_C000_000D) && capture(0) == Some(0xFFFF_FFFF_C000_000D), "dbgk: WerLiveKernelCreateReport ausente e nome do componente validado");
    let reports = crate::ntos::cm::registry::open_or_create("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\CrashControl\\FullLiveKernelReports", None).unwrap_or(0);
    crate::ntos::cm::registry::set_value(reports, "FullLiveReportsMax", 4, alloc::vec![0; 4]);
    let blocked = capture(component);
    crate::ntos::cm::registry::delete_key(reports);
    crate::ntos::cm::registry::close_handle(reports);
    assert(reports != 0 && blocked == Some(0xFFFF_FFFF_C000_0804), "dbgk: FullLiveReportsMax zero bloqueia a captura");
    guest::free_bytes(component);
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
    use crate::ntos::init::exports;
    use crate::ntos::se::{audit, subject_context};
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
    let first_guid = at::<nt::Guid>(first);
    assert(call_export("EtwActivityIdControl", &[3, first]) == Some(0) && (first_guid.data3.get() & 0xFF) >> 4 == 4 && first_guid.data4[0].get() >> 6 == 2, "etw: CREATE_ID gera uuid v4");
    assert(call_export("EtwActivityIdControl", &[2, first]) == Some(0) && call_export("EtwActivityIdControl", &[1, second]) == Some(0) && guest::read_bytes(first, 16) == guest::read_bytes(second, 16), "etw: SET_ID e GET_ID da atividade corrente");
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
    let subject = at::<nt::SecuritySubjectContext>(context);
    assert(call_export("SeCaptureSubjectContext", &[context]) == Some(0) && subject.primary_token.get() == primary && subject.process_audit_id.get() == process::get_current_process_id() && refs(primary) == before + 1, "se: SeCaptureSubjectContext retem o token primario");
    assert(call_export("SeReleaseSubjectContext", &[context]) == Some(0) && subject.primary_token.get() == 0 && refs(primary) == before, "se: SeReleaseSubjectContext devolve as referencias");
    let luid = guest::alloc_bytes(8);
    assert(call_export("SeQueryAuthenticationIdToken", &[primary, luid]) == Some(0) && Some(luid_at(luid)) == tokens::with(primary, |token| token.authentication_id) && call_export("SeQueryAuthenticationIdToken", &[0x1000, luid]) == Some(0xFFFF_FFFF_C000_0008), "se: AuthenticationId lido do token");
    assert(call_export("SeSinglePrivilegeCheck", &[luid, 0]) == Some(1) && call_export("SeSinglePrivilegeCheck", &[luid, 1]) == Some(0), "se: privilegio no modo kernel");
    call_export("SeLockSubjectContext", &[context]);
    call_export("SeLockSubjectContext", &[context]);
    call_export("SeUnlockSubjectContext", &[context]);
    let still_locked = subject_context::is_locked();
    call_export("SeUnlockSubjectContext", &[context]);
    assert(still_locked && !subject_context::is_locked(), "se: bloqueio aninhado do subject context");
    assert(call_export("SeAuditFipsCryptoSelftests", &[1, 2, 0x30]) == Some(0) && audit::events().last().is_some_and(|event| event.kind == "FipsCryptoSelftest" && event.detail == "general=1 causing=2 extra=0x30"), "se: auditoria gravada no anel");
    guest::free_bytes(luid);
    guest::free_bytes(context);
}

fn ntoskrnl_small_modules(assert: Assert) {
    use crate::ntos::mm::{kernel_pool, paging, physical_layout};
    use crate::ntos::ob::get_object_type;
    // MmSizeOfMdl: cabeçalho de 48 bytes e um PFN por página, somas de 64 bits.
    assert(call_export("MmSizeOfMdl", &[0x1234, 0x2000]) == Some(0x48) && call_export("MmSizeOfMdl", &[0, 0]) == Some(0x30) && call_export("MmSizeOfMdl", &[0x1, u64::MAX]) == Some(0x30 + ((u64::MAX).wrapping_add(0x1000) >> 12) * 8), "mdlsize: paginas abrangidas e transbordamento de 64 bits");
    // MmIsAddressValid: só mapeamentos residentes e endereços canônicos.
    let buffer = guest::alloc_bytes(64);
    let slist = at::<nt::SlistHeader>(buffer);
    assert(call_export("MmIsAddressValid", &[buffer]) == Some(1) && call_export("MmIsAddressValid", &[0x0000_8000_0000_0000]) == Some(0), "addrvalid: endereco residente e nao canonico");
    // FirstEntrySList: segunda palavra do cabeçalho sem os bits de marcação.
    slist.region.set(0x1234_5678_9ABC_DEF7);
    assert(call_export("FirstEntrySList", &[buffer]) == Some(0x1234_5678_9ABC_DEF0) && slist.region.get() == 0x1234_5678_9ABC_DEF7, "firstslist: primeiro elemento sem alterar o cabecalho");
    guest::free_bytes(buffer);
    // PsGetProcessDebugPort e ObGetObjectType.
    let process = guest::alloc_bytes(nt::Eprocess::SIZE);
    at::<nt::Eprocess>(process).debug_port.set(0xFFFF_9100_0000_0040);
    assert(call_export("PsGetProcessDebugPort", &[process]) == Some(0xFFFF_9100_0000_0040), "debugport: campo DebugPort do EPROCESS");
    guest::free_bytes(process);
    let current = crate::ntos::ps::process::get_current_process();
    let process_type = get_object_type::get(current).unwrap_or(0);
    assert(process_type != 0 && call_export("ObGetObjectType", &[current]) == Some(process_type) && get_object_type::get(0x1234).is_err(), "objtype: tipo pelo dono registrado e ponteiro desconhecido recusado");
    // MmGetPhysicalMemoryRanges: vetor do layout terminado por zeros.
    let ranges = physical_layout::ranges();
    let vector = call_export("MmGetPhysicalMemoryRanges", &[]).unwrap_or(0);
    let terminator = vector + ranges.len() as u64 * 16;
    assert(vector != 0 && !ranges.is_empty() && at::<nt::PhysicalMemoryRange>(vector).base_address.quad_part.get() as u64 == ranges[0].0 && at::<nt::PhysicalMemoryRange>(vector).number_of_bytes.quad_part.get() as u64 == ranges[0].1 - ranges[0].0 && at::<nt::PhysicalMemoryRange>(terminator).base_address.quad_part.get() == 0 && at::<nt::PhysicalMemoryRange>(terminator).number_of_bytes.quad_part.get() == 0, "physranges: faixas fisicas com terminador");
    if vector != 0 {
        let _ = kernel_pool::free(vector, None);
    }
    // KeTestAlertThread: consome o alerta do modo kernel da thread corrente.
    let region = crate::ntos::ke::pcr::get_pcr_address();
    let thread = at::<nt::Kpcr>(region).prcb.current_thread.get();
    let kthread = at::<nt::Kthread>(thread);
    let saved = kthread.alerted[0].get();
    kthread.alerted[0].set(1);
    assert(call_export("KeTestAlertThread", &[0]) == Some(1) && kthread.alerted[0].get() == 0 && call_export("KeTestAlertThread", &[0]) == Some(0), "testalert: alerta do modo kernel consumido");
    kthread.alerted[0].set(saved);
    // MmProtectMdlSystemAddress sobre um mapeamento supervisor 4K real.
    let mdl = guest::alloc_bytes(0x40);
    let mdl_header = at::<nt::Mdl>(mdl);
    assert(call_export("MmProtectMdlSystemAddress", &[mdl, 2]) == Some(0xC000_0019), "protectmdl: MDL sem mapeamento de sistema");
    let va = 0xFFFF_F800_0300_0000u64;
    let backing = guest::alloc_page();
    let mapped = paging::map_page(va, backing, paging::PAGE_PRESENT | paging::PAGE_RW, paging::MapOptions::default());
    mdl_header.mdl_flags.set(1);
    mdl_header.mapped_system_va.set(va + 0x10);
    mdl_header.byte_count.set(0x100);
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
    // KeSetPriorityThread/KeSetBasePriorityThread sobre um KTHREAD fora das filas.
    let process = guest::alloc_bytes(nt::Eprocess::SIZE);
    let thread = guest::alloc_bytes(nt::Ethread::SIZE);
    let (eprocess, kthread) = (at::<nt::Eprocess>(process), at::<nt::Kthread>(thread));
    eprocess.pcb.base_priority.set(8);
    kthread.process.set(process);
    kthread.priority.set(8);
    kthread.base_priority.set(8);
    kthread.quantum_reset.set(6);
    assert(call_export("KeSetPriorityThread", &[thread, 12]) == Some(8) && kthread.priority.get() == 12 && kthread.quantum_target.get() != 0, "prioridade: KeSetPriorityThread devolve a anterior e renova o quantum");
    kthread.priority_floor_summary.set(1 << 13);
    assert(call_export("KeSetPriorityThread", &[thread, 10]) == Some(12) && kthread.priority.get() == 13, "prioridade: o piso ativo eleva a prioridade efetiva");
    kthread.priority_floor_summary.set(0);
    assert(call_export("KeSetPriorityThread", &[thread, 0]) == Some(13) && kthread.priority.get() == 1, "prioridade: zero com base nao nula vira 1");
    kthread.priority.set(8);
    assert(call_export("KeSetBasePriorityThread", &[thread, 2]) == Some(0) && kthread.base_priority.get() == 10 && kthread.priority.get() == 10, "prioridade: incremento de base relativo ao processo");
    assert(call_export("KeSetBasePriorityThread", &[thread, 16]) == Some(2) && kthread.saturation.get() == 1 && kthread.base_priority.get() == 15 && kthread.priority.get() == 15, "prioridade: incremento saturado leva a base ao teto");
    assert(call_export("KeSetBasePriorityThread", &[thread, 0]) == Some(16) && kthread.saturation.get() == 0, "prioridade: incremento anterior saturado vale 16");
    guest::free_bytes(thread);
    // PsReferenceProcessFilePointer e SeLocateProcessImageName.
    let output = guest::alloc_bytes(8);
    assert(call_export("PsReferenceProcessFilePointer", &[process, output]) == Some(0xFFFF_FFFF_C000_0001) && call_export("SeLocateProcessImageName", &[process, output]) == Some(0xFFFF_FFFF_C000_0225), "psimage: processo sem secao nem nome de auditoria");
    fn destroy_section(_: u64) -> Result<(), crate::rtl::KernelError> {
        Ok(())
    }
    let section = section_objects::register(SectionState { size: 0x1000, ..Default::default() }, destroy_section).unwrap_or(0);
    eprocess.section_object.set(section);
    guest::write64(output, 0xFFFF);
    assert(section != 0 && call_export("PsReferenceProcessFilePointer", &[process, output]) == Some(0) && guest::read64(output) == 0, "psimage: secao sem FILE_OBJECT de imagem");
    eprocess.rundown_protect.count.set(1);
    assert(call_export("PsReferenceProcessFilePointer", &[process, output]) == Some(0xFFFF_FFFF_C000_0001), "psimage: processo em rundown");
    let name: alloc::vec::Vec<u16> = "\\Device\\HarddiskVolume1\\teste.exe".encode_utf16().collect();
    let cache = guest::alloc_bytes(16 + name.len() as u64 * 2 + 2);
    let name_info = at::<nt::ObjectNameInformation>(cache);
    name_info.name.length.set(name.len() as u16 * 2);
    name_info.name.maximum_length.set(name.len() as u16 * 2 + 2);
    name_info.name.buffer.set(cache + 16);
        guest::write_bytes(cache + 16, &name.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    eprocess.se_audit_process_creation_info.image_file_name.set(cache);
    let located = call_export("SeLocateProcessImageName", &[process, output]);
    let copy = guest::read64(output);
    assert(located == Some(0) && copy != 0 && copy != cache && at::<nt::ObjectNameInformation>(copy).name.length.get() == name.len() as u16 * 2 && at::<nt::ObjectNameInformation>(copy).name.buffer.get() == copy + 16 && crate::ntos::rtl::guest_strings::read_unicode_string(copy) == "\\Device\\HarddiskVolume1\\teste.exe", "psimage: copia do nome de auditoria em pool");
    let _ = data_pool::free(copy);
    let _ = section_objects::collect(section);
    guest::free_bytes(cache);
    guest::free_bytes(output);
    guest::free_bytes(process);
}

fn ntoskrnl_thread_information(assert: Assert) {
    use crate::ntos::ps::process;
    // Claims de pacote: o token do sistema não tem SYSAPPID.
    let primary = process::get_primary_token(process::get_current_process()).unwrap_or(0);
    let claim = guest::alloc_bytes(16);
    assert(call_export("RtlQueryPackageClaims", &[primary, 0, 0, 0, 0, 0, claim, claim + 8]) == Some(0xC000_0225) && call_export("RtlQueryPackageIdentity", &[primary, 0, 0, 0, 0, claim]) == Some(0xC000_0225), "pacote: token sem identidade de pacote");
    guest::free_bytes(claim);
    // ThreadPagePriority da thread corrente (-2) por Zw e Nt.
    let thread = process::get_current_thread();
    let ethread = at::<nt::Ethread>(thread);
    let saved = ethread.cross_thread_flags.get();
    let buffer = guest::alloc_bytes(16);
    let current_handle = (-2i64) as u64;
    assert(call_export("ZwQueryInformationThread", &[current_handle, 24, buffer, 4, buffer + 8]) == Some(0) && guest::read32(buffer) == (saved >> 12) & 7 && guest::read32(buffer + 8) == 4, "threadinfo: ZwQueryInformationThread le ThreadPagePriority");
    assert(call_export("ZwQueryInformationThread", &[current_handle, 2, buffer, 4, 0]) == Some(0xC000_0003) && call_export("ZwQueryInformationThread", &[current_handle, 0, buffer, 4, 0]) == Some(0xC000_0002) && call_export("ZwQueryInformationThread", &[current_handle, 24, buffer, 8, 0]) == Some(0xC000_0004), "threadinfo: classe rejeitada, sem provedor e tamanho errado");
    guest::write32(buffer, 3);
    assert(call_export("ZwSetInformationThread", &[current_handle, 24, buffer, 4]) == Some(0) && (ethread.cross_thread_flags.get() >> 12) & 7 == 3 && ethread.cross_thread_flags.get() & !0x7000 == saved & !0x7000, "threadinfo: ZwSetInformationThread troca so os tres bits");
    guest::write32(buffer + 4, 0xFFFF);
    assert(call_export("NtQueryInformationThread", &[current_handle, 24, buffer + 4, 4, 0]) == Some(0) && guest::read32(buffer + 4) == 3, "threadinfo: NtQueryInformationThread em modo kernel");
    guest::write32(buffer, 0);
    assert(call_export("NtSetInformationThread", &[current_handle, 24, buffer, 4]) == Some(0xC000_000D) && call_export("ZwSetInformationThread", &[current_handle, 0, buffer, 4]) == Some(0xC000_0003), "threadinfo: prioridade invalida e classe rejeitada");
    ethread.set_thread_page_priority((saved >> 12) & 7);
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
    let fast_mutex = at::<nt::FastMutex>(mutex);
    assert(call_export("ExInitializeFastMutex", &[mutex]) == Some(0) && fast_mutex.count.get() == 1, "ex: ExInitializeFastMutex disponivel");
    let entry_irql = irql::get_irql();
    call_export("ExAcquireFastMutex", &[mutex]);
    let held = fast_mutex.count.get() == 0 && fast_mutex.owner.get() == process::get_current_thread() && irql::get_irql() == 1;
    call_export("ExReleaseFastMutex", &[mutex]);
    assert(held && fast_mutex.count.get() == 1 && fast_mutex.owner.get() == 0 && irql::get_irql() == entry_irql, "ex: fast mutex adquirido em APC_LEVEL e liberado");
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
    let push_lock = at::<nt::ExPushLock>(push);
    assert(call_export("ExInitializePushLock", &[push]) == Some(0) && call_export("ExAcquirePushLockExclusiveEx", &[push, 0]) == Some(0) && push_lock.locked() == 1 && call_export("ExReleasePushLockExclusiveEx", &[push, 0]) == Some(0) && push_lock.value.get() == 0, "ex: push lock exclusivo");
    let spin = block + 0x198;
    let old = call_export("ExAcquireSpinLockExclusive", &[spin]).unwrap_or(0xFF);
    let at_dispatch = irql::get_irql() == 2;
    call_export("ExReleaseSpinLockExclusive", &[spin, old]);
    assert(old == entry_irql as u64 && at_dispatch && irql::get_irql() == entry_irql, "ex: spin lock executivo em DISPATCH_LEVEL");
    // UUID, extensões, hora local e Error Management.
    let uuid = block + 0x1A0;
    let uuid_guid = at::<nt::Guid>(uuid);
    // UUID v4: versão nos 4 bits altos do Data3 (byte 7) e variante 10b no Data4[0].
    assert(call_export("ExUuidCreate", &[uuid]) == Some(0) && uuid_guid.data3.get() >> 12 == 4 && uuid_guid.data4[0].get() >> 6 == 2, "ex: ExUuidCreate versao 4");
    let output = block + 0x1B0;
    assert(call_export("ExRegisterExtension", &[output, 1, 0xFFFF_F800_DEAD_0000]) == Some(0) && guest::read16(guest::read64(output)) == 1 && guest::read64(guest::read64(output) + 8) == 0xFFFF_F800_DEAD_0000, "ex: ExRegisterExtension");
    at::<nt::LargeInteger>(block + 0x1B8).quad_part.set(0x01DA_0000_1234_5678);
    assert(call_export("ExSystemTimeToLocalTime", &[block + 0x1B8, block + 0x1C0]) == Some(0) && at::<nt::LargeInteger>(block + 0x1C0).quad_part.get() == 0x01DA_0000_1234_5678 && call_export("EmClientQueryRuleState", &[0, 0]) == Some(0xFFFF_FFFF_C000_0225), "ex: hora local sem fuso e regra inexistente");
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
    // Processo gerenciado de destino na PML4 compartilhada.
    let Ok(target) = process::create_process(0x7D10, "phase6-attach.exe", 0, None) else {
        assert(false, "attach: processo de destino criado");
        return;
    };
    let thread = process::get_current_thread();
    let (kthread, kprocess) = (at::<nt::Kthread>(thread), at::<nt::Kprocess>(target));
    let original = kthread.apc_state.process.get();
    let stack_count = kprocess.stack_count.value.get();
    let state = guest::alloc_bytes(0x30);
    let attached = process_attachment::attach(target, state);
    let during = (kthread.apc_state.process.get(), kthread.apc_state_index.get(), kprocess.stack_count.value.get(), kprocess.active_processors.bitmap[0].get() != 0);
    assert(attached.is_ok() && during.0 == target && during.1 == 1 && during.2 == stack_count + 8 && during.3, "attach: KeStackAttachProcess troca o ApcState e publica a CPU no destino");
    let detached = process_attachment::detach(state);
    assert(detached.is_ok() && kthread.apc_state.process.get() == original && kthread.apc_state_index.get() == 0 && kprocess.stack_count.value.get() == stack_count, "attach: KeUnstackDetachProcess restaura o processo e a contagem de pilhas");
    // Anexar ao processo corrente só grava o marcador.
    assert(process_attachment::attach(original, state).is_ok() && at::<nt::KapcState>(state).process.get() == 1 && process_attachment::detach(state).is_ok(), "attach: processo corrente usa o marcador 1");
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
    let queued = at::<nt::KlockQueueHandle>(handle).lock_queue.lock.get() == lock && guest::read32(lock) == 1;
    call_export("KeReleaseInStackQueuedSpinLock", &[handle]);
    assert(queued && guest::read32(lock) == 0 && irql::get_irql() == entry, "ke: in-stack queued spin lock");
    // Eventos e esperas com timeout zero.
    let event = block + 0x80;
    let zero_timeout = block + 0x60;
    at::<nt::LargeInteger>(zero_timeout).quad_part.set(0);
    call_export("KeInitializeEvent", &[event, 0, 0]);
    assert(call_export("KeReadStateEvent", &[event]) == Some(0) && call_export("KeWaitForSingleObject", &[event, 0, 0, 0, zero_timeout]) == Some(0x102), "ke: evento nao sinalizado expira com timeout zero");
    assert(call_export("KeSetEvent", &[event, 0, 0]) == Some(0) && call_export("KeWaitForSingleObject", &[event, 0, 0, 0, zero_timeout]) == Some(0) && call_export("KeResetEvent", &[event]) == Some(1) && call_export("KeReadStateEvent", &[event]) == Some(0), "ke: KeSetEvent, espera satisfeita e KeResetEvent");
    // Semáforo, timer e consultas.
    let semaphore = block + 0xA0;
    call_export("KeInitializeSemaphore", &[semaphore, 1, 3]);
    assert(call_export("KeReleaseSemaphore", &[semaphore, 0, 2, 0]) == Some(1) && call_export("KeReleaseSemaphore", &[semaphore, 0, 5, 0]) == Some(3) && at::<nt::Ksemaphore>(semaphore).header.signal_state.get() == 3, "ke: semaforo limitado");
    let timer = block + 0xC0;
    call_export("KeInitializeTimer", &[timer]);
    assert(call_export("KeReadStateTimer", &[timer]) == Some(0) && call_export("KeSetTimer", &[timer, (-10_000_000i64) as u64, 0]) == Some(0) && call_export("KeCancelTimer", &[timer]) == Some(1), "ke: timer agendado e cancelado");
    assert(call_export("PsGetVersion", &[block + 0x100, block + 0x104, block + 0x108, 0]) == Some(1) && guest::read32(block + 0x100) == 10 && guest::read32(block + 0x108) == 26100 && call_export("KeQueryTimeIncrement", &[]) == Some(100_000), "ke: PsGetVersion e KeQueryTimeIncrement");
    assert(call_export("KeQueryActiveProcessorCount", &[]) == Some(smp::online_cpu_count() as u64) && call_export("KeGetProcessorNumberFromIndex", &[999, block + 0x110]) == Some(0xFFFF_FFFF_C000_000D), "ke: processadores ativos");
    assert(call_export("KeQueryPerformanceCounter", &[block + 0x118]).is_some_and(|counter| counter != 0) && at::<nt::LargeInteger>(block + 0x118).quad_part.get() as u64 == clock::tsc_frequency_hz() && call_export("KeStallExecutionProcessor", &[10]) == Some(0), "ke: contador de desempenho e espera ocupada");
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
    let kdpc = at::<nt::Kdpc>(dpc);
    assert(kdpc.importance.get() == 2 && kdpc.number.get() == 1 && call_export("KeRemoveQueueDpc", &[dpc]) == Some(0), "ke: KDPC importancia, processador alvo e remocao");
    let mutex = block + 0x200;
    call_export("KeInitializeGuardedMutex", &[mutex]);
    assert(call_export("KeTryToAcquireGuardedMutex", &[mutex]) == Some(1) && call_export("KeReleaseGuardedMutex", &[mutex]) == Some(0) && at::<nt::FastMutex>(mutex).count.get() == 1, "ke: guarded mutex");
    // O XSTATE_SAVE é do chamador: o kernel preenche o XSTATE_CONTEXT.
    let state = block + 0x240;
    let saved = call_export("KeSaveExtendedProcessorState", &[3, state]);
    let context = &at::<nt::XstateSave>(state).x_state_context;
    let area_saved = context.mask.get() == 3 && context.area.get() != 0;
    assert(saved == Some(0) && area_saved && call_export("KeRestoreExtendedProcessorState", &[state]) == Some(0) && context.area.get() == 0 && call_export("KeRestoreExtendedProcessorState", &[0]) == Some(0xFFFF_FFFF_C000_000D), "ke: estado estendido salvo e restaurado");
    assert(call_export("KeDeregisterBugCheckCallback", &[0x1234]) == Some(0), "ke: registro de bugcheck desconhecido");
    // Dados KiBugCheckData/KeNumberProcessors e anexação pelo export.
    let data = |name: &str| match exports::lookup("ntoskrnl.exe", name) {
        Some(ResolvedImport::Address { address, .. }) => address,
        _ => 0,
    };
    assert(data("KiBugCheckData") != 0 && guest::read32(data("KeNumberProcessors")) == smp::online_cpu_count() as u32, "ke: dados KiBugCheckData e KeNumberProcessors");
    if let Ok(target) = process::create_process(0x7D20, "phase6-ke.exe", 0, None) {
        let apc_state = block + 0x300;
        let attached = call_export("KeStackAttachProcess", &[target, apc_state]) == Some(0) && at::<nt::Kthread>(process::get_current_thread()).apc_state.process.get() == target;
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
    assert(exports::implemented() == 1151 && exports::export_names().len() == 1151, "ntoskrnl: 198 grupos com os 1151 exports implementados");
    let block = guest::alloc_bytes(0x200);
    // MmGetSystemRoutineAddress: trampolim chamável e nome desconhecido.
    let name: alloc::vec::Vec<u16> = "KeGetCurrentIrql".encode_utf16().collect();
    let text = block + 0x40;
        guest::write_bytes(text, &name.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    let routine_name = at::<nt::UnicodeString>(block);
    routine_name.length.set(name.len() as u16 * 2);
    routine_name.maximum_length.set(name.len() as u16 * 2);
    routine_name.buffer.set(text);
    let routine = call_export("MmGetSystemRoutineAddress", &[block]).unwrap_or(0);
    assert(routine != 0 && native_call::call(routine, &[]) == crate::ntos::ke::irql::get_irql() as u64, "mm: MmGetSystemRoutineAddress devolve o trampolim chamavel");
    routine_name.length.set(4);
    guest::write16(text, b'Z' as u16);
    assert(call_export("MmGetSystemRoutineAddress", &[block]) == Some(0), "mm: rotina desconhecida devolve NULL");
    // MDL de pool não paginado: PFNs reais, flags e mapeamento identidade.
    let buffer = guest::alloc_aligned(0x2000, 0x1000, true);
    let descriptor = guest::alloc_bytes(0x40);
    let mdl_header = at::<nt::Mdl>(descriptor);
    mdl_header.start_va.set(buffer);
    mdl_header.byte_offset.set(0x10);
    mdl_header.byte_count.set(0x1800);
    assert(call_export("MmBuildMdlForNonPagedPool", &[descriptor]) == Some(0) && mdl_pfn(descriptor, 0) == paging::translate(buffer) >> 12 && mdl_pfn(descriptor, 1) == paging::translate(buffer + 0x1000) >> 12 && mdl_header.mdl_flags.get() & 6 == 6, "mm: MmBuildMdlForNonPagedPool com PFNs reais");
    assert(call_export("MmMapLockedPagesSpecifyCache", &[descriptor, 0, 1, 0, 0, 16]) == Some(buffer + 0x10) && mdl_header.mdl_flags.get() & 1 == 1 && call_export("MmUnmapLockedPages", &[buffer + 0x10, descriptor]) == Some(0) && mdl_header.mdl_flags.get() & 1 == 0, "mm: mapeamento do MDL marcado e desfeito");
    assert(call_export("MmGetPhysicalAddress", &[buffer]) == Some(paging::translate(buffer)) && call_export("MmMapLockedPagesWithReservedMapping", &[buffer, 0, descriptor, 1]) == Some(0), "mm: endereco fisico e VA nao reservada recusada");
    let pages = call_export("MmAllocatePagesForMdl", &[0, u64::MAX, 0, 0x2000]).unwrap_or(0);
    assert(pages != 0 && at::<nt::Mdl>(pages).size.get() == 0x40 && mdl_pfn(pages, 0) != 0 && mdl_pfn(pages, 1) != 0 && call_export("MmFreePagesFromMdl", &[pages]) == Some(0), "mm: MmAllocatePagesForMdl com frames reais");
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
    let original_exports = physical::read_bytes(paging::translate(base + 0x2000), 16);
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
    // Leitura confiável da .edata despejada: um MOV direto na VA; a falta de
    // página do anel 0 passa pelos provedores de residência e repete o acesso.
    let faults_before = image_paging::state(base).map_or(0, |state| state.faults);
    let absent = paging::translate(base + 0x2000) == 0;
    let paged_in = guest::read64(base + 0x2000).to_le_bytes();
    assert(absent && paged_in[..] == original_exports[..8] && image_paging::state(base).is_some_and(|state| state.faults == faults_before + 1), "imgpaging: leitura confiavel de pagina despejada entra pela falta do anel 0");
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
    let base = if driver != 0 { at::<nt::DriverObject>(driver).driver_start.get() } else { 0 };
    assert(loaded.as_ref().is_ok_and(|&value| value) && driver != 0 && at::<nt::DriverObject>(driver).type_.get() == 4 && base != 0, "lifecycle: DriverEntry executado e \\Driver publicado com o DRIVER_OBJECT");
    assert(at::<nt::DriverObject>(driver).driver_unload.get() == base + 0x1320 && guest_strings_read(at::<nt::DriverObject>(driver).driver_name.address()) == "opennt-lc-a" && lifecycle::get_driver_export("opennt-lc-a", "Alpha") == base + 0x1010, "lifecycle: DriverUnload registrado, DriverName e export do driver");
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
    let boot_information = at::<nt::SystemBootEnvironmentInformation>(buffer);
    guest::write_bytes(buffer, &[0xAA; 40]);
    assert(boot_environment_information::query(buffer, 32, length, false).is_ok_and(|status| status == 0) && guest::read32(length) == 32 && guest::read_bytes(boot_information.boot_identifier.address(), 8) == bytes[..8] && guest::read32(buffer + 20) == 0xAAAA_AAAA && boot_information.boot_flags.get() == u64::from_le_bytes(bytes[24..32].try_into().unwrap()), "bootenvinfo: 32 bytes preservando o padding do chamador");
    guest::write_bytes(buffer, &[0xAA; 40]);
    assert(boot_environment_information::query(buffer, 24, length, false).is_ok_and(|status| status == 0) && guest::read32(length) == 20 && boot_information.boot_flags.get() == 0xAAAA_AAAA_AAAA_AAAA, "bootenvinfo: formato antigo de 20 bytes");
    assert(boot_environment_information::query(buffer, 10, length, false).is_ok_and(|status| status == 0xC000_0004) && guest::read32(length) == 32, "bootenvinfo: buffer curto informa 32 bytes");
    // Integridade de código antes da CI: opções zeradas.
    let code_integrity = at::<nt::SystemCodeintegrityInformation>(buffer);
    code_integrity.length.set(8);
    code_integrity.code_integrity_options.set(0xFFFF);
    assert(code_integrity_information::query(buffer, 8, length, false).is_ok_and(|status| status == 0) && code_integrity.code_integrity_options.get() == 0 && guest::read32(length) == 8, "ciinfo: CodeIntegrityOptions zerado antes da CI");
    code_integrity.length.set(4);
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
        let record = at::<nt::SystemProcessInformation>(cursor);
        let name = record.image_name.buffer.get();
        names_inside &= name >= buffer && name < buffer + needed;
        let next = record.next_entry_offset.get() as u64;
        if next == 0 || count > 64 {
            break;
        }
        cursor += next;
    }
    assert(queried.is_ok_and(|status| status == 0) && count == processes.len() && names_inside && at::<nt::SystemProcessInformation>(buffer).unique_process_id.get() == processes[0].pid && at::<nt::SystemProcessInformation>(buffer).number_of_threads.get() as usize == processes[0].threads.len(), "spi: um registro por processo ativo com nome no buffer do chamador");
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
    let (file_object, lower_device, upper_device) = (at::<nt::FileObject>(file), at::<nt::DeviceObject>(lower), at::<nt::DeviceObject>(upper));
    // FILE_OBJECT sem VPB, no dispositivo de baixo (sem desvio de volume).
    file_object.device_object.set(lower);
    file_object.flags.set(0x800);
    lower_device.attached_device.set(upper);
    assert(file_information::related_device(file).is_ok_and(|device| device == upper), "fileinfo: IoGetRelatedDeviceObject sobe ate o topo da pilha");
    // Extensão de arquivo com filtro que fixa o dispositivo abaixo do topo.
    file_object.file_object_extension.set(extension);
    at::<nt::IopFileObjectExtension>(extension).fo_ext_per_type_extension[1].set(filter);
    // Registro de extensão por tipo [1]: o primeiro qword é o dispositivo indicado.
    guest::write64(filter, lower);
    assert(file_information::related_device(file).is_ok_and(|device| device == lower), "fileinfo: filtro da extensao seleciona o dispositivo indicado");
    file_object.file_object_extension.set(0);
    upper_device.attached_device.set(lower);
    assert(file_information::related_device(file).is_err(), "fileinfo: anexacao ciclica recusada");
    upper_device.attached_device.set(0);
    file_object.device_object.set(0);
    assert(file_information::related_device(file).is_ok_and(|device| device == 0) && file_information::query_native(file, 5, 24, block + 0x700, 0, false, false, 0).is_ok_and(|status| status == 0xC000_0010), "fileinfo: arquivo sem dispositivo");
    // Trava síncrona do FILE_OBJECT.
    let acquired = file_information::acquire_file(file).is_ok() && file_object.busy.get() == 1;
    assert(acquired && file_information::release_file(file).is_ok() && file_object.busy.get() == 0, "fileinfo: trava sincrona do FILE_OBJECT");
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
        guest::write_bytes(text, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    let unicode = block + 0x40;
    let name = at::<nt::UnicodeString>(unicode);
    name.length.set(units.len() as u16 * 2);
    name.maximum_length.set(units.len() as u16 * 2);
    name.buffer.set(text);
    let attributes = at::<nt::ObjectAttributes>(block);
    attributes.length.set(48);
    attributes.root_directory.set(0);
    attributes.object_name.set(unicode);
    attributes.attributes.set(flags);
    block
}

fn zw_kernel_files(assert: Assert) {
    use crate::drivers::fs::{memory_file_system, ntfs, volume::FileSystem};
    use crate::ntos::ob::close;
    use crate::ntos::io::file::zw as zw_files;
    let block = guest::alloc_bytes(0x400);
    let output = block + 0x300;
    let io_status = block + 0x310;
    let iosb = at::<nt::IoStatusBlock>(io_status);
    // Disco em memória (\FS): FILE_CREATE cria, a segunda vez informa FILE_EXISTS.
    let attributes = object_attributes_for(block, "\\FS\\opennt-zw.txt", 0x240);
    let created = zw_files::create_kernel_file(output, 0x12019F, attributes, io_status, 3, 2, 0x20);
    let handle = guest::read64(output);
    let file = zw_files::file_object_of_handle(handle);
    assert(created.is_ok_and(|status| status == 0) && iosb.information.get() == 2 && memory_file_system::exists("/opennt-zw.txt") && file != 0 && at::<nt::FileObject>(file).flags.get() & 2 != 0, "zwfile: ZwCreateFile cria no disco em memoria com FILE_OBJECT sincrono");
    assert(zw_files::file_backing(file).is_some_and(|(_, path)| path == "/opennt-zw.txt") && zw_files::query_file_handle(handle, false).is_some_and(|entry| entry.is_ok_and(|(pointer, _, options)| pointer == file && options == 0x20)), "zwfile: backing do FILE_OBJECT e consulta do handle");
    let again = zw_files::create_kernel_file(output, 0x12019F, attributes, io_status, 3, 2, 0x20);
    let second = guest::read64(output);
    assert(again.is_ok_and(|status| status == 0) && iosb.information.get() == 4 && close::close(second, Some(0)).is_ok_and(|status| status == 0), "zwfile: FILE_CREATE de arquivo existente informa FILE_EXISTS");
    assert(close::close(handle, Some(0)).is_ok_and(|status| status == 0) && close::close(handle, Some(0)).is_ok_and(|status| status == 0xC000_0008) && zw_files::file_object_of_handle(handle) == 0, "zwfile: ZwClose fecha o handle de arquivo uma vez");
    let missing = object_attributes_for(block, "\\FS\\opennt-nao-existe.txt", 0x240);
    assert(zw_files::create_kernel_file(output, 0x120089, missing, io_status, 1, 1, 0).is_ok_and(|status| status == 0xC000_0034) && iosb.status.get() as u32 == 0xC000_0034, "zwfile: FILE_OPEN de arquivo inexistente");
    let relative = object_attributes_for(block, "sem-raiz.txt", 0x240);
    assert(zw_files::create_kernel_file(output, 0x120089, relative, io_status, 1, 1, 0).is_ok_and(|status| status == 0xC000_003B), "zwfile: nome relativo sem RootDirectory");
    let _ = memory_file_system::remove("/opennt-zw.txt");
    // NTFS pelo link \DosDevices\D: com FILE_OPEN_IF.
    let attributes = object_attributes_for(block, "\\DosDevices\\D:\\opennt-zw.bin", 0x240);
    let created = zw_files::create_kernel_file(output, 0x12019F, attributes, io_status, 0, 3, 0x20);
    let handle = guest::read64(output);
    let on_ntfs = ntfs::mounted().is_some_and(|volume| FileSystem::exists(volume.as_ref(), "/opennt-zw.bin"));
    assert(created.is_ok_and(|status| status == 0) && iosb.information.get() == 2 && on_ntfs && close::close(handle, Some(0)).is_ok_and(|status| status == 0), "zwfile: ZwCreateFile pelo link \\DosDevices\\D: cria no NTFS");
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
    let iosb = at::<nt::IoStatusBlock>(io_status);
    let _ = memory_file_system::write_bytes("/opennt-q.txt", b"0123456789".to_vec());
    let attributes = object_attributes_for(block, "\\FS\\opennt-q.txt", 0x240);
    let opened = zw_files::create_kernel_file(output, 0x120089, attributes, io_status, 1, 1, 0x20);
    let handle = guest::read64(output);
    let file = zw_files::file_object_of_handle(handle);
    assert(opened.is_ok_and(|status| status == 0) && file != 0, "queryfile: arquivo aberto pelo ZwCreateFile");
    // FileStandardInformation e FileNameInformation.
    assert(query_file::query(handle, io_status, buffer, 24, 5).is_ok_and(|status| status == 0) && at::<nt::FileStandardInformation>(buffer).end_of_file.quad_part.get() == 10 && iosb.information.get() == 24 && at::<nt::FileStandardInformation>(buffer).directory.get() == 0, "queryfile: FileStandardInformation com o tamanho do arquivo");
    assert(query_file::query(handle, io_status, buffer, 64, 9).is_ok_and(|status| status == 0) && at::<nt::FileNameInformation>(buffer).file_name_length.get() == 26 && guest::read_bytes(at::<nt::FileNameInformation>(buffer).file_name[0].address(), 4) == [b'\\', 0, b'o', 0], "queryfile: FileNameInformation com o caminho no volume");
    assert(query_file::query(handle, io_status, buffer, 8, 9).is_ok_and(|status| status == 0x8000_0005) && at::<nt::FileNameInformation>(buffer).file_name_length.get() == 26 && iosb.information.get() == 8, "queryfile: nome truncado devolve BUFFER_OVERFLOW");
    assert(query_file::query(handle, io_status, buffer, 4, 8).is_ok_and(|status| status == 0) && at::<nt::FileAccessInformation>(buffer).access_flags.get() == 0x120089 && query_file::query(handle, io_status, buffer, 8, 14).is_ok_and(|status| status == 0) && at::<nt::FilePositionInformation>(buffer).current_byte_offset.quad_part.get() == 0, "queryfile: acesso concedido e posicao corrente");
    assert(query_file::query(handle, io_status, buffer, 64, 2).is_ok_and(|status| status == 0xC000_0003) && query_file::query(handle, io_status, buffer, 64, 99).is_ok_and(|status| status == 0xC000_0003) && query_file::query(0x7FF0, io_status, buffer, 24, 5).is_ok_and(|status| status == 0xC000_0008), "queryfile: classe invalida e handle invalido");
    // Consulta por objeto (IoQueryFileInformation) e criação por nome.
    let length = block + 0x320;
    assert(zw_files::query_file_information_by_object(file, 5, 24, buffer, length).is_ok_and(|status| status == 0) && at::<nt::FileStandardInformation>(buffer).end_of_file.quad_part.get() == 10 && guest::read32(length) == 0x18, "queryfile: IoQueryFileInformation por FILE_OBJECT");
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
    let (iosb, byte_offset) = (at::<nt::IoStatusBlock>(io_status), at::<nt::LargeInteger>(offset));
    // Disco em memória, arquivo síncrono: a posição corrente avança.
    let _ = memory_file_system::write_bytes("/opennt-read.txt", b"abcdefghij".to_vec());
    let attributes = object_attributes_for(block, "\\FS\\opennt-read.txt", 0x240);
    let _ = zw_files::create_kernel_file(output, 0x120089, attributes, io_status, 1, 1, 0x20);
    let handle = guest::read64(output);
    let file = zw_files::file_object_of_handle(handle);
    let file_object = || at::<nt::FileObject>(file);
    let first = read_file::read(handle, 0, 0, 0, io_status, buffer, 4, 0, 0);
    assert(first.is_ok_and(|status| status == 0) && iosb.information.get() == 4 && guest::read32(buffer) == u32::from_le_bytes(*b"abcd") && file_object().current_byte_offset.quad_part.get() == 4, "readfile: leitura sincrona na posicao corrente");
    assert(read_file::read(handle, 0, 0, 0, io_status, buffer, 4, 0, 0).is_ok_and(|status| status == 0) && guest::read32(buffer) == u32::from_le_bytes(*b"efgh") && file_object().current_byte_offset.quad_part.get() == 8, "readfile: segunda leitura continua de onde parou");
    byte_offset.quad_part.set(8);
    assert(read_file::read(handle, 0, 0, 0, io_status, buffer, 10, offset, 0).is_ok_and(|status| status == 0) && iosb.information.get() == 2 && guest::read16(buffer) == u16::from_le_bytes(*b"ij"), "readfile: leitura curta no fim do arquivo");
    byte_offset.quad_part.set(20);
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
        let bytes = guest::read_bytes(buffer, 300);
        assert(read.is_ok_and(|status| status == 0) && iosb.information.get() == 300 && bytes == pattern, "readfile: leitura de arquivo NTFS com os bytes do volume");
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
    let (iosb, byte_offset) = (at::<nt::IoStatusBlock>(io_status), at::<nt::LargeInteger>(offset));
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
    let file_object = || at::<nt::FileObject>(file);
    guest::write_bytes(buffer, b"ABC");
    let first = write_file::write(handle, 0, 0, 0, io_status, buffer, 3, 0, 0);
    assert(first.is_ok_and(|status| status == 0) && iosb.information.get() == 3 && file_object().current_byte_offset.quad_part.get() == 3 && memory_file_system::read_bytes("/opennt-write.txt").is_some_and(|bytes| bytes == b"ABC3456789"), "writefile: escrita sincrona na posicao corrente");
    byte_offset.quad_part.set(8);
    guest::write_bytes(buffer, b"zzzz");
    assert(write_file::write(handle, 0, 0, 0, io_status, buffer, 4, offset, 0).is_ok_and(|status| status == 0) && file_object().current_byte_offset.quad_part.get() == 12 && memory_file_system::read_bytes("/opennt-write.txt").is_some_and(|bytes| bytes == b"ABC34567zzzz"), "writefile: escrita com offset estende o arquivo");
    byte_offset.quad_part.set(-1);
    guest::write_bytes(buffer, b"!");
    assert(write_file::write(handle, 0, 0, 0, io_status, buffer, 1, offset, 0).is_ok_and(|status| status == 0) && memory_file_system::read_bytes("/opennt-write.txt").is_some_and(|bytes| bytes == b"ABC34567zzzz!"), "writefile: offset -1 escreve no fim do arquivo");
    byte_offset.quad_part.set(0);
    assert(read_file::read(handle, 0, 0, 0, io_status, buffer + 0x80, 13, offset, 0).is_ok_and(|status| status == 0) && iosb.information.get() == 13 && guest::read8(buffer + 0x80 + 12) == b'!', "writefile: leitura devolve o conteudo escrito");
    let _ = close::close(handle, Some(0));
    // Só FILE_APPEND_DATA: toda escrita vai para o fim.
    let _ = zw_files::create_kernel_file(output, 0x100005, attributes, io_status, 3, 1, 0x20);
    let append = guest::read64(output);
    byte_offset.quad_part.set(0);
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
        assert(written.is_ok_and(|status| status == 0) && iosb.information.get() == 200 && ntfs_volume.read_bytes("/opennt-write.bin").is_some_and(|bytes| bytes == pattern), "writefile: escrita em arquivo NTFS");
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
    assert(created.is_ok() && pointer != 0 && at::<nt::ClientId>(client_id).unique_thread.get() >= 0x804 && at::<nt::Kthread>(pointer).header.type_.get() == 6 && kernel_threads::get_current_thread_handle() == 0, "kthreads: PsCreateSystemThread publica handle, KTHREAD e CLIENT_ID");
    let finished = pump(&|| guest::read32(block) == 0x1234 && pointer != 0 && at::<nt::Kthread>(pointer).header.signal_state.get() == 1);
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
    let resumed = pump(&|| guest::read32(block + 16) == 0x77 && waiting_pointer != 0 && at::<nt::Kthread>(waiting_pointer).header.signal_state.get() == 1);
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
    use crate::ntos::ex::system_information;
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
        guest::write_bytes(block + 0x220, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    let name = at::<nt::UnicodeString>(value_name);
    name.length.set(12);
    name.maximum_length.set(12);
    name.buffer.set(block + 0x220);
    guest::write32(block + 0x2F0, 42);
    let set = call_export("ZwSetValueKey", &[key, value_name, 0, 4, block + 0x2F0, 4]);
    let query = call_export("ZwQueryValueKey", &[key, value_name, 2, buffer, 0x100, block + 0x2F8]);
    assert(status(created) == 0 && status(set) == 0 && status(query) == 0 && at::<nt::KeyValuePartialInformation>(buffer).type_.get() == 4 && guest::read32(at::<nt::KeyValuePartialInformation>(buffer).data[0].address()) == 42, "zw: ZwCreateKey, ZwSetValueKey e ZwQueryValueKey (partial)");
    assert(status(call_export("ZwDeleteKey", &[key])) == 0 && status(call_export("ZwClose", &[key])) == 0, "zw: ZwDeleteKey e ZwClose da chave");
    // Arquivos: cria, escreve, relê, consulta tamanho e volume, apaga.
    let file_attributes = object_attributes_for(block, "\\FS\\opennt-zw.txt", 0x240);
    let created = call_export("ZwCreateFile", &[output, 0x12019F, file_attributes, io_status, 0, 0x80, 3, 3, 0x20, 0, 0]);
    let file = guest::read64(output);
    guest::write_bytes(buffer, b"OpenNT zw");
    let written = call_export("ZwWriteFile", &[file, 0, 0, 0, io_status, buffer, 9, 0, 0]);
    at::<nt::LargeInteger>(block + 0x2F0).quad_part.set(0);
    let read = call_export("ZwReadFile", &[file, 0, 0, 0, io_status, buffer + 0x100, 9, block + 0x2F0, 0]);
    assert(status(created) == 0 && status(written) == 0 && status(read) == 0 && guest::read_bytes(buffer + 0x100, 9) == b"OpenNT zw", "zw: ZwCreateFile, ZwWriteFile e ZwReadFile");
    let standard = call_export("ZwQueryInformationFile", &[file, io_status, buffer, 24, 5]);
    assert(status(standard) == 0 && at::<nt::FileStandardInformation>(buffer).end_of_file.quad_part.get() == 9, "zw: ZwQueryInformationFile (FileStandardInformation)");
    let volume = call_export("ZwQueryVolumeInformationFile", &[file, io_status, buffer, 0x100, 1]);
    assert(status(volume) == 0 && at::<nt::FileFsVolumeInformation>(buffer).volume_label_length.get() == 12 && at::<nt::FileFsVolumeInformation>(buffer).volume_label[0].get() == b'O' as u16 && at::<nt::IoStatusBlock>(io_status).information.get() == 30, "zw: ZwQueryVolumeInformationFile (rotulo do volume)");
    assert(status(call_export("ZwFlushBuffersFile", &[file, io_status])) == 0 && status(call_export("ZwFlushBuffersFile", &[0x7FF0, io_status])) == 0xC000_0008, "zw: ZwFlushBuffersFile valida o handle");
    at::<nt::FileDispositionInformation>(block + 0x2F0).delete_file.set(1);
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
    assert(status(call_export("ZwPowerInformation", &[4, 0, 0, buffer, 0x40])) == 0 && at::<nt::SystemPowerCapabilities>(buffer).power_button_present.get() == 1 && at::<nt::SystemPowerCapabilities>(buffer).lid_present.get() == 0 && status(call_export("ZwPowerInformation", &[4, 0, 0, buffer, 8])) == 0xC000_0023, "zw: ZwPowerInformation (SystemPowerCapabilities)");
    let before = system_information::entropy_registrations().len();
    guest::write64(buffer, 0x1111);
    guest::write64(buffer + 8, 0x2222);
    guest::write64(buffer + 16, 0x3333);
    assert(status(call_export("ZwSetSystemInformation", &[131, buffer, 24])) == 0 && system_information::entropy_registrations().len() == before + 1 && status(call_export("ZwSetSystemInformation", &[999, buffer, 24])) == 0xC000_0003, "zw: ZwSetSystemInformation registra as rotinas de entropia");
    let basic = call_export("ZwQueryInformationProcess", &[u64::MAX, 0, buffer, 0x30, block + 0x2F0]);
    assert(status(basic) == 0 && at::<nt::ProcessBasicInformation>(buffer).exit_status.get() == 0x103 && at::<nt::ProcessBasicInformation>(buffer).unique_process_id.get() == process_id_of_current() && guest::read32(block + 0x2F0) == 0x30, "zw: ZwQueryInformationProcess (ProcessBasicInformation)");
    // Evento nomeado: ZwOpenEvent + ZwWaitForSingleObject.
    let event = block + 0x380;
    dispatcher::initialize_event(event, 0, false);
    let node = object_manager::create_object("\\KernelObjects", "OpenNTZwEvent", "Event", Some(object_manager::ObjectData::pointer(event)));
    let event_attributes = object_attributes_for(block, "\\KernelObjects\\OpenNTZwEvent", 0x200);
    let opened = call_export("ZwOpenEvent", &[output, 0x1F0003, event_attributes]);
    let event_handle = guest::read64(output);
    at::<nt::LargeInteger>(block + 0x2F0).quad_part.set(0);
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
    assert(status(directory) == 0 && status(listed) == 0 && at::<nt::ObjectDirectoryInformation>(buffer).name.length.get() != 0 && status(call_export("ZwClose", &[directory_handle])) == 0, "zw: ZwOpenDirectoryObject e ZwQueryDirectoryObject");
    guest::free_bytes(block);
}

fn process_id_of_current() -> u64 {
    let thread = crate::ntos::ps::process::get_current_thread();
    if thread == 0 { 4 } else { at::<nt::Ethread>(thread).cid.unique_process.get() }
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
        guest::write_bytes(block + 16, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    let string = at::<nt::UnicodeString>(block);
    string.length.set(units.len() as u16 * 2);
    string.maximum_length.set(units.len() as u16 * 2);
    string.buffer.set(block + 16);
    block
}

fn io_group_exports(assert: Assert) {
    use crate::drivers::fs::memory_file_system;
    use crate::ntos::io::io_manager;
    use crate::ntos::mm::paging;
    use crate::ntos::ob::object_manager;
    use crate::{ntos::io::device_interface, ntos::io::lifecycle};
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
    let base = if driver != 0 { at::<nt::DriverObject>(driver).driver_start.get() } else { 0 };
    assert(loaded.is_ok() && driver != 0, "io: driver de teste carregado");
    let block = guest::alloc_bytes(0x1000);
    let output = block + 0xF00;
    // IoCreateDevice: DEVICE_OBJECT com extensão, no namespace e na lista do driver.
    let name = unicode_at(block, "\\Device\\OpenNtIoTest");
    let created = call_export("IoCreateDevice", &[driver, 0x20, name, 0x22, 0, 0, output]);
    let first = guest::read64(output);
    let node = object_manager::lookup("\\Device\\OpenNtIoTest");
    assert(status(created) == 0 && first != 0 && at::<nt::DriverObject>(driver).device_object.get() == first && at::<nt::DeviceObject>(first).device_extension.get() == first + nt::DeviceObject::SIZE && at::<nt::DeviceObject>(first).device_type.get() == 0x22 && node.and_then(io_manager::device).is_some_and(|entry| entry.native_device == first), "io: IoCreateDevice publica o dispositivo no namespace e na lista do driver");
    let unnamed = call_export("IoCreateDevice", &[driver, 0, 0, 0x22, 0, 0, output]);
    let second = guest::read64(output);
    assert(status(unnamed) == 0 && second != 0 && at::<nt::DriverObject>(driver).device_object.get() == second && at::<nt::DeviceObject>(second).next_device.get() == first, "io: dispositivo sem nome entra na cabeca da lista");
    // Pilha: attach, topo, referência do topo, propriedade do PDO e detach.
    let lower = call_export("IoAttachDeviceToDeviceStack", &[second, first]);
    assert(lower == Some(first) && at::<nt::DeviceObject>(first).attached_device.get() == second && node.and_then(io_manager::device).is_some_and(|entry| entry.stack_top == second), "io: IoAttachDeviceToDeviceStack empilha e atualiza a rota de despacho");
    let top = call_export("IoGetAttachedDeviceReference", &[first]);
    let _ = crate::ntos::ob::objects::device::dereference(second);
    let property = call_export("IoGetDeviceProperty", &[first, 0xB, 0x200, block + 0x400, block + 0xF10]);
    let property_name: alloc::string::String = char::decode_utf16(guest::read_bytes(block + 0x400, 40).chunks(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]]))).map(|unit| unit.unwrap_or('?')).collect();
    assert(top == Some(second) && status(property) == 0 && property_name == "\\Device\\OpenNtIoTest" && guest::read32(block + 0xF10) == 42, "io: topo da pilha e PhysicalDeviceObjectName");
    assert(status(call_export("IoGetDeviceProperty", &[first, 0xB, 4, block + 0x400, block + 0xF10])) == 0xC000_0023 && status(call_export("IoGetDeviceProperty", &[first, 7, 0x200, block + 0x400, block + 0xF10])) == 0xC000_000D, "io: buffer curto e propriedade desconhecida");
    assert(status(call_export("IoDetachDevice", &[first])) == 0 && at::<nt::DeviceObject>(first).attached_device.get() == 0 && node.and_then(io_manager::device).is_some_and(|entry| entry.stack_top == first), "io: IoDetachDevice desfaz a pilha");
    // Links simbólicos.
    let link = unicode_at(block + 0x100, "\\DosDevices\\OpenNtIoTest");
    assert(status(call_export("IoCreateSymbolicLink", &[link, name])) == 0 && object_manager::lookup("\\DosDevices\\OpenNtIoTest").is_some() && status(call_export("IoDeleteSymbolicLink", &[link])) == 0 && status(call_export("IoDeleteSymbolicLink", &[link])) == 0xC000_0009, "io: IoCreateSymbolicLink e IoDeleteSymbolicLink");
    // IRP, extensões e atividade.
    let packet = call_export("IoAllocateIrp", &[2, 0]).unwrap_or(0);
    assert(packet != 0 && at::<nt::Irp>(packet).type_.get() == 6 && at::<nt::Irp>(packet).stack_count.get() == 2 && at::<nt::Irp>(packet).current_location.get() == 3, "io: IoAllocateIrp posiciona a pilha acima do topo");
    call_export("IoSetGenericIrpExtension", &[packet, 0x1234_5678, 1]);
    guest::write_bytes(block + 0x500, &[7u8; 16]);
    call_export("IoSetActivityIdIrp", &[packet, block + 0x500]);
    let activity = call_export("IoGetActivityIdIrp", &[packet, block + 0x520]);
    assert(call_export("IoGetGenericIrpExtension", &[packet]) == Some(0x1234_5678) && status(activity) == 0 && guest::read_bytes(block + 0x520, 16) == [7u8; 16] && call_export("IoSetCancelRoutine", &[packet, 0xABC]) == Some(0) && call_export("IoSetCancelRoutine", &[packet, 0]) == Some(0xABC), "io: extensao generica, activity id e cancel routine do IRP");
    assert(status(call_export("IoFreeIrp", &[packet])) == 0, "io: IoFreeIrp");
    // MDL com os PFNs reais.
    let mdl = call_export("IoAllocateMdl", &[block + 0x800, 0x1000, 0, 0, 0]).unwrap_or(0);
    assert(mdl != 0 && mdl_pfn(mdl, 0) == paging::translate((block + 0x800) & !0xFFF) / 0x1000 && at::<nt::Mdl>(mdl).byte_count.get() == 0x1000 && at::<nt::Mdl>(mdl).byte_offset.get() == ((block + 0x800) & 0xFFF) as u32, "io: IoAllocateMdl com os PFNs das tabelas de pagina");
    call_export("IoFreeMdl", &[mdl]);
    // Remove lock.
    let lock = block + 0x600;
    call_export("IoInitializeRemoveLockEx", &[lock, 0, 0, 0, 0x58]);
    let acquired = call_export("IoAcquireRemoveLockEx", &[lock, 0, 0, 0, 0x58]);
    call_export("IoAcquireRemoveLockEx", &[lock, 0, 0, 0, 0x58]);
    call_export("IoReleaseRemoveLockEx", &[lock, 0, 0x58]);
    call_export("IoReleaseRemoveLockAndWaitEx", &[lock, 0, 0x58]);
    assert(status(acquired) == 0 && at::<nt::IoRemoveLock>(lock).common.io_count.get() == 0 && status(call_export("IoAcquireRemoveLockEx", &[lock, 0, 0, 0, 0x58])) == 0xC000_0056, "io: remove lock conta e recusa depois da remocao");
    // Extensão de driver object.
    let extension = call_export("IoAllocateDriverObjectExtension", &[driver, 0x4F70, 0x40, output]);
    let extension_pointer = guest::read64(output);
    assert(status(extension) == 0 && status(call_export("IoAllocateDriverObjectExtension", &[driver, 0x4F70, 0x40, output])) == 0xC000_0035 && call_export("IoGetDriverObjectExtension", &[driver, 0x4F70]) == Some(extension_pointer), "io: extensao de driver object unica por tag");
    // Interface de dispositivo com notificação PnP nativa.
    let context = block + 0x700;
    guest::write32(context, 0);
    // Assinatura do WDK: categoria, flags, GUID da classe, driver, callback,
    // contexto e o registro de saída.
        guest::write_bytes(block + 0x720, &[0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF0, 0x01]);
    let registered = call_export("IoRegisterPlugPlayNotification", &[2, 0, block + 0x720, driver, base + 0x1340, context, block + 0x710]);
    let registration = guest::read64(block + 0x710);
    let interface = call_export("IoRegisterDeviceInterface", &[first, block + 0x720, 0, block + 0x740]);
    let link_name = guest_strings_read(block + 0x740);
    let enabled = call_export("IoSetDeviceInterfaceState", &[block + 0x740, 1]);
    assert(status(registered) == 0 && status(interface) == 0 && link_name == "\\DosDevices\\#{112233445566778899aabbccddeef001}" && status(enabled) == 0 && guest::read32(context) == 0x55 && device_interface::interface_enabled(&link_name) == Some(true), "io: interface de dispositivo habilitada notifica o callback PnP nativo");
    assert(status(call_export("IoUnregisterPlugPlayNotification", &[registration])) == 0 && status(call_export("IoUnregisterPlugPlayNotification", &[registration])) == 0xC000_0034, "io: IoUnregisterPlugPlayNotification");
    let configuration = call_export("IoGetConfigurationInformation", &[]);
    assert(configuration.is_some_and(|pointer| pointer != 0) && call_export("IoGetConfigurationInformation", &[]) == configuration && call_export("IoSizeofWorkItem", &[]) == Some(crate::ntos::io::work_items::work_item_size()) && call_export("IoGetRequestorProcess", &[0]) == Some(crate::ntos::ps::process::get_system_process()), "io: configuracao global, tamanho do work item e processo do IRP");
    // Exclusão dos dispositivos e descarga do driver.
    let deleted = (status(call_export("IoDeleteDevice", &[second])), status(call_export("IoDeleteDevice", &[first])));
    assert(deleted == (0, 0) && object_manager::lookup("\\Device\\OpenNtIoTest").is_none() && at::<nt::DriverObject>(driver).device_object.get() == 0, "io: IoDeleteDevice retira o dispositivo do namespace e da lista");
    assert(lifecycle::unload_driver("opennt-io") && guest::read32(counter) == 1, "io: driver descarregado");
    guest::free_bytes(block);
    guest::free_bytes(counter);
}

fn ob_group_exports(assert: Assert) {
    use crate::drivers::fs::memory_file_system;
    use crate::ntos::ob::{close, object_manager, object_security, object_types, reference_trace};
    use crate::ntos::ob::objects::{device as device_objects, driver as driver_objects};
    use crate::ntos::ps::process;
    use crate::{ntos::io::lifecycle, ntos::ob::object_reference as ob};
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
    // Nome do objeto: OBJECT_NAME_INFORMATION com o texto logo depois da
    // estrutura; ReturnLength conta estrutura, texto e terminador.
    let unicode = block + 0x300;
    let queried = call_export("ObQueryNameString", &[device, unicode, 0x200, block + 0xF10]);
    assert(status(queried) == 0 && guest_strings_read(unicode) == "\\Device\\OpenNtObTest" && at::<nt::ObjectNameInformation>(unicode).name.buffer.get() == unicode + nt::ObjectNameInformation::SIZE && guest::read32(block + 0xF10) == nt::ObjectNameInformation::SIZE as u32 + 42 && status(call_export("ObQueryNameString", &[device, unicode, 8, block + 0xF10])) == 0xC000_0004, "ob: ObQueryNameString devolve o caminho completo");
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
    assert(status(pseudo) == 0 && guest::read64(block + 0xF20) == current && at::<nt::ObjectHandleInformation>(block + 0xF30).granted_access.get() == object_types::process_type().valid_access, "ob: pseudo-handle -1 resolve o processo corrente");
    call_export("ObDereferenceObject", &[current]);
    let thread = call_export("ObReferenceObjectByHandle", &[u64::MAX - 1, 0, 0, 0, block + 0xF20, 0]);
    let thread_mismatch = call_export("ObReferenceObjectByHandle", &[u64::MAX - 1, 0, object_types::event_type().pointer, 1, block + 0xF20, 0]);
    assert(status(thread) == 0 && guest::read64(block + 0xF20) == process::get_current_thread() && status(thread_mismatch) == 0xC000_0024 && status(call_export("ObReferenceObjectByHandle", &[u64::MAX - 5, 0, 0, 0, block + 0xF20, 0])) == 0xC000_0008, "ob: pseudo-handle -2, tipo validado antes do acesso e handle negativo");
    call_export("ObDereferenceObject", &[process::get_current_thread()]);
    // Por ponteiro: tipo exigido em modo usuário.
    assert(status(call_export("ObReferenceObjectByPointer", &[current, 0, object_types::process_type().pointer, 1])) == 0 && status(call_export("ObReferenceObjectByPointer", &[current, 0, object_types::thread_type().pointer, 1])) == 0xC000_0024 && status(call_export("ObReferenceObjectByPointer", &[0, 0, 0, 0])) == 0xC000_000D, "ob: ObReferenceObjectByPointer confere o tipo em modo usuario");
    call_export("ObDereferenceObject", &[current]);
    // Segurança, device maps e histórico de referências.
    assert(status(call_export("ObSetSecurityObjectByPointer", &[device, 0x5000, 4])) == 0 && object_security::security_descriptor(device) == Some(0x5000) && call_export("ObIsDosDeviceLocallyMapped", &[0]) == Some(0), "ob: descritor de seguranca e device maps");
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
    let thunk = exports::thunk_address(738).unwrap_or(0);
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
    at::<nt::LargeInteger>(block + 0xF40).quad_part.set(0);
    let written = call_export("NtWriteFile", &[file, 0, 0, 0, block + 0xF30, block + 0x700, 2, block + 0xF40, 0]);
    let read = call_export("NtReadFile", &[file, 0, 0, 0, block + 0xF30, block + 0x780, 6, block + 0xF40, 0]);
    assert(status(queried) == 0 && at::<nt::FileStandardInformation>(block + 0x600).end_of_file.quad_part.get() == 6 && status(written) == 0 && status(read) == 0 && guest::read_bytes(block + 0x780, 6) == b"XYenNT", "pequenos: NtQueryInformationFile, NtWriteFile e NtReadFile");
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
    use core::mem::offset_of;
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
    at::<nt::ObjectAttributes>(block).length.set(40);
    assert(status(call_export("ZwDeleteFile", &[block])) == 0xC000_000D, "deletefile: OBJECT_ATTRIBUTES com Length errado");
    // Rotinas de despacho nativas: 0x1300 conclui com sucesso; 0x1340 grava
    // "OKAY" no SystemBuffer com Information 4. Ambas chamam IofCompleteRequest (IAT[0]).
    let code = |at: usize, ioctl: bool| -> Vec<u8> {
        let mut bytes = Vec::new();
        if ioctl {
            bytes.extend_from_slice(&[0x48, 0x8B, 0x42, offset_of!(nt::Irp, associated_irp) as u8]); // mov rax, [rdx+SystemBuffer]
            bytes.extend_from_slice(&[0xC7, 0x00, b'O', b'K', b'A', b'Y']); // mov dword [rax], "OKAY"
        }
        bytes.extend_from_slice(&[0xC7, 0x42, offset_of!(nt::Irp, io_status) as u8, 0, 0, 0, 0]); // mov dword [rdx+IoStatus], 0
        bytes.extend_from_slice(&[0x48, 0xC7, 0x42, (offset_of!(nt::Irp, io_status) + offset_of!(nt::IoStatusBlock, information)) as u8, if ioctl { 4 } else { 0 }, 0, 0, 0]); // mov qword [rdx+Information], n
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
        at::<nt::DriverObject>(driver).major_function[major as usize].set(image.image_base + 0x1300);
    }
    at::<nt::DriverObject>(driver).major_function[14].set(image.image_base + 0x1340);
    let name = unicode_at(block + 0x200, "\\Device\\OpenNtIoctl");
    let _ = call_export("IoCreateDevice", &[driver, 0, name, 0x22, 0, 0, output]);
    let device = guest::read64(output);
    // Abertura do dispositivo e IOCTL METHOD_BUFFERED (0x222000).
    let file_attributes = object_attributes_for(block + 0x300, "\\Device\\OpenNtIoctl", 0x240);
    let opened = call_export("ZwCreateFile", &[output, 0x12019F, file_attributes, block + 0xF10, 0, 0, 3, 1, 0x20, 0, 0]);
    let handle = guest::read64(output);
    guest::write32(block + 0x500, 0);
    let controlled = call_export("ZwDeviceIoControlFile", &[handle, 0, 0, 0, block + 0xF20, 0x22_2000, 0, 0, block + 0x500, 16]);
    assert(device != 0 && status(opened) == 0 && status(controlled) == 0 && guest::read_bytes(block + 0x500, 4) == b"OKAY" && at::<nt::IoStatusBlock>(block + 0xF20).status.get() == 0 && at::<nt::IoStatusBlock>(block + 0xF20).information.get() == 4, "devctl: ZwDeviceIoControlFile entrega o IRP ao driver nativo e copia a saida buffered");
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
    let (device_object, device_extension, volume) = (at::<nt::DeviceObject>(device), at::<nt::DevobjExtension>(extension), at::<nt::Vpb>(block_vpb));
    device_object.vpb.set(block_vpb);
    assert(status(call_export("IoGetDiskDeviceObject", &[device, output])) == 0xC000_000D, "diskdevice: dispositivo de armazenamento com VPB proprio recusado");
    device_object.vpb.set(0);
    device_object.device_object_extension.set(extension);
    device_extension.vpb.set(0);
    assert(status(call_export("IoGetDiskDeviceObject", &[device, output])) == 0xC000_000D, "diskdevice: volume sem VPB");
    device_extension.vpb.set(block_vpb);
    volume.reference_count.set(0);
    volume.flags.set(1);
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
    let (descriptor, owner) = (at::<nt::SecurityDescriptorRelative>(buffer), at::<nt::Sid>(buffer + 20));
    // Arquivo de volume sem ACLs: o descritor mundial do SeAssignWorldSecurityDescriptor.
    let _ = memory_file_system::write_bytes("/opennt-qsec.txt", b"s".to_vec());
    let attributes = object_attributes_for(block, "\\FS\\opennt-qsec.txt", 0x240);
    let _ = zw_files::create_kernel_file(output, 0x12019F, attributes, block + 0x720, 3, 1, 0x20);
    let file = guest::read64(output);
    let world = call_export("ZwQuerySecurityObject", &[file, 1, buffer, 0x100, needed]);
    assert(status(world) == 0 && guest::read32(needed) == 44 && descriptor.revision.get() == 1 && descriptor.owner.get() == 20 && owner.revision.get() == 1 && owner.identifier_authority.value[5].get() == 1 && descriptor.control.get() & 0x8000 != 0, "querysecurity: arquivo de volume recebe o descritor mundial");
    assert(status(call_export("ZwQuerySecurityObject", &[file, 1, buffer, 8, needed])) == 0xC000_0023 && guest::read32(needed) == 44, "querysecurity: buffer curto informa os 44 bytes");
    let _ = close::close(file, Some(0));
    let _ = memory_file_system::remove("/opennt-qsec.txt");
    // Processo corrente: descritor da política do dono.
    guest::write32(needed, 0);
    let process = call_export("ZwQuerySecurityObject", &[u64::MAX, 1, buffer, 0, needed]);
    let process_needed = guest::read32(needed);
    let process_full = call_export("ZwQuerySecurityObject", &[u64::MAX, 1, buffer, process_needed as u64, needed]);
    assert(status(process) == 0xC000_0023 && process_needed > 20 && status(process_full) == 0 && descriptor.revision.get() == 1 && descriptor.owner.get() != 0, "querysecurity: processo corrente pelo descritor da politica do dono");
    guest::write32(needed, 0xABCD);
    assert(status(call_export("ZwQuerySecurityObject", &[0x7FF0, 1, buffer, 0x100, needed])) == 0xC000_0008 && guest::read32(needed) == 0xABCD, "querysecurity: handle invalido nao toca a saida");
    guest::free_bytes(block);
}

fn persistent_thread_state_capture(assert: Assert) {
    use crate::ntos::init::exports;
    let output = guest::alloc_bytes(0x40000);
    let context = guest::alloc_bytes(0x500);
        guest::write_bytes(context, &(0..0x4D0u64).step_by(8).flat_map(|offset| (0x5A5A_0000_0000_0000 | offset).to_le_bytes()).collect::<Vec<u8>>());
    // RIP num trampolim real (página de código legível) e RSP qualquer.
    let rip = exports::thunk_address(100).unwrap_or(0);
    at::<nt::Context>(context).rip.set(rip);
    let returned = call_export("KeCapturePersistentThreadState", &[context, 0, 0xDEAD, 1, 2, 3, 4, output]);
    let flags = guest::read32(output + 0x1038);
    assert(returned == Some(0x40000) && guest::read32(output + 4) == 0x3436_5544 && guest::read32(output + 0x30) == 0x8664 && guest::read32(output + 0x38) == 0xDEAD && guest::read64(output + 0x40) == 1 && guest::read64(output + 0x58) == 4, "triage: cabecalho DU64 com o bugcheck e os parametros");
    assert(guest::read64(output + 0x348 + 8) == 0x5A5A_0000_0000_0008 && at::<nt::ExceptionRecord64>(output + 0xF00).exception_address.get() == rip && guest::read32(output + 0x2080 + 0x10) == 0x4742_444B && guest::read32(output + 0x3FFFC) == 0x4447_5254, "triage: CONTEXT copiado, KDBG e o verificador TRGD");
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
        guest::write_bytes(packet, &[0u8; 0x80]);
    let image_information = at::<nt::BdcbImageInformation>(packet);
        image_information.image_name.buffer.set(packet + 0x62);
    image_information.certificate_publisher.buffer.set(packet + 0x66);
    image_information.certificate_issuer.buffer.set(packet + 0x68);
    image_information.image_hash.set(packet + 0x69);
    image_information.certificate_thumbprint.set(packet + 0x6A);
    let queued = image_verification::queue_owned_information(packet, 0x80);
    for _ in 0..64 {
        if image_verification::pending() == 0 {
            break;
        }
        scheduler::tick(-1);
    }
    let copy = guest::read64(context + 8);
    assert(queued.is_ok_and(|status| status == 0) && image_verification::pending() == 0 && guest::read64(context) == 1 && copy != 0 && copy != packet, "imgver: o callback recebe a copia do pacote pela thread de sistema");
    assert(copy != 0 && at::<nt::BdcbImageInformation>(copy).image_name.buffer.get() == copy + 0x62 && at::<nt::BdcbImageInformation>(copy).certificate_thumbprint.get() == copy + 0x6A, "imgver: ponteiros internos ajustados a base da copia");
    assert(status(call_export("SeUnregisterImageVerificationCallback", &[handle])) == 0 && image_verification::count() == 0, "imgver: inscricao removida");
    guest::free_bytes(block);
    let _ = image.release();
}

fn rtl_unwind_dynamic_table(assert: Assert) {
    use crate::ntos::rtl::unwind;
    let block = guest::alloc_bytes(0x2000);
    let base = (block + 0xFFF) & !0xFFF;
    // Código: prólogo push rbx; sub rsp, 20h; corpo de NOPs; epílogo em 0x130.
        guest::write_bytes(base + 0x100, &[0x90u8; 0x40]);
    guest::write_bytes(base + 0x100, &[0x53, 0x48, 0x83, 0xEC, 0x20]);
    guest::write_bytes(base + 0x130, &[0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3]);
    // UNWIND_INFO v1: prólogo de 5 bytes, 2 slots (ALLOC_SMALL 0x20 em 5, PUSH_NONVOL rbx em 1).
    guest::write_bytes(base + 0x200, &[0x01, 0x05, 0x02, 0x00]);
    let unwind_info = at::<nt::UnwindInfo>(base + 0x200);
    unwind_info.unwind_code[0].set(5 | (2 << 8) | (3 << 12));
    at::<nt::Field<u16>>(unwind_info.unwind_code[0].address() + 2).set(1 | (3 << 12));
    // RUNTIME_FUNCTION.
    let runtime_function = at::<nt::ImageRuntimeFunctionEntry>(base + 0x300);
    runtime_function.begin_address.set(0x100);
    runtime_function.end_address.set(0x140);
    runtime_function.unwind_data.set(0x200);
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
    let context_record = at::<nt::Context>(context);
    let run = |rip: u64| {
            guest::write_bytes(context, &[0u8; 0x4D0]);
        context_record.rsp.set(stack);
        context_record.rip.set(rip);
        let handler = unwind::unwind(0, base, rip, table, context, base + 0x410, base + 0x418, 0);
        handler.is_ok_and(|handler| handler == 0) && context_record.rbx.get() == 0xB0B0 && context_record.rip.get() == 0xCAFE && context_record.rsp.get() == stack + 0x30
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
    let destination_string = at::<nt::UnicodeString>(destination);
    destination_string.length.set(0);
    destination_string.maximum_length.set(16);
    destination_string.buffer.set(buffer);
    let text = block + 0x200;
        guest::write_bytes(text, &"OpenNT".encode_utf16().chain([0]).flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    assert(strings_counted::append(destination, text) == 0 && destination_string.length.get() == 12 && guest::read16(buffer + 12) == 0 && guest::read16(buffer) == b'O' as u16 && strings_counted::append(destination, text) == 0xC000_0023, "rtlstrings: RtlAppendUnicodeToString com NUL e buffer cheio");
    let copy = block + 0x20;
    let copy_string = at::<nt::UnicodeString>(copy);
    copy_string.length.set(0);
    copy_string.maximum_length.set(8);
    copy_string.buffer.set(block + 0x300);
    strings_counted::copy(copy, destination);
    assert(copy_string.length.get() == 8 && guest::read16(block + 0x300 + 6) == b'n' as u16, "rtlstrings: RtlCopyUnicodeString trunca em MaximumLength");
    guest::write_bytes(block + 0x400, b"ansi\0");
    strings_counted::initialize_ansi(block + 0x40, block + 0x400);
    assert(at::<nt::String>(block + 0x40).length.get() == 4 && at::<nt::String>(block + 0x40).maximum_length.get() == 5 && at::<nt::String>(block + 0x40).buffer.get() == block + 0x400, "rtlstrings: RtlInitAnsiString");
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
    let run_once_state = at::<nt::RtlRunOnce>(once);
    guest::write64(context, 0);
    let first = run_once::execute(once, image.image_base + 0x1300, 0, context);
    assert(first.is_ok_and(|status| status == 0) && run_once_state.value.get() == 0x1002 && guest::read64(context) == 0x1000, "runonce: RtlRunOnceExecuteOnce chama o inicializador e publica o contexto");
    guest::write64(context, 0);
    assert(run_once::execute(once, 0xDEAD, 0, context).is_ok_and(|status| status == 0) && guest::read64(context) == 0x1000, "runonce: segunda execucao devolve o contexto sem chamar");
    let _ = run_once::initialize(once);
    assert(run_once::begin_initialize(once, 0, context).is_ok_and(|status| status == 0x103) && run_once::complete(once, 0, 0x2000).is_ok_and(|status| status == 0) && run_once::begin_initialize(once, 1, context).is_ok_and(|status| status == 0) && guest::read64(context) == 0x2000 && run_once::complete(once, 0, 0x3001).is_ok_and(|status| status == 0xC000_00F1), "runonce: BeginInitialize/Complete e contexto desalinhado recusado");
    // Pela thread de sistema (interceptação do RtlRunOnceExecuteOnce).
    let _ = run_once::initialize(once);
    guest::write64(context, 0);
    let request = run_once::execute_request(once, image.image_base + 0x1300, 0, context).map(|request| kernel_threads::create_system_request(alloc::boxed::Box::new(request)));
    for _ in 0..32 {
        if run_once_state.value.get() & 3 == 2 {
            break;
        }
        scheduler::tick(-1);
    }
    assert(request.is_ok_and(|created| created.is_ok()) && run_once_state.value.get() == 0x1002 && guest::read64(context) == 0x1000, "runonce: execucao pela requisicao de thread de sistema");
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
    assert(at::<nt::UnicodeString>(first).length.get() == 12 && at::<nt::UnicodeString>(first).maximum_length.get() == 14 && at::<nt::UnicodeString>(first).buffer.get() == text, "rtl: RtlInitUnicodeString aponta o buffer sem copiar");
    let second = unicode_at(block + 0x40, "OPENNT");
    assert(call("RtlEqualUnicodeString", &[first, second, 0]) == 0 && (call("RtlCompareUnicodeString", &[first, second, 0]) as i32) > 0, "rtl: RtlEqual/CompareUnicodeString sensiveis a caixa");
    // Sem caixa só com a tabela NLS do volume (a ausência é erro, não fallback).
    let casing = crate::ntos::rtl::unicode_case::upcase_char(b'a' as u16);
    assert(casing.as_ref().map_or_else(|error| error.message.contains("l_intl"), |&upper| upper == b'A' as u16 && call("RtlEqualUnicodeString", &[first, second, 1]) == 1), "rtl: RtlEqualUnicodeString sem caixa pela tabela l_intl.nls (ou ausencia reportada)");
    let lower = block + 0x80;
    assert(call("RtlDowncaseUnicodeString", &[lower, second, 1]) == 0 && guest_strings_read(lower) == "opennt" && call("RtlFreeUnicodeString", &[lower]) == 0 && at::<nt::UnicodeString>(lower).buffer.get() == 0, "rtl: RtlDowncaseUnicodeString aloca e RtlFreeUnicodeString libera");
    // Inteiros.
    let value = block + 0x100;
    let number = unicode_at(block + 0xC0, "0x1F");
    assert(call("RtlUnicodeStringToInteger", &[number, 0, value]) == 0 && guest::read32(value) == 31, "rtl: RtlUnicodeStringToInteger com base automatica");
    let invalid = unicode_at(block + 0xC0, "zz");
    assert(call("RtlUnicodeStringToInteger", &[invalid, 10, value]) as u32 == 0xC000_000D, "rtl: RtlUnicodeStringToInteger recusa texto sem digitos");
    let digits = block + 0x110;
    let digits_string = at::<nt::UnicodeString>(digits);
    digits_string.maximum_length.set(16);
    digits_string.buffer.set(block + 0x120);
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
    let list_head = at::<nt::ListEntry>(head);
    list_head.flink.set(head);
    list_head.blink.set(head);
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
    // dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW): wSuiteMask (+0x118) e wProductType (+0x11A).
    guest::write32(info, 0x11C);
    call("RtlGetVersion", &[info]);
    let version = at::<nt::OsVersionInfoExW>(info);
    assert(version.dw_major_version.get() == 10 && version.dw_build_number.get() == 26100 && version.dw_platform_id.get() == 2 && version.w_suite_mask.get() == 0x100 && version.w_product_type.get() == 1, "rtl: RtlGetVersion 10.0.26100 estacao de trabalho");
    assert(call("RtlVerifyVersionInfo", &[info, 1, 1]) == 0, "rtl: RtlVerifyVersionInfo aceita a versao igual");
    version.dw_major_version.set(11);
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
    let time_fields = at::<nt::TimeFields>(fields);
    time_fields.year.set(2024);
    time_fields.month.set(2);
    time_fields.day.set(29);
    time_fields.hour.set(12);
    time_fields.minute.set(34);
    time_fields.second.set(56);
    time_fields.milliseconds.set(789);
    assert(call("RtlTimeFieldsToTime", &[fields, time]) == 1 && at::<nt::LargeInteger>(time).quad_part.get() == 133_536_836_967_890_000, "rtl: RtlTimeFieldsToTime em 100 ns desde 1601");
    call("RtlTimeToTimeFields", &[time, back]);
    let back_fields = at::<nt::TimeFields>(back);
    let decoded = [back_fields.year.get(), back_fields.month.get(), back_fields.day.get(), back_fields.hour.get(), back_fields.minute.get(), back_fields.second.get(), back_fields.milliseconds.get(), back_fields.weekday.get()];
    assert(decoded == [2024, 2, 29, 12, 34, 56, 789, 4], "rtl: RtlTimeToTimeFields com dia da semana (quinta)");
    time_fields.day.set(30);
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
    let (query_entry, default_entry) = (at::<nt::RtlQueryRegistryTable>(table), at::<nt::RtlQueryRegistryTable>(table + nt::RtlQueryRegistryTable::SIZE));
    query_entry.flags.set(0x20);
    query_entry.name.set(value_name);
    query_entry.entry_context.set(direct);
    default_entry.flags.set(0x20);
    default_entry.name.set(missing_name);
    default_entry.entry_context.set(defaulted);
    default_entry.default_type.set(4);
    default_entry.default_data.set(default_data);
    default_entry.default_length.set(4);
    assert(call("RtlQueryRegistryValues", &[0, path, table, 0, 0]) == 0 && guest::read32(direct) == 0x1234 && guest::read32(defaulted) == 0x55, "rtl: RtlQueryRegistryValues DIRECT com valor e default");
    default_entry.flags.set(0x24);
    default_entry.default_type.set(0);
    assert(call("RtlQueryRegistryValues", &[0, path, table, 0, 0]) as u32 == 0xC000_0034, "rtl: RtlQueryRegistryValues REQUIRED sem valor nem default");
    assert(call("RtlDeleteRegistryValue", &[1, relative, value_name]) == 0 && call("RtlDeleteRegistryValue", &[1, relative, value_name]) as u32 == 0xC000_0034, "rtl: RtlDeleteRegistryValue remove o valor");
    // SID S-1-5-32-544.
    let (sid, authority, copy) = (block + 0xA00, block + 0xA40, block + 0xA60);
    guest::write_bytes(authority, &[0, 0, 0, 0, 0, 5]);
    assert(call("RtlInitializeSidEx", &[sid, authority, 2, 32, 544]) == 0 && call("RtlValidSid", &[sid]) == (sid > 0x7FFF_FFFF_0000) as u64 && call("RtlLengthSid", &[sid]) == 16 && sub_authority(sid, 1).get() == 544, "rtl: RtlInitializeSidEx com subautoridades variadicas (RtlValidSid recusa a faixa de usuario)");
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
    assert(level == 12 && at::<nt::KlockQueueHandle>(handle).lock_queue.lock.get() == spin && guest::read64(spin) == 0 && irql::get_irql() == 0, "ke: in-stack RaiseToSynch e liberacao ForDpc");
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
    let first = call_export("KeSetSystemAffinityThreadEx", &[1]);
    let second = call_export("KeSetSystemAffinityThreadEx", &[1]);
    call_export("KeRevertToUserAffinityThreadEx", &[0]);
    let group = guest::alloc_bytes(32);
    guest::write_bytes(group, &[0; 32]);
    at::<nt::GroupAffinity>(group).mask.set(1);
    call_export("KeSetSystemGroupAffinityThread", &[group, group + 16]);
    let previous_mask = at::<nt::GroupAffinity>(group + 16).mask.get();
    call_export("KeRevertToUserGroupAffinityThread", &[group + 16]);
    assert(first == Some(0) && second == Some(1) && previous_mask == 0, "ke: afinidade de sistema com a anterior e a volta para a de usuario");
    let groups = (call_export("KeQueryActiveGroupCount", &[]), call_export("KeQueryMaximumGroupCount", &[]));
    assert(groups == (Some(1), Some(1)) && call_export("KeQueryGroupAffinity", &[0]).is_some_and(|mask| mask & 1 == 1) && call_export("KeQueryGroupAffinity", &[1]) == Some(0) && call_export("KeQueryNodeMaximumProcessorCount", &[0]) == call_export("KeQueryMaximumProcessorCount", &[]), "ke: grupos e nos de processadores");
    let dpc = guest::alloc_bytes(0x40);
    let number = guest::alloc_bytes(8);
    guest::write_bytes(number, &[0u8; 8]);
    let valid = call_export("KeSetTargetProcessorDpcEx", &[dpc, number]);
    at::<nt::ProcessorNumber>(number).number.set(200);
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
    let (client_id, object_attributes) = (at::<nt::ClientId>(cid), at::<nt::ObjectAttributes>(attributes));
    object_attributes.length.set(0x30);
    object_attributes.attributes.set(0x200);
    let processes = crate::ntos::ps::process::list_active_processes();
    let target = processes.iter().find(|entry| !entry.threads.is_empty());
    let (pid, thread) = target.map_or((0, 0), |entry| (entry.pid, entry.threads[0]));
    client_id.unique_process.set(pid);
    let opened = call_export("ZwOpenProcess", &[handle, 0x1000, attributes, cid]);
    let process_handle = guest::read64(handle);
    assert(target.is_some() && opened == Some(0) && process_handle != 0, "ps: ZwOpenProcess pelo CLIENT_ID");
    let mixed = call_export("ZwOpenProcess", &[handle, 0x1000, 0, 0]);
    client_id.unique_process.set(0x7FFF_FFF0);
    let missing = call_export("ZwOpenProcess", &[handle, 0x1000, attributes, cid]);
    assert(mixed == Some(0xFFFF_FFFF_C000_0030) && missing == Some(0xFFFF_FFFF_C000_000B), "ps: ZwOpenProcess sem nome nem CLIENT_ID e com CLIENT_ID inexistente");
    client_id.unique_process.set(pid);
    client_id.unique_thread.set(if thread != 0 { at::<nt::Ethread>(thread).cid.unique_thread.get() } else { 0 });
    let opened_thread = call_export("ZwOpenThread", &[handle, 0x800, attributes, cid]);
    let thread_handle = guest::read64(handle);
    client_id.unique_process.set(pid + 4);
    let wrong_process = call_export("ZwOpenThread", &[handle + 8, 0x800, attributes, cid]);
    assert(opened_thread == Some(0) && thread_handle != 0 && wrong_process == Some(0xFFFF_FFFF_C000_000B), "ps: ZwOpenThread confere a thread contra o processo pedido");
    let next = call_export("ZwGetNextProcess", &[0, 0x1000, 0x200, 0, handle]);
    let first_process = guest::read64(handle);
    let bad_flags = call_export("ZwGetNextProcess", &[0, 0x1000, 0x200, 2, handle + 8]);
    assert(next == Some(0) && first_process != 0 && bad_flags == Some(0xFFFF_FFFF_C000_000D), "ps: ZwGetNextProcess abre o primeiro processo e recusa Flags invalidos");
    let next_thread = call_export("ZwGetNextThread", &[process_handle, 0, 0x800, 0x200, 0, handle + 8]);
    let next_thread_handle = guest::read64(handle + 8);
    let bad_thread_flags = call_export("ZwGetNextThread", &[process_handle, 0, 0x800, 0x200, 1, block + 0x80]);
    assert(next_thread == Some(0) && next_thread_handle != 0 && bad_thread_flags == Some(0xFFFF_FFFF_C000_000D), "ps: ZwGetNextThread abre a primeira thread do processo e recusa Flags invalidos");
    for opened_handle in [process_handle, thread_handle, first_process, next_thread_handle] {
        call_export("ZwClose", &[opened_handle]);
    }
}

/// Rotina nativa da DPC genérica: conta, sincroniza e avisa o fim.
fn generic_call_routine() -> u64 {
    extern "win64" fn routine(_dpc: u64, context: u64, done: u64, barrier: u64) {
        guest::atomic_u64(context).fetch_add(1, core::sync::atomic::Ordering::SeqCst);
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
    let links = at::<nt::RtlBalancedLinks>(node);
    let (left, right) = (avl_height(links.left_child.get())?, avl_height(links.right_child.get())?);
    let balance = links.balance.get() as i32;
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
            assert(avl_height(at::<nt::RtlAvlTable>(table).balanced_root.right_child.get()).is_some(), "rtl: avl: arvore equilibrada depois de insercoes e remocoes");
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
    let processes = crate::ntos::ps::process::list_active_processes();
    let process = processes.first().map_or(0, |entry| entry.address);
    let acquired = call_export("PsAcquireProcessExitSynchronization", &[process]);
    let held = if process != 0 { at::<nt::Eprocess>(process).rundown_protect.count.get() } else { 0 };
    call_export("PsReleaseProcessExitSynchronization", &[process]);
    assert(process != 0 && acquired == Some(0) && held >= 2 && at::<nt::Eprocess>(process).rundown_protect.count.get() == held - 2, "ps: PsAcquire/ReleaseProcessExitSynchronization na RundownProtect");
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
    assert(queried == Some(0) && at::<nt::MemoryBasicInformation>(info).base_address.get() == address && at::<nt::MemoryBasicInformation>(info).state.get() == 0x1000 && at::<nt::MemoryBasicInformation>(info).protect.get() == 4, "mm: ZwQueryVirtualMemory ve a regiao comitada");
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
    let first = call_export("ZwAllocateLocallyUniqueId", &[luid]).map(|_| luid_at(luid));
    let second = call_export("ZwAllocateLocallyUniqueId", &[luid]).map(|_| luid_at(luid));
    assert(first.is_some_and(|value| value != 0) && first != second, "se: ZwAllocateLocallyUniqueId nunca repete");
}

/// Acessores de ETHREAD/EPROCESS e os campos que a criação preenche.
fn thread_process_queries(assert: Assert) {
    let thread = crate::ntos::ps::process::get_current_thread();
    let process = crate::ntos::ps::process::get_current_process();
    assert(call_export("PsGetCurrentThread", &[]) == Some(thread) && call_export("PsGetCurrentThreadProcess", &[]) == Some(at::<nt::Kthread>(thread).process.get()) && call_export("PsGetCurrentThreadProcessId", &[]) == Some(at::<nt::Ethread>(thread).cid.unique_process.get()), "ps: thread corrente, processo e PID");
    assert(call_export("PsIsThreadTerminating", &[thread]) == Some(0) && call_export("PsGetThreadCreateTime", &[thread]).is_some_and(|time| time != 0) && call_export("PsGetThreadTeb", &[thread]) == Some(at::<nt::Kthread>(thread).teb.get()), "ps: thread viva com CreateTime e Teb do KTHREAD");
    let processes = crate::ntos::ps::process::list_active_processes();
    let system = processes.iter().find(|entry| entry.pid == 4).map_or(0, |entry| entry.address);
    let other = processes.iter().find(|entry| entry.pid != 4).map_or(0, |entry| entry.address);
    assert(system != 0 && call_export("PsIsSystemProcess", &[system]) == Some(1) && call_export("PsGetProcessSessionIdEx", &[system]) == Some(0xFFFF_FFFF) && call_export("PsGetProcessInheritedFromUniqueProcessId", &[system]) == Some(0), "ps: o System nao tem sessao nem criador");
    assert(other == 0 || (call_export("PsIsSystemProcess", &[other]) == Some(0) && call_export("PsGetProcessSequenceNumber", &[other]).is_some_and(|number| system != 0 && number > at::<nt::Eprocess>(system).sequence_number.get()) && call_export("PsGetProcessPriorityClass", &[other]) == Some(2)), "ps: numero de sequencia crescente e classe de prioridade normal");
    assert(call_export("PsIsProcessBeingDebugged", &[process]) == Some((at::<nt::Eprocess>(process).debug_port.get() != 0) as u64), "ps: processo depurado segue a DebugPort");
}

/// ZwTraceControl: início, consulta, duplicata, parada e validações das
/// sessões de log.
fn etw_trace_control(assert: Assert) {
    let block = guest::alloc_bytes(0x200);
    guest::write_bytes(block, &[0; 0x200]);
    let (properties, returned, name) = (block, block + 0x180, block + 0x100);
    let text: Vec<u16> = "OpenNT-Teste".encode_utf16().collect();
        guest::write_bytes(name, &text.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
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

/// RtlCreate/Set*SecurityDescriptor, RtlCreateAcl, RtlAddAccessAllowedAce[Ex],
/// RtlInitializeSid/SubAuthoritySid/LengthRequiredSid.
fn rtl_security_descriptors(assert: Assert) {
    let block = guest::alloc_bytes(0x400);
    guest::write_bytes(block, &[0xAA; 0x400]);
    let (sd, acl_buf, sid_buf, authority) = (block, block + 0x40, block + 0x100, block + 0x180);
    // SID S-1-5-32-544 (BUILTIN\Administradores): autoridade NT (5), subs 32,544.
    guest::write_bytes(authority, &[0, 0, 0, 0, 0, 5]);
    assert(call_export("RtlLengthRequiredSid", &[2]) == Some(16) && call_export("RtlLengthRequiredSid", &[0]) == Some(8), "rtl: RtlLengthRequiredSid");
    let init = call_export("RtlInitializeSid", &[sid_buf, authority, 2]);
    let sub0 = call_export("RtlSubAuthoritySid", &[sid_buf, 0]).unwrap_or(0);
    let sub1 = call_export("RtlSubAuthoritySid", &[sid_buf, 1]).unwrap_or(0);
    guest::write32(sub0, 32);
    guest::write32(sub1, 544);
    assert(init == Some(0) && at::<nt::Sid>(sid_buf).revision.get() == 1 && at::<nt::Sid>(sid_buf).sub_authority_count.get() == 2 && sub0 == sid_buf + 8 && sub1 == sid_buf + 12 && at::<nt::Sid>(sid_buf).identifier_authority.value[5].get() == 5, "rtl: RtlInitializeSid + RtlSubAuthoritySid");
    // Descritor absoluto vazio, revisão 1.
    let created = call_export("RtlCreateSecurityDescriptor", &[sd, 1]);
    let bad_rev = call_export("RtlCreateSecurityDescriptor", &[sd + 0x20, 2]);
    assert(created == Some(0) && at::<nt::SecurityDescriptor>(sd).revision.get() == 1 && at::<nt::SecurityDescriptor>(sd).control.get() == 0 && bad_rev == Some(0xFFFF_FFFF_C000_0058), "rtl: RtlCreateSecurityDescriptor");
    // ACL vazia e uma ACE de acesso permitido.
    let acl_created = call_export("RtlCreateAcl", &[acl_buf, 0x80, 2]);
    let small = call_export("RtlCreateAcl", &[acl_buf + 0x200, 4, 2]);
    let added = call_export("RtlAddAccessAllowedAce", &[acl_buf, 2, 0x1F01FF, sid_buf]);
    let ace = acl_buf + 8;
    let ace_size = 8 + 8 + 2 * 4; // header+mask + SID(8+2*4)
    assert(acl_created == Some(0) && small == Some(0xFFFF_FFFF_C000_0023) && added == Some(0) && at::<nt::Acl>(acl_buf).ace_count.get() == 1 && at::<nt::AccessAllowedAce>(ace).header.ace_type.get() == 0 && at::<nt::AccessAllowedAce>(ace).header.ace_size.get() == ace_size as u16 && at::<nt::AccessAllowedAce>(ace).mask.get() == 0x1F01FF, "rtl: RtlCreateAcl + RtlAddAccessAllowedAce");
    // Liga a DACL ao descritor.
    let set = call_export("RtlSetDaclSecurityDescriptor", &[sd, 1, acl_buf, 0]);
    assert(set == Some(0) && at::<nt::SecurityDescriptor>(sd).control.get() & 0x0004 != 0 && at::<nt::SecurityDescriptor>(sd).dacl.get() == acl_buf, "rtl: RtlSetDaclSecurityDescriptor liga a DACL");
}

/// Auxiliares de drivers: mapeamento do FILE_OBJECT, referência segura de
/// objeto e as consultas de energia/boot/portabilidade.
fn driver_helper_exports(assert: Assert) {
    let mapping = call_export("IoGetFileObjectGenericMapping", &[]).unwrap_or(0);
    assert(mapping != 0 && at::<nt::GenericMapping>(mapping).generic_read.get() == 0x0012_0089 && at::<nt::GenericMapping>(mapping).generic_all.get() == 0x001F_01FF && call_export("IoGetFileObjectGenericMapping", &[]) == Some(mapping), "io: IoGetFileObjectGenericMapping (valores reais, em cache)");
    let out = guest::alloc_bytes(8);
    guest::write8(out, 0xFF);
    let portable = call_export("RtlCheckPortableOperatingSystem", &[out]);
    assert(call_export("PoEnergyEstimationEnabled", &[]) == Some(0) && call_export("ExIsSoftBoot", &[]) == Some(0) && portable == Some(0) && guest::read8(out) == 0 && call_export("ZwFlushKey", &[0x1C8]) == Some(0), "misc: energia/soft-boot/portabilidade/flush");
    // ObReferenceObjectSafe/DeferDelete sobre o processo corrente (objeto vivo).
    let process = crate::ntos::ps::process::get_current_process();
    let before = crate::ntos::ps::process::reference_count(process).unwrap_or(0);
    let safe = call_export("ObReferenceObjectSafe", &[process]);
    let held = crate::ntos::ps::process::reference_count(process).unwrap_or(0);
    call_export("ObDereferenceObjectDeferDelete", &[process]);
    assert(process != 0 && safe == Some(1) && held == before + 1 && crate::ntos::ps::process::reference_count(process).unwrap_or(0) == before, "ob: ObReferenceObjectSafe + ObDereferenceObjectDeferDelete ajustam a referência");
}

/// Exports que habilitam o watchdog.sys real: status tolerados de WMI, console
/// e depuração; o ZwFlushBuffersFileEx roteado; e a captura de contexto (sem
/// contexto nativo ativo no self-test, só marca ContextFlags = CONTEXT_FULL).
fn io_diagnostics_exports(assert: Assert) {
    let ntstatus = |result: Option<u64>| result.map(|value| value as u32);
    let context = guest::alloc_bytes(0x4D0);
    at::<nt::Context>(context).context_flags.set(0);
    let captured = call_export("RtlCaptureContext", &[context]);
    let io_status = guest::alloc_bytes(16);
    assert(
        call_export("IoRaiseInformationalHardError", &[0, 0, 0]) == Some(0)
            && ntstatus(call_export("IoWMIOpenBlock", &[0, 0, 0])) == Some(0xC000_0295)
            && ntstatus(call_export("IoWMIQueryAllData", &[0, 0, 0])) == Some(0xC000_0295)
            && call_export("RtlGetActiveConsoleId", &[]) == Some(0)
            && ntstatus(call_export("ZwSystemDebugControl", &[0])) == Some(0xC000_0002)
            && captured == Some(0)
            && at::<nt::Context>(context).context_flags.get() == 0x0010_000B,
        "watchdog: WMI/console/debug tolerados + RtlCaptureContext marca o CONTEXT",
    );
    assert(ntstatus(call_export("ZwFlushBuffersFileEx", &[0x7FF0, 0, 0, 0, io_status])) == Some(0xC000_0008), "watchdog: ZwFlushBuffersFileEx valida o handle");
}

/// Exports do BasicDisplay.sys real: bit-scan, _strnicmp, bloqueio de sono e os
/// x86Bios (sem VBIOS emulado, falham de forma tolerada).
fn x86bios_sleep_misc_exports(assert: Assert) {
    let ntstatus = |result: Option<u64>| result.map(|value| value as u32);
    let signed = |result: Option<u64>| result.map(|value| value as i64);
    let (first, second) = (guest::alloc_bytes(8), guest::alloc_bytes(8));
    guest::write_bytes(first, b"Abc\0");
    guest::write_bytes(second, b"aBc\0");
    let equal = call_export("_strnicmp", &[first, second, 3]);
    guest::write_bytes(second, b"aBd\0");
    let less = signed(call_export("_strnicmp", &[first, second, 3]));
    let handle = call_export("PoDisableSleepStates", &[1]).unwrap_or(0);
    assert(
        call_export("RtlFindLeastSignificantBit", &[0x100]) == Some(8)
            && signed(call_export("RtlFindLeastSignificantBit", &[0])) == Some(-1)
            && equal == Some(0)
            && less == Some(-1)
            && handle != 0
            && call_export("PoReenableSleepStates", &[handle]) == Some(0)
            && call_export("x86BiosCall", &[0, 0]) == Some(0)
            && ntstatus(call_export("x86BiosReadMemory", &[0, 0, 0, 0])) == Some(0xC000_0002),
        "basicdisplay: bit-scan/_strnicmp/sono/x86Bios",
    );
}

/// Captura/validação/deassign de SECURITY_DESCRIPTOR (grupo se-descriptor).
fn se_descriptor_exports(assert: Assert) {
    // SD self-relative mínimo: Revision=1, Control=SELF_RELATIVE, sem componentes.
    let descriptor = guest::alloc_bytes(20);
        guest::write_bytes(descriptor, &[0u8; 20]);
    let relative = at::<nt::SecurityDescriptorRelative>(descriptor);
    relative.revision.set(1);
    relative.control.set(0x8000);
    let output = guest::alloc_bytes(8);
    let captured = call_export("SeCaptureSecurityDescriptor", &[descriptor, 0, 0, 0, output]);
    let copy = guest::read64(output);
    assert(captured == Some(0), "se: SeCaptureSecurityDescriptor retorna sucesso");
    assert(copy != 0 && copy != descriptor && at::<nt::SecurityDescriptorRelative>(copy).revision.get() == 1, "se: SeCaptureSecurityDescriptor devolve copia self-relative");
    assert(call_export("SeValidSecurityDescriptor", &[20, copy]) == Some(1), "se: SeValidSecurityDescriptor aceita o SD valido");
    assert(call_export("SeValidSecurityDescriptor", &[4, descriptor]) == Some(0), "se: SeValidSecurityDescriptor rejeita tamanho pequeno");
    assert(call_export("SeDeassignSecurity", &[output]) == Some(0) && guest::read64(output) == 0, "se: SeDeassignSecurity libera e zera");
    assert(call_export("SeCaptureSecurityDescriptor", &[0, 0, 0, 0, output]) == Some(0) && guest::read64(output) == 0, "se: SeCaptureSecurityDescriptor com NULL devolve NULL");
}

fn se_token_info_exports(assert: Assert) {
    use crate::ntos::ps::process;
    use crate::ntos::se::token::tokens;

    let current = process::get_current_process();
    let primary = process::get_primary_token(current).unwrap_or(0);
    let refs = |token: u64| tokens::get(token).map_or(0, |token| token.refs);
    let (kind, level, baseline) = tokens::with(primary, |token| (token.kind as u64, token.impersonation_level as u64, token.refs)).unwrap_or((0, 0, 0));

    // Acessores de campo: tipo, nível, não restrito, admin (SYSTEM carrega S-1-5-32-544).
    assert(
        primary != 0
            && call_export("SeTokenType", &[primary]) == Some(kind)
            && call_export("SeTokenImpersonationLevel", &[primary]) == Some(level)
            && call_export("SeTokenIsRestricted", &[primary]) == Some(0)
            && call_export("SeTokenIsAdmin", &[primary]) == Some(1),
        "se-token-info: tipo, nivel, restricao e admin do token primario",
    );

    // SeQueryInformationToken alocador: TOKEN_USER (classe 1).
    let out = guest::alloc_bytes(8);
    assert(call_export("SeQueryInformationToken", &[primary, 1, out]) == Some(0) && guest::read64(out) != 0, "se-token-info: SeQueryInformationToken classe TokenUser aloca");
    let user = guest::read64(out);
    // User.Sid aponta para o corpo do SID em +16, com revisão 1.
    assert(user != 0 && at::<nt::TokenUser>(user).user.sid.get() == user + 16 && at::<nt::Sid>(user + 16).revision.get() == 1, "se-token-info: TOKEN_USER aponta para o corpo do SID");
    guest::free_bytes(user);

    // TOKEN_PRIVILEGES (classe 3): o token do Sistema não tem privilégios inventados.
    assert(call_export("SeQueryInformationToken", &[primary, 3, out]) == Some(0) && guest::read64(out) != 0, "se-token-info: SeQueryInformationToken classe TokenPrivileges aloca");
    let privileges = guest::read64(out);
    assert(privileges != 0 && at::<nt::TokenPrivileges>(privileges).privilege_count.get() == 0, "se-token-info: TOKEN_PRIVILEGES do Sistema vazio");
    guest::free_bytes(privileges);

    // TOKEN_STATISTICS (classe 10): 56 bytes, Id do token no início.
    assert(call_export("SeQueryInformationToken", &[primary, 10, out]) == Some(0) && guest::read64(out) != 0, "se-token-info: SeQueryInformationToken classe TokenStatistics aloca");
    let statistics = guest::read64(out);
    assert(statistics != 0 && Some(luid_at(at::<nt::TokenStatistics>(statistics).token_id.address())) == tokens::with(primary, |token| token.id), "se-token-info: TOKEN_STATISTICS carrega o TokenId");
    guest::free_bytes(statistics);

    // Classe não implementada → STATUS_INVALID_INFO_CLASS.
    assert(call_export("SeQueryInformationToken", &[primary, 7, out]) == Some(0xFFFF_FFFF_C000_0003), "se-token-info: classe nao suportada recusada");

    // SeQuerySecurityAttributesTokenAccessInformation: estrutura vazia bem-formada.
    assert(call_export("SeQuerySecurityAttributesTokenAccessInformation", &[primary, out]) == Some(0) && guest::read64(out) != 0, "se-token-info: AccessInformation aloca o conjunto de atributos");
    let attributes = guest::read64(out);
    assert(attributes != 0 && at::<nt::TokenSecurityAttributesInformation>(attributes).version.get() == 1 && at::<nt::TokenSecurityAttributesInformation>(attributes).attribute_count.get() == 0, "se-token-info: conjunto de atributos vazio (Version=1, Count=0)");
    guest::free_bytes(attributes);

    // SeSecurityAttributePresent: o conjunto vazio do Sistema não tem SYSAPPID.
    let name = "WIN://SYSAPPID";
    let utf16: alloc::vec::Vec<u16> = name.encode_utf16().collect();
    let text = guest::alloc_bytes(utf16.len() as u64 * 2);
        guest::write_bytes(text, &utf16.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    let unicode_string = guest::alloc_bytes(16);
    let attribute_name = at::<nt::UnicodeString>(unicode_string);
    attribute_name.length.set(utf16.len() as u16 * 2);
    attribute_name.maximum_length.set(utf16.len() as u16 * 2);
    attribute_name.buffer.set(text);
    assert(call_export("SeSecurityAttributePresent", &[primary, unicode_string]) == Some(0), "se-token-info: atributo ausente devolve FALSE");

    // Acessores e produtores não alteram a contagem de referências do token.
    assert(refs(primary) == baseline, "se-token-info: acessores nao alteram a referencia do token");

    guest::free_bytes(unicode_string);
    guest::free_bytes(text);
    guest::free_bytes(out);
}


fn po_fx_exports(assert: Assert) {
    use crate::ntos::mm::guest_memory as guest;

    // Fake PO_FX_DEVICE_V1: Version=1, ComponentCount=1, callbacks left NULL.
    let pdo = guest::alloc_bytes(0x400);
    let device = guest::alloc_bytes(0x80);
    let fx_device = at::<nt::PoFxDeviceV1>(device);
    fx_device.version.set(1);
    fx_device.component_count.set(1);
    fx_device.device_context.set(0); // callbacks NULL (bloco zerado)

    let handle_cell = guest::alloc_bytes(8);
    let status = call_export("PoFxRegisterDevice", &[pdo, device, handle_cell]);
    let handle = guest::read64(handle_cell);
    assert(
        status == Some(0) && handle != 0,
        "po-fx: PoFxRegisterDevice devolve STATUS_SUCCESS e um POHANDLE",
    );
    assert(
        handle != 0 && at::<nt::PopFxDevice>(handle).component_count.get() == 1,
        "po-fx: ComponentCount gravado no handle em +0x33c",
    );

    // Device powers up; component 0 activates and idles without faulting.
    call_export("PoFxStartDevicePowerManagement", &[handle]);
    assert(
        call_export("PoFxActivateComponent", &[handle, 0, 0]).is_some()
            && call_export("PoFxIdleComponent", &[handle, 0, 0]).is_some(),
        "po-fx: activar/ociar o componente 0 tem sucesso",
    );

    // No PEP services PowerControl; perf/crashdump are unsupported.
    assert(
        call_export("PoFxPowerControl", &[handle, 0, 0, 0, 0, 0, 0]).map(|s| s as u32)
            == Some(0xC000_0002),
        "po-fx: PoFxPowerControl sem PEP -> STATUS_NOT_IMPLEMENTED",
    );
    assert(
        call_export("PoFxRegisterCrashdumpDevice", &[handle, 0]).map(|s| s as u32)
            == Some(0xC000_00BB),
        "po-fx: PoFxRegisterCrashdumpDevice -> STATUS_NOT_SUPPORTED",
    );

    // Unregister releases the handle without faulting.
    assert(
        call_export("PoFxUnregisterDevice", &[handle]).is_some(),
        "po-fx: PoFxUnregisterDevice aceita o handle",
    );

    guest::free_bytes(handle_cell);
    guest::free_bytes(device);
    guest::free_bytes(pdo);
}


fn se_assign_exports(assert: Assert) {
    let block = guest::alloc_bytes(0x600);
        guest::write_bytes(block, &[0u8; 0x600]);
    // GENERIC_MAPPING de arquivo (Read/Write/Execute/All).
    let map = block;
    let generic_mapping = at::<nt::GenericMapping>(map);
    generic_mapping.generic_read.set(0x0012_0089);
    generic_mapping.generic_write.set(0x0012_0116);
    generic_mapping.generic_execute.set(0x0012_00A0);
    generic_mapping.generic_all.set(0x001F_01FF);
    // SID S-1-5-18 (LocalSystem): autoridade NT (5), subautoridade 18.
    let authority = block + 0x10;
    guest::write_bytes(authority, &[0, 0, 0, 0, 0, 5]);
    let sid_sys = block + 0x20;
    call_export("RtlInitializeSid", &[sid_sys, authority, 1]);
    let sub0 = call_export("RtlSubAuthoritySid", &[sid_sys, 0]).unwrap_or(0);
    guest::write32(sub0, 18);
    // DACL explícita: concede 0x1F01FF ao SYSTEM.
    let acl = block + 0x40;
    call_export("RtlCreateAcl", &[acl, 0x80, 2]);
    call_export("RtlAddAccessAllowedAce", &[acl, 2, 0x001F_01FF, sid_sys]);
    // Descritor explícito absoluto: owner+group SYSTEM, DACL acima
    // (RtlSetGroupSecurityDescriptor não é exportado; escreve-se o Group@0x10).
    let explicit = block + 0xC0;
    call_export("RtlCreateSecurityDescriptor", &[explicit, 1]);
    call_export("RtlSetOwnerSecurityDescriptor", &[explicit, sid_sys, 0]);
    at::<nt::SecurityDescriptor>(explicit).group.set(sid_sys);
    call_export("RtlSetDaclSecurityDescriptor", &[explicit, 1, acl, 0]);

    // SeAssignSecurityEx: parent NULL, AutoInherit DACL+SACL, subject NULL.
    let out = block + 0x100;
    let assigned = call_export("SeAssignSecurityEx", &[0, explicit, out, 0, 0, 3, 0, map, 0]);
    let newsd = guest::read64(out);
    let newlen = call_export("RtlLengthSecurityDescriptor", &[newsd]).unwrap_or(0);
    assert(
        assigned == Some(0) && newsd != 0 && newsd != explicit && at::<nt::SecurityDescriptorRelative>(newsd).revision.get() == 1 && at::<nt::SecurityDescriptorRelative>(newsd).control.get() & 0x8000 != 0,
        "se-assign: SeAssignSecurityEx produz um SD self-relative",
    );
    assert(
        call_export("SeValidSecurityDescriptor", &[newlen, newsd]) == Some(1) && at::<nt::SecurityDescriptorRelative>(newsd).control.get() & 0x0004 != 0,
        "se-assign: o SD atribuido e valido e carrega a DACL",
    );
    // Forma legada de 7 args produz um SD igualmente valido.
    let out_legacy = block + 0x108;
    let legacy = call_export("SeAssignSecurity", &[0, explicit, out_legacy, 0, 0, map, 0]);
    let legacy_sd = guest::read64(out_legacy);
    let legacy_len = call_export("RtlLengthSecurityDescriptor", &[legacy_sd]).unwrap_or(0);
    assert(
        legacy == Some(0) && legacy_sd != 0 && call_export("SeValidSecurityDescriptor", &[legacy_len, legacy_sd]) == Some(1),
        "se-assign: SeAssignSecurity (legada) tambem valida",
    );
    call_export("SeDeassignSecurity", &[out_legacy]);

    // SeQuerySecurityDescriptorInfo: mede (BUFFER_TOO_SMALL) e copia OWNER|GROUP|DACL.
    let info_ptr = block + 0x110;
    let length_ptr = block + 0x118;
    let qbuf = block + 0x120;
    guest::write32(info_ptr, 7);
    guest::write32(length_ptr, 8);
    let short = call_export("SeQuerySecurityDescriptorInfo", &[info_ptr, qbuf, length_ptr, out]);
    let needed = guest::read32(length_ptr);
    assert(
        short == Some(0xFFFF_FFFF_C000_0023) && needed == newlen as u32,
        "se-assign: SeQuerySecurityDescriptorInfo informa o LengthNeeded",
    );
    let full = call_export("SeQuerySecurityDescriptorInfo", &[info_ptr, qbuf, length_ptr, out]);
    assert(
        full == Some(0) && at::<nt::SecurityDescriptorRelative>(qbuf).revision.get() == 1 && at::<nt::SecurityDescriptorRelative>(qbuf).control.get() & 0x8000 != 0 && at::<nt::SecurityDescriptorRelative>(qbuf).control.get() & 0x0004 != 0,
        "se-assign: SeQuerySecurityDescriptorInfo copia o descritor pedido",
    );

    // SeSetSecurityDescriptorInfo: troca a DACL do objeto (*out) por outra mascara.
    let mod_acl = block + 0x200;
    call_export("RtlCreateAcl", &[mod_acl, 0x80, 2]);
    call_export("RtlAddAccessAllowedAce", &[mod_acl, 2, 0x0012_0089, sid_sys]);
    let mod_sd = block + 0x280;
    call_export("RtlCreateSecurityDescriptor", &[mod_sd, 1]);
    call_export("RtlSetDaclSecurityDescriptor", &[mod_sd, 1, mod_acl, 0]);
    guest::write32(info_ptr, 4);
    let before_set = guest::read64(out);
    let set = call_export("SeSetSecurityDescriptorInfo", &[0, info_ptr, mod_sd, out, 0, map]);
    let updated = guest::read64(out);
    let updated_len = call_export("RtlLengthSecurityDescriptor", &[updated]).unwrap_or(0);
    let dacl_off = if updated != 0 { at::<nt::SecurityDescriptorRelative>(updated).dacl.get() as u64 } else { 0 };
    assert(
        set == Some(0) && updated != 0 && updated != before_set,
        "se-assign: SeSetSecurityDescriptorInfo troca o SD do objeto",
    );
    assert(
        call_export("SeValidSecurityDescriptor", &[updated_len, updated]) == Some(1) && dacl_off != 0 && at::<nt::AccessAllowedAce>(updated + dacl_off + 8).mask.get() == 0x0012_0089,
        "se-assign: a nova DACL carrega a mascara da modificacao",
    );
    call_export("SeDeassignSecurity", &[out]);
    guest::free_bytes(block);
}


fn se_access_exports(assert: Assert) {
    use crate::ntos::ps::process;
    use crate::ntos::se::token::tokens;

    let refs = |token: u64| tokens::get(token).map_or(0, |token| token.refs);
    let primary = process::get_primary_token(process::get_current_process()).unwrap_or(0);
    let baseline = refs(primary);

    // SID S-1-5-18 (NT AUTHORITY\SYSTEM), o usuário do token de boot.
    let system_sid: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];

    // SD self-relative: owner=SYSTEM@20, DACL@32 com 1 ACCESS_ALLOWED_ACE
    // (mask=0x1FF, SID=SYSTEM). Control = SELF_RELATIVE | DACL_PRESENT.
    let descriptor = guest::alloc_bytes(0x80);
    let mut bytes = alloc::vec![0u8; 60];
    bytes[0] = 1; // Revision
    bytes[2..4].copy_from_slice(&0x8004u16.to_le_bytes()); // Control
    bytes[4..8].copy_from_slice(&20u32.to_le_bytes()); // Owner offset
    bytes[16..20].copy_from_slice(&32u32.to_le_bytes()); // Dacl offset
    bytes[20..32].copy_from_slice(&system_sid); // Owner SID
    bytes[32] = 2; // ACL revision
    bytes[34..36].copy_from_slice(&28u16.to_le_bytes()); // AclSize = 8 + 20
    bytes[36..38].copy_from_slice(&1u16.to_le_bytes()); // AceCount
    bytes[40] = 0; // ACCESS_ALLOWED_ACE_TYPE
    bytes[42..44].copy_from_slice(&20u16.to_le_bytes()); // AceSize = 8 + 12
    bytes[44..48].copy_from_slice(&0x1FFu32.to_le_bytes()); // AccessMask
    bytes[48..60].copy_from_slice(&system_sid); // Ace SID
    guest::write_bytes(descriptor, &bytes);

    // GENERIC_MAPPING estilo arquivo e saídas.
    let mapping = guest::alloc_bytes(16);
    let generic_mapping = at::<nt::GenericMapping>(mapping);
        generic_mapping.generic_read.set(0x0012_0089);
    generic_mapping.generic_write.set(0x0012_0116);
    generic_mapping.generic_execute.set(0x0012_00A0);
    generic_mapping.generic_all.set(0x001F_01FF);
    let context = guest::alloc_bytes(0x20);
    let granted = guest::alloc_bytes(4);
    let status = guest::alloc_bytes(4);
    assert(call_export("SeCaptureSubjectContext", &[context]) == Some(0) && refs(primary) == baseline + 1, "se-access: subject context captura o token primario");

    // UserMode (Mode=1), SubjLocked=1, Privileges=NULL: concede 1.
    let allow = call_export("SeAccessCheck", &[descriptor, context, 1, 1, 0, 0, mapping, 1, granted, status]);
    assert(allow == Some(1) && guest::read32(status) == 0 && guest::read32(granted) & 1 != 0, "se-access: SeAccessCheck concede o acesso pedido ao dono");
    // DELETE (0x10000) não está na DACL nem nos direitos de dono: nega.
    guest::write32(status, 0xFFFF);
    let deny = call_export("SeAccessCheck", &[descriptor, context, 1, 0x10000, 0, 0, mapping, 1, granted, status]);
    assert(deny == Some(0) && guest::read32(status) == 0xC000_0022, "se-access: SeAccessCheck nega o direito ausente");
    // KernelMode (Mode=0) concede sem avaliar a DACL; SD nulo em UserMode nega.
    guest::write32(granted, 0);
    let kernel = call_export("SeAccessCheck", &[descriptor, context, 1, 3, 0, 0, mapping, 0, granted, status]);
    let null_sd = call_export("SeAccessCheck", &[0, context, 1, 1, 0, 0, mapping, 1, granted, status]);
    assert(kernel == Some(1) && null_sd == Some(0) && guest::read32(status) == 0xC000_0022, "se-access: KernelMode concede, SD nulo nega");

    // SeAccessCheckFromState: TOKEN_ACCESS_INFORMATION montado à mão (SidHash
    // com SidCount=1 e SidAttr apontando [ {SYSTEM, enabled} ]).
    let sid_buffer = guest::alloc_bytes(12);
    guest::write_bytes(sid_buffer, &system_sid);
    let sid_attr = guest::alloc_bytes(0x10);
    let sid_and_attributes = at::<nt::SidAndAttributes>(sid_attr);
    sid_and_attributes.sid.set(sid_buffer);
    sid_and_attributes.attributes.set(0x04); // SE_GROUP_ENABLED
    let sid_hash = guest::alloc_bytes(0x110);
    let hash = at::<nt::SidAndAttributesHash>(sid_hash);
    hash.sid_count.set(1);
    hash.sid_attr.set(sid_attr);
    let access_info = guest::alloc_bytes(0x58);
    at::<nt::TokenAccessInformation>(access_info).sid_hash.set(sid_hash);
    let from_state = call_export("SeAccessCheckFromState", &[descriptor, access_info, 0, 1, 0, 0, mapping, 1, granted, status]);
    assert(from_state == Some(1) && guest::read32(status) == 0 && guest::read32(granted) & 1 != 0, "se-access: SeAccessCheckFromState usa o TOKEN_ACCESS_INFORMATION");

    // SePrivilegeCheck: PRIVILEGE_SET de 1 privilégio (LUID 0x1234 inexistente),
    // ALL_NECESSARY. KernelMode concede; UserMode nega (não detido).
    let privilege_set = guest::alloc_bytes(0x20);
    let required = at::<nt::PrivilegeSet>(privilege_set);
    required.privilege_count.set(1);
    required.control.set(1); // ALL_NECESSARY
    required.privilege[0].luid.low_part.set(0x1234);
    required.privilege[0].attributes.set(2); // ENABLED
    assert(call_export("SePrivilegeCheck", &[privilege_set, context, 0]) == Some(1) && call_export("SePrivilegeCheck", &[privilege_set, context, 1]) == Some(0), "se-access: SePrivilegeCheck kernel concede, usuario sem o privilegio nega");

    assert(call_export("SeReleaseSubjectContext", &[context]) == Some(0) && refs(primary) == baseline, "se-access: subject context devolve a referencia");

    // SeAppendPrivileges: conjunto inline vazio recebe 2 privilégios; depois
    // SeFreePrivileges libera o PRIVILEGE_SET alocado e ignora o inline.
    let access_state = guest::alloc_bytes(0xA0);
        guest::write_bytes(access_state, &[0u8; 0xA0]);
    let aux_data = guest::alloc_bytes(0x20);
    let state = at::<nt::AccessState>(access_state);
    state.aux_data.set(aux_data);
    let append = guest::alloc_bytes(0x20);
    let (appended_set, second_privilege) = (at::<nt::PrivilegeSet>(append), at::<nt::LuidAndAttributes>(append + 8 + nt::LuidAndAttributes::SIZE));
    appended_set.privilege_count.set(2);
    appended_set.privilege[0].luid.low_part.set(20);
    appended_set.privilege[0].attributes.set(2);
    second_privilege.luid.low_part.set(21);
    second_privilege.attributes.set(1);
    let appended = call_export("SeAppendPrivileges", &[access_state, append]);
    assert(appended == Some(0) && state.privileges.initial_privilege_set.privilege_count.get() == 2 && luid_at(state.privileges.initial_privilege_set.privilege[0].luid.address()) == 20 && luid_at(state.privileges.initial_privilege_set.privilege[1].luid.address()) == 21, "se-access: SeAppendPrivileges cresce o conjunto inline");
    assert(state.privileges_allocated.get() == 0 && crate::ntos::mm::guest_memory::owns_allocation(append), "se-access: append inline nao aloca pool");
    call_export("SeFreePrivileges", &[append]);
    call_export("SeFreePrivileges", &[access_state + 0x50]); // inline: no-op seguro
    assert(!crate::ntos::mm::guest_memory::owns_allocation(append), "se-access: SeFreePrivileges libera o conjunto alocado e ignora o inline");

    for buffer in [descriptor, mapping, context, granted, status, sid_buffer, sid_attr, sid_hash, access_info, privilege_set, access_state, aux_data] {
        guest::free_bytes(buffer);
    }
}


fn rtl_crt_extended_exports(assert: Assert) {
    use crate::ntos::init::exports;
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::rtl::guest_strings;

    // ---- RtlMapGenericMask: GENERIC_READ -> direitos específicos ----------
    let mask = guest::alloc_bytes(4);
    let mapping = guest::alloc_bytes(16);
    guest::write32(mask, 0x8000_0000); // GENERIC_READ
    at::<nt::GenericMapping>(mapping).generic_read.set(0x0012_0089);
    call_export("RtlMapGenericMask", &[mask, mapping]);
    assert(guest::read32(mask) == 0x0012_0089, "rtl: RtlMapGenericMask aplica GenericRead e limpa genéricos");

    // ---- RtlSubAuthorityCountSid / RtlCopyLuid ----------------------------
    let sid = guest::alloc_bytes(16);
    at::<nt::Sid>(sid).sub_authority_count.set(3);
    assert(call_export("RtlSubAuthorityCountSid", &[sid]) == Some(sid + 1), "rtl: RtlSubAuthorityCountSid = &Sid->SubAuthorityCount");
    let luid_source = guest::alloc_bytes(8);
    let luid_dest = guest::alloc_bytes(8);
    let source_luid = at::<nt::Luid>(luid_source);
    source_luid.low_part.set(0x5566_7788);
    source_luid.high_part.set(0x1122_3344);
    call_export("RtlCopyLuid", &[luid_dest, luid_source]);
    assert(luid_at(luid_dest) == 0x1122_3344_5566_7788, "rtl: RtlCopyLuid copia os 8 bytes");

    // ---- informação de sistema / produto ----------------------------------
    let product_type = guest::alloc_bytes(4);
    assert(call_export("RtlGetNtProductType", &[product_type]) == Some(1) && guest::read32(product_type) == 1, "rtl: RtlGetNtProductType = WinNt, TRUE");
    assert(call_export("RtlGetSuiteMask", &[]) == Some(0) && call_export("RtlIsMultiSessionSku", &[]) == Some(0), "rtl: SuiteMask 0 e MultiSession FALSE");
    let edition = guest::alloc_bytes(4);
    assert(call_export("RtlGetProductInfo", &[10, 0, 0, 0, edition]) == Some(1) && guest::read32(edition) == 0x30, "rtl: RtlGetProductInfo = PROFESSIONAL, TRUE");

    // ---- RtlHashUnicodeString: X65599 de "ABC" ----------------------------
    let hash_text = guest::alloc_bytes(8);
    guest_strings::write_wide_string(hash_text, "ABC");
    let hash_string = guest::alloc_bytes(16);
    let hashed = at::<nt::UnicodeString>(hash_string);
    hashed.length.set(6); // 3 unidades
    hashed.buffer.set(hash_text);
    let hash_out = guest::alloc_bytes(4);
    assert(call_export("RtlHashUnicodeString", &[hash_string, 0, 0, hash_out]) == Some(0) && guest::read32(hash_out) == 0x2044_0042, "rtl: RtlHashUnicodeString X65599 de \"ABC\"");
    assert(call_export("RtlHashUnicodeString", &[hash_string, 0, 2, hash_out]).map(|status| status as u32) == Some(0xC000_000D), "rtl: RtlHashUnicodeString Alg>1 -> INVALID_PARAMETER");

    // ---- RtlInt64ToUnicodeString: valor > 2^32 (prova 64 bits) ------------
    let number_buffer = guest::alloc_bytes(64);
    let number_string = guest::alloc_bytes(16);
    let number = at::<nt::UnicodeString>(number_string);
    number.maximum_length.set(64);
    number.buffer.set(number_buffer);
    assert(call_export("RtlInt64ToUnicodeString", &[0x1_0000_0000, 10, number_string]) == Some(0) && number.length.get() == 20 && guest_strings::read_wide_string(number_buffer) == "4294967296", "rtl: RtlInt64ToUnicodeString formata 64 bits");

    // ---- RtlInt64ToUnicodeString: BUFFER_OVERFLOW -------------------------
    let tiny_string = guest::alloc_bytes(16);
    let tiny = at::<nt::UnicodeString>(tiny_string);
    tiny.maximum_length.set(4); // só 1 char + NUL
    tiny.buffer.set(guest::alloc_bytes(8));
    assert(call_export("RtlInt64ToUnicodeString", &[123456, 10, tiny_string]).map(|status| status as u32) == Some(0x8000_0005), "rtl: RtlInt64ToUnicodeString sem espaço -> BUFFER_OVERFLOW");

    // ---- RtlAppendStringToString (ANSI contada) ---------------------------
    let dest_buffer = guest::alloc_bytes(8);
    guest::write_bytes(dest_buffer, b"AB");
    let dest_ansi = guest::alloc_bytes(16);
    let destination = at::<nt::String>(dest_ansi);
    destination.length.set(2);
    destination.maximum_length.set(8);
    destination.buffer.set(dest_buffer);
    let src_buffer = guest::alloc_bytes(8);
    guest::write_bytes(src_buffer, b"CD");
    let src_ansi = guest::alloc_bytes(16);
    let source = at::<nt::String>(src_ansi);
    source.length.set(2);
    source.maximum_length.set(2);
    source.buffer.set(src_buffer);
    assert(call_export("RtlAppendStringToString", &[dest_ansi, src_ansi]) == Some(0) && destination.length.get() == 4 && guest::read_bytes(dest_buffer, 4) == b"ABCD", "rtl: RtlAppendStringToString concatena ANSI");

    // ---- RtlAnsiCharToUnicodeChar (avança o ponteiro) ---------------------
    let ansi_source = guest::alloc_bytes(2);
    guest::write8(ansi_source, b'A');
    let pointer_field = guest::alloc_bytes(8);
    guest::write64(pointer_field, ansi_source);
    assert(call_export("RtlAnsiCharToUnicodeChar", &[pointer_field]) == Some(0x41) && guest::read64(pointer_field) == ansi_source + 1, "rtl: RtlAnsiCharToUnicodeChar traduz e avança");

    // ---- RtlFormatCurrentUserKeyPath --------------------------------------
    let user_key = guest::alloc_bytes(16);
    assert(call_export("RtlFormatCurrentUserKeyPath", &[user_key]) == Some(0) && guest_strings::read_wide_string(at::<nt::UnicodeString>(user_key).buffer.get()).contains("S-1-5"), "rtl: RtlFormatCurrentUserKeyPath monta \\REGISTRY\\USER\\<SID>");

    // ---- descritores de segurança: Set/Get Group, Get Sacl ----------------
    let descriptor = guest::alloc_bytes(0x30);
    assert(call_export("RtlCreateSecurityDescriptor", &[descriptor, 1]) == Some(0), "rtl: SD absoluto criado");
    let group = guest::alloc_bytes(12);
    let group_sid = at::<nt::Sid>(group);
    group_sid.revision.set(1);
    group_sid.sub_authority_count.set(1);
    group_sid.identifier_authority.value[5].set(5); // NT
    group_sid.sub_authority[0].set(18); // S-1-5-18
    assert(call_export("RtlSetGroupSecurityDescriptor", &[descriptor, group, 0]) == Some(0), "rtl: RtlSetGroupSecurityDescriptor");
    let group_out = guest::alloc_bytes(8);
    let group_defaulted = guest::alloc_bytes(1);
    assert(call_export("RtlGetGroupSecurityDescriptor", &[descriptor, group_out, group_defaulted]) == Some(0) && guest::read64(group_out) == group, "rtl: RtlGetGroupSecurityDescriptor devolve o grupo");
    let sacl_present = guest::alloc_bytes(1);
    let sacl_out = guest::alloc_bytes(8);
    let sacl_defaulted = guest::alloc_bytes(1);
    assert(call_export("RtlGetSaclSecurityDescriptor", &[descriptor, sacl_present, sacl_out, sacl_defaulted]) == Some(0) && guest::read8(sacl_present) == 0, "rtl: RtlGetSaclSecurityDescriptor sem SACL -> ausente");

    // ---- RtlAddAce: insere uma ACCESS_ALLOWED_ACE numa ACL vazia ----------
    let acl = guest::alloc_bytes(0x80);
    assert(call_export("RtlCreateAcl", &[acl, 0x80, 2]) == Some(0), "rtl: ACL vazia criada");
    let ace = guest::alloc_bytes(0x14);
    let (allowed, ace_sid) = (at::<nt::AccessAllowedAce>(ace), at::<nt::Sid>(ace + 8));
    allowed.header.ace_type.set(0); // ACCESS_ALLOWED_ACE_TYPE
    allowed.header.ace_flags.set(0);
    allowed.header.ace_size.set(0x14);
    allowed.mask.set(0x001F_01FF);
    ace_sid.revision.set(1); // SID em SidStart
    ace_sid.sub_authority_count.set(1);
    ace_sid.identifier_authority.value[5].set(5); // NT
    ace_sid.sub_authority[0].set(18); // S-1-5-18
    assert(call_export("RtlAddAce", &[acl, 2, 0, ace, 0x14]) == Some(0), "rtl: RtlAddAce");
    assert(at::<nt::Acl>(acl).ace_count.get() == 1 && at::<nt::AccessAllowedAce>(acl + 8).mask.get() == 0x001F_01FF && call_export("RtlValidAcl", &[acl]) == Some(1), "rtl: RtlAddAce incrementa AceCount e mantém a ACL válida");

    // ---- RtlFindExportedRoutineByName: imagem PE mínima com 1 export ------
    let image = guest::alloc_bytes(0x400);
    let (dos_header, nt_headers) = (at::<nt::ImageDosHeader>(image), at::<nt::ImageNtHeaders64>(image + 0x80));
    dos_header.e_magic.set(0x5A4D); // 'MZ'
    dos_header.e_lfanew.set(0x80);
    nt_headers.signature.set(0x0000_4550); // 'PE\0\0'
    let optional = &nt_headers.optional_header;
    optional.magic.set(0x20B); // PE32+
    optional.number_of_rva_and_sizes.set(1);
    optional.data_directory[0].virtual_address.set(0x200); // exports
    optional.data_directory[0].size.set(0x40);
    let export_directory = image + 0x200;
    let directory = at::<nt::ImageExportDirectory>(export_directory);
    directory.number_of_functions.set(1);
    directory.number_of_names.set(1);
    directory.address_of_functions.set(0x300);
    directory.address_of_names.set(0x320);
    directory.address_of_name_ordinals.set(0x340);
    guest::write32(image + 0x300, 0x3C0); // função[0] RVA
    guest::write32(image + 0x320, 0x350); // nome[0] RVA
    guest::write16(image + 0x340, 0); // ordinal[0]
    guest::write_bytes(image + 0x350, b"MyRoutine\0");
    let wanted_name = guest::alloc_bytes(16);
    guest::write_bytes(wanted_name, b"MyRoutine\0");
    assert(call_export("RtlFindExportedRoutineByName", &[image, wanted_name]) == Some(image + 0x3C0), "rtl: RtlFindExportedRoutineByName resolve o export pelo nome");
    let missing_name = guest::alloc_bytes(16);
    guest::write_bytes(missing_name, b"Nope\0");
    assert(call_export("RtlFindExportedRoutineByName", &[image, missing_name]) == Some(0), "rtl: RtlFindExportedRoutineByName NULL para ausente");

    // ---- RtlCaptureStackBackTrace: seguro, conta <= pedido ----------------
    let back_trace = guest::alloc_bytes(8 * 8);
    let trace_hash = guest::alloc_bytes(4);
    assert(call_export("RtlCaptureStackBackTrace", &[0, 8, back_trace, trace_hash]).is_some_and(|count| count <= 8), "rtl: RtlCaptureStackBackTrace devolve contagem <= pedido");

    // ---- RtlGenerateClass5Guid: vetor RFC 4122 (DNS, "www.example.com") ---
    let namespace = guest::alloc_bytes(16);
    guest::write_bytes(namespace, &[0x10, 0xB8, 0xA7, 0x6B, 0xAD, 0x9D, 0xD1, 0x11, 0x80, 0xB4, 0x00, 0xC0, 0x4F, 0xD4, 0x30, 0xC8]);
    let guid_name = guest::alloc_bytes(16);
    guest::write_bytes(guid_name, b"www.example.com");
    let guid_out = guest::alloc_bytes(16);
    // Esperados calculados com o uuid5 de referência (módulo `uuid` do Python),
    // no layout nativo do GUID (Data1/2/3 little-endian), lidos como dois u64.
    assert(call_export("RtlGenerateClass5Guid", &[namespace, guid_name, 15, guid_out]) == Some(0) && guest::read_bytes(guid_out, 16) == [0x568B_E927_2ED6_657Du64.to_le_bytes(), 0xA2A6_AEA8_6526_E195u64.to_le_bytes()].concat(), "rtl: RtlGenerateClass5Guid = v5(DNS, www.example.com) = 2ed6657d-e927-568b-95e1-2665a8aea6a2");
    let url_namespace = guest::alloc_bytes(16);
    guest::write_bytes(url_namespace, &[0x11, 0xB8, 0xA7, 0x6B, 0xAD, 0x9D, 0xD1, 0x11, 0x80, 0xB4, 0x00, 0xC0, 0x4F, 0xD4, 0x30, 0xC8]);
    assert(call_export("RtlGenerateClass5Guid", &[url_namespace, guid_name, 0, guid_out]) == Some(0) && guest::read_bytes(guid_out, 16) == [0x5DDF_4057_1B4D_B7EBu64.to_le_bytes(), 0xF571_20C7_DE36_E091u64.to_le_bytes()].concat(), "rtl: RtlGenerateClass5Guid = v5(URL, nome vazio) = 1b4db7eb-4057-5ddf-91e0-36dec72071f5");
    let url_name = guest::alloc_bytes(32);
    guest::write_bytes(url_name, b"http://example.com/");
    assert(call_export("RtlGenerateClass5Guid", &[url_namespace, url_name, 19, guid_out]) == Some(0) && guest::read_bytes(guid_out, 16) == [0x5697_F9E4_0A30_0EE9u64.to_le_bytes(), 0x67BA_FAFA_C7EF_1AA5u64.to_le_bytes()].concat(), "rtl: RtlGenerateClass5Guid = v5(URL, http://example.com/) = 0a300ee9-f9e4-5697-a51a-efc7fafaba67");

    // ---- CRT: wcsnlen / wcsrchr -------------------------------------------
    let wide = guest::alloc_bytes(16);
    guest_strings::write_wide_string(wide, "a/b/c");
    assert(call_export("wcsnlen", &[wide, 3]) == Some(3) && call_export("wcsnlen", &[wide, 10]) == Some(5), "crt: wcsnlen respeita o limite");
    assert(call_export("wcsrchr", &[wide, b'/' as u64]) == Some(wide + 6), "crt: wcsrchr acha a última '/'");

    // ---- CRT: _wcslwr ------------------------------------------------------
    let upper = guest::alloc_bytes(16);
    guest_strings::write_wide_string(upper, "ABC");
    assert(call_export("_wcslwr", &[upper]) == Some(upper) && guest_strings::read_wide_string(upper) == "abc", "crt: _wcslwr minúsculas no lugar");

    // ---- CRT: wcsncpy_s (_TRUNCATE e ERANGE) ------------------------------
    let source_wide = guest::alloc_bytes(16);
    guest_strings::write_wide_string(source_wide, "Hi");
    let copy_dest = guest::alloc_bytes(16);
    assert(call_export("wcsncpy_s", &[copy_dest, 8, source_wide, u64::MAX]) == Some(0) && guest_strings::read_wide_string(copy_dest) == "Hi", "crt: wcsncpy_s _TRUNCATE copia e termina");
    let hello = guest::alloc_bytes(16);
    guest_strings::write_wide_string(hello, "Hello");
    let small_dest = guest::alloc_bytes(8);
    assert(call_export("wcsncpy_s", &[small_dest, 2, hello, 4]) == Some(34) && guest::read16(small_dest) == 0, "crt: wcsncpy_s sem espaço -> ERANGE");

    // ---- CRT: _snwprintf ---------------------------------------------------
    let format = guest::alloc_bytes(16);
    guest_strings::write_wide_string(format, "%d");
    let formatted = guest::alloc_bytes(16);
    assert(call_export("_snwprintf", &[formatted, 8, format, 42]) == Some(2) && guest_strings::read_wide_string(formatted) == "42", "crt: _snwprintf formata largo");

    // ---- CRT: sqrt / _purecall --------------------------------------------
    // O harness passa inteiros, não XMM0, então o export sqrt só é exercitado
    // sem crash; a matemática é validada direto em `sqrt_bits` com os bits
    // IEEE-754 exatos. O _purecall derruba o sistema por contrato, então só se
    // verifica o registro — nunca se chama.
    assert(call_export("sqrt", &[0]).is_some(), "crt: sqrt resolve e não quebra");
    let root = crate::ntos::rtl::math::sqrt_bits;
    assert(
        root(0x4010_0000_0000_0000) == 0x4000_0000_0000_0000 // sqrt(4) = 2
            && root(0x4022_0000_0000_0000) == 0x4008_0000_0000_0000 // sqrt(9) = 3
            && root(0x3FF0_0000_0000_0000) == 0x3FF0_0000_0000_0000 // sqrt(1) = 1
            && root(0x4000_0000_0000_0000) == 0x3FF6_A09E_667F_3BCD, // sqrt(2) arredondado
        "crt: sqrt_bits exato em quadrados perfeitos e sqrt(2) com arredondamento correto",
    );
    assert(
        root(0) == 0
            && root(0x8000_0000_0000_0000) == 0x8000_0000_0000_0000 // -0 -> -0
            && root(0x7FF0_0000_0000_0000) == 0x7FF0_0000_0000_0000 // +inf -> +inf
            && root(0xBFF0_0000_0000_0000) == 0xFFF8_0000_0000_0000 // sqrt(-1) -> NaN indefinido
            && root(0xFFF0_0000_0000_0000) == 0xFFF8_0000_0000_0000 // -inf -> NaN indefinido
            && root(0x7FF0_0000_0000_0001) == 0x7FF8_0000_0000_0001 // NaN -> NaN silenciado
            && root(0x0000_0000_0000_0001) == 0x1E60_0000_0000_0000, // menor subnormal -> 2^-537
        "crt: sqrt_bits em zeros, infinitos, NaN, negativos e subnormal",
    );
    assert(matches!(exports::lookup("ntoskrnl.exe", "_purecall"), Some(_)), "crt: _purecall registrado (bugcheck; não chamado)");
}


fn ke_ex_sync_exports(assert: Assert) {
    // --- KePulseEvent: define, sinaliza, pulsa -> devolve o estado anterior e
    //     deixa o evento não-sinalizado (NotificationEvent) ---
    let event = guest::alloc_bytes(0x20);
    call_export("KeInitializeEvent", &[event, 0, 0]); // NotificationEvent, inicial FALSE
    call_export("KeSetEvent", &[event, 0, 0]);         // estado -> 1
    assert(
        call_export("KePulseEvent", &[event, 0, 0]) == Some(1)
            && call_export("KeReadStateEvent", &[event]) == Some(0),
        "ke: KePulseEvent devolve estado anterior e limpa o evento",
    );
    guest::free_bytes(event);

    // --- KeReadStateMutant / KeReadStateMutex: mesmo handler, mutante livre -> 1 ---
    let mutant = guest::alloc_bytes(0x40);
    call_export("KeInitializeMutex", &[mutant, 0]);    // SignalState = 1 (livre)
    assert(
        call_export("KeReadStateMutant", &[mutant]) == Some(1)
            && call_export("KeReadStateMutex", &[mutant]) == Some(1),
        "ke: KeReadStateMutant e o alias KeReadStateMutex leem SignalState=1",
    );
    guest::free_bytes(mutant);

    // --- KeIsAttachedProcess: a thread de teste não está anexada -> FALSE ---
    assert(
        call_export("KeIsAttachedProcess", &[]) == Some(0),
        "ke: KeIsAttachedProcess FALSE sem anexação",
    );

    // --- KeQueryInterruptTimePrecise: devolve tempo e grava o QPC (TSC != 0) ---
    let qpc = guest::alloc_bytes(8);
    let interrupt_time = call_export("KeQueryInterruptTimePrecise", &[qpc]);
    assert(
        interrupt_time.is_some() && at::<nt::LargeInteger>(qpc).quad_part.get() != 0,
        "ke: KeQueryInterruptTimePrecise grava o QPC",
    );
    guest::free_bytes(qpc);

    // --- par região-crítica + fast-mutex-unsafe: entra (devolve thread) e sai ---
    let fast_mutex = guest::alloc_bytes(0x38);
    call_export("ExInitializeFastMutex", &[fast_mutex]);
    assert(
        call_export("ExEnterCriticalRegionAndAcquireFastMutexUnsafe", &[fast_mutex]).unwrap_or(0) != 0
            && call_export("ExReleaseFastMutexUnsafeAndLeaveCriticalRegion", &[fast_mutex]) == Some(0),
        "ex: enter/leave critical-region + fast-mutex-unsafe emparelham",
    );
    guest::free_bytes(fast_mutex);

    // --- constantes e stubs de firmware/licença ---
    assert(
        call_export("ExGetFirmwareType", &[]) == Some(2)
            && call_export("ExIsManufacturingModeEnabled", &[]) == Some(0),
        "ex: firmware = UEFI(2) e modo de fábrica desligado",
    );
    assert(
        call_export("ExShareAddressSpaceWithDevice", &[0, 0, 0]).map(|s| s as u32) == Some(0xC000_00BB)
            && call_export("ExQueryFastCacheDevLicense", &[0, 0, 0, 0]).map(|s| s as u32) == Some(0xC000_00BB),
        "ex: ExShareAddressSpaceWithDevice/ExQueryFastCacheDevLicense -> STATUS_NOT_SUPPORTED",
    );}


/// HalDispatchTable: HAL_DISPATCH público publicado (versão 4); todo slot de
/// função aponta para o stub seguro, e o slot 1 (HalQuerySystemInformation) é
/// chamável e devolve STATUS_NOT_SUPPORTED em vez de faultar.
fn hal_dispatch_table_exports(assert: Assert) {
    use crate::hal::amd64::{native_call, private_entries};
    use crate::hal::public_dispatch;
    use crate::ntos::init::exports;
    use crate::ntos::mm::pe_loader::ResolvedImport;
    let table = match exports::lookup("ntoskrnl.exe", "HalDispatchTable") {
        Some(ResolvedImport::Address { address, .. }) => address,
        _ => 0,
    };
    let stub = private_entries::entry("hal_default_not_supported").and_then(|entry| crate::ntos::mm::kernel_address::virtual_address(entry).ok()).unwrap_or(0);
    let slots_ok = stub != 0 && (0..public_dispatch::SLOT_COUNT as u64).all(|slot| guest::read64(table + 0x08 + slot * 8) == stub);
    assert(table != 0 && table == public_dispatch::table_address() && at::<nt::HalDispatch>(table).version.get() == public_dispatch::VERSION && slots_ok, "hal: HalDispatchTable publicada (versao 4, slots no stub seguro)");
    assert(native_call::call(at::<nt::HalDispatch>(table).hal_query_system_information.get(), &[0, 0, 0, 0]) == 0xC000_00BB, "hal: HalQuerySystemInformation (slot 1) devolve STATUS_NOT_SUPPORTED");
}

fn fsrtl_core_exports(assert: Assert) {
    use crate::ntos::mm::guest_memory as guest;

    // Monta uma UNICODE_STRING {Length, MaximumLength, _, Buffer} no convidado.
    fn wide(text: &str) -> u64 {
        let units: alloc::vec::Vec<u16> = text.encode_utf16().collect();
        let bytes = (units.len() * 2) as u64;
        let buffer = guest::alloc_bytes(bytes.max(2));
            guest::write_bytes(buffer, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
        let string = guest::alloc_bytes(16);
        let unicode = at::<nt::UnicodeString>(string);
        unicode.length.set(bytes as u16);
        unicode.maximum_length.set(bytes as u16);
        unicode.buffer.set(buffer);
        string
    }

    // IsNameInExpression: curinga casa / não casa.
    assert(
        call_export("FsRtlIsNameInExpression", &[wide("*.txt"), wide("a.txt"), 0, 0]) == Some(1)
            && call_export("FsRtlIsNameInExpression", &[wide("*.txt"), wide("a.bin"), 0, 0]) == Some(0),
        "fsrtl-core: IsNameInExpression wildcard match/no-match",
    );

    // DoesNameContainWildCards.
    assert(
        call_export("FsRtlDoesNameContainWildCards", &[wide("a*b")]) == Some(1)
            && call_export("FsRtlDoesNameContainWildCards", &[wide("plain")]) == Some(0),
        "fsrtl-core: DoesNameContainWildCards",
    );

    // IsNtstatusExpected (tabela exata) + NormalizeNtstatus (sem sinal).
    assert(
        call_export("FsRtlIsNtstatusExpected", &[0xC000_0005]) == Some(0)
            && call_export("FsRtlIsNtstatusExpected", &[0x0000_0103]) == Some(1)
            && call_export("FsRtlNormalizeNtstatus", &[0xC000_0005, 0xC000_0001]) == Some(0xC000_0001)
            && call_export("FsRtlNormalizeNtstatus", &[0xC000_0011, 0xC000_0001]) == Some(0xC000_0011),
        "fsrtl-core: IsNtstatusExpected / NormalizeNtstatus",
    );

    // DissectName: a\b\c -> first="a" (2 bytes), remaining="b\c" (6 bytes).
    let path = wide("a\\b\\c");
    let first = guest::alloc_bytes(16);
    let rest = guest::alloc_bytes(16);
    call_export("FsRtlDissectName", &[path, first, rest]);
    assert(
        at::<nt::UnicodeString>(first).length.get() == 2 && at::<nt::UnicodeString>(rest).length.get() == 6,
        "fsrtl-core: DissectName split",
    );

    // Data export resolve para uma célula .kdata não-nula.
    assert(
        crate::ntos::mm::kernel_data::address("FsRtlLegalAnsiCharacterArray").is_ok(),
        "fsrtl-core: FsRtlLegalAnsiCharacterArray data export",
    );
}


fn ob_object_lifecycle_exports(assert: Assert) {
    use crate::ntos::init::exports;
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::mm::kernel_data;
    use crate::ntos::ob::object_types;
    use crate::ntos::rtl::guest_strings;
    use crate::ntos::mm::pe_loader::ResolvedImport;

    let cell = |name: &str| match exports::lookup("ntoskrnl.exe", name) {
        Some(ResolvedImport::Address { address, .. }) => address,
        _ => 0,
    };

    // 1. The three new type-pointer cells resolve and point at a live OBJECT_TYPE.
    let pointers = ["IoDeviceObjectType", "ExSemaphoreObjectType", "LpcPortObjectType"];
    let cells_ok = pointers.iter().all(|name| {
        let c = cell(name);
        c != 0 && kernel_data::address(name).ok() == Some(c) && guest::read64(c) != 0
    });
    assert(cells_ok, "ob-object-lifecycle: celulas IoDevice/ExSemaphore/LpcPort apontam para OBJECT_TYPE");
    assert(guest::read64(cell("IoDeviceObjectType")) == object_types::device_type().pointer, "ob-object-lifecycle: IoDeviceObjectType e o corpo Device");

    // 2. Build an OBJECT_TYPE_INITIALIZER (0x78) + a UNICODE_STRING name.
    let name_text = "DxgkCompositionTest";
    let name_buf = guest::alloc_bytes((name_text.len() as u64 + 1) * 2);
    guest_strings::write_wide_string(name_buf, name_text);
    let name_us = guest::alloc_bytes(0x10);
    let type_name = at::<nt::UnicodeString>(name_us);
    type_name.length.set((name_text.len() * 2) as u16);
    type_name.maximum_length.set((name_text.len() * 2) as u16);
    type_name.buffer.set(name_buf);

    let init = guest::alloc_bytes(0x78);
    let initializer = at::<nt::ObjectTypeInitializer>(init);
    initializer.length.set(0x78); // ObjectTypeFlags = 0
    initializer.generic_mapping.generic_read.set(0x120001);
    initializer.generic_mapping.generic_write.set(0x120002);
    initializer.generic_mapping.generic_execute.set(0x120004);
    initializer.generic_mapping.generic_all.set(0x1F0003);
    initializer.valid_access_mask.set(0x1F0003);

    let scratch = guest::alloc_bytes(0x80);
    let out_type = scratch;
    let out_obj = scratch + 8;
    let out_handle = scratch + 0x10;
    let out_ref = scratch + 0x18;
    let out_info = scratch + 0x20;
    let granted = scratch + 0x30; // in/out ACCESS_MASK for ObCheckObjectAccess
    let status = scratch + 0x38;

    // 3. ObCreateObjectType -> a fresh type pointer.
    let created_type = call_export("ObCreateObjectType", &[name_us, init, 0, out_type]);
    let type_ptr = guest::read64(out_type);
    assert(created_type == Some(0) && type_ptr != 0 && object_types::find(type_ptr).is_some(), "ob-object-lifecycle: ObCreateObjectType registra o tipo");

    // 4. ObCreateObject -> an object body (unnamed, user handle).
    let created = call_export("ObCreateObject", &[0, type_ptr, 0, 0, 0, 0x40, 0, 0, out_obj]);
    let body = guest::read64(out_obj);
    assert(created == Some(0) && body != 0, "ob-object-lifecycle: ObCreateObject aloca o corpo");

    // 5. ObInsertObject -> a handle in the current table.
    let inserted = call_export("ObInsertObject", &[body, 0, 0x1F0003, 0, 0, out_handle]);
    let handle = guest::read64(out_handle);
    assert(inserted == Some(0) && handle != 0, "ob-object-lifecycle: ObInsertObject abre o handle");

    // 6. ObReferenceObjectByHandleWithTag resolves back to the body (tag 'Dxgk').
    let tag = u32::from_le_bytes(*b"Dxgk") as u64;
    let referenced = call_export("ObReferenceObjectByHandleWithTag", &[handle, 0, 0, 0, tag, out_ref, out_info]);
    assert(referenced == Some(0) && guest::read64(out_ref) == body, "ob-object-lifecycle: ObReferenceObjectByHandleWithTag devolve o corpo");

    // 7. ObCheckObjectAccess grants in kernel mode (desired within valid-access).
    guest::write32(granted, 0x0001);
    let checked = call_export("ObCheckObjectAccess", &[body, 0, 0, 0, granted, status]);
    assert(checked == Some(1) && guest::read32(status) == 0 && guest::read32(granted) & 0x0001 != 0, "ob-object-lifecycle: ObCheckObjectAccess concede em modo kernel");

    // 8. ObIsKernelHandle: bit test, pseudo-handles excluded.
    assert(call_export("ObIsKernelHandle", &[0xFFFF_FFFF_8000_0004]) == Some(1) && call_export("ObIsKernelHandle", &[0x4]) == Some(0) && call_export("ObIsKernelHandle", &[0xFFFF_FFFF_FFFF_FFFF]) == Some(0), "ob-object-lifecycle: ObIsKernelHandle");

    // 9. ObReleaseObjectSecurity + ObGetObjectSecurity (no SD set -> NULL, FALSE).
    let got = call_export("ObGetObjectSecurity", &[body, out_ref, status]);
    assert(got == Some(0) && guest::read64(out_ref) == 0 && call_export("ObReleaseObjectSecurity", &[0, 0]) == Some(0), "ob-object-lifecycle: ObGet/ReleaseObjectSecurity");

    // 10. ObCloseHandle closes the dxgkrnl handle; a second close is invalid.
    assert(call_export("ObCloseHandle", &[handle, 0]) == Some(0), "ob-object-lifecycle: ObCloseHandle fecha o handle");
    assert(call_export("ObCloseHandle", &[handle, 0]).is_some_and(|s| s & 0x8000_0000 != 0), "ob-object-lifecycle: ObCloseHandle de handle ja fechado falha");

    guest::free_bytes(scratch);
    guest::free_bytes(init);
    guest::free_bytes(name_us);
    guest::free_bytes(name_buf);
}


fn ex_lookaside_wnf_exports(assert: Assert) {
    use crate::ntos::init::exports;

    let export = |name: &str| exports::export_module().ok().and_then(|module| module.exports.exports.get(name).copied());

    // Lookaside-Ex: a inicialização instala os exports de pool em AllocateEx/FreeEx.
    // O cabeçalho SLIST exige alinhamento de 16 bytes.
    let list = guest::alloc_aligned(nt::LookasideListEx::SIZE, 16, true);
    let lookaside = at::<nt::LookasideListEx>(list);
    let tag = u32::from_le_bytes(*b"TseL") as u64;
    // (List, AllocateEx=NULL, FreeEx=NULL, PoolType=NonPagedPoolNx, Flags=0, Size=64, Tag, Depth=0)
    assert(call_export("ExInitializeLookasideListEx", &[list, 0, 0, 0x200, 0, 64, tag, 0]) == Some(0), "ex: ExInitializeLookasideListEx inicializa a LOOKASIDE_LIST_EX");
    assert(
        lookaside.l.allocate_ex.get() != 0
            && lookaside.l.free_ex.get() != 0
            && Some(lookaside.l.allocate_ex.get()) == export("ExAllocatePoolWithTag")
            && Some(lookaside.l.free_ex.get()) == export("ExFreePool"),
        "ex: AllocateEx/FreeEx recebem ExAllocatePoolWithTag/ExFreePool",
    );
    assert(lookaside.l.type_.get().0 == 0x200 && lookaside.l.size.get() == 64, "ex: Type(+0x24) e Size(+0x2C) da lista Ex");
    assert(call_export("ExDeleteLookasideListEx", &[list]) == Some(0), "ex: ExDeleteLookasideListEx desregistra a lista Ex");
    guest::free_bytes(list);

    // WNF: nome indefinido devolve falha (sem faultar).
    let state_name = guest::alloc_bytes(8);
    let wnf_name = at::<nt::WnfStateName>(state_name);
    wnf_name.data[0].set(0);
    wnf_name.data[1].set(0);
    let size = guest::alloc_bytes(4);
    guest::write32(size, 0);
    assert(call_export("ExQueryWnfStateData", &[state_name, 0, 0, 0, 0, size]).is_some_and(|status| status & 0x8000_0000 != 0), "ex: ExQueryWnfStateData devolve falha p/ nome indefinido");
    guest::free_bytes(state_name);
    guest::free_bytes(size);
}


fn mm_verifier_exports(assert: Assert) {
    use crate::ntos::mm::loaded_images;

    // MmIsVerifierEnabled: saída zerada e STATUS_NOT_SUPPORTED; NULL aceito.
    let flags = guest::alloc_bytes(8);
    guest::write32(flags, 0xFFFF_FFFF);
    assert(call_export("MmIsVerifierEnabled", &[flags]) == Some(0xFFFF_FFFF_C000_00BB) && guest::read32(flags) == 0, "mm-verifier: MmIsVerifierEnabled zera as flags e devolve NOT_SUPPORTED");
    assert(call_export("MmIsVerifierEnabled", &[0]) == Some(0xFFFF_FFFF_C000_00BB), "mm-verifier: MmIsVerifierEnabled com saida NULL");

    // MmIsDriverVerifying: bit 25 de KLDR_DATA_TABLE_ENTRY.Flags via DriverSection.
    let driver = guest::alloc_bytes(nt::DriverObject::SIZE);
    let entry = guest::alloc_bytes(nt::KldrDataTableEntry::SIZE);
    assert(call_export("MmIsDriverVerifying", &[driver]) == Some(0), "mm-verifier: sem DriverSection nao verifica");
    at::<nt::DriverObject>(driver).driver_section.set(entry);
    at::<nt::KldrDataTableEntry>(entry).flags.set(0x0200_0000);
    assert(call_export("MmIsDriverVerifying", &[driver]) == Some(1), "mm-verifier: LDRP_IMAGE_VERIFYING ligado");
    at::<nt::KldrDataTableEntry>(entry).flags.set(0xFDFF_FFFF);
    assert(call_export("MmIsDriverVerifying", &[driver]) == Some(0), "mm-verifier: so o bit 25 conta");
    assert(call_export("MmIsDriverSuspectForVerifier", &[driver]) == Some(0), "mm-verifier: lista de suspeitos vazia sem verificador");

    // MmIsDriverVerifyingByAddress: o ntoskrnl não é verificado; endereço sem imagem = FALSE.
    let kernel = loaded_images::kernel().map_or(0, |image| image.image_base + 0x1000);
    assert(kernel != 0 && call_export("MmIsDriverVerifyingByAddress", &[kernel]) == Some(0) && call_export("MmIsDriverVerifyingByAddress", &[0]) == Some(0), "mm-verifier: MmIsDriverVerifyingByAddress pela entrada do loader");

    // MmAddVerifierThunks: verificador desligado.
    assert(call_export("MmAddVerifierThunks", &[flags, 16]) == Some(0xFFFF_FFFF_C000_00BB), "mm-verifier: MmAddVerifierThunks sem verificador");
    guest::free_bytes(entry);
    guest::free_bytes(driver);
    guest::free_bytes(flags);
}


fn mm_session_views_exports(assert: Assert) {
    use crate::ntos::mm::section::create as create_section;
    use crate::ntos::ob::objects::section as section_objects;
    use crate::ntos::ps::process;
    use crate::ntos::ps::user::sections;

    let block = guest::alloc_bytes(0x100);
    let (output, size, base, offset) = (block, block + 8, block + 0x10, block + 0x18);
    // SEC_RESERVE: as páginas só entram pelo MmCommitSessionMappedView.
    at::<nt::LargeInteger>(size).quad_part.set(0x3000);
    let created = create_section::create_object(output, 0, 0, size, 4, 0x0400_0000, 0, 0, 0);
    let body = guest::read64(output);
    assert(created.is_ok_and(|status| status == 0) && body != 0, "mm-session-views: secao SEC_RESERVE criada");
    let process = process::get_current_process();
    let eprocess = at::<nt::Eprocess>(process);
    let in_session = eprocess.process_in_session();

    // Fora de sessão (o System não tem ProcessInSession): STATUS_NOT_MAPPED_VIEW.
    eprocess.set_process_in_session(0);
    guest::write64(size, 0);
    assert(call_export("MmMapViewInSessionSpace", &[body, base, size]) == Some(0xFFFF_FFFF_C000_0019), "mm-session-views: processo fora de sessao recusado");

    eprocess.set_process_in_session(1);
    let mapped = call_export("MmMapViewInSessionSpace", &[body, base, size]);
    let address = guest::read64(base);
    let section = sections::by_pointer(body);
    let reserved = section.as_ref().is_some_and(|section| section.frame(1).is_none());
    assert(mapped == Some(0) && guest::read64(size) == 0x3000 && sections::find_system_view(address).is_some() && reserved, "mm-session-views: vista de sessao com o tamanho integral e paginas reservadas");

    // Commit da segunda página (faixa dentro dela) e repetição idempotente.
    let committed = call_export("MmCommitSessionMappedView", &[address + 0x1800, 0x10]);
    assert(committed == Some(0) && section.as_ref().is_some_and(|section| section.frame(1).is_some() && section.frame(2).is_none()), "mm-session-views: MmCommitSessionMappedView confirma so a pagina pedida");
    assert(call_export("MmCommitSessionMappedView", &[address + 0x1000, 0x1000]) == Some(0), "mm-session-views: commit repetido aceito");
    // Validações na ordem do original.
    assert(call_export("MmCommitSessionMappedView", &[block, 0x1000]) == Some(0xFFFF_FFFF_C000_00EF), "mm-session-views: endereco fora da sessao = INVALID_PARAMETER_1");
    assert(call_export("MmCommitSessionMappedView", &[address, 0]) == Some(0xFFFF_FFFF_C000_00F0) && call_export("MmCommitSessionMappedView", &[address, 0x4000]) == Some(0xFFFF_FFFF_C000_00F0), "mm-session-views: tamanho nulo ou alem da vista = INVALID_PARAMETER_2");
    eprocess.set_process_in_session(0);
    assert(call_export("MmCommitSessionMappedView", &[address, 0x1000]) == Some(0xFFFF_FFFF_C000_0019), "mm-session-views: commit fora de sessao = NOT_MAPPED_VIEW");
    eprocess.set_process_in_session(1);

    assert(call_export("MmUnmapViewInSessionSpace", &[address]) == Some(0) && sections::find_system_view(address).is_none(), "mm-session-views: MmUnmapViewInSessionSpace remove a vista");
    assert(call_export("MmCommitSessionMappedView", &[address, 0x1000]) == Some(0xFFFF_FFFF_C000_00EF), "mm-session-views: vista removida deixa de ser sessao");

    // Ex: o delta do offset entra no tamanho e o offset é alinhado (64 KiB).
    guest::write64(size, 0x1000);
    at::<nt::LargeInteger>(offset).quad_part.set(0x1234);
    let extended = call_export("MmMapViewInSessionSpaceEx", &[body, base, size, offset, 0]);
    let extended_base = guest::read64(base);
    assert(extended == Some(0) && guest::read64(size) == 0x2234 && at::<nt::LargeInteger>(offset).quad_part.get() == 0, "mm-session-views: Ex soma o delta do offset e alinha");
    assert(call_export("MmMapViewInSessionSpaceEx", &[body, base, size, offset, 2]) == Some(0xFFFF_FFFF_C000_00F4), "mm-session-views: Ex com flags invalidas");
    assert(call_export("MmUnmapViewInSessionSpace", &[extended_base]) == Some(0), "mm-session-views: vista Ex removida");

    eprocess.set_process_in_session(in_session);
    drop(section);
    assert(section_objects::dereference(body).is_ok() && sections::by_pointer(body).is_none(), "mm-session-views: secao liberada");
    guest::free_bytes(block);
}


fn mm_system_image_exports(assert: Assert) {
    use crate::drivers::fs::memory_file_system;
    use crate::ntos::mm::loaded_images;
    use crate::ntos::rtl::guest_strings;

    let block = guest::alloc_bytes(0x400);
    let (name, handle, base, missing) = (block, block + 0x10, block + 0x18, block + 0x20);
    let set_name = |descriptor: u64, text_at: u64, text: &str| {
        let units = text.encode_utf16().count() as u64;
        guest_strings::write_wide_string(text_at, text);
        let unicode = at::<nt::UnicodeString>(descriptor);
        unicode.length.set((units * 2) as u16);
        unicode.maximum_length.set((units * 2 + 2) as u16);
        unicode.buffer.set(text_at);
    };
    set_name(name, block + 0x100, "\\SystemRoot\\System32\\opennt-mmload.sys");
    set_name(missing, block + 0x200, "\\SystemRoot\\System32\\opennt-mmload-ausente.sys");
    let _ = memory_file_system::write_bytes("/opennt-mmload.sys", ntoskrnl_importer(b"DbgPrint\0"));

    let loaded = call_export("MmLoadSystemImage", &[name, 0, 0, 0, handle, base]);
    let (entry, image_base) = (guest::read64(handle), guest::read64(base));
    let published = loaded_images::find(image_base + 0x1000).is_some_and(|image| image.name.ends_with("opennt-mmload.sys"));
    assert(loaded == Some(0) && entry != 0 && image_base != 0 && at::<nt::ImageDosHeader>(image_base).e_magic.get() == 0x5A4D && at::<nt::KldrDataTableEntry>(entry).dll_base.get() == image_base && published, "mm-system-image: MmLoadSystemImage mapeia, resolve os imports e devolve a entrada do loader");

    // Já carregada: mesma entrada e base; sessão = sucesso, senão IMAGE_ALREADY_LOADED.
    guest::write64(handle, 0);
    let again = call_export("MmLoadSystemImage", &[name, 0, 0, 0, handle, base]);
    assert(again == Some(0xFFFF_FFFF_C000_010E) && guest::read64(handle) == entry && guest::read64(base) == image_base, "mm-system-image: segunda carga = STATUS_IMAGE_ALREADY_LOADED com a entrada existente");
    assert(call_export("MmLoadSystemImage", &[name, 0, 0, 1, handle, base]) == Some(0) && guest::read64(base) == image_base, "mm-system-image: carga de sessao de imagem presente = sucesso");

    // Flags: o wrapper recusa antes de zerar a base; o Ex zera e recusa sessão+lockdown.
    assert(call_export("MmLoadSystemImage", &[name, 0, 0, 4, handle, base]) == Some(0xFFFF_FFFF_C000_00F2) && guest::read64(base) == image_base, "mm-system-image: flag fora da mascara = INVALID_PARAMETER_4 sem tocar a saida");
    assert(call_export("MmLoadSystemImage", &[name, 0, 0, 3, handle, base]) == Some(0xFFFF_FFFF_C000_00F2) && guest::read64(base) == 0, "mm-system-image: sessao com lockdown = INVALID_PARAMETER_4 com a base zerada");
    assert(call_export("MmLoadSystemImage", &[missing, 0, 0, 0, handle, base]) == Some(0xFFFF_FFFF_C000_0034) && guest::read64(base) == 0, "mm-system-image: imagem ausente = OBJECT_NAME_NOT_FOUND");

    assert(call_export("MmUnloadSystemImage", &[entry]) == Some(0) && loaded_images::find(image_base + 0x1000).is_none(), "mm-system-image: MmUnloadSystemImage libera imagem e registro");
    assert(call_export("MmUnloadSystemImage", &[entry]) == Some(0), "mm-system-image: descarga repetida devolve sucesso sem efeito");
    guest::free_bytes(block);
}


fn mm_mdl_ex_exports(assert: Assert) {
    use crate::hal::physical;
    use crate::ntos::ps::process;

    // MmAllocatePagesForMdlEx: 3 páginas zeradas, MDL_PAGES_LOCKED, Size 0x48.
    let pages = call_export("MmAllocatePagesForMdlEx", &[0, u64::MAX, 0, 0x2800, 1, 0]).unwrap_or(0);
    let frames: Vec<u64> = if pages != 0 { (0..3).map(|index| mdl_pfn(pages, index)).collect() } else { Vec::new() };
    let zeroed = frames.iter().all(|&frame| frame != 0 && physical::read64(frame * 0x1000 + 0x800) == 0);
    assert(pages != 0 && at::<nt::Mdl>(pages).size.get() == 0x48 && at::<nt::Mdl>(pages).mdl_flags.get() == 2 && at::<nt::Mdl>(pages).byte_count.get() == 0x3000 && at::<nt::Mdl>(pages).start_va.get() == 0 && zeroed, "mm-mdl-ex: MmAllocatePagesForMdlEx com frames reais zerados e MDL_PAGES_LOCKED");
    assert(call_export("MmFreePagesFromMdl", &[pages]) == Some(0), "mm-mdl-ex: MmFreePagesFromMdl devolve os frames");
    guest::free_bytes(pages);
    // Faixa física limitada: todos os frames dentro de [64 MiB, 512 MiB).
    let bounded = call_export("MmAllocatePagesForMdlEx", &[0x400_0000, 0x1FFF_FFFF, 0, 0x2000, 1, 1]).unwrap_or(0);
    let in_range = bounded != 0 && (0..2).all(|index| (0x4000..=0x1_FFFF).contains(&mdl_pfn(bounded, index)));
    assert(in_range, "mm-mdl-ex: frames dentro da faixa fisica pedida");
    if bounded != 0 {
        call_export("MmFreePagesFromMdl", &[bounded]);
        guest::free_bytes(bounded);
    }
    // Validações: flags fora da máscara, nó inexistente, total nulo, skip desalinhado.
    assert(call_export("MmAllocatePagesForMdlEx", &[0, u64::MAX, 0, 0x1000, 1, 0x800]) == Some(0) && call_export("MmAllocateNodePagesForMdlEx", &[0, u64::MAX, 0, 0x1000, 1, 1, 0]) == Some(0) && call_export("MmAllocatePagesForMdlEx", &[0, u64::MAX, 0, 0, 1, 0]) == Some(0) && call_export("MmAllocatePagesForMdlEx", &[0, u64::MAX, 0x800, 0x1000, 1, 0]) == Some(0), "mm-mdl-ex: pedidos invalidos devolvem NULL");
    // Chunks contíguos: skip potência de dois que não divide o total = NULL.
    assert(call_export("MmAllocatePagesForMdlEx", &[0, u64::MAX, 0x2000, 0x3000, 1, 0x20]) == Some(0), "mm-mdl-ex: REQUIRE_CONTIGUOUS_CHUNKS exige skip divisor do total");
    let node = call_export("MmAllocateNodePagesForMdlEx", &[0, u64::MAX, 0, 0x1000, 1, 0, 1]).unwrap_or(0);
    assert(node != 0 && at::<nt::Mdl>(node).byte_count.get() == 0x1000, "mm-mdl-ex: MmAllocateNodePagesForMdlEx no no 0");
    if node != 0 {
        call_export("MmFreePagesFromMdl", &[node]);
        guest::free_bytes(node);
    }

    // MmCreateMdl: StartVa/ByteOffset/Size do original; Length >= 4 GiB = NULL.
    let created = call_export("MmCreateMdl", &[0, 0x1234_5678_9ABC, 0x2000]).unwrap_or(0);
    assert(created != 0 && at::<nt::Mdl>(created).size.get() == 0x48 && at::<nt::Mdl>(created).start_va.get() == 0x1234_5678_9000 && at::<nt::Mdl>(created).byte_offset.get() == 0xABC && at::<nt::Mdl>(created).byte_count.get() == 0x2000 && at::<nt::Mdl>(created).mdl_flags.get() == 0, "mm-mdl-ex: MmCreateMdl aloca e inicializa o MDL");
    let caller = guest::alloc_bytes(0x40);
    at::<nt::Mdl>(caller).mapped_system_va.set(0x5555);
    assert(call_export("MmCreateMdl", &[caller, 0x1000, 0x1000]) == Some(caller) && at::<nt::Mdl>(caller).size.get() == 0x38 && at::<nt::Mdl>(caller).mapped_system_va.get() == 0x5555, "mm-mdl-ex: MmCreateMdl sobre MDL do chamador preserva MappedSystemVa");
    assert(call_export("MmCreateMdl", &[0, 0x1000, 0x1_0000_0000]) == Some(0), "mm-mdl-ex: MmCreateMdl recusa 4 GiB");

    // MmMdlPageContentsState: consulta/liga/desliga o bit 14 e devolve o State.
    at::<nt::Mdl>(created).mdl_flags.set(2);
    assert(call_export("MmMdlPageContentsState", &[created, 1]) == Some(1) && at::<nt::Mdl>(created).mdl_flags.get() == 0x4002 && call_export("MmMdlPageContentsState", &[created, 2]) == Some(1), "mm-mdl-ex: MdlPageContentsZeroed liga MDL_PAGE_CONTENTS_INVARIANT");
    assert(call_export("MmMdlPageContentsState", &[created, 0]) == Some(0) && at::<nt::Mdl>(created).mdl_flags.get() == 2 && call_export("MmMdlPageContentsState", &[created, 2]) == Some(0), "mm-mdl-ex: MdlPageContentsDirty desliga o bit");

    // MmMapLockedPages = MmMapLockedPagesSpecifyCache(MmCached): marca o MDL mapeado.
    let buffer = guest::alloc_bytes(0x2000);
    let described = call_export("MmCreateMdl", &[0, buffer + 0x10, 0x100]).unwrap_or(0);
    call_export("MmBuildMdlForNonPagedPool", &[described]);
    let mapped = call_export("MmMapLockedPages", &[described, 0]);
    assert(mapped == Some(buffer + 0x10) && at::<nt::Mdl>(described).mdl_flags.get() & 1 == 1, "mm-mdl-ex: MmMapLockedPages mapeia e marca o MDL");
    call_export("MmUnmapLockedPages", &[buffer + 0x10, described]);

    // MmProbeAndLockProcessPages no processo corrente: PFNs e MDL_PAGES_LOCKED.
    let locked = guest::alloc_bytes(0x40);
    call_export("MmCreateMdl", &[locked, buffer, 0x1000]);
    let current = process::get_current_process();
    assert(call_export("MmProbeAndLockProcessPages", &[locked, current, 0, 2]) == Some(0) && at::<nt::Mdl>(locked).mdl_flags.get() & 2 == 2 && mdl_pfn(locked, 0) == crate::ntos::mm::paging::translate(buffer) >> 12, "mm-mdl-ex: MmProbeAndLockProcessPages trava as paginas do processo");
    call_export("MmUnlockPages", &[locked]);
    for pointer in [locked, described, buffer, caller, created] {
        guest::free_bytes(pointer);
    }
}


fn mm_secure_memory_exports(assert: Assert) {
    let current = u64::MAX;
    let block = guest::alloc_bytes(0x40);
    let (base, size, old) = (block, block + 8, block + 0x10);
    guest::write64(base, 0);
    guest::write64(size, 0x3000);
    let allocated = call_export("ZwAllocateVirtualMemory", &[current, base, 0, size, 0x3000, 4]);
    let address = guest::read64(base);
    assert(allocated == Some(0) && address != 0, "mm-secure-memory: regiao privada de 3 paginas");

    // Escrita e leitura sobre páginas RW comitadas: handles distintos e não nulos.
    let write = call_export("MmSecureVirtualMemory", &[address + 0x10, 0x2000, 4]).unwrap_or(0);
    let read = call_export("MmSecureVirtualMemory", &[address, 0x3000, 2]).unwrap_or(0);
    assert(write != 0 && read != 0 && write != read, "mm-secure-memory: MmSecureVirtualMemory devolve handles opacos");
    // Faixas inválidas: tamanho nulo, além da região, além de MmUserProbeAddress.
    assert(call_export("MmSecureVirtualMemory", &[address, 0, 4]) == Some(0) && call_export("MmSecureVirtualMemory", &[address, 0x3001, 2]) == Some(0) && call_export("MmSecureVirtualMemory", &[0x7FFF_FFFF_F000, 0x2000, 2]) == Some(0), "mm-secure-memory: faixas invalidas devolvem NULL");

    // Página 3 somente leitura: sonda de escrita falha, de leitura passa.
    guest::write64(base, address + 0x2000);
    guest::write64(size, 0x1000);
    let protected = call_export("ZwProtectVirtualMemory", &[current, base, size, 2, old]);
    assert(protected == Some(0) && call_export("MmSecureVirtualMemory", &[address, 0x3000, 4]) == Some(0), "mm-secure-memory: sonda de escrita recusa pagina somente leitura");
    let read_only = call_export("MmSecureVirtualMemory", &[address + 0x2000, 0x1000, 2]).unwrap_or(0);
    assert(read_only != 0, "mm-secure-memory: sonda de leitura aceita pagina somente leitura");
    // Página 2 descomitada: até a sonda de leitura falha.
    guest::write64(base, address + 0x1000);
    guest::write64(size, 0x1000);
    let decommitted = call_export("ZwFreeVirtualMemory", &[current, base, size, 0x4000]);
    assert(decommitted == Some(0) && call_export("MmSecureVirtualMemory", &[address, 0x3000, 2]) == Some(0), "mm-secure-memory: pagina descomitada recusada");

    for handle in [write, read, read_only] {
        assert(call_export("MmUnsecureVirtualMemory", &[handle]) == Some(0), "mm-secure-memory: MmUnsecureVirtualMemory solta a entrada");
    }
    assert(call_export("MmUnsecureVirtualMemory", &[write]) == Some(0), "mm-secure-memory: handle ja solto ignorado");
    guest::write64(base, address);
    guest::write64(size, 0);
    call_export("ZwFreeVirtualMemory", &[current, base, size, 0x8000]);
    guest::free_bytes(block);
}


fn mm_physical_memory_exports(assert: Assert) {
    use crate::ntos::init::exports;
    use crate::ntos::mm::contiguous_memory;
    use crate::ntos::mm::memory_map as map;
    use crate::ntos::mm::native_pfn_database;
    use crate::ntos::mm::pe_loader::ResolvedImport;
    use crate::ntos::mm::protection;

    // MiMakeProtectionMask contra o modelo de referência.
    let masks = [(0x02u32, Some(1u32)), (0x04, Some(4)), (0x40, Some(6)), (0x104, Some(0x14)), (0x204, Some(0x0C)), (0x404, Some(0x1C)), (0x240, Some(0x0E)), (0x440, None), (0x01, Some(0x18)), (0x03, None), (0x800, None)];
    assert(masks.iter().all(|&(protect, mask)| protection::make_mask(protect) == mask), "mm-physical-memory: MiMakeProtectionMask pelas tabelas do ntoskrnl");

    // PAGE_READWRITE: cacheada, NX, na janela contígua do kernel.
    let cached = call_export("MmAllocateContiguousNodeMemory", &[0x2000, 0, u64::MAX, 0, 4, 0]).unwrap_or(0);
    let info = contiguous_memory::info(cached);
    assert(cached != 0 && (map::KERNEL_CONTIGUOUS_BASE..map::KERNEL_CONTIGUOUS_TOP).contains(&cached) && info.as_ref().is_some_and(|info| info.cache == 1 && info.nx && info.bytes == 0x2000), "mm-physical-memory: PAGE_READWRITE cacheada e NX");
    // MmGetVirtualForPhysical devolve a VA da PTE registrada no MMPFN.
    let physical = call_export("MmGetPhysicalAddress", &[cached + 0x1234]).unwrap_or(0);
    let expected = if native_pfn_database::information().is_some() { cached + 0x1234 } else { 0 };
    assert(physical != 0 && call_export("MmGetVirtualForPhysical", &[physical]) == Some(expected), "mm-physical-memory: MmGetVirtualForPhysical pela PteAddress do PFN");
    assert(call_export("MmFreeContiguousMemory", &[cached]) == Some(0) && contiguous_memory::info(cached).is_none(), "mm-physical-memory: liberada pelo MmFreeContiguousMemory");

    // PAGE_READWRITE|PAGE_NOCACHE (máscara 0xC) -> não cacheada; EXECUTE_READWRITE (6) -> executável.
    let uncached = call_export("MmAllocateContiguousNodeMemory", &[0x1000, 0, u64::MAX, 0, 0x204, 0]).unwrap_or(0);
    let executable = call_export("MmAllocateContiguousNodeMemory", &[0x1000, 0, u64::MAX, 0, 0x40, 0]).unwrap_or(0);
    assert(contiguous_memory::info(uncached).is_some_and(|info| info.cache == 0) && contiguous_memory::info(executable).is_some_and(|info| info.cache == 1 && !info.nx), "mm-physical-memory: cache e execucao pela mascara de protecao");
    call_export("MmFreeContiguousMemory", &[uncached]);
    call_export("MmFreeContiguousMemory", &[executable]);

    // Recusas: READONLY (1), GUARD, EXECUTE_READWRITE|NOCACHE (0xE), WRITECOMBINE com execução (inválida), boundary desalinhado, faixa vazia.
    let refused = [(2u64, 0u64, 0u64, u64::MAX), (0x104, 0, 0, u64::MAX), (0x240, 0, 0, u64::MAX), (0x440, 0, 0, u64::MAX), (4, 0x800, 0, u64::MAX), (4, 0, 0x2000_0000, 0x1000_0000)];
    assert(refused.iter().all(|&(protect, boundary, lowest, highest)| call_export("MmAllocateContiguousNodeMemory", &[0x1000, lowest, highest, boundary, protect, 0]) == Some(0)), "mm-physical-memory: protecoes, boundary e faixa invalidos devolvem NULL");

    // Mm64BitPhysicalAddress: BOOLEAN TRUE.
    let cell = match exports::lookup("ntoskrnl.exe", "Mm64BitPhysicalAddress") {
        Some(ResolvedImport::Address { address, .. }) => address,
        _ => 0,
    };
    assert(cell != 0 && guest::read8(cell) == 1, "mm-physical-memory: Mm64BitPhysicalAddress = TRUE");
}


fn mm_system_info_exports(assert: Assert) {
    use crate::ntos::init::exports;
    use crate::ntos::mm::memory_map;
    use crate::ntos::mm::paging;
    use crate::ntos::mm::pe_loader::ResolvedImport;

    let cell = |name: &str| match exports::lookup("ntoskrnl.exe", name) {
        Some(ResolvedImport::Address { address, .. }) => address,
        _ => 0,
    };
    assert(call_export("MmIsThisAnNtAsSystem", &[]).map(|value| value & 0xFF) == Some(0) && call_export("MmQuerySystemSize", &[]).map(|value| value as u32) == Some(2), "mm-system-info: estacao de trabalho e MmLargeSystem");
    let range = cell("MmSystemRangeStart");
    assert(range != 0 && guest::read64(range) == 0xFFFF_8000_0000_0000, "mm-system-info: MmSystemRangeStart = 0xFFFF800000000000");
    let bad = cell("MmBadPointer");
    let pointer = if bad != 0 { guest::read64(bad) } else { 0 };
    assert(pointer == memory_map::KERNEL_POOL_TOP && pointer & 0xFFF == 0 && paging::translate(pointer) == 0 && call_export("MmIsAddressValid", &[pointer]) == Some(0), "mm-system-info: MmBadPointer e uma VA de kernel nunca mapeada");
}


fn rtl_hash_tables_exports(assert: Assert) {
    let holder = guest::alloc_bytes(8);
    assert(call_export("RtlCreateHashTable", &[holder, 0, 0]) == Some(1), "rtl-hash-tables: RtlCreateHashTable aloca o cabecalho");
    let table = guest::read64(holder);
    if table == 0 {
        assert(false, "rtl-hash-tables: cabecalho alocado (Flags=1) com 128 baldes, mascara 127");
        return;
    }
    let hash_table = at::<nt::RtlDynamicHashTable>(table);
    assert(hash_table.flags.get() == 1 && hash_table.table_size.get() == 128 && hash_table.divisor_mask.get() == 127 && hash_table.pivot.get() == 0, "rtl-hash-tables: cabecalho alocado (Flags=1) com 128 baldes, mascara 127");
    let directory = hash_table.directory.get();
    let bucket_head = |bucket: u64| directory + bucket * 16;
    let bucket = |index: u64| at::<nt::ListEntry>(bucket_head(index));
    let entry = |address: u64| at::<nt::RtlDynamicHashTableEntry>(address);
    assert(directory != 0 && bucket(0).flink.get() == bucket_head(0) && bucket(127).blink.get() == bucket_head(127), "rtl-hash-tables: cabecas iniciadas vazias");

    // Inserções: a segunda assinatura 5 entra antes da primeira (cadeia ordenada,
    // nova entrada antes da primeira com Signature >= a dela).
    let (a, b, c, d) = (guest::alloc_bytes(0x20), guest::alloc_bytes(0x20), guest::alloc_bytes(0x20), guest::alloc_bytes(0x20));
    let inserted = [(a, 5u64), (c, 9), (b, 5), (d, 335)].iter().all(|&(entry, signature)| call_export("RtlInsertEntryHashTable", &[table, entry, signature, 0]) == Some(1));
    assert(inserted && hash_table.num_entries.get() == 4 && hash_table.non_empty_buckets.get() == 3, "rtl-hash-tables: 4 entradas em 3 baldes nao vazios");
    assert(bucket(95).flink.get() == b && entry(b).linkage.flink.get() == a && entry(a).linkage.flink.get() == bucket_head(95) && bucket(0).flink.get() == d && entry(d).signature.get() == 335, "rtl-hash-tables: cadeia do balde 95 = [b, a]; 335 no balde 0");

    // Lookup + GetNext percorrem as duplicatas; 7 cai num balde vazio.
    let context = guest::alloc_bytes(0x18);
    let lookup_context = at::<nt::RtlDynamicHashTableContext>(context);
    let first = call_export("RtlLookupEntryHashTable", &[table, 5, context]);
    assert(first == Some(b) && lookup_context.chain_head.get() == bucket_head(95) && lookup_context.prev_linkage.get() == bucket_head(95) && lookup_context.signature.get() == 5, "rtl-hash-tables: Lookup devolve a primeira duplicata e preenche o contexto");
    assert(call_export("RtlGetNextEntryHashTable", &[table, context]) == Some(a) && call_export("RtlGetNextEntryHashTable", &[table, context]) == Some(0), "rtl-hash-tables: GetNext devolve a segunda duplicata e depois NULL");
    assert(call_export("RtlLookupEntryHashTable", &[table, 7, 0]) == Some(0) && call_export("RtlLookupEntryHashTable", &[table, 9, 0]) == Some(c), "rtl-hash-tables: Lookup sem contexto (7 ausente, 9 presente)");

    // Enumeração normal: marcador no balde 0; Expand recusa enquanto ativo.
    let count = |next: &str, enumerator: u64| {
        let mut seen = 0;
        while let Some(entry) = call_export(next, &[table, enumerator]) {
            if entry == 0 || seen > 8 {
                break;
            }
            seen += 1;
        }
        seen
    };
    let enumerator = guest::alloc_bytes(0x28);
    assert(call_export("RtlInitEnumerationHashTable", &[table, enumerator]) == Some(1) && hash_table.num_enumerators.get() == 1 && bucket(0).flink.get() == enumerator && at::<nt::RtlDynamicHashTableEnumerator>(enumerator).chain_head.get() == bucket_head(0), "rtl-hash-tables: InitEnumeration insere o marcador na cabeca do balde 0");
    let normal = count("RtlEnumerateEntryHashTable", enumerator);
    assert(normal == 4 && call_export("RtlExpandHashTable", &[table]) == Some(0), "rtl-hash-tables: enumeracao ve 4 entradas; Expand recusa com enumerador ativo");
    call_export("RtlEndEnumerationHashTable", &[table, enumerator]);
    assert(hash_table.num_enumerators.get() == 0 && hash_table.non_empty_buckets.get() == 3 && at::<nt::RtlDynamicHashTableEnumerator>(enumerator).chain_head.get() == 0, "rtl-hash-tables: EndEnumeration retira o marcador e restaura os contadores");

    // Variantes fraca (encaminha para a normal) e forte (sem marcador).
    let weak = guest::alloc_bytes(0x28);
    assert(call_export("RtlInitWeakEnumerationHashTable", &[table, weak]) == Some(1), "rtl-hash-tables: InitWeakEnumeration");
    let weak_seen = count("RtlWeaklyEnumerateEntryHashTable", weak);
    call_export("RtlEndWeakEnumerationHashTable", &[table, weak]);
    let strong = guest::alloc_bytes(0x28);
    assert(call_export("RtlInitStrongEnumerationHashTable", &[table, strong]) == Some(1) && hash_table.num_enumerators.get() == 0 && at::<nt::RtlDynamicHashTableEnumerator>(strong).cur_entry.get() == bucket_head(0), "rtl-hash-tables: InitStrongEnumeration nao conta enumerador");
    let strong_seen = count("RtlStronglyEnumerateEntryHashTable", strong);
    call_export("RtlEndStrongEnumerationHashTable", &[table, strong]);
    assert(weak_seen == 4 && strong_seen == 4 && hash_table.num_enumerators.get() == 0, "rtl-hash-tables: enumeracoes fraca e forte veem as 4 entradas");

    // Expand: 128 -> 129 baldes, diretório de dois níveis; 335 migra do balde 0
    // para o 128 (nível 1, deslocamento 0).
    assert(call_export("RtlExpandHashTable", &[table]) == Some(1) && hash_table.table_size.get() == 129 && hash_table.pivot.get() == 1 && hash_table.divisor_mask.get() == 127, "rtl-hash-tables: Expand divide o balde do Pivot");
    let first_level = hash_table.directory.get();
    let level1 = guest::read64(first_level + 8);
    assert(first_level != directory && guest::read64(first_level) == directory && level1 != 0 && at::<nt::ListEntry>(level1).flink.get() == d && bucket(0).flink.get() == bucket_head(0) && hash_table.non_empty_buckets.get() == 3, "rtl-hash-tables: 335 migra para o balde 128 do nivel 1");
    assert(call_export("RtlLookupEntryHashTable", &[table, 335, 0]) == Some(d) && call_export("RtlLookupEntryHashTable", &[table, 9, 0]) == Some(c), "rtl-hash-tables: Lookup depois do Expand");

    // Contract: volta a 128 baldes e ao diretório de um nível.
    assert(call_export("RtlContractHashTable", &[table]) == Some(1) && hash_table.table_size.get() == 128 && hash_table.pivot.get() == 0 && hash_table.directory.get() == directory && bucket(0).flink.get() == d && hash_table.non_empty_buckets.get() == 3, "rtl-hash-tables: Contract funde o balde 128 no 0 e libera o nivel 1");
    assert(call_export("RtlContractHashTable", &[table]) == Some(0), "rtl-hash-tables: Contract recusa no tamanho minimo");

    // Remove: sem contexto, e com contexto vazio (recebe a posição).
    assert(call_export("RtlRemoveEntryHashTable", &[table, a, 0]) == Some(1) && hash_table.num_entries.get() == 3 && hash_table.non_empty_buckets.get() == 3, "rtl-hash-tables: Remove de duplicata mantem o balde");
    assert(call_export("RtlLookupEntryHashTable", &[table, 5, context]) == Some(b) && call_export("RtlGetNextEntryHashTable", &[table, context]) == Some(0), "rtl-hash-tables: resta uma entrada com assinatura 5");
    lookup_context.chain_head.set(0);
    assert(call_export("RtlRemoveEntryHashTable", &[table, c, context]) == Some(1) && hash_table.non_empty_buckets.get() == 2 && lookup_context.chain_head.get() == bucket_head(120) && bucket(120).flink.get() == bucket_head(120), "rtl-hash-tables: Remove esvazia o balde 120 e preenche o contexto");
    call_export("RtlDeleteHashTable", &[table]);

    // CreateEx: tamanhos inválidos; 256 baldes em dois níveis.
    let holder2 = guest::alloc_bytes(8);
    assert(call_export("RtlCreateHashTableEx", &[holder2, 100, 0, 0]) == Some(0) && call_export("RtlCreateHashTableEx", &[holder2, 64, 0, 0]) == Some(0) && guest::read64(holder2) == 0, "rtl-hash-tables: CreateEx recusa tamanho nao potencia de 2 ou < 128");
    assert(call_export("RtlCreateHashTableEx", &[holder2, 256, 0, 0]) == Some(1), "rtl-hash-tables: CreateEx com 256 baldes");
    let big = guest::read64(holder2);
    let big_directory = if big != 0 { at::<nt::RtlDynamicHashTable>(big).directory.get() } else { 0 };
    assert(big != 0 && at::<nt::RtlDynamicHashTable>(big).table_size.get() == 256 && at::<nt::RtlDynamicHashTable>(big).divisor_mask.get() == 255 && guest::read64(big_directory) != 0 && guest::read64(big_directory + 8) != 0 && guest::read64(big_directory + 16) == 0, "rtl-hash-tables: diretorio de dois niveis com niveis 0 e 1");
    let e = guest::alloc_bytes(0x20);
    assert(call_export("RtlInsertEntryHashTable", &[big, e, 1, 0]) == Some(1) && at::<nt::ListEntry>(guest::read64(big_directory + 8) + 70 * 16).flink.get() == e && call_export("RtlLookupEntryHashTable", &[big, 1, 0]) == Some(e), "rtl-hash-tables: assinatura 1 no balde 198 (nivel 1, deslocamento 70)");
    call_export("RtlDeleteHashTable", &[big]);

    // Cabeçalho do chamador (sem RTL_HASH_ALLOCATED_HEADER) e Shift=4: 0x50 se
    // espalha como 5 (balde 95).
    let header = guest::alloc_bytes(0x28);
    let holder3 = guest::alloc_bytes(8);
    guest::write64(holder3, header);
    assert(call_export("RtlCreateHashTable", &[holder3, 4, 0]) == Some(1) && guest::read64(holder3) == header && at::<nt::RtlDynamicHashTable>(header).flags.get() == 0 && at::<nt::RtlDynamicHashTable>(header).shift.get() == 4, "rtl-hash-tables: cabecalho fornecido pelo chamador mantem Flags=0");
    let f = guest::alloc_bytes(0x20);
    assert(call_export("RtlInsertEntryHashTable", &[header, f, 0x50, 0]) == Some(1) && at::<nt::ListEntry>(at::<nt::RtlDynamicHashTable>(header).directory.get() + 95 * 16).flink.get() == f, "rtl-hash-tables: Shift=4 espalha 0x50 como 5");
    call_export("RtlDeleteHashTable", &[header]);
}


fn rtl_strings_exports(assert: Assert) {
    use crate::ntos::rtl::guest_strings;

    let ansi = |text: &[u8]| {
        let block = guest::alloc_bytes(16 + text.len() as u64 + 1);
        guest::write_bytes(block + 16, text);
        let string = at::<nt::String>(block);
        string.length.set(text.len() as u16);
        string.maximum_length.set(text.len() as u16 + 1);
        string.buffer.set(block + 16);
        block
    };
    let c_string = |text: &[u8]| {
        let block = guest::alloc_bytes(text.len() as u64 + 1);
        guest::write_bytes(block, text);
        block
    };
    let wide = |text: &str| {
        let units: Vec<u16> = text.encode_utf16().collect();
        let block = guest::alloc_bytes(units.len() as u64 * 2 + 2);
            guest::write_bytes(block, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
        block
    };
    let status = |value: Option<u64>| value.map(|value| value as u32);

    // ---- RtlInitUnicodeStringEx --------------------------------------------
    let destination = guest::alloc_bytes(16);
    let destination_string = at::<nt::UnicodeString>(destination);
    let abc = wide("abc");
    assert(call_export("RtlInitUnicodeStringEx", &[destination, abc]) == Some(0) && destination_string.length.get() == 6 && destination_string.maximum_length.get() == 8 && destination_string.buffer.get() == abc, "rtl-strings: RtlInitUnicodeStringEx mede o texto");
    assert(call_export("RtlInitUnicodeStringEx", &[destination, 0]) == Some(0) && destination_string.length.get() == 0 && destination_string.maximum_length.get() == 0 && destination_string.buffer.get() == 0, "rtl-strings: RtlInitUnicodeStringEx com NULL zera");
    let long = guest::alloc_bytes(0x7FFF * 2 + 2);
    guest::write_bytes(long, &alloc::vec![b'a'; 0x7FFF * 2]);
    assert(status(call_export("RtlInitUnicodeStringEx", &[destination, long])) == Some(0xC000_0106) && destination_string.length.get() == 0 && destination_string.maximum_length.get() == 0 && destination_string.buffer.get() == long, "rtl-strings: 0x7FFF WCHARs -> STATUS_NAME_TOO_LONG com Buffer publicado");

    // ---- RtlFreeOemString: ExFreePool do Buffer, campos preservados ----------
    let pool = call_export("ExAllocatePoolWithTag", &[0x200, 0x20, 0x7473_6554]).unwrap_or(0);
    let oem = guest::alloc_bytes(16);
    let oem_string = at::<nt::String>(oem);
    oem_string.length.set(3);
    oem_string.buffer.set(pool);
    call_export("RtlFreeOemString", &[oem]);
    assert(pool != 0 && !crate::ntos::mm::kernel_pool::owns(pool) && oem_string.length.get() == 3 && oem_string.buffer.get() == pool, "rtl-strings: RtlFreeOemString libera o Buffer sem zerar os campos");

    // ---- RtlCompareString / RtlPrefixString (RtlUpperChar só ASCII) --------
    let (s_abc, s_abd, s_upper, s_ab, s_e_acute, s_e_upper) = (ansi(b"abc"), ansi(b"abd"), ansi(b"ABC"), ansi(b"ab"), ansi(b"\xE9"), ansi(b"\xC9"));
    let compare = |a: u64, b: u64, ci: u64| call_export("RtlCompareString", &[a, b, ci]).map(|value| value as i32);
    assert(compare(s_abc, s_abd, 0) == Some(-1) && compare(s_upper, s_abc, 1) == Some(0) && compare(s_upper, s_abc, 0) == Some(-32) && compare(s_ab, s_abc, 0) == Some(-1), "rtl-strings: RtlCompareString diferenca de bytes e de comprimentos");
    assert(compare(s_e_acute, s_e_upper, 1) == Some(32), "rtl-strings: RtlCompareString sem caixa nao dobra o intervalo alto");
    assert(call_export("RtlPrefixString", &[s_ab, s_abc, 0]) == Some(1) && call_export("RtlPrefixString", &[ansi(b"AB"), s_abc, 1]) == Some(1) && call_export("RtlPrefixString", &[ansi(b"AB"), s_abc, 0]) == Some(0) && call_export("RtlPrefixString", &[ansi(b"abcd"), s_abc, 0]) == Some(0), "rtl-strings: RtlPrefixString");

    // ---- RtlCharToInteger ----------------------------------------------------
    let value = guest::alloc_bytes(4);
    let parse = |text: &[u8], base: u64| {
        guest::write32(value, 0xDEAD_BEEF);
        call_export("RtlCharToInteger", &[c_string(text), base, value]).map(|status| (status as u32, guest::read32(value)))
    };
    assert(parse(b"  -123", 0) == Some((0, 0xFFFF_FF85)) && parse(b"0x1F", 0) == Some((0, 0x1F)) && parse(b"777", 8) == Some((0, 0x1FF)) && parse(b"101", 2) == Some((0, 5)), "rtl-strings: RtlCharToInteger sinal, prefixo 0x e bases 8/2");
    assert(parse(b"12z", 10) == Some((0, 12)) && parse(b"0b101", 0) == Some((0, 5)) && parse(b"+ff", 16) == Some((0, 0xFF)) && parse(b"0o17", 0) == Some((0, 15)) && parse(b"09", 0) == Some((0, 9)) && parse(b"\t\n42", 10) == Some((0, 42)), "rtl-strings: RtlCharToInteger para no primeiro nao digito; 0 inicial sem prefixo e decimal");
    assert(parse(b"5", 7).map(|(status, _)| status) == Some(0xC000_000D), "rtl-strings: RtlCharToInteger base 7 -> STATUS_INVALID_PARAMETER");

    // ---- RtlIntegerToUnicode -------------------------------------------------
    let output = guest::alloc_bytes(32);
    let render = |number: u64, base: u64, length: i32| {
            guest::write_bytes(output, &[0xFFu8; 32]);
        let status = call_export("RtlIntegerToUnicode", &[number, base, length as u32 as u64, output]).map(|status| status as u32);
        let units: Vec<u16> = guest::read_bytes(output, 32).chunks(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
        (status, units)
    };
    let text = |units: &[u16], count: usize| String::from_utf16_lossy(&units[..count]);
    let (status_a, units_a) = render(1234, 10, 10);
    let (status_b, units_b) = render(0xBEEF, 16, 4);
    let (status_c, units_c) = render(5, 2, -8);
    assert(status_a == Some(0) && text(&units_a, 4) == "1234" && units_a[4] == 0, "rtl-strings: RtlIntegerToUnicode decimal termina com NUL");
    assert(status_b == Some(0) && text(&units_b, 4) == "BEEF" && units_b[4] == 0xFFFF && status_c == Some(0) && text(&units_c, 8) == "00000101" && units_c[8] == 0xFFFF, "rtl-strings: RtlIntegerToUnicode hex justo sem NUL; comprimento negativo preenche com zeros");
    assert(render(123456, 10, 3).0 == Some(0x8000_0005) && render(7, 3, 10).0 == Some(0xC000_000D), "rtl-strings: RtlIntegerToUnicode BUFFER_OVERFLOW e base invalida");

    // ---- RtlConvertSidToUnicodeString (SID no pool: RtlValidSid recusa usuário)
    let sid = call_export("ExAllocatePoolWithTag", &[0x200, 0x40, 0x7473_6554]).unwrap_or(0);
    let sid_bytes = |authority: [u8; 6], subs: &[u32]| {
        let sid_header = at::<nt::Sid>(sid);
        sid_header.revision.set(1);
        sid_header.sub_authority_count.set(subs.len() as u8);
        guest::write_bytes(sid + 2, &authority);
        for (index, sub) in subs.iter().enumerate() {
            sub_authority(sid, index as u64).set(*sub);
        }
    };
    sid_bytes([0, 0, 0, 0, 0, 5], &[21, 1_234_567_890, 4_294_967_295, 500]);
    let unicode_string = guest::alloc_bytes(16);
    assert(call_export("RtlConvertSidToUnicodeString", &[unicode_string, sid, 1]) == Some(0) && guest_strings::read_unicode_string(unicode_string) == "S-1-5-21-1234567890-4294967295-500", "rtl-strings: RtlConvertSidToUnicodeString aloca o texto decimal");
    call_export("RtlFreeUnicodeString", &[unicode_string]);
    sid_bytes([0x12, 0x34, 0, 0, 0, 1], &[7]);
    let fixed = guest::alloc_bytes(64);
    let caller_string = at::<nt::UnicodeString>(unicode_string);
    caller_string.length.set(0);
    caller_string.maximum_length.set(64);
    caller_string.buffer.set(fixed);
    assert(call_export("RtlConvertSidToUnicodeString", &[unicode_string, sid, 0]) == Some(0) && guest_strings::read_unicode_string(unicode_string) == "S-1-0x123400000001-7" && caller_string.length.get() == 40 && guest::read16(fixed + 40) == 0, "rtl-strings: autoridade de 48 bits em hex no buffer do chamador");
    caller_string.maximum_length.set(40);
    assert(status(call_export("RtlConvertSidToUnicodeString", &[unicode_string, sid, 0])) == Some(0x8000_0005), "rtl-strings: Length >= MaximumLength -> BUFFER_OVERFLOW");
    at::<nt::Sid>(sid).revision.set(2);
    assert(status(call_export("RtlConvertSidToUnicodeString", &[unicode_string, sid, 1])) == Some(0xC000_0078), "rtl-strings: revisao 2 -> STATUS_INVALID_SID");
    call_export("ExFreePool", &[sid]);

    // ---- RtlUnicodeToMultiByteN / Size (c_1252: é=E9, €=80, 一 -> '?') ----
    let source = wide("A\u{e9}\u{20ac}\u{4e00}");
    let bytes = guest::alloc_bytes(16);
    let written = guest::alloc_bytes(4);
    guest::write_bytes(bytes, &[0xCC; 8]);
    assert(call_export("RtlUnicodeToMultiByteN", &[bytes, 3, written, source, 8]) == Some(0) && guest::read32(written) == 3 && guest::read_bytes(bytes, 4) == [0x41, 0xE9, 0x80, 0xCC], "rtl-strings: RtlUnicodeToMultiByteN limitado por MaxBytes");
    assert(call_export("RtlUnicodeToMultiByteN", &[bytes, 10, written, source, 8]) == Some(0) && guest::read32(written) == 4 && guest::read_bytes(bytes, 4) == [0x41, 0xE9, 0x80, 0x3F], "rtl-strings: RtlUnicodeToMultiByteN usa o caractere padrao da WideCharTable");
    assert(call_export("RtlUnicodeToMultiByteSize", &[written, source, 8]) == Some(0) && guest::read32(written) == 4 && call_export("RtlUnicodeToMultiByteSize", &[written, source, 7]) == Some(0) && guest::read32(written) == 3, "rtl-strings: RtlUnicodeToMultiByteSize em SBCS = WCHARs");

    // ---- correção do RtlAnsiCharToUnicodeChar: bytes >= 0x80 pela c_1252
    // (0x80 -> U+20AC, 0x9A -> U+0161), avançando o ponteiro um byte cada.
    let high = guest::alloc_bytes(4);
    guest::write_bytes(high, &[0x80, 0x9A]);
    let pointer_field = guest::alloc_bytes(8);
    guest::write64(pointer_field, high);
    let euro = call_export("RtlAnsiCharToUnicodeChar", &[pointer_field]);
    let caron = call_export("RtlAnsiCharToUnicodeChar", &[pointer_field]);
    assert(euro == Some(0x20AC) && caron == Some(0x0161) && guest::read64(pointer_field) == high + 2, "rtl-strings: RtlAnsiCharToUnicodeChar traduz bytes >= 0x80 pela pagina ANSI");
}


fn rtl_bit_ops_exports(assert: Assert) {
    // Bitmap de 100 bits: 0..9 e 40..63 ocupados (palavras 0x3FF, 0xFFFFFF00, 0, 0).
    let words = guest::alloc_bytes(16);
        guest::write_bytes(words, &[0x0000_03FFu32, 0xFFFF_FF00, 0, 0].iter().flat_map(|word| word.to_le_bytes()).collect::<Vec<u8>>());
    let header = guest::alloc_bytes(16);
    let bitmap = at::<nt::RtlBitmap>(header);
    bitmap.size_of_bit_map.set(100);
    bitmap.buffer.set(words);
    let start = guest::alloc_bytes(4);
    let run = |from: u64| call_export("RtlFindNextForwardRunClear", &[header, from, start]).map(|length| (guest::read32(start), length as u32));
    assert(run(0) == Some((10, 30)) && run(5) == Some((10, 30)) && run(20) == Some((20, 20)), "rtl-bit-ops: RtlFindNextForwardRunClear acha o primeiro run livre");
    assert(run(45) == Some((64, 36)) && run(63) == Some((64, 36)) && run(64) == Some((64, 36)), "rtl-bit-ops: run livre atravessa palavras ate SizeOfBitMap");
    assert(run(100) == Some((100, 0)) && run(150) == Some((150, 0)), "rtl-bit-ops: FromIndex fora do mapa devolve 0");
    guest::write32(words + 8, u32::MAX);
    guest::write32(words + 12, u32::MAX);
    assert(run(64) == Some((100, 0)), "rtl-bit-ops: sem bit livre, StartingRunIndex = SizeOfBitMap");

    assert(call_export("RtlNumberOfSetBitsUlongPtr", &[0xF0F0_0000_0000_0001]) == Some(9) && call_export("RtlNumberOfSetBitsUlongPtr", &[u64::MAX]) == Some(64) && call_export("RtlNumberOfSetBitsUlongPtr", &[0]) == Some(0), "rtl-bit-ops: RtlNumberOfSetBitsUlongPtr");
    assert(call_export("RtlFindMostSignificantBit", &[0x8000_0000_0000_0000]) == Some(63) && call_export("RtlFindMostSignificantBit", &[1]) == Some(0) && call_export("RtlFindMostSignificantBit", &[0x0000_0100_0000_0000]) == Some(40) && call_export("RtlFindMostSignificantBit", &[0x123]) == Some(8) && call_export("RtlFindMostSignificantBit", &[0]) == Some(0xFFFF_FFFF), "rtl-bit-ops: RtlFindMostSignificantBit (zero -> -1)");

    // CRC-32 de "123456789" = 0xCBF43926, inteiro e encadeado ("1234" + "56789").
    let digits = guest::alloc_bytes(16);
    guest::write_bytes(digits, b"123456789");
    let whole = call_export("RtlComputeCrc32", &[0, digits, 9]);
    let head = call_export("RtlComputeCrc32", &[0, digits, 4]).unwrap_or(0);
    let chained = call_export("RtlComputeCrc32", &[head, digits + 4, 5]);
    assert(whole == Some(0xCBF4_3926) && chained == Some(0xCBF4_3926) && call_export("RtlComputeCrc32", &[0x1234, digits, 0]) == Some(0x1234), "rtl-bit-ops: RtlComputeCrc32 IEEE, encadeavel, Length 0 devolve o parcial");
}


fn crt_strings_exports(assert: Assert) {
    let int = |value: Option<u64>| value.map(|value| value as i32);
    let wide = |text: &str| {
        let units: Vec<u16> = text.encode_utf16().collect();
        let block = guest::alloc_bytes(units.len() as u64 * 2 + 8);
            guest::write_bytes(block, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
        block
    };

    // ---- memcpy_s ------------------------------------------------------------
    let (destination, source) = (guest::alloc_bytes(16), guest::alloc_bytes(16));
    guest::write_bytes(source, b"ABCD");
    guest::write_bytes(destination, &[0xEE; 8]);
    assert(call_export("memcpy_s", &[destination, 8, source, 4]) == Some(0) && guest::read_bytes(destination, 6) == b"ABCD\xEE\xEE", "crt-strings: memcpy_s copia Count bytes");
    guest::write_bytes(destination, &[0xEE; 8]);
    assert(call_export("memcpy_s", &[destination, 2, source, 4]) == Some(34) && guest::read_bytes(destination, 3) == [0, 0, 0xEE], "crt-strings: memcpy_s DestSize < Count -> ERANGE e zera DestSize bytes");
    guest::write_bytes(destination, &[0xEE; 8]);
    assert(call_export("memcpy_s", &[destination, 8, 0, 4]) == Some(22) && guest::read_bytes(destination, 8) == [0; 8], "crt-strings: memcpy_s Src nulo -> EINVAL e zera o destino");
    assert(call_export("memcpy_s", &[0, 8, source, 4]) == Some(22) && call_export("memcpy_s", &[0, 0, 0, 0]) == Some(0), "crt-strings: memcpy_s Dest nulo -> EINVAL; Count 0 -> 0");

    // ---- strrchr -------------------------------------------------------------
    let path = guest::alloc_bytes(16);
    guest::write_bytes(path, b"a/b/c");
    let rooted = guest::alloc_bytes(8);
    guest::write_bytes(rooted, b"/abc");
    assert(call_export("strrchr", &[path, b'/' as u64]) == Some(path + 3) && call_export("strrchr", &[path, b'z' as u64]) == Some(0) && call_export("strrchr", &[path, 0]) == Some(path + 5) && call_export("strrchr", &[rooted, b'/' as u64]) == Some(rooted), "crt-strings: strrchr ultima ocorrencia, terminador e primeiro caractere");

    // ---- wcsspn / wcscspn ----------------------------------------------------
    let (text, empty) = (wide("abcxyz"), wide(""));
    assert(call_export("wcsspn", &[text, wide("cba")]) == Some(3) && call_export("wcsspn", &[empty, wide("a")]) == Some(0) && call_export("wcsspn", &[text, text]) == Some(6), "crt-strings: wcsspn");
    assert(call_export("wcscspn", &[text, wide("zyx")]) == Some(3) && call_export("wcscspn", &[text, empty]) == Some(6) && call_export("wcscspn", &[text, wide("a")]) == Some(0), "crt-strings: wcscspn");

    // ---- wcstoul -------------------------------------------------------------
    let end = guest::alloc_bytes(8);
    let parse = |text: &str, base: u64| {
        let block = wide(text);
        let value = call_export("wcstoul", &[block, end, base]).unwrap_or(0xDEAD);
        (value, (guest::read64(end) - block) / 2)
    };
    assert(parse(" \t+123abc", 10) == (123, 6) && parse("0x1F", 0) == (0x1F, 4) && parse("0X1f", 16) == (0x1F, 4) && parse("017", 0) == (15, 3), "crt-strings: wcstoul brancos, sinal, prefixo 0x e octal");
    assert(parse("-1", 10) == (0xFFFF_FFFF, 2) && parse("4294967296", 10) == (0xFFFF_FFFF, 10) && parse("-4294967296", 10) == (1, 11), "crt-strings: wcstoul negacao e saturacao em ULONG_MAX");
    assert(parse("zz", 36) == (1295, 2) && parse("1Z", 36) == (71, 2) && parse("\u{663}\u{664}", 10) == (34, 2) && parse("\u{a0} 42", 0) == (42, 4), "crt-strings: wcstoul letras, digitos arabe-indicos e NBSP como branco");
    assert(parse("xyz", 10) == (0, 0) && parse("0x", 16) == (0, 0) && parse("5", 1) == (0, 0), "crt-strings: wcstoul sem digitos ou base invalida devolve 0 com EndPtr = String");
    assert(call_export("wcstoul", &[wide("77"), 0, 8]) == Some(63), "crt-strings: wcstoul sem EndPtr");

    // ---- classificação ---------------------------------------------------------
    assert(call_export("isspace", &[0x20]) == Some(8) && call_export("isspace", &[0x0B]) == Some(8) && call_export("isspace", &[0xA0]) == Some(0) && call_export("isspace", &[0xFFFF_FFFF]) == Some(0) && call_export("isspace", &[0x109]) == Some(8) && call_export("isspace", &[b'x' as u64]) == Some(0), "crt-strings: isspace pelo pctype (byte baixo, EOF = 0)");
    assert(int(call_export("tolower", &[b'A' as u64])) == Some(b'a' as i32) && int(call_export("tolower", &[0x141])) == Some(0x161) && int(call_export("tolower", &[0xC9])) == Some(0xC9) && int(call_export("tolower", &[0xFFFF_FFFF])) == Some(-1), "crt-strings: tolower so A..Z do locale C");
    assert(int(call_export("toupper", &[b'a' as u64])) == Some(b'A' as i32) && int(call_export("toupper", &[0xE9])) == Some(0xC9) && int(call_export("toupper", &[0x9A])) == Some(0x8A) && int(call_export("toupper", &[0xFF])) == Some(0x9F) && int(call_export("toupper", &[0xB5])) == Some(0xB5) && int(call_export("toupper", &[0x161])) == Some(0x41), "crt-strings: toupper pela pagina ANSI (1252)");
    assert(call_export("iswdigit", &[b'7' as u64]) == Some(4) && call_export("iswdigit", &[0xB2]) == Some(4) && call_export("iswdigit", &[0x663]) == Some(0) && call_export("iswdigit", &[b'a' as u64]) == Some(0), "crt-strings: iswdigit pelo pwctype");
}


fn crt_formatting_exports(assert: Assert) {
    let int = |value: Option<u64>| value.map(|value| value as i32);
    let buffer = guest::alloc_bytes(32);
    let format = guest::alloc_bytes(16);
    guest::write_bytes(format, b"%d-%s");
    let word = guest::alloc_bytes(8);
    guest::write_bytes(word, b"xy");
    // va_list MS x64: slots de 8 bytes.
    let va_list = guest::alloc_bytes(16);
    guest::write64(va_list, 42);
    guest::write64(va_list + 8, word);

    guest::write_bytes(buffer, &[0xEE; 8]);
    assert(int(call_export("vsprintf_s", &[buffer, 6, format, va_list])) == Some(5) && guest::read_bytes(buffer, 7) == b"42-xy\0\xEE", "crt-formatting: vsprintf_s formata e termina");
    guest::write_bytes(buffer, &[0xEE; 8]);
    assert(int(call_export("vsprintf_s", &[buffer, 5, format, va_list])) == Some(-1) && guest::read8(buffer) == 0 && guest::read8(buffer + 4) == 0 && guest::read8(buffer + 5) == 0xEE, "crt-formatting: vsprintf_s sem espaco para o NUL -> Buffer[0] = 0 e -1");
    assert(int(call_export("vsprintf_s", &[0, 6, format, va_list])) == Some(-1) && int(call_export("vsprintf_s", &[buffer, 0, format, va_list])) == Some(-1) && int(call_export("vsprintf_s", &[buffer, 6, 0, va_list])) == Some(-1), "crt-formatting: vsprintf_s parametros nulos -> -1");
    guest::write8(buffer, 0x41);
    assert(int(call_export("vsprintf_s", &[buffer, 0x8000_0000, format, va_list])) == Some(-1) && guest::read8(buffer) == 0, "crt-formatting: SizeOfBuffer > INT_MAX recusa com Buffer[0] = 0");

    let hex_format = guest::alloc_bytes(16);
    guest::write_bytes(hex_format, b"%u:%x");
    assert(int(call_export("sprintf_s", &[buffer, 16, hex_format, 7, 255])) == Some(4) && guest::read_bytes(buffer, 5) == b"7:ff\0", "crt-formatting: sprintf_s variadico");
}


fn io_csq_exports(assert: Assert) {
    fn code(bytes: &[u8]) -> u64 {
        let pointer = guest::alloc_bytes(bytes.len() as u64 + 16);
        guest::write_bytes(pointer, bytes);
        pointer
    }
    // mov rax, cell; mov [rax], rdx; ret
    fn store_rdx(cell: u64) -> Vec<u8> {
        let mut bytes = alloc::vec![0x48, 0xB8];
        bytes.extend_from_slice(&cell.to_le_bytes());
        bytes.extend_from_slice(&[0x48, 0x89, 0x10, 0xC3]);
        bytes
    }
    let cells = guest::alloc_bytes(0x40);
    let (queued, completed, released) = (cells, cells + 8, cells + 16);
    // CsqAcquireLock: mov byte [rdx], 5; ret — CsqReleaseLock grava o KIRQL recebido.
    let acquire = code(&[0xC6, 0x02, 0x05, 0xC3]);
    let release = code(&store_rdx(released));
    let insert = code(&store_rdx(queued));
    // CsqRemoveIrp: mov rax, queued; mov qword [rax], 0; ret
    let mut remove_bytes = alloc::vec![0x48, 0xB8];
    remove_bytes.extend_from_slice(&queued.to_le_bytes());
    remove_bytes.extend_from_slice(&[0x48, 0xC7, 0x00, 0, 0, 0, 0, 0xC3]);
    let remove = code(&remove_bytes);
    // CsqPeekNextIrp: Irp != NULL -> NULL; senão *queued.
    let mut peek_bytes = alloc::vec![0x48, 0x85, 0xD2, 0x75, 0x0E, 0x48, 0xB8];
    peek_bytes.extend_from_slice(&queued.to_le_bytes());
    peek_bytes.extend_from_slice(&[0x48, 0x8B, 0x00, 0xC3, 0x31, 0xC0, 0xC3]);
    let peek = code(&peek_bytes);
    let complete = code(&store_rdx(completed));
    // CsqInsertIrpEx que recusa com STATUS_CANCELLED (0xC0000120).
    let mut insert_ex_bytes = store_rdx(queued);
    insert_ex_bytes.pop();
    insert_ex_bytes.extend_from_slice(&[0xB8, 0x20, 0x01, 0x00, 0xC0, 0xC3]);
    let insert_ex = code(&insert_ex_bytes);

    let csq = guest::alloc_bytes(0x40);
    let context = guest::alloc_bytes(0x18);
    let (queue, irp_context) = (at::<nt::IoCsq>(csq), at::<nt::IoCsqIrpContext>(context));
    // IRP com a stack location corrente válida (CSL = slot 0).
    let irp = guest::alloc_bytes(nt::Irp::SIZE + nt::IoStackLocation::SIZE);
    let (packet, slot) = (at::<nt::Irp>(irp), at::<nt::IoStackLocation>(irp + nt::Irp::SIZE));
    packet.tail.overlay.current_stack_location.set(slot.address());

    assert(
        call_export("IoCsqInitialize", &[csq, insert, remove, peek, acquire, release, complete]) == Some(0)
            && queue.type_.get() == 2
            && queue.csq_insert_irp.get() == insert
            && queue.csq_peek_next_irp.get() == peek
            && queue.csq_complete_canceled_irp.get() == complete,
        "io-csq: IoCsqInitialize preenche o IO_CSQ (Type=2)",
    );
    call_export("IoCsqInsertIrp", &[csq, irp, context]);
    assert(
        guest::read64(queued) == irp
            && packet.tail.overlay.driver_context[3].get() == context
            && irp_context.type_.get() == 1
            && irp_context.irp.get() == irp
            && irp_context.csq.get() == csq,
        "io-csq: IoCsqInsertIrp liga IRP, contexto e fila do driver",
    );
    assert(
        packet.cancel_routine.get() != 0 && slot.control.get() & 1 == 1 && guest::read64(released) == 5,
        "io-csq: insert marca pendente, instala a cancel routine e devolve o KIRQL ao release",
    );
    assert(
        call_export("IoCsqRemoveNextIrp", &[csq, 0]) == Some(irp)
            && guest::read64(queued) == 0
            && irp_context.irp.get() == 0
            && packet.tail.overlay.driver_context[3].get() == 0
            && packet.cancel_routine.get() == 0,
        "io-csq: IoCsqRemoveNextIrp retira o IRP e solta o contexto",
    );
    assert(call_export("IoCsqRemoveNextIrp", &[csq, 0]) == Some(0), "io-csq: fila vazia devolve NULL");
    call_export("IoCsqInsertIrp", &[csq, irp, context]);
    assert(
        call_export("IoCsqRemoveIrp", &[csq, context]) == Some(irp) && guest::read64(queued) == 0 && irp_context.irp.get() == 0,
        "io-csq: IoCsqRemoveIrp pelo contexto",
    );
    assert(call_export("IoCsqRemoveIrp", &[csq, context]) == Some(0), "io-csq: contexto sem IRP devolve NULL");
    // Cancelamento real: IoCancelIrp -> IopCsqCancelRoutine -> CsqCompleteCanceledIrp.
    call_export("IoCsqInsertIrp", &[csq, irp, 0]);
    assert(packet.tail.overlay.driver_context[3].get() == csq, "io-csq: sem contexto o IRP aponta para a IO_CSQ");
    assert(
        call_export("IoCancelIrp", &[irp]) == Some(1) && guest::read64(completed) == irp && guest::read64(queued) == 0,
        "io-csq: IoCancelIrp entrega o IRP ao CsqCompleteCanceledIrp pela IopCsqCancelRoutine",
    );
    // Corrida: Cancel já ligado antes do insert.
    guest::write64(completed, 0);
    packet.cancel.set(1);
    call_export("IoCsqInsertIrp", &[csq, irp, context]);
    assert(
        guest::read64(completed) == irp && guest::read64(queued) == 0 && packet.cancel_routine.get() == 0 && irp_context.irp.get() == 0 && packet.tail.overlay.driver_context[3].get() == 0,
        "io-csq: insert de IRP ja cancelado completa pelo CsqCompleteCanceledIrp",
    );
    // Variante Ex: a recusa do driver volta ao chamador sem pendência.
    packet.cancel.set(0);
    slot.control.set(0);
    packet.cancel_routine.set(0);
    let csq_ex = guest::alloc_bytes(0x40);
    assert(call_export("IoCsqInitializeEx", &[csq_ex, insert_ex, remove, peek, acquire, release, complete]) == Some(0) && at::<nt::IoCsq>(csq_ex).type_.get() == 3, "io-csq: IoCsqInitializeEx marca Type=3");
    let refused = call_export("IoCsqInsertIrpEx", &[csq_ex, irp, 0, 0x1234]).map(|status| status as u32);
    assert(
        refused == Some(0xC000_0120) && packet.cancel_routine.get() == 0 && slot.control.get() & 1 == 0,
        "io-csq: IoCsqInsertIrpEx devolve a recusa do CsqInsertIrpEx sem marcar pendente",
    );
    for pointer in [cells, acquire, release, insert, remove, peek, complete, insert_ex, csq, csq_ex, context, irp] {
        guest::free_bytes(pointer);
    }
}


fn io_irp_request_exports(assert: Assert) {
    use crate::ntos::ps::process;
    fn code(bytes: &[u8]) -> u64 {
        let pointer = guest::alloc_bytes(bytes.len() as u64 + 16);
        guest::write_bytes(pointer, bytes);
        pointer
    }
    let complete_request = crate::ntos::init::exports::export_module().ok().and_then(|module| module.exports.exports.get("IofCompleteRequest").copied()).unwrap_or(0);
    // Despacho que grava IoStatus.Status, chama IofCompleteRequest(Irp, 0) e devolve `result`.
    let dispatch = |io_status: u32, result: u32| {
        let mut bytes = alloc::vec![0x48, 0x83, 0xEC, 0x28, 0xC7, 0x42, 0x30];
        bytes.extend_from_slice(&io_status.to_le_bytes());
        bytes.extend_from_slice(&[0x48, 0x89, 0xD1, 0x31, 0xD2, 0x48, 0xB8]);
        bytes.extend_from_slice(&complete_request.to_le_bytes());
        bytes.extend_from_slice(&[0xFF, 0xD0, 0xB8]);
        bytes.extend_from_slice(&result.to_le_bytes());
        bytes.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
        code(&bytes)
    };
    let completed_now = dispatch(0x77, 0x77);
    let completed_later = dispatch(0x66, 0x103);
    let driver = guest::alloc_bytes(nt::DriverObject::SIZE);
    let device = guest::alloc_bytes(nt::DeviceObject::SIZE);
    let (fake_driver, fake_device) = (at::<nt::DriverObject>(driver), at::<nt::DeviceObject>(device));
    fake_device.driver_object.set(driver);
    fake_device.stack_size.set(1);
    let device_control = &fake_driver.major_function[0x0E];

    // IoSynchronousCallDriver: status síncrono direto, pendente pelo evento.
    device_control.set(completed_now);
    let packet = call_export("IoAllocateIrp", &[1, 0]).unwrap_or(0);
    at::<nt::IoStackLocation>(packet + nt::Irp::SIZE).major_function.set(0x0E);
    assert(complete_request != 0 && packet != 0 && call_export("IoSynchronousCallDriver", &[device, packet]).map(|status| status as u32) == Some(0x77), "io-irp-request: IoSynchronousCallDriver devolve o status sincrono do despacho");
    call_export("IoReuseIrp", &[packet, 0]);
    at::<nt::IoStackLocation>(packet + nt::Irp::SIZE).major_function.set(0x0E);
    device_control.set(completed_later);
    assert(call_export("IoSynchronousCallDriver", &[device, packet]).map(|status| status as u32) == Some(0x66), "io-irp-request: IoSynchronousCallDriver espera o evento e devolve IoStatus");
    call_export("IoFreeIrp", &[packet]);

    // IoForwardIrpSynchronously: copia a stack location corrente para a próxima.
    device_control.set(completed_now);
    let forwarded = call_export("IoAllocateIrp", &[2, 0]).unwrap_or(0);
    let (slot0, slot1) = (forwarded + nt::Irp::SIZE, forwarded + nt::Irp::SIZE + nt::IoStackLocation::SIZE);
    let (forwarded_irp, first_slot, second_slot) = (at::<nt::Irp>(forwarded), at::<nt::IoStackLocation>(slot0), at::<nt::IoStackLocation>(slot1));
    forwarded_irp.current_location.set(2);
    forwarded_irp.tail.overlay.current_stack_location.set(slot1);
    second_slot.major_function.set(0x0E);
    second_slot.parameters.device_io_control.io_control_code.set(0x0022_2003);
    second_slot.control.set(0xE0);
    assert(call_export("IoForwardIrpSynchronously", &[device, forwarded]) == Some(1) && first_slot.major_function.get() == 0x0E && first_slot.parameters.device_io_control.io_control_code.get() == 0x0022_2003 && forwarded_irp.io_status.status.get() == 0x77, "io-irp-request: IoForwardIrpSynchronously copia a stack location e despacha");
    forwarded_irp.current_location.set(1);
    assert(call_export("IoForwardIrpSynchronously", &[device, forwarded]) == Some(0), "io-irp-request: IoForwardIrpSynchronously sem stack location livre devolve FALSE");
    call_export("IoFreeIrp", &[forwarded]);

    // IoBuildAsynchronousFsdRequest: buffered (leitura/escrita) e neither.
    let buffer = guest::alloc_bytes(16);
    guest::write_bytes(buffer, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    let offset = guest::alloc_bytes(8);
    at::<nt::LargeInteger>(offset).quad_part.set(0x2000);
    let iosb = guest::alloc_bytes(16);
    let buffered = guest::alloc_bytes(nt::DeviceObject::SIZE);
    let buffered_device = at::<nt::DeviceObject>(buffered);
    buffered_device.stack_size.set(1);
    buffered_device.flags.set(4); // DO_BUFFERED_IO
    let read = call_export("IoBuildAsynchronousFsdRequest", &[3, buffered, buffer, 16, offset, iosb]).unwrap_or(0);
    let read_irp = || at::<nt::Irp>(read);
    let top = if read != 0 { read_irp().tail.overlay.current_stack_location.get() - nt::IoStackLocation::SIZE } else { 0 };
    let top_stack = || at::<nt::IoStackLocation>(top);
    assert(
        read != 0
            && top_stack().major_function.get() == 3
            && top_stack().parameters.read.length.get() == 16
            && top_stack().parameters.read.byte_offset.quad_part.get() == 0x2000
            && read_irp().user_iosb.get() == iosb
            && read_irp().user_event.get() == 0
            && read_irp().user_buffer.get() == buffer
            && read_irp().flags.get() & 0xFFFF == 0x70
            && read_irp().associated_irp.system_buffer.get() != 0
            && read_irp().tail.overlay.thread.get() == process::get_current_thread(),
        "io-irp-request: IoBuildAsynchronousFsdRequest de leitura buffered",
    );
    let write = call_export("IoBuildAsynchronousFsdRequest", &[4, buffered, buffer, 16, offset, iosb]).unwrap_or(0);
    let system = if write != 0 { at::<nt::Irp>(write).associated_irp.system_buffer.get() } else { 0 };
    assert(write != 0 && system != 0 && guest::read_bytes(system, 16) == guest::read_bytes(buffer, 16) && at::<nt::Irp>(write).flags.get() & 0xFFFF == 0x30 && at::<nt::Irp>(write).user_buffer.get() == 0, "io-irp-request: IoBuildAsynchronousFsdRequest de escrita copia para o SystemBuffer");
    let neither = guest::alloc_bytes(nt::DeviceObject::SIZE);
    at::<nt::DeviceObject>(neither).stack_size.set(1);
    let raw = call_export("IoBuildAsynchronousFsdRequest", &[3, neither, buffer, 16, 0, iosb]).unwrap_or(0);
    assert(raw != 0 && at::<nt::Irp>(raw).user_buffer.get() == buffer && at::<nt::Irp>(raw).associated_irp.system_buffer.get() == 0 && at::<nt::Irp>(raw).mdl_address.get() == 0, "io-irp-request: IoBuildAsynchronousFsdRequest METHOD_NEITHER usa o UserBuffer");
    for packet in [read, write, raw] {
        let system = if packet != 0 { at::<nt::Irp>(packet).associated_irp.system_buffer.get() } else { 0 };
        if system != 0 {
            guest::free_bytes(system);
        }
        call_export("IoFreeIrp", &[packet]);
    }

    // IoAllocateIrpEx: com extensão reserva duas stack locations no topo.
    let plain = call_export("IoAllocateIrpEx", &[0, 2, 0]).unwrap_or(0);
    let extended = call_export("IoAllocateIrpEx", &[u64::MAX, 2, 0]).unwrap_or(0);
    // IRP+0xC8: extensão do IRP do OpenNT (io/irp_request.rs); o _IRP do 19041 não tem campo nesse offset.
    assert(plain != 0 && at::<nt::Irp>(plain).stack_count.get() == 2 && at::<nt::Irp>(plain).current_location.get() == 3 && guest::read64(plain + 0xC8) == 0, "io-irp-request: IoAllocateIrpEx sem extensao");
    assert(
        extended != 0 && at::<nt::Irp>(extended).stack_count.get() == 2 && at::<nt::Irp>(extended).current_location.get() == 3 && at::<nt::Irp>(extended).tail.overlay.current_stack_location.get() == extended + nt::Irp::SIZE + 2 * nt::IoStackLocation::SIZE && guest::read64(extended + 0xC8) == extended + nt::Irp::SIZE + 2 * nt::IoStackLocation::SIZE,
        "io-irp-request: IoAllocateIrpEx(-1) reserva a IOP_IRP_EXTENSION acima da pilha",
    );
    call_export("IoFreeIrp", &[plain]);
    call_export("IoFreeIrp", &[extended]);

    // IoSetCompletionRoutineEx + IofCompleteRequest -> IopUnloadSafeCompletion -> rotina.
    let cells = guest::alloc_bytes(0x20);
    // mov rax, cells; mov [rax], rdx; mov [rax+8], r8; mov eax, 0xC0000016; ret
    let mut routine_bytes = alloc::vec![0x48, 0xB8];
    routine_bytes.extend_from_slice(&cells.to_le_bytes());
    routine_bytes.extend_from_slice(&[0x48, 0x89, 0x10, 0x4C, 0x89, 0x40, 0x08, 0xB8, 0x16, 0x00, 0x00, 0xC0, 0xC3]);
    let routine = code(&routine_bytes);
    let chained = guest::alloc_bytes(nt::Irp::SIZE + 2 * nt::IoStackLocation::SIZE);
    let (chained_irp, chained_slot) = (at::<nt::Irp>(chained), at::<nt::IoStackLocation>(chained + nt::Irp::SIZE));
    chained_irp.stack_count.set(2);
    chained_irp.current_location.set(2);
    chained_irp.tail.overlay.current_stack_location.set(chained_slot.address() + nt::IoStackLocation::SIZE);
    assert(call_export("IoSetCompletionRoutineEx", &[0, chained, routine, 0xC0DE, 0, 0, 0]).map(|status| status as u32) == Some(0xC000_000D), "io-irp-request: IoSetCompletionRoutineEx sem gatilhos recusa");
    assert(call_export("IoSetCompletionRoutineEx", &[0, chained, routine, 0xC0DE, 1, 1, 1]) == Some(0) && chained_slot.control.get() == 0xE0 && chained_slot.completion_routine.get() != routine && chained_slot.completion_routine.get() != 0, "io-irp-request: IoSetCompletionRoutineEx instala o invólucro unload-safe");
    chained_irp.current_location.set(1);
    chained_irp.tail.overlay.current_stack_location.set(chained_slot.address());
    chained_irp.io_status.status.set(0);
    call_export("IofCompleteRequest", &[chained, 0]);
    assert(guest::read64(cells) == chained && guest::read64(cells + 8) == 0xC0DE, "io-irp-request: IopUnloadSafeCompletion chama a rotina do driver com IRP e contexto");
    guest::free_bytes(chained);

    // IoIsOperationSynchronous (vetores do modelo de referência da desmontagem).
    let file = guest::alloc_bytes(nt::FileObject::SIZE);
    let probe = guest::alloc_bytes(nt::Irp::SIZE + nt::IoStackLocation::SIZE);
    let (probe_irp, probe_slot, file_object) = (at::<nt::Irp>(probe), at::<nt::IoStackLocation>(probe + nt::Irp::SIZE), at::<nt::FileObject>(file));
    probe_irp.tail.overlay.current_stack_location.set(probe_slot.address());
    probe_slot.file_object.set(file);
    let cases: [(u32, u32, u64); 7] = [(0, 0, 0), (4, 0, 1), (0, 2, 1), (2, 2, 0), (0x42, 0, 1), (0x42, 2, 1), (2, 0, 0)];
    let synchronous = cases.iter().all(|&(irp_flags, file_flags, expected)| {
        probe_irp.flags.set(irp_flags);
        file_object.flags.set(file_flags);
        call_export("IoIsOperationSynchronous", &[probe]) == Some(expected)
    });
    assert(synchronous, "io-irp-request: IoIsOperationSynchronous segue FO_SYNCHRONOUS_IO, IRP_SYNCHRONOUS_API e paging");

    // IoPropagateIrpExtension: só os tipos pedidos nas flags.
    let source = guest::alloc_bytes(0xD0);
    let target = guest::alloc_bytes(0xD0);
    call_export("IoSetGenericIrpExtension", &[source, 0x5A5A, 1]);
    guest::write_bytes(cells, &[9u8; 16]);
    call_export("IoSetActivityIdIrp", &[source, cells]);
    call_export("IoPropagateIrpExtension", &[source, target, 0]);
    assert(call_export("IoGetGenericIrpExtension", &[target]) == Some(0), "io-irp-request: IoPropagateIrpExtension sem flags nao copia");
    call_export("IoPropagateIrpExtension", &[source, target, 3]);
    let activity = call_export("IoGetActivityIdIrp", &[target, cells + 0x10]).map(|status| status as u32);
    assert(call_export("IoGetGenericIrpExtension", &[target]) == Some(0x5A5A) && activity == Some(0) && guest::read_bytes(cells + 0x10, 16) == [9u8; 16], "io-irp-request: IoPropagateIrpExtension copia extensao generica e activity id");
    call_export("IoFreeIrp", &[source]);
    call_export("IoFreeIrp", &[target]);

    // IoGetRequestorProcessId: UniqueProcessId do processo do IRP.
    let owner = call_export("IoGetRequestorProcess", &[probe]).unwrap_or(0);
    let expected = if owner != 0 { at::<nt::Eprocess>(owner).unique_process_id.get() as u32 as u64 } else { 0 };
    assert(call_export("IoGetRequestorProcessId", &[probe]) == Some(expected), "io-irp-request: IoGetRequestorProcessId le o UniqueProcessId");

    // IoGetRequestorSessionId: sem thread -> -1/STATUS_UNSUCCESSFUL; com thread -> sessão do processo.
    probe_irp.tail.overlay.thread.set(0);
    let unsuccessful = call_export("IoGetRequestorSessionId", &[probe, cells]).map(|status| status as u32);
    assert(unsuccessful == Some(0xC000_0001) && guest::read32(cells) == 0xFFFF_FFFF, "io-irp-request: IoGetRequestorSessionId sem thread");
    let thread = process::get_current_thread();
    if thread != 0 {
        probe_irp.tail.overlay.thread.set(thread);
        let owner = at::<nt::Kthread>(thread).process.get();
        let session = if owner != 0 { crate::ntos::ps::session::query(owner) } else { 0 };
        assert(call_export("IoGetRequestorSessionId", &[probe, cells]) == Some(0) && guest::read32(cells) == session, "io-irp-request: IoGetRequestorSessionId devolve a sessao do processo da thread");
    }

    // IoGetInitiatorProcess: extensão do FILE_OBJECT, slot 1, processo em +8.
    file_object.file_object_extension.set(0);
    assert(call_export("IoGetInitiatorProcess", &[file]) == Some(0), "io-irp-request: IoGetInitiatorProcess sem extensao devolve NULL");
    let extension = guest::alloc_bytes(0x40);
    let initiator = guest::alloc_bytes(0x10);
    // Registro de extensão por tipo [1]: o processo iniciador fica em +8.
    guest::write64(initiator + 8, 0xFFFF_8000_1234_5000);
    at::<nt::IopFileObjectExtension>(extension).fo_ext_per_type_extension[1].set(initiator);
    file_object.file_object_extension.set(extension);
    assert(call_export("IoGetInitiatorProcess", &[file]) == Some(0xFFFF_8000_1234_5000), "io-irp-request: IoGetInitiatorProcess le o processo iniciador da extensao");
    file_object.file_object_extension.set(0);
    guest::free_bytes(extension);
    guest::free_bytes(initiator);

    for pointer in [completed_now, completed_later, driver, device, buffer, offset, iosb, buffered, neither, cells, routine, file, probe] {
        guest::free_bytes(pointer);
    }
}


fn io_pnp_interface_exports(assert: Assert) {
    use crate::hal::amd64::native_call;
    use crate::ntos::rtl::guest_strings;
    let block = guest::alloc_bytes(0x400);
    let guid = block;
    guest::write_bytes(guid, b"OpenNTIoDevIfcT1");
    let link_string = block + 0x20;
    let list_slot = block + 0x40;
    // PDO sintético sem \Device próprio: o link vai para \Device\PDO0.
    let pdo = guest::alloc_bytes(0x150);
    let registered = call_export("IoRegisterDeviceInterface", &[pdo, guid, 0, link_string]).map(|status| status as u32);
    let link = guest_strings_read(link_string);
    assert(registered == Some(0) && link.starts_with("\\DosDevices\\#{"), "io-pnp-interface: interface de teste registrada");

    let list_of = |pdo: u64, flags: u64| -> Option<Vec<alloc::string::String>> {
        if call_export("IoGetDeviceInterfaces", &[guid, pdo, flags, list_slot]) != Some(0) {
            return None;
        }
        let list = guest::read64(list_slot);
        let mut links = Vec::new();
        let mut cursor = list;
        loop {
            let entry = guest_strings::read_wide_string(cursor);
            if entry.is_empty() {
                break;
            }
            cursor += (entry.encode_utf16().count() as u64 + 1) * 2;
            links.push(entry);
        }
        call_export("ExFreePool", &[list]);
        Some(links)
    };
    assert(list_of(0, 0).is_some_and(|links| links.is_empty()), "io-pnp-interface: interface desabilitada fica fora da lista (um L'\\0')");
    assert(list_of(0, 1).is_some_and(|links| links.len() == 1 && links[0] == link), "io-pnp-interface: DEVICE_INTERFACE_INCLUDE_NONACTIVE inclui a interface desabilitada");
    call_export("IoSetDeviceInterfaceState", &[link_string, 1]);
    assert(list_of(0, 0).is_some_and(|links| links.len() == 1 && links[0] == link), "io-pnp-interface: interface habilitada entra na lista MULTI_SZ");
    let stranger = guest::alloc_bytes(0x150);
    assert(list_of(stranger, 1).is_some_and(|links| links.is_empty()), "io-pnp-interface: filtro por PDO exclui interfaces de outro dispositivo");
    call_export("IoSetDeviceInterfaceState", &[link_string, 0]);

    // IoGetIommuInterface: o mesmo status da HalPrivateDispatchTable.
    let table = crate::hal::private_dispatch::table_address();
    let routine = if table != 0 { at::<nt::HalPrivateDispatch>(table).hal_get_iommu_interface.get() } else { 0 };
    let expected = if routine != 0 { native_call::call(routine, &[1, block + 0x100]) as u32 } else { 0xC000_00BB };
    assert(call_export("IoGetIommuInterface", &[1, block + 0x100]).map(|status| status as u32) == Some(expected), "io-pnp-interface: IoGetIommuInterface delega a HalGetIommuInterface");

    guest::free_bytes(at::<nt::UnicodeString>(link_string).buffer.get());
    guest::free_bytes(stranger);
    guest::free_bytes(pdo);
    guest::free_bytes(block);
}


fn io_builtin_driver_exports(assert: Assert) {
    use crate::ntos::io::lifecycle;
    use crate::ntos::ob::object_manager;
    fn code(bytes: &[u8]) -> u64 {
        let pointer = guest::alloc_bytes(bytes.len() as u64 + 16);
        guest::write_bytes(pointer, bytes);
        pointer
    }
    let previous = lifecycle::current_driver();
    let cells = guest::alloc_bytes(0x20);
    // Inicialização: mov rax, cells; mov [rax], rcx; mov [rax+8], rdx; xor eax, eax; ret
    let mut init_bytes = alloc::vec![0x48, 0xB8];
    init_bytes.extend_from_slice(&cells.to_le_bytes());
    init_bytes.extend_from_slice(&[0x48, 0x89, 0x08, 0x48, 0x89, 0x50, 0x08, 0x31, 0xC0, 0xC3]);
    let init = code(&init_bytes);
    // Inicialização que falha: mov eax, 0xC0000001; ret
    let failing = code(&[0xB8, 0x01, 0x00, 0x00, 0xC0, 0xC3]);
    let block = guest::alloc_bytes(0x200);
    guest::write64(cells + 8, 0xFFFF);
    let name = unicode_at(block, "\\Driver\\OpenNtBuiltinTest");
    let created = call_export("IoCreateDriver", &[name, init]).map(|status| status as u32);
    let driver = guest::read64(cells);
    let published = object_manager::lookup("\\Driver\\OpenNtBuiltinTest").and_then(object_manager::node).and_then(|node| node.data).map_or(0, |data| data.native_pointer);
    assert(created == Some(0) && driver != 0 && published == driver && guest::read64(cells + 8) == 0, "io-builtin-driver: IoCreateDriver publica o DRIVER_OBJECT e chama a inicializacao com RegistryPath NULL");
    let extension = if driver != 0 { at::<nt::DriverObject>(driver).driver_extension.get() } else { 0 };
    assert(
        extension != 0 && at::<nt::DriverObject>(driver).flags.get() & 4 != 0 && at::<nt::DriverObject>(driver).driver_init.get() == init && guest_strings_read(at::<nt::DriverExtension>(extension).service_key_name.address()) == "\\Driver\\OpenNtBuiltinTest" && at::<nt::DriverExtension>(extension).driver_object.get() == driver,
        "io-builtin-driver: DRVO_BUILTIN_DRIVER, DriverInit, DriverExtension e ServiceKeyName",
    );
    assert(call_export("IoCreateDriver", &[name, init]).map(|status| status as u32) == Some(0xC000_0035), "io-builtin-driver: nome repetido colide");
    let failed_name = unicode_at(block + 0x100, "\\Driver\\OpenNtBuiltinFail");
    assert(
        call_export("IoCreateDriver", &[failed_name, failing]).map(|status| status as u32) == Some(0xC000_0001) && object_manager::lookup("\\Driver\\OpenNtBuiltinFail").is_none(),
        "io-builtin-driver: falha da inicializacao retira o driver",
    );
    // Sem nome: "\Driver\%08u".
    guest::write64(cells, 0);
    let unnamed = call_export("IoCreateDriver", &[0, init]).map(|status| status as u32);
    let unnamed_driver = guest::read64(cells);
    let unnamed_name = lifecycle::node_by_driver_object(unnamed_driver).and_then(object_manager::node).map(|node| node.name).unwrap_or_default();
    assert(unnamed == Some(0) && unnamed_name.len() == 8 && unnamed_name.bytes().all(|byte| byte.is_ascii_digit()), "io-builtin-driver: IoCreateDriver sem nome gera \\Driver\\%08u");
    assert(lifecycle::current_driver() == previous, "io-builtin-driver: contexto de driver ambiente restaurado");
    assert(lifecycle::unload_driver("OpenNtBuiltinTest") && lifecycle::unload_driver(&unnamed_name), "io-builtin-driver: drivers embutidos de teste descarregados");
    for pointer in [cells, init, failing, block] {
        guest::free_bytes(pointer);
    }
}


fn io_named_event_exports(assert: Assert) {
    use crate::ntos::ke::dispatcher;
    use crate::ntos::ob::object_manager;
    let block = guest::alloc_bytes(0x400);
    let handles = block + 0x300;
    let name = unicode_at(block, "\\KernelObjects\\OpenNtIoNotificationTest");
    let event = call_export("IoCreateNotificationEvent", &[name, handles]).unwrap_or(0);
    let first = guest::read64(handles);
    assert(
        event != 0 && first != 0 && at::<nt::Kevent>(event).header.type_.get() == 0 && dispatcher::read_state(event) == 1 && object_manager::lookup("\\KernelObjects\\OpenNtIoNotificationTest").is_some(),
        "io-named-event: IoCreateNotificationEvent cria o evento nomeado sinalizado com handle de kernel",
    );
    let again = call_export("IoCreateNotificationEvent", &[name, handles + 8]).unwrap_or(0);
    let second = guest::read64(handles + 8);
    assert(again == event && second != 0 && second != first, "io-named-event: OBJ_OPENIF reabre o mesmo KEVENT com outro handle");
    let sync_name = unicode_at(block + 0x100, "\\KernelObjects\\OpenNtIoSynchronizationTest");
    let sync = call_export("IoCreateSynchronizationEvent", &[sync_name, handles + 0x10]).unwrap_or(0);
    let third = guest::read64(handles + 0x10);
    assert(sync != 0 && third != 0 && at::<nt::Kevent>(sync).header.type_.get() == 1 && dispatcher::read_state(sync) == 1, "io-named-event: IoCreateSynchronizationEvent cria SynchronizationEvent sinalizado");
    guest::write64(handles + 0x18, 0x5A5A);
    let directory = unicode_at(block + 0x200, "\\KernelObjects");
    assert(call_export("IoCreateNotificationEvent", &[directory, handles + 0x18]) == Some(0) && guest::read64(handles + 0x18) == 0x5A5A, "io-named-event: nome de outro tipo devolve NULL sem handle");
    let orphan = unicode_at(block + 0x280, "\\OpenNtNoSuchDirectory\\Event");
    assert(call_export("IoCreateNotificationEvent", &[orphan, handles + 0x18]) == Some(0), "io-named-event: diretorio pai inexistente devolve NULL");
    let closed = [first, second, third].iter().all(|&handle| call_export("ZwClose", &[handle]) == Some(0));
    assert(closed && object_manager::lookup("\\KernelObjects\\OpenNtIoNotificationTest").is_none(), "io-named-event: fechar o ultimo handle libera o evento e o nome");
    guest::free_bytes(block);
}


fn io_wmi_data_block_exports(assert: Assert) {
    let buffer = guest::alloc_bytes(0x40);
    guest::write32(buffer, 0x20);
    let opened = call_export("IoWMIOpenBlock", &[buffer + 0x10, 1, buffer + 0x30]).map(|status| status as u32);
    let query = call_export("IoWMIQuerySingleInstance", &[0, buffer + 0x10, buffer, buffer + 0x20]).map(|status| status as u32);
    let name = call_export("IoWMIHandleToInstanceName", &[0, 0, buffer + 0x20]).map(|status| status as u32);
    assert(opened == Some(0xC000_0295) && query == opened && name == opened, "io-wmi-data-block: sem provedor WMI as consultas por bloco seguem o IoWMIOpenBlock (STATUS_WMI_GUID_NOT_FOUND)");
    guest::free_bytes(buffer);
}


fn io_work_item_queue_exports(assert: Assert) {
    let cells = guest::alloc_bytes(0x20);
    // Rotina Ex: mov rax, cells; mov [rax], rcx; mov [rax+8], rdx; mov [rax+0x10], r8; ret
    let mut routine_bytes = alloc::vec![0x48, 0xB8];
    routine_bytes.extend_from_slice(&cells.to_le_bytes());
    routine_bytes.extend_from_slice(&[0x48, 0x89, 0x08, 0x48, 0x89, 0x50, 0x08, 0x4C, 0x89, 0x40, 0x10, 0xC3]);
    let routine = guest::alloc_bytes(routine_bytes.len() as u64 + 16);
    guest::write_bytes(routine, &routine_bytes);
    let device = guest::alloc_bytes(0x150);
    let item = call_export("IoAllocateWorkItem", &[device]).unwrap_or(0);
    assert(item != 0 && call_export("IoTryQueueWorkItem", &[item, routine, 1, 0x77]) == Some(1), "io-work-item-queue: IoTryQueueWorkItem aceita o item");
    crate::ntos::io::work_items::run_queue();
    assert(guest::read64(cells) == device && guest::read64(cells + 8) == 0x77 && guest::read64(cells + 0x10) == item, "io-work-item-queue: a rotina Ex recebe (IoObject, Context, IoWorkItem)");
    call_export("IoFreeWorkItem", &[item]);
    for pointer in [cells, routine, device] {
        guest::free_bytes(pointer);
    }
}


fn rtl_bitmap_ex_exports(assert: Assert) {
    // 200 bits sobre 4 ULONG64: livres 8..15, 32..63, 129..190, 192..199.
    const BASE: [u64; 4] = [0x0000_0000_FFFF_00FF, 0xFFFF_FFFF_FFFF_FFFF, 0x8000_0000_0000_0001, 0];
    let words = guest::alloc_bytes(32);
    let header = guest::alloc_bytes(nt::RtlBitmapEx::SIZE);
    let word = |index: u64| at::<nt::Field<u64>>(words + index * 8);
    let reset = || {
        for (index, value) in BASE.iter().enumerate() {
            word(index as u64).set(*value);
        }
    };
    reset();
    let bitmap = at::<nt::RtlBitmapEx>(header);
    assert(call_export("RtlInitializeBitMapEx", &[header, words, 200]).is_some() && bitmap.size_of_bit_map.get() == 200 && bitmap.buffer.get() == words, "rtl-bitmap-ex: RtlInitializeBitMapEx grava Size e Buffer");
    assert(call_export("RtlTestBitEx", &[header, 0]) == Some(1) && call_export("RtlTestBitEx", &[header, 8]) == Some(0) && call_export("RtlTestBitEx", &[header, 191]) == Some(1), "rtl-bitmap-ex: RtlTestBitEx le bits de palavras distintas");
    call_export("RtlSetBitEx", &[header, 130]);
    assert(word(2).get() == 0x8000_0000_0000_0005, "rtl-bitmap-ex: RtlSetBitEx liga o bit 130");
    call_export("RtlClearBitEx", &[header, 191]);
    assert(word(2).get() == 0x0000_0000_0000_0005 && call_export("RtlTestBitEx", &[header, 191]) == Some(0), "rtl-bitmap-ex: RtlClearBitEx desliga o bit 191");

    // (NumberToFind, HintIndex) -> (indice, palavra alterada, valor esperado).
    let cases: [(u64, u64, u64, u64, u64); 8] = [
        (4, 0, 0x8, 0, 0x0000_0000_FFFF_0FFF),
        (9, 0, 0x20, 0, 0x0000_01FF_FFFF_00FF),
        (40, 0, 0x81, 2, 0x8000_01FF_FFFF_FFFF),
        (3, 150, 0x96, 2, 0x8000_0000_01C0_0001),
        (60, 150, 0x81, 2, 0x9FFF_FFFF_FFFF_FFFF),
        (10, 199, 0x20, 0, 0x0000_03FF_FFFF_00FF),
        (8, 250, 0x8, 0, 0x0000_0000_FFFF_FFFF),
        (1, 0, 0x8, 0, 0x0000_0000_FFFF_01FF),
    ];
    let mut all = true;
    for (count, hint, index, changed, value) in cases {
        reset();
        all &= call_export("RtlFindClearBitsAndSetEx", &[header, count, hint]) == Some(index) && word(changed).get() == value;
    }
    assert(all, "rtl-bitmap-ex: RtlFindClearBitsAndSetEx acha o primeiro run e o liga (com segunda passada)");
    reset();
    let none = [(63u64, 0u64), (64, 0), (130, 0), (300, 0)].iter().all(|&(count, hint)| call_export("RtlFindClearBitsAndSetEx", &[header, count, hint]) == Some(u64::MAX));
    assert(none && (0..4u64).all(|index| word(index).get() == BASE[index as usize]), "rtl-bitmap-ex: sem run livre devolve -1 sem alterar o mapa");
    assert(call_export("RtlFindClearBitsAndSetEx", &[header, 0, 13]) == Some(8) && call_export("RtlFindClearBitsAndSetEx", &[header, 0, 250]) == Some(0), "rtl-bitmap-ex: NumberToFind 0 devolve a dica alinhada a 8");
    guest::free_bytes(header);
    guest::free_bytes(words);
}


fn ex_interlocked_exports(assert: Assert) {
    let cell = guest::alloc_bytes(16);
    let lock = guest::alloc_bytes(8);
    let (large, low, neighbour, spin) = (at::<nt::Field<i64>>(cell), at::<nt::Field<u32>>(cell + 8), at::<nt::Field<u32>>(cell + 12), at::<nt::Field<u64>>(lock));
    spin.set(0);
    large.set(0x7FFF_FFFF_FFFF_FFF0);
    let interrupts_before = crate::hal::cpu::save_and_disable_interrupts();
    crate::hal::cpu::restore_interrupts(interrupts_before);
    assert(call_export("ExInterlockedAddLargeInteger", &[cell, 0x20, lock]) == Some(0x7FFF_FFFF_FFFF_FFF0) && large.get() as u64 == 0x8000_0000_0000_0010 && spin.get() == 0, "ex-interlocked: ExInterlockedAddLargeInteger devolve o anterior e libera o lock");
    assert(call_export("ExInterlockedAddLargeInteger", &[cell, (-0x10i64) as u64, lock]) == Some(0x8000_0000_0000_0010) && large.get() as u64 == 0x8000_0000_0000_0000, "ex-interlocked: ExInterlockedAddLargeInteger soma incremento negativo");
    low.set(0xFFFF_FFFE);
    neighbour.set(0x1234_5678);
    assert(call_export("ExInterlockedAddUlong", &[cell + 8, 5, lock]) == Some(0xFFFF_FFFE) && low.get() == 3 && neighbour.get() == 0x1234_5678 && spin.get() == 0, "ex-interlocked: ExInterlockedAddUlong da a volta em 32 bits sem tocar o vizinho");
    let interrupts_after = crate::hal::cpu::save_and_disable_interrupts();
    crate::hal::cpu::restore_interrupts(interrupts_after);
    assert(interrupts_after & 0x200 == interrupts_before & 0x200, "ex-interlocked: estado de IF preservado");
    guest::free_bytes(lock);
    guest::free_bytes(cell);
}


fn ex_processor_usage_exports(assert: Assert) {
    use crate::ntos::ke::pcr;
    let prcb = at::<nt::Kprcb>(at::<nt::Kpcr>(pcr::get_pcr_address()).current_prcb.get());
    let (saved_idle, saved_kernel, saved_user) = (prcb.idle_thread.get(), prcb.kernel_time.get(), prcb.user_time.get());
    let out = guest::alloc_bytes(16);
    let field = |offset: u64| at::<nt::Field<u32>>(out + offset);
    // KTHREAD ociosa sintética: só KernelTime; Process aponta para o próprio
    // bloco, então nenhuma thread real casa com ela em is_idle_thread.
    let idle = guest::alloc_bytes(nt::Kthread::SIZE);
    let idle_thread = at::<nt::Kthread>(idle);
    idle_thread.process.set(idle);
    idle_thread.kernel_time.set(250);
    prcb.idle_thread.set(idle);
    prcb.kernel_time.set(700);
    prcb.user_time.set(300);
    call_export("ExGetCurrentProcessorCounts", &[out, out + 4, out + 8]);
    assert(field(0).get() == 250 && field(4).get() == 1000 && field(8).get() == prcb.number.get(), "ex-processor-usage: ExGetCurrentProcessorCounts le ocioso, kernel+usuario e o numero da KPRCB");
    call_export("ExGetCurrentProcessorCpuUsage", &[out + 12]);
    // 100 - 250*100/1000 = 75.
    assert(field(12).get() == 75, "ex-processor-usage: ExGetCurrentProcessorCpuUsage = 100 - ocioso*100/total");
    idle_thread.kernel_time.set(999);
    call_export("ExGetCurrentProcessorCpuUsage", &[out + 12]);
    // 100 - 99900/1000 = 100 - 99 = 1 (divisão inteira).
    assert(field(12).get() == 1, "ex-processor-usage: divisao inteira do original");
    prcb.idle_thread.set(saved_idle);
    prcb.kernel_time.set(saved_kernel);
    prcb.user_time.set(saved_user);
    guest::free_bytes(idle);
    guest::free_bytes(out);
}


fn io_driver_registry_exports(assert: Assert) {
    use crate::ntos::cm::key::services as key_services;
    use crate::ntos::cm::registry;
    use crate::ntos::io::io_manager;
    const SERVICE: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\OpenNTDrvKeyTest";
    // DRIVER_OBJECT + DRIVER_EXTENSION sintéticos com ServiceKeyName "OpenNTDrvKeyTest".
    let driver = guest::alloc_bytes(nt::DriverObject::SIZE);
    let extension = guest::alloc_bytes(nt::DriverExtension::SIZE);
    let name = guest::alloc_bytes(64);
    guest::write_bytes(name, &crate::ntos::rtl::guest_strings::wide_bytes_with_nul("OpenNTDrvKeyTest"));
    let service_key_name = &at::<nt::DriverExtension>(extension).service_key_name;
    service_key_name.length.set(32);
    service_key_name.maximum_length.set(34);
    service_key_name.buffer.set(name);
    at::<nt::DriverObject>(driver).driver_extension.set(extension);
    let out = guest::alloc_bytes(8);
    let handle_out = at::<nt::Field<u64>>(out);
    let open = |key_type: u64, access: u64, flags: u64| call_export("IoOpenDriverRegistryKey", &[driver, key_type, access, flags, out]);
    let service = registry::open_or_create(SERVICE, None).unwrap_or(0);
    let parameters = registry::open_or_create(&alloc::format!("{SERVICE}\\Parameters"), None).unwrap_or(0);
    assert(service != 0 && parameters != 0 && open(0, 0x2_0019, 1) == Some(0xFFFF_FFFF_C000_000D) && call_export("IoOpenDriverRegistryKey", &[driver, 0, 0x2_0019, 0, 0]) == Some(0xFFFF_FFFF_C000_000D), "io-driver-registry: Flags != 0 ou saida NULL = STATUS_INVALID_PARAMETER");
    assert(open(0, 0x2_0019, 0) == Some(0xFFFF_FFFF_C000_000D), "io-driver-registry: servico sem Type = STATUS_INVALID_PARAMETER");
    registry::set_value(service, "Type", 4, 0x10u32.to_le_bytes().to_vec());
    assert(open(0, 0x2_0019, 0) == Some(0xFFFF_FFFF_C000_000D), "io-driver-registry: Type de servico Win32 recusado");
    registry::set_value(service, "Type", 1, alloc::vec![0x31, 0, 0, 0]);
    assert(open(0, 0x2_0019, 0) == Some(0xFFFF_FFFF_C000_014C), "io-driver-registry: Type nao REG_DWORD = STATUS_REGISTRY_CORRUPT");
    registry::set_value(service, "Type", 4, 1u32.to_le_bytes().to_vec());
    registry::set_value(parameters, "Probe", 4, 7u32.to_le_bytes().to_vec());
    handle_out.set(0);
    let opened = open(0, 0x2_0019, 0) == Some(0) && handle_out.get() != 0;
    let handle = handle_out.get();
    // O handle devolvido enxerga o valor gravado em ...\Parameters.
    let path_ok = key_services::named_value(key_services::Kind::QueryValue, handle, "Probe", 0, &[]).is_ok_and(|(status, value)| status == 0 && value.is_some_and(|value| value.data == 7u32.to_le_bytes()));
    assert(opened && path_ok, "io-driver-registry: DriverRegKeyParameters abre Services\\<nome>\\Parameters");
    call_export("ZwClose", &[handle]);
    assert(open(0, 0x2_0006, 0) == Some(0xFFFF_FFFF_C000_0022), "io-driver-registry: escrita em Parameters = STATUS_ACCESS_DENIED");
    assert(open(0, 0x0200_0000, 0) == Some(0), "io-driver-registry: MAXIMUM_ALLOWED vira KEY_READ");
    call_export("ZwClose", &[handle_out.get()]);
    let state_path = alloc::format!("{SERVICE}\\State");
    assert(registry::node_by_path(&state_path).is_none() && open(1, 0xF_003F, 0) == Some(0) && registry::node_by_path(&state_path).is_some(), "io-driver-registry: DriverRegKeyPersistentState cria e abre State");
    call_export("ZwClose", &[handle_out.get()]);
    assert(open(2, 0x2_0019, 0) == Some(0xFFFF_FFFF_C000_000D), "io-driver-registry: tipo de chave desconhecido recusado");
    let state = registry::open(&state_path).unwrap_or(0);
    if state != 0 {
        registry::delete_key(state);
        registry::close_handle(state);
    }
    registry::delete_key(parameters);
    registry::close_handle(parameters);
    registry::delete_key(service);
    registry::close_handle(service);
    for pointer in [out, name, extension, driver] {
        guest::free_bytes(pointer);
    }

    // IoGetDeviceNumaNode.
    let node = guest::alloc_bytes(8);
    let node_number = at::<nt::Field<u16>>(node);
    node_number.set(0x7777);
    assert(call_export("IoGetDeviceNumaNode", &[0, node]) == Some(0xFFFF_FFFF_C000_000D) && call_export("IoGetDeviceNumaNode", &[node, node]) == Some(0xFFFF_FFFF_C000_000D) && node_number.get() == 0x7777, "io-driver-registry: IoGetDeviceNumaNode sem devnode = STATUS_INVALID_PARAMETER");
    if let Some(pdo) = io_manager::devices().into_iter().find(|(_, entry)| entry.pdo && entry.native_device != 0).map(|(_, entry)| entry.native_device) {
        assert(call_export("IoGetDeviceNumaNode", &[pdo, node]) == Some(0) && node_number.get() == 0, "io-driver-registry: PDO do PnP fica no no 0 (maquina de um no)");
    }
    guest::free_bytes(node);
}


fn ps_property_sets_exports(assert: Assert) {
    use crate::ntos::ps::process;
    let thread = process::get_current_thread();
    let refs = || process::thread_reference_count(thread).unwrap_or(0);
    let baseline = refs();
    let key = 0x0000_1111u64;
    assert(call_export("PsSetThreadProperty", &[thread, key, thread]) == Some(0) && refs() == baseline + 1, "ps-property-sets: PsSetThreadProperty insere e referencia o valor");
    assert(call_export("PsSetThreadProperty", &[thread, key, thread]) == Some(0xFFFF_FFFF_C000_0035) && refs() == baseline + 1, "ps-property-sets: chave repetida = STATUS_OBJECT_NAME_COLLISION");
    assert(call_export("PsGetThreadProperty", &[thread, key, 0]) == Some(thread) && refs() == baseline + 2, "ps-property-sets: PsGetThreadProperty devolve o objeto referenciado");
    call_export("ObfDereferenceObject", &[thread]);
    assert(call_export("PsGetThreadProperty", &[thread, key, 2]) == Some(0) && call_export("PsGetThreadProperty", &[thread, 0x2222, 1]) == Some(0) && call_export("PsGetThreadProperty", &[thread, 0x2222, 0]) == Some(0), "ps-property-sets: flags invalidas e chave ausente devolvem NULL");
    assert(call_export("PsSetThreadProperty", &[thread, key, 0]) == Some(0) && refs() == baseline, "ps-property-sets: Value NULL remove e solta a referencia");
    assert(call_export("PsSetThreadProperty", &[thread, key, 0]) == Some(0) && call_export("PsGetThreadProperty", &[thread, key, 0]) == Some(0), "ps-property-sets: remover chave ausente tambem e sucesso");
    let not_an_object = guest::alloc_bytes(0x40);
    assert(call_export("PsSetThreadProperty", &[not_an_object, key, thread]) == Some(0xFFFF_FFFF_C000_000D) && call_export("PsGetThreadProperty", &[not_an_object, key, 0]) == Some(0), "ps-property-sets: corpo que nao e Thread recusado em PASSIVE");
    assert(call_export("PsSetJobProperty", &[not_an_object, key, thread]) == Some(0xFFFF_FFFF_C000_000D) && call_export("PsGetJobProperty", &[not_an_object, key]) == Some(0) && refs() == baseline, "ps-property-sets: corpo que nao e Job recusado em PASSIVE");
    guest::free_bytes(not_an_object);
}


fn pcw_counters_exports(assert: Assert) {
    use crate::ntos::cm::registry;
    use crate::ntos::ex::pcw;
    const KEY: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\pcw";
    let out = guest::alloc_bytes(8);
    let registration = at::<nt::Field<u64>>(out);
    let preexisting = registry::node_by_path(KEY).is_some();
    if !preexisting {
        pcw::reset_enable_state_for_test();
        registration.set(0xDEAD);
        assert(call_export("PcwRegister", &[out, 0]) == Some(0xFFFF_FFFF_C000_0002) && registration.get() == 0, "pcw-counters: sem chave pcw = STATUS_NOT_IMPLEMENTED e handle NULL");
    }
    let handle = registry::open_or_create(KEY, None).unwrap_or(0);
    let saved = registry::get_value(handle, "Start");
    registry::set_value(handle, "Start", 4, 4u32.to_le_bytes().to_vec());
    pcw::reset_enable_state_for_test();
    registration.set(0xDEAD);
    assert(handle != 0 && call_export("PcwRegister", &[out, 0]) == Some(0) && registration.get() == 0, "pcw-counters: Start=4 (pcw desligado) = sucesso com handle NULL");
    assert(call_export("PcwAddInstance", &[0, 0, 7, 1, 0]) == Some(0) && call_export("PcwUnregister", &[0]) == Some(0), "pcw-counters: AddInstance/Unregister sem extensao");
    registry::set_value(handle, "Start", 4, 0u32.to_le_bytes().to_vec());
    // O estado fica em cache como no NT: sem reset, Start=0 ainda não conta.
    assert(call_export("PcwAddInstance", &[0, 0, 7, 1, 0]) == Some(0), "pcw-counters: ExpPcwEnableState calculado uma vez");
    pcw::reset_enable_state_for_test();
    assert(call_export("PcwAddInstance", &[0, 0, 7, 1, 0]) == Some(0xFFFF_FFFF_C000_0002), "pcw-counters: Start=0 (boot sem pcw.sys) = STATUS_NOT_IMPLEMENTED");
    registry::delete_value(handle, "Start");
    pcw::reset_enable_state_for_test();
    assert(call_export("PcwRegister", &[out, 0]) == Some(0), "pcw-counters: valor Start ausente usa o default 0xFFFFFFFF");
    registry::set_value(handle, "Start", 1, alloc::vec![0x41, 0, 0, 0]);
    pcw::reset_enable_state_for_test();
    assert(call_export("PcwRegister", &[out, 0]) == Some(0xFFFF_FFFF_C000_0024), "pcw-counters: Start com tipo errado = STATUS_OBJECT_TYPE_MISMATCH");
    match saved {
        Some(value) => {
            registry::set_value(handle, "Start", value.value_type, value.data);
        }
        None => {
            registry::delete_value(handle, "Start");
        }
    }
    if !preexisting {
        registry::delete_key(handle);
    }
    registry::close_handle(handle);
    pcw::reset_enable_state_for_test();
    guest::free_bytes(out);
}


fn rtl_self_relative_sd_exports(assert: Assert) {
    let relative = guest::alloc_bytes(0x60);
    let bytes: [u8; 0x54] = [
        // Revision 1, Sbz1 0, Control 0x8014 (SELF_RELATIVE|SACL_PRESENT|DACL_PRESENT).
        1, 0, 0x14, 0x80, 0x14, 0, 0, 0, 0x20, 0, 0, 0, 0x30, 0, 0, 0, 0x38, 0, 0, 0,
        // +0x14 dono S-1-5-18 (12 bytes).
        1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
        // +0x20 grupo S-1-5-32-544 (16 bytes).
        1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0,
        // +0x30 SACL vazia: AclRevision 2, AclSize 8, AceCount 0.
        2, 0, 8, 0, 0, 0, 0, 0,
        // +0x38 DACL de 0x1C: um ACCESS_ALLOWED_ACE (0x14) com S-1-1-0.
        2, 0, 0x1C, 0, 1, 0, 0, 0,
        0, 0, 0x14, 0, 0xFF, 0x01, 0x1F, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
    ];
    guest::write_bytes(relative, &bytes);
    let sizes = guest::alloc_bytes(20);
    let (abs_size, dacl_size, sacl_size, owner_size, group_size) = (sizes, sizes + 4, sizes + 8, sizes + 12, sizes + 16);
    let size = |address: u64| at::<nt::Field<u32>>(address);
    for address in [abs_size, dacl_size, sacl_size, owner_size, group_size] {
        size(address).set(0);
    }
    let absolute = guest::alloc_bytes(nt::SecurityDescriptor::SIZE);
    let buffers = guest::alloc_bytes(0x80);
    let (dacl, sacl, owner, group) = (buffers, buffers + 0x20, buffers + 0x40, buffers + 0x60);
    let call = |absolute: u64| call_export("RtlSelfRelativeToAbsoluteSD", &[relative, absolute, abs_size, dacl, dacl_size, sacl, sacl_size, owner, owner_size, group, group_size]);
    assert(call(absolute) == Some(0xFFFF_FFFF_C000_0023) && size(abs_size).get() == 0x28 && size(owner_size).get() == 12 && size(group_size).get() == 16 && size(sacl_size).get() == 8 && size(dacl_size).get() == 0x1C, "rtl-self-relative-sd: buffers pequenos devolvem os tamanhos e STATUS_BUFFER_TOO_SMALL");
    assert(call(absolute) == Some(0), "rtl-self-relative-sd: conversao com os tamanhos informados");
    let sd = at::<nt::SecurityDescriptor>(absolute);
    // Bytes 4..7 (padding do absoluto) recebem o offset do dono, como o memcpy de 0x14 bytes.
    let header_ok = sd.revision.get() == 1 && sd.control.get() == 0x0014 && guest::read_bytes(absolute + 4, 4) == 0x14u32.to_le_bytes();
    let pointers_ok = sd.owner.get() == owner && sd.group.get() == group && sd.sacl.get() == sacl && sd.dacl.get() == dacl;
    let copies_ok = guest::read_bytes(owner, 12) == bytes[0x14..0x20] && guest::read_bytes(group, 16) == bytes[0x20..0x30] && guest::read_bytes(sacl, 8) == bytes[0x30..0x38] && guest::read_bytes(dacl, 0x1C) == bytes[0x38..0x54];
    assert(header_ok && pointers_ok && copies_ok, "rtl-self-relative-sd: cabecalho sem SELF_RELATIVE, ponteiros e componentes copiados");
    assert(call_export("RtlSelfRelativeToAbsoluteSD", &[absolute, absolute, abs_size, dacl, dacl_size, sacl, sacl_size, owner, owner_size, group, group_size]) == Some(0xFFFF_FFFF_C000_00E7), "rtl-self-relative-sd: SD absoluto na entrada = STATUS_BAD_DESCRIPTOR_FORMAT");
    for pointer in [buffers, absolute, sizes, relative] {
        guest::free_bytes(pointer);
    }
}


fn kd_debug_filter_exports(assert: Assert) {
    use crate::ntos::kd::debug_filter;
    // DPFLTR_IHVNETWORK_ID = 79 (0x4F): o componente do ndis.
    let before = debug_filter::component_mask(79);
    assert(call_export("DbgSetDebugFilterState", &[79, 3, 1]) == Some(0) && debug_filter::component_mask(79) == before | 0x8, "kd-debug-filter: nivel 3 liga o bit 3 do componente");
    assert(call_export("DbgSetDebugFilterState", &[79, 0x30, 1]) == Some(0) && debug_filter::component_mask(79) == before | 0x38, "kd-debug-filter: nivel acima de 31 e a propria mascara");
    assert(call_export("DbgSetDebugFilterState", &[79, 0x38, 0]) == Some(0) && debug_filter::component_mask(79) == before & !0x38, "kd-debug-filter: State FALSE desliga os bits");
    let default_before = debug_filter::component_mask(101);
    call_export("DbgSetDebugFilterState", &[0x9C, 31, 1]);
    assert(debug_filter::component_mask(101) == default_before | 0x8000_0000 && debug_filter::component_mask(0x9C) == debug_filter::component_mask(101), "kd-debug-filter: componente fora da tabela cai no DEFAULT (101)");
    call_export("DbgSetDebugFilterState", &[0x9C, 31, 0]);
    let win2000 = debug_filter::component_mask(0xFFFF_FFFF);
    call_export("DbgSetDebugFilterState", &[0xFFFF_FFFF, 2, 1]);
    assert(debug_filter::component_mask(0xFFFF_FFFF) == win2000 | 4, "kd-debug-filter: ComponentId -1 altera Kd_WIN2000_Mask");
    call_export("DbgSetDebugFilterState", &[0xFFFF_FFFF, 2, (win2000 >> 2) as u64 & 1]);
}


fn etw_wmi_clock_exports(assert: Assert) {
    use crate::ntos::ke::clock;
    let before = clock::system_time_100ns();
    let system = call_export("WmiGetClock", &[1, 0]).unwrap_or(0);
    let out_of_range = call_export("WmiGetClock", &[9, 0]).unwrap_or(0);
    let negative = call_export("WmiGetClock", &[0xFFFF_FFFF, 0]).unwrap_or(0);
    let after = clock::system_time_100ns();
    assert(system >= before && system <= after && out_of_range >= system && out_of_range <= after && negative >= out_of_range && negative <= after, "etw-wmi-clock: WMICT_SYSTEMTIME, tipo negativo e > 5 = hora do sistema");
    assert(call_export("WmiGetClock", &[3, 0]) == Some(0) && call_export("WmiGetClock", &[4, 0]) == Some(0), "etw-wmi-clock: WMICT_PROCESS/THREAD = 0");
    let first = call_export("WmiGetClock", &[2, 0]).unwrap_or(0);
    let cycle = call_export("WmiGetClock", &[5, 0]).unwrap_or(0);
    let default = call_export("WmiGetClock", &[0, 0]).unwrap_or(0);
    assert(first != 0 && cycle >= first && default >= cycle, "etw-wmi-clock: contador de desempenho, ciclos e o padrao (contador) avancam");
}


fn kse_shim_engine_exports(assert: Assert) {
    let flags = guest::alloc_bytes(8);
    let flags_cell = at::<nt::Field<u64>>(flags);
    flags_cell.set(0x1234);
    let device = guest::alloc_bytes(16);
    guest::write_bytes(device, &crate::ntos::rtl::guest_strings::wide_bytes_with_nul("PCI"));
    assert(call_export("KseQueryDeviceFlags", &[device, device, flags]) == Some(0xFFFF_FFFF_C000_0225) && flags_cell.get() == 0x1234, "kse-shim-engine: sem motor = STATUS_NOT_FOUND e Flags intocado");
    assert(call_export("KseQueryDeviceFlags", &[0, 0, 0]) == Some(0xFFFF_FFFF_C000_0225), "kse-shim-engine: o estado do motor e testado antes dos argumentos");
    guest::free_bytes(device);
    guest::free_bytes(flags);
}


fn ex_access_violation_exports(assert: Assert) {
    use crate::ntos::rtl::{native_context, unwind};
    use crate::ntos::mm::pe_loader::{self as loader, LoadOptions};
    let mut bytes = ntoskrnl_importer(b"ExRaiseAccessViolation\0");
    for byte in &mut bytes[0x4442..0x4480] {
        *byte = 0;
    }
    bytes[0x4442..0x444E].copy_from_slice(b"RtlUnwindEx\0");
    let rel = |from_next: usize, to: usize| ((to as i64 - from_next as i64) as i32).to_le_bytes();
    // F (0x1300): sub rsp,28h; mov ecx,0; call [ExRaiseAccessViolation]; add rsp,28h; xor eax,eax; ret.
    // Bloco de tratamento (0x1316): add rsp,28h; ret (RAX = valor do RtlUnwindEx).
    let mut f = alloc::vec![0x48, 0x83, 0xEC, 0x28, 0xB9, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x15];
    f.extend_from_slice(&rel(0x130F, 0x4200));
    f.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28, 0x31, 0xC0, 0xC3, 0x48, 0x83, 0xC4, 0x28, 0xC3]);
    bytes[0x1300..0x1300 + f.len()].copy_from_slice(&f);
    // Handler (0x1330): RtlUnwindEx(frame, 0x1316, record, record->ExceptionCode, NULL, NULL).
    let mut handler = alloc::vec![0x48, 0x83, 0xEC, 0x38, 0x48, 0x89, 0xC8, 0x48, 0x89, 0xD1, 0x48, 0x8D, 0x15];
    handler.extend_from_slice(&rel(0x1341, 0x1316));
    handler.extend_from_slice(&[0x49, 0x89, 0xC0, 0x44, 0x8B, 0x08, 0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0, 0x48, 0xC7, 0x44, 0x24, 0x28, 0, 0, 0, 0, 0xFF, 0x15]);
    handler.extend_from_slice(&rel(0x135F, 0x4210));
    handler.extend_from_slice(&[0x48, 0x83, 0xC4, 0x38, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]);
    bytes[0x1330..0x1330 + handler.len()].copy_from_slice(&handler);
    bytes[0x1400..0x1404].copy_from_slice(&[0x09, 0x04, 0x01, 0x00]);
    bytes[0x1404..0x1406].copy_from_slice(&(4u16 | (2 << 8) | (4 << 12)).to_le_bytes());
    bytes[0x1408..0x140C].copy_from_slice(&0x1330u32.to_le_bytes());
    bytes[0x1500..0x1504].copy_from_slice(&0x1300u32.to_le_bytes());
    bytes[0x1504..0x1508].copy_from_slice(&0x1320u32.to_le_bytes());
    bytes[0x1508..0x150C].copy_from_slice(&0x1400u32.to_le_bytes());
    let Ok(mut image) = loader::load(bytes, &LoadOptions { image_name: Some(String::from("opennt-av.sys")), ..Default::default() }) else {
        assert(false, "ex-access-violation: imagem de teste carregada");
        return;
    };
    let base = image.image_base;
    let added = unwind::add_function_table(base + 0x1500, 1, base);
    let result = native_context::call(base + 0x1300, &[], 0);
    assert(added.is_ok_and(|added| added == 1) && result.as_ref().is_ok_and(|value| *value as u32 == 0xC000_0005), "ex-access-violation: ExRaiseAccessViolation levanta STATUS_ACCESS_VIOLATION ate o handler");
    let _ = unwind::delete_function_table(base + 0x1500);
    let _ = image.release();
}


fn rtl_network_address_exports(assert: Assert) {
    use crate::ntos::rtl::guest_strings;
    let text = guest::alloc_bytes(128);
    let terminator = guest::alloc_bytes(8);
    let address = guest::alloc_bytes(16);
    let (end_cell, v4_cell) = (at::<nt::Field<u64>>(terminator), at::<nt::Field<u32>>(address));
    let put = |value: &str| guest::write_bytes(text, &guest_strings::wide_bytes_with_nul(value));
    let read_text = |pointer: u64| guest_strings::read_wide_string(pointer);
    const INVALID: u64 = 0xFFFF_FFFF_C000_000D;

    // IPv4: (texto, strict, status, índice do terminador, endereço em ordem de rede).
    let v4: [(&str, u64, u64, u64, [u8; 4]); 12] = [
        ("192.168.0.1", 1, 0, 11, [192, 168, 0, 1]),
        ("10.1", 0, 0, 4, [10, 0, 0, 1]),
        ("10.1", 1, INVALID, 4, [0; 4]),
        ("0x7f.1", 0, 0, 6, [0x7F, 0, 0, 1]),
        ("0x7f.1", 1, INVALID, 2, [0; 4]),
        ("010.0.0.1", 0, 0, 9, [8, 0, 0, 1]),
        ("1.2.3.4.5", 0, INVALID, 7, [0; 4]),
        ("256.1.1.1", 1, INVALID, 9, [0; 4]),
        ("1.2.3.4:80", 1, 0, 7, [1, 2, 3, 4]),
        ("4294967296", 0, INVALID, 9, [0; 4]),
        ("1.2.65535", 0, 0, 9, [1, 2, 0xFF, 0xFF]),
        ("09", 0, INVALID, 1, [0; 4]),
    ];
    let mut all = true;
    for (value, strict, status, end, bytes) in v4 {
        put(value);
        v4_cell.set(0xAAAA_AAAA);
        let result = call_export("RtlIpv4StringToAddressW", &[text, strict, terminator, address]);
        let expected_address = if status == 0 { u32::from_le_bytes(bytes) } else { 0xAAAA_AAAA };
        all &= result == Some(status) && end_cell.get() == text + end * 2 && v4_cell.get() == expected_address;
    }
    assert(all, "rtl-network-address: RtlIpv4StringToAddressW (bases, partes, Strict, terminador)");

    // IPv6: (texto, status, terminador (None = não gravado), endereço).
    let v6: [(&str, u64, Option<u64>, &str); 14] = [
        ("::1", 0, Some(3), "00000000000000000000000000000001"),
        ("::", 0, Some(2), "00000000000000000000000000000000"),
        ("1:2::3", 0, Some(6), "00010002000000000000000000000003"),
        ("2001:db8::ff00:42:8329", 0, Some(22), "20010db8000000000000ff0000428329"),
        ("1:2:3:4:5:6:7:8:9", 0, Some(15), "00010002000300040005000600070008"),
        ("::ffff:1.2.3.4", 0, Some(14), "00000000000000000000ffff01020304"),
        ("1:2:3:4:5:6:1.2.3.4", 0, Some(19), "00010002000300040005000601020304"),
        ("1::2::3", 0, Some(4), "00010000000000000000000000000002"),
        ("::1.2.3.4a", 0, Some(9), "00000000000000000000000001020304"),
        ("1:2:3:4:5:6:7::", 0, Some(15), "00010002000300040005000600070000"),
        ("12345::", INVALID, None, ""),
        (":1::", INVALID, Some(0), ""),
        ("::1.2.3", INVALID, Some(7), ""),
        ("::256.1.1.1", INVALID, None, ""),
    ];
    let hex = |value: &str| (0..16).map(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap_or(0)).collect::<alloc::vec::Vec<u8>>();
    let mut all = true;
    for (value, status, end, bytes) in v6 {
        put(value);
        end_cell.set(0x5A5A);
        let result = call_export("RtlIpv6StringToAddressW", &[text, terminator, address]);
        let end_ok = match end {
            Some(end) => end_cell.get() == text + end * 2,
            None => end_cell.get() == 0x5A5A,
        };
        all &= result == Some(status) && end_ok && (status != 0 || guest::read_bytes(address, 16) == hex(bytes));
    }
    assert(all, "rtl-network-address: RtlIpv6StringToAddressW (compressao, sufixo IPv4, terminador e erros)");

    // Texto IPv6: (endereço, texto, texto Ex com escopo 3 e porta 80).
    let s6: [(&str, &str); 9] = [
        ("00000000000000000000000000000001", "::1"),
        ("00000000000000000000000000000000", "::"),
        ("20010db8000000000000ff0000428329", "2001:db8::ff00:42:8329"),
        ("00000000000000000000ffff01020304", "::ffff:1.2.3.4"),
        ("00000000000000000000000001020304", "::1.2.3.4"),
        ("0000000000000000ffff000001020304", "::ffff:0:1.2.3.4"),
        ("fe8000000000000002005efe0a000001", "fe80::200:5efe:10.0.0.1"),
        ("00010000000100000000000000000001", "1:0:1::1"),
        ("00000001000000000000000000000000", "0:1::"),
    ];
    let output = guest::alloc_bytes(128);
    let length = guest::alloc_bytes(4);
    let length_cell = at::<nt::Field<u32>>(length);
    let mut all = true;
    for (bytes, expected) in s6 {
        guest::write_bytes(address, &hex(bytes));
        let end = call_export("RtlIpv6AddressToStringW", &[address, output]).unwrap_or(0);
        all &= read_text(output) == expected && end == output + expected.len() as u64 * 2;
    }
    assert(all, "rtl-network-address: RtlIpv6AddressToStringW (zeros, IPv4 embutido, ISATAP)");
    guest::write_bytes(address, &hex("20010db8000000010000000000000001"));
    length_cell.set(4);
    let small = call_export("RtlIpv6AddressToStringExW", &[address, 3, 0x5000, output, length]);
    let needed = "[2001:db8:0:1::1%3]:80".len() as u32 + 1;
    assert(small == Some(INVALID) && length_cell.get() == needed, "rtl-network-address: RtlIpv6AddressToStringExW informa o tamanho");
    assert(call_export("RtlIpv6AddressToStringExW", &[address, 3, 0x5000, output, length]) == Some(0) && read_text(output) == "[2001:db8:0:1::1%3]:80" && length_cell.get() == needed, "rtl-network-address: RtlIpv6AddressToStringExW com escopo e porta");

    // Texto IPv4.
    guest::write_bytes(address, &[192, 168, 0, 1]);
    let end = call_export("RtlIpv4AddressToStringW", &[address, output]).unwrap_or(0);
    assert(read_text(output) == "192.168.0.1" && end == output + 22, "rtl-network-address: RtlIpv4AddressToStringW devolve o fim");
    guest::write_bytes(address, &[10, 0, 0, 255]);
    length_cell.set(0);
    let probe = call_export("RtlIpv4AddressToStringExW", &[address, 0x901F, 0, length]);
    assert(probe == Some(INVALID) && length_cell.get() == 16, "rtl-network-address: RtlIpv4AddressToStringExW sem buffer informa o tamanho");
    assert(call_export("RtlIpv4AddressToStringExW", &[address, 0x901F, output, length]) == Some(0) && read_text(output) == "10.0.0.255:8080", "rtl-network-address: RtlIpv4AddressToStringExW com porta");
    length_cell.set(1);
    assert(call_export("RtlIpv4AddressToStringExW", &[address, 0, 0, length]) == Some(INVALID), "rtl-network-address: Buffer NULL com Length != 0 recusado");
    for pointer in [length, output, address, terminator, text] {
        guest::free_bytes(pointer);
    }
}


fn rtl_crt_wide_exports(assert: Assert) {
    let text = guest::alloc_bytes(64);
    let put = |units: &[u16]| {
        let mut bytes: alloc::vec::Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        bytes.extend_from_slice(&[0, 0]);
        guest::write_bytes(text, &bytes);
    };
    let wtoi = |units: &[u16]| {
        put(units);
        call_export("_wtoi", &[text]).map(|value| value as i64)
    };
    let ascii = |value: &str| value.encode_utf16().collect::<alloc::vec::Vec<u16>>();
    assert(wtoi(&ascii("  \t-1234xyz")) == Some(-1234) && wtoi(&ascii("+77")) == Some(77) && wtoi(&ascii("abc")) == Some(0), "rtl-crt-wide: _wtoi com espacos, sinal e lixo final");
    // 0xA0 é _SPACE; 0x0663/0xFF15 são dígitos (árabe-índico 3, largo 5).
    assert(wtoi(&[0xA0, 0x31, 0x0663, 0xFF15]) == Some(135) && wtoi(&[0x2003, 0x31]) == Some(0), "rtl-crt-wide: _wtoi usa pwctype e wchartodigit");
    // 4294967297 dá a volta para 1 (sem clamp em _wtol); -2147483648 inteiro.
    assert(wtoi(&ascii("4294967297")) == Some(1) && wtoi(&ascii("-2147483648")) == Some(-2147483648), "rtl-crt-wide: _wtoi acumula com volta de 32 bits");
    assert(call_export("_wtoi", &[0]) == Some(0), "rtl-crt-wide: _wtoi(NULL) = 0");
    let lower = |c: u64| call_export("towlower", &[c]);
    assert(lower(0x41) == Some(0x61) && lower(0x5A) == Some(0x7A) && lower(0xC9) == Some(0xE9) && lower(0xD7) == Some(0xD7) && lower(0xDE) == Some(0xFE), "rtl-crt-wide: towlower nas maiusculas Latin-1");
    assert(lower(0x61) == Some(0x61) && lower(0x100) == Some(0x100) && lower(0x391) == Some(0x391), "rtl-crt-wide: towlower nao toca minusculas nem c >= 0x100");
    assert(call_export("RtlPrefetchMemoryNonTemporal", &[text, 0x1000]) == Some(0), "rtl-crt-wide: RtlPrefetchMemoryNonTemporal e so uma dica");
    guest::free_bytes(text);
}


fn io_top_level_irp_exports(assert: Assert) {
    use crate::ntos::ps::process;
    let thread = process::get_current_thread();
    let ethread = at::<nt::Ethread>(thread);
    let saved = ethread.top_level_irp.get();
    assert(call_export("IoGetTopLevelIrp", &[]) == Some(saved), "io-top-level-irp: IoGetTopLevelIrp le ETHREAD.TopLevelIrp");
    // FSRTL_FSP_TOP_LEVEL_IRP (1) e um ponteiro qualquer, como os FS gravam.
    call_export("IoSetTopLevelIrp", &[1]);
    let marker = ethread.top_level_irp.get() == 1 && call_export("IoGetTopLevelIrp", &[]) == Some(1);
    call_export("IoSetTopLevelIrp", &[0xFFFF_8000_1234_5670]);
    let pointer = call_export("IoGetTopLevelIrp", &[]) == Some(0xFFFF_8000_1234_5670);
    call_export("IoSetTopLevelIrp", &[saved]);
    assert(marker && pointer && ethread.top_level_irp.get() == saved, "io-top-level-irp: IoSetTopLevelIrp grava e restaura");
    assert(call_export("IoThreadToProcess", &[thread]) == Some(ethread.tcb.process.get()) && call_export("IoThreadToProcess", &[thread]) == call_export("IoGetCurrentProcess", &[]), "io-top-level-irp: IoThreadToProcess = KTHREAD.Process");
}


fn se_access_from_state_exports(assert: Assert) {
    let system_sid: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let admins_sid: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0];
    let sids = guest::alloc_bytes(32);
    guest::write_bytes(sids, &system_sid);
    guest::write_bytes(sids + 16, &admins_sid);
    let sid_attr = guest::alloc_bytes(2 * nt::SidAndAttributes::SIZE);
    let groups = [at::<nt::SidAndAttributes>(sid_attr), at::<nt::SidAndAttributes>(sid_attr + nt::SidAndAttributes::SIZE)];
    groups[0].sid.set(sids);
    groups[0].attributes.set(0x04);
    groups[1].sid.set(sids + 16);
    groups[1].attributes.set(0x60);
    let hashes = guest::alloc_bytes(3 * nt::SidAndAttributesHash::SIZE);
    let (sid_hash, restricted_hash, capabilities_hash) = (hashes, hashes + nt::SidAndAttributesHash::SIZE, hashes + 2 * nt::SidAndAttributesHash::SIZE);
    at::<nt::SidAndAttributesHash>(sid_hash).sid_count.set(2);
    at::<nt::SidAndAttributesHash>(sid_hash).sid_attr.set(sid_attr);
    // TOKEN_PRIVILEGES com 2 entradas (o cabeçalho + 2 LUID_AND_ATTRIBUTES).
    let privileges = guest::alloc_bytes(4 + 2 * nt::LuidAndAttributes::SIZE);
    at::<nt::TokenPrivileges>(privileges).privilege_count.set(2);
    let privilege = |index: u64| at::<nt::LuidAndAttributes>(privileges + 4 + index * nt::LuidAndAttributes::SIZE);
    privilege(0).luid.low_part.set(20); // SeDebugPrivilege
    privilege(0).attributes.set(3); // ENABLED | ENABLED_BY_DEFAULT
    privilege(1).luid.low_part.set(40); // fora de 2..36: ignorado
    privilege(1).attributes.set(2);
    let information = guest::alloc_bytes(nt::TokenAccessInformation::SIZE);
    let info = at::<nt::TokenAccessInformation>(information);
    info.sid_hash.set(sid_hash);
    info.restricted_sid_hash.set(restricted_hash);
    info.privileges.set(privileges);
    info.authentication_id.low_part.set(0x3E7); // SYSTEM_LUID
    info.token_type.set(nt::TokenType::TOKEN_PRIMARY);
    info.mandatory_policy.policy.set(1);
    info.flags.set(0x2000);
    info.capabilities_hash.set(capabilities_hash);
    let token = guest::alloc_bytes(nt::Token::SIZE);
    let required = guest::alloc_bytes(4);
    let required_cell = at::<nt::Field<u32>>(required);
    assert(call_export("SeTokenFromAccessInformation", &[information, token, 0x100, required]) == Some(0xFFFF_FFFF_C000_0023) && required_cell.get() == 0x498, "se-access-from-state: buffer menor que TOKEN = STATUS_BUFFER_TOO_SMALL com 0x498");
    required_cell.set(0);
    assert(call_export("SeTokenFromAccessInformation", &[information, token, 0x498, required]) == Some(0) && required_cell.get() == 0, "se-access-from-state: SeTokenFromAccessInformation monta o TOKEN");
    let built = at::<nt::Token>(token);
    let fields_ok = built.authentication_id.low_part.get() == 0x3E7 && built.token_type.get() == nt::TokenType::TOKEN_PRIMARY && built.user_and_group_count.get() == 2 && built.user_and_groups.get() == sid_attr && built.token_flags.get() == 0x2000 && built.mandatory_policy.get() == 1 && built.integrity_level_index.get() == 1;
    let privileges_ok = built.privileges.present.get() == 1 << 20 && built.privileges.enabled.get() == 1 << 20 && built.privileges.enabled_by_default.get() == 1 << 20;
    // SidHash: S-1-5-18 (byte 0x12) -> Hash[2] e Hash[16+1] bit 0;
    // S-1-5-32-544 (byte 0x20) -> Hash[0] e Hash[16+2] bit 1.
    let hash = &built.sid_hash;
    let hash_ok = hash.sid_count.get() == 2 && hash.sid_attr.get() == sid_attr && hash.hash[2].get() == 1 && hash.hash[17].get() == 1 && hash.hash[0].get() == 2 && hash.hash[18].get() == 2;
    assert(fields_ok && privileges_ok && hash_ok, "se-access-from-state: campos, privilegios e SidHash do TOKEN montado");

    // SD self-relative: dono SYSTEM, DACL com ACCESS_ALLOWED 0x1FF para SYSTEM.
    let descriptor = guest::alloc_bytes(64);
    let mut bytes = [0u8; 60];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
    bytes[4..8].copy_from_slice(&20u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&32u32.to_le_bytes());
    bytes[20..32].copy_from_slice(&system_sid);
    bytes[32] = 2;
    bytes[34..36].copy_from_slice(&28u16.to_le_bytes());
    bytes[36..38].copy_from_slice(&1u16.to_le_bytes());
    bytes[42..44].copy_from_slice(&20u16.to_le_bytes());
    bytes[44..48].copy_from_slice(&0x1FFu32.to_le_bytes());
    bytes[48..60].copy_from_slice(&system_sid);
    guest::write_bytes(descriptor, &bytes);
    let mapping = guest::alloc_bytes(nt::GenericMapping::SIZE);
    let generic = at::<nt::GenericMapping>(mapping);
    generic.generic_read.set(0x0012_0089);
    generic.generic_write.set(0x0012_0116);
    generic.generic_execute.set(0x0012_00A0);
    generic.generic_all.set(0x001F_01FF);
    let out = guest::alloc_bytes(16);
    let (granted, status, used_privileges) = (out, out + 4, out + 8);
    let (granted_cell, status_cell, privileges_cell) = (at::<nt::Field<u32>>(granted), at::<nt::Field<u32>>(status), at::<nt::Field<u64>>(used_privileges));
    let check = |primary: u64, client: u64, desired: u64, mode: u64| call_export("SeAccessCheckFromStateEx", &[descriptor, primary, client, desired, 0, used_privileges, mapping, mode, granted, status]);
    assert(check(token, 0, 1, 1) == Some(1) && status_cell.get() == 0 && granted_cell.get() == 1 && privileges_cell.get() == 0, "se-access-from-state: concede o direito da DACL ao TOKEN montado");
    assert(check(token, 0, 0x10000, 1) == Some(0) && status_cell.get() == 0xC000_0022, "se-access-from-state: nega DELETE ausente da DACL");
    // Cliente em SecurityIdentification = STATUS_BAD_IMPERSONATION_LEVEL.
    let client = guest::alloc_bytes(nt::Token::SIZE);
    guest::write_bytes(client, &guest::read_bytes(token, nt::Token::SIZE as usize));
    let client_token = at::<nt::Token>(client);
    client_token.impersonation_level.set(nt::SecurityImpersonationLevel::SECURITY_IDENTIFICATION);
    assert(check(token, client, 1, 1) == Some(0) && status_cell.get() == 0xC000_00A5, "se-access-from-state: cliente em Identification recusado");
    client_token.impersonation_level.set(nt::SecurityImpersonationLevel::SECURITY_IMPERSONATION);
    assert(check(0, client, 1, 1) == Some(1) && check(token, 0, 0x10000, 0) == Some(1) && granted_cell.get() == 0x10000, "se-access-from-state: cliente personificando decide; KernelMode concede");
    for pointer in [client, out, mapping, descriptor, required, token, information, privileges, hashes, sid_attr, sids] {
        guest::free_bytes(pointer);
    }
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
    rtl_security_descriptors(assert);
    driver_helper_exports(assert);
    io_diagnostics_exports(assert);
    x86bios_sleep_misc_exports(assert);
    se_descriptor_exports(assert);
    se_token_info_exports(assert);
    po_fx_exports(assert);
    se_assign_exports(assert);
    se_access_exports(assert);
    rtl_crt_extended_exports(assert);
    ke_ex_sync_exports(assert);
    hal_dispatch_table_exports(assert);
    fsrtl_core_exports(assert);
    ob_object_lifecycle_exports(assert);
    ex_lookaside_wnf_exports(assert);
    mm_verifier_exports(assert);
    mm_session_views_exports(assert);
    mm_system_image_exports(assert);
    mm_mdl_ex_exports(assert);
    mm_secure_memory_exports(assert);
    mm_physical_memory_exports(assert);
    mm_system_info_exports(assert);
    rtl_hash_tables_exports(assert);
    rtl_strings_exports(assert);
    rtl_bit_ops_exports(assert);
    crt_strings_exports(assert);
    crt_formatting_exports(assert);
    io_csq_exports(assert);
    io_irp_request_exports(assert);
    io_pnp_interface_exports(assert);
    io_builtin_driver_exports(assert);
    io_named_event_exports(assert);
    io_wmi_data_block_exports(assert);
    io_work_item_queue_exports(assert);
    nt_struct_field_access(assert);
    rtl_bitmap_ex_exports(assert);
    ex_interlocked_exports(assert);
    ex_processor_usage_exports(assert);
    io_driver_registry_exports(assert);
    ps_property_sets_exports(assert);
    pcw_counters_exports(assert);
    rtl_self_relative_sd_exports(assert);
    kd_debug_filter_exports(assert);
    etw_wmi_clock_exports(assert);
    kse_shim_engine_exports(assert);
    ex_access_violation_exports(assert);
    rtl_network_address_exports(assert);
    rtl_crt_wide_exports(assert);
    io_top_level_irp_exports(assert);
    se_access_from_state_exports(assert);
    debug_print!("PHASE6_SELFTEST_OK");
}

/// Estruturas do NT tipadas (`inc::types`, geradas dos símbolos) sobre
/// memória de convidado: células `Field`, caminhos aninhados, vistas de
/// uniões, atômicos, bitfields, vetores, campo desalinhado e sondas.
fn nt_struct_field_access(assert: Assert) {
    use core::sync::atomic::Ordering;

    use crate::ntos::inc::nt_abi::{driver_object, irp as irp_layout};
    use crate::ntos::inc::types::{
        CmPartialResourceDescriptor, DispatcherHeader, DriverObject, Irp, Kthread, ObjectHeader,
    };
    use crate::ntos::inc::NtStruct;

    // IRP: u8/u16/u32/u64 e caminhos aninhados (IoStatus, Tail.Overlay).
    let block = guest::alloc_bytes(Irp::SIZE);
    // SAFETY: bloco zerado e alinhado do tamanho do IRP.
    let irp = unsafe { Irp::at(block) };
    irp.size.set(0xD0);
    irp.stack_count.set(3);
    irp.cancel.set(1);
    irp.flags.set(0x1234_5678);
    irp.io_status.status.set(0x103);
    irp.io_status.information.set(0x1122_3344_5566_7788);
    irp.tail.overlay.current_stack_location.set(0xFFFF_8000_1234_5678);
    assert(guest::read16(block + irp_layout::SIZE_FIELD) == 0xD0 && guest::read8(block + irp_layout::STACK_COUNT) == 3 && guest::read8(block + irp_layout::CANCEL) == 1 && guest::read32(block + irp_layout::FLAGS) == 0x1234_5678 && guest::read32(block + irp_layout::IO_STATUS) == 0x103 && guest::read64(block + irp_layout::IO_STATUS_INFORMATION) == 0x1122_3344_5566_7788 && guest::read64(block + irp_layout::CURRENT_STACK_LOCATION) == 0xFFFF_8000_1234_5678, "ntstruct: set de u8/u16/u32/u64 e caminhos aninhados no IRP");
    guest::write32(block + irp_layout::IO_STATUS, 0xC000_0001);
    guest::write64(block + irp_layout::USER_BUFFER, 0x7FFE_0000_1000);
    assert(irp.io_status.status.get() == 0xC000_0001u32 as i32 && irp.user_buffer.get() == 0x7FFE_0000_1000 && irp.stack_count.get() == 3, "ntstruct: get le o que outro escritor gravou");
    assert(irp.address() == block && irp.io_status.address() == block + irp_layout::IO_STATUS && irp.io_status.information.address() == block + irp_layout::IO_STATUS_INFORMATION, "ntstruct: enderecos de objeto e de campo");

    // União anônima: IO_STATUS_BLOCK.Pointer sobre Status (vista por Deref).
    irp.io_status.pointer.set(0xAAAA_BBBB_CCCC_DDDD);
    assert(irp.io_status.status.get() as u32 == 0xCCCC_DDDD && guest::read64(block + irp_layout::IO_STATUS) == 0xAAAA_BBBB_CCCC_DDDD, "ntstruct: membro de uniao anonima (Status/Pointer)");

    // Sondas (ponteiro não confiável).
    assert(Irp::try_at(0).is_err() && Irp::try_at(block + 1).is_err() && Irp::try_at(block).is_ok_and(|probed| probed.flags.get() == 0x1234_5678), "ntstruct: try_at recusa nulo e desalinhado e aceita o IRP");
    assert(irp.flags.probe_get().is_ok_and(|flags| flags == 0x1234_5678) && irp.io_status.information.probe_set(7).is_ok() && irp.io_status.information.get() == 7, "ntstruct: probe_get/probe_set");
    guest::free_bytes(block);

    // Atômicos: contador de referências do OBJECT_HEADER.
    let block = guest::alloc_bytes(ObjectHeader::SIZE);
    // SAFETY: bloco zerado do tamanho do cabeçalho.
    let header = unsafe { ObjectHeader::at(block) };
    header.pointer_count.set(1);
    header.pointer_count.atomic().fetch_add(2, Ordering::SeqCst);
    let previous = header.handle_count.atomic().fetch_sub(1, Ordering::SeqCst);
    assert(header.pointer_count.get() == 3 && previous == 0 && header.handle_count.get() == -1 && guest::read64(block) == 3, "ntstruct: fetch_add/fetch_sub atomicos em i64");
    header.flags.set(0);
    header.set_permanent_object(1);
    header.set_kernel_object(1);
    assert(header.flags.get() == 0x12 && header.permanent_object() == 1 && header.new_object() == 0 && ObjectHeader::PERMANENT_OBJECT_MASK == 0x10, "ntstruct: bitfields do OBJECT_HEADER (Flags)");
    guest::free_bytes(block);

    // Vistas do DISPATCHER_HEADER (Lock sobre Type/Signalling/Size) e bitfield do KTHREAD.
    let block = guest::alloc_bytes(Kthread::SIZE);
    // SAFETY: bloco zerado do tamanho do KTHREAD.
    let thread = unsafe { Kthread::at(block) };
    let dispatcher: &DispatcherHeader = &thread.header;
    dispatcher.lock.set(0x0004_0601);
    dispatcher.signal_state.set(-2);
    assert(dispatcher.type_.get() == 1 && dispatcher.signalling.get() == 6 && dispatcher.size.get() == 4 && guest::read32(block + 4) == 0xFFFF_FFFE, "ntstruct: vistas do DISPATCHER_HEADER");
    thread.misc_flags.set(0x11);
    thread.set_system_thread(1);
    thread.state.set(5);
    assert(thread.misc_flags.get() == 0x411 && thread.system_thread() == 1 && thread.alertable() == 1 && Kthread::SYSTEM_THREAD_SHIFT == 10 && guest::read8(block + 0x184) == 5, "ntstruct: bitfield com CAS e campo sobreposto (State)");
    guest::free_bytes(block);

    // Vetor de células: DRIVER_OBJECT.MajorFunction[IRP_MJ_DEVICE_CONTROL].
    let block = guest::alloc_bytes(DriverObject::SIZE);
    // SAFETY: bloco zerado do tamanho do DRIVER_OBJECT.
    let driver = unsafe { DriverObject::at(block) };
    driver.major_function[0x0E].set(0xFFFF_F800_0000_1234);
    assert(guest::read64(block + driver_object::MAJOR_FUNCTION + 0x0E * 8) == 0xFFFF_F800_0000_1234 && driver.major_function.len() == 28, "ntstruct: vetor de celulas (MajorFunction)");
    guest::free_bytes(block);

    // Campo desalinhado (#pragma pack(4)): u.Interrupt.Affinity em +0xC.
    let block = guest::alloc_bytes(0x20);
    // SAFETY: bloco zerado maior que o descritor.
    let descriptor = unsafe { CmPartialResourceDescriptor::at(block) };
    descriptor.type_.set(2);
    descriptor.u.interrupt.affinity.set(0x8000_0000_0000_0003);
    assert(CmPartialResourceDescriptor::SIZE == 0x14 && guest::read32(block + 0xC) == 3 && guest::read32(block + 0x10) == 0x8000_0000 && descriptor.u.interrupt.affinity.get() == 0x8000_0000_0000_0003, "ntstruct: campo desalinhado de estrutura empacotada");
    guest::free_bytes(block);

    // Estrutura do WDK fora dos símbolos (types/wdk.rs) e struct própria fora
    // dos arquivos gerados, com a mesma receita (Field/Reserved/NtStruct).
    use crate::ntos::inc::field::{Field, Reserved};
    use crate::ntos::inc::types::{ListEntry, ObCallbackRegistration};
    #[repr(C)]
    struct PrivateBody {
        count: Field<u32>,
        _pad_4: Reserved<4>,
        links: ListEntry,
    }
    // SAFETY: #[repr(C)] só de células.
    unsafe impl NtStruct for PrivateBody {}
    const _: () = assert!(core::mem::size_of::<PrivateBody>() == 0x18 && core::mem::offset_of!(PrivateBody, links) == 8);
    let block = guest::alloc_bytes(0x40);
    // SAFETY: bloco zerado de 0x40 bytes.
    let registration = unsafe { ObCallbackRegistration::at(block) };
    registration.version.set(0x100);
    registration.altitude.length.set(12);
    registration.operation_registration.set(0xFFFF_8000_0000_0040);
    assert(guest::read16(block) == 0x100 && guest::read16(block + 8) == 12 && guest::read64(block + 0x20) == 0xFFFF_8000_0000_0040, "ntstruct: estrutura do WDK fora dos simbolos (OB_CALLBACK_REGISTRATION)");
    // SAFETY: mesmo bloco, reinterpretado como a struct própria.
    let body = unsafe { PrivateBody::at(block) };
    body.count.atomic().fetch_add(5, Ordering::SeqCst);
    body.links.flink.set(block + 8);
    assert(body.count.get() == 0x105 &&guest::read64(block + 8) == block + 8 && body.links.address() == block + 8, "ntstruct: struct propria com NtStruct fora dos arquivos gerados");
    guest::free_bytes(block);
}
