//! Autoteste do suporte que os file systems reais pedem ao kernel: os
//! imports do clipsp.sys que o ntoskrnl ainda não tinha (towupper,
//! HviGetEnlightenmentInformation, IoGetDeviceInterfacePropertyData,
//! MmChangeImageProtection, ExUpdateLicenseData; o ZwQueryEaFile é coberto
//! no teste de informação de arquivos da fase 6), o ObQueryNameString num
//! buffer só com alinhamento de WCHAR (o do FltMgr) e os defaults e o DIRECT
//! do RtlQueryRegistryValues que o DriverEntry do ntfs.sys usa.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::init::exports::signed_status;
use crate::ntos::inc::types::{self as nt, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::test::phase6::{call_export, ntoskrnl_importer};

type Assert = fn(bool, &str);

fn at<T: NtStruct>(address: u64) -> &'static T {
    // SAFETY: blocos do convidado alocados por este teste.
    unsafe { T::at(address) }
}

fn wide(text: &str) -> Vec<u8> {
    text.encode_utf16().chain(core::iter::once(0)).flat_map(u16::to_le_bytes).collect()
}

pub fn run(assert: Assert) {
    towupper(assert);
    enlightenment_information(assert);
    interface_property_data(assert);
    change_image_protection(assert);
    update_license_data(assert);
    name_query_alignment(assert);
    registry_defaults(assert);
    stack_callout_status(assert);
    legal_ansi_character_array(assert);
}

/// towupper é o RtlUpcaseUnicodeChar: 'a'..'z' direto, o resto abaixo de
/// U+00C0 inalterado (µ, U+00B5) e a tabela de maiúsculas acima (é -> É,
/// ÿ -> Ÿ, α -> Α, а -> А; ÷ fica).
fn towupper(assert: Assert) {
    let cases = [(0x61u64, 0x41u64), (0x7A, 0x5A), (0x41, 0x41), (0xB5, 0xB5), (0xE9, 0xC9), (0xF7, 0xF7), (0xFF, 0x178), (0x3B1, 0x391), (0x430, 0x410)];
    let upper = |name: &str, unit: u64| call_export(name, &[unit]).map(|value| value & 0xFFFF);
    let towupper_ok = cases.iter().all(|&(unit, expected)| upper("towupper", unit) == Some(expected));
    let same = cases.iter().all(|&(unit, _)| upper("towupper", unit) == upper("RtlUpcaseUnicodeChar", unit));
    assert(towupper_ok && same, "fs-imports: towupper pela tabela de maiusculas, igual ao RtlUpcaseUnicodeChar");
}

/// HviGetEnlightenmentInformation: a leaf 0x40000004 com a interface "Hv#1",
/// zeros sem ela; os 16 bytes sempre gravados.
fn enlightenment_information(assert: Assert) {
    use crate::hal::cpu::cpuid;
    let buffer = guest::alloc_bytes(16);
    guest::write_bytes(buffer, &[0xAA; 16]);
    call_export("HviGetEnlightenmentInformation", &[buffer]);
    let interface = cpuid(0x4000_0001)[0];
    let compatible = cpuid(1)[2] & 0x8000_0000 != 0 && interface != 0x766E_6258 && interface == 0x3123_7648;
    let expected = if compatible { cpuid(0x4000_0004) } else { [0; 4] };
    let written: Vec<u32> = (0..4).map(|index| guest::read32(buffer + index * 4)).collect();
    assert(written == expected, "fs-imports: HviGetEnlightenmentInformation pela leaf 0x40000004 da interface Hv#1");
    guest::free_bytes(buffer);
}

/// IoGetDeviceInterfacePropertyData no armazenamento do
/// IoSetDeviceInterfacePropertyData: leitura, buffer curto com o tamanho e o
/// tipo, propriedade e interface ausentes, link NULL.
fn interface_property_data(assert: Assert) {
    let block = guest::alloc_bytes(0x400);
    let (guid, link, key_address, data, required, kind, output) = (block, block + 0x20, block + 0x100, block + 0x140, block + 0x180, block + 0x184, block + 0x188);
    guest::write_bytes(guid, b"OpenNTIfcProp01!");
    let pdo = guest::alloc_bytes(0x150);
    let registered = call_export("IoRegisterDeviceInterface", &[pdo, guid, 0, link]);
    guest::write_bytes(key_address, &[0x22; 16]);
    let key = at::<nt::Devpropkey>(key_address);
    key.pid.set(9);
    guest::write32(data, 0x1234_5678);
    let set = call_export("IoSetDeviceInterfacePropertyData", &[link, key_address, 0, 0, 7, 4, data]);
    let get = |size: u64| call_export("IoGetDeviceInterfacePropertyData", &[link, key_address, 0, 0, size, output, required, kind]);
    let read = get(8);
    let read_ok = read == Some(0) && guest::read32(output) == 0x1234_5678 && guest::read32(required) == 4 && guest::read32(kind) == 7;
    guest::write32(required, 0);
    let short = get(2) == Some(signed_status(0xC000_0023)) && guest::read32(required) == 4;
    key.pid.set(10);
    let missing = get(8) == Some(signed_status(0xC000_0034));
    let null = call_export("IoGetDeviceInterfacePropertyData", &[0, key_address, 0, 0, 8, output, required, kind]) == Some(signed_status(0xC000_000D));
    let stranger = block + 0x200;
    let name: Vec<u8> = "\\??\\OpenNtNoSuchInterface".encode_utf16().flat_map(u16::to_le_bytes).collect();
    guest::write_bytes(stranger + 0x10, &name);
    crate::ntos::rtl::guest_strings::write_string_fields(stranger, name.len() as u16, name.len() as u16, stranger + 0x10);
    let absent = call_export("IoGetDeviceInterfacePropertyData", &[stranger, key_address, 0, 0, 8, output, required, kind]) == Some(signed_status(0xC000_0034));
    assert(registered == Some(0) && set == Some(0) && read_ok && short && missing && null && absent, "fs-imports: IoGetDeviceInterfacePropertyData le a propriedade da interface com os erros do PnP");
    guest::free_bytes(pdo);
    guest::free_bytes(block);
}

/// MmChangeImageProtection numa imagem carregada: parâmetros, faixa fora da
/// imagem, MDL fora de imagem, troca em andamento, o modo 2 tirando a
/// execução e o modo 1 aprovado pelo CiValidateDynamicCodePages devolvendo-a.
fn change_image_protection(assert: Assert) {
    use crate::ntos::mm::pe_loader::{self, LoadOptions};
    use crate::ntos::mm::{loaded_images, paging, sysload};
    let options = LoadOptions { image_name: Some(String::from("opennt-image-protection.sys")), ..Default::default() };
    let Ok(mut image) = pe_loader::load(ntoskrnl_importer(b"PsGetThreadId\0"), &options) else {
        assert(false, "fs-imports: imagem de teste do MmChangeImageProtection carregada");
        return;
    };
    let (base, size) = (image.image_base, image.size_of_image);
    let page = base + 0x1000;
    let mdl = call_export("IoAllocateMdl", &[page, 0x1000, 0, 0, 0]).unwrap_or(0);
    call_export("MmProbeAndLockPages", &[mdl, 0, 0]);
    // O MDL que o MmProbeAndLockPages do NT deixa num endereço de sistema só
    // tem MDL_PAGES_LOCKED entre os três bits baixos; o IoAllocateMdl do
    // OpenNT já o marca mapeado e de pool não paginado (mapeamento por
    // identidade), então os dois bits saem aqui.
    let flags = &at::<nt::Mdl>(mdl).mdl_flags;
    flags.set(flags.get() & !5);
    let change = |address: u64, length: u64, mode: u64| call_export("MmChangeImageProtection", &[mdl, address, length, mode]);
    let executable = || paging::query_page(page, false).map(|query| !query.nx);
    let invalid = change(page, 0x1000, 3) == Some(signed_status(0xC000_000D)) && change(page, 0x1000, 0) == Some(signed_status(0xC000_000D));
    let outside = change(base + size, 0x1000, 2) == Some(signed_status(0xC000_0018)) && change(page, 0, 2) == Some(signed_status(0xC000_0018));
    let entry = loaded_images::native_list().ok().and_then(|(_, entries)| entries.into_iter().find(|(loaded, _)| loaded.image_base == base).map(|(_, entry)| entry)).unwrap_or(0);
    let loader = at::<nt::KldrDataTableEntry>(entry);
    loader.flags.set(loader.flags.get() | 0x0008_0000);
    let busy = change(page, 0x1000, 2) == Some(signed_status(0xC000_0043));
    loader.flags.set(loader.flags.get() & !0x0008_0000);
    let load_count = loader.load_count.get();
    let data_only = change(page, 0x1000, 2) == Some(0) && executable() == Some(false);
    let validator = crate::ntos::se::code_integrity::dynamic_code_validator_present();
    let approved = if validator { change(page, 0x1000, 1) == Some(0) && executable() == Some(true) } else { change(page, 0x1000, 1) == Some(signed_status(0xC000_0002)) && executable() == Some(false) };
    let settled = loader.flags.get() & 0x0008_0000 == 0 && loader.load_count.get() == load_count;
    // MDL de pool, fora de qualquer imagem: STATUS_NOT_FOUND.
    let pool = guest::alloc_bytes(0x2000);
    let pool_mdl = call_export("IoAllocateMdl", &[(pool + 0xFFF) & !0xFFF, 0x1000, 0, 0, 0]).unwrap_or(0);
    call_export("MmProbeAndLockPages", &[pool_mdl, 0, 0]);
    let pool_flags = &at::<nt::Mdl>(pool_mdl).mdl_flags;
    pool_flags.set(pool_flags.get() & !5);
    let not_image = call_export("MmChangeImageProtection", &[pool_mdl, page, 0x1000, 2]) == Some(signed_status(0xC000_0225));
    assert(entry != 0 && invalid && outside && busy && data_only && approved && settled && not_image, "fs-imports: MmChangeImageProtection valida o MDL e troca a execucao das paginas da imagem");
    let _ = sysload::set_image_protection(page, 0x1000, sysload::MM_EXECUTE_READWRITE);
    for descriptor in [mdl, pool_mdl] {
        call_export("MmUnlockPages", &[descriptor]);
        call_export("IoFreeMdl", &[descriptor]);
    }
    guest::free_bytes(pool);
    let _ = image.release();
}

/// Entrada do ProductPolicy: cabeçalho, nome UTF-16 e dados, em múltiplo de 4.
fn license_entry(name: &str, value_type: u16, data: &[u8], flags: u32) -> Vec<u8> {
    let units: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let size = (16 + units.len() + data.len()).div_ceil(4) * 4;
    let mut bytes = Vec::new();
    for value in [size as u16, units.len() as u16, value_type, data.len() as u16] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(&units);
    bytes.extend_from_slice(data);
    bytes.resize(size, 0);
    bytes
}

/// ProductPolicy versão 1 com os flags do cabeçalho e o rodapé 0x45.
fn license_policy(entries: &[Vec<u8>], header_flags: u32) -> Vec<u8> {
    let body: Vec<u8> = entries.iter().flatten().copied().collect();
    let mut bytes = Vec::new();
    for value in [(20 + body.len() + 4) as u32, body.len() as u32, 4, header_flags, 1] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(&0x45u32.to_le_bytes());
    bytes
}

/// ExUpdateLicenseData pelo export (a validação do SLUpdateLicenseDataInternal,
/// que marca um estado local zero como violado) e a publicação num contexto
/// próprio pelas seções do kernel: um valor marcado novo dá
/// STATUS_SOME_NOT_MAPPED, a mesma política dá STATUS_OBJECT_NAME_EXISTS sem
/// trocar a visão, um valor comum mudado troca a visão e a consulta, e o
/// ProductPolicy do Registry recebe a política publicada.
fn update_license_data(assert: Assert) {
    use crate::ntos::ex::license::boot::{self, BootProviders};
    use crate::ntos::ex::license::special::Providers;
    use crate::ntos::ex::license::{service, special, state, values};
    let blob = guest::alloc_bytes(0x100);
    let header = |total: u32, values_size: u32, footer: u32, version: u32| {
        guest::write_bytes(blob, &[0u8; 0x100]);
        for (offset, value) in [(0, total), (4, values_size), (8, footer), (16, version)] {
            guest::write32(blob + offset, value);
        }
    };
    let host = values::host_context();
    let saved = special::read_local_state(host).unwrap_or(0);
    let update = |size: u64, buffer: u64| call_export("ExUpdateLicenseData", &[size, buffer]);
    let invalid = signed_status(0xC000_000D);
    header(0x40, 0x24, 8, 1);
    let null = update(0x40, 0) == Some(invalid);
    let marked = special::read_local_state(host).is_ok_and(|current| current == if saved == 0 { 5 } else { saved });
    let small = update(0x18, blob) == Some(invalid);
    let large = update(0x14001, blob) == Some(invalid);
    let unaligned = update(0x40, blob + 2) == Some(invalid);
    header(0x14004, 0x24, 8, 1);
    let field = update(0x40, blob) == Some(signed_status(0xC000_0040));
    header(0x40, 0x22, 8, 1);
    let footer_alignment = update(0x40, blob) == Some(invalid);
    header(0x44, 0x24, 8, 1);
    let sum = update(0x44, blob) == Some(invalid);
    header(0x40, 0x24, 8, 1);
    let size = update(0x3C, blob) == Some(invalid);
    header(0x40, 0x24, 8, 2);
    let version = update(0x40, blob) == Some(invalid);
    let _ = state::set_context_state(host, saved);
    assert(null && marked && small && large && unaligned && field && footer_alignment && sum && size && version, "fs-imports: ExUpdateLicenseData valida a politica como o SLUpdateLicenseDataInternal");
    guest::free_bytes(blob);

    // Publicação num contexto próprio, sem buffer primário.
    const PRODUCT_OPTIONS: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\ProductOptions";
    let previous = crate::ntos::cm::registry::read_value_by_path(PRODUCT_OPTIONS, "ProductPolicy");
    let Ok(Ok((context, _))) = boot::create(None, &BootProviders::default()) else {
        assert(false, "fs-imports: contexto de licenca de teste criado");
        return;
    };
    let buffer = guest::alloc_bytes(0x200);
    let publish = |policy: &[u8]| {
        guest::write_bytes(buffer, policy);
        boot::update(context, buffer, policy.len() as u32).ok()
    };
    let name = guest::alloc_bytes(0x80);
    let output = guest::alloc_bytes(0x10);
    let length = guest::alloc_bytes(8);
    let query = |text: &str| {
        let units: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        guest::write_bytes(name + 0x10, &units);
        crate::ntos::rtl::guest_strings::write_string_fields(name, units.len() as u16, units.len() as u16, name + 0x10);
        match service::query(context, name, 0, output, 4, length, &Providers::default()) {
            Ok(0) => Some(guest::read32(output)),
            _ => None,
        }
    };
    let policy = |plain: u32, flagged: u32| license_policy(&[license_entry("OpenNt-Plain", 4, &plain.to_le_bytes(), 0), license_entry("OpenNt-Flagged", 4, &flagged.to_le_bytes(), 2)], 0);
    // A SECTION é criada com OBJ_KERNEL_HANDLE | OBJ_EXCLUSIVE, como no
    // SLUpdateLicenseDataInternal.
    let first = publish(&policy(1, 7)) == Some(0x107) && query("OpenNt-Plain") == Some(1);
    let view = guest::read64(context + 0xB6F0);
    let same = publish(&policy(1, 7)) == Some(0x4000_0000) && guest::read64(context + 0xB6F0) == view;
    let plain = publish(&policy(5, 7)) == Some(0) && query("OpenNt-Plain") == Some(5) && guest::read64(context + 0xB6F0) != view;
    let flagged = publish(&policy(5, 8)) == Some(0x107) && query("OpenNt-Flagged") == Some(8);
    let stored = crate::ntos::cm::registry::read_value_by_path(PRODUCT_OPTIONS, "ProductPolicy").is_some_and(|value| value.value_type == 3 && value.data == policy(5, 8));
    let refused = publish(&license_policy(&[license_entry("OpenNt-Plain", 4, &1u32.to_le_bytes(), 0)], 1)) == Some(0xC000_000D);
    assert(first && same && plain && flagged && stored && refused, "fs-imports: SLUpdateLicenseDataInternal publica, reconhece a mesma politica, troca a visao e grava o ProductPolicy");
    let _ = boot::destroy(context);
    if let Ok(handle) = crate::ntos::cm::registry::open_or_create(PRODUCT_OPTIONS, None) {
        match previous {
            Some(value) => {
                crate::ntos::cm::registry::set_value(handle, "ProductPolicy", value.value_type, value.data);
            }
            None => {
                crate::ntos::cm::registry::delete_value(handle, "ProductPolicy");
            }
        }
        crate::ntos::cm::registry::close_handle(handle);
    }
    for pointer in [buffer, name, output, length] {
        guest::free_bytes(pointer);
    }
}

/// ObQueryNameString de um DEVICE_OBJECT nomeado num buffer só com
/// alinhamento de WCHAR: OBJECT_NAME_INFORMATION e o texto logo depois.
fn name_query_alignment(assert: Assert) {
    use crate::ntos::io::lifecycle;
    use crate::ntos::ob::object_manager;
    // Um driver carregado de verdade (DriverEntry `xor eax, eax; ret`), dono
    // dos dispositivos nomeados no \Device.
    let mut image = ntoskrnl_importer(b"PsGetThreadId\0");
    image[0x1340..0x1343].copy_from_slice(&[0x31, 0xC0, 0xC3]);
    image[0x58 + 16..0x58 + 20].copy_from_slice(&0x1340u32.to_le_bytes());
    let _ = crate::drivers::fs::memory_file_system::write_bytes("/opennt-fs-names.sys", image);
    let loaded = lifecycle::load_driver("/opennt-fs-names.sys", &lifecycle::DriverOptions::default());
    let driver = object_manager::lookup("\\Driver\\opennt-fs-names").and_then(object_manager::node).and_then(|node| node.data).map_or(0, |data| data.native_pointer);
    if loaded.is_err() || driver == 0 {
        assert(false, "fs-imports: driver de teste do ObQueryNameString carregado");
        return;
    }
    let block = guest::alloc_bytes(0x400);
    let name = "\\Device\\OpenNtNameAlignment";
    let units = wide(name);
    guest::write_bytes(block + 0x40, &units);
    crate::ntos::rtl::guest_strings::write_string_fields(block, (units.len() - 2) as u16, units.len() as u16, block + 0x40);
    let created = call_export("IoCreateDevice", &[driver, 0, block, 0x22, 0, 0, block + 0x20]);
    let device = guest::read64(block + 0x20);
    let output = block + 0x102;
    let returned = block + 0x3F0;
    let status = call_export("ObQueryNameString", &[device, output, 0x200, returned]);
    let length = guest::read16(output) as usize;
    let text_buffer = guest::read64(output + 8);
    let text: Vec<u16> = (0..length / 2).map(|index| guest::read16(output + 16 + index as u64 * 2)).collect();
    let ok = created == Some(0) && status == Some(0) && length == name.len() * 2 && text_buffer == output + 16 && String::from_utf16_lossy(&text) == name && guest::read32(returned) as usize == 16 + name.len() * 2 + 2;
    assert(ok, "fs-imports: ObQueryNameString num buffer desalinhado do chamador");
    // Size do DEVICE_OBJECT: sizeof(DEVICE_OBJECT) + DeviceExtensionSize.
    let extended = call_export("IoCreateDevice", &[driver, 0x58, 0, 0x22, 0, 0, block + 0x28]);
    let with_extension = guest::read64(block + 0x28);
    let sizes = created == Some(0) && extended == Some(0) && at::<nt::DeviceObject>(device).size.get() == 0x150 && at::<nt::DeviceObject>(with_extension).size.get() == 0x1A8;
    assert(sizes, "fs-imports: IoCreateDevice grava Size com a extensao do driver");
    if extended == Some(0) {
        call_export("IoDeleteDevice", &[with_extension]);
    }
    if created == Some(0) {
        call_export("IoDeleteDevice", &[device]);
    }
    guest::free_bytes(block);
    let _ = lifecycle::unload_driver("opennt-fs-names");
}

/// RtlQueryRegistryValues com valores ausentes: default de string sem dados
/// = STATUS_DATA_OVERRUN; default REG_SZ medido até o terminador e alocado
/// no UNICODE_STRING do DIRECT; DWORD direto; REG_NONE ignorado ou exigido;
/// dado maior que 4 bytes pelo tamanho negativo no início do buffer.
fn registry_defaults(assert: Assert) {
    const DIRECT: u32 = 0x20;
    const REQUIRED: u32 = 0x04;
    let block = guest::alloc_bytes(0x800);
    let path = block + 0x600;
    guest::write_bytes(path, &wide("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Ntfs"));
    let value_name = block + 0x500;
    guest::write_bytes(value_name, &wide("OpenNtMissingValue"));
    let default_text = block + 0x580;
    guest::write_bytes(default_text, &wide("abc"));
    let (table, context) = (block, block + 0x100);
    let query = |flags: u32, default_type: u32, default_data: u64, default_length: u32| {
        guest::write_bytes(table, &[0u8; 0xA8]);
        let entry = at::<nt::RtlQueryRegistryTable>(table);
        entry.flags.set(flags);
        entry.name.set(value_name);
        entry.entry_context.set(context);
        entry.default_type.set(default_type);
        entry.default_data.set(default_data);
        entry.default_length.set(default_length);
        call_export("RtlQueryRegistryValues", &[0, path, table, 0, 0])
    };
    guest::write_bytes(context, &[0u8; 0x20]);
    let overrun = query(DIRECT, 2, 0, 0) == Some(signed_status(0xC000_003C));
    guest::write_bytes(context, &[0u8; 0x20]);
    let string = at::<nt::UnicodeString>(context);
    let measured = query(DIRECT, 1, default_text, 0) == Some(0) && string.length.get() == 6 && string.maximum_length.get() == 8 && string.buffer.get() != 0 && guest::read_bytes(string.buffer.get(), 8) == wide("abc");
    if string.buffer.get() != 0 {
        call_export("RtlFreeUnicodeString", &[context]);
    }
    guest::write32(block + 0x590, 0x4433_2211);
    guest::write_bytes(context, &[0u8; 0x20]);
    let dword = query(DIRECT, 4, block + 0x590, 4) == Some(0) && guest::read32(context) == 0x4433_2211;
    guest::write_bytes(context, &[0x5Au8; 0x20]);
    let none = query(DIRECT, 0, 0, 0) == Some(0) && guest::read32(context) == 0x5A5A_5A5A && query(DIRECT | REQUIRED, 0, 0, 0) == Some(signed_status(0xC000_0034));
    guest::write64(block + 0x598, 0x8877_6655_4433_2211);
    guest::write_bytes(context, &[0u8; 0x20]);
    guest::write32(context, (-8i32) as u32);
    let sized = query(DIRECT, 11, block + 0x598, 8) == Some(0) && guest::read64(context) == 0x8877_6655_4433_2211;
    guest::write_bytes(context, &[0u8; 0x20]);
    let too_small = query(DIRECT, 11, block + 0x598, 8) == Some(signed_status(0xC000_0023));
    assert(overrun && measured && dword && none && sized && too_small, "fs-imports: RtlQueryRegistryValues com os defaults e o DIRECT do RtlpQueryRegistryDirect");
    guest::free_bytes(block);
}

/// KeExpandKernelStackAndCalloutEx devolve o NTSTATUS da expansão (o
/// callout é VOID): um callout que grava no parâmetro e deixa
/// STATUS_INVALID_DEVICE_REQUEST em RAX dá STATUS_SUCCESS; tamanho acima do
/// máximo é STATUS_INVALID_PARAMETER_3 sem chamar o callout.
fn stack_callout_status(assert: Assert) {
    // mov qword ptr [rcx], 1; mov eax, 0xC0000010; ret
    let block = super::executable_code::place(&[0x48, 0xC7, 0x01, 0x01, 0x00, 0x00, 0x00, 0xB8, 0x10, 0x00, 0x00, 0xC0, 0xC3]);
    let parameter = guest::alloc_bytes(8);
    guest::write64(parameter, 0);
    let expanded = call_export("KeExpandKernelStackAndCalloutEx", &[block, parameter, 0x3000, 1, 0]);
    let ran = guest::read64(parameter) == 1;
    guest::write64(parameter, 0);
    let too_large = call_export("KeExpandKernelStackAndCalloutEx", &[block, parameter, 0x11801, 1, 0]) == Some(signed_status(0xC000_00F1)) && guest::read64(parameter) == 0;
    assert(block != 0 && expanded == Some(0) && ran && too_large, "fs-imports: KeExpandKernelStackAndCalloutEx devolve o NTSTATUS da expansao, nao o RAX do callout");
    super::executable_code::release(block);
    guest::free_bytes(parameter);
}

/// FsRtlLegalAnsiCharacterArray é um PUCHAR, como no ntoskrnl: a célula
/// exportada aponta a tabela (curingas '*' e '?' = 0x18, letras = 0x17).
fn legal_ansi_character_array(assert: Assert) {
    let cell = crate::ntos::fsrtl::name::legal_ansi_character_array_address();
    let table = guest::read64(cell);
    let ok = table == cell + 8 && guest::read_bytes(table + 0x2A, 1)[0] == 0x18 && guest::read_bytes(table + 0x3F, 1)[0] == 0x18 && guest::read_bytes(table + 0x41, 1)[0] == 0x17 && guest::read_bytes(table, 1)[0] == 0;
    assert(ok, "fs-imports: FsRtlLegalAnsiCharacterArray exporta o ponteiro para a tabela");
}
