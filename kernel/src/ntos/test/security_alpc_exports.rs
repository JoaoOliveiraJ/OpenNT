//! Autoteste dos exports de Se, Ob, Lsa e ALPC que eram os últimos imports de
//! drivers reais: o SDDL dos SIDs e dos descritores, os níveis de assinatura
//! em cache, as verificações de token do Rtl, o ZwOpenProcessToken, o
//! LsaFreeReturnBuffer, o NtSetSecurityObject e o ALPC de modo kernel; e a
//! decodificação das mensagens LRPC do rastro `--trace-rpc`.
//!
//! Os vetores do SDDL (descritores, strings de SID e o tamanho reservado que
//! o conversor devolve) foram calculados executando as rotinas do ntoskrnl
//! 19041 real num emulador; cada teste chama o export pelo trampolim nativo
//! (ABI MS x64).

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::inc::{types as nt, NtStruct};
use crate::ntos::mm::guest_memory as guest;

type Assert = fn(bool, &str);

fn call(name: &str, arguments: &[u64]) -> u64 {
    super::phase6::call_export(name, arguments).unwrap_or(0xDEAD_DEAD_DEAD_DEAD)
}

fn status(name: &str, arguments: &[u64]) -> u32 {
    call(name, arguments) as u32
}

fn at<T: NtStruct>(address: u64) -> &'static T {
    // SAFETY: blocos alocados pelo teste com o tamanho do tipo.
    unsafe { T::at(address) }
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap_or(0)).collect()
}

/// Um bloco do kernel com os bytes (SIDs e descritores precisam de VA de sistema).
fn kernel_bytes(bytes: &[u8]) -> u64 {
    let pointer = guest::alloc_bytes(bytes.len() as u64 + 8);
    guest::write_bytes(pointer, bytes);
    pointer
}

fn wide_string(text: &str) -> u64 {
    let mut bytes: Vec<u8> = text.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
    bytes.extend_from_slice(&[0, 0]);
    kernel_bytes(&bytes)
}

fn read_wide(pointer: u64) -> String {
    crate::ntos::rtl::guest_strings::read_wide_string(pointer)
}

fn free_pool(pointer: u64) {
    if pointer != 0 {
        call("ExFreePool", &[pointer]);
    }
}

// ---- SDDL: SIDs ----------------------------------------------------------------

/// (SID em hexadecimal, texto do SeConvertSidToStringSid).
const SID_STRING_VECTORS: &[(&str, &str)] = &[
    ("01020000000000052000000020020000", "S-1-5-32-544"),
    ("010100000000000000000000", "S-1-0-0"),
    ("010500000000000515000000010000000200000003000000f4010000", "S-1-5-21-1-2-3-500"),
    ("010100000000001000300000", "S-1-16-12288"),
    ("0101ffffffffffffffffffff", "S-1-0xFFFFFFFFFFFF-4294967295"),
    ("010101000000000005000000", "S-1-0x10000000000-5"),
    ("010100010000000007000000", "S-1-0x100000000-7"),
];

/// (texto, NTSTATUS do SeConvertStringSidToSid, SID devolvido em hexadecimal
/// ou vazio quando o *Sid fica nulo).
const STRING_SID_VECTORS: &[(&str, u32, &str)] = &[
    ("S-1-5-32-544", 0x00000000, "01020000000000052000000020020000"),
    ("s-1-5-18", 0x00000000, "010100000000000512000000"),
    ("S-1-5", 0xC0000078, ""),
    ("S-1-5-", 0xC0000078, ""),
    ("S-1-5-32-", 0xC0000078, ""),
    ("BA", 0xC0000078, ""),
    ("S-1-0x5-0x20-0x220", 0x00000000, "01020000000000052000000020020000"),
    ("S-0x1-10-20", 0x00000000, "010100000000001020000000"),
    ("S-1-5-32-544;x", 0x00000000, "01020000000000052000000020020000"),
    ("S-1-5-32-544 ", 0xC0000078, ""),
    ("S-1-5--32", 0xC0000078, ""),
    ("S-256-5-1", 0xC0000078, ""),
    ("S-1-281474976710656-1", 0xC0000078, ""),
    ("S-1-5-4294967296", 0x00000000, "0101000000000005ffffffff"),
    ("S-1-5-1a", 0x00000000, ""),
    ("S-1-5-32-544)", 0x00000000, "01020000000000052000000020020000"),
    ("S-1-5-32-544D:", 0x00000000, "01020000000000052000000020020000"),
    ("S-1-5-32-544G:x", 0x00000000, "01020000000000052000000020020000"),
    ("S-1-5-32-544K:", 0xC0000078, ""),
    ("S-1-1-0", 0x00000000, "010100000000000100000000"),
    ("S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16", 0x00000000, "01100000000000050100000002000000030000000400000005000000060000000700000008000000090000000a0000000b0000000c0000000d0000000e0000000f00000010000000"),
    ("", 0xC0000078, ""),
    ("S-", 0xC0000078, ""),
    ("S-1-5-0x20-0X221", 0x00000000, "01020000000000052000000021020000"),
    ("S-0x1-0x10-20", 0x00000000, "010100000000001020000000"),
    ("S-1-1-0,", 0x00000000, "010100000000000100000000"),
    ("S-1-1-0-", 0xC0000078, ""),
];

fn sddl_sid_strings(assert: Assert) {
    let output = guest::alloc_bytes(8);
    let converted = SID_STRING_VECTORS.iter().all(|&(sid, text)| {
        guest::write64(output, 0);
        let pointer = kernel_bytes(&hex(sid));
        let result = status("SeConvertSidToStringSid", &[pointer, output]);
        let buffer = guest::read64(output);
        let ok = result == 0 && buffer != 0 && read_wide(buffer) == text;
        free_pool(buffer);
        guest::free_bytes(pointer);
        ok
    });
    assert(converted, "se-sddl: SeConvertSidToStringSid com a autoridade em hexadecimal acima de 32 bits");
    let sid = kernel_bytes(&hex(SID_STRING_VECTORS[0].0));
    guest::write64(output, 0x5A5A);
    assert(
        status("SeConvertSidToStringSid", &[0, output]) == 0xC000_000D && status("SeConvertSidToStringSid", &[sid, 0]) == 0xC000_000D && status("SeConvertSidToStringSid", &[0x1000, output]) == 0xC000_0078 && guest::read64(output) == 0x5A5A,
        "se-sddl: SID ou saida nulos = STATUS_INVALID_PARAMETER, SID em VA de usuario = STATUS_INVALID_SID",
    );
    guest::free_bytes(sid);
    let parsed = STRING_SID_VECTORS.iter().position(|&(text, expected, sid)| {
        guest::write64(output, 0);
        let string = wide_string(text);
        let result = status("SeConvertStringSidToSid", &[string, output]);
        let pointer = guest::read64(output);
        let bytes = if pointer != 0 { guest::read_bytes(pointer, 8 + guest::read8(pointer + 1) as usize * 4) } else { Vec::new() };
        free_pool(pointer);
        guest::free_bytes(string);
        result != expected || bytes != hex(sid)
    });
    let message = alloc::format!("se-sddl: SeConvertStringSidToSid com bases, terminadores do SDDL e falhas no fim da string (primeiro vetor errado: {parsed:?})");
    assert(parsed.is_none(), &message);
    let string = wide_string("S-1-1-0");
    assert(status("SeConvertStringSidToSid", &[0, output]) == 0xC000_000D && status("SeConvertStringSidToSid", &[string, 0]) == 0xC000_000D, "se-sddl: SeConvertStringSidToSid recusa ponteiros nulos");
    guest::free_bytes(string);
    guest::free_bytes(output);
}

// ---- SDDL: descritores -----------------------------------------------------------

/// (descritor em hexadecimal, SECURITY_INFORMATION, NTSTATUS, texto, tamanho
/// devolvido em caracteres; 0xFFFFFFFF = não escrito).
const DESCRIPTOR_VECTORS: &[(&str, u32, u32, &str, u32)] = &[
    ("010000801400000024000000000000000000000001020000000000052000000020020000010100000000000512000000", 0x3, 0x00000000, "O:BAG:SY", 8),
    ("01000080140000003000000000000000000000000105000000000005150000000100000002000000030000000002000001050000000000051500000001000000020000000300000001020000", 0x3, 0x00000000, "O:S-1-5-21-1-2-3-512G:S-1-5-21-1-2-3-513", 40),
    ("010004800000000000000000000000001400000002001c00010000000000140000000010010100000000000100000000", 0x4, 0x00000000, "D:(A;;GA;;;WD)", 15),
    ("0100049414000000000000000000000020000000010100000000000512000000020034000200000000031400ff011f00010100000000000512000000011018008900120001020000000000052000000021020000", 0x5, 0x00000000, "O:SYD:PAI(A;OICI;FA;;;SY)(D;ID;FR;;;BU)", 41),
    ("01000481000000000000000000000000140000000200480003000000001b14007856341201010000000000050b0000000000180003000300010200000000000520000000200200000020140000000000010100000000000300000000", 0x4, 0x00000000, "D:AR(A;OICIIOID;0x12345678;;;AU)(A;;CCDCSDRC;;;BA)(A;CR;;;;CO)", 65),
    ("0100048000000000000000000000000000000000", 0x4, 0x00000000, "D:NO_ACCESS_CONTROL", 20),
    ("01000490000000000000000000000000140000000200080000000000", 0x4, 0x00000000, "D:P", 3),
    ("010010a800000000000000001400000000000000020044000300000002c0140000000010010100000000000100000000110014000300000001010000000000100030000003811400ff011f00010100000000000507000000", 0x18, 0x00000000, "S:PAI(AU;SAFA;GA;;;WD)(ML;;NWNR;;;HI)(AL;OIFA;FA;;;AN)", 57),
    ("0100108000000000000000001400000000000000020030000200000002c01400000000100101000000000001000000001100140001000000010100000000001000100000", 0x10, 0x00000000, "S:(ML;;NW;;;LW)", 16),
    ("0100108000000000000000001400000000000000020030000200000002c01400000000100101000000000001000000001100140001000000010100000000001000100000", 0x8, 0x00000000, "S:(AU;SAFA;GA;;;WD)", 20),
    ("01000480000000000000000000000000140000000200680002000000050238003000000003000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f01010000000000050b000000060028000001000001000000000102030405060708090a0b0c0d0e0f010100000000000100000000", 0x4, 0x00000000, "D:(OA;CI;RPWP;03020100-0504-0706-0809-0a0b0c0d0e0f;13121110-1514-1716-1819-1a1b1c1d1e1f;AU)(OD;;CR;03020100-0504-0706-0809-0a0b0c0d0e0f;;WD)", 142),
    ("010004800000000000000000000000001400000002001c00010000001100140001000000010100000000001000100000", 0x4, 0xC0070538, "", 0xFFFF_FFFF),
    ("0100149c1400000024000000300000004c0000000102000000000005200000002002000001010000000000051200000002001c0001000000024014000000001001010000000000010000000002001c00010000000000140000000010010100000000000512000000", 0xf, 0x00000000, "O:BAG:SYD:PAI(A;;GA;;;SY)S:AI(AU;SA;GA;;;WD)", 46),
    ("0100008014000000000000000000000000000000010100000000000512000000", 0x0, 0x00000000, "", 0),
    ("010004800000000000000000000000001400000002004400030000000000140005000f0001010000000000051200000000001400190002000101000000000005120000000000140008000000010100000000000512000000", 0x4, 0x00000000, "D:(A;;CCLCSDRCWDWO;;;SY)(A;;KR;;;SY)(A;;SW;;;SY)", 51),
    ("010004800000000000000000000000001400000002001c00010000000900140001000000010100000000000512000000", 0x4, 0x00000000, "D:(XA;;CC;;;SY)", 16),
    ("010004800000000000000000000000001400000002003000020000000000140001efcdab0101000000000005120000000000140000100000010100000000000512000000", 0x4, 0x00000000, "D:(A;;0xabcdef01;;;SY)(A;;0x1000;;;SY)", 44),
    ("020004800000000000000000000000001400000002001c00010000000000140000000010010100000000000512000000", 0x4, 0xC0070519, "", 0xFFFF_FFFF),
    ("020004800000000000000000000000001400000002001c00010000000000140000000010010100000000000512000000", 0x200, 0xC0070519, "", 0xFFFF_FFFF),
    ("010004800000000000000000000000001400000002001c00010000000000140001000000020100000000000512000000", 0x4, 0xC0070539, "", 0xFFFF_FFFF),
    ("01000490140000000000000000000000200000000101000000000005120000000200080000000000", 0x200, 0x00000000, "", 0),
    ("0100008014000000000000000000000000000000010100000000000512000000", 0x4, 0x00000000, "", 0),
    ("0100108000000000000000000000000000000000", 0x8, 0x00000000, "S:NO_ACCESS_CONTROL", 20),
];

fn sddl_descriptor_strings(assert: Assert) {
    // Os erros do conversor passam pelo RtlNtStatusToDosError.
    assert(call("RtlNtStatusToDosErrorNoTeb", &[0xC000_0078]) == 1337 && call("RtlNtStatusToDosErrorNoTeb", &[0xC000_0058]) == 1305, "se-sddl: STATUS_INVALID_SID e STATUS_UNKNOWN_REVISION na tabela do RtlNtStatusToDosError");
    let (output, length) = (guest::alloc_bytes(8), guest::alloc_bytes(8));
    let convert = |descriptor: u64, revision: u64, information: u64, output: u64| {
        guest::write64(length, 0xFFFF_FFFF);
        status("SeConvertSecurityDescriptorToStringSecurityDescriptor", &[descriptor, revision, information, output, length])
    };
    let mut failed: Option<usize> = None;
    for (index, &(descriptor, information, expected, text, reserved)) in DESCRIPTOR_VECTORS.iter().enumerate() {
        guest::write64(output, 0);
        let pointer = kernel_bytes(&hex(descriptor));
        let result = convert(pointer, 1, information as u64, output);
        let buffer = guest::read64(output);
        let converted = if buffer != 0 { read_wide(buffer) } else { String::new() };
        if result != expected || converted != text || guest::read32(length) != reserved || (expected != 0 && buffer != 0) {
            failed.get_or_insert(index);
        }
        free_pool(buffer);
        guest::free_bytes(pointer);
    }
    let message = alloc::format!("se-sddl: SeConvertSecurityDescriptorToStringSecurityDescriptor com apelidos, flags, direitos, GUIDs, filtro da SACL e o tamanho reservado (primeiro vetor errado: {failed:?})");
    assert(failed.is_none(), &message);
    // Descritor absoluto: os componentes por ponteiro.
    let owner = kernel_bytes(&hex("01020000000000052000000020020000"));
    let dacl = kernel_bytes(&hex("02001c00010000000102140016011200010100000000000100000000"));
    let absolute = guest::alloc_bytes(nt::SecurityDescriptor::SIZE);
    guest::write_bytes(absolute, &[0; nt::SecurityDescriptor::SIZE as usize]);
    let header = at::<nt::SecurityDescriptor>(absolute);
    header.revision.set(1);
    header.control.set(0x0004);
    header.owner.set(owner);
    header.dacl.set(dacl);
    guest::write64(output, 0);
    let result = convert(absolute, 1, 5, output);
    let buffer = guest::read64(output);
    assert(result == 0 && buffer != 0 && read_wide(buffer) == "O:BAD:(D;CI;FW;;;WD)" && guest::read32(length) == 21, "se-sddl: descritor absoluto");
    free_pool(buffer);
    // Revisão, saída nula e descritor nulo.
    guest::write64(output, 0);
    let revision = convert(owner, 2, 1, output);
    let no_output = convert(absolute, 1, 1, 0);
    let null_descriptor = convert(0, 1, 1, output);
    let empty = guest::read64(output);
    assert(
        revision == 0xC007_0519 && no_output == 0xC007_0057 && null_descriptor == 0 && empty != 0 && guest::read16(empty) == 0 && guest::read32(length) == 0 && convert(0, 1, 1, 0) == 0xC007_0057,
        "se-sddl: revisao != 1 = ERROR_UNKNOWN_REVISION, saida nula = ERROR_INVALID_PARAMETER, descritor nulo = string vazia",
    );
    free_pool(empty);
    for pointer in [owner, dacl, absolute, output, length] {
        guest::free_bytes(pointer);
    }
}

// ---- Níveis de assinatura ---------------------------------------------------------

fn signing_levels(assert: Assert) {
    use crate::drivers::fs::memory_file_system;
    use crate::ntos::io::file::zw as zw_files;
    use crate::ntos::se::code_integrity::{self, SigningCallback};
    let block = guest::alloc_bytes(0x900);
    guest::write_bytes(block, &[0; 0x900]);
    let (flags, level, size, algorithm, thumbprint, handle) = (block + 0x700, block + 0x708, block + 0x710, block + 0x718, block + 0x780, block + 0x7F0);
    // Sem a CI inicializada os slots da SeCiCallbacks são nulos.
    let compare_absent = code_integrity::signing_callback(SigningCallback::CompareSigningLevels) == 0;
    assert(!compare_absent || (call("SeCompareSigningLevels", &[8, 4]) & 0xFF == 0 && call("SeCompareSigningLevels", &[4, 8]) & 0xFF == 0), "se-signing: SeCompareSigningLevels sem a CI devolve FALSE");
    let _ = memory_file_system::write_bytes("/opennt-signing.txt", b"assinatura".to_vec());
    let attributes = super::phase6::object_attributes_for(block, "\\FS\\opennt-signing.txt", 0x240);
    let _ = zw_files::create_kernel_file(handle, 0x12019F, attributes, block + 0x7F8, 3, 1, 0x20);
    let file = guest::read64(handle);
    guest::write32(flags, 0xAAAA);
    guest::write8(level, 0xBB);
    let get = |file: u64, flags: u64, level: u64| status("ZwGetCachedSigningLevel", &[file, flags, level, thumbprint, size, algorithm]);
    let get_absent = code_integrity::signing_callback(SigningCallback::GetFileCache) == 0;
    assert(
        file != 0 && get(file, 0, level) == 0xC000_000D && get(file, flags, 0) == 0xC000_000D && get(0, flags, level) == 0xC000_000D && get(0x7FF0, flags, level) == 0xC000_0008,
        "se-signing: ZwGetCachedSigningLevel valida os ponteiros antes do handle e recusa handle invalido",
    );
    assert(!get_absent || (get(file, flags, level) == 0xC000_0001 && guest::read32(flags) == 0xAAAA && guest::read8(level) == 0xBB), "se-signing: sem a CI o arquivo aberto da STATUS_UNSUCCESSFUL sem tocar nas saidas");
    let set_absent = code_integrity::signing_callback(SigningCallback::SetFileCache) == 0;
    guest::write64(block + 0x7E0, file);
    assert(!set_absent || (status("ZwSetCachedSigningLevel", &[4, 0, block + 0x7E0, 1, file]) == 0xC000_0001 && status("ZwSetCachedSigningLevel", &[1, 0x30, block + 0x7E0, 0, file]) == 0xC000_0001), "se-signing: sem a CI o ZwSetCachedSigningLevel da STATUS_UNSUCCESSFUL antes de validar");
    let _ = call("ZwClose", &[file]);
    guest::free_bytes(block);
}

// ---- Token: Rtl, ZwOpenProcessToken ---------------------------------------------

fn token_checks(assert: Assert) {
    let block = guest::alloc_bytes(0x100);
    guest::write_bytes(block, &[0; 0x100]);
    let (output, handle) = (block, block + 8);
    let system = kernel_bytes(&hex("010100000000000512000000"));
    let domain = kernel_bytes(&hex("010500000000000515000000010000000200000003000000f4010000"));
    // S-1-15-3-1 (internetClient): autoridade 15, primeira subautoridade 3.
    let capability = kernel_bytes(&hex("010200000000000f0300000001000000"));
    // ZwOpenProcessToken: o token primário do processo corrente (System).
    let opened = status("ZwOpenProcessToken", &[u64::MAX, 0xA, handle]);
    let token = guest::read64(handle);
    guest::write64(block + 0x10, 0x77);
    let invalid = status("ZwOpenProcessToken", &[0x7FF0, 0xA, block + 0x10]);
    assert(opened == 0 && token != 0 && invalid == 0xC000_0008 && guest::read64(block + 0x10) == 0x77, "zw-open-process-token: token do processo corrente e handle de processo invalido");
    // Em KernelMode o SeAccessCheck concede tudo: membro e capacidade sempre.
    let membership = |token: u64, sid: u64, flags: u64| {
        guest::write8(output, 0x55);
        (status("RtlCheckTokenMembershipEx", &[token, sid, flags, output]), guest::read8(output))
    };
    assert(membership(0, system, 0) == (0, 1) && membership(0, domain, 3) == (0, 1) && membership(token, domain, 0) == (0, 1), "rtl-token: RtlCheckTokenMembershipEx em modo kernel, pela identidade corrente e por handle");
    assert(membership(0, system, 4) == (0xC000_000D, 0) && membership(0x7FF0, system, 0) == (0xC000_0008, 0), "rtl-token: flags fora de 3 = STATUS_INVALID_PARAMETER; handle invalido devolvido do ZwDuplicateToken");
    let capability_check = |token: u64, sid: u64| {
        guest::write8(output, 0x55);
        (status("RtlCheckTokenCapability", &[token, sid, output]), guest::read8(output))
    };
    assert(capability_check(0, capability) == (0, 1) && capability_check(token, capability) == (0, 1) && capability_check(0, system) == (0xC000_000D, 0) && capability_check(0x7FF0, capability) == (0xC000_0008, 0), "rtl-token: RtlCheckTokenCapability exige SID de capacidade e duplica o handle");
    let _ = call("ZwClose", &[token]);
    for pointer in [system, domain, capability, block] {
        guest::free_bytes(pointer);
    }
}

// ---- LsaFreeReturnBuffer ------------------------------------------------------

fn lsa_return_buffer(assert: Assert) {
    use crate::ntos::ex::extension_host;
    use crate::ntos::se::extension_hosts;
    let host = extension_hosts::authorization_host();
    let installed = extension_host::get_extension_table(host).unwrap_or(0);
    if installed != 0 {
        let _ = extension_host::release_extension_table(host);
    }
    assert(host != 0 && (installed != 0 || status("LsaFreeReturnBuffer", &[0x1234]) == 0xC000_0002), "lsa: sem a extensao de autorizacao, STATUS_NOT_IMPLEMENTED");
    if installed != 0 {
        return;
    }
    // Extensão de teste (id 2, versão 1, 6 funções): a terceira devolve
    // o argumento com xor 0x12345678 (mov eax, ecx; xor eax, imm32; ret).
    let routine = super::executable_code::place(&[0x89, 0xC8, 0x35, 0x78, 0x56, 0x34, 0x12, 0xC3]);
    let table = guest::alloc_bytes(0x30);
    for index in 0..6 {
        guest::write64(table + index * 8, routine);
    }
    let registration = guest::alloc_bytes(0x40);
    guest::write_bytes(registration, &[0; 0x40]);
    guest::write16(registration, 2);
    guest::write16(registration + 2, 1);
    guest::write16(registration + 4, 6);
    guest::write64(registration + 8, table);
    guest::write64(registration + 0x10, registration + 0x30);
    let extension = registration + 0x38;
    let registered = status("ExRegisterExtension", &[extension, 0x1_0000, registration]);
    let freed = status("LsaFreeReturnBuffer", &[0xABCD_0000]);
    let _ = call("ExUnregisterExtension", &[guest::read64(extension)]);
    let after = status("LsaFreeReturnBuffer", &[0xABCD_0000]);
    assert(routine != 0 && registered == 0 && freed == 0xABCD_0000 ^ 0x1234_5678 && after == 0xC000_0002, "lsa: LsaFreeReturnBuffer chama a terceira funcao da tabela de autorizacao com o buffer");
    super::executable_code::release(routine);
    guest::free_bytes(table);
    guest::free_bytes(registration);
}

// ---- NtSetSecurityObject ------------------------------------------------------

fn nt_set_security_object(assert: Assert) {
    let block = guest::alloc_bytes(0x400);
    let output = block + 0x300;
    let attributes = super::phase6::object_attributes_for(block, "\\Registry\\Machine\\Software\\OpenNT-ntsetsecurity", 0x240);
    let _ = call("ZwCreateKey", &[output, 0xF003F, attributes, 0, 0, 1, 0]);
    let handle = guest::read64(output);
    let key = match crate::ntos::ob::handles::security::reference_kernel_handle(handle) {
        Ok(Ok(mut reference)) => {
            let pointer = reference.pointer;
            let _ = reference.release();
            pointer
        }
        _ => 0,
    };
    // SD self-relative com a DACL presente e nula.
    let descriptor = guest::alloc_bytes(nt::SecurityDescriptorRelative::SIZE);
    guest::write_bytes(descriptor, &[0; nt::SecurityDescriptorRelative::SIZE as usize]);
    let relative = at::<nt::SecurityDescriptorRelative>(descriptor);
    relative.revision.set(1);
    relative.control.set(0x8004);
    let set = |handle: u64, information: u64, descriptor: u64| status("NtSetSecurityObject", &[handle, information, descriptor]);
    assert(key != 0 && set(handle, 4, 0) == 0xC000_0005 && set(handle, 1, descriptor) == 0xC000_0079 && set(handle, 2, descriptor) == 0xC000_0079 && set(0x7FFF_FFF0, 4, descriptor) == 0xC000_0008, "ob-nt-set-security: em KernelMode valida como o ZwSetSecurityObject");
    let applied = set(handle, 4, descriptor);
    // O descritor gravado volta pelo ZwQuerySecurityObject (a chave guarda o
    // dela na hive, pelo método de segurança do tipo Key).
    let stored = guest::alloc_bytes(0x200);
    let needed = block + 0x380;
    let queried = status("ZwQuerySecurityObject", &[handle, 4, stored, 0x200, needed]);
    let text = guest::alloc_bytes(8);
    guest::write64(text, 0);
    let converted = if queried == 0 { status("SeConvertSecurityDescriptorToStringSecurityDescriptor", &[stored, 1, 4, text, 0]) } else { u32::MAX };
    let string = guest::read64(text);
    let sddl = if string != 0 { read_wide(string) } else { String::new() };
    if !(applied == 0 && queried == 0 && converted == 0 && sddl.starts_with("D:") && sddl.ends_with("NO_ACCESS_CONTROL")) {
        crate::debug_print!("[teste-se] NtSetSecurityObject {:#x} consulta {:#x} SDDL {:#x} '{}'", applied, queried, converted, sddl);
    }
    assert(applied == 0 && queried == 0 && converted == 0 && sddl.starts_with("D:") && sddl.ends_with("NO_ACCESS_CONTROL"), "ob-nt-set-security: DACL nula gravada e lida de volta pelo SDDL");
    free_pool(string);
    let _ = call("ZwDeleteKey", &[handle]);
    let _ = call("ZwClose", &[handle]);
    for pointer in [text, stored, descriptor, block] {
        guest::free_bytes(pointer);
    }
}

// ---- ALPC de modo kernel --------------------------------------------------------

fn alpc_kernel_security(assert: Assert) {
    let block = guest::alloc_bytes(0x800);
    guest::write_bytes(block, &[0; 0x800]);
    let (server_out, port_attributes, attribute, quality, reserve, sender_out, message) = (block + 0x300, block + 0x340, block + 0x400, block + 0x440, block + 0x460, block + 0x470, block + 0x500);
    let attributes = super::phase6::object_attributes_for(block, "\\OpenNtAlpcQw2", 0x200);
    at::<nt::AlpcPortAttributes>(port_attributes).max_message_length.set(0x200);
    let created = status("ZwAlpcCreatePort", &[server_out, attributes, port_attributes]);
    let port = guest::read64(server_out);
    assert(created == 0 && port != 0, "alpc-kernel: porta de servidor de kernel para os testes");
    // AlpcCreateSecurityContext: flags != 0 recusadas antes da porta; o QoS
    // do atributo (SecurityImpersonation, estático) e a thread corrente.
    let thread = crate::ntos::ps::process::get_current_thread();
    guest::write32(quality, nt::SecurityQualityOfService::SIZE as u32);
    guest::write32(quality + 4, 2);
    let security = at::<nt::AlpcSecurityAttr>(attribute);
    security.p_qos.set(quality);
    security.context_handle.set(0);
    let flags = status("AlpcCreateSecurityContext", &[port, thread, 1, attribute]);
    let invalid = status("AlpcCreateSecurityContext", &[0x7FF0, thread, 0, attribute]);
    let context = status("AlpcCreateSecurityContext", &[port, thread, 0, attribute]);
    let context_handle = security.context_handle.get();
    let deleted = status("ZwAlpcDeleteSecurityContext", &[port, 0, context_handle]);
    let again = status("ZwAlpcDeleteSecurityContext", &[port, 0, context_handle]);
    assert(flags == 0xC000_000D && invalid == 0xC000_0008 && context == 0 && context_handle != 0 && deleted == 0 && again != 0, "alpc-kernel: AlpcCreateSecurityContext publica o contexto da thread no atributo");
    // ZwAlpcDeleteResourceReserve: flags e bit 31 do ResourceId validados
    // antes da porta; reserva inexistente = STATUS_INVALID_HANDLE.
    let reserved = status("ZwAlpcCreateResourceReserve", &[port, 0, 0x80, reserve]);
    let identifier = guest::read64(reserve);
    let removed = status("ZwAlpcDeleteResourceReserve", &[port, 0, identifier]);
    let removed_again = status("ZwAlpcDeleteResourceReserve", &[port, 0, identifier]);
    assert(
        reserved == 0 && identifier & 0x8000_0000 != 0 && removed == 0 && removed_again == 0xC000_0008 && status("ZwAlpcDeleteResourceReserve", &[port, 1, identifier]) == 0xC000_000D && status("ZwAlpcDeleteResourceReserve", &[port, 0, 0x1234]) == 0xC000_000D && status("ZwAlpcDeleteResourceReserve", &[0x7FF0, 0, identifier]) == 0xC000_0008,
        "alpc-kernel: ZwAlpcDeleteResourceReserve remove a reserva uma vez",
    );
    // ZwAlpcOpenSenderProcess: handle inválido e MessageId sem mensagem
    // (o AlpcpLookupMessage devolve STATUS_INVALID_MESSAGE).
    at::<nt::PortMessage>(message).message_id.set(0x7777);
    guest::write64(sender_out, 0x99);
    let no_port = status("ZwAlpcOpenSenderProcess", &[sender_out, 0x7FF0, message, 0, 0x1000, 0]);
    let no_message = status("ZwAlpcOpenSenderProcess", &[sender_out, port, message, 0, 0x1000, 0]);
    assert(no_port == 0xC000_0008 && no_message == 0xC000_0702 && guest::read64(sender_out) == 0x99, "alpc-kernel: ZwAlpcOpenSenderProcess sem porta ou sem mensagem nao toca a saida");
    let _ = call("ZwClose", &[port]);
    guest::free_bytes(block);
}

// ---- ALPC: mensagens novas do lado servidor e a porta esperável ----------------

/// Um PORT_MESSAGE x64 de 4 bytes de dados com o Type e o MessageId dados.
fn short_message(at: u64, message_type: u16, id: u32, data: &[u8; 4]) {
    guest::write_bytes(at, &[0; 0x28]);
    guest::write16(at, 4);
    guest::write16(at + 2, 0x2C);
    guest::write16(at + 4, message_type);
    guest::write32(at + 0x18, id);
    guest::write_bytes(at + 0x28, data);
}

/// As mensagens novas na própria porta de conexão (o caminho do dwm.exe e do
/// win32k com a DwmApiPort), como o AlpcpSendMessage e o
/// AlpcpDispatchNewMessage do 19041: o LpcRequestPort chega como
/// LPC_DATAGRAM com o LPC_KERNELMODE_MESSAGE que o remetente pôs no Type
/// (0x8003); o envio sem RELEASE_MESSAGE nem SYNC_REQUEST é um LPC_REQUEST
/// com LPC_CONTINUATION_REQUIRED (0x2001) cuja resposta volta à mesma fila
/// como LPC_REPLY. Na porta esperável (WAITABLE_PORT) cada mensagem posta
/// libera o semáforo uma vez e a espera pelo handle consome uma liberação.
/// E o NtAlpcSetInformation das classes 1, 5, 7, 8 e 10.
fn alpc_kernel_new_messages(assert: Assert) {
    let block = guest::alloc_bytes(0x800);
    guest::write_bytes(block, &[0; 0x800]);
    let (server_out, port_attributes, timeout, length, message, receive) = (block + 0x300, block + 0x340, block + 0x3A0, block + 0x3A8, block + 0x400, block + 0x600);
    let attributes = super::phase6::object_attributes_for(block, "\\OpenNtAlpcWaitable", 0x200);
    let requested = at::<nt::AlpcPortAttributes>(port_attributes);
    requested.flags.set(0x4_0000);
    requested.max_message_length.set(0x200);
    let created = status("ZwAlpcCreatePort", &[server_out, attributes, port_attributes]);
    let port = guest::read64(server_out);
    assert(created == 0 && port != 0, "alpc-novas: porta de conexao esperavel de kernel");
    if created != 0 || port == 0 {
        guest::free_bytes(block);
        return;
    }
    let wait = || crate::ntos::ob::wait::ob_wait_for_single_object(port, 0, 0, false, timeout);
    let empty = wait();
    let object = match crate::ntos::alpc::port_reference::reference(port, 0, 0) {
        Ok(Ok(mut reference)) => {
            let pointer = reference.port.pointer;
            let _ = reference.release();
            pointer
        }
        _ => 0,
    };
    short_message(message, 0x8000, 0, b"DWMQ");
    let posted = status("LpcRequestPort", &[object, message]);
    let signaled = wait();
    let drained = wait();
    guest::write64(length, 0x200);
    let received = status("ZwAlpcSendWaitReceivePort", &[port, 0, 0, 0, receive, length, 0, timeout]);
    let datagram = (guest::read16(receive + 4), guest::read32(receive + 0x28), guest::read64(receive + 0x10));
    assert(
        empty == 0x102 && object != 0 && posted == 0 && signaled == 0 && drained == 0x102 && received == 0 && datagram == (0x8003, u32::from_le_bytes(*b"DWMQ"), crate::ntos::ps::process::get_current_thread_id()),
        "alpc-novas: LpcRequestPort na porta de conexao vira LPC_DATAGRAM com o bit de modo kernel, e a porta esperavel sinaliza uma vez por mensagem",
    );
    short_message(message, 0, 0, b"ASK?");
    let asked = status("ZwAlpcSendWaitReceivePort", &[port, 0, message, 0, 0, 0, 0, 0]);
    guest::write64(length, 0x200);
    let request = status("ZwAlpcSendWaitReceivePort", &[port, 0, 0, 0, receive, length, 0, timeout]);
    let (request_type, request_id) = (guest::read16(receive + 4), guest::read32(receive + 0x18));
    short_message(message, 0, request_id, b"ACK!");
    let replied = status("ZwAlpcSendWaitReceivePort", &[port, 0, message, 0, 0, 0, 0, 0]);
    guest::write64(length, 0x200);
    let reply = status("ZwAlpcSendWaitReceivePort", &[port, 0, 0, 0, receive, length, 0, timeout]);
    let answer = (guest::read16(receive + 4), guest::read32(receive + 0x18), guest::read32(receive + 0x28));
    let releases = (wait(), wait(), wait());
    assert(
        asked == 0 && request == 0 && request_type == 0x2001 && request_id != 0 && replied == 0 && reply == 0 && answer == (2, request_id, u32::from_le_bytes(*b"ACK!")) && releases == (0, 0, 0x102),
        "alpc-novas: o pedido do servidor a propria porta de conexao recebe a resposta como LPC_REPLY na mesma fila",
    );
    // NtAlpcSetInformation: a classe 1 muda só o ALLOW_LPC_REQUESTS (e exige
    // os 0x48 bytes e o Flags dentro de 0x3FF0000); a 5 aceita 16 bytes; a 7
    // sem lista não faz nada; a 8 e a 10 sem lista recusam.
    let information = block + 0x700;
    guest::write32(information, 0x2_0000);
    let class1 = status("ZwAlpcSetInformation", &[port, 1, information, 0x48]);
    let class1_size = status("ZwAlpcSetInformation", &[port, 1, information, 0x40]);
    guest::write32(information, 0x1);
    let class1_flags = status("ZwAlpcSetInformation", &[port, 1, information, 0x48]);
    let zone = status("ZwAlpcSetInformation", &[port, 5, information, 0x10]);
    let unregister = status("ZwAlpcSetInformation", &[port, 7, 0, 0]);
    guest::write32(information, 2);
    let adjust = status("ZwAlpcSetInformation", &[port, 8, information, 4]);
    let rundown = status("ZwAlpcSetInformation", &[port, 10, 0, 0]);
    assert(
        class1 == 0 && class1_size == 0xC000_0004 && class1_flags == 0xC000_000D && zone == 0 && unregister == 0 && adjust == 0xC000_000D && rundown == 0xC000_000D,
        "alpc-novas: NtAlpcSetInformation das classes 1, 5, 7, 8 e 10 como o 19041",
    );
    let _ = call("ZwClose", &[port]);
    guest::free_bytes(block);
}

// ---- Rastro LRPC (--trace-rpc) ---------------------------------------------------

/// O rastro do `--trace-rpc` decodifica as mensagens LRPC como o rpcrt4 19041
/// as monta (`alpc/rpc_trace/lrpc.rs`): o bind da interface do SCM (svcctl,
/// 367abb81-9844-35f1-ad32-98f038001003 v2.0) com os contextos 5 (NDR) e 6
/// (NDR64), o pedido do opnum 15 com o contexto 5 e o UUID de objeto, a
/// falha RPC_S_UNKNOWN_IF, a resposta e os tipos sem decodificação; e a linha
/// do pedido mostra a interface do bind, e a da falha o pedido a que ela
/// responde.
fn lrpc_trace_decoding(assert: Assert) {
    use crate::ntos::alpc::rpc_trace::{self, lrpc, Direction, Record};
    let put32 = |data: &mut Vec<u8>, offset: usize, value: u32| data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    let svcctl = [0x81, 0xBB, 0x7A, 0x36, 0x44, 0x98, 0xF1, 0x35, 0xAD, 0x32, 0x98, 0xF0, 0x38, 0x00, 0x10, 0x03];
    let object = [0x11u8; 16];
    let mut bind = alloc::vec![0u8; 0x48];
    put32(&mut bind, 0, 1);
    bind[0x0C..0x1C].copy_from_slice(&svcctl);
    bind[0x1C..0x1E].copy_from_slice(&2u16.to_le_bytes());
    put32(&mut bind, 0x20, 3);
    bind[0x24..0x26].copy_from_slice(&5u16.to_le_bytes());
    bind[0x26..0x28].copy_from_slice(&6u16.to_le_bytes());
    let mut request = alloc::vec![0u8; 0x48];
    put32(&mut request, 0x08, lrpc::FLAG_OBJECT);
    put32(&mut request, 0x0C, 0x21);
    put32(&mut request, 0x10, 5);
    put32(&mut request, 0x14, 15);
    request[0x30..0x40].copy_from_slice(&object);
    let mut fault = alloc::vec![0u8; 0x14];
    put32(&mut fault, 0, 2);
    put32(&mut fault, 0x08, 0x6B5);
    let mut response = alloc::vec![0u8; 0x20];
    put32(&mut response, 0, 3);
    put32(&mut response, 0x0C, 0x21);
    let mut callback = alloc::vec![0u8; 0x40];
    put32(&mut callback, 0, 9);
    let interface = lrpc::Interface { uuid: lrpc::Uuid(svcctl), major: 2, minor: 0 };
    let decoded = (lrpc::decode(&bind), lrpc::decode(&request), lrpc::decode(&fault), lrpc::decode(&response), lrpc::decode(&callback));
    assert(
        decoded
            == (
                Some(lrpc::Message::Bind { interface, syntaxes: 3, contexts: [Some(5), Some(6), None], status: 0 }),
                Some(lrpc::Message::Request { context: 5, opnum: 15, call: 0x21, flags: lrpc::FLAG_OBJECT, object: Some(lrpc::Uuid(object)) }),
                Some(lrpc::Message::Fault { status: 0x6B5 }),
                Some(lrpc::Message::Response { call: 0x21, flags: 0 }),
                Some(lrpc::Message::Other(9)),
            )
            && alloc::format!("{}", interface) == "367abb81-9844-35f1-ad32-98f038001003 v2.0"
            && lrpc::kind_name(9) == "callback",
        "rpc-trace: bind, pedido, falha, resposta e callback do LRPC decodificados",
    );
    assert(
        lrpc::decode(&request[..0x3F]).is_none() && lrpc::decode(&bind[..0x47]).is_none() && lrpc::decode(&[0u8; 7]).is_none(),
        "rpc-trace: pedido e bind menores que o minimo do servidor nao sao decodificados",
    );
    // A conversa por uma porta do \RPC Control (ponteiros fora de qualquer
    // porta real, soltos no fim).
    let (listener, client_port) = (0xFFFF_DEAD_0000_1000u64, 0xFFFF_DEAD_0000_2000u64);
    rpc_trace::port_created(listener, Some("\\RPC Control\\teste-rpc"));
    let to_server = |id: u32, data: &[u8], attributes: u32| rpc_trace::line(&Record { listener, client_port, client: 0x30, server: 0x40, message_type: 0x2001, id, attributes, data, ..Record::default() });
    let bound = to_server(7, &bind, 0x2000_0000);
    let called = to_server(8, &request, 0xA200_0000);
    let failed = rpc_trace::line(&Record { listener, client_port, client: 0x30, server: 0x40, direction: Direction::ToClient, message_type: 2, id: 8, data: &fault, ..Record::default() });
    let again = rpc_trace::line(&Record { listener, client_port, client: 0x30, server: 0x40, direction: Direction::ToClient, message_type: 2, id: 8, data: &fault, ..Record::default() });
    rpc_trace::client_closed(client_port);
    let unbound = to_server(9, &request, 0);
    rpc_trace::port_closed(listener);
    let unnamed = to_server(10, &request, 0);
    let message = alloc::format!("rpc-trace: linhas da conversa: {bound} | {called} | {failed} | {again} | {unbound} | {unnamed}");
    assert(
        bound == "[rpc] \\RPC Control\\teste-rpc pid 48 -> 64 LPC_REQUEST(0x2001) id 7 atrib 0x20000000 lrpc bind 367abb81-9844-35f1-ad32-98f038001003 v2.0 sintaxes 0x3 ctx 5,6"
            && called == "[rpc] \\RPC Control\\teste-rpc pid 48 -> 64 LPC_REQUEST(0x2001) id 8 atrib 0xa2000000 lrpc pedido 367abb81-9844-35f1-ad32-98f038001003 v2.0 opnum 15 objeto 11111111-1111-1111-1111-111111111111"
            && failed == "[rpc] \\RPC Control\\teste-rpc pid 48 <- 64 LPC_REPLY(0x2) id 8 atrib 0x0 lrpc falha 0x6b5 (367abb81-9844-35f1-ad32-98f038001003 v2.0 opnum 15)"
            && again == "[rpc] \\RPC Control\\teste-rpc pid 48 <- 64 LPC_REPLY(0x2) id 8 atrib 0x0 lrpc falha 0x6b5"
            && unbound.ends_with("id 9 atrib 0x0 lrpc pedido ctx 5 opnum 15 objeto 11111111-1111-1111-1111-111111111111")
            && unnamed == "[rpc] (sem nome) pid 48 -> 64 LPC_REQUEST(0x2001) id 10 atrib 0x0",
        &message,
    );
}

pub fn run(assert: Assert) {
    sddl_sid_strings(assert);
    sddl_descriptor_strings(assert);
    signing_levels(assert);
    token_checks(assert);
    lsa_return_buffer(assert);
    nt_set_security_object(assert);
    alpc_kernel_security(assert);
    alpc_kernel_new_messages(assert);
    lrpc_trace_decoding(assert);
}
