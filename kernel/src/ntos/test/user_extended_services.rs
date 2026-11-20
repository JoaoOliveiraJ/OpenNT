//! Autotestes (fase 7) dos serviços de modo usuário que estendem os
//! clássicos: o NtReadFileScatter e o NtWriteFileGather num arquivo do
//! volume sem buffer intermediário, o NtCreateSectionEx e o
//! NtMapViewOfSectionEx com os parâmetros estendidos, e o
//! NtSetCachedSigningLevel(2) de modo usuário (com uma SeCiCallbacks de
//! teste quando a ci.dll não está carregada).

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{EventBasicInformation, Eprocess};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user::file_io::{self, OpenRequest};
use crate::ntos::ps::user::{memory, state};

type Assert = fn(bool, &str);
type Call<'a> = &'a dyn Fn(&str, u64, u64, u64, u64) -> u32;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_END_OF_FILE: u32 = 0xC000_0011;
const STATUS_CONFLICTING_ADDRESSES: u32 = 0xC000_0018;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_INVALID_PAGE_PROTECTION: u32 = 0xC000_0045;
const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;
const STATUS_INVALID_PARAMETER_5: u32 = 0xC000_00F3;
const STATUS_INVALID_PARAMETER_6: u32 = 0xC000_00F4;
const STATUS_MAPPED_ALIGNMENT: u32 = 0xC000_0220;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const SCATTER_FILE: &str = "\\??\\D:\\OPENNTSCATTER.BIN";

pub fn run(assert: Assert) {
    let Ok(block) = memory::map_user_region(0x4000) else {
        assert(false, "extended: memoria de usuario");
        return;
    };
    let rsp = block + 0x3000;
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map_or(u32::MAX, |handler| handler(a1, a2, a3, a4, rsp).unwrap_or(u32::MAX));
    scatter_gather(assert, block, rsp, &call);
    sections_ex(assert, block, rsp, &call);
    set_signing_level(assert, block, rsp, &call);
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

/// Os argumentos de pilha de NtReadFileScatter/NtWriteFileGather.
fn segment_arguments(rsp: u64, iosb: u64, segments: u64, length: u32, offset: u64, key: u64) {
    guest::write64(rsp + 0x28, iosb);
    guest::write64(rsp + 0x30, segments);
    guest::write64(rsp + 0x38, length as u64);
    guest::write64(rsp + 0x40, offset);
    guest::write64(rsp + 0x48, key);
}

/// NtWriteFileGather e NtReadFileScatter num arquivo do volume aberto sem
/// buffer intermediário e assíncrono: a escrita reúne as páginas na ordem
/// da lista, a leitura espalha, a leitura que cruza o fim devolve até ele e
/// a que começa no fim é STATUS_END_OF_FILE sem tocar o IO_STATUS_BLOCK; o
/// -1 da escrita vai ao fim; o evento sinalizado na conclusão; as recusas
/// do handle (síncrono, com buffer, sem o acesso), das páginas, do setor,
/// do ByteOffset nulo e da lista desalinhada.
fn scatter_gather(assert: Assert, block: u64, rsp: u64, call: Call) {
    let Ok(pages) = memory::map_user_region(0x6000) else {
        assert(false, "extended: paginas da lista");
        return;
    };
    let (out, iosb, offset, segments, event_out, info) = (block + 0x100, block + 0x110, block + 0x120, block + 0x140, block + 0x180, block + 0x190);
    let open = |access: u32, options: u32, disposition: u32| {
        guest::write64(out, 0);
        let status = file_io::open(out, SCATTER_FILE, iosb, disposition, &OpenRequest { access, share: 7, options, ..OpenRequest::default() }).unwrap_or(1);
        (status, guest::read64(out))
    };
    let set_segments = |list: &[u64]| {
        for (index, page) in list.iter().enumerate() {
            guest::write64(segments + index as u64 * 8, *page);
        }
    };
    let transfer = |name: &str, handle: u64, event: u64, length: u32, at: Option<u64>| {
        guest::write_bytes(iosb, &[0xEE; 16]);
        if let Some(at) = at {
            guest::write64(offset, at);
        }
        segment_arguments(rsp, iosb, segments, length, if at.is_some() { offset } else { 0 }, 0);
        call(name, handle, event, 0, 0)
    };
    // Um evento de notificação não sinalizado.
    guest::write64(rsp + 0x28, 0);
    let event_created = call("NtCreateEvent", event_out, 0x1F_0003, 0, 0);
    let event = guest::read64(event_out);
    let signaled = || {
        guest::write64(rsp + 0x28, 0);
        call("NtQueryEvent", event, 0, info, 8) == 0 && unsafe { EventBasicInformation::at(info) }.event_state.get() != 0
    };
    // GENERIC_READ | GENERIC_WRITE, FILE_NO_INTERMEDIATE_BUFFERING, assíncrono.
    let (created, file) = open(0xC000_0000, 8, 5);
    let (p0, p1, p2) = (pages, pages + 0x1000, pages + 0x2000);
    guest::write_bytes(p0, &[0xB2; 0x1000]);
    guest::write_bytes(p1, &[0xC3; 0x1000]);
    guest::write_bytes(p2, &[0xA1; 0x1000]);
    set_segments(&[p2, p0, p1, 0]);
    let gathered = transfer("NtWriteFileGather", file, event, 0x3000, Some(0));
    let gathered_iosb = (guest::read32(iosb), guest::read64(iosb + 8));
    let event_set = signaled();
    // Lê 0x1000..0x3000 em duas páginas na ordem inversa.
    let (q0, q1) = (pages + 0x3000, pages + 0x4000);
    guest::write_bytes(q0, &[0; 0x2000]);
    set_segments(&[q1, q0]);
    let scattered = transfer("NtReadFileScatter", file, 0, 0x2000, Some(0x1000));
    let scattered_iosb = (guest::read32(iosb), guest::read64(iosb + 8));
    let spread = guest::read_bytes(q1, 0x1000).iter().all(|&byte| byte == 0xB2) && guest::read_bytes(q0, 0x1000).iter().all(|&byte| byte == 0xC3);
    set_segments(&[q0, q1]);
    let crossing = transfer("NtReadFileScatter", file, 0, 0x2000, Some(0x2000));
    let crossing_iosb = (guest::read32(iosb), guest::read64(iosb + 8));
    let at_end = transfer("NtReadFileScatter", file, 0, 0x1000, Some(0x3000));
    let at_end_untouched = guest::read32(iosb) == 0xEEEE_EEEE;
    assert(
        event_created == 0 && created == 0 && gathered == 0 && gathered_iosb == (0, 0x3000) && event_set && scattered == 0 && scattered_iosb == (0, 0x2000) && spread
            && crossing == 0 && crossing_iosb == (0, 0x1000) && at_end == STATUS_END_OF_FILE && at_end_untouched,
        &alloc::format!("extended: NtWriteFileGather reune e NtReadFileScatter espalha as paginas da lista (evento {event_created:#x}, abertura {created:#x}, escrita {gathered:#x}/{gathered_iosb:x?}, sinalizado {event_set}, leitura {scattered:#x}/{scattered_iosb:x?}/{spread}, fim {crossing:#x}/{crossing_iosb:x?}, alem {at_end:#x}/{at_end_untouched})"),
    );
    // O -1 da escrita vai ao fim; a FileStandardInformation mostra 0x4000.
    set_segments(&[p0]);
    let appended = transfer("NtWriteFileGather", file, 0, 0x1000, Some(u64::MAX));
    let appended_iosb = (guest::read32(iosb), guest::read64(iosb + 8));
    guest::write64(rsp + 0x28, 5);
    let standard = call("NtQueryInformationFile", file, iosb, info, 24);
    let end_of_file = guest::read64(info + 8);
    // Recusas.
    set_segments(&[p0 + 0x10]);
    let unaligned_page = transfer("NtReadFileScatter", file, 0, 0x1000, Some(0));
    set_segments(&[p0, p1]);
    let unaligned_length = transfer("NtReadFileScatter", file, 0, 0x300, Some(0));
    let unaligned_offset = transfer("NtReadFileScatter", file, 0, 0x1000, Some(0x100));
    let no_offset = transfer("NtReadFileScatter", file, 0, 0x1000, None);
    let negative_offset = transfer("NtReadFileScatter", file, 0, 0x1000, Some(u64::MAX));
    guest::write64(offset, 0);
    segment_arguments(rsp, iosb, segments + 4, 0x1000, offset, 0);
    let unaligned_list = call("NtReadFileScatter", file, 0, 0, 0);
    segment_arguments(rsp, 0xFFFF_8000_0000_0000, segments, 0x1000, offset, 0);
    let bad_iosb = call("NtReadFileScatter", file, 0, 0, 0);
    let _ = state::close_user_handle(file, true, false);
    assert(
        appended == 0 && appended_iosb == (0, 0x1000) && standard == 0 && end_of_file == 0x4000 && unaligned_page == STATUS_INVALID_PARAMETER && unaligned_length == STATUS_INVALID_PARAMETER
            && unaligned_offset == STATUS_INVALID_PARAMETER && no_offset == STATUS_INVALID_PARAMETER && negative_offset == STATUS_INVALID_PARAMETER && unaligned_list == STATUS_DATATYPE_MISALIGNMENT && bad_iosb == STATUS_ACCESS_VIOLATION,
        &alloc::format!("extended: a escrita no fim e as recusas da lista, do setor e do ByteOffset ({appended:#x}/{appended_iosb:x?} tamanho {standard:#x}/{end_of_file:#x}, pagina {unaligned_page:#x}, setor {unaligned_length:#x}/{unaligned_offset:#x}, sem offset {no_offset:#x}, negativo {negative_offset:#x}, lista {unaligned_list:#x}, iosb {bad_iosb:#x})"),
    );
    // O handle: síncrono, com buffer, sem FILE_READ_DATA e sem escrita.
    let (_, synchronous) = open(0xC010_0000, 0x28, 1);
    let synchronous_read = transfer("NtReadFileScatter", synchronous, 0, 0x1000, Some(0));
    let _ = state::close_user_handle(synchronous, true, false);
    let (_, buffered) = open(0xC000_0000, 0, 1);
    let buffered_read = transfer("NtReadFileScatter", buffered, 0, 0x1000, Some(0));
    let _ = state::close_user_handle(buffered, true, false);
    let (_, write_only) = open(0x4000_0000, 8, 1);
    let write_only_read = transfer("NtReadFileScatter", write_only, 0, 0x1000, Some(0));
    let _ = state::close_user_handle(write_only, true, false);
    let (_, read_only) = open(0x8000_0000, 8, 1);
    let read_only_write = transfer("NtWriteFileGather", read_only, 0, 0x1000, Some(0));
    let _ = state::close_user_handle(read_only, true, false);
    let _ = state::close_user_handle(event, true, false);
    assert(
        synchronous_read == STATUS_INVALID_PARAMETER && buffered_read == STATUS_INVALID_PARAMETER && write_only_read == STATUS_ACCESS_DENIED && read_only_write == STATUS_ACCESS_DENIED,
        &alloc::format!("extended: a lista de paginas pede arquivo assincrono sem buffer e o acesso de leitura ou escrita (sincrono {synchronous_read:#x}, com buffer {buffered_read:#x}, so escrita {write_only_read:#x}, so leitura {read_only_write:#x})"),
    );
    if let Some(region) = memory::find_region(pages) {
        memory::release_private_region(&region);
    }
}

/// Um MEM_EXTENDED_PARAMETER em `at`.
fn parameter(at: u64, kind: u64, value: u64) {
    guest::write64(at, kind);
    guest::write64(at + 8, value);
}

/// NtCreateSectionEx com os parâmetros de seção (UserPhysicalFlags e
/// NumaNode) e NtMapViewOfSectionEx com AddressRequirements, NumaNode e
/// AttributeFlags: as faixas aceitas e as recusas do vetor, dos tipos, do
/// nó e da faixa, a granularidade da base e do deslocamento e o
/// MEM_REPLACE_PLACEHOLDER sem placeholder.
fn sections_ex(assert: Assert, block: u64, rsp: u64, call: Call) {
    let (out, size, parameters, requirements, base, view_size, view_offset) = (block + 0x400, block + 0x408, block + 0x440, block + 0x4C0, block + 0x4E0, block + 0x4E8, block + 0x4F0);
    // NtCreateSectionEx(out, SECTION_ALL_ACCESS, NULL, &size, protect,
    // attributes, file, parameters, count).
    let create = |protect: u32, attributes: u32, file: u64, list: u64, count: u64| {
        guest::write64(out, 0);
        guest::write64(size, 0x2_0000);
        guest::write64(rsp + 0x28, protect as u64);
        guest::write64(rsp + 0x30, attributes as u64);
        guest::write64(rsp + 0x38, file);
        guest::write64(rsp + 0x40, list);
        guest::write64(rsp + 0x48, count);
        let status = call("NtCreateSectionEx", out, 0xF_001F, 0, size);
        (status, guest::read64(out))
    };
    let (plain, section) = create(4, 0x0800_0000, 0, 0, 0);
    parameter(parameters, 2, 0);
    let (node_zero, node_section) = create(4, 0x0800_0000, 0, parameters, 1);
    let _ = state::close_user_handle(node_section, true, false);
    parameter(parameters, 2, 1);
    let node_one = create(4, 0x0800_0000, 0, parameters, 1).0;
    parameter(parameters, 2, 0xFFFF_FFFF);
    let node_all = create(4, 0x0800_0000, 0, parameters, 1).0;
    parameter(parameters, 3, 0);
    let wrong_type = create(4, 0x0800_0000, 0, parameters, 1).0;
    parameter(parameters, 0x102, 0);
    let reserved_bits = create(4, 0x0800_0000, 0, parameters, 1).0;
    parameter(parameters, 2, 0);
    parameter(parameters + 0x10, 2, 0);
    let repeated = create(4, 0x0800_0000, 0, parameters, 2).0;
    let null_vector = create(4, 0x0800_0000, 0, 0, 1).0;
    let stray_vector = create(4, 0x0800_0000, 0, parameters, 0).0;
    let unaligned_vector = create(4, 0x0800_0000, 0, parameters + 4, 1).0;
    let node_bits = create(4, 0x0800_0001, 0, 0, 0).0;
    parameter(parameters, 1, 2);
    let physical_value = create(4, 0x0400_0000, 0, parameters, 1).0;
    parameter(parameters, 1, 1);
    let physical_commit = create(4, 0x0800_0000, 0, parameters, 1).0;
    let physical_readonly = create(2, 0x0400_0000, 0, parameters, 1).0;
    assert(
        plain == 0 && node_zero == 0 && node_one == STATUS_INVALID_PARAMETER && node_all == STATUS_INVALID_PARAMETER && wrong_type == STATUS_INVALID_PARAMETER && reserved_bits == STATUS_INVALID_PARAMETER
            && repeated == STATUS_INVALID_PARAMETER && null_vector == STATUS_INVALID_PARAMETER && stray_vector == STATUS_INVALID_PARAMETER && unaligned_vector == STATUS_DATATYPE_MISALIGNMENT
            && node_bits == STATUS_INVALID_PARAMETER && physical_value == STATUS_INVALID_PARAMETER && physical_commit == STATUS_INVALID_PARAMETER && physical_readonly == STATUS_INVALID_PAGE_PROTECTION,
        &alloc::format!("extended: NtCreateSectionEx captura UserPhysicalFlags e NumaNode como o 19041 ({plain:#x} {node_zero:#x} no {node_one:#x}/{node_all:#x} tipo {wrong_type:#x}/{reserved_bits:#x}/{repeated:#x} vetor {null_vector:#x}/{stray_vector:#x}/{unaligned_vector:#x} bits {node_bits:#x} fisica {physical_value:#x}/{physical_commit:#x}/{physical_readonly:#x})"),
    );
    // NtMapViewOfSectionEx(section, process, base*, offset*, viewSize*,
    // allocation, protect, parameters, count).
    let map = |at: u64, offset: u64, allocation: u32, list: u64, count: u64| {
        guest::write64(base, at);
        guest::write64(view_size, 0x1_0000);
        guest::write64(view_offset, offset);
        guest::write64(rsp + 0x28, view_size);
        guest::write64(rsp + 0x30, allocation as u64);
        guest::write64(rsp + 0x38, 4);
        guest::write64(rsp + 0x40, list);
        guest::write64(rsp + 0x48, count);
        let status = call("NtMapViewOfSectionEx", section, u64::MAX, base, view_offset);
        let view = guest::read64(base);
        if status == 0 {
            let _ = call("NtUnmapViewOfSection", u64::MAX, view, 0, 0);
        }
        (status, view)
    };
    let requirements_of = |lowest: u64, highest: u64, alignment: u64| {
        guest::write64(requirements, lowest);
        guest::write64(requirements + 8, highest);
        guest::write64(requirements + 0x10, alignment);
        parameter(parameters, 1, requirements);
    };
    let (unbounded, _) = map(0, 0, 0, 0, 0);
    requirements_of(0x2_0000_0000, 0x2_FFFF_FFFF, 0);
    let (bounded, bounded_view) = map(0, 0, 0, parameters, 1);
    requirements_of(0x2_0000_0000, 0x2_FFFF_FFFF, 0x1_0000);
    let with_alignment = map(0, 0, 0, parameters, 1).0;
    requirements_of(0x2_0000_1000, 0x2_FFFF_FFFF, 0);
    let unaligned_lowest = map(0, 0, 0, parameters, 1).0;
    requirements_of(0x2_0000_0000, 0x2_0000_0000, 0);
    let ragged_highest = map(0, 0, 0, parameters, 1).0;
    requirements_of(0x2_0000_0000, 0x2_0000_7FFF, 0);
    let too_small = map(0, 0, 0, parameters, 1).0;
    requirements_of(0x2_0000_0000, 0, 0);
    let with_base = map(0x3_0000_0000, 0, 0, parameters, 1).0;
    let misaligned_offset = map(0, 0x1000, 0, 0, 0).0;
    let misaligned_base = map(0x3_0000_1000, 0, 0, 0, 0).0;
    parameter(parameters, 5, 1);
    let graphics_flag = map(0, 0, 0, parameters, 1).0;
    parameter(parameters, 5, 0x20);
    let soft_fault = map(0, 0, 0, parameters, 1).0;
    parameter(parameters, 3, u64::MAX);
    let partition = map(0, 0, 0, parameters, 1).0;
    parameter(parameters, 2, 0);
    let node = map(0, 0, 0, parameters, 1).0;
    let numa_allocation = map(0, 0, 1, 0, 0).0;
    let placeholder = map(0x3_0000_0000, 0, 0x4000, 0, 0).0;
    let _ = state::close_user_handle(section, true, false);
    assert(
        unbounded == 0 && bounded == 0 && (0x2_0000_0000..0x3_0000_0000).contains(&bounded_view) && with_alignment == STATUS_INVALID_PARAMETER && unaligned_lowest == STATUS_INVALID_PARAMETER
            && ragged_highest == STATUS_INVALID_PARAMETER && too_small == STATUS_INVALID_PARAMETER && with_base == STATUS_INVALID_PARAMETER && misaligned_offset == STATUS_MAPPED_ALIGNMENT
            && misaligned_base == STATUS_MAPPED_ALIGNMENT && graphics_flag == STATUS_INVALID_PARAMETER && soft_fault == 0 && partition == STATUS_INVALID_PARAMETER && node == 0
            && numa_allocation == STATUS_INVALID_PARAMETER && placeholder == STATUS_CONFLICTING_ADDRESSES,
        &alloc::format!("extended: NtMapViewOfSectionEx com a faixa de enderecos, o no e as flags (livre {unbounded:#x}, faixa {bounded:#x}@{bounded_view:#x}, alinhamento {with_alignment:#x}, minimo {unaligned_lowest:#x}, maximo {ragged_highest:#x}/{too_small:#x}, base {with_base:#x}, granularidade {misaligned_offset:#x}/{misaligned_base:#x}, flags {graphics_flag:#x}/{soft_fault:#x}, particao {partition:#x}, no {node:#x}/{numa_allocation:#x}, placeholder {placeholder:#x})"),
    );
}

/// A rotina de teste do SetFileCache: grava os oito argumentos em
/// `record` (+0x00..+0x38), o primeiro handle da cópia (+0x40) e o Length
/// do caminho capturado (+0x48), e devolve 0x1234.
fn recorder(record: u64) -> alloc::vec::Vec<u8> {
    let mut code = alloc::vec![0x48, 0xB8];
    code.extend_from_slice(&record.to_le_bytes());
    code.extend_from_slice(&[
        0x48, 0x89, 0x08, // mov [rax], rcx
        0x48, 0x89, 0x50, 0x08, // mov [rax+8], rdx
        0x4C, 0x89, 0x40, 0x10, // mov [rax+0x10], r8
        0x4C, 0x89, 0x48, 0x18, // mov [rax+0x18], r9
        0x4C, 0x8B, 0x54, 0x24, 0x28, // mov r10, [rsp+0x28]
        0x4C, 0x89, 0x50, 0x20, // mov [rax+0x20], r10
        0x4D, 0x8B, 0x1A, // mov r11, [r10]
        0x4C, 0x89, 0x58, 0x40, // mov [rax+0x40], r11
        0x4C, 0x8B, 0x54, 0x24, 0x30, // mov r10, [rsp+0x30]
        0x4C, 0x89, 0x50, 0x28, // mov [rax+0x28], r10
        0x4C, 0x8B, 0x54, 0x24, 0x38, // mov r10, [rsp+0x38]
        0x4C, 0x89, 0x50, 0x30, // mov [rax+0x30], r10
        0x4C, 0x8B, 0x54, 0x24, 0x40, // mov r10, [rsp+0x40]
        0x4C, 0x89, 0x50, 0x38, // mov [rax+0x38], r10
        0x4D, 0x85, 0xD2, // test r10, r10
        0x74, 0x08, // jz +8
        0x45, 0x0F, 0xB7, 0x1A, // movzx r11d, word [r10]
        0x4C, 0x89, 0x58, 0x48, // mov [rax+0x48], r11
        0xB8, 0x34, 0x12, 0x00, 0x00, // mov eax, 0x1234
        0xC3, // ret
    ]);
    code
}

/// NtSetCachedSigningLevel(2) de modo usuário. Sem a ci.dll o slot nulo
/// dá STATUS_UNSUCCESSFUL; com a SeCiCallbacks de teste, as recusas dos
/// níveis, das flags e da contagem, a cópia dos handles e o que a CI
/// recebe (as flags com a 1 ligada, UserMode, os níveis, a cópia, a
/// contagem, o alvo e o caminho capturado), o processo não PPL
/// (STATUS_ACCESS_DENIED) e, num processo PPL, o nível dele ou o das seções
/// pelo CompareSigningLevels.
fn set_signing_level(assert: Assert, block: u64, rsp: u64, call: Call) {
    use crate::ntos::se::code_integrity::{self, SigningCallback};
    let (sources, information, path, record, accept) = (block + 0xA00, block + 0xA40, block + 0xA80, block + 0xB00, block + 0xB80);
    const TARGET: u64 = 0x1234_5678;
    let set = |flags: u64, level: u64, list: u64, count: u64, target: u64| {
        guest::write64(rsp + 0x28, target);
        call("NtSetCachedSigningLevel", flags, level, list, count)
    };
    let set2 = |flags: u64, level: u64, list: u64, count: u64, target: u64, cache: u64| {
        guest::write64(rsp + 0x28, target);
        guest::write64(rsp + 0x30, cache);
        call("NtSetCachedSigningLevel2", flags, level, list, count)
    };
    guest::write64(sources, TARGET);
    if code_integrity::signing_callback(SigningCallback::SetFileCache) != 0 {
        // A ci.dll real: só a recusa da flag 2, antes de qualquer handle.
        assert(set(2, 0, sources, 1, TARGET) == STATUS_INVALID_PARAMETER_1, "extended: NtSetCachedSigningLevel recusa a flag 2 do modo usuario");
        return;
    }
    let without_ci = set(4, 0xC, sources, 1, TARGET);
    let recorder_code = crate::ntos::test::executable_code::place(&recorder(record));
    // CompareSigningLevels: o ULONG em `accept`.
    let mut compare_code = alloc::vec![0x48, 0xB8];
    compare_code.extend_from_slice(&accept.to_le_bytes());
    compare_code.extend_from_slice(&[0x8B, 0x00, 0xC3]);
    let compare_code = crate::ntos::test::executable_code::place(&compare_code);
    let Some(table) = (recorder_code != 0 && compare_code != 0).then(|| code_integrity::install_test_signing_callbacks(recorder_code, compare_code)).flatten() else {
        assert(false, "extended: SeCiCallbacks de teste");
        return;
    };
    guest::write_bytes(record, &[0; 0x50]);
    let target_only = set(4, 0xC, sources, 1, TARGET);
    let recorded: alloc::vec::Vec<u64> = (0..10).map(|index| guest::read64(record + index * 8)).collect();
    let copied = recorded[4] != sources && recorded[8] == TARGET;
    let target_arguments = recorded[0] == 5 && recorded[1] == 1 && recorded[2] == 0xC && recorded[3] == 0 && recorded[5] == 1 && recorded[6] == TARGET && recorded[7] == 0;
    let flag_two = set(2, 0, sources, 1, TARGET);
    let flags_both = set(3, 0, sources, 1, TARGET);
    let level_bits = set(4, 0x30, sources, 1, TARGET);
    let level_without_flag = set(0, 1, sources, 1, TARGET);
    let no_sources = set(4, 0, sources, 0, TARGET);
    let too_many = set(4, 0, sources, 0x1001, TARGET);
    let two_sources = set(4, 0, sources, 2, TARGET);
    let other_target = set(4, 0, sources, 1, TARGET + 4);
    let unaligned_sources = set(4, 0, sources + 4, 1, TARGET);
    // SE_SET_FILE_CACHE_INFORMATION { Size, CatalogDirectoryPath }.
    state::write_user_wide(path, "C:\\CATALOGO");
    guest::write32(information, 0x18);
    state::write_unicode_string(information + 8, path, "C:\\CATALOGO");
    guest::write_bytes(record, &[0; 0x50]);
    let with_path = set2(4, 0, sources, 1, TARGET, information);
    let captured_length = guest::read64(record + 0x48);
    let captured_pointer = guest::read64(record + 0x38);
    guest::write32(information, 0x10);
    let short_information = set2(4, 0, sources, 1, TARGET, information);
    guest::write32(information, 0x18);
    guest::write16(information + 8, 21);
    let odd_path = set2(4, 0, sources, 1, TARGET, information);
    let unaligned_information = set2(4, 0, sources, 1, TARGET, information + 2);
    // Sem a flag 4: o processo não PPL é recusado; num PPL, o nível dele
    // ou o das seções.
    // SAFETY: o processo corrente do autoteste.
    let process = unsafe { Eprocess::at(crate::ntos::ps::process::get_current_process()) };
    let not_light = process.protection.type_() != 1;
    let unprotected = set(0, 0, sources, 1, TARGET);
    let saved = (process.protection.level.get(), process.signature_level.get(), process.section_signature_level.get());
    process.protection.level.set(0x61);
    process.signature_level.set(0x0C);
    process.section_signature_level.set(0x08);
    guest::write32(accept, 1);
    let accepted = set(0, 0, sources, 1, TARGET);
    let accepted_level = guest::read64(record + 0x18);
    guest::write32(accept, 0);
    let refused = set(0, 0, sources, 1, TARGET);
    let refused_level = guest::read64(record + 0x18);
    process.protection.level.set(saved.0);
    process.signature_level.set(saved.1);
    process.section_signature_level.set(saved.2);
    code_integrity::remove_test_signing_callbacks(table);
    crate::ntos::test::executable_code::release(recorder_code);
    crate::ntos::test::executable_code::release(compare_code);
    assert(
        without_ci == STATUS_UNSUCCESSFUL && target_only == 0x1234 && copied && target_arguments && flag_two == STATUS_INVALID_PARAMETER_1 && flags_both == STATUS_INVALID_PARAMETER_1
            && level_bits == STATUS_INVALID_PARAMETER_2 && level_without_flag == STATUS_INVALID_PARAMETER_2 && no_sources == STATUS_INVALID_PARAMETER_4 && too_many == STATUS_INVALID_PARAMETER_4
            && two_sources == STATUS_INVALID_PARAMETER_4 && other_target == STATUS_INVALID_PARAMETER_5 && unaligned_sources == STATUS_DATATYPE_MISALIGNMENT,
        &alloc::format!("extended: NtSetCachedSigningLevel de modo usuario passa a CI os argumentos do 19041 e recusa os parametros (sem CI {without_ci:#x}, alvo {target_only:#x}/{copied}/{target_arguments} {recorded:x?}, flags {flag_two:#x}/{flags_both:#x}, nivel {level_bits:#x}/{level_without_flag:#x}, contagem {no_sources:#x}/{too_many:#x}/{two_sources:#x}, alvo {other_target:#x}, alinhamento {unaligned_sources:#x})"),
    );
    assert(
        with_path == 0x1234 && captured_length == 22 && captured_pointer != 0 && captured_pointer != information + 8 && short_information == STATUS_INVALID_PARAMETER_6 && odd_path == STATUS_INVALID_PARAMETER
            && unaligned_information == STATUS_DATATYPE_MISALIGNMENT && (!not_light || unprotected == STATUS_ACCESS_DENIED) && accepted == 0x1234 && accepted_level == 0x0C && refused == 0x1234 && refused_level == 0x08,
        &alloc::format!("extended: NtSetCachedSigningLevel2 captura o caminho do catalogo e o nivel do processo PPL ({with_path:#x}/{captured_length}/{captured_pointer:#x}, curto {short_information:#x}, impar {odd_path:#x}, alinhamento {unaligned_information:#x}, sem PPL {unprotected:#x}, PPL {accepted:#x}/{accepted_level:#x} {refused:#x}/{refused_level:#x})"),
    );
}

