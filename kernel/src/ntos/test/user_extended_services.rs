//! Autotestes (fase 7) dos serviços de modo usuário que estendem os
//! clássicos: o NtReadFileScatter e o NtWriteFileGather num arquivo do
//! volume sem buffer intermediário, o NtCreateSectionEx e o
//! NtMapViewOfSectionEx com os parâmetros estendidos, e o
//! NtSetCachedSigningLevel(2) de modo usuário (com uma SeCiCallbacks de
//! teste quando a ci.dll não está carregada), o NtExtendSection e o
//! NtSetVolumeInformationFile, e as recusas dos serviços AWE.

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
const EXTEND_FILE: &str = "\\??\\D:\\OPENNTEXTEND.BIN";
const STATUS_SECTION_TOO_BIG: u32 = 0xC000_0040;
const STATUS_SECTION_NOT_EXTENDED: u32 = 0xC000_0087;

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
    extend_section(assert, block, rsp, &call);
    set_volume_information(assert, block, rsp, &call);
    user_physical_pages(assert, block, rsp, &call);
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

/// NtExtendSection numa seção de dados de um arquivo do volume: um tamanho
/// menor volta como o SizeOfSection; um maior estende o arquivo e a seção
/// (NtQuerySection, FileStandardInformation e uma vista da seção inteira);
/// a seção só leitura cresce até o arquivo e não além dele; a seção sem
/// arquivo, o tamanho acima do máximo, o handle sem SECTION_EXTEND_SIZE e o
/// ponteiro desalinhado são recusados.
fn extend_section(assert: Assert, block: u64, rsp: u64, call: Call) {
    let (out, iosb, cells, data, info) = (block + 0xC00, block + 0xC10, block + 0xC40, block + 0x1000, block + 0xD00);
    guest::write64(out, 0);
    let created = file_io::open(out, EXTEND_FILE, iosb, 5, &OpenRequest { access: 0xC010_0000, share: 7, options: 0x20, ..OpenRequest::default() }).unwrap_or(1);
    let file = guest::read64(out);
    guest::write_bytes(data, &[0x5A; 0x1800]);
    guest::write64(rsp + 0x28, iosb);
    guest::write64(rsp + 0x30, data);
    guest::write32(rsp + 0x38, 0x1800);
    guest::write64(rsp + 0x40, 0);
    guest::write64(rsp + 0x48, 0);
    let written = call("NtWriteFile", file, 0, 0, 0);
    // NtCreateSection(handle*, access, NULL, size*, protect, SEC_COMMIT, file).
    let create = |access: u64, size: u64, protect: u64, file: u64| {
        guest::write64(cells, 0);
        guest::write64(cells + 8, size);
        guest::write64(rsp + 0x28, protect);
        guest::write64(rsp + 0x30, 0x0800_0000);
        guest::write64(rsp + 0x38, file);
        let status = call("NtCreateSection", cells, access, 0, if size != 0 || file == 0 { cells + 8 } else { 0 });
        (status, guest::read64(cells))
    };
    let extend = |section: u64, size: u64| {
        guest::write64(cells + 0x10, size);
        let status = call("NtExtendSection", section, cells + 0x10, 0, 0);
        (status, guest::read64(cells + 0x10))
    };
    // O SizeOfSection pelo objeto (o MaximumSize do NtQuerySection).
    let maximum = |section: u64| {
        use crate::ntos::mm::section::handles::{self as section_handles, Kind};
        match section_handles::reference(section, Kind::Section, 0, 0) {
            Ok(reference) => {
                let size = reference.section.as_ref().map_or(u64::MAX, |section| section.maximum_size());
                let _ = reference.release();
                size
            }
            Err(status) => 0xDEAD_0000_0000_0000 | status as u64,
        }
    };
    let end_of_file = || {
        guest::write64(rsp + 0x28, 5);
        if call("NtQueryInformationFile", file, iosb, info, 24) == 0 { guest::read64(info + 8) } else { u64::MAX }
    };
    let (section_created, section) = create(0xF_001F, 0, 4, file);
    let initial = maximum(section);
    let smaller = extend(section, 0x1000);
    let larger = extend(section, 0x5000);
    let grown = maximum(section);
    let file_grown = end_of_file();
    // A vista da seção inteira depois de crescer: NtMapViewOfSection(section,
    // process, base*, 0, 0, offset*, viewSize*, ViewUnmap, 0, PAGE_READWRITE).
    guest::write64(cells + 0x18, 0);
    guest::write64(cells + 0x20, 0);
    guest::write64(cells + 0x28, 0);
    guest::write64(rsp + 0x28, 0);
    guest::write64(rsp + 0x30, cells + 0x28);
    guest::write64(rsp + 0x38, cells + 0x20);
    guest::write64(rsp + 0x40, 2);
    guest::write64(rsp + 0x48, 0);
    guest::write64(rsp + 0x50, 4);
    let mapped = call("NtMapViewOfSection", section, u64::MAX, cells + 0x18, 0);
    let (view, view_size) = (guest::read64(cells + 0x18), guest::read64(cells + 0x20));
    let (first, last) = if mapped == 0 { (guest::try_read::<u8>(view).map_or(0x100, u32::from), guest::try_read::<u8>(view + 0x4FFF).map_or(0x100, u32::from)) } else { (0x200, 0x200) };
    let contents = (first, last) == (0x5A, 0);
    if mapped == 0 {
        let _ = call("NtUnmapViewOfSection", u64::MAX, view, 0, 0);
    }
    let shrink = extend(section, 0x3000);
    let too_big = extend(section, 0x40_0000_0000_0000);
    guest::write64(cells + 0x30, 0x6000);
    let misaligned = call("NtExtendSection", section, cells + 0x2E, 0, 0);
    let _ = state::close_user_handle(section, true, false);
    assert(
        created == 0 && written == 0 && section_created == 0 && initial == 0x1800 && smaller == (0, 0x1800) && larger == (0, 0x5000) && grown == 0x5000 && file_grown == 0x5000
            && mapped == 0 && view_size == 0x5000 && contents && shrink == (0, 0x5000) && too_big == (STATUS_SECTION_TOO_BIG, 0x40_0000_0000_0000) && misaligned == STATUS_DATATYPE_MISALIGNMENT,
        &alloc::format!("extended: NtExtendSection estende o arquivo e a secao (abertura {created:#x}/{written:#x}, secao {section_created:#x}, inicial {initial:#x}, menor {smaller:x?}, maior {larger:x?}, consulta {grown:#x}, arquivo {file_grown:#x}, vista {mapped:#x}/{view_size:#x}/{first:#x}/{last:#x}, de novo {shrink:x?}, grande {too_big:x?}, alinhamento {misaligned:#x})"),
    );
    // Só leitura: cresce até o arquivo (0x5000), não além.
    let (read_only_created, read_only) = create(0xF_001F, 0x1000, 2, file);
    let within = extend(read_only, 0x3000);
    let beyond = extend(read_only, 0x6000).0;
    let _ = state::close_user_handle(read_only, true, false);
    // SECTION_QUERY | SECTION_MAP_READ, sem SECTION_EXTEND_SIZE.
    let (query_created, query_only) = create(0x5, 0, 2, file);
    let denied = extend(query_only, 0x6000).0;
    let _ = state::close_user_handle(query_only, true, false);
    let (pagefile_created, pagefile) = create(0xF_001F, 0x1000, 4, 0);
    let pagefile_extend = extend(pagefile, 0x2000).0;
    let _ = state::close_user_handle(pagefile, true, false);
    let final_size = end_of_file();
    let _ = state::close_user_handle(file, true, false);
    assert(
        read_only_created == 0 && within == (0, 0x3000) && beyond == STATUS_SECTION_NOT_EXTENDED && query_created == 0 && denied == STATUS_ACCESS_DENIED && pagefile_created == 0
            && pagefile_extend == STATUS_SECTION_NOT_EXTENDED && final_size == 0x5000,
        &alloc::format!("extended: NtExtendSection recusa a secao so leitura alem do arquivo, o handle sem SECTION_EXTEND_SIZE e a secao sem arquivo (so leitura {read_only_created:#x}/{within:x?}/{beyond:#x}, acesso {query_created:#x}/{denied:#x}, sem arquivo {pagefile_created:#x}/{pagefile_extend:#x}, arquivo {final_size:#x})"),
    );
}

/// NtSetVolumeInformationFile: as recusas do I/O Manager (classe, tamanho,
/// alinhamento, IO_STATUS_BLOCK, acesso, VolumeLabelLength) e a resposta
/// do file system a um arquivo que não é a abertura do volume
/// (STATUS_ACCESS_DENIED); na abertura do volume `\??\D:`, o rótulo novo
/// (visto pelo FileFsVolumeInformation e no VPB) e as recusas do
/// NtfsSetFsLabelInfo, o FileFsControlInformation e o
/// FileFsDataCopyInformation recusados, e o ObjectId do volume gravado e
/// lido pelo FileFsObjectIdInformation, trocado por outro.
fn set_volume_information(assert: Assert, block: u64, rsp: u64, call: Call) {
    let (out, iosb, buffer, query) = (block + 0xE00, block + 0xE10, block + 0xE40, block + 0xEC0);
    let open = |name: &str, access: u32, share: u32| {
        guest::write64(out, 0);
        let status = file_io::open(out, name, iosb, 1, &OpenRequest { access, share, options: 0x20, ..OpenRequest::default() }).unwrap_or(1);
        (status, guest::read64(out))
    };
    let set = |handle: u64, at: u64, length: u64, class: u64| {
        guest::write_bytes(iosb, &[0xEE; 16]);
        guest::write64(rsp + 0x28, class);
        call("NtSetVolumeInformationFile", handle, iosb, at, length)
    };
    let label = |text: &str| {
        let units: alloc::vec::Vec<u8> = text.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
        guest::write32(buffer, units.len() as u32);
        guest::write_bytes(buffer + 4, &units);
        4 + units.len() as u64
    };
    let volume_label = |handle: u64| {
        guest::write_bytes(query, &[0; 0x80]);
        guest::write64(rsp + 0x28, 1);
        let status = call("NtQueryVolumeInformationFile", handle, iosb, query, 0x80);
        let length = guest::read32(query + 12) as usize;
        let units: alloc::vec::Vec<u16> = guest::read_bytes(query + 18, length.min(0x60)).chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]])).collect();
        (status, alloc::string::String::from_utf16_lossy(&units))
    };
    // Um arquivo do volume (não a abertura do volume).
    let (file_opened, file) = open(SCATTER_FILE, 0xC010_0000, 7);
    let length = label("ARQUIVO");
    let not_volume = set(file, buffer, length, 2);
    let wrong_class = set(file, buffer, length, 1);
    let short = set(file, buffer, 4, 2);
    let unaligned = set(file, buffer + 2, length, 2);
    guest::write32(buffer, 0x100);
    let long_label = set(file, buffer, 8, 2);
    guest::write32(buffer, 0x8000_0000);
    let negative_label = set(file, buffer, 8, 2);
    let length = label("ARQUIVO");
    guest::write64(rsp + 0x28, 2);
    let bad_iosb = call("NtSetVolumeInformationFile", file, 0xFFFF_8000_0000_0000, buffer, length);
    let _ = state::close_user_handle(file, true, false);
    let (_, read_only) = open(SCATTER_FILE, 0x8010_0000, 7);
    let no_write = set(read_only, buffer, length, 2);
    let _ = state::close_user_handle(read_only, true, false);
    assert(
        file_opened == 0 && not_volume == STATUS_ACCESS_DENIED && wrong_class == 0xC000_0003 && short == 0xC000_0004 && unaligned == STATUS_DATATYPE_MISALIGNMENT && long_label == STATUS_INVALID_PARAMETER
            && negative_label == STATUS_INVALID_PARAMETER && bad_iosb == STATUS_ACCESS_VIOLATION && no_write == STATUS_ACCESS_DENIED,
        &alloc::format!("extended: NtSetVolumeInformationFile confere os parametros e recusa o arquivo que nao e o volume (abertura {file_opened:#x}, arquivo {not_volume:#x}, classe {wrong_class:#x}, curto {short:#x}, alinhamento {unaligned:#x}, rotulo {long_label:#x}/{negative_label:#x}, iosb {bad_iosb:#x}, so leitura {no_write:#x})"),
    );
    // A abertura do volume pelo file system, com escrita.
    let (volume_opened, volume) = open("\\??\\D:", 0xC010_0000, 3);
    let (original_status, original) = volume_label(volume);
    let length = label("OPENNTVOL");
    let relabeled = set(volume, buffer, length, 2);
    let relabeled_iosb = guest::read32(iosb);
    let (_, new_label) = volume_label(volume);
    let vpb_label = crate::drivers::fs::volume_device::vpb_label(crate::drivers::fs::ntfs::DEVICE_INDEX);
    let too_long = set(volume, buffer, label("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFG"), 2);
    guest::write32(buffer, 5);
    let odd = set(volume, buffer, 12, 2);
    let restored = set(volume, buffer, label(&original), 2);
    let (_, restored_label) = volume_label(volume);
    guest::write_bytes(buffer, &[0; 0x40]);
    let control = set(volume, buffer, 0x30, 6);
    let data_copy = set(volume, buffer, 4, 10);
    assert(
        volume_opened == 0 && original_status == 0 && relabeled == 0 && relabeled_iosb == 0 && new_label == "OPENNTVOL" && vpb_label.as_deref() == Some("OPENNTVOL") && too_long == 0xC000_0086 && odd == 0xC000_0086
            && restored == 0 && restored_label == original && control == STATUS_INVALID_PARAMETER && data_copy == STATUS_INVALID_PARAMETER,
        &alloc::format!("extended: NtSetVolumeInformationFile troca o rotulo do volume (abertura {volume_opened:#x}, original {original_status:#x}/{original:?}, novo {relabeled:#x}/{relabeled_iosb:#x}/{new_label:?}/{vpb_label:?}, longo {too_long:#x}, impar {odd:#x}, de volta {restored:#x}/{restored_label:?}, controle {control:#x}, copia {data_copy:#x})"),
    );
    // O ObjectId do volume.
    let object_id = |handle: u64| {
        guest::write_bytes(query, &[0; 0x40]);
        guest::write64(rsp + 0x28, 8);
        let status = call("NtQueryVolumeInformationFile", handle, iosb, query, 0x40);
        (status, guest::read_bytes(query, 0x40))
    };
    let (absent, _) = object_id(volume);
    let first: alloc::vec::Vec<u8> = (0..0x40u8).map(|byte| byte.wrapping_mul(7).wrapping_add(1)).collect();
    guest::write_bytes(buffer, &first);
    let stored = set(volume, buffer, 0x40, 8);
    let (read_status, read) = object_id(volume);
    let second: alloc::vec::Vec<u8> = (0..0x40u8).map(|byte| byte.wrapping_mul(13).wrapping_add(5)).collect();
    guest::write_bytes(buffer, &second);
    let replaced = set(volume, buffer, 0x40, 8);
    let (replaced_status, replaced_read) = object_id(volume);
    let _ = state::close_user_handle(volume, true, false);
    assert(
        absent == 0xC000_0034 && stored == 0 && read_status == 0 && read == first && replaced == 0 && replaced_status == 0 && replaced_read == second,
        &alloc::format!("extended: NtSetVolumeInformationFile grava o ObjectId do volume ($OBJECT_ID e $O) e o FileFsObjectIdInformation o le (ausente {absent:#x}, gravado {stored:#x}, lido {read_status:#x}/{}, trocado {replaced:#x}/{replaced_status:#x}/{})", read == first, replaced_read == second),
    );
}

/// Os serviços AWE: as checagens do 19041 antes da AweInfo (zero páginas, o
/// tamanho, as sondas, os parâmetros estendidos do Ex, a seção que não é
/// AWE, o handle) e, sem AweInfo nem VAD AWE no OpenNT, o
/// STATUS_PRIVILEGE_NOT_HELD da alocação, o STATUS_INVALID_PARAMETER_1 da
/// liberação (com o NumberOfPages zerado) e dos mapeamentos.
fn user_physical_pages(assert: Assert, block: u64, rsp: u64, call: Call) {
    const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    let (count, pfns, parameters, addresses, cells) = (block + 0x2C00, block + 0x2C40, block + 0x2C80, block + 0x2CC0, block + 0x2D00);
    let allocate = |handle: u64, pages: u64, array: u64| {
        guest::write64(count, pages);
        call("NtAllocateUserPhysicalPages", handle, count, array, 0)
    };
    let allocate_ex = |kind: u64, value: u64| {
        guest::write64(count, 2);
        parameter(parameters, kind, value);
        guest::write64(rsp + 0x28, 1);
        call("NtAllocateUserPhysicalPagesEx", u64::MAX, count, pfns, parameters)
    };
    let zero = allocate(u64::MAX, 0, pfns);
    let allocated = allocate(u64::MAX, 4, pfns);
    let huge = allocate(u64::MAX, 0x2000_0000_0000_0000, pfns);
    let unaligned = allocate(u64::MAX, 4, pfns + 4);
    let bad_count = call("NtAllocateUserPhysicalPages", u64::MAX, 0xFFFF_8000_0000_0000, pfns, 0);
    let graphics = allocate_ex(5, 1);
    let both = allocate_ex(5, 0xA);
    let partition = allocate_ex(3, u64::MAX);
    let node = allocate_ex(2, 1);
    let nonpaged = allocate_ex(5, 2);
    // Uma seção de pagefile não é AWE.
    guest::write64(cells + 8, 0x1000);
    guest::write64(rsp + 0x28, 4);
    guest::write64(rsp + 0x30, 0x0800_0000);
    guest::write64(rsp + 0x38, 0);
    let section_created = call("NtCreateSection", cells, 0xF_001F, 0, cells + 8);
    let section = guest::read64(cells);
    let not_awe = allocate(section, 4, pfns);
    let _ = state::close_user_handle(section, true, false);
    let bad_handle = allocate(0x7FF8, 4, pfns);
    assert(
        zero == 0 && allocated == STATUS_PRIVILEGE_NOT_HELD && huge == STATUS_INVALID_PARAMETER_2 && unaligned == STATUS_DATATYPE_MISALIGNMENT && bad_count == STATUS_ACCESS_VIOLATION
            && graphics == STATUS_INVALID_PARAMETER && both == STATUS_INVALID_PARAMETER && partition == STATUS_INVALID_PARAMETER && node == STATUS_INVALID_PARAMETER && nonpaged == STATUS_PRIVILEGE_NOT_HELD
            && section_created == 0 && not_awe == STATUS_INVALID_HANDLE && bad_handle == STATUS_INVALID_HANDLE,
        &alloc::format!("extended: NtAllocateUserPhysicalPages(Ex) confere os parametros e o handle antes da AweInfo (zero {zero:#x}, quatro {allocated:#x}, grande {huge:#x}, alinhamento {unaligned:#x}, contagem {bad_count:#x}, ex {graphics:#x}/{both:#x}/{partition:#x}/{node:#x}/{nonpaged:#x}, secao {section_created:#x}/{not_awe:#x}, handle {bad_handle:#x})"),
    );
    guest::write64(count, 0);
    let free_zero = call("NtFreeUserPhysicalPages", u64::MAX, count, pfns, 0);
    guest::write64(count, 2);
    let free_some = call("NtFreeUserPhysicalPages", u64::MAX, count, pfns, 0);
    let free_count = guest::read64(count);
    guest::write64(count, 2);
    let free_bad_handle = call("NtFreeUserPhysicalPages", 0x7FF8, count, pfns, 0);
    let map_zero = call("NtMapUserPhysicalPages", 0x2_0000_0000, 0, 0, 0);
    let map_unmap = call("NtMapUserPhysicalPages", 0x2_0000_0000, 1, 0, 0);
    let map_unaligned = call("NtMapUserPhysicalPages", 0x2_0000_0000, 1, pfns + 4, 0);
    guest::write64(addresses, 0x2_0000_0000);
    let scatter_zero = call("NtMapUserPhysicalPagesScatter", addresses, 0, 0, 0);
    let scatter_one = call("NtMapUserPhysicalPagesScatter", addresses, 1, pfns, 0);
    let scatter_unaligned = call("NtMapUserPhysicalPagesScatter", addresses + 4, 1, 0, 0);
    assert(
        free_zero == STATUS_INVALID_PARAMETER_2 && free_some == STATUS_INVALID_PARAMETER_1 && free_count == 0 && free_bad_handle == STATUS_INVALID_HANDLE && map_zero == STATUS_INVALID_PARAMETER_2
            && map_unmap == STATUS_INVALID_PARAMETER_1 && map_unaligned == STATUS_DATATYPE_MISALIGNMENT && scatter_zero == 0 && scatter_one == STATUS_INVALID_PARAMETER_1 && scatter_unaligned == STATUS_DATATYPE_MISALIGNMENT,
        &alloc::format!("extended: NtFreeUserPhysicalPages e NtMapUserPhysicalPages(Scatter) sem AweInfo nem VAD AWE (liberacao {free_zero:#x}/{free_some:#x}/{free_count:#x}/{free_bad_handle:#x}, mapa {map_zero:#x}/{map_unmap:#x}/{map_unaligned:#x}, espalhado {scatter_zero:#x}/{scatter_one:#x}/{scatter_unaligned:#x})"),
    );
}
