//! NtCopyFileChunk e as classes 46/74 do NtQueryInformationFile e 74 do
//! NtSetInformationFile nos arquivos do volume do kernel (fase 7), como o
//! CopyFile do kernelbase (BaseCopyStream) os usa: cópia em pedaços com a
//! origem síncrona e a assíncrona, offsets, a posição do arquivo síncrono,
//! as recusas de acesso e de parâmetros, FileHardLinkInformation e
//! FileStorageReserveIdInformation.

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user::file_io::{self, OpenRequest};
use crate::ntos::ps::user::memory;
use crate::ntos::ps::user::state;

type Assert = fn(bool, &str);

const SIZE: u64 = 3 * 4096 + 100;
const SOURCE: &str = "\\??\\D:\\OPENNTCPYSRC.BIN";
const DESTINATION: &str = "\\??\\D:\\OPENNTCPYDST.BIN";

fn pattern(index: u64) -> u8 {
    (index * 7 + 3) as u8
}

pub fn run(assert: Assert) {
    let Ok(block) = memory::map_user_region(0x1_0000) else {
        assert(false, "copychunk: memoria de usuario");
        return;
    };
    let (out, iosb, offsets, rsp, info, data) = (block, block + 0x10, block + 0x20, block + 0x800, block + 0x1000, block + 0x2000);
    let open = |name: &str, disposition: u32, access: u32, options: u32| {
        guest::write64(out, 0);
        let status = file_io::open(out, name, iosb, disposition, &OpenRequest { access, share: 7, options, ..OpenRequest::default() }).unwrap_or(1);
        (status, guest::read64(out))
    };
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map(|handler| handler(a1, a2, a3, a4, rsp).unwrap_or(1)).unwrap_or(1);
    let close = |handle: u64| {
        let _ = state::close_user_handle(handle, true, false);
    };
    // A origem com o padrão.
    let bytes: alloc::vec::Vec<u8> = (0..SIZE).map(pattern).collect();
    let (created, writer) = open(SOURCE, 2, 0xC010_0000, 0x20);
    guest::write_bytes(data, &bytes);
    guest::write64(rsp + 0x28, iosb);
    guest::write64(rsp + 0x30, data);
    guest::write32(rsp + 0x38, SIZE as u32);
    guest::write64(rsp + 0x40, 0);
    guest::write64(rsp + 0x48, 0);
    let written = call("NtWriteFile", writer, 0, 0, 0);
    close(writer);
    assert(created == 0 && written == 0, "copychunk: origem criada com o padrao");
    let (_, source_sync) = open(SOURCE, 1, 0x8010_0000, 0x20);
    let (_, source_async) = open(SOURCE, 1, 0x8000_0000, 0);
    let (dst_created, destination) = open(DESTINATION, 2, 0x4010_0000, 0x20);
    assert(dst_created == 0 && source_sync != 0 && source_async != 0, "copychunk: aberturas da origem e do destino");
    // NtCopyFileChunk(src, dst, event, iosb, length, &so, &do, 0, 0, flags).
    let chunk_with = |source: u64, destination: u64, event: u64, length: u32, source_offset: Option<i64>, destination_offset: Option<i64>, flags: u32, io_status: u64| {
        if let Some(offset) = source_offset {
            guest::write64(offsets, offset as u64);
        }
        if let Some(offset) = destination_offset {
            guest::write64(offsets + 8, offset as u64);
        }
        guest::write32(iosb, 0x103);
        guest::write64(iosb + 8, 0);
        guest::write64(rsp + 0x28, length as u64);
        guest::write64(rsp + 0x30, if source_offset.is_some() { offsets } else { 0 });
        guest::write64(rsp + 0x38, if destination_offset.is_some() { offsets + 8 } else { 0 });
        guest::write64(rsp + 0x40, 0);
        guest::write64(rsp + 0x48, 0);
        guest::write64(rsp + 0x50, flags as u64);
        call("NtCopyFileChunk", source, destination, event, io_status)
    };
    let chunk = |source: u64, destination: u64, event: u64, length: u32, source_offset: i64, destination_offset: i64| chunk_with(source, destination, event, length, Some(source_offset), Some(destination_offset), 0, iosb);
    let information = || guest::read64(iosb + 8);
    let iosb_status = || guest::read32(iosb);
    let contents = |handle: u64, offset: u64, length: u64| file_io::volume_open(handle).ok().and_then(|(_, file)| file.file.read_at(offset, length).ok());
    let size_of = |handle: u64| file_io::volume_open(handle).map_or(u64::MAX, |(_, file)| file.file.size());
    let position = |handle: u64| {
        guest::write64(rsp + 0x28, 14);
        if call("NtQueryInformationFile", handle, iosb, info, 8) == 0 { guest::read64(info) } else { u64::MAX }
    };
    // 1. Cópia em pedaços; no fim, STATUS_END_OF_FILE sem tocar no IOSB.
    let mut pieces = true;
    for (index, expected) in [4096u64, 4096, 4096, 100].into_iter().enumerate() {
        let offset = index as i64 * 4096;
        pieces &= chunk(source_sync, destination, 0, 4096, offset, offset) == 0 && information() == expected;
    }
    let end = chunk(source_sync, destination, 0, 4096, 4 * 4096, 4 * 4096) == 0xC000_0011 && iosb_status() == 0x103;
    let copied = size_of(destination) == SIZE && contents(destination, 0, SIZE).is_some_and(|read| read == bytes);
    assert(pieces && end && copied, "copychunk: copia em varios pedacos");
    // 2. Offsets de origem e destino; a leitura corta no fim do arquivo.
    let shifted = chunk(source_sync, destination, 0, 1000, 500, SIZE as i64 + 24) == 0 && information() == 1000;
    let shifted_ok = size_of(destination) == SIZE + 1024 && contents(destination, SIZE + 24, 1000).is_some_and(|read| read[..] == bytes[500..1500]);
    let clipped = chunk(source_sync, destination, 0, 4096, SIZE as i64 - 10, 0) == 0 && information() == 10;
    assert(shifted && shifted_ok && clipped, "copychunk: origem e destino com offset");
    // 3. A posição da origem síncrona e FILE_USE_FILE_POINTER_POSITION.
    let after_clip = position(source_sync) == SIZE;
    let moved = chunk(source_sync, destination, 0, 100, 1000, 0) == 0 && position(source_sync) == 1100;
    let current = chunk(source_sync, destination, 0, 50, -2, 0) == 0 && information() == 50 && contents(destination, 0, 50).is_some_and(|read| read[..] == bytes[1100..1150]) && position(source_sync) == 1150;
    let destination_position = position(destination) == 50;
    assert(after_clip && moved && current && destination_position, "copychunk: posicao do arquivo sincrono");
    // 4. Origem assíncrona: STATUS_PENDING com o IOSB e o evento concluídos;
    //    no fim do arquivo, o evento fica zerado e o IOSB intocado.
    guest::write64(rsp + 0x28, 0);
    let event_created = call("NtCreateEvent", out + 8, 0x1F_0003, 0, 0) == 0;
    let event = guest::read64(out + 8);
    let event_state = || {
        guest::write64(rsp + 0x28, 0);
        if call("NtQueryEvent", event, 0, info, 8) == 0 { guest::read32(info + 4) } else { u32::MAX }
    };
    let pending = chunk(source_async, destination, event, 4096, 0, 0) == 0x103 && iosb_status() == 0 && information() == 4096 && event_state() == 1;
    let async_end = chunk(source_async, destination, event, 4096, SIZE as i64, 0) == 0xC000_0011 && iosb_status() == 0x103 && event_state() == 0;
    assert(event_created && pending && async_end, "copychunk: origem assincrona devolve STATUS_PENDING com o evento");
    // 5. Acesso: origem sem FILE_READ_DATA, destino sem escrita; destino só
    //    com FILE_APPEND_DATA escreve no fim.
    let (_, no_read) = open(SOURCE, 1, 0x10_0080, 0x20);
    let (_, no_write) = open(DESTINATION, 1, 0x8010_0000, 0x20);
    let (_, append) = open(DESTINATION, 1, 0x10_0004, 0x20);
    let read_denied = chunk(no_read, destination, 0, 16, 0, 0) == 0xC000_0022;
    let write_denied = chunk(source_sync, no_write, 0, 16, 0, 0) == 0xC000_0022;
    let before = size_of(destination);
    let appended = chunk(source_sync, append, 0, 16, 0, 0) == 0 && size_of(destination) == before + 16 && contents(destination, before, 16).is_some_and(|read| read[..] == bytes[..16]);
    close(no_read);
    close(no_write);
    close(append);
    assert(read_denied && write_denied && appended, "copychunk: recusas de acesso");
    // 6. Parâmetros inválidos.
    let flags = chunk_with(source_sync, destination, 0, 16, Some(0), Some(0), 1, iosb) == 0xC000_000D;
    guest::write64(rsp + 0x28, 16);
    guest::write64(rsp + 0x30, offsets + 2);
    guest::write64(rsp + 0x38, offsets + 8);
    guest::write64(rsp + 0x40, 0);
    guest::write64(rsp + 0x48, 0);
    guest::write64(rsp + 0x50, 0);
    let misaligned = call("NtCopyFileChunk", source_sync, destination, 0, iosb) == 0x8000_0002;
    let no_source_offset = chunk_with(source_sync, destination, 0, 16, None, Some(0), 0, iosb) == 0xC000_0005;
    let no_destination_offset = chunk_with(source_sync, destination, 0, 16, Some(0), None, 0, iosb) == 0xC000_000D;
    let negative_destination = chunk(source_sync, destination, 0, 16, 0, -5) == 0xC000_000D;
    let negative_source = chunk(source_sync, destination, 0, 16, -5, 0) == 0xC000_000D;
    let bad_handle = chunk(0x7FF0, destination, 0, 16, 0, 0) == 0xC000_0008;
    let file_as_event = chunk(source_async, destination, destination, 16, 0, 0) == 0xC000_0024;
    let no_iosb = chunk_with(source_sync, destination, 0, 16, Some(0), Some(0), 0, 0) == 0xC000_0005;
    assert(flags && misaligned && no_source_offset && no_destination_offset && negative_destination && negative_source && bad_handle && file_as_event && no_iosb, "copychunk: parametros invalidos");
    // 7. FileHardLinkInformation: o nome na raiz do volume.
    let (_, attributes) = open(DESTINATION, 1, 0x10_0080, 0x20);
    let links = |length: u64| {
        guest::write64(rsp + 0x28, 46);
        call("NtQueryInformationFile", attributes, iosb, info, length)
    };
    let name: alloc::vec::Vec<u16> = "OPENNTCPYDST.BIN".encode_utf16().collect();
    let full = links(0x100) == 0 && guest::read32(info) == 64 && guest::read32(info + 4) == 1 && guest::read32(info + 8) == 0 && guest::read32(info + 8 + 0x10) == 16 && (0..name.len()).all(|index| guest::read16(info + 8 + 0x14 + index as u64 * 2) == name[index]) && information() == 64;
    let overflow = links(40) == 0x8000_0005 && guest::read32(info) == 64 && guest::read32(info + 4) == 0 && information() == 8;
    let short = links(16) == 0xC000_0004;
    assert(full && overflow && short, "copychunk: FileHardLinkInformation");
    // 8. FileStorageReserveIdInformation: consulta e mudança.
    let reserve = |handle: u64, length: u64| {
        guest::write64(rsp + 0x28, 74);
        guest::write_bytes(info, &[0xAA; 16]);
        call("NtQueryInformationFile", handle, iosb, info, length)
    };
    let queried = reserve(attributes, 16) == 0 && information() == 16 && guest::read_bytes(info, 16) == [0u8; 16];
    let queried_short = reserve(attributes, 4) == 0 && information() == 4;
    let (_, write_only) = open(DESTINATION, 1, 0x10_0002, 0x20);
    let query_denied = reserve(write_only, 16) == 0xC000_0022;
    let (_, writer) = open(DESTINATION, 1, 0xC010_0000, 0x20);
    let set = |handle: u64, id: u32, flags: u32, length: u64| {
        guest::write32(info, id);
        guest::write32(info + 4, flags);
        guest::write64(rsp + 0x28, 74);
        call("NtSetInformationFile", handle, iosb, info, length)
    };
    let set_ok = set(writer, 0, 0, 8) == 0 && set(writer, 2, 0, 8) == 0xC000_04AE && set(writer, 16, 0, 8) == 0xC000_04AD && set(writer, 0, 0x10, 8) == 0xC000_00BB && set(writer, 0, 0, 2) == 0xC000_0004;
    let set_denied = set(attributes, 0, 0, 8) == 0xC000_0022;
    close(write_only);
    close(writer);
    close(attributes);
    assert(queried && queried_short && query_denied && set_ok && set_denied, "copychunk: FileStorageReserveIdInformation");
    // 9. Limpeza.
    let _ = call("NtClose", event, 0, 0, 0);
    close(source_sync);
    close(source_async);
    close(destination);
    for name in [SOURCE, DESTINATION] {
        let (status, handle) = open(name, 1, 0x8011_0000, 0x1020);
        if status == 0 {
            close(handle);
        }
    }
    let gone = open(SOURCE, 1, 0x8010_0000, 0x20).0 == 0xC000_0034 && open(DESTINATION, 1, 0x8010_0000, 0x20).0 == 0xC000_0034;
    assert(gone, "copychunk: arquivos apagados");
}
