//! Autoteste dos exports que os minifiltros reais importam do ntoskrnl:
//! os caminhos lentos de push lock (ExfAcquirePushLockExclusive,
//! ExfAcquirePushLockShared, ExfReleasePushLock), PsSetCurrentThreadPrefetching,
//! IoGetSiloParameters, _i64tow_s, o PfFileInfoNotify do prefetcher e o
//! ZwQuerySystemInformation(SystemBasicInformation) de modo kernel, o
//! WmiQueryTraceInformation(FltIoNotifyRoutinesClass) e a largura dos
//! argumentos do RtlInitializeSid e do RtlSubAuthoritySid.
//! Cada teste chama o export pelo trampolim nativo (ABI MS x64); o registro
//! da interface do FileInfo no prefetcher é conferido com o FileInfo.sys
//! real no teste dos minifiltros (`test/minifilters.rs`).

use alloc::vec::Vec;

use crate::ntos::inc::{types as nt, NtStruct};
use crate::ntos::mm::guest_memory as guest;

type Assert = fn(bool, &str);

fn call(name: &str, arguments: &[u64]) -> u64 {
    super::phase6::call_export(name, arguments).unwrap_or(0xDEAD_DEAD_DEAD_DEAD)
}

fn at<T: NtStruct>(address: u64) -> &'static T {
    // SAFETY: blocos alocados pelo teste com o tamanho do tipo.
    unsafe { T::at(address) }
}

/// A palavra do push lock passa pelos estados do NT: livre (0), escritor
/// (1), um e dois leitores (0x11, 0x21) e livre de novo; o
/// ExfReleasePushLock escolhe o modo pela palavra.
fn push_lock_slow_paths(assert: Assert) {
    let lock = guest::alloc_bytes(8);
    guest::write64(lock, 0);
    let mut states = Vec::new();
    call("ExfAcquirePushLockExclusive", &[lock]);
    states.push(guest::read64(lock));
    call("ExfReleasePushLock", &[lock]);
    states.push(guest::read64(lock));
    call("ExfAcquirePushLockShared", &[lock]);
    states.push(guest::read64(lock));
    call("ExfAcquirePushLockShared", &[lock]);
    states.push(guest::read64(lock));
    call("ExfReleasePushLock", &[lock]);
    states.push(guest::read64(lock));
    call("ExfReleasePushLock", &[lock]);
    states.push(guest::read64(lock));
    guest::free_bytes(lock);
    assert(states == [1, 0, 0x11, 0x21, 0x11, 0], "minifilter-support: ExfAcquirePushLock* e ExfReleasePushLock pelo modo da palavra");
}

/// O bit Prefetching da thread corrente: cada troca devolve o anterior e o
/// PsIsCurrentThreadPrefetching o vê.
fn thread_prefetching(assert: Assert) {
    let first = call("PsSetCurrentThreadPrefetching", &[1]) & 0xFF;
    let set = call("PsIsCurrentThreadPrefetching", &[]) & 0xFF;
    let second = call("PsSetCurrentThreadPrefetching", &[0]) & 0xFF;
    let cleared = call("PsIsCurrentThreadPrefetching", &[]) & 0xFF;
    assert(first == 0 && set == 1 && second == 1 && cleared == 0, "minifilter-support: PsSetCurrentThreadPrefetching troca o bit e devolve o anterior");
}

/// IoGetSiloParameters: NULL sem extensão; com ela, FoExtPerTypeExtension[7].
fn silo_parameters(assert: Assert) {
    let file = guest::alloc_bytes(nt::FileObject::SIZE);
    guest::write_bytes(file, &alloc::vec![0u8; nt::FileObject::SIZE as usize]);
    let without = call("IoGetSiloParameters", &[file]);
    let extension = guest::alloc_bytes(nt::IopFileObjectExtension::SIZE);
    guest::write_bytes(extension, &alloc::vec![0u8; nt::IopFileObjectExtension::SIZE as usize]);
    let parameters = guest::alloc_bytes(0x20);
    at::<nt::IopFileObjectExtension>(extension).fo_ext_per_type_extension[7].set(parameters);
    at::<nt::FileObject>(file).file_object_extension.set(extension);
    let with = call("IoGetSiloParameters", &[file]);
    at::<nt::FileObject>(file).file_object_extension.set(0);
    for block in [parameters, extension, file] {
        guest::free_bytes(block);
    }
    assert(without == 0 && with == parameters, "minifilter-support: IoGetSiloParameters le FoExtPerTypeExtension[7]");
}

fn wide(address: u64) -> alloc::string::String {
    crate::ntos::rtl::guest_strings::read_wide_string(address)
}

/// _i64tow_s: base 10 com sinal, base 16 sem sinal (o negativo vira os 64
/// bits), ERANGE com Buffer[0] = 0 e EINVAL.
fn i64tow_s(assert: Assert) {
    let buffer = guest::alloc_bytes(0x100);
    let run = |value: i64, size: u64, radix: u64| -> (u32, alloc::string::String) {
        guest::write_bytes(buffer, &[0xAAu8; 0x80]);
        let errno = call("_i64tow_s", &[value as u64, buffer, size, radix]) as u32;
        (errno, wide(buffer))
    };
    let decimal = run(-1_234_567_890_123, 32, 10);
    let hexadecimal = run(0xABCDEF, 32, 16);
    let all_ones = run(-1, 32, 16);
    let exact = run(12345, 6, 10);
    let short = run(12345, 5, 10);
    let sign_only = run(-5, 2, 10);
    let bad_radix = run(7, 8, 1);
    let null = call("_i64tow_s", &[1, 0, 8, 10]) as u32;
    guest::free_bytes(buffer);
    assert(
        decimal == (0, "-1234567890123".into()) && hexadecimal == (0, "abcdef".into()) && all_ones == (0, "ffffffffffffffff".into()) && exact == (0, "12345".into()) && short == (34, "".into()) && sign_only == (34, "".into()) && bad_radix == (22, "".into()) && null == 22,
        "minifilter-support: _i64tow_s converte, recusa sem espaco (ERANGE) e base invalida (EINVAL)",
    );
}

/// PfFileInfoNotify: a versão, os números de sequência, a consulta de
/// estado, o tipo desconhecido, a retirada sem interface e as notificações
/// de log aceitas sem efeito.
fn file_info_notify(assert: Assert) {
    let notify = guest::alloc_bytes(0x40);
    let send = |version: u32, kind: u32, flags: u32| -> u32 {
        guest::write32(notify, version);
        guest::write32(notify + 4, kind);
        guest::write32(notify + 8, flags);
        call("PfFileInfoNotify", &[notify]) as u32
    };
    let bad_version = send(0xE, 7, 8);
    let first = send(0xF, 7, 8);
    let sequence = guest::read32(notify + 0x10);
    let second = send(0xF, 7, 8);
    let next = guest::read32(notify + 0x10);
    let state = send(0xF, 0xC, 8);
    let unknown = send(0xF, 0xD, 8);
    // Sem o FileInfo carregado nenhuma interface está registrada.
    let registered = crate::ntos::mm::prefetcher_file_info::registered_interface() != 0;
    let unregister = if registered { 0xC000_0225 } else { send(0xF, 0xB, 8) };
    let logged = send(0xF, 4, 1);
    guest::free_bytes(notify);
    assert(
        bad_version == 0xC000_000D && first == 0 && second == 0 && next == sequence.wrapping_add(1) && state == 0 && unknown == 0xC000_00BB && unregister == 0xC000_0225 && logged == 0,
        "minifilter-support: PfFileInfoNotify valida a versao, numera, consulta e recusa o tipo desconhecido",
    );
}

/// ZwQuerySystemInformation(SystemBasicInformation) de um chamador de modo
/// kernel (o FileInfo lê a memória física por ela): páginas de 4 KB, a
/// granularidade de 64 KB, a faixa de usuário e os processadores; buffer
/// curto dá STATUS_INFO_LENGTH_MISMATCH com o tamanho em ReturnLength.
fn system_basic_information(assert: Assert) {
    let buffer = guest::alloc_bytes(0x48);
    let returned = guest::alloc_bytes(8);
    let status = call("ZwQuerySystemInformation", &[0, buffer, 0x40, returned]) as u32;
    let basic = at::<nt::SystemBasicInformation>(buffer);
    let filled = basic.page_size.get() == 0x1000 && basic.allocation_granularity.get() == 0x10000 && basic.number_of_physical_pages.get() != 0 && basic.minimum_user_mode_address.get() == 0x1_0000 && basic.maximum_user_mode_address.get() == 0x7FFF_FFFE_FFFF && basic.number_of_processors.get() >= 1 && guest::read32(returned) == 0x40;
    guest::write32(returned, 0);
    let short = call("ZwQuerySystemInformation", &[0, buffer, 0x20, returned]) as u32;
    let needed = guest::read32(returned);
    guest::free_bytes(returned);
    guest::free_bytes(buffer);
    assert(status == 0 && filled && short == 0xC000_0004 && needed == 0x40, "minifilter-support: ZwQuerySystemInformation(SystemBasicInformation) em modo kernel");
}

/// RtlInitializeSid recebe a contagem como UCHAR e RtlSubAuthoritySid o
/// índice como ULONG: os bits altos dos registradores (lixo de quem chama,
/// como o clfs.sys carregado depois do FileInfo) não contam.
fn sid_argument_widths(assert: Assert) {
    let sid = guest::alloc_bytes(0x20);
    let authority = guest::alloc_bytes(8);
    guest::write_bytes(authority, &[0, 0, 0, 0, 0, 5]);
    let status = call("RtlInitializeSid", &[sid, authority, 0xFFFF_F801]) as u32;
    let header = guest::read_bytes(sid, 8);
    let sub_authority = call("RtlSubAuthoritySid", &[sid, 0xFFFF_FFFF_0000_0002]);
    guest::free_bytes(authority);
    guest::free_bytes(sid);
    assert(status == 0 && header == [1, 1, 0, 0, 0, 0, 0, 5] && sub_authority == sid + 8 + 8, "minifilter-support: RtlInitializeSid (UCHAR) e RtlSubAuthoritySid (ULONG) ignoram os bits altos");
}

/// WmiQueryTraceInformation(FltIoNotifyRoutinesClass): o endereço da
/// tabela de rotinas de notificação de E/S dos minifiltros (zerada sem
/// sessão de rastreamento), que o fltmgr.sys lê antes e depois de cada
/// callback; Length diferente de 8 é STATUS_INFO_LENGTH_MISMATCH.
fn flt_io_notify_routines(assert: Assert) {
    let buffer = guest::alloc_bytes(0x10);
    let returned = guest::alloc_bytes(8);
    guest::write64(buffer, 0);
    let status = call("WmiQueryTraceInformation", &[13, buffer, 8, returned, 0]) as u32;
    let table = guest::read64(buffer);
    let empty = table != 0 && guest::read_bytes(table, 0x30).iter().all(|&byte| byte == 0);
    let length = guest::read32(returned);
    let short = call("WmiQueryTraceInformation", &[13, buffer, 4, 0, 0]) as u32;
    guest::free_bytes(returned);
    guest::free_bytes(buffer);
    assert(status == 0 && empty && length == 8 && short == 0xC000_0004, "minifilter-support: WmiQueryTraceInformation(FltIoNotifyRoutinesClass) devolve a tabela de rotinas");
}

pub fn run(assert: Assert) {
    flt_io_notify_routines(assert);
    sid_argument_widths(assert);
    system_basic_information(assert);
    push_lock_slow_paths(assert);
    thread_prefetching(assert);
    silo_parameters(assert);
    i64tow_s(assert);
    file_info_notify(assert);
}
