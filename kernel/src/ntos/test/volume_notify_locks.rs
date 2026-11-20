//! Autotestes das travas de faixa de bytes nos arquivos do volume de boot
//! (NtLockFile/NtUnlockFile pelo I/O Manager, `io/file/irp_service.rs`; o
//! IRP_MJ_LOCK_CONTROL do file system embutido, `drivers/fs/volume_streams.rs`;
//! o FsRtl, `fsrtl/file_lock.rs`), pelos serviços de modo usuário no D: (o
//! mesmo volume do C: no boot do smss), contra o ntoskrnl e o ntfs.sys 19041:
//!
//! - exclusiva concedida e STATUS_LOCK_NOT_GRANTED para outro FILE_OBJECT;
//!   compartilhadas sobrepostas de donos diferentes;
//! - STATUS_FILE_LOCK_CONFLICT na leitura e na escrita (NtfsCommonRead
//!   0xee93, NtfsCommonWrite 0x1fc67);
//! - o pedido em espera (STATUS_PENDING) de um arquivo assíncrono, concedido
//!   pelo NtUnlockFile, com o IO_STATUS_BLOCK e o evento;
//! - STATUS_RANGE_NOT_LOCKED e o NtUnlockFile síncrono de um arquivo
//!   assíncrono;
//! - as recusas: acesso sem FILE_READ_DATA/FILE_WRITE_DATA, diretório,
//!   ByteOffset desalinhado e faixa que dá a volta;
//! - a faixa inteira do BaseDllOpenIniFileOnDisk do kernel32;
//! - o fechamento do handle solta as travas do processo (IopCloseFile);
//! - um handle de evento inválido é ignorado (0x656004).
//!
//! E a notificação de mudança de diretório (NtNotifyChangeDirectoryFile pelo
//! I/O Manager; o IRP_MN_NOTIFY_CHANGE_DIRECTORY do file system embutido,
//! `volume_streams::notify_change_directory`; o FsRtl Lite,
//! `fsrtl/notify.rs`), contra o ntfs.sys 19041:
//!
//! - o pedido pendente (STATUS_PENDING, o IO_STATUS_BLOCK intocado) e a
//!   criação que o conclui com FILE_ACTION_ADDED;
//! - a renomeação no mesmo diretório numa conclusão só (RENAMED_OLD_NAME e
//!   RENAMED_NEW_NAME);
//! - o relato guardado sem pedido pendente;
//! - WatchTree: o subdiretório só conta com ele, com o nome relativo;
//! - o NtCancelIoFileEx (STATUS_CANCELLED, depois STATUS_NOT_FOUND);
//! - o buffer curto (STATUS_NOTIFY_ENUM_DIR);
//! - a escrita relatada como FILE_ACTION_MODIFIED só no fechamento;
//! - o pedido num arquivo (STATUS_INVALID_PARAMETER) e o fechamento do
//!   diretório (STATUS_NOTIFY_CLEANUP).

use alloc::string::String;
use alloc::vec::Vec;

use crate::drivers::fs::volume_files;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types as nt;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user::{memory, state};

type Assert = fn(bool, &str);

const FILE: &str = "/OPENNTLK.TXT";

/// O bloco de usuário do teste: handle, IOSBs, a faixa, o OBJECT_ATTRIBUTES,
/// os argumentos de pilha e o buffer de dados.
struct Harness {
    block: u64,
}

impl Harness {
    const HANDLE: u64 = 0;
    const IOSB: u64 = 0x10;
    const ASYNC_IOSB: u64 = 0x20;
    /// ByteOffset em +0 e Length em +8.
    const RANGE: u64 = 0x40;
    const TIMEOUT: u64 = 0x58;
    const ATTRIBUTES: u64 = 0x100;
    const STRING: u64 = 0x140;
    const TEXT: u64 = 0x180;
    const STACK: u64 = 0x1000;
    const DATA: u64 = 0x2000;

    fn at(&self, offset: u64) -> u64 {
        self.block + offset
    }

    fn call(&self, name: &str, a1: u64, a2: u64, a3: u64, a4: u64) -> u32 {
        state::handler(name).map(|handler| handler(a1, a2, a3, a4, self.at(Self::STACK)).unwrap_or(1)).unwrap_or(1)
    }

    fn arguments(&self, values: &[u64]) {
        for (index, value) in values.iter().enumerate() {
            guest::write64(self.at(Self::STACK) + 0x28 + index as u64 * 8, *value);
        }
    }

    /// NtCreateFile(FILE_OPEN) de `name`: (status, handle).
    fn open(&self, name: &str, access: u32, share: u32, options: u32) -> (u32, u64) {
        state::write_user_wide(self.at(Self::TEXT), name);
        state::write_unicode_string(self.at(Self::STRING), self.at(Self::TEXT), name);
        // SAFETY: OBJECT_ATTRIBUTES no bloco de usuário do teste.
        let attributes = unsafe { nt::ObjectAttributes::at(self.at(Self::ATTRIBUTES)) };
        attributes.length.set(nt::ObjectAttributes::SIZE as u32);
        attributes.root_directory.set(0);
        attributes.object_name.set(self.at(Self::STRING));
        attributes.attributes.set(0x40);
        attributes.security_descriptor.set(0);
        attributes.security_quality_of_service.set(0);
        guest::write64(self.at(Self::HANDLE), 0);
        self.arguments(&[0, 0, share as u64, 1, options as u64, 0, 0]);
        let status = self.call("NtCreateFile", self.at(Self::HANDLE), access as u64, self.at(Self::ATTRIBUTES), self.at(Self::IOSB));
        (status, guest::read64(self.at(Self::HANDLE)))
    }

    fn close(&self, handle: u64) {
        let _ = self.call("NtClose", handle, 0, 0, 0);
    }

    /// NtLockFile com os ponteiros de ByteOffset e Length dados.
    #[allow(clippy::too_many_arguments)]
    fn lock_with(&self, handle: u64, event: u64, iosb: u64, offset: u64, length: u64, exclusive: bool, fail_immediately: bool) -> u32 {
        self.arguments(&[iosb, offset, length, 0, fail_immediately as u64, exclusive as u64]);
        self.call("NtLockFile", handle, event, 0, 0)
    }

    /// NtLockFile de [offset, offset + length) com Key 0.
    #[allow(clippy::too_many_arguments)]
    fn lock(&self, handle: u64, event: u64, iosb: u64, offset: u64, length: u64, exclusive: bool, fail_immediately: bool) -> u32 {
        guest::write64(self.at(Self::RANGE), offset);
        guest::write64(self.at(Self::RANGE) + 8, length);
        self.lock_with(handle, event, iosb, self.at(Self::RANGE), self.at(Self::RANGE) + 8, exclusive, fail_immediately)
    }

    /// NtUnlockFile de [offset, offset + length) com Key 0.
    fn unlock(&self, handle: u64, iosb: u64, offset: u64, length: u64) -> u32 {
        guest::write64(self.at(Self::RANGE), offset);
        guest::write64(self.at(Self::RANGE) + 8, length);
        self.arguments(&[0]);
        self.call("NtUnlockFile", handle, iosb, self.at(Self::RANGE), self.at(Self::RANGE) + 8)
    }

    /// NtReadFile ou NtWriteFile de `length` bytes em `offset`, sem Key.
    fn transfer(&self, handle: u64, write: bool, offset: u64, length: u64) -> u32 {
        guest::write64(self.at(Self::RANGE), offset);
        self.arguments(&[self.at(Self::IOSB), self.at(Self::DATA), length, self.at(Self::RANGE), 0]);
        self.call(if write { "NtWriteFile" } else { "NtReadFile" }, handle, 0, 0, 0)
    }

    /// NtCreateEvent de notificação, não sinalizado: o handle, 0 na falha.
    fn event(&self) -> u64 {
        guest::write64(self.at(Self::HANDLE), 0);
        self.arguments(&[0]);
        if self.call("NtCreateEvent", self.at(Self::HANDLE), 0x1F_0003, 0, 0) != 0 {
            return 0;
        }
        guest::read64(self.at(Self::HANDLE))
    }

    /// NtWaitForSingleObject com tempo zero: o objeto está sinalizado.
    fn signalled(&self, handle: u64) -> bool {
        guest::write64(self.at(Self::TIMEOUT), 0);
        self.call("NtWaitForSingleObject", handle, 0, self.at(Self::TIMEOUT), 0) == 0
    }
}

/// O caminho NT do D: de um caminho do volume.
fn dos(path: &str) -> String {
    alloc::format!("\\??\\D:{}", path.replace('/', "\\"))
}

pub fn run(assert: Assert) {
    locks(assert);
    notify(assert);
}

/// As travas de faixa de bytes (Q-FSGAPS G3).
fn locks(assert: Assert) {
    let Some(volume) = volume_files::volume() else {
        assert(false, "locks: volume de boot");
        return;
    };
    let Ok(block) = memory::map_user_region(0x4000) else {
        assert(false, "locks: memoria de usuario");
        return;
    };
    let test = Harness { block };
    let _ = volume.remove(FILE);
    volume_files::forget(FILE);
    let prepared = volume.create(FILE, false, 0x20, 0).is_ok() && volume.write(FILE, 0, &[0x4C; 64]).is_ok();
    assert(prepared, "locks: arquivo de 64 bytes no D:");
    let name = dos(FILE);
    // h1 e h2 síncronos (GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE), h3
    // assíncrono; compartilhamento de leitura e escrita.
    let (first, h1) = test.open(&name, 0xC010_0000, 3, 0x60);
    let (second, h2) = test.open(&name, 0xC010_0000, 3, 0x60);
    let (third, h3) = test.open(&name, 0xC000_0000, 3, 0x40);
    assert(first == 0 && second == 0 && third == 0, "locks: duas aberturas sincronas e uma assincrona");
    let iosb = test.at(Harness::IOSB);

    // Exclusiva imediata; a mesma faixa por outro FILE_OBJECT não sai.
    let granted = test.lock(h1, 0, iosb, 0, 10, true, true);
    let refused = test.lock(h2, 0, iosb, 0, 10, true, true);
    assert(granted == 0 && refused == 0xC000_0055, "locks: exclusiva concedida e STATUS_LOCK_NOT_GRANTED para outro FILE_OBJECT");
    // Compartilhadas sobrepostas de donos diferentes convivem.
    let shared_first = test.lock(h1, 0, iosb, 20, 10, false, true);
    let shared_second = test.lock(h2, 0, iosb, 25, 10, false, true);
    assert(shared_first == 0 && shared_second == 0, "locks: compartilhadas sobrepostas de donos diferentes");

    // A leitura esbarra só na exclusiva de outro dono; a escrita, em
    // qualquer compartilhada.
    let blocked_read = test.transfer(h2, false, 0, 5);
    let own_read = test.transfer(h1, false, 0, 5);
    let blocked_write = test.transfer(h1, true, 26, 3);
    assert(blocked_read == 0xC000_0054 && own_read == 0 && blocked_write == 0xC000_0054, "locks: leitura e escrita dao STATUS_FILE_LOCK_CONFLICT contra as travas");

    // A exclusiva do arquivo assíncrono espera (STATUS_PENDING) e o
    // NtUnlockFile da do h1 a concede: IO_STATUS_BLOCK e evento.
    let event = test.event();
    let async_iosb = test.at(Harness::ASYNC_IOSB);
    guest::write64(async_iosb, 0xFFFF_FFFF);
    let pending = test.lock(h3, event, async_iosb, 0, 10, true, false);
    let waiting = !test.signalled(event);
    let unlocked = test.unlock(h1, iosb, 0, 10);
    assert(event != 0 && pending == 0x103 && waiting && unlocked == 0 && guest::read32(async_iosb) == 0 && test.signalled(event), "locks: pedido em espera concedido pelo NtUnlockFile (IOSB e evento)");

    // Faixa não travada; o NtUnlockFile de um arquivo assíncrono é síncrono.
    let missing = test.unlock(h1, iosb, 100, 1);
    guest::write32(iosb, 0xFFFF_FFFF);
    let async_unlock = test.unlock(h3, iosb, 0, 10);
    assert(missing == 0xC000_007E && async_unlock == 0 && guest::read32(iosb) == 0, "locks: STATUS_RANGE_NOT_LOCKED e o desbloqueio sincrono de um arquivo assincrono");

    // Só FILE_READ_ATTRIBUTES: STATUS_ACCESS_DENIED; diretório:
    // STATUS_INVALID_PARAMETER (NtfsCommonLockControl 0x22f47e).
    let (opened, attributes_only) = test.open(&name, 0x0010_0080, 7, 0x60);
    let denied = test.lock(attributes_only, 0, iosb, 0, 1, true, true);
    test.close(attributes_only);
    let (root_opened, root) = test.open("\\??\\D:\\", 0x0010_0001, 7, 0x21);
    let directory = test.lock(root, 0, iosb, 0, 1, true, true);
    test.close(root);
    assert(opened == 0 && denied == 0xC000_0022 && root_opened == 0 && directory == 0xC000_000D, "locks: handle sem FILE_READ_DATA/FILE_WRITE_DATA e diretorio recusados");

    // ByteOffset desalinhado (ExRaiseDatatypeMisalignment) e faixa que dá a
    // volta (STATUS_INVALID_LOCK_RANGE).
    let misaligned = test.lock_with(h1, 0, iosb, test.at(Harness::RANGE) + 1, test.at(Harness::RANGE) + 8, true, true);
    let wrapped = test.lock(h1, 0, iosb, 0xFFFF_FFFF_FFFF_FFF0, 0x20, true, true);
    assert(misaligned == 0x8000_0002 && wrapped == 0xC000_01A1, "locks: ByteOffset desalinhado e faixa que da a volta");

    // O formato do BaseDllOpenIniFileOnDisk do kernel32: a faixa inteira,
    // compartilhada, e o NtUnlockFile da mesma faixa.
    let whole = test.lock(h1, 0, iosb, 0, u64::MAX, false, false);
    let whole_unlocked = test.unlock(h1, iosb, 0, u64::MAX);
    assert(whole == 0 && whole_unlocked == 0, "locks: a faixa inteira do kernel32 travada e destravada");

    // O fechamento do h2 solta a compartilhada dele em [25, 35): a
    // exclusiva do h1 em [30, 35) passa a sair.
    let before = test.lock(h1, 0, iosb, 30, 5, true, true);
    test.close(h2);
    let after = test.lock(h1, 0, iosb, 30, 5, true, true);
    assert(before == 0xC000_0055 && after == 0, "locks: o fechamento do handle solta as travas do processo");

    // Um handle de evento inválido é ignorado e a trava sai (0x656004).
    let ignored = test.lock(h1, 0xDEAD_0, iosb, 40, 4, true, true);
    assert(ignored == 0, "locks: evento invalido ignorado pelo NtLockFile");

    for handle in [h1, h3, event] {
        test.close(handle);
    }
    let _ = volume.remove(FILE);
    volume_files::forget(FILE);
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

/// O diretório da notificação de mudança e os arquivos dele.
const WATCHED: &str = "/OPENNTNW";

impl Harness {
    const NOTIFY_IOSB: u64 = 0x30;
    const NOTIFY_BUFFER: u64 = 0x3000;

    /// NtNotifyChangeDirectoryFile(handle, event, NULL, NULL, iosb, buffer,
    /// length, filter, watch_tree) com o IOSB preenchido com um valor
    /// conhecido antes.
    fn notify(&self, handle: u64, event: u64, length: u32, filter: u32, watch_tree: bool) -> u32 {
        guest::write64(self.at(Self::NOTIFY_IOSB), 0xDEAD_BEEF);
        guest::write64(self.at(Self::NOTIFY_IOSB) + 8, 0xDEAD_BEEF);
        guest::write_bytes(self.at(Self::NOTIFY_BUFFER), &[0u8; 0x100]);
        self.arguments(&[self.at(Self::NOTIFY_IOSB), self.at(Self::NOTIFY_BUFFER), length as u64, filter as u64, watch_tree as u64]);
        self.call("NtNotifyChangeDirectoryFile", handle, event, 0, 0)
    }

    /// O IO_STATUS_BLOCK do pedido de notificação: (Status, Information).
    fn notify_iosb(&self) -> (u32, u64) {
        (guest::read32(self.at(Self::NOTIFY_IOSB)), guest::read64(self.at(Self::NOTIFY_IOSB) + 8))
    }

    /// Os registros FILE_NOTIFY_INFORMATION do buffer: (Action, nome).
    fn records(&self) -> Vec<(u32, String)> {
        let mut records = Vec::new();
        let mut at = self.at(Self::NOTIFY_BUFFER);
        loop {
            let next = guest::read32(at);
            let action = guest::read32(at + 4);
            let length = guest::read32(at + 8) as u64;
            let units: Vec<u16> = (0..length / 2).map(|index| guest::read16(at + 12 + index * 2)).collect();
            records.push((action, String::from_utf16_lossy(&units)));
            if next == 0 || records.len() > 8 {
                break;
            }
            at += next as u64;
        }
        records
    }

    /// NtCancelIoFileEx(handle, iosb, out).
    fn cancel(&self, handle: u64, iosb: u64) -> u32 {
        self.call("NtCancelIoFileEx", handle, iosb, self.at(Self::IOSB), 0)
    }
}

fn record(action: u32, name: &str) -> (u32, String) {
    (action, String::from(name))
}

/// A notificação de mudança de diretório (Q-FSGAPS G1): o IRP pendente no
/// file system embutido e os relatos do NtfsReportDirNotify pelo FsRtl Lite.
fn notify(assert: Assert) {
    let Some(volume) = volume_files::volume() else {
        assert(false, "notify: volume de boot");
        return;
    };
    let cleanup = || {
        for path in ["/OPENNTNW/A.TXT", "/OPENNTNW/B.TXT", "/OPENNTNW/C.TXT", "/OPENNTNW/SUB/D.TXT", "/OPENNTNW/SUB", WATCHED] {
            let _ = volume.remove(path);
            volume_files::forget(path);
        }
    };
    cleanup();
    let Ok(block) = memory::map_user_region(0x4000) else {
        assert(false, "notify: memoria de usuario");
        return;
    };
    let test = Harness { block };
    let created = volume.create(WATCHED, true, 0x10, 0).is_ok() && volume.create("/OPENNTNW/C.TXT", false, 0x20, 0).is_ok();
    // FILE_LIST_DIRECTORY | SYNCHRONIZE, assíncrono (sem FILE_SYNCHRONOUS_IO_*).
    let (status, directory) = test.open(&dos(WATCHED), 0x10_0001, 7, 0x1);
    let event = test.event();
    if !created || status != 0 || event == 0 {
        assert(false, "notify: diretorio, abertura assincrona e evento");
        cleanup();
        return;
    }
    // O pedido fica pendente: STATUS_PENDING e o IO_STATUS_BLOCK intocado.
    let pending = test.notify(directory, event, 0x400, 0x1B, false) == 0x103 && test.notify_iosb() == (0xDEAD_BEEF, 0xDEAD_BEEF) && !test.signalled(event);
    let _ = volume.create("/OPENNTNW/A.TXT", false, 0x20, 0);
    let added = test.notify_iosb() == (0, 0x16) && test.records() == [record(1, "A.TXT")] && test.signalled(event);
    assert(pending && added, "notify: o pedido fica pendente e a criacao de A.TXT o conclui com FILE_ACTION_ADDED");
    // A renomeação no mesmo diretório: os dois registros numa conclusão só.
    let rearmed = test.notify(directory, event, 0x400, 0x1B, false) == 0x103;
    let _ = volume.rename("/OPENNTNW/A.TXT", "/OPENNTNW/B.TXT", false);
    let renamed = test.notify_iosb().0 == 0 && test.records() == [record(4, "A.TXT"), record(5, "B.TXT")];
    assert(rearmed && renamed, "notify: a renomeacao da RENAMED_OLD_NAME e RENAMED_NEW_NAME numa conclusao");
    // Sem pedido pendente, o relato fica guardado e o próximo pedido sai
    // concluído na hora.
    let _ = volume.remove("/OPENNTNW/B.TXT");
    let kept = test.notify(directory, event, 0x400, 0x1B, false) == 0x103 && test.notify_iosb().0 == 0 && test.records() == [record(2, "B.TXT")];
    assert(kept, "notify: a remocao sem pedido pendente fica guardada para o pedido seguinte");
    // Sem WatchTree, a mudança num subdiretório não conta; com ele, o nome
    // vem relativo.
    // A criação do SUB sem pedido pendente fica guardada: o pedido seguinte
    // a leva.
    let _ = volume.create("/OPENNTNW/SUB", true, 0x10, 0);
    let sub_added = test.notify(directory, event, 0x400, 0x1B, false) == 0x103 && test.records() == [record(1, "SUB")];
    let _ = test.notify(directory, event, 0x400, 0x1B, false);
    let _ = volume.create("/OPENNTNW/SUB/D.TXT", false, 0x20, 0);
    let shallow = test.notify_iosb() == (0xDEAD_BEEF, 0xDEAD_BEEF);
    assert(sub_added && shallow, "notify: o subdiretorio criado e relatado; sem WatchTree a mudanca dentro dele nao conta");
    let cancel_status = test.cancel(directory, test.at(Harness::NOTIFY_IOSB));
    let cancelled = cancel_status == 0 && test.notify_iosb().0 == 0xC000_0120;
    let again = test.cancel(directory, test.at(Harness::NOTIFY_IOSB));
    if !cancelled || again != 0xC000_0225 {
        crate::debug_print!("notify: NtCancelIoFileEx {:#x}, IOSB {:#x?}, segundo {:#x}", cancel_status, test.notify_iosb(), again);
    }
    assert(cancelled && again == 0xC000_0225, "notify: o NtCancelIoFileEx conclui o pedido com STATUS_CANCELLED e o segundo da STATUS_NOT_FOUND");
    // O WatchTree vale para o NOTIFY_CHANGE do FILE_OBJECT, criado no
    // primeiro pedido dele (o FsRtl reusa o mesmo nos seguintes): outra
    // abertura do diretório, com WatchTree desde o primeiro pedido.
    let (tree_opened, tree_handle) = test.open(&dos(WATCHED), 0x10_0001, 7, 0x1);
    let _ = test.notify(tree_handle, event, 0x400, 0x1B, true);
    let _ = volume.remove("/OPENNTNW/SUB/D.TXT");
    let tree = tree_opened == 0 && test.notify_iosb().0 == 0 && test.records() == [record(2, "SUB\\D.TXT")];
    if tree_opened == 0 {
        test.close(tree_handle);
    }
    assert(tree, "notify: com WatchTree o nome vem relativo ao diretorio observado");
    // O buffer pequeno demais dá STATUS_NOTIFY_ENUM_DIR.
    let _ = test.notify(directory, event, 16, 0x1B, false);
    let _ = volume.create("/OPENNTNW/A.TXT", false, 0x20, 0);
    let enum_dir = test.notify_iosb() == (0x10C, 0);
    // A escrita relata FILE_ACTION_MODIFIED no fechamento, não na escrita.
    let (opened, file) = test.open(&dos("/OPENNTNW/A.TXT"), 0x12_0116, 7, 0x20);
    let _ = test.notify(directory, event, 0x400, 0x1B, false);
    let written = opened == 0 && test.transfer(file, true, 0, 3) == 0 && test.notify_iosb() == (0xDEAD_BEEF, 0xDEAD_BEEF);
    test.close(file);
    let modified = test.notify_iosb().0 == 0 && test.records() == [record(3, "A.TXT")];
    assert(enum_dir && written && modified, "notify: buffer curto da STATUS_NOTIFY_ENUM_DIR; a escrita relata FILE_ACTION_MODIFIED so no fechamento");
    // Num arquivo, STATUS_INVALID_PARAMETER; o fechamento do diretório
    // conclui o pedido com STATUS_NOTIFY_CLEANUP.
    let (_, file) = test.open(&dos("/OPENNTNW/C.TXT"), 0x10_0001, 7, 0x40);
    let not_directory = test.notify(file, 0, 0x400, 0x1B, false) == 0xC000_000D;
    test.close(file);
    let _ = test.notify(directory, event, 0x400, 0x1B, false);
    test.close(directory);
    let closed = test.notify_iosb() == (0x10B, 0);
    assert(not_directory && closed, "notify: num arquivo da STATUS_INVALID_PARAMETER; o fechamento do diretorio conclui com STATUS_NOTIFY_CLEANUP");
    test.close(event);
    cleanup();
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}
