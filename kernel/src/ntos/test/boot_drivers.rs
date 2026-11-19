//! Conferência dos drivers reais iniciados por `--start-driver`: depois do
//! DRIVER_START_COMPLETED, com o anel 3 armado, o que o driver publicou é
//! usado como um programa usaria, e o resultado vai à serial.
//!
//! - null.sys: um processo de teste abre \Device\Null pelo NtCreateFile; a
//!   leitura devolve STATUS_END_OF_FILE sem tocar no buffer nem no IOSB (uma
//!   falha síncrona, sem STATUS_PENDING, não o regrava) e a escrita
//!   conclui com o tamanho inteiro (o despacho do driver, por IRPs neither).
//! - beep.sys: o processo abre \Device\Beep, deixa pendente o IOCTL de
//!   redirecionamento da sessão (0x10004) e manda IOCTL_BEEP_SET: o pedido
//!   passa pelo IoStartPacket, pela DeviceQueue e pelo StartIo do driver, que
//!   entrega a frequência e a duração ao redirecionamento e chama o
//!   IoStartNextPacket (adiado, DOE_SIO_DEFERRED); sem redirecionamento o
//!   StartIo conclui com STATUS_NOT_FOUND, e um tom sem duração conclui sem
//!   passar pela fila.
//! - ksecdd.sys: dois processos de teste cifram e decifram memória pelo
//!   \Device\KsecDD como o cryptbase.dll (SystemFunction040/041), com as
//!   quatro opções; o que um processo cifrou o outro decifra, menos com
//!   SAME_PROCESS, e a opção do SYSTEM não decifra para o token anônimo.
//!   Depois, um processo de teste WinTcb-Light faz o cliente protegido do LSA
//!   e outro faz o lsass.exe: o 0x478 do LsapOpenCaller é recusado só com a
//!   proteção ligada, o 0x1000 abre, e o CopyVm, o AllocVm e o DupLsaHandle
//!   do ksecdd servem o cliente, que libera a faixa pelo 0x390058 do
//!   LsaFreeReturnBuffer.
//! - fs_rec.sys: os reconhecedores registrados pelo IoRegisterFileSystem
//!   estão nas filas de disco e de CD-ROM, e cada reconhecedor de disco
//!   responde a um IRP_MN_MOUNT_VOLUME sobre o volume NTFS do segundo disco
//!   (lido por um DEVICE_OBJECT de teste, criado pelo IoCreateDriver, que
//!   serve os setores e a geometria) sem montar nada.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::inc::types::{DeviceObject, DevobjExtension, Eprocess, IoStackLocation, Irp, NtStruct};
use crate::ntos::io::{file_system, io_manager};
use crate::ntos::io::irp_builder::{self, BuildOptions};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager;
use crate::ntos::ps::user::{memory, state};
use crate::ntos::test::multiprocess::identity::with_test_process;
use crate::ntos::test::phase6::call_export;

const STATUS_PENDING: u32 = 0x103;
const STATUS_END_OF_FILE: u32 = 0xC000_0011;
const STATUS_UNRECOGNIZED_VOLUME: u32 = 0xC000_014F;
const STATUS_FS_DRIVER_REQUIRED: u32 = 0xC000_019C;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
const IOCTL_BEEP_SET: u64 = 0x1_0000;
/// O IOCTL com que o componente da sessão recebe os tons (beep.sys).
const IOCTL_BEEP_REDIRECT: u64 = 0x1_0004;
const IOCTL_DISK_GET_DRIVE_GEOMETRY: u32 = 0x7_0000;
const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x7_405C;
const FILE_DEVICE_DISK: u64 = 7;
const FILE_DEVICE_CD_ROM_FILE_SYSTEM: u32 = 3;
const FILE_DEVICE_DISK_FILE_SYSTEM: u32 = 8;
const DOE_SIO_DEFERRED: u32 = 0x100;
const IRP_MJ_READ: u8 = 3;
const IRP_MJ_DEVICE_CONTROL: u8 = 0xE;
const IRP_MJ_FILE_SYSTEM_CONTROL: u8 = 0xD;
const IRP_MN_MOUNT_VOLUME: u8 = 1;
/// O segundo disco IDE, com o volume NTFS a partir do setor 0.
const NTFS_DRIVE: u8 = 1;

/// Inicia a conferência do driver dado, quando há uma para ele.
pub fn after_start(name: &str) {
    match name.to_ascii_lowercase().as_str() {
        "null" => null_device(),
        "beep" => beep_device(),
        "fs_rec" => file_system_recognizers(),
        "ksecdd" => {
            ksecdd_memory_protection();
            ksecdd_protected_client();
        }
        _ => {}
    }
}

/// Chamadas de sistema de um processo de teste pelos handlers de usuário,
/// com os ponteiros e os buffers numa região de usuário dele.
struct UserCalls {
    block: u64,
}

impl UserCalls {
    const HANDLE: u64 = 0x000;
    const NAME: u64 = 0x100;
    const ATTRIBUTES: u64 = 0x200;
    const IOSB: u64 = 0x300;
    const SECOND_IOSB: u64 = 0x320;
    const DATA: u64 = 0x400;
    const RSP: u64 = 0x800;

    fn new() -> Option<Self> {
        memory::map_user_region(0x1000).ok().map(|block| Self { block })
    }

    fn at(&self, offset: u64) -> u64 {
        self.block + offset
    }

    /// Argumentos 5 em diante, em [rsp+0x28]...
    fn stack(&self, arguments: &[u64]) {
        for (index, value) in arguments.iter().enumerate() {
            guest::write64(self.at(Self::RSP) + 0x28 + index as u64 * 8, *value);
        }
    }

    fn call(&self, name: &str, arguments: [u64; 4]) -> u32 {
        state::handler(name).and_then(|handler| handler(arguments[0], arguments[1], arguments[2], arguments[3], self.at(Self::RSP)).ok()).unwrap_or(u32::MAX)
    }

    fn iosb(&self, offset: u64) -> (u32, u64) {
        (guest::read32(self.at(offset)), guest::read64(self.at(offset) + 8))
    }

    /// NtCreateFile(GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, FILE_OPEN,
    /// FILE_SYNCHRONOUS_IO_NONALERT) do caminho: o status e o handle.
    fn open(&self, path: &str) -> (u32, u64) {
        let units: Vec<u16> = path.encode_utf16().collect();
        let (name, text) = (self.at(Self::NAME), self.at(Self::NAME) + 0x10);
        for (index, unit) in units.iter().enumerate() {
            guest::write16(text + index as u64 * 2, *unit);
        }
        guest::write16(name, units.len() as u16 * 2);
        guest::write16(name + 2, units.len() as u16 * 2);
        guest::write64(name + 8, text);
        let attributes = self.at(Self::ATTRIBUTES);
        guest::write_bytes(attributes, &[0; 0x30]);
        guest::write32(attributes, 0x30);
        guest::write64(attributes + 0x10, name);
        guest::write32(attributes + 0x18, 0x40);
        self.stack(&[0, 0, 3, 1, 0x20, 0, 0]);
        let status = self.call("NtCreateFile", [self.at(Self::HANDLE), 0xC010_0000, attributes, self.at(Self::IOSB)]);
        (status, guest::read64(self.at(Self::HANDLE)))
    }

    /// NtDeviceIoControlFile síncrono (sem evento) com o IOSB em `iosb`.
    fn ioctl(&self, handle: u64, iosb: u64, code: u64, input: u64, input_length: u64, output: u64, output_length: u64) -> u32 {
        self.stack(&[self.at(iosb), code, input, input_length, output, output_length]);
        self.call("NtDeviceIoControlFile", [handle, 0, 0, 0])
    }

    fn close(&self, handle: u64) -> u32 {
        self.call("NtClose", [handle, 0, 0, 0])
    }

    /// NtOpenFile(SYNCHRONIZE | FILE_READ_DATA, OBJECT_ATTRIBUTES sem
    /// atributos, FILE_SHARE_READ | WRITE | DELETE,
    /// FILE_SYNCHRONOUS_IO_NONALERT) de \Device\KsecDD, como o
    /// EncryptMemoryInitialize do cryptbase.dll: o status e o handle.
    fn open_ksecdd(&self) -> (u32, u64) {
        let units: Vec<u16> = "\\Device\\KsecDD".encode_utf16().collect();
        let (name, text) = (self.at(Self::NAME), self.at(Self::NAME) + 0x10);
        for (index, unit) in units.iter().enumerate() {
            guest::write16(text + index as u64 * 2, *unit);
        }
        guest::write16(name, units.len() as u16 * 2);
        guest::write16(name + 2, units.len() as u16 * 2);
        guest::write64(name + 8, text);
        let attributes = self.at(Self::ATTRIBUTES);
        guest::write_bytes(attributes, &[0; 0x30]);
        guest::write32(attributes, 0x30);
        guest::write64(attributes + 0x10, name);
        self.stack(&[7, 0x20]);
        let status = self.call("NtOpenFile", [self.at(Self::HANDLE), 0x10_0001, attributes, self.at(Self::IOSB)]);
        (status, guest::read64(self.at(Self::HANDLE)))
    }

    /// O SystemFunction040/041 do cryptbase.dll: NtDeviceIoControlFile no
    /// \Device\KsecDD com o mesmo buffer de entrada e de saída
    /// (METHOD_OUT_DIRECT), cifrado ou decifrado no lugar. O status, o IOSB
    /// e o conteúdo do buffer depois do pedido.
    fn protect_memory(&self, handle: u64, code: u64, data: &[u8]) -> (u32, (u32, u64), Vec<u8>) {
        let buffer = self.at(Self::DATA);
        guest::write_bytes(buffer, data);
        guest::write_bytes(self.at(Self::IOSB), &[0; 16]);
        let status = self.ioctl(handle, Self::IOSB, code, buffer, data.len() as u64, buffer, data.len() as u64);
        (status, self.iosb(Self::IOSB), guest::read_bytes(buffer, data.len()))
    }
}

/// O DEVICE_OBJECT nativo publicado num caminho \Device\X.
fn device_at_path(path: &str) -> Option<&'static DeviceObject> {
    let node = object_manager::lookup(path)?;
    let native = io_manager::device(node)?.native_device;
    // SAFETY: DEVICE_OBJECT vivo de um driver carregado.
    (native != 0).then(|| unsafe { DeviceObject::at(native) })
}

fn null_device() {
    let outcome = with_test_process("null-teste.exe", None, |_| {
        let user = UserCalls::new()?;
        let (opened, handle) = user.open("\\Device\\Null");
        // O IOSB da abertura: uma falha síncrona sem STATUS_PENDING (a
        // leitura no fim) não o regrava, como no IopCompleteRequest.
        let opened_iosb = user.iosb(UserCalls::IOSB);
        let data = user.at(UserCalls::DATA);
        guest::write_bytes(data, &[0x5A; 0x100]);
        user.stack(&[user.at(UserCalls::IOSB), data, 64, 0, 0]);
        let read = user.call("NtReadFile", [handle, 0, 0, 0]);
        let read_iosb = user.iosb(UserCalls::IOSB);
        let untouched = guest::read_bytes(data, 64).iter().all(|&byte| byte == 0x5A);
        user.stack(&[user.at(UserCalls::IOSB), data, 77, 0, 0]);
        let written = user.call("NtWriteFile", [handle, 0, 0, 0]);
        let write_iosb = user.iosb(UserCalls::IOSB);
        let closed = user.close(handle);
        Some((opened, read, read_iosb == opened_iosb, read_iosb, untouched, written, write_iosb, closed))
    })
    .flatten();
    let Some((opened, read, iosb_kept, read_iosb, untouched, written, write_iosb, closed)) = outcome else {
        debug_print!("[null] processo de teste nao montado");
        return;
    };
    debug_print!("[null] \\Device\\Null: abertura={:#x} leitura={:#x} (iosb {:#x}, {} bytes, buffer intacto={}) escrita={:#x} (iosb {:#x}, {} bytes) fechamento={:#x}", opened, read, read_iosb.0, read_iosb.1, untouched, written, write_iosb.0, write_iosb.1, closed);
    if opened == 0 && read == STATUS_END_OF_FILE && iosb_kept && untouched && written == 0 && write_iosb == (0, 77) && closed == 0 {
        debug_print!("NULL_DEVICE_OK leitura=EOF escrita=77");
    }
}

fn beep_device() {
    let outcome = with_test_process("beep-teste.exe", None, |_| {
        let user = UserCalls::new()?;
        let (opened, handle) = user.open("\\Device\\Beep");
        let (tone, redirected) = (user.at(UserCalls::DATA), user.at(UserCalls::DATA) + 0x40);
        guest::write_bytes(redirected, &[0xEE; 8]);
        // O componente da sessão espera os tons: o IOCTL fica pendente na CSQ do driver.
        let waiting = user.ioctl(handle, UserCalls::SECOND_IOSB, IOCTL_BEEP_REDIRECT, 0, 0, redirected, 8);
        // BEEP_SET_PARAMETERS { Frequency 440, Duration 100 }.
        guest::write32(tone, 440);
        guest::write32(tone + 4, 100);
        let beep = user.ioctl(handle, UserCalls::IOSB, IOCTL_BEEP_SET, tone, 8, 0, 0);
        let delivered = (user.iosb(UserCalls::SECOND_IOSB), guest::read32(redirected), guest::read32(redirected + 4));
        let device = device_at_path("\\Device\\Beep");
        let queue = device.map(|device| {
            // SAFETY: a DEVOBJ_EXTENSION do DEVICE_OBJECT vivo.
            let extension = unsafe { DevobjExtension::at(device.device_object_extension.get()) };
            (device.device_queue.busy.get(), device.current_irp.get(), extension.start_io_flags.get() & DOE_SIO_DEFERRED != 0, extension.start_io_count.get())
        });
        // Sem redirecionamento pendente: o StartIo conclui com STATUS_NOT_FOUND.
        let alone = user.ioctl(handle, UserCalls::IOSB, IOCTL_BEEP_SET, tone, 8, 0, 0);
        let alone_iosb = user.iosb(UserCalls::IOSB);
        // Frequência sem duração: concluído no despacho, sem a fila.
        guest::write32(tone + 4, 0);
        let instant = user.ioctl(handle, UserCalls::IOSB, IOCTL_BEEP_SET, tone, 8, 0, 0);
        let short = user.ioctl(handle, UserCalls::IOSB, IOCTL_BEEP_SET, tone, 4, 0, 0);
        let closed = user.close(handle);
        Some((opened, waiting, beep, delivered, queue, alone, alone_iosb, instant, short, closed))
    })
    .flatten();
    let Some((opened, waiting, beep, delivered, queue, alone, alone_iosb, instant, short, closed)) = outcome else {
        debug_print!("[beep] processo de teste nao montado");
        return;
    };
    let ((redirect_status, redirect_bytes), frequency, duration) = delivered;
    debug_print!("[beep] \\Device\\Beep: abertura={:#x} redirecionamento={:#x} BEEP_SET={:#x} entregue=({:#x}, {} bytes, {} Hz, {} ms) fila={:?} sem-redirecionamento={:#x}/{:#x} tom-sem-duracao={:#x} curto={:#x} fechamento={:#x}", opened, waiting, beep, redirect_status, redirect_bytes, frequency, duration, queue, alone, alone_iosb.0, instant, short, closed);
    let queue_ok = queue == Some((0, 0, true, 0));
    if opened == 0 && waiting == STATUS_PENDING && beep == 0 && (redirect_status, redirect_bytes, frequency, duration) == (0, 8, 440, 100) && queue_ok && alone == STATUS_NOT_FOUND && instant == 0 && short == 0xC000_000D && closed == 0 {
        debug_print!("BEEP_DEVICE_OK StartIo=440Hz/100ms fila=livre");
    }
}

// ---- ksecdd.sys --------------------------------------------------------------

/// Os IOCTLs do RtlEncryptMemory/RtlDecryptMemory (SystemFunction040/041 do
/// cryptbase.dll) por opção: SAME_PROCESS (0), CROSS_PROCESS (1),
/// SAME_LOGON (2) e a 4 do CredProtectEx(CRED_PROTECT_TO_SYSTEM). O
/// ksecdd.sys passa todos à extensão de device control que o cng.sys lhe
/// entregou no DriverEntry (IOCTL 0x390048 no \Device\CNG).
const KSEC_SAME_PROCESS: (u64, u64) = (0x39_000E, 0x39_0012);
const KSEC_CROSS_PROCESS: (u64, u64) = (0x39_0016, 0x39_001A);
const KSEC_SAME_LOGON: (u64, u64) = (0x39_001E, 0x39_0022);
const KSEC_FOR_SYSTEM: (u64, u64) = (0x39_007A, 0x39_007E);
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

/// Uma volta de cifra e decifra no mesmo processo: o status e o IOSB da
/// cifra, o texto cifrado, e se a decifra devolveu o texto original com o
/// IOSB do tamanho inteiro.
struct RoundTrip {
    encrypted: (u32, (u32, u64)),
    cipher: Vec<u8>,
    restored: bool,
}

impl RoundTrip {
    fn run(user: &UserCalls, handle: u64, (encrypt, decrypt): (u64, u64), plain: &[u8]) -> Self {
        let (status, iosb, cipher) = user.protect_memory(handle, encrypt, plain);
        let (back, back_iosb, text) = user.protect_memory(handle, decrypt, &cipher);
        Self { encrypted: (status, iosb), cipher, restored: back == 0 && back_iosb == (0, plain.len() as u64) && text == plain }
    }

    fn ok(&self, plain: &[u8]) -> bool {
        self.encrypted == (0, (0, plain.len() as u64)) && self.cipher != plain && self.restored
    }
}

/// O caminho do CredProtectEx do LogonUI e do CredUnprotectEx do lsass:
/// dois processos de teste usam o \Device\KsecDD como o cryptbase.dll. No
/// primeiro, cada opção cifra e decifra 32 bytes (AES) no lugar, a
/// CROSS_PROCESS também 24 bytes (3DES), um tamanho fora de múltiplo de 8
/// é recusado, e impersonando o token anônimo a decifra da opção 4 é negada
/// (só a sessão do SYSTEM decifra) e a da SAME_LOGON não devolve o texto. O
/// segundo processo decifra o que o primeiro cifrou: CROSS_PROCESS, a opção
/// 4 e SAME_LOGON devolvem o texto (a chave do boot é uma só no cng.sys),
/// SAME_PROCESS não (a chave mistura o ProcessCookie e a hora de criação do
/// processo), e a opção 4 cifra igual nos dois.
fn ksecdd_memory_protection() {
    let plain: Vec<u8> = (0..32u8).map(|index| index.wrapping_mul(7).wrapping_add(3)).collect();
    let first = with_test_process("ksec-cifra.exe", None, |_| {
        let user = UserCalls::new()?;
        let (opened, handle) = user.open_ksecdd();
        let trips: Vec<RoundTrip> = [KSEC_SAME_PROCESS, KSEC_CROSS_PROCESS, KSEC_SAME_LOGON, KSEC_FOR_SYSTEM].into_iter().map(|codes| RoundTrip::run(&user, handle, codes, &plain)).collect();
        let triple_des = RoundTrip::run(&user, handle, KSEC_CROSS_PROCESS, &plain[..24]).ok(&plain[..24]);
        let odd = user.protect_memory(handle, KSEC_FOR_SYSTEM.0, &plain[..20]).0;
        let anonymous = user.call("NtImpersonateAnonymousToken", [u64::MAX - 1, 0, 0, 0]);
        let denied = user.protect_memory(handle, KSEC_FOR_SYSTEM.1, &trips[3].cipher).0;
        let (other_logon, _, other_text) = user.protect_memory(handle, KSEC_SAME_LOGON.1, &trips[2].cipher);
        // De volta ao token primário (o PsRevertToSelf da thread de teste),
        // a opção do SYSTEM decifra de novo.
        let _ = call_export("PsRevertToSelf", &[]);
        let (after, _, after_text) = user.protect_memory(handle, KSEC_FOR_SYSTEM.1, &trips[3].cipher);
        let reverted = after == 0 && after_text == plain;
        let closed = user.close(handle);
        Some((opened, trips, triple_des, odd, anonymous, denied, other_logon == 0 && other_text != plain, reverted, closed))
    })
    .flatten();
    let Some((opened, trips, triple_des, odd, anonymous, denied, other_logon, reverted, closed)) = first else {
        debug_print!("[ksecdd] processo de teste nao montado");
        return;
    };
    let (same_cipher, cross_cipher, logon_cipher, system_cipher) = (trips[0].cipher.clone(), trips[1].cipher.clone(), trips[2].cipher.clone(), trips[3].cipher.clone());
    let second = with_test_process("ksec-decifra.exe", None, |_| {
        let user = UserCalls::new()?;
        let (opened, handle) = user.open_ksecdd();
        let decrypted = |code: u64, cipher: &[u8]| {
            let (status, iosb, text) = user.protect_memory(handle, code, cipher);
            (status, iosb.0, text == plain)
        };
        let cross = decrypted(KSEC_CROSS_PROCESS.1, &cross_cipher);
        let system = decrypted(KSEC_FOR_SYSTEM.1, &system_cipher);
        let logon = decrypted(KSEC_SAME_LOGON.1, &logon_cipher);
        let same = decrypted(KSEC_SAME_PROCESS.1, &same_cipher);
        let (again, _, again_cipher) = user.protect_memory(handle, KSEC_FOR_SYSTEM.0, &plain);
        let closed = user.close(handle);
        Some((opened, cross, system, logon, same, again == 0 && again_cipher == system_cipher, closed))
    })
    .flatten();
    let Some((second_opened, cross, system, logon, same, same_system_key, second_closed)) = second else {
        debug_print!("[ksecdd] segundo processo de teste nao montado");
        return;
    };
    let summary: Vec<_> = trips.iter().map(|trip| (trip.encrypted.0, trip.encrypted.1 .0, trip.cipher != plain, trip.restored)).collect();
    debug_print!("[ksecdd] \\Device\\KsecDD: abertura={:#x} voltas(same,cross,logon,system)={:?} 3des={} tamanho-impar={:#x} anonimo={:#x} decifra-system-anonima={:#x} logon-alheio-difere={} system-depois-do-revert={} fechamento={:#x}", opened, summary, triple_des, odd, anonymous, denied, other_logon, reverted, closed);
    debug_print!("[ksecdd] outro processo: abertura={:#x} cross={:?} system={:?} logon={:?} same-process={:?} system-mesma-chave={} fechamento={:#x}", second_opened, cross, system, logon, same, same_system_key, second_closed);
    let first_ok = opened == 0 && trips.iter().all(|trip| trip.ok(&plain)) && triple_des && odd == STATUS_INVALID_PARAMETER && anonymous == 0 && denied == STATUS_ACCESS_DENIED && other_logon && reverted && closed == 0;
    let second_ok = second_opened == 0 && cross == (0, 0, true) && system == (0, 0, true) && logon == (0, 0, true) && same == (0, 0, false) && same_system_key && second_closed == 0;
    if first_ok && second_ok {
        debug_print!("KSECDD_MEMORY_OK same/cross/logon/system cross-process=ok");
    }
}

const IOCTL_KSEC_DUP_LSA_HANDLE: u64 = 0x39_0034;
const IOCTL_KSEC_ALLOC_VM: u64 = 0x39_004C;
const IOCTL_KSEC_COPY_VM: u64 = 0x39_0054;
/// O LsaFreeReturnBuffer do sspicli num processo protegido.
const IOCTL_KSEC_FREE_CLIENT_VM: u64 = 0x39_0058;
const IOCTL_KSEC_INSERT_PROTECTED_ADDRESS: u64 = 0x39_005C;
const IOCTL_KSEC_REMOVE_PROTECTED_ADDRESS: u64 = 0x39_0060;
/// O LsapOpenKsec do lsass.exe: o processo vira o LSA do ksecdd.
const IOCTL_KSEC_CONNECT_LSA: u64 = 0x39_8000;
/// O primeiro NtOpenProcess do LsapOpenCaller e o da segunda tentativa.
const PROCESS_LSA_CALLER: u64 = 0x478;
const PROCESS_QUERY_LIMITED_INFORMATION: u64 = 0x1000;
const WINTCB_LIGHT: u8 = 0x61;
const MEM_COMMIT: u32 = 0x1000;
const MEM_FREE: u32 = 0x1_0000;

impl UserCalls {
    /// NtOpenProcess(out, access, OBJECT_ATTRIBUTES vazio, CLIENT_ID {pid, 0}).
    fn open_process(&self, process_id: u64, access: u64) -> (u32, u64) {
        let attributes = self.at(Self::ATTRIBUTES);
        guest::write_bytes(attributes, &[0; 0x30]);
        guest::write32(attributes, 0x30);
        let client_id = self.at(Self::DATA + 0x80);
        guest::write64(client_id, process_id);
        guest::write64(client_id + 8, 0);
        guest::write64(self.at(Self::HANDLE), 0);
        let status = self.call("NtOpenProcess", [self.at(Self::HANDLE), access, attributes, client_id]);
        (status, guest::read64(self.at(Self::HANDLE)))
    }

    /// O State do MEMORY_BASIC_INFORMATION de `base` no próprio processo.
    fn region_state(&self, base: u64) -> u32 {
        let information = self.at(Self::DATA + 0x100);
        self.stack(&[0x30, 0]);
        match self.call("NtQueryVirtualMemory", [u64::MAX, base, 0, information]) {
            0 => guest::read32(information + 0x20),
            _ => 0,
        }
    }
}

#[derive(Debug, Default)]
struct ProtectedClient {
    opened: u32,
    registered: u32,
    lsa_opened: u32,
    connected: u32,
    control: u32,
    denied: u32,
    limited: u32,
    queried: u32,
    protected_flag: u32,
    read: u32,
    read_ok: bool,
    written: u32,
    written_ok: bool,
    outside: u32,
    allocated: u32,
    committed: u32,
    duplicated: u32,
    token_closed: u32,
    freed: u32,
    again: u32,
    released: u32,
    removed: u32,
    closed: u32,
}

/// O cliente protegido do LSA (services.exe, wininit.exe: o sspicli abre o
/// \Device\KsecDD quando a PEB diz IsProtectedProcess). Um processo de teste
/// WinTcb-Light faz o cliente e, dentro dele, um processo comum faz o lsass:
/// registra-se no ksecdd (0x398000), abre o cliente como o LsapOpenCaller
/// (0x478 recusado só com a proteção ligada, 0x1000 aceito, IsProtectedProcess
/// nos Flags da ProcessBasicInformation estendida), lê e grava a faixa que o
/// cliente registrou (0x39005C, CopyVm 0x390054), aloca no cliente (AllocVm
/// 0x39004C) e duplica para ele o próprio token (DupLsaHandle 0x390034). De
/// volta ao cliente, o LsaFreeReturnBuffer (0x390058) libera a faixa uma vez.
fn ksecdd_protected_client() {
    let pattern: Vec<u8> = (0..0x40u8).map(|index| index ^ 0xA5).collect();
    let outcome = with_test_process("ksec-cliente.exe", None, |client| {
        let mut result = ProtectedClient::default();
        // SAFETY: o EPROCESS do processo de teste, vivo durante o corpo.
        let protection = &unsafe { Eprocess::at(client.process) }.protection.level;
        protection.set(WINTCB_LIGHT);
        let user = UserCalls::new()?;
        let (opened, handle) = user.open_ksecdd();
        result.opened = opened;
        let shared = user.at(UserCalls::DATA + 0x200);
        guest::write_bytes(shared, &pattern);
        let request = user.at(UserCalls::DATA + 0x180);
        guest::write64(request, shared);
        guest::write64(request + 8, 0x40);
        result.registered = user.ioctl(handle, UserCalls::IOSB, IOCTL_KSEC_INSERT_PROTECTED_ADDRESS, request, 16, 0, 0);
        let (client_process, client_id) = (client.process, client.process_id);
        let lsa = with_test_process("ksec-lsa.exe", None, |lsa| {
            // Sem lsass neste boot o \Security\LSA_AUTHENTICATION_INITIALIZED
            // não sinaliza: com SecurityPort = 1 o CreateClient do
            // IsOkayToExec (o 0x398000 o chama) devolve na hora
            // STATUS_PROCESS_IS_TERMINATING (ksecdd 0x5b79) em vez de esperar.
            // SAFETY: o EPROCESS do processo de teste interno.
            unsafe { Eprocess::at(lsa.process) }.security_port.set(1);
            let user = UserCalls::new()?;
            let (opened, ksec) = user.open_ksecdd();
            let out = user.at(UserCalls::DATA + 0x1C0);
            let connected = user.ioctl(ksec, UserCalls::IOSB, IOCTL_KSEC_CONNECT_LSA, 0, 0, out, 4);
            // O mesmo pedido sem e com a proteção do alvo.
            // SAFETY: o EPROCESS do cliente, vivo durante o processo interno.
            let level = &unsafe { Eprocess::at(client_process) }.protection.level;
            level.set(0);
            let (control, control_handle) = user.open_process(client_id, PROCESS_LSA_CALLER);
            if control == 0 {
                user.close(control_handle);
            }
            level.set(WINTCB_LIGHT);
            let (denied, _) = user.open_process(client_id, PROCESS_LSA_CALLER);
            let (limited, process) = user.open_process(client_id, PROCESS_QUERY_LIMITED_INFORMATION);
            let information = user.at(UserCalls::DATA + 0x100);
            user.stack(&[0]);
            let queried = user.call("NtQueryInformationProcess", [process, 0, information, 0x40]);
            let protected_flag = guest::read32(information + 0x38) & 1;
            let request = user.at(UserCalls::DATA + 0x180);
            let local = user.at(UserCalls::DATA + 0x200);
            let copy = |client_address: u64, to_client: u32| {
                guest::write64(request, process);
                guest::write64(request + 8, client_address);
                guest::write64(request + 0x10, local);
                guest::write32(request + 0x18, 0x40);
                guest::write32(request + 0x1C, to_client);
                user.ioctl(ksec, UserCalls::IOSB, IOCTL_KSEC_COPY_VM, request, 0x20, 0, 0)
            };
            guest::write_bytes(local, &[0; 0x40]);
            let read = copy(shared, 0);
            let read_back = guest::read_bytes(local, 0x40);
            let inverted: Vec<u8> = read_back.iter().map(|byte| !byte).collect();
            guest::write_bytes(local, &inverted);
            let written = copy(shared, 1);
            let outside = copy(shared + 0x1000, 0);
            guest::write64(request, process);
            guest::write64(request + 8, 0x100);
            guest::write64(out, 0);
            let allocated = user.ioctl(ksec, UserCalls::IOSB, IOCTL_KSEC_ALLOC_VM, request, 16, out, 8);
            let base = guest::read64(out);
            user.call("NtOpenProcessToken", [u64::MAX, 8, user.at(UserCalls::HANDLE), 0]);
            guest::write64(request, guest::read64(user.at(UserCalls::HANDLE)));
            guest::write64(request + 8, process);
            guest::write64(request + 0x10, 0);
            guest::write64(out, 0);
            let duplicated = user.ioctl(ksec, UserCalls::IOSB, IOCTL_KSEC_DUP_LSA_HANDLE, request, 0x18, out, 8);
            let client_token = guest::read64(out);
            Some((opened, connected, control, denied, limited, queried, protected_flag, read, read_back == pattern, written, outside, allocated, base, duplicated, client_token))
        })
        .flatten();
        let (lsa_opened, connected, control, denied, limited, queried, protected_flag, read, read_ok, written, outside, allocated, base, duplicated, client_token) = lsa?;
        result.lsa_opened = lsa_opened;
        result.connected = connected;
        result.control = control;
        result.denied = denied;
        result.limited = limited;
        result.queried = queried;
        result.protected_flag = protected_flag;
        result.read = read;
        result.read_ok = read_ok;
        result.written = written;
        result.outside = outside;
        result.allocated = allocated;
        result.duplicated = duplicated;
        result.written_ok = guest::read_bytes(shared, 0x40).iter().zip(&pattern).all(|(byte, original)| *byte == !original);
        result.committed = user.region_state(base);
        let cell = user.at(UserCalls::DATA + 0x1C0);
        guest::write64(cell, base);
        result.freed = user.ioctl(handle, UserCalls::IOSB, IOCTL_KSEC_FREE_CLIENT_VM, cell, 8, 0, 0);
        result.again = user.ioctl(handle, UserCalls::IOSB, IOCTL_KSEC_FREE_CLIENT_VM, cell, 8, 0, 0);
        result.released = user.region_state(base);
        result.token_closed = user.close(client_token);
        guest::write64(request, shared);
        guest::write64(request + 8, 0x40);
        result.removed = user.ioctl(handle, UserCalls::IOSB, IOCTL_KSEC_REMOVE_PROTECTED_ADDRESS, request, 16, 0, 0);
        result.closed = user.close(handle);
        Some(result)
    })
    .flatten();
    let Some(result) = outcome else {
        debug_print!("[ksecdd] cliente protegido: processo de teste nao montado");
        return;
    };
    debug_print!("[ksecdd] cliente protegido: {:?}", result);
    let lsa_ok = result.lsa_opened == 0 && result.connected == 0 && result.control == 0 && result.denied == STATUS_ACCESS_DENIED && result.limited == 0 && result.queried == 0 && result.protected_flag == 1;
    let copy_ok = result.registered == 0 && result.read == 0 && result.read_ok && result.written == 0 && result.written_ok && result.outside == STATUS_ACCESS_DENIED && result.removed == 0;
    let vm_ok = result.allocated == 0 && result.committed == MEM_COMMIT && result.freed == 0 && result.again == STATUS_INVALID_PARAMETER && result.released == MEM_FREE;
    let handle_ok = result.duplicated == 0 && result.token_closed == 0;
    if result.opened == 0 && result.closed == 0 && lsa_ok && copy_ok && vm_ok && handle_ok {
        debug_print!("KSECDD_PROTECTED_CLIENT_OK open=0x1000 copy alloc dup free=0x390058");
    }
}

// ---- fs_rec.sys --------------------------------------------------------------

/// O DEVICE_OBJECT de teste do volume e os setores dele.
static VOLUME_DEVICE: AtomicU64 = AtomicU64::new(0);
static VOLUME_SECTORS: AtomicU64 = AtomicU64::new(0);

/// Despacho do volume de teste: IRP_MJ_READ do segundo disco e os IOCTLs de
/// geometria e tamanho que o fs_rec pede.
extern "win64" fn volume_dispatch(_device: u64, packet: u64) -> u32 {
    // SAFETY: o IRP vivo que o I/O Manager entrega ao despacho.
    let irp = unsafe { Irp::at(packet) };
    // SAFETY: CurrentStackLocation de um IRP vivo.
    let location = unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get()) };
    let buffer = match irp.associated_irp.system_buffer.get() {
        0 => irp.user_buffer.get(),
        system => system,
    };
    let (status, information) = match location.major_function.get() {
        IRP_MJ_READ => {
            let (length, offset) = (location.parameters.read.length.get(), location.parameters.read.byte_offset.quad_part.get() as u64);
            match crate::drivers::storage::ata_pio::read_sectors(offset / 512, length.div_ceil(512), NTFS_DRIVE) {
                Ok(bytes) if buffer != 0 => {
                    guest::write_bytes(buffer, &bytes[..length as usize]);
                    (0, length as u64)
                }
                _ => (0xC000_0185, 0),
            }
        }
        IRP_MJ_DEVICE_CONTROL => {
            let sectors = VOLUME_SECTORS.load(Ordering::SeqCst);
            match location.parameters.device_io_control.io_control_code.get() {
                IOCTL_DISK_GET_LENGTH_INFO => {
                    guest::write64(buffer, sectors * 512);
                    (0, 8)
                }
                IOCTL_DISK_GET_DRIVE_GEOMETRY => {
                    // DISK_GEOMETRY: Cylinders, FixedMedia, 255 trilhas, 63 setores, 512 bytes.
                    guest::write64(buffer, sectors / (255 * 63));
                    guest::write32(buffer + 8, 12);
                    guest::write32(buffer + 12, 255);
                    guest::write32(buffer + 16, 63);
                    guest::write32(buffer + 20, 512);
                    (0, 0x18)
                }
                _ => (STATUS_INVALID_DEVICE_REQUEST, 0),
            }
        }
        _ => (0, 0),
    };
    irp.io_status.status.set(status as i32);
    irp.io_status.information.set(information);
    let _ = call_export("IofCompleteRequest", &[packet, 0]);
    status
}

/// DriverEntry do volume de teste (IoCreateDriver): o despacho e o
/// DEVICE_OBJECT de disco.
extern "win64" fn volume_driver_entry(driver: u64, _registry: u64) -> u32 {
    use crate::ntos::inc::types::DriverObject;
    // SAFETY: o DRIVER_OBJECT que o IoCreateDriver acabou de criar.
    let driver_object = unsafe { DriverObject::at(driver) };
    let dispatch = volume_dispatch as extern "win64" fn(u64, u64) -> u32 as usize as u64;
    for major in [0usize, 2, IRP_MJ_READ as usize, IRP_MJ_DEVICE_CONTROL as usize] {
        driver_object.major_function[major].set(dispatch);
    }
    let block = guest::alloc_bytes(0x80);
    let name = "\\Device\\OpenNtFsRecVolume";
    let units: Vec<u16> = name.encode_utf16().collect();
    for (index, unit) in units.iter().enumerate() {
        guest::write16(block + 0x20 + index as u64 * 2, *unit);
    }
    guest::write16(block, units.len() as u16 * 2);
    guest::write16(block + 2, units.len() as u16 * 2);
    guest::write64(block + 8, block + 0x20);
    let status = call_export("IoCreateDevice", &[driver, 0, block, FILE_DEVICE_DISK, 0, 0, block + 0x10]).unwrap_or(1) as u32;
    let device = guest::read64(block + 0x10);
    if status == 0 && device != 0 {
        // SAFETY: o DEVICE_OBJECT recém-criado.
        let flags = &unsafe { DeviceObject::at(device) }.flags;
        flags.set(flags.get() & !0x80);
        VOLUME_DEVICE.store(device, Ordering::SeqCst);
    }
    guest::free_bytes(block);
    status
}

/// IRP_MJ_FILE_SYSTEM_CONTROL/IRP_MN_MOUNT_VOLUME ao reconhecedor, com o
/// VPB e o dispositivo do volume em Parameters.MountVolume.
fn mount_request(recognizer: &DeviceObject, volume: u64) -> u32 {
    let stack_count = (recognizer.stack_size.get() as u8).max(1) as u32;
    let packet = guest::alloc_bytes(irp_builder::size_for(stack_count));
    let vpb = guest::alloc_bytes(0x60);
    guest::write_bytes(vpb, &[0; 0x60]);
    irp_builder::build(packet, &BuildOptions { major: IRP_MJ_FILE_SYSTEM_CONTROL, minor: IRP_MN_MOUNT_VOLUME, device_object: recognizer.address(), stack_count, ..BuildOptions::default() });
    // SAFETY: o IRP recém-montado e o slot do topo dele.
    let location = unsafe { IoStackLocation::at(Irp::at(packet).tail.overlay.current_stack_location.get() - IoStackLocation::SIZE) };
    location.parameters.mount_volume.vpb.set(vpb);
    location.parameters.mount_volume.device_object.set(volume);
    let status = io_manager::iof_call_driver(recognizer.address(), packet) as u32;
    guest::free_bytes(packet);
    guest::free_bytes(vpb);
    status
}

fn file_system_recognizers() {
    // (nome, fila, é o reconhecedor de NTFS).
    let recognizers = [
        ("NtfsRecognizer", FILE_DEVICE_DISK_FILE_SYSTEM),
        ("FatDiskRecognizer", FILE_DEVICE_DISK_FILE_SYSTEM),
        ("ExFatRecognizer", FILE_DEVICE_DISK_FILE_SYSTEM),
        ("ReFSRecognizer", FILE_DEVICE_DISK_FILE_SYSTEM),
        ("ReFSv1Recognizer", FILE_DEVICE_DISK_FILE_SYSTEM),
        ("UdfsDiskRecognizer", FILE_DEVICE_DISK_FILE_SYSTEM),
        ("FatCdRomRecognizer", FILE_DEVICE_CD_ROM_FILE_SYSTEM),
        ("UdfsCdRomRecognizer", FILE_DEVICE_CD_ROM_FILE_SYSTEM),
        ("CdfsRecognizer", FILE_DEVICE_CD_ROM_FILE_SYSTEM),
    ];
    let mut present = Vec::new();
    let mut misplaced = 0;
    for (name, queue) in recognizers {
        let Some(device) = device_at_path(&alloc::format!("\\FileSystem\\{name}")) else { continue };
        if !file_system::registered_file_systems(queue).contains(&device.address()) {
            misplaced += 1;
        }
        present.push((name, queue, device));
    }
    let listed: Vec<&str> = present.iter().map(|&(name, _, _)| name).collect();
    debug_print!("[fs_rec] reconhecedores registrados: {:?} (fora da fila certa: {})", listed, misplaced);
    // O volume NTFS do segundo disco, servido pelo DEVICE_OBJECT de teste.
    let boot = crate::drivers::storage::ata_pio::read_sectors(0, 1, NTFS_DRIVE).unwrap_or_default();
    if boot.len() < 0x30 {
        debug_print!("[fs_rec] segundo disco ilegivel");
        return;
    }
    // Setores do volume (+1 do setor de boot de reserva no fim).
    VOLUME_SECTORS.store(u64::from_le_bytes(boot[0x28..0x30].try_into().unwrap_or([0; 8])) + 1, Ordering::SeqCst);
    let entry = volume_driver_entry as extern "win64" fn(u64, u64) -> u32 as usize as u64;
    let created = call_export("IoCreateDriver", &[0, entry]).unwrap_or(1) as u32;
    let volume = VOLUME_DEVICE.load(Ordering::SeqCst);
    if created != 0 || volume == 0 {
        debug_print!("[fs_rec] volume de teste nao criado: {:#x}", created);
        return;
    }
    let mut all_answered = !present.is_empty() && misplaced == 0;
    let mut ntfs_recognized = false;
    for &(name, queue, device) in present.iter().filter(|&&(_, queue, _)| queue == FILE_DEVICE_DISK_FILE_SYSTEM) {
        let status = mount_request(device, volume);
        let expected = if name == "NtfsRecognizer" { STATUS_FS_DRIVER_REQUIRED } else { STATUS_UNRECOGNIZED_VOLUME };
        ntfs_recognized |= name == "NtfsRecognizer" && status == STATUS_FS_DRIVER_REQUIRED;
        all_answered &= status == expected;
        debug_print!("[fs_rec] IRP_MN_MOUNT_VOLUME do volume NTFS -> {} (fila {}): {:#x}", name, queue, status);
    }
    // O reconhecedor de NTFS só existe sem um \Ntfs no namespace.
    let ntfs_expected = listed.contains(&"NtfsRecognizer");
    debug_print!("[fs_rec] volume NTFS reconhecido pelo NtfsRecognizer: {} (reconhecedor presente: {})", ntfs_recognized, ntfs_expected);
    if all_answered && ntfs_recognized == ntfs_expected {
        debug_print!("FS_REC_OK reconhecedores={} ntfs={}", present.len(), if ntfs_recognized { "STATUS_FS_DRIVER_REQUIRED" } else { "sem reconhecedor" });
    }
}
