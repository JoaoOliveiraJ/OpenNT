//! Autoteste dos mapas de devices DOS por sessão de logon
//! (`ob/device_map.rs`, `se/logon_session.rs`): duas sessões de logon com
//! LogonIds diferentes, cada uma com um token de impersonação, veem `\??\Q:`
//! diferentes (cada `\??` é o `\Sessions\0\DosDevices\<LUID>` da sessão,
//! criado no primeiro uso com o link `Global`), o nome que falta no `\??`
//! da sessão vem do `\GLOBAL??`, o SYSTEM continua no `\GLOBAL??`, o
//! ProcessDeviceMap (consulta e troca) e o ObIsDosDeviceLocallyMapped
//! seguem o mapa, e a saída da sessão leva os links, o mapa e o diretório.
//!
//! O `\Sessions\0\DosDevices` é do csrss da sessão 0; sem ele (boot sem o
//! smss), o teste o cria e o tira no fim.

use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::device_map;
use crate::ntos::ob::handles::namespace as namespace_handles;
use crate::ntos::ob::object_manager as om;
use crate::ntos::ps::{process, security};
use crate::ntos::se::logon_session;
use crate::ntos::se::token::tokens;

type Assert = fn(bool, &str);

/// OBJ_CASE_INSENSITIVE | OBJ_OPENIF | OBJ_KERNEL_HANDLE e o link
/// permanente.
const OPEN_ATTRIBUTES: u32 = 0x2C0;
const PERMANENT_LINK: u32 = 0x250;

fn call(name: &str, arguments: &[u64]) -> u32 {
    super::phase6::call_export(name, arguments).map_or(0xFFFF_FFFF, |value| value as u32)
}

fn system_token() -> u64 {
    process::get_primary_token(process::get_system_process()).unwrap_or(0)
}

/// Uma sessão de logon nova com um token primário e uma cópia de
/// impersonação (SecurityImpersonation) do LogonId.
fn session() -> (u64, u64, u64) {
    let logon_id = tokens::allocate_luid();
    let _ = logon_session::create_track(logon_id);
    let primary = tokens::create(Some(system_token()), Some(&|token: &mut tokens::Token| token.authentication_id = logon_id)).unwrap_or(0);
    let impersonation = if primary != 0 { tokens::duplicate(primary, 2, false, 2).unwrap_or(0) } else { 0 };
    (logon_id, primary, impersonation)
}

fn impersonate(token: u64) -> bool {
    security::impersonate_client(process::get_current_thread(), token, false, false, 2).is_ok_and(|status| status == 0)
}

fn revert() {
    let _ = security::revert_to_self();
}

fn kernel_close(handle: u64) {
    let _ = crate::ntos::ob::close::close(handle, Some(0));
}

pub fn run(assert: Assert) {
    // O \Sessions\0\DosDevices do csrss, criado só se falta.
    let created_parents: Vec<&str> = ["\\Sessions", "\\Sessions\\0", "\\Sessions\\0\\DosDevices"].into_iter().filter(|path| om::lookup(path).is_none()).collect();
    let prepared = om::create_directory("\\Sessions\\0\\DosDevices").is_ok();
    let global_directory = om::lookup(device_map::GLOBAL_DOS_DEVICES);
    let kernel_objects = om::lookup("\\KernelObjects");
    let callbacks = om::lookup("\\Callback");
    let devices = om::lookup("\\Device");
    // Um nome só do \GLOBAL??, para a queda das sessões no diretório global.
    let global_link = om::create_symlink("\\GLOBAL??\\OpenNtDevMapG", "\\Device").is_ok();
    let system_view = om::lookup("\\??") == global_directory && om::lookup("\\??\\OpenNtDevMapG") == devices && om::lookup("\\DosDevices\\OpenNtDevMapG") == devices;
    assert(prepared && global_link && global_directory.is_some() && system_view && device_map::system_device_map() != 0, "devmaps: o \\?? e o \\DosDevices do SYSTEM sao o \\GLOBAL??");

    let (logon_a, primary_a, token_a) = session();
    let (logon_b, primary_b, token_b) = session();
    let path_a = logon_session::dos_devices_directory_name(logon_a);
    let path_b = logon_session::dos_devices_directory_name(logon_b);

    // Sessão A: o primeiro \?? cria o diretório da sessão; o Q: criado por
    // \??\Q: entra nele.
    let impersonated_a = token_a != 0 && impersonate(token_a);
    let directory_a = om::lookup("\\??");
    let link_a = namespace_handles::create_link_named_from_kernel(0, "\\??\\Q:", 0xF0001, PERMANENT_LINK, "\\KernelObjects");
    if let Ok(handle) = link_a {
        kernel_close(handle);
    }
    let q_a = om::lookup("\\??\\Q:");
    let fallback_a = om::lookup("\\??\\OpenNtDevMapG");
    let global_name_a = om::lookup("\\??\\Global");
    let ignoring_a = om::resolve_open_with("\\??", true, false, om::ROOT, false, true).0;
    let only_local = device_map::query(0, 1);
    let merged = device_map::query(0, 0);
    let mapped = guest::alloc_bytes(8);
    guest::write8(mapped, 0xAA);
    let q_local = call("ObIsDosDeviceLocallyMapped", &[17, mapped]) == 0 && guest::read8(mapped) == 1;
    let c_local = call("ObIsDosDeviceLocallyMapped", &[3, mapped]) == 0 && guest::read8(mapped) == 0;
    revert();
    let system_q = om::lookup("\\??\\Q:");
    let session_map_a = logon_session::device_map(logon_a, 0).unwrap_or(0);
    assert(
        impersonated_a && directory_a.is_some() && directory_a == om::lookup(&path_a) && directory_a != global_directory && link_a.is_ok() && q_a == kernel_objects && fallback_a == devices && global_name_a == global_directory && ignoring_a == global_directory && session_map_a != 0,
        "devmaps: o \\?? da sessao A e o \\Sessions\\0\\DosDevices\\<LUID> dela, com o Global e a queda no \\GLOBAL??",
    );
    let system_drives = device_map::query(0, 0).unwrap_or_default();
    assert(
        only_local.is_ok_and(|information| information.drive_map == 1 << 16 && information.drive_type[16] == device_map::DRIVE_CALCULATE) && merged.is_ok_and(|information| information.drive_map == system_drives.drive_map | 1 << 16) && q_local && c_local && system_q != kernel_objects,
        "devmaps: ProcessDeviceMap da sessao A (so o Q: com PROCESS_LUID_DOSDEVICES_ONLY, o resto do global) e o ObIsDosDeviceLocallyMapped",
    );

    // Sessão B: outro diretório, outro Q:, a mesma queda no global.
    let impersonated_b = token_b != 0 && impersonate(token_b);
    let directory_b = om::lookup("\\??");
    let before_b = om::lookup("\\??\\Q:");
    let link_b = namespace_handles::create_link_named_from_kernel(0, "\\??\\Q:", 0xF0001, PERMANENT_LINK, "\\Callback");
    if let Ok(handle) = link_b {
        kernel_close(handle);
    }
    let q_b = om::lookup("\\??\\Q:");
    let fallback_b = om::lookup("\\??\\OpenNtDevMapG");
    revert();
    // De volta à A: o Q: dela continua o dela.
    let again_a = impersonate(token_a) && om::lookup("\\??\\Q:") == kernel_objects;
    revert();
    assert(
        impersonated_b && directory_b.is_some() && directory_b == om::lookup(&path_b) && directory_b != directory_a && before_b == system_q && link_b.is_ok() && q_b == callbacks && q_b != q_a && fallback_b == devices && again_a,
        "devmaps: dois tokens com LogonIds diferentes veem \\??\\Q: diferentes e o mesmo \\GLOBAL??",
    );

    // ProcessDeviceMap (classe 23) pelo ZwSetInformationProcess: o diretório
    // da sessão A vira o \?? do processo corrente e o \GLOBAL?? volta. O
    // SystemDeviceMap não tem referência própria (como no NT): enquanto o
    // processo corrente troca de mapa, o teste segura o do sistema.
    let held = device_map::reference(true);
    let input = guest::alloc_bytes(8);
    let set_status = match (namespace_handles::create_directory_from_kernel(0, &path_a, 0xF000F, OPEN_ATTRIBUTES), namespace_handles::create_directory_from_kernel(0, device_map::GLOBAL_DOS_DEVICES, 0xF000F, OPEN_ATTRIBUTES)) {
        (Ok(session_handle), Ok(global_handle)) => {
            guest::write64(input, session_handle);
            let short = call("ZwSetInformationProcess", &[u64::MAX, 23, input, 4]);
            let set = call("ZwSetInformationProcess", &[u64::MAX, 23, input, 8]);
            let switched = om::lookup("\\??") == directory_a && om::lookup("\\??\\Q:") == kernel_objects && om::lookup("\\??\\OpenNtDevMapG") == devices;
            guest::write64(input, global_handle);
            let restored = call("ZwSetInformationProcess", &[u64::MAX, 23, input, 8]);
            let back = om::lookup("\\??") == global_directory;
            kernel_close(session_handle);
            kernel_close(global_handle);
            short == 0xC000_0004 && set == 0 && switched && restored == 0 && back
        }
        (first, second) => {
            for handle in [first, second].into_iter().flatten() {
                kernel_close(handle);
            }
            false
        }
    };
    guest::write64(input, 0x7FFF_FFF8);
    let bad_handle = call("ZwSetInformationProcess", &[u64::MAX, 23, input, 8]) == 0xC000_0008;
    let system_held = held != 0 && held == device_map::system_device_map();
    if held != 0 {
        device_map::dereference(held);
    }
    assert(set_status && bad_handle && system_held,"devmaps: ProcessDeviceMap troca o \\?? do processo pelo diretorio do handle e recusa tamanho e handle invalidos");

    // A saída das sessões: os links ficam temporários e saem, o mapa e o
    // diretório temporário da sessão também.
    for token in [token_a, primary_a, token_b, primary_b] {
        if token != 0 {
            let _ = tokens::release(token);
        }
    }
    let gone = !logon_session::exists(logon_a, 0) && !logon_session::exists(logon_b, 0) && om::lookup(&path_a).is_none() && om::lookup(&path_b).is_none();
    guest::write8(mapped, 0xAA);
    let unmapped = call("ObIsDosDeviceLocallyMapped", &[17, mapped]) == 0 && guest::read8(mapped) == 0;
    assert(gone && unmapped, "devmaps: a sessao que sai leva os links, o mapa e o diretorio dela");

    om::unlink("\\GLOBAL??\\OpenNtDevMapG");
    for path in created_parents.iter().rev() {
        om::unlink(path);
    }
    guest::free_bytes(mapped);
    guest::free_bytes(input);
}
