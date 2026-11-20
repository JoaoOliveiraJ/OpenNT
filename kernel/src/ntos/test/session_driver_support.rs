//! O suporte do kernel à carga de um driver de sessão (o win32k.sys pelo
//! smss): as classes do ZwSetSystemInformation para os drivers do GDI, o
//! ramo de modo usuário do NtSetSystemInformation, o SessionPowerInit do
//! ZwPowerInformation e a seção nomeada com OBJ_KERNEL_EXCLUSIVE.
//!
//! `run` (fase 6, no System, fora de sessão):
//! - SystemLoadGdiDriverInSystemSpace (54) carrega uma DLL sintética do
//!   sistema de arquivos em memória sem chamar ponto de entrada nenhum e
//!   devolve ImageAddress, SectionPointer (a entrada do loader), EntryPoint,
//!   ExportSectionPointer e ImageLength da imagem; a segunda carga devolve
//!   STATUS_IMAGE_ALREADY_LOADED sem tocar a saída; tamanhos errados dão
//!   STATUS_INFO_LENGTH_MISMATCH;
//! - uma segunda DLL que importa da primeira, carregada pelo
//!   MmLoadSystemImage, acha a imagem já carregada pela lista (o
//!   MiResolveImageReferences), sem outra cópia: a IAT aponta para o export
//!   da primeira e o LoadCount dela sobe; o SystemUnloadGdiDriverInformation
//!   (27) da primeira só desconta, e ela sai quando a importadora sai;
//! - o NtSetSystemInformation de modo usuário confere alinhamento, faixa e
//!   tamanho antes de tocar o buffer, recusa as classes 26/27/54 e, num
//!   processo que não é mestre de sessão (o System), a classe 38;
//! - SessionPowerInit (41) exige saída de exatamente 0x40 bytes sem entrada
//!   e devolve os endereços de dois BOOLEANs do Po, a tampa aberta e o TTM
//!   desligado; SessionPowerCleanup (63) não aceita buffers; SystemVideoState
//!   (29) devolve o estado da tela do console;
//! - PowerInformationInternal (87) de modo kernel, os tipos internos do
//!   win32kbase: SessionPowerState (0x13), InputControllerState (0x1C) e o
//!   watchdog de energia do SetWatchdog (0x15) criado, armado, desarmado e
//!   apagado;
//! - ZwCreateSection com OBJ_KERNEL_EXCLUSIVE (0x10000, o atributo das seções
//!   entre sessões do win32k) cria a seção nomeada e devolve o handle;
//! - SystemThreadPriorityClientIdInformation (82), a classe que a
//!   RawInputThread do win32kfull pede em KernelMode: tamanho, faixa 1..31,
//!   CLIENT_ID conferido e a base absoluta pelo KeSetActualBasePriorityThread,
//!   com STATUS_PENDING de volta.

use alloc::vec::Vec;

use super::phase6::call_export;
use crate::ntos::ex::system_information;
use crate::ntos::inc::types::extra_ps_user::{PowerSessionInit, SystemGdiDriverInformation};
use crate::ntos::inc::types::{KldrDataTableEntry, NtStruct, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::loaded_images;
use crate::ntos::mm::sysload;

type Assert = fn(bool, &str);

const HOST: &str = "opennt-gdi-host.sys";
const CLIENT: &str = "opennt-gdi-client.sys";
const STATUS_INFO_LENGTH_MISMATCH: u64 = 0xC000_0004;
const STATUS_IMAGE_ALREADY_LOADED: u64 = 0xC000_010E;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_INVALID_PARAMETER: u64 = 0xC000_000D;

/// UNICODE_STRING com o texto em `buffer` (o texto vem logo depois).
fn unicode(buffer: u64, text: &str) {
    let units: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    guest::write_bytes(buffer + 16, &units);
    guest::write_bytes(buffer + 16 + units.len() as u64, &[0, 0]);
    // SAFETY: bloco do teste com espaço para a estrutura e o texto.
    let string = unsafe { UnicodeString::at(buffer) };
    string.length.set(units.len() as u16);
    string.maximum_length.set(units.len() as u16 + 2);
    string.buffer.set(buffer + 16);
}

fn gdi_drivers(assert: Assert) {
    use crate::drivers::fs::memory_file_system;
    // O hospedeiro importa do ntoskrnl; o cliente importa o export dele.
    let host = super::import_cycle::cycle_dll("GdiHost", "ntoskrnl.exe", "RtlCompareMemory", &[0x31, 0xC0, 0xC3], &[0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3]);
    let client = super::import_cycle::cycle_dll("GdiClient", HOST, "GdiHost", &[0x31, 0xC0, 0xC3], &[0x31, 0xC0, 0xC3]);
    let written = memory_file_system::write_bytes(&alloc::format!("/{HOST}"), host).is_ok() && memory_file_system::write_bytes(&alloc::format!("/{CLIENT}"), client).is_ok();
    assert(written, "gdi-driver: as duas DLLs no sistema de arquivos em memoria");
    let block = guest::alloc_bytes(0x400);
    let information = block;
    let name = block + 0x100;
    unicode(name, &alloc::format!("\\SystemRoot\\System32\\{HOST}"));
    // SAFETY: SYSTEM_GDI_DRIVER_INFORMATION dentro do bloco do teste.
    let gdi = unsafe { SystemGdiDriverInformation::at(information) };
    guest::write_bytes(information, &[0u8; 0x38]);
    gdi.driver_name.length.set(guest::read16(name));
    gdi.driver_name.maximum_length.set(guest::read16(name + 2));
    gdi.driver_name.buffer.set(guest::read64(name + 8));
    assert(system_information::set(54, information, 0x30) as u64 == STATUS_INFO_LENGTH_MISMATCH && system_information::set(27, information, 4) as u64 == STATUS_INFO_LENGTH_MISMATCH, "gdi-driver: tamanhos errados das classes 54 e 27");
    let loaded = system_information::set(54, information, 0x38);
    let listed = loaded_images::find_by_base_name(HOST);
    let Some(image) = listed.filter(|_| loaded == 0) else {
        debug_print!("[gdi-driver] classe 54 -> {:#x}", loaded);
        assert(false, "gdi-driver: a classe 54 carrega a DLL no espaco de sistema");
        guest::free_bytes(block);
        return;
    };
    let base = image.image_base;
    let entry = gdi.section_pointer.get();
    // SAFETY: a entrada do loader devolvida pela classe 54.
    let load_count = |entry: u64| unsafe { KldrDataTableEntry::at(entry) }.load_count.get();
    // SAFETY: idem.
    let entry_base = unsafe { KldrDataTableEntry::at(entry) }.dll_base.get();
    assert(gdi.image_address.get() == base && entry_base == base && gdi.entry_point.get() == base + 0x1000 && gdi.export_section_pointer.get() == base + 0x2000 && gdi.image_length.get() == 0x4000 && load_count(entry) == 1, "gdi-driver: a classe 54 devolve base, entrada do loader, ponto de entrada, exports e tamanho, com LoadCount 1");
    let marker = 0x5A5A_5A5A_5A5A_5A5A;
    gdi.image_address.set(marker);
    assert(system_information::set(54, information, 0x38) as u64 == STATUS_IMAGE_ALREADY_LOADED && gdi.image_address.get() == marker && load_count(entry) == 1, "gdi-driver: a segunda carga da classe 54 = STATUS_IMAGE_ALREADY_LOADED, sem saida nem LoadCount");
    // O cliente carregado pelo MmLoadSystemImage acha o hospedeiro na lista.
    let client_name = block + 0x200;
    unicode(client_name, &alloc::format!("\\SystemRoot\\System32\\{CLIENT}"));
    let outputs = block + 0x380;
    let status = sysload::load_system_image(client_name, 0, 0, 0, outputs, outputs + 8).unwrap_or(0xC000_0001);
    let client_entry = guest::read64(outputs);
    let client_base = guest::read64(outputs + 8);
    let snapped = status == 0 && client_base != 0 && guest::read64(client_base + 0x3060) == base + 0x1020;
    let copies = loaded_images::list().iter().filter(|image| image.name.ends_with(HOST)).count();
    assert(snapped && copies == 1 && load_count(entry) == 2, "gdi-driver: o import de outra imagem usa a imagem ja carregada pela classe 54 (LoadCount 2, uma copia so)");
    // A classe 27 só desconta; o hospedeiro sai com a importadora.
    guest::write64(block + 0x3F0, entry);
    let unloaded = system_information::set(27, block + 0x3F0, 8) == 0;
    assert(unloaded && loaded_images::find_by_base_name(HOST).is_some() && load_count(entry) == 1, "gdi-driver: a classe 27 solta a referencia de quem carregou e a imagem fica com o import");
    let released = status == 0 && sysload::unload_system_image(client_entry).is_ok();
    assert(released && loaded_images::find_by_base_name(CLIENT).is_none() && loaded_images::find_by_base_name(HOST).is_none(), "gdi-driver: a saida da importadora solta a ultima referencia do hospedeiro");
    guest::free_bytes(block);
    let _ = memory_file_system::remove(&alloc::format!("/{HOST}"));
    let _ = memory_file_system::remove(&alloc::format!("/{CLIENT}"));
}

fn user_mode_branch(assert: Assert) {
    let set = system_information::set_from_user_mode;
    let status = |class: u32, buffer: u64, length: u32| set(class, buffer, length).unwrap_or(0);
    assert(status(38, 0x1_0001, 0x10) == 0x8000_0002 && status(0x59, 0x1_0001, 1) != 0x8000_0002, "ntsetsysinfo: alinhamento de 4 (1 na classe 0x59) conferido antes do buffer");
    assert(status(38, 0x7FFF_FFFF_0000 - 8, 0x10) == 0xC000_0005, "ntsetsysinfo: fim do buffer acima de MmUserProbeAddress = STATUS_ACCESS_VIOLATION");
    assert(status(38, 0x1_0000, 8) == STATUS_INFO_LENGTH_MISMATCH as u32, "ntsetsysinfo: classe 38 exige uma UNICODE_STRING (0x10)");
    assert(status(38, 0x1_0000, 0x10) == STATUS_PRIVILEGE_NOT_HELD, "ntsetsysinfo: classe 38 fora de um mestre de sessao = STATUS_PRIVILEGE_NOT_HELD");
    assert(status(26, 0x1_0000, 0x38) == STATUS_PRIVILEGE_NOT_HELD && status(54, 0x1_0000, 0x38) == STATUS_PRIVILEGE_NOT_HELD && status(27, 0x1_0000, 8) == STATUS_PRIVILEGE_NOT_HELD && status(27, 0x1_0000, 4) == STATUS_INFO_LENGTH_MISMATCH as u32, "ntsetsysinfo: as classes dos drivers do GDI sao so de modo kernel");
    assert(status(39, 0x1_0000, 8) == STATUS_INFO_LENGTH_MISMATCH as u32 && status(39, 0x1_0000, 0) == STATUS_INFO_LENGTH_MISMATCH as u32, "ntsetsysinfo: classe 39 (SystemPrioritySeperation) exige 4 bytes");
    let separation = guest::alloc_bytes(8);
    guest::write32(separation, 2);
    let kernel = call_export("ZwSetSystemInformation", &[39, separation, 4]).map(|status| status & 0xFFFF_FFFF);
    let short = call_export("ZwSetSystemInformation", &[39, separation, 2]).map(|status| status & 0xFFFF_FFFF);
    guest::free_bytes(separation);
    assert(kernel == Some(0) && short == Some(STATUS_INFO_LENGTH_MISMATCH) && crate::ntos::ps::quantum::priority_separation() == 2 && crate::ntos::ps::quantum::foreground_quantum() == [6, 12, 18], "ntsetsysinfo: classe 39 em modo kernel (PsChangeQuantumTable com 2: separacao 2 e a metade curta da tabela variavel)");
}

fn session_power(assert: Assert) {
    let buffer = guest::alloc_bytes(0x80);
    let power = |level: u64, input: u64, output: u64, length: u64| call_export("ZwPowerInformation", &[level, input, 0, output, length]).map(|status| status & 0xFFFF_FFFF);
    assert(power(41, buffer, buffer, 0x40) == Some(STATUS_INVALID_PARAMETER) && power(41, 0, buffer, 0x3F) == Some(STATUS_INVALID_PARAMETER) && power(41, 0, 0, 0x40) == Some(STATUS_INVALID_PARAMETER), "power: SessionPowerInit sem entrada e com saida de exatamente 0x40 bytes");
    guest::write_bytes(buffer, &[0xEE; 0x40]);
    let initialized = power(41, 0, buffer, 0x40) == Some(0);
    // SAFETY: os 0x40 bytes gravados pelo SessionPowerInit.
    let session = unsafe { PowerSessionInit::at(buffer) };
    let (no_more_input, force_off) = (session.no_more_input.get(), session.hiber_boot_force_monitor_off.get());
    let kernel = |pointer: u64| pointer >= 0xFFFF_8000_0000_0000 && guest::try_read::<u8>(pointer).is_ok();
    assert(initialized && kernel(no_more_input) && kernel(force_off) && no_more_input != force_off && session.lid_opened.get() == 1 && session.ttm_enabled.get() == 0 && session.setting_ec.get() == 0 && session.energy_saver_on.get() == 0, "power: SessionPowerInit devolve os dois BOOLEANs do Po, a tampa aberta, o TTM desligado e as configuracoes sem esquema");
    assert(power(63, buffer, 0, 0) == Some(STATUS_INVALID_PARAMETER) && power(63, 0, buffer, 8) == Some(STATUS_INVALID_PARAMETER) && power(63, 0, 0, 0) == Some(0), "power: SessionPowerCleanup sem buffers");
    guest::write32(buffer, 0xEEEE_EEEE);
    // Como no 19041, um comprimento zero anula o ponteiro (a entrada sem
    // comprimento conta como NULL; a saída sem comprimento, como ausente).
    let with_input = call_export("ZwPowerInformation", &[29, buffer + 0x40, 4, buffer, 4]).map(|status| status & 0xFFFF_FFFF);
    assert(with_input == Some(STATUS_INVALID_PARAMETER) && power(29, 0, buffer, 0) == Some(STATUS_INVALID_PARAMETER) && power(29, 0, buffer, 3) == Some(0xC000_0023) && power(29, buffer + 0x40, buffer, 4) == Some(0) && guest::read32(buffer) == crate::ntos::po::display_state::console_display_state(), "power: SystemVideoState sem entrada devolve os 4 bytes do PopConsoleDisplayState");
    session_display_state(assert, buffer);
    power_internal(assert);
    guest::free_bytes(buffer);
}

/// PowerInformationInternal (87) de modo kernel: antes recusado com
/// STATUS_INVALID_PARAMETER, agora pelo PopPowerInformationInternal
/// (0x6f1b04) do modo usuário, sem captura. O tipo 4 (sem AoAc), o
/// SessionPowerState (0x13, o UpdateSessionPowerState do win32kbase:
/// exatamente 0x14 bytes, sem saída; com Console, o
/// PopUpdateConsoleDisplayState com On), o InputControllerState (0x1C:
/// exatamente 0xC bytes, o ULONG em GUID_ADAPTIVE_INPUT_CONTROLLER_STATE) e o
/// SetWatchdog (0x15: pelo menos 0x60 bytes; NULL só com saída, que recebe o
/// watchdog criado; um prazo arma o timer; prazo 0 desarma; Delete apaga, e o
/// estágio de um watchdog 0x19C vai ao boot status data).
fn power_internal(assert: Assert) {
    use crate::ntos::inc::types::extra_ps_user::PowerInternalSetWatchdogInput;
    use crate::ntos::po::{display_state, power_setting, watchdog};
    let block = guest::alloc_bytes(0x100);
    let (input, output) = (block, block + 0x80);
    let internal = |length: u64, output_length: u64| call_export("ZwPowerInformation", &[87, input, length, if output_length != 0 { output } else { 0 }, output_length]).map(|status| status & 0xFFFF_FFFF);
    let ac_value = |setting: &[u8; 16]| power_setting::setting_value(setting, 0x40).ok().filter(|bytes| bytes.len() >= 16).map(|bytes| u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]));
    // Tipo 4 (PowerInternalUserAbsencePredictionCapability).
    guest::write32(input, 4);
    guest::write32(input + 4, 0);
    guest::write8(output, 0xFF);
    let absence = internal(8, 1);
    let absence_value = guest::read8(output);
    let null_input = call_export("ZwPowerInformation", &[87, 0, 0, output, 1]).map(|status| status & 0xFFFF_FFFF);
    let short_header = internal(4, 1);
    assert(absence == Some(0) && absence_value == 0 && null_input == Some(STATUS_INVALID_PARAMETER) && short_header == Some(STATUS_INVALID_PARAMETER), "power: PowerInformationInternal de modo kernel (tipo 4 sem AoAc; sem entrada ou com menos de 8 bytes, STATUS_INVALID_PARAMETER)");

    // SessionPowerState: {header, SessionId, On, Console, Reason}.
    let session_power = |on: u8, console: u8, length: u64, output_length: u64| {
        guest::write_bytes(input, &[0u8; 0x18]);
        guest::write32(input, 0x13);
        guest::write32(input + 8, 1);
        guest::write8(input + 0xC, on);
        guest::write8(input + 0xD, console);
        internal(length, output_length)
    };
    let previous = display_state::console_display_state();
    let short = session_power(0, 1, 0x10, 0);
    let with_output = session_power(0, 1, 0x14, 4);
    let not_console = session_power(0, 0, 0x14, 0);
    let unchanged = display_state::console_display_state() == previous;
    let off = session_power(0, 1, 0x14, 0);
    let off_state = (display_state::console_display_state(), ac_value(&power_setting::GUID_MONITOR_POWER_ON));
    let on = session_power(1, 1, 0x14, 0);
    let on_state = (display_state::console_display_state(), ac_value(&power_setting::GUID_MONITOR_POWER_ON));
    assert(
        previous == 1 && short == Some(STATUS_INVALID_PARAMETER) && with_output == Some(STATUS_INVALID_PARAMETER) && not_console == Some(0) && unchanged && off == Some(0) && off_state == (0, Some(0)) && on == Some(0) && on_state == (1, Some(1)),
        "power: SessionPowerState (0x13) de exatamente 0x14 bytes sem saida; com Console, a tela do console segue o On",
    );

    // InputControllerState: {header, ULONG State}.
    guest::write32(input, 0x1C);
    guest::write32(input + 4, 0);
    guest::write32(input + 8, 2);
    let controller = internal(0xC, 0);
    let controller_value = ac_value(&power_setting::GUID_ADAPTIVE_INPUT_CONTROLLER_STATE);
    let controller_long = internal(0x10, 0);
    assert(controller == Some(0) && controller_value == Some(2) && controller_long == Some(STATUS_INVALID_PARAMETER), "power: InputControllerState (0x1C) de exatamente 0xC bytes grava GUID_ADAPTIVE_INPUT_CONTROLLER_STATE");

    // SetWatchdog.
    guest::write_bytes(input, &[0u8; 0x60]);
    // SAFETY: os 0x60 bytes zerados do bloco do teste.
    let request = unsafe { PowerInternalSetWatchdogInput::at(input) };
    request.internal_type.set(0x15);
    let too_short = internal(0x5F, 8);
    let null_without_output = internal(0x60, 0);
    guest::write64(output, 0);
    let created = internal(0x60, 8);
    let object = guest::read64(output);
    let created_idle = object != 0 && watchdog::is_live(object) && !watchdog::is_armed(object);
    request.watchdog.set(object);
    request.parameters.timeout.set(60_000);
    request.parameters.session_id.set(u32::MAX);
    request.parameters.bug_check_code.set(watchdog::WIN32K_POWER_WATCHDOG_TIMEOUT);
    request.parameters.parameters[0].set(0x21);
    let armed = internal(0x60, 0);
    let armed_state = (watchdog::is_armed(object), watchdog::bsd_power_watchdog());
    request.parameters.timeout.set(0);
    let disarmed = internal(0x60, 0);
    let disarmed_state = (watchdog::is_armed(object), watchdog::bsd_power_watchdog());
    request.delete.set(1);
    guest::write64(output, 0xEEEE_EEEE);
    let deleted = internal(0x60, 8);
    let deleted_state = (guest::read64(output), watchdog::is_live(object));
    assert(
        too_short == Some(0xC000_0023) && null_without_output == Some(0xC000_0023) && created == Some(0) && created_idle && armed == Some(0) && armed_state == (true, (true, 0x21)) && disarmed == Some(0) && disarmed_state == (false, (false, 0x21)) && deleted == Some(0) && deleted_state == (0, false),
        "power: SetWatchdog (0x15) cria, arma, desarma e apaga o watchdog de energia",
    );
    guest::free_bytes(block);
}

/// SessionDisplayState (42), o aviso de tela do UpdateDisplayState do
/// win32kbase: entrada de exatamente 0x10 bytes e nenhuma saída; sem o
/// BOOLEAN de +0xD nada muda; com +0xC e +0xD, o PopConsoleDisplayState (o
/// SystemVideoState o devolve), GUID_CONSOLE_DISPLAY_STATE, GUID_MONITOR_POWER_ON
/// e o GUID_SESSION_DISPLAY_STATUS da sessão de quem chama. A tela começa
/// ligada (o PoInitSystem) e volta ao estado de antes no fim.
fn session_display_state(assert: Assert, buffer: u64) {
    use crate::ntos::po::{display_state, power_setting};
    let input = buffer + 0x40;
    let display = |state: u32, flags: [u8; 4], length: u64, output: u64| {
        guest::write32(input, 1);
        guest::write32(input + 4, state);
        guest::write32(input + 8, 0);
        guest::write_bytes(input + 0xC, &flags);
        call_export("ZwPowerInformation", &[42, input, length, output, if output != 0 { 4 } else { 0 }]).map(|status| status & 0xFFFF_FFFF)
    };
    // O valor AC de um setting (o primeiro registro do PopGetSettingValue).
    let ac_value = |setting: &[u8; 16]| power_setting::setting_value(setting, 0x40).ok().filter(|bytes| bytes.len() >= 16).map(|bytes| u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]));
    let video = || {
        guest::write32(buffer, 0xEEEE_EEEE);
        (call_export("ZwPowerInformation", &[29, 0, 0, buffer, 4]).map(|status| status & 0xFFFF_FFFF), guest::read32(buffer))
    };
    let previous = display_state::console_display_state();
    let boot_settings = (ac_value(&power_setting::GUID_CONSOLE_DISPLAY_STATE), ac_value(&power_setting::GUID_MONITOR_POWER_ON));
    assert(previous == 1 && boot_settings == (Some(1), Some(1)), "power: a tela do console comeca ligada (PopUpdateConsoleDisplayState do PoInitSystem)");
    let target = if previous == 1 { 2 } else { 1 };
    let short = display(target, [1, 1, 0, 0], 0xC, 0);
    let with_output = display(target, [1, 1, 0, 0], 0x10, buffer);
    let without_d = display(target, [1, 0, 1, 0], 0x10, 0);
    let unchanged = display_state::console_display_state() == previous;
    let applied = display(target, [1, 1, 0, 0], 0x10, 0);
    let settings = (ac_value(&power_setting::GUID_CONSOLE_DISPLAY_STATE), ac_value(&power_setting::GUID_MONITOR_POWER_ON), ac_value(&power_setting::GUID_SESSION_DISPLAY_STATUS));
    let read_back = video();
    let restored = display(previous, [1, 1, 1, 0], 0x10, 0);
    let monitor_restored = ac_value(&power_setting::GUID_MONITOR_POWER_ON);
    assert(
        short == Some(STATUS_INVALID_PARAMETER) && with_output == Some(STATUS_INVALID_PARAMETER) && without_d == Some(0) && unchanged && applied == Some(0) && settings == (Some(target), Some(1), Some(target)) && read_back == (Some(0), target) && restored == Some(0) && display_state::console_display_state() == previous && monitor_restored == Some((previous != 0) as u32),
        "power: SessionDisplayState grava o estado da tela do console, GUID_CONSOLE_DISPLAY_STATE, GUID_MONITOR_POWER_ON e o estado da sessao",
    );
}

fn kernel_exclusive_section(assert: Assert) {
    use crate::ntos::inc::types::ObjectAttributes;
    let block = guest::alloc_bytes(0x200);
    guest::write_bytes(block, &[0u8; 0x200]);
    let (attributes, name, size, handle) = (block, block + 0x40, block + 0x180, block + 0x188);
    unicode(name, "\\OpenNtKernelExclusiveSection");
    // SAFETY: OBJECT_ATTRIBUTES dentro do bloco do teste.
    let object = unsafe { ObjectAttributes::at(attributes) };
    object.length.set(ObjectAttributes::SIZE as u32);
    object.object_name.set(name);
    // OBJ_KERNEL_EXCLUSIVE | OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE.
    object.attributes.set(0x1_0240);
    guest::write64(size, 0x30);
    let status = call_export("ZwCreateSection", &[handle, 0xF001F, attributes, size, 4, 0x0800_0000, 0]).map(|status| status & 0xFFFF_FFFF);
    let created = status == Some(0) && guest::read64(handle) != 0;
    assert(created, "section: ZwCreateSection com OBJ_KERNEL_EXCLUSIVE cria a secao nomeada");
    if created {
        let _ = call_export("ZwClose", &[guest::read64(handle)]);
    }
    guest::free_bytes(block);
}

/// SystemThreadPriorityClientIdInformation em KernelMode (a chamada da
/// RawInputThread do win32kfull) e o KeSetActualBasePriorityThread.
fn thread_priority_client_id(assert: Assert) {
    use crate::ntos::ke::thread_priority;
    use crate::ntos::ps::process;
    let target = process::create_process(0x7D50, "opennt-cid-priority.exe", 0, None).unwrap_or(0);
    let thread = process::create_kernel_thread(target, 0x7D54, false, 0, None).unwrap_or(0);
    let buffer = guest::alloc_bytes(0x20);
    let request = |process_id: u64, thread_id: u64, priority: u32, length: u32| {
        guest::write64(buffer, process_id);
        guest::write64(buffer + 8, thread_id);
        guest::write32(buffer + 16, priority);
        guest::write32(buffer + 20, 0);
        system_information::set(system_information::SYSTEM_THREAD_PRIORITY_CLIENT_ID_INFORMATION, buffer, length)
    };
    let short = request(0x7D50, 0x7D54, 9, 0x10);
    let (zero, high) = (request(0x7D50, 0x7D54, 0, 0x18), request(0x7D50, 0x7D54, 32, 0x18));
    let (other_process, missing) = (request(0x7D58, 0x7D54, 9, 0x18), request(0x7D50, 0x7D5C, 9, 0x18));
    let base_before = thread_priority::query_base_priority(thread);
    let set = request(0x7D50, 0x7D54, 13, 0x18);
    let (base, priority) = (thread_priority::query_base_priority(thread), thread_priority::query_priority(thread));
    let previous = thread_priority::set_actual_base_priority(thread, base_before as i64 as u64);
    assert(
        target != 0 && thread != 0 && short == 0xC000_0004 && zero == 0xC000_000D && high == 0xC000_000D && other_process == 0xC000_000B && missing == 0xC000_000B,
        "priority: SystemThreadPriorityClientIdInformation confere o tamanho, a faixa 1..31 e o CLIENT_ID",
    );
    assert(
        set == 0x103 && base == 13 && priority == 13 && matches!(previous, Ok(13)) && thread_priority::query_base_priority(thread) == base_before,
        "priority: a classe 82 troca a base absoluta pelo KeSetActualBasePriorityThread e devolve STATUS_PENDING",
    );
    guest::free_bytes(buffer);
    let _ = process::terminate_process(target, 0);
    let _ = process::release_thread(thread);
}

pub fn run(assert: Assert) {
    gdi_drivers(assert);
    user_mode_branch(assert);
    session_power(assert);
    kernel_exclusive_section(assert);
    thread_priority_client_id(assert);
}
