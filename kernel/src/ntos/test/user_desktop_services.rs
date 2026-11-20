//! Autotestes dos serviços de modo usuário que a área de trabalho, a barra
//! de tarefas e o AppX pedem ao kernel (fase 7): o NtSetThreadExecutionState
//! (o CKeepAwake do explorer), os níveis do NtPowerInformation do dwm, do
//! winlogon e do explorer (14, 15, 16, 64, 65, 94 e 95) e os pedidos de
//! energia de modo usuário (43, 44 e 72; o PowerCreateRequest,
//! PowerSetRequest e PowerClearRequest do kernelbase), o
//! NtFlushVirtualMemory (o FlushViewOfFile do SQLite do StateRepository) e
//! o NtFlushBuffersFileEx, o NtGetCachedSigningLevel e o
//! NtCompareSigningLevels (o AppXDeploymentServer), e o NtSetEaFile e o
//! NtQueryEaFile de modo usuário (as extensões de implantação do AppX e o
//! CreateFile com modelo do kernelbase), e o NtCancelSynchronousIoFile (o
//! CancelSynchronousIo do AppXDeploymentServer e do taskmgr) e o NtDeleteFile
//! (a limpeza do wevtsvc e a migração de hive do bisrv), e o
//! NtAreMappedFilesTheSame (o carregador da ntdll).

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::po::power_request;
use crate::ntos::ps::user::file_io::{self, OpenRequest};
use crate::ntos::ps::user::{memory, state};

type Assert = fn(bool, &str);
type Call<'a> = &'a dyn Fn(&str, u64, u64, u64, u64) -> u32;

const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
/// EXECUTION_STATE.
const ES_SYSTEM_REQUIRED: u32 = 0x1;
const ES_DISPLAY_REQUIRED: u32 = 0x2;
const ES_USER_PRESENT: u32 = 0x4;
const ES_AWAYMODE_REQUIRED: u32 = 0x40;
const ES_CONTINUOUS: u32 = 0x8000_0000;
/// Os índices internos dos tipos de pedido.
const SYSTEM_REQUIRED: usize = 1;
const AWAY_MODE_REQUIRED: usize = 2;

pub fn run(assert: Assert) {
    let Ok(block) = memory::map_user_region(0x4000) else {
        assert(false, "desktop: memoria de usuario");
        return;
    };
    let rsp = block + 0x3000;
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map_or(u32::MAX, |handler| handler(a1, a2, a3, a4, rsp).unwrap_or(u32::MAX));
    thread_execution_state(assert, block, &call);
    power_levels(assert, block, rsp, &call);
    power_requests(assert, block, rsp, &call);
    flushes(assert, block, rsp, &call);
    mapped_images(assert, block, rsp, &call);
    signing_levels(assert, block, rsp, &call);
    extended_attributes(assert, block, rsp, &call);
    cancel_synchronous_io(assert, block, &call);
    delete_file(assert, block, &call);
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

/// NtSetThreadExecutionState: as flags recusadas, a sonda de
/// PreviousFlags, o pedido legado contínuo (as flags anteriores sempre com
/// ES_CONTINUOUS e os contadores globais) e o pedido não contínuo, que não
/// fica.
fn thread_execution_state(assert: Assert, block: u64, call: Call) {
    let previous = block + 0x100;
    let set = |flags: u32| {
        guest::write32(previous, 0xEEEE_EEEE);
        let status = call("NtSetThreadExecutionState", flags as u64, previous, 0, 0);
        (status, guest::read32(previous))
    };
    let invalid = set(ES_USER_PRESENT).0;
    let away_alone = set(ES_AWAYMODE_REQUIRED).0;
    let unprobed = call("NtSetThreadExecutionState", ES_CONTINUOUS as u64, 0xFFFF_8000_0000_0000, 0, 0);
    let null = call("NtSetThreadExecutionState", ES_CONTINUOUS as u64, 0, 0, 0);
    assert(
        invalid == STATUS_INVALID_PARAMETER && away_alone == STATUS_INVALID_PARAMETER && unprobed == STATUS_ACCESS_VIOLATION && null == STATUS_ACCESS_VIOLATION,
        "desktop: NtSetThreadExecutionState recusa ES_USER_PRESENT, ES_AWAYMODE_REQUIRED sem ES_CONTINUOUS e PreviousFlags fora do modo usuario",
    );
    // Um estado limpo antes: ES_CONTINUOUS sozinho desliga o que houver.
    let _ = set(ES_CONTINUOUS);
    let (system_before, away_before) = (power_request::active_requests(SYSTEM_REQUIRED), power_request::active_requests(AWAY_MODE_REQUIRED));
    let (on, on_previous) = set(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED);
    let (system_on, away_on) = (power_request::active_requests(SYSTEM_REQUIRED), power_request::active_requests(AWAY_MODE_REQUIRED));
    let (again, again_previous) = set(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED);
    let system_again = power_request::active_requests(SYSTEM_REQUIRED);
    let idle_before = crate::ntos::po::system_state::system_idle_reset();
    let (pulse, pulse_previous) = set(ES_SYSTEM_REQUIRED);
    let system_pulse = power_request::active_requests(SYSTEM_REQUIRED);
    let (off, off_previous) = set(ES_CONTINUOUS);
    let (system_off, away_off) = (power_request::active_requests(SYSTEM_REQUIRED), power_request::active_requests(AWAY_MODE_REQUIRED));
    let (_, cleared_previous) = set(ES_CONTINUOUS);
    assert(
        on == 0 && on_previous & ES_CONTINUOUS != 0 && on_previous & (ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED | ES_AWAYMODE_REQUIRED) == 0
            && system_on == system_before + 1 && away_on == away_before + 1
            && again == 0 && again_previous == ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED && system_again == system_on
            && pulse == 0 && pulse_previous == ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED && system_pulse == system_on
            && crate::ntos::po::system_state::system_idle_reset() >= idle_before
            && off == 0 && off_previous == ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED && system_off == system_before && away_off == away_before
            && cleared_previous == ES_CONTINUOUS,
        "desktop: NtSetThreadExecutionState liga e desliga o pedido legado da thread e devolve as flags anteriores com ES_CONTINUOUS",
    );
}

/// O NtPowerInformation de modo usuário com a saída em rsp+0x28.
fn power(call: Call, rsp: u64, level: u64, input: u64, input_length: u64, output: u64, output_length: u64) -> u32 {
    guest::write64(rsp + 0x28, output_length);
    call("NtPowerInformation", level, input, input_length, output)
}

/// Os níveis 14, 15, 16, 64, 65, 94 e 95 de modo usuário. Com entrada, os
/// níveis 14, 15, 16 e 65 (fora da lista sem privilégio) passam antes pelo
/// SeShutdownPrivilege.
fn power_levels(assert: Assert, block: u64, rsp: u64, call: Call) {
    let (input, output) = (block + 0x200, block + 0x280);
    let with_input = if crate::ntos::se::privilege::single_privilege_check(19, 1) { STATUS_INVALID_PARAMETER } else { 0xC000_0061 };
    guest::write_bytes(output, &[0xEE; 0x10]);
    let wake = power(call, rsp, 14, 0, 0, output, 8);
    let wake_value = guest::read64(output);
    guest::write_bytes(output, &[0xEE; 0x10]);
    let sleep = power(call, rsp, 15, 0, 0, output, 8);
    let sleep_value = guest::read64(output);
    let wake_short = power(call, rsp, 14, 0, 0, output, 4);
    let wake_input = power(call, rsp, 14, input, 4, output, 8);
    let sleep_no_output = power(call, rsp, 15, 0, 0, 0, 0);
    assert(
        wake == 0 && wake_value == 0 && sleep == 0 && sleep_value == 0 && wake_short == STATUS_BUFFER_TOO_SMALL && wake_input == with_input && sleep_no_output == STATUS_INVALID_PARAMETER,
        "desktop: NtPowerInformation 14 e 15 (LastWakeTime/LastSleepTime zero sem transicao de sono)",
    );
    // SystemExecutionState: o ULONG dos pedidos de sistema e de tela.
    guest::write32(output, 0xEEEE_EEEE);
    let execution = power(call, rsp, 16, 0, 0, output, 4);
    let value = guest::read32(output);
    let expected = (if power_request::active_requests(1) != 0 { ES_SYSTEM_REQUIRED } else { 0 }) | (if power_request::active_requests(0) != 0 { ES_DISPLAY_REQUIRED } else { 0 });
    let execution_short = power(call, rsp, 16, 0, 0, output, 2);
    let execution_input = power(call, rsp, 16, input, 4, output, 4);
    assert(
        execution == 0 && value == expected && execution_short == STATUS_BUFFER_TOO_SMALL && execution_input == with_input,
        "desktop: NtPowerInformation 16 (SystemExecutionState pelos pedidos ligados)",
    );
    // SessionLockState: 8 bytes de entrada e nenhuma saída.
    guest::write_bytes(input, &[0u8; 8]);
    let lock = power(call, rsp, 64, input, 8, 0, 0);
    let lock_short = power(call, rsp, 64, input, 4, 0, 0);
    let lock_output = power(call, rsp, 64, input, 8, output, 4);
    let lock_no_input = power(call, rsp, 64, 0, 0, 0, 0);
    // SystemHiberbootState: um BOOLEAN, FALSE sem Hiberboot nas capacidades.
    guest::write8(output, 0xEE);
    let hiberboot = power(call, rsp, 65, 0, 0, output, 1);
    let hiberboot_value = guest::read8(output);
    let hiberboot_input = power(call, rsp, 65, input, 1, output, 1);
    // SessionAllowExternalDmaDevices: um BOOLEAN de entrada e nenhuma saída.
    guest::write8(input, 1);
    let dma = power(call, rsp, 95, input, 1, 0, 0);
    let dma_long = power(call, rsp, 95, input, 2, 0, 0);
    let dma_output = power(call, rsp, 95, input, 1, output, 1);
    assert(
        lock == 0 && lock_short == STATUS_INVALID_PARAMETER && lock_output == STATUS_INVALID_PARAMETER && lock_no_input == STATUS_INVALID_PARAMETER
            && hiberboot == 0 && hiberboot_value == 0 && hiberboot_input == with_input
            && dma == 0 && dma_long == STATUS_INVALID_PARAMETER && dma_output == STATUS_INVALID_PARAMETER,
        "desktop: NtPowerInformation 64, 65 e 95 de modo usuario",
    );
    // UpdateBlackBoxRecorder de modo usuário: o pedido de 32 bytes
    // {Buffer, Length, Offset, Category, Flags}.
    let (request, payload) = (block + 0x300, block + 0x340);
    guest::write_bytes(payload, b"desktop-black-box");
    let black_box = |buffer: u64, length: u64, category: u32, input_length: u64| {
        guest::write64(request, buffer);
        guest::write64(request + 8, length);
        guest::write64(request + 0x10, 0);
        guest::write32(request + 0x18, category);
        guest::write32(request + 0x1C, 0);
        power(call, rsp, 94, request, input_length, 0, 0)
    };
    let recorded = black_box(payload, 17, 1, 0x20);
    let stored = crate::ntos::po::black_box::snapshot(1).is_ok_and(|snapshot| snapshot.bytes == b"desktop-black-box");
    let bad_category = black_box(payload, 17, 22, 0x20);
    let short = black_box(payload, 17, 1, 0x18);
    let unprobed = black_box(0xFFFF_8000_0000_0000, 17, 1, 0x20);
    let with_output = {
        guest::write64(rsp + 0x28, 4);
        call("NtPowerInformation", 94, request, 0x20, output)
    };
    assert(
        recorded == 0 && stored && bad_category == STATUS_INVALID_PARAMETER && short == STATUS_BUFFER_TOO_SMALL && unprobed == STATUS_ACCESS_VIOLATION && with_output == STATUS_INVALID_PARAMETER,
        "desktop: NtPowerInformation 94 de modo usuario grava a categoria com o buffer sondado",
    );
}

/// O COUNTED_REASON_CONTEXT simples em `context` com o texto em `text`.
fn simple_context(context: u64, text: u64, units: &[u16], length: u16) {
    for (index, unit) in units.iter().enumerate() {
        guest::write16(text + index as u64 * 2, *unit);
    }
    guest::write_bytes(context, &[0u8; 0x28]);
    guest::write32(context + 4, 1);
    guest::write16(context + 8, length);
    guest::write16(context + 0xA, length);
    guest::write64(context + 0x10, text);
}

/// Os pedidos de energia de modo usuário: PowerRequestCreate com o contexto
/// capturado de modo usuário, PowerRequestAction pelo handle e o
/// fechamento do último handle, que desconta o tipo ainda ligado.
fn power_requests(assert: Assert, block: u64, rsp: u64, call: Call) {
    let (context, text, handle_out, action) = (block + 0x400, block + 0x480, block + 0x500, block + 0x520);
    let units: alloc::vec::Vec<u16> = "Explorer".encode_utf16().collect();
    simple_context(context, text, &units, 16);
    let live = power_request::live_requests();
    guest::write64(handle_out, 0);
    let created = power(call, rsp, 43, context, 0x28, handle_out, 8);
    let handle = guest::read64(handle_out);
    let short_input = power(call, rsp, 43, context, 0x20, handle_out, 8);
    let short_output = power(call, rsp, 43, context, 0x28, handle_out, 4);
    let no_output = power(call, rsp, 43, context, 0x28, 0, 0);
    // Um NUL no meio do texto, Length ímpar e o Buffer desalinhado.
    simple_context(context, text, &[0x41, 0, 0x42], 6);
    let embedded_nul = power(call, rsp, 43, context, 0x28, handle_out, 8);
    simple_context(context, text, &units, 15);
    let odd = power(call, rsp, 43, context, 0x28, handle_out, 8);
    simple_context(context, text + 1, &units, 16);
    let misaligned = power(call, rsp, 43, context, 0x28, handle_out, 8);
    simple_context(context, 0xFFFF_8000_0000_0000, &[], 16);
    let unprobed = power(call, rsp, 43, context, 0x28, handle_out, 8);
    assert(
        created == 0 && handle != 0 && power_request::live_requests() == live + 1
            && short_input == STATUS_BUFFER_TOO_SMALL && short_output == STATUS_BUFFER_TOO_SMALL && no_output == STATUS_INVALID_PARAMETER
            && embedded_nul == STATUS_INVALID_PARAMETER && odd == STATUS_INVALID_PARAMETER && misaligned == STATUS_DATATYPE_MISALIGNMENT && unprobed == STATUS_ACCESS_VIOLATION,
        "desktop: NtPowerInformation 43 cria o pedido de modo usuario e captura o contexto com sondas",
    );
    // PowerRequestAction {Handle, RequestType, SetAction, ProcessHandle}.
    let act = |target: u64, kind: u32, set: bool, length: u64| {
        guest::write_bytes(action, &[0u8; 0x18]);
        guest::write64(action, target);
        guest::write32(action + 8, kind);
        guest::write8(action + 0xC, set as u8);
        power(call, rsp, 44, action, length, 0, 0)
    };
    let before = power_request::active_requests(SYSTEM_REQUIRED);
    let set_system = act(handle, 1, true, 0x18);
    let after_set = power_request::active_requests(SYSTEM_REQUIRED);
    let set_twice = act(handle, 1, true, 0x18);
    let clear_once = act(handle, 1, false, 0x18);
    let still_on = power_request::active_requests(SYSTEM_REQUIRED);
    let clear_last = act(handle, 1, false, 0x18);
    let clear_off = act(handle, 1, false, 0x18);
    let out_of_range = act(handle, 6, true, 0x18);
    let short_action = act(handle, 1, true, 0x10);
    let bad_handle = act(0x7FF8, 1, true, 0x18);
    guest::write32(rsp + 0x28, 0);
    guest::write32(rsp + 0x30, 0);
    let event_created = call("NtCreateEvent", handle_out, 0x1F_0003, 0, 0);
    let event = guest::read64(handle_out);
    let wrong_type = act(event, 1, true, 0x18);
    let _ = call("NtClose", event, 0, 0, 0);
    assert(
        set_system == 0 && after_set == before + 1 && set_twice == 0 && clear_once == 0 && still_on == before + 1 && clear_last == 0 && power_request::active_requests(SYSTEM_REQUIRED) == before
            && clear_off == STATUS_NOT_SUPPORTED && out_of_range == STATUS_NOT_SUPPORTED && short_action == STATUS_BUFFER_TOO_SMALL
            && bad_handle == STATUS_INVALID_HANDLE && event_created == 0 && wrong_type == STATUS_OBJECT_TYPE_MISMATCH,
        "desktop: NtPowerInformation 44 liga e desliga o tipo pelo handle e recusa tipo, handle e tamanho invalidos",
    );
    // O fechamento do último handle limpa o pedido com o tipo ligado.
    let relit = act(handle, 1, true, 0x18);
    let closed = call("NtClose", handle, 0, 0, 0);
    assert(
        relit == 0 && closed == 0 && power_request::active_requests(SYSTEM_REQUIRED) == before && power_request::live_requests() == live,
        "desktop: o NtClose do pedido de energia desconta o tipo ligado e o tira da lista",
    );
    // PlmPowerRequestCreate: o pedido especial do PLM.
    simple_context(context, text, &units, 16);
    let plm = power(call, rsp, 72, context, 0x28, handle_out, 8);
    let plm_handle = guest::read64(handle_out);
    let plm_closed = call("NtClose", plm_handle, 0, 0, 0);
    assert(plm == 0 && plm_handle != 0 && plm_closed == 0 && power_request::live_requests() == live, "desktop: NtPowerInformation 72 cria e fecha o pedido especial");
}

/// O arquivo do volume dos testes de gravação.
const FLUSH_FILE: &str = "\\??\\D:\\OPENNTFLUSHVM.BIN";

/// NtFlushVirtualMemory numa vista de arquivo do volume (a faixa alinhada,
/// o tamanho dela, o IoStatus e os bytes no arquivo), numa região privada e
/// com as faixas e o handle recusados; NtFlushBuffersFileEx e o
/// NtFlushBuffersFile com o acesso, os parâmetros e a sonda.
fn flushes(assert: Assert, block: u64, rsp: u64, call: Call) {
    let (out, iosb, cells, data) = (block + 0x600, block + 0x610, block + 0x640, block + 0x1000);
    let open = |access: u32, disposition: u32| {
        guest::write64(out, 0);
        let status = file_io::open(out, FLUSH_FILE, iosb, disposition, &OpenRequest { access, share: 7, options: 0x20, ..OpenRequest::default() }).unwrap_or(1);
        (status, guest::read64(out))
    };
    let (created, file) = open(0xC010_0000, 5);
    guest::write_bytes(data, &[0x5A; 0x2000]);
    guest::write64(rsp + 0x28, iosb);
    guest::write64(rsp + 0x30, data);
    guest::write32(rsp + 0x38, 0x2000);
    guest::write64(rsp + 0x40, 0);
    guest::write64(rsp + 0x48, 0);
    let written = call("NtWriteFile", file, 0, 0, 0);
    // NtCreateSection(handle*, SECTION_ALL_ACCESS, NULL, &0, PAGE_READWRITE,
    // SEC_COMMIT, file) e a vista inteira no processo corrente.
    guest::write64(cells, 0);
    guest::write64(rsp + 0x28, 4);
    guest::write64(rsp + 0x30, 0x0800_0000);
    guest::write64(rsp + 0x38, file);
    let section_created = call("NtCreateSection", cells + 8, 0xF_001F, 0, cells);
    let section = guest::read64(cells + 8);
    guest::write64(cells + 0x10, 0);
    guest::write64(cells + 0x18, 0);
    guest::write64(cells + 0x20, 0);
    guest::write64(rsp + 0x28, 0);
    guest::write64(rsp + 0x30, cells + 0x18);
    guest::write64(rsp + 0x38, cells + 0x20);
    guest::write64(rsp + 0x40, 2);
    guest::write64(rsp + 0x48, 0);
    guest::write64(rsp + 0x50, 4);
    let mapped = call("NtMapViewOfSection", section, u64::MAX, cells + 0x10, 0);
    let view = guest::read64(cells + 0x10);
    assert(
        created == 0 && written == 0 && section_created == 0 && mapped == 0 && view != 0,
        &alloc::format!("desktop: vista de arquivo do volume para o NtFlushVirtualMemory (abertura {created:#x}, escrita {written:#x}, secao {section_created:#x}, vista {mapped:#x}, {:?})", crate::ntos::io::file::query::resolve(file, true).map(|selected| (selected.access, crate::ntos::io::file::zw::file_backing(selected.pointer).map(|(volume, path)| (volume.writable(), volume.stat(&path).map(|stat| stat.attributes)))))),
    );
    if view == 0 {
        return;
    }
    guest::write_bytes(view + 0x1010, b"flushed!");
    let (base_cell, size_cell) = (cells + 0x30, cells + 0x38);
    let flush = |process: u64, base: u64, size: u64| {
        guest::write64(base_cell, base);
        guest::write64(size_cell, size);
        guest::write_bytes(iosb, &[0xEE; 16]);
        call("NtFlushVirtualMemory", process, base_cell, size_cell, iosb)
    };
    let flushed = flush(u64::MAX, view + 0x1010, 0x10);
    let (aligned, length, io_status, information) = (guest::read64(base_cell), guest::read64(size_cell), guest::read32(iosb), guest::read64(iosb + 8));
    let on_disk = file_io::volume_open(file).ok().and_then(|(_, opened)| opened.file.read_at(0x1010, 8).ok()).is_some_and(|bytes| bytes == b"flushed!");
    assert(
        flushed == 0 && aligned == view + 0x1000 && length == 0x1000 && io_status == 0 && information == 0 && on_disk,
        "desktop: NtFlushVirtualMemory grava a vista de arquivo e devolve a faixa alinhada e o IoStatus",
    );
    let private = flush(u64::MAX, block, 0x1000);
    let private_size = guest::read64(size_cell);
    let high = flush(u64::MAX, 0x7FFF_FFFF_0000, 0);
    let long = flush(u64::MAX, 0x7FFF_FFFE_F000, 0x2_0000);
    let bad_handle = flush(0x7FF8, view, 0x1000);
    let unprobed = call("NtFlushVirtualMemory", u64::MAX, base_cell, 0xFFFF_8000_0000_0000, iosb);
    assert(
        private == 0xC000_0019 && private_size == 0x1000 && high == 0xC000_00F0 && long == 0xC000_00F1 && bad_handle == STATUS_INVALID_HANDLE && unprobed == STATUS_ACCESS_VIOLATION,
        "desktop: NtFlushVirtualMemory recusa a regiao privada, as faixas, o handle e o ponteiro de kernel",
    );
    // NtAreMappedFilesTheSame: a mesma alocação, um endereço de kernel, a
    // memória privada e duas vistas de dados do mesmo arquivo (a primeira
    // não é imagem, então não é a control area de imagem do arquivo).
    guest::write64(cells + 0x40, 0);
    guest::write64(cells + 0x48, 0);
    guest::write64(cells + 0x50, 0);
    guest::write64(rsp + 0x28, 0);
    guest::write64(rsp + 0x30, cells + 0x48);
    guest::write64(rsp + 0x38, cells + 0x50);
    guest::write64(rsp + 0x40, 2);
    guest::write64(rsp + 0x48, 0);
    guest::write64(rsp + 0x50, 4);
    let remapped = call("NtMapViewOfSection", section, u64::MAX, cells + 0x40, 0);
    let second_view = guest::read64(cells + 0x40);
    let same_allocation = call("NtAreMappedFilesTheSame", view, view + 0x1000, 0, 0);
    let kernel_address = call("NtAreMappedFilesTheSame", view, 0xFFFF_8000_0000_0000, 0, 0);
    let private = call("NtAreMappedFilesTheSame", block, view, 0, 0);
    let data_views = call("NtAreMappedFilesTheSame", view, second_view, 0, 0);
    assert(
        remapped == 0 && second_view != 0 && second_view != view && same_allocation == 0 && kernel_address == 0xC000_0141 && private == 0xC000_0018 && data_views == 0xC000_00D4,
        "desktop: NtAreMappedFilesTheSame pela alocacao, pela memoria privada e pela control area de imagem",
    );
    let _ = call("NtUnmapViewOfSection", u64::MAX, second_view, 0, 0);
    let _ = call("NtUnmapViewOfSection", u64::MAX, view, 0, 0);
    let _ = call("NtClose", section, 0, 0, 0);
    // Uma seção maior que o arquivo aberto com escrita pelo modo usuário (o
    // CreateFileMapping do explorer no Caches\cversions.2.db novo): o
    // MmCreateSection do 19041 estende o arquivo até o MaximumSize.
    guest::write64(cells + 0x58, 0x3000);
    guest::write64(cells + 0x60, 0);
    guest::write64(rsp + 0x28, 4);
    guest::write64(rsp + 0x30, 0x0800_0000);
    guest::write64(rsp + 0x38, file);
    let grown = call("NtCreateSection", cells + 0x60, 0xF_001F, 0, cells + 0x58);
    let grown_size = file_io::volume_open(file).ok().map(|(_, opened)| {
        opened.file.refresh();
        opened.file.size()
    });
    let _ = call("NtClose", guest::read64(cells + 0x60), 0, 0, 0);
    assert(grown == 0 && grown_size == Some(0x3000), &alloc::format!("desktop: NtCreateSection maior que o arquivo aberto com escrita estende o arquivo ({grown:#x}, {grown_size:?})"));
    // NtFlushBuffersFileEx(handle, flags, parameters, size, iosb).
    let flush_ex = |handle: u64, flags: u64, parameters: u64, size: u64, io_status: u64| {
        guest::write64(rsp + 0x28, io_status);
        guest::write_bytes(iosb, &[0xEE; 16]);
        call("NtFlushBuffersFileEx", handle, flags, parameters, size)
    };
    let plain = flush_ex(file, 0, 0, 0, iosb);
    let plain_iosb = guest::read32(iosb);
    let data_only = flush_ex(file, 1, 0, 0, iosb);
    let with_parameters = flush_ex(file, 0, data, 0, iosb);
    let with_size = flush_ex(file, 0, 0, 4, iosb);
    let bad_iosb = flush_ex(file, 0, 0, 0, 0xFFFF_8000_0000_0000);
    let bad_handle = flush_ex(0x7FF8, 0, 0, 0, iosb);
    let _ = state::close_user_handle(file, true, false);
    let (_, reader) = open(0x8010_0000, 1);
    let read_only = flush_ex(reader, 0, 0, 0, iosb);
    let read_only_iosb = guest::read32(iosb);
    let _ = state::close_user_handle(reader, true, false);
    let (_, attributes_only) = open(0x0010_0100, 1);
    let attributes_flush = call("NtFlushBuffersFile", attributes_only, iosb, 0, 0);
    let _ = state::close_user_handle(attributes_only, true, false);
    assert(
        plain == 0 && plain_iosb == 0 && data_only == 0 && with_parameters == STATUS_INVALID_PARAMETER && with_size == STATUS_INVALID_PARAMETER
            && bad_iosb == STATUS_ACCESS_VIOLATION && bad_handle == STATUS_INVALID_HANDLE && read_only == 0xC000_0022 && read_only_iosb == 0xEEEE_EEEE
            && attributes_flush == 0xC000_0022,
        "desktop: NtFlushBuffersFileEx e NtFlushBuffersFile pedem FILE_WRITE_DATA ou FILE_APPEND_DATA e recusam parametros",
    );
}

/// O arquivo PE do volume do teste das vistas de imagem.
const IMAGE_FILE: &str = "\\??\\D:\\OPENNTIMAGEVM.DLL";

/// NtAreMappedFilesTheSame com vistas de imagem, como o
/// LdrpFindLoadedDllByMappingLockHeld da ntdll o chama (a base de uma DLL
/// já carregada e a da imagem que acabou de mapear): as vistas de duas
/// seções de imagem do mesmo arquivo PE, cada uma de uma abertura (o
/// LoadLibrary do mesmo arquivo por outro caminho), dão STATUS_SUCCESS, e a
/// ntdll usa o módulo que já existe; a vista de imagem contra uma vista de
/// dados do mesmo arquivo também (a control area da primeira é o
/// ImageSectionObject do arquivo da segunda); a de dados contra a de
/// imagem, STATUS_NOT_SAME_DEVICE.
fn mapped_images(assert: Assert, block: u64, rsp: u64, call: Call) {
    let (out, iosb, cells, data) = (block + 0x600, block + 0x610, block + 0x640, block + 0x1000);
    let open = |access: u32, disposition: u32| {
        guest::write64(out, 0);
        let status = file_io::open(out, IMAGE_FILE, iosb, disposition, &OpenRequest { access, share: 7, options: 0x20, ..OpenRequest::default() }).unwrap_or(1);
        (status, guest::read64(out))
    };
    // O PE mínimo gravado no arquivo, e o handle de escrita fechado antes
    // da seção de imagem.
    let image = super::phase7::minimal_image();
    let (created, writer) = open(0xC010_0000, 5);
    guest::write_bytes(data, &image);
    guest::write64(rsp + 0x28, iosb);
    guest::write64(rsp + 0x30, data);
    guest::write32(rsp + 0x38, image.len() as u32);
    guest::write64(rsp + 0x40, 0);
    guest::write64(rsp + 0x48, 0);
    let written = call("NtWriteFile", writer, 0, 0, 0);
    let _ = state::close_user_handle(writer, true, false);
    // GENERIC_READ | GENERIC_EXECUTE | SYNCHRONIZE, como a ntdll abre a DLL,
    // duas vezes.
    let (opened, file) = open(0xA010_0000, 1);
    let (reopened, other_file) = open(0xA010_0000, 1);
    // NtCreateSection(handle*, SECTION_ALL_ACCESS, NULL, NULL, protect,
    // attributes, file): SEC_IMAGE com PAGE_EXECUTE e SEC_COMMIT com
    // PAGE_READONLY.
    let section = |file: u64, protect: u64, attributes: u64| {
        guest::write64(cells, 0);
        guest::write64(rsp + 0x28, protect);
        guest::write64(rsp + 0x30, attributes);
        guest::write64(rsp + 0x38, file);
        (call("NtCreateSection", cells, 0xF_001F, 0, 0), guest::read64(cells))
    };
    // NtMapViewOfSection(section, NtCurrentProcess, base*, 0, 0, NULL,
    // size*, ViewUnmap, 0, protect) no processo corrente.
    let map = |section: u64, protect: u64| {
        guest::write64(cells + 0x10, 0);
        guest::write64(cells + 0x18, 0);
        guest::write64(rsp + 0x28, 0);
        guest::write64(rsp + 0x30, 0);
        guest::write64(rsp + 0x38, cells + 0x18);
        guest::write64(rsp + 0x40, 2);
        guest::write64(rsp + 0x48, 0);
        guest::write64(rsp + 0x50, protect);
        (call("NtMapViewOfSection", section, u64::MAX, cells + 0x10, 0), guest::read64(cells + 0x10))
    };
    let (image_created, image_section) = section(file, 0x10, 0x0100_0000);
    let (other_created, other_section) = section(other_file, 0x10, 0x0100_0000);
    let (first_mapped, first) = map(image_section, 0x80);
    let (second_mapped, second) = map(other_section, 0x80);
    let (data_created, data_section) = section(file, 2, 0x0800_0000);
    let (data_mapped, data_view) = map(data_section, 2);
    let image_status = |status: u32| status == 0 || status == 0x4000_0003;
    let ready = created == 0 && written == 0 && opened == 0 && reopened == 0 && image_created == 0 && other_created == 0 && image_status(first_mapped) && image_status(second_mapped) && data_created == 0 && data_mapped == 0;
    assert(
        ready && first != 0 && second != 0 && first != second && data_view != 0,
        &alloc::format!("desktop: duas vistas de imagem e uma de dados do mesmo PE (arquivo {created:#x}/{written:#x}/{opened:#x}/{reopened:#x}, secoes de imagem {image_created:#x} {other_created:#x}, vistas {first_mapped:#x} {second_mapped:#x}, secao de dados {data_created:#x}, vista {data_mapped:#x})"),
    );
    if ready {
        let images = call("NtAreMappedFilesTheSame", first, second, 0, 0);
        let image_then_data = call("NtAreMappedFilesTheSame", second, data_view + 0x10, 0, 0);
        let data_then_image = call("NtAreMappedFilesTheSame", data_view, first, 0, 0);
        assert(
            images == 0 && image_then_data == 0 && data_then_image == 0xC000_00D4,
            &alloc::format!("desktop: NtAreMappedFilesTheSame com vistas de imagem do mesmo arquivo (imagem e imagem {images:#x}, imagem e dados {image_then_data:#x}, dados e imagem {data_then_image:#x})"),
        );
    }
    for view in [first, second, data_view].into_iter().filter(|&view| view != 0) {
        let _ = call("NtUnmapViewOfSection", u64::MAX, view, 0, 0);
    }
    for handle in [image_section, other_section, data_section].into_iter().filter(|&handle| handle != 0) {
        let _ = call("NtClose", handle, 0, 0, 0);
    }
    for handle in [file, other_file].into_iter().filter(|&handle| handle != 0) {
        let _ = state::close_user_handle(handle, true, false);
    }
}

/// NtGetCachedSigningLevel num arquivo do volume sem o cache de assinatura
/// (com a ci.dll inicializada, STATUS_NOT_FOUND, o único status que o
/// AppXDeploymentServer aceita; sem ela, o slot nulo da SeCiCallbacks dá
/// STATUS_UNSUCCESSFUL, como no 19041; nos dois casos sem tocar as saídas),
/// as recusas dos parâmetros e do handle, e o NtCompareSigningLevels
/// (Windows contra Store e não assinado contra Store; sem CI, o callback
/// ausente vale FALSE).
fn signing_levels(assert: Assert, block: u64, rsp: u64, call: Call) {
    use crate::ntos::se::code_integrity::{self, SigningCallback};
    let (out, iosb, flags, level, size, algorithm, thumbprint) = (block + 0x700, block + 0x710, block + 0x720, block + 0x724, block + 0x728, block + 0x72C, block + 0x740);
    guest::write64(out, 0);
    let opened = file_io::open(out, FLUSH_FILE, iosb, 1, &OpenRequest { access: 0x8010_0000, share: 7, options: 0x20, ..OpenRequest::default() }).unwrap_or(1);
    let file = guest::read64(out);
    let get = |handle: u64, flags_out: u64, level_out: u64| {
        guest::write32(flags, 0xEEEE_EEEE);
        guest::write8(level, 0xEE);
        guest::write32(size, 0x40);
        guest::write64(rsp + 0x28, size);
        guest::write64(rsp + 0x30, algorithm);
        call("NtGetCachedSigningLevel", handle, flags_out, level_out, thumbprint)
    };
    let uncached = get(file, flags, level);
    let untouched = guest::read32(flags) == 0xEEEE_EEEE && guest::read8(level) == 0xEE && guest::read32(size) == 0x40;
    let no_file = get(0, flags, level);
    let no_flags = get(file, 0, level);
    let no_level = get(file, flags, 0);
    let bad_handle = get(0x7FF8, flags, level);
    let _ = state::close_user_handle(file, true, false);
    let ci = code_integrity::signing_callback(SigningCallback::GetFileCache) != 0;
    let expected_uncached = if ci { 0xC000_0225 } else { 0xC000_0001 };
    assert(
        opened == 0 && uncached == expected_uncached && untouched && no_file == STATUS_INVALID_PARAMETER && no_flags == STATUS_INVALID_PARAMETER && no_level == STATUS_INVALID_PARAMETER && bad_handle == STATUS_INVALID_HANDLE,
        &alloc::format!("desktop: NtGetCachedSigningLevel de arquivo sem cache devolve STATUS_NOT_FOUND pela ci.dll e recusa os parametros nulos (abertura {opened:#x}, ci {ci}, sem cache {uncached:#x}, intactas {untouched}, nulos {no_file:#x}/{no_flags:#x}/{no_level:#x}, handle {bad_handle:#x})"),
    );
    let compare_slot = code_integrity::signing_callback(SigningCallback::CompareSigningLevels) != 0;
    let windows_over_store = call("NtCompareSigningLevels", 0xC, 6, 0, 0);
    let unsigned_under_store = call("NtCompareSigningLevels", 1, 6, 0, 0);
    assert(
        windows_over_store == if compare_slot { 0 } else { 0xC000_0428 } && unsigned_under_store == 0xC000_0428,
        "desktop: NtCompareSigningLevels: Windows satisfaz Store pela ci.dll e nao assinado da STATUS_INVALID_IMAGE_HASH",
    );
}

/// Um FILE_FULL_EA_INFORMATION único em `at`: o comprimento.
fn full_ea(at: u64, name: &[u8], value: &[u8]) -> u64 {
    guest::write32(at, 0);
    guest::write8(at + 4, 0);
    guest::write8(at + 5, name.len() as u8);
    guest::write16(at + 6, value.len() as u16);
    guest::write_bytes(at + 8, name);
    guest::write8(at + 8 + name.len() as u64, 0);
    guest::write_bytes(at + 9 + name.len() as u64, value);
    9 + name.len() as u64 + value.len() as u64
}

/// NtSetEaFile e NtQueryEaFile de modo usuário num arquivo do volume: a EA
/// gravada e lida (pela lista de nomes também), o `$KERNEL.` ignorado do
/// modo usuário, a lista FILE_GET_EA_INFORMATION conferida, o alinhamento e
/// os acessos FILE_WRITE_EA e FILE_READ_EA.
fn extended_attributes(assert: Assert, block: u64, rsp: u64, call: Call) {
    let (out, iosb, ea, names, buffer) = (block + 0x800, block + 0x810, block + 0x840, block + 0x8C0, block + 0x900);
    let open = |access: u32| {
        guest::write64(out, 0);
        let status = file_io::open(out, FLUSH_FILE, iosb, 1, &OpenRequest { access, share: 7, options: 0x20, ..OpenRequest::default() }).unwrap_or(1);
        (status, guest::read64(out))
    };
    let set = |handle: u64, at: u64, length: u64| {
        guest::write_bytes(iosb, &[0xEE; 16]);
        call("NtSetEaFile", handle, iosb, at, length)
    };
    // NtQueryEaFile(handle, iosb, buffer, length, single, list, listLength,
    // index, restart).
    let query = |handle: u64, at: u64, length: u64, list: u64, list_length: u64| {
        guest::write_bytes(iosb, &[0xEE; 16]);
        guest::write_bytes(buffer, &[0; 0x80]);
        guest::write64(rsp + 0x28, 1);
        guest::write64(rsp + 0x30, list);
        guest::write64(rsp + 0x38, list_length);
        guest::write64(rsp + 0x40, 0);
        guest::write64(rsp + 0x48, 1);
        call("NtQueryEaFile", handle, iosb, at, length)
    };
    let (opened, file) = open(0x0012_019F);
    let length = full_ea(ea, b"DESKTOP", b"value");
    let stored = set(file, ea, length);
    let stored_iosb = guest::read32(iosb);
    let read = query(file, buffer, 0x80, 0, 0);
    let read_entry = guest::read8(buffer + 5) == 7 && guest::read16(buffer + 6) == 5 && guest::read_bytes(buffer + 8, 7) == b"DESKTOP" && guest::read_bytes(buffer + 16, 5) == b"value";
    let read_information = guest::read64(iosb + 8);
    // FILE_GET_EA_INFORMATION {NextEntryOffset, EaNameLength, EaName}.
    guest::write32(names, 0);
    guest::write8(names + 4, 7);
    guest::write_bytes(names + 5, b"DESKTOP\0");
    let by_name = query(file, buffer, 0x80, names, 13);
    let by_name_entry = guest::read_bytes(buffer + 16, 5) == b"value";
    let short_list = query(file, buffer, 0x80, names, 3);
    let short_list_iosb = (guest::read32(iosb), guest::read64(iosb + 8));
    guest::write32(names, 4);
    let bad_next = query(file, buffer, 0x80, names, 13);
    let bad_next_iosb = (guest::read32(iosb), guest::read64(iosb + 8));
    guest::write32(names, 0);
    let misaligned = query(file, buffer + 1, 0x40, 0, 0);
    let unprobed = set(file, 0xFFFF_8000_0000_0000, length);
    assert(
        opened == 0 && stored == 0 && stored_iosb == 0 && read == 0 && read_entry && read_information != 0 && by_name == 0 && by_name_entry
            && short_list == 0x8000_0014 && short_list_iosb == (0x8000_0014, 0) && bad_next == 0x8000_0014 && bad_next_iosb == (0x8000_0014, 0)
            && misaligned == STATUS_DATATYPE_MISALIGNMENT && unprobed == STATUS_ACCESS_VIOLATION,
        &alloc::format!("desktop: NtSetEaFile e NtQueryEaFile de modo usuario gravam e leem a EA e conferem a lista e as sondas ({opened:#x} {stored:#x}/{stored_iosb:#x} {read:#x}/{read_entry}/{read_information:#x} {by_name:#x}/{by_name_entry} {short_list:#x}/{short_list_iosb:x?} {bad_next:#x}/{bad_next_iosb:x?} {misaligned:#x} {unprobed:#x})"),
    );
    // A EA de kernel não é gravada pelo modo usuário: o pedido tem sucesso
    // e a consulta pelo nome não a encontra.
    let kernel_length = full_ea(ea, b"$KERNEL.DESKTOP", b"forged");
    let kernel_set = set(file, ea, kernel_length);
    guest::write32(names, 0);
    guest::write8(names + 4, 15);
    guest::write_bytes(names + 5, b"$KERNEL.DESKTOP\0");
    let kernel_read = query(file, buffer, 0x80, names, 21);
    let kernel_absent = guest::read16(buffer + 6) == 0;
    let _ = state::close_user_handle(file, true, false);
    // Acessos: sem FILE_WRITE_EA e sem FILE_READ_EA.
    let (_, reader) = open(0x8010_0000);
    let write_denied = set(reader, ea, length);
    let write_denied_iosb = guest::read32(iosb);
    let _ = state::close_user_handle(reader, true, false);
    let (_, data_only) = open(0x0010_0001);
    let read_denied = query(data_only, buffer, 0x80, 0, 0);
    let _ = state::close_user_handle(data_only, true, false);
    assert(
        kernel_set == 0 && kernel_read == 0 && kernel_absent && write_denied == 0xC000_0022 && write_denied_iosb == 0xEEEE_EEEE && read_denied == 0xC000_0022,
        &alloc::format!("desktop: o modo usuario nao grava EA $KERNEL e os servicos de EA pedem FILE_WRITE_EA e FILE_READ_EA ({kernel_set:#x} {kernel_read:#x}/{kernel_absent} {write_denied:#x}/{write_denied_iosb:#x} {read_denied:#x})"),
    );
}

/// NtCancelSynchronousIoFile numa thread sem E/S síncrona pendente (a
/// própria): STATUS_NOT_FOUND no retorno e no IO_STATUS_BLOCK; o handle
/// inválido e o IO_STATUS_BLOCK de kernel recusados.
fn cancel_synchronous_io(assert: Assert, block: u64, call: Call) {
    let iosb = block + 0xA00;
    let cancel = |thread: u64, io_status: u64| {
        guest::write_bytes(iosb, &[0xEE; 16]);
        call("NtCancelSynchronousIoFile", thread, 0, io_status, 0)
    };
    let idle = cancel(u64::MAX - 1, iosb);
    let idle_iosb = (guest::read32(iosb), guest::read64(iosb + 8));
    let bad_handle = cancel(0x7FF8, iosb);
    let bad_handle_iosb = guest::read32(iosb);
    let unprobed = cancel(u64::MAX - 1, 0xFFFF_8000_0000_0000);
    assert(
        idle == 0xC000_0225 && idle_iosb == (0xC000_0225, 0) && bad_handle == STATUS_INVALID_HANDLE && bad_handle_iosb == 0xEEEE_EEEE && unprobed == STATUS_ACCESS_VIOLATION,
        &alloc::format!("desktop: NtCancelSynchronousIoFile sem E/S sincrona pendente devolve STATUS_NOT_FOUND ({idle:#x}/{idle_iosb:x?} {bad_handle:#x}/{bad_handle_iosb:#x} {unprobed:#x})"),
    );
}

/// O arquivo do volume do teste do NtDeleteFile.
const DELETE_FILE: &str = "\\??\\D:\\OPENNTDELETE.BIN";

/// NtDeleteFile pelo OBJECT_ATTRIBUTES de modo usuário: o arquivo some (a
/// abertura seguinte e o segundo pedido dão STATUS_OBJECT_NAME_NOT_FOUND) e
/// um OBJECT_ATTRIBUTES de tamanho errado é recusado.
fn delete_file(assert: Assert, block: u64, call: Call) {
    let (out, iosb, attributes, name, text) = (block + 0xB00, block + 0xB10, block + 0xB40, block + 0xB80, block + 0xBA0);
    let open = |disposition: u32| {
        guest::write64(out, 0);
        let status = file_io::open(out, DELETE_FILE, iosb, disposition, &OpenRequest { access: 0xC010_0000, share: 7, options: 0x20, ..OpenRequest::default() }).unwrap_or(1);
        (status, guest::read64(out))
    };
    let (created, file) = open(5);
    let _ = state::close_user_handle(file, true, false);
    let units: alloc::vec::Vec<u16> = DELETE_FILE.encode_utf16().collect();
    for (index, unit) in units.iter().enumerate() {
        guest::write16(text + index as u64 * 2, *unit);
    }
    guest::write16(name, units.len() as u16 * 2);
    guest::write16(name + 2, units.len() as u16 * 2);
    guest::write32(name + 4, 0);
    guest::write64(name + 8, text);
    guest::write_bytes(attributes, &[0u8; 0x30]);
    guest::write32(attributes, 0x30);
    guest::write64(attributes + 0x10, name);
    guest::write32(attributes + 0x18, 0x40);
    let deleted = call("NtDeleteFile", attributes, 0, 0, 0);
    let (reopened, _) = open(1);
    let again = call("NtDeleteFile", attributes, 0, 0, 0);
    guest::write32(attributes, 0x20);
    let bad_length = call("NtDeleteFile", attributes, 0, 0, 0);
    assert(
        created == 0 && deleted == 0 && reopened == 0xC000_0034 && again == 0xC000_0034 && bad_length == STATUS_INVALID_PARAMETER,
        &alloc::format!("desktop: NtDeleteFile retira o arquivo do volume pelo OBJECT_ATTRIBUTES de modo usuario ({created:#x} {deleted:#x} {reopened:#x} {again:#x} {bad_length:#x})"),
    );
}
