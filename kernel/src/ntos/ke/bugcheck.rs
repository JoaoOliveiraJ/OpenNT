//! KeBugCheckEx (o KeBugCheck2 do ntoskrnl 19041) e os callbacks de bugcheck
//! dos drivers.
//!
//! A sequência, na ordem do KeBugCheck2 (rva 0x516a10):
//! 1. KiBugCheckActive: o primeiro processador grava `(número << 4) | 3`; um
//!    segundo processador que entra fica girando até ser congelado, e um
//!    bugcheck aninhado no mesmo processador soma 4 e para a máquina;
//! 2. KiBugCheckData recebe o código e os quatro parâmetros, e a linha
//!    `*** STOP (KeBugCheckEx)` vai para a serial, seguida do bloco de
//!    diagnóstico `[kcrash]` do OpenNT (`bugcheck_trace`: a exceção ou a
//!    chamada que levou à parada, os registradores e a pilha);
//! 3. com o depurador do kernel ligado, a máquina para nele antes de tudo
//!    (DBG_STATUS_BUGCHECK_FIRST), menos no MANUALLY_INITIATED_CRASH (0xE2),
//!    que o KeBugCheck2 pula;
//! 4. interrupções desligadas, IRQL HIGH_LEVEL e os outros processadores
//!    congelados pela NMI (KiSendFreeze);
//! 5. KiDisplayBlueScreen: o KiBugCheckDriver é o driver que contém um dos
//!    parâmetros (KiDumpParameterImages, fora o VerifierExt.sys), o nome do
//!    código sai da tabela de mensagens da imagem do kernel
//!    (KeGetBugMessageText sobre o KiBugCodeMessages; sem mensagem,
//!    `0x%08x`), o vídeo volta ao kernel (InbvAcquireDisplayOwnership) e a
//!    tela é desenhada (`bgk/bugcheck_screen`) com as flags: 4 sem despejo
//!    configurado, 2 sem reinício automático;
//! 6. os callbacks de entrada (KiInvokeBugCheckEntryCallbacks: os de motivo
//!    KbCallbackReserved1, com dados nulos);
//! 7. o despejo, quando o CrashControl o configura: no OpenNT ele vai para a
//!    serial (os dados secundários dos callbacks de motivo
//!    KbCallbackSecondaryDumpData e o black box), com o progresso na tela;
//! 8. os callbacks de KeRegisterBugCheckCallback (KiScanBugCheckCallbackList:
//!    a lista na ordem da inserção pela cabeça, cada registro conferido —
//!    vínculos, checksum e estado inserido — antes de a rotina rodar com
//!    (Buffer, Length));
//! 9. com o AutoReboot, os processadores voltam a rodar e a máquina reinicia
//!    (HalReturnToFirmware); sem ele, o depurador recebe a segunda parada
//!    (DBG_STATUS_BUGCHECK_SECOND) e a máquina para.
//!
//! O AutoReboot e o despejo vêm de `Control\CrashControl`, lidos no boot
//! como o IopReadDumpRegistry ([`read_crash_control`]). Antes de o handler
//! ser instalado (início do boot) o bugcheck só imprime o código STOP e os
//! quatro parâmetros e para a CPU. Os callbacks de motivo que pertencem à
//! escrita de um arquivo de despejo (DumpIo, AddPages, RemovePages, as
//! partes múltiplas e a triagem) não rodam: o OpenNT não grava MEMORY.DMP.
//! Um bugcheck num processador secundário não congela o de boot (a NMI de
//! congelamento só existe nos processadores secundários).

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use super::{bugcheck_reason, bugcheck_trace, irql};
use crate::hal::amd64::native_call;
use crate::hal::{cpu, firmware_return};
use crate::ntos::bgk::bugcheck_screen::{self, Text, FLAG_NO_AUTO_REBOOT, FLAG_NO_DUMP};
use crate::ntos::inc::types::extra_ke_misc::KbugcheckCallbackRecord;
use crate::ntos::inc::types::{Field, ListEntry, NtStruct};
use crate::ntos::mm::{guest_memory as guest, kernel_data, loaded_images, memory_map};
use crate::ntos::po::black_box;
use crate::rtl::SpinLock;

/// O kernel completou a inicialização do bugcheck ([`init`]).
static READY: AtomicBool = AtomicBool::new(false);
/// KiBugCheckActive: `(processador << 4) | 3` e, nos bits 2-3, a contagem de
/// bugchecks aninhados.
static ACTIVE: AtomicU32 = AtomicU32::new(0);
/// IopAutoReboot e o despejo configurado (CrashDumpEnabled != 0).
static AUTO_REBOOT: AtomicBool = AtomicBool::new(false);
static DUMP_ENABLED: AtomicBool = AtomicBool::new(false);
/// KiBugCodeMessages: a MESSAGE_RESOURCE_DATA da imagem do kernel.
static BUG_CODE_MESSAGES: AtomicU64 = AtomicU64::new(0);
static BUG_CODE_MESSAGES_SIZE: AtomicU64 = AtomicU64::new(0);

/// KBUGCHECK_BUFFER_DUMP_STATE.
const BUFFER_EMPTY: u8 = 0;
const BUFFER_INSERTED: u8 = 1;
const BUFFER_STARTED: u8 = 2;
const BUFFER_FINISHED: u8 = 3;

/// KeBugCheckCallbackListHead: a LIST_ENTRY (memória própria) dos
/// KBUGCHECK_CALLBACK_RECORD inseridos (memória do chamador).
static CALLBACK_LIST_HEAD: SpinLock<u64> = SpinLock::new(0);

/// KiBugCheckData: ULONG_PTR[5] (código e os quatro parâmetros).
const BUG_CHECK_DATA_COUNT: usize = 5;
/// MANUALLY_INITIATED_CRASH.
const MANUALLY_INITIATED_CRASH: u32 = 0xE2;
const CRASH_CONTROL: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\CrashControl";

fn callback_record(record: u64) -> &'static KbugcheckCallbackRecord {
    // SAFETY: o registro pertence ao driver enquanto estiver inserido.
    unsafe { KbugcheckCallbackRecord::at(record) }
}

fn list_entry(address: u64) -> &'static ListEntry {
    // SAFETY: a cabeça própria ou o Entry de um registro inserido.
    unsafe { ListEntry::at(address) }
}

/// A cabeça da lista, criada vazia no primeiro uso.
fn callback_list_head() -> u64 {
    let mut head = CALLBACK_LIST_HEAD.lock();
    if *head == 0 {
        let storage = guest::alloc_bytes(ListEntry::SIZE);
        if storage != 0 {
            list_entry(storage).flink.set(storage);
            list_entry(storage).blink.set(storage);
            *head = storage;
        }
    }
    *head
}

/// O registro está na lista (procurado pelos vínculos, sem tocar em
/// registros que não estão nela).
fn listed(head: u64, record: u64) -> bool {
    let mut current = list_entry(head).flink.get();
    let mut steps = 0;
    while current != head && current != 0 && steps < 4096 {
        if current == record {
            return true;
        }
        current = list_entry(current).flink.get();
        steps += 1;
    }
    false
}

/// KiBugCheckData: o export de dados da `.kdata`, ULONG_PTR[5] (o EAT e a
/// IAT dos drivers recebem o mesmo endereço).
pub fn bug_check_data() -> u64 {
    kernel_data::required_address("KiBugCheckData")
}

/// O papel do KiBugCheckActive: um bugcheck está em andamento.
pub fn is_active() -> bool {
    ACTIVE.load(Ordering::Acquire) & 3 == 3
}

/// KeBugCheckEx(BugCheckCode, P1, P2, P3, P4): nunca volta.
pub fn bug_check_ex(code: u32, first: u64, second: u64, third: u64, fourth: u64) -> ! {
    let parameters = [first, second, third, fourth];
    // Chamado de dentro de um comando do depurador do kernel (com a máquina
    // parada): o comando é abandonado e a sessão segue, sem bugcheck.
    crate::ntos::kd::stop::bug_check_in_debugger(code, parameters);
    if !READY.load(Ordering::Acquire) {
        crate::ntos::kd::stop::bug_check(code, parameters);
        debug_print!("*** STOP: {:#010x} ({:#018x}, {:#018x}, {:#018x}, {:#018x})", code, first, second, third, fourth);
        bugcheck_trace::report();
        cpu::halt_forever()
    }
    bug_check2(code, parameters)
}

/// O nome histórico usado pelo kernel: o mesmo KeBugCheckEx.
pub fn raise_bug_check(code: u32, first: u64, second: u64, third: u64, fourth: u64) -> ! {
    bug_check_ex(code, first, second, third, fourth)
}

/// KeBugCheck2.
fn bug_check2(code: u32, parameters: [u64; 4]) -> ! {
    let processor = crate::ntos::kd::stop::current_processor() as u32;
    let mine = (processor << 4) | 3;
    if let Err(current) = ACTIVE.compare_exchange(0, mine, Ordering::AcqRel, Ordering::Acquire) {
        if current >> 4 != processor {
            // Outro processador já está no bugcheck: este fica girando até a
            // NMI de congelamento prendê-lo (KiCheckForFreezeExecution).
            loop {
                core::hint::spin_loop();
            }
        }
        let previous = ACTIVE.fetch_add(4, Ordering::AcqRel);
        debug_print!("*** STOP (KeBugCheckEx aninhado): {:#010x} ({:#x}, {:#x}, {:#x}, {:#x})", code, parameters[0], parameters[1], parameters[2], parameters[3]);
        if previous & 0xC != 0 {
            cpu::halt_forever();
        }
        finish(code, parameters)
    }
    // SAFETY: célula própria de KiBugCheckData.
    let data = unsafe { Field::<u64>::array_at(bug_check_data(), BUG_CHECK_DATA_COUNT) };
    for (cell, value) in data.iter().zip([code as u64, parameters[0], parameters[1], parameters[2], parameters[3]]) {
        cell.set(value);
    }
    debug_print!("");
    debug_print!("*** STOP (KeBugCheckEx): {:#010x} ({:#x}, {:#x}, {:#x}, {:#x})", code, parameters[0], parameters[1], parameters[2], parameters[3]);
    // Diagnóstico do OpenNT, só serial: a pilha de quem parou.
    bugcheck_trace::report();
    // O depurador do kernel para a máquina antes da tela (o KeBugCheck2 pula
    // essa parada no despejo manual).
    if code != MANUALLY_INITIATED_CRASH {
        crate::ntos::kd::stop::bug_check(code, parameters);
    }
    // Interrupções desligadas, HIGH_LEVEL e os outros processadores presos.
    cpu::save_and_disable_interrupts();
    irql::raise_irql(irql::HIGH_LEVEL);
    let frozen = crate::ntos::kd::stop::freeze_for_bug_check();
    if frozen != 0 {
        debug_print!("[bugcheck] {} processadores congelados", frozen);
    }
    let auto_reboot = AUTO_REBOOT.load(Ordering::Acquire);
    let dump = DUMP_ENABLED.load(Ordering::Acquire);
    display_blue_screen(code, &parameters, (if dump { 0 } else { FLAG_NO_DUMP }) | if auto_reboot { 0 } else { FLAG_NO_AUTO_REBOOT });
    // KiInvokeBugCheckEntryCallbacks(KbCallbackReserved1, NULL, 0).
    let entry_callbacks = bugcheck_reason::invoke_entry_callbacks();
    if dump {
        // O despejo: os dados secundários e o black box pela serial.
        bugcheck_screen::update_progress(10);
        if let Err(error) = bugcheck_reason::publish_secondary_data(0) {
            debug_print!("[bugcheck] dados secundarios: {}", error);
        }
        bugcheck_screen::update_progress(60);
        black_box::publish_crash_records();
        bugcheck_screen::update_progress(100);
        debug_print!("[bugcheck] coleta de dados do erro: 100%");
    }
    let legacy_callbacks = scan_callback_list();
    debug_print!("[bugcheck] callbacks: {} de entrada, {} de KeRegisterBugCheckCallback", entry_callbacks, legacy_callbacks);
    if auto_reboot {
        debug_print!("[bugcheck] reiniciando (AutoReboot)");
        crate::ntos::kd::stop::thaw_after_bug_check();
        firmware_return::return_to_firmware(firmware_return::Routine::Reboot)
    }
    finish(code, parameters)
}

/// KiBugCheckDebugBreak(DBG_STATUS_BUGCHECK_SECOND) e a parada final.
fn finish(code: u32, parameters: [u64; 4]) -> ! {
    debug_print!("[bugcheck] maquina parada (AutoReboot=0)");
    crate::ntos::kd::stop::bug_check(code, parameters);
    cpu::halt_forever()
}

/// KiDumpParameterImages: o primeiro parâmetro que cai numa imagem
/// carregada fora do kernel (sem esperar a trava da lista).
pub fn parameter_driver(parameters: &[u64; 4], name: &mut [u8; 64]) -> usize {
    let mut length = 0;
    for &parameter in parameters {
        // Só endereços de sistema podem cair numa imagem de driver.
        if parameter < 0xFFFF_8000_0000_0000 {
            continue;
        }
        loaded_images::try_for_each(|image| {
            let inside = parameter >= image.image_base && parameter < image.image_base + image.size_of_image;
            let kernel = image.image_base == memory_map::KERNEL_VIRTUAL_BASE;
            let base_name = image.name.rsplit(['\\', '/']).next().unwrap_or(&image.name);
            if length == 0 && inside && !kernel && !base_name.eq_ignore_ascii_case("VerifierExt.sys") {
                for (slot, &byte) in name.iter_mut().zip(base_name.as_bytes()) {
                    *slot = byte;
                    length += 1;
                }
            }
        });
        if length != 0 {
            break;
        }
    }
    length
}

/// KiDisplayBlueScreen.
fn display_blue_screen(code: u32, parameters: &[u64; 4], flags: u32) {
    let mut driver = [0u8; 64];
    let driver_length = parameter_driver(parameters, &mut driver);
    let driver = core::str::from_utf8(&driver[..driver_length]).ok().filter(|name| !name.is_empty());
    let name = match bug_message_text(code) {
        Some(text) => Text::from_chars(text.iter().map(|&byte| byte as char).take_while(|&character| !matches!(character, '\r' | '\n'))),
        None => {
            let mut text = Text::new();
            text.extend("0x".chars());
            for shift in (0..8).rev() {
                text.push(char::from_digit((code >> (shift * 4)) & 0xF, 16).unwrap_or('0'));
            }
            text
        }
    };
    let mut ansi = [0u8; 128];
    let ansi_length = name.as_slice().iter().zip(ansi.iter_mut()).map(|(&character, slot)| *slot = character as u8).count();
    debug_print!("[bugcheck] codigo de parada: {}", core::str::from_utf8(&ansi[..ansi_length]).unwrap_or("?"));
    if let Some(driver) = driver {
        debug_print!("[bugcheck] o que falhou: {}", driver);
    }
    crate::ntos::inbv::display::acquire_display_ownership();
    match bugcheck_screen::display(name.as_slice(), driver, flags) {
        bugcheck_screen::Mode::FrameBuffer { width, height, kind } => {
            debug_print!("[bugcheck] tela de bugcheck: framebuffer {}x{} (tipo {}), fonte do BIOS {}", width, height, kind, if bugcheck_screen::font_ready() { "carregada" } else { "ausente" })
        }
        bugcheck_screen::Mode::Text => debug_print!("[bugcheck] tela de bugcheck: modo texto VGA"),
    }
}

/// KeGetBugMessageText: o texto ANSI da mensagem do código (até o NUL)
/// no KiBugCodeMessages.
pub fn bug_message_text(code: u32) -> Option<&'static [u8]> {
    let data = BUG_CODE_MESSAGES.load(Ordering::Acquire);
    let size = BUG_CODE_MESSAGES_SIZE.load(Ordering::Acquire);
    if data == 0 {
        return None;
    }
    // SAFETY: a tabela da seção de recursos da imagem do kernel, residente.
    let table = unsafe { core::slice::from_raw_parts(data as *const u8, size as usize) };
    let read32 = |offset: usize| table.get(offset..offset + 4).map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
    let read16 = |offset: usize| table.get(offset..offset + 2).map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]));
    for block in 0..read32(0)? as usize {
        let at = 4 + block * 12;
        let (low, high, offset) = (read32(at)?, read32(at + 4)?, read32(at + 8)? as usize);
        if code < low || code > high {
            continue;
        }
        let mut entry = offset;
        for _ in low..code {
            entry += read16(entry)? as usize;
        }
        let text = table.get(entry + 4..entry + read16(entry)? as usize)?;
        return Some(&text[..text.iter().position(|&byte| byte == 0).unwrap_or(text.len())]);
    }
    None
}

/// O KiBugCodeMessages do InitBootProcessor (LdrFindResource_U +
/// LdrAccessResource de [RT_MESSAGETABLE, 1] na imagem do kernel): o
/// diretório de recursos do PE do kernel, mapeado inteiro na ImageBase.
fn locate_bug_code_messages() -> Option<(u64, u64)> {
    let base = memory_map::KERNEL_VIRTUAL_BASE;
    let optional = base + guest::read32(base + 0x3C) as u64 + 24;
    let (rva, size) = (guest::read32(optional + 128) as u64, guest::read32(optional + 132) as u64);
    if rva == 0 || size == 0 {
        return None;
    }
    let root = base + rva;
    let child = |directory: u64, identifier: Option<u32>| -> Option<u32> {
        let count = guest::read16(directory + 12) as u64 + guest::read16(directory + 14) as u64;
        (0..count).find_map(|index| {
            let entry = directory + 16 + index * 8;
            identifier.is_none_or(|wanted| guest::read32(entry) == wanted).then(|| guest::read32(entry + 4))
        })
    };
    let names = root + (child(root, Some(11))? & 0x7FFF_FFFF) as u64;
    let languages = root + (child(names, Some(1))? & 0x7FFF_FFFF) as u64;
    let data = root + child(languages, None)? as u64;
    Some((base + guest::read32(data) as u64, guest::read32(data + 4) as u64))
}

/// O IopReadDumpRegistry do boot: AutoReboot e CrashDumpEnabled de
/// `Control\CrashControl`.
pub fn read_crash_control() {
    let dword = |name: &str| {
        crate::ntos::cm::registry::read_value_by_path(CRASH_CONTROL, name)
            .filter(|value| value.value_type == 4 && value.data.len() >= 4)
            .map(|value| u32::from_le_bytes([value.data[0], value.data[1], value.data[2], value.data[3]]))
    };
    let (auto_reboot, dump) = (dword("AutoReboot").unwrap_or(0), dword("CrashDumpEnabled").unwrap_or(0));
    AUTO_REBOOT.store(auto_reboot != 0, Ordering::Release);
    DUMP_ENABLED.store(dump != 0, Ordering::Release);
    debug_print!("[bugcheck] CrashControl: AutoReboot={} CrashDumpEnabled={}", auto_reboot, dump);
}

/// O nome do módulo que contém o endereço (sem esperar a trava).
fn module_name(address: u64, name: &mut [u8; 64]) -> usize {
    let mut length = 0;
    loaded_images::try_for_each(|image| {
        if length == 0 && address >= image.image_base && address < image.image_base + image.size_of_image {
            let base_name = image.name.rsplit(['\\', '/']).next().unwrap_or(&image.name);
            for (slot, &byte) in name.iter_mut().zip(base_name.as_bytes()) {
                *slot = byte;
                length += 1;
            }
        }
    });
    length
}

/// A linha de serial de um callback invocado: o motivo (0 = KeRegister-
/// BugCheckCallback), o módulo da rotina e o texto do componente.
pub fn announce_callback(reason: u32, routine: u64, component: u64) {
    let mut module = [0u8; 64];
    let length = module_name(routine, &mut module);
    let mut text = [0u8; 48];
    let mut text_length = 0;
    if component != 0 {
        if let Ok(bytes) = guest::try_read_bytes(component, text.len()) {
            for (slot, &byte) in text.iter_mut().zip(bytes.iter().take_while(|&&byte| byte != 0)) {
                *slot = if byte.is_ascii_graphic() || byte == b' ' { byte } else { b'?' };
                text_length += 1;
            }
        }
    }
    debug_print!(
        "[bugcheck] callback (motivo {}) de {}: rotina {:#x}, componente \"{}\"",
        reason,
        core::str::from_utf8(&module[..length]).unwrap_or("?"),
        routine,
        core::str::from_utf8(&text[..text_length]).unwrap_or("?")
    );
}

/// KiScanBugCheckCallbackList: cada registro conferido (vínculo de volta,
/// checksum, estado inserido) roda com (Buffer, Length); devolve quantos
/// rodaram.
fn scan_callback_list() -> usize {
    let head = *CALLBACK_LIST_HEAD.lock();
    if head == 0 {
        return 0;
    }
    let mut previous = head;
    let mut current = list_entry(head).flink.get();
    let mut invoked = 0;
    let mut steps = 0;
    while current != head && current != 0 && current & 7 == 0 && steps < 4096 {
        steps += 1;
        if guest::try_read_bytes(current, KbugcheckCallbackRecord::SIZE as usize).is_err() || list_entry(current).blink.get() != previous {
            break;
        }
        let entry = callback_record(current);
        let routine = entry.callback_routine.get();
        let checksum = routine.wrapping_add(entry.buffer.get()).wrapping_add(entry.length.get() as u64).wrapping_add(entry.component.get());
        if entry.state.get() == BUFFER_INSERTED && entry.checksum.get() == checksum {
            entry.state.set(BUFFER_STARTED);
            announce_callback(0, routine, entry.component.get());
            native_call::call(routine, &[entry.buffer.get(), entry.length.get() as u64]);
            entry.state.set(BUFFER_FINISHED);
            invoked += 1;
        }
        previous = current;
        current = list_entry(current).flink.get();
    }
    invoked
}

/// KeRegisterBugCheckCallback(CallbackRecord, CallbackRoutine, Buffer,
/// Length, Component): FALSE se o registro já está inserido (estado ou
/// presença na lista); senão preenche o registro, soma o checksum
/// (rotina + buffer + tamanho + componente), marca BufferInserted e o
/// insere pela cabeça (a varredura do bugcheck roda o mais novo primeiro).
pub fn register_callback(record: u64, routine: u64, buffer: u64, length: u32, component: u64) -> bool {
    let head = callback_list_head();
    if head == 0 {
        return false;
    }
    let previous = irql::raise_irql(irql::HIGH_LEVEL);
    let _guard = CALLBACK_LIST_HEAD.lock();
    let entry = callback_record(record);
    let inserted = if entry.state.get() != BUFFER_EMPTY || listed(head, record) {
        false
    } else {
        entry.callback_routine.set(routine);
        entry.buffer.set(buffer);
        entry.length.set(length);
        entry.component.set(component);
        entry.checksum.set(routine.wrapping_add(buffer).wrapping_add(length as u64).wrapping_add(component));
        entry.state.set(BUFFER_INSERTED);
        let first = list_entry(head).flink.get();
        entry.entry.flink.set(first);
        entry.entry.blink.set(head);
        list_entry(first).blink.set(record);
        list_entry(head).flink.set(record);
        true
    };
    drop(_guard);
    irql::lower_irql(previous as u64);
    inserted
}

/// KeDeregisterBugCheckCallback: FALSE quando o registro não está inserido
/// (procurado na lista antes de tocar nele); senão sai da lista e volta a
/// BufferEmpty.
pub fn deregister_callback(record: u64) -> bool {
    let head = callback_list_head();
    if head == 0 {
        return false;
    }
    let previous = irql::raise_irql(irql::HIGH_LEVEL);
    let guard = CALLBACK_LIST_HEAD.lock();
    let removed = listed(head, record) && callback_record(record).state.get() == BUFFER_INSERTED;
    if removed {
        let entry = callback_record(record);
        let (next, back) = (entry.entry.flink.get(), entry.entry.blink.get());
        list_entry(back).flink.set(next);
        list_entry(next).blink.set(back);
        entry.state.set(BUFFER_EMPTY);
    }
    drop(guard);
    irql::lower_irql(previous as u64);
    removed
}

/// Confere a célula de KiBugCheckData, acha o KiBugCodeMessages e liga o
/// bugcheck completo.
pub fn init() {
    bug_check_data();
    callback_list_head();
    match locate_bug_code_messages() {
        Some((data, size)) => {
            BUG_CODE_MESSAGES_SIZE.store(size, Ordering::Release);
            BUG_CODE_MESSAGES.store(data, Ordering::Release);
        }
        None => debug_print!("[bugcheck] imagem do kernel sem tabela de mensagens"),
    }
    READY.store(true, Ordering::Release);
}
