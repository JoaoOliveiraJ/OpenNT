//! Exports ETW para drivers — `system32/win32/ntoskrnl/etw.js`.
//!
//! Registros e habilitações pertencem ao proprietário ETW
//! (`ntos::etw::provider_state`); só eventos aceitos por sessões ativas
//! chegam aos consumidores. Aqui ficam a atividade corrente
//! (EtwActivityIdControl) e os traits guardados por EtwSetInformation.

use alloc::collections::BTreeMap;

use crate::ntos::init::exports::{signed_status, Call, Group};
use crate::hal::cpu;
use crate::ntos::etw::provider_state;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

struct Activity {
    /// GUID da atividade corrente (16 bytes).
    current: u64,
    /// Estado do gerador xorshift32 (CREATE_ID).
    random: u32,
}

static ACTIVITY: SpinLock<Activity> = SpinLock::new(Activity { current: 0, random: 0 });
/// EventProviderSetTraits: tamanho dos traits por registro.
static TRAITS: SpinLock<BTreeMap<u64, u32>> = SpinLock::new(BTreeMap::new());

fn current_activity() -> u64 {
    ACTIVITY.lock().current
}

/// O REGHANDLE é o endereço de um registro próprio (GUID e silo).
fn register(call: &Call) -> Result<u64, KernelError> {
    Ok(provider_state::register(call.arg(1), call.arg(2), call.arg(3), call.arg(4), false)? as u64)
}

fn unregister(call: &Call) -> Result<u64, KernelError> {
    TRAITS.lock().remove(&call.arg(1));
    Ok(provider_state::unregister(call.arg(1))? as u64)
}

/// Sem ID explícito vale a atividade mantida pelo EtwActivityIdControl.
fn write(call: &Call) -> Result<u64, KernelError> {
    let activity = if call.arg(3) != 0 { call.arg(3) } else { current_activity() };
    Ok(provider_state::write(call.arg(1), call.arg(2), activity, 0, call.arg(4) as u32, call.arg(5))? as u64)
}

fn write_transfer(call: &Call) -> Result<u64, KernelError> {
    let activity = if call.arg(3) != 0 { call.arg(3) } else { current_activity() };
    Ok(provider_state::write(call.arg(1), call.arg(2), activity, call.arg(4), call.arg(5) as u32, call.arg(6))? as u64)
}

/// Atualiza os metadados de um registro conforme a classe.
fn set_information(call: &Call) -> Result<u64, KernelError> {
    if !provider_state::exists(call.arg(1)) {
        return Ok(signed_status(0xC000_0008));
    }
    if call.arg(2) as u32 == 1 && call.arg(3) != 0 {
        TRAITS.lock().insert(call.arg(1), guest::read32(call.arg(3)));
    }
    Ok(0)
}

/// A entrada clássica também associa um novo handle aos bytes do GUID.
fn register_classic_provider(call: &Call) -> Result<u64, KernelError> {
    Ok(provider_state::register(call.arg(1), call.arg(3), call.arg(4), call.arg(5), true)? as u64)
}

fn xorshift(state: &mut u32) {
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
}

/// EtwActivityIdControl(code, &guid): GET_ID=1, SET_ID=2, CREATE_ID=3,
/// GET_SET_ID=4, CREATE_SET_ID=5 (evntprov.h) sobre o GUID corrente.
fn activity_id_control(call: &Call) -> Result<u64, KernelError> {
    let pointer = call.arg(2);
    let mut activity = ACTIVITY.lock();
    if activity.current == 0 {
        activity.current = guest::alloc_bytes(16);
    }
    let current = activity.current;
    let copy_current = || {
        for byte in 0..16 {
            guest::write8(pointer + byte, guest::read8(current + byte));
        }
    };
    let store_current = || {
        for byte in 0..16 {
            guest::write8(current + byte, guest::read8(pointer + byte));
        }
    };
    // uuid v4 por xorshift32 semeado no TSC (o mesmo padrão do Ex).
    let generate = |state: &mut u32| {
        xorshift(state);
        if *state == 0 {
            *state = match cpu::rdtsc() as u32 {
                0 => 0x2545_F491,
                seed => seed,
            };
        }
        for word in 0..4 {
            xorshift(state);
            guest::write32(pointer + word * 4, *state);
        }
        guest::write8(pointer + 6, (guest::read8(pointer + 6) & 0x0F) | 0x40);
        guest::write8(pointer + 8, (guest::read8(pointer + 8) & 0x3F) | 0x80);
    };
    match call.arg(1) as u32 {
        1 => copy_current(),
        2 => store_current(),
        3 => generate(&mut activity.random),
        4 => {
            copy_current();
            store_current();
        }
        5 => {
            generate(&mut activity.random);
            store_current();
        }
        _ => return Ok(signed_status(0xC000_000D)),
    }
    Ok(0)
}

pub static GROUP: Group = Group {
    name: "etw",
    names: &["EtwRegister", "EtwUnregister", "EtwWrite", "EtwWriteTransfer", "EtwSetInformation", "EtwRegisterClassicProvider", "EtwActivityIdControl"],
    handlers: &[register, unregister, write, write_transfer, set_information, register_classic_provider, activity_id_control],
    data_exports: &[],
};

pub mod event_enabled {
    //! EtwEventEnabled — `system32/win32/ntoskrnl/event-enabled.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::etw::event_enabled;

    fn etw_event_enabled(call: &Call) -> Result<u64, KernelError> {
        Ok(event_enabled::query(call.arg(1), call.arg(2)) as u64)
    }

    pub static GROUP: Group = Group {
        name: "event-enabled",
        names: &["EtwEventEnabled"],
        handlers: &[etw_event_enabled],
        data_exports: &[],
    };
}

pub mod wpp {
    //! Exports da WppRecorder.sys (rastreamento WPP) — `system32/win32/ntoskrnl/wpp.js`.
    //!
    //! As sessões de trace existem de verdade (estado e buffer circular de 256
    //! eventos por sessão) e os eventos saem na serial.

    use alloc::collections::{BTreeMap, VecDeque};
    use alloc::format;
    use alloc::string::String;

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::{KernelError, SpinLock};
    use crate::ntos::mm::guest_memory as guest;

    struct Sessions {
        next: u64,
        sessions: BTreeMap<u64, VecDeque<String>>,
    }

    static SESSIONS: SpinLock<Sessions> = SpinLock::new(Sessions { next: 1, sessions: BTreeMap::new() });

    /// WppAutoLogStart(guid, &handle, callback): inicia uma sessão real.
    fn auto_log_start(call: &Call) -> Result<u64, KernelError> {
        let mut sessions = SESSIONS.lock();
        let handle = sessions.next;
        sessions.next += 1;
        sessions.sessions.insert(handle, VecDeque::new());
        drop(sessions);
        if call.arg(2) != 0 {
            guest::write64(call.arg(2), handle);
        }
        Ok(0)
    }

    /// WppAutoLogTrace(handle, level, flags, guid, msgNumber, ...): registra
    /// pelo número da mensagem (o conteúdo WPP é binário, formatado offline).
    fn auto_log_trace(call: &Call) -> Result<u64, KernelError> {
        let line = format!("[wpp] evento msg#{}", call.arg(5) as u32);
        if let Some(events) = SESSIONS.lock().sessions.get_mut(&(call.arg(1) as u32 as u64)) {
            events.push_back(line.clone());
            if events.len() > 256 {
                events.pop_front();
            }
        }
        debug_print!("{}", line);
        Ok(0)
    }

    /// WppAutoLogStop(handle, guid): encerra a sessão.
    fn auto_log_stop(call: &Call) -> Result<u64, KernelError> {
        SESSIONS.lock().sessions.remove(&(call.arg(1) as u32 as u64));
        Ok(0)
    }

    /// imp_WppRecorderReplay(handle, ...): repete o buffer circular.
    fn recorder_replay(call: &Call) -> Result<u64, KernelError> {
        let sessions = SESSIONS.lock();
        let Some(events) = sessions.sessions.get(&(call.arg(1) as u32 as u64)) else { return Ok(signed_status(0xC000_0008)) };
        for line in events {
            debug_print!("[replay] {}", line);
        }
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "wpp",
        names: &["WppAutoLogStart", "WppAutoLogTrace", "WppAutoLogStop", "imp_WppRecorderReplay"],
        handlers: &[auto_log_start, auto_log_trace, auto_log_stop, recorder_replay],
        data_exports: &[],
    };
}

pub mod wmi {
    //! Exports da WMILIB.SYS — `system32/win32/ntoskrnl/wmi.js`.
    //!
    //! Despacho, conclusão de IRPs e saída de rastreamento; as limitações estão
    //! descritas em cada operação.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::io_manager;
    use crate::rtl::KernelError;
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::rtl::guest_strings;
    use crate::ntos::inc::nt_abi::irp;

    /// Escreve disposição zero e retorna zero; ainda não consulta os GUIDs nem
    /// despacha os callbacks do bloco de controle.
    fn system_control(call: &Call) -> Result<u64, KernelError> {
        guest::write32(call.arg(4), 0);
        Ok(0)
    }

    /// Grava status e bytes no IRP e conclui; dispositivo e incremento de
    /// prioridade não são usados.
    fn complete_request(call: &Call) -> Result<u64, KernelError> {
        let packet = call.arg(2);
        guest::write32(packet + irp::IO_STATUS, call.arg(3) as u32);
        guest::write64(packet + irp::IO_STATUS_INFORMATION, call.arg(4) as u32 as u64);
        io_manager::iof_complete_request(packet);
        Ok(0)
    }

    /// WmiTraceMessage(handle, level, guid, msgId, fmt, ...): texto formatado
    /// para a serial.
    fn trace_message(call: &Call) -> Result<u64, KernelError> {
        let arguments = [call.arg(6), call.arg(7), call.arg(8), call.arg(9)];
        let format_text = guest_strings::read_c_string(call.arg(5));
        let text = guest_strings::format_guest_text(&format_text, &mut |index| arguments.get(index).copied().unwrap_or(0), false)?;
        let text = text.strip_suffix('\n').map(|rest| rest.strip_suffix('\r').unwrap_or(rest)).unwrap_or(&text);
        debug_print!("[wmitrace] {}", text);
        Ok(0)
    }

    /// Sem sessão de trace ativa o logger não existe: STATUS_INVALID_HANDLE.
    fn trace_message_va(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(0xC000_0008))
    }

    /// Zera até 0x30 bytes em palavras de quatro bytes, sem distinguir classes.
    fn query_trace_information(call: &Call) -> Result<u64, KernelError> {
        let reported = (call.arg(3) as u32).min(0x30);
        let mut offset = 0;
        while offset < reported {
            guest::write32(call.arg(2) + offset as u64, 0);
            offset += 4;
        }
        if call.arg(4) != 0 {
            guest::write32(call.arg(4), reported);
        }
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "wmi",
        names: &["WmiSystemControl", "WmiCompleteRequest", "WmiTraceMessage", "WmiTraceMessageVa", "WmiQueryTraceInformation"],
        handlers: &[system_control, complete_request, trace_message, trace_message_va, query_trace_information],
        data_exports: &[],
    };
}

pub mod trace_control {
    //! NtTraceControl (modo anterior da thread) e ZwTraceControl (KernelMode):
    //! o controle das sessões de log em `ntos::etw::logger`.

    use crate::ntos::etw::logger;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::ps::previous_mode;
    use crate::rtl::KernelError;

    fn control(call: &Call, mode: u8) -> Result<u64, KernelError> {
        Ok(signed_status(logger::trace_control(call.arg(1) as u32, call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5) as u32, call.arg(6), mode)?))
    }

    fn nt_trace_control(call: &Call) -> Result<u64, KernelError> {
        control(call, previous_mode::get()?)
    }

    fn zw_trace_control(call: &Call) -> Result<u64, KernelError> {
        control(call, 0)
    }

    pub static GROUP: Group = Group { name: "trace-control", names: &["NtTraceControl", "ZwTraceControl"], handlers: &[nt_trace_control, zw_trace_control], data_exports: &[] };

    /// EtwEnableTrace(ProviderId, SourceId, LoggerId, ControlCode, Level,
    /// MatchAnyKeyword, MatchAllKeyword, EnableProperty).
    fn enable_trace(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(logger::enable_trace(call.arg(1), call.arg(2), call.arg(3) as u16, call.arg(4) as u32, call.arg(5) as u8, call.arg(6), call.arg(7), call.arg(8) as u32)?))
    }

    pub static ENABLE_TRACE_GROUP: Group = Group { name: "enable-trace", names: &["EtwEnableTrace"], handlers: &[enable_trace], data_exports: &[] };
}
