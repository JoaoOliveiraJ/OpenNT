//! Exports ETW para drivers.
//!
//! Só adaptadores. Registros, habilitações e traits pertencem ao proprietário
//! ETW (`ntos::etw::provider_state`); só eventos aceitos por sessões ativas
//! chegam aos consumidores. A atividade corrente (EtwActivityIdControl) mora
//! em `ntos::etw::activity`.

use crate::ntos::init::exports::{signed_status, Call, Group};
use crate::ntos::etw::{activity, provider_state};
use crate::rtl::KernelError;

/// O REGHANDLE é o endereço de um registro próprio (GUID e silo).
fn register(call: &Call) -> Result<u64, KernelError> {
    Ok(provider_state::register(call.arg(1), call.arg(2), call.arg(3), call.arg(4), false)? as u64)
}

fn unregister(call: &Call) -> Result<u64, KernelError> {
    Ok(provider_state::unregister_with_traits(call.arg(1))? as u64)
}

fn write(call: &Call) -> Result<u64, KernelError> {
    Ok(provider_state::write(call.arg(1), call.arg(2), activity::resolve(call.arg(3)), 0, call.arg(4) as u32, call.arg(5))? as u64)
}

fn write_transfer(call: &Call) -> Result<u64, KernelError> {
    Ok(provider_state::write(call.arg(1), call.arg(2), activity::resolve(call.arg(3)), call.arg(4), call.arg(5) as u32, call.arg(6))? as u64)
}

fn set_information(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(provider_state::set_information(call.arg(1), call.arg(2) as u32, call.arg(3))))
}

/// A entrada clássica também associa um novo handle aos bytes do GUID.
fn register_classic_provider(call: &Call) -> Result<u64, KernelError> {
    Ok(provider_state::register(call.arg(1), call.arg(3), call.arg(4), call.arg(5), true)? as u64)
}

fn activity_id_control(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(activity::control(call.arg(1) as u32, call.arg(2))))
}

pub static GROUP: Group = Group {
    name: "etw",
    names: &["EtwRegister", "EtwUnregister", "EtwWrite", "EtwWriteTransfer", "EtwSetInformation", "EtwRegisterClassicProvider", "EtwActivityIdControl"],
    handlers: &[register, unregister, write, write_transfer, set_information, register_classic_provider, activity_id_control],
    data_exports: &[],
};

pub mod event_enabled {
    //! EtwEventEnabled.

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

pub mod wmi {
    //! WmiTraceMessage, WmiTraceMessageVa e WmiQueryTraceInformation.
    //!
    //! Adaptadores de `ntos::etw::wmi`; as limitações estão descritas em cada
    //! operação de lá.

    use crate::ntos::etw::wmi;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    fn trace_message(call: &Call) -> Result<u64, KernelError> {
        wmi::trace_message(call.arg(5), [call.arg(6), call.arg(7), call.arg(8), call.arg(9)])?;
        Ok(0)
    }

    /// Sem sessão de trace ativa o logger não existe: STATUS_INVALID_HANDLE.
    fn trace_message_va(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(0xC000_0008))
    }

    fn query_trace_information(call: &Call) -> Result<u64, KernelError> {
        wmi::query_trace_information(call.arg(2), call.arg(3) as u32, call.arg(4));
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "wmi",
        names: &["WmiTraceMessage", "WmiTraceMessageVa", "WmiQueryTraceInformation"],
        handlers: &[trace_message, trace_message_va, query_trace_information],
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
