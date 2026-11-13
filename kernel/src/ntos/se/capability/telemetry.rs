//! Telemetria de RtlCapabilityCheck.
//!
//! O provedor ETW só entrega o evento quando uma sessão real o habilitou; o
//! relógio é o QPC/TSC do boot. Um evento a cada 100 consultas.

use crate::ntos::etw::{event_enabled, provider_state as providers};
use crate::ntos::ke::clock;
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::rtl::SpinLock;
use crate::ntos::mm::guest_memory as guest;

/// Metadados TraceLogging do contrato original: GUID, nome do provedor e a
/// descrição dos cinco campos, com os comprimentos do helper nativo medido.
pub const PROVIDER_IDENTIFIER: &str = "f4fda827779b5b57be3be7163ef159bb";
const PROVIDER_METADATA: &str = "3d004d6963726f736f66742e57696e646f77732e53656375726974792e4361706162696c6974696573001300011a73504fcf898247b3e0dce8c90476ba";
const EVENT_METADATA: &str = "6900800052746c4361706162696c697479436865636b4c6174656e6379004c6174656e63790009497341646d696e0084034973496e74657261637469766555736572008403497341646d696e4361706162696c6974790084034861734361706162696c697479008403";
const TELEMETRY_TAG: u32 = 0x744C_7043;

struct State {
    initialized: bool,
    registration: u64,
    metadata: u64,
    frequency: u64,
    remaining: u16,
}

static STATE: SpinLock<State> = SpinLock::new(State { initialized: false, registration: 0, metadata: 0, frequency: 0, remaining: 1 });

fn write_hex(pointer: u64, text: &str) {
    let bytes = text.as_bytes();
    for index in (0..bytes.len()).step_by(2) {
        let value = u8::from_str_radix(core::str::from_utf8(&bytes[index..index + 2]).unwrap_or("00"), 16).unwrap_or(0);
        guest::write8(pointer + index as u64 / 2, value);
    }
}

/// RunOnce: o inicializador original conclui mesmo se o registro ETW falhar.
fn initialize() {
    if STATE.lock().initialized {
        return;
    }
    STATE.lock().initialized = true;
    let mut registration = 0;
    let mut metadata = kernel_pool::allocate(512, AllocateOptions { tag: TELEMETRY_TAG, zero: true, ..Default::default() }).unwrap_or(0);
    if metadata != 0 {
        write_hex(metadata, PROVIDER_IDENTIFIER);
        write_hex(metadata + 32, PROVIDER_METADATA);
        write_hex(metadata + 96, EVENT_METADATA);
        guest::write8(metadata + 19, 11); // Channel do EVENT_DESCRIPTOR
        guest::write8(metadata + 20, 5); // TRACE_LEVEL_VERBOSE
        guest::write64(metadata + 24, 0x2000_0000_0000);
        match providers::register(metadata, 0, 0, metadata + 240, false) {
            Ok(0) => registration = guest::read64(metadata + 240),
            _ => {
                let _ = kernel_pool::free(metadata, None);
                metadata = 0;
            }
        }
    }
    let mut state = STATE.lock();
    state.registration = registration;
    state.metadata = metadata;
    state.frequency = clock::tsc_frequency_hz();
}

/// Registra a latência de uma consulta (contadores TSC de início e fim).
pub fn record(start: u64, end: u64, administrator: u8, interactive: u8, admin_capability: u8, result: u8) {
    initialize();
    let (registration, metadata, frequency) = {
        let mut state = STATE.lock();
        if start == 0 || end == 0 || state.frequency == 0 {
            return;
        }
        state.remaining = state.remaining.wrapping_sub(1);
        if state.remaining != 0 {
            return;
        }
        (state.registration, state.metadata, state.frequency)
    };
    if registration != 0 && event_enabled::query(registration, metadata + 16) != 0 {
        // SUB/IMUL em 64 bits com wrap; IDIV conserva o sinal e trunca.
        let microseconds = (end.wrapping_sub(start).wrapping_mul(1_000_000) as i64) / frequency as i64;
        // Sem armazenamento para o evento, o NTSTATUS da consulta não muda.
        if let Ok(frame) = kernel_pool::allocate(128, AllocateOptions { tag: TELEMETRY_TAG, zero: true, ..Default::default() }) {
            guest::write64(frame + 112, microseconds as u64);
            for (index, value) in [administrator, interactive, admin_capability, result].into_iter().enumerate() {
                guest::write8(frame + 120 + index as u64, value);
            }
            let segments: [(u64, u32, u32); 7] = [
                (metadata + 32, PROVIDER_METADATA.len() as u32 / 2, 2),
                (metadata + 96, EVENT_METADATA.len() as u32 / 2, 1),
                (frame + 112, 8, 0),
                (frame + 120, 1, 0),
                (frame + 121, 1, 0),
                (frame + 122, 1, 0),
                (frame + 123, 1, 0),
            ];
            for (index, (pointer, size, kind)) in segments.iter().enumerate() {
                let descriptor = frame + index as u64 * 16;
                guest::write64(descriptor, *pointer);
                guest::write32(descriptor + 8, *size);
                guest::write32(descriptor + 12, *kind);
            }
            let _ = providers::write(registration, metadata + 16, 0, 0, segments.len() as u32, frame);
            let _ = kernel_pool::free(frame, None);
        }
    }
    STATE.lock().remaining = 100;
}
