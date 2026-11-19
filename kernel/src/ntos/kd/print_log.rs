//! Saída do DbgPrint para o depurador.
//!
//! Todo texto do DbgPrint/DbgPrintEx/vDbgPrintEx(WithPrefix) entra num anel
//! de 32 KB (o `monitor log` do host o lê) e, com o depurador ativo, um host
//! anexado e a máquina rodando, vai ao host como pacote `O` do protocolo,
//! como o KdpPrintString do NT manda a saída ao depurador. Sem host
//! anexado o texto fica só no anel e no log do kernel (o transporte do NT
//! descarta a impressão quando o depurador não está presente).
//!
//! O anel não tem trava: cada escritor reserva o seu trecho com um
//! incremento atômico da posição, e a leitura do depurador (com os outros
//! processadores congelados) copia os bytes mais recentes.

use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use super::{packet, session, stop, transport};

const LOG_SIZE: usize = 0x8000;
/// Maior trecho de texto por pacote `O` (dois dígitos por byte).
const CHUNK: usize = 200;

static LOG: [AtomicU8; LOG_SIZE] = [const { AtomicU8::new(0) }; LOG_SIZE];
/// Bytes já escritos desde o boot (a posição de escrita é `HEAD % LOG_SIZE`).
static HEAD: AtomicUsize = AtomicUsize::new(0);

fn record(bytes: &[u8]) {
    let start = HEAD.fetch_add(bytes.len() + 1, Ordering::AcqRel);
    for (index, &byte) in bytes.iter().chain(core::iter::once(&b'\n')).enumerate() {
        LOG[(start + index) % LOG_SIZE].store(byte, Ordering::Relaxed);
    }
}

/// Entrega os últimos `limit` bytes do anel, em ordem; devolve quantos.
pub fn recent(limit: usize, mut each: impl FnMut(u8)) -> usize {
    let head = HEAD.load(Ordering::Acquire);
    let available = head.min(LOG_SIZE).min(limit);
    let start = head - available;
    for index in 0..available {
        each(LOG[(start + index) % LOG_SIZE].load(Ordering::Relaxed));
    }
    available
}

/// Uma linha do DbgPrint (sem a quebra final).
pub fn output(text: &str) {
    record(text.as_bytes());
    if !stop::active() || !session::attached() || stop::stopped() {
        return;
    }
    let cpu = stop::current_processor();
    let flags = crate::hal::cpu::save_and_disable_interrupts();
    transport::lock(cpu);
    let mut buffer = [0u8; 2 * CHUNK + 8];
    let bytes = text.as_bytes();
    let count = bytes.len().div_ceil(CHUNK).max(1);
    for index in 0..count {
        let chunk = &bytes[(index * CHUNK).min(bytes.len())..((index + 1) * CHUNK).min(bytes.len())];
        let mut payload = packet::Payload::new(&mut buffer);
        payload.push(b'O');
        payload.push_hex(chunk);
        if index + 1 == count {
            payload.push_hex(b"\n");
        }
        packet::send_unreliable(payload.as_bytes());
    }
    transport::unlock();
    crate::hal::cpu::restore_interrupts(flags);
    // Um 0x03 consumido durante a espera de confirmação é a parada pedida, e
    // o host espera a resposta de parada (o byte já saiu da porta).
    if packet::take_interrupt() {
        session::set_host_waiting();
        stop::break_in_now();
    }
}
