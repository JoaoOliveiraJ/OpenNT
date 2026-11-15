//! Autoteste do depurador do kernel visto pelos drivers, no boot com
//! `--kd` (o teste `kd`): KdDebuggerEnabled, KdDebuggerNotPresent e o
//! KUSER_SHARED_DATA.KdDebuggerEnabled com o depurador ligado, e
//! KdChangeOption, KdDisableDebugger, KdEnableDebugger,
//! KdRefreshDebuggerNotPresent e KdPowerTransitionEx chamados pelo nome,
//! como um driver chamaria.
//!
//! Os valores esperados vêm das instruções do ntoskrnl 19041
//! (KdChangeOption 0x510c10, KdDisableDebuggerWithLock 0x3cf338 e o
//! trecho frio 0x4b5614, KdEnableDebuggerWithLock 0x510cbc,
//! KdRefreshDebuggerNotPresent 0x3cf810, KdPowerTransitionEx 0x510f00). O
//! teste roda com as interrupções desligadas: o pedido de parada do host
//! (que anexa a sessão e muda a presença) só é visto no tique seguinte.

use super::phase6::call_export;
use crate::hal::cpu;
use crate::ntos::kd::{debugger, session, stop};
use crate::ntos::mm::{guest_memory as guest, kernel_data, shared_user_data};

const STATUS_INVALID_INFO_CLASS: u64 = 0xFFFF_FFFF_C000_0003;
const STATUS_INVALID_PARAMETER: u64 = 0xFFFF_FFFF_C000_000D;
const STATUS_ACCESS_DENIED: u64 = 0xFFFF_FFFF_C000_0022;

fn shared_flags() -> u8 {
    shared_user_data::data().map_or(0xFF, |shared| shared.kd_debugger_enabled.get())
}

fn checks() -> Result<(), &'static str> {
    let enabled = || kernel_data::read("KdDebuggerEnabled");
    let not_present = || kernel_data::read("KdDebuggerNotPresent");
    let attached = session::attached();
    if enabled() != 1 || shared_flags() & 1 != 1 || !stop::active() {
        return Err("depurador ligado no boot (KdDebuggerEnabled e bit 0 do KUSER_SHARED_DATA)");
    }
    if kernel_data::read("KdComPortInUse") != crate::ntos::kd::transport::base() as u64 {
        return Err("KdComPortInUse aponta a porta do depurador");
    }
    if not_present() != !attached as u64 || (shared_flags() & 2 != 0) != attached {
        return Err("presenca do host (KdDebuggerNotPresent e bit 1 do KUSER_SHARED_DATA)");
    }
    if call_export("KdRefreshDebuggerNotPresent", &[]) != Some(!attached as u64) {
        return Err("KdRefreshDebuggerNotPresent devolve a presenca da sessao");
    }
    let block = guest::alloc_bytes(16);
    let (input, needed) = (block, block + 8);
    let result = (|| {
        guest::write32(needed, 0xFFFF_FFFF);
        if call_export("KdChangeOption", &[1, 0, 0, 0, 0, needed]) != Some(STATUS_INVALID_INFO_CLASS) || guest::read32(needed) != 0 {
            return Err("KdChangeOption: opcao desconhecida e OutBufferNeeded = 0");
        }
        guest::write32(needed, 0xFFFF_FFFF);
        if call_export("KdChangeOption", &[0, 2, input, 0, 0, needed]) != Some(STATUS_INVALID_PARAMETER) || guest::read32(needed) != 0xFFFF_FFFF {
            return Err("KdChangeOption: InBufferBytes != 1 sem tocar no OutBufferNeeded");
        }
        if call_export("KdEnableDebugger", &[]) != Some(STATUS_INVALID_PARAMETER) {
            return Err("KdEnableDebugger sem desligamento pendente");
        }
        guest::write8(input, 1);
        if call_export("KdChangeOption", &[0, 1, input, 0, 0, needed]) != Some(0) || guest::read32(needed) != 0 || call_export("KdDisableDebugger", &[]) != Some(STATUS_ACCESS_DENIED) {
            return Err("KdChangeOption liga o KdBlockEnable e o KdDisableDebugger recusa");
        }
        guest::write8(input, 0);
        if call_export("KdChangeOption", &[0, 1, input, 0, 0, 0]) != Some(0) {
            return Err("KdChangeOption desliga o KdBlockEnable");
        }
        if call_export("KdDisableDebugger", &[]) != Some(0) || enabled() != 0 || not_present() != 1 || shared_flags() != 0 || stop::active() {
            return Err("KdDisableDebugger desliga o depurador");
        }
        if call_export("KdRefreshDebuggerNotPresent", &[]) != Some(1) || call_export("KdPowerTransitionEx", &[1, 1]) != Some(0) {
            return Err("depurador desligado: nao presente e transicao sem efeito");
        }
        if call_export("KdDisableDebugger", &[]) != Some(0) || call_export("KdEnableDebugger", &[]) != Some(0) || enabled() != 0 {
            return Err("KdDisableCount: dois desligamentos pedem dois religamentos");
        }
        if call_export("KdEnableDebugger", &[]) != Some(0) || enabled() != 1 || shared_flags() != 1 || !stop::active() {
            return Err("KdEnableDebugger religa o depurador");
        }
        if call_export("KdPowerTransitionEx", &[5, 1]) != Some(STATUS_INVALID_PARAMETER) || call_export("KdPowerTransitionEx", &[1, 1]) != Some(0) || call_export("KdPowerTransitionEx", &[4, 0]) != Some(0) {
            return Err("KdPowerTransitionEx: D0 e D3 do transporte, estado invalido recusado");
        }
        Ok(())
    })();
    guest::free_bytes(block);
    // A presença volta com o próximo pacote do host, como no transporte do
    // NT; o teste a devolve já.
    debugger::set_debugger_present(attached);
    result
}

/// Roda os testes e imprime KD_EXPORTS_OK (ou a falha).
pub fn run() {
    let flags = cpu::save_and_disable_interrupts();
    let result = checks();
    cpu::restore_interrupts(flags);
    match result {
        Ok(()) => debug_print!("KD_EXPORTS_OK"),
        Err(message) => debug_print!("SELFTEST FALHOU: kd: {}", message),
    }
}
