//! Autoteste do depurador do kernel visto pelos drivers, no boot com
//! `--kd` (o teste `kd`): KdDebuggerEnabled, KdDebuggerNotPresent e o
//! KUSER_SHARED_DATA.KdDebuggerEnabled com o depurador ligado, e
//! KdChangeOption, KdDisableDebugger, KdEnableDebugger,
//! KdRefreshDebuggerNotPresent e KdPowerTransitionEx chamados pelo nome,
//! como um driver chamaria. Também o filtro das exceções do anel 3 por
//! código e o ponto de recuperação da sessão do depurador.
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

/// O filtro das exceções do anel 3 por código (`kd::exception_filter`):
/// a regra do KdpReport do 19041 (0x511924) para o FLG_STOP_ON_EXCEPTION e
/// as escolhas por código. Os códigos do teste são de cliente (0xE0D0...)
/// e saem da tabela no fim: o que o host pôs nela fica.
fn filter_checks() -> Result<(), &'static str> {
    use crate::ntos::kd::exception_filter::{self as filter, Choice};
    let reported = [0xC000_0005, 0x8000_0003, 0x4000_001E, 0xE06D_7363, 0xC000_0409].into_iter().all(filter::reportable_first_chance);
    let excluded = [0x4001_0006, 0x406D_1388, 0xC000_0037, 0x4000_001D, 0x4000_0015].into_iter().all(|code| !filter::reportable_first_chance(code));
    if !reported || !excluded {
        return Err("KdpReport: a primeira chance relatada com FLG_STOP_ON_EXCEPTION (sem os informativos, o PORT_DISCONNECTED e os positivos acima de 0x4000001F)");
    }
    const BOTH: u32 = 0xE0D0_0001;
    const SECOND: u32 = 0xE0D0_0002;
    const NEVER: u32 = 0xE0D0_0003;
    if filter::first_chance(BOTH, false) || !filter::first_chance(BOTH, true) || filter::second_chance(BOTH) {
        return Err("filtro sem entrada: a primeira chance segue o uex e a segunda nao para");
    }
    if !filter::set(BOTH, Choice::Break, Choice::Break) || !filter::set(SECOND, Choice::Default, Choice::Break) || !filter::set(NEVER, Choice::Ignore, Choice::Ignore) {
        return Err("filtro: tabela sem entradas livres");
    }
    let decisions = filter::first_chance(BOTH, false)
        && filter::second_chance(BOTH)
        && !filter::first_chance(SECOND, false)
        && filter::first_chance(SECOND, true)
        && filter::second_chance(SECOND)
        && !filter::first_chance(NEVER, true)
        && !filter::second_chance(NEVER);
    let removed = filter::remove(BOTH) && filter::remove(SECOND) && filter::remove(NEVER) && filter::choices(BOTH) == (Choice::Default, Choice::Default) && !filter::remove(NEVER);
    if !decisions || !removed {
        return Err("filtro: e (as duas chances), d (so a segunda), i (nunca) e a entrada tirada");
    }
    Ok(())
}

extern "sysv64" fn recovery_plain(cell: u64) {
    // SAFETY: a célula u64 do teste, viva na pilha de quem armou.
    unsafe { core::ptr::write_volatile(cell as *mut u64, 0x4B44) };
}

extern "sysv64" fn recovery_bug_check(_argument: u64) {
    crate::ntos::ke::bugcheck::bug_check_ex(0xE2, 0x4B44_5445_5354, 0, 0, 0);
}

/// O ponto de recuperação da sessão (`kd::recovery`): a rotina que volta e
/// o KeBugCheckEx dentro dela, que volta ao ponto sem bugcheck. A falta sem
/// tratador é testada no roteiro do teste `kd` (`kdtest falta`), com a
/// máquina parada.
fn recovery_checks() -> Result<(), &'static str> {
    use crate::ntos::kd::recovery::{self, Event};
    let number = stop::current_processor();
    let mut cell = 0u64;
    if !recovery::run(number, recovery_plain, &mut cell as *mut u64 as u64) || cell != 0x4B44 || recovery::armed_here(number) {
        return Err("ponto de recuperacao: a rotina que volta");
    }
    // Sem as entradas do depurador o KeBugCheckEx seria de verdade.
    if !stop::active() {
        return Err("ponto de recuperacao: entradas do depurador desligadas");
    }
    let before = recovery::recovered();
    let returned = recovery::run(number, recovery_bug_check, 0);
    if returned || !matches!(recovery::last_event(), Some(Event::BugCheck { code: 0xE2, .. })) || recovery::recovered() != before + 1 || recovery::armed_here(number) || crate::ntos::ke::bugcheck::is_active() {
        return Err("ponto de recuperacao: o KeBugCheckEx volta ao ponto, sem bugcheck");
    }
    Ok(())
}

/// Roda os testes e imprime KD_EXPORTS_OK (ou a falha).
pub fn run() {
    let flags = cpu::save_and_disable_interrupts();
    let result = checks().and_then(|()| filter_checks()).and_then(|()| recovery_checks());
    cpu::restore_interrupts(flags);
    match result {
        Ok(()) => debug_print!("KD_EXPORTS_OK"),
        Err(message) => debug_print!("SELFTEST FALHOU: kd: {}", message),
    }
}
