//! Roteiros sem janela sobre o backend, usados pelo teste de fumaça e pelas
//! capturas de tela: esperar um estado, parar num símbolo, parar dentro de
//! um driver da Microsoft (no retorno de uma chamada ao kernel) e provocar
//! um bugcheck pelo despejo manual do teclado.

use std::time::{Duration, Instant};

use opennt_kd::BreakpointKind;

use crate::backend::{Backend, Request, Shared, Status};

/// Espera o estado satisfazer `predicate` (desconectar é erro).
pub fn wait(backend: &Backend, what: &str, timeout: Duration, log: &dyn Fn(&str), predicate: impl Fn(&Shared) -> bool) -> Result<(), String> {
    log(&format!("esperando: {what}"));
    let ok = backend.wait_for(timeout, |shared| predicate(shared) || matches!(shared.status, Status::Disconnected(_)));
    let shared = backend.shared();
    if let Status::Disconnected(reason) = &shared.status {
        return Err(format!("{what}: desconectado: {reason}\n--- xtask ---\n{}", shared.launch_log));
    }
    if !ok {
        let transcript: Vec<String> = shared.transcript.iter().rev().take(6).map(|entry| format!("kd> {}\n{}", entry.input, entry.output)).collect();
        return Err(format!("{what}: tempo esgotado (estado {:?})\n{}", shared.status, transcript.join("\n")));
    }
    Ok(())
}

/// Espera uma parada nova (snapshot mais novo que `before`).
pub fn wait_stop(backend: &Backend, what: &str, before: u64, timeout: Duration, log: &dyn Fn(&str)) -> Result<(), String> {
    wait(backend, what, timeout, log, |shared| shared.status == Status::Stopped && shared.snapshot.generation > before && shared.activity.is_empty())
}

fn generation(backend: &Backend) -> u64 {
    backend.shared().snapshot.generation
}

/// Breakpoint num símbolo e continuar até ele.
pub fn stop_at(backend: &Backend, expression: &str, log: &dyn Fn(&str)) -> Result<(), String> {
    let before = generation(backend);
    backend.send(Request::AddBreakpoint(BreakpointKind::Software, expression.into()));
    wait(backend, "o breakpoint armado", Duration::from_secs(60), log, |shared| shared.snapshot.generation > before)?;
    let before = generation(backend);
    backend.send(Request::Go);
    wait(backend, &format!("a parada em {expression}"), Duration::from_secs(900), log, |shared| shared.status == Status::Stopped && shared.snapshot.generation > before && shared.snapshot.stop.contains("swbreak") && shared.activity.is_empty())
}

/// O nome do módulo de um endereço, fora o kernel do OpenNT.
pub fn driver_module(shared: &Shared, address: u64) -> Option<String> {
    shared.snapshot.modules.iter().find(|module| address >= module.base && address < module.end && module.source != "ELF do kernel").map(|module| module.name.clone())
}

/// Para dentro de um driver da Microsoft: no `IoCreateDevice` do kernel
/// (chamado pelo DriverEntry ou pelo AddDevice de um driver real) e, de lá,
/// no endereço de retorno dentro do driver. Devolve o módulo.
pub fn stop_inside_driver(backend: &Backend, log: &dyn Fn(&str)) -> Result<String, String> {
    const HOOK: &str = "kernel::ntos::io::device::create_device";
    stop_at(backend, HOOK, log)?;
    for _ in 0..40 {
        let found = {
            let shared = backend.shared();
            shared.snapshot.frames.iter().skip(1).find_map(|frame| driver_module(&shared, frame.address).map(|module| (frame.address, module)))
        };
        if let Some((address, module)) = found {
            log(&format!("retorno em {module} ({address:#x})"));
            let hook = backend.shared().snapshot.breakpoints.iter().find(|breakpoint| breakpoint.expression == HOOK).map(|breakpoint| breakpoint.id);
            if let Some(id) = hook {
                backend.send(Request::RemoveBreakpoint(id));
            }
            let target = format!("{address:#x}");
            stop_at(backend, &target, log)?;
            let temporary = backend.shared().snapshot.breakpoints.iter().find(|breakpoint| breakpoint.address == address).map(|breakpoint| breakpoint.id);
            if let Some(id) = temporary {
                let before = generation(backend);
                backend.send(Request::RemoveBreakpoint(id));
                wait(backend, "o breakpoint temporario removido", Duration::from_secs(60), log, |shared| shared.snapshot.generation > before)?;
            }
            return Ok(module);
        }
        // O próprio kernel criou o dispositivo: a próxima chamada.
        let before = generation(backend);
        backend.send(Request::Go);
        wait_stop(backend, "a proxima chamada ao IoCreateDevice", before, Duration::from_secs(600), log)?;
    }
    Err("nenhum driver chamou o IoCreateDevice".into())
}

/// Espera o PDB público do módulo (o download em segundo plano); sem rede,
/// segue com os exports.
pub fn wait_for_driver_symbols(backend: &Backend, module: &str, log: &dyn Fn(&str)) -> bool {
    let deadline = Instant::now() + Duration::from_secs(180);
    while Instant::now() < deadline {
        let (pdb, pending) = backend.shared().snapshot.modules.iter().find(|row| row.name == module).map_or((false, false), |row| (row.pdb, row.pending));
        if pdb {
            return true;
        }
        if pending {
            log(&format!("baixando o PDB de {module}"));
        }
        let before = generation(backend);
        backend.send(Request::ReloadSymbols);
        let _ = wait(backend, &format!("o PDB de {module}"), Duration::from_secs(30), log, |shared| shared.snapshot.generation > before);
        std::thread::sleep(Duration::from_secs(2));
    }
    log(&format!("sem o PDB de {module}: seguem os exports"));
    false
}

/// Continua até o shell e manda o Ctrl direito com Scroll Lock duas vezes
/// (o CrashOnCtrlScroll do i8042prt.sys real): a parada do KeBugCheckEx.
pub fn trigger_bugcheck(backend: &Backend, log: &dyn Fn(&str)) -> Result<(), String> {
    if backend.shared().status == Status::Stopped {
        backend.send(Request::Go);
        wait(backend, "a maquina rodando", Duration::from_secs(60), log, |shared| shared.status == Status::Running)?;
    }
    wait(backend, "o shell na COM1", Duration::from_secs(1200), log, |shared| shared.serial.contains("[shell] pronto"))?;
    std::thread::sleep(Duration::from_secs(2));
    let before = generation(backend);
    backend.send(Request::SendKeys("ctrl_r-scroll_lock-scroll_lock".into()));
    wait(backend, "a parada pelo bugcheck", Duration::from_secs(300), log, |shared| shared.status == Status::Stopped && shared.snapshot.generation > before && shared.snapshot.bugcheck.is_some() && shared.activity.is_empty())
}
