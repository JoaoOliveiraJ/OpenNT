//! A sessão inteira contra um alvo de mentira: um stub do protocolo remoto
//! do GDB num socket local, com registradores, uma pilha capturada e as
//! paradas roteirizadas. Confere a negociação, a pilha pelos frame
//! pointers, os breakpoints (ligar, desligar, religar, tirar) e o passo por
//! cima de um `call`, inclusive o retorno numa recursão mais funda (o
//! cliente segue sozinho até o RSP certo), o breakpoint condicional e a
//! parada pela carga de um módulo.

mod support;

use std::time::Duration;

use kd_client::client::{BreakpointOptions, BreakpointRequest, Resumed};
use kd_client::BreakpointKind;
use support::fake_stub::{connect, connect_replay, start, Stop, CODE, STACK, USER_DATA};

/// A reprodução: os módulos da gravação, as consultas recusadas sem ir ao
/// alvo, um passo para a frente e o passo para trás de volta ao RIP de
/// antes, e o "voltar até o breakpoint".
#[test]
fn replay_steps_back_to_the_previous_rip() {
    let stops = vec![Stop::at(CODE + 4, "T05thread:1;"), Stop::at(CODE, "T05thread:1;"), Stop::at(CODE + 0x2000, "T05thread:1;swbreak:;")];
    let (address, log) = start(stops);
    let recorded = vec![(0xfffff800_4200_0000, 0xfffff800_4201_0000, "\\SystemRoot\\System32\\drivers\\gravado.sys".to_string())];
    let mut client = connect_replay(&address, recorded);
    assert!(client.is_replay());
    assert!(client.reverse_supported());
    assert!(client.symbols.modules.iter().any(|module| module.name == "gravado"), "{:?}", client.symbols.modules.iter().map(|module| module.name.clone()).collect::<Vec<_>>());
    assert!(client.monitor("ps").unwrap_err().contains("reproducao"));
    assert!(!log.lock().unwrap().iter().any(|packet| packet.starts_with("qRcmd")));
    let before = client.register("rip").unwrap();
    client.step().unwrap();
    assert_eq!(client.register("rip").unwrap(), CODE + 4);
    client.reverse_step().unwrap();
    assert_eq!(client.register("rip").unwrap(), before);
    assert!(log.lock().unwrap().iter().any(|packet| packet == "bs"));
    let stop = client.reverse_continue().unwrap();
    assert!(stop.contains("kernel::alvo::chamador"), "{stop}");
    assert!(log.lock().unwrap().iter().any(|packet| packet == "bc"));
    // Fora da reprodução, os passos para trás são recusados.
    let (address, _) = start(Vec::new());
    let mut normal = connect(&address);
    assert!(normal.reverse_step().unwrap_err().contains("reproducao"));
}

/// Os comandos de objetos do NT que não precisam do PDB: a tabela de
/// handles filtrada (com o tipo `ALPC Port` inteiro), as portas de um
/// processo consultadas no stub pelo handle, a ObTypeIndexTable e a porta
/// de conclusão pelo endereço.
#[test]
fn object_commands_over_the_stub() {
    let (address, _) = start(Vec::new());
    let mut client = connect(&address);
    let output = client.execute("!handles 500 alpc").unwrap();
    assert!(output.contains("PID 500 csrss.exe handles 3 mostrados 1"), "{output}");
    assert!(output.contains("ALPC_Port"), "{output}");
    assert!(output.contains("\\Windows\\ApiPort"), "{output}");
    let output = client.execute("!alpc 500").unwrap();
    assert!(output.contains("1 handles ALPC_Port"), "{output}");
    assert!(output.contains("HANDLE 0x8 objeto 0xffffc00000800000"), "{output}");
    assert!(output.contains("ALPC 0xffffc00000800000 tipo alpc"), "{output}");
    assert!(output.contains("fila-do-servidor 2"), "{output}");
    let output = client.execute("!obtypes").unwrap();
    assert!(output.contains("ObHeaderCookie 0x5a"), "{output}");
    let output = client.execute("!iocp 0xffffc00000900000").unwrap();
    assert!(output.contains("IOCP 0xffffc00000900000"), "{output}");
    assert!(client.execute("!handles 77").unwrap_err().contains("processo nao encontrado"));
}

#[test]
fn backtrace_registers_and_memory() {
    let (address, log) = start(Vec::new());
    let mut client = connect(&address);
    assert_eq!(client.register("rip").unwrap(), CODE);
    assert_eq!(client.evaluate("%rbp+8").unwrap(), STACK + 0x28);
    assert_eq!(client.evaluate("[%rbp+8]").unwrap(), CODE + 0x2010);
    let frames = client.backtrace(16).unwrap();
    let text = client.format_frames(&frames);
    assert_eq!(frames.len(), 3, "{text}");
    assert!(text.contains("kernel::alvo::corrente"), "{text}");
    assert!(text.contains("kernel::alvo::chamador+0x10"), "{text}");
    assert!(text.contains("kernel::alvo::kmain+0x20"), "{text}");
    // Gravar um registrador refaz o `g` (o cache da parada é descartado).
    client.write_register("rax", 0x1234).unwrap();
    assert_eq!(client.register("rax").unwrap(), 0x1234);
    assert!(log.lock().unwrap().iter().any(|packet| packet == "P0=3412000000000000"));
    let output = client.execute("x %rsp 16").unwrap();
    assert!(output.contains("ffff800000100f00"), "{output}");
}

#[test]
fn breakpoints_enable_disable_remove() {
    let (address, log) = start(Vec::new());
    let mut client = connect(&address);
    let breakpoint = client.add_breakpoint(BreakpointKind::Software, "kernel::alvo::chamador", 1).unwrap();
    assert_eq!(breakpoint.address, CODE + 0x2000);
    client.set_breakpoint_enabled(breakpoint.id, false).unwrap();
    assert!(!client.breakpoints()[0].enabled);
    client.set_breakpoint_enabled(breakpoint.id, true).unwrap();
    let hardware = client.add_breakpoint(BreakpointKind::Hardware, "kernel::alvo::kmain", 1).unwrap();
    assert!(!client.toggle_breakpoint(CODE + 0x2000).unwrap());
    assert!(client.toggle_breakpoint(CODE + 0x10).unwrap());
    client.remove_breakpoint(hardware.id).unwrap();
    assert_eq!(client.breakpoints().len(), 1);
    assert_eq!(client.breakpoints()[0].expression, "kernel::alvo::corrente+0x10");
    let sent: Vec<String> = log.lock().unwrap().iter().filter(|packet| packet.starts_with('Z') || packet.starts_with('z')).cloned().collect();
    assert_eq!(sent, vec!["Z0,fffff80040102000,1", "z0,fffff80040102000,1", "Z0,fffff80040102000,1", "Z1,fffff80040103000,1", "z0,fffff80040102000,1", "Z0,fffff80040100010,1", "z1,fffff80040103000,1"]);
}

#[test]
fn step_over_skips_deeper_recursion() {
    // O `call` está em CODE + 4 (RSP = STACK - 0x20 depois do `sub`). A
    // primeira parada no retorno vem com outro RSP (uma recursão mais
    // funda): o cliente segue sozinho; a segunda é a certa.
    let stops = vec![
        Stop { rip: CODE + 4, rsp: STACK - 0x20, packet: "T05thread:1;", rax: 0, load: None },
        Stop { rip: CODE + 9, rsp: STACK - 0x80, packet: "T05thread:1;swbreak:;", rax: 0, load: None },
        Stop { rip: CODE + 9, rsp: STACK - 0x20, packet: "T05thread:1;swbreak:;", rax: 0, load: None },
    ];
    let (address, log) = start(stops);
    let mut client = connect(&address);
    // O `sub rsp, 0x20` não é chamada: passo simples.
    match client.step_over().unwrap() {
        Resumed::Stopped(text) => assert!(text.contains("SIGTRAP"), "{text}"),
        Resumed::Running => panic!("um passo simples terminaria na hora"),
    }
    assert_eq!(client.register("rip").unwrap(), CODE + 4);
    assert_eq!(client.step_over().unwrap(), Resumed::Running);
    let stop = client.wait_stop(Duration::from_secs(10)).unwrap();
    assert!(stop.contains("kernel::alvo::corrente+0x9"), "{stop}");
    assert_eq!(client.register("rsp").unwrap(), STACK - 0x20);
    let sent: Vec<String> = log.lock().unwrap().iter().filter(|packet| matches!(packet.as_bytes().first(), Some(b'Z' | b'z' | b'c' | b's'))).cloned().collect();
    assert_eq!(sent, vec!["s", "Z0,fffff80040100009,1", "c", "c", "z0,fffff80040100009,1"]);
    assert!(client.breakpoints().is_empty());
}

#[test]
fn conditional_breakpoint_and_pass_count() {
    // Três acertos em CODE + 0x10: RAX 1, 7 e 7. Com a condição `@rax == 7`
    // e a contagem 3, só o terceiro para; os outros seguem sozinhos.
    let stops = vec![
        Stop { rip: CODE + 0x10, rsp: STACK, packet: "T05thread:1;swbreak:;", rax: 1, load: None },
        Stop { rip: CODE + 0x10, rsp: STACK, packet: "T05thread:1;swbreak:;", rax: 7, load: None },
        Stop { rip: CODE + 0x10, rsp: STACK, packet: "T05thread:1;swbreak:;", rax: 7, load: None },
    ];
    let (address, log) = start(stops);
    let mut client = connect(&address);
    let text = client.execute("bp kernel::alvo::corrente+0x10 3 /w \"@rax == 7\"").unwrap();
    assert!(text.contains("a partir do acerto 3") && text.contains("se @rax == 7"), "{text}");
    client.go().unwrap();
    let stop = client.wait_stop(Duration::from_secs(10)).unwrap();
    assert!(stop.contains("breakpoint #0, condicao verdadeira, acerto 3"), "{stop}");
    assert_eq!(client.register("rax").unwrap(), 7);
    assert_eq!(client.breakpoints()[0].hits, 3);
    let continues = log.lock().unwrap().iter().filter(|packet| *packet == "c").count();
    assert_eq!(continues, 3);
    // A sessão gravada recria o breakpoint com a condição.
    let specs = client.breakpoint_specs();
    assert!(specs.starts_with("software\t1\t1\t3\tkernel::alvo::corrente+0x10\t@rax == 7"), "{specs}");
}

#[test]
fn stops_when_a_module_loads() {
    // A notificação de carga para duas vezes: primeiro outro módulo (segue
    // sozinho), depois o pedido.
    let hook = CODE + 0x1000;
    let stops = vec![
        Stop { rip: hook, rsp: STACK, packet: "T05thread:1;swbreak:;", rax: 0, load: Some("outro.sys") },
        Stop { rip: hook, rsp: STACK, packet: "T05thread:1;swbreak:;", rax: 0, load: Some("novo.sys") },
    ];
    let (address, log) = start(stops);
    let mut client = connect(&address);
    let text = client.execute("sxe ld:novo").unwrap();
    assert!(text.contains("para quando novo carregar"), "{text}");
    // Um breakpoint adiado num módulo que ainda não existe.
    let text = client.execute("bu novo!Entrada").unwrap();
    assert!(text.contains("adiado"), "{text}");
    client.go().unwrap();
    let stop = client.wait_stop(Duration::from_secs(10)).unwrap();
    assert!(stop.contains("modulo carregado: novo.sys"), "{stop}");
    assert!(client.symbols.module_named("novo").is_some());
    let sent: Vec<String> = log.lock().unwrap().iter().filter(|packet| matches!(packet.as_bytes().first(), Some(b'Z' | b'z' | b'c'))).cloned().collect();
    assert_eq!(sent, vec!["Z0,fffff80040101000,1", "c", "c"]);
    let list = client.execute("bl").unwrap();
    assert!(list.contains("ld:novo") && list.contains("(adiado)"), "{list}");
}

#[test]
fn extended_registers_and_debug_registers() {
    let (address, _) = start(Vec::new());
    let mut client = connect(&address);
    let state = client.extended_registers().unwrap();
    // XMM0 = 00..0f, XMM15 = 0f..1e (pelo `g`); MXCSR padrão.
    assert_eq!(state.xmm[0].unwrap()[1], 1);
    assert_eq!(state.xmm[15].unwrap()[0], 15);
    assert_eq!(state.mxcsr, Some(0x1F80));
    // As extensões do OpenNT por `p`: a metade alta dos YMM e os DRs.
    assert_eq!(state.ymm_high[3], Some([0xA3; 16]));
    assert_eq!(state.ymm(3).unwrap()[16], 0xA3);
    assert_eq!(state.debug[0], Some(0xD0));
    assert_eq!(state.debug[5], Some(0x401));
    assert_eq!(client.evaluate("@dr7").unwrap(), 0x401);
    // O comando de texto do cargo xtask debug.
    let text = client.execute("rx").unwrap();
    assert!(text.contains("xmm0  0f0e0d0c0b0a09080706050403020100"), "{text}");
    assert!(text.contains("ymm3h a3a3") && text.contains("dr7: DR0:L x/1"), "{text}");
}

#[test]
fn breakpoint_options_log_condition_single_shot_and_silent() {
    // Três acertos em CODE + 0x10 com RAX 1, 2 e 3: a condição de parada é
    // `@rax == 3`, o log só sai com `@rax >= 2` e o breakpoint some depois
    // de parar (uma vez só).
    let stops = vec![
        Stop { rip: CODE + 0x10, rsp: STACK, packet: "T05thread:1;swbreak:;", rax: 1, load: None },
        Stop { rip: CODE + 0x10, rsp: STACK, packet: "T05thread:1;swbreak:;", rax: 2, load: None },
        Stop { rip: CODE + 0x10, rsp: STACK, packet: "T05thread:1;swbreak:;", rax: 3, load: None },
    ];
    let (address, log) = start(stops);
    let mut client = connect(&address);
    let mut request = BreakpointRequest::new(BreakpointKind::Software, "kernel::alvo::corrente+0x10");
    request.condition = "@rax == 3".into();
    request.log = "rax={@rax:d}".into();
    request.command = "r rax".into();
    request.options = BreakpointOptions { name: "laco".into(), log_condition: "@rax >= 2".into(), command_condition: String::new(), single_shot: true, silent: true, fast_resume: false };
    let breakpoint = client.add_breakpoint_with(&request).unwrap();
    client.go().unwrap();
    let stop = client.wait_stop(Duration::from_secs(10)).unwrap();
    assert!(stop.contains("breakpoint #0 laco, condicao verdadeira, acerto 3"), "{stop}");
    assert!(stop.contains("uma vez so removido"), "{stop}");
    // O log saiu nos acertos 2 e 3; sem a linha de acerto (silencioso).
    assert_eq!(client.log_lines(), &["[bp #0 laco] rax=2".to_string(), "[bp #0 laco] rax=3".to_string()]);
    // Os comandos ficam para quem trata a parada (a condição vazia vale a
    // da parada).
    assert_eq!(client.stop_commands(), Some((breakpoint.id, "r rax".into())));
    assert!(client.breakpoints().is_empty());
    assert!(log.lock().unwrap().iter().any(|packet| packet == "z0,fffff80040100010,1"));
    // As opções voltam pelo arquivo de sessão.
    let mut request = BreakpointRequest::new(BreakpointKind::Software, "kernel::alvo::chamador");
    request.options = BreakpointOptions { name: "nome".into(), log_condition: "1".into(), command_condition: "@rax".into(), single_shot: false, silent: true, fast_resume: true };
    client.add_breakpoint_with(&request).unwrap();
    let specs = client.breakpoint_specs();
    assert!(specs.trim_end().ends_with("\tnome\t1\t@rax\tqf"), "{specs:?}");
    let id = client.breakpoints()[0].id;
    client.remove_breakpoint(id).unwrap();
    assert!(client.restore_breakpoints(&specs).is_empty());
    assert_eq!(client.breakpoints()[0].options, request.options);
}

#[test]
fn memory_breakpoint_by_page() {
    // A primeira parada é de outra página vigiada (nenhum breakpoint do
    // cliente a cobre: segue); a segunda cai na página pedida.
    let stops = vec![
        Stop { rip: CODE + 0x20, rsp: STACK, packet: "T05thread:1;awatch:7ff600005008;membp:7ff600005008;", rax: 0, load: None },
        Stop { rip: CODE + 0x24, rsp: STACK, packet: "T05thread:1;watch:7ff600001010;membp:7ff600001010;", rax: 0, load: None },
    ];
    let (address, log) = start(stops);
    let mut client = connect(&address);
    let text = client.execute(&format!("bpm w {:#x} 0x20", USER_DATA + 0x10)).unwrap();
    assert!(text.contains("breakpoint de memoria (memoria-escrita)"), "{text}");
    // A faixa vira páginas inteiras.
    let breakpoint = client.breakpoints()[0].clone();
    assert_eq!((breakpoint.address, breakpoint.length), (USER_DATA, 0x1000));
    assert!(client.monitor("membp").unwrap().contains("0x7ff600001000 0x1000 w"));
    client.go().unwrap();
    let stop = client.wait_stop(Duration::from_secs(10)).unwrap();
    assert!(stop.contains("breakpoint #0, acerto 1"), "{stop}");
    assert_eq!(log.lock().unwrap().iter().filter(|packet| *packet == "c").count(), 2);
    client.execute(&format!("bpmc {:#x}", USER_DATA)).unwrap();
    assert!(client.breakpoints().is_empty());
    assert!(client.monitor("membp").unwrap().contains("nenhum"));
}
