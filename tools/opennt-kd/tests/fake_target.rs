//! A sessão inteira contra um alvo de mentira: um stub do protocolo remoto
//! do GDB num socket local, com registradores, uma pilha capturada e as
//! paradas roteirizadas. Confere a negociação, a pilha pelos frame
//! pointers, os breakpoints (ligar, desligar, religar, tirar) e o passo por
//! cima de um `call`, inclusive o retorno numa recursão mais funda (o
//! cliente segue sozinho até o RSP certo), o breakpoint condicional e a
//! parada pela carga de um módulo. E os roteiros (`kd_script`): o log que
//! sai à medida que chega, os tratadores de parada, as condições, os laços
//! e as mensagens de erro.

mod support;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use opennt_kd::client::{BreakpointOptions, BreakpointRequest, Resumed};
use opennt_kd::kd_script::{check_script, ScriptHost, ScriptOptions};
use opennt_kd::symbols::Symbol;
use opennt_kd::{BreakpointKind, Client};
use support::fake_stub::{connect, connect_replay, kernel_module, start, start_opennt, start_with, Stop, CODE, STACK, USER_DATA};

/// Os pacotes de breakpoint e de continuação mandados ao alvo.
fn breakpoint_packets(log: &std::sync::Mutex<Vec<String>>) -> Vec<String> {
    log.lock().unwrap().iter().filter(|packet| matches!(packet.as_bytes().first(), Some(b'Z' | b'z' | b'c'))).cloned().collect()
}

/// Um `bu /p alvo.exe` arma na carga da DLL no processo (o ponto de evento
/// de imagem, sem a DLL nos módulos da sessão e sem arquivo nesta máquina:
/// `módulo+0xRVA`), para no acerto e some quando o processo sai.
#[test]
fn deferred_user_breakpoint_arms_in_the_loading_process() {
    let image_hook = CODE + 0x1100;
    let process_hook = CODE + 0x1200;
    let name_address = 0xffff_a000_0001_0000u64;
    let name = b"\\Windows\\System32\\falso.dll".to_vec();
    let (base, eprocess, pid) = (0x7ff7_1000_0000u64, 0xffff_a000_0000_7000u64, 0x99u64);
    let stops = vec![
        Stop::at(image_hook, "T05thread:1;swbreak:;"),
        Stop::at(base + 0x1234, "T05thread:1;swbreak:;"),
        Stop::at(process_hook, "T05thread:1;swbreak:;"),
        Stop::at(CODE + 0x20, "T05thread:1;"),
    ];
    // Os argumentos dos pontos de evento: RDI, RSI, RDX, RCX e R8 (índices
    // 5, 4, 3, 2 e 8 do `g`).
    let registers = vec![vec![(5, base), (4, 0x20000), (3, pid), (2, name_address), (8, name.len() as u64)], Vec::new(), vec![(5, eprocess), (4, pid), (3, 0)]];
    let processes = format!("PID EPROCESS CR3 threads nome\n{pid:#x} {eprocess:#x} 0x12345000 3 alvo.exe\n");
    let (address, log) = start_with(stops, registers, vec![(name_address, name)], &processes);
    let mut client = connect(&address);
    let mut kernel = kernel_module();
    kernel.symbols.push(Symbol { address: image_hook, size: 0x10, name: "opennt_kd_image_event".into(), function: true });
    kernel.symbols.push(Symbol { address: process_hook, size: 0x10, name: "opennt_kd_process_event".into(), function: true });
    kernel.symbols.sort_by_key(|symbol| symbol.address);
    client.symbols.set_kernel(kernel);
    let text = client.execute("bu /p alvo.exe falso+0x1234").unwrap();
    assert!(text.contains("modelo") && text.contains("/p alvo.exe"), "{text}");
    client.go().unwrap();
    let stop = client.wait_stop(Duration::from_secs(10)).unwrap();
    assert!(stop.contains("breakpoint #1, acerto 1"), "{stop}");
    assert_eq!(client.breakpoints().len(), 2);
    assert_eq!((client.breakpoints()[1].address, client.breakpoints()[1].process), (base + 0x1234, eprocess));
    assert_eq!(client.breakpoint_instances(0), vec![1]);
    assert!(client.log_lines().iter().any(|line| line.contains("instancia #1") && line.contains("alvo.exe")), "{:?}", client.log_lines());
    client.go().unwrap();
    let stop = client.wait_stop(Duration::from_secs(10)).unwrap();
    assert!(!stop.contains("breakpoint #"), "{stop}");
    // A instância saiu com o processo; o modelo segue adiado.
    assert_eq!(client.breakpoints().len(), 1);
    assert!(client.breakpoints()[0].pending);
    assert!(client.breakpoint_instances(0).is_empty());
    assert_eq!(breakpoint_packets(&log), vec!["Z0,fffff80040101100,1", "c", "Z0,7ff710001234,1", "Z0,fffff80040101200,1", "c", "c", "z0,fffff80040101200,1", "c"]);
    // O modelo volta pelo arquivo de sessão com o `/p`.
    assert!(client.breakpoint_specs().trim_end().ends_with("\talvo.exe\t0"), "{:?}", client.breakpoint_specs());
}

/// O `/max`: depois de dois acertos registrados, o breakpoint se desliga.
#[test]
fn hit_limit_disables_the_breakpoint() {
    let stops = vec![
        Stop { rip: CODE + 0x10, rsp: STACK, packet: "T05thread:1;swbreak:;", rax: 1, load: None },
        Stop { rip: CODE + 0x10, rsp: STACK, packet: "T05thread:1;swbreak:;", rax: 2, load: None },
        Stop::at(CODE + 0x20, "T05thread:1;"),
    ];
    let (address, log) = start(stops);
    let mut client = connect(&address);
    let text = client.execute("bp kernel::alvo::corrente+0x10 /log \"x={@rax:d}\" /max 2").unwrap();
    assert!(text.contains("max 2"), "{text}");
    client.go().unwrap();
    let stop = client.wait_stop(Duration::from_secs(10)).unwrap();
    assert!(!stop.contains("breakpoint #0"), "{stop}");
    assert_eq!(client.log_lines(), &["[bp #0] x=1".to_string(), "[bp #0] x=2".to_string(), "[bp #0] limite de 2 acertos: desligado".to_string()]);
    assert!(!client.breakpoints()[0].enabled);
    assert_eq!(breakpoint_packets(&log), vec!["Z0,fffff80040100010,1", "c", "c", "z0,fffff80040100010,1", "c"]);
}

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

/// Com as extensões do alvo do OpenNT: o filtro de carga no lugar do
/// breakpoint na notificação (a carga de outro módulo nem chega ao
/// cliente), nenhum `g` (os registradores vêm na resposta de parada), o
/// `lm` só quando a impressão digital muda e a memória pelo `x` binário.
#[test]
fn opennt_target_filters_loads_without_g_or_lm() {
    let stops = vec![
        // A carga de outro módulo: o filtro do alvo não deixa parar.
        Stop { rip: CODE + 0x1000, rsp: STACK, packet: "T05thread:1;swbreak:;", rax: 0, load: Some("outro.sys") },
        Stop { rip: CODE + 0x1000, rsp: STACK, packet: "T05thread:1;swbreak:;", rax: 0, load: Some("novo.sys") },
        // Um passo depois: a lista de módulos não mudou.
        Stop::at(CODE + 4, "T05thread:1;"),
    ];
    let (address, log) = start_opennt(stops);
    let mut client = connect(&address);
    // `monitor lm` (o `qRcmd` com "lm" em hexadecimal).
    fn lm_requests(log: &std::sync::Mutex<Vec<String>>) -> usize {
        log.lock().unwrap().iter().filter(|packet| *packet == "qRcmd,6c6d").count()
    }
    // O attach leu a lista uma vez e esvaziou o filtro de uma sessão velha.
    assert_eq!(lm_requests(&log), 1);
    assert!(log.lock().unwrap().iter().any(|packet| packet == "QOpenNTLoadBreak:"));
    let text = client.execute("sxe ld:novo").unwrap();
    assert!(text.contains("para quando novo carregar"), "{text}");
    let text = client.execute("bu novo!Entrada").unwrap();
    assert!(text.contains("adiado"), "{text}");
    client.go().unwrap();
    let stop = client.wait_stop(Duration::from_secs(10)).unwrap();
    assert!(stop.contains("modulo carregado: novo.sys"), "{stop}");
    assert!(stop.contains("library novo.sys"), "{stop}");
    assert!(client.symbols.module_named("novo").is_some());
    // Os dois módulos novos: uma releitura nesta parada.
    assert_eq!(lm_requests(&log), 2);
    assert_eq!(client.register("rip").unwrap(), CODE + 0x1000);
    // Um passo: a mesma impressão digital, sem `lm`; o RIP sem `g`.
    client.step().unwrap();
    assert_eq!(client.register("rip").unwrap(), CODE + 4);
    assert_eq!(lm_requests(&log), 2);
    // A memória em binário (os bytes acima de 0x7F intactos).
    let code = client.read_memory(CODE, 10).unwrap();
    assert_eq!(code, vec![0x48, 0x83, 0xEC, 0x20, 0xE8, 0, 0, 0, 0, 0x90]);
    let sent = log.lock().unwrap().clone();
    assert!(sent.iter().any(|packet| packet == "xfffff80040100000,a"), "{sent:?}");
    assert!(!sent.iter().any(|packet| packet.starts_with('m')), "{sent:?}");
    assert!(!sent.iter().any(|packet| packet == "g"), "{sent:?}");
    // Nenhum breakpoint na notificação de carga; o filtro foi uma vez.
    assert!(!sent.iter().any(|packet| packet.starts_with("Z0")), "{sent:?}");
    assert_eq!(sent.iter().filter(|packet| packet.starts_with("QOpenNTLoadBreak:novo")).count(), 1, "{sent:?}");
    assert_eq!(sent.iter().filter(|packet| *packet == "c").count(), 1);
    // O registrador gravado volta pelo `g`.
    client.write_register("rax", 0x55).unwrap();
    assert_eq!(client.register("rax").unwrap(), 0x55);
    assert!(log.lock().unwrap().iter().any(|packet| packet == "g"));
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

/// O roteiro: as linhas do breakpoint de log saem na transcrição à medida
/// que chegam (antes da parada), o tratador da parada roda e deixa a
/// máquina parada, as condições, os laços pelas linhas, processos e
/// threads, as variáveis tiradas da saída e as esperas pela COM1 com prazo.
#[test]
fn script_log_lines_handlers_conditions_and_loops() {
    // Dois acertos do breakpoint de log (RAX 1 e 2) e a parada no chamador.
    let stops = vec![
        Stop { rip: CODE + 0x10, rsp: STACK, packet: "T05thread:1;swbreak:;", rax: 1, load: None },
        Stop { rip: CODE + 0x10, rsp: STACK, packet: "T05thread:1;swbreak:;", rax: 2, load: None },
        Stop { rip: CODE + 0x2000, rsp: STACK, packet: "T05thread:1;swbreak:;", rax: 7, load: None },
    ];
    let (address, log) = start(stops);
    let mut client = connect(&address);
    client.set_serial(Arc::new(Mutex::new("[boot] ok\n[shell] pronto\n".to_string())));
    let transcript = std::env::temp_dir().join(format!("kd-script-teste-{}.log", std::process::id()));
    let script = r#"
bp kernel::alvo::corrente+0x10 /log "rax={@rax:d}"
bp kernel::alvo::chamador
set contador 0
on-break kernel::alvo::chamador {
    save contador $contador+1
    expect-stop chamador
    stop
}
continue
wait-stop 10000
expect-stop breakpoint #1
expect-eq $contador 1
expect-eq $hits 1
expect-eq @rax 7
if console-has rax=2 {
    echo o log chegou
} else {
    fail sem o log
}
bl
for-each line linha containing software {
    echo ${linha.0}
}
expect-eq $linha_count 2
ps
save-after cr3 0xffffe00000042000
expect-eq $cr3 0x2cd000
save-text nome smss.exe -1
for-each process p name smss {
    leave
}
expect-eq $p_pid 100
expect-eq $p 0xffffe00000042000
if "${p_name}" != "${nome}" {
    fail nome errado: ${p_name}
}
for-each thread t state Waiting process System {
    next
}
expect-eq $t_count 2
expect-eq $t_tid 12
if wait-serial /t 200 nunca-aparece {
    fail achou o que nao existe
}
wait-serial /t 1000 [shell] pronto
repeat 3 volta {
    save ultima $volta
}
expect-eq $ultima 2
"#;
    let options = ScriptOptions { name: "teste.txt".into(), transcript: Some(transcript.clone()), capture: None };
    let result = client.run_script_with(script, &options);
    let text = std::fs::read_to_string(&transcript).unwrap_or_default();
    let _ = std::fs::remove_file(&transcript);
    result.unwrap();
    // O breakpoint de log seguiu sozinho duas vezes; o tratador deixou a
    // máquina parada no chamador.
    assert_eq!(log.lock().unwrap().iter().filter(|packet| *packet == "c").count(), 3);
    assert!(client.is_stopped());
    let first_log = text.find("[kd-log] [bp #0] rax=1").expect(&text);
    let second_log = text.find("[kd-log] [bp #0] rax=2").expect(&text);
    let handler = text.find("> on-break kernel::alvo::chamador (linha 5)").expect(&text);
    assert!(first_log < second_log && second_log < handler, "{text}");
    assert!(text.contains("[kd-log] [bp #1] acerto 1"), "{text}");
    assert!(text.contains("[kd-script] [on-break #1] > save contador $contador+1"), "{text}");
    assert!(text.contains("[kd-script] o log chegou") && text.contains("[kd-script] #0") && text.contains("[kd-script] #1"), "{text}");
    assert!(text.contains("for-each process p name smss: 1 itens"), "{text}");
}

/// Uma conferência que falha mostra a linha, o comando anterior e a saída
/// dele; um erro de sintaxe sai antes de rodar; um erro dentro de um laço
/// diz a volta.
#[test]
fn script_errors_show_the_command_output_and_line() {
    let (address, _) = start(Vec::new());
    let mut client = connect(&address);
    let error = client.run_script("x %rsp 16\n# comentario\nexpect nada-disso\n").unwrap_err();
    assert!(error.starts_with("roteiro, linha 3: expect nada-disso: a saida do comando anterior nao tem \"nada-disso\""), "{error}");
    assert!(error.contains("comando (linha 1): x %rsp 16"), "{error}");
    assert!(error.contains("  | 0xffff800000100f00"), "{error}");
    let error = client.run_script("if 1 {\necho x\n").unwrap_err();
    assert!(error.contains("linha 1: if 1 {: if sem }"), "{error}");
    let error = client.run_script("set n 2\nrepeat 3 i {\n  if $i == $n {\n    fail volta ${i}\n  }\n}\n").unwrap_err();
    assert!(error.contains("linha 4: fail volta ${i} (= fail volta 0x2): volta 0x2"), "{error}");
    assert!(error.contains("dentro de: repeat da linha 2, volta 3 de 3"), "{error}");
}

/// Um tratador sem `stop` faz a máquina seguir: a espera continua até o
/// acerto em que ele a deixa parada.
#[test]
fn script_handler_resumes_until_it_stops() {
    let stops = (1..=3).map(|rax| Stop { rip: CODE + 0x10, rsp: STACK, packet: "T05thread:1;swbreak:;", rax, load: None }).collect();
    let (address, log) = start(stops);
    let mut client = connect(&address);
    let script = "bp kernel::alvo::corrente+0x10\non-break #0 {\n    print acerto {$hits:d} rax={@rax:d}\n    if $hits >= 3 {\n        stop\n    }\n}\ncontinue\nwait-stop 10000\nexpect-eq @rax 3\nexpect-eq $hits 3\non-break #0 off\n";
    client.run_script(script).unwrap();
    assert_eq!(log.lock().unwrap().iter().filter(|packet| *packet == "c").count(), 3);
    assert!(client.is_stopped());
}

/// Um `bp` num módulo que ainda não carregou fica adiado, como o `bu`; um
/// símbolo que falta num módulo carregado continua sendo erro.
#[test]
fn bp_on_a_module_not_loaded_is_deferred() {
    let (address, _) = start(Vec::new());
    let mut client = connect(&address);
    let text = client.execute("bp novo!Entrada /log \"entrou\"").unwrap();
    assert!(text.contains("modulo novo nao carregado: o bp ficou adiado (como o bu)"), "{text}");
    assert!(text.contains("adiado: novo!Entrada"), "{text}");
    assert!(client.breakpoints().iter().any(|breakpoint| breakpoint.pending && breakpoint.expression == "novo!Entrada" && breakpoint.log == "entrou"));
    let error = client.execute("bp kernel::alvo::nao_existe").unwrap_err();
    assert!(error.contains("simbolo nao encontrado"), "{error}");
    assert_eq!(client.breakpoints().len(), 1);
}

/// O `sleep` e o `wait-stop` aceitam `$variavel` e expressões; um argumento
/// que não dá número é erro (antes o `sleep` dormia 1000 ms sem aviso).
#[test]
fn script_sleep_takes_variables_and_rejects_text() {
    let (address, _) = start(Vec::new());
    let mut client = connect(&address);
    let started = Instant::now();
    client.run_script("set espera 60\nsleep $espera\nsave t 2*0n30\nsleep $t\nwait-stop $t\n").unwrap();
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(120) && elapsed < Duration::from_millis(1500), "{elapsed:?}");
    let error = client.run_script("echo a\nsleep muito\n").unwrap_err();
    assert!(error.contains("linha 2: sleep muito: uso: sleep <ms>"), "{error}");
    let error = client.run_script("wait-stop $nada\n").unwrap_err();
    assert!(error.contains("uso: wait-stop [ms]"), "{error}");
    let error = client.run_script("wait-serial /t depressa x\n").unwrap_err();
    assert!(error.contains("/t:"), "{error}");
}

/// O alvo que fecha a conexão durante uma espera (o QEMU que termina): o
/// erro diz que a conexão caiu e traz o fim da COM1.
#[test]
fn script_wait_reports_the_com1_tail_when_the_target_closes() {
    // Sem paradas roteirizadas: o `c` derruba o alvo de mentira.
    let (address, _) = start(Vec::new());
    let mut client = connect(&address);
    client.set_serial(Arc::new(Mutex::new("[boot] ok\n*** STOP: 0x000000E2 (teste)\n".to_string())));
    let error = client.run_script("continue\nsleep 5000\n").unwrap_err();
    assert!(error.contains("linha 2: sleep 5000: o alvo fechou a conexao"), "{error}");
    assert!(error.contains("a conexao caiu durante a espera") && error.contains("  | *** STOP: 0x000000E2 (teste)"), "{error}");
}

/// Um anfitrião de teste: guarda as linhas, o progresso e as voltas, e
/// responde ao `attach` e ao `detach` como a janela e o servidor MCP.
#[derive(Default)]
struct TestHost {
    lines: Vec<String>,
    progress: Vec<usize>,
    ticks: usize,
    /// Cancela depois de tantos passos.
    cancel_after: Option<usize>,
    deadline: Option<Instant>,
    serial: Option<PathBuf>,
    /// Atende a parada com este RAX (e a máquina segue).
    service_rax: Option<u64>,
    serviced: usize,
}

impl ScriptHost for TestHost {
    fn output(&mut self, line: &str) {
        self.lines.push(line.to_string());
    }

    fn progress(&mut self, line: usize, _text: &str) {
        self.progress.push(line);
    }

    fn tick(&mut self, _client: &mut Client) {
        self.ticks += 1;
    }

    fn cancelled(&self) -> bool {
        self.cancel_after.is_some_and(|steps| self.progress.len() > steps)
    }

    fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    fn serial_log(&self) -> Option<PathBuf> {
        self.serial.clone()
    }

    fn service_stop(&mut self, client: &mut Client) -> bool {
        let wanted = self.service_rax.is_some() && client.register("rax").ok() == self.service_rax;
        self.serviced += usize::from(wanted);
        wanted
    }

    fn intercept(&mut self, client: &mut Client, word: &str, _text: &str) -> Option<Result<String, String>> {
        match word {
            "attach" => Some(Ok(format!("sessao ja anexada\n{}", client.last_stop()))),
            "detach" => Some(Err("detach recusado pelo anfitriao".into())),
            _ => None,
        }
    }
}

/// O roteiro por um anfitrião: as linhas vão para ele, o `attach` e o
/// `detach` são dele, o `wait-serial` lê o log que ele passa (e acompanha o
/// arquivo crescendo), e o resultado diz os comandos, as variáveis e a
/// linha que falhou.
#[test]
fn hosted_script_routes_lines_and_reports_the_outcome() {
    let (address, _) = start(Vec::new());
    let mut client = connect(&address);
    let serial = std::env::temp_dir().join(format!("kd-script-com1-{}.log", std::process::id()));
    std::fs::write(&serial, "[boot] ok\n[shell] pronto\n").unwrap();
    let appender = {
        let serial = serial.clone();
        std::thread::spawn(move || {
            use std::io::Write;
            std::thread::sleep(Duration::from_millis(300));
            let mut file = std::fs::OpenOptions::new().append(true).open(&serial).unwrap();
            file.write_all(b"[shell] depois\n").unwrap();
        })
    };
    let mut host = TestHost { serial: Some(serial.clone()), ..TestHost::default() };
    let script = "attach\nexpect sessao ja anexada\nwait-serial /t 2000 [shell] pronto\nif serial-has [boot] ok {\n  echo com1 ok\n}\nwait-serial /t 1500 [shell] depois\nset n 3\nsave x 0x10\nrepeat $n i {\n  echo volta ${i}\n}\n";
    let outcome = client.run_script_hosted(script, &ScriptOptions::default(), &mut host);
    appender.join().unwrap();
    let _ = std::fs::remove_file(&serial);
    assert_eq!(outcome.result, Ok(()), "{:?}", host.lines);
    assert_eq!(outcome.failed_line, None);
    assert_eq!(outcome.commands, 10);
    assert_eq!(outcome.variables.get("x").map(String::as_str), Some("0x10"));
    assert_eq!(outcome.variables.get("n").map(String::as_str), Some("3"));
    assert_eq!(outcome.variables.get("i").map(String::as_str), Some("0x2"));
    assert!(host.lines.iter().any(|line| line == "[kd-script]   sessao ja anexada"), "{:?}", host.lines);
    assert!(host.lines.iter().any(|line| line == "[kd-script] com1 ok"), "{:?}", host.lines);
    assert!(host.lines.iter().any(|line| line == "[kd-script] volta 0x2"), "{:?}", host.lines);
    assert_eq!(host.progress, vec![1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 11, 11]);
    assert!(host.ticks >= host.progress.len());

    // O `detach` recusado pelo anfitrião encerra na linha dele.
    let mut host = TestHost::default();
    let outcome = client.run_script_hosted("echo a\ndetach\necho nunca\n", &ScriptOptions::default(), &mut host);
    assert!(outcome.result.as_ref().unwrap_err().contains("linha 2: detach: detach recusado pelo anfitriao"), "{outcome:?}");
    assert_eq!((outcome.failed_line, outcome.commands), (Some(2), 2));
    assert!(!host.lines.iter().any(|line| line.contains("nunca")));

    // Um erro de sintaxe: nada roda, e a linha vem no resultado.
    assert_eq!(check_script("echo a\nif 1 {\n").unwrap_err().0, 2);
    let mut host = TestHost::default();
    let outcome = client.run_script_hosted("echo a\nif 1 {\n", &ScriptOptions::default(), &mut host);
    assert_eq!((outcome.failed_line, outcome.commands), (Some(2), 0));
    assert!(host.lines.is_empty(), "{:?}", host.lines);
}

/// O Cancelar para antes do próximo comando; o prazo encurta o `sleep` e
/// não deixa o comando seguinte começar.
#[test]
fn hosted_script_cancel_and_deadline() {
    let (address, _) = start(Vec::new());
    let mut client = connect(&address);
    let mut host = TestHost { cancel_after: Some(1), ..TestHost::default() };
    let outcome = client.run_script_hosted("echo a\necho b\n", &ScriptOptions::default(), &mut host);
    assert!(outcome.result.as_ref().unwrap_err().contains("parado pelo usuario antes desta linha (Cancelar)"), "{outcome:?}");
    assert_eq!((outcome.failed_line, outcome.commands), (Some(2), 1));

    let started = Instant::now();
    let mut host = TestHost { deadline: Some(started + Duration::from_millis(200)), ..TestHost::default() };
    let outcome = client.run_script_hosted("sleep 5000\necho nunca\n", &ScriptOptions::default(), &mut host);
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    assert!(outcome.result.as_ref().unwrap_err().contains("linha 2: echo nunca: prazo esgotado antes desta linha"), "{outcome:?}");
    assert_eq!(outcome.failed_line, Some(2));
}

/// O anfitrião atende uma parada antes dos tratadores (o aviso de carga dos
/// adiados do opennt-mcp): a máquina segue e a espera chega à parada
/// seguinte.
#[test]
fn hosted_script_host_services_a_stop() {
    let stops = (1..=2).map(|rax| Stop { rip: CODE + 0x10, rsp: STACK, packet: "T05thread:1;swbreak:;", rax, load: None }).collect();
    let (address, log) = start(stops);
    let mut client = connect(&address);
    let mut host = TestHost { service_rax: Some(1), ..TestHost::default() };
    let outcome = client.run_script_hosted("bp kernel::alvo::corrente+0x10\ncontinue\nwait-stop 10000\nexpect-eq @rax 2\n", &ScriptOptions::default(), &mut host);
    assert_eq!(outcome.result, Ok(()), "{:?}", host.lines);
    assert_eq!(host.serviced, 1);
    assert_eq!(log.lock().unwrap().iter().filter(|packet| *packet == "c").count(), 2);
}
