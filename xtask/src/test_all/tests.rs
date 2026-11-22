//! Testes do `test-all`: a leitura dos comandos do `components.toml`, a
//! seleção e o trecho mostrado de uma falha.

use super::plan::{self, split_words, Extras, Suites, Test};
use super::report;

#[test]
fn commands_split_like_the_shell() {
    let words = split_words(r#"cargo xtask test-boot KERNEL_RS_OK 120000 "--keys=run hello\nps\n" "--expect== 42" "--expect=PID  STATE""#).unwrap();
    assert_eq!(words, ["cargo", "xtask", "test-boot", "KERNEL_RS_OK", "120000", r"--keys=run hello\nps\n", "--expect== 42", "--expect=PID  STATE"]);
    let words = split_words(r#"a "b \"c\" \\d" 'e f' g\ h"#).unwrap();
    assert_eq!(words, ["a", r#"b "c" \d"#, "e f", "g h"]);
    assert!(split_words(r#"a "b"#).is_err());
}

/// Todo `[[teste]]` do `components.toml` vira um `test-boot` válido, com
/// id único, e a seleção padrão leva as suítes e deixa de fora os cobertos
/// por elas e os que esperam falha; `--espera-falha` e `--all` os trazem.
#[test]
fn every_components_test_is_a_valid_test_boot() {
    let tests = plan::load(&crate::build::workspace_root()).unwrap();
    assert!(tests.len() > 2);
    let chosen = plan::select(&tests, &[], &[], Suites::Included, Extras::default()).unwrap();
    let with_failures = plan::select(&tests, &[], &[], Suites::Included, Extras { expected_failures: true, covered_by_suite: false }).unwrap();
    let all = plan::select(&tests, &[], &[], Suites::Included, Extras { expected_failures: true, covered_by_suite: true }).unwrap();
    assert_eq!(all.len(), tests.len());
    for (index, test) in tests.iter().enumerate() {
        assert!(!test.arguments.iter().any(|word| word.starts_with("--build-dir=") || word.starts_with("--accel")), "{}", test.id);
        assert_eq!(chosen.contains(&index), !test.covered_by_suite && !test.expected_failure, "{}", test.id);
        assert_eq!(with_failures.contains(&index), !test.covered_by_suite, "{}", test.id);
        assert!(test.accelerator.as_deref().is_none_or(|accelerator| plan::ACCELERATORS.contains(&accelerator)), "{}", test.id);
    }
    assert!(chosen.iter().any(|&index| tests[index].id == "suite-smp4"));
    // O primeiro logon continua conferido do volume novo nos testes dele; os
    // que só precisam da área de trabalho sobem do volume já logado.
    let first_logon = |id: &str| tests.iter().find(|test| test.id == id).unwrap().first_logon.is_some();
    for fresh in ["logon-do-usuario", "perfil-do-usuario", "sihost", "userinit", "explorer", "area-de-trabalho", "desligamento-cadeia"] {
        assert!(!first_logon(fresh), "{fresh} confere o primeiro logon: sobe do volume novo");
    }
    assert!(first_logon("barra-de-tarefas") && first_logon("reinicio-do-shell"));
    let only = plan::select(&tests, &[String::from("suite-smp1")], &[], Suites::Included, Extras::default()).unwrap();
    assert_eq!(only.len(), 1);
    assert!(plan::select(&tests, &[String::from("nao-existe")], &[], Suites::Included, Extras::default()).is_err());
    // As duas suítes dividem as imagens.
    let suites = plan::select(&tests, &[], &[], Suites::Only, Extras::default()).unwrap();
    let runs = plan::runs(&tests, &suites, &vec![Vec::new(); suites.len()], 2);
    let names: Vec<&str> = runs.iter().map(|run| run.name.as_str()).collect();
    assert_eq!(names, ["suite-smp4.1", "suite-smp4.2", "suite-smp1.1", "suite-smp1.2"]);
    assert!(runs.iter().all(|run| run.image == 0));
    assert_eq!(tests[runs[0].test].image_key, tests[runs[3].test].image_key);
}

/// A rodada inteira compila um kernel só: as opções de boot dos testes vão
/// nas opções de carga, e só o volume do smss, o do processo de console
/// (`--console-process`), o da conta de teste (`--conta-de-teste`), o das
/// contas embutidas desligadas (os testes com entrada: `--send`,
/// `--dismiss`, `--mouse`, `--start-menu`) e o do gancho que desliga a
/// cadeia (`--shutdown-test=cadeia`) pedem outras pastas de imagens, uma
/// por volume, e a lista dos volumes é esta.
#[test]
fn the_whole_round_compiles_one_kernel() {
    let tests = plan::load(&crate::build::workspace_root()).unwrap();
    let all: Vec<String> = tests.iter().map(|test| test.id.clone()).collect();
    let chosen = plan::select(&tests, &all, &[], Suites::Included, Extras::default()).unwrap();
    let (booted, guests) = plan::split_guests(&tests, &chosen, true);
    assert_eq!(booted, chosen, "no capturas cada teste sobe o proprio QEMU");
    let runs = plan::runs(&tests, &booted, &guests, 1);
    let mut kernels: Vec<&str> = runs.iter().map(|run| tests[run.test].kernel_key.as_str()).collect();
    kernels.dedup();
    assert_eq!(kernels.len(), 1, "builds do kernel diferentes na rodada");
    // Cada pasta de imagens é um volume: o processo inicial, o processo de
    // console, a conta de teste, as contas embutidas desligadas, o gancho
    // que desliga a cadeia, o escopo e-process (que leva os programas do
    // boot do smss ao volume) e o volume do sistema no ntfs.sys (o disco
    // particionado).
    let volume = |test: &Test| {
        let mut command = vec![String::from("test-boot")];
        command.extend(test.arguments.iter().cloned());
        let options = crate::test_build_options(&crate::parse(command).unwrap());
        // Com a conta de teste, as contas embutidas desligadas não mudam o
        // volume (o gancho da conta já as desliga).
        let builtin = options.builtin_accounts_off && !options.test_account;
        (options.initial_process.clone(), options.console_process, options.test_account, builtin, options.shutdown_chain, options.kernel_test_scope == "e-process", !options.system_volume.is_empty())
    };
    let mut volumes: Vec<(String, bool, bool, bool, bool, bool, bool)> = Vec::new();
    for run in &runs {
        let found = volume(&tests[run.test]);
        if !volumes.contains(&found) {
            volumes.push(found);
        }
    }
    volumes.sort();
    // O boot comum, o do processo de console, o do smss, o do smss com as
    // contas embutidas desligadas (os testes com entrada), o da conta de
    // teste (com ou sem entrada: o --start-menu do menu-iniciar e o --run
    // do prompt-de-comando ligam o gancho das contas embutidas, que o da
    // conta já cobre) e o da conta de teste com o gancho que desliga a
    // cadeia (o desligamento-cadeia), mais o do e-process e o do
    // volume-sistema.
    let expected = [
        ("", false, false, false, false, false, false),
        ("", false, false, false, false, false, true),
        ("", false, false, false, false, true, false),
        ("", true, false, false, false, false, false),
        ("smss", false, false, false, false, false, false),
        ("smss", false, false, true, false, false, false),
        ("smss", false, true, false, false, false, false),
        ("smss", false, true, false, true, false, false),
    ];
    assert_eq!(volumes, expected.map(|(process, console, account, builtin, chain, e_process, system_volume)| (String::from(process), console, account, builtin, chain, e_process, system_volume)), "volumes da rodada");
    let images = runs.iter().map(|run| run.image + 1).max().unwrap_or(0);
    assert_eq!(images, volumes.len(), "uma pasta de imagens por volume");
    // As execuções de uma pasta vêm juntas, e a de cada teste é a da chave dele.
    for pair in runs.windows(2) {
        assert!(pair[0].image <= pair[1].image);
        assert_eq!(pair[0].image == pair[1].image, tests[pair[0].test].image_key == tests[pair[1].test].image_key);
    }
}

#[test]
fn excerpt_starts_at_the_failure_or_keeps_the_tail() {
    let serial = "boot\n\na\nb\nfase 1\n[kbd] ok\n*** STOP 0x1e\nKERNEL_BLACKBOX_BYTES {}\nrip=1\n\nrsp=2\n";
    assert_eq!(report::serial_excerpt(serial), ["a", "b", "fase 1", "[kbd] ok", "*** STOP 0x1e", "rip=1", "rsp=2"]);
    let timeout: String = (1..=30).map(|line| format!("linha {line}\n")).collect();
    let excerpt = report::serial_excerpt(&timeout);
    assert_eq!(excerpt.first().map(String::as_str), Some("linha 19"));
    assert_eq!(excerpt.last().map(String::as_str), Some("linha 30"));
    let console = "texto\nTEST-BOOT FALHOU: tempo esgotado esperando \"X\" (serial em s)\n";
    assert_eq!(report::failure_reason(console), "TEST-BOOT FALHOU: tempo esgotado esperando \"X\"");
}

/// O build morto de fora (o rustc fechado à mão) se repete; um erro de
/// compilação, um erro de ligação e uma conferência do xtask, não.
#[test]
fn a_build_killed_from_outside_is_told_apart_from_a_real_failure() {
    let killed = "binarios do Windows no bundle: 17 de 17\n   Compiling kernel v0.6.0 (C:\\kernel)\nerror: could not compile `kernel` (bin \"kernel\")\n\nCaused by:\n  process didn't exit successfully: `rustc.exe --crate-name kernel` (exit code: 1)\ncomando falhou (exit code: 101): \"cargo\" \"build\" \"--package\" \"kernel\"\n";
    assert!(report::build_killed(killed));
    // O cargo morto antes de dizer qualquer coisa.
    assert!(report::build_killed("   Compiling kernel v0.6.0\ncomando falhou (exit code: 1): \"cargo\" \"build\"\n"));
    let compile_error = "error[E0425]: cannot find value `x` in this scope\n  --> kernel/src/main.rs:1:1\nerror: could not compile `kernel` (bin \"kernel\") due to 1 previous error\ncomando falhou (exit code: 101): \"cargo\"\n";
    assert!(!report::build_killed(compile_error));
    let denied_warning = "error: unused variable: `y`\nerror: could not compile `kernel`\ncomando falhou (exit code: 101): \"cargo\"\n";
    assert!(!report::build_killed(denied_warning));
    let link_error = "error: linking with `rust-lld` failed: exit code: 1\nerror: could not compile `kernel`\ncomando falhou (exit code: 101): \"cargo\"\n";
    assert!(!report::build_killed(link_error));
    // Uma conferência do xtask depois do cargo.
    assert!(!report::build_killed("    Finished `dev` profile\nkernel com 70000 setores nao cabe no campo u16 do stage2\n"));
}

/// O QEMU morto de fora antes do marcador se repete; um prazo esgotado, um
/// STOP, um autoteste que falhou e o QEMU que saiu sozinho, não.
#[test]
fn a_qemu_killed_from_outside_is_told_apart_from_a_real_failure() {
    let killed = "[boot] fase 1\nTEST-BOOT FALHOU: QEMU terminou (QEMU encerrado de fora (exit code: 1)) antes de \"KERNEL_RS_OK\" (serial em s)\n";
    assert!(report::qemu_killed(killed, "[boot] fase 1\n"));
    assert!(!report::qemu_killed(killed, "[boot] fase 1\n*** STOP (KeBugCheckEx): 0x0000001e\n"));
    assert!(!report::qemu_killed(killed, "SELFTEST FALHOU: time\n"));
    let timeout = "TEST-BOOT FALHOU: tempo esgotado esperando \"KERNEL_RS_OK\" (serial em s)\n";
    assert!(!report::qemu_killed(timeout, ""));
    let by_itself = "TEST-BOOT FALHOU: QEMU terminou (exit code: 0, evento SHUTDOWN do QMP: nenhum) antes de \"X\" (serial em s)\n";
    assert!(!report::qemu_killed(by_itself, ""));
    let failure = "TEST-BOOT FALHOU: falha detectada na serial: *** PANIC (serial em s)\n";
    assert!(!report::qemu_killed(failure, "*** PANIC\n"));
}

/// Um teste da rodada como o `components.toml` o daria.
fn test(id: &str, command: &str, host: Option<&str>, expected_failure: bool) -> Test {
    let arguments = split_words(command).unwrap();
    Test::new(id, arguments, false, expected_failure, false, None, host.map(String::from)).unwrap()
}

/// Os convidados (`na_execucao_de`) saem das execuções quando o anfitrião
/// entra na rodada e vão para a execução dele, que espera também os textos
/// deles; com `--only` só do convidado, como num `espera_falha` e no
/// `capturas`, ele sobe o próprio QEMU.
#[test]
fn guests_run_inside_the_host_when_both_are_chosen() {
    let chain = "USER_INITIALIZED 900000 --initial-process=smss --display=basic --smp=1";
    let tests = vec![
        test("anfitriao", &format!("{chain} --expect=SESSION1_CONNECTED --expect=LOGONUI_STARTED"), None, false),
        test("pixel", "FIRST_PIXEL_OK 600000 --initial-process=smss --display=basic --smp=1 --watch-screen", Some("anfitriao"), false),
        test("dwm", &format!("{chain} --expect=SESSION1_CONNECTED --expect=DWM_STARTED"), Some("anfitriao"), false),
        test("conhecida", &format!("{chain} --expect=USER_LOGON_OK"), Some("anfitriao"), true),
    ];
    plan::check_hosts(&tests).unwrap();
    let all = [0, 1, 2, 3];
    let (booted, guests) = plan::split_guests(&tests, &all, false);
    assert_eq!(booted, [0, 3], "o espera_falha roda sozinho");
    assert_eq!(guests, [vec![1, 2], vec![]]);
    // Os textos que o anfitrião já espera não se repetem.
    assert_eq!(plan::host_arguments(&tests, 0, &guests[0]), ["--expect-any=FIRST_PIXEL_OK", "--expect-any=DWM_STARTED", "--watch-screen"]);
    let runs = plan::runs(&tests, &booted, &guests, 2);
    let names: Vec<(&str, Vec<&str>)> = runs.iter().map(|run| (run.name.as_str(), run.guests.iter().map(|(_, name)| name.as_str()).collect())).collect();
    assert_eq!(names, [("anfitriao.1", vec!["pixel.1", "dwm.1"]), ("anfitriao.2", vec!["pixel.2", "dwm.2"]), ("conhecida.1", vec![]), ("conhecida.2", vec![])]);
    assert!(runs[0].extra.contains(&String::from("--watch-screen")));
    // Só o convidado, ou o capturas: QEMU próprio.
    assert_eq!(plan::split_guests(&tests, &[2], false), (vec![2], vec![vec![]]));
    assert_eq!(plan::split_guests(&tests, &[0, 2], true).0, [0, 2]);
}

/// Um convidado precisa do mesmo boot do anfitrião, sem nada que só valha
/// num QEMU próprio e com o prazo dentro do dele.
#[test]
fn a_guest_must_share_the_whole_boot_of_its_host() {
    let host = || test("anfitriao", "USER_INITIALIZED 900000 --initial-process=smss --display=basic --smp=1", None, false);
    let refused = |guest: Test| plan::check_hosts(&[host(), guest]).unwrap_err();
    assert!(refused(test("g", "X 600000 --initial-process=smss --display=basic --smp=1", Some("outro"), false)).contains("teste desconhecido"));
    assert!(refused(test("g", "X 600000 --initial-process=smss --display=basic --conta-de-teste --smp=1", Some("anfitriao"), false)).contains("as imagens"));
    assert!(refused(test("g", "X 600000 --initial-process=smss --smp=1", Some("anfitriao"), false)).contains("o boot difere"));
    assert!(refused(test("g", "X 600000 --initial-process=smss --display=basic --smp=2", Some("anfitriao"), false)).contains("o boot difere"));
    assert!(refused(test("g", "X 600000 --initial-process=smss --display=basic --smp=1 --hold=5000", Some("anfitriao"), false)).contains("--hold"));
    assert!(refused(test("g", "X 600000 --initial-process=smss --display=basic --smp=1 --send=X:a", Some("anfitriao"), false)).contains("--send"));
    assert!(refused(test("g", "X 1200000 --initial-process=smss --display=basic --smp=1", Some("anfitriao"), false)).contains("prazo"));
    // A vigia da tela, as telas periódicas e um prazo menor podem diferir.
    plan::check_hosts(&[host(), test("g", "X 600000 --initial-process=smss --display=basic --smp=1 --watch-screen --capture-every=30", Some("anfitriao"), false)]).unwrap();
    // O anfitrião não é convidado de outro.
    let chained = [host(), test("g", "X 600000 --initial-process=smss --display=basic --smp=1", Some("anfitriao"), false), test("h", "Y 600000 --initial-process=smss --display=basic --smp=1", Some("g"), false)];
    assert!(plan::check_hosts(&chained).unwrap_err().contains("ja roda na execucao de outro"));
}

/// Os testes com `--primeiro-logon-feito` ganham um gerador por máquina, que
/// roda uma vez, antes deles na pasta de imagens, com o comando sem o que
/// só vale no teste; o teste do volume novo não espera nada.
#[test]
fn first_logon_tests_wait_for_one_producer_per_machine() {
    let desktop = "USER_INITIALIZED 1800000 --initial-process=smss --display=basic --conta-de-teste";
    let mut tests = vec![
        test("fresco", &format!("{desktop} --smp=1 --watch-screen --expect=DESKTOP_OK"), None, false),
        test("barra", &format!("{desktop} --primeiro-logon-feito --smp=1 --watch-screen --expect=DESKTOP_OK --expect=TASKBAR_OK"), None, false),
        test("cmd", &format!("{desktop} --primeiro-logon-feito --smp=1 --kd=com2 --watch-screen --expect=DESKTOP_OK --run=DESKTOP_OK+5000:cmd --expect=WINDOW_OPENED_OK"), None, false),
        test("duas", &format!("{desktop} --primeiro-logon-feito --smp=2 --user-smp --expect=DESKTOP_OK"), None, false),
    ];
    assert_eq!(tests[1].first_logon, tests[2].first_logon, "o depurador e a entrada nao mudam o gerador");
    assert_ne!(tests[1].first_logon, tests[3].first_logon, "outra maquina, outro gerador");
    assert_eq!(tests[0].image_key, tests[2].image_key, "a entrada nao muda o volume da conta de teste");
    let mut booted = vec![0, 1, 2, 3];
    let producers = plan::add_producers(&mut tests, &booted).unwrap();
    assert_eq!(producers, [4, 5]);
    assert_eq!((tests[4].id.as_str(), tests[5].id.as_str()), ("primeiro-logon", "primeiro-logon-2"));
    assert_eq!(tests[4].arguments, ["USER_INITIALIZED", "2100000", "--initial-process=smss", "--display=basic", "--conta-de-teste", "--smp=1", "--gerar-primeiro-logon"]);
    assert!(tests[5].arguments.contains(&String::from("--user-smp")));
    assert_eq!(tests[4].produces, tests[1].first_logon);
    booted.extend(&producers);
    let guests = vec![Vec::new(); booted.len()];
    let runs = plan::runs(&tests, &booted, &guests, 2);
    let names: Vec<(&str, Option<usize>)> = runs.iter().map(|run| (run.name.as_str(), run.waits_for)).collect();
    assert_eq!(names[0], ("primeiro-logon", None), "o gerador abre a pasta de imagens");
    assert_eq!(names[1], ("primeiro-logon-2", None));
    assert_eq!(runs.iter().filter(|run| tests[run.test].produces.is_some()).count(), 2, "o gerador roda uma vez com --repeat");
    for run in &runs {
        let expected = match tests[run.test].id.as_str() {
            "barra" | "cmd" => Some(4),
            "duas" => Some(5),
            _ => None,
        };
        assert_eq!(run.waits_for, expected, "{}", run.name);
    }
    assert!(runs.iter().all(|run| run.image == 0));
    // Um convidado não mistura o volume novo e o já logado com o anfitrião.
    let host = test("fresco", &format!("{desktop} --smp=1"), None, false);
    let guest = test("g", &format!("{desktop} --smp=1 --primeiro-logon-feito"), Some("fresco"), false);
    assert!(plan::check_hosts(&[host, guest]).unwrap_err().contains("primeiro logon"));
}

/// O veredito de um convidado na serial do anfitrião: a cadeia em ordem,
/// as `--expect-any` em qualquer ponto, e um marcador de falha antes de um
/// texto reprova.
#[test]
fn derived_verdicts_follow_the_test_boot_rules() {
    let words = |list: &[&str]| list.iter().map(|word| word.to_string()).collect::<Vec<_>>();
    let serial = "boot\nUSER_INITIALIZED\nLSASS_STARTED\nWINSTA0_OK\nWINLOGON_DESKTOPS_OK\nfim\n";
    assert!(report::derived(serial, &words(&["USER_INITIALIZED", "WINSTA0_OK", "WINLOGON_DESKTOPS_OK"]), &[]).is_ok());
    let missing = report::derived(serial, &words(&["USER_INITIALIZED", "WINLOGON_DESKTOPS_OK", "WINSTA0_OK"]), &[]).unwrap_err();
    assert_eq!(missing, "\"WINSTA0_OK\" nao aparece na serial do anfitriao depois de \"WINLOGON_DESKTOPS_OK\"");
    assert!(report::derived(serial, &words(&["USER_INITIALIZED"]), &words(&["WINLOGON_DESKTOPS_OK", "LSASS_STARTED"])).is_ok());
    assert!(report::derived(serial, &words(&["USER_INITIALIZED"]), &words(&["DWM_STARTED"])).unwrap_err().contains("DWM_STARTED"));
    let stopped = "USER_INITIALIZED\n*** STOP (KeBugCheckEx): 0x0000001e\nWINSTA0_OK\n";
    let failure = report::derived(stopped, &words(&["USER_INITIALIZED", "WINSTA0_OK"]), &[]).unwrap_err();
    assert!(failure.starts_with("falha detectada na serial antes de \"WINSTA0_OK\": *** STOP"), "{failure}");
    assert!(report::derived(stopped, &words(&["USER_INITIALIZED"]), &words(&["WINSTA0_OK"])).unwrap_err().contains("*** STOP"));
    // Uma falha depois do último texto do convidado não é dele.
    assert!(report::derived(stopped, &words(&["USER_INITIALIZED"]), &[]).is_ok());
    let console = "x\n[xtask] \"LOGONUI_STARTED\" aos 45.3 s\n[xtask] \"esquema \\\"x\\\"\" aos 7.0 s\n";
    assert_eq!(report::arrival(console, "LOGONUI_STARTED"), Some(std::time::Duration::from_millis(45_300)));
    assert_eq!(report::arrival(console, "esquema \"x\""), Some(std::time::Duration::from_secs(7)));
    assert_eq!(report::arrival(console, "DWM_STARTED"), None);
}
