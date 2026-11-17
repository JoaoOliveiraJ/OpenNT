//! Testes do `test-all`: a leitura dos comandos do `components.toml`, a
//! seleção e o trecho mostrado de uma falha.

use super::plan::{self, split_words, Extras, Suites};
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
    let only = plan::select(&tests, &[String::from("suite-smp1")], &[], Suites::Included, Extras::default()).unwrap();
    assert_eq!(only.len(), 1);
    assert!(plan::select(&tests, &[String::from("nao-existe")], &[], Suites::Included, Extras::default()).is_err());
    // As duas suítes dividem as imagens.
    let runs = plan::runs(&tests, &plan::select(&tests, &[], &[], Suites::Only, Extras::default()).unwrap(), 2);
    let names: Vec<&str> = runs.iter().map(|run| run.name.as_str()).collect();
    assert_eq!(names, ["suite-smp4.1", "suite-smp4.2", "suite-smp1.1", "suite-smp1.2"]);
    assert!(runs.iter().all(|run| run.image == 0));
    assert_eq!(tests[runs[0].test].image_key, tests[runs[3].test].image_key);
}

/// A rodada inteira compila um kernel só: as opções de boot dos testes vão
/// nas opções de carga, e só o volume do smss pede outra pasta de imagens.
#[test]
fn the_whole_round_compiles_one_kernel() {
    let tests = plan::load(&crate::build::workspace_root()).unwrap();
    let all: Vec<String> = tests.iter().map(|test| test.id.clone()).collect();
    let runs = plan::runs(&tests, &plan::select(&tests, &all, &[], Suites::Included, Extras::default()).unwrap(), 1);
    let mut kernels: Vec<&str> = runs.iter().map(|run| tests[run.test].kernel_key.as_str()).collect();
    kernels.dedup();
    assert_eq!(kernels.len(), 1, "builds do kernel diferentes na rodada");
    let images = runs.iter().map(|run| run.image + 1).max().unwrap_or(0);
    assert!(images <= 2, "{images} pastas de imagens");
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
