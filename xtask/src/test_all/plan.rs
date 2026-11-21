//! A lista de testes do `test-all`: as duas suítes completas e os
//! `[[teste]]` de `docs/status/components.toml`, cada um com os argumentos
//! do `test-boot` que o `comando` dele dá.

use std::fs;
use std::path::Path;
use std::time::Duration;

use crate::status::toml;

const COMPONENTS: &str = "docs/status/components.toml";

/// Os valores da chave `acelerador` de um `[[teste]]`.
pub const ACCELERATORS: &[&str] = &["tcg", "whpx"];

/// A suíte completa de autoteste, rodada com 4 CPUs e com 1 (`--smp`). As
/// saídas esperadas seguem a ordem das fontes: na fase 6, o estado estendido
/// e a hora antes do PHASE6; na fase 7, depois do processo de usuário, o
/// estado estendido e a hora em modo usuário, os pipes e as portas LPC antes
/// do PHASE7. Cada marcador conferido aqui é um sub-teste que não pode sair
/// da suíte sem ela falhar.
pub const SUITE: &[&str] = &[
    "PHASE3_SELFTEST_OK",
    "900000",
    "--kernel-test-scope=all",
    "--expect=PHASE4_SELFTEST_OK",
    "--expect=PHASE5_SELFTEST_OK",
    "--expect=XSTATE_KERNEL_OK",
    "--expect=TIME_KEEPING_OK",
    "--expect=PHASE6_SELFTEST_OK",
    "--expect=MULTIPROCESS_OK",
    "--expect=XSTATE_USER_OK",
    "--expect=TIME_USER_OK",
    "--expect=PIPES_OK",
    "--expect=LPC_PORTS_OK",
    "--expect=PHASE7_SELFTEST_OK",
    "--expect=KBDTEST_OK",
    "--expect=SELFTEST_OK",
];
pub const SUITE_CPUS: &[u32] = &[4, 1];

/// Folga sobre o prazo e o `--hold` do test-boot antes de dar o processo
/// como travado.
const GRACE: Duration = Duration::from_secs(120);
/// O que o QEMU compromete além da memória do convidado (medido: uns 5 GB
/// de memória privada com `-m 4096`).
const QEMU_OVERHEAD: u64 = 1 << 30;

pub struct Test {
    pub id: String,
    /// Argumentos do `test-boot`, sem `--build-dir` (o test-all escolhe).
    pub arguments: Vec<String>,
    /// Uma das suítes completas (fora do `components.toml`).
    pub suite: bool,
    /// `espera_falha = true`: falha conhecida; fora da rodada padrão, roda
    /// com `--espera-falha`, `--all` ou `--only` e é contada à parte.
    pub expected_failure: bool,
    /// `coberto_pela_suite = true`: os marcadores dele as suítes já
    /// conferem; só roda quando pedido por `--only`.
    pub covered_by_suite: bool,
    /// O que as imagens embutem (`BuildOptions::image_key`): execuções com a
    /// mesma chave rodam nas mesmas imagens, cada uma com as próprias opções
    /// de carga.
    pub image_key: String,
    /// O kernel compilado (`BuildOptions::kernel_key`).
    pub kernel_key: String,
    /// `acelerador = "tcg"`: o teste roda sempre neste acelerador; sem a
    /// chave, no padrão da rodada (o WHPX quando a máquina o tem).
    pub accelerator: Option<String>,
    /// Tempo máximo do `test-boot --no-build` (prazo + hold + folga).
    pub limit: Duration,
    /// Commit que o QEMU do teste faz ao subir (a memória do convidado
    /// inteira e o do próprio QEMU), em bytes.
    pub memory: u64,
    /// `na_execucao_de = "<id>"`: o teste tem o mesmo boot que aquele (o
    /// anfitrião) e, quando os dois entram na rodada, não sobe um QEMU
    /// próprio: a cadeia dele é conferida na serial do anfitrião
    /// ([`super::report::derived`]).
    pub host: Option<String>,
    /// O marcador e as `--expect`, na ordem: a cadeia que o teste confere.
    pub chain: Vec<String>,
    /// As `--expect-any`.
    pub unordered: Vec<String>,
    /// `--watch-screen` (a vigia põe marcadores da tela na serial).
    pub watch_screen: bool,
    /// O prazo do test-boot.
    pub timeout: Duration,
    /// O que o boot do teste é além das imagens: a máquina (CPUs, memória,
    /// USB, rede, TPM) e o texto das opções de carga.
    boot: String,
    /// As opções do comando que só valem num QEMU próprio (entrada pelo
    /// monitor, espera do fim, depurador, desligamento, parada esperada).
    own_qemu: Vec<&'static str>,
}

impl Test {
    pub(super) fn new(id: &str, arguments: Vec<String>, suite: bool, expected_failure: bool, covered_by_suite: bool, accelerator: Option<String>, host: Option<String>) -> Result<Test, String> {
        let mut command = vec![String::from("test-boot")];
        command.extend(arguments.iter().cloned());
        let parsed = crate::parse(command).map_err(|error| format!("teste {id}: {error}"))?;
        if parsed.build_only || parsed.no_build || parsed.image_dir.is_some() || parsed.build.windows_dir.is_some() || parsed.capture.is_some() {
            return Err(format!("teste {id}: --windows-dir, --build-only, --no-build, --image-dir e --capture sao escolhidos pelo test-all"));
        }
        if arguments.iter().any(|word| word.starts_with("--accel")) {
            return Err(format!("teste {id}: o acelerador vem da chave acelerador do components.toml, nao de --accel no comando"));
        }
        if let Some(accelerator) = &accelerator {
            if !ACCELERATORS.contains(&accelerator.as_str()) {
                return Err(format!("teste {id}: acelerador aceita {} ({accelerator} recebido)", ACCELERATORS.join(", ")));
            }
        }
        let (marker, timeout_ms) = crate::marker_and_timeout(&parsed).map_err(|error| format!("teste {id}: {error}"))?;
        let options = crate::test_build_options(&parsed);
        // As opções de carga que valem no QEMU: as do teste, inteiras.
        options.load_options_block().map_err(|error| format!("teste {id}: {error}"))?;
        let machine = &parsed.machine;
        let boot = format!(
            "smp={} memoria={} usb={} rede={} tpm={} opcoes de carga: {}",
            machine.smp,
            machine.memory_mb,
            machine.usb,
            machine.net,
            machine.tpm,
            options.load_options().map_err(|error| format!("teste {id}: {error}"))?
        );
        let own_qemu = [
            ("--keys", parsed.keys.is_some()),
            ("--send/--dismiss/--mouse/--start-menu/--context-menu", !parsed.inputs.is_empty()),
            ("--hold", parsed.hold_ms > 0),
            ("--kd", !options.kd.is_empty()),
            ("--script", parsed.script.is_some()),
            ("--expect-poweroff", parsed.expect_poweroff),
            ("--power-cycles", parsed.power_cycles > 0),
            ("--allow-reboot", parsed.allow_reboot),
            ("--expect-stop", parsed.expect_stop),
            ("--manual-crash", parsed.manual_crash),
        ]
        .into_iter()
        .filter_map(|(option, present)| present.then_some(option))
        .collect();
        let mut chain = vec![marker];
        chain.extend(parsed.expect.iter().cloned());
        Ok(Test {
            id: id.to_string(),
            arguments,
            suite,
            expected_failure,
            covered_by_suite,
            accelerator,
            image_key: options.image_key(),
            kernel_key: options.kernel_key(),
            limit: Duration::from_millis(timeout_ms.saturating_add(parsed.hold_ms)) + GRACE,
            memory: (u64::from(parsed.machine.memory_mb) << 20) + QEMU_OVERHEAD,
            host,
            chain,
            unordered: parsed.expect_any.clone(),
            watch_screen: parsed.watch_screen,
            timeout: Duration::from_millis(timeout_ms),
            boot,
            own_qemu,
        })
    }

    /// Tudo o que o teste procura na serial: a cadeia e as `--expect-any`.
    pub fn needles(&self) -> impl Iterator<Item = &String> {
        self.chain.iter().chain(&self.unordered)
    }

    /// O comando como o integrador o digitaria, com a pasta dada.
    pub fn command_line(&self, build_dir: &str, extra: &str) -> String {
        let mut words = vec![String::from("cargo xtask test-boot")];
        words.extend(self.arguments.iter().map(|word| quote(word)));
        words.push(quote(&format!("--build-dir={build_dir}")));
        if !extra.is_empty() {
            words.push(extra.to_string());
        }
        words.join(" ")
    }
}

/// As palavras como o integrador as digitaria ([`quote`]).
pub fn quoted(words: &[String]) -> String {
    words.iter().map(|word| quote(word)).collect::<Vec<_>>().join(" ")
}

/// Aspas duplas quando a palavra tem espaço ou caractere especial do shell
/// (as barras ficam como estão: `\n` em `--keys` vale nos dois shells).
fn quote(word: &str) -> String {
    let plain = !word.is_empty() && word.chars().all(|character| character.is_ascii_alphanumeric() || "-_=./:,+@%".contains(character));
    if plain {
        word.to_string()
    } else {
        format!("\"{}\"", word.replace('"', "\\\""))
    }
}

/// Separa um comando de shell em palavras: aspas duplas (com `\"`, `\\`,
/// `\$` e `` \` `` como escapes) e simples agrupam, e uma barra fora das
/// aspas escapa o caractere seguinte. Dentro das aspas duplas, outra barra
/// fica como está (o `\n` de `--keys`, que o test-boot converte).
pub fn split_words(text: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_word = false;
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            ' ' | '\t' | '\n' | '\r' => {
                if in_word {
                    words.push(std::mem::take(&mut current));
                    in_word = false;
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match characters.next() {
                        None => return Err(format!("aspas duplas sem fechamento: {text}")),
                        Some('"') => break,
                        Some('\\') if matches!(characters.peek(), Some('"' | '\\' | '$' | '`')) => {
                            current.extend(characters.next());
                        }
                        Some(other) => current.push(other),
                    }
                }
            }
            '\'' => {
                in_word = true;
                loop {
                    match characters.next() {
                        None => return Err(format!("aspas simples sem fechamento: {text}")),
                        Some('\'') => break,
                        Some(other) => current.push(other),
                    }
                }
            }
            '\\' => {
                in_word = true;
                current.extend(characters.next());
            }
            other => {
                in_word = true;
                current.push(other);
            }
        }
    }
    if in_word {
        words.push(current);
    }
    Ok(words)
}

fn flag(entry: &toml::Table, key: &str) -> Result<bool, String> {
    match entry.get(key) {
        None => Ok(false),
        Some(toml::Value::Bool(value)) => Ok(*value),
        Some(_) => Err(format!("{key} deve ser true ou false")),
    }
}

/// As duas suítes e os `[[teste]]` do `components.toml`, nesta ordem.
pub fn load(root: &Path) -> Result<Vec<Test>, String> {
    let mut tests = Vec::new();
    for cpus in SUITE_CPUS {
        let mut arguments: Vec<String> = SUITE.iter().map(|word| word.to_string()).collect();
        arguments.push(format!("--smp={cpus}"));
        tests.push(Test::new(&format!("suite-smp{cpus}"), arguments, true, false, false, None, None)?);
    }
    let path = root.join(COMPONENTS);
    let text = fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let document = toml::parse(&text).map_err(|error| format!("{COMPONENTS}: {error}"))?;
    for entry in document.array("teste") {
        let id = entry.string("id").ok_or_else(|| format!("{COMPONENTS}: [[teste]] sem id"))?;
        let command = entry.string("comando").ok_or_else(|| format!("teste {id}: sem comando"))?;
        let words = split_words(command).map_err(|error| format!("teste {id}: {error}"))?;
        let arguments = match words.as_slice() {
            [cargo, xtask, test_boot, rest @ ..] if cargo == "cargo" && xtask == "xtask" && test_boot == "test-boot" => {
                rest.iter().filter(|word| !word.starts_with("--build-dir=")).cloned().collect()
            }
            _ => return Err(format!("teste {id}: o comando nao e um `cargo xtask test-boot`: {command}")),
        };
        let expected_failure = flag(entry, "espera_falha").map_err(|error| format!("teste {id}: {error}"))?;
        let covered_by_suite = flag(entry, "coberto_pela_suite").map_err(|error| format!("teste {id}: {error}"))?;
        let accelerator = match entry.get("acelerador") {
            None => None,
            Some(toml::Value::String(value)) => Some(value.clone()),
            Some(_) => return Err(format!("teste {id}: acelerador deve ser um texto")),
        };
        let host = match entry.get("na_execucao_de") {
            None => None,
            Some(toml::Value::String(value)) => Some(value.clone()),
            Some(_) => return Err(format!("teste {id}: na_execucao_de deve ser o id de outro teste")),
        };
        if tests.iter().any(|test: &Test| test.id == id) {
            return Err(format!("{COMPONENTS}: id de teste repetido: {id}"));
        }
        tests.push(Test::new(id, arguments, false, expected_failure, covered_by_suite, accelerator, host)?);
    }
    check_hosts(&tests)?;
    Ok(tests)
}

/// Confere cada `na_execucao_de`: o anfitrião existe, não é ele mesmo
/// convidado de outro, sobe o mesmo boot (as imagens, o kernel, a máquina,
/// as opções de carga e o acelerador) com um prazo que cobre o do
/// convidado, e o convidado não usa nada que só vale num QEMU próprio. A
/// vigia da tela, as telas do `--capture-every` e o prazo podem diferir.
pub fn check_hosts(tests: &[Test]) -> Result<(), String> {
    for guest in tests {
        let Some(host_id) = &guest.host else { continue };
        let fail = |why: String| Err(format!("teste {}: na_execucao_de = \"{host_id}\": {why}", guest.id));
        let Some(host) = tests.iter().find(|test| &test.id == host_id) else {
            return fail("teste desconhecido".into());
        };
        if host.id == guest.id {
            return fail("um teste nao roda na execucao dele mesmo".into());
        }
        if host.host.is_some() {
            return fail(format!("{host_id} ja roda na execucao de outro teste"));
        }
        if !guest.own_qemu.is_empty() {
            return fail(format!("{} so vale num QEMU proprio", guest.own_qemu.join(", ")));
        }
        if guest.image_key != host.image_key || guest.kernel_key != host.kernel_key {
            return fail("as imagens do boot diferem das do anfitriao (outro volume ou outro kernel)".into());
        }
        if guest.boot != host.boot {
            return fail(format!("o boot difere do anfitriao ({} contra {})", guest.boot, host.boot));
        }
        if guest.accelerator != host.accelerator {
            return fail("o acelerador difere do anfitriao".into());
        }
        if guest.timeout > host.timeout {
            return fail(format!("o prazo de {} s passa o do anfitriao ({} s)", guest.timeout.as_secs(), host.timeout.as_secs()));
        }
    }
    Ok(())
}

/// Os convidados que rodam na execução de cada teste escolhido: um teste
/// com `na_execucao_de` cujo anfitrião também foi escolhido sai das
/// execuções e vai para a lista do anfitrião (o veredito dele sai da serial
/// do anfitrião). Fica com o QEMU próprio o `espera_falha` (a falha
/// conhecida roda à parte, como sempre) e todo teste do `capturas`
/// (`own_runs`: cada teste grava a própria tela). Devolve os escolhidos que
/// sobem um QEMU e, para cada um, os convidados dele.
pub fn split_guests(tests: &[Test], chosen: &[usize], own_runs: bool) -> (Vec<usize>, Vec<Vec<usize>>) {
    let host_of = |index: usize| -> Option<usize> {
        let test = &tests[index];
        if own_runs || test.expected_failure {
            return None;
        }
        let host = tests.iter().position(|other| Some(&other.id) == test.host.as_ref())?;
        chosen.contains(&host).then_some(host)
    };
    let booted: Vec<usize> = chosen.iter().copied().filter(|&index| host_of(index).is_none()).collect();
    let guests = booted.iter().map(|&host| chosen.iter().copied().filter(|&index| host_of(index) == Some(host)).collect()).collect();
    (booted, guests)
}

/// O que o anfitrião passa ao `test-boot` além do comando dele, pelos
/// `guests`: uma `--expect-any` para cada texto que um convidado procura e
/// o anfitrião não (assim a execução só acaba com todos na serial, em
/// qualquer ordem entre eles), e o `--watch-screen` quando um convidado o
/// tem.
pub fn host_arguments(tests: &[Test], host: usize, guests: &[usize]) -> Vec<String> {
    let own: Vec<&String> = tests[host].needles().collect();
    let mut extra: Vec<String> = Vec::new();
    for &guest in guests {
        for needle in tests[guest].needles() {
            let argument = format!("--expect-any={needle}");
            if !own.contains(&needle) && !extra.contains(&argument) {
                extra.push(argument);
            }
        }
    }
    if !tests[host].watch_screen && guests.iter().any(|&guest| tests[guest].watch_screen) {
        extra.push("--watch-screen".into());
    }
    extra
}

/// Quais suítes entram quando não há `--only`.
#[derive(Clone, Copy, PartialEq)]
pub enum Suites {
    /// As suítes e os `[[teste]]` (padrão).
    Included,
    /// Só as suítes (`--suite`).
    Only,
    /// Só os `[[teste]]` (`--no-suite`).
    Excluded,
}

/// O que entra na rodada sem `--only`, além dos testes comuns.
#[derive(Clone, Copy, Default)]
pub struct Extras {
    /// Os `espera_falha` (`--espera-falha` ou `--all`).
    pub expected_failures: bool,
    /// Os `coberto_pela_suite` (`--all`).
    pub covered_by_suite: bool,
}

/// Índices dos testes escolhidos: os de `only` na ordem dada, ou todos os
/// que não são `coberto_pela_suite` nem `espera_falha` (os dois entram com
/// `extras`); depois saem os de `skip`.
pub fn select(tests: &[Test], only: &[String], skip: &[String], suites: Suites, extras: Extras) -> Result<Vec<usize>, String> {
    let find = |id: &str| {
        tests
            .iter()
            .position(|test| test.id == id)
            .ok_or_else(|| format!("teste desconhecido: {id} (cargo xtask test-all --list mostra os ids)"))
    };
    let mut chosen = Vec::new();
    if only.is_empty() {
        for (index, test) in tests.iter().enumerate() {
            let wanted = match suites {
                Suites::Included => true,
                Suites::Only => test.suite,
                Suites::Excluded => !test.suite,
            };
            let extra = (test.covered_by_suite && !extras.covered_by_suite) || (test.expected_failure && !extras.expected_failures);
            if wanted && !extra {
                chosen.push(index);
            }
        }
    } else {
        for id in only {
            let index = find(id)?;
            if !chosen.contains(&index) {
                chosen.push(index);
            }
        }
    }
    for id in skip {
        let index = find(id)?;
        chosen.retain(|&chosen| chosen != index);
    }
    if chosen.is_empty() {
        return Err("nenhum teste selecionado".into());
    }
    Ok(chosen)
}

/// Uma execução: um teste, a pasta dela (`<id>` ou `<id>.<n>` com
/// `--repeat`) e as imagens em que roda.
pub struct Run {
    pub name: String,
    pub test: usize,
    /// O índice da chave de imagem (`image_key`) entre as desta rodada.
    pub image: usize,
    /// Os convidados que esta execução decide ([`split_guests`]), com o
    /// nome do resultado de cada um (`<id>` ou `<id>.<n>`).
    pub guests: Vec<(usize, String)>,
    /// O que o anfitrião passa a mais ao `test-boot` ([`host_arguments`]).
    pub extra: Vec<String>,
}

/// As execuções na ordem em que vão para as pistas: as de mesmas imagens
/// juntas (montadas uma vez), os grupos de teste mais longo primeiro e, em
/// cada grupo, as de prazo maior primeiro, para as longas (as suítes)
/// começarem cedo e as curtas fecharem a rodada. `guests[i]` são os
/// convidados de `booted[i]` ([`split_guests`]).
pub fn runs(tests: &[Test], booted: &[usize], guests: &[Vec<usize>], repeat: usize) -> Vec<Run> {
    let mut groups: Vec<(&str, Vec<usize>)> = Vec::new();
    for &index in booted {
        let key = tests[index].image_key.as_str();
        match groups.iter_mut().find(|(group, _)| *group == key) {
            Some((_, members)) => members.push(index),
            None => groups.push((key, vec![index])),
        }
    }
    let longest = |members: &[usize]| members.iter().map(|&index| tests[index].limit).max().unwrap_or_default();
    groups.sort_by_key(|(_, members)| std::cmp::Reverse(longest(members)));
    let name = |index: usize, round: usize| {
        let id = &tests[index].id;
        if repeat > 1 {
            format!("{id}.{round}")
        } else {
            id.clone()
        }
    };
    let mut runs = Vec::new();
    for (image, (_, mut members)) in groups.into_iter().enumerate() {
        members.sort_by_key(|&index| std::cmp::Reverse(tests[index].limit));
        for index in members {
            let own: &[usize] = booted.iter().position(|&host| host == index).and_then(|at| guests.get(at)).map_or(&[], Vec::as_slice);
            let extra = host_arguments(tests, index, own);
            for round in 1..=repeat {
                let guests = own.iter().map(|&guest| (guest, name(guest, round))).collect();
                runs.push(Run { name: name(index, round), test: index, image, guests, extra: extra.clone() });
            }
        }
    }
    runs
}
