//! `cargo xtask test-all` — a validação inteira num comando.
//!
//! Roda as duas suítes completas de autoteste (`suite-smp4` e `suite-smp1`)
//! e cada `[[teste]]` de `docs/status/components.toml` (o `comando` de cada
//! um é um `cargo xtask test-boot`), cada execução na própria pasta
//! `build/test-all/<id>`:
//!
//! 1. uma thread monta as imagens (`test-boot --build-only`), uma vez por
//!    chave de imagem, em `build/test-all/imagem-<n>`. As opções de boot dos
//!    testes não mudam o kernel (vão no bloco de opções de carga da imagem
//!    de boot): todos dividem um kernel compilado, e só o volume NTFS do
//!    boot do smss pede outra pasta de imagens;
//! 2. `--jobs` pistas rodam o QEMU sobre as imagens prontas (`test-boot
//!    --no-build --image-dir`): a pasta da execução recebe a cópia do
//!    `os.img` com as opções de carga dela, a saída em `test-boot.log` e a
//!    serial em `serial.log`, e o volume NTFS da pasta de imagens entra com
//!    `snapshot=on`, então execuções paralelas o dividem e cada uma começa
//!    dele intacto. A pasta de uma execução que passou é apagada, e a de
//!    imagens no fim, se todas as execuções dela passaram (`--keep` guarda
//!    todas). Cada QEMU compromete toda a memória do convidado logo ao
//!    subir; um QEMU só começa quando o commit livre do sistema cobre a
//!    memória dele e uma margem, contando a dos QEMUs que acabaram de subir,
//!    porque com o commit esgotado processos morrem sem mensagem (o próprio
//!    test-all, o cargo, o rustc);
//! 3. no fim, a tabela com o resultado de cada uma e, para cada falha, o
//!    trecho da serial que a explica.
//!
//! `espera_falha = true` marca um teste que falha conhecidamente: fica fora
//! da rodada padrão (não gasta o prazo inteiro dele em toda validação) e roda
//! com `--espera-falha`, `--all` ou `--only`, contado à parte, sem reprovar a
//! rodada. `coberto_pela_suite = true` marca um teste cujos marcadores as
//! suítes já conferem (roda com `--all` ou `--only`).
//!
//! O acelerador: cada execução roda no padrão da rodada, o WHPX quando o
//! QEMU o tem e a partição sobe nesta máquina, senão o TCG (`--accel`
//! troca). `acelerador = "tcg"` num `[[teste]]` fixa o dele.
//!
//! `cargo xtask capturas` usa a mesma máquina para as capturas de tela das
//! páginas: roda cada `[[teste]]` (sem as suítes, com os cobertos por elas)
//! e passa ao `test-boot --no-build` o `--capture=docs/site/capturas/<id>.png`,
//! que grava a tela do QEMU no fim do teste, passando ou não.

mod host;
mod plan;
mod report;
#[cfg(test)]
mod tests;

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use crate::build;
use plan::{Extras, Run, Suites, Test};
pub use plan::{SUITE, SUITE_CPUS};
use report::{Outcome, Verdict};

pub const USAGE: &str = "uso: cargo xtask test-all [opcoes]
  roda as suites completas (suite-smp4, suite-smp1) e os [[teste]] de docs/status/components.toml
  --jobs=N          execucoes em paralelo (padrao: metade das CPUs)
  --only=ID[,ID]    so estes testes (inclusive os coberto_pela_suite)
  --skip=ID[,ID]    deixa estes de fora
  --suite           so as duas suites; --no-suite: so os [[teste]]
  --espera-falha    inclui os espera_falha (fora da rodada padrao)
  --all             todos: as suites e os [[teste]], inclusive espera_falha e coberto_pela_suite
  --accel=tcg|whpx  acelerador dos testes sem a chave acelerador (padrao: whpx quando a maquina tem)
  --repeat=N        roda cada teste N vezes (falhas intermitentes)
  --keep            guarda a pasta de toda execucao (padrao: so das que falharam)
  --cpu-friendly    prioridade abaixo do normal e 4 CPUs logicas livres (Windows)
  --list            mostra os testes e os comandos, sem rodar
cada execucao fica em build/test-all/<id> (ou <id>.<n> com --repeat): build.log, test-boot.log, serial.log
as opcoes aceitam --nome=valor ou --nome valor";

pub const CAPTURE_USAGE: &str = "uso: cargo xtask capturas [opcoes]
  roda cada [[teste]] de docs/status/components.toml (inclusive os coberto_pela_suite, sem as suites)
  e grava a tela do QEMU no fim de cada um em docs/site/capturas/<id>.png (passando ou nao)
  --jobs=N          execucoes em paralelo (padrao: metade das CPUs)
  --only=ID[,ID]    so estes testes
  --skip=ID[,ID]    deixa estes de fora
  --accel=tcg|whpx  acelerador dos testes sem a chave acelerador (padrao: whpx quando a maquina tem)
  --keep            guarda a pasta de toda execucao
  --cpu-friendly    prioridade abaixo do normal e 4 CPUs logicas livres (Windows)
  --list            mostra os testes e os comandos, sem rodar";

/// Pasta das capturas de tela, relativa à raiz do workspace.
pub const CAPTURE_DIR: &str = "docs/site/capturas";

/// Pasta das execuções, relativa à raiz do workspace.
const OUTPUT_DIR: &str = "build/test-all";
/// Commit que fica livre além dos QEMUs: o rustc do build do kernel (até
/// uns 4 GB) e o resto do sistema.
const COMMIT_RESERVE: u64 = 6 << 30;
/// Tempo para um QEMU recém-criado comprometer a memória do convidado: até
/// lá, a próxima pista conta a memória dele como já comprometida.
const SETTLE: Duration = Duration::from_secs(3);

struct Options {
    jobs: Option<usize>,
    only: Vec<String>,
    skip: Vec<String>,
    suites: Suites,
    extras: Extras,
    /// `--accel`: o acelerador padrão da rodada (sem ele, o detectado).
    accelerator: Option<String>,
    repeat: usize,
    keep: bool,
    cpu_friendly: bool,
    list: bool,
}

/// Opções do `test-all`, ou do `capturas` (`capture`), que não aceita
/// `--repeat`, `--suite` e `--no-suite`.
fn parse_options(arguments: &[String], capture: bool) -> Result<Options, String> {
    let mut options = Options {
        jobs: None,
        only: Vec::new(),
        skip: Vec::new(),
        suites: Suites::Included,
        extras: Extras::default(),
        accelerator: None,
        repeat: 1,
        keep: false,
        cpu_friendly: false,
        list: false,
    };
    let mut suite_flag = false;
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        let (name, inline) = match argument.split_once('=') {
            Some((name, value)) => (name, Some(value.to_string())),
            None => (argument.as_str(), None),
        };
        let mut value = || inline.clone().or_else(|| rest.next().cloned()).ok_or_else(|| format!("{name} exige um valor"));
        let ids = |text: String| text.split(',').map(str::trim).filter(|id| !id.is_empty()).map(String::from).collect::<Vec<_>>();
        let number = |text: String| match text.parse::<usize>() {
            Ok(value) if value > 0 => Ok(value),
            _ => Err(format!("{name} espera um numero maior que zero ({text} recebido)")),
        };
        match name {
            "--repeat" | "--suite" | "--no-suite" if capture => return Err(format!("{name} nao vale no capturas\n{CAPTURE_USAGE}")),
            "--help" | "-h" if capture => return Err(CAPTURE_USAGE.to_string()),
            "--jobs" | "-j" => options.jobs = Some(number(value()?)?),
            "--only" => options.only.extend(ids(value()?)),
            "--skip" => options.skip.extend(ids(value()?)),
            "--repeat" => options.repeat = number(value()?)?,
            "--accel" => {
                let accelerator = value()?;
                if !plan::ACCELERATORS.contains(&accelerator.as_str()) {
                    return Err(format!("--accel aceita {} ({accelerator} recebido)", plan::ACCELERATORS.join(", ")));
                }
                options.accelerator = Some(accelerator);
            }
            "--espera-falha" | "--all" if capture => return Err(format!("{name} nao vale no capturas\n{CAPTURE_USAGE}")),
            "--keep" | "--suite" | "--no-suite" | "--cpu-friendly" | "--list" | "--espera-falha" | "--all" if inline.is_some() => {
                return Err(format!("{name} nao aceita valor"));
            }
            "--keep" => options.keep = true,
            "--cpu-friendly" => options.cpu_friendly = true,
            "--list" => options.list = true,
            "--espera-falha" => options.extras.expected_failures = true,
            "--all" => options.extras = Extras { expected_failures: true, covered_by_suite: true },
            "--suite" | "--no-suite" => {
                if suite_flag {
                    return Err("use --suite ou --no-suite, uma vez".into());
                }
                suite_flag = true;
                options.suites = if name == "--suite" { Suites::Only } else { Suites::Excluded };
            }
            "--help" | "-h" => return Err(USAGE.to_string()),
            _ => return Err(format!("opcao desconhecida: {argument}\n{}", if capture { CAPTURE_USAGE } else { USAGE })),
        }
    }
    if suite_flag && !options.only.is_empty() {
        return Err("--only ja escolhe os testes; tire o --suite/--no-suite".into());
    }
    if (options.extras.expected_failures || options.extras.covered_by_suite) && !options.only.is_empty() {
        return Err("--only ja escolhe os testes; tire o --espera-falha/--all".into());
    }
    Ok(options)
}

/// Relógio da rodada no começo de cada linha.
struct Console {
    started: Instant,
    lock: Mutex<()>,
}

impl Console {
    fn say(&self, text: &str) {
        let _guard = self.lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let seconds = self.started.elapsed().as_secs();
        println!("[{:02}:{:02}] {text}", seconds / 60, seconds % 60);
    }
}

/// Tudo o que as threads dividem.
struct Context {
    tests: Vec<Test>,
    runs: Vec<Run>,
    root: PathBuf,
    executable: PathBuf,
    keep: bool,
    console: Console,
    /// Largura da coluna de nomes nas linhas ao vivo.
    width: usize,
    /// Um QEMU começa de cada vez, depois de conferir o commit livre; o gate
    /// guarda quando subiram os QEMUs recentes e quanto cada um compromete.
    memory_gate: Mutex<Vec<(Instant, u64)>>,
    /// QEMUs rodando agora.
    running: AtomicUsize,
    /// `capturas`: a pasta dos PNG de cada teste.
    capture: Option<PathBuf>,
    /// O acelerador dos testes sem a chave `acelerador`.
    accelerator: String,
}

impl Context {
    fn directory(&self, run: &Run) -> PathBuf {
        self.root.join(OUTPUT_DIR).join(&run.name)
    }

    /// O caminho como o integrador o vê, relativo à raiz.
    fn relative(&self, run: &Run, file: &str) -> String {
        format!("{OUTPUT_DIR}/{}/{file}", run.name)
    }

    /// A pasta das imagens de índice `image`, relativa à raiz.
    fn image_relative(image: usize) -> String {
        format!("{OUTPUT_DIR}/imagem-{}", image + 1)
    }

    fn image_directory(&self, image: usize) -> PathBuf {
        self.root.join(Self::image_relative(image))
    }

    /// O acelerador em que o teste roda.
    fn accelerator<'a>(&'a self, test: &'a Test) -> &'a str {
        test.accelerator.as_deref().unwrap_or(&self.accelerator)
    }

    /// Quantas pastas de imagens a rodada usa.
    fn image_count(&self) -> usize {
        self.runs.iter().map(|run| run.image + 1).max().unwrap_or(0)
    }

    /// Um `test-boot` do próprio xtask (sem passar de novo pelo cargo); com
    /// `images`, sobre as imagens montadas daquela pasta.
    fn test_boot(&self, test: &Test, directory: &Path, stage: &str, log: &Path, images: Option<&Path>) -> Result<Child, String> {
        let file = File::create(log).map_err(|error| format!("{}: {error}", log.display()))?;
        let errors = file.try_clone().map_err(|error| format!("{}: {error}", log.display()))?;
        let mut command = Command::new(&self.executable);
        command.arg("test-boot").args(&test.arguments).arg(format!("--build-dir={}", directory.display())).arg(stage);
        if let Some(images) = images {
            command.arg(format!("--image-dir={}", images.display()));
            command.arg(format!("--accel={}", self.accelerator(test)));
        }
        if let (Some(capture), "--no-build") = (&self.capture, stage) {
            command.arg(format!("--capture={}", capture.join(format!("{}.png", test.id)).display()));
        }
        command
            .stdin(Stdio::null())
            .stdout(file)
            .stderr(errors)
            .spawn()
            .map_err(|error| format!("{}: {error}", self.executable.display()))
    }
}

/// Uma execução com as imagens dela montadas (ou o erro do build), a
/// caminho de uma pista.
struct Prepared {
    run: usize,
    /// O tempo do build das imagens, na primeira execução que as usa (zero
    /// nas outras).
    build: Result<Duration, String>,
}

/// Uma pasta vazia (a de uma rodada anterior, com a serial velha, sai antes).
fn fresh_directory(directory: &Path) -> Result<(), String> {
    if directory.exists() {
        fs::remove_dir_all(directory).map_err(|error| format!("{}: {error}", directory.display()))?;
    }
    fs::create_dir_all(directory).map_err(|error| format!("{}: {error}", directory.display()))
}

/// Monta cada pasta de imagens uma vez, em sequência, e entrega às pistas
/// as execuções dela; um build que falhou vale para todas elas.
fn builder(context: &Context, ready: Sender<Prepared>) {
    for image in 0..context.image_count() {
        let members: Vec<usize> = (0..context.runs.len()).filter(|&index| context.runs[index].image == image).collect();
        let Some(&first) = members.first() else { continue };
        let started = Instant::now();
        let build = build_images(context, image, &context.tests[context.runs[first].test]).map(|()| started.elapsed());
        for (position, &run) in members.iter().enumerate() {
            let build = match &build {
                Ok(time) => Ok(if position == 0 { *time } else { Duration::ZERO }),
                Err(error) => Err(error.clone()),
            };
            if ready.send(Prepared { run, build }).is_err() {
                return;
            }
        }
    }
}

fn build_images(context: &Context, image: usize, test: &Test) -> Result<(), String> {
    let directory = context.image_directory(image);
    fresh_directory(&directory)?;
    let mut child = context.test_boot(test, &directory, "--build-only", &directory.join("build.log"), None)?;
    let status = child.wait().map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("build falhou ({status})"))
    }
}

/// Mata o test-boot e o QEMU que ele criou.
fn kill_tree(child: &mut Child) {
    if cfg!(windows) {
        let _ = Command::new("taskkill")
            .args(["/T", "/F", "/PID", &child.id().to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn gib(bytes: u64) -> String {
    format!("{:.1} GB", bytes as f64 / (1u64 << 30) as f64)
}

/// Espera o commit livre cobrir o QEMU e a margem, com a memória dos QEMUs
/// que subiram há menos de [`SETTLE`] contada como já comprometida (`recent`,
/// o conteúdo do gate). Sem nenhum QEMU nosso rodando, segue mesmo assim (um
/// de cada vez), para a rodada não parar.
fn wait_for_memory(context: &Context, run: &Run, test: &Test, recent: &mut Vec<(Instant, u64)>) {
    let need = test.memory + COMMIT_RESERVE;
    let mut warned = false;
    while let Some(available) = host::available_commit() {
        recent.retain(|(started, _)| started.elapsed() < SETTLE);
        let starting: u64 = recent.iter().map(|(_, memory)| memory).sum();
        if available >= need + starting || context.running.load(Ordering::SeqCst) == 0 {
            break;
        }
        // A espera curta pelos QEMUs recentes não é falta de memória.
        if !warned && starting == 0 {
            let width = context.width;
            context.console.say(&format!(
                "{:<14} {:<width$}  commit livre {}, precisa {}",
                "esperando",
                run.name,
                gib(available),
                gib(need)
            ));
            warned = true;
        }
        // Um QEMU recente que ainda não apareceu no commit sai da conta em
        // até SETTLE; um commit que falta de verdade espera mais.
        thread::sleep(if starting > 0 { Duration::from_millis(500) } else { Duration::from_secs(5) });
    }
}

/// Roda o QEMU sobre as imagens montadas; `Ok(true)` se o test-boot passou.
fn execute(context: &Context, run: &Run, test: &Test, build: Duration) -> Result<(bool, Duration), String> {
    let directory = context.directory(run);
    fresh_directory(&directory)?;
    let images = context.image_directory(run.image);
    let (mut child, started) = {
        let mut recent = context.memory_gate.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        wait_for_memory(context, run, test, &mut recent);
        let width = context.width;
        context.console.say(&format!("{:<14} {:<width$}  (build {})", "rodando", run.name, report::duration(build)));
        let child = context.test_boot(test, &directory, "--no-build", &directory.join("test-boot.log"), Some(&images))?;
        let started = Instant::now();
        context.running.fetch_add(1, Ordering::SeqCst);
        recent.push((started, test.memory));
        (child, started)
    };
    let result = loop {
        match child.try_wait() {
            Err(error) => break Err(error.to_string()),
            Ok(Some(status)) => break Ok((status.success(), started.elapsed())),
            Ok(None) => {}
        }
        if started.elapsed() > test.limit {
            kill_tree(&mut child);
            break Err(format!("o test-boot passou de {} sem terminar e foi morto", report::duration(test.limit)));
        }
        thread::sleep(Duration::from_millis(200));
    };
    context.running.fetch_sub(1, Ordering::SeqCst);
    // O test-boot apaga a pasta temporária do QEMU ao terminar; um test-boot
    // morto pelo prazo não chega lá, e o volume com snapshot=on deixaria o
    // arquivo de escritas dele na pasta da execução que falhou.
    crate::qemu::remove_temp_dir(&directory.join(crate::qemu::QEMU_TEMP_DIR));
    result
}

/// Uma pista: pega a próxima imagem pronta, roda e anota o resultado.
fn lane(context: &Context, ready: &Mutex<Receiver<Prepared>>, outcomes: &Mutex<Vec<Outcome>>) {
    loop {
        let next = ready.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).recv();
        let Ok(prepared) = next else { break };
        let run = &context.runs[prepared.run];
        let test = &context.tests[run.test];
        let directory = context.directory(run);
        let width = context.width;
        let (passed, build, time, reason, excerpt, log) = match prepared.build {
            Err(error) => {
                let text = report::read_lossy(&context.image_directory(run.image).join("build.log")).unwrap_or_default();
                (false, None, None, error, report::build_excerpt(&text), format!("{}/build.log", Context::image_relative(run.image)))
            }
            Ok(build) => {
                let started = Instant::now();
                let result = execute(context, run, test, build);
                let time = match &result {
                    Ok((_, time)) => *time,
                    Err(_) => started.elapsed(),
                };
                let console = report::read_lossy(&directory.join("test-boot.log")).unwrap_or_default();
                if context.capture.is_some() {
                    // A pasta de quem passou some: o que a captura disse vem para cá.
                    for line in console.lines().filter(|line| line.starts_with("captura:") || line.starts_with("aviso: sem captura")) {
                        context.console.say(&format!("{:<14} {}", run.name, line.trim()));
                    }
                }
                // A serial do test-boot; sem ela (processo morto), a saída
                // dele, que também traz a serial.
                let serial = report::read_lossy(&directory.join("serial.log"));
                let log = if serial.is_some() { context.relative(run, "serial.log") } else { context.relative(run, "test-boot.log") };
                let excerpt = report::serial_excerpt(serial.as_deref().unwrap_or(&console));
                match result {
                    Ok((passed, _)) => (passed, Some(build), Some(time), report::failure_reason(&console), excerpt, log),
                    Err(error) => (false, Some(build), Some(time), error, excerpt, log),
                }
            }
        };
        let verdict = match (passed, test.expected_failure) {
            (true, false) => Verdict::Passed,
            (false, false) => Verdict::Failed,
            (false, true) => Verdict::ExpectedFailure,
            (true, true) => Verdict::UnexpectedPass,
        };
        if verdict.passed() && !context.keep {
            let _ = fs::remove_dir_all(&directory);
        }
        let mut outcomes = outcomes.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let shown = if verdict.passed() { String::new() } else { format!("  {log}") };
        context.console.say(&format!(
            "{:<14} {:<width$}  {}{shown}  ({}/{})",
            verdict.label(),
            run.name,
            time.map(report::duration).unwrap_or_else(|| String::from("-")),
            outcomes.len() + 1,
            context.runs.len()
        ));
        let repeat_command = match build {
            Some(_) => test.command_line(
                &format!("{OUTPUT_DIR}/{}", run.name),
                &format!("--no-build --image-dir={} --accel={}", Context::image_relative(run.image), context.accelerator(test)),
            ),
            None => String::new(),
        };
        outcomes.push(Outcome { name: run.name.clone(), verdict, build, test: time, reason, excerpt, log, repeat_command });
    }
}

fn list(context: &Context, chosen: &[usize]) {
    for (index, test) in context.tests.iter().enumerate() {
        let mark = if chosen.contains(&index) { "x" } else { " " };
        let mut notes = Vec::new();
        if test.expected_failure {
            notes.push("espera falha");
        }
        if test.covered_by_suite {
            notes.push("coberto pela suite");
        }
        let accelerator = format!("acelerador {}", context.accelerator(test));
        notes.push(&accelerator);
        let notes = format!(" ({})", notes.join(", "));
        println!("[{mark}] {}{notes}", test.id);
        println!("      {}", test.command_line(&format!("{OUTPUT_DIR}/{}", test.id), ""));
    }
    println!("{} de {} testes selecionados ([x])", chosen.len(), context.tests.len());
}

pub fn run(arguments: &[String]) -> Result<(), String> {
    run_with(parse_options(arguments, false)?, false)
}

/// `cargo xtask capturas`: cada `[[teste]]` com `--capture`.
pub fn capture(arguments: &[String]) -> Result<(), String> {
    let mut options = parse_options(arguments, true)?;
    options.suites = Suites::Excluded;
    run_with(options, true)
}

fn run_with(mut options: Options, capture: bool) -> Result<(), String> {
    let root = build::workspace_root();
    let tests = plan::load(&root)?;
    if capture && options.only.is_empty() {
        // Todos os [[teste]], inclusive os que só as suítes rodam.
        options.only = tests.iter().filter(|test| !test.suite).map(|test| test.id.clone()).collect();
    }
    let chosen = plan::select(&tests, &options.only, &options.skip, options.suites, options.extras)?;
    if capture && chosen.iter().any(|&index| tests[index].suite) {
        return Err("as suites nao tem captura: escolha ids de [[teste]]".into());
    }
    let runs = plan::runs(&tests, &chosen, options.repeat);
    let width = runs.iter().map(|run| run.name.len()).max().unwrap_or(0);
    let executable = std::env::current_exe().map_err(|error| format!("executavel do xtask: {error}"))?;
    // Detectado uma vez para a rodada: cada test-boot recebe o --accel dele.
    let detected = crate::qemu::detect_accelerator()?;
    let accelerator = options.accelerator.clone().unwrap_or_else(|| detected.to_string());
    if detected != "whpx" && (accelerator == "whpx" || chosen.iter().any(|&index| tests[index].accelerator.as_deref() == Some("whpx"))) {
        return Err("o WHPX foi pedido, mas o QEMU ou esta maquina nao o tem".into());
    }
    let skipped = if options.only.is_empty() && !options.extras.expected_failures {
        tests.iter().filter(|test| test.expected_failure && !test.covered_by_suite).map(|test| test.id.clone()).collect()
    } else {
        Vec::new()
    };
    let context = Context {
        tests,
        runs,
        root,
        executable,
        keep: options.keep,
        console: Console { started: Instant::now(), lock: Mutex::new(()) },
        width,
        memory_gate: Mutex::new(Vec::new()),
        running: AtomicUsize::new(0),
        capture: capture.then(|| build::workspace_root().join(CAPTURE_DIR)),
        accelerator,
    };
    if options.list {
        list(&context, &chosen);
        return Ok(());
    }

    let mut cpus = thread::available_parallelism().map(usize::from).unwrap_or(2);
    if options.cpu_friendly {
        let applied = host::cpu_friendly()?;
        println!(
            "cpu-friendly: prioridade abaixo do normal; afinidade {:#x} ({} de {} CPUs logicas, {} livres)",
            applied.mask,
            applied.cpus,
            applied.total,
            applied.total - applied.cpus
        );
        cpus = applied.cpus;
    }
    let jobs = options.jobs.unwrap_or((cpus / 2).max(1)).min(context.runs.len());
    let kernels = {
        let mut keys: Vec<&str> = context.runs.iter().map(|run| context.tests[run.test].kernel_key.as_str()).collect();
        keys.sort_unstable();
        keys.dedup();
        keys.len()
    };
    println!(
        "test-all: {} execucoes ({} {} do kernel, {} {} de imagens) em {jobs} pistas; pastas em {OUTPUT_DIR}/",
        context.runs.len(),
        kernels,
        if kernels == 1 { "build" } else { "builds" },
        context.image_count(),
        if context.image_count() == 1 { "pasta" } else { "pastas" }
    );
    let fixed: Vec<String> = context
        .runs
        .iter()
        .filter_map(|run| context.tests[run.test].accelerator.as_ref().map(|accelerator| format!("{} ({accelerator})", context.tests[run.test].id)))
        .collect();
    println!(
        "acelerador: {}{}",
        context.accelerator,
        if fixed.is_empty() { String::new() } else { format!("; fixado no components.toml: {}", fixed.join(", ")) }
    );
    if !skipped.is_empty() {
        println!("fora da rodada (espera_falha; --espera-falha os inclui): {}", skipped.join(", "));
    }
    if let Some(available) = host::available_commit() {
        let largest = context.runs.iter().map(|run| context.tests[run.test].memory).max().unwrap_or(0);
        println!(
            "memoria: commit livre {}; cada QEMU compromete ate {} e so comeca com {} de margem",
            gib(available),
            gib(largest),
            gib(COMMIT_RESERVE)
        );
    }

    // A pasta dos binários do Windows do formato anterior do test-all: o
    // build usa a de todos (build/windows), com o mesmo kernel compilado.
    let _ = fs::remove_dir_all(context.root.join(OUTPUT_DIR).join("windows"));
    let (sender, receiver) = mpsc::channel::<Prepared>();
    let receiver = Mutex::new(receiver);
    let outcomes = Mutex::new(Vec::new());
    thread::scope(|scope| {
        let context = &context;
        scope.spawn(move || builder(context, sender));
        for _ in 0..jobs {
            scope.spawn(|| lane(context, &receiver, &outcomes));
        }
    });

    // A tabela na ordem da lista (as suítes e depois o components.toml).
    let mut outcomes = outcomes.into_inner().unwrap_or_else(|poisoned| poisoned.into_inner());
    let order = |name: &str| {
        let position = context.runs.iter().position(|run| run.name == name).unwrap_or(usize::MAX);
        (context.runs.get(position).map_or(usize::MAX, |run| run.test), position)
    };
    outcomes.sort_by_key(|outcome| order(&outcome.name));
    // As imagens de quem passou saem; as de uma falha ficam para o comando
    // que repete o QEMU.
    if !context.keep {
        for image in 0..context.image_count() {
            let failed = outcomes.iter().any(|outcome| {
                !outcome.verdict.passed() && context.runs.iter().any(|run| run.name == outcome.name && run.image == image)
            });
            if !failed {
                let _ = fs::remove_dir_all(context.image_directory(image));
            }
        }
    }
    let failed = report::summary(&outcomes, context.console.started.elapsed());
    if let Some(directory) = &context.capture {
        return capture_report(&context, directory);
    }
    if failed > 0 {
        Err(format!("test-all: {failed} de {} execucoes falharam", outcomes.len()))
    } else {
        Ok(())
    }
}

/// As capturas desta rodada: o que cada uma registrou e as que faltaram
/// (um teste cujo QEMU morreu antes da tela). Uma falha de teste não
/// reprova o `capturas`: a tela da falha é a captura dele.
fn capture_report(context: &Context, directory: &Path) -> Result<(), String> {
    let started = std::time::SystemTime::now() - context.console.started.elapsed();
    let mut missing = Vec::new();
    println!();
    println!("capturas em {CAPTURE_DIR}/:");
    let mut seen: Vec<&str> = Vec::new();
    for run in &context.runs {
        let id = context.tests[run.test].id.as_str();
        if seen.contains(&id) {
            continue;
        }
        seen.push(id);
        let path = directory.join(format!("{id}.png"));
        let fresh = fs::metadata(&path).and_then(|metadata| metadata.modified()).is_ok_and(|modified| modified >= started);
        let info = fs::read(&path).ok().and_then(|bytes| crate::png::read_info(&bytes).map(|info| (info, bytes.len())));
        match (fresh, info) {
            (true, Some((info, size))) => println!(
                "  {id:<20} {}x{} {:>6} bytes  {}",
                info.width,
                info.height,
                size,
                info.text("opennt-resultado").unwrap_or("-")
            ),
            _ => {
                println!("  {id:<20} SEM CAPTURA NOVA");
                missing.push(id.to_string());
            }
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("capturas: {} sem captura nova: {}", missing.len(), missing.join(", ")))
    }
}
