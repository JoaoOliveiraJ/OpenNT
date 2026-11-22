//! O volume do primeiro logon feito (`--primeiro-logon-feito` e
//! `--gerar-primeiro-logon` do test-boot).
//!
//! O primeiro logon da conta de teste é a parte mais lenta do boot da cadeia
//! e a mais sensível à carga do hospedeiro: o serviço de perfis cria o
//! perfil, o StateRepository cria os bancos dele com milhares de escritas
//! síncronas e o AppReadiness registra os pacotes da caixa. Os testes que só
//! precisam de uma área de trabalho com o usuário logado podem começar de um
//! volume em que esse trabalho já foi feito, pelo próprio convidado:
//!
//! 1. o gerador sobe o boot da cadeia (o mesmo volume e o mesmo kernel do
//!    teste, a máquina dele e as opções de carga sem os diagnósticos,
//!    [`producer_options`]) sobre uma cópia gravável do `ntfs.img` montado
//!    pelo build, até a área de trabalho (`DESKTOP_OK` da vigia da tela);
//! 2. espera o disco do convidado parar de gravar e desliga a máquina como
//!    uma pessoa: Win+R e `shutdown -s -t 0` (o shutdown.exe real, o
//!    InitiateShutdownW, o fim da sessão pelo winlogon e o NtShutdownSystem),
//!    conferindo na serial o desligamento ordenado e o evento ACPI do QMP;
//! 3. só então a cópia vira a entrada do cache. O xtask não escreve nada
//!    nela: tudo o que muda em relação ao volume do build foi gravado pelo
//!    convidado nesse boot (os IDs, o perfil, os bancos e as chaves dele).
//!
//! A chave de uma entrada é o hash do conteúdo de tudo o que o boot do
//! gerador usa: o `ntfs.img` (que leva o kernel, os arquivos do Windows, as
//! hives das sementes e os perfis), o `os.img` com as opções de carga do
//! gerador, a máquina, o executável do QEMU e a versão da receita
//! ([`RECIPE`]). Qualquer mudança numa entrada dá outra chave. Cada teste
//! sobe a entrada com `snapshot=on`: as escritas dele vão para o overlay
//! temporário do QEMU e a entrada fica intacta para o próximo.
//!
//! O cache fica em `OPENNT_PRIMEIRO_LOGON` (padrão `build/primeiro-logon` da
//! raiz do workspace), com as [`KEEP`] entradas mais novas.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::build::{self, BuildOptions};
use crate::qemu::{self, Disks, InputSend, MachineOptions, TestOptions};
use crate::screen_check::DESKTOP_MARKER;

/// A versão da receita do gerador: muda quando o boot que gera o volume
/// muda (as opções, a espera do disco, o comando de desligamento).
pub const RECIPE: u32 = 1;
/// A variável com a pasta do cache.
pub const CACHE_VARIABLE: &str = "OPENNT_PRIMEIRO_LOGON";
/// A pasta padrão do cache, relativa à raiz do workspace.
const DEFAULT_CACHE: &str = "build/primeiro-logon";
/// Quantas entradas ficam no cache (cada uma tem o volume inteiro).
const KEEP: usize = 2;
/// O prazo do boot do gerador: o da área de trabalho, a espera do disco e
/// o desligamento.
pub const PRODUCER_TIMEOUT: Duration = Duration::from_secs(2100);
/// O comando da caixa Executar que desliga a máquina (`-s`: desligar; `-t
/// 0`: sem espera). O hífen e as letras têm a mesma tecla no layout dos
/// EUA e no ABNT2.
pub const SHUTDOWN_COMMAND: &str = "shutdown -s -t 0";
/// O volume de uma entrada.
const VOLUME: &str = "ntfs.img";
/// O que a entrada guarda do boot que a gerou.
const MANIFEST: &str = "chave.txt";
const PRODUCER_SERIAL: &str = "serial.log";
/// A pasta do boot do gerador dentro da pasta de build do teste.
pub const WORK_DIR: &str = "primeiro-logon";
/// A cadeia que o gerador confere: o logon, a área de trabalho e o
/// desligamento ordenado até o fim (como o teste desligamento-cadeia).
const PRODUCER_CHAIN: &[&str] = &[
    "USER_LOGON_OK",
    "PROFILE_LOADED",
    "EXPLORER_STARTED",
    DESKTOP_MARKER,
    "[po] desligamento ordenado",
    "[ntfs] desligamento: ",
    "FLUSHED",
    "POWER_OFF",
];
/// Quanto um gerador espera a trava de outro que gera a mesma entrada.
const LOCK_WAIT: Duration = Duration::from_secs(2700);
/// Uma entrada mais nova que isso fica mesmo além das [`KEEP`]: uma rodada
/// pode estar subindo testes dela.
const RECENT: Duration = Duration::from_secs(6 * 3600);

/// A pasta do cache.
pub fn cache_root() -> PathBuf {
    match std::env::var_os(CACHE_VARIABLE) {
        Some(directory) if !directory.is_empty() => PathBuf::from(directory),
        _ => build::workspace_root().join(DEFAULT_CACHE),
    }
}

/// As opções de carga do boot do gerador: as do teste sem os diagnósticos
/// e os testes de kernel (o depurador, os rastros, o perfil, os drivers
/// extras, o teste de desligamento e o de pressão de memória). O volume, o
/// vídeo, a pilha de armazenamento e os dispositivos ficam.
pub fn producer_options(options: &BuildOptions) -> BuildOptions {
    BuildOptions {
        kernel_test_scope: if options.kernel_test_scope == "e-process" { options.kernel_test_scope.clone() } else { String::from("none") },
        console_mirror: true,
        start_driver: String::new(),
        trace_driver_api: false,
        trace_rpc: false,
        trace_failures: false,
        trace_files: false,
        heap_census: false,
        profile: String::new(),
        slow_service_exit: false,
        kd: String::new(),
        shutdown_test: String::new(),
        memory_pressure: false,
        ..options.clone()
    }
}

/// A máquina do gerador: a do teste, sem o depurador e sem falha de disco.
fn producer_machine(machine: &MachineOptions) -> MachineOptions {
    MachineOptions { kd_port: None, monitor_port: None, ata_fault: String::new(), ..machine.clone() }
}

/// O que da máquina entra na chave (e no texto da entrada).
fn machine_text(machine: &MachineOptions) -> String {
    format!("smp={} memoria={} usb={} rede={} tpm={} acelerador={}", machine.smp, machine.memory_mb, machine.usb, machine.net, machine.tpm, machine.accelerator)
}

/// As opções que o test-boot recusa com o primeiro logon feito.
pub fn check(options: &BuildOptions, machine: &MachineOptions) -> Result<(), String> {
    if !options.test_account {
        return Err("--primeiro-logon-feito e --gerar-primeiro-logon exigem --conta-de-teste (o primeiro logon e o da conta de teste)".into());
    }
    if options.display != "basic" {
        return Err("--primeiro-logon-feito e --gerar-primeiro-logon exigem --display=basic (o gerador confere a area de trabalho na tela)".into());
    }
    if options.shutdown_chain {
        return Err("--primeiro-logon-feito e --gerar-primeiro-logon nao valem com --shutdown-test=cadeia (o teste e o do primeiro boot)".into());
    }
    if !machine.ata_fault.is_empty() {
        return Err("--primeiro-logon-feito e --gerar-primeiro-logon nao valem com --ata-fault".into());
    }
    Ok(())
}

// ---- hash do conteúdo ---------------------------------------------------------

const PRIME_1: u64 = 0x9E37_79B1_85EB_CA87;
const PRIME_2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const PRIME_3: u64 = 0x1656_67B1_9E37_79F9;
const PRIME_4: u64 = 0x85EB_CA77_C2B2_AE63;
const PRIME_5: u64 = 0x27D4_EB2F_1656_67C5;

/// O XXH64 (o hash de 64 bits do xxHash, semente 0), aos pedaços: rápido o
/// bastante para os 1,5 GB do volume em cada boot que o usa.
struct Xxh64 {
    lanes: [u64; 4],
    pending: [u8; 32],
    pending_length: usize,
    total: u64,
}

fn round(lane: u64, input: u64) -> u64 {
    lane.wrapping_add(input.wrapping_mul(PRIME_2)).rotate_left(31).wrapping_mul(PRIME_1)
}

fn merge(hash: u64, lane: u64) -> u64 {
    (hash ^ round(0, lane)).wrapping_mul(PRIME_1).wrapping_add(PRIME_4)
}

fn word(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[..8].try_into().unwrap())
}

impl Xxh64 {
    fn new() -> Xxh64 {
        Xxh64 { lanes: [PRIME_1.wrapping_add(PRIME_2), PRIME_2, 0, 0u64.wrapping_sub(PRIME_1)], pending: [0; 32], pending_length: 0, total: 0 }
    }

    fn stripe(&mut self, block: &[u8]) {
        for (index, lane) in self.lanes.iter_mut().enumerate() {
            *lane = round(*lane, word(&block[index * 8..]));
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.total += input.len() as u64;
        if self.pending_length > 0 {
            let take = (32 - self.pending_length).min(input.len());
            self.pending[self.pending_length..self.pending_length + take].copy_from_slice(&input[..take]);
            self.pending_length += take;
            input = &input[take..];
            if self.pending_length < 32 {
                return;
            }
            let block = self.pending;
            self.stripe(&block);
            self.pending_length = 0;
        }
        let mut blocks = input.chunks_exact(32);
        for block in blocks.by_ref() {
            self.stripe(block);
        }
        let rest = blocks.remainder();
        self.pending[..rest.len()].copy_from_slice(rest);
        self.pending_length = rest.len();
    }

    fn finish(&self) -> u64 {
        let [v1, v2, v3, v4] = self.lanes;
        let mut hash = if self.total >= 32 {
            let hash = v1.rotate_left(1).wrapping_add(v2.rotate_left(7)).wrapping_add(v3.rotate_left(12)).wrapping_add(v4.rotate_left(18));
            [v1, v2, v3, v4].into_iter().fold(hash, merge)
        } else {
            PRIME_5
        };
        hash = hash.wrapping_add(self.total);
        let mut rest = &self.pending[..self.pending_length];
        while rest.len() >= 8 {
            hash = (hash ^ round(0, word(rest))).rotate_left(27).wrapping_mul(PRIME_1).wrapping_add(PRIME_4);
            rest = &rest[8..];
        }
        if rest.len() >= 4 {
            let value = u64::from(u32::from_le_bytes(rest[..4].try_into().unwrap()));
            hash = (hash ^ value.wrapping_mul(PRIME_1)).rotate_left(23).wrapping_mul(PRIME_2).wrapping_add(PRIME_3);
            rest = &rest[4..];
        }
        for &byte in rest {
            hash = (hash ^ u64::from(byte).wrapping_mul(PRIME_5)).rotate_left(11).wrapping_mul(PRIME_1);
        }
        hash ^= hash >> 33;
        hash = hash.wrapping_mul(PRIME_2);
        hash ^= hash >> 29;
        hash = hash.wrapping_mul(PRIME_3);
        hash ^ (hash >> 32)
    }
}

fn hash_bytes(bytes: &[u8]) -> u64 {
    let mut hasher = Xxh64::new();
    hasher.update(bytes);
    hasher.finish()
}

/// O hash e o tamanho de um arquivo, lido em blocos de 4 MB.
fn hash_file(path: &Path) -> Result<(u64, u64), String> {
    let error = |error: std::io::Error| format!("{}: {error}", path.display());
    let mut file = fs::File::open(path).map_err(error)?;
    let mut hasher = Xxh64::new();
    let mut buffer = vec![0u8; 4 << 20];
    loop {
        let count = file.read(&mut buffer).map_err(error)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok((hasher.finish(), hasher.total))
}

// ---- a chave e as entradas ------------------------------------------------------

/// A chave de uma entrada e o texto do que ela cobre.
struct Key {
    name: String,
    manifest: String,
}

/// A chave do boot do gerador: o volume do build, a imagem de boot com as
/// opções de carga do gerador, a máquina, o QEMU e a receita.
fn compute_key(volume: &Path, boot: &Path, options: &BuildOptions, machine: &MachineOptions) -> Result<Key, String> {
    let started = Instant::now();
    let (volume_hash, volume_size) = hash_file(volume)?;
    let (boot_hash, boot_size) = hash_file(boot)?;
    let qemu = qemu::find_qemu()?;
    let metadata = fs::metadata(&qemu).map_err(|error| format!("{}: {error}", qemu.display()))?;
    let modified = metadata.modified().ok().and_then(|time| time.duration_since(UNIX_EPOCH).ok()).map_or(0, |time| time.as_secs());
    let manifest = format!(
        "receita={RECIPE}\nvolume={volume_hash:016x} ({volume_size} bytes)\nboot={boot_hash:016x} ({boot_size} bytes)\nopcoes de carga={}\nmaquina={}\nqemu={} bytes, modificado em {modified}\n",
        options.load_options()?,
        machine_text(machine),
        metadata.len()
    );
    let name = format!("{:016x}", hash_bytes(manifest.as_bytes()));
    println!("[primeiro-logon] chave {name} ({:.1} s para o hash do volume)", started.elapsed().as_secs_f64());
    Ok(Key { name, manifest })
}

/// A trava de quem gera uma entrada: o arquivo `<chave>.trava` travado
/// pelo sistema (`File::try_lock`) enquanto o handle vive. Um gerador morto
/// (o test-all mata o test-boot que passa do prazo) solta a trava com o
/// processo.
struct Lock(#[allow(dead_code)] fs::File);

/// O arquivo da trava de `name`, travado agora (`Some`) ou por outro
/// processo (`None`).
fn try_lock(path: &Path) -> Result<Option<fs::File>, String> {
    let file = fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(fs::TryLockError::WouldBlock) => Ok(None),
        Err(fs::TryLockError::Error(error)) => Err(format!("{}: {error}", path.display())),
    }
}

/// Pega a trava da entrada `name`, ou espera outro gerador terminá-la.
/// Devolve `None` quando a entrada ficou pronta durante a espera.
fn lock_or_wait(root: &Path, name: &str) -> Result<Option<Lock>, String> {
    let path = root.join(format!("{name}.trava"));
    let deadline = Instant::now() + LOCK_WAIT;
    let mut said = false;
    loop {
        let file = try_lock(&path)?;
        if root.join(name).join(VOLUME).is_file() {
            return Ok(None);
        }
        if let Some(file) = file {
            return Ok(Some(Lock(file)));
        }
        if !said {
            println!("[primeiro-logon] outro gerador esta montando {name}; esperando");
            said = true;
        }
        if Instant::now() > deadline {
            return Err(format!("{}: a trava de outro gerador nao saiu em {} s", path.display(), LOCK_WAIT.as_secs()));
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

fn age(path: &Path) -> Option<Duration> {
    fs::metadata(path).ok()?.modified().ok()?.elapsed().ok()
}

/// Apaga as entradas mais velhas, deixando as [`KEEP`] mais novas (pela
/// data do texto delas) e as de menos de [`RECENT`], que uma rodada ainda
/// pode estar usando. As pastas `.parcial` e as travas que ninguém trava
/// são de um gerador que terminou ou morreu.
fn prune(root: &Path) {
    let Ok(entries) = fs::read_dir(root) else { return };
    let mut ready: Vec<(SystemTime, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(stem) = name.strip_suffix(".parcial") {
            if matches!(try_lock(&root.join(format!("{stem}.trava"))), Ok(Some(_))) {
                let _ = fs::remove_dir_all(&path);
            }
            continue;
        }
        if name.ends_with(".trava") {
            let unused = matches!(try_lock(&path), Ok(Some(_)));
            if unused {
                let _ = fs::remove_file(&path);
            }
            continue;
        }
        if let Some(time) = fs::metadata(path.join(MANIFEST)).ok().and_then(|metadata| metadata.modified().ok()) {
            ready.push((time, path));
        }
    }
    ready.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, path) in ready.into_iter().skip(KEEP) {
        if age(&path.join(MANIFEST)).is_some_and(|age| age < RECENT) {
            continue;
        }
        println!("[primeiro-logon] entrada velha removida: {}", path.display());
        let _ = fs::remove_dir_all(&path);
    }
}

/// O volume do primeiro logon feito para o boot de `options` e `machine`
/// sobre as imagens de `images`: a entrada do cache, ou uma nova, gerada
/// por um boot do convidado ([`produce`]). Os arquivos desse boot ficam em
/// `<work>/primeiro-logon`.
pub fn ensure(images: &Path, work: &Path, options: &BuildOptions, machine: &MachineOptions) -> Result<PathBuf, String> {
    let options = producer_options(options);
    let machine = producer_machine(machine);
    let volume = images.join(VOLUME);
    if !volume.is_file() {
        return Err(format!("{}: o primeiro logon precisa do volume NTFS do build", volume.display()));
    }
    let work = work.join(WORK_DIR);
    fs::create_dir_all(&work).map_err(|error| format!("{}: {error}", work.display()))?;
    let boot = work.join("os.img");
    fs::copy(images.join("os.img"), &boot).map_err(|error| format!("{}: {error}", boot.display()))?;
    build::stamp_load_options(&boot, &options)?;
    let key = compute_key(&volume, &boot, &options, &machine)?;
    let root = cache_root();
    fs::create_dir_all(&root).map_err(|error| format!("{}: {error}", root.display()))?;
    let entry = root.join(&key.name);
    let ready = entry.join(VOLUME);
    if ready.is_file() {
        println!("[primeiro-logon] volume do primeiro logon feito: {} (do cache)", ready.display());
        return Ok(ready);
    }
    let Some(_lock) = lock_or_wait(&root, &key.name)? else {
        println!("[primeiro-logon] volume do primeiro logon feito: {} (gerado por outro test-boot)", ready.display());
        return Ok(ready);
    };
    let partial = root.join(format!("{}.parcial", key.name));
    if partial.exists() {
        fs::remove_dir_all(&partial).map_err(|error| format!("{}: {error}", partial.display()))?;
    }
    fs::create_dir_all(&partial).map_err(|error| format!("{}: {error}", partial.display()))?;
    let result = produce(&volume, &boot, &work, &partial, &machine);
    let log = work.join(PRODUCER_SERIAL);
    let elapsed = match result {
        Ok(elapsed) => elapsed,
        Err(error) => {
            let _ = fs::remove_dir_all(&partial);
            // O motivo do test-boot do gerador, com a serial dele.
            return Err(format!("TEST-BOOT FALHOU: boot do primeiro logon: {}", error.trim_start_matches("TEST-BOOT FALHOU: ")));
        }
    };
    let _ = fs::copy(&log, partial.join(PRODUCER_SERIAL));
    let generated = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |time| time.as_secs());
    let manifest = format!("{}gerada em {generated} (Unix), boot do gerador de {:.0} s\n", key.manifest, elapsed.as_secs_f64());
    fs::write(partial.join(MANIFEST), manifest).map_err(|error| format!("{}: {error}", partial.display()))?;
    fs::rename(&partial, &entry).map_err(|error| format!("{} -> {}: {error}", partial.display(), entry.display()))?;
    prune(&root);
    println!("[primeiro-logon] volume do primeiro logon feito: {} (gerado em {:.0} s)", ready.display(), elapsed.as_secs_f64());
    Ok(ready)
}

/// O boot do gerador: a cópia gravável do volume em `partial`, a área de
/// trabalho, o disco parado, o shutdown.exe e o desligamento ACPI.
fn produce(volume: &Path, boot: &Path, work: &Path, partial: &Path, machine: &MachineOptions) -> Result<Duration, String> {
    let copy = partial.join(VOLUME);
    println!("[primeiro-logon] gerando: copia de {} para {}", volume.display(), copy.display());
    fs::copy(volume, &copy).map_err(|error| format!("{} -> {}: {error}", volume.display(), copy.display()))?;
    let disks = Disks { boot: boot.to_path_buf(), data: Some(copy), data_snapshot: false, nvme: None, nvme_snapshot: false };
    let test = TestOptions {
        marker: String::from("USER_INITIALIZED"),
        timeout: PRODUCER_TIMEOUT,
        keys: None,
        expect: PRODUCER_CHAIN.iter().map(|text| text.to_string()).collect(),
        expect_any: Vec::new(),
        hold: Duration::ZERO,
        capture: None,
        expect_stop: false,
        manual_crash: false,
        power_cycles: 0,
        allow_reboot: false,
        expect_poweroff: true,
        watch_screen: true,
        capture_every: Some(Duration::from_secs(30)),
        inputs: vec![InputSend::shutdown(DESKTOP_MARKER, SHUTDOWN_COMMAND)],
        nmi_samples: false,
    };
    let started = Instant::now();
    qemu::test_boot(&disks, machine, &test, &work.join(PRODUCER_SERIAL), None)?;
    Ok(started.elapsed())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Os valores de referência do XXH64 com semente 0.
    #[test]
    fn xxh64_reference_values() {
        assert_eq!(hash_bytes(b""), 0xEF46_DB37_51D8_E999);
        assert_eq!(hash_bytes(b"abc"), 0x44BC_2CF5_AD77_0999);
    }

    /// Aos pedaços (de qualquer tamanho) ou de uma vez, o mesmo hash.
    #[test]
    fn xxh64_in_pieces() {
        let data: Vec<u8> = (0..1000u32).map(|value| (value.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
        let whole = hash_bytes(&data);
        for piece in [1usize, 3, 7, 31, 32, 33, 100] {
            let mut hasher = Xxh64::new();
            for chunk in data.chunks(piece) {
                hasher.update(chunk);
            }
            assert_eq!(hasher.finish(), whole, "pedacos de {piece}");
        }
        assert_ne!(hash_bytes(&data[..999]), whole);
    }

    /// A trava de uma entrada vale enquanto o handle vive; a entrada pronta
    /// dispensa a trava; o `prune` apaga a trava solta e a pasta `.parcial`
    /// sem dono e guarda as entradas recentes.
    #[test]
    fn lock_and_prune() {
        let root = std::env::temp_dir().join(format!("opennt-primeiro-logon-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let held = lock_or_wait(&root, "abc").unwrap().expect("trava livre");
        assert!(try_lock(&root.join("abc.trava")).unwrap().is_none(), "a trava vale para outro handle");
        fs::create_dir_all(root.join("abc.parcial")).unwrap();
        prune(&root);
        assert!(root.join("abc.parcial").is_dir() && root.join("abc.trava").is_file(), "o gerador vivo fica");
        drop(held);
        prune(&root);
        assert!(!root.join("abc.parcial").exists() && !root.join("abc.trava").exists(), "o gerador morto sai");
        for name in ["e1", "e2", "e3"] {
            fs::create_dir_all(root.join(name)).unwrap();
            fs::write(root.join(name).join(MANIFEST), name).unwrap();
            fs::write(root.join(name).join(VOLUME), name).unwrap();
        }
        prune(&root);
        assert!(["e1", "e2", "e3"].iter().all(|name| root.join(name).join(VOLUME).is_file()), "as recentes ficam");
        assert!(lock_or_wait(&root, "e1").unwrap().is_none(), "a entrada pronta dispensa a trava");
        let _ = fs::remove_dir_all(&root);
    }

    /// O gerador tira os diagnósticos e guarda o volume, o vídeo e os
    /// dispositivos do teste.
    #[test]
    fn producer_drops_diagnostics() {
        let mut command = vec![String::from("test-boot")];
        command.extend(["USER_INITIALIZED", "1800000", "--initial-process=smss", "--display=basic", "--conta-de-teste", "--kd=com2", "--trace-rpc", "--smp=2", "--user-smp"].map(String::from));
        let parsed = crate::parse(command).unwrap();
        let options = crate::test_build_options(&parsed);
        let producer = producer_options(&options);
        assert_eq!(producer.load_options().unwrap(), "INITIALPROCESS=smss DISPLAY=basic USERSMP CONSOLEMIRROR");
        assert_eq!(producer.image_key(), options.image_key());
        let machine = producer_machine(&MachineOptions { kd_port: Some(1234), ..parsed.machine.clone() });
        assert_eq!(machine.kd_port, None);
        assert!(machine_text(&machine).starts_with("smp=2 memoria=8192"));
    }
}
