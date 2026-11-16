//! Build do OpenNT:
//!
//! 1. compila `boot` (setor de boot + stage2) e `kernel` para
//!    `x86_64-unknown-none`;
//! 2. extrai o binário plano do boot com `llvm-objcopy`;
//! 3. empacota o kernel ELF como PE32+ (`kernel_pe`);
//! 4. monta `os.img`: [setor 0: boot][LBA 1..63: stage2][LBA 64: opções de
//!    carga][LBA 65+: kernel] e grava o número de setores do kernel no
//!    header do stage2 (offset 3).
//!
//! O kernel é um só para todas as opções: as de boot (`--kernel-test-scope`,
//! `--start-driver`, `--kd`, `--initial-process`...) vão no bloco de opções
//! de carga do LBA 64 (`kernel/src/ntos/init/load_options.rs`), que o kernel
//! lê ao entrar. Só o volume NTFS depende delas: o do boot do smss leva os
//! programas dessa cadeia e outra hive SYSTEM.

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::kernel_pe;

#[path = "../../kernel/src/ntos/init/load_options.rs"]
#[allow(dead_code)]
pub mod load_options;

pub const TARGET: &str = "x86_64-unknown-none";
const STAGE2_MAX: usize = 64 * 512; // reserva do stage2 na imagem (LBA 1..64)
/// Posição do bloco de opções de carga na imagem de boot.
const LOAD_OPTIONS_OFFSET: u64 = load_options::SECTOR as u64 * 512;
/// Os binários do Windows do bundle, para todo build (`--windows-dir` troca):
/// o caminho entra no build do kernel, então uma pasta só faz builds com
/// `--build-dir` diferentes reaproveitarem o mesmo kernel compilado.
pub const WINDOWS_DIR: &str = "build/windows";

/// As opções de um build. As de boot (do `user_program` ao `kd`, menos o
/// `release`, o `build_dir` e o `windows_dir`) não mudam o kernel compilado:
/// vão no bloco de opções de carga da imagem ([`BuildOptions::load_options`]).
#[derive(Clone, Debug)]
pub struct BuildOptions {
    pub release: bool,
    pub build_dir: PathBuf,
    pub user_program: String,
    pub kernel_test_scope: String,
    pub console_mirror: bool,
    /// `--start-driver=NOME[,NOME...]`: serviços iniciados pelo SCM antes do
    /// programa, na ordem dada.
    pub start_driver: String,
    /// `--trace-driver-api`: rastreia as APIs chamadas durante esse início.
    pub trace_driver_api: bool,
    /// `--initial-process=smss`: o kernel inicia o smss.exe real como o
    /// primeiro processo de usuário (vazio = o boot comum).
    pub initial_process: String,
    /// `--storage=real`: a pilha de armazenamento do Windows sobe pelo PnP.
    pub storage: String,
    /// `--display=basic`: o PnP instala o BasicDisplay.sys real no adaptador
    /// VGA e o inicia sobre o dxgkrnl.sys real.
    pub display: String,
    /// `--windows-dir=DIR`: pasta dos binários do Windows copiados para o
    /// bundle do kernel (padrão [`WINDOWS_DIR`]). Builds que dividem a pasta
    /// não recompilam o kernel só porque o caminho dela mudou.
    pub windows_dir: Option<PathBuf>,
    /// `--pnp-root=acpi`: a raiz da árvore de dispositivos é o acpi.sys real
    /// sobre o dispositivo ACPI da HAL, com o pci.sys real no barramento PCI.
    pub pnp_root: String,
    /// `--kd=com2`: o depurador do kernel nessa porta serial (vazio = sem
    /// depurador).
    pub kd: String,
}

impl BuildOptions {
    /// O texto das opções de carga: as opções de boot fora do padrão, com os
    /// nomes de `load_options.rs` (`DEBUG DEBUGPORT=COM2` como no Windows).
    /// Um valor é uma palavra só, de ASCII imprimível.
    pub fn load_options(&self) -> Result<String, String> {
        use load_options as name;
        let debug = self.kd.to_uppercase();
        let user_program = if self.user_program == "shell" { "" } else { self.user_program.as_str() };
        let test_scope = if self.kernel_test_scope == "none" { "" } else { self.kernel_test_scope.as_str() };
        let values = [
            (name::DEBUG_PORT, debug.as_str()),
            (name::USER_PROGRAM, user_program),
            (name::KERNEL_TEST_SCOPE, test_scope),
            (name::START_DRIVER, self.start_driver.as_str()),
            (name::INITIAL_PROCESS, self.initial_process.as_str()),
            (name::STORAGE, self.storage.as_str()),
            (name::DISPLAY, self.display.as_str()),
            (name::PNP_ROOT, self.pnp_root.as_str()),
        ];
        let mut words: Vec<String> = Vec::new();
        if !debug.is_empty() {
            words.push(String::from(name::DEBUG));
        }
        for (key, value) in values.into_iter().filter(|(_, value)| !value.is_empty()) {
            if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
                return Err(format!("opcao de boot com espaco ou fora do ASCII: {key}={value:?}"));
            }
            words.push(format!("{key}={value}"));
        }
        if self.trace_driver_api {
            words.push(String::from(name::TRACE_DRIVER_API));
        }
        if self.console_mirror {
            words.push(String::from(name::CONSOLE_MIRROR));
        }
        Ok(words.join(" "))
    }

    /// O bloco do LBA 64: assinatura, tamanho e o texto.
    pub fn load_options_block(&self) -> Result<Vec<u8>, String> {
        let text = self.load_options()?;
        if text.len() > load_options::TEXT_MAX {
            return Err(format!("opcoes de carga com {} bytes (cabem {}): {text}", text.len(), load_options::TEXT_MAX));
        }
        let mut block = vec![0u8; load_options::BLOCK_SIZE];
        block[..4].copy_from_slice(&load_options::SIGNATURE.to_le_bytes());
        block[4..8].copy_from_slice(&(text.len() as u32).to_le_bytes());
        block[load_options::HEADER_SIZE..load_options::HEADER_SIZE + text.len()].copy_from_slice(text.as_bytes());
        Ok(block)
    }

    /// As mesmas opções sem as de boot: o que o build embute nos arquivos.
    fn without_load_options(&self) -> BuildOptions {
        BuildOptions {
            build_dir: PathBuf::new(),
            user_program: String::from("shell"),
            kernel_test_scope: String::from("none"),
            console_mirror: false,
            start_driver: String::new(),
            trace_driver_api: false,
            storage: String::new(),
            display: String::new(),
            pnp_root: String::new(),
            kd: String::new(),
            ..self.clone()
        }
    }

    /// Builds com a mesma chave montam as mesmas imagens (o kernel e o volume
    /// NTFS) e só diferem no bloco de opções de carga. O Debug lista todas as
    /// opções, inclusive as que vierem a existir: uma opção nova divide as
    /// imagens até entrar em [`Self::without_load_options`].
    pub fn image_key(&self) -> String {
        format!("{:?}", self.without_load_options())
    }

    /// Builds com a mesma chave compilam o mesmo kernel: a das imagens sem o
    /// volume do smss.
    pub fn kernel_key(&self) -> String {
        let mut options = self.without_load_options();
        options.initial_process.clear();
        format!("{options:?}")
    }
}

/// Grava o bloco de opções de carga de `options` numa imagem de boot já
/// montada (o mesmo kernel serve a outro boot).
pub fn stamp_load_options(image: &Path, options: &BuildOptions) -> Result<(), String> {
    let block = options.load_options_block()?;
    let error = |error: std::io::Error| format!("{}: {error}", image.display());
    let mut file = fs::File::options().write(true).open(image).map_err(error)?;
    file.seek(SeekFrom::Start(LOAD_OPTIONS_OFFSET)).map_err(error)?;
    file.write_all(&block).map_err(error)
}

pub struct BuildOutput {
    pub image: PathBuf,
}

pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

/// Um caminho relativo das opções vale a partir da raiz do workspace.
pub fn in_workspace(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        workspace_root().join(path)
    }
}

fn run(command: &mut Command) -> Result<(), String> {
    let status = command.status().map_err(|error| format!("falha ao executar {command:?}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("comando falhou ({status}): {command:?}"))
    }
}

fn capture(command: &mut Command) -> Result<String, String> {
    let output = command.output().map_err(|error| format!("falha ao executar {command:?}: {error}"))?;
    if !output.status.success() {
        return Err(format!("comando falhou: {command:?}\n{}", String::from_utf8_lossy(&output.stderr)));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// `llvm-objcopy` do componente `llvm-tools` do toolchain ativo.
fn llvm_objcopy(root: &Path) -> Result<PathBuf, String> {
    let sysroot = capture(Command::new("rustc").current_dir(root).args(["--print", "sysroot"]))?;
    let version = capture(Command::new("rustc").current_dir(root).arg("-vV"))?;
    let host = version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .ok_or("rustc -vV sem host")?
        .to_string();
    let executable = if cfg!(windows) { "llvm-objcopy.exe" } else { "llvm-objcopy" };
    let path = Path::new(&sysroot).join("lib").join("rustlib").join(host).join("bin").join(executable);
    if path.exists() {
        Ok(path)
    } else {
        Err(format!(
            "{} nao encontrado; instale com: rustup component add llvm-tools-preview",
            path.display()
        ))
    }
}

fn cargo_build(root: &Path, package: &str, options: &BuildOptions, windows_binaries: Option<&Path>) -> Result<PathBuf, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut command = Command::new(cargo);
    command.current_dir(root).args(["build", "--package", package, "--target", TARGET]);
    if options.release {
        command.arg("--release");
    }
    match windows_binaries {
        Some(directory) => command.env("OPENNT_WINDOWS_BINARIES", directory),
        None => command.env_remove("OPENNT_WINDOWS_BINARIES"),
    };
    run(&mut command)?;
    let profile = if options.release { "release" } else { "debug" };
    // O cargo filho herda o CARGO_TARGET_DIR (relativo, vale a partir da
    // raiz): o binário fica onde ele mandar, e duas rodadas podem compilar
    // em pastas separadas ao mesmo tempo.
    let target = std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), |directory| root.join(directory));
    Ok(target.join(TARGET).join(profile).join(package))
}

/// O ELF do kernel na pasta de build: um hard link para o que o cargo gerou
/// (centenas de MB com o DWARF), ou uma cópia onde o link não dá. O link
/// guarda o conteúdo deste build: o linker grava o próximo num arquivo novo
/// e o cargo troca o dele de lugar, sem tocar no antigo.
fn link_or_copy(source: &Path, target: &Path) -> Result<(), String> {
    if target.exists() {
        fs::remove_file(target).map_err(|error| format!("{}: {error}", target.display()))?;
    }
    if fs::hard_link(source, target).is_ok() {
        return Ok(());
    }
    fs::copy(source, target).map(|_| ()).map_err(|error| format!("{}: {error}", target.display()))
}

pub fn build(options: &BuildOptions) -> Result<BuildOutput, String> {
    let root = workspace_root();
    let build_dir = in_workspace(&options.build_dir);
    fs::create_dir_all(&build_dir).map_err(|error| format!("{}: {error}", build_dir.display()))?;

    // Binários reais do Windows desta máquina, copiados antes do kernel que
    // os embute no bundle.
    let windows_dir = in_workspace(options.windows_dir.as_deref().unwrap_or(Path::new(WINDOWS_DIR)));
    crate::windows_binaries::stage(&windows_dir)?;
    let boot_elf = cargo_build(&root, "boot", options, None)?;
    let kernel_elf = cargo_build(&root, "kernel", options, Some(&windows_dir))?;

    // ---- boot: setor 0 + stage2 como binário plano -------------------------
    let boot_bin = build_dir.join("boot.bin");
    run(Command::new(llvm_objcopy(&root)?)
        .args(["-O", "binary", "--only-section=.boot"])
        .arg(&boot_elf)
        .arg(&boot_bin))?;
    let boot = fs::read(&boot_bin).map_err(|error| format!("{}: {error}", boot_bin.display()))?;
    if boot.len() < 512 + 5 || boot[510] != 0x55 || boot[511] != 0xAA {
        return Err("boot.bin: setor de boot sem assinatura 0xAA55".into());
    }
    let mut stage2 = boot[512..].to_vec();
    if stage2[0] != 0xEB || stage2[1] != 0x03 {
        return Err("stage2: cabecalho inesperado (kernel_sectors precisa ficar no offset 3)".into());
    }
    // O último setor da reserva é o das opções de carga.
    if 512 + stage2.len() > LOAD_OPTIONS_OFFSET as usize {
        return Err(format!("stage2 com {} bytes invade o setor das opcoes de carga (cabem {})", stage2.len(), LOAD_OPTIONS_OFFSET - 512));
    }

    // ---- kernel: ELF -> PE32+ -------------------------------------------------
    let elf = fs::read(&kernel_elf).map_err(|error| format!("{}: {error}", kernel_elf.display()))?;
    link_or_copy(&kernel_elf, &build_dir.join("kernel.elf"))?;
    let mut kernel = kernel_pe::build_kernel_pe(&elf, crate::windows_binaries::kernel_message_table().as_deref())?;
    fs::write(build_dir.join("kernel.pe"), &kernel).map_err(|error| error.to_string())?;
    // O volume leva o PE exatamente como foi gerado (sem o preenchimento).
    let kernel_pe = kernel.clone();
    kernel.resize(kernel.len().div_ceil(512) * 512, 0);
    let kernel_sectors = kernel.len() / 512;
    if kernel_sectors > u16::MAX as usize {
        return Err(format!("kernel com {kernel_sectors} setores nao cabe no campo u16 do stage2"));
    }

    // ---- os.img ---------------------------------------------------------------
    stage2[3..5].copy_from_slice(&(kernel_sectors as u16).to_le_bytes());
    stage2.resize(STAGE2_MAX, 0);
    let mut image = Vec::with_capacity(512 + STAGE2_MAX + kernel.len());
    image.extend_from_slice(&boot[..512]);
    image.extend_from_slice(&stage2);
    image.extend_from_slice(&kernel);
    let block = options.load_options_block()?;
    let at = LOAD_OPTIONS_OFFSET as usize;
    image[at..at + block.len()].copy_from_slice(&block);
    let image_path = build_dir.join("os.img");
    fs::write(&image_path, &image).map_err(|error| format!("{}: {error}", image_path.display()))?;
    // Segundo disco IDE (mestre-escravo primário): o volume NTFS de dados.
    let ntfs_path = build_dir.join("ntfs.img");
    let mut ntfs_files = crate::windows_binaries::ntfs_files(&root, &kernel_pe, &options.initial_process)?;
    // As hives de máquina que o kernel carrega no boot, das tabelas de
    // semente dele.
    for (name, image) in crate::hive_image::machine_hives(options.initial_process == "smss") {
        ntfs_files.push((format!("Windows/System32/config/{name}"), image));
    }
    let ntfs_bytes = crate::ntfs_image::build(&ntfs_path, &ntfs_files, 32, 256)?;

    let text = options.load_options()?;
    println!(
        "OK: {}  (kernel {}b/{} setores, NTFS {}MB, opcoes de carga: {})",
        image_path.strip_prefix(&root).unwrap_or(&image_path).display(),
        kernel.len(),
        kernel_sectors,
        ntfs_bytes / 1_048_576,
        if text.is_empty() { "nenhuma" } else { text.as_str() }
    );
    Ok(BuildOutput { image: image_path })
}

#[cfg(test)]
mod tests {
    use super::{load_options, BuildOptions};
    use std::path::PathBuf;

    fn options() -> BuildOptions {
        BuildOptions {
            release: false,
            build_dir: PathBuf::from("build"),
            user_program: "shell".into(),
            kernel_test_scope: "none".into(),
            console_mirror: false,
            start_driver: String::new(),
            trace_driver_api: false,
            initial_process: String::new(),
            storage: String::new(),
            display: String::new(),
            windows_dir: None,
            pnp_root: String::new(),
            kd: String::new(),
        }
    }

    /// O bloco que o build grava é o que o kernel lê (`load_options.rs`,
    /// o mesmo arquivo dos dois lados).
    #[test]
    fn the_kernel_reads_the_block_the_build_writes() {
        let plain = options().load_options_block().unwrap();
        assert_eq!(load_options::text_of(&plain), Some(""));
        let mut options = options();
        options.kd = "com2".into();
        options.kernel_test_scope = "all".into();
        options.start_driver = "NDIS,AFD".into();
        options.initial_process = "smss".into();
        options.display = "basic".into();
        options.trace_driver_api = true;
        options.console_mirror = true;
        let block = options.load_options_block().unwrap();
        assert_eq!(block.len(), load_options::BLOCK_SIZE);
        let text = load_options::text_of(&block).unwrap();
        assert_eq!(text, "DEBUG DEBUGPORT=COM2 KERNELTESTSCOPE=all STARTDRIVER=NDIS,AFD INITIALPROCESS=smss DISPLAY=basic TRACEDRIVERAPI CONSOLEMIRROR");
        assert!(load_options::flag(text, load_options::DEBUG) && load_options::flag(text, "consolemirror"));
        assert_eq!(load_options::value(text, load_options::START_DRIVER), Some("NDIS,AFD"));
        assert_eq!(load_options::value(text, load_options::STORAGE), None);
        assert!(!load_options::flag(text, load_options::DEBUG_PORT));
        // Bloco sem assinatura, tamanho fora do setor e texto fora do ASCII
        // imprimível: o kernel segue sem opções.
        let mut broken = block.clone();
        broken[0] ^= 1;
        assert_eq!(load_options::text_of(&broken), None);
        let mut broken = block.clone();
        broken[4..8].copy_from_slice(&600u32.to_le_bytes());
        assert_eq!(load_options::text_of(&broken), None);
        let mut broken = block;
        broken[9] = 0x0A;
        assert_eq!(load_options::text_of(&broken), None);
        // Um valor com espaço viraria duas opções.
        options.start_driver = "NDIS AFD".into();
        assert!(options.load_options_block().is_err());
    }

    /// As opções de boot não mudam as imagens; o volume do smss e o
    /// `--release` mudam.
    #[test]
    fn boot_options_share_the_images() {
        let base = options();
        let mut driver = options();
        driver.start_driver = "ksecdd".into();
        driver.kd = "com2".into();
        driver.build_dir = PathBuf::from("build/kd");
        assert_eq!(base.image_key(), driver.image_key());
        let mut smss = options();
        smss.initial_process = "smss".into();
        assert_ne!(base.image_key(), smss.image_key());
        assert_eq!(base.kernel_key(), smss.kernel_key());
        let mut release = options();
        release.release = true;
        assert_ne!(base.kernel_key(), release.kernel_key());
    }
}
