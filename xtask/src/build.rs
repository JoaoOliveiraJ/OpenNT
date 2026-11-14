//! Build do OpenNT:
//!
//! 1. compila `boot` (setor de boot + stage2) e `kernel` para
//!    `x86_64-unknown-none`;
//! 2. extrai o binário plano do boot com `llvm-objcopy`;
//! 3. empacota o kernel ELF como PE32+ (`kernel_pe`);
//! 4. monta `os.img`: [setor 0: boot][LBA 1..64: stage2][LBA 65+: kernel] e
//!    grava o número de setores do kernel no header do stage2 (offset 3).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::kernel_pe;

pub const TARGET: &str = "x86_64-unknown-none";
const STAGE2_MAX: usize = 64 * 512; // reserva do stage2 na imagem (LBA 1..64)

#[derive(Clone, Debug)]
pub struct BuildOptions {
    pub release: bool,
    pub build_dir: PathBuf,
    pub user_program: String,
    pub kernel_test_scope: String,
    pub console_mirror: bool,
    /// `--start-driver=NOME`: serviço iniciado pelo SCM antes do programa.
    pub start_driver: String,
    /// `--trace-driver-api`: rastreia as APIs chamadas durante esse início.
    pub trace_driver_api: bool,
    /// `--initial-process=smss`: o kernel inicia o smss.exe real como o
    /// primeiro processo de usuário (vazio = o boot comum).
    pub initial_process: String,
}

pub struct BuildOutput {
    pub image: PathBuf,
}

pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
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
    command
        .env("OPENNT_USER_PROGRAM", &options.user_program)
        .env("OPENNT_KERNEL_TEST_SCOPE", &options.kernel_test_scope)
        .env("OPENNT_START_DRIVER", &options.start_driver)
        .env("OPENNT_INITIAL_PROCESS", &options.initial_process);
    if options.trace_driver_api {
        command.env("OPENNT_TRACE_DRIVER_API", "1");
    } else {
        command.env_remove("OPENNT_TRACE_DRIVER_API");
    }
    if options.console_mirror {
        command.env("OPENNT_CONSOLE_MIRROR", "1");
    } else {
        command.env_remove("OPENNT_CONSOLE_MIRROR");
    }
    match windows_binaries {
        Some(directory) => command.env("OPENNT_WINDOWS_BINARIES", directory),
        None => command.env_remove("OPENNT_WINDOWS_BINARIES"),
    };
    run(&mut command)?;
    let profile = if options.release { "release" } else { "debug" };
    Ok(root.join("target").join(TARGET).join(profile).join(package))
}

pub fn build(options: &BuildOptions) -> Result<BuildOutput, String> {
    let root = workspace_root();
    let build_dir = if options.build_dir.is_absolute() {
        options.build_dir.clone()
    } else {
        root.join(&options.build_dir)
    };
    fs::create_dir_all(&build_dir).map_err(|error| format!("{}: {error}", build_dir.display()))?;

    // Binários reais do Windows desta máquina, copiados antes do kernel que
    // os embute no bundle.
    let windows_dir = build_dir.join("windows");
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
    if stage2.len() > STAGE2_MAX {
        return Err(format!("stage2 maior que a reserva de 32KB ({} bytes)", stage2.len()));
    }

    // ---- kernel: ELF -> PE32+ -------------------------------------------------
    let elf = fs::read(&kernel_elf).map_err(|error| format!("{}: {error}", kernel_elf.display()))?;
    fs::copy(&kernel_elf, build_dir.join("kernel.elf")).map_err(|error| error.to_string())?;
    let mut kernel = kernel_pe::build_kernel_pe(&elf)?;
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
    let image_path = build_dir.join("os.img");
    fs::write(&image_path, &image).map_err(|error| format!("{}: {error}", image_path.display()))?;
    // Segundo disco IDE (mestre-escravo primário): o volume NTFS de dados.
    let ntfs_path = build_dir.join("ntfs.img");
    let ntfs_bytes = crate::ntfs_image::build(&ntfs_path, &crate::windows_binaries::ntfs_files(&root, &kernel_pe, &options.initial_process)?, 32, 256)?;

    println!(
        "OK: {}  (kernel {}b/{} setores, NTFS {}MB, programa {}, testes {})",
        image_path.strip_prefix(&root).unwrap_or(&image_path).display(),
        kernel.len(),
        kernel_sectors,
        ntfs_bytes / 1_048_576,
        options.user_program,
        options.kernel_test_scope
    );
    Ok(BuildOutput { image: image_path })
}
