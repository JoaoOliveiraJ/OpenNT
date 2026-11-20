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
/// Espaço livre do volume NTFS do boot do smss, em MiB: o máximo do arquivo
/// de paginação (`cm/session_manager.rs`), os 256 MB do `C:\swapfile.sys`
/// que o smss cria no volume do sistema, os 256 MB que a extensão do
/// arquivo de paginação sempre deixa livres no volume
/// (`mm/paging_file/extend.rs`) e folga para o resto do boot.
const SMSS_FREE_SPACE_MIB: usize = 800;
/// Os binários do Windows do bundle, para todo build (`--windows-dir` troca):
/// o caminho entra no build do kernel, então uma pasta só faz builds com
/// `--build-dir` diferentes reaproveitarem o mesmo kernel compilado.
pub const WINDOWS_DIR: &str = "build/windows";
/// O disco do controlador NVMe (`--storage=nvme`), ao lado do `os.img`.
pub const NVME_IMAGE: &str = "nvme.img";
/// O arquivo de texto do volume NVMe, que o teste lê pelo ntfs.sys.
const NVME_FILE: &str = "NVME.TXT";
const NVME_FILE_DATA: &[u8] = b"Volume NTFS no disco NVMe do OpenNT.\r\n";

/// As opções de um build. As de boot (do `user_program` ao `usb`, menos o
/// `release`, o `build_dir` e o `windows_dir`) não mudam o kernel compilado:
/// vão no bloco de opções de carga da imagem ([`BuildOptions::load_options`]).
#[derive(Clone, Debug)]
pub struct BuildOptions {
    pub release: bool,
    /// O perfil `depuracao` (o DWARF completo do kernel, com tipos e
    /// variáveis locais): o do `cargo xtask debug` e dos depuradores
    /// gráficos. Sem ele, o `dev` leva só as tabelas de linha.
    pub full_debuginfo: bool,
    pub build_dir: PathBuf,
    pub user_program: String,
    pub kernel_test_scope: String,
    pub console_mirror: bool,
    /// `--start-driver=NOME[,NOME...]`: serviços iniciados pelo SCM antes do
    /// programa, na ordem dada.
    pub start_driver: String,
    /// `--trace-driver-api`: rastreia as APIs chamadas durante esse início.
    pub trace_driver_api: bool,
    /// `--trace-rpc`: uma linha na serial por mensagem ALPC das portas de
    /// servidor, com a interface e o opnum dos pedidos LRPC.
    pub trace_rpc: bool,
    /// `--heap-census`: o censo do heap do kernel na serial a cada 4 MB a
    /// mais de uso (`hal::heap_census`).
    pub heap_census: bool,
    /// `--slow-service-exit`: toda saída de serviço passa pelo despachante
    /// (sem a volta direta ao anel 3, o KiSystemServiceExit, que é o padrão).
    pub slow_service_exit: bool,
    /// `--initial-process=smss`: o kernel inicia o smss.exe real como o
    /// primeiro processo de usuário (vazio = o boot comum).
    pub initial_process: String,
    /// `--storage=real`: a pilha de armazenamento do Windows sobe pelo PnP
    /// na controladora IDE. `--storage=nvme`: o QEMU ganha um controlador
    /// NVMe com o `nvme.img` e o storport.sys com o stornvme.sys sobem nele.
    pub storage: String,
    /// `--display=basic`: o PnP instala o BasicDisplay.sys real no adaptador
    /// VGA e o inicia sobre o dxgkrnl.sys real.
    pub display: String,
    /// `--windows-dir=DIR`: pasta dos binários do Windows copiados para o
    /// bundle do kernel (padrão [`WINDOWS_DIR`]). Builds que dividem a pasta
    /// não recompilam o kernel só porque o caminho dela mudou.
    pub windows_dir: Option<PathBuf>,
    /// `--pnp-root=acpi|internal`: a raiz da árvore de dispositivos é o
    /// acpi.sys real sobre o dispositivo ACPI da HAL, com o pci.sys real no
    /// barramento PCI (o padrão, vazio ou `acpi`), ou o barramento PCI
    /// interno do kernel (`internal`).
    pub pnp_root: String,
    /// `--kd=com2`: o depurador do kernel nessa porta serial (vazio = sem
    /// depurador).
    pub kd: String,
    /// `--shutdown-test=poweroff|reboot`: o teste do desligamento depois do
    /// `--start-driver=ntfs` (vazio = sem o teste).
    pub shutdown_test: String,
    /// `--usb`: a máquina ganha a controladora xHCI com teclado e tablet USB
    /// e o PnP sobe a pilha USB 3 e HID do Windows sobre ela.
    pub usb: bool,
    /// `--net`: a máquina ganha a placa de rede e1000 com a rede de modo
    /// usuário do QEMU e o PnP sobe nela o miniport da Intel com o NDIS e o
    /// TCP/IP do Windows.
    pub net: bool,
    /// `--memory-pressure`: o teste de pressão de memória sobre o arquivo de
    /// paginação do boot do smss.
    pub memory_pressure: bool,
    /// `--tpm`: a máquina ganha um TPM 2.0 (tpm-crb sobre o simulador) e o
    /// PnP sobe o tpm.sys real nele.
    pub tpm: bool,
    /// `--conta-de-teste`: o volume do boot do smss leva em `SYSTEM\Setup` o
    /// gancho de primeiro boot que cria a conta local de teste
    /// (`test_account`). Muda a hive SYSTEM, não o kernel nem as opções de
    /// carga.
    pub test_account: bool,
    /// `--desligar-contas-embutidas` (e o `run` do boot do smss): o volume do
    /// boot do smss leva em `SYSTEM\Setup` o gancho de primeiro boot que só
    /// desabilita o Administrador e o Convidado internos
    /// (`test_account::builtin_accounts_command`), o estado em que eles chegam
    /// numa instalação nova (o modelo de segurança `defltbase.inf` do Setup,
    /// EnableAdminAccount e EnableGuestAccount 0). Só nas execuções que chegam
    /// à tela de credenciais: os testes que param na tela de bloqueio não
    /// pagam o cmd.exe e o net.exe do primeiro boot.
    pub builtin_accounts_off: bool,
    /// `--console-process`: no boot comum, o kernel roda o cmd.exe real com
    /// um console sem janela (o teste console-processo). Também muda o
    /// volume NTFS, que leva os programas de modo usuário do boot do smss
    /// (o cmd.exe, o conhost.exe e as DLLs deles); o kernel é o mesmo.
    pub console_process: bool,
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
            (name::SHUTDOWN_TEST, self.shutdown_test.as_str()),
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
        if self.trace_rpc {
            words.push(String::from(name::TRACE_RPC));
        }
        if self.heap_census {
            words.push(String::from(name::HEAP_CENSUS));
        }
        if self.slow_service_exit {
            words.push(String::from(name::SLOW_SERVICE_EXIT));
        }
        if self.console_mirror {
            words.push(String::from(name::CONSOLE_MIRROR));
        }
        if self.usb {
            words.push(String::from(name::USB));
        }
        if self.net {
            words.push(String::from(name::NET));
        }
        if self.memory_pressure {
            words.push(String::from(name::MEMORY_PRESSURE));
        }
        if self.tpm {
            words.push(String::from(name::TPM));
        }
        if self.console_process {
            words.push(String::from(name::CONSOLE_PROCESS));
        }
        Ok(words.join(" "))
    }

    /// O perfil do cargo: `release`, `depuracao` (o DWARF completo) ou `dev`.
    pub fn cargo_profile(&self) -> &'static str {
        if self.release {
            "release"
        } else if self.full_debuginfo {
            "depuracao"
        } else {
            "dev"
        }
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
            trace_rpc: false,
            heap_census: false,
            slow_service_exit: false,
            storage: String::new(),
            display: String::new(),
            pnp_root: String::new(),
            kd: String::new(),
            shutdown_test: String::new(),
            usb: false,
            net: false,
            memory_pressure: false,
            tpm: false,
            // O `console_process` e o `test_account` ficam: eles também mudam o
            // volume NTFS.
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
        options.console_process = false;
        options.test_account = false;
        options.builtin_accounts_off = false;
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
    let profile = options.cargo_profile();
    if profile != "dev" {
        command.args(["--profile", profile]);
    }
    match windows_binaries {
        Some(directory) => command.env("OPENNT_WINDOWS_BINARIES", directory),
        None => command.env_remove("OPENNT_WINDOWS_BINARIES"),
    };
    run(&mut command)?;
    // A pasta do perfil `dev` se chama `debug`.
    let profile = if profile == "dev" { "debug" } else { profile };
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
    // O volume do `--console-process` leva os programas de modo usuário do
    // boot do smss (o cmd.exe, o conhost.exe e as DLLs deles); as hives e o
    // espaço livre seguem os do boot comum.
    let staged_programs = if options.console_process { "smss" } else { options.initial_process.as_str() };
    let staged = crate::windows_binaries::ntfs_files(&root, &kernel_pe, staged_programs)?;
    // A origem daqui de cada arquivo, para o descritor de segurança dele
    // (`host_security::system_nodes`); um arquivo gerado não tem origem.
    let mut origins: Vec<(String, Option<std::path::PathBuf>)> = staged.iter().map(|file| (file.path.clone(), file.host.clone())).collect();
    let mut ntfs_files: Vec<(String, Vec<u8>)> = staged.into_iter().map(|file| (file.path, file.bytes)).collect();
    // O gancho de primeiro boot do `--conta-de-teste`, com os nomes do
    // samsrv.dll.mui do idioma do convidado.
    // Sem a conta, o `--desligar-contas-embutidas` só desabilita as contas
    // embutidas, com o mesmo gancho.
    let setup_command = if options.test_account {
        Some(crate::test_account::setup_command(&crate::test_account::builtin_names()?)?)
    } else if options.builtin_accounts_off && options.initial_process == "smss" {
        Some(crate::test_account::builtin_accounts_command(&crate::test_account::builtin_names()?)?)
    } else {
        None
    };
    if let Some(command) = &setup_command {
        let what = if options.test_account { format!("conta de teste {}", crate::test_account::ACCOUNT_NAME) } else { String::from("contas embutidas desligadas") };
        println!("{what}: gancho de primeiro boot em SYSTEM\\Setup ({} caracteres)", command.encode_utf16().count());
    }
    // As hives de máquina que o kernel carrega no boot, das tabelas de
    // semente dele.
    for (name, image) in crate::hive_image::machine_hives(options.initial_process == "smss", setup_command.as_deref()) {
        let path = format!("Windows/System32/config/{name}");
        origins.push((path.clone(), None));
        ntfs_files.push((path, image));
    }
    // No boot do smss, os perfis de usuário de uma instalação nova
    // (`user_profiles`): `\Users`, o perfil padrão e o público, com os
    // atributos e os descritores de cada pasta e arquivo. As junções do
    // perfil ficam listadas em `juncoes.txt` até o volume levar pontos de
    // reanálise.
    let mut nodes = Vec::new();
    if options.initial_process == "smss" {
        let profiles = crate::user_profiles::stage();
        let folders = profiles.nodes.iter().filter(|node| node.directory).count();
        println!("perfis de usuario no volume NTFS: {folders} pastas e {} arquivos; juncoes pendentes: {} (juncoes.txt)", profiles.files.len(), profiles.junctions.len());
        let report = build_dir.join("juncoes.txt");
        fs::write(&report, crate::user_profiles::junction_report(&profiles.junctions)).map_err(|error| format!("{}: {error}", report.display()))?;
        ntfs_files.extend(profiles.files);
        nodes = profiles.nodes;
    }
    // Os descritores de segurança dos arquivos do Windows desta máquina
    // (sem SID de conta), a raiz com o de System32 e, no boot do smss, as
    // pastas vazias de uma instalação nova que a cadeia usa. Os perfis
    // ficam com os nós deles.
    let security = crate::host_security::system_nodes(&origins, &nodes, options.initial_process == "smss");
    println!("descritores dos arquivos do Windows no volume NTFS: {} nos ({} pastas), raiz {}", security.nodes.len(), security.nodes.iter().filter(|node| node.directory).count(), if security.root.is_some() { "com o descritor de System32" } else { "com o descritor comum" });
    nodes.extend(security.nodes);
    // O boot do smss cria o arquivo de paginação do `PagingFiles` (192 MB a
    // 256 MB em D:): o volume dele tem espaço livre para o arquivo crescer
    // até o máximo.
    let free_space_mib = if options.initial_process == "smss" { SMSS_FREE_SPACE_MIB } else { 32 };
    let ntfs_bytes = crate::ntfs_image::build(&ntfs_path, &ntfs_files, &nodes, security.root.as_deref(), free_space_mib, 256)?;
    // O disco do controlador NVMe do QEMU, particionado, com um volume NTFS
    // próprio: montado em todo build (a opção de carga `--storage=nvme`
    // não muda as imagens), ligado só às máquinas com a opção.
    let files = [(String::from(NVME_FILE), NVME_FILE_DATA.to_vec())];
    crate::ntfs_image::build_partitioned(&build_dir.join(NVME_IMAGE), &files, 16, 64)?;

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
            full_debuginfo: false,
            build_dir: PathBuf::from("build"),
            user_program: "shell".into(),
            kernel_test_scope: "none".into(),
            console_mirror: false,
            start_driver: String::new(),
            trace_driver_api: false,
            trace_rpc: false,
            heap_census: false,
            slow_service_exit: false,
            initial_process: String::new(),
            storage: String::new(),
            display: String::new(),
            windows_dir: None,
            pnp_root: String::new(),
            kd: String::new(),
            shutdown_test: String::new(),
            usb: false,
            net: false,
            memory_pressure: false,
            tpm: false,
            console_process: false,
            test_account: false,
            builtin_accounts_off: false,
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
        options.trace_rpc = true;
        options.heap_census = true;
        options.console_mirror = true;
        options.shutdown_test = "reboot".into();
        options.usb = true;
        options.net = true;
        options.tpm = true;
        let block = options.load_options_block().unwrap();
        assert_eq!(block.len(), load_options::BLOCK_SIZE);
        let text = load_options::text_of(&block).unwrap();
        assert_eq!(text, "DEBUG DEBUGPORT=COM2 KERNELTESTSCOPE=all STARTDRIVER=NDIS,AFD INITIALPROCESS=smss DISPLAY=basic SHUTDOWNTEST=reboot TRACEDRIVERAPI TRACERPC HEAPCENSUS CONSOLEMIRROR USB NET TPM");
        assert!(load_options::flag(text, load_options::DEBUG) && load_options::flag(text, "consolemirror") && load_options::flag(text, load_options::USB) && load_options::flag(text, load_options::NET) && load_options::flag(text, load_options::TPM));
        assert!(load_options::flag(text, load_options::TRACE_RPC) && load_options::flag(text, "tracerpc") && load_options::flag(text, load_options::HEAP_CENSUS));
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
        driver.usb = true;
        driver.net = true;
        driver.tpm = true;
        driver.trace_rpc = true;
        driver.heap_census = true;
        driver.build_dir = PathBuf::from("build/kd");
        assert_eq!(base.image_key(), driver.image_key());
        let mut smss = options();
        smss.initial_process = "smss".into();
        assert_ne!(base.image_key(), smss.image_key());
        assert_eq!(base.kernel_key(), smss.kernel_key());
        // O processo de console muda o volume (os programas do smss), não o
        // kernel, e vai nas opções de carga.
        let mut console = options();
        console.console_process = true;
        assert_ne!(base.image_key(), console.image_key());
        assert_ne!(smss.image_key(), console.image_key());
        assert_eq!(base.kernel_key(), console.kernel_key());
        assert_eq!(console.load_options().unwrap(), "CONSOLEPROCESS");
        // A conta de teste muda só a hive SYSTEM do volume do smss.
        let mut account = options();
        account.initial_process = "smss".into();
        account.test_account = true;
        assert_ne!(smss.image_key(), account.image_key());
        assert_eq!(base.kernel_key(), account.kernel_key());
        assert_eq!(smss.load_options().unwrap(), account.load_options().unwrap());
        let mut release = options();
        release.release = true;
        assert_ne!(base.kernel_key(), release.kernel_key());
        // O DWARF completo do `debug` é outro kernel compilado.
        let mut full = options();
        full.full_debuginfo = true;
        assert_ne!(base.kernel_key(), full.kernel_key());
        assert_eq!((base.cargo_profile(), full.cargo_profile(), release.cargo_profile()), ("dev", "depuracao", "release"));
    }
}
