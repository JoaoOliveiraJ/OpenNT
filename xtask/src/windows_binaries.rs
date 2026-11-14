//! Binários reais do Windows desta máquina, copiados no build (nunca ficam
//! no repositório).
//!
//! O hal.dll, as pilhas de teclado/mouse e de armazenamento e as bibliotecas
//! de export que elas importam (wmilib.sys e WppRecorder.sys) entram no
//! bundle do kernel (a fase 0 os copia para o sistema de arquivos em
//! memória). O volume NTFS leva o cng.sys, a cadeia da CI (ci.dll, msrpc.sys
//! e a lista de revogação), o runtime do KMDF com um cliente (WdfLdr.sys,
//! Wdf01000.sys, SleepStudyHelper.sys e msisadrv.sys) e os catálogos que os
//! assinam, os arquivos que o vgk.sys abre pelo caminho
//! completo, o PE do kernel e o próprio vgk.sys quando houver um: um
//! `vgk.sys` na raiz do repositório ou o caminho em `OPENNT_VGK_SYS`.
//!
//! Com `--initial-process=smss`, o volume leva também os programas de modo
//! usuário que o smss.exe real e o csrss.exe real carregam, na raiz (o
//! `C:\Windows\System32` que o modo usuário vê): os dois executáveis, as
//! DLLs de servidor do csrss e o fecho dos imports delas (estáticos e pelos
//! API sets do apisetschema.dll desta máquina).

use std::fs;
use std::path::{Path, PathBuf};

/// Imagens do bundle, relativas ao diretório do Windows.
const BUNDLED: &[&str] = &[
    "System32/hal.dll",
    "System32/drivers/kbdclass.sys",
    "System32/drivers/i8042prt.sys",
    "System32/drivers/mouclass.sys",
    "System32/drivers/ataport.sys",
    "System32/drivers/atapi.sys",
    "System32/drivers/disk.sys",
    "System32/drivers/classpnp.sys",
    "System32/drivers/mountmgr.sys",
    "System32/drivers/wmilib.sys",
    "System32/drivers/WppRecorder.sys",
    "System32/drivers/watchdog.sys",
];

/// Arquivos do volume NTFS: (caminho no volume, origem no Windows).
const NTFS_FILES: &[(&str, &str)] = &[
    ("CNG.SYS", "System32/drivers/cng.sys"),
    // O núcleo gráfico (DXGKrnl), iniciado por `--start-driver=DXGKrnl`.
    ("DXGKRNL.SYS", "System32/drivers/dxgkrnl.sys"),
    // A CI original e a sua dependência, carregadas do volume.
    ("CI.DLL", "System32/ci.dll"),
    ("MSRPC.SYS", "System32/drivers/msrpc.sys"),
    // Provedor dos contadores de desempenho (driver de boot) e o console, a
    // segurança do kernel e a pilha de rede (com as bibliotecas de export
    // que importam), iniciados sob demanda (`--start-driver`).
    ("PCW.SYS", "System32/drivers/pcw.sys"),
    ("CONDRV.SYS", "System32/drivers/condrv.sys"),
    ("KSECDD.SYS", "System32/drivers/ksecdd.sys"),
    ("NETIO.SYS", "System32/drivers/netio.sys"),
    ("NDIS.SYS", "System32/drivers/ndis.sys"),
    ("TCPIP.SYS", "System32/drivers/tcpip.sys"),
    ("AFD.SYS", "System32/drivers/afd.sys"),
    ("FWPKCLNT.SYS", "System32/drivers/fwpkclnt.sys"),
    ("TDI.SYS", "System32/drivers/tdi.sys"),
    ("FLTMGR.SYS", "System32/drivers/fltmgr.sys"),
    // Esquema de API sets: os imports ext-ms-* das imagens de kernel.
    ("APISETSCHEMA.DLL", "System32/apisetschema.dll"),
    // A CI lê a lista de revogação pelo caminho completo.
    ("Windows/System32/CodeIntegrity/driver.stl", "System32/CodeIntegrity/driver.stl"),
    // Catálogo de assinatura da Microsoft que cobre o watchdog.sys e o
    // dxgkrnl.sys (drivers inbox são assinados por catálogo, não embutido): a
    // ci.dll varre \SystemRoot\System32\CatRoot\{GUID}\*.cat e valida o hash da
    // imagem contra ele. O catálogo encadeia na Microsoft Root CA 2010, que a
    // ci.dll já conhece (a mesma raiz que valida o vgk.sys).
    (
        "Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package0510~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
        "System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package0510~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
    ),
    // O ntfs.sys real (`--start-driver=ntfs`) e o catálogo que o cobre.
    ("NTFS.SYS", "System32/drivers/ntfs.sys"),
    // KMDF: a WdfLdr.sys (biblioteca de import dos clientes), o runtime
    // Wdf01000.sys (carregado pela WdfLdr pela chave do serviço) e a
    // SleepStudyHelper.sys que ele importa; o msisadrv.sys é um cliente KMDF.
    // Os catálogos da Microsoft que os assinam: o 0516 (o mesmo do ntfs.sys)
    // assina a WdfLdr, o Wdf01000, a SleepStudyHelper e a WppRecorder; o
    // 0110, o msisadrv.
    ("WDFLDR.SYS", "System32/drivers/WdfLdr.sys"),
    ("WDF01000.SYS", "System32/drivers/Wdf01000.sys"),
    ("SLEEPSTUDYHELPER.SYS", "System32/drivers/SleepStudyHelper.sys"),
    ("MSISADRV.SYS", "System32/drivers/msisadrv.sys"),
    (
        "Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package0516~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
        "System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package0516~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
    ),
    (
        "Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package0110~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
        "System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/Microsoft-Windows-Client-Desktop-Required-Package0110~31bf3856ad364e35~amd64~~10.0.19041.6456.cat",
    ),
    // Abertos pelo vgk.sys pelo caminho SystemRoot.
    ("Windows/System32/ntdll.dll", "System32/ntdll.dll"),
    ("Windows/System32/win32k.sys", "System32/win32k.sys"),
    ("Windows/System32/drivers/fltmgr.sys", "System32/drivers/fltmgr.sys"),
];

/// Os programas de modo usuário do caminho do smss (`--initial-process=smss`):
/// smss.exe, csrss.exe, as DLLs de servidor (csrsrv, basesrv, winsrv com o
/// winsrvext, sxssrv) e o fecho dos imports delas, incluindo a ntdll; e os
/// file systems de pipes e mailslots (npfs.sys e msfs.sys, serviços de
/// System32\Drivers que o boot carrega antes do smss).
const SMSS_PROGRAMS: &[&str] = &[
    "drivers/npfs.sys",
    "drivers/msfs.sys",
    "smss.exe",
    "csrss.exe",
    "csrsrv.dll",
    "basesrv.dll",
    "winsrv.dll",
    "winsrvext.dll",
    "sxssrv.dll",
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "user32.dll",
    "win32u.dll",
    "gdi32.dll",
    "gdi32full.dll",
    "msvcp_win.dll",
    "ucrtbase.dll",
    "combase.dll",
    "rpcrt4.dll",
    "cfgmgr32.dll",
];

fn windows_directory() -> PathBuf {
    std::env::var("SystemRoot").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("C:/Windows"))
}

/// Copia as imagens do bundle para `output`; as ausentes ficam de fora com
/// aviso (o kernel registra a ausência ao carregá-las).
pub fn stage(output: &Path) -> Result<usize, String> {
    let windows = windows_directory();
    fs::create_dir_all(output).map_err(|error| format!("{}: {error}", output.display()))?;
    // Remove cópias de um build anterior que não pertencem mais à lista.
    if let Ok(entries) = fs::read_dir(output) {
        for entry in entries.filter_map(|entry| entry.ok()) {
            let _ = fs::remove_file(entry.path());
        }
    }
    let mut copied = 0;
    for relative in BUNDLED {
        let source = windows.join(relative);
        let name = Path::new(relative).file_name().unwrap_or_default();
        if !source.exists() {
            println!("AVISO: {} ausente no Windows desta maquina", source.display());
            continue;
        }
        fs::copy(&source, output.join(name)).map_err(|error| format!("{}: {error}", source.display()))?;
        copied += 1;
    }
    println!("binarios do Windows no bundle: {copied} de {}", BUNDLED.len());
    Ok(copied)
}

/// O vgk.sys: `OPENNT_VGK_SYS` ou `vgk.sys` na raiz do repositório.
fn vgk_source(root: &Path) -> Option<PathBuf> {
    std::env::var_os("OPENNT_VGK_SYS").map(PathBuf::from).or_else(|| Some(root.join("vgk.sys"))).filter(|path| path.is_file())
}

/// Arquivos do volume NTFS que existem nesta máquina, mais o PE do kernel
/// gerado (`NTOSKRNL.EXE` e o caminho canônico em System32) e, com
/// `initial_process == "smss"`, os programas de [`SMSS_PROGRAMS`].
pub fn ntfs_files(root: &Path, kernel_pe: &[u8], initial_process: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
    let windows = windows_directory();
    let mut files = Vec::new();
    let mut present = 0;
    for (name, relative) in NTFS_FILES {
        let source = windows.join(relative);
        if !source.exists() {
            println!("AVISO: {} ausente no Windows desta maquina", source.display());
            continue;
        }
        files.push((String::from(*name), fs::read(&source).map_err(|error| format!("{}: {error}", source.display()))?));
        present += 1;
    }
    println!("binarios do Windows no volume NTFS: {present} de {}", NTFS_FILES.len());
    match vgk_source(root) {
        Some(source) => {
            let bytes = fs::read(&source).map_err(|error| format!("{}: {error}", source.display()))?;
            println!("VGK.SYS no volume NTFS ({} bytes)", bytes.len());
            files.push((String::from("VGK.SYS"), bytes));
        }
        None => println!("AVISO: vgk.sys ausente (OPENNT_VGK_SYS ou vgk.sys na raiz) — volume sem o vgk"),
    }
    // Tabelas NLS reais na raiz (codepages, casing e normalização), como o
    // `C:\Windows\System32` que o kernel e a ntdll consultam.
    let system32 = windows.join("System32");
    let named = ["l_intl.nls", "locale.nls", "normnfc.nls", "normnfd.nls", "normnfkc.nls", "normnfkd.nls", "normidna.nls"];
    let mut tables: Vec<(String, PathBuf)> = fs::read_dir(&system32)
        .map(|entries| entries.filter_map(|entry| entry.ok()).map(|entry| entry.path()).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|path| {
            let name = path.file_name()?.to_str()?.to_lowercase();
            let codepage = name.strip_prefix("c_").and_then(|rest| rest.strip_suffix(".nls")).is_some_and(|digits| !digits.is_empty() && digits.chars().all(|character| character.is_ascii_digit()));
            (codepage || named.contains(&name.as_str())).then(|| (name.to_uppercase(), path))
        })
        .collect();
    tables.sort();
    tables.push((String::from("SORTDEFAULT.NLS"), windows.join("Globalization/Sorting/SortDefault.nls")));
    let mut nls = 0;
    for (name, source) in tables {
        if let Ok(bytes) = fs::read(&source) {
            files.push((name, bytes));
            nls += 1;
        }
    }
    println!("tabelas NLS no volume NTFS: {nls}");
    if initial_process == "smss" {
        let mut staged = 0;
        for name in SMSS_PROGRAMS {
            let source = system32.join(name);
            match fs::read(&source) {
                Ok(bytes) => {
                    // Na raiz, como o resto de System32 (e de System32\Drivers).
                    files.push((name.rsplit('/').next().unwrap_or(name).to_uppercase(), bytes));
                    staged += 1;
                }
                Err(_) => println!("AVISO: {} ausente no Windows desta maquina", source.display()),
            }
        }
        println!("programas de modo usuario do smss no volume NTFS: {staged} de {}", SMSS_PROGRAMS.len());
    }
    files.push((String::from("NTOSKRNL.EXE"), kernel_pe.to_vec()));
    files.push((String::from("Windows/System32/ntoskrnl.exe"), kernel_pe.to_vec()));
    Ok(files)
}
