//! Binários reais do Windows desta máquina, copiados no build (nunca ficam
//! no repositório), como o build original fazia.
//!
//! O hal.dll e as pilhas de teclado/mouse e de armazenamento entram no
//! bundle do kernel (a fase 0 os copia para o sistema de arquivos em
//! memória). O volume NTFS leva o cng.sys, a cadeia da CI (ci.dll, msrpc.sys
//! e a lista de revogação), os arquivos que o vgk.sys abre pelo caminho
//! completo, o PE do kernel e o próprio vgk.sys quando houver um: um
//! `vgk.sys` na raiz do repositório ou o caminho em `OPENNT_VGK_SYS`.

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
];

/// Arquivos do volume NTFS: (caminho no volume, origem no Windows).
const NTFS_FILES: &[(&str, &str)] = &[
    ("CNG.SYS", "System32/drivers/cng.sys"),
    // A CI original e a sua dependência, carregadas do volume.
    ("CI.DLL", "System32/ci.dll"),
    ("MSRPC.SYS", "System32/drivers/msrpc.sys"),
    // Esquema de API sets: os imports ext-ms-* das imagens de kernel.
    ("APISETSCHEMA.DLL", "System32/apisetschema.dll"),
    // A CI lê a lista de revogação pelo caminho completo.
    ("Windows/System32/CodeIntegrity/driver.stl", "System32/CodeIntegrity/driver.stl"),
    // Abertos pelo vgk.sys pelo caminho SystemRoot.
    ("Windows/System32/ntdll.dll", "System32/ntdll.dll"),
    ("Windows/System32/win32k.sys", "System32/win32k.sys"),
    ("Windows/System32/drivers/fltmgr.sys", "System32/drivers/fltmgr.sys"),
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
/// gerado (`NTOSKRNL.EXE` e o caminho canônico em System32).
pub fn ntfs_files(root: &Path, kernel_pe: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
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
    files.push((String::from("NTOSKRNL.EXE"), kernel_pe.to_vec()));
    files.push((String::from("Windows/System32/ntoskrnl.exe"), kernel_pe.to_vec()));
    Ok(files)
}
