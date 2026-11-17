//! Os assemblies lado a lado (WinSxS) desta instalação que o csrss real usa
//! no boot do processo inicial real (`--initial-process=smss`).
//!
//! No primeiro CreateProcessW de um programa Win32 (o services.exe que o
//! wininit.exe cria), o BaseSrvSxsCreateProcess do sxssrv.dll gera o
//! contexto de ativação padrão do sistema: o sxs.dll resolve o assembly
//! `Microsoft.Windows.SystemCompatible` (amd64) pela chave
//! `SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide\Winners`, lê o
//! manifesto da versão vencedora em `\Windows\WinSxS\Manifests` e resolve do
//! mesmo jeito as dependências obrigatórias dele
//! (`Microsoft.Windows.IsolationAutomation` e o
//! `Microsoft.Windows.IsolationAutomation.ProxyStub`). Sem eles, o sxs.dll
//! devolve STATUS_SXS_CANT_GEN_ACTCTX e o csrss encerra o processo novo.
//!
//! O LogonUI.exe e o dwm.exe da tela de logon (e o authui.dll e outras
//! DLLs dela) trazem no RT_MANIFEST a dependência do
//! `Microsoft.Windows.Common-Controls` 6.0: sem o assembly, o contexto de
//! ativação do processo não é gerado e o csrss encerra o processo novo.
//! Com ele, o user32 carrega o comctl32.dll da versão 6 de WinSxS para as
//! classes de janela que o manifesto redireciona.
//!
//! Como os binários de System32, os dados vêm desta máquina no build: a
//! subchave de Winners de cada assembly (com as versões vencedoras), os
//! manifestos dessas versões e os arquivos que eles listam (`<file
//! name=...>`, na pasta do componente em WinSxS), com os nomes e os valores
//! daqui. As dependências opcionais (`optional="yes"`) ficam de fora: sem a
//! chave de Winners, o sxs.dll as pula. Fora do Windows nada é copiado.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::host_language::HostKey;

/// As raízes da resolução (nome em minúsculas e token de chave pública): o
/// assembly do contexto de ativação padrão do sistema e os controles comuns
/// que os manifestos dos programas da tela de logon pedem.
const ROOTS: &[(&str, &str)] = &[("microsoft.windows.systemcompatible", "6595b64144ccf1df"), ("microsoft.windows.common-controls", "6595b64144ccf1df")];

/// A chave de Winners relativa à raiz da hive SOFTWARE.
const WINNERS: &str = "Microsoft\\Windows\\CurrentVersion\\SideBySide\\Winners";

/// Os assemblies resolvidos: as chaves copiadas e os arquivos (caminho no
/// volume, arquivo de origem): os manifestos e os arquivos deles.
struct Resolved {
    keys: Vec<HostKey>,
    files: Vec<(String, PathBuf)>,
}

/// O nome do assembly nos nomes de WinSxS: até 40 caracteres inteiro; acima
/// disso, os 19 primeiros, `..` e os 19 últimos.
fn abbreviated(name: &str) -> String {
    let characters: Vec<char> = name.chars().collect();
    if characters.len() <= 40 {
        return String::from(name);
    }
    let head: String = characters[..19].iter().collect();
    let tail: String = characters[characters.len() - 19..].iter().collect();
    format!("{head}..{tail}")
}

/// O valor do atributo `name` dentro de um elemento XML.
fn attribute(element: &str, name: &str) -> Option<String> {
    let start = element.find(&format!(" {name}=\""))? + name.len() + 3;
    let end = element[start..].find('"')? + start;
    Some(String::from(&element[start..end]))
}

/// As dependências obrigatórias de amd64 de um manifesto: (nome em
/// minúsculas, token).
fn dependencies(manifest: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for block in manifest.split("<dependency").skip(1) {
        let block = block.split("</dependency>").next().unwrap_or("");
        let header = block.split('>').next().unwrap_or("");
        if attribute(header, "optional").is_some_and(|value| value.eq_ignore_ascii_case("yes")) {
            continue;
        }
        let Some(identity) = block.split("<assemblyIdentity").nth(1).and_then(|rest| rest.split('>').next()) else { continue };
        let architecture = attribute(identity, "processorArchitecture").unwrap_or_default();
        if !(architecture.eq_ignore_ascii_case("amd64") || architecture == "*") {
            continue;
        }
        if let (Some(name), Some(token)) = (attribute(identity, "name"), attribute(identity, "publicKeyToken")) {
            found.push((name.to_lowercase(), token.to_lowercase()));
        }
    }
    found
}

/// Os arquivos que um manifesto lista (`<file name="...">`).
fn payload(manifest: &str) -> Vec<String> {
    manifest
        .split("<file")
        .skip(1)
        .filter(|element| element.starts_with(char::is_whitespace))
        .filter_map(|element| attribute(element.split('>').next().unwrap_or(""), "name"))
        .collect()
}

/// Os assemblies de [`ROOTS`] e as dependências obrigatórias deles, com as
/// chaves de Winners, os manifestos e os arquivos desta máquina.
fn resolve(windows: &Path) -> Resolved {
    let mut resolved = Resolved { keys: Vec::new(), files: Vec::new() };
    #[cfg(windows)]
    {
        use crate::host_language::registry;
        let host = format!("SOFTWARE\\{WINNERS}");
        let winners = registry::list(registry::LOCAL_MACHINE, &host);
        let directory = windows.join("WinSxS").join("Manifests");
        let files: Vec<String> = std::fs::read_dir(&directory).map(|entries| entries.filter_map(|entry| entry.ok()).filter_map(|entry| entry.file_name().into_string().ok()).collect()).unwrap_or_default();
        let mut pending: Vec<(String, String)> = ROOTS.iter().map(|(name, token)| (String::from(*name), String::from(*token))).collect();
        let mut seen = BTreeSet::new();
        while let Some((name, token)) = pending.pop() {
            let prefix = format!("amd64_{}_{token}_none_", abbreviated(&name));
            if !seen.insert(prefix.clone()) {
                continue;
            }
            let Some(key) = winners.iter().find(|candidate| candidate.to_lowercase().starts_with(&prefix)) else { continue };
            let mut keys = Vec::new();
            registry::copy(registry::LOCAL_MACHINE, &format!("{host}\\{key}"), &format!("{WINNERS}\\{key}"), true, &mut keys);
            // As versões vencedoras: o valor padrão de cada subchave M.m.
            let versions: Vec<String> = keys.iter().filter_map(|key| key.values.iter().find(|(value, kind, _)| value.is_empty() && *kind == 1).map(|(_, _, data)| String::from_utf16_lossy(&data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect::<Vec<u16>>()).trim_end_matches('\0').to_string())).collect();
            resolved.keys.extend(keys);
            for version in versions {
                let manifest = format!("amd64_{}_{token}_{version}_none_", abbreviated(&name));
                for file in files.iter().filter(|file| file.to_lowercase().starts_with(&manifest) && file.to_lowercase().ends_with(".manifest")) {
                    let source = directory.join(file);
                    // A pasta do componente tem o nome do manifesto sem a
                    // extensão.
                    let component = &file[..file.len() - ".manifest".len()];
                    if let Ok(text) = std::fs::read_to_string(&source) {
                        pending.extend(dependencies(&text));
                        for name in payload(&text) {
                            let payload = windows.join("WinSxS").join(component).join(&name);
                            if payload.is_file() {
                                resolved.files.push((format!("WinSxS/{component}/{name}"), payload));
                            }
                        }
                    }
                    // Como os outros subdiretórios do diretório do Windows
                    // que o modo usuário abre por `C:\Windows\...`, o WinSxS
                    // fica na raiz do volume.
                    resolved.files.push((format!("WinSxS/Manifests/{file}"), source));
                }
            }
        }
    }
    #[cfg(not(windows))]
    let _ = windows;
    resolved
}

/// As subchaves de Winners dos assemblies, inteiras, no caminho relativo à
/// raiz da hive SOFTWARE.
pub fn software_keys(windows: &Path) -> Vec<HostKey> {
    resolve(windows).keys
}

/// Os manifestos dos assemblies e os arquivos deles: (caminho no volume,
/// arquivo de origem).
pub fn assembly_files(windows: &Path) -> Vec<(String, PathBuf)> {
    let mut files = resolve(windows).files;
    files.sort();
    files.dedup();
    files
}
