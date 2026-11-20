//! O `Control\ProductOptions\ProductPolicy` do convidado: a política de
//! licença de uma instalação limpa e não ativada desta edição, nunca a desta
//! máquina.
//!
//! O valor que o sppsvc deixa numa instalação é a soma de duas origens:
//! - a política da edição, igual em toda instalação da mesma edição e build:
//!   as entradas das licenças de política do produto (PPD) da edição em
//!   `System32\spp\tokens\skus\<edição>` (`DefaultPpd-<edição>-ppdlic.xrm-ms`,
//!   prioridade 100, e `<edição>-ppdlic.xrm-ms`, prioridade 200), que o
//!   sppsvc consome em qualquer estado de ativação;
//! - o estado desta instalação, que o sppsvc, o sppwinob.dll e o ClipSp.sys
//!   gravam depois: o estado genuíno, a última ativação, as listas de
//!   identificadores contados, a licença por tempo e o histórico de
//!   identificadores de máquina ([`INSTALL_STATE`]).
//!
//! O convidado leva só a primeira, com os dados tirados das licenças da
//! edição (e não do valor desta máquina): o valor desta máquina dá apenas
//! os nomes que o sppsvc publica no kernel (ele não publica todas as
//! entradas `Security-SPP-Reserved-*` das licenças). Uma entrada que as
//! licenças não definem e que [`INSTALL_STATE`] e [`PRODUCT_LICENSE`] não
//! classificam fica de fora. As entradas de [`INSTALL_STATE`] ficam com o
//! valor de uma instalação nova que nunca foi ativada.

#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::BTreeMap;

/// Cabeçalho do valor: tamanho total, tamanho das entradas, tamanho do
/// marcador final, flags e versão (u32 cada).
const HEADER: usize = 0x14;
/// Cabeçalho de uma entrada: u16 tamanho, u16 tamanho do nome, u16 tipo,
/// u16 tamanho dos dados, u32 flags, u32 reservado; depois o nome (UTF-16,
/// sem NUL) e os dados.
const ENTRY_HEADER: usize = 0x10;
/// O marcador final (um DWORD) e a versão do formato que o kernel aceita.
const END_MARKER: u32 = 0x45;
const VERSION: u32 = 1;
/// O flag de entrada das políticas com o atributo `reboot-required`.
const REBOOT_REQUIRED: u32 = 2;

const REG_SZ: u16 = 1;
const REG_BINARY: u16 = 3;
const REG_DWORD: u16 = 4;

/// Uma entrada da política.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub name: String,
    pub kind: u16,
    pub data: Vec<u8>,
    pub flags: u32,
}

/// O valor limpo de uma entrada de [`INSTALL_STATE`].
#[derive(Clone, Copy, Debug, PartialEq)]
enum Clean {
    /// O valor padrão das licenças da edição (o de uma instalação que nunca
    /// passou pela ativação); sem ele nas licenças, a entrada sai.
    License,
    /// Um DWORD fixo.
    Dword(u32),
    /// Fora do convidado.
    Remove,
}

/// As entradas de estado da instalação (por instalação ou de ativação), com
/// quem as grava e o valor de uma instalação limpa e não ativada:
///
/// | Entrada | Quem grava | Valor no convidado |
/// |---|---|---|
/// | Security-SPP-GenuineLocalStatus | sppwinob.dll e ClipSp.sys, o estado genuíno | o da licença: 1 (SL_GEN_STATE_INVALID_LICENSE, não ativado) |
/// | Security-SPP-LastWindowsActivationTime | sppwinob.dll e ClipSp.sys, na ativação | o da licença: 8 bytes zero (nenhuma ativação) |
/// | Security-SPP-LastWindowsActivationHResult | sppwinob.dll e ClipSp.sys, na ativação | o da licença: 0xC004F012 (SL_E_VALUE_NOT_FOUND, nenhuma tentativa) |
/// | Security-SPP-Action-StateData | ClipSp.sys, no consumo da licença | o da licença, que é também o padrão embutido no ClipSp.sys |
/// | Security-SPP-IACountedIdList | ClipSp.sys, na ativação herdada | o da licença: vazio |
/// | Security-SPP-KmsCountedIdList | sppsvc e ClipSp.sys, na ativação por KMS | o da licença: vazio fora do canal de volume |
/// | Security-SPP-TokenActivation-AdditionalInfo | sppwinob.dll e ClipSp.sys, na ativação por token | o da licença: vazio |
/// | Security-SPP-Reserved-TBLState | sppwinob.dll, a licença por tempo | 0: sem licença por tempo o sppwinob grava 0 |
/// | Security-SPP-Reserved-TBLProductKeyType | sppwinob.dll, a licença por tempo | 0, pelo mesmo caminho |
/// | Security-SPP-Reserved-TBLRemainingTime | sppwinob.dll, a licença por tempo | 0, pelo mesmo caminho |
/// | 4A0C606B-2CE9-4A35-9B3E-A57D37F18632 | sppwinob.dll: acrescenta cada `Kernel-Session-Machine-Identifier` novo | removida: é o histórico das máquinas desta instalação, e o sppwinob do convidado cria a dele |
///
/// As outras entradas `Security-SPP-*` que o ClipSp.sys pode atualizar (as
/// contagens de rearme, `AllowOSReactivation`, `SharedLicense`,
/// `AzureImdsResponse` e as demais) são definidas pelas licenças da edição
/// e já recebem o valor delas pela regra geral.
const INSTALL_STATE: &[(&str, Clean)] = &[
    ("Security-SPP-GenuineLocalStatus", Clean::License),
    ("Security-SPP-LastWindowsActivationTime", Clean::License),
    ("Security-SPP-LastWindowsActivationHResult", Clean::License),
    ("Security-SPP-Action-StateData", Clean::License),
    ("Security-SPP-IACountedIdList", Clean::License),
    ("Security-SPP-KmsCountedIdList", Clean::License),
    ("Security-SPP-TokenActivation-AdditionalInfo", Clean::License),
    ("Security-SPP-Reserved-TBLState", Clean::Dword(0)),
    ("Security-SPP-Reserved-TBLProductKeyType", Clean::Dword(0)),
    ("Security-SPP-Reserved-TBLRemainingTime", Clean::Dword(0)),
    ("4A0C606B-2CE9-4A35-9B3E-A57D37F18632", Clean::Remove),
];

/// As entradas da edição que vêm da licença de produto do canal e não das
/// licenças PPD, com o valor, igual nas licenças de produto e de uso de
/// todos os canais (varejo, OEM e volume).
const PRODUCT_LICENSE: &[(&str, u32)] = &[("Security-SPP-WriteWauMarker", 1)];

/// Uma política das licenças, já no formato da entrada.
#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    pub kind: u16,
    pub data: Vec<u8>,
    pub flags: u32,
    priority: u32,
    sum: bool,
}

/// O que [`clean`] fez com as entradas desta máquina (só nomes).
#[derive(Debug, Default, PartialEq)]
pub struct Report {
    /// Entradas que as licenças e as tabelas não classificam: fora.
    pub unknown: Vec<String>,
    /// Entradas fora de [`INSTALL_STATE`] cujos dados aqui diferem dos da
    /// licença (o convidado leva os da licença).
    pub replaced: Vec<String>,
}

fn word(bytes: &[u8], at: usize) -> usize {
    u16::from_le_bytes([bytes[at], bytes[at + 1]]) as usize
}

fn dword(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// As entradas de um valor ProductPolicy; `None` se o formato não fecha.
pub fn entries(blob: &[u8]) -> Option<Vec<Entry>> {
    if blob.len() < HEADER {
        return None;
    }
    let (total, values, marker) = (dword(blob, 0) as usize, dword(blob, 4) as usize, dword(blob, 8) as usize);
    if total != blob.len() || dword(blob, 16) != VERSION || HEADER.checked_add(values)?.checked_add(marker)? != total {
        return None;
    }
    let end = HEADER + values;
    let (mut at, mut list) = (HEADER, Vec::new());
    while at < end {
        if at + ENTRY_HEADER > end {
            return None;
        }
        let (size, name_size, kind, data_size) = (word(blob, at), word(blob, at + 2), word(blob, at + 4) as u16, word(blob, at + 6));
        if size < ENTRY_HEADER + name_size + data_size || at + size > end || name_size % 2 != 0 {
            return None;
        }
        let units: Vec<u16> = blob[at + ENTRY_HEADER..at + ENTRY_HEADER + name_size].chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
        let data_at = at + ENTRY_HEADER + name_size;
        list.push(Entry { name: String::from_utf16_lossy(&units), kind, data: blob[data_at..data_at + data_size].to_vec(), flags: dword(blob, at + 8) });
        at += size;
    }
    Some(list)
}

/// O valor ProductPolicy com `entries` na ordem dada: cada entrada com um
/// WCHAR nulo depois dos dados e alinhada a 4 bytes, como o sppsvc grava,
/// e o marcador final.
pub fn blob(entries: &[Entry]) -> Vec<u8> {
    let mut values = Vec::new();
    for entry in entries {
        let name: Vec<u8> = entry.name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let size = (ENTRY_HEADER + name.len() + entry.data.len() + 2 + 3) & !3;
        for field in [size, name.len(), entry.kind as usize, entry.data.len()] {
            values.extend_from_slice(&(field as u16).to_le_bytes());
        }
        values.extend_from_slice(&entry.flags.to_le_bytes());
        values.extend_from_slice(&0u32.to_le_bytes());
        values.extend_from_slice(&name);
        values.extend_from_slice(&entry.data);
        values.resize(values.len() + size - ENTRY_HEADER - name.len() - entry.data.len(), 0);
    }
    let total = HEADER + values.len() + 4;
    let mut bytes = Vec::with_capacity(total);
    for field in [total as u32, values.len() as u32, 4, 0, VERSION] {
        bytes.extend_from_slice(&field.to_le_bytes());
    }
    bytes.extend_from_slice(&values);
    bytes.extend_from_slice(&END_MARKER.to_le_bytes());
    bytes
}

/// Base64 (RFC 4648, com `=`), ignorando espaços; `None` se inválido.
fn base64(text: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for character in text.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        let value = match character {
            b'A'..=b'Z' => character - b'A',
            b'a'..=b'z' => character - b'a' + 26,
            b'0'..=b'9' => character - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        buffer = buffer << 6 | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
        }
    }
    Some(bytes)
}

/// As referências de entidade do XML.
fn unescape(text: &str) -> String {
    text.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

/// O número de um `policyInt` ou `policySum` (decimal, negativo em
/// complemento de dois, ou hexadecimal com `0x`).
fn integer(text: &str) -> Option<u32> {
    let text = text.trim();
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => text.parse::<i64>().ok().map(|value| value as u32),
    }
}

/// As políticas dos blocos `<sl:productPolicies>` das licenças `texts`,
/// combinadas como o sppsvc as combina: a de prioridade maior (ou igual,
/// a que vem depois) vence, e as `policySum` somam.
pub fn license_policies(texts: &[&str]) -> BTreeMap<String, Policy> {
    let mut policies: BTreeMap<String, Policy> = BTreeMap::new();
    for text in texts {
        let mut rest = *text;
        while let Some(start) = rest.find("<sl:productPolicies") {
            let block_end = rest[start..].find("</sl:productPolicies>").map_or(rest.len(), |end| start + end);
            let block = &rest[start..block_end];
            rest = &rest[block_end..];
            let priority = block.split_once("<sl:priority>").and_then(|(_, tail)| tail.split_once('<')).and_then(|(number, _)| number.trim().parse::<u32>().ok()).unwrap_or(0);
            let mut cursor = block;
            while let Some(at) = cursor.find("<sl:policy") {
                cursor = &cursor[at + "<sl:policy".len()..];
                let Some(kind) = ["Int", "Str", "Bin", "Sum"].into_iter().find(|kind| cursor.starts_with(kind)) else { continue };
                let Some(tag_end) = cursor.find('>') else { break };
                let tag = &cursor[kind.len()..tag_end];
                let Some(name) = tag.split_once("name=\"").and_then(|(_, tail)| tail.split_once('"')).map(|(name, _)| unescape(name)) else { continue };
                let attributes = tag.split_once("attributes=\"").and_then(|(_, tail)| tail.split_once('"')).map_or("", |(attributes, _)| attributes);
                let value = if tag.ends_with('/') {
                    String::new()
                } else {
                    let close = format!("</sl:policy{kind}>");
                    let Some(value_end) = cursor[tag_end + 1..].find(&close) else { break };
                    unescape(&cursor[tag_end + 1..tag_end + 1 + value_end])
                };
                let (entry_kind, data) = match kind {
                    "Str" => (REG_SZ, value.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()),
                    "Bin" => match base64(&value) {
                        Some(bytes) => (REG_BINARY, bytes),
                        None => continue,
                    },
                    _ => match integer(&value) {
                        Some(number) => (REG_DWORD, number.to_le_bytes().to_vec()),
                        None => continue,
                    },
                };
                let flags = if attributes.split(',').any(|attribute| attribute.trim() == "reboot-required") { REBOOT_REQUIRED } else { 0 };
                let policy = Policy { kind: entry_kind, data, flags, priority, sum: kind == "Sum" };
                match policies.get_mut(&name) {
                    Some(current) if current.sum && policy.sum => {
                        let total = dword(&current.data, 0).wrapping_add(dword(&policy.data, 0));
                        current.data = total.to_le_bytes().to_vec();
                        if policy.priority >= current.priority {
                            current.priority = policy.priority;
                            current.flags = policy.flags;
                        }
                    }
                    Some(current) if policy.priority < current.priority => {}
                    _ => {
                        policies.insert(name, policy);
                    }
                }
            }
        }
    }
    policies
}

/// O nome da edição da política (`Kernel-EditionName`), que dá a pasta das
/// licenças dela; só letras e dígitos.
pub fn edition_name(entries: &[Entry]) -> Option<String> {
    let entry = entries.iter().find(|entry| entry.name == "Kernel-EditionName" && entry.kind == REG_SZ)?;
    let units: Vec<u16> = entry.data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
    let name = String::from_utf16(&units).ok()?;
    (!name.is_empty() && name.chars().all(|character| character.is_ascii_alphanumeric())).then_some(name)
}

/// A política limpa a partir dos nomes que esta máquina publica (`host`) e
/// das políticas das licenças da edição (`license`): cada entrada com o tipo,
/// os dados e o flag da licença, as de [`INSTALL_STATE`] com o valor de uma
/// instalação não ativada, as de [`PRODUCT_LICENSE`] com o valor dela, e o
/// resto fora. A ordem é a do kernel e do sppsvc: os nomes em ordem de
/// unidades UTF-16.
pub fn clean(host: &[Entry], license: &BTreeMap<String, Policy>) -> (Vec<u8>, Report) {
    let mut kept = Vec::new();
    let mut report = Report::default();
    for entry in host {
        let state = INSTALL_STATE.iter().find(|(name, _)| *name == entry.name).map(|&(_, clean)| clean);
        let from_license = |policy: &Policy| Entry { name: entry.name.clone(), kind: policy.kind, data: policy.data.clone(), flags: policy.flags };
        let guest = match state {
            Some(Clean::Remove) => None,
            Some(Clean::Dword(value)) => Some(Entry { name: entry.name.clone(), kind: REG_DWORD, data: value.to_le_bytes().to_vec(), flags: 0 }),
            Some(Clean::License) => license.get(&entry.name).map(from_license),
            None => match (license.get(&entry.name), PRODUCT_LICENSE.iter().find(|(name, _)| *name == entry.name)) {
                (Some(policy), _) => {
                    if policy.kind != entry.kind || policy.data != entry.data {
                        report.replaced.push(entry.name.clone());
                    }
                    Some(from_license(policy))
                }
                (None, Some(&(_, value))) => Some(Entry { name: entry.name.clone(), kind: REG_DWORD, data: value.to_le_bytes().to_vec(), flags: 0 }),
                (None, None) => {
                    report.unknown.push(entry.name.clone());
                    None
                }
            },
        };
        kept.extend(guest);
    }
    kept.sort_by(|left, right| left.name.encode_utf16().cmp(right.name.encode_utf16()));
    (blob(&kept), report)
}

/// A política do convidado para o valor `host` desta máquina, com as
/// licenças da edição de `windows\System32\spp\tokens\skus`; `None` sem as
/// licenças (o convidado fica sem o valor).
#[cfg(windows)]
pub fn guest_policy(host: &[u8], windows: &std::path::Path) -> Option<Vec<u8>> {
    let Some(host_entries) = entries(host) else {
        eprintln!("ProductPolicy: o valor desta máquina não está no formato esperado; o convidado fica sem ele");
        return None;
    };
    let Some(edition) = edition_name(&host_entries) else {
        eprintln!("ProductPolicy: sem Kernel-EditionName; o convidado fica sem a política");
        return None;
    };
    let folder = windows.join("System32").join("spp").join("tokens").join("skus").join(&edition);
    let mut texts = Vec::new();
    for file in [format!("DefaultPpd-{edition}-ppdlic.xrm-ms"), format!("{edition}-ppdlic.xrm-ms")] {
        match std::fs::read_to_string(folder.join(&file)) {
            Ok(text) => texts.push(text.trim_start_matches('\u{feff}').to_string()),
            Err(error) => {
                eprintln!("ProductPolicy: licença {} ilegível ({error}); o convidado fica sem a política", folder.join(&file).display());
                return None;
            }
        }
    }
    let license = license_policies(&texts.iter().map(String::as_str).collect::<Vec<_>>());
    let (guest, report) = clean(&host_entries, &license);
    if !report.unknown.is_empty() {
        println!("ProductPolicy: entradas sem classificação, fora do convidado: {}", report.unknown.join(", "));
    }
    if !report.replaced.is_empty() {
        println!("ProductPolicy: entradas com o valor da licença da edição no lugar do desta máquina: {}", report.replaced.join(", "));
    }
    Some(guest)
}

#[cfg(test)]
mod tests {
    use super::{blob, clean, edition_name, entries, license_policies, Entry, END_MARKER, HEADER, REBOOT_REQUIRED};

    fn utf16z(text: &str) -> Vec<u8> {
        text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
    }

    fn entry(name: &str, kind: u16, data: Vec<u8>) -> Entry {
        Entry { name: name.to_string(), kind, data, flags: 0 }
    }

    fn find<'a>(list: &'a [Entry], name: &str) -> Option<&'a Entry> {
        list.iter().find(|entry| entry.name == name)
    }

    const DEFAULT_PPD: &str = r#"<?xml version="1.0" encoding="utf-8"?><r:license><r:grant><r:allConditions><sl:productPolicies xmlns:sl="x"><sl:priority>100</sl:priority>
<sl:policyInt name="Kernel-ProductInfo">1</sl:policyInt>
<sl:policyStr name="Kernel-EditionName">Base</sl:policyStr>
<sl:policyInt name="Security-SPP-GenuineLocalStatus">1</sl:policyInt>
<sl:policyBin name="Security-SPP-LastWindowsActivationHResult">EvAEwA==</sl:policyBin>
<sl:policyBin name="Security-SPP-LastWindowsActivationTime">AAAAAAAAAAA=</sl:policyBin>
<sl:policyStr name="Security-SPP-TokenActivation-AdditionalInfo"></sl:policyStr>
<sl:policySum name="TerminalServices-RemoteConnectionManager-AllowRemoteConnections" attributes="reboot-required">0</sl:policySum>
<sl:policyInt name="Negative">-1</sl:policyInt>
</sl:productPolicies></r:allConditions></r:grant></r:license>"#;
    const EDITION_PPD: &str = r#"<r:license><sl:productPolicies><sl:priority>200</sl:priority>
<sl:policyInt name="Kernel-ProductInfo" attributes="override-only">48</sl:policyInt>
<sl:policyStr name="Kernel-EditionName">Professional</sl:policyStr>
<sl:policyInt name="Security-SPP-GenuineLocalStatus" attributes="override-only">1</sl:policyInt>
<sl:policySum name="TerminalServices-RemoteConnectionManager-AllowRemoteConnections" attributes="reboot-required, override-only">1</sl:policySum>
<sl:policyInt name="Kernel-MUI-Number-Allowed" attributes="reboot-required, override-only">1000</sl:policyInt>
</sl:productPolicies></r:license>"#;

    /// As licenças combinam por prioridade, somam as policySum e dão o tipo,
    /// os dados e o flag de cada política.
    #[test]
    fn license_policies_merge_by_priority() {
        let policies = license_policies(&[DEFAULT_PPD, EDITION_PPD]);
        assert_eq!(policies["Kernel-ProductInfo"].data, 48u32.to_le_bytes());
        assert_eq!(policies["Kernel-EditionName"].data, utf16z("Professional"));
        assert_eq!(policies["Kernel-EditionName"].kind, 1);
        assert_eq!(policies["Security-SPP-LastWindowsActivationHResult"].data, 0xC004_F012u32.to_le_bytes());
        assert_eq!(policies["Security-SPP-LastWindowsActivationTime"].data, [0; 8]);
        assert_eq!(policies["Security-SPP-TokenActivation-AdditionalInfo"].data, [0, 0]);
        let sum = &policies["TerminalServices-RemoteConnectionManager-AllowRemoteConnections"];
        assert_eq!((sum.kind, sum.data.as_slice(), sum.flags), (4, &1u32.to_le_bytes()[..], REBOOT_REQUIRED));
        assert_eq!(policies["Kernel-MUI-Number-Allowed"].flags, REBOOT_REQUIRED);
        assert_eq!(policies["Kernel-ProductInfo"].flags, 0);
        assert_eq!(policies["Negative"].data, u32::MAX.to_le_bytes());
    }

    /// O formato: cabeçalho com os tamanhos, entradas alinhadas a 4 bytes
    /// com o WCHAR nulo depois dos dados, marcador 0x45; e a leitura volta
    /// as mesmas entradas.
    #[test]
    fn blob_round_trips() {
        let list = vec![entry("A", 4, vec![1, 0, 0, 0]), entry("Bc", 1, utf16z("x")), Entry { name: "Long-Name".into(), kind: 3, data: vec![9; 5], flags: 2 }];
        let bytes = blob(&list);
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        assert_eq!(word(0) as usize, bytes.len());
        assert_eq!(HEADER + word(4) as usize + word(8) as usize, bytes.len());
        assert_eq!((word(8), word(12), word(16)), (4, 0, 1));
        assert_eq!(word(4) % 4, 0);
        assert_eq!(word(bytes.len() - 4), END_MARKER);
        // "A": 16 + 2 + 4 + 2 = 24; "Bc": 16 + 4 + 4 + 2 = 26 -> 28;
        // "Long-Name": 16 + 18 + 5 + 2 = 41 -> 44.
        assert_eq!(u16::from_le_bytes([bytes[HEADER], bytes[HEADER + 1]]), 24);
        assert_eq!(u16::from_le_bytes([bytes[HEADER + 24], bytes[HEADER + 25]]), 28);
        assert_eq!(word(4), 24 + 28 + 44);
        assert_eq!(entries(&bytes), Some(list));
        let mut broken = bytes.clone();
        broken[0] ^= 1;
        assert_eq!(entries(&broken), None);
    }

    /// A lista de permissão: só as entradas das licenças da edição (com os
    /// dados da licença, mesmo quando os daqui diferem) e as classificadas;
    /// o estado da ativação volta ao de uma instalação limpa e o histórico
    /// de máquinas sai.
    #[test]
    fn clean_keeps_only_edition_entries() {
        let license = license_policies(&[DEFAULT_PPD, EDITION_PPD]);
        let host = vec![
            entry("Kernel-EditionName", 1, utf16z("Professional")),
            entry("Kernel-ProductInfo", 4, 48u32.to_le_bytes().to_vec()),
            entry("Kernel-MUI-Number-Allowed", 4, 7u32.to_le_bytes().to_vec()),
            entry("Security-SPP-GenuineLocalStatus", 4, 0u32.to_le_bytes().to_vec()),
            entry("Security-SPP-LastWindowsActivationTime", 3, vec![0xAA; 8]),
            entry("Security-SPP-LastWindowsActivationHResult", 3, vec![0; 4]),
            entry("Security-SPP-TokenActivation-AdditionalInfo", 1, utf16z("host")),
            entry("Security-SPP-Action-StateData", 1, utf16z("host")),
            entry("Security-SPP-Reserved-TBLState", 4, 5u32.to_le_bytes().to_vec()),
            entry("Security-SPP-Reserved-TBLProductKeyType", 4, 6u32.to_le_bytes().to_vec()),
            entry("Security-SPP-Reserved-TBLRemainingTime", 4, 7u32.to_le_bytes().to_vec()),
            entry("Security-SPP-WriteWauMarker", 4, 9u32.to_le_bytes().to_vec()),
            entry("4A0C606B-2CE9-4A35-9B3E-A57D37F18632", 3, vec![0xBB; 60]),
            entry("Some-Unknown-Dynamic", 4, 3u32.to_le_bytes().to_vec()),
            entry("TerminalServices-RemoteConnectionManager-AllowRemoteConnections", 4, 1u32.to_le_bytes().to_vec()),
        ];
        let (bytes, report) = clean(&host, &license);
        let guest = entries(&bytes).expect("formato válido");
        let data = |name: &str| find(&guest, name).map(|entry| entry.data.clone());
        assert_eq!(edition_name(&guest).as_deref(), Some("Professional"));
        assert_eq!(data("Kernel-ProductInfo"), Some(48u32.to_le_bytes().to_vec()));
        assert_eq!(data("Kernel-MUI-Number-Allowed"), Some(1000u32.to_le_bytes().to_vec()));
        assert_eq!(find(&guest, "Kernel-MUI-Number-Allowed").unwrap().flags, REBOOT_REQUIRED);
        assert_eq!(data("Security-SPP-GenuineLocalStatus"), Some(1u32.to_le_bytes().to_vec()));
        assert_eq!(data("Security-SPP-LastWindowsActivationTime"), Some(vec![0; 8]));
        assert_eq!(data("Security-SPP-LastWindowsActivationHResult"), Some(0xC004_F012u32.to_le_bytes().to_vec()));
        assert_eq!(data("Security-SPP-TokenActivation-AdditionalInfo"), Some(vec![0, 0]));
        // Sem o valor nas licenças, o estado da ativação sai.
        assert_eq!(data("Security-SPP-Action-StateData"), None);
        for name in ["Security-SPP-Reserved-TBLState", "Security-SPP-Reserved-TBLProductKeyType", "Security-SPP-Reserved-TBLRemainingTime"] {
            assert_eq!(data(name), Some(vec![0; 4]), "{name}");
        }
        assert_eq!(data("Security-SPP-WriteWauMarker"), Some(1u32.to_le_bytes().to_vec()));
        assert_eq!(data("4A0C606B-2CE9-4A35-9B3E-A57D37F18632"), None);
        assert_eq!(data("Some-Unknown-Dynamic"), None);
        assert_eq!(report.unknown, vec![String::from("Some-Unknown-Dynamic")]);
        assert_eq!(report.replaced, vec![String::from("Kernel-MUI-Number-Allowed")]);
        // Nenhum byte dos dados desta máquina passa.
        assert!(!bytes.windows(8).any(|window| window == [0xAA; 8]));
        assert!(!bytes.windows(8).any(|window| window == [0xBB; 8]));
        assert!(!bytes.windows(8).any(|window| *window == utf16z("host")[..8]));
        // Ordem de unidades UTF-16 (maiúsculas antes de minúsculas, como o
        // sppsvc grava).
        let names: Vec<&str> = guest.iter().map(|entry| entry.name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
        assert_eq!(names, sorted);
        assert_eq!(guest.len(), 12);
    }
}
