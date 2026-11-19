//! As anotações compartilhadas com o opennt-re: comentários, rótulos e
//! marcadores por módulo + RVA no arquivo de notas da sessão dele
//! (`Engine::notes_file`, `<build>/opennt-re/notas.txt`, o formato de
//! `kd_client::analysis::notes`). Valem de novo quando o módulo carrega em
//! outra base; a ferramenta `disassemble` mostra os rótulos e os
//! comentários nas linhas.

use kd_client::analysis::notes::{Location, Notes};
use kd_client::Client;
use serde_json::{json, Value};

use super::{boolean, hex, integer, object, text, Arguments, ToolError, ToolResult};
use crate::engine::Engine;

/// As definições (nome, descrição, esquema).
pub fn definitions() -> Vec<(&'static str, &'static str, Value)> {
    vec![
        (
            "annotations_list",
            "As anotacoes compartilhadas com o opennt-re (comentarios, rotulos e marcadores por modulo + RVA, no notas.txt da sessao dele): o lugar, o endereco com os modulos de agora (com sessao) e o texto.",
            object(json!({"module": text("so deste modulo (ntdll, kernel, dwmcore)"), "filter": text("so as que contem este texto (sem caixa)"), "limit": integer("anotacoes (padrao 200)", 1, 10_000)}), &[]),
        ),
        (
            "annotation_set",
            "Grava uma anotacao compartilhada com o opennt-re: comentario, rotulo e/ou marcador num endereco (expressao, precisa da sessao) ou num lugar modulo+0xRVA (sem sessao). Texto vazio apaga.",
            object(
                json!({
                    "address": text("expressao do endereco (precisa da sessao)"),
                    "location": text("ou o lugar: modulo+0xRVA (ntdll+0x1234, kernel+0x2000) ou 0x... absoluto"),
                    "comment": text("comentario (vazio apaga)"),
                    "label": text("rotulo (vazio apaga)"),
                    "bookmark": boolean("liga (true) ou tira (false) o marcador")
                }),
                &[],
            ),
        ),
    ]
}

/// Roda uma das ferramentas deste módulo (`None`: não é daqui).
pub fn run(engine: &mut dyn Engine, name: &str, args: &Arguments) -> Option<ToolResult> {
    let result = match name {
        "annotations_list" => list(engine, args),
        "annotation_set" => set(engine, args),
        _ => return None,
    };
    Some(result.map_err(ToolError::Failed))
}

/// O lugar de um endereço: módulo (o kernel do OpenNT é `kernel`, como no
/// opennt-re) e RVA, ou o endereço absoluto fora dos módulos.
pub(super) fn location_of(client: &Client, address: u64) -> Location {
    match client.symbols.module_at(address) {
        Some(module) if client.symbols.is_kernel(module) => Location::new("kernel", address - module.base),
        Some(module) => Location::new(&module.name, address - module.base),
        None => Location::absolute(address),
    }
}

/// O endereço de um lugar com os módulos de agora.
fn address_of(client: &Client, location: &Location) -> Option<u64> {
    if location.module.is_empty() {
        return Some(location.offset);
    }
    client.symbols.module_named(&location.module).map(|module| module.base + location.offset)
}

/// `ntdll+0x1234`, `kernel+0x2000` ou `0x...` (absoluto).
pub fn parse_location(text: &str) -> Result<Location, String> {
    let text = text.trim();
    match text.rsplit_once('+') {
        Some((module, offset)) if !module.trim().is_empty() => {
            let offset = kd_client::parse_number(offset.trim()).ok_or_else(|| format!("{text}: deslocamento invalido"))?;
            Ok(Location::new(module.trim(), offset))
        }
        _ => kd_client::parse_number(text).map(Location::absolute).ok_or_else(|| format!("{text}: lugar invalido (modulo+0xRVA ou 0x...)")),
    }
}

fn list(engine: &mut dyn Engine, args: &Arguments) -> Result<Value, String> {
    let path = engine.notes_file();
    let notes = Notes::load(&path)?;
    let module = args.text("module").map(|module| module.to_ascii_lowercase());
    let filter = args.text("filter").map(|filter| filter.to_ascii_lowercase()).unwrap_or_default();
    let limit = args.integer("limit").unwrap_or(200) as usize;
    let client: Option<&Client> = engine.client().ok().map(|client| &*client);
    let mut entries: Vec<(&str, &Location, String)> = Vec::new();
    entries.extend(notes.labels.iter().map(|(location, text)| ("rotulo", location, text.clone())));
    entries.extend(notes.comments.iter().map(|(location, text)| ("comentario", location, text.clone())));
    entries.extend(notes.bookmarks.iter().map(|location| ("marcador", location, String::new())));
    let matching: Vec<Value> = entries
        .into_iter()
        .filter(|(_, location, text)| module.as_ref().is_none_or(|wanted| location.module == *wanted) && (filter.is_empty() || text.to_ascii_lowercase().contains(&filter) || location.display().to_ascii_lowercase().contains(&filter)))
        .map(|(kind, location, text)| {
            let mut value = json!({"kind": kind, "location": location.display()});
            if !text.is_empty() {
                value["text"] = json!(text);
            }
            if let Some(address) = client.and_then(|client| address_of(client, location)) {
                value["address"] = json!(hex(address));
            }
            value
        })
        .collect();
    let total = matching.len();
    Ok(json!({"file": path.display().to_string(), "total": total, "annotations": matching.into_iter().take(limit).collect::<Vec<_>>()}))
}

fn set(engine: &mut dyn Engine, args: &Arguments) -> Result<Value, String> {
    let path = engine.notes_file();
    let (location, address) = match (args.text("address"), args.text("location")) {
        (Some(expression), None) => {
            let client = engine.client()?;
            let address = client.evaluate(&expression)?;
            (location_of(client, address), Some(address))
        }
        (None, Some(text)) => (parse_location(&text)?, None),
        _ => return Err("annotation_set: address ou location (um dos dois)".into()),
    };
    let comment = args.raw("comment");
    let label = args.raw("label");
    let bookmark = args.flag("bookmark");
    if comment.is_none() && label.is_none() && bookmark.is_none() {
        return Err("annotation_set: falta comment, label ou bookmark".into());
    }
    let mut notes = Notes::load(&path)?;
    if let Some(comment) = comment {
        notes.set_comment(location.clone(), comment);
    }
    if let Some(label) = label {
        notes.set_label(location.clone(), label);
    }
    if let Some(on) = bookmark {
        if notes.bookmarks.contains(&location) != on {
            notes.toggle_bookmark(location.clone());
        }
    }
    notes.save(&path)?;
    Ok(json!({
        "file": path.display().to_string(),
        "location": location.display(),
        "address": address.map(hex),
        "comment": notes.comments.get(&location),
        "label": notes.labels.get(&location),
        "bookmark": notes.bookmarks.contains(&location),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_locations() {
        assert_eq!(parse_location("ntdll+0x1234"), Ok(Location::new("ntdll", 0x1234)));
        assert_eq!(parse_location(" Kernel+0x2000 "), Ok(Location::new("kernel", 0x2000)));
        assert_eq!(parse_location("0xfffff80040000000"), Ok(Location::absolute(0xfffff800_40000000)));
        assert!(parse_location("ntdll+zz").is_err());
        assert!(parse_location("nada").is_err());
    }
}
