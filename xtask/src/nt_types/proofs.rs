//! Provas das constantes de `nt_abi.rs`: cada constante de offset que
//! corresponde a um campo do layout real vira uma asserção de compilação
//! contra os tipos gerados; divergências são listadas, não corrigidas.

use super::emit::member_view_name;
use super::layout::Generator;
use super::{Proof, Target};

/// Início do bloco gerado no fim de `nt_abi.rs` (o texto antes dele é mantido à mão).
const MARKER_PREFIX: &str = "// ---- Prova contra os símbolos do ntoskrnl";
pub const MARKER: &str = "// ---- Prova contra os símbolos do ntoskrnl (gerado por `cargo xtask nt-types`) ----";

pub struct Outcome {
    pub text: String,
    pub asserts: usize,
    /// (módulo, constante, valor, rótulo, valor nos símbolos)
    pub mismatches: Vec<(String, String, i128, String, i128)>,
    pub unmapped: Vec<String>,
}

/// `pub const X: u64 = <expressão>;` dentro de `pub mod m {`, na ordem do arquivo.
fn parse_constants(text: &str) -> Vec<((String, String), String)> {
    let mut constants: Vec<((String, String), String)> = Vec::new();
    let mut module: Option<String> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("pub mod ") {
            let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
            if !name.is_empty() && rest[name.len()..].starts_with(" {") {
                module = Some(name);
                continue;
            }
        }
        if line.starts_with('}') {
            module = None;
            continue;
        }
        let Some(module) = &module else { continue };
        let trimmed = line.trim_start();
        if trimmed.len() == line.len() {
            continue;
        }
        let Some(rest) = trimmed.strip_prefix("pub const ") else { continue };
        let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
        let Some(rest) = rest[name.len()..].strip_prefix(": u64 = ") else { continue };
        let Some(end) = rest.find(';') else { continue };
        if name.is_empty() || end == 0 {
            continue;
        }
        let key = (module.clone(), name);
        let expression = rest[..end].to_string();
        match constants.iter_mut().find(|(existing, _)| *existing == key) {
            Some(entry) => entry.1 = expression,
            None => constants.push((key, expression)),
        }
    }
    constants
}

/// Avalia a expressão de uma constante (`0x70 + 29 * 8`).
fn evaluate(expression: &str) -> Result<i128, String> {
    fn number(text: &[u8], at: &mut usize) -> Result<i128, String> {
        while *at < text.len() && text[*at] == b' ' {
            *at += 1;
        }
        if *at < text.len() && text[*at] == b'(' {
            *at += 1;
            let value = sum(text, at)?;
            while *at < text.len() && text[*at] == b' ' {
                *at += 1;
            }
            if text.get(*at) != Some(&b')') {
                return Err("')' esperado".into());
            }
            *at += 1;
            return Ok(value);
        }
        let start = *at;
        while *at < text.len() && text[*at].is_ascii_alphanumeric() {
            *at += 1;
        }
        let word = std::str::from_utf8(&text[start..*at]).unwrap();
        let parsed = match word.strip_prefix("0x") {
            Some(hex) => i128::from_str_radix(hex, 16),
            None => word.parse(),
        };
        parsed.map_err(|_| format!("numero invalido: {word}"))
    }
    fn product(text: &[u8], at: &mut usize) -> Result<i128, String> {
        let mut value = number(text, at)?;
        loop {
            while *at < text.len() && text[*at] == b' ' {
                *at += 1;
            }
            match text.get(*at) {
                Some(b'*') => {
                    *at += 1;
                    value *= number(text, at)?;
                }
                _ => return Ok(value),
            }
        }
    }
    fn sum(text: &[u8], at: &mut usize) -> Result<i128, String> {
        let mut value = product(text, at)?;
        loop {
            while *at < text.len() && text[*at] == b' ' {
                *at += 1;
            }
            match text.get(*at) {
                Some(b'+') => {
                    *at += 1;
                    value += product(text, at)?;
                }
                Some(b'-') => {
                    *at += 1;
                    value -= product(text, at)?;
                }
                _ => return Ok(value),
            }
        }
    }
    let cleaned = expression.replace('_', "");
    let text = cleaned.as_bytes();
    let mut at = 0;
    let value = sum(text, &mut at).map_err(|error| format!("{expression}: {error}"))?;
    if at != text.len() {
        return Err(format!("{expression}: expressao nao suportada"));
    }
    Ok(value)
}

/// Offset nos símbolos e expressão Rust (soma de `offset_of!` pelas vistas).
pub(super) fn path_offset(generator: &Generator, nt_struct: &str, path: &str) -> Option<(i128, String)> {
    let mut typedef = generator.by_nt_name(nt_struct);
    let steps: Vec<&str> = path.split('.').collect();
    let mut total: i128 = 0;
    let mut pieces = Vec::new();
    for (position, step) in steps.iter().enumerate() {
        let current = typedef?;
        let member = current.members.iter().find(|member| member.nt_name.as_deref() == Some(step))?;
        total += member.offset as i128;
        pieces.push(format!("core::mem::offset_of!({}, {})", member_view_name(current, member.view), member.rust_name));
        if position + 1 < steps.len() {
            typedef = member.leaf.deps.first().and_then(|key| generator.types.get(key));
        }
    }
    Some((total, pieces.join(" + ")))
}

pub fn rewrite(generator: &Generator, proofs: &[Proof], original: &str) -> Result<Outcome, String> {
    let mut text = original.replace("\r\n", "\n");
    if let Some(start) = text.find(MARKER_PREFIX) {
        text = format!("{}\n", text[..start].trim_end_matches('\n'));
    }
    let mut asserts = Vec::new();
    let mut mismatches = Vec::new();
    let mut unmapped = Vec::new();
    for ((module, constant), expression) in parse_constants(&text) {
        let proof = proofs.iter().find(|proof| proof.module == module);
        let Some(target) = proof.and_then(|proof| proof.fields.iter().find(|(name, _)| *name == constant)).map(|(_, target)| target) else {
            unmapped.push(format!("{module}::{constant}"));
            continue;
        };
        let default_struct = &proof.unwrap().structure;
        let value = evaluate(&expression)?;
        let (pdb_value, rust, label) = match target {
            Target::Rust { rust_type, field, value } => (
                *value,
                format!("core::mem::offset_of!({rust_type}, {field})"),
                format!("{rust_type}.{field} (wdk.rs)"),
            ),
            Target::SizeOf(structure) => {
                let structure = structure.as_deref().unwrap_or(default_struct);
                let typedef = generator.by_nt_name(structure).ok_or_else(|| format!("provas: {structure} fora do conjunto gerado"))?;
                (typedef.size as i128, format!("core::mem::size_of::<{}>()", typedef.rust_name), format!("sizeof({structure})"))
            }
            Target::Path(structure, path) => {
                let structure = structure.as_deref().unwrap_or(default_struct);
                let Some((offset, rust)) = path_offset(generator, structure, path) else {
                    unmapped.push(format!("{module}::{constant} ({structure}.{path} não encontrado)"));
                    continue;
                };
                (offset, rust, format!("{structure}.{path}"))
            }
        };
        if pdb_value != value {
            mismatches.push((module, constant, value, label, pdb_value));
            continue;
        }
        asserts.push(format!("    assert!({module}::{constant} as usize == {rust});"));
    }
    let mut lines = vec![
        MARKER.to_string(),
        "//".to_string(),
        "// Cada constante de offset acima que corresponde a um campo do layout real".to_string(),
        "// é conferida em compilação contra `inc::types` (gerado dos símbolos).".to_string(),
    ];
    if !mismatches.is_empty() {
        lines.push("// Divergem dos símbolos (constantes mantidas como estão; a conferir):".into());
        for (module, constant, value, label, pdb_value) in &mismatches {
            lines.push(format!("//   {module}::{constant} = {value:#x}; símbolos: {label} = {pdb_value:#x}"));
        }
    }
    lines.push("const _: () = {".into());
    lines.push("    use crate::ntos::inc::types::*;".into());
    let count = asserts.len();
    lines.extend(asserts);
    lines.push("};".into());
    let text = format!("{text}\n{}\n", lines.join("\n"));
    Ok(Outcome { text, asserts: count, mismatches, unmapped })
}
