//! Exploradores do estado vivo do convidado, para as abas Registro, Objetos
//! e Arquivos do host:
//!
//! - `reg keys|values|value`: as chaves e os valores como o Configuration
//!   Manager os guarda (a arena de `cm/registry`, com as células das hives
//!   carregadas por trás), seguindo os links como uma abertura;
//! - `objdir`: um diretório do namespace do Object Manager (filhos com o
//!   tipo, o corpo nativo, o destino dos links e o arquivo por trás);
//! - `fs ls|read`: arquivos do volume que o kernel montou, pelo leitor NTFS
//!   do próprio kernel.
//!
//! Todas usam estruturas do Rust e alocam: só rodam quando nenhum
//! processador parado tinha trava do kernel (`stop::locks_held`), como o
//! `obj` e a lista de módulos. A saída é paginada pelo tamanho do pacote:
//! a última linha dá o índice seguinte (`mais: N`). Os campos de cada linha
//! vão separados por tabulação.

use alloc::string::String;
use core::fmt::Write;

use super::packet::Payload;
use super::stop;

/// O texto de uma página para antes deste tamanho (o pacote tem 4 KB).
const PAGE_BYTES: usize = 3000;
/// Bytes de dados de um valor ou de um arquivo por pedido (em hexadecimal).
const DATA_BYTES: usize = 1400;

fn refuse(out: &mut Payload) -> bool {
    if stop::locks_held() {
        out.push_str("indisponivel: um processador parado tinha trava do kernel\n");
        return true;
    }
    false
}

fn push_clean(out: &mut Payload, text: &str) {
    for character in text.chars() {
        match character {
            '\t' | '\n' | '\r' => out.push(b' '),
            other => {
                let mut buffer = [0u8; 4];
                out.push_str(other.encode_utf8(&mut buffer));
            }
        }
    }
}

fn push_hex(out: &mut Payload, bytes: &[u8]) {
    out.push_hex(bytes);
}

/// Separa o primeiro argumento (um caminho entre aspas pode ter espaços).
fn split_argument(text: &str) -> (&str, &str) {
    let text = text.trim_start();
    if let Some(quoted) = text.strip_prefix('"') {
        return match quoted.find('"') {
            Some(end) => (&quoted[..end], quoted[end + 1..].trim_start()),
            None => (quoted, ""),
        };
    }
    match text.find(char::is_whitespace) {
        Some(end) => (&text[..end], text[end..].trim_start()),
        None => (text, ""),
    }
}

/// `reg keys <caminho> [início]`, `reg values <caminho> [início]` e
/// `reg value <caminho> <nome> [deslocamento]`.
pub fn registry(line: &str, out: &mut Payload) {
    use crate::ntos::cm::registry;
    if refuse(out) {
        return;
    }
    let (verb, rest) = split_argument(line);
    let (path, rest) = split_argument(rest);
    if path.is_empty() {
        out.push_str("uso: reg keys|values <caminho> [inicio] | reg value <caminho> <nome> [deslocamento]\n");
        return;
    }
    let Some(node) = registry::node_by_path(path) else {
        let _ = writeln!(out, "{}: chave nao encontrada", path);
        return;
    };
    match verb {
        "keys" => {
            let start = rest.trim().parse::<usize>().unwrap_or(0);
            let children = registry::children(node);
            let header = registry::with_node(node, |key| (key.values.len(), key.last_write_time, key.volatile, key.link)).unwrap_or((0, 0, false, false));
            let hive = registry::hive_of(node).and_then(|(identifier, _)| registry::hive_path(identifier)).unwrap_or_default();
            out.push_str("chave\t");
            push_clean(out, &registry::path_of(node).unwrap_or_else(|| String::from(path)));
            let _ = writeln!(out, "\t{}\t{}\t{:#x}\t{}\t{}\t{}", children.len(), header.0, header.1, header.2 as u8, header.3 as u8, hive);
            for (index, child) in children.iter().enumerate().skip(start) {
                if out.len() > PAGE_BYTES {
                    let _ = writeln!(out, "mais: {}", index);
                    return;
                }
                let Some((name, subkeys, values)) = registry::with_node(*child, |key| (key.name.clone(), key.children.len(), key.values.len())) else { continue };
                out.push_str("k\t");
                push_clean(out, &name);
                let _ = writeln!(out, "\t{}\t{}", subkeys, values);
            }
        }
        "values" => {
            let start = rest.trim().parse::<usize>().unwrap_or(0);
            let count = registry::with_node(node, |key| key.values.len()).unwrap_or(0);
            for index in start..count {
                if out.len() > PAGE_BYTES {
                    let _ = writeln!(out, "mais: {}", index);
                    return;
                }
                let Some(value) = registry::with_node(node, |key| key.values.get(index).cloned()).flatten() else { continue };
                out.push_str("v\t");
                push_clean(out, &value.name);
                let _ = write!(out, "\t{}\t{}\t", value.value_type, value.data.len());
                push_hex(out, &value.data[..value.data.len().min(96)]);
                out.push(b'\n');
            }
        }
        "value" => {
            let (name, rest) = split_argument(rest);
            let offset = rest.trim().parse::<usize>().unwrap_or(0);
            let lower = name.to_lowercase();
            let wanted = if lower == "(padrao)" || lower == "@" { String::new() } else { lower };
            let Some(value) = registry::with_node(node, |key| key.value(&wanted).cloned()).flatten() else {
                let _ = writeln!(out, "{}: valor {} nao encontrado", path, name);
                return;
            };
            let end = (offset + DATA_BYTES).min(value.data.len());
            out.push_str("valor\t");
            push_clean(out, &value.name);
            let _ = write!(out, "\t{}\t{}\t{}\t", value.value_type, value.data.len(), offset.min(value.data.len()));
            push_hex(out, &value.data[offset.min(end)..end]);
            out.push(b'\n');
        }
        _ => out.push_str("uso: reg keys|values <caminho> [inicio] | reg value <caminho> <nome> [deslocamento]\n"),
    }
}

/// `objdir <caminho> [início]`.
pub fn object_directory(line: &str, out: &mut Payload) {
    use crate::ntos::ob::object_manager;
    if refuse(out) {
        return;
    }
    let (path, rest) = split_argument(line);
    let path = if path.is_empty() { "\\" } else { path };
    let start = rest.trim().parse::<usize>().unwrap_or(0);
    let Some(id) = object_manager::lookup(path) else {
        let _ = writeln!(out, "{}: nao encontrado", path);
        return;
    };
    let Some(node) = object_manager::node(id) else {
        let _ = writeln!(out, "{}: nao encontrado", path);
        return;
    };
    let body = |node: &object_manager::Node| {
        let body = node.data.as_ref().map_or(0, |data| if data.native_pointer != 0 { data.native_pointer } else { data.native_body });
        if body != 0 {
            body
        } else {
            node.native_namespace
        }
    };
    out.push_str("diretorio\t");
    push_clean(out, path);
    let _ = writeln!(out, "\t{}\t{:#x}\t{}", node.type_name, body(&node), node.children.as_ref().map_or(0, |children| children.len()));
    let Some(children) = node.children.as_ref() else { return };
    for (index, (name, child)) in children.iter().enumerate().skip(start) {
        if out.len() > PAGE_BYTES {
            let _ = writeln!(out, "mais: {}", index);
            return;
        }
        let Some(child) = object_manager::node(*child) else { continue };
        out.push_str("o\t");
        // A chave do mapa é o nome em minúsculas; o nó guarda o original.
        push_clean(out, if child.name.is_empty() { name } else { &child.name });
        let _ = write!(out, "\t{}\t{:#x}\t{}\t", child.type_name, body(&child), child.children.as_ref().map_or(0, |children| children.len()));
        if let Some(target) = child.data.as_ref().and_then(|data| data.symlink_target.as_ref()) {
            push_clean(out, target);
        } else if let Some(file) = child.data.as_ref().and_then(|data| data.file_path.as_ref()) {
            push_clean(out, file);
        }
        out.push(b'\n');
    }
}

/// `fs ls <caminho> [início]` e `fs read <caminho> <deslocamento> [bytes]`.
pub fn files(line: &str, out: &mut Payload) {
    if refuse(out) {
        return;
    }
    let Some(volume) = crate::drivers::fs::ntfs::mounted() else {
        out.push_str("fs: nenhum volume NTFS montado pelo kernel\n");
        return;
    };
    let (verb, rest) = split_argument(line);
    let (path, rest) = split_argument(rest);
    let path = path.replace('\\', "/");
    let path = if path.is_empty() { String::from("/") } else { path };
    match verb {
        "ls" => {
            let start = rest.trim().parse::<usize>().unwrap_or(0);
            let names = match volume.list(&path) {
                Ok(Some(names)) => names,
                Ok(None) => {
                    let _ = writeln!(out, "{}: nao encontrado", path);
                    return;
                }
                Err(error) => {
                    let _ = writeln!(out, "{}: {}", path, error);
                    return;
                }
            };
            out.push_str("pasta\t");
            push_clean(out, &path);
            let _ = writeln!(out, "\t{}", names.len());
            for (index, name) in names.iter().enumerate().skip(start) {
                if out.len() > PAGE_BYTES {
                    let _ = writeln!(out, "mais: {}", index);
                    return;
                }
                let stat = volume.stat(name).ok().flatten();
                let leaf = name.rsplit('/').next().unwrap_or(name);
                out.push_str("f\t");
                push_clean(out, leaf);
                match stat {
                    Some(stat) => {
                        let modified = if stat.times.len() >= 16 { u64::from_le_bytes(stat.times[8..16].try_into().unwrap_or([0; 8])) } else { 0 };
                        let _ = writeln!(out, "\t{}\t{}\t{:#x}\t{:#x}", stat.directory as u8, stat.size, stat.attributes, modified);
                    }
                    None => out.push_str("\t0\t0\t0\t0\n"),
                }
            }
        }
        "read" => {
            let mut words = rest.split_whitespace();
            let offset = words.next().and_then(|word| word.parse::<u64>().ok()).unwrap_or(0);
            let length = words.next().and_then(|word| word.parse::<u64>().ok()).unwrap_or(DATA_BYTES as u64).min(DATA_BYTES as u64);
            let size = match volume.stat(&path) {
                Ok(Some(stat)) if !stat.directory => stat.size,
                Ok(Some(_)) => {
                    let _ = writeln!(out, "{}: e uma pasta", path);
                    return;
                }
                Ok(None) => {
                    let _ = writeln!(out, "{}: nao encontrado", path);
                    return;
                }
                Err(error) => {
                    let _ = writeln!(out, "{}: {}", path, error);
                    return;
                }
            };
            match volume.read_range(&path, offset, length) {
                Ok(Some(bytes)) => {
                    out.push_str("dados\t");
                    push_clean(out, &path);
                    let _ = write!(out, "\t{}\t{}\t", size, offset);
                    push_hex(out, &bytes);
                    out.push(b'\n');
                }
                Ok(None) => {
                    let _ = writeln!(out, "{}: nao encontrado", path);
                }
                Err(error) => {
                    let _ = writeln!(out, "{}: {}", path, error);
                }
            }
        }
        _ => out.push_str("uso: fs ls <caminho> [inicio] | fs read <caminho> <deslocamento> [bytes]\n"),
    }
}
