//! A sessão com as extensões das ferramentas de engenharia reversa: o
//! monitor de APIs e o rastreador de IRPs (o fluxo de registros do alvo),
//! os exploradores do Registro, do namespace e dos arquivos, a vista de um
//! endereço como tipo do PDB, os snapshots da máquina pelo monitor do QEMU
//! e a reprodução de uma gravação (record/replay) com os passos para trás
//! do gdbstub do QEMU (`bs`, `bc`).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::api_monitor::{self, ApiRow, ExportNames};
use super::client::Client;
use super::explore::{self, FileEntry, KeyInfo, ObjectDirectory, RegistryValue, SubKey};
use super::hmp;
use super::irp_timeline::Timeline;
use super::rsp::unhex;
use super::stream::{self, Collector, Record};
use super::struct_view::{self, ListElement, Row};
use super::types::TypeDb;

/// Linhas guardadas no máximo (as mais antigas saem).
pub const MAX_API_ROWS: usize = 400_000;

/// O estado do monitor de APIs e do rastreador de IRPs na sessão.
#[derive(Default)]
pub struct Monitors {
    pub collector: Collector,
    pub names: ExportNames,
    pub api_enabled: bool,
    pub irp_enabled: bool,
    /// As chamadas decodificadas, em ordem de sequência.
    pub api_rows: Vec<ApiRow>,
    /// Linhas tiradas do começo por causa do limite.
    pub api_trimmed: usize,
    pub irps: Timeline,
    /// Perdidos no alvo (anel cheio) segundo o último cabeçalho lido.
    pub target_dropped: u64,
    /// Muda a cada registro novo (a interface relê).
    pub generation: u64,
    /// Os tipos dos PDBs dos módulos de usuário (pelo caminho do PDB).
    pub user_types: HashMap<PathBuf, Arc<TypeDb>>,
}

/// Uma sessão de reprodução (o gdbstub do QEMU sobre uma gravação).
#[derive(Clone, Debug, Default)]
pub struct Replay {
    /// Os módulos da gravação (base, fim, caminho).
    pub modules: Vec<(u64, u64, String)>,
    /// O gdbstub aceita os passos para trás (`ReverseStep+`).
    pub reverse: bool,
}

/// O arquivo com os módulos de uma gravação (ao lado dela).
pub fn modules_file(recording: &Path) -> PathBuf {
    let mut name = recording.as_os_str().to_owned();
    name.push(".modulos");
    PathBuf::from(name)
}

/// A gravação reproduzida pelas opções do `xtask` (`--replay=ARQ`; um
/// caminho relativo vale a partir da raiz).
pub fn replay_recording(extra: &[String], root: &Path) -> Option<PathBuf> {
    extra.iter().find_map(|argument| argument.strip_prefix("--replay=")).map(|value| {
        let path = PathBuf::from(value);
        if path.is_relative() {
            root.join(path)
        } else {
            path
        }
    })
}

/// Os módulos em texto (`base fim caminho` por linha).
pub fn modules_text(modules: &[(u64, u64, String)]) -> String {
    modules.iter().map(|(base, end, path)| format!("{base:#x} {end:#x} {path}\n")).collect()
}

pub fn parse_modules(text: &str) -> Vec<(u64, u64, String)> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.splitn(3, ' ');
            let base = super::parse_number(parts.next()?)?;
            let end = super::parse_number(parts.next()?)?;
            Some((base, end, parts.next()?.trim().to_string()))
        })
        .collect()
}

impl Client {
    // ---- fluxo de registros ----

    /// Os `O` do fluxo recebidos com a máquina rodando.
    pub(crate) fn collect_records(&mut self) {
        let packets = self.connection.take_records();
        if packets.is_empty() {
            return;
        }
        let mut records = Vec::new();
        for packet in packets {
            if let Some(parsed) = stream::parse_packet(&packet) {
                records.extend(parsed);
            }
        }
        self.accept_records(records);
    }

    fn accept_records(&mut self, records: Vec<Record>) {
        let mut changed = false;
        for record in records {
            if !self.monitors.collector.accept(record.sequence()) {
                continue;
            }
            changed = true;
            match record {
                Record::Api(call) => {
                    let row = self.decode_api(call);
                    self.monitors.api_rows.push(row);
                }
                Record::Irp(event) => self.monitors.irps.push(&event),
                Record::Unknown { .. } => {}
            }
        }
        if !changed {
            return;
        }
        self.monitors.generation += 1;
        if self.monitors.api_rows.len() > MAX_API_ROWS {
            let cut = self.monitors.api_rows.len() - MAX_API_ROWS / 2;
            self.monitors.api_rows.drain(..cut);
            self.monitors.api_trimmed += cut;
        }
    }

    /// Uma chamada em linha da tabela (nomes, módulo e símbolo do chamador).
    pub fn decode_api(&self, call: stream::ApiCall) -> ApiRow {
        let symbols = &self.symbols;
        api_monitor::decode(call, &self.monitors.names, &|address| symbols.module_at(address).map(|module| module.name.clone()), &|address| symbols.name_at(address).or_else(|| symbols.module_at(address).map(|_| symbols.describe(address))))
    }

    /// Com a máquina parada, lê o que falta do fluxo (`qOpenNTStream`).
    pub fn fetch_records(&mut self) -> Result<usize, String> {
        self.require_stopped()?;
        if self.replay.is_some() {
            return Ok(0);
        }
        self.collect_records();
        let mut total = 0;
        for _ in 0..4096 {
            let from = self.monitors.collector.next;
            let reply = self.request(&format!("qOpenNTStream:{from:x}"))?;
            if reply.is_empty() || reply.starts_with('E') {
                return Err(format!("qOpenNTStream: {}", if reply.is_empty() { "sem suporte no alvo" } else { &reply }));
            }
            let (header, records) = stream::parse_read(&unhex(&reply)).ok_or("qOpenNTStream: resposta curta")?;
            self.monitors.target_dropped = header.dropped;
            if from < header.oldest {
                // Saíram do anel antes da leitura.
                self.monitors.collector.lost += header.oldest - from;
                self.monitors.collector.next = header.oldest;
            }
            let count = records.len();
            let last = records.last().map(Record::sequence);
            self.accept_records(records);
            total += count;
            match last {
                Some(last) if last + 1 < header.next => continue,
                _ => {
                    if count == 0 && self.monitors.collector.next < header.next {
                        // Um registro ainda não selado (o gravador congelado no
                        // meio): fica para a próxima parada.
                    }
                    break;
                }
            }
        }
        Ok(total)
    }

    /// Os nomes dos exports do alvo (uma vez por sessão).
    pub fn load_export_names(&mut self) -> Result<usize, String> {
        if !self.monitors.names.is_empty() {
            return Ok(self.monitors.names.len());
        }
        let mut start = 0;
        loop {
            let text = self.monitor(&format!("api names {start}"))?;
            if !text.lines().any(|line| line.split_whitespace().next().is_some_and(|id| id.parse::<u32>().is_ok())) {
                return Err(format!("api names: {}", text.trim()));
            }
            match self.monitors.names.add_page(&text) {
                Some(next) if next > start => start = next,
                _ => break,
            }
        }
        Ok(self.monitors.names.len())
    }

    /// Liga o monitor de APIs para os módulos pedidos (nomes ou endereços;
    /// vazio = todos os chamadores).
    pub fn api_monitor_start(&mut self, modules: &[String]) -> Result<String, String> {
        self.require_stopped()?;
        self.load_export_names()?;
        let mut ranges = Vec::new();
        for module in modules {
            let found = match super::parse_number(module) {
                Some(address) => self.symbols.module_at(address),
                None => self.symbols.module_named(module),
            };
            let found = found.ok_or_else(|| format!("modulo {module} nao carregado"))?;
            ranges.push(format!("mod={:x}-{:x}", found.base, found.end));
        }
        if ranges.len() > 8 {
            return Err("no maximo 8 modulos".into());
        }
        let _ = self.monitor("api clear")?;
        for command in api_monitor::spec_commands(&self.monitors.names, 240) {
            let reply = self.monitor(&command)?;
            if !reply.contains("especificacoes") {
                return Err(reply.trim().to_string());
            }
        }
        // Os registros de antes não interessam.
        let _ = self.fetch_records();
        let command = if ranges.is_empty() { "api on all".to_string() } else { format!("api on {}", ranges.join(" ")) };
        let reply = self.monitor(&command)?;
        if !reply.contains("ligado") {
            return Err(reply.trim().to_string());
        }
        self.monitor("stream on")?;
        self.monitors.api_enabled = true;
        Ok(format!("{} ({} exports com nome)", reply.trim(), self.monitors.names.len()))
    }

    pub fn api_monitor_stop(&mut self) -> Result<String, String> {
        self.require_stopped()?;
        let reply = self.monitor("api off")?;
        self.monitors.api_enabled = false;
        if !self.monitors.irp_enabled {
            let _ = self.monitor("stream off");
        }
        let _ = self.fetch_records();
        Ok(reply.trim().to_string())
    }

    pub fn irp_trace_start(&mut self) -> Result<String, String> {
        self.require_stopped()?;
        let _ = self.fetch_records();
        let reply = self.monitor("irptrace on")?;
        if !reply.contains("ligado") {
            return Err(reply.trim().to_string());
        }
        self.monitor("stream on")?;
        self.monitors.irp_enabled = true;
        Ok(reply.trim().to_string())
    }

    pub fn irp_trace_stop(&mut self) -> Result<String, String> {
        self.require_stopped()?;
        let reply = self.monitor("irptrace off")?;
        self.monitors.irp_enabled = false;
        if !self.monitors.api_enabled {
            let _ = self.monitor("stream off");
        }
        let _ = self.fetch_records();
        Ok(reply.trim().to_string())
    }

    /// Esquece as chamadas e os IRPs guardados.
    pub fn clear_monitors(&mut self) {
        self.monitors.api_rows.clear();
        self.monitors.api_trimmed = 0;
        self.monitors.irps = Timeline::default();
        self.monitors.generation += 1;
    }

    /// O nome de um DRIVER_OBJECT (`\Driver\X`), pelo DriverName.
    pub fn driver_name(&mut self, driver: u64) -> String {
        if driver == 0 {
            return "(sem driver)".into();
        }
        let offset = self.type_database().and_then(|types| types.field_offset("_DRIVER_OBJECT", "DriverName")).unwrap_or(0x38);
        super::types::read_unicode_string(self, driver + offset).filter(|name| !name.is_empty()).unwrap_or_else(|| format!("{driver:#x}"))
    }

    // ---- exploradores ----

    /// Todas as páginas de um comando paginado (`mais: N`).
    fn pages(&mut self, command: &str) -> Result<Vec<String>, String> {
        let mut pages = Vec::new();
        let mut start = 0;
        for _ in 0..256 {
            let text = self.monitor(&format!("{command} {start}"))?;
            let next = explore::more(&text);
            pages.push(text);
            match next {
                Some(next) if next > start => start = next,
                _ => break,
            }
        }
        Ok(pages)
    }

    fn quoted(path: &str) -> String {
        if path.contains(char::is_whitespace) {
            format!("\"{path}\"")
        } else {
            path.to_string()
        }
    }

    /// Uma chave do Registro e as subchaves.
    pub fn registry_keys(&mut self, path: &str) -> Result<(KeyInfo, Vec<SubKey>), String> {
        let mut info = None;
        let mut keys = Vec::new();
        for page in self.pages(&format!("reg keys {}", Self::quoted(path)))? {
            let (header, mut subkeys) = explore::parse_keys(&page)?;
            info.get_or_insert(header);
            keys.append(&mut subkeys);
        }
        Ok((info.unwrap_or_default(), keys))
    }

    /// Os valores de uma chave (os dados cortados em 96 bytes).
    pub fn registry_values(&mut self, path: &str) -> Result<Vec<RegistryValue>, String> {
        let mut values = Vec::new();
        for page in self.pages(&format!("reg values {}", Self::quoted(path)))? {
            values.append(&mut explore::parse_values(&page)?);
        }
        Ok(values)
    }

    /// Um valor inteiro (os dados em vários pedidos).
    pub fn registry_value(&mut self, path: &str, name: &str) -> Result<RegistryValue, String> {
        let shown_name = if name.is_empty() { "(padrao)" } else { name };
        let mut value: Option<RegistryValue> = None;
        let mut offset = 0;
        loop {
            let text = self.monitor(&format!("reg value {} {} {offset}", Self::quoted(path), Self::quoted(shown_name)))?;
            let (part, _) = explore::parse_value(&text)?;
            let received = part.data.len();
            match value.as_mut() {
                Some(value) => value.data.extend_from_slice(&part.data),
                None => value = Some(part),
            }
            offset += received;
            let size = value.as_ref().map_or(0, |value| value.size);
            if received == 0 || offset >= size || offset > 1 << 20 {
                break;
            }
        }
        value.ok_or_else(|| "valor vazio".into())
    }

    /// Um diretório do namespace do Object Manager.
    pub fn object_directory(&mut self, path: &str) -> Result<ObjectDirectory, String> {
        let mut directory: Option<ObjectDirectory> = None;
        for page in self.pages(&format!("objdir {}", Self::quoted(path)))? {
            let mut part = explore::parse_object_directory(&page)?;
            match directory.as_mut() {
                Some(directory) => directory.entries.append(&mut part.entries),
                None => directory = Some(part),
            }
        }
        directory.ok_or_else(|| "diretorio vazio".into())
    }

    /// Uma pasta do volume do kernel.
    pub fn file_list(&mut self, path: &str) -> Result<Vec<FileEntry>, String> {
        let mut entries = Vec::new();
        for page in self.pages(&format!("fs ls {}", Self::quoted(path)))? {
            let (_, _, mut part) = explore::parse_files(&page)?;
            entries.append(&mut part);
        }
        Ok(entries)
    }

    /// Lê até `length` bytes de um arquivo do volume a partir de `offset`;
    /// devolve o tamanho do arquivo e os bytes.
    pub fn file_read(&mut self, path: &str, offset: u64, length: u64) -> Result<(u64, Vec<u8>), String> {
        let mut bytes = Vec::new();
        let mut size = 0;
        while (bytes.len() as u64) < length {
            let at = offset + bytes.len() as u64;
            let want = (length - bytes.len() as u64).min(1400);
            let text = self.monitor(&format!("fs read {} {at} {want}", Self::quoted(path)))?;
            let (total, _, part) = explore::parse_file_data(&text)?;
            size = total;
            if part.is_empty() {
                break;
            }
            bytes.extend_from_slice(&part);
            if at + part.len() as u64 >= total {
                break;
            }
        }
        Ok((size, bytes))
    }

    // ---- vista como tipo ----

    /// Os tipos de um PDB de usuário (o do módulo que contém `address`, ou
    /// do módulo pelo nome), carregados uma vez.
    pub fn user_type_database(&mut self, module: &str) -> Result<Arc<TypeDb>, String> {
        let address = match super::parse_number(module) {
            Some(address) => address,
            None => self.symbols.module_named(module).map(|found| found.base).ok_or_else(|| format!("modulo {module} nao carregado"))?,
        };
        // Os tipos vêm do PDB: o que ainda não chegou é esperado.
        self.symbols.wait_pdb_at(address);
        let found = self.symbols.module_at(address).ok_or_else(|| format!("modulo {module} nao carregado"))?;
        let path = found.pdb.clone().ok_or_else(|| format!("{}: sem PDB ({})", found.name, found.source))?;
        if let Some(types) = self.monitors.user_types.get(&path) {
            return Ok(Arc::clone(types));
        }
        let types = Arc::new(TypeDb::load(&path)?);
        self.monitors.user_types.insert(path, Arc::clone(&types));
        Ok(types)
    }

    /// Os tipos para um nome `[módulo!]tipo`: `nt!`/sem módulo é o PDB do
    /// ntoskrnl; outro módulo usa o PDB dele (de usuário ou de driver).
    pub fn types_for(&mut self, type_name: &str) -> Result<(Arc<TypeDb>, u32), String> {
        if let Some((module, name)) = type_name.split_once('!') {
            if !module.eq_ignore_ascii_case("nt") && !module.eq_ignore_ascii_case("ntoskrnl") && !module.eq_ignore_ascii_case("ntkrnlmp") {
                let types = self.user_type_database(module)?;
                let index = types.find(name).ok_or_else(|| format!("tipo {name} nao encontrado no PDB de {module}"))?;
                return Ok((types, index));
            }
        }
        let types = self.type_database().ok_or_else(|| self.types_note.clone())?;
        let index = types.find(type_name).ok_or_else(|| format!("tipo {type_name} nao encontrado no PDB do ntoskrnl"))?;
        Ok((types, index))
    }

    /// A árvore de `type_name` em `address`.
    pub fn struct_view(&mut self, type_name: &str, address: u64, expanded: &HashSet<String>, lists: &HashMap<String, ListElement>) -> Result<(Arc<TypeDb>, u32, Vec<Row>), String> {
        let (types, index) = self.types_for(type_name)?;
        let mut rows = struct_view::build(&types, self, &struct_view::Request { ty: index, address, expanded, lists }, &|_| None);
        // O símbolo dos ponteiros (depois: a árvore lê a memória pela sessão).
        for row in &mut rows {
            if let (struct_view::RowKind::Pointer, Some(value)) = (row.kind, row.number) {
                if let Some(name) = self.symbols.name_at(value) {
                    row.value = format!("{} {name}", row.value);
                }
            }
        }
        Ok((types, index, rows))
    }

    /// Grava um campo escalar da vista (o texto do valor).
    pub fn struct_edit(&mut self, types: &TypeDb, ty: u32, address: u64, text: &str) -> Result<(), String> {
        self.require_stopped()?;
        let (address, bytes) = struct_view::encode_edit(types, self, ty, address, text)?;
        self.write_memory(address, &bytes)
    }

    // ---- snapshots e reprodução ----

    pub fn set_qemu_monitor(&mut self, address: Option<String>) {
        self.qemu_monitor = address;
    }

    fn hmp(&self, line: &str, timeout: Duration) -> Result<String, String> {
        let address = self.qemu_monitor.as_deref().ok_or("sem o monitor do QEMU (o QEMU precisa ser aberto pelo depurador)")?;
        hmp::command(address, line, timeout)
    }

    /// Grava o estado da máquina num snapshot (`savevm`). Com o depurador
    /// do kernel a máquina está parada no laço da sessão: a volta ao
    /// snapshot volta a esse ponto.
    pub fn snapshot_save(&mut self, name: &str) -> Result<String, String> {
        if !hmp::valid_name(name) {
            return Err(format!("nome de snapshot invalido: {name:?} (letras, digitos, - _ .)"));
        }
        let output = self.hmp(&format!("savevm {name}"), Duration::from_secs(600))?;
        if let Some(error) = hmp::error_text(&output) {
            return Err(format!("savevm: {error}"));
        }
        Ok(format!("snapshot {name} gravado"))
    }

    /// Volta a um snapshot (`loadvm`) e relê a parada.
    pub fn snapshot_load(&mut self, name: &str) -> Result<String, String> {
        if !hmp::valid_name(name) {
            return Err(format!("nome de snapshot invalido: {name:?}"));
        }
        let output = self.hmp(&format!("loadvm {name}"), Duration::from_secs(600))?;
        if let Some(error) = hmp::error_text(&output) {
            return Err(format!("loadvm: {error}"));
        }
        self.after_restore()?;
        Ok(format!("de volta ao snapshot {name}: {}", self.last_stop()))
    }

    pub fn snapshot_delete(&mut self, name: &str) -> Result<String, String> {
        if !hmp::valid_name(name) {
            return Err(format!("nome de snapshot invalido: {name:?}"));
        }
        let output = self.hmp(&format!("delvm {name}"), Duration::from_secs(120))?;
        if let Some(error) = hmp::error_text(&output) {
            return Err(format!("delvm: {error}"));
        }
        Ok(format!("snapshot {name} apagado"))
    }

    pub fn snapshot_list(&mut self) -> Result<Vec<hmp::Snapshot>, String> {
        let output = self.hmp("info snapshots", Duration::from_secs(30))?;
        if let Some(error) = hmp::error_text(&output) {
            return Err(error);
        }
        Ok(hmp::parse_snapshots(&output))
    }

    /// O estado do record/replay do QEMU (`info replay`).
    pub fn replay_status(&mut self) -> Result<String, String> {
        self.hmp("info replay", Duration::from_secs(10))
    }

    /// Depois do `loadvm`: a máquina voltou ao ponto do snapshot (com o
    /// depurador, parada na sessão); a parada é lida de novo e os
    /// breakpoints da sessão voltam a ser gravados (a memória voltou ao
    /// estado do snapshot).
    pub fn after_restore(&mut self) -> Result<(), String> {
        self.resync_after_restore()
    }

    // ---- reprodução (gdbstub do QEMU) ----

    /// Passa a sessão para o modo de reprodução (antes do `attach`).
    pub fn set_replay(&mut self, modules: Vec<(u64, u64, String)>) {
        self.replay = Some(Replay { modules, reverse: false });
    }

    pub fn is_replay(&self) -> bool {
        self.replay.is_some()
    }

    /// A reprodução aceita os passos para trás.
    pub fn reverse_supported(&self) -> bool {
        self.replay.as_ref().is_some_and(|replay| replay.reverse)
    }

    /// Um passo para trás (`bs`): a instrução anterior.
    pub fn reverse_step(&mut self) -> Result<String, String> {
        self.require_reverse()?;
        self.resume("bs")?;
        self.wait_stop(Duration::from_secs(600))
    }

    /// Para trás até o breakpoint ou o vigia anterior (`bc`); sem nenhum,
    /// até o começo da gravação.
    pub fn reverse_continue(&mut self) -> Result<String, String> {
        self.require_reverse()?;
        self.resume("bc")?;
        self.wait_stop(Duration::from_secs(1800))
    }

    fn require_reverse(&self) -> Result<(), String> {
        match &self.replay {
            Some(replay) if replay.reverse => Ok(()),
            Some(_) => Err("o gdbstub do QEMU nao aceita passos para tras (a reproducao precisa de um snapshot inicial)".into()),
            None => Err("passos para tras so na reproducao de uma gravacao (abra com --replay)".into()),
        }
    }

    /// O `qSupported` da reprodução diz se há passos para trás.
    pub(crate) fn note_replay_features(&mut self, supported: &str) {
        if let Some(replay) = self.replay.as_mut() {
            replay.reverse = supported.contains("ReverseStep+") || supported.contains("ReverseContinue+");
        }
    }

    /// Os módulos de agora, para guardar ao lado de uma gravação.
    pub fn module_list(&self) -> Vec<(u64, u64, String)> {
        self.symbols.modules.iter().filter(|module| !module.user).map(|module| (module.base, module.end, module.path.clone())).collect()
    }
}

impl Client {
    /// Os comandos de texto destas extensões (`commands.rs` chama).
    pub(crate) fn re_command(&mut self, command: &str, words: &[&str]) -> Result<String, String> {
        let number = |index: usize, default: u64| words.get(index).and_then(|word| super::parse_number(word)).unwrap_or(default);
        let rest_from = |index: usize| words.iter().skip(index).copied().collect::<Vec<_>>().join(" ");
        match command {
            "apimon" => match words.first().copied().unwrap_or("status") {
                "on" => {
                    let modules: Vec<String> = words[1..].iter().map(|word| word.to_string()).collect();
                    self.api_monitor_start(&modules)
                }
                "off" => self.api_monitor_stop(),
                "clear" => {
                    self.clear_monitors();
                    Ok("chamadas e IRPs guardados esquecidos".into())
                }
                "save" => {
                    let path = words.get(1).ok_or("uso: apimon save <arq.csv>")?;
                    if self.is_stopped() {
                        let _ = self.fetch_records();
                    }
                    std::fs::write(path, api_monitor::to_csv(&self.monitors.api_rows)).map_err(|error| format!("{path}: {error}"))?;
                    Ok(format!("{} chamadas em {path}", self.monitors.api_rows.len()))
                }
                verb @ ("show" | "fails") => {
                    if self.is_stopped() {
                        self.fetch_records()?;
                    }
                    let count = number(1, 40) as usize;
                    let text = rest_from(2).to_ascii_lowercase();
                    let rows: Vec<&ApiRow> = self
                        .monitors
                        .api_rows
                        .iter()
                        .filter(|row| (verb == "show" || row.failed) && (text.is_empty() || format!("{} {} {} {}", row.module, row.name, row.arguments, row.result).to_ascii_lowercase().contains(&text)))
                        .collect();
                    let start = rows.len().saturating_sub(count);
                    let mut output: String = rows[start..].iter().map(|row| api_monitor::format_row(row) + "\n").collect();
                    output.push_str(&format!("({} de {} chamadas; perdidas {} no fluxo, {} no alvo)", rows.len() - start, self.monitors.api_rows.len(), self.monitors.collector.lost, self.monitors.target_dropped));
                    Ok(output)
                }
                _ => {
                    let target = self.monitor("api status")?;
                    Ok(format!("{target}chamadas guardadas: {}", self.monitors.api_rows.len()))
                }
            },
            "irptrace" => match words.first().copied().unwrap_or("show") {
                "on" => self.irp_trace_start(),
                "off" => self.irp_trace_stop(),
                "irp" => {
                    if self.is_stopped() {
                        self.fetch_records()?;
                    }
                    let wanted = words.get(1).ok_or("uso: irptrace irp <n|endereco>")?;
                    let value = super::parse_number(wanted).ok_or("numero ou endereco invalido")?;
                    let life = self.monitors.irps.irps.iter().rev().find(|life| life.number as u64 == value || life.address == value).cloned().ok_or_else(|| format!("IRP {wanted} nao visto"))?;
                    Ok(self.describe_irp(&life))
                }
                _ => {
                    if self.is_stopped() {
                        self.fetch_records()?;
                    }
                    let count = number(1, 20) as usize;
                    let text = rest_from(2).to_ascii_lowercase();
                    let lives = self.monitors.irps.irps.clone();
                    let mut parts = Vec::new();
                    for life in lives.iter().rev() {
                        if parts.len() == count {
                            break;
                        }
                        let description = self.describe_irp(life);
                        if text.is_empty() || description.to_ascii_lowercase().contains(&text) {
                            parts.push(description);
                        }
                    }
                    let shown = parts.len();
                    parts.reverse();
                    Ok(format!("{}({shown} de {} IRPs)", parts.concat(), lives.len()))
                }
            },
            "reg" => {
                let path = rest_from(0);
                let path = if path.is_empty() { "\\Registry".to_string() } else { path };
                let (info, keys) = self.registry_keys(&path)?;
                let values = self.registry_values(&path)?;
                let hive = if info.hive.is_empty() { String::new() } else { format!(", hive {}", info.hive) };
                let mut output = format!("{}  ({} subchaves, {} valores, escrita {}{hive})\n", info.path, info.subkeys, info.values, explore::nt_time(info.last_write));
                for key in keys {
                    output.push_str(&format!("  [{}]  ({} subchaves, {} valores)\n", key.name, key.subkeys, key.values));
                }
                for value in values {
                    output.push_str(&format!("  {:<32} {:<14} {}\n", if value.name.is_empty() { "(padrao)" } else { &value.name }, value.kind_name(), value.display()));
                }
                Ok(output)
            }
            "regv" => {
                let (path, name) = match words {
                    [path, name @ ..] if !name.is_empty() => (path.to_string(), name.join(" ")),
                    _ => return Err("uso: regv <caminho> <nome> ((padrao) para o valor sem nome)".into()),
                };
                let value = self.registry_value(&path, &name)?;
                Ok(format!("{} {} ({} bytes): {}", if value.name.is_empty() { "(padrao)" } else { &value.name }, value.kind_name(), value.size, value.display()))
            }
            "objdir" => {
                let path = rest_from(0);
                let directory = self.object_directory(if path.is_empty() { "\\" } else { &path })?;
                let mut output = format!("{} ({}, {} objetos)\n", directory.path, directory.kind, directory.count);
                for entry in directory.entries {
                    output.push_str(&format!("  {:<40} {:<20} {:#018x} {}\n", entry.name, entry.kind, entry.body, entry.target));
                }
                Ok(output)
            }
            "fsls" => {
                let path = rest_from(0);
                let entries = self.file_list(if path.is_empty() { "/" } else { &path })?;
                Ok(entries.iter().map(|entry| format!("  {:<5} {:>12} {}  {}\n", if entry.directory { "<DIR>" } else { "" }, entry.size, explore::nt_time(entry.modified), entry.name)).collect())
            }
            "fscat" => {
                let path = words.first().ok_or("uso: fscat <caminho> [deslocamento] [bytes]")?;
                let offset = number(1, 0);
                let (size, bytes) = self.file_read(path, offset, number(2, 512).min(1 << 20))?;
                let mut output = format!("{path}: {size} bytes\n");
                for (row, chunk) in bytes.chunks(16).enumerate() {
                    let text: String = chunk.iter().map(|&byte| if (0x20..0x7F).contains(&byte) { byte as char } else { '.' }).collect();
                    output.push_str(&format!("{:08x}  {:<48} {text}\n", offset + row as u64 * 16, chunk.iter().map(|byte| format!("{byte:02x} ")).collect::<String>()));
                }
                Ok(output)
            }
            "dtv" => {
                let usage = "uso: dtv [modulo!]<tipo> <expr> [abertos,...]";
                let type_name = words.first().ok_or(usage)?;
                let address = self.evaluate(words.get(1).ok_or(usage)?)?;
                let expanded: HashSet<String> = words.get(2).map(|list| list.split(',').map(str::to_string).collect()).unwrap_or_default();
                let (types, index, rows) = self.struct_view(type_name, address, &expanded, &HashMap::new())?;
                Ok(format!("{} em {address:#x} ({:#x} bytes)\n{}", types.name(index), types.size(index), struct_view::format_rows(&rows)))
            }
            "rstep" => self.reverse_step(),
            "rcont" => self.reverse_continue(),
            "nmi" => {
                // O botão de NMI do QEMU (pelo LINT1 do BSP): o depurador do
                // alvo para mesmo num trecho com as interrupções desligadas,
                // onde o 0x03 do `break` não é visto.
                let output = self.hmp("nmi", Duration::from_secs(10))?;
                if let Some(error) = hmp::error_text(&output) {
                    return Err(format!("nmi: {error}"));
                }
                Ok("NMI mandada pelo monitor do QEMU (a parada chega no wait-stop)".into())
            }
            "snap" => match words.first().copied().unwrap_or("list") {
                "save" => self.snapshot_save(words.get(1).ok_or("uso: snap save <nome>")?),
                "load" => self.snapshot_load(words.get(1).ok_or("uso: snap load <nome>")?),
                "del" => self.snapshot_delete(words.get(1).ok_or("uso: snap del <nome>")?),
                _ => {
                    let snapshots = self.snapshot_list()?;
                    if snapshots.is_empty() {
                        return Ok("nenhum snapshot".into());
                    }
                    Ok(snapshots.iter().map(|snapshot| format!("  {:<20} {:>12} {} {}\n", snapshot.tag, snapshot.vm_size, snapshot.date, snapshot.vm_clock)).collect())
                }
            },
            other => Err(format!("comando desconhecido: {other}")),
        }
    }

    /// O texto de um IRP com os nomes dos drivers e os símbolos.
    pub fn describe_irp(&mut self, life: &super::irp_timeline::IrpLife) -> String {
        let mut drivers = life.drivers();
        for step in &life.steps {
            if let super::irp_timeline::Step::Routine(call) = step {
                drivers.push(call.driver);
            }
        }
        let mut names = HashMap::new();
        for driver in drivers {
            if let std::collections::hash_map::Entry::Vacant(entry) = names.entry(driver) {
                entry.insert(self.driver_name(driver));
            }
        }
        let symbols = &self.symbols;
        super::irp_timeline::describe(life, &|address| if address == 0 { "-".to_string() } else { symbols.describe(address) }, &|driver| names.get(&driver).cloned().unwrap_or_else(|| format!("{driver:#x}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_files() {
        let modules = vec![(0xfffff800_00000000, 0xfffff800_00100000, "\\SystemRoot\\system32\\ntoskrnl.exe".to_string()), (0x1000, 0x2000, "C:\\com espaco\\x.sys".to_string())];
        assert_eq!(parse_modules(&modules_text(&modules)), modules);
        assert_eq!(modules_file(Path::new("build/x/gravacao.bin")), PathBuf::from("build/x/gravacao.bin.modulos"));
    }
}
