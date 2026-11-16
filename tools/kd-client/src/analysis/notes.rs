//! Comentários, rótulos, marcadores e patches guardados por módulo + RVA:
//! valem de novo quando o módulo carrega em outra base (ASLR, relocação)
//! e passam de uma sessão para a outra num arquivo de texto.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

/// Um lugar no código: módulo (nome em minúsculas, sem extensão: `ntdll`,
/// `kernel`, `acpi`) e deslocamento; módulo vazio é um endereço absoluto.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Location {
    pub module: String,
    pub offset: u64,
}

impl Location {
    /// Um lugar dentro de um módulo (o nome vai para minúsculas).
    pub fn new(module: &str, offset: u64) -> Self {
        Location { module: module.to_ascii_lowercase(), offset }
    }

    /// Um endereço fora dos módulos.
    pub fn absolute(address: u64) -> Self {
        Location { module: String::new(), offset: address }
    }

    /// `ntdll+0x1234` ou `0x...`.
    pub fn display(&self) -> String {
        if self.module.is_empty() {
            format!("{:#x}", self.offset)
        } else {
            format!("{}+{:#x}", self.module, self.offset)
        }
    }
}

/// Troca `\`, tabulação, quebra de linha e retorno por escapes.
fn escape(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '\t' => output.push_str("\\t"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            other => output.push(other),
        }
    }
    output
}

fn unescape(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }
        match characters.next() {
            Some('t') => output.push('\t'),
            Some('n') => output.push('\n'),
            Some('r') => output.push('\r'),
            Some(other) => output.push(other),
            None => output.push('\\'),
        }
    }
    output
}

fn parse_hex(text: &str) -> Option<u64> {
    let text = text.trim();
    u64::from_str_radix(text.strip_prefix("0x").unwrap_or(text), 16).ok()
}

/// As notas de uma sessão.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Notes {
    pub comments: BTreeMap<Location, String>,
    pub labels: BTreeMap<Location, String>,
    pub bookmarks: BTreeSet<Location>,
}

impl Notes {
    /// Grava o comentário (texto vazio apaga).
    pub fn set_comment(&mut self, at: Location, text: &str) {
        let text = text.trim();
        if text.is_empty() {
            self.comments.remove(&at);
        } else {
            self.comments.insert(at, text.to_string());
        }
    }

    /// Grava o rótulo (nome vazio apaga).
    pub fn set_label(&mut self, at: Location, name: &str) {
        let name = name.trim();
        if name.is_empty() {
            self.labels.remove(&at);
        } else {
            self.labels.insert(at, name.to_string());
        }
    }

    /// Liga ou tira o marcador; devolve se ficou ligado.
    pub fn toggle_bookmark(&mut self, at: Location) -> bool {
        if self.bookmarks.remove(&at) {
            false
        } else {
            self.bookmarks.insert(at);
            true
        }
    }

    /// O lugar de um rótulo pelo nome (o exato antes, depois sem diferença
    /// de caixa).
    pub fn label_named(&self, name: &str) -> Option<&Location> {
        let name = name.trim();
        self.labels.iter().find(|(_, label)| label.as_str() == name).or_else(|| self.labels.iter().find(|(_, label)| label.eq_ignore_ascii_case(name))).map(|(location, _)| location)
    }

    /// O texto do arquivo: uma nota por linha (`comentario`, `rotulo` ou
    /// `marcador`, módulo, deslocamento e o texto), separados por tabulação.
    pub fn to_text(&self) -> String {
        let mut output = String::from("# notas do opennt-re: tipo, modulo, deslocamento e texto\n");
        for (location, text) in &self.comments {
            let _ = writeln!(output, "comentario\t{}\t{:#x}\t{}", escape(&location.module), location.offset, escape(text));
        }
        for (location, name) in &self.labels {
            let _ = writeln!(output, "rotulo\t{}\t{:#x}\t{}", escape(&location.module), location.offset, escape(name));
        }
        for location in &self.bookmarks {
            let _ = writeln!(output, "marcador\t{}\t{:#x}", escape(&location.module), location.offset);
        }
        output
    }

    /// Lê o texto de `to_text`.
    pub fn from_text(text: &str) -> Result<Notes, String> {
        let mut notes = Notes::default();
        for (index, line) in text.lines().enumerate() {
            let line = line.trim_end_matches('\r');
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split('\t').collect();
            let fail = || format!("linha {}: nota invalida: {line}", index + 1);
            let (Some(kind), Some(module), Some(offset)) = (fields.first(), fields.get(1), fields.get(2).and_then(|text| parse_hex(text))) else { return Err(fail()) };
            let location = Location { module: unescape(module), offset };
            match *kind {
                "comentario" => notes.set_comment(location, &unescape(fields.get(3).ok_or_else(fail)?)),
                "rotulo" => notes.set_label(location, &unescape(fields.get(3).ok_or_else(fail)?)),
                "marcador" => {
                    notes.bookmarks.insert(location);
                }
                _ => return Err(fail()),
            }
        }
        Ok(notes)
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
        }
        std::fs::write(path, self.to_text()).map_err(|error| format!("{}: {error}", path.display()))
    }

    /// Lê o arquivo; ausente, as notas vêm vazias.
    pub fn load(path: &Path) -> Result<Notes, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => Notes::from_text(&text).map_err(|error| format!("{}: {error}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Notes::default()),
            Err(error) => Err(format!("{}: {error}", path.display())),
        }
    }

    /// Junta outras notas (as de `other` valem sobre as daqui).
    pub fn merge(&mut self, other: Notes) {
        self.comments.extend(other.comments);
        self.labels.extend(other.labels);
        self.bookmarks.extend(other.bookmarks);
    }
}

/// Bytes trocados no alvo a partir de `address`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Patch {
    pub location: Location,
    pub address: u64,
    pub original: Vec<u8>,
    pub patched: Vec<u8>,
}

impl Patch {
    fn contains(&self, address: u64) -> bool {
        address >= self.address && address - self.address < self.patched.len() as u64
    }
}

/// A lista de patches da sessão.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Patches {
    pub list: Vec<Patch>,
}

/// Cada byte trocado: lugar, original e novo.
type ByteMap = BTreeMap<u64, (Location, u8, u8)>;

impl Patches {
    fn bytes(&self) -> ByteMap {
        let mut map = ByteMap::new();
        for patch in &self.list {
            for (index, &new) in patch.patched.iter().enumerate() {
                let location = Location { module: patch.location.module.clone(), offset: patch.location.offset + index as u64 };
                let original = patch.original.get(index).copied().unwrap_or(new);
                map.insert(patch.address + index as u64, (location, original, new));
            }
        }
        map
    }

    /// Os bytes viram trechos contíguos (mesmo módulo, deslocamentos
    /// seguidos).
    fn from_bytes(map: ByteMap) -> Vec<Patch> {
        let mut list: Vec<Patch> = Vec::new();
        for (address, (location, original, new)) in map {
            if let Some(last) = list.last_mut() {
                let next = last.address + last.patched.len() as u64;
                if next == address && last.location.module == location.module && last.location.offset + last.patched.len() as u64 == location.offset {
                    last.original.push(original);
                    last.patched.push(new);
                    continue;
                }
            }
            list.push(Patch { location, address, original: vec![original], patched: vec![new] });
        }
        list
    }

    /// Junta um patch: sobre bytes já trocados fica o original mais antigo,
    /// e um byte que volta ao original sai da lista.
    pub fn add(&mut self, patch: Patch) {
        let mut map = self.bytes();
        for (index, &new) in patch.patched.iter().enumerate() {
            let address = patch.address + index as u64;
            match map.get_mut(&address) {
                Some(entry) => entry.2 = new,
                None => {
                    let location = Location { module: patch.location.module.clone(), offset: patch.location.offset + index as u64 };
                    let original = patch.original.get(index).copied().unwrap_or(new);
                    map.insert(address, (location, original, new));
                }
            }
        }
        map.retain(|_, (_, original, new)| original != new);
        self.list = Patches::from_bytes(map);
    }

    /// Tira o patch que cobre `address` (quem chama devolve os bytes
    /// originais ao alvo).
    pub fn remove(&mut self, address: u64) -> Option<Patch> {
        let index = self.list.iter().position(|patch| patch.contains(address))?;
        Some(self.list.remove(index))
    }

    /// O patch que cobre `address`.
    pub fn covering(&self, address: u64) -> Option<&Patch> {
        self.list.iter().find(|patch| patch.contains(address))
    }

    /// A exportação: um bloco por módulo (`>ntdll`), com uma linha por byte
    /// trocado (`00001234:90->CC`: RVA, original e novo). Endereços fora de
    /// módulos ficam sob `>` com 16 dígitos.
    pub fn export(&self) -> String {
        let mut modules: BTreeMap<String, Vec<(u64, u8, u8)>> = BTreeMap::new();
        for (_, (location, original, new)) in self.bytes() {
            modules.entry(location.module).or_default().push((location.offset, original, new));
        }
        let mut output = String::new();
        for (module, mut entries) in modules {
            entries.sort_unstable();
            let _ = writeln!(output, ">{module}");
            for (offset, original, new) in entries {
                if module.is_empty() {
                    let _ = writeln!(output, "{offset:016X}:{original:02X}->{new:02X}");
                } else {
                    let _ = writeln!(output, "{offset:08X}:{original:02X}->{new:02X}");
                }
            }
        }
        output
    }

    /// Lê uma exportação: (lugar, RVA ou endereço absoluto, original,
    /// novo) por byte. O número é o mesmo `Location::offset`; quem importa
    /// soma a base do módulo carregado.
    pub fn import(text: &str) -> Result<Vec<(Location, u64, u8, u8)>, String> {
        let mut module: Option<String> = None;
        let mut output = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(name) = line.strip_prefix('>') {
                module = Some(name.trim().to_ascii_lowercase());
                continue;
            }
            let fail = || format!("linha {}: patch invalido: {line}", index + 1);
            let module = module.clone().ok_or_else(|| format!("linha {}: byte antes do cabecalho '>modulo'", index + 1))?;
            let (offset, change) = line.split_once(':').ok_or_else(fail)?;
            let (original, new) = change.split_once("->").ok_or_else(fail)?;
            let offset = u64::from_str_radix(offset.trim(), 16).map_err(|_| fail())?;
            let original = u8::from_str_radix(original.trim(), 16).map_err(|_| fail())?;
            let new = u8::from_str_radix(new.trim(), 16).map_err(|_| fail())?;
            output.push((Location { module, offset }, offset, original, new));
        }
        Ok(output)
    }

    /// O texto da sessão: um patch por linha (`patch`, módulo,
    /// deslocamento, endereço, bytes originais e novos em hexadecimal).
    pub fn to_text(&self) -> String {
        let hex = |bytes: &[u8]| bytes.iter().map(|byte| format!("{byte:02X}")).collect::<String>();
        let mut output = String::from("# patches do opennt-re: modulo, deslocamento, endereco, original e novo\n");
        for patch in &self.list {
            let _ = writeln!(output, "patch\t{}\t{:#x}\t{:#x}\t{}\t{}", escape(&patch.location.module), patch.location.offset, patch.address, hex(&patch.original), hex(&patch.patched));
        }
        output
    }

    /// Lê o texto de `to_text`.
    pub fn from_text(text: &str) -> Result<Patches, String> {
        let bytes = |text: &str| -> Option<Vec<u8>> {
            if text.len() % 2 != 0 {
                return None;
            }
            (0..text.len() / 2).map(|index| u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok()).collect()
        };
        let mut patches = Patches::default();
        for (index, line) in text.lines().enumerate() {
            let line = line.trim_end_matches('\r');
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split('\t').collect();
            let fail = || format!("linha {}: patch invalido: {line}", index + 1);
            if fields.len() != 6 || fields[0] != "patch" {
                return Err(fail());
            }
            let offset = parse_hex(fields[2]).ok_or_else(fail)?;
            let address = parse_hex(fields[3]).ok_or_else(fail)?;
            let original = bytes(fields[4]).ok_or_else(fail)?;
            let patched = bytes(fields[5]).ok_or_else(fail)?;
            if original.len() != patched.len() || patched.is_empty() {
                return Err(fail());
            }
            patches.list.push(Patch { location: Location { module: unescape(fields[1]), offset }, address, original, patched });
        }
        Ok(patches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locations() {
        assert_eq!(Location::new("NTDLL", 0x1234).display(), "ntdll+0x1234");
        assert_eq!(Location::absolute(0xfffff800_00001000).display(), "0xfffff80000001000");
        assert!(Location::new("a", 5) < Location::new("b", 1));
    }

    #[test]
    fn notes_roundtrip() {
        let mut notes = Notes::default();
        notes.set_comment(Location::new("ntdll", 0x10), "abre o arquivo\tcom \\ e\nduas linhas");
        notes.set_label(Location::new("kernel", 0x2000), "laco_principal");
        notes.set_label(Location::absolute(0x7000), "solto");
        assert!(notes.toggle_bookmark(Location::new("acpi", 0x30)));
        assert!(notes.toggle_bookmark(Location::new("acpi", 0x40)));
        assert!(!notes.toggle_bookmark(Location::new("acpi", 0x40)));
        let text = notes.to_text();
        assert_eq!(text.lines().filter(|line| !line.starts_with('#')).count(), 4);
        let back = Notes::from_text(&text).unwrap();
        assert_eq!(back, notes);
        assert_eq!(back.label_named("LACO_PRINCIPAL"), Some(&Location::new("kernel", 0x2000)));
        assert_eq!(back.label_named("nenhum"), None);
        // Texto vazio apaga.
        let mut edited = back.clone();
        edited.set_comment(Location::new("ntdll", 0x10), "  ");
        assert!(edited.comments.is_empty());
        assert!(Notes::from_text("comentario\tx").is_err());
        assert!(Notes::from_text("outro\tx\t0x1\ty").unwrap_err().starts_with("linha 1"));
        let mut merged = Notes::default();
        merged.set_label(Location::new("kernel", 0x2000), "velho");
        merged.merge(notes.clone());
        assert_eq!(merged.labels[&Location::new("kernel", 0x2000)], "laco_principal");
    }

    #[test]
    fn notes_file() {
        let directory = std::env::temp_dir().join(format!("opennt-notes-{}", std::process::id()));
        let path = directory.join("sessao").join("notas.txt");
        let _ = std::fs::remove_dir_all(&directory);
        assert_eq!(Notes::load(&path).unwrap(), Notes::default());
        let mut notes = Notes::default();
        notes.set_label(Location::new("ntdll", 0x1234), "LdrpInitialize_meu");
        notes.set_comment(Location::new("ntdll", 0x1234), "comentario");
        notes.save(&path).unwrap();
        assert_eq!(Notes::load(&path).unwrap(), notes);
        let _ = std::fs::remove_dir_all(&directory);
    }

    fn patch(address: u64, original: &[u8], patched: &[u8]) -> Patch {
        Patch { location: Location::new("ntdll", address - 0x1000), address, original: original.to_vec(), patched: patched.to_vec() }
    }

    #[test]
    fn patches_merge_and_revert() {
        let mut patches = Patches::default();
        patches.add(patch(0x1000, &[0x90, 0x90], &[0xCC, 0xCC]));
        assert_eq!(patches.list.len(), 1);
        // O segundo byte volta ao original; o terceiro é novo.
        patches.add(patch(0x1001, &[0xCC, 0x55], &[0x90, 0xEB]));
        assert_eq!(patches.list.len(), 2);
        assert_eq!(patches.list[0], patch(0x1000, &[0x90], &[0xCC]));
        assert_eq!(patches.list[1], patch(0x1002, &[0x55], &[0xEB]));
        assert_eq!(patches.covering(0x1002).map(|patch| patch.address), Some(0x1002));
        assert_eq!(patches.covering(0x1001), None);
        // Contíguos se juntam.
        patches.add(patch(0x1001, &[0x90], &[0x91]));
        assert_eq!(patches.list.len(), 1);
        assert_eq!(patches.list[0].original, vec![0x90, 0x90, 0x55]);
        assert_eq!(patches.list[0].patched, vec![0xCC, 0x91, 0xEB]);
        let removed = patches.remove(0x1002).unwrap();
        assert_eq!(removed.address, 0x1000);
        assert!(patches.list.is_empty());
        assert_eq!(patches.remove(0x1000), None);
    }

    #[test]
    fn patches_export_import_and_text() {
        let mut patches = Patches::default();
        patches.add(patch(0x1010, &[0x74, 0x05], &[0xEB, 0x05]));
        patches.add(Patch { location: Location::absolute(0xfffff800_00401000), address: 0xfffff800_00401000, original: vec![0x48], patched: vec![0x90] });
        let exported = patches.export();
        assert_eq!(exported, ">\nFFFFF80000401000:48->90\n>ntdll\n00000010:74->EB\n");
        let imported = Patches::import(&exported).unwrap();
        assert_eq!(imported, vec![(Location::absolute(0xfffff800_00401000), 0xfffff800_00401000, 0x48, 0x90), (Location::new("ntdll", 0x10), 0x10, 0x74, 0xEB)]);
        assert!(Patches::import("00000010:74->EB").is_err());
        assert!(Patches::import(">x\nzz").unwrap_err().starts_with("linha 2"));
        let text = patches.to_text();
        assert_eq!(Patches::from_text(&text).unwrap(), patches);
        assert!(Patches::from_text("patch\tx\t0x1\t0x2\t90\t").is_err());
    }
}
