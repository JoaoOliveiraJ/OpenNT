//! Tradução dos tipos do PDB em layouts Rust: o fecho transitivo das raízes,
//! as folhas `Field<T>`, os bitfields e as vistas sobrepostas.
//!
//! Para cada struct/união alcançada por valor a partir das raízes:
//!
//! - cada membro escalar vira uma célula `Field<T>` (ou `UnalignedField<T>`
//!   quando o offset não respeita o alinhamento natural, como nas structs
//!   empacotadas); ponteiros são `Field<u64>` com o tipo apontado guardado
//!   para o comentário; structs aninhadas por valor entram no fecho;
//! - bitfields se juntam ao inteiro de mesmo tamanho no mesmo offset (o par
//!   `Flags`/bits das uniões do NT) ou a um armazenamento sintético
//!   `bitfield_<offset>`;
//! - membros que se sobrepõem (uniões e structs anônimas que o PDB achata)
//!   são distribuídos em vistas por coloração gulosa na ordem de declaração;
//! - membros `...Fill` que só posicionam outros campos são omitidos.

use std::collections::{HashMap, HashSet, VecDeque};

use super::pdb::{self, Body, FieldMember, Tpi};
use super::Config;

pub type Key = (u32, bool);

const RUST_KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn", "for", "if", "impl", "in",
    "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "self", "Self", "static", "struct", "super",
    "trait", "true", "type", "unsafe", "use", "where", "while", "async", "await", "dyn", "abstract", "become", "box",
    "do", "final", "macro", "override", "priv", "typeof", "unsized", "virtual", "yield", "try", "gen", "union",
];

/// Tipo Rust de um tipo simples do PDB (índices < 0x1000).
fn simple_rust(code: u32) -> Option<&'static str> {
    Some(match code {
        0x08 | 0x12 | 0x74 => "i32",
        0x10 | 0x70 | 0x68 => "i8",
        0x20 | 0x69 | 0x30 => "u8",
        0x71 | 0x7A | 0x21 | 0x73 | 0x31 => "u16",
        0x7B | 0x22 | 0x75 | 0x32 => "u32",
        0x11 | 0x72 => "i16",
        0x13 | 0x76 => "i64",
        0x23 | 0x77 | 0x33 => "u64",
        0x14 | 0x24 | 0x78 | 0x79 => "[u64; 2]",
        0x40 => "f32",
        0x41 => "f64",
        0x42 => "[u8; 10]",
        _ => return None,
    })
}

/// Tamanho e alinhamento de um escalar Rust.
pub fn primitive(rust: &str) -> Result<(u64, u64), String> {
    Ok(match rust {
        "u8" | "i8" => (1, 1),
        "u16" | "i16" => (2, 2),
        "u32" | "i32" | "f32" => (4, 4),
        "u64" | "i64" | "f64" => (8, 8),
        "[u64; 2]" => (16, 8),
        "[u8; 10]" => (10, 1),
        other => return Err(format!("escalar sem traducao: {other}")),
    })
}

/// Inteiro sem sinal de mesma largura (para máscaras e bitfields).
pub fn unsigned(rust: &str) -> Option<&'static str> {
    Some(match rust {
        "u8" | "i8" => "u8",
        "u16" | "i16" => "u16",
        "u32" | "i32" => "u32",
        "u64" | "i64" => "u64",
        _ => return None,
    })
}

/// `_KTHREAD_STATE` -> `KthreadState`; `_IMAGE_NT_HEADERS64` -> `ImageNtHeaders64`.
pub fn camel(nt_name: &str) -> String {
    let mut out = String::new();
    for part in nt_name.trim_start_matches('_').split('_').filter(|part| !part.is_empty()) {
        let mut characters = part.chars();
        let first = characters.next().unwrap();
        out.extend(first.to_uppercase());
        if part.to_uppercase() == part {
            out.push_str(&characters.as_str().to_lowercase());
        } else {
            out.push_str(characters.as_str());
        }
    }
    if out.is_empty() || out.starts_with(|character: char| character.is_ascii_digit()) {
        out.insert(0, 'T');
    }
    out
}

/// `IoStatus` -> `io_status`, `CPUHint` -> `cpu_hint`; palavras reservadas ganham `_`.
pub fn snake(name: &str) -> String {
    let characters: Vec<char> = name.chars().collect();
    // ([a-z0-9])([A-Z]) -> \1_\2
    let mut first = Vec::with_capacity(characters.len() + 8);
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        let next = characters.get(index + 1).copied();
        if (character.is_ascii_lowercase() || character.is_ascii_digit()) && next.is_some_and(|c| c.is_ascii_uppercase()) {
            first.extend([character, '_', next.unwrap()]);
            index += 2;
        } else {
            first.push(character);
            index += 1;
        }
    }
    // ([A-Z]+)([A-Z][a-z]) -> \1_\2: numa sequência de 2+ maiúsculas seguida de
    // minúscula, o `_` entra antes da última maiúscula.
    let mut second = Vec::with_capacity(first.len() + 8);
    let mut index = 0;
    while index < first.len() {
        if first[index].is_ascii_uppercase() {
            let start = index;
            let mut end = index;
            while end < first.len() && first[end].is_ascii_uppercase() {
                end += 1;
            }
            if end - start >= 2 && first.get(end).is_some_and(|c| c.is_ascii_lowercase()) {
                second.extend_from_slice(&first[start..end - 1]);
                second.extend(['_', first[end - 1], first[end]]);
                index = end + 1;
            } else {
                second.extend_from_slice(&first[start..end]);
                index = end;
            }
        } else {
            second.push(first[index]);
            index += 1;
        }
    }
    let lowered: String = second.into_iter().collect::<String>().to_lowercase();
    let mut collapsed = String::with_capacity(lowered.len());
    for character in lowered.chars() {
        if character == '_' && collapsed.ends_with('_') {
            continue;
        }
        collapsed.push(character);
    }
    let mut text = collapsed.trim_matches('_').to_string();
    if text.is_empty() {
        text = "field".into();
    }
    if text.starts_with(|character: char| character.is_ascii_digit()) {
        text.insert(0, 'n');
    }
    if RUST_KEYWORDS.contains(&text.as_str()) {
        text.push('_');
    }
    text
}

/// `SignalState` -> `SIGNAL_STATE`.
pub fn screaming(name: &str) -> String {
    snake(name).trim_end_matches('_').to_uppercase()
}

/// Tipo de um membro já traduzido para Rust.
#[derive(Clone, Debug)]
pub struct Leaf {
    pub rust: String,
    pub size: u64,
    pub align: u64,
    pub deps: Vec<Key>,
    pub pointee: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Member {
    pub nt_name: Option<String>,
    pub rust_name: String,
    pub offset: u64,
    pub leaf: Leaf,
    pub order: usize,
    pub view: usize,
    /// (nome NT, posição, largura)
    pub bits: Vec<(String, u32, u32)>,
}

impl Member {
    pub fn end(&self) -> u64 {
        self.offset + self.leaf.size
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Struct,
    Union,
    Enum,
}

pub struct TypeDef {
    pub rust_name: String,
    base_name: String,
    pub nt_name: String,
    pub kind: Kind,
    pub size: u64,
    pub family: String,
    pub members: Vec<Member>,
    /// Índices em `members`, por vista.
    pub views: Vec<Vec<usize>>,
    pub align: u64,
    /// (CONSTANTE, valor, nome NT)
    pub enum_values: Vec<(String, i128, String)>,
    pub enum_repr: Option<&'static str>,
    built: bool,
}

/// O que um tipo anônimo herda do tipo que o contém.
#[derive(Clone)]
struct Parent {
    base_name: String,
    nt_name: String,
    family: String,
}

pub struct Generator<'a> {
    tpi: &'a Tpi,
    config: &'a Config,
    /// Nome -> definição completa; com duplicatas (_KPCR, _KPRCB, ...), a maior.
    pub definitions: HashMap<String, u32>,
    pub types: HashMap<Key, TypeDef>,
    /// Chaves em ordem de descoberta.
    pub order: Vec<Key>,
    rust_names: HashMap<String, Key>,
    pending: VecDeque<Key>,
}

fn overlaps(first: &Member, second: &Member) -> bool {
    if first.leaf.size == 0 {
        return second.offset < first.offset && first.offset < second.end();
    }
    if second.leaf.size == 0 {
        return first.offset < second.offset && second.offset < first.end();
    }
    first.offset < second.end() && second.offset < first.end()
}

/// `T` de `Field<T>`/`UnalignedField<T>`.
pub fn cell_inner(rust: &str) -> &str {
    rust.split_once('<').map(|(_, inner)| inner.trim_end_matches('>')).unwrap_or("")
}

impl<'a> Generator<'a> {
    pub fn new(tpi: &'a Tpi, config: &'a Config) -> Generator<'a> {
        let mut definitions: HashMap<String, u32> = HashMap::new();
        for index in tpi.indices() {
            let record = tpi.get(index).unwrap();
            if !matches!(record.kind, pdb::LF_STRUCTURE | pdb::LF_CLASS | pdb::LF_UNION | pdb::LF_ENUM) {
                continue;
            }
            let udt = record.udt().unwrap();
            if udt.property & pdb::PROP_FWDREF != 0 || udt.name.starts_with('<') {
                continue;
            }
            let replace = match definitions.get(&udt.name) {
                None => true,
                Some(&current) => udt.size > tpi.get(current).unwrap().udt().unwrap().size,
            };
            if replace {
                definitions.insert(udt.name.clone(), index);
            }
        }
        Generator {
            tpi,
            config,
            definitions,
            types: HashMap::new(),
            order: Vec::new(),
            rust_names: HashMap::new(),
            pending: VecDeque::new(),
        }
    }

    fn resolve(&self, mut index: u32) -> u32 {
        while index >= 0x1000 {
            let Some(record) = self.tpi.get(index) else { return index };
            if let Body::Modifier { modified } = record.body {
                index = modified;
                continue;
            }
            if matches!(record.kind, pdb::LF_STRUCTURE | pdb::LF_CLASS | pdb::LF_UNION | pdb::LF_ENUM) {
                let name = &record.udt().unwrap().name;
                if !name.starts_with('<') {
                    if let Some(&definition) = self.definitions.get(name) {
                        return definition;
                    }
                }
            }
            return index;
        }
        index
    }

    fn type_size(&self, index: u32) -> Result<u64, String> {
        self.tpi.type_size(self.resolve(index))
    }

    fn enum_repr_of(&self, index: u32) -> &'static str {
        let underlying = self.tpi.get(index).and_then(|record| record.udt()).map_or(0x1000, |udt| udt.underlying);
        if underlying < 0x1000 {
            simple_rust(underlying & 0xFF).unwrap_or("i32")
        } else {
            "i32"
        }
    }

    fn enum_repr(&mut self, key: Key) -> &'static str {
        if let Some(repr) = self.types[&key].enum_repr {
            return repr;
        }
        let repr = self.enum_repr_of(key.0);
        self.types.get_mut(&key).unwrap().enum_repr = Some(repr);
        repr
    }

    /// Garante a geração do tipo (struct/união/enum) e devolve a chave.
    fn request(&mut self, index: u32, unaligned: bool, parent: Option<&Parent>, member_name: &str) -> Result<Key, String> {
        let index = self.resolve(index);
        let record = self.tpi.record(index)?;
        let unaligned = unaligned && record.kind != pdb::LF_ENUM;
        let key = (index, unaligned);
        if self.types.contains_key(&key) {
            return Ok(key);
        }
        let udt = record.udt().ok_or_else(|| format!("{index:#x} nao e struct/uniao/enum"))?;
        let (base, nt_label, family) = if udt.name.starts_with('<') {
            let parent = parent.ok_or_else(|| format!("tipo anonimo sem pai: {member_name}"))?;
            (format!("{}{}", parent.base_name, camel(member_name)), format!("{}::{member_name}", parent.nt_name), parent.family.clone())
        } else {
            (camel(&udt.name), udt.name.clone(), self.config.family_of(&udt.name))
        };
        let mut rust_name = format!("{base}{}", if unaligned { "Unaligned" } else { "" });
        if self.rust_names.get(&rust_name).is_some_and(|&owner| owner != key) {
            let mut suffix = 2;
            while self.rust_names.contains_key(&format!("{rust_name}{suffix}")) {
                suffix += 1;
            }
            rust_name = format!("{rust_name}{suffix}");
        }
        self.rust_names.insert(rust_name.clone(), key);
        let kind = match record.kind {
            pdb::LF_UNION => Kind::Union,
            pdb::LF_ENUM => Kind::Enum,
            _ => Kind::Struct,
        };
        let size = if kind == Kind::Enum { self.type_size(udt.underlying)? } else { udt.size };
        self.types.insert(
            key,
            TypeDef {
                rust_name,
                base_name: base,
                nt_name: nt_label,
                kind,
                size,
                family,
                members: Vec::new(),
                views: Vec::new(),
                align: 1,
                enum_values: Vec::new(),
                enum_repr: None,
                built: false,
            },
        );
        self.order.push(key);
        self.pending.push_back(key);
        Ok(key)
    }

    fn scalar(rust: &str, offset: u64, unaligned: bool, pointee: Option<String>) -> Result<Leaf, String> {
        let (size, align) = primitive(rust)?;
        let misaligned = unaligned || offset % align != 0;
        let cell = if misaligned { "UnalignedField" } else { "Field" };
        Ok(Leaf { rust: format!("{cell}<{rust}>"), size, align: if misaligned { 1 } else { align }, deps: Vec::new(), pointee })
    }

    /// Traduz o tipo de um membro em `offset` (relativo ao início do tipo pai).
    fn leaf(&mut self, index: u32, offset: u64, unaligned: bool, parent: &Parent, member_name: &str) -> Result<Leaf, String> {
        let resolved = self.resolve(index);
        if resolved < 0x1000 {
            let mode = (resolved >> 8) & 0xF;
            if mode != 0 {
                let pointee = pdb::simple_type(resolved & 0xFF).map_or("?", |(name, _)| name).to_string();
                return Self::scalar(if mode == 6 { "u64" } else { "u32" }, offset, unaligned, Some(pointee));
            }
            let rust = simple_rust(resolved & 0xFF)
                .ok_or_else(|| format!("tipo simples sem traducao {resolved:#x} em {}.{member_name}", parent.nt_name))?;
            return Self::scalar(rust, offset, unaligned, None);
        }
        let record = self.tpi.record(resolved)?;
        match (&record.body, record.kind) {
            (Body::Pointer { referent, size }, _) => {
                let size = if *size == 0 { 8 } else { *size };
                let pointee = self.tpi.type_name(*referent)?;
                Self::scalar(if size == 8 { "u64" } else { "u32" }, offset, unaligned, Some(pointee))
            }
            (_, pdb::LF_ENUM) => {
                let key = self.request(resolved, false, Some(parent), member_name)?;
                let (size, align) = primitive(self.enum_repr(key))?;
                let misaligned = unaligned || offset % align != 0;
                let cell = if misaligned { "UnalignedField" } else { "Field" };
                Ok(Leaf {
                    rust: format!("{cell}<{}>", self.types[&key].rust_name),
                    size,
                    align: if misaligned { 1 } else { align },
                    deps: vec![key],
                    pointee: None,
                })
            }
            (Body::Array { element, size }, _) => {
                let (element, size) = (*element, *size);
                let element_size = self.type_size(element)?;
                let count = if element_size != 0 { size / element_size } else { 0 };
                // Os elementos herdam o desalinhamento quando o passo não preserva o alinhamento.
                let mut inner = self.leaf(element, offset, unaligned, parent, member_name)?;
                if inner.align > 1 && element_size % inner.align != 0 {
                    inner = self.leaf(element, offset, true, parent, member_name)?;
                }
                Ok(Leaf {
                    rust: format!("[{}; {count}]", inner.rust),
                    size: element_size * count,
                    align: inner.align,
                    deps: inner.deps,
                    pointee: inner.pointee,
                })
            }
            (_, pdb::LF_STRUCTURE | pdb::LF_CLASS | pdb::LF_UNION) => {
                let mut key = self.request(resolved, unaligned, Some(parent), member_name)?;
                self.build(key)?;
                if !unaligned && offset % self.types[&key].align != 0 {
                    key = self.request(resolved, true, Some(parent), member_name)?;
                    self.build(key)?;
                }
                let typedef = &self.types[&key];
                Ok(Leaf { rust: typedef.rust_name.clone(), size: typedef.size, align: typedef.align, deps: vec![key], pointee: None })
            }
            (_, pdb::LF_PROCEDURE | pdb::LF_MFUNCTION) => {
                Err(format!("funcao por valor em {}.{member_name}", parent.nt_name))
            }
            (_, kind) => Err(format!("folha {kind:#x} sem traducao em {}.{member_name}", parent.nt_name)),
        }
    }

    /// Monta os membros, bitfields e vistas de uma struct/união.
    fn build(&mut self, key: Key) -> Result<(), String> {
        let (parent, size) = {
            let typedef = self.types.get_mut(&key).unwrap();
            if typedef.built || typedef.kind == Kind::Enum {
                return Ok(());
            }
            typedef.built = true;
            (
                Parent { base_name: typedef.base_name.clone(), nt_name: typedef.nt_name.clone(), family: typedef.family.clone() },
                typedef.size,
            )
        };
        let (index, unaligned) = key;
        let field = self.tpi.record(index)?.udt().unwrap().field;
        let raw: Vec<(String, u32, u64)> = self
            .tpi
            .field_members(field)?
            .into_iter()
            .filter_map(|member| match member {
                FieldMember::Member { name, type_index, offset } => Some((name, type_index, offset)),
                _ => None,
            })
            .collect();

        // (offset, tamanho) -> [(nome, posição, largura, tipo base)], na ordem do primeiro bit.
        let mut plain: Vec<(usize, String, u32, u64)> = Vec::new();
        let mut storages: Vec<((u64, u64), usize, Vec<(String, u32, u32, &'static str)>)> = Vec::new();
        for (order, (name, type_index, offset)) in raw.into_iter().enumerate() {
            let bitfield = if type_index >= 0x1000 {
                match self.tpi.get(type_index).map(|record| &record.body) {
                    Some(Body::Bitfield { base, length, position }) => Some((*base, *length, *position)),
                    _ => None,
                }
            } else {
                None
            };
            let Some((base, length, position)) = bitfield else {
                plain.push((order, name, type_index, offset));
                continue;
            };
            let base = self.resolve(base);
            let base_rust = match if base < 0x1000 { simple_rust(base & 0xFF) } else { None } {
                Some(rust) => rust,
                None => {
                    if self.tpi.record(base)?.kind != pdb::LF_ENUM {
                        return Err(format!("bitfield de base desconhecida em {}", parent.nt_name));
                    }
                    self.enum_repr_of(base)
                }
            };
            let storage = (offset, primitive(base_rust)?.0);
            match storages.iter_mut().find(|(existing, _, _)| *existing == storage) {
                Some((_, _, bits)) => bits.push((name, position, length, base_rust)),
                None => storages.push((storage, order, vec![(name, position, length, base_rust)])),
            }
        }

        let mut used: HashSet<String> = HashSet::new();
        let mut unique = |rust_name: String| {
            let mut candidate = rust_name.clone();
            let mut suffix = 2;
            while used.contains(&candidate) {
                candidate = format!("{rust_name}_{suffix}");
                suffix += 1;
            }
            used.insert(candidate.clone());
            candidate
        };

        let mut members = Vec::new();
        for (order, name, type_index, offset) in &plain {
            let leaf = self.leaf(*type_index, *offset, unaligned, &parent, name)?;
            members.push(Member {
                nt_name: Some(name.clone()),
                rust_name: unique(snake(name)),
                offset: *offset,
                leaf,
                order: *order,
                view: 0,
                bits: Vec::new(),
            });
        }

        // Estruturas empacotadas (#pragma pack): o tamanho não é múltiplo do
        // alinhamento natural. Membros mais exigentes que o empacotamento viram
        // células desalinhadas (UnalignedField / variante `...Unaligned`).
        let natural = members.iter().map(|member| member.leaf.align).max().unwrap_or(1);
        if size % natural != 0 {
            let mut pack = natural;
            while size % pack != 0 {
                pack /= 2;
            }
            for position in 0..members.len() {
                if members[position].leaf.align > pack {
                    let (_, name, type_index, _) = plain.iter().find(|item| item.0 == members[position].order).unwrap();
                    members[position].leaf = self.leaf(*type_index, members[position].offset, true, &parent, name)?;
                }
            }
        }

        // Preenchimentos posicionais (`...Fill`) que só existem para encaixar
        // campos no meio de outro: ficam de fora (as vistas já posicionam).
        let is_fill = |member: &Member| {
            let name = member.nt_name.as_deref().unwrap_or("");
            let fill_name = name.trim_end_matches(|c: char| c.is_ascii_digit()).ends_with("Fill");
            let rust = member.leaf.rust.strip_prefix('[').unwrap_or("");
            let rust = rust.strip_prefix("Unaligned").unwrap_or(rust);
            fill_name && (rust.starts_with("Field<u8>") || rust.starts_with("Field<i8>"))
        };
        let fills: Vec<bool> = members.iter().map(&is_fill).collect();
        let keep: Vec<bool> = (0..members.len())
            .map(|position| {
                !(fills[position]
                    && (0..members.len()).any(|other| {
                        other != position && !fills[other] && overlaps(&members[position], &members[other])
                    }))
            })
            .collect();
        let mut members: Vec<Member> =
            members.into_iter().zip(keep).filter_map(|(member, keep)| keep.then_some(member)).collect();

        // Bitfields: anexados a um inteiro de mesmo tamanho no mesmo offset
        // (o par `Flags`/bits das uniões do NT) ou a um armazenamento sintético.
        storages.sort_by_key(|(_, order, _)| *order);
        for ((offset, size), order, bits) in storages {
            let mut partner: Option<usize> = None;
            for (position, member) in members.iter().enumerate() {
                if member.offset == offset && member.leaf.size == size && !member.leaf.rust.starts_with('[') {
                    let inner = cell_inner(&member.leaf.rust);
                    if unsigned(inner).is_some() && partner.is_none_or(|current| members[current].leaf.pointee.is_some()) {
                        partner = Some(position);
                    }
                }
            }
            let partner = match partner {
                Some(position) => position,
                None => {
                    let rust = bits[0].3;
                    let leaf = Self::scalar(unsigned(rust).unwrap_or(rust), offset, unaligned, None)?;
                    members.push(Member {
                        nt_name: None,
                        rust_name: unique(format!("bitfield_{offset:x}")),
                        offset,
                        leaf,
                        order,
                        view: 0,
                        bits: Vec::new(),
                    });
                    members.len() - 1
                }
            };
            members[partner].bits.extend(bits.into_iter().map(|(name, position, length, _)| (name, position, length)));
        }

        members.sort_by_key(|member| member.order);

        // Vistas: coloração gulosa por ordem de declaração.
        let mut views: Vec<Vec<usize>> = Vec::new();
        for position in 0..members.len() {
            let free = views.iter().position(|view| !view.iter().any(|&other| overlaps(&members[position], &members[other])));
            match free {
                Some(view) => {
                    views[view].push(position);
                    members[position].view = view;
                }
                None => {
                    members[position].view = views.len();
                    views.push(vec![position]);
                }
            }
        }
        if views.is_empty() {
            views.push(Vec::new());
        }
        let alignment = members.iter().map(|member| member.leaf.align).max().unwrap_or(1);
        if size % alignment != 0 {
            return Err(format!("{}: tamanho {size:#x} nao e multiplo do alinhamento {alignment}", parent.nt_name));
        }
        let typedef = self.types.get_mut(&key).unwrap();
        typedef.members = members;
        typedef.views = views;
        typedef.align = alignment;
        Ok(())
    }

    /// Fecho transitivo das raízes.
    pub fn close(&mut self, roots: &[String]) -> Result<(), String> {
        for name in roots {
            let index = *self.definitions.get(name).ok_or_else(|| format!("raiz ausente no PDB: {name}"))?;
            let key = self.request(index, false, None, name)?;
            self.build(key)?;
        }
        while let Some(key) = self.pending.pop_front() {
            self.build(key)?;
            let typedef = &self.types[&key];
            if typedef.kind == Kind::Enum && typedef.enum_values.is_empty() {
                self.build_enum(key)?;
            }
        }
        Ok(())
    }

    fn build_enum(&mut self, key: Key) -> Result<(), String> {
        let repr = self.enum_repr(key);
        let signed = repr.starts_with('i');
        let bits = primitive(repr)?.0 * 8;
        let field = self.tpi.record(key.0)?.udt().unwrap().field;
        let mut seen: HashSet<String> = HashSet::new();
        let mut values = Vec::new();
        for member in self.tpi.field_members(field)? {
            let FieldMember::Enumerate { name: nt_name, mut value } = member else { continue };
            if signed && value >= 1i128 << (bits - 1) {
                value -= 1i128 << bits;
            }
            if !signed && value < 0 {
                value += 1i128 << bits;
            }
            let mut name = screaming(&nt_name);
            if name.is_empty() {
                name = "VALUE".into();
            }
            while seen.contains(&name) {
                name.push('_');
            }
            seen.insert(name.clone());
            values.push((name, value, nt_name));
        }
        self.types.get_mut(&key).unwrap().enum_values = values;
        Ok(())
    }

    /// Tipos alcançados a partir das raízes, em ordem de descoberta.
    pub fn reachable(&self, roots: &[String]) -> Vec<Key> {
        let mut seen: HashSet<Key> = HashSet::new();
        let mut stack: Vec<Key> = roots.iter().map(|name| (self.definitions[name], false)).collect();
        while let Some(key) = stack.pop() {
            if !seen.insert(key) {
                continue;
            }
            for member in &self.types[&key].members {
                stack.extend(member.leaf.deps.iter().copied());
            }
        }
        self.order.iter().copied().filter(|key| seen.contains(key)).collect()
    }

    /// A definição gerada de uma struct do NT pelo nome (`_KTHREAD`).
    pub fn by_nt_name(&self, nt_name: &str) -> Option<&TypeDef> {
        self.definitions.get(nt_name).and_then(|&index| self.types.get(&(index, false)))
    }
}
