//! Os tipos do NT para as vistas tipadas do depurador: os registros do TPI
//! do PDB do ntoskrnl (o mesmo `build/symbols/ntkrnlmp.pdb` de onde o
//! `cargo xtask nt-types` gera as estruturas do kernel) em consultas por
//! nome, membros com offset e tipo, e o valor de cada campo lido da
//! memória do alvo (`dt _IRP endereço`, a janela de observação).

use std::path::Path;

use super::tpi::{self, Body, FieldMember, Tpi};
use super::unwind::ReadMemory;

/// O que um índice de tipo é.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Void,
    /// Inteiro, booleano ou ponto flutuante.
    Primitive { name: String, size: u64, signed: bool, float: bool },
    Pointer { target: u32 },
    Struct { name: String, size: u64, union: bool },
    Enum { name: String, underlying: u32 },
    Array { element: u32, size: u64 },
    Bitfield { base: u32, length: u32, position: u32 },
    Function,
    Unknown,
}

/// Um membro de struct ou união.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub name: String,
    pub offset: u64,
    pub ty: u32,
}

/// Uma linha de uma vista tipada: o campo, onde está, o tipo e o valor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub offset: u64,
    pub address: u64,
    pub ty: u32,
    pub type_name: String,
    pub value: String,
    /// Struct, união, array ou ponteiro para struct: dá para abrir.
    pub expandable: bool,
    /// O valor numérico (escalares e ponteiros).
    pub number: Option<u64>,
}

pub struct TypeDb {
    tpi: Tpi,
    /// De onde vieram os tipos (o PDB).
    pub source: String,
}

/// Os nomes de tipos simples aceitos num cast (`(ULONG*)x`) e o código do
/// CodeView.
const PRIMITIVES: &[(&str, u32)] = &[
    ("void", 0x03),
    ("char", 0x10),
    ("CHAR", 0x10),
    ("i8", 0x68),
    ("u8", 0x69),
    ("UCHAR", 0x20),
    ("BYTE", 0x20),
    ("BOOLEAN", 0x20),
    ("short", 0x11),
    ("SHORT", 0x11),
    ("i16", 0x72),
    ("USHORT", 0x21),
    ("WORD", 0x21),
    ("u16", 0x73),
    ("wchar_t", 0x71),
    ("WCHAR", 0x71),
    ("int", 0x74),
    ("i32", 0x74),
    ("LONG", 0x12),
    ("unsigned", 0x75),
    ("u32", 0x75),
    ("ULONG", 0x22),
    ("DWORD", 0x22),
    ("i64", 0x76),
    ("LONG64", 0x13),
    ("LONGLONG", 0x13),
    ("u64", 0x77),
    ("ULONG64", 0x23),
    ("ULONGLONG", 0x23),
    ("DWORD64", 0x23),
    ("SIZE_T", 0x23),
    ("ULONG_PTR", 0x23),
    ("PVOID", 0x603),
];

impl TypeDb {
    pub fn new(tpi: Tpi, source: String) -> Self {
        Self { tpi, source }
    }

    /// Os tipos de um PDB (o stream TPI).
    pub fn load(path: &Path) -> Result<Self, String> {
        let msf = tpi::Msf::parse(std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?)?;
        let tpi = Tpi::parse(&msf.stream(2)?)?;
        Ok(Self::new(tpi, path.display().to_string()))
    }

    /// Um tipo pelo nome: `nt!_IRP`, `_IRP`, `IRP`, `PIRP` (ponteiro) ou um
    /// tipo simples (`ULONG`, `u64`).
    pub fn find(&self, name: &str) -> Option<u32> {
        let name = name.trim();
        let name = name.rsplit_once('!').map_or(name, |(_, type_name)| type_name);
        if let Some(&(_, code)) = PRIMITIVES.iter().find(|(primitive, _)| *primitive == name) {
            return Some(code);
        }
        if let Some(index) = self.tpi.find_udt(name) {
            return Some(index);
        }
        if !name.starts_with('_') {
            if let Some(index) = self.tpi.find_udt(&format!("_{name}")) {
                return Some(index);
            }
        }
        None
    }

    /// Nomes de tipos que começam com o texto (o autocompletar).
    pub fn names_starting_with(&self, prefix: &str, limit: usize) -> Vec<String> {
        let mut names: Vec<String> = self.tpi.udt_names().filter(|name| name.starts_with(prefix) && !name.starts_with('<')).map(str::to_string).collect();
        names.sort();
        names.truncate(limit);
        names
    }

    pub fn resolve(&self, index: u32) -> u32 {
        self.tpi.resolve(index)
    }

    pub fn kind(&self, index: u32) -> Kind {
        if index < 0x1000 {
            if (index >> 8) & 0xF != 0 {
                return Kind::Pointer { target: index & 0xFF };
            }
            return match tpi::simple_type(index & 0xFF) {
                Some(("void", _)) => Kind::Void,
                Some((name, size)) => Kind::Primitive { name: name.to_string(), size, signed: name.starts_with('i'), float: name.starts_with('f') },
                None => Kind::Unknown,
            };
        }
        let index = self.tpi.resolve(index);
        let Some(record) = self.tpi.get(index) else { return Kind::Unknown };
        match (&record.body, record.kind) {
            (Body::Modifier { modified }, _) => self.kind(*modified),
            (Body::Pointer { referent, .. }, _) => Kind::Pointer { target: *referent },
            (Body::Udt(udt), tpi::LF_ENUM) => Kind::Enum { name: udt.name.clone(), underlying: udt.underlying },
            (Body::Udt(udt), kind) => Kind::Struct { name: udt.name.clone(), size: udt.size, union: kind == tpi::LF_UNION },
            (Body::Array { element, size }, _) => Kind::Array { element: *element, size: *size },
            (Body::Bitfield { base, length, position }, _) => Kind::Bitfield { base: *base, length: *length, position: *position },
            (_, tpi::LF_PROCEDURE | tpi::LF_MFUNCTION) => Kind::Function,
            _ => Kind::Unknown,
        }
    }

    pub fn size(&self, index: u32) -> u64 {
        self.tpi.type_size(index).unwrap_or(0)
    }

    pub fn name(&self, index: u32) -> String {
        self.tpi.type_name(index).unwrap_or_else(|_| format!("?{index:#x}"))
    }

    /// Os membros de uma struct ou união (os das uniões anônimas do C já
    /// vêm na lista do pai, com o mesmo offset).
    pub fn members(&self, index: u32) -> Vec<Member> {
        let index = self.tpi.resolve(index);
        let Some(field) = self.tpi.get(index).and_then(|record| record.udt()).map(|udt| udt.field) else { return Vec::new() };
        let Ok(list) = self.tpi.field_members(field) else { return Vec::new() };
        list.into_iter()
            .filter_map(|member| match member {
                FieldMember::Member { name, type_index, offset } => Some(Member { name, offset, ty: type_index }),
                _ => None,
            })
            .collect()
    }

    /// O deslocamento de um campo de uma struct pelo nome dos dois.
    pub fn field_offset(&self, structure: &str, field: &str) -> Option<u64> {
        let index = self.find(structure)?;
        self.member(index, field).map(|member| member.offset)
    }

    /// Um membro pelo nome (sem diferença de caixa se não houver o exato).
    pub fn member(&self, index: u32, name: &str) -> Option<Member> {
        let members = self.members(index);
        members.iter().find(|member| member.name == name).or_else(|| members.iter().find(|member| member.name.eq_ignore_ascii_case(name))).cloned()
    }

    /// O nome do enumerador com o valor.
    pub fn enumerator(&self, index: u32, value: i128) -> Option<String> {
        let index = self.tpi.resolve(index);
        let field = self.tpi.get(index)?.udt()?.field;
        self.tpi.field_members(field).ok()?.into_iter().find_map(|member| match member {
            FieldMember::Enumerate { name, value: candidate } if candidate == value => Some(name),
            _ => None,
        })
    }

    /// O alvo de um ponteiro, se for um.
    pub fn pointee(&self, index: u32) -> Option<u32> {
        match self.kind(index) {
            Kind::Pointer { target } => Some(target),
            _ => None,
        }
    }

    /// Escalar (lido como número): inteiros, enums, ponteiros e bitfields.
    pub fn is_scalar(&self, index: u32) -> bool {
        matches!(self.kind(index), Kind::Primitive { .. } | Kind::Pointer { .. } | Kind::Enum { .. } | Kind::Bitfield { .. })
    }

    /// Lê um escalar do tipo em `address`.
    pub fn read_scalar(&self, memory: &mut dyn ReadMemory, index: u32, address: u64) -> Result<u64, String> {
        let (size, signed, bits) = match self.kind(index) {
            Kind::Primitive { size, signed, .. } => (size, signed, None),
            Kind::Pointer { .. } => (8, false, None),
            Kind::Enum { underlying, .. } => {
                let size = self.size(underlying).max(1);
                (size, matches!(self.kind(underlying), Kind::Primitive { signed: true, .. }), None)
            }
            Kind::Bitfield { base, length, position } => (self.size(base).max(1), false, Some((length, position))),
            other => return Err(format!("{}: nao e escalar ({other:?})", self.name(index))),
        };
        let size = size.clamp(1, 8) as usize;
        let bytes = memory.read(address, size)?;
        if bytes.len() < size {
            return Err(format!("memoria em {address:#x} inacessivel"));
        }
        let mut raw = [0u8; 8];
        raw[..size].copy_from_slice(&bytes[..size]);
        let mut value = u64::from_le_bytes(raw);
        if let Some((length, position)) = bits {
            value = (value >> position) & if length >= 64 { u64::MAX } else { (1 << length) - 1 };
        } else if signed && size < 8 {
            let shift = 64 - 8 * size as u32;
            value = (((value << shift) as i64) >> shift) as u64;
        }
        Ok(value)
    }

    /// O texto de um escalar: decimal e hexadecimal para inteiros, o nome
    /// do enumerador, o ponteiro em hexadecimal (com `describe` para o
    /// símbolo do endereço apontado).
    pub fn format_scalar(&self, index: u32, value: u64, describe: &dyn Fn(u64) -> Option<String>) -> String {
        match self.kind(index) {
            Kind::Pointer { .. } => match describe(value) {
                Some(name) => format!("{value:#018x} {name}"),
                None => format!("{value:#018x}"),
            },
            Kind::Enum { underlying, .. } => {
                let signed = matches!(self.kind(underlying), Kind::Primitive { signed: true, .. });
                let numeric = if signed { value as i64 as i128 } else { value as i128 };
                match self.enumerator(index, numeric) {
                    Some(name) => format!("{numeric} ({name})"),
                    None => format!("{numeric}"),
                }
            }
            Kind::Primitive { name, signed, size, .. } => {
                if name.starts_with("bool") {
                    return format!("{}", value != 0);
                }
                if signed {
                    format!("{} ({:#x})", value as i64, value & mask(size))
                } else if size == 1 && (0x20..0x7F).contains(&value) {
                    format!("{value:#04x} '{}'", value as u8 as char)
                } else {
                    format!("{value:#x}")
                }
            }
            Kind::Bitfield { length, position, .. } => format!("{value:#x} (bits {position}..{})", position + length - 1),
            _ => format!("{value:#x}"),
        }
    }

    /// Os campos de uma struct em `address` (um nível; structs aninhadas
    /// ficam para abrir).
    pub fn fields(&self, memory: &mut dyn ReadMemory, index: u32, address: u64, describe: &dyn Fn(u64) -> Option<String>) -> Vec<Field> {
        let index = self.tpi.resolve(index);
        match self.kind(index) {
            Kind::Struct { .. } => self.members(index).into_iter().map(|member| self.field(memory, &member.name, member.offset, member.ty, address + member.offset, describe)).collect(),
            Kind::Array { element, size } => {
                let element_size = self.size(element).max(1);
                let count = (size / element_size).min(64);
                (0..count).map(|position| self.field(memory, &format!("[{position}]"), position * element_size, element, address + position * element_size, describe)).collect()
            }
            Kind::Pointer { target } => match memory.read_u64(address) {
                Some(pointer) if pointer != 0 => self.fields(memory, target, pointer, describe),
                _ => Vec::new(),
            },
            _ => Vec::new(),
        }
    }

    /// Uma linha da vista.
    pub fn field(&self, memory: &mut dyn ReadMemory, name: &str, offset: u64, ty: u32, address: u64, describe: &dyn Fn(u64) -> Option<String>) -> Field {
        let type_name = self.name(ty);
        let kind = self.kind(ty);
        let (value, number) = match &kind {
            Kind::Struct { name, .. } => (format!("{name} em {address:#x}"), None),
            Kind::Array { element, size } => {
                let element_size = self.size(*element).max(1);
                // Texto: arrays de WCHAR/char viram cadeia.
                let text = match self.kind(*element) {
                    Kind::Primitive { size: 2, .. } if self.name(*element).contains("16") || self.name(*element) == "u16" => read_wide(memory, address, (*size as usize).min(256)),
                    Kind::Primitive { size: 1, .. } => read_narrow(memory, address, (*size as usize).min(256)),
                    _ => None,
                };
                (text.unwrap_or_else(|| format!("[{}] em {address:#x}", size / element_size)), None)
            }
            _ => match self.read_scalar(memory, ty, address) {
                Ok(number) => (self.format_scalar(ty, number, describe), Some(number)),
                Err(error) => (error, None),
            },
        };
        let expandable = match kind {
            Kind::Struct { .. } | Kind::Array { .. } => true,
            Kind::Pointer { target } => matches!(self.kind(target), Kind::Struct { .. }) && number.is_some_and(|pointer| pointer != 0),
            _ => false,
        };
        Field { name: name.to_string(), offset, address, ty, type_name, value, expandable, number }
    }
}

fn mask(size: u64) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (8 * size)) - 1
    }
}

/// Cadeia UTF-16 de até `length` bytes (até o NUL).
pub fn read_wide(memory: &mut dyn ReadMemory, address: u64, length: usize) -> Option<String> {
    let bytes = memory.read(address, length).ok()?;
    let units: Vec<u16> = bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
    Some(format!("\"{}\"", String::from_utf16_lossy(&units)))
}

/// Cadeia de bytes de até `length` bytes (até o NUL).
pub fn read_narrow(memory: &mut dyn ReadMemory, address: u64, length: usize) -> Option<String> {
    let bytes = memory.read(address, length).ok()?;
    let text: String = bytes.iter().take_while(|&&byte| byte != 0).map(|&byte| if (0x20..0x7F).contains(&byte) { byte as char } else { '.' }).collect();
    Some(format!("\"{text}\""))
}

/// Um UNICODE_STRING em `address` (Length, MaximumLength, Buffer).
pub fn read_unicode_string(memory: &mut dyn ReadMemory, address: u64) -> Option<String> {
    let header = memory.read(address, 16).ok()?;
    if header.len() < 16 {
        return None;
    }
    let length = u16::from_le_bytes([header[0], header[1]]) as usize;
    let buffer = u64::from_le_bytes(header[8..16].try_into().ok()?);
    if length == 0 || buffer == 0 {
        return Some(String::new());
    }
    let bytes = memory.read(buffer, length.min(1024)).ok()?;
    let units: Vec<u16> = bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    Some(String::from_utf16_lossy(&units))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::unwind::Captured;

    /// Registros de tipo montados à mão, com o cabeçalho do TPI.
    pub struct Builder {
        records: Vec<Vec<u8>>,
    }

    impl Builder {
        pub fn new() -> Self {
            Self { records: Vec::new() }
        }

        /// Acrescenta um registro e devolve o índice dele.
        pub fn add(&mut self, kind: u16, body: Vec<u8>) -> u32 {
            let mut record = Vec::new();
            let mut body = body;
            while (body.len() + 2) % 4 != 0 {
                body.push(0xF0 + (4 - (body.len() + 2) % 4) as u8);
            }
            record.extend_from_slice(&((body.len() + 2) as u16).to_le_bytes());
            record.extend_from_slice(&kind.to_le_bytes());
            record.extend_from_slice(&body);
            self.records.push(record);
            0x1000 + self.records.len() as u32 - 1
        }

        pub fn member(name: &str, ty: u32, offset: u16) -> Vec<u8> {
            let mut bytes = 0x150Du16.to_le_bytes().to_vec();
            bytes.extend_from_slice(&3u16.to_le_bytes());
            bytes.extend_from_slice(&ty.to_le_bytes());
            bytes.extend_from_slice(&offset.to_le_bytes());
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(0);
            while bytes.len() % 4 != 0 {
                bytes.push(0xF0 + (4 - bytes.len() % 4) as u8);
            }
            bytes
        }

        pub fn enumerate(name: &str, value: u16) -> Vec<u8> {
            let mut bytes = 0x1502u16.to_le_bytes().to_vec();
            bytes.extend_from_slice(&3u16.to_le_bytes());
            bytes.extend_from_slice(&value.to_le_bytes());
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(0);
            while bytes.len() % 4 != 0 {
                bytes.push(0xF0 + (4 - bytes.len() % 4) as u8);
            }
            bytes
        }

        pub fn structure(fields: u32, size: u16, name: &str) -> Vec<u8> {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&1u16.to_le_bytes()); // count
            bytes.extend_from_slice(&0u16.to_le_bytes()); // property
            bytes.extend_from_slice(&fields.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes()); // derived
            bytes.extend_from_slice(&0u32.to_le_bytes()); // vshape
            bytes.extend_from_slice(&size.to_le_bytes());
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(0);
            bytes
        }

        pub fn pointer(target: u32) -> Vec<u8> {
            let mut bytes = target.to_le_bytes().to_vec();
            bytes.extend_from_slice(&((8u32 << 13) | 0x0C).to_le_bytes());
            bytes
        }

        pub fn build(self) -> TypeDb {
            let records: Vec<u8> = self.records.concat();
            let mut stream = vec![0u8; 56];
            stream[4..8].copy_from_slice(&56u32.to_le_bytes());
            stream[8..12].copy_from_slice(&0x1000u32.to_le_bytes());
            stream[16..20].copy_from_slice(&(records.len() as u32).to_le_bytes());
            stream.extend_from_slice(&records);
            TypeDb::new(Tpi::parse(&stream).expect("TPI de teste"), "teste".into())
        }
    }

    /// `_DEVICE_OBJECT` reduzido: Type (i16), Flags (u32, bitfield de 1
    /// bit em +8), DriverObject (ponteiro para `_DRIVER_OBJECT`), um enum
    /// e um array de WCHAR.
    pub fn sample() -> TypeDb {
        let mut builder = Builder::new();
        let driver_fields = builder.add(0x1203, Builder::member("Type", 0x11, 0));
        let driver = builder.add(0x1505, Builder::structure(driver_fields, 0x10, "_DRIVER_OBJECT"));
        let driver_pointer = builder.add(0x1002, Builder::pointer(driver));
        let mut enum_fields = Builder::enumerate("PowerDeviceD0", 1);
        enum_fields.extend(Builder::enumerate("PowerDeviceD3", 4));
        let enum_list = builder.add(0x1203, enum_fields);
        let mut enum_body = 2u16.to_le_bytes().to_vec();
        enum_body.extend_from_slice(&0u16.to_le_bytes());
        enum_body.extend_from_slice(&0x74u32.to_le_bytes());
        enum_body.extend_from_slice(&enum_list.to_le_bytes());
        enum_body.extend_from_slice(b"_DEVICE_POWER_STATE\0");
        let power = builder.add(0x1507, enum_body);
        let mut bitfield = 0x22u32.to_le_bytes().to_vec();
        bitfield.extend_from_slice(&[1, 3]);
        let flag = builder.add(0x1205, bitfield);
        let mut array = 0x71u32.to_le_bytes().to_vec();
        array.extend_from_slice(&0x23u32.to_le_bytes());
        array.extend_from_slice(&8u16.to_le_bytes());
        array.push(0);
        let name = builder.add(0x1503, array);
        let mut members = Builder::member("Type", 0x11, 0);
        members.extend(Builder::member("Size", 0x21, 2));
        members.extend(Builder::member("Initialized", flag, 4));
        members.extend(Builder::member("DriverObject", driver_pointer, 8));
        members.extend(Builder::member("Power", power, 0x10));
        members.extend(Builder::member("Name", name, 0x14));
        let fields = builder.add(0x1203, members);
        builder.add(0x1505, Builder::structure(fields, 0x20, "_DEVICE_OBJECT"));
        builder.build()
    }

    #[test]
    fn finds_types_and_members() {
        let db = sample();
        let device = db.find("nt!_DEVICE_OBJECT").unwrap();
        assert_eq!(db.find("DEVICE_OBJECT"), Some(device));
        assert_eq!(db.size(device), 0x20);
        assert_eq!(db.find("ULONG"), Some(0x22));
        let members = db.members(device);
        assert_eq!(members.iter().map(|member| member.name.as_str()).collect::<Vec<_>>(), vec!["Type", "Size", "Initialized", "DriverObject", "Power", "Name"]);
        let driver_object = db.member(device, "driverobject").unwrap();
        assert_eq!(driver_object.offset, 8);
        assert!(matches!(db.kind(driver_object.ty), Kind::Pointer { .. }));
        assert_eq!(db.name(driver_object.ty), "_DRIVER_OBJECT*");
        assert_eq!(db.names_starting_with("_DEV", 4), vec!["_DEVICE_OBJECT".to_string(), "_DEVICE_POWER_STATE".to_string()]);
    }

    #[test]
    fn renders_fields_from_memory() {
        let db = sample();
        let device = db.find("_DEVICE_OBJECT").unwrap();
        let mut bytes = vec![0u8; 0x20];
        bytes[0..2].copy_from_slice(&(-3i16).to_le_bytes());
        bytes[2..4].copy_from_slice(&0x150u16.to_le_bytes());
        bytes[4..8].copy_from_slice(&0b1000u32.to_le_bytes());
        bytes[8..16].copy_from_slice(&0xffffc000_00001000u64.to_le_bytes());
        bytes[0x10..0x14].copy_from_slice(&4u32.to_le_bytes());
        bytes[0x14..0x1a].copy_from_slice(&[b'N', 0, b't', 0, 0, 0]);
        let mut memory = Captured { regions: vec![(0x5000, bytes), (0xffffc000_00001000, vec![4, 0, 0, 0])] };
        let describe = |address: u64| (address == 0xffffc000_00001000).then(|| "objeto".to_string());
        let fields = db.fields(&mut memory, device, 0x5000, &describe);
        assert_eq!(fields.len(), 6);
        assert_eq!(fields[0].value, "-3 (0xfffd)");
        assert_eq!(fields[1].value, "0x150");
        assert_eq!(fields[2].number, Some(1));
        assert_eq!(fields[3].value, "0xffffc00000001000 objeto");
        assert!(fields[3].expandable);
        assert_eq!(fields[4].value, "4 (PowerDeviceD3)");
        assert_eq!(fields[5].value, "\"Nt\"");
        // Abrir o ponteiro mostra a struct apontada.
        let inner = db.fields(&mut memory, fields[3].ty, fields[3].address, &describe);
        assert_eq!(inner[0].name, "Type");
        assert_eq!(inner[0].value, "4 (0x4)");
    }
}
