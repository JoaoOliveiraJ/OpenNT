//! Emissão do texto Rust dos tipos gerados: uma struct `#[repr(C)]` por
//! vista, os `Deref` entre vistas, `NtStruct`, os acessores de bitfields, as
//! asserções de layout e os newtypes dos enums.

use super::layout::{cell_inner, primitive, snake, unsigned, Kind, TypeDef};

/// Nomes já usados pelos métodos de NtStruct/Deref nas structs geradas.
const RESERVED_METHODS: &[&str] = &["at", "try_at", "array_at", "address", "deref"];

fn view_name(typedef: &TypeDef, index: usize) -> String {
    if index == 0 {
        typedef.rust_name.clone()
    } else {
        format!("{}View{index}", typedef.rust_name)
    }
}

/// Nome Rust da vista que contém um membro (para `offset_of!`).
pub fn member_view_name(typedef: &TypeDef, view: usize) -> String {
    view_name(typedef, view)
}

fn align_primitive(align: u64) -> &'static str {
    match align {
        1 => "u8",
        2 => "u16",
        4 => "u32",
        _ => "u64",
    }
}

pub fn emit(typedef: &TypeDef, out: &mut Vec<String>) -> Result<(), String> {
    match typedef.kind {
        Kind::Enum => emit_enum(typedef, out),
        Kind::Struct | Kind::Union => emit_struct(typedef, out),
    }
}

fn emit_struct(typedef: &TypeDef, out: &mut Vec<String>) -> Result<(), String> {
    let size = typedef.size;
    let view_count = typedef.views.len();
    for (view_index, view) in typedef.views.iter().enumerate() {
        let name = view_name(typedef, view_index);
        if view_index == 0 {
            out.push(format!("/// `{}` ({size:#x} bytes).", typedef.nt_name));
            if view_count > 1 {
                out.push("///".into());
                out.push("/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas".into());
                if view_count == 2 {
                    out.push(format!("/// `{}View1`, alcançada por `Deref`.", typedef.rust_name));
                } else {
                    out.push(format!(
                        "/// `{0}View1`..`{0}View{1}`, alcançadas por `Deref`.",
                        typedef.rust_name,
                        view_count - 1
                    ));
                }
            }
        } else {
            out.push(format!("/// Vista {view_index} de `{}` (membros sobrepostos à vista anterior).", typedef.nt_name));
        }
        out.push("#[repr(C)]".into());
        out.push(format!("pub struct {name} {{"));
        let natural = view.iter().map(|&member| typedef.members[member].leaf.align).max().unwrap_or(1);
        if natural < typedef.align {
            out.push(format!("    _align: [{}; 0],", align_primitive(typedef.align)));
        }
        let mut sorted: Vec<usize> = view.clone();
        sorted.sort_by_key(|&member| {
            let member = &typedef.members[member];
            (member.offset, member.leaf.size > 0, member.order)
        });
        let mut cursor = 0;
        for member in sorted.iter().map(|&member| &typedef.members[member]) {
            if member.offset < cursor || member.offset % member.leaf.align != 0 {
                return Err(format!(
                    "{}.{}: offset {:#x} impossivel (cursor {cursor:#x})",
                    typedef.nt_name, member.rust_name, member.offset
                ));
            }
            if member.offset > cursor {
                out.push(format!("    _pad_{cursor:x}: Reserved<{:#x}>,", member.offset - cursor));
            }
            if let Some(pointee) = &member.leaf.pointee {
                out.push(format!("    /// -> `{pointee}`"));
            }
            out.push(format!("    pub {}: {},", member.rust_name, member.leaf.rust));
            cursor = member.end();
        }
        if cursor < size {
            out.push(format!("    _pad_{cursor:x}: Reserved<{:#x}>,", size - cursor));
        }
        out.push("}".into());
        out.push(String::new());
    }

    // Deref entre vistas.
    for view_index in 0..view_count.saturating_sub(1) {
        let source = view_name(typedef, view_index);
        let target = view_name(typedef, view_index + 1);
        out.push(format!("impl core::ops::Deref for {source} {{"));
        out.push(format!("    type Target = {target};"));
        out.push("    #[inline(always)]".into());
        out.push(format!("    fn deref(&self) -> &{target} {{"));
        out.push("        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.".into());
        out.push(format!("        unsafe {{ &*(self as *const Self).cast::<{target}>() }}"));
        out.push("    }".into());
        out.push("}".into());
        out.push(String::new());
    }

    out.push(format!("unsafe impl NtStruct for {} {{}}", typedef.rust_name));
    out.push(String::new());

    // Bitfields: constantes e acessores.
    let mut bit_lines = Vec::new();
    let mut used_helpers: Vec<String> = Vec::new();
    for member in &typedef.members {
        for (nt_name, position, length) in &member.bits {
            let mut helper = snake(nt_name);
            if RESERVED_METHODS.contains(&helper.as_str()) {
                helper.push('_');
            }
            while used_helpers.contains(&helper) {
                helper.push('_');
            }
            used_helpers.push(helper.clone());
            let cell = cell_inner(&member.leaf.rust);
            let unsigned = unsigned(cell).ok_or_else(|| format!("{}: bitfield em {cell}", typedef.nt_name))?;
            let trimmed = helper.trim_end_matches('_');
            let constant = trimmed.to_uppercase();
            let mask: u128 = ((1u128 << length) - 1) << position;
            bit_lines.push(format!(
                "    /// `{nt_name}`: bits {position}..={} de `{}`.",
                position + length - 1,
                member.rust_name
            ));
            bit_lines.push(format!("    pub const {constant}_SHIFT: u32 = {position};"));
            bit_lines.push(format!("    pub const {constant}_MASK: {unsigned} = {mask:#x};"));
            bit_lines.push("    #[inline(always)]".into());
            bit_lines.push(format!("    pub fn {helper}(&self) -> {unsigned} {{"));
            bit_lines.push(format!("        self.{}.bits({position}, {length}) as {unsigned}", member.rust_name));
            bit_lines.push("    }".into());
            bit_lines.push("    #[inline(always)]".into());
            bit_lines.push(format!("    pub fn set_{trimmed}(&self, value: {unsigned}) {{"));
            bit_lines.push(format!("        self.{}.set_bits({position}, {length}, value as u64)", member.rust_name));
            bit_lines.push("    }".into());
        }
    }
    if !bit_lines.is_empty() {
        out.push(format!("impl {} {{", typedef.rust_name));
        out.extend(bit_lines);
        out.push("}".into());
        out.push(String::new());
    }

    // Asserções de layout.
    out.push("const _: () = {".into());
    for (view_index, view) in typedef.views.iter().enumerate() {
        let name = view_name(typedef, view_index);
        out.push(format!("    assert!(core::mem::size_of::<{name}>() == {size:#x});"));
        if view_index != 0 {
            out.push(format!(
                "    assert!(core::mem::align_of::<{name}>() == core::mem::align_of::<{}>());",
                typedef.rust_name
            ));
        }
        let mut sorted = view.clone();
        sorted.sort_by_key(|&member| typedef.members[member].offset);
        for member in sorted.iter().map(|&member| &typedef.members[member]) {
            out.push(format!("    assert!(core::mem::offset_of!({name}, {}) == {:#x});", member.rust_name, member.offset));
        }
    }
    out.push("};".into());
    out.push(String::new());
    Ok(())
}

fn emit_enum(typedef: &TypeDef, out: &mut Vec<String>) -> Result<(), String> {
    let repr = typedef.enum_repr.ok_or_else(|| format!("{}: enum sem tipo base", typedef.nt_name))?;
    out.push(format!("/// `{}`.", typedef.nt_name));
    out.push("#[derive(Clone, Copy, PartialEq, Eq, Debug)]".into());
    out.push("#[repr(transparent)]".into());
    out.push(format!("pub struct {}(pub {repr});", typedef.rust_name));
    out.push(String::new());
    if !typedef.enum_values.is_empty() {
        out.push(format!("impl {} {{", typedef.rust_name));
        for (name, value, _) in &typedef.enum_values {
            let literal = if value.abs() < 0x10000 {
                value.to_string()
            } else if *value >= 0 {
                format!("{value:#x}")
            } else {
                format!("-{:#x}", -value)
            };
            out.push(format!("    pub const {name}: Self = Self({literal});"));
        }
        out.push("}".into());
        out.push(String::new());
    }
    // Célula de uma instrução para os acessos sondados (`probe_get`/`probe_set`).
    let unsigned = unsigned(repr).ok_or_else(|| format!("{}: enum de base {repr}", typedef.nt_name))?;
    out.push(format!("impl GuestScalar for {} {{", typedef.rust_name));
    out.push(format!("    const SIZE: u64 = {};", primitive(repr)?.0));
    out.push("    #[inline(always)]".into());
    out.push("    fn from_bits(bits: u64) -> Self {".into());
    out.push(format!("        Self(bits as {unsigned} as {repr})"));
    out.push("    }".into());
    out.push("    #[inline(always)]".into());
    out.push("    fn to_bits(self) -> u64 {".into());
    out.push(format!("        self.0 as {unsigned} as u64"));
    out.push("    }".into());
    out.push("}".into());
    out.push(String::new());
    Ok(())
}
