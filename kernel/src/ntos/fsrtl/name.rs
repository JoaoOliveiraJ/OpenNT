//! Nomes do FsRtl — correspondência com curingas DOS, detecção de curingas,
//! desmontagem de caminhos e o bitmap FsRtlLegalAnsiCharacterArray.
//!
//! `IsNameInExpression`/`DoesNameContainWildCards`/`DissectName` reproduzem
//! o `ntoskrnl` real (desmontagem por RVA). As UNICODE_STRING são endereços
//! do convidado.

use alloc::vec::Vec;

use crate::ntos::inc::types::{NtStruct, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_data;
use crate::ntos::mm::kernel_data_layout::FSRTL_LEGAL_ANSI_CHARACTER_ARRAY;
use crate::ntos::rtl::unicode_case;

// Classe FSRTL_WILD_CHARACTER no bitmap de 256 bytes.
const FSRTL_WILD_CHARACTER: u8 = 0x08;

// Os cinco curingas do FsRtl (valores UTF-16 = ASCII).
const WC_STAR: u16 = b'*' as u16; // 0x2A
const WC_QM: u16 = b'?' as u16; // 0x3F
const WC_DOS_STAR: u16 = b'<' as u16; // 0x3C
const WC_DOS_QM: u16 = b'>' as u16; // 0x3E
const WC_DOS_DOT: u16 = b'"' as u16; // 0x22
const WC_DOT: u16 = b'.' as u16; // 0x2E
const WC_BACKSLASH: u16 = 0x5C;

// ---- FsRtlLegalAnsiCharacterArray (data export) -----------------------------

/// Endereço da célula `.kdata` com o bitmap de classes (mesmos bytes que o
/// `ntoskrnl` real referencia em VA 0x140011b20). O armazenamento de 256
/// bytes e os valores iniciais ficam em `mm::kernel_data_layout`
/// (ver REGISTRATION) — aqui só devolvemos o endereço público, como a HAL
/// faz com `HalPrivateDispatchTable`.
pub fn legal_ansi_character_array_address() -> u64 {
    kernel_data::address("FsRtlLegalAnsiCharacterArray")
        .unwrap_or_else(|error| panic!("FsRtlLegalAnsiCharacterArray: {error}"))
}

// ---- Name helpers (§2.1) ----------------------------------------------------

/// FsRtlDoesNameContainWildCards(Name) -> BOOLEAN (RVA 0x24f730).
/// Varre do último caractere para trás; para em `\` (FALSE); para um
/// caractere < 0x40 testa o bit FSRTL_WILD_CHARACTER no bitmap; caracteres
/// >= 0x40 nunca são curingas e são ignorados.
pub fn does_name_contain_wild_cards(name: u64) -> bool {
    let units = read_unicode_string(name);
    let mut index = units.len();
    while index > 0 {
        index -= 1;
        let unit = units[index];
        if unit == WC_BACKSLASH {
            return false;
        }
        if unit < 0x40 && FSRTL_LEGAL_ANSI_CHARACTER_ARRAY[unit as usize] & FSRTL_WILD_CHARACTER != 0 {
            return true;
        }
    }
    false
}

/// FsRtlDissectName(Path, FirstName, RemainingName) (RVA 0x2ede60).
/// Zera as duas UNICODE_STRING de saída; divide `a\b\c` em first=`a`,
/// remaining=`b\c`; pula um `\` inicial. `Path` é passado por ponteiro
/// (struct de 16 bytes na ABI x64).
pub fn dissect_name(path: u64, first: u64, remaining: u64) {
    // SAFETY: as três UNICODE_STRING do chamador.
    let (path_string, first, remaining) = unsafe { (UnicodeString::at(path), UnicodeString::at(first), UnicodeString::at(remaining)) };
    // Saídas zeradas (Length, MaximumLength, Buffer).
    set_string(first, 0, 0);
    set_string(remaining, 0, 0);

    let units = read_unicode_string(path);
    let count = units.len() as u64;
    if count == 0 {
        return;
    }
    let buffer = path_string.buffer.get();
    let leading = if units[0] == WC_BACKSLASH { 1 } else { 0 };

    // Índice do separador `\` (ou `count` se não houver), a partir de `leading`.
    let mut separator = leading;
    while separator < count && units[separator as usize] != WC_BACKSLASH {
        separator += 1;
    }

    set_string(first, ((separator - leading) * 2) as u16, buffer + leading * 2);

    if separator < count {
        set_string(remaining, ((count - separator - 1) * 2) as u16, buffer + (separator + 1) * 2);
    }
}

/// UNICODE_STRING de saída apontando para dentro do buffer de entrada.
fn set_string(string: &UnicodeString, length: u16, buffer: u64) {
    string.length.set(length);
    string.maximum_length.set(length);
    string.buffer.set(buffer);
}

/// FsRtlIsNameInExpression(Expression, Name, IgnoreCase, UpcaseTable)
/// -> BOOLEAN (RVA 0x24f160 -> RtlpIsNameInExpressionPrivate 0x24f290).
/// Matcher de curingas DOS auto-contido (`* ? < > "`), com upcase opcional.
pub fn is_name_in_expression(expression: u64, name: u64, ignore_case: bool) -> bool {
    let expression = read_unicode_string(expression);
    let name = read_unicode_string(name);
    match_expression(&expression, 0, &name, 0, ignore_case)
}

fn read_unicode_string(pointer: u64) -> Vec<u16> {
    // SAFETY: UNICODE_STRING do chamador.
    let string = unsafe { UnicodeString::at(pointer) };
    let count = string.length.get() as usize / 2;
    if count == 0 {
        return Vec::new();
    }
    guest::read_bytes(string.buffer.get(), count * 2).chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect()
}

fn upcase(unit: u16) -> u16 {
    unicode_case::upcase_char(unit).unwrap_or(unit)
}

fn unit_eq(a: u16, b: u16, ignore_case: bool) -> bool {
    a == b || (ignore_case && upcase(a) == upcase(b))
}

/// Correspondência recursiva com retrocesso. `expr`/`name` são listas de
/// code units; o retrocesso vive apenas nas ramificações `*` / DOS_STAR.
fn match_expression(expr: &[u16], mut ei: usize, name: &[u16], mut ni: usize, ic: bool) -> bool {
    loop {
        if ei == expr.len() {
            return ni == name.len();
        }
        match expr[ei] {
            WC_STAR => {
                // Zero ou mais de qualquer caractere.
                if ei + 1 == expr.len() {
                    return true; // `*` final casa com o resto.
                }
                for split in ni..=name.len() {
                    if match_expression(expr, ei + 1, name, split, ic) {
                        return true;
                    }
                }
                return false;
            }
            WC_DOS_STAR => {
                // Zero ou mais caracteres até o último `.` do nome restante.
                let mut last_dot = name.len();
                for position in ni..name.len() {
                    if name[position] == WC_DOT {
                        last_dot = position;
                    }
                }
                for split in ni..=last_dot {
                    if match_expression(expr, ei + 1, name, split, ic) {
                        return true;
                    }
                }
                return false;
            }
            WC_QM => {
                // Exatamente um caractere.
                if ni < name.len() {
                    ei += 1;
                    ni += 1;
                    continue;
                }
                return false;
            }
            WC_DOS_QM => {
                // Um caractere qualquer; em `.` ou fim do nome, casa com zero.
                if ni < name.len() && name[ni] != WC_DOT {
                    ni += 1;
                }
                ei += 1;
                continue;
            }
            WC_DOS_DOT => {
                // Um `.` ou zero caracteres (ponto opcional).
                if ni < name.len() && name[ni] == WC_DOT {
                    ni += 1;
                }
                ei += 1;
                continue;
            }
            literal => {
                if ni < name.len() && unit_eq(literal, name[ni], ic) {
                    ei += 1;
                    ni += 1;
                    continue;
                }
                return false;
            }
        }
    }
}

// ---- Motor exato do NT e FsRtlIsNameInUnUpcasedExpression ----
//
// Append do grupo fsrtl-file-system-support ao `fsrtl/name.rs` existente.
// Reusa os itens do arquivo (WC_*, FSRTL_WILD_CHARACTER,
// FSRTL_LEGAL_ANSI_CHARACTER_ARRAY, read_unicode_string, upcase, guest, Vec,
// unicode_case, NtStruct); Field e KernelError vão por caminho absoluto, sem
// `use` novo.
//
// Conferido contra o RtlpIsNameInExpressionPrivate (RVA 0x24f290 no ntoskrnl
// 19045), o motor de FsRtlIsNameInExpression (0x24f160) e de
// FsRtlIsNameInUnUpcasedExpression (0x24f1e0). Autômato não determinístico
// sobre a expressão: um estado é `offset_em_bytes * 2` (+3 depois de `*` /
// DOS_STAR, +4 depois de consumir um caractere); `Expression.Length * 2` é o
// estado final. `*` mantém o estado e salta (+3); DOS_STAR (`<`) faz o mesmo,
// exceto sobre um `.` que é o último ponto do nome (aí só salta); DOS_QM
// (`>`) consome um caractere que não seja `.` e, no fim do nome ou sobre `.`,
// avança sem consumir; DOS_DOT (`"`) consome `.` e no fim do nome avança sem
// consumir; `?` consome qualquer caractere; o resto compara literalmente
// (pela tabela quando IgnoreCase). Destinos repetidos são podados contra as
// origens ainda não processadas; quando o nome acaba, uma última passada só
// segue as transições vazias. Atalhos do NT: vazios (TRUE só se ambos), `*`
// e `*literal` sem outros curingas (sufixo por memcmp ou pela tabela).
// `upcase_expression` é o 4º parâmetro do motor (TRUE na variante UnUpcased).
// Nota: o `match_expression` recursivo acima, usado por
// FsRtlIsNameInExpression, difere do NT (ex.: DOS_DOT casa zero caracteres
// no meio do nome); `is_name_in_expression_private(.., false, ..)` é o
// equivalente exato, se quiserem trocar.

/// Tabela de maiúsculas do chamador (`PWCH`, 64K entradas) ou nenhuma.
#[derive(Clone, Copy)]
pub struct UpcaseTable(Option<&'static [crate::ntos::inc::types::Field<u16>]>);

impl UpcaseTable {
    /// A tabela em `address` (NULL = sem tabela).
    ///
    /// # Safety
    /// `address` é NULL ou aponta para as 0x10000 WCHARs da tabela.
    pub unsafe fn at(address: u64) -> Self {
        // SAFETY: garantido pelo chamador.
        Self((address != 0).then(|| unsafe { crate::ntos::inc::types::Field::<u16>::array_at(address, 0x1_0000) }))
    }

    fn map(self, unit: u16) -> u16 {
        self.0.map_or(unit, |table| table[unit as usize].get())
    }
}

/// RtlDoesNameContainWildCards sobre code units (0x24f730): do fim até `\`,
/// classe FSRTL_WILD_CHARACTER para caracteres < 0x40.
fn units_contain_wild_cards(units: &[u16]) -> bool {
    for &unit in units.iter().rev() {
        if unit == WC_BACKSLASH {
            return false;
        }
        if unit < 0x40 && FSRTL_LEGAL_ANSI_CHARACTER_ARRAY[unit as usize] & FSRTL_WILD_CHARACTER != 0 {
            return true;
        }
    }
    false
}

/// RtlpIsNameInExpressionPrivate(Expression, Name, IgnoreCase,
/// UpcaseExpression, UpcaseTable). Com IgnoreCase a tabela é obrigatória
/// (os chamadores convertem antes quando ela é NULL).
pub fn is_name_in_expression_private(expression: &[u16], name: &[u16], ignore_case: bool, upcase_expression: bool, table: UpcaseTable) -> bool {
    if name.is_empty() || expression.is_empty() {
        return name.is_empty() && expression.is_empty();
    }
    if expression[0] == WC_STAR {
        if expression.len() == 1 {
            return true;
        }
        let tail = &expression[1..];
        if !units_contain_wild_cards(tail) {
            if name.len() < tail.len() {
                return false;
            }
            let suffix = &name[name.len() - tail.len()..];
            if !ignore_case {
                return suffix == tail;
            }
            return suffix.iter().zip(tail).all(|(&n, &e)| table.map(n) == if upcase_expression { table.map(e) } else { e });
        }
    }
    let expression_length = expression.len() as u32 * 2;
    let max_state = expression_length * 2;
    let mut previous: Vec<u32> = alloc::vec![0];
    let mut current: Vec<u32> = Vec::new();
    let mut name_offset = 0usize;
    let mut name_finished = false;
    let mut name_char = 0u16;
    loop {
        if name_offset < name.len() {
            name_char = name[name_offset];
            name_offset += 1;
        } else {
            name_finished = true;
            if previous[previous.len() - 1] == max_state {
                return true;
            }
        }
        current.clear();
        let mut source = 0usize;
        let mut previous_dest = 0usize;
        while source < previous.len() {
            let mut offset = (previous[source] + 1) >> 1;
            source += 1;
            let mut length = 0u32;
            loop {
                if offset == expression_length {
                    break;
                }
                offset += length;
                length = 2;
                let mut state = offset * 2;
                if offset == expression_length {
                    current.push(max_state);
                    break;
                }
                let raw = expression[(offset / 2) as usize];
                let expression_char = if ignore_case && upcase_expression { table.map(raw) } else { raw };
                if expression_char == WC_STAR {
                    current.push(state);
                    current.push(state + 3);
                    continue;
                }
                if expression_char == WC_DOS_STAR {
                    // Sobre um `.` sem outro ponto adiante, só o salto.
                    let can_eat_dot = name[name_offset..].contains(&WC_DOT);
                    if name_char != WC_DOT || name_finished || can_eat_dot {
                        current.push(state);
                    }
                    current.push(state + 3);
                    continue;
                }
                state += 4;
                if expression_char == WC_DOS_QM {
                    if name_finished || name_char == WC_DOT {
                        continue;
                    }
                    current.push(state);
                    break;
                }
                if expression_char == WC_DOS_DOT {
                    if name_finished {
                        continue;
                    }
                    if name_char == WC_DOT {
                        current.push(state);
                        break;
                    }
                } else {
                    if name_finished {
                        break;
                    }
                    if expression_char == WC_QM {
                        current.push(state);
                        break;
                    }
                }
                let compared = if ignore_case { table.map(name_char) } else { name_char };
                if expression_char == compared {
                    current.push(state);
                }
                break;
            }
            // Poda: avança as origens já cobertas pelos destinos novos.
            if source < previous.len() {
                while previous_dest < current.len() {
                    while source < previous.len() && previous[source] < current[previous_dest] {
                        source += 1;
                    }
                    previous_dest += 1;
                    if source >= previous.len() {
                        break;
                    }
                }
            }
        }
        if current.is_empty() {
            return false;
        }
        core::mem::swap(&mut previous, &mut current);
        if name_finished {
            return previous[previous.len() - 1] == max_state;
        }
    }
}

/// FsRtlIsNameInUnUpcasedExpression / RtlIsNameInUnUpcasedExpression
/// (Expression, Name, IgnoreCase, UpcaseTable) -> BOOLEAN. Sem tabela e com
/// IgnoreCase, as duas strings passam por RtlUpcaseUnicodeString (tabela NLS
/// do sistema) e o motor roda sensível a caixa.
pub fn is_name_in_un_upcased_expression(expression: u64, name: u64, ignore_case: bool, table: UpcaseTable) -> Result<bool, crate::rtl::KernelError> {
    let expression = read_unicode_string(expression);
    let name = read_unicode_string(name);
    if ignore_case && table.0.is_none() {
        let name = unicode_case::upcase_units(&name)?;
        let expression = unicode_case::upcase_units(&expression)?;
        return Ok(is_name_in_expression_private(&expression, &name, false, true, table));
    }
    Ok(is_name_in_expression_private(&expression, &name, ignore_case, true, table))
}

// ---- FsRtlAreNamesEqual / FsRtlIsFatDbcsLegal (fsrtl-volume-support) -------------

/// FsRtlAreNamesEqual(NameA, NameB, IgnoreCase, UpcaseTable) (RVA 0x2e0be0):
/// comprimentos diferentes -> FALSE; sem IgnoreCase, memcmp; com UpcaseTable
/// (65536 WCHARs), compara os dois pela tabela; sem ela, RtlUpcaseUnicodeString
/// dos dois e memcmp.
pub fn are_names_equal(first: &UnicodeString, second: &UnicodeString, ignore_case: bool, upcase_table: u64) -> Result<bool, crate::rtl::KernelError> {
    if first.length.get() != second.length.get() {
        return Ok(false);
    }
    let (left, right) = (read_unicode_string(first.address()), read_unicode_string(second.address()));
    if !ignore_case {
        return Ok(left == right);
    }
    if upcase_table != 0 {
        // SAFETY: a UpcaseTable do FS tem 65536 WCHARs.
        let table = unsafe { crate::ntos::inc::field::Field::<u16>::array_at(upcase_table, 0x10000) };
        return Ok(left.iter().zip(&right).all(|(&a, &b)| table[a as usize].get() == table[b as usize].get()));
    }
    Ok(unicode_case::upcase_units(&left)? == unicode_case::upcase_units(&right)?)
}

const FSRTL_FAT_LEGAL: u8 = 0x01;

/// FsRtlIsLeadDbcsCharacter: NlsMbOemCodePageTag e NlsOemLeadByteInfo[c].
fn is_lead_dbcs(byte: u8) -> bool {
    use crate::ntos::inc::field::Field;
    let (Ok(tag), Ok(info)) = (kernel_data::address("NlsMbOemCodePageTag"), kernel_data::address("NlsOemLeadByteInfo")) else { return false };
    // SAFETY: os dados exportados BOOLEAN NlsMbOemCodePageTag e PUSHORT NlsOemLeadByteInfo.
    let (tag, table) = unsafe { (Field::<u8>::at(tag).get(), Field::<u64>::at(info).get()) };
    // SAFETY: a tabela de 256 USHORTs do code page OEM.
    tag != 0 && table != 0 && unsafe { Field::<u16>::array_at(table, 256) }[byte as usize].get() != 0
}

/// FsRtlDoesDbcsContainWildCards.
fn dbcs_contains_wild_cards(name: &[u8]) -> bool {
    let mut index = 0;
    while index < name.len() {
        let byte = name[index];
        if is_lead_dbcs(byte) {
            index += 2;
            continue;
        }
        if byte < 0x80 && FSRTL_LEGAL_ANSI_CHARACTER_ARRAY[byte as usize] & FSRTL_WILD_CHARACTER != 0 {
            return true;
        }
        index += 1;
    }
    false
}

/// FsRtlDissectDbcs: primeiro componente até '\' e o resto depois dele.
fn dissect_dbcs(name: &[u8]) -> (&[u8], &[u8]) {
    let mut index = 0;
    while index < name.len() && name[index] != b'\\' {
        index += if is_lead_dbcs(name[index]) { 2 } else { 1 };
    }
    let index = index.min(name.len());
    (&name[..index], if index < name.len() { &name[index + 1..] } else { &[] })
}

/// FsRtlIsFatDbcsLegal(DbcsName, WildCardsPermissible, PathNamePermissible,
/// LeadingBackslashPermissible) (RVA 0x688910): nome 8.3 com o bitmap
/// FSRTL_FAT_LEGAL (curingas com FSRTL_WILD_CHARACTER), um ponto, extensão de
/// até 3, sem espaço antes do ponto nem ponto/espaço no fim; "." e ".." só com
/// curingas; caminhos componente a componente.
pub fn is_fat_dbcs_legal(name: &[u8], wild_cards: bool, path: bool, leading_backslash: bool) -> bool {
    if name.is_empty() {
        return false;
    }
    if wild_cards && matches!(name, [b'.'] | [b'"'] | [b'.', b'.'] | [b'"', b'"']) {
        return true;
    }
    let mut name = name;
    if name[0] == b'\\' {
        if !leading_backslash {
            return false;
        }
        if name.len() <= 1 {
            return true;
        }
        name = &name[1..];
    }
    if path {
        if name[0] == b'\\' {
            return false;
        }
        loop {
            let (first, remaining) = dissect_dbcs(name);
            if !is_fat_dbcs_legal(first, wild_cards, false, false) {
                return false;
            }
            if remaining.is_empty() {
                return true;
            }
            if remaining[0] == b'\\' {
                return false;
            }
            name = remaining;
        }
    }
    let legal_mask = if wild_cards { FSRTL_FAT_LEGAL | FSRTL_WILD_CHARACTER } else { FSRTL_FAT_LEGAL };
    if wild_cards && dbcs_contains_wild_cards(name) {
        let mut index = 0;
        while index < name.len() {
            let byte = name[index];
            if byte >= 0x80 && is_lead_dbcs(byte) {
                index += 2;
                continue;
            }
            if byte < 0x80 && FSRTL_LEGAL_ANSI_CHARACTER_ARRAY[byte as usize] & legal_mask == 0 {
                return false;
            }
            index += 1;
        }
        return true;
    }
    if name.len() > 12 {
        return false;
    }
    let (mut extension, mut index, mut last) = (false, 0, 0u8);
    while index < name.len() {
        let byte = name[index];
        last = byte;
        if byte >= 0x80 && is_lead_dbcs(byte) {
            if !extension && index >= 7 {
                return false;
            }
            if index == name.len() - 1 {
                return false;
            }
            index += 2;
            continue;
        }
        if byte < 0x80 && FSRTL_LEGAL_ANSI_CHARACTER_ARRAY[byte as usize] & legal_mask == 0 {
            return false;
        }
        if byte == b'.' || byte == b'"' {
            if index == 0 || extension || name.len() - index - 1 > 3 || name[index - 1] == b' ' {
                return false;
            }
            extension = true;
        }
        if index >= 8 && !extension {
            return false;
        }
        index += 1;
    }
    !matches!(last, b' ' | b'"' | b'.')
}
