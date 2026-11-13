//! Regras de registro da política de Secure Boot.
//!
//! Capturar os bytes do loader valida a estrutura; não autentica nem ativa
//! Secure Boot.

use alloc::vec::Vec;

use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

const HEADER_SIZE: usize = 0x3C;
const REGISTRY_RULE_SIZE: usize = 16;
const REGISTRY_RULE_KIND: u32 = 0x8100_0000;

#[derive(Clone)]
pub struct Rule {
    key_offset: usize,
    name_offset: usize,
    value_type: u32,
    supported: bool,
    data_offset: usize,
    data_length: u32,
}

/// Consulta capturada: sem política, ou os bytes próprios e as regras.
#[derive(Clone)]
pub enum Captured {
    Inactive,
    Active { bytes: Vec<u8>, rules: Vec<Rule> },
}

struct Boot {
    query: Captured,
    /// Provider, Version e Options do cabeçalho (SeSecureBootQueryInformation).
    information: Option<[u8; 24]>,
}

static BOOT: SpinLock<Option<Boot>> = SpinLock::new(None);

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u32_at(bytes, offset) as u64 | (u32_at(bytes, offset + 4) as u64) << 32
}

/// QWORDs iguais como caminho rápido, depois WCHARs convertendo só a..z
/// ASCII. MaximumLength não participa.
fn equal_policy_name(descriptor: u64, bytes: &[u8], name_offset: usize) -> bool {
    let length = guest::read16(descriptor) as usize;
    if length != u16_at(bytes, name_offset) as usize {
        return false;
    }
    let buffer = guest::read64(descriptor + 8);
    let text = name_offset + 2;
    let mut offset = 0usize;
    while offset + 8 <= length {
        if guest::read64(buffer + offset as u64) != u64_at(bytes, text + offset) {
            break;
        }
        offset += 8;
    }
    let upper = |unit: u16| if (97..=122).contains(&unit) { unit - 32 } else { unit };
    while offset < length {
        if upper(guest::read16(buffer + offset as u64)) != upper(u16_at(bytes, text + offset)) {
            return false;
        }
        offset += 2;
    }
    true
}

/// A captura possui todos os bytes; offsets nunca viram ponteiros externos.
/// Regras de outros tipos são ignoradas, não reinterpretadas.
pub fn capture(policy: Option<&[u8]>) -> Result<Captured, KernelError> {
    let Some(source) = policy else { return Ok(Captured::Inactive) };
    if source.len() < HEADER_SIZE {
        return Err(KernelError::new("SecureBootPolicy: invalid loader policy header"));
    }
    let bytes = source.to_vec();
    let rule_count = u16_at(&bytes, 0x26) as usize;
    let rules_offset = HEADER_SIZE + u32_at(&bytes, 0x2C) as usize;
    let values_offset = HEADER_SIZE + u32_at(&bytes, 0x34) as usize;
    let require = |offset: usize, size: usize| -> Result<(), KernelError> {
        if offset > bytes.len() || size > bytes.len() - offset {
            return Err(KernelError::new("SecureBootPolicy: table exceeds owned policy"));
        }
        Ok(())
    };
    let capture_name = |offset: usize| -> Result<usize, KernelError> {
        require(offset, 2)?;
        // Comprimento ímpar ainda faz o comparador ler o último WCHAR inteiro.
        require(offset + 2, (u16_at(&bytes, offset) as usize + 1) & !1)?;
        Ok(offset)
    };
    if rule_count != 0 {
        require(rules_offset, rule_count * REGISTRY_RULE_SIZE)?;
    }
    let mut rules = Vec::new();
    for index in 0..rule_count {
        let record = rules_offset + index * REGISTRY_RULE_SIZE;
        if u32_at(&bytes, record) != REGISTRY_RULE_KIND {
            continue;
        }
        let key_offset = capture_name(values_offset + u32_at(&bytes, record + 4) as usize)?;
        let name_offset = capture_name(values_offset + u32_at(&bytes, record + 8) as usize)?;
        let value_offset = values_offset + u32_at(&bytes, record + 12) as usize;
        require(value_offset, 2)?;
        let value_type = u16_at(&bytes, value_offset) as u32;
        let (supported, data_offset, data_length) = match value_type & 31 {
            0 | 10 => {
                require(value_offset, 4)?;
                (true, value_offset + 4, u16_at(&bytes, value_offset + 2) as u32)
            }
            2 => (true, value_offset + 2, 4),
            4 => {
                require(value_offset, 8)?;
                (true, value_offset + 8, u16_at(&bytes, value_offset + 6) as u32 * 4)
            }
            5 => (true, value_offset + 2, 8),
            _ => (false, value_offset, 0),
        };
        if supported {
            require(data_offset, data_length as usize)?;
        }
        rules.push(Rule { key_offset, name_offset, value_type, supported, data_offset, data_length });
    }
    Ok(Captured::Active { bytes, rules })
}

impl Captured {
    /// A primeira regra com os dois nomes vence, mesmo de tipo diferente;
    /// nada é escrito antes dessa validação.
    pub fn query(&self, key: u64, name: u64, expected_type: u64, buffer: u64, capacity: u64, returned_length: u64) -> u32 {
        let Captured::Active { bytes, rules } = self else { return 0x8043_0006 };
        for rule in rules {
            if !equal_policy_name(key, bytes, rule.key_offset) || !equal_policy_name(name, bytes, rule.name_offset) {
                continue;
            }
            if expected_type as u32 != rule.value_type {
                return 0xC000_0034;
            }
            if !rule.supported {
                return 0xC000_0002;
            }
            guest::write32(returned_length, rule.data_length);
            if buffer == 0 {
                return 0;
            }
            if (capacity as u32) < rule.data_length {
                return 0xC000_0023;
            }
            // A escrita do tamanho pode sobrepor o buffer de saída.
            guest::write_bytes(buffer, &bytes[rule.data_offset..rule.data_offset + rule.data_length as usize]);
            return 0;
        }
        0xC000_0034
    }
}

pub fn init(policy: Option<&[u8]>) -> Result<(), KernelError> {
    let mut boot = BOOT.lock();
    if boot.is_some() {
        return Err(KernelError::new("SecureBootPolicy: boot already initialized"));
    }
    let query = capture(policy)?;
    let information = policy.map(|bytes| {
        let mut information = [0u8; 24];
        information[..16].copy_from_slice(&bytes[4..20]);
        information[16..20].copy_from_slice(&bytes[0x14..0x18]);
        information[20..24].copy_from_slice(&bytes[0x20..0x24]);
        information
    });
    *boot = Some(Boot { query, information });
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn query(key: u64, name: u64, expected_type: u64, buffer: u64, capacity: u64, returned_length: u64) -> Result<u32, KernelError> {
    let captured = BOOT.lock().as_ref().map(|boot| boot.query.clone()).ok_or_else(|| KernelError::new("SecureBootPolicy: boot not initialized"))?;
    Ok(captured.query(key, name, expected_type, buffer, capacity, returned_length))
}

/// Cópia dos metadados; o consumidor não altera a política do boot.
pub fn get_information() -> Result<Option<[u8; 24]>, KernelError> {
    BOOT.lock().as_ref().map(|boot| boot.information).ok_or_else(|| KernelError::new("SecureBootPolicy: boot not initialized"))
}
