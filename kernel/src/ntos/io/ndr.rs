//! NDR32 limitado.
//!
//! Escalares little-endian, strings conformantes e context handles; os
//! referentes do fio são identificadores, nunca endereços virtuais.

use alloc::string::String;
use alloc::vec::Vec;

/// RPC_X_BAD_STUB_DATA.
pub const FAULT: u32 = 1783;

pub struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, offset: 0 }
    }

    pub fn align(&mut self, alignment: usize) {
        self.offset = self.offset.div_ceil(alignment) * alignment;
    }

    fn take(&mut self, count: usize) -> Result<usize, u32> {
        if self.offset.checked_add(count).is_none_or(|end| end > self.bytes.len()) {
            return Err(FAULT);
        }
        let at = self.offset;
        self.offset += count;
        Ok(at)
    }

    pub fn u32(&mut self) -> Result<u32, u32> {
        self.align(4);
        let at = self.take(4)?;
        Ok(u32::from_le_bytes(self.bytes[at..at + 4].try_into().unwrap()))
    }

    pub fn u8(&mut self) -> Result<u8, u32> {
        let at = self.take(1)?;
        Ok(self.bytes[at])
    }

    pub fn u64(&mut self) -> Result<u64, u32> {
        self.align(8);
        let at = self.take(8)?;
        Ok(u64::from_le_bytes(self.bytes[at..at + 8].try_into().unwrap()))
    }

    pub fn raw(&mut self, count: usize) -> Result<Vec<u8>, u32> {
        let at = self.take(count)?;
        Ok(self.bytes[at..self.offset].to_vec())
    }

    pub fn context(&mut self) -> Result<Vec<u8>, u32> {
        self.align(4);
        self.raw(20)
    }

    /// String conformante e variável terminada em NUL; `unique` aceita o
    /// ponteiro nulo.
    pub fn string(&mut self, unique: bool, limit: u32) -> Result<Option<String>, u32> {
        if unique && self.u32()? == 0 {
            return Ok(None);
        }
        let maximum = self.u32()?;
        let offset = self.u32()?;
        let length = self.u32()?;
        if length == 0 || maximum > limit || offset != 0 || length > maximum {
            return Err(FAULT);
        }
        let at = self.take(length as usize * 2)?;
        let unit = |index: usize| u16::from_le_bytes([self.bytes[at + index * 2], self.bytes[at + index * 2 + 1]]);
        if unit(length as usize - 1) != 0 {
            return Err(FAULT);
        }
        let units: Vec<u16> = (0..length as usize - 1).map(unit).collect();
        Ok(Some(String::from_utf16_lossy(&units)))
    }

    pub fn end(&mut self) -> Result<(), u32> {
        self.align(4);
        if self.offset > self.bytes.len() + 3 || self.offset < self.bytes.len() {
            return Err(FAULT);
        }
        Ok(())
    }
}

pub struct Writer {
    bytes: Vec<u8>,
    referent: u32,
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

impl Writer {
    pub fn new() -> Self {
        Writer { bytes: Vec::new(), referent: 0x20000 }
    }

    pub fn align(&mut self, alignment: usize) -> &mut Self {
        while !self.bytes.len().is_multiple_of(alignment) {
            self.bytes.push(0);
        }
        self
    }

    pub fn u32(&mut self, value: u32) -> &mut Self {
        self.align(4);
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn u8(&mut self, value: u8) -> &mut Self {
        self.bytes.push(value);
        self
    }

    pub fn u64(&mut self, value: u64) -> &mut Self {
        self.align(8);
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.bytes.extend_from_slice(bytes);
        self
    }

    pub fn context(&mut self, bytes: Option<&[u8]>) -> &mut Self {
        self.align(4);
        match bytes {
            Some(bytes) => self.raw(bytes),
            None => self.raw(&[0; 20]),
        }
    }

    /// Referente não nulo: identificadores crescentes a partir de 0x20000.
    pub fn pointer(&mut self, present: bool) -> &mut Self {
        let value = if present {
            self.referent += 4;
            self.referent
        } else {
            0
        };
        self.u32(value)
    }

    pub fn string(&mut self, value: Option<&str>, unique: bool) -> &mut Self {
        if unique {
            self.pointer(value.is_some());
        }
        let Some(value) = value else { return self };
        let units: Vec<u16> = value.encode_utf16().collect();
        let count = units.len() as u32 + 1;
        self.u32(count).u32(0).u32(count);
        for unit in units.iter().chain(core::iter::once(&0)) {
            self.bytes.extend_from_slice(&unit.to_le_bytes());
        }
        self
    }

    pub fn finish(&mut self) -> Vec<u8> {
        self.align(4);
        core::mem::take(&mut self.bytes)
    }
}
