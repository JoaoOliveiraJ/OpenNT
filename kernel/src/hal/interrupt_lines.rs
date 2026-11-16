//! As linhas de interrupção que a HAL publica por GSI.
//!
//! No NT, cada controlador de interrupção registrado pela HAL tem faixas de
//! linhas (`HalpRegisteredInterruptControllers`, o registro de linhas de
//! cada um com a linha mínima, a máxima exclusiva e a GSI base); o
//! `HalpInterruptFindLinesForGsiRange` acha a faixa que cobre uma GSI e as
//! linhas sem GSI (as do 8259, GSI base -1) ficam de fora. Num PC ACPI os
//! controladores com GSI são os IOAPICs da MADT: a faixa de um IOAPIC
//! começa na GSI base da entrada da MADT e tem tantas linhas quantas o
//! registrador de versão dele declara (MaxRedirectionEntry + 1).
//!
//! O OpenNT entrega as interrupções de dispositivo pelo 8259 (vetor
//! `0x20 + IRQ`), mas o registro de linhas por GSI é o que a MADT descreve,
//! como o que a HAL do NT monta; é dele que o acpi.sys tira a validade de
//! uma GSI (HalpInterruptIsGsiValid) e a versão de um IOAPIC
//! (HalpInterruptGetApicVersion), pela tabela de energia da HAL.

use alloc::vec::Vec;

use crate::hal::{acpi, physical};
use crate::rtl::SpinLock;

/// Uma faixa de linhas com GSI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LineRange {
    /// Id do IOAPIC na MADT.
    pub apic_id: u8,
    /// Endereço físico dos registradores do IOAPIC.
    pub address: u32,
    pub gsi_base: u32,
    /// Linhas da faixa (MaxLine - MinLine; MinLine = 0).
    pub count: u32,
}

impl LineRange {
    /// A GSI está nesta faixa ([base, base + count)).
    pub fn covers(&self, gsi: u32) -> bool {
        gsi >= self.gsi_base && gsi - self.gsi_base < self.count
    }
}

static RANGES: SpinLock<Option<Vec<LineRange>>> = SpinLock::new(None);

/// Tipo de entrada da MADT de um IOAPIC (ACPI 6.x, 5.2.12.3).
const MADT_IO_APIC: u8 = 1;
/// Cabeçalho da MADT: SDT (36), LocalApicAddress e Flags.
const MADT_ENTRIES: usize = 44;

/// MaxRedirectionEntry + 1 do registrador de versão (índice 1) do IOAPIC:
/// IOREGSEL em +0, IOWIN em +0x10.
fn io_apic_lines(address: u32) -> u32 {
    physical::write32(address as u64, 1);
    let version = physical::read32(address as u64 + 0x10);
    ((version >> 16) & 0xFF) + 1
}

/// As faixas dos IOAPICs da MADT, na ordem da tabela.
fn discover() -> Vec<LineRange> {
    let Some(madt) = acpi::get_table("APIC", 0, false) else { return Vec::new() };
    let bytes = &madt.bytes;
    let mut ranges = Vec::new();
    let mut offset = MADT_ENTRIES;
    while offset + 2 <= bytes.len() {
        let (entry_type, length) = (bytes[offset], bytes[offset + 1] as usize);
        if length < 2 || offset + length > bytes.len() {
            break;
        }
        if entry_type == MADT_IO_APIC && length >= 12 {
            let address = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
            let gsi_base = u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap());
            ranges.push(LineRange { apic_id: bytes[offset + 2], address, gsi_base, count: io_apic_lines(address) });
        }
        offset += length;
    }
    ranges
}

/// As faixas registradas (descobertas na primeira consulta).
pub fn ranges() -> Vec<LineRange> {
    let mut cached = RANGES.lock();
    if cached.is_none() {
        *cached = Some(discover());
    }
    cached.as_ref().cloned().unwrap_or_default()
}

/// HalpInterruptFindLinesForGsiRange(Start, End): a faixa que contém
/// [start, end) inteiro.
pub fn find(start: u32, end: u32) -> Option<LineRange> {
    ranges().into_iter().find(|range| range.covers(start) && end > start && range.covers(end - 1))
}

/// HalpInterruptIsGsiValid: a GSI tem linha (HalpInterruptGsiToLine).
pub fn is_gsi_valid(gsi: u32) -> bool {
    find(gsi, gsi.wrapping_add(1)).is_some()
}

/// HalpInterruptGetApicVersion: o registrador de versão sintetizado da faixa
/// que cobre a GSI (versão 0x11, MaxRedirectionEntry no byte 2 e o número de
/// linhas no byte 3); sem faixa, 0xF0000000.
pub fn apic_version(gsi: u32) -> u32 {
    match find(gsi, gsi.wrapping_add(1)) {
        Some(range) => 0x11 | (range.count.wrapping_sub(1) & 0xFF) << 16 | (range.count & 0xFF) << 24,
        None => 0xF000_0000,
    }
}

// ---- vetores atribuídos e as linhas do 8259 ---------------------------------
//
// Com a raiz ACPI, o árbitro de IRQ do acpi.sys escolhe para cada GSI um
// vetor do IDT do conjunto que a HAL dá ao dispositivo ACPI raiz (GSIs no
// mesmo IRQL podem dividir um vetor), e o tradutor dele entrega esse vetor
// na lista traduzida; a HAL do NT programa então a entrada do IOAPIC de cada
// GSI para o vetor dela quando o driver conecta, e todas as ISRs conectadas
// ao vetor recebem as interrupções das GSIs que o alimentam. A HAL do
// OpenNT entrega as linhas pelo 8259, cada uma no vetor fixo
// `0x20 + linha`: cada linha fica registrada com o vetor atribuído a ela, a
// conexão num vetor atribuído recebe as interrupções das linhas dele, e o
// vetor fixo de uma linha despacha a cadeia do vetor atribuído.

/// (vetor atribuído, linha do 8259 que o alimenta); uma linha tem um vetor.
static ROUTES: SpinLock<Vec<(u32, u32)>> = SpinLock::new(Vec::new());
/// Vetor do IDT da linha 0 do 8259 na HAL do OpenNT.
const PIC_VECTOR_BASE: u32 = 0x20;
/// Linhas do par de 8259.
const PIC_LINES: u32 = 16;

/// Registra que a linha `line` (a GSI bruta) alimenta o vetor `vector`
/// atribuído a um dispositivo. Linhas fora do 8259 não têm entrega; o vetor
/// fixo da própria linha não precisa de registro.
pub fn route_vector(vector: u32, line: u32) {
    if line >= PIC_LINES || vector == PIC_VECTOR_BASE + line {
        return;
    }
    let mut routes = ROUTES.lock();
    routes.retain(|&(_, routed)| routed != line);
    routes.push((vector, line));
}

/// Os vetores do IDT em que a HAL entrega as interrupções de um vetor
/// atribuído: os das linhas do 8259 que o alimentam, ou o próprio vetor.
pub fn delivery_vectors(vector: u32) -> Vec<u32> {
    let lines: Vec<u32> = ROUTES.lock().iter().filter(|&&(assigned, _)| assigned == vector).map(|&(_, line)| PIC_VECTOR_BASE + line).collect();
    if lines.is_empty() {
        alloc::vec![vector]
    } else {
        lines
    }
}

/// A cadeia que o vetor do IDT `vector` despacha: a do vetor atribuído à
/// linha do 8259 dele, ou a do próprio vetor.
pub fn chain_vector(vector: u32) -> u32 {
    let Some(line) = vector.checked_sub(PIC_VECTOR_BASE).filter(|&line| line < PIC_LINES) else { return vector };
    ROUTES.lock().iter().find(|&&(_, routed)| routed == line).map_or(vector, |&(assigned, _)| assigned)
}
