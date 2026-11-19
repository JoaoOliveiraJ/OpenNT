//! O fluxo de registros do alvo (`kernel/src/ntos/kd/stream.rs`): as
//! chamadas de API do monitor e os eventos do rastreador de IRPs.
//!
//! Os registros chegam de dois jeitos: em pacotes `O` com a máquina rodando
//! (o conteúdo começa com o marcador `\0OSTR` e a versão, e a conexão os
//! separa da saída de texto) e pelo `qOpenNTStream:SEQ` com a máquina
//! parada (um cabeçalho de 32 bytes e os registros a partir de SEQ). Cada
//! registro tem número de sequência: o `Collector` descarta os repetidos e
//! conta as falhas de sequência como perdas.
//!
//! ```text
//! cabeçalho: tamanho u16 | tipo u8 | CPU u8 | flags u32 | sequência u64 | hora u64 (100 ns)
//! API:       id u32 | argumentos u8 | textos u8 | reservado u16 | PID u32 | TID u32 |
//!            ETHREAD u64 | retorno u64 | duração u64 | resultado u64 | argumentos u64... |
//!            textos: argumento u8, tipo u8, tamanho u16, bytes
//! IRP:       IRP u64 | dispositivo u64 | driver u64 | ETHREAD u64 | chamador u64 |
//!            rotina u64 | valor u64 | Information u64 | major u8 | minor u8 |
//!            posição u8 | pilha u8 | PID u32
//! ```

/// O marcador do conteúdo de um `O` com registros.
pub const MARKER: &[u8] = b"\0OSTR";
pub const HEADER_SIZE: usize = 24;

pub const KIND_API: u8 = 1;
pub const KIND_IRP_ALLOCATE: u8 = 0x10;
pub const KIND_IRP_CALL: u8 = 0x11;
pub const KIND_IRP_RETURN: u8 = 0x12;
pub const KIND_IRP_COMPLETE: u8 = 0x13;
pub const KIND_IRP_ROUTINE: u8 = 0x14;
pub const KIND_IRP_FREE: u8 = 0x15;

/// Os tipos de texto copiado pelo alvo (`api spec`).
pub const TEXT_UNICODE_STRING: u8 = 1;
pub const TEXT_ANSI_STRING: u8 = 2;
pub const TEXT_WIDE: u8 = 3;
pub const TEXT_ANSI: u8 = 4;
pub const TEXT_OBJECT_ATTRIBUTES: u8 = 5;
pub const TEXT_OUTPUT_POINTER: u8 = 6;

pub const FLAG_ERROR: u32 = 1;
pub const FLAG_TRANSFER: u32 = 2;

/// Um argumento copiado pelo alvo na volta da chamada.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capture {
    /// O argumento (1 = o primeiro).
    pub argument: u8,
    pub kind: u8,
    pub bytes: Vec<u8>,
}

impl Capture {
    /// O texto (UTF-8) ou o ponteiro apontado.
    pub fn text(&self) -> String {
        if self.kind == TEXT_OUTPUT_POINTER && self.bytes.len() == 8 {
            return format!("{:#x}", u64::from_le_bytes(self.bytes[..8].try_into().unwrap_or([0; 8])));
        }
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

/// Uma chamada de export.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiCall {
    pub sequence: u64,
    pub cpu: u8,
    pub flags: u32,
    /// A hora da entrada (100 ns desde o boot).
    pub time: u64,
    pub id: u32,
    pub pid: u32,
    pub tid: u32,
    pub thread: u64,
    pub return_address: u64,
    /// 100 ns.
    pub duration: u64,
    pub result: u64,
    pub arguments: Vec<u64>,
    pub captures: Vec<Capture>,
}

impl ApiCall {
    pub fn failed_internally(&self) -> bool {
        self.flags & FLAG_ERROR != 0
    }

    pub fn capture(&self, argument: u8) -> Option<&Capture> {
        self.captures.iter().find(|capture| capture.argument == argument)
    }
}

/// Um evento de IRP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrpEvent {
    pub sequence: u64,
    pub kind: u8,
    pub cpu: u8,
    pub time: u64,
    pub irp: u64,
    pub device: u64,
    pub driver: u64,
    pub thread: u64,
    pub caller: u64,
    pub routine: u64,
    pub value: u64,
    pub information: u64,
    pub major: u8,
    pub minor: u8,
    pub location: u8,
    pub stack: u8,
    pub pid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    Api(ApiCall),
    Irp(IrpEvent),
    /// Um tipo que este cliente não conhece (o tamanho já pulado).
    Unknown { sequence: u64, kind: u8 },
}

impl Record {
    pub fn sequence(&self) -> u64 {
        match self {
            Record::Api(call) => call.sequence,
            Record::Irp(event) => event.sequence,
            Record::Unknown { sequence, .. } => *sequence,
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Reader<'_> {
    fn take(&mut self, count: usize) -> Option<&[u8]> {
        let slice = self.bytes.get(self.position..self.position + count)?;
        self.position += count;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|bytes| bytes[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap_or([0; 4])))
    }

    fn u64(&mut self) -> Option<u64> {
        self.take(8).map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8])))
    }
}

/// Um registro inteiro (com o cabeçalho); `None` se estiver truncado.
pub fn parse_record(bytes: &[u8]) -> Option<Record> {
    let mut reader = Reader { bytes, position: 0 };
    let length = reader.u16()? as usize;
    if length < HEADER_SIZE || length > bytes.len() {
        return None;
    }
    let mut reader = Reader { bytes: &bytes[..length], position: 2 };
    let kind = reader.u8()?;
    let cpu = reader.u8()?;
    let flags = reader.u32()?;
    let sequence = reader.u64()?;
    let time = reader.u64()?;
    match kind {
        KIND_API => {
            let id = reader.u32()?;
            let argument_count = reader.u8()? as usize;
            let capture_count = reader.u8()? as usize;
            reader.u16()?;
            let pid = reader.u32()?;
            let tid = reader.u32()?;
            let thread = reader.u64()?;
            let return_address = reader.u64()?;
            let duration = reader.u64()?;
            let result = reader.u64()?;
            let mut arguments = Vec::with_capacity(argument_count);
            for _ in 0..argument_count {
                arguments.push(reader.u64()?);
            }
            let mut captures = Vec::with_capacity(capture_count);
            for _ in 0..capture_count {
                let argument = reader.u8()?;
                let kind = reader.u8()?;
                let size = reader.u16()? as usize;
                captures.push(Capture { argument, kind, bytes: reader.take(size)?.to_vec() });
            }
            Some(Record::Api(ApiCall { sequence, cpu, flags, time, id, pid, tid, thread, return_address, duration, result, arguments, captures }))
        }
        KIND_IRP_ALLOCATE..=KIND_IRP_FREE => {
            let mut values = [0u64; 8];
            for value in &mut values {
                *value = reader.u64()?;
            }
            let fields = reader.take(4)?.to_vec();
            let pid = reader.u32()?;
            Some(Record::Irp(IrpEvent {
                sequence,
                kind,
                cpu,
                time,
                irp: values[0],
                device: values[1],
                driver: values[2],
                thread: values[3],
                caller: values[4],
                routine: values[5],
                value: values[6],
                information: values[7],
                major: fields[0],
                minor: fields[1],
                location: fields[2],
                stack: fields[3],
                pid,
            }))
        }
        _ => Some(Record::Unknown { sequence, kind }),
    }
}

/// Os registros seguidos de um bloco (o conteúdo de um `O` sem o marcador,
/// ou a resposta do `qOpenNTStream` sem o cabeçalho).
pub fn parse_records(mut bytes: &[u8]) -> Vec<Record> {
    let mut records = Vec::new();
    while bytes.len() >= HEADER_SIZE {
        let length = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        if length < HEADER_SIZE || length > bytes.len() {
            break;
        }
        if let Some(record) = parse_record(&bytes[..length]) {
            records.push(record);
        }
        bytes = &bytes[length..];
    }
    records
}

/// O conteúdo de um `O` assíncrono, se for do fluxo: os registros.
pub fn parse_packet(bytes: &[u8]) -> Option<Vec<Record>> {
    let rest = bytes.strip_prefix(MARKER)?;
    let (&version, records) = rest.split_first()?;
    (version == 1).then(|| parse_records(records))
}

/// O cabeçalho da resposta do `qOpenNTStream`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadHeader {
    /// O próximo número que o alvo vai dar.
    pub next: u64,
    /// O mais antigo ainda no anel.
    pub oldest: u64,
    /// Perdidos no alvo (anel cheio na entrega).
    pub dropped: u64,
    pub api_enabled: bool,
    pub irp_enabled: bool,
    pub async_enabled: bool,
}

/// A resposta do `qOpenNTStream`: o cabeçalho e os registros.
pub fn parse_read(bytes: &[u8]) -> Option<(ReadHeader, Vec<Record>)> {
    if bytes.len() < 32 {
        return None;
    }
    let number = |offset: usize| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap_or([0; 8]));
    let flags = u32::from_le_bytes(bytes[24..28].try_into().unwrap_or([0; 4]));
    let header = ReadHeader { next: number(0), oldest: number(8), dropped: number(16), api_enabled: flags & 1 != 0, irp_enabled: flags & 2 != 0, async_enabled: flags & 4 != 0 };
    Some((header, parse_records(&bytes[32..])))
}

/// Junta os registros dos dois caminhos em ordem, sem repetir.
#[derive(Clone, Debug, Default)]
pub struct Collector {
    /// O próximo número esperado.
    pub next: u64,
    /// Falhas de sequência (registros que nunca chegaram).
    pub lost: u64,
    pub records: Vec<Record>,
}

impl Collector {
    /// Aceita um registro; devolve se era novo.
    pub fn push(&mut self, record: Record) -> bool {
        let sequence = record.sequence();
        if sequence < self.next {
            return false;
        }
        self.lost += sequence - self.next;
        self.next = sequence + 1;
        self.records.push(record);
        true
    }

    /// Conta um número sem guardar o registro; devolve se era novo.
    pub fn accept(&mut self, sequence: u64) -> bool {
        if sequence < self.next {
            return false;
        }
        self.lost += sequence - self.next;
        self.next = sequence + 1;
        true
    }

    pub fn extend(&mut self, records: impl IntoIterator<Item = Record>) -> usize {
        records.into_iter().map(|record| self.push(record) as usize).sum()
    }

    /// Começa do número dado (um monitor religado: o que veio antes não
    /// interessa).
    pub fn restart(&mut self, next: u64) {
        self.next = next;
        self.lost = 0;
    }

    /// Tira os registros acumulados.
    pub fn take(&mut self) -> Vec<Record> {
        std::mem::take(&mut self.records)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Monta um registro de API como o alvo grava.
    pub fn api_record(sequence: u64, id: u32, arguments: &[u64], result: u64, return_address: u64, captures: &[(u8, u8, &[u8])]) -> Vec<u8> {
        let mut bytes = vec![0u8; HEADER_SIZE];
        bytes[2] = KIND_API;
        bytes[3] = 1;
        bytes[8..16].copy_from_slice(&sequence.to_le_bytes());
        bytes[16..24].copy_from_slice(&(1000 + sequence * 10).to_le_bytes());
        bytes.extend_from_slice(&id.to_le_bytes());
        bytes.push(arguments.len() as u8);
        bytes.push(captures.len() as u8);
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&88u32.to_le_bytes());
        bytes.extend_from_slice(&0xFFFF_A000_0000_1000u64.to_le_bytes());
        bytes.extend_from_slice(&return_address.to_le_bytes());
        bytes.extend_from_slice(&25u64.to_le_bytes());
        bytes.extend_from_slice(&result.to_le_bytes());
        for argument in arguments {
            bytes.extend_from_slice(&argument.to_le_bytes());
        }
        for (argument, kind, text) in captures {
            bytes.push(*argument);
            bytes.push(*kind);
            bytes.extend_from_slice(&(text.len() as u16).to_le_bytes());
            bytes.extend_from_slice(text);
        }
        let length = bytes.len() as u16;
        bytes[0..2].copy_from_slice(&length.to_le_bytes());
        bytes
    }

    /// Monta um evento de IRP como o alvo grava.
    #[allow(clippy::too_many_arguments)]
    pub fn irp_record(sequence: u64, kind: u8, time: u64, irp: u64, device: u64, driver: u64, caller: u64, routine: u64, value: u64, major: u8, minor: u8, location: u8, stack: u8) -> Vec<u8> {
        let mut bytes = vec![0u8; HEADER_SIZE];
        bytes[2] = kind;
        bytes[8..16].copy_from_slice(&sequence.to_le_bytes());
        bytes[16..24].copy_from_slice(&time.to_le_bytes());
        for value in [irp, device, driver, 0xFFFF_A000_0000_2000, caller, routine, value, 0x10] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&[major, minor, location, stack]);
        bytes.extend_from_slice(&4u32.to_le_bytes());
        let length = bytes.len() as u16;
        bytes[0..2].copy_from_slice(&length.to_le_bytes());
        bytes
    }

    #[test]
    fn decodes_an_api_record_with_texts() {
        let bytes = api_record(7, 600, &[0xFFFF_8000_1000_0000, 0x40, 0xFFFF_8000_2000_0000], 0, 0xFFFF_F800_1234_5678, &[(3, TEXT_UNICODE_STRING, "\\Device\\Teste".as_bytes())]);
        let Some(Record::Api(call)) = parse_record(&bytes) else { panic!("registro de API") };
        assert_eq!(call.sequence, 7);
        assert_eq!(call.id, 600);
        assert_eq!(call.arguments.len(), 3);
        assert_eq!(call.arguments[1], 0x40);
        assert_eq!(call.return_address, 0xFFFF_F800_1234_5678);
        assert_eq!(call.pid, 4);
        assert_eq!(call.tid, 88);
        assert_eq!(call.duration, 25);
        assert_eq!(call.capture(3).map(Capture::text).as_deref(), Some("\\Device\\Teste"));
    }

    #[test]
    fn decodes_irp_events_and_packets() {
        let mut packet = MARKER.to_vec();
        packet.push(1);
        packet.extend(irp_record(1, KIND_IRP_CALL, 50, 0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0, 3, 0, 2, 2));
        packet.extend(irp_record(2, KIND_IRP_RETURN, 60, 0x1000, 0x2000, 0x3000, 0, 0, 0x103, 0, 0, 2, 2));
        let records = parse_packet(&packet).expect("pacote do fluxo");
        assert_eq!(records.len(), 2);
        let Record::Irp(call) = &records[0] else { panic!("evento de IRP") };
        assert_eq!((call.kind, call.irp, call.device, call.driver, call.major, call.location), (KIND_IRP_CALL, 0x1000, 0x2000, 0x3000, 3, 2));
        assert!(parse_packet(b"texto comum").is_none());
    }

    #[test]
    fn collector_skips_repeats_and_counts_gaps() {
        let mut collector = Collector::default();
        let record = |sequence| Record::Unknown { sequence, kind: 9 };
        assert!(collector.push(record(0)));
        assert!(collector.push(record(1)));
        assert!(!collector.push(record(1)));
        assert!(collector.push(record(4)));
        assert_eq!(collector.lost, 2);
        assert_eq!(collector.next, 5);
        assert_eq!(collector.take().len(), 3);
    }

    #[test]
    fn read_reply_header() {
        let mut bytes = vec![0u8; 32];
        bytes[0..8].copy_from_slice(&10u64.to_le_bytes());
        bytes[8..16].copy_from_slice(&2u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&1u64.to_le_bytes());
        bytes[24] = 0b101;
        bytes.extend(api_record(9, 40, &[], 0, 0, &[]));
        let (header, records) = parse_read(&bytes).expect("resposta");
        assert_eq!((header.next, header.oldest, header.dropped, header.api_enabled, header.irp_enabled, header.async_enabled), (10, 2, 1, true, false, true));
        assert_eq!(records.len(), 1);
    }
}
