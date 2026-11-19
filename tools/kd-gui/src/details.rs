//! As leituras e os textos das vistas além do básico de cada parada:
//!
//! - espera e prioridade de cada thread: o KTHREAD lido pelos offsets e
//!   pelos enums (`_KTHREAD_STATE`, `_KWAIT_REASON`) do PDB do ntoskrnl;
//! - a parte de usuário da pilha de uma thread que entrou no kernel: o
//!   CONTEXT de usuário salvo da thread (a consulta `uthreads` do alvo),
//!   desenrolado pela `.pdata` dos módulos do processo;
//! - o estado do PDB de cada módulo (o ELF do OpenNT, o PDB público, o
//!   download, só os exports);
//! - o símbolo dos ponteiros da janela de memória;
//! - os textos dos registradores: vetores do SSE/AVX por lanes, seletores
//!   de segmento e o DR6.

use std::collections::HashMap;

use kd_client::pdb::Fetch;
use kd_client::pe::guid_text;
use kd_client::symbols::{base_name, Module, Symbols};
use kd_client::types::{Kind, TypeDb};
use kd_client::unwind::Frame;
use kd_client::user::UserThread;
use kd_client::Client;

/// Onde está um campo escalar de uma struct e como lê-lo.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FieldSpec {
    pub offset: u64,
    pub size: usize,
    pub signed: bool,
    /// Bitfield: (primeiro bit, quantos bits).
    pub bits: Option<(u32, u32)>,
}

impl FieldSpec {
    /// O campo `name` da struct `index` do PDB (`None` se não existe ou não
    /// é escalar).
    pub fn of(database: &TypeDb, index: u32, name: &str) -> Option<FieldSpec> {
        let member = database.member(index, name)?;
        let (size, signed, bits) = match database.kind(member.ty) {
            Kind::Primitive { size, signed, .. } => (size, signed, None),
            Kind::Enum { underlying, .. } => (database.size(underlying), matches!(database.kind(underlying), Kind::Primitive { signed: true, .. }), None),
            Kind::Bitfield { base, length, position } => (database.size(base), false, Some((position, length))),
            _ => return None,
        };
        Some(FieldSpec { offset: member.offset, size: (size as usize).clamp(1, 8), signed, bits })
    }

    /// O valor do campo em `bytes`, que começam no offset `start` da struct
    /// (`None` se o campo cai fora deles).
    pub fn read(&self, bytes: &[u8], start: u64) -> Option<i64> {
        let at = usize::try_from(self.offset.checked_sub(start)?).ok()?;
        let slice = bytes.get(at..at + self.size)?;
        let mut raw = [0u8; 8];
        raw[..self.size].copy_from_slice(slice);
        let value = u64::from_le_bytes(raw);
        if let Some((position, length)) = self.bits {
            let mask = if length >= 64 { u64::MAX } else { (1u64 << length) - 1 };
            return Some(((value >> position) & mask) as i64);
        }
        if self.signed && self.size < 8 {
            let shift = 64 - 8 * self.size as u32;
            return Some(((value << shift) as i64) >> shift);
        }
        Some(value as i64)
    }

    fn end(&self) -> u64 {
        self.offset + self.size as u64
    }
}

/// Os campos do KTHREAD que a lista de threads mostra, pelo PDB.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KthreadLayout {
    pub state: Option<FieldSpec>,
    pub wait_reason: Option<FieldSpec>,
    pub wait_mode: Option<FieldSpec>,
    pub priority: Option<FieldSpec>,
    pub base_priority: Option<FieldSpec>,
    pub suspend_count: Option<FieldSpec>,
    pub kernel_time: Option<FieldSpec>,
    pub user_time: Option<FieldSpec>,
    /// Os nomes do `_KTHREAD_STATE` e do `_KWAIT_REASON`, pelo valor.
    pub state_names: Vec<String>,
    pub wait_names: Vec<String>,
}

/// O estado de uma thread lido do KTHREAD.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ThreadDetail {
    pub state: String,
    /// O motivo da espera (vazio fora de uma espera).
    pub wait_reason: String,
    /// `kernel` ou `usuário` (o WaitMode), junto com o motivo.
    pub wait_mode: String,
    pub priority: Option<i64>,
    pub base_priority: Option<i64>,
    pub suspend_count: Option<i64>,
    /// KernelTime e UserTime, em tiques do relógio.
    pub kernel_time: Option<i64>,
    pub user_time: Option<i64>,
}

/// Os enumeradores de um enum do PDB, pelo valor (de 0 até o último que
/// existe; os buracos ficam vazios).
fn enumerators(database: &TypeDb, name: &str) -> Vec<String> {
    let Some(index) = database.find(name) else { return Vec::new() };
    let mut names: Vec<String> = (0..96i128).map(|value| database.enumerator(index, value).unwrap_or_default()).collect();
    while names.last().is_some_and(String::is_empty) {
        names.pop();
    }
    names
}

impl KthreadLayout {
    /// Os offsets do `_KTHREAD` (o ETHREAD começa por ele) e os nomes dos
    /// enums. `None` sem o `_KTHREAD` ou sem o campo State.
    pub fn from_types(database: &TypeDb) -> Option<KthreadLayout> {
        let kthread = database.find("_KTHREAD")?;
        let field = |name: &str| FieldSpec::of(database, kthread, name);
        let layout = KthreadLayout {
            state: field("State"),
            wait_reason: field("WaitReason"),
            wait_mode: field("WaitMode"),
            priority: field("Priority"),
            base_priority: field("BasePriority"),
            suspend_count: field("SuspendCount"),
            kernel_time: field("KernelTime"),
            user_time: field("UserTime"),
            state_names: enumerators(database, "_KTHREAD_STATE"),
            wait_names: enumerators(database, "_KWAIT_REASON"),
        };
        layout.state.is_some().then_some(layout)
    }

    fn fields(&self) -> [Option<FieldSpec>; 8] {
        [self.state, self.wait_reason, self.wait_mode, self.priority, self.base_priority, self.suspend_count, self.kernel_time, self.user_time]
    }

    /// O pedaço do KTHREAD que cobre todos os campos: (offset, tamanho).
    pub fn span(&self) -> Option<(u64, usize)> {
        let start = self.fields().into_iter().flatten().map(|field| field.offset).min()?;
        let end = self.fields().into_iter().flatten().map(|field| field.end()).max()?;
        Some((start, (end - start) as usize))
    }

    /// Os campos de um KTHREAD em `bytes` (que começam no offset `start`).
    pub fn decode(&self, bytes: &[u8], start: u64) -> ThreadDetail {
        let value = |field: Option<FieldSpec>| field.and_then(|field| field.read(bytes, start));
        let name = |names: &[String], number: i64| usize::try_from(number).ok().and_then(|index| names.get(index)).filter(|entry| !entry.is_empty()).cloned().unwrap_or_else(|| number.to_string());
        let state = value(self.state);
        let state_name = state.map(|number| name(self.state_names.as_slice(), number)).unwrap_or_default();
        // Waiting (5), GateWaitObsolete e WaitingForProcessInSwap.
        let waiting = state == Some(5) || state_name.contains("Wait");
        let (wait_reason, wait_mode) = if waiting {
            let reason = value(self.wait_reason).map(|number| name(self.wait_names.as_slice(), number)).unwrap_or_default();
            let mode = match value(self.wait_mode) {
                Some(0) => "kernel".to_string(),
                Some(1) => "usuário".to_string(),
                Some(other) => other.to_string(),
                None => String::new(),
            };
            (reason, mode)
        } else {
            (String::new(), String::new())
        };
        ThreadDetail {
            state: state_name,
            wait_reason,
            wait_mode,
            priority: value(self.priority),
            base_priority: value(self.base_priority),
            suspend_count: value(self.suspend_count),
            kernel_time: value(self.kernel_time),
            user_time: value(self.user_time),
        }
    }
}

/// Espera e prioridade das threads pedidas: uma leitura do KTHREAD por
/// thread (as ilegíveis ficam de fora).
pub fn thread_details(client: &mut Client, layout: &KthreadLayout, threads: &[u64]) -> HashMap<u64, ThreadDetail> {
    let mut details = HashMap::new();
    let Some((start, length)) = layout.span() else { return details };
    for &ethread in threads {
        if let Ok(bytes) = client.read_memory(ethread + start, length) {
            details.insert(ethread, layout.decode(&bytes, start));
        }
    }
    details
}

/// A pilha de usuário de uma thread de um processo (o processo das
/// leituras já tem de ser o dela, `.process`): o CONTEXT salvo, desenrolado
/// pela `.pdata` dos módulos de usuário.
pub fn user_frames(client: &mut Client, ethread: u64, eprocess: u64, limit: usize) -> Result<(UserThread, Vec<Frame>), String> {
    let process = format!("{eprocess:#x}");
    let thread = client.user_threads(&process)?.into_iter().find(|thread| thread.ethread == ethread).ok_or_else(|| format!("ETHREAD {ethread:#x} sem estado de thread de usuario no processo {process}"))?;
    let (_, frames) = client.user_thread_backtrace(&thread, limit)?;
    Ok((thread, frames))
}

/// O estado dos símbolos de um módulo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PdbStatus {
    /// O kernel do OpenNT: os símbolos e as linhas do ELF (DWARF).
    Elf,
    /// O PDB público carregado (o caminho no cache).
    Loaded(String),
    Downloading,
    /// O download falhou (o motivo).
    Failed(String),
    /// O arquivo desta máquina sem PDB: só os exports (sem RSDS, ou sem
    /// download).
    ExportsOnly,
    /// Nenhum arquivo desta máquina para a imagem.
    NoFile,
}

impl PdbStatus {
    pub fn of(symbols: &Symbols, module: &Module) -> PdbStatus {
        if symbols.is_kernel(module) {
            return PdbStatus::Elf;
        }
        if let Some(path) = &module.pdb {
            return PdbStatus::Loaded(path.display().to_string());
        }
        if module.pdb_pending {
            return PdbStatus::Downloading;
        }
        // A identidade do PDB (o RSDS do arquivo desta máquina ou da memória
        // do alvo) e o estado dela na fila do cache de símbolos.
        let Some(id) = &module.pdb_id else {
            return if module.image.is_some() { PdbStatus::ExportsOnly } else { PdbStatus::NoFile };
        };
        let state = symbols.store.as_ref().and_then(|store| store.state(id));
        match state {
            Some(Fetch::Failed(error)) => PdbStatus::Failed(error.lines().next().unwrap_or("").to_string()),
            Some(Fetch::Downloading) => PdbStatus::Downloading,
            None => PdbStatus::ExportsOnly,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            PdbStatus::Elf => "ELF do OpenNT",
            PdbStatus::Loaded(_) => "PDB",
            PdbStatus::Downloading => "baixando",
            PdbStatus::Failed(_) => "falhou",
            PdbStatus::ExportsOnly => "só exports",
            PdbStatus::NoFile => "sem arquivo",
        }
    }
}

/// O nome do PDB e a identidade dele no servidor de símbolos (GUID e
/// idade), pelo RSDS do arquivo desta máquina.
pub fn pdb_identity(module: &Module) -> (String, String) {
    match module.image.as_ref().and_then(|image| image.rsds()) {
        Some((guid, age, name)) => (base_name(&name).to_string(), format!("{}{age:X}", guid_text(&guid))),
        None => (String::new(), String::new()),
    }
}

/// O símbolo de cada qword da janela de memória (a partir do começo dela)
/// que cai num módulo.
pub fn pointer_names(symbols: &Symbols, bytes: &[u8]) -> Vec<Option<String>> {
    bytes
        .chunks_exact(8)
        .map(|chunk| {
            let value = u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]));
            symbols.module_at(value).map(|_| symbols.describe(value))
        })
        .collect()
}

/// Um valor que parece ponteiro: canônico do kernel ou dentro da metade de
/// usuário (de MmLowestUserAddress até o fim dela).
pub fn looks_like_pointer(value: u64) -> bool {
    (value >> 47 == 0x1FFFF && value != u64::MAX) || (0x10000..0x7FFF_FFFF_0000).contains(&value)
}

/// O nome de um quadro sem o prefixo do módulo (`ACPI!AcpiX+0x10` →
/// `AcpiX+0x10`, `ACPI+0x1234` → `+0x1234`).
pub fn strip_module<'a>(name: &'a str, module: &str) -> &'a str {
    if module.is_empty() {
        return name;
    }
    name.strip_prefix(module).and_then(|rest| rest.strip_prefix('!').or_else(|| rest.starts_with('+').then_some(rest))).unwrap_or(name)
}

/// Como mostrar um registrador vetorial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VectorFormat {
    Hex,
    U8,
    U16,
    U32,
    U64,
    F32,
    F64,
}

impl VectorFormat {
    pub const ALL: [VectorFormat; 7] = [VectorFormat::Hex, VectorFormat::U8, VectorFormat::U16, VectorFormat::U32, VectorFormat::U64, VectorFormat::F32, VectorFormat::F64];

    pub fn label(self) -> &'static str {
        match self {
            VectorFormat::Hex => "hexadecimal",
            VectorFormat::U8 => "bytes",
            VectorFormat::U16 => "words (16 bits)",
            VectorFormat::U32 => "dwords (32 bits)",
            VectorFormat::U64 => "qwords (64 bits)",
            VectorFormat::F32 => "float",
            VectorFormat::F64 => "double",
        }
    }
}

/// Um registrador vetorial (bytes em little-endian) no formato pedido, da
/// lane mais alta para a mais baixa, como o número inteiro em hexadecimal.
pub fn vector_text(bytes: &[u8], format: VectorFormat) -> String {
    let join = |lanes: Vec<String>| lanes.join(" ");
    match format {
        VectorFormat::Hex => bytes.iter().rev().map(|byte| format!("{byte:02x}")).collect(),
        VectorFormat::U8 => join(bytes.iter().rev().map(|byte| format!("{byte:02x}")).collect()),
        VectorFormat::U16 => join(bytes.chunks_exact(2).rev().map(|lane| format!("{:04x}", u16::from_le_bytes([lane[0], lane[1]]))).collect()),
        VectorFormat::U32 => join(bytes.chunks_exact(4).rev().map(|lane| format!("{:08x}", u32::from_le_bytes(lane.try_into().unwrap_or([0; 4])))).collect()),
        VectorFormat::U64 => join(bytes.chunks_exact(8).rev().map(|lane| format!("{:016x}", u64::from_le_bytes(lane.try_into().unwrap_or([0; 8])))).collect()),
        VectorFormat::F32 => join(bytes.chunks_exact(4).rev().map(|lane| format!("{}", f32::from_le_bytes(lane.try_into().unwrap_or([0; 4])))).collect()),
        VectorFormat::F64 => join(bytes.chunks_exact(8).rev().map(|lane| format!("{}", f64::from_le_bytes(lane.try_into().unwrap_or([0; 8])))).collect()),
    }
}

/// Um seletor de segmento: a tabela, o índice, o RPL e o uso no x64 do NT
/// (os KGDT64_* dos cabeçalhos públicos).
pub fn segment_text(selector: u64) -> String {
    let selector = selector & 0xFFFF;
    if selector & !3 == 0 {
        return "nulo".into();
    }
    let table = if selector & 4 != 0 { "LDT" } else { "GDT" };
    let role = match selector & !3 {
        0x10 => " (código do anel 0)",
        0x18 => " (dados do anel 0)",
        0x20 => " (código de 32 bits do anel 3)",
        0x28 => " (dados do anel 3)",
        0x30 => " (código do anel 3)",
        0x40 => " (TSS)",
        0x50 => " (TEB de 32 bits)",
        _ => "",
    };
    format!("{table}[{}] RPL {}{role}", selector >> 3, selector & 3)
}

/// Os bits do DR6 ligados: os comparadores que acertaram (B0-B3), o acesso
/// a um DR (BD), o passo único (BS) e a troca de tarefa (BT).
pub fn dr6_text(value: u64) -> String {
    let mut parts: Vec<String> = (0u32..4).filter(|&bit| value >> bit & 1 != 0).map(|bit| format!("B{bit}")).collect();
    for (bit, name) in [(13u32, "BD"), (14, "BS"), (15, "BT")] {
        if value >> bit & 1 != 0 {
            parts.push(name.to_string());
        }
    }
    if parts.is_empty() {
        "nenhum acerto".into()
    } else {
        parts.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(offset: u64, size: usize, signed: bool) -> Option<FieldSpec> {
        Some(FieldSpec { offset, size, signed, bits: None })
    }

    #[test]
    fn reads_fields() {
        let bytes = [0xFF, 0x34, 0x12, 0b1011_0000];
        assert_eq!(spec(0x10, 1, true).unwrap().read(&bytes, 0x10), Some(-1));
        assert_eq!(spec(0x10, 1, false).unwrap().read(&bytes, 0x10), Some(0xFF));
        assert_eq!(spec(0x11, 2, false).unwrap().read(&bytes, 0x10), Some(0x1234));
        // Fora dos bytes lidos.
        assert_eq!(spec(0x13, 2, false).unwrap().read(&bytes, 0x10), None);
        assert_eq!(spec(0x0F, 1, false).unwrap().read(&bytes, 0x10), None);
        let bits = FieldSpec { offset: 0x13, size: 1, signed: false, bits: Some((4, 3)) };
        assert_eq!(bits.read(&bytes, 0x10), Some(0b011));
    }

    #[test]
    fn decodes_a_kthread() {
        // Os offsets do _KTHREAD do 19041 (o PDB dá os de verdade).
        let layout = KthreadLayout {
            state: spec(0x184, 1, false),
            wait_reason: spec(0x283, 1, false),
            wait_mode: spec(0x187, 1, true),
            priority: spec(0xC3, 1, true),
            base_priority: spec(0x233, 1, true),
            suspend_count: spec(0x284, 1, true),
            kernel_time: spec(0x28C, 4, false),
            user_time: None,
            state_names: ["Initialized", "Ready", "Running", "Standby", "Terminated", "Waiting"].iter().map(|name| name.to_string()).collect(),
            wait_names: ["Executive", "FreePage", "PageIn", "PoolAllocation", "DelayExecution", "Suspended", "UserRequest"].iter().map(|name| name.to_string()).collect(),
        };
        let (start, length) = layout.span().unwrap();
        assert_eq!((start, length), (0xC3, 0x290 - 0xC3));
        let mut bytes = vec![0u8; length];
        let mut put = |offset: u64, value: &[u8]| bytes[(offset - start) as usize..(offset - start) as usize + value.len()].copy_from_slice(value);
        put(0x184, &[5]);
        put(0x283, &[6]);
        put(0x187, &[1]);
        put(0xC3, &[9]);
        put(0x233, &[8]);
        put(0x28C, &1234u32.to_le_bytes());
        let detail = layout.decode(&bytes, start);
        assert_eq!(detail.state, "Waiting");
        assert_eq!(detail.wait_reason, "UserRequest");
        assert_eq!(detail.wait_mode, "usuário");
        assert_eq!((detail.priority, detail.base_priority, detail.suspend_count), (Some(9), Some(8), Some(0)));
        assert_eq!((detail.kernel_time, detail.user_time), (Some(1234), None));
        // Rodando: sem motivo de espera; um valor sem nome vira o número.
        bytes[(0x184 - start) as usize] = 2;
        assert_eq!(layout.decode(&bytes, start).wait_reason, "");
        assert_eq!(layout.decode(&bytes, start).state, "Running");
        bytes[(0x184 - start) as usize] = 7;
        assert_eq!(layout.decode(&bytes, start).state, "7");
    }

    #[test]
    fn vectors() {
        let bytes: Vec<u8> = (0u8..16).collect();
        assert_eq!(vector_text(&bytes, VectorFormat::Hex), "0f0e0d0c0b0a09080706050403020100");
        assert_eq!(vector_text(&bytes, VectorFormat::U32), "0f0e0d0c 0b0a0908 07060504 03020100");
        assert_eq!(vector_text(&bytes, VectorFormat::U64), "0f0e0d0c0b0a0908 0706050403020100");
        assert_eq!(vector_text(&bytes[..4], VectorFormat::U16), "0302 0100");
        let mut floats = Vec::new();
        for value in [1.0f32, -2.5, 0.0, 4.0] {
            floats.extend_from_slice(&value.to_le_bytes());
        }
        assert_eq!(vector_text(&floats, VectorFormat::F32), "4 0 -2.5 1");
        let mut doubles = Vec::new();
        for value in [0.5f64, 3.0] {
            doubles.extend_from_slice(&value.to_le_bytes());
        }
        assert_eq!(vector_text(&doubles, VectorFormat::F64), "3 0.5");
    }

    #[test]
    fn segments_and_debug_status() {
        assert_eq!(segment_text(0x33), "GDT[6] RPL 3 (código do anel 3)");
        assert_eq!(segment_text(0x10), "GDT[2] RPL 0 (código do anel 0)");
        assert_eq!(segment_text(0x2B), "GDT[5] RPL 3 (dados do anel 3)");
        assert_eq!(segment_text(0), "nulo");
        assert_eq!(segment_text(0x0F), "LDT[1] RPL 3");
        assert_eq!(dr6_text(0xFFFF_0FF0), "nenhum acerto");
        assert_eq!(dr6_text(0x4001), "B0 BS");
        assert_eq!(dr6_text(0x200C), "B2 B3 BD");
    }

    #[test]
    fn frames_pointers_and_modules() {
        assert_eq!(strip_module("ACPI!AcpiInitialize+0x10", "ACPI"), "AcpiInitialize+0x10");
        assert_eq!(strip_module("ACPI+0x1234", "ACPI"), "+0x1234");
        assert_eq!(strip_module("kernel::ntos::ke::run_kernel_tasks+0x5", "ntoskrnl"), "kernel::ntos::ke::run_kernel_tasks+0x5");
        assert_eq!(strip_module("kernelbase!X", "kernel"), "kernelbase!X");
        assert_eq!(strip_module("0x1234", ""), "0x1234");
        assert!(looks_like_pointer(0xFFFF_F800_4000_1234));
        assert!(looks_like_pointer(0x7FF6_1234_0000));
        assert!(!looks_like_pointer(0x1234));
        assert!(!looks_like_pointer(u64::MAX));
        assert!(!looks_like_pointer(0x8000_0000_0000_0000));
        let mut module = Module::new("ntfs.sys", "\\SystemRoot\\System32\\Drivers\\ntfs.sys", 0x1000, 0x2000, Vec::new(), "teste");
        let symbols = Symbols::default();
        assert_eq!(PdbStatus::of(&symbols, &module), PdbStatus::NoFile);
        module.pdb_pending = true;
        assert_eq!(PdbStatus::of(&symbols, &module), PdbStatus::Downloading);
        module.pdb = Some("build/symbols/ntfs.pdb".into());
        assert_eq!(PdbStatus::of(&symbols, &module).label(), "PDB");
        assert_eq!(pdb_identity(&module), (String::new(), String::new()));
        let mut bytes = 0x1010u64.to_le_bytes().to_vec();
        bytes.extend_from_slice(&0x5u64.to_le_bytes());
        let mut with_module = Symbols::default();
        with_module.add_module(Module::new("ntfs.sys", "ntfs.sys", 0x1000, 0x2000, Vec::new(), "teste"));
        assert_eq!(pointer_names(&with_module, &bytes), vec![Some("ntfs+0x10".to_string()), None]);
    }
}
