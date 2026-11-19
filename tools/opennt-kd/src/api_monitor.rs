//! O monitor de APIs do lado do host: a tabela de nomes dos exports do
//! alvo (`monitor api names`), as especificações que o cliente manda ao
//! ligar (`monitor api spec`: quantos argumentos cada export tem e quais
//! apontam para texto, pelos protótipos de `analysis::prototypes`), a
//! decodificação de cada chamada numa linha (argumentos com nome, o
//! resultado e o nome do NTSTATUS, o módulo e o símbolo do chamador), os
//! filtros da tabela e o CSV.

use std::collections::HashMap;
use std::sync::Arc;

use super::analysis::prototypes::{self, Kind, Prototype};
use super::ntstatus;
use super::stream::{self, ApiCall};

/// Os nomes dos exports pelo id (o `api names` do alvo).
#[derive(Clone, Debug, Default)]
pub struct ExportNames {
    names: HashMap<u32, Arc<str>>,
}

impl ExportNames {
    /// Acrescenta uma página do `api names`; devolve o índice da próxima
    /// (`mais: N`), se houver.
    pub fn add_page(&mut self, text: &str) -> Option<usize> {
        let mut more = None;
        for line in text.lines() {
            if let Some(next) = line.strip_prefix("mais: ") {
                more = next.trim().parse().ok();
                continue;
            }
            let Some((id, name)) = line.trim().split_once(' ') else { continue };
            if let Ok(id) = id.parse::<u32>() {
                self.names.insert(id, Arc::from(name.trim()));
            }
        }
        more
    }

    pub fn name(&self, id: u32) -> Arc<str> {
        self.names.get(&id).cloned().unwrap_or_else(|| Arc::from(format!("export#{id}")))
    }

    pub fn id(&self, name: &str) -> Option<u32> {
        self.names.iter().find(|(_, candidate)| candidate.as_ref() == name).map(|(&id, _)| id)
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (u32, &str)> + '_ {
        self.names.iter().map(|(&id, name)| (id, name.as_ref()))
    }
}

/// O tipo de texto que o alvo copia para um argumento.
fn capture_kind(kind: Kind) -> Option<u8> {
    match kind {
        Kind::UnicodeString => Some(stream::TEXT_UNICODE_STRING),
        Kind::AnsiString => Some(stream::TEXT_ANSI_STRING),
        Kind::WideText => Some(stream::TEXT_WIDE),
        Kind::AnsiText => Some(stream::TEXT_ANSI),
        Kind::ObjectAttributes => Some(stream::TEXT_OBJECT_ATTRIBUTES),
        _ => None,
    }
}

/// Um ponteiro de saída que vale ler na volta (o objeto ou o handle criado).
fn is_output_pointer(prototype: &Prototype, index: usize) -> bool {
    let (name, kind) = prototype.arguments[index];
    if kind != Kind::Pointer {
        return false;
    }
    if name.ends_with("Handle") && !name.starts_with('h') {
        return true;
    }
    index > 0 && matches!(name, "DeviceObject" | "Object" | "Process" | "Thread" | "FileObject")
}

/// A especificação de um export (`ID:ARGC[:ARG:TIPO]...`) pelo protótipo.
pub fn spec_for(id: u32, prototype: &Prototype) -> String {
    let mut spec = format!("{id}:{}", prototype.arguments.len().min(14));
    let mut captures = 0;
    for (index, (_, kind)) in prototype.arguments.iter().enumerate().take(14) {
        if captures == 2 {
            break;
        }
        if let Some(text) = capture_kind(*kind) {
            spec.push_str(&format!(":{}:{text}", index + 1));
            captures += 1;
        }
    }
    for index in 0..prototype.arguments.len().min(14) {
        if captures == 2 {
            break;
        }
        if is_output_pointer(prototype, index) {
            spec.push_str(&format!(":{}:{}", index + 1, stream::TEXT_OUTPUT_POINTER));
            captures += 1;
        }
    }
    spec
}

/// As linhas `api spec ...` para os exports com protótipo conhecido, cada
/// uma abaixo de `limit` caracteres.
pub fn spec_commands(names: &ExportNames, limit: usize) -> Vec<String> {
    let mut specs: Vec<(u32, String)> = names.iter().filter_map(|(id, name)| prototypes::find(name).map(|prototype| (id, spec_for(id, prototype)))).collect();
    specs.sort();
    let mut commands = Vec::new();
    let mut line = String::from("api spec");
    for (_, spec) in specs {
        if line.len() + spec.len() + 1 > limit {
            commands.push(std::mem::replace(&mut line, String::from("api spec")));
        }
        line.push(' ');
        line.push_str(&spec);
    }
    if line.len() > "api spec".len() {
        commands.push(line);
    }
    commands
}

/// Como mostrar o resultado de um export.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultKind {
    Status,
    Pointer,
    Value,
    Void,
}

const VOID_RESULTS: &[&str] = &[
    "IofCompleteRequest", "IoCompleteRequest", "IoFreeIrp", "IoFreeMdl", "IoFreeWorkItem", "IoQueueWorkItem", "IoQueueWorkItemEx", "IoDeleteDevice", "IoDetachDevice",
    "IoReleaseCancelSpinLock", "IoAcquireCancelSpinLock", "IoStartNextPacket", "IoStartPacket", "IoInitializeRemoveLockEx", "IoReleaseRemoveLockEx", "IoReleaseRemoveLockAndWaitEx",
    "ExFreePool", "ExFreePoolWithTag", "ExAcquireFastMutex", "ExReleaseFastMutex", "ExInitializeNPagedLookasideList", "ExDeleteNPagedLookasideList", "KeInitializeEvent",
    "KeInitializeDpc", "KeInitializeTimer", "KeInitializeTimerEx", "KeInitializeSpinLock", "KeInitializeMutex", "KeInitializeSemaphore", "KeClearEvent", "KeReleaseSpinLock",
    "KeReleaseSpinLockFromDpcLevel", "KeAcquireSpinLockAtDpcLevel", "KeEnterCriticalRegion", "KeLeaveCriticalRegion", "KeBugCheckEx", "KeStackAttachProcess",
    "KeUnstackDetachProcess", "KeLowerIrql", "RtlInitUnicodeString", "RtlInitAnsiString", "RtlInitString", "RtlCopyUnicodeString", "RtlFreeUnicodeString", "RtlFreeAnsiString",
    "MmUnmapIoSpace", "MmUnlockPages", "MmProbeAndLockPages", "ObfDereferenceObject", "ObfReferenceObject", "ObDereferenceObjectDeferDelete", "ExReleaseResourceLite",
    "ExReleaseResourceForThreadLite", "KeQuerySystemTimePrecise", "KeQueryTickCount", "IoWriteErrorLogEntry", "PsSetCreateThreadNotifyRoutine",
];

const POINTER_RESULTS: &[&str] = &[
    "ExAllocatePool", "ExAllocatePoolWithTag", "ExAllocatePool2", "ExAllocatePool3", "ExAllocatePoolWithQuotaTag", "ExAllocatePoolZero", "IoAllocateIrp", "IoAllocateIrpEx",
    "IoAllocateMdl", "IoAllocateWorkItem", "IoAllocateErrorLogEntry", "IoBuildDeviceIoControlRequest", "IoBuildSynchronousFsdRequest", "IoBuildAsynchronousFsdRequest",
    "IoMakeAssociatedIrp", "IoGetAttachedDevice", "IoGetAttachedDeviceReference", "IoGetRelatedDeviceObject", "IoGetCurrentProcess", "IoGetCurrentThread",
    "IoGetDeviceAttachmentBaseRef", "IoGetLowerDeviceObject", "IoAttachDeviceToDeviceStack", "MmGetSystemRoutineAddress", "MmMapIoSpace", "MmMapIoSpaceEx",
    "MmMapLockedPagesSpecifyCache", "MmGetSystemAddressForMdlSafe", "MmAllocateContiguousMemory", "MmAllocateContiguousMemorySpecifyCache", "MmAllocateNonCachedMemory",
    "PsGetCurrentProcess", "PsGetCurrentThread", "PsGetCurrentProcessId", "PsGetCurrentThreadId", "PsGetProcessId", "PsGetThreadId", "KeGetCurrentThread",
    "IoGetDriverObjectExtension", "IoGetInitialStack", "RtlLookupFunctionEntry", "RtlImageNtHeader", "RtlFindExportedRoutineByName", "ExAllocateFromNPagedLookasideList",
];

const VALUE_RESULTS: &[&str] = &[
    "KeGetCurrentIrql", "KeRaiseIrqlToDpcLevel", "KeAcquireSpinLockRaiseToDpc", "KfRaiseIrql", "KeSetEvent", "KePulseEvent", "KeResetEvent", "KeReadStateEvent",
    "KeQueryPerformanceCounter", "KeQueryInterruptTime", "KeQueryTimeIncrement", "KeGetCurrentProcessorNumberEx", "KeQueryActiveProcessorCountEx", "RtlCompareUnicodeString",
    "RtlEqualUnicodeString", "RtlCompareMemory", "ExInterlockedInsertTailList", "ExInterlockedRemoveHeadList", "InterlockedIncrement", "InterlockedDecrement",
    "MmIsAddressValid", "PsIsSystemThread", "IoIsWdmVersionAvailable", "KeInsertQueueDpc", "KeRemoveQueueDpc", "KeCancelTimer", "KeSetTimer", "KeSetTimerEx",
    "KeReleaseMutex", "KeReleaseSemaphore", "ExAcquireResourceExclusiveLite", "ExAcquireResourceSharedLite", "RtlNumberOfSetBits", "DbgPrint", "DbgPrintEx", "vDbgPrintEx",
    "vDbgPrintExWithPrefix", "strcmp", "_stricmp", "strncmp", "_strnicmp", "wcscmp", "_wcsicmp", "strlen", "wcslen", "memcmp", "memcpy", "memmove", "memset",
];

/// O tipo do resultado pelo nome do export.
pub fn result_kind(name: &str) -> ResultKind {
    if VOID_RESULTS.contains(&name) {
        ResultKind::Void
    } else if POINTER_RESULTS.contains(&name) {
        ResultKind::Pointer
    } else if VALUE_RESULTS.contains(&name) || name.starts_with("Interlocked") || name.starts_with("_") || name.starts_with("Hal") && !name.starts_with("HalGetBusData") {
        ResultKind::Value
    } else {
        ResultKind::Status
    }
}

/// Uma linha da tabela.
#[derive(Clone, Debug)]
pub struct ApiRow {
    pub call: ApiCall,
    pub name: Arc<str>,
    /// O módulo do chamador (o driver).
    pub module: String,
    /// O símbolo do endereço de retorno.
    pub caller: String,
    /// Os argumentos decodificados (`Nome=valor, ...`).
    pub arguments: String,
    pub result: String,
    /// O NTSTATUS, quando o resultado é um.
    pub status: Option<u32>,
    /// Falhou: status de erro ou o provedor sem resultado.
    pub failed: bool,
}

fn format_value(kind: Kind, value: u64, symbol: &dyn Fn(u64) -> Option<String>) -> String {
    match kind {
        Kind::Integer => {
            if value < 10 {
                format!("{value}")
            } else {
                format!("{value:#x}")
            }
        }
        Kind::Boolean => if value & 0xFF != 0 { "TRUE" } else { "FALSE" }.to_string(),
        Kind::Tag => {
            let bytes = (value as u32).to_le_bytes();
            if bytes.iter().all(|byte| (0x20..0x7F).contains(byte)) {
                format!("'{}'", String::from_utf8_lossy(&bytes))
            } else {
                format!("{value:#x}")
            }
        }
        Kind::Status => ntstatus::describe(value as u32),
        Kind::Code => match symbol(value) {
            Some(name) => format!("{value:#x} {name}"),
            None => format!("{value:#x}"),
        },
        _ => {
            if value == 0 {
                "NULL".to_string()
            } else {
                format!("{value:#x}")
            }
        }
    }
}

/// Decodifica uma chamada: `module_of` dá o módulo de um endereço e
/// `symbol` o símbolo.
pub fn decode(call: ApiCall, names: &ExportNames, module_of: &dyn Fn(u64) -> Option<String>, symbol: &dyn Fn(u64) -> Option<String>) -> ApiRow {
    let name = names.name(call.id);
    let prototype = prototypes::find(&name);
    let mut parts = Vec::new();
    for (index, &value) in call.arguments.iter().enumerate() {
        let (argument_name, kind) = prototype.and_then(|prototype| prototype.arguments.get(index).copied()).unwrap_or(("", Kind::Pointer));
        let label = if argument_name.is_empty() { format!("a{}", index + 1) } else { argument_name.to_string() };
        let shown = match call.capture(index as u8 + 1) {
            Some(capture) if capture.kind == stream::TEXT_OUTPUT_POINTER => format!("{} -> {}", format_value(kind, value, symbol), capture.text()),
            Some(capture) if capture.bytes.is_empty() && value != 0 => format!("{value:#x} \"\""),
            Some(capture) => format!("\"{}\"", capture.text()),
            None => format_value(kind, value, symbol),
        };
        parts.push(format!("{label}={shown}"));
    }
    let kind = result_kind(&name);
    let (result, status, failed) = if call.failed_internally() {
        ("(o provedor falhou)".to_string(), None, true)
    } else {
        match kind {
            ResultKind::Void => ("-".to_string(), None, false),
            ResultKind::Pointer => (if call.result == 0 { "NULL".to_string() } else { format!("{:#x}", call.result) }, None, call.result == 0),
            ResultKind::Value => (format!("{:#x}", call.result), None, false),
            ResultKind::Status => {
                let status = ntstatus::of_result(call.result);
                (ntstatus::describe(status), Some(status), ntstatus::is_error(status))
            }
        }
    };
    let module = module_of(call.return_address).unwrap_or_else(|| "?".to_string());
    let caller = symbol(call.return_address).unwrap_or_else(|| format!("{:#x}", call.return_address));
    ApiRow { call, name, module, caller, arguments: parts.join(", "), result, status, failed }
}

/// Os filtros da tabela.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Filter {
    /// O módulo do chamador (parte do nome, sem caixa).
    pub driver: String,
    /// O export (parte do nome, sem caixa).
    pub export: String,
    /// O status (parte do nome ou do valor, sem caixa).
    pub status: String,
    pub failures_only: bool,
}

impl Filter {
    pub fn is_empty(&self) -> bool {
        self.driver.is_empty() && self.export.is_empty() && self.status.is_empty() && !self.failures_only
    }

    pub fn matches(&self, row: &ApiRow) -> bool {
        let contains = |text: &str, wanted: &str| wanted.is_empty() || text.to_ascii_lowercase().contains(&wanted.to_ascii_lowercase());
        (!self.failures_only || row.failed) && contains(&row.module, &self.driver) && contains(&row.name, &self.export) && contains(&row.result, &self.status)
    }
}

fn csv_field(text: &str) -> String {
    if text.contains([',', '"', '\n']) {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text.to_string()
    }
}

/// As linhas em CSV (com o cabeçalho).
pub fn to_csv<'a>(rows: impl IntoIterator<Item = &'a ApiRow>) -> String {
    let mut text = String::from("sequencia,hora_us,cpu,pid,tid,thread,modulo,chamador,export,argumentos,resultado,duracao_us\n");
    for row in rows {
        let call = &row.call;
        text.push_str(&format!(
            "{},{:.1},{},{},{},{:#x},{},{},{},{},{},{:.1}\n",
            call.sequence,
            call.time as f64 / 10.0,
            call.cpu,
            call.pid,
            call.tid,
            call.thread,
            csv_field(&row.module),
            csv_field(&row.caller),
            csv_field(&row.name),
            csv_field(&row.arguments),
            csv_field(&row.result),
            call.duration as f64 / 10.0
        ));
    }
    text
}

/// Uma linha de texto (o `apimon show` do prompt).
pub fn format_row(row: &ApiRow) -> String {
    format!(
        "#{:<6} {:>10.1}us cpu{} tid {:<5} {:<14} {}({}) -> {}  [{}]",
        row.call.sequence,
        row.call.time as f64 / 10.0,
        row.call.cpu,
        row.call.tid,
        row.module,
        row.name,
        row.arguments,
        row.result,
        row.caller
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::tests::api_record;
    use crate::stream::{parse_record, Record};

    fn names() -> ExportNames {
        let mut names = ExportNames::default();
        assert_eq!(names.add_page("40 IoCreateDevice\n41 ExAllocatePoolWithTag\n42 KeSetEvent\nmais: 3\n"), Some(3));
        assert_eq!(names.add_page("43 ZwOpenKey\n44 IofCompleteRequest\n"), None);
        names
    }

    fn row(bytes: Vec<u8>) -> ApiRow {
        let Some(Record::Api(call)) = parse_record(&bytes) else { panic!("registro") };
        decode(call, &names(), &|address| (address >> 32 == 0xFFFF_F800).then(|| "teste".to_string()), &|address| (address == 0xFFFF_F800_0000_1234).then(|| "teste!DriverEntry+0x34".to_string()))
    }

    #[test]
    fn specs_come_from_the_prototypes() {
        let names = names();
        let commands = spec_commands(&names, 240);
        let all = commands.join(" ");
        // IoCreateDevice: 7 argumentos, o nome (3) e o DeviceObject criado (7).
        assert!(all.contains("40:7:3:1:7:6"), "{all}");
        // ExAllocatePoolWithTag: 3 argumentos, sem texto.
        assert!(all.contains("41:3"), "{all}");
        // ZwOpenKey: o OBJECT_ATTRIBUTES (3) e o handle de saída (1).
        assert!(all.contains("43:3:3:5:1:6"), "{all}");
        assert!(commands.iter().all(|command| command.len() <= 240 && command.starts_with("api spec ")));
    }

    #[test]
    fn decodes_a_create_device_call() {
        let row = row(api_record(1, 40, &[0xFFFF_A000_0000_1000, 0x40, 0xFFFF_A000_0000_2000, 0x22, 0, 0, 0xFFFF_A000_0000_3000], 0, 0xFFFF_F800_0000_1234, &[(3, stream::TEXT_UNICODE_STRING, "\\Device\\Teste".as_bytes()), (7, stream::TEXT_OUTPUT_POINTER, &0xFFFF_A000_0000_4000u64.to_le_bytes())]));
        assert_eq!(row.name.as_ref(), "IoCreateDevice");
        assert!(row.arguments.contains("DeviceName=\"\\Device\\Teste\""), "{}", row.arguments);
        assert!(row.arguments.contains("DeviceObject=0xffffa00000003000 -> 0xffffa00000004000"), "{}", row.arguments);
        assert!(row.arguments.contains("Exclusive=FALSE"), "{}", row.arguments);
        assert_eq!(row.result, "STATUS_SUCCESS (0x00000000)");
        assert!(!row.failed);
        assert_eq!(row.module, "teste");
        assert_eq!(row.caller, "teste!DriverEntry+0x34");
    }

    #[test]
    fn failures_and_filters() {
        let failed = row(api_record(2, 43, &[0, 0x20019, 0], 0xFFFF_FFFF_C000_0034, 0xFFFF_F800_0000_1234, &[(3, stream::TEXT_OBJECT_ATTRIBUTES, "\\Registry\\Machine\\X".as_bytes())]));
        assert_eq!(failed.status, Some(0xC000_0034));
        assert!(failed.failed);
        assert!(failed.result.contains("STATUS_OBJECT_NAME_NOT_FOUND"));
        let pool = row(api_record(3, 41, &[1, 0x100, 0x6B736554], 0xFFFF_A000_0000_8000, 0xFFFF_F800_0000_1234, &[]));
        assert!(pool.arguments.contains("Tag='Tesk'"), "{}", pool.arguments);
        assert!(!pool.failed);
        let void = row(api_record(4, 44, &[0x1000, 0], 0, 0x1000, &[]));
        assert_eq!(void.result, "-");
        assert_eq!(void.module, "?");
        let filter = Filter { failures_only: true, ..Filter::default() };
        assert!(filter.matches(&failed) && !filter.matches(&pool));
        let filter = Filter { export: "pool".into(), ..Filter::default() };
        assert!(filter.matches(&pool) && !filter.matches(&failed));
        let filter = Filter { status: "name_not_found".into(), driver: "TES".into(), ..Filter::default() };
        assert!(filter.matches(&failed));
        let csv = to_csv([&failed, &pool]);
        assert_eq!(csv.lines().count(), 3);
        assert!(csv.contains("ZwOpenKey"));
    }
}
