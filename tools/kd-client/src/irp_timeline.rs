//! O rastreador de IRPs do lado do host: junta os eventos do alvo
//! (`stream::IrpEvent`) na vida de cada IRP. Um IRP começa na criação por
//! um driver ou no primeiro IofCallDriver do topo da pilha, passa por cada
//! IofCallDriver (um salto: dispositivo, driver, rotina, major/minor, a
//! posição na pilha, a hora de entrada e de volta e o status devolvido),
//! pelo IofCompleteRequest (status final e Information) e pelas rotinas de
//! conclusão, e termina no IoFreeIrp ou na conclusão que chega ao topo. O
//! mesmo endereço reaproveitado depois do fim é outro IRP.

use std::collections::HashMap;

use super::ntstatus;
use super::stream::{self, IrpEvent};

/// Os nomes das major functions (IRP_MJ_*).
pub const MAJOR_NAMES: [&str; 28] = [
    "CREATE",
    "CREATE_NAMED_PIPE",
    "CLOSE",
    "READ",
    "WRITE",
    "QUERY_INFORMATION",
    "SET_INFORMATION",
    "QUERY_EA",
    "SET_EA",
    "FLUSH_BUFFERS",
    "QUERY_VOLUME_INFORMATION",
    "SET_VOLUME_INFORMATION",
    "DIRECTORY_CONTROL",
    "FILE_SYSTEM_CONTROL",
    "DEVICE_CONTROL",
    "INTERNAL_DEVICE_CONTROL",
    "SHUTDOWN",
    "LOCK_CONTROL",
    "CLEANUP",
    "CREATE_MAILSLOT",
    "QUERY_SECURITY",
    "SET_SECURITY",
    "POWER",
    "SYSTEM_CONTROL",
    "DEVICE_CHANGE",
    "QUERY_QUOTA",
    "SET_QUOTA",
    "PNP",
];

pub fn major_name(major: u8) -> String {
    MAJOR_NAMES.get(major as usize).map_or_else(|| format!("{major:#x}"), |name| format!("IRP_MJ_{name}"))
}

/// Os minors de PnP e de power mais vistos.
pub fn minor_name(major: u8, minor: u8) -> Option<&'static str> {
    const PNP: [&str; 25] = [
        "START_DEVICE",
        "QUERY_REMOVE_DEVICE",
        "REMOVE_DEVICE",
        "CANCEL_REMOVE_DEVICE",
        "STOP_DEVICE",
        "QUERY_STOP_DEVICE",
        "CANCEL_STOP_DEVICE",
        "QUERY_DEVICE_RELATIONS",
        "QUERY_INTERFACE",
        "QUERY_CAPABILITIES",
        "QUERY_RESOURCES",
        "QUERY_RESOURCE_REQUIREMENTS",
        "QUERY_DEVICE_TEXT",
        "FILTER_RESOURCE_REQUIREMENTS",
        "0x0e",
        "READ_CONFIG",
        "WRITE_CONFIG",
        "EJECT",
        "SET_LOCK",
        "QUERY_ID",
        "QUERY_PNP_DEVICE_STATE",
        "QUERY_BUS_INFORMATION",
        "DEVICE_USAGE_NOTIFICATION",
        "SURPRISE_REMOVAL",
        "0x18",
    ];
    const POWER: [&str; 4] = ["WAIT_WAKE", "POWER_SEQUENCE", "SET_POWER", "QUERY_POWER"];
    const FILE_SYSTEM: [&str; 5] = ["USER_FS_REQUEST", "MOUNT_VOLUME", "VERIFY_VOLUME", "LOAD_FILE_SYSTEM", "KERNEL_CALL"];
    match major {
        0x1B => PNP.get(minor as usize).copied(),
        0x16 => POWER.get(minor as usize).copied(),
        0x0D => FILE_SYSTEM.get(minor as usize).copied(),
        _ => None,
    }
}

/// Um IofCallDriver de um IRP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hop {
    pub time: u64,
    /// A volta da rotina (0 = ainda não voltou).
    pub returned: u64,
    pub device: u64,
    pub driver: u64,
    pub routine: u64,
    pub caller: u64,
    pub major: u8,
    pub minor: u8,
    pub location: u8,
    /// O status devolvido pela rotina de despacho.
    pub status: Option<u32>,
    /// Profundidade (um IofCallDriver de dentro da rotina de outro).
    pub depth: usize,
}

/// Uma rotina de conclusão chamada.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletionCall {
    pub time: u64,
    pub routine: u64,
    pub device: u64,
    pub driver: u64,
    pub result: u32,
    pub location: u8,
}

/// Um passo da linha do tempo de um IRP (para a vista e o texto).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    Created { time: u64, caller: u64, export: u64 },
    Call(Hop),
    Completed { time: u64, status: u32, information: u64, location: u8, caller: u64 },
    Routine(CompletionCall),
    Freed { time: u64, caller: u64 },
}

impl Step {
    pub fn time(&self) -> u64 {
        match self {
            Step::Created { time, .. } | Step::Completed { time, .. } | Step::Freed { time, .. } => *time,
            Step::Call(hop) => hop.time,
            Step::Routine(call) => call.time,
        }
    }
}

/// A vida de um IRP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrpLife {
    /// O número do IRP na sessão (o endereço se repete).
    pub number: usize,
    pub address: u64,
    pub start: u64,
    pub end: Option<u64>,
    pub thread: u64,
    pub pid: u32,
    /// O primeiro major/minor visto.
    pub major: u8,
    pub minor: u8,
    pub stack: u8,
    /// Quem criou (o endereço de retorno no driver), se foi um driver.
    pub creator: Option<u64>,
    pub steps: Vec<Step>,
    pub final_status: Option<u32>,
    pub information: u64,
    /// Liberado pelo IoFreeIrp.
    pub freed: bool,
    /// A conclusão chegou ao topo (sem STATUS_MORE_PROCESSING_REQUIRED no meio).
    pub completed: bool,
}

impl IrpLife {
    pub fn hops(&self) -> impl Iterator<Item = &Hop> {
        self.steps.iter().filter_map(|step| match step {
            Step::Call(hop) => Some(hop),
            _ => None,
        })
    }

    /// Os dispositivos por onde passou, em ordem.
    pub fn devices(&self) -> Vec<u64> {
        let mut devices = Vec::new();
        for hop in self.hops() {
            if !devices.contains(&hop.device) {
                devices.push(hop.device);
            }
        }
        devices
    }

    pub fn drivers(&self) -> Vec<u64> {
        let mut drivers = Vec::new();
        for hop in self.hops() {
            if !drivers.contains(&hop.driver) {
                drivers.push(hop.driver);
            }
        }
        drivers
    }

    /// A duração (100 ns), se terminou.
    pub fn duration(&self) -> Option<u64> {
        self.end.map(|end| end.saturating_sub(self.start))
    }

    pub fn status_text(&self) -> String {
        match self.final_status {
            Some(status) => ntstatus::describe(status),
            None if self.hops().any(|hop| hop.status == Some(0x103)) => "pendente (STATUS_PENDING)".into(),
            None => "em andamento".into(),
        }
    }
}

/// Os IRPs da sessão.
#[derive(Clone, Debug, Default)]
pub struct Timeline {
    pub irps: Vec<IrpLife>,
    /// O IRP aberto de cada endereço.
    open: HashMap<u64, usize>,
    /// As chamadas sem volta de cada IRP (índices dos passos), para casar
    /// a volta com a entrada.
    pending_calls: HashMap<u64, Vec<usize>>,
}

const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;

impl Timeline {
    fn start(&mut self, event: &IrpEvent) -> usize {
        let number = self.irps.len();
        self.irps.push(IrpLife {
            number,
            address: event.irp,
            start: event.time,
            end: None,
            thread: event.thread,
            pid: event.pid,
            major: event.major,
            minor: event.minor,
            stack: event.stack,
            creator: None,
            steps: Vec::new(),
            final_status: None,
            information: 0,
            freed: false,
            completed: false,
        });
        self.open.insert(event.irp, number);
        self.pending_calls.remove(&event.irp);
        number
    }

    fn finish(&mut self, address: u64) {
        self.open.remove(&address);
        self.pending_calls.remove(&address);
    }

    /// Acrescenta um evento.
    pub fn push(&mut self, event: &IrpEvent) {
        match event.kind {
            stream::KIND_IRP_ALLOCATE => {
                self.finish(event.irp);
                let index = self.start(event);
                let life = &mut self.irps[index];
                life.creator = Some(event.caller);
                life.steps.push(Step::Created { time: event.time, caller: event.caller, export: event.value });
            }
            stream::KIND_IRP_CALL => {
                let index = match self.open.get(&event.irp) {
                    // Uma conclusão que chegou ao topo encerra o IRP: um
                    // IofCallDriver depois disso é o endereço reaproveitado.
                    Some(&index) if !self.irps[index].completed => index,
                    _ => self.start(event),
                };
                let depth = self.pending_calls.get(&event.irp).map_or(0, Vec::len);
                let life = &mut self.irps[index];
                if life.hops().next().is_none() {
                    life.major = event.major;
                    life.minor = event.minor;
                    life.stack = event.stack;
                }
                life.steps.push(Step::Call(Hop { time: event.time, returned: 0, device: event.device, driver: event.driver, routine: event.routine, caller: event.caller, major: event.major, minor: event.minor, location: event.location, status: None, depth }));
                let step = life.steps.len() - 1;
                self.pending_calls.entry(event.irp).or_default().push(step);
            }
            stream::KIND_IRP_RETURN => {
                let Some(&index) = self.open.get(&event.irp) else {
                    // A volta de um IRP já encerrado (completado no meio da
                    // rotina): procura o último com o endereço.
                    if let Some(life) = self.irps.iter_mut().rev().find(|life| life.address == event.irp) {
                        if let Some(Step::Call(hop)) = life.steps.iter_mut().rev().find(|step| matches!(step, Step::Call(hop) if hop.returned == 0 && hop.device == event.device)) {
                            hop.returned = event.time;
                            hop.status = Some(event.value as u32);
                        }
                    }
                    return;
                };
                let step = self.pending_calls.get_mut(&event.irp).and_then(Vec::pop);
                let life = &mut self.irps[index];
                if let Some(Step::Call(hop)) = step.and_then(|step| life.steps.get_mut(step)) {
                    hop.returned = event.time;
                    hop.status = Some(event.value as u32);
                }
                // Todas as rotinas voltaram e a conclusão já chegou ao topo.
                if life.completed && self.pending_calls.get(&event.irp).is_none_or(Vec::is_empty) {
                    life.end = Some(life.end.unwrap_or(event.time).max(event.time));
                }
            }
            stream::KIND_IRP_COMPLETE => {
                let index = match self.open.get(&event.irp) {
                    Some(&index) => index,
                    None => self.start(event),
                };
                let life = &mut self.irps[index];
                let status = event.value as u32;
                life.final_status = Some(status);
                life.information = event.information;
                life.completed = true;
                life.end = Some(event.time);
                life.steps.push(Step::Completed { time: event.time, status, information: event.information, location: event.location, caller: event.caller });
            }
            stream::KIND_IRP_ROUTINE => {
                let Some(&index) = self.open.get(&event.irp) else { return };
                let life = &mut self.irps[index];
                let result = event.value as u32;
                life.steps.push(Step::Routine(CompletionCall { time: event.time, routine: event.routine, device: event.device, driver: event.driver, result, location: event.location }));
                life.end = Some(event.time);
                if result == STATUS_MORE_PROCESSING_REQUIRED {
                    // A rotina segurou o IRP: ele volta à vida (o dono o
                    // reusa ou completa de novo).
                    life.completed = false;
                }
            }
            stream::KIND_IRP_FREE => {
                let index = match self.open.get(&event.irp) {
                    Some(&index) => index,
                    None => return,
                };
                let life = &mut self.irps[index];
                life.freed = true;
                life.end = Some(event.time);
                life.steps.push(Step::Freed { time: event.time, caller: event.caller });
                self.finish(event.irp);
            }
            _ => {}
        }
    }

    pub fn extend<'a>(&mut self, events: impl IntoIterator<Item = &'a IrpEvent>) {
        for event in events {
            self.push(event);
        }
    }
}

/// Os filtros da linha do tempo.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Filter {
    /// O driver (nome, parte sem caixa) por onde o IRP passou.
    pub driver: String,
    /// O dispositivo (endereço em hexadecimal, parte).
    pub device: String,
    /// A major function (número ou parte do nome).
    pub major: String,
    pub failures_only: bool,
}

impl Filter {
    /// `driver_name` dá o nome de um DRIVER_OBJECT.
    pub fn matches(&self, life: &IrpLife, driver_name: &dyn Fn(u64) -> String) -> bool {
        let lower = |text: &str| text.to_ascii_lowercase();
        if self.failures_only && !life.final_status.is_some_and(ntstatus::is_error) {
            return false;
        }
        if !self.driver.is_empty() && !life.drivers().iter().any(|&driver| lower(&driver_name(driver)).contains(&lower(&self.driver))) {
            return false;
        }
        if !self.device.is_empty() {
            let wanted = lower(self.device.trim_start_matches("0x"));
            if !life.devices().iter().any(|device| format!("{device:x}").contains(&wanted)) {
                return false;
            }
        }
        if !self.major.is_empty() {
            let wanted = lower(&self.major);
            let number = crate::parse_number(&self.major).map(|number| number as u8);
            if number != Some(life.major) && !lower(&major_name(life.major)).contains(&wanted) {
                return false;
            }
        }
        true
    }
}

/// O texto de um IRP (o `irptrace show` e a vista de detalhe).
pub fn describe(life: &IrpLife, name: &dyn Fn(u64) -> String, driver_name: &dyn Fn(u64) -> String) -> String {
    let mut text = format!("IRP #{} {:#x} {} {} pilha {} thread {:#x} PID {}\n", life.number, life.address, major_name(life.major), minor_name(life.major, life.minor).unwrap_or(""), life.stack, life.thread, life.pid);
    if let Some(creator) = life.creator {
        text.push_str(&format!("  criado por {}\n", name(creator)));
    }
    for step in &life.steps {
        let offset = (step.time().saturating_sub(life.start)) as f64 / 10.0;
        match step {
            Step::Created { .. } => text.push_str(&format!("  +{offset:>9.1}us criado\n")),
            Step::Call(hop) => {
                let returned = if hop.returned != 0 { format!(" volta +{:.1}us {}", (hop.returned - life.start) as f64 / 10.0, hop.status.map(ntstatus::describe).unwrap_or_default()) } else { String::new() };
                text.push_str(&format!(
                    "  +{offset:>9.1}us {}IofCallDriver -> {} dispositivo {:#x} posicao {} rotina {}{}\n",
                    "  ".repeat(hop.depth),
                    driver_name(hop.driver),
                    hop.device,
                    hop.location,
                    name(hop.routine),
                    returned
                ));
            }
            Step::Completed { status, information, location, caller, .. } => {
                text.push_str(&format!("  +{offset:>9.1}us IofCompleteRequest {} Information {:#x} posicao {} por {}\n", ntstatus::describe(*status), information, location, name(*caller)))
            }
            Step::Routine(call) => text.push_str(&format!("  +{offset:>9.1}us rotina de conclusao {} ({}) -> {}\n", name(call.routine), driver_name(call.driver), ntstatus::describe(call.result))),
            Step::Freed { caller, .. } => text.push_str(&format!("  +{offset:>9.1}us IoFreeIrp por {}\n", name(*caller))),
        }
    }
    text.push_str(&format!("  final: {}{}\n", life.status_text(), life.duration().map(|duration| format!(" em {:.1}us", duration as f64 / 10.0)).unwrap_or_default()));
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::tests::irp_record;
    use crate::stream::{parse_record, Record};

    fn event(bytes: Vec<u8>) -> IrpEvent {
        match parse_record(&bytes) {
            Some(Record::Irp(event)) => event,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn builds_a_create_through_two_drivers() {
        let mut timeline = Timeline::default();
        let events = [
            // Topo: o filtro recebe o CREATE e passa ao ntfs.
            irp_record(1, stream::KIND_IRP_CALL, 100, 0xA000, 0xD1, 0x51, 0x7001, 0x8001, 0, 0, 0, 2, 2),
            irp_record(2, stream::KIND_IRP_CALL, 110, 0xA000, 0xD2, 0x52, 0x8001, 0x8002, 0, 0, 0, 1, 2),
            // O ntfs completa dentro da rotina dele.
            irp_record(3, stream::KIND_IRP_COMPLETE, 150, 0xA000, 0, 0, 0x8002, 0, 0, 0, 0, 1, 2),
            irp_record(4, stream::KIND_IRP_ROUTINE, 155, 0xA000, 0xD1, 0x51, 0, 0x9001, 0, 0, 0, 2, 2),
            irp_record(5, stream::KIND_IRP_RETURN, 160, 0xA000, 0xD2, 0x52, 0, 0, 0, 0, 0, 0, 0),
            irp_record(6, stream::KIND_IRP_RETURN, 170, 0xA000, 0xD1, 0x51, 0, 0, 0, 0, 0, 0, 0),
            // O mesmo endereço, outro IRP (um READ).
            irp_record(7, stream::KIND_IRP_CALL, 300, 0xA000, 0xD1, 0x51, 0x7001, 0x8001, 0, 3, 0, 2, 2),
        ];
        for bytes in events {
            timeline.push(&event(bytes));
        }
        assert_eq!(timeline.irps.len(), 2, "{:#?}", timeline.irps);
        let create = &timeline.irps[0];
        assert_eq!(create.major, 0);
        assert_eq!(create.hops().count(), 2);
        assert_eq!(create.devices(), vec![0xD1, 0xD2]);
        assert_eq!(create.hops().nth(1).map(|hop| hop.depth), Some(1));
        assert_eq!(create.final_status, Some(0));
        assert!(create.completed);
        assert_eq!(create.hops().map(|hop| hop.status).collect::<Vec<_>>(), vec![Some(0), Some(0)]);
        assert_eq!(create.end, Some(170));
        assert!(create.steps.iter().any(|step| matches!(step, Step::Routine(call) if call.routine == 0x9001)));
        let read = &timeline.irps[1];
        assert_eq!(read.major, 3);
        assert!(read.final_status.is_none());
        let names = |driver: u64| if driver == 0x52 { "\\FileSystem\\Ntfs".to_string() } else { format!("{driver:#x}") };
        assert!(Filter { driver: "ntfs".into(), ..Filter::default() }.matches(create, &names));
        assert!(!Filter { driver: "ntfs".into(), ..Filter::default() }.matches(read, &names));
        assert!(Filter { major: "read".into(), ..Filter::default() }.matches(read, &names));
        assert!(Filter { major: "0".into(), ..Filter::default() }.matches(create, &names));
        assert!(Filter { device: "d2".into(), ..Filter::default() }.matches(create, &names));
        let text = describe(create, &|address| format!("{address:#x}"), &names);
        assert!(text.contains("IRP_MJ_CREATE"), "{text}");
        assert!(text.contains("\\FileSystem\\Ntfs"), "{text}");
        assert!(text.contains("STATUS_SUCCESS"), "{text}");
    }

    #[test]
    fn allocation_more_processing_and_free() {
        let mut timeline = Timeline::default();
        let events = [
            irp_record(1, stream::KIND_IRP_ALLOCATE, 10, 0xB000, 0, 0, 0x7777, 0, 600, 0, 0, 0, 3),
            irp_record(2, stream::KIND_IRP_CALL, 20, 0xB000, 0xD1, 0x51, 0x7778, 0x8001, 0, 0x1B, 7, 3, 3),
            irp_record(3, stream::KIND_IRP_COMPLETE, 30, 0xB000, 0, 0, 0, 0, 0, 0x1B, 7, 3, 3),
            irp_record(4, stream::KIND_IRP_ROUTINE, 31, 0xB000, 0, 0, 0, 0x9999, 0xC000_0016, 0, 0, 4, 3),
            irp_record(5, stream::KIND_IRP_RETURN, 40, 0xB000, 0xD1, 0x51, 0, 0, 0, 0, 0, 0, 0),
            irp_record(6, stream::KIND_IRP_FREE, 50, 0xB000, 0, 0, 0x7779, 0, 0, 0, 0, 0, 0),
        ];
        for bytes in events {
            timeline.push(&event(bytes));
        }
        assert_eq!(timeline.irps.len(), 1);
        let life = &timeline.irps[0];
        assert_eq!(life.creator, Some(0x7777));
        assert_eq!(minor_name(life.major, life.minor), Some("QUERY_DEVICE_RELATIONS"));
        assert!(life.freed);
        assert!(!life.completed);
        assert_eq!(life.end, Some(50));
        assert_eq!(life.duration(), Some(40));
    }
}
