//! As ferramentas das extensões de engenharia reversa: o monitor de APIs,
//! o rastreador de IRPs, os passos para trás da reprodução, os snapshots
//! da máquina, a vista de um endereço como tipo do PDB e os exploradores
//! do Registro, do namespace e dos arquivos.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use opennt_kd::api_monitor;
use opennt_kd::explore;
use opennt_kd::irp_timeline::{self, Step};
use opennt_kd::ntstatus;
use opennt_kd::Client;
use serde_json::{json, Value};

use super::{boolean, hex, integer, object, set_process_argument, stop_value, text, timeout, Arguments, ToolError, ToolResult};
use crate::engine::Engine;

/// As definições (nome, descrição, esquema).
pub fn definitions() -> Vec<(&'static str, &'static str, Value)> {
    let path = |what: &str| text(what);
    vec![
        (
            "api_monitor_start",
            "Liga o monitor de APIs no alvo (maquina parada): cada export do ntoskrnl e da HAL chamado pelos drivers pedidos vira um registro (argumentos, resultado, NTSTATUS, thread, hora, chamador), entregue em lotes com a maquina rodando.",
            object(json!({"drivers": {"type": "array", "items": {"type": "string"}, "description": "modulos dos chamadores (nomes ou enderecos; ate 8); vazio = todos"}}), &[]),
        ),
        ("api_monitor_stop", "Desliga o monitor de APIs (as chamadas guardadas ficam).", object(json!({}), &[])),
        (
            "api_monitor_fetch",
            "As chamadas guardadas pelo monitor de APIs (le o que falta do alvo se a maquina estiver parada), com filtros.",
            object(
                json!({
                    "driver": text("parte do nome do modulo chamador"),
                    "export": text("parte do nome do export"),
                    "status": text("parte do resultado (nome ou valor do NTSTATUS)"),
                    "failures_only": boolean("so as que falharam"),
                    "offset": integer("primeira linha (depois do filtro)", 0, u32::MAX as u64),
                    "limit": integer("linhas (padrao 200)", 1, 5000),
                    "clear": boolean("esquece as chamadas guardadas depois de ler")
                }),
                &[],
            ),
        ),
        ("irp_trace_start", "Liga o rastreador de IRPs (maquina parada): criacao, cada IofCallDriver, IofCompleteRequest, rotinas de conclusao e IoFreeIrp.", object(json!({}), &[])),
        ("irp_trace_stop", "Desliga o rastreador de IRPs.", object(json!({}), &[])),
        (
            "irp_trace_fetch",
            "Os IRPs vistos (le o que falta do alvo se a maquina estiver parada): a vida de cada um pelos dispositivos, com filtros.",
            object(
                json!({
                    "driver": text("parte do nome do driver por onde passou (\\\\Driver\\\\X, \\\\FileSystem\\\\Ntfs)"),
                    "device": text("parte do endereco do dispositivo"),
                    "major": text("major function (numero ou parte do nome, como CREATE)"),
                    "failures_only": boolean("so os concluidos com erro"),
                    "irp": text("um IRP (numero da sessao ou endereco): os passos dele"),
                    "limit": integer("IRPs (padrao 50, os mais recentes)", 1, 2000)
                }),
                &[],
            ),
        ),
        ("reverse_step", "Na reproducao de uma gravacao (launch com extra --replay=ARQ): volta uma instrucao (reverse-stepi do gdbstub do QEMU).", object(json!({"count": integer("instrucoes (padrao 1)", 1, 100)}), &[])),
        ("reverse_continue", "Na reproducao: volta ate o breakpoint ou vigia anterior (reverse-continue); sem nenhum, ate o comeco da gravacao.", object(json!({"timeout_ms": timeout(1_800_000)}), &[])),
        ("snapshot_save", "Grava um snapshot da maquina (savevm). Precisa dos discos em qcow2: launch com extra --vm-snapshots ou --record=ARQ.", object(json!({"name": text("nome (letras, digitos, - _ .)")}), &["name"])),
        ("snapshot_restore", "Volta a um snapshot (loadvm): a maquina volta ao ponto dele; os breakpoints da sessao sao regravados.", object(json!({"name": text("nome do snapshot")}), &["name"])),
        ("snapshot_list", "Os snapshots da maquina (info snapshots).", object(json!({}), &[])),
        (
            "view_struct",
            "Um endereco como tipo do PDB, campo a campo em arvore: structs aninhadas, arrays, ponteiros e listas (LIST_ENTRY pelo Flink). Tipos do ntoskrnl (_EPROCESS) ou de um modulo (ntdll!_PEB).",
            object(
                json!({
                    "type": text("o tipo: _EPROCESS, _IRP, nt!_DEVICE_OBJECT, ntdll!_PEB"),
                    "address": text("expressao do endereco"),
                    "expand": {"type": "array", "items": {"type": "string"}, "description": "campos a abrir pela chave (Pcb, ThreadListHead, ThreadListHead/#0)"},
                    "process": text("PID ou EPROCESS do processo das leituras (tipos de usuario)")
                }),
                &["type", "address"],
            ),
        ),
        ("registry_list", "Uma chave do Registro vivo (a arena do Configuration Manager): as subchaves e os valores.", object(json!({"path": path("caminho: \\\\Registry\\\\Machine\\\\SYSTEM\\\\Select")}), &["path"])),
        ("registry_read", "Um valor do Registro inteiro (tipo, tamanho, dados em hexadecimal e em texto).", object(json!({"path": path("caminho da chave"), "name": text("nome do valor ((padrao) = o sem nome)")}), &["path", "name"])),
        ("object_list", "Um diretorio do namespace do Object Manager: nome, tipo, corpo nativo, filhos e o destino dos links.", object(json!({"path": path("caminho (\\\\, \\\\Device, \\\\Driver, \\\\GLOBAL??)")}), &[])),
        ("file_list", "Uma pasta do volume NTFS do kernel (o leitor do proprio kernel): nome, pasta, tamanho, atributos, data.", object(json!({"path": path("caminho com / (padrao /)")}), &[])),
        (
            "file_read",
            "Le bytes de um arquivo do volume do kernel.",
            object(json!({"path": path("caminho com /"), "offset": integer("deslocamento (padrao 0)", 0, u64::MAX >> 1), "length": integer("bytes (padrao 4096)", 1, 1 << 20)}), &["path"]),
        ),
    ]
}

fn api_row(row: &api_monitor::ApiRow) -> Value {
    let call = &row.call;
    json!({
        "sequence": call.sequence,
        "time_us": call.time as f64 / 10.0,
        "cpu": call.cpu,
        "pid": call.pid,
        "tid": call.tid,
        "thread": hex(call.thread),
        "driver": row.module,
        "caller": row.caller,
        "return_address": hex(call.return_address),
        "export": row.name.as_ref(),
        "arguments": row.arguments,
        "raw_arguments": call.arguments.iter().map(|value| hex(*value)).collect::<Vec<_>>(),
        "result": row.result,
        "status": row.status.map(|status| json!({"value": format!("{status:#010x}"), "name": ntstatus::name(status)})),
        "failed": row.failed,
        "duration_us": call.duration as f64 / 10.0,
    })
}

fn step_value(step: &Step, start: u64, names: &HashMap<u64, String>, client: &Client) -> Value {
    let offset = step.time().saturating_sub(start) as f64 / 10.0;
    let name = |driver: u64| names.get(&driver).cloned().unwrap_or_else(|| hex(driver));
    match step {
        Step::Created { caller, export, .. } => json!({"at_us": offset, "event": "created", "caller": client.symbols.describe(*caller), "export_id": export}),
        Step::Call(hop) => json!({
            "at_us": offset,
            "event": "call",
            "depth": hop.depth,
            "device": hex(hop.device),
            "driver": name(hop.driver),
            "routine": client.symbols.describe(hop.routine),
            "caller": if hop.caller == 0 { Value::Null } else { json!(client.symbols.describe(hop.caller)) },
            "major": irp_timeline::major_name(hop.major),
            "minor": irp_timeline::minor_name(hop.major, hop.minor),
            "location": hop.location,
            "returned_us": if hop.returned == 0 { Value::Null } else { json!(hop.returned.saturating_sub(start) as f64 / 10.0) },
            "status": hop.status.map(ntstatus::describe),
        }),
        Step::Completed { status, information, location, caller, .. } => json!({"at_us": offset, "event": "completed", "status": ntstatus::describe(*status), "information": hex(*information), "location": location, "caller": client.symbols.describe(*caller)}),
        Step::Routine(call) => json!({"at_us": offset, "event": "completion_routine", "routine": client.symbols.describe(call.routine), "driver": name(call.driver), "result": ntstatus::describe(call.result)}),
        Step::Freed { caller, .. } => json!({"at_us": offset, "event": "freed", "caller": client.symbols.describe(*caller)}),
    }
}

/// Roda uma das ferramentas deste módulo (`None`: não é daqui).
pub fn run(engine: &mut dyn Engine, name: &str, args: &Arguments) -> Option<ToolResult> {
    Some(match name {
        "api_monitor_start" => (|| {
            let client = engine.client()?;
            let text = client.api_monitor_start(&args.list("drivers"))?;
            Ok(json!({"enabled": true, "message": text}))
        })(),
        "api_monitor_stop" => (|| {
            let client = engine.client()?;
            let text = client.api_monitor_stop()?;
            Ok(json!({"enabled": false, "message": text, "stored": client.monitors.api_rows.len()}))
        })(),
        "api_monitor_fetch" => (|| {
            let client = engine.client()?;
            if client.is_stopped() {
                client.fetch_records()?;
            } else {
                let _ = client.poll(Duration::from_millis(20))?;
            }
            let filter = api_monitor::Filter { driver: args.text("driver").unwrap_or_default(), export: args.text("export").unwrap_or_default(), status: args.text("status").unwrap_or_default(), failures_only: args.flag("failures_only").unwrap_or(false) };
            let offset = args.integer("offset").unwrap_or(0) as usize;
            let limit = args.integer("limit").unwrap_or(200) as usize;
            let matching: Vec<&api_monitor::ApiRow> = client.monitors.api_rows.iter().filter(|row| filter.matches(row)).collect();
            let rows: Vec<Value> = matching.iter().skip(offset).take(limit).map(|row| api_row(row)).collect();
            let value = json!({
                "enabled": client.monitors.api_enabled,
                "total": client.monitors.api_rows.len(),
                "matching": matching.len(),
                "lost": client.monitors.collector.lost,
                "dropped_in_target": client.monitors.target_dropped,
                "rows": rows,
            });
            if args.flag("clear").unwrap_or(false) {
                client.monitors.api_rows.clear();
            }
            Ok(value)
        })(),
        "irp_trace_start" => (|| {
            let client = engine.client()?;
            Ok(json!({"enabled": true, "message": client.irp_trace_start()?}))
        })(),
        "irp_trace_stop" => (|| {
            let client = engine.client()?;
            Ok(json!({"enabled": false, "message": client.irp_trace_stop()?}))
        })(),
        "irp_trace_fetch" => (|| {
            let client = engine.client()?;
            if client.is_stopped() {
                client.fetch_records()?;
            } else {
                let _ = client.poll(Duration::from_millis(20))?;
            }
            let lives = client.monitors.irps.irps.clone();
            // Os nomes dos drivers (lidos da memória com a máquina parada).
            let mut names = HashMap::new();
            if client.is_stopped() {
                let drivers: HashSet<u64> = lives.iter().flat_map(|life| life.drivers()).collect();
                for driver in drivers.into_iter().take(512) {
                    names.insert(driver, client.driver_name(driver));
                }
            }
            if let Some(wanted) = args.text("irp") {
                let value = opennt_kd::parse_number(&wanted).ok_or("irp: numero ou endereco")?;
                let life = lives.iter().rev().find(|life| life.number as u64 == value || life.address == value).ok_or_else(|| format!("IRP {wanted} nao visto"))?;
                let steps: Vec<Value> = life.steps.iter().map(|step| step_value(step, life.start, &names, client)).collect();
                return Ok(json!({"irp": hex(life.address), "number": life.number, "major": irp_timeline::major_name(life.major), "minor": irp_timeline::minor_name(life.major, life.minor), "creator": life.creator.map(|address| client.symbols.describe(address)), "status": life.status_text(), "final_status": life.final_status.map(|status| json!({"value": format!("{status:#010x}"), "name": ntstatus::name(status)})), "information": hex(life.information), "completed": life.completed, "freed": life.freed, "duration_us": life.duration().map(|duration| duration as f64 / 10.0), "steps": steps}));
            }
            let filter = irp_timeline::Filter { driver: args.text("driver").unwrap_or_default(), device: args.text("device").unwrap_or_default(), major: args.text("major").unwrap_or_default(), failures_only: args.flag("failures_only").unwrap_or(false) };
            let name = |driver: u64| names.get(&driver).cloned().unwrap_or_else(|| hex(driver));
            let matching: Vec<&irp_timeline::IrpLife> = lives.iter().filter(|life| filter.matches(life, &name)).collect();
            let limit = args.integer("limit").unwrap_or(50) as usize;
            let start = matching.len().saturating_sub(limit);
            let irps: Vec<Value> = matching[start..]
                .iter()
                .map(|life| json!({"number": life.number, "irp": hex(life.address), "major": irp_timeline::major_name(life.major), "minor": irp_timeline::minor_name(life.major, life.minor), "drivers": life.drivers().into_iter().map(name).collect::<Vec<_>>(), "status": life.status_text(), "final_status": life.final_status.map(|status| format!("{status:#010x}")), "completed": life.completed, "freed": life.freed, "duration_us": life.duration().map(|duration| duration as f64 / 10.0), "hops": life.hops().count()}))
                .collect();
            Ok(json!({"enabled": client.monitors.irp_enabled, "total": lives.len(), "matching": matching.len(), "irps": irps}))
        })(),
        "reverse_step" => (|| {
            let client = engine.client()?;
            let mut text = String::new();
            for _ in 0..args.integer("count").unwrap_or(1) {
                text = client.reverse_step()?;
            }
            Ok(stop_value(client, &text))
        })(),
        "reverse_continue" => (|| {
            let client = engine.client()?;
            let text = client.reverse_continue()?;
            Ok(stop_value(client, &text))
        })(),
        "snapshot_save" => (|| {
            let monitor = engine.monitor_address();
            let client = engine.client()?;
            if client.qemu_monitor.is_none() {
                client.set_qemu_monitor(monitor);
            }
            Ok(json!({"saved": args.text("name"), "message": client.snapshot_save(&args.text("name").unwrap_or_default())?}))
        })(),
        "snapshot_restore" => (|| {
            let monitor = engine.monitor_address();
            let client = engine.client()?;
            if client.qemu_monitor.is_none() {
                client.set_qemu_monitor(monitor);
            }
            let message = client.snapshot_load(&args.text("name").unwrap_or_default())?;
            let stop = client.last_stop().to_string();
            let mut value = stop_value(client, &stop);
            value["message"] = json!(message);
            Ok(value)
        })(),
        "snapshot_list" => (|| {
            let monitor = engine.monitor_address();
            let client = engine.client()?;
            if client.qemu_monitor.is_none() {
                client.set_qemu_monitor(monitor);
            }
            let list: Vec<Value> = client.snapshot_list()?.into_iter().map(|snapshot| json!({"name": snapshot.tag, "id": snapshot.id, "vm_size": snapshot.vm_size, "date": snapshot.date, "vm_clock": snapshot.vm_clock, "icount": snapshot.icount})).collect();
            Ok(json!({"snapshots": list}))
        })(),
        "view_struct" => (|| {
            let client = engine.client()?;
            set_process_argument(client, args)?;
            let address = client.evaluate(&args.text("address").unwrap_or_default())?;
            let expanded: HashSet<String> = args.list("expand").into_iter().collect();
            let type_name = args.text("type").unwrap_or_default();
            let (types, index, rows) = client.struct_view(&type_name, address, &expanded, &HashMap::new())?;
            let fields: Vec<Value> = rows
                .iter()
                .map(|row| json!({"key": row.key, "depth": row.depth, "name": row.name, "offset": hex(row.offset), "address": hex(row.address), "type": row.type_name, "value": row.value, "expandable": row.expandable, "expanded": row.expanded, "editable": row.editable}))
                .collect();
            Ok(json!({"type": types.name(index), "size": hex(types.size(index)), "address": hex(address), "fields": fields}))
        })(),
        "registry_list" => (|| {
            let client = engine.client()?;
            let path = args.text("path").unwrap_or_default();
            let (info, keys) = client.registry_keys(&path)?;
            let values = client.registry_values(&path)?;
            Ok(json!({
                "path": info.path,
                "last_write": explore::nt_time(info.last_write),
                "volatile": info.volatile,
                "hive": info.hive,
                "subkeys": keys.iter().map(|key| json!({"name": key.name, "subkeys": key.subkeys, "values": key.values})).collect::<Vec<_>>(),
                "values": values.iter().map(|value| json!({"name": value.name, "type": value.kind_name(), "size": value.size, "data": value.display()})).collect::<Vec<_>>(),
            }))
        })(),
        "registry_read" => (|| {
            let client = engine.client()?;
            let value = client.registry_value(&args.text("path").unwrap_or_default(), &args.text("name").unwrap_or_default())?;
            Ok(json!({"name": value.name, "type": value.kind_name(), "type_code": value.kind, "size": value.size, "text": value.display(), "hex": opennt_kd::rsp::hex(&value.data)}))
        })(),
        "object_list" => (|| {
            let client = engine.client()?;
            let directory = client.object_directory(&args.text("path").unwrap_or_else(|| "\\".into()))?;
            Ok(json!({
                "path": directory.path,
                "type": directory.kind,
                "count": directory.count,
                "objects": directory.entries.iter().map(|entry| json!({"name": entry.name, "type": entry.kind, "body": hex(entry.body), "children": entry.children, "target": entry.target})).collect::<Vec<_>>(),
            }))
        })(),
        "file_list" => (|| {
            let client = engine.client()?;
            let path = args.text("path").unwrap_or_else(|| "/".into());
            let entries = client.file_list(&path)?;
            Ok(json!({"path": path, "entries": entries.iter().map(|entry| json!({"name": entry.name, "directory": entry.directory, "size": entry.size, "attributes": format!("{:#x}", entry.attributes), "modified": explore::nt_time(entry.modified)})).collect::<Vec<_>>()}))
        })(),
        "file_read" => (|| {
            let client = engine.client()?;
            let path = args.text("path").unwrap_or_default();
            let offset = args.integer("offset").unwrap_or(0);
            let (size, bytes) = client.file_read(&path, offset, args.integer("length").unwrap_or(4096))?;
            let text: String = bytes.iter().map(|&byte| if (0x20..0x7F).contains(&byte) || byte == b'\n' { byte as char } else { '.' }).collect();
            Ok(json!({"path": path, "size": size, "offset": offset, "length": bytes.len(), "hex": opennt_kd::rsp::hex(&bytes), "text": text}))
        })(),
        _ => return None,
    })
    .map(|result: Result<Value, String>| result.map_err(ToolError::Failed))
}
