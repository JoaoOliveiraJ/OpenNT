//! Testes do gerador: a tradução de nomes, offsets de uma amostra de
//! estruturas conferidos contra o código do ntoskrnl.exe real e a
//! atualidade dos arquivos gerados.
//!
//! Os dois últimos precisam do PDB em `build/symbols` (o `cargo xtask
//! nt-types` o baixa); sem ele, são pulados com um aviso.

use std::fs;

use super::layout::{camel, screaming, snake, Generator};
use super::{generate, open_pdb, outdated, pdb, proofs, Config, CONFIG};

#[test]
fn names_follow_the_nt_convention() {
    let cases = [
        ("IoStatus", "io_status", "IO_STATUS"),
        ("Type", "type_", "TYPE"),
        ("WoW64Process", "wo_w64_process", "WO_W64_PROCESS"),
        ("CPUHint", "cpu_hint", "CPU_HINT"),
        ("DPCQueueDepth", "dpc_queue_depth", "DPC_QUEUE_DEPTH"),
        ("KTHREAD", "kthread", "KTHREAD"),
        ("u", "u", "U"),
        ("Reserved1", "reserved1", "RESERVED1"),
        ("__Fill", "fill", "FILL"),
        ("0Field", "n0_field", "N0_FIELD"),
        ("SeAuditProcessCreationInfo", "se_audit_process_creation_info", "SE_AUDIT_PROCESS_CREATION_INFO"),
        ("XStateFeaturesFlags", "x_state_features_flags", "X_STATE_FEATURES_FLAGS"),
    ];
    for (nt, rust, constant) in cases {
        assert_eq!(snake(nt), rust, "snake({nt})");
        assert_eq!(screaming(nt), constant, "screaming({nt})");
    }
    let types = [
        ("_KTHREAD_STATE", "KthreadState"),
        ("_IMAGE_NT_HEADERS64", "ImageNtHeaders64"),
        ("HAL_PRIVATE_DISPATCH", "HalPrivateDispatch"),
        ("_KiIoAccessMap", "KiIoAccessMap"),
        ("__m128", "M128"),
        ("_2D_ARRAY", "T2dArray"),
        ("_IO_STATUS_BLOCK32", "IoStatusBlock32"),
    ];
    for (nt, rust) in types {
        assert_eq!(camel(nt), rust, "camel({nt})");
    }
}

/// O PDB de `build/symbols` e a lista de tipos; `None` (teste pulado) sem o PDB.
fn inputs() -> Option<(std::path::PathBuf, Config, pdb::Tpi)> {
    let root = crate::build::workspace_root();
    let config = Config::load(&root.join(CONFIG)).unwrap();
    let path = root.join(&config.pdb_file);
    if !path.exists() {
        eprintln!("{} ausente (rode `cargo xtask nt-types`); teste pulado", path.display());
        return None;
    }
    let tpi = open_pdb(&config, &path).unwrap();
    Some((root, config, tpi))
}

/// Primeira instrução de um acessor do ntoskrnl: um `mov rax, gs:[disp32]`
/// opcional (a thread corrente) e um acesso `[rax|rcx + disp]` por
/// mov/movzx/lea. Devolve (deslocamento do gs, deslocamento do campo).
fn accessor(code: &[u8]) -> Option<(Option<u32>, u32)> {
    let le32 = |at: usize| u32::from_le_bytes(code[at..at + 4].try_into().unwrap());
    let mut at = 0;
    let mut gs = None;
    if code.starts_with(&[0x65, 0x48, 0x8B, 0x04, 0x25]) {
        gs = Some(le32(5));
        at = 9;
    }
    if code[at] & 0xF0 == 0x40 {
        at += 1; // REX
    }
    match code[at] {
        0x8B | 0x8D | 0x8A => at += 1,
        0x0F if code[at + 1] == 0xB6 => at += 2,
        // `ret` logo depois do gs (KeGetCurrentThread): só o deslocamento do gs.
        0xC3 if gs.is_some() => return Some((gs, 0)),
        _ => return None,
    }
    let modrm = code[at];
    if !matches!(modrm & 7, 0 | 1) {
        return None;
    }
    match modrm >> 6 {
        1 => Some((gs, code[at + 1] as u32)),
        2 => Some((gs, le32(at + 1))),
        _ => None,
    }
}

/// Offsets que o próprio código do ntoskrnl usa nos acessores exportados,
/// conferidos com os que o gerador tira do PDB (os das asserções geradas).
#[test]
fn sample_offsets_match_ntoskrnl_accessors() {
    let Some((_, config, tpi)) = inputs() else { return };
    let Some(system_root) = std::env::var_os("SystemRoot") else { return };
    let kernel_path = std::path::Path::new(&system_root).join("System32").join("ntoskrnl.exe");
    let Ok(kernel) = fs::read(&kernel_path) else {
        eprintln!("{} ilegível; teste pulado", kernel_path.display());
        return;
    };
    let pe = pdb::PeFile::parse(&kernel).unwrap();
    let (guid, age, _) = pe.rsds().unwrap();
    if pdb::guid_text(&guid) != config.pdb_guid || age != config.pdb_age {
        eprintln!("{} é de outra compilação que o PDB do nt_types.toml; teste pulado", kernel_path.display());
        return;
    }
    let mut generator = Generator::new(&tpi, &config);
    generator.close(&config.roots).unwrap();
    let offset = |structure: &str, path: &str| -> u32 {
        proofs::path_offset(&generator, structure, path)
            .unwrap_or_else(|| panic!("{structure}.{path} fora do conjunto gerado"))
            .0 as u32
    };

    // KeGetCurrentThread: mov rax, gs:[KPCR.Prcb.CurrentThread]; ret.
    let current_thread = offset("_KPCR", "Prcb") + offset("_KPRCB", "CurrentThread");
    let (gs, _) = accessor(pe.export_code("KeGetCurrentThread").unwrap()).unwrap();
    assert_eq!(gs, Some(current_thread), "KeGetCurrentThread");

    let sample = [
        ("PsGetProcessId", "_EPROCESS", "UniqueProcessId"),
        ("PsGetProcessPeb", "_EPROCESS", "Peb"),
        ("PsGetProcessImageFileName", "_EPROCESS", "ImageFileName"),
        ("PsGetProcessSectionBaseAddress", "_EPROCESS", "SectionBaseAddress"),
        ("PsGetProcessWin32Process", "_EPROCESS", "Win32Process"),
        ("PsGetProcessExitStatus", "_EPROCESS", "ExitStatus"),
        ("PsGetProcessInheritedFromUniqueProcessId", "_EPROCESS", "InheritedFromUniqueProcessId"),
        ("PsGetProcessJob", "_EPROCESS", "Job"),
        ("PsGetProcessDebugPort", "_EPROCESS", "DebugPort"),
        ("PsGetProcessCreateTimeQuadPart", "_EPROCESS", "CreateTime"),
        ("PsGetProcessProtection", "_EPROCESS", "Protection"),
        ("PsGetThreadTeb", "_KTHREAD", "Teb"),
        ("PsGetThreadWin32Thread", "_KTHREAD", "Win32Thread"),
        ("PsGetThreadProcess", "_KTHREAD", "Process"),
        ("PsGetThreadId", "_ETHREAD", "Cid.UniqueThread"),
        ("PsGetThreadProcessId", "_ETHREAD", "Cid.UniqueProcess"),
        ("IoGetCurrentProcess", "_KTHREAD", "ApcState.Process"),
        ("IoGetInitialStack", "_KTHREAD", "InitialStack"),
        ("IoGetTopLevelIrp", "_ETHREAD", "TopLevelIrp"),
        ("ExGetPreviousMode", "_KTHREAD", "PreviousMode"),
        ("PsGetCurrentThreadStackBase", "_KTHREAD", "StackBase"),
        ("PsGetCurrentThreadStackLimit", "_KTHREAD", "StackLimit"),
        ("IoGetAttachedDevice", "_DEVICE_OBJECT", "AttachedDevice"),
    ];
    for (export, structure, path) in sample {
        let code = pe.export_code(export).unwrap();
        let (gs, displacement) = accessor(code).unwrap_or_else(|| panic!("{export}: padrão de acessor não reconhecido"));
        if let Some(gs) = gs {
            assert_eq!(gs, current_thread, "{export}: thread corrente");
        }
        assert_eq!(displacement, offset(structure, path), "{export}: {structure}.{path}");
    }
}

/// O mesmo que `cargo xtask nt-types --check`.
#[test]
fn generated_files_are_current() {
    let Some((root, config, tpi)) = inputs() else { return };
    let mut generator = Generator::new(&tpi, &config);
    generator.close(&config.roots).unwrap();
    let generated = generate(&root, &config, &generator).unwrap();
    let problems = generated.problems(&outdated(&root, &generated));
    assert!(problems.is_empty(), "{}\nrode `cargo xtask nt-types`", problems.join("\n"));
}
