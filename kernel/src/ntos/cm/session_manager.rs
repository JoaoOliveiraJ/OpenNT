//! Configuração do Session Manager (`Control\Session Manager`).
//!
//! Os valores que o smss.exe real lê na inicialização, copiados do registro
//! de uma instalação do Windows 10 19041: os subsistemas (o `Required` com
//! `Debug` e `Windows`, e a linha de comando do csrss), as DLLs conhecidas
//! (um valor por DLL), os dispositivos DOS, o ambiente do sistema, os
//! diretórios de objetos e os parâmetros do Memory Management, e o
//! `Control\CrashControl` que o smss abre antes dos arquivos de paginação.
//!
//! O `SubSystems` leva o `Kmode` da instalação
//! (`\SystemRoot\System32\win32k.sys`): o smss da sessão o carrega pela
//! SystemExtendServiceTableInformation antes de criar o csrss. Ficam de fora
//! o que pertence a outro marco ou à máquina de origem: o `BootExecute` (o
//! autochk) e as renomeações pendentes; o arquivo de paginação fica no
//! volume de dados (D:) em vez do C: da instalação; do
//! ambiente saem os caminhos de programas de terceiros. Só o boot do
//! processo inicial real (`--initial-process=smss`) leva esta configuração.
//!
//! Dados puros da hive SYSTEM (veja `cm/seed.rs`): o `xtask` grava estas
//! chaves no arquivo da hive e o kernel só as semeia em memória quando o
//! arquivo falta.

use alloc::vec::Vec;

use super::seed::SeedKey;

const SESSION_MANAGER: &str = "CurrentControlSet\\Control\\Session Manager";

const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_DWORD: u32 = 4;
const REG_MULTI_SZ: u32 = 7;

/// Um valor do registro de origem.
enum Value<'a> {
    Text(u32, &'a str),
    Number(u32),
    Strings(&'a [&'a str]),
}

/// Valores do próprio `Session Manager`.
const ROOT: &[(&str, Value)] = &[
    ("AutoChkTimeout", Value::Number(0x8)),
    ("BootShell", Value::Text(REG_EXPAND_SZ, "%SystemRoot%\\system32\\bootim.exe")),
    ("CriticalSectionTimeout", Value::Number(0x278d00)),
    ("ExcludeFromKnownDlls", Value::Strings(&[])),
    ("GlobalFlag", Value::Number(0)),
    ("GlobalFlag2", Value::Number(0)),
    ("HeapDeCommitFreeBlockThreshold", Value::Number(0)),
    ("HeapDeCommitTotalFreeThreshold", Value::Number(0)),
    ("HeapSegmentCommit", Value::Number(0)),
    ("HeapSegmentReserve", Value::Number(0)),
    ("InitConsoleFlags", Value::Number(0)),
    ("NumberOfInitialSessions", Value::Number(0x2)),
    ("ObjectDirectories", Value::Strings(&["\\Windows", "\\RPC Control"])),
    ("ProcessorControl", Value::Number(0x2)),
    ("ProtectionMode", Value::Number(0x1)),
    ("ResourceTimeoutCount", Value::Number(0x96)),
    ("RunLevelExecute", Value::Strings(&["WinInit", "ServiceControlManager"])),
    ("RunLevelValidate", Value::Strings(&["ServiceControlManager"])),
    ("SETUPEXECUTE", Value::Strings(&[])),
    ("AutoChkSkipSystemPartition", Value::Number(0)),
];

/// `SubSystems`.
const SUBSYSTEMS: &[(&str, Value)] = &[
    ("", Value::Text(REG_SZ, "mnmsrvc")),
    ("Debug", Value::Text(REG_EXPAND_SZ, "")),
    ("Kmode", Value::Text(REG_EXPAND_SZ, "\\SystemRoot\\System32\\win32k.sys")),
    ("Optional", Value::Strings(&[])),
    ("Required", Value::Strings(&["Debug", "Windows"])),
    (
        "Windows",
        Value::Text(
            REG_EXPAND_SZ,
            "%SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16",
        ),
    ),
];

/// `KnownDLLs`: um valor REG_SZ por DLL.
const KNOWN_DLLS: &[(&str, &str)] = &[
    ("_wow64cpu", "wow64cpu.dll"),
    ("_wowarmhw", "wowarmhw.dll"),
    ("_xtajit", "xtajit.dll"),
    ("advapi32", "advapi32.dll"),
    ("clbcatq", "clbcatq.dll"),
    ("combase", "combase.dll"),
    ("COMDLG32", "COMDLG32.dll"),
    ("coml2", "coml2.dll"),
    ("DifxApi", "difxapi.dll"),
    ("gdi32", "gdi32.dll"),
    ("gdiplus", "gdiplus.dll"),
    ("IMAGEHLP", "IMAGEHLP.dll"),
    ("IMM32", "IMM32.dll"),
    ("kernel32", "kernel32.dll"),
    ("MSCTF", "MSCTF.dll"),
    ("MSVCRT", "MSVCRT.dll"),
    ("NORMALIZ", "NORMALIZ.dll"),
    ("NSI", "NSI.dll"),
    ("ole32", "ole32.dll"),
    ("OLEAUT32", "OLEAUT32.dll"),
    ("PSAPI", "PSAPI.DLL"),
    ("rpcrt4", "rpcrt4.dll"),
    ("sechost", "sechost.dll"),
    ("Setupapi", "Setupapi.dll"),
    ("SHCORE", "SHCORE.dll"),
    ("SHELL32", "SHELL32.dll"),
    ("SHLWAPI", "SHLWAPI.dll"),
    ("user32", "user32.dll"),
    ("WLDAP32", "WLDAP32.dll"),
    ("wow64", "wow64.dll"),
    ("wow64win", "wow64win.dll"),
    ("WS2_32", "WS2_32.dll"),
];

/// `DOS Devices`: os links que o smss cria no diretório global
/// (SmpInitializeDosDevices 0xba80, um link permanente por valor, 0xbb7c);
/// sem o smss, a fase 0 cria os mesmos.
pub const DOS_DEVICES: &[(&str, &str)] = &[
    ("AUX", "\\DosDevices\\COM1"),
    ("CON", "\\Device\\ConDrv\\Console"),
    ("CONIN$", "\\Device\\ConDrv\\CurrentIn"),
    ("CONOUT$", "\\Device\\ConDrv\\CurrentOut"),
    ("MAILSLOT", "\\Device\\MailSlot"),
    ("NUL", "\\Device\\Null"),
    ("PIPE", "\\Device\\NamedPipe"),
    ("PRN", "\\DosDevices\\LPT1"),
    ("Silos", "\\Silos"),
    ("UNC", "\\Device\\Mup"),
];

/// `Environment`: o ambiente do sistema, sem os caminhos de terceiros.
const ENVIRONMENT: &[(&str, Value)] = &[
    ("ComSpec", Value::Text(REG_EXPAND_SZ, "%SystemRoot%\\system32\\cmd.exe")),
    ("DriverData", Value::Text(REG_SZ, "C:\\Windows\\System32\\Drivers\\DriverData")),
    ("OS", Value::Text(REG_SZ, "Windows_NT")),
    ("Path", Value::Text(REG_EXPAND_SZ, "%SystemRoot%\\system32;%SystemRoot%;%SystemRoot%\\System32\\Wbem;%SYSTEMROOT%\\System32\\WindowsPowerShell\\v1.0\\;%SYSTEMROOT%\\System32\\OpenSSH\\")),
    ("PATHEXT", Value::Text(REG_SZ, ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC")),
    ("PSModulePath", Value::Text(REG_EXPAND_SZ, "%ProgramFiles%\\WindowsPowerShell\\Modules;%SystemRoot%\\system32\\WindowsPowerShell\\v1.0\\Modules")),
    ("TEMP", Value::Text(REG_EXPAND_SZ, "%SystemRoot%\\TEMP")),
    ("TMP", Value::Text(REG_EXPAND_SZ, "%SystemRoot%\\TEMP")),
    ("USERNAME", Value::Text(REG_SZ, "SYSTEM")),
    ("windir", Value::Text(REG_EXPAND_SZ, "%SystemRoot%")),
];

/// `Memory Management`. O `PagingFiles` segue o formato da instalação
/// (`caminho mínimo máximo`, em MB), com o arquivo de paginação no volume de
/// dados D:, que o smss cria pelo NtCreatePagingFile.
const MEMORY_MANAGEMENT: &[(&str, Value)] = &[
    ("PagingFiles", Value::Strings(&["D:\\pagefile.sys 192 256"])),
    ("ClearPageFileAtShutdown", Value::Number(0)),
    ("DisablePagingExecutive", Value::Number(0)),
    ("LargeSystemCache", Value::Number(0)),
    ("NonPagedPoolQuota", Value::Number(0)),
    ("NonPagedPoolSize", Value::Number(0)),
    ("PagedPoolQuota", Value::Number(0)),
    ("PagedPoolSize", Value::Number(0)),
    ("SecondLevelDataCache", Value::Number(0)),
    ("SessionPoolSize", Value::Number(0x4)),
    ("SessionViewSize", Value::Number(0x30)),
    ("SystemPages", Value::Number(0)),
    ("PhysicalAddressExtension", Value::Number(0x1)),
    ("FeatureSettings", Value::Number(0)),
];

/// `Control\CrashControl` da instalação: o SmpPagefileInitialize abre a
/// chave antes de criar os arquivos de paginação.
const CRASH_CONTROL: &[(&str, Value)] = &[
    ("AutoReboot", Value::Number(0x1)),
    ("CrashDumpEnabled", Value::Number(0x7)),
    ("DumpFile", Value::Text(REG_EXPAND_SZ, "%SystemRoot%\\MEMORY.DMP")),
    ("DumpLogLevel", Value::Number(0)),
    ("EnableLogFile", Value::Number(0x1)),
    ("LogEvent", Value::Number(0x1)),
    ("MinidumpDir", Value::Text(REG_EXPAND_SZ, "%SystemRoot%\\Minidump")),
    ("MinidumpsCount", Value::Number(0x5)),
    ("Overwrite", Value::Number(0x1)),
    ("DumpFilters", Value::Strings(&["dumpfve.sys"])),
];

/// UTF-16LE com NUL.
fn wide_z(text: &str) -> Vec<u8> {
    text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
}

fn encode(value: &Value) -> (u32, Vec<u8>) {
    match value {
        Value::Text(kind, text) => (*kind, wide_z(text)),
        Value::Number(number) => (REG_DWORD, number.to_le_bytes().to_vec()),
        Value::Strings(strings) => {
            let mut data: Vec<u8> = strings.iter().flat_map(|text| wide_z(text)).collect();
            data.extend_from_slice(&[0, 0]);
            (REG_MULTI_SZ, data)
        }
    }
}

fn key(relative: &str, values: &[(&str, Value)]) -> SeedKey {
    let path = if relative.is_empty() { alloc::string::String::from(SESSION_MANAGER) } else { alloc::format!("{SESSION_MANAGER}\\{relative}") };
    let mut key = SeedKey::new(&path);
    for (name, value) in values {
        let (kind, data) = encode(value);
        key.value(name, kind, data);
    }
    key
}

/// As chaves do Session Manager que o smss.exe real lê.
pub fn seed_keys() -> Vec<SeedKey> {
    let known: Vec<(&str, Value)> = KNOWN_DLLS.iter().map(|&(name, dll)| (name, Value::Text(REG_SZ, dll))).collect();
    let devices: Vec<(&str, Value)> = DOS_DEVICES.iter().map(|&(name, target)| (name, Value::Text(REG_SZ, target))).collect();
    let mut crash_control = SeedKey::new("CurrentControlSet\\Control\\CrashControl");
    for (name, value) in CRASH_CONTROL {
        let (kind, data) = encode(value);
        crash_control.value(name, kind, data);
    }
    alloc::vec![key("", ROOT), key("SubSystems", SUBSYSTEMS), key("KnownDLLs", &known), key("DOS Devices", &devices), key("Environment", ENVIRONMENT), key("Memory Management", MEMORY_MANAGEMENT), crash_control]
}
