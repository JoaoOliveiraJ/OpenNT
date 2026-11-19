//! Os protótipos das APIs comuns do kernel, da ntdll e do Win32 para os
//! comentários automáticos das chamadas: o nome e o tipo de cada
//! argumento, e como mostrar o valor (texto apontado, UNICODE_STRING,
//! OBJECT_ATTRIBUTES, tag de pool, símbolo).
//!
//! As estruturas apontadas (UNICODE_STRING, ANSI_STRING,
//! OBJECT_ATTRIBUTES) usam os deslocamentos do PDB do ntoskrnl quando os
//! tipos estão carregados (`Layouts::from_types`) e os do x64 público
//! senão.

use super::args::{value_text, Value};
use crate::types::TypeDb;

/// Como mostrar um argumento.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Inteiro, tamanho, flags, máscara de acesso.
    Integer,
    Handle,
    Pointer,
    /// Endereço de código (o símbolo).
    Code,
    /// `PCSTR`: texto ASCII apontado.
    AnsiText,
    /// `PCWSTR`: texto UTF-16 apontado.
    WideText,
    /// `PUNICODE_STRING`.
    UnicodeString,
    /// `PANSI_STRING`/`PSTRING`.
    AnsiString,
    /// `POBJECT_ATTRIBUTES` (o ObjectName).
    ObjectAttributes,
    /// Tag de pool (quatro caracteres).
    Tag,
    Boolean,
    Status,
}

/// Um protótipo: o nome e os argumentos (nome, tipo).
#[derive(Clone, Copy, Debug)]
pub struct Prototype {
    pub name: &'static str,
    pub arguments: &'static [(&'static str, Kind)],
}

use Kind::*;

macro_rules! prototypes {
    ($($name:literal => [$($argument:literal : $kind:ident),* $(,)?]),* $(,)?) => {
        &[$(Prototype { name: $name, arguments: &[$(($argument, $kind)),*] }),*]
    };
}

/// A tabela (nomes sem o prefixo do módulo; `Zw` e `Nt` dividem a
/// entrada).
pub const TABLE: &[Prototype] = prototypes! {
    // ---- kernel ----
    "IoCreateDevice" => ["DriverObject": Pointer, "DeviceExtensionSize": Integer, "DeviceName": UnicodeString, "DeviceType": Integer, "DeviceCharacteristics": Integer, "Exclusive": Boolean, "DeviceObject": Pointer],
    "IoCreateSymbolicLink" => ["SymbolicLinkName": UnicodeString, "DeviceName": UnicodeString],
    "IoDeleteSymbolicLink" => ["SymbolicLinkName": UnicodeString],
    "IoDeleteDevice" => ["DeviceObject": Pointer],
    "IofCompleteRequest" => ["Irp": Pointer, "PriorityBoost": Integer],
    "IofCallDriver" => ["DeviceObject": Pointer, "Irp": Pointer],
    "IoAttachDeviceToDeviceStack" => ["SourceDevice": Pointer, "TargetDevice": Pointer],
    "IoGetDeviceObjectPointer" => ["ObjectName": UnicodeString, "DesiredAccess": Integer, "FileObject": Pointer, "DeviceObject": Pointer],
    "IoRegisterDeviceInterface" => ["PhysicalDeviceObject": Pointer, "InterfaceClassGuid": Pointer, "ReferenceString": UnicodeString, "SymbolicLinkName": Pointer],
    "IoAllocateIrp" => ["StackSize": Integer, "ChargeQuota": Boolean],
    "IoBuildDeviceIoControlRequest" => ["IoControlCode": Integer, "DeviceObject": Pointer, "InputBuffer": Pointer, "InputBufferLength": Integer, "OutputBuffer": Pointer, "OutputBufferLength": Integer, "InternalDeviceIoControl": Boolean, "Event": Pointer, "IoStatusBlock": Pointer],
    "IoCreateDriver" => ["DriverName": UnicodeString, "InitializationFunction": Code],
    "ExAllocatePoolWithTag" => ["PoolType": Integer, "NumberOfBytes": Integer, "Tag": Tag],
    "ExAllocatePool2" => ["Flags": Integer, "NumberOfBytes": Integer, "Tag": Tag],
    "ExAllocatePool" => ["PoolType": Integer, "NumberOfBytes": Integer],
    "ExFreePoolWithTag" => ["P": Pointer, "Tag": Tag],
    "ExFreePool" => ["P": Pointer],
    "ExInitializeNPagedLookasideList" => ["Lookaside": Pointer, "Allocate": Code, "Free": Code, "Flags": Integer, "Size": Integer, "Tag": Tag, "Depth": Integer],
    "RtlInitUnicodeString" => ["DestinationString": Pointer, "SourceString": WideText],
    "RtlInitAnsiString" => ["DestinationString": Pointer, "SourceString": AnsiText],
    "RtlInitString" => ["DestinationString": Pointer, "SourceString": AnsiText],
    "RtlCopyUnicodeString" => ["DestinationString": Pointer, "SourceString": UnicodeString],
    "RtlCompareUnicodeString" => ["String1": UnicodeString, "String2": UnicodeString, "CaseInSensitive": Boolean],
    "RtlEqualUnicodeString" => ["String1": UnicodeString, "String2": UnicodeString, "CaseInSensitive": Boolean],
    "RtlAppendUnicodeToString" => ["Destination": UnicodeString, "Source": WideText],
    "RtlAnsiStringToUnicodeString" => ["DestinationString": Pointer, "SourceString": AnsiString, "AllocateDestinationString": Boolean],
    "RtlUnicodeStringToAnsiString" => ["DestinationString": Pointer, "SourceString": UnicodeString, "AllocateDestinationString": Boolean],
    "RtlQueryRegistryValues" => ["RelativeTo": Integer, "Path": WideText, "QueryTable": Pointer, "Context": Pointer, "Environment": Pointer],
    "RtlGetVersion" => ["lpVersionInformation": Pointer],
    "MmGetSystemRoutineAddress" => ["SystemRoutineName": UnicodeString],
    "MmMapIoSpace" => ["PhysicalAddress": Integer, "NumberOfBytes": Integer, "CacheType": Integer],
    "MmUnmapIoSpace" => ["BaseAddress": Pointer, "NumberOfBytes": Integer],
    "KeWaitForSingleObject" => ["Object": Pointer, "WaitReason": Integer, "WaitMode": Integer, "Alertable": Boolean, "Timeout": Pointer],
    "KeWaitForMultipleObjects" => ["Count": Integer, "Object": Pointer, "WaitType": Integer, "WaitReason": Integer, "WaitMode": Integer, "Alertable": Boolean, "Timeout": Pointer, "WaitBlockArray": Pointer],
    "KeInitializeEvent" => ["Event": Pointer, "Type": Integer, "State": Boolean],
    "KeSetEvent" => ["Event": Pointer, "Increment": Integer, "Wait": Boolean],
    "KeClearEvent" => ["Event": Pointer],
    "KeInitializeDpc" => ["Dpc": Pointer, "DeferredRoutine": Code, "DeferredContext": Pointer],
    "KeInsertQueueDpc" => ["Dpc": Pointer, "SystemArgument1": Pointer, "SystemArgument2": Pointer],
    "KeSetTimer" => ["Timer": Pointer, "DueTime": Integer, "Dpc": Pointer],
    "KeDelayExecutionThread" => ["WaitMode": Integer, "Alertable": Boolean, "Interval": Pointer],
    "KeAcquireSpinLockRaiseToDpc" => ["SpinLock": Pointer],
    "KeReleaseSpinLock" => ["SpinLock": Pointer, "NewIrql": Integer],
    "KeBugCheckEx" => ["BugCheckCode": Integer, "BugCheckParameter1": Integer, "BugCheckParameter2": Integer, "BugCheckParameter3": Integer, "BugCheckParameter4": Integer],
    "KeStackAttachProcess" => ["Process": Pointer, "ApcState": Pointer],
    "ObReferenceObjectByHandle" => ["Handle": Handle, "DesiredAccess": Integer, "ObjectType": Pointer, "AccessMode": Integer, "Object": Pointer, "HandleInformation": Pointer],
    "ObReferenceObjectByName" => ["ObjectName": UnicodeString, "Attributes": Integer, "AccessState": Pointer, "DesiredAccess": Integer, "ObjectType": Pointer, "AccessMode": Integer, "ParseContext": Pointer, "Object": Pointer],
    "ObfDereferenceObject" => ["Object": Pointer],
    "ObfReferenceObject" => ["Object": Pointer],
    "ObRegisterCallbacks" => ["CallbackRegistration": Pointer, "RegistrationHandle": Pointer],
    "PsCreateSystemThread" => ["ThreadHandle": Pointer, "DesiredAccess": Integer, "ObjectAttributes": ObjectAttributes, "ProcessHandle": Handle, "ClientId": Pointer, "StartRoutine": Code, "StartContext": Pointer],
    "PsSetCreateProcessNotifyRoutine" => ["NotifyRoutine": Code, "Remove": Boolean],
    "PsSetCreateProcessNotifyRoutineEx" => ["NotifyRoutine": Code, "Remove": Boolean],
    "PsSetCreateThreadNotifyRoutine" => ["NotifyRoutine": Code],
    "PsSetLoadImageNotifyRoutine" => ["NotifyRoutine": Code],
    "PsLookupProcessByProcessId" => ["ProcessId": Handle, "Process": Pointer],
    "PsLookupThreadByThreadId" => ["ThreadId": Handle, "Thread": Pointer],
    "CmRegisterCallbackEx" => ["Function": Code, "Altitude": UnicodeString, "Driver": Pointer, "Context": Pointer, "Cookie": Pointer, "Reserved": Pointer],
    "DbgPrint" => ["Format": AnsiText],
    "DbgPrintEx" => ["ComponentId": Integer, "Level": Integer, "Format": AnsiText],
    "vDbgPrintExWithPrefix" => ["Prefix": AnsiText, "ComponentId": Integer, "Level": Integer, "Format": AnsiText],
    // ---- serviços (Nt e Zw) ----
    "NtCreateFile" => ["FileHandle": Pointer, "DesiredAccess": Integer, "ObjectAttributes": ObjectAttributes, "IoStatusBlock": Pointer, "AllocationSize": Pointer, "FileAttributes": Integer, "ShareAccess": Integer, "CreateDisposition": Integer, "CreateOptions": Integer, "EaBuffer": Pointer, "EaLength": Integer],
    "NtOpenFile" => ["FileHandle": Pointer, "DesiredAccess": Integer, "ObjectAttributes": ObjectAttributes, "IoStatusBlock": Pointer, "ShareAccess": Integer, "OpenOptions": Integer],
    "NtReadFile" => ["FileHandle": Handle, "Event": Handle, "ApcRoutine": Code, "ApcContext": Pointer, "IoStatusBlock": Pointer, "Buffer": Pointer, "Length": Integer, "ByteOffset": Pointer, "Key": Pointer],
    "NtWriteFile" => ["FileHandle": Handle, "Event": Handle, "ApcRoutine": Code, "ApcContext": Pointer, "IoStatusBlock": Pointer, "Buffer": Pointer, "Length": Integer, "ByteOffset": Pointer, "Key": Pointer],
    "NtDeviceIoControlFile" => ["FileHandle": Handle, "Event": Handle, "ApcRoutine": Code, "ApcContext": Pointer, "IoStatusBlock": Pointer, "IoControlCode": Integer, "InputBuffer": Pointer, "InputBufferLength": Integer, "OutputBuffer": Pointer, "OutputBufferLength": Integer],
    "NtFsControlFile" => ["FileHandle": Handle, "Event": Handle, "ApcRoutine": Code, "ApcContext": Pointer, "IoStatusBlock": Pointer, "FsControlCode": Integer, "InputBuffer": Pointer, "InputBufferLength": Integer, "OutputBuffer": Pointer, "OutputBufferLength": Integer],
    "NtQueryInformationFile" => ["FileHandle": Handle, "IoStatusBlock": Pointer, "FileInformation": Pointer, "Length": Integer, "FileInformationClass": Integer],
    "NtClose" => ["Handle": Handle],
    "NtOpenKey" => ["KeyHandle": Pointer, "DesiredAccess": Integer, "ObjectAttributes": ObjectAttributes],
    "NtOpenKeyEx" => ["KeyHandle": Pointer, "DesiredAccess": Integer, "ObjectAttributes": ObjectAttributes, "OpenOptions": Integer],
    "NtCreateKey" => ["KeyHandle": Pointer, "DesiredAccess": Integer, "ObjectAttributes": ObjectAttributes, "TitleIndex": Integer, "Class": UnicodeString, "CreateOptions": Integer, "Disposition": Pointer],
    "NtQueryValueKey" => ["KeyHandle": Handle, "ValueName": UnicodeString, "KeyValueInformationClass": Integer, "KeyValueInformation": Pointer, "Length": Integer, "ResultLength": Pointer],
    "NtSetValueKey" => ["KeyHandle": Handle, "ValueName": UnicodeString, "TitleIndex": Integer, "Type": Integer, "Data": Pointer, "DataSize": Integer],
    "NtEnumerateKey" => ["KeyHandle": Handle, "Index": Integer, "KeyInformationClass": Integer, "KeyInformation": Pointer, "Length": Integer, "ResultLength": Pointer],
    "NtAllocateVirtualMemory" => ["ProcessHandle": Handle, "BaseAddress": Pointer, "ZeroBits": Integer, "RegionSize": Pointer, "AllocationType": Integer, "Protect": Integer],
    "NtFreeVirtualMemory" => ["ProcessHandle": Handle, "BaseAddress": Pointer, "RegionSize": Pointer, "FreeType": Integer],
    "NtProtectVirtualMemory" => ["ProcessHandle": Handle, "BaseAddress": Pointer, "RegionSize": Pointer, "NewProtect": Integer, "OldProtect": Pointer],
    "NtQueryVirtualMemory" => ["ProcessHandle": Handle, "BaseAddress": Pointer, "MemoryInformationClass": Integer, "MemoryInformation": Pointer, "MemoryInformationLength": Integer, "ReturnLength": Pointer],
    "NtCreateSection" => ["SectionHandle": Pointer, "DesiredAccess": Integer, "ObjectAttributes": ObjectAttributes, "MaximumSize": Pointer, "SectionPageProtection": Integer, "AllocationAttributes": Integer, "FileHandle": Handle],
    "NtMapViewOfSection" => ["SectionHandle": Handle, "ProcessHandle": Handle, "BaseAddress": Pointer, "ZeroBits": Integer, "CommitSize": Integer, "SectionOffset": Pointer, "ViewSize": Pointer, "InheritDisposition": Integer, "AllocationType": Integer, "Win32Protect": Integer],
    "NtUnmapViewOfSection" => ["ProcessHandle": Handle, "BaseAddress": Pointer],
    "NtCreateEvent" => ["EventHandle": Pointer, "DesiredAccess": Integer, "ObjectAttributes": ObjectAttributes, "EventType": Integer, "InitialState": Boolean],
    "NtSetEvent" => ["EventHandle": Handle, "PreviousState": Pointer],
    "NtWaitForSingleObject" => ["Handle": Handle, "Alertable": Boolean, "Timeout": Pointer],
    "NtWaitForMultipleObjects" => ["Count": Integer, "Handles": Pointer, "WaitType": Integer, "Alertable": Boolean, "Timeout": Pointer],
    "NtQuerySystemInformation" => ["SystemInformationClass": Integer, "SystemInformation": Pointer, "SystemInformationLength": Integer, "ReturnLength": Pointer],
    "NtQueryInformationProcess" => ["ProcessHandle": Handle, "ProcessInformationClass": Integer, "ProcessInformation": Pointer, "ProcessInformationLength": Integer, "ReturnLength": Pointer],
    "NtSetInformationProcess" => ["ProcessHandle": Handle, "ProcessInformationClass": Integer, "ProcessInformation": Pointer, "ProcessInformationLength": Integer],
    "NtQueryInformationThread" => ["ThreadHandle": Handle, "ThreadInformationClass": Integer, "ThreadInformation": Pointer, "ThreadInformationLength": Integer, "ReturnLength": Pointer],
    "NtSetInformationThread" => ["ThreadHandle": Handle, "ThreadInformationClass": Integer, "ThreadInformation": Pointer, "ThreadInformationLength": Integer],
    "NtOpenProcess" => ["ProcessHandle": Pointer, "DesiredAccess": Integer, "ObjectAttributes": ObjectAttributes, "ClientId": Pointer],
    "NtTerminateProcess" => ["ProcessHandle": Handle, "ExitStatus": Status],
    "NtTerminateThread" => ["ThreadHandle": Handle, "ExitStatus": Status],
    "NtCreateThreadEx" => ["ThreadHandle": Pointer, "DesiredAccess": Integer, "ObjectAttributes": ObjectAttributes, "ProcessHandle": Handle, "StartRoutine": Code, "Argument": Pointer, "CreateFlags": Integer, "ZeroBits": Integer, "StackSize": Integer, "MaximumStackSize": Integer, "AttributeList": Pointer],
    "NtCreateUserProcess" => ["ProcessHandle": Pointer, "ThreadHandle": Pointer, "ProcessDesiredAccess": Integer, "ThreadDesiredAccess": Integer, "ProcessObjectAttributes": ObjectAttributes, "ThreadObjectAttributes": ObjectAttributes, "ProcessFlags": Integer, "ThreadFlags": Integer, "ProcessParameters": Pointer, "CreateInfo": Pointer, "AttributeList": Pointer],
    "NtOpenDirectoryObject" => ["DirectoryHandle": Pointer, "DesiredAccess": Integer, "ObjectAttributes": ObjectAttributes],
    "NtCreateDirectoryObject" => ["DirectoryHandle": Pointer, "DesiredAccess": Integer, "ObjectAttributes": ObjectAttributes],
    "NtOpenSymbolicLinkObject" => ["LinkHandle": Pointer, "DesiredAccess": Integer, "ObjectAttributes": ObjectAttributes],
    "NtCreatePort" => ["PortHandle": Pointer, "ObjectAttributes": ObjectAttributes, "MaxConnectionInfoLength": Integer, "MaxMessageLength": Integer, "MaxPoolUsage": Integer],
    "NtAlpcCreatePort" => ["PortHandle": Pointer, "ObjectAttributes": ObjectAttributes, "PortAttributes": Pointer],
    "NtAlpcConnectPort" => ["PortHandle": Pointer, "PortName": UnicodeString, "ObjectAttributes": ObjectAttributes, "PortAttributes": Pointer, "Flags": Integer, "RequiredServerSid": Pointer, "ConnectionMessage": Pointer, "BufferLength": Pointer, "OutMessageAttributes": Pointer, "InMessageAttributes": Pointer, "Timeout": Pointer],
    "NtRaiseHardError" => ["ErrorStatus": Status, "NumberOfParameters": Integer, "UnicodeStringParameterMask": Integer, "Parameters": Pointer, "ValidResponseOptions": Integer, "Response": Pointer],
    // ---- ntdll ----
    "LdrLoadDll" => ["DllPath": WideText, "DllCharacteristics": Pointer, "DllName": UnicodeString, "DllHandle": Pointer],
    "LdrGetDllHandle" => ["DllPath": WideText, "DllCharacteristics": Pointer, "DllName": UnicodeString, "DllHandle": Pointer],
    "LdrGetProcedureAddress" => ["DllHandle": Pointer, "ProcedureName": AnsiString, "ProcedureNumber": Integer, "ProcedureAddress": Pointer],
    "LdrUnloadDll" => ["DllHandle": Pointer],
    "RtlAllocateHeap" => ["HeapHandle": Pointer, "Flags": Integer, "Size": Integer],
    "RtlFreeHeap" => ["HeapHandle": Pointer, "Flags": Integer, "BaseAddress": Pointer],
    "RtlReAllocateHeap" => ["HeapHandle": Pointer, "Flags": Integer, "BaseAddress": Pointer, "Size": Integer],
    "RtlCreateHeap" => ["Flags": Integer, "HeapBase": Pointer, "ReserveSize": Integer, "CommitSize": Integer, "Lock": Pointer, "Parameters": Pointer],
    "RtlEnterCriticalSection" => ["CriticalSection": Pointer],
    "RtlLeaveCriticalSection" => ["CriticalSection": Pointer],
    "RtlInitializeCriticalSection" => ["CriticalSection": Pointer],
    "RtlDosPathNameToNtPathName_U" => ["DosFileName": WideText, "NtFileName": Pointer, "FilePart": Pointer, "RelativeName": Pointer],
    "RtlCreateUserThread" => ["Process": Handle, "ThreadSecurityDescriptor": Pointer, "CreateSuspended": Boolean, "ZeroBits": Integer, "MaximumStackSize": Integer, "CommittedStackSize": Integer, "StartAddress": Code, "Parameter": Pointer, "Thread": Pointer, "ClientId": Pointer],
    "RtlRaiseStatus" => ["Status": Status],
    "CsrClientConnectToServer" => ["ObjectDirectory": WideText, "ServerId": Integer, "ConnectionInformation": Pointer, "ConnectionInformationLength": Pointer, "CalledFromServer": Pointer],
    "CsrServerInitialization" => ["ArgumentCount": Integer, "Arguments": Pointer],
    "CsrLoadServerDll" => ["ModuleName": AnsiText, "InitRoutine": AnsiText, "ServerId": Integer],
    // ---- Win32 ----
    "CreateFileW" => ["lpFileName": WideText, "dwDesiredAccess": Integer, "dwShareMode": Integer, "lpSecurityAttributes": Pointer, "dwCreationDisposition": Integer, "dwFlagsAndAttributes": Integer, "hTemplateFile": Handle],
    "CreateFileA" => ["lpFileName": AnsiText, "dwDesiredAccess": Integer, "dwShareMode": Integer, "lpSecurityAttributes": Pointer, "dwCreationDisposition": Integer, "dwFlagsAndAttributes": Integer, "hTemplateFile": Handle],
    "ReadFile" => ["hFile": Handle, "lpBuffer": Pointer, "nNumberOfBytesToRead": Integer, "lpNumberOfBytesRead": Pointer, "lpOverlapped": Pointer],
    "WriteFile" => ["hFile": Handle, "lpBuffer": Pointer, "nNumberOfBytesToWrite": Integer, "lpNumberOfBytesWritten": Pointer, "lpOverlapped": Pointer],
    "DeviceIoControl" => ["hDevice": Handle, "dwIoControlCode": Integer, "lpInBuffer": Pointer, "nInBufferSize": Integer, "lpOutBuffer": Pointer, "nOutBufferSize": Integer, "lpBytesReturned": Pointer, "lpOverlapped": Pointer],
    "CloseHandle" => ["hObject": Handle],
    "LoadLibraryW" => ["lpLibFileName": WideText],
    "LoadLibraryA" => ["lpLibFileName": AnsiText],
    "LoadLibraryExW" => ["lpLibFileName": WideText, "hFile": Handle, "dwFlags": Integer],
    "LoadLibraryExA" => ["lpLibFileName": AnsiText, "hFile": Handle, "dwFlags": Integer],
    "GetModuleHandleW" => ["lpModuleName": WideText],
    "GetModuleHandleA" => ["lpModuleName": AnsiText],
    "GetProcAddress" => ["hModule": Pointer, "lpProcName": AnsiText],
    "FreeLibrary" => ["hLibModule": Pointer],
    "VirtualAlloc" => ["lpAddress": Pointer, "dwSize": Integer, "flAllocationType": Integer, "flProtect": Integer],
    "VirtualFree" => ["lpAddress": Pointer, "dwSize": Integer, "dwFreeType": Integer],
    "VirtualProtect" => ["lpAddress": Pointer, "dwSize": Integer, "flNewProtect": Integer, "lpflOldProtect": Pointer],
    "HeapAlloc" => ["hHeap": Pointer, "dwFlags": Integer, "dwBytes": Integer],
    "HeapFree" => ["hHeap": Pointer, "dwFlags": Integer, "lpMem": Pointer],
    "CreateProcessW" => ["lpApplicationName": WideText, "lpCommandLine": WideText, "lpProcessAttributes": Pointer, "lpThreadAttributes": Pointer, "bInheritHandles": Boolean, "dwCreationFlags": Integer, "lpEnvironment": Pointer, "lpCurrentDirectory": WideText, "lpStartupInfo": Pointer, "lpProcessInformation": Pointer],
    "CreateProcessA" => ["lpApplicationName": AnsiText, "lpCommandLine": AnsiText, "lpProcessAttributes": Pointer, "lpThreadAttributes": Pointer, "bInheritHandles": Boolean, "dwCreationFlags": Integer, "lpEnvironment": Pointer, "lpCurrentDirectory": AnsiText, "lpStartupInfo": Pointer, "lpProcessInformation": Pointer],
    "CreateThread" => ["lpThreadAttributes": Pointer, "dwStackSize": Integer, "lpStartAddress": Code, "lpParameter": Pointer, "dwCreationFlags": Integer, "lpThreadId": Pointer],
    "CreateEventW" => ["lpEventAttributes": Pointer, "bManualReset": Boolean, "bInitialState": Boolean, "lpName": WideText],
    "CreateMutexW" => ["lpMutexAttributes": Pointer, "bInitialOwner": Boolean, "lpName": WideText],
    "OpenProcess" => ["dwDesiredAccess": Integer, "bInheritHandle": Boolean, "dwProcessId": Integer],
    "WaitForSingleObject" => ["hHandle": Handle, "dwMilliseconds": Integer],
    "WaitForSingleObjectEx" => ["hHandle": Handle, "dwMilliseconds": Integer, "bAlertable": Boolean],
    "Sleep" => ["dwMilliseconds": Integer],
    "SetLastError" => ["dwErrCode": Integer],
    "ExitProcess" => ["uExitCode": Integer],
    "TerminateProcess" => ["hProcess": Handle, "uExitCode": Integer],
    "OutputDebugStringW" => ["lpOutputString": WideText],
    "OutputDebugStringA" => ["lpOutputString": AnsiText],
    "MessageBoxW" => ["hWnd": Handle, "lpText": WideText, "lpCaption": WideText, "uType": Integer],
    "MessageBoxA" => ["hWnd": Handle, "lpText": AnsiText, "lpCaption": AnsiText, "uType": Integer],
    "RegOpenKeyExW" => ["hKey": Handle, "lpSubKey": WideText, "ulOptions": Integer, "samDesired": Integer, "phkResult": Pointer],
    "RegQueryValueExW" => ["hKey": Handle, "lpValueName": WideText, "lpReserved": Pointer, "lpType": Pointer, "lpData": Pointer, "lpcbData": Pointer],
    "RegSetValueExW" => ["hKey": Handle, "lpValueName": WideText, "Reserved": Integer, "dwType": Integer, "lpData": Pointer, "cbData": Integer],
    "RegCloseKey" => ["hKey": Handle],
    "lstrcmpiW" => ["lpString1": WideText, "lpString2": WideText],
    "lstrlenW" => ["lpString": WideText],
    "wcslen" => ["String": WideText],
    "strlen" => ["String": AnsiText],
    "wcscmp" => ["String1": WideText, "String2": WideText],
    "_wcsicmp" => ["String1": WideText, "String2": WideText],
    "strcmp" => ["String1": AnsiText, "String2": AnsiText],
    "memcpy" => ["Destination": Pointer, "Source": Pointer, "Count": Integer],
    "memset" => ["Destination": Pointer, "Value": Integer, "Count": Integer],
    "swprintf_s" => ["Buffer": Pointer, "SizeOfBuffer": Integer, "Format": WideText],
    "sprintf_s" => ["Buffer": Pointer, "SizeOfBuffer": Integer, "Format": AnsiText],
};

/// O nome base de um símbolo: sem o módulo (`ntdll!`), sem `__imp_`, sem
/// o deslocamento (`+0x10`) e com `Zw` trocado por `Nt`.
pub fn base_name(symbol: &str) -> String {
    let name = symbol.rsplit('!').next().unwrap_or(symbol);
    let name = name.split('+').next().unwrap_or(name).trim();
    let name = name.strip_prefix("__imp_").unwrap_or(name);
    // `kernel::...::IoCreateDevice` (as rotinas do OpenNT com o nome do NT).
    let name = name.rsplit("::").next().unwrap_or(name);
    match name.strip_prefix("Zw") {
        Some(rest) => format!("Nt{rest}"),
        None => name.to_string(),
    }
}

/// O protótipo de um símbolo (pelo nome base).
pub fn find(symbol: &str) -> Option<&'static Prototype> {
    let name = base_name(symbol);
    TABLE.iter().find(|prototype| prototype.name == name)
}

/// Os deslocamentos das estruturas apontadas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layouts {
    /// UNICODE_STRING/STRING: Length (u16) e Buffer (ponteiro).
    pub string_length: u64,
    pub string_buffer: u64,
    /// OBJECT_ATTRIBUTES.ObjectName.
    pub object_name: u64,
}

impl Default for Layouts {
    fn default() -> Self {
        Layouts { string_length: 0, string_buffer: 8, object_name: 0x10 }
    }
}

impl Layouts {
    /// Os deslocamentos pelo PDB (os campos que existirem).
    pub fn from_types(types: &TypeDb) -> Layouts {
        let mut layouts = Layouts::default();
        if let Some(offset) = types.field_offset("_UNICODE_STRING", "Buffer") {
            layouts.string_buffer = offset;
        }
        if let Some(offset) = types.field_offset("_UNICODE_STRING", "Length") {
            layouts.string_length = offset;
        }
        if let Some(offset) = types.field_offset("_OBJECT_ATTRIBUTES", "ObjectName") {
            layouts.object_name = offset;
        }
        layouts
    }
}

/// Até onde um texto apontado é lido.
const TEXT_LIMIT: usize = 96;

/// Texto curto com aspas (cortado em `TEXT_LIMIT`).
fn quoted(prefix: &str, text: &str) -> String {
    let mut shown: String = text.chars().take(TEXT_LIMIT).map(|character| if character.is_control() { '.' } else { character }).collect();
    if text.chars().count() > TEXT_LIMIT {
        shown.push('…');
    }
    format!("{prefix}\"{shown}\"")
}

fn read_wide(memory: &mut dyn FnMut(u64, usize) -> Option<Vec<u8>>, address: u64, bytes: usize) -> Option<String> {
    let data = memory(address, bytes)?;
    let units: Vec<u16> = data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
    Some(String::from_utf16_lossy(&units))
}

fn read_ansi(memory: &mut dyn FnMut(u64, usize) -> Option<Vec<u8>>, address: u64, bytes: usize) -> Option<String> {
    let data = memory(address, bytes)?;
    let end = data.iter().position(|&byte| byte == 0).unwrap_or(data.len());
    Some(String::from_utf8_lossy(&data[..end]).into_owned())
}

fn read_u64(memory: &mut dyn FnMut(u64, usize) -> Option<Vec<u8>>, address: u64) -> Option<u64> {
    let data = memory(address, 8)?;
    Some(u64::from_le_bytes(data.get(..8)?.try_into().ok()?))
}

fn counted_string(memory: &mut dyn FnMut(u64, usize) -> Option<Vec<u8>>, layouts: &Layouts, address: u64, wide: bool) -> Option<String> {
    let header = memory(address + layouts.string_length, 2)?;
    let length = u16::from_le_bytes([header[0], *header.get(1)?]) as usize;
    let buffer = read_u64(memory, address + layouts.string_buffer)?;
    if buffer == 0 || length == 0 {
        return Some(String::new());
    }
    let length = length.min(TEXT_LIMIT * 2 + 2);
    if wide {
        read_wide(memory, buffer, length)
    } else {
        read_ansi(memory, buffer, length)
    }
}

/// Um argumento em texto: o valor conhecido (constante, endereço) é
/// mostrado pelo tipo (lendo a memória apontada); o resto, pelo preparo.
/// `symbol` dá o nome de um endereço de código.
pub fn format_argument(kind: Kind, value: &Value, memory: &mut dyn FnMut(u64, usize) -> Option<Vec<u8>>, symbol: &dyn Fn(u64) -> Option<String>, layouts: &Layouts) -> String {
    let number = match value {
        Value::Constant(number) | Value::Address(number) => Some(*number),
        _ => None,
    };
    let Some(number) = number else { return value_text(value) };
    let pointer_text = || {
        if number == 0 {
            return Some("NULL".to_string());
        }
        None
    };
    match kind {
        Integer | Status => {
            if number < 10 {
                number.to_string()
            } else {
                format!("{number:#x}")
            }
        }
        Boolean => match number {
            0 => "FALSE".into(),
            1 => "TRUE".into(),
            other => format!("{other:#x}"),
        },
        Handle | Pointer => pointer_text().unwrap_or_else(|| symbol(number).map_or_else(|| format!("{number:#x}"), |name| format!("{number:#x} {name}"))),
        Code => pointer_text().unwrap_or_else(|| symbol(number).unwrap_or_else(|| format!("{number:#x}"))),
        Tag => {
            let bytes = (number as u32).to_le_bytes();
            if bytes.iter().all(|byte| byte.is_ascii_graphic() || *byte == b' ') {
                format!("'{}'", String::from_utf8_lossy(&bytes))
            } else {
                format!("{number:#x}")
            }
        }
        AnsiText => pointer_text().unwrap_or_else(|| read_ansi(memory, number, TEXT_LIMIT + 1).map_or_else(|| format!("{number:#x}"), |text| quoted("", &text))),
        WideText => pointer_text().unwrap_or_else(|| read_wide(memory, number, (TEXT_LIMIT + 1) * 2).map_or_else(|| format!("{number:#x}"), |text| quoted("L", &text))),
        UnicodeString | AnsiString => pointer_text().unwrap_or_else(|| counted_string(memory, layouts, number, kind == UnicodeString).map_or_else(|| format!("{number:#x}"), |text| quoted(if kind == UnicodeString { "L" } else { "" }, &text))),
        ObjectAttributes => pointer_text().unwrap_or_else(|| {
            let name = read_u64(memory, number + layouts.object_name).filter(|&name| name != 0).and_then(|name| counted_string(memory, layouts, name, true));
            match name {
                Some(text) => format!("{{ObjectName={}}}", quoted("L", &text)),
                None => format!("{number:#x}"),
            }
        }),
    }
}

/// O comentário de uma chamada: `Nome(arg=valor, ...)`. Os valores
/// desconhecidos aparecem como o preparo (`rsi`, `[rsp+0x50]`, `?`).
pub fn call_comment(prototype: &Prototype, values: &[Value], memory: &mut dyn FnMut(u64, usize) -> Option<Vec<u8>>, symbol: &dyn Fn(u64) -> Option<String>, layouts: &Layouts) -> String {
    let arguments: Vec<String> = prototype
        .arguments
        .iter()
        .enumerate()
        .map(|(index, (name, kind))| {
            let value = values.get(index).copied().unwrap_or(Value::Unknown);
            format!("{name}={}", format_argument(*kind, &value, memory, symbol, layouts))
        })
        .collect();
    format!("{}({})", prototype.name, arguments.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Memória de mentira: uma UNICODE_STRING em 0x1000 apontando para
    /// L"\Device\Teste" em 0x2000, um OBJECT_ATTRIBUTES em 0x3000 com o
    /// ObjectName em 0x1000 e um texto ASCII em 0x4000.
    fn memory() -> impl FnMut(u64, usize) -> Option<Vec<u8>> {
        let text: Vec<u8> = "\\Device\\Teste".encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
        let mut string = vec![0u8; 16];
        string[0..2].copy_from_slice(&(text.len() as u16).to_le_bytes());
        string[2..4].copy_from_slice(&(text.len() as u16 + 2).to_le_bytes());
        string[8..16].copy_from_slice(&0x2000u64.to_le_bytes());
        let mut attributes = vec![0u8; 0x30];
        attributes[0x10..0x18].copy_from_slice(&0x1000u64.to_le_bytes());
        let regions: Vec<(u64, Vec<u8>)> = vec![(0x1000, string), (0x2000, text), (0x3000, attributes), (0x4000, b"ola %s\n\0".to_vec())];
        move |address: u64, length: usize| {
            regions.iter().find(|(base, bytes)| address >= *base && address < base + bytes.len() as u64).map(|(base, bytes)| {
                let start = (address - base) as usize;
                bytes[start..(start + length).min(bytes.len())].to_vec()
            })
        }
    }

    #[test]
    fn finds_prototypes_by_symbol() {
        assert_eq!(find("nt!IoCreateDevice").unwrap().arguments.len(), 7);
        assert_eq!(find("ntdll!ZwClose").unwrap().name, "NtClose");
        assert_eq!(find("__imp_ExAllocatePoolWithTag").unwrap().arguments[2], ("Tag", Kind::Tag));
        assert_eq!(find("ntoskrnl!KeBugCheckEx+0x10").unwrap().arguments.len(), 5);
        assert!(find("FuncaoQueNaoExiste").is_none());
        assert_eq!(base_name("kernel::ntos::io::device::IoCreateDevice"), "IoCreateDevice");
    }

    #[test]
    fn formats_call_comments() {
        let mut memory = memory();
        let symbol = |address: u64| (address == 0x5000).then(|| "drv!DriverEntry".to_string());
        let layouts = Layouts::default();
        let prototype = find("IoCreateDevice").unwrap();
        let values = [Value::Register(3), Value::Constant(0x40), Value::Address(0x1000), Value::Constant(0x22), Value::Constant(0), Value::Constant(0), Value::Stack(0x50)];
        let text = call_comment(prototype, &values, &mut memory, &symbol, &layouts);
        assert_eq!(text, "IoCreateDevice(DriverObject=rbx, DeviceExtensionSize=0x40, DeviceName=L\"\\Device\\Teste\", DeviceType=0x22, DeviceCharacteristics=0, Exclusive=FALSE, DeviceObject=[rsp+0x50])");
        let tag = format_argument(Kind::Tag, &Value::Constant(u32::from_le_bytes(*b"Tst1") as u64), &mut memory, &symbol, &layouts);
        assert_eq!(tag, "'Tst1'");
        assert_eq!(format_argument(Kind::ObjectAttributes, &Value::Address(0x3000), &mut memory, &symbol, &layouts), "{ObjectName=L\"\\Device\\Teste\"}");
        assert_eq!(format_argument(Kind::AnsiText, &Value::Address(0x4000), &mut memory, &symbol, &layouts), "\"ola %s.\"");
        assert_eq!(format_argument(Kind::Code, &Value::Address(0x5000), &mut memory, &symbol, &layouts), "drv!DriverEntry");
        assert_eq!(format_argument(Kind::Pointer, &Value::Constant(0), &mut memory, &symbol, &layouts), "NULL");
        assert_eq!(format_argument(Kind::WideText, &Value::Address(0x9000), &mut memory, &symbol, &layouts), "0x9000");
    }
}
