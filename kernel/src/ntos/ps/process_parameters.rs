//! Parâmetros de processo (RTL_USER_PROCESS_PARAMETERS).
//!
//! O papel do RtlCreateProcessParametersEx para os processos que o kernel
//! cria: os textos do processo novo (caminho da imagem, linha de comando,
//! diretório corrente, caminho de DLLs, título, desktop, shell e dados de
//! runtime), o bloco de ambiente, os campos escalares do STARTUPINFO, o
//! console e os handles padrão, gravados num bloco do processo em montagem (o
//! corrente: a criação roda anexada a ele). [`capture`] faz o caminho inverso
//! para o NtCreateUserProcess: lê o bloco que o chamador montou na memória de
//! usuário dele, normalizado ou não, antes de a criação anexar ao processo
//! novo. [`capture_to_pool`] é o PsCaptureUserProcessParameters que o
//! condrv.sys chama: o bloco normalizado de um chamador de modo usuário
//! copiado para um pool de kernel, com Buffers absolutos.
//!
//! Formato entregue ao processo: auto-relativo, sem
//! RTL_USER_PROC_PARAMS_NORMALIZED (o Flags é só o que a criação passa:
//! RTL_USER_PROC_APP_MANIFEST_PRESENT quando achou o manifesto embutido do
//! executável, senão 0), com o Buffer de cada
//! UNICODE_STRING sendo o deslocamento desde a base do bloco; o loader da
//! ntdll normaliza na inicialização. O Environment é absoluto (a
//! normalização só converte os Buffers). Os textos ficam bem depois da
//! estrutura: a ntdll 24H2 lê campos até +0x440. Um texto ausente fica com o
//! UNICODE_STRING zerado (Buffer NULL), que a normalização preserva; o
//! MaximumLength de cada texto respeita a capacidade pedida (o diretório
//! corrente do chamador, por exemplo, vem com espaço para o
//! SetCurrentDirectory trocar o caminho no lugar).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::mem::offset_of;

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{RtlUserProcessParameters, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user::{memory, state};
use crate::rtl::KernelError;

/// HANDLE_DETACHED_PROCESS: sem console pai.
pub const DETACHED_PROCESS: u64 = u64::MAX;
/// Onde começam os textos dentro do bloco.
const STRINGS_OFFSET: u64 = 0x800;
/// Folga entre um texto e o próximo, depois do NUL.
const STRING_GAP: u64 = 8;
/// O menor bloco entregue (o MaximumLength mínimo).
const MINIMUM_BLOCK: u64 = 0x2000;
/// RTL_USER_PROC_PARAMS_NORMALIZED: os Buffers do bloco são VAs, não
/// deslocamentos desde a base.
const NORMALIZED: u32 = 1;
/// O menor bloco capturado: a estrutura até o RuntimeData inclusive.
const MINIMUM_CAPTURED: u64 = offset_of!(RtlUserProcessParameters, current_directores) as u64;
/// O maior bloco de ambiente capturado.
const ENVIRONMENT_LIMIT: u64 = 0x10_0000;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;

/// Os campos escalares que o criador passa (STARTUPINFO e afins), entregues
/// como vieram.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    pub debug_flags: u32,
    pub console_flags: u32,
    pub starting_x: u32,
    pub starting_y: u32,
    pub count_x: u32,
    pub count_y: u32,
    pub count_chars_x: u32,
    pub count_chars_y: u32,
    pub fill_attribute: u32,
    pub window_flags: u32,
    pub show_window_flags: u32,
    pub process_group_id: u32,
    pub loader_threads: u32,
}

/// O MaximumLength pedido para cada texto, em bytes (0: o comprimento mais o
/// NUL).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Capacities {
    pub image_path_name: u16,
    pub command_line: u16,
    pub current_directory: u16,
    pub dll_path: u16,
    pub window_title: u16,
    pub desktop_info: u16,
    pub shell_info: u16,
    pub runtime_data: u16,
}

/// O que o processo novo recebe nos parâmetros.
#[derive(Clone, Debug)]
pub struct ProcessParameters {
    /// Caminho da imagem (o ImagePathName; o mesmo do estado do processo).
    pub image_path_name: String,
    pub command_line: String,
    pub current_directory: String,
    pub dll_path: String,
    pub window_title: Option<String>,
    pub desktop_info: Option<String>,
    pub shell_info: Option<String>,
    /// RuntimeData: bytes opacos (o lpReserved2 do STARTUPINFO), entregues
    /// como vieram.
    pub runtime_data: Option<Vec<u8>>,
    /// As variáveis do ambiente, cada uma `NOME=valor`.
    pub environment: Vec<String>,
    /// ConsoleHandle: [`DETACHED_PROCESS`] ou um handle/pseudo-handle de
    /// console, que passa direto.
    pub console_handle: u64,
    pub standard_input: u64,
    pub standard_output: u64,
    pub standard_error: u64,
    pub settings: Settings,
    pub capacities: Capacities,
}

impl ProcessParameters {
    /// Os parâmetros padrão de uma imagem: a linha de comando é o caminho
    /// entre aspas, o diretório corrente C:\, as DLLs de System32, o ambiente
    /// mínimo do sistema, sem console pai e sem handles padrão.
    pub fn for_image(image_path: &str) -> Self {
        Self {
            image_path_name: String::from(image_path),
            command_line: format!("\"{image_path}\""),
            current_directory: String::from("C:\\"),
            dll_path: String::from("C:\\Windows\\System32"),
            window_title: None,
            desktop_info: None,
            shell_info: None,
            runtime_data: None,
            environment: ["SystemRoot=C:\\Windows", "PATH=C:\\Windows\\System32;C:\\Windows", "WINDIR=C:\\Windows"].into_iter().map(String::from).collect(),
            console_handle: DETACHED_PROCESS,
            standard_input: 0,
            standard_output: 0,
            standard_error: 0,
            settings: Settings::default(),
            capacities: Capacities::default(),
        }
    }

    /// O bloco de ambiente: as variáveis em UTF-16, cada uma com NUL, e o NUL
    /// final.
    fn environment_block(&self) -> Vec<u8> {
        let mut units: Vec<u16> = Vec::new();
        for variable in &self.environment {
            units.extend(variable.encode_utf16());
            units.push(0);
        }
        units.push(0);
        units.into_iter().flat_map(u16::to_le_bytes).collect()
    }

    /// Grava o bloco no processo corrente (o processo em montagem, anexado)
    /// e devolve a VA dele, para PEB.ProcessParameters. Length cobre a
    /// estrutura, os textos e o ambiente; MaximumLength, o bloco inteiro;
    /// Flags é `flags` (sem RTL_USER_PROC_PARAMS_NORMALIZED: o bloco é
    /// auto-relativo).
    pub fn write(&self, flags: u32) -> Result<u64, KernelError> {
        let capacities = &self.capacities;
        // Um texto vazio dos obrigatórios fica NULL, como um ausente.
        let required = |text: &str| (!text.is_empty()).then(|| wide(text));
        let strings: [(&str, Option<Vec<u8>>, u16, u64); 8] = [
            ("ImagePathName", required(&self.image_path_name), capacities.image_path_name, 2),
            ("CommandLine", required(&self.command_line), capacities.command_line, 2),
            ("DllPath", required(&self.dll_path), capacities.dll_path, 2),
            ("CurrentDirectory", required(&self.current_directory), capacities.current_directory, 2),
            ("WindowTitle", self.window_title.as_deref().map(wide), capacities.window_title, 2),
            ("DesktopInfo", self.desktop_info.as_deref().map(wide), capacities.desktop_info, 2),
            ("ShellInfo", self.shell_info.as_deref().map(wide), capacities.shell_info, 2),
            // Bytes opacos: sem NUL.
            ("RuntimeData", self.runtime_data.clone(), capacities.runtime_data, 0),
        ];
        // Os UNICODE_STRING guardam o comprimento em 16 bits.
        if let Some((name, ..)) = strings.iter().find(|(_, bytes, _, terminator)| bytes.as_ref().is_some_and(|bytes| bytes.len() as u64 + terminator > u16::MAX as u64)) {
            return Err(KernelError::with_status(format!("parametros de processo: {name} longo demais"), STATUS_INVALID_PARAMETER));
        }
        // MaximumLength de cada texto: o pedido, ou o comprimento mais o NUL.
        let maximum = |bytes: &[u8], capacity: u16, terminator: u64| (bytes.len() as u64 + terminator).max(capacity as u64);
        let environment = self.environment_block();
        let texts: u64 = strings.iter().filter_map(|(_, bytes, capacity, terminator)| bytes.as_ref().map(|bytes| maximum(bytes, *capacity, *terminator).next_multiple_of(2) + STRING_GAP)).sum();
        let length = STRINGS_OFFSET + texts + environment.len() as u64;
        let size = length.div_ceil(0x1000).max(MINIMUM_BLOCK / 0x1000) * 0x1000;
        if size > u32::MAX as u64 {
            return Err(KernelError::with_status("parametros de processo grandes demais", STATUS_INVALID_PARAMETER));
        }
        let block = memory::map_user_region(size)?;
        // SAFETY: o bloco acabou de ser comprometido no processo corrente e
        // nenhum código de usuário roda nele ainda.
        let parameters = unsafe { RtlUserProcessParameters::at(block) };
        let targets: [&UnicodeString; 8] = [&parameters.image_path_name, &parameters.command_line, &parameters.dll_path, &parameters.current_directory.dos_path, &parameters.window_title, &parameters.desktop_info, &parameters.shell_info, &parameters.runtime_data];
        let mut offset = STRINGS_OFFSET;
        for (target, (_, bytes, capacity, terminator)) in targets.into_iter().zip(strings.iter()) {
            let Some(bytes) = bytes else { continue };
            let maximum = maximum(bytes, *capacity, *terminator);
            // O bloco novo é zerado: o NUL e a folga já estão lá.
            guest::write_bytes(block + offset, bytes);
            target.length.set(bytes.len() as u16);
            target.maximum_length.set(maximum as u16);
            target.buffer.set(offset);
            offset += maximum.next_multiple_of(2) + STRING_GAP;
        }
        guest::write_bytes(block + offset, &environment);
        parameters.environment.set(block + offset);
        parameters.environment_size.set(environment.len() as u64);
        parameters.maximum_length.set(size as u32);
        parameters.length.set(length as u32);
        parameters.flags.set(flags & !NORMALIZED);
        parameters.console_handle.set(self.console_handle);
        parameters.standard_input.set(self.standard_input);
        parameters.standard_output.set(self.standard_output);
        parameters.standard_error.set(self.standard_error);
        let settings = &self.settings;
        parameters.debug_flags.set(settings.debug_flags);
        parameters.console_flags.set(settings.console_flags);
        parameters.starting_x.set(settings.starting_x);
        parameters.starting_y.set(settings.starting_y);
        parameters.count_x.set(settings.count_x);
        parameters.count_y.set(settings.count_y);
        parameters.count_chars_x.set(settings.count_chars_x);
        parameters.count_chars_y.set(settings.count_chars_y);
        parameters.fill_attribute.set(settings.fill_attribute);
        parameters.window_flags.set(settings.window_flags);
        parameters.show_window_flags.set(settings.show_window_flags);
        parameters.process_group_id.set(settings.process_group_id);
        parameters.loader_threads.set(settings.loader_threads);
        Ok(block)
    }
}

/// O texto em UTF-16LE, sem NUL.
fn wide(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// UTF-16LE (um byte ímpar no fim é descartado).
fn text_of(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    String::from_utf16_lossy(&units)
}

/// Captura o RTL_USER_PROCESS_PARAMETERS que o chamador montou em
/// `address`, na memória de usuário do processo corrente (o NtCreateUserProcess
/// roda antes de anexar ao processo novo). A estrutura é copiada uma vez (até
/// o Length dela; o que falta lê zero) e lida da cópia; cada texto e o
/// ambiente são sondados e copiados. Normalizado (Flags & 1), cada Buffer é
/// uma VA; senão, o deslocamento desde `address`. O Environment é sempre uma
/// VA, com EnvironmentSize ou, se ele é 0, até o NUL duplo. CurrentDirectory.
/// Handle não passa (é um handle da tabela do chamador); o console e os
/// handles padrão passam como valores. Devolve o NTSTATUS da falha:
/// ACCESS_VIOLATION numa sonda, INVALID_PARAMETER num bloco malformado.
pub fn capture(address: u64) -> Result<ProcessParameters, u32> {
    capture_with_header(address).map(|(parameters, _)| parameters)
}

/// Os campos do cabeçalho de um bloco capturado que o
/// PsCaptureUserProcessParameters confere: o Flags, o Environment e o
/// EnvironmentSize, como o chamador os deixou.
#[derive(Clone, Copy, Debug)]
struct CapturedHeader {
    flags: u32,
    environment: u64,
    environment_size: u64,
}

/// O [`capture`] com o [`CapturedHeader`] da cópia de kernel.
fn capture_with_header(address: u64) -> Result<(ProcessParameters, CapturedHeader), u32> {
    if address % 8 != 0 || !state::probe_user_read(address, 8) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let maximum_length = guest::try_read::<u32>(address).map_err(|_| STATUS_ACCESS_VIOLATION)? as u64;
    let length = guest::try_read::<u32>(address + 4).map_err(|_| STATUS_ACCESS_VIOLATION)? as u64;
    if length < MINIMUM_CAPTURED || maximum_length < length {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let captured = length.min(RtlUserProcessParameters::SIZE);
    if !state::probe_user_read(address, captured) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let bytes = guest::try_read_bytes(address, captured as usize).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    let copy = guest::alloc_bytes(RtlUserProcessParameters::SIZE);
    if copy == 0 {
        return Err(STATUS_NO_MEMORY);
    }
    guest::write_bytes(copy, &bytes);
    // SAFETY: a cópia de kernel recém-alocada e zerada além do Length.
    let copied = unsafe { RtlUserProcessParameters::at(copy) };
    let header = CapturedHeader { flags: copied.flags.get(), environment: copied.environment.get(), environment_size: copied.environment_size.get() };
    let result = read_captured(address, copied).map(|parameters| (parameters, header));
    guest::free_bytes(copy);
    result
}

// ---- PsCaptureUserProcessParameters ------------------------------------------
//
// ntoskrnl 19041 0x6a5500 = PspCaptureUserProcessParameters(Out, Params, NULL,
// Flags 3, CurrentServerSilo) 0x606d2c, o export só por ordinal (1) que o
// condrv.sys chama no CdpLaunchServerProcess, na thread do cliente, com o
// bloco que o kernelbase montou (ConsoleLaunchServerProcess):
// - Params alinhado a 4 (senão STATUS_DATATYPE_MISALIGNMENT) e sondado;
// - Flags do chamador sem o bit 14; `(Flags ^ 1) & 0xF7010E11` diferente de
//   zero (sem RTL_USER_PROC_PARAMS_NORMALIZED, ou um bit proibido) ou 0x20
//   junto com 0x40: STATUS_INVALID_PARAMETER;
// - Environment com EnvironmentSize diferente de zero e par, senão
//   STATUS_INVALID_PARAMETER;
// - o Flags 3 da chamada: o CurrentDirectory vira o PsProtectedCurrentDirectory
//   do silo (o NtSystemRoot), o RuntimeData o PspProtectedRuntimeData (vazio),
//   o ambiente do chamador fica, e o ConsoleHandle e os três handles padrão
//   vão a zero;
// - um bloco ExAllocatePoolWithQuotaTag(NonPagedPoolNx |
//   POOL_QUOTA_FAIL_INSTEAD_OF_RAISE, 'PsPb') de ((0x441 + soma dos
//   MaximumLength) & ~1) + EnvironmentSize bytes: o cabeçalho de 0x440, os
//   textos a partir de +0x440 cada um com o seu MaximumLength e Buffer
//   absoluto (o bloco continua NORMALIZED), depois o ambiente; Length =
//   MaximumLength = cabeçalho + textos; EnvironmentVersion (+0x3f8) e
//   +0x420..+0x43f zerados. Quem chama libera com ExFreePoolWithTag(bloco, 0).
//
// O condrv reescreve a CommandLine do bloco no lugar (RtlStringCbPrintfW com o
// MaximumLength dela) antes do ZwCreateUserProcess, por isso cada texto
// guarda o MaximumLength do chamador. O DesktopInfo passa como veio: é ele
// que põe a janela do conhost na WinSta0\Default de quem chamou.

/// RTL_USER_PROC_RESERVED_14: o bit que a captura limpa.
const CAPTURE_CLEARED_FLAG: u32 = 0x4000;
/// Os bits que a captura recusa, com o NORMALIZED invertido.
const CAPTURE_REFUSED_FLAGS: u32 = 0xF701_0E11;
/// Dois flags que não podem vir juntos.
const CAPTURE_EXCLUSIVE_FLAGS: u32 = 0x60;
/// NonPagedPoolNx | POOL_QUOTA_FAIL_INSTEAD_OF_RAISE.
const CAPTURE_POOL_TYPE: u32 = 0x208;
/// 'PsPb'.
const CAPTURE_POOL_TAG: u32 = u32::from_le_bytes(*b"PsPb");
/// O cabeçalho copiado: a estrutura inteira.
const CAPTURE_HEADER: u64 = 0x440;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_INTEGER_OVERFLOW: u32 = 0xC000_0095;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// PsCaptureUserProcessParameters(Out, UserParameters): captura o bloco
/// NORMALIZED do chamador de modo usuário em `user` para um bloco de pool
/// de kernel e grava a VA dele em `*out` (um ponteiro de kernel). Devolve o
/// NTSTATUS.
pub fn capture_to_pool(out: u64, user: u64) -> u32 {
    if user % 4 != 0 {
        return STATUS_DATATYPE_MISALIGNMENT;
    }
    let (mut parameters, header) = match capture_with_header(user) {
        Ok(captured) => captured,
        Err(status) => return status,
    };
    let flags = header.flags & !CAPTURE_CLEARED_FLAG;
    if (flags ^ NORMALIZED) & CAPTURE_REFUSED_FLAGS != 0 || flags & CAPTURE_EXCLUSIVE_FLAGS == CAPTURE_EXCLUSIVE_FLAGS {
        return STATUS_INVALID_PARAMETER;
    }
    if header.environment == 0 || header.environment_size == 0 || header.environment_size % 2 != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    // O ambiente como o chamador o deixou: EnvironmentSize bytes (o
    // `capture` já os sondou).
    if !state::probe_user_read(header.environment, header.environment_size) {
        return STATUS_ACCESS_VIOLATION;
    }
    let Ok(environment) = guest::try_read_bytes(header.environment, header.environment_size as usize) else { return STATUS_ACCESS_VIOLATION };
    // O Flags 3 da chamada.
    parameters.current_directory = crate::ntos::rtl::guest_strings::read_wide_string(crate::ntos::rtl::version::nt_system_root());
    parameters.capacities.current_directory = 0;
    parameters.runtime_data = None;
    parameters.capacities.runtime_data = 0;
    parameters.console_handle = 0;
    parameters.standard_input = 0;
    parameters.standard_output = 0;
    parameters.standard_error = 0;
    let block = match parameters.write_kernel_block(flags, &environment) {
        Ok(block) => block,
        Err(status) => return status,
    };
    // SAFETY: o PVOID* de saída de um chamador de modo kernel.
    unsafe { crate::ntos::inc::field::Field::<u64>::at(out) }.set(block);
    0
}

impl ProcessParameters {
    /// O bloco de pool de kernel do [`capture_to_pool`]: o cabeçalho de
    /// 0x440 bytes, os textos a partir de +0x440 com o MaximumLength de cada
    /// um e Buffer absoluto, e `environment` depois deles. Flags = `flags`
    /// (com o NORMALIZED). Devolve a VA do bloco, ou o NTSTATUS da falha.
    fn write_kernel_block(&self, flags: u32, environment: &[u8]) -> Result<u64, u32> {
        let capacities = &self.capacities;
        let required = |text: &str| (!text.is_empty()).then(|| wide(text));
        // Na ordem dos campos da estrutura.
        let strings: [(Option<Vec<u8>>, u16, u64); 8] = [
            (required(&self.current_directory), capacities.current_directory, 2),
            (required(&self.dll_path), capacities.dll_path, 2),
            (required(&self.image_path_name), capacities.image_path_name, 2),
            (required(&self.command_line), capacities.command_line, 2),
            (self.window_title.as_deref().map(wide), capacities.window_title, 2),
            (self.desktop_info.as_deref().map(wide), capacities.desktop_info, 2),
            (self.shell_info.as_deref().map(wide), capacities.shell_info, 2),
            (self.runtime_data.clone(), capacities.runtime_data, 0),
        ];
        let maximum = |bytes: &[u8], capacity: u16, terminator: u64| (bytes.len() as u64 + terminator).max(capacity as u64);
        if strings.iter().any(|(bytes, capacity, terminator)| bytes.as_ref().is_some_and(|bytes| maximum(bytes, *capacity, *terminator) > u16::MAX as u64)) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let texts: u64 = strings.iter().filter_map(|(bytes, capacity, terminator)| bytes.as_ref().map(|bytes| maximum(bytes, *capacity, *terminator).next_multiple_of(2))).sum();
        let length = CAPTURE_HEADER + texts;
        let size = length.checked_add(environment.len() as u64).filter(|&size| size <= u32::MAX as u64).ok_or(STATUS_INTEGER_OVERFLOW)?;
        let block = match crate::ntos::ex::pool_quota::allocate(CAPTURE_POOL_TYPE, size, CAPTURE_POOL_TAG) {
            Ok(block) if block != 0 => block,
            _ => return Err(STATUS_INSUFFICIENT_RESOURCES),
        };
        guest::write_bytes(block, &alloc::vec![0u8; size as usize]);
        // SAFETY: o bloco de pool recém-alocado e zerado.
        let parameters = unsafe { RtlUserProcessParameters::at(block) };
        let targets: [&UnicodeString; 8] = [&parameters.current_directory.dos_path, &parameters.dll_path, &parameters.image_path_name, &parameters.command_line, &parameters.window_title, &parameters.desktop_info, &parameters.shell_info, &parameters.runtime_data];
        let mut offset = CAPTURE_HEADER;
        for (target, (bytes, capacity, terminator)) in targets.into_iter().zip(strings.iter()) {
            let Some(bytes) = bytes else { continue };
            let maximum = maximum(bytes, *capacity, *terminator);
            // O bloco é zerado: o NUL já está lá.
            guest::write_bytes(block + offset, bytes);
            target.length.set(bytes.len() as u16);
            target.maximum_length.set(maximum as u16);
            target.buffer.set(block + offset);
            offset += maximum.next_multiple_of(2);
        }
        guest::write_bytes(block + length, environment);
        parameters.environment.set(block + length);
        parameters.environment_size.set(environment.len() as u64);
        parameters.environment_version.set(0);
        parameters.maximum_length.set(length as u32);
        parameters.length.set(length as u32);
        parameters.flags.set(flags);
        parameters.console_handle.set(self.console_handle);
        parameters.standard_input.set(self.standard_input);
        parameters.standard_output.set(self.standard_output);
        parameters.standard_error.set(self.standard_error);
        let settings = &self.settings;
        parameters.debug_flags.set(settings.debug_flags);
        parameters.console_flags.set(settings.console_flags);
        parameters.starting_x.set(settings.starting_x);
        parameters.starting_y.set(settings.starting_y);
        parameters.count_x.set(settings.count_x);
        parameters.count_y.set(settings.count_y);
        parameters.count_chars_x.set(settings.count_chars_x);
        parameters.count_chars_y.set(settings.count_chars_y);
        parameters.fill_attribute.set(settings.fill_attribute);
        parameters.window_flags.set(settings.window_flags);
        parameters.show_window_flags.set(settings.show_window_flags);
        parameters.process_group_id.set(settings.process_group_id);
        parameters.loader_threads.set(settings.loader_threads);
        Ok(block)
    }
}

/// Os campos da cópia de kernel de um bloco do chamador em `block`.
fn read_captured(block: u64, copy: &RtlUserProcessParameters) -> Result<ProcessParameters, u32> {
    let normalized = copy.flags.get() & NORMALIZED != 0;
    let string = |string: &UnicodeString| capture_string(block, normalized, string);
    let text = |string: &UnicodeString| -> Result<(Option<String>, u16), u32> { capture_string(block, normalized, string).map(|captured| captured.map_or((None, 0), |(bytes, maximum)| (Some(text_of(&bytes)), maximum))) };
    let (image_path_name, image_capacity) = text(&copy.image_path_name)?;
    let (command_line, command_capacity) = text(&copy.command_line)?;
    let (current_directory, directory_capacity) = text(&copy.current_directory.dos_path)?;
    let (dll_path, dll_capacity) = text(&copy.dll_path)?;
    let (window_title, title_capacity) = text(&copy.window_title)?;
    let (desktop_info, desktop_capacity) = text(&copy.desktop_info)?;
    let (shell_info, shell_capacity) = text(&copy.shell_info)?;
    let (runtime_data, runtime_capacity) = string(&copy.runtime_data)?.map_or((None, 0), |(bytes, maximum)| (Some(bytes), maximum));
    let environment = capture_environment(copy.environment.get(), copy.environment_size.get())?;
    Ok(ProcessParameters {
        image_path_name: image_path_name.unwrap_or_default(),
        command_line: command_line.unwrap_or_default(),
        current_directory: current_directory.unwrap_or_default(),
        dll_path: dll_path.unwrap_or_default(),
        window_title,
        desktop_info,
        shell_info,
        runtime_data,
        environment,
        console_handle: copy.console_handle.get(),
        standard_input: copy.standard_input.get(),
        standard_output: copy.standard_output.get(),
        standard_error: copy.standard_error.get(),
        settings: Settings {
            debug_flags: copy.debug_flags.get(),
            console_flags: copy.console_flags.get(),
            starting_x: copy.starting_x.get(),
            starting_y: copy.starting_y.get(),
            count_x: copy.count_x.get(),
            count_y: copy.count_y.get(),
            count_chars_x: copy.count_chars_x.get(),
            count_chars_y: copy.count_chars_y.get(),
            fill_attribute: copy.fill_attribute.get(),
            window_flags: copy.window_flags.get(),
            show_window_flags: copy.show_window_flags.get(),
            process_group_id: copy.process_group_id.get(),
            loader_threads: copy.loader_threads.get(),
        },
        capacities: Capacities {
            image_path_name: image_capacity,
            command_line: command_capacity,
            current_directory: directory_capacity,
            dll_path: dll_capacity,
            window_title: title_capacity,
            desktop_info: desktop_capacity,
            shell_info: shell_capacity,
            runtime_data: runtime_capacity,
        },
    })
}

/// Um UNICODE_STRING do bloco do chamador (a cópia de kernel `string`): os
/// bytes e o MaximumLength, ou `None` com Buffer NULL.
fn capture_string(block: u64, normalized: bool, string: &UnicodeString) -> Result<Option<(Vec<u8>, u16)>, u32> {
    let (length, maximum, buffer) = (string.length.get(), string.maximum_length.get(), string.buffer.get());
    if length > maximum {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if buffer == 0 {
        return if length == 0 { Ok(None) } else { Err(STATUS_INVALID_PARAMETER) };
    }
    let address = if normalized { buffer } else { block.checked_add(buffer).ok_or(STATUS_INVALID_PARAMETER)? };
    if !state::probe_user_read(address, length as u64) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let bytes = guest::try_read_bytes(address, length as usize).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    Ok(Some((bytes, maximum)))
}

/// O bloco de ambiente do chamador em `address`: `size` bytes ou, com 0, até
/// o NUL duplo (no máximo [`ENVIRONMENT_LIMIT`]); as variáveis até a primeira
/// vazia.
fn capture_environment(address: u64, size: u64) -> Result<Vec<String>, u32> {
    if address == 0 {
        return Ok(Vec::new());
    }
    if address % 2 != 0 || size > ENVIRONMENT_LIMIT {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let bytes = if size != 0 {
        if !state::probe_user_read(address, size) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        guest::try_read_bytes(address, size as usize).map_err(|_| STATUS_ACCESS_VIOLATION)?
    } else {
        // Sem tamanho: página a página até o NUL duplo.
        let mut bytes: Vec<u8> = Vec::new();
        loop {
            let at = address + bytes.len() as u64;
            let chunk = 0x1000 - (at & 0xFFF);
            if bytes.len() as u64 + chunk > ENVIRONMENT_LIMIT {
                return Err(STATUS_INVALID_PARAMETER);
            }
            if !state::probe_user_read(at, chunk) {
                return Err(STATUS_ACCESS_VIOLATION);
            }
            bytes.extend(guest::try_read_bytes(at, chunk as usize).map_err(|_| STATUS_ACCESS_VIOLATION)?);
            let units = bytes.len() / 2;
            if (1..units).any(|index| bytes[index * 2 - 2..index * 2 + 2] == [0, 0, 0, 0]) || bytes.starts_with(&[0, 0]) {
                break;
            }
        }
        bytes
    };
    let units: Vec<u16> = bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    Ok(units.split(|&unit| unit == 0).take_while(|variable| !variable.is_empty()).map(String::from_utf16_lossy).collect())
}
