//! Parâmetros de processo (RTL_USER_PROCESS_PARAMETERS).
//!
//! O papel do RtlCreateProcessParametersEx para os processos que o kernel
//! cria: os textos do processo novo (caminho da imagem, linha de comando,
//! diretório corrente, caminho de DLLs, título, desktop, shell e dados de
//! runtime), o bloco de ambiente, o console e os handles padrão, gravados num
//! bloco do processo em montagem (o corrente: a criação roda anexada a ele).
//!
//! Formato entregue ao processo: auto-relativo, sem
//! RTL_USER_PROC_PARAMS_NORMALIZED (Flags 0), com o Buffer de cada
//! UNICODE_STRING sendo o deslocamento desde a base do bloco; o loader da
//! ntdll normaliza na inicialização. O Environment é absoluto (a
//! normalização só converte os Buffers). Os textos ficam bem depois da
//! estrutura: a ntdll 24H2 lê campos até +0x440. Um texto ausente fica com o
//! UNICODE_STRING zerado (Buffer NULL), que a normalização preserva.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

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
    pub runtime_data: Option<String>,
    /// As variáveis do ambiente, cada uma `NOME=valor`.
    pub environment: Vec<String>,
    /// ConsoleHandle: [`DETACHED_PROCESS`] ou um handle/pseudo-handle de
    /// console, que passa direto.
    pub console_handle: u64,
    pub standard_input: u64,
    pub standard_output: u64,
    pub standard_error: u64,
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
    /// estrutura, os textos e o ambiente; MaximumLength, o bloco inteiro.
    pub fn write(&self) -> Result<u64, KernelError> {
        let texts: [(&str, Option<&str>); 8] = [
            ("ImagePathName", Some(self.image_path_name.as_str())),
            ("CommandLine", Some(self.command_line.as_str())),
            ("DllPath", Some(self.dll_path.as_str())),
            ("CurrentDirectory", Some(self.current_directory.as_str())),
            ("WindowTitle", self.window_title.as_deref()),
            ("DesktopInfo", self.desktop_info.as_deref()),
            ("ShellInfo", self.shell_info.as_deref()),
            ("RuntimeData", self.runtime_data.as_deref()),
        ];
        // Os UNICODE_STRING guardam o comprimento em 16 bits.
        if let Some((name, _)) = texts.iter().find(|(_, text)| text.is_some_and(|text| units(text) * 2 + 2 > u16::MAX as u64)) {
            return Err(KernelError::with_status(format!("parametros de processo: {name} longo demais"), 0xC000_000D));
        }
        let environment = self.environment_block();
        let strings: u64 = texts.iter().filter_map(|(_, text)| *text).map(|text| (units(text) + 1) * 2 + STRING_GAP).sum();
        let length = STRINGS_OFFSET + strings + environment.len() as u64;
        let size = length.div_ceil(0x1000).max(MINIMUM_BLOCK / 0x1000) * 0x1000;
        if size > u32::MAX as u64 {
            return Err(KernelError::with_status("parametros de processo grandes demais", 0xC000_000D));
        }
        let block = memory::map_user_region(size)?;
        // SAFETY: o bloco acabou de ser comprometido no processo corrente e
        // nenhum código de usuário roda nele ainda.
        let parameters = unsafe { RtlUserProcessParameters::at(block) };
        let mut offset = STRINGS_OFFSET;
        let mut place = |string: &UnicodeString, text: Option<&str>| {
            let Some(text) = text else { return };
            state::write_user_wide(block + offset, text);
            let bytes = units(text) as u16 * 2;
            string.length.set(bytes);
            string.maximum_length.set(bytes + 2);
            string.buffer.set(offset);
            offset += (units(text) + 1) * 2 + STRING_GAP;
        };
        place(&parameters.image_path_name, texts[0].1);
        place(&parameters.command_line, texts[1].1);
        place(&parameters.dll_path, texts[2].1);
        place(&parameters.current_directory.dos_path, texts[3].1);
        place(&parameters.window_title, texts[4].1);
        place(&parameters.desktop_info, texts[5].1);
        place(&parameters.shell_info, texts[6].1);
        place(&parameters.runtime_data, texts[7].1);
        guest::write_bytes(block + offset, &environment);
        parameters.environment.set(block + offset);
        parameters.environment_size.set(environment.len() as u64);
        parameters.maximum_length.set(size as u32);
        parameters.length.set(length as u32);
        parameters.flags.set(0);
        parameters.console_handle.set(self.console_handle);
        parameters.standard_input.set(self.standard_input);
        parameters.standard_output.set(self.standard_output);
        parameters.standard_error.set(self.standard_error);
        Ok(block)
    }
}

/// Unidades UTF-16 do texto.
fn units(text: &str) -> u64 {
    text.encode_utf16().count() as u64
}
