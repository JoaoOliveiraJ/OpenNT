//! O processo de console de ponta a ponta (`--console-process`, teste
//! console-processo): no boot comum, sem carregar o condrv.sys antes, o
//! kernel roda o cmd.exe real com um console sem janela. O ConsoleHandle é o
//! CONSOLE_CREATE_NO_WINDOW (-3): o kernelbase do cmd manda o WindowVisible
//! FALSE no CONSOLE_SERVER_MSG, e o conhost.exe serve o console sem janela e
//! sem o user32 (este boot não tem o win32k). A linha
//! `cmd /d /c "echo CONSOLE_OK>CONOUT$&&exit /b 7"` passa pelo caminho
//! inteiro do 19041:
//!
//! - o cmd.exe abre a sessão 0, como o smss de sessão num boot real: o
//!   pedido de criação leva PROCESS_CREATE_FLAGS_CREATE_SESSION (o
//!   MiSessionCreate do MiMapProcessExecutable) e o cmd é o mestre da
//!   sessão.
//!   O token dele (o SeSubProcessToken do token do System) recebe o
//!   SessionId da sessão do processo, e o ZwCreateUserProcess do condrv,
//!   com o token e o ParentProcess do cmd, põe o conhost na mesma sessão.
//!   Sem ela, o token diria sessão 0 com quem cria fora de sessão, e o
//!   PspAttachSession recusaria o conhost (STATUS_PROCESS_IS_TERMINATING),
//!   porque o boot comum não tem o smss que abre a sessão 0;
//! - o ConsoleAllocate do kernelbase não acha o `\Device\ConDrv\Server` e
//!   carrega o condrv pelo NtSetSystemInformation(132);
//! - o IOCTL 0x500037 do servidor leva o CdpLaunchServerProcess do condrv ao
//!   PsCaptureUserProcessParameters e ao ZwCreateUserProcess do conhost.exe
//!   (handles de kernel, AUXILIARY_PROCESS); o conhost recebe o servidor por
//!   um handle de usuário do ObOpenObjectByPointer de UserMode e a linha de
//!   comando reescrita nos parâmetros normalizados;
//! - o cmd abre o `\Reference`, o `\Connect` (com o EA "server") e o
//!   `\Input` e o `\Output` relativos aos handles de dispositivo, e o CONNECT
//!   pendente conclui quando o conhost responde;
//! - o `echo` vai ao CONOUT$ (o `\Device\ConDrv\CurrentOut`) e o `exit /b 7`
//!   só roda se ele deu certo.
//!
//! A serial mostra `CONSOLE_PROCESS_OK` quando o cmd sai com 7, ou
//! `CONSOLE_PROCESS_FALHOU` com o código ou o erro, e o estado do conhost.exe
//! (ele sai quando o último cliente desconecta).
//!
//! Com `--wow64` (teste wow64-console) o cmd.exe é o x86 de SysWOW64, que
//! roda pela camada WoW64 real (o processo nasce com EWOW64PROCESS, a ntdll
//! de 32 bits e o contexto x86 inicial), o ambiente leva o
//! `PROCESSOR_ARCHITECTURE=AMD64` de uma sessão x64 e a linha é
//! `cmd /d /c "echo %PROCESSOR_ARCHITECTURE%,%PROCESSOR_ARCHITEW6432%>C:\wow64-arq.txt&&exit /b 7"`:
//! a ntdll de 32 bits converte o ambiente do processo x86
//! (RtlpWow64ThunkEnvironment64To32: `x86`, com o valor nativo em
//! `PROCESSOR_ARCHITEW6432`) e o cmd grava os dois num arquivo do volume,
//! que o kernel lê quando ele sai. `WOW64_CONSOLE_OK` sai quando o processo
//! era WoW64, o cmd saiu com 7 e o arquivo tem `x86,AMD64`; senão
//! `WOW64_CONSOLE_FALHOU`. (O `ver` precisaria do cmd.exe.mui no idioma
//! deste boot sem o smss, o en-US, que a instalação não tem.)

use alloc::format;
use alloc::string::String;

use crate::ntos::ps::create::{self, CreateProcessRequest, ImageOrigin};
use crate::ntos::ps::process;
use crate::ntos::ps::process_parameters::ProcessParameters;
use crate::ntos::ps::user::process as user_process;

/// O cmd.exe do volume, pelo caminho NT e pelo caminho DOS.
const IMAGE_NT_PATH: &str = "\\SystemRoot\\System32\\cmd.exe";
const IMAGE_DOS_PATH: &str = "C:\\Windows\\System32\\cmd.exe";
/// O `echo` só deixa o `exit /b 7` rodar quando a escrita no console deu
/// certo.
const COMMAND_LINE: &str = "\"C:\\Windows\\System32\\cmd.exe\" /d /c \"echo CONSOLE_OK>CONOUT$&&exit /b 7\"";
const EXIT_CODE: u32 = 7;
/// CONSOLE_CREATE_NO_WINDOW no ConsoleHandle dos parâmetros.
const CONSOLE_CREATE_NO_WINDOW: u64 = 0xFFFF_FFFF_FFFF_FFFD;

/// O cmd.exe x86 do `--wow64` e o arquivo em que o `echo` dele escreve.
const WOW64_IMAGE_NT_PATH: &str = "\\SystemRoot\\SysWOW64\\cmd.exe";
const WOW64_IMAGE_DOS_PATH: &str = "C:\\Windows\\SysWOW64\\cmd.exe";
const WOW64_COMMAND_LINE: &str = "\"C:\\Windows\\SysWOW64\\cmd.exe\" /d /c \"echo %PROCESSOR_ARCHITECTURE%,%PROCESSOR_ARCHITEW6432%>C:\\wow64-arq.txt&&exit /b 7\"";
const WOW64_ARCHITECTURE_FILE: &str = "\\??\\C:\\wow64-arq.txt";
/// O PROCESSOR_ARCHITECTURE do ambiente de uma sessão x64 (o
/// `Session Manager\Environment` da instalação) e o que o processo x86 vê
/// depois do RtlpWow64ThunkEnvironment64To32 da ntdll de 32 bits.
const NATIVE_ARCHITECTURE: &str = "PROCESSOR_ARCHITECTURE=AMD64";
const WOW64_ARCHITECTURES: &str = "x86,AMD64";

/// Roda o cmd.exe até ele sair e põe o resultado na serial.
pub fn run() {
    let wow64 = crate::ntos::init::boot_config::wow64();
    let (image_nt_path, image_dos_path, command_line) = if wow64 { (WOW64_IMAGE_NT_PATH, WOW64_IMAGE_DOS_PATH, WOW64_COMMAND_LINE) } else { (IMAGE_NT_PATH, IMAGE_DOS_PATH, COMMAND_LINE) };
    let mut parameters = ProcessParameters::for_image(image_dos_path);
    parameters.command_line = String::from(command_line);
    parameters.current_directory = String::from("C:\\Windows\\System32\\");
    parameters.console_handle = CONSOLE_CREATE_NO_WINDOW;
    if wow64 {
        parameters.environment.push(String::from(NATIVE_ARCHITECTURE));
    }
    // O cmd.exe nasce numa sessão nova, a 0 neste boot sem smss, como o smss
    // de sessão do boot real: o token dele fica com a sessão do processo.
    let request = CreateProcessRequest {
        image: ImageOrigin::NtPath(String::from(image_nt_path)),
        image_name: "cmd.exe",
        parameters,
        parent: None,
        thread_flags: 0,
        inherit_handles_from: None,
        on_created: None,
        protection: 0,
        create_session: true,
        primary_token: None,
        image_request: Default::default(),
    };
    crate::debug_print!("[console] {}", command_line);
    let mut was_wow64 = false;
    let exit = match create::create_user_process(&request) {
        Ok(created) => {
            was_wow64 = crate::ntos::ps::wow64::is_x86_process(created.process_pointer);
            crate::debug_print!("[console] cmd.exe na sessao {:#x} (WoW64 {}, PEB32 {:#x})", crate::ntos::mm::session::session_id_ex(created.process_pointer), was_wow64, created.peb32);
            user_process::run_created(created).map_err(|error| format!("{error}"))
        }
        Err(failure) => Err(format!("cmd.exe nao criado: {failure}")),
    };
    if wow64 {
        report_wow64(was_wow64, exit);
        return;
    }
    let conhost = process::list_active_processes().into_iter().find(|entry| entry.name.eq_ignore_ascii_case("conhost.exe"));
    crate::debug_print!(
        "[console] cmd.exe saiu: {:?}; conhost.exe {}",
        exit,
        conhost.map_or_else(|| String::from("nao esta na lista de processos ativos"), |entry| format!("pid {} ainda ativo ({} threads)", entry.pid, entry.threads.len()))
    );
    match exit {
        Ok(EXIT_CODE) => crate::debug_print!("CONSOLE_PROCESS_OK"),
        Ok(code) => crate::debug_print!("CONSOLE_PROCESS_FALHOU: cmd.exe saiu com {:#x}", code),
        Err(message) => crate::debug_print!("CONSOLE_PROCESS_FALHOU: {}", message),
    }
}

/// O resultado do cmd.exe x86: o código de saída e a linha que o `echo`
/// gravou no arquivo (os bytes fora do ASCII saem como `?`).
fn report_wow64(was_wow64: bool, exit: Result<u32, String>) {
    let text = crate::drivers::fs::volume_files::lookup_volume_file(WOW64_ARCHITECTURE_FILE).and_then(|file| file.read_at(0, u64::MAX).ok()).map(|bytes| bytes.iter().map(|&byte| if byte.is_ascii() { byte as char } else { '?' }).collect::<String>());
    let line = text.as_deref().and_then(|text| text.lines().map(str::trim).find(|line| !line.is_empty())).map(String::from);
    crate::debug_print!("[wow64] arquitetura: {}", line.as_deref().unwrap_or("(arquivo ausente ou vazio)"));
    let architectures = line.as_deref() == Some(WOW64_ARCHITECTURES);
    match exit {
        Ok(EXIT_CODE) if was_wow64 && architectures => crate::debug_print!("WOW64_CONSOLE_OK"),
        Ok(code) => crate::debug_print!("WOW64_CONSOLE_FALHOU: cmd.exe saiu com {:#x} (WoW64 {}, arquiteturas {})", code, was_wow64, architectures),
        Err(message) => crate::debug_print!("WOW64_CONSOLE_FALHOU: {}", message),
    }
}
