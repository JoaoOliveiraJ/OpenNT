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

/// Roda o cmd.exe até ele sair e põe o resultado na serial.
pub fn run() {
    let mut parameters = ProcessParameters::for_image(IMAGE_DOS_PATH);
    parameters.command_line = String::from(COMMAND_LINE);
    parameters.current_directory = String::from("C:\\Windows\\System32\\");
    parameters.console_handle = CONSOLE_CREATE_NO_WINDOW;
    // O cmd.exe nasce numa sessão nova, a 0 neste boot sem smss, como o smss
    // de sessão do boot real: o token dele fica com a sessão do processo.
    let request = CreateProcessRequest {
        image: ImageOrigin::NtPath(String::from(IMAGE_NT_PATH)),
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
    crate::debug_print!("[console] {}", COMMAND_LINE);
    let exit = match create::create_user_process(&request) {
        Ok(created) => {
            crate::debug_print!("[console] cmd.exe na sessao {:#x}", crate::ntos::mm::session::session_id_ex(created.process_pointer));
            user_process::run_created(created).map_err(|error| format!("{error}"))
        }
        Err(failure) => Err(format!("cmd.exe nao criado: {failure}")),
    };
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
