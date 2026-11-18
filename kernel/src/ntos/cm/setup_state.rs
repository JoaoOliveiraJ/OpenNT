//! O estado de setup de uma instalação concluída do Windows 10 19041: sem
//! setup nem OOBE em andamento, com o OOBE da máquina e o primeiro logon do
//! usuário já feitos. Os valores são os mesmos em toda instalação acabada
//! (não dependem da máquina) e vêm de quem os lê:
//!
//! - `SYSTEM\Setup`: o WinMain do winlogon.exe só roda o setup
//!   (`g_fRunSetup`, o WinLogonSetup) com o `CmdLine` não vazio e o
//!   `SetupType` (ou o `Respecialize`) diferente de zero; o
//!   ShouldSetupExecute executa o setup com o `SetupType` 1 ou 4, o mesmo
//!   teste do ExInitSystemPhase2 do kernel (o ExpSetupModeDetected). O
//!   `SystemSetupInProgress` e o `OOBEInProgress` em zero valem para o
//!   kernel (ExpSystemSetupInProgress, PipUpdateSetupInProgress), o
//!   services.exe, o lsm.dll (o RCM só sobe fora do sysprep), o samsrv.dll e
//!   o umpnpmgr.dll. O `SetupSupported` 1 faz o OOBEComplete do kernel32 ler
//!   o estado do OOBE pelo WNF; sem ele (e sem o `OobeCompleteWnfSupported`
//!   do CoreShell) a chamada falha com ERROR_NOT_SUPPORTED. O `AuditBoot` de
//!   `Setup\Status` e a chave `AuditBootVolatile` (o modo de auditoria)
//!   ficam ausentes, como numa instalação acabada; o `ChildCompletion` traz
//!   as fases filhas do setup concluídas (o IsSysprepComplete do umpnpmgr
//!   testa o `setup.exe` diferente de zero).
//! - `Setup\State` da SOFTWARE: a imagem completa (`IMAGE_STATE_COMPLETE`),
//!   que o spp.dll e o motor de reset leem.
//! - `OOBE\Stats` da SOFTWARE: o `OOBEUserSignedIn` 1. O
//!   IsFirstLogonAfterOOBE do logoncontroller.dll (LogonUI) dá verdadeiro
//!   com o valor ausente ou zero, e o _IsOOBEAutoLogon do CLogonController
//!   trata um logon automático configurado como o do fim do OOBE.
//! - Os dados persistidos de dois nomes WNF bem conhecidos com dados
//!   permanentes, em `Windows NT\CurrentVersion\Notifications\Data` (um
//!   REG_BINARY por nome: o ChangeStamp seguido dos dados, como o kernel os
//!   grava e lê ao criar a instância do nome): o WNF_DEP_OOBE_COMPLETE e o
//!   WNF_SHEL_OOBE_USER_LOGON_COMPLETE, carimbo 1 e ULONG 1, publicados uma
//!   vez pelo setup e pelo winlogon. O OOBEComplete do kernel32 lê o segundo
//!   numa estação de trabalho (o primeiro num servidor ou com
//!   `WinInit\Headless`) e dá completo só com 4 bytes diferentes de zero;
//!   sem os dados, o CPolicyMonitor do lsm.dll fica esperando o fim do OOBE
//!   (RegisterWaitUntilOOBECompleted) e o PerformPostOOBEWorkIfNecessary do
//!   winlogon refaz o trabalho de pós-OOBE no primeiro logon (a cifragem do
//!   dispositivo e a publicação do nome).
//!
//! Nada aqui é do usuário: nem SIDs, nem nomes, nem o último logon, nem a
//! chave do produto. Dados puros das hives SYSTEM e SOFTWARE (veja
//! `cm/seed.rs`): o `xtask` grava estas chaves nos arquivos das hives e o
//! kernel só as semeia em memória quando um arquivo falta.

use alloc::vec::Vec;

use super::seed::{SeedKey, REG_BINARY, REG_SZ};

/// WNF_DEP_OOBE_COMPLETE e WNF_SHEL_OOBE_USER_LOGON_COMPLETE (o nome
/// codificado é o nome do valor em `Notifications\Data`).
pub const OOBE_COMPLETE_STATE_NAMES: [u64; 2] = [0x4196_0B29_A3BC_0C75, 0x0D83_063E_A3BC_2475];

/// As chaves da hive SYSTEM.
pub fn system_keys() -> Vec<SeedKey> {
    let mut setup = SeedKey::new("Setup");
    setup
        .dword("SystemSetupInProgress", 0)
        .dword("OOBEInProgress", 0)
        .dword("SetupType", 0)
        .text("CmdLine", REG_SZ, "")
        .dword("SetupPhase", 0)
        .dword("RestartSetup", 0)
        .dword("SetupSupported", 1);
    let mut child_completion = SeedKey::new("Setup\\Status\\ChildCompletion");
    child_completion.dword("setup.exe", 3).dword("oobeldr.exe", 3).dword("SetupFinalTasks", 3);
    alloc::vec![setup, child_completion]
}

/// As chaves da hive SOFTWARE.
pub fn software_keys() -> Vec<SeedKey> {
    let mut state = SeedKey::new("Microsoft\\Windows\\CurrentVersion\\Setup\\State");
    state.text("ImageState", REG_SZ, "IMAGE_STATE_COMPLETE");
    let mut stats = SeedKey::new("Microsoft\\Windows\\CurrentVersion\\OOBE\\Stats");
    stats.dword("OOBEUserSignedIn", 1);
    let mut data = SeedKey::new("Microsoft\\Windows NT\\CurrentVersion\\Notifications\\Data");
    for name in OOBE_COMPLETE_STATE_NAMES {
        // ChangeStamp 1 seguido do ULONG 1.
        let value: Vec<u8> = [1u32, 1u32].iter().flat_map(|word| word.to_le_bytes()).collect();
        data.value(&alloc::format!("{name:016X}"), REG_BINARY, value);
    }
    alloc::vec![state, stats, data]
}
