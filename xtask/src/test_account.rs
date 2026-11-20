//! A conta local de teste do `--conta-de-teste` (só no boot do processo
//! inicial real, `--initial-process=smss`).
//!
//! O xtask não cria a conta: grava em `SYSTEM\Setup` o gancho de primeiro
//! boot que o winlogon.exe de uma instalação concluída honra, o mesmo que o
//! Setup do Windows usa (`SetupType` 2 com o `CmdLine` não vazio). O WinMain
//! do winlogon roda o `CmdLine` uma vez, como SYSTEM, em `winsta0\Default`,
//! depois que os serviços sobem e antes do LogonUI, e espera o fim dele
//! (ExecuteSetup: CreateProcessInternalW sem nome de aplicativo e
//! WaitForSingleObject INFINITE). O comando roda só programas da Microsoft:
//! o cmd.exe, o net.exe (que chama o net1.exe: NetUserAdd e os aliases pelo
//! samcli e o samlib, até o samsrv do lsass) e o reg.exe, que no fim volta o
//! gancho ao estado de uma instalação concluída (`SetupType` 0 e `CmdLine`
//! vazio, os valores de `cm/setup_state.rs`): ele roda uma vez só.
//!
//! A conta é a de um primeiro usuário local: no grupo Administradores (o
//! OOBE põe a primeira conta nele) e sem senha. O `net user /add` sem senha
//! não grava senha nenhuma (o usri3_password vai nulo e o samcli pula o
//! campo), então a política do banco novo (complexidade ligada, comprimento
//! mínimo 0) não entra, e o samsrv responde senha vazia ao LogonUI. O `net
//! user /add` também põe a conta em Usuários; tirá-la de lá, como o OOBE
//! faz, não cabe no limite do comando, e Usuários não dá direito nenhum além
//! dos de Administradores. O banco que o samsrv cria no primeiro boot deixa
//! o Administrador e o Convidado habilitados quando a política do produto
//! não manda desabilitar (`LSA-Policy-DisableBuiltinAdminByDefault` e
//! `...GuestByDefault` em 0, como aqui); numa instalação de verdade os dois
//! chegam desabilitados na imagem. O comando os desabilita: com uma única
//! conta local habilitada e de senha vazia, o LogonUI entra sozinho nela
//! (o modo de usuário único sem senha do logoncontroller), sem
//! AutoAdminLogon nem senha guardada.
//!
//! O `net localgroup` e o `net user` só aceitam nomes: os do grupo e das
//! contas embutidas são os que o samsrv.dll do convidado dá ao criar o
//! banco, das mensagens do `.mui` dele no idioma de interface do sistema.

use std::path::{Path, PathBuf};

use crate::host_language::HostKey;

/// O nome da conta: genérico, sem dado pessoal.
pub const ACCOUNT_NAME: &str = "Usuario";

/// O maior `CmdLine`: o IsSetupAvailable do winlogon o lê num buffer de
/// 0x104 WCHARs com o NUL; um valor maior dá ERROR_MORE_DATA e o setup não
/// roda.
pub const COMMAND_LINE_MAX: usize = 0x104 - 1;

/// RT_MESSAGETABLE.
const RT_MESSAGETABLE: u32 = 11;
/// As mensagens do samsrv.dll com os nomes que o CreateAccountDomain e o
/// CreateBuiltinDomain dão ao Administrador (RID 0x1F4), ao Convidado
/// (0x1F5) e ao alias Administradores (0x220; a 0x201B é a de uma edição
/// Home, com o VER_SUITE_PERSONAL que o kernel não anuncia).
const ADMINISTRATOR_MESSAGE: u32 = 0x2000;
const GUEST_MESSAGE: u32 = 0x2001;
const ADMINISTRATORS_MESSAGE: u32 = 0x2005;

/// Os nomes do banco novo que o comando usa.
pub struct BuiltinNames {
    pub administrators: String,
    pub administrator: String,
    pub guest: String,
}

/// O `CmdLine` do gancho: cria a conta, põe no grupo Administradores,
/// desabilita as contas embutidas e volta o gancho, nessa ordem (com `&`
/// cada parte roda mesmo se a anterior falhar).
pub fn setup_command(names: &BuiltinNames) -> Result<String, String> {
    let administrators = argument(&names.administrators)?;
    let administrator = argument(&names.administrator)?;
    let guest = argument(&names.guest)?;
    let command = format!(
        "cmd /d /c net user {ACCOUNT_NAME} /add\
         &net localgroup {administrators} {ACCOUNT_NAME} /add\
         &net user {administrator} /active:no\
         &net user {guest} /active:no\
         &reg add HKLM\\SYSTEM\\Setup /v SetupType /t REG_DWORD /d 0 /f\
         &reg add HKLM\\SYSTEM\\Setup /v CmdLine /d \"\" /f"
    );
    let length = command.encode_utf16().count();
    if length > COMMAND_LINE_MAX {
        return Err(format!("--conta-de-teste: comando com {length} caracteres (o winlogon le ate {COMMAND_LINE_MAX}): {command}"));
    }
    Ok(command)
}

/// O `CmdLine` do gancho sem a conta de teste (`--desligar-contas-embutidas`
/// e o `run` do boot do smss): só desabilita o Administrador e o Convidado
/// internos e volta o gancho. O estado final do SAM é o que o Setup do
/// Windows deixa ao aplicar o modelo de segurança `inf\defltbase.inf`
/// (EnableAdminAccount = 0 e EnableGuestAccount = 0, pelo scesrv até o
/// SamSetInformationUser com USER_ACCOUNT_DISABLED); o banco que o samsrv
/// cria no primeiro boot só os desabilitaria pela consulta de licença
/// cifrada do ShouldDisableAccountByDefault (NtQuerySystemInformation 134),
/// que o OpenNT não responde. Rodar o próprio modelo pelo secedit.exe (o
/// scecli, o scesrv no lsass e o banco ESE dele) é a alternativa mais fiel.
pub fn builtin_accounts_command(names: &BuiltinNames) -> Result<String, String> {
    let administrator = argument(&names.administrator)?;
    let guest = argument(&names.guest)?;
    let command = format!(
        "cmd /d /c net user {administrator} /active:no\
         &net user {guest} /active:no\
         &reg add HKLM\\SYSTEM\\Setup /v SetupType /t REG_DWORD /d 0 /f\
         &reg add HKLM\\SYSTEM\\Setup /v CmdLine /d \"\" /f"
    );
    let length = command.encode_utf16().count();
    if length > COMMAND_LINE_MAX {
        return Err(format!("--desligar-contas-embutidas: comando com {length} caracteres (o winlogon le ate {COMMAND_LINE_MAX}): {command}"));
    }
    Ok(command)
}

/// Um nome como argumento do cmd: entre aspas com espaço ou um caractere
/// especial do cmd; aspas, `%` e caracteres de controle não passam.
fn argument(name: &str) -> Result<String, String> {
    if name.is_empty() || name.chars().any(|character| character == '"' || character == '%' || character.is_control()) {
        return Err(format!("--conta-de-teste: o nome {name:?} nao passa pela linha do cmd"));
    }
    let special = name.chars().any(|character| character.is_whitespace() || "&|<>^()".contains(character));
    Ok(if special { format!("\"{name}\"") } else { String::from(name) })
}

/// A chave `Setup` da SYSTEM com o gancho: entra depois das de
/// `cm/setup_state.rs` e troca só o `SetupType` (REG_DWORD 2) e o `CmdLine`
/// (REG_SZ).
pub fn system_keys(command: &str) -> Vec<HostKey> {
    let text: Vec<u8> = command.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect();
    vec![HostKey {
        path: String::from("Setup"),
        values: vec![(String::from("SetupType"), 4, 2u32.to_le_bytes().to_vec()), (String::from("CmdLine"), 1, text)],
    }]
}

/// Os nomes do banco que o samsrv.dll do convidado cria, das mensagens do
/// `.mui` dele no primeiro idioma em que o lsass (SYSTEM, perfil
/// `.DEFAULT`) o procura.
pub fn builtin_names() -> Result<BuiltinNames, String> {
    let system32 = crate::windows_binaries::windows_directory().join("System32");
    let mui = samsrv_mui(&system32).ok_or("--conta-de-teste: samsrv.dll.mui ausente nos idiomas desta maquina")?;
    let bytes = std::fs::read(&mui).map_err(|error| format!("{}: {error}", mui.display()))?;
    let table = crate::windows_binaries::pe_resource(&bytes, RT_MESSAGETABLE, 1).ok_or_else(|| format!("{}: sem RT_MESSAGETABLE", mui.display()))?;
    let name = |id: u32| samsrv_name(&table, id).ok_or_else(|| format!("{}: sem a mensagem {id:#x}", mui.display()));
    Ok(BuiltinNames { administrators: name(ADMINISTRATORS_MESSAGE)?, administrator: name(ADMINISTRATOR_MESSAGE)?, guest: name(GUEST_MESSAGE)? })
}

/// O `.mui` do samsrv.dll que o convidado carrega: o do primeiro idioma de
/// `MachinePreferredUILanguages` (o perfil do sistema, que `host_language`
/// copia), depois os idiomas de interface e os de fallback.
fn samsrv_mui(system32: &Path) -> Option<PathBuf> {
    let mut languages = machine_preferred_languages();
    for language in crate::host_language::ui_languages() {
        if !languages.iter().any(|known| known.eq_ignore_ascii_case(&language)) {
            languages.push(language);
        }
    }
    let fallbacks = crate::host_language::fallback_languages(&languages);
    crate::host_language::mui_files(system32, "samsrv.dll", &languages, &fallbacks).into_iter().next().map(|(_, source)| source)
}

fn machine_preferred_languages() -> Vec<String> {
    #[cfg(windows)]
    {
        use crate::host_language::registry;
        registry::strings(registry::USERS, ".DEFAULT\\Control Panel\\Desktop\\MuiCached", "MachinePreferredUILanguages")
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

/// O texto da mensagem `id` de uma MESSAGE_RESOURCE_DATA e se ele é UTF-16:
/// os blocos [LowId, HighId, OffsetToEntries] e, em cada bloco, as
/// MESSAGE_RESOURCE_ENTRY em sequência (Length com o cabeçalho, Flags 1 =
/// UTF-16, o texto).
fn message_text(table: &[u8], id: u32) -> Option<(String, bool)> {
    let u16_at = |at: usize| Some(u16::from_le_bytes(table.get(at..at + 2)?.try_into().ok()?));
    let u32_at = |at: usize| Some(u32::from_le_bytes(table.get(at..at + 4)?.try_into().ok()?));
    for block in 0..u32_at(0)? as usize {
        let at = 4 + block * 12;
        let (low, high, mut entry) = (u32_at(at)?, u32_at(at + 4)?, u32_at(at + 8)? as usize);
        if !(low..=high).contains(&id) {
            continue;
        }
        for _ in low..id {
            entry += u16_at(entry)? as usize;
        }
        let (length, flags) = (u16_at(entry)? as usize, u16_at(entry + 2)?);
        let text = table.get(entry + 4..entry + length)?;
        let unicode = flags & 1 != 0;
        let text = if unicode {
            let units: Vec<u16> = text.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
            String::from_utf16(&units).ok()?
        } else {
            text.iter().map(|&byte| byte as char).collect()
        };
        return Some((String::from(text.trim_end_matches('\0')), unicode));
    }
    None
}

/// O nome como o SampFindMessageWrapper do samsrv o tira da mensagem: o
/// texto UTF-16 sem os dois caracteres do fim (o CR LF).
fn samsrv_name(table: &[u8], id: u32) -> Option<String> {
    let (text, unicode) = message_text(table, id)?;
    text.strip_suffix("\r\n").filter(|name| unicode && !name.is_empty()).map(String::from)
}

#[cfg(test)]
mod tests {
    use super::{builtin_accounts_command, message_text, samsrv_name, setup_command, system_keys, BuiltinNames, COMMAND_LINE_MAX};

    fn portuguese() -> BuiltinNames {
        BuiltinNames { administrators: "Administradores".into(), administrator: "Administrador".into(), guest: "Convidado".into() }
    }

    /// O comando de um convidado em português, inteiro: cria a conta, põe
    /// em Administradores, desabilita as embutidas e volta o gancho, dentro
    /// do buffer do winlogon e sem senha nenhuma.
    #[test]
    fn the_command_creates_the_account_and_resets_the_hook() {
        let command = setup_command(&portuguese()).unwrap();
        assert_eq!(
            command,
            "cmd /d /c net user Usuario /add&net localgroup Administradores Usuario /add&net user Administrador /active:no&net user Convidado /active:no&reg add HKLM\\SYSTEM\\Setup /v SetupType /t REG_DWORD /d 0 /f&reg add HKLM\\SYSTEM\\Setup /v CmdLine /d \"\" /f"
        );
        assert_eq!(command.encode_utf16().count(), 245);
        assert!(command.encode_utf16().count() <= COMMAND_LINE_MAX);
    }

    /// Sem a conta, o comando só desabilita as embutidas e volta o gancho.
    #[test]
    fn the_builtin_accounts_command_only_disables_them() {
        assert_eq!(
            builtin_accounts_command(&portuguese()).unwrap(),
            "cmd /d /c net user Administrador /active:no&net user Convidado /active:no&reg add HKLM\\SYSTEM\\Setup /v SetupType /t REG_DWORD /d 0 /f&reg add HKLM\\SYSTEM\\Setup /v CmdLine /d \"\" /f"
        );
    }

    /// Nome com espaço vai entre aspas; aspas e `%` não passam; um comando
    /// acima de 259 caracteres é recusado.
    #[test]
    fn names_are_quoted_or_refused() {
        let mut names = portuguese();
        names.administrators = "Admin Group".into();
        assert!(setup_command(&names).unwrap().contains("net localgroup \"Admin Group\" Usuario /add"));
        names.administrators = "A\"B".into();
        assert!(setup_command(&names).is_err());
        names.administrators = "%PATH%".into();
        assert!(setup_command(&names).is_err());
        names.administrators = "X".repeat(40);
        assert!(setup_command(&names).is_err());
    }

    /// O gancho são só os dois valores, com os tipos que o winlogon lê.
    #[test]
    fn the_hook_is_setup_type_2_and_the_command_line() {
        let keys = system_keys("cmd /d /c echo");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].path, "Setup");
        let command: Vec<u8> = "cmd /d /c echo".encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect();
        assert_eq!(keys[0].values, vec![(String::from("SetupType"), 4, vec![2, 0, 0, 0]), (String::from("CmdLine"), 1, command)]);
    }

    /// Uma MESSAGE_RESOURCE_DATA montada aqui: o nome é o texto UTF-16 sem
    /// o CR LF, uma mensagem ANSI ou fora dos blocos não dá nome.
    #[test]
    fn the_name_is_the_message_without_cr_lf() {
        let entry = |text: &str, unicode: bool| -> Vec<u8> {
            let mut body: Vec<u8> = if unicode { text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect() } else { text.bytes().chain([0]).collect() };
            body.resize(body.len().next_multiple_of(4), 0);
            let mut bytes = ((body.len() + 4) as u16).to_le_bytes().to_vec();
            bytes.extend_from_slice(&(unicode as u16).to_le_bytes());
            bytes.extend(body);
            bytes
        };
        let mut table = Vec::new();
        table.extend_from_slice(&1u32.to_le_bytes());
        table.extend_from_slice(&0x2000u32.to_le_bytes());
        table.extend_from_slice(&0x2002u32.to_le_bytes());
        table.extend_from_slice(&16u32.to_le_bytes());
        table.extend(entry("Administrador\r\n", true));
        table.extend(entry("Convidado\r\n", true));
        table.extend(entry("Ansi\r\n", false));
        assert_eq!(samsrv_name(&table, 0x2000).as_deref(), Some("Administrador"));
        assert_eq!(samsrv_name(&table, 0x2001).as_deref(), Some("Convidado"));
        assert_eq!(message_text(&table, 0x2002), Some((String::from("Ansi\r\n"), false)));
        assert_eq!(samsrv_name(&table, 0x2002), None);
        assert_eq!(samsrv_name(&table, 0x2003), None);
    }

    /// Nesta máquina os nomes vêm do samsrv.dll.mui e o comando cabe.
    #[cfg(windows)]
    #[test]
    fn this_machine_gives_the_names_from_samsrv() {
        let names = super::builtin_names().unwrap();
        assert!(!names.administrators.is_empty() && !names.administrator.is_empty() && !names.guest.is_empty());
        setup_command(&names).unwrap();
    }
}
