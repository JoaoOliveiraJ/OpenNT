//! As pastas que uma instalação nova do Windows 10 19041 cria na raiz da
//! unidade do sistema e em `\Windows`, com os atributos e o descritor de
//! cada uma, para o volume do boot do smss (`host_security::system_nodes`).
//!
//! A lista, os atributos e os descritores são os que os manifestos dos
//! componentes do Windows (`WinSxS\Manifests`, versões 10.0.19041) declaram: o
//! `<directory destinationPath=...>` e o `securityDescriptorDefinition` que
//! ele nomeia, com o SDDL no texto do manifesto. As pastas sem descritor no
//! manifesto, e as que só aparecem como destino dos arquivos de um componente,
//! herdam da pasta pai. Nenhuma depende de esta máquina a ter, e nada do
//! conteúdo delas vem daqui.
//!
//! Um SDDL sem `O:` e `G:` tem o dono e o grupo SYSTEM, e um sem `D:` herda a
//! DACL: é o que o instalador de componentes põe no que falta
//! (ApplySecurityToObjectWithDefaults do wcp.dll 10.0.19041.1, 0x109b7c, com
//! o GetSystemSid, chamado pelo CFileInstallerHierarchy::
//! CommitDirectoryChanges, 0x107a8c). Uma DACL não protegida herda da pasta
//! pai, como o CommitDirectoryChanges faz.
//!
//! Os componentes são os do cliente padrão: os alcançados a partir do pacote
//! da edição (Microsoft-Windows-ProfessionalEdition) e do pacote de idioma do
//! cliente pelos pacotes de `servicing\Packages`, com cada recurso opcional
//! no estado padrão dele. Ficam de fora as pastas cujo componente nenhum
//! desses pacotes lista (`addins`, `AppReadiness`, `Migration`, `OCR`), as que
//! só um recurso opcional ou uma atualização acrescenta (`inetpub`, `ADAM`,
//! `Application Compatibility Scripts`, `SystemTemp`, `InboxApps`), o SysWOW64
//! (o `--wow64` o põe com os binários), as que o Setup cria e nenhum manifesto
//! declara (`assembly`, `CbsTemp`, `Panther`, `Setup`, `SoftwareDistribution`,
//! `System`, `TextInput`), as que o sistema cria quando precisa (`System
//! Volume Information`, `Recovery`), e a junção `Documents and Settings` (um
//! ponto de reanálise, que o volume ainda não grava).

/// FILE_ATTRIBUTE_READONLY, _HIDDEN, _SYSTEM, _DIRECTORY e
/// _NOT_CONTENT_INDEXED.
const READ_ONLY: u32 = 0x1;
const HIDDEN: u32 = 0x2;
const SYSTEM: u32 = 0x4;
const FOLDER: u32 = 0x10;
const NOT_INDEXED: u32 = 0x2000;

/// Uma pasta: o caminho na unidade, os atributos e o descritor em SDDL
/// (vazio, o herdado da pasta pai).
pub struct StockFolder {
    pub path: &'static str,
    pub attributes: u32,
    pub sddl: &'static str,
}

const fn folder(path: &'static str, attributes: u32, sddl: &'static str) -> StockFolder {
    StockFolder { path, attributes: FOLDER | attributes, sddl }
}

/// WRP_CLIENT_ROOT_DIR_DEFAULT_SDDL (Microsoft-Windows-ClientRootSecurity
/// 10.0.19041.1): a raiz da unidade do sistema.
pub const ROOT: &str = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:P(A;OICI;GA;;;BA)(A;OICI;GA;;;SY)(A;OICI;0x1200a9;;;BU)(A;OICIIO;SDGXGWGR;;;AU)(A;;0x4;;;AU)S:P(ML;OINPIO;NW;;;HI)";

/// WRP_PARENT_DIR_DEFAULT_SDDL: o TrustedInstaller manda na pasta, o SYSTEM
/// e os Administradores só no que está dentro.
const PARENT_DIR: &str = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:P(A;CI;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1301bf;;;SY)(A;IOCIOI;GA;;;SY)(A;;0x1301bf;;;BA)(A;IOCIOI;GA;;;BA)(A;CIOI;GRGX;;;BU)(A;OICIIO;GA;;;CO)(A;CIOI;GRGX;;;S-1-15-2-1)(A;CIOI;GRGX;;;S-1-15-2-2)";

/// WRP_DIR_DEFAULT_SDDL: só o TrustedInstaller escreve.
const DIR: &str = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:P(A;CIOI;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIOI;GRGX;;;SY)(A;CIOI;GRGX;;;BA)(A;CIOI;GRGX;;;BU)(A;CIOI;GRGX;;;S-1-15-2-1)(A;CIOI;GRGX;;;S-1-15-2-2)S:(AU;FASA;SDWDWOFW;;;WD)";

/// O `System32\winevt` (WinEVT-FS-Security, Microsoft-Windows-EventLog) e o
/// `Logs` dele (WinEVT-FS-Logs-Security,
/// Microsoft-Windows-EventLog-RequiredConfiguration): o serviço EventLog.
const EVENT_LOG: &str = "D:P(A;CIOI;DTFRFWFX;;;S-1-5-80-880578595-1860270145-482643319-2788375705-1540778122)(A;CIOI;FA;;;SY)(A;CIOI;FA;;;BA)(A;CI;FR;;;AU)";
const EVENT_LOGS: &str = "D:P(A;CIOI;FA;;;S-1-5-80-880578595-1860270145-482643319-2788375705-1540778122)(A;CIOI;FA;;;SY)(A;CIOI;FA;;;BA)(A;CI;FR;;;AU)";

pub const FOLDERS: &[StockFolder] = &[
    // A raiz. O `$Recycle.Bin` é do Microsoft-Windows-Explorer, o `PerfLogs`
    // do Microsoft-Windows-PerformanceCounterInfrastructureConsumer, o
    // `ProgramData` do Microsoft-Windows-ProfApi-OneCore; o `Program Files`
    // e o `Program Files (x86)` têm o descritor do
    // Microsoft-Windows-Foundation-Default-Security e o atributo do
    // Microsoft-Windows-Shell32.
    folder("$Recycle.Bin", HIDDEN | SYSTEM, "D:P(A;CIOI;GA;;;BA)(A;CIOI;GA;;;SY)(A;NP;0x001201AD;;;BU)S:(ML;CIOIIO;1;;;LW)"),
    folder("PerfLogs", 0, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OI;0x1200af;;;LU)"),
    folder("Program Files", READ_ONLY, PARENT_DIR),
    folder("Program Files (x86)", READ_ONLY, PARENT_DIR),
    folder("ProgramData", HIDDEN | NOT_INDEXED, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;GA;;;CO)(A;OICI;0x1200a9;;;BU)(A;CI;DCLCRPCR;;;BU)"),
    // `\Windows`.
    folder("Windows/appcompat", 0, ""),
    folder("Windows/apppatch", 0, PARENT_DIR),
    folder("Windows/bcastdvr", 0, PARENT_DIR),
    folder("Windows/Boot", 0, DIR),
    folder("Windows/Branding", 0, PARENT_DIR),
    folder("Windows/Containers", 0, ""),
    folder("Windows/CSC", 0, ""),
    folder("Windows/Cursors", 0, PARENT_DIR),
    // WINDOWS_DEBUG_DIRECTORY_SDDL.
    folder("Windows/debug", 0, "D:AI(D;CIOI;FA;;;S-1-15-2-1)"),
    folder("Windows/diagnostics", 0, DIR),
    folder("Windows/DiagTrack", 0, PARENT_DIR),
    folder("Windows/DigitalLocker", 0, ""),
    folder("Windows/Downloaded Program Files", SYSTEM, PARENT_DIR),
    folder("Windows/ELAMBKUP", HIDDEN, PARENT_DIR),
    folder("Windows/en-US", 0, PARENT_DIR),
    folder("Windows/GameBarPresenceWriter", 0, PARENT_DIR),
    folder("Windows/Globalization", 0, PARENT_DIR),
    folder("Windows/Help", 0, ""),
    folder("Windows/IdentityCRL", 0, ""),
    folder("Windows/IME", 0, PARENT_DIR),
    folder("Windows/ImmersiveControlPanel", READ_ONLY, PARENT_DIR),
    folder("Windows/InputMethod", 0, ""),
    // WINDOWS_INSTALLER_DIR_SDDL.
    folder("Windows/Installer", HIDDEN, "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;WD)(A;OICI;FA;;;BA)"),
    folder("Windows/L2Schemas", 0, PARENT_DIR),
    // LXP_FILE_SDDL (o serviço LanguageComponentsInstaller manda na pasta).
    folder("Windows/LanguageOverlayCache", HIDDEN, "D:PAI(A;OICI;0x1200a9;;;BA)(A;OICI;GXGR;;;BA)(A;OICI;0x1200a9;;;SY)(A;OICI;GXGR;;;SY)(A;OICI;0x1200a9;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;OICI;GXGR;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;OICI;0x1200a9;;;BU)(A;OICI;GXGR;;;BU)(A;OICI;0x1200a9;;;AC)(A;OICI;GXGR;;;AC)(A;OICI;0x1200a9;;;S-1-15-2-2)(A;OICI;GXGR;;;S-1-15-2-2)(A;CIOI;GA;;;S-1-5-80-1594061079-2000966165-462148798-751814865-2644087104)"),
    // WRP_ADMIN_SYSTEM.
    folder("Windows/LiveKernelReports", 0, "D:P(A;OICI;GA;;;BA)(A;OICI;GA;;;SY)"),
    folder("Windows/Media", READ_ONLY | SYSTEM, PARENT_DIR),
    folder("Windows/Microsoft.NET", 0, PARENT_DIR),
    // UnimodemLogDirSddl.
    folder("Windows/ModemLogs", 0, "D:PAR(A;OICI;SDGRGW;;;NS)(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)"),
    folder("Windows/Offline Web Pages", READ_ONLY, PARENT_DIR),
    folder("Windows/Performance", 0, PARENT_DIR),
    folder("Windows/PLA", 0, ""),
    folder("Windows/PolicyDefinitions", 0, PARENT_DIR),
    // AdminGroupOnlyNoInherit.
    folder("Windows/Prefetch", 0, "D:PAI(A;OICI;GA;;;BA)"),
    folder("Windows/PrintDialog", READ_ONLY, PARENT_DIR),
    folder("Windows/Provisioning", 0, PARENT_DIR),
    // ComRegistrationDirectorySecurity.
    folder("Windows/Registration", 0, "O:BAG:SYD:PAI(A;OI;FA;;;BA)(A;OI;0x1200A9;;;WD)(A;OI;FA;;;SY)"),
    // ADMIN_MS_WRITE_USERS_ES_RA_READ.
    folder("Windows/RemotePackages", 0, "D:(A;CI;GA;;;SY)(A;CI;GA;;;BA)(A;OICI;GRGX;;;AU)(A;CI;GA;;;S-1-5-32-577)(A;CI;GRGX;;;S-1-5-32-576)(A;CI;GRGX;;;S-1-5-32-575)"),
    folder("Windows/rescache", 0, DIR),
    folder("Windows/Resources", 0, PARENT_DIR),
    folder("Windows/SchCache", 0, ""),
    folder("Windows/schemas", 0, PARENT_DIR),
    folder("Windows/security", 0, PARENT_DIR),
    // SERVICE_FILE_STATE_ROOT_SDDL.
    folder("Windows/ServiceState", 0, "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FR;;;BA)(A;CI;WP;;;BA)(A;OICI;FR;;;UD)(A;CI;WP;;;UD)(A;CI;WP;;;SU)"),
    folder("Windows/servicing", 0, DIR),
    folder("Windows/ShellComponents", 0, PARENT_DIR),
    folder("Windows/ShellExperiences", 0, PARENT_DIR),
    folder("Windows/SKB", 0, PARENT_DIR),
    folder("Windows/Speech", 0, PARENT_DIR),
    folder("Windows/Speech_OneCore", 0, PARENT_DIR),
    folder("Windows/System32/winevt", 0, EVENT_LOG),
    folder("Windows/System32/winevt/Logs", 0, EVENT_LOGS),
    folder("Windows/System32/winevt/TraceFormat", 0, ""),
    folder("Windows/SystemResources", 0, DIR),
    // TapiSrvPublicSddl.
    folder("Windows/TAPI", 0, "D:PAR(A;OICI;GA;;;S-1-5-80-4230913304-2206818457-801678004-120036174-1892434133)(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GR;;;BU)"),
    // CompatibilityTasksFolderACL.
    folder("Windows/Tasks", 0, "D:P(A;;0x1200ab;;;AU)(A;CIOI;GA;;;BA)(A;CIOI;GA;;;SY)(A;CIOI;GA;;;CO)"),
    // ComPlusUserSDDL.
    folder("Windows/Temp", 0, "D:P(A;CI;0x100026;;;BU)(A;CIOI;GA;;;BA)(A;CIOI;GA;;;SY)(A;CIOIIO;GA;;;CO)"),
    // RTUTILS_FOLDER_TRACING.
    folder("Windows/tracing", 0, "D:P(A;OICI;GRGWGX;;;LS)(A;OICI;GRGWGX;;;NS)(A;OICI;FA;;;SY)(A;CI;GRGXGW;;;BU)(A;OI;GRGW;;;BU)(A;CI;GRGXGWSD;;;BA)(A;OI;GRGWSD;;;BA)"),
    folder("Windows/twain_32", 0, PARENT_DIR),
    // VssMetadataStoreSecurity (as ACEs herdadas do texto são as do
    // `\Windows`, que a herança refaz).
    folder("Windows/Vss", 0, "D:(A;OICI;FA;;;BO)(A;OICI;FA;;;LS)(A;OICI;FA;;;NS)(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)"),
    folder("Windows/WaaS", 0, DIR),
    folder("Windows/Web", 0, PARENT_DIR),
];
