//! Opções de carga: o texto que o loader entrega ao kernel em cada boot, como
//! o LoadOptions do LOADER_PARAMETER_BLOCK que o winload monta das opções do
//! BCD (`DEBUG DEBUGPORT=COM2`, sem as barras). São palavras separadas por
//! espaço, `NOME` ou `NOME=valor`; o nome não distingue maiúsculas e o valor
//! fica como foi escrito. Um nome repetido vale pela primeira ocorrência.
//!
//! O bloco ocupa o último setor da reserva do stage2 na imagem de boot
//! ([`SECTOR`]): o setor de boot carrega os 64 setores do stage2 a partir de
//! 0x7E00, então o bloco chega à memória em
//! `memory_map::BOOT_LOAD_OPTIONS_PHYS`, onde o kernel o lê ao entrar
//! (`init/boot_config.rs`). Sem a assinatura, o boot segue sem opções.
//!
//! O `cargo xtask` inclui este arquivo (`#[path]`) e monta o bloco com os
//! mesmos nomes e o mesmo formato.

/// Assinatura do bloco ('LOP1').
pub const SIGNATURE: u32 = 0x3150_4F4C;
/// O bloco: assinatura (u32), tamanho do texto (u32) e o texto ASCII.
pub const BLOCK_SIZE: usize = 512;
pub const HEADER_SIZE: usize = 8;
/// Maior texto que cabe no bloco.
pub const TEXT_MAX: usize = BLOCK_SIZE - HEADER_SIZE;
/// LBA do bloco na imagem de boot: o último dos 64 setores do stage2
/// (LBA 1..64), que o stage2 não ocupa.
pub const SECTOR: usize = 64;
/// Endereço físico em que o setor de boot deixa o stage2 (LBA 1).
pub const STAGE2_LOAD_ADDRESS: u64 = 0x7E00;

/// `DEBUG DEBUGPORT=COMn`: o depurador do kernel nessa porta serial.
pub const DEBUG: &str = "DEBUG";
pub const DEBUG_PORT: &str = "DEBUGPORT";
/// O programa iniciado depois do boot (`shell` sem a opção).
pub const USER_PROGRAM: &str = "USERPROGRAM";
/// O autoteste do kernel: `all` ou `disk-stress` (`none` sem a opção).
pub const KERNEL_TEST_SCOPE: &str = "KERNELTESTSCOPE";
/// Serviços de driver iniciados pelo SCM antes do programa, em ordem.
pub const START_DRIVER: &str = "STARTDRIVER";
/// Cada chamada de API dos drivers iniciados no boot vai para a serial.
pub const TRACE_DRIVER_API: &str = "TRACEDRIVERAPI";
/// Cada mensagem ALPC das portas de servidor vai para a serial, com a
/// interface e o opnum dos pedidos LRPC (`alpc/rpc_trace`).
pub const TRACE_RPC: &str = "TRACERPC";
/// O censo do heap do kernel (`hal::heap_census`) vai para a serial cada
/// vez que o uso passa um múltiplo novo de 4 MB.
pub const HEAP_CENSUS: &str = "HEAPCENSUS";
/// Toda saída de serviço passa pelo despachante (a volta direta ao anel 3,
/// o KiSystemServiceExit, desligada): para isolar um problema nela.
pub const SLOW_SERVICE_EXIT: &str = "SLOWSERVICEEXIT";
/// Os APs armam o anel 3 no boot (a GDT, a TSS, a IDT, os MSRs de syscall e
/// o timer local de cada um) e esperam no laço ocioso deles, com as
/// interrupções ligadas (`ke::smp::start_scheduling`).
pub const USER_SMP: &str = "USERSMP";
/// O texto do console também vai para a serial.
pub const CONSOLE_MIRROR: &str = "CONSOLEMIRROR";
/// `smss`: o primeiro processo de usuário é o smss.exe real.
pub const INITIAL_PROCESS: &str = "INITIALPROCESS";
/// `real`: a pilha de armazenamento do Windows sobe pelo PnP na controladora
/// IDE; `nvme`: o storport.sys com o stornvme.sys no controlador NVMe.
pub const STORAGE: &str = "STORAGE";
/// `ntfs.sys`: o volume do sistema é a partição do segundo disco IDE, servida
/// pela pilha de armazenamento real e pelo ntfs.sys (com `STORAGE=real`).
pub const SYSTEM_VOLUME: &str = "SYSTEMVOLUME";
/// `basic`: o BasicDisplay.sys real no adaptador VGA.
pub const DISPLAY: &str = "DISPLAY";
/// A raiz da árvore de dispositivos: `acpi` (o acpi.sys real, o padrão) ou
/// `internal` (o barramento PCI interno do kernel).
pub const PNP_ROOT: &str = "PNPROOT";
/// `poweroff` ou `reboot`: o teste do desligamento depois do
/// `STARTDRIVER=ntfs`.
pub const SHUTDOWN_TEST: &str = "SHUTDOWNTEST";
/// A pilha USB 3 e HID real sobe pelo PnP na controladora xHCI.
pub const USB: &str = "USB";
/// A placa de rede Intel PRO/1000 (e1000) recebe o miniport real pelo PnP e
/// a pilha de rede do Windows (NDIS e TCP/IP) sobe sobre ela.
pub const NET: &str = "NET";
/// O teste de pressão de memória sobre o arquivo de paginação, no boot do
/// smss (`test/memory_pressure.rs`).
pub const MEMORY_PRESSURE: &str = "MEMORYPRESSURE";
/// A máquina tem um TPM 2.0 (tpm-crb do QEMU): o tpm.sys real sobe pelo PnP
/// e o kernel manda comandos a ele pelo tbs.sys.
pub const TPM: &str = "TPM";
/// O teste do processo de console de ponta a ponta no boot comum: o
/// cmd.exe real com um console sem janela (`test/console_process.rs`).
pub const CONSOLE_PROCESS: &str = "CONSOLEPROCESS";
/// O volume leva a camada WoW64 e os programas x86 de SysWOW64; com
/// `CONSOLEPROCESS`, o cmd.exe do console é o de 32 bits
/// (`test/console_process.rs`).
pub const WOW64: &str = "WOW64";
/// Toda linha `FALHOU` dos serviços de modo usuário vai para a serial; sem
/// a opção, cada (pid, serviço, status, chamador) sai nas quatro primeiras
/// vezes e depois uma a cada 256, com a contagem.
pub const TRACE_FAILURES: &str = "TRACEFAILURES";
/// Cada abertura de arquivo do volume e cada abertura ou consulta de
/// atributos de um caminho que não existe vão para a serial (`[usermode]
/// arquivo aberto:`, `[file-io] open absent:`, `[file-io] attributes
/// absent:`).
pub const TRACE_FILES: &str = "TRACEFILES";
/// `timer` ou `nmi`: o perfil por amostragem do processador de boot, pelo
/// tique do relógio ou pela NMI que o xtask injeta (`kd/sampler.rs`).
pub const PROFILE: &str = "PROFILE";

/// O valor de `NOME=valor`.
pub fn value<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.split_ascii_whitespace().filter_map(|word| word.split_once('=')).find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value)
}

/// A opção `NOME` sem valor está presente.
pub fn flag(text: &str, name: &str) -> bool {
    text.split_ascii_whitespace().any(|word| word.eq_ignore_ascii_case(name))
}

/// O texto de um bloco: assinatura certa, tamanho dentro do bloco e só ASCII
/// imprimível (espaço inclusive); senão, nenhum.
pub fn text_of(block: &[u8]) -> Option<&str> {
    let header = |at: usize| block.get(at..at + 4).map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
    if header(0)? != SIGNATURE {
        return None;
    }
    let length = header(4)? as usize;
    if length > TEXT_MAX {
        return None;
    }
    let text = block.get(HEADER_SIZE..HEADER_SIZE + length)?;
    if !text.iter().all(|&byte| byte == b' ' || byte.is_ascii_graphic()) {
        return None;
    }
    core::str::from_utf8(text).ok()
}
