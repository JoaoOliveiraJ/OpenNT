//! Configuração de boot: as opções de carga que o loader entrega
//! (`load_options.rs`), lidas uma vez na entrada do kernel, antes de qualquer
//! outra CPU ou thread existir, e só lidas depois disso. Sem o bloco do
//! loader, o boot segue sem opções (o boot comum, com o shell).

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::load_options::{self as name, BLOCK_SIZE, TEXT_MAX};
use crate::ntos::mm::memory_map;

const _: () = assert!(memory_map::BOOT_LOAD_OPTIONS_PHYS == name::STAGE2_LOAD_ADDRESS + (name::SECTOR as u64 - 1) * 512);

/// O texto das opções, copiado do bloco do loader.
struct Text(UnsafeCell<[u8; TEXT_MAX]>);

// SAFETY: `capture` grava o texto uma vez, no BSP, antes de qualquer leitura
// e de qualquer outra CPU; depois dele o texto só é lido.
unsafe impl Sync for Text {}

static TEXT: Text = Text(UnsafeCell::new([0; TEXT_MAX]));
/// Tamanho do texto válido em [`TEXT`], publicado depois da cópia.
static LENGTH: AtomicUsize = AtomicUsize::new(0);
/// `TRACERPC`, decidido no [`capture`]: o ALPC consulta a opção a cada
/// mensagem, e o boot sem ela paga só a leitura desta célula.
static TRACE_RPC: AtomicBool = AtomicBool::new(false);

/// Copia as opções do bloco que o setor de boot deixou em
/// `BOOT_LOAD_OPTIONS_PHYS` (a memória baixa ainda é a do loader). Chamada
/// uma vez, na entrada do kernel.
pub fn capture() {
    let mut block = [0u8; BLOCK_SIZE];
    for (offset, byte) in block.iter_mut().enumerate() {
        *byte = crate::hal::physical::read8(memory_map::BOOT_LOAD_OPTIONS_PHYS + offset as u64);
    }
    let Some(text) = name::text_of(&block) else { return };
    // SAFETY: ninguém lê o texto antes de LENGTH ser publicado, e esta é a
    // única escrita (ver `Text`).
    unsafe { (&mut *TEXT.0.get())[..text.len()].copy_from_slice(text.as_bytes()) };
    LENGTH.store(text.len(), Ordering::Release);
    TRACE_RPC.store(flag(name::TRACE_RPC), Ordering::Relaxed);
}

/// O texto das opções de carga deste boot (vazio sem o bloco).
pub fn load_options() -> &'static str {
    let length = LENGTH.load(Ordering::Acquire);
    // SAFETY: os `length` primeiros bytes já foram gravados por `capture`
    // (ASCII validado por `text_of`) e não mudam mais.
    let bytes = unsafe { &(&*TEXT.0.get())[..length] };
    core::str::from_utf8(bytes).unwrap_or("")
}

fn value(option: &str) -> Option<&'static str> {
    name::value(load_options(), option)
}

fn flag(option: &str) -> bool {
    name::flag(load_options(), option)
}

/// `USERPROGRAM` (`--user-program`): programa iniciado depois do boot
/// (`shell` por padrão).
pub fn user_program() -> &'static str {
    value(name::USER_PROGRAM).unwrap_or("shell")
}

/// `KERNELTESTSCOPE` (`--kernel-test-scope`): `none` no boot comum; `all`
/// roda o autoteste.
pub fn kernel_test_scope() -> &'static str {
    value(name::KERNEL_TEST_SCOPE).unwrap_or("none")
}

/// O boot roda o autoteste (`KERNELTESTSCOPE` diferente de `none`).
pub fn kernel_tests() -> bool {
    kernel_test_scope() != "none"
}

/// `STARTDRIVER` (`--start-driver`): serviços de driver iniciados pelo SCM
/// antes do programa de usuário, separados por vírgula e na ordem dada, com
/// a CI fiscalizando as cargas (vazio = nenhum).
pub fn start_driver() -> &'static str {
    value(name::START_DRIVER).unwrap_or("")
}

/// `TRACEDRIVERAPI` (`--trace-driver-api`): imprime cada chamada de API do
/// driver de `--start-driver` enquanto ele inicia.
pub fn trace_driver_api() -> bool {
    flag(name::TRACE_DRIVER_API)
}

/// `TRACERPC` (`--trace-rpc`): cada mensagem ALPC das portas de servidor vai
/// para a serial, com a interface e o opnum dos pedidos LRPC e o status das
/// respostas (`alpc/rpc_trace`).
pub fn trace_rpc() -> bool {
    TRACE_RPC.load(Ordering::Relaxed)
}

/// `SLOWSERVICEEXIT` (`--slow-service-exit`): toda saída de serviço passa
/// pelo despachante (`threads::may_return_to_user` sempre recusa), como antes
/// da volta direta ao anel 3: a comparação e a bissecção dela.
pub fn slow_service_exit() -> bool {
    // Consultada em toda saída de serviço: a opção lida uma vez.
    static CACHED: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
    match CACHED.load(Ordering::Relaxed) {
        0 => {
            let value = flag(name::SLOW_SERVICE_EXIT);
            CACHED.store(1 + value as u8, Ordering::Relaxed);
            value
        }
        cached => cached == 2,
    }
}

/// `HEAPCENSUS` (`--heap-census`): o censo do heap do kernel
/// (`hal::heap_census`) vai para a serial a cada 4 MB a mais de uso.
pub fn heap_census() -> bool {
    flag(name::HEAP_CENSUS)
}

/// `OPENNT_TRACE_SYSCALLS` no ambiente do build: imprime cada serviço de
/// modo usuário despachado, com os argumentos e o resultado (diagnóstico).
pub const TRACE_SYSCALLS: bool = option_env!("OPENNT_TRACE_SYSCALLS").is_some();

/// `CONSOLEMIRROR` (`--console-mirror`): espelha o texto do console na
/// serial.
pub fn console_serial_mirror() -> bool {
    flag(name::CONSOLE_MIRROR)
}

/// `INITIALPROCESS=smss` (`--initial-process=smss`): o kernel inicia o
/// smss.exe real como o primeiro processo de usuário
/// (`init/initial_process.rs`), com o CSR emulado e o `\KnownDlls` do kernel
/// desligados; vazio no boot comum.
pub fn initial_process() -> &'static str {
    value(name::INITIAL_PROCESS).unwrap_or("")
}

/// `SHUTDOWNTEST=poweroff|reboot` (`--shutdown-test`): depois do
/// `--start-driver=ntfs`, o teste do desligamento (`ntos/test/shutdown.rs`)
/// grava pelo ntfs.sys e no Registro e chama o NtShutdownSystem com essa
/// ação; no boot seguinte confere o que sobreviveu e desliga (vazio = sem o
/// teste).
pub fn shutdown_test() -> &'static str {
    value(name::SHUTDOWN_TEST).unwrap_or("")
}

/// `CONSOLEPROCESS` (`--console-process`): no boot comum, depois do
/// `--start-driver`, o cmd.exe real com um console sem janela, pelo
/// condrv.sys e pelo conhost.exe reais (`ntos/test/console_process.rs`).
pub fn console_process() -> bool {
    flag(name::CONSOLE_PROCESS)
}

/// O boot do processo inicial real (`--initial-process=smss`).
pub fn smss_boot() -> bool {
    initial_process() == "smss"
}

/// `DEBUG DEBUGPORT=COM2` (`--kd=com2`; ou `COM3`, `COM4`): o depurador do
/// kernel atende um host pelo protocolo remoto do GDB nessa porta serial
/// (`ntos::kd`); vazio = sem depurador, como um boot do Windows sem /DEBUG.
pub fn kernel_debugger() -> &'static str {
    if flag(name::DEBUG) {
        value(name::DEBUG_PORT).unwrap_or("")
    } else {
        ""
    }
}

/// `STORAGE=real` (`--storage=real`): a pilha de armazenamento do Windows
/// sobe pelo PnP.
pub fn real_storage() -> bool {
    value(name::STORAGE) == Some("real")
}

/// `STORAGE=nvme` (`--storage=nvme`): o storport.sys com o stornvme.sys sobem
/// pelo PnP no controlador NVMe do QEMU.
pub fn nvme_storage() -> bool {
    value(name::STORAGE) == Some("nvme")
}

/// `DISPLAY=basic` (`--display=basic`): o PnP instala o BasicDisplay.sys real
/// no adaptador VGA.
pub fn basic_display() -> bool {
    value(name::DISPLAY) == Some("basic")
}

/// A raiz da árvore de dispositivos é o acpi.sys real sobre a HAL, o padrão;
/// `PNPROOT=internal` (`--pnp-root=internal`) volta ao barramento PCI
/// interno do kernel.
pub fn acpi_root() -> bool {
    value(name::PNP_ROOT) != Some("internal")
}

/// `USB` (`--usb`): a máquina tem a controladora xHCI com teclado e tablet
/// USB, e o PnP sobe a pilha USB 3 e HID real sobre ela.
pub fn usb() -> bool {
    flag(name::USB)
}

/// `NET` (`--net`): a máquina tem a placa de rede e1000 com a rede de modo
/// usuário do QEMU, e o PnP sobe nela o miniport da Intel, com o NDIS e o
/// TCP/IP reais.
pub fn network() -> bool {
    flag(name::NET)
}

/// `TPM` (`--tpm`): a máquina tem um TPM 2.0 com interface CRB; o tpm.sys
/// real sobe pelo PnP no ACPI\MSFT0101 e o kernel confere uma ida e volta de
/// comandos pelo tbs.sys (`drivers/security/tpm_stack.rs`).
pub fn tpm() -> bool {
    flag(name::TPM)
}

/// `MEMORYPRESSURE` (`--memory-pressure`): depois que o smss cria o arquivo
/// de paginação, um programa de usuário comita mais memória que a RAM e a
/// relê (`test/memory_pressure.rs`).
pub fn memory_pressure_test() -> bool {
    flag(name::MEMORY_PRESSURE)
}
