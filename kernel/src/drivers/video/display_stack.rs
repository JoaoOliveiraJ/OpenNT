//! A pilha de vídeo real do Windows (`--display=basic`).
//!
//! Com a opção, na árvore de dispositivos do fim da fase 1
//! (`device_tree::build`, sobre o pci.sys real com a raiz ACPI ou o
//! barramento PCI interno) o adaptador VGA do QEMU (PCI\VEN_1234&
//! DEV_1111, classe 03.00) é instalado como no Windows: o display.inf dá o
//! serviço BasicDisplay a todo PCI\CC_0300 (seção MSBDA, classe Display). O
//! PnP carrega o BasicDisplay.sys real do repositório de drivers; o
//! DriverEntry dele carrega o dxgkrnl.sys real (ZwLoadDriver do DXGKrnl) e
//! se registra nele (DxgkInitialize pelo IOCTL interno do \Device\DxgKrnl),
//! e o dxgkrnl passa a ser o despacho do driver: o AddDevice (DpiAddDevice,
//! que cria o FDO de vídeo e chama o DxgkDdiAddDevice do miniport) e o
//! START_DEVICE (DpiFdoHandleStartDevice, que repassa o pedido ao PDO e
//! guarda as listas de recursos) vão a ele.
//!
//! O adaptador de renderização sobe igual, pela raiz: a instância
//! `ROOT\BasicRender\0000` (`seed_render_device`) é enumerada pela raiz do
//! PnP e instalada pelo basicrender.inf com o BasicRender.sys real, um
//! driver WDDM de renderização sem saída de vídeo. O dxgkrnl o reconhece
//! como o adaptador WARP pelo nome `\Driver\BasicRender` (DpiAddDevice); é
//! nele que o cdd.dll cria o dispositivo de renderização da sessão, e é ele
//! que leva o dxgkrnl a carregar o dxgmms2.sys quando o adaptador inicia.
//!
//! O dxgkrnl não inicia o adaptador no START_DEVICE do primeiro adaptador:
//! o início (DpiFdoStartAdapterThread, com o DxgkDdiStartDevice do miniport)
//! espera a criação da primeira sessão, que o win32k.sys anuncia no
//! NtUserInitialize (watchdog!SMgrNotifySessionChange ->
//! DxgkNotifySessionStateChange -> DpiSessionCreateCallback). O teste confere
//! o estado até ali e sai na serial (`BASICDISPLAY_OK` e `BASICRENDER_OK`).
//!
//! Sem a opção nada disto roda e o adaptador continua com o console em modo
//! texto do kernel.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::drivers::bus::device_tree;
use crate::ntos::cm::registry;
use crate::ntos::inc::types::{DeviceObject, DriverExtension, DriverObject, NtStruct};
use crate::ntos::io::pnp::{self, devnode, install};
use crate::ntos::io::{device_interface, lifecycle};
use crate::ntos::ob::object_manager;
use crate::rtl::KernelError;

/// `--display=basic`: o BasicDisplay.sys sobe pelo PnP no adaptador VGA.
pub fn enabled() -> bool {
    crate::ntos::init::boot_config::basic_display()
}

/// GUID_DEVINTERFACE_DISPLAY_ADAPTER {5b45201d-f2f2-4f3b-85bb-30ff1f953599}.
const GUID_DEVINTERFACE_DISPLAY_ADAPTER: [u8; 16] = [0x1D, 0x20, 0x45, 0x5B, 0xF2, 0xF2, 0x3B, 0x4F, 0x85, 0xBB, 0x30, 0xFF, 0x1F, 0x95, 0x35, 0x99];
/// GUID_DISPLAY_DEVICE_ARRIVAL {1ca05180-a699-450a-9a0c-de4fbe3ddd89}: o
/// dxgkrnl registra a interface no DpiFdoInitializeFdo e só a habilita no
/// fim de um DpiFdoStartAdapter bem-sucedido (depois do DxgkDdiStartDevice).
const GUID_DISPLAY_DEVICE_ARRIVAL: [u8; 16] = [0x80, 0x51, 0xA0, 0x1C, 0x99, 0xA6, 0x0A, 0x45, 0x9A, 0x0C, 0xDE, 0x4F, 0xBE, 0x3D, 0xDD, 0x89];
static ADAPTER_STARTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static RENDER_ADAPTER_STARTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// A instância da raiz do adaptador de renderização, como esta instalação a
/// tem (`Enum\ROOT\BasicRender\0000`, HardwareID `ROOT\BasicRender`).
const RENDER_INSTANCE: &str = "ROOT\\BasicRender\\0000";
const RENDER_HARDWARE_ID: &str = "ROOT\\BasicRender";

/// A instância `ROOT\BasicRender\0000`, antes de o PnP enumerar a raiz.
/// Numa instalação do 19041 ela existe desde o primeiro boot: o DriverEntry
/// do BasicRender.sys a relata (o IOCTL 0x232063 do \Device\DxgKrnl chama o
/// IoReportRootDevice, que só grava a chave) e o instalador a completa pelo
/// basicrender.inf; dali em diante a raiz a enumera em todo boot. Aqui ela
/// entra só com o HardwareID, e o PnP a instala pelo basicrender.inf
/// (`pnp/install.rs`) como instala o adaptador VGA. Uma instância que já
/// existe fica como está.
pub fn seed_render_device() -> Result<(), KernelError> {
    let key = format!("{}\\Enum\\{RENDER_INSTANCE}", install::CONTROL_SET);
    if registry::node_by_path(&key).is_some() {
        return Ok(());
    }
    if pnp::root::root_pdo() != 0 {
        debug_print!("[display] a raiz do PnP ja foi enumerada: {} fica para a proxima enumeracao", RENDER_INSTANCE);
    }
    install::write_multi(&key, "HardwareID", &[String::from(RENDER_HARDWARE_ID)])
}

/// Observação de IoSetDeviceInterfaceState: a interface de chegada de
/// dispositivo de vídeo habilitada num adaptador do BasicDisplay ou do
/// BasicRender é o adaptador iniciado pelo dxgkrnl (`ADAPTER_STARTED` e
/// `RENDER_ADAPTER_STARTED`).
pub fn interface_enabled(class: &[u8; 16], link: &str) {
    if !enabled() || *class != GUID_DISPLAY_DEVICE_ARRIVAL {
        return;
    }
    let started = |service: &str| pnp::tree::summary().into_iter().find(|(path, state, _, owner)| owner.as_deref() == Some(service) && *state == devnode::State::Started && link.to_uppercase().contains(&path.replace('\\', "#").to_uppercase()));
    if !ADAPTER_STARTED.load(core::sync::atomic::Ordering::Acquire) {
        if let Some((path, _, _, _)) = started("BasicDisplay") {
            if !ADAPTER_STARTED.swap(true, core::sync::atomic::Ordering::AcqRel) {
                debug_print!("[display] {}: adaptador iniciado pelo dxgkrnl (DxgkDdiStartDevice do BasicDisplay); interface {} habilitada", path, link);
                debug_print!("ADAPTER_STARTED");
            }
            return;
        }
    }
    if !RENDER_ADAPTER_STARTED.load(core::sync::atomic::Ordering::Acquire) {
        if let Some((path, _, _, _)) = started("BasicRender") {
            if !RENDER_ADAPTER_STARTED.swap(true, core::sync::atomic::Ordering::AcqRel) {
                debug_print!("[display] {}: adaptador de renderizacao iniciado pelo dxgkrnl (DxgkDdiStartDevice do BasicRender); interface {} habilitada", path, link);
                debug_print!("RENDER_ADAPTER_STARTED");
            }
        }
    }
}
/// FILE_DEVICE_VIDEO.
const FILE_DEVICE_VIDEO: u32 = 0x23;
/// IRP_MJ_PNP.
const IRP_MJ_PNP: usize = 0x1B;

/// O adaptador instalado com o serviço `service` (o miniport), pronto até
/// onde o dxgkrnl o leva sem sessão: nó iniciado; FDO de vídeo do
/// \Driver\<serviço> na pilha do PDO; o despacho do driver (PnP e
/// AddDevice) dentro do dxgkrnl.sys.
fn check_adapter(service: &str) -> Result<String, String> {
    let adapter = devnode::all().into_iter().find(|node| node.service.as_deref() == Some(service)).ok_or_else(|| format!("nenhum adaptador instalado com o {service}"))?;
    if adapter.state != devnode::State::Started {
        return Err(format!("{}: estado {:?}, problema {:#x}", adapter.instance_path, adapter.state, adapter.problem));
    }
    let miniport = lifecycle::initialized_driver(service).ok_or_else(|| format!("\\Driver\\{service} ausente"))?;
    let dxgkrnl = lifecycle::initialized_driver("DXGKrnl").ok_or("\\Driver\\DXGKrnl ausente (o DxgkInitialize nao carregou o dxgkrnl)")?;
    if object_manager::lookup("\\Device\\DxgKrnl").is_none() {
        return Err(String::from("\\Device\\DxgKrnl ausente"));
    }
    let (start, end) = device_tree::image_range(dxgkrnl);
    // SAFETY: DRIVER_OBJECT do miniport e a sua extensão.
    let (pnp_dispatch, add_device) = unsafe {
        let object = DriverObject::at(miniport);
        (object.major_function[IRP_MJ_PNP].get(), DriverExtension::at(object.driver_extension.get()).add_device.get())
    };
    if !(start..end).contains(&pnp_dispatch) || !(start..end).contains(&add_device) {
        return Err(format!("despacho do {service} fora do dxgkrnl (PnP {pnp_dispatch:#x}, AddDevice {add_device:#x})"));
    }
    let fdo = adapter.function_device;
    if fdo == 0 {
        return Err(String::from("sem FDO sobre o PDO do adaptador"));
    }
    // SAFETY: DEVICE_OBJECT do FDO criado no AddDevice.
    let (owner, device_type) = unsafe {
        let device = DeviceObject::at(fdo);
        (device.driver_object.get(), device.device_type.get())
    };
    if owner != miniport || device_type != FILE_DEVICE_VIDEO || !device_tree::attached_above(adapter.pdo, fdo) {
        return Err(format!("FDO {fdo:#x}: driver {owner:#x}, tipo {device_type:#x}, fora da pilha do PDO {:#x}", adapter.pdo));
    }
    Ok(adapter.instance_path)
}

/// Antes da árvore: o vídeo de boot que o carregador deixa numa máquina com
/// adaptador de vídeo (o BGFX de um boot por BIOS), antes do driver de
/// vídeo.
pub fn before_tree() {
    debug_print!("[display] pilha de video real pelo PnP");
    if crate::ntos::bgk::graphics_information::initialize_firmware_display().is_none() {
        debug_print!("[bgk] sem modo VBE para o video de boot");
    }
}

/// Depois da árvore: o adaptador de vídeo, o de renderização e a ponte KMDF.
pub fn check() {
    let links: Vec<String> = device_interface::class_links(&GUID_DEVINTERFACE_DISPLAY_ADAPTER, true);
    let enabled = device_interface::enabled_links(&GUID_DEVINTERFACE_DISPLAY_ADAPTER);
    debug_print!("[display] interfaces de adaptador: {:?} (habilitadas: {:?})", links, enabled);
    match check_adapter("BasicDisplay") {
        Ok(instance) => {
            debug_print!("[display] {}: FDO de video do BasicDisplay pelo dxgkrnl, START_DEVICE concluido; o inicio do adaptador espera a primeira sessao (NtUserInitialize do win32k)", instance);
            debug_print!("BASICDISPLAY_OK");
        }
        Err(error) => debug_print!("[display] adaptador incompleto: {}", error),
    }
    match check_adapter("BasicRender") {
        Ok(instance) => {
            debug_print!("[display] {}: FDO de video do BasicRender (adaptador WARP) pelo dxgkrnl, START_DEVICE concluido; o inicio do adaptador espera a primeira sessao", instance);
            debug_print!("BASICRENDER_OK");
        }
        Err(error) => debug_print!("[display] adaptador de renderizacao incompleto: {}", error),
    }
    match device_tree::check_kmdf_bus() {
        Ok(instance) => {
            debug_print!("[display] {}: AddDevice e START do msisadrv.sys pelo KMDF (Wdf01000)", instance);
            debug_print!("KMDF_PNP_OK");
        }
        Err(error) => debug_print!("[display] ponte KMDF incompleta: {}", error),
    }
}
