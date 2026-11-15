//! A pilha de vídeo real do Windows (`--display=basic`).
//!
//! Com a opção, o fim da fase 1 monta a árvore de dispositivos do PnP sobre
//! o barramento PCI interno e o adaptador VGA do QEMU (PCI\VEN_1234&
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
//! O dxgkrnl não inicia o adaptador no START_DEVICE do primeiro adaptador:
//! o início (DpiFdoStartAdapterThread, com o DxgkDdiStartDevice do miniport)
//! espera a criação da primeira sessão, que o win32k.sys anuncia no
//! NtUserInitialize (watchdog!SMgrNotifySessionChange ->
//! DxgkNotifySessionStateChange -> DpiSessionCreateCallback). O teste confere
//! o estado até ali e sai na serial (`BASICDISPLAY_OK`).
//!
//! Sem a opção nada disto roda e o adaptador continua com o console em modo
//! texto do kernel.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::drivers::bus::device_tree;
use crate::ntos::inc::types::{DeviceObject, DriverExtension, DriverObject, NtStruct};
use crate::ntos::io::pnp::{self, devnode};
use crate::ntos::io::{device_interface, lifecycle};
use crate::ntos::ob::object_manager;

const fn equals(value: Option<&str>, expected: &str) -> bool {
    let Some(value) = value else { return false };
    let (left, right) = (value.as_bytes(), expected.as_bytes());
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// `--display=basic`: o BasicDisplay.sys sobe pelo PnP no adaptador VGA.
pub const ENABLED: bool = equals(option_env!("OPENNT_DISPLAY"), "basic");

/// GUID_DEVINTERFACE_DISPLAY_ADAPTER {5b45201d-f2f2-4f3b-85bb-30ff1f953599}.
const GUID_DEVINTERFACE_DISPLAY_ADAPTER: [u8; 16] = [0x1D, 0x20, 0x45, 0x5B, 0xF2, 0xF2, 0x3B, 0x4F, 0x85, 0xBB, 0x30, 0xFF, 0x1F, 0x95, 0x35, 0x99];
/// FILE_DEVICE_VIDEO.
const FILE_DEVICE_VIDEO: u32 = 0x23;
/// IRP_MJ_PNP.
const IRP_MJ_PNP: usize = 0x1B;

/// O adaptador instalado com o BasicDisplay, pronto até onde o dxgkrnl o
/// leva sem sessão: nó iniciado; FDO de vídeo do \Driver\BasicDisplay
/// sobre o PDO; o despacho do driver (PnP e AddDevice) dentro do dxgkrnl.sys.
fn check_adapter() -> Result<String, String> {
    let adapter = devnode::all().into_iter().find(|node| node.service.as_deref() == Some("BasicDisplay")).ok_or("nenhum adaptador instalado com o BasicDisplay")?;
    if adapter.state != devnode::State::Started {
        return Err(format!("{}: estado {:?}, problema {:#x}", adapter.instance_path, adapter.state, adapter.problem));
    }
    let miniport = lifecycle::initialized_driver("BasicDisplay").ok_or("\\Driver\\BasicDisplay ausente")?;
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
        return Err(format!("despacho do BasicDisplay fora do dxgkrnl (PnP {pnp_dispatch:#x}, AddDevice {add_device:#x})"));
    }
    let fdo = adapter.function_device;
    if fdo == 0 {
        return Err(String::from("sem FDO sobre o PDO do adaptador"));
    }
    // SAFETY: DEVICE_OBJECT do FDO criado no AddDevice.
    let (owner, device_type, attached) = unsafe {
        let device = DeviceObject::at(fdo);
        (device.driver_object.get(), device.device_type.get(), DeviceObject::at(adapter.pdo).attached_device.get())
    };
    if owner != miniport || device_type != FILE_DEVICE_VIDEO || attached != fdo {
        return Err(format!("FDO {fdo:#x}: driver {owner:#x}, tipo {device_type:#x}, anexado ao PDO {attached:#x}"));
    }
    Ok(adapter.instance_path)
}

/// Sobe a pilha de vídeo e confere o adaptador. Só com `--display=basic`.
pub fn initialize() {
    debug_print!("[display] pilha de video real pelo PnP");
    if let Err(error) = crate::drivers::bus::device_tree::prepare() {
        debug_print!("[display] raiz do PnP: {}", error);
        return;
    }
    // `--trace-driver-api` rastreia as APIs que os drivers da árvore chamam.
    crate::ntos::init::exports::set_api_trace(crate::ntos::init::boot_config::TRACE_DRIVER_API);
    let processed = pnp::tree::process();
    crate::ntos::init::exports::set_api_trace(false);
    if let Err(error) = processed {
        debug_print!("[display] arvore do PnP: {}", error);
    }
    for (path, state, problem, service) in pnp::tree::summary() {
        debug_print!("[display] devnode {} estado {:?} problema {:#x} servico {}", path, state, problem, service.as_deref().unwrap_or("-"));
    }
    let links: Vec<String> = device_interface::class_links(&GUID_DEVINTERFACE_DISPLAY_ADAPTER, true);
    let enabled = device_interface::enabled_links(&GUID_DEVINTERFACE_DISPLAY_ADAPTER);
    debug_print!("[display] interfaces de adaptador: {:?} (habilitadas: {:?})", links, enabled);
    match check_adapter() {
        Ok(instance) => {
            debug_print!("[display] {}: FDO de video do BasicDisplay pelo dxgkrnl, START_DEVICE concluido; o inicio do adaptador espera a primeira sessao (NtUserInitialize do win32k)", instance);
            debug_print!("BASICDISPLAY_OK");
        }
        Err(error) => debug_print!("[display] adaptador incompleto: {}", error),
    }
    match device_tree::check_kmdf_bus() {
        Ok(instance) => {
            debug_print!("[display] {}: AddDevice e START do msisadrv.sys pelo KMDF (Wdf01000)", instance);
            debug_print!("KMDF_PNP_OK");
        }
        Err(error) => debug_print!("[display] ponte KMDF incompleta: {}", error),
    }
}
