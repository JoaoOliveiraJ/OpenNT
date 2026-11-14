//! FASE 1 do boot (estilo NT).
//!
//! Sobe o I/O Manager e os exports do kernel, monta o NTFS do segundo disco
//! IDE em `D:` (driver ata-pio), enumera o PCI, carrega os drivers de
//! serviço de boot lidos do Registry com IRP_MJ_PNP/START_DEVICE, publica o
//! catálogo CNG e executa as rotinas de reinicialização dos drivers. Os
//! binários da Microsoft (hal.dll, atapi, disk, mountmgr, i8042prt,
//! kbdclass, mouclass, cng.sys) vêm do Windows da máquina de build e nunca
//! ficam no repositório: sem eles, o carregador registra a ausência e o boot
//! segue.

pub fn init() {
    debug_print!("[boot] fase 1: I/O manager + drivers + servicos");
    crate::ntos::io::io_manager::init().unwrap_or_else(|error| panic!("I/O Manager: {error}"));
    // Exports do kernel para drivers: resolvedor do loader e trampolins.
    crate::ntos::init::exports::init();
    // Hosts de extensão que os drivers de boot preenchem (ExRegisterHost do
    // SepInitializeAuthorizationCallbacks e do PspInitializeNetRateControl).
    crate::ntos::se::extension_hosts::initialize_authorization_callbacks().unwrap_or_else(|error| panic!("hosts de extensao do Se: {error}"));
    crate::ntos::ps::net_rate_control::initialize().unwrap_or_else(|error| panic!("host de controle de taxa de rede: {error}"));
    crate::ntos::ex::pcw::initialize().unwrap_or_else(|error| panic!("host do PCW: {error}"));
    // hal.dll real da instalação: biblioteca sem entrada com os seus
    // encaminhamentos, carregada logo depois dos resolvedores do ntoskrnl,
    // de que os encaminhamentos dependem.
    match crate::ntos::mm::sysload::load("hal.dll") {
        Ok(module) => debug_print!("[boot] hal.dll carregado ({} exports, {} encaminhamentos)", module.exports.exports.len(), module.exports.forwarders.len()),
        Err(error) => debug_print!("[boot] hal.dll falhou: {}", error),
    }
    // HalPrivateDispatchTable preenchida como na inicialização da HAL do NT.
    crate::hal::private_dispatch::initialize().unwrap_or_else(|error| panic!("HAL privada: {error}"));
    // HalDispatchTable pública, preenchida como na inicialização da HAL do NT.
    crate::hal::public_dispatch::initialize().unwrap_or_else(|error| panic!("HAL publica: {error}"));
    // NTFS no segundo disco IDE (ata-pio): o carregador de imagens e o
    // ZwCreateFile resolvem a mesma montagem em \NTFS (D:).
    if matches!(crate::drivers::storage::ata_pio::present(1), Ok(true)) {
        match crate::drivers::fs::ntfs::mount(1) {
            Ok(volume) => {
                let file_system: &'static crate::drivers::fs::ntfs::Ntfs = alloc::boxed::Box::leak(alloc::boxed::Box::new(volume.clone()));
                let mounted = crate::ntos::ob::object_manager::mount("\\NTFS", file_system).and_then(|_| crate::ntos::ob::object_manager::create_symlink("\\DosDevices\\D:", "\\NTFS"));
                match mounted {
                    Ok(_) => {
                        crate::drivers::fs::ntfs::set_mounted(Some(volume));
                        debug_print!("[boot] NTFS montado em D:");
                    }
                    Err(error) => debug_print!("[boot] NTFS falhou: {}", error),
                }
            }
            Err(error) => debug_print!("[boot] NTFS falhou: {}", error),
        }
    }
    // Barramento PCI primeiro (como o pci.sys): hardware enumerado e PDOs
    // com recursos reais antes dos drivers funcionais.
    match crate::drivers::bus::pci::init() {
        Ok(count) => debug_print!("[boot] PCI: {} funcoes", count),
        Err(error) => debug_print!("[pci] enumeracao falhou: {}", error),
    }
    // Drivers de serviço lidos do Registry + PnP START. O provedor de status
    // dos drivers entra com `cm::service::driver`.
    crate::ntos::cm::service::driver::init();
    let loaded = crate::ntos::cm::service::system_drivers::start_boot_drivers();
    // IopCallBootDriverReinitializationRoutines: depois do último driver de boot.
    crate::ntos::io::lifecycle::run_boot_driver_reinitialization_routines();
    debug_print!("[boot] servicos carregados: {}", loaded);
    // Catálogo CNG publicado antes de qualquer processo de usuário. O cng.sys
    // é o binário real do Windows no volume: o OpenNT não o distribui.
    crate::ntos::cm::cng_defaults::initialize().unwrap_or_else(|error| panic!("CNG: {error}"));
    // Control\GraphicsDrivers da instalação, que o dxgkrnl.sys abre no DriverEntry.
    crate::ntos::cm::graphics_defaults::initialize().unwrap_or_else(|error| panic!("GraphicsDrivers: {error}"));
    // O cng.sys real do volume, antes de qualquer processo de usuário: imagem,
    // imports e DriverEntry completos, publicando \Device\CNG.
    match crate::ntos::mm::sysload::load("cng.sys") {
        Ok(_) if crate::ntos::ob::object_manager::lookup("\\Device\\CNG").is_some() => debug_print!("[boot] cng.sys carregado; \\Device\\CNG publicado"),
        Ok(_) => debug_print!("[boot] cng.sys carregado sem publicar \\Device\\CNG"),
        Err(error) => debug_print!("[boot] cng.sys falhou: {}", error),
    }
    // Rotinas de IoRegisterDriverReinitialization, como no NT.
    crate::ntos::io::lifecycle::run_reinitialization_routines();
}
