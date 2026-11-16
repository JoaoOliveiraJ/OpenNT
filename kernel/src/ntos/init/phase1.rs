//! FASE 1 do boot (estilo NT).
//!
//! Sobe o I/O Manager e os exports do kernel, monta o NTFS do segundo disco
//! IDE em `D:` (driver ata-pio), carrega a hive SYSTEM do arquivo desse
//! volume (ou semeia as chaves estáticas dela), enumera o PCI, carrega os drivers de
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
    // HalInitializeBios: o BIOS de vídeo da máquina para os x86Bios*.
    if let Err(error) = crate::hal::x86bios::initialize() {
        debug_print!("[hal] BIOS x86 indisponivel: {}", error);
    }
    // NTFS no segundo disco IDE (ata-pio): o carregador de imagens e o
    // ZwCreateFile resolvem o mesmo volume, montado no dispositivo
    // \Device\KernelVolume1 (o D:).
    if matches!(crate::drivers::storage::ata_pio::present(1), Ok(true)) {
        match crate::drivers::fs::ntfs::mount(1) {
            Ok(volume) => {
                crate::drivers::fs::ntfs::set_mounted(Some(volume));
                let mounted = crate::drivers::fs::ntfs::fixed().ok_or_else(|| crate::rtl::KernelError::new("NTFS sem volume")).and_then(|file_system| crate::drivers::fs::volume_device::mount(crate::drivers::fs::ntfs::DEVICE_INDEX, file_system)).and_then(|device| crate::ntos::ob::object_manager::create_symlink("\\DosDevices\\D:", &device));
                match mounted {
                    Ok(_) => debug_print!("[boot] NTFS montado em D:"),
                    Err(error) => {
                        crate::drivers::fs::ntfs::set_mounted(None);
                        debug_print!("[boot] NTFS falhou: {}", error);
                    }
                }
            }
            Err(error) => debug_print!("[boot] NTFS falhou: {}", error),
        }
    }
    // CmInitSystem1 / CmpInitializeHiveList: a hive SYSTEM do arquivo do
    // volume (\SystemRoot\System32\config\SYSTEM) em
    // \Registry\Machine\SYSTEM, com as chaves de serviço, o link
    // CurrentControlSet, as hives SOFTWARE, SAM, SECURITY e DEFAULT e a
    // lista de hives; sem um arquivo, as mesmas chaves em memória.
    crate::ntos::cm::hive_init::initialize_hives().unwrap_or_else(|error| panic!("hives de maquina: {error}"));
    // IopReadDumpRegistry: o AutoReboot e o despejo do CrashControl, que o
    // KeBugCheckEx consulta sem tocar no Registro.
    crate::ntos::ke::bugcheck::read_crash_control();
    // Definições WNF da hive (Control\Notifications), que NTDLL e KERNELBASE
    // consultam; os dados só existem depois de publicação real.
    crate::ntos::cm::wnf_defaults::initialize().unwrap_or_else(|error| panic!("{error}"));
    // EmInitSystem: o banco do Errata Manager a partir da imagem do
    // \SystemRoot\INF\errata.inf que o carregador entrega (lida do volume
    // de boot, agora montado), os callbacks da HAL e os embutidos; o work
    // item do Errata Manager atualiza as regras antes dos drivers. A falha
    // é o PHASE1_INITIALIZATION_FAILED do NT.
    let errata = crate::ntos::em::loader_inf_image();
    crate::ntos::em::initialize_system(errata.as_deref()).unwrap_or_else(|status| panic!("EmInitSystem: {status:#x}"));
    crate::ntos::em::initialize_dynamic();
    crate::ntos::io::work_items::run_queue();
    // IopInitializePlugPlayServices: o driver embutido \Driver\DeviceApi
    // (PiDaInit), com o \Device\DeviceApi que o cfgmgr32 abre.
    match crate::ntos::io::pnp::device_api::initialize() {
        Ok(0) => {}
        Ok(status) => panic!("\\Driver\\DeviceApi: IoCreateDriver -> {status:#x}"),
        Err(error) => panic!("\\Driver\\DeviceApi: {error}"),
    }
    // Barramento PCI primeiro (como o pci.sys): hardware enumerado e PDOs
    // com recursos reais antes dos drivers funcionais.
    match crate::drivers::bus::pci::init() {
        Ok(count) => debug_print!("[boot] PCI: {} funcoes", count),
        Err(error) => debug_print!("[pci] enumeracao falhou: {}", error),
    }
    // Control\GraphicsDrivers da instalação, que o dxgkrnl.sys abre no
    // DriverEntry: antes dos drivers de sistema, entre os quais ele está no
    // boot do smss.
    crate::ntos::cm::graphics_defaults::initialize().unwrap_or_else(|error| panic!("GraphicsDrivers: {error}"));
    // Drivers de serviço lidos do Registry + PnP START. O provedor de status
    // dos drivers entra com `cm::service::driver`.
    crate::ntos::cm::service::driver::init();
    let loaded = crate::ntos::cm::service::system_drivers::start_boot_drivers();
    // IopCallBootDriverReinitializationRoutines: depois do último driver de boot.
    crate::ntos::io::lifecycle::run_boot_driver_reinitialization_routines();
    crate::ntos::io::pnp::mark_boot_drivers_initialized();
    debug_print!("[boot] servicos carregados: {}", loaded);
    // Catálogo CNG publicado antes de qualquer processo de usuário. O cng.sys
    // é o binário real do Windows no volume: o OpenNT não o distribui.
    crate::ntos::cm::cng_defaults::initialize().unwrap_or_else(|error| panic!("CNG: {error}"));
    // Control\Nsi da instalação, o repositório persistente do netio.sys.
    crate::ntos::cm::network_defaults::initialize().unwrap_or_else(|error| panic!("Nsi: {error}"));
    // O cng.sys real do volume, antes de qualquer processo de usuário: imagem,
    // imports e DriverEntry completos, publicando \Device\CNG.
    match crate::ntos::mm::sysload::load("cng.sys") {
        Ok(_) if crate::ntos::ob::object_manager::lookup("\\Device\\CNG").is_some() => debug_print!("[boot] cng.sys carregado; \\Device\\CNG publicado"),
        Ok(_) => debug_print!("[boot] cng.sys carregado sem publicar \\Device\\CNG"),
        Err(error) => debug_print!("[boot] cng.sys falhou: {}", error),
    }
    // Rotinas de IoRegisterDriverReinitialization, como no NT.
    crate::ntos::io::lifecycle::run_reinitialization_routines();
    // A árvore de dispositivos do PnP, uma vez: a raiz é o acpi.sys real
    // sobre o dispositivo ACPI da HAL, com o pci.sys no barramento PCI (o
    // padrão; `--pnp-root=internal` volta ao barramento PCI interno), com as
    // pilhas pedidas: `--storage=real` (a pilha de armazenamento do Windows)
    // e `--display=basic` (o BasicDisplay.sys real no adaptador VGA, sobre o
    // dxgkrnl.sys real).
    if crate::drivers::bus::acpi_stack::enabled() || crate::drivers::storage::storage_stack::enabled() || crate::drivers::video::display_stack::enabled() {
        // `--start-driver` liga o Code Integrity: como no NT, ele já valida
        // os drivers que a árvore carrega (acpi.sys, pci.sys, i8042prt.sys...).
        if !crate::ntos::init::boot_config::start_driver().is_empty() {
            if let Err(error) = crate::ntos::se::code_integrity::initialize() {
                debug_print!("[boot] Code Integrity antes da arvore de dispositivos: {}", error);
            }
        }
        crate::drivers::bus::device_tree::build();
    }
}
