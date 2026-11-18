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
    // ExInitSystem / ExpWorkerInitialization: as worker threads do sistema,
    // antes dos drivers. Os work items enfileirados antes delas (a fila só os
    // guardava) rodam agora, cada um na pilha de uma worker.
    crate::ntos::io::work_items::initialize_workers().unwrap_or_else(|error| panic!("worker threads: {error}"));
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
    // \Device\KernelVolume1 (o D:). No boot do smss ele é também o C:, o
    // volume do sistema (o \Windows do \SystemRoot): os caminhos C:\ que o
    // modo usuário passa ao kernel (o \??\C:\WINDOWS\FONTS\X.TTF do
    // AddFontResource que o win32k abre) chegam ao mesmo volume que o modo
    // usuário abre por C:.
    if matches!(crate::drivers::storage::ata_pio::present(1), Ok(true)) {
        match crate::drivers::fs::ntfs::mount(1) {
            Ok(volume) => {
                crate::drivers::fs::ntfs::set_mounted(Some(volume));
                let link_drives = |device: alloc::string::String| -> Result<(), crate::rtl::KernelError> {
                    crate::ntos::ob::object_manager::create_symlink("\\DosDevices\\D:", &device)?;
                    if crate::ntos::init::boot_config::smss_boot() {
                        crate::ntos::ob::object_manager::create_symlink("\\DosDevices\\C:", &device)?;
                    }
                    Ok(())
                };
                let mounted = crate::drivers::fs::ntfs::fixed().ok_or_else(|| crate::rtl::KernelError::new("NTFS sem volume")).and_then(|file_system| crate::drivers::fs::volume_device::mount(crate::drivers::fs::ntfs::DEVICE_INDEX, file_system)).and_then(link_drives);
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
    // O contexto de licenciamento do host com o ProductPolicy capturado da
    // SYSTEM: a inicialização que o Phase1InitializationIoReady do NT faz
    // (a rotina em rva 0x7ab058: cabeçalho validado, política publicada numa
    // SECTION pelo SLUpdateLicenseDataInternal). No NT os drivers de boot
    // anteriores a ela já leem a política pelo buffer primário que o
    // CmGetSystemControlValues encheu na fase 0; aqui a SYSTEM só existe
    // agora, então a publicação vem antes do primeiro driver.
    crate::ntos::ex::license::values::init_runtime(&crate::ntos::ex::license::boot::BootProviders::default()).unwrap_or_else(|error| panic!("{error}"));
    // IopReadDumpRegistry: o AutoReboot e o despejo do CrashControl, que o
    // KeBugCheckEx consulta sem tocar no Registro.
    crate::ntos::ke::bugcheck::read_crash_control();
    // O fuso do Registro: a hora do relógio da CMOS (local) com o
    // ActiveTimeBias e o ExpRefreshTimeZoneInformation.
    crate::ntos::ex::time_zone::initialize();
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
    // FsRtlInitSystem / FsRtlInitializeSmssEvent: o evento permanente
    // \Device\VolumesSafeForWriteAccess, que o smss.exe sinaliza depois dos
    // comandos BootExecute, e o work item que o espera.
    crate::ntos::fsrtl::volume_support::initialize_smss_event().unwrap_or_else(|error| panic!("FsRtlInitializeSmssEvent: {error}"));
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
    // `--display=basic`: a instância ROOT\BASICRENDER do adaptador de
    // renderização, antes de qualquer enumeração da raiz do PnP.
    if crate::drivers::video::display_stack::enabled() {
        if let Err(error) = crate::drivers::video::display_stack::seed_render_device() {
            debug_print!("[display] instancia ROOT\\BASICRENDER: {}", error);
        }
    }
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
    // pilhas pedidas: `--storage=real` (a pilha de armazenamento do Windows),
    // `--storage=nvme` (o storport.sys com o stornvme.sys no controlador
    // NVMe) e `--display=basic` (o BasicDisplay.sys real no adaptador VGA,
    // sobre o dxgkrnl.sys real); com `--usb`, a controladora xHCI recebe o
    // usbxhci.sys.
    //
    // O Code Integrity sobe como no SepInitializationPhase1 do NT (rva
    // 0x79d8f4), que chama o SepInitializeCodeIntegrity sem condição: ele
    // valida as imagens de kernel carregadas daqui em diante (os drivers da
    // árvore: acpi.sys, pci.sys, i8042prt.sys...) e responde às classes de
    // política do NtQuerySystemInformation (a 164, que o IsLockdownSKU do
    // KERNELBASE consulta no CoInitializeSecurity do combase; sem CI ela é
    // STATUS_UNSUCCESSFUL e o COM do processo falha). Só o boot dos
    // autotestes fica sem ele, a menos que um `--start-driver` o peça: os
    // autotestes carregam imagens de kernel sintéticas do sistema de
    // arquivos em memória, que a CI recusaria.
    if crate::ntos::init::boot_config::kernel_test_scope() == "none" || !crate::ntos::init::boot_config::start_driver().is_empty() {
        if let Err(error) = crate::ntos::se::code_integrity::initialize() {
            debug_print!("[boot] Code Integrity antes da arvore de dispositivos: {}", error);
        }
    }
    if crate::drivers::bus::acpi_stack::enabled()
        || crate::drivers::storage::storage_stack::enabled()
        || crate::drivers::storage::nvme_stack::enabled()
        || crate::drivers::video::display_stack::enabled()
        || crate::drivers::bus::usb_stack::enabled()
        || crate::drivers::net::net_stack::enabled()
    {
        crate::drivers::bus::device_tree::build();
    }
    // `--usb`: a pilha USB 3 e HID real, que a árvore instalou na
    // controladora xHCI, enumera as portas; os marcos saem dela.
    if crate::drivers::bus::usb_stack::enabled() {
        crate::drivers::bus::usb_stack::initialize();
    }
}
