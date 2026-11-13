//! FASE 0 do boot (estilo NT).
//!
//! Em ordem: política da hive, licenças, firmware e identidade
//! do boot, relógio e interrupções, memória (PFN, mapeamento recursivo,
//! descritores nativos, imagens carregadas, células de dado), KPCR, SMP,
//! pool, escalonador com o EPROCESS do System, os tipos de objeto e as suas
//! células, WNF, o sistema de arquivos em memória com as apps embutidas, o
//! namespace NT (com a partição e os eventos `\KernelObjects`), a hive de
//! serviços (pilhas de teclado/mouse e de armazenamento, parâmetros do
//! i8042prt e classes de dispositivo) e a descrição de hardware. O serviço
//! do vgk (ferramenta de diagnóstico) fica fora.

use crate::hal::bundle;
use crate::nano::interrupts;
use crate::drivers::fs::memory_file_system;
use crate::ntos::ke::clock;
use crate::ntos::cm::state_separation;
use crate::ntos::ke::{critical_region, pcr, smp};
use crate::ntos::mm::{dump_mdl, kernel_data, kernel_pool, loaded_images, memory_map, native_pfn_database, pfn, pool_lock, recursive_mapping, shared_user_data};
use crate::ntos::ob::object_manager;
use crate::ntos::ps::scheduler;
use crate::rtl::text::latin1_to_string;

pub fn init() {
    debug_print!("[boot] fase 0: nanokernel + escalonador + arquivos em memoria");
    // captura a política da hive entregue a este boot; não anuncia isolamento
    // que o boot não fornece
    clock::init(); // relógio TSC de alta resolução (calibra com o PIT)
    state_separation::init(Some(|key, name| crate::ntos::cm::registry::read_value_by_path(key, name).map(|value| value.data)));
    state_separation::require_supported_boot().unwrap_or_else(|error| panic!("{error}"));
    crate::ntos::ex::license::values::init(); // captura ProductPolicy sem criar licenças nem capabilities
    interrupts::init();
    // memory manager: alocador de frames físicos, tabelas supervisoras reais
    // (antes dos APs) e descritores nativos ligados ao PFN e às PTEs
    pfn::init().unwrap_or_else(|error| panic!("PFN: {error}"));
    recursive_mapping::initialize().unwrap_or_else(|error| panic!("mapeamento recursivo: {error}"));
    native_pfn_database::initialize().unwrap_or_else(|error| panic!("PFN nativo: {error}"));
    // publica as VAs nativas do PE real e os limites de usuário
    loaded_images::init_kernel().unwrap_or_else(|error| panic!("imagem do kernel: {error}"));
    kernel_data::write("MmUserProbeAddress", memory_map::USER_ADDRESS_LIMIT);
    kernel_data::write("MmHighestUserAddress", memory_map::USER_ADDRESS_LIMIT - 1);
    pcr::init().unwrap_or_else(|error| panic!("KPCR: {error}")); // KPCR do BSP + IA32_GS_BASE
    pool_lock::init().unwrap_or_else(|error| panic!("pool lock: {error}")); // lock nativo da arena NT
    crate::ntos::io::volume_parameters::init().unwrap_or_else(|error| panic!("{error}")); // LockQueueIoVpbLock antes dos drivers nativos
    crate::hal::pci_config::init().unwrap_or_else(|error| panic!("{error}")); // lock CF8/CFC antes dos APs
    shared_user_data::init(); // página KUSER_SHARED_DATA mapeada (drivers WDK)
    smp::init().unwrap_or_else(|error| panic!("SMP: {error}")); // ACPI MADT + INIT-SIPI dos APs (LAPIC)
    if crate::ntos::init::boot_config::IDENTITY_AUDIT {
        crate::ntos::mm::identity_audit::run(); // --identity-audit: prova do mapa direto
    }
    crate::ntos::mm::image_paging::init().unwrap_or_else(|error| panic!("image paging: {error}"));
    kernel_pool::init(); // pool executivo (paginável com apoio no NTFS)
    dump_mdl::init().unwrap_or_else(|error| panic!("dump MDL: {error}"));
    critical_region::init(); // entrega de APCs respeita KernelApcDisable/SpecialApcDisable
    scheduler::init().unwrap_or_else(|error| panic!("Process Manager: {error}")); // EPROCESS System + thread do boot
    crate::ntos::po::black_box::init().unwrap_or_else(|error| panic!("{error}")); // diagnóstico antes dos drivers nativos
    // Células de dado públicas do processo inicial e dos tipos de objeto, na
    // ordem de criação dos tipos do boot.
    {
        use crate::ntos::ob::object_types;
        kernel_data::write("PsInitialSystemProcess", crate::ntos::ps::process::get_system_process());
        kernel_data::write("PsProcessType", object_types::process_type().pointer);
        kernel_data::write("PsThreadType", object_types::thread_type().pointer);
        kernel_data::write("IoDriverObjectType", object_types::driver_type().pointer);
        kernel_data::write("IoFileObjectType", object_types::file_type().pointer);
        kernel_data::write("MmSectionObjectType", object_types::section_type().pointer);
        kernel_data::write("SeTokenObjectType", object_types::token_type().pointer);
        kernel_data::write("IoDeviceObjectType", object_types::device_type().pointer);
        // Semaphore e ALPC Port são criados sob demanda pelo user_type; a
        // ausência seria um tipo que não pôde ser criado — falha alto.
        kernel_data::write("ExSemaphoreObjectType", object_types::user_type("semaphore").expect("tipo Semaphore").pointer);
        kernel_data::write("LpcPortObjectType", object_types::user_type("port").expect("tipo ALPC Port").pointer);
        object_types::event_type();
        object_types::meta_type();
        object_types::directory_type();
        object_types::symbolic_link_type();
        object_types::key_type();
    }
    // O stage2 não carrega nem entrega pacote de política de Secure Boot; a
    // ausência pertence ao loader atual e não é inferida do firmware.
    crate::hal::firmware_environment::init().unwrap_or_else(|error| panic!("{error}")); // handoff real do loader
    crate::ntos::ex::boot_environment::init().unwrap_or_else(|error| panic!("boot environment: {error}")); // identidade única e flags reais, antes das consultas de drivers
    crate::ntos::se::platform_manifest::init(None).unwrap_or_else(|error| panic!("{error}"));
    crate::ntos::se::secure_boot_policy::init(None).unwrap_or_else(|error| panic!("{error}"));
    // contexto de licenças próprio: estado, locks e (com política válida) a SECTION
    crate::ntos::ex::license::values::init_runtime(&crate::ntos::ex::license::boot::BootProviders::default()).unwrap_or_else(|error| panic!("{error}"));
    // metadados WNF instalados; os dados só existem depois de publicação real
    crate::ntos::cm::wnf_defaults::initialize().unwrap_or_else(|error| panic!("{error}"));
    memory_file_system::init(clock::now_ms());

    // apps embutidas viram arquivos do VFS ( /<basename> )
    for name in bundle::list() {
        if !name.starts_with("apps/") {
            continue;
        }
        let destination = alloc::format!("/{}", name.rsplit('/').next().unwrap_or(name));
        let Some(data) = bundle::read(name) else { continue };
        let binary = [".exe", ".sys", ".dll"].iter().any(|extension| name.ends_with(extension));
        let stored = if binary {
            memory_file_system::write_bytes(&destination, data.to_vec())
        } else {
            memory_file_system::write(&destination, &latin1_to_string(data))
        };
        if let Err(error) = stored {
            debug_print!("[boot] falha ao copiar {}: {}", name, error);
        }
    }
    namespace().unwrap_or_else(|error| panic!("namespace: {error}"));
    seed_services().unwrap_or_else(|error| panic!("hive de servicos: {error}"));
    crate::ntos::cm::hw_description::seed_hardware_description().unwrap_or_else(|error| panic!("{error}"));
    // mapa real de RAM na hive de hardware, antes de iniciar os drivers
    crate::ntos::cm::physical_memory_resources::initialize().unwrap_or_else(|error| panic!("{error}"));
}

/// Diretórios e links do namespace NT, na ordem de criação, com a
/// partição do sistema e os eventos `\KernelObjects\*`.
fn namespace() -> Result<(), crate::rtl::KernelError> {
    crate::ntos::se::se_exports::init()?; // SE_EXPORTS na reserva permanente da imagem
    object_manager::create_directory("\\Device")?;
    object_manager::create_directory("\\Driver")?;
    object_manager::create_directory("\\KnownDlls")?;
    object_manager::create_symlink("\\KnownDlls\\KnownDllPath", "C:\\Windows\\System32")?;
    // Destino NT até o diretório instalado no volume de boot (montado na fase 1).
    object_manager::create_symlink("\\SystemRoot", "\\NTFS\\Windows")?;
    // CmpInitializeDriverStores: o diretório e o alias do sistema.
    object_manager::create_directory("\\DriverStores")?;
    object_manager::create_symlink("\\DriverStores\\SYSTEM", "\\SystemRoot")?;
    // \Callback com SetSystemTime, PowerState e ProcessorAdd permanentes.
    crate::ntos::ex::callbacks::init()?;
    // \GLOBAL??: o diretório global de devices DOS; todas as grafias resolvem
    // aos mesmos objetos, inclusive o GLOBALROOT para a raiz NT.
    object_manager::create_directory("\\GLOBAL??")?;
    object_manager::create_symlink("\\DosDevices", "\\GLOBAL??")?;
    object_manager::create_symlink("\\??", "\\GLOBAL??")?;
    object_manager::create_symlink("\\GLOBAL??\\GLOBALROOT", "\\")?;
    object_manager::create_directory("\\KernelObjects")?;
    crate::ntos::mm::partition::init()?;
    crate::ntos::mm::partition::install();
    // Eventos de pressão de memória e de commit abertos pelo mountmgr.
    for name in ["HighMemoryCondition", "LowMemoryCondition", "HighCommitCondition", "LowCommitCondition", "MaximumCommitCondition"] {
        crate::ntos::ps::user::events::create_kernel_event(&alloc::format!("\\KernelObjects\\{name}"), 0, false)?;
    }
    object_manager::mount("\\FS", &memory_file_system::VOLUME)?;
    object_manager::create_symlink("\\DosDevices\\C:", "\\FS")?;
    Ok(())
}

/// Serviço de driver: tipo kernel, Start e o caminho em
/// `\SystemRoot\System32\Drivers`; os de Start <= 1 sobem na fase 1.
fn seed_service(name: &str, driver_file: &str, start: u32) -> Result<(), crate::rtl::KernelError> {
    use crate::ntos::cm::service::database::{self as service_database, ConfigurationInput, ServiceError};
    let input = ConfigurationInput { name: alloc::string::String::from(name), service_type: Some(1), start: Some(start), image_path: Some(alloc::format!("\\SystemRoot\\System32\\Drivers\\{driver_file}")), ..ConfigurationInput::default() };
    match service_database::install(&input, false) {
        Ok(_) => Ok(()),
        Err(ServiceError::Win32(code, message)) => Err(crate::rtl::KernelError::new(alloc::format!("{name}: {message} ({code})"))),
        Err(ServiceError::Kernel(error)) => Err(error),
    }
}

/// Subchave Parameters de um serviço, como o INF criaria.
fn seed_service_parameters(name: &str, entries: &[(&str, u32)]) -> Result<(), crate::rtl::KernelError> {
    use crate::ntos::cm::registry;
    let handle = registry::open_or_create(&alloc::format!("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\{name}\\Parameters"), None)?;
    for &(value_name, value) in entries {
        registry::set_value(handle, value_name, 4, value.to_le_bytes().to_vec());
    }
    registry::close_handle(handle);
    Ok(())
}

/// Classe de dispositivo com os seus UpperFilters (REG_MULTI_SZ), lidos pelo
/// PnP para anexar os filtros de classe sobre o FDO funcional.
fn seed_device_class(class_guid: &str, upper_filters: &[&str]) -> Result<(), crate::rtl::KernelError> {
    use crate::ntos::cm::registry;
    let handle = registry::open_or_create(&alloc::format!("\\Registry\\Machine\\System\\Control\\Class\\{class_guid}"), None)?;
    let mut multi = alloc::vec::Vec::new();
    for filter in upper_filters {
        multi.extend(registry::encode_wide(filter));
    }
    multi.extend([0, 0]);
    registry::set_value(handle, "UpperFilters", 7, multi);
    registry::close_handle(handle);
    Ok(())
}

/// Hive de serviços com driver .sys (como `\System\Services` no NT): a pilha
/// de teclado/mouse sob demanda, a de armazenamento no boot (port -> class
/// -> mount manager), os parâmetros do i8042prt e as classes de teclado e
/// mouse, e o serviço do vgk (demand). Os drivers de integração da suíte de
/// testes, compilados em C, ficam fora.
fn seed_services() -> Result<(), crate::rtl::KernelError> {
    // i8042prt: demand, inicializado pela pilha de teclado; lê os defaults
    // da subchave Parameters no DriverEntry.
    seed_service("i8042prt", "i8042prt.sys", 3)?;
    // kbdclass/mouclass: filtros de classe carregados quando o PnP casa um
    // devnode da classe Keyboard/Mouse.
    seed_service("kbdclass", "kbdclass.sys", 3)?;
    seed_service("mouclass", "mouclass.sys", 3)?;
    // Armazenamento na ordem de boot do NT: miniport IDE (ataport carrega
    // como dependência de import), classe de disco e Mount Manager.
    seed_service("atapi", "atapi.sys", 0)?;
    seed_service("disk", "disk.sys", 0)?;
    seed_service("mountmgr", "mountmgr.sys", 0)?;
    // vgk: binário real no volume NTFS (D:\VGK.SYS); o cng.sys carrega como
    // módulo de import. Start=3: iniciado pelo SCM ou por `--start-driver=vgk`.
    seed_service("vgk", "vgk.sys", 3)?;
    // watchdog.sys: binário real da MS (WDM), dependência do stack de vídeo
    // (dxgkrnl/BasicDisplay). Start=3: iniciado por `--start-driver=watchdog`.
    seed_service("watchdog", "watchdog.sys", 3)?;
    seed_service_parameters("i8042prt", &[("KeyboardDataQueueSize", 0x64), ("MouseDataQueueSize", 0x64), ("PollStatusIterations", 0x2000), ("PollingIterations", 0x1900), ("ResendIterations", 3), ("OverrideKeyboardType", 0), ("CrashOnCtrlScroll", 0)])?;
    seed_device_class("{4D36E96B-E325-11CE-BFC1-08002BE10318}", &["kbdclass"])?;
    seed_device_class("{4D36E96F-E325-11CE-BFC1-08002BE10318}", &["mouclass"])?;
    Ok(())
}
