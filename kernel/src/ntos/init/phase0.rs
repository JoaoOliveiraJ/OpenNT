//! FASE 0 do boot (estilo NT).
//!
//! Em ordem: política da hive, firmware e identidade do boot, relógio e
//! interrupções, memória (PFN, mapeamento recursivo, metade de sistema
//! congelada, descritores nativos, imagens carregadas, células de dado),
//! KPCR, SMP, pool, escalonador com o EPROCESS do System, os tipos de objeto
//! e as suas células, o sistema de arquivos em memória com as apps
//! embutidas, o namespace NT (com a partição e os eventos `\KernelObjects`)
//! e a hive de hardware (a descrição e o mapa de memória). A hive SYSTEM,
//! com os serviços, as definições WNF e o ProductPolicy do licenciamento,
//! só existe na fase 1, quando o volume que guarda o arquivo dela está
//! montado: nada da fase 0 lê nem escreve `\Registry\Machine\System`.

use crate::hal::bundle;
use crate::nano::interrupts;
use crate::drivers::fs::{memory_file_system, volume_device};
use crate::ntos::ke::clock;
use crate::ntos::cm::state_separation;
use crate::ntos::ke::{critical_region, pcr, smp};
use crate::ntos::mm::{direct_map, dump_mdl, kernel_data, kernel_pool, loaded_images, memory_map, native_pfn_database, pfn, pool_lock, process_address_space, recursive_mapping, shared_user_data};
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
    interrupts::init();
    // memory manager: alocador de frames físicos, tabelas supervisoras reais
    // (antes dos APs) e descritores nativos ligados ao PFN e às PTEs
    pfn::init().unwrap_or_else(|error| panic!("PFN: {error}"));
    // a RAM acima de 4 GB entra no mapa direto antes de algum frame dela sair do PFN
    direct_map::extend().unwrap_or_else(|error| panic!("mapa direto: {error}"));
    recursive_mapping::initialize().unwrap_or_else(|error| panic!("mapeamento recursivo: {error}"));
    // PML4[256..512) presentes e permanentes: toda raiz futura copia a metade de sistema
    process_address_space::prepare_system_space().unwrap_or_else(|error| panic!("metade de sistema: {error}"));
    native_pfn_database::initialize().unwrap_or_else(|error| panic!("PFN nativo: {error}"));
    // registra o ntoskrnl na sua ImageBase e publica os limites de usuário
    loaded_images::init_kernel().unwrap_or_else(|error| panic!("imagem do kernel: {error}"));
    kernel_data::write("MmUserProbeAddress", memory_map::USER_PROBE_ADDRESS);
    kernel_data::write("MmHighestUserAddress", memory_map::HIGHEST_USER_ADDRESS);
    pcr::init().unwrap_or_else(|error| panic!("KPCR: {error}")); // KPCR do BSP + IA32_GS_BASE
    // identidade do BSP na KPRCB (CPUID, FeatureBits, topologia, caches, MHz)
    crate::ntos::ke::processor_identity::initialize_boot_processor().unwrap_or_else(|error| panic!("{error}"));
    pool_lock::init().unwrap_or_else(|error| panic!("pool lock: {error}")); // lock nativo da arena NT
    crate::ntos::io::volume_parameters::init().unwrap_or_else(|error| panic!("{error}")); // LockQueueIoVpbLock antes dos drivers nativos
    crate::hal::pci_config::init().unwrap_or_else(|error| panic!("{error}")); // lock CF8/CFC antes dos APs
    shared_user_data::init(); // página KUSER_SHARED_DATA mapeada (drivers WDK)
    smp::init().unwrap_or_else(|error| panic!("SMP: {error}")); // ACPI MADT + INIT-SIPI dos APs (LAPIC)
    // identidade de cada AP na própria KPRCB e os conjuntos de pacote, núcleo e cache
    crate::ntos::ke::processor_identity::initialize_application_processors().unwrap_or_else(|error| panic!("{error}"));
    crate::ntos::kd::initialize(); // depurador do kernel (`--kd`): KdInitSystem com o transporte serial
    crate::ntos::kd::sampler::initialize(); // perfil por amostragem (`--perfil`)
    crate::ntos::mm::user_half::assert_user_only(); // trampolim desfeito: nada do kernel abaixo de MmSystemRangeStart
    // o cache de metadados do disco: o primeiro provedor de residência, que
    // devolve frames ao PFN antes de qualquer página ir para o disco
    crate::drivers::storage::sector_cache::initialize().unwrap_or_else(|error| panic!("cache de metadados: {error}"));
    crate::ntos::mm::image_paging::init().unwrap_or_else(|error| panic!("image paging: {error}"));
    kernel_pool::init(); // pool executivo (paginável com apoio no NTFS)
    crate::ntos::mm::page_fault::init(); // zero sob demanda das alocações privadas
    dump_mdl::init().unwrap_or_else(|error| panic!("dump MDL: {error}"));
    critical_region::init(); // entrega de APCs respeita KernelApcDisable/SpecialApcDisable
    scheduler::init().unwrap_or_else(|error| panic!("Process Manager: {error}")); // EPROCESS System + thread do boot
    loaded_images::publish_module_list().unwrap_or_else(|error| panic!("PsLoadedModuleList: {error}")); // lista do loader + ERESOURCE
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
            memory_file_system::write_embedded(&destination, data)
        } else {
            memory_file_system::write(&destination, &latin1_to_string(data))
        };
        if let Err(error) = stored {
            debug_print!("[boot] falha ao copiar {}: {}", name, error);
        }
    }
    namespace().unwrap_or_else(|error| panic!("namespace: {error}"));
    // CmInitSystem1: as chaves mestras e a hive volátil HARDWARE, antes da
    // descrição do hardware gravada nela.
    crate::ntos::cm::hive_init::initialize_hardware_hive().unwrap_or_else(|error| panic!("{error}"));
    crate::ntos::cm::hw_description::seed_hardware_description().unwrap_or_else(|error| panic!("{error}"));
    // mapa real de RAM na hive de hardware, antes de iniciar os drivers
    crate::ntos::cm::physical_memory_resources::initialize().unwrap_or_else(|error| panic!("{error}"));
}

/// Os diretórios de KnownDlls que o kernel cria, com o KnownDllPath de cada
/// um. São do smss: no boot do processo inicial real
/// (`--initial-process=smss`) o kernel não cria nenhum (o
/// SmpInitializeKnownDlls do smss.exe cria o `\KnownDlls` e, com o WoW64, o
/// `\KnownDlls32`). No boot sem o smss, o `\KnownDlls` e, com o volume do
/// WoW64, o `\KnownDlls32` da ntdll de 32 bits.
pub fn kernel_known_dll_directories(smss: bool, wow64: bool) -> &'static [(&'static str, &'static str)] {
    const NATIVE: (&str, &str) = ("\\KnownDlls", "C:\\Windows\\System32");
    const WOW64: (&str, &str) = ("\\KnownDlls32", "C:\\Windows\\SysWOW64");
    match (smss, wow64) {
        (true, _) => &[],
        (false, false) => &[NATIVE],
        (false, true) => &[NATIVE, WOW64],
    }
}

/// Diretórios e links do namespace NT, na ordem de criação, com a
/// partição do sistema e os eventos `\KernelObjects\*`.
fn namespace() -> Result<(), crate::rtl::KernelError> {
    crate::ntos::se::se_exports::init()?; // SE_EXPORTS na reserva permanente da imagem
    object_manager::create_directory("\\Device")?;
    object_manager::create_directory("\\Driver")?;
    for (directory, path) in kernel_known_dll_directories(crate::ntos::init::boot_config::smss_boot(), crate::ntos::init::boot_config::wow64()) {
        object_manager::create_directory(directory)?;
        object_manager::create_symlink(&alloc::format!("{directory}\\KnownDllPath"), path)?;
    }
    // CreateSystemRootLink: o \ArcName, \Device\BootDevice apontando para o
    // volume de boot (no NT, pelo \ArcName do dispositivo de boot; o OpenNT
    // não tem nome ARC para ele e aponta direto para o volume, montado na
    // fase 1) e o \SystemRoot, que é "\Device\BootDevice" + o diretório
    // instalado. Quem traduz o \SystemRoot componente a componente (o
    // luafv.sys) acha o volume ao abrir \Device\BootDevice como link.
    crate::ntos::io::arc_name::create_directory()?;
    object_manager::create_symlink("\\Device\\BootDevice", &volume_device::device_path(crate::drivers::fs::ntfs::DEVICE_INDEX))?;
    object_manager::create_symlink("\\SystemRoot", "\\Device\\BootDevice\\Windows")?;
    // CmpInitializeDriverStores: o diretório e o alias do sistema.
    object_manager::create_directory("\\DriverStores")?;
    object_manager::create_symlink("\\DriverStores\\SYSTEM", "\\SystemRoot")?;
    // \Callback com os sete objetos permanentes do ExpInitializeCallbacks.
    crate::ntos::ex::callbacks::init()?;
    // ObpInitializeRootNamespace: o \ObjectTypes com um objeto Type por tipo.
    crate::ntos::ob::object_types::initialize_type_directory()?;
    // \GLOBAL??: o diretório global de devices DOS, com o GLOBALROOT para a
    // raiz NT e o Global de volta ao próprio \GLOBAL??, e o \DosDevices da
    // raiz como link para \?? (ObpCreateDosDevicesDirectory). O \?? não é um
    // objeto: o ObpLookupObjectName o troca pelo diretório do mapa de
    // devices de quem procura (`ob/device_map.rs`), que a fase 1 liga ao
    // \GLOBAL?? para o System e os tokens do SYSTEM.
    object_manager::create_directory("\\GLOBAL??")?;
    object_manager::create_symlink("\\DosDevices", "\\??")?;
    object_manager::create_symlink("\\GLOBAL??\\GLOBALROOT", "\\")?;
    object_manager::create_symlink("\\GLOBAL??\\Global", "\\GLOBAL??")?;
    // Os dispositivos DOS do `DOS Devices` do Session Manager (CON, CONIN$,
    // CONOUT$, NUL, PIPE, MAILSLOT...). No boot do processo inicial real quem
    // os cria é o smss, a partir do Registro (SmpInitializeDosDevices); o
    // condrv, o ntoskrnl e o kernelbase não criam nenhum, e o "CONOUT$" de
    // um CreateFile vira \??\CONOUT$ (RtlpIsDosDeviceName_Ustr da ntdll).
    if !crate::ntos::init::boot_config::smss_boot() {
        for &(name, target) in crate::ntos::cm::session_manager::DOS_DEVICES {
            object_manager::create_symlink(&alloc::format!("\\GLOBAL??\\{name}"), target)?;
        }
    }
    object_manager::create_directory("\\KernelObjects")?;
    crate::ntos::mm::partition::init()?;
    crate::ntos::mm::partition::install();
    // MiSectionInitialization: a seção nomeada da memória física.
    crate::ntos::mm::section::physical_memory::initialize()?;
    // Os eventos de memória do MiInitializeMemoryEvents (a tabela
    // MiMemoryEventNames, na ordem dela): pool paginável e não paginável,
    // memória, commit, erros de memória e mudança da memória física. Com o
    // pool folgado, o MiInitializePagedPoolEvents e o
    // MiSignalNonPagedPoolWatchers deixam os High*PoolCondition sinalizados
    // e os Low* não (o mountmgr abre os de memória e de commit; o tcpip.sys
    // abre o LowPagedPoolCondition).
    for (name, signaled) in [
        ("LowPagedPoolCondition", false),
        ("HighPagedPoolCondition", true),
        ("LowNonPagedPoolCondition", false),
        ("HighNonPagedPoolCondition", true),
        ("LowMemoryCondition", false),
        ("HighMemoryCondition", false),
        ("LowCommitCondition", false),
        ("HighCommitCondition", false),
        ("MaximumCommitCondition", false),
        ("MemoryErrors", false),
        ("PhysicalMemoryChange", false),
    ] {
        // Com o descritor do MiCreateMemoryEventSD.
        let event = crate::ntos::ps::user::events::create_kernel_event(&alloc::format!("\\KernelObjects\\{name}"), 0, signaled)?;
        crate::ntos::ob::objects::dispatcher::set_security(event.pointer, crate::ntos::mm::partition::memory_event_policy());
    }
    // O disco em memória no seu dispositivo (\Device\KernelVolume0), o C:;
    // \FS é o nome curto que os componentes do boot usam para ele. No boot
    // do smss o C: é o volume do sistema, o NTFS que tem o \Windows do
    // \SystemRoot, e a fase 1 cria o link quando o monta.
    let memory = volume_device::mount(0, &memory_file_system::VOLUME)?;
    object_manager::create_symlink("\\FS", &memory)?;
    if !crate::ntos::init::boot_config::smss_boot() {
        object_manager::create_symlink("\\GLOBAL??\\C:", &memory)?;
    }
    Ok(())
}

