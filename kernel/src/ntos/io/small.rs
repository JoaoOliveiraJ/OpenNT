//! Módulos pequenos do I/O Manager.
//!
//! - `delete_device` — exclusão de objetos de dispositivo
//! - `completion_entry` — entradas das portas de conclusão
//! - `boot_drivers_state` — estado dos drivers de boot
//! - `initial_stack` — pilha de dispositivos inicial
//! - `thread_io` — I/O pendente por thread
//! - `configuration_information` — a CONFIGURATION_INFORMATION global
//! - `error_log` — entradas do log de erros de I/O
//! - `shutdown_notification` — dispositivos que recebem IRP_MJ_SHUTDOWN
//! - `priority_callbacks` — callbacks de prioridade de I/O registrados
//! - `wmi_registration` — dispositivos com classes WMI registradas
//! - `sfio_stream` — identificadores de stream do Storage QoS
//! - `partition_table` — IoReadPartitionTableEx
//! - `portable_operating_system` — RtlCheckPortableOperatingSystem

/// Remoção compartilhada pelos exports Io* e pelo descarregamento de drivers.
pub mod delete_device {
    use crate::ntos::ob::objects::device as device_objects;
    use crate::rtl::KernelError;

    /// IoDeleteDevice: o registro mantém o corpo enquanto arquivos abertos,
    /// anexos ou outras referências ainda o usam.
    pub fn delete_device(device: u64) -> Result<u32, KernelError> {
        if !device_objects::retire(device)? {
            return Err(KernelError::new("unregistered device deletion"));
        }
        Ok(0)
    }
}

/// Entrada de retirada de conclusões, resolvida depois da carga dos módulos
/// (sem ciclo entre os escalonadores).
pub mod completion_entry {
    use crate::rtl::{KernelError, SpinLock};

    pub type Removal = fn(&[u64]) -> Result<u64, KernelError>;

    static REMOVAL: SpinLock<Option<Removal>> = SpinLock::new(None);

    pub fn install(entry: Removal) -> Result<(), KernelError> {
        let mut removal = REMOVAL.lock();
        if removal.is_some_and(|current| current as usize != entry as usize) {
            return Err(KernelError::new("invalid completion removal registration"));
        }
        *removal = Some(entry);
        Ok(())
    }

    pub fn begin(arguments: &[u64]) -> Result<u64, KernelError> {
        let removal = REMOVAL.lock().ok_or_else(|| KernelError::new("completion removal is not initialized"))?;
        removal(arguments)
    }
}

/// A fase só termina depois de o gerenciador percorrer os drivers de boot;
/// o loader de recursos consulta este estado antes de abrir arquivos MUI.
pub mod boot_drivers_state {
    use core::sync::atomic::{AtomicBool, Ordering};

    static COMPLETED: AtomicBool = AtomicBool::new(false);

    pub fn is_initialized() -> bool {
        COMPLETED.load(Ordering::Acquire)
    }

    pub fn complete() {
        COMPLETED.store(true, Ordering::Release);
    }
}

/// IoGetInitialStack (19041): GS:[188] -> KTHREAD.InitialStack.
pub mod initial_stack {
    use crate::ntos::inc::field::Field;
    use crate::ntos::inc::types::{Kthread, NtStruct};
    use crate::ntos::ps::process;

    pub fn get() -> u64 {
        // SAFETY: a thread corrente.
        unsafe { Kthread::at(process::get_current_thread()) }.initial_stack.get()
    }

    /// A pilha de kernel da thread corrente: (StackLimit, StackBase) da
    /// KTHREAD (a pilha própria da thread, ou a de boot de quem roda nela).
    pub fn current_limits() -> (u64, u64) {
        let thread = process::get_current_thread();
        if thread == 0 {
            return (0, 0);
        }
        // SAFETY: a thread corrente.
        let thread = unsafe { Kthread::at(thread) };
        (thread.stack_limit.get(), thread.stack_base.get())
    }

    /// IoGetStackLimits: LowLimit = StackLimit e HighLimit = StackBase da
    /// pilha de kernel da thread corrente. (O OpenNT não tem pilhas de DPC
    /// nem de ISR separadas: DPCs e ISRs rodam na pilha de quem as despacha.)
    pub fn limits(low_output: u64, high_output: u64) {
        let (low, high) = current_limits();
        // SAFETY: PULONG_PTR LowLimit/HighLimit do chamador de modo kernel.
        unsafe {
            Field::<u64>::at(low_output).set(low);
            Field::<u64>::at(high_output).set(high);
        }
    }
}

/// ETHREAD.CrossThreadFlags.HardErrorsAreDisabled (19041); o bit segue a
/// thread por esperas e chamadas nativas aninhadas.
pub mod thread_io {
    use core::sync::atomic::Ordering;

    use crate::ntos::inc::types::{Ethread, NtStruct};
    use crate::ntos::ps::process;
    use crate::rtl::KernelError;

    /// IoSetThreadHardErrorMode: devolve o modo anterior (1 = habilitado).
    pub fn set_hard_error_mode(enabled: u8) -> Result<u32, KernelError> {
        let thread = process::get_current_thread();
        if thread == 0 {
            return Err(KernelError::new("hard-error mode requires a current thread"));
        }
        // ETHREAD.CrossThreadFlags.HardErrorsAreDisabled (bit 4).
        // SAFETY: a thread corrente.
        let flags = unsafe { Ethread::at(thread) }.cross_thread_flags.atomic();
        let previous = if enabled != 0 { flags.fetch_and(!Ethread::HARD_ERRORS_ARE_DISABLED_MASK, Ordering::SeqCst) } else { flags.fetch_or(Ethread::HARD_ERRORS_ARE_DISABLED_MASK, Ordering::SeqCst) };
        Ok(if previous & Ethread::HARD_ERRORS_ARE_DISABLED_MASK != 0 { 0 } else { 1 })
    }
}

/// IoGetConfigurationInformation: CONFIGURATION_INFORMATION global, criada
/// na primeira consulta (drivers incrementam as contagens).
pub mod configuration_information {
    use core::sync::atomic::{AtomicU64, Ordering};

    use crate::ntos::mm::guest_memory as guest;

    static CONFIGURATION_INFORMATION: AtomicU64 = AtomicU64::new(0);

    pub fn get() -> u64 {
        let current = CONFIGURATION_INFORMATION.load(Ordering::Acquire);
        if current != 0 {
            return current;
        }
        let pointer = guest::alloc_bytes(0x40);
        match CONFIGURATION_INFORMATION.compare_exchange(0, pointer, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => pointer,
            Err(existing) => {
                guest::free_bytes(pointer);
                existing
            }
        }
    }
}

/// IoAllocateErrorLogEntry / IoWriteErrorLogEntry: o código vai para o log
/// do sistema (serial).
pub mod error_log {
    use crate::ntos::mm::guest_memory as guest;

    pub fn allocate_entry(size: u8) -> u64 {
        guest::alloc_bytes(size as u64)
    }

    pub fn write_entry(entry: u64) {
        // SAFETY: IO_ERROR_LOG_PACKET alocado por allocate_entry e preenchido pelo driver.
        let code = unsafe { <crate::ntos::inc::types::IoErrorLogPacket as crate::ntos::inc::types::NtStruct>::at(entry) }.error_code.get() as u32;
        debug_print!("[errorlog] codigo=0x{:x}", code);
        guest::free_bytes(entry);
    }
}

/// IoRegister/UnregisterShutdownNotification: dispositivos que recebem
/// IRP_MJ_SHUTDOWN no desligamento.
pub mod shutdown_notification {
    use alloc::format;
    use alloc::vec::Vec;

    use crate::ntos::io::{device, io_manager};
    use crate::rtl::SpinLock;

    static SHUTDOWN_DEVICES: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());

    pub fn register(device: u64) {
        SHUTDOWN_DEVICES.lock().push(device);
    }

    pub fn unregister(device: u64) {
        let mut devices = SHUTDOWN_DEVICES.lock();
        if let Some(index) = devices.iter().position(|&candidate| candidate == device) {
            devices.remove(index);
        }
    }

    /// Chamado no desligamento: IRP_MJ_SHUTDOWN a cada dispositivo registrado.
    pub fn run_shutdown_notifications() {
        let devices = SHUTDOWN_DEVICES.lock().clone();
        for device in devices {
            let Some(node) = device::find_device_node_by_pointer(device) else { continue };
            let mut request = io_manager::make_io_request(io_manager::irp_mj::SHUTDOWN, io_manager::IoParams::default());
            let _ = io_manager::call_driver(&format!("\\Device\\{}", device::device_name(node)), &mut request);
        }
    }
}

/// IoRegister/UnregisterPriorityCallback: callbacks de prioridade de I/O.
pub mod priority_callbacks {
    use alloc::vec::Vec;

    use crate::rtl::SpinLock;

    static PRIORITY_CALLBACKS: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());

    pub fn register(callback: u64) {
        PRIORITY_CALLBACKS.lock().push(callback);
    }

    pub fn unregister(callback: u64) {
        let mut callbacks = PRIORITY_CALLBACKS.lock();
        if let Some(index) = callbacks.iter().position(|&candidate| candidate == callback) {
            callbacks.remove(index);
        }
    }
}

/// IoWMIRegistrationControl e as consultas WMI dos drivers: sem provedor
/// WMI nesta plataforma, os blocos não existem.
pub mod wmi_registration {
    use alloc::collections::BTreeSet;

    use crate::rtl::SpinLock;

    const STATUS_WMI_GUID_NOT_FOUND: u32 = 0xC000_0295;

    /// Dispositivos com classes WMI registradas.
    static WMI_DEVICES: SpinLock<BTreeSet<u64>> = SpinLock::new(BTreeSet::new());

    /// IoWMIRegistrationControl: a ação 0 registra; as demais retiram.
    pub fn registration_control(device: u64, action: u32) {
        if action == 0 {
            WMI_DEVICES.lock().insert(device);
        } else {
            WMI_DEVICES.lock().remove(&device);
        }
    }

    /// IoWMIDeviceObjectToProviderId: um ponteiro único e estável serve de
    /// id do provedor WMI.
    pub fn provider_id(device: u64) -> u64 {
        device as u32 as u64
    }

    /// IoWMIOpenBlock / IoWMIQueryAllData: sem provedor WMI, o GUID não
    /// existe — a inicialização de WMI dos drivers segue mesmo com essa falha.
    pub fn guid_not_found() -> u32 {
        STATUS_WMI_GUID_NOT_FOUND
    }
}

/// IoAllocateSfioStreamIdentifier: Storage QoS sem política configurada,
/// identificador nulo.
pub mod sfio_stream {
    use crate::ntos::inc::field::Field;
    use crate::ntos::inc::types::NtStruct;

    /// IoAllocateSfioStreamIdentifier: o PVOID* StreamIdentifier recebe NULL.
    pub fn allocate_identifier(output: u64) {
        if output != 0 {
            // SAFETY: PVOID* de saída do chamador de modo kernel.
            unsafe { Field::<u64>::at(output) }.set(0);
        }
    }
}

/// IoReadPartitionTableEx: IOCTL_DISK_GET_DRIVE_LAYOUT_EX ao dispositivo e
/// o buffer devolvido ao chamador.
pub mod partition_table {
    use alloc::format;

    use crate::ntos::io::{device, io_manager};
    use crate::ntos::ke::dispatcher;
    use crate::rtl::KernelError;
    use crate::ntos::mm::guest_memory as guest;

    const IOCTL_DISK_GET_DRIVE_LAYOUT_EX: u32 = 0x0007_0050;

    pub fn read_partition_table_ex(device_object: u64, output: u64) -> Result<u32, KernelError> {
        let buffer = guest::alloc_bytes(0x1000);
        let event = guest::alloc_bytes(0x18);
        dispatcher::initialize_event(event, 0, false);
        let Some(node) = device::find_device_node_by_pointer(device_object) else { return Ok(0xC000_000D) };
        let mut request = io_manager::make_io_request(io_manager::irp_mj::DEVICE_CONTROL, io_manager::IoParams { control_code: IOCTL_DISK_GET_DRIVE_LAYOUT_EX, binary: true, buffer_length: Some(0x1000), user_event: event, ..Default::default() });
        io_manager::call_driver(&format!("\\Device\\{}", device::device_name(node)), &mut request)?;
        if request.status != 0 {
            return Ok(request.status as u32);
        }
        if let io_manager::IoResult::Bytes(bytes) = &request.result {
            guest::write_bytes(buffer, &bytes[..bytes.len().min(0x1000)]);
        }
        // SAFETY: PDRIVE_LAYOUT_INFORMATION_EX* do chamador de modo kernel.
        unsafe { <crate::ntos::inc::field::Field<u64> as crate::ntos::inc::types::NtStruct>::at(output) }.set(buffer);
        Ok(0)
    }
}

/// RtlCheckPortableOperatingSystem: este boot nunca é Windows To Go.
pub mod portable_operating_system {
    use crate::ntos::inc::field::Field;
    use crate::ntos::inc::types::NtStruct;

    pub fn check(output: u64) {
        if output != 0 {
            // SAFETY: PBOOLEAN de saída do chamador de modo kernel.
            unsafe { Field::<u8>::at(output) }.set(0);
        }
    }
}

pub mod wdm_version {
    //! IoIsWdmVersionAvailable (ntoskrnl 19041 rva 0x89e370): o kernel do
    //! Windows 10 anuncia WDM 6.0 — versão maior abaixo de 6 é aceita, 6 só com
    //! a menor 0.

    const WDM_MAJOR_VERSION: u8 = 6;
    const WDM_MINOR_VERSION: u8 = 0;

    /// IoIsWdmVersionAvailable(MajorVersion, MinorVersion).
    pub fn is_available(major: u8, minor: u8) -> bool {
        major < WDM_MAJOR_VERSION || (major == WDM_MAJOR_VERSION && minor <= WDM_MINOR_VERSION)
    }
}

pub mod headless {
    //! HeadlessDispatch (ntoskrnl 19041 rva 0x3aa580) sem Emergency Management
    //! Services: HeadlessGlobals é NULL no OpenNT (nenhum terminal headless
    //! configurado no boot). Nesse estado o original devolve:
    //!   comandos 1 e 0x15                     -> STATUS_UNSUCCESSFUL;
    //!   comandos de consulta com saída (2, 11, 12, 15, 16 — máscara 0x13804)
    //!     zeram *OutputBufferSize bytes do OutputBuffer, ou
    //!     STATUS_INVALID_PARAMETER sem buffer/tamanho;
    //!   os demais                             -> STATUS_SUCCESS.

    use crate::ntos::inc::types::{Field, NtStruct};
    use crate::ntos::mm::guest_memory as guest;

    const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const QUERY_COMMAND_MASK: u32 = 0x0001_3804;

    /// HeadlessDispatch(Command, InputBuffer, InputBufferSize, OutputBuffer,
    /// OutputBufferSize*).
    pub fn dispatch(command: u32, _input: u64, _input_size: u64, output: u64, output_size: u64) -> u32 {
        if command == 0x15 || command == 1 {
            return STATUS_UNSUCCESSFUL;
        }
        if command <= 0x10 && (QUERY_COMMAND_MASK >> command) & 1 != 0 {
            if output == 0 || output_size == 0 {
                return STATUS_INVALID_PARAMETER;
            }
            // SAFETY: PSIZE_T OutputBufferSize de um chamador de modo kernel.
            let size = unsafe { Field::<u64>::at(output_size) }.get();
            guest::write_bytes(output, &alloc::vec![0u8; size as usize]);
        }
        0
    }
}
