//! Módulos pequenos do I/O Manager.
//!
//! - `delete_device` — `system32/ntos/io/delete-device.js`
//! - `completion_entry` — `system32/ntos/io/completion-entry.js`
//! - `boot_drivers_state` — `system32/ntos/io/boot-drivers-state.js`
//! - `initial_stack` — `system32/ntos/io/initial-stack.js`
//! - `thread_io` — `system32/ntos/io/thread-io.js`

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
    use crate::ntos::ps::process;
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::inc::nt_abi::kthread;

    pub fn get() -> u64 {
        guest::read64(process::get_current_thread() + kthread::INITIAL_STACK)
    }
}

/// ETHREAD.CrossThreadFlags.HardErrorsAreDisabled (19041); o bit segue a
/// thread por esperas e chamadas nativas aninhadas.
pub mod thread_io {
    use crate::ntos::ps::process;
    use crate::rtl::KernelError;
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::inc::nt_abi::kthread;

    /// IoSetThreadHardErrorMode: devolve o modo anterior (1 = habilitado).
    pub fn set_hard_error_mode(enabled: u8) -> Result<u32, KernelError> {
        let thread = process::get_current_thread();
        if thread == 0 {
            return Err(KernelError::new("hard-error mode requires a current thread"));
        }
        let address = thread + kthread::CROSS_THREAD_FLAGS;
        loop {
            let previous = guest::read32(address);
            let next = if enabled != 0 { previous & !16 } else { previous | 16 };
            if guest::compare_exchange32(address, previous, next)? == previous {
                return Ok(if previous & 16 != 0 { 0 } else { 1 });
            }
        }
    }
}
