//! Timers e estado de I/O por dispositivo e por thread.
//!
//! - `io_timer` — IoTimers por dispositivo
//! - `thread_activity` — atividade de I/O por thread
//! - `thread_requests` — IRPs pendentes por thread

/// IoInitializeTimer/IoStartTimer/IoStopTimer: uma rotina por dispositivo,
/// chamada a cada ~1 s enquanto ligada; DEVICE_OBJECT.Timer marca o
/// dispositivo com timer inicializado.
pub mod io_timer {
    use alloc::vec::Vec;

    use crate::hal::amd64::native_call;
    use crate::ntos::ke::clock;
    use crate::rtl::SpinLock;
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::inc::nt_abi::device_object;

    const IO_TIMER_PERIOD_MS: u64 = 1000;

    #[derive(Clone, Copy)]
    struct DeviceTimer {
        device: u64,
        routine: u64,
        context: u64,
        active: bool,
        next_due_ms: u64,
    }

    static TIMERS: SpinLock<Vec<DeviceTimer>> = SpinLock::new(Vec::new());

    /// Rotina e contexto ficam com os 32 bits baixos, como no original.
    pub fn initialize_timer(device: u64, routine: u64, context: u64) -> u32 {
        let mut timers = TIMERS.lock();
        if timers.iter().any(|timer| timer.device == device) {
            return 0xC000_0035;
        }
        timers.push(DeviceTimer { device, routine: routine as u32 as u64, context: context as u32 as u64, active: false, next_due_ms: 0 });
        guest::write64(device + device_object::TIMER, 1);
        0
    }

    pub fn start_timer(device: u64) -> u32 {
        match TIMERS.lock().iter_mut().find(|timer| timer.device == device) {
            Some(timer) => {
                timer.active = true;
                timer.next_due_ms = clock::uptime_ms() + IO_TIMER_PERIOD_MS;
                0
            }
            None => 0xC000_000D,
        }
    }

    pub fn stop_timer(device: u64) -> u32 {
        match TIMERS.lock().iter_mut().find(|timer| timer.device == device) {
            Some(timer) => {
                timer.active = false;
                0
            }
            None => 0xC000_000D,
        }
    }

    /// Do laço ocioso: dispara IoTimerRoutine(DeviceObject, Context) vencidas.
    pub fn check_io_timers() {
        let now = clock::uptime_ms();
        let due: Vec<DeviceTimer> = {
            let mut timers = TIMERS.lock();
            timers
                .iter_mut()
                .filter(|timer| timer.active && timer.next_due_ms <= now)
                .map(|timer| {
                    timer.next_due_ms = now + IO_TIMER_PERIOD_MS;
                    *timer
                })
                .collect()
        };
        for timer in due {
            native_call::call(timer.routine, &[timer.device, timer.context]);
        }
    }

    /// Força o vencimento (diagnóstico e testes).
    pub fn expire_now(device: u64) {
        if let Some(timer) = TIMERS.lock().iter_mut().find(|timer| timer.device == device) {
            timer.next_due_ms = 0;
        }
    }

    pub fn forget_device(device: u64) {
        TIMERS.lock().retain(|timer| timer.device != device);
    }
}

/// Activity ID da ETHREAD corrente, no mesmo campo lido pelo código nativo.
/// O chamador mantém o GUID vivo; nada é copiado nem alocado aqui.
pub mod thread_activity {
    use crate::ntos::ps::process;
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::inc::nt_abi::kthread;

    fn field() -> u64 {
        process::get_current_thread() + kthread::ACTIVITY_ID
    }

    pub fn get() -> u64 {
        guest::read64(field())
    }

    /// IoSetActivityIdThread: devolve o ponteiro anterior.
    pub fn set(activity: u64) -> u64 {
        let field = field();
        let previous = guest::read64(field);
        guest::write64(field, activity);
        previous
    }

    /// IoClearActivityIdThread: restaura o ponteiro recebido, mesmo NULL.
    pub fn clear(previous: u64) {
        guest::write64(field(), previous);
    }

    /// IoPropagateActivityIdToThread: captura os 16 bytes antes de escrever
    /// (aceita buffers iguais); sem origem devolve STATUS_NOT_FOUND.
    pub fn propagate(source: u64, propagated: u64, previous_output: u64) -> u32 {
        if source == 0 {
            return 0xC000_0225;
        }
        let first = guest::read64(source);
        let second = guest::read64(source + 8);
        guest::write64(propagated, first);
        guest::write64(propagated + 8, second);
        let previous = set(propagated);
        guest::write64(previous_output, previous);
        0
    }
}

/// IRPs pendentes ligados à ETHREAD real (lista e trava do 19041).
pub mod thread_requests {
    use crate::hal::cpu;
    use crate::ntos::ke::irql;
    use crate::rtl::KernelError;
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::inc::nt_abi::kthread;

    const THREAD_LIST_ENTRY: u64 = 0x20;

    fn with_lock<T>(thread: u64, operation: impl FnOnce() -> Result<T, KernelError>) -> Result<T, KernelError> {
        let lock = thread + kthread::IRP_LIST_LOCK;
        let previous = irql::raise_irql(2);
        while guest::compare_exchange64(lock, 0, 1)? != 0 {
            cpu::pause();
        }
        let result = operation();
        let _ = guest::compare_exchange64(lock, 1, 0);
        irql::lower_irql(previous as u64);
        result
    }

    /// IopQueueThreadIrp: insere no início da lista da thread.
    pub fn insert(request: u64, thread: u64) -> Result<(), KernelError> {
        let entry = request + THREAD_LIST_ENTRY;
        let head = thread + kthread::IRP_LIST_HEAD;
        with_lock(thread, || {
            let first = guest::read64(head);
            if first == 0 || guest::read64(first + 8) != head {
                return Err(KernelError::new("invalid ETHREAD IRP list"));
            }
            if guest::read64(entry) != 0 || guest::read64(entry + 8) != 0 {
                return Err(KernelError::new("IRP already linked"));
            }
            guest::write64(entry, first);
            guest::write64(entry + 8, head);
            guest::write64(first + 8, entry);
            guest::write64(head, entry);
            Ok(())
        })
    }

    /// A conclusão retira só o pedido que possui, fora de ordem inclusive.
    pub fn remove(request: u64, thread: u64) -> Result<(), KernelError> {
        let entry = request + THREAD_LIST_ENTRY;
        with_lock(thread, || {
            let next = guest::read64(entry);
            let previous = guest::read64(entry + 8);
            if next == 0 || previous == 0 || guest::read64(next + 8) != entry || guest::read64(previous) != entry {
                return Err(KernelError::new("invalid linked IRP"));
            }
            guest::write64(previous, next);
            guest::write64(next + 8, previous);
            guest::write64(entry, 0);
            guest::write64(entry + 8, 0);
            Ok(())
        })
    }
}
