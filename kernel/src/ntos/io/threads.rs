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
    use crate::ntos::inc::types::{DeviceObject, NtStruct};

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

    /// IoInitializeTimer: rotina e contexto guardados inteiros; o
    /// DEVICE_OBJECT.Timer recebe uma marca não nula (o IO_TIMER do NT fica
    /// no registro de cá).
    pub fn initialize_timer(device: u64, routine: u64, context: u64) -> u32 {
        let mut timers = TIMERS.lock();
        if timers.iter().any(|timer| timer.device == device) {
            return 0xC000_0035;
        }
        timers.push(DeviceTimer { device, routine, context, active: false, next_due_ms: 0 });
        // SAFETY: DEVICE_OBJECT vivo do driver.
        unsafe { DeviceObject::at(device) }.timer.set(1);
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
    use crate::ntos::inc::field::Field;
    use crate::ntos::inc::types::{Ethread, Guid, NtStruct};
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::ps::process;

    /// ETHREAD.ActivityId (PGUID) da thread corrente.
    fn field() -> &'static Field<u64> {
        // SAFETY: a thread corrente é um ETHREAD vivo.
        &unsafe { Ethread::at(process::get_current_thread()) }.activity_id
    }

    pub fn get() -> u64 {
        field().get()
    }

    /// IoSetActivityIdThread: devolve o ponteiro anterior.
    pub fn set(activity: u64) -> u64 {
        let field = field();
        let previous = field.get();
        field.set(activity);
        previous
    }

    /// IoClearActivityIdThread: restaura o ponteiro recebido, mesmo NULL.
    pub fn clear(previous: u64) {
        field().set(previous);
    }

    /// IoPropagateActivityIdToThread: captura os 16 bytes antes de escrever
    /// (aceita buffers iguais); sem origem devolve STATUS_NOT_FOUND.
    pub fn propagate(source: u64, propagated: u64, previous_output: u64) -> u32 {
        if source == 0 {
            return 0xC000_0225;
        }
        let guid = guest::read_bytes(source, Guid::SIZE as usize);
        guest::write_bytes(propagated, &guid);
        let previous = set(propagated);
        // SAFETY: PGUID* PreviousActivityId do chamador de modo kernel.
        unsafe { Field::<u64>::at(previous_output) }.set(previous);
        0
    }
}

/// IRPs pendentes ligados à ETHREAD real (lista e trava do 19041).
pub mod thread_requests {
    use core::sync::atomic::Ordering;

    use crate::hal::cpu;
    use crate::ntos::inc::types::{Ethread, Irp, ListEntry, NtStruct};
    use crate::ntos::ke::irql;
    use crate::rtl::KernelError;

    fn thread_at(thread: u64) -> &'static Ethread {
        // SAFETY: ETHREAD vivo (retido pelo pedido).
        unsafe { Ethread::at(thread) }
    }

    fn link_at(address: u64) -> &'static ListEntry {
        // SAFETY: elos da lista IrpList (cabeça na ETHREAD ou ThreadListEntry de um IRP).
        unsafe { ListEntry::at(address) }
    }

    /// Irp->ThreadListEntry.
    fn entry_of(request: u64) -> &'static ListEntry {
        // SAFETY: IRP vivo do chamador.
        &unsafe { Irp::at(request) }.thread_list_entry
    }

    /// ETHREAD.IrpListLock (KSPIN_LOCK) retido em DISPATCH_LEVEL.
    fn with_lock<T>(thread: u64, operation: impl FnOnce() -> Result<T, KernelError>) -> Result<T, KernelError> {
        let lock = thread_at(thread).irp_list_lock.atomic();
        let previous = irql::raise_irql(2);
        while lock.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
            cpu::pause();
        }
        let result = operation();
        lock.store(0, Ordering::Release);
        irql::lower_irql(previous as u64);
        result
    }

    /// IopQueueThreadIrp: insere no início da lista da thread.
    pub fn insert(request: u64, thread: u64) -> Result<(), KernelError> {
        let entry = entry_of(request);
        let head = &thread_at(thread).irp_list;
        with_lock(thread, || {
            let first = head.flink.get();
            if first == 0 || link_at(first).blink.get() != head.address() {
                return Err(KernelError::new("invalid ETHREAD IRP list"));
            }
            if entry.flink.get() != 0 || entry.blink.get() != 0 {
                return Err(KernelError::new("IRP already linked"));
            }
            entry.flink.set(first);
            entry.blink.set(head.address());
            link_at(first).blink.set(entry.address());
            head.flink.set(entry.address());
            Ok(())
        })
    }

    /// As IRPs da IrpList da thread, da cabeça para o fim (com a trava).
    pub fn of_thread(thread: u64) -> Result<alloc::vec::Vec<u64>, KernelError> {
        let head = &thread_at(thread).irp_list;
        let offset = core::mem::offset_of!(Irp, thread_list_entry) as u64;
        with_lock(thread, || {
            let mut requests = alloc::vec::Vec::new();
            let mut link = head.flink.get();
            while link != 0 && link != head.address() && requests.len() < 4096 {
                requests.push(link - offset);
                link = link_at(link).flink.get();
            }
            Ok(requests)
        })
    }

    /// A conclusão retira só o pedido que possui, fora de ordem inclusive.
    pub fn remove(request: u64, thread: u64) -> Result<(), KernelError> {
        let entry = entry_of(request);
        with_lock(thread, || {
            let next = entry.flink.get();
            let previous = entry.blink.get();
            if next == 0 || previous == 0 || link_at(next).blink.get() != entry.address() || link_at(previous).flink.get() != entry.address() {
                return Err(KernelError::new("invalid linked IRP"));
            }
            link_at(previous).flink.set(next);
            link_at(next).blink.set(previous);
            entry.flink.set(0);
            entry.blink.set(0);
            Ok(())
        })
    }
}

/// IRP de nível superior da thread corrente e o processo de uma thread —
/// ntoskrnl 19041 IoGetTopLevelIrp 0x2d73f0, IoSetTopLevelIrp 0x2d73d0
/// (`gs:[0x188]` -> ETHREAD.TopLevelIrp) e IoThreadToProcess 0x2056c0
/// (KTHREAD.Process, o mesmo campo de PsGetThreadProcess). Sem validação nem
/// referência, como os originais. É o mesmo campo que o lazy writer do Cc
/// salva e zera.
pub mod top_level_irp {
    use crate::ntos::inc::types::{Ethread, NtStruct};
    use crate::ntos::ps::{process, thread_accessors};

    fn current_thread() -> &'static Ethread {
        // SAFETY: a thread corrente do Process Manager é um ETHREAD vivo.
        unsafe { Ethread::at(process::get_current_thread()) }
    }

    /// IoGetTopLevelIrp: o IRP (ou marcador FSRTL_*_TOP_LEVEL_IRP) da thread
    /// corrente.
    pub fn get() -> u64 {
        current_thread().top_level_irp.get()
    }

    /// IoSetTopLevelIrp(Irp).
    pub fn set(irp: u64) {
        current_thread().top_level_irp.set(irp);
    }

    /// IoThreadToProcess(Thread).
    pub fn thread_to_process(thread: u64) -> u64 {
        thread_accessors::process(thread)
    }
}

/// Consultas de thread usadas por file systems e filtros: IoIsSystemThread
/// (RVA 0x3096d0, KTHREAD.MiscFlags.SystemThread) e IoWithinStackLimits
/// (RVA 0x2e53b0).
pub mod thread_queries {
    use crate::ntos::inc::types::extra_fs_fat::KernelStackControl;
    use crate::ntos::inc::types::{Kthread, NtStruct};
    use crate::ntos::ps::process;

    pub fn is_system_thread(thread: &Kthread) -> bool {
        thread.system_thread() != 0
    }

    /// [Start, Start+Size] dentro da pilha corrente: [StackLimit, StackBase] da
    /// thread e, a partir de InitialStack, os segmentos anteriores do
    /// KERNEL_STACK_CONTROL de pilhas expandidas. Toda KTHREAD publica
    /// StackBase/StackLimit (`ps::process::create_kernel_thread`); sem limites
    /// publicados (a pilha já devolvida pelo ceifador) a região não pode ser
    /// provada na pilha e a resposta é FALSE. O controle só é seguido quando
    /// cabe dentro do segmento, como no NT; a thread que descreve a pilha de
    /// boot tem InitialStack no topo, sem controle. O ramo da pilha de DPC
    /// (Prcb.DpcStack) não existe no OpenNT.
    pub fn within_stack_limits(start: u64, size: u64) -> bool {
        let address = process::get_current_thread();
        if address == 0 {
            return false;
        }
        // SAFETY: o KTHREAD corrente.
        let thread = unsafe { Kthread::at(address) };
        let end = start.wrapping_add(size);
        let (mut high, mut low) = (thread.stack_base.get(), thread.stack_limit.get());
        if high == 0 || low == 0 {
            return false;
        }
        let mut control = thread.initial_stack.get();
        for _ in 0..64 {
            if start >= low && end <= high {
                return true;
            }
            if control < low || control > high.saturating_sub(KernelStackControl::SIZE) {
                return false;
            }
            // SAFETY: o KERNEL_STACK_CONTROL cabe no segmento publicado, que
            // está mapeado.
            let previous = &unsafe { KernelStackControl::at(control) }.previous;
            if previous.stack_base.get() == 0 {
                return false;
            }
            high = previous.stack_base.get();
            low = previous.stack_limit.get();
            control = previous.initial_stack.get();
        }
        false
    }
}

/// IoTransferActivityId(ActivityId, RelatedActivityId) (RVA 0x398c60): só
/// escreve o evento IoTrace_ActivityIdTransfer (EtwWriteEx no IoTraceHandle)
/// quando uma sessão habilitou o provedor IoTrace do kernel. O OpenNT não
/// registra esse provedor interno do ntoskrnl, então nenhuma sessão o
/// habilita: a rotina não faz nada, como no Windows sem sessão IoTrace.
pub mod activity_transfer {
    pub fn transfer(_activity: u64, _related_activity: u64) {}
}
