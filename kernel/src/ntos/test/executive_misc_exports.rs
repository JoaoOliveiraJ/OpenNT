//! Autoteste dos exports de Ex, Etw, Inbv, Hvl, Ob e Tm que eram os últimos
//! imports de drivers reais.
//!
//! Cada export é chamado pelo trampolim nativo (ABI MS x64). Os valores
//! esperados seguem o ntoskrnl 19041: os caminhos lidos na desmontagem para
//! a configuração do OpenNT (firmware BIOS, sem hipervisor conectado, sem
//! tm.sys, vídeo de boot em modo texto).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{EtwBufferState, LookasideListEx, WmiBufferHeader};
use crate::ntos::mm::guest_memory as guest;

type Assert = fn(bool, &str);

fn call(name: &str, arguments: &[u64]) -> u64 {
    super::phase6::call_export(name, arguments).unwrap_or(0xDEAD_DEAD_DEAD_DEAD)
}

fn status(value: u32) -> u64 {
    crate::ntos::init::exports::signed_status(value)
}

fn zeroed(size: u64) -> u64 {
    let block = guest::alloc_bytes(size);
    guest::write_bytes(block, &alloc::vec![0u8; size as usize]);
    block
}

/// Espera ~10 ms (KeDelayExecutionThread relativo), deixando a CPU para as
/// threads de sistema.
fn sleep_10ms() {
    let interval = zeroed(8);
    guest::write64(interval, (-100_000i64) as u64);
    call("KeDelayExecutionThread", &[0, 0, interval]);
    guest::free_bytes(interval);
}

pub fn run(assert: Assert) {
    lookaside_flush(assert);
    boot_device(assert);
    firmware_variable(assert);
    etw_send_trace_buffer(assert);
    inbv_boot_driver(assert);
    hypervisor_queries(assert);
    nt_event_and_wait(assert);
    zw_query_information_transaction(assert);
}

// ---- ExFlushLookasideListEx ------------------------------------------------

static FREED: AtomicU64 = AtomicU64::new(0);
static FREED_FROM: AtomicU64 = AtomicU64::new(0);

/// FreeEx(Buffer, Lookaside) de teste: conta e devolve ao pool.
extern "win64" fn counting_free(buffer: u64, lookaside: u64) {
    FREED.fetch_add(1, Ordering::SeqCst);
    FREED_FROM.store(lookaside, Ordering::SeqCst);
    let _ = crate::ntos::ex::pool_allocation::free(buffer, 0);
}

fn lookaside_flush(assert: Assert) {
    use crate::ntos::ex::{lookaside, slist};
    let list = zeroed(LookasideListEx::SIZE);
    FREED.store(0, Ordering::SeqCst);
    let free_routine = counting_free as extern "win64" fn(u64, u64) as usize as u64;
    let initialized = call("ExInitializeLookasideListEx", &[list, 0, free_routine, 0x200, 0, 0x40, 0x4C57_5132, 0]);
    let blocks: Vec<u64> = (0..3).map(|_| lookaside::allocate(list).unwrap_or(0)).collect();
    for &block in &blocks {
        let _ = lookaside::free(list, block);
    }
    let cached = (slist::depth(list), FREED.load(Ordering::SeqCst));
    // SAFETY: LOOKASIDE_LIST_EX recém-inicializada.
    let descriptor = unsafe { LookasideListEx::at(list) };
    let depth_before = descriptor.l.depth.get();
    call("ExFlushLookasideListEx", &[list]);
    let flushed = (slist::depth(list), FREED.load(Ordering::SeqCst), FREED_FROM.load(Ordering::SeqCst));
    call("ExFlushLookasideListEx", &[list]);
    let again = FREED.load(Ordering::SeqCst);
    assert(
        initialized == 0 && blocks.iter().all(|&block| block != 0) && cached == (3, 0) && flushed == (0, 3, list) && again == 3 && descriptor.l.depth.get() == depth_before && descriptor.l.total_frees.get() == 3,
        "ex-lookaside-flush: ExFlushLookasideListEx devolve cada entrada do cache ao FreeEx(Buffer, Lookaside) e mantém Depth e contadores",
    );
    call("ExDeleteLookasideListEx", &[list]);
}

// ---- ExRegisterBootDevice / ExNotifyBootDeviceRemoval ------------------------

static BOOT_CALLS: AtomicU64 = AtomicU64::new(0);
static BOOT_ARGUMENTS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

/// BOOLEAN Callback(Object, Context): o dispositivo voltou.
extern "win64" fn boot_device_back(object: u64, context: u64) -> u8 {
    BOOT_ARGUMENTS[0].store(object, Ordering::SeqCst);
    BOOT_ARGUMENTS[1].store(context, Ordering::SeqCst);
    BOOT_CALLS.fetch_add(1, Ordering::SeqCst);
    1
}

/// Um KEVENT de verdade (ZwCreateEvent + ObReferenceObjectByHandle) para
/// os objetos retidos pelo registro.
fn referenced_event() -> u64 {
    let block = zeroed(16);
    call("ZwCreateEvent", &[block, 0x1F_0003, 0, 0, 0]);
    let handle = guest::read64(block);
    call("ObReferenceObjectByHandle", &[handle, 0, 0, 0, block + 8, 0]);
    let pointer = guest::read64(block + 8);
    call("ZwClose", &[handle]);
    pointer
}

fn boot_device(assert: Assert) {
    use crate::ntos::ex::boot_device;
    let object = referenced_event();
    let callback_object = referenced_event();
    let registration = zeroed(0x28);
    let handle = zeroed(8);
    // SAFETY: BOOT_DEVICE_REGISTRATION de teste.
    let fields = unsafe { boot_device::BootDeviceRegistration::at(registration) };
    let fill = |version: u32, reserved: u32, retained: u64, callback: u64| {
        fields.version.set(version);
        fields.reserved.set(reserved);
        fields.object.set(retained);
        fields.callback_object.set(callback_object);
        fields.callback.set(callback);
        fields.context.set(0xC0_7E47);
    };
    let callback = boot_device_back as extern "win64" fn(u64, u64) -> u8 as usize as u64;
    let invalid = [(2, 0, object, callback), (1, 1, object, callback), (1, 0, 0, callback), (1, 0, object, 0)].iter().all(|&(version, reserved, retained, routine)| {
        fill(version, reserved, retained, routine);
        call("ExRegisterBootDevice", &[registration, handle]) == status(0xC000_000D)
    });
    assert(invalid && guest::read64(handle) == 0 && object != 0 && callback_object != 0, "ex-boot-device: Version != 1, reservado, objeto ou rotina ausentes = STATUS_INVALID_PARAMETER");
    fill(1, 0, object, callback);
    let registered = call("ExRegisterBootDevice", &[registration, handle]);
    let entry = guest::read64(handle);
    assert(registered == 0 && entry != 0 && guest::read32(entry) == 0x504E_4442 && guest::read64(entry + 0x30) == callback && boot_device::removal_handler() != 0, "ex-boot-device: ExRegisterBootDevice devolve a entrada 'BDNP' com a cópia do registro e cria a thread de espera");
    let bogus = zeroed(0x40);
    assert(call("ExNotifyBootDeviceRemoval", &[bogus]) & 0xFF == 0, "ex-boot-device: handle sem a assinatura = FALSE");
    BOOT_CALLS.store(0, Ordering::SeqCst);
    let notified = call("ExNotifyBootDeviceRemoval", &[entry]) & 0xFF;
    let mut waited = 0;
    while BOOT_CALLS.load(Ordering::SeqCst) == 0 && waited < 300 {
        sleep_10ms();
        waited += 1;
    }
    let mut settled = 0;
    while boot_device::missing(entry) != (0, 0) && settled < 100 {
        sleep_10ms();
        settled += 1;
    }
    assert(
        notified == 1 && BOOT_CALLS.load(Ordering::SeqCst) == 1 && BOOT_ARGUMENTS[0].load(Ordering::SeqCst) == callback_object && BOOT_ARGUMENTS[1].load(Ordering::SeqCst) == 0xC0_7E47 && boot_device::missing(entry) == (0, 0),
        "ex-boot-device: a remoção acorda a ExpWaitForBootDevices, que chama a rotina com o objeto e o contexto e desconta o dispositivo de volta",
    );
}

// ---- ExSetFirmwareEnvironmentVariable ----------------------------------------

fn firmware_variable(assert: Assert) {
    let bios = matches!(crate::hal::firmware_environment::firmware_type(), Ok(1));
    // Nem os argumentos NULL são tocados antes da checagem do firmware.
    assert(bios && call("ExSetFirmwareEnvironmentVariable", &[0, 0, 0, 0, 0]) == status(0xC000_0002), "ex-set-firmware-variable: firmware BIOS = STATUS_NOT_IMPLEMENTED antes de ler os argumentos");
}

// ---- EtwSendTraceBuffer --------------------------------------------------------

fn etw_send_trace_buffer(assert: Assert) {
    use crate::ntos::etw::logger;
    let block = zeroed(0x400);
    let (properties, returned, name, buffer) = (block, block + 0x180, block + 0x100, block + 0x200);
    let text: Vec<u16> = "OpenNT-Buffers".encode_utf16().collect();
    guest::write_bytes(name, &text.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    // WMI_LOGGER_INFORMATION: Wnode.BufferSize, Wnode.Flags (TRACED_GUID),
    // LogFileMode e LoggerName, como no teste do ZwTraceControl.
    let prepare = |mode: u32| {
        guest::write_bytes(properties, &[0; 0xB0]);
        guest::write32(properties, 0xB0);
        guest::write32(properties + 0x2C, 0x2_0000);
        guest::write32(properties + 0x40, mode);
        guest::write16(properties + 0x90, (text.len() * 2) as u16);
        guest::write16(properties + 0x92, (text.len() * 2) as u16);
        guest::write64(properties + 0x98, name);
    };
    let control = |code: u32| logger::trace_control(code, properties, 0xB0, properties, 0xB0, returned, 0).unwrap_or(u32::MAX);
    assert(call("EtwSendTraceBuffer", &[64, buffer, 0, 0, 0]) == status(0xC000_0008) && call("EtwSendTraceBuffer", &[63, buffer, 0, 0, 0]) == status(0xC000_0296), "etw-send-trace-buffer: LoggerId >= MaxLoggers = STATUS_INVALID_HANDLE, sessão ausente = STATUS_WMI_INSTANCE_NOT_FOUND");
    // Sessão comum: o modo de interface de buffers é obrigatório.
    prepare(0x100);
    let started = control(1);
    let plain = guest::read64(properties + 8) & 0xFFFF;
    let refused = call("EtwSendTraceBuffer", &[plain, buffer, 0, 0, 0]);
    prepare(0x100);
    control(2);
    assert(started == 0 && plain != 0 && refused == status(0xC000_0008), "etw-send-trace-buffer: sessão sem EVENT_TRACE_BUFFER_INTERFACE_MODE = STATUS_INVALID_HANDLE");
    prepare(0x4_0000);
    let started = control(1);
    let id = guest::read64(properties + 8) & 0xFFFF;
    // SAFETY: WMI_BUFFER_HEADER de teste.
    let header = unsafe { WmiBufferHeader::at(buffer) };
    header.buffer_size.set(0x1000);
    header.offset.set(0x80);
    header.client_context.processor_number.set(2);
    header.client_context.alignment.set(7);
    let sent = call("EtwSendTraceBuffer", &[id, buffer, 3, 0x1111_2222, 0x3333_4444]);
    let prepared = header.saved_offset.get() == 0x80 && header.current_offset.get() == 0x1080 && header.state.get() == EtwBufferState::ETW_BUFFER_STATE_FLUSH && header.buffer_type.get() == 5 && header.client_context.alignment.get() == 0 && header.client_context.processor_number.get() == 2;
    let reference = (header.reference_time.start_time.quad_part.get(), header.reference_time.start_perf_clock.quad_part.get(), header.time_stamp.quad_part.get() != 0);
    header.buffer_flag.set(0x20);
    header.client_context.alignment.set(7);
    let kept = call("EtwSendTraceBuffer", &[id, buffer, 4, 0, 0]) == 0 && header.client_context.alignment.get() == 7;
    prepare(0x4_0000);
    let queried = control(3);
    let (lost, written) = (guest::read32(properties + 0x68), guest::read32(properties + 0x6C));
    prepare(0x4_0000);
    control(2);
    assert(started == 0 && sent == 0 && prepared && reference == (0x1111_2222, 0x3333_4444, true), "etw-send-trace-buffer: o cabeçalho sai pronto (offsets, ETW_BUFFER_STATE_FLUSH, tipo 5, hora de referência e TimeStamp)");
    assert(kept && queried == 0 && lost == 7 && written >= 2, "etw-send-trace-buffer: BufferFlag 0x20 preserva o Alignment; EventsLost e os buffers entregues contam na sessão");
    // O código 24 (EtwpRegisterSecurityProvider): sem buffers; o primeiro
    // processo fica como provedor de segurança, o segundo registro dá
    // STATUS_ACCESS_DENIED.
    let register = |length: u32| logger::trace_control(24, if length != 0 { properties } else { 0 }, length, 0, 0, returned, 0).unwrap_or(u32::MAX);
    let sized = register(8);
    let before = logger::security_provider_pid();
    let first = register(0);
    let second = register(0);
    let expected_first = if before == 0 { 0 } else { 0xC000_0022 };
    assert(sized == 0xC000_000D && first == expected_first && second == 0xC000_0022 && logger::security_provider_pid() == if before == 0 { crate::ntos::ps::process::get_current_process_id() } else { before }, "etw-security-provider: codigo 24 registra o primeiro processo; o segundo registro da STATUS_ACCESS_DENIED");
    // NtTraceEvent 0x500 (EtwWriteUMSecurityEvent): o provedor registrado
    // escreve (sem sessão de segurança, aceito); outro processo, não.
    let event = crate::ntos::etw::user_registration::trace_event(0, 0x500, 0x78, properties, 0).unwrap_or(u32::MAX);
    let provider = logger::security_provider_pid() == crate::ntos::ps::process::get_current_process_id();
    assert(event == if provider { 0 } else { 0xC000_0022 }, "etw-security-provider: NtTraceEvent 0x500 aceito so do provedor de seguranca");
}

// ---- InbvCheckDisplayOwnership / InbvEnableBootDriver ------------------------

fn inbv_boot_driver(assert: Assert) {
    use crate::drivers::video::vga;
    use crate::hal::port;
    use crate::ntos::inbv::display;
    if display::display_state() != display::DISPLAY_STATE_OWNED {
        assert(false, "inbv-boot-driver: o vídeo de boot começa com o kernel");
        return;
    }
    let owned = call("InbvCheckDisplayOwnership", &[]) & 0xFF;
    call("InbvEnableBootDriver", &[0]);
    let disabled = (display::display_state(), vga::owned(), call("InbvCheckDisplayOwnership", &[]) & 0xFF);
    call("InbvEnableBootDriver", &[1]);
    let enabled = (display::display_state(), vga::owned());
    // Do estado "do kernel", o VidCleanUp devolve a Bit Mask do GC a 0xFF.
    port::write8(0x3CE, 8);
    port::write8(0x3CF, 0x0F);
    call("InbvEnableBootDriver", &[1]);
    port::write8(0x3CE, 8);
    let bit_mask = port::read8(0x3CF);
    assert(
        owned == 1 && disabled == (display::DISPLAY_STATE_DISABLED, false, 1) && enabled == (display::DISPLAY_STATE_OWNED, true) && bit_mask == 0xFF,
        "inbv-boot-driver: InbvEnableBootDriver desliga e religa o desenho do kernel (VidCleanUp no estado do kernel) sem ceder o vídeo",
    );
    call("InbvNotifyDisplayOwnershipChange", &[0, 0]);
    let lost = call("InbvCheckDisplayOwnership", &[]) & 0xFF;
    call("InbvEnableBootDriver", &[1]);
    let still_lost = display::display_state();
    call("InbvNotifyDisplayOwnershipChange", &[1, 0]);
    assert(lost == 0 && still_lost == display::DISPLAY_STATE_LOST && call("InbvCheckDisplayOwnership", &[]) & 0xFF == 1 && vga::owned(), "inbv-boot-driver: com o vídeo perdido o kernel não é dono e InbvEnableBootDriver não muda nada");
}

// ---- Hvl/Hvi -------------------------------------------------------------------

fn hypervisor_queries(assert: Assert) {
    use crate::hal::cpu;
    let block = zeroed(16);
    guest::write64(block, 0xAAAA_AAAA_AAAA_AAAA);
    assert(call("HvlInvokeHypercall", &[0x0001_0012, 0x1000, 0x2000]) == 0x1000, "hvl: sem hipervisor conectado o HvlInvokeHypercall é o HvcallpNoHypervisorPresent (0x1000)");
    let count = call("HvlQueryActiveHypervisorProcessorCount", &[block]);
    let node = call("HvlQueryHypervisorProcessorNodeNumber", &[0, block]);
    assert(count == status(0xC000_0001) && node == status(0xC000_0001) && guest::read64(block) == 0xAAAA_AAAA_AAAA_AAAA, "hvl: sem partição raiz as consultas de processadores do hipervisor = STATUS_UNSUCCESSFUL sem escrever a saída");
    // HviGetPartitionIsolationType pelo CPUID: interface "Hv#1" e privilégio
    // Isolation (bit 54 de EAX:EBX da leaf 0x40000003).
    let present = cpu::cpuid(1)[2] & (1 << 31) != 0 && cpu::cpuid(0x4000_0001)[0] != 0x766E_6258;
    let compatible = present && cpu::cpuid(0x4000_0001)[0] == 0x3123_7648;
    let isolation = compatible && cpu::cpuid(0x4000_0003)[1] & (1 << 22) != 0;
    let expected = if isolation { (cpu::cpuid(0x4000_000C)[1] & 0xF) as u64 } else { 0 };
    assert(call("HviGetPartitionIsolationType", &[]) & 0xFFFF_FFFF == expected, "hvi: HviGetPartitionIsolationType segue o CPUID de isolamento da partição");
}

// ---- NtCreateEvent / NtWaitForSingleObject -----------------------------------

fn nt_event_and_wait(assert: Assert) {
    use crate::ntos::inc::types::Ethread;
    let block = zeroed(0x40);
    let (output, timeout) = (block, block + 8);
    let kernel_mode = matches!(crate::ntos::ps::previous_mode::get(), Ok(0));
    assert(kernel_mode && call("NtCreateEvent", &[output, 0x1F_0003, 0, 2, 0]) == status(0xC000_000D), "nt-create-event: EventType > SynchronizationEvent = STATUS_INVALID_PARAMETER");
    let created = call("NtCreateEvent", &[output, 0x1F_0003, 0, 0, 0]);
    let notification = guest::read64(output);
    let not_signaled = call("NtWaitForSingleObject", &[notification, 0, timeout]);
    call("ZwSetEvent", &[notification, 0]);
    let signaled = (call("NtWaitForSingleObject", &[notification, 0, timeout]), call("NtWaitForSingleObject", &[notification, 0, timeout]));
    assert(created == 0 && notification != 0 && not_signaled == 0x102 && signaled == (0, 0), "nt-create-event: NtCreateEvent em KernelMode cria o NotificationEvent e o NtWaitForSingleObject espera nele (STATUS_TIMEOUT, depois sinalizado)");
    let synchronization = call("NtCreateEvent", &[output, 0x1F_0003, 0, 1, 1]);
    let auto = guest::read64(output);
    let first = call("NtWaitForSingleObject", &[auto, 0, timeout]);
    let second = call("NtWaitForSingleObject", &[auto, 0, timeout]);
    let invalid = call("NtWaitForSingleObject", &[0x7FF0, 0, timeout]);
    assert(synchronization == 0 && first == 0 && second == 0x102 && invalid == status(0xC000_0008), "nt-wait-single: SynchronizationEvent sinalizado satisfaz uma espera só; handle inválido = STATUS_INVALID_HANDLE");
    // Em UserMode o prazo é capturado: um endereço do kernel vira o
    // MmUserProbeAddress e a leitura falha com STATUS_ACCESS_VIOLATION.
    let thread = crate::ntos::ps::process::get_current_thread();
    // SAFETY: o ETHREAD corrente.
    let previous_mode = &unsafe { Ethread::at(thread) }.tcb.previous_mode;
    let saved = previous_mode.get();
    previous_mode.set(1);
    let probed = call("NtWaitForSingleObject", &[auto, 0, timeout]);
    previous_mode.set(saved);
    assert(probed == status(0xC000_0005), "nt-wait-single: em UserMode o prazo de endereço do kernel falha na captura (STATUS_ACCESS_VIOLATION)");
    call("ZwClose", &[notification]);
    call("ZwClose", &[auto]);
}

// ---- ZwQueryInformationTransaction -------------------------------------------

fn zw_query_information_transaction(assert: Assert) {
    let block = zeroed(0x60);
    guest::write_bytes(block, &[0xCC; 0x60]);
    let returned = block + 0x50;
    let result = call("ZwQueryInformationTransaction", &[0x1234, 0, block, 0x40, returned]);
    // SAFETY: célula ULONG de teste.
    let untouched = unsafe { Field::<u32>::at(returned) }.get() == 0xCCCC_CCCC && guest::read_bytes(block, 0x40).iter().all(|&byte| byte == 0xCC);
    assert(result == status(0xC000_00BB) && untouched, "tm-query-transaction: sem tm.sys o slot do KTM devolve STATUS_NOT_SUPPORTED sem escrever o buffer nem o ReturnLength");
}
