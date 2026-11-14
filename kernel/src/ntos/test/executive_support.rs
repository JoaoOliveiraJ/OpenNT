//! Autotestes (fase 6) dos exports Ob/Ps/Ex/Io/Mm/Po/Se/Etw/Dbgk que o
//! subsistema de janelas importa e dos tipos de objeto que o executive cria
//! no boot. Cada teste chama o export pelo nome (`call_export`): sem ele o
//! export não resolve e o teste falha.

use alloc::vec::Vec;

use crate::ntos::dbgk::live_dump;
use crate::ntos::etw::coverage;
use crate::ntos::inc::types::{self as nt, NtStruct};
use crate::ntos::init::exports;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::pe_loader::ResolvedImport;
use crate::ntos::mm::{kernel_data, kernel_stack};
use crate::ntos::ob::object_types;
use crate::ntos::po::system_state;
use crate::ntos::ps::{cid, process};
use crate::ntos::se::audit;
use crate::ntos::test::phase6::call_export;

type Assert = fn(bool, &str);

fn at<T: NtStruct>(address: u64) -> &'static T {
    // SAFETY: blocos alocados pelo teste com o tamanho do tipo ou objetos
    // vivos do kernel.
    unsafe { T::at(address) }
}

/// O NTSTATUS de 32 bits como o export devolve (estendido com sinal).
fn status(value: Option<u64>) -> u32 {
    value.map_or(0xDEAD_BEEF, |value| value as u32)
}

/// UNICODE_STRING e OBJECT_ATTRIBUTES com `name` em `block` (0x200 bytes).
fn object_attributes(block: u64, name: &str, flags: u32) -> u64 {
    let units: Vec<u16> = name.encode_utf16().collect();
    let text = block + 0x80;
    guest::write_bytes(text, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    let unicode = at::<nt::UnicodeString>(block + 0x40);
    unicode.length.set(units.len() as u16 * 2);
    unicode.maximum_length.set(units.len() as u16 * 2);
    unicode.buffer.set(text);
    let attributes = at::<nt::ObjectAttributes>(block);
    attributes.length.set(48);
    attributes.object_name.set(unicode.address());
    attributes.attributes.set(flags);
    block
}

/// Os tipos do boot: a célula exportada resolve pelo loader e aponta o
/// OBJECT_TYPE com o TypeInfo do ntoskrnl.
fn boot_object_types(assert: Assert) {
    let expected: [(&str, &str, u16, u32, u32, u32, [u32; 4], u32); 8] = [
        ("ExWindowStationObjectType", "WindowStation", 0x18, 0, 0x130, 0x200, [0x2_0000, 0x2_0000, 0x2_0000, 0xF_0000], 0xF_0000),
        ("ExDesktopObjectType", "Desktop", 0x58, 0, 0x130, 0x200, [0x2_0000, 0x2_0000, 0x2_0000, 0xF_0000], 0xF_0000),
        ("ExCompositionObjectType", "Composition", 0x1A, 0x400, 0x130, 0x200, [0x2_0000, 0x2_0000, 0x2_0000, 0xF_0000], 0xF_0000),
        ("ExRawInputManagerObjectType", "RawInputManager", 0x1A, 0, 0x130, 0x200, [0x2_0000, 0x2_0000, 0x2_0000, 0xF_0000], 0xF_0000),
        ("ExCoreMessagingObjectType", "CoreMessaging", 0x1A, 0, 0x130, 0x200, [0x2_0000, 0x2_0000, 0x2_0000, 0xF_0000], 0xF_0000),
        ("ExActivationObjectType", "ActivationObject", 0x1E, 0, 0x130, 0x221, [0x2_0000, 0x2_0000, 0x2_0000, 0xF_0000], 0xF_0000),
        ("ExTimerObjectType", "Timer", 0, 0, 0x100, 0x200, [0x2_0001, 0x2_0002, 0x12_0000, 0x1F_0003], 0x1F_0003),
        ("PsJobType", "Job", 0x08, 0x800, 0, 0x200, [0x2_0004, 0x2_000B, 0x12_0000, 0x1F_003F], 0x1F_003F),
    ];
    for (cell, name, flags, code, invalid, pool, mapping, valid) in expected {
        let address = kernel_data::address(cell).unwrap_or(0);
        let resolved = matches!(exports::lookup("ntoskrnl.exe", cell), Some(ResolvedImport::Address { address: resolved, .. }) if resolved == address);
        let pointer = if address != 0 { guest::read64(address) } else { 0 };
        let registered = object_types::find(pointer).is_some_and(|object_type| object_type.name == name);
        let ok = resolved && pointer != 0 && registered && {
            let info = &at::<nt::ObjectType>(pointer).type_info;
            let generic = &info.generic_mapping;
            info.object_type_flags.get() == flags
                && info.object_type_code.get() == code
                && info.invalid_attributes.get() == invalid
                && info.pool_type.get().0 as u32 == pool
                && info.valid_access_mask.get() == valid
                && [generic.generic_read.get(), generic.generic_write.get(), generic.generic_execute.get(), generic.generic_all.get()] == mapping
        };
        assert(ok, alloc::format!("tipos do boot: {cell} publica o tipo {name} com o inicializador do ntoskrnl").leak());
    }
    let charges = |cell: &str| at::<nt::ObjectType>(guest::read64(kernel_data::address(cell).unwrap_or(0))).type_info.default_non_paged_pool_charge.get();
    assert(charges("ExTimerObjectType") == 0x148 && charges("PsJobType") == 0x640, "tipos do boot: cobranca nao paginavel do Timer e do Job");
}

/// ObCreateObject/ObInsertObject com nome, ObQueryNameInfo, ObAssignSecurity,
/// ObSetSecurityDescriptorInfo e ObCheckCreateObjectAccess.
fn ob_object_support(assert: Assert) {
    let block = guest::alloc_bytes(0x1000);
    let desktop = guest::read64(kernel_data::address("ExDesktopObjectType").unwrap_or(0));
    let attributes = object_attributes(block, "\\SuporteDesktopTeste", 0x200);
    let (out_object, out_handle, slot) = (block + 0x300, block + 0x308, block + 0x310);
    let created = status(call_export("ObCreateObject", &[0, desktop, attributes, 0, 0, 0x40, 0, 0, out_object]));
    let object = guest::read64(out_object);
    let inserted = status(call_export("ObInsertObject", &[object, 0, 0xF_0000, 0, 0, out_handle]));
    assert(created == 0 && inserted == 0 && object != 0, "ob: objeto Desktop com nome criado e inserido");
    let info = call_export("ObQueryNameInfo", &[object]).unwrap_or(0);
    let named = info != 0 && {
        let header = at::<nt::ObjectHeaderNameInfo>(info);
        crate::ntos::rtl::guest_strings::read_unicode_string(header.name.address()) == "SuporteDesktopTeste" && header.reference_count.get() == 0
    };
    let unnamed_out = block + 0x318;
    let unnamed = status(call_export("ObCreateObject", &[0, desktop, 0, 0, 0, 0x40, 0, 0, unnamed_out]));
    let unnamed_object = guest::read64(unnamed_out);
    assert(named && unnamed == 0 && call_export("ObQueryNameInfo", &[unnamed_object]) == Some(0), "ob: ObQueryNameInfo devolve o OBJECT_HEADER_NAME_INFO do objeto com nome (so o componente final) e NULL sem nome");
    let _ = call_export("ObDeleteCapturedInsertInfo", &[unnamed_object]);

    // ObAssignSecurity: o descritor atribuído vira o do objeto.
    let access_state = guest::alloc_bytes(nt::AccessState::SIZE);
    let state = at::<nt::AccessState>(access_state);
    let _ = call_export("SeCaptureSubjectContext", &[state.subject_security_context.address()]);
    let assigned = status(call_export("ObAssignSecurity", &[access_state, 0, object, desktop]));
    let got = call_export("ObGetObjectSecurity", &[object, slot, block + 0x320]);
    let descriptor = guest::read64(slot);
    assert(assigned == 0 && got == Some(0) && descriptor != 0 && crate::ntos::se::descriptor::control(descriptor) & 0x8000 != 0, "ob: ObAssignSecurity atribui um descritor auto-relativo ao objeto");
    // ObSetSecurityDescriptorInfo: troca a DACL pelo descritor dado.
    let modification = block + 0x400;
    let created_sd = status(call_export("RtlCreateSecurityDescriptor", &[modification, 1]));
    let null_dacl = status(call_export("RtlSetDaclSecurityDescriptor", &[modification, 1, 0, 0]));
    let information = block + 0x480;
    guest::write32(information, 4);
    let objects_descriptor = block + 0x488;
    guest::write64(objects_descriptor, descriptor);
    let mapping = block + 0x490;
    for (index, value) in [0x2_0000u32, 0x2_0000, 0x2_0000, 0xF_0000].into_iter().enumerate() {
        guest::write32(mapping + index as u64 * 4, value);
    }
    let changed = status(call_export("ObSetSecurityDescriptorInfo", &[object, information, modification, objects_descriptor, 1, mapping]));
    let replaced = guest::read64(objects_descriptor);
    let _ = call_export("ObGetObjectSecurity", &[object, slot, block + 0x320]);
    assert(created_sd == 0 && null_dacl == 0 && changed == 0 && replaced != 0 && replaced != descriptor && guest::read64(slot) == replaced, "ob: ObSetSecurityDescriptorInfo mescla a DACL e troca o descritor do objeto");
    // ObCheckCreateObjectAccess no diretório raiz, em KernelMode.
    let access_status = block + 0x4A0;
    guest::write32(access_status, 0xFFFF_FFFF);
    let root = crate::ntos::ob::object_manager::node(crate::ntos::ob::object_manager::ROOT).and_then(|node| node.data).map_or(0, |data| data.native_body);
    assert(call_export("ObCheckCreateObjectAccess", &[root, 1, access_state, 0, 0, 0, access_status]) == Some(1) && guest::read32(access_status) == 0, "ob: ObCheckCreateObjectAccess concede a criacao em KernelMode");
    let _ = call_export("ZwClose", &[guest::read64(out_handle)]);
    guest::free_bytes(access_state);
    guest::free_bytes(block);
}

/// Wake counters, referências da pilha de kernel, falhas e prioridade por
/// classe do processo.
fn ps_support(assert: Assert) {
    let eprocess = guest::alloc_bytes(nt::Eprocess::SIZE);
    let object = at::<nt::Eprocess>(eprocess);
    let counters = |index: usize| object.wake_info.wake_counters[index].get();
    // Sem pai, o PsChargeProcessWakeCounter não cobra.
    let _ = call_export("PsChargeProcessWakeCounter", &[eprocess, 0, 2, 0]);
    let orphan = counters(2) == 0;
    object.inherited_from_unique_process_id.set(4);
    let _ = call_export("PsChargeProcessWakeCounter", &[eprocess, 0, 2, 0]);
    let _ = call_export("PsChargeProcessWakeCounter", &[eprocess, 0, 2, 0]);
    let charged = counters(2) == 2;
    let _ = call_export("PsReleaseProcessWakeCounter", &[eprocess | 2, 0]);
    let released = counters(2) == 1;
    let _ = call_export("PsChargeProcessWakeCounter", &[eprocess, 2, 0, 0]);
    let no_wake = object.wake_info.no_wake_counter.get() == 1 && counters(0) == 0;
    let _ = call_export("PsReleaseProcessWakeCounter", &[eprocess | 7, 0]);
    assert(orphan && charged && released && no_wake && object.wake_info.no_wake_counter.get() == 0, "ps: wake counters por indice e o NoWakeCounter (flag 2, indice etiquetado 7), so com pai");

    // PsSetProcessFaultInformation.
    let flags = guest::alloc_bytes(8);
    let fault = |value: u32| {
        guest::write32(flags, value);
        status(call_export("PsSetProcessFaultInformation", &[eprocess, flags]))
    };
    let results: Vec<u32> = [1u32, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4, 8].iter().map(|&value| fault(value)).collect();
    assert(results.iter().all(|&result| result == 0) && object.flags3.get() & nt::Eprocess::CRASHED_MASK != 0 && object.hang_count() == 7 && object.ghost_count() == 1 && object.prefilter_exception() == 1, "ps: PsSetProcessFaultInformation liga Crashed, conta HangCount (satura em 7) e GhostCount e marca PrefilterException");

    // PsSetProcessPriorityByClass.
    object.priority_class.set(3);
    let _ = call_export("PsSetProcessPriorityByClass", &[eprocess, 1]);
    let foreground = object.pcb.base_priority.get() == 13 && object.vm.instance.flags.memory_priority.get() == 2;
    let _ = call_export("PsSetProcessPriorityByClass", &[eprocess, 0]);
    let background = object.vm.instance.flags.memory_priority.get() == 0;
    object.priority_class.set(1);
    object.vm.instance.flags.memory_priority.set(5);
    let _ = call_export("PsSetProcessPriorityByClass", &[eprocess, 2]);
    assert(foreground && background && object.pcb.base_priority.get() == 4 && object.vm.instance.flags.memory_priority.get() == 5, "ps: PsSetProcessPriorityByClass pela PspPriorityTable e a prioridade de memoria do primeiro plano");
    guest::free_bytes(flags);
    guest::free_bytes(eprocess);

    // PsReferenceKernelStack/PsDereferenceKernelStack: a pilha sobrevive ao
    // ceifador enquanto referenciada.
    let Ok(stack) = kernel_stack::create(false) else {
        assert(false, "ps: pilha de kernel para o teste");
        return;
    };
    let Ok(thread) = process::create_kernel_thread(process::get_system_process(), cid::ALLOCATE, true, 0, Some(stack)) else {
        assert(false, "ps: thread com pilha propria");
        return;
    };
    let ethread = at::<nt::Ethread>(thread);
    let initial = ethread.kernel_stack_reference.get();
    let _ = call_export("PsReferenceKernelStack", &[thread]);
    let referenced = ethread.kernel_stack_reference.get();
    process::release_kernel_stack(thread);
    let kept = kernel_stack::find(stack.base).is_some() && ethread.tcb.initial_stack.get() == stack.initial;
    let _ = call_export("PsDereferenceKernelStack", &[thread]);
    let freed = kernel_stack::find(stack.base).is_none() && ethread.tcb.initial_stack.get() == 0 && ethread.kernel_stack_reference.get() == 0;
    let _ = process::release_thread(thread);
    assert(initial == 1 && referenced == 2 && kept && freed, "ps: PsReferenceKernelStack retem a pilha depois do ceifador e o ultimo PsDereferenceKernelStack a devolve");
}

extern "win64" fn live_dump_callback(_: u64, _: u64) -> u64 {
    0
}

/// ExRaiseHardError, IoQueueThreadIrp, MmPrefetchVirtualAddresses,
/// NtDeviceIoControlFile, Po*, SePrivilegeObjectAuditAlarm,
/// EtwTelemetryCoverageReport e DbgkLkmdRegisterCallback.
fn executive_support(assert: Assert) {
    let block = guest::alloc_bytes(0x1000);
    // ExRaiseHardError.
    let parameters = block;
    let message = block + 0x40;
    let text: Vec<u16> = "erro".encode_utf16().collect();
    guest::write_bytes(block + 0x80, &text.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    at::<nt::UnicodeString>(message).length.set(8);
    at::<nt::UnicodeString>(message).maximum_length.set(8);
    at::<nt::UnicodeString>(message).buffer.set(block + 0x80);
    guest::write64(parameters, message);
    let response = block + 0x100;
    guest::write32(response, 0xFF);
    let too_many = status(call_export("ExRaiseHardError", &[0xC000_0135, 6, 0, parameters, 1, response]));
    let raised = status(call_export("ExRaiseHardError", &[0xC000_0135, 1, 1, parameters, 1, response]));
    assert(too_many == 0xC000_00F0 && raised == 0 && guest::read32(response) == 0, "ex: ExRaiseHardError recusa mais de cinco parametros e, sem porta de erros, responde ResponseReturnToCaller");

    // IoQueueThreadIrp.
    let irp = call_export("IoAllocateIrp", &[1, 0]).unwrap_or(0);
    let thread = process::get_current_thread();
    let queued = irp != 0 && {
        at::<nt::Irp>(irp).tail.overlay.thread.set(thread);
        let queued = call_export("IoQueueThreadIrp", &[irp]) == Some(0);
        let head = &at::<nt::Ethread>(thread).irp_list;
        let linked = head.flink.get() == at::<nt::Irp>(irp).thread_list_entry.address();
        let _ = crate::ntos::io::threads::thread_requests::remove(irp, thread);
        queued && linked
    };
    if irp != 0 {
        let _ = call_export("IoFreeIrp", &[irp]);
    }
    assert(queued, "io: IoQueueThreadIrp poe a IRP no inicio da IrpList da thread dela");

    // MmPrefetchVirtualAddresses: validação do pedido.
    let request = block + 0x200;
    let ranges = block + 0x240;
    let fill = |version: u32, flags: u32| {
        guest::write32(request, version);
        guest::write32(request + 4, flags);
        guest::write64(request + 8, process::get_system_process());
        guest::write64(request + 0x10, 1);
        guest::write64(request + 0x18, ranges);
        status(call_export("MmPrefetchVirtualAddresses", &[request]))
    };
    guest::write64(ranges, 0);
    guest::write64(ranges + 8, 0);
    assert(fill(2, 0) == 0xC000_00EF && fill(1, 8) == 0xC000_00EF && fill(1, 6) == 0xC000_00EF && fill(1, 0) == 0, "mm: MmPrefetchVirtualAddresses confere Version e Flags e aceita o pedido valido");

    // NtDeviceIoControlFile em KernelMode: o mesmo caminho do Zw.
    let iosb = block + 0x300;
    assert(status(call_export("NtDeviceIoControlFile", &[0x7FF0, 0, 0, 0, iosb, 0x22_2000, 0, 0, block + 0x400, 16])) == 0xC000_0008, "io: NtDeviceIoControlFile em KernelMode recusa o handle invalido como o Zw");

    // Po.
    let _ = call_export("PoSetUserPresent", &[1]);
    let present = system_state::user_presence() == 1;
    let _ = call_export("PoSetUserPresent", &[0]);
    let _ = call_export("PoLatencySensitivityHint", &[3]);
    let event_out = block + 0x500;
    guest::write64(event_out, 0x1234);
    let requested = status(call_export("PoRequestShutdownEvent", &[event_out]));
    let event = guest::read64(event_out);
    assert(present && system_state::user_presence() == 0 && system_state::latency_hint().0 == 3, "po: PoSetUserPresent e PoLatencySensitivityHint registram o estado");
    assert(requested == 0 && event != 0 && at::<nt::Kevent>(event).header.type_.get() == 0 && system_state::shutdown_waiters().contains(&thread), "po: PoRequestShutdownEvent poe a thread na lista de shutdown e devolve o evento de notificacao");

    // SePrivilegeObjectAuditAlarm: só o modo usuário gera o evento.
    let before = audit::events().len();
    let _ = call_export("SePrivilegeObjectAuditAlarm", &[0x44, 0, 0x2_0000, 0, 1, 0]);
    let kernel = audit::events().len();
    let _ = call_export("SePrivilegeObjectAuditAlarm", &[0x44, 0, 0x2_0000, 0, 1, 1]);
    let events = audit::events();
    assert((kernel == before || kernel == 256) && events.last().is_some_and(|event| event.kind == "privileged object operation" && event.detail.contains("handle=0x44")), "se: SePrivilegeObjectAuditAlarm audita o pedido do modo usuario e ignora o de KernelMode");

    // EtwTelemetryCoverageReport.
    let point = block + 0x600;
    let name: Vec<u16> = "PontoDeCobertura\0".encode_utf16().collect();
    guest::write_bytes(block + 0x640, &name.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    let cover = |hash: u32, flags: u32| {
        guest::write64(point, block + 0x640);
        guest::write32(point + 8, hash);
        guest::write32(point + 0xC, 0);
        guest::write32(point + 0x10, flags);
        status(call_export("EtwTelemetryCoverageReport", &[point]))
    };
    let disabled = cover(0x5EED_0002, 1) == 0 && coverage::covered(0x5EED_0002).is_none();
    let covered = cover(0x5EED_0001, 0) == 0 && coverage::covered(0x5EED_0001).as_deref() == Some("PontoDeCobertura") && guest::read32(point + 0xC) == 1;
    assert(disabled && covered, "etw: EtwTelemetryCoverageReport registra o ponto habilitado uma vez por rodada e ignora o desabilitado");

    // DbgkLkmdRegisterCallback.
    let routine = live_dump_callback as *const () as usize as u64;
    let registered = status(call_export("DbgkLkmdRegisterCallback", &[routine, 0x77, 1]));
    let again = status(call_export("DbgkLkmdRegisterCallback", &[routine, 0x77, 1]));
    let invalid = status(call_export("DbgkLkmdRegisterCallback", &[routine + 1, 0, 3]));
    let recorded = live_dump::registration(routine) == Some(live_dump::Registration { callback: routine, context: 0x77, flags: 1 });
    live_dump::unregister(routine);
    assert(registered == 0 && again == 0xC000_0718 && invalid == 0xC000_000D && recorded, "dbgk: DbgkLkmdRegisterCallback guarda rotina, contexto e flags, recusa a repetida e as flags 3");
    guest::free_bytes(block);
}

/// Os Zw em modo kernel: localidade e idioma, consulta de job, cancelamento
/// de E/S e informação de memória virtual.
fn zw_support(assert: Assert) {
    let block = guest::alloc_bytes(0x200);
    let query_locale = |user: u64| {
        guest::write32(block, 0);
        (status(call_export("ZwQueryDefaultLocale", &[user, block])), guest::read32(block))
    };
    let initial = query_locale(1);
    let set = status(call_export("ZwSetDefaultLocale", &[1, 0x416]));
    let changed = query_locale(1);
    let system = query_locale(0);
    let refused = status(call_export("ZwSetDefaultLocale", &[0, 0]));
    let _ = call_export("ZwSetDefaultLocale", &[1, initial.1 as u64]);
    assert(initial == (0, 0x409) && set == 0 && changed == (0, 0x416) && system == (0, 0x409) && refused == 0xC000_000D, "zw: ZwQueryDefaultLocale/ZwSetDefaultLocale com o LCID do usuario e o do sistema separados, LCID 0 recusado");
    guest::write16(block, 0);
    let ui = status(call_export("ZwQueryDefaultUILanguage", &[block])) == 0 && guest::read16(block) == 0x409;
    let ui_set = status(call_export("ZwSetDefaultUILanguage", &[0x416])) == 0 && status(call_export("ZwQueryDefaultUILanguage", &[block])) == 0 && guest::read16(block) == 0x416;
    let ui_refused = status(call_export("ZwSetDefaultUILanguage", &[0])) == 0xC000_000D;
    let _ = call_export("ZwSetDefaultUILanguage", &[0x409]);
    assert(ui && ui_set && ui_refused, "zw: ZwQueryDefaultUILanguage/ZwSetDefaultUILanguage trocam o idioma de interface");
    let job = |handle: u64, class: u64| status(call_export("ZwQueryInformationJobObject", &[handle, class, block, 0x40, 0]));
    assert(job(0, 2) == 0xC000_0022 && job(0, 0x1F) == 0xC000_00BB && job(0x7FF0, 2) == 0xC000_0008, "zw: ZwQueryInformationJobObject sem job (ACCESS_DENIED fora das classes de silo) e handle invalido");
    guest::write64(block + 0x100, 0x5555);
    assert(status(call_export("ZwCancelIoFile", &[0x7FF0, block + 0x100])) == 0xC000_0008 && guest::read64(block + 0x100) == 0x5555, "zw: ZwCancelIoFile recusa o handle que nao e de arquivo sem tocar no IOSB");
    let flags = block + 0x140;
    let vm = |process: u64, class: u64, value: u32| {
        guest::write32(flags, value);
        status(call_export("ZwSetInformationVirtualMemory", &[process, class, 0, 0, flags, 4]))
    };
    assert(vm(u64::MAX, 0, 0) == 0 && vm(u64::MAX, 0, 1) == 0xC000_00F3 && vm(u64::MAX, 9, 0) == 0xC000_00F0 && vm(0x7FF0, 0, 0) == 0xC000_0008, "zw: ZwSetInformationVirtualMemory pre-busca no processo corrente e confere flags, classe e handle");
    guest::free_bytes(block);
}

pub fn run(assert: Assert) {
    boot_object_types(assert);
    ob_object_support(assert);
    ps_support(assert);
    executive_support(assert);
    zw_support(assert);
}

/// ObSetHandleAttributes e ObWaitFor*Object sobre handles de usuário de um
/// processo de teste (fase 7): eventos criados pelo NtCreateEvent dele.
pub fn run_user(assert: Assert) {
    use crate::ntos::ps::user::{memory, state};
    use crate::ntos::test::multiprocess::identity::with_test_process;
    let outcome = with_test_process("suporte-ob.exe", None, |_| {
        let Ok(page) = memory::map_user_region(0x1000) else { return None };
        let create = |out: u64, signaled: u64| {
            guest::write64(page + 0x828, signaled);
            state::handler("NtCreateEvent").map_or(1, |handler| handler(out, 0x1F_0003, 0, 0, page + 0x800).unwrap_or(1))
        };
        let created = create(page, 1) == 0 && create(page + 8, 0) == 0;
        let (signaled, waiting) = (guest::read64(page), guest::read64(page + 8));
        let flags = guest::alloc_bytes(16);
        let set = |handle: u64, inherit: u8, protect: u8, mode: u64| {
            guest::write8(flags, inherit);
            guest::write8(flags + 1, protect);
            status(call_export("ObSetHandleAttributes", &[handle, flags, mode]))
        };
        let attributes = set(signaled, 1, 1, 1) == 0 && state::get_user_handle(signaled).is_some_and(|entry| entry.attributes() & 3 == 3) && set(signaled, 0, 0, 1) == 0 && state::get_user_handle(signaled).is_some_and(|entry| entry.attributes() & 3 == 0);
        let refused = set(0x7FF0, 1, 0, 1) == 0xC000_0008 && set(0xFFFF_FFFF_8000_0F00, 1, 0, 1) == 0xC000_0008;
        let zero = guest::alloc_bytes(8);
        guest::write64(zero, 0);
        let single = status(call_export("ObWaitForSingleObject", &[signaled, 1, 0, 0, zero])) == 0 && status(call_export("ObWaitForSingleObject", &[waiting, 1, 0, 0, zero])) == 0x102 && status(call_export("ObWaitForSingleObject", &[0x7FF0, 1, 0, 0, zero])) == 0xC000_0008;
        let handles = guest::alloc_bytes(16);
        guest::write64(handles, waiting);
        guest::write64(handles + 8, signaled);
        let any = status(call_export("ObWaitForMultipleObjects", &[2, handles, 1, 1, 0, 0, zero]));
        let all = status(call_export("ObWaitForMultipleObjects", &[2, handles, 1, 0, 0, 0, zero]));
        let invalid = status(call_export("ObWaitForMultipleObjects", &[0, handles, 1, 1, 0, 0, zero]));
        // Pacotes de espera e a IOCP pelos Zw, com saídas na memória do kernel.
        let kernel = guest::alloc_bytes(0x40);
        // A IOCP de usuário (tabela do processo) e uma criada em modo kernel
        // (tabela nativa).
        let port_created = crate::ntos::io::completion::create::create(page + 0x100, 0x1F_0003, 0, 0, 1).unwrap_or(1) == 0 && crate::ntos::io::completion::create::create(kernel + 0x18, 0x1F_0003, 0, 0, 0).unwrap_or(1) == 0;
        let (port, native_port) = (guest::read64(page + 0x100), guest::read64(kernel + 0x18));
        let packet_created = status(call_export("ZwCreateWaitCompletionPacket", &[kernel + 8, 1, 0])) == 0;
        let packet = guest::read64(kernel + 8);
        guest::write8(kernel + 0x10, 0xFF);
        let associated = status(call_export("ZwAssociateWaitCompletionPacket", &[packet, port, signaled, 0x11, 0x22, 0x33, 0x44, kernel + 0x10])) == 0 && guest::read8(kernel + 0x10) == 1;
        let posted = status(call_export("ZwSetIoCompletionEx", &[port, 0, 0x55, 0x66, 0x77, 0x88])) == 0 && status(call_export("ZwSetIoCompletionEx", &[port, 0x1234, 0x55, 0x66, 0x77, 0x88])) == 0xC000_0008;
        let depth = |port: u64| crate::ntos::ps::user::io_completion::resolve(port, 0).map_or(usize::MAX, |(_, port)| port.with(|state| state.packets.len()));
        let native_posted = status(call_export("ZwSetIoCompletionEx", &[native_port, 0, 0x99, 0, 0, 0])) == 0 && crate::ntos::ob::open_pointer::resolve(native_port, false).and_then(|opened| opened.ok()).and_then(|opened| crate::ntos::ob::objects::completion::port_of(opened.item.pointer)).is_some_and(|port| port.with(|state| state.packets.len()) == 1);
        let queued = depth(port) == 2 && native_posted;
        let _ = call_export("ZwClose", &[native_port]);
        let cancelled = status(call_export("ZwCancelWaitCompletionPacket", &[packet, 1])) == 0 && depth(port) == 1;
        let packets = port_created && packet_created && associated && posted && queued && cancelled;
        crate::debug_print!("[suporte-zw] iocp={} pacote={} associado={} postado={} fila={} cancelado={}", port_created, packet_created, associated, posted, queued, cancelled);
        for handle in [signaled, waiting, port, packet] {
            let _ = state::close_user_handle(handle, true, false);
        }
        guest::free_bytes(kernel);
        for block in [flags, zero, handles] {
            guest::free_bytes(block);
        }
        if let Some(region) = memory::find_region(page) {
            memory::release_private_region(&region);
        }
        Some((created, attributes, refused, single, any, all, invalid, packets))
    })
    .flatten();
    let Some((created, attributes, refused, single, any, all, invalid, packets)) = outcome else {
        assert(false, "ob: processo de teste com eventos de usuario");
        return;
    };
    assert(created && attributes && refused, "ob: ObSetHandleAttributes troca Inherit e ProtectFromClose do handle e recusa handle ausente e de kernel em UserMode");
    assert(single && any == 1 && all == 0x102 && invalid == 0xC000_000D, "ob: ObWaitForSingleObject e ObWaitForMultipleObjects (WaitAny no indice sinalizado, WaitAll com prazo zero) sobre handles de usuario");
    assert(packets, "zw: ZwCreateWaitCompletionPacket, ZwAssociateWaitCompletionPacket (ja sinalizado), ZwSetIoCompletionEx (reserva recusada) e ZwCancelWaitCompletionPacket tirando o pacote da fila");
}
