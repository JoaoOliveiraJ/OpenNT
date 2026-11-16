//! Autoteste do serviço de depuração (`int 0x2D`) do modo usuário: o filtro
//! do DbgPrint, o KdTrap e o despacho de primeira chance, com os valores do
//! ntoskrnl 19041 (KiDebugServiceTrap 0x410540, KiDispatchException
//! 0x33c330, KdpStub 0x33c8c4, KdpTrap 0x9baa20, KdpPrint 0x9b96c8 e
//! NtQueryDebugFilterState 0x364540).
//!
//! Com o host do depurador anexado, o DbgPrint da ntdll vai pelo
//! `int 0x2D`. Antes, o portão 0x2D da IDT tinha DPL 0 e o serviço chegava
//! ao processo como STATUS_ACCESS_VIOLATION: o csrss.exe morria no DebugPrint
//! da thread do RawInputThread e o wininit.exe no do services.exe. A entrada
//! pelo anel 3 está no teste `userring3` da fase 7; aqui fica o resto do
//! caminho, que agora trata o serviço sem entregar exceção ao processo.

use alloc::string::String;
use alloc::vec::Vec;

use crate::hal::amd64::usermode;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types as nt;
use crate::ntos::kd::{debug_filter, debug_service, debugger, print_log};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user::{exceptions, memory, state, threads};

type Assert = fn(bool, &str);

const STATUS_BREAKPOINT: u32 = 0x8000_0003;
/// STATUS_ACCESS_VIOLATION e STATUS_DEVICE_NOT_CONNECTED no RAX (o LONG do
/// KdpPrint estendido com sinal).
const RAX_ACCESS_VIOLATION: u64 = 0xFFFF_FFFF_C000_0005;
const RAX_DEVICE_NOT_CONNECTED: u64 = 0xFFFF_FFFF_C000_009D;
const MESSAGE: &[u8] = b"dbgsvc: texto do anel 3\n";
const FILTERED: &[u8] = b"dbgsvc: texto filtrado\n";

pub fn run(assert: Assert) {
    filter(assert);
    let Ok(block) = memory::map_user_region(0x4000) else {
        assert(false, "dbgsvc: memoria de usuario");
        return;
    };
    guest::write_bytes(block + 0x100, MESSAGE);
    guest::write_bytes(block + 0x200, FILTERED);
    trap(assert, block);
    dispatch(assert, block);
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

/// O filtro do KdpPrint e do NtQueryDebugFilterState, com as máscaras da
/// imagem (Kd_WIN2000_Mask = 1, componentes zerados) e bits ligados e
/// desligados pelo DbgSetDebugFilterState.
fn filter(assert: Assert) {
    let query = |component: u64, level: u64| state::handler("NtQueryDebugFilterState").and_then(|handler| handler(component, level, 0, 0, 0).ok());
    let error_level = debug_filter::print_enabled(0, 0) && query(0, 0) == Some(1);
    let info_level = !debug_filter::print_enabled(0, 3) && query(0, 3) == Some(0);
    assert(error_level && info_level, "dbgsvc: Kd_WIN2000_Mask deixa passar so o nivel 0; NtQueryDebugFilterState devolve TRUE ou FALSE");
    // Componente 79, bit 5: o nível 5 e a máscara 0x80000020 (Level > 31).
    let free = debug_filter::component_mask(79) & 0x20 == 0 && debug_filter::component_mask(0xFFFF_FFFF) & 0x28 == 0;
    let before = !debug_filter::print_enabled(79, 5);
    debug_filter::set_filter_state(79, 5, true);
    let set = debug_filter::print_enabled(79, 5) && debug_filter::print_enabled(79, 0x8000_0020) && query(79, 5) == Some(1);
    debug_filter::set_filter_state(79, 5, false);
    let cleared = !debug_filter::print_enabled(79, 5);
    assert(free && before && set && cleared, "dbgsvc: a mascara do componente decide o nivel e o Level acima de 31 e a mascara");
    // ComponentId fora da tabela (o -1 do DbgPrint, 0x9C): DPFLTR_DEFAULT_ID
    // com o nível 3, qualquer que seja o Level pedido.
    let default_free = debug_filter::component_mask(101) & 0x8 == 0;
    let default_before = !debug_filter::print_enabled(0xFFFF_FFFF, 0);
    debug_filter::set_filter_state(101, 3, true);
    let default_set = debug_filter::print_enabled(0xFFFF_FFFF, 0) && debug_filter::print_enabled(0x9C, 31) && query(0xFFFF_FFFF, 0) == Some(1);
    debug_filter::set_filter_state(101, 3, false);
    assert(default_free && default_before && default_set && !debug_filter::print_enabled(0x9C, 0), "dbgsvc: componente fora da tabela usa o DEFAULT com o nivel 3");
}

/// Os últimos bytes do anel do DbgPrint.
fn recent_log() -> Vec<u8> {
    let mut bytes = Vec::new();
    print_log::recent(0x400, |byte| bytes.push(byte));
    bytes
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

/// O KdTrap do serviço, pelas duas rotinas, sobre um CONTEXT com o RIP no
/// `int3` (o recuo do KiDispatchException).
fn trap(assert: Assert, block: u64) {
    let raw = guest::alloc_aligned(nt::Context::SIZE, 16, true);
    // SAFETY: bloco do kernel recém-alocado do tamanho do CONTEXT.
    let context = unsafe { nt::Context::at(raw) };
    let breakpoint = block + 0x1000;
    let set = |service: u64, level: u64, text: u64, length: u64| {
        guest::write_bytes(raw, &[0u8; nt::Context::SIZE as usize]);
        context.rip.set(breakpoint);
        context.rax.set(service);
        context.rcx.set(text);
        context.rdx.set(length);
        context.r8.set(0);
        context.r9.set(level);
    };
    let message = (block + 0x100, MESSAGE.len() as u64);
    // KdpStub: 1, 3, 4 e 5 pulam o `int3` sem imprimir; 2 e 6 seguem.
    set(1, 0, message.0, message.1);
    let stub_print = debug_service::service_trap(context, false) && context.rip.get() == breakpoint + 1 && context.rax.get() == 1;
    set(4, 0, 0, 0);
    let stub_symbols = debug_service::service_trap(context, false) && context.rip.get() == breakpoint + 1;
    set(2, 0, message.0, message.1);
    let stub_prompt = !debug_service::service_trap(context, false) && context.rip.get() == breakpoint;
    set(6, 0, 0, 0);
    let stub_other = !debug_service::service_trap(context, false) && context.rip.get() == breakpoint;
    assert(stub_print && stub_symbols && stub_prompt && stub_other, "dbgsvc: KdpStub pula o int3 dos servicos 1, 3, 4 e 5; o prompt e os outros seguem ao processo");
    // KdpTrap: o KdpPrint imprime o texto do nível 0 e devolve o status no
    // RAX; sem host, STATUS_DEVICE_NOT_CONNECTED.
    let expected = if debugger::debugger_not_present() { RAX_DEVICE_NOT_CONNECTED } else { 0 };
    set(1, 0, message.0, message.1);
    let printed = debug_service::service_trap(context, true) && context.rip.get() == breakpoint + 1 && context.rax.get() == expected;
    let logged = contains(&recent_log(), &MESSAGE[..MESSAGE.len() - 1]);
    assert(printed && logged, "dbgsvc: KdpTrap imprime o texto do anel 3, pula o int3 e devolve o status no RAX");
    set(1, 3, block + 0x200, FILTERED.len() as u64);
    let filtered = debug_service::service_trap(context, true) && context.rip.get() == breakpoint + 1 && context.rax.get() == 0 && !contains(&recent_log(), &FILTERED[..FILTERED.len() - 1]);
    set(1, 0, 0x7FFF_FFFF_0000 - 8, 16);
    let outside = !debug_service::service_trap(context, true) && context.rip.get() == breakpoint + 1 && context.rax.get() == RAX_ACCESS_VIOLATION;
    assert(filtered && outside, "dbgsvc: texto filtrado tratado sem sair; faixa acima do MmUserProbeAddress devolve STATUS_ACCESS_VIOLATION sem tratar");
    set(3, 0, 0, 0);
    let symbols = debug_service::service_trap(context, true) && context.rip.get() == breakpoint + 1 && context.rax.get() == 3;
    set(2, 0, message.0, message.1);
    let prompt = !debug_service::service_trap(context, true) && context.rip.get() == breakpoint;
    set(6, 0, 0, 0);
    let other = !debug_service::service_trap(context, true) && context.rip.get() == breakpoint + 1;
    assert(symbols && prompt && other, "dbgsvc: KdpTrap trata os simbolos; o prompt segue; servico acima de 5 pula o int3 sem tratar");
    guest::free_bytes(raw);
}

/// O despacho de primeira chance de uma thread de usuário (o vetor 0x2D
/// salvo pela HAL): o serviço tratado não chega ao processo; o prompt chega
/// ao KiUserExceptionDispatcher com o registro do KiDebugServiceTrap.
fn dispatch(assert: Assert, block: u64) {
    let dispatcher = block + 0x800;
    let saved_exports = state::with(|state| state.ntdll_exports.clone());
    state::with(|state| state.ntdll_exports = Some([(String::from("KiUserExceptionDispatcher"), dispatcher)].into_iter().collect()));
    let thread = threads::UserThread::new(0x7F70, 0, 0, 0);
    let live = guest::alloc_aligned(nt::Context::SIZE, 16, true);
    thread.with(|state| state.context = live);
    // SAFETY: bloco do kernel recém-alocado do tamanho do CONTEXT.
    let context = unsafe { nt::Context::at(live) };
    let saved_vector = usermode::block().fault_vector.get();
    usermode::block().fault_vector.set(0x2D);
    // `int 0x2D` em block+0x8FF: o RIP salvo é o do `int3` em block+0x901.
    let breakpoint = block + 0x901;
    let user_rsp = block + 0x3F00;
    let fill = |service: u64| {
        guest::write_bytes(live, &[0u8; nt::Context::SIZE as usize]);
        context.context_flags.set(0x10_0003);
        context.seg_cs.set(0x33);
        context.seg_ss.set(0x2B);
        context.e_flags.set(0x246);
        context.rsp.set(user_rsp);
        context.rip.set(breakpoint);
        context.rax.set(service);
        context.rcx.set(block + 0x100);
        context.rdx.set(MESSAGE.len() as u64);
    };
    fill(1);
    let printed = exceptions::hardware(&thread, STATUS_BREAKPOINT) == 0 && context.rip.get() == breakpoint + 1 && context.rsp.get() == user_rsp;
    assert(printed, "dbgsvc: DbgPrint do anel 3 tratado no kernel, sem excecao no processo, e a thread segue depois do int3");
    fill(2);
    let delivered = exceptions::hardware(&thread, STATUS_BREAKPOINT);
    let stack = context.rsp.get();
    let record_offset = (nt::Context::SIZE + nt::ContextEx::SIZE + 15) & !15;
    // SAFETY: o quadro que o despacho montou na pilha de usuário mapeada.
    let (frame, record) = unsafe { (nt::Context::at(stack), nt::ExceptionRecord::at(stack + record_offset)) };
    let prompt = delivered == 0
        && context.rip.get() == dispatcher
        && record.exception_code.get() as u32 == STATUS_BREAKPOINT
        && record.number_parameters.get() == 1
        && record.exception_information[0].get() == 2
        && record.exception_address.get() == breakpoint + 1
        && frame.rip.get() == breakpoint;
    assert(prompt, "dbgsvc: prompt entregue ao KiUserExceptionDispatcher com STATUS_BREAKPOINT, o servico e o RIP no int3");
    usermode::block().fault_vector.set(saved_vector);
    state::with(|state| state.ntdll_exports = saved_exports);
    guest::free_bytes(live);
}
