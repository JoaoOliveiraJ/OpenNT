//! O estado estendido do processador no kernel (`ke::xsave`, `ke::xstate`,
//! `hal::amd64::extended_state`), conferido com o CPUID de cada CPU e as
//! regras do ntoskrnl 19041:
//!
//! - a configuração: XState publicada igual à do kernel; os recursos
//!   habilitados dentro dos que o CPUID 0xD anuncia, com x87 e SSE, e só com
//!   a política do hwpolicy.sys no bundle; os tamanhos e deslocamentos de
//!   cada recurso (o formato padrão ou o compactado), Size, AllFeatureSize =
//!   KeXStateLength = KiXSaveAreaLength, os voláteis e o ControlFlags pelo
//!   CPUID 0xD.1; KF_XSTATE, KF_XSAVEOPT, KF_XSAVES e os PF_* do XSAVE e do
//!   AVX; CR4.OSXSAVE e XCR0 = EnabledFeatures em todos os processadores;
//! - os exports: RtlGetEnabledExtendedFeatures,
//!   RtlGetEnabledExtendedAndSupervisorFeatures, KeGetXSaveFeatureFlags,
//!   KeSaveFloatingPointState e KeRestoreFloatingPointState;
//! - o KeSaveExtendedProcessorState e o KeRestoreExtendedProcessorState de
//!   um driver: em PASSIVE_LEVEL (área do pool, alinhada a 64, com a metade
//!   alta dos YMM salvos), aninhados (a lista KTHREAD.XStateSave) e em
//!   DISPATCH_LEVEL (a KPRCB.ExtendedState); a metade alta dos YMM volta
//!   depois de sobrescrita (o XMM não é parte do salvamento);
//! - duas threads de sistema com YMM diferentes esperam e recebem
//!   interrupções do relógio várias vezes (KeDelayExecutionThread e espera
//!   ativa): cada uma termina com a metade alta dos 16 YMM e o XMM6-XMM15
//!   próprios (o XMM0-XMM5 é volátil pela ABI), e, fora da CPU, a área
//!   KTHREAD.StateSaveArea de cada uma tem a metade alta dos YMM dela (o
//!   salvamento ansioso da troca).
//!
//! `XSTATE_KERNEL_OK` sai só se todas as conferências passarem.

use core::arch::global_asm;
use core::sync::atomic::{AtomicBool, Ordering};

use super::phase6::call_export;
use crate::hal::cpu;
use crate::ntos::inc::types::{Kthread, NtStruct, XstateConfiguration, XstateSave};
use crate::ntos::ke::processor_identity::{self, kf};
use crate::ntos::ke::{clock, irql, pcr, smp, xsave, xstate};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::shared_user_data;
use crate::ntos::ob::object_manager;
use crate::ntos::ps::{kernel_threads, process, scheduler};

type Assert = fn(bool, &str);

static FAILED: AtomicBool = AtomicBool::new(false);

global_asm!(
    r#"
.pushsection .text.opennt_xstate_test, "ax", @progbits
# opennt_xs_ymm_load(rdi = 16 x 32 bytes): YMM0..YMM15 da memória.
.global opennt_xs_ymm_load
opennt_xs_ymm_load:
    vmovdqu ymm0, [rdi + 0x000]
    vmovdqu ymm1, [rdi + 0x020]
    vmovdqu ymm2, [rdi + 0x040]
    vmovdqu ymm3, [rdi + 0x060]
    vmovdqu ymm4, [rdi + 0x080]
    vmovdqu ymm5, [rdi + 0x0A0]
    vmovdqu ymm6, [rdi + 0x0C0]
    vmovdqu ymm7, [rdi + 0x0E0]
    vmovdqu ymm8, [rdi + 0x100]
    vmovdqu ymm9, [rdi + 0x120]
    vmovdqu ymm10, [rdi + 0x140]
    vmovdqu ymm11, [rdi + 0x160]
    vmovdqu ymm12, [rdi + 0x180]
    vmovdqu ymm13, [rdi + 0x1A0]
    vmovdqu ymm14, [rdi + 0x1C0]
    vmovdqu ymm15, [rdi + 0x1E0]
    ret

# opennt_xs_ymm_store(rdi): YMM0..YMM15 na memória.
.global opennt_xs_ymm_store
opennt_xs_ymm_store:
    vmovdqu [rdi + 0x000], ymm0
    vmovdqu [rdi + 0x020], ymm1
    vmovdqu [rdi + 0x040], ymm2
    vmovdqu [rdi + 0x060], ymm3
    vmovdqu [rdi + 0x080], ymm4
    vmovdqu [rdi + 0x0A0], ymm5
    vmovdqu [rdi + 0x0C0], ymm6
    vmovdqu [rdi + 0x0E0], ymm7
    vmovdqu [rdi + 0x100], ymm8
    vmovdqu [rdi + 0x120], ymm9
    vmovdqu [rdi + 0x140], ymm10
    vmovdqu [rdi + 0x160], ymm11
    vmovdqu [rdi + 0x180], ymm12
    vmovdqu [rdi + 0x1A0], ymm13
    vmovdqu [rdi + 0x1C0], ymm14
    vmovdqu [rdi + 0x1E0], ymm15
    ret
.popsection
"#
);

extern "C" {
    fn opennt_xs_ymm_load(source: u64);
    fn opennt_xs_ymm_store(target: u64);
}

/// 16 registros YMM de 32 bytes.
pub const YMM_BYTES: usize = 0x200;

/// Um padrão de YMM distinto por semente.
pub fn pattern(seed: u8) -> [u8; YMM_BYTES] {
    core::array::from_fn(|index| (index as u8).wrapping_mul(7).wrapping_add(seed.wrapping_mul(0x35)).wrapping_add(1))
}

/// A metade alta dos 16 YMM de um padrão (o componente AVX do XSAVE).
pub fn upper_halves(pattern: &[u8]) -> alloc::vec::Vec<u8> {
    (0..16).flat_map(|register| pattern[register * 32 + 16..register * 32 + 32].iter().copied()).collect()
}

/// Os 16 YMM com a metade baixa (o XMM) de `lower` e a alta de `upper`: o
/// que uma restauração do estado estendido sem o SSE deixa (o salvamento dos
/// drivers e o da troca levam só os recursos além do x87 e do SSE).
fn mixed(lower: &[u8], upper: &[u8]) -> alloc::vec::Vec<u8> {
    (0..16).flat_map(|register| lower[register * 32..register * 32 + 16].iter().chain(&upper[register * 32 + 16..register * 32 + 32]).copied()).collect()
}

/// O que uma chamada preserva pela ABI x64 da Microsoft numa troca de
/// contexto: a metade alta dos 16 YMM (o estado estendido) e o XMM6-XMM15
/// inteiros (o quadro de troca); o XMM0-XMM5 é volátil.
fn preserved_across_calls(observed: &[u8], expected: &[u8]) -> bool {
    (0..16).all(|register| {
        let start = register * 32 + if register < 6 { 16 } else { 0 };
        observed[start..register * 32 + 32] == expected[start..register * 32 + 32]
    })
}

fn load(buffer: u64) {
    // SAFETY: 512 bytes do chamador; o AVX está ligado (conferido antes).
    unsafe { opennt_xs_ymm_load(buffer) }
}

fn store(buffer: u64) {
    // SAFETY: como em `load`.
    unsafe { opennt_xs_ymm_store(buffer) }
}

fn check(assert: Assert, condition: bool, message: &str) {
    if !condition {
        FAILED.store(true, Ordering::SeqCst);
    }
    assert(condition, message);
}

fn avx_enabled() -> bool {
    xsave::enabled_features() & xsave::feature::AVX != 0
}

/// CR4 e XCR0 do processador que executa (um job num AP).
extern "win64" fn read_control(output: u64, _: u64, _: u64, _: u64) -> u64 {
    let control4 = cpu::read_cr4();
    guest::write64(output, control4);
    guest::write64(output + 8, if control4 & (1 << 18) != 0 { cpu::read_xcr(0) } else { u64::MAX });
    0
}

fn configuration(assert: Assert) {
    let config = xsave::configuration();
    let Some(data) = shared_user_data::data() else {
        check(assert, false, "xstate: KUSER_SHARED_DATA publicada");
        return;
    };
    let size = XstateConfiguration::SIZE as usize;
    check(assert, guest::read_bytes(data.x_state.address(), size) == guest::read_bytes(config.address(), size), "xstate: KUSER_SHARED_DATA.XState igual a configuracao do kernel");
    let enabled = config.enabled_features.get();
    let bits = processor_identity::feature_bits();
    if cpu::cpuid(1)[2] & (1 << 26) == 0 {
        check(assert, enabled == 0 && bits & kf::XSTATE == 0, "xstate: sem XSAVE no CPUID, nada habilitado");
        return;
    }
    let [eax0, _, _, edx0] = cpu::cpuid_subleaf(0xD, 0);
    let supported = (edx0 as u64) << 32 | eax0 as u64;
    let policy = crate::hal::bundle::read("apps/hwpolicy.sys").is_some();
    check(assert, (enabled != 0) == policy && enabled & !supported == 0 && (enabled == 0 || enabled & 3 == 3), "xstate: recursos habilitados dentro do CPUID 0xD, com x87 e SSE, e so com a politica do hwpolicy.sys");
    if enabled == 0 {
        check(assert, bits & (kf::XSTATE | kf::XSAVEOPT | kf::XSAVES) == 0 && cpu::read_cr4() & (1 << 18) == 0, "xstate: sem recursos, sem KF_XSTATE e sem CR4.OSXSAVE");
        return;
    }
    let [eax1, _, _, _] = cpu::cpuid_subleaf(0xD, 1);
    let compaction = eax1 & 0xA == 0xA;
    let optimized = eax1 & 1 != 0;
    let flags = config.control_flags.get();
    check(assert, (flags & 1 != 0) == optimized && (flags & 2 != 0) == compaction, "xstate: ControlFlags (OptimizedSave e CompactionEnabled) pelo CPUID 0xD.1");
    let aligned = config.aligned_features.get();
    let mut layout_ok = config.features[0].size.get() == 0xA0 && config.features[1].offset.get() == 0xA0 && config.features[1].size.get() == 0x100;
    let mut standard_size = 0x240u32;
    let mut compacted = 0x240u32;
    for index in 2..64u32 {
        if enabled & (1u64 << index) == 0 {
            continue;
        }
        let [eax, ebx, ecx, _] = cpu::cpuid_subleaf(0xD, index);
        let feature = &config.features[index as usize];
        if ecx & 2 != 0 {
            compacted = (compacted + 0x3F) & !0x3F;
            layout_ok &= aligned & (1u64 << index) != 0;
        }
        let offset = if compaction { compacted } else { ebx };
        layout_ok &= feature.size.get() == eax && feature.offset.get() == offset;
        compacted += eax;
        standard_size = standard_size.max(ebx + eax);
    }
    let expected_size = if compaction { compacted } else { standard_size };
    check(assert, layout_ok && config.size.get() == expected_size, "xstate: deslocamento e tamanho de cada recurso e Size pelo CPUID 0xD (formato compactado com a compactacao)");
    let all = config.all_feature_size.get();
    check(assert, all >= config.size.get() && xsave::xstate_length() == all && xsave::xsave_area_length() == all, "xstate: AllFeatureSize = KeXStateLength = KiXSaveAreaLength");
    check(assert, config.enabled_volatile_features.get() == enabled & !0x4000_0000_0000_0010, "xstate: EnabledVolatileFeatures sem o BNDCSR e o LWP");
    let expected_bits = (bits & kf::XSTATE != 0) && (bits & kf::XSAVEOPT != 0) == optimized && (bits & kf::XSAVES != 0) == compaction;
    check(assert, expected_bits, "xstate: KF_XSTATE, KF_XSAVEOPT e KF_XSAVES no KeFeatureBits");
    let features = |index: usize| data.processor_features[index].get() != 0;
    let leaf7 = cpu::cpuid_subleaf(7, 0);
    check(assert, features(17) && features(39) == (enabled & 4 != 0 && cpu::cpuid(1)[2] & (1 << 28) != 0) && features(40) == (enabled & 4 != 0 && leaf7[1] & (1 << 5) != 0), "xstate: PF_XSAVE_ENABLED, PF_AVX e PF_AVX2 na KUSER_SHARED_DATA");
    // KiEnableXSave em cada processador.
    let scratch = guest::alloc_bytes(16);
    let mut processors_ok = true;
    for number in 0..smp::online_cpu_count() {
        if number == 0 {
            read_control(scratch, 0, 0, 0);
        } else if let Some(slot) = smp::ap_slot(number - 1) {
            processors_ok &= smp::run_on_ap(slot, read_control as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64, [scratch, 0, 0, 0]).is_ok();
        } else {
            continue;
        }
        processors_ok &= guest::read64(scratch) & (1 << 18) != 0 && guest::read64(scratch + 8) == enabled;
        processors_ok &= pcr::processor_block(number as u32).is_some_and(|prcb| prcb.extended_state.get() != 0 && prcb.extended_state.get() % 64 == 0 && prcb.feature_bits.get() & kf::XSTATE != 0);
    }
    guest::free_bytes(scratch);
    check(assert, processors_ok, "xstate: CR4.OSXSAVE, XCR0 = EnabledFeatures, KF_XSTATE e KPRCB.ExtendedState em todos os processadores");
}

fn exports(assert: Assert) {
    let enabled = xsave::enabled_features();
    let visible = enabled | xsave::enabled_user_visible_supervisor_features();
    let all = call_export("RtlGetEnabledExtendedFeatures", &[u64::MAX]);
    let none = call_export("RtlGetEnabledExtendedFeatures", &[0]);
    let avx = call_export("RtlGetEnabledExtendedFeatures", &[4]);
    check(assert, all == Some(visible) && none == Some(0) && avx == Some(enabled & 4), "xstate: RtlGetEnabledExtendedFeatures = (EnabledFeatures | supervisor visivel) & mascara");
    let supervisor = call_export("RtlGetEnabledExtendedAndSupervisorFeatures", &[u64::MAX]);
    check(assert, supervisor == Some(enabled | xsave::enabled_supervisor_features()), "xstate: RtlGetEnabledExtendedAndSupervisorFeatures com os recursos de supervisor");
    let flags = xsave::configuration().control_flags.get();
    let expected = if enabled == 0 { 0 } else { (flags & 1) << 3 | if flags & 2 != 0 { 0x10 } else { 0 } };
    check(assert, call_export("KeGetXSaveFeatureFlags", &[]) == Some(expected as u64), "xstate: KeGetXSaveFeatureFlags pelo OptimizedSave e pela compactacao");
    let buffer = guest::alloc_bytes(0x80);
    guest::write_bytes(buffer, &[0xCC; 0x80]);
    let saved = call_export("KeSaveFloatingPointState", &[buffer]);
    let restored = call_export("KeRestoreFloatingPointState", &[buffer]);
    check(assert, saved == Some(0) && restored == Some(0) && guest::read_bytes(buffer, 0x80).iter().all(|&byte| byte == 0xCC), "xstate: KeSaveFloatingPointState e KeRestoreFloatingPointState devolvem STATUS_SUCCESS sem tocar no buffer");
    guest::free_bytes(buffer);
}

/// O XSTATE_SAVE de um driver.
fn save_block(address: u64) -> &'static XstateSave {
    // SAFETY: bloco do teste.
    unsafe { XstateSave::at(address) }
}

fn driver_api(assert: Assert) {
    if !avx_enabled() {
        check(assert, false, "xstate: AVX habilitado para o teste dos drivers");
        return;
    }
    let current = process::get_current_thread();
    // SAFETY: a KTHREAD corrente.
    let thread = unsafe { Kthread::at(current) };
    let blocks = guest::alloc_aligned(0x1000 + 4 * YMM_BYTES as u64, 64, true);
    let (first, second, third) = (blocks, blocks + 0x40, blocks + 0x80);
    let (a, b, c, out) = (blocks + 0x1000, blocks + 0x1200, blocks + 0x1400, blocks + 0x1600);
    guest::write_bytes(a, &pattern(1));
    guest::write_bytes(b, &pattern(2));
    guest::write_bytes(c, &pattern(3));
    let chain_before = thread.x_state_save.get();
    // PASSIVE_LEVEL: área do pool.
    load(a);
    let status = call_export("KeSaveExtendedProcessorState", &[4, first]);
    let save = save_block(first);
    let context = &save.x_state_context;
    let area = context.area.get();
    let config = xsave::configuration();
    let fields_ok = status == Some(0)
        && save.thread.get() == current
        && save.level.get() == 0
        && save.prev.get() == chain_before
        && thread.x_state_save.get() == first
        && context.mask.get() == xsave::enabled_features() & !3
        && area != 0
        && area % 64 == 0
        && context.buffer.get() != 0
        && context.length.get() == config.size.get().max(0x240);
    let saved_ok = xstate::feature_bytes(area, 2).is_some_and(|bytes| bytes == upper_halves(&pattern(1)));
    check(assert, fields_ok && saved_ok, "xstate: KeSaveExtendedProcessorState em PASSIVE_LEVEL preenche o XSTATE_SAVE, entra na lista da thread e salva a metade alta dos YMM");
    // Aninhado: o segundo vai ao topo da lista.
    load(b);
    let nested = call_export("KeSaveExtendedProcessorState", &[4, second]);
    let nested_ok = nested == Some(0) && save_block(second).prev.get() == first && thread.x_state_save.get() == second && xstate::user_state_area(current) == area;
    load(c);
    call_export("KeRestoreExtendedProcessorState", &[second]);
    store(out);
    let inner_ok = guest::read_bytes(out, YMM_BYTES) == mixed(&pattern(3), &pattern(2)) && thread.x_state_save.get() == first && save_block(second).x_state_context.buffer.get() == 0;
    call_export("KeRestoreExtendedProcessorState", &[first]);
    store(out);
    let outer_ok = guest::read_bytes(out, YMM_BYTES) == mixed(&pattern(3), &pattern(1)) && thread.x_state_save.get() == chain_before && context.buffer.get() == 0 && context.area.get() == 0;
    check(assert, nested_ok && inner_ok && outer_ok, "xstate: salvamentos aninhados na lista KTHREAD.XStateSave; cada restauracao devolve a metade alta dos YMM daquele salvamento (o XMM fica) e libera a area");
    // DISPATCH_LEVEL: a KPRCB.ExtendedState.
    let previous = irql::raise_irql(irql::DISPATCH_LEVEL);
    load(a);
    let raised = call_export("KeSaveExtendedProcessorState", &[4, third]);
    let save = save_block(third);
    let prcb_area = pcr::current().prcb.extended_state.get();
    let dispatch_ok = raised == Some(0) && save.level.get() == irql::DISPATCH_LEVEL + 1 && save.x_state_context.area.get() == prcb_area && save.x_state_context.buffer.get() == 0 && save.x_state_context.length.get() == xsave::xstate_length();
    load(b);
    call_export("KeRestoreExtendedProcessorState", &[third]);
    store(out);
    irql::lower_irql(previous as u64);
    let dispatch_restored = guest::read_bytes(out, YMM_BYTES) == mixed(&pattern(2), &pattern(1)) && thread.x_state_save.get() == chain_before;
    check(assert, dispatch_ok && dispatch_restored, "xstate: em DISPATCH_LEVEL o salvamento usa a KPRCB.ExtendedState (nivel IRQL + 1) e a restauracao devolve a metade alta dos YMM");
    guest::free_bytes(blocks);
}

// ---- duas threads de sistema --------------------------------------------------

/// Bloco de cada thread: [0] padrão (0x200), [0x200] saída (0x200), [0x400]
/// rodadas, [0x408] rodadas concluídas, [0x410] fim, [0x418] o intervalo
/// relativo do KeDelayExecutionThread (1 ms).
const ROUNDS: u64 = 12;

extern "win64" fn ymm_worker(block: u64) {
    load(block);
    for round in 0..guest::read64(block + 0x400) {
        // A espera tira a thread da CPU (uma troca de contexto de verdade).
        call_export("KeDelayExecutionThread", &[0, 0, block + 0x418]);
        // Espera ticks do relógio com as interrupções ligadas.
        let until = clock::uptime_ms() + 3;
        while clock::uptime_ms() < until {
            cpu::pause();
        }
        guest::write64(block + 0x408, round + 1);
    }
    store(block + 0x200);
    guest::write64(block + 0x410, 1);
}

fn thread_switches(assert: Assert) {
    if !avx_enabled() {
        return;
    }
    let blocks = [guest::alloc_bytes(0x480), guest::alloc_bytes(0x480)];
    for (index, &block) in blocks.iter().enumerate() {
        guest::write_bytes(block, &[0; 0x480]);
        guest::write_bytes(block, &pattern(0x10 + index as u8));
        guest::write64(block + 0x400, ROUNDS);
        guest::write64(block + 0x418, (-10_000i64) as u64);
    }
    let started: alloc::vec::Vec<(u64, u64)> = blocks
        .iter()
        .map(|&block| {
            let handle = kernel_threads::create_system_thread(0, ymm_worker as extern "win64" fn(u64) as usize as u64, block, 0x1F_FFFF, 0, None).unwrap_or(0);
            (handle, kernel_threads::of_handle(handle).unwrap_or(0))
        })
        .collect();
    let mut area_checks = 0u32;
    let mut area_ok = true;
    let deadline = clock::uptime_ms() + 30_000;
    let done = || blocks.iter().all(|&block| guest::read64(block + 0x410) == 1);
    while !done() && clock::uptime_ms() < deadline {
        scheduler::tick(-1);
        // Uma thread que já cedeu a vez e não terminou tem a metade alta dos
        // YMM dela na área (ela não muda os YMM depois de carregá-los).
        for (&block, &(_, thread)) in blocks.iter().zip(&started) {
            if thread == 0 || guest::read64(block + 0x408) == 0 || guest::read64(block + 0x410) != 0 {
                continue;
            }
            let area = xstate::thread_area(thread);
            area_ok &= xstate::feature_bytes(area, 2).is_some_and(|bytes| bytes == upper_halves(&guest::read_bytes(block, YMM_BYTES)));
            area_checks += 1;
        }
    }
    let finished = done();
    let values_ok = blocks.iter().all(|&block| preserved_across_calls(&guest::read_bytes(block + 0x200, YMM_BYTES), &guest::read_bytes(block, YMM_BYTES)));
    check(assert, started.iter().all(|&(_, thread)| thread != 0) && finished && values_ok, "xstate: duas threads de sistema com YMM diferentes terminam com a metade alta dos 16 YMM e o XMM6-XMM15 proprios depois de esperar e receber ticks do relogio");
    check(assert, area_checks > 0 && area_ok, "xstate: fora da CPU, a KTHREAD.StateSaveArea de cada thread tem a metade alta dos YMM dela (salvamento ansioso)");
    let _ = started.iter().all(|&(_, thread)| thread == 0 || kernel_threads::is_terminated(thread));
    for &(handle, _) in &started {
        if handle != 0 {
            let _ = object_manager::close(handle as u32);
        }
    }
    for block in blocks {
        guest::free_bytes(block);
    }
}

/// O teste inteiro; `XSTATE_KERNEL_OK` sai só se todas as conferências passarem.
pub fn run(assert: Assert) {
    FAILED.store(false, Ordering::SeqCst);
    configuration(assert);
    exports(assert);
    if xsave::enabled_features() != 0 {
        driver_api(assert);
        thread_switches(assert);
    }
    if !FAILED.load(Ordering::SeqCst) {
        crate::debug_print!("XSTATE_KERNEL_OK");
    }
}
