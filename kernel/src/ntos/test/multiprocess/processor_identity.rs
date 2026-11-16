//! A identidade dos processadores (`ke/processor_identity`), conferida com o
//! CPUID de cada CPU pelas regras do ntoskrnl 19041:
//!
//! - em cada processador online (um job no AP): ProcessorSignature = CPUID 1
//!   EAX, o APIC id legado nos 8 bits baixos do InitialApicId, o mesmo
//!   APIC id que a MADT deu a esse número, GroupSetMember = 1 << Number;
//!   VendorString, CpuVendor, CpuType, CpuStep e CpuID decodificados do
//!   CPUID; MHz = o TSC arredondado; KeQueryPrcbAddress devolve cada KPRCB e
//!   NULL além delas;
//! - FeatureBits com os recursos exigidos, o bit do fabricante e os bits de
//!   SSE3, SSSE3, SSE4.1/4.2, RDRAND e RDTSCP; KeFeatureBits com o NX ligado
//!   pelo EFER;
//! - núcleos disjuntos que cobrem os ativos, cada processador no próprio
//!   núcleo e pacote;
//! - os ProcessorFeatures da KUSER_SHARED_DATA pela lista do
//!   KiInitializeKernel, iguais na visão de usuário (0x7FFE0274) que o
//!   IsProcessorFeaturePresent lê;
//! - pelas chamadas de sistema, com buffers de usuário:
//!   SystemProcessorInformation (nível, revisão, MaximumProcessors = MADT e
//!   o ULONG baixo de KeFeatureBits), SystemProcessorFeaturesInformation
//!   (KeFeatureBits e zeros; o buffer curto pede 0x20),
//!   SystemLogicalProcessorInformation (registros de 0x20 bytes, núcleos que
//!   cobrem os ativos e o nó com eles; o buffer curto pede o tamanho) e o
//!   NtQuerySystemInformationEx(107) igual ao KeQueryLogicalProcessorRelationship.

use alloc::vec::Vec;

use super::identity::with_test_process;
use crate::hal::cpu;
use crate::ntos::inc::types::{Kprcb, NtStruct};
use crate::ntos::ke::processor_identity::{self, kf, vendor};
use crate::ntos::ke::{clock, pcr, processor_topology, smp};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::shared_user_data;
use crate::ntos::ps::user::{memory, state};
use crate::ntos::test::phase6::call_export;

type Assert = fn(bool, &str);

const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;

/// O que um processador lê do próprio CPUID: [assinatura, APIC id legado].
extern "win64" fn read_identity(output: u64, _: u64, _: u64, _: u64) -> u64 {
    let [eax, ebx, _, _] = cpu::cpuid(1);
    guest::write32(output, eax);
    guest::write32(output + 4, ebx >> 24);
    0
}

/// O texto do fabricante e o CPU_VENDORS esperado.
fn expected_vendor() -> (Vec<u8>, u8) {
    let [_, ebx, ecx, edx] = cpu::cpuid(0);
    let text: Vec<u8> = [ebx, edx, ecx].iter().flat_map(|register| register.to_le_bytes()).collect();
    let code = match text.as_slice() {
        b"AuthenticAMD" | b"HygonGenuine" => vendor::AMD,
        b"GenuineIntel" => vendor::INTEL,
        b"CentaurHauls" => vendor::CENTAUR,
        _ => vendor::UNKNOWN,
    };
    (text, code)
}

/// (família, modelo, stepping) pelas regras do KiGetProcessorSignature.
fn expected_signature(code: u8, eax: u32) -> (u32, u32, u32) {
    let base = (eax >> 8) & 0xF;
    let extended_model = (eax >> 16) & 0xF;
    let family = if base == 0xF { base + ((eax >> 20) & 0xFF) } else { base };
    let mut model = (eax >> 4) & 0xF;
    if base == 0xF || (base == 6 && (code == vendor::INTEL || code == vendor::CENTAUR)) {
        model |= extended_model << 4;
    }
    (family, model, eax & 0xF)
}

fn identity_of(assert: Assert, prcb: &Kprcb, number: u32, signature: u32, legacy_apic: u32) {
    let (text, code) = expected_vendor();
    let vendor_text: Vec<u8> = prcb.vendor_string.iter().map(|cell| cell.get()).collect();
    let (family, model, stepping) = expected_signature(code, signature);
    let megahertz = ((clock::tsc_frequency_hz() + 500_000) / 1_000_000) as u32;
    let madt = processor_topology::processor_apic_ids().get(number as usize).copied();
    assert(
        vendor_text[..12] == text[..] && vendor_text[12] == 0 && prcb.cpu_vendor.get() == code && prcb.cpu_id.get() == 1,
        "cpu-identidade: VendorString e CpuVendor do CPUID 0 em cada processador",
    );
    assert(
        prcb.cpu_type.get() as u8 as u32 == family & 0xFF && prcb.cpu_step.get() as u32 == ((model & 0xFF) << 8 | stepping) && prcb.processor_signature.get() == signature,
        "cpu-identidade: CpuType, CpuStep e ProcessorSignature do CPUID 1 do proprio processador",
    );
    assert(
        prcb.initial_apic_id.get() & 0xFF == legacy_apic && madt == Some(prcb.initial_apic_id.get()) && prcb.group_set_member.get() == 1u64 << number && prcb.group_index.get() as u32 == number,
        "cpu-identidade: InitialApicId do proprio CPUID, igual ao da MADT, e GroupSetMember",
    );
    assert(prcb.m_hz.get() == megahertz && prcb.logical_processors_per_core.get() >= 1 && prcb.cores_per_physical_processor.get() >= 1 && prcb.cache_count.get() <= 5, "cpu-identidade: MHz pelo TSC e contagens de nucleo e cache");
    assert(prcb.core_processor_set.get() & prcb.group_set_member.get() != 0 && prcb.package_processor_set.bitmap[0].get() & prcb.core_processor_set.get() == prcb.core_processor_set.get(), "cpu-identidade: o processador no proprio nucleo, e o nucleo dentro do pacote");
}

fn per_processor(assert: Assert) {
    let online = smp::online_cpu_count() as u32;
    let scratch = guest::alloc_bytes(8);
    let Some(boot) = pcr::processor_block(0) else {
        assert(false, "cpu-identidade: KiProcessorBlock[0]");
        return;
    };
    let [eax, ebx, _, _] = cpu::cpuid(1);
    identity_of(assert, boot, 0, eax, ebx >> 24);
    let mut cores = 0u64;
    let mut disjoint = true;
    for number in 0..online {
        let Some(prcb) = pcr::processor_block(number) else {
            assert(false, "cpu-identidade: uma KPRCB por processador online");
            continue;
        };
        assert(call_export("KeQueryPrcbAddress", &[number as u64]) == Some(prcb.address()) && prcb.number.get() == number, "cpu-identidade: KeQueryPrcbAddress devolve a KPRCB de cada processador");
        let core = prcb.core_processor_set.get();
        if core.trailing_zeros() == number {
            disjoint &= cores & core == 0;
            cores |= core;
        }
        if number == 0 {
            continue;
        }
        let Some(slot) = smp::ap_slot(number as usize - 1) else { continue };
        let ran = smp::run_on_ap(slot, read_identity as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64, [scratch, 0, 0, 0]);
        assert(ran.is_ok(), "cpu-identidade: job no AP");
        identity_of(assert, prcb, number, guest::read32(scratch), guest::read32(scratch + 4));
    }
    let active = if online >= 64 { u64::MAX } else { (1u64 << online) - 1 };
    assert(disjoint && cores == active, "cpu-identidade: os nucleos sao disjuntos e cobrem os processadores ativos");
    assert(call_export("KeQueryPrcbAddress", &[online as u64]) == Some(0), "cpu-identidade: KeQueryPrcbAddress alem dos processadores online = NULL");
    guest::free_bytes(scratch);
}

fn feature_bits(assert: Assert) {
    let (_, code) = expected_vendor();
    let Some(boot) = pcr::processor_block(0) else { return };
    let bits = boot.feature_bits.get();
    let [_, _, ecx1, _] = cpu::cpuid(1);
    let extended = if cpu::cpuid(0x8000_0000)[0] >= 0x8000_0001 { cpu::cpuid(0x8000_0001) } else { [0; 4] };
    let family = boot.cpu_type.get() as u8;
    let vendor_bit = match code {
        vendor::AMD => kf::AUTHENTIC_AMD,
        vendor::INTEL => kf::GENUINE_INTEL,
        _ => 0,
    };
    let ssse3 = ecx1 & (1 << 9) != 0 && !(code == vendor::AMD && (family == 0x10 || family == 0x12));
    let expected = [
        (kf::SSE3, ecx1 & 1 != 0),
        (kf::SSSE3, ssse3),
        (kf::SSE4_1, ecx1 & (1 << 19) != 0),
        (kf::SSE4_2, ecx1 & (1 << 20) != 0),
        (kf::RDRAND, ecx1 & (1 << 30) != 0),
        (kf::RDTSCP, extended[3] & (1 << 27) != 0),
    ];
    assert(bits & kf::REQUIRED == kf::REQUIRED && bits & vendor_bit == vendor_bit && expected.iter().all(|&(bit, present)| (bits & bit != 0) == present), "cpu-identidade: FeatureBits com os recursos exigidos, o fabricante e os bits do CPUID");
    let nx = extended[3] & (1 << 20) != 0 && cpu::read_msr(0xC000_0080) & 0x800 != 0;
    let global = processor_identity::feature_bits();
    let nx_bits = if nx { kf::NX_ENABLED } else { kf::NX_DISABLED };
    assert(global & !(kf::NX_ENABLED | kf::NX_DISABLED) == bits & !(kf::NX_ENABLED | kf::NX_DISABLED) && global & (kf::NX_ENABLED | kf::NX_DISABLED) == nx_bits, "cpu-identidade: KeFeatureBits = FeatureBits do BSP com o NX do EFER");
    assert(processor_identity::processor_level() == boot.cpu_type.get() as i16 as u16 && processor_identity::processor_revision() == boot.cpu_step.get(), "cpu-identidade: KeProcessorLevel e KeProcessorRevision da KPRCB do BSP");
}

/// Os PF_* esperados do CPUID, pela lista do KiInitializeKernel (sem o 20 e
/// o 21, que dependem dos MSRs de virtualização).
fn expected_processor_features(enabled_xstate: u64) -> [Option<bool>; 64] {
    let (_, code) = expected_vendor();
    let maximum = cpu::cpuid(0)[0];
    let [_, _, ecx1, _] = cpu::cpuid(1);
    let extended = if cpu::cpuid(0x8000_0000)[0] >= 0x8000_0001 { cpu::cpuid(0x8000_0001) } else { [0; 4] };
    let leaf7 = if maximum >= 7 { cpu::cpuid_subleaf(7, 0) } else { [0; 4] };
    let family = expected_signature(code, cpu::cpuid(1)[0]).0;
    let amd_or_intel = code == vendor::AMD || code == vendor::INTEL;
    let mut features = [Some(false); 64];
    for index in [2, 3, 6, 8, 9, 10, 14, 23] {
        features[index] = Some(true);
    }
    features[7] = Some(extended[3] & (1 << 31) != 0);
    features[12] = Some(extended[3] & (1 << 20) != 0 && cpu::read_msr(0xC000_0080) & 0x800 != 0);
    features[13] = Some(ecx1 & 1 != 0);
    features[17] = Some(enabled_xstate != 0);
    features[20] = None;
    features[21] = None;
    features[22] = Some(amd_or_intel && leaf7[1] & 1 != 0 && cpu::read_cr4() & (1 << 16) != 0);
    features[28] = Some(ecx1 & (1 << 30) != 0);
    features[32] = Some(extended[3] & (1 << 27) != 0);
    features[33] = Some(leaf7[2] & (1 << 22) != 0);
    features[35] = Some(code == vendor::AMD && extended[2] & (1 << 29) != 0);
    features[36] = Some(ecx1 & (1 << 9) != 0 && !(code == vendor::AMD && (family == 0x10 || family == 0x12)));
    features[37] = Some(ecx1 & (1 << 19) != 0);
    features[38] = Some(ecx1 & (1 << 20) != 0);
    features[39] = Some(enabled_xstate & 4 != 0 && ecx1 & (1 << 28) != 0);
    features[40] = Some(enabled_xstate & 4 != 0 && leaf7[1] & (1 << 5) != 0);
    features[41] = Some(enabled_xstate & 0xE0 != 0 && leaf7[1] & (1 << 16) != 0);
    features
}

fn shared_data(assert: Assert) {
    let Some(data) = shared_user_data::data() else {
        assert(false, "cpu-identidade: KUSER_SHARED_DATA publicada");
        return;
    };
    let published: Vec<u8> = data.processor_features.iter().map(|cell| cell.get()).collect();
    let expected = expected_processor_features(data.x_state.enabled_features.get());
    let agrees = published.iter().zip(expected.iter()).all(|(&value, wanted)| wanted.is_none_or(|wanted| value == wanted as u8));
    assert(agrees, "cpu-identidade: ProcessorFeatures (PF_*) da KUSER_SHARED_DATA pela lista do KiInitializeKernel");
    assert(data.active_processor_count.get() == smp::online_cpu_count() as u32 && data.test_ret_instruction.get() == 0xC3, "cpu-identidade: ActiveProcessorCount com os processadores online e TestRetInstruction");
    let user_view = with_test_process("cpu-recursos.exe", None, |_| guest::read_bytes(0x7FFE_0274, 64));
    assert(user_view.is_some_and(|view| view == published), "cpu-identidade: a visao de usuario (0x7FFE0274) que o IsProcessorFeaturePresent le e a mesma");
}

/// As consultas pela chamada de sistema, num processo de teste com buffers
/// de usuário.
fn system_information(assert: Assert) {
    let Some(query) = state::handler("NtQuerySystemInformation") else {
        assert(false, "cpu-identidade: NtQuerySystemInformation registrada");
        return;
    };
    let query_ex = state::handler("NtQuerySystemInformationEx");
    let outcome = with_test_process("cpu-consultas.exe", None, |_| {
        let Ok(buffer) = memory::map_user_region(0x4000) else { return false };
        let returned = buffer + 0x3FF0;
        let call = |class: u64, length: u64| query(class, buffer, length, returned, 0).unwrap_or(0xC000_0001);
        // SystemProcessorInformation.
        let status = call(1, 12);
        let information_ok = status == 0
            && guest::read16(buffer) == 9
            && guest::read16(buffer + 2) == processor_identity::processor_level()
            && guest::read16(buffer + 4) == processor_identity::processor_revision()
            && guest::read16(buffer + 6) as usize == smp::discovered_cpu_count()
            && guest::read32(buffer + 8) == processor_identity::feature_bits() as u32;
        assert(information_ok, "cpu-identidade: SystemProcessorInformation com o nivel, a revisao, os processadores da MADT e KeFeatureBits");
        // SystemProcessorFeaturesInformation.
        guest::write_bytes(buffer, &[0xCC; 0x20]);
        let status = call(154, 0x20);
        let features_ok = status == 0 && guest::read64(buffer) == processor_identity::feature_bits() && guest::read_bytes(buffer + 8, 0x18).iter().all(|&byte| byte == 0) && guest::read32(returned) == 0x20;
        let short = call(154, 0x18);
        assert(features_ok && short == STATUS_INFO_LENGTH_MISMATCH && guest::read32(returned) == 0x20, "cpu-identidade: SystemProcessorFeaturesInformation com KeFeatureBits; o buffer curto pede 0x20");
        // SystemLogicalProcessorInformation.
        let status = call(73, 0x3000);
        let used = guest::read32(returned) as u64;
        let online = smp::online_cpu_count() as u32;
        let active = if online >= 64 { u64::MAX } else { (1u64 << online) - 1 };
        let (mut cores, mut node, mut packages) = (0u64, 0u64, 0);
        for offset in (0..used).step_by(0x20) {
            let mask = guest::read64(buffer + offset);
            match guest::read32(buffer + offset + 8) {
                0 => cores |= mask,
                1 => node = mask,
                3 => packages += 1,
                _ => {}
            }
        }
        let legacy_ok = status == 0 && used % 0x20 == 0 && used != 0 && cores == active && node == active && packages >= 1;
        let short = call(73, 0x20);
        assert(legacy_ok && short == STATUS_INFO_LENGTH_MISMATCH && guest::read32(returned) as u64 == used, "cpu-identidade: SystemLogicalProcessorInformation com nucleos e no cobrindo os ativos; o buffer curto pede o tamanho");
        // NtQuerySystemInformationEx(107, RelationAll) = KeQueryLogicalProcessorRelationship.
        let Some(query_ex) = query_ex else { return false };
        let input = buffer + 0x3FE0;
        guest::write32(input, 0xFFFF);
        // Os argumentos 5 e 6 (Length, ReturnLength) na pilha de usuário.
        let rsp = buffer + 0x3F00;
        guest::write64(rsp + 0x28, 0x3000);
        guest::write64(rsp + 0x30, returned);
        let status = query_ex(107, input, 4, buffer + 0x1000, rsp).unwrap_or(0xC000_0001);
        let user_bytes = guest::read_bytes(buffer + 0x1000, guest::read32(returned) as usize);
        let kernel = guest::alloc_bytes(0x3004);
        guest::write32(kernel + 0x3000, 0x3000);
        let direct = call_export("KeQueryLogicalProcessorRelationship", &[0, 0xFFFF, kernel, kernel + 0x3000]).map(|status| status as u32);
        let kernel_bytes = guest::read_bytes(kernel, guest::read32(kernel + 0x3000) as usize);
        guest::free_bytes(kernel);
        status == 0 && direct == Some(0) && !user_bytes.is_empty() && user_bytes == kernel_bytes
    });
    assert(outcome == Some(true), "cpu-identidade: NtQuerySystemInformationEx(107) de modo usuario igual ao KeQueryLogicalProcessorRelationship");
}

pub fn run(assert: Assert) {
    if !processor_identity::ready() {
        assert(false, "cpu-identidade: identidade do BSP montada no boot");
        return;
    }
    per_processor(assert);
    feature_bits(assert);
    shared_data(assert);
    system_information(assert);
}
