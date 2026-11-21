//! O conjunto de contadores "Processor Information" do kernel:
//! ExProcessorCounterSetCallback (ntoskrnl 19041, rva 0x6c6a20) e
//! ExpQueryProcessorInformationCounters (0x6c7240), que o
//! ExpPcwHostCallback (`ex/pcw`) registra no pcw.sys com os 0x23
//! descritores do PcwpRegisterProcessorCounterSet (rva 0xe540).
//!
//! Cada instância é um bloco de 0xc8 bytes ([`ProcessorInformationCounters`])
//! que o PcwAddInstance entrega ao pcw.sys. A rotina responde a
//! PcwCallbackEnumerateInstances (2) e a PcwCallbackCollectData (3):
//!
//! - para cada nó (KeNumberNodes) e cada processador ativo do nó, na ordem
//!   da afinidade, a instância "nó,n" (n conta os processadores do nó) com
//!   o id do índice do processador; depois a do nó, "nó,_Total", com o id
//!   KeMaximumProcessors + nó; no fim "_Total", com o id KeMaximumProcessors
//!   + KeNumberNodes. Os totais somam os campos dos processadores, juntam as
//!   flags de limite de desempenho por OR, deixam de fora o estado de
//!   estacionamento e as flags de estado, e dividem pela contagem de
//!   processadores (quando há mais de um) os tempos, a frequência e as
//!   porcentagens; as bases e os numeradores da utilidade e o limite de
//!   desempenho só quando esses contadores foram pedidos;
//! - na coleta, um InstanceMask "%u,%u" pede só a instância do processador
//!   InstanceId (STATUS_NOT_FOUND além de KeNumberProcessors), com o nome do
//!   pedido;
//! - a máscara de contadores diz o que é lido: os tempos ociosos
//!   (0x1_00e0_ff05), o estado de desempenho e estacionamento (0xc00f_0000)
//!   e a utilidade (0x6_3f00_0000). Na enumeração, nada disso.
//!
//! ExpQueryProcessorInformationCounters lê da KPRCB do processador o que o
//! NT lê dela: a contagem de interrupções, os tempos de DPC e de interrupção
//! (DpcTime e InterruptTime em ticks vezes o KeMaximumIncrement), o
//! AvailableTime (que entra no tempo de prioridade), as interrupções de
//! relógio, a contagem e a taxa de DPCs e a frequência (MHz). O ocioso, o
//! tempo privilegiado e o de usuário são os do PoGetIdleTimes; no OpenNT, o
//! que `ke/processor_information` cobra de cada processador (os mesmos
//! valores da SystemProcessorPerformanceInformation). Sem PPM o
//! PoGetPerfStateAndParkingInfo dá a frequência da KPRCB, 100% da frequência
//! máxima e do limite de desempenho e nenhum estado C. A utilidade, que o
//! NT tira do acúmulo de desempenho da KPRCB (PpmSnapPerformanceAccumulation)
//! em unidades deslocadas para caber nas bases de 32 bits, sai aqui do mesmo
//! tempo por processador, à frequência nominal: a base da utilidade (+0x90)
//! é o tempo decorrido, a do desempenho (+0x94) o tempo ocupado, e os
//! numeradores (+0x98, +0xa0 e +0xc0) cem vezes o tempo ocupado, o
//! privilegiado e o ocupado, todos em unidades de 1024 x 100 ns; a
//! "% Processor Utility" é então o tempo ocupado sobre o decorrido e a
//! "% Processor Performance", 100.

use alloc::string::String;
use alloc::vec::Vec;

use crate::hal::amd64::routine_stubs::Routine;
use crate::ntos::ex::pcw;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{PcwCallbackInformation, UnicodeString};
use crate::ntos::init::exports::Call;
use crate::ntos::ke::{clock, pcr, processor_group, processor_information};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

const STATUS_NOT_FOUND: u32 = 0xC000_0225;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// PCW_CALLBACK_TYPE.
const PCW_CALLBACK_ENUMERATE_INSTANCES: u32 = 2;
const PCW_CALLBACK_COLLECT_DATA: u32 = 3;
/// Os contadores que pedem cada parte da leitura.
const IDLE_COUNTERS: u64 = 0x1_00e0_ff05;
const PERFORMANCE_COUNTERS: u64 = 0xc00f_0000;
const UTILITY_COUNTERS: u64 = 0x6_3f00_0000;
/// O deslocamento das unidades de tempo da utilidade (100 ns << 10).
const UTILITY_SHIFT: u32 = 10;
/// O nome do conjunto.
pub const NAME: &str = "Processor Information";
/// A primeira coleta já foi anotada na serial.
static FIRST_COLLECT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Os PCW_COUNTER_DESCRIPTOR do PcwpRegisterProcessorCounterSet: (Id,
/// StructIndex, Offset, Size).
pub const DESCRIPTORS: [(u16, u16, u16, u16); 0x23] = [
    (0x00, 0, 0x00, 8),
    (0x01, 0, 0x10, 8),
    (0x02, 0, 0x18, 8),
    (0x03, 0, 0x20, 4),
    (0x04, 0, 0x28, 8),
    (0x05, 0, 0x30, 8),
    (0x06, 0, 0x3c, 4),
    (0x07, 0, 0x40, 4),
    (0x08, 0, 0x00, 8),
    (0x09, 0, 0x48, 8),
    (0x0a, 0, 0x50, 8),
    (0x0b, 0, 0x58, 8),
    (0x0c, 0, 0x60, 8),
    (0x0d, 0, 0x68, 8),
    (0x0e, 0, 0x70, 8),
    (0x0f, 0, 0x08, 8),
    (0x10, 0, 0x80, 4),
    (0x11, 0, 0x84, 4),
    (0x12, 0, 0x88, 4),
    (0x13, 0, 0x8c, 4),
    (0x14, 0, 0x38, 4),
    (0x15, 0, 0xa8, 8),
    (0x16, 0, 0xb0, 8),
    (0x17, 0, 0xb0, 8),
    (0x18, 0, 0x98, 8),
    (0x19, 0, 0x94, 4),
    (0x1a, 0, 0x98, 8),
    (0x1b, 0, 0x90, 4),
    (0x1c, 0, 0xa0, 8),
    (0x1d, 0, 0x90, 4),
    (0x1e, 0, 0xb8, 4),
    (0x1f, 0, 0xbc, 4),
    (0x20, 0, 0x78, 8),
    (0x21, 0, 0xc0, 8),
    (0x22, 0, 0x94, 4),
];

/// O bloco de uma instância (0xc8 bytes, os deslocamentos dos descritores).
#[repr(C)]
pub struct ProcessorInformationCounters {
    pub idle_time: Field<u64>,
    pub priority_time: Field<u64>,
    pub user_time: Field<u64>,
    pub privileged_time: Field<u64>,
    pub interrupt_count: Field<u32>,
    _pad_24: Reserved<0x4>,
    pub dpc_time: Field<u64>,
    pub interrupt_time: Field<u64>,
    pub clock_interrupts: Field<u32>,
    pub dpc_count: Field<u32>,
    pub dpc_rate: Field<u32>,
    _pad_44: Reserved<0x4>,
    pub idle_state_time: [Field<u64>; 3],
    pub idle_state_transitions: [Field<u64>; 3],
    pub idle_accounting_time: Field<u64>,
    pub parking_status: Field<u32>,
    pub frequency: Field<u32>,
    pub percent_maximum_frequency: Field<u32>,
    pub state_flags: Field<u32>,
    pub utility_base: Field<u32>,
    pub performance_base: Field<u32>,
    pub performance: Field<u64>,
    pub privileged_utility: Field<u64>,
    pub total_idle_time: Field<u64>,
    pub total_idle_transitions: Field<u64>,
    pub performance_limit: Field<u32>,
    pub performance_limit_flags: Field<u32>,
    pub performance_weighted: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for ProcessorInformationCounters {}

const _: () = {
    assert!(core::mem::size_of::<ProcessorInformationCounters>() == 0xc8);
    assert!(core::mem::offset_of!(ProcessorInformationCounters, user_time) == 0x10);
    assert!(core::mem::offset_of!(ProcessorInformationCounters, interrupt_count) == 0x20);
    assert!(core::mem::offset_of!(ProcessorInformationCounters, dpc_time) == 0x28);
    assert!(core::mem::offset_of!(ProcessorInformationCounters, clock_interrupts) == 0x38);
    assert!(core::mem::offset_of!(ProcessorInformationCounters, dpc_count) == 0x3c);
    assert!(core::mem::offset_of!(ProcessorInformationCounters, dpc_rate) == 0x40);
    assert!(core::mem::offset_of!(ProcessorInformationCounters, idle_state_time) == 0x48);
    assert!(core::mem::offset_of!(ProcessorInformationCounters, idle_state_transitions) == 0x60);
    assert!(core::mem::offset_of!(ProcessorInformationCounters, idle_accounting_time) == 0x78);
    assert!(core::mem::offset_of!(ProcessorInformationCounters, parking_status) == 0x80);
    assert!(core::mem::offset_of!(ProcessorInformationCounters, state_flags) == 0x8c);
    assert!(core::mem::offset_of!(ProcessorInformationCounters, utility_base) == 0x90);
    assert!(core::mem::offset_of!(ProcessorInformationCounters, performance) == 0x98);
    assert!(core::mem::offset_of!(ProcessorInformationCounters, privileged_utility) == 0xa0);
    assert!(core::mem::offset_of!(ProcessorInformationCounters, total_idle_time) == 0xa8);
    assert!(core::mem::offset_of!(ProcessorInformationCounters, performance_limit) == 0xb8);
    assert!(core::mem::offset_of!(ProcessorInformationCounters, performance_weighted) == 0xc0);
};

/// Uma cópia dos valores de um bloco, para somar e dividir.
#[derive(Clone, Copy, Default)]
struct Values {
    idle_time: u64,
    priority_time: u64,
    user_time: u64,
    privileged_time: u64,
    interrupt_count: u32,
    dpc_time: u64,
    interrupt_time: u64,
    clock_interrupts: u32,
    dpc_count: u32,
    dpc_rate: u32,
    idle_state_time: [u64; 3],
    idle_state_transitions: [u64; 3],
    idle_accounting_time: u64,
    parking_status: u32,
    frequency: u32,
    percent_maximum_frequency: u32,
    state_flags: u32,
    utility_base: u64,
    performance_base: u64,
    performance: u64,
    privileged_utility: u64,
    total_idle_time: u64,
    total_idle_transitions: u64,
    performance_limit: u32,
    performance_limit_flags: u32,
    performance_weighted: u64,
}

impl Values {
    /// A soma de um processador num total (o estacionamento e as flags de
    /// estado ficam de fora; as flags de limite, por OR).
    fn add(&mut self, other: &Values) {
        self.idle_time += other.idle_time;
        self.priority_time += other.priority_time;
        self.user_time += other.user_time;
        self.privileged_time += other.privileged_time;
        self.interrupt_count = self.interrupt_count.wrapping_add(other.interrupt_count);
        self.dpc_time += other.dpc_time;
        self.interrupt_time += other.interrupt_time;
        self.clock_interrupts = self.clock_interrupts.wrapping_add(other.clock_interrupts);
        self.dpc_count = self.dpc_count.wrapping_add(other.dpc_count);
        self.dpc_rate = self.dpc_rate.wrapping_add(other.dpc_rate);
        for index in 0..3 {
            self.idle_state_time[index] += other.idle_state_time[index];
            self.idle_state_transitions[index] += other.idle_state_transitions[index];
        }
        self.idle_accounting_time += other.idle_accounting_time;
        self.frequency = self.frequency.wrapping_add(other.frequency);
        self.percent_maximum_frequency = self.percent_maximum_frequency.wrapping_add(other.percent_maximum_frequency);
        self.utility_base += other.utility_base;
        self.performance_base += other.performance_base;
        self.performance += other.performance;
        self.privileged_utility += other.privileged_utility;
        self.total_idle_time += other.total_idle_time;
        self.total_idle_transitions += other.total_idle_transitions;
        self.performance_limit = self.performance_limit.wrapping_add(other.performance_limit);
        self.performance_limit_flags |= other.performance_limit_flags;
        self.performance_weighted += other.performance_weighted;
    }

    /// A média de um total de `count` processadores.
    fn average(&mut self, count: u64, performance: bool, utility: bool) {
        if count <= 1 {
            return;
        }
        for time in [&mut self.idle_time, &mut self.priority_time, &mut self.user_time, &mut self.privileged_time, &mut self.interrupt_time, &mut self.dpc_time, &mut self.idle_accounting_time] {
            *time /= count;
        }
        for time in self.idle_state_time.iter_mut() {
            *time /= count;
        }
        self.frequency /= count as u32;
        self.percent_maximum_frequency /= count as u32;
        if utility {
            self.utility_base /= count;
            self.performance_base /= count;
            self.performance /= count;
            self.privileged_utility /= count;
            self.performance_weighted /= count;
        }
        if performance {
            self.performance_limit /= count as u32;
        }
    }

    fn store(&self, block: &ProcessorInformationCounters) {
        block.idle_time.set(self.idle_time);
        block.priority_time.set(self.priority_time);
        block.user_time.set(self.user_time);
        block.privileged_time.set(self.privileged_time);
        block.interrupt_count.set(self.interrupt_count);
        block.dpc_time.set(self.dpc_time);
        block.interrupt_time.set(self.interrupt_time);
        block.clock_interrupts.set(self.clock_interrupts);
        block.dpc_count.set(self.dpc_count);
        block.dpc_rate.set(self.dpc_rate);
        for index in 0..3 {
            block.idle_state_time[index].set(self.idle_state_time[index]);
            block.idle_state_transitions[index].set(self.idle_state_transitions[index]);
        }
        block.idle_accounting_time.set(self.idle_accounting_time);
        block.parking_status.set(self.parking_status);
        block.frequency.set(self.frequency);
        block.percent_maximum_frequency.set(self.percent_maximum_frequency);
        block.state_flags.set(self.state_flags);
        block.utility_base.set(self.utility_base as u32);
        block.performance_base.set(self.performance_base as u32);
        block.performance.set(self.performance);
        block.privileged_utility.set(self.privileged_utility);
        block.total_idle_time.set(self.total_idle_time);
        block.total_idle_transitions.set(self.total_idle_transitions);
        block.performance_limit.set(self.performance_limit);
        block.performance_limit_flags.set(self.performance_limit_flags);
        block.performance_weighted.set(self.performance_weighted);
    }
}

/// ExpQueryProcessorInformationCounters(Prcb, Idle, Performance, Utility,
/// Counters) do processador `index`.
fn query_processor(index: u32, idle: bool, performance: bool, utility: bool) -> Values {
    let mut values = Values::default();
    let Some(prcb) = pcr::processor_block(index) else { return values };
    let increment = u64::from(clock::MAXIMUM_INCREMENT);
    let (idle_time, kernel_time, user_time) = processor_information::processor_times(index as usize);
    let (idle_time, kernel_time, user_time) = (idle_time as u64, kernel_time as u64, user_time as u64);
    if idle {
        values.idle_time = idle_time;
        values.priority_time = u64::from(prcb.available_time.get()) * increment + idle_time;
        values.privileged_time = kernel_time.saturating_sub(idle_time);
        values.idle_accounting_time = idle_time;
    }
    values.user_time = user_time;
    values.interrupt_count = prcb.interrupt_count.get();
    values.interrupt_time = u64::from(prcb.interrupt_time.get()) * increment;
    values.dpc_count = prcb.dpc_data[0].dpc_count.get();
    values.dpc_rate = prcb.dpc_request_rate.get();
    values.dpc_time = u64::from(prcb.dpc_time.get()) * increment;
    values.clock_interrupts = prcb.clock_interrupts.get();
    values.total_idle_time = values.idle_state_time.iter().sum();
    values.total_idle_transitions = values.idle_state_transitions.iter().sum();
    if performance || utility {
        // PoGetPerfStateAndParkingInfo sem estados de desempenho.
        values.frequency = prcb.m_hz.get();
        values.percent_maximum_frequency = 100;
        values.performance_limit = 100;
    }
    if utility {
        let busy = (kernel_time.saturating_sub(idle_time) + user_time) >> UTILITY_SHIFT;
        let privileged = kernel_time.saturating_sub(idle_time) >> UTILITY_SHIFT;
        let elapsed = (kernel_time + user_time) >> UTILITY_SHIFT;
        values.utility_base = elapsed & 0xFFFF_FFFF;
        values.performance_base = busy & 0xFFFF_FFFF;
        values.performance = busy * 100;
        values.privileged_utility = privileged * 100;
        values.performance_weighted = busy * 100;
    }
    values
}

/// Os blocos e o nome de uma chamada ao PcwAddInstance, em memória que o
/// pcw.sys lê.
struct Scratch {
    block: u64,
    data: u64,
    name: u64,
    text: u64,
}

const NAME_CAPACITY: u64 = 0x40;

impl Scratch {
    fn new() -> Option<Scratch> {
        let block = guest::alloc_bytes(ProcessorInformationCounters::SIZE + 0x10 + UnicodeString::SIZE + NAME_CAPACITY);
        if block == 0 {
            return None;
        }
        let data = block + ProcessorInformationCounters::SIZE;
        let name = data + 0x10;
        Some(Scratch { block, data, name, text: name + UnicodeString::SIZE })
    }

    /// PcwAddInstance(Buffer, Name, Id, 1, {bloco, 0xc8}).
    fn add(&self, buffer: u64, name: &str, id: u32, values: &Values) -> u32 {
        // SAFETY: o bloco de 0xc8 bytes alocado em `new`.
        values.store(unsafe { ProcessorInformationCounters::at(self.block) });
        let units: Vec<u8> = name.encode_utf16().take((NAME_CAPACITY / 2) as usize).flat_map(|unit| unit.to_le_bytes()).collect();
        guest::write_bytes(self.text, &units);
        // SAFETY: o UNICODE_STRING alocado em `new`.
        let string = unsafe { UnicodeString::at(self.name) };
        string.length.set(units.len() as u16);
        string.maximum_length.set(units.len() as u16);
        string.buffer.set(self.text);
        guest::write64(self.data, self.block);
        guest::write64(self.data + 8, ProcessorInformationCounters::SIZE);
        pcw::add_instance(buffer, self.name, id, 1, self.data)
    }

    /// PcwAddInstance com o nome do pedido.
    fn add_named(&self, buffer: u64, name: u64, id: u32, values: &Values) -> u32 {
        // SAFETY: o bloco de 0xc8 bytes alocado em `new`.
        values.store(unsafe { ProcessorInformationCounters::at(self.block) });
        guest::write64(self.data, self.block);
        guest::write64(self.data + 8, ProcessorInformationCounters::SIZE);
        pcw::add_instance(buffer, name, id, 1, self.data)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        guest::free_bytes(self.block);
    }
}

/// O InstanceMask pede uma instância "%u,%u" (o swscanf_s com duas
/// conversões).
fn names_one_processor(mask: u64) -> bool {
    if mask == 0 {
        return false;
    }
    // SAFETY: o PCUNICODE_STRING InstanceMask do pcw.sys.
    let string = unsafe { UnicodeString::at(mask) };
    let (length, buffer) = (string.length.get() as usize & !1, string.buffer.get());
    if buffer == 0 {
        return false;
    }
    let units: Vec<u16> = guest::read_bytes(buffer, length).chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
    let text = String::from_utf16_lossy(&units);
    let text = text.trim_start();
    let digits = |text: &str| text.chars().take_while(char::is_ascii_digit).count();
    let first = digits(text);
    if first == 0 || !text[first..].starts_with(',') {
        return false;
    }
    digits(text[first + 1..].trim_start()) > 0
}

/// ExProcessorCounterSetCallback(Type, Info, Context).
pub fn callback(callback_type: u32, information: &PcwCallbackInformation) -> u32 {
    let (buffer, mask) = match callback_type {
        PCW_CALLBACK_ENUMERATE_INSTANCES => (information.enumerate_instances.buffer.get(), 0),
        PCW_CALLBACK_COLLECT_DATA => (information.collect_data.buffer.get(), information.collect_data.counter_mask.get()),
        _ => return 0,
    };
    let (idle, performance, utility) = (mask & IDLE_COUNTERS != 0, mask & PERFORMANCE_COUNTERS != 0, mask & UTILITY_COUNTERS != 0);
    if callback_type == PCW_CALLBACK_COLLECT_DATA && !FIRST_COLLECT.swap(true, core::sync::atomic::Ordering::AcqRel) {
        crate::debug_print!("[pcw] {}: primeira coleta (contadores {:#x})", NAME, mask);
    }
    let Some(scratch) = Scratch::new() else { return STATUS_INSUFFICIENT_RESOURCES };
    if callback_type == PCW_CALLBACK_COLLECT_DATA && names_one_processor(information.collect_data.instance_mask.get()) {
        let index = information.collect_data.instance_id.get();
        if index as usize >= crate::ntos::ke::smp::online_cpu_count() {
            return STATUS_NOT_FOUND;
        }
        let values = query_processor(index, idle, performance, utility);
        let status = scratch.add_named(buffer, information.collect_data.instance_mask.get(), index, &values);
        return if status & 0x8000_0000 != 0 { status } else { 0 };
    }
    let maximum = processor_group::maximum_processor_count() as u32;
    let nodes = processor_group::number_nodes() as u32;
    let mut total = Values::default();
    let mut processors = 0u64;
    for node in 0..nodes {
        // KeQueryNodeActiveAffinity: o nó único tem todos os ativos.
        let mut affinity = if node == 0 { processor_group::active_mask() } else { 0 };
        let mut node_total = Values::default();
        let mut count = 0u64;
        while affinity != 0 {
            let index = affinity.trailing_zeros();
            affinity &= affinity - 1;
            let values = query_processor(index, idle, performance, utility);
            let status = scratch.add(buffer, &alloc::format!("{},{}", node, count), index, &values);
            if status & 0x8000_0000 != 0 {
                return status;
            }
            node_total.add(&values);
            total.add(&values);
            count += 1;
        }
        if count == 0 {
            continue;
        }
        processors += count;
        node_total.average(count, performance, utility);
        let status = scratch.add(buffer, &alloc::format!("{},_Total", node), maximum + node, &node_total);
        if status & 0x8000_0000 != 0 {
            return status;
        }
    }
    total.average(processors, performance, utility);
    let status = scratch.add(buffer, "_Total", nodes + maximum, &total);
    if status & 0x8000_0000 != 0 { status } else { 0 }
}

fn callback_routine(call: &Call) -> Result<u64, KernelError> {
    if call.arg(2) == 0 {
        return Ok(0);
    }
    // SAFETY: o PCW_CALLBACK_INFORMATION que o pcw.sys passa.
    Ok(callback(call.arg(1) as u32, unsafe { PcwCallbackInformation::at(call.arg(2)) }) as u64)
}

/// A rotina entregue ao pcw.sys no registro do conjunto.
pub const ROUTINES: &[Routine] = &[Routine { name: "ExProcessorCounterSetCallback", handler: callback_routine }];
