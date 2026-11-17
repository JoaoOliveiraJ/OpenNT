//! Interrupções por mensagem (MSI e MSI-X) na HAL.
//!
//! Uma interrupção por mensagem não passa por um controlador de linhas: o
//! dispositivo grava um DWORD (o dado da mensagem) num endereço da janela
//! do APIC (0xFEE00000-0xFEEFFFFF), e o APIC local do destino recebe o
//! vetor que o dado leva, como uma interrupção de borda. A HAL é dona dos
//! vetores do IDT que essas mensagens usam e do formato do endereço e do
//! dado:
//! - os vetores saem da faixa de dispositivos 0x50-0xCF (acima do timer do
//!   APIC local, 0x40, e dos vetores das linhas do 8259, 0x20-0x2F), um
//!   bloco contíguo e alinhado ao tamanho para o MSI de várias mensagens
//!   (o dispositivo troca os bits baixos do dado pelo número da mensagem);
//!   o IRQL de um vetor é a classe de prioridade dele (vetor >> 4, o
//!   HalConvertDeviceIdtToIrql), e o CR8 do processador segura a entrega
//!   enquanto o IRQL corrente for igual ou maior;
//! - o endereço e o dado são os do HalpApicGenerateMessage do ntoskrnl
//!   19041 para um destino físico do xAPIC (o tipo 4 do
//!   HalpInterruptTargets, o modo que a HAL programa, `interrupt_targets`):
//!   o endereço é 0xFEE00000 com o APIC ID do destino nos bits 19:12, sem
//!   redirecionamento nem destino lógico (RH = 0, DM = 0); o dado é o
//!   vetor com entrega de menor prioridade (bits 10:8 = 001, do bit 1 do
//!   pedido 0x12 que o HalpInterruptGenerateMessage monta), Level = 1
//!   (bit 14) e disparo por borda (bit 15 = 0). Com um destino físico só, a
//!   menor prioridade entrega no próprio destino.
//! As mensagens vão ao processador 0 (o BSP), que despacha os vetores de
//! dispositivo; o EOI vai ao APIC local (os trampolins mandam o EOI dos
//! vetores 0x30 em diante a ele; só 0x20-0x2F são do 8259).
//!
//! Quando o árbitro de IRQ do acpi.sys atribui as mensagens (a raiz ACPI),
//! ele mesmo grava os dados de conexão do PDO (InterruptTypeMessageRequest)
//! e pede à HAL, pelo HalAddInterruptRemapping da HalPrivateDispatchTable
//! (o IrtRemapNewMsiAssignments), o endereço e o dado de cada mensagem:
//! [`add_interrupt_remapping`].

use alloc::vec::Vec;

use crate::ntos::inc::types::{InterruptConnectionType, InterruptVectorData, NtStruct};
use crate::ntos::ke::processor_topology;
use crate::rtl::SpinLock;

/// Faixa de vetores das mensagens.
pub const FIRST_VECTOR: u32 = 0x50;
pub const LAST_VECTOR: u32 = 0xCF;

/// Base da janela de mensagens do APIC (MSI address, bits 31:20 = 0xFEE).
const MESSAGE_ADDRESS_BASE: u64 = 0xFEE0_0000;
const DESTINATION_SHIFT: u32 = 12;

/// Blocos alocados: (primeiro vetor, quantidade).
static ALLOCATED: SpinLock<Vec<(u32, u32)>> = SpinLock::new(Vec::new());

fn in_use(vector: u32, allocated: &[(u32, u32)]) -> bool {
    allocated.iter().any(|&(base, count)| (base..base + count).contains(&vector)) || crate::ntos::ke::interrupt_object::is_vector_connected(vector)
}

/// Aloca `count` vetores contíguos, alinhados a `count` arredondado para
/// potência de dois (o MSI de várias mensagens). None = faixa esgotada.
pub fn allocate_vectors(count: u32) -> Option<u32> {
    if count == 0 || count > 32 {
        return None;
    }
    let alignment = count.next_power_of_two();
    let mut allocated = ALLOCATED.lock();
    let mut base = FIRST_VECTOR.div_ceil(alignment) * alignment;
    while base + count - 1 <= LAST_VECTOR {
        if !(base..base + count).any(|vector| in_use(vector, &allocated)) {
            allocated.push((base, count));
            return Some(base);
        }
        base += alignment;
    }
    None
}

/// Devolve o bloco que começa em `base`.
pub fn release_vectors(base: u32) {
    ALLOCATED.lock().retain(|&(first, _)| first != base);
}

/// O vetor pertence a um bloco de mensagens alocado.
pub fn is_message_vector(vector: u32) -> bool {
    ALLOCATED.lock().iter().any(|&(base, count)| (base..base + count).contains(&vector))
}

/// O IRQL de um vetor de mensagem (a classe de prioridade).
pub fn vector_irql(vector: u32) -> u8 {
    super::interrupt_targets::device_idt_to_irql(vector)
}

/// O processador que recebe as mensagens (o índice do NT) e o APIC ID dele.
pub fn target_processor() -> (u32, u32) {
    (0, processor_topology::processor_apic_ids().first().copied().unwrap_or(0))
}

/// Endereço da mensagem para o APIC `apic_id` (modo físico).
pub fn message_address(apic_id: u32) -> u64 {
    MESSAGE_ADDRESS_BASE | ((apic_id as u64 & 0xFF) << DESTINATION_SHIFT)
}

/// Dado da mensagem: entrega de menor prioridade (bits 10:8 = 001).
const DATA_LOWEST_PRIORITY: u32 = 1 << 8;
/// Dado da mensagem: Level = 1 (bit 14).
const DATA_LEVEL_ASSERT: u32 = 1 << 14;

/// Dado da mensagem: o vetor, menor prioridade, Level = 1, borda.
pub fn message_data(vector: u32) -> u32 {
    (vector & 0xFF) | DATA_LOWEST_PRIORITY | DATA_LEVEL_ASSERT
}

const STATUS_SUCCESS: i32 = 0;
const STATUS_UNSUCCESSFUL: i32 = 0xC000_0001_u32 as i32;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000D_u32 as i32;

/// HalpInterruptDestinationToTarget no modo físico: o destino de um
/// GROUP_AFFINITY é o APIC ID do processador do bit mais alto da máscara
/// (cada processador da máscara sobrescreve o destino anterior); None se a
/// máscara não tem processador iniciado.
fn physical_destination(mask: u64, group: u16) -> Option<u32> {
    if group != 0 {
        return None;
    }
    let apic_ids = processor_topology::processor_apic_ids();
    (0..64u32).rev().filter(|&index| mask & (1u64 << index) != 0).find_map(|index| apic_ids.get(index as usize).copied().filter(|&id| id != u32::MAX))
}

/// HaliAddInterruptRemapping(Bus, Slot, Descriptor, Flags, VectorData,
/// Count) do ntoskrnl 19041, nesta HAL sem IOMMU nem hipervisor: limpa o
/// FlagHalInternal do IntRemapInfo de cada entrada e segue o
/// HalpInterruptRemap pelo tipo da primeira:
/// - InterruptTypeMessageRequest: o HalpPopulateMsiMessages, que dá a cada
///   entrada o endereço e o dado do HalpInterruptGenerateMessage (o destino
///   é o da afinidade da primeira entrada, o vetor é o de cada uma) no
///   IntRemapInfo.u.Msi;
/// - InterruptTypeControllerInput: sem tabela de remapeamento, nada a
///   gravar;
/// - os demais tipos: STATUS_UNSUCCESSFUL.
pub fn add_interrupt_remapping(vector_data: u64, count: u32) -> i32 {
    if count == 0 || vector_data == 0 {
        return STATUS_SUCCESS;
    }
    // SAFETY: o chamador passa `count` INTERRUPT_VECTOR_DATA contíguos.
    let entry = |index: u32| unsafe { InterruptVectorData::at(vector_data + index as u64 * InterruptVectorData::SIZE) };
    for index in 0..count {
        entry(index).int_remap_info.set_flag_hal_internal(0);
    }
    let first = entry(0);
    match first.type_.get() {
        InterruptConnectionType::INTERRUPT_TYPE_CONTROLLER_INPUT => STATUS_SUCCESS,
        InterruptConnectionType::INTERRUPT_TYPE_MESSAGE_REQUEST => {
            let Some(apic_id) = physical_destination(first.target_processors.mask.get(), first.target_processors.group.get()) else { return STATUS_INVALID_PARAMETER };
            let address = message_address(apic_id);
            for index in 0..count {
                let current = entry(index);
                let msi = &current.int_remap_info.u.msi;
                msi.message_address_high.set((address >> 32) as u32);
                msi.message_address_low.set(address as u32);
                msi.message_data.set(message_data(current.vector.get()) as u16);
                msi.reserved.set(0);
            }
            STATUS_SUCCESS
        }
        _ => STATUS_UNSUCCESSFUL,
    }
}
