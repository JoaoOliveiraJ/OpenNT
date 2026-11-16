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
//! - o endereço é o do modo de destino físico do xAPIC, o mesmo dos APICs
//!   que a HAL programa (`interrupt_targets`): 0xFEE00000 com o APIC ID do
//!   destino nos bits 19:12, sem redirecionamento (RH = 0, DM = 0);
//! - o dado é o vetor com entrega fixa e disparo por borda (bits 10:8 = 0,
//!   bit 15 = 0).
//! As mensagens vão ao processador 0 (o BSP), que despacha os vetores de
//! dispositivo; o EOI vai ao APIC local (os trampolins mandam o EOI dos
//! vetores 0x40 em diante a ele).

use alloc::vec::Vec;

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

/// Dado da mensagem: o vetor, entrega fixa, borda.
pub fn message_data(vector: u32) -> u32 {
    vector & 0xFF
}
