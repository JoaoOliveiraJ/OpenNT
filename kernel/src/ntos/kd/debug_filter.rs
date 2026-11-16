//! Filtro de componentes do DbgPrintEx — as máscaras Kd_<COMPONENTE>_Mask
//! (KdComponentTable, ntoskrnl 19041 .data RVA 0x7660, 0x9C entradas) e
//! Kd_WIN2000_Mask, com NtSetDebugFilterState 0x7a5810 (DbgSetDebugFilterState
//! 0x3b6de0 é só `call NtSetDebugFilterState`).
//!
//! Valores iniciais conferidos com pefile na imagem real: as 0x9C máscaras de
//! componente valem 0 e Kd_WIN2000_Mask vale 1. (O KdInitSystem do NT ainda
//! sobrepõe valores da chave "Debug Print Filter"; o OpenNT não a lê.)
//!
//! NtSetDebugFilterState(ComponentId, Level, State):
//! - PreviousMode != KernelMode exige SeDebugPrivilege (senão
//!   STATUS_ACCESS_DENIED);
//! - ComponentId < 0x9C escolhe KdComponentTable[ComponentId]; -1 escolhe
//!   Kd_WIN2000_Mask; qualquer outro cai em KdComponentTable[101]
//!   (DPFLTR_DEFAULT_ID);
//! - Level <= 31 vira o bit 1 << Level, acima disso já é a máscara;
//! - State TRUE liga os bits, FALSE desliga; sempre STATUS_SUCCESS.
//!
//! A consulta (NtQueryDebugFilterState, KdpPrint) escolhe a máscara de outro
//! jeito: um ComponentId fora da tabela, o -1 inclusive, vai para
//! DPFLTR_DEFAULT_ID com o nível 3 (`print_enabled`).

use core::sync::atomic::{AtomicU32, Ordering};

use crate::ntos::ps::previous_mode;
use crate::ntos::se::privilege;

const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
/// Número de entradas de KdComponentTable (DPFLTR_ENDOFTABLE_ID + 1).
pub const COMPONENT_COUNT: usize = 0x9C;
/// DPFLTR_DEFAULT_ID.
pub const DEFAULT_COMPONENT: usize = 101;
/// ComponentId que seleciona Kd_WIN2000_Mask.
pub const WIN2000_COMPONENT: u32 = 0xFFFF_FFFF;

static COMPONENT_MASKS: [AtomicU32; COMPONENT_COUNT] = [const { AtomicU32::new(0) }; COMPONENT_COUNT];
static WIN2000_MASK: AtomicU32 = AtomicU32::new(1);

fn mask_cell(component: u32) -> &'static AtomicU32 {
    if (component as usize) < COMPONENT_COUNT {
        &COMPONENT_MASKS[component as usize]
    } else if component == WIN2000_COMPONENT {
        &WIN2000_MASK
    } else {
        &COMPONENT_MASKS[DEFAULT_COMPONENT]
    }
}

/// Level 0..31 é um índice de bit; acima disso, a própria máscara.
fn level_mask(level: u32) -> u32 {
    if level <= 31 { 1 << level } else { level }
}

/// NtSetDebugFilterState / DbgSetDebugFilterState.
pub fn set_filter_state(component: u32, level: u32, state: bool) -> u32 {
    let mode = previous_mode::get().unwrap_or(0);
    // SeDebugPrivilege.
    if mode != 0 && !privilege::single_privilege_check(20, mode as u32) {
        return STATUS_ACCESS_DENIED;
    }
    let mask = level_mask(level);
    let cell = mask_cell(component);
    if state {
        cell.fetch_or(mask, Ordering::AcqRel);
    } else {
        cell.fetch_and(!mask, Ordering::AcqRel);
    }
    0
}

/// Valor atual da máscara de um componente (as mesmas regras de seleção).
pub fn component_mask(component: u32) -> u32 {
    mask_cell(component).load(Ordering::Acquire)
}

/// O filtro do KdpPrint (0x9b96c8) e do NtQueryDebugFilterState
/// (0x364540): um ComponentId abaixo de 0x9C usa a própria máscara com o
/// Level pedido; qualquer outro (o -1 do DbgPrint inclusive) usa a de
/// DPFLTR_DEFAULT_ID com o nível 3. O texto passa quando Kd_WIN2000_Mask ou
/// a máscara do componente tem o bit do nível.
pub fn print_enabled(component: u32, level: u32) -> bool {
    let (index, level) = if (component as usize) < COMPONENT_COUNT { (component as usize, level) } else { (DEFAULT_COMPONENT, 3) };
    let mask = level_mask(level);
    WIN2000_MASK.load(Ordering::Acquire) & mask != 0 || COMPONENT_MASKS[index].load(Ordering::Acquire) & mask != 0
}

/// NtQueryDebugFilterState(ComponentId, Level): TRUE ou FALSE pelo filtro,
/// sem outro status. O DbgPrintEx da ntdll pergunta antes de formatar o
/// texto; um status de erro valeria como TRUE e todo texto iria ao
/// `int 0x2D`.
fn nt_query_debug_filter_state(component: u64, level: u64, _: u64, _: u64, _rsp: u64) -> Result<u32, crate::rtl::KernelError> {
    Ok(print_enabled(component as u32, level as u32) as u32)
}

/// Registra o serviço NtQueryDebugFilterState.
pub fn register_user_services() {
    crate::ntos::ps::user::state::register_handler("NtQueryDebugFilterState", nt_query_debug_filter_state);
}
