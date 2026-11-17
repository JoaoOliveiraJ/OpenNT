//! O estado estendido do processador (XSAVE) de cada thread e o dos drivers.
//!
//! Cada KTHREAD tem a área de XSAVE dela em KTHREAD.StateSaveArea, com
//! KiXSaveAreaLength bytes e 64 de alinhamento: numa thread com pilha própria
//! é o topo da pilha de kernel (`mm::kernel_stack`), como no
//! KiInitializeContextThread; as threads que rodam na pilha de boot usam a
//! área do despachante da CPU 0. A área nova sai do KiInitializeContextThread:
//! zerada; numa thread de usuário, palavra de controle x87 0x27F e XSTATE_BV
//! com o x87; com a compactação, XCOMP_BV = bit 63 | x87 | SSE. O
//! KTHREAD.NpxState é o do KiSetSwitchingNpxState: os recursos habilitados
//! sem x87 e SSE, mais o x87 numa thread de usuário.
//!
//! O salvamento é ansioso, como no SwapContext: o estado estendido sai da CPU
//! sempre que a thread a deixa e volta quando ela a retoma (as primitivas de
//! `hal::amd64::extended_state`). Os pontos de troca do OpenNT são o fim e o
//! começo de cada intervalo de usuário e de cada retomada no kernel
//! (`hal::amd64::usermode`) e as trocas entre o despachante e as threads de
//! kernel (`ke::context_switch`); o despachante de cada CPU tem a área dele.
//! O x87 e o SSE seguem no CONTEXT do intervalo e nos quadros de troca; a
//! área leva o resto (a metade alta dos YMM, o AVX-512).
//!
//! Os drivers salvam e restauram o estado corrente pelo
//! KeSaveExtendedProcessorState e pelo KeRestoreExtendedProcessorState: o
//! XSTATE_SAVE do chamador entra na lista KTHREAD.XStateSave, com a área
//! alocada (pool NonPagedPoolNx, tag 'XSav') ou, em DISPATCH_LEVEL, a da
//! KPRCB (KPRCB.ExtendedState). Enquanto a lista não está vazia, o estado de
//! usuário da thread é o da área mais antiga dela ([`user_state_area`]).

use core::sync::atomic::{AtomicU64, Ordering};

use super::xsave::{self, feature, LEGACY_SIZE};
use super::{bugcheck, critical_region, irql, pcr};
use crate::hal::amd64::extended_state;
use crate::ntos::inc::status::{STATUS_INSUFFICIENT_RESOURCES, STATUS_SUCCESS};
use crate::ntos::inc::types::{Kthread, NtStruct, XstateContext, XstateSave};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::memory_map::MAX_CPUS;
use crate::ntos::ps::process;

/// INVALID_EXTENDED_PROCESSOR_STATE.
const INVALID_EXTENDED_PROCESSOR_STATE: u32 = 0x131;
/// Deslocamentos numa área de XSAVE.
pub const XSTATE_BV: u64 = 0x200;
pub const XCOMP_BV: u64 = 0x208;
/// A palavra de controle x87 de uma thread de usuário nova.
const INITIAL_CONTROL_WORD: u16 = 0x27F;

/// A área do despachante de cada CPU (o contexto que retoma as threads).
static DISPATCHER_AREAS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// O despachante da CPU `processor` (zero antes da configuração dela).
pub fn dispatcher_area(processor: usize) -> u64 {
    DISPATCHER_AREAS.get(processor).map_or(0, |cell| cell.load(Ordering::Acquire))
}

/// A área da thread `thread` (KTHREAD.StateSaveArea), zero sem thread.
pub fn thread_area(thread: u64) -> u64 {
    if thread == 0 {
        return 0;
    }
    // SAFETY: KTHREAD viva do chamador.
    unsafe { Kthread::at(thread) }.state_save_area.get()
}

/// Inicializa uma área nova como o KiInitializeContextThread.
pub fn initialize_area(area: u64, user: bool) {
    let length = xsave::xsave_area_length() as usize;
    guest::write_bytes(area, &alloc::vec![0; length]);
    if user {
        guest::write16(area, INITIAL_CONTROL_WORD);
        if crate::ntos::ke::processor_identity::feature_bits() & crate::ntos::ke::processor_identity::kf::XSTATE != 0 {
            guest::write64(area + XSTATE_BV, feature::LEGACY_FLOATING_POINT);
        }
    }
    if xsave::enabled_features() != 0 && xsave::compaction() {
        guest::write64(area + XCOMP_BV, feature::COMPACTED_FORMAT | feature::LEGACY);
    }
}

/// KiSetSwitchingNpxState: os recursos habilitados sem x87 e SSE, mais o x87
/// numa thread de usuário.
pub fn switching_npx_state(user: bool) -> u64 {
    (xsave::enabled_features() & !feature::LEGACY) | user as u64
}

/// A área de XSAVE no topo de uma pilha de kernel de topo `base`.
pub fn stack_area(base: u64) -> u64 {
    (base - xsave::xsave_area_length() as u64) & !0x3F
}

/// Publica a área e o NpxState de uma KTHREAD nova (`area` zero: a pilha de
/// boot, que usa a área do despachante da CPU 0).
pub fn initialize_thread(thread: &Kthread, area: u64) {
    let area = if area != 0 {
        initialize_area(area, false);
        area
    } else {
        dispatcher_area(0)
    };
    thread.state_save_area.set(area);
    thread.npx_state.set(switching_npx_state(false));
}

/// A thread passa a ter contexto de usuário: a área e o NpxState de uma
/// thread de usuário nova.
pub fn initialize_user_thread(thread: u64) {
    if thread == 0 {
        return;
    }
    // SAFETY: KTHREAD viva, ainda sem executar no anel 3.
    let kthread = unsafe { Kthread::at(thread) };
    let area = kthread.state_save_area.get();
    if area == 0 || area == dispatcher_area(0) {
        return;
    }
    initialize_area(area, true);
    kthread.npx_state.set(switching_npx_state(true));
}

/// A configuração da CPU corrente, depois do KiEnableXSave: as primitivas
/// da troca (no BSP), a KPRCB.ExtendedState e a área do despachante.
pub fn initialize_processor() {
    use crate::ntos::ke::processor_identity::{self, kf};
    let prcb = &pcr::current().prcb;
    let number = prcb.number.get() as usize;
    if number == 0 {
        let bits = processor_identity::feature_bits();
        let instruction = if bits & kf::XSAVES != 0 {
            extended_state::kind::XSAVES
        } else if bits & kf::XSAVEOPT != 0 {
            extended_state::kind::XSAVEOPT
        } else if bits & kf::XSTATE != 0 {
            extended_state::kind::XSAVE
        } else {
            extended_state::kind::NONE
        };
        extended_state::configure(instruction, switching_npx_state(false));
    }
    if prcb.extended_state.get() == 0 {
        let area = guest::alloc_aligned(xsave::xstate_length() as u64, 64, true);
        prcb.extended_state.set(area);
    }
    if let Some(cell) = DISPATCHER_AREAS.get(number) {
        if cell.load(Ordering::Acquire) == 0 {
            let area = guest::alloc_aligned(xsave::xsave_area_length() as u64, 64, true);
            if area != 0 {
                initialize_area(area, false);
                cell.store(area, Ordering::Release);
            }
        }
    }
}

/// Salva o estado estendido da CPU em `area` (a primitiva da troca).
pub fn save_current(area: u64) {
    // SAFETY: as áreas das threads e dos despachantes são vivas, alinhadas e
    // inicializadas para a instrução da troca.
    unsafe { extended_state::save(area) }
}

/// Recarrega o estado estendido de `area` (a primitiva da troca).
pub fn restore_current(area: u64) {
    // SAFETY: como em `save_current`.
    unsafe { extended_state::restore(area) }
}

/// A área com o estado de usuário da thread: a do XSTATE_SAVE mais antigo
/// da lista KTHREAD.XStateSave, quando há um com área (o estado que o driver
/// guardou ao salvar), senão KTHREAD.StateSaveArea. É o que o
/// KeContextFromKframes e o KxContextToKframes consultam.
pub fn user_state_area(thread: u64) -> u64 {
    if thread == 0 {
        return 0;
    }
    // SAFETY: KTHREAD viva do chamador.
    let kthread = unsafe { Kthread::at(thread) };
    let mut save = kthread.x_state_save.get();
    if save == 0 {
        return kthread.state_save_area.get();
    }
    loop {
        // SAFETY: os XSTATE_SAVE da lista são dos drivers e vivos até o
        // KeRestoreExtendedProcessorState que os tira dela.
        let previous = unsafe { XstateSave::at(save) }.prev.get();
        if previous == 0 {
            break;
        }
        save = previous;
    }
    // SAFETY: o XSTATE_SAVE mais antigo da lista.
    let area = unsafe { XstateSave::at(save) }.x_state_context.area.get();
    if area != 0 { area } else { kthread.state_save_area.get() }
}

/// O deslocamento de cada recurso numa área de origem pelo XCOMP_BV dela
/// (compactado) ou pelo deslocamento padrão.
fn copy_feature(destination: u64, destination_offset: u64, source: u64, source_offset: u64, size: u32) {
    let bytes = guest::read_bytes(source + source_offset, size as usize);
    guest::write_bytes(destination + destination_offset, &bytes);
}

/// KiCopyXStateArea(Destination, Mask, Source): os recursos de `mask`
/// presentes na origem vão ao destino, nos deslocamentos de
/// XState.Features; XSTATE_BV do destino atualizado nos bits da máscara e,
/// com a compactação, XCOMP_BV = bit 63 | EnabledFeatures. As duas áreas
/// são bases de XSAVE (o cabeçalho em +0x200); sem origem (zero), os
/// recursos da máscara ficam no estado inicial.
pub fn copy_area(destination: u64, mask: u64, source: u64) {
    if mask == 0 {
        return;
    }
    let config = xsave::configuration();
    // Sem área de origem (uma thread sem KTHREAD), os recursos ficam no
    // estado inicial.
    let present = if source == 0 { 0 } else { guest::read64(source + XSTATE_BV) & config.enabled_features.get() & mask };
    let kept = guest::read64(destination + XSTATE_BV) & !mask;
    guest::write64(destination + XSTATE_BV, kept | present);
    if present & feature::LEGACY_SSE != 0 {
        guest::write32(destination + 0x18, guest::read32(source + 0x18));
    }
    if present == 0 {
        if xsave::compaction() {
            guest::write64(destination + XCOMP_BV, config.enabled_features.get() | feature::COMPACTED_FORMAT);
        }
        return;
    }
    if xsave::compaction() {
        guest::write64(destination + XCOMP_BV, config.enabled_features.get() | feature::COMPACTED_FORMAT);
        let source_mask = guest::read64(source + XCOMP_BV);
        if present & feature::LEGACY_FLOATING_POINT != 0 {
            copy_feature(destination, 0, source, 0, 0xA0);
        }
        if present & feature::LEGACY_SSE != 0 {
            copy_feature(destination, 0xA0, source, 0xA0, 0x100);
        }
        let aligned = config.aligned_features.get();
        let mut offset = xsave::LEGACY_AND_HEADER;
        for index in 2..64usize {
            let bit = 1u64 << index;
            if source_mask & bit == 0 {
                continue;
            }
            if aligned & bit != 0 {
                offset = (offset + 0x3F) & !0x3F;
            }
            let size = config.features[index].size.get();
            if present & bit != 0 {
                copy_feature(destination, config.features[index].offset.get() as u64, source, offset as u64, size);
            }
            offset += size;
        }
    } else {
        for index in 0..64usize {
            if present & (1u64 << index) != 0 {
                let offset = config.features[index].offset.get() as u64;
                copy_feature(destination, offset, source, offset, config.features[index].size.get());
            }
        }
    }
}

/// Os bytes do recurso `index` numa área de XSAVE, pelo XCOMP_BV dela
/// (compactada) ou pelo deslocamento padrão; zeros quando o XSTATE_BV diz
/// que o recurso está no estado inicial. Nenhum, se o recurso não está
/// habilitado.
pub fn feature_bytes(area: u64, index: usize) -> Option<alloc::vec::Vec<u8>> {
    let config = xsave::configuration();
    let bit = 1u64 << index;
    if area == 0 || index < 2 || index >= 64 || config.enabled_features.get() & bit == 0 {
        return None;
    }
    let size = config.features[index].size.get() as usize;
    let compacted = guest::read64(area + XCOMP_BV);
    if guest::read64(area + XSTATE_BV) & bit == 0 || (compacted & feature::COMPACTED_FORMAT != 0 && compacted & bit == 0) {
        return Some(alloc::vec![0; size]);
    }
    let offset = if compacted & feature::COMPACTED_FORMAT != 0 {
        let aligned = config.aligned_features.get();
        let mut offset = xsave::LEGACY_AND_HEADER;
        for earlier in 2..=index {
            let mask = 1u64 << earlier;
            if compacted & mask == 0 {
                continue;
            }
            if aligned & mask != 0 {
                offset = (offset + 0x3F) & !0x3F;
            }
            if earlier < index {
                offset += config.features[earlier].size.get();
            }
        }
        offset
    } else {
        config.features[index].offset.get()
    };
    Some(guest::read_bytes(area + offset as u64, size))
}

// ---- KeSaveExtendedProcessorState / KeRestoreExtendedProcessorState --------------

fn xstate_supported() -> bool {
    use crate::ntos::ke::processor_identity::{self, kf};
    processor_identity::feature_bits() & kf::XSTATE != 0
}

fn invalid_mask(mask: u64) -> ! {
    bugcheck::bug_check_ex(INVALID_EXTENDED_PROCESSOR_STATE, 0, mask & 0xFFFF_FFFF, mask >> 32, 0)
}

/// O nível de um XSTATE_SAVE: zero em PASSIVE_LEVEL fora de uma APC de
/// kernel, senão IRQL + 1.
fn save_level(thread: &Kthread, level: u8) -> u8 {
    if level == 0 && thread.apc_state.in_progress_flags.get() & 1 == 0 {
        0
    } else {
        level + 1
    }
}

/// KeAllocateXStateContext: pool de max(0x240, Length) + 63 bytes; Area é o
/// bloco alinhado a 64, com o cabeçalho zerado.
fn allocate_context(context: &XstateContext, length: u32) -> u32 {
    let size = length.max(xsave::LEGACY_AND_HEADER);
    let buffer = guest::alloc_aligned(size as u64 + 0x3F, 16, false);
    context.buffer.set(buffer);
    if buffer == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let area = (buffer + 0x3F) & !0x3F;
    context.length.set(size);
    context.area.set(area);
    guest::write_bytes(area + LEGACY_SIZE as u64, &[0; xsave::HEADER_SIZE as usize]);
    STATUS_SUCCESS
}

/// KeFreeXStateContext.
fn free_context(context: &XstateContext) {
    let buffer = context.buffer.get();
    if buffer == 0 {
        return;
    }
    guest::free_bytes(buffer);
    context.mask.set(0);
    context.length.set(0);
    context.buffer.set(0);
    context.area.set(0);
}

/// KeSaveExtendedProcessorState(Mask, XStateSave): a máscara precisa caber
/// nos recursos habilitados (sem XSTATE, no x87 e SSE); senão
/// INVALID_EXTENDED_PROCESSOR_STATE.
pub fn save(mask: u64, state: u64) -> u32 {
    let outside = if xstate_supported() { mask & !xsave::enabled_features() } else { mask & !feature::LEGACY };
    if outside != 0 {
        invalid_mask(mask);
    }
    save_extended_and_supervisor_state(mask, state)
}

/// KeSaveExtendedAndSupervisorState(Mask, XStateSave): salva todos os
/// recursos habilitados menos o x87 e o SSE (a máscara só é conferida) e
/// empilha o XSTATE_SAVE em KTHREAD.XStateSave.
fn save_extended_and_supervisor_state(mask: u64, state: u64) -> u32 {
    let level = irql::get_irql();
    let current = process::get_current_thread();
    if level > irql::DISPATCH_LEVEL {
        bugcheck::bug_check_ex(INVALID_EXTENDED_PROCESSOR_STATE, 1, level as u64, 0, 0);
    }
    let supported = xstate_supported();
    let compaction = xsave::compaction();
    let enabled = xsave::enabled_features();
    let allowed = if !supported {
        feature::LEGACY
    } else if level == irql::DISPATCH_LEVEL && compaction {
        enabled | xsave::enabled_supervisor_features()
    } else {
        enabled
    };
    if mask & !allowed != 0 {
        invalid_mask(mask);
    }
    // SAFETY: a KTHREAD corrente e o XSTATE_SAVE do chamador.
    let (thread, save) = unsafe { (Kthread::at(current), XstateSave::at(state)) };
    let save_level = save_level(thread, level);
    let features = (enabled | mask) & !feature::LEGACY;
    let previous = thread.x_state_save.get();
    if previous != 0 {
        // SAFETY: o topo da lista da thread.
        let previous_level = unsafe { XstateSave::at(previous) }.level.get();
        if previous_level > save_level {
            bugcheck::bug_check_ex(INVALID_EXTENDED_PROCESSOR_STATE, 2, previous_level as u64, save_level as u64, 0);
        }
    }
    let context = &save.x_state_context;
    let prcb = &pcr::current().prcb;
    if features == 0 {
        context.length.set(0);
        context.buffer.set(0);
        context.area.set(0);
    } else if level < irql::DISPATCH_LEVEL {
        let status = allocate_context(context, xsave::configuration().size.get());
        if status != STATUS_SUCCESS {
            return status;
        }
    } else {
        // SAFETY: o topo da lista da thread, quando existe.
        let nested_same_level = previous != 0 && unsafe { XstateSave::at(previous) }.level.get() == save_level;
        if nested_same_level {
            let config = xsave::configuration();
            let length = if compaction { config.all_feature_size.get() } else { config.size.get() };
            let status = allocate_context(context, length);
            if status != STATUS_SUCCESS {
                return status;
            }
        } else {
            let area = prcb.extended_state.get();
            guest::write_bytes(area + LEGACY_SIZE as u64, &[0; xsave::HEADER_SIZE as usize]);
            context.length.set(xsave::xstate_length());
            context.buffer.set(0);
            context.area.set(area);
        }
    }
    save.thread.set(current);
    save.level.set(save_level);
    context.mask.set(features);
    if level < irql::APC_LEVEL {
        let _ = critical_region::enter_guarded();
    }
    save.prev.set(thread.x_state_save.get());
    if features != 0 && supported {
        let area = context.area.get();
        // SAFETY: a área do XSTATE_SAVE, alinhada e com o cabeçalho zerado.
        unsafe {
            if level == irql::DISPATCH_LEVEL && compaction {
                extended_state::rtl_xrestore(area, 0);
                guest::write64(area + XCOMP_BV, features);
                extended_state::rtl_xsave_s(area, features, true);
            } else {
                extended_state::rtl_xsave(area, features, compaction);
            }
        }
    }
    thread.x_state_save.set(state);
    if level < irql::APC_LEVEL {
        let _ = critical_region::leave_guarded();
    }
    STATUS_SUCCESS
}

/// KeRestoreExtendedProcessorState(XStateSave) (KeRestoreExtendedAndSupervisorState):
/// o XSTATE_SAVE precisa ser o topo da lista desta thread, no mesmo nível;
/// sai da lista, o estado volta à CPU e a área alocada volta ao pool.
pub fn restore(state: u64) {
    let level = irql::get_irql();
    let current = process::get_current_thread();
    if level > irql::DISPATCH_LEVEL {
        bugcheck::bug_check_ex(INVALID_EXTENDED_PROCESSOR_STATE, 1, level as u64, 0, 0);
    }
    // SAFETY: a KTHREAD corrente e o XSTATE_SAVE preenchido pelo save.
    let (thread, save) = unsafe { (Kthread::at(current), XstateSave::at(state)) };
    let expected = save_level(thread, level);
    if save.level.get() != expected {
        bugcheck::bug_check_ex(INVALID_EXTENDED_PROCESSOR_STATE, 4, save.level.get() as u64, expected as u64, 0);
    }
    if save.thread.get() != current {
        bugcheck::bug_check_ex(INVALID_EXTENDED_PROCESSOR_STATE, 3, save.thread.get(), current, 0);
    }
    if level < irql::APC_LEVEL {
        let _ = critical_region::enter_guarded();
    }
    thread.x_state_save.set(save.prev.get());
    let context = &save.x_state_context;
    let mask = context.mask.get();
    let supported = xstate_supported();
    let compaction = xsave::compaction();
    let allowed = if !supported {
        feature::LEGACY
    } else if level == irql::DISPATCH_LEVEL && compaction {
        xsave::enabled_features() | xsave::enabled_supervisor_features()
    } else {
        xsave::enabled_features()
    };
    if mask & !allowed != 0 {
        invalid_mask(mask);
    }
    if mask != 0 && supported {
        let area = context.area.get();
        // SAFETY: a área que o save gravou.
        unsafe {
            if level == irql::DISPATCH_LEVEL && compaction {
                extended_state::rtl_xrestore_s(area, mask, true);
            } else {
                extended_state::rtl_xrestore(area, mask);
            }
        }
    }
    if level < irql::APC_LEVEL {
        let _ = critical_region::leave_guarded();
    }
    if context.buffer.get() != 0 {
        free_context(context);
    }
}
