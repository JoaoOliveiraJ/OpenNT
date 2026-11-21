//! Gerência de energia dos processadores (PPM) vista pelos drivers: o aviso
//! de buffering de mídia (PoNotifyMediaBuffering) e a consulta de
//! ociosidade de uma CPU (PoCpuIdledSinceLastCallImprecise).
//!
//! ntoskrnl 19041:
//! - PoNotifyMediaBuffering(Engaged) 0x36c240: sob a trava do
//!   PpmMediaBufferingWork (já em DISPATCH_LEVEL) grava o pedido e, se o
//!   trabalho não está na fila, marca e enfileira o work item
//!   (ExQueueWorkItem, prioridade da thread corrente + 1 até 31, ao menos 16
//!   quando desengatado). O PpmMediaBufferingWorker (0x36bf90) repete até o
//!   estado aplicado alcançar o pedido: aplica, avisa o ETW e reavalia a
//!   política de desempenho (PpmPerfPolicyLock); quando alcança, desmarca a
//!   fila. O OpenNT não tem política de desempenho de processador: o
//!   trabalho aplica o estado e conta as aplicações.
//! - PoCpuIdledSinceLastCallImprecise(Processor, LastIdleTime*) 0x36bb20:
//!   sem KPRCB (KiProcessorBlock[Processor] nulo), TRUE; senão troca
//!   *LastIdleTime pelo PowerState.IdleTimeTotal da CPU e devolve TRUE se ela
//!   está ociosa agora (IdleTimeEntry != 0) ou se o total cresceu.
//! - Os perfis de desempenho que o pdc.sys registra (`po/pdc.rs`):
//!   PpmRegisterProfiles(Count, Profiles) 0x7c5e48 recusa mais de 0x1F
//!   perfis (STATUS_INVALID_PARAMETER); aloca um bloco com um PPM_PROFILE
//!   de 0x15B0 bytes por perfil seguido dos nomes (sem memória,
//!   STATUS_INSUFFICIENT_RESOURCES) e preenche cada um: o nome copiado (+0),
//!   o índice a partir de 1 (+8), o GUID (+0xC), o BOOLEAN da entrada (+0x20)
//!   e +0x15A0 = -1; grava o perfil no elemento da entrada (+0x18). Sob as
//!   travas de política o bloco vira o PpmProfiles e o PpmProfileCount, cada
//!   perfil recebe o PpmResetProfileSettings (as duas metades de 0xAB0 bytes
//!   do PpmDefaultProfile, que o OpenNT não tem: ficam zeradas) e o
//!   PpmProfileStatus liga o bit 0. PpmApplyProfile(Profile) 0x8f5a6c troca o
//!   PpmCurrentProfile (nulo = o padrão), marca o bit 1 do +0x1C do novo e o
//!   apaga do antigo e grava o InterruptTime em +0x1588; a reavaliação da
//!   política de desempenho não existe no OpenNT. O PdcPoPpmResetProfile só
//!   age com o bit 1 do PpmProfileStatus apagado (habilitar ou desabilitar o
//!   perfil, sem efeito sem a política).

use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::WorkQueueItem;
use crate::ntos::ke::pcr;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

/// O estado do PpmMediaBufferingWork.
struct MediaBuffering {
    /// O WORK_QUEUE_ITEM embutido (alocado na primeira vez).
    work_item: u64,
    queued: bool,
    requested: bool,
    applied: bool,
}

static MEDIA_BUFFERING: SpinLock<MediaBuffering> = SpinLock::new(MediaBuffering { work_item: 0, queued: false, requested: false, applied: false });
/// Quantas vezes o trabalho aplicou uma mudança de estado.
static MEDIA_BUFFERING_UPDATES: AtomicU64 = AtomicU64::new(0);

/// PpmMediaBufferingWorker.
fn media_buffering_worker(_item: u64, _parameter: u64) {
    loop {
        let mut state = MEDIA_BUFFERING.lock();
        if state.requested == state.applied {
            state.queued = false;
            return;
        }
        state.applied = state.requested;
        drop(state);
        MEDIA_BUFFERING_UPDATES.fetch_add(1, Ordering::SeqCst);
    }
}

/// PoNotifyMediaBuffering(Engaged).
pub fn notify_media_buffering(engaged: bool) {
    let item = {
        let mut state = MEDIA_BUFFERING.lock();
        state.requested = engaged;
        if state.queued {
            return;
        }
        if state.work_item == 0 {
            state.work_item = crate::ntos::mm::guest_memory::alloc_bytes(WorkQueueItem::SIZE);
            if state.work_item == 0 {
                return;
            }
        }
        state.queued = true;
        state.work_item
    };
    crate::ntos::io::work_items::queue_kernel_ex_work_item(item, media_buffering_worker, 0);
}

/// (pedido, aplicado, na fila, aplicações) do buffering de mídia.
pub fn media_buffering_state() -> (bool, bool, bool, u64) {
    let state = MEDIA_BUFFERING.lock();
    (state.requested, state.applied, state.queued, MEDIA_BUFFERING_UPDATES.load(Ordering::SeqCst))
}

/// PoCpuIdledSinceLastCallImprecise(Processor, LastIdleTime*) -> BOOLEAN.
pub fn cpu_idled_since_last_call(processor: u32, last_idle_time: &Field<u64>) -> bool {
    let Some(prcb) = pcr::processor_block(processor) else { return true };
    let power = &prcb.power_state;
    let total = power.idle_time_total.get();
    let previous = last_idle_time.get();
    last_idle_time.set(total);
    power.idle_time_entry.get() != 0 || total > previous
}


/// O tamanho de um PPM_PROFILE e os campos que o registro preenche.
const PROFILE_SIZE: u64 = 0x15B0;
const PROFILE_INDEX: u64 = 8;
const PROFILE_GUID: u64 = 0xC;
const PROFILE_FLAGS: u64 = 0x1C;
const PROFILE_SELECTED: u64 = 0x20;
const PROFILE_ACCUMULATION_START: u64 = 0x1588;
const PROFILE_SENTINEL: u64 = 0x15A0;
/// O elemento da entrada do registro: {GUID*, PWSTR, BOOLEAN, PPM_PROFILE*}.
const ENTRY_SIZE: u64 = 0x20;
const MAXIMUM_PROFILES: u32 = 0x1F;
/// O bit 1 do +0x1C: o perfil aplicado.
const PROFILE_APPLIED: u32 = 2;

/// PpmProfiles, PpmProfileCount, PpmProfileStatus e PpmCurrentProfile
/// (zero = o PpmDefaultProfile).
struct Profiles {
    block: u64,
    count: u32,
    status: u32,
    current: u64,
}

static PROFILES: SpinLock<Profiles> = SpinLock::new(Profiles { block: 0, count: 0, status: 0, current: 0 });

/// O comprimento em WCHARs de uma cadeia terminada em NUL do chamador.
fn wide_length(text: u64) -> u64 {
    let mut length = 0;
    while guest::read16(text + length * 2) != 0 {
        length += 1;
    }
    length
}

/// PpmRegisterProfiles(Count, Profiles): o NTSTATUS.
pub fn register_profiles(count: u32, entries: u64) -> u32 {
    if count > MAXIMUM_PROFILES {
        return 0xC000_000D;
    }
    let headers = count as u64 * PROFILE_SIZE;
    let names: u64 = (0..count as u64).map(|index| (wide_length(guest::read64(entries + index * ENTRY_SIZE + 8)) + 1) * 2).sum();
    let size = ((headers + 1) & !1) + names;
    let block = guest::alloc_bytes(size.max(1));
    if block == 0 {
        return 0xC000_009A;
    }
    guest::write_bytes(block, &alloc::vec![0u8; size.max(1) as usize]);
    let mut name_cursor = block + ((headers + 1) & !1);
    for index in 0..count as u64 {
        let entry = entries + index * ENTRY_SIZE;
        let profile = block + index * PROFILE_SIZE;
        let length = wide_length(guest::read64(entry + 8));
        let name = guest::read_bytes(guest::read64(entry + 8), (length * 2) as usize);
        guest::write_bytes(name_cursor, &name);
        guest::write64(profile, name_cursor);
        guest::write8(profile + PROFILE_INDEX, (index + 1) as u8);
        guest::write_bytes(profile + PROFILE_GUID, &guest::read_bytes(guest::read64(entry), 16));
        guest::write8(profile + PROFILE_SELECTED, guest::read8(entry + 0x10));
        guest::write64(profile + PROFILE_SENTINEL, u64::MAX);
        guest::write64(entry + 0x18, profile);
        name_cursor += (length + 1) * 2;
    }
    let mut profiles = PROFILES.lock();
    profiles.block = block;
    profiles.count = count;
    profiles.status |= 1;
    0
}

/// PpmApplyProfile(Profile).
pub fn apply_profile(profile: u64) {
    let mut profiles = PROFILES.lock();
    if profiles.current == profile {
        return;
    }
    if profiles.current != 0 {
        let old = guest::read32(profiles.current + PROFILE_FLAGS);
        guest::write32(profiles.current + PROFILE_FLAGS, old & !PROFILE_APPLIED);
    }
    if profile != 0 {
        let flags = guest::read32(profile + PROFILE_FLAGS);
        guest::write32(profile + PROFILE_FLAGS, flags | PROFILE_APPLIED);
        guest::write64(profile + PROFILE_ACCUMULATION_START, crate::ntos::ke::clock::unbiased_interrupt_time());
    }
    profiles.current = profile;
}

/// O PpmProfileStatus (o PdcPoPpmResetProfile só age com o bit 1 apagado).
pub fn profile_status() -> u32 {
    PROFILES.lock().status
}

/// (PpmProfiles, PpmProfileCount, PpmCurrentProfile).
pub fn profiles_state() -> (u64, u32, u64) {
    let profiles = PROFILES.lock();
    (profiles.block, profiles.count, profiles.current)
}
