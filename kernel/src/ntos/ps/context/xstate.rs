//! O pedaço XSTATE (CONTEXT_XSTATE) dos CONTEXT de usuário: a parte do
//! KeContextFromKframes e do KxContextToKframes que move o estado estendido
//! entre a thread e um CONTEXT estendido do kernel, a cópia sondada entre
//! esse CONTEXT e o do usuário (RtlpCopyXStateChunk) e a cópia direta do
//! buffer de um chamador de KernelMode.
//!
//! O estado de usuário de uma thread é o da área de `ke::xstate::user_state_area`
//! (KTHREAD.StateSaveArea, ou a do XSTATE_SAVE mais antigo de um driver);
//! quando a thread é a do serviço em curso nesta CPU, o estado vivo na CPU é
//! o dela e vai à área antes da leitura, e uma escrita volta à CPU
//! (o RtlXRestoreS do KxContextToKframes).

use crate::hal::amd64::usermode;
use crate::ntos::inc::types::{ContextEx, NtStruct};
use crate::ntos::ke::xsave::{self, feature, HEADER_SIZE, LEGACY_SIZE};
use crate::ntos::ke::xstate;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user::state;
use crate::ntos::rtl::extended_context::{self, CONTEXT_LENGTH, CONTEXT_XSTATE};
use crate::rtl::KernelError;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;

/// O CONTEXT pede o XSTATE (CONTEXT_AMD64 | CONTEXT_XSTATE).
pub fn requested(flags: u32) -> bool {
    flags & CONTEXT_XSTATE == CONTEXT_XSTATE
}

/// Um CONTEXT estendido do kernel com o pedaço XSTATE de todos os recursos
/// visíveis (RtlInitializeExtendedContext2 com EnabledFeatures | supervisor
/// visível).
pub struct Extended {
    buffer: u64,
    context_ex: u64,
}

impl Extended {
    pub fn new(flags: u32) -> Result<Self, u32> {
        let mask = xsave::enabled_features() | xsave::enabled_user_visible_supervisor_features();
        let length = extended_context::extended_context_length2(flags, mask)?;
        let buffer = guest::alloc_aligned(length as u64, 16, true);
        if buffer == 0 {
            return Err(STATUS_NO_MEMORY);
        }
        match extended_context::initialize_extended_context2(buffer, flags, mask) {
            Ok(context_ex) => Ok(Self { buffer, context_ex }),
            Err(status) => {
                guest::free_bytes(buffer);
                Err(status)
            }
        }
    }

    /// O CONTEXT legado.
    pub fn context(&self) -> u64 {
        self.context_ex - CONTEXT_LENGTH as u64
    }

    /// O CONTEXT_EX.
    pub fn context_ex(&self) -> u64 {
        self.context_ex
    }

    /// (cabeçalho do pedaço XSTATE, tamanho).
    pub fn chunk(&self) -> (u64, u32) {
        extended_context::xstate_chunk(self.context_ex)
    }

    /// A base de XSAVE que o pedaço representa (o cabeçalho menos a área
    /// legada, que fica no CONTEXT).
    fn base(&self) -> u64 {
        self.chunk().0 - LEGACY_SIZE as u64
    }
}

impl Drop for Extended {
    fn drop(&mut self) {
        guest::free_bytes(self.buffer);
    }
}

/// O estado estendido da thread está vivo na CPU: ela é a do serviço em
/// curso aqui.
pub fn live(thread: u64) -> bool {
    let area = xstate::thread_area(thread);
    area != 0 && usermode::in_service() && usermode::block().xstate_area.get() == area
}

/// O lado de leitura do KeContextFromKframes: o estado de usuário da thread
/// (KiCopyXStateArea com EnabledFeatures sem x87 e SSE) no pedaço.
pub fn fill_from_thread(extended: &Extended, thread: u64) {
    fill_base_from_thread(extended.base(), thread);
}

/// [`fill_from_thread`] num pedaço montado por quem chama (o frame das APCs
/// especiais): `base` é o cabeçalho do pedaço menos a área legada, que não
/// é escrita (o x87 e o SSE seguem no CONTEXT.FltSave).
pub fn fill_base_from_thread(base: u64, thread: u64) {
    let area = xstate::user_state_area(thread);
    if area == 0 {
        return;
    }
    if live(thread) && area == xstate::thread_area(thread) {
        xstate::save_current(area);
    }
    xstate::copy_area(base, xsave::enabled_features() & !feature::LEGACY, area);
}

/// O pedaço XSTATE de um CONTEXT de KernelMode com CONTEXT_XSTATE, num
/// CONTEXT estendido do kernel: o buffer é o do próprio chamador, sem sonda,
/// e o pedaço é o que o XState do CONTEXT_EX logo depois do CONTEXT aponta
/// (o PspSetContext o lê assim para uma thread de UserMode).
pub fn capture_kernel(context: u64, flags: u32) -> Result<Extended, u32> {
    let extended = Extended::new(flags)?;
    let chunks = context + CONTEXT_LENGTH as u64;
    extended_context::copy_xstate_chunk(extended.context_ex(), extended.context_ex(), chunks, chunks)?;
    Ok(extended)
}

/// O lado de escrita do KxContextToKframes: com um XSTATE_SAVE de driver na
/// lista, o pedaço vai à área mais antiga dela (EnabledVolatileFeatures sem
/// x87 e SSE); senão à área da thread (com a supervisor visível), que volta
/// à CPU quando a thread é a do serviço em curso.
pub fn apply_to_thread(extended: &Extended, thread: u64) {
    let own = xstate::thread_area(thread);
    let area = xstate::user_state_area(thread);
    if area == 0 {
        return;
    }
    let volatile = xsave::enabled_volatile_features();
    if area != own {
        xstate::copy_area(area, volatile & !feature::LEGACY, extended.base());
        return;
    }
    let is_live = live(thread);
    if is_live {
        // A área recebe só os recursos do pedaço; o resto segue o vivo.
        xstate::save_current(own);
    }
    xstate::copy_area(own, (volatile | xsave::enabled_user_visible_supervisor_features()) & !feature::LEGACY, extended.base());
    if is_live {
        xstate::restore_current(own);
    }
}

/// O CONTEXT_EX de um CONTEXT de usuário (sondado): Legacy precisa ser o
/// CONTEXT logo antes, sem passar dos 0x4D0 bytes (o teste do
/// RtlpCopyExtendedContext). Devolve (cabeçalho do XSTATE, tamanho).
pub fn user_chunk(context: u64) -> Result<Result<(u64, u32), u32>, KernelError> {
    let context_ex = context + CONTEXT_LENGTH as u64;
    if !state::probe_user_read(context_ex, ContextEx::SIZE) {
        return Ok(Err(STATUS_ACCESS_VIOLATION));
    }
    let chunks = state::user_struct::<ContextEx>(context_ex)?;
    let legacy_offset = chunks.legacy.offset.probe_get()?;
    let legacy_length = chunks.legacy.length.probe_get()?;
    if legacy_offset != -(CONTEXT_LENGTH as i32) || legacy_length > CONTEXT_LENGTH {
        return Ok(Err(STATUS_INVALID_PARAMETER));
    }
    let offset = chunks.x_state.offset.probe_get()?;
    let length = chunks.x_state.length.probe_get()?;
    Ok(Ok((context_ex.wrapping_add(offset as i64 as u64), length)))
}

/// Um CONTEXT_EX do kernel cujo pedaço XSTATE tem `length` bytes: o
/// espelho de um pedaço de usuário.
struct Mirror {
    buffer: u64,
}

impl Mirror {
    const HEADER: u64 = 0x40;

    fn new(length: u32) -> Option<Self> {
        let buffer = guest::alloc_aligned(Self::HEADER + length.max(HEADER_SIZE) as u64, 64, true);
        if buffer == 0 {
            return None;
        }
        // SAFETY: o CONTEXT_EX no começo do bloco recém-alocado.
        let chunks = unsafe { ContextEx::at(buffer) };
        chunks.x_state.offset.set(Self::HEADER as i32);
        chunks.x_state.length.set(length);
        Some(Self { buffer })
    }

    fn header(&self) -> u64 {
        self.buffer + Self::HEADER
    }
}

impl Drop for Mirror {
    fn drop(&mut self) {
        guest::free_bytes(self.buffer);
    }
}

/// O pedaço XSTATE de um CONTEXT de usuário com CONTEXT_XSTATE, capturado
/// num CONTEXT estendido do kernel (RtlpCopyXStateChunk do usuário para o
/// kernel). Os bytes além do pedaço do kernel não seriam copiados: a leitura
/// para nele.
pub fn capture_user(context: u64, flags: u32) -> Result<Result<Extended, u32>, KernelError> {
    let (header, length) = match user_chunk(context)? {
        Ok(chunk) => chunk,
        Err(status) => return Ok(Err(status)),
    };
    let extended = match Extended::new(flags) {
        Ok(extended) => extended,
        Err(status) => return Ok(Err(status)),
    };
    let readable = length.min(extended.chunk().1);
    if readable != 0 && !state::probe_user_read(header, readable as u64) {
        return Ok(Err(STATUS_ACCESS_VIOLATION));
    }
    let Some(mirror) = Mirror::new(readable) else { return Ok(Err(STATUS_NO_MEMORY)) };
    let bytes = guest::try_read_bytes(header, readable as usize)?;
    guest::write_bytes(mirror.header(), &bytes);
    match extended_context::copy_xstate_chunk(extended.context_ex(), extended.context_ex(), mirror.buffer, mirror.buffer) {
        Ok(_) => Ok(Ok(extended)),
        Err(status) => Ok(Err(status)),
    }
}

/// O estado estendido da thread no pedaço XSTATE de um CONTEXT de usuário
/// (o RtlpWriteExtendedContext do NtGetContextThread): o cabeçalho e os
/// recursos copiados; o resto do pedaço do usuário fica como estava.
pub fn write_user(thread: u64, context: u64) -> Result<u32, KernelError> {
    let (header, length) = match user_chunk(context)? {
        Ok(chunk) => chunk,
        Err(status) => return Ok(status),
    };
    let extended = match Extended::new(CONTEXT_XSTATE | 0xF) {
        Ok(extended) => extended,
        Err(status) => return Ok(status),
    };
    fill_from_thread(&extended, thread);
    let writable = length.min(extended.chunk().1);
    let Some(mirror) = Mirror::new(writable) else { return Ok(STATUS_NO_MEMORY) };
    let ranges = match extended_context::copy_xstate_chunk(mirror.buffer, mirror.buffer, extended.context_ex(), extended.context_ex()) {
        Ok(ranges) => ranges,
        Err(status) => return Ok(status),
    };
    let end = ranges.iter().map(|&(_, end)| end).max().unwrap_or(HEADER_SIZE).max(HEADER_SIZE);
    if !state::probe_user_write(header, end as u64) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    guest::try_write_bytes(header, &guest::read_bytes(mirror.header(), HEADER_SIZE as usize))?;
    for (start, end) in ranges {
        guest::try_write_bytes(header + start as u64, &guest::read_bytes(mirror.header() + start as u64, (end - start) as usize))?;
    }
    Ok(0)
}
