//! Estado USER/GDI da sessão — `system32/ntos/ps/user/win32k.js`.
//!
//! Layout das DLLs x64 instaladas (19041), tirado de
//! USER32!UserClientDllInitialize, win32kfull!NtUserProcessConnect e
//! gdi32full!GdiProcessSetup — não da antiga ABI USERCONNECT.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use super::sections::{self, CreateOptions, MapRequest, Section, View};
use super::{csr, state, threads};
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

pub const USER_CAPACITY: u64 = 4096;
pub const USER_ENTRY_SIZE: u64 = 0x20;
const USER_TABLE: u64 = 0x1_0000;
pub const GDI_CAPACITY: u64 = 65536;
pub const GDI_ENTRY_SIZE: u64 = 0x18;
const GDI_CAPS: u64 = 0x18_0000;
/// A sessão de serviço zero não tem política de escala de monitor: os
/// pixels lógicos Win32 usam 96 DPI (unidade de coordenada).
const SESSION_DPI: u32 = 96;

/// Alocação compartilhada: alias supervisor RW, vistas de usuário RO.
#[derive(Clone)]
struct Shared {
    section: Arc<Section>,
    _view: Arc<View>,
    base: u64,
}

/// Estado de fila e entrada de uma thread Win32.
pub struct Win32Thread {
    pub pointer: u64,
    pub teb: u64,
    pub id: u64,
    pub active: u64,
    pub focus: u64,
    pub capture: u64,
    pub extra_info: u64,
    pub ime_window: u64,
    pub input_context: u64,
    pub last_message_time: u64,
}

pub struct ProcessRecord {
    pub peb: u64,
    pub threads: BTreeMap<u64, Win32Thread>,
    user_view: Option<Arc<View>>,
    gdi_view: Option<Arc<View>>,
    pub flags: u64,
    pub dpi: u32,
    pub startup_flags: u32,
}

struct Session {
    user: Option<Shared>,
    gdi: Option<Shared>,
    processes: BTreeMap<u64, ProcessRecord>,
}

static SESSION: SpinLock<Session> = SpinLock::new(Session { user: None, gdi: None, processes: BTreeMap::new() });

/// Um alias supervisor RW possui cada alocação; as vistas de usuário são
/// somente leitura, inclusive contra NtProtectVirtualMemory.
fn create_shared(size: u64) -> Result<Result<Shared, u32>, KernelError> {
    let section = match sections::create(CreateOptions { size, page_protect: 4, attributes: 0x0800_0000, ..CreateOptions::default() })? {
        Ok(section) => section,
        Err(status) => return Ok(Err(status)),
    };
    let view = match sections::map(&section, &MapRequest { supervisor: true, protect: 4, ..MapRequest::default() })? {
        Ok(view) => view,
        Err(status) => {
            sections::release(&section)?;
            return Ok(Err(status));
        }
    };
    section.set_page_protect(2);
    let base = view.base;
    Ok(Ok(Shared { section, _view: view, base }))
}

fn ensure_user() -> Result<Result<Shared, u32>, KernelError> {
    if let Some(shared) = SESSION.lock().user.clone() {
        return Ok(Ok(shared));
    }
    let shared = match create_shared(USER_TABLE + USER_CAPACITY * USER_ENTRY_SIZE)? {
        Ok(shared) => shared,
        Err(status) => return Ok(Err(status)),
    };
    // Sem IME nem desktop interativo na sessão zero: as flags de
    // SERVERINFO e as tabelas de mensagens/classes começam vazias.
    guest::write64(shared.base + 8, USER_CAPACITY);
    guest::write16(shared.base + 0x1B56, SESSION_DPI as u16); // DPI de referência de fontes/métricas
    guest::write16(shared.base + 0x1B66, 1); // geração da configuração de DPI
    SESSION.lock().user = Some(shared.clone());
    Ok(Ok(shared))
}

fn ensure_gdi() -> Result<Result<Shared, u32>, KernelError> {
    if let Some(shared) = SESSION.lock().gdi.clone() {
        return Ok(Ok(shared));
    }
    let shared = match create_shared(GDI_CAPS + 0x1000)? {
        Ok(shared) => shared,
        Err(status) => return Ok(Err(status)),
    };
    SESSION.lock().gdi = Some(shared.clone());
    Ok(Ok(shared))
}

fn with_process<R>(process_id: u64, body: impl FnOnce(&mut ProcessRecord) -> R) -> R {
    let peb = state::with(|state| state.current_peb_va);
    let mut session = SESSION.lock();
    let record = session.processes.entry(process_id).or_insert_with(|| ProcessRecord { peb, threads: BTreeMap::new(), user_view: None, gdi_view: None, flags: 0, dpi: SESSION_DPI, startup_flags: 0 });
    body(record)
}

/// Vista RO da alocação compartilhada, reaproveitada enquanto mapeada.
fn map_shared(process_id: u64, gdi: bool, shared: &Shared) -> Result<Result<u64, u32>, KernelError> {
    let existing = with_process(process_id, |record| if gdi { record.gdi_view.clone() } else { record.user_view.clone() });
    if let Some(view) = existing.filter(|view| !view.state.lock().unmapped) {
        return Ok(Ok(view.base));
    }
    let view = match sections::map(&shared.section, &MapRequest { protect: 2, ..MapRequest::default() })? {
        Ok(view) => view,
        Err(status) => return Ok(Err(status)),
    };
    let base = view.base;
    with_process(process_id, |record| {
        if gdi {
            record.gdi_view = Some(view);
        } else {
            record.user_view = Some(view);
        }
    });
    Ok(Ok(base))
}

/// Registro do servidor 3 da CSR (USERCONNECT): DWORD de despacho, padding
/// e o SHAREDINFO de 0x238 bytes.
pub fn connect_user(process_id: u64, payload: u64) -> u32 {
    connect_user_checked(process_id, payload).unwrap_or_else(|error| {
        crate::debug_print!("[win32k] {}", error);
        0xC000_0001
    })
}

fn connect_user_checked(process_id: u64, payload: u64) -> Result<u32, KernelError> {
    if process_id != state::with(|state| state.current_process_id) {
        return Ok(0xC000_0008);
    }
    let dispatch = state::with(|state| state.mapped_image_exports.get("win32u.dll").and_then(|exports| exports.get("gDispatchTableValues").copied()));
    let Some(dispatch) = dispatch.filter(|&dispatch| state::probe_user_read(dispatch, 4)) else { return Ok(0xC000_007B) };
    let shared = match ensure_user()? {
        Ok(shared) => shared,
        Err(status) => return Ok(status),
    };
    let base = match map_shared(process_id, false, &shared)? {
        Ok(base) => base,
        Err(status) => return Ok(status),
    };
    // Resposta local primeiro: nenhum ponteiro parcial publicado em falha.
    let mut bytes = [0u8; 0x240];
    bytes[0..4].copy_from_slice(&guest::read32(dispatch).to_le_bytes());
    bytes[8..16].copy_from_slice(&base.to_le_bytes()); // psi
    bytes[0x10..0x18].copy_from_slice(&(base + USER_TABLE).to_le_bytes()); // aheList
    bytes[0x18..0x1C].copy_from_slice(&(USER_ENTRY_SIZE as u32).to_le_bytes());
    bytes[0x20..0x28].copy_from_slice(&(base + 0x4000).to_le_bytes()); // pDispInfo, fora do SERVERINFO
    bytes[0x28..0x30].copy_from_slice(&base.to_le_bytes()); // base da alocação compartilhada
    state::write_user_bytes(payload, &bytes)?;
    crate::debug_print!("[win32k] USER conectado: pid={} handles={}", process_id, USER_CAPACITY);
    Ok(0)
}

pub fn initialize_gdi() -> Result<u32, KernelError> {
    let (process_id, peb) = state::with(|state| (state.current_process_id, state.current_peb_va));
    if process_id == 0 || !state::probe_user_write(peb + 0xF8, 8) {
        return Ok(0xC000_0005);
    }
    let shared = match ensure_gdi()? {
        Ok(shared) => shared,
        Err(status) => return Ok(status),
    };
    let base = match map_shared(process_id, true, &shared)? {
        Ok(base) => base,
        Err(status) => return Ok(status),
    };
    let peb = with_process(process_id, |record| record.peb);
    guest::write64(peb + 0xF8, base);
    // As operações de desenho são síncronas: nenhuma fila assíncrona de
    // lote GDI é anunciada ao cliente nativo.
    guest::write32(peb + 0x108, 1); // GdiDCAttributeList / limite do lote
    Ok(0)
}

fn current_thread() -> Option<Arc<threads::UserThread>> {
    threads::find_by_id(process::get_current_thread_id())
}

/// SetLastError no TEB da thread corrente; devolve zero.
pub fn last_error(value: u32) -> u32 {
    if let Some(thread) = current_thread() {
        let teb = thread.with(|thread| thread.teb_va);
        if teb != 0 {
            guest::write32(teb + 0x68, value);
        }
    }
    0
}

/// Converte a thread corrente em thread Win32 (W32THREAD opaco no TEB).
pub fn ensure_thread() -> Option<u64> {
    let source = current_thread()?;
    let (teb, thread_pointer) = source.with(|thread| (thread.teb_va, thread.thread_pointer));
    let process_id = state::with(|state| state.current_process_id);
    if let Some(pointer) = with_process(process_id, |record| record.threads.get(&source.thread_id).map(|thread| thread.pointer)) {
        return Some(pointer);
    }
    let pointer = guest::alloc_bytes(0x100);
    if pointer == 0 {
        last_error(8);
        return None;
    }
    guest::write64(pointer, thread_pointer);
    guest::write64(pointer + 8, process_id);
    guest::write64(pointer + 16, source.thread_id);
    // Win32ThreadInfo é um ponteiro supervisor opaco, nunca um handle.
    guest::write64(teb + 0x78, pointer);
    guest::write32(teb + 0x810, 0x400); // versão de compatibilidade Win32 padrão
    with_process(process_id, |record| {
        record.threads.insert(source.thread_id, Win32Thread { pointer, teb, id: source.thread_id, active: 0, focus: 0, capture: 0, extra_info: 0, ime_window: 0, input_context: 0, last_message_time: 0 });
    });
    Some(pointer)
}

pub fn release_process(process_id: u64) {
    let Some(record) = SESSION.lock().processes.remove(&process_id) else { return };
    for thread in record.threads.values() {
        guest::write64(thread.teb + 0x78, 0);
        guest::free_bytes(thread.pointer);
    }
    if let Some(view) = &record.gdi_view {
        guest::write64(record.peb + 0xF8, 0);
        if !view.state.lock().unmapped {
            let _ = sections::unmap(view, None);
        }
    }
    if let Some(view) = record.user_view.as_ref().filter(|view| !view.state.lock().unmapped) {
        let _ = sections::unmap(view, None);
    }
}

pub fn release_thread(process_id: u64, thread_id: u64) {
    let thread = SESSION.lock().processes.get_mut(&process_id).and_then(|record| record.threads.remove(&thread_id));
    if let Some(thread) = thread {
        guest::write64(thread.teb + 0x78, 0);
        guest::free_bytes(thread.pointer);
    }
}

/// Estado de um processo: DPI e flags de inicialização.
pub fn process_info(process_id: u64) -> Option<(u32, u32, bool, bool)> {
    SESSION.lock().processes.get(&process_id).map(|record| (record.dpi, record.startup_flags, record.user_view.is_some(), record.gdi_view.is_some()))
}

/// O NtGdiInit nativo devolve um BOOL; o mapeamento do processo é feito
/// explicitamente aqui.
fn nt_gdi_init(_: u64, _: u64, _: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(if initialize_gdi()? != 0 { last_error(8) } else { 1 })
}

fn nt_user_get_dpi_for_current_process(_: u64, _: u64, _: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    let process_id = state::with(|state| state.current_process_id);
    Ok(with_process(process_id, |record| record.dpi))
}

fn nt_user_modify_user_startup_info_flags(mask: u64, value: u64, _: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    let process_id = state::with(|state| state.current_process_id);
    let (mask, value) = (mask as u32, value as u32);
    with_process(process_id, |record| record.startup_flags = (record.startup_flags & !mask) | (mask & value));
    Ok(1)
}

fn nt_user_get_thread_state(routine: u64, _: u64, _: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    let Some(pointer) = ensure_thread() else { return Ok(0) };
    let process_id = state::with(|state| state.current_process_id);
    let value = with_process(process_id, |record| {
        let flags = record.flags;
        let thread = record.threads.values().find(|thread| thread.pointer == pointer)?;
        Some(match routine as u32 {
            0 => thread.active,
            1 => thread.focus,
            2 => thread.capture,
            3 => thread.ime_window,
            4 => thread.input_context,
            7 => thread.extra_info,
            9 => thread.last_message_time,
            11 => flags,
            14 => 1, // conversão para thread Win32 concluída
            _ => return None,
        })
    });
    Ok(match value {
        Some(value) => value as u32,
        None => {
            crate::debug_print!("[win32k] GetThreadState sem implementacao: {}", routine as u32);
            last_error(120)
        }
    })
}

pub fn init() {
    state::register_handler("NtGdiInit", nt_gdi_init);
    state::register_handler("NtUserGetDpiForCurrentProcess", nt_user_get_dpi_for_current_process);
    state::register_handler("NtUserModifyUserStartupInfoFlags", nt_user_modify_user_startup_info_flags);
    state::register_handler("NtUserGetThreadState", nt_user_get_thread_state);
    csr::set_user_connector(connect_user);
    threads::set_win32k_release(release_thread);
}
