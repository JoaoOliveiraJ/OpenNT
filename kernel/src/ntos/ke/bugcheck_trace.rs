//! Diagnóstico das paradas do kernel na serial: a pilha de quem parou.
//!
//! Só diagnóstico: nada aqui muda o KeBugCheckEx nem o despacho de exceções.
//! Logo depois da linha `*** STOP (KeBugCheckEx)`, antes da parada no
//! depurador e da tela, sai um bloco curto `[kcrash]` ([`report`]) com:
//! - a origem: a exceção de kernel sem tratamento que levou ao
//!   KMODE_EXCEPTION_NOT_HANDLED ([`note_exception`], do despacho de
//!   exceções: código, endereço e, numa violação de acesso, o tipo de acesso
//!   e o endereço que faltou); senão o ponto de onde o código nativo chamou
//!   o kernel (o CONTEXT da chamada ao export em curso, com a rotina chamada
//!   quando a instrução de chamada é a de um import); sem nenhum dos dois
//!   (uma parada do próprio kernel fora de uma chamada nativa), a pilha do
//!   kernel;
//! - os registradores inteiros desse CONTEXT;
//! - até 16 quadros, desenrolados pela .pdata de cada imagem
//!   (`rtl::frame_walk`) e, nas funções do kernel (sem .pdata, compiladas
//!   com frame pointers), pela cadeia de RBP; a pilha termina no retorno de
//!   um contexto nativo (`win32_thunk::kernel_thread_return`) ou num endereço
//!   fora da metade de sistema, e a linha `(fim: ...)` diz onde e por quê
//!   ([`WalkEnd`]).
//!
//! Cada endereço sai como módulo+deslocamento pela PsLoadedModuleList (as
//! KLDR_DATA_TABLE_ENTRY, que também trazem as imagens de sessão: win32k*.sys
//! e cdd.dll) e com o export mais próximo do módulo. A exceção de kernel que
//! não passou pelo despacho (`*** EXCECAO DE KERNEL` da HAL) ganha os mesmos
//! quadros ([`trap`]).
//!
//! O bloco roda em qualquer IRQL e com interrupções desligadas: não aloca,
//! não espera trava e só lê páginas presentes da metade de sistema mapeadas
//! com cache, pela tabela de páginas da raiz corrente, sem trazer páginas de
//! volta ([`Walker`]); um endereço que não pode ser lido encerra o quadro ou
//! a pilha. O espaço de sessão só existe nas raízes dos processos da sessão:
//! quando a raiz corrente não mapeia uma página das imagens de sessão
//! (win32k*.sys, cdd.dll; o System, um processo sem sessão, o aviso de uma
//! thread sobre outra), a página sai pela raiz do primeiro processo da
//! PsActiveProcessHead que a mapeia, lida pelo endereço físico (as imagens
//! de sessão ficam na mesma VA em todas as sessões que as carregam). Um
//! bloco por boot: uma falta dentro do próprio diagnóstico não o repete.

use core::fmt::{self, Write};
use core::mem::offset_of;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::pcr;
use crate::hal::amd64::win32_thunk;
use crate::hal::{cpu, physical};
use crate::ntos::inc::types::{Context, Eprocess, ExceptionRecord, ImageExportDirectory, KldrDataTableEntry, Kprocess, NtStruct};
use crate::ntos::mm::guest_memory::{self as guest, GuestScalar};
use crate::ntos::mm::memory_map::{self, KERNEL_VIRTUAL_BASE, MAX_CPUS};
use crate::ntos::mm::{kernel_data, loaded_images, paging};
use crate::ntos::ps::process;
use crate::ntos::rtl::frame_walk::{self, Images, Memory, Registers, RBP, RSP};
use crate::ntos::rtl::native_context;

/// Quadros desenrolados e quadros por linha.
pub const MAX_FRAMES: usize = 16;
const FRAMES_PER_LINE: usize = 4;
/// Distância máxima ao export mais próximo: no endereço da falha e nos quadros.
const FAULT_SYMBOL_RANGE: u64 = 0x1_0000;
const FRAME_SYMBOL_RANGE: u64 = 0x1000;
/// Limites das leituras da lista de módulos e dos exports.
const MAX_MODULES: usize = 512;
const MAX_EXPORTS: u32 = 0x4000;
const CACHED_MODULES: usize = 8;
const NAME_LENGTH: usize = 32;
const SYMBOL_LENGTH: usize = 64;
const LINE_LENGTH: usize = 384;
/// IMAGE_DIRECTORY_ENTRY_EXPORT.
const EXPORT_DIRECTORY: usize = 0;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_IN_PAGE_ERROR: u32 = 0xC000_0006;
/// A metade de sistema: VAs canônicas com o bit 47 ligado.
const SYSTEM_HALF: u64 = 0x1_FFFF;
/// Processos da PsActiveProcessHead olhados para achar a raiz de uma sessão.
const MAX_PROCESSES: usize = 1024;
/// O frame físico numa entrada de tabela de páginas (sem flags nem NX).
const FRAME_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// O bloco já saiu neste boot.
static TRACED: AtomicBool = AtomicBool::new(false);

/// Uma exceção sem tratamento anotada: o dono ([`owner`]), o
/// EXCEPTION_RECORD e o CONTEXT.
struct Noted {
    owner: AtomicU64,
    record: AtomicU64,
    context: AtomicU64,
}

/// Uma anotação por processador (o da anotação; a thread pode trocar de
/// processador antes da parada, então a busca é pelo dono).
static NOTED: [Noted; MAX_CPUS] = [const { Noted { owner: AtomicU64::new(0), record: AtomicU64::new(0), context: AtomicU64::new(0) } }; MAX_CPUS];

fn system_address(address: u64) -> bool {
    address >> 47 == SYSTEM_HALF
}

/// O dono de uma anotação: a KTHREAD corrente, ou o processador antes de
/// haver thread.
fn owner() -> u64 {
    if pcr::get_pcr_address() == 0 {
        return 1;
    }
    match pcr::current().prcb.current_thread.get() {
        0 => crate::ntos::kd::stop::current_processor() as u64 + 1,
        thread => thread,
    }
}

// ---- pontos de entrada ----------------------------------------------------------

/// A exceção de kernel sem tratamento que vai virar KMODE_EXCEPTION_NOT_HANDLED
/// na thread corrente: o EXCEPTION_RECORD e o CONTEXT da falha, vivos até a
/// parada (o despacho não volta).
pub fn note_exception(record: u64, context: u64) {
    let slot = &NOTED[crate::ntos::kd::stop::current_processor()];
    slot.owner.store(0, Ordering::Release);
    slot.record.store(record, Ordering::Release);
    slot.context.store(context, Ordering::Release);
    slot.owner.store(owner(), Ordering::Release);
}

/// A anotação da thread corrente, retirada.
fn take_noted() -> Option<(u64, u64)> {
    let owner = owner();
    let slot = NOTED.iter().find(|slot| slot.owner.load(Ordering::Acquire) == owner)?;
    let noted = (slot.record.load(Ordering::Acquire), slot.context.load(Ordering::Acquire));
    slot.owner.store(0, Ordering::Release);
    Some(noted)
}

/// O bloco `[kcrash]` do KeBugCheckEx, depois da linha `*** STOP`, com as
/// interrupções desligadas enquanto ele sai (o estado delas volta depois).
#[inline(never)]
pub fn report() {
    if TRACED.swap(true, Ordering::AcqRel) {
        return;
    }
    let flags = cpu::save_and_disable_interrupts();
    let mut walker = Walker::new();
    let mut line = Line::new();
    if let Some((record, context)) = take_noted() {
        exception_block(&mut walker, &mut line, record, context);
    } else if let Some(context) = native_context::try_current() {
        call_block(&mut walker, &mut line, context);
    } else {
        kernel_block(&mut walker, &mut line);
    }
    cpu::restore_interrupts(flags);
}

/// A exceção de kernel que não passou pelo despacho: o módulo do RIP e os
/// quadros, depois dos registradores que o diagnóstico da HAL já imprimiu.
pub fn trap(registers: Registers) {
    if TRACED.swap(true, Ordering::AcqRel) {
        return;
    }
    let mut walker = Walker::new();
    let mut line = Line::new();
    let _ = write!(line, "[kcrash] rip = ");
    walker.describe(&mut line, registers.rip, FAULT_SYMBOL_RANGE);
    line.emit();
    stack_lines(&mut walker, &mut line, registers, true);
}

// ---- blocos ---------------------------------------------------------------------

fn exception_block(walker: &mut Walker, line: &mut Line, record: u64, context: u64) {
    let field = |offset: usize| record + offset as u64;
    let code = walker.read::<u32>(field(offset_of!(ExceptionRecord, exception_code)));
    let address = walker.read::<u64>(field(offset_of!(ExceptionRecord, exception_address)));
    let parameters = walker.read::<u32>(field(offset_of!(ExceptionRecord, number_parameters))).unwrap_or(0);
    let mut information = [0u64; 3];
    for (index, slot) in information.iter_mut().enumerate() {
        *slot = walker.read::<u64>(field(offset_of!(ExceptionRecord, exception_information) + index * 8)).unwrap_or(0);
    }
    match (code, address) {
        (Some(code), Some(address)) => {
            let _ = write!(line, "[kcrash] excecao {code:#x} em {address:#x} = ");
            walker.describe(line, address, FAULT_SYMBOL_RANGE);
            if matches!(code, STATUS_ACCESS_VIOLATION | STATUS_IN_PAGE_ERROR) && parameters >= 2 {
                let access = match information[0] {
                    0 => "leitura de",
                    1 => "escrita em",
                    8 => "execucao em",
                    _ => "acesso a",
                };
                let _ = write!(line, ", {access} {:#x}", information[1]);
                if code == STATUS_IN_PAGE_ERROR && parameters >= 3 {
                    let _ = write!(line, " (status {:#x})", information[2]);
                }
            }
        }
        _ => {
            let _ = write!(line, "[kcrash] excecao sem registro legivel ({record:#x})");
        }
    }
    line.emit();
    match registers_at(walker, context) {
        Some(registers) => {
            register_lines(line, &registers);
            stack_lines(walker, line, registers, true);
        }
        None => {
            let _ = write!(line, "[kcrash] CONTEXT ilegivel ({context:#x})");
            line.emit();
        }
    }
}

/// Uma parada dentro de uma chamada nativa ao kernel: o CONTEXT é o do
/// chamador logo depois da instrução de chamada (o RIP é o retorno).
fn call_block(walker: &mut Walker, line: &mut Line, context: u64) {
    let Some(registers) = registers_at(walker, context) else {
        let _ = write!(line, "[kcrash] parada dentro de uma chamada nativa, CONTEXT ilegivel ({context:#x})");
        line.emit();
        return;
    };
    let _ = write!(line, "[kcrash] parada dentro de ");
    match walker.call_target(registers.rip) {
        Some(target) => walker.callee(line, target),
        None => {
            let _ = line.write_str("uma chamada ao kernel");
        }
    }
    let _ = write!(line, ", chamada de ");
    walker.describe(line, registers.rip, FRAME_SYMBOL_RANGE);
    line.emit();
    register_lines(line, &registers);
    stack_lines(walker, line, registers, false);
}

/// Uma parada do próprio kernel fora de uma chamada nativa: a cadeia de RBP
/// a partir de quem chamou este bloco.
fn kernel_block(walker: &mut Walker, line: &mut Line) {
    let _ = write!(line, "[kcrash] parada do proprio kernel, fora de uma chamada nativa");
    line.emit();
    let mut frames = [0u64; MAX_FRAMES];
    let (count, rbp) = kernel_frames_into(walker, &mut frames);
    frame_lines(walker, line, "pilha do kernel (rbp", rbp, &frames[..count]);
}

fn register_lines(line: &mut Line, registers: &Registers) {
    let value = |index: usize| registers.integer[index];
    let _ = write!(
        line,
        "[kcrash] rip={:016x} rsp={:016x} rbp={:016x} rax={:016x} rcx={:016x} rdx={:016x} r8={:016x} r9={:016x}",
        registers.rip,
        value(RSP),
        value(RBP),
        value(0),
        value(1),
        value(2),
        value(8),
        value(9)
    );
    line.emit();
    let _ = write!(
        line,
        "[kcrash] rbx={:016x} rsi={:016x} rdi={:016x} r10={:016x} r11={:016x} r12={:016x} r13={:016x} r14={:016x} r15={:016x}",
        value(3),
        value(6),
        value(7),
        value(10),
        value(11),
        value(12),
        value(13),
        value(14),
        value(15)
    );
    line.emit();
}

fn stack_lines(walker: &mut Walker, line: &mut Line, registers: Registers, exact: bool) {
    let mut frames = [0u64; MAX_FRAMES];
    let count = walker.walk(registers, exact, &mut frames);
    frame_lines(walker, line, "pilha (rsp", registers.integer[RSP], &frames[..count]);
}

/// Os quadros, quatro por linha, e a linha de onde e por que a pilha acabou
/// (o último `walk`).
fn frame_lines(walker: &mut Walker, line: &mut Line, origin: &str, pointer: u64, frames: &[u64]) {
    let _ = write!(line, "[kcrash] {origin} {pointer:#x}):");
    if frames.is_empty() {
        let _ = line.write_str(" ilegivel");
    }
    for (index, &address) in frames.iter().enumerate() {
        if index != 0 && index % FRAMES_PER_LINE == 0 {
            line.emit();
            let _ = line.write_str("[kcrash]  ");
        } else if index != 0 {
            let _ = line.write_str(" |");
        }
        let _ = line.write_str(" ");
        walker.describe(line, address, FRAME_SYMBOL_RANGE);
    }
    line.emit();
    let end = walker.end;
    let _ = write!(line, "[kcrash]  (fim: {end})");
    line.emit();
}

/// Os inteiros e o Rip de um CONTEXT.
fn registers_at(walker: &mut Walker, context: u64) -> Option<Registers> {
    let mut integer = [0u64; 16];
    let first = context + offset_of!(Context, rax) as u64;
    for (index, slot) in integer.iter_mut().enumerate() {
        *slot = walker.read::<u64>(first + index as u64 * 8)?;
    }
    Some(Registers { integer, rip: walker.read::<u64>(context + offset_of!(Context, rip) as u64)? })
}

/// A cadeia de RBP a partir de quem chamou esta função: os retornos e o RBP
/// de partida.
#[inline(never)]
fn kernel_frames_into(walker: &mut Walker, frames: &mut [u64; MAX_FRAMES]) -> (usize, u64) {
    let rbp: u64;
    // SAFETY: só lê o registrador (o kernel é compilado com frame pointers).
    unsafe { core::arch::asm!("mov {}, rbp", out(reg) rbp, options(nomem, nostack, preserves_flags)) };
    let mut registers = Registers { integer: [0; 16], rip: 0 };
    registers.integer[RSP] = rbp;
    registers.integer[RBP] = rbp;
    if walker.frame_pointer_step(&mut registers).is_none() {
        walker.end = WalkEnd::FramePointer(rbp);
        return (0, rbp);
    }
    (walker.walk(registers, false, frames), rbp)
}

// ---- linha sem alocação ---------------------------------------------------------

/// Uma linha da serial montada num buffer fixo (o excesso é cortado).
struct Line {
    text: [u8; LINE_LENGTH],
    length: usize,
}

impl Line {
    fn new() -> Self {
        Self { text: [0; LINE_LENGTH], length: 0 }
    }

    fn emit(&mut self) {
        crate::debug_print!("{}", core::str::from_utf8(&self.text[..self.length]).unwrap_or("[kcrash] ?"));
        self.length = 0;
    }
}

impl Write for Line {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let count = text.len().min(LINE_LENGTH - self.length);
        self.text[self.length..self.length + count].copy_from_slice(&text.as_bytes()[..count]);
        self.length += count;
        Ok(())
    }
}

/// Um texto ASCII curto num buffer fixo.
#[derive(Clone, Copy)]
struct Name<const N: usize> {
    text: [u8; N],
    length: usize,
}

impl<const N: usize> Name<N> {
    const EMPTY: Self = Self { text: [0; N], length: 0 };

    fn push(&mut self, byte: u8) -> bool {
        if self.length == N {
            return false;
        }
        self.text[self.length] = if byte.is_ascii_graphic() { byte } else { b'?' };
        self.length += 1;
        true
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.text[..self.length]).unwrap_or("?")
    }
}

// ---- memória, módulos e exports -------------------------------------------------

#[derive(Clone, Copy)]
struct Module {
    base: u64,
    size: u64,
    name: Name<NAME_LENGTH>,
}

impl Module {
    const EMPTY: Self = Self { base: 0, size: 0, name: Name::EMPTY };

    fn contains(&self, address: u64) -> bool {
        self.size != 0 && address >= self.base && address - self.base < self.size
    }
}

/// O export mais próximo: nome (ou ordinal) e a distância até o endereço.
struct Symbol {
    name: Name<SYMBOL_LENGTH>,
    ordinal: u32,
    distance: u64,
}

impl fmt::Display for Symbol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.name.length != 0 {
            formatter.write_str(self.name.as_str())
        } else {
            write!(formatter, "#{}", self.ordinal)
        }
    }
}

/// Por que a pilha acabou (o último `Walker::walk`).
#[derive(Clone, Copy)]
enum WalkEnd {
    /// Os MAX_FRAMES quadros.
    Limit,
    /// Retorno zero.
    Zero,
    /// O retorno de um contexto nativo (`kernel_thread_return`).
    NativeStart,
    /// Um retorno fora da metade de sistema (o anel 3 ou lixo).
    OutsideSystem(u64),
    /// O quadro não pôde ser desfeito.
    Unwind(frame_walk::Fail),
    /// A pilha não subiu (o RSP do chamador).
    NoProgress(u64),
    /// A cadeia de RBP do kernel não começa (o RBP de partida).
    FramePointer(u64),
}

impl fmt::Display for WalkEnd {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WalkEnd::Limit => write!(formatter, "limite de {MAX_FRAMES} quadros"),
            WalkEnd::Zero => formatter.write_str("retorno zero"),
            WalkEnd::NativeStart => formatter.write_str("comeco do contexto nativo"),
            WalkEnd::OutsideSystem(address) => write!(formatter, "retorno {address:#x} fora da metade de sistema"),
            WalkEnd::Unwind(fail) => write!(formatter, "{fail}"),
            WalkEnd::NoProgress(rsp) => write!(formatter, "a pilha nao subiu (rsp {rsp:#x})"),
            WalkEnd::FramePointer(rbp) => write!(formatter, "cadeia de RBP do kernel invalida (rbp {rbp:#x})"),
        }
    }
}

/// Como ler uma página conferida: pela VA (presente na raiz corrente) ou
/// pelo endereço físico (uma página de sessão vista pela raiz de outro
/// processo).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Virtual,
    Physical(u64),
}

/// Leitor da metade de sistema que não falta, com as últimas páginas
/// conferidas e os últimos módulos achados.
struct Walker {
    pages: [(u64, Page); 2],
    next_page: usize,
    /// A raiz (PML4 física) de um processo com o espaço de sessão, achada
    /// na primeira página de sessão que a raiz corrente não mapeia.
    session_root: Option<u64>,
    modules: [Module; CACHED_MODULES],
    next_module: usize,
    end: WalkEnd,
}

/// A página presente de `va` pelas tabelas da raiz `root`, mapeada com
/// cache (sem PWT, PCD nem PAT): o endereço físico dela. Cada tabela é
/// conferida contra o limite do mapa direto antes de ser lida (uma raiz de
/// um processo que sai não para o diagnóstico).
fn translate_in(root: u64, va: u64) -> Option<u64> {
    let mut table = root & FRAME_MASK;
    for (level, shift) in [39u32, 30, 21, 12].into_iter().enumerate() {
        if table == 0 || table >= memory_map::PHYSICAL_MEMORY_LIMIT {
            return None;
        }
        let entry = physical::read64(table + ((va >> shift) & 511) * 8);
        if entry & paging::PAGE_PRESENT == 0 {
            return None;
        }
        let large = (level == 1 || level == 2) && entry & paging::PAGE_PS != 0;
        if level == 3 || large {
            // O PAT fica no bit 7 da PTE de 4 KB e no bit 12 das grandes.
            let pat = if level == 3 { entry & 0x80 != 0 } else { entry & 0x1000 != 0 };
            if entry & (paging::PAGE_PWT | paging::PAGE_PCD) != 0 || pat {
                return None;
            }
            let size = 1u64 << shift;
            let frame = (entry & FRAME_MASK & !(size - 1)) + (va & (size - 1) & !0xFFF);
            return (frame < memory_map::PHYSICAL_MEMORY_LIMIT).then_some(frame);
        }
        table = entry & FRAME_MASK;
    }
    None
}

impl Walker {
    fn new() -> Self {
        Self { pages: [(u64::MAX, Page::Virtual); 2], next_page: 0, session_root: None, modules: [Module::EMPTY; CACHED_MODULES], next_module: 0, end: WalkEnd::Limit }
    }

    /// Como ler a página: presente na raiz corrente e mapeada com cache
    /// (sem PWT, PCD nem PAT: memória comum, não registradores de
    /// dispositivo), ou, no espaço de sessão que a raiz corrente não tem,
    /// pela raiz de um processo da sessão.
    fn page(&mut self, page: u64) -> Option<Page> {
        if let Some(&(_, found)) = self.pages.iter().find(|(cached, _)| *cached == page) {
            return Some(found);
        }
        if !system_address(page) {
            return None;
        }
        // Só as imagens de sessão saem por outra raiz: o pool de sessão é de
        // cada sessão, a mesma VA em outra seria outro dado.
        let session_image = (memory_map::SESSION_IMAGE_BASE..memory_map::SESSION_IMAGE_TOP).contains(&page);
        let found = match paging::query_page(page, false) {
            Some(mapping) if mapping.flags & (paging::PAGE_PWT | paging::PAGE_PCD) == 0 && !mapping.pat => Page::Virtual,
            Some(_) => return None,
            None if session_image => Page::Physical(self.session_frame(page)?),
            None => return None,
        };
        self.pages[self.next_page] = (page, found);
        self.next_page ^= 1;
        Some(found)
    }

    /// O endereço físico de uma página de sessão pela raiz do primeiro
    /// processo da PsActiveProcessHead que a mapeia (sem esperar a trava).
    fn session_frame(&mut self, page: u64) -> Option<u64> {
        if let Some(frame) = self.session_root.and_then(|root| translate_in(root, page)) {
            return Some(frame);
        }
        let head = process::try_active_process_head()?;
        let mut link = self.read::<u64>(head)?;
        for _ in 0..MAX_PROCESSES {
            if link == 0 || link == head {
                return None;
            }
            let eprocess = link - offset_of!(Eprocess, active_process_links) as u64;
            if let Some(root) = self.read::<u64>(eprocess + offset_of!(Kprocess, directory_table_base) as u64) {
                if let Some(frame) = translate_in(root, page) {
                    self.session_root = Some(root);
                    return Some(frame);
                }
            }
            link = self.read::<u64>(link)?;
        }
        None
    }

    /// O módulo que contém `address`: a PsLoadedModuleList ou, antes de ela
    /// existir, o registro das imagens (sem esperar a trava).
    fn module(&mut self, address: u64) -> Option<Module> {
        if let Some(module) = self.modules.iter().find(|module| module.contains(address)) {
            return Some(*module);
        }
        let found = self.listed_module(address).or_else(|| registered_module(address))?;
        self.modules[self.next_module] = found;
        self.next_module = (self.next_module + 1) % CACHED_MODULES;
        Some(found)
    }

    /// As KLDR_DATA_TABLE_ENTRY da PsLoadedModuleList, sem o recurso (como o
    /// depurador as lê).
    fn listed_module(&mut self, address: u64) -> Option<Module> {
        let head = kernel_data::address("PsLoadedModuleList").ok()?;
        let entry_field = |entry: u64, offset: usize| entry + offset as u64;
        let mut link = self.read::<u64>(head)?;
        for _ in 0..MAX_MODULES {
            if link == 0 || link == head {
                return None;
            }
            let entry = link - offset_of!(KldrDataTableEntry, in_load_order_links) as u64;
            let base = self.read::<u64>(entry_field(entry, offset_of!(KldrDataTableEntry, dll_base)))?;
            let size = self.read::<u32>(entry_field(entry, offset_of!(KldrDataTableEntry, size_of_image)))? as u64;
            let mut module = Module { base, size, name: Name::EMPTY };
            if module.contains(address) {
                let characters = self.read::<u16>(entry_field(entry, offset_of!(KldrDataTableEntry, base_dll_name.length))).unwrap_or(0) / 2;
                let buffer = self.read::<u64>(entry_field(entry, offset_of!(KldrDataTableEntry, base_dll_name.buffer))).unwrap_or(0);
                for index in 0..characters as u64 {
                    let unit = self.read::<u16>(buffer + index * 2).unwrap_or(b'?' as u16);
                    if !module.name.push(if unit < 0x80 { unit as u8 } else { b'?' }) {
                        break;
                    }
                }
                return Some(module);
            }
            link = self.read::<u64>(link)?;
        }
        None
    }

    /// O export de maior RVA até o endereço no módulo (forwarders fora).
    fn nearest_export(&mut self, module: &Module, address: u64) -> Option<Symbol> {
        let rva = address - module.base;
        let header = frame_walk::nt_headers(self, module.base)?;
        let (start, length) = frame_walk::data_directory(self, header, EXPORT_DIRECTORY)?;
        if start == 0 || start as u64 + ImageExportDirectory::SIZE > module.size {
            return None;
        }
        let directory = module.base + start as u64;
        let field = |offset: usize| directory + offset as u64;
        let functions = self.read::<u32>(field(offset_of!(ImageExportDirectory, number_of_functions)))?.min(MAX_EXPORTS);
        let names = self.read::<u32>(field(offset_of!(ImageExportDirectory, number_of_names)))?.min(MAX_EXPORTS);
        let ordinal_base = self.read::<u32>(field(offset_of!(ImageExportDirectory, base)))?;
        let function_table = module.base + self.read::<u32>(field(offset_of!(ImageExportDirectory, address_of_functions)))? as u64;
        let name_table = module.base + self.read::<u32>(field(offset_of!(ImageExportDirectory, address_of_names)))? as u64;
        let ordinal_table = module.base + self.read::<u32>(field(offset_of!(ImageExportDirectory, address_of_name_ordinals)))? as u64;
        let forwarders = start..start.saturating_add(length);
        let mut best: Option<(u32, u32)> = None;
        for index in 0..functions {
            let Some(function) = self.read::<u32>(function_table + index as u64 * 4) else { break };
            if function != 0 && function as u64 <= rva && !forwarders.contains(&function) && best.is_none_or(|(_, nearest)| function > nearest) {
                best = Some((index, function));
            }
        }
        let (index, function) = best?;
        let mut symbol = Symbol { name: Name::EMPTY, ordinal: ordinal_base.wrapping_add(index), distance: rva - function as u64 };
        for slot in 0..names as u64 {
            if self.read::<u16>(ordinal_table + slot * 2) != Some(index as u16) {
                continue;
            }
            let Some(name) = self.read::<u32>(name_table + slot * 4) else { break };
            let mut cursor = module.base + name as u64;
            while let Some(byte) = self.read::<u8>(cursor) {
                if byte == 0 || !symbol.name.push(byte) {
                    break;
                }
                cursor += 1;
            }
            break;
        }
        Some(symbol)
    }

    /// `módulo+deslocamento (Export+distância)`, ou o endereço cru.
    fn describe(&mut self, out: &mut impl Write, address: u64, range: u64) {
        let Some(module) = self.module(address) else {
            let _ = write!(out, "{address:#x}");
            return;
        };
        let _ = write!(out, "{}+{:#x}", module.name.as_str(), address - module.base);
        if let Some(symbol) = self.nearest_export(&module, address).filter(|symbol| symbol.distance <= range) {
            let _ = write!(out, " ({symbol}+{:#x})", symbol.distance);
        }
    }

    /// A rotina chamada: o nome do export quando o destino é o começo de um,
    /// senão o endereço descrito.
    fn callee(&mut self, out: &mut impl Write, target: u64) {
        let exact = self.module(target).and_then(|module| self.nearest_export(&module, target)).filter(|symbol| symbol.distance == 0);
        match exact {
            Some(symbol) => {
                let _ = write!(out, "{symbol}");
            }
            None => self.describe(out, target, FRAME_SYMBOL_RANGE),
        }
    }

    /// O destino da chamada que volta em `return_address`: `call [rip+disp32]`
    /// (o import pela IAT) ou `call rel32`, seguindo o `jmp [rip+disp32]` de
    /// um import no destino.
    fn call_target(&mut self, return_address: u64) -> Option<u64> {
        let relative = |walker: &mut Self, at: u64| walker.read::<i32>(at).map(|displacement| displacement as i64 as u64);
        if self.read::<u16>(return_address.wrapping_sub(6)) == Some(0x15FF) {
            let slot = return_address.wrapping_add(relative(self, return_address.wrapping_sub(4))?);
            return self.read::<u64>(slot);
        }
        if self.read::<u8>(return_address.wrapping_sub(5)) == Some(0xE8) {
            let target = return_address.wrapping_add(relative(self, return_address.wrapping_sub(4))?);
            if self.read::<u16>(target) == Some(0x25FF) {
                let slot = target.wrapping_add(6).wrapping_add(relative(self, target.wrapping_add(2))?);
                return self.read::<u64>(slot);
            }
            return Some(target);
        }
        None
    }

    /// Um quadro do kernel pela cadeia de RBP: [RBP] é o RBP do chamador e
    /// [RBP+8] o retorno.
    fn frame_pointer_step(&mut self, registers: &mut Registers) -> Option<()> {
        let rbp = registers.integer[RBP];
        if rbp & 7 != 0 || rbp < registers.integer[RSP] {
            return None;
        }
        registers.rip = self.read::<u64>(rbp + 8)?;
        registers.integer[RBP] = self.read::<u64>(rbp)?;
        registers.integer[RSP] = rbp + 16;
        Some(())
    }

    /// Os RIPs dos quadros a partir de `start` (`exact`: o primeiro RIP é o da
    /// falha, não um retorno), enquanto a pilha sobe; `end` fica com o motivo
    /// do fim.
    fn walk(&mut self, start: Registers, exact: bool, frames: &mut [u64; MAX_FRAMES]) -> usize {
        let sentinel = win32_thunk::kernel_thread_return();
        let mut registers = start;
        let mut count = 0;
        self.end = WalkEnd::Limit;
        while count < MAX_FRAMES {
            let rip = registers.rip;
            if rip == 0 {
                self.end = WalkEnd::Zero;
                break;
            }
            if rip == sentinel {
                self.end = WalkEnd::NativeStart;
                break;
            }
            if !system_address(rip) {
                self.end = WalkEnd::OutsideSystem(rip);
                break;
            }
            frames[count] = rip;
            count += 1;
            let rsp = registers.integer[RSP];
            if let Err(fail) = frame_walk::unwind_frame_why(self, &mut registers, exact && count == 1) {
                self.end = WalkEnd::Unwind(fail);
                break;
            }
            if registers.integer[RSP] <= rsp {
                self.end = WalkEnd::NoProgress(registers.integer[RSP]);
                break;
            }
        }
        count
    }
}

impl Memory for Walker {
    fn read<T: GuestScalar>(&mut self, address: u64) -> Option<T> {
        let last = address.checked_add(T::SIZE - 1)?;
        let first_page = self.page(address & !0xFFF)?;
        let last_page = self.page(last & !0xFFF)?;
        if first_page == Page::Virtual && last_page == Page::Virtual {
            return Some(guest::read::<T>(address));
        }
        // Uma página de sessão de outra raiz: byte a byte pelo físico.
        let mut bits = 0u64;
        for index in 0..T::SIZE {
            let at = address + index;
            let page = if at & !0xFFF == address & !0xFFF { first_page } else { last_page };
            let byte = match page {
                Page::Virtual => guest::read::<u8>(at),
                Page::Physical(frame) => physical::read8(frame + (at & 0xFFF)),
            };
            bits |= (byte as u64) << (index * 8);
        }
        Some(T::from_bits(bits))
    }
}

impl Images for Walker {
    fn image(&mut self, address: u64) -> Option<(u64, u64)> {
        self.module(address).map(|module| (module.base, module.size))
    }

    /// Sem RUNTIME_FUNCTION: no kernel (fora dos trampolins dos exports, que
    /// não montam quadro), a cadeia de RBP; nas outras imagens, função folha.
    fn frameless(&mut self, pc: u64, registers: &mut Registers) -> Option<()> {
        let (stubs, count) = win32_thunk::thunk_table();
        let in_stubs = pc >= stubs && pc - stubs < count as u64 * win32_thunk::STUB_SIZE;
        if !in_stubs && self.module(pc).is_some_and(|module| module.base == KERNEL_VIRTUAL_BASE) {
            return self.frame_pointer_step(registers);
        }
        frame_walk::pop_return(self, registers)
    }
}

/// O registro das imagens, sem esperar a trava.
fn registered_module(address: u64) -> Option<Module> {
    let mut found = None;
    loaded_images::try_for_each(|image| {
        let mut module = Module { base: image.image_base, size: image.size_of_image, name: Name::EMPTY };
        if found.is_none() && module.contains(address) {
            for byte in image.name.rsplit(['\\', '/']).next().unwrap_or(&image.name).bytes() {
                if !module.name.push(byte) {
                    break;
                }
            }
            found = Some(module);
        }
    });
    found
}

// ---- consultas do autoteste -----------------------------------------------------

/// `módulo+deslocamento (Export+distância)` de um endereço de sistema.
pub fn describe(out: &mut impl Write, address: u64, range: u64) {
    Walker::new().describe(out, address, range);
}

/// O destino da chamada que volta em `return_address`.
pub fn call_target(return_address: u64) -> Option<u64> {
    Walker::new().call_target(return_address)
}

/// A faixa pode ser lida pelo diagnóstico.
pub fn readable(address: u64, length: u64) -> bool {
    let mut walker = Walker::new();
    length != 0 && address.checked_add(length - 1).is_some_and(|last| (address & !0xFFF..=last & !0xFFF).step_by(0x1000).all(|page| walker.page(page).is_some()))
}

/// A cadeia de RBP a partir de quem chama: quantos retornos couberam em
/// `frames`.
#[inline(never)]
pub fn kernel_frames(frames: &mut [u64; MAX_FRAMES]) -> usize {
    kernel_frames_into(&mut Walker::new(), frames).0
}
