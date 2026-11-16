//! Breakpoints do depurador do kernel.
//!
//! Software: o byte original dá lugar a um `int 3` (0xCC), gravado pelo
//! quadro físico (`kd::memory`), por cima da proteção da página de código.
//! As leituras de memória do host veem o byte original, e uma escrita do
//! host sobre um breakpoint troca o original guardado. Para continuar de um
//! breakpoint, o byte original volta por um passo (`suspend`/`restore`).
//!
//! Hardware: DR0-DR3 com o DR7, em execução, escrita ou acesso (leitura ou
//! escrita: o x86 não vigia só leitura). O conjunto fica também em
//! KPRCB.ProcessorState.SpecialRegisters.KernelDr0-3/KernelDr7 do
//! processador que os carrega, onde o NT guarda os registradores de depuração
//! do kernel (o KdpAllowDisable recusa desligar o depurador com algum
//! habilitado ali).
//!
//! Breakpoints na metade de usuário: o 0xCC vai ao quadro físico pela raiz
//! do processo escolhido (`kd::process_context`). Um quadro de código
//! compartilhado (a ntdll e as DLLs mapeadas por seção de imagem) leva o
//! 0xCC a todos os processos que o mapeiam; o `int 3` de outro processo é
//! reconhecido pelo quadro físico e passa sem parar (`classify_user_hit`).
//! Antes de gravar num endereço de usuário, o byte atual é conferido: um
//! processo que saiu não leva bytes alheios.
//!
//! Só o dono da parada altera as tabelas; a entrada de um trap só consulta.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use super::memory;
use crate::ntos::ke::pcr;

const SOFTWARE_SLOTS: usize = 64;
const INT3: u8 = 0xCC;
/// Endereços abaixo daqui são da metade de usuário (a raiz importa).
const USER_LIMIT: u64 = 0x8000_0000_0000;

/// Grava `byte` em `address` pela raiz `cr3`; num endereço de usuário, só
/// se o byte atual for `expected` (a página ainda é a do breakpoint).
fn write_checked(cr3: u64, address: u64, expected: u8, byte: u8) {
    if address < USER_LIMIT && memory::read_u8(cr3, address) != Some(expected) {
        return;
    }
    memory::write(cr3, address, &[byte]);
}

/// O byte em `address` pela raiz `at` é o mesmo byte físico do breakpoint
/// gravado pela raiz `slot` (sempre, na metade de sistema).
fn same_frame(slot: u64, at: u64, address: u64) -> bool {
    address >= USER_LIMIT || slot == at || matches!((memory::translate(slot, address), memory::translate(at, address)), (Some(a), Some(b)) if a == b)
}

struct Software {
    /// 0 = livre.
    address: AtomicU64,
    cr3: AtomicU64,
    original: AtomicU8,
    /// O byte original está de volta por um passo.
    suspended: AtomicBool,
}

impl Software {
    const fn new() -> Self {
        Self { address: AtomicU64::new(0), cr3: AtomicU64::new(0), original: AtomicU8::new(0), suspended: AtomicBool::new(false) }
    }
}

static SOFTWARE: [Software; SOFTWARE_SLOTS] = [const { Software::new() }; SOFTWARE_SLOTS];

fn find(address: u64) -> Option<&'static Software> {
    SOFTWARE.iter().find(|slot| slot.address.load(Ordering::Acquire) == address && address != 0)
}

/// Insere um breakpoint de software; `false` sem slot livre ou se o byte
/// não pode ser lido e trocado.
pub fn insert(cr3: u64, address: u64) -> bool {
    if find(address).is_some() {
        return true;
    }
    let Some(slot) = SOFTWARE.iter().find(|slot| slot.address.load(Ordering::Acquire) == 0) else { return false };
    let Some(original) = memory::read_u8(cr3, address) else { return false };
    if memory::write(cr3, address, &[INT3]) != 1 {
        return false;
    }
    slot.cr3.store(cr3, Ordering::Relaxed);
    slot.original.store(original, Ordering::Relaxed);
    slot.suspended.store(false, Ordering::Relaxed);
    slot.address.store(address, Ordering::Release);
    true
}

/// Remove o breakpoint de `address`, devolvendo o byte original.
pub fn remove(address: u64) -> bool {
    let Some(slot) = find(address) else { return false };
    let cr3 = slot.cr3.load(Ordering::Relaxed);
    if !slot.suspended.load(Ordering::Acquire) {
        write_checked(cr3, address, INT3, slot.original.load(Ordering::Relaxed));
    }
    slot.address.store(0, Ordering::Release);
    true
}

/// De quem é o `int 3` de usuário em `address` executado com a raiz `cr3`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HitOwner {
    /// Do processo do breakpoint: a parada.
    Mine,
    /// Outro processo que mapeia o mesmo quadro: passa sem parar.
    Foreign,
    /// Nenhum breakpoint do depurador naquele byte físico.
    None,
}

pub fn classify_user_hit(address: u64, cr3: u64) -> HitOwner {
    let Some(slot) = find(address) else { return HitOwner::None };
    if slot.suspended.load(Ordering::Acquire) {
        return HitOwner::None;
    }
    let root = slot.cr3.load(Ordering::Relaxed);
    if root == cr3 {
        HitOwner::Mine
    } else if same_frame(root, cr3, address) {
        HitOwner::Foreign
    } else {
        HitOwner::None
    }
}

/// Remove todos (o host se desligou).
pub fn remove_all() {
    for slot in SOFTWARE.iter() {
        let address = slot.address.load(Ordering::Acquire);
        if address != 0 {
            remove(address);
        }
    }
    for index in 0..HARDWARE_SLOTS {
        HARDWARE_KIND[index].store(0, Ordering::Release);
    }
}

/// KdpSuspendAllBreakpoints: os bytes originais voltam à memória (o
/// depurador desligado pelo KdDisableDebugger).
pub fn suspend_all() {
    for slot in SOFTWARE.iter() {
        let address = slot.address.load(Ordering::Acquire);
        if address != 0 {
            suspend(address);
        }
    }
}

/// KdpRestoreAllBreakpoints: os 0xCC voltam (KdEnableDebugger).
pub fn restore_all() {
    for slot in SOFTWARE.iter() {
        let address = slot.address.load(Ordering::Acquire);
        if address != 0 {
            restore(address);
        }
    }
}

/// Há um breakpoint de software ativo (com o 0xCC na memória) em `address`.
pub fn inserted_at(address: u64) -> bool {
    find(address).is_some_and(|slot| !slot.suspended.load(Ordering::Acquire))
}

/// Devolve o byte original por um passo.
pub fn suspend(address: u64) -> bool {
    let Some(slot) = find(address) else { return false };
    if !slot.suspended.swap(true, Ordering::AcqRel) {
        write_checked(slot.cr3.load(Ordering::Relaxed), address, INT3, slot.original.load(Ordering::Relaxed));
    }
    true
}

/// Recoloca o 0xCC depois do passo.
pub fn restore(address: u64) {
    if let Some(slot) = find(address) {
        if slot.suspended.swap(false, Ordering::AcqRel) {
            write_checked(slot.cr3.load(Ordering::Relaxed), address, slot.original.load(Ordering::Relaxed), INT3);
        }
    }
}

/// Troca, numa leitura de `bytes` em `address` pela raiz `cr3`, cada 0xCC
/// de breakpoint pelo byte original.
pub fn mask_read(cr3: u64, address: u64, bytes: &mut [u8]) {
    for slot in SOFTWARE.iter() {
        let at = slot.address.load(Ordering::Acquire);
        if at == 0 || slot.suspended.load(Ordering::Acquire) {
            continue;
        }
        let offset = at.wrapping_sub(address);
        if offset < bytes.len() as u64 && same_frame(slot.cr3.load(Ordering::Relaxed), cr3, at) {
            bytes[offset as usize] = slot.original.load(Ordering::Relaxed);
        }
    }
}

/// Uma escrita do host (pela raiz `cr3`) sobre breakpoints muda o byte
/// original guardado e mantém o 0xCC na memória.
pub fn shadow_write(cr3: u64, address: u64, bytes: &mut [u8]) {
    for slot in SOFTWARE.iter() {
        let at = slot.address.load(Ordering::Acquire);
        if at == 0 || slot.suspended.load(Ordering::Acquire) {
            continue;
        }
        let offset = at.wrapping_sub(address);
        if offset < bytes.len() as u64 && same_frame(slot.cr3.load(Ordering::Relaxed), cr3, at) {
            slot.original.store(bytes[offset as usize], Ordering::Relaxed);
            bytes[offset as usize] = INT3;
        }
    }
}

/// Endereços dos breakpoints de software ativos, para o `monitor bl`.
pub fn software_list(mut each: impl FnMut(u64)) {
    for slot in SOFTWARE.iter() {
        let at = slot.address.load(Ordering::Acquire);
        if at != 0 {
            each(at);
        }
    }
}

// ---- hardware ----------------------------------------------------------------

const HARDWARE_SLOTS: usize = 4;

/// Tipo de um breakpoint de hardware (campo R/W do DR7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Watch {
    Execute,
    Write,
    Access,
}

impl Watch {
    fn code(self) -> u8 {
        match self {
            Watch::Execute => 1,
            Watch::Write => 2,
            Watch::Access => 3,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Watch::Execute),
            2 => Some(Watch::Write),
            3 => Some(Watch::Access),
            _ => None,
        }
    }

    fn read_write_bits(self) -> u64 {
        match self {
            Watch::Execute => 0,
            Watch::Write => 1,
            Watch::Access => 3,
        }
    }
}

/// 0 = livre; senão `Watch::code`.
static HARDWARE_KIND: [AtomicU8; HARDWARE_SLOTS] = [const { AtomicU8::new(0) }; HARDWARE_SLOTS];
static HARDWARE_ADDRESS: [AtomicU64; HARDWARE_SLOTS] = [const { AtomicU64::new(0) }; HARDWARE_SLOTS];
static HARDWARE_LENGTH: [AtomicU8; HARDWARE_SLOTS] = [const { AtomicU8::new(0) }; HARDWARE_SLOTS];

fn length_bits(length: u64) -> Option<u64> {
    match length {
        1 => Some(0),
        2 => Some(1),
        4 => Some(3),
        8 => Some(2),
        _ => None,
    }
}

/// Arma um comparador; `false` sem comparador livre ou com tamanho e
/// alinhamento que o x86 não aceita (execução sempre com tamanho 1).
pub fn insert_hardware(kind: Watch, address: u64, length: u64) -> bool {
    let length = if kind == Watch::Execute { 1 } else { length };
    if length_bits(length).is_none() || address % length != 0 {
        return false;
    }
    for index in 0..HARDWARE_SLOTS {
        if HARDWARE_KIND[index].load(Ordering::Acquire) == kind.code() && HARDWARE_ADDRESS[index].load(Ordering::Relaxed) == address {
            return true;
        }
    }
    for index in 0..HARDWARE_SLOTS {
        if HARDWARE_KIND[index].load(Ordering::Acquire) == 0 {
            HARDWARE_ADDRESS[index].store(address, Ordering::Relaxed);
            HARDWARE_LENGTH[index].store(length as u8, Ordering::Relaxed);
            HARDWARE_KIND[index].store(kind.code(), Ordering::Release);
            return true;
        }
    }
    false
}

pub fn remove_hardware(kind: Watch, address: u64) -> bool {
    for index in 0..HARDWARE_SLOTS {
        if HARDWARE_KIND[index].load(Ordering::Acquire) == kind.code() && HARDWARE_ADDRESS[index].load(Ordering::Relaxed) == address {
            HARDWARE_KIND[index].store(0, Ordering::Release);
            return true;
        }
    }
    false
}

/// O comparador `index` armado: tipo, endereço e tamanho.
pub fn hardware_slot(index: usize) -> Option<(Watch, u64, u64)> {
    let kind = Watch::from_code(HARDWARE_KIND.get(index)?.load(Ordering::Acquire))?;
    Some((kind, HARDWARE_ADDRESS[index].load(Ordering::Relaxed), HARDWARE_LENGTH[index].load(Ordering::Relaxed) as u64))
}

/// DR7 correspondente aos comparadores armados (habilitação global, com o
/// GE ligado quando há vigia de dados, e o bit 10 reservado em 1).
pub fn dr7() -> u64 {
    let mut value = 0x400u64;
    for index in 0..HARDWARE_SLOTS {
        if let Some((kind, _, length)) = hardware_slot(index) {
            value |= 1 << (index * 2 + 1);
            value |= (kind.read_write_bits() | length_bits(length).unwrap_or(0) << 2) << (16 + index * 4);
            if kind != Watch::Execute {
                value |= 1 << 9;
            }
        }
    }
    value
}

/// Um comparador de execução armado em `address` (o retorno precisa do RF
/// para não disparar de novo na mesma instrução).
pub fn hardware_execute_at(address: u64) -> bool {
    (0..HARDWARE_SLOTS).any(|index| matches!(hardware_slot(index), Some((Watch::Execute, at, _)) if at == address))
}

/// Carrega o conjunto nos registradores de depuração deste processador e o
/// publica na KPRCB dele.
pub fn load_into_processor() {
    let addresses: [u64; 4] = core::array::from_fn(|index| hardware_slot(index).map_or(0, |(_, address, _)| address));
    let control = dr7();
    // SAFETY: registradores de depuração do processador corrente, em anel 0.
    unsafe {
        core::arch::asm!("mov dr0, {}", in(reg) addresses[0], options(nostack));
        core::arch::asm!("mov dr1, {}", in(reg) addresses[1], options(nostack));
        core::arch::asm!("mov dr2, {}", in(reg) addresses[2], options(nostack));
        core::arch::asm!("mov dr3, {}", in(reg) addresses[3], options(nostack));
        core::arch::asm!("mov dr6, {}", in(reg) 0xFFFF_0FF0u64, options(nostack));
        core::arch::asm!("mov dr7, {}", in(reg) control, options(nostack));
    }
    if pcr::get_pcr_address() != 0 {
        let special = &pcr::current().prcb.processor_state.special_registers;
        special.kernel_dr0.set(addresses[0]);
        special.kernel_dr1.set(addresses[1]);
        special.kernel_dr2.set(addresses[2]);
        special.kernel_dr3.set(addresses[3]);
        special.kernel_dr7.set(if control & 0xFF != 0 { control } else { 0 });
    }
}

/// Desliga os comparadores durante a parada (uma vigia de dados não pode
/// disparar dentro do próprio depurador).
pub fn disarm_processor() {
    // SAFETY: DR7 do processador corrente, em anel 0.
    unsafe { core::arch::asm!("mov dr7, {}", in(reg) 0x400u64, options(nostack)) };
}

/// Algum comparador armado (o KdDisableDebugger recusa).
pub fn any_hardware() -> bool {
    (0..HARDWARE_SLOTS).any(|index| hardware_slot(index).is_some())
}
