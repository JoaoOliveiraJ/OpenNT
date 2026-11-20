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
//! Breakpoints na metade de usuário: o 0xCC mora num byte físico, e é esse
//! byte (não a VA) que identifica o breakpoint. O host arma pela raiz do
//! processo escolhido (`kd::process_context`), e a raiz entra na lista de
//! donos do slot. Um quadro de código compartilhado (a ntdll e as DLLs
//! mapeadas por seção de imagem) leva o 0xCC a todos os processos que o
//! mapeiam, em qualquer VA: o `int 3` de um dono para a máquina, o de outro
//! processo passa sem parar (`classify_user_hit`). Bytes físicos diferentes
//! na mesma VA (o executável de cada processo, uma cópia privada) têm slots
//! separados.
//!
//! - Copy-on-write (`page_copied`): a cópia privada de uma página leva os
//!   0xCC do quadro. O breakpoint do processo que copiou segue com ele para
//!   o quadro novo; o quadro compartilhado volta ao byte original quando o
//!   processo era o único dono. O 0xCC de um breakpoint alheio sai da cópia.
//! - Saída do processo (`process_exited`) e vista de imagem desmapeada
//!   (`view_unmapped`): o processo deixa de ser dono, e o slot sem dono
//!   devolve o byte original enquanto o quadro ainda é da imagem.
//! - Antes de devolver um byte de usuário, o byte atual é conferido (tem de
//!   ser o 0xCC): um quadro que mudou de dono não leva bytes alheios.
//!
//! O dono da parada altera as tabelas com os outros processadores
//! congelados. Com a máquina rodando, só o copy-on-write, a saída de
//! processo e o desmapeamento mexem nelas (campos atômicos, o endereço
//! publicado por último). A entrada de um trap só consulta.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use super::memory;
use crate::hal::cpu;
use crate::ntos::ke::pcr;
use crate::hal::physical::direct_map_limit;
use crate::ntos::mm::memory_map::direct_map;

const SOFTWARE_SLOTS: usize = 64;
/// Processos donos de um mesmo byte físico de usuário.
const OWNERS: usize = 8;
const INT3: u8 = 0xCC;
/// Endereços abaixo daqui são da metade de usuário (a raiz importa).
const USER_LIMIT: u64 = 0x8000_0000_0000;
/// Os bits do endereço físico da raiz no CR3 (sem PCID e sem flags).
const ROOT_ADDRESS: u64 = 0x000F_FFFF_FFFF_F000;
const PAGE_MASK: u64 = !0xFFF;
const PAGE: u64 = 0x1000;

fn is_user(address: u64) -> bool {
    address < USER_LIMIT
}

/// A raiz sem os bits baixos do CR3 (a comparação entre donos).
fn root_key(cr3: u64) -> u64 {
    cr3 & ROOT_ADDRESS
}

fn read_physical(physical: u64) -> Option<u8> {
    if physical >= direct_map_limit() {
        return None;
    }
    // SAFETY: o mapa direto cobre toda a faixa física abaixo do limite.
    Some(unsafe { core::ptr::read_volatile(direct_map(physical) as *const u8) })
}

/// Grava `byte` no byte físico só se o atual for `expected`.
fn write_physical_checked(physical: u64, expected: u8, byte: u8) {
    if read_physical(physical) == Some(expected) {
        // SAFETY: o mesmo byte do mapa direto lido acima (abaixo do limite).
        unsafe { core::ptr::write_volatile(direct_map(physical) as *mut u8, byte) };
    }
}

struct Software {
    /// A VA (0 = livre). Na metade de usuário, a VA do primeiro dono.
    address: AtomicU64,
    /// Sistema: a raiz da gravação. Usuário: a do primeiro dono (só para
    /// consulta).
    cr3: AtomicU64,
    /// Usuário: o endereço físico do byte (a identidade do breakpoint).
    physical: AtomicU64,
    original: AtomicU8,
    /// O byte original está de volta por um passo.
    suspended: AtomicBool,
    /// Usuário: as raízes donas (0 = entrada livre).
    owners: [AtomicU64; OWNERS],
}

impl Software {
    const fn new() -> Self {
        Self { address: AtomicU64::new(0), cr3: AtomicU64::new(0), physical: AtomicU64::new(0), original: AtomicU8::new(0), suspended: AtomicBool::new(false), owners: [const { AtomicU64::new(0) }; OWNERS] }
    }

    /// Ocupado por um breakpoint da metade de usuário.
    fn user(&self) -> bool {
        let address = self.address.load(Ordering::Acquire);
        address != 0 && is_user(address)
    }

    fn is_owner(&self, root: u64) -> bool {
        let key = root_key(root);
        key != 0 && self.owners.iter().any(|owner| owner.load(Ordering::Relaxed) == key)
    }

    /// Acrescenta uma raiz dona; `false` sem entrada livre.
    fn add_owner(&self, root: u64) -> bool {
        if self.is_owner(root) {
            return true;
        }
        let key = root_key(root);
        key != 0 && self.owners.iter().any(|owner| owner.compare_exchange(0, key, Ordering::AcqRel, Ordering::Relaxed).is_ok())
    }

    fn remove_owner(&self, root: u64) {
        let key = root_key(root);
        for owner in &self.owners {
            let _ = owner.compare_exchange(key, 0, Ordering::AcqRel, Ordering::Relaxed);
        }
    }

    fn owner_count(&self) -> usize {
        self.owners.iter().filter(|owner| owner.load(Ordering::Relaxed) != 0).count()
    }

    fn clear_owners(&self) {
        for owner in &self.owners {
            owner.store(0, Ordering::Relaxed);
        }
    }

    /// Ocupa um slot livre; o endereço é publicado por último.
    fn fill(&self, address: u64, cr3: u64, physical: u64, original: u8) {
        self.cr3.store(cr3, Ordering::Relaxed);
        self.physical.store(physical, Ordering::Relaxed);
        self.original.store(original, Ordering::Relaxed);
        self.suspended.store(false, Ordering::Relaxed);
        self.clear_owners();
        if is_user(address) {
            self.owners[0].store(root_key(cr3), Ordering::Relaxed);
        }
        self.address.store(address, Ordering::Release);
    }

    /// Grava no lugar do breakpoint o byte original (`true`) ou o 0xCC.
    fn write_byte(&self, original: bool) {
        let address = self.address.load(Ordering::Acquire);
        let saved = self.original.load(Ordering::Relaxed);
        let (expected, byte) = if original { (INT3, saved) } else { (saved, INT3) };
        if is_user(address) {
            write_physical_checked(self.physical.load(Ordering::Relaxed), expected, byte);
        } else {
            memory::write(self.cr3.load(Ordering::Relaxed), address, &[byte]);
        }
    }

    /// Devolve o byte original (se o 0xCC está lá) e libera o slot.
    fn release(&self) {
        if self.address.load(Ordering::Acquire) == 0 {
            return;
        }
        if !self.suspended.load(Ordering::Acquire) {
            self.write_byte(true);
        }
        self.clear_owners();
        self.address.store(0, Ordering::Release);
    }

    /// O byte original de volta por um passo.
    fn suspend(&self) {
        if !self.suspended.swap(true, Ordering::AcqRel) {
            self.write_byte(true);
        }
    }

    /// O 0xCC de volta depois do passo.
    fn restore(&self) {
        if self.suspended.swap(false, Ordering::AcqRel) {
            self.write_byte(false);
        }
    }
}

static SOFTWARE: [Software; SOFTWARE_SLOTS] = [const { Software::new() }; SOFTWARE_SLOTS];

fn free_slot() -> Option<&'static Software> {
    SOFTWARE.iter().find(|slot| slot.address.load(Ordering::Acquire) == 0)
}

/// O breakpoint de usuário no byte físico `physical`.
fn find_physical(physical: u64) -> Option<&'static Software> {
    SOFTWARE.iter().find(|slot| slot.user() && slot.physical.load(Ordering::Relaxed) == physical)
}

/// O breakpoint em `address` visto pela raiz `cr3`: na metade de sistema
/// pelo endereço; na de usuário pelo byte físico que a raiz traduz.
fn find_at(cr3: u64, address: u64) -> Option<&'static Software> {
    if address == 0 {
        return None;
    }
    if !is_user(address) {
        return SOFTWARE.iter().find(|slot| slot.address.load(Ordering::Acquire) == address);
    }
    find_physical(memory::translate(cr3, address)?)
}

/// O mesmo pela raiz deste processador: as entradas de trap e a saída da
/// parada rodam no espaço da thread interrompida.
fn find_here(address: u64) -> Option<&'static Software> {
    find_at(cpu::read_cr3(), address)
}

/// Insere um breakpoint de software pela raiz `cr3`; `false` sem slot livre
/// ou se o byte não pode ser lido e trocado. Na metade de usuário, um byte
/// físico que já tem breakpoint só ganha o dono novo.
pub fn insert(cr3: u64, address: u64) -> bool {
    if address == 0 {
        return false;
    }
    if !is_user(address) {
        if find_at(cr3, address).is_some() {
            return true;
        }
        let Some(slot) = free_slot() else { return false };
        let Some(original) = memory::read_u8(cr3, address) else { return false };
        if memory::write(cr3, address, &[INT3]) != 1 {
            return false;
        }
        slot.fill(address, cr3, 0, original);
        return true;
    }
    let Some(physical) = memory::translate(cr3, address) else { return false };
    if let Some(slot) = find_physical(physical) {
        return slot.add_owner(cr3);
    }
    let Some(slot) = free_slot() else { return false };
    let Some(original) = read_physical(physical) else { return false };
    write_physical_checked(physical, original, INT3);
    slot.fill(address, cr3, physical, original);
    true
}

/// Tira o breakpoint de `address` do processo de raiz `cr3`. Na metade de
/// usuário, o byte original só volta quando sai o último dono; uma raiz que
/// não é dona (o host sem processo escolhido) tira o breakpoint de todos, e
/// sem byte traduzível vale o primeiro breakpoint de usuário naquela VA.
pub fn remove(cr3: u64, address: u64) -> bool {
    let slot = match find_at(cr3, address) {
        Some(slot) => slot,
        None if address != 0 && is_user(address) => match SOFTWARE.iter().find(|slot| slot.address.load(Ordering::Acquire) == address) {
            Some(slot) => slot,
            None => return false,
        },
        None => return false,
    };
    if slot.user() && slot.is_owner(cr3) {
        slot.remove_owner(cr3);
        if slot.owner_count() != 0 {
            return true;
        }
    }
    slot.release();
    true
}

/// De quem é o `int 3` de usuário em `address` executado com a raiz `cr3`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HitOwner {
    /// De um processo dono do breakpoint: a parada.
    Mine,
    /// Outro processo que mapeia o mesmo quadro: passa sem parar.
    Foreign,
    /// Nenhum breakpoint do depurador naquele byte físico.
    None,
}

pub fn classify_user_hit(address: u64, cr3: u64) -> HitOwner {
    let Some(slot) = find_at(cr3, address) else { return HitOwner::None };
    if slot.suspended.load(Ordering::Acquire) {
        return HitOwner::None;
    }
    if slot.is_owner(cr3) {
        HitOwner::Mine
    } else {
        HitOwner::Foreign
    }
}

/// Remove todos (o host se desligou).
pub fn remove_all() {
    for slot in SOFTWARE.iter() {
        slot.release();
    }
    for index in 0..HARDWARE_SLOTS {
        HARDWARE_KIND[index].store(0, Ordering::Release);
    }
}

/// KdpSuspendAllBreakpoints: os bytes originais voltam à memória (o
/// depurador desligado pelo KdDisableDebugger).
pub fn suspend_all() {
    for slot in SOFTWARE.iter().filter(|slot| slot.address.load(Ordering::Acquire) != 0) {
        slot.suspend();
    }
}

/// KdpRestoreAllBreakpoints: os 0xCC voltam (KdEnableDebugger).
pub fn restore_all() {
    for slot in SOFTWARE.iter().filter(|slot| slot.address.load(Ordering::Acquire) != 0) {
        slot.restore();
    }
}

/// Há um breakpoint de software ativo (com o 0xCC na memória) em `address`,
/// no espaço deste processador.
pub fn inserted_at(address: u64) -> bool {
    find_here(address).is_some_and(|slot| !slot.suspended.load(Ordering::Acquire))
}

/// Devolve o byte original por um passo.
pub fn suspend(address: u64) -> bool {
    let Some(slot) = find_here(address) else { return false };
    slot.suspend();
    true
}

/// Recoloca o 0xCC depois do passo.
pub fn restore(address: u64) {
    if let Some(slot) = find_here(address) {
        slot.restore();
    }
}

/// Onde o byte do breakpoint `slot` (na VA `at`) cai numa faixa
/// `[address, address + length)` lida ou gravada pela raiz `cr3`. Na metade
/// de usuário vale o byte físico: a mesma DLL em outra VA também conta.
fn offset_in(slot: &Software, at: u64, cr3: u64, address: u64, length: usize) -> Option<usize> {
    if !is_user(at) {
        let offset = at.wrapping_sub(address);
        return (offset < length as u64).then_some(offset as usize);
    }
    if !is_user(address) || length == 0 {
        return None;
    }
    let physical = slot.physical.load(Ordering::Relaxed);
    let end = address.saturating_add(length as u64);
    let mut page = address & PAGE_MASK;
    while page < end {
        if memory::translate(cr3, page).is_some_and(|frame| frame & PAGE_MASK == physical & PAGE_MASK) {
            let offset = (page | (physical & 0xFFF)).wrapping_sub(address);
            if offset < length as u64 {
                return Some(offset as usize);
            }
        }
        page += PAGE;
    }
    None
}

/// Troca, numa leitura de `bytes` em `address` pela raiz `cr3`, cada 0xCC
/// de breakpoint pelo byte original.
pub fn mask_read(cr3: u64, address: u64, bytes: &mut [u8]) {
    for slot in SOFTWARE.iter() {
        let at = slot.address.load(Ordering::Acquire);
        if at == 0 || slot.suspended.load(Ordering::Acquire) {
            continue;
        }
        if let Some(offset) = offset_in(slot, at, cr3, address, bytes.len()) {
            bytes[offset] = slot.original.load(Ordering::Relaxed);
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
        if let Some(offset) = offset_in(slot, at, cr3, address, bytes.len()) {
            slot.original.store(bytes[offset], Ordering::Relaxed);
            bytes[offset] = INT3;
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

/// Copy-on-write: a página `page` (VA alinhada) da raiz `root` trocou o
/// quadro `frame` pela cópia privada `copy`, que leva os bytes do quadro,
/// os 0xCC inclusive. Chamado por quem fez a cópia, antes ou logo depois
/// de a PTE apontar para ela.
pub fn page_copied(root: u64, page: u64, frame: u64, copy: u64) {
    if !super::stop::active() || !is_user(page) || root_key(root) == 0 {
        return;
    }
    let (frame, copy) = (frame & PAGE_MASK, copy & PAGE_MASK);
    for slot in SOFTWARE.iter() {
        if !slot.user() {
            continue;
        }
        let physical = slot.physical.load(Ordering::Relaxed);
        if physical & PAGE_MASK != frame {
            continue;
        }
        let moved = copy | (physical & 0xFFF);
        let original = slot.original.load(Ordering::Relaxed);
        let suspended = slot.suspended.load(Ordering::Acquire);
        if !slot.is_owner(root) {
            // A cópia de quem não é dono não leva o 0xCC (o processo
            // executaria um `int 3` que ninguém reconhece).
            if !suspended {
                write_physical_checked(moved, INT3, original);
            }
            continue;
        }
        if slot.owner_count() == 1 {
            // O único dono leva o breakpoint para o quadro novo; o
            // compartilhado, que outros processos executam, volta ao byte
            // original. Suspenso, o original já está nos dois, e o 0xCC volta
            // no fim do passo pelo quadro novo.
            slot.physical.store(moved, Ordering::Release);
            slot.cr3.store(root, Ordering::Relaxed);
            slot.address.store(page | (physical & 0xFFF), Ordering::Release);
            if !suspended {
                write_physical_checked(physical, INT3, original);
            }
            continue;
        }
        // Os outros donos ficam no quadro compartilhado; este processo ganha
        // um slot no quadro novo, armado (sem slot livre, a cópia sai sem o
        // 0xCC e o processo perde o breakpoint).
        slot.remove_owner(root);
        match free_slot() {
            Some(fresh) => {
                write_physical_checked(moved, original, INT3);
                fresh.fill(page | (physical & 0xFFF), root, moved, original);
            }
            None => {
                if !suspended {
                    write_physical_checked(moved, INT3, original);
                }
            }
        }
    }
}

/// O processo de raiz `root` saiu (antes de o espaço de endereços ser
/// desmontado): deixa de ser dono dos breakpoints de usuário, e os que
/// ficam sem dono devolvem o byte original (o quadro pode ser de uma imagem
/// que outros processos ainda executam).
pub fn process_exited(root: u64) {
    if root_key(root) == 0 {
        return;
    }
    for slot in SOFTWARE.iter() {
        if slot.user() && slot.is_owner(root) {
            slot.remove_owner(root);
            if slot.owner_count() == 0 {
                slot.release();
            }
        }
    }
}

/// Uma vista de imagem da raiz `root` saiu (NtUnmapViewOfSection, a saída
/// do processo): os breakpoints do processo nos quadros dela (`frames`, os
/// protótipos e as cópias privadas) saem antes de os quadros voltarem ao
/// PFN.
pub fn view_unmapped(root: u64, frames: &[u64]) {
    if !super::stop::active() || root_key(root) == 0 {
        return;
    }
    for slot in SOFTWARE.iter() {
        if !slot.user() || !slot.is_owner(root) {
            continue;
        }
        let page = slot.physical.load(Ordering::Relaxed) & PAGE_MASK;
        if frames.iter().any(|&frame| frame & PAGE_MASK == page) {
            slot.remove_owner(root);
            if slot.owner_count() == 0 {
                slot.release();
            }
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
