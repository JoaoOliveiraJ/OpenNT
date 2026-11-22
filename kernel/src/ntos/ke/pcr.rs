//! PCR de cada processador.
//!
//! Memória virtual do kernel com páginas físicas próprias, uma reserva de
//! `layout::SIZE` bytes por processador a partir de `PCR_VIRTUAL_BASE`
//! (número do processador * SIZE), publicada em IA32_GS_BASE da CPU dona: o
//! BSP a carrega em `init`, e cada AP na entrada (`ap_kernel_entry`), com a
//! KPCR que `init_processor` montou antes do SIPI. Os campos são os da `Kpcr`
//! gerada dos símbolos (a KPRCB embutida em +0x180, a LockQueue dentro dela);
//! o CurrentThread de cada uma é a thread corrente daquela CPU (gs:[188h]),
//! gravado pela troca de thread que roda nela, junto com o Used_Self
//! (gs:[30h], a TEB da thread de usuário que entra, como no SwapContext).
//! Na cauda da reserva, depois da KPCR, fica o bloco de execução de usuário
//! da CPU (`hal::amd64::usermode::UserExecutionBlock`), endereçado pelos
//! stubs por `gs:`.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::{cpu, physical};
use crate::hal::amd64::native_call;
use crate::ntos::inc::types::{Kpcr, Kprcb, Kthread, NtStruct};
use crate::ntos::mm::paging::{self, MapOptions};
use crate::ntos::mm::{kernel_address, memory_map as map, pfn};
use crate::rtl::{KernelError, SpinLock};

/// Offsets da KPCR/KPRCB (derivados dos tipos gerados) para quem ainda lê
/// por deslocamento; a reserva de 0xC000 bytes cobre a KPCR de 0xB080 e o
/// bloco de execução de usuário logo depois dela.
pub mod layout {
    use core::mem::{offset_of, size_of};

    use crate::hal::amd64::usermode::UserExecutionBlock;
    use crate::ntos::inc::types::{Kpcr, KpcrView1, Kprcb};

    pub const GDT_BASE: u64 = offset_of!(KpcrView1, gdt_base) as u64;
    pub const TSS_BASE: u64 = offset_of!(KpcrView1, tss_base) as u64;
    pub const USER_RSP: u64 = offset_of!(KpcrView1, user_rsp) as u64;
    pub const SELF: u64 = offset_of!(KpcrView1, self_) as u64;
    pub const CURRENT_PRCB: u64 = offset_of!(KpcrView1, current_prcb) as u64;
    pub const LOCK_ARRAY: u64 = offset_of!(KpcrView1, lock_array) as u64;
    pub const USED_SELF: u64 = offset_of!(KpcrView1, used_self) as u64;
    pub const IDT_BASE: u64 = offset_of!(Kpcr, idt_base) as u64;
    pub const MAJOR_VERSION: u64 = offset_of!(Kpcr, major_version) as u64;
    pub const MINOR_VERSION: u64 = offset_of!(Kpcr, minor_version) as u64;
    pub const STALL_SCALE_FACTOR: u64 = offset_of!(Kpcr, stall_scale_factor) as u64;
    pub const PRCB: u64 = offset_of!(Kpcr, prcb) as u64;
    pub const PRCB_MXCSR: u64 = PRCB + offset_of!(Kprcb, mx_csr) as u64;
    pub const PRCB_CURRENT_THREAD: u64 = PRCB + offset_of!(Kprcb, current_thread) as u64;
    pub const PRCB_NEXT_THREAD: u64 = PRCB + offset_of!(Kprcb, next_thread) as u64;
    pub const PRCB_IDLE_THREAD: u64 = PRCB + offset_of!(Kprcb, idle_thread) as u64;
    pub const PRCB_NESTING_LEVEL: u64 = PRCB + offset_of!(Kprcb, nesting_level) as u64;
    pub const PRCB_NUMBER: u64 = PRCB + offset_of!(Kprcb, number) as u64;
    /// KPRCB.IpiFrozen: o estado de congelamento do processador (o
    /// depurador do kernel, `kd::stop`).
    pub const PRCB_IPI_FROZEN: u64 = PRCB + offset_of!(Kprcb, ipi_frozen) as u64;
    pub const LOCK_QUEUE_ARRAY: u64 = PRCB + offset_of!(Kprcb, lock_queue) as u64;
    pub const PRCB_DPC_ROUTINE_ACTIVE: u64 = PRCB + offset_of!(Kprcb, dpc_routine_active) as u64;
    pub const PRCB_DPC_REQUEST_SUMMARY: u64 = PRCB + offset_of!(Kprcb, dpc_request_summary) as u64;
    /// KPRCB.RspBase: o topo da pilha de kernel que a entrada de syscall
    /// carrega (`mov rsp, gs:[1A8h]` do KiSystemCall64).
    pub const PRCB_RSP_BASE: u64 = PRCB + offset_of!(Kprcb, rsp_base) as u64;
    /// Bloco de execução de usuário da CPU, alinhado a 64 depois da KPCR.
    pub const USER_EXECUTION: u64 = (size_of::<Kpcr>() as u64 + 63) & !63;
    /// Contadores de posse de SpinLock e de SharedLock da CPU
    /// (`rtl::sync`), logo depois do bloco de execução de usuário.
    pub const SPIN_LOCKS_HELD: u64 = (USER_EXECUTION + size_of::<UserExecutionBlock>() as u64 + 15) & !15;
    pub const SHARED_LOCKS_HELD: u64 = SPIN_LOCKS_HELD + 4;
    /// As chamadas nativas em curso da CPU (`hal::amd64::native_call`): o
    /// contexto nativo agendado que executa e a posse de execução nativa
    /// síncrona, células da thread corrente que a troca leva.
    pub const NATIVE_FRAME: u64 = SPIN_LOCKS_HELD + 8;
    pub const NATIVE_OWNER: u64 = NATIVE_FRAME + 8;
    /// A GDT da CPU (16 entradas) e a TSS dela (104 bytes), que o
    /// `usermode::processor_user_mode_init` monta e publica em
    /// KPCR.GdtBase/TssBase, como as que o KiInitializeProcessor do 19041
    /// aloca para cada processador.
    pub const PROCESSOR_GDT: u64 = (NATIVE_OWNER + 8 + 63) & !63;
    pub const PROCESSOR_TSS: u64 = PROCESSOR_GDT + 0x80;
    /// Os tiques do timer local de um AP (vetor 0x41), contados pelo stub de
    /// interrupção pelo GS.
    pub const PROCESSOR_TICKS: u64 = PROCESSOR_TSS + 0x70;
    pub const SIZE: u64 = 0xC000;

    const _: () = assert!(size_of::<Kpcr>() as u64 <= SIZE);
    const _: () = assert!(USER_EXECUTION + size_of::<UserExecutionBlock>() as u64 <= SIZE);
    const _: () = assert!(SHARED_LOCKS_HELD + 4 <= NATIVE_FRAME && NATIVE_OWNER + 8 <= PROCESSOR_GDT && PROCESSOR_TICKS + 4 <= SIZE);
    const _: () = assert!(USER_RSP == 0x10 && PRCB_CURRENT_THREAD == 0x188 && PRCB_RSP_BASE == 0x1A8);
}

/// KSPIN_LOCK_QUEUE_NUMBER das entradas com lock próprio.
const LOCK_QUEUE_NON_PAGED_POOL: usize = 6;
const LOCK_QUEUE_IO_VPB: usize = 9;
const LOCK_QUEUE_IO_DATABASE: usize = 10;

const GS_BASE_MSR: u32 = 0xC000_0101;
/// GDTR do stage2 publicado no handoff (limite em +0, base de 32 bits em +2).
const DESCRIPTOR_TABLE_REGISTER_CELL: u64 = map::BOOT_GDTR_PHYS;

/// A KPCR de um AP: número do processador, VA e frames.
struct Secondary {
    number: u32,
    address: u64,
    backing_pages: Vec<u64>,
}

struct Pcr {
    address: u64,
    backing_pages: Vec<u64>,
    secondary: Vec<Secondary>,
    io_database_lock: u64,
    vpb_lock: u64,
}

static PCR: SpinLock<Pcr> = SpinLock::new(Pcr { address: 0, backing_pages: Vec::new(), secondary: Vec::new(), io_database_lock: 0, vpb_lock: 0 });
static ADDRESS: AtomicU64 = AtomicU64::new(0);

/// A KPCR da CPU corrente (nenhuma antes de `init`): o aninhamento e os
/// pedidos de DPC são do processador que executa, e as entradas da
/// LockQueue de todos apontam para os mesmos KSPIN_LOCKs.
fn kpcr() -> Option<&'static Kpcr> {
    (ADDRESS.load(Ordering::Acquire) != 0).then(current)
}

/// A VA da reserva do processador `number`.
fn reservation(number: u32) -> u64 {
    map::PCR_VIRTUAL_BASE + number as u64 * layout::SIZE
}

const _: () = assert!(map::PCR_VIRTUAL_BASE + map::MAX_CPUS as u64 * layout::SIZE <= map::KERNEL_DATA_POOL_BASE);

/// Aloca, zera e mapeia as páginas de uma reserva (com rollback) e devolve
/// os frames.
fn map_reservation(base: u64) -> Result<Vec<u64>, KernelError> {
    let mut pages = Vec::new();
    for offset in (0..layout::SIZE).step_by(0x1000) {
        let page = pfn::alloc_page();
        let ok = page != 0 && {
            pages.push(page);
            physical::zero(page, 0x1000);
            paging::map_page(base + offset, page, paging::PAGE_PRESENT | paging::PAGE_RW, MapOptions::default())
        };
        if !ok {
            unmap_reservation(base, &pages[..pages.len() - (page != 0) as usize]);
            if page != 0 {
                pfn::free_page(page);
            }
            return Err(KernelError::new(if page == 0 { "sem frames p/ a KPCR" } else { "mapeamento da KPCR falhou" }));
        }
    }
    Ok(pages)
}

/// Desmapeia as primeiras `pages.len()` páginas da reserva e devolve os frames.
fn unmap_reservation(base: u64, pages: &[u64]) {
    for (index, &page) in pages.iter().enumerate() {
        paging::unmap_page(base + index as u64 * 0x1000, MapOptions::default());
        pfn::free_page(page);
    }
}

/// Campos iniciais comuns a toda KPCR (o KiInitializePcr): referências
/// próprias, a LockQueue, versão, MXCSR e o número do processador. O IRQL
/// não mora aqui: é o CR8 de cada CPU (`irql`).
fn initialize(kpcr: &Kpcr, number: u32, io_database_lock: u64, vpb_lock: u64) -> Result<(), KernelError> {
    let base = kpcr.address();
    kpcr.self_.set(base);
    kpcr.current_prcb.set(kpcr.prcb.address());
    let lock_queue = &kpcr.prcb.lock_queue;
    kpcr.lock_array.set(lock_queue[0].address());
    // Como o KiInitSpinLocks: toda entrada da LockQueue, de toda CPU, aponta
    // para um KSPIN_LOCK global; as do pool, da VPB e da base de I/O vêm em
    // seguida.
    for (number, entry) in lock_queue.iter().enumerate() {
        let lock = kernel_address::image_address(QUEUED_SPIN_LOCKS.as_ptr() as u64 + number as u64 * 8)?;
        entry.next.set(0);
        entry.lock.set(lock);
    }
    // LockQueueNonPagedPoolLock recebe o lock real do alocador.
    let pool_lock = kernel_address::image_address(native_call::non_paged_pool_lock_address())?;
    lock_queue[LOCK_QUEUE_NON_PAGED_POOL].lock.set(pool_lock);
    if io_database_lock != 0 {
        lock_queue[LOCK_QUEUE_IO_DATABASE].lock.set(io_database_lock);
    }
    if vpb_lock != 0 {
        lock_queue[LOCK_QUEUE_IO_VPB].lock.set(vpb_lock);
    }
    // O KiSystemStartup só grava o Self; o Used_Self é a TEB da última
    // thread de usuário que entrou (`set_current_thread`), nenhuma no boot.
    kpcr.used_self.set(0);
    kpcr.major_version.set(1);
    kpcr.minor_version.set(1);
    kpcr.prcb.mx_csr.set(0x1F80);
    kpcr.prcb.number.set(number);
    Ok(())
}

/// Aloca e mapeia as páginas da PCR (com rollback), publica as referências
/// próprias, os campos iniciais e a GS base.
pub fn init() -> Result<(), KernelError> {
    let mut pcr = PCR.lock();
    if pcr.address != 0 {
        return Ok(());
    }
    let base = reservation(0);
    pcr.backing_pages = map_reservation(base)?;
    pcr.address = base;
    // SAFETY: as páginas recém-zeradas acabaram de ser mapeadas em `base`.
    let kpcr = unsafe { Kpcr::at(base) };

    // A GDT do stage2 continua a mesma; o GDTR (que o stage2 já carregou
    // assim) e a KPCR a alcançam pela VA do mapa direto.
    let gdt_limit = physical::read16(DESCRIPTOR_TABLE_REGISTER_CELL);
    let gdt_base = physical::to_virtual(physical::read32(DESCRIPTOR_TABLE_REGISTER_CELL + 2) as u64);
    cpu::load_gdt(gdt_base, gdt_limit);
    kpcr.gdt_base.set(gdt_base);
    // TssBase fica zerado; isso não descreve a TSS configurada em outras camadas.
    kpcr.tss_base.set(0);
    initialize(kpcr, 0, pcr.io_database_lock, pcr.vpb_lock)?;
    kpcr.idt_base.set(crate::nano::interrupts::IDT_VIRTUAL_ADDRESS);
    drop(pcr);

    // Só depois de materializar os campos ativa a PCR como base de GS.
    cpu::write_msr(GS_BASE_MSR, base);
    ADDRESS.store(base, Ordering::Release);
    native_call::publish_processor_cells();
    // Daqui em diante toda CPU que executa o kernel tem o GS na sua KPCR (os
    // APs o carregam na entrada): as posses de lock passam a ser contadas.
    crate::rtl::sync::publish_lock_counters(layout::SPIN_LOCKS_HELD, layout::SHARED_LOCKS_HELD);
    debug_print!("[pcr] KPCR em {:#x} — GS base ativa (IA32_GS_BASE)", base);
    Ok(())
}

/// KPCR do AP que vai receber o número `number` (1..MAX_CPUS), montada
/// antes do SIPI com os mesmos campos iniciais da do BSP; o AP a publica em
/// IA32_GS_BASE na entrada. GdtBase, IdtBase e TssBase ficam zerados: os
/// APs ainda usam a GDT e a IDT mínimas da imagem e não têm TSS. Devolve a VA.
pub fn init_processor(number: u32) -> Result<u64, KernelError> {
    if number == 0 || number as usize >= map::MAX_CPUS {
        return Err(KernelError::new("numero de processador invalido p/ a KPCR"));
    }
    let mut pcr = PCR.lock();
    if pcr.address == 0 {
        return Err(KernelError::new("KPCR do BSP ausente"));
    }
    if let Some(existing) = pcr.secondary.iter().find(|secondary| secondary.number == number) {
        return Ok(existing.address);
    }
    let base = reservation(number);
    let backing_pages = map_reservation(base)?;
    // SAFETY: as páginas recém-zeradas acabaram de ser mapeadas em `base`.
    if let Err(error) = initialize(unsafe { Kpcr::at(base) }, number, pcr.io_database_lock, pcr.vpb_lock) {
        unmap_reservation(base, &backing_pages);
        return Err(error);
    }
    pcr.secondary.push(Secondary { number, address: base, backing_pages });
    Ok(base)
}

/// Desfaz a KPCR de um número que nenhum AP assumiu (o AP não respondeu e
/// foi reiniciado).
pub fn release_processor(number: u32) {
    let mut pcr = PCR.lock();
    if let Some(index) = pcr.secondary.iter().position(|secondary| secondary.number == number) {
        let secondary = pcr.secondary.swap_remove(index);
        unmap_reservation(secondary.address, &secondary.backing_pages);
    }
}

/// A KPCR da CPU corrente, por gs:[KPCR.Self] (o KeGetPcr do NT). Vale em
/// qualquer CPU depois de `init`/`ap_kernel_entry`; o anel 0 sempre tem a
/// KPCR no GS (a do usuário fica no KernelGSbase).
pub fn current_address() -> u64 {
    let address: u64;
    // SAFETY: leitura de um campo da KPCR desta CPU, mapeada desde que o GS a publica.
    unsafe { core::arch::asm!("mov {}, gs:[{}]", out(reg) address, const layout::SELF, options(nostack, readonly, preserves_flags)) };
    address
}

/// A `Kpcr` da CPU corrente.
pub fn current() -> &'static Kpcr {
    // SAFETY: a KPCR de cada CPU fica mapeada por toda a vida do sistema.
    unsafe { Kpcr::at(current_address()) }
}

/// KeGetCurrentThread: KPRCB.CurrentThread da CPU que executa, gs:[188h]
/// (o mesmo `mov rax, gs:[188h]` que os drivers fazem inline); 0 antes da
/// KPCR do BSP. Cada CPU tem a sua: threads em CPUs diferentes ao mesmo
/// tempo veem cada uma a si mesma.
pub fn current_thread() -> u64 {
    if ADDRESS.load(Ordering::Acquire) == 0 {
        return 0;
    }
    let thread: u64;
    // SAFETY: leitura de um campo da KPCR desta CPU (o GS do anel 0 é sempre
    // a KPCR, publicada antes de qualquer código do kernel nesta CPU).
    unsafe { core::arch::asm!("mov {}, gs:[{}]", out(reg) thread, const layout::PRCB_CURRENT_THREAD, options(nostack, readonly, preserves_flags)) };
    thread
}

/// A troca de thread corrente desta CPU grava KPRCB.CurrentThread na KPCR
/// dela (pelo GS), nunca na de outra CPU. Antes da KPCR do BSP não há onde
/// gravar.
///
/// Como o SwapContext do 19041, a troca para uma thread que não é de
/// sistema também grava em KPCR.Used_Self (NtTib.Self, gs:[30h]) a
/// KTHREAD.Teb dela; numa thread de sistema (MiscFlags.SystemThread), ou
/// sem thread, o SwapContext pula o estado de usuário e o Used_Self fica o
/// da última thread de usuário. É por ele que o código de kernel acha a TEB
/// corrente, o NtCurrentTeb do anel 0: o xxxCreateThreadInfo do win32kbase
/// aponta o pClientInfo da THREADINFO para gs:[30h] + 0x800
/// (TEB.Win32ClientInfo), onde o win32k grava o CallbackWnd dos callbacks
/// de janela que a user32 lê de volta.
pub fn set_current_thread(thread: u64) {
    if ADDRESS.load(Ordering::Acquire) != 0 {
        let kpcr = current();
        kpcr.prcb.current_thread.set(thread);
        if thread != 0 {
            // SAFETY: quem troca a thread corrente passa uma KTHREAD viva.
            let kthread = unsafe { Kthread::at(thread) };
            if kthread.system_thread() == 0 {
                kpcr.used_self.set(kthread.teb.get());
            }
        }
    }
}

pub fn get_pcr_address() -> u64 {
    ADDRESS.load(Ordering::Acquire)
}

/// A VA da KPRCB do processador `number`, pela reserva fixa dele (sem
/// trava: o despacho a lê a cada escolha). Só vale para um processador
/// online, cuja KPCR fica mapeada por toda a vida do sistema.
pub fn prcb_address(number: u32) -> u64 {
    reservation(number) + layout::PRCB
}

/// KiProcessorBlock[number]: a KPRCB embutida na KPCR do processador
/// `number`, entre os que estão online (KeNumberProcessors); None para os
/// demais.
pub fn processor_block(number: u32) -> Option<&'static Kprcb> {
    if number as usize >= super::smp::online_cpu_count() {
        return None;
    }
    all().into_iter().map(|kpcr| &kpcr.prcb).find(|prcb| prcb.number.get() == number)
}

/// KeQueryPrcbAddress: a entrada de KiProcessorBlock do processador; sem
/// KPRCB, NULL.
pub fn query_prcb_address(number: u32) -> u64 {
    processor_block(number).map_or(0, |prcb| prcb.address())
}

/// Todas as KPCRs publicadas (a do BSP primeiro).
fn all() -> Vec<&'static Kpcr> {
    let pcr = PCR.lock();
    let addresses = core::iter::once(pcr.address).filter(|&address| address != 0).chain(pcr.secondary.iter().map(|secondary| secondary.address));
    // SAFETY: cada reserva listada fica mapeada enquanto está no registro.
    addresses.map(|address| unsafe { Kpcr::at(address) }).collect()
}

pub fn set_io_database_lock(pointer: u64) {
    PCR.lock().io_database_lock = pointer;
    for kpcr in all() {
        kpcr.prcb.lock_queue[LOCK_QUEUE_IO_DATABASE].lock.set(pointer);
    }
}

/// LockQueueMaximumLock.
pub const LOCK_QUEUE_MAXIMUM: u64 = 17;

/// Os KSPIN_LOCK globais das entradas da LockQueue sem lock de dono.
static QUEUED_SPIN_LOCKS: [AtomicU64; LOCK_QUEUE_MAXIMUM as usize] = [const { AtomicU64::new(0) }; LOCK_QUEUE_MAXIMUM as usize];

/// O KSPIN_LOCK da entrada `number` da LockQueue (sem os bits de dono e de
/// espera).
pub fn queued_spin_lock(number: u64) -> Option<u64> {
    if number >= LOCK_QUEUE_MAXIMUM {
        return None;
    }
    kpcr().map(|kpcr| kpcr.prcb.lock_queue[number as usize].lock.get() & !3).filter(|&lock| lock != 0)
}

pub fn set_io_vpb_lock(pointer: u64) {
    PCR.lock().vpb_lock = pointer;
    for kpcr in all() {
        kpcr.prcb.lock_queue[LOCK_QUEUE_IO_VPB].lock.set(pointer);
    }
}

pub fn get_nesting_level() -> u8 {
    kpcr().map_or(0, |kpcr| kpcr.prcb.nesting_level.get())
}

pub fn get_dpc_request_summary() -> u32 {
    kpcr().map_or(0, |kpcr| kpcr.prcb.dpc_request_summary.get() as u32)
}

/// Campos que `enter_dpc` altera, para restaurar depois do callback.
#[derive(Clone, Copy, Debug)]
pub struct DpcState {
    pub nesting: u8,
    pub active: u32,
    pub routine: u8,
}

/// Publica que uma DPC está em execução.
pub fn enter_dpc() -> Result<DpcState, KernelError> {
    if get_pcr_address() == 0 {
        return Err(KernelError::new("DPC dispatch requires initialized PCR"));
    }
    let Some(kpcr) = kpcr() else { return Err(KernelError::new("DPC dispatch requires initialized PCR")) };
    let prcb = &kpcr.prcb;
    let previous = DpcState {
        nesting: prcb.nesting_level.get(),
        active: prcb.dpc_request_summary.get() as u32 & 1,
        routine: prcb.dpc_routine_active.get(),
    };
    prcb.nesting_level.set(1);
    // DpcRequestSummary bit 0 (DpcNormalProcessingActive): LOCK OR, como o
    // NT, porque outras CPUs pedem DPCs no mesmo DWORD.
    prcb.dpc_request_summary.atomic().fetch_or(1, Ordering::SeqCst);
    prcb.dpc_routine_active.set(1);
    Ok(previous)
}

/// Restaura rotina ativa, bit de atividade e aninhamento.
pub fn leave_dpc(previous: DpcState) {
    let Some(kpcr) = kpcr() else { return };
    let prcb = &kpcr.prcb;
    prcb.dpc_routine_active.set(previous.routine);
    if previous.active == 0 {
        prcb.dpc_request_summary.atomic().fetch_and(!1, Ordering::SeqCst);
    } else {
        prcb.dpc_request_summary.atomic().fetch_or(1, Ordering::SeqCst);
    }
    prcb.nesting_level.set(previous.nesting);
}
