//! O estado de execução por CPU (`ke/pcr.rs`, `hal/amd64/usermode.rs`): cada
//! processador tem a sua KPCR, publicada no próprio GS, e nela o bloco de
//! execução de usuário; a entrada de syscall grava a pilha do usuário na
//! KPCR.UserRsp (gs:[10h]) da CPU que a executa.
//!
//! Uma syscall de teste, publicada na tabela 1 do Shadow para uma thread GUI
//! (o caminho do KiSystemCall64 inteiro: SWAPGS, KPRCB.RspBase, a busca no
//! descritor e a chamada MS x64), devolve o gs:[10h] que vê, e o programa de
//! anel 3 compara com o próprio RSP. Nos APs, um job lê o GS da CPU e grava
//! no próprio bloco: os blocos são distintos e cada um tem o seu número de
//! processador.

use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use crate::hal::amd64::usermode::{self, UserExecutionBlock};
use crate::hal::cpu;
use crate::ntos::ex::service_table;
use crate::ntos::inc::types::{Ethread, Kpcr, NtStruct};
use crate::ntos::ke::pcr::{self, layout};
use crate::ntos::ke::smp;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::memory_map as map;
use crate::ntos::ps::{cid, process};
use crate::ntos::ps::user::{memory, state};

type Assert = fn(bool, &str);

const IA32_GS_BASE: u32 = 0xC000_0101;
/// Primeiro serviço da tabela 1 (o índice 0 da tabela gráfica).
const TEST_SERVICE: u32 = 0x1000;

/// A tabela compactada de um serviço, na imagem do kernel: a entrada é
/// relativa à tabela e só alcança ±128 MB, então a rotina e a tabela moram
/// na mesma imagem.
static SERVICE_TABLE: [AtomicU32; 1] = [AtomicU32::new(0)];
static SERVICE_ARGUMENTS: [AtomicU8; 4] = [const { AtomicU8::new(0) }; 4];

/// O serviço de teste: a KPCR.UserRsp desta CPU, por gs:[10h].
extern "win64" fn user_rsp_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    let value: u64;
    // SAFETY: leitura de um campo da KPCR desta CPU.
    unsafe { core::arch::asm!("mov {}, gs:[{}]", out(reg) value, const layout::USER_RSP, options(nostack, readonly, preserves_flags)) };
    value
}

/// Job de AP: grava `marker` no código de saída do bloco da própria CPU e
/// devolve a VA do bloco, alcançado pelo GS. 0: o GS do AP não aponta para
/// nada; 1: gs:[KPCR.Self] não é a base do GS.
extern "win64" fn ap_block_job(marker: u64, _: u64, _: u64, _: u64) -> u64 {
    let base = cpu::read_msr(IA32_GS_BASE);
    if base == 0 {
        return 0;
    }
    if pcr::current_address() != base {
        return 1;
    }
    let block = usermode::block();
    block.exit_code.set(marker as u32);
    block.address()
}

fn kpcr_of(number: u64) -> u64 {
    map::PCR_VIRTUAL_BASE + number * layout::SIZE
}

/// Cada CPU tem a sua KPCR no GS e, nela, o seu bloco.
fn distinct_blocks(assert: Assert) {
    let own = usermode::block();
    assert(pcr::current_address() == kpcr_of(0) && pcr::current().prcb.number.get() == 0 && own.address() == kpcr_of(0) + layout::USER_EXECUTION, "por-cpu: o BSP alcanca a propria KPCR e o bloco pelo GS");
    if smp::discovered_cpu_count() > 1 {
        assert(smp::ap_slot_count() > 0, "por-cpu: algum AP online para comparar");
    }
    let saved_exit = own.exit_code.get();
    let mut seen = alloc::vec![own.address()];
    for index in 0..smp::ap_slot_count() {
        let Some(slot) = smp::ap_slot(index) else { break };
        let number = index as u64 + 1;
        let marker = 0xA0 + number;
        let result = smp::run_on_ap(slot, ap_block_job as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64, [marker, 0, 0, 0]);
        let expected = kpcr_of(number) + layout::USER_EXECUTION;
        assert(result.as_ref().is_ok_and(|&block| block != 0), "por-cpu: o AP tem KPCR no GS");
        assert(result.as_ref().is_ok_and(|&block| block != 1), "por-cpu: gs:[KPCR.Self] do AP e a base do GS");
        let Ok(block) = result else { continue };
        if block != expected {
            assert(false, "por-cpu: o bloco do AP fica na KPCR do seu numero");
            continue;
        }
        // SAFETY: a KPCR do AP online fica mapeada por toda a vida do sistema.
        let (kpcr, ap_block) = unsafe { (Kpcr::at(kpcr_of(number)), UserExecutionBlock::at(block)) };
        assert(kpcr.prcb.number.get() as u64 == number && kpcr.self_.get() == kpcr_of(number) && kpcr.current_prcb.get() == kpcr.prcb.address(), "por-cpu: KPCR do AP com Self, CurrentPrcb e o numero do processador");
        assert(!seen.contains(&block), "por-cpu: blocos de CPUs diferentes sao distintos");
        assert(ap_block.exit_code.get() as u64 == marker && own.exit_code.get() == saved_exit, "por-cpu: a escrita do AP fica no bloco dele");
        ap_block.exit_code.set(0);
        seen.push(block);
    }
}

/// Uma syscall de anel 3 vê, em gs:[10h], o RSP do usuário na entrada.
fn syscall_user_rsp(assert: Assert) {
    if !usermode::ready() || state::with(|state| state.name_by_number.get(&0x2C).is_none()) {
        assert(false, "por-cpu: anel 3 armado e NtTerminateProcess registrado");
        return;
    }
    let Ok(saved_shadow) = service_table::shadow_second_table() else {
        assert(false, "por-cpu: descritores de servico publicados");
        return;
    };
    let table = SERVICE_TABLE.as_ptr() as u64;
    let Ok(entry) = service_table::encode_entry(table, user_rsp_service as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64, 0) else {
        assert(false, "por-cpu: entrada do servico de teste");
        return;
    };
    SERVICE_TABLE[0].store(entry, Ordering::Release);
    let scratch = guest::alloc_bytes(16);
    let allocate = |size: u64, protect: u32| {
        guest::write64(scratch, 0);
        guest::write64(scratch + 8, size);
        let status = memory::do_user_allocate(scratch, scratch + 8, 0x3000, protect, 0x10000, 0x7FFF_FFFF_0000, 0x10000).unwrap_or(1);
        if status == 0 { guest::read64(scratch) } else { 0 }
    };
    let (code, stack) = (allocate(0x1000, 0x40), allocate(0x4000, 4));
    let previous = process::get_current_thread();
    let thread = process::create_kernel_thread(process::get_current_process(), cid::ALLOCATE, true, 1, None);
    if code != 0 && stack != 0 && service_table::publish_shadow_second_table(table, 1, SERVICE_ARGUMENTS.as_ptr() as u64).is_ok() {
        if let Ok(thread) = thread {
            let stack_top = stack + 0x4000 - 0x28;
            // syscall TEST_SERVICE; [rsp+10h] = rax; edx = (rax == rsp);
            // NtTerminateProcess(-1, edx).
            let mut program = alloc::vec![0xB8];
            program.extend_from_slice(&TEST_SERVICE.to_le_bytes());
            program.extend_from_slice(&[0x49, 0x89, 0xCA, 0x0F, 0x05, 0x48, 0x89, 0x44, 0x24, 0x10, 0x31, 0xD2, 0x48, 0x39, 0xE0, 0x0F, 0x94, 0xC2]);
            program.extend_from_slice(&[0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0x49, 0x89, 0xCA, 0xB8, 0x2C, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xEB, 0xFE]);
            guest::write_bytes(code, &program);
            guest::write64(stack_top + 0x10, 0);
            // A thread GUI busca no Shadow, cuja tabela 1 é a de teste.
            // SAFETY: a ETHREAD acabou de ser criada e é retida até o fim.
            let tcb = &unsafe { Ethread::at(thread) }.tcb;
            tcb.set_gui_thread(1);
            process::set_current_thread(thread);
            let saved_exit = usermode::block().exit_code.get();
            let exited = usermode::exec_user_mode(code, stack_top, 0, 0, 0, 0);
            usermode::block().exit_code.set(saved_exit);
            process::set_current_thread(previous);
            tcb.set_gui_thread(0);
            let seen = guest::read64(stack_top + 0x10);
            assert(seen == stack_top && exited == 1, "por-cpu: a syscall de teste devolve gs:[10h] igual ao RSP do usuario na entrada");
            assert(pcr::current().user_rsp.get() == stack_top && (1..=smp::ap_slot_count() as u64).all(|number| unsafe { Kpcr::at(kpcr_of(number)) }.user_rsp.get() == 0), "por-cpu: so a KPCR da CPU que executou a syscall guarda a pilha do usuario");
        } else {
            assert(false, "por-cpu: thread da syscall de teste");
        }
    } else {
        assert(false, "por-cpu: memoria de usuario e tabela 1 de teste");
    }
    let _ = service_table::restore_shadow_second_table(saved_shadow);
    SERVICE_TABLE[0].store(0, Ordering::Release);
    if let Ok(thread) = thread {
        let _ = process::release_thread(thread);
    }
    guest::free_bytes(scratch);
    for base in [code, stack] {
        if let Some(region) = memory::find_region(base).filter(|_| base != 0) {
            memory::release_private_region(&region);
        }
    }
}

pub fn run(assert: Assert) {
    distinct_blocks(assert);
    syscall_user_rsp(assert);
}
