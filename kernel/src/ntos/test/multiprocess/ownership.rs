//! O modo estrito de posse (`mm/guest_memory`, com o verificador
//! `ps/user/memory::check_user_access`): a sonda de uma página de usuário
//! presente exige o processo dono corrente (o anexado conta) ou uma faixa de
//! sistema compartilhada.
//!
//! - o modo está ligado (a suíte inteira roda com ele);
//! - de A, a leitura e a escrita de uma região de B são recusadas e
//!   registradas com o dono, o processo corrente, a thread e a linha do
//!   chamador; a de B fica intacta. Do System, sem anexar, também;
//! - anexado a B (aninhado dentro de A, e pelo KeStackAttachProcess), o
//!   mesmo acesso passa e lê o valor de B;
//! - de A, a visão de usuário da KUSER_SHARED_DATA, a ntdll, o apiset e o
//!   NLS passam;
//! - uma página de usuário presente fora de todo VAD é recusada sem dono, e
//!   uma VA sem página só dá ACCESS_VIOLATION, sem violação;
//! - a conclusão de um IRP de modo usuário de uma thread de A, chegando no
//!   contexto do System, copia o SystemBuffer e o IOSB para A anexada a ele,
//!   sem violação.
//!
//! As violações são capturadas para a thread do teste
//! (`guest_memory::capture_ownership_violations`); fora da captura cada uma
//! pararia o sistema com `*** PANIC`.

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{IoStatusBlock, Irp, KapcState, KuserSharedData};
use crate::ntos::io::io_manager;
use crate::ntos::io::irp_builder::{self, BuildOptions};
use crate::ntos::ke::process_attachment;
use crate::ntos::mm::guest_memory::{self as guest, OwnershipViolation, STATUS_ACCESS_VIOLATION};
use crate::ntos::mm::paging::{self, MapOptions, PAGE_PRESENT, PAGE_RW, PAGE_USER};
use crate::ntos::mm::pfn;
use crate::ntos::ps::{cid, process, process_context};
use crate::ntos::ps::user::{loader, memory, state};
use crate::rtl::KernelError;

type Assert = fn(bool, &str);

const A_VALUE: u64 = 0x0A0A_0000_0000_00A1;
const B_VALUE: u64 = 0x0B0B_0000_0000_00B1;

/// `body` com as violações de posse desta thread capturadas.
fn captured<T>(body: impl FnOnce() -> T) -> (T, alloc::vec::Vec<OwnershipViolation>) {
    guest::capture_ownership_violations(process::get_current_thread(), body)
}

/// `body` anexado a `target` (o escopo de KeStackAttachProcess do Ps).
fn within<T>(target: u64, body: impl FnOnce() -> T) -> Option<T> {
    process_context::with_process(target, body).ok()
}

fn refused<T>(result: &Option<Result<T, KernelError>>) -> bool {
    matches!(result, Some(Err(error)) if error.status == STATUS_ACCESS_VIOLATION)
}

/// Uma violação da VA, do dono e do processo corrente, chamada deste
/// arquivo pela thread do teste.
fn names(violations: &[OwnershipViolation], address: u64, write: bool, owner: u64, current: u64) -> bool {
    let thread = process::get_current_thread();
    matches!(violations, [violation] if violation.address == address && violation.write == write && violation.fault.owner == owner && violation.fault.current == current && violation.fault.thread == thread && violation.caller.file().ends_with("ownership.rs"))
}

pub fn run(assert: Assert) {
    assert(guest::ownership_check_enabled(), "posse: modo estrito ligado na suite");
    if process::get_current_thread() == 0 {
        assert(false, "posse: thread corrente para anexar");
        return;
    }
    let created = [process::create_process(cid::ALLOCATE, "posse-a.exe", 0, None), process::create_process(cid::ALLOCATE, "posse-b.exe", 0, None)];
    let [Ok(a), Ok(b)] = created else {
        for process in created.into_iter().flatten() {
            let _ = process::terminate_process(process, 0);
        }
        assert(false, "posse: processos A e B criados");
        return;
    };
    // Uma região em cada um, montada anexado e gravada pelo dono.
    let region = |target: u64, value: u64| within(target, || memory::map_user_region(0x1000).ok().filter(|&base| guest::try_write::<u64>(base, value).is_ok())).flatten().unwrap_or(0);
    let (a_region, b_region) = (region(a, A_VALUE), region(b, B_VALUE));
    if a_region == 0 || b_region == 0 {
        assert(false, "posse: regioes de A e de B");
    } else {
        cross_process(assert, [a, b], [a_region, b_region]);
        shared_ranges(assert, a);
        unowned(assert, a);
        irp_completion(assert, a, a_region);
    }
    for process in [a, b] {
        let _ = process::terminate_process(process, 0);
    }
}

/// O acesso de A (ou do System) à região de B é recusado e registrado;
/// anexado a B, passa.
fn cross_process(assert: Assert, [a, b]: [u64; 2], [a_region, b_region]: [u64; 2]) {
    let (read, violations) = captured(|| within(a, || guest::try_read::<u64>(b_region)));
    assert(refused(&read) && names(&violations, b_region, false, b, a), "posse: leitura de A numa regiao de B recusada e registrada com o dono");
    let (written, violations) = captured(|| within(a, || guest::try_write::<u64>(b_region, A_VALUE)));
    let intact = within(b, || guest::try_read::<u64>(b_region).ok()).flatten() == Some(B_VALUE);
    assert(refused(&written) && names(&violations, b_region, true, b, a) && intact, "posse: escrita de A numa regiao de B recusada e a de B intacta");
    let system = process::get_system_process();
    let (from_system, violations) = captured(|| guest::try_read::<u64>(a_region));
    assert(matches!(&from_system, Err(error) if error.status == STATUS_ACCESS_VIOLATION) && names(&violations, a_region, false, a, system), "posse: o System sem anexar nao toca a regiao de A");

    // Anexado a B, dentro de A: o dono corrente é B.
    let (nested, violations) = captured(|| within(a, || within(b, || guest::try_read::<u64>(b_region).ok())));
    assert(nested == Some(Some(Some(B_VALUE))) && violations.is_empty(), "posse: anexado a B (aninhado em A) o acesso a regiao de B passa");
    // KeStackAttachProcess a B.
    let saved = guest::alloc_bytes(KapcState::SIZE);
    let (stacked, violations) = captured(|| {
        within(a, || {
            if saved == 0 || process_attachment::attach(b, saved).is_err() {
                return None;
            }
            let value = guest::try_read::<u64>(b_region).ok();
            process_attachment::detach(saved).ok().and(value)
        })
    });
    if saved != 0 {
        guest::free_bytes(saved);
    }
    assert(stacked == Some(Some(B_VALUE)) && violations.is_empty(), "posse: KeStackAttachProcess a B libera o acesso a regiao de B");
    let (own, violations) = captured(|| within(a, || guest::try_read::<u64>(a_region).ok()));
    assert(own == Some(Some(A_VALUE)) && violations.is_empty(), "posse: A le a propria regiao");
}

/// As faixas de sistema que todo processo vê na mesma VA passam.
fn shared_ranges(assert: Assert, a: u64) {
    let nls = state::with(|state| state.nls_vas).map_or(0, |vas| vas.ansi);
    let api_set = state::with(|state| state.api_set_map_va);
    let ntdll = loader::ntdll_module().map_or(0, |module| module.image_base);
    assert(nls != 0 && api_set != 0 && ntdll != 0, "posse: NLS, apiset e ntdll mapeados");
    let (seen, violations) = captured(|| {
        within(a, || {
            // SAFETY: a visão de usuário da KUSER_SHARED_DATA; o acesso é sondado.
            let kuser = unsafe { KuserSharedData::at(state::KUSER_SHARED_DATA_USER_VA) }.nt_major_version.probe_get().ok();
            (kuser, guest::try_read::<u16>(ntdll).ok(), guest::try_read::<u32>(api_set).ok(), guest::try_read::<u8>(nls).ok())
        })
    });
    let Some((kuser, mz, schema, table)) = seen else {
        assert(false, "posse: anexado a A para as faixas de sistema");
        return;
    };
    assert(kuser == Some(10) && mz == Some(0x5A4D) && schema.is_some() && table.is_some() && violations.is_empty(), "posse: KUSER_SHARED_DATA, ntdll, apiset e NLS passam de A");
}

/// Página presente fora de todo VAD: recusada sem dono. VA sem página: só
/// ACCESS_VIOLATION.
fn unowned(assert: Assert, a: u64) {
    let Ok(va) = memory::find_free(memory::Space::current(), 0x1000, 0x1_0000, false) else {
        assert(false, "posse: VA livre para a pagina sem dono");
        return;
    };
    let frame = pfn::alloc_page();
    let mapped = frame != 0 && paging::map_page(va, frame, PAGE_PRESENT | PAGE_RW | PAGE_USER, MapOptions { nx: true, ..MapOptions::default() });
    let (read, violations) = captured(|| within(a, || guest::try_read::<u64>(va)));
    let detected = mapped && refused(&read) && names(&violations, va, false, 0, a);
    if mapped {
        paging::unmap_page(va, MapOptions::default());
    }
    if frame != 0 {
        pfn::free_page(frame);
    }
    assert(detected, "posse: pagina de usuario presente fora de todo VAD recusada sem dono");
    let (missing, violations) = captured(|| within(a, || guest::try_read::<u64>(va)));
    assert(refused(&missing) && violations.is_empty(), "posse: VA sem pagina da ACCESS_VIOLATION sem violacao");
}

/// IofCompleteRequest de um IRP de modo usuário de uma thread de A, no
/// contexto do System: o SystemBuffer e o IOSB vão para A, anexado.
fn irp_completion(assert: Assert, a: u64, a_region: u64) {
    let Ok(thread) = process::create_kernel_thread(a, cid::ALLOCATE, true, 1, None) else {
        assert(false, "posse: thread de A para o IRP");
        return;
    };
    let (iosb, output) = (a_region + 0x100, a_region + 0x200);
    let packet = guest::alloc_bytes(irp_builder::size_for(1));
    let system = guest::alloc_bytes(16);
    if packet != 0 && system != 0 {
        guest::write_bytes(system, b"POSSE-OK");
        irp_builder::build(packet, &BuildOptions { major: 3, buffer: system, buffer_length: 8, stack_count: 1, user_iosb: iosb, user_buffer: output, thread, requestor_mode: 1, ..BuildOptions::default() });
        // SAFETY: o IRP recém-montado acima.
        let irp = unsafe { Irp::at(packet) };
        irp.tail.overlay.current_stack_location.set(irp_builder::first_stack_location(packet, 1));
        irp.current_location.set(1);
        irp.io_status.status.set(0);
        irp.io_status.information.set(8);
        let (completed, violations) = captured(|| io_manager::iof_complete_request(packet));
        let seen = within(a, || {
            let block = IoStatusBlock::try_at(iosb).ok()?;
            Some((guest::try_read_bytes(output, 8).ok()?, block.status.probe_get().ok()?, block.information.probe_get().ok()?))
        })
        .flatten();
        assert(completed == 0 && violations.is_empty() && seen == Some((b"POSSE-OK".to_vec(), 0, 8)), "posse: conclusao de IRP de A no contexto do System anexa a A para o IOSB e o buffer");
    } else {
        assert(false, "posse: IRP e SystemBuffer de teste");
    }
    for pointer in [packet, system] {
        if pointer != 0 {
            guest::free_bytes(pointer);
        }
    }
    let _ = process::release_thread(thread);
}
