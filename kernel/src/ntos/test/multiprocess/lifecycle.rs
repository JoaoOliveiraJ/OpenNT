//! Ciclo de vida por processo: o que um processo possui volta quando ELE
//! termina, e só o dele; nada é reiniciado entre um processo e o próximo.
//! O mesmo programa executado três vezes seguidas não deixa delta de PFN
//! nem da arena a partir da segunda execução, e depois de cada saída nada do
//! processo sobra (estado, threads no índice global). Um processo vivo
//! mantém handles, regiões, threads e módulos do loader enquanto outro
//! processo nasce, roda e termina, e perde tudo no próprio término.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::cell::Cell;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Eprocess, Ethread};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::{paging, pfn};
use crate::ntos::ps::{cid, process, process_context};
use crate::ntos::ps::user::loader::{self, Module};
use crate::ntos::ps::user::process::{self as user_process, RunOptions};
use crate::ntos::ps::user::state::{self, UserObject};
use crate::ntos::ps::user::threads::{self, UserThread};
use crate::ntos::ps::user::{memory, process_state};
use crate::rtl::KernelError;

type Assert = fn(bool, &str);

/// O código com que o programa sai.
const EXIT_CODE: u32 = 0x5A;
/// Marca gravada na região do processo vivo.
const MARK: u64 = 0x0A11_CE00_0000_0001;

/// O programa: NtTerminateProcess(-1, 0x5A) pela syscall da ntdll de
/// bring-up, depois do LdrInitializeThunk.
fn program() -> Vec<u8> {
    let entry: &[u8] = &[0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0xBA, 0x5A, 0x00, 0x00, 0x00, 0x49, 0x89, 0xCA, 0xB8, 0x2C, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xEB, 0xFE];
    crate::ntos::test::phase7::single_section_image(0x1_4000_0000, 0x0022, b".text", 0x6000_0020, 0x1000, entry)
}

/// Uma execução do programa: o resultado e o EPROCESS, retido pelo teste
/// desde a criação (o chamador solta). `inspect` vê o processo vivo.
fn run_once(name: &str, inspect: &dyn Fn(u64)) -> (Result<u32, KernelError>, u64) {
    let owner = Cell::new(0u64);
    let created = |process_id: u64| -> Result<(), KernelError> {
        let pointer = process::list_active_processes().into_iter().find(|entry| entry.pid == process_id).map_or(0, |entry| entry.address);
        if pointer != 0 {
            process::reference(pointer);
            inspect(pointer);
        }
        owner.set(pointer);
        Ok(())
    };
    let result = user_process::run_windows_process(Some(program()), name, &format!("C:\\{name}"), None, RunOptions { on_process_created: Some(&created), ..RunOptions::default() });
    (result, owner.get())
}

/// O processo saiu com o código e nada dele sobra nas tabelas: sem estado e
/// sem thread no índice global (o EPROCESS é o retido pelo teste).
fn gone(process: u64) -> bool {
    // SAFETY: EPROCESS retido pelo teste.
    let exit_status = if process != 0 { unsafe { Eprocess::at(process) }.exit_status.get() as u32 } else { 0 };
    process != 0 && exit_status == EXIT_CODE && process_state::get(process).is_none() && !threads::all().iter().any(|thread| thread.with(|thread| thread.process_pointer) == process)
}

/// PFN livre e uso da arena.
fn sample() -> (u64, (usize, u64)) {
    (pfn::free_count(), guest::usage())
}

/// Três execuções seguidas do mesmo programa.
fn repeated_runs(assert: Assert) {
    let mut samples = Vec::new();
    let mut clean = true;
    for round in 0..3 {
        let (result, owner) = run_once("vida.exe", &|_| {});
        let ok = matches!(result, Ok(EXIT_CODE)) && gone(owner);
        if !ok {
            crate::debug_print!("[vida] execucao {}: {:?}, processo {:#x}", round + 1, result.as_ref().map_err(|error| format!("{error}")), owner);
        }
        clean &= ok;
        if owner != 0 {
            let _ = process::dereference(owner);
        }
        samples.push(sample());
    }
    assert(clean, "vida: tres execucoes seguidas saem com o codigo e nada do processo sobra");
    let stable = samples.iter().all(|&taken| taken == samples[0]);
    if !stable {
        crate::debug_print!("[vida] PFN livre e arena (alocacoes, bytes) depois de cada execucao: {:?}", samples);
    }
    assert(stable, "vida: sem delta de PFN nem da arena a partir da segunda execucao");
}

/// Objeto sem corpo nativo, só na tabela de usuário do processo vivo.
struct Plain {
    released: AtomicU32,
}

impl UserObject for Plain {
    fn kind(&self) -> &'static str {
        "event"
    }
    fn release(&self) {
        self.released.fetch_add(1, Ordering::Relaxed);
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// O que o processo vivo possui.
struct Owned {
    region: u64,
    handle: u64,
    thread: Arc<UserThread>,
}

/// Monta o processo vivo A (com PEB): uma região marcada, um handle, uma
/// thread de usuário com KTHREAD próprio e um módulo do loader.
fn populate(process: u64, kernel_thread: u64, object: Arc<dyn UserObject>, module: &Arc<Module>) -> Option<Owned> {
    process_context::with_process(process, || {
        let peb = memory::map_user_region(0x1000).ok()?;
        // SAFETY: EPROCESS vivo criado pelo teste.
        unsafe { Eprocess::at(process) }.peb.set(peb);
        let region = memory::map_user_region(0x1000).ok()?;
        guest::write64(region, MARK);
        let handle = state::alloc_user_handle(object, 0x1F_0003, 0).ok()? as u64;
        // SAFETY: ETHREAD recém-criado pelo teste.
        let thread_id = unsafe { Ethread::at(kernel_thread) }.cid.unique_thread.get();
        let thread = UserThread::new(thread_id, kernel_thread, 0, 0);
        threads::push(thread.clone());
        loader::register_module(module.clone(), None).ok()?;
        Some(Owned { region, handle, thread })
    })
    .ok()
    .flatten()
}

/// Anexado a `process`: a região com a marca, o handle, o módulo e a thread
/// viva na lista do processo.
fn holds(process: u64, owned: &Owned, module: &Arc<Module>) -> bool {
    let listed = threads::of_process(process).iter().any(|thread| Arc::ptr_eq(thread, &owned.thread));
    let attached = process_context::with_process(process, || {
        memory::find_region(owned.region).is_some() && guest::read64(owned.region) == MARK && state::get_user_handle(owned.handle).is_some() && loader::loaded_module("vida-a.dll").is_some_and(|found| Arc::ptr_eq(&found, module))
    });
    listed && attached.unwrap_or(false) && !owned.thread.dead() && owned.thread.pointer() != 0
}

/// Um processo vivo mantém o que é dele enquanto outro nasce e termina.
fn live_process_keeps_its_own(assert: Assert) {
    let Ok(a) = process::create_process(cid::ALLOCATE, "vida-a.exe", 0, None) else {
        assert(false, "vida: processo vivo criado");
        return;
    };
    let Ok(kernel_thread) = process::create_kernel_thread(a, cid::ALLOCATE, true, 1, None) else {
        let _ = process::terminate_process(a, 0);
        assert(false, "vida: thread do processo vivo");
        return;
    };
    let plain = Arc::new(Plain { released: AtomicU32::new(0) });
    let module = Arc::new(Module { name: String::from("vida-a.dll"), full_name: String::from("C:\\Windows\\System32\\vida-a.dll"), image_base: 0, size_of_image: 0, entry_point: 0, exports: Default::default(), is_exe: false, notification_source: None });
    let Some(owned) = populate(a, kernel_thread, plain.clone(), &module) else {
        let _ = process::release_thread(kernel_thread);
        let _ = process::terminate_process(a, 0);
        assert(false, "vida: regiao, handle, thread e modulo do processo vivo");
        return;
    };
    assert(holds(a, &owned, &module) && state::is_user_process(a), "vida: o processo vivo tem regiao, handle, thread e modulo proprios");

    // B nasce, roda e termina; vivo, ele não vê nada de A. B tem raiz
    // própria: na VA da região de A ele pode ter uma região dele, nunca a
    // de A.
    let isolated = Cell::new(false);
    let region_of_a = memory::Space::of(a).find(owned.region);
    let inspect = |b: u64| {
        let foreign = process_context::with_process(b, || memory::find_region(owned.region).is_none_or(|found| region_of_a.as_ref().is_none_or(|mine| !state::same_region(&found, mine))) && state::get_user_handle(owned.handle).is_none() && loader::loaded_module("vida-a.dll").is_none());
        isolated.set(foreign.unwrap_or(false) && !threads::of_process(b).iter().any(|thread| Arc::ptr_eq(thread, &owned.thread)));
    };
    let (result, b) = run_once("vida-b.exe", &inspect);
    assert(matches!(result, Ok(EXIT_CODE)) && isolated.get(), "vida: o outro processo roda sem ver nada do processo vivo");
    assert(gone(b), "vida: nada do outro processo sobra depois da saida dele");
    if b != 0 {
        let _ = process::dereference(b);
    }
    assert(process_state::get(a).is_some() && holds(a, &owned, &module) && plain.released.load(Ordering::Relaxed) == 0, "vida: o processo vivo mantem regiao, handle, thread e modulo depois da saida do outro");

    // O término de A devolve tudo o que era dele: o handle fecha, a região
    // volta ao PFN, a thread morre e sai do índice (com o KTHREAD) e o
    // módulo sai do processo.
    let terminated = process::terminate_process(a, 0).is_ok();
    assert(terminated && process_state::get(a).is_none() && paging::translate(owned.region) == 0 && plain.released.load(Ordering::Relaxed) == 1, "vida: o termino do processo fecha o handle e devolve a regiao");
    let listed = threads::all().iter().any(|thread| Arc::ptr_eq(thread, &owned.thread));
    assert(owned.thread.dead() && owned.thread.pointer() == 0 && !listed && Arc::strong_count(&module) == 1, "vida: o termino do processo solta a thread e o modulo");
}

pub fn run(assert: Assert) {
    if process::get_current_thread() == 0 {
        assert(false, "vida: thread corrente para anexar");
        return;
    }
    if state::with(|state| state.ntdll_exports.as_ref().is_none_or(|exports| !exports.contains_key("LdrInitializeThunk"))) {
        assert(false, "vida: ntdll com LdrInitializeThunk mapeada");
        return;
    }
    repeated_runs(assert);
    live_process_keeps_its_own(assert);
}
