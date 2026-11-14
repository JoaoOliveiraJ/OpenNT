//! A virada: cada processo de usuário roda na própria raiz de tabelas de
//! páginas (`ps::process::create_process` dá a raiz com o processo).
//!
//! - Dois processos de usuário montados ao mesmo tempo pelo caminho real
//!   (`create_windows_process`), de executáveis com ImageBase diferentes,
//!   ganham raízes próprias, distintas e diferentes da do System, gravadas no
//!   KPROCESS; o CR3 de quem os montou continua na raiz dele.
//! - A PEB e a pilha da primeira thread ficam na MESMA VA nos dois, com
//!   conteúdo diferente lido anexado a cada um: a ImageBaseAddress da PEB é a
//!   do exe de cada um, e a marca gravada na pilha de um não aparece na do
//!   outro. Os frames dessas VAs são distintos, e a raiz do System não vê
//!   nenhum deles.
//! - A ntdll está na mesma VA nos dois, com o cabeçalho MZ, em frames
//!   diferentes entre si e da cópia de sistema (cópias privadas).
//! - Depois os dois rodam em sequência e saem com os próprios códigos.
//! - No fim, nada sobra: sem estado, raízes já sem página de usuário além da
//!   visão da KUSER enquanto o EPROCESS está retido, devolvidas no último
//!   dereference, e a contagem livre do PFN de volta à de antes da montagem
//!   (nenhuma tabela, cópia ou frame perdido).
//! - O `run_service` (imagem lida do volume pelo SCM) roda o serviço num
//!   processo com raiz própria e devolve o código de saída.

use alloc::format;

use crate::ntos::inc::types::{Eprocess, Kprocess, NtStruct, Peb};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::process_address_space::{self as address_space, SYSTEM_ROOT};
use crate::ntos::mm::shared_user_data::MM_SHARED_USER_DATA_VA;
use crate::ntos::mm::{kernel_stack, memory_map as map, paging, pfn};
use crate::ntos::ps::{process, process_context};
use crate::ntos::ps::user::process::{self as user_process, CreatedProcess, RunOptions};
use crate::ntos::ps::user::file_io::{self, OpenRequest};
use crate::ntos::ps::user::{loader, memory, process_state, state};
use crate::ntos::cm::service::database::{self as service_database, ConfigurationInput};
use crate::drivers::fs::volume_files;

type Assert = fn(bool, &str);

/// ImageBase e código de saída de cada programa.
const FIRST: (u64, u32) = (0x1_4000_0000, 0x51);
const SECOND: (u64, u32) = (0x1_5000_0000, 0x52);
/// Marcas gravadas na pilha de cada processo, na mesma VA.
const FIRST_MARK: u64 = 0xA0A0_0000_0000_0051;
const SECOND_MARK: u64 = 0xB0B0_0000_0000_0052;

/// NtTerminateProcess(-1, código) pela syscall da ntdll de bring-up, depois
/// do LdrInitializeThunk, num exe com a ImageBase pedida.
fn program(image_base: u64, exit_code: u32) -> alloc::vec::Vec<u8> {
    let code = exit_code.to_le_bytes();
    let entry: &[u8] = &[0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0xBA, code[0], code[1], code[2], code[3], 0x49, 0x89, 0xCA, 0xB8, 0x2C, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xEB, 0xFE];
    crate::ntos::test::phase7::single_section_image(image_base, 0x0022, b".text", 0x6000_0020, 0x1000, entry)
}

/// Monta, sem rodar, um processo do programa; o EPROCESS fica retido pelo
/// teste até o fim.
fn create(name: &str, (image_base, exit_code): (u64, u32)) -> Option<CreatedProcess> {
    match user_process::create_windows_process(Some(program(image_base, exit_code)), name, &format!("C:\\{name}"), None, &RunOptions::default()) {
        Ok(Ok(created)) => {
            process::reference(created.process_pointer);
            Some(created)
        }
        Ok(Err(status)) => {
            crate::debug_print!("[raiz] {} terminou na montagem: {:#x}", name, status);
            None
        }
        Err(error) => {
            crate::debug_print!("[raiz] {} nao montado: {}", name, error);
            None
        }
    }
}

fn directory_table_base(process: u64) -> u64 {
    // SAFETY: EPROCESS retido pelo teste.
    unsafe { Kprocess::at(process) }.directory_table_base.get()
}

fn peb_of(process: u64) -> u64 {
    // SAFETY: EPROCESS retido pelo teste.
    unsafe { Eprocess::at(process) }.peb.get()
}

/// O que se lê anexado ao processo: a ImageBaseAddress da PEB, o cabeçalho
/// da ntdll e a marca da pilha (gravada antes, se pedida).
fn inspect(process: u64, peb: u64, ntdll: u64, mark_at: u64, mark: Option<u64>) -> Option<(u64, u16, u64)> {
    process_context::with_process(process, || {
        if let Some(mark) = mark {
            guest::try_write::<u64>(mark_at, mark).ok()?;
        }
        // SAFETY: a PEB do processo anexado, montada pelo kernel.
        let image_base = unsafe { Peb::at(peb) }.image_base_address.get();
        Some((image_base, guest::try_read::<u16>(ntdll).ok()?, guest::try_read::<u64>(mark_at).ok()?))
    })
    .ok()
    .flatten()
}

/// A metade de usuário da raiz só tem a visão da KUSER_SHARED_DATA.
fn only_kuser(root: u64) -> bool {
    let kuser_end = MM_SHARED_USER_DATA_VA + 0x1000;
    paging::find_mapping_in(root, map::LOWEST_USER_ADDRESS, MM_SHARED_USER_DATA_VA - map::LOWEST_USER_ADDRESS).is_none() && paging::find_mapping_in(root, kuser_end, map::USER_ADDRESS_LIMIT - kuser_end).is_none() && paging::translate_in(root, MM_SHARED_USER_DATA_VA) != 0
}

pub fn run(assert: Assert) {
    if process::get_current_thread() == 0 {
        assert(false, "raiz: thread corrente para anexar");
        return;
    }
    if state::with(|state| state.ntdll_exports.as_ref().is_none_or(|exports| !exports.contains_key("LdrInitializeThunk"))) {
        assert(false, "raiz: ntdll com LdrInitializeThunk mapeada");
        return;
    }
    // As cópias de sistema já existem antes da amostra do PFN.
    let ready = loader::ensure_ntdll().and_then(|_| loader::ensure_api_set_schema()).and_then(|_| loader::ensure_nls_data().map(|_| ())).and_then(|_| loader::parse_api_set_schema());
    assert(ready.is_ok(), "raiz: ntdll, apiset e NLS de sistema prontos");
    kernel_stack::reap();
    let free_before = pfn::free_count();
    let caller_root = paging::current_root();

    let Some(first) = create("raiz-a.exe", FIRST) else {
        assert(false, "raiz: primeiro processo montado");
        return;
    };
    let Some(second) = create("raiz-b.exe", SECOND) else {
        let pointer = first.process_pointer;
        drop(first);
        let _ = process::dereference(pointer);
        assert(false, "raiz: segundo processo montado");
        return;
    };
    let (a, b) = (first.process_pointer, second.process_pointer);
    let (root_a, root_b) = (address_space::root_of(a).unwrap_or(0), address_space::root_of(b).unwrap_or(0));

    // Raízes próprias, distintas, no KPROCESS e no estado; o CR3 de quem
    // montou não mudou.
    let state_root = |process: u64| process_state::get(process).map_or(0, |state| state.directory_table_base.load(core::sync::atomic::Ordering::Acquire));
    assert(root_a != 0 && root_b != 0 && root_a != root_b && root_a != SYSTEM_ROOT && root_b != SYSTEM_ROOT && directory_table_base(a) == root_a && directory_table_base(b) == root_b && state_root(a) == root_a && state_root(b) == root_b, "raiz: dois processos de usuario vivos com raizes proprias e distintas, fora da do System");
    assert(paging::current_root() == caller_root && caller_root != root_a && caller_root != root_b, "raiz: o CR3 de quem montou continua na raiz dele");

    // A mesma VA de PEB e de pilha nos dois, com frames próprios.
    let (peb_a, peb_b) = (peb_of(a), peb_of(b));
    let mark_at = (first.stack_top & !0xFFF) - 0x100;
    let same_va = peb_a != 0 && peb_a == peb_b && first.teb == second.teb && first.stack_top == second.stack_top;
    if !same_va {
        crate::debug_print!("[raiz] PEB {:#x}/{:#x}, TEB {:#x}/{:#x}, pilha {:#x}/{:#x}", peb_a, peb_b, first.teb, second.teb, first.stack_top, second.stack_top);
    }
    assert(same_va, "raiz: PEB, TEB e pilha da primeira thread na mesma VA nos dois processos");
    // Sem raiz própria (o comportamento anterior) não há o que traduzir.
    let frames = |va: u64| if root_a == 0 || root_b == 0 { (0, 0, 0) } else { (paging::translate_in(root_a, va), paging::translate_in(root_b, va), paging::translate_in(SYSTEM_ROOT, va)) };
    let (peb_frames, stack_frames) = (frames(peb_a), frames(mark_at));
    let private = |(in_a, in_b, in_system): (u64, u64, u64)| in_a != 0 && in_b != 0 && in_a != in_b && in_system != in_a && in_system != in_b;
    assert(private(peb_frames) && private(stack_frames), "raiz: a PEB e a pilha caem em frames diferentes em cada raiz, e a raiz do System nao ve nenhum deles");

    // Conteúdo diferente na mesma VA, lido anexado a cada um.
    let ntdll = loader::ntdll_module().map_or(0, |module| module.image_base);
    let seen_a = inspect(a, peb_a, ntdll, mark_at, Some(FIRST_MARK));
    let seen_b = inspect(b, peb_b, ntdll, mark_at, Some(SECOND_MARK));
    let again_a = inspect(a, peb_a, ntdll, mark_at, None);
    assert(seen_a.is_some_and(|(image_base, _, mark)| image_base == FIRST.0 && mark == FIRST_MARK) && seen_b.is_some_and(|(image_base, _, mark)| image_base == SECOND.0 && mark == SECOND_MARK), "raiz: a mesma VA de PEB e de pilha tem conteudo diferente em cada processo (ImageBaseAddress e marca)");
    assert(again_a.is_some_and(|(_, _, mark)| mark == FIRST_MARK), "raiz: a marca gravada na pilha do segundo nao aparece na do primeiro");
    let ntdll_frames = frames(ntdll);
    assert(ntdll != 0 && seen_a.is_some_and(|(_, mz, _)| mz == 0x5A4D) && seen_b.is_some_and(|(_, mz, _)| mz == 0x5A4D) && private(ntdll_frames) && ntdll_frames.2 != 0, "raiz: a ntdll na mesma VA nos dois, em copias privadas distintas da de sistema");
    let copies = |process: u64| process_state::get(process).map_or(0, |state| state.system_page_count());
    assert(copies(a) != 0 && copies(a) == copies(b), "raiz: cada processo tem as proprias copias de sistema");

    // Em sequência, cada um com o próprio código de saída.
    let first_exit = user_process::run_created(first);
    let second_exit = user_process::run_created(second);
    // SAFETY: EPROCESS retidos pelo teste.
    let exit_status = |process: u64| unsafe { Eprocess::at(process) }.exit_status.get() as u32;
    let ran = matches!(first_exit, Ok(code) if code == FIRST.1) && matches!(second_exit, Ok(code) if code == SECOND.1) && exit_status(a) == FIRST.1 && exit_status(b) == SECOND.1;
    if !ran {
        crate::debug_print!("[raiz] saidas {:?} {:?}", first_exit.as_ref().map_err(|error| format!("{error}")), second_exit.as_ref().map_err(|error| format!("{error}")));
    }
    assert(ran, "raiz: os dois rodam em sequencia e saem com os proprios codigos");

    // Nada sobra: sem estado, raízes só com a KUSER enquanto retidas e
    // devolvidas no último dereference, PFN de volta.
    let emptied = process_state::get(a).is_none() && process_state::get(b).is_none() && address_space::root_of(a) == Some(root_a) && address_space::root_of(b) == Some(root_b) && only_kuser(root_a) && only_kuser(root_b);
    assert(emptied, "raiz: no termino a raiz de cada processo fica so com a visao da KUSER_SHARED_DATA");
    let _ = process::dereference(a);
    let _ = process::dereference(b);
    kernel_stack::reap();
    let free_after = pfn::free_count();
    if free_after != free_before {
        crate::debug_print!("[raiz] PFN livre antes {} depois {}", free_before, free_after);
    }
    assert(address_space::root_of(a).is_none() && address_space::root_of(b).is_none() && free_after == free_before, "raiz: as raizes voltam no ultimo dereference e o PFN livre volta ao de antes da montagem");
    service(assert);
}

/// Serviço de teste e a imagem dele no volume.
const SERVICE: &str = "OpenNtRaizServico";
const SERVICE_IMAGE: &str = "\\??\\D:\\raiz-servico.exe";

/// Grava (ou, com `None`, apaga) um arquivo do volume pelos serviços de
/// arquivo, de um bloco de usuário do processo corrente.
fn volume_file(path: &str, bytes: Option<&[u8]>) -> bool {
    let Ok(block) = memory::map_user_region(0x2000) else { return false };
    let (out, iosb, rsp) = (block, block + 0x20, block + 0x1800);
    let request = match bytes {
        Some(_) => OpenRequest { access: 0x4010_0000, share: 0, options: 0x20, ..OpenRequest::default() },
        None => OpenRequest { access: 0x8011_0000, share: 7, options: 0x1020, ..OpenRequest::default() },
    };
    let opened = file_io::open(out, path, iosb, if bytes.is_some() { 5 } else { 1 }, &request).unwrap_or(1);
    let handle = guest::read64(out);
    let written = match bytes {
        Some(bytes) => {
            guest::write_bytes(block + 0x100, bytes);
            guest::write64(rsp + 0x28, iosb);
            guest::write64(rsp + 0x30, block + 0x100);
            guest::write32(rsp + 0x38, bytes.len() as u32);
            guest::write64(rsp + 0x40, 0);
            state::handler("NtWriteFile").map_or(1, |handler| handler(handle, 0, 0, 0, rsp).unwrap_or(1))
        }
        None => 0,
    };
    let _ = state::close_user_handle(handle, true, false);
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
    opened == 0 && written == 0
}

/// O `run_service` lê a imagem do volume e roda o serviço num processo com
/// raiz própria: o código de saída volta e o serviço fica STOPPED.
fn service(assert: Assert) {
    let written = volume_file(SERVICE_IMAGE, Some(&program(0x1_4000_0000, 0x42)));
    let installed = service_database::install(&ConfigurationInput { name: alloc::string::String::from(SERVICE), image_path: Some(alloc::string::String::from(SERVICE_IMAGE)), service_type: Some(16), start: Some(3), ..ConfigurationInput::default() }, false).is_ok();
    let result = if written && installed { user_process::run_service(SERVICE, None).map_err(|error| format!("{error:?}")) } else { Err(alloc::string::String::from("instalacao")) };
    let stopped = service_database::status(SERVICE).is_ok_and(|status| status.current_state == service_database::STOPPED && status.process_exit_code == Some(0x42));
    if !matches!(result, Ok(0x42)) {
        crate::debug_print!("[raiz] servico: gravado={} instalado={} resultado={:?}", written, installed, result);
    }
    assert(matches!(result, Ok(0x42)) && stopped, "raiz: run_service roda o servico do volume num processo com raiz propria e devolve o codigo");
    let _ = service_database::remove(SERVICE);
    let removed = volume_file(SERVICE_IMAGE, None) && volume_files::lookup_volume_file(SERVICE_IMAGE).is_none();
    assert(removed, "raiz: imagem do servico removida do volume");
}
