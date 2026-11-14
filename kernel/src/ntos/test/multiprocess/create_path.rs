//! Um caminho de criação de processos (`ps::create::create_user_process`).
//!
//! - Um processo criado pelo caminho único, ainda parado, com uma linha de
//!   comando com argumentos:
//!   - PEB.ApiSetMap (+0x68) aponta para o apiset do processo: a VA da cópia
//!     de sistema, mapeada na raiz dele numa cópia privada (frame diferente
//!     do da cópia de sistema), e o API_SET_NAMESPACE v6 lido anexado; a
//!     PEB traz o subsistema da imagem;
//!   - PEB.ProcessParameters é o bloco da criação, e o ImagePathName e o
//!     CommandLine dele, lidos anexado pelo formato auto-relativo, são os
//!     pedidos; o caminho da imagem fica no estado do processo e a linha de
//!     comando no registro do processo (a das notificações de processo);
//!   - a notificação de carga de imagem do executável e da ntdll já rodou na
//!     criação, anexada ao processo novo: o callback de teste recebe o PID
//!     dele, vê a raiz dele no CR3 e o processo dele como o corrente, e lê
//!     o MZ em ImageBase.
//! - Depois ele roda e sai com o código.
//! - Uma imagem inexistente por caminho NT falha ao abrir
//!   (STATUS_OBJECT_NAME_NOT_FOUND) sem criar processo.

use alloc::string::String;
use alloc::vec::Vec;
use core::mem::offset_of;

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_ps_user::ApiSetNamespace;
use crate::ntos::inc::types::{ImageInfo, Peb, RtlUserProcessParameters, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::paging;
use crate::ntos::mm::process_address_space::{self as address_space, SYSTEM_ROOT};
use crate::ntos::ps::create::{self, CreateFailure, CreateProcessRequest, ImageOrigin};
use crate::ntos::ps::notify::image as image_notify;
use crate::ntos::ps::process_parameters::ProcessParameters;
use crate::ntos::ps::user::process as user_process;
use crate::ntos::ps::user::{loader, memory, process_state, state};
use crate::ntos::ps::{process, process_context};
use crate::rtl::SpinLock;

type Assert = fn(bool, &str);

const EXIT_CODE: u32 = 0x61;
const IMAGE_NAME: &str = "criacao.exe";
const IMAGE_PATH: &str = "C:\\OpenNT\\criacao.exe";
const COMMAND_LINE: &str = "\"C:\\OpenNT\\criacao.exe\" -modo teste";
const MISSING_IMAGE: &str = "\\??\\C:\\OpenNT\\naoexiste.exe";
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
/// IMAGE_SUBSYSTEM_WINDOWS_CUI, o subsistema do executável do teste.
const SUBSYSTEM_CUI: u32 = 3;

/// NtTerminateProcess(-1, código) pela syscall da ntdll de bring-up, depois
/// do LdrInitializeThunk.
fn program() -> Vec<u8> {
    let code = EXIT_CODE.to_le_bytes();
    let entry: &[u8] = &[0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0xBA, code[0], code[1], code[2], code[3], 0x49, 0x89, 0xCA, 0xB8, 0x2C, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xEB, 0xFE];
    crate::ntos::test::phase7::single_section_image(0x1_4000_0000, 0x0022, b".text", 0x6000_0020, 0x1000, entry)
}

/// Uma notificação de carga de imagem vista pelo callback de teste.
#[derive(Clone, Copy)]
struct Seen {
    process_id: u64,
    image_base: u64,
    /// O cabeçalho lido em ImageBase (0 se a VA não é do processo corrente).
    mz: u16,
    /// A raiz no CR3 e o processo corrente durante a chamada.
    root: u64,
    process: u64,
}

static SEEN: SpinLock<Vec<Seen>> = SpinLock::new(Vec::new());

/// O callback de PsSetLoadImageNotifyRoutine do teste: lê o MZ em ImageBase
/// quando a VA é do processo corrente (o anexado), como um driver que lê os
/// cabeçalhos da imagem.
extern "win64" fn image_loaded(_name: u64, process_id: u64, info: u64) {
    // SAFETY: IMAGE_INFO montado pelo notificador para esta chamada.
    let image_base = unsafe { ImageInfo::at(info) }.image_base.get();
    let readable = memory::check_user_access(image_base).is_ok();
    let mz = if readable { guest::try_read::<u16>(image_base).unwrap_or(0) } else { 0 };
    SEEN.lock().push(Seen { process_id, image_base, mz, root: paging::current_root(), process: process::get_current_process() });
}

/// O que se lê anexado ao processo: (ApiSetMap, versão do schema, subsistema
/// da imagem, bloco de parâmetros, ImagePathName, CommandLine, Flags).
type Observed = (u64, u32, u32, u64, String, String, u32);

fn observe(process_pointer: u64, peb: u64) -> Option<Observed> {
    process_context::with_process(process_pointer, || {
        // SAFETY: a PEB do processo anexado, criada pelo kernel.
        let peb = unsafe { Peb::at(peb) };
        let map = peb.api_set_map.get();
        let version = state::user_struct::<ApiSetNamespace>(map).and_then(|namespace| namespace.version.probe_get()).unwrap_or(0);
        let block = peb.process_parameters.get();
        // SAFETY: o bloco de parâmetros do processo anexado, gravado pelo
        // kernel no formato auto-relativo.
        let parameters = unsafe { RtlUserProcessParameters::at(block) };
        let text = |string: &UnicodeString| state::read_user_wide_string(block + string.buffer.get(), string.length.get() as u64 / 2);
        (map, version, peb.image_subsystem.get(), block, text(&parameters.image_path_name), text(&parameters.command_line), parameters.flags.get())
    })
    .ok()
}

pub fn run(assert: Assert) {
    if process::get_current_thread() == 0 {
        assert(false, "criacao: thread corrente para anexar");
        return;
    }
    if state::with(|state| state.ntdll_exports.as_ref().is_none_or(|exports| !exports.contains_key("LdrInitializeThunk"))) {
        assert(false, "criacao: ntdll com LdrInitializeThunk mapeada");
        return;
    }
    let callback = image_loaded as extern "win64" fn(u64, u64, u64) as usize as u64;
    SEEN.lock().clear();
    assert(matches!(image_notify::register(callback), Ok(0)), "criacao: callback de carga de imagem registrado");

    let mut parameters = ProcessParameters::for_image(IMAGE_PATH);
    parameters.command_line = String::from(COMMAND_LINE);
    let request = CreateProcessRequest { image: ImageOrigin::Bytes(program()), image_name: IMAGE_NAME, parameters, parent: None, thread_flags: 0, inherit_handles_from: None, on_created: None };
    match create::create_user_process(&request) {
        Ok(created) => {
            let (process_pointer, process_id) = (created.process_pointer, created.process_id);
            let root = address_space::root_of(process_pointer).unwrap_or(0);
            // As notificações já rodaram na criação, anexadas ao processo novo.
            let seen: Vec<Seen> = SEEN.lock().iter().copied().filter(|seen| seen.process_id == process_id).collect();
            let ntdll = loader::ntdll_module().map_or(0, |module| module.image_base);
            let attached = |image_base: u64| seen.iter().any(|seen| seen.image_base == image_base && seen.mz == 0x5A4D && seen.root == root && seen.process == process_pointer);
            if !(attached(created.image_base) && attached(ntdll)) {
                crate::debug_print!("[criacao] pid {:#x} raiz {:#x}: {} notificacoes do processo", process_id, root, seen.len());
            }
            assert(root != 0 && root != SYSTEM_ROOT && attached(created.image_base) && attached(ntdll), "criacao: a notificacao de imagem do exe e da ntdll roda na criacao, anexada ao processo novo (PID dele, raiz dele no CR3 e o MZ lido em ImageBase)");

            // PEB.ApiSetMap e os parâmetros, lidos anexado.
            let api_set = state::with(|state| state.api_set_map_va);
            let observed = observe(process_pointer, created.peb);
            let (in_process, in_system) = (paging::translate_in(root, api_set), paging::translate_in(SYSTEM_ROOT, api_set));
            assert(offset_of!(Peb, api_set_map) == 0x68 && api_set != 0 && in_process != 0 && in_process != in_system && observed.as_ref().is_some_and(|observed| observed.0 == api_set && observed.1 == 6 && observed.2 == SUBSYSTEM_CUI), "criacao: PEB.ApiSetMap (+0x68) aponta para o apiset do processo (a VA de sistema, em copia privada na raiz dele), com o schema v6 lido anexado, e a PEB traz o subsistema da imagem");
            if !observed.as_ref().is_some_and(|observed| observed.4 == IMAGE_PATH && observed.5 == COMMAND_LINE) {
                crate::debug_print!("[criacao] parametros: {:?}", observed.as_ref().map(|observed| (observed.4.clone(), observed.5.clone())));
            }
            let recorded = process::with_record(process_pointer, |record| record.command_line.clone()).flatten();
            let identity = process_state::get(process_pointer).map(|identity| identity.image_path());
            assert(observed.as_ref().is_some_and(|observed| observed.3 == created.parameters && observed.4 == IMAGE_PATH && observed.5 == COMMAND_LINE && observed.6 == 0) && identity.as_deref() == Some(IMAGE_PATH) && recorded.as_deref() == Some(COMMAND_LINE), "criacao: ImagePathName e CommandLine (com argumentos) certos nos parametros, lidos anexado; o caminho no estado do processo e a linha de comando no registro do processo");

            let exit = user_process::run_created(created);
            if !matches!(exit, Ok(EXIT_CODE)) {
                crate::debug_print!("[criacao] saida {:?}", exit.as_ref().map_err(|error| alloc::format!("{error}")));
            }
            assert(matches!(exit, Ok(EXIT_CODE)), "criacao: o processo criado roda e sai com o codigo");
        }
        Err(failure) => {
            crate::debug_print!("[criacao] {} nao criado: {}", IMAGE_NAME, failure);
            assert(false, "criacao: processo criado pelo caminho unico");
        }
    }

    // Imagem inexistente: nada é criado.
    let before = process::list_active_processes().len();
    let missing = create::create_user_process(&CreateProcessRequest { image: ImageOrigin::NtPath(String::from(MISSING_IMAGE)), image_name: "naoexiste.exe", parameters: ProcessParameters::for_image("C:\\OpenNT\\naoexiste.exe"), parent: None, thread_flags: 0, inherit_handles_from: None, on_created: None });
    let refused = matches!(&missing, Err(CreateFailure::FileOpen(STATUS_OBJECT_NAME_NOT_FOUND)));
    assert(refused && missing.as_ref().err().is_some_and(|failure| failure.status() == STATUS_OBJECT_NAME_NOT_FOUND) && process::list_active_processes().len() == before, "criacao: imagem inexistente por caminho NT falha ao abrir, sem criar processo");
    drop(missing);

    assert(matches!(image_notify::remove(callback), Ok(0)), "criacao: callback de carga de imagem removido");
    SEEN.lock().clear();
}
