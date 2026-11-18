//! Espaço de sessão (`mm/session.rs`, `mm/session_pool.rs`,
//! `mm/session_image.rs`), com dois processos criados pelo caminho real com
//! PROCESS_CREATE_FLAGS_CREATE_SESSION e um filho do primeiro:
//!
//! - duas sessões com ids distintos; o filho entra na sessão do pai; o
//!   System fica fora (MmGetSessionIdEx -1); ProcessInSession nos três e
//!   SessionMaster só nos dois que criaram as sessões; as contagens e a
//!   ProcessList do MM_SESSION_SPACE (a ProcessReferenceToSession conta
//!   também a do objeto Session);
//! - o objeto Session de cada sessão (MiSessionObjectCreate): do tipo
//!   Session, nomeado `\KernelObjects\Session<id>`, com o handle de kernel
//!   e o bit 0x40 no MM_SESSION_SPACE; o MmGetSessionObjectById o devolve;
//!   o NtSetInformationObject(ObjectSessionObjectInformation) de um processo
//!   da sessão liga o objeto a um diretório uma vez (a segunda dá
//!   STATUS_ACCESS_DENIED);
//! - cada sessão tem a própria tabela de topo, ligada no slot de sessão da
//!   raiz de cada processo dela (o filho divide a do pai) e ausente na raiz
//!   do System; o MM_SESSION_SPACE está em SessionCore, na mesma VA, com o id
//!   de cada sessão, em frames próprios; MmIsSessionAddress;
//! - MmAttachSession/MmDetachSession trocam para a raiz da sessão e contam
//!   AttachCount; MmGetSessionById só serve sessão com driver de sessão
//!   (MmSessionSetUnloadAddress) e devolve um processo que não é o mestre;
//! - PagedPoolSession: o bloco de uma sessão só existe nas raízes dela; a
//!   outra sessão recebe a mesma VA em outro frame; a contabilidade da tag
//!   vai para o PoolTags de cada sessão com os bytes do 19041; liberar fora
//!   do heap da sessão corrente dá o veredito BAD_POOL_CALLER (0, 0, VA, 0);
//!   NonPagedPoolSession é VA de sistema com contabilidade de sessão;
//! - o BOOTVID.DLL real carregado como imagem de sessão nas duas sessões: a
//!   mesma VA e a mesma entrada do loader (LoadCount 2), o código nos mesmos
//!   frames mestres e sem escrita, a .data em cópias privadas que começam
//!   iguais à mestra (o cookie) e separam na primeira escrita; uma segunda
//!   carga na mesma sessão conta uma carga a mais nela, que o
//!   MmUnloadSystemImage seguinte só desconta; fora de uma sessão,
//!   STATUS_NO_MEMORY; MmUnloadSystemImage tira a imagem de uma sessão só;
//! - no fim dos processos, as sessões somem com o pool que sobrou e a imagem
//!   ainda carregada, e o PFN livre volta ao de antes.

use alloc::format;

use crate::hal::physical;
use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::types::{DriverObject, Eprocess, KapcState, KldrDataTableEntry, MmSessionSpace, NtStruct, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::process_address_space::{self as address_space, SYSTEM_ROOT};
use crate::ntos::mm::{kernel_stack, loaded_images, memory_map as map, paging, pfn, session, session_image, session_pool, sysload};
use crate::ntos::ps::create::{self, CreatedProcess, ImageOrigin};
use crate::ntos::ps::user::process::{self as user_process, RunOptions};
use crate::ntos::ps::user::{loader, state};
use crate::ntos::ps::{process, process_context};

type Assert = fn(bool, &str);

const FIRST: (u64, u32) = (0x1_4000_0000, 0x61);
const SECOND: (u64, u32) = (0x1_5000_0000, 0x62);
const CHILD: (u64, u32) = (0x1_6000_0000, 0x63);
const FRAME_MASK: u64 = 0x000F_FFFF_FFFF_F000;
const PAGED_POOL_SESSION: u32 = 33;
const NONPAGED_POOL_SESSION: u32 = 32;
const PAGED_TAG: u32 = u32::from_le_bytes(*b"SsnP");
const NONPAGED_TAG: u32 = u32::from_le_bytes(*b"SsnN");
const IMAGE_PATH: &str = "\\SystemRoot\\System32\\BOOTVID.DLL";
const MARK_A: u64 = 0xA5A5_0000_5E55_000A;
const MARK_B: u64 = 0xB5B5_0000_5E55_000B;
const STATUS_NO_MEMORY: u64 = 0xC000_0017;

/// NtTerminateProcess(-1, código) pela syscall da ntdll de bring-up.
fn program(image_base: u64, exit_code: u32) -> alloc::vec::Vec<u8> {
    let code = exit_code.to_le_bytes();
    let entry: &[u8] = &[0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0xBA, code[0], code[1], code[2], code[3], 0x49, 0x89, 0xCA, 0xB8, 0x2C, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xEB, 0xFE];
    crate::ntos::test::phase7::single_section_image(image_base, 0x0022, b".text", 0x6000_0020, 0x1000, entry)
}

/// Cria, sem rodar, um processo pelo caminho único (com sessão nova ou na
/// sessão de `parent`); o EPROCESS fica retido pelo teste.
fn create(name: &str, (image_base, exit_code): (u64, u32), create_session: bool, parent: Option<u64>) -> Option<CreatedProcess> {
    let mut request = user_process::windows_process_request(ImageOrigin::Bytes(program(image_base, exit_code)), name, &format!("C:\\{name}"), &RunOptions::default());
    request.create_session = create_session;
    request.parent = parent;
    match create::create_user_process(&request) {
        Ok(created) => {
            process::reference(created.process_pointer);
            Some(created)
        }
        Err(failure) => {
            crate::debug_print!("[sessao] {} nao criado: {}", name, failure);
            None
        }
    }
}

fn eprocess(process: u64) -> &'static Eprocess {
    // SAFETY: EPROCESS retido pelo teste.
    unsafe { Eprocess::at(process) }
}

fn space(pointer: u64) -> &'static MmSessionSpace {
    // SAFETY: VA global de uma sessão viva (só a primeira página).
    unsafe { MmSessionSpace::at(pointer) }
}

fn inside<T>(process: u64, body: impl FnOnce() -> T) -> Option<T> {
    process_context::with_process(process, body).ok()
}

/// Os processos da ProcessList de uma sessão.
fn members(pointer: u64) -> alloc::vec::Vec<u64> {
    let list = &space(pointer).process_list;
    let mut found = alloc::vec::Vec::new();
    let mut link = list.flink.get();
    while link != list.address() && link != 0 && found.len() < 16 {
        let candidate = link - core::mem::offset_of!(Eprocess, session_process_links) as u64;
        found.push(candidate);
        link = eprocess(candidate).session_process_links.flink.get();
    }
    found
}

/// O id do MM_SESSION_SPACE em SessionCore, lido no processo `process`.
fn core_session_id(process: u64) -> Option<u32> {
    inside(process, || {
        // SAFETY: SessionCore, conferido mapeado na raiz carregada.
        (paging::translate(map::SESSION_CORE_BASE) != 0).then(|| unsafe { MmSessionSpace::at(map::SESSION_CORE_BASE) }.session_id.get())
    })
    .flatten()
}

/// RVA e características da seção `name` da imagem mapeada em `base`.
fn section(base: u64, name: &[u8]) -> Option<(u64, u32)> {
    let nt = base + guest::read32(base + 0x3C) as u64;
    let count = guest::read16(nt + 6) as u64;
    let table = nt + 24 + guest::read16(nt + 20) as u64;
    (0..count).map(|index| table + index * 40).find(|&header| guest::read_bytes(header, name.len()) == name).map(|header| (guest::read32(header + 12) as u64, guest::read32(header + 36)))
}

fn writable(root: u64, va: u64) -> bool {
    paging::query_page_in(root, va, false).is_some_and(|query| query.flags & paging::PAGE_RW != 0)
}

/// O NtOpenSession e o NtNotifyChangeSession de modo usuário (o caminho do
/// Local Session Manager), num processo da sessão `session` (id `id`):
/// abrir `\KernelObjects\Session<id>` por nome (um nome ausente devolve o
/// handle 0); a sequência que avança com o número certo e fica com um
/// número atrasado; o IoState gravado com o NewState; o Event 0 só conta a
/// sequência; o payload acima de 0x100 bytes e o handle inválido
/// recusados; o aviso de um evento assíncrono (Connected) devolve o evento
/// de sincronização só depois do worker.
fn session_notifications(assert: Assert, process: u64, session: u64, id: u32) {
    let outcome = inside(process, || {
        let block = crate::ntos::ps::user::memory::map_user_region(0x1000).ok()?;
        let (attributes, text, unicode, handle, payload, rsp) = (block, block + 0x100, block + 0x80, block + 0x200, block + 0x300, block + 0x800);
        let name = format!("\\KernelObjects\\Session{id}");
        crate::ntos::ps::user::state::write_user_wide(text, &name);
        crate::ntos::ps::user::state::write_unicode_string(unicode, text, &name);
        // SAFETY: OBJECT_ATTRIBUTES no bloco do processo da sessão.
        let object_attributes = unsafe { crate::ntos::inc::types::ObjectAttributes::at(attributes) };
        object_attributes.length.set(crate::ntos::inc::types::ObjectAttributes::SIZE as u32);
        object_attributes.object_name.set(unicode);
        object_attributes.attributes.set(0x40);
        let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map_or(1, |handler| handler(a1, a2, a3, a4, rsp).unwrap_or(1));
        let notify = |session_handle: u64, sequence: u32, event: u32, new_state: u32, data: u64, size: u32| {
            guest::write64(rsp + 0x28, new_state as u64);
            guest::write64(rsp + 0x30, 0);
            guest::write64(rsp + 0x38, data);
            guest::write64(rsp + 0x40, size as u64);
            call("NtNotifyChangeSession", session_handle, sequence as u64, 0, event as u64)
        };
        let opened = call("NtOpenSession", handle, 0xC000_0000, attributes, 0);
        let session_handle = guest::read64(handle);
        let state_now = || (space(session).io_state_sequence.get(), space(session).io_state.get().0);
        let first = state_now().0;
        let created = notify(session_handle, first, 1, 2, 0, 0);
        let after_created = state_now();
        let stale = notify(session_handle, first, 0, 0, 0, 0);
        let after_stale = state_now();
        let ignored = notify(session_handle, first + 1, 0, 0, 0, 0);
        let after_ignored = state_now();
        guest::write64(payload, 0x5E55_0000_0000_0001);
        let with_payload = notify(session_handle, first + 2, 2, 8, payload, 8);
        let oversized = notify(session_handle, first + 3, 1, 2, payload, 0x101);
        let invalid = notify(0x7FFC, first + 3, 1, 2, 0, 0);
        let connected = notify(session_handle, first + 3, 3, 3, payload, 8);
        // O worker solta o evento de sincronização: a espera (com prazo de
        // 1 s) o consome e o devolve sinalizado.
        let event = space(session).io_notification_event.address();
        crate::ntos::io::work_items::run_queue();
        let timeout = guest::alloc_bytes(8);
        guest::write::<i64>(timeout, -10_000_000);
        let released = crate::ntos::ke::dispatcher::wait_for_single_object(event, timeout, 0, false) == 0;
        guest::free_bytes(timeout);
        if released {
            crate::ntos::ke::dispatcher::set_event(event);
        }
        let after_connected = state_now();
        guest::write64(handle, u64::MAX);
        crate::ntos::ps::user::state::write_user_wide(text, "\\KernelObjects\\SessionNada");
        crate::ntos::ps::user::state::write_unicode_string(unicode, text, "\\KernelObjects\\SessionNada");
        let missing = call("NtOpenSession", handle, 0xC000_0000, attributes, 0);
        let missing_handle = guest::read64(handle);
        call("NtClose", session_handle, 0, 0, 0);
        if let Some(region) = crate::ntos::ps::user::memory::find_region(block) {
            crate::ntos::ps::user::memory::release_private_region(&region);
        }
        Some((opened, session_handle, first, (created, after_created), (stale, after_stale), (ignored, after_ignored), with_payload, oversized, invalid, (connected, released, after_connected), (missing, missing_handle)))
    })
    .flatten();
    let Some((opened, session_handle, first, created, stale, ignored, with_payload, oversized, invalid, connected, missing)) = outcome else {
        assert(false, "sessao: NtOpenSession e NtNotifyChangeSession no processo da sessao");
        return;
    };
    assert(opened == 0 && session_handle != 0 && missing == (0xC000_0034, 0), "sessao: NtOpenSession abre \\KernelObjects\\Session<id> por nome; um nome ausente devolve STATUS_OBJECT_NAME_NOT_FOUND e o handle 0");
    assert(created == (0, (first + 1, 2)) && stale == (0, (first + 1, 2)) && ignored == (0, (first + 2, 2)), "sessao: NtNotifyChangeSession avanca a sequencia com o numero certo, grava o NewState e deixa a sequencia com um numero atrasado ou o Event 0");
    assert(with_payload == 0 && oversized == 0xC000_00F4 && invalid == 0xC000_0008, "sessao: NtNotifyChangeSession aceita o payload de 8 bytes e recusa o de 0x101 (STATUS_INVALID_PARAMETER_6) e o handle invalido");
    assert(connected == (0, true, (first + 4, 3)), "sessao: o aviso Connected vai ao worker, que solta o evento de sincronizacao da sessao");
}

pub fn run(assert: Assert) {
    if process::get_current_thread() == 0 {
        assert(false, "sessao: thread corrente para anexar");
        return;
    }
    if state::with(|state| state.ntdll_exports.as_ref().is_none_or(|exports| !exports.contains_key("LdrInitializeThunk"))) {
        assert(false, "sessao: ntdll com LdrInitializeThunk mapeada");
        return;
    }
    let ready = loader::ensure_ntdll().and_then(|_| loader::ensure_api_set_schema()).and_then(|_| loader::ensure_nls_data().map(|_| ())).and_then(|_| loader::parse_api_set_schema());
    assert(ready.is_ok(), "sessao: ntdll, apiset e NLS de sistema prontos");
    let block = guest::alloc_bytes(0x400);
    let (name, handle, base_out) = (block, block + 0x40, block + 0x48);
    let units: alloc::vec::Vec<u16> = IMAGE_PATH.encode_utf16().collect();
    guest::write_bytes(block + 0x100, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<alloc::vec::Vec<u8>>());
    // SAFETY: UNICODE_STRING no bloco do teste.
    let unicode = unsafe { UnicodeString::at(name) };
    unicode.length.set(units.len() as u16 * 2);
    unicode.maximum_length.set(units.len() as u16 * 2);
    unicode.buffer.set(block + 0x100);
    let load = |flags: u32| sysload::load_system_image(name, 0, 0, flags, handle, base_out).unwrap_or(0xC000_0001) as u64;
    // A CI e o loader prontos para a imagem antes da amostra do PFN: uma
    // carga de sistema e a descarga dela.
    let warmed = load(0) == 0 && sysload::unload_system_image(guest::read64(handle)).is_ok();
    assert(warmed, "sessao: o BOOTVID.DLL real carrega e descarrega como imagem de sistema");
    kernel_stack::reap();
    let free_before = pfn::free_count();
    let sessions_before = session::count();

    let Some(first) = create("sessao-a.exe", FIRST, true, None) else {
        assert(false, "sessao: primeiro processo com sessao nova");
        return;
    };
    let a = first.process_pointer;
    let (Some(second), Some(child)) = (create("sessao-b.exe", SECOND, true, None), create("sessao-c.exe", CHILD, false, Some(a))) else {
        assert(false, "sessao: segundo processo com sessao nova e filho do primeiro");
        return;
    };
    let (b, c) = (second.process_pointer, child.process_pointer);
    let (root_a, root_b, root_c) = (address_space::root_of(a).unwrap_or(0), address_space::root_of(b).unwrap_or(0), address_space::root_of(c).unwrap_or(0));
    let system = process::get_system_process();

    // Ids, bits e contagens.
    let (id_a, id_b) = (session::session_id_ex(a), session::session_id_ex(b));
    let (sa, sb) = (session::of_process(a), session::of_process(b));
    assert(id_a != u32::MAX && id_b != u32::MAX && id_a != id_b && session::session_id_ex(c) == id_a && session::of_process(c) == sa && crate::ntos::ps::session::query(a) == id_a && crate::ntos::ps::session::query(b) == id_b, "sessao: duas sessoes com ids distintos; o filho entra na sessao do pai");
    assert(session::session_id_ex(system) == u32::MAX && session::session_id(system) == 0 && session::of_process(system) == 0, "sessao: o System fica fora (MmGetSessionIdEx -1, MmGetSessionId 0)");
    let in_session = |process: u64| eprocess(process).process_in_session() != 0;
    let master = |process: u64| eprocess(process).vm.instance.flags.session_master() != 0;
    assert(in_session(a) && in_session(b) && in_session(c) && !in_session(system) && master(a) && master(b) && !master(c), "sessao: ProcessInSession nos tres, SessionMaster so em quem criou a sessao");
    let counts = |pointer: u64| (space(pointer).reference_count.get(), space(pointer).process_reference_to_session.get());
    let listed_a = members(sa);
    assert(counts(sa) == (2, 3) && counts(sb) == (1, 2) && listed_a.len() == 2 && listed_a.contains(&a) && listed_a.contains(&c) && members(sb) == alloc::vec![b], "sessao: ReferenceCount, ProcessReferenceToSession (com a do objeto Session) e ProcessList de cada sessao");

    // O objeto Session de cada sessão.
    let object_a = space(sa).session_object.get();
    let named_a = crate::ntos::ob::object_manager::lookup(&format!("\\KernelObjects\\Session{id_a}")).and_then(crate::ntos::ob::object_manager::node).and_then(|node| node.data).is_some_and(|data| data.native_pointer == object_a);
    let typed_a = crate::ntos::ob::object_header::object_type_info(object_a).is_some_and(|object_type| object_type.name == "Session" && object_type.valid_access == 0x1F_0003);
    assert(object_a != 0 && typed_a && named_a && space(sa).session_object_handle.get() != 0 && space(sa).u.long_flags.get() & 0x40 != 0 && space(sb).session_object.get() != 0 && space(sb).session_object.get() != object_a, "sessao: objeto Session de cada sessao, nomeado \\KernelObjects\\Session<id>, com o handle de kernel e o bit 0x40");
    let by_id = crate::ntos::mm::session_object::by_id(id_a);
    if by_id != 0 {
        crate::ntos::ob::object_header::dereference(by_id, false);
    }
    assert(by_id == object_a && crate::ntos::mm::session_object::by_id(0x7FFF) == 0, "sessao: MmGetSessionObjectById devolve o objeto da sessao (e nada para uma sessao inexistente)");
    let linked = inside(a, || {
        let block = crate::ntos::ps::user::memory::map_user_region(0x1000).ok()?;
        let (attributes, text, unicode, handle, rsp) = (block, block + 0x100, block + 0x80, block + 0x200, block + 0x800);
        crate::ntos::ps::user::state::write_user_wide(text, "\\OpenNtSessaoDir");
        crate::ntos::ps::user::state::write_unicode_string(unicode, text, "\\OpenNtSessaoDir");
        // SAFETY: OBJECT_ATTRIBUTES no bloco do processo da sessão.
        let object_attributes = unsafe { crate::ntos::inc::types::ObjectAttributes::at(attributes) };
        object_attributes.length.set(crate::ntos::inc::types::ObjectAttributes::SIZE as u32);
        object_attributes.object_name.set(unicode);
        object_attributes.attributes.set(0x40);
        let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map_or(1, |handler| handler(a1, a2, a3, a4, rsp).unwrap_or(1));
        let created = call("NtCreateDirectoryObject", handle, 0xF_000F, attributes, 0);
        let directory = guest::read64(handle);
        let first = call("NtSetInformationObject", directory, 6, 0, 0);
        let second = call("NtSetInformationObject", directory, 6, 0, 0);
        let attached = crate::ntos::ob::object_security::resolve_user_handle(directory).ok().map_or(0, |(pointer, _, _)| crate::ntos::ob::objects::namespace::session_object(pointer));
        call("NtClose", directory, 0, 0, 0);
        if let Some(region) = crate::ntos::ps::user::memory::find_region(block) {
            crate::ntos::ps::user::memory::release_private_region(&region);
        }
        Some((created, first, second, attached))
    })
    .flatten();
    assert(linked == Some((0, 0, 0xC000_0022, object_a)), "sessao: ObjectSessionObjectInformation liga o objeto Session da sessao ao diretorio uma vez; a segunda e STATUS_ACCESS_DENIED");
    session_notifications(assert, a, sa, id_a);

    // Tabela de topo por sessão, ligada na raiz de cada processo dela.
    let (top_a, top_b) = (session::tables(sa).map_or(0, |(top, _)| top), session::tables(sb).map_or(0, |(top, _)| top));
    let top_of = |root: u64| paging::session_top_level(root) & FRAME_MASK;
    assert(top_a != 0 && top_b != 0 && top_a != top_b && top_of(root_a) == top_a && top_of(root_c) == top_a && top_of(root_b) == top_b && paging::session_top_level(SYSTEM_ROOT) == 0, "sessao: tabela de topo propria de cada sessao no slot de sessao de cada raiz dela, vazio na do System");
    assert(space(sa).session_page_directory_index.get() == top_a >> 12 && space(sa).page_directory.u.long.get() & FRAME_MASK == top_a && space(sa).session_id.get() == id_a, "sessao: SessionPageDirectoryIndex e PageDirectory do MM_SESSION_SPACE apontam a tabela de topo");
    let core_frames = (paging::translate_in(root_a, map::SESSION_CORE_BASE), paging::translate_in(root_b, map::SESSION_CORE_BASE), paging::translate_in(root_c, map::SESSION_CORE_BASE));
    assert(core_session_id(a) == Some(id_a) && core_session_id(b) == Some(id_b) && core_session_id(c) == Some(id_a) && paging::translate_in(SYSTEM_ROOT, map::SESSION_CORE_BASE) == 0, "sessao: o MM_SESSION_SPACE em SessionCore, na mesma VA, com o id de cada sessao; ausente na raiz do System");
    assert(core_frames.0 != 0 && core_frames.1 != 0 && core_frames.0 != core_frames.1 && core_frames.2 == core_frames.0, "sessao: SessionCore em frames proprios de cada sessao, divididos entre os processos dela");
    assert(session::is_session_address(map::SESSION_CORE_BASE) && session::is_session_address(map::SESSION_SPACE_TOP - 1) && !session::is_session_address(map::KERNEL_POOL_BASE) && !session::is_session_address(map::SYSTEM_IMAGE_BASE) && !session::is_session_address(0x7FFE_0000), "sessao: MmIsSessionAddress so no slot de sessao");

    // MmAttachSession/MmDetachSession.
    let apc_state = guest::alloc_bytes(KapcState::SIZE);
    let attach_count = |pointer: u64| space(pointer).attach_count.get();
    let attached = session::attach(b, apc_state);
    let seen = (process::get_current_process() == b, paging::current_root() == root_b, session::current() == sb, attach_count(sb));
    let detached = session::detach(b, apc_state);
    assert(matches!(attached, Ok(0)) && seen == (true, true, true, 1) && matches!(detached, Ok(0)) && attach_count(sb) == 0 && process::get_current_process() == system && session::current() == 0, "sessao: MmAttachSession anexa a raiz da sessao e conta AttachCount; MmDetachSession volta");
    let driver = guest::alloc_bytes(DriverObject::SIZE);
    // SAFETY: DRIVER_OBJECT do teste.
    unsafe { DriverObject::at(driver) }.driver_unload.set(0xFFFF_F800_4000_1000);
    assert(session::by_id(id_a) == 0, "sessao: MmGetSessionById sem driver de sessao carregado devolve NULL");
    let _ = inside(a, || session::set_unload_address(driver));
    let found = session::by_id(id_a);
    assert(found == c && session::by_id(id_b) == 0 && space(sa).driver_unload.function.get() == 0xFFFF_F800_4000_1000, "sessao: MmGetSessionById devolve um processo da sessao que nao e o mestre");
    if found != 0 {
        let _ = process::dereference(found);
    }
    // O ExplicitScope de sessão do WNF acha o processo da sessão pelo
    // MmGetSessionById (ExpWnfCaptureScopeInstanceId 0x60fdda); a sessão B,
    // sem driver de sessão, dá nulo e STATUS_INVALID_PARAMETER.
    let scope = guest::alloc_bytes(4);
    guest::write32(scope, id_a);
    let captured = crate::ntos::ex::wnf::scope_capture::capture_kernel(1, scope);
    let scope_found = matches!(&captured, Ok(Ok(captured)) if captured.identity != 0);
    if let Ok(Ok(captured)) = captured {
        let _ = captured.release();
    }
    guest::write32(scope, id_b);
    let scope_refused = matches!(crate::ntos::ex::wnf::scope_capture::capture_kernel(1, scope), Ok(Err(0xC000_000D)));
    guest::free_bytes(scope);
    assert(scope_found && scope_refused, "wnf: ExplicitScope de sessao acha o processo da sessao pelo MmGetSessionById");

    // PagedPoolSession.
    let paged_a = inside(a, || pool_allocation::allocate_tagged(PAGED_POOL_SESSION, 0x100, PAGED_TAG).unwrap_or(0)).unwrap_or(0);
    let in_dynamic = (map::SESSION_DYNAMIC_VA_BASE..map::SESSION_DYNAMIC_VA_TOP).contains(&paged_a);
    let _ = inside(a, || guest::write64(paged_a, MARK_A));
    let tags_a = inside(a, || session_pool::tag_counts(PAGED_TAG)).flatten();
    assert(in_dynamic && tags_a == Some([1, 0, 0x110, 0, 0, 0]), "sessao: PagedPoolSession na VA dinamica da sessao, com PagedAllocs 1 e PagedBytes 0x110 no PoolTags dela");
    assert(paging::translate_in(root_a, paged_a) != 0 && paging::translate_in(root_c, paged_a) == paging::translate_in(root_a, paged_a) && paging::translate_in(root_b, paged_a) == 0 && paging::translate_in(SYSTEM_ROOT, paged_a) == 0 && inside(b, || session_pool::tag_counts(PAGED_TAG)).flatten().is_none(), "sessao: o bloco de pool de sessao so existe nas raizes da sessao dele");
    let paged_b = inside(b, || pool_allocation::allocate_tagged(PAGED_POOL_SESSION, 0x100, PAGED_TAG).unwrap_or(0)).unwrap_or(0);
    let _ = inside(b, || guest::write64(paged_b, MARK_B));
    let marks = (inside(a, || guest::read64(paged_a)), inside(b, || guest::read64(paged_b)));
    assert(paged_b == paged_a && paging::translate_in(root_b, paged_b) != paging::translate_in(root_a, paged_a) && marks == (Some(MARK_A), Some(MARK_B)), "sessao: a outra sessao recebe a mesma VA em outro frame, com conteudo proprio");
    let wrong = inside(b, || session_pool::check_free(paged_a + 0x10)).flatten();
    assert(wrong == Some((0xC2, [0, 0, paged_a + 0x10, 0])) && session_pool::check_free(paged_a) == Some((0xC2, [0, 0, paged_a, 0])) && inside(a, || session_pool::check_free(paged_a)).flatten().is_none(), "sessao: liberar fora do heap da sessao corrente da BAD_POOL_CALLER (0, 0, VA, 0)");
    let freed_b = inside(b, || pool_allocation::free(paged_b, 0).is_ok() && session_pool::tag_counts(PAGED_TAG) == Some([1, 1, 0, 0, 0, 0])).unwrap_or(false);
    assert(freed_b && session_pool::block(sb, paged_b).is_none() && session_pool::block(sa, paged_a).is_some(), "sessao: ExFreePool no heap da sessao conta PagedFrees e zera os bytes so nela");
    let nonpaged = inside(a, || {
        let pointer = pool_allocation::allocate_tagged(NONPAGED_POOL_SESSION, 0x40, NONPAGED_TAG).unwrap_or(0);
        let counted = session_pool::tag_counts(NONPAGED_TAG);
        let freed = pointer != 0 && pool_allocation::free(pointer, 0).is_ok();
        (pointer, counted, freed, session_pool::tag_counts(NONPAGED_TAG))
    });
    assert(nonpaged.is_some_and(|(pointer, counted, freed, after)| pointer != 0 && !session::is_session_address(pointer) && paging::translate_in(SYSTEM_ROOT, pointer) != 0 && counted == Some([0, 0, 0, 1, 0, 0x50]) && freed && after == Some([0, 0, 0, 1, 1, 0])), "sessao: NonPagedPoolSession e VA de sistema com NonPagedAllocs/Frees/Bytes na sessao corrente");

    // O BOOTVID.DLL real como imagem de sessão nas duas sessões.
    let status_a = inside(a, || load(1)).unwrap_or(1);
    let (entry, base) = (guest::read64(handle), guest::read64(base_out));
    let status_b = inside(b, || load(1)).unwrap_or(1);
    let same = guest::read64(handle) == entry && guest::read64(base_out) == base;
    let again = inside(a, || load(1)).unwrap_or(1);
    // SAFETY: a KLDR_DATA_TABLE_ENTRY viva da imagem de sessão.
    let load_count = || if entry != 0 { unsafe { KldrDataTableEntry::at(entry) }.load_count.get() } else { 0 };
    assert(status_a == 0 && status_b == 0 && again == 0 && same && (map::SESSION_IMAGE_BASE..map::SESSION_IMAGE_TOP).contains(&base) && session_image::is_session_image(base) && load_count() == 2, "sessao: o BOOTVID.DLL carregado nas duas sessoes na mesma VA de sessao, com a mesma entrada e LoadCount 2");
    // A segunda carga na sessão a contou mais uma carga nela (o
    // ImageCountInThisSession), sem mexer no LoadCount: o primeiro
    // MmUnloadSystemImage só desconta, e a imagem segue mapeada em a.
    let discounted = inside(a, || sysload::unload_system_image(entry).is_ok()).unwrap_or(false);
    assert(discounted && paging::translate_in(root_a, base) != 0 && load_count() == 2 && session_image::sessions_of(base).len() == 2, "sessao: a segunda carga na mesma sessao conta uma carga a mais e o MmUnloadSystemImage seguinte so a desconta");
    assert(load(1) == STATUS_NO_MEMORY && guest::read64(base_out) == 0, "sessao: carga de sessao fora de uma sessao = STATUS_NO_MEMORY");
    let sections = inside(a, || (guest::read16(base), section(base, b".text\0"), section(base, b".data\0"))).unwrap_or((0, None, None));
    let (Some((text, text_flags)), Some((data, data_flags))) = (sections.1, sections.2) else {
        assert(false, "sessao: secoes .text e .data do BOOTVID.DLL legiveis na sessao");
        return;
    };
    assert(sections.0 == 0x5A4D && text_flags & 0x2000_0000 != 0 && data_flags & 0x8000_0000 != 0, "sessao: cabecalho e secoes do BOOTVID.DLL lidos na VA de sessao");
    let (code, writable_page) = (base + text, base + data);
    let master_code = session_image::master_frame(code);
    assert(master_code != 0 && paging::translate_in(root_a, code) == master_code && paging::translate_in(root_b, code) == master_code && !writable(root_a, code) && !writable(root_b, code) && paging::translate_in(SYSTEM_ROOT, code) == 0, "sessao: o codigo da imagem de sessao nos mesmos frames mestres nas duas sessoes, sem escrita");
    let master_data = session_image::master_frame(writable_page);
    let (data_a, data_b) = (paging::translate_in(root_a, writable_page), paging::translate_in(root_b, writable_page));
    assert(data_a != 0 && data_b != 0 && data_a != data_b && data_a != master_data && data_b != master_data && writable(root_a, writable_page) && writable(root_b, writable_page), "sessao: a .data da imagem de sessao em copias privadas de cada sessao");
    let cookie = physical::read64(master_data + data % 0x1000);
    let pristine = physical::read64(master_data + (data + 0x80) % 0x1000);
    let cookies = (inside(a, || guest::read64(writable_page)), inside(b, || guest::read64(writable_page)));
    assert(cookies == (Some(cookie), Some(cookie)), "sessao: as copias da .data comecam iguais a mestra (o cookie GS)");
    let _ = inside(a, || guest::write64(writable_page + 0x80, MARK_A));
    let globals = (inside(a, || guest::read64(writable_page + 0x80)), inside(b, || guest::read64(writable_page + 0x80)));
    assert(globals == (Some(MARK_A), Some(pristine)) && pristine != MARK_A && physical::read64(master_data + (data + 0x80) % 0x1000) == pristine, "sessao: a escrita num global da imagem numa sessao nao aparece na outra nem na mestra");
    let unloaded = inside(b, || sysload::unload_system_image(entry).is_ok()).unwrap_or(false);
    assert(unloaded && paging::translate_in(root_b, base) == 0 && paging::translate_in(root_a, base) != 0 && load_count() == 1 && session_image::sessions_of(base) == alloc::vec![sa], "sessao: MmUnloadSystemImage tira a imagem so da sessao corrente (LoadCount 1)");

    // Fim: os processos saem; as sessões somem com o pool e a imagem que
    // sobraram.
    let exits = (user_process::run_created(first), user_process::run_created(second), user_process::run_created(child));
    let ran = matches!(exits, (Ok(0x61), Ok(0x62), Ok(0x63)));
    assert(ran, "sessao: os tres processos rodam e saem com os proprios codigos");
    let _ = process::dereference(a);
    let _ = process::dereference(b);
    let _ = process::dereference(c);
    kernel_stack::reap();
    guest::free_bytes(apc_state);
    guest::free_bytes(driver);
    guest::free_bytes(block);
    let free_after = pfn::free_count();
    if free_after != free_before {
        crate::debug_print!("[sessao] PFN livre antes {} depois {}", free_before, free_after);
    }
    assert(session::count() == sessions_before && session::id_of(sa).is_none() && session::id_of(sb).is_none() && !session_image::is_session_image(base) && loaded_images::find(base).is_none() && session_pool::usage(sa) == (0, 0), "sessao: o fim dos processos desfaz as duas sessoes, com o pool vivo e a imagem ainda carregada");
    assert(free_after == free_before, "sessao: o PFN livre volta ao de antes das sessoes");
}
