//! Self-test da fase 7 — modo usuário.
//!
//! Exercita, conforme entram, o estado do subsistema de usuário (tabela de
//! handles do processo, sondas de memória), a validação de vistas e os
//! módulos de seções, processos, threads e ALPC.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types as nt;
use crate::ntos::ps::user::state::{self, NativeBody, UserObject};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

type Assert = fn(bool, &str);

/// Texto UTF-16 sem NUL numa cópia de bloco; devolve o comprimento em bytes.
fn write_wide(at: u64, text: &str) -> u16 {
    let bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    guest::write_bytes(at, &bytes);
    bytes.len() as u16
}

/// UNICODE_STRING com os três campos.
fn set_unicode(string: &nt::UnicodeString, length: u16, maximum_length: u16, buffer: u64) {
    string.length.set(length);
    string.maximum_length.set(maximum_length);
    string.buffer.set(buffer);
}

/// OBJECT_ATTRIBUTES completo (os campos não citados ficam zerados).
fn set_object_attributes(attributes: &nt::ObjectAttributes, length: u32, root: u64, name: u64, flags: u32) {
    attributes.length.set(length);
    attributes.root_directory.set(root);
    attributes.object_name.set(name);
    attributes.attributes.set(flags);
    attributes.security_descriptor.set(0);
    attributes.security_quality_of_service.set(0);
}

/// Atributo de contexto ALPC no formato compacto (campos de 32 bits) que o
/// NtAlpcCancelMessage aceita com a flag 4.
#[repr(C)]
struct AlpcContextAttr32 {
    port_context: Field<u32>,
    message_context: Field<u32>,
    sequence: Field<u32>,
    message_id: Field<u32>,
    callback_id: Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for AlpcContextAttr32 {}

const _: () = {
    assert!(core::mem::size_of::<AlpcContextAttr32>() == 0x14);
    assert!(core::mem::offset_of!(AlpcContextAttr32, callback_id) == 0x10);
};

/// Informação de conexão da sessão CSR (48 bytes), no formato que
/// `ps/user/csr` recebe e devolve.
#[repr(C)]
struct CsrConnectionInformation {
    shared_section_base: Field<u64>,
    shared_static_server_data: Field<u64>,
    server_process_id: Field<u64>,
    reserved: Field<u64>,
    server_id: Field<u32>,
    status: Field<u32>,
    /// Dados do servidor 1: o callback de criação de processo.
    server_data: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for CsrConnectionInformation {}

/// Pedido CSR de conexão a um servidor: PORT_MESSAGE seguido do corpo
/// ApiNumber/ReturnValue e do pedido ClientConnect.
#[repr(C)]
struct CsrClientConnectMessage {
    header: nt::PortMessage,
    capture_buffer: Field<u64>,
    api_number: Field<u32>,
    return_value: Field<u32>,
    reserved: Field<u32>,
    _pad_3c: Reserved<4>,
    server_id: Field<u32>,
    _pad_44: Reserved<4>,
    connection_information: Field<u64>,
    connection_information_length: Field<u32>,
    _pad_54: Reserved<4>,
}

// SAFETY: #[repr(C)] só de células e de estruturas do NT.
unsafe impl NtStruct for CsrClientConnectMessage {}

const _: () = {
    assert!(core::mem::size_of::<CsrConnectionInformation>() == 48);
    assert!(core::mem::offset_of!(CsrConnectionInformation, server_id) == 0x20);
    assert!(core::mem::size_of::<CsrClientConnectMessage>() == 88);
    assert!(core::mem::offset_of!(CsrClientConnectMessage, return_value) == 0x34);
    assert!(core::mem::offset_of!(CsrClientConnectMessage, server_id) == 0x40);
    assert!(core::mem::offset_of!(CsrClientConnectMessage, connection_information_length) == 0x50);
};

/// Cabeçalho PORT_MESSAGE zerado com os comprimentos dados.
fn init_port_message(message: &nt::PortMessage, data_length: u16, total_length: u16) {
    guest::write_bytes(message.address(), &[0u8; nt::PortMessage::SIZE as usize]);
    message.u1.s1.data_length.set(data_length as i16);
    message.u1.s1.total_length.set(total_length as i16);
}

/// Objeto de usuário instrumentado: conta os ganchos de handle.
struct TestObject {
    kind: &'static str,
    body: Option<NativeBody>,
    opens: AtomicU32,
    closes: AtomicU32,
    last: AtomicU32,
    released: AtomicU32,
}

impl TestObject {
    fn new(kind: &'static str, body: Option<NativeBody>) -> Arc<Self> {
        Arc::new(Self { kind, body, opens: AtomicU32::new(0), closes: AtomicU32::new(0), last: AtomicU32::new(0), released: AtomicU32::new(0) })
    }

    fn count(counter: &AtomicU32) -> u32 {
        counter.load(Ordering::Relaxed)
    }
}

impl UserObject for TestObject {
    fn kind(&self) -> &'static str {
        self.kind
    }
    fn native_body(&self) -> Option<NativeBody> {
        self.body.clone()
    }
    fn on_each_handle_open(&self) -> Result<bool, KernelError> {
        self.opens.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }
    fn on_each_handle_close(&self) {
        self.closes.fetch_add(1, Ordering::Relaxed);
    }
    fn on_handle_closed(&self) {
        self.last.fetch_add(1, Ordering::Relaxed);
    }
    fn release(&self) {
        self.released.fetch_add(1, Ordering::Relaxed);
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

static BODY_REFERENCES: AtomicI32 = AtomicI32::new(0);

fn user_handle_table(assert: Assert) {
    let count = TestObject::count;
    let object = TestObject::new("event", None);
    let Ok(handle) = state::alloc_user_handle(object.clone(), 0x1F_0003, 0) else {
        assert(false, "user: handle alocado");
        return;
    };
    let entry = state::get_user_handle(handle as u64);
    assert(handle >= 0x100 && handle & 3 == 0 && count(&object.opens) == 1 && entry.as_ref().is_some_and(|entry| entry.access() == 0x1F_0003 && entry.kind() == "event" && entry.downcast::<TestObject>().is_some()), "user: handle baixo com acesso, tipo e gancho de abertura");
    let Some(entry) = entry else { return };
    let Ok(duplicate) = state::duplicate_user_handle(&entry, 1, 0) else {
        assert(false, "user: duplicata alocada");
        return;
    };
    let duplicate_entry = state::get_user_handle(duplicate as u64);
    assert(duplicate != handle && duplicate_entry.as_ref().is_some_and(|other| other.access() == 1 && state::same_object(&entry, other)) && entry.access() == 0x1F_0003 && count(&object.opens) == 2, "user: duplicata compartilha a descricao com acesso proprio");
    assert(state::change_user_handle_attributes(duplicate as u64, 1).is_ok_and(|status| status == 0) && state::close_user_handle(duplicate as u64, true, false).is_ok_and(|status| status == 0xC000_0235), "user: handle protegido recusa o fechamento");
    assert(state::close_user_handle(duplicate as u64, true, true).is_ok_and(|status| status == 0) && count(&object.closes) == 1 && count(&object.last) == 0 && count(&object.released) == 0 && state::get_user_handle(duplicate as u64).is_none(), "user: fechamento forcado da duplicata conserva a descricao");
    state::retain_user_handle_reference(&entry);
    assert(state::close_user_handle(handle as u64, true, false).is_ok_and(|status| status == 0) && count(&object.last) == 1 && count(&object.released) == 0, "user: espera em curso adia a liberacao do ultimo handle");
    assert(state::release_user_handle_reference(&entry).is_ok() && count(&object.released) == 1 && state::release_user_handle_reference(&entry).is_err(), "user: liberacao ao fim da espera e desbalanceamento recusado");
    assert(state::close_user_handle(handle as u64, true, false).is_ok_and(|status| status == 0xC000_0008), "user: handle fechado fica invalido");
    // Corpo nativo: publicado na HANDLE_TABLE do processo e retido nas esperas.
    let block = guest::alloc_bytes(0x80);
    let pointer = (block + 0x3F) & !0xF;
    let body = NativeBody {
        pointer,
        type_name: String::from("Event"),
        record: pointer,
        reference: Arc::new(|| {
            BODY_REFERENCES.fetch_add(1, Ordering::Relaxed);
        }),
        dereference: Arc::new(|| {
            BODY_REFERENCES.fetch_sub(1, Ordering::Relaxed);
        }),
    };
    let native = TestObject::new("event", Some(body));
    let published = state::alloc_user_handle(native.clone(), 0x1F_0003, 0);
    assert(published.is_ok(), "user: corpo nativo publicado na tabela de handles do processo");
    if let Ok(handle) = published {
        let entry = state::get_user_handle(handle as u64);
        if let Some(entry) = &entry {
            state::retain_user_handle_reference(entry);
            let retained = BODY_REFERENCES.load(Ordering::Relaxed);
            let _ = state::release_user_handle_reference(entry);
            assert(retained == 1 && BODY_REFERENCES.load(Ordering::Relaxed) == 0, "user: espera retem e libera o corpo nativo");
        }
        // NtClose interno (force) pelo provedor instalado no ob/close.
        assert(crate::ntos::ob::close::close_user(handle as u64, false) == 0 && count(&native.released) == 1 && state::get_user_handle(handle as u64).is_none(), "user: ob close fecha pela tabela de usuario e libera o objeto");
    }
    guest::free_bytes(block);
    // Threads sem abertura nativa passam pelos callbacks de objeto.
    if crate::ntos::ob::callbacks::registration_count() == 0 {
        let thread = TestObject::new("thread", None);
        let routed = state::alloc_user_handle(thread.clone(), 0x1F_FFFF, 0);
        assert(routed.as_ref().is_ok_and(|handle| state::get_user_handle(*handle as u64).is_some_and(|entry| entry.access() == 0x1F_FFFF)), "user: thread roteada pelos callbacks sem registros");
        if let Ok(handle) = routed {
            let _ = state::close_user_handle(handle as u64, false, true);
        }
    }
}

fn user_memory_helpers(assert: Assert) {
    assert(!state::probe_user_read(0, 8) && state::probe_user_read(0x1000, 0) && !state::probe_user_read(0x7FFF_FFFF_0000, 1) && !state::probe_user_write(u64::MAX - 4, 8), "user: sondas recusam NULL, o limite e o estouro");
    // A arena do kernel não tem o bit USER: a sonda recusa.
    let block = guest::alloc_bytes(0x40);
    assert(!state::probe_user_read(block, 8), "user: memoria de supervisor recusada pela sonda");
    let length = state::write_user_wide(block, "ntdll");
    state::write_unicode_string(block + 0x20, block, "ntdll");
    let string = unsafe { nt::UnicodeString::at(block + 0x20) };
    assert(length == 10 && state::read_user_wide_string(block, 5) == "ntdll" && string.length.get() == 10 && string.maximum_length.get() == 12 && string.buffer.get() == block, "user: strings largas e UNICODE_STRING de usuario");
    guest::write64(block + 0x28 + 0x08, 0x1234);
    assert(state::stack_arg(block, 6) == 0x1234 && state::stack_arg32(block, 6) == 0x1234, "user: argumento de pilha do syscall");
    guest::free_bytes(block);
    assert(state::with(|state| state.next_process_id == 300 || state.next_process_id > 300) && state::handler("NtNaoExiste").is_none(), "user: estado inicial e tabela de handlers");
}

fn map_view_parameter_validation(assert: Assert) {
    use crate::ntos::mm::section::map_view_parameters::{self as parameters, Decoded, MapInput, SectionTraits};
    assert(parameters::protection(4) == 4 && parameters::protection(0x104) == 20 && parameters::protection(0x204) == 12 && parameters::protection(0x401) == -1 && parameters::protection(0x804) == -1 && parameters::protection(3) == -1, "mapview: mascaras de protecao");
    assert(parameters::prefix(21, 4).is_ok_and(|prefix| prefix.zero == 53 && prefix.access == 2) && parameters::prefix(22, 4) == Err(0xC000_000D) && parameters::prefix(0, 3) == Err(0xC000_0045) && parameters::prefix(0xFFFF_FFFF, 2).is_ok_and(|prefix| prefix.zero == 32), "mapview: ZeroBits e protecao");
    let data = SectionTraits { size: 0x3000, page_protect: 4, ..Default::default() };
    let input = MapInput { protect: 4, inherit: 2, ..Default::default() };
    assert(matches!(parameters::decode(&data, &input, None), Decoded::View(view) if view.base == 0 && view.size == 0x3000 && view.alignment == 0x1_0000 && view.upper == 0x7FFF_FFFE_FFFF), "mapview: vista inteira da secao");
    assert(parameters::decode(&data, &MapInput { offset: 0x1000, ..input }, None) == Decoded::Status(0xC000_0220) && parameters::decode(&data, &MapInput { inherit: 3, ..input }, None) == Decoded::Status(0xC000_000D) && parameters::decode(&data, &MapInput { protect: 0x40, ..input }, None) == Decoded::Status(0xC000_004E) && parameters::decode(&data, &MapInput { size: 0x4000, ..input }, None) == Decoded::Status(0xC000_001F), "mapview: alinhamento, heranca, protecao e extensao");
    assert(matches!(parameters::decode(&data, &MapInput { base: 0x1_0000, size: 0x1000, ..input }, None), Decoded::View(view) if view.base == 0x1_0000 && view.size == 0x1000), "mapview: base explicita");
    let image = SectionTraits { is_image: true, size: 0x3000, page_protect: 0x80, ..Default::default() };
    assert(parameters::decode(&image, &MapInput { allocation: 0x2000_0000, ..input }, None) == Decoded::Boundary("lock_pages_privilege_check"), "mapview: imagem com paginas grandes vai a fronteira de privilegio");
    let readonly = SectionTraits { size: 0x3000, page_protect: 2, ..Default::default() };
    assert(parameters::decode(&readonly, &MapInput { protect: 2, size: 0x1_0000, allocation: 0x2000, ..input }, None) == Decoded::Status(0xC000_004E), "mapview: MEM_RESERVE exige secao gravavel");
    assert(parameters::captured(0x7FFF_FFFF_0000, 0, 0) == 0xC000_000D && parameters::captured(0x1_0000, 0x1000, 0) == 0, "mapview: captura abaixo do limite de usuario");
}

/// Arquivo em memória para seções de arquivo e de imagem.
struct MemoryFile {
    identity: Option<String>,
    bytes: crate::rtl::SpinLock<alloc::vec::Vec<u8>>,
    writes: crate::rtl::SpinLock<alloc::vec::Vec<(u64, usize)>>,
}

impl MemoryFile {
    fn new(identity: Option<&str>, bytes: alloc::vec::Vec<u8>) -> Arc<Self> {
        Arc::new(Self { identity: identity.map(String::from), bytes: crate::rtl::SpinLock::new(bytes), writes: crate::rtl::SpinLock::new(alloc::vec::Vec::new()) })
    }
}

impl crate::ntos::ps::user::sections::SectionFile for MemoryFile {
    fn identity(&self) -> Option<String> {
        self.identity.clone()
    }
    fn size(&self) -> u64 {
        self.bytes.lock().len() as u64
    }
    fn read_at(&self, offset: u64, length: u64) -> Result<alloc::vec::Vec<u8>, KernelError> {
        let bytes = self.bytes.lock();
        let end = ((offset + length) as usize).min(bytes.len());
        Ok(bytes[(offset as usize).min(end)..end].to_vec())
    }
    fn write_at(&self, offset: u64, data: &[u8]) -> Result<(), KernelError> {
        self.writes.lock().push((offset, data.len()));
        self.bytes.lock()[offset as usize..offset as usize + data.len()].copy_from_slice(data);
        Ok(())
    }
    fn nt_path(&self) -> Option<String> {
        Some(String::from("\\Device\\HarddiskVolume1\\opennt-secao.bin"))
    }
}

/// PE32+ AMD64 mínimo: cabeçalhos em 0x200 e uma seção de código em 0x1000.
fn minimal_image() -> alloc::vec::Vec<u8> {
    let mut bytes = alloc::vec![0u8; 0x400];
    bytes[0] = b'M';
    bytes[1] = b'Z';
    bytes[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    bytes[0x40..0x44].copy_from_slice(&0x4550u32.to_le_bytes());
    bytes[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
    bytes[0x46..0x48].copy_from_slice(&1u16.to_le_bytes());
    bytes[0x54..0x56].copy_from_slice(&0xF0u16.to_le_bytes());
    bytes[0x58..0x5A].copy_from_slice(&0x20Bu16.to_le_bytes());
    bytes[0x40 + 80..0x40 + 84].copy_from_slice(&0x2000u32.to_le_bytes());
    bytes[0x40 + 84..0x40 + 88].copy_from_slice(&0x200u32.to_le_bytes());
    let table = 0x40 + 24 + 0xF0;
    bytes[table + 8..table + 12].copy_from_slice(&0x100u32.to_le_bytes());
    bytes[table + 12..table + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[table + 16..table + 20].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[table + 20..table + 24].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[table + 36..table + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    bytes[0x200] = 0xC3;
    bytes
}

fn data_sections(assert: Assert) {
    use crate::hal::physical;
    use crate::ntos::mm::paging;
    use crate::ntos::ps::user::sections::{self, CreateOptions, MapRequest};
    let Ok(Ok(section)) = sections::create(CreateOptions { size: 0x2800, page_protect: 4, attributes: 0x0800_0000, ..CreateOptions::default() }) else {
        assert(false, "sections: secao de dados criada");
        return;
    };
    assert(section.pointer() != 0 && section.size == 0x3000 && section.maximum_size == 0x2800 && section.frames().len() == 3, "sections: SEC_COMMIT arredonda e confirma as paginas");
    let regions = state::with(|state| state.user_regions.len());
    let request = MapRequest { protect: 4, ..MapRequest::default() };
    let first = sections::map(&section, &request);
    let second = sections::map(&section, &request);
    let (Ok(Ok(first)), Ok(Ok(second))) = (first, second) else {
        assert(false, "sections: duas vistas mapeadas");
        return;
    };
    let frame = section.frame(0).unwrap_or(0);
    assert(first.base != second.base && first.base % 0x1_0000 == 0 && paging::translate(first.base) == frame && paging::translate(second.base) == frame && paging::access_flags(first.base) & (paging::PAGE_USER | paging::PAGE_RW) == paging::PAGE_USER | paging::PAGE_RW && state::with(|state| state.user_regions.len()) == regions + 2, "sections: vistas sao aliases das mesmas paginas com USER e RW");
    assert(sections::map(&section, &MapRequest { offset: 0x1000, ..request }).is_ok_and(|mapped| mapped.is_err_and(|status| status == 0xC000_0220)) && sections::map(&section, &MapRequest { protect: 0x40, ..request }).is_ok_and(|mapped| mapped.is_err_and(|status| status == 0xC000_004E)) && sections::map(&section, &MapRequest { size: 0x4000, ..request }).is_ok_and(|mapped| mapped.is_err_and(|status| status == 0xC000_001F)), "sections: alinhamento, protecao e extensao recusados");
    // Copy-on-write: a falta de escrita publica uma página privada.
    physical::write_bytes(frame, b"compartilhado");
    let Ok(Ok(copy)) = sections::map(&section, &MapRequest { protect: 8, ..request }) else {
        assert(false, "sections: vista WRITECOPY");
        return;
    };
    let read_only_before = paging::access_flags(copy.base) & paging::PAGE_RW == 0;
    let faulted = sections::fault(copy.base, 3);
    let private = paging::translate(copy.base);
    assert(read_only_before && faulted && private != 0 && private != frame && physical::read_bytes(private, 13) == b"compartilhado" && paging::access_flags(copy.base) & paging::PAGE_RW != 0 && paging::translate(first.base) == frame && !sections::fault(copy.base, 3), "sections: copy-on-write copia para um PFN privado");
    assert(sections::protect_view(&copy, copy.base, 0x1000, 2) == 0 && paging::access_flags(copy.base) & paging::PAGE_RW == 0 && paging::translate(copy.base) == private && sections::protect_view(&copy, copy.base, 0x1000, 0x202) == 0xC000_00F2 && sections::protect_view(&copy, copy.base, 0x1000, 0x104) == 0xC000_004E && sections::protect_view(&copy, copy.base + 0x3000, 0x1000, 2) == 0xC000_002D, "sections: protecao por pagina, cache recusado e pagina nao confirmada");
    // Retenção protegida: só o próprio token desmonta a vista.
    let token = crate::ntos::mm::section::secured_views::acquire(&copy);
    assert(token.as_ref().is_ok_and(|_| sections::protection_status(&copy, 1) == 0xC000_0045 && sections::unmap(&copy, None).is_err_and(|error| error.status == 0xC000_0045)), "sections: vista protegida recusa NOACCESS e desmontagem sem o token");
    if let Ok(token) = &token {
        assert(sections::unmap(&copy, Some(token)).is_ok() && crate::ntos::mm::section::secured_views::release(token).is_ok() && crate::ntos::mm::section::secured_views::acquire(&copy).is_err_and(|status| status == 0xC000_0019) && paging::translate(copy.base) == 0, "sections: o token autoriza a desmontagem e a vista retirada nao aceita retencao");
    }
    // Commit sob demanda pela vista.
    let Ok(Ok(sparse)) = sections::create(CreateOptions { size: 0x3000, page_protect: 4, committed: Some(false), ..CreateOptions::default() }) else {
        assert(false, "sections: secao reservada");
        return;
    };
    let Ok(Ok(lazy)) = sections::map(&sparse, &MapRequest { commit_size: 0x1000, no_change: true, ..request }) else {
        assert(false, "sections: vista com commit parcial");
        return;
    };
    assert(sparse.frames().len() == 1 && paging::translate(lazy.base) != 0 && paging::translate(lazy.base + 0x1000) == 0, "sections: commit parcial confirma so a primeira pagina");
    assert(sections::commit_view(&lazy, lazy.base + 0x1000, 0x1000, 4).is_ok_and(|status| status == 0) && sparse.frames().len() == 2 && paging::translate(lazy.base + 0x1000) == sparse.frame(1).unwrap_or(1), "sections: commit pela vista publica a pagina nova");
    assert(sections::protect_view(&lazy, lazy.base, 0x1000, 2) == 0xC000_0045, "sections: SEC_NO_CHANGE recusa trocar a protecao");
    let sparse_pointer = sparse.pointer();
    assert(sections::unmap(&lazy, None).is_ok() && sections::by_pointer(sparse_pointer).is_none() && sparse.state.lock().destroyed && sparse.frames().is_empty(), "sections: a ultima vista destroi a secao sem handles");
    // Vistas restantes da primeira seção.
    let pointer = section.pointer();
    assert(sections::unmap(&first, None).is_ok() && paging::translate(first.base) == 0 && sections::by_pointer(pointer).is_some() && sections::unmap(&first, None).is_err(), "sections: desmontagem remove o alias e recusa repeticao");
    assert(sections::unmap(&second, None).is_ok() && sections::by_pointer(pointer).is_none() && state::with(|state| state.user_regions.len()) == regions, "sections: a ultima vista libera a secao e as regioes");
}

fn file_and_named_sections(assert: Assert) {
    use crate::hal::physical;
    use crate::ntos::ps::user::sections::{self, CreateOptions, MapRequest};
    let mut contents = alloc::vec![0x41u8; 0x1800];
    contents[0x10..0x16].copy_from_slice(b"OpenNT");
    let file = MemoryFile::new(Some("opennt-secao-arquivo"), contents);
    let shared: Arc<dyn sections::SectionFile> = file.clone();
    let Ok(Ok(section)) = sections::create(CreateOptions { size: 0x1800, page_protect: 4, attributes: 0x0800_0000, file: Some(shared.clone()), name: Some(String::from("\\OpenNtSecaoTeste")), ..CreateOptions::default() }) else {
        assert(false, "sections: secao de arquivo nomeada criada");
        return;
    };
    let frame = section.frame(0).unwrap_or(0);
    assert(section.frames().len() == 2 && physical::read_bytes(frame + 0x10, 6) == b"OpenNT" && physical::read8(section.frame(1).unwrap_or(0) + 0x7FF) == 0x41 && physical::read8(section.frame(1).unwrap_or(0) + 0x800) == 0, "sections: paginas lidas do arquivo e o resto zerado");
    assert(sections::open("\\OpenNtSecaoTeste").is_ok_and(|opened| Arc::ptr_eq(&opened, &section)) && sections::create(CreateOptions { size: 0x1000, page_protect: 4, name: Some(String::from("\\OpenNtSecaoTeste")), ..CreateOptions::default() }).is_ok_and(|created| created.is_err_and(|status| status == 0xC000_0035)) && sections::open("\\OpenNtSecaoAusente").is_err_and(|status| status == 0xC000_0034), "sections: nome publicado, colisao e ausencia");
    // Writeback: só a diferença vai para o arquivo.
    physical::write_bytes(frame + 0x100, b"xyz");
    assert(sections::flush(&section).is_ok() && *file.writes.lock() == [(0x100u64, 3usize)] && &file.bytes.lock()[0x100..0x103] == b"xyz" && sections::flush(&section).is_ok() && file.writes.lock().len() == 1, "sections: flush grava so os bytes alterados uma vez");
    let Ok(Ok(view)) = sections::map(&section, &MapRequest { protect: 2, ..MapRequest::default() }) else {
        assert(false, "sections: vista da secao de arquivo");
        return;
    };
    assert(view.name.as_deref() == Some("\\Device\\HarddiskVolume1\\opennt-secao.bin") && crate::ntos::mm::paging::translate(view.base) == frame, "sections: vista de arquivo nomeada pelo caminho NT");
    // A segunda seção do mesmo arquivo reutiliza a control area.
    let reused = sections::create(CreateOptions { size: 0x1800, page_protect: 4, file: Some(shared.clone()), committed: Some(false), ..CreateOptions::default() });
    assert(reused.as_ref().is_ok_and(|created| created.as_ref().is_ok_and(|other| other.frame(0) == Some(frame))) && sections::create(CreateOptions { size: 0x1800, page_protect: 0x204, file: Some(shared), ..CreateOptions::default() }).is_ok_and(|created| created.is_err_and(|status| status == 0xC000_004E)), "sections: control area compartilhada pela identidade e cache divergente recusado");
    let pointer = section.pointer();
    assert(sections::unmap(&view, None).is_ok() && sections::by_pointer(pointer).is_none() && crate::ntos::ob::object_manager::lookup("\\OpenNtSecaoTeste").is_none(), "sections: destruicao remove o nome do namespace");
    if let Ok(Ok(other)) = reused {
        // Sem vistas nem handles: a coleta direta libera a control area.
        assert(crate::ntos::ob::objects::section::collect(other.pointer()).is_ok() && sections::by_pointer(other.pointer()).is_none(), "sections: segunda secao do arquivo coletada");
    }
}

fn image_sections(assert: Assert) {
    use crate::hal::physical;
    use crate::ntos::mm::{paging, system_image_pages};
    use crate::ntos::ps::user::sections::{self, MapRequest};
    let file: Arc<dyn sections::SectionFile> = MemoryFile::new(None, minimal_image());
    assert(sections::create_image(file.clone(), None, 4, true).is_ok_and(|created| created.is_err_and(|status| status == 0xC000_0045)) && sections::create_image(MemoryFile::new(None, alloc::vec![0u8; 0x100]), None, 2, false).is_ok_and(|created| created.is_err_and(|status| status == 0xC000_007B)), "sections: imagem NX exige PAGE_READONLY e PE invalido recusado");
    let Ok(Ok(image)) = sections::create_image(file, None, 0x80, false) else {
        assert(false, "sections: secao de imagem criada");
        return;
    };
    assert(image.is_image && image.size == 0x2000 && image.attributes == 0x0100_0000 && system_image_pages::prepare(&image).is_ok() && system_image_pages::protection(&image, 0) == 2 && system_image_pages::protection(&image, 1) == 0x20, "sections: layout PE com cabecalho legivel e codigo executavel");
    let Ok(Ok(view)) = sections::map(&image, &MapRequest { protect: 0x80, commit_size: 0x2000, ..MapRequest::default() }) else {
        assert(false, "sections: vista de imagem");
        return;
    };
    let code = paging::translate(view.base + 0x1000);
    assert(code != 0 && physical::read8(code) == 0xC3 && physical::read8(paging::translate(view.base)) == b'M' && paging::access_flags(view.base) & paging::PAGE_RW == 0, "sections: vista de imagem com o layout virtual do PE");
    let pointer = image.pointer();
    assert(sections::unmap(&view, None).is_ok() && sections::by_pointer(pointer).is_none(), "sections: imagem destruida na ultima vista");
}

/// Fonte de arquivo de imagem/dados para FILE_OBJECTs de teste.
struct BytesSource {
    bytes: alloc::vec::Vec<u8>,
}

impl crate::ntos::ob::objects::file::FileSource for BytesSource {
    fn name(&self) -> &str {
        "\\Device\\OpenNtTeste\\dados.bin"
    }
    fn size(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_at(&self, offset: u64, length: usize) -> Result<alloc::vec::Vec<u8>, KernelError> {
        let end = (offset as usize + length).min(self.bytes.len());
        Ok(self.bytes[(offset as usize).min(end)..end].to_vec())
    }
}

/// OBJECT_ATTRIBUTES em `block`, UNICODE_STRING em +0x40 e o nome em +0x60.
fn object_attributes_named(block: u64, name: &str, flags: u32) -> u64 {
    let unicode = block + 0x40;
    let text = block + 0x60;
    let length = state::write_user_wide(text, name) as u16;
    set_unicode(unsafe { nt::UnicodeString::at(unicode) }, length, length + 2, text);
    set_object_attributes(unsafe { nt::ObjectAttributes::at(block) }, nt::ObjectAttributes::SIZE as u32, 0, unicode, flags);
    block
}

fn section_creation(assert: Assert) {
    use crate::ntos::mm::section::create as create_section;
    use crate::ntos::ob::{object_manager, open_pointer};
    use crate::ntos::ob::objects::section as section_objects;
    use crate::ntos::ps::user::sections;
    let block = guest::alloc_bytes(0x400);
    let (output, size) = (block + 0x300, block + 0x308);
    let maximum = unsafe { nt::LargeInteger::at(size) };
    maximum.quad_part.set(0x3000);
    let pointer_of = |handle: u64| open_pointer::resolve(handle, false).and_then(|resolved| resolved.ok()).map_or(0, |resolved| resolved.item.pointer);
    // ZwCreateSection de pagefile com SEC_COMMIT.
    let status = create_section::create(output, 0xF_001F, 0, size, 4, 0x0800_0000, 0, 0, None);
    let handle = guest::read64(output);
    let pointer = pointer_of(handle);
    assert(status.is_ok_and(|status| status == 0) && sections::by_pointer(pointer).is_some_and(|section| section.size == 0x3000 && section.frames().len() == 3), "createsection: ZwCreateSection de pagefile confirmado");
    assert(open_pointer::close(handle) == Some(0) && sections::by_pointer(pointer).is_none(), "createsection: fechar o ultimo handle destroi a secao");
    // Nome, colisão e OPENIF.
    let attributes = object_attributes_named(block, "\\OpenNtSecaoNt", 0x40);
    let oa = unsafe { nt::ObjectAttributes::at(attributes) };
    let named = create_section::create(output, 0xF_001F, attributes, size, 4, 0x0800_0000, 0, 0, None);
    let first = guest::read64(output);
    let named_pointer = pointer_of(first);
    assert(named.is_ok_and(|status| status == 0) && object_manager::lookup("\\OpenNtSecaoNt").is_some() && sections::by_pointer(named_pointer).is_some_and(|section| section.name().as_deref() == Some("\\OpenNtSecaoNt")), "createsection: secao nomeada publicada no namespace");
    assert(create_section::create(output, 0xF_001F, attributes, size, 4, 0x0800_0000, 0, 0, None).is_ok_and(|status| status == 0xC000_0035), "createsection: colisao de nome sem OPENIF");
    oa.attributes.set(0xC0);
    let reopened = create_section::create(output, 0xF_001F, attributes, size, 4, 0x0800_0000, 0, 0, None);
    let second = guest::read64(output);
    assert(reopened.is_ok_and(|status| status == 0x4000_0000) && pointer_of(second) == named_pointer, "createsection: OPENIF abre a secao existente com OBJECT_NAME_EXISTS");
    assert(open_pointer::close(second) == Some(0) && sections::by_pointer(named_pointer).is_some() && open_pointer::close(first) == Some(0) && sections::by_pointer(named_pointer).is_none() && object_manager::lookup("\\OpenNtSecaoNt").is_none(), "createsection: secao temporaria some com o ultimo handle e o nome");
    // Recusas dos OBJECT_ATTRIBUTES.
    oa.attributes.set(0x40);
    oa.length.set(40);
    assert(create_section::create(output, 0xF_001F, attributes, size, 4, 0x0800_0000, 0, 0, None).is_ok_and(|status| status == 0xC000_000D), "createsection: Length invalido");
    let relative = object_attributes_named(block, "SemBarra", 0x40);
    assert(create_section::create(output, 0xF_001F, relative, size, 4, 0x0800_0000, 0, 0, None).is_ok_and(|status| status == 0xC000_003B), "createsection: nome relativo sem raiz");
    let trailing = object_attributes_named(block, "\\Final\\", 0x40);
    assert(create_section::create(output, 0xF_001F, trailing, size, 4, 0x0800_0000, 0, 0, None).is_ok_and(|status| status == 0xC000_0033), "createsection: barra final invalida");
    // MmCreateSection: corpo referenciado, sem handle.
    let object = create_section::create_object(output, 0, 0, size, 4, 0x0800_0000, 0, 0, 0);
    let body = guest::read64(output);
    assert(object.is_ok_and(|status| status == 0) && section_objects::reference_count(body) == Some(1) && sections::by_pointer(body).is_some(), "createsection: MmCreateSection devolve o SECTION referenciado");
    assert(section_objects::dereference(body).is_ok() && sections::by_pointer(body).is_none(), "createsection: a ultima referencia destroi a secao");
    // Seção de arquivo pelo FILE_OBJECT (MmCreateSection).
    let mut bytes = alloc::vec![0x5Au8; 0x1400];
    bytes[..6].copy_from_slice(b"OpenNT");
    let file_object = crate::ntos::ob::objects::file::create_source(Arc::new(BytesSource { bytes }));
    let Ok(file_object) = file_object else {
        assert(false, "createsection: FILE_OBJECT de teste");
        return;
    };
    let before = crate::ntos::ob::objects::file::reference_count(file_object);
    maximum.quad_part.set(0);
    let from_file = create_section::create_object(output, 0, 0, size, 2, 0x0800_0000, 0, file_object, 0);
    let file_section = guest::read64(output);
    let mapped = sections::by_pointer(file_section);
    assert(from_file.is_ok_and(|status| status == 0) && mapped.as_ref().is_some_and(|section| section.size == 0x2000 && section.maximum_size == 0x2000 && crate::hal::physical::read_bytes(section.frame(0).unwrap_or(0), 6) == b"OpenNT") && crate::ntos::ob::objects::file::reference_count(file_object) > before && section_objects::file_object(file_section).is_ok_and(|object| object == file_object), "createsection: secao de arquivo le o FILE_OBJECT e retem o arquivo");
    assert(create_section::create_object(output, 0, 0, size, 4, 0x0800_0000, 0, file_object, 0).is_ok_and(|status| status == 0xC000_0022), "createsection: arquivo sem escrita recusa PAGE_READWRITE");
    drop(mapped);
    assert(section_objects::dereference(file_section).is_ok() && sections::by_pointer(file_section).is_none() && crate::ntos::ob::objects::file::reference_count(file_object) == before, "createsection: destruicao solta o arquivo");
    let _ = crate::ntos::ob::objects::file::dereference(file_object);
    guest::free_bytes(block);
}

fn section_open_and_map(assert: Assert) {
    use crate::ntos::mm::section::{create as create_section, map_view, open as open_section, unmap_view};
    use crate::ntos::mm::paging;
    use crate::ntos::ob::{object_manager, open_pointer};
    use crate::ntos::ps::user::sections;
    let block = guest::alloc_bytes(0x400);
    let (output, size, base, view_size, offset) = (block + 0x300, block + 0x308, block + 0x310, block + 0x318, block + 0x320);
    unsafe { nt::LargeInteger::at(size) }.quad_part.set(0x2000);
    let attributes = object_attributes_named(block, "\\OpenNtSecaoAberta", 0x40);
    let created = create_section::create(output, 0xF_001F, attributes, size, 4, 0x0800_0000, 0, 0, None);
    let creator = guest::read64(output);
    let pointer = open_pointer::resolve(creator, false).and_then(|resolved| resolved.ok()).map_or(0, |resolved| resolved.item.pointer);
    assert(created.is_ok_and(|status| status == 0) && pointer != 0, "opensection: secao nomeada para abrir");
    // NtOpenSection por nome, com e sem caixa.
    let upper = object_attributes_named(block, "\\OPENNTSECAOABERTA", 0x40);
    let opened = open_section::open(output, 4, upper, 0);
    let handle = guest::read64(output);
    assert(opened.is_ok_and(|status| status == 0) && open_pointer::resolve(handle, false).and_then(|resolved| resolved.ok()).is_some_and(|resolved| resolved.item.pointer == pointer), "opensection: abre a secao existente sem caixa");
    let sensitive = object_attributes_named(block, "\\OPENNTSECAOABERTA", 0);
    guest::write64(output, 0xDEAD);
    assert(open_section::open(output, 4, sensitive, 0).is_ok_and(|status| status == 0xC000_0034) && guest::read64(output) == 0, "opensection: nome sensivel a caixa ausente grava handle zero");
    assert(open_section::open(output, 4, 0, 0).is_ok_and(|status| status == 0xC000_000D), "opensection: OBJECT_ATTRIBUTES nulo");
    let link = object_attributes_named(block, "\\OpenNtSecaoAberta", 0x140);
    assert(open_section::open(output, 4, link, 0).is_ok_and(|status| status == 0xC000_000D), "opensection: Section recusa OBJ_OPENLINK");
    let _ = object_manager::create_directory("\\OpenNtDiretorioTeste");
    let directory = object_attributes_named(block, "\\OpenNtDiretorioTeste", 0x40);
    assert(open_section::open(output, 4, directory, 0).is_ok_and(|status| status == 0xC000_0024), "opensection: objeto de outro tipo");
    let deep = object_attributes_named(block, "\\NaoExiste\\Secao", 0x40);
    assert(open_section::open(output, 4, deep, 0).is_ok_and(|status| status == 0xC000_003A), "opensection: caminho intermediario ausente");
    // NtMapViewOfSection/NtUnmapViewOfSection pelo handle aberto.
    let current = u64::MAX;
    guest::write64(base, 0);
    guest::write64(view_size, 0);
    unsafe { nt::LargeInteger::at(offset) }.quad_part.set(0);
    let mapped = map_view::map(handle, current, base, 0, 0, offset, view_size, 2, 0, 4, 0);
    let mapped_base = guest::read64(base);
    let section = sections::by_pointer(pointer);
    assert(mapped.is_ok_and(|status| status == 0) && mapped_base != 0 && guest::read64(view_size) == 0x2000 && section.as_ref().is_some_and(|section| paging::translate(mapped_base) == section.frame(0).unwrap_or(1)), "mapview: vista mapeada pelo handle com base e tamanho gravados");
    guest::write64(base, 0);
    guest::write64(view_size, 0);
    assert(map_view::map(handle, current, base, 0, 0, offset, view_size, 2, 0, 0x40, 0).is_ok_and(|status| status == 0xC000_004E) && map_view::map(handle, current, base, 0, 0, offset, view_size, 2, 0, 0x104, 0).is_ok_and(|status| status == 0xC000_00BB) && map_view::map(handle, current, base, 0, 0, offset, view_size, 3, 0, 4, 0).is_ok_and(|status| status == 0xC000_000D), "mapview: protecao incompativel, PAGE_GUARD na fronteira e heranca invalida");
    assert(map_view::map(0x7FF0, current, base, 0, 0, offset, view_size, 2, 0, 4, 0).is_ok_and(|status| status == 0xC000_0008) && map_view::map(handle, u64::MAX - 1, base, 0, 0, offset, view_size, 2, 0, 4, 0).is_ok_and(|status| status == 0xC000_0024) && map_view::map(current, current, base, 0, 0, offset, view_size, 2, 0, 4, 0).is_ok_and(|status| status == 0xC000_0024), "mapview: handles invalido, de thread e de outro tipo");
    assert(unmap_view::unmap(current, mapped_base, 0).is_ok_and(|status| status == 0) && paging::translate(mapped_base) == 0 && unmap_view::unmap(current, mapped_base, 0).is_ok_and(|status| status == 0xC000_0019) && unmap_view::validate_base(0x7FFF_FFFF_0000, 1) == 0xC000_0019 && unmap_view::validate_base(0x7FFF_FFFF_0000, 0) == 0, "unmapview: desmontagem pelo processo, repeticao e base invalida");
    assert(open_pointer::close(handle) == Some(0) && open_pointer::close(creator) == Some(0) && sections::by_pointer(pointer).is_none(), "opensection: handles fechados liberam a secao");
    drop(section);
    guest::free_bytes(block);
}

fn system_space_views(assert: Assert) {
    use crate::ntos::mm::section::{create as create_section, map_system_view, unmap_system_view};
    use crate::ntos::mm::{paging, system_view_paging};
    use crate::ntos::ob::objects::section as section_objects;
    use crate::ntos::ps::user::sections::{self, CreateOptions};
    let block = guest::alloc_bytes(0x100);
    let (output, size, base, offset) = (block, block + 8, block + 0x10, block + 0x18);
    unsafe { nt::LargeInteger::at(size) }.quad_part.set(0x3000);
    let created = create_section::create_object(output, 0, 0, size, 4, 0x0800_0000, 0, 0, 0);
    let body = guest::read64(output);
    assert(created.is_ok_and(|status| status == 0) && body != 0, "systemview: MmCreateSection para a vista global");
    // MmMapViewInSystemSpace: ViewSize zero publica o tamanho integral.
    guest::write64(size, 0);
    let mapped = map_system_view::map_from_start(body, base, size);
    let address = guest::read64(base);
    let section = sections::by_pointer(body);
    let view = sections::find_system_view(address);
    assert(mapped.is_ok_and(|status| status == 0) && guest::read64(size) == 0x3000 && view.as_ref().is_some_and(|view| view.supervisor && view.system_space && view.state.lock().system_paging) && section.as_ref().is_some_and(|section| paging::translate(address) == section.frame(0).unwrap_or(1)) && paging::access_flags(address) & paging::PAGE_USER == 0, "systemview: vista global de supervisor com o tamanho integral");
    assert(unmap_system_view::unmap(address).is_ok_and(|status| status == 0) && paging::translate(address) == 0 && sections::find_system_view(address).is_none(), "systemview: MmUnmapViewInSystemSpace remove a vista");
    // Ex: o offset soma o delta de 64 KiB ao tamanho e é alinhado.
    guest::write64(size, 0x1000);
    let section_offset = unsafe { nt::LargeInteger::at(offset) };
    section_offset.quad_part.set(0x1234);
    let extended = map_system_view::map(body, base, size, offset, 0);
    let extended_base = guest::read64(base);
    assert(extended.is_ok_and(|status| status == 0) && guest::read64(size) == 0x2234 && section_offset.quad_part.get() == 0 && sections::find_system_view(extended_base).is_some(), "systemview: Ex soma o delta do offset e alinha a 64 KiB");
    assert(unmap_system_view::unmap(extended_base).is_ok_and(|status| status == 0), "systemview: vista Ex removida");
    guest::write64(size, 0x1000);
    section_offset.quad_part.set(0);
    assert(map_system_view::map(body, base, size, offset, 2).is_ok_and(|status| status == 0xC000_00F4), "systemview: flags invalidas");
    guest::write64(size, 0x4000);
    assert(map_system_view::map(body, base, size, offset, 0).is_ok_and(|status| status == 0xC000_001F), "systemview: tamanho alem da secao");
    assert(section_objects::dereference(body).is_ok() && sections::by_pointer(body).is_none(), "systemview: secao liberada");
    drop(section);
    drop(view);
    // Paginação: o PFN volta ao sistema e o page-in restaura do arquivo.
    let mut contents = alloc::vec![0x33u8; 0x2000];
    contents[..6].copy_from_slice(b"OpenNT");
    let file: Arc<dyn sections::SectionFile> = MemoryFile::new(Some("opennt-paginacao"), contents);
    let Ok(Ok(paged)) = sections::create(CreateOptions { size: 0x2000, page_protect: 2, attributes: 0x0800_0000, file: Some(file), ..CreateOptions::default() }) else {
        assert(false, "systemview: secao de arquivo paginavel");
        return;
    };
    guest::write64(size, 0);
    let mapped = map_system_view::map_from_start(paged.pointer(), base, size);
    let paged_base = guest::read64(base);
    let Some(paged_view) = sections::find_system_view(paged_base).filter(|_| mapped.is_ok_and(|status| status == 0)) else {
        assert(false, "systemview: vista global do arquivo");
        return;
    };
    let evicted = system_view_paging::evict(&paged_view, 0);
    assert(evicted.is_ok_and(|evicted| evicted) && paging::translate(paged_base) == 0 && paged.frame(0).is_none() && system_view_paging::evicted(&paged) == [0], "systemview: despejo devolve o PFN e deixa a PTE reservada");
    let resolved = system_view_paging::resolve(paged_base);
    assert(resolved.as_ref().is_ok_and(|physical| physical.is_some_and(|physical| crate::hal::physical::read_bytes(physical, 6) == b"OpenNT")) && system_view_paging::evicted(&paged).is_empty() && paging::translate(paged_base) == paged.frame(0).unwrap_or(1), "systemview: resolucao faz page-in do arquivo e republica o alias");
    assert(system_view_paging::resolve(0x10).is_ok_and(|physical| physical.is_none()), "systemview: endereco fora da faixa nao e resolvido");
    let pointer = paged.pointer();
    drop(paged_view);
    assert(unmap_system_view::unmap(paged_base).is_ok_and(|status| status == 0) && sections::by_pointer(pointer).is_none(), "systemview: vista paginada removida e secao destruida");
    guest::free_bytes(block);
}

fn virtual_memory_queries(assert: Assert) {
    use crate::ntos::mm::query_virtual;
    use crate::ntos::ps::user::sections::{self, CreateOptions, MapRequest};
    let current = crate::ntos::ps::process::get_current_process();
    let block = guest::alloc_bytes(0x200);
    let (buffer, returned) = (block, block + 0x100);
    let Ok(Ok(section)) = sections::create(CreateOptions { size: 0x3000, page_protect: 4, attributes: 0x0800_0000, ..CreateOptions::default() }) else {
        assert(false, "queryvirtual: secao de pagefile");
        return;
    };
    let Ok(Ok(view)) = sections::map(&section, &MapRequest { protect: 4, owner_process: Some(current), regions: Some(crate::ntos::ps::user::state::RegionKind::Detached), ..MapRequest::default() }) else {
        assert(false, "queryvirtual: vista do processo corrente");
        return;
    };
    let pseudo = u64::MAX;
    // MEMORY_BASIC_INFORMATION da vista mapeada.
    let basic = query_virtual::query(pseudo, view.base + 0x1234, 0, buffer, 48, returned);
    let basic_info = unsafe { nt::MemoryBasicInformation::at(buffer) };
    assert(basic.is_ok_and(|status| status == 0) && basic_info.base_address.get() == view.base + 0x1000 && basic_info.allocation_base.get() == view.base && basic_info.allocation_protect.get() == 4 && basic_info.region_size.get() == 0x2000 && basic_info.state.get() == 0x1000 && basic_info.protect.get() == 4 && basic_info.type_.get() == 0x4_0000 && guest::read64(returned) == 48, "queryvirtual: MEMORY_BASIC_INFORMATION da vista mapeada");
    // Endereço livre: MEM_FREE com PAGE_NOACCESS.
    let free = view.base + view.size + 0x10_0000;
    assert(query_virtual::query(pseudo, free, 0, buffer, 48, 0).is_ok_and(|status| status == 0) && basic_info.state.get() == 0x1_0000 && basic_info.protect.get() == 1 && basic_info.allocation_base.get() == 0, "queryvirtual: regiao livre");
    // MEMORY_REGION_INFORMATION (classe 3) e o tipo da classe 7.
    let region = unsafe { nt::MemoryRegionInformation::at(buffer) };
    assert(query_virtual::query(pseudo, view.base, 3, buffer, 48, returned).is_ok_and(|status| status == 0) && region.allocation_base.get() == view.base && region.region_type.get() == 0x4_0000 && region.region_size.get() == 0x3000 && region.commit_size.get() == 0x3000 && region.node_preference.get() == 0xFFFF_FFFF && guest::read64(returned) == 48, "queryvirtual: MEMORY_REGION_INFORMATION com commit e NUMA");
    assert(query_virtual::query(pseudo, view.base, 7, buffer, 32, returned).is_ok_and(|status| status == 0) && region.region_type.get() == 8 && guest::read64(returned) == 32, "queryvirtual: classe 7 com o tipo de seção de pagefile");
    assert(query_virtual::query(pseudo, view.base, 2, buffer, 0x100, returned).is_ok_and(|status| status == 0xC000_0098) && query_virtual::query(pseudo, free, 3, buffer, 48, 0).is_ok_and(|status| status == 0xC000_0141), "queryvirtual: secao sem arquivo nao tem nome e regiao livre e endereco invalido");
    // MEMORY_WORKING_SET_EX_INFORMATION.
    let working_set = unsafe { nt::MemoryWorkingSetExInformation::array_at(buffer, 2) };
    working_set[0].virtual_address.set(view.base);
    working_set[1].virtual_address.set(free);
    assert(query_virtual::query(pseudo, 0, 4, buffer, 32, 0).is_ok_and(|status| status == 0) && working_set[0].virtual_attributes.get() == 0x8041 && working_set[1].virtual_attributes.get() == 0, "queryvirtual: working set com pagina valida, protecao e compartilhamento");
    // Recusas.
    assert(query_virtual::query(pseudo, view.base, 9, buffer, 48, 0).is_ok_and(|status| status == 0xC000_0003) && query_virtual::query(pseudo, view.base, 0, buffer, 40, 0).is_ok_and(|status| status == 0xC000_0004) && query_virtual::query(pseudo, 0x7FFF_FFFF_0000, 0, buffer, 48, 0).is_ok_and(|status| status == 0xC000_000D) && query_virtual::query(u64::MAX - 1, view.base, 0, buffer, 48, 0).is_ok_and(|status| status == 0xC000_0024) && query_virtual::query(pseudo, view.base, 4, buffer, 24, 0).is_ok_and(|status| status == 0xC000_0004), "queryvirtual: classe, tamanho, base, handle e vetor desalinhado recusados");
    // Nome da vista de arquivo (classe 2), com o tamanho necessário.
    let file: Arc<dyn sections::SectionFile> = MemoryFile::new(None, alloc::vec![0u8; 0x1000]);
    let Ok(Ok(mapped_file)) = sections::create(CreateOptions { size: 0x1000, page_protect: 2, attributes: 0x0800_0000, file: Some(file), ..CreateOptions::default() }) else {
        assert(false, "queryvirtual: secao de arquivo");
        return;
    };
    let Ok(Ok(file_view)) = sections::map(&mapped_file, &MapRequest { protect: 2, owner_process: Some(current), regions: Some(crate::ntos::ps::user::state::RegionKind::Detached), ..MapRequest::default() }) else {
        assert(false, "queryvirtual: vista de arquivo");
        return;
    };
    let expected = "\\Device\\HarddiskVolume1\\opennt-secao.bin";
    let needed = 16 + (expected.len() as u64 + 1) * 2;
    assert(query_virtual::query(pseudo, file_view.base, 2, buffer, 16, returned).is_ok_and(|status| status == 0xC000_0004) && guest::read64(returned) == needed, "queryvirtual: nome com buffer curto informa o tamanho");
    assert(query_virtual::query(pseudo, file_view.base, 2, buffer, 0x100, returned).is_ok_and(|status| status == 0) && guest_strings_of(unsafe { nt::UnicodeString::at(buffer) }) == expected && guest::read64(returned) == needed, "queryvirtual: nome nativo do arquivo da vista");
    assert(sections::unmap(&file_view, None).is_ok() && sections::unmap(&view, None).is_ok(), "queryvirtual: vistas removidas");
    guest::free_bytes(block);
}

fn guest_strings_of(unicode: &nt::UnicodeString) -> String {
    crate::ntos::rtl::guest_strings::read_unicode_string(unicode.address())
}

fn user_virtual_memory(assert: Assert) {
    use crate::ntos::mm::paging;
    use crate::ntos::ps::user::memory;
    use crate::ntos::ps::user::memory_query::{self, Context};
    let block = guest::alloc_bytes(0x100);
    let (base_pointer, size_pointer, rsp) = (block, block + 8, block + 0x40);
    let allocate = |base: u64, size: u64, kind: u32, protect: u32| {
        guest::write64(base_pointer, base);
        guest::write64(size_pointer, size);
        guest::write32(rsp + 0x28, kind);
        guest::write32(rsp + 0x30, protect);
        memory::nt_allocate_virtual_memory(u64::MAX, base_pointer, 0, size_pointer, rsp).unwrap_or(1)
    };
    // MEM_COMMIT|MEM_RESERVE com páginas reais de usuário.
    let committed = allocate(0, 0x2800, 0x3000, 4);
    let data = guest::read64(base_pointer);
    assert(committed == 0 && data >= crate::ntos::mm::memory_map::LOWEST_USER_ADDRESS && data % 0x10000 == 0 && guest::read64(size_pointer) == 0x3000 && paging::translate(data + 0x2000) != 0 && paging::access_flags(data) & (paging::PAGE_USER | paging::PAGE_RW) == paging::PAGE_USER | paging::PAGE_RW, "usermemory: NtAllocateVirtualMemory confirma paginas de usuario");
    // Reserva e commit da subfaixa.
    let reserved_status = allocate(0, 0x4000, 0x2000, 4);
    let reserved = guest::read64(base_pointer);
    assert(reserved_status == 0 && paging::translate(reserved) == 0 && allocate(reserved + 0x1000, 0x1000, 0x1000, 4) == 0 && paging::translate(reserved + 0x1000) != 0 && paging::translate(reserved) == 0, "usermemory: commit sobre a reserva confirma so a subfaixa");
    assert(allocate(reserved, 0x1000, 0x2000, 4) == 0xC000_0018 && allocate(0, 0x1000, 0x3000, 3) == 0xC000_0045 && allocate(0, 0x1000, 0x3000, 0x104) == 0xC000_00BB && allocate(0, 0, 0x3000, 4) == 0xC000_000D, "usermemory: conflito, protecao invalida, modificador e tamanho zero");
    let context = Context::current();
    assert(memory_query::describe(reserved, &context).state == 0x2000 && memory_query::describe(reserved + 0x1000, &context).state == 0x1000 && memory_query::describe(data, &context).size == 0x3000, "usermemory: regioes privadas descritas com reserva e commit");
    // NtProtectVirtualMemory com os parâmetros na memória de usuário.
    let parameters = data;
    let protect_rsp = block + 0x80;
    guest::write64(protect_rsp + 0x28, parameters + 16);
    let protect = |base: u64, size: u64, value: u64| {
        guest::write64(parameters, base);
        guest::write64(parameters + 8, size);
        memory::nt_protect_virtual_memory(u64::MAX, parameters, parameters + 8, value, protect_rsp).unwrap_or(1)
    };
    assert(protect(reserved + 0x1000, 0x1000, 2) == 0 && guest::read32(parameters + 16) == 4 && paging::access_flags(reserved + 0x1000) & paging::PAGE_RW == 0 && memory_query::describe(reserved + 0x1000, &Context::current()).protect == 2, "usermemory: NtProtectVirtualMemory devolve a protecao anterior e retira RW");
    assert(protect(reserved, 0x1000, 2) == 0xC000_002D && guest::read32(parameters + 16) == 1 && protect(0x8000, 0x1000, 2) == 0xC000_0018 && protect(reserved + 0x1000, 0x1000, 3) == 0xC000_0045, "usermemory: pagina nao confirmada, endereco sem regiao e protecao invalida");
    assert(memory::nt_protect_virtual_memory(u64::MAX, block, block + 8, 2, protect_rsp).is_ok_and(|status| status == 0xC000_0005), "usermemory: parametros fora da memoria de usuario");
    // NtRead/WriteVirtualMemory pelas PTEs de usuário.
    let transfer_rsp = data + 0x800;
    guest::write64(transfer_rsp + 0x28, data + 0x900);
    guest::write_bytes(data + 0x100, b"OpenNT");
    assert(memory::nt_read_virtual_memory(u64::MAX, data + 0x100, data + 0x200, 6, transfer_rsp).is_ok_and(|status| status == 0) && guest::read_bytes(data + 0x200, 6) == b"OpenNT" && guest::read64(data + 0x900) == 6, "usermemory: NtReadVirtualMemory copia e informa o total");
    assert(memory::nt_read_virtual_memory(u64::MAX, reserved + 0x1FFC, data + 0x300, 8, transfer_rsp).is_ok_and(|status| status == 0x8000_000D) && guest::read64(data + 0x900) == 4, "usermemory: copia parcial ate a pagina nao confirmada");
    assert(memory::nt_write_virtual_memory(u64::MAX, reserved + 0x1000, data + 0x200, 4, transfer_rsp).is_ok_and(|status| status == 0x8000_000D) && guest::read64(data + 0x900) == 0, "usermemory: escrita recusada pela PTE somente leitura");
    // NtFreeVirtualMemory: decommit e release.
    let free = |base: u64, size: u64, kind: u64| {
        guest::write64(base_pointer, base);
        guest::write64(size_pointer, size);
        memory::nt_free_virtual_memory(u64::MAX, base_pointer, size_pointer, kind, 0).unwrap_or(1)
    };
    assert(free(reserved + 0x1000, 0x1000, 0x4000) == 0 && paging::translate(reserved + 0x1000) == 0 && memory::find_region(reserved).is_some(), "usermemory: MEM_DECOMMIT desmapeia e conserva a reserva");
    assert(free(reserved, 0x1000, 0x8000) == 0xC000_000D && free(reserved, 0, 0x8000) == 0 && memory::find_region(reserved).is_none() && free(0x8000, 0, 0x8000) == 0xC000_000D, "usermemory: MEM_RELEASE exige base e tamanho zero e libera a regiao");
    // Estruturas do processo e regiões compartilhadas.
    let structures = memory::map_user_region(0x1800);
    assert(structures.as_ref().is_ok_and(|&va| va % 0x1000 == 0 && va > data && va + 0x2000 <= memory::USER_ALLOCATION_TOP && paging::translate(va + 0x1000) != 0 && memory::find_region(va).is_some_and(|region| region.base() == va && region.size() == 0x2000)), "usermemory: regiao de estruturas de cima para baixo, pelo alocador");
    let shared = memory::map_shared_user_region(0x1000);
    assert(shared.as_ref().is_ok_and(|&va| paging::translate(va) != 0 && state::with(|state| state.shared_user_regions.iter().any(|region| region.base() == va))), "usermemory: regiao compartilhada mapeada");
    if let Ok(va) = structures {
        if let Some(region) = memory::find_region(va) {
            memory::release_private_region(&region);
        }
        assert(memory::find_region(va).is_none() && paging::translate(va) == 0, "usermemory: regiao de estruturas liberada");
    }
    assert(free(data, 0, 0x8000) == 0 && memory::find_region(data).is_none(), "usermemory: regiao confirmada liberada");
    assert(state::handler("NtAllocateVirtualMemory").is_some() && state::handler("NtQueryVirtualMemory").is_some(), "usermemory: handlers registrados");
    guest::free_bytes(block);
}

fn volume_file_lookup(assert: Assert) {
    use crate::drivers::fs::volume_files::{self, nt_path_to_volume_path};
    assert(nt_path_to_volume_path("\\??\\C:\\Windows\\System32\\ntdll.dll").as_deref() == Some("/ntdll.dll") && nt_path_to_volume_path("C:\\Windows\\Globalization\\Sorting\\SortDefault.nls").as_deref() == Some("/SortDefault.nls") && nt_path_to_volume_path("D:\\dir\\sub\\file.txt").as_deref() == Some("/dir/sub/file.txt") && nt_path_to_volume_path("/ntfs/x.bin").as_deref() == Some("/x.bin"), "volumefiles: prefixos NT/DOS e aliases de instalacao");
    assert(nt_path_to_volume_path("E:\\x").is_none() && nt_path_to_volume_path("C:\\a\\..\\b").is_none() && nt_path_to_volume_path("C:\\a?b").is_none() && nt_path_to_volume_path("C:\\Windows").as_deref() == Some("/"), "volumefiles: unidade, travessia e caracteres proibidos recusados");
    let Some(file) = volume_files::lookup_volume_file("C:\\Windows\\System32\\HELLO.TXT") else {
        assert(false, "volumefiles: HELLO.TXT do volume de teste");
        return;
    };
    let expected: &[u8] = b"Ola do NTFS no OpenNT!\r\n";
    assert(file.size() == expected.len() as u64 && !file.directory() && file.read_at(0, 64).is_ok_and(|bytes| bytes == expected) && file.read_at(4, 2).is_ok_and(|bytes| bytes == b"do") && file.read_at(100, 4).is_ok_and(|bytes| bytes.is_empty()) && file.read_all().is_some_and(|bytes| bytes.as_slice() == expected), "volumefiles: leitura limitada ao EOF, pelo cache e completa");
    assert(volume_files::lookup_volume_file("\\??\\D:\\HELLO.TXT").is_some_and(|again| Arc::ptr_eq(&again, &file)) && file.nt_path().ends_with("\\HELLO.TXT") && file.nt_path().starts_with('\\') && volume_files::lookup_volume_file("C:\\NaoExiste.dll").is_none(), "volumefiles: mesma identidade no cache, nome nativo e ausencia");
    let source: Arc<dyn crate::ntos::ps::user::sections::SectionFile> = file.clone();
    assert(crate::ntos::ps::user::sections::create_image(source, None, 2, false).is_ok_and(|created| created.is_err_and(|status| status == 0xC000_007B)), "volumefiles: arquivo sem PE recusado como imagem");
    // KnownDlls: provisiona do volume na primeira busca.
    let _ = crate::ntos::ob::object_manager::create_directory("\\KnownDlls");
    let block = guest::alloc_bytes(0x200);
    let output = block + 0x1F0;
    let present = object_attributes_named(block, "\\KnownDlls\\HELLO.TXT", 0x40);
    assert(crate::ntos::mm::section::open::open(output, 4, present, 0).is_ok_and(|status| status == 0xC000_007B) && crate::ntos::ob::object_manager::lookup("\\KnownDlls\\HELLO.TXT").is_none(), "volumefiles: KnownDlls tenta provisionar a imagem do volume");
    let absent = object_attributes_named(block, "\\KnownDlls\\NAOEXISTE.DLL", 0x40);
    assert(crate::ntos::mm::section::open::open(output, 4, absent, 0).is_ok_and(|status| status == 0xC000_0034), "volumefiles: KnownDlls sem arquivo no volume");
    guest::free_bytes(block);
}

fn user_registry(assert: Assert) {
    use crate::ntos::cm::key::services as key_services;
    use crate::ntos::cm::registry;
    use crate::ntos::ps::user::{memory, registry as user_registry};
    assert(user_registry::seed_registry_for_user_mode().is_ok(), "userregistry: seed dos valores lidos pelo loader");
    let acp = registry::read_value_by_path("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\CodePage", "ACP");
    let known = registry::read_value_by_path("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\KnownDlls", "KnownDlls");
    assert(acp.is_some_and(|value| value.value_type == 1 && value.data == [b'1', 0, b'2', 0, b'5', 0, b'2', 0, 0, 0]) && known.is_some_and(|value| value.value_type == 7 && value.data.ends_with(&[0, 0, 0, 0])), "userregistry: ACP REG_SZ e KnownDlls REG_MULTI_SZ");
    // OBJECT_ATTRIBUTES e UNICODE_STRING em memória de usuário.
    let Ok(block) = memory::map_user_region(0x1000) else {
        assert(false, "userregistry: memoria de usuario para os parametros");
        return;
    };
    let write_attributes = |root: u64, name: &str| {
        let text = block + 0x100;
        let length = state::write_user_wide(text, name);
        state::write_unicode_string(block + 0x40, text, name);
        let _ = length;
        set_object_attributes(unsafe { nt::ObjectAttributes::at(block) }, nt::ObjectAttributes::SIZE as u32, root, block + 0x40, 0x40);
        block
    };
    let attributes = write_attributes(0, "\\Registry\\Machine\\System");
    assert(user_registry::parse_user_object_attributes(attributes).is_some_and(|parsed| parsed.path == "\\Registry\\Machine\\System" && parsed.root_directory == 0), "userregistry: caminho absoluto dos atributos");
    unsafe { nt::ObjectAttributes::at(block) }.length.set(0x20);
    assert(user_registry::parse_user_object_attributes(block).is_none(), "userregistry: Length curto recusado");
    // NtOpenKey de usuário: handle `key` do processo.
    let output = block + 0x300;
    let attributes = write_attributes(0, "\\Registry\\Machine\\System");
    let opened = state::handler("NtOpenKey").map(|handler| handler(output, 0x2_0019, attributes, 0, 0));
    let handle = guest::read64(output);
    let entry = state::get_user_handle(handle);
    assert(opened.is_some_and(|status| status.is_ok_and(|status| status == 0)) && entry.as_ref().is_some_and(|entry| entry.kind() == "key" && entry.access() & 0x2_0019 == 0x2_0019), "userregistry: NtOpenKey devolve handle key do processo");
    let relative = write_attributes(handle, "CurrentControlSet");
    assert(user_registry::parse_user_object_attributes(relative).is_some_and(|parsed| parsed.path.to_lowercase().ends_with("\\system\\currentcontrolset") && parsed.root_directory == handle), "userregistry: raiz de chave compoe o caminho");
    let khandle = entry.as_ref().and_then(|entry| entry.downcast::<user_registry::UserKey>().map(|key| key.khandle)).unwrap_or(0);
    drop(entry);
    assert(khandle != 0 && registry::get_path(khandle).is_some() && state::close_user_handle(handle, true, false).is_ok_and(|status| status == 0) && registry::get_path(khandle).is_none() && state::get_user_handle(handle).is_none(), "userregistry: fechamento libera o handle interno da hive");
    let missing = write_attributes(0, "\\Registry\\Machine\\NaoExisteOpenNt");
    assert(key_services::open(output, 0x2_0019, missing, true, 0).is_ok_and(|status| status == 0xC000_0034), "userregistry: chave ausente");
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn user_file_io(assert: Assert) {
    use crate::drivers::fs::volume_files;
    use crate::ntos::ps::user::file_io::{self, OpenRequest};
    use crate::ntos::ps::user::memory;
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "userfiles: memoria de usuario");
        return;
    };
    let (out, iosb, buffer, rsp) = (block, block + 0x10, block + 0x100, block + 0x800);
    let io_status = unsafe { nt::IoStatusBlock::at(iosb) };
    let open = |name: &str, disposition: u32, access: u32, share: u32, options: u32| {
        guest::write64(out, 0);
        file_io::open(out, name, iosb, disposition, &OpenRequest { access, share, options, ..OpenRequest::default() }).unwrap_or(1)
    };
    // Abertura do arquivo existente com E/S síncrona.
    let opened = open("\\??\\D:\\HELLO.TXT", 1, 0x8010_0000, 1, 0x20);
    let handle = guest::read64(out);
    assert(opened == 0 && io_status.information.get() == 1 && state::get_user_handle(handle).is_some_and(|entry| entry.kind() == "file" && entry.access() == 0x12_0089), "userfiles: abertura com acesso generico mapeado");
    // NtReadFile pela posição síncrona.
    let read = |length: u64| {
        guest::write64(rsp + 0x28, iosb);
        guest::write64(rsp + 0x30, buffer);
        guest::write32(rsp + 0x38, length as u32);
        guest::write64(rsp + 0x40, 0);
        state::handler("NtReadFile").map(|handler| handler(handle, 0, 0, 0, rsp).unwrap_or(1)).unwrap_or(1)
    };
    let expected: &[u8] = b"Ola do NTFS no OpenNT!\r\n";
    assert(read(64) == 0 && io_status.information.get() == expected.len() as u64 && guest::read_bytes(buffer, expected.len()) == expected && read(8) == 0xC000_0011, "userfiles: NtReadFile le ate o fim e devolve END_OF_FILE");
    // NtQueryInformationFile: padrão, posição e nome.
    let query = |class: u32, length: u64| {
        guest::write32(rsp + 0x28, class);
        state::handler("NtQueryInformationFile").map(|handler| handler(handle, iosb, buffer, length, rsp).unwrap_or(1)).unwrap_or(1)
    };
    assert(query(5, 24) == 0 && { let standard = unsafe { nt::FileStandardInformation::at(buffer) }; standard.end_of_file.quad_part.get() == expected.len() as i64 && standard.directory.get() == 0 }, "userfiles: FILE_STANDARD_INFORMATION com o tamanho");
    assert(query(14, 8) == 0 && unsafe { nt::FilePositionInformation::at(buffer) }.current_byte_offset.quad_part.get() == expected.len() as i64, "userfiles: FILE_POSITION_INFORMATION depois da leitura");
    assert(query(9, 64) == 0 && { let name_info = unsafe { nt::FileNameInformation::at(buffer) }; name_info.file_name_length.get() == 20 && name_info.file_name[0].get() == b'\\' as u16 } && query(99, 64) == 0xC000_0003 && query(5, 8) == 0xC000_0004, "userfiles: nome, classe e tamanho invalidos");
    assert(state::close_user_handle(handle, true, false).is_ok_and(|status| status == 0), "userfiles: handle fechado");
    // Criação, escrita, colisão e DELETE_ON_CLOSE.
    let name = "\\??\\D:\\OPENNTUSR.TXT";
    let created = open(name, 2, 0x4010_0000, 0, 0x20);
    let writer = guest::read64(out);
    assert(created == 0 && io_status.information.get() == 2, "userfiles: FILE_CREATE cria o arquivo no volume");
    guest::write_bytes(buffer, b"OpenNT-usr");
    guest::write64(rsp + 0x28, iosb);
    guest::write64(rsp + 0x30, buffer);
    guest::write32(rsp + 0x38, 10);
    guest::write64(rsp + 0x40, 0);
    let written = state::handler("NtWriteFile").map(|handler| handler(writer, 0, 0, 0, rsp).unwrap_or(1)).unwrap_or(1);
    assert(written == 0 && io_status.information.get() == 10 && volume_files::lookup_volume_file(name).is_some_and(|file| file.size() == 10 && file.read_at(0, 10).is_ok_and(|bytes| bytes == b"OpenNT-usr")), "userfiles: NtWriteFile grava no volume");
    assert(open(name, 2, 0x4010_0000, 0, 0x20) == 0xC000_0035, "userfiles: FILE_CREATE de nome existente");
    assert(state::close_user_handle(writer, true, false).is_ok_and(|status| status == 0), "userfiles: escritor fechado");
    let deleting = open(name, 1, 0x8011_0000, 7, 0x1020);
    let deleter = guest::read64(out);
    assert(deleting == 0 && state::close_user_handle(deleter, true, false).is_ok_and(|status| status == 0) && volume_files::lookup_volume_file(name).is_none(), "userfiles: DELETE_ON_CLOSE remove o arquivo no ultimo fechamento");
    // Recusas.
    let absent = open("\\??\\D:\\NaoExisteOpenNt.txt", 1, 0x8010_0000, 1, 0x20);
    assert(absent == 0xC000_0034 && io_status.status.get() as u32 == 0xC000_0034, "userfiles: arquivo ausente com o IOSB");
    let missing_parent = open("\\??\\D:\\SemPasta\\x.txt", 1, 0x8010_0000, 1, 0x20);
    if missing_parent != 0xC000_003A {
        debug_print!("[userfiles] pasta ausente devolveu 0x{:x}", missing_parent);
    }
    assert(missing_parent == 0xC000_003A, "userfiles: pasta intermediaria ausente");
    assert(open("\\??\\D:\\HELLO.TXT", 6, 0x8010_0000, 1, 0x20) == 0xC000_000D && open("\\??\\D:\\HELLO.TXT", 1, 1, 1, 0x20) == 0xC000_000D, "userfiles: disposicao invalida e E/S sincrona sem SYNCHRONIZE");
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn user_file_io_more(assert: Assert) {
    use crate::drivers::fs::volume_files;
    use crate::ntos::ps::user::file_io::{self, OpenRequest};
    use crate::ntos::ps::user::memory;
    assert(file_io::matches("*.*", "HELLO.TXT") && file_io::matches("*.txt", "hello.TXT") && !file_io::matches("*.DLL", "HELLO.TXT") && file_io::matches("H?LLO.*", "HELLO.TXT") && file_io::matches("<.TXT", "A.B.TXT") && !file_io::matches("HEL", "HELLO"), "userfiles: curingas DOS sem caixa");
    let Ok(block) = memory::map_user_region(0x3000) else {
        assert(false, "userfiles: memoria de usuario (parte 2)");
        return;
    };
    let (out, iosb, buffer, rsp, pattern) = (block, block + 0x10, block + 0x200, block + 0x1800, block + 0x100);
    let open = |name: &str, disposition: u32, access: u32, share: u32, options: u32| {
        guest::write64(out, 0);
        let status = file_io::open(out, name, iosb, disposition, &OpenRequest { access, share, options, ..OpenRequest::default() }).unwrap_or(1);
        (status, guest::read64(out))
    };
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map(|handler| handler(a1, a2, a3, a4, rsp).unwrap_or(1)).unwrap_or(1);
    // Listagem da raiz com padrão.
    let (status, directory) = open("\\??\\D:\\", 1, 0x10_0001, 7, 0x21);
    assert(status == 0, "userfiles: diretorio raiz aberto");
    let text = pattern + 0x20;
    let length = state::write_user_wide(text, "HELLO.*");
    state::write_unicode_string(pattern, text, "HELLO.*");
    let _ = length;
    let list = |name_pointer: u64| {
        guest::write64(rsp + 0x28, iosb);
        guest::write64(rsp + 0x30, buffer);
        guest::write32(rsp + 0x38, 0x400);
        guest::write32(rsp + 0x40, 1);
        guest::write32(rsp + 0x48, 0);
        guest::write64(rsp + 0x50, name_pointer);
        guest::write32(rsp + 0x58, 0);
        call("NtQueryDirectoryFile", directory, 0, 0, 0)
    };
    assert(list(pattern) == 0 && { let entry = unsafe { nt::FileDirectoryInformation::at(buffer) }; entry.file_name_length.get() == 18 && entry.end_of_file.quad_part.get() == 24 && entry.file_name[0].get() == b'H' as u16 && entry.next_entry_offset.get() == 0 }, "userfiles: FileDirectoryInformation com o padrao");
    assert(list(0) == 0x8000_0006, "userfiles: NO_MORE_FILES na continuacao");
    // Volume da descrição.
    guest::write32(rsp + 0x28, 1);
    assert(call("NtQueryVolumeInformationFile", directory, iosb, buffer, 0x100) == 0 && unsafe { nt::IoStatusBlock::at(iosb) }.information.get() >= 18, "userfiles: FileFsVolumeInformation pelo volume do arquivo");
    let _ = state::close_user_handle(directory, true, false);
    // Fim de arquivo, posição, renomeação e disposição de exclusão.
    let name = "\\??\\D:\\OPENNTREN.TXT";
    let (status, handle) = open(name, 2, 0xC011_0000, 7, 0x20);
    assert(status == 0, "userfiles: arquivo para renomear criado");
    guest::write_bytes(buffer, b"0123456789");
    guest::write64(rsp + 0x28, iosb);
    guest::write64(rsp + 0x30, buffer);
    guest::write32(rsp + 0x38, 10);
    guest::write64(rsp + 0x40, 0);
    assert(call("NtWriteFile", handle, 0, 0, 0) == 0, "userfiles: dados escritos");
    let set = |class: u32, data: &[u8]| {
        guest::write_bytes(buffer, data);
        guest::write32(rsp + 0x28, class);
        call("NtSetInformationFile", handle, iosb, buffer, data.len() as u64)
    };
    assert(set(20, &4u64.to_le_bytes()) == 0 && volume_files::lookup_volume_file(name).is_some_and(|file| file.size() == 4), "userfiles: FileEndOfFileInformation trunca");
    guest::write32(rsp + 0x28, 14);
    assert(set(14, &2u64.to_le_bytes()) == 0 && { guest::write32(rsp + 0x28, 14); call("NtQueryInformationFile", handle, iosb, buffer, 8) == 0 } && unsafe { nt::FilePositionInformation::at(buffer) }.current_byte_offset.quad_part.get() == 2, "userfiles: FilePositionInformation definida e consultada");
    let mut rename = alloc::vec![0u8; 20];
    let target: Vec<u16> = "OPENNTREN2.TXT".encode_utf16().collect();
    rename[16..20].copy_from_slice(&(target.len() as u32 * 2).to_le_bytes());
    for unit in &target {
        rename.extend_from_slice(&unit.to_le_bytes());
    }
    assert(set(10, &rename) == 0 && volume_files::lookup_volume_file(name).is_none() && volume_files::lookup_volume_file("\\??\\D:\\OPENNTREN2.TXT").is_some_and(|file| file.size() == 4) && { guest::write32(rsp + 0x28, 9); call("NtQueryInformationFile", handle, iosb, buffer, 64) == 0 } && unsafe { nt::FileNameInformation::at(buffer) }.file_name_length.get() == 30, "userfiles: renomeacao relativa atualiza o volume e o nome");
    assert(call("NtFlushBuffersFile", handle, iosb, 0, 0) == 0, "userfiles: NtFlushBuffersFile");
    assert(set(13, &[1]) == 0 && state::close_user_handle(handle, true, false).is_ok_and(|status| status == 0) && volume_files::lookup_volume_file("\\??\\D:\\OPENNTREN2.TXT").is_none(), "userfiles: FileDispositionInformation remove no fechamento");
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

/// Fim do leitor concorrente da estressa de disco.
static DISK_STRESS_STOP: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// FNV-1a de 64 bits: a assinatura dos setores relidos.
fn fnv64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xCBF2_9CE4_8422_2325u64, |hash, &byte| (hash ^ byte as u64).wrapping_mul(0x100_0000_01B3))
}

/// Job de AP: relê `count` setores a partir de `lba` do drive `drive` até o
/// sinal de parada e confere a assinatura. Devolve falhas << 32 | leituras.
extern "win64" fn disk_stress_reader(lba: u64, count: u64, drive: u64, expected: u64) -> u64 {
    use crate::drivers::storage::ata_pio;
    let (mut reads, mut failures) = (0u64, 0u64);
    while !DISK_STRESS_STOP.load(Ordering::Acquire) {
        if !ata_pio::read_sectors(lba, count as u32, drive as u8).is_ok_and(|bytes| fnv64(&bytes) == expected) {
            failures += 1;
        }
        reads += 1;
    }
    failures << 32 | reads.min(0xFFFF_FFFF)
}

/// Arquivo que o BSP regrava inteiro a cada rodada (um só byte repetido)
/// enquanto um AP o relê.
const DISK_STRESS_SHARED_FILE: &str = "/STRESSAP.DAT";
const DISK_STRESS_SHARED_SIZE: usize = 24_000;

/// Job de AP: pelo volume NTFS, lê `HELLO.TXT` (busca na raiz, registro e
/// dados) enquanto o BSP cria e remove arquivos na mesma raiz, e relê o
/// arquivo que o BSP regrava, que precisa aparecer inteiro numa só versão.
/// Devolve falhas << 32 | leituras.
extern "win64" fn disk_stress_volume_reader(volume: u64, expected: u64, _: u64, _: u64) -> u64 {
    // SAFETY: o `Ntfs` da montagem do boot; o BSP segura o Arc até o fim do job.
    let volume = unsafe { &*(volume as *const crate::drivers::fs::ntfs::Ntfs) };
    let (mut reads, mut failures) = (0u64, 0u64);
    while !DISK_STRESS_STOP.load(Ordering::Acquire) {
        let found = volume.stat("/HELLO.TXT").is_ok_and(|stat| stat.is_some_and(|stat| stat.reference == 16 && stat.size == 24));
        let read = volume.read_bytes("/HELLO.TXT").is_ok_and(|bytes| bytes.is_some_and(|bytes| fnv64(&bytes) == expected));
        let whole = volume.read_bytes(DISK_STRESS_SHARED_FILE).is_ok_and(|bytes| bytes.is_some_and(|bytes| bytes.len() == DISK_STRESS_SHARED_SIZE && bytes.iter().all(|&byte| byte == bytes[0])));
        if !found || !read || !whole {
            failures += 1;
        }
        reads += 1;
    }
    failures << 32 | reads.min(0xFFFF_FFFF)
}

/// Estressa o caminho de escrita do disco: a cada rodada um arquivo do NTFS
/// é criado (FILE_OVERWRITE_IF), escrito, truncado (FileEndOfFileInformation),
/// estendido com zeros, relido, ganha EAs e é excluído no fechamento, pelos
/// serviços Nt* do modo usuário; um segundo arquivo passa pelas mesmas
/// mutações direto no volume. Enquanto isso, um AP relê setores fixos do
/// disco mestre, outro o setor de boot do volume NTFS (o mesmo canal IDE) e
/// um terceiro lê um arquivo da mesma raiz pelo volume, conferindo cada
/// leitura.
pub fn disk_write_stress(assert: Assert, rounds: u32, readers: usize) {
    use crate::drivers::fs::extended_attributes::{self as ea, Entry, QueryOptions, QueryState};
    use crate::drivers::fs::{ntfs, volume_files};
    use crate::drivers::storage::ata_pio;
    use crate::ntos::ke::smp;
    use crate::ntos::ps::user::file_io::{self, OpenRequest};
    use crate::ntos::ps::user::memory;
    let Some(volume) = ntfs::mounted() else {
        assert(false, "diskstress: volume NTFS montado");
        return;
    };
    let Ok(block) = memory::map_user_region(0x2_2000) else {
        assert(false, "diskstress: memoria de usuario");
        return;
    };
    let (out, iosb, offset, rsp, buffer) = (block, block + 0x10, block + 0x20, block + 0x1000, block + 0x2000);
    let io_status = unsafe { nt::IoStatusBlock::at(iosb) };
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map(|handler| handler(a1, a2, a3, a4, rsp).unwrap_or(1)).unwrap_or(1);
    // Leitores concorrentes nos APs: (lba, setores, drive) com a assinatura
    // lida antes de começar.
    let regions = [(1000u64, 64u64, 0u64), (0, 4, 1)];
    let mut slots = Vec::new();
    DISK_STRESS_STOP.store(false, Ordering::Release);
    for (index, &(lba, count, drive)) in regions.iter().take(readers).enumerate() {
        let Some(slot) = smp::ap_slot(index) else { break };
        let Ok(reference) = ata_pio::read_sectors(lba, count as u32, drive as u8) else {
            assert(false, "diskstress: referencia dos leitores");
            return;
        };
        slots.push(slot);
        let routine = disk_stress_reader as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64;
        assert(smp::start_job(slot, routine, [lba, count, drive, fnv64(&reference)]).is_ok_and(|started| started), "diskstress: leitor concorrente no AP");
    }
    let shared_file = volume.create(DISK_STRESS_SHARED_FILE, false, 0x20, 0).and_then(|_| volume.write(DISK_STRESS_SHARED_FILE, 0, &[0; DISK_STRESS_SHARED_SIZE]));
    assert(shared_file.is_ok(), "diskstress: arquivo regravado criado");
    if readers > regions.len() {
        if let Some(slot) = smp::ap_slot(regions.len()) {
            let expected = volume.read_bytes("/HELLO.TXT").ok().flatten().map(|bytes| fnv64(&bytes)).unwrap_or(0);
            slots.push(slot);
            let routine = disk_stress_volume_reader as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64;
            assert(smp::start_job(slot, routine, [Arc::as_ptr(&volume) as u64, expected, 0, 0]).is_ok_and(|started| started), "diskstress: leitor do volume no AP");
        }
    }
    let lengths = [10u64, 4096, 24_000, 65_000];
    for round in 0..rounds {
        let name = alloc::format!("\\??\\D:\\STRESS-{}.DAT", round % 3);
        let path = alloc::format!("/STRESS-{}.DAT", round % 3);
        let length = lengths[round as usize % lengths.len()];
        let pattern: Vec<u8> = (0..length).map(|index| (index * 7 + round as u64) as u8).collect();
        guest::write64(out, 0);
        let opened = file_io::open(out, &name, iosb, 5, &OpenRequest { access: 0xC011_0000, share: 7, options: 0x20, ..OpenRequest::default() }).unwrap_or(1);
        let handle = guest::read64(out);
        assert(opened == 0, "diskstress: FILE_OVERWRITE_IF cria o arquivo");
        guest::write_bytes(buffer, &pattern);
        guest::write64(offset, 0);
        let transfer = |service: &str, length: u64| {
            guest::write64(rsp + 0x28, iosb);
            guest::write64(rsp + 0x30, buffer);
            guest::write32(rsp + 0x38, length as u32);
            guest::write64(rsp + 0x40, offset);
            call(service, handle, 0, 0, 0)
        };
        assert(transfer("NtWriteFile", length) == 0 && io_status.information.get() == length, "diskstress: NtWriteFile");
        let set = |class: u32, data: &[u8]| {
            guest::write_bytes(block + 0x40, data);
            guest::write32(rsp + 0x28, class);
            call("NtSetInformationFile", handle, iosb, block + 0x40, data.len() as u64)
        };
        let truncated = length / 3 + 1;
        assert(set(20, &truncated.to_le_bytes()) == 0 && volume_files::lookup_volume_file(&name).is_some_and(|file| file.size() == truncated), "diskstress: FileEndOfFileInformation trunca");
        let extended = truncated + 100;
        assert(set(20, &extended.to_le_bytes()) == 0 && volume_files::lookup_volume_file(&name).is_some_and(|file| file.size() == extended), "diskstress: FileEndOfFileInformation estende");
        guest::write_bytes(buffer, &alloc::vec![0xEEu8; extended as usize]);
        let read = transfer("NtReadFile", length + 512);
        let back = guest::read_bytes(buffer, extended as usize);
        assert(read == 0 && io_status.information.get() == extended && back[..truncated as usize] == pattern[..truncated as usize] && back[truncated as usize..].iter().all(|&byte| byte == 0), "diskstress: releitura dos dados e da extensao zerada");
        let value = alloc::vec![round as u8; 1 + round as usize % 300];
        let encoded = ea::encode(&[Entry { name: b"OPENNT.STRESS".to_vec(), flags: 0, value: value.clone() }], false);
        let listed = volume.set_ea(&path, &encoded, false).and_then(|()| volume.query_ea(&path, 1024, &QueryOptions { restart: true, ..Default::default() }, &mut QueryState::default()));
        assert(listed.is_ok_and(|result| result.status == 0 && ea::parse(&result.bytes[..result.information as usize], false, false).is_ok_and(|entries| entries.len() == 1 && entries[0].value == value)), "diskstress: EA gravado e relido");
        assert(set(13, &[1]) == 0 && state::close_user_handle(handle, true, false).is_ok_and(|status| status == 0) && volume_files::lookup_volume_file(&name).is_none() && matches!(volume.exists(&path), Ok(false)), "diskstress: exclusao no fechamento");
        // O mesmo ciclo direto no volume.
        let direct = "/STRESSV.DAT";
        let created = volume.create(direct, false, 0x20, 0);
        let written = volume.write(direct, 0, &pattern);
        let shrunk = volume.resize(direct, truncated);
        let bytes = volume.read_bytes(direct);
        let removed = volume.remove(direct);
        assert(created.is_ok() && written.is_ok_and(|count| count == length) && shrunk.is_ok_and(|size| size == truncated) && bytes.is_ok_and(|bytes| bytes.is_some_and(|bytes| bytes[..] == pattern[..truncated as usize])) && removed.is_ok() && matches!(volume.exists(direct), Ok(false)), "diskstress: ciclo direto no volume");
        let rewritten = volume.write(DISK_STRESS_SHARED_FILE, 0, &[(round as u8).wrapping_add(1); DISK_STRESS_SHARED_SIZE]);
        assert(rewritten.is_ok_and(|count| count == DISK_STRESS_SHARED_SIZE as u64), "diskstress: arquivo compartilhado regravado");
    }
    DISK_STRESS_STOP.store(true, Ordering::Release);
    for slot in slots {
        let result = smp::wait_job(slot, 60_000).unwrap_or(u64::MAX);
        debug_print!("[diskstress] AP slot {}: {} leituras, {} falhas", slot, result & 0xFFFF_FFFF, result >> 32);
        assert(result >> 32 == 0 && result & 0xFFFF_FFFF != 0, "diskstress: leituras concorrentes conferidas");
    }
    assert(volume.remove(DISK_STRESS_SHARED_FILE).is_ok(), "diskstress: arquivo regravado removido");
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn user_file_syscalls(assert: Assert) {
    use crate::drivers::fs::volume_files;
    use crate::ntos::ps::user::memory;
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "usersyscalls: memoria de usuario");
        return;
    };
    let (handle_pointer, iosb, attributes, rsp) = (block, block + 0x10, block + 0x100, block + 0x1000);
    let set_name = |name: &str| {
        let text = attributes + 0x80;
        state::write_user_wide(text, name);
        state::write_unicode_string(attributes + 0x40, text, name);
        set_object_attributes(unsafe { nt::ObjectAttributes::at(attributes) }, nt::ObjectAttributes::SIZE as u32, 0, attributes + 0x40, 0x40);
        guest::write64(handle_pointer, 0);
    };
    let io_status = unsafe { nt::IoStatusBlock::at(iosb) };
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map(|handler| handler(a1, a2, a3, a4, rsp).unwrap_or(1)).unwrap_or(1);
    // NtOpenFile do volume.
    set_name("\\??\\D:\\HELLO.TXT");
    guest::write32(rsp + 0x28, 1);
    guest::write32(rsp + 0x30, 0x20);
    let opened = call("NtOpenFile", handle_pointer, 0x8010_0000, attributes, iosb);
    let handle = guest::read64(handle_pointer);
    assert(opened == 0 && state::get_user_handle(handle).is_some_and(|entry| entry.kind() == "file"), "usersyscalls: NtOpenFile abre o arquivo do volume");
    assert(call("NtClose", handle, 0, 0, 0) == 0 && state::get_user_handle(handle).is_none() && call("NtClose", handle, 0, 0, 0) == 0xC000_0008, "usersyscalls: NtClose fecha e recusa repeticao");
    // NtCreateFile com FILE_CREATE e limpeza por DELETE_ON_CLOSE.
    set_name("\\??\\D:\\OPENNTNT.TXT");
    for (offset, value) in [(0x28u64, 0u64), (0x30, 0x80), (0x38, 0), (0x40, 2), (0x48, 0x20), (0x50, 0), (0x58, 0)] {
        guest::write64(rsp + offset, value);
    }
    let created = call("NtCreateFile", handle_pointer, 0x4010_0000, attributes, iosb);
    let file = guest::read64(handle_pointer);
    assert(created == 0 && io_status.information.get() == 2 && volume_files::lookup_volume_file("\\??\\D:\\OPENNTNT.TXT").is_some(), "usersyscalls: NtCreateFile cria pelo FILE_CREATE");
    let _ = call("NtClose", file, 0, 0, 0);
    guest::write64(rsp + 0x40, 1);
    guest::write64(rsp + 0x48, 0x1020);
    guest::write64(rsp + 0x38, 7);
    let reopened = call("NtCreateFile", handle_pointer, 0x8011_0000, attributes, iosb);
    let deleter = guest::read64(handle_pointer);
    assert(reopened == 0 && call("NtClose", deleter, 0, 0, 0) == 0 && volume_files::lookup_volume_file("\\??\\D:\\OPENNTNT.TXT").is_none(), "usersyscalls: DELETE_ON_CLOSE pelo NtCreateFile remove o arquivo");
    // Dispositivo DOS inexistente: NOT_FOUND real no IOSB.
    set_name("\\\\.\\OpenNtSemDevice");
    guest::write32(rsp + 0x28, 0);
    guest::write32(rsp + 0x30, 0);
    assert(call("NtOpenFile", handle_pointer, 0x8010_0000, attributes, iosb) == 0xC000_0034 && io_status.status.get() as u32 == 0xC000_0034, "usersyscalls: dispositivo inexistente devolve NOT_FOUND");
    // Recusas.
    set_name("\\??\\D:\\HELLO.TXT");
    guest::write32(rsp + 0x28, 1);
    guest::write32(rsp + 0x30, 0x20);
    let _ = call("NtOpenFile", handle_pointer, 0x8010_0000, attributes, iosb);
    let plain = guest::read64(handle_pointer);
    assert(call("NtDeviceIoControlFile", plain, 0, 0, 0) == 0xC000_0008 && call("NtQuerySection", plain, 0, block + 0x800, 24) == 0xC000_0008 && call("NtUnmapViewOfSectionEx", u64::MAX, 0x2_0000_0000, 1, 0) == 0xC000_00BB, "usersyscalls: IOCTL e NtQuerySection em arquivo, placeholder recusado");
    let _ = call("NtClose", plain, 0, 0, 0);
    // NtCreateSection de usuário (pagefile).
    let size = block + 0x20;
    unsafe { nt::LargeInteger::at(size) }.quad_part.set(0x2000);
    guest::write32(rsp + 0x28, 4);
    guest::write32(rsp + 0x30, 0x0800_0000);
    guest::write64(rsp + 0x38, 0);
    let section = call("NtCreateSection", handle_pointer, 0xF_001F, 0, size);
    let section_handle = guest::read64(handle_pointer);
    assert(section == 0 && section_handle != 0, "usersyscalls: NtCreateSection de usuario");
    let _ = crate::ntos::ob::open_pointer::close(section_handle);
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn user_handle_operations(assert: Assert) {
    use crate::ntos::ps::user::file_io::{self, OpenRequest};
    use crate::ntos::ps::user::memory;
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "userhandles: memoria de usuario");
        return;
    };
    let (out, iosb, input, rsp) = (block, block + 0x10, block + 0x40, block + 0x1000);
    let open_hello = || {
        guest::write64(out, 0);
        let _ = file_io::open(out, "\\??\\D:\\HELLO.TXT", iosb, 1, &OpenRequest { access: 0x8010_0000, share: 1, options: 0x20, ..OpenRequest::default() });
        guest::read64(out)
    };
    let duplicate = |source_process: u64, source: u64, target_process: u64, access: u32, attributes: u32, options: u32| {
        guest::write64(out, 0);
        guest::write32(rsp + 0x28, access);
        guest::write32(rsp + 0x30, attributes);
        guest::write32(rsp + 0x38, options);
        let status = state::handler("NtDuplicateObject").map(|handler| handler(source_process, source, target_process, out, rsp).unwrap_or(1)).unwrap_or(1);
        (status, guest::read64(out))
    };
    let source = open_hello();
    let (status, copy) = duplicate(u64::MAX, source, u64::MAX, 0, 0, 2);
    let (source_entry, copy_entry) = (state::get_user_handle(source), state::get_user_handle(copy));
    assert(status == 0 && copy != source && source_entry.as_ref().zip(copy_entry.as_ref()).is_some_and(|(left, right)| state::same_object(left, right) && right.access() == left.access()), "userhandles: DUPLICATE_SAME_ACCESS sobre a mesma descricao");
    drop(source_entry);
    drop(copy_entry);
    assert(duplicate(u64::MAX, source, u64::MAX, 0x1F_01FF, 0, 0).0 == 0xC000_0022 && duplicate(u64::MAX, source, u64::MAX, 0, 0, 8).0 == 0xC000_000D && duplicate(u64::MAX, 0x7FF0, u64::MAX, 0, 0, 2).0 == 0xC000_0008, "userhandles: direitos alem da origem, opcoes invalidas e handle ausente");
    // DUPLICATE_CLOSE_SOURCE, inclusive com destino nulo.
    let (status, moved) = duplicate(u64::MAX, source, u64::MAX, 0, 0, 3);
    assert(status == 0 && state::get_user_handle(source).is_none() && state::get_user_handle(moved).is_some(), "userhandles: DUPLICATE_CLOSE_SOURCE fecha a origem");
    assert(duplicate(u64::MAX, moved, 0, 0, 0, 1).0 == 0 && state::get_user_handle(moved).is_none(), "userhandles: destino nulo so fecha a origem");
    // Pseudo-handle do processo corrente.
    let (status, process_handle) = duplicate(u64::MAX, u64::MAX, u64::MAX, 0, 0, 2);
    assert(status == 0 && state::get_user_handle(process_handle).is_some_and(|entry| entry.kind() == "process" && entry.access() == 0x1F_FFFF), "userhandles: pseudo-handle de processo vira handle process");
    let _ = state::close_user_handle(process_handle, true, false);
    // NtSetInformationObject: Inherit e ProtectFromClose.
    let flag_info = unsafe { nt::ObjectHandleFlagInformation::at(input) };
    let set = |handle: u64, flags: [u8; 2], class: u64, length: u64| {
        flag_info.inherit.set(flags[0]);
        flag_info.protect_from_close.set(flags[1]);
        state::handler("NtSetInformationObject").map(|handler| handler(handle, class, input, length, rsp).unwrap_or(1)).unwrap_or(1)
    };
    assert(set(copy, [1, 1], 4, 2) == 0 && state::get_user_handle(copy).is_some_and(|entry| entry.attributes() == 3) && state::close_user_handle(copy, true, false).is_ok_and(|status| status == 0xC000_0235), "userhandles: handle protegido contra fechamento");
    assert(set(copy, [0, 0], 4, 2) == 0 && set(copy, [0, 0], 3, 2) == 0xC000_0003 && set(copy, [0, 0], 4, 3) == 0xC000_0004 && state::close_user_handle(copy, true, false).is_ok_and(|status| status == 0), "userhandles: protecao removida, classe e tamanho invalidos");
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn user_events_and_semaphores(assert: Assert) {
    use crate::ntos::ob::object_manager;
    use crate::ntos::ps::user::memory;
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "userevents: memoria de usuario");
        return;
    };
    let (out, previous, info, attributes, rsp) = (block, block + 0x10, block + 0x20, block + 0x100, block + 0x1000);
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map(|handler| handler(a1, a2, a3, a4, rsp).unwrap_or(1)).unwrap_or(1);
    let named = |name: &str, flags: u32| {
        let text = attributes + 0x80;
        state::write_user_wide(text, name);
        state::write_unicode_string(attributes + 0x40, text, name);
        set_object_attributes(unsafe { nt::ObjectAttributes::at(attributes) }, nt::ObjectAttributes::SIZE as u32, 0, attributes + 0x40, flags);
        attributes
    };
    let event_info = unsafe { nt::EventBasicInformation::at(info) };
    // Evento anônimo de sincronização.
    guest::write32(rsp + 0x28, 0);
    let created = call("NtCreateEvent", out, 0x1F_0003, 0, 1);
    let event = guest::read64(out);
    assert(created == 0 && state::get_user_handle(event).is_some_and(|entry| entry.kind() == "event"), "userevents: NtCreateEvent anonimo");
    assert(call("NtSetEvent", event, previous, 0, 0) == 0 && guest::read32(previous) == 0 && call("NtQueryEvent", event, 0, info, 8) == 0 && event_info.event_type.get() == 1 && event_info.event_state.get() == 1, "userevents: NtSetEvent e NtQueryEvent com tipo e estado");
    assert(call("NtResetEvent", event, previous, 0, 0) == 0 && guest::read32(previous) == 1 && call("NtQueryEvent", event, 0, info, 8) == 0 && event_info.event_state.get() == 0 && call("NtQueryEvent", event, 1, info, 8) == 0xC000_0003 && call("NtCreateEvent", out, 0x1F_0003, 0, 2) == 0xC000_000D, "userevents: NtResetEvent, classe e tipo invalidos");
    // Evento nomeado: colisão, OPENIF, NtOpenEvent e acesso insuficiente.
    let first_attributes = named("\\OpenNtEventoTeste", 0x40);
    assert(call("NtCreateEvent", out, 0x1F_0003, first_attributes, 0) == 0, "userevents: evento nomeado criado");
    let first = guest::read64(out);
    assert(object_manager::lookup("\\OpenNtEventoTeste").is_some() && call("NtCreateEvent", out, 0x1F_0003, named("\\OpenNtEventoTeste", 0x40), 0) == 0xC000_0035, "userevents: nome publicado e colisao sem OPENIF");
    assert(call("NtCreateEvent", out, 0x1F_0003, named("\\OpenNtEventoTeste", 0xC0), 0) == 0x4000_0000, "userevents: OPENIF abre o existente");
    let second = guest::read64(out);
    assert(call("NtOpenEvent", out, 0x10_0000, named("\\OpenNtEventoTeste", 0x40), 0) == 0, "userevents: NtOpenEvent so com SYNCHRONIZE");
    let weak = guest::read64(out);
    assert(call("NtSetEvent", weak, 0, 0, 0) == 0xC000_0022 && call("NtSetEvent", second, 0, 0, 0) == 0 && call("NtQueryEvent", first, 0, info, 8) == 0 && event_info.event_state.get() == 1, "userevents: acesso insuficiente e estado compartilhado pelo nome");
    for handle in [first, second, weak] {
        let _ = call("NtClose", handle, 0, 0, 0);
    }
    assert(object_manager::lookup("\\OpenNtEventoTeste").is_none() && call("NtOpenEvent", out, 0x10_0000, named("\\OpenNtEventoTeste", 0x40), 0) == 0xC000_0034, "userevents: ultimo handle remove o evento e o nome");
    let _ = call("NtClose", event, 0, 0, 0);
    // Semáforo: liberação até o limite e consulta.
    guest::write32(rsp + 0x28, 2);
    let semaphore_status = call("NtCreateSemaphore", out, 0x1F_0003, 0, 1);
    let semaphore = guest::read64(out);
    assert(semaphore_status == 0 && state::get_user_handle(semaphore).is_some_and(|entry| entry.kind() == "semaphore"), "userevents: NtCreateSemaphore");
    assert(call("NtReleaseSemaphore", semaphore, 1, previous, 0) == 0 && guest::read32(previous) == 1 && call("NtReleaseSemaphore", semaphore, 1, previous, 0) == 0xC000_0047, "userevents: NtReleaseSemaphore ate o limite");
    guest::write64(rsp + 0x28, 0);
    assert(call("NtQuerySemaphore", semaphore, 0, info, 8) == 0 && { let semaphore_info = unsafe { nt::SemaphoreBasicInformation::at(info) }; semaphore_info.current_count.get() == 2 && semaphore_info.maximum_count.get() == 2 }, "userevents: NtQuerySemaphore com contagem e limite");
    guest::write32(rsp + 0x28, 0);
    assert(call("NtCreateSemaphore", out, 0x1F_0003, 0, 0) == 0xC000_000D, "userevents: limite zero recusado");
    let _ = call("NtClose", semaphore, 0, 0, 0);
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn user_mutants_and_timers(assert: Assert) {
    use crate::ntos::ps::user::{memory, mutants, timer_objects};
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "usermutants: memoria de usuario");
        return;
    };
    let (out, previous, info, due, attributes, rsp) = (block, block + 0x10, block + 0x20, block + 0x40, block + 0x100, block + 0x1000);
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map(|handler| handler(a1, a2, a3, a4, rsp).unwrap_or(1)).unwrap_or(1);
    let named = |name: &str, flags: u32| {
        let text = attributes + 0x80;
        state::write_user_wide(text, name);
        state::write_unicode_string(attributes + 0x40, text, name);
        set_object_attributes(unsafe { nt::ObjectAttributes::at(attributes) }, nt::ObjectAttributes::SIZE as u32, 0, attributes + 0x40, flags);
        attributes
    };
    let (mutant_info, owner, timer_info, due_time) = unsafe { (nt::MutantBasicInformation::at(info), nt::ClientId::at(info), nt::TimerBasicInformation::at(info), nt::LargeInteger::at(due)) };
    guest::write64(rsp + 0x28, 0);
    // Mutante com dono inicial: consulta, liberação e não dono.
    let owned = call("NtCreateMutant", out, 0x1F_0001, 0, 1);
    let mutant = guest::read64(out);
    assert(owned == 0 && call("NtQueryMutant", mutant, 0, info, 8) == 0 && mutant_info.current_count.get() == 0 && mutant_info.owned_by_caller.get() == 1 && mutant_info.abandoned_state.get() == 0, "usermutants: mutante possuido pela thread corrente");
    assert(call("NtReleaseMutant", mutant, previous, 0, 0) == 0 && guest::read32(previous) == 0 && call("NtReleaseMutant", mutant, previous, 0, 0) == 0xC000_0046, "usermutants: liberacao e MUTANT_NOT_OWNED");
    assert(call("NtQueryMutant", mutant, 1, info, 16) == 0 && owner.unique_process.get() == 0 && owner.unique_thread.get() == 0 && call("NtQueryMutant", mutant, 2, info, 16) == 0xC000_0003, "usermutants: dono vazio e classe invalida");
    let _ = call("NtClose", mutant, 0, 0, 0);
    // Saída de thread abandona o mutante possuído.
    let _ = call("NtCreateMutant", out, 0x1F_0001, 0, 1);
    let abandoned = guest::read64(out);
    mutants::release_thread(crate::ntos::ps::process::get_current_thread());
    assert(call("NtQueryMutant", abandoned, 0, info, 8) == 0 && mutant_info.current_count.get() == 1 && mutant_info.abandoned_state.get() == 1, "usermutants: saida da thread abandona o mutante");
    let _ = call("NtClose", abandoned, 0, 0, 0);
    // Nome, colisão, OPENIF e NtOpenMutant.
    assert(call("NtCreateMutant", out, 0x1F_0001, named("\\OpenNtMutanteTeste", 0x40), 0) == 0, "usermutants: mutante nomeado");
    let first = guest::read64(out);
    assert(call("NtCreateMutant", out, 0x1F_0001, named("\\OpenNtMutanteTeste", 0x40), 0) == 0xC000_0035 && call("NtCreateMutant", out, 0x1F_0001, named("\\OpenNtMutanteTeste", 0xC0), 0) == 0x4000_0000, "usermutants: colisao e OPENIF");
    let second = guest::read64(out);
    assert(call("NtOpenMutant", out, 0x10_0000, named("\\OpenNtMutanteTeste", 0x40), 0) == 0, "usermutants: NtOpenMutant");
    let third = guest::read64(out);
    for handle in [first, second, third] {
        let _ = call("NtClose", handle, 0, 0, 0);
    }
    assert(crate::ntos::ob::object_manager::lookup("\\OpenNtMutanteTeste").is_none(), "usermutants: nome removido no ultimo handle");
    // Timer: prazo relativo, vencido, cancelamento e recusas.
    guest::write32(rsp + 0x28, 0x1F_0003);
    let created = call("NtCreateTimer2", out, 0, 0, 0);
    let timer = guest::read64(out);
    assert(created == 0 && state::get_user_handle(timer).is_some_and(|entry| entry.kind() == "timer"), "usermutants: NtCreateTimer2");
    guest::write64(rsp + 0x28, 0);
    due_time.quad_part.set(-1_000_000);
    assert(call("NtSetTimer2", timer, due, 0, 0) == 0 && call("NtQueryTimer", timer, 0, info, 16) == 0 && timer_info.remaining_time.quad_part.get() > 0 && timer_info.remaining_time.quad_part.get() <= 1_000_000 && timer_info.timer_state.get() == 0, "usermutants: prazo relativo e tempo restante");
    due_time.quad_part.set(116_444_736_000_000_000);
    assert(call("NtSetTimer2", timer, due, 0, 0) == 0 && { timer_objects::pump(); call("NtQueryTimer", timer, 0, info, 16) == 0 } && timer_info.timer_state.get() == 1 && timer_info.remaining_time.quad_part.get() == 0, "usermutants: prazo absoluto vencido sinaliza pelo pump");
    assert(call("NtCancelTimer2", timer, 0, 0, 0) == 0 && call("NtCancelTimer2", timer, due, 0, 0) == 0xC000_000D && call("NtQueryTimer", timer, 0, info, 8) == 0xC000_0004, "usermutants: cancelamento e recusas de parametros e tamanho");
    unsafe { nt::LargeInteger::at(previous) }.quad_part.set(-5);
    assert(call("NtSetTimer2", timer, due, previous, 0) == 0xC000_000D, "usermutants: periodo negativo recusado");
    guest::write32(rsp + 0x28, 0x1F_0003);
    assert(call("NtCreateTimer2", out, 0, 0, 0x10) == 0xC000_000D && call("NtCreateTimer2", out, 1, 0, 0) == 0xC000_00BB, "usermutants: atributos invalidos e provedor IR");
    let _ = call("NtClose", timer, 0, 0, 0);
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn user_io_completion(assert: Assert) {
    use crate::ntos::io::completion::{create as create_completion, set as set_completion};
    use crate::ntos::ob::objects::{completion as completion_objects, dispatcher as dispatcher_objects};
    use crate::ntos::ob::{object_manager, open_pointer};
    use crate::ntos::ps::user::{io_completion, memory};
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "usercompletion: memoria de usuario");
        return;
    };
    let (out, info, raw, attributes, rsp) = (block, block + 0x20, block + 0x40, block + 0x100, block + 0x1000);
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map(|handler| handler(a1, a2, a3, a4, rsp).unwrap_or(1)).unwrap_or(1);
    let named = |name: &str, flags: u32| {
        let text = attributes + 0x80;
        state::write_user_wide(text, name);
        state::write_unicode_string(attributes + 0x40, text, name);
        set_object_attributes(unsafe { nt::ObjectAttributes::at(attributes) }, nt::ObjectAttributes::SIZE as u32, 0, attributes + 0x40, flags);
        attributes
    };
    guest::write64(rsp + 0x28, 0);
    // Criação anônima, profundidade e classes.
    let created = call("NtCreateIoCompletion", out, 0x1F_0003, 0, 0);
    let handle = guest::read64(out);
    let port = io_completion::resolve(handle, 0).ok().map(|(_, port)| port);
    assert(created == 0 && port.as_ref().is_some_and(|port| port.concurrency() == crate::ntos::ke::smp::online_cpu_count() as u32 && !port.closed()), "usercompletion: porta anonima com concorrencia dos processadores");
    guest::write64(rsp + 0x28, info + 8);
    assert(call("NtQueryIoCompletion", handle, 0, info, 4) == 0 && unsafe { nt::IoCompletionBasicInformation::at(info) }.depth.get() == 0 && guest::read32(info + 8) == 4, "usercompletion: profundidade vazia e tamanho devolvido");
    assert(call("NtQueryIoCompletion", handle, 0, info, 8) == 0xC000_0004 && call("NtQueryIoCompletion", handle, 1, info, 4) == 0xC000_0003, "usercompletion: tamanho e classe invalidos");
    // NtSetIoCompletion lê chave e contexto em 64 bits do frame bruto.
    guest::write64(raw + 16, 0x1122_3344_5566_7788);
    guest::write64(raw + 24, 0xAABB_CCDD_0000_0001);
    guest::write64(rsp + 0x28, 0x99);
    state::with(|state| state.service_raw_arguments = raw);
    let posted = call("NtSetIoCompletion", handle, 0, 0, 0x103);
    state::with(|state| state.service_raw_arguments = 0);
    let front = port.as_ref().and_then(|port| port.with(|state| state.packets.front().map(|packet| packet.values())));
    assert(posted == 0 && front == Some((0x1122_3344_5566_7788, 0xAABB_CCDD_0000_0001, 0x103, 0x99)), "usercompletion: pacote com chave, contexto, status e informacao");
    guest::write64(rsp + 0x28, 0);
    assert(call("NtQueryIoCompletion", handle, 0, info, 4) == 0 && unsafe { nt::IoCompletionBasicInformation::at(info) }.depth.get() == 1 && port.as_ref().is_some_and(|port| guest::read32(port.pointer + 0x18) == 1), "usercompletion: profundidade espelhada no corpo");
    assert(call("NtSetIoCompletion", 0x7FF0, 0, 0, 0) == 0xC000_0008 && call("NtQueryIoCompletion", out, 0, info, 4) == 0xC000_0008, "usercompletion: handle invalido");
    // Pacote de memória do kernel e associação de thread.
    if let Some(port) = port.as_ref() {
        let before = set_completion::pending_count();
        let refs = dispatcher_objects::get(port.pointer).map(|(_, refs, _)| refs).unwrap_or(0);
        assert(set_completion::post(port.pointer, 7, 8, 0, 9, 0, 0).ok() == Some(0) && set_completion::pending_count() == before + 1 && port.with(|state| state.packets.back().map(|packet| packet.values())) == Some((7, 8, 0, 9)), "usercompletion: IoSetIoCompletionEx publica pacote de memoria");
        let thread = crate::ntos::ps::process::get_current_thread();
        completion_objects::associate(thread, port);
        let associated = dispatcher_objects::get(port.pointer).map(|(_, refs, _)| refs).unwrap_or(0);
        completion_objects::associate(thread, port);
        let again = dispatcher_objects::get(port.pointer).map(|(_, refs, _)| refs).unwrap_or(0);
        completion_objects::dissociate(thread);
        assert(associated == refs + 1 && again == associated && dispatcher_objects::get(port.pointer).map(|(_, refs, _)| refs) == Some(refs), "usercompletion: associacao retem a porta uma vez");
        let pointer = port.pointer;
        let _ = call("NtClose", handle, 0, 0, 0);
        assert(set_completion::pending_count() == before && dispatcher_objects::get(pointer).is_none(), "usercompletion: fechamento drena pacotes e libera o corpo");
    }
    // Nome, colisão, OPENIF, NtOpenIoCompletion e recusas de atributos.
    assert(call("NtCreateIoCompletion", out, 0x1F_0003, named("\\OpenNtPortaTeste", 0x40), 2) == 0, "usercompletion: porta nomeada");
    let first = guest::read64(out);
    assert(call("NtCreateIoCompletion", out, 0x1F_0003, named("\\OpenNtPortaTeste", 0x40), 2) == 0xC000_0035 && call("NtCreateIoCompletion", out, 0x1F_0003, named("\\OpenNtPortaTeste", 0xC0), 5) == 0x4000_0000, "usercompletion: colisao e OPENIF");
    let second = guest::read64(out);
    assert(io_completion::resolve(second, 0).is_ok_and(|(_, port)| port.concurrency() == 2), "usercompletion: OPENIF preserva a concorrencia");
    assert(call("NtOpenIoCompletion", out, 1, named("\\OpenNtPortaTeste", 0x40), 0) == 0, "usercompletion: NtOpenIoCompletion");
    let third = guest::read64(out);
    assert(call("NtSetIoCompletion", third, 0, 0, 0) == 0xC000_0022, "usercompletion: acesso sem MODIFY_STATE recusado");
    for handle in [first, second, third] {
        let _ = call("NtClose", handle, 0, 0, 0);
    }
    assert(object_manager::lookup("\\OpenNtPortaTeste").is_none(), "usercompletion: nome removido no ultimo handle");
    assert(call("NtCreateIoCompletion", out, 0x1F_0003, named("\\OpenNtPortaTeste", 0x10), 0) == 0xC000_000D && call("NtCreateIoCompletion", out, 0x1F_0003, attributes + 4, 0) == 0x8000_0002 && call("NtCreateIoCompletion", out, 0x1F_0003, named("OpenNtPortaTeste", 0x40), 0) == 0xC000_003B, "usercompletion: OBJ_PERMANENT, desalinhamento e nome relativo sem raiz");
    // ZwCreateIoCompletion publica handle de kernel.
    let kernel_out = guest::alloc_bytes(8);
    let status = create_completion::create(kernel_out, 0x1F_0003, 0, 1, 0);
    let kernel_handle = guest::read64(kernel_out);
    assert(status.ok() == Some(0) && kernel_handle != 0 && open_pointer::close(kernel_handle) == Some(0), "usercompletion: ZwCreateIoCompletion em KernelMode");
    guest::free_bytes(kernel_out);
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

static THREAD_WAIT_CLEANUP: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn user_threads(assert: Assert) {
    use crate::ntos::ke::{thread_dispatch, thread_priority};
    use crate::ntos::ps::process;
    use crate::ntos::ps::user::threads::{self, Wait};
    use crate::ntos::ps::user::{io_completion, memory};
    use core::sync::atomic::Ordering;
    let Ok(block) = memory::map_user_region(0x4000) else {
        assert(false, "userthreads: memoria de usuario");
        return;
    };
    let (out, info, list, cid, teb_out, timeout, image, peb, rsp) = (block, block + 0x40, block + 0x100, block + 0x180, block + 0x190, block + 0x1A0, block + 0x1000, block + 0x2000, block + 0x3000);
    let (client_id, delay) = unsafe { (nt::ClientId::at(cid), nt::LargeInteger::at(timeout)) };
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map(|handler| handler(a1, a2, a3, a4, rsp).unwrap_or(1)).unwrap_or(1);
    // PEB e cabeçalho de imagem mínimos: reserva de pilha de 0x20000.
    unsafe { nt::Peb::at(peb) }.image_base_address.set(image);
    unsafe { nt::ImageDosHeader::at(image) }.e_lfanew.set(0x80);
    unsafe { nt::ImageNtHeaders64::at(image + 0x80) }.optional_header.size_of_stack_reserve.set(0x20000);
    let saved_peb = state::with(|state| core::mem::replace(&mut state.current_peb_va, peb));
    let known = threads::all().len();
    let process_pointer = process::get_current_process();
    let baseline = unsafe { nt::Eprocess::at(process_pointer) }.active_threads.get();
    if baseline == 0 {
        process::add_thread(process_pointer);
    }
    // Fora do laço de execução a criação é recusada.
    for (offset, value) in [(0x28u64, block + 0x800), (0x30, 0x1122_3344_5566_7788), (0x38, 5), (0x40, 0), (0x48, 0), (0x50, 0), (0x58, list)] {
        guest::write64(rsp + offset, value);
    }
    let attribute_list = unsafe { nt::PsAttributeList::at(list) };
    attribute_list.total_length.set(8 + 2 * nt::PsAttribute::SIZE);
    let entries = unsafe { nt::PsAttribute::array_at(attribute_list.attributes[0].address(), 2) };
    for (entry, (attribute, size, target, returned)) in entries.iter().zip([(0x10003u64, 16u64, cid, info + 0x30), (0x10004, 8, teb_out, 0)]) {
        entry.attribute.set(attribute);
        entry.size.set(size);
        entry.value.set(target);
        entry.return_length.set(returned);
    }
    assert(call("NtCreateThreadEx", out, 0x1F_FFFF, 0, u64::MAX) == 0xC000_0005 && call("NtCreateThreadEx", out, 0x1F_FFFF, 0, 4) == 0xC000_0008, "userthreads: criacao fora do laco e processo alheio recusados");
    threads::set_running(true, None);
    guest::write64(rsp + 0x38, 0x80);
    assert(call("NtCreateThreadEx", out, 0x1F_FFFF, 0, u64::MAX) == 0xC000_000D, "userthreads: flags invalidas");
    guest::write64(rsp + 0x38, 5);
    let created = call("NtCreateThreadEx", out, 0x1F_FFFF, 0, u64::MAX);
    let handle = guest::read64(out);
    let thread = threads::resolve(handle, 0).ok();
    let Some(thread) = thread.filter(|_| created == 0) else {
        assert(false, "userthreads: NtCreateThreadEx suspensa e oculta");
        threads::set_running(false, None);
        state::with(|state| state.current_peb_va = saved_peb);
        return;
    };
    let (pointer, teb) = (thread.pointer(), thread.with(|thread| thread.teb_va));
    let teb_view = unsafe { nt::Teb::at(teb) };
    let stack = teb_view.nt_tib.stack_limit.get();
    assert(client_id.unique_thread.get() == thread.thread_id && guest::read64(info + 0x30) == 16 && guest::read64(teb_out) == teb && teb_view.nt_tib.self_.get() == teb && teb_view.client_id.unique_thread.get() == thread.thread_id && teb_view.process_environment_block.get() == peb && teb_view.nt_tib.stack_base.get() == stack + 0x20000, "userthreads: CLIENT_ID, TEB e pilha pela reserva da imagem");
    let startup = unsafe { nt::Context::at(nt::Context::at(thread.with(|thread| thread.context)).rcx.get()) };
    assert(startup.rcx.get() == block + 0x800 && startup.rdx.get() == 0x1122_3344_5566_7788 && thread_dispatch::thread_state(pointer) == thread_dispatch::state::WAITING, "userthreads: contexto inicial com argumento de 64 bits e thread suspensa");
    // Consultas.
    guest::write64(rsp + 0x28, info + 0x38);
    let basic = unsafe { nt::ThreadBasicInformation::at(info) };
    assert(call("NtQueryInformationThread", handle, 0, info, 48) == 0 && basic.exit_status.get() == 0x103 && basic.teb_base_address.get() == teb && basic.client_id.unique_thread.get() == thread.thread_id && guest::read32(info + 0x38) == 48, "userthreads: ThreadBasicInformation");
    assert(call("NtQueryInformationThread", handle, 9, info, 8) == 0 && guest::read64(info) == block + 0x800 && call("NtQueryInformationThread", handle, 17, info, 1) == 0 && guest::read8(info) == 1, "userthreads: endereco inicial e oculta do depurador");
    assert(call("NtQueryInformationThread", handle, 0, info, 40) == 0xC000_0004 && call("NtQueryInformationThread", handle, 5, info, 8) == 0xC000_0003, "userthreads: tamanho e classe invalidos");
    // Suspensão, retomada e prioridades.
    assert(call("NtResumeThread", handle, info, 0, 0) == 0 && guest::read32(info) == 1 && thread_dispatch::thread_state(pointer) == thread_dispatch::state::READY, "userthreads: retomada deixa a thread pronta");
    assert(call("NtSuspendThread", handle, info, 0, 0) == 0 && guest::read32(info) == 0 && thread_dispatch::thread_state(pointer) == thread_dispatch::state::WAITING, "userthreads: suspensao tira da fila");
    guest::write32(info, 10);
    let priority = call("NtSetInformationThread", handle, 1, info, 4) == 0 && thread_priority::query_priority(pointer) == 10;
    guest::write32(info, 2);
    let base = call("NtSetInformationThread", handle, 2, info, 4) == 0 && thread_priority::query_base_priority(pointer) == 10;
    guest::write32(info, 40);
    assert(priority && base && call("NtSetInformationThread", handle, 1, info, 4) == 0xC000_000D && call("NtSetInformationThread", handle, 17, info, 1) == 0xC000_0004, "userthreads: prioridade, base e recusas");
    teb_view.tls_slots[5].set(0x55);
    guest::write32(info, 5);
    assert(call("NtSetInformationThread", handle, 10, info, 4) == 0 && teb_view.tls_slots[5].get() == 0, "userthreads: ThreadZeroTlsCell zera o indice nas TEBs");
    // Abertura por CLIENT_ID.
    client_id.unique_process.set(0);
    assert(call("NtOpenThread", out, 0x40, 0, cid) == 0, "userthreads: NtOpenThread pelo id");
    let opened = guest::read64(out);
    client_id.unique_process.set(0x7777_0000);
    assert(call("NtOpenThread", out, 0x40, 0, cid) == 0xC000_000B && call("NtSuspendThread", opened, 0, 0, 0) == 0xC000_0022, "userthreads: processo alheio e acesso insuficiente");
    // Alertas por id e esperas, com a thread retomada como corrente (laço real).
    let previous_thread = process::get_current_thread();
    let _ = call("NtResumeThread", handle, 0, 0, 0);
    process::set_current_thread(pointer);
    threads::set_running(true, Some(thread.clone()));
    assert(call("NtAlertThreadByThreadId", thread.thread_id, 0, 0, 0) == 0 && call("NtWaitForAlertByThreadId", 0, 0, 0, 0) == 0x101 && call("NtAlertThreadByThreadId", 0xFFFF_0000, 0, 0, 0) == 0xC000_000B, "userthreads: alerta por id consumido");
    delay.quad_part.set(0);
    assert(call("NtWaitForAlertByThreadId", 0, timeout, 0, 0) == 0x102, "userthreads: espera de alerta com prazo zero");
    delay.quad_part.set(-1);
    assert(call("NtDelayExecution", 0, timeout, 0, 0) == 0 && !thread.waiting(), "userthreads: atraso vencido retorna sem bloquear");
    let immediate = threads::wait_custom(Wait { poll: Some(alloc::boxed::Box::new(|| Some(0x77))), cleanup: Some(alloc::boxed::Box::new(|status| THREAD_WAIT_CLEANUP.store(status, Ordering::Release))), ..Wait::default() }, 0, Some(None));
    assert(immediate == 0x77 && THREAD_WAIT_CLEANUP.load(Ordering::Acquire) == 0x77, "userthreads: espera personalizada imediata com limpeza");
    // Retirada de IOCP: pacote disponível e espera bloqueada.
    guest::write64(rsp + 0x28, 0);
    let _ = call("NtCreateIoCompletion", out, 0x1F_0003, 0, 1);
    let port_handle = guest::read64(out);
    let port = io_completion::resolve(port_handle, 0).ok().map(|(_, port)| port);
    let raw = block + 0x1C0;
    guest::write64(raw + 16, 0xABCD);
    guest::write64(raw + 24, 0x1234);
    guest::write64(rsp + 0x28, 0x10);
    state::with(|state| state.service_raw_arguments = raw);
    let _ = call("NtSetIoCompletion", port_handle, 0, 0, 0x55);
    state::with(|state| state.service_raw_arguments = 0);
    guest::write64(rsp + 0x28, 0);
    let removed = call("NtRemoveIoCompletion", port_handle, info, info + 8, info + 16);
    assert(removed == 0 && guest::read64(info) == 0xABCD && guest::read64(info + 8) == 0x1234 && unsafe { nt::IoStatusBlock::at(info + 16) }.status.get() == 0x55 && unsafe { nt::IoStatusBlock::at(info + 16) }.information.get() == 0x10 && port.as_ref().is_some_and(|port| port.with(|state| state.active.contains(&pointer) && state.associated.contains(&pointer) && state.waiters.is_empty())), "userthreads: NtRemoveIoCompletion entrega o pacote e ativa a thread");
    let blocked = call("NtRemoveIoCompletion", port_handle, info, info + 8, info + 16);
    assert(blocked == 0x103 && thread.waiting() && port.as_ref().is_some_and(|port| port.with(|state| state.waiters.len() == 1 && !state.active.contains(&pointer))), "userthreads: fila vazia bloqueia o consumidor");
    // Término: a espera acaba com THREAD_IS_TERMINATING e a porta é solta.
    assert(call("NtTerminateThread", handle, 0x1234, 0, 0) == 0 && thread.dead() && !thread.waiting() && port.as_ref().is_some_and(|port| port.with(|state| state.waiters.is_empty() && state.associated.is_empty())), "userthreads: NtTerminateThread encerra a espera e dissocia");
    guest::write64(rsp + 0x28, 0);
    assert(call("NtQueryInformationThread", handle, 0, info, 48) == 0 && basic.exit_status.get() == 0x1234 && basic.teb_base_address.get() == 0 && call("NtTerminateThread", handle, 0, 0, 0) == 0xC000_004B && call("NtResumeThread", handle, 0, 0, 0) == 0xC000_004B, "userthreads: status de saida e recusas apos o termino");
    process::set_current_thread(previous_thread);
    threads::set_running(false, None);
    for value in [port_handle, opened, handle] {
        let _ = call("NtClose", value, 0, 0, 0);
    }
    threads::release_execution_resources(&thread);
    assert(thread.pointer() == 0 && thread.with(|thread| thread.regions.is_none() && thread.context == 0) && memory::find_region(stack).is_none(), "userthreads: recursos e ETHREAD liberados sem handles");
    if known == 0 {
        threads::clear();
    }
    if baseline == 0 {
        process::remove_thread(process_pointer);
    }
    state::with(|state| state.current_peb_va = saved_peb);
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn user_wait_packets(assert: Assert) {
    use crate::ntos::ob::objects::work as work_objects;
    use crate::ntos::ps::user::{io_completion, memory, wait_packets};
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "userwaitpackets: memoria de usuario");
        return;
    };
    let (out, info, already, raw, attributes, rsp) = (block, block + 0x20, block + 0x60, block + 0x80, block + 0x100, block + 0x1000);
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map(|handler| handler(a1, a2, a3, a4, rsp).unwrap_or(1)).unwrap_or(1);
    guest::write64(rsp + 0x28, 0);
    let _ = call("NtCreateIoCompletion", out, 0x1F_0003, 0, 1);
    let port_handle = guest::read64(out);
    let port = io_completion::resolve(port_handle, 0).ok().map(|(_, port)| port);
    let depth = || port.as_ref().map_or(99, |port| port.with(|state| state.packets.len()));
    // Evento de sincronização (consumido pela espera do pacote).
    guest::write64(rsp + 0x28, 0);
    let _ = call("NtCreateEvent", out, 0x1F_0003, 0, 1);
    let event = guest::read64(out);
    assert(call("NtCreateWaitCompletionPacket", out, 0xF_0001, 0, 0) == 0, "userwaitpackets: NtCreateWaitCompletionPacket");
    let packet_handle = guest::read64(out);
    let packet = state::get_user_handle(packet_handle).and_then(|entry| entry.downcast::<crate::ntos::ob::objects::dispatcher::UserDispatcher>().map(|dispatcher| dispatcher.pointer)).unwrap_or(0);
    let phase = || guest::read32(packet + 0x10);
    set_object_attributes(unsafe { nt::ObjectAttributes::at(attributes) }, nt::ObjectAttributes::SIZE as u32, 0, attributes + 0x40, 0);
    assert(packet != 0 && call("NtCreateWaitCompletionPacket", out, 0xF_0001, attributes, 0) == 0xC000_0033, "userwaitpackets: pacote sem nome");
    // Associação: chave do frame bruto, contexto/status/informação da pilha.
    let associate = |target: u64| {
        guest::write64(raw + 32, 0x4B45_5900_0000_0001);
        guest::write64(rsp + 0x28, 0xC0DE);
        guest::write64(rsp + 0x30, 0x77);
        guest::write64(rsp + 0x38, 0x99);
        guest::write64(rsp + 0x40, already);
        guest::write8(already, 0xFF);
        state::with(|state| state.service_raw_arguments = raw);
        let status = call("NtAssociateWaitCompletionPacket", packet_handle, port_handle, target, 0);
        state::with(|state| state.service_raw_arguments = 0);
        status
    };
    assert(associate(event) == 0 && guest::read8(already) == 0 && phase() == 1 && guest::read64(packet + 0x20) != 0 && depth() == 0, "userwaitpackets: associacao pendente com evento nao sinalizado");
    assert(associate(event) == 0xC000_000D && associate(port_handle) == 0xC000_000D, "userwaitpackets: pacote ja associado");
    assert(call("NtSetEvent", event, 0, 0, 0) == 0 && { wait_packets::pump(); depth() == 1 } && phase() == 2, "userwaitpackets: sinal publicado na porta pelo pump");
    guest::write64(rsp + 0x28, 0);
    assert(call("NtQueryEvent", event, 0, info, 8) == 0 && unsafe { nt::EventBasicInformation::at(info) }.event_state.get() == 0, "userwaitpackets: evento de sincronizacao consumido");
    let removed = call("NtRemoveIoCompletion", port_handle, info, info + 8, info + 16);
    assert(removed == 0 && guest::read64(info) == 0x4B45_5900_0000_0001 && guest::read64(info + 8) == 0xC0DE && unsafe { nt::IoStatusBlock::at(info + 16) }.status.get() == 0x77 && unsafe { nt::IoStatusBlock::at(info + 16) }.information.get() == 0x99 && phase() == 0, "userwaitpackets: retirada entrega os dados e encerra a fase");
    // Objeto já sinalizado: publicado na hora; cancelamento sem e com remoção.
    let _ = call("NtSetEvent", event, 0, 0, 0);
    assert(associate(event) == 0 && guest::read8(already) == 1 && phase() == 2 && depth() == 1, "userwaitpackets: alvo ja sinalizado publica na associacao");
    assert(call("NtCancelWaitCompletionPacket", packet_handle, 0, 0, 0) == 0x103 && call("NtCancelWaitCompletionPacket", packet_handle, 1, 0, 0) == 0 && depth() == 0 && phase() == 0, "userwaitpackets: cancelamento do pacote enfileirado");
    assert(call("NtCancelWaitCompletionPacket", packet_handle, 0, 0, 0) == 0xC000_0120, "userwaitpackets: cancelamento sem associacao");
    assert(associate(event) == 0 && call("NtCancelWaitCompletionPacket", packet_handle, 0, 0, 0) == 0 && phase() == 0, "userwaitpackets: cancelamento da associacao pendente");
    assert(associate(port_handle) == 0xC000_0024 && call("NtCancelWaitCompletionPacket", event, 0, 0, 0) == 0xC000_0024, "userwaitpackets: tipos invalidos");
    // O último handle do pacote desfaz a associação e o corpo é liberado.
    let _ = associate(event);
    let _ = call("NtClose", packet_handle, 0, 0, 0);
    assert(work_objects::packet_of(packet).is_none(), "userwaitpackets: fechamento desfaz a associacao e libera o corpo");
    for handle in [event, port_handle] {
        let _ = call("NtClose", handle, 0, 0, 0);
    }
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

/// A ntdll de bring-up do build: stubs canônicos de NtDisplayString (0x27) e
/// NtTerminateProcess (0x2C), um stub não canônico e o alias Zw.
fn bring_up_ntdll() -> alloc::vec::Vec<u8> {
    let mut image = alloc::vec![0u8; 0x700];
    let put16 = |image: &mut [u8], at: usize, value: u16| image[at..at + 2].copy_from_slice(&value.to_le_bytes());
    let put32 = |image: &mut [u8], at: usize, value: u32| image[at..at + 4].copy_from_slice(&value.to_le_bytes());
    put16(&mut image, 0, 0x5A4D);
    put32(&mut image, 0x3C, 0x40);
    put32(&mut image, 0x40, 0x4550);
    put16(&mut image, 0x44, 0x8664);
    put16(&mut image, 0x46, 1);
    put16(&mut image, 0x54, 240);
    let optional = 0x58;
    put16(&mut image, 0x56, 0x2022);
    put16(&mut image, optional, 0x20B);
    put32(&mut image, optional + 16, 0x1030);
    image[optional + 24..optional + 32].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
    put32(&mut image, optional + 32, 0x1000);
    put32(&mut image, optional + 36, 0x200);
    put16(&mut image, optional + 48, 6);
    put16(&mut image, optional + 68, 2);
    put32(&mut image, optional + 108, 16);
    put32(&mut image, optional + 56, 0x3000);
    put32(&mut image, optional + 60, 0x400);
    put32(&mut image, optional + 112, 0x1100);
    put32(&mut image, optional + 116, 0x100);
    let section = optional + 240;
    image[section..section + 5].copy_from_slice(b".text");
    put32(&mut image, section + 8, 0x300);
    put32(&mut image, section + 12, 0x1000);
    put32(&mut image, section + 16, 0x300);
    put32(&mut image, section + 20, 0x400);
    put32(&mut image, section + 36, 0x6000_0020);
    // Código em 0x1000: dois stubs canônicos, um não canônico e o DllMain.
    let raw = |rva: usize| rva - 0x1000 + 0x400;
    for (rva, number) in [(0x1000usize, 0x27u32), (0x1010, 0x2C)] {
        image[raw(rva)..raw(rva) + 4].copy_from_slice(&[0x4C, 0x8B, 0xD1, 0xB8]);
        put32(&mut image, raw(rva) + 4, number);
        image[raw(rva) + 8..raw(rva) + 11].copy_from_slice(&[0x0F, 0x05, 0xC3]);
    }
    image[raw(0x1020)..raw(0x1020) + 8].copy_from_slice(&[0x90; 8]);
    image[raw(0x1030)..raw(0x1030) + 6].copy_from_slice(&[0xB8, 1, 0, 0, 0, 0xC3]);
    // LdrInitializeThunk(rcx = CONTEXT inicial): segue para o entry do exe
    // (CONTEXT.Rcx) com a PEB (CONTEXT.Rdx); RtlUserThreadStart não volta.
    image[raw(0x1040)..raw(0x1040) + 19].copy_from_slice(&[0x48, 0x8B, 0x91, 0x88, 0, 0, 0, 0x48, 0x8B, 0x81, 0x80, 0, 0, 0, 0x48, 0x89, 0xD1, 0xFF, 0xE0]);
    image[raw(0x1060)..raw(0x1060) + 2].copy_from_slice(&[0x0F, 0x0B]);
    // Diretório de exports em 0x1100 com nomes ordenados.
    let names = ["LdrInitializeThunk", "NtDisplayString", "NtFake", "NtTerminateProcess", "RtlUserThreadStart", "ZwTerminateProcess"];
    let functions = [0x1040u32, 0x1000, 0x1020, 0x1010, 0x1060, 0x1010];
    let directory = raw(0x1100);
    put32(&mut image, directory + 12, 0x1210);
    put32(&mut image, directory + 16, 1);
    put32(&mut image, directory + 20, 6);
    put32(&mut image, directory + 24, 6);
    put32(&mut image, directory + 28, 0x1140);
    put32(&mut image, directory + 32, 0x1160);
    put32(&mut image, directory + 36, 0x1180);
    let mut text = 0x1190usize;
    for (index, name) in names.iter().enumerate() {
        put32(&mut image, raw(0x1140) + index * 4, functions[index]);
        put32(&mut image, raw(0x1160) + index * 4, text as u32);
        put16(&mut image, raw(0x1180) + index * 2, index as u16);
        image[raw(text)..raw(text) + name.len()].copy_from_slice(name.as_bytes());
        text += name.len() + 1;
    }
    image[raw(0x1210)..raw(0x1210) + 9].copy_from_slice(b"ntdll.dll");
    image
}

/// A ntdll de bring-up gerada pelo build a partir da tabela única de
/// syscalls: DllMain e os stubs canônicos, copiada para o VFS e registrada
/// pelo boot.
fn bundled_bring_up_ntdll(assert: Assert) {
    use crate::drivers::fs::memory_file_system;
    use crate::ntos::ps::user::{loader, syscall_scan};
    let Some(bytes) = crate::hal::bundle::read("apps/ntdll.dll") else {
        assert(false, "bring-up: ntdll.dll no bundle do build de testes");
        return;
    };
    let expected: alloc::collections::BTreeMap<u32, alloc::string::String> = loader::SYSCALLS.iter().map(|&(name, number)| (number, alloc::string::String::from(name))).collect();
    let scanned = syscall_scan::scan_syscall_image(bytes);
    let pe = u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
    let entry = u32::from_le_bytes([bytes[pe + 40], bytes[pe + 41], bytes[pe + 42], bytes[pe + 43]]);
    let characteristics = u16::from_le_bytes([bytes[pe + 22], bytes[pe + 23]]);
    assert(scanned.as_ref().is_ok_and(|map| *map == expected) && expected.len() == 2 && entry == 0x1000 && bytes[0x400..0x406] == [0xB8, 1, 0, 0, 0, 0xC3] && characteristics & 0x2000 != 0, "bring-up: DLL gerada com DllMain e os stubs da tabela unica");
    let copied = memory_file_system::read_bytes("/ntdll.dll").is_some_and(|copy| copy == bytes);
    let registered = state::with(|state| expected.iter().all(|(number, name)| state.name_by_number.get(number) == Some(name)));
    assert(copied && registered, "bring-up: copiada para o VFS e tabela nativa registrada no boot");
}

fn user_system_services(assert: Assert) {
    use crate::hal::amd64::native_call;
    use crate::ntos::ex::{service_table, system_services};
    use crate::ntos::mm::kernel_address;
    use crate::ntos::ps::user::{memory, structures, syscall_scan};
    // Varredura da imagem e recusas de cabeçalho.
    let image = bring_up_ntdll();
    let scanned = syscall_scan::scan_syscall_image(&image);
    let expected: alloc::collections::BTreeMap<u32, alloc::string::String> = [(0x27u32, alloc::string::String::from("NtDisplayString")), (0x2C, alloc::string::String::from("NtTerminateProcess"))].into_iter().collect();
    assert(scanned.as_ref().is_ok_and(|map| *map == expected), "userservices: stubs canonicos da ntdll de bring-up");
    let mut foreign = image.clone();
    foreign[0x44] = 0x4C;
    assert(syscall_scan::scan_syscall_image(&image[..0x30]).is_err() && syscall_scan::scan_syscall_image(&foreign).is_err(), "userservices: imagem truncada e maquina alheia recusadas");
    // Registro da tabela nativa (o boot sem ntdll real a deixa livre).
    // O boot com a ntdll de bring-up do bundle já registra exatamente esta
    // tabela; sem ntdll ela fica livre para o registro do teste.
    let boot_table = state::with(|state| state.name_by_number.clone());
    if boot_table.is_empty() || boot_table == expected {
        let invalid: alloc::collections::BTreeMap<u32, alloc::string::String> = [(5000u32, alloc::string::String::from("NtClose"))].into_iter().collect();
        let unmeasured: alloc::collections::BTreeMap<u32, alloc::string::String> = [(3u32, alloc::string::String::from("NtBogus"))].into_iter().collect();
        assert(system_services::register(&invalid).is_err() && system_services::register(&unmeasured).is_err() && system_services::register(&alloc::collections::BTreeMap::new()).is_err(), "userservices: numeros e convencao nao medida recusados");
        assert(system_services::register(&expected).is_ok() && state::with(|state| state.name_by_number.get(&0x2C).is_some_and(|name| name == "NtTerminateProcess")), "userservices: tabela nativa registrada");
        let entries = crate::hal::amd64::service_table::entries();
        let (gateways, unavailable) = (kernel_address::image_address(entries[5]).unwrap_or(0), kernel_address::image_address(entries[6]).unwrap_or(0));
        assert(service_table::inspect(0x2C, false).is_ok_and(|(address, arguments)| address == gateways + 0x2C * 10 && arguments == 0) && service_table::inspect(0x27, false).is_ok_and(|(address, _)| address == gateways + 0x27 * 10) && service_table::inspect(0x28, false).is_ok_and(|(address, _)| address == unavailable), "userservices: gateways dos provedores e falha comum do slot sem provedor");
        assert(system_services::private_name(0x4000_002C).as_deref() == Some("ZwTerminateProcess") && system_services::private_name(0x4000_0027).as_deref() == Some("ZwDisplayString") && system_services::private_name(0x4000_0028).as_deref() == Some("UnavailableSystemService") && system_services::private_name(5).is_none(), "userservices: nomes privados conforme o PreviousMode");
        let changed: alloc::collections::BTreeMap<u32, alloc::string::String> = [(0x27u32, alloc::string::String::from("NtDisplayString"))].into_iter().collect();
        assert(system_services::register(&expected).is_ok() && system_services::register(&changed).is_err(), "userservices: a ABI viva nao muda");
        // Chamadas nativas: o gateway chega ao export Zw; o slot vazio falha.
        let terminated = native_call::call(gateways + 0x2C * 10, &[0x7FFF_FFF0, 0]);
        assert(terminated as u32 == 0xC000_0008 && native_call::call(unavailable, &[]) == 0xC000_0002, "userservices: gateway em KernelMode e STATUS_NOT_IMPLEMENTED");
    }
    // Cópia de argumentos de pilha.
    let destination = guest::alloc_bytes(19 * 8);
    if let Ok(block) = memory::map_user_region(0x1000) {
        for index in 0..3u64 {
            guest::write64(block + 0x28 + index * 8, 0xA000_0000_0000_0000 + index);
        }
        assert(system_services::copy_arguments(destination, block, 16) == 0xC000_000D && system_services::copy_arguments(destination, block, 0) == 0 && system_services::copy_arguments(destination, block, 3) == 0 && guest::read64(destination + 32) == 0xA000_0000_0000_0000 && guest::read64(destination + 48) == 0xA000_0000_0000_0002 && system_services::copy_arguments(destination, destination, 2) == 0xC000_0005, "userservices: copia de argumentos de pilha e sondagem");
        if let Some(region) = memory::find_region(block) {
            memory::release_private_region(&region);
        }
    }
    guest::free_bytes(destination);
    // Estruturas de processo para o loader da ntdll.
    let process_pointer = guest::alloc_bytes(nt::Eprocess::SIZE);
    guest::write_bytes(process_pointer, &alloc::vec![0u8; nt::Eprocess::SIZE as usize]);
    let (saved_peb, saved_ldr, regions_before) = state::with(|state| (state.current_peb_va, state.current_ldr_va, state.user_regions.len()));
    let built = structures::build_process_structures(&structures::ProcessDescription { process_id: 0x6F0, process_pointer, image_base: 0x1_4000_0000, dos_path: "C:\\teste.exe", detached: true, console_handle: 0x44, stack_base: 0x20_0000, stack_top: 0x30_0000 });
    if let Ok(teb) = built {
        let (peb, ldr) = state::with(|state| (state.current_peb_va, state.current_ldr_va));
        let (teb_view, peb_view, ldr_data) = unsafe { (nt::Teb::at(teb), nt::Peb::at(peb), nt::PebLdrData::at(ldr)) };
        let rupp = peb_view.process_parameters.get();
        let parameters = unsafe { nt::RtlUserProcessParameters::at(rupp) };
        assert(teb_view.nt_tib.self_.get() == teb && teb_view.client_id.unique_thread.get() == 0x6F0 && teb_view.process_environment_block.get() == peb && peb == teb + 0x2000 && unsafe { nt::Eprocess::at(process_pointer) }.peb.get() == peb && teb_view.nt_tib.stack_base.get() == 0x30_0000 && teb_view.nt_tib.stack_limit.get() == 0x20_0000 && teb_view.deallocation_stack.get() == 0x20_0000, "userservices: TEB (com a pilha dada) e PEB publicados");
        assert(peb_view.image_base_address.get() == 0x1_4000_0000 && peb_view.ldr.get() == ldr && peb_view.os_major_version.get() == 10 && peb_view.os_build_number.get() == 26100 && peb_view.number_of_processors.get() == crate::ntos::ke::smp::online_cpu_count() as u32, "userservices: campos do PEB 24H2");
        assert(ldr_data.initialized.get() == 1 && ldr_data.in_load_order_module_list.flink.get() == ldr_data.in_load_order_module_list.address() && ldr_data.in_initialization_order_module_list.blink.get() == ldr_data.in_initialization_order_module_list.address(), "userservices: PEB_LDR_DATA com listas vazias");
        let image_path = parameters.image_path_name.buffer.get();
        assert(parameters.flags.get() == 0 && parameters.console_handle.get() == u64::MAX && parameters.standard_output.get() == 0x44 && parameters.image_path_name.length.get() == 24 && image_path < 0x2000 && guest::read16(rupp + image_path) == b'C' as u16 && parameters.environment.get() > rupp, "userservices: parametros auto-relativos com ambiente absoluto");
        let entry = guest::alloc_bytes(nt::LdrDataTableEntry::SIZE);
        structures::insert_list_tail(ldr, core::mem::offset_of!(nt::PebLdrData, in_load_order_module_list) as u64, entry, core::mem::offset_of!(nt::LdrDataTableEntry, in_load_order_links) as u64);
        assert(ldr_data.in_load_order_module_list.flink.get() == entry && ldr_data.in_load_order_module_list.blink.get() == entry && unsafe { nt::LdrDataTableEntry::at(entry) }.in_load_order_links.flink.get() == ldr_data.in_load_order_module_list.address(), "userservices: insercao no fim da lista LDR");
        structures::write_list_head(ldr_data.in_load_order_module_list.address());
        guest::free_bytes(entry);
    } else {
        assert(false, "userservices: estruturas de processo");
    }
    let added: alloc::vec::Vec<_> = state::with(|state| {
        state.current_peb_va = saved_peb;
        state.current_ldr_va = saved_ldr;
        state.user_regions[regions_before..].to_vec()
    });
    for region in &added {
        memory::release_private_region(region);
    }
    guest::free_bytes(process_pointer);
}

/// Executável mínimo que importa NtTerminateProcess da ntdll pelo nome.
fn importer_image() -> alloc::vec::Vec<u8> {
    let mut image = alloc::vec![0u8; 0x600];
    let put16 = |image: &mut [u8], at: usize, value: u16| image[at..at + 2].copy_from_slice(&value.to_le_bytes());
    let put32 = |image: &mut [u8], at: usize, value: u32| image[at..at + 4].copy_from_slice(&value.to_le_bytes());
    put16(&mut image, 0, 0x5A4D);
    put32(&mut image, 0x3C, 0x40);
    put32(&mut image, 0x40, 0x4550);
    put16(&mut image, 0x44, 0x8664);
    put16(&mut image, 0x46, 1);
    put16(&mut image, 0x54, 240);
    put16(&mut image, 0x56, 0x0022);
    let optional = 0x58;
    put16(&mut image, optional, 0x20B);
    image[optional + 24..optional + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
    put32(&mut image, optional + 32, 0x1000);
    put32(&mut image, optional + 36, 0x200);
    put16(&mut image, optional + 48, 6);
    put32(&mut image, optional + 56, 0x2000);
    put32(&mut image, optional + 60, 0x400);
    put16(&mut image, optional + 68, 3);
    put32(&mut image, optional + 108, 16);
    put32(&mut image, optional + 120, 0x1000);
    put32(&mut image, optional + 124, 40);
    let section = optional + 240;
    image[section..section + 6].copy_from_slice(b".rdata");
    put32(&mut image, section + 8, 0x200);
    put32(&mut image, section + 12, 0x1000);
    put32(&mut image, section + 16, 0x200);
    put32(&mut image, section + 20, 0x400);
    put32(&mut image, section + 36, 0xC000_0040);
    let raw = |rva: usize| rva - 0x1000 + 0x400;
    put32(&mut image, raw(0x1000), 0x1040);
    put32(&mut image, raw(0x1000) + 12, 0x1080);
    put32(&mut image, raw(0x1000) + 16, 0x1060);
    put32(&mut image, raw(0x1040), 0x10A0);
    put32(&mut image, raw(0x1060), 0x10A0);
    image[raw(0x1080)..raw(0x1080) + 9].copy_from_slice(b"ntdll.dll");
    image[raw(0x10A2)..raw(0x10A2) + 18].copy_from_slice(b"NtTerminateProcess");
    image
}

fn user_loader(assert: Assert) {
    use crate::ntos::ps::user::{loader, memory};
    use crate::ntos::mm::pe_loader::{self, LoadOptions};
    if state::with(|state| state.ntdll_exports.is_none()) {
        assert(loader::map_ntdll(bring_up_ntdll(), "bring-up (bundle)").is_ok(), "userloader: ntdll de bring-up mapeada");
    }
    let Some(ntdll) = loader::ntdll_module() else {
        assert(false, "userloader: modulo da ntdll");
        return;
    };
    let terminate = state::with(|state| state.ntdll_exports.as_ref().and_then(|exports| exports.get("NtTerminateProcess").copied())).unwrap_or(0);
    let bring_up = ntdll.exports.exports.contains_key("NtFake");
    assert(terminate != 0 && (!bring_up || (terminate == ntdll.image_base + 0x1010 && guest::read32(terminate) == 0xB8D1_8B4C && guest::read32(terminate + 4) == 0x2C)) && state::with(|state| state.ntdll_image_base == ntdll.image_base && state.name_by_number.get(&0x2C).is_some_and(|name| name == "NtTerminateProcess")), "userloader: exports mapeados e numeros de servico");
    assert(loader::ensure_ntdll().is_ok() && loader::load_dll_by_name("NTDLL.dll", 0, "").is_ok_and(|module| alloc::sync::Arc::ptr_eq(&module, &ntdll)), "userloader: ntdll mapeada uma vez e reaproveitada");
    assert(loader::load_dll_by_name("naoexiste.dll", 0, "").is_err() && loader::load_dll_by_name("kernel32.dll", 129, "").is_err(), "userloader: DLL ausente e cadeia excessiva");
    // Imports: pelo resolvedor do carregador de PE e pelo binding do loader.
    let resolved = pe_loader::load_user(importer_image(), &LoadOptions { notify_image: false, ..LoadOptions::default() });
    assert(resolved.as_ref().is_ok_and(|image| unsafe { nt::ImageThunkData64::at(image.image_base + 0x1060) }.u1.function.get() == terminate), "userloader: resolvedor de imports da ntdll");
    let unbound = pe_loader::load_user(importer_image(), &LoadOptions { skip_imports: true, skip_relocations: true, notify_image: false, ..LoadOptions::default() });
    let bound = unbound.as_ref().is_ok_and(|image| { let slot = unsafe { nt::ImageThunkData64::at(image.image_base + 0x1060) }; slot.u1.function.get() == 0x10A0 && loader::bind_imports(image.image_base, 0).is_ok() && slot.u1.function.get() == terminate });
    assert(bound, "userloader: binding da IAT contra os exports reais");
    for image in [resolved, unbound].into_iter().flatten() {
        let mut image = image;
        let _ = image.release();
    }
    // Entradas LDR numa PEB_LDR_DATA própria.
    let (saved_ldr, saved_next, saved_end, regions_before) = state::with(|state| (state.current_ldr_va, state.next_ldr_string_va, state.ldr_string_region_end, state.user_regions.len()));
    if let Ok(ldr) = memory::map_user_region(0x1000) {
        let ldr_data = unsafe { nt::PebLdrData::at(ldr) };
        for head in [&ldr_data.in_load_order_module_list, &ldr_data.in_memory_order_module_list, &ldr_data.in_initialization_order_module_list] {
            crate::ntos::ps::user::structures::write_list_head(head.address());
        }
        state::with(|state| {
            state.current_ldr_va = ldr;
            state.next_ldr_string_va = 0;
        });
        let entry = loader::create_ldr_entry(&ntdll).unwrap_or(0);
        let exe = loader::Module { name: alloc::string::String::from("teste.exe"), full_name: alloc::string::String::from("C:\\teste.exe"), image_base: 0x1_4000_0000, size_of_image: 0x2000, entry_point: 0x1_4000_1000, exports: Default::default(), is_exe: true, notification_source: None };
        let second = loader::create_ldr_entry(&exe).unwrap_or(0);
        let (dll, exe_entry) = unsafe { (nt::LdrDataTableEntry::at(entry), nt::LdrDataTableEntry::at(second)) };
        let full = dll.full_dll_name.buffer.get();
        assert(entry != 0 && dll.dll_base.get() == ntdll.image_base && dll.entry_point.get() == ntdll.entry_point && dll.flags.get() == 0x4006 && dll.obsolete_load_count.get() == 0xFFFF && dll.full_dll_name.length.get() == 58 && guest::read16(full) == b'C' as u16, "userloader: entrada LDR da DLL com nomes e flags");
        assert(second != 0 && exe_entry.entry_point.get() == 0 && exe_entry.flags.get() == 0x4002 && ldr_data.in_load_order_module_list.flink.get() == entry && ldr_data.in_load_order_module_list.blink.get() == second && dll.in_load_order_links.flink.get() == second && ldr_data.in_initialization_order_module_list.flink.get() == dll.in_initialization_order_links.address(), "userloader: exe sem EntryPoint e listas na ordem de carga");
    }
    let added: alloc::vec::Vec<_> = state::with(|state| {
        state.current_ldr_va = saved_ldr;
        state.next_ldr_string_va = saved_next;
        state.ldr_string_region_end = saved_end;
        state.user_regions[regions_before..].to_vec()
    });
    for region in &added {
        memory::release_private_region(region);
    }
}

fn user_nls(assert: Assert) {
    use crate::ntos::ps::user::file_io::{self, OpenRequest};
    use crate::ntos::ps::user::memory;
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "usernls: memoria de usuario");
        return;
    };
    let (out, size, iosb, buffer, rsp) = (block, block + 0x10, block + 0x20, block + 0x100, block + 0x1000);
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map(|handler| handler(a1, a2, a3, a4, rsp).unwrap_or(1)).unwrap_or(1);
    assert(call("NtQueryDefaultLocale", 0, out, 0, 0) == 0 && guest::read32(out) == 0x409 && call("NtQueryDefaultUILanguage", out, 0, 0, 0) == 0 && guest::read16(out) == 0x409 && call("NtQueryInstallUILanguage", 0x10, 0, 0, 0) == 0xC000_0005, "usernls: locale e idioma padrao");
    guest::write64(rsp + 0x28, size);
    assert(call("NtGetNlsSectionPtr", 13, 0, 0, out) == 0xC000_000D && call("NtGetNlsSectionPtr", 12, 3, 0, out) == 0xC000_000D && call("NtGetNlsSectionPtr", 11, 0x10000, 0, out) == 0xC000_000D && call("NtGetNlsSectionPtr", 9, 0, 1, out) == 0xC000_00BB, "usernls: tipo, dado e contexto invalidos");
    assert(call("NtGetNlsSectionPtr", 11, 4243, 0, out) == 0xC000_0034 && call("NtGetNlsSectionPtr", 11, 4242, 0, 0x10) == 0xC000_0005, "usernls: tabela ausente e saida invalida");
    assert(call("NtInitializeNlsFiles", out, 0x10, 0, 0) == 0xC000_0005, "usernls: NtInitializeNlsFiles sonda as saidas");
    // Tabela do volume mapeada como seção permanente, uma vista por processo.
    guest::write64(out, 0);
    let created = file_io::open(out, "\\??\\D:\\C_4242.NLS", iosb, 2, &OpenRequest { access: 0x4010_0000, share: 0, options: 0x20, ..OpenRequest::default() }).unwrap_or(1);
    let writer = guest::read64(out);
    guest::write_bytes(buffer, b"NLS-OpenNT");
    guest::write64(rsp + 0x28, iosb);
    guest::write64(rsp + 0x30, buffer);
    guest::write32(rsp + 0x38, 10);
    guest::write64(rsp + 0x40, 0);
    let written = call("NtWriteFile", writer, 0, 0, 0);
    let _ = state::close_user_handle(writer, true, false);
    guest::write64(rsp + 0x28, size);
    let mapped = call("NtGetNlsSectionPtr", 11, 4242, 0, out);
    let base = guest::read64(out);
    let table_ok = created == 0 && written == 0 && mapped == 0 && base != 0 && guest::read32(size) >= 10 && guest::read_bytes(base, 10) == b"NLS-OpenNT";
    if !table_ok {
        crate::debug_print!("[usernls] created={:#x} written={:#x} mapped={:#x} base={:#x} size={:#x}", created, written, mapped, base, guest::read32(size));
    }
    assert(table_ok, "usernls: tabela do volume mapeada com o conteudo");
    assert(call("NtGetNlsSectionPtr", 11, 4242, 0, out) == 0 && guest::read64(out) == base && state::with(|state| state.user_regions.iter().filter(|region| region.section().is_some() && region.base() == base).count()) == 1, "usernls: a vista existente do processo e reaproveitada");
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn user_syscalls_core(assert: Assert) {
    use crate::ntos::ps::user::memory;
    let Ok(block) = memory::map_user_region(0x3000) else {
        assert(false, "usercore: memoria de usuario");
        return;
    };
    let (out, info, string, buffer, attributes, rsp) = (block, block + 0x20, block + 0x80, block + 0x400, block + 0x900, block + 0x2000);
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map(|handler| handler(a1, a2, a3, a4, rsp).unwrap_or(1)).unwrap_or(1);
    guest::write64(rsp + 0x28, 0);
    let (processor, counter, frequency) = unsafe { (nt::ProcessorNumber::at(out), nt::LargeInteger::at(out), nt::LargeInteger::at(out + 8)) };
    // Processador, display, contador e término.
    processor.group.set(0xFFFF);
    processor.number.set(0xFF);
    processor.reserved.set(0xFF);
    assert(call("NtGetCurrentProcessorNumber", 0, 0, 0, 0) == 0 && call("NtGetCurrentProcessorNumberEx", out, 0, 0, 0) == 0 && processor.group.get() == 0 && processor.number.get() == 0 && processor.reserved.get() == 0 && call("NtGetCurrentProcessorNumberEx", 0x10, 0, 0, 0) == 0xC000_0005, "usercore: processador corrente");
    state::write_user_wide(string + 0x10, "OpenNT usuario\r\n");
    state::write_unicode_string(string, string + 0x10, "OpenNT usuario\r\n");
    assert(call("NtDisplayString", string, 0, 0, 0) == 0, "usercore: NtDisplayString");
    assert(call("NtQueryPerformanceCounter", out, out + 8, 0, 0) == 0 && counter.quad_part.get() != 0 && frequency.quad_part.get() as u64 == crate::ntos::ke::clock::tsc_frequency_hz() && call("NtQueryPerformanceCounter", 0, 0, 0, 0) == 0xC000_0005, "usercore: contador e frequencia");
    let exit_cell = guest::read32(state::EXIT_CODE_CELL);
    assert(call("NtTerminateProcess", u64::MAX, 0x42, 0, 0) == state::TERMINATE_MAGIC && guest::read32(state::EXIT_CODE_CELL) == 0x42, "usercore: NtTerminateProcess publica o codigo para a HAL");
    guest::write32(state::EXIT_CODE_CELL, exit_cell);
    // Informações do sistema.
    assert(call("NtQuerySystemInformation", 0, buffer, 0x40, info) == 0 && { let system = unsafe { nt::SystemBasicInformation::at(buffer) }; system.page_size.get() == 0x1000 && system.allocation_granularity.get() == 0x10000 && system.minimum_user_mode_address.get() == 0x1_0000 && system.maximum_user_mode_address.get() == 0x7FFF_FFFE_FFFF } && guest::read32(info) == 0x40, "usercore: SYSTEM_BASIC_INFORMATION (usuario de 64 KB a MmHighestUserAddress)");
    assert(call("NtQuerySystemInformation", 0, buffer, 0x20, info) == 0xC000_0004 && guest::read32(info) == 0x40 && call("NtQuerySystemInformation", 50, buffer, 8, 0) == 0 && guest::read64(buffer) == 0xFFFF_8000_0000_0000 && call("NtQuerySystemInformation", 55, buffer, 24, 0) == 0 && { let numa = unsafe { nt::SystemNumaInformation::at(buffer) }; numa.highest_node_number.get() == 0 && numa.reserved.get() == 0 }, "usercore: tamanho curto, inicio do sistema e NUMA");
    guest::write64(buffer, u64::MAX);
    assert(call("NtQuerySystemInformation", 192, buffer, 8, info) == 0 && guest::read64(buffer) == 0 && call("NtQuerySystemInformation", 80, buffer, 22 * 8, 0) == 0 && unsafe { nt::extra_test_p7::SystemMemoryListInformation::at(buffer) }.free_page_count.get() == crate::ntos::mm::pfn::free_count() && call("NtQuerySystemInformation", 999, buffer, 8, 0) == 0xC000_0003, "usercore: recurso ausente zerado, lista de memoria e classe invalida");
    guest::write32(rsp + 0x28, 80);
    guest::write64(rsp + 0x30, info);
    guest::write32(string, 4);
    let topology = call("NtQuerySystemInformationEx", 107, string, 4, buffer);
    assert(topology == 0 && { let relation = unsafe { nt::SystemLogicalProcessorInformationEx::at(buffer) }; relation.relationship.get() == 4 && relation.group.active_group_count.get() == 1 && relation.group.group_info[0].active_processor_count.get() == crate::ntos::ke::smp::online_cpu_count() as u8 } && call("NtQuerySystemInformationEx", 107, string, 8, buffer) == 0xC000_000D, "usercore: topologia do grupo 0 e entrada invalida");
    guest::write32(string, 9);
    assert(call("NtQuerySystemInformationEx", 107, string, 4, buffer) == 0xC000_0003, "usercore: relacao de topologia invalida");
    // Erro fatal e informações do processo.
    guest::write64(rsp + 0x30, info);
    guest::write64(string, 0x1234);
    assert(call("NtRaiseHardError", 0xC000_0135, 5, 0, string) == 0xC000_000D && call("NtRaiseHardError", 0xC000_0135, 1, 0, string) == 0 && guest::read32(info) == 2, "usercore: HARDERROR responde ResponseAbort");
    guest::write64(rsp + 0x28, info);
    let (peb, process_id) = state::with(|state| (state.current_peb_va, state.current_process_id));
    assert(call("NtQueryInformationProcess", u64::MAX, 0, buffer, 0x30) == 0 && { let basic = unsafe { nt::ProcessBasicInformation::at(buffer) }; basic.exit_status.get() == 0x103 && basic.peb_base_address.get() == peb && basic.unique_process_id.get() == process_id } && guest::read32(info) == 0x30, "usercore: ProcessBasicInformation");
    assert(call("NtQueryInformationProcess", u64::MAX, 0, buffer, 0x40) == 0 && { let extended = unsafe { nt::ProcessExtendedBasicInformation::at(buffer) }; extended.size.get() == 0x40 && extended.basic_info.exit_status.get() == 0x103 } && call("NtQueryInformationProcess", u64::MAX, 0, buffer, 0x20) == 0xC000_0004 && guest::read32(info) == 0x30, "usercore: informacao basica estendida e tamanho invalido");
    let cookie = (call("NtQueryInformationProcess", u64::MAX, 36, buffer, 4) == 0).then(|| guest::read32(buffer)).unwrap_or(0);
    assert(cookie != 0 && call("NtQueryInformationProcess", u64::MAX, 36, buffer, 4) == 0 && guest::read32(buffer) == cookie && call("NtQueryInformationProcess", u64::MAX, 31, buffer, 4) == 0 && guest::read32(buffer) == 1, "usercore: cookie estavel e sem depurador");
    assert(call("NtQueryInformationProcess", u64::MAX, 27, buffer, 0x100) == 0 && { let image_name = unsafe { nt::UnicodeString::at(buffer) }; image_name.length.get() > 0 && image_name.buffer.get() == buffer + nt::UnicodeString::SIZE } && call("NtQueryInformationProcess", u64::MAX, 99, buffer, 8) == 0xC000_0003 && call("NtSetInformationProcess", u64::MAX, 99, buffer, 8) == 0xC000_0003, "usercore: nome da imagem e classes invalidas");
    // Esperas reais sobre eventos.
    guest::write64(rsp + 0x28, 0);
    let _ = call("NtCreateEvent", out, 0x1F_0003, 0, 1);
    let first = guest::read64(out);
    guest::write64(rsp + 0x28, 1);
    let _ = call("NtCreateEvent", out, 0x1F_0003, 0, 0);
    let second = guest::read64(out);
    unsafe { nt::LargeInteger::at(string) }.quad_part.set(0);
    assert(call("NtWaitForSingleObject", first, 0, string, 0) == 0x102 && call("NtWaitForSingleObject", second, 0, string, 0) == 0 && call("NtWaitForSingleObject", 0x7FF0, 0, 0, 0) == 0xC000_0008, "usercore: espera unica com prazo zero e evento sinalizado");
    let _ = call("NtSetEvent", first, 0, 0, 0);
    let _ = call("NtResetEvent", second, 0, 0, 0);
    guest::write64(buffer, second);
    guest::write64(buffer + 8, first);
    guest::write64(rsp + 0x28, string);
    assert(call("NtWaitForMultipleObjects", 2, buffer, 1, 0) == 1 && call("NtWaitForMultipleObjects", 0, buffer, 1, 0) == 0xC000_000D, "usercore: espera multipla devolve o indice sinalizado");
    guest::write64(buffer + 8, second);
    assert(call("NtWaitForMultipleObjects", 2, buffer, 1, 0) == 0xC000_000D, "usercore: handles repetidos recusados");
    // Segurança do objeto e namespace.
    guest::write64(rsp + 0x28, info);
    assert(call("NtQuerySecurityObject", first, 4, buffer, 0x200) == 0 && guest::read32(info) > 0 && call("NtQuerySecurityObject", first, 4, buffer, 1) == 0xC000_0023 && call("NtQuerySecurityObject", first, 0x20, buffer, 0x200) == 0xC000_000D, "usercore: descritor do evento e recusas");
    state::write_user_wide(attributes + 0x80, "\\");
    state::write_unicode_string(attributes + 0x40, attributes + 0x80, "\\");
    set_object_attributes(unsafe { nt::ObjectAttributes::at(attributes) }, nt::ObjectAttributes::SIZE as u32, 0, attributes + 0x40, 0x40);
    let opened = call("NtOpenDirectoryObject", out, 1, attributes, 0);
    let directory = guest::read64(out);
    assert(opened == 0 && call("NtCreatePartition", 0, 0, 0, 0) == 0xC000_0008, "usercore: diretorio raiz e particao inexistente");
    // NtContinue sobre o frame do syscall.
    assert(call("NtContinue", 0, 0, 0, 0) == 0xC000_0005, "usercore: NtContinue sem contexto");
    let context = block + 0x1000;
    guest::write_bytes(context, &[0u8; nt::Context::SIZE as usize]);
    let context_record = unsafe { nt::Context::at(context) };
    context_record.context_flags.set(0x10_0001);
    assert(call("NtContinue", context, 0, 0, 0) == 0xC000_000D, "usercore: NtContinue sem CONTROL|INTEGER");
    let frame_block = guest::alloc_bytes(0x1000);
    let saved = state::with(|state| core::mem::replace(&mut state.syscall_stack_top, frame_block + 0x1000));
    let saved_rsp = guest::read64(state::USER_RSP_CELL_ADDR);
    context_record.context_flags.set(0x10_0003);
    context_record.seg_cs.set(0x33);
    context_record.seg_ss.set(0x2B);
    context_record.e_flags.set(0xFFFF_FFFF);
    context_record.rax.set(0x1122_3344_5566_7788);
    context_record.rsp.set(0x7FF0_0000);
    context_record.rip.set(0x1_4000_1000);
    let continued = call("NtContinue", context, 0, 0, 0);
    let frame = frame_block + 0x1000 - 0x78;
    assert(continued == 0x5566_7788 && guest::read64(frame) == 0x1122_3344_5566_7788 && guest::read64(frame + 8) == 0x1_4000_1000 && guest::read64(frame + 0x40) == 0x21_0DD5 | 0x200 && guest::read64(state::USER_RSP_CELL_ADDR) == 0x7FF0_0000, "usercore: NtContinue reescreve o frame com RFLAGS filtrado");
    guest::write64(state::USER_RSP_CELL_ADDR, saved_rsp);
    state::with(|state| state.syscall_stack_top = saved);
    guest::free_bytes(frame_block);
    for handle in [first, second, directory] {
        let _ = call("NtClose", handle, 0, 0, 0);
    }
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn user_index(assert: Assert) {
    use crate::hal::amd64::native_call;
    use crate::ntos::mm::kernel_address;
    use crate::ntos::ps::process;
    use crate::ntos::ps::user::{index, memory};
    assert(crate::hal::amd64::usermode::ready() && state::with(|state| state.syscall_stack_top != 0) && crate::ntos::mm::paging::translate(state::KUSER_SHARED_DATA_USER_VA) != 0, "userindex: anel 3 armado no boot com a KUSER_SHARED_DATA de usuario");
    let Ok(block) = memory::map_user_region(0x1000) else {
        assert(false, "userindex: memoria de usuario");
        return;
    };
    let string = block;
    state::write_user_wide(string + 0x10, "ponte de servico\r\n");
    state::write_unicode_string(string, string + 0x10, "ponte de servico\r\n");
    let exit_cell = guest::read32(state::EXIT_CODE_CELL);
    assert(index::handle_service(Some("NtNaoExisteOpenNt"), [0; 4], 0, 0, 0).ok() == Some(0xC000_0002) && index::handle_service(None, [0; 4], 0, 0, 0x99).ok() == Some(0xC000_0002), "userindex: servico sem implementacao");
    assert(index::invoke_service("NtDisplayString", [string, 0, 0, 0], 0x1_4000_1000, block + 0x800).ok() == Some(0) && state::with(|state| state.seen_syscalls.contains("NtDisplayString")), "userindex: invokeService chega ao handler por nome");
    if state::with(|state| state.name_by_number.get(&0x2C).is_some()) {
        assert(index::handle(0x2C, [u64::MAX, 0x31, 0, 0], 0, block + 0x800).ok() == Some(state::TERMINATE_MAGIC) && guest::read32(state::EXIT_CODE_CELL) == 0x31 && index::handle(0x28, [0; 4], 0, 0).ok() == Some(0xC000_0002), "userindex: entrada por numero de servico");
        // Caminho completo em UserMode: gateway, trampolim, despacho e ponte.
        let gateways = kernel_address::image_address(crate::hal::amd64::service_table::entries()[5]).unwrap_or(0);
        let previous = process::get_current_thread();
        if let Ok(thread) = process::create_kernel_thread(process::get_current_process(), 0x7F00, true, 1, None) {
            process::set_current_thread(thread);
            let displayed = native_call::call(gateways + 0x27 * 10, &[string]);
            let terminated = native_call::call(gateways + 0x2C * 10, &[u64::MAX, 0x55]);
            let restored = state::with(|state| state.service_raw_arguments == 0 && state.service_stack.is_none());
            process::set_current_thread(previous);
            let _ = process::release_thread(thread);
            assert(displayed == 0 && terminated as u32 == state::TERMINATE_MAGIC && guest::read32(state::EXIT_CODE_CELL) == 0x55 && restored, "userindex: syscall de UserMode pelo descritor ate o handler, com o contexto restaurado");
        } else {
            assert(false, "userindex: thread de UserMode");
        }
    }
    guest::write32(state::EXIT_CODE_CELL, exit_cell);
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn user_ring3(assert: Assert) {
    use crate::hal::amd64::usermode;
    use crate::ntos::ps::process;
    use crate::ntos::ps::user::{memory, threads};
    if !usermode::ready() || state::with(|state| state.name_by_number.get(&0x27).is_none()) {
        assert(false, "userring3: anel 3 armado e tabela de servicos registrada");
        return;
    }
    // Página de código executável e pilha de usuário.
    let scratch = guest::alloc_bytes(16);
    let allocate = |size: u64, protect: u32| {
        guest::write64(scratch, 0);
        guest::write64(scratch + 8, size);
        let status = memory::do_user_allocate(scratch, scratch + 8, 0x3000, protect, 0x10000, 0x7FFF_FFFF_0000, 0x10000).unwrap_or(1);
        if status == 0 { guest::read64(scratch) } else { 0 }
    };
    let code = allocate(0x1000, 0x40);
    let stack = allocate(0x4000, 4);
    if code == 0 || stack == 0 {
        assert(false, "userring3: memoria de usuario executavel");
        return;
    }
    let stack_top = stack + 0x4000 - 0x28;
    let string = stack;
    state::write_user_wide(string + 0x10, "ola do anel 3\r\n");
    state::write_unicode_string(string, string + 0x10, "ola do anel 3\r\n");
    // A syscall marca o PreviousMode na KTHREAD corrente: uma thread própria.
    let previous = process::get_current_thread();
    let Ok(thread) = process::create_kernel_thread(process::get_current_process(), 0x7F10, true, 1, None) else {
        assert(false, "userring3: thread de usuario");
        return;
    };
    process::set_current_thread(thread);
    let exit_cell = guest::read32(state::EXIT_CODE_CELL);
    let terminate: &[u8] = &[0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0x49, 0x89, 0xCA, 0xB8, 0x2C, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xEB, 0xFE];
    // 1. NtTerminateProcess(-1, 0x42) direto do anel 3.
    let mut program: alloc::vec::Vec<u8> = alloc::vec![0xBA, 0x42, 0x00, 0x00, 0x00];
    program.extend_from_slice(terminate);
    guest::write_bytes(code, &program);
    let exited = usermode::exec_user_mode(code, stack_top, 0, 0, 0, 0);
    assert(exited == 0x42, "userring3: NtTerminateProcess pela instrucao syscall devolve o codigo de saida");
    // 2. NtDisplayString volta ao anel 3 (iretq) e o status vira o código.
    let mut program: alloc::vec::Vec<u8> = alloc::vec![0x48, 0xB9];
    program.extend_from_slice(&string.to_le_bytes());
    program.extend_from_slice(&[0x49, 0x89, 0xCA, 0xB8, 0x27, 0x00, 0x00, 0x00, 0x0F, 0x05, 0x89, 0xC2, 0x83, 0xC2, 0x30]);
    program.extend_from_slice(terminate);
    guest::write_bytes(code, &program);
    let displayed = usermode::exec_user_mode(code, stack_top, 0, 0, 0, 0);
    assert(displayed == 0x30, "userring3: NtDisplayString retorna ao anel 3 com o status em RAX");
    // 2b. Serviço gráfico (0x1000) sem o win32k: a conversão em thread GUI
    // falha e a syscall devolve STATUS_INVALID_SYSTEM_SERVICE.
    let mut program: alloc::vec::Vec<u8> = alloc::vec![0xB8, 0x00, 0x10, 0x00, 0x00, 0x49, 0x89, 0xCA, 0x0F, 0x05, 0x89, 0xC2];
    program.extend_from_slice(terminate);
    guest::write_bytes(code, &program);
    let graphics = usermode::exec_user_mode(code, stack_top, 0, 0, 0, 0);
    assert(graphics == 0xC000_001C && unsafe { nt::Ethread::at(thread) }.tcb.gui_thread() == 0, "userring3: syscall da tabela 1 sem o win32k devolve STATUS_INVALID_SYSTEM_SERVICE e a thread segue nao-GUI");
    // 3. ud2: o processo morre com STATUS_ILLEGAL_INSTRUCTION e o kernel segue.
    guest::write_bytes(code, &[0x0F, 0x0B]);
    let faulted = usermode::exec_user_mode(code, stack_top, 0, 0, 0, 0);
    assert(faulted == 0xC000_001D && guest::read32(usermode::FAULT_VECTOR_CELL) == 6 && guest::read64(usermode::FAULT_RIP_CELL) == code, "userring3: excecao de usuario termina o processo com o NTSTATUS");
    // 4. Um intervalo de escalonamento termina na syscall com o CONTEXT salvo.
    let mut program: alloc::vec::Vec<u8> = alloc::vec![0x48, 0xB9];
    program.extend_from_slice(&string.to_le_bytes());
    program.extend_from_slice(&[0x49, 0x89, 0xCA, 0xB8, 0x27, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xEB, 0xFE]);
    guest::write_bytes(code, &program);
    let raw_context = guest::alloc_bytes(threads::CONTEXT_SIZE + 16);
    let context = (raw_context + 15) & !15;
    threads::initialize_context(context, code, stack_top, 0, 0);
    let mut kind = 2;
    let mut rounds = 0;
    while kind == 2 && rounds < 64 {
        let _ = usermode::exec_user_context(context, 0);
        kind = guest::read32(usermode::USER_EXIT_KIND);
        rounds += 1;
    }
    let after_syscall = code + 10 + 10;
    assert(kind == 1 && { let saved = unsafe { nt::Context::at(context) }; saved.rax.get() == 0 && saved.rip.get() == after_syscall && saved.rsp.get() == stack_top }, "userring3: intervalo encerrado pela syscall com RAX, RIP e RSP no CONTEXT");
    process::set_current_thread(previous);
    let _ = process::release_thread(thread);
    guest::write32(state::EXIT_CODE_CELL, exit_cell);
    guest::free_bytes(raw_context);
    guest::free_bytes(scratch);
    for base in [code, stack] {
        if let Some(region) = memory::find_region(base) {
            memory::release_private_region(&region);
        }
    }
}

/// A metade de usuário do Windows 10 19041 x64: memória de usuário abaixo de
/// 4 GB lida e escrita do anel 3, base abaixo de 64 KB recusada como no NT,
/// a primeira faixa livre de 64 KB numa alocação sem base (sem cursor: uma
/// faixa liberada volta a ser a escolhida), MEM_TOP_DOWN a partir do topo e
/// os limites de usuário exportados.
fn user_address_floor(assert: Assert) {
    use crate::hal::amd64::usermode;
    use crate::ntos::mm::{kernel_data, memory_map as map, paging};
    use crate::ntos::mm::pe_loader::ResolvedImport;
    use crate::ntos::ps::process;
    use crate::ntos::ps::user::memory;
    // (d) MmUserProbeAddress e MmHighestUserAddress do 19041, pela célula e
    // pelo export que um driver importa.
    let exported = |name: &str| match crate::ntos::init::exports::lookup("ntoskrnl.exe", name) {
        Some(ResolvedImport::Address { address, .. }) => guest::read64(address),
        _ => 0,
    };
    assert(kernel_data::read("MmUserProbeAddress") == 0x7FFF_FFFF_0000 && kernel_data::read("MmHighestUserAddress") == 0x7FFF_FFFE_FFFF && exported("MmUserProbeAddress") == 0x7FFF_FFFF_0000 && exported("MmHighestUserAddress") == 0x7FFF_FFFE_FFFF, "userfloor: MmUserProbeAddress e MmHighestUserAddress com os valores do 19041");
    assert(map::LOWEST_USER_ADDRESS == 0x1_0000 && map::USER_ADDRESS_LIMIT == 0x7FFF_FFFF_0000 && map::HIGHEST_VAD_ADDRESS == 0x7FFF_FFFD_FFFF, "userfloor: constantes internas iguais aos exports");
    let block = guest::alloc_bytes(0x100);
    let (base_pointer, size_pointer, rsp) = (block, block + 8, block + 0x40);
    let allocate = |base: u64, size: u64, kind: u32, protect: u32| {
        guest::write64(base_pointer, base);
        guest::write64(size_pointer, size);
        guest::write32(rsp + 0x28, kind);
        guest::write32(rsp + 0x30, protect);
        memory::nt_allocate_virtual_memory(u64::MAX, base_pointer, 0, size_pointer, rsp).unwrap_or(1)
    };
    let release = |base: u64| {
        guest::write64(base_pointer, base);
        guest::write64(size_pointer, 0);
        memory::nt_free_virtual_memory(u64::MAX, base_pointer, size_pointer, 0x8000, 0).unwrap_or(1)
    };
    // Uma faixa está livre se nenhuma região, vista ou PTE a ocupa.
    let free = |base: u64, size: u64| {
        let occupied = memory::occupied();
        !occupied.iter().any(|region| base < region.base + region.size && base + size > region.base) && paging::find_mapping(base, size).is_none()
    };
    // Varredura independente do alocador, de 64 KB em 64 KB.
    let lowest_free = |size: u64| (map::LOWEST_USER_ADDRESS..0x1_0000_0000).step_by(0x10000).find(|&base| free(base, size)).unwrap_or(0);
    let highest_free = |size: u64| {
        let top = (map::HIGHEST_VAD_ADDRESS + 1 - size) & !0xFFFF;
        (0..0x10000u64).map(|step| top - step * 0x10000).find(|&base| free(base, size)).unwrap_or(0)
    };

    // (b) Base abaixo de MM_LOWEST_USER_ADDRESS: STATUS_CONFLICTING_ADDRESSES
    // (a reserva desce a 0, como no MiIsVaRangeAvailable), sem nada mapeado.
    assert(allocate(0x1000, 0x1000, 0x3000, 4) == 0xC000_0018 && allocate(0xF000, 0x1000, 0x2000, 4) == 0xC000_0018 && allocate(0x8000, 0x1_0000, 0x3000, 4) == 0xC000_0018 && allocate(0xFFFF, 1, 0x1000, 4) == 0xC000_0018, "userfloor: base abaixo de 64 KB recusada com STATUS_CONFLICTING_ADDRESSES");
    assert(paging::find_mapping(0, map::LOWEST_USER_ADDRESS).is_none() && memory::find_region(0x1000).is_none(), "userfloor: os primeiros 64 KB seguem sem mapeamento");
    assert(allocate(map::HIGHEST_VAD_ADDRESS + 1, 0x1000, 0x3000, 4) == 0xC000_0018 && allocate(0x7FFF_FFFF_0000, 0x1000, 0x3000, 4) == 0xC000_000D, "userfloor: base acima do ultimo VAD e alem de MmHighestUserAddress");

    // (c) Sem base: a primeira faixa livre alinhada a 64 KB a partir do piso.
    let expected = lowest_free(0x3000);
    let first_status = allocate(0, 0x3000, 0x3000, 4);
    let first = guest::read64(base_pointer);
    assert(first_status == 0 && expected != 0 && first == expected && first < 0x1_0000_0000 && guest::read64(size_pointer) == 0x3000, "userfloor: sem base, a faixa livre mais baixa de 64 KB a partir do piso");
    let second_expected = lowest_free(0x1000);
    let second_status = allocate(0, 0x1000, 0x3000, 4);
    let second = guest::read64(base_pointer);
    assert(second_status == 0 && second == second_expected && second != first, "userfloor: a seguinte vai para a proxima faixa livre");
    let released = release(first);
    let again_status = allocate(0, 0x3000, 0x3000, 4);
    let again = guest::read64(base_pointer);
    assert(released == 0 && again_status == 0 && again == first, "userfloor: faixa liberada volta a ser a primeira escolhida (sem cursor)");
    // MEM_RESERVE com base: a base desce à granularidade de 64 KB.
    let reserve_at = lowest_free(0x1_0000);
    let rounded_status = allocate(reserve_at + 0x3000, 0x1000, 0x2000, 4);
    assert(rounded_status == 0 && guest::read64(base_pointer) == reserve_at && guest::read64(size_pointer) == 0x4000, "userfloor: reserva com base desce a 64 KB e cobre ate o fim pedido");
    // MEM_TOP_DOWN: a primeira faixa livre a partir de MM_HIGHEST_VAD_ADDRESS.
    let top_expected = highest_free(0x1000);
    let top_status = allocate(0, 0x1000, 0x10_3000, 4);
    let top = guest::read64(base_pointer);
    assert(top_status == 0 && top == top_expected && top > 0x7FFF_0000_0000 && top + 0x1000 <= map::HIGHEST_VAD_ADDRESS + 1, "userfloor: MEM_TOP_DOWN a partir do topo das alocacoes");

    // (a) Base fixa abaixo de 4 GB, lida e escrita do anel 3.
    let target = (0x5000_0000u64..0x7FF0_0000).step_by(0x10000).find(|&base| free(base, 0x1_0000)).unwrap_or(0);
    let fixed_status = allocate(target, 0x1_0000, 0x3000, 4);
    let mapped = fixed_status == 0 && target != 0 && guest::read64(base_pointer) == target && paging::access_flags(target) & (paging::PAGE_PRESENT | paging::PAGE_USER | paging::PAGE_RW) == paging::PAGE_PRESENT | paging::PAGE_USER | paging::PAGE_RW;
    assert(mapped, "userfloor: base fixa abaixo de 4 GB mapeada com paginas de usuario");
    let code_status = allocate(0, 0x1000, 0x3000, 0x40);
    let code = guest::read64(base_pointer);
    let stack_status = allocate(0, 0x4000, 0x3000, 4);
    let stack = guest::read64(base_pointer);
    let armed = usermode::ready() && state::with(|state| state.name_by_number.get(&0x2C).is_some_and(|name| name == "NtTerminateProcess"));
    if mapped && armed && code_status == 0 && stack_status == 0 {
        guest::write32(target + 8, 0x1234);
        // mov rax, target; mov edx, [rax+8]; add edx, 0x1111; mov [rax], edx;
        // NtTerminateProcess(-1, edx).
        let mut program: alloc::vec::Vec<u8> = alloc::vec![0x48, 0xB8];
        program.extend_from_slice(&target.to_le_bytes());
        program.extend_from_slice(&[0x8B, 0x50, 0x08, 0x81, 0xC2, 0x11, 0x11, 0x00, 0x00, 0x89, 0x10]);
        program.extend_from_slice(&[0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0x49, 0x89, 0xCA, 0xB8, 0x2C, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xEB, 0xFE]);
        guest::write_bytes(code, &program);
        let previous = process::get_current_thread();
        if let Ok(thread) = process::create_kernel_thread(process::get_current_process(), 0x7F14, true, 1, None) {
            process::set_current_thread(thread);
            let exit_cell = guest::read32(state::EXIT_CODE_CELL);
            let exited = usermode::exec_user_mode(code, stack + 0x4000 - 0x28, 0, 0, 0, 0);
            guest::write32(state::EXIT_CODE_CELL, exit_cell);
            process::set_current_thread(previous);
            let _ = process::release_thread(thread);
            assert(exited == 0x2345 && guest::read32(target) == 0x2345 && code < 0x1_0000_0000 && stack < 0x1_0000_0000, "userfloor: o anel 3 le e escreve a memoria abaixo de 4 GB, com codigo e pilha tambem abaixo de 4 GB");
        } else {
            assert(false, "userfloor: thread de usuario");
        }
    } else {
        assert(false, "userfloor: anel 3 armado com codigo e pilha de usuario");
    }
    for base in [first, second, reserve_at, top, target, code, stack] {
        if memory::find_region(base).is_some() {
            release(base);
        }
    }
    assert(memory::find_region(target).is_none() && paging::translate(target) == 0, "userfloor: regioes liberadas");
    guest::free_bytes(block);
}

/// PE x64 mínimo de uma seção (código ou dados) com o conteúdo dado em 0x1000.
fn single_section_image(image_base: u64, characteristics: u16, section_name: &[u8], section_flags: u32, entry: u32, content: &[u8]) -> alloc::vec::Vec<u8> {
    let mut image = alloc::vec![0u8; 0x600];
    let put16 = |image: &mut [u8], at: usize, value: u16| image[at..at + 2].copy_from_slice(&value.to_le_bytes());
    let put32 = |image: &mut [u8], at: usize, value: u32| image[at..at + 4].copy_from_slice(&value.to_le_bytes());
    put16(&mut image, 0, 0x5A4D);
    put32(&mut image, 0x3C, 0x40);
    put32(&mut image, 0x40, 0x4550);
    put16(&mut image, 0x44, 0x8664);
    put16(&mut image, 0x46, 1);
    put16(&mut image, 0x54, 240);
    put16(&mut image, 0x56, characteristics);
    let optional = 0x58;
    put16(&mut image, optional, 0x20B);
    put32(&mut image, optional + 16, entry);
    image[optional + 24..optional + 32].copy_from_slice(&image_base.to_le_bytes());
    put32(&mut image, optional + 32, 0x1000);
    put32(&mut image, optional + 36, 0x200);
    put16(&mut image, optional + 48, 6);
    put32(&mut image, optional + 56, 0x2000);
    put32(&mut image, optional + 60, 0x400);
    put16(&mut image, optional + 68, 3);
    put32(&mut image, optional + 108, 16);
    let section = optional + 240;
    image[section..section + section_name.len()].copy_from_slice(section_name);
    put32(&mut image, section + 8, 0x200);
    put32(&mut image, section + 12, 0x1000);
    put32(&mut image, section + 16, 0x200);
    put32(&mut image, section + 20, 0x400);
    put32(&mut image, section + 36, section_flags);
    image[0x400..0x400 + content.len()].copy_from_slice(content);
    image
}

fn user_windows_process(assert: Assert) {
    use crate::drivers::fs::volume_files;
    use crate::ntos::ps::user::file_io::{self, OpenRequest};
    use crate::ntos::ps::user::{memory, process};
    if state::with(|state| state.ntdll_exports.as_ref().is_none_or(|exports| !exports.contains_key("LdrInitializeThunk"))) {
        assert(false, "userprocess: ntdll de bring-up com LdrInitializeThunk mapeada");
        return;
    }
    // Instalação mínima no volume: apiset schema v6 vazio e tabelas NLS,
    // sobrescrevendo as reais que o build instala (FILE_OVERWRITE_IF).
    let mut namespace = alloc::vec![0u8; 28];
    namespace[0] = 6;
    namespace[4] = 28;
    namespace[16] = 28;
    let schema = single_section_image(0x1_8100_0000, 0x2022, b".apiset", 0x4000_0040, 0, &namespace);
    let files: [(&str, alloc::vec::Vec<u8>); 4] = [("APISETSCHEMA.DLL", schema), ("C_1252.NLS", b"NLS-ANSI-OpenNT".to_vec()), ("C_437.NLS", b"NLS-OEM-OpenNT".to_vec()), ("L_INTL.NLS", b"NLS-CASE-OpenNT".to_vec())];
    let write_file = |name: &str, bytes: &[u8]| -> bool {
        let Ok(block) = memory::map_user_region(0x2000) else { return false };
        let (out, iosb, rsp) = (block, block + 0x20, block + 0x1800);
        let path = alloc::format!("\\??\\D:\\{name}");
        let created = file_io::open(out, &path, iosb, 5, &OpenRequest { access: 0x4010_0000, share: 0, options: 0x20, ..OpenRequest::default() }).unwrap_or(1);
        let writer = guest::read64(out);
        guest::write_bytes(block + 0x100, bytes);
        guest::write64(rsp + 0x28, iosb);
        guest::write64(rsp + 0x30, block + 0x100);
        guest::write32(rsp + 0x38, bytes.len() as u32);
        guest::write64(rsp + 0x40, 0);
        let written = state::handler("NtWriteFile").map(|handler| handler(writer, 0, 0, 0, rsp).unwrap_or(1)).unwrap_or(1);
        let _ = state::close_user_handle(writer, true, false);
        if let Some(region) = memory::find_region(block) {
            memory::release_private_region(&region);
        }
        created == 0 && written == 0
    };
    let installed = files.iter().all(|(name, bytes)| write_file(name, bytes));
    assert(installed, "userprocess: apiset schema e NLS gravados no volume");
    // Executável que encerra o processo com 0x5A pela syscall.
    let entry: &[u8] = &[0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0xBA, 0x5A, 0x00, 0x00, 0x00, 0x49, 0x89, 0xCA, 0xB8, 0x2C, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xEB, 0xFE];
    let exe = single_section_image(0x1_4000_0000, 0x0022, b".text", 0x6000_0020, 0x1000, entry);
    // Onde o processo ficou: a imagem principal, a PEB e a base da pilha
    // da primeira thread (StackLimit da TEB, logo abaixo da PEB).
    let placed = core::cell::Cell::new((0u64, 0u64, 0u64));
    let created = |_process_id: u64| -> Result<(), KernelError> {
        let (exe_base, peb) = state::with(|state| (state.process_images.iter().find(|image| image.name().is_some_and(|name| name == "C:\\opennt-teste.exe")).map_or(0, |image| image.base()), state.current_peb_va));
        let stack = if peb != 0 { unsafe { nt::Teb::at(peb - 0x2000) }.nt_tib.stack_limit.get() } else { 0 };
        placed.set((exe_base, peb, stack));
        Ok(())
    };
    let result = process::run_windows_process(Some(exe), "opennt-teste.exe", "C:\\opennt-teste.exe", None, process::RunOptions { on_process_created: Some(&created), ..process::RunOptions::default() });
    let ran = matches!(result, Ok(0x5A));
    if !ran {
        crate::debug_print!("[userprocess] resultado {:?}", result.as_ref().map_err(|error| alloc::format!("{error}")));
    }
    assert(ran, "userprocess: runWindowsProcess passa por LdrInitializeThunk, entra no exe e sai com o codigo");
    assert(state::with(|state| state.api_set_map_va != 0 && state.nls_vas.is_some_and(|vas| vas.ansi != 0 && vas.oem != 0 && vas.unicode != 0) && state.current_image_path == "C:\\opennt-teste.exe") && crate::ntos::ps::user::threads::all().len() == 1, "userprocess: apiset, NLS, caminho da imagem e thread principal do processo");
    assert(state::with(|state| state.user_regions.is_empty()), "userprocess: recursos do processo liberados na saida");
    let (exe_base, peb, stack) = placed.get();
    let user = |address: u64| crate::ntos::mm::memory_map::is_user_range(address, 0x1000);
    assert(exe_base == 0x1_4000_0000 && user(peb) && peb % 0x1000 == 0 && user(stack) && stack % 0x10000 == 0 && stack < 0x1_0000_0000, "userprocess: exe na ImageBase, PEB e pilha escolhidas pelo alocador (pilha de baixo para cima, abaixo de 4 GB)");
    assert(crate::ntos::mm::paging::find_mapping(exe_base, 0x2000).is_none() && crate::ntos::mm::paging::translate(stack) == 0, "userprocess: imagem principal e pilha desfeitas na saida");
    // Remove a instalação mínima do volume.
    for (name, _) in &files {
        let Ok(block) = memory::map_user_region(0x1000) else { continue };
        let path = alloc::format!("\\??\\D:\\{name}");
        let _ = file_io::open(block, &path, block + 0x20, 1, &OpenRequest { access: 0x8011_0000, share: 7, options: 0x1020, ..OpenRequest::default() });
        let _ = state::close_user_handle(guest::read64(block), true, false);
        if let Some(region) = memory::find_region(block) {
            memory::release_private_region(&region);
        }
        assert(volume_files::lookup_volume_file(&path).is_none(), "userprocess: arquivo temporario removido do volume");
    }
}

fn user_tokens(assert: Assert) {
    use crate::ntos::ps::user::memory;
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "usertokens: memoria de usuario");
        return;
    };
    let (out, returned, buffer, raw, rsp) = (block, block + 0x10, block + 0x100, block + 0x800, block + 0x1000);
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map(|handler| handler(a1, a2, a3, a4, rsp).unwrap_or(1)).unwrap_or(1);
    // Token primário do processo corrente.
    let opened = call("NtOpenProcessToken", u64::MAX, 0x18, out, 0);
    let token = guest::read64(out);
    assert(opened == 0 && state::get_user_handle(token).is_some_and(|entry| entry.kind() == "token"), "usertokens: NtOpenProcessToken publica um handle de usuario");
    let query = |handle: u64, class: u64, length: u64| {
        guest::write64(rsp + 0x28, returned);
        call("NtQueryInformationToken", handle, class, buffer, length)
    };
    let user = query(token, 1, 0x100);
    let sid = unsafe { nt::TokenUser::at(buffer) }.user.sid.get();
    assert(user == 0 && sid >= buffer && sid < buffer + guest::read32(returned) as u64 && unsafe { nt::Sid::at(sid) }.revision.get() == 1, "usertokens: TOKEN_USER com o SID dentro do buffer");
    assert(query(token, 8, 4) == 0 && guest::read32(buffer) == 1 && query(token, 9, 4) == 0xC000_0003 && query(token, 18, 4) == 0 && guest::read32(buffer) == 1 && query(token, 19, 4) == 0xC000_000D && query(token, 99, 4) == 0xC000_0003, "usertokens: tipo primario, nivel recusado, elevacao e classes invalidas");
    assert(query(token, 7, 16) == 0 && guest::read_bytes(unsafe { nt::TokenSource::at(buffer) }.source_name[0].address(), 8) == b"OpenNTbt" && query(token, 1, 4) == 0xC000_0023 && guest::read32(returned) >= 16, "usertokens: TOKEN_SOURCE e buffer curto com o tamanho devolvido");
    assert(query(token, 2, 0x400) == 0 && unsafe { nt::TokenGroups::at(buffer) }.group_count.get() as u64 * nt::SidAndAttributes::SIZE + core::mem::offset_of!(nt::TokenGroups, groups) as u64 <= guest::read32(returned) as u64 && query(token, 25, 0x100) == 0 && unsafe { nt::SidAndAttributes::at(buffer) }.attributes.get() == 0x60, "usertokens: grupos e rotulo de integridade");
    // Pseudo-handles: -4 consulta o primário; -5 sem impersonação não tem token.
    assert(query((-4i64) as u64, 12, 4) == 0 && query((-5i64) as u64, 1, 0x100) == 0xC000_007C && query((-4i64) as u64, 7, 16) == 0xC000_0022, "usertokens: pseudo-handles de token");
    // TokenStatistics pela variante de syscall (frame bruto).
    for (index, value) in [token, 10, buffer, 56, returned].into_iter().enumerate() {
        guest::write64(raw + (index as u64 + 1) * 8, value);
    }
    guest::write64(rsp + 0x28, returned);
    state::with(|state| state.service_raw_arguments = raw);
    let statistics = call("NtQueryInformationToken", token, 10, buffer, 56);
    state::with(|state| state.service_raw_arguments = 0);
    assert(statistics == 0 && guest::read32(returned) == 56, "usertokens: TokenStatistics pela variante de syscall");
    assert(call("NtOpenThreadToken", (-2i64) as u64, 8, 0, out) == 0xC000_007C, "usertokens: thread sem impersonacao nao tem token");
    guest::write32(rsp + 0x28, 0);
    guest::write64(rsp + 0x30, returned);
    assert(call("NtQuerySecurityAttributesToken", token, 0, 0, buffer) == 0xC000_000D && call("NtQuerySecurityAttributesToken", 0x7FF0, 0, 0, buffer) == 0xC000_000D, "usertokens: atributos de seguranca exigem saida");
    let _ = call("NtClose", token, 0, 0, 0);
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn user_query_object(assert: Assert) {
    use crate::ntos::ob::query_object;
    use crate::ntos::ps::user::memory;
    let Ok(block) = memory::map_user_region(0x3000) else {
        assert(false, "userquery: memoria de usuario");
        return;
    };
    let (out, returned, buffer, attributes, rsp) = (block, block + 0x10, block + 0x400, block + 0x200, block + 0x2000);
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map(|handler| handler(a1, a2, a3, a4, rsp).unwrap_or(1)).unwrap_or(1);
    let query = |handle: u64, class: u64, length: u64| {
        guest::write64(rsp + 0x28, returned);
        call("NtQueryObject", handle, class, buffer, length)
    };
    // O handle é aberto e consultado na tabela do processo de usuário.
    let previous = crate::ntos::ps::process::get_current_thread();
    let saved_pid = state::with(|state| state.current_process_id);
    let Ok(owner) = crate::ntos::ps::process::create_process(0x7F20, "consulta.exe", 0, None) else {
        assert(false, "userquery: processo de usuario");
        return;
    };
    let Ok(thread) = crate::ntos::ps::process::create_kernel_thread(owner, 0x7F24, true, 1, None) else {
        assert(false, "userquery: thread do processo");
        return;
    };
    crate::ntos::ps::process::set_current_thread(thread);
    state::with(|state| state.current_process_id = 0x7F20);
    // Evento nomeado do processo.
    state::write_user_wide(attributes + 0x80, "\\OpenNtEventoQuery");
    state::write_unicode_string(attributes + 0x40, attributes + 0x80, "\\OpenNtEventoQuery");
    set_object_attributes(unsafe { nt::ObjectAttributes::at(attributes) }, nt::ObjectAttributes::SIZE as u32, 0, attributes + 0x40, 0x40);
    guest::write64(rsp + 0x28, 0);
    let created = call("NtCreateEvent", out, 0x1F_0003, attributes, 0);
    let event = guest::read64(out);
    assert(created == 0, "userquery: evento nomeado");
    assert(query(event, 0, 56) == 0 && { let basic = unsafe { nt::ObjectBasicInformation::at(buffer) }; basic.granted_access.get() == 0x1F_0003 && basic.handle_count.get() == 1 && basic.pointer_count.get() >= 1 }, "userquery: OBJECT_BASIC_INFORMATION com acesso e handles");
    let named = query(event, 1, 0x100);
    let name_info = unsafe { nt::ObjectNameInformation::at(buffer) };
    let length = name_info.name.length.get() as u64;
    assert(named == 0 && length == 36 && name_info.name.buffer.get() == buffer + nt::ObjectNameInformation::SIZE && state::read_user_wide_string(name_info.name.buffer.get(), length / 2) == "\\OpenNtEventoQuery", "userquery: nome do objeto pelo namespace");
    let typed = query(event, 2, 0x200);
    assert(typed == 0 && { let type_info = unsafe { nt::ObjectTypeInformation::at(buffer) }; state::read_user_wide_string(type_info.type_name.buffer.get(), type_info.type_name.length.get() as u64 / 2) } == "Event", "userquery: OBJECT_TYPE_INFORMATION do evento");
    assert(query(event, 4, 2) == 0 && query(event, 5, 8) == 0xC000_0003 && query(event, 0, 40) == 0xC000_0004 && query(event, 1, 8) == 0xC000_0004 && guest::read32(returned) == 54, "userquery: flags, classe e tamanhos invalidos com o tamanho exigido");
    assert(query(event, 3, 0x2000) == 0 && unsafe { nt::ObjectTypesInformation::at(buffer) }.number_of_types.get() as usize == crate::ntos::ob::object_types::all().len(), "userquery: lista de todos os tipos");
    // Pseudo-handle do processo, handles inválidos e alinhamento.
    let process = query(u64::MAX, 2, 0x200);
    assert(process == 0 && { let type_info = unsafe { nt::ObjectTypeInformation::at(buffer) }; state::read_user_wide_string(type_info.type_name.buffer.get(), type_info.type_name.length.get() as u64 / 2) } == "Process", "userquery: pseudo-handle do processo corrente");
    guest::write64(rsp + 0x28, returned);
    assert(query(0x7FF0, 0, 56) == 0xC000_0008 && query(0x8000_0000, 0, 56) == 0xC000_0008 && call("NtQueryObject", event, 0, buffer + 1, 56) == 0x8000_0002, "userquery: handles invalidos e saida desalinhada");
    // ZwQueryObject pelo caminho de kernel.
    let kernel = guest::alloc_bytes(0x100);
    assert(query_object::query(u64::MAX, 0, kernel, 56, 0).ok() == Some(0) && unsafe { nt::ObjectBasicInformation::at(kernel) }.granted_access.get() == crate::ntos::ob::object_types::process_type().valid_access, "userquery: ZwQueryObject do processo corrente em KernelMode");
    guest::free_bytes(kernel);
    let _ = call("NtClose", event, 0, 0, 0);
    crate::ntos::ps::process::set_current_thread(previous);
    state::with(|state| state.current_process_id = saved_pid);
    let _ = crate::ntos::ps::process::release_thread(thread);
    let _ = crate::ntos::ps::process::terminate_process(owner, 0);
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn user_remove_completion(assert: Assert) {
    use crate::ntos::alpc::completion_reference;
    use crate::ntos::io::completion::{create as create_completion, remove as remove_completion, set as set_completion};
    use crate::ntos::ps::user::memory;
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "userremove: memoria de usuario");
        return;
    };
    let (out, removed, timeout, raw, entries, rsp) = (block, block + 0x10, block + 0x18, block + 0x40, block + 0x200, block + 0x1000);
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map(|handler| handler(a1, a2, a3, a4, rsp).unwrap_or(1)).unwrap_or(1);
    guest::write64(rsp + 0x28, 0);
    let _ = call("NtCreateIoCompletion", out, 0x1F_0003, 0, 0);
    let port = guest::read64(out);
    for key in [0x11u64, 0x22, 0x33] {
        guest::write64(raw + 16, key);
        guest::write64(raw + 24, key + 1);
        guest::write64(rsp + 0x28, key + 2);
        state::with(|state| state.service_raw_arguments = raw);
        let _ = call("NtSetIoCompletion", port, 0, 0, 0);
        state::with(|state| state.service_raw_arguments = 0);
    }
    // Lote de dois em UserMode: FILE_IO_COMPLETION_INFORMATION de 32 bytes.
    unsafe { nt::LargeInteger::at(timeout) }.quad_part.set(0);
    let packets = unsafe { nt::FileIoCompletionInformation::array_at(entries, 2) };
    guest::write64(rsp + 0x28, timeout);
    guest::write64(rsp + 0x30, 0);
    let batch = call("NtRemoveIoCompletionEx", port, entries, 2, removed);
    assert(batch == 0 && guest::read32(removed) == 2 && packets[0].key_context.get() == 0x11 && packets[0].apc_context.get() == 0x12 && packets[0].io_status_block.information.get() == 0x13 && packets[1].key_context.get() == 0x22, "userremove: NtRemoveIoCompletionEx retira o lote em ordem FIFO");
    assert(call("NtRemoveIoCompletionEx", port, entries, 4, removed) == 0 && guest::read32(removed) == 1 && packets[0].key_context.get() == 0x33, "userremove: lote maior que a fila entrega o que existe");
    assert(call("NtRemoveIoCompletionEx", port, entries, 1, removed) == 0x102, "userremove: fila vazia com prazo zero devolve STATUS_TIMEOUT");
    assert(call("NtRemoveIoCompletionEx", port, entries, 0, removed) == 0xC000_000D && call("NtRemoveIoCompletionEx", port, entries + 4, 1, removed) == 0x8000_0002 && call("NtRemoveIoCompletionEx", 0x7FF0, entries, 1, removed) == 0xC000_0008, "userremove: contagem, alinhamento e handle invalidos");
    guest::write64(rsp + 0x28, 0);
    let _ = call("NtCreateEvent", out, 0x1F_0003, 0, 0);
    let event = guest::read64(out);
    guest::write64(rsp + 0x28, timeout);
    assert(call("NtRemoveIoCompletionEx", event, entries, 1, removed) == 0xC000_0024, "userremove: handle de outro tipo");
    // KernelMode por handle de kernel, com a espera cooperativa.
    let kernel = guest::alloc_bytes(0x100);
    let created = create_completion::create(kernel, 0x1F_0003, 0, 1, 0).unwrap_or(1);
    let handle = guest::read64(kernel);
    let posted = completion_reference::reference(handle, 0).ok().and_then(|reference| reference.ok()).map(|mut reference| {
        let status = set_completion::post(reference.port.pointer, 0x44, 0x45, 0, 0x46, 0, 0).unwrap_or(1);
        let _ = reference.release();
        status
    });
    unsafe { nt::LargeInteger::at(kernel + 0x10) }.quad_part.set(0);
    let mut request = remove_completion::begin(handle, kernel + 0x40, 1, kernel + 0x18, kernel + 0x10, false, 0, true, None);
    let status = request.as_mut().ok().and_then(|request| request.poll());
    assert(created == 0 && posted == Some(0) && status == Some(0) && guest::read32(kernel + 0x18) == 1 && { let packet = unsafe { nt::FileIoCompletionInformation::at(kernel + 0x40) }; packet.key_context.get() == 0x44 && packet.io_status_block.information.get() == 0x46 }, "userremove: retirada em KernelMode por handle de kernel");
    assert(completion_reference::reference(0xFFFF_FFFF_8000_0004, 1).ok().is_some_and(|reference| reference.is_err_and(|status| status == 0xC000_0008)) && completion_reference::reference(u64::MAX, 0).ok().is_some_and(|reference| reference.is_err_and(|status| status == 0xC000_0024)), "userremove: handle de kernel recusado em UserMode e pseudo-handle");
    let _ = crate::ntos::ob::open_pointer::close(handle);
    guest::free_bytes(kernel);
    for value in [port, event] {
        let _ = call("NtClose", value, 0, 0, 0);
    }
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

static ALPC_CLEANED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn user_alpc_foundation(assert: Assert) {
    use crate::ntos::alpc::small::{context_attribute, direct_event, wake_policy};
    use crate::ntos::alpc::message::identity as message_identity;
    use crate::ntos::alpc::{port_sections, security_contexts};
    use crate::ntos::alpc::resource::reserves as resource_reserves;
    use crate::ntos::ob::objects::port::{self as port_objects, PortState, Role};
    use crate::ntos::ps::user::{memory, sections};
    use core::sync::atomic::Ordering;
    let Ok(block) = memory::map_user_region(0x1000) else {
        assert(false, "useralpc: memoria de usuario");
        return;
    };
    ALPC_CLEANED.store(false, Ordering::SeqCst);
    let created = port_objects::create("alpc", PortState { role: Role::Listener, ..PortState::default() }, 0x200, 0, 0, alloc::boxed::Box::new(|_| ALPC_CLEANED.store(true, Ordering::SeqCst)), port_objects::CreateOptions::default());
    let Ok(port) = created else {
        assert(false, "useralpc: porta ALPC criada");
        return;
    };
    assert(guest::read32(port.pointer + 0x28) == 0x200 && guest::read64(port.pointer + 0x50) != 0 && port.token() != 0 && crate::ntos::ob::objects::dispatcher::get(port.pointer).is_some_and(|(kind, _, _)| kind == "alpc"), "useralpc: corpo de 0x80 bytes com maximo e token do processo");
    let published = port_objects::publish(&port, block, 0).unwrap_or(1);
    let handle = guest::read64(block);
    assert(published == 0 && port_objects::resolve(handle, "alpc").is_some_and(|(_, resolved)| alloc::sync::Arc::ptr_eq(&resolved, &port)) && port_objects::resolve(handle, "port").is_none(), "useralpc: handle publicado e resolvido pelo tipo");
    // Identidade das mensagens: geração, callback e curinga.
    let identity = message_identity::activate(&port, None).ok().flatten();
    let resolved = identity.as_ref().map(|identity| (message_identity::resolve(&port, identity.identifier, identity.callback).is_ok(), message_identity::resolve(&port, identity.identifier, 0).is_ok(), message_identity::resolve(&port, identity.identifier, identity.callback.wrapping_add(1)).err()));
    assert(identity.as_ref().is_some_and(|identity| identity.identifier % 4 == 0 && identity.identifier != 0) && resolved == Some((true, true, Some(0xC000_0702))), "useralpc: identidade resolvida pelo callback e pelo curinga");
    if let Some(identity) = &identity {
        let _ = message_identity::release(identity);
        assert(message_identity::resolve(&port, identity.identifier, identity.callback).err() == Some(0xC000_0702), "useralpc: geracao liberada deixa de resolver");
    }
    assert(message_identity::next_callback(u32::MAX) == 1 && message_identity::next_sequence(u32::MAX) == 0, "useralpc: callback pula zero e sequencia admite zero");
    // Reservas: identificador com bit alto, cobrança e slot reservado.
    let reserve = resource_reserves::create(&port, 0x100).ok().and_then(|result| result.ok());
    assert(reserve.as_ref().is_some_and(|reserve| reserve.identifier & 0x8000_0000 != 0 && resource_reserves::find(&port, reserve.identifier).is_some_and(|found| alloc::sync::Arc::ptr_eq(&found, reserve))) && port.reserve_bytes() == 0x100 && guest::read32(port.pointer + 0x3C) == 1, "useralpc: reserva publicada na tabela da porta");
    assert(resource_reserves::create(&port, 0x1_0000).ok().and_then(|result| result.err()) == Some(0x8000_0005) && resource_reserves::create(&port, 10).ok().and_then(|result| result.err()) == Some(0xC000_000D), "useralpc: tamanhos de reserva recusados");
    if let Some(reserve) = &reserve {
        let message = message_identity::activate(&port, Some(reserve.slot.clone())).ok().flatten();
        let busy = reserve.state.lock().busy;
        if let Some(message) = &message {
            let _ = message_identity::release(message);
        }
        assert(message.is_some_and(|message| message.reserved) && busy && !reserve.state.lock().busy, "useralpc: mensagem no slot reservado marca a reserva ocupada");
        assert(resource_reserves::remove(reserve).ok() == Some(0) && resource_reserves::find(&port, reserve.identifier).is_none() && port.reserve_bytes() == 0, "useralpc: reserva removida e descobrada");
    }
    // Contexto de segurança: referência pela tabela e exclusão.
    let quality = security_contexts::Quality { level: 2, tracking: 0, effective_only: false };
    let context = security_contexts::create(&port, &quality, true).ok().and_then(|result| result.ok());
    let referenced = context.as_ref().and_then(|context| security_contexts::reference(&port, context.handle).ok().and_then(|result| result.ok()));
    if let Some(referenced) = &referenced {
        let _ = security_contexts::release(referenced);
    }
    // O criador devolve a referência que recebeu; a da tabela sai na exclusão.
    if let Some(context) = &context {
        let _ = security_contexts::release(context);
    }
    assert(context.as_ref().is_some_and(|context| context.client.token != 0 && context.client.level == 2) && referenced.is_some() && context.as_ref().is_some_and(|context| security_contexts::delete_referenced(context).ok() == Some(0)), "useralpc: contexto de seguranca criado, referenciado e excluido");
    assert(security_contexts::create(&port, &security_contexts::Quality { level: 4, tracking: 0, effective_only: false }, true).ok().and_then(|result| result.err()) == Some(0xC000_00A5), "useralpc: nivel de impersonacao invalido");
    // Seção da porta e regiões de 64 KiB.
    let section = sections::create(sections::CreateOptions { size: 0x4_0000, page_protect: 4, attributes: 0x800_0000, committed: Some(true), ..sections::CreateOptions::default() }).ok().and_then(|created| created.ok());
    let attached = section.as_ref().and_then(|section| port_sections::attach(&port, section, port_sections::Creation::default()).ok().and_then(|result| result.ok()));
    if let Some((section_handle, record)) = &attached {
        let borrowed = port_sections::reference(&port, *section_handle as u64).ok();
        let first = port_sections::allocate_region(record, 0x1000).ok();
        let second = port_sections::allocate_region(record, 0x1_8000).ok();
        let layout = first.as_ref().map(|region| (region.offset, region.reserved_size, region.view_size)) == Some((0, 0x1_0000, 0x1000)) && second.as_ref().map(|region| (region.offset, region.reserved_size)) == Some((0x1_0000, 0x2_0000));
        if let Some(first) = &first {
            let _ = port_sections::release_region(record, first);
        }
        let refill = port_sections::allocate_region(record, 0x8000).ok();
        let reused = refill.as_ref().is_some_and(|region| region.offset == 0) && port_sections::allocate_region(record, 0x10_0000).err() == Some(0xC000_009A);
        for region in [second, refill].into_iter().flatten() {
            let _ = port_sections::release_region(record, &region);
        }
        if let Some(borrowed) = &borrowed {
            let _ = port_sections::release(borrowed);
        }
        assert(borrowed.is_some() && layout && reused && port_sections::delete_referenced(record).ok() == Some(0) && port_sections::reference(&port, *section_handle as u64).is_err(), "useralpc: secao da porta com regioes de 64 KiB e exclusao");
    } else {
        assert(false, "useralpc: secao anexada a porta");
    }
    // Políticas pequenas.
    assert(wake_policy::select_charge_mode(0, 0, 0, true).is_none() && wake_policy::select_charge_mode(0, 0x20_0000, 0, false) == Some(3) && wake_policy::select_charge_mode(0, 0x40_0000, 0, false) == Some(1) && wake_policy::select_charge_mode(0, 0, 1, false).is_none() && wake_policy::select_charge_mode(0x2_0000, 0, 3, false) == Some(0x8000_0003), "useralpc: politica de cobranca de ativacao");
    assert(direct_event::validate(0x10, 0x2000_0000) == 0xC000_000D && direct_event::validate(0, 0) == 0xC000_000D && direct_event::validate(0, 0x2000_0000) == 0, "useralpc: validacao do atributo direto");
    let attribute = guest::alloc_bytes(32);
    let context_attribute_view = unsafe { nt::AlpcContextAttr::at(attribute) };
    let tail = context_attribute_view.callback_id.address() + 4;
    context_attribute_view.message_context.set(0xABCD);
    guest::write32(tail, 0x5A5A);
    if let Ok(Some(identity)) = message_identity::activate(&port, None) {
        let captured = context_attribute::capture(attribute, 0x77, &identity);
        assert(captured == 0xABCD && context_attribute_view.port_context.get() == 0x77 && context_attribute_view.sequence.get() == 0 && context_attribute_view.message_id.get() == identity.identifier && guest::read32(tail) == 0x5A5A && identity.with(|state| state.client_context) == 0xABCD, "useralpc: atributo de contexto capturado sem tocar o reservado");
        let _ = message_identity::release(&identity);
    }
    guest::free_bytes(attribute);
    // Fechamento: último handle, limpeza do transporte e destruição.
    let pointer = port.pointer;
    drop(port);
    let _ = state::handler("NtClose").map(|close| close(handle, 0, 0, 0, block + 0x800));
    assert(ALPC_CLEANED.load(Ordering::SeqCst) && port_objects::port_of(pointer).is_none(), "useralpc: ultimo handle limpa o transporte e destroi a porta");
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn user_alpc_services(assert: Assert) {
    use crate::ntos::alpc::port_reference;
    use crate::ntos::alpc::resource::services;
    use crate::ntos::ob::objects::completion as completion_objects;
    use crate::ntos::ob::objects::port::{self as port_objects, PortState, Role};
    use crate::ntos::ps::user::memory;
    let Ok(block) = memory::map_user_region(0x1000) else {
        assert(false, "useralpcsvc: memoria de usuario");
        return;
    };
    let created = port_objects::create("alpc", PortState { role: Role::Listener, ..PortState::default() }, 0x200, 0, 0, alloc::boxed::Box::new(|_| {}), port_objects::CreateOptions::default());
    let Ok(port) = created else {
        assert(false, "useralpcsvc: porta ALPC criada");
        return;
    };
    let _ = port_objects::publish(&port, block, 0);
    let handle = guest::read64(block);
    // Referência pela tabela dona.
    let referenced = port_reference::reference(handle, 1, 1).ok().and_then(|result| result.ok());
    let same = referenced.as_ref().is_some_and(|reference| alloc::sync::Arc::ptr_eq(&reference.port, &port));
    if let Some(mut reference) = referenced {
        let _ = reference.release();
    }
    let status = |handle: u64| port_reference::reference(handle, 1, 1).ok().and_then(|result| result.err());
    assert(same && status(u64::MAX) == Some(0xC000_0024) && status(handle + 0x400) == Some(0xC000_0008) && status(0xFFFF_FFFF_8000_0004) == Some(0xC000_0008) && status(0x1_0000_0000) == Some(0xC000_0008), "useralpcsvc: referencia da porta pela tabela e recusas");
    // Contexto de segurança pela entrada Nt (qualidade padrão da porta).
    let attribute = block + 0x100;
    let security_attribute = unsafe { nt::AlpcSecurityAttr::at(attribute) };
    security_attribute.p_qos.set(0);
    let create_context = state::handler("NtAlpcCreateSecurityContext").map(|handler| handler(handle, 0, attribute, 0, block + 0x800));
    let context = security_attribute.context_handle.get();
    assert(matches!(create_context, Some(Ok(0))) && context >= 0x10 && services::create_security_context(handle, 1, attribute, 1).ok() == Some(0xC000_000D) && services::create_security_context(handle, 0, attribute + 4, 1).ok() == Some(0x8000_0002), "useralpcsvc: contexto de seguranca criado pela syscall");
    assert(services::delete_security_context(handle, 0, context, 1).ok() == Some(0) && services::delete_security_context(handle, 0, context, 1).ok() == Some(0xC000_0008), "useralpcsvc: contexto excluido e identificador retirado");
    // Reserva de mensagem.
    let output = block + 0x200;
    let reserve_status = services::create_resource_reserve(handle, 0, 0x80, output, 1).ok();
    let identifier = guest::read32(output);
    assert(reserve_status == Some(0) && identifier & 0x8000_0000 != 0 && port.reserve_bytes() == 0x80, "useralpcsvc: reserva criada pela syscall");
    assert(services::delete_resource_reserve(handle, 0, identifier & 0x7FFF_FFFF, 1).ok() == Some(0xC000_000D) && services::delete_resource_reserve(handle, 0, identifier, 1).ok() == Some(0) && services::delete_resource_reserve(handle, 0, identifier, 1).ok() == Some(0xC000_0008) && port.reserve_bytes() == 0, "useralpcsvc: reserva excluida e recusas");
    // Seção da porta e vista.
    let (section_out, size_out) = (block + 0x280, block + 0x288);
    let section_status = services::create_port_section(handle, 0, 0, 0x2000, section_out, size_out, 1).ok();
    let section = guest::read64(section_out);
    assert(section_status == Some(0) && guest::read64(size_out) == 0x1_0000 && services::create_port_section(handle, 0x4_0000, 4, 0x2000, section_out, size_out, 1).ok() == Some(0xC000_000D) && services::create_port_section(handle, 0, 0, 0, section_out, size_out, 1).ok() == Some(0xC000_000D), "useralpcsvc: secao de porta de pagefile arredondada a 64 KiB");
    let view = block + 0x300;
    let view_attribute = unsafe { nt::AlpcDataViewAttr::at(view) };
    view_attribute.flags.set(0);
    view_attribute.section_handle.set(section);
    view_attribute.view_base.set(0);
    view_attribute.view_size.set(0x1000);
    let view_status = services::create_section_view(handle, 0, view, 1).ok();
    let base = view_attribute.view_base.get();
    let mapped = base != 0 && view_attribute.view_size.get() == 0x1000 && port.with(|state| state.owned_section_views.len()) == 1;
    if mapped {
        guest::write32(base, 0xA1C0_5EC7);
    }
    assert(view_status == Some(0) && mapped && guest::read32(base) == 0xA1C0_5EC7, "useralpcsvc: vista da secao mapeada no processo dono");
    assert(services::delete_section_view(handle, 0, base, 1).ok() == Some(0) && services::delete_section_view(handle, 0, base, 1).ok() == Some(0xC000_0141) && port.with(|state| state.owned_section_views.is_empty()), "useralpcsvc: vista excluida pela base");
    assert(services::delete_port_section(handle, 0, section, 1).ok() == Some(0) && services::delete_port_section(handle, 0, section, 1).ok() == Some(0xC000_0008), "useralpcsvc: secao da porta excluida");
    // Associação com a IOCP e notificações limitadas.
    let queue = completion_objects::create("", 2, 0, true);
    let queue_handle = queue.as_ref().ok().map(|queue| {
        let _ = completion_objects::publish(queue, block + 0x380, 0x1F_0003, 0, 0, true);
        guest::read64(block + 0x380)
    });
    let input = block + 0x400;
    let association = unsafe { nt::AlpcPortAssociateCompletionPort::at(input) };
    association.completion_key.set(0x55);
    association.completion_port.set(queue_handle.unwrap_or(0));
    let associated = services::set_information(handle, 2, input, 16, 1).ok();
    assert(associated == Some(0) && port.completion_key() == 0x55 && services::set_information(handle, 2, input, 16, 1).ok() == Some(0xC000_0048) && services::set_information(handle, 2, input, 8, 1).ok() == Some(0xC000_0004) && services::set_information(handle, 1, input, 8, 1).ok() == Some(0xC000_00BB) && services::set_information(handle, 3, input, 8, 1).ok() == Some(0xC000_000D) && services::set_information(0, 2, input, 16, 1).ok() == Some(0xC000_000D) && services::set_information(handle, 2, input, 80, 1).ok() == Some(0xC000_0004), "useralpcsvc: associacao da IOCP por set-information");
    if let (Ok(queue), Some(completion)) = (&queue, port.with(|state| state.completion.clone())) {
        let limit = queue.concurrency().min(4) as usize;
        for _ in 0..limit + 2 {
            completion.notify();
        }
        let depth = queue.with(|state| state.packets.len());
        let packet = queue.with(|state| state.packets.pop_front());
        let key = packet.as_ref().map(|packet| packet.key);
        if let Some(dequeue) = packet.and_then(|packet| packet.on_dequeue) {
            dequeue();
        }
        let refilled = queue.with(|state| state.packets.len());
        assert(limit == 2 && depth == limit && key == Some(0x55) && refilled == limit && completion.port_pointer() == queue.pointer, "useralpcsvc: notificacoes limitadas e retirada reabastece");
        queue.with(|state| state.packets.clear());
    } else {
        assert(false, "useralpcsvc: associacao publicada na porta");
    }
    // Desconexão e fechamento.
    assert(services::disconnect_port(handle, 2, 1).ok() == Some(0xC000_000D) && services::disconnect_port(handle, 0, 1).ok() == Some(0) && services::disconnect_port(handle, 1, 1).ok() == Some(0xC000_0037) && services::create_resource_reserve(handle, 0, 0x80, output, 1).ok() == Some(0xC000_0037), "useralpcsvc: desconexao repetida e recurso recusado");
    let pointer = port.pointer;
    drop(port);
    let close = state::handler("NtClose");
    let _ = close.map(|close| close(handle, 0, 0, 0, block + 0x800));
    if let Some(queue_handle) = queue_handle {
        let _ = close.map(|close| close(queue_handle, 0, 0, 0, block + 0x800));
    }
    assert(port_objects::port_of(pointer).is_none(), "useralpcsvc: porta destruida com a associacao");
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

struct AlpcTestService {
    deferred: bool,
}

struct AlpcTestContinuation {
    message: alloc::sync::Arc<crate::rtl::SpinLock<alloc::vec::Vec<u8>>>,
    ready: bool,
}

impl crate::ntos::alpc::transport::ServiceContinuation for AlpcTestContinuation {
    fn poll(&mut self) -> Option<u32> {
        if !self.ready {
            self.ready = true;
            return None;
        }
        let mut message = self.message.lock();
        message[40] = 0x99;
        message[0..2].copy_from_slice(&1u16.to_le_bytes());
        message[2..4].copy_from_slice(&41u16.to_le_bytes());
        Some(0)
    }
}

impl crate::ntos::alpc::transport::Service for AlpcTestService {
    fn max_message_length(&self) -> u32 {
        0x200
    }
    fn connect(&self, _port: &alloc::sync::Arc<crate::ntos::ob::objects::port::Port>, _data: &[u8], _request: Option<&[u8]>) -> crate::ntos::alpc::transport::Reply {
        crate::ntos::alpc::transport::Reply::Now(crate::ntos::alpc::transport::JobResult::default())
    }
    fn request(&self, _port: &alloc::sync::Arc<crate::ntos::ob::objects::port::Port>, message: &alloc::sync::Arc<crate::rtl::SpinLock<alloc::vec::Vec<u8>>>) -> crate::ntos::alpc::transport::ServiceReply {
        if self.deferred {
            return crate::ntos::alpc::transport::ServiceReply::Later(alloc::boxed::Box::new(AlpcTestContinuation { message: message.clone(), ready: false }));
        }
        let mut bytes = message.lock();
        let first = bytes[40];
        bytes[40] = first.wrapping_add(1);
        crate::ntos::alpc::transport::ServiceReply::Now(0)
    }
}

fn user_alpc_connect_capture(assert: Assert) {
    use crate::ntos::alpc::transport::{self, JobResult, Reply, Request, RequestState};
    use crate::ntos::alpc::{cancel_message, legacy_service, query_information};
    use crate::ntos::alpc::connect::{capture as connect_capture, parameters as connect_parameters, target as connect_target};
    use crate::ntos::alpc::message::{buffer as message_buffer, identity as message_identity, security as message_security};
    use crate::ntos::ob::objects::port::{self as port_objects, PortState, Role};
    use crate::ntos::ps::user::memory;
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "useralpcconn: memoria de usuario");
        return;
    };
    let unicode = |at: u64, buffer: u64, text: &str| {
        let length = write_wide(buffer, text);
        set_unicode(unsafe { nt::UnicodeString::at(at) }, length, length, buffer);
    };
    let path = "\\RPC Control\\OpenNtTesteAlpc";
    let Ok(listener) = transport::register(path, alloc::sync::Arc::new(AlpcTestService { deferred: false })) else {
        assert(false, "useralpcconn: endpoint registrado");
        return;
    };
    // Nome do endpoint.
    let name = block;
    unicode(name, block + 0x40, path);
    let target = connect_capture::listener(name, None, 1);
    assert(target.as_ref().is_ok_and(|target| target.path == path && target.node == listener.node && target.server.process == crate::ntos::ps::process::get_current_process()), "useralpcconn: endpoint resolvido pelo nome");
    unicode(name, block + 0x40, "RPC Control\\OpenNtTesteAlpc");
    let relative = connect_capture::listener(name, None, 1).err();
    unicode(name, block + 0x40, "\\RPC Control\\NaoExiste");
    let missing = connect_capture::listener(name, None, 1).err();
    unicode(name, block + 0x40, "\\RPC Control");
    let directory = connect_capture::listener(name, None, 1).err();
    unicode(name, block + 0x40, "\\RPC Control\\OpenNtTesteAlpc\\");
    let trailing = connect_capture::listener(name, None, 1).err();
    unicode(name, block + 0x40, "\\RPC Control\\opennttestealpc");
    let case = connect_capture::listener(name, None, 1).err();
    unsafe { nt::UnicodeString::at(name) }.length.set(3);
    let odd = connect_capture::listener(name, None, 1).err();
    assert(relative == Some(0xC000_003B) && missing == Some(0xC000_0034) && directory == Some(0xC000_0024) && trailing == Some(0xC000_0033) && case == Some(0xC000_0034) && odd == Some(0xC000_0033), "useralpcconn: recusas do nome do endpoint");
    // SID exigido do servidor.
    let user = crate::ntos::ps::process::get_primary_token(crate::ntos::ps::process::get_current_process()).and_then(|token| crate::ntos::se::token::tokens::with(token, |token| token.user.clone())).unwrap_or_default();
    unicode(name, block + 0x40, path);
    let mut wrong = user.clone();
    if let Some(last) = wrong.last_mut() {
        *last ^= 0xFF;
    }
    assert(connect_capture::listener(name, Some(&user), 1).is_ok() && connect_capture::listener(name, Some(&wrong), 1).err() == Some(0xC000_02A0), "useralpcconn: SID exigido comparado com o token do servidor");
    let sid = block + 0x100;
    guest::write_bytes(sid, &user);
    let captured_sid = connect_capture::identifier(sid, 1);
    unsafe { nt::Sid::at(sid) }.revision.set(2);
    assert(captured_sid.as_ref().is_ok_and(|bytes| bytes.as_deref() == Some(user.as_slice())) && connect_capture::identifier(sid, 1).err() == Some(0xC000_0078) && connect_capture::identifier(0, 1) == Ok(None), "useralpcconn: SID capturado e revisao invalida");
    // ALPC_PORT_ATTRIBUTES.
    let defaults = connect_parameters::capture(0, 1).ok().and_then(|captured| connect_parameters::for_client(&captured, 0x200).ok().and_then(|result| result.ok()));
    assert(defaults.is_some_and(|parameters| parameters.port_flags == 0x1_0000 && parameters.maximum == 0x200 && parameters.security_quality.tracking == 1 && parameters.maximum_total_section_size == 0x2_0000), "useralpcconn: parametros padrao do cliente");
    let attributes = block + 0x200;
    guest::write_bytes(attributes, &[0u8; nt::AlpcPortAttributes::SIZE as usize]);
    let port_attributes = unsafe { nt::AlpcPortAttributes::at(attributes) };
    let client = |flags: u32, level: u32, tracking: u8, maximum: u64| {
        port_attributes.flags.set(flags);
        port_attributes.security_qos.impersonation_level.set(nt::SecurityImpersonationLevel(level as i32));
        port_attributes.security_qos.context_tracking_mode.set(tracking);
        port_attributes.security_qos.effective_only.set(1);
        port_attributes.max_message_length.set(maximum);
        port_attributes.dup_object_types.set(0xFFFF);
        connect_parameters::capture(attributes, 1).ok().and_then(|captured| connect_parameters::for_client(&captured, 0x200).ok())
    };
    let accepted = client(0x8001_0000 | 0x20_0000, 2, 0, 0x1000);
    assert(matches!(accepted, Some(Ok(parameters)) if parameters.maximum == 0x200 && parameters.port_flags == 0x21_0000 && parameters.security_quality.level == 2 && parameters.security_quality.effective_only && parameters.duplicate_object_types == 0xFFD), "useralpcconn: atributos do cliente validados");
    assert(matches!(client(0, 2, 0, 30), Some(Err(0xC000_000D))) && matches!(client(0x10_0000, 2, 0, 0x100), Some(Err(0xC000_000D))) && matches!(client(0, 2, 2, 0x100), Some(Err(0xC000_000D))) && matches!(client(0, 4, 0, 0x100), Some(Err(0xC000_00A5))), "useralpcconn: ordem das recusas dos atributos");
    // OBJECT_ATTRIBUTES da porta cliente.
    let object = block + 0x300;
    let object_attributes = unsafe { nt::ObjectAttributes::at(object) };
    set_object_attributes(object_attributes, nt::ObjectAttributes::SIZE as u32, 0, name, 0);
    unicode(name, block + 0x40, "\\RPC Control\\OpenNtTesteCliente");
    let creation = connect_capture::object_attributes(object, 1);
    unicode(name, block + 0x40, path);
    let collision = connect_capture::object_attributes(object, 1).err();
    unicode(name, block + 0x40, "\\NaoExiste\\Cliente");
    let parent_missing = connect_capture::object_attributes(object, 1).err();
    object_attributes.length.set(40);
    let bad_length = connect_capture::object_attributes(object, 1).err();
    object_attributes.length.set(nt::ObjectAttributes::SIZE as u32);
    assert(creation.as_ref().is_ok_and(|creation| creation.leaf == "OpenNtTesteCliente" && creation.parent.is_some() && creation.name.as_deref() == Some("\\RPC Control\\OpenNtTesteCliente")) && collision == Some(0xC000_0035) && parent_missing == Some(0xC000_003A) && bad_length == Some(0xC000_000D), "useralpcconn: OBJECT_ATTRIBUTES da porta cliente");
    // Busca Ex por OBJECT_ATTRIBUTES.
    unicode(name, block + 0x40, path);
    let ex_target = connect_target::listener(object, None, 1);
    object_attributes.attributes.set(0x8000_0000);
    let ex_flags = connect_target::listener(object, None, 1).err();
    object_attributes.attributes.set(0);
    assert(ex_target.is_ok_and(|target| target.node == listener.node) && ex_flags == Some(0xC000_000D) && connect_target::listener(0, None, 1).err() == Some(0xC000_0033) && connect_target::required_security(0x1234, 0).ok().is_some_and(|policy| policy.is_none()), "useralpcconn: busca Ex do endpoint");
    // Mensagem de conexão.
    let message = block + 0x400;
    let connection_message = unsafe { nt::PortMessage::at(message) };
    connection_message.u1.s1.data_length.set(4);
    connection_message.u1.s1.total_length.set(44);
    connection_message.u2.s2.type_.set(0x8000u16 as i16);
    guest::write_bytes(message + nt::PortMessage::SIZE, &0xC0FF_EE11u32.to_le_bytes());
    let captured = connect_capture::message(message, 0x200, 1);
    let kernel = connect_capture::message(message, 0x200, 0).map(|message| message.message_type);
    connection_message.u1.s1.total_length.set(45);
    let incoherent = connect_capture::message(message, 0x200, 1).err();
    connection_message.u1.s1.total_length.set(44);
    assert(captured.as_ref().is_ok_and(|message| message.data == [0x11, 0xEE, 0xFF, 0xC0] && message.message_type == 0x200A) && kernel == Ok(0xA00A) && incoherent == Some(0xC000_000D) && connect_capture::message(message, 43, 1).err() == Some(0xC000_002F) && connect_capture::message(0, 0x200, 1).is_ok_and(|message| message.data.is_empty()), "useralpcconn: mensagem de conexao capturada");
    // Consultas da porta.
    let Ok(port) = port_objects::create("alpc", PortState { role: Role::Listener, port_flags: 0x8001_0000, port_context: 0x7777, ..PortState::default() }, 0x200, 5, 0, alloc::boxed::Box::new(|_| {}), port_objects::CreateOptions::default()) else {
        assert(false, "useralpcconn: porta de escuta");
        return;
    };
    let _ = port_objects::publish(&port, block + 0x500, 0);
    let handle = guest::read64(block + 0x500);
    let (output, returned) = (block + 0x600, block + 0x620);
    let basic = query_information::query(handle, 0, output, 16, returned, 1).ok();
    let short = query_information::query(handle, 0, output, 8, returned, 1).ok();
    assert(basic == Some(0) && { let basic_info = unsafe { nt::AlpcBasicInformation::at(output) }; basic_info.flags.get() == 0x1_0000 && basic_info.sequence_no.get() == 5 && basic_info.port_context.get() == 0x7777 } && short == Some(0xC000_0004) && guest::read32(returned) == 16, "useralpcconn: consulta basica da porta");
    guest::write_bytes(sid, &user);
    let own = query_information::query(handle, 3, sid, 0, returned, 1).ok();
    guest::write8(sid + user.len() as u64 - 1, user[user.len() - 1] ^ 0xFF);
    let other = query_information::query(handle, 3, sid, 0, returned, 1).ok();
    assert(own == Some(0) && other == Some(0xC000_02A0) && query_information::query(handle, 4, output, 16, 0, 1).ok() == Some(0xC000_00BB) && query_information::query(handle, 9, output, 16, 0, 1).ok() == Some(0xC000_000D) && query_information::query(handle, 0, 0, 16, 0, 1).ok() == Some(0xC000_000D) && query_information::query(handle, 0, output + 1, 16, 0, 1).ok() == Some(0x8000_0002), "useralpcconn: SID do processo conectado e classes recusadas");
    let query_handler = state::handler("NtAlpcQueryInformation").is_some();
    // Segurança por mensagem: CREATE publicado, seleção explícita e RELEASE.
    let security = block + 0x700;
    let security_attribute = unsafe { nt::AlpcSecurityAttr::at(security) };
    security_attribute.flags.set(0x2_0000);
    security_attribute.p_qos.set(0);
    security_attribute.context_handle.set(0xFFFF_FFFF_FFFF_FFFE);
    let created = message_security::capture(&port, security, 1).ok().and_then(|result| result.ok());
    let context = security_attribute.context_handle.get();
    let identity = message_identity::activate(&port, None).ok().flatten();
    let mut selected_token = 0;
    let mut implicit = None;
    if let (Some(message_security::Captured::Borrowed(borrowed)), Some(identity)) = (&created, &identity) {
        implicit = message_security::select(&port, identity).ok().and_then(|result| result.err());
        identity.with(|state| state.security = Some(borrowed.clone()));
        if let Ok(Ok(selected)) = message_security::select(&port, identity) {
            selected_token = selected.token;
            selected.release();
        }
        message_identity::clear_attributes(identity);
    }
    if let Some(identity) = &identity {
        let _ = message_identity::release(identity);
    }
    assert(matches!(created, Some(message_security::Captured::Borrowed(_))) && context != 0xFFFF_FFFF_FFFF_FFFE && selected_token != 0 && implicit == Some(0xC000_0022), "useralpcconn: contexto de mensagem criado e selecionado");
    security_attribute.flags.set(0x1_0000);
    let released = message_security::capture(&port, security, 1).ok().and_then(|result| result.ok());
    security_attribute.flags.set(0x3_0000);
    let both = message_security::capture(&port, security, 1).ok().and_then(|result| result.err());
    assert(matches!(released, Some(message_security::Captured::Empty)) && both == Some(0xC000_000D) && crate::ntos::alpc::security_contexts::reference(&port, context).ok().and_then(|result| result.err()) == Some(0xC000_0008), "useralpcconn: RELEASE retira o contexto");
    // Cancelamento: captura dos layouts x64 e compacto.
    let cancel_context = block + 0x800;
    let (cancel_attribute, compact_attribute) = unsafe { (nt::AlpcContextAttr::at(cancel_context), AlpcContextAttr32::at(cancel_context)) };
    cancel_attribute.message_context.set(0xABCD_0000_1234);
    cancel_attribute.message_id.set(0x40);
    cancel_attribute.callback_id.set(7);
    let mut seen = None;
    let canceled = cancel_message::cancel(handle, 0, cancel_context, 1, |_, selection, _| {
        seen = Some(selection);
        Ok(0x1234)
    });
    compact_attribute.message_context.set(0x55);
    compact_attribute.message_id.set(0x80);
    compact_attribute.callback_id.set(9);
    let mut compact = None;
    let _ = cancel_message::cancel(handle, 4, cancel_context, 1, |_, selection, _| {
        compact = Some(selection);
        Ok(0)
    });
    cancel_attribute.message_id.set(0);
    let zero = cancel_message::cancel(handle, 0, cancel_context, 1, |_, _, _| Ok(0)).ok();
    assert(canceled.ok() == Some(0x1234) && seen.is_some_and(|selection| selection.identifier == 0x40 && selection.callback == 7 && selection.message_context == 0xABCD_0000_1234) && compact.is_some_and(|selection| selection.identifier == 0x80 && selection.callback == 9 && selection.message_context == 0x55) && zero == Some(0xC000_0109) && cancel_message::cancel(handle, 0x10, cancel_context, 1, |_, _, _| Ok(0)).ok() == Some(0xC000_000D), "useralpcconn: captura do cancelamento");
    // Serviço LPC legado: imediato e por continuação.
    let header = |data_length: u16| {
        let mut header = [0u8; 40];
        header[0..2].copy_from_slice(&data_length.to_le_bytes());
        header[2..4].copy_from_slice(&(data_length + 40).to_le_bytes());
        header
    };
    let mut legacy = (None, None);
    if let Ok(Some(identity)) = message_identity::activate(&port, None) {
        let request = alloc::sync::Arc::new(Request { id: identity.identifier, identity: identity.clone(), state: crate::rtl::SpinLock::new(RequestState::default()) });
        port.with(|state| state.service = Some(alloc::sync::Arc::new(AlpcTestService { deferred: false })));
        let captured = message_buffer::Captured { header: header(2), data: alloc::vec![5, 6] };
        if let Ok(Reply::Now(JobResult { status: 0, data, .. })) = legacy_service::exchange(&port, &captured, &request, false) {
            legacy.0 = Some(data);
        }
        port.with(|state| state.service = Some(alloc::sync::Arc::new(AlpcTestService { deferred: true })));
        if let Ok(Reply::Later(mut job)) = legacy_service::exchange(&port, &captured, &request, true) {
            let first = job.poll().is_none();
            if let Some(JobResult { status: 0, data, .. }) = job.poll() {
                legacy.1 = first.then_some(data);
            }
        }
        port.with(|state| state.service = None);
        drop(request);
        let _ = message_identity::release(&identity);
    }
    assert(legacy.0.as_deref() == Some(&[6, 6][..]) && legacy.1.as_deref() == Some(&[0x99][..]), "useralpcconn: servico LPC legado imediato e por continuacao");
    assert(query_handler, "useralpcconn: NtAlpcQueryInformation registrado");
    // Limpeza.
    let pointer = port.pointer;
    drop(port);
    let _ = state::handler("NtClose").map(|close| close(handle, 0, 0, 0, block + 0x1800));
    transport::unregister(&listener);
    assert(port_objects::port_of(pointer).is_none() && transport::listener_of(listener.node).is_none(), "useralpcconn: porta e endpoint retirados");
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn user_alpc_message_handles(assert: Assert) {
    use crate::ntos::alpc::message::{handles as message_handles, identity as message_identity, security as message_security};
    use crate::ntos::alpc::query_message;
    use crate::ntos::ob::open_pointer;
    use crate::ntos::ob::objects::port::{self as port_objects, PortState, Role};
    use crate::ntos::ps::user::memory;
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "useralpchnd: memoria de usuario");
        return;
    };
    let Ok(port) = port_objects::create("alpc", PortState { role: Role::Listener, duplicate_object_types: 0xFFD, ..PortState::default() }, 0x200, 0, 0, alloc::boxed::Box::new(|_| {}), port_objects::CreateOptions::default()) else {
        assert(false, "useralpchnd: porta de escuta");
        return;
    };
    let _ = port_objects::publish(&port, block, 0);
    let handle = guest::read64(block);
    // Evento de origem.
    guest::write64(block + 0x828, 0);
    let created = state::handler("NtCreateEvent").map(|create| create(block + 8, 0x1F_0003, 0, 0, block + 0x800));
    let event = guest::read64(block + 8);
    assert(matches!(created, Some(Ok(0))) && event != 0, "useralpchnd: evento de origem");
    // Formato simples.
    let attribute = block + 0x100;
    let handle_attribute = unsafe { nt::AlpcHandleAttr::at(attribute) };
    let simple = |flags: u32, value: u64, access: u32| {
        handle_attribute.flags.set(flags);
        handle_attribute.handle.set(value);
        handle_attribute.object_type.set(0);
        handle_attribute.desired_access.set(access);
        message_handles::capture(attribute, 1).ok()
    };
    let captured = simple(0, event, 0x10_0002).and_then(|result| result.ok());
    let summary = captured.as_ref().and_then(|data| data.entries.lock().first().map(|entry| (entry.object_type, entry.access, entry.item.object_type.name.clone())));
    assert(summary.as_ref().is_some_and(|(code, access, name)| *code == 0x10 && *access == 0x10_0002 && name == "Event"), "useralpchnd: handle de evento capturado com o acesso pedido");
    let same = simple(0x1_0000, event, 0).and_then(|result| result.ok());
    let same_access = same.as_ref().and_then(|data| data.entries.lock().first().map(|entry| entry.access));
    if let Some(data) = &same {
        message_identity::Retained::release(data.as_ref());
    }
    let pseudo = simple(0, u64::MAX, 0x1000).and_then(|result| result.ok());
    let pseudo_summary = pseudo.as_ref().and_then(|data| data.entries.lock().first().map(|entry| (entry.object_type, entry.access)));
    if let Some(data) = &pseudo {
        message_identity::Retained::release(data.as_ref());
    }
    assert(same_access == Some(0x1F_0003) && pseudo_summary == Some((0x20, 0x1000)), "useralpchnd: mesmo acesso e pseudo-handle de processo");
    let refusals = (simple(0x100, event, 0).and_then(|result| result.err()), simple(0, event, 0x20_0000).and_then(|result| result.err()), simple(0, 0x7FFF_0000, 0x10_0002).and_then(|result| result.err()), simple(0, 0x1_0000_0000, 0x10_0002).and_then(|result| result.err()), simple(0, event, 0x1F_0003 | 0x0100_0000).and_then(|result| result.err()));
    assert(refusals == (Some(0xC000_000D), Some(0xC000_0022), Some(0xC000_0008), Some(0xC000_0008), Some(0xC000_0022)), "useralpchnd: recusas da captura simples");
    // Forma indireta.
    let array = block + 0x200;
    for entry in unsafe { nt::AlpcHandleAttr32::array_at(array, 2) } {
        entry.flags.set(0);
        entry.handle.set(event as u32);
        entry.object_type.set(0);
        entry.desired_access.set(0x10_0000);
    }
    let indirect = |count: u32| {
        handle_attribute.flags.set(0x4_0000);
        handle_attribute.handle_attr_array.set(array);
        handle_attribute.handle_count.set(count);
        message_handles::capture(attribute, 1).ok()
    };
    let pair = indirect(2).and_then(|result| result.ok());
    let pair_count = pair.as_ref().map(|data| data.entries.lock().len());
    if let Some(data) = &pair {
        message_identity::Retained::release(data.as_ref());
    }
    assert(pair_count == Some(2) && indirect(1).and_then(|result| result.err()) == Some(0xC000_000D) && indirect(513).and_then(|result| result.err()) == Some(0xC000_0722), "useralpchnd: forma indireta com 2..512 entradas");
    // Consulta de mensagem: duplicação na tabela do dono da porta.
    let Some(captured) = captured else {
        assert(false, "useralpchnd: captura disponivel");
        return;
    };
    let Ok(Some(identity)) = message_identity::activate(&port, None) else {
        assert(false, "useralpchnd: identidade de mensagem");
        return;
    };
    identity.with(|state| state.handles = Some(captured.clone()));
    let message = block + 0x300;
    let selector = unsafe { nt::PortMessage::at(message) };
    selector.u2.s2.type_.set(1);
    selector.message_id.set(identity.identifier);
    selector.callback_id.set(identity.callback);
    let (output, returned) = (block + 0x400, block + 0x480);
    let handle_info = unsafe { nt::AlpcMessageHandleInformation::at(output) };
    handle_info.index.set(0);
    let queried = query_message::query(handle, message, 3, output, 20, returned, 1, None).ok();
    let duplicated = handle_info.handle.get() as u64;
    // O dono da porta é o System nestes testes: o ULONG traz o bit de kernel.
    let system_owner = port.process_pointer == crate::ntos::ps::process::get_system_process();
    let kernel = duplicated & 0x8000_0000 != 0;
    let duplicated = if kernel { 0xFFFF_FFFF_0000_0000 | duplicated } else { duplicated };
    let resolved = open_pointer::resolve(duplicated, !kernel).and_then(|resolved| resolved.ok()).map(|resolved| resolved.access);
    assert(queried == Some(0) && kernel == system_owner && duplicated != 0 && duplicated != event && handle_info.object_type.get() == 0x10 && handle_info.granted_access.get() == 0x10_0002 && guest::read32(returned) == 20 && resolved == Some(0x10_0002), "useralpchnd: handle duplicado na tabela do dono");
    let _ = open_pointer::close(duplicated);
    handle_info.index.set(5);
    let missing = query_message::query(handle, message, 3, output, 20, returned, 1, None).ok();
    handle_info.index.set(0);
    let short = query_message::query(handle, message, 3, output, 16, returned, 1, None).ok();
    port.with(|state| state.duplicate_object_types = 0x20);
    let kind = query_message::query(handle, message, 3, output, 20, returned, 1, None).ok();
    port.with(|state| state.duplicate_object_types = 0xFFD);
    assert(missing == Some(0xC000_0008) && short == Some(0xC000_0004) && kind == Some(0xC000_0024), "useralpchnd: indice ausente, tamanho e especie recusada");
    // Classes de token e de evento direto.
    let anonymous = query_message::query(handle, message, 0, output, 64, returned, 1, None).ok();
    let security = block + 0x500;
    let security_attribute = unsafe { nt::AlpcSecurityAttr::at(security) };
    security_attribute.flags.set(0);
    security_attribute.p_qos.set(0);
    security_attribute.context_handle.set(0xFFFF_FFFF_FFFF_FFFE);
    if let Ok(Ok(message_security::Captured::Borrowed(borrowed))) = message_security::capture(&port, security, 1) {
        identity.with(|state| state.security = Some(borrowed));
    }
    let user = crate::ntos::ps::process::get_primary_token(crate::ntos::ps::process::get_current_process()).and_then(|token| crate::ntos::se::token::tokens::with(token, |token| token.user.clone())).unwrap_or_default();
    let sid_status = query_message::query(handle, message, 0, output, 64, returned, 1, None).ok();
    let sid: alloc::vec::Vec<u8> = guest::read_bytes(output, user.len());
    let sid_length = guest::read32(returned);
    let modified_short = query_message::query(handle, message, 1, output, 4, returned, 1, None).ok();
    let modified_short_length = guest::read32(returned);
    let modified = query_message::query(handle, message, 1, output, 8, returned, 1, None).ok();
    assert(anonymous == Some(0xC000_0022) && sid_status == Some(0) && sid == user && sid_length == user.len() as u32 && modified_short == Some(0xC000_0023) && modified_short_length == 8 && modified == Some(0), "useralpchnd: SID e ModifiedId do contexto da mensagem");
    let direct = query_message::query(handle, message, 2, 0, 0, 0, 1, None).ok();
    let direct_args = query_message::query(handle, message, 2, output, 0, 0, 1, None).ok();
    selector.message_id.set(0);
    let zero = query_message::query(handle, message, 3, output, 20, returned, 1, None).ok();
    selector.message_id.set(identity.identifier);
    selector.callback_id.set(identity.callback.wrapping_add(1));
    let wrong = query_message::query(handle, message, 3, output, 20, returned, 1, None).ok();
    selector.callback_id.set(identity.callback);
    identity.with(|state| state.canceled = true);
    let canceled = query_message::query(handle, message, 3, output, 20, returned, 1, None).ok();
    identity.with(|state| state.canceled = false);
    assert(direct == Some(0x103) && direct_args == Some(0xC000_000D) && zero == Some(0xC000_000D) && wrong == Some(0xC000_0702) && canceled == Some(0xC000_0703) && state::handler("NtAlpcQueryInformationMessage").is_some(), "useralpchnd: classe de evento direto e recusas da selecao");
    // Liberação: a mensagem devolve handles e contexto.
    let _ = message_identity::release(&identity);
    let released = identity.with(|state| state.handles.is_none() && state.security.is_none());
    drop(captured);
    let pointer = port.pointer;
    drop(port);
    let close = state::handler("NtClose");
    let _ = close.map(|close| close(handle, 0, 0, 0, block + 0x800));
    let _ = close.map(|close| close(event, 0, 0, 0, block + 0x800));
    assert(released && port_objects::port_of(pointer).is_none(), "useralpchnd: mensagem liberada e porta destruida");
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

static ALPC_TRANSPORT_CLEANUP: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);
static ALPC_TRANSPORT_DISCONNECTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

struct AlpcTransportJob {
    polls: u32,
    data: alloc::vec::Vec<u8>,
}

impl crate::ntos::alpc::transport::Job for AlpcTransportJob {
    fn poll(&mut self) -> Option<crate::ntos::alpc::transport::JobResult> {
        self.polls += 1;
        (self.polls >= 2).then(|| crate::ntos::alpc::transport::JobResult { status: 0, data: self.data.clone(), sender: None })
    }
    fn cleanup(&mut self, status: u32) {
        ALPC_TRANSPORT_CLEANUP.store(status, core::sync::atomic::Ordering::SeqCst);
    }
}

struct AlpcTransportService;

impl crate::ntos::alpc::transport::Service for AlpcTransportService {
    fn max_message_length(&self) -> u32 {
        0x200
    }
    fn connect(&self, _port: &alloc::sync::Arc<crate::ntos::ob::objects::port::Port>, _data: &[u8], _request: Option<&[u8]>) -> crate::ntos::alpc::transport::Reply {
        crate::ntos::alpc::transport::Reply::Now(crate::ntos::alpc::transport::JobResult { status: 0, data: alloc::vec![0xC0, 0x01], sender: None })
    }
    fn exchange(&self, _port: &alloc::sync::Arc<crate::ntos::ob::objects::port::Port>, data: &[u8], _request: &alloc::sync::Arc<crate::ntos::alpc::transport::Request>) -> crate::ntos::alpc::transport::Reply {
        let reversed: alloc::vec::Vec<u8> = data.iter().rev().copied().collect();
        if data.first() == Some(&0xDD) {
            return crate::ntos::alpc::transport::Reply::Later(alloc::boxed::Box::new(AlpcTransportJob { polls: 0, data: reversed }));
        }
        crate::ntos::alpc::transport::Reply::Now(crate::ntos::alpc::transport::JobResult { status: 0, data: reversed, sender: None })
    }
    fn disconnect(&self, _port: &alloc::sync::Arc<crate::ntos::ob::objects::port::Port>) {
        ALPC_TRANSPORT_DISCONNECTED.store(true, core::sync::atomic::Ordering::SeqCst);
    }
}

fn user_alpc_transport(assert: Assert) {
    use crate::ntos::alpc::{kernel_entry, transport};
    use crate::ntos::ob::objects::port as port_objects;
    use crate::ntos::ps::user::{alpc, memory};
    use core::sync::atomic::Ordering;
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "useralpctrn: memoria de usuario");
        return;
    };
    ALPC_TRANSPORT_DISCONNECTED.store(false, Ordering::SeqCst);
    let path = "\\RPC Control\\OpenNtTesteTransporte";
    let Ok(listener) = transport::register(path, alloc::sync::Arc::new(AlpcTransportService)) else {
        assert(false, "useralpctrn: endpoint registrado");
        return;
    };
    let unicode = |at: u64, buffer: u64, text: &str| {
        let length = write_wide(buffer, text);
        set_unicode(unsafe { nt::UnicodeString::at(at) }, length, length, buffer);
    };
    let message = |at: u64, data: &[u8]| {
        init_port_message(unsafe { nt::PortMessage::at(at) }, data.len() as u16, data.len() as u16 + nt::PortMessage::SIZE as u16);
        guest::write_bytes(at + nt::PortMessage::SIZE, data);
    };
    let rsp = block + 0x800;
    let stack = |args: &[u64]| {
        for (index, value) in args.iter().enumerate() {
            guest::write64(rsp + 0x28 + index as u64 * 8, *value);
        }
    };
    let read = |at: u64, length: u64| -> alloc::vec::Vec<u8> { guest::read_bytes(at, length as usize) };
    let call = |name: &str, a: u64, b: u64, c: u64, d: u64| state::handler(name).map(|handler| handler(a, b, c, d, rsp)).and_then(|result| result.ok());
    // Conexão com mensagem e atributos de recepção.
    let name = block + 0x10;
    unicode(name, block + 0x40, path);
    let connection = block + 0x100;
    message(connection, &[7, 8]);
    guest::write64(block + 0x1F0, 0x100);
    let receive = block + 0x200;
    let receive_attributes = unsafe { nt::AlpcMessageAttributes::at(receive) };
    receive_attributes.allocated_attributes.set(0x2000_0000);
    receive_attributes.valid_attributes.set(0);
    stack(&[0, 0, connection, block + 0x1F0, 0, receive]);
    let connected = call("NtAlpcConnectPort", block + 8, name, 0, 0);
    let handle = guest::read64(block + 8);
    let port = port_objects::resolve(handle, "alpc").map(|(_, port)| port);
    assert(connected == Some(0) && port.is_some() && unsafe { nt::PortMessage::at(connection) }.u2.s2.type_.get() == 10 && read(connection + nt::PortMessage::SIZE, 2) == [0xC0, 0x01] && guest::read64(block + 0x1F0) == 42 && receive_attributes.valid_attributes.get() == 0x2000_0000 && unsafe { nt::AlpcContextAttr::at(receive + nt::AlpcMessageAttributes::SIZE) }.port_context.get() == handle, "useralpctrn: conexao com resposta e contexto da porta");
    let Some(port) = port else { return };
    unicode(name, block + 0x40, "\\RPC Control\\NaoExiste");
    let missing = call("NtAlpcConnectPort", block + 0x18, name, 0, 0);
    unicode(name, block + 0x40, path);
    stack(&[0x1_0000]);
    let bad_flags = call("NtAlpcConnectPort", block + 0x18, name, 0, 0);
    let sid = block + 0x180;
    guest::write_bytes(sid, &[1u8, 1, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0]);
    stack(&[0, sid]);
    let bad_sid = call("NtAlpcConnectPort", block + 0x18, name, 0, 0);
    assert(missing == Some(0xC000_0034) && bad_flags == Some(0xC000_00BB) && bad_sid == Some(0xC000_0257), "useralpctrn: recusas da conexao");
    // Troca síncrona.
    let (input, output, length) = (block + 0x300, block + 0x400, block + 0x3F0);
    message(input, &[1, 2, 3]);
    guest::write64(length, 0x100);
    stack(&[output, length, 0, 0]);
    let synchronous = call("NtAlpcSendWaitReceivePort", handle, 0x2_0000, input, 0);
    assert(synchronous == Some(0) && unsafe { nt::PortMessage::at(output) }.u2.s2.type_.get() == 2 && read(output + nt::PortMessage::SIZE, 3) == [3, 2, 1] && port.with(|state| state.pending.is_empty()), "useralpctrn: troca sincrona com resposta do servico");
    // Envio assíncrono e recepção posterior.
    let sequence = port.sequence();
    stack(&[0, 0, 0, 0]);
    message(input, &[4, 5]);
    let sent = call("NtAlpcSendWaitReceivePort", handle, 0, input, 0);
    let queued = port.with(|state| state.pending.len());
    stack(&[output, length, 0, 0]);
    let received = call("NtAlpcSendWaitReceivePort", handle, 0, 0, 0);
    assert(sent == Some(0) && queued == 1 && received == Some(0) && read(output + nt::PortMessage::SIZE, 2) == [5, 4] && port.sequence() == sequence.wrapping_add(1) && port.with(|state| state.pending.is_empty()), "useralpctrn: envio assincrono e recepcao da fila");
    // Trabalho adiado pelo pump.
    ALPC_TRANSPORT_CLEANUP.store(u32::MAX, Ordering::SeqCst);
    stack(&[0, 0, 0, 0]);
    message(input, &[0xDD, 6]);
    let deferred = call("NtAlpcSendWaitReceivePort", handle, 0, input, 0);
    let jobs = port.with(|state| state.jobs.len());
    alpc::pump();
    let after_first = port.with(|state| (state.jobs.len(), state.pending.len()));
    alpc::pump();
    let after_second = port.with(|state| (state.jobs.len(), state.pending.len()));
    stack(&[output, length, 0, 0]);
    let drained = call("NtAlpcSendWaitReceivePort", handle, 0, 0, 0);
    assert(deferred == Some(0) && jobs == 1 && after_first == (1, 0) && after_second == (0, 1) && ALPC_TRANSPORT_CLEANUP.load(Ordering::SeqCst) == 0 && drained == Some(0) && read(output + nt::PortMessage::SIZE, 2) == [6, 0xDD], "useralpctrn: trabalho adiado concluido pelo pump");
    // Cancelamento de um pedido entregue.
    ALPC_TRANSPORT_CLEANUP.store(u32::MAX, Ordering::SeqCst);
    stack(&[0, 0, 0, 0]);
    message(input, &[0xDD, 9]);
    let _ = call("NtAlpcSendWaitReceivePort", handle, 0, input, 0);
    let identity = port.with(|state| state.jobs.first().map(|request| request.identity.clone()));
    let context = block + 0x500;
    let cancel_attribute = unsafe { nt::AlpcContextAttr::at(context) };
    cancel_attribute.message_context.set(0);
    cancel_attribute.message_id.set(identity.as_ref().map_or(0, |identity| identity.identifier));
    cancel_attribute.callback_id.set(identity.as_ref().map_or(0, |identity| identity.callback));
    let canceled = call("NtAlpcCancelMessage", handle, 0, context, 0);
    let again = call("NtAlpcCancelMessage", handle, 0, context, 0);
    alpc::pump();
    alpc::pump();
    assert(canceled == Some(0x4000_002E) && again == Some(0xC000_0703) && ALPC_TRANSPORT_CLEANUP.load(Ordering::SeqCst) == 0xC000_0703 && port.with(|state| state.jobs.is_empty() && state.pending.is_empty()), "useralpctrn: cancelamento recusa a resposta tardia");
    // Recusas da troca.
    message(input, &[1]);
    unsafe { nt::PortMessage::at(input) }.client_id.unique_process.set(0x44);
    stack(&[0, 0, 0, 0]);
    let cid = call("NtAlpcSendWaitReceivePort", handle, 0, input, 0);
    message(input, &[1]);
    let no_input = call("NtAlpcSendWaitReceivePort", handle, 0x2_0000, 0, 0);
    let unsupported = call("NtAlpcSendWaitReceivePort", handle, 0x4000_0000, input, 0);
    let empty = call("NtAlpcSendWaitReceivePort", handle, 0, 0, 0);
    assert(cid == Some(0xC000_0702) && no_input == Some(0xC000_00F0) && unsupported == Some(0xC000_00BB) && empty == Some(0), "useralpctrn: recusas da troca");
    // Troca de kernel pela entrada instalada.
    message(input, &[0xA, 0xB]);
    let kernel = kernel_entry::begin(&[handle, 0x2_0000, input, 0, output, length, 0, 0]).ok().and_then(|mut pending| pending.poll());
    assert(kernel == Some(0) && read(output + nt::PortMessage::SIZE, 2) == [0xB, 0xA], "useralpctrn: troca de kernel imediata");
    // Desconexão e fechamento.
    let disconnected = call("NtAlpcDisconnectPort", handle, 0, 0, 0);
    stack(&[0, 0, 0, 0]);
    let after = call("NtAlpcSendWaitReceivePort", handle, 0, input, 0);
    let pointer = port.pointer;
    drop(port);
    drop(identity);
    let _ = call("NtClose", handle, 0, 0, 0);
    transport::unregister(&listener);
    assert(disconnected == Some(0) && after == Some(0xC000_0037) && ALPC_TRANSPORT_DISCONNECTED.load(Ordering::SeqCst) && port_objects::port_of(pointer).is_none(), "useralpctrn: desconexao, fechamento e desconexao do servico");
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

static ALPC_CONNECT_STATUS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static ALPC_CONNECT_DEFERRED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static ALPC_CONNECT_DISCONNECTS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

struct AlpcConnectJob {
    polls: u32,
}

impl crate::ntos::alpc::transport::Job for AlpcConnectJob {
    fn poll(&mut self) -> Option<crate::ntos::alpc::transport::JobResult> {
        self.polls += 1;
        (self.polls >= 2).then(|| crate::ntos::alpc::transport::JobResult { status: 0, data: alloc::vec![0xAA], sender: None })
    }
}

struct AlpcConnectService;

impl crate::ntos::alpc::transport::Service for AlpcConnectService {
    fn max_message_length(&self) -> u32 {
        0x200
    }
    fn connect(&self, _port: &alloc::sync::Arc<crate::ntos::ob::objects::port::Port>, data: &[u8], request: Option<&[u8]>) -> crate::ntos::alpc::transport::Reply {
        use core::sync::atomic::Ordering;
        if ALPC_CONNECT_DEFERRED.load(Ordering::SeqCst) {
            return crate::ntos::alpc::transport::Reply::Later(alloc::boxed::Box::new(AlpcConnectJob { polls: 0 }));
        }
        // A carga chega também no PORT_MESSAGE montado (tipo de conexão).
        let typed = request.is_some_and(|bytes| bytes.len() == 40 + data.len() && u16::from_le_bytes([bytes[4], bytes[5]]) & 0xFFF == 0xA);
        let status = if typed { ALPC_CONNECT_STATUS.load(Ordering::SeqCst) } else { 0xC000_0001 };
        crate::ntos::alpc::transport::Reply::Now(crate::ntos::alpc::transport::JobResult { status, data: alloc::vec![0x11, 0x22], sender: None })
    }
    fn exchange(&self, _port: &alloc::sync::Arc<crate::ntos::ob::objects::port::Port>, data: &[u8], _request: &alloc::sync::Arc<crate::ntos::alpc::transport::Request>) -> crate::ntos::alpc::transport::Reply {
        crate::ntos::alpc::transport::Reply::Now(crate::ntos::alpc::transport::JobResult { status: 0, data: data.to_vec(), sender: None })
    }
    fn disconnect(&self, _port: &alloc::sync::Arc<crate::ntos::ob::objects::port::Port>) {
        ALPC_CONNECT_DISCONNECTS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    }
}

fn user_alpc_connect_port(assert: Assert) {
    use crate::ntos::alpc::{kernel_entry, transport};
    use crate::ntos::ob::open_pointer;
    use crate::ntos::ob::objects::port as port_objects;
    use crate::ntos::ps::user::{alpc, memory};
    use core::sync::atomic::Ordering;
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "useralpccp: memoria de usuario");
        return;
    };
    ALPC_CONNECT_STATUS.store(0, Ordering::SeqCst);
    ALPC_CONNECT_DEFERRED.store(false, Ordering::SeqCst);
    ALPC_CONNECT_DISCONNECTS.store(0, Ordering::SeqCst);
    let path = "\\RPC Control\\OpenNtTesteConexao";
    let Ok(listener) = transport::register(path, alloc::sync::Arc::new(AlpcConnectService)) else {
        assert(false, "useralpccp: endpoint registrado");
        return;
    };
    let name = block + 0x10;
    let length = write_wide(block + 0x40, path);
    set_unicode(unsafe { nt::UnicodeString::at(name) }, length, length, block + 0x40);
    let connection = block + 0x100;
    let capacity = block + 0x1F0;
    let prepare = || {
        guest::write_bytes(connection, &[0u8; 0x60]);
        let header = unsafe { nt::PortMessage::at(connection) };
        header.u1.s1.data_length.set(2);
        header.u1.s1.total_length.set(42);
        guest::write_bytes(connection + nt::PortMessage::SIZE, &[1, 2]);
        guest::write64(capacity, 0x100);
    };
    let read = |at: u64, length: u64| -> alloc::vec::Vec<u8> { guest::read_bytes(at, length as usize) };
    let connect = |output: u64, flags: u64, extended: bool, target: u64| {
        let arguments = [output, target, 0, 0, flags, 0, connection, capacity, 0, 0, 0];
        let begun = if extended { kernel_entry::begin_connection_ex(&arguments) } else { kernel_entry::begin_connection(&arguments) };
        begun.ok().map(|mut pending| {
            for _ in 0..64 {
                if let Some(status) = pending.poll() {
                    return status;
                }
                alpc::pump();
            }
            pending.cancel();
            0x102
        })
    };
    let (output, length) = (block + 0x400, block + 0x3F0);
    let receive = |handle: u64| {
        guest::write64(length, 0x100);
        kernel_entry::begin(&[handle, 0, 0, 0, output, length, 0, 0]).ok().and_then(|mut pending| pending.poll())
    };
    // Conexão assíncrona: a resposta fica na fila da porta.
    prepare();
    let asynchronous = connect(block + 0x600, 0, false, name);
    let first = guest::read64(block + 0x600);
    let first_port = port_objects::port_of(open_pointer::resolve(first, false).and_then(|resolved| resolved.ok()).map_or(0, |resolved| resolved.item.pointer));
    let state = first_port.as_ref().map(|port| port.with(|state| (state.connection_state, state.pending.len(), state.role)));
    let received = receive(first);
    assert(asynchronous == Some(0) && first != 0 && state == Some((port_objects::CONNECTION_CONNECTED, 1, port_objects::Role::Client)) && received == Some(0) && unsafe { nt::PortMessage::at(output) }.u2.s2.type_.get() == 11 && read(output + nt::PortMessage::SIZE, 2) == [0x11, 0x22], "useralpccp: conexao assincrona com resposta na fila");
    // Conexão síncrona: a resposta chega no buffer da mensagem.
    prepare();
    let synchronous = connect(block + 0x608, 0x2_0000, false, name);
    let second = guest::read64(block + 0x608);
    assert(synchronous == Some(0) && second != 0 && second != first && unsafe { nt::PortMessage::at(connection) }.u2.s2.type_.get() == 11 && read(connection + nt::PortMessage::SIZE, 2) == [0x11, 0x22] && unsafe { nt::PortMessage::at(connection) }.client_id.unique_process.get() == crate::ntos::ps::process::get_current_process_id(), "useralpccp: conexao sincrona com resposta do servidor");
    // Recusa do servidor: o handle não é publicado.
    ALPC_CONNECT_STATUS.store(0xC000_0041, Ordering::SeqCst);
    prepare();
    guest::write64(block + 0x610, 0);
    let refused = connect(block + 0x610, 0x2_0000, false, name);
    ALPC_CONNECT_STATUS.store(0, Ordering::SeqCst);
    assert(refused == Some(0xC000_0041) && guest::read64(block + 0x610) == 0, "useralpccp: recusa do servidor sem publicar o handle");
    // Decisão adiada: a porta fica pendente até o pump.
    ALPC_CONNECT_DEFERRED.store(true, Ordering::SeqCst);
    prepare();
    let deferred = kernel_entry::begin_connection(&[block + 0x618, name, 0, 0, 0, 0, connection, capacity, 0, 0, 0]).ok().and_then(|mut pending| pending.poll());
    ALPC_CONNECT_DEFERRED.store(false, Ordering::SeqCst);
    let third = guest::read64(block + 0x618);
    let third_port = port_objects::port_of(open_pointer::resolve(third, false).and_then(|resolved| resolved.ok()).map_or(0, |resolved| resolved.item.pointer));
    let pending_state = third_port.as_ref().map(|port| port.with(|state| state.connection_state));
    let input = block + 0x300;
    init_port_message(unsafe { nt::PortMessage::at(input) }, 1, 41);
    let blocked = kernel_entry::begin(&[third, 0, input, 0, 0, 0, 0, 0]).ok().and_then(|mut pending| pending.poll());
    alpc::pump();
    alpc::pump();
    let decided = third_port.as_ref().map(|port| port.with(|state| (state.connection_state, state.pending.len())));
    let late = receive(third);
    assert(deferred == Some(0) && pending_state == Some(port_objects::CONNECTION_PENDING) && blocked == Some(0xC000_0707) && decided == Some((port_objects::CONNECTION_CONNECTED, 1)) && late == Some(0) && read(output + nt::PortMessage::SIZE, 1) == [0xAA], "useralpccp: decisao adiada concluida pelo pump");
    // Variante Ex: OBJECT_ATTRIBUTES da porta de conexão.
    let attributes = block + 0x500;
    set_object_attributes(unsafe { nt::ObjectAttributes::at(attributes) }, nt::ObjectAttributes::SIZE as u32, 0, name, 0);
    prepare();
    let extended = connect(block + 0x620, 0x2_0000, true, attributes);
    let fourth = guest::read64(block + 0x620);
    assert(extended == Some(0) && fourth != 0 && read(connection + nt::PortMessage::SIZE, 2) == [0x11, 0x22], "useralpccp: conexao Ex pelo OBJECT_ATTRIBUTES");
    // Fechamento: cada porta iniciada desconecta o serviço.
    drop(first_port);
    drop(third_port);
    for handle in [first, second, third, fourth] {
        let _ = open_pointer::close(handle);
    }
    transport::unregister(&listener);
    let disconnects = ALPC_CONNECT_DISCONNECTS.load(Ordering::SeqCst);
    assert(disconnects >= 4, "useralpccp: portas fechadas desconectam o servico");
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn user_lpc_csr(assert: Assert) {
    use crate::ntos::ob::objects::port as port_objects;
    use crate::ntos::ps::user::{csr, memory};
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "userlpc: memoria de usuario");
        return;
    };
    let _ = csr::initialize();
    let rsp = block + 0x800;
    let stack = |args: &[u64]| {
        for (index, value) in args.iter().enumerate() {
            guest::write64(rsp + 0x28 + index as u64 * 8, *value);
        }
    };
    let call = |name: &str, a: u64, b: u64, c: u64, d: u64| state::handler(name).map(|handler| handler(a, b, c, d, rsp)).and_then(|result| result.ok());
    let unicode = |at: u64, buffer: u64, text: &str| {
        let length = write_wide(buffer, text);
        set_unicode(unsafe { nt::UnicodeString::at(at) }, length, length, buffer);
    };
    // Seção de transferência do cliente.
    unsafe { nt::LargeInteger::at(block + 0x10) }.quad_part.set(0x1_0000);
    stack(&[4, 0x0800_0000, 0]);
    let created = call("NtCreateSection", block + 0x18, 0xF_001F, 0, block + 0x10);
    let section = guest::read64(block + 0x18);
    // Conexão ao ApiPort.
    let name = block + 0x20;
    unicode(name, block + 0x40, "\\Windows\\ApiPort");
    let qos = block + 0x100;
    let quality = unsafe { nt::SecurityQualityOfService::at(qos) };
    quality.length.set(nt::SecurityQualityOfService::SIZE as u32);
    quality.impersonation_level.set(nt::SecurityImpersonationLevel::SECURITY_IMPERSONATION);
    quality.context_tracking_mode.set(0);
    quality.effective_only.set(0);
    let view = block + 0x120;
    let client_view = unsafe { nt::PortView::at(view) };
    client_view.length.set(nt::PortView::SIZE as u32);
    client_view.section_handle.set(section);
    client_view.section_offset.set(0);
    client_view.view_size.set(0x1_0000);
    let info = block + 0x180;
    guest::write_bytes(info, &[0u8; CsrConnectionInformation::SIZE as usize]);
    let connection_info = unsafe { CsrConnectionInformation::at(info) };
    connection_info.server_id.set(1);
    connection_info.server_data.set(0x1234);
    let (max_length, info_length) = (block + 0x1C0, block + 0x1C8);
    guest::write32(info_length, 48);
    stack(&[0, max_length, info, info_length]);
    let connected = call("NtConnectPort", block + 0x8, name, qos, view);
    let handle = guest::read64(block + 0x8);
    let port = port_objects::resolve(handle, "port").map(|(_, port)| port);
    let process_id = port.as_ref().map_or(0, |port| port.process_id());
    let (local, remote) = (client_view.view_base.get(), client_view.view_remote_base.get());
    let client = csr::client(process_id);
    assert(created == Some(0) && connected == Some(0) && port.is_some() && connection_info.server_process_id.get() == 4 && connection_info.status.get() == 0 && connection_info.shared_section_base.get() != 0 && guest::read32(max_length) == 0x3B8 && guest::read32(info_length) == 48 && local != 0 && remote != 0 && local != remote && client.as_ref().is_some_and(|(_, servers, callback)| servers == &[1] && *callback == 0x1234), "userlpc: conexao CSR com os dois aliases da secao");
    let Some(port) = port else { return };
    // Registro de servidor com carga no alias supervisor.
    guest::write64(local + 0x100, 0x5678);
    let message = |at: u64, id: u32, pointer: u64, size: u32| {
        guest::write_bytes(at, &[0u8; CsrClientConnectMessage::SIZE as usize]);
        let request = unsafe { CsrClientConnectMessage::at(at) };
        request.header.u1.s1.data_length.set((CsrClientConnectMessage::SIZE - nt::PortMessage::SIZE) as i16);
        request.header.u1.s1.total_length.set(CsrClientConnectMessage::SIZE as i16);
        request.api_number.set(0);
        request.server_id.set(id);
        request.connection_information.set(pointer);
        request.connection_information_length.set(size);
    };
    let (input, output) = (block + 0x300, block + 0x400);
    let reply = unsafe { CsrClientConnectMessage::at(output) };
    message(input, 1, remote + 0x100, 8);
    let registered = call("NtRequestWaitReplyPort", handle, input, output, 0);
    let registered_status = reply.return_value.get();
    let reply_type = reply.header.u2.s2.type_.get();
    let callback = csr::client(process_id).map(|(_, _, callback)| callback);
    message(input, 1, local + 0x100, 8);
    let _ = call("NtRequestWaitReplyPort", handle, input, output, 0);
    let outside = reply.return_value.get();
    message(input, 2, remote + 0x100, 8);
    let _ = call("NtRequestWaitReplyPort", handle, input, output, 0);
    let unknown = reply.return_value.get();
    message(input, 3, remote + 0x100, 8);
    let _ = call("NtRequestWaitReplyPort", handle, input, output, 0);
    let user_size = reply.return_value.get();
    assert(registered == Some(0) && registered_status == 0 && reply_type == 2 && callback == Some(0x5678) && outside == 0xC000_000D && unknown == 0xC000_0002 && user_size == 0xC000_000D && reply.header.message_id.get() != 0, "userlpc: registro de servidor pelo alias supervisor e recusas");
    // Fallback LPC do NtAlpcSendWaitReceivePort.
    message(input, 1, remote + 0x100, 8);
    let length = block + 0x3F0;
    guest::write64(length, 0x100);
    stack(&[output, length, 0, 0]);
    let alpc = call("NtAlpcSendWaitReceivePort", handle, 0x2_0000, input, 0);
    let alpc_length = guest::read64(length);
    guest::write64(length, 40);
    let short = call("NtAlpcSendWaitReceivePort", handle, 0x2_0000, input, 0);
    let short_length = guest::read64(length);
    let flags = call("NtAlpcSendWaitReceivePort", handle, 0x1_0000, input, 0);
    unsafe { nt::PortMessage::at(input) }.u1.s1.total_length.set(87);
    let malformed = call("NtRequestWaitReplyPort", handle, input, output, 0);
    assert(alpc == Some(0) && alpc_length == 88 && short == Some(0xC000_0023) && short_length == 88 && flags == Some(0xC000_00BB) && malformed == Some(0xC000_0021), "userlpc: pedido LPC pelo NtAlpcSendWaitReceivePort e recusas");
    // Recusas da conexão.
    stack(&[0, max_length, info, info_length]);
    unicode(name, block + 0x40, "\\Windows\\NaoExiste");
    let missing = call("NtConnectPort", block + 0x1D0, name, qos, 0);
    unicode(name, block + 0x40, "\\Windows\\ApiPort");
    guest::write32(info_length, 49);
    let too_long = call("NtConnectPort", block + 0x1D0, name, qos, 0);
    guest::write32(info_length, 48);
    quality.impersonation_level.set(nt::SecurityImpersonationLevel(4));
    let level = call("NtConnectPort", block + 0x1D0, name, qos, 0);
    quality.impersonation_level.set(nt::SecurityImpersonationLevel::SECURITY_IMPERSONATION);
    stack(&[block + 0x100]);
    let secure = call("NtSecureConnectPort", block + 0x1D0, name, qos, 0);
    stack(&[0, max_length, info, info_length]);
    let no_views = call("NtConnectPort", block + 0x1D0, name, qos, 0);
    assert(missing == Some(0xC000_0034) && too_long == Some(0xC000_000D) && level == Some(0xC000_000D) && secure == Some(0xC000_00BB) && no_views == Some(0xC000_000D), "userlpc: recusas da conexao");
    // Fechamento: o serviço desconecta e as vistas saem.
    let pointer = port.pointer;
    drop(port);
    let _ = call("NtClose", handle, 0, 0, 0);
    let _ = call("NtClose", section, 0, 0, 0);
    assert(port_objects::port_of(pointer).is_none() && csr::client(process_id).is_none(), "userlpc: fechamento desconecta o cliente CSR");
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn user_alpc_zw_group(assert: Assert) {
    use crate::hal::amd64::{native_call, win32_thunk};
    use crate::ntos::alpc::transport;
    use crate::ntos::ob::open_pointer;
    use crate::ntos::ob::objects::port as port_objects;
    use crate::ntos::ps::user::memory;
    use crate::ntos::init::exports;
    use crate::ntos::mm::pe_loader::ResolvedImport;
    let zw = |name: &str, arguments: &[u64]| -> Option<u32> {
        let Some(ResolvedImport::Thunk(id)) = exports::lookup("ntoskrnl.exe", name) else { return None };
        let (table, _) = win32_thunk::thunk_table();
        let address = crate::ntos::mm::kernel_address::image_address(table + id as u64 * win32_thunk::STUB_SIZE).ok()?;
        Some(native_call::call(address, arguments) as u32)
    };
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "zwalpc: memoria");
        return;
    };
    let path = "\\RPC Control\\OpenNtTesteZw";
    let Ok(listener) = transport::register(path, alloc::sync::Arc::new(AlpcTransportService)) else {
        assert(false, "zwalpc: endpoint registrado");
        return;
    };
    let name = block + 0x10;
    let length = write_wide(block + 0x40, path);
    set_unicode(unsafe { nt::UnicodeString::at(name) }, length, length, block + 0x40);
    let message = |at: u64, data: &[u8]| {
        init_port_message(unsafe { nt::PortMessage::at(at) }, data.len() as u16, data.len() as u16 + nt::PortMessage::SIZE as u16);
        guest::write_bytes(at + nt::PortMessage::SIZE, data);
    };
    let read = |at: u64, length: u64| -> alloc::vec::Vec<u8> { guest::read_bytes(at, length as usize) };
    // ZwAlpcConnectPort síncrono com mensagem de conexão.
    let (connection, capacity, out) = (block + 0x100, block + 0x1F0, block + 0x600);
    message(connection, &[1]);
    guest::write64(capacity, 0x100);
    let connected = zw("ZwAlpcConnectPort", &[out, name, 0, 0, 0x2_0000, 0, connection, capacity, 0, 0, 0]);
    let handle = guest::read64(out);
    let port = port_objects::port_of(open_pointer::resolve(handle, false).and_then(|resolved| resolved.ok()).map_or(0, |resolved| resolved.item.pointer));
    assert(connected == Some(0) && port.is_some() && unsafe { nt::PortMessage::at(connection) }.u2.s2.type_.get() == 11 && read(connection + nt::PortMessage::SIZE, 2) == [0xC0, 0x01], "zwalpc: ZwAlpcConnectPort sincrono");
    let Some(port) = port else { return };
    // ZwAlpcSendWaitReceivePort: oito argumentos exatos.
    let (input, output, length) = (block + 0x300, block + 0x400, block + 0x3F0);
    message(input, &[7, 8, 9]);
    guest::write64(length, 0x100);
    let exchanged = zw("ZwAlpcSendWaitReceivePort", &[handle, 0x2_0000, input, 0, output, length, 0, 0]);
    assert(exchanged == Some(0) && unsafe { nt::PortMessage::at(output) }.u2.s2.type_.get() == 2 && read(output + nt::PortMessage::SIZE, 3) == [9, 8, 7], "zwalpc: ZwAlpcSendWaitReceivePort sincrono");
    // Consulta básica e set-information.
    let basic = zw("ZwAlpcQueryInformation", &[handle, 0, output, 16, block + 0x480]);
    let unsupported = zw("ZwAlpcSetInformation", &[handle, 1, input, 8]);
    unsafe { nt::PortMessage::at(input) }.message_id.set(0);
    let no_message = zw("ZwAlpcQueryInformationMessage", &[handle, input, 0, output, 64, 0]);
    assert(basic == Some(0) && unsafe { nt::AlpcBasicInformation::at(output) }.sequence_no.get() == port.sequence() && guest::read32(block + 0x480) == 16 && unsupported == Some(0xC000_00BB) && no_message == Some(0xC000_000D), "zwalpc: consultas e set-information");
    // Recursos: contexto, reserva, seção e vista.
    let attribute = block + 0x500;
    let security_attribute = unsafe { nt::AlpcSecurityAttr::at(attribute) };
    security_attribute.p_qos.set(0);
    let context = zw("ZwAlpcCreateSecurityContext", &[handle, 0, attribute]);
    let context_handle = security_attribute.context_handle.get();
    let context_deleted = zw("ZwAlpcDeleteSecurityContext", &[handle, 0, context_handle]);
    let reserve = zw("ZwAlpcCreateResourceReserve", &[handle, 0, 0x80, block + 0x540]);
    let identifier = guest::read32(block + 0x540);
    let section = zw("ZwAlpcCreatePortSection", &[handle, 0, 0, 0x2000, block + 0x548, block + 0x550]);
    let section_handle = guest::read64(block + 0x548);
    let view = block + 0x560;
    let view_attribute = unsafe { nt::AlpcDataViewAttr::at(view) };
    view_attribute.flags.set(0);
    view_attribute.section_handle.set(section_handle);
    view_attribute.view_base.set(0);
    view_attribute.view_size.set(0x1000);
    let mapped = zw("ZwAlpcCreateSectionView", &[handle, 0, view]);
    let base = view_attribute.view_base.get();
    let unmapped = zw("ZwAlpcDeleteSectionView", &[handle, 0, base]);
    let section_deleted = zw("ZwAlpcDeletePortSection", &[handle, 0, section_handle]);
    assert(context == Some(0) && context_handle != 0 && context_deleted == Some(0) && reserve == Some(0) && identifier & 0x8000_0000 != 0 && section == Some(0) && guest::read64(block + 0x550) == 0x1_0000 && mapped == Some(0) && base != 0 && unmapped == Some(0) && section_deleted == Some(0), "zwalpc: contexto, reserva, secao e vista pelas entradas Zw");
    // Cancelamento da reserva: geração no slot reservado.
    let selection = block + 0x5C0;
    let selection_attribute = unsafe { nt::AlpcContextAttr::at(selection) };
    selection_attribute.message_context.set(0);
    selection_attribute.message_id.set(identifier);
    selection_attribute.callback_id.set(0);
    let canceled = zw("ZwAlpcCancelMessage", &[handle, 0, selection]);
    let reserve_queued = port.with(|state| state.pending.len());
    assert(canceled == Some(0x4000_002E) && reserve_queued == 0, "zwalpc: ZwAlpcCancelMessage sobre a reserva");
    // ZwAlpcConnectPortEx por OBJECT_ATTRIBUTES.
    let attributes = block + 0x700;
    set_object_attributes(unsafe { nt::ObjectAttributes::at(attributes) }, nt::ObjectAttributes::SIZE as u32, 0, name, 0);
    message(connection, &[2]);
    let extended = zw("ZwAlpcConnectPortEx", &[out + 8, attributes, 0, 0, 0x2_0000, 0, connection, capacity, 0, 0, 0]);
    let second = guest::read64(out + 8);
    assert(extended == Some(0) && second != 0 && second != handle, "zwalpc: ZwAlpcConnectPortEx");
    // Desconexão e fechamento.
    let disconnected = zw("ZwAlpcDisconnectPort", &[handle, 0]);
    let again = zw("ZwAlpcDisconnectPort", &[handle, 0]);
    let pointer = port.pointer;
    drop(port);
    let _ = open_pointer::close(handle);
    let _ = open_pointer::close(second);
    transport::unregister(&listener);
    assert(disconnected == Some(0) && again == Some(0xC000_0037) && port_objects::port_of(pointer).is_none() && exports::implemented() == 1610, "zwalpc: desconexao e grupo com 15 exports");
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn user_worker_factory(assert: Assert) {
    use crate::ntos::ob::objects::work as work_objects;
    use crate::ntos::ps::user::{io_completion, memory};
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "userwf: memoria de usuario");
        return;
    };
    let rsp = block + 0x800;
    let stack = |args: &[u64]| {
        for (index, value) in args.iter().enumerate() {
            guest::write64(rsp + 0x28 + index as u64 * 8, *value);
        }
    };
    let call = |name: &str, a: u64, b: u64, c: u64, d: u64| state::handler(name).map(|handler| handler(a, b, c, d, rsp)).and_then(|result| result.ok());
    // IOCP da fábrica.
    let created_port = call("NtCreateIoCompletion", block + 8, 0x1F_0003, 0, 2);
    let port_handle = guest::read64(block + 8);
    let port = io_completion::resolve(port_handle, 0).ok().map(|(_, port)| port);
    let listeners_before = port.as_ref().map_or(0, |port| port.listeners.lock().len());
    // Criação.
    let start = block + 0x100;
    guest::write8(start, 0xC3);
    stack(&[u64::MAX, start, 0x1122_3344_5566_7788, 4, 0x1_0000, 0x1000]);
    let created = call("NtCreateWorkerFactory", block + 0x10, 0xF_00FF, 0, port_handle);
    let handle = guest::read64(block + 0x10);
    let entry = state::get_user_handle(handle);
    let pointer = entry.as_ref().and_then(|entry| entry.downcast::<crate::ntos::ob::objects::dispatcher::UserDispatcher>().map(|dispatcher| dispatcher.pointer)).unwrap_or(0);
    let factory = work_objects::factory_of(pointer);
    assert(created_port == Some(0) && created == Some(0) && entry.as_ref().is_some_and(|entry| entry.kind() == "workerfactory") && factory.is_some() && port.as_ref().is_some_and(|port| port.listeners.lock().len() == listeners_before + 1) && guest::read64(pointer + 0x38) == port.as_ref().map_or(0, |port| port.pointer), "userwf: fabrica criada sobre a IOCP");
    drop(entry);
    // Recusas da criação.
    stack(&[0x1234, start, 0, 4, 0, 0]);
    let process = call("NtCreateWorkerFactory", block + 0x18, 0xF_00FF, 0, port_handle);
    stack(&[u64::MAX, start, 0, 0, 0, 0]);
    let maximum = call("NtCreateWorkerFactory", block + 0x18, 0xF_00FF, 0, port_handle);
    let wrong_port = call("NtCreateWorkerFactory", block + 0x18, 0xF_00FF, 0, handle);
    assert(process == Some(0xC000_0008) && maximum == Some(0xC000_000D) && wrong_port == Some(0xC000_0024), "userwf: recusas da criacao");
    // Consulta: 0x78 bytes.
    let (out, returned) = (block + 0x200, block + 0x2F0);
    let factory_info = unsafe { nt::WorkerFactoryBasicInformation::at(out) };
    stack(&[returned]);
    let queried = call("NtQueryInformationWorkerFactory", handle, 7, out, 0x78);
    assert(queried == Some(0) && guest::read32(returned) == 0x78 && factory_info.timeout.quad_part.get() == -100_000_000 && factory_info.retry_timeout.quad_part.get() == -10_000_000 && factory_info.may_create.get() == 1 && factory_info.thread_maximum.get() == 4 && factory_info.thread_minimum.get() == 0 && factory_info.start_routine.get() == start && factory_info.start_parameter.get() == 0x1122_3344_5566_7788 && factory_info.stack_reserve.get() == 0x1_0000 && factory_info.stack_commit.get() == 0x1000 && factory_info.total_worker_count.get() == 0, "userwf: consulta basica da fabrica");
    let short = call("NtQueryInformationWorkerFactory", handle, 7, out, 0x70);
    let class = call("NtQueryInformationWorkerFactory", handle, 1, out, 0x78);
    assert(short == Some(0xC000_0004) && class == Some(0xC000_0003), "userwf: recusas da consulta");
    // Set-information: cada classe com as recusas.
    let input = block + 0x300;
    let set = |class: u64, value: u64, length: u64| {
        guest::write64(input, value);
        call("NtSetInformationWorkerFactory", handle, class, input, length)
    };
    let classes = (set(5, 8, 4), set(5, 0, 4), set(3, 2, 4), set(3, (-5i32) as u32 as u64, 4), set(2, 5, 8), set(2, (-50_000_000i64) as u64, 8), set(11, 40, 4), set(11, 12, 4), set(13, 1, 4), set(14, 100, 4), set(1, 0, 4), set(5, 8, 2));
    assert(classes == (Some(0), Some(0xC000_000D), Some(0), Some(0xC000_000D), Some(0xC000_000D), Some(0), Some(0xC000_000D), Some(0), Some(0), Some(0), Some(0xC000_0003), Some(0xC000_0004)), "userwf: classes do set-information");
    let factory = factory.expect("fabrica");
    assert(factory.maximum() == 8 && factory.binding_count() == 2 && factory.idle_timeout() == -50_000_000 && factory.priority() == 12 && factory.loader_worker() && factory.soft_maximum() == 8, "userwf: configuracao gravada no corpo da fabrica");
    // Mínimo: a criação de workers falha fora do runtime e registra o status.
    let minimum = set(4, 2, 4);
    let last = factory.last_status();
    let back = set(4, 0, 4);
    assert(minimum.is_some_and(|status| status != 0) && last == minimum.unwrap_or(0) && back == Some(0) && factory.minimum() == 0, "userwf: minimo com falha de criacao registrada");
    // Liberação de worker: pacote de dreno na IOCP.
    let released = call("NtReleaseWorkerFactoryWorker", handle, 0, 0, 0);
    let packets = port.as_ref().map_or(0, |port| port.with(|state| state.packets.len()));
    assert(released.is_some() && factory.release_count() == 1 && packets >= 1, "userwf: liberacao enfileira o dreno");
    // Fora de uma thread worker.
    let ready = call("NtWorkerFactoryWorkerReady", handle, 0, 0, 0);
    stack(&[0]);
    let wait = call("NtWaitForWorkViaWorkerFactory", handle, out, 1, returned);
    assert(ready == Some(0xC000_000D) && wait == Some(0xC000_000D), "userwf: chamadas de worker recusadas fora de uma thread worker");
    // Encerramento.
    guest::write32(block + 0x320, 3);
    let shut = call("NtShutdownWorkerFactory", handle, block + 0x320, 0, 0);
    stack(&[returned]);
    let _ = call("NtQueryInformationWorkerFactory", handle, 7, out, 0x78);
    let after = (set(5, 4, 4), set(14, 2, 4), call("NtReleaseWorkerFactoryWorker", handle, 0, 0, 0));
    assert(shut == Some(0) && guest::read32(block + 0x320) == 3 && factory_info.shutdown.get() == 1 && factory.shutdown() && port.as_ref().is_some_and(|port| port.listeners.lock().len() == listeners_before) && after == (Some(0xC000_010A), Some(0x80), Some(0xC000_010A)), "userwf: encerramento recusa configuracao e liberacao");
    // Fechamento: a última referência libera a fábrica e a IOCP.
    drop(factory);
    let _ = call("NtClose", handle, 0, 0, 0);
    if let Some(port) = &port {
        port.with(|state| state.packets.clear());
    }
    drop(port);
    let _ = call("NtClose", port_handle, 0, 0, 0);
    assert(work_objects::factory_of(pointer).is_none(), "userwf: fabrica destruida no fechamento");
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn user_wnf(assert: Assert) {
    use crate::ntos::ex::wnf::service;
    use crate::ntos::ps::user::memory;
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "userwnf: memoria de usuario");
        return;
    };
    let rsp = block + 0x800;
    let stack = |args: &[u64]| {
        for (index, value) in args.iter().enumerate() {
            guest::write64(rsp + 0x28 + index as u64 * 8, *value);
        }
    };
    let call = |name: &str, a: u64, b: u64, c: u64, d: u64| state::handler(name).map(|handler| handler(a, b, c, d, rsp)).and_then(|result| result.ok());
    let (name, guid, data, stamp, length, output) = (block, block + 0x10, block + 0x20, block + 0x40, block + 0x48, block + 0x60);
    let (state_name, invalid_name) = unsafe { (nt::WnfStateName::at(name), nt::WnfStateName::at(name + nt::WnfStateName::SIZE)) };
    state_name.data[0].set(0xA3BC_0875);
    state_name.data[1].set(0x0280_032E);
    let type_id = unsafe { nt::Guid::at(guid) };
    type_id.data1.set(0x48F9_6463);
    type_id.data2.set(0x52D6);
    type_id.data3.set(0x4E85);
    for (cell, byte) in type_id.data4.iter().zip([0x9C, 0x02, 0xF2, 0xC1, 0x4E, 0x17, 0x26, 0x4E]) {
        cell.set(byte);
    }
    guest::write32(data, 0xFEED_BEEF);
    let updated = service::update(name, data, 4, guid, 0, 0, false).ok();
    // NtQueryWnfStateData pela captura de usuário.
    guest::write32(length, 8);
    stack(&[output, length]);
    let queried = call("NtQueryWnfStateData", name, guid, 0, stamp);
    let read = (guest::read32(stamp), guest::read32(length), guest::read32(output));
    guest::write32(length, 8);
    let untyped = call("NtQueryWnfStateData", name, 0, 0, stamp);
    guest::write32(length, 2);
    let short = call("NtQueryWnfStateData", name, guid, 0, stamp);
    let short_length = guest::read32(length);
    guest::write32(length, 8);
    let bad_stamp = call("NtQueryWnfStateData", name, guid, 0, 0x10);
    assert(updated == Some(0) && queried == Some(0) && read == (1, 4, 0xFEED_BEEF) && untyped == Some(0xC000_000D) && short == Some(0xC000_0023) && short_length == 4 && bad_stamp == Some(0xC000_0005), "userwnf: NtQueryWnfStateData pela captura de usuario");
    // Inscrição e evento pertencem a um processo de usuário: um assinante do
    // System seria despachado como inscrição de kernel (callback em +0x50).
    let previous = crate::ntos::ps::process::get_current_thread();
    let saved_pid = state::with(|state| state.current_process_id);
    let Ok(owner) = crate::ntos::ps::process::create_process(0x7F30, "wnf.exe", 0, None) else {
        assert(false, "userwnf: processo de usuario");
        return;
    };
    let Ok(thread) = crate::ntos::ps::process::create_kernel_thread(owner, 0x7F34, true, 1, None) else {
        assert(false, "userwnf: thread do processo");
        return;
    };
    crate::ntos::ps::process::set_current_thread(thread);
    state::with(|state| state.current_process_id = 0x7F30);
    // NtSubscribeWnfStateChange.
    let identifier = block + 0x100;
    guest::write64(identifier, 0x1234);
    let subscribed = call("NtSubscribeWnfStateChange", name, 0, 1, identifier);
    let subscription = guest::read64(identifier);
    let mask = call("NtSubscribeWnfStateChange", name, 0, 0x20, identifier);
    invalid_name.data[0].set(0xA3BC_0876);
    invalid_name.data[1].set(0x0280_032E);
    guest::write64(identifier, 0x1234);
    let bad_name = call("NtSubscribeWnfStateChange", invalid_name.address(), 0, 1, identifier);
    let zeroed = guest::read64(identifier);
    let bad_pointer = call("NtSubscribeWnfStateChange", 0x10, 0, 1, 0);
    assert(subscribed == Some(0) && subscription != 0 && mask == Some(0xC000_000D) && bad_name == Some(0xC000_000D) && zeroed == 0 && bad_pointer == Some(0xC000_0005), "userwnf: NtSubscribeWnfStateChange e recusas");
    // NtSetWnfProcessNotificationEvent: uma única inscrição por processo.
    guest::write64(rsp + 0x28, 0);
    let created = call("NtCreateEvent", block + 0x108, 0x1F_0003, 0, 0);
    let event = guest::read64(block + 0x108);
    let registered = call("NtSetWnfProcessNotificationEvent", event, 0, 0, 0);
    let again = call("NtSetWnfProcessNotificationEvent", event, 0, 0, 0);
    let invalid = call("NtSetWnfProcessNotificationEvent", 0x7FFF_0000, 0, 0, 0);
    assert(created == Some(0) && registered == Some(0) && again == Some(0xC000_0718) && invalid.is_some_and(|status| status & 0x8000_0000 != 0), "userwnf: evento de notificacao do processo registrado uma vez");
    // O encerramento devolve inscrições, contexto e a referência do evento.
    let _ = call("NtClose", event, 0, 0, 0);
    crate::ntos::ps::process::set_current_thread(previous);
    state::with(|state| state.current_process_id = saved_pid);
    let _ = crate::ntos::ps::process::release_thread(thread);
    let _ = crate::ntos::ps::process::terminate_process(owner, 0);
    assert(service::shutdown().is_ok() && !service::exists(), "userwnf: encerramento do servico");
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn user_thread_context(assert: Assert) {
    use crate::hal::amd64::{native_call, win32_thunk};
    use crate::ntos::ps::context::{kernel_frame as kernel_context_frame, set as set_thread_context, input as thread_context_input, registers as registers};
    use crate::ntos::ps::process;
    use crate::ntos::ps::user::{context_frame, memory};
    use crate::ntos::init::exports;
    use crate::ntos::mm::pe_loader::ResolvedImport;
    let Ok(block) = memory::map_user_region(0x2000) else {
        assert(false, "userctx: memoria de usuario");
        return;
    };
    let thread = process::get_current_thread();
    // Captura da entrada: KernelMode usa o buffer; UserMode exige alinhamento.
    let source = guest::alloc_aligned(registers::SIZE, 16, true);
    let source_context = unsafe { nt::Context::at(source) };
    source_context.context_flags.set(0x10_0002);
    source_context.rax.set(0x1234);
    let kernel = thread_context_input::capture(source, 0).ok().and_then(|result| result.ok());
    let user = block + 0x100;
    let user_context = unsafe { nt::Context::at(user) };
    user_context.context_flags.set(0x10_0002);
    let misaligned = thread_context_input::capture(user + 8, 1).ok().and_then(|result| result.err());
    let mut owned = thread_context_input::capture(user, 1).ok().and_then(|result| result.ok());
    let copied = owned.as_ref().is_some_and(|captured| captured.source != user && captured.flags == 0x10_0002);
    if let Some(captured) = owned.as_mut() {
        captured.release();
    }
    user_context.context_flags.set(0x1234_5678);
    let normalized = thread_context_input::capture(user, 1).ok().and_then(|result| result.ok()).map(|mut captured| {
        let flags = captured.flags;
        captured.release();
        flags
    });
    assert(kernel.as_ref().is_some_and(|captured| captured.source == source && captured.flags == 0x10_0002) && misaligned == Some(0x8000_0002) && copied && normalized.is_some_and(|flags| flags & registers::AMD64 != 0), "userctx: captura da entrada em KernelMode e UserMode");
    // Thread de sistema recusa o contexto de usuário; KernelMode sem frame
    // de interrupção vivo é uma falha real.
    let system_thread = unsafe { nt::Kthread::at(thread) }.system_thread() != 0;
    let user_mode = set_thread_context::execute(thread, source, 0, 1, 1).ok();
    let kernel_mode = set_thread_context::execute(thread, source, 0, 0, 1).ok();
    assert((!system_thread || user_mode == Some(0xC000_0030)) && kernel_mode == Some(0xC000_0001), "userctx: thread de sistema e KernelMode sem frame vivo");
    // PsSetContextThread pelo corpo nativo e PspSetContextThreadInternal.
    let address = match exports::lookup("ntoskrnl.exe", "PsSetContextThread") {
        Some(ResolvedImport::Address { address, .. }) => address,
        Some(ResolvedImport::Thunk(id)) => crate::ntos::mm::kernel_address::image_address(win32_thunk::thunk_table().0 + id as u64 * win32_thunk::STUB_SIZE).unwrap_or(0),
        _ => 0,
    };
    let native = if address != 0 { native_call::call(address, &[thread, source, 0]) as u32 } else { 0 };
    assert(address != 0 && native == 0xC000_0001 && crate::ntos::init::exports::private_routines::address("PspContextOperationApc") != 0, "userctx: PsSetContextThread pelo corpo nativo");
    // Frame de interrupção sintético: o CONTEXT de KernelMode volta ao frame.
    let frame = guest::alloc_aligned(0x100, 16, true);
    let fx = guest::alloc_aligned(512, 16, true);
    let cpu = guest::alloc_aligned(64, 16, true);
    let workspace = guest::alloc_aligned(0x980, 16, true);
    guest::write64(frame + 136, 0x10);
    guest::write64(frame + 112, 0x1111);
    unsafe { nt::XsaveFormat::at(fx) }.mx_csr.set(0x1F80);
    let old_trap = unsafe { nt::Kthread::at(thread) }.trap_frame.get();
    let applied = kernel_context_frame::with_interrupt(frame, fx, cpu, workspace, || kernel_context_frame::apply_kernel(source), 0);
    let restored = unsafe { nt::Kthread::at(thread) }.trap_frame.get() == old_trap;
    let user_frame = { guest::write64(frame + 136, 0x33); kernel_context_frame::with_interrupt(frame, fx, cpu, workspace, || 7, 0).ok() };
    assert(matches!(applied, Ok(Ok(0))) && guest::read64(frame + 112) == 0x1234 && restored && user_frame == Some(7) && kernel_context_frame::with_interrupt(frame, fx, cpu, workspace, || 0, 4).is_err(), "userctx: CONTEXT de KernelMode aplicado ao frame de interrupcao");
    // Faixas retidas só no frame vivo da syscall.
    assert(!context_frame::retain(source, 0x10_0002) && !context_frame::retain(source, 0x2) && crate::ntos::ps::user::set_thread_context::apply(thread + 8, source).is_err(), "userctx: faixas retidas so no frame vivo e aplicacao na thread errada recusada");
    for pointer in [source, frame, fx, cpu, workspace] {
        guest::free_bytes(pointer);
    }
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn user_exceptions(assert: Assert) {
    use crate::ntos::ps::process;
    use crate::ntos::ps::user::{exceptions, memory, threads};
    let Ok(block) = memory::map_user_region(0x4000) else {
        assert(false, "userexc: memoria de usuario");
        return;
    };
    let (context, record, dispatcher) = (block, block + 0x600, block + 0x800);
    let fill = |pointer: u64, rip: u64, rsp: u64| {
        guest::write_bytes(pointer, &[0u8; nt::Context::SIZE as usize]);
        let frame = unsafe { nt::Context::at(pointer) };
        frame.context_flags.set(0x10_0003);
        frame.seg_cs.set(0x33);
        frame.seg_ss.set(0x2B);
        frame.e_flags.set(0x0004_7346);
        frame.rsp.set(rsp);
        frame.rip.set(rip);
        frame.rax.set(0xAAAA);
    };
    let (context_record, exception) = unsafe { (nt::Context::at(context), nt::ExceptionRecord::at(record)) };
    // Quadro do KiUserExceptionDispatcher na pilha: CONTEXT, CONTEXT_EX, EXCEPTION_RECORD e MACHINE_FRAME, alinhados a 16.
    let record_offset = (nt::Context::SIZE + nt::ContextEx::SIZE + 15) & !15;
    let machine_offset = (record_offset + nt::ExceptionRecord::SIZE + 15) & !15;
    // Validação do CONTEXT.
    fill(context, block + 0x900, block + 0x3F00);
    let valid = exceptions::validate_context(context);
    context_record.seg_cs.set(0x10);
    let bad_cs = exceptions::validate_context(context);
    context_record.seg_cs.set(0x33);
    context_record.context_flags.set(0x10_0002);
    let no_control = exceptions::validate_context(context);
    context_record.context_flags.set(0x10_0003);
    assert(valid == 0 && bad_cs == 0xC000_000D && no_control == 0xC000_000D && exceptions::validate_context(0) == 0xC000_0005, "userexc: validacao do CONTEXT");
    // Segunda chance: termina o processo com o código da exceção.
    guest::write_bytes(record, &[0u8; nt::ExceptionRecord::SIZE as usize]);
    exception.exception_code.set(0xC000_0096u32 as i32);
    exception.exception_address.set(block + 0x900);
    let saved_exit = guest::read32(crate::ntos::ps::user::state::EXIT_CODE_CELL);
    let second = exceptions::raise(record, context, 0).ok();
    let exit_code = guest::read32(crate::ntos::ps::user::state::EXIT_CODE_CELL);
    guest::write32(crate::ntos::ps::user::state::EXIT_CODE_CELL, saved_exit);
    exception.number_parameters.set(16);
    let parameters = exceptions::raise(record, context, 1).ok();
    exception.number_parameters.set(0);
    let no_thread = exceptions::raise(record, context, 1).ok();
    assert(second == Some(crate::ntos::ps::user::state::TERMINATE_MAGIC) && exit_code == 0xC000_0096 && parameters == Some(0xC000_000D) && no_thread == Some(0xC000_00BB), "userexc: segunda chance termina e recusas do NtRaiseException");
    // Thread de usuário com CONTEXT salvo e a NTDLL simulada.
    let saved_exports = state::with(|state| state.ntdll_exports.clone());
    let thread = threads::UserThread::new(0x7F50, process::get_current_thread(), 0, 0);
    let live = guest::alloc_aligned(nt::Context::SIZE, 16, true);
    thread.with(|state| state.context = live);
    let live_context = unsafe { nt::Context::at(live) };
    let missing = { fill(live, block + 0x900, block + 0x3F00); exceptions::deliver(&thread, &[0u8; 0x98]) };
    state::with(|state| state.ntdll_exports = Some([(alloc::string::String::from("KiUserExceptionDispatcher"), dispatcher)].into_iter().collect()));
    // Breakpoint de hardware: RIP recua para o INT3.
    let saved_vector = guest::read32(crate::hal::amd64::usermode::FAULT_VECTOR_CELL);
    guest::write32(crate::hal::amd64::usermode::FAULT_VECTOR_CELL, 3);
    fill(live, block + 0x901, block + 0x3F00);
    let delivered = exceptions::hardware(&thread, 0x8000_0003);
    guest::write32(crate::hal::amd64::usermode::FAULT_VECTOR_CELL, saved_vector);
    let stack = live_context.rsp.get();
    let (dispatch_context, dispatch_context_ex, dispatch_record, machine_frame) = unsafe { (nt::Context::at(stack), nt::ContextEx::at(stack + nt::Context::SIZE), nt::ExceptionRecord::at(stack + record_offset), nt::MachineFrame::at(stack + machine_offset)) };
    let frame_ok = stack == (block + 0x3F00 - 0x5C0) & !15 && live_context.rip.get() == dispatcher && live_context.rcx.get() == stack + record_offset && live_context.rdx.get() == stack;
    let record_ok = dispatch_record.exception_code.get() as u32 == 0x8000_0003 && dispatch_record.exception_address.get() == block + 0x900 && machine_frame.rip.get() == block + 0x900 && dispatch_context.rip.get() == block + 0x900 && dispatch_context.context_flags.get() & 0x10_0010 == 0x10_0010;
    let flags_ok = live_context.e_flags.get() & 0x1_0500 == 0 && dispatch_context.e_flags.get() & 0x1A_7000 == 0 && dispatch_context_ex.all.length.get() as u64 == record_offset;
    assert(missing == 0xC000_0139 && delivered == 0 && frame_ok && record_ok && flags_ok, "userexc: breakpoint de hardware entregue ao KiUserExceptionDispatcher");
    // Primeira chance pelo NtRaiseException: pendente até a saída da syscall.
    let previous = threads::current();
    threads::set_running(false, Some(thread.clone()));
    fill(live, block + 0xA00, block + 0x3E00);
    live_context.dr0.set(0x1111);
    fill(context, block + 0x900, block + 0x3F00);
    context_record.rax.set(0xBBBB);
    context_record.context_flags.set(0x10_0003);
    exception.exception_code.set(0xC000_0005u32 as i32);
    let raised = exceptions::raise(record, context, 1).ok();
    let marked = thread.with(|state| state.pending_exception);
    let untouched = live_context.rip.get() == block + 0xA00;
    let applied = exceptions::pending(&thread);
    let integer_kept = live_context.rax.get() == 0xBBBB && live_context.dr0.get() == 0x1111;
    let stack = live_context.rsp.get();
    let pending_ok = applied == 0 && live_context.rip.get() == dispatcher && stack == (block + 0x3F00 - 0x5C0) & !15 && unsafe { nt::ExceptionRecord::at(stack + record_offset) }.exception_code.get() as u32 == 0xC000_0005 && !thread.with(|state| state.pending_exception);
    threads::set_running(false, previous);
    state::with(|state| state.ntdll_exports = saved_exports);
    guest::free_bytes(live);
    assert(raised == Some(0) && marked && untouched && integer_kept && pending_ok, "userexc: primeira chance pendente aplicada so com os grupos selecionados");
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn user_process_information_hooks(assert: Assert) {
    use crate::hal::amd64::usermode;
    use crate::ntos::ps::process;
    use crate::ntos::ps::user::{call_capture, instrumentation, memory, threads};
    let Ok(block) = memory::map_user_region(0x3000) else {
        assert(false, "userinfo: memoria de usuario");
        return;
    };
    let rsp = block + 0x2800;
    let call = |name: &str, a: u64, b: u64, c: u64, d: u64| state::handler(name).map(|handler| handler(a, b, c, d, rsp)).and_then(|result| result.ok());
    // ProcessInstrumentationCallback (40): versão 0 e callback na célula da HAL.
    let input = block + 0x100;
    let instrumentation = unsafe { nt::ProcessInstrumentationCallbackInformation::at(input) };
    instrumentation.version.set(0);
    instrumentation.reserved.set(0);
    instrumentation.callback.set(block + 0x200);
    let set = call("NtSetInformationProcess", u64::MAX, 40, input, 16);
    let cell = guest::read64(usermode::INSTRUMENTATION_CALLBACK);
    instrumentation.reserved.set(1);
    let reserved = call("NtSetInformationProcess", u64::MAX, 40, input, 16);
    let other = call("NtSetInformationProcess", 0x10, 40, input, 16);
    let length = call("NtSetInformationProcess", u64::MAX, 40, input, 12);
    instrumentation.version.set(0);
    instrumentation.reserved.set(0);
    let cleared = call("NtSetInformationProcess", u64::MAX, 40, input, 8);
    let cleared_cell = guest::read64(usermode::INSTRUMENTATION_CALLBACK);
    instrumentation::release_process();
    assert(set == Some(0) && cell == block + 0x200 && reserved == Some(0xC000_000D) && other == Some(0xC000_0008) && length == Some(0xC000_0004) && cleared == Some(0) && cleared_cell == 0, "userinfo: callback de instrumentacao publicado na celula da HAL");
    // ProcessTlsInformation (35) sobre uma thread de usuário com TLS.
    let snapshot = threads::all();
    threads::clear();
    let teb = block + 0x1000;
    let vector = block + 0x1800;
    let thread = threads::UserThread::new(0x7F60, process::get_current_thread(), teb, 0);
    threads::push(thread.clone());
    let test_teb = unsafe { nt::Teb::at(teb) };
    test_teb.thread_local_storage_pointer.set(vector);
    for slot in 0..4u64 {
        guest::write64(vector + slot * 8, 0x1000 + slot);
    }
    let tls = block + 0x400;
    let tls_information = unsafe { nt::ProcessTlsInformation::at(tls) };
    let header = |operation: u32, index: u32, replacement: u64| {
        tls_information.flags.set(0);
        tls_information.operation_type.set(operation);
        tls_information.thread_data_count.set(1);
        tls_information.tls_index.set(index);
        tls_information.thread_data[0].flags.set(0);
        tls_information.thread_data[0].new_tls_data.set(replacement);
        tls_information.thread_data[0].thread_id.set(0);
    };
    header(0, 2, 0x5678);
    let slot = call("NtSetInformationProcess", u64::MAX, 35, tls, 40);
    let slot_ok = slot == Some(0) && guest::read64(vector + 16) == 0x5678 && tls_information.thread_data[0].old_tls_data.get() == 0x1002 && tls_information.thread_data[0].flags.get() == 2;
    let replacement = block + 0x1C00;
    header(1, 3, replacement);
    let swap = call("NtSetInformationProcess", u64::MAX, 35, tls, 40);
    let swap_ok = swap == Some(0) && test_teb.thread_local_storage_pointer.get() == replacement && guest::read64(replacement) == 0x1000 && guest::read64(replacement + 16) == 0x5678 && tls_information.thread_data[0].old_tls_data.get() == vector && tls_information.thread_data[0].thread_id.get() == 0x7F60;
    header(0, 0, 0);
    tls_information.flags.set(1);
    let wow64 = call("NtSetInformationProcess", u64::MAX, 35, tls, 40);
    let tls_refusals = (call("NtSetInformationProcess", 0x10, 35, tls, 40), call("NtSetInformationProcess", u64::MAX, 35, tls, 30), wow64);
    threads::clear();
    for previous in snapshot {
        threads::push(previous);
    }
    assert(slot_ok && swap_ok && tls_refusals == (Some(0xC000_000D), Some(0xC000_0004), Some(0xC000_000D)), "userinfo: troca de slot e de vetor TLS das threads");
    // ProcessDebugPort (7) pelos argumentos brutos da syscall.
    let raw = guest::alloc_bytes(0x40);
    let saved_raw = state::with(|state| core::mem::replace(&mut state.service_raw_arguments, raw));
    let out = block + 0x500;
    let returned = block + 0x510;
    guest::write64(rsp + 0x28, returned);
    let query = |handle: u64, target: u64, length: u64| {
        guest::write64(raw + 8, handle);
        guest::write64(raw + 16, 7);
        guest::write64(raw + 24, target);
        guest::write64(raw + 32, length);
        call("NtQueryInformationProcess", handle, 7, target, length)
    };
    guest::write64(out, 0x55);
    let none = query(u64::MAX, out, 8);
    let none_value = guest::read64(out);
    let current = process::get_current_process();
    let current_process = unsafe { nt::Eprocess::at(current) };
    let saved_port = current_process.debug_port.get();
    current_process.debug_port.set(0x1234);
    let debugged = query(u64::MAX, out, 8);
    let debugged_value = guest::read64(out);
    current_process.debug_port.set(saved_port);
    let refusals = (query(u64::MAX, out, 4), query(u64::MAX, out + 1, 8), query(u64::MAX - 1, out, 8), query(0x7FF0, out, 8));
    state::with(|state| state.service_raw_arguments = saved_raw);
    guest::free_bytes(raw);
    assert(none == Some(0) && none_value == 0 && guest::read32(returned) == 8 && debugged == Some(0) && debugged_value == u64::MAX && refusals == (Some(0xC000_0004), Some(0x8000_0002), Some(0xC000_0024), Some(0xC000_0008)), "userinfo: ProcessDebugPort indica a porta sem expor o ponteiro");
    // Captura de chamada: pedido nas células da HAL, consumo e limpeza.
    let saved_export = state::with(|state| core::mem::replace(&mut state.capture_export, alloc::string::String::from("ntdll.dll!NtTesteCaptura")));
    call_capture::reset();
    let exports: alloc::collections::BTreeMap<alloc::string::String, u64> = [(alloc::string::String::from("NtTesteCaptura"), block + 0x600)].into_iter().collect();
    call_capture::arm("kernel32.dll", &exports);
    let other_dll = guest::read32(usermode::CAPTURE_STATE);
    call_capture::arm("NTDLL.DLL", &exports);
    let armed = (guest::read32(usermode::CAPTURE_STATE), guest::read64(usermode::CAPTURE_ADDRESS));
    guest::write32(usermode::CAPTURE_STATE, 2);
    guest::write64(usermode::CAPTURE_ARGUMENTS_CELL, 0x11);
    call_capture::consume();
    let consumed = guest::read32(usermode::CAPTURE_STATE);
    call_capture::finish();
    let finished = (guest::read32(usermode::CAPTURE_STATE), guest::read64(usermode::CAPTURE_ADDRESS));
    state::with(|state| state.capture_export = saved_export);
    assert(other_dll == 0 && armed == (1, block + 0x600) && consumed == 3 && finished == (0, 0) && usermode::arm_user_call_capture(0x100).is_err(), "userinfo: captura de chamada armada, consumida e limpa");
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn section_image_views(assert: Assert) {
    use crate::hal::physical;
    use crate::ntos::mm::section::map_view_parameters::View as Request;
    use crate::ntos::mm::section::image_view as section_image_view;
    use crate::ntos::mm::section::views::{self as section_views, OwnedView};
    use crate::ntos::mm::{memory_map, paging};
    use crate::ntos::ps::process;
    use crate::ntos::ps::user::sections;
    use crate::ntos::ps::user::state::{self, RegionKind};
    // Base preferida acima de 4 GB, alinhada a 64 KB.
    let preferred = 0x6_5432_0000u64;
    let mut bytes = minimal_image();
    bytes[0x70..0x78].copy_from_slice(&preferred.to_le_bytes());
    let Ok(Ok(section)) = sections::create_image(MemoryFile::new(None, bytes), None, 0x80, false) else {
        assert(false, "imageview: secao de imagem criada");
        return;
    };
    let request = Request { base: 0, size: 0x2000, offset: 0, upper: memory_map::USER_ADDRESS_LIMIT - 1, alignment: 0x10000, protect: 0x80, allocation: 0, inherit: 2, commit: 0, preferred_node_plus_one: 0 };
    let owner = process::get_current_process();
    let Ok(Ok(first)) = section_image_view::map(&section, &request, owner, RegionKind::ProcessImages) else {
        assert(false, "imageview: primeira vista");
        return;
    };
    let code = paging::translate(first.view.base + 0x1000);
    let listed = state::with(|state| state.process_images.iter().any(|region| region.base() == first.view.base && region.name().as_deref() == Some("\\Device\\HarddiskVolume1\\opennt-secao.bin") && region.allocation_protect() == 0x80));
    let exports = state::with(|state| state.mapped_image_exports.contains_key("opennt-secao.bin"));
    assert(first.view.base == preferred && first.status == 0 && code != 0 && physical::read8(code) == 0xC3 && listed && exports, "imageview: imagem inteira na base preferida, listada e com exports publicados");
    // A base preferida ocupada: a vista vai para outro endereço e o status
    // informa STATUS_IMAGE_NOT_AT_BASE.
    let Ok(Ok(second)) = section_image_view::map(&section, &request, owner, RegionKind::ProcessImages) else {
        assert(false, "imageview: segunda vista");
        return;
    };
    let relocated = paging::translate(second.view.base + 0x1000);
    assert(second.view.base != preferred && second.view.base % 0x10000 == 0 && second.status == 0x4000_0003 && relocated != 0 && physical::read8(relocated) == 0xC3, "imageview: segunda vista realocada com STATUS_IMAGE_NOT_AT_BASE");
    // Vista parcial (só a página de código), sem lista do processo.
    let partial = section_image_view::map(&section, &Request { offset: 0x1000, size: 0x1000, ..request }, owner, RegionKind::Detached);
    let partial_ok = match &partial {
        Ok(Ok(view)) => view.offset == 0x1000 && view.view.size == 0x1000 && paging::translate(view.view.base) != 0 && physical::read8(paging::translate(view.view.base)) == 0xC3,
        _ => false,
    };
    assert(partial_ok, "imageview: vista parcial mapeia so a pagina pedida");
    let pointer = section.pointer();
    let mut released = section_views::unmap(&OwnedView::Image(first.view.clone())).is_ok() && section_views::unmap(&OwnedView::Image(second.view.clone())).is_ok();
    if let Ok(Ok(view)) = partial {
        released &= section_views::unmap(&OwnedView::Image(view.view)).is_ok();
    }
    let unlisted = state::with(|state| {
        state.mapped_image_exports.remove("opennt-secao.bin");
        !state.process_images.iter().any(|region| region.base() == first.view.base || region.base() == second.view.base)
    });
    drop(section);
    assert(released && unlisted && sections::by_pointer(pointer).is_none(), "imageview: vistas soltas e secao destruida na ultima");
}

fn memory_partition(assert: Assert) {
    use crate::ntos::mm::{partition, pfn};
    use crate::ntos::ob::object_manager;
    use crate::ntos::ps::process;
    use crate::ntos::ps::user::memory;
    // Corpo publicado no namespace, espelhando o PFN e as contagens.
    let Some(body) = partition::get() else {
        assert(false, "partition: corpo publicado no boot");
        return;
    };
    let node = object_manager::lookup("\\KernelObjects\\MemoryPartition0").and_then(object_manager::node);
    let named = node.as_ref().is_some_and(|node| node.type_name == "Partition" && node.data.as_ref().is_some_and(|data| data.native_pointer == body));
    let events = ["HighMemoryCondition", "LowMemoryCondition", "HighCommitCondition", "LowCommitCondition", "MaximumCommitCondition"].iter().all(|name| object_manager::lookup(&alloc::format!("\\KernelObjects\\{name}")).is_some());
    let (base_refs, base_handles) = (guest::read64(body), guest::read32(body + 8));
    assert(named && events && base_refs >= 1 && guest::read64(body + 16) == pfn::partition().total && guest::read64(body + 24) == pfn::free_count(), "partition: MemoryPartition0 e eventos de memoria publicados, corpo espelha o PFN");
    // A contabilidade física aparece no corpo e volta com a liberação.
    let free = pfn::free_count();
    let one = pfn::alloc_page();
    let run = pfn::alloc_contiguous_default(3, 1);
    let allocated = guest::read64(body + 24);
    let released = pfn::free_page(one) && (0..3).all(|index| pfn::free_page(run + index * 4096));
    assert(one != 0 && run != 0 && allocated == free - 4 && released && guest::read64(body + 24) == free, "partition: alocacoes simples e contiguas contadas no corpo");
    // NtOpenPartition num processo de usuário.
    let Ok(block) = memory::map_user_region(0x1000) else {
        assert(false, "partition: memoria de usuario");
        return;
    };
    let (attributes, unicode, text, result, maximum, rsp) = (block, block + 48, block + 64, block + 256, block + 272, block + 0x400);
    let call = |name: &str, a: u64, b: u64, c: u64, d: u64| state::handler(name).map(|handler| handler(a, b, c, d, rsp)).and_then(|result| result.ok());
    let set_name = |name: &str, flags: u32, root: u64| {
        set_object_attributes(unsafe { nt::ObjectAttributes::at(attributes) }, nt::ObjectAttributes::SIZE as u32, root, unicode, flags);
        let length = write_wide(text, name);
        set_unicode(unsafe { nt::UnicodeString::at(unicode) }, length, length + 2, text);
    };
    let saved_pid = state::with(|state| state.current_process_id);
    let previous = process::get_current_thread();
    let Ok(owner) = process::create_process(0x7DC0, "partition.exe", 0, None) else {
        assert(false, "partition: processo de usuario");
        return;
    };
    let Ok(thread) = process::create_kernel_thread(owner, 0x7DC4, true, 1, None) else {
        assert(false, "partition: thread do processo");
        return;
    };
    process::set_current_thread(thread);
    state::with(|state| state.current_process_id = 0x7DC0);
    set_name("\\KernelObjects\\MemoryPartition0", 0x42, 0);
    let opened = call("NtOpenPartition", result, 3, attributes, 0);
    let handle = guest::read64(result);
    let counted = (guest::read64(body), guest::read32(body + 8));
    let resolved = partition::resolve(handle, 2, 1);
    assert(opened == Some(0) && handle != 0 && counted == (base_refs + 1, base_handles + 1) && resolved == Ok(body), "partition: NtOpenPartition pelo nome abre o alocador real");
    // Seção ligada à partição: a seção retém o corpo.
    unsafe { nt::LargeInteger::at(maximum) }.quad_part.set(4096);
    guest::write64(rsp + 40, 4);
    guest::write64(rsp + 48, 0x804_0000);
    guest::write64(rsp + 56, handle);
    let created = call("NtCreateSection", result, 7, 0, maximum);
    let section = guest::read64(result);
    let retained = guest::read64(body) == base_refs + 2;
    let section_resolved = crate::ntos::mm::section::handles::reference(section, crate::ntos::mm::section::handles::Kind::Section, 4, 1).is_ok_and(|reference| {
        let partitioned = reference.section.as_ref().is_some_and(|section| section.state.lock().partition.is_some());
        let _ = reference.release();
        partitioned
    });
    assert(created == Some(0) && retained && section_resolved, "partition: secao da particao retem o corpo");
    // Recusas da captura e do acesso.
    let zero = call("NtOpenPartition", result, 0, attributes, 0);
    set_name("KernelObjects\\MemoryPartition0", 0x40, 0);
    let relative = call("NtOpenPartition", result, 3, attributes, 0);
    set_name("\\KernelObjects\\MemoryPartition9", 0x40, 0);
    let missing = call("NtOpenPartition", result, 3, attributes, 0);
    set_name("\\KernelObjects\\LowMemoryCondition", 0x40, 0);
    let wrong = call("NtOpenPartition", result, 3, attributes, 0);
    set_name("\\KernelObjects\\MemoryPartition0", 0x1, 0);
    let flags = call("NtOpenPartition", result, 3, attributes, 0);
    set_name("\\KernelObjects\\MemoryPartition0\\x", 0x40, 0);
    let through = call("NtOpenPartition", result, 3, attributes, 0);
    let output = call("NtOpenPartition", 0x10, 3, attributes, 0);
    assert((zero, relative, missing, wrong, flags, through, output) == (Some(0xC000_0022), Some(0xC000_003B), Some(0xC000_0034), Some(0xC000_0024), Some(0xC000_000D), Some(0xC000_003A), Some(0xC000_0005)), "partition: recusas de acesso, nome, tipo, flags e saida");
    // O encerramento do processo fecha a partição e a seção da tabela
    // nativa; a seção destruída solta a referência da partição.
    process::set_current_thread(previous);
    state::with(|state| state.current_process_id = saved_pid);
    let _ = process::release_thread(thread);
    let _ = process::terminate_process(owner, 0);
    let restored = (guest::read64(body), guest::read32(body + 8)) == (base_refs, base_handles);
    assert(restored && partition::get() == Some(body), "partition: o fim do processo fecha particao e secao e o alocador fica");
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

fn service_dispatcher_channel(assert: Assert) {
    use crate::ntos::cm::service::channel as service_channel;
    use crate::ntos::cm::service::database::{self as service_database, ConfigurationInput, ReportedStatus};
    use crate::ntos::io::lrpc::{Body, RpcContext};
    use crate::ntos::io::ndr::{Reader, Writer};
    let token = crate::ntos::ps::process::get_primary_token(crate::ntos::ps::process::get_system_process()).unwrap_or(0);
    let client = RpcContext { process_id: 304, token };
    let scmr = |operation: u32, bytes: &[u8], caller: &RpcContext| crate::ntos::cm::service::rpc::call(caller, operation, bytes);
    let now = |result: Result<Body, u32>| match result {
        Ok(Body::Now(bytes)) => bytes,
        _ => alloc::vec::Vec::new(),
    };
    let code = |bytes: &[u8]| if bytes.len() >= 4 { u32::from_le_bytes(bytes[bytes.len() - 4..].try_into().unwrap()) } else { u32::MAX };
    let open = || now(service_channel::call(&client, 0, &[0, 0, 0, 0]));
    let exchange = |handle: &[u8], id: u64, handler: u32| {
        let mut input = Writer::new();
        input.context(Some(handle));
        input.align(8);
        input.u32(0).u64(id).u32(handler).u32(0).u32(0);
        service_channel::call(&client, 1, &input.finish())
    };
    // Pacote de controle: nome do serviço, código e id.
    let packet = |bytes: &[u8]| -> (alloc::string::String, u32, u64) {
        let mut reader = Reader::new(bytes);
        let name = reader.string(true, 32768).ok().flatten().unwrap_or_default();
        reader.align(8);
        (name, reader.u32().unwrap_or(0), reader.u64().unwrap_or(0))
    };
    assert(code(&open()) == 1063, "scmchannel: processo comum nao registra dispatcher");
    let installed = service_database::install(&ConfigurationInput { name: alloc::string::String::from("opennt-native-service"), image_path: Some(alloc::string::String::from("C:\\service.exe")), ..ConfigurationInput::default() }, false);
    let mut steps = [false; 8];
    let launched = service_database::launch("opennt-native-service", |_| Some(((), false)), |_, _, created| {
        let _ = created(304);
        let opened = open();
        let handle = opened.get(..20).map(<[u8]>::to_vec).unwrap_or_default();
        steps[0] = code(&opened) == 0 && code(&open()) == 1056 && code(&now(service_channel::call(&RpcContext { process_id: 308, token: 0 }, 2, &handle))) == 6;
        // START entregue: o serviço fica em START_PENDING.
        let start = now(exchange(&handle, 0, 0));
        let (name, control, start_id) = packet(&start);
        steps[1] = code(&start) == 0 && name == "opennt-native-service" && control == 0x51 && service_database::status("opennt-native-service").is_ok_and(|status| status.current_state == 2);
        // Handle de status pelo START entregue (I_ScOpenServiceStatusHandle).
        let manager = now(scmr(64, &Writer::new().string(None, true).u32(1).finish(), &client)).get(..20).map(<[u8]>::to_vec).unwrap_or_default();
        let status_request = |id: u64| Writer::new().context(Some(&manager)).string(Some("opennt-native-service"), false).u64(id).finish();
        let wrong_id = code(&now(scmr(54, &status_request(start_id + 1), &client)));
        let foreign = code(&now(scmr(54, &status_request(start_id), &RpcContext { process_id: 308, token })));
        let status_opened = now(scmr(54, &status_request(start_id), &client));
        let status_handle = status_opened.get(..20).map(<[u8]>::to_vec).unwrap_or_default();
        let repeated = code(&now(scmr(54, &status_request(start_id), &client)));
        let no_query = code(&now(scmr(6, &status_handle, &client)));
        steps[2] = wrong_id == 5 && foreign == 6 && code(&status_opened) == 0 && repeated == 1056 && no_query == 5;
        // A troca seguinte fica pendente até haver controle.
        let mut wait = match exchange(&handle, start_id, 1235) {
            Ok(Body::Later(pending)) => Some(pending),
            _ => None,
        };
        let waiting = wait.as_mut().is_some_and(|pending| matches!(pending.poll(), Ok(None)));
        let service = now(scmr(16, &Writer::new().context(Some(&manager)).string(Some("opennt-native-service"), false).u32(0x24).finish(), &client)).get(..20).map(<[u8]>::to_vec).unwrap_or_default();
        let stop = || scmr(1, &Writer::new().context(Some(&service)).u32(1).finish(), &client);
        let early = code(&now(stop()));
        // SERVICE_RUNNING relatado pelo handle de status.
        let running = code(&now(scmr(7, &Writer::new().context(Some(&status_handle)).u32(16).u32(4).u32(1).u32(0).u32(0).u32(0).u32(0).finish(), &client)));
        let mut pending_stop = match stop() {
            Ok(Body::Later(pending)) => Some(pending),
            _ => None,
        };
        let stop_waits = pending_stop.as_mut().is_some_and(|pending| matches!(pending.poll(), Ok(None)));
        let delivered = wait.as_mut().and_then(|pending| pending.poll().ok().flatten()).map(|bytes| packet(&bytes));
        if let Some(pending) = wait.as_mut() {
            pending.cleanup();
        }
        let stop_id = delivered.as_ref().map_or(0, |packet| packet.2);
        let still_waiting = pending_stop.as_mut().is_some_and(|pending| matches!(pending.poll(), Ok(None)));
        steps[3] = waiting && early == 1061 && running == 0 && stop_waits && delivered.is_some_and(|(name, control, _)| name == "opennt-native-service" && control == 1) && still_waiting;
        // O STOPPED do serviço enfileira o encerramento; a confirmação conclui
        // o ControlService com o status relatado.
        let _ = service_database::report_status("opennt-native-service", 304, &ReportedStatus { current_state: 1, ..ReportedStatus::default() });
        let shutdown = now(exchange(&handle, stop_id, 0));
        let done = pending_stop.as_mut().and_then(|pending| pending.poll().ok().flatten()).unwrap_or_default();
        steps[4] = packet(&shutdown).1 == 0x20 && code(&done) == 0 && done.get(4..8) == Some(&1u32.to_le_bytes()[..]) && code(&now(stop())) == 1062;
        steps[5] = code(&now(service_channel::call(&client, 2, &handle))) == 0 && code(&now(service_channel::call(&client, 2, &handle))) == 6;
        crate::ntos::cm::service::rpc::release_process(304);
        Ok(0)
    });
    assert(installed.is_ok() && launched.is_ok_and(|code| code == 0) && steps[..6].iter().all(|&step| step), "scmchannel: START, handle de status, RUNNING relatado, STOP adiado ate a confirmacao, encerramento e fechamento");
    assert(service_database::status("opennt-native-service").is_ok_and(|status| status.current_state == 1), "scmchannel: servico parado depois do processo");
    // START recusado pelo dispatcher: o erro fica no status e o canal recebe o encerramento.
    let rejected = service_database::launch("opennt-native-service", |_| Some(((), false)), |_, _, created| {
        let _ = created(304);
        let handle = open().get(..20).map(<[u8]>::to_vec).unwrap_or_default();
        let (_, control, id) = packet(&now(exchange(&handle, 0, 0)));
        let mut input = Writer::new();
        input.context(Some(&handle));
        input.align(8);
        input.u32(5).u64(id).u32(1235).u32(0).u32(0);
        let shutdown = packet(&now(service_channel::call(&client, 1, &input.finish())));
        let status = service_database::status("opennt-native-service");
        steps[6] = control == 0x51 && shutdown.0.is_empty() && shutdown.1 == 0x20;
        steps[7] = status.is_ok_and(|status| status.current_state == 1 && status.win32_exit_code == 5);
        let _ = service_channel::call(&client, 2, &handle);
        service_channel::release_process(304);
        Ok(5)
    });
    assert(rejected.is_ok_and(|code| code == 5) && steps[6] && steps[7], "scmchannel: START recusado guarda o erro do dispatcher");
    let _ = service_database::remove("opennt-native-service");
}

fn service_control_manager_rpc(assert: Assert) {
    use crate::ntos::alpc::transport::{Reply, Service};
    use crate::ntos::cm::service::{database as service_database, rpc as service_rpc};
    use crate::ntos::io::lrpc::{self, Body, Interface, Pending, RpcContext};
    use crate::ntos::io::ndr::{Reader, Writer};
    use crate::ntos::ob::objects::port::{self as port_objects, PortState, Role};
    use crate::ntos::ps::process;
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    let token = process::get_primary_token(process::get_system_process()).unwrap_or(0);
    let client = RpcContext { process_id: 304, token };
    let call = |operation: u32, bytes: &[u8], caller: &RpcContext| -> Vec<u8> {
        match service_rpc::call(caller, operation, bytes) {
            Ok(Body::Now(bytes)) => bytes,
            _ => Vec::new(),
        }
    };
    let code = |bytes: &[u8]| if bytes.len() >= 4 { u32::from_le_bytes(bytes[bytes.len() - 4..].try_into().unwrap()) } else { u32::MAX };
    let hex = |text: &str| -> Vec<u8> { (0..text.len()).step_by(2).map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap_or(0)).collect() };
    // OpenSCManager: gerenciador local, base ServicesActive.
    let opened = call(15, &hex("00000000000000003f000f00"), &client);
    let manager = opened.get(..20).map(<[u8]>::to_vec).unwrap_or_default();
    let local = call(64, &hex("000000003f000f00"), &client);
    let failed = call(64, &Writer::new().string(Some("ServicesFailed"), true).u32(1).finish(), &client);
    let invalid = call(64, &Writer::new().string(Some("invalid"), true).u32(1).finish(), &client);
    assert(code(&opened) == 0 && opened.len() == 24 && manager.iter().any(|&byte| byte != 0) && code(&local) == 0 && code(&call(0, &local[..20], &client)) == 0 && code(&failed) == 1065 && code(&invalid) == 123, "scmr: OpenSCManager local e bases recusadas");
    let _ = service_database::install(&service_database::ConfigurationInput { name: String::from("opennt-scmr-test"), image_path: Some(String::from("C:\\test.exe")), display_name: Some(String::from("Serviço teste")), ..service_database::ConfigurationInput::default() }, false);
    let open_service = |name: &str, access: u32| call(16, &Writer::new().context(Some(&manager)).string(Some(name), false).u32(access).finish(), &client);
    let answer = open_service("opennt-scmr-test", 0x1_0005);
    let service = answer.get(..20).map(<[u8]>::to_vec).unwrap_or_default();
    let status = call(6, &service, &client);
    let foreign = call(6, &service, &RpcContext { process_id: 308, token });
    assert(code(&answer) == 0 && status.len() == 32 && u32::from_le_bytes(status[4..8].try_into().unwrap_or([0; 4])) == 1 && code(&foreign) == 6 && code(&open_service("opennt-scmr-missing", 4)) == 1060, "scmr: OpenService, status e dono do contexto");
    // QueryServiceConfig: tamanho necessário e a configuração serializada.
    let short = call(17, &Writer::new().context(Some(&service)).u32(0).finish(), &client);
    let needed = if short.len() >= 8 { u32::from_le_bytes(short[short.len() - 8..short.len() - 4].try_into().unwrap()) } else { 0 };
    let full = call(17, &Writer::new().context(Some(&service)).u32(needed).finish(), &client);
    let parsed = (|| -> Result<bool, u32> {
        let mut reader = Reader::new(&full);
        let header = [reader.u32()?, reader.u32()?, reader.u32()?];
        let pointers = [reader.u32()?, reader.u32()?, reader.u32()?, reader.u32()?, reader.u32()?, reader.u32()?];
        let strings = [reader.string(false, 32768)?, reader.string(false, 32768)?, reader.string(false, 32768)?, reader.string(false, 32768)?, reader.string(false, 32768)?];
        let tail = [reader.u32()?, reader.u32()?];
        reader.end()?;
        let expected = [Some(String::from("C:\\test.exe")), Some(String::new()), Some(String::from("\0")), Some(String::from("LocalSystem")), Some(String::from("Serviço teste"))];
        Ok(header == [16, 3, 1] && pointers[0] != 0 && pointers[1] != 0 && pointers[2] == 0 && pointers[3..].iter().all(|&pointer| pointer != 0) && strings == expected && tail == [needed, 0])
    })();
    assert(code(&short) == 122 && needed > 64 && code(&full) == 0 && parsed == Ok(true), "scmr: QueryServiceConfig com tamanho necessario e strings");
    let ex_short = call(40, &Writer::new().context(Some(&service)).u32(0).u32(0).finish(), &client);
    let ex = call(40, &Writer::new().context(Some(&service)).u32(0).u32(36).finish(), &client);
    assert(code(&ex_short) == 122 && code(&ex) == 0 && ex.get(0..4) == Some(&36u32.to_le_bytes()[..]) && ex.get(8..12) == Some(&1u32.to_le_bytes()[..]), "scmr: QueryServiceStatusEx com buffer de 36 bytes");
    // Direitos insuficientes, exclusão adiada até o último contexto.
    let denied = open_service("opennt-scmr-test", 1).get(..20).map(<[u8]>::to_vec).unwrap_or_default();
    assert(code(&call(6, &denied, &client)) == 5 && code(&call(0, &denied, &client)) == 0, "scmr: contexto sem SERVICE_QUERY_STATUS recusado");
    let deleted = code(&call(2, &service, &client));
    let still = service_database::read("opennt-scmr-test").ok().flatten().is_some();
    let reopened = code(&open_service("opennt-scmr-test", 4));
    let closed = code(&call(0, &service, &client));
    let gone = service_database::read("opennt-scmr-test").ok().flatten().is_none();
    assert(deleted == 0 && still && reopened == 1072 && closed == 0 && gone && code(&call(0, &service, &client)) == 6, "scmr: DeleteService adiado ate o ultimo contexto");
    // CreateService e a liberação do processo.
    let create = Writer::new().context(Some(&manager)).string(Some("opennt-scmr-created"), false).string(Some("Créé"), true).u32(0xF_01FF).u32(16).u32(3).u32(1).string(Some("C:\\created.exe"), false).string(None, true).u32(0).u32(0).u32(0).string(None, true).u32(0).u32(0).finish();
    let created = call(12, &create, &client);
    let display = service_database::read("opennt-scmr-created").ok().flatten().map(|configuration| configuration.display_name);
    let created_handle = created.get(4..24).map(<[u8]>::to_vec).unwrap_or_default();
    let marked = code(&call(2, &created_handle, &client));
    service_rpc::release_process(304);
    assert(code(&created) == 0 && display.as_deref() == Some("Créé") && marked == 0 && service_database::read("opennt-scmr-created").ok().flatten().is_none() && code(&call(0, &manager, &client)) == 6, "scmr: CreateService, exclusao e liberacao do processo");
    // Dados NDR malformados e chamador sem o SID de LocalSystem.
    let truncated = service_rpc::call(&client, 15, &[0; 3]).err();
    let trailing = service_rpc::call(&client, 15, &hex("00000000000000003f000f0011223344")).err();
    let anonymous = call(15, &[0; 12], &RpcContext { process_id: 304, token: 0 });
    assert(truncated == Some(1783) && trailing == Some(1783) && code(&anonymous) == 5, "scmr: NDR malformado e chamador sem LocalSystem");
    // LRPC: bind, request, operação inexistente e interface desconhecida.
    let Ok(port) = port_objects::create("alpc", PortState { role: Role::Listener, ..PortState::default() }, 0x200, 0, 0, alloc::boxed::Box::new(|_| {}), port_objects::CreateOptions::default()) else {
        assert(false, "lrpc: porta de teste");
        return;
    };
    let data = |reply: Reply| match reply {
        Reply::Now(result) => result.data,
        Reply::Later(_) => Vec::new(),
    };
    let endpoint = lrpc::Endpoint::new([(String::from("81bb7a364498f135ad3298f038001003:2"), service_rpc::scmr())].into_iter().collect());
    let _ = endpoint.connect(&port, &[], None);
    let mut bind = alloc::vec![0u8; 72];
    bind[0..4].copy_from_slice(&1u32.to_le_bytes());
    bind[12..28].copy_from_slice(&hex("81bb7a364498f135ad3298f038001003"));
    bind[28..32].copy_from_slice(&2u32.to_le_bytes());
    bind[32..36].copy_from_slice(&1u32.to_le_bytes());
    let bound = data(endpoint.exchange_bytes(&port, &bind));
    bind[36..38].copy_from_slice(&17u16.to_le_bytes());
    let rebound = data(endpoint.exchange_bytes(&port, &bind));
    let mut request = alloc::vec![0u8; 76];
    request[12..16].copy_from_slice(&9u32.to_le_bytes());
    request[20..24].copy_from_slice(&15u32.to_le_bytes());
    let response = data(endpoint.exchange_bytes(&port, &request));
    request[20..24].copy_from_slice(&9999u32.to_le_bytes());
    let fault = data(endpoint.exchange_bytes(&port, &request));
    bind[12] ^= 1;
    let unknown = data(endpoint.exchange_bytes(&port, &bind));
    let word = |bytes: &[u8], at: usize| bytes.get(at..at + 4).map_or(u32::MAX, |slice| u32::from_le_bytes(slice.try_into().unwrap()));
    assert(word(&bound, 8) == 0 && u16::from_le_bytes([bound[36], bound[37]]) == 0 && u16::from_le_bytes([rebound[36], rebound[37]]) == 17, "lrpc: bind do SCMR com o id de sintaxe do cliente");
    assert(word(&response, 0) == 3 && word(&response, 12) == 9 && code(&response) == 0 && word(&fault, 0) == 2 && word(&fault, 8) == 1745 && word(&unknown, 8) == 1717, "lrpc: request, operacao inexistente e interface desconhecida");
    endpoint.disconnect(&port);
    service_rpc::release_process(4);
    // Ordem causal: a sequência 2 chega antes e espera; a 1 despacha com a
    // resposta adiada, sem bloquear a 2.
    struct Ordered {
        order: Arc<crate::rtl::SpinLock<Vec<u32>>>,
        complete: Arc<core::sync::atomic::AtomicBool>,
        cleanups: Arc<core::sync::atomic::AtomicU32>,
    }
    struct Deferred {
        complete: Arc<core::sync::atomic::AtomicBool>,
        cleanups: Arc<core::sync::atomic::AtomicU32>,
    }
    impl Pending for Deferred {
        fn poll(&mut self) -> Result<Option<Vec<u8>>, u32> {
            Ok(self.complete.load(core::sync::atomic::Ordering::SeqCst).then(|| alloc::vec![1]))
        }
        fn cleanup(&mut self) {
            self.cleanups.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        }
    }
    impl Interface for Ordered {
        fn call(&self, _context: &RpcContext, operation: u32, _arguments: &[u8]) -> Result<Body, u32> {
            self.order.lock().push(operation);
            Ok(if operation == 101 { Body::Later(alloc::boxed::Box::new(Deferred { complete: self.complete.clone(), cleanups: self.cleanups.clone() })) } else { Body::Now(alloc::vec![2]) })
        }
    }
    let order = Arc::new(crate::rtl::SpinLock::new(Vec::new()));
    let complete = Arc::new(core::sync::atomic::AtomicBool::new(false));
    let cleanups = Arc::new(core::sync::atomic::AtomicU32::new(0));
    let ordered = lrpc::Endpoint::new([(String::from("00112233445566778899aabbccddeeff:1"), Arc::new(Ordered { order: order.clone(), complete: complete.clone(), cleanups: cleanups.clone() }) as Arc<dyn Interface>)].into_iter().collect());
    let _ = ordered.connect(&port, &[], None);
    let mut bind = alloc::vec![0u8; 72];
    bind[0..4].copy_from_slice(&1u32.to_le_bytes());
    bind[12..28].copy_from_slice(&hex("00112233445566778899aabbccddeeff"));
    bind[28..32].copy_from_slice(&1u32.to_le_bytes());
    bind[32..36].copy_from_slice(&1u32.to_le_bytes());
    let _ = ordered.exchange_bytes(&port, &bind);
    let flow_request = |sequence: u32, operation: u32| {
        let mut bytes = alloc::vec![0u8; 64];
        bytes[8..12].copy_from_slice(&2u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&(sequence + 10).to_le_bytes());
        bytes[20..24].copy_from_slice(&operation.to_le_bytes());
        bytes[32..40].copy_from_slice(&0xFEDC_BA98_7654_3210u64.to_le_bytes());
        bytes[40..44].copy_from_slice(&sequence.to_le_bytes());
        bytes
    };
    let later = |reply: Reply| match reply {
        Reply::Later(job) => Some(job),
        Reply::Now(_) => None,
    };
    let mut second = later(ordered.exchange_bytes(&port, &flow_request(2, 102)));
    let second_waits = second.as_mut().is_some_and(|job| job.poll().is_none()) && order.lock().is_empty();
    let duplicate = word(&data(ordered.exchange_bytes(&port, &flow_request(2, 102))), 8);
    let mut first = later(ordered.exchange_bytes(&port, &flow_request(1, 101)));
    let first_pending = first.as_mut().is_some_and(|job| job.poll().is_none()) && *order.lock() == [101];
    let second_reply = second.as_mut().and_then(|job| job.poll()).map(|result| word(&result.data, 12));
    let in_order = *order.lock() == [101, 102];
    complete.store(true, core::sync::atomic::Ordering::SeqCst);
    let first_reply = first.as_mut().and_then(|job| job.poll()).map(|result| word(&result.data, 12));
    if let Some(job) = first.as_mut() {
        job.cleanup(0);
    }
    if let Some(job) = second.as_mut() {
        job.cleanup(0);
    }
    let replayed = word(&data(ordered.exchange_bytes(&port, &flow_request(1, 101))), 8);
    assert(second_waits && duplicate == 1728 && first_pending && second_reply == Some(12) && in_order && first_reply == Some(11) && cleanups.load(core::sync::atomic::Ordering::SeqCst) == 1 && replayed == 1728, "lrpc: ordem causal com resposta adiada que nao bloqueia a seguinte");
    ordered.disconnect(&port);
    // O último handle destrói a porta de teste.
    let scratch = guest::alloc_bytes(8);
    if port_objects::publish(&port, scratch, 0).is_ok_and(|status| status == 0) {
        let _ = crate::ntos::ob::close::close_user(guest::read64(scratch), true);
    }
    guest::free_bytes(scratch);
}

static SC_OUTPUT: crate::rtl::SpinLock<alloc::vec::Vec<alloc::string::String>> = crate::rtl::SpinLock::new(alloc::vec::Vec::new());

fn sc_capture(line: &str) {
    SC_OUTPUT.lock().push(alloc::string::String::from(line));
}

fn shell_service_control(assert: Assert) {
    use crate::ntos::cm::service::database as service_database;
    use crate::drivers::fs::memory_file_system;
    use crate::shell::service_control::{self, Execution};
    use alloc::string::String;
    use alloc::vec::Vec;
    // Executa o comando e devolve (código de saída, saída).
    let run = |command: &str| -> (u32, String) {
        SC_OUTPUT.lock().clear();
        let code = match service_control::execute(command, sc_capture) {
            Execution::Done(code) => code,
            Execution::Pending(mut waiting) => waiting.poll().unwrap_or(u32::MAX),
        };
        (code, SC_OUTPUT.lock().join("\n"))
    };
    let code = |command: &str| run(command).0;
    // Aspas não destroem caminhos, valores vazios nem aspas internas.
    let tokens = |line: &str| service_control::tokenize(line).ok().unwrap_or_default();
    let strings = |items: &[&str]| items.iter().map(|item| String::from(*item)).collect::<Vec<String>>();
    assert(tokens("create \"Service One\" binPath= \"C:\\Driver Files\\driver.sys\"") == strings(&["create", "Service One", "binPath=", "C:\\Driver Files\\driver.sys"]) && tokens("config svc depend= \"\"") == strings(&["config", "svc", "depend=", ""]) && tokens("create svc binPath= \"\\\"C:\\Program Files\\svc.exe\\\"\"") == strings(&["create", "svc", "binPath=", "\"C:\\Program Files\\svc.exe\""]), "sc: tokenizacao com aspas, vazios e aspas internas");
    // Opções inválidas não tocam a hive.
    let invalid = [code("create opennt-sc-invalid binPath= \"unterminated"), code("create opennt-sc-bad binPath= C:\\bad.sys unknown= yes"), code("create opennt-sc-bad binPath= C:\\bad.sys type= kernel type= own"), code("create opennt-sc-bad binPath= C:\\bad.sys start= bananas"), code("create opennt-sc-bad binPath= C:\\bad.sys type= constructor"), code("create opennt-sc-bad binPath= C:\\bad.sys depend= +group"), code("create opennt-sc-bad binPath="), code("create opennt-sc-bad binPath= C:\\bad.sys obj= OtherAccount")];
    let untouched = service_database::read("opennt-sc-invalid").ok().flatten().is_none() && service_database::read("opennt-sc-bad").ok().flatten().is_none();
    assert(invalid == [87, 87, 87, 87, 87, 50, 87, 50] && untouched && code("query opennt-sc-missing") == 1060 && code("\\\\server query") == 50 && code("bogus") == 87, "sc: opcoes invalidas, servico ausente, SCM remoto e comando desconhecido");
    // Drivers nativos reais: DriverEntry registra um DriverUnload que só retorna.
    let entry = [0x48, 0x8D, 0x05, 0x19, 0x00, 0x00, 0x00, 0x48, 0x89, 0x41, 0x68, 0x31, 0xC0, 0xC3];
    let _ = memory_file_system::write_bytes("/opennt-sc.sys", super::phase6::driver_image(&entry, &[(0x1320, &[0xC3])]));
    let _ = memory_file_system::write_bytes("/opennt-sc-dep.sys", super::phase6::driver_image(&entry, &[(0x1320, &[0xC3])]));
    let _ = memory_file_system::write_bytes("/opennt-sc-fail.sys", super::phase6::driver_image(&[0xB8, 0x01, 0x00, 0x00, 0xC0, 0xC3], &[]));
    let created = code("CREATE \"OpenNt Sc One\" binPath= \"C:\\opennt-sc.sys\" type= kernel displayName= \"Driver de teste\"");
    let image = service_database::read("OpenNt Sc One").ok().flatten().map(|configuration| configuration.image_path);
    assert(created == 0 && image.as_deref() == Some("C:\\opennt-sc.sys") && code("create \"OpenNt Sc One\" binPath= C:\\duplicate.sys") == 1073, "sc: CreateService com aspas e duplicado recusado");
    let qc = run("qc \"OpenNt Sc One\"").1;
    let keyname = run("getkeyname \"driver de teste\"").1;
    let display = run("getdisplayname \"OpenNt Sc One\"").1;
    let queryex = run("queryex \"OPENNT SC ONE\"").1;
    assert(qc.contains("DISPLAY_NAME       : Driver de teste") && keyname.contains("NAME = OpenNt Sc One") && display.contains("NAME = Driver de teste") && queryex.contains("STATE              : 1  STOPPED"), "sc: qc, getkeyname, getdisplayname e queryex");
    let services = run("query").1;
    let inactive = run("query type= driver state= inactive").1;
    assert(!services.contains("OpenNt Sc One") && inactive.contains("OpenNt Sc One") && code("query state= invalid") == 87 && code("query type= constructor") == 87 && code("query \"OpenNt Sc One\" state= all") == 87, "sc: filtros de enumeracao");
    // Ciclo do driver: desabilitado, início real, controles e parada.
    let disabled = (code("config \"OpenNt Sc One\" start= disabled"), code("start \"OpenNt Sc One\""));
    let enabled = code("config \"OpenNt Sc One\" start=demand");
    let started = run("start \"OpenNt Sc One\"");
    assert(disabled == (0, 1058) && enabled == 0 && started.0 == 0 && started.1.contains("STATE              : 4  RUNNING"), "sc: servico desabilitado recusado e driver iniciado de verdade");
    let controls = [code("start \"OpenNt Sc One\""), code("delete \"OpenNt Sc One\""), code("pause \"OpenNt Sc One\"")];
    let interrogated = run("interrogate \"OpenNt Sc One\"");
    let stopped = (code("stop \"OpenNt Sc One\""), code("stop \"OpenNt Sc One\""));
    assert(controls == [1056, 1061, 1052] && interrogated.0 == 0 && interrogated.1.contains("RUNNING") && stopped == (0, 1062), "sc: controles do driver, interrogate e stop");
    // Dependências: início em ordem e proteção contra parada.
    let dependency = (code("create opennt-sc-dep binPath=C:\\opennt-sc-dep.sys type=kernel"), code("config \"OpenNt Sc One\" depend= opennt-sc-dep"), code("start \"OpenNt Sc One\""));
    let enumerated = run("enumdepend opennt-sc-dep").1;
    let guarded = (code("stop opennt-sc-dep"), code("config opennt-sc-dep depend= \"OpenNt Sc One\""));
    let released = (code("stop \"OpenNt Sc One\""), code("stop opennt-sc-dep"), code("config \"OpenNt Sc One\" depend= \"\""));
    let cleared = service_database::read("OpenNt Sc One").ok().flatten().is_some_and(|configuration| configuration.dependencies.is_empty());
    assert(dependency == (0, 0, 0) && enumerated.contains("OpenNt Sc One") && guarded == (1051, 1059) && released == (0, 0, 0) && cleared, "sc: dependencias iniciadas em ordem e protegidas contra parada e ciclo");
    assert(code("delete \"OpenNt Sc One\"") == 0 && code("delete opennt-sc-dep") == 0 && code("query \"OpenNt Sc One\"") == 1060, "sc: DeleteService dos servicos parados");
    // O NTSTATUS da fronteira nativa não se perde no erro de start.
    let failure = (code("create opennt-sc-fail binPath=C:\\opennt-sc-fail.sys type=kernel"), run("start opennt-sc-fail"));
    let after = run("query opennt-sc-fail").1;
    assert(failure.0 == 0 && failure.1 .0 == 31 && failure.1 .1.contains("NTSTATUS: 0xc0000001") && after.contains("STOPPED") && code("delete opennt-sc-fail") == 0, "sc: falha do DriverEntry com o NTSTATUS e servico parado");
    // Serviço de usuário: argumentos de início recusados; controle de serviço parado.
    let user = (code("create opennt-sc-user binPath=C:\\user.exe"), code("start opennt-sc-user extra"), code("pause opennt-sc-user"), code("control opennt-sc-user 300"), code("control opennt-sc-user 200"), code("delete opennt-sc-user"));
    assert(user == (0, 50, 1062, 87, 1062, 0), "sc: servico de usuario com argumentos recusados e controles de servico parado");
    let help = run("help").1;
    assert(help.contains("sc query [nome]") && run("").1.contains("sc qc <nome>"), "sc: ajuda");
    let _ = memory_file_system::remove("/opennt-sc.sys");
    let _ = memory_file_system::remove("/opennt-sc-dep.sys");
    let _ = memory_file_system::remove("/opennt-sc-fail.sys");
}

fn boot_services_hive(assert: Assert) {
    use crate::ntos::cm::registry;
    use crate::ntos::cm::service::database as service_database;
    use crate::ntos::io::pnp;
    use crate::ntos::io::small::boot_drivers_state;
    use alloc::string::String;
    // Serviços semeados no phase0: tipo kernel, Start e o caminho em Drivers.
    let expected = [("i8042prt", 3), ("kbdclass", 3), ("mouclass", 3), ("atapi", 0), ("disk", 0), ("mountmgr", 0)];
    let seeded = expected.iter().all(|&(name, start)| {
        service_database::read(name).ok().flatten().is_some_and(|configuration| configuration.service_type == 1 && configuration.start == start && configuration.image_path == alloc::format!("\\SystemRoot\\System32\\Drivers\\{name}.sys"))
    });
    let vgk_seeded = service_database::read("vgk").ok().flatten().is_some_and(|configuration| configuration.service_type == 1 && configuration.start == 3 && configuration.image_path == "\\SystemRoot\\System32\\Drivers\\vgk.sys");
    // Parâmetros do i8042prt e os UpperFilters das classes de teclado e mouse.
    let parameters = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\i8042prt\\Parameters";
    let dword = |name: &str| registry::read_value_by_path(parameters, name).filter(|value| value.value_type == 4 && value.data.len() == 4).map(|value| u32::from_le_bytes([value.data[0], value.data[1], value.data[2], value.data[3]]));
    let values = (dword("KeyboardDataQueueSize"), dword("MouseDataQueueSize"), dword("PollStatusIterations"), dword("PollingIterations"), dword("ResendIterations"), dword("OverrideKeyboardType"), dword("CrashOnCtrlScroll"));
    let classes = pnp::read_class_upper_filters("{4D36E96B-E325-11CE-BFC1-08002BE10318}") == [String::from("kbdclass")] && pnp::read_class_upper_filters("{4D36E96F-E325-11CE-BFC1-08002BE10318}") == [String::from("mouclass")];
    assert(seeded && vgk_seeded, "bootservices: pilhas de teclado/mouse, armazenamento e vgk semeadas na hive");
    assert(values == (Some(0x64), Some(0x64), Some(0x2000), Some(0x1900), Some(3), Some(0), Some(0)) && classes, "bootservices: parametros do i8042prt e UpperFilters das classes");
    // A fase 1 percorreu os serviços de boot e concluiu a fase de drivers.
    assert(boot_drivers_state::is_initialized(), "bootservices: fase de drivers de boot concluida pela fase 1");
}

fn usermode_syscalls_exports(assert: Assert) {
    use core::mem::offset_of;
    use crate::ntos::inc::types::extra_usermode::{ApcCallbackData, KcontinueArgument};
    use crate::ntos::ke::{apc, thread_alert};
    use crate::ntos::mm::kernel_pool;
    use crate::ntos::ps::process;
    use crate::ntos::ps::user::handles::UserProcess;
    use crate::ntos::ps::user::{memory, threads, user_apc};
    let Ok(block) = memory::map_user_region(0x4000) else {
        assert(false, "userapc: memoria de usuario");
        return;
    };
    let rsp = block + 0x3800;
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map(|handler| handler(a1, a2, a3, a4, rsp).unwrap_or(1)).unwrap_or(1);
    // Argumentos de pilha 5.. (ULONG_PTR em [rsp+0x28]...).
    let stack = |index: u64, value: u64| unsafe { nt::Field::<u64>::at(rsp + 0x28 + (index - 5) * 8) }.set(value);
    let (dispatcher, routine, routine2, oa, cid, out, timeout, name, getbuf, uctx) = (block + 0x100, block + 0x180, block + 0x1C0, block + 0x500, block + 0x540, block + 0x580, block + 0x5C0, block + 0x5D0, block + 0x1000, block + 0x1800);
    // Processo e threads de usuário simulados (não de sistema).
    let previous_thread = process::get_current_thread();
    let saved = state::with(|state| (state.current_process_id, state.ntdll_exports.clone()));
    let snapshot = threads::all();
    let previous_current = threads::current();
    let Ok(owner) = process::create_process(0x7DD0, "apc.exe", 0, None) else {
        assert(false, "userapc: processo de usuario");
        return;
    };
    let (Ok(first), Ok(second)) = (process::create_kernel_thread(owner, 0x7DD4, true, 1, None), process::create_kernel_thread(owner, 0x7DD8, true, 1, None)) else {
        assert(false, "userapc: threads do processo");
        return;
    };
    let thread = threads::UserThread::new(0x7DD4, first, 0, 0);
    let other = threads::UserThread::new(0x7DD8, second, 0, 0);
    let live = guest::alloc_aligned(nt::Context::SIZE, 16, true);
    thread.with(|state| state.context = live);
    threads::clear();
    threads::push(thread.clone());
    threads::push(other.clone());
    process::set_current_thread(first);
    threads::set_running(true, Some(thread.clone()));
    state::with(|state| {
        state.current_process_id = 0x7DD0;
        state.ntdll_exports = Some([(alloc::string::String::from("KiUserApcDispatcher"), dispatcher)].into_iter().collect());
    });
    let (live_context, target) = unsafe { (nt::Context::at(live), nt::Kthread::at(first)) };
    let reset = || {
        threads::initialize_context(live, block + 0x200, block + 0x3000, 0, 0);
        live_context.rax.set(0xC0);
    };
    reset();
    let handle = threads::thread_handle(&thread, 0x1F_FFFF, 0).unwrap_or(0);
    let limited = threads::thread_handle(&thread, 0x40, 0).unwrap_or(0);
    let head = &target.apc_state.apc_list_head[1];
    let pending = || target.apc_state.user_apc_pending_all.get();
    // Frame do KiUserApcDispatcher: MACHINE_FRAME alinhado logo abaixo da
    // pilha; CONTEXT 0x530 bytes antes (CONTEXT + CONTEXT_EX/KCONTINUE_ARGUMENT/APC_CALLBACK_DATA, 0x20 cada).
    let machine = (block + 0x3000 - nt::MachineFrame::SIZE) & !15;
    let frame = machine - (nt::Context::SIZE + 0x60);
    let (apc_frame, continuation, callback, machine_frame) = unsafe { (nt::Context::at(frame), KcontinueArgument::at(frame + 0x4F0), ApcCallbackData::at(frame + 0x510), nt::MachineFrame::at(machine)) };
    let homes = |context: &nt::Context, values: [u64; 5]| [&context.p1_home, &context.p2_home, &context.p3_home, &context.p4_home, &context.p5_home].iter().zip(values).all(|(field, value)| field.get() == value);

    // NtQueueApcThread*: recusas na ordem do NtQueueApcThreadEx2.
    stack(5, 0x33);
    stack(6, 0);
    stack(7, 0);
    assert(call("NtQueueApcThreadEx2", handle, 0, 2, routine) == 0xC000_000D && call("NtQueueApcThreadEx2", handle, 4, 1, routine) == 0xC000_000D && call("NtQueueApcThread", limited, routine, 0x11, 0x22) == 0xC000_0022 && call("NtQueueApcThreadEx", handle, 0x7FF0, routine, 0x11) == 0xC000_0008, "userapc: flags, reserva com especial, acesso e reserva inexistente");
    // APC normal: na fila nativa, sem pendência (thread fora de espera alertável).
    let queued = call("NtQueueApcThread", handle, routine, 0x11, 0x22);
    let packet = head.flink.get().wrapping_sub(offset_of!(nt::Kapc, apc_list_entry) as u64);
    let kapc = unsafe { nt::Kapc::at(packet) };
    assert(queued == 0 && head.flink.get() != head.address() && kapc.reserved[2].get() == routine && kapc.normal_context.get() == 0x11 && kapc.system_argument1.get() == 0x22 && kapc.system_argument2.get() == 0x33 && kapc.apc_mode.get() == 1 && kapc.inserted.get() == 1 && pending() == 0, "userapc: KAPC de usuario na fila nativa sem pendencia");
    assert(thread_alert::consume(first, 1, false).is_none() && user_apc::deliver(&thread) == 0 && live_context.rip.get() == block + 0x200, "userapc: sem pendencia nada e entregue nem espera nao alertavel interrompida");
    // SleepEx(..., TRUE): a espera alertável de UserMode volta com STATUS_USER_APC.
    unsafe { nt::LargeInteger::at(timeout) }.quad_part.set(-10_000_000);
    assert(call("NtDelayExecution", 1, timeout, 0, 0) == 0xC0 && pending() & 2 != 0 && thread_alert::consume(first, 1, false) == Some(0xC0), "userapc: espera alertavel interrompida e UserApcPending publicado");
    // Entrega no retorno ao modo usuário.
    let delivered = user_apc::deliver(&thread);
    let context_ok = apc_frame.context_flags.get() == 0x10_001B && apc_frame.rip.get() == block + 0x200 && apc_frame.rsp.get() == block + 0x3000 && apc_frame.rax.get() == 0xC0 && apc_frame.e_flags.get() == 0x202;
    let tail_ok = continuation.continue_type.get() == 1 && continuation.continue_flags.get() == 3 && machine_frame.rip.get() == block + 0x200 && machine_frame.rsp.get() == block + 0x3000;
    let redirected = live_context.rsp.get() == frame && live_context.rip.get() == dispatcher && live_context.seg_cs.get() == 0x33;
    assert(delivered == 0 && homes(apc_frame, [0x11, 0x22, 0x33, routine, 1]) && context_ok && tail_ok && redirected && head.flink.get() == head.address() && pending() == 0 && !kernel_pool::owns(packet), "userapc: frame CONTEXT/KCONTINUE_ARGUMENT/MACHINE_FRAME e KAPC liberada");
    // APC especial (NtQueueApcThreadEx com 1): entregue sem espera alertável.
    reset();
    stack(5, 0x55);
    stack(6, 0x66);
    let special = call("NtQueueApcThreadEx", handle, 1, routine2, 0x44);
    let marked = pending() & 1 != 0;
    let delivered = user_apc::deliver(&thread);
    assert(special == 0 && marked && delivered == 0 && homes(apc_frame, [0x44, 0x55, 0x66, routine2, 2]) && continuation.continue_flags.get() == 2 && pending() == 0, "userapc: APC especial com SpecialUserApcPending e continuacao sem TEST_ALERT");
    // APC_CALLBACK_DATA (Ex2 com 0x10000) e NtTestAlert publicando a pendência.
    reset();
    stack(5, 0x77);
    stack(6, 0x88);
    stack(7, 0x99);
    let queued_callback = call("NtQueueApcThreadEx2", handle, 0, 0x1_0000, routine);
    let tested = call("NtTestAlert", 0, 0, 0, 0);
    let delivered = user_apc::deliver(&thread);
    let callback_ok = callback.parameter.get() == 0x88 && callback.context_record.get() == frame;
    assert(queued_callback == 0 && tested == 0 && delivered == 0 && callback_ok && homes(apc_frame, [0x77, frame + 0x510, 0x99, routine, 5]), "userapc: NtTestAlert publica a pendencia e APC_CALLBACK_DATA substitui o argumento 1");
    // NtTestAlert consome o alerta de usuário.
    let _ = thread_alert::alert(first, 1);
    assert(call("NtTestAlert", 0, 0, 0, 0) == 0x101 && target.alerted[1].get() == 0 && call("NtTestAlert", 0, 0, 0, 0) == 0, "userapc: NtTestAlert consome o alerta de usuario");

    // NtContinueEx: alinhamentos, entrega no próprio CONTEXT e continuação.
    guest::write_bytes(uctx, &[0u8; 0x530]);
    let (user_context, user_continuation) = unsafe { (nt::Context::at(uctx), KcontinueArgument::at(uctx + 0x4F0)) };
    user_context.context_flags.set(0x10_0001); // sem INTEGER: a restauração recusa
    user_continuation.continue_type.set(1);
    user_continuation.continue_flags.set(3);
    assert(call("NtContinueEx", uctx, uctx + 0x4F4, 0, 0) == 0x8000_0002 && call("NtContinueEx", uctx + 8, 0, 0, 0) == 0x8000_0002 && call("NtContinue", 0, 1, 0, 0) == 0xC000_0005, "userapc: NtContinueEx alinhamentos e NtContinue sem contexto");
    stack(5, 0xA3);
    let self_queued = call("NtQueueApcThread", (-2i64) as u64, routine, 0xA1, 0xA2);
    let in_place = call("NtContinueEx", uctx, uctx + 0x4F0, 0, 0);
    let in_place_homes = homes(user_context, [0xA1, 0xA2, 0xA3, routine, 1]);
    let restored = call("NtContinueEx", uctx, uctx + 0x4F0, 0, 0);
    assert(self_queued == 0 && in_place == 0 && in_place_homes && head.flink.get() == head.address() && pending() == 0 && restored == 0xC000_000D, "userapc: DELIVER_APC entrega no proprio CONTEXT e sem APC segue para a restauracao");

    // NtGetContextThread/NtSetContextThread na thread corrente (-2).
    reset();
    live_context.rax.set(0x1234);
    live_context.dr0.set(0x1111);
    guest::write_bytes(getbuf, &[0xEE; nt::Context::SIZE as usize]);
    let buffer = unsafe { nt::Context::at(getbuf) };
    let current = (-2i64) as u64;
    buffer.context_flags.set(0x10_0003);
    let got = call("NtGetContextThread", current, getbuf, 0, 0);
    let control_ok = buffer.rip.get() == block + 0x200 && buffer.rsp.get() == block + 0x3000 && buffer.seg_cs.get() == 0x33 && buffer.e_flags.get() == 0x202 && buffer.rax.get() == 0x1234;
    assert(got == 0 && control_ok && buffer.context_flags.get() == 0x10_0003 && buffer.flt_save.control_word.get() == 0xEEEE, "userctx2: NtGetContextThread copia so os grupos pedidos");
    buffer.context_flags.set(0x10_0014);
    let segments = call("NtGetContextThread", current, getbuf, 0, 0) == 0 && buffer.seg_ds.get() == 0x2B && buffer.seg_es.get() == 0x2B && buffer.seg_fs.get() == 0x53 && buffer.seg_gs.get() == 0x2B && buffer.dr0.get() == 0;
    live_context.dr7.set(1);
    let debug = call("NtGetContextThread", current, getbuf, 0, 0) == 0 && buffer.dr0.get() == 0x1111 && buffer.dr7.get() == 1;
    buffer.context_flags.set(0x4010_0001);
    let reporting = call("NtGetContextThread", current, getbuf, 0, 0) == 0 && buffer.context_flags.get() == 0xD010_0001;
    // getbuf+8 lê ContextFlags em getbuf+0x38 (SegCs/SegDs...): válido, para chegar ao alinhamento.
    unsafe { nt::Field::<u32>::at(getbuf + 0x38) }.set(0x10_0001);
    buffer.context_flags.set(0x10_0040);
    let refusals = call("NtGetContextThread", current, getbuf, 0, 0) == 0xC000_00BB && call("NtGetContextThread", current, getbuf + 8, 0, 0) == 0x8000_0002 && call("NtGetContextThread", limited, getbuf, 0, 0) == 0xC000_0022;
    assert(segments && debug && reporting && refusals, "userctx2: segmentos fixos, banco de depuracao ativo, REPORTING|SERVICE_ACTIVE e recusas");
    buffer.context_flags.set(0x10_0002);
    buffer.rax.set(0xCAFE);
    let set = call("NtSetContextThread", current, getbuf, 0, 0);
    let applied = live_context.rax.get() == 0xCAFE && live_context.rip.get() == block + 0x200;
    let restrict = unsafe { nt::Eprocess::at(owner) };
    restrict.set_restrict_set_thread_context(1);
    let restricted = call("NtSetContextThread", current, getbuf, 0, 0);
    restrict.set_restrict_set_thread_context(0);
    assert(set == 0 && applied && restricted == 0xC000_060A && call("NtSetContextThread", limited, getbuf, 0, 0) == 0xC000_0022, "userctx2: NtSetContextThread aplica INTEGER e RestrictSetThreadContext recusa");

    // NtOpenProcess.
    let (attributes, client) = unsafe { (nt::ObjectAttributes::at(oa), nt::ClientId::at(cid)) };
    set_object_attributes(attributes, nt::ObjectAttributes::SIZE as u32, 0, 0, 0);
    client.unique_process.set(0x7DD0);
    client.unique_thread.set(0);
    let opened_handle = unsafe { nt::Field::<u64>::at(out) };
    let pointer_of = |handle: u64| state::get_user_handle(handle).and_then(|entry| entry.downcast::<UserProcess>().map(|object| (object.pointer, object.process_id)));
    let access_of = |handle: u64| state::get_user_handle(handle).map(|entry| (entry.kind(), entry.access()));
    let opened = call("NtOpenProcess", out, 0x1000, oa, cid);
    let process_handle = opened_handle.get();
    let entry_ok = access_of(process_handle) == Some(("process", 0x1000)) && pointer_of(process_handle) == Some((owner, 0x7DD0));
    let maximum = call("NtOpenProcess", out, 0x0200_0000, oa, cid) == 0 && access_of(opened_handle.get()) == Some(("process", 0x1F_FFFF));
    let maximum_handle = opened_handle.get();
    client.unique_process.set(0);
    client.unique_thread.set(0x7DD8);
    let by_thread = call("NtOpenProcess", out, 0x1400, oa, cid) == 0 && pointer_of(opened_handle.get()).is_some_and(|(pointer, _)| pointer == owner);
    let query_handle = opened_handle.get();
    client.unique_process.set(0x7DD4);
    let wrong_owner = call("NtOpenProcess", out, 0x1000, oa, cid);
    client.unique_process.set(0x7FFF_FFF0);
    client.unique_thread.set(0);
    let missing = call("NtOpenProcess", out, 0x1000, oa, cid);
    assert(opened == 0 && entry_ok && maximum && by_thread && wrong_owner == 0xC000_000B && missing == 0xC000_000B, "userproc: NtOpenProcess por PID, MAXIMUM_ALLOWED, pela thread e CLIENT_ID invalidos");
    client.unique_process.set(0x7DD0);
    let no_cid = call("NtOpenProcess", out, 0x1000, oa, 0);
    attributes.object_name.set(name);
    let named = call("NtOpenProcess", out, 0x1000, oa, cid);
    attributes.object_name.set(0);
    assert(no_cid == 0xC000_0030 && named == 0xC000_0030 && call("NtOpenProcess", out, 0x1000, 0, cid) == 0xC000_0005 && call("NtOpenProcess", out, 0x1000, oa + 2, cid) == 0x8000_0002 && call("NtOpenProcess", out, 0x1000, oa, cid + 2) == 0x8000_0002 && call("NtOpenProcess", 0, 0x1000, oa, cid) == 0xC000_0005, "userproc: NtOpenProcess recusas de mistura, nome, alinhamento e sonda");
    // NtGetNextProcess: começo, para trás/frente a partir do processo e Flags inválido.
    let list: Vec<u64> = process::list_active_processes().into_iter().map(|entry| entry.address).collect();
    let pointer = |handle: u64| pointer_of(handle).map(|(pointer, _)| pointer);
    stack(5, out);
    let from_start = call("NtGetNextProcess", 0, 0, 0, 0) == 0 && pointer(opened_handle.get()) == list.first().copied();
    let start_handle = opened_handle.get();
    let index = list.iter().position(|&address| address == owner).unwrap_or(0);
    let backward = call("NtGetNextProcess", process_handle, 0, 0, 1);
    let backward_ok = if index == 0 { backward == 0x8000_001A } else { backward == 0 && pointer(opened_handle.get()) == Some(list[index - 1]) };
    let backward_handle = opened_handle.get();
    let forward = call("NtGetNextProcess", process_handle, 0, 0, 0);
    let forward_ok = if index + 1 == list.len() { forward == 0x8000_001A && opened_handle.get() == 0 } else { forward == 0 && pointer(opened_handle.get()) == Some(list[index + 1]) };
    let forward_handle = opened_handle.get();
    let bad_flags = call("NtGetNextProcess", 0, 0, 0, 2);
    stack(5, 0);
    assert(from_start && backward_ok && forward_ok && bad_flags == 0xC000_000D && call("NtGetNextProcess", 0, 0, 0, 0) == 0xC000_0005, "userproc: NtGetNextProcess pela PsActiveProcessHead");
    // NtGetNextThread: ordem de criação dentro do processo.
    stack(5, 0);
    stack(6, out);
    let first_thread = call("NtGetNextThread", query_handle, 0, 0x40, 0) == 0 && threads::resolve(opened_handle.get(), 0x40).is_ok_and(|found| Arc::ptr_eq(&found, &thread));
    let first_handle = opened_handle.get();
    let second_thread = call("NtGetNextThread", query_handle, first_handle, 0x0200_0000, 0) == 0 && threads::resolve(opened_handle.get(), 0x1F_FFFF).is_ok_and(|found| Arc::ptr_eq(&found, &other));
    let second_handle = opened_handle.get();
    let end = call("NtGetNextThread", query_handle, second_handle, 0x40, 0);
    let denied = call("NtGetNextThread", process_handle, 0, 0x40, 0);
    stack(5, 1);
    let bad_thread_flags = call("NtGetNextThread", query_handle, 0, 0x40, 0);
    assert(first_thread && second_thread && end == 0x8000_001A && denied == 0xC000_0022 && bad_thread_flags == 0xC000_000D, "userproc: NtGetNextThread na ordem de criacao, fim, acesso ao processo e Flags");

    // Restaura o runtime e libera tudo.
    for value in [handle, limited, process_handle, maximum_handle, query_handle, start_handle, backward_handle, forward_handle, first_handle, second_handle] {
        if value != 0 {
            let _ = call("NtClose", value, 0, 0, 0);
        }
    }
    let _ = apc::rundown(first);
    threads::set_running(false, previous_current);
    process::set_current_thread(previous_thread);
    threads::clear();
    for saved_thread in snapshot {
        threads::push(saved_thread);
    }
    state::with(|state| {
        state.current_process_id = saved.0;
        state.ntdll_exports = saved.1;
    });
    guest::free_bytes(live);
    let _ = process::release_thread(first);
    let _ = process::release_thread(second);
    let _ = process::terminate_process(owner, 0);
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

pub fn run(assert: Assert) {
    crate::ntos::test::multiprocess::process_state::run(assert);
    crate::ntos::test::multiprocess::page_table_root::run(assert);
    crate::ntos::test::multiprocess::handles::run(assert);
    user_handle_table(assert);
    user_memory_helpers(assert);
    map_view_parameter_validation(assert);
    data_sections(assert);
    file_and_named_sections(assert);
    image_sections(assert);
    section_image_views(assert);
    section_creation(assert);
    section_open_and_map(assert);
    system_space_views(assert);
    virtual_memory_queries(assert);
    user_virtual_memory(assert);
    volume_file_lookup(assert);
    user_registry(assert);
    user_file_io(assert);
    user_file_io_more(assert);
    disk_write_stress(assert, 12, 3);
    user_file_syscalls(assert);
    user_handle_operations(assert);
    user_events_and_semaphores(assert);
    user_mutants_and_timers(assert);
    user_io_completion(assert);
    user_threads(assert);
    user_wait_packets(assert);
    bundled_bring_up_ntdll(assert);
    user_system_services(assert);
    user_loader(assert);
    user_nls(assert);
    user_syscalls_core(assert);
    user_index(assert);
    user_ring3(assert);
    user_address_floor(assert);
    user_tokens(assert);
    user_query_object(assert);
    user_remove_completion(assert);
    user_alpc_foundation(assert);
    user_alpc_services(assert);
    user_alpc_connect_capture(assert);
    user_alpc_message_handles(assert);
    user_alpc_transport(assert);
    user_alpc_connect_port(assert);
    user_lpc_csr(assert);
    user_alpc_zw_group(assert);
    user_worker_factory(assert);
    user_wnf(assert);
    user_thread_context(assert);
    user_exceptions(assert);
    usermode_syscalls_exports(assert);
    user_process_information_hooks(assert);
    memory_partition(assert);
    service_dispatcher_channel(assert);
    service_control_manager_rpc(assert);
    shell_service_control(assert);
    boot_services_hive(assert);
    user_windows_process(assert);
    crate::ntos::test::user_half::run(assert);
    debug_print!("PHASE7_SELFTEST_OK");
}
