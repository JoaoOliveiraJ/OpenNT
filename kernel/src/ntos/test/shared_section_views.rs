//! Autotestes das seções que o DWM, o LogonUI e o BasicRender compartilham:
//! as sequências exatas dos binários do 19041 pelos exports reais.
//!
//! - Backing store de uma alocação do VidMm
//!   (VIDMM_GLOBAL::CommitGlobalBackingStore 0x65E90 e CommitLocalBackingStore
//!   0x77510 do dxgmms2): MmCreateSection com SEC_PARTITION_OWNER_HANDLE e -1,
//!   ObfReferenceObject + ObInsertObject sem nome + ObCloseHandle, vista de
//!   sistema, ObOpenObjectByPointer em UserMode com acesso 0 e
//!   MmMapViewOfSection no processo; as vistas são alias dos mesmos PFNs.
//! - MDL da vista de usuário (VidMmiProbeAndLockAllocation e
//!   WARPKMALLOCATION::Map 0x3F2C do BasicRender): MmProbeAndLockPages grava o
//!   processo no MDL, e o BasicRender anexa a ele para travar de novo a vista
//!   de usuário e mapeá-la no sistema.
//! - Página de cerca monitorada (VIDMM_FENCE_STORAGE_PAGE::Init 0x60430 e
//!   MapCpuVA 0x87510): vista de sistema RW travada por MDL e vista de usuário
//!   PAGE_READONLY da mesma página.
//! - Seções do DirectComposition (CApplicationChannel::Initialize 0x5CA50,
//!   CBatchSharedMemoryPool, CSharedSectionMarshaler::CreateSection 0xA6B10 e
//!   CDCompMappedSharedSectionMarshaler::InitializeSection 0x9F714 do
//!   win32kbase; CTokenManager::Initialize do dxgkrnl): SEC_COMMIT |
//!   SEC_NO_CHANGE no MmCreateSection e no ZwCreateSection, vistas com
//!   SEC_NO_CHANGE e o ObOpenObjectByPointer com HandleAttributes 0xC0000000;
//!   o desmapeamento da vista SEC_NO_CHANGE recusado só enquanto uma faixa
//!   dela está protegida por MmSecureVirtualMemory (MiUnmapViewOfSection).
//! - Objetos de um tipo de driver duplicados entre processos e resolvidos
//!   pelo tipo no destino (os objetos compartilhados do dxgkrnl movidos pelo
//!   NtDCompositionDuplicateHandleToProcess).
//! - Superfície de redirecionamento GDI (Win32CreateSection 0x6c854 do
//!   win32kbase, SURFACE::Map 0x7ab20, CddBitmapSw::GetSysMemBits 0x27f94 do
//!   cdd, GetSoSurfaceData 0x173a8 do win32kfull e MapSection 0x4510e do
//!   dwmcore): a vista desmapeada de outro processo sem anexar, a vista nova
//!   do processo corrente e o handle de usuário do DWM pelo
//!   ObOpenObjectByPointer de modo kernel.
//! - Vistas na saída do processo: só o EPROCESS.Flags.VmDeleted recusa o
//!   mapeamento; nas rotinas de saída (depois do callout de saída do win32k)
//!   o processo que sai ainda desmapeia (CddBitmapSw::OnCloseProcess 0x23f0c).
//! - Leitura da tela composta (bSpDwmUpdateSurface 0x2ded8 do win32kfull): a
//!   seção que o DWM devolve na tabela dele vai para a tabela do System pelo
//!   ObDuplicateObject com destino nulo, OBJ_KERNEL_HANDLE e KernelMode.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::ntos::inc::types::{self as nt, NtStruct};
use crate::ntos::mm::{guest_memory as guest, paging};
use crate::ntos::ob::objects::section as section_objects;
use crate::ntos::ob::{object_header, object_types, open_pointer};
use crate::ntos::ps::process;
use crate::ntos::ps::user::{sections, state};
use crate::ntos::test::multiprocess::identity::with_test_process;
use crate::ntos::test::phase6::call_export;

type Assert = fn(bool, &str);

const SEC_COMMIT: u64 = 0x0800_0000;
const SEC_NO_CHANGE: u64 = 0x0040_0000;
const SEC_PARTITION_OWNER_HANDLE: u64 = 0x0004_0000;
const MDL_PAGES_LOCKED: i16 = 0x0002;
const MDL_WRITE_OPERATION: i16 = 0x0080;

/// O NTSTATUS de 32 bits como o export devolve.
fn status(value: Option<u64>) -> u32 {
    value.map_or(0xDEAD_BEEF, |value| value as u32)
}

fn mdl(address: u64) -> &'static nt::Mdl {
    // SAFETY: MDL devolvido pelo IoAllocateMdl do teste.
    unsafe { nt::Mdl::at(address) }
}

/// O PFN `index` do MDL (o vetor logo depois do cabeçalho).
fn mdl_frame(address: u64, index: u64) -> u64 {
    guest::read64(address + nt::Mdl::SIZE + index * 8) << 12
}

/// A vista de dados de `section` com a base `base`.
fn view_at(section: u64, base: u64) -> Option<alloc::sync::Arc<sections::View>> {
    sections::views().into_iter().find(|view| view.base == base && view.section.pointer() == section)
}

/// MmMapViewOfSection(Section, Process, &Base(0), 0, CommitSize, &Offset(0),
/// &ViewSize, ViewUnmap, AllocationType, Protect): o status e a base.
fn map_user_view(block: u64, section: u64, target: u64, commit: u64, size: u64, allocation: u64, protect: u64) -> (u32, u64) {
    let (base, offset, view_size) = (block, block + 8, block + 0x10);
    guest::write64(base, 0);
    guest::write64(offset, 0);
    guest::write64(view_size, size);
    let mapped = status(call_export("MmMapViewOfSection", &[section, target, base, 0, commit, offset, view_size, 2, allocation, protect]));
    (mapped, guest::read64(base))
}

/// Backing store de uma alocação, as vistas e os MDLs.
fn backing_store(assert: Assert) {
    let block = guest::alloc_bytes(0x200);
    let (output, size, handle, kernel_view) = (block, block + 8, block + 0x10, block + 0x18);
    let current = process::get_current_process();
    guest::write64(size, 0x3000);
    let created = status(call_export("MmCreateSection", &[output, 0, 0, size, 4, SEC_COMMIT | SEC_PARTITION_OWNER_HANDLE, u64::MAX, 0]));
    let body = guest::read64(output);
    let section = sections::by_pointer(body);
    assert(created == 0 && section.as_ref().is_some_and(|section| section.frames().len() == 3) && section_objects::reference_count(body) == Some(1), "sharedview: MmCreateSection com SEC_PARTITION_OWNER_HANDLE e -1 (CommitGlobalBackingStore)");
    let Some(section) = section else {
        guest::free_bytes(block);
        return;
    };
    // ObfReferenceObject + ObInsertObject sem nome + ObCloseHandle.
    let _ = call_export("ObfReferenceObject", &[body]);
    let inserted = status(call_export("ObInsertObject", &[body, 0, 0, 0, 0, handle]));
    let creation_handle = guest::read64(handle);
    let counted = section_objects::state(body).is_some_and(|state| state.handles == 1 && state.creation_attributes.is_none());
    assert(inserted == 0 && creation_handle != 0 && counted && section_objects::reference_count(body) == Some(1), "sharedview: ObInsertObject da secao do MmCreateSection abre o handle e solta a referencia de criacao");
    let again = status(call_export("ObInsertObject", &[body, 0, 0, 0, 0, handle]));
    assert(again == 0xC000_000D && section_objects::reference_count(body) == Some(1), "sharedview: secao ja inserida recusa o segundo ObInsertObject");
    let mode = if creation_handle & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000 { 0 } else { 1 };
    let closed = status(call_export("ObCloseHandle", &[creation_handle, mode]));
    assert(closed == 0 && section_objects::state(body).is_some_and(|state| state.handles == 0) && sections::by_pointer(body).is_some(), "sharedview: ObCloseHandle do handle de criacao conserva a secao referenciada");
    // MmMapViewInSystemSpace com ViewSize zero.
    guest::write64(size, 0);
    let system_mapped = status(call_export("MmMapViewInSystemSpace", &[body, kernel_view, size]));
    let kva = guest::read64(kernel_view);
    assert(system_mapped == 0 && paging::translate(kva) == section.frame(0).unwrap_or(1), "sharedview: vista de sistema do backing store");
    // ObOpenObjectByPointer(Section, 0, NULL, 0, tipo, UserMode): sem
    // descritor, o handle de acesso 0 abre sem SeAccessCheck.
    let section_type = object_types::section_type().pointer;
    let opened = status(call_export("ObOpenObjectByPointer", &[body, 0, 0, 0, section_type, 1, handle]));
    let user_handle = guest::read64(handle);
    let granted = open_pointer::resolve(user_handle, true).and_then(|resolved| resolved.ok()).map(|resolved| (resolved.item.pointer, resolved.access));
    assert(opened == 0 && granted == Some((body, 0)), "sharedview: ObOpenObjectByPointer em UserMode com acesso 0 de secao sem descritor (CommitLocalBackingStore)");
    // MmMapViewOfSection no processo: o mesmo PFN da vista de sistema.
    let (mapped, uva) = map_user_view(block + 0x40, body, current, 0x3000, 0x3000, 0, 4);
    guest::write32(kva + 0x1004, 0x5A5A_1234);
    let aliased = (0..3).all(|page| paging::translate(uva + page * 0x1000) == section.frame(page).unwrap_or(1) && paging::translate(kva + page * 0x1000) == section.frame(page).unwrap_or(2));
    assert(mapped == 0 && uva != 0 && aliased && guest::read32(uva + 0x1004) == 0x5A5A_1234, "sharedview: vista de usuario e vista de sistema sao alias das mesmas paginas");
    // MDL da vista de usuário (VidMmiProbeAndLockAllocation): Process e PFNs.
    let user_mdl = call_export("IoAllocateMdl", &[uva, 0x3000, 0, 0, 0]).unwrap_or(0);
    if user_mdl != 0 {
        let _ = call_export("MmProbeAndLockPages", &[user_mdl, 0, 2]);
        let header = mdl(user_mdl);
        let locked = header.process.get() == current && header.mdl_flags.get() & (MDL_PAGES_LOCKED | MDL_WRITE_OPERATION) == MDL_PAGES_LOCKED | MDL_WRITE_OPERATION && (0..3).all(|page| mdl_frame(user_mdl, page) == section.frame(page).unwrap_or(1));
        assert(locked, "sharedview: MmProbeAndLockPages da vista de usuario grava o processo e os PFNs da secao");
        let sva = call_export("MmMapLockedPagesSpecifyCache", &[user_mdl, 0, 1, 0, 0, 0x4000_0020]).unwrap_or(0);
        assert(sva != 0 && paging::translate(sva) == section.frame(0).unwrap_or(1) && guest::read32(sva + 0x1004) == 0x5A5A_1234, "sharedview: o MDL travado mapeia no sistema as paginas da vista de usuario");
        if sva != 0 {
            let _ = call_export("MmUnmapLockedPages", &[sva, user_mdl]);
        }
        let _ = call_export("MmUnlockPages", &[user_mdl]);
        let _ = call_export("IoFreeMdl", &[user_mdl]);
    }
    // MDL da vista de sistema em leitura: Process nulo, sem MDL_WRITE_OPERATION.
    let system_mdl = call_export("IoAllocateMdl", &[kva, 0x1000, 0, 0, 0]).unwrap_or(0);
    if system_mdl != 0 {
        mdl(system_mdl).process.set(0x1234);
        let _ = call_export("MmProbeAndLockPages", &[system_mdl, 0, 0]);
        let header = mdl(system_mdl);
        assert(header.process.get() == 0 && header.mdl_flags.get() & MDL_WRITE_OPERATION == 0 && mdl_frame(system_mdl, 0) == section.frame(0).unwrap_or(1), "sharedview: MDL de vista de sistema sem processo e com IoReadAccess");
        let _ = call_export("MmUnlockPages", &[system_mdl]);
        let _ = call_export("IoFreeMdl", &[system_mdl]);
    }
    let unmapped = status(call_export("MmUnmapViewOfSection", &[current, uva])) == 0 && status(call_export("MmUnmapViewInSystemSpace", &[kva])) == 0;
    let released = open_pointer::close(user_handle) == Some(0) && section_objects::dereference(body).is_ok();
    drop(section);
    assert(unmapped && released && sections::by_pointer(body).is_none(), "sharedview: vistas, handle e referencia soltos destroem a secao");
    // Uma seção nomeada tem descritor: acesso 0 em UserMode é negado.
    let named_attributes = block + 0x100;
    let unicode = block + 0x140;
    let text = block + 0x160;
    let units: alloc::vec::Vec<u8> = "\\OpenNtSecaoComDescritor".encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
    guest::write_bytes(text, &units);
    // SAFETY: blocos do teste do tamanho das estruturas.
    let (oa, name) = unsafe { (nt::ObjectAttributes::at(named_attributes), nt::UnicodeString::at(unicode)) };
    name.length.set(units.len() as u16);
    name.maximum_length.set(units.len() as u16);
    name.buffer.set(text);
    oa.length.set(nt::ObjectAttributes::SIZE as u32);
    oa.root_directory.set(0);
    oa.object_name.set(unicode);
    oa.attributes.set(0x40);
    oa.security_descriptor.set(0);
    oa.security_quality_of_service.set(0);
    guest::write64(size, 0x1000);
    let named = status(call_export("ZwCreateSection", &[handle, 0xF_001F, named_attributes, size, 4, SEC_COMMIT, 0]));
    let named_handle = guest::read64(handle);
    let named_body = open_pointer::resolve(named_handle, false).and_then(|resolved| resolved.ok()).map_or(0, |resolved| resolved.item.pointer);
    let denied = status(call_export("ObOpenObjectByPointer", &[named_body, 0, 0, 0, section_type, 1, output]));
    assert(named == 0 && named_body != 0 && denied == 0xC000_0022, "sharedview: secao nomeada tem descritor e o acesso 0 em UserMode e negado");
    let _ = open_pointer::close(named_handle);
    guest::free_bytes(block);
}

/// A página de cerca monitorada: RW no sistema travada por MDL, RO no processo.
fn fence_page(assert: Assert) {
    let block = guest::alloc_bytes(0x100);
    let (output, size, kernel_view, offset) = (block, block + 8, block + 0x10, block + 0x18);
    let current = process::get_current_process();
    guest::write64(size, 0x1000);
    let created = status(call_export("MmCreateSection", &[output, 0, 0, size, 4, SEC_COMMIT | SEC_PARTITION_OWNER_HANDLE, u64::MAX, 0]));
    let body = guest::read64(output);
    guest::write64(offset, 0);
    let mapped = status(call_export("MmMapViewInSystemSpaceEx", &[body, kernel_view, size, offset, 0]));
    let kva = guest::read64(kernel_view);
    let Some(section) = sections::by_pointer(body).filter(|_| created == 0 && mapped == 0) else {
        assert(false, "fencepage: MmCreateSection e MmMapViewInSystemSpaceEx da pagina de cerca");
        guest::free_bytes(block);
        return;
    };
    let frame = section.frame(0).unwrap_or(1);
    let fence_mdl = call_export("IoAllocateMdl", &[kva, 0x1000, 0, 0, 0]).unwrap_or(0);
    if fence_mdl != 0 {
        let _ = call_export("MmProbeAndLockPages", &[fence_mdl, 0, 2]);
    }
    assert(fence_mdl != 0 && mdl(fence_mdl).process.get() == 0 && mdl_frame(fence_mdl, 0) == frame && paging::access_flags(kva) & paging::PAGE_RW != 0, "fencepage: vista de sistema RW travada pelo MDL");
    // MapCpuVA: PAGE_READONLY no processo, o mesmo PFN.
    let (user_mapped, uva) = map_user_view(block + 0x40, body, current, 0x1000, 0x1000, 0, 2);
    guest::write64(kva + 0x18, 0x0123_4567_89AB_CDEF);
    let flags = paging::access_flags(uva);
    assert(user_mapped == 0 && paging::translate(uva) == frame && flags & paging::PAGE_USER != 0 && flags & paging::PAGE_RW == 0 && guest::read64(uva + 0x18) == 0x0123_4567_89AB_CDEF, "fencepage: vista de usuario PAGE_READONLY ve o valor escrito pela vista de sistema");
    let _ = call_export("MmUnmapViewOfSection", &[current, uva]);
    if fence_mdl != 0 {
        let _ = call_export("MmUnlockPages", &[fence_mdl]);
        let _ = call_export("IoFreeMdl", &[fence_mdl]);
    }
    let _ = call_export("MmUnmapViewInSystemSpace", &[kva]);
    drop(section);
    assert(section_objects::dereference(body).is_ok() && sections::by_pointer(body).is_none(), "fencepage: pagina de cerca liberada");
    guest::free_bytes(block);
}

/// As seções do DirectComposition e do gerenciador de tokens.
fn composition_sections(assert: Assert) {
    let block = guest::alloc_bytes(0x200);
    let (output, size, kernel_view, handle) = (block, block + 8, block + 0x10, block + 0x18);
    let current = process::get_current_process();
    let section_type = object_types::section_type().pointer;
    // CApplicationChannel::Initialize: SECTION_MAP_READ|WRITE, SEC_COMMIT | SEC_NO_CHANGE.
    guest::write64(size, 0x2000);
    let created = status(call_export("MmCreateSection", &[output, 6, 0, size, 4, SEC_COMMIT | SEC_NO_CHANGE, 0, 0]));
    let body = guest::read64(output);
    guest::write64(size, 0);
    let system_mapped = status(call_export("MmMapViewInSystemSpace", &[body, kernel_view, size]));
    let kva = guest::read64(kernel_view);
    let Some(section) = sections::by_pointer(body).filter(|_| created == 0 && system_mapped == 0) else {
        assert(false, "dcomp: MmCreateSection com SEC_COMMIT | SEC_NO_CHANGE");
        guest::free_bytes(block);
        return;
    };
    // MmMapViewOfSection com SEC_NO_CHANGE e o tamanho da vista de sistema.
    let (mapped, uva) = map_user_view(block + 0x40, body, current, 0x2000, guest::read64(size), SEC_NO_CHANGE, 4);
    let channel = view_at(body, uva);
    guest::write32(uva + 0x1010, 0xD0C0_0001);
    assert(mapped == 0 && channel.as_ref().is_some_and(|view| view.no_change) && paging::translate(uva + 0x1000) == paging::translate(kva + 0x1000) && guest::read32(kva + 0x1010) == 0xD0C0_0001, "dcomp: vista do canal com SEC_NO_CHANGE e alias da vista de sessao");
    assert(channel.as_ref().is_some_and(|view| sections::protection_status(view, 2) == 0xC000_0045), "dcomp: vista SEC_NO_CHANGE recusa trocar a protecao");
    // Sem SEC_NO_CHANGE no AllocationType a seção NoChange protege a vista
    // (MiMapViewOfDataSection 0x639F9D).
    let (readonly_mapped, readonly) = map_user_view(block + 0x60, body, current, 0x1000, 0, 0, 2);
    assert(readonly_mapped == 0 && view_at(body, readonly).is_some_and(|view| view.no_change) && paging::translate(readonly) == section.frame(0).unwrap_or(1), "dcomp: secao SEC_NO_CHANGE protege toda vista");
    drop(channel);
    // MiUnmapViewOfSection (rva 0x61e510): num VAD NoChange o
    // MiCheckSecuredVad da remoção (0x55) recusa a vista com uma faixa do
    // MmSecureVirtualMemory, em modo usuário e em modo kernel; sem a faixa,
    // a vista SEC_NO_CHANGE desmapeia pelo NtUnmapViewOfSection de modo
    // usuário.
    let user_unmap = |base: u64| state::handler("NtUnmapViewOfSection").map_or(1, |handler| handler(u64::MAX, base, 0, 0, 0).unwrap_or(1));
    let secured = call_export("MmSecureVirtualMemory", &[uva + 0x1008, 0x10, 4]).unwrap_or(0);
    let refused = secured != 0 && user_unmap(uva) == 0xC000_0045 && status(call_export("ZwUnmapViewOfSection", &[u64::MAX, uva])) == 0xC000_0045 && view_at(body, uva).is_some();
    let _ = call_export("MmUnsecureVirtualMemory", &[secured]);
    assert(refused, "dcomp: faixa do MmSecureVirtualMemory na vista SEC_NO_CHANGE recusa o desmapeamento com STATUS_INVALID_PAGE_PROTECTION");
    let _ = call_export("MmUnmapViewOfSection", &[current, readonly]);
    assert(user_unmap(uva) == 0 && view_at(body, uva).is_none(), "dcomp: solta a faixa, a vista SEC_NO_CHANGE desmapeia pelo NtUnmapViewOfSection de modo usuario");
    let _ = call_export("MmUnmapViewInSystemSpace", &[kva]);
    drop(section);
    assert(section_objects::dereference(body).is_ok() && sections::by_pointer(body).is_none(), "dcomp: secao do canal liberada");
    // CSharedSectionMarshaler::CreateSection / CTokenManager::Initialize:
    // ZwCreateSection com OBJ_KERNEL_HANDLE; depois o
    // ObReferenceObjectByHandle(GENERIC_READ|GENERIC_WRITE, KernelMode) e o
    // ObOpenObjectByPointer(0xC0000000, SECTION_MAP_READ|WRITE, UserMode).
    let attributes = block + 0x100;
    // SAFETY: bloco do teste do tamanho de um OBJECT_ATTRIBUTES.
    let oa = unsafe { nt::ObjectAttributes::at(attributes) };
    oa.length.set(nt::ObjectAttributes::SIZE as u32);
    oa.root_directory.set(0);
    oa.object_name.set(0);
    oa.attributes.set(0x200);
    oa.security_descriptor.set(0);
    oa.security_quality_of_service.set(0);
    guest::write64(size, 0x1000);
    let shared = status(call_export("ZwCreateSection", &[handle, 6, attributes, size, 4, SEC_COMMIT | SEC_NO_CHANGE, 0]));
    let kernel_handle = guest::read64(handle);
    let referenced = status(call_export("ObReferenceObjectByHandle", &[kernel_handle, 0xC000_0000, section_type, 0, output, 0]));
    let object = guest::read64(output);
    assert(shared == 0 && kernel_handle & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000 && referenced == 0 && sections::by_pointer(object).is_some_and(|section| section.attributes & 0x0040_0000 != 0), "dcomp: ZwCreateSection SEC_NO_CHANGE de modo kernel e a referencia pelo handle");
    let opened = status(call_export("ObOpenObjectByPointer", &[object, 0xC000_0000, 0, 6, section_type, 1, handle]));
    let user_handle = guest::read64(handle);
    let resolved = open_pointer::resolve(user_handle, true).and_then(|resolved| resolved.ok()).map(|resolved| (resolved.item.pointer, resolved.access, resolved.attributes));
    assert(opened == 0 && user_handle & 0xFFFF_FFFF_8000_0000 == 0 && resolved == Some((object, 6, 0)), "dcomp: ObOpenObjectByPointer aceita HandleAttributes 0xC0000000 e abre o handle de usuario");
    let _ = call_export("ObCloseHandle", &[kernel_handle, 0]);
    let _ = open_pointer::close(user_handle);
    let _ = call_export("ObfDereferenceObject", &[object]);
    assert(sections::by_pointer(object).is_none(), "dcomp: secao compartilhada liberada");
    guest::free_bytes(block);
}

/// Um objeto de tipo de driver duplicado para outro processo e resolvido
/// pelo tipo lá; e a vista de usuário travada por um terceiro anexado.
fn cross_process_objects(assert: Assert) {
    let shared_type = object_types::ensure(&object_types::TypeTemplate { name: "OpenNTTesteCompartilhado", mapping: [0x2_0001, 0x2_0002, 0x2_0000, 0x1F_0003], valid_access: 0x1F_0003, flags: 0, object_type_code: 0, invalid_attributes: 0x100, pool_type: 0x200, paged_charge: 0, non_paged_charge: 0 }).pointer;
    let event_type = object_types::event_type().pointer;
    let block = guest::alloc_bytes(0x200);
    let (output, handle, size) = (block, block + 8, block + 0x10);
    // A seção do DWM/LogonUI.
    guest::write64(size, 0x2000);
    let created = status(call_export("MmCreateSection", &[output, 0, 0, size, 4, SEC_COMMIT, 0, 0]));
    let body = guest::read64(output);
    let section = sections::by_pointer(body).filter(|_| created == 0);
    let outcome = with_test_process("composicao-a.exe", None, |first| {
        // SAFETY: a KTHREAD do processo de teste, viva durante o corpo.
        let mode = unsafe { nt::Kthread::at(first.thread) }.previous_mode.get() as u8;
        let created = status(call_export("ObCreateObject", &[0, shared_type, 0, mode as u64, 0, 0x40, 0, 0, output])) == 0;
        let object = guest::read64(output);
        let inserted = created && status(call_export("ObInsertObject", &[object, 0, 0x1F_0003, 0, 0, handle])) == 0;
        let source_handle = guest::read64(handle);
        let rejected = status(call_export("ObOpenObjectByPointer", &[object, 0x100, 0, 1, shared_type, 0, output])) == 0xC000_000D;
        // A vista de usuário do processo A.
        let (view_status, uva) = map_user_view(block + 0x40, body, first.process, 0x2000, 0x2000, 0, 4);
        let inner = with_test_process("composicao-b.exe", None, |second| {
            let target = block + 0x80;
            let duplicated = status(call_export("ObDuplicateObject", &[first.process, source_handle, second.process, target, 0, 0, 2, 0])) == 0;
            let target_handle = guest::read64(target);
            let by_type = status(call_export("ObReferenceObjectByHandle", &[target_handle, 1, shared_type, 1, output, 0])) == 0 && guest::read64(output) == object;
            if by_type {
                let _ = call_export("ObfDereferenceObject", &[object]);
            }
            let mismatch = status(call_export("ObReferenceObjectByHandle", &[target_handle, 1, event_type, 1, output, 0])) == 0xC000_0024;
            let other_table = open_pointer::resolve(source_handle, true).is_none_or(|resolved| resolved.is_err());
            let closed = status(call_export("ObCloseHandle", &[target_handle, 1])) == 0;
            // WARPKMALLOCATION::Map: anexa ao processo do MDL, trava a vista
            // de usuário em UserMode/IoModifyAccess e a mapeia no sistema.
            let apc_state = block + 0x100;
            let mut locked = false;
            let attached = view_status == 0 && {
                let _ = call_export("KeStackAttachProcess", &[first.process, apc_state]);
                // SAFETY: a KTHREAD corrente (a do processo B).
                unsafe { nt::Kthread::at(process::get_current_thread()) }.apc_state.process.get() == first.process
            };
            if attached {
                let warp_mdl = call_export("IoAllocateMdl", &[uva, 0x2000, 0, 0, 0]).unwrap_or(0);
                let mut sva = 0;
                if warp_mdl != 0 {
                    let _ = call_export("MmProbeAndLockPages", &[warp_mdl, 1, 2]);
                    sva = call_export("MmMapLockedPagesSpecifyCache", &[warp_mdl, 0, 1, 0, 0, 0x4000_0020]).unwrap_or(0);
                    locked = mdl(warp_mdl).process.get() == first.process && section.as_ref().is_some_and(|section| mdl_frame(warp_mdl, 1) == section.frame(1).unwrap_or(1));
                }
                let _ = call_export("KeUnstackDetachProcess", &[apc_state]);
                if sva != 0 {
                    guest::write32(sva + 0x1008, 0x0BA5_1C00);
                    locked = locked && section.as_ref().is_some_and(|section| paging::translate(sva + 0x1000) == section.frame(1).unwrap_or(1) && crate::hal::physical::read32(section.frame(1).unwrap_or(0) + 8) == 0x0BA5_1C00);
                    let _ = call_export("MmUnmapLockedPages", &[sva, warp_mdl]);
                }
                if warp_mdl != 0 {
                    let _ = call_export("MmUnlockPages", &[warp_mdl]);
                    let _ = call_export("IoFreeMdl", &[warp_mdl]);
                }
            }
            (duplicated && by_type && mismatch && other_table && closed, locked)
        });
        let unmapped = view_status == 0 && status(call_export("MmUnmapViewOfSection", &[first.process, uva])) == 0;
        let closed = status(call_export("ObCloseHandle", &[source_handle, mode as u64])) == 0 && !object_header::is_object(object);
        (inserted && rejected, inner, unmapped && closed)
    });
    let (created_ok, inner, released) = outcome.map_or((false, None, false), |(created, inner, released)| (created, inner, released));
    assert(created_ok, "crossprocess: objeto de tipo de driver inserido no processo A e InvalidAttributes do tipo no ObOpenObjectByPointer");
    assert(inner.is_some_and(|(duplicated, _)| duplicated), "crossprocess: ObDuplicateObject leva o handle ao processo B e ele resolve pelo tipo so la");
    assert(inner.is_some_and(|(_, locked)| locked), "crossprocess: vista de usuario de A travada por B anexado (WARPKMALLOCATION::Map) e mapeada no sistema");
    assert(released, "crossprocess: vista e handles soltos destroem o objeto");
    drop(section);
    let _ = section_objects::dereference(body);
    guest::free_bytes(block);
}

/// MmMapViewOfSection(Section, Process, &Base(0), 0, CommitSize, &Offset(0),
/// &ViewSize, ViewShare, 0, PAGE_READWRITE): o mapeamento do
/// MapKernelSectionForUserMapping (win32kbase 0x7ae1c) e do
/// CddBitmapSw::GetSysMemBits (cdd 0x2803c).
fn map_view_share(block: u64, section: u64, target: u64, size: u64) -> (u32, u64) {
    let (base, offset, view_size) = (block, block + 8, block + 0x10);
    guest::write64(base, 0);
    guest::write64(offset, 0);
    guest::write64(view_size, size);
    let mapped = status(call_export("MmMapViewOfSection", &[section, target, base, 0, size, offset, view_size, 1, 0, 4]));
    (mapped, guest::read64(base))
}

/// Superfície de redirecionamento GDI (a seção SEC_COMMIT|SEC_NO_CHANGE do
/// Win32CreateSection, win32kbase 0x6c854 + ObDeleteCapturedInsertInfo
/// 0x6c869): o processo que desenha a mapeia e o kernel escreve na vista de
/// usuário (EngBitBlt); outro processo desmapeia a vista do primeiro sem
/// anexar e mapeia a sua (CddBitmapSw::GetSysMemBits 0x27f94, SURFACE::Map
/// 0x7ab20); o DWM recebe um handle de usuário pelo ObOpenObjectByPointer(
/// seção, 0, NULL, 6, NULL, KernelMode) (GetSoSurfaceData 0x173a8) e mapeia
/// por ele (CSectionBitmapRealization::MapSection 0x4510e).
fn gdi_redirection_views(assert: Assert) {
    const PIXEL: u32 = 0x00FF_8000;
    let block = guest::alloc_bytes(0x200);
    let (output, size) = (block, block + 8);
    guest::write64(size, 0x3000);
    let created = status(call_export("MmCreateSection", &[output, 6, 0, size, 4, SEC_COMMIT | SEC_NO_CHANGE, 0, 0]));
    let body = guest::read64(output);
    if created == 0 {
        let _ = call_export("ObDeleteCapturedInsertInfo", &[body]);
    }
    let section = sections::by_pointer(body).filter(|_| created == 0);
    let outcome = with_test_process("redir-desenha.exe", None, |drawer| {
        let (first, uva_a) = map_view_share(block + 0x40, body, drawer.process, 0x3000);
        if first == 0 {
            guest::write32(uva_a + 0x2010, PIXEL);
        }
        with_test_process("redir-dwm.exe", None, |dwm| {
            let unmapped = first == 0 && status(call_export("MmUnmapViewOfSection", &[drawer.process, uva_a])) == 0 && view_at(body, uva_a).is_none();
            let (second, uva_b) = map_view_share(block + 0x60, body, dwm.process, 0x3000);
            let pixel = second == 0 && guest::read32(uva_b + 0x2010) == PIXEL;
            let opened = status(call_export("ObOpenObjectByPointer", &[body, 0, 0, 6, 0, 0, block + 0x80])) == 0;
            let handle = guest::read64(block + 0x80);
            let user_handle = opened && handle & 0xFFFF_FFFF_8000_0000 != 0xFFFF_FFFF_8000_0000;
            guest::write64(block + 0x90, 0);
            guest::write64(block + 0x98, 0);
            let mapped = user_handle && status(call_export("ZwMapViewOfSection", &[handle, u64::MAX, block + 0x90, 0, 0, 0, block + 0x98, 2, 0, 4])) == 0;
            let uva_c = guest::read64(block + 0x90);
            let aliased = mapped && guest::read32(uva_c + 0x2010) == PIXEL && section.as_ref().is_some_and(|section| paging::translate(uva_c + 0x2000) == section.frame(2).unwrap_or(1) && paging::translate(uva_b + 0x2000) == section.frame(2).unwrap_or(2));
            if mapped {
                let _ = call_export("MmUnmapViewOfSection", &[dwm.process, uva_c]);
            }
            if second == 0 {
                let _ = call_export("MmUnmapViewOfSection", &[dwm.process, uva_b]);
            }
            if opened {
                let _ = open_pointer::close(handle);
            }
            (unmapped, pixel, user_handle, aliased)
        })
    })
    .flatten();
    assert(created == 0 && section.is_some(), "gdiredir: MmCreateSection SEC_COMMIT|SEC_NO_CHANGE + ObDeleteCapturedInsertInfo (Win32CreateSection)");
    assert(outcome.is_some_and(|(unmapped, ..)| unmapped), "gdiredir: MmUnmapViewOfSection da vista de outro processo sem anexar (GetSysMemBits)");
    assert(outcome.is_some_and(|(_, pixel, ..)| pixel), "gdiredir: a vista nova do processo corrente ve o que o kernel escreveu na vista do anterior");
    assert(outcome.is_some_and(|(_, _, user_handle, _)| user_handle), "gdiredir: ObOpenObjectByPointer(secao, 0, NULL, 6, NULL, KernelMode) da handle de usuario (GetSoSurfaceData)");
    assert(outcome.is_some_and(|(.., aliased)| aliased), "gdiredir: o mapeamento do DWM pelo handle e alias dos mesmos PFNs (MapSection)");
    drop(section);
    let _ = section_objects::dereference(body);
    guest::free_bytes(block);
}

static EXIT_TARGET: AtomicU64 = AtomicU64::new(0);
static EXIT_VIEW: AtomicU64 = AtomicU64::new(0);
static EXIT_UNMAP: AtomicU32 = AtomicU32::new(u32::MAX);

/// Rotina de saída de processo (depois do callout de saída do win32k, antes
/// do VmDeleted): desmapeia a vista do processo que sai, como o
/// CddBitmapSw::OnCloseProcess (cdd 0x23f0c) e o Release (0x289e9).
fn unmap_on_exit(process: u64) {
    if process == 0 || EXIT_TARGET.compare_exchange(process, 0, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return;
    }
    let base = EXIT_VIEW.swap(0, Ordering::SeqCst);
    EXIT_UNMAP.store(status(call_export("MmUnmapViewOfSection", &[process, base])), Ordering::SeqCst);
}

/// MiObtainReferencedVadEx (0x21b31d) e MiMapViewOfDataSection (0x639ce8):
/// só o VmDeleted recusa; um processo saindo ainda desmapeia. O
/// `with_test_process` termina o processo pelo `process::terminate_process`,
/// que roda as rotinas de saída no contexto do teste, depois do
/// `process_exit_callout` e antes do VmDeleted.
fn exit_callout_views(assert: Assert) {
    let block = guest::alloc_bytes(0x100);
    guest::write64(block + 8, 0x2000);
    let created = status(call_export("MmCreateSection", &[block, 0, 0, block + 8, 4, SEC_COMMIT, 0, 0]));
    let body = guest::read64(block);
    EXIT_UNMAP.store(u32::MAX, Ordering::SeqCst);
    process::register_process_exit_routine(unmap_on_exit);
    let refused = with_test_process("redir-saida.exe", None, |exiting| {
        let (mapped, uva) = map_view_share(block + 0x40, body, exiting.process, 0x2000);
        if mapped == 0 {
            EXIT_VIEW.store(uva, Ordering::SeqCst);
            EXIT_TARGET.store(exiting.process, Ordering::SeqCst);
        }
        // SAFETY: o EPROCESS do processo de teste, vivo durante o corpo.
        let eprocess = unsafe { nt::Eprocess::at(exiting.process) };
        eprocess.set_vm_deleted(1);
        let refused = map_view_share(block + 0x60, body, exiting.process, 0x1000).0 == 0xC000_010A;
        eprocess.set_vm_deleted(0);
        mapped == 0 && refused
    });
    process::unregister_process_exit_routine(unmap_on_exit);
    EXIT_TARGET.store(0, Ordering::SeqCst);
    assert(created == 0 && refused == Some(true), "gdiredir: VmDeleted recusa o MmMapViewOfSection com STATUS_PROCESS_IS_TERMINATING");
    assert(EXIT_UNMAP.load(Ordering::SeqCst) == 0, "gdiredir: MmUnmapViewOfSection num processo saindo, antes do VmDeleted, desmapeia (callout de saida do win32k)");
    let _ = section_objects::dereference(body);
    guest::free_bytes(block);
}

/// A leitura da tela composta pelo DWM: o bSpDwmUpdateSurface do win32kfull
/// (chamado pelo bSpDwmValidateSurface do BitBlt/StretchBlt/AlphaBlend/
/// GetPixel num DC de tela e pelo GreSpDwmSyncCaptureSurfaceBits do
/// PrintWindow) recebe do DwmSyncCaptureSurfaceBits um handle de seção da
/// tabela do dwm.exe e faz ObDuplicateObject(dwm, h, NULL, &k,
/// SECTION_MAP_READ, OBJ_KERNEL_HANDLE, DUPLICATE_CLOSE_SOURCE, KernelMode)
/// (0x2ded8), ObReferenceObjectByHandle(k, SECTION_MAP_READ,
/// MmSectionObjectType, KernelMode) (0x2df11) e ZwClose(k). No
/// ObDuplicateObject 19041 o OBJ_KERNEL_HANDLE em KernelMode troca o
/// TargetProcess pelo PsInitialSystemProcess antes de olhar o destino nulo
/// (0x5f5237 -> 0x5f55cf).
fn dwm_capture_kernel_handle(assert: Assert) {
    let section_type = object_types::section_type().pointer;
    let block = guest::alloc_bytes(0x100);
    guest::write64(block + 8, 0x2000);
    let created = status(call_export("MmCreateSection", &[block, 6, 0, block + 8, 4, SEC_COMMIT, 0, 0]));
    let body = guest::read64(block);
    if created == 0 {
        let _ = call_export("ObDeleteCapturedInsertInfo", &[body]);
    }
    let outcome = with_test_process("redir-captura.exe", None, |dwm| {
        let opened = created == 0 && status(call_export("ObOpenObjectByPointer", &[body, 0, 0, 6, 0, 0, block + 0x10])) == 0;
        let dwm_handle = guest::read64(block + 0x10);
        guest::write64(block + 0x18, 0);
        let duplicated = opened && status(call_export("ObDuplicateObject", &[dwm.process, dwm_handle, 0, block + 0x18, 4, 0x200, 1, 0])) == 0;
        let kernel_handle = guest::read64(block + 0x18);
        let kernel = duplicated && kernel_handle & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000;
        let referenced = kernel && status(call_export("ObReferenceObjectByHandle", &[kernel_handle, 4, section_type, 0, block + 0x20, 0])) == 0 && guest::read64(block + 0x20) == body;
        if referenced {
            let _ = call_export("ObfDereferenceObject", &[body]);
        }
        let source_closed = opened && open_pointer::resolve(dwm_handle, true).is_none_or(|resolved| resolved.is_err());
        if kernel {
            let _ = call_export("ObCloseHandle", &[kernel_handle, 0]);
        } else if duplicated && kernel_handle != 0 {
            let _ = open_pointer::close(kernel_handle);
        }
        if opened && !source_closed {
            let _ = open_pointer::close(dwm_handle);
        }
        (referenced, source_closed)
    });
    assert(outcome.is_some_and(|(referenced, _)| referenced), "gdiredir: ObDuplicateObject(dwm, h, NULL, OBJ_KERNEL_HANDLE, KernelMode) poe a copia na tabela do System e ela resolve pelo tipo Section (bSpDwmUpdateSurface)");
    assert(outcome.is_some_and(|(_, closed)| closed), "gdiredir: DUPLICATE_CLOSE_SOURCE fecha o handle de secao do dwm");
    let _ = section_objects::dereference(body);
    guest::free_bytes(block);
}

pub fn run(assert: Assert) {
    backing_store(assert);
    fence_page(assert);
    composition_sections(assert);
    cross_process_objects(assert);
    gdi_redirection_views(assert);
    exit_callout_views(assert);
    dwm_capture_kernel_handle(assert);
}
