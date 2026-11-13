//! ZwQueryVirtualMemory (serviço de kernel).
//!
//! Resolve e retém o processo alvo antes de consultar os metadados reais
//! das regiões dele; a ordem de validação segue o contrato público de
//! MEMORY_BASIC_INFORMATION, e as demais classes têm seus layouts.

use alloc::vec::Vec;

use super::memory_map::USER_ADDRESS_LIMIT as LIMIT;
use super::paging;
use crate::ntos::mm::section::views as section_views;
use crate::ntos::ke::irql;
use crate::ntos::ob::{object_manager, open_pointer};
use crate::ntos::ps::process;
use crate::ntos::ps::user::memory_query::{self, Context, Info};
use crate::ntos::ps::user::state::{self, Region};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Eprocess, MemoryBasicInformation, MemoryImageInformation, MemoryRegionInformation, MemoryWorkingSetExInformation, UnicodeString};

fn eprocess(process: u64) -> &'static Eprocess {
    // SAFETY: processo corrente ou alvo referenciado pela consulta.
    unsafe { Eprocess::at(process) }
}

const BAD_HANDLE: u32 = 0xC000_0008;

/// Processo alvo: pseudo-handle, aberto por ponteiro, de usuário ou do
/// Object Manager. A tabela de usuário pertence ao processo dela.
pub(crate) fn target(handle: u64) -> Result<(u64, bool), u32> {
    if handle == u64::MAX {
        return Ok((process::get_current_process(), true));
    }
    if handle == u64::MAX - 1 {
        return Err(0xC000_0024);
    }
    if let Some(opened) = open_pointer::resolve(handle, false) {
        let opened = opened?;
        if opened.item.object_type.name != "Process" {
            return Err(0xC000_0024);
        }
        return Ok((opened.item.pointer, false));
    }
    if handle > 0x7FFF_FFFF {
        return Err(BAD_HANDLE);
    }
    let current = process::get_current_process();
    let pid = eprocess(current).unique_process_id.get();
    let user = if state::with(|state| state.current_process_id) == pid { state::get_user_handle(handle) } else { None };
    if let Some(user) = user {
        if user.kind() != "process" {
            return Err(0xC000_0024);
        }
        let data = user.object.callback_data();
        let pointer = if data.native_pointer != 0 { data.native_pointer } else { data.process_id.and_then(|pid| process::list_active_processes().into_iter().find(|entry| entry.pid == pid)).map_or(0, |entry| entry.address) };
        return Ok((pointer, false));
    }
    let Some(node) = object_manager::get_object(handle as u32).and_then(object_manager::node) else { return Err(BAD_HANDLE) };
    if node.type_name != "Process" {
        return Err(0xC000_0024);
    }
    Ok((node.data.map_or(0, |data| data.native_pointer), false))
}

fn push_unique(list: &mut Vec<Region>, region: Region) {
    if !list.iter().any(|existing| state::same_region(existing, &region)) {
        list.push(region);
    }
}

/// O runtime hospeda um processo de usuário nativo; outros processos não
/// têm VADs de usuário e nunca emprestam as regiões do processo ativo.
fn regions(process: u64) -> Context {
    let pid = eprocess(process).unique_process_id.get();
    let owned = section_views::regions(process);
    let owned_user: Vec<Region> = owned.user_regions.iter().map(|view| view.region()).collect();
    let owned_images: Vec<Region> = owned.process_images.iter().map(|view| view.region()).collect();
    if pid != state::with(|state| state.current_process_id) {
        let mut user_regions = owned_user;
        user_regions.extend(crate::ntos::ps::user::memory::foreign_regions(process));
        return Context { user_regions, process_images: owned_images };
    }
    let (user, shared, images) = state::with(|state| (state.user_regions.clone(), state.shared_user_regions.clone(), state.process_images.clone()));
    let mut user_regions = Vec::new();
    for region in user.into_iter().chain(shared).chain(owned_user) {
        push_unique(&mut user_regions, region);
    }
    let mut process_images = Vec::new();
    for region in images.into_iter().chain(owned_images) {
        push_unique(&mut process_images, region);
    }
    Context { user_regions, process_images }
}

/// Buffer de kernel ou de usuário presente e gravável (resolve antes um
/// dono paginado).
fn writable(pointer: u64, bytes: u64) -> bool {
    let end = pointer as u128 + bytes as u128;
    if pointer == 0 || end > 1u128 << 64 || (pointer < 0xFFFF_8000_0000_0000 && end > 0x8000_0000_0000) {
        return false;
    }
    let mut at = pointer as u128;
    while at < end {
        let address = at as u64;
        if guest::try_read8(address).is_err() || paging::access_flags(address) & 3 != 3 {
            return false;
        }
        at = (at & !4095) + 4096;
    }
    true
}

pub fn query(handle: u64, base: u64, class: u32, buffer: u64, length: u64, returned: u64) -> Result<u32, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("ZwQueryVirtualMemory requires PASSIVE_LEVEL"));
    }
    let minimum = match class {
        0 => 48,
        2 => 0,
        3 => 24,
        4 => 16,
        6 => 24,
        7 => 32,
        _ => return Ok(0xC000_0003),
    };
    if length < minimum {
        return Ok(0xC000_0004);
    }
    if base >= LIMIT {
        return Ok(0xC000_000D);
    }
    let (pointer, pseudo) = match target(handle) {
        Ok(selected) => selected,
        Err(status) => return Ok(status),
    };
    let Some(terminated) = process::with_record(pointer, |record| record.terminated) else { return Ok(BAD_HANDLE) };
    if process::reference(pointer).is_none() {
        return Ok(BAD_HANDLE);
    }
    let result = (|| -> Result<u32, KernelError> {
        if !pseudo && eprocess(pointer).system_process() != 0 {
            return Ok(0xC000_0022);
        }
        if terminated {
            return Ok(0xC000_010A);
        }
        let context = regions(pointer);
        let info = memory_query::describe(base, &context);
        Ok(format(class, &info, &context, buffer, length, returned))
    })();
    process::dereference(pointer)?;
    result
}

/// Grava um campo da estrutura de saída com sonda: o buffer pode ser de
/// modo usuário e a página pode sumir depois de `writable` (o `__try` do NT).
macro_rules! put {
    ($at:expr, $type:ty, $field:ident, $value:expr) => {
        guest::try_write($at + core::mem::offset_of!($type, $field) as u64, $value)
    };
}

fn format(class: u32, info: &Info, context: &Context, buffer: u64, length: u64, returned: u64) -> u32 {
    let written = (|| -> Result<u32, KernelError> { format_into(class, info, context, buffer, length, returned) })();
    written.unwrap_or(0xC000_0005)
}

fn format_into(class: u32, info: &Info, context: &Context, buffer: u64, length: u64, returned: u64) -> Result<u32, KernelError> {
    let prepare = |bytes: u64| writable(buffer, bytes) && (returned == 0 || writable(returned, 8));
    let done = |bytes: u64| -> Result<u32, KernelError> {
        if returned != 0 {
            guest::try_write::<u64>(returned, bytes)?;
        }
        Ok(0)
    };
    if class == 0 {
        if !prepare(MemoryBasicInformation::SIZE) {
            return Ok(0xC000_0005);
        }
        put!(buffer, MemoryBasicInformation, base_address, info.base)?;
        put!(buffer, MemoryBasicInformation, allocation_base, info.allocation_base)?;
        put!(buffer, MemoryBasicInformation, allocation_protect, info.allocation_protect)?;
        // PartitionId; o preenchimento nativo restante não é especificado.
        put!(buffer, MemoryBasicInformation, partition_id, 0u16)?;
        put!(buffer, MemoryBasicInformation, region_size, info.size)?;
        put!(buffer, MemoryBasicInformation, state, info.state)?;
        put!(buffer, MemoryBasicInformation, protect, if info.state == 0x10000 { 1 } else { info.protect })?;
        put!(buffer, MemoryBasicInformation, type_, info.kind)?;
        return done(MemoryBasicInformation::SIZE);
    }
    if class == 4 {
        // Endereços de entrada independentes de BaseAddress; cada resultado
        // reflete residência, proteção, compartilhamento e tamanho da página.
        if length % MemoryWorkingSetExInformation::SIZE != 0 {
            return Ok(0xC000_0004);
        }
        if !prepare(length) {
            return Ok(0xC000_0005);
        }
        let mut entry = buffer;
        while entry < buffer + length {
            let va: u64 = guest::try_read(entry + core::mem::offset_of!(MemoryWorkingSetExInformation, virtual_address) as u64)?;
            let page = (va < LIMIT).then(|| memory_query::describe(va, context));
            let pte = page.as_ref().filter(|page| page.region.is_some()).and_then(|_| paging::query_page(va, false));
            let mut flags = 0u64;
            if let (Some(pte), Some(page)) = (pte, &page) {
                if pte.access & 4 != 0 {
                    flags = 1 | ((page.protect & 0x7FF) as u64) << 4;
                    if page.image.is_some() || page.region.as_ref().is_some_and(|region| region.section().is_some()) {
                        flags |= 1 << 15;
                    }
                    if pte.page_size > 4096 {
                        flags |= 1 << 23;
                    }
                }
            }
            put!(entry, MemoryWorkingSetExInformation, virtual_attributes, flags)?;
            entry += MemoryWorkingSetExInformation::SIZE;
        }
        return done(length);
    }
    let Some(region) = &info.region else { return Ok(0xC000_0141) };
    if class == 2 {
        let name = memory_query::view_name(info.image.as_ref().unwrap_or(region));
        if info.image.is_none() && region.section().is_none() {
            return Ok(0xC000_0141);
        }
        let Some(name) = name else { return Ok(0xC000_0098) };
        if length > 0xFFFF_FFFF {
            return Ok(0xC000_00F3);
        }
        let units: Vec<u16> = name.encode_utf16().collect();
        let bytes = UnicodeString::SIZE + (units.len() as u64 + 1) * 2;
        if length < bytes {
            if returned != 0 {
                if !writable(returned, 8) {
                    return Ok(0xC000_0005);
                }
                guest::try_write::<u64>(returned, bytes)?;
            }
            return Ok(0xC000_0004);
        }
        if !prepare(bytes) {
            return Ok(0xC000_0005);
        }
        put!(buffer, UnicodeString, length, units.len() as u16 * 2)?;
        put!(buffer, UnicodeString, maximum_length, (units.len() as u16 + 1) * 2)?;
        put!(buffer, UnicodeString, buffer, buffer + UnicodeString::SIZE)?;
        // Os caracteres e o NUL final logo depois do UNICODE_STRING.
        let characters: Vec<u8> = units.iter().chain(core::iter::once(&0)).flat_map(|unit| unit.to_le_bytes()).collect();
        guest::try_write_bytes(buffer + UnicodeString::SIZE, &characters)?;
        return done(bytes);
    }
    if class == 6 {
        if !prepare(MemoryImageInformation::SIZE) {
            return Ok(0xC000_0005);
        }
        put!(buffer, MemoryImageInformation, image_base, info.image.as_ref().map_or(0, |image| image.base()))?;
        put!(buffer, MemoryImageInformation, size_of_image, info.image.as_ref().map_or(0, |image| image.size()))?;
        let no_execute = info.image.is_some() && region.section().is_some_and(|section| section.no_execute);
        // ImageFlags: ImageNotExecutable.
        put!(buffer, MemoryImageInformation, image_flags, if no_execute { 2u32 } else { 0 })?;
        guest::try_write::<u32>(buffer + core::mem::offset_of!(MemoryImageInformation, image_flags) as u64 + 4, 0)?;
        return done(MemoryImageInformation::SIZE);
    }
    // MemoryRegionInformation(Ex): versões de 24, 32, 40 ou 48 bytes.
    let size = if length >= 48 {
        48
    } else if length >= 40 {
        40
    } else if length >= 32 {
        32
    } else {
        24
    };
    if !prepare(size) {
        return Ok(0xC000_0005);
    }
    put!(buffer, MemoryRegionInformation, allocation_base, info.allocation_base)?;
    put!(buffer, MemoryRegionInformation, allocation_protect, info.allocation_protect)?;
    let kind = if info.image.is_some() {
        4
    } else {
        match region.section() {
            Some(section) if section.file.is_some() => 2,
            Some(_) => 8,
            None => 1,
        }
    };
    put!(buffer, MemoryRegionInformation, region_type, if class == 7 { kind } else { info.kind })?;
    put!(buffer, MemoryRegionInformation, region_size, region.size())?;
    if size > core::mem::offset_of!(MemoryRegionInformation, commit_size) as u64 {
        put!(buffer, MemoryRegionInformation, commit_size, memory_query::committed_bytes(info))?;
    }
    if size > core::mem::offset_of!(MemoryRegionInformation, partition_id) as u64 {
        // Partição do sistema real.
        put!(buffer, MemoryRegionInformation, partition_id, 0u64)?;
    }
    if size > core::mem::offset_of!(MemoryRegionInformation, node_preference) as u64 {
        // Nenhum nó NUMA preferido atribuído.
        put!(buffer, MemoryRegionInformation, node_preference, 0xFFFF_FFFFu64)?;
    }
    done(size)
}
