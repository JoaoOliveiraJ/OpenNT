//! NtQueryVirtualMemory de usuário.
//!
//! Layouts NT x64 distintos por classe (phnt/ntmmapi.h,
//! MEMORY_INFORMATION_CLASS). `describe` também serve ao serviço de kernel
//! (`mm/query_virtual`), com o contexto de regiões do processo alvo.

use alloc::string::String;
use alloc::vec::Vec;

use super::memory::Space;
use super::state::{self, Region};
use crate::ntos::mm::memory_map::USER_ADDRESS_LIMIT as MAX_USER;
use crate::ntos::mm::paging;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{MemoryBasicInformation, MemoryImageInformation, MemoryRegionInformation, MemoryWorkingSetExInformation, NtStruct, UnicodeString};

const PAGE: u64 = 0x1000;

/// Regiões consultadas: o VAD de um processo (o padrão é o corrente) e a
/// raiz das tabelas dele, onde as PTEs são lidas.
#[derive(Clone, Default)]
pub struct Context {
    pub user_regions: Vec<Region>,
    pub process_images: Vec<Region>,
    /// A raiz do processo consultado; 0 = a carregada.
    pub root: u64,
}

impl Context {
    pub fn current() -> Self {
        Self::of(Space::current())
    }

    pub fn of(space: Space) -> Self {
        Self { user_regions: space.regions(), process_images: space.images(), root: space.root() }
    }

    /// VA -> PA na raiz do processo consultado.
    pub fn translate(&self, va: u64) -> u64 {
        if self.root != 0 { paging::translate_in(self.root, va) } else { paging::translate(va) }
    }

    fn is_image(&self, region: &Region) -> bool {
        self.process_images.iter().any(|image| state::same_region(image, region))
    }
}

/// Uma faixa homogênea a partir do endereço.
#[derive(Clone)]
pub struct Info {
    pub base: u64,
    pub size: u64,
    pub allocation_base: u64,
    pub protect: u32,
    pub allocation_protect: u32,
    pub state: u32,
    pub kind: u32,
    pub region: Option<Region>,
    pub image: Option<Region>,
}

pub fn page_protection(region: &Region, index: u64, context: &Context) -> u32 {
    region.page_protect(index).filter(|&protect| protect != 0).unwrap_or_else(|| match region.protect() {
        0 => {
            if context.is_image(region) {
                0x40
            } else {
                4
            }
        }
        protect => protect,
    })
}

fn contains(region: &Region, va: u64) -> bool {
    va >= region.base() && va < region.base() + region.size()
}

/// Região livre até a próxima alocação, ou a faixa da região com o mesmo
/// estado de commit e a mesma proteção.
pub fn describe(va: u64, context: &Context) -> Info {
    let base = va & !(PAGE - 1);
    let image = context.process_images.iter().find(|region| contains(region, va)).cloned();
    let region = image.clone().or_else(|| context.user_regions.iter().find(|region| contains(region, va)).cloned());
    let Some(region) = region else {
        let mut end = MAX_USER;
        for candidate in context.user_regions.iter().chain(context.process_images.iter()) {
            if candidate.base() > base && candidate.base() < end {
                end = candidate.base();
            }
        }
        // MEM_FREE com Protect PAGE_NOACCESS, como o MmQueryVirtualMemory
        // descreve um endereço sem VAD.
        return Info { base, size: end - base, allocation_base: 0, protect: 1, allocation_protect: 0, state: 0x10000, kind: 0, region: None, image: None };
    };
    let index = (base - region.base()) / PAGE;
    let pages = region.committed_pages();
    let committed = match &pages {
        Some(pages) => pages.contains(&index),
        None => image.is_some() || region.committed() || context.translate(base) != 0,
    };
    let mut end = region.base() + region.size();
    let protection = page_protection(&region, index, context);
    for page in index + 1..region.size() / PAGE {
        let next_committed = pages.as_ref().map_or(committed, |pages| pages.contains(&page));
        if next_committed != committed || (committed && page_protection(&region, page, context) != protection) {
            end = region.base() + page * PAGE;
            break;
        }
    }
    let allocation_protect = match (region.allocation_protect(), region.protect()) {
        (0, 0) => {
            if image.is_some() {
                0x40
            } else {
                4
            }
        }
        (0, protect) => protect,
        (protect, _) => protect,
    };
    let kind = if image.is_some() {
        0x0100_0000
    } else if region.section().is_some() {
        0x4_0000
    } else {
        0x2_0000
    };
    Info { base, size: end - base, allocation_base: region.base(), allocation_protect, protect: if committed { protection } else { 0 }, state: if committed { 0x1000 } else { 0x2000 }, kind, region: Some(region), image }
}

/// Nome de uma vista: arquivo da seção, senão o nome nativo.
pub fn view_name(region: &Region) -> Option<String> {
    if let Some(file) = region.section().and_then(|section| section.file.clone()) {
        return file.nt_path().filter(|name| name.starts_with('\\'));
    }
    region.name().filter(|name| name.starts_with('\\'))
}

/// Páginas confirmadas da região, ou a região inteira quando confirmada sem
/// rastreio por página.
pub fn committed_bytes(info: &Info) -> u64 {
    let Some(region) = &info.region else { return 0 };
    match region.committed_pages() {
        Some(pages) => pages.len() as u64 * PAGE,
        None if info.state == 0x1000 => region.size(),
        None => 0,
    }
}

/// O comprimento mínimo do buffer por classe no MmQueryVirtualMemory do
/// ntoskrnl 19041 (rva 0x61ed50; a tabela das classes 1 a 11 em 0x61fa9c);
/// `None` para as classes que ele recusa com STATUS_INVALID_INFO_CLASS (as
/// 9 e 10, e as acima de 11).
fn minimum_length(class: u32) -> Option<u64> {
    match class {
        // Basic e PrivilegedBasic: o MEMORY_BASIC_INFORMATION.
        0 | 8 => Some(0x30),
        1 | 5 => Some(8),
        // MappedFilename: o ObQueryNameString confere o tamanho.
        2 => Some(0),
        // Region (a versão de 24 bytes) e Image.
        3 | 6 => Some(0x18),
        4 => Some(0x10),
        7 => Some(0x20),
        11 => Some(0x28),
        _ => None,
    }
}

/// O MiIsUserQueryVmCallerTrusted: o token efetivo (o de impersonação, senão
/// o primário) é de administrador ou o chamador tem
/// SeProfileSingleProcessPrivilege.
fn trusted_caller() -> bool {
    use crate::ntos::ps::process;
    let thread = process::get_current_thread();
    let token = crate::ntos::se::token::thread::get(thread).map(|impersonation| impersonation.token).or_else(|| process::get_primary_token(process::get_current_process()));
    token.is_some_and(crate::ntos::se::token::information::is_admin) || crate::ntos::se::privilege::single_privilege_check(SE_PROFILE_SINGLE_PROCESS_PRIVILEGE, 1)
}

/// SeProfileSingleProcessPrivilege.
const SE_PROFILE_SINGLE_PROCESS_PRIVILEGE: u64 = 13;
/// PROCESS_QUERY_LIMITED_INFORMATION.
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
/// STATUS_INVALID_ADDRESS: classe que descreve um VAD num endereço livre.
const STATUS_INVALID_ADDRESS: u32 = 0xC000_0141;
/// STATUS_FILE_INVALID: MappedFilename de uma vista sem arquivo.
const STATUS_FILE_INVALID: u32 = 0xC000_0098;

/// O syscall de usuário NtQueryVirtualMemory (o MmQueryVirtualMemory do
/// ntoskrnl 19041 com PreviousMode UserMode), sobre o VAD e a raiz do
/// processo do handle; as saídas vão para o chamador. A ordem é a do 19041:
/// a classe e o comprimento mínimo dela (STATUS_INVALID_INFO_CLASS,
/// STATUS_INFO_LENGTH_MISMATCH), o ProbeForWrite do buffer com alinhamento 8
/// e o do ReturnLength, o endereço acima de MM_HIGHEST_USER_ADDRESS
/// (STATUS_INVALID_PARAMETER) e o handle com
/// PROCESS_QUERY_LIMITED_INFORMATION; as classes 1, 4 e 11 pedem
/// PROCESS_QUERY_INFORMATION a quem não é administrador nem tem
/// SeProfileSingleProcessPrivilege. Um processo de sistema mínimo
/// (EPROCESS.Flags3.SystemProcess) aberto por handle dá STATUS_ACCESS_DENIED.
pub fn query_virtual_memory(process: u64, base_va: u64, info_class: u64, buffer_va: u64, user_rsp: u64) -> Result<u32, KernelError> {
    let class = info_class as u32;
    let length = state::stack_arg(user_rsp, 5);
    let return_length = state::stack_arg(user_rsp, 6);
    let Some(minimum) = minimum_length(class) else { return Ok(0xC000_0003) };
    if length < minimum {
        return Ok(0xC000_0004);
    }
    if length != 0 {
        if buffer_va & 7 != 0 {
            return Ok(0x8000_0002);
        }
        if !state::probe_user_write(buffer_va, length) {
            return Ok(0xC000_0005);
        }
    }
    if return_length != 0 && !state::probe_user_write(return_length, 8) {
        return Ok(0xC000_0005);
    }
    if base_va >= MAX_USER {
        return Ok(0xC000_000D);
    }
    let access = if matches!(class, 1 | 4 | 11) && !trusted_caller() { super::memory::PROCESS_QUERY_INFORMATION } else { PROCESS_QUERY_LIMITED_INFORMATION };
    super::memory::with_process_handle(process, access, |target| {
        // SAFETY: EPROCESS retido pelo handle durante a consulta.
        if process != u64::MAX && unsafe { crate::ntos::inc::types::Eprocess::at(target) }.system_process() != 0 {
            return Ok(0xC000_0022);
        }
        let context = Context::of(Space::of(target));
        let info = describe(base_va, &context);
        format(class, &info, &context, buffer_va, length, return_length)
    })
}

/// Grava a resposta da classe na memória do chamador (o buffer e o
/// ReturnLength já sondados); o ReturnLength recebe o tamanho gravado.
fn format(class: u32, info: &Info, context: &Context, buffer_va: u64, length: u64, return_length: u64) -> Result<u32, KernelError> {
    let done = |bytes: u64| -> Result<u32, KernelError> {
        if return_length != 0 {
            guest::try_write::<u64>(return_length, bytes)?;
        }
        Ok(0)
    };
    state::guarded(|| match class {
        // MemoryBasicInformation e MemoryPrivilegedBasicInformation (o
        // VslQueryVirtualMemory só entra num processo seguro, que o OpenNT não
        // tem): o kernelbase!WriteProcessMemory consulta a classe 8 antes de
        // escrever e falha junto com ela.
        0 | 8 => {
            guest::try_write_bytes(buffer_va, &[0; MemoryBasicInformation::SIZE as usize])?;
            let basic = state::user_struct::<MemoryBasicInformation>(buffer_va)?;
            basic.base_address.probe_set(info.base)?;
            basic.allocation_base.probe_set(info.allocation_base)?;
            basic.allocation_protect.probe_set(info.allocation_protect)?;
            basic.region_size.probe_set(info.size)?;
            basic.state.probe_set(info.state)?;
            basic.protect.probe_set(info.protect)?;
            basic.type_.probe_set(info.kind)?;
            done(MemoryBasicInformation::SIZE)
        }
        // MemoryMappedFilename: o OBJECT_NAME_INFORMATION do arquivo da vista
        // ou da imagem; endereço livre ou memória privada dá
        // STATUS_INVALID_ADDRESS, vista sem arquivo STATUS_FILE_INVALID. O
        // ReturnLength recebe o tamanho necessário mesmo com o buffer curto.
        2 => {
            let Some(region) = &info.region else { return Ok(STATUS_INVALID_ADDRESS) };
            if info.image.is_none() && region.section().is_none() {
                return Ok(STATUS_INVALID_ADDRESS);
            }
            let Some(name) = view_name(info.image.as_ref().unwrap_or(region)) else { return Ok(STATUS_FILE_INVALID) };
            if length > 0xFFFF_FFFF {
                return Ok(0xC000_00F3);
            }
            let need = UnicodeString::SIZE + (name.encode_utf16().count() as u64 + 1) * 2;
            if return_length != 0 {
                guest::try_write::<u64>(return_length, need)?;
            }
            if length < need {
                return Ok(0xC000_0004);
            }
            state::try_write_user_wide(buffer_va + UnicodeString::SIZE, &name)?;
            state::try_write_unicode_string(buffer_va, buffer_va + UnicodeString::SIZE, &name)?;
            Ok(0)
        }
        // MemoryRegionInformation e MemoryRegionInformationEx: a saída cresce
        // com o buffer (24, 32, 40 ou 48 bytes). Na classe 3 o RegionType é o
        // Type do MEMORY_BASIC_INFORMATION (com 48 bytes, uma vista sem
        // arquivo é 0x8000000); na 7, os bits Private, MappedDataFile,
        // MappedImage e MappedPageFile.
        3 | 7 => {
            let Some(region) = &info.region else { return Ok(STATUS_INVALID_ADDRESS) };
            let page_file = info.image.is_none() && region.section().is_some_and(|section| section.file.is_none());
            let kind = if class == 7 {
                if info.image.is_some() {
                    4
                } else {
                    match region.section() {
                        Some(_) if page_file => 8,
                        Some(_) => 2,
                        None => 1,
                    }
                }
            } else if page_file && length >= 0x30 {
                0x800_0000
            } else {
                info.kind
            };
            let information = state::user_struct::<MemoryRegionInformation>(buffer_va)?;
            information.allocation_base.probe_set(info.allocation_base)?;
            information.allocation_protect.probe_set(info.allocation_protect)?;
            information.region_type.probe_set(kind)?;
            information.region_size.probe_set(region.size())?;
            let mut written = 0x18;
            if length >= 0x20 {
                information.commit_size.probe_set(committed_bytes(info))?;
                written = 0x20;
            }
            if length >= 0x28 {
                // A partição do sistema.
                information.partition_id.probe_set(0)?;
                written = 0x28;
            }
            if length >= 0x30 {
                // Nenhum nó NUMA preferido.
                information.node_preference.probe_set(0xFFFF_FFFF)?;
                written = 0x30;
            }
            done(written)
        }
        4 => {
            // Vetor MEMORY_WORKING_SET_EX_INFORMATION (entrada e saída).
            if length % 16 != 0 {
                return Ok(0xC000_0004);
            }
            let mut offset = 0;
            while offset < length {
                let entry = state::user_struct::<MemoryWorkingSetExInformation>(buffer_va + offset)?;
                let va = entry.virtual_address.probe_get()?;
                let page = describe(va, context);
                let valid = va < MAX_USER && context.translate(va) != 0;
                // VirtualAttributes: Valid e Win32Protection.
                entry.virtual_attributes.probe_set(if valid { 1 + page.protect as u64 * 16 } else { 0 })?;
                offset += MemoryWorkingSetExInformation::SIZE;
            }
            done(length)
        }
        // MemoryImageInformation: o MEMORY_IMAGE_INFORMATION de uma imagem
        // (ImageNotExecutable de uma seção sem execução); fora de imagem, 24
        // bytes zerados com sucesso; endereço livre, STATUS_INVALID_ADDRESS.
        6 => {
            let Some(region) = &info.region else { return Ok(STATUS_INVALID_ADDRESS) };
            guest::try_write_bytes(buffer_va, &[0; MemoryImageInformation::SIZE as usize])?;
            if let Some(image) = &info.image {
                let information = state::user_struct::<MemoryImageInformation>(buffer_va)?;
                information.image_base.probe_set(image.base())?;
                information.size_of_image.probe_set(image.size())?;
                if region.section().is_some_and(|section| section.no_execute) {
                    information.image_flags.probe_set(2)?;
                }
            }
            done(MemoryImageInformation::SIZE)
        }
        // As classes 1, 5 e 11 (working set, commit compartilhado e
        // contiguidade física) ainda não existem no OpenNT.
        _ => Ok(0xC000_0003),
    })
}
