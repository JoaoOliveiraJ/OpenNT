//! Pré-busca de memória virtual: MmPrefetchVirtualAddresses (ntoskrnl
//! 19041).
//!
//! O pedido (Version, Flags, Process, NumberOfEntries, VirtualAddresses: um
//! vetor de MEMORY_RANGE_ENTRY {VirtualAddress, NumberOfBytes}) é conferido
//! como no NT — Version diferente de 1, Flags fora dos três bits ou com os
//! bits 1 e 2 juntos dão STATUS_INVALID_PARAMETER_1 — e cada faixa é
//! trazida para a memória no espaço do processo (anexado a ele): cada
//! página de usuário da faixa é lida uma vez, o que resolve as faltas de
//! demanda das páginas comprometidas. A pré-busca é um conselho: página
//! inacessível não é erro, e o resultado é STATUS_SUCCESS.
//!
//! MmPrefetchPages (leitura antecipada de páginas de arquivos mapeados):
//! ntoskrnl 10.0.19041: MmPrefetchPages 0x61afc0 -> MmPrefetchPagesEx
//! 0x61c774 (Flags 0) -> MiPfPrepareReadList 0x63d030 por READ_LIST. Mais de
//! 0x1FFFFFFF listas é STATUS_INVALID_PARAMETER_1. Cada lista é preparada
//! sobre a CONTROL_AREA de dados (ou de imagem, com IsImage) do
//! SECTION_OBJECT_POINTERS do arquivo; uma falha de preparação só fica
//! registrada e as outras listas seguem. O primeiro elemento com os bits
//! 0x180 ligados, ou uma CONTROL_AREA de memória física (u.Flags 0x400) ou
//! sem FilePointer, é STATUS_INVALID_PARAMETER_1. Uma lista sem páginas a
//! ler não gera leitura; sem nenhuma leitura, o resultado é o status da
//! última falha de preparação (ou sucesso).
//!
//! No OpenNT nenhuma CONTROL_AREA nativa tem PTEs protótipo para encher: a
//! lista válida não tem páginas a ler, como no NT quando todas já estão
//! residentes. O NT exige uma seção no arquivo (desreferencia a CONTROL_AREA
//! sem conferir); o arquivo sem CONTROL_AREA — todo arquivo de file system
//! no OpenNT, cujas páginas vêm do Cache Manager — também fica sem leitura,
//! em vez de parar o sistema.

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::memory_map;
use crate::ntos::ps::process_context;
use crate::rtl::KernelError;
use crate::ntos::inc::types::{ControlArea, FileObject, SectionObjectPointers};

pub const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
const PAGE: u64 = 0x1000;

/// O pedido de pré-busca.
#[repr(C)]
pub struct PrefetchRequest {
    pub version: Field<u32>,
    pub flags: Field<u32>,
    pub process: Field<u64>,
    pub number_of_entries: Field<u64>,
    pub virtual_addresses: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for PrefetchRequest {}

/// MEMORY_RANGE_ENTRY.
#[repr(C)]
struct MemoryRangeEntry {
    virtual_address: Field<u64>,
    number_of_bytes: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for MemoryRangeEntry {}

/// Páginas que uma faixa pede, no máximo (o resto é ignorado: conselho).
const MAXIMUM_PAGES_PER_RANGE: u64 = 0x1_0000;

/// MmPrefetchVirtualAddresses(Request). Devolve o NTSTATUS e as páginas
/// lidas.
pub fn prefetch_virtual_addresses(request: &PrefetchRequest) -> Result<(u32, u64), KernelError> {
    let flags = request.flags.get();
    if request.version.get() != 1 || flags >= 8 || flags & 6 == 6 {
        return Ok((STATUS_INVALID_PARAMETER_1, 0));
    }
    let (process, count, entries) = (request.process.get(), request.number_of_entries.get(), request.virtual_addresses.get());
    process_context::with_process(process, || {
        let mut touched = 0;
        for index in 0..count {
            // SAFETY: o vetor de faixas do chamador de kernel.
            let entry = unsafe { MemoryRangeEntry::at(entries + index * MemoryRangeEntry::SIZE) };
            let (start, length) = (entry.virtual_address.get(), entry.number_of_bytes.get());
            let Some(end) = start.checked_add(length) else { continue };
            let mut page = start & !(PAGE - 1);
            let mut pages = 0;
            while page < end && page < memory_map::USER_PROBE_ADDRESS && pages < MAXIMUM_PAGES_PER_RANGE {
                if guest::try_read::<u8>(page).is_ok() {
                    touched += 1;
                }
                page += PAGE;
                pages += 1;
            }
        }
        Ok((0, touched))
    })?
}

/// VIRTUAL_MEMORY_INFORMATION_CLASS.VmPrefetchInformation.
const VM_PREFETCH_INFORMATION: u32 = 0;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
const STATUS_INVALID_PARAMETER_5: u32 = 0xC000_00F3;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;

/// ZwSetInformationVirtualMemory(Process, VmInformationClass,
/// NumberOfEntries, VirtualAddresses, VmInformation, VmInformationLength):
/// VmPrefetchInformation (o ULONG de flags, que precisa ser 0) pré-busca as
/// faixas no processo, como o MmPrefetchVirtualAddresses; as classes de
/// prioridade de página e de alvos de CFG ainda não existem no OpenNT
/// (STATUS_NOT_SUPPORTED); classe desconhecida, STATUS_INVALID_PARAMETER_2.
/// O processo é o NtCurrentProcess ou um handle de processo da tabela
/// nativa; outro handle dá STATUS_INVALID_HANDLE.
pub fn set_information_virtual_memory(process_handle: u64, class: u32, count: u64, entries: u64, information: u64, length: u32) -> Result<u32, KernelError> {
    let process = if process_handle == u64::MAX {
        crate::ntos::ps::process::get_current_process()
    } else {
        match crate::ntos::ob::open_pointer::resolve(process_handle, false) {
            Some(Ok(opened)) if opened.item.object_type.name == "Process" => opened.item.pointer,
            _ => return Ok(0xC000_0008),
        }
    };
    match class {
        VM_PREFETCH_INFORMATION => {
            if length != 4 || information == 0 {
                return Ok(STATUS_INVALID_PARAMETER_5);
            }
            // SAFETY: o ULONG de flags do chamador de kernel.
            if unsafe { Field::<u32>::at(information) }.get() != 0 {
                return Ok(STATUS_INVALID_PARAMETER_5);
            }
            let request = guest::alloc_bytes(PrefetchRequest::SIZE);
            // SAFETY: bloco recém-alocado do tamanho do pedido.
            let prefetch = unsafe { PrefetchRequest::at(request) };
            prefetch.version.set(1);
            prefetch.process.set(process);
            prefetch.number_of_entries.set(count);
            prefetch.virtual_addresses.set(entries);
            let result = prefetch_virtual_addresses(prefetch);
            guest::free_bytes(request);
            Ok(result?.0)
        }
        1..=4 => Ok(STATUS_NOT_SUPPORTED),
        _ => Ok(STATUS_INVALID_PARAMETER_2),
    }
}

// ---- MmPrefetchPages ---------------------------------------------------------

/// Bits do primeiro elemento que a preparação recusa.
const INVALID_ENTRY_FLAGS: u32 = 0x180;
/// u.Flags.PhysicalMemory.
const PHYSICAL_MEMORY: u32 = 0x400;
const MAXIMUM_LISTS: u32 = 0x1FFF_FFFF;

/// READ_LIST (ntifs.h): FileObject, NumberOfEntries, IsImage e os
/// FILE_SEGMENT_ELEMENT (deslocamentos no arquivo) a partir de +0x10.
#[repr(C)]
struct ReadList {
    file_object: Field<u64>,
    number_of_entries: Field<u32>,
    is_image: Field<u32>,
    first_entry: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for ReadList {}

const _: () = {
    assert!(core::mem::offset_of!(ReadList, number_of_entries) == 0x8);
    assert!(core::mem::offset_of!(ReadList, is_image) == 0xC);
    assert!(core::mem::offset_of!(ReadList, first_entry) == 0x10);
};

/// MiPfPrepareReadList: Ok(()) quando a lista não tem nada a ler.
fn prepare(list: &ReadList) -> Result<(), u32> {
    if list.first_entry.get() as u32 & INVALID_ENTRY_FLAGS != 0 {
        return Err(STATUS_INVALID_PARAMETER_1);
    }
    // SAFETY: FILE_OBJECT vivo e o SECTION_OBJECT_POINTERS do seu FCB.
    let file = unsafe { FileObject::at(list.file_object.get()) };
    let pointers_address = file.section_object_pointer.get();
    if pointers_address == 0 {
        return Ok(());
    }
    // SAFETY: SECTION_OBJECT_POINTERS do FCB do file system dono do arquivo.
    let pointers = unsafe { SectionObjectPointers::at(pointers_address) };
    let slot = if list.is_image.get() != 0 { &pointers.image_section_object } else { &pointers.data_section_object };
    let address = slot.get();
    if address == 0 {
        return Ok(());
    }
    // SAFETY: CONTROL_AREA publicada na SOP pelo Mm.
    let control_area = unsafe { ControlArea::at(address) };
    if control_area.u.long_flags.get() & PHYSICAL_MEMORY != 0 || control_area.file_pointer.value.get() == 0 {
        return Err(STATUS_INVALID_PARAMETER_1);
    }
    Ok(())
}

/// MmPrefetchPages(NumberOfLists, ReadLists) -> NTSTATUS.
pub fn prefetch_pages(count: u32, lists: u64) -> u32 {
    if count > MAXIMUM_LISTS {
        return STATUS_INVALID_PARAMETER_1;
    }
    let mut status = 0;
    for index in 0..count as u64 {
        // SAFETY: PREAD_LIST ReadLists[NumberOfLists] do chamador.
        let list = unsafe { ReadList::at(guest::read64(lists + index * 8)) };
        if let Err(failure) = prepare(list) {
            status = failure;
        }
    }
    status
}
