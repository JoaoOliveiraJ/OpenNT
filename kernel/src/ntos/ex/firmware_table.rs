//! Tabelas de firmware: os provedores de SYSTEM_FIRMWARE_TABLE_INFORMATION e
//! o ExGetSystemFirmwareTable.
//!
//! ntoskrnl 19041:
//! - ExGetSystemFirmwareTable(ProviderSignature, TableID, Buffer,
//!   BufferLength, ReturnLength) 0x7d0ec0: Buffer NULL com BufferLength != 0
//!   é STATUS_INVALID_PARAMETER; senão monta, no pool 'ARFT', um
//!   SYSTEM_FIRMWARE_TABLE_INFORMATION com Action = SystemFirmwareTable_Get e
//!   TableBufferLength = BufferLength e o entrega ao
//!   ExpGetSystemFirmwareTableInformation em KernelMode. Com sucesso ou
//!   STATUS_BUFFER_TOO_SMALL, *ReturnLength (se dado) recebe o
//!   TableBufferLength que o provedor deixou; com sucesso e Buffer, a tabela
//!   é copiada.
//! - ExpGetSystemFirmwareTableInformation 0x69061c: menos de 16 bytes é
//!   STATUS_INFO_LENGTH_MISMATCH; o provedor da assinatura é procurado na
//!   lista ExpFirmwareTableProviderListHead sob o ExpFirmwareTableResource
//!   (compartilhado, em região crítica) e chamado com o bloco; sem provedor,
//!   STATUS_NOT_IMPLEMENTED. O tamanho devolvido é o
//!   TableBufferLength do provedor mais o cabeçalho.
//! - Os provedores do próprio kernel, que o WMI registra no boot pelo
//!   SystemRegisterFirmwareTableInformationHandler: 'RSMB'
//!   (WmipRawSMBiosTableHandler 0x2e7a90) sempre e 'FIRM'
//!   (WmipFirmwareTableHandler 0x3ca8d0) só com firmware BIOS. O OpenNT os
//!   põe na lista na primeira consulta ou no primeiro registro.
//! - ExpRegisterFirmwareTableInformationHandler 0x7cb498 (a classe 75 do
//!   NtSetSystemInformation, a do 'ACPI' do acpi.sys): o modo usuário é
//!   STATUS_PRIVILEGE_NOT_HELD; buffer NULL ou menor que o
//!   SYSTEM_FIRMWARE_TABLE_HANDLER de 0x18 bytes, STATUS_INFO_LENGTH_MISMATCH.
//!   Sob o recurso exclusivo: uma assinatura já registrada com Register é
//!   STATUS_OBJECT_NAME_EXISTS (0x40000000) sem mudar nada; sem Register, o
//!   mesmo DriverObject tira o provedor (e solta a referência do driver) e
//!   outro dá STATUS_INVALID_PARAMETER. Uma assinatura nova sem Register é
//!   STATUS_INVALID_PARAMETER; com Register, o bloco 'ARFT' de 0x28 bytes vai
//!   ao fim da lista com uma referência ao DriverObject.
//! - A consulta de modo usuário (a classe 76 do NtQuerySystemInformation)
//!   copia o buffer inteiro para um bloco de kernel com quota, recusa com
//!   STATUS_ACCESS_DENIED um processo AppContainer (o 19041 deixa passar o
//!   'RSMB' quando o token tem a capacidade smbios ou
//!   Microsoft.firmwareRead, ExpFirmwareAccessAppContainerCheck; o OpenNT
//!   recusa todos), chama o provedor e devolve a tabela (com sucesso) e o
//!   TableBufferLength (com sucesso ou STATUS_BUFFER_TOO_SMALL) ao buffer do
//!   chamador.
//!
//! 'FIRM' (WmipFirmwareTableArray 0x20550): as tabelas 0xC0000 e 0xE0000, de
//! 0x20000 bytes cada, copiadas da memória física. Enumerar devolve os dois
//! TableIDs (8 bytes); um TableID desconhecido é STATUS_INVALID_PARAMETER_1,
//! buffer curto STATUS_BUFFER_TOO_SMALL com o tamanho, mapeamento recusado
//! STATUS_NOT_FOUND.
//!
//! 'RSMB': enumerar devolve um único TableID 0 (4 bytes); ler devolve o
//! RawSMBIOSData (Used20CallingMethod 0, as versões maior e menor do SMBIOS,
//! DmiRevision 0, Length) seguido da tabela de estruturas. O WMI tira
//! endereço, tamanho e versões do ponto de entrada que o carregador passa
//! (WmipGetSMBiosFromLoaderBlock 0xa73d6c); o OpenNT acha o ponto de entrada
//! no segmento F do BIOS, de 16 em 16 bytes: o de 64 bits ("_SM3_", o
//! tamanho máximo da tabela em +0xC e o endereço em +0x10) ou, sem ele, o de
//! 32 bits ("_SM_" com "_DMI_" em +0x10, o tamanho em +0x16 e o endereço em
//! +0x18). Sem SMBIOS, STATUS_INVALID_DEVICE_REQUEST (0xC0000010) e
//! TableBufferLength 0. O valor HideMachine de Control\WMI\Restrictions, com
//! que o NT apaga números de série da cópia, não existe na hive do OpenNT.

use alloc::vec::Vec;

use crate::hal::amd64::native_call;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::extra_ps_user::SystemFirmwareTableHandler;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::io_space;
use crate::rtl::{KernelError, SpinLock};

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
/// O ExpGetSystemFirmwareTableInformation sem provedor da assinatura.
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_OBJECT_NAME_EXISTS: u32 = 0x4000_0000;
/// PagedPool com quota (o ExAllocatePoolWithQuotaTag do modo usuário).
const PAGED_POOL: u32 = 1;
/// TOKEN_LOWBOX: o token de um processo AppContainer.
const TOKEN_LOWBOX: u32 = 0x4000;
const FIRMWARE_TABLE_TAG: u32 = u32::from_le_bytes(*b"ARFT");
const NON_PAGED_POOL: u32 = 0;

/// SystemFirmwareTable_Enumerate e SystemFirmwareTable_Get.
const ACTION_ENUMERATE: u32 = 0;
const ACTION_GET: u32 = 1;
/// FIRMWARE_TYPE: FirmwareTypeBios.
const FIRMWARE_TYPE_BIOS: u32 = 1;

pub const PROVIDER_RSMB: u32 = u32::from_be_bytes(*b"RSMB");
pub const PROVIDER_FIRM: u32 = u32::from_be_bytes(*b"FIRM");

/// SYSTEM_FIRMWARE_TABLE_INFORMATION (SDK, ntexapi.h): o cabeçalho de 16
/// bytes; TableBuffer[] segue em +0x10.
#[repr(C)]
struct TableInformation {
    provider_signature: Field<u32>,
    action: Field<u32>,
    table_id: Field<u32>,
    table_buffer_length: Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for TableInformation {}

const HEADER: u64 = TableInformation::SIZE;
const _: () = assert!(core::mem::size_of::<TableInformation>() == 0x10);

/// RawSMBIOSData (o cabeçalho da tabela 'RSMB', 8 bytes).
#[repr(C)]
struct RawSmbiosHeader {
    used20_calling_method: Field<u8>,
    major_version: Field<u8>,
    minor_version: Field<u8>,
    dmi_revision: Field<u8>,
    length: Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for RawSmbiosHeader {}

const _: () = assert!(core::mem::size_of::<RawSmbiosHeader>() == 8);

/// Ponto de entrada de 64 bits ("_SM3_") do SMBIOS 3.0, o formato que o
/// carregador do Windows entrega ao WMI.
#[repr(C)]
struct Smbios3EntryPoint {
    anchor: [Field<u8>; 5],
    checksum: Field<u8>,
    length: Field<u8>,
    major_version: Field<u8>,
    minor_version: Field<u8>,
    docrev: Field<u8>,
    revision: Field<u8>,
    _reserved: Reserved<1>,
    table_maximum_size: Field<u32>,
    table_address: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for Smbios3EntryPoint {}

const _: () = {
    assert!(core::mem::offset_of!(Smbios3EntryPoint, table_maximum_size) == 0xC);
    assert!(core::mem::offset_of!(Smbios3EntryPoint, table_address) == 0x10);
    assert!(core::mem::size_of::<Smbios3EntryPoint>() == 0x18);
};

/// Ponto de entrada de 32 bits ("_SM_"), com o intermediário "_DMI_".
#[repr(C)]
struct Smbios2EntryPoint {
    anchor: [Field<u8>; 4],
    checksum: Field<u8>,
    length: Field<u8>,
    major_version: Field<u8>,
    minor_version: Field<u8>,
    _maximum_structure_size: Field<u16>,
    _revision: Field<u8>,
    _formatted: Reserved<5>,
    intermediate_anchor: [Field<u8>; 5],
    _intermediate_checksum: Field<u8>,
    table_length: Field<u16>,
    table_address: Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for Smbios2EntryPoint {}

const _: () = {
    assert!(core::mem::offset_of!(Smbios2EntryPoint, intermediate_anchor) == 0x10);
    assert!(core::mem::offset_of!(Smbios2EntryPoint, table_length) == 0x16);
    assert!(core::mem::offset_of!(Smbios2EntryPoint, table_address) == 0x18);
    assert!(core::mem::size_of::<Smbios2EntryPoint>() == 0x1C);
};

/// O que o WMI guarda do SMBIOS: WmipSMBiosTablePhysicalAddress,
/// WmipSMBiosTableLength e as versões de WmipSMBiosVersionInfo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmbiosTable {
    pub physical_address: u64,
    pub length: u32,
    pub major_version: u8,
    pub minor_version: u8,
}

/// A rotina de um provedor: recebe o bloco e devolve o NTSTATUS. Os do
/// kernel são rotinas internas; os de drivers, o PFNFTH nativo.
#[derive(Clone, Copy)]
enum Handler {
    Kernel(fn(&TableInformation) -> u32),
    Native(u64),
}

impl Handler {
    fn call(self, information: &TableInformation) -> u32 {
        match self {
            Handler::Kernel(routine) => routine(information),
            Handler::Native(routine) => native_call::call(routine, &[information.address()]) as u32,
        }
    }
}

struct Provider {
    signature: u32,
    handler: Handler,
    /// O DriverObject referenciado do registro (0 nos do kernel).
    driver_object: u64,
}

struct Providers {
    initialized: bool,
    list: Vec<Provider>,
    smbios: Option<SmbiosTable>,
}

/// ExpFirmwareTableProviderListHead sob o ExpFirmwareTableResource.
static PROVIDERS: SpinLock<Providers> = SpinLock::new(Providers { initialized: false, list: Vec::new(), smbios: None });

/// A soma dos bytes do ponto de entrada fecha em zero.
fn checksum_ok(physical: u64, length: u64) -> bool {
    length != 0 && crate::hal::physical::read_bytes(physical, length as usize).iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) == 0
}

/// Procura o ponto de entrada no segmento F (0xF0000..0x100000).
fn find_smbios() -> Option<SmbiosTable> {
    let segment = io_space::map_ex(0xF_0000, 0x1_0000);
    if segment == 0 {
        return None;
    }
    let mut legacy = None;
    let mut modern = None;
    for offset in (0..0x1_0000u64 - 0x20).step_by(16) {
        let candidate = segment + offset;
        let physical = 0xF_0000 + offset;
        let head = guest::read_bytes(candidate, 5);
        if modern.is_none() && head == *b"_SM3_" {
            // SAFETY: 0x18 bytes dentro do segmento mapeado.
            let entry = unsafe { Smbios3EntryPoint::at(candidate) };
            if checksum_ok(physical, entry.length.get() as u64) {
                modern = Some(SmbiosTable { physical_address: entry.table_address.get(), length: entry.table_maximum_size.get(), major_version: entry.major_version.get(), minor_version: entry.minor_version.get() });
            }
        } else if legacy.is_none() && head[..4] == *b"_SM_" {
            // SAFETY: 0x1F bytes dentro do segmento mapeado.
            let entry = unsafe { Smbios2EntryPoint::at(candidate) };
            let intermediate: Vec<u8> = entry.intermediate_anchor.iter().map(|byte| byte.get()).collect();
            if checksum_ok(physical, entry.length.get() as u64) && intermediate == *b"_DMI_" {
                legacy = Some(SmbiosTable { physical_address: entry.table_address.get() as u64, length: entry.table_length.get() as u32, major_version: entry.major_version.get(), minor_version: entry.minor_version.get() });
            }
        }
    }
    io_space::unmap(segment, 0x1_0000);
    modern.or(legacy)
}

/// Os provedores do kernel na primeira consulta ou registro (o registro do
/// WMI no boot, antes dos drivers).
fn with_providers<T>(body: impl FnOnce(&mut Providers) -> T) -> T {
    let mut providers = PROVIDERS.lock();
    if !providers.initialized {
        providers.initialized = true;
        providers.smbios = find_smbios();
        providers.list.push(Provider { signature: PROVIDER_RSMB, handler: Handler::Kernel(raw_smbios_handler), driver_object: 0 });
        let firmware_type = crate::ntos::ex::boot_environment::get_information().map_or(0, |information| u32::from_le_bytes([information[16], information[17], information[18], information[19]]));
        if firmware_type == FIRMWARE_TYPE_BIOS {
            providers.list.push(Provider { signature: PROVIDER_FIRM, handler: Handler::Kernel(firmware_table_handler), driver_object: 0 });
        }
    }
    body(&mut providers)
}

/// O SMBIOS que o provedor 'RSMB' entrega.
pub fn smbios_table() -> Option<SmbiosTable> {
    with_providers(|providers| providers.smbios)
}

/// Copia `length` bytes da memória física para `destination`.
fn copy_physical(destination: u64, physical: u64, length: u32) -> bool {
    let mapped = io_space::map_ex(physical, length as u64);
    if mapped == 0 {
        return false;
    }
    guest::write_bytes(destination, &guest::read_bytes(mapped, length as usize));
    io_space::unmap(mapped, length as u64);
    true
}

/// WmipFirmwareTableArray: (TableID = endereço físico, tamanho).
const FIRMWARE_TABLES: [(u32, u32); 2] = [(0xC_0000, 0x2_0000), (0xE_0000, 0x2_0000)];

/// WmipFirmwareTableHandler ('FIRM').
fn firmware_table_handler(information: &TableInformation) -> u32 {
    let buffer = information.address() + HEADER;
    match information.action.get() {
        ACTION_ENUMERATE => {
            let capacity = information.table_buffer_length.get();
            information.table_buffer_length.set(8);
            if capacity < 8 {
                return STATUS_BUFFER_TOO_SMALL;
            }
            for (index, &(table, _)) in FIRMWARE_TABLES.iter().enumerate() {
                guest::write32(buffer + index as u64 * 4, table);
            }
            STATUS_SUCCESS
        }
        ACTION_GET => {
            let Some(&(table, size)) = FIRMWARE_TABLES.iter().find(|&&(table, _)| table == information.table_id.get()) else { return STATUS_INVALID_PARAMETER_1 };
            let capacity = information.table_buffer_length.get();
            information.table_buffer_length.set(size);
            if capacity < size {
                return STATUS_BUFFER_TOO_SMALL;
            }
            if copy_physical(buffer, table as u64, size) { STATUS_SUCCESS } else { STATUS_NOT_FOUND }
        }
        _ => STATUS_INVALID_PARAMETER_1,
    }
}

/// WmipRawSMBiosTableHandler ('RSMB').
fn raw_smbios_handler(information: &TableInformation) -> u32 {
    let buffer = information.address() + HEADER;
    match information.action.get() {
        ACTION_ENUMERATE => {
            let capacity = information.table_buffer_length.get();
            information.table_buffer_length.set(4);
            if capacity < 4 {
                return STATUS_BUFFER_TOO_SMALL;
            }
            guest::write32(buffer, 0);
            STATUS_SUCCESS
        }
        ACTION_GET => {
            // O WmipGetSMBiosTableData lê o SMBIOS guardado sem a trava dos provedores.
            let Some(table) = PROVIDERS.lock().smbios.filter(|table| table.physical_address != 0) else {
                information.table_buffer_length.set(0);
                return STATUS_INVALID_DEVICE_REQUEST;
            };
            if table.length == 0 {
                // O mapeamento de tamanho zero falha no WmipGetSMBiosTableData.
                information.table_buffer_length.set(0);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            let needed = table.length + RawSmbiosHeader::SIZE as u32;
            if information.table_buffer_length.get() < needed {
                information.table_buffer_length.set(needed);
                return STATUS_BUFFER_TOO_SMALL;
            }
            // SAFETY: o começo do TableBuffer, com espaço para o cabeçalho.
            let header = unsafe { RawSmbiosHeader::at(buffer) };
            if !copy_physical(buffer + RawSmbiosHeader::SIZE, table.physical_address, table.length) {
                information.table_buffer_length.set(needed);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            header.used20_calling_method.set(0);
            header.major_version.set(table.major_version);
            header.minor_version.set(table.minor_version);
            header.dmi_revision.set(0);
            header.length.set(table.length);
            information.table_buffer_length.set(needed);
            STATUS_SUCCESS
        }
        _ => STATUS_INVALID_PARAMETER_1,
    }
}

/// ExpGetSystemFirmwareTableInformation(Information, KernelMode, Length,
/// ReturnLength): o status e o tamanho a devolver (`None` sem provedor).
fn query_information(information: &TableInformation, length: u32) -> (u32, Option<u32>) {
    if length < HEADER as u32 {
        return (STATUS_INFO_LENGTH_MISMATCH, Some(HEADER as u32));
    }
    information.table_buffer_length.set(length - HEADER as u32);
    let Some(handler) = provider_handler(information.provider_signature.get()) else { return (STATUS_NOT_IMPLEMENTED, None) };
    let status = handler.call(information);
    (status, Some(information.table_buffer_length.get() + HEADER as u32))
}

/// O provedor da assinatura (a busca na ExpFirmwareTableProviderListHead).
fn provider_handler(signature: u32) -> Option<Handler> {
    with_providers(|providers| providers.list.iter().find(|provider| provider.signature == signature).map(|provider| provider.handler))
}

/// PsIsProcessAppContainer do processo corrente: o token primário é lowbox.
fn current_process_is_app_container() -> bool {
    use crate::ntos::ps::process;
    process::get_primary_token(process::get_current_process()).is_some_and(|token| crate::ntos::se::token::tokens::body(token).token_flags.get() & TOKEN_LOWBOX != 0)
}

/// ExpGetSystemFirmwareTableInformation(Buffer, PreviousMode, Length,
/// &ReturnLength), a classe 76 do NtQuerySystemInformation: (NTSTATUS,
/// tamanho para o ReturnLength). O tamanho fica 0 quando a assinatura não
/// tem provedor (a célula local do ExpQuerySystemInformation). No modo
/// kernel o provedor recebe o próprio buffer; no modo usuário (`user`, o
/// buffer já sondado para escrita), uma cópia de kernel.
pub fn query_system_information(buffer: u64, length: u32, user: bool) -> Result<(u32, u32), KernelError> {
    if length < HEADER as u32 {
        return Ok((STATUS_INFO_LENGTH_MISMATCH, HEADER as u32));
    }
    if !user {
        // SAFETY: o buffer de modo kernel do chamador, com o cabeçalho.
        let information = unsafe { TableInformation::at(buffer) };
        let (status, returned) = query_information(information, length);
        return Ok((status, returned.unwrap_or(0)));
    }
    let block = crate::ntos::ex::pool_allocation::allocate_tagged(PAGED_POOL, length as u64, FIRMWARE_TABLE_TAG)?;
    if block == 0 {
        return Ok((STATUS_INSUFFICIENT_RESOURCES, 0));
    }
    let result = (|| -> Result<(u32, u32), KernelError> {
        guest::write_bytes(block, &guest::try_read_bytes(buffer, length as usize)?);
        // SAFETY: o bloco de kernel com a cópia do buffer do chamador.
        let information = unsafe { TableInformation::at(block) };
        if current_process_is_app_container() {
            return Ok((STATUS_ACCESS_DENIED, 0));
        }
        let (status, returned) = query_information(information, length);
        let Some(returned) = returned else { return Ok((status, 0)) };
        let table_length = information.table_buffer_length.get();
        if status & 0x8000_0000 == 0 {
            guest::try_write_bytes(buffer + HEADER, &guest::read_bytes(block + HEADER, table_length as usize))?;
        }
        if status & 0x8000_0000 == 0 || status == STATUS_BUFFER_TOO_SMALL {
            TableInformation::try_at(buffer)?.table_buffer_length.probe_set(table_length)?;
        }
        Ok((status, returned))
    })();
    crate::ntos::ex::pool_allocation::free(block, FIRMWARE_TABLE_TAG as u64)?;
    match result {
        Ok(answer) => Ok(answer),
        Err(error) if error.status != 0 => Ok((error.status, 0)),
        Err(error) => Err(error),
    }
}

/// ExpRegisterFirmwareTableInformationHandler(Buffer, Length, PreviousMode):
/// o NTSTATUS do registro ou da remoção de um provedor de driver.
pub fn register_handler(buffer: u64, length: u32, user: bool) -> u32 {
    if user {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    if buffer == 0 || (length as u64) < SystemFirmwareTableHandler::SIZE {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    // SAFETY: o SYSTEM_FIRMWARE_TABLE_HANDLER de modo kernel do chamador,
    // com o tamanho conferido.
    let request = unsafe { SystemFirmwareTableHandler::at(buffer) };
    let (signature, register, routine, driver_object) = (request.provider_signature.get(), request.register.get() != 0, request.firmware_table_handler.get(), request.driver_object.get());
    let released = with_providers(|providers| {
        if let Some(index) = providers.list.iter().position(|provider| provider.signature == signature) {
            if register {
                return Err(STATUS_OBJECT_NAME_EXISTS);
            }
            if providers.list[index].driver_object != driver_object {
                return Err(STATUS_INVALID_PARAMETER);
            }
            return Ok(Some(providers.list.remove(index).driver_object));
        }
        if !register {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if driver_object != 0 {
            crate::ntos::ob::object_header::reference(driver_object, 1);
        }
        providers.list.push(Provider { signature, handler: Handler::Native(routine), driver_object });
        Ok(None)
    });
    match released {
        Ok(Some(driver_object)) => {
            if driver_object != 0 {
                crate::ntos::ob::object_header::dereference(driver_object, false);
            }
            0
        }
        Ok(None) => 0,
        Err(status) => status,
    }
}

/// ExGetSystemFirmwareTable(ProviderSignature, TableID, Buffer, BufferLength,
/// ReturnLength) -> NTSTATUS.
pub fn get_system_firmware_table(signature: u32, table_id: u32, buffer: u64, buffer_length: u32, return_length: Option<&Field<u32>>) -> Result<u32, KernelError> {
    if buffer == 0 && buffer_length != 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let size = buffer_length as u64 + HEADER;
    let block = crate::ntos::ex::pool_allocation::allocate_tagged(NON_PAGED_POOL, size, FIRMWARE_TABLE_TAG)?;
    if block == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    // SAFETY: bloco do pool com o cabeçalho e o buffer da tabela.
    let information = unsafe { TableInformation::at(block) };
    information.provider_signature.set(signature);
    information.action.set(ACTION_GET);
    information.table_id.set(table_id);
    information.table_buffer_length.set(buffer_length);
    let (status, returned) = query_information(information, size as u32);
    let success = status & 0x8000_0000 == 0;
    if success || status == STATUS_BUFFER_TOO_SMALL {
        if let Some(cell) = return_length {
            cell.set(information.table_buffer_length.get());
        }
    }
    if success && buffer != 0 {
        let copied = returned.unwrap_or(HEADER as u32).saturating_sub(HEADER as u32);
        guest::write_bytes(buffer, &guest::read_bytes(block + HEADER, copied as usize));
    }
    crate::ntos::ex::pool_allocation::free(block, FIRMWARE_TABLE_TAG as u64)?;
    Ok(status)
}
