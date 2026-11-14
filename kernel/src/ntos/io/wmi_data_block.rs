//! Consultas WMI por bloco de dados (IoWMIQuerySingleInstance,
//! IoWMIHandleToInstanceName, IoWMIExecuteMethod).
//!
//! No ntoskrnl 19041 operam sobre um DataBlockObject aberto por IoWMIOpenBlock:
//! IoWMIQuerySingleInstance (rva 0x756850) vai ao WmipQuerySetExecuteSI e
//! IoWMIHandleToInstanceName (rva 0x78cf50) a WmipGetFilePDO +
//! IoWMIDeviceObjectToInstanceName.
//!
//! STUB HONESTO: o OpenNT não tem o subsistema WMI e o seu IoWMIOpenBlock
//! (grupo io-diagnostics) devolve STATUS_WMI_GUID_NOT_FOUND, então nenhum
//! bloco de dados pode existir; estas consultas devolvem o mesmo status, o que
//! o Windows reporta quando o GUID não tem provedor registrado.

pub const STATUS_WMI_GUID_NOT_FOUND: u32 = 0xC000_0295;

/// IoWMIQuerySingleInstance(DataBlockObject, InstanceName, InOutBufferSize, OutBuffer).
pub fn query_single_instance(_data_block: u64, _instance_name: u64, _buffer_size: u64, _buffer: u64) -> u32 {
    STATUS_WMI_GUID_NOT_FOUND
}

/// IoWMIHandleToInstanceName(DataBlockObject, FileHandle, InstanceName).
pub fn handle_to_instance_name(_data_block: u64, _file_handle: u64, _instance_name: u64) -> u32 {
    STATUS_WMI_GUID_NOT_FOUND
}

const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const NON_PAGED_POOL_NX: u32 = 0x200;
const WMI_TAG: u32 = u32::from_le_bytes(*b"Wmip");
/// WNODE_METHOD_ITEM: o nome da instância começa em 0x44.
const METHOD_ITEM_NAME_OFFSET: u32 = 0x44;
const WNODE_FLAG_METHOD_ITEM: u32 = 0x8000;

/// IoWMIExecuteMethod(DataBlockObject, InstanceName, MethodId,
/// InBufferSize, OutBufferSize*, Buffer) (ntoskrnl 19041 rva 0x930df0):
/// monta o WNODE_METHOD_ITEM (NonPagedPoolNx 'Wmip': nome contado em 0x44,
/// dados alinhados a 8 com o maior dos dois tamanhos) e o entrega ao
/// WmipQuerySetExecuteSI, que referencia o DataBlockObject pelo tipo
/// WmiGuid: sem objeto, o handle 0 do WNODE dá STATUS_INVALID_HANDLE; o
/// OpenNT não cria objetos WmiGuid (o IoWMIOpenBlock acima falha), então
/// qualquer outro objeto dá STATUS_OBJECT_TYPE_MISMATCH. *OutBufferSize só
/// muda num método executado.
pub fn execute_method(data_block: u64, instance_name: u64, method_id: u32, in_size: u32, out_size: u32, buffer: u64) -> u32 {
    use crate::ntos::ex::pool_allocation;
    use crate::ntos::mm::guest_memory as guest;
    let data_size = in_size.max(out_size);
    let name_length = guest::read16(instance_name) as u32;
    let Some(data_offset) = (METHOD_ITEM_NAME_OFFSET + name_length).checked_add(2 + 7).map(|end| end & !7) else { return STATUS_INSUFFICIENT_RESOURCES };
    let Some(total) = data_offset.checked_add(data_size) else { return STATUS_INSUFFICIENT_RESOURCES };
    let wnode = pool_allocation::allocate_tagged(NON_PAGED_POOL_NX, total as u64, WMI_TAG).unwrap_or(0);
    if wnode == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    guest::write_bytes(wnode, &alloc::vec![0u8; total as usize]);
    guest::write32(wnode, total);
    guest::write32(wnode + 0x2C, WNODE_FLAG_METHOD_ITEM);
    guest::write32(wnode + 0x30, METHOD_ITEM_NAME_OFFSET);
    guest::write32(wnode + 0x38, method_id);
    guest::write32(wnode + 0x3C, data_offset);
    guest::write32(wnode + 0x40, in_size);
    guest::write16(wnode + METHOD_ITEM_NAME_OFFSET as u64, name_length as u16);
    if name_length != 0 {
        guest::write_bytes(wnode + METHOD_ITEM_NAME_OFFSET as u64 + 2, &guest::read_bytes(guest::read64(instance_name + 8), name_length as usize));
    }
    if in_size != 0 {
        guest::write_bytes(wnode + data_offset as u64, &guest::read_bytes(buffer, in_size as usize));
    }
    let status = if data_block == 0 { STATUS_INVALID_HANDLE } else { STATUS_OBJECT_TYPE_MISMATCH };
    let _ = pool_allocation::free(wnode, 0);
    status
}
