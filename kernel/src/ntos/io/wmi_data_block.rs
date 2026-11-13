//! Consultas WMI por bloco de dados (IoWMIQuerySingleInstance,
//! IoWMIHandleToInstanceName).
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
