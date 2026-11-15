//! A tabela de energia ACPI da HAL (HalAcpiDispatchTable).
//!
//! No NT o acpi.sys chama o HalInitPowerManagement do HalDispatchTable
//! (slot +0x68) com a tabela de rotinas dele (PM_DISPATCH_TABLE com a
//! assinatura 'ACPI', que a HAL guarda em PmAcpiDispatchTable) e recebe a da
//! HAL: assinatura 'HAL ', versão 4 e 21 rotinas, na ordem da
//! HalAcpiDispatchTable da `.rdata` do ntoskrnl 19041 (HaliInitPowerManagement):
//!
//! | # | rotina | uso no acpi.sys |
//! | --- | --- | --- |
//! | 0 | corpo vazio (`ret 0`) | ACPIInterruptServiceRoutine |
//! | 1 | HaliAcpiMachineStateInit | NotifyHalWithMachineStatesAndRetrieveInterruptModel |
//! | 2 | devolve 1 | — |
//! | 3 | HalpInterruptIsPicStateIntact | LinkNodeRestoreHardwareState |
//! | 4 | HalpInterruptRestoreAllControllerState | idem |
//! | 5, 6 | HaliPciInterfaceRead/WriteConfig | regiões PCI_Config da AML |
//! | 7 | HalpInterruptGetApicVersion | IcAddApicInstance |
//! | 8 | HaliSetMaxLegacyPciBusNumber | GetPciAddressWorker |
//! | 9 | HalpInterruptIsGsiValid | — |
//! | 10 | HalAcpiGetTableDispatch | RSDT/XSDT, DSDT, SSDTs |
//! | 11 | HalAcpiGetRsdpDispatch | — |
//! | 12 | HalAcpiGetFacsMappingDispatch | ACPILoadProcessFACS |
//! | 13 | HalAcpiGetAllTablesDispatch | ACPILoadProcessRSDT |
//! | 14-16 | HalpAcpiPmRegisterAvailable/Read/Write | PM1, GPE |
//! | 17 | HalpAcpiAccessSecureAddress | — |
//! | 18-20 | HalpPciReadIoConfigUlong/Uchar/Ushort | — |
//!
//! As tabelas vêm do cache da HAL (`acpi_native`, o HalpAcpiGetTable): cópias
//! em pool, menos a FACS, que é mapeada (o firmware e o SO dividem o
//! GlobalLock dela). Os registradores de PM saem da FADT como no
//! HalpAcpiInitializePmRegisters: PM1a_EVT (id 0), PM1a_CNT (1), PM_TMR (2),
//! PM1b_EVT (3), PM1b_CNT (4), PM2_CNT (5), GPE0 (6), GPE1 (7) e o RESET_REG
//! (8); numa FADT de revisão menor que 5 vale o bloco de 32 bits com o
//! tamanho em bytes (o HalpAcpiSetupPmRegisterLegacy), noutra o GAS X_.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::hal::amd64::routine_stubs::{self, Routine};
use crate::hal::{acpi, acpi_native, interrupt_lines, pci_native, physical, port};
use crate::ntos::inc::types::{Field, NtStruct};
use crate::ntos::init::exports::Call;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::{KernelError, SpinLock};

/// 'HAL ' e a versão da HalAcpiDispatchTable do ntoskrnl 19041.
const SIGNATURE: u32 = 0x2048_414C;
const VERSION: u32 = 4;
pub const FUNCTIONS: usize = 21;

/// PM_DISPATCH_TABLE: assinatura, versão e as rotinas.
#[repr(C)]
struct PmDispatchTable {
    signature: Field<u32>,
    version: Field<u32>,
    function: [Field<u64>; FUNCTIONS],
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for PmDispatchTable {}

const _: () = assert!(core::mem::size_of::<PmDispatchTable>() == 8 + 8 * FUNCTIONS);

/// As rotinas por ponteiro, na ordem dos slots da tabela.
pub const ROUTINES: &[Routine] = &[
    Routine { name: "HalAcpiDispatchVoid", handler: dispatch_void },
    Routine { name: "HaliAcpiMachineStateInit", handler: machine_state_init_routine },
    Routine { name: "HalAcpiDispatchTrue", handler: dispatch_true },
    Routine { name: "HalpInterruptIsPicStateIntact", handler: is_pic_state_intact },
    Routine { name: "HalpInterruptRestoreAllControllerState", handler: restore_all_controller_state },
    Routine { name: "HaliPciInterfaceReadConfig", handler: pci_interface_read_config },
    Routine { name: "HaliPciInterfaceWriteConfig", handler: pci_interface_write_config },
    Routine { name: "HalpInterruptGetApicVersion", handler: get_apic_version },
    Routine { name: "HaliSetMaxLegacyPciBusNumber", handler: set_max_legacy_pci_bus_number },
    Routine { name: "HalpInterruptIsGsiValid", handler: is_gsi_valid },
    Routine { name: "HalAcpiGetTableDispatch", handler: get_table },
    Routine { name: "HalAcpiGetRsdpDispatch", handler: get_rsdp },
    Routine { name: "HalAcpiGetFacsMappingDispatch", handler: get_facs_mapping },
    Routine { name: "HalAcpiGetAllTablesDispatch", handler: get_all_tables },
    Routine { name: "HalpAcpiPmRegisterAvailable", handler: pm_register_available },
    Routine { name: "HalpAcpiPmRegisterRead", handler: pm_register_read },
    Routine { name: "HalpAcpiPmRegisterWrite", handler: pm_register_write },
    Routine { name: "HalpAcpiAccessSecureAddress", handler: access_secure_address },
    Routine { name: "HalpPciReadIoConfigUlong", handler: read_io_config_ulong },
    Routine { name: "HalpPciReadIoConfigUchar", handler: read_io_config_uchar },
    Routine { name: "HalpPciReadIoConfigUshort", handler: read_io_config_ushort },
    Routine { name: "HaliInitPowerManagement", handler: init_power_management },
];

const _: () = assert!(ROUTINES.len() == FUNCTIONS + 1);

/// A tabela publicada (pool do kernel; 0 antes do primeiro HalInitPowerManagement).
static TABLE: AtomicU64 = AtomicU64::new(0);
/// PmAcpiDispatchTable: a tabela que o acpi.sys entregou.
static ACPI_TABLE: AtomicU64 = AtomicU64::new(0);
/// HalpInterruptPicStateIntact: falso no boot, verdadeiro depois do
/// HalpInterruptRestoreAllControllerState.
static PIC_STATE_INTACT: AtomicBool = AtomicBool::new(false);
/// HalpMaxPciBus.
static MAX_PCI_BUS: AtomicU32 = AtomicU32::new(0);
/// HalpWakeupState (o HaliAcpiMachineStateInit grava 1).
static WAKEUP_STATE: AtomicU32 = AtomicU32::new(0);
/// HalpAcpiTablePointers: a lista do HalAcpiGetAllTablesDispatch, montada uma vez.
static ALL_TABLES: AtomicU64 = AtomicU64::new(0);
/// HalpAcpiFacsMapping.
static FACS_MAPPING: AtomicU64 = AtomicU64::new(0);

/// Endereço nativo de uma rotina desta tabela.
fn routine(name: &str) -> Result<u64, KernelError> {
    routine_stubs::address(name)
}

/// O corpo do slot +0x68 do HalDispatchTable.
pub fn init_power_management_address() -> Result<u64, KernelError> {
    routine("HaliInitPowerManagement")
}

/// A HalAcpiDispatchTable (montada na primeira vez).
fn table() -> Result<u64, KernelError> {
    let current = TABLE.load(Ordering::Acquire);
    if current != 0 {
        return Ok(current);
    }
    let address = guest::alloc_bytes(core::mem::size_of::<PmDispatchTable>() as u64);
    if address == 0 {
        return Err(KernelError::new("HalAcpiDispatchTable: sem pool"));
    }
    // SAFETY: bloco recém-alocado do tamanho da tabela.
    let dispatch = unsafe { PmDispatchTable::at(address) };
    dispatch.signature.set(SIGNATURE);
    dispatch.version.set(VERSION);
    for (slot, entry) in ROUTINES.iter().take(FUNCTIONS).enumerate() {
        dispatch.function[slot].set(routine(entry.name)?);
    }
    match TABLE.compare_exchange(0, address, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Ok(address),
        Err(existing) => {
            guest::free_bytes(address);
            Ok(existing)
        }
    }
}

/// HaliInitPowerManagement(PmDriverDispatchTable, *PmHalDispatchTable):
/// guarda a tabela do acpi.sys e devolve a da HAL.
pub fn initialize_power_management(driver_table: u64, hal_table_out: u64) -> Result<i32, KernelError> {
    let table = table()?;
    // SAFETY: parâmetro de saída do chamador.
    unsafe { Field::<u64>::at(hal_table_out) }.set(table);
    ACPI_TABLE.store(driver_table, Ordering::Release);
    debug_print!("[hal] HalInitPowerManagement: tabela do driver {:#x}, HalAcpiDispatchTable {:#x}", driver_table, table);
    Ok(0)
}

/// PmAcpiDispatchTable (0 antes do HalInitPowerManagement).
pub fn acpi_driver_table() -> u64 {
    ACPI_TABLE.load(Ordering::Acquire)
}

/// HalpInterruptModel: o valor do _PIC. A HAL x64 não tem modo 8259 puro:
/// sem controlador registrado, ou com IOAPIC, o modelo é APIC (1).
pub fn interrupt_model() -> u32 {
    1
}

/// HaliAcpiMachineStateInit(SleepValues, *InterruptModel): o estado de
/// despertar e o modelo de interrupção para o _PIC. Os tratadores de S1-S4
/// (HaliAcpiSleep pelo ZwPowerInformation(SystemPowerStateHandler)) não são
/// registrados: o Po do OpenNT não suspende o sistema.
pub fn machine_state_init(_sleep_values: u64, interrupt_model_out: u64) {
    WAKEUP_STATE.store(1, Ordering::SeqCst);
    if interrupt_model_out != 0 {
        // SAFETY: parâmetro de saída do acpi.sys.
        unsafe { Field::<u32>::at(interrupt_model_out) }.set(interrupt_model());
    }
}

// ---- tabelas ---------------------------------------------------------------

/// HalAcpiGetTableDispatch(Signature, OemId, OemTableId): a cópia em cache.
pub fn get_table_copy(signature: u32, oem_id: u64, oem_table_id: u64) -> u64 {
    acpi_native::get_cached_table(signature, oem_id, oem_table_id)
}

/// HalpAcpiGetFacsMapping: o FIRMWARE_CTRL de 32 bits da FADT (+0x24)
/// mapeado (o mapa direto), conferida a assinatura 'FACS'.
pub fn facs_mapping() -> u64 {
    let current = FACS_MAPPING.load(Ordering::Acquire);
    if current != 0 {
        return current;
    }
    let Some(fadt) = acpi::get_table("FACP", 0, false) else { return 0 };
    if fadt.bytes.len() < 0x28 {
        return 0;
    }
    let physical_address = u32::from_le_bytes(fadt.bytes[0x24..0x28].try_into().unwrap()) as u64;
    if physical_address == 0 || physical_address + 0x40 > crate::ntos::mm::memory_map::PHYSICAL_MEMORY_LIMIT || physical::read32(physical_address) != u32::from_le_bytes(*b"FACS") {
        return 0;
    }
    let mapping = physical::to_virtual(physical_address);
    FACS_MAPPING.store(mapping, Ordering::Release);
    mapping
}

/// HalpAcpiGetAllTablesWork: as tabelas da RSDT/XSDT em cache, menos DSDT,
/// RSDT, XSDT e FACS, numa lista { ULONG Count; PVOID Table[Count] } (o
/// vetor começa em +8) montada uma vez.
pub fn all_tables() -> u64 {
    let current = ALL_TABLES.load(Ordering::Acquire);
    if current != 0 {
        return current;
    }
    let excluded = ["DSDT", "RSDT", "XSDT", "FACS"];
    let mut pointers = Vec::new();
    for table in acpi::enumerate().iter().filter(|table| !excluded.contains(&table.signature.as_str())) {
        let signature = u32::from_le_bytes(table.signature.as_bytes().try_into().unwrap_or([0; 4]));
        let instance = acpi::enumerate().iter().take_while(|other| other.address != table.address).filter(|other| other.signature == table.signature).count();
        let copy = acpi_native::cached_instance(signature, instance);
        if copy != 0 {
            pointers.push(copy);
        }
    }
    let list = guest::alloc_bytes(8 + 8 * pointers.len() as u64);
    if list == 0 {
        return 0;
    }
    guest::write32(list, pointers.len() as u32);
    for (index, pointer) in pointers.iter().enumerate() {
        guest::write64(list + 8 + 8 * index as u64, *pointer);
    }
    match ALL_TABLES.compare_exchange(0, list, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => list,
        Err(existing) => {
            guest::free_bytes(list);
            existing
        }
    }
}

// ---- registradores de PM ---------------------------------------------------

/// Um registro de PmRegisters: a porta (só espaço de I/O nesta máquina),
/// o tamanho do acesso que o chamador faz e a largura do registrador.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PmRegister {
    pub present: bool,
    pub port: u16,
    /// Tamanho do acesso (o 5º argumento do HalpAcpiSetupPmRegisterLegacy).
    pub size: u32,
    /// Largura do registrador em bytes (RegisterBitWidth / 8).
    pub width: u32,
}

/// Ids dos registradores (índices de PmRegisters).
pub mod register {
    pub const PM1A_EVT: usize = 0;
    pub const PM1A_CNT: usize = 1;
    pub const PM_TMR: usize = 2;
    pub const PM1B_EVT: usize = 3;
    pub const PM1B_CNT: usize = 4;
    pub const PM2_CNT: usize = 5;
    pub const GPE0: usize = 6;
    pub const GPE1: usize = 7;
    pub const RESET: usize = 8;
    pub const COUNT: usize = 9;
}

static PM_REGISTERS: SpinLock<Option<[PmRegister; register::COUNT]>> = SpinLock::new(None);

/// HalpAcpiSetupPmRegister com o GAS (SpaceId, BitWidth, AccessSize,
/// Address): AccessSize 0/1 = 1 byte, 2 = 2, 3 = 4, 4 = 8; a largura é o
/// BitWidth/8 (ou o AccessSize sem BitWidth) e precisa cobrir o acesso.
fn setup(space: u8, bit_width: u8, access_size: u8, address: u64, size: u32) -> PmRegister {
    let access = match access_size {
        0 | 1 => 1,
        2 => 2,
        3 => 4,
        4 => 8,
        _ => return PmRegister::default(),
    };
    let width = if bit_width != 0 { (bit_width >> 3) as u32 } else { access };
    // Espaço de I/O (1) com endereço; memória fica fora nesta máquina.
    if access < size || address == 0 || space != 1 || address > 0xFFFF {
        return PmRegister::default();
    }
    PmRegister { present: true, port: address as u16, size, width }
}

/// HalpAcpiSetupPmRegisterLegacy: revisão < 5 usa o bloco de 32 bits
/// (`block`) com o tamanho em bytes (`length`): GAS de I/O com BitWidth =
/// length * 8 e o AccessSize do tamanho; revisão >= 5, o GAS X_ em `gas`.
fn setup_legacy(fadt: &[u8], block: usize, length: usize, gas: usize, size: u32) -> PmRegister {
    let read32 = |offset: usize| fadt.get(offset..offset + 4).map_or(0, |bytes| u32::from_le_bytes(bytes.try_into().unwrap()));
    let revision = fadt.get(8).copied().unwrap_or(0);
    if revision < 5 {
        let address = read32(block);
        let bytes = fadt.get(length).copied().unwrap_or(0);
        if address == 0 {
            return PmRegister::default();
        }
        let access_size = match bytes {
            1 => 1,
            2 => 2,
            4 => 3,
            8 => 4,
            _ => 0,
        };
        let bit_width = if (bytes as u32) * 8 > 0xFF { 0 } else { bytes * 8 };
        return setup(1, bit_width, access_size, address as u64, size);
    }
    let Some(entry) = fadt.get(gas..gas + 12) else { return PmRegister::default() };
    setup(entry[0], entry[1], entry[3], u64::from_le_bytes(entry[4..12].try_into().unwrap()), size)
}

/// HalpAcpiInitializePmRegisters sobre a FADT.
fn pm_registers() -> [PmRegister; register::COUNT] {
    let mut cached = PM_REGISTERS.lock();
    if let Some(registers) = *cached {
        return registers;
    }
    let mut registers = [PmRegister::default(); register::COUNT];
    if let Some(fadt) = acpi::get_table("FACP", 0, false) {
        let bytes = &fadt.bytes;
        registers[register::PM1A_EVT] = setup_legacy(bytes, 0x38, 0x58, 0x94, 2);
        registers[register::PM1A_CNT] = setup_legacy(bytes, 0x40, 0x59, 0xAC, 2);
        registers[register::PM_TMR] = setup_legacy(bytes, 0x4C, 0x5B, 0xD0, 4);
        registers[register::PM1B_EVT] = setup_legacy(bytes, 0x3C, 0x58, 0xA0, 2);
        registers[register::PM1B_CNT] = setup_legacy(bytes, 0x44, 0x59, 0xB8, 2);
        registers[register::PM2_CNT] = setup_legacy(bytes, 0x48, 0x5A, 0xC4, 1);
        // RESET_REG (+0x74) só com FADT de revisão > 1 e RESET_REG_SUP (bit 10).
        let flags = bytes.get(0x70..0x74).map_or(0, |flags| u32::from_le_bytes(flags.try_into().unwrap()));
        if bytes.get(8).copied().unwrap_or(0) > 1 && flags & 0x400 != 0 {
            if let Some(entry) = bytes.get(0x74..0x80) {
                registers[register::RESET] = setup(entry[0], entry[1], entry[3], u64::from_le_bytes(entry[4..12].try_into().unwrap()), 1);
            }
        }
        registers[register::GPE0] = setup_legacy(bytes, 0x50, 0x5C, 0xDC, 1);
        registers[register::GPE1] = setup_legacy(bytes, 0x54, 0x5D, 0xE8, 1);
    }
    *cached = Some(registers);
    registers
}

/// O registro `id` (None fora da tabela).
pub fn pm_register(id: usize) -> Option<PmRegister> {
    pm_registers().get(id).copied()
}

/// HalpAcpiPmRegisterAvailable: 0 ou STATUS_NOT_SUPPORTED.
pub fn register_available(id: u32) -> i32 {
    match pm_register(id as usize) {
        Some(register) if register.present => 0,
        _ => 0xC000_00BB_u32 as i32,
    }
}

/// Leitura de porta da largura do acesso (HalpAcpiPmRegisterReadPort).
fn read_port(port_number: u16, size: u32, buffer: u64) {
    match size {
        1 => guest::write8(buffer, port::read8(port_number)),
        2 => guest::write16(buffer, port::read16(port_number)),
        _ => guest::write32(buffer, port::read32(port_number)),
    }
}

fn write_port(port_number: u16, size: u32, buffer: u64) {
    match size {
        1 => port::write8(port_number, guest::read8(buffer)),
        2 => port::write16(port_number, guest::read16(buffer)),
        _ => port::write32(port_number, guest::read32(buffer)),
    }
}

/// HalpAcpiPmRegisterRead/Write(Id, Offset, Buffer, BufferSize, *Bytes):
/// BufferSize menor que o acesso = STATUS_BUFFER_TOO_SMALL; senão o acesso
/// na porta base + Offset, com o tamanho em *Bytes.
pub fn register_access(id: u32, offset: u32, buffer: u64, buffer_size: u32, bytes_out: u64, write: bool) -> i32 {
    let Some(register) = pm_register(id as usize) else { return 0xC000_000D_u32 as i32 };
    if register.size > buffer_size {
        return 0xC000_0023_u32 as i32;
    }
    let port_number = register.port.wrapping_add(offset as u16);
    if write {
        write_port(port_number, register.size, buffer);
    } else {
        read_port(port_number, register.size, buffer);
    }
    if bytes_out != 0 {
        guest::write32(bytes_out, register.size);
    }
    0
}

// ---- PCI -------------------------------------------------------------------

/// HaliSetMaxLegacyPciBusNumber.
pub fn set_max_pci_bus(bus: u32) {
    MAX_PCI_BUS.fetch_max(bus, Ordering::SeqCst);
}

pub fn max_pci_bus() -> u32 {
    MAX_PCI_BUS.load(Ordering::SeqCst)
}

/// HaliPciInterfaceRead/WriteConfig(Context, BusNumber, Slot, Buffer,
/// Offset, Length): o segmento é BusNumber >> 8; devolve Length. Uma
/// leitura de VendorID válido num barramento acima do maior conhecido o
/// atualiza (HalpMaxPciBus).
pub fn pci_interface_config(bus_number: u32, slot: u32, buffer: u64, offset: u32, length: u32, write: bool) -> Result<u32, KernelError> {
    let (segment, bus) = (bus_number >> 8, bus_number & 0xFF);
    if segment == 0 {
        if write {
            pci_native::set_bus_data_by_offset(4, bus, slot, buffer, offset, length)?;
        } else {
            pci_native::get_bus_data_by_offset(4, bus, slot, buffer, offset, length)?;
        }
    } else if !write {
        guest::write_bytes(buffer, &alloc::vec![0xFF; length as usize]);
    }
    if !write && length >= 2 && guest::read16(buffer) != 0xFFFF {
        set_max_pci_bus(bus);
    }
    Ok(length)
}

/// HalpPciReadIoConfig{Uchar,Ushort,Ulong}(PCI_TYPE1_CFG_BITS*, Buffer,
/// Offset): grava os bits de registrador no endereço do chamador, latch em
/// 0xCF8 e lê 0xCFC + (Offset & 3); devolve a largura. O chamador segura o
/// lock do espaço de configuração.
pub fn read_io_config(bits: u64, buffer: u64, offset: u32, width: u32) -> u32 {
    // SAFETY: o PCI_TYPE1_CFG_BITS do chamador.
    let address = unsafe { Field::<u32>::at(bits) };
    let value = address.get();
    address.set(value ^ ((value ^ offset) & 0xFC));
    port::write32(0xCF8, address.get());
    let data = 0xCFC + (offset & 3) as u16;
    match width {
        1 => guest::write8(buffer, port::read8(data)),
        2 => guest::write16(buffer, port::read16(data)),
        _ => guest::write32(buffer, port::read32(data)),
    }
    width
}

// ---- adaptadores das rotinas por ponteiro ---------------------------------

fn dispatch_void(_: &Call) -> Result<u64, KernelError> {
    Ok(0)
}

fn dispatch_true(_: &Call) -> Result<u64, KernelError> {
    Ok(1)
}

fn machine_state_init_routine(call: &Call) -> Result<u64, KernelError> {
    machine_state_init(call.arg(1), call.arg(2));
    Ok(0)
}

fn is_pic_state_intact(_: &Call) -> Result<u64, KernelError> {
    Ok(PIC_STATE_INTACT.load(Ordering::SeqCst) as u64)
}

/// HalpInterruptRestoreAllControllerState: restaura cada controlador
/// registrado (nada mudou, o sistema não suspende) e marca o estado intacto.
fn restore_all_controller_state(_: &Call) -> Result<u64, KernelError> {
    PIC_STATE_INTACT.store(true, Ordering::SeqCst);
    Ok(0)
}

fn pci_interface_read_config(call: &Call) -> Result<u64, KernelError> {
    Ok(pci_interface_config(call.arg(2) as u32, call.arg(3) as u32, call.arg(4), call.arg(5) as u32, call.arg(6) as u32, false)? as u64)
}

fn pci_interface_write_config(call: &Call) -> Result<u64, KernelError> {
    Ok(pci_interface_config(call.arg(2) as u32, call.arg(3) as u32, call.arg(4), call.arg(5) as u32, call.arg(6) as u32, true)? as u64)
}

fn get_apic_version(call: &Call) -> Result<u64, KernelError> {
    Ok(interrupt_lines::apic_version(call.arg(1) as u32) as u64)
}

fn set_max_legacy_pci_bus_number(call: &Call) -> Result<u64, KernelError> {
    set_max_pci_bus(call.arg(1) as u32);
    Ok(0)
}

fn is_gsi_valid(call: &Call) -> Result<u64, KernelError> {
    Ok(interrupt_lines::is_gsi_valid(call.arg(1) as u32) as u64)
}

fn get_table(call: &Call) -> Result<u64, KernelError> {
    Ok(get_table_copy(call.arg(1) as u32, call.arg(2), call.arg(3)))
}

/// HalAcpiGetRsdpDispatch: o endereço físico do RSDP.
fn get_rsdp(_: &Call) -> Result<u64, KernelError> {
    Ok(acpi::rsdp_address())
}

fn get_facs_mapping(_: &Call) -> Result<u64, KernelError> {
    Ok(facs_mapping())
}

fn get_all_tables(_: &Call) -> Result<u64, KernelError> {
    Ok(all_tables())
}

fn pm_register_available(call: &Call) -> Result<u64, KernelError> {
    Ok(register_available(call.arg(1) as u32) as u32 as u64)
}

fn pm_register_read(call: &Call) -> Result<u64, KernelError> {
    Ok(register_access(call.arg(1) as u32, call.arg(2) as u32, call.arg(3), call.arg(4) as u32, call.arg(5), false) as u32 as u64)
}

fn pm_register_write(call: &Call) -> Result<u64, KernelError> {
    Ok(register_access(call.arg(1) as u32, call.arg(2) as u32, call.arg(3), call.arg(4) as u32, call.arg(5), true) as u32 as u64)
}

/// HalpAcpiAccessSecureAddress: zera *Bytes e, sem dispositivo PCI seguro
/// (HalpPciHandleSecureAccess), devolve STATUS_INVALID_ADDRESS.
fn access_secure_address(call: &Call) -> Result<u64, KernelError> {
    if call.arg(5) != 0 {
        guest::write32(call.arg(5), 0);
    }
    Ok(0xC000_0141)
}

fn read_io_config_ulong(call: &Call) -> Result<u64, KernelError> {
    Ok(read_io_config(call.arg(1), call.arg(2), call.arg(3) as u32, 4) as u64)
}

fn read_io_config_uchar(call: &Call) -> Result<u64, KernelError> {
    Ok(read_io_config(call.arg(1), call.arg(2), call.arg(3) as u32, 1) as u64)
}

fn read_io_config_ushort(call: &Call) -> Result<u64, KernelError> {
    Ok(read_io_config(call.arg(1), call.arg(2), call.arg(3) as u32, 2) as u64)
}

fn init_power_management(call: &Call) -> Result<u64, KernelError> {
    Ok(initialize_power_management(call.arg(1), call.arg(2))? as u32 as u64)
}

/// Estado para os autotestes.
pub fn wakeup_state() -> u32 {
    WAKEUP_STATE.load(Ordering::SeqCst)
}
