//! Calor de E/S para armazenamento em camadas (Storage Tiering) —
//! FsRtlHeatInit (0x88cda0), FsRtlHeatUninit (0x88d020) e FsRtlHeatLogIo
//! (0x88cee0) do ntoskrnl 19045.
//!
//! * Init: zera o [`HeatInfo`] do volume (VolumeId, máscara de operações
//!   medidas). `...\Control\TieredStorage\Enabled` com dado zero desliga
//!   (STATUS_UNSUCCESSFUL); `MeasuredOperations & 7` entra na máscara (7
//!   quando ausente). O volume é registrado por GUID numa lista global
//!   (FsRtlTieringHeatData) ordenada por id: um GUID já presente só ganha
//!   referência e devolve o mesmo id; um novo recebe
//!   `(g[10]<<24 | g[15]) ^ (g16[2]<<16 | g16[3]) ^ g32[0]`, somando 1 a cada
//!   colisão. Depois o NT publica WNF_FSRL_TIERED_VOLUME_DETECTED (sem dados).
//! * Uninit: solta a referência do GUID e remove o volume na última.
//! * LogIo: só emite eventos ETW do provedor Microsoft-Windows-Storage-Tiering
//!   (IoHeat) para IRP_MJ_READ, IRP_MJ_WRITE e IRP_MJ_CLEANUP; outro major é
//!   STATUS_INVALID_PARAMETER_2. Nenhuma sessão ETW habilita esse provedor no
//!   OpenNT (os EnableBits nunca ligam), então não há evento a escrever — o
//!   mesmo resultado do NT com o provedor desligado.
//!
//! Os valores de registro passam pelo FsRtlpQueryValueKey do NT: valor
//! ausente ou com DataLength 0 conta como não encontrado; o dword é lido sem
//! conferir o tipo.

use alloc::vec::Vec;

use crate::ntos::cm::registry;
use crate::ntos::ex::wnf::service as wnf_service;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{Guid, IoStackLocation, Irp};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::{KernelError, SpinLock};

/// Estado de calor do volume no FCB/VCB do file system (layout que o NT
/// lê e escreve em FsRtlHeatInit/FsRtlpHeatRegisterVolume, 8 bytes).
#[repr(C)]
pub struct HeatInfo {
    pub volume_id: Field<u32>,
    pub measured_operations: Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for HeatInfo {}

const _: () = {
    assert!(core::mem::size_of::<HeatInfo>() == 0x8);
    assert!(core::mem::offset_of!(HeatInfo, measured_operations) == 0x4);
};

const TIERED_STORAGE: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\TieredStorage";
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
const ALL_OPERATIONS: u32 = 7;
/// WNF_FSRL_TIERED_VOLUME_DETECTED (ntoskrnl .rdata 0x2ed28).
const WNF_FSRL_TIERED_VOLUME_DETECTED: u64 = 0x0D94_1D2B_A3BC_0875;
const IRP_MJ_READ: u8 = 3;
const IRP_MJ_WRITE: u8 = 4;
const IRP_MJ_CLEANUP: u8 = 0x12;

struct HeatVolume {
    guid: [u8; 16],
    id: u32,
    references: u32,
}

/// FsRtlTieringHeatData: volumes em ordem crescente de id.
static VOLUMES: SpinLock<Vec<HeatVolume>> = SpinLock::new(Vec::new());

/// FsRtlpQueryValueKey + leitura do primeiro dword do dado.
fn registry_dword(name: &str) -> Option<u32> {
    let value = registry::read_value_by_path(TIERED_STORAGE, name)?;
    if value.data.is_empty() {
        return None;
    }
    let mut bytes = [0u8; 4];
    for (target, source) in bytes.iter_mut().zip(value.data.iter()) {
        *target = *source;
    }
    Some(u32::from_le_bytes(bytes))
}

fn volume_id(guid: &[u8; 16]) -> u32 {
    let first = u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]);
    let word2 = u16::from_le_bytes([guid[4], guid[5]]) as u32;
    let word3 = u16::from_le_bytes([guid[6], guid[7]]) as u32;
    ((guid[10] as u32) << 24 | guid[15] as u32) ^ (word2 << 16 | word3) ^ first
}

fn guid_bytes(guid: &Guid) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&guest::read_bytes(guid.address(), Guid::SIZE as usize));
    bytes
}

/// FsRtlpHeatRegisterVolume: devolve o id do volume.
fn register_volume(guid: [u8; 16]) -> u32 {
    let mut volumes = VOLUMES.lock();
    if let Some(volume) = volumes.iter_mut().find(|volume| volume.guid == guid) {
        volume.references += 1;
        return volume.id;
    }
    let mut id = volume_id(&guid);
    let mut index = 0;
    while index < volumes.len() {
        let existing = volumes[index].id;
        if existing == id {
            id = id.wrapping_add(1);
            index = if id == 0 { 0 } else { index + 1 };
            continue;
        }
        if existing > id {
            break;
        }
        index += 1;
    }
    volumes.insert(index, HeatVolume { guid, id, references: 1 });
    id
}

/// FsRtlHeatInit(HeatInfo, VolumeGuid, VolumeContext) -> NTSTATUS.
pub fn heat_init(heat_info: &HeatInfo, volume_guid: &Guid) -> Result<u32, KernelError> {
    heat_info.volume_id.set(0);
    heat_info.measured_operations.set(0);
    if registry_dword("Enabled") == Some(0) {
        return Ok(STATUS_UNSUCCESSFUL);
    }
    let measured = registry_dword("MeasuredOperations").map_or(ALL_OPERATIONS, |value| value & ALL_OPERATIONS);
    heat_info.measured_operations.set(heat_info.measured_operations.get() | measured);
    heat_info.volume_id.set(register_volume(guid_bytes(volume_guid)));
    // ZwUpdateWnfStateData(&WNF_FSRL_TIERED_VOLUME_DETECTED, NULL, 0, NULL,
    // NULL, 0, FALSE); o status é ignorado como no NT.
    let cell = guest::alloc_bytes(core::mem::size_of::<u64>() as u64);
    // SAFETY: célula recém-alocada para o nome do estado WNF.
    let state_name = unsafe { Field::<u64>::at(cell) };
    state_name.set(WNF_FSRL_TIERED_VOLUME_DETECTED);
    let _ = wnf_service::update(state_name.address(), 0, 0, 0, 0, 0, false);
    guest::free_bytes(cell);
    Ok(0)
}

/// FsRtlHeatUninit(HeatInfo, VolumeGuid) -> VOID.
pub fn heat_uninit(volume_guid: &Guid) {
    let guid = guid_bytes(volume_guid);
    let mut volumes = VOLUMES.lock();
    if let Some(index) = volumes.iter().position(|volume| volume.guid == guid) {
        volumes[index].references -= 1;
        if volumes[index].references == 0 {
            volumes.remove(index);
        }
    }
}

/// FsRtlHeatLogIo(HeatInfo, Irp, FileContext, Extra) -> NTSTATUS.
pub fn heat_log_io(irp: &Irp) -> u32 {
    // SAFETY: stack location corrente do IRP que o file system está tratando.
    let stack = unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get()) };
    match stack.major_function.get() {
        IRP_MJ_READ | IRP_MJ_WRITE | IRP_MJ_CLEANUP => 0,
        _ => STATUS_INVALID_PARAMETER_2,
    }
}
