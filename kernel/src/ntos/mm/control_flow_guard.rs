//! Control Flow Guard ausente, um estado válido do Windows 10 19041: nenhum
//! processo do OpenNT recebe o bitmap de CFG (o MiCfgInitializeProcess só o
//! mapeia com MitigationFlags.ControlFlowGuardEnabled, que nunca é ligado;
//! o LdrSystemDllInitBlock.CfgBitMap da ntdll fica zero e o
//! LdrControlFlowGuardEnforced responde FALSE). As imagens com CFG ficam com
//! os `_guard_check_icall_nop` do link, e a ProcessControlFlowGuardPolicy
//! consultada responde 0, então o d3d10warp (WarpPlatform::ProtectCodePages)
//! e o user32 não chamam o SetProcessValidCallTargets.
//!
//! Os pedaços de CFG que chegam ao kernel seguem o 19041 nesse estado:
//!
//! - PAGE_TARGETS_INVALID (NtAllocateVirtualMemory) e PAGE_TARGETS_NO_UPDATE
//!   (NtProtectVirtualMemory) são conferidos e saem da proteção
//!   (`ps/user/memory.rs`): sem bitmap não há bits a marcar.
//! - VmCfgCallTargetInformation, a classe 2 do NtSetInformationVirtualMemory
//!   (o SetProcessValidCallTargets e o ...ForMappedView do kernelbase):
//!   [`capture_list`] faz as sondas do serviço (rva 0x6fa41e) sobre o
//!   CFG_CALL_TARGET_LIST_INFORMATION de 0x28 bytes, e [`set_call_targets`]
//!   a seção opcional (SECTION_QUERY), a captura dos CFG_CALL_TARGET_INFO,
//!   as faixas (STATUS_INVALID_PARAMETER_4, exatamente uma) e o
//!   MiCfgMarkValidEntries (0x6fa964). Sem bitmap, a lista é conferida
//!   inteira e o resultado é STATUS_INVALID_PAGE_PROTECTION (o
//!   MiIsProcessCfgEnabled falso), com NumberOfEntriesProcessed 0 gravado.

use alloc::vec::Vec;

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{Eprocess, EprocessMitigationFlagsValues as MitigationFlags, Ethread};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::memory_map as map;
use crate::ntos::mm::prefetch;
use crate::ntos::mm::section::handles::{self as section_handles, Kind};
use crate::ntos::ps::process;
use crate::ntos::ps::user::state;
use crate::rtl::KernelError;

/// VIRTUAL_MEMORY_INFORMATION_CLASS.VmCfgCallTargetInformation.
pub const VM_CFG_CALL_TARGET_INFORMATION: u32 = 2;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_INVALID_PAGE_PROTECTION: u32 = 0xC000_0045;
const STATUS_INVALID_PARAMETER_5: u32 = 0xC000_00F3;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
/// SECTION_QUERY, o acesso que a seção do ...ForMappedView pede.
const SECTION_QUERY: u32 = 0x1;
/// CFG_CALL_TARGET_VALID.
const CFG_CALL_TARGET_VALID: u64 = 0x1;
/// CFG_CALL_TARGET_CONVERT_EXPORT_SUPPRESSED_TO_VALID.
const CFG_CALL_TARGET_CONVERT_EXPORT_SUPPRESSED_TO_VALID: u64 = 0x4;
/// Bits de CFG_CALL_TARGET_INFO.Flags que o MiCfgMarkValidEntries conhece.
const CFG_CALL_TARGET_FLAGS: u64 = 0x7;

/// CFG_CALL_TARGET_LIST_INFORMATION (o VmInformation da classe 2).
#[repr(C)]
pub struct CfgCallTargetListInformation {
    pub number_of_entries: Field<u32>,
    pub reserved: Field<u32>,
    /// PULONG NumberOfEntriesProcessed.
    pub number_of_entries_processed: Field<u64>,
    /// PCFG_CALL_TARGET_INFO CallTargetInfo: {ULONG_PTR Offset, ULONG_PTR
    /// Flags} por alvo.
    pub call_target_info: Field<u64>,
    /// HANDLE Section (SetProcessValidCallTargetsForMappedView).
    pub section: Field<u64>,
    pub file_offset: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for CfgCallTargetListInformation {}

const _: () = assert!(core::mem::size_of::<CfgCallTargetListInformation>() == 0x28);

/// A lista capturada do chamador.
#[derive(Clone, Copy, Debug)]
pub struct CallTargetList {
    pub count: u32,
    pub processed: u64,
    pub targets: u64,
    pub section: u64,
    pub file_offset: u64,
}

impl CallTargetList {
    fn of(information: &CfgCallTargetListInformation) -> Result<Self, KernelError> {
        Ok(Self {
            count: information.number_of_entries.probe_get()?,
            processed: information.number_of_entries_processed.probe_get()?,
            targets: information.call_target_info.probe_get()?,
            section: information.section.probe_get()?,
            file_offset: information.file_offset.probe_get()?,
        })
    }
}

/// As sondas de modo usuário do NtSetInformationVirtualMemory sobre o
/// VmInformation da classe 2: alinhamento 4 (senão
/// STATUS_DATATYPE_MISALIGNMENT) e a faixa de 0x28 bytes na metade de
/// usuário (senão STATUS_ACCESS_VIOLATION); NumberOfEntries zero ou
/// Reserved diferente de zero é STATUS_INVALID_PARAMETER_5; o
/// ProbeForWrite(NumberOfEntriesProcessed, 4, 4) e o vetor de alvos alinhado
/// a 4, inteiro abaixo de MmUserProbeAddress.
pub fn capture_list(information: u64) -> Result<CallTargetList, u32> {
    if information & 3 != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }
    if !state::probe_user_read(information, core::mem::size_of::<CfgCallTargetListInformation>() as u64) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let list = state::user_struct::<CfgCallTargetListInformation>(information).and_then(|information| {
        let reserved = information.reserved.probe_get()?;
        CallTargetList::of(information).map(|list| (list, reserved))
    });
    let (list, reserved) = list.map_err(|error| error.status)?;
    if list.count == 0 || reserved != 0 {
        return Err(STATUS_INVALID_PARAMETER_5);
    }
    if list.processed & 3 != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }
    if !state::probe_user_write(list.processed, 4) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    if list.targets & 3 != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }
    if !list.targets.checked_add(list.count as u64 * 16).is_some_and(|end| end <= map::USER_PROBE_ADDRESS) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(list)
}

/// A mesma lista de um chamador de modo kernel (ZwSetInformationVirtualMemory),
/// sem sondas: NumberOfEntries zero ou Reserved diferente de zero é
/// STATUS_INVALID_PARAMETER_5.
pub fn capture_kernel_list(information: u64) -> Result<CallTargetList, u32> {
    if information == 0 {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    // SAFETY: o CFG_CALL_TARGET_LIST_INFORMATION do chamador de kernel.
    let block = unsafe { CfgCallTargetListInformation::at(information) };
    let list = CallTargetList::of(block).map_err(|error| error.status)?;
    if list.count == 0 || block.reserved.get() != 0 {
        return Err(STATUS_INVALID_PARAMETER_5);
    }
    Ok(list)
}

/// O processo corrente proíbe código dinâmico (MitigationFlags.DisableDynamicCode)
/// e a thread não saiu da proibição (CrossThreadFlags.DisableDynamicCodeOptOut):
/// o serviço passa então ao MiCfgMarkValidEntries a recusa de novos alvos.
fn dynamic_code_blocked() -> bool {
    // SAFETY: o EPROCESS e a ETHREAD correntes, vivos durante o serviço.
    let (eprocess, ethread) = unsafe { (Eprocess::at(process::get_current_process()), Ethread::at(process::get_current_thread())) };
    eprocess.mitigation_flags.get() & MitigationFlags::DISABLE_DYNAMIC_CODE_MASK != 0 && ethread.disable_dynamic_code_opt_out() == 0
}

/// O resto da classe 2 depois do handle do processo (PROCESS_VM_OPERATION):
/// a seção do ...ForMappedView referenciada com SECTION_QUERY no modo do
/// chamador (a falha volta como está), os alvos capturados, as faixas
/// conferidas pelo MiValidateMemoryRangeEntries e exatamente uma faixa
/// (senão STATUS_INVALID_PARAMETER_4, sem tocar NumberOfEntriesProcessed) e
/// o MiCfgMarkValidEntries, cujo contador vai para NumberOfEntriesProcessed
/// qualquer que seja o resultado.
pub fn set_call_targets(_process: u64, ranges: &[(u64, u64)], list: &CallTargetList, mode: u8) -> Result<u32, KernelError> {
    let blocked = dynamic_code_blocked();
    let section = if list.section != 0 {
        match section_handles::reference(list.section, Kind::Section, SECTION_QUERY, mode) {
            Ok(section) => Some(section),
            Err(status) => return Ok(status),
        }
    } else {
        None
    };
    let result = (|| -> Result<u32, KernelError> {
        let captured = guest::try_read_bytes(list.targets, list.count as usize * 16)?;
        let targets: Vec<(u64, u64)> = captured.chunks_exact(16).map(|entry| (u64::from_le_bytes(entry[..8].try_into().unwrap_or([0; 8])), u64::from_le_bytes(entry[8..].try_into().unwrap_or([0; 8])))).collect();
        if !prefetch::valid_user_ranges(ranges) || ranges.len() != 1 {
            return Ok(prefetch::STATUS_INVALID_PARAMETER_4);
        }
        let (status, processed) = mark_valid_entries(ranges[0], &targets, blocked);
        guest::try_write::<u32>(list.processed, processed)?;
        Ok(status)
    })();
    if let Some(section) = section {
        section.release()?;
    }
    result
}

/// MiCfgMarkValidEntries sem bitmap de CFG: a faixa alinhada à página
/// (senão STATUS_INVALID_PARAMETER), os deslocamentos em ordem e dentro da
/// faixa, cada alvo alinhado a 16 com Flags só nos três bits conhecidos; com
/// o código dinâmico proibido, um alvo CFG_CALL_TARGET_VALID é
/// STATUS_ACCESS_DENIED, e a conversão de alvos de export suprimido também
/// (sem supressão de exports). Passada a lista, o processo sem CFG responde
/// STATUS_INVALID_PAGE_PROTECTION. Devolve o status e os alvos processados.
pub fn mark_valid_entries((base, size): (u64, u64), targets: &[(u64, u64)], dynamic_code_blocked: bool) -> (u32, u32) {
    if (base | size) & 0xFFF != 0 {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    if targets.windows(2).any(|pair| pair[0].0 > pair[1].0) || targets.last().is_some_and(|&(offset, _)| offset >= size) {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    for &(offset, flags) in targets {
        if offset & 0xF != 0 || flags & !CFG_CALL_TARGET_FLAGS != 0 {
            return (STATUS_INVALID_PARAMETER, 0);
        }
        if dynamic_code_blocked && flags & CFG_CALL_TARGET_VALID != 0 {
            return (STATUS_ACCESS_DENIED, 0);
        }
        if flags & CFG_CALL_TARGET_CONVERT_EXPORT_SUPPRESSED_TO_VALID != 0 {
            return (STATUS_ACCESS_DENIED, 0);
        }
    }
    (STATUS_INVALID_PAGE_PROTECTION, 0)
}
