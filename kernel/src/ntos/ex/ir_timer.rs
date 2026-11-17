//! Os timers IR do Executive (ntoskrnl 19041): a validação dos atributos do
//! NtCreateTimer2 (ExpExTimerAttributesAreValid, rva 0x35a780) e o acesso a
//! um identificador IR (ExpCheckIRTimerAccess, rva 0x7724c8).
//!
//! - Atributos válidos: só os bits 0x8000000E, e o bit 8 sem o 2 nem o 4.
//! - Um identificador IR é `índice | sub << 16`: índice de 1 a 15 e sub até o
//!   máximo do ExpIRTimerDescs (senão STATUS_INVALID_PARAMETER).
//! - De modo usuário, um índice com SID exige o SID na identidade do chamador
//!   (RtlCheckTokenMembership); sem SID, o ExpCheckWakeTimerAccess (acesso 1
//!   no ExpWakeTimerSecurityDescriptor: a DACL dá o bit 1 ao SYSTEM e a dois
//!   SIDs de serviço) e o sub abaixo do máximo (ExCheckValidIRTimerId). Fora
//!   disso, STATUS_ACCESS_DENIED.
//!
//! Sem hardware de wake IR, o timer IR se comporta como um Timer2 comum.

use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::se::model::sid;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

/// Uma entrada do ExpIRTimerDescs: o nome, as subautoridades do SID de
/// serviço (S-1-5-80-...) e o maior sub.
struct IrTimerDescriptor {
    _name: &'static str,
    service: Option<[u32; 5]>,
    maximum: u16,
}

const fn descriptor(name: &'static str, service: Option<[u32; 5]>, maximum: u16) -> IrTimerDescriptor {
    IrTimerDescriptor { _name: name, service, maximum }
}

/// ExpIRTimerDescs (rva 0x5240, 16 entradas).
const DESCRIPTORS: [IrTimerDescriptor; 16] = [
    descriptor("Unknown", None, 1),
    descriptor("TestIdentifier", None, 1),
    descriptor("BrokerInfrastructure", Some([1_988_685_059, 1_921_232_356, 378_231_328, 2_704_142_597, 890_457_928]), 1),
    descriptor("TimeBrokerSvc", Some([410_965_207, 2_550_896_871, 1_717_734_767, 2_321_332_215, 3_755_966_139]), 1),
    descriptor("LfSvc", Some([3_704_025_948, 1_094_794_811, 1_175_534_343, 2_088_422_159, 783_153_058]), 9),
    descriptor("WinLogon", None, 1),
    descriptor("Power", Some([2_343_416_411, 2_961_288_913, 598_565_901, 392_633_850, 2_111_459_193]), 2),
    descriptor("SensorService", Some([869_152_694, 422_618_349, 3_448_047_118, 1_397_179_936, 2_828_741_493]), 1),
    descriptor("NtosPo", None, 6),
    descriptor("Acpi", None, 1),
    descriptor("Button", None, 1),
    descriptor("MsGpioClx", None, 2),
    descriptor("ButtonConverter", None, 1),
    descriptor("MsGpioWin32", None, 2),
    descriptor("KNetPwrDepBroker", None, 2),
    descriptor("Cmbatt", None, 1),
];

/// Os SIDs de serviço que a DACL do ExpWakeTimerSecurityDescriptor lista
/// depois do SYSTEM.
const WAKE_TIMER_SERVICES: [[u32; 5]; 2] = [[3_557_709_225, 3_446_934_100, 2_592_608_561, 3_401_846_376, 4_273_827_271], [3_704_025_948, 1_094_794_811, 1_175_534_343, 2_088_422_159, 783_153_058]];

/// S-1-5-80-a-b-c-d-e.
fn service_sid(parts: &[u32; 5]) -> Vec<u8> {
    sid(5, &[80, parts[0], parts[1], parts[2], parts[3], parts[4]])
}

/// ExpExTimerAttributesAreValid.
pub fn attributes_are_valid(attributes: u32) -> bool {
    let low = attributes & 0xE;
    attributes & 0x8000_000E == attributes && !(low & 8 != 0 && low & !8 != 0)
}

/// RtlCheckTokenMembership(NULL, Sid) da identidade do chamador.
fn caller_is_member(identifier: &[u8]) -> bool {
    let block = guest::alloc_bytes(8 + identifier.len() as u64);
    if block == 0 {
        return false;
    }
    guest::write_bytes(block + 8, identifier);
    let status = crate::ntos::se::token::membership::check(0, block + 8, block).unwrap_or(STATUS_ACCESS_DENIED);
    let member = status & 0x8000_0000 == 0 && guest::read8(block) != 0;
    guest::free_bytes(block);
    member
}

/// ExpCheckIRTimerAccess(Id, UserMode): o NTSTATUS.
pub fn check_user_access(id: u32) -> u32 {
    let (index, sub) = ((id & 0xFFFF) as usize, (id >> 16) as u16);
    if !(1..=15).contains(&index) || sub > DESCRIPTORS[index].maximum {
        return STATUS_INVALID_PARAMETER;
    }
    let allowed = match &DESCRIPTORS[index].service {
        Some(service) => caller_is_member(&service_sid(service)),
        None => {
            let wake_access = caller_is_member(&sid(5, &[18])) || WAKE_TIMER_SERVICES.iter().any(|service| caller_is_member(&service_sid(service)));
            wake_access && sub < DESCRIPTORS[index].maximum
        }
    };
    if allowed { 0 } else { STATUS_ACCESS_DENIED }
}
