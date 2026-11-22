//! WoW64: o suporte do kernel aos programas x86 de 32 bits.
//!
//! No Windows 10 x64, um programa x86 roda pela camada WoW64 da Microsoft
//! (wow64.dll, wow64win.dll e wow64cpu.dll de System32, a ntdll de 32 bits e
//! o resto de SysWOW64). O kernel só dá o suporte, o mesmo do 19041:
//!
//! - o processo (`process`): o EWOW64PROCESS que o PspAllocateProcess cria
//!   para uma imagem IMAGE_FILE_MACHINE_I386 (Machine e NtdllType), o
//!   PsWow64IsMachineSupported e o bloco de parâmetros de 32 bits do
//!   PspWow64ThunkProcessParameters;
//! - a ntdll de 32 bits (`system_dll`): a DLL de sistema do WoW64 x86
//!   (PspSystemDlls[PsWowX86SystemDll], SysWOW64\ntdll.dll) mapeada em cada
//!   processo WoW64, o PsWowX86SharedInformation com as entradas dela e o
//!   LdrSystemDllInitBlock das duas ntdll (PspPrepareSystemDllInitBlock);
//! - a thread (`thread`): a área de CPU no topo da pilha de 64 bits
//!   (PspWow64SetupCpuArea), a pilha de 32 bits (RtlpWow64CreateUserStack)
//!   e o contexto x86 inicial (PspWow64InitThread e
//!   PspWow64InitThreadGuestx86), que o wow64cpu carrega na primeira
//!   entrada no código de 32 bits.
//!
//! A PEB e a TEB de 32 bits (MiInitializeWowPeb e o MmCreateTeb) ficam em
//! `mm/peb_teb.rs`, o limite de VA do processo (MiComputeProcessUserVa) em
//! `mm/process_address_space.rs` e o modo de compatibilidade da CPU (o
//! KGDT64_R3_CMCODE, o descritor da TEB de 32 bits e o FS do SwapContext)
//! em `hal/amd64/usermode.rs`. O código de 32 bits nunca chama o kernel: a
//! camada WoW64 volta ao modo de 64 bits e faz as syscalls normais do x64.

pub mod process;
pub mod system_dll;
pub mod thread;

use crate::ntos::inc::types::{Eprocess, Ewow64process, NtStruct};

/// A TEB de 32 bits fica logo depois da de 64 bits, arredondada à página
/// (TEB.WowTebOffset): ROUND_TO_PAGES(sizeof(TEB)).
pub const TEB32_OFFSET: u64 = 0x2000;
/// IMAGE_FILE_MACHINE_I386, a única máquina WoW64 deste kernel x64.
pub const MACHINE_I386: u16 = 0x14C;
/// WOW64_TLS_CPURESERVED: o slot de TLS da TEB de 64 bits com a área de CPU.
pub const TLS_CPURESERVED: usize = 1;

/// O EWOW64PROCESS do processo (EPROCESS.WoW64Process), ou `None` num
/// processo nativo.
pub fn ewow64(process: u64) -> Option<&'static Ewow64process> {
    if process == 0 {
        return None;
    }
    // SAFETY: o EPROCESS vivo, retido por quem pergunta.
    let wow64 = unsafe { Eprocess::at(process) }.wo_w64_process.get();
    // SAFETY: o EWOW64PROCESS vive enquanto o EPROCESS dono vive.
    (wow64 != 0).then(|| unsafe { Ewow64process::at(wow64) })
}

/// O processo é WoW64 x86 (EWOW64PROCESS.Machine IMAGE_FILE_MACHINE_I386).
pub fn is_x86_process(process: u64) -> bool {
    ewow64(process).is_some_and(|wow64| wow64.machine.get() == MACHINE_I386)
}

/// A PEB de 32 bits do processo (EWOW64PROCESS.Peb), ou 0.
pub fn peb32(process: u64) -> u64 {
    ewow64(process).map_or(0, |wow64| wow64.peb.get())
}

/// O ExGenRandom(1) dos sorteios do WoW64 (a pilha de 32 bits e o RngData do
/// LdrSystemDllInitBlock).
pub fn random() -> u32 {
    crate::hal::cpu::hardware_random_u64().unwrap_or_else(crate::hal::cpu::rdtsc) as u32
}
