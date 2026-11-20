//! O desligamento do Memory Manager (MmShutdownSystem).
//!
//! Como no ntoskrnl 19041 (MmShutdownSystem rva 0x9b02c0):
//! - fase 0, o MiShutdownSystem (rva 0x9afef8), antes do IoShutdownSystem(1)
//!   fechar os file systems: o CcNotifyWriteBehind e o
//!   MiFlushAllFilesystemPages (rva 0x535508), que grava as páginas
//!   alteradas de toda seção de dados de arquivo com vista
//!   (`ps/user/sections::flush_all_file_sections`); depois o
//!   MiZeroAllPageFiles (só com ZeroPagingFile), os enclaves de hardware e o
//!   MiDeletePagingFiles. O OpenNT não tem enclaves nem a política
//!   ZeroPagingFile;
//! - fase 1 (só na hibernação) e fase 2: nada que o OpenNT tenha.

/// MmShutdownSystem(Phase).
pub fn shutdown_system(phase: u32) {
    if phase == 0 {
        let (flushed, failed) = crate::ntos::ps::user::sections::flush_all_file_sections();
        debug_print!("[mm] desligamento: {} secoes de arquivo descarregadas ({} falhas)", flushed, failed);
    }
}
