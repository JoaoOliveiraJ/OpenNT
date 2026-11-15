//! O que o test-all consulta e ajusta no host.
//!
//! `--cpu-friendly`: o test-all baixa a própria prioridade e tira as CPUs
//! lógicas de número mais baixo da própria afinidade. Os processos que ele
//! cria (o test-boot, o cargo e o rustc, o QEMU) herdam as duas coisas: no
//! Windows, um processo criado sem classe de prioridade explícita herda a
//! BELOW_NORMAL do pai, e a máscara de afinidade sempre passa ao filho.
//! As funções vêm direto do kernel32, sem crate.
//!
//! `available_commit`: o commit livre do sistema, que o test-all confere
//! antes de cada QEMU.

/// O que ficou valendo: as CPUs que o test-all e os filhos podem usar, as
/// que o processo tinha e a máscara nova.
#[cfg_attr(not(windows), allow(dead_code))]
pub struct Applied {
    pub cpus: usize,
    pub total: usize,
    pub mask: usize,
}

#[cfg(windows)]
pub fn cpu_friendly() -> Result<Applied, String> {
    use std::ffi::c_void;
    use std::io::Error;

    const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x4000;
    /// CPUs lógicas deixadas livres.
    const FREE_CPUS: u32 = 4;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn SetPriorityClass(process: *mut c_void, class: u32) -> i32;
        fn GetProcessAffinityMask(process: *mut c_void, process_mask: *mut usize, system_mask: *mut usize) -> i32;
        fn SetProcessAffinityMask(process: *mut c_void, mask: usize) -> i32;
    }

    // SAFETY: o pseudo-handle do processo corrente vale sempre, e as
    // máscaras são saídas em variáveis locais.
    unsafe {
        let process = GetCurrentProcess();
        if SetPriorityClass(process, BELOW_NORMAL_PRIORITY_CLASS) == 0 {
            return Err(format!("SetPriorityClass: {}", Error::last_os_error()));
        }
        let (mut mask, mut system) = (0usize, 0usize);
        if GetProcessAffinityMask(process, &mut mask, &mut system) == 0 {
            return Err(format!("GetProcessAffinityMask: {}", Error::last_os_error()));
        }
        let total = mask.count_ones() as usize;
        // Tira as de número mais baixo (a CPU 0 atende a maior parte das
        // interrupções), deixando pelo menos uma.
        let mut reduced = mask;
        for _ in 0..FREE_CPUS {
            if reduced.count_ones() > 1 {
                reduced &= reduced - 1;
            }
        }
        if SetProcessAffinityMask(process, reduced) == 0 {
            return Err(format!("SetProcessAffinityMask: {}", Error::last_os_error()));
        }
        Ok(Applied { cpus: reduced.count_ones() as usize, total, mask: reduced })
    }
}

#[cfg(not(windows))]
pub fn cpu_friendly() -> Result<Applied, String> {
    Err("--cpu-friendly existe so no host Windows".into())
}

/// Commit que o sistema ainda aceita (o limite de commit menos o que já está
/// comprometido), em bytes: o `ullAvailPageFile` do GlobalMemoryStatusEx.
#[cfg(windows)]
pub fn available_commit() -> Option<u64> {
    /// MEMORYSTATUSEX; só o `avail_page_file` é lido.
    #[allow(dead_code)]
    #[repr(C)]
    struct MemoryStatusEx {
        length: u32,
        memory_load: u32,
        total_phys: u64,
        avail_phys: u64,
        total_page_file: u64,
        avail_page_file: u64,
        total_virtual: u64,
        avail_virtual: u64,
        avail_extended_virtual: u64,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalMemoryStatusEx(buffer: *mut MemoryStatusEx) -> i32;
    }

    let mut status = MemoryStatusEx {
        length: std::mem::size_of::<MemoryStatusEx>() as u32,
        memory_load: 0,
        total_phys: 0,
        avail_phys: 0,
        total_page_file: 0,
        avail_page_file: 0,
        total_virtual: 0,
        avail_virtual: 0,
        avail_extended_virtual: 0,
    };
    // SAFETY: a estrutura é local, com o `dwLength` preenchido.
    let ok = unsafe { GlobalMemoryStatusEx(&mut status) } != 0;
    ok.then_some(status.avail_page_file)
}

/// Fora do Windows o test-all não confere o commit.
#[cfg(not(windows))]
pub fn available_commit() -> Option<u64> {
    None
}
