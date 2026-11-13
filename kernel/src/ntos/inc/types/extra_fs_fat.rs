//! Layouts do suporte a file systems (FAT/CDFS/fltmgr) ausentes dos símbolos
//! do 19041 e de `wdk.rs`.
//!
//! Mesmo estilo de `wdk.rs`: `#[repr(C)]`, folhas `Field<T>`, layout x64 e
//! asserções de tamanho e de offsets. Cada estrutura cita o cabeçalho público
//! (ntifs.h, mountmgr.h, mountdev.h) ou, para as privadas do kernel, o
//! layout conferido na desmontagem do ntoskrnl 10.0.19045.
//!
//! SHARE_ACCESS, _IOP_IRP_EXTENSION e BASE_MCB são os de `extra_fs_ntfs`;
//! FILE_LOCK, FILE_LOCK_INFO, FSRTL_ADVANCED_FCB_HEADER e
//! FSRTL_PER_STREAM_CONTEXT os de `extra_fsrtl` (não duplicados aqui).

use super::*;

/// `IO_PRIORITY_INFO` (ntifs.h; 0x10 bytes; IoPriority é um IO_PRIORITY_HINT).
#[repr(C)]
pub struct IoPriorityInfo {
    pub size: Field<u32>,
    pub thread_priority: Field<u32>,
    pub page_priority: Field<u32>,
    pub io_priority: Field<u32>,
}

unsafe impl NtStruct for IoPriorityInfo {}

const _: () = {
    assert!(core::mem::size_of::<IoPriorityInfo>() == 0x10);
    assert!(core::mem::offset_of!(IoPriorityInfo, io_priority) == 0xC);
};

/// `MOUNTMGR_MOUNT_POINT` (mountmgr.h; 0x18 bytes).
#[repr(C)]
pub struct MountmgrMountPoint {
    pub symbolic_link_name_offset: Field<u32>,
    pub symbolic_link_name_length: Field<u16>,
    pub reserved1: Field<u16>,
    pub unique_id_offset: Field<u32>,
    pub unique_id_length: Field<u16>,
    pub reserved2: Field<u16>,
    pub device_name_offset: Field<u32>,
    pub device_name_length: Field<u16>,
    pub reserved3: Field<u16>,
}

unsafe impl NtStruct for MountmgrMountPoint {}

const _: () = {
    assert!(core::mem::size_of::<MountmgrMountPoint>() == 0x18);
    assert!(core::mem::offset_of!(MountmgrMountPoint, unique_id_offset) == 0x8);
    assert!(core::mem::offset_of!(MountmgrMountPoint, device_name_offset) == 0x10);
    assert!(core::mem::offset_of!(MountmgrMountPoint, device_name_length) == 0x14);
};

/// `MOUNTMGR_MOUNT_POINTS` (mountmgr.h; cabeçalho de 8 bytes e o vetor; 0x20
/// com o primeiro elemento).
#[repr(C)]
pub struct MountmgrMountPoints {
    pub size: Field<u32>,
    pub number_of_mount_points: Field<u32>,
    pub mount_points: [MountmgrMountPoint; 1],
}

unsafe impl NtStruct for MountmgrMountPoints {}

const _: () = {
    assert!(core::mem::size_of::<MountmgrMountPoints>() == 0x20);
    assert!(core::mem::offset_of!(MountmgrMountPoints, mount_points) == 0x8);
};

/// `MOUNTDEV_NAME` (mountdev.h; USHORT NameLength e o nome a seguir).
#[repr(C)]
pub struct MountdevName {
    pub name_length: Field<u16>,
    pub name: [Field<u16>; 1],
}

unsafe impl NtStruct for MountdevName {}

const _: () = {
    assert!(core::mem::size_of::<MountdevName>() == 0x4);
    assert!(core::mem::offset_of!(MountdevName, name) == 0x2);
};

/// `_KERNEL_STACK_SEGMENT` (ntkrnlmp.pdb; 0x20 bytes).
#[repr(C)]
pub struct KernelStackSegment {
    pub stack_base: Field<u64>,
    pub stack_limit: Field<u64>,
    pub kernel_stack: Field<u64>,
    pub initial_stack: Field<u64>,
}

unsafe impl NtStruct for KernelStackSegment {}

/// `_KERNEL_STACK_CONTROL` no InitialStack de uma thread (privada do Ke; o
/// IoWithinStackLimits do 19041 lê Previous em +0x10: StackBase +0x10,
/// StackLimit +0x18, InitialStack +0x28; 0x30 bytes).
#[repr(C)]
pub struct KernelStackControl {
    pub current_stack_base: Field<u64>,
    pub actual_limit: Field<u64>,
    pub previous: KernelStackSegment,
}

unsafe impl NtStruct for KernelStackControl {}

const _: () = {
    assert!(core::mem::size_of::<KernelStackSegment>() == 0x20);
    assert!(core::mem::size_of::<KernelStackControl>() == 0x30);
    assert!(core::mem::offset_of!(KernelStackControl, previous) == 0x10);
};

/// `LARGE_MCB` (ntifs.h; 0x20 bytes). O `BASE_MCB` é o do lote fs-ntfs
/// (`extra_fs_ntfs::BaseMcb`, o mesmo que `fsrtl::mcb` usa).
#[repr(C)]
pub struct LargeMcb {
    /// -> `KGUARDED_MUTEX` (o 19041 usa uma FAST_MUTEX do lookaside)
    pub guarded_mutex: Field<u64>,
    pub base_mcb: super::extra_fs_ntfs::BaseMcb,
}

unsafe impl NtStruct for LargeMcb {}

const _: () = {
    assert!(core::mem::size_of::<LargeMcb>() == 0x20);
    assert!(core::mem::offset_of!(LargeMcb, base_mcb) == 0x8);
};

/// `TUNNEL` (ntifs.h; 0x58 bytes). Também é o tipo que o grupo fsrtl-tunnel
/// do lote fs-ntfs usa (o motor `fsrtl::tunnel` é compartilhado).
#[repr(C)]
pub struct Tunnel {
    pub mutex: FastMutex,
    /// -> `RTL_SPLAY_LINKS`
    pub cache: Field<u64>,
    pub timer_queue: ListEntry,
    pub num_entries: Field<u16>,
    _pad_52: Reserved<0x6>,
}

unsafe impl NtStruct for Tunnel {}

const _: () = {
    assert!(core::mem::size_of::<Tunnel>() == 0x58);
    assert!(core::mem::offset_of!(Tunnel, cache) == 0x38);
    assert!(core::mem::offset_of!(Tunnel, timer_queue) == 0x40);
    assert!(core::mem::offset_of!(Tunnel, num_entries) == 0x50);
};

/// `FILE_NOTIFY_INFORMATION` (winnt.h/ntifs.h; registro de
/// IRP_MN_NOTIFY_CHANGE_DIRECTORY com o nome a seguir; 0x10 com o primeiro WCHAR).
#[repr(C)]
pub struct FileNotifyInformation {
    pub next_entry_offset: Field<u32>,
    pub action: Field<u32>,
    pub file_name_length: Field<u32>,
    pub file_name: [Field<u16>; 1],
    _pad_e: Reserved<0x2>,
}

unsafe impl NtStruct for FileNotifyInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileNotifyInformation>() == 0x10);
    assert!(core::mem::offset_of!(FileNotifyInformation, file_name_length) == 0x8);
    assert!(core::mem::offset_of!(FileNotifyInformation, file_name) == 0xC);
};

/// `EX_PUSH_LOCK_CACHE_AWARE_PADDED` (privada do Ex; layout de
/// ExAllocateCacheAwarePushLock 0x3c8090: Lock +0, Single +8, ParentLock
/// +0x10, linha de 0x80 bytes).
#[repr(C)]
pub struct ExPushLockCacheAwarePadded {
    pub lock: ExPushLock,
    pub single: Field<u8>,
    _pad_9: Reserved<0x7>,
    /// -> a tabela `EX_PUSH_LOCK_CACHE_AWARE` dona
    pub parent_lock: Field<u64>,
    _pad_18: Reserved<0x68>,
}

/// `EX_PUSH_LOCK_CACHE_AWARE` (privada do Ex; 32 ponteiros para os slots; 0x100 bytes).
#[repr(C)]
pub struct ExPushLockCacheAware {
    /// -> `EX_PUSH_LOCK_CACHE_AWARE_PADDED`
    pub locks: [Field<u64>; 32],
}

unsafe impl NtStruct for ExPushLockCacheAwarePadded {}
unsafe impl NtStruct for ExPushLockCacheAware {}

const _: () = {
    assert!(core::mem::size_of::<ExPushLockCacheAwarePadded>() == 0x80);
    assert!(core::mem::offset_of!(ExPushLockCacheAwarePadded, single) == 0x8);
    assert!(core::mem::offset_of!(ExPushLockCacheAwarePadded, parent_lock) == 0x10);
    assert!(core::mem::size_of::<ExPushLockCacheAware>() == 0x100);
};
