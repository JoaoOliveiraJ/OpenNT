//! Consultas do FsRtl.
//!
//! Sem VHDs aninhados nem arquivo de paginação.

use crate::ntos::init::exports::{Call, Group};
use crate::rtl::KernelError;

fn get_virtual_disk_nesting_level(_: &Call) -> Result<u64, KernelError> {
    Ok(0)
}

fn is_system_paging_file(_: &Call) -> Result<u64, KernelError> {
    Ok(0)
}

pub static GROUP: Group = Group {
    name: "fsrtl",
    names: &["FsRtlGetVirtualDiskNestingLevel", "FsRtlIsSystemPagingFile"],
    handlers: &[get_virtual_disk_nesting_level, is_system_paging_file],
    data_exports: &[],
};

pub mod file_information {
    //! FsRtlGetFileSize, IoQueryVolumeInformation, FsRtlKernelFsControlFile e
    //! FsRtlQuery/SetKernelEaFile.
    //!
    //! Cada provedor interpreta a classe de informação e opera no objeto
    //! nativo de arquivo.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::io::file::zw as zw_files;
    use crate::ntos::io::file::information as file_information;
    use crate::ntos::io::{kernel_ea, kernel_fs_control};
    use crate::rtl::KernelError;

    /// Tamanho a partir do FILE_OBJECT.
    fn get_file_size(call: &Call) -> Result<u64, KernelError> {
        Ok(file_information::get_size(call.arg(1), call.arg(2))? as u64)
    }

    /// Consulta de volume pelo serviço que conhece os arquivos abertos.
    fn query_volume_information(call: &Call) -> Result<u64, KernelError> {
        Ok(zw_files::query_volume_information_by_object(call.arg(1), call.arg(2) as u32, call.arg(3) as u32, call.arg(4), call.arg(5))? as u64)
    }

    fn kernel_fs_control_file(call: &Call) -> Result<u64, KernelError> {
        Ok(kernel_fs_control::control(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32, call.arg(5), call.arg(6) as u32, call.arg(7))? as u64)
    }

    fn query_kernel_ea_file(call: &Call) -> Result<u64, KernelError> {
        Ok(kernel_ea::query(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4) as u8, call.arg(5), call.arg(6) as u32, call.arg(7), call.arg(8) as u8, call.arg(9))? as u64)
    }

    fn set_kernel_ea_file(call: &Call) -> Result<u64, KernelError> {
        Ok(kernel_ea::set(call.arg(1), call.arg(2), call.arg(3) as u32)? as u64)
    }

    pub static GROUP: Group = Group {
        name: "file-information",
        names: &["FsRtlGetFileSize", "IoQueryVolumeInformation", "FsRtlKernelFsControlFile", "FsRtlQueryKernelEaFile", "FsRtlSetKernelEaFile"],
        handlers: &[get_file_size, query_volume_information, kernel_fs_control_file, query_kernel_ea_file, set_kernel_ea_file],
        data_exports: &[],
    };
}

pub mod file_name_information {
    //! FsRtlGetFileNameInformation.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::drivers::fs::filter_callbacks;

    fn get_file_name_information(call: &Call) -> Result<u64, KernelError> {
        Ok(filter_callbacks::get_file_name_information(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4)) as u64)
    }

    pub static GROUP: Group = Group {
        name: "file-name-information",
        names: &["FsRtlGetFileNameInformation"],
        handlers: &[get_file_name_information],
        data_exports: &[],
    };
}

pub mod release_file_name_information {
    //! FsRtlReleaseFileNameInformation.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::drivers::fs::filter_callbacks;

    fn release_file_name_information(call: &Call) -> Result<u64, KernelError> {
        filter_callbacks::release_file_name_information(call.arg(1));
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "release-file-name-information",
        names: &["FsRtlReleaseFileNameInformation"],
        handlers: &[release_file_name_information],
        data_exports: &[],
    };
}

pub mod fsrtl_core {
    //! Núcleo puro do FsRtl — correspondência de nomes com curingas DOS,
    //! helpers de NTSTATUS e o portão de carga do Filter Manager.
    //!
    //! Adaptadores: a lógica mora em `fsrtl::name` (nomes e o bitmap
    //! FsRtlLegalAnsiCharacterArray), `fsrtl::ntstatus` e `fsrtl::filter`.

    use crate::ntos::fsrtl::{filter, name, ntstatus};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    fn legal_ansi_character_array_address() -> u64 {
        name::legal_ansi_character_array_address()
    }

    /// FsRtlIsNtstatusExpected(Status) -> BOOLEAN (zero-extendido).
    fn is_ntstatus_expected(call: &Call) -> Result<u64, KernelError> {
        Ok(ntstatus::is_ntstatus_expected(call.arg(1) as u32) as u64)
    }

    /// FsRtlNormalizeNtstatus: `mov eax, edi` zera os 32 bits altos de RAX —
    /// devolve sem sinal.
    fn normalize_ntstatus(call: &Call) -> Result<u64, KernelError> {
        Ok(ntstatus::normalize_ntstatus(call.arg(1) as u32, call.arg(2) as u32) as u64)
    }

    fn does_name_contain_wild_cards(call: &Call) -> Result<u64, KernelError> {
        Ok(name::does_name_contain_wild_cards(call.arg(1)) as u64)
    }

    fn dissect_name(call: &Call) -> Result<u64, KernelError> {
        name::dissect_name(call.arg(1), call.arg(2), call.arg(3));
        Ok(0)
    }

    fn is_name_in_expression(call: &Call) -> Result<u64, KernelError> {
        Ok(name::is_name_in_expression(call.arg(1), call.arg(2), call.arg(3) != 0) as u64)
    }

    fn register_flt_mgr_calls(call: &Call) -> Result<u64, KernelError> {
        Ok(filter::register_flt_mgr_calls(call.arg(1)))
    }

    fn register_file_system_filter_callbacks(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(filter::register_file_system_filter_callbacks(call.arg(1), call.arg(2))))
    }

    pub static GROUP: Group = Group {
        name: "fsrtl-core",
        names: &[
            "FsRtlIsNameInExpression",
            "FsRtlDoesNameContainWildCards",
            "FsRtlDissectName",
            "FsRtlIsNtstatusExpected",
            "FsRtlNormalizeNtstatus",
            "FsRtlRegisterFltMgrCalls",
            "FsRtlRegisterFileSystemFilterCallbacks",
        ],
        handlers: &[
            is_name_in_expression,
            does_name_contain_wild_cards,
            dissect_name,
            is_ntstatus_expected,
            normalize_ntstatus,
            register_flt_mgr_calls,
            register_file_system_filter_callbacks,
        ],
        data_exports: &[("FsRtlLegalAnsiCharacterArray", legal_ansi_character_array_address)],
    };
}

pub mod fsrtl_file_locks {
    //! Adaptadores de FILE_LOCK — a lógica mora em `fsrtl::file_lock`.

    use crate::ntos::fsrtl::file_lock;
    use crate::ntos::inc::field::NtStruct;
    use crate::ntos::inc::types::extra_fsrtl::FileLock;
    use crate::ntos::inc::types::{IoStatusBlock, Irp, LargeInteger};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    // SAFETY (todos os `at`): ponteiros de kernel/driver que o NT recebe como
    // PFILE_LOCK, PLARGE_INTEGER, PIO_STATUS_BLOCK e PIRP (Irp opcional).

    fn initialize_file_lock(call: &Call) -> Result<u64, KernelError> {
        file_lock::initialize_file_lock(unsafe { FileLock::at(call.arg(1)) }, call.arg(2), call.arg(3));
        Ok(0)
    }

    fn allocate_file_lock(call: &Call) -> Result<u64, KernelError> {
        Ok(file_lock::allocate_file_lock(call.arg(1), call.arg(2)))
    }

    fn free_file_lock(call: &Call) -> Result<u64, KernelError> {
        file_lock::free_file_lock(unsafe { FileLock::at(call.arg(1)) });
        Ok(0)
    }

    fn uninitialize_file_lock(call: &Call) -> Result<u64, KernelError> {
        file_lock::uninitialize_file_lock(unsafe { FileLock::at(call.arg(1)) });
        Ok(0)
    }

    fn fast_check_lock_for_read(call: &Call) -> Result<u64, KernelError> {
        let (lock, start, length) = unsafe { (FileLock::at(call.arg(1)), LargeInteger::at(call.arg(2)), LargeInteger::at(call.arg(3))) };
        Ok(file_lock::fast_check_lock_for_read(lock, start, length, call.arg(4) as u32, call.arg(5), call.arg(6)) as u64)
    }

    fn fast_check_lock_for_write(call: &Call) -> Result<u64, KernelError> {
        let (lock, start, length) = unsafe { (FileLock::at(call.arg(1)), LargeInteger::at(call.arg(2)), LargeInteger::at(call.arg(3))) };
        Ok(file_lock::fast_check_lock_for_write(lock, start, length, call.arg(4) as u32, call.arg(5), call.arg(6)) as u64)
    }

    fn private_lock(call: &Call) -> Result<u64, KernelError> {
        let (lock, start, length, iosb) = unsafe { (FileLock::at(call.arg(1)), LargeInteger::at(call.arg(3)), LargeInteger::at(call.arg(4)), IoStatusBlock::at(call.arg(9))) };
        let irp = (call.arg(10) != 0).then(|| unsafe { Irp::at(call.arg(10)) });
        Ok(file_lock::private_lock(lock, call.arg(2), start, length, call.arg(5), call.arg(6) as u32, call.arg(7) & 0xFF != 0, call.arg(8) & 0xFF != 0, iosb, irp, call.arg(11)) as u64)
    }

    fn fast_unlock_single(call: &Call) -> Result<u64, KernelError> {
        let (lock, offset, length) = unsafe { (FileLock::at(call.arg(1)), LargeInteger::at(call.arg(3)), LargeInteger::at(call.arg(4))) };
        Ok(signed_status(file_lock::fast_unlock_single(lock, call.arg(2), offset, length, call.arg(5), call.arg(6) as u32, call.arg(7))))
    }

    fn fast_unlock_all(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(file_lock::fast_unlock_all(unsafe { FileLock::at(call.arg(1)) }, call.arg(2), call.arg(3), call.arg(4))))
    }

    fn fast_unlock_all_by_key(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(file_lock::fast_unlock_all_by_key(unsafe { FileLock::at(call.arg(1)) }, call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5))))
    }

    pub static GROUP: Group = Group {
        name: "fsrtl-file-locks",
        names: &[
            "FsRtlInitializeFileLock",
            "FsRtlAllocateFileLock",
            "FsRtlFreeFileLock",
            "FsRtlUninitializeFileLock",
            "FsRtlFastCheckLockForRead",
            "FsRtlFastCheckLockForWrite",
            "FsRtlPrivateLock",
            "FsRtlFastUnlockSingle",
            "FsRtlFastUnlockAll",
            "FsRtlFastUnlockAllByKey",
        ],
        handlers: &[
            initialize_file_lock,
            allocate_file_lock,
            free_file_lock,
            uninitialize_file_lock,
            fast_check_lock_for_read,
            fast_check_lock_for_write,
            private_lock,
            fast_unlock_single,
            fast_unlock_all,
            fast_unlock_all_by_key,
        ],
        data_exports: &[],
    };
}

pub mod fsrtl_oplocks {
    //! Adaptadores de oplock — a lógica mora em `fsrtl::oplock`.

    use crate::ntos::fsrtl::oplock;
    use crate::ntos::inc::field::{Field, NtStruct};
    use crate::ntos::inc::types::{FileObject, Irp};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    // SAFETY (todos os `at`): POPLOCK (PVOID*), PIRP e PFILE_OBJECT de
    // kernel/driver; o Irp é opcional onde o NT aceita NULL.

    fn initialize_oplock(call: &Call) -> Result<u64, KernelError> {
        oplock::initialize_oplock(unsafe { Field::<u64>::at(call.arg(1)) });
        Ok(0)
    }

    fn uninitialize_oplock(call: &Call) -> Result<u64, KernelError> {
        oplock::uninitialize_oplock(unsafe { Field::<u64>::at(call.arg(1)) });
        Ok(0)
    }

    fn current_oplock(call: &Call) -> Result<u64, KernelError> {
        Ok(oplock::current_oplock(unsafe { Field::<u64>::at(call.arg(1)) }) as u64)
    }

    fn current_batch_oplock(call: &Call) -> Result<u64, KernelError> {
        Ok(oplock::current_batch_oplock(unsafe { Field::<u64>::at(call.arg(1)) }) as u64)
    }

    fn current_oplock_h(call: &Call) -> Result<u64, KernelError> {
        Ok(oplock::current_oplock_h(unsafe { Field::<u64>::at(call.arg(1)) }) as u64)
    }

    fn oplock_is_fast_io_possible(call: &Call) -> Result<u64, KernelError> {
        Ok(oplock::oplock_is_fast_io_possible(unsafe { Field::<u64>::at(call.arg(1)) }) as u64)
    }

    fn oplock_keys_equal(call: &Call) -> Result<u64, KernelError> {
        let first = (call.arg(1) != 0).then(|| unsafe { FileObject::at(call.arg(1)) });
        let second = (call.arg(2) != 0).then(|| unsafe { FileObject::at(call.arg(2)) });
        Ok(oplock::oplock_keys_equal(first, second) as u64)
    }

    fn oplock_is_shared_request(call: &Call) -> Result<u64, KernelError> {
        Ok(oplock::oplock_is_shared_request(unsafe { Irp::at(call.arg(1)) }) as u64)
    }

    fn check_oplock(call: &Call) -> Result<u64, KernelError> {
        let irp = (call.arg(2) != 0).then(|| unsafe { Irp::at(call.arg(2)) });
        Ok(signed_status(oplock::check_oplock(unsafe { Field::<u64>::at(call.arg(1)) }, irp)))
    }

    fn check_oplock_ex(call: &Call) -> Result<u64, KernelError> {
        let irp = (call.arg(2) != 0).then(|| unsafe { Irp::at(call.arg(2)) });
        Ok(signed_status(oplock::check_oplock_ex(unsafe { Field::<u64>::at(call.arg(1)) }, irp, call.arg(3) as u32)))
    }

    fn oplock_break_h(call: &Call) -> Result<u64, KernelError> {
        let irp = (call.arg(2) != 0).then(|| unsafe { Irp::at(call.arg(2)) });
        Ok(signed_status(oplock::oplock_break_h(unsafe { Field::<u64>::at(call.arg(1)) }, irp)))
    }

    fn oplock_break_to_none(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(oplock::oplock_break_to_none(unsafe { Field::<u64>::at(call.arg(1)) })))
    }

    fn oplock_break_to_none_ex(call: &Call) -> Result<u64, KernelError> {
        let irp = (call.arg(2) != 0).then(|| unsafe { Irp::at(call.arg(2)) });
        Ok(signed_status(oplock::oplock_break_to_none_ex(unsafe { Field::<u64>::at(call.arg(1)) }, irp, call.arg(3) as u32)))
    }

    fn oplock_fsctrl_ex(call: &Call) -> Result<u64, KernelError> {
        let (handle, irp) = unsafe { (Field::<u64>::at(call.arg(1)), Irp::at(call.arg(2))) };
        Ok(signed_status(oplock::oplock_fsctrl_ex(handle, irp, call.arg(3) as u32, call.arg(4) as u32)))
    }

    pub static GROUP: Group = Group {
        name: "fsrtl-oplocks",
        names: &[
            "FsRtlInitializeOplock",
            "FsRtlUninitializeOplock",
            "FsRtlCurrentOplock",
            "FsRtlCurrentBatchOplock",
            "FsRtlCurrentOplockH",
            "FsRtlOplockIsFastIoPossible",
            "FsRtlOplockKeysEqual",
            "FsRtlOplockIsSharedRequest",
            "FsRtlCheckOplock",
            "FsRtlCheckOplockEx",
            "FsRtlOplockBreakH",
            "FsRtlOplockBreakToNone",
            "FsRtlOplockBreakToNoneEx",
            "FsRtlOplockFsctrlEx",
        ],
        handlers: &[
            initialize_oplock,
            uninitialize_oplock,
            current_oplock,
            current_batch_oplock,
            current_oplock_h,
            oplock_is_fast_io_possible,
            oplock_keys_equal,
            oplock_is_shared_request,
            check_oplock,
            check_oplock_ex,
            oplock_break_h,
            oplock_break_to_none,
            oplock_break_to_none_ex,
            oplock_fsctrl_ex,
        ],
        data_exports: &[],
    };
}

pub mod fsrtl_ecp {
    //! Adaptadores de ECP — a lógica mora em `fsrtl::ecp`.

    use crate::ntos::fsrtl::ecp;
    use crate::ntos::inc::field::{Field, NtStruct};
    use crate::ntos::inc::types::extra_fsrtl::EcpList;
    use crate::ntos::inc::types::{GeneralLookaside, Guid, Irp};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    // SAFETY (todos os `at`): PECP_LIST, LPCGUID, PIRP, PLOOKASIDE_LIST e
    // parâmetros de saída de kernel/driver; os opcionais do NT viram Option.

    fn allocate_list(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(ecp::allocate_list(call.arg(1) as u32, unsafe { Field::<u64>::at(call.arg(2)) })?))
    }

    fn free_list(call: &Call) -> Result<u64, KernelError> {
        ecp::free_list(unsafe { EcpList::at(call.arg(1)) })?;
        Ok(0)
    }

    fn allocate(call: &Call) -> Result<u64, KernelError> {
        let (ecp_type, out) = unsafe { (Guid::at(call.arg(1)), Field::<u64>::at(call.arg(6))) };
        Ok(signed_status(ecp::allocate(ecp_type, call.arg(2) as u32, call.arg(3) as u32, call.arg(4), call.arg(5) as u32, out)?))
    }

    fn free(call: &Call) -> Result<u64, KernelError> {
        ecp::free(call.arg(1))?;
        Ok(0)
    }

    fn insert(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(ecp::insert(unsafe { EcpList::at(call.arg(1)) }, call.arg(2))))
    }

    fn find(call: &Call) -> Result<u64, KernelError> {
        let (list, ecp_type) = unsafe { (EcpList::at(call.arg(1)), Guid::at(call.arg(2))) };
        let context_out = (call.arg(3) != 0).then(|| unsafe { Field::<u64>::at(call.arg(3)) });
        let size_out = (call.arg(4) != 0).then(|| unsafe { Field::<u32>::at(call.arg(4)) });
        Ok(signed_status(ecp::find(list, ecp_type, context_out, size_out)))
    }

    fn remove(call: &Call) -> Result<u64, KernelError> {
        let (list, ecp_type, context_out) = unsafe { (EcpList::at(call.arg(1)), Guid::at(call.arg(2)), Field::<u64>::at(call.arg(3))) };
        let size_out = (call.arg(4) != 0).then(|| unsafe { Field::<u32>::at(call.arg(4)) });
        Ok(signed_status(ecp::remove(list, ecp_type, context_out, size_out)))
    }

    fn get_next(call: &Call) -> Result<u64, KernelError> {
        let list = unsafe { EcpList::at(call.arg(1)) };
        let type_out = (call.arg(3) != 0).then(|| unsafe { Guid::at(call.arg(3)) });
        let context_out = (call.arg(4) != 0).then(|| unsafe { Field::<u64>::at(call.arg(4)) });
        let size_out = (call.arg(5) != 0).then(|| unsafe { Field::<u32>::at(call.arg(5)) });
        Ok(signed_status(ecp::get_next(list, call.arg(2), type_out, context_out, size_out)))
    }

    fn acknowledge(call: &Call) -> Result<u64, KernelError> {
        ecp::acknowledge(call.arg(1));
        Ok(0)
    }

    fn is_acknowledged(call: &Call) -> Result<u64, KernelError> {
        Ok(ecp::is_acknowledged(call.arg(1)) as u64)
    }

    fn is_from_user_mode(call: &Call) -> Result<u64, KernelError> {
        Ok(ecp::is_from_user_mode(call.arg(1)) as u64)
    }

    fn prepare_to_reuse(call: &Call) -> Result<u64, KernelError> {
        ecp::prepare_to_reuse(call.arg(1));
        Ok(0)
    }

    fn get_list_from_irp(call: &Call) -> Result<u64, KernelError> {
        let (irp, out) = unsafe { (Irp::at(call.arg(1)), Field::<u64>::at(call.arg(2))) };
        Ok(signed_status(ecp::get_list_from_irp(irp, out)))
    }

    fn set_list_into_irp(call: &Call) -> Result<u64, KernelError> {
        let (irp, list) = unsafe { (Irp::at(call.arg(1)), EcpList::at(call.arg(2))) };
        Ok(signed_status(ecp::set_list_into_irp(irp, list)))
    }

    fn init_lookaside(call: &Call) -> Result<u64, KernelError> {
        ecp::init_lookaside(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32)?;
        Ok(0)
    }

    fn delete_lookaside(call: &Call) -> Result<u64, KernelError> {
        ecp::delete_lookaside(call.arg(1))?;
        Ok(0)
    }

    fn allocate_from_lookaside(call: &Call) -> Result<u64, KernelError> {
        let (ecp_type, list, out) = unsafe { (Guid::at(call.arg(1)), GeneralLookaside::at(call.arg(5)), Field::<u64>::at(call.arg(6))) };
        Ok(signed_status(ecp::allocate_from_lookaside(ecp_type, call.arg(2) as u32, call.arg(3) as u32, call.arg(4), list, out)?))
    }

    pub static GROUP: Group = Group {
        name: "fsrtl-ecp",
        names: &[
            "FsRtlAllocateExtraCreateParameterList",
            "FsRtlFreeExtraCreateParameterList",
            "FsRtlAllocateExtraCreateParameter",
            "FsRtlFreeExtraCreateParameter",
            "FsRtlInsertExtraCreateParameter",
            "FsRtlFindExtraCreateParameter",
            "FsRtlRemoveExtraCreateParameter",
            "FsRtlGetNextExtraCreateParameter",
            "FsRtlAcknowledgeEcp",
            "FsRtlIsEcpAcknowledged",
            "FsRtlIsEcpFromUserMode",
            "FsRtlPrepareToReuseEcp",
            "FsRtlGetEcpListFromIrp",
            "FsRtlSetEcpListIntoIrp",
            "FsRtlInitExtraCreateParameterLookasideList",
            "FsRtlDeleteExtraCreateParameterLookasideList",
            "FsRtlAllocateExtraCreateParameterFromLookasideList",
        ],
        handlers: &[
            allocate_list,
            free_list,
            allocate,
            free,
            insert,
            find,
            remove,
            get_next,
            acknowledge,
            is_acknowledged,
            is_from_user_mode,
            prepare_to_reuse,
            get_list_from_irp,
            set_list_into_irp,
            init_lookaside,
            delete_lookaside,
            allocate_from_lookaside,
        ],
        data_exports: &[],
    };
}

pub mod fsrtl_filter_contexts {
    //! Adaptadores de contextos de filtro — a lógica mora em `fsrtl::filter_context`.

    use crate::ntos::fsrtl::filter_context;
    use crate::ntos::inc::field::{Field, NtStruct};
    use crate::ntos::inc::types::extra_fsrtl::{FsrtlAdvancedFcbHeader, FsrtlPerFileContext, FsrtlPerFileobjectContext, FsrtlPerStreamContext};
    use crate::ntos::inc::types::FileObject;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    // SAFETY (todos os `at`): PFSRTL_ADVANCED_FCB_HEADER, PVOID*
    // (PerFileContextPointer), PFILE_OBJECT e os registros FSRTL_PER_*_CONTEXT
    // de kernel/driver; os que o NT confere contra NULL viram Option.

    fn insert_per_stream_context(call: &Call) -> Result<u64, KernelError> {
        let header = (call.arg(1) != 0).then(|| unsafe { FsrtlAdvancedFcbHeader::at(call.arg(1)) });
        Ok(signed_status(filter_context::insert_per_stream_context(header, unsafe { FsrtlPerStreamContext::at(call.arg(2)) })?))
    }

    fn lookup_per_stream_context_internal(call: &Call) -> Result<u64, KernelError> {
        filter_context::lookup_per_stream_context(unsafe { FsrtlAdvancedFcbHeader::at(call.arg(1)) }, call.arg(2), call.arg(3))
    }

    fn remove_per_stream_context(call: &Call) -> Result<u64, KernelError> {
        let header = (call.arg(1) != 0).then(|| unsafe { FsrtlAdvancedFcbHeader::at(call.arg(1)) });
        filter_context::remove_per_stream_context(header, call.arg(2), call.arg(3))
    }

    fn insert_per_file_context(call: &Call) -> Result<u64, KernelError> {
        let pointer = (call.arg(1) != 0).then(|| unsafe { Field::<u64>::at(call.arg(1)) });
        Ok(signed_status(filter_context::insert_per_file_context(pointer, unsafe { FsrtlPerFileContext::at(call.arg(2)) })?))
    }

    fn lookup_per_file_context(call: &Call) -> Result<u64, KernelError> {
        filter_context::lookup_per_file_context(unsafe { Field::<u64>::at(call.arg(1)) }, call.arg(2), call.arg(3))
    }

    fn remove_per_file_context(call: &Call) -> Result<u64, KernelError> {
        filter_context::remove_per_file_context(unsafe { Field::<u64>::at(call.arg(1)) }, call.arg(2), call.arg(3))
    }

    fn insert_per_file_object_context(call: &Call) -> Result<u64, KernelError> {
        let file_object = (call.arg(1) != 0).then(|| unsafe { FileObject::at(call.arg(1)) });
        Ok(signed_status(filter_context::insert_per_file_object_context(file_object, unsafe { FsrtlPerFileobjectContext::at(call.arg(2)) })?))
    }

    fn lookup_per_file_object_context(call: &Call) -> Result<u64, KernelError> {
        let file_object = (call.arg(1) != 0).then(|| unsafe { FileObject::at(call.arg(1)) });
        filter_context::lookup_per_file_object_context(file_object, call.arg(2), call.arg(3))
    }

    fn remove_per_file_object_context(call: &Call) -> Result<u64, KernelError> {
        let file_object = (call.arg(1) != 0).then(|| unsafe { FileObject::at(call.arg(1)) });
        filter_context::remove_per_file_object_context(file_object, call.arg(2), call.arg(3))
    }

    pub static GROUP: Group = Group {
        name: "fsrtl-filter-contexts",
        names: &[
            "FsRtlInsertPerStreamContext",
            "FsRtlLookupPerStreamContextInternal",
            "FsRtlRemovePerStreamContext",
            "FsRtlInsertPerFileContext",
            "FsRtlLookupPerFileContext",
            "FsRtlRemovePerFileContext",
            "FsRtlInsertPerFileObjectContext",
            "FsRtlLookupPerFileObjectContext",
            "FsRtlRemovePerFileObjectContext",
        ],
        handlers: &[
            insert_per_stream_context,
            lookup_per_stream_context_internal,
            remove_per_stream_context,
            insert_per_file_context,
            lookup_per_file_context,
            remove_per_file_context,
            insert_per_file_object_context,
            lookup_per_file_object_context,
            remove_per_file_object_context,
        ],
        data_exports: &[],
    };
}

pub mod fsrtl_file_system_support {
    //! Adaptador de rotinas de apoio a file systems: reparse points, nomes
    //! com expressão não convertida, processo 32 bits, lista do loader,
    //! aninhamento de discos virtuais, extensões pendentes e troca do arquivo
    //! que sustenta seção/cache. Lógica em `ntos/fsrtl/{reparse, name,
    //! process, virtual_disk, backing_file}.rs` e `ntos/mm/dangling_extent.rs`.

    use crate::ntos::fsrtl::{backing_file, name, process, reparse, virtual_disk};
    use crate::ntos::inc::field::NtStruct;
    use crate::ntos::inc::types::{Eprocess, FileObject};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::mm::dangling_extent;
    use crate::rtl::KernelError;

    /// FsRtlValidateReparsePointBuffer(BufferLength, ReparseBuffer) -> NTSTATUS.
    fn validate_reparse_point_buffer(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(reparse::validate_reparse_point_buffer(call.arg(1) as u32, call.arg(2))))
    }

    /// FsRtlIsNameInUnUpcasedExpression(Expression, Name, IgnoreCase, UpcaseTable) -> BOOLEAN.
    fn is_name_in_un_upcased_expression(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: tabela de maiúsculas do file system (64K WCHARs) ou NULL.
        let table = unsafe { name::UpcaseTable::at(call.arg(4)) };
        Ok(name::is_name_in_un_upcased_expression(call.arg(1), call.arg(2), call.arg(3) as u8 != 0, table)? as u64)
    }

    /// FsRtlIs32BitProcess(Process) -> BOOLEAN.
    fn is_32bit_process(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: EPROCESS vivo passado pelo file system.
        Ok(process::is_32bit_process(unsafe { Eprocess::at(call.arg(1)) }) as u64)
    }

    /// FsRtlGetCurrentProcessLoaderList() -> PLIST_ENTRY.
    fn get_current_process_loader_list(_: &Call) -> Result<u64, KernelError> {
        process::current_process_loader_list()
    }

    /// FsRtlQueryMaximumVirtualDiskNestingLevel() -> ULONG.
    fn query_maximum_virtual_disk_nesting_level(_: &Call) -> Result<u64, KernelError> {
        Ok(virtual_disk::query_maximum_nesting_level() as u64)
    }

    /// FsRtlIsExtentDangling(StartPage, NumberOfPages) -> PFN_NUMBER.
    fn is_extent_dangling(call: &Call) -> Result<u64, KernelError> {
        Ok(dangling_extent::first_dangling_page(call.arg(1), call.arg(2)))
    }

    /// FsRtlChangeBackingFileObject(CurrentFileObject, NewFileObject, ChangeBackingType, Flags) -> NTSTATUS.
    fn change_backing_file_object(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: FILE_OBJECTs do file system; o atual pode ser NULL.
        let (current, new) = unsafe { ((call.arg(1) != 0).then(|| FileObject::at(call.arg(1))), FileObject::at(call.arg(2))) };
        Ok(signed_status(backing_file::change_backing_file_object(current, new, call.arg(3) as u32, call.arg(4) as u32)?))
    }

    pub static GROUP: Group = Group {
        name: "fsrtl-file-system-support",
        names: &[
            "FsRtlValidateReparsePointBuffer",
            "FsRtlIsNameInUnUpcasedExpression",
            "FsRtlIs32BitProcess",
            "FsRtlGetCurrentProcessLoaderList",
            "FsRtlQueryMaximumVirtualDiskNestingLevel",
            "FsRtlIsExtentDangling",
            "FsRtlChangeBackingFileObject",
        ],
        handlers: &[
            validate_reparse_point_buffer,
            is_name_in_un_upcased_expression,
            is_32bit_process,
            get_current_process_loader_list,
            query_maximum_virtual_disk_nesting_level,
            is_extent_dangling,
            change_backing_file_object,
        ],
        data_exports: &[],
    };
}

pub mod fsrtl_misc {
    //! Adaptadores dos auxiliares de portão do FsRtl — a lógica mora em
    //! `fsrtl::small`, `fsrtl::cancellable_wait`, `fsrtl::device_control` e
    //! `fsrtl::reparse`.

    use crate::ntos::fsrtl::small::{app_termination, driver_backing, mobile_os, paging_file};
    use crate::ntos::fsrtl::{cancellable_wait, device_control, reparse};
    use crate::ntos::inc::field::{Field, NtStruct};
    use crate::ntos::inc::types::{DeviceObject, DriverObject, FileObject, Guid, Irp, LargeInteger};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    // SAFETY (todos os `at`): PFILE_OBJECT, PDRIVER_OBJECT, PDEVICE_OBJECT,
    // LPGUID, PLARGE_INTEGER (opcional), PVOID[] e PIRP (opcional) de
    // kernel/driver.

    fn is_paging_file(call: &Call) -> Result<u64, KernelError> {
        Ok(paging_file::is_paging_file(unsafe { FileObject::at(call.arg(1)) }) as u64)
    }

    fn is_mobile_os(_: &Call) -> Result<u64, KernelError> {
        Ok(mobile_os::is_mobile_os() as u64)
    }

    fn is_non_empty_directory_reparse_point_allowed(call: &Call) -> Result<u64, KernelError> {
        Ok(reparse::is_non_empty_directory_reparse_point_allowed(call.arg(1) as u32) as u64)
    }

    fn set_driver_backing(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(driver_backing::set_driver_backing(unsafe { DriverObject::at(call.arg(1)) }, call.arg(2) as u32)))
    }

    fn send_modern_app_termination(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(app_termination::send_modern_app_termination(call.arg(1), call.arg(2) as u32, call.arg(3) as u32)?))
    }

    fn cancellable_wait_for_single_object(call: &Call) -> Result<u64, KernelError> {
        let timeout = (call.arg(2) != 0).then(|| unsafe { LargeInteger::at(call.arg(2)) });
        let irp = (call.arg(3) != 0).then(|| unsafe { Irp::at(call.arg(3)) });
        Ok(signed_status(cancellable_wait::wait_for_single_object(call.arg(1), timeout, irp)))
    }

    fn cancellable_wait_for_multiple_objects(call: &Call) -> Result<u64, KernelError> {
        let objects = unsafe { Field::<u64>::at(call.arg(2)) };
        let timeout = (call.arg(4) != 0).then(|| unsafe { LargeInteger::at(call.arg(4)) });
        let irp = (call.arg(6) != 0).then(|| unsafe { Irp::at(call.arg(6)) });
        Ok(signed_status(cancellable_wait::wait_for_multiple_objects(call.arg(1) as u32, objects, call.arg(3) as u32, timeout, call.arg(5), irp)))
    }

    fn volume_device_to_correlation_id(call: &Call) -> Result<u64, KernelError> {
        let (device, guid) = unsafe { (DeviceObject::at(call.arg(1)), Guid::at(call.arg(2))) };
        Ok(signed_status(device_control::volume_device_to_correlation_id(device, guid)))
    }

    pub static GROUP: Group = Group {
        name: "fsrtl-misc",
        names: &[
            "FsRtlIsPagingFile",
            "FsRtlIsMobileOS",
            "FsRtlIsNonEmptyDirectoryReparsePointAllowed",
            "FsRtlSetDriverBacking",
            "FsRtlSendModernAppTermination",
            "FsRtlCancellableWaitForSingleObject",
            "FsRtlCancellableWaitForMultipleObjects",
            "FsRtlVolumeDeviceToCorrelationId",
        ],
        handlers: &[
            is_paging_file,
            is_mobile_os,
            is_non_empty_directory_reparse_point_allowed,
            set_driver_backing,
            send_modern_app_termination,
            cancellable_wait_for_single_object,
            cancellable_wait_for_multiple_objects,
            volume_device_to_correlation_id,
        ],
        data_exports: &[],
    };
}

pub mod fsrtl_base_mcb {
    //! BASE_MCB (mapa VBN -> LBN dos file systems): adaptadores finos sobre
    //! `fsrtl::mcb`, verificado contra o código do ntoskrnl 19045 executado
    //! num emulador. O PBASE_MCB do driver vira `&BaseMcb` aqui, uma vez.

    use crate::ntos::fsrtl::mcb;
    use crate::ntos::inc::types::extra_fs_ntfs::BaseMcb;
    use crate::ntos::inc::NtStruct;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    /// FsRtlInitializeBaseMcbEx(Mcb, PoolType, Flags) -> BOOLEAN.
    fn initialize_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(mcb::initialize(unsafe { BaseMcb::at(call.arg(1)) }, call.arg(2) as u32, call.arg(3) as u16)? as u64)
    }

    fn uninitialize(call: &Call) -> Result<u64, KernelError> {
        mcb::uninitialize(unsafe { BaseMcb::at(call.arg(1)) })?;
        Ok(0)
    }

    fn reset(call: &Call) -> Result<u64, KernelError> {
        mcb::reset(unsafe { BaseMcb::at(call.arg(1)) });
        Ok(0)
    }

    fn truncate(call: &Call) -> Result<u64, KernelError> {
        mcb::truncate(unsafe { BaseMcb::at(call.arg(1)) }, call.arg(2))?;
        Ok(0)
    }

    fn number_of_runs(call: &Call) -> Result<u64, KernelError> {
        Ok(mcb::number_of_runs(unsafe { BaseMcb::at(call.arg(1)) }) as u64)
    }

    /// FsRtlAddBaseMcbEntryEx(Mcb, Vbn, Lbn, SectorCount) -> NTSTATUS.
    fn add_entry_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(mcb::add_entry_ex(unsafe { BaseMcb::at(call.arg(1)) }, call.arg(2), call.arg(3), call.arg(4))?))
    }

    /// FsRtlAddBaseMcbEntry(Mcb, Vbn, Lbn, SectorCount) -> BOOLEAN.
    fn add_entry(call: &Call) -> Result<u64, KernelError> {
        Ok(mcb::add_entry_boolean(unsafe { BaseMcb::at(call.arg(1)) }, call.arg(2), call.arg(3), call.arg(4))? as u64)
    }

    /// FsRtlRemoveBaseMcbEntry(Mcb, Vbn, SectorCount) -> BOOLEAN.
    fn remove_entry(call: &Call) -> Result<u64, KernelError> {
        Ok(mcb::remove(unsafe { BaseMcb::at(call.arg(1)) }, call.arg(2), call.arg(3))? as u64)
    }

    /// FsRtlLookupBaseMcbEntry(Mcb, Vbn, *Lbn, *SectorCountFromLbn, *StartingLbn,
    /// *SectorCountFromStartingLbn, *Index) -> BOOLEAN.
    fn lookup_entry(call: &Call) -> Result<u64, KernelError> {
        let outputs = mcb::LookupOutputs { lbn: call.arg(3), sector_count_from_lbn: call.arg(4), starting_lbn: call.arg(5), sector_count_from_starting_lbn: call.arg(6), index: call.arg(7) };
        Ok(mcb::lookup(unsafe { BaseMcb::at(call.arg(1)) }, call.arg(2), &outputs) as u64)
    }

    /// FsRtlLookupLastBaseMcbEntry(Mcb, *Vbn, *Lbn) -> BOOLEAN.
    fn lookup_last_entry(call: &Call) -> Result<u64, KernelError> {
        Ok(mcb::lookup_last(unsafe { BaseMcb::at(call.arg(1)) }, call.arg(2), call.arg(3)) as u64)
    }

    /// FsRtlLookupLastBaseMcbEntryAndIndex(Mcb, *Vbn, *Lbn, *Index) -> BOOLEAN.
    fn lookup_last_entry_and_index(call: &Call) -> Result<u64, KernelError> {
        Ok(mcb::lookup_last_and_index(unsafe { BaseMcb::at(call.arg(1)) }, call.arg(2), call.arg(3), call.arg(4)) as u64)
    }

    /// FsRtlGetNextBaseMcbEntry(Mcb, RunIndex, *Vbn, *Lbn, *SectorCount) -> BOOLEAN.
    fn get_next_entry(call: &Call) -> Result<u64, KernelError> {
        Ok(mcb::get_next_entry(unsafe { BaseMcb::at(call.arg(1)) }, call.arg(2) as u32, call.arg(3), call.arg(4), call.arg(5)) as u64)
    }

    pub static GROUP: Group = Group {
        name: "fsrtl-base-mcb",
        names: &[
            "FsRtlInitializeBaseMcbEx",
            "FsRtlUninitializeBaseMcb",
            "FsRtlResetBaseMcb",
            "FsRtlTruncateBaseMcb",
            "FsRtlNumberOfRunsInBaseMcb",
            "FsRtlAddBaseMcbEntryEx",
            "FsRtlAddBaseMcbEntry",
            "FsRtlRemoveBaseMcbEntry",
            "FsRtlLookupBaseMcbEntry",
            "FsRtlLookupLastBaseMcbEntry",
            "FsRtlLookupLastBaseMcbEntryAndIndex",
            "FsRtlGetNextBaseMcbEntry",
        ],
        handlers: &[
            initialize_ex,
            uninitialize,
            reset,
            truncate,
            number_of_runs,
            add_entry_ex,
            add_entry,
            remove_entry,
            lookup_entry,
            lookup_last_entry,
            lookup_last_entry_and_index,
            get_next_entry,
        ],
        data_exports: &[],
    };
}

pub mod fsrtl_large_mcb {
    //! LARGE_MCB (mapeamento VBN -> LBN dos file systems): a lógica mora em
    //! `fsrtl/large_mcb.rs`.

    use crate::ntos::fsrtl::large_mcb;
    use crate::ntos::inc::types::extra_fs_fat::LargeMcb;
    use crate::ntos::inc::types::NtStruct;
    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;

    fn mcb(address: u64) -> &'static LargeMcb {
        // SAFETY: o FS passa o LARGE_MCB do seu FCB.
        unsafe { LargeMcb::at(address) }
    }

    fn initialize(call: &Call) -> Result<u64, KernelError> {
        large_mcb::initialize(mcb(call.arg(1)), call.arg(2) as u32).map(|_| 0)
    }
    fn uninitialize(call: &Call) -> Result<u64, KernelError> {
        large_mcb::uninitialize(mcb(call.arg(1))).map(|_| 0)
    }
    fn add(call: &Call) -> Result<u64, KernelError> {
        large_mcb::add_entry(mcb(call.arg(1)), call.arg(2), call.arg(3), call.arg(4)).map(|added| added as u64)
    }
    fn remove(call: &Call) -> Result<u64, KernelError> {
        large_mcb::remove_entry(mcb(call.arg(1)), call.arg(2), call.arg(3)).map(|_| 0)
    }
    fn lookup(call: &Call) -> Result<u64, KernelError> {
        large_mcb::lookup_entry(mcb(call.arg(1)), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7)).map(|found| found as u64)
    }
    fn lookup_last(call: &Call) -> Result<u64, KernelError> {
        large_mcb::lookup_last_entry(mcb(call.arg(1)), call.arg(2), call.arg(3), call.arg(4)).map(|found| found as u64)
    }
    fn next(call: &Call) -> Result<u64, KernelError> {
        large_mcb::next_entry(mcb(call.arg(1)), call.arg(2) as u32, call.arg(3), call.arg(4), call.arg(5)).map(|found| found as u64)
    }
    fn number_of_runs(call: &Call) -> Result<u64, KernelError> {
        large_mcb::number_of_runs(mcb(call.arg(1))).map(u64::from)
    }
    fn truncate(call: &Call) -> Result<u64, KernelError> {
        large_mcb::truncate(mcb(call.arg(1)), call.arg(2)).map(|_| 0)
    }
    fn reset(call: &Call) -> Result<u64, KernelError> {
        large_mcb::reset(mcb(call.arg(1)), call.arg(2) & 0xFF != 0).map(|_| 0)
    }

    pub static GROUP: Group = Group {
        name: "fsrtl-large-mcb",
        names: &[
            "FsRtlInitializeLargeMcb",
            "FsRtlUninitializeLargeMcb",
            "FsRtlAddLargeMcbEntry",
            "FsRtlRemoveLargeMcbEntry",
            "FsRtlLookupLargeMcbEntry",
            "FsRtlLookupLastLargeMcbEntryAndIndex",
            "FsRtlGetNextLargeMcbEntry",
            "FsRtlNumberOfRunsInLargeMcb",
            "FsRtlTruncateLargeMcb",
            "FsRtlResetLargeMcb",
        ],
        handlers: &[initialize, uninitialize, add, remove, lookup, lookup_last, next, number_of_runs, truncate, reset],
        data_exports: &[],
    };
}

pub mod fsrtl_eof_lock {
    //! Adaptador do EOF lock e do mutex do cabeçalho de FCB (lógica em
    //! `ntos/fsrtl/eof_lock.rs`). ntfs.sys usa estas rotinas em create,
    //! leitura, escrita, set/query information e na criação de SCB.

    use crate::ntos::fsrtl::eof_lock::{self, EofLock};
    use crate::ntos::inc::field::{Field, NtStruct};
    use crate::ntos::inc::types::extra_fsrtl::FsrtlAdvancedFcbHeader;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    /// FsRtlInitializeEofLock(EofLock, AdvancedHeader) -> VOID.
    fn initialize_eof_lock(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: EOF lock e cabeçalho avançado do FCB do file system.
        let (lock, header) = unsafe { (EofLock::at(call.arg(1)), FsrtlAdvancedFcbHeader::at(call.arg(2))) };
        eof_lock::initialize(lock, header);
        Ok(0)
    }

    /// FsRtlAcquireEofLock(EofLock, Counter) -> VOID.
    fn acquire_eof_lock(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: EOF lock inicializado e PULONG opcional do file system.
        let (lock, counter) = unsafe { (EofLock::at(call.arg(1)), eof_lock::optional_counter(call.arg(2))) };
        eof_lock::acquire(lock, counter)?;
        Ok(0)
    }

    /// FsRtlReleaseEofLock(EofLock, Counter) -> VOID.
    fn release_eof_lock(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: idem.
        let (lock, counter) = unsafe { (EofLock::at(call.arg(1)), eof_lock::optional_counter(call.arg(2))) };
        eof_lock::release(lock, counter)?;
        Ok(0)
    }

    /// FsRtlAcquireHeaderMutex(EofLock, Counter) -> VOID.
    fn acquire_header_mutex(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: idem.
        let (lock, counter) = unsafe { (EofLock::at(call.arg(1)), eof_lock::optional_counter(call.arg(2))) };
        eof_lock::acquire_header_mutex(lock, counter)?;
        Ok(0)
    }

    /// FsRtlReleaseHeaderMutex(EofLock, Counter) -> VOID.
    fn release_header_mutex(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: idem.
        let (lock, counter) = unsafe { (EofLock::at(call.arg(1)), eof_lock::optional_counter(call.arg(2))) };
        eof_lock::release_header_mutex(lock, counter)?;
        Ok(0)
    }

    /// FsRtlTryToAcquireHeaderMutex(EofLock, Counter) -> BOOLEAN.
    fn try_to_acquire_header_mutex(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: idem.
        let (lock, counter) = unsafe { (EofLock::at(call.arg(1)), eof_lock::optional_counter(call.arg(2))) };
        Ok(eof_lock::try_to_acquire_header_mutex(lock, counter)? as u64)
    }

    /// FsRtlGetIoAtEof(EofLock, Counter, StartingOffset, Length, Wait,
    /// *IoAtEof) -> NTSTATUS.
    fn get_io_at_eof(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: EOF lock, PULONG opcional e o PBOOLEAN de saída do file system.
        let (lock, counter, io_at_eof) = unsafe { (EofLock::at(call.arg(1)), eof_lock::optional_counter(call.arg(2)), Field::<u8>::at(call.arg(6))) };
        let status = eof_lock::get_io_at_eof(lock, counter, call.arg(3) as i64, call.arg(4), call.arg(5) as u8 != 0, io_at_eof)?;
        Ok(signed_status(status))
    }

    pub static GROUP: Group = Group {
        name: "fsrtl-eof-lock",
        names: &[
            "FsRtlInitializeEofLock",
            "FsRtlAcquireEofLock",
            "FsRtlReleaseEofLock",
            "FsRtlAcquireHeaderMutex",
            "FsRtlReleaseHeaderMutex",
            "FsRtlTryToAcquireHeaderMutex",
            "FsRtlGetIoAtEof",
        ],
        handlers: &[
            initialize_eof_lock,
            acquire_eof_lock,
            release_eof_lock,
            acquire_header_mutex,
            release_header_mutex,
            try_to_acquire_header_mutex,
            get_io_at_eof,
        ],
        data_exports: &[],
    };
}

pub mod fsrtl_fast_io {
    //! Adaptador dos contadores de leitura rápida do Cc e do MDL read /
    //! prepare MDL write "Ex" (lógica em `ntos/fsrtl/fast_io.rs`).
    //! ntfs.sys: NtfsCopyReadA/NtfsMdlReadA (contadores) e
    //! NtfsFlushStreamThroughCache (MdlReadEx/PrepareMdlWriteEx).

    use crate::ntos::fsrtl::fast_io::{self, CacheCounter};
    use crate::ntos::inc::field::{Field, NtStruct};
    use crate::ntos::inc::types::{FileObject, IoStatusBlock};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    fn increment_fast_mdl_read_wait(_: &Call) -> Result<u64, KernelError> {
        fast_io::increment(CacheCounter::FastMdlReadWait);
        Ok(0)
    }

    fn increment_fast_read_no_wait(_: &Call) -> Result<u64, KernelError> {
        fast_io::increment(CacheCounter::FastReadNoWait);
        Ok(0)
    }

    fn increment_fast_read_not_possible(_: &Call) -> Result<u64, KernelError> {
        fast_io::increment(CacheCounter::FastReadNotPossible);
        Ok(0)
    }

    fn increment_fast_read_resource_miss(_: &Call) -> Result<u64, KernelError> {
        fast_io::increment(CacheCounter::FastReadResourceMiss);
        Ok(0)
    }

    fn increment_fast_read_wait(_: &Call) -> Result<u64, KernelError> {
        fast_io::increment(CacheCounter::FastReadWait);
        Ok(0)
    }

    /// FsRtlMdlReadEx(FileObject, FileOffset, Length, LockKey, MdlChain, IoStatus) -> NTSTATUS.
    fn mdl_read_ex(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: FILE_OBJECT, PMDL* e IO_STATUS_BLOCK do file system (modo kernel).
        let (file_object, mdl_chain, io_status) = unsafe { (FileObject::at(call.arg(1)), Field::<u64>::at(call.arg(5)), IoStatusBlock::at(call.arg(6))) };
        let status = fast_io::mdl_read_ex(file_object, call.arg(2), call.arg(3) as u32, call.arg(4) as u32, mdl_chain, io_status)?;
        Ok(signed_status(status))
    }

    /// FsRtlPrepareMdlWriteEx(FileObject, FileOffset, Length, LockKey, MdlChain, IoStatus) -> NTSTATUS.
    fn prepare_mdl_write_ex(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: idem.
        let (file_object, mdl_chain, io_status) = unsafe { (FileObject::at(call.arg(1)), Field::<u64>::at(call.arg(5)), IoStatusBlock::at(call.arg(6))) };
        let status = fast_io::prepare_mdl_write_ex(file_object, call.arg(2), call.arg(3) as u32, call.arg(4) as u32, mdl_chain, io_status)?;
        Ok(signed_status(status))
    }

    pub static GROUP: Group = Group {
        name: "fsrtl-fast-io",
        names: &[
            "FsRtlIncrementCcFastMdlReadWait",
            "FsRtlIncrementCcFastReadNoWait",
            "FsRtlIncrementCcFastReadNotPossible",
            "FsRtlIncrementCcFastReadResourceMiss",
            "FsRtlIncrementCcFastReadWait",
            "FsRtlMdlReadEx",
            "FsRtlPrepareMdlWriteEx",
        ],
        handlers: &[
            increment_fast_mdl_read_wait,
            increment_fast_read_no_wait,
            increment_fast_read_not_possible,
            increment_fast_read_resource_miss,
            increment_fast_read_wait,
            mdl_read_ex,
            prepare_mdl_write_ex,
        ],
        data_exports: &[],
    };
}

pub mod fsrtl_heat {
    //! Adaptador do calor de E/S do Storage Tiering (lógica em
    //! `ntos/fsrtl/heat.rs`). ntfs.sys: NtfsUpdateTieringInfo (Init),
    //! NtfsHeatLogIo/NtfsCommonCleanup (LogIo), NtfsDeleteVcb (Uninit).

    use crate::ntos::fsrtl::heat::{self, HeatInfo};
    use crate::ntos::inc::field::NtStruct;
    use crate::ntos::inc::types::{Guid, Irp};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    /// FsRtlHeatInit(HeatInfo, VolumeGuid, VolumeContext) -> NTSTATUS.
    fn heat_init(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: HEAT_INFO e GUID do volume no VCB do file system.
        let (info, guid) = unsafe { (HeatInfo::at(call.arg(1)), Guid::at(call.arg(2))) };
        Ok(signed_status(heat::heat_init(info, guid)?))
    }

    /// FsRtlHeatUninit(HeatInfo, VolumeGuid) -> VOID.
    fn heat_uninit(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: GUID do volume no VCB do file system.
        heat::heat_uninit(unsafe { Guid::at(call.arg(2)) });
        Ok(0)
    }

    /// FsRtlHeatLogIo(HeatInfo, Irp, FileContext, Extra) -> NTSTATUS.
    fn heat_log_io(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: IRP que o file system está tratando.
        Ok(signed_status(heat::heat_log_io(unsafe { Irp::at(call.arg(2)) })))
    }

    pub static GROUP: Group = Group {
        name: "fsrtl-heat",
        names: &["FsRtlHeatInit", "FsRtlHeatLogIo", "FsRtlHeatUninit"],
        handlers: &[heat_init, heat_log_io, heat_uninit],
        data_exports: &[],
    };
}

pub mod fsrtl_oplock_ex {
    //! Adaptador de FsRtlCheckOplockEx2 e FsRtlOplockGetAnyBreakOwnerProcess
    //! (lógica no assunto `ntos/fsrtl/oplock.rs`, modelo "nenhum oplock
    //! concedido" do grupo irmão fsrtl-oplocks). ntfs.sys chama CheckOplockEx2
    //! em create, cleanup, close e zero-range.

    use crate::ntos::fsrtl::oplock;
    use crate::ntos::inc::field::{Field, NtStruct};
    use crate::ntos::inc::types::Irp;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    /// FsRtlCheckOplockEx2(Oplock, Irp, Flags, FlagsEx2, ...) -> NTSTATUS.
    fn check_oplock_ex2(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: o POPLOCK (handle opaco) embutido no FCB e o IRP (ou NULL) do file system.
        let (handle, irp) = unsafe { (Field::<u64>::at(call.arg(1)), (call.arg(2) != 0).then(|| Irp::at(call.arg(2)))) };
        Ok(signed_status(oplock::check_oplock_ex2(handle, irp, call.arg(3) as u32, call.arg(4) as u32)))
    }

    /// FsRtlOplockGetAnyBreakOwnerProcess(Oplock) -> PEPROCESS.
    fn oplock_get_any_break_owner_process(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: POPLOCK do file system ou NULL.
        let handle = unsafe { (call.arg(1) != 0).then(|| Field::<u64>::at(call.arg(1))) };
        oplock::any_break_owner_process(handle)
    }

    pub static GROUP: Group = Group {
        name: "fsrtl-oplock-ex",
        names: &["FsRtlCheckOplockEx2", "FsRtlOplockGetAnyBreakOwnerProcess"],
        handlers: &[check_oplock_ex2, oplock_get_any_break_owner_process],
        data_exports: &[],
    };
}

pub mod fsrtl_per_file_teardown {
    //! Adaptador de FsRtlTeardownPerFileContexts (lógica no assunto
    //! `ntos/fsrtl/filter_context.rs` do grupo irmão fsrtl-filter-contexts).
    //! ntfs.sys chama em NtfsDeleteFcb.

    use crate::ntos::fsrtl::filter_context;
    use crate::ntos::inc::field::{Field, NtStruct};
    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;

    /// FsRtlTeardownPerFileContexts(PerFileContextPointer) -> VOID.
    fn teardown_per_file_contexts(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: o PVOID* FileContextSupportPointer do FCB do file system.
        filter_context::teardown_per_file_contexts(unsafe { Field::<u64>::at(call.arg(1)) })?;
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "fsrtl-per-file-teardown",
        names: &["FsRtlTeardownPerFileContexts"],
        handlers: &[teardown_per_file_contexts],
        data_exports: &[],
    };
}

pub mod fsrtl_tunnel_cache {
    //! FsRtl*TunnelCache: a lógica mora em `fsrtl/tunnel.rs`.

    use crate::ntos::fsrtl::tunnel;
    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;

    fn initialize(call: &Call) -> Result<u64, KernelError> {
        tunnel::initialize(call.arg(1));
        Ok(0)
    }
    fn add(call: &Call) -> Result<u64, KernelError> {
        tunnel::add(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5) & 0xFF != 0, call.arg(6) as u32, call.arg(7)).map(|_| 0)
    }
    fn find(call: &Call) -> Result<u64, KernelError> {
        tunnel::find(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7)).map(|found| found as u64)
    }
    fn delete_key(call: &Call) -> Result<u64, KernelError> {
        tunnel::delete_key(call.arg(1), call.arg(2)).map(|_| 0)
    }
    fn delete(call: &Call) -> Result<u64, KernelError> {
        tunnel::delete_cache(call.arg(1));
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "fsrtl-tunnel-cache",
        names: &["FsRtlInitializeTunnelCache", "FsRtlAddToTunnelCache", "FsRtlFindInTunnelCache", "FsRtlDeleteKeyFromTunnelCache", "FsRtlDeleteTunnelCache"],
        handlers: &[initialize, add, find, delete_key, delete],
        data_exports: &[],
    };
}

pub mod fsrtl_tunnel {
    //! Adaptador do cache de tunelamento — as rotinas Ex (motor em
    //! `ntos/fsrtl/tunnel.rs`, compartilhado com o grupo das rotinas
    //! clássicas). ntfs.sys: NtfsSetRenameInfo, NtfsCommonCleanup,
    //! NtfsCreateNewFile, NtfsRenameToPrivateDir.

    use crate::ntos::fsrtl::tunnel;
    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;

    /// FsRtlAddToTunnelCacheEx(Cache, DirectoryKey, ShortName, LongName,
    /// Flags, DataLength, Data) -> VOID.
    fn add_to_tunnel_cache_ex(call: &Call) -> Result<u64, KernelError> {
        tunnel::add_ex(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5) as u32, call.arg(6) as u32, call.arg(7))?;
        Ok(0)
    }

    /// FsRtlFindInTunnelCacheEx(Cache, DirectoryKey, Name, ShortName, LongName,
    /// Flags, DataLength, Data) -> BOOLEAN.
    fn find_in_tunnel_cache_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(tunnel::find_ex(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6) as u32, call.arg(7), call.arg(8))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "fsrtl-tunnel",
        names: &["FsRtlAddToTunnelCacheEx", "FsRtlFindInTunnelCacheEx"],
        handlers: &[add_to_tunnel_cache_ex, find_in_tunnel_cache_ex],
        data_exports: &[],
    };
}

pub mod fsrtl_file_lock_irp {
    //! IRP_MJ_LOCK_CONTROL e consultas do FILE_LOCK: a lógica mora em `fsrtl/file_lock.rs`.

    use crate::ntos::fsrtl::file_lock;
    use crate::ntos::inc::types::extra_fsrtl::FileLock;
    use crate::ntos::inc::types::{Irp, LargeInteger, NtStruct};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    // SAFETY (todas): o FS passa o FILE_LOCK do seu FCB, o IRP que está
    // processando e um PLARGE_INTEGER de kernel.
    fn file_lock(address: u64) -> &'static FileLock {
        unsafe { FileLock::at(address) }
    }
    fn irp(address: u64) -> &'static Irp {
        unsafe { Irp::at(address) }
    }

    fn process(call: &Call) -> Result<u64, KernelError> {
        file_lock::process_file_lock(file_lock(call.arg(1)), irp(call.arg(2)), call.arg(3)).map(signed_status)
    }
    fn read_access(call: &Call) -> Result<u64, KernelError> {
        file_lock::check_lock_for_irp(file_lock(call.arg(1)), irp(call.arg(2)), false).map(|granted| granted as u64)
    }
    fn write_access(call: &Call) -> Result<u64, KernelError> {
        file_lock::check_lock_for_irp(file_lock(call.arg(1)), irp(call.arg(2)), true).map(|granted| granted as u64)
    }
    fn oplock_request(call: &Call) -> Result<u64, KernelError> {
        Ok(file_lock::check_lock_for_oplock_request(file_lock(call.arg(1)), unsafe { LargeInteger::at(call.arg(2)) }) as u64)
    }
    fn current_or_in_progress(call: &Call) -> Result<u64, KernelError> {
        Ok(file_lock::current_or_in_progress_locks(file_lock(call.arg(1))) as u64)
    }
    fn waiting(call: &Call) -> Result<u64, KernelError> {
        Ok(file_lock::waiting_locks((call.arg(1) != 0).then(|| file_lock(call.arg(1)))) as u64)
    }

    pub static GROUP: Group = Group {
        name: "fsrtl-file-lock-irp",
        names: &[
            "FsRtlProcessFileLock",
            "FsRtlCheckLockForReadAccess",
            "FsRtlCheckLockForWriteAccess",
            "FsRtlCheckLockForOplockRequest",
            "FsRtlAreThereCurrentOrInProgressFileLocks",
            "FsRtlAreThereWaitingFileLocks",
        ],
        handlers: &[process, read_access, write_access, oplock_request, current_or_in_progress, waiting],
        data_exports: &[],
    };
}

pub mod fsrtl_notify {
    //! FsRtlNotify*: a lógica mora em `fsrtl/notify.rs`.

    use crate::ntos::fsrtl::notify::{self, ChangeDirectory, ReportChange};
    use crate::ntos::inc::field::Field;
    use crate::ntos::inc::types::{Irp, ListEntry, NtStruct};
    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;

    // SAFETY (todas): o FS passa o PNOTIFY_SYNC (célula ou valor), a cabeça
    // NotifyList do seu VCB e o IRP de IRP_MN_NOTIFY_CHANGE_DIRECTORY vivos.
    fn cell(address: u64) -> &'static Field<u64> {
        unsafe { Field::<u64>::at(address) }
    }
    fn list(address: u64) -> &'static ListEntry {
        unsafe { ListEntry::at(address) }
    }

    fn initialize_sync(call: &Call) -> Result<u64, KernelError> {
        notify::initialize_sync(cell(call.arg(1))).map(|_| 0)
    }
    fn uninitialize_sync(call: &Call) -> Result<u64, KernelError> {
        notify::uninitialize_sync(cell(call.arg(1))).map(|_| 0)
    }
    fn change_directory(call: &Call, filter_callback: u64) -> Result<u64, KernelError> {
        notify::filter_change_directory(&ChangeDirectory {
            notify_sync: call.arg(1),
            notify_list: list(call.arg(2)),
            fs_context: call.arg(3),
            full_directory_name: call.arg(4),
            watch_tree: call.arg(5) & 0xFF != 0,
            ignore_buffer: call.arg(6) & 0xFF != 0,
            completion_filter: call.arg(7) as u32,
            irp: (call.arg(8) != 0).then(|| unsafe { Irp::at(call.arg(8)) }),
            traverse_callback: call.arg(9),
            subject_context: call.arg(10),
            filter_callback,
        })
        .map(|_| 0)
    }
    fn filter_change_directory(call: &Call) -> Result<u64, KernelError> {
        change_directory(call, call.arg(11))
    }
    fn full_change_directory(call: &Call) -> Result<u64, KernelError> {
        change_directory(call, 0)
    }
    fn full_report_change(call: &Call) -> Result<u64, KernelError> {
        notify::full_report_change(&ReportChange {
            notify_sync: call.arg(1),
            notify_list: list(call.arg(2)),
            full_target_name: call.arg(3),
            target_name_offset: call.arg(4) as u16,
            stream_name: call.arg(5),
            normalized_parent_name: call.arg(6),
            filter_match: call.arg(7) as u32,
            action: call.arg(8) as u32,
            target_context: call.arg(9),
            filter_context: 0,
        })
        .map(|_| 0)
    }
    fn cleanup(call: &Call) -> Result<u64, KernelError> {
        notify::cleanup(call.arg(1), list(call.arg(2)), call.arg(3)).map(|_| 0)
    }

    pub static GROUP: Group = Group {
        name: "fsrtl-notify",
        names: &[
            "FsRtlNotifyInitializeSync",
            "FsRtlNotifyUninitializeSync",
            "FsRtlNotifyFilterChangeDirectory",
            "FsRtlNotifyFullChangeDirectory",
            "FsRtlNotifyFullReportChange",
            "FsRtlNotifyCleanup",
        ],
        handlers: &[initialize_sync, uninitialize_sync, filter_change_directory, full_change_directory, full_report_change, cleanup],
        data_exports: &[],
    };
}

pub mod fsrtl_volume_support {
    //! Nomes FAT/Unicode, estado de volume, contadores, MDL "Dev", teardown de
    //! contextos por stream e o FSCTL de oplock: a lógica mora nos assuntos do fsrtl.

    use crate::ntos::fsrtl::{fast_io, filter_context, name, oplock, volume_support};
    use crate::ntos::inc::field::Field;
    use crate::ntos::inc::types::extra_fsrtl::FsrtlAdvancedFcbHeader;
    use crate::ntos::inc::types::{FileObject, Irp, NtStruct, ObjectAttributes, String as AnsiString, UnicodeString};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::mm::guest_memory as guest;
    use crate::rtl::KernelError;

    // SAFETY (todas): o FS passa UNICODE_STRING/ANSI_STRING, FILE_OBJECT, IRP,
    // cabeçalho avançado do FCB e células de saída de kernel vivos.
    fn file(address: u64) -> &'static FileObject {
        unsafe { FileObject::at(address) }
    }

    fn are_names_equal(call: &Call) -> Result<u64, KernelError> {
        let (first, second) = unsafe { (UnicodeString::at(call.arg(1)), UnicodeString::at(call.arg(2))) };
        name::are_names_equal(first, second, call.arg(3) & 0xFF != 0, call.arg(4)).map(|equal| equal as u64)
    }
    fn is_fat_dbcs_legal(call: &Call) -> Result<u64, KernelError> {
        let string = unsafe { AnsiString::at(call.arg(1)) };
        let bytes = guest::read_bytes(string.buffer.get(), string.length.get() as usize);
        Ok(name::is_fat_dbcs_legal(&bytes, call.arg(2) & 0xFF != 0, call.arg(3) & 0xFF != 0, call.arg(4) & 0xFF != 0) as u64)
    }
    fn startup_applications_complete(_: &Call) -> Result<u64, KernelError> {
        Ok(volume_support::startup_applications_complete() as u64)
    }
    fn dismount_complete(call: &Call) -> Result<u64, KernelError> {
        volume_support::dismount_complete(call.arg(2) as u32);
        Ok(0)
    }
    fn update_disk_counters(call: &Call) -> Result<u64, KernelError> {
        volume_support::update_disk_counters(call.arg(1), call.arg(2));
        Ok(0)
    }
    fn post_stack_overflow(call: &Call) -> Result<u64, KernelError> {
        volume_support::post_stack_overflow(call.arg(1), call.arg(2), call.arg(3));
        Ok(0)
    }
    fn mdl_read_complete_dev(call: &Call) -> Result<u64, KernelError> {
        Ok(fast_io::mdl_read_complete_dev(file(call.arg(1)), call.arg(2)) as u64)
    }
    fn mdl_write_complete_dev(call: &Call) -> Result<u64, KernelError> {
        fast_io::mdl_write_complete_dev(file(call.arg(1)), call.arg(2), call.arg(3)).map(|done| done as u64)
    }
    fn oplock_fsctrl(call: &Call) -> Result<u64, KernelError> {
        let (oplock, irp) = unsafe { (Field::<u64>::at(call.arg(1)), Irp::at(call.arg(2))) };
        Ok(signed_status(oplock::oplock_fsctrl_ex(oplock, irp, call.arg(3) as u32, 0)))
    }
    fn teardown_per_stream_contexts(call: &Call) -> Result<u64, KernelError> {
        filter_context::teardown_per_stream_contexts(unsafe { FsrtlAdvancedFcbHeader::at(call.arg(1)) }).map(|_| 0)
    }
    fn create_section_for_data_scan(call: &Call) -> Result<u64, KernelError> {
        let cell = |address: u64| unsafe { Field::<u64>::at(address) };
        volume_support::create_section_for_data_scan(&volume_support::DataScanSection {
            section_handle: cell(call.arg(1)),
            section_object: cell(call.arg(2)),
            section_file_size: (call.arg(3) != 0).then(|| cell(call.arg(3))),
            file_object: file(call.arg(4)),
            desired_access: call.arg(5) as u32,
            object_attributes: (call.arg(6) != 0).then(|| unsafe { ObjectAttributes::at(call.arg(6)) }),
            protection: call.arg(8) as u32,
            allocation: call.arg(9) as u32,
        })
        .map(signed_status)
    }

    pub static GROUP: Group = Group {
        name: "fsrtl-volume-support",
        names: &[
            "FsRtlAreNamesEqual",
            "FsRtlIsFatDbcsLegal",
            "FsRtlAreVolumeStartupApplicationsComplete",
            "FsRtlDismountComplete",
            "FsRtlUpdateDiskCounters",
            "FsRtlPostStackOverflow",
            "FsRtlPostPagingFileStackOverflow",
            "FsRtlMdlReadCompleteDev",
            "FsRtlMdlWriteCompleteDev",
            "FsRtlOplockFsctrl",
            "FsRtlTeardownPerStreamContexts",
            "FsRtlCreateSectionForDataScan",
        ],
        handlers: &[
            are_names_equal,
            is_fat_dbcs_legal,
            startup_applications_complete,
            dismount_complete,
            update_disk_counters,
            post_stack_overflow,
            post_stack_overflow,
            mdl_read_complete_dev,
            mdl_write_complete_dev,
            oplock_fsctrl,
            teardown_per_stream_contexts,
            create_section_for_data_scan,
        ],
        data_exports: &[],
    };
}

pub mod fsrtl_status {
    use crate::ntos::fsrtl::ntstatus;
    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;

    fn is_total_device_failure(call: &Call) -> Result<u64, KernelError> {
        Ok(ntstatus::is_total_device_failure(call.arg(1) as u32) as u64)
    }

    pub static GROUP: Group = Group { name: "fsrtl-status", names: &["FsRtlIsTotalDeviceFailure"], handlers: &[is_total_device_failure], data_exports: &[] };
}

pub mod fsrtl_cached_fast_io {
    //! O Fast I/O genérico em cache (FsRtlCopyRead/CopyWrite, MdlReadDev,
    //! PrepareMdlWriteDev) e os repasses FsRtlMdlRead/MdlReadComplete: a
    //! lógica mora em `fsrtl/fast_io.rs`.

    use crate::ntos::fsrtl::fast_io;
    use crate::ntos::inc::field::Field;
    use crate::ntos::inc::types::{DeviceObject, FileObject, IoStatusBlock, NtStruct};
    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;

    // SAFETY (todas): FILE_OBJECT, IO_STATUS_BLOCK, PMDL* e DEVICE_OBJECT
    // vivos do file system (modo kernel).
    fn file(address: u64) -> &'static FileObject {
        unsafe { FileObject::at(address) }
    }
    fn io_status(address: u64) -> &'static IoStatusBlock {
        unsafe { IoStatusBlock::at(address) }
    }
    fn device(address: u64) -> &'static DeviceObject {
        unsafe { DeviceObject::at(address) }
    }

    /// FsRtlCopyRead(FileObject, FileOffset, Length, Wait, LockKey, Buffer, IoStatus, DeviceObject).
    fn copy_read(call: &Call) -> Result<u64, KernelError> {
        Ok(fast_io::copy_read(file(call.arg(1)), call.arg(2), call.arg(3) as u32, call.arg(4) & 0xFF != 0, call.arg(5) as u32, call.arg(6), io_status(call.arg(7)), device(call.arg(8)))? as u64)
    }

    /// FsRtlCopyWrite(FileObject, FileOffset, Length, Wait, LockKey, Buffer, IoStatus, DeviceObject).
    fn copy_write(call: &Call) -> Result<u64, KernelError> {
        Ok(fast_io::copy_write(file(call.arg(1)), call.arg(2), call.arg(3) as u32, call.arg(4) & 0xFF != 0, call.arg(5) as u32, call.arg(6), io_status(call.arg(7)), device(call.arg(8)))? as u64)
    }

    /// FsRtlMdlReadDev(FileObject, FileOffset, Length, LockKey, MdlChain, IoStatus, DeviceObject).
    fn mdl_read_dev(call: &Call) -> Result<u64, KernelError> {
        Ok(fast_io::mdl_read_dev(file(call.arg(1)), call.arg(2), call.arg(3) as u32, call.arg(4) as u32, call.arg(5), io_status(call.arg(6)), device(call.arg(7)))? as u64)
    }

    /// FsRtlPrepareMdlWriteDev(FileObject, FileOffset, Length, LockKey, MdlChain, IoStatus, DeviceObject).
    fn prepare_mdl_write_dev(call: &Call) -> Result<u64, KernelError> {
        Ok(fast_io::prepare_mdl_write_dev(file(call.arg(1)), call.arg(2), call.arg(3) as u32, call.arg(4) as u32, call.arg(5), io_status(call.arg(6)), device(call.arg(7)))? as u64)
    }

    /// FsRtlMdlRead(FileObject, FileOffset, Length, LockKey, MdlChain, IoStatus).
    fn mdl_read(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: o PMDL* do chamador.
        let chain = unsafe { Field::<u64>::at(call.arg(5)) };
        Ok(fast_io::mdl_read(file(call.arg(1)), call.arg(2), call.arg(3) as u32, call.arg(4) as u32, chain, io_status(call.arg(6)))? as u64)
    }

    /// FsRtlMdlReadComplete(FileObject, MdlChain).
    fn mdl_read_complete(call: &Call) -> Result<u64, KernelError> {
        Ok(fast_io::mdl_read_complete(file(call.arg(1)), call.arg(2))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "fsrtl-cached-fast-io",
        names: &["FsRtlCopyRead", "FsRtlCopyWrite", "FsRtlMdlReadDev", "FsRtlPrepareMdlWriteDev", "FsRtlMdlRead", "FsRtlMdlReadComplete"],
        handlers: &[copy_read, copy_write, mdl_read_dev, prepare_mdl_write_dev, mdl_read, mdl_read_complete],
        data_exports: &[],
    };
}

pub mod fsrtl_volume_event {
    //! FsRtlNotifyVolumeEvent(Ex): a lógica mora em `fsrtl/volume_support.rs`.

    use crate::ntos::fsrtl::volume_support;
    use crate::ntos::inc::types::{FileObject, NtStruct};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    /// FsRtlNotifyVolumeEvent(FileObject, EventCode).
    fn notify_volume_event(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: FILE_OBJECT do volume (modo kernel).
        Ok(signed_status(volume_support::notify_volume_event(unsafe { FileObject::at(call.arg(1)) }, call.arg(2) as u32)?))
    }

    /// FsRtlNotifyVolumeEventEx(FileObject, EventCode, Event).
    fn notify_volume_event_ex(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: idem.
        Ok(signed_status(volume_support::notify_volume_event_ex(unsafe { FileObject::at(call.arg(1)) }, call.arg(2) as u32, call.arg(3))?))
    }

    pub static GROUP: Group = Group { name: "fsrtl-volume-event", names: &["FsRtlNotifyVolumeEvent", "FsRtlNotifyVolumeEventEx"], handlers: &[notify_volume_event, notify_volume_event_ex], data_exports: &[] };
}

pub mod fsrtl_device_queries {
    //! FsRtlBalanceReads e FsRtlGetSectorSizeInformation: a lógica mora em
    //! `fsrtl/device_control.rs`.

    use crate::ntos::fsrtl::device_control::{self, FileFsSectorSizeInformation};
    use crate::ntos::inc::types::{DeviceObject, NtStruct};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    /// FsRtlBalanceReads(TargetDevice).
    fn balance_reads(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: DEVICE_OBJECT alvo do file system.
        Ok(signed_status(device_control::balance_reads(unsafe { DeviceObject::at(call.arg(1)) })))
    }

    /// FsRtlGetSectorSizeInformation(DeviceObject, SectorSizeInfo).
    fn get_sector_size_information(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: DEVICE_OBJECT e FILE_FS_SECTOR_SIZE_INFORMATION do file system.
        let (device, info) = unsafe { (DeviceObject::at(call.arg(1)), FileFsSectorSizeInformation::at(call.arg(2))) };
        Ok(signed_status(device_control::get_sector_size_information(device, info)))
    }

    pub static GROUP: Group = Group { name: "fsrtl-device-queries", names: &["FsRtlBalanceReads", "FsRtlGetSectorSizeInformation"], handlers: &[balance_reads, get_sector_size_information], data_exports: &[] };
}

pub mod fsrtl_oplock_filter {
    //! FsRtlCheckOplockForFsFilterCallback: a lógica mora em `fsrtl/oplock.rs`.

    use crate::ntos::fsrtl::oplock::{self, FsFilterCallbackData};
    use crate::ntos::inc::field::Field;
    use crate::ntos::inc::types::NtStruct;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    /// FsRtlCheckOplockForFsFilterCallback(Oplock, CallbackData, Flags).
    fn check_oplock_for_fs_filter_callback(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: POPLOCK e FS_FILTER_CALLBACK_DATA do file system.
        let (handle, data) = unsafe { (Field::<u64>::at(call.arg(1)), FsFilterCallbackData::at(call.arg(2))) };
        Ok(signed_status(oplock::check_oplock_for_fs_filter_callback(handle, data, call.arg(3) as u32)?))
    }

    pub static GROUP: Group = Group { name: "fsrtl-oplock-filter", names: &["FsRtlCheckOplockForFsFilterCallback"], handlers: &[check_oplock_for_fs_filter_callback], data_exports: &[] };
}

pub mod fsrtl_notify_filter {
    //! FsRtlNotifyFilterReportChange e a variante Lite: a lógica mora em
    //! `fsrtl/notify.rs`.

    use crate::ntos::fsrtl::notify::{self, ChangeDirectoryLite, ReportChange, ReportChangeLite};
    use crate::ntos::inc::field::Field;
    use crate::ntos::inc::types::{Irp, ListEntry, NtStruct};
    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;

    // SAFETY (todas): PNOTIFY_SYNC (célula ou valor), NotifyList e IRP vivos do FS.
    fn cell(address: u64) -> &'static Field<u64> {
        unsafe { Field::<u64>::at(address) }
    }
    fn list(address: u64) -> &'static ListEntry {
        unsafe { ListEntry::at(address) }
    }

    /// FsRtlNotifyFilterReportChange(NotifySync, NotifyList, FullTargetName,
    /// TargetNameOffset, StreamName, NormalizedParentName, FilterMatch,
    /// Action, TargetContext, FilterContext).
    fn filter_report_change(call: &Call) -> Result<u64, KernelError> {
        notify::full_report_change(&ReportChange {
            notify_sync: call.arg(1),
            notify_list: list(call.arg(2)),
            full_target_name: call.arg(3),
            target_name_offset: call.arg(4) as u16,
            stream_name: call.arg(5),
            normalized_parent_name: call.arg(6),
            filter_match: call.arg(7) as u32,
            action: call.arg(8) as u32,
            target_context: call.arg(9),
            filter_context: call.arg(10),
        })
        .map(|_| 0)
    }

    /// FsRtlNotifyFilterChangeDirectoryLite(NotifySync*, NotifyList,
    /// FsContext, Flags, CompletionFilter, NotifyIrp, TraverseCallback,
    /// SubjectContext, FilterCallback).
    fn filter_change_directory_lite(call: &Call) -> Result<u64, KernelError> {
        notify::filter_change_directory_lite(&ChangeDirectoryLite {
            notify_sync: cell(call.arg(1)),
            notify_list: list(call.arg(2)),
            fs_context: call.arg(3),
            flags: call.arg(4) as u32,
            completion_filter: call.arg(5) as u32,
            irp: (call.arg(6) != 0).then(|| unsafe { Irp::at(call.arg(6)) }),
            traverse_callback: call.arg(7),
            subject_context: call.arg(8),
            filter_callback: call.arg(9),
        })
        .map(|_| 0)
    }

    /// FsRtlNotifyFilterReportChangeLiteEx(NotifySync*, NotifyList, Name,
    /// StreamName, FilterMatch, Action, TargetContext, FilterContext, Flags,
    /// ExtendedInformation).
    fn filter_report_change_lite(call: &Call) -> Result<u64, KernelError> {
        notify::filter_report_change_lite(&ReportChangeLite {
            notify_sync: cell(call.arg(1)),
            notify_list: list(call.arg(2)),
            name: call.arg(3),
            stream_name: call.arg(4),
            filter_match: call.arg(5) as u32,
            action: call.arg(6) as u32,
            target_context: call.arg(7),
            filter_context: call.arg(8),
            flags: call.arg(9) as u32,
            extended_information: call.arg(10),
        })
        .map(|_| 0)
    }

    pub static GROUP: Group = Group {
        name: "fsrtl-notify-filter",
        names: &["FsRtlNotifyFilterReportChange", "FsRtlNotifyFilterChangeDirectoryLite", "FsRtlNotifyFilterReportChangeLiteEx"],
        handlers: &[filter_report_change, filter_change_directory_lite, filter_report_change_lite],
        data_exports: &[],
    };
}

pub mod fsrtl_dbcs_expression {
    //! FsRtlIsDbcsInExpression; a lógica mora em `fsrtl/name`.

    use crate::ntos::fsrtl::name;
    use crate::ntos::inc::types::{NtStruct, String as AnsiString};
    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;

    /// FsRtlIsDbcsInExpression(Expression, Name) -> BOOLEAN.
    fn is_dbcs_in_expression(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: os dois ANSI_STRING do chamador.
        let (expression, file_name) = unsafe { (AnsiString::at(call.arg(1)), AnsiString::at(call.arg(2))) };
        Ok(name::is_dbcs_in_expression_strings(expression, file_name) as u64)
    }

    pub static GROUP: Group = Group { name: "fsrtl-dbcs-expression", names: &["FsRtlIsDbcsInExpression"], handlers: &[is_dbcs_in_expression], data_exports: &[] };
}
