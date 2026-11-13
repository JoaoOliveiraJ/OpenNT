//! Consultas do FsRtl — `system32/win32/ntoskrnl/fsrtl.js`.
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
    //! FsRtlQuery/SetKernelEaFile — `system32/win32/ntoskrnl/file-information.js`.
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
    //! FsRtlGetFileNameInformation — `system32/win32/ntoskrnl/file-name-information.js`.

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
    //! FsRtlReleaseFileNameInformation — `system32/win32/ntoskrnl/release-file-name-information.js`.

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
