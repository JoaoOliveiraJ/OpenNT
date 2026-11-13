//! Módulos pequenos do FsRtl (como `io/small.rs`), do ntoskrnl 10.0.19045:
//!
//! - `paging_file` — FsRtlIsPagingFile (RVA 0x3023a0)
//! - `mobile_os` — FsRtlIsMobileOS (RVA 0x6a6490)
//! - `driver_backing` — FsRtlSetDriverBacking (RVA 0x780880)
//! - `app_termination` — FsRtlSendModernAppTermination (RVA 0x3c0110)

/// O FCB do FILE_OBJECT marcado como arquivo de paginação.
pub mod paging_file {
    use crate::ntos::inc::field::NtStruct;
    use crate::ntos::inc::types::extra_fsrtl::FsrtlCommonFcbHeader;
    use crate::ntos::inc::types::FileObject;

    /// FSRTL_COMMON_FCB_HEADER.Flags2: FSRTL_FLAG2_IS_PAGING_FILE.
    const FSRTL_FLAG2_IS_PAGING_FILE: u8 = 0x08;

    /// `fcb = FileObject->FsContext; fcb && (fcb->Flags2 & FSRTL_FLAG2_IS_PAGING_FILE)`.
    pub fn is_paging_file(file_object: &FileObject) -> bool {
        let fcb = file_object.fs_context.get();
        // SAFETY: o FsContext de um FILE_OBJECT de FS começa pelo cabeçalho comum do FCB.
        fcb != 0 && unsafe { FsrtlCommonFcbHeader::at(fcb) }.flags2.get() & FSRTL_FLAG2_IS_PAGING_FILE != 0
    }
}

/// SKU "móvel" = extensão do KTM ausente.
pub mod mobile_os {
    use crate::ntos::inc::field::{Field, NtStruct};
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::tm::extension;

    /// O real é literalmente `TmCurrentTransaction(&t) == STATUS_NOT_SUPPORTED`
    /// pelo slot `ext-ms-win-ntos-tm` (stub padrão 0x36d0e0 sem tm.sys). O
    /// OpenNT não carrega tm.sys, então isto é TRUE — e o fltmgr.sys
    /// (fltMgr+0x64f84, no init) escolhe os handlers sem TxF.
    pub fn is_mobile_os() -> bool {
        let address = guest::alloc_bytes(Field::<u64>::SIZE);
        // SAFETY: célula recém-alocada (o `PKTRANSACTION` local do NT).
        unsafe { Field::<u64>::at(address) }.set(0);
        let status = extension::current_transaction(address);
        guest::free_bytes(address);
        status == extension::STATUS_NOT_SUPPORTED
    }
}

/// Troca do backing da imagem do driver para o paging file.
pub mod driver_backing {
    use crate::ntos::inc::types::DriverObject;

    pub const STATUS_SUCCESS: u32 = 0;
    pub const STATUS_DRIVER_ENTRYPOINT_NOT_FOUND: u32 = 0xC000_0263;
    const DRIVER_BACKING_PAGEFILE: u32 = 1;

    /// Flags bit 0 pede backing pelo paging file: exige DriverInit (um
    /// endereço dentro da imagem) não nulo, senão
    /// STATUS_DRIVER_ENTRYPOINT_NOT_FOUND. STUB (sinalizado) do
    /// MmBackSystemImageWithPagefile: o OpenNT mantém toda imagem de sistema
    /// residente em memória não paginada, sem backing de arquivo — a troca já
    /// é o estado do sistema -> STATUS_SUCCESS.
    pub fn set_driver_backing(driver_object: &DriverObject, flags: u32) -> u32 {
        if flags & DRIVER_BACKING_PAGEFILE == 0 {
            return STATUS_SUCCESS;
        }
        if driver_object.driver_init.get() == 0 {
            return STATUS_DRIVER_ENTRYPOINT_NOT_FOUND;
        }
        STATUS_SUCCESS
    }
}

/// Notificação WNF de término de apps modernos.
pub mod app_termination {
    use crate::ntos::ex::wnf::service;
    use crate::ntos::inc::field::{Field, NtStruct};
    use crate::ntos::mm::guest_memory as guest;
    use crate::rtl::KernelError;

    pub const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
    pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    /// Nomes de estado WNF lidos de .rdata do ntoskrnl (RVA 0x2ee00 / 0x21428).
    const WNF_FLT_RUNDOWN_WAIT: u64 = 0x4192_022B_A3BC_0875;
    const WNF_FSRL_OPLOCK_BREAK: u64 = 0x0D94_1D2B_A3BC_1075;
    const MAXIMUM_LENGTH: u32 = 0x1000;
    /// O ULONG -1 que substitui Buffer NULL / Length 0 (com o resto zerado).
    const DEFAULT_PAYLOAD: [u8; 8] = [0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0];

    /// FsRtlSendModernAppTermination(Buffer, Length, Kind): Buffer NULL ou
    /// Length 0 viram um ULONG 0xFFFFFFFF de 4 bytes; Length > 0x1000 ->
    /// STATUS_BUFFER_OVERFLOW; Kind 0 publica em WNF_FLT_RUNDOWN_WAIT, 1 em
    /// WNF_FSRL_OPLOCK_BREAK, outro -> STATUS_INVALID_PARAMETER; publica com
    /// ZwUpdateWnfStateData(.., TypeId NULL, ExplicitScope NULL, 0, FALSE).
    pub fn send_modern_app_termination(buffer: u64, length: u32, kind: u32) -> Result<u32, KernelError> {
        // WNF_STATE_NAME + o payload padrão (locais no NT).
        let scratch = guest::alloc_bytes(Field::<u64>::SIZE + DEFAULT_PAYLOAD.len() as u64);
        let payload = scratch + Field::<u64>::SIZE;
        let (mut buffer, mut length) = (buffer, length);
        if buffer == 0 || length == 0 {
            guest::write_bytes(payload, &DEFAULT_PAYLOAD);
            buffer = payload;
            length = 4;
        }
        let state_name = match kind {
            0 => Some(WNF_FLT_RUNDOWN_WAIT),
            1 => Some(WNF_FSRL_OPLOCK_BREAK),
            _ => None,
        };
        let status = if length > MAXIMUM_LENGTH {
            Ok(STATUS_BUFFER_OVERFLOW)
        } else if let Some(name) = state_name {
            // SAFETY: célula recém-alocada para o WNF_STATE_NAME.
            unsafe { Field::<u64>::at(scratch) }.set(name);
            service::update(scratch, buffer, length, 0, 0, 0, false)
        } else {
            Ok(STATUS_INVALID_PARAMETER)
        };
        guest::free_bytes(scratch);
        status
    }
}
