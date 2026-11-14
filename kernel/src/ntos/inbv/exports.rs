//! Exports Inbv* do ntoskrnl; a lógica mora em `inbv/display`.

pub mod inbv_display_ownership {
    //! InbvNotifyDisplayOwnershipChange e InbvSetVirtualFrameBuffer.

    use crate::ntos::inbv::display;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    /// InbvNotifyDisplayOwnershipChange(BOOLEAN Owned, PVOID Context).
    fn notify_display_ownership_change(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(display::notify_display_ownership_change(call.arg(1) & 0xFF != 0, call.arg(2))))
    }

    /// InbvSetVirtualFrameBuffer(PVOID FrameBuffer, PVOID Context).
    fn set_virtual_frame_buffer(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(display::set_virtual_frame_buffer(call.arg(1), call.arg(2))))
    }

    pub static GROUP: Group = Group {
        name: "inbv-display-ownership",
        names: &["InbvNotifyDisplayOwnershipChange", "InbvSetVirtualFrameBuffer"],
        handlers: &[notify_display_ownership_change, set_virtual_frame_buffer],
        data_exports: &[],
    };
}
