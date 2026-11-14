//! Exports Bgk*: adaptadores de `bgk/console`.

pub mod bgk_console {
    use crate::ntos::bgk::console;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    /// BgkDisplayCharacter(Character, X, Y, Color, ...).
    fn display_character(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(console::display_character(call.arg(1) as u16, call.arg(2) as u32, call.arg(3) as u32, call.arg(4) as u32, call.arg(5) as u32)?))
    }

    /// BgkGetConsoleState(State*).
    fn get_console_state(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(console::get_console_state(call.arg(1))?))
    }

    /// BgkSetCursor(X, Y, ...).
    fn set_cursor(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(console::set_cursor(call.arg(1) as u32, call.arg(2) as u32, call.arg(3) as u32)?))
    }

    pub static GROUP: Group = Group {
        name: "bgk-console",
        names: &["BgkDisplayCharacter", "BgkGetConsoleState", "BgkSetCursor"],
        handlers: &[display_character, get_console_state, set_cursor],
        data_exports: &[],
    };
}
