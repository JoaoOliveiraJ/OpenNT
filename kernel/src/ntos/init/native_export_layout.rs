//! Exports com corpo x64 próprio — `system32/win32/native-export-layout.js`.
//!
//! Compartilhado pelo empacotamento do PE e pelos resolvedores: estes exports
//! têm corpo real fora da tabela fixa de despachantes de dez bytes.

/// (export, símbolo, primitiva que devolve a entrada, índice).
pub const NATIVE_EXPORTS: [(&str, &str, &str, u32); 4] = [
    ("__chkstk", "probe_kernel_stack", "getKernelStackProbeEntry", 0),
    ("DbgPrompt", "dbg_prompt", "getDebugPromptEntry", 0),
    ("PsSetContextThread", "ps_set_context_thread", "getContextOperationEntry", 2),
    ("ObFindHandleForObject", "ob_find_handle_for_object", "getFindHandleEntry", 0),
];

pub fn lookup(name: &str) -> Option<(&'static str, &'static str, u32)> {
    NATIVE_EXPORTS.iter().find(|(export, ..)| *export == name).map(|&(_, symbol, primitive, index)| (symbol, primitive, index))
}
