//! Código x64 da HAL: tratadores de interrupção, transição para o anel 3,
//! trampolim dos APs, chamadas MS-ABI, trampolins de exports, entradas
//! privadas e tabelas de serviço.

pub mod irqstubs;
pub mod usermode;
pub mod aptrampoline;
pub mod win32_thunk;
pub mod native_call;
pub mod private_entries;
pub mod service_table;
pub mod runtime_signing_policy;
