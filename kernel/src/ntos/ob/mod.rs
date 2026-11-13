//! Object Manager (Ob) — `system32/ntos/ob/`.

pub mod callbacks;
pub mod handle_ids;
pub mod handle_table;
pub mod handles;
pub mod objects;
pub mod object_access;
pub mod object_manager;
pub mod object_types;
pub mod open_pointer;
pub mod close;
pub mod process_reference;
pub mod query_object_format;
pub mod get_object_type;
pub mod reference_trace;
pub mod find_handle;
pub mod query_security;
pub mod query_object;
pub mod object_create;
pub mod object_open;
pub mod object_reference;
pub mod object_security;
pub mod exports;
