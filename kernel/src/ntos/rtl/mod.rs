//! Runtime library do executive (Rtl).
//!
//! Fase 3: strings, AVL, bitmap, qsort, SHA-256, imagem PE, UTF-8, CRT e
//! maiúsculas NLS. `native_context`, `exceptions` e `unwind` acompanham a
//! execução de código nativo em contexto próprio (fase 6); os recursos de
//! imagens (`resource::*`) e a página ANSI dependem do volume (fase 4).

pub mod avl;
pub mod bitmap;
pub mod crt;
pub mod image;
pub mod native_context;
pub mod nls_configuration;
pub mod sha256;
pub mod sort;
pub mod strings;
pub mod unicode;
pub mod unicode_case;
pub mod utf8;
pub mod resource;
pub mod unwind;
pub mod exceptions;
pub mod strings_counted;
pub mod ansi_code_page;
pub mod atom;
pub mod code_page_table;
pub mod heap;
pub mod shared_data;
pub mod run_once;
pub mod exports;
pub mod guest_strings;
pub mod api_set;
pub mod avltable;
pub mod gentable;
pub mod error;
pub mod feature_configuration;
pub mod guid;
pub mod integer_conversion;
pub mod interlocked;
pub mod math;
pub mod memory;
pub mod nls_translation;
pub mod printf;
pub mod registry;
pub mod security;
pub mod sha1;
pub mod stack_trace;
pub mod system_volume;
pub mod time;
pub mod version;
pub mod hash_table;
pub mod range_list;
pub mod resource_encoding;
pub mod checksum;
pub mod network_address;
pub mod non_volatile;
pub mod reparse;
pub mod module_information;
pub mod oem_code_page;
pub mod gen8dot3;
pub mod altitude;
pub mod compression;
