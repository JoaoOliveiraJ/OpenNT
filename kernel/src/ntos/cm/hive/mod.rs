//! O formato de hive do Registro (regf) e as operações do Cm sobre ele.
//!
//! - `storage`: o bloco base, os bins, as células e o vetor de sujeira (Hv);
//! - `base_block`: a soma e a validação do bloco base;
//! - `index`: as listas de subchaves ('li', 'lf', 'lh', 'ri');
//! - `security_cells`: as células 'sk' com contagem de referências;
//! - `key_cells`: as células 'nk', 'vk', de dados e 'db';
//! - `tree`: a leitura da árvore de uma hive e a montagem de uma hive nova;
//! - `log`: os logs incrementais (.LOG1/.LOG2) e a recuperação;
//! - `sync`: a descarga (log, primário e sequências do bloco base).
//!
//! As hives carregadas e a ligação delas ao namespace do Registro ficam em
//! `cm/hive_list.rs`; a E/S de arquivo em `cm/hive_file.rs`.

pub mod base_block;
pub mod index;
pub mod key_cells;
pub mod log;
pub mod security_cells;
pub mod storage;
pub mod sync;
pub mod tree;
