//! Cache Manager (Cc).
//!
//! Cache de arquivo dos file systems reais: um SHARED_CACHE_MAP nativo por
//! arquivo (em `SectionObjectPointer->SharedCacheMap`), vistas de 256 KB
//! preenchidas por IRPs de paginação à pilha do próprio arquivo, BCBs para
//! map/pin, páginas sujas gravadas por flush e no último
//! CcUninitializeCacheMap (modelo síncrono, sem thread de lazy writer).
//!
//! * `layout` — estruturas nativas e constantes;
//! * `status` — falhas levantadas (ExRaiseStatus) e a conversão do export;
//! * `cache_map` — shared/private cache maps, tamanhos e atributos;
//! * `vacb` — vistas e cópias de memória;
//! * `section_io` — a paginação que o Mm faz debaixo do Cc no NT;
//! * `copy`, `pin`, `mdl`, `flush`, `log` — cópias, pin, MDLs, escrita/flush
//!   e fluxos com log.

pub mod layout;
pub mod status;
pub mod cache_map;
pub mod vacb;
pub mod section_io;
pub mod copy;
pub mod pin;
pub mod mdl;
pub mod flush;
pub mod log;
pub mod exports;
