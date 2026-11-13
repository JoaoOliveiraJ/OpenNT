//! Cache Manager (Cc) — `ntos\cache` do NT.
//!
//! Cache de arquivo dos file systems reais: um SHARED_CACHE_MAP nativo por
//! arquivo (em `SectionObjectPointer->SharedCacheMap`), vistas de 256 KB
//! preenchidas por IRPs de paginação à pilha do próprio arquivo, BCBs para
//! map/pin, páginas sujas gravadas por flush e no último
//! CcUninitializeCacheMap (modelo síncrono, sem thread de lazy writer).
//!
//! * `layout` — estruturas nativas e constantes;
//! * `status` — falhas levantadas (ExRaiseStatus) e a conversão do export;
//! * `cache_map` — shared/private cache maps, tamanhos e atributos (fssup.c);
//! * `vacb` — vistas e cópias de memória (vacbsup.c);
//! * `section_io` — a paginação que o Mm faz debaixo do Cc no NT;
//! * `copy`, `pin`, `mdl`, `flush`, `log` — copysup.c, pinsup.c, mdlsup.c,
//!   lazyrite.c/fssup.c e logsup.c.

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
