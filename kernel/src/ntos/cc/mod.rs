//! Cache Manager (Cc).
//!
//! Cache de arquivo dos file systems reais: um SHARED_CACHE_MAP nativo por
//! arquivo (em `SectionObjectPointer->SharedCacheMap`), vistas de 256 KB
//! preenchidas por IRPs de paginação à pilha do próprio arquivo, BCBs para
//! map/pin, páginas sujas gravadas por flush e pelo lazy writer, que também
//! apaga os mapas que o último CcUninitializeCacheMap lhe deixa.
//!
//! * `layout` — estruturas nativas e constantes;
//! * `status` — falhas levantadas (ExRaiseStatus) e a conversão do export;
//! * `cache_map` — shared/private cache maps, tamanhos e atributos;
//! * `vacb` — vistas e cópias de memória;
//! * `section_io` — a paginação que o Mm faz debaixo do Cc no NT;
//! * `cache_section` — a seção de dados do stream (SharedCacheMap->Section)
//!   cujas vistas de sistema são as vistas do cache, com as mesmas páginas
//!   das vistas de usuário do arquivo;
//! * `copy`, `pin`, `mdl`, `flush`, `log` — cópias, pin, MDLs, escrita/flush
//!   e fluxos com log;
//! * `lazy_writer` — a passada do lazy writer (write-behind e remoção
//!   adiada dos mapas).

pub mod layout;
pub mod status;
pub mod cache_map;
pub mod vacb;
pub mod section_io;
pub mod cache_section;
pub mod copy;
pub mod pin;
pub mod mdl;
pub mod flush;
pub mod log;
pub mod lazy_writer;
pub mod exports;
