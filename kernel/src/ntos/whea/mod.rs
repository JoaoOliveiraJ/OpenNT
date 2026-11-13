//! Windows Hardware Error Architecture (WHEA).
//!
//! O OpenNT não tem HEST nem PSHED: só as fontes de erro registradas por
//! drivers (tipos não-HEST) existem. Ver `error_source`.

pub mod error_source;
pub mod exports;
