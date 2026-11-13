//! tm — o gerenciador de transações do kernel (KTM) como o ntoskrnl o vê: um
//! host de extensão que o tm.sys preencheria. O OpenNT não carrega tm.sys;
//! `extension` reproduz o comportamento do Windows nessa configuração.
pub mod exports;
pub mod extension;
