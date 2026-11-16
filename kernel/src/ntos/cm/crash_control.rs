//! `Control\CrashControl` na hive SYSTEM: a configuração do bugcheck que o
//! kernel lê no boot (o IopAutoReboot e o despejo configurado).
//! - CrashDumpEnabled 7 (despejo automático de memória), como nesta
//!   instalação: o kernel coleta os dados do erro, que no OpenNT vão para a
//!   serial;
//! - AutoReboot 0 (a opção "Reiniciar automaticamente" desmarcada): a
//!   máquina para na tela de bugcheck em vez de reiniciar, porque o QEMU dos
//!   testes roda com `-no-reboot` e um reinício encerraria a máquina antes de
//!   a tela ser vista.
//! Dados puros, incluídos também pelo `xtask`.

use alloc::vec::Vec;

use super::seed::SeedKey;

pub fn seed_keys() -> Vec<SeedKey> {
    let mut key = SeedKey::new("CurrentControlSet\\Control\\CrashControl");
    key.dword("AutoReboot", 0).dword("CrashDumpEnabled", 7);
    alloc::vec![key]
}
