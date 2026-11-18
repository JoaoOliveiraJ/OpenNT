//! `Control\FileSystem` na hive SYSTEM: a política de avaliação de links
//! simbólicos que o I/O Manager lê (IopSymlinkQueryEnabledClasses, os quatro
//! valores; sem eles nenhuma classe de link é avaliada) com os valores de
//! uma instalação nova do Windows 10 19041: local→local e local→remoto
//! ligados, remoto→local e remoto→remoto desligados (o
//! `fsutil behavior query SymlinkEvaluation` padrão).
//! Dados puros, incluídos também pelo `xtask`.

use alloc::vec::Vec;

use super::seed::SeedKey;

pub fn seed_keys() -> Vec<SeedKey> {
    let mut key = SeedKey::new("CurrentControlSet\\Control\\FileSystem");
    key.dword("SymlinkLocalToLocalEvaluation", 1).dword("SymlinkLocalToRemoteEvaluation", 1).dword("SymlinkRemoteToLocalEvaluation", 0).dword("SymlinkRemoteToRemoteEvaluation", 0);
    alloc::vec![key]
}
