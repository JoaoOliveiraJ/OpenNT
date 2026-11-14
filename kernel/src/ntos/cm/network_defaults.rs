//! O repositório persistente do NSI no SYSTEM hive.
//!
//! O netio.sys guarda o estado persistente dos módulos de rede em
//! `Control\Nsi\{ModuleId}\{ObjectIndex}`: o NsipCreateKey cria só o último
//! nível com ZwCreateKey, e um módulo sem a sua chave falha com
//! STATUS_OBJECT_PATH_NOT_FOUND no meio do DriverEntry do tcpip.sys. No
//! Windows as chaves dos módulos vêm da instalação; aqui entram as mesmas
//! (vazias), com os ModuleIds desta máquina de build. Os valores e as
//! subchaves de objetos, que guardam a configuração de cada interface, são
//! criados pelo próprio netio.sys em tempo de execução e não entram aqui.

use alloc::format;

use super::registry;
use crate::rtl::KernelError;

const NSI: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nsi";

/// Os ModuleIds com chave no repositório da instalação.
const MODULES: &[&str] = &[
    "{eb004a00-9b1a-11d4-9123-0050047759bc}",
    "{eb004a01-9b1a-11d4-9123-0050047759bc}",
    "{eb004a02-9b1a-11d4-9123-0050047759bc}",
    "{eb004a03-9b1a-11d4-9123-0050047759bc}",
    "{eb004a11-9b1a-11d4-9123-0050047759bc}",
    "{eb004a1c-9b1a-11d4-9123-0050047759bc}",
];

/// Cria as chaves que faltam (uma chave existente fica como está).
pub fn initialize() -> Result<(), KernelError> {
    for module in MODULES {
        let key = registry::open_or_create(&format!("{NSI}\\{module}"), None)?;
        registry::close_handle(key);
    }
    Ok(())
}
