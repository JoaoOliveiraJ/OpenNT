//! Nome do computador — `system32/ntos/cm/computer-name.js`.
//!
//! Configuração de nome do próprio sistema; o KERNELBASE lê esses valores por
//! consultas normais do registro.

use super::registry;
use crate::rtl::KernelError;

const SYSTEM_CONFIGURATION_PATH: &str = "\\Registry\\Machine\\System\\CurrentControlSet";

/// Insere os padrões ausentes; valores presentes têm precedência.
fn write_missing_values(relative: &str, defaults: &[(&str, &str)]) -> Result<(), KernelError> {
    let handle = registry::open_or_create(&(alloc::string::String::from(SYSTEM_CONFIGURATION_PATH) + relative), None)?;
    for (name, text) in defaults {
        if registry::get_value(handle, name).is_none() {
            registry::set_value(handle, name, 1, registry::encode_wide(text));
        }
    }
    registry::close_handle(handle);
    Ok(())
}

/// Cria o nome configurado e os parâmetros de rede ausentes; copia o nome
/// configurado para o ativo só quando este ainda não existe.
pub fn initialize() -> Result<(), KernelError> {
    write_missing_values("\\Control\\ComputerName\\ComputerName", &[("ComputerName", "OPENNT")])?;
    let configured = registry::read_value_by_path(&(alloc::string::String::from(SYSTEM_CONFIGURATION_PATH) + "\\Control\\ComputerName\\ComputerName"), "ComputerName");
    let active = registry::open_or_create(&(alloc::string::String::from(SYSTEM_CONFIGURATION_PATH) + "\\Control\\ComputerName\\ActiveComputerName"), None)?;
    if registry::get_value(active, "ComputerName").is_none() {
        if let Some(configured) = configured {
            registry::set_value(active, "ComputerName", configured.value_type, configured.data);
        }
    }
    registry::close_handle(active);
    write_missing_values("\\Services\\Tcpip\\Parameters", &[("Hostname", "opennt"), ("NV Hostname", "opennt"), ("Domain", ""), ("NV Domain", "")])
}
