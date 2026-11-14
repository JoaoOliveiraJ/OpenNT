//! Configuração da pilha gráfica no SYSTEM hive.
//!
//! O dxgkrnl.sys abre `Control\GraphicsDrivers` no DriverEntry e falha com
//! STATUS_OBJECT_NAME_NOT_FOUND sem ela; também abre `Control\Video` (com a
//! barra final, que só resolve numa chave existente). No Windows as duas vêm
//! da instalação, `GraphicsDrivers` com os valores de versão do kernel
//! gráfico; as subchaves de adaptadores, monitores e configurações de vídeo
//! são criadas pelo próprio dxgkrnl em tempo de execução e não entram aqui.
//! Os valores são os do Windows 10 19041 desta máquina de build. Só valores
//! ausentes são gravados.
//!
//! Também garante `Control\Class`, a raiz das classes de dispositivo que a
//! instalação cria: o IoCreateDeviceSecure da wdmsec estática (que o dxgkrnl
//! usa quando o ntoskrnl não exporta a rotina) abre essa raiz e cria nela a
//! subchave da classe do dispositivo; sem ela, a criação de \Device\DxgKrnl
//! falha.

use alloc::string::String;

use super::registry;
use crate::rtl::KernelError;

const GRAPHICS_DRIVERS: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\GraphicsDrivers";
const VIDEO: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Video";
const CLASS: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class";

/// (nome, REG_DWORD) de `Control\GraphicsDrivers`.
const GRAPHICS_DRIVERS_VALUES: &[(&str, u32)] = &[("PlatformSupportMiracast", 1), ("DxgKrnlVersion", 0xC004), ("MinDxgKrnlVersion", 0x5013)];

/// Cria as chaves e grava os valores que faltam.
pub fn initialize() -> Result<(), KernelError> {
    let handle = registry::open_or_create(&String::from(GRAPHICS_DRIVERS), None)?;
    for &(name, value) in GRAPHICS_DRIVERS_VALUES {
        if registry::get_value(handle, name).is_none() {
            registry::set_value(handle, name, 4, value.to_le_bytes().to_vec());
        }
    }
    registry::close_handle(handle);
    for path in [VIDEO, CLASS] {
        let key = registry::open_or_create(&String::from(path), None)?;
        registry::close_handle(key);
    }
    Ok(())
}
