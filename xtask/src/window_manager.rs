//! A chave `Microsoft\Windows\DWM` da hive SOFTWARE, como numa instalação
//! desta versão, no boot do processo inicial real
//! (`--initial-process=smss`):
//!
//! - o dwm.exe lê dela as preferências do CSettingsManager
//!   (UseDPIScaling, DisableLockingMemory, as de animação e de cor; valor
//!   ausente é o padrão), o dwmcore o ShaderLinkingGPUBlacklist e o
//!   DwmInitSessionActivityId da sessão, e o dcomp o
//!   AnimationAttributionEnabled;
//! - o dwminit.dll do winlogon cria a chave (RegCreateKeyExW com
//!   REG_OPTION_VOLATILE: sem ela na hive, nasceria volátil) e grava o
//!   `DwmInitSessionActivityId_<sessão>` de cada sessão que inicia; o
//!   OneCoreNoBootDWM só é lido no wininit.
//!
//! Os valores vêm desta máquina no build, sem os
//! `DwmInitSessionActivityId_*` que as sessões daqui gravaram e sem as
//! subchaves (a ExtendedComposition é do compositor holográfico, que o
//! dwm.exe não lê). Fora do Windows nada é copiado.

use crate::host_language::HostKey;

/// A chave, relativa à raiz da hive SOFTWARE.
#[cfg(windows)]
const DWM_KEY: &str = "Microsoft\\Windows\\DWM";

/// O prefixo dos valores que o dwminit grava a cada sessão.
const SESSION_ACTIVITY_PREFIX: &str = "DwmInitSessionActivityId_";

/// Um valor gravado pelo dwminit numa sessão desta máquina.
fn session_value(name: &str) -> bool {
    name.get(..SESSION_ACTIVITY_PREFIX.len()).is_some_and(|head| head.eq_ignore_ascii_case(SESSION_ACTIVITY_PREFIX))
}

/// As chaves da hive SOFTWARE.
pub fn software_keys() -> Vec<HostKey> {
    let mut keys = Vec::new();
    #[cfg(windows)]
    {
        use crate::host_language::registry;
        registry::copy(registry::LOCAL_MACHINE, &format!("SOFTWARE\\{DWM_KEY}"), DWM_KEY, false, &mut keys);
    }
    for key in &mut keys {
        key.values.retain(|(name, _, _)| !session_value(name));
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::session_value;

    #[test]
    fn session_values_stay_on_this_machine() {
        assert!(session_value("DwmInitSessionActivityId_00000001"));
        assert!(session_value("dwminitsessionactivityid_00000002"));
        assert!(!session_value("OneCoreNoBootDWM"));
        assert!(!session_value("ShaderLinkingGPUBlacklist"));
        assert!(!session_value("DwmInit"));
    }
}
