//! O idioma desta instalação do Windows, lido do Registro desta máquina no
//! build: o convidado do boot do processo inicial real
//! (`--initial-process=smss`) tem a mesma configuração de idioma, e o
//! volume leva os arquivos `.mui` do mesmo idioma.
//!
//! As chaves vêm inteiras, com os valores e os tipos como estão aqui:
//! - na SYSTEM, `Control\Nls\Language` (o `Default`, que o kernel lê como
//!   PsDefaultSystemLocaleId, e o `InstallLanguage`, o
//!   PsInstallUILanguageId) e `Control\MUI\UILanguages` (os idiomas de
//!   interface instalados, que a ntdll consulta ao procurar um `.mui`);
//! - na DEFAULT (`\Registry\User\.DEFAULT`), `Control Panel\International`
//!   e `Control Panel\Desktop\MuiCached` (a localidade e os idiomas de
//!   interface preferidos do perfil do sistema).
//!
//! Fora do Windows (ou sem as chaves) nada é copiado e o convidado fica com
//! o padrão do kernel.

use std::path::Path;

/// Uma chave copiada: o caminho relativo à raiz da hive e os valores
/// (nome, tipo, dados como o Registro os guarda).
pub struct HostKey {
    pub path: String,
    pub values: Vec<(String, u32, Vec<u8>)>,
}

#[cfg(windows)]
mod registry {
    use super::HostKey;

    type Hkey = isize;
    /// HKEY_LOCAL_MACHINE e HKEY_USERS (o valor de 32 bits com sinal).
    pub const LOCAL_MACHINE: Hkey = 0x8000_0002u32 as i32 as isize;
    pub const USERS: Hkey = 0x8000_0003u32 as i32 as isize;
    /// KEY_READ | KEY_WOW64_64KEY.
    const KEY_READ_64: u32 = 0x2_0019 | 0x100;
    const ERROR_SUCCESS: i32 = 0;
    const ERROR_MORE_DATA: i32 = 234;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(key: Hkey, sub_key: *const u16, options: u32, desired: u32, result: *mut Hkey) -> i32;
        fn RegEnumKeyExW(key: Hkey, index: u32, name: *mut u16, name_length: *mut u32, reserved: *mut u32, class: *mut u16, class_length: *mut u32, last_write: *mut u64) -> i32;
        fn RegEnumValueW(key: Hkey, index: u32, name: *mut u16, name_length: *mut u32, reserved: *mut u32, value_type: *mut u32, data: *mut u8, data_length: *mut u32) -> i32;
        fn RegCloseKey(key: Hkey) -> i32;
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain([0]).collect()
    }

    struct Key(Hkey);

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: handle aberto por RegOpenKeyExW e fechado uma vez.
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn open(root: Hkey, path: &str) -> Option<Key> {
        let mut key = 0;
        let name = wide(path);
        // SAFETY: nome terminado em NUL e saída válida.
        (unsafe { RegOpenKeyExW(root, name.as_ptr(), 0, KEY_READ_64, &mut key) } == ERROR_SUCCESS).then_some(Key(key))
    }

    fn values(key: &Key) -> Vec<(String, u32, Vec<u8>)> {
        let mut values = Vec::new();
        let mut capacity = 64 * 1024;
        let mut index = 0;
        loop {
            let mut name = vec![0u16; 16384];
            let mut data = vec![0u8; capacity];
            let (mut name_length, mut data_length, mut value_type) = (name.len() as u32, data.len() as u32, 0u32);
            // SAFETY: buffers com os comprimentos passados.
            let status = unsafe { RegEnumValueW(key.0, index, name.as_mut_ptr(), &mut name_length, core::ptr::null_mut(), &mut value_type, data.as_mut_ptr(), &mut data_length) };
            if status == ERROR_MORE_DATA && (data_length as usize) > capacity {
                // O mesmo índice de novo, com o tamanho que o valor pede.
                capacity = data_length as usize;
                continue;
            }
            if status != ERROR_SUCCESS {
                break;
            }
            data.truncate(data_length as usize);
            values.push((String::from_utf16_lossy(&name[..name_length as usize]), value_type, data));
            index += 1;
        }
        values
    }

    fn subkeys(key: &Key) -> Vec<String> {
        let mut names = Vec::new();
        for index in 0.. {
            let mut name = vec![0u16; 256];
            let mut length = name.len() as u32;
            // SAFETY: buffer com o comprimento passado; o resto opcional nulo.
            let status = unsafe { RegEnumKeyExW(key.0, index, name.as_mut_ptr(), &mut length, core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut()) };
            if status != ERROR_SUCCESS {
                break;
            }
            names.push(String::from_utf16_lossy(&name[..length as usize]));
        }
        names
    }

    /// A chave `path` e, com `recursive`, as subchaves, com os caminhos
    /// trocados de `path` para `target`.
    pub fn copy(root: Hkey, path: &str, target: &str, recursive: bool, keys: &mut Vec<HostKey>) {
        let Some(key) = open(root, path) else { return };
        keys.push(HostKey { path: String::from(target), values: values(&key) });
        if recursive {
            for name in subkeys(&key) {
                copy(root, &format!("{path}\\{name}"), &format!("{target}\\{name}"), true, keys);
            }
        }
    }

    /// Os nomes das subchaves de `path`.
    pub fn list(root: Hkey, path: &str) -> Vec<String> {
        open(root, path).map(|key| subkeys(&key)).unwrap_or_default()
    }
}

/// As chaves de idioma da SYSTEM, já no conjunto de controle que a hive
/// guarda (`control_set`, como `ControlSet001`).
pub fn system_keys(control_set: &str) -> Vec<HostKey> {
    let mut keys = Vec::new();
    #[cfg(windows)]
    {
        let control = "SYSTEM\\CurrentControlSet\\Control";
        registry::copy(registry::LOCAL_MACHINE, &format!("{control}\\Nls\\Language"), &format!("{control_set}\\Control\\Nls\\Language"), false, &mut keys);
        registry::copy(registry::LOCAL_MACHINE, &format!("{control}\\MUI\\UILanguages"), &format!("{control_set}\\Control\\MUI\\UILanguages"), true, &mut keys);
    }
    #[cfg(not(windows))]
    let _ = control_set;
    keys
}

/// As chaves de idioma do perfil do sistema (a DEFAULT).
pub fn default_keys() -> Vec<HostKey> {
    let mut keys = Vec::new();
    #[cfg(windows)]
    {
        registry::copy(registry::USERS, ".DEFAULT\\Control Panel\\International", "Control Panel\\International", true, &mut keys);
        registry::copy(registry::USERS, ".DEFAULT\\Control Panel\\Desktop\\MuiCached", "Control Panel\\Desktop\\MuiCached", false, &mut keys);
    }
    keys
}

/// Os idiomas de interface instalados nesta máquina (os nomes das pastas
/// dos `.mui`, como `pt-BR`), na ordem do Registro.
pub fn ui_languages() -> Vec<String> {
    #[cfg(windows)]
    {
        registry::list(registry::LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\MUI\\UILanguages")
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

/// Os `.mui` de `name` (um arquivo de `directory`) nos idiomas de interface
/// desta máquina: (caminho relativo `idioma/NOME.MUI`, arquivo de origem).
pub fn mui_files(directory: &Path, name: &str, languages: &[String]) -> Vec<(String, std::path::PathBuf)> {
    languages
        .iter()
        .map(|language| (format!("{language}/{}.MUI", name.to_uppercase()), directory.join(language).join(format!("{name}.mui"))))
        .filter(|(_, source)| source.is_file())
        .collect()
}
