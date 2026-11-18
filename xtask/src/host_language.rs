//! O idioma desta instalação do Windows, lido do Registro desta máquina no
//! build: o convidado do boot do processo inicial real
//! (`--initial-process=smss`) tem a mesma configuração de idioma, e o
//! volume leva os arquivos `.mui` do mesmo idioma (ou, para um arquivo que
//! não tem `.mui` nele, os do idioma de fallback, como o en-US).
//!
//! As chaves vêm inteiras, com os valores e os tipos como estão aqui:
//! - na SYSTEM, `Control\Nls\Language` (o `Default`, que o kernel lê como
//!   PsDefaultSystemLocaleId, e o `InstallLanguage`, o
//!   PsInstallUILanguageId), `Control\MUI\UILanguages` (os idiomas de
//!   interface instalados, que a ntdll consulta ao procurar um `.mui`),
//!   `Control\Keyboard Layouts` (os layouts de teclado instalados, com o
//!   `Layout File` de cada um) e `Control\Keyboard Layout`;
//! - na DEFAULT (`\Registry\User\.DEFAULT`), `Control Panel\International`,
//!   `Control Panel\Desktop\MuiCached` (a localidade e os idiomas de
//!   interface preferidos do perfil do sistema) e `Keyboard Layout` (o
//!   `Preload`, os `Substitutes` e o `Toggle` do perfil do sistema: o
//!   user32 do wininit e do winlogon abre o arquivo do primeiro layout do
//!   `Preload`, e o volume leva esse arquivo, [`keyboard_layout_files`]),
//!   `Control Panel\Input Method` (as teclas de atalho dos editores de
//!   entrada) e `Software\Microsoft\CTF` (os perfis de entrada do TSF).
//!
//! Fora do Windows (ou sem as chaves) nada é copiado e o convidado fica com
//! o padrão do kernel (sem `Preload`, o user32 cai no kbdus.dll).

use std::path::Path;

/// Uma chave copiada: o caminho relativo à raiz da hive e os valores
/// (nome, tipo, dados como o Registro os guarda).
pub struct HostKey {
    pub path: String,
    pub values: Vec<(String, u32, Vec<u8>)>,
}

#[cfg(windows)]
pub(crate) mod registry {
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

    /// As cadeias do valor `name` de `path` (REG_SZ, REG_EXPAND_SZ ou
    /// REG_MULTI_SZ), sem as vazias.
    pub fn strings(root: Hkey, path: &str, name: &str) -> Vec<String> {
        let Some(key) = open(root, path) else { return Vec::new() };
        let Some((_, kind, data)) = values(&key).into_iter().find(|(value, _, _)| value.eq_ignore_ascii_case(name)) else { return Vec::new() };
        if !matches!(kind, 1 | 2 | 7) {
            return Vec::new();
        }
        let units: Vec<u16> = data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
        units.split(|&unit| unit == 0).filter(|text| !text.is_empty()).map(String::from_utf16_lossy).collect()
    }

    /// Os valores de cadeia de `path` (REG_SZ ou REG_EXPAND_SZ) com o nome,
    /// na ordem do Registro: (nome, cadeia até o primeiro NUL).
    pub fn named_strings(root: Hkey, path: &str) -> Vec<(String, String)> {
        let Some(key) = open(root, path) else { return Vec::new() };
        values(&key)
            .into_iter()
            .filter(|(_, kind, _)| matches!(kind, 1 | 2))
            .map(|(name, _, data)| {
                let units: Vec<u16> = data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
                (name, String::from_utf16_lossy(&units))
            })
            .collect()
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
        registry::copy(registry::LOCAL_MACHINE, &format!("{control}\\Keyboard Layouts"), &format!("{control_set}\\Control\\Keyboard Layouts"), true, &mut keys);
        registry::copy(registry::LOCAL_MACHINE, &format!("{control}\\Keyboard Layout"), &format!("{control_set}\\Control\\Keyboard Layout"), true, &mut keys);
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
        registry::copy(registry::USERS, ".DEFAULT\\Keyboard Layout", "Keyboard Layout", true, &mut keys);
        // As teclas de atalho dos editores de entrada (`Hot Keys`), que o
        // user32 do wininit e do winlogon lê ao carregar os layouts, e os
        // perfis de entrada do TSF do perfil do sistema
        // (`Software\Microsoft\CTF`: `Assemblies` e `SortOrder` com o layout
        // de cada idioma), que o MSCTF.dll lê ao ativar o gerenciador de
        // threads do TSF para uma caixa de texto.
        registry::copy(registry::USERS, ".DEFAULT\\Control Panel\\Input Method", "Control Panel\\Input Method", true, &mut keys);
        registry::copy(registry::USERS, ".DEFAULT\\Software\\Microsoft\\CTF", "Software\\Microsoft\\CTF", true, &mut keys);
    }
    keys
}

/// Os arquivos de layout de teclado (o `Layout File` de
/// `Control\Keyboard Layouts\<KLID>`, como `KBDBR.DLL`) dos layouts que o
/// perfil do sistema desta máquina pré-carrega (`Keyboard Layout\Preload`
/// da DEFAULT, na ordem dos valores, com o `Substitutes` aplicado), sem
/// repetição. O user32 abre o do primeiro no CreateWindowStationW (o
/// NtUserCreateWindowStation recebe o handle) e no LoadKeyboardLayout do
/// winlogon; sem o arquivo no volume a WinSta0 falha com
/// ERROR_MOD_NOT_FOUND.
pub fn keyboard_layout_files() -> Vec<String> {
    #[cfg(windows)]
    {
        let profile = ".DEFAULT\\Keyboard Layout";
        let substitutes = registry::named_strings(registry::USERS, &format!("{profile}\\Substitutes"));
        let mut files: Vec<String> = Vec::new();
        // Os valores do Preload são numerados ("1", "2", ...): o user32 os
        // lê nessa ordem.
        let mut preload = registry::named_strings(registry::USERS, &format!("{profile}\\Preload"));
        preload.sort_by_key(|(name, _)| name.parse::<u32>().unwrap_or(u32::MAX));
        for (_, layout) in preload {
            let layout = substitutes.iter().find(|(name, _)| name.eq_ignore_ascii_case(&layout)).map_or(layout.clone(), |(_, substitute)| substitute.clone());
            let path = format!("SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts\\{layout}");
            for file in registry::strings(registry::LOCAL_MACHINE, &path, "Layout File") {
                if !files.iter().any(|known| known.eq_ignore_ascii_case(&file)) {
                    files.push(file);
                }
            }
        }
        files
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
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

/// Os idiomas de recurso para um arquivo sem `.mui` nos idiomas de
/// interface, na ordem em que o carregador os procura: o `DefaultFallback`
/// de cada idioma de interface (`Control\MUI\UILanguages\<idioma>`) e o
/// `InstallLanguageFallback` de `Control\Nls\Language`, sem os idiomas de
/// interface.
pub fn fallback_languages(languages: &[String]) -> Vec<String> {
    #[cfg(windows)]
    {
        let mut fallbacks: Vec<String> = Vec::new();
        let control = "SYSTEM\\CurrentControlSet\\Control";
        let candidates = languages
            .iter()
            .flat_map(|language| registry::strings(registry::LOCAL_MACHINE, &format!("{control}\\MUI\\UILanguages\\{language}"), "DefaultFallback"))
            .chain(registry::strings(registry::LOCAL_MACHINE, &format!("{control}\\Nls\\Language"), "InstallLanguageFallback"));
        for candidate in candidates {
            let known = |list: &[String]| list.iter().any(|language| language.eq_ignore_ascii_case(&candidate));
            if !known(languages) && !known(&fallbacks) {
                fallbacks.push(candidate);
            }
        }
        fallbacks
    }
    #[cfg(not(windows))]
    {
        let _ = languages;
        Vec::new()
    }
}

/// Os `.mui` de `name` (um arquivo de `directory`) nos idiomas de interface
/// desta máquina ou, se nenhum deles tiver o arquivo, no primeiro idioma de
/// `fallbacks` que o tiver: (caminho relativo `idioma/NOME.MUI`, arquivo de
/// origem).
pub fn mui_files(directory: &Path, name: &str, languages: &[String], fallbacks: &[String]) -> Vec<(String, std::path::PathBuf)> {
    let candidate = |language: &String| (format!("{language}/{}.MUI", name.to_uppercase()), directory.join(language).join(format!("{name}.mui")));
    let found: Vec<(String, std::path::PathBuf)> = languages.iter().map(candidate).filter(|(_, source)| source.is_file()).collect();
    if !found.is_empty() {
        return found;
    }
    fallbacks.iter().map(candidate).find(|(_, source)| source.is_file()).into_iter().collect()
}

#[cfg(all(test, windows))]
mod tests {
    use super::{default_keys, keyboard_layout_files, registry, system_keys};

    /// Os layouts pré-carregados desta máquina resolvem para arquivos de
    /// System32, e as chaves copiadas levam o Preload e o layout dele.
    #[test]
    fn preloaded_keyboard_layouts_resolve_to_system32_files() {
        let preload = registry::named_strings(registry::USERS, ".DEFAULT\\Keyboard Layout\\Preload");
        let files = keyboard_layout_files();
        if preload.is_empty() {
            assert!(files.is_empty());
            return;
        }
        assert!(!files.is_empty(), "Preload {preload:?} sem Layout File");
        let system32 = crate::windows_binaries::windows_directory().join("System32");
        for file in &files {
            assert!(system32.join(file).is_file(), "{file} ausente em System32");
        }
        assert!(default_keys().iter().any(|key| key.path == "Keyboard Layout\\Preload"));
        let first = &preload.iter().min_by_key(|(name, _)| name.parse::<u32>().unwrap_or(u32::MAX)).unwrap().1;
        let layout = format!("ControlSet001\\Control\\Keyboard Layouts\\{first}");
        assert!(system_keys("ControlSet001").iter().any(|key| key.path.eq_ignore_ascii_case(&layout)), "{layout} nao copiada");
        // O perfil de entrada do TSF do idioma do primeiro layout, quando
        // esta máquina o tem: o KLID tem o idioma nos quatro dígitos finais
        // (00000416 -> 0x00000416).
        let first_language = format!("0x{:0>8}", first.get(4..).unwrap_or_default());
        let assembly = format!(".DEFAULT\\Software\\Microsoft\\CTF\\Assemblies\\{first_language}");
        if !registry::list(registry::USERS, &assembly).is_empty() {
            let copied = format!("Software\\Microsoft\\CTF\\Assemblies\\{first_language}");
            assert!(default_keys().iter().any(|key| key.path.eq_ignore_ascii_case(&copied)), "{copied} nao copiada");
        }
    }
}
