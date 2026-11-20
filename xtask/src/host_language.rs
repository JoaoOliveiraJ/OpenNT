//! O idioma desta instalação do Windows, lido do Registro desta máquina no
//! build: o convidado do boot do processo inicial real
//! (`--initial-process=smss`) tem a mesma configuração de idioma, e o
//! volume leva os arquivos `.mui` do mesmo idioma (ou, para um arquivo que
//! não tem `.mui` nele, os do idioma de fallback, como o en-US).
//!
//! As chaves vêm inteiras, com os valores e os tipos como estão aqui:
//! - na SYSTEM, `Control\Nls` inteira, como a instalação a deixa
//!   ([`clean_install_nls`] desfaz o que se troca depois dela): `Language`
//!   (o `Default`, que o kernel lê como PsDefaultSystemLocaleId, e o
//!   `InstallLanguage`, o PsInstallUILanguageId), `CodePage` (ACP, OEMCP,
//!   MACCP, OEMHAL e o arquivo de cada página, de onde o kernel tira as
//!   tabelas ANSI e OEM), `Locale`, `Language Groups`, `Sorting` (`Ids` e
//!   `Versions`), `Normalization` (o arquivo de cada forma, que o
//!   NtGetNlsSectionPtr lê) e `Calendars`; `Control\MUI\UILanguages` (os
//!   idiomas de interface instalados, que a ntdll consulta ao procurar um
//!   `.mui`), `Control\MUI\StringCacheSettings` (a geração do cache de
//!   cadeias MUI que a KernelBase lê antes de resolver uma cadeia indireta),
//!   `Control\Keyboard Layouts` (os layouts de teclado instalados,
//!   com o `Layout File` de cada um) e `Control\Keyboard Layout`;
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

/// O formato regional padrão de uma localidade, como uma instalação nova o
/// grava em `Control Panel\International` do perfil do sistema.
#[cfg(windows)]
pub(crate) mod region {
    use super::HostKey;

    /// LOCALE_NOUSEROVERRIDE: os dados da localidade, não os do usuário.
    const LOCALE_NOUSEROVERRIDE: u32 = 0x8000_0000;
    const REG_SZ: u32 = 1;
    const REG_MULTI_SZ: u32 = 7;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetLocaleInfoEx(locale: *const u16, kind: u32, data: *mut u16, length: i32) -> i32;
        fn LocaleNameToLCID(name: *const u16, flags: u32) -> u32;
    }

    /// Os valores de `International`, na ordem em que a instalação os grava,
    /// com o LCTYPE de cada um.
    const VALUES: &[(&str, u32)] = &[
        ("s1159", 0x28),
        ("s2359", 0x29),
        ("sCurrency", 0x14),
        ("sDate", 0x1D),
        ("sDecimal", 0x0E),
        ("sGrouping", 0x10),
        ("sLanguage", 0x03),
        ("sList", 0x0C),
        ("sLongDate", 0x20),
        ("sMonDecimalSep", 0x16),
        ("sMonGrouping", 0x18),
        ("sMonThousandSep", 0x17),
        ("sNativeDigits", 0x13),
        ("sNegativeSign", 0x51),
        ("sPositiveSign", 0x50),
        ("sShortDate", 0x1F),
        ("sThousand", 0x0F),
        ("sTime", 0x1E),
        ("sTimeFormat", 0x1003),
        ("sShortTime", 0x79),
        ("sYearMonth", 0x1006),
        ("iCalendarType", 0x1009),
        ("iCountry", 0x05),
        ("iCurrDigits", 0x19),
        ("iCurrency", 0x1B),
        ("iDate", 0x21),
        ("iDigits", 0x11),
        ("NumShape", 0x1014),
        ("iFirstDayOfWeek", 0x100C),
        ("iFirstWeekOfYear", 0x100D),
        ("iLZero", 0x12),
        ("iMeasure", 0x0D),
        ("iNegCurr", 0x1C),
        ("iNegNumber", 0x1010),
        ("iPaperSize", 0x100A),
        ("iTime", 0x23),
        ("iTimePrefix", 0x1005),
        ("iTLZero", 0x25),
    ];

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain([0]).collect()
    }

    fn info(locale: &[u16], kind: u32) -> Option<String> {
        let mut data = vec![0u16; 256];
        // SAFETY: nome terminado em NUL e buffer com o comprimento passado.
        let length = unsafe { GetLocaleInfoEx(locale.as_ptr(), kind | LOCALE_NOUSEROVERRIDE, data.as_mut_ptr(), data.len() as i32) };
        (length > 0).then(|| String::from_utf16_lossy(&data[..length as usize - 1]))
    }

    fn text(value: &str) -> Vec<u8> {
        value.encode_utf16().chain([0]).flat_map(|unit| unit.to_le_bytes()).collect()
    }

    /// `International` (Locale, LocaleName e os formatos), `Geo` (Nation e
    /// Name do país da localidade) e `User Profile` (Languages só com o
    /// idioma principal).
    pub fn international_keys(locale_name: &str) -> Vec<HostKey> {
        let locale = wide(locale_name);
        // SAFETY: nome terminado em NUL.
        let lcid = unsafe { LocaleNameToLCID(locale.as_ptr(), 0) };
        let mut values = vec![(String::from("Locale"), REG_SZ, text(&format!("{lcid:08X}"))), (String::from("LocaleName"), REG_SZ, text(locale_name))];
        for &(name, kind) in VALUES {
            if let Some(value) = info(&locale, kind) {
                values.push((String::from(name), REG_SZ, text(&value)));
            }
        }
        let mut keys = vec![HostKey { path: String::from("Control Panel\\International"), values }];
        // LOCALE_IGEOID e LOCALE_SISO3166CTRYNAME.
        if let (Some(nation), Some(name)) = (info(&locale, 0x5B), info(&locale, 0x5A)) {
            keys.push(HostKey { path: String::from("Control Panel\\International\\Geo"), values: vec![(String::from("Nation"), REG_SZ, text(&nation)), (String::from("Name"), REG_SZ, text(&name))] });
        }
        let languages: Vec<u8> = locale_name.encode_utf16().chain([0, 0]).flat_map(|unit| unit.to_le_bytes()).collect();
        keys.push(HostKey { path: String::from("Control Panel\\International\\User Profile"), values: vec![(String::from("Languages"), REG_MULTI_SZ, languages)] });
        keys
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn portuguese_brazil_defaults() {
            let keys = super::international_keys("pt-BR");
            let value = |name: &str| keys[0].values.iter().find(|(key, _, _)| key == name).map(|(_, _, data)| String::from_utf16_lossy(&data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect::<Vec<u16>>()));
            assert_eq!(value("Locale").as_deref(), Some("00000416"));
            assert_eq!(value("sShortDate").as_deref(), Some("dd/MM/yyyy"));
            assert_eq!(value("iCountry").as_deref(), Some("55"));
            assert_eq!(value("sLanguage").as_deref(), Some("PTB"));
            assert!(keys.iter().any(|key| key.path.ends_with("Geo")));
        }
    }
}

/// As páginas padrão de um idioma que a instalação grava em `CodePage`: o
/// valor e o LCTYPE do GetLocaleInfoW (LOCALE_IDEFAULTANSICODEPAGE,
/// LOCALE_IDEFAULTCODEPAGE, que é a OEM, e LOCALE_IDEFAULTMACCODEPAGE).
#[cfg(windows)]
const DEFAULT_CODE_PAGES: [(&str, u32); 3] = [("ACP", 0x1004), ("OEMCP", 0x000B), ("MACCP", 0x1011)];

/// O dado `lc_type` da localidade `lcid` (GetLocaleInfoW com
/// LOCALE_NOUSEROVERRIDE: o padrão da localidade, sem as personalizações do
/// usuário desta máquina), sem o NUL.
#[cfg(windows)]
fn locale_info(lcid: u32, lc_type: u32) -> Option<String> {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetLocaleInfoW(locale: u32, lc_type: u32, data: *mut u16, length: i32) -> i32;
    }
    const LOCALE_NOUSEROVERRIDE: u32 = 0x8000_0000;
    let mut buffer = [0u16; 32];
    // SAFETY: buffer com o comprimento passado, em caracteres.
    let written = unsafe { GetLocaleInfoW(lcid, lc_type | LOCALE_NOUSEROVERRIDE, buffer.as_mut_ptr(), buffer.len() as i32) };
    (written > 1).then(|| String::from_utf16_lossy(&buffer[..written as usize - 1]))
}

/// O texto de um valor REG_SZ ou REG_EXPAND_SZ de `key`, até o primeiro NUL.
#[cfg(windows)]
fn text_value(key: &HostKey, name: &str) -> Option<String> {
    key.values.iter().find(|(value, kind, _)| value.eq_ignore_ascii_case(name) && matches!(kind, 1 | 2)).map(|(_, _, data)| {
        let units: Vec<u16> = data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
        String::from_utf16_lossy(&units)
    })
}

/// Grava o valor REG_SZ `name` de `key` (UTF-16 com o NUL).
#[cfg(windows)]
fn set_text(key: &mut HostKey, name: &str, text: &str) {
    let data: Vec<u8> = text.encode_utf16().chain([0]).flat_map(|unit| unit.to_le_bytes()).collect();
    match key.values.iter_mut().find(|(value, _, _)| value.eq_ignore_ascii_case(name)) {
        Some(slot) => {
            slot.1 = 1;
            slot.2 = data;
        }
        None => key.values.push((String::from(name), 1, data)),
    }
}

/// `Control\Nls` como uma instalação nova a deixa, sobre a cópia desta
/// máquina (`keys`, as chaves de `nls` para baixo). O que se troca depois
/// da instalação volta ao padrão dela:
/// - `CustomLocale` e `ExtendedLocale` ficam sem valores (são as
///   localidades que o usuário instala; vazias numa instalação nova);
/// - a localidade do sistema (`Language\Default` e o valor padrão de
///   `Locale`) é o idioma da instalação (`Language\InstallLanguage`), e
///   ACP, OEMCP e MACCP de `CodePage` são as páginas padrão desse idioma,
///   quando `CodePage` tem o arquivo delas: o "idioma para programas não
///   Unicode" e a opção beta de UTF-8 (65001) do intl.cpl trocam esses
///   valores. Numa instalação pt-BR: 0416, ACP 1252, OEMCP 850, MACCP 10000.
#[cfg(windows)]
fn clean_install_nls(keys: &mut [HostKey], nls: &str) {
    let path = |leaf: &str| format!("{nls}\\{leaf}");
    let (custom, extended) = (path("CustomLocale"), path("ExtendedLocale"));
    for key in keys.iter_mut().filter(|key| key.path.eq_ignore_ascii_case(&custom) || key.path.eq_ignore_ascii_case(&extended)) {
        key.values.clear();
    }
    let language_path = path("Language");
    let Some(install) = keys.iter().find(|key| key.path.eq_ignore_ascii_case(&language_path)).and_then(|key| text_value(key, "InstallLanguage")) else { return };
    let install = install.trim().to_string();
    let Ok(lcid) = u32::from_str_radix(&install, 16) else { return };
    let is_install = |text: Option<String>| text.and_then(|text| u32::from_str_radix(text.trim(), 16).ok()) == Some(lcid);
    if let Some(language) = keys.iter_mut().find(|key| key.path.eq_ignore_ascii_case(&language_path)) {
        if !is_install(text_value(language, "Default")) {
            println!("Control\\Nls\\Language: Default de volta ao idioma da instalacao ({install})");
            set_text(language, "Default", &install);
        }
    }
    let locale_path = path("Locale");
    if let Some(locale) = keys.iter_mut().find(|key| key.path.eq_ignore_ascii_case(&locale_path)) {
        if !is_install(text_value(locale, "")) {
            println!("Control\\Nls\\Locale: padrao de volta ao idioma da instalacao ({lcid:08x})");
            set_text(locale, "", &format!("{lcid:08x}"));
        }
    }
    let code_page_path = path("CodePage");
    if let Some(code_page) = keys.iter_mut().find(|key| key.path.eq_ignore_ascii_case(&code_page_path)) {
        for (name, lc_type) in DEFAULT_CODE_PAGES {
            let Some(default) = locale_info(lcid, lc_type).filter(|page| page.as_str() != "0") else { continue };
            if text_value(code_page, &default).is_none() {
                continue;
            }
            let current = text_value(code_page, name);
            if current.as_deref().map(str::trim) != Some(default.as_str()) {
                println!("Control\\Nls\\CodePage: {name} {} -> {default} (o padrao do idioma da instalacao {install})", current.unwrap_or_default());
                set_text(code_page, name, &default);
            }
        }
    }
}

/// As chaves de idioma da SYSTEM, já no conjunto de controle que a hive
/// guarda (`control_set`, como `ControlSet001`).
pub fn system_keys(control_set: &str) -> Vec<HostKey> {
    let mut keys = Vec::new();
    #[cfg(windows)]
    {
        let control = "SYSTEM\\CurrentControlSet\\Control";
        // `Control\Nls` inteira, com o que se troca depois da instalação de
        // volta ao padrão dela ([`clean_install_nls`]).
        let nls = format!("{control_set}\\Control\\Nls");
        let first = keys.len();
        registry::copy(registry::LOCAL_MACHINE, &format!("{control}\\Nls"), &nls, true, &mut keys);
        clean_install_nls(&mut keys[first..], &nls);
        registry::copy(registry::LOCAL_MACHINE, &format!("{control}\\MUI\\UILanguages"), &format!("{control_set}\\Control\\MUI\\UILanguages"), true, &mut keys);
        // O StringCacheGeneration (REG_DWORD): o LoadStringByReference da
        // KernelBase o lê antes de resolver toda cadeia indireta
        // ("@arquivo,-id") que não é do shell32.dll, para achar o cache de
        // cadeias MUI do usuário (`Local Settings\MuiCache\<geração>`); sem
        // a chave a resolução falha, e o explorer mostra o nome padrão do
        // Registro no lugar do traduzido (o "This PC" do Este Computador).
        registry::copy(registry::LOCAL_MACHINE, &format!("{control}\\MUI\\StringCacheSettings"), &format!("{control_set}\\Control\\MUI\\StringCacheSettings"), false, &mut keys);
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
        // O formato regional de uma instalação nova no idioma desta máquina:
        // os valores padrão da localidade (o GetLocaleInfoEx com
        // LOCALE_NOUSEROVERRIDE), o país dela em Geo e só o idioma principal
        // em User Profile, sem as personalizações daqui.
        let international = ".DEFAULT\\Control Panel\\International";
        let locale_name = registry::named_strings(registry::USERS, international).into_iter().find(|(name, _)| name.eq_ignore_ascii_case("LocaleName")).map(|(_, value)| value);
        if let Some(locale_name) = locale_name {
            keys.extend(region::international_keys(&locale_name));
            let profile = format!("{international}\\User Profile\\{locale_name}");
            registry::copy(registry::USERS, &profile, &format!("Control Panel\\International\\User Profile\\{locale_name}"), false, &mut keys);
        }
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
    use super::{default_keys, keyboard_layout_files, registry, system_keys, text_value, HostKey};

    /// A chave `Control\Nls\<leaf>` copiada para o ControlSet001.
    fn nls_key<'a>(keys: &'a [HostKey], leaf: &str) -> Option<&'a HostKey> {
        let path = format!("ControlSet001\\Control\\Nls\\{leaf}");
        keys.iter().find(|key| key.path.eq_ignore_ascii_case(&path))
    }

    /// `Control\Nls` vai inteira: ACP e OEMCP de `CodePage` nomeiam valores
    /// `CodePage\<página>` cujos arquivos estão em System32, com
    /// `Sorting\Versions` e `Normalization`; CustomLocale e ExtendedLocale vão
    /// sem valores, e a localidade do sistema é o idioma da instalação.
    #[test]
    fn nls_tree_is_copied_as_a_clean_install() {
        let keys = system_keys("ControlSet001");
        let Some(code_page) = nls_key(&keys, "CodePage") else {
            assert!(registry::list(registry::LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Nls").is_empty(), "Control\\Nls\\CodePage nao copiada");
            return;
        };
        let system32 = crate::windows_binaries::windows_directory().join("System32");
        for selector in ["ACP", "OEMCP"] {
            let page = text_value(code_page, selector).unwrap_or_else(|| panic!("CodePage sem {selector}"));
            let file = text_value(code_page, page.trim()).unwrap_or_else(|| panic!("CodePage sem o arquivo da pagina {page}"));
            assert!(system32.join(&file).is_file(), "{file} (pagina {page}) ausente em System32");
        }
        assert!(nls_key(&keys, "Sorting\\Versions").is_some_and(|key| text_value(key, "").is_some()), "Sorting\\Versions nao copiada");
        assert!(nls_key(&keys, "Normalization").is_some_and(|key| !key.values.is_empty()), "Normalization nao copiada");
        for leaf in ["CustomLocale", "ExtendedLocale"] {
            assert!(nls_key(&keys, leaf).is_none_or(|key| key.values.is_empty()), "{leaf} com valores");
        }
        let language = nls_key(&keys, "Language").expect("Nls\\Language nao copiada");
        let lcid = |text: Option<String>| text.and_then(|text| u32::from_str_radix(text.trim(), 16).ok());
        assert_eq!(lcid(text_value(language, "Default")), lcid(text_value(language, "InstallLanguage")), "Language\\Default diferente do idioma da instalacao");
    }

    /// O `Control\MUI\StringCacheSettings` vai com o StringCacheGeneration
    /// (REG_DWORD, 4 bytes), o valor que a KernelBase exige para resolver as
    /// cadeias indiretas fora do shell32.
    #[test]
    fn mui_string_cache_generation_is_copied() {
        let keys = system_keys("ControlSet001");
        let host = registry::list(registry::LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\MUI");
        if !host.iter().any(|name| name.eq_ignore_ascii_case("StringCacheSettings")) {
            return;
        }
        let key = keys.iter().find(|key| key.path.eq_ignore_ascii_case("ControlSet001\\Control\\MUI\\StringCacheSettings")).expect("StringCacheSettings nao copiada");
        let generation = key.values.iter().find(|(name, _, _)| name.eq_ignore_ascii_case("StringCacheGeneration"));
        assert!(generation.is_some_and(|(_, kind, data)| *kind == 4 && data.len() == 4), "StringCacheGeneration ausente ou fora de REG_DWORD");
    }

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
