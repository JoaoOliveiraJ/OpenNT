//! Mapeamento de arquivos .ini para o Registro
//! (`SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping`).
//!
//! O basesrv.dll real lê a árvore inteira na inicialização do csrss
//! (BaseSrvInitializeIniFileMappings) e falha a carga do servidor sem ela.
//! Os valores são os de uma instalação do Windows 10 19041: uma subchave por
//! arquivo .ini, uma por seção mapeada, e REG_SZ que apontam a seção para
//! uma chave do usuário (`USR:`) ou da máquina (`SYS:`), com os prefixos de
//! comportamento (`#`, `!`) do formato. Os textos com `\\` dobrado são assim
//! no registro de origem. Só o boot do processo inicial real
//! (`--initial-process=smss`) leva esta árvore.
//!
//! Dados puros da hive SOFTWARE (veja `cm/seed.rs`): o `xtask` grava estas
//! chaves no arquivo da hive e o kernel só as semeia em memória quando o
//! arquivo falta.

use alloc::vec::Vec;

use super::seed::{SeedKey, REG_SZ};

/// A raiz da árvore, relativa à hive SOFTWARE.
const ROOT: &str = "Microsoft\\Windows NT\\CurrentVersion\\IniFileMapping";

/// (subchave relativa a `IniFileMapping`, valores REG_SZ; nome vazio é o
/// valor padrão da chave).
const TREE: &[(&str, &[(&str, &str)])] = &[
    ("", &[]),
    (
        "control.ini",
        &[
            ("Color Schemes", "#USR:Control Panel\\Color Schemes"),
            ("Current", "#USR:Control Panel\\Current"),
            ("Custom Colors", "#USR:Control Panel\\Custom Colors"),
            ("don't load", "USR:Control Panel\\don't load"),
            ("drivers.desc", "SYS:Microsoft\\Windows NT\\CurrentVersion\\drivers.desc"),
            ("MMCPL", "USR:Control Panel\\MMCPL"),
            ("Patterns", "#USR:Control Panel\\Patterns"),
            ("related.desc", "SYS:Microsoft\\Windows NT\\CurrentVersion\\related.desc"),
            ("Screen Saver.3DText", "USR:Control Panel\\Screen Saver.3DText"),
            ("Userinstallable.drivers", "SYS:Microsoft\\Windows NT\\CurrentVersion\\Userinstallable.drivers"),
        ],
    ),
    ("KeyboardLayout.ini", &[("", ""), ("Preload", "USR:Keyboard Layout\\Preload")]),
    ("KeyboardLayout.ini\\Keyboard Layout", &[("", "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Keyboard Layout"), ("Active", "USR:Keyboard Layout")]),
    ("KeyboardLayout.ini\\Substitutes", &[("", "USR:Keyboard Layout\\Substitutes")]),
    ("regedt32.ini", &[("", "USR:Software\\Microsoft\\RegEdt32")]),
    (
        "system.ini",
        &[
            ("drivers32", "SYS:Microsoft\\Windows NT\\CurrentVersion\\Drivers32"),
            ("MCI", "SYS:Microsoft\\Windows NT\\CurrentVersion\\MCI"),
            ("MCI32", "SYS:Microsoft\\Windows NT\\CurrentVersion\\MCI32"),
        ],
    ),
    (
        "system.ini\\boot",
        &[
            ("", "SYS:Microsoft\\Windows NT\\CurrentVersion\\WOW\\boot"),
            ("ScreenSaverActive", "USR:Control Panel\\Desktop"),
            ("ScreenSaverIsSecure", "USR:Control Panel\\Desktop"),
            ("SCRNSAVE.EXE", "USR:Control Panel\\Desktop"),
            ("Shell", "SYS:Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
        ],
    ),
    (
        "win.ini",
        &[
            ("AeDebug", "SYS:Microsoft\\Windows NT\\CurrentVersion\\AeDebug"),
            ("CLOCK", "#USR:SOFTWARE\\\\MICROSOFT\\\\CLOCK"),
            ("COLORS", "#USR:CONTROL PANEL\\\\COLORS"),
            ("CONSOLE", "USR:CONSOLE"),
            ("CURSORS", "#USR:CONTROL PANEL\\\\CURSORS"),
            ("DESKTOP", "#USR:CONTROL PANEL\\\\DESKTOP"),
            ("Devices", "USR:Software\\Microsoft\\Windows NT\\CurrentVersion\\Devices"),
            ("EMBEDDING", "!#SYS:MICROSOFT\\\\WINDOWS NT\\\\CURRENTVERSION\\\\EMBEDDING"),
            ("EXTENSIONS", "#USR:SOFTWARE\\\\MICROSOFT\\\\WINDOWS NT\\\\CURRENTVERSION\\\\EXTENSIONS"),
            ("Fonts", "#SYS:Microsoft\\Windows NT\\CurrentVersion\\Fonts"),
            ("FontSubstitutes", "#SYS:Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes"),
            ("GRE_INITIALIZE", "SYS:MICROSOFT\\\\WINDOWS NT\\\\CURRENTVERSION\\\\GRE_INITIALIZE"),
            ("Intl", "#USR:Control Panel\\International"),
            ("IOPROCS", "#USR:CONTROL PANEL\\\\IOPROCS"),
            ("MCI EXTENSIONS", "SYS:MICROSOFT\\\\WINDOWS NT\\\\CURRENTVERSION\\\\MCI EXTENSIONS"),
            ("MODULECOMPATIBILITY", "SYS:MICROSOFT\\\\WINDOWS NT\\\\CURRENTVERSION\\\\MODULECOMPATIBILITY"),
            ("MSCHARMAP", "#USR:SOFTWARE\\\\MICROSOFT\\\\CHARMAP"),
            ("NET_FILES", "USR:SOFTWARE\\\\MICROSOFT\\\\WINDOWS NT\\\\CURRENTVERSION\\\\NETWORK\\\\PERSISTENT CONNECTIONS"),
            ("NWCS", "SYS:MICROSOFT\\\\WINDOWS NT\\\\CURRENTVERSION\\\\NWCS"),
            ("Ports", "SYS:Microsoft\\Windows NT\\CurrentVersion\\Ports"),
            ("PrinterPorts", "USR:Software\\Microsoft\\Windows NT\\CurrentVersion\\PrinterPorts"),
            ("SOUNDS", "#USR:CONTROL PANEL\\\\SOUNDS"),
            ("TRUETYPE", "#USR:SOFTWARE\\\\MICROSOFT\\\\WINDOWS NT\\\\CURRENTVERSION\\\\TRUETYPE"),
            ("TWAIN", "#USR:SOFTWARE\\\\MICROSOFT\\\\WINDOWS NT\\\\CURRENTVERSION\\\\TWAIN"),
            ("WINDOWS HELP", "USR:SOFTWARE\\\\MICROSOFT\\\\WINDOWS HELP"),
            ("Winlogon", "SYS:Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
        ],
    ),
    ("win.ini\\NETWORK", &[]),
    (
        "win.ini\\Windows",
        &[
            ("", "USR:Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"),
            ("APPINIT_DLLS", "SYS:MICROSOFT\\\\WINDOWS NT\\\\CURRENTVERSION\\\\WINDOWS"),
            ("Beep", "#USR:Control Panel\\Sound"),
            ("CoolSwitch", "USR:Control Panel\\Desktop"),
            ("DEFAULTSEPARATEVDM", "\\\\REGISTRY\\\\MACHINE\\\\SYSTEM\\\\CURRENTCONTROLSET\\\\CONTROL\\\\WOW"),
            ("DEVICENOTSELECTEDTIMEOUT", "#SYS:MICROSOFT\\\\WINDOWS NT\\\\CURRENTVERSION\\\\WINDOWS"),
            ("DoubleClickHeight", "#USR:Control Panel\\Mouse"),
            ("DoubleClickSpeed", "#USR:Control Panel\\Mouse"),
            ("DoubleClickWidth", "#USR:Control Panel\\Mouse"),
            ("DragFullWindows", "USR:Control Panel\\Desktop"),
            ("InitialKeyboardIndicators", "USR:Control Panel\\Keyboard"),
            ("LowPowerActive", "#USR:Control Panel\\Desktop"),
            ("LowPowerTimeOut", "#USR:Control Panel\\Desktop"),
            ("MouseSpeed", "#USR:Control Panel\\Mouse"),
            ("MouseThreshold1", "#USR:Control Panel\\Mouse"),
            ("MouseThreshold2", "#USR:Control Panel\\Mouse"),
            ("PowerOffActive", "#USR:Control Panel\\Desktop"),
            ("PowerOffTimeOut", "#USR:Control Panel\\Desktop"),
            ("ScreenSaveActive", "#USR:Control Panel\\Desktop"),
            ("ScreenSaveTimeOut", "#USR:Control Panel\\Desktop"),
            ("SnapToDefaultButton", "#USR:Control Panel\\Mouse"),
            ("Spooler", "#SYS:Microsoft\\Windows NT\\CurrentVersion\\Windows"),
            ("SWAPDISK", "SYS:MICROSOFT\\\\WINDOWS NT\\\\CURRENTVERSION\\\\WINDOWS"),
            ("SwapMouseButtons", "#USR:Control Panel\\Mouse"),
            ("TRANSMISSIONRETRYTIMEOUT", "#SYS:MICROSOFT\\\\WINDOWS NT\\\\CURRENTVERSION\\\\WINDOWS"),
        ],
    ),
];

/// As chaves da árvore `IniFileMapping` que o basesrv.dll real lê.
pub fn seed_keys() -> Vec<SeedKey> {
    TREE.iter()
        .map(|(relative, values)| {
            let path = if relative.is_empty() { alloc::string::String::from(ROOT) } else { alloc::format!("{ROOT}\\{relative}") };
            let mut key = SeedKey::new(&path);
            for (name, text) in values.iter() {
                key.text(name, REG_SZ, text);
            }
            key
        })
        .collect()
}
