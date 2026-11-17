//! A máquina do depurador com snapshots e com gravação e reprodução
//! (`cargo xtask debug --vm-snapshots | --record=ARQ | --replay=ARQ`).
//!
//! - `--vm-snapshots`: os discos entram como overlays qcow2 novos sobre as
//!   imagens cruas do build (`<build>/snapshots/*.qcow2`), e o `savevm` e o
//!   `loadvm` do monitor do QEMU funcionam. As imagens cruas não mudam.
//! - `--record=ARQ`: a gravação do QEMU (`-icount shift=auto,rr=record`)
//!   com o snapshot inicial `inicio` (`rrsnapshot`), sempre no TCG. Os
//!   discos são overlays qcow2 ao lado da gravação, atrás do `blkreplay`;
//!   a entrada das portas seriais (a sessão do depurador na COM2) entra no
//!   arquivo. O relógio da CMOS anda pelo relógio virtual a partir de uma
//!   data fixa, guardada com a memória e os processadores em `ARQ.maquina`.
//! - `--replay=ARQ`: a reprodução da mesma gravação, com o gdbstub do QEMU
//!   numa porta local (`-gdb`): o cliente fala com ele e não com o
//!   depurador do kernel, e os passos para trás (`bs`, `bc`) voltam pelo
//!   snapshot inicial.
//!
//! Os arquivos ficam todos na pasta da gravação (ou na de build): nada vai
//! para a pasta temporária do usuário.

use std::path::{Path, PathBuf};

use crate::qcow2;
use crate::qemu::{Disks, MachineOptions};

/// O snapshot criado no começo da gravação (e carregado na reprodução).
pub const INITIAL_SNAPSHOT: &str = "inicio";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    Snapshots,
    Record(PathBuf),
    Replay(PathBuf),
}

impl Mode {
    pub fn replay(&self) -> bool {
        matches!(self, Mode::Replay(_))
    }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// O overlay de cada disco: (nome, imagem crua, overlay).
fn overlays(disks: &Disks, mode: &Mode) -> Vec<(&'static str, PathBuf, PathBuf)> {
    let place = |name: &str| match mode {
        Mode::Snapshots => disks.boot.with_file_name("snapshots").join(format!("{name}.qcow2")),
        Mode::Record(file) | Mode::Replay(file) => with_suffix(file, &format!(".{name}.qcow2")),
    };
    let mut list = vec![("os", disks.boot.clone(), place("os"))];
    if let Some(data) = &disks.data {
        list.push(("ntfs", data.clone(), place("ntfs")));
    }
    if let Some(nvme) = &disks.nvme {
        list.push(("nvme", nvme.clone(), place("nvme")));
    }
    list
}

/// O arquivo com a memória, os processadores e o relógio de uma gravação.
pub fn machine_file(recording: &Path) -> PathBuf {
    with_suffix(recording, ".maquina")
}

/// Cria (ou confere, na reprodução) os overlays dos discos.
fn prepare_overlays(disks: &Disks, mode: &Mode) -> Result<Vec<(&'static str, PathBuf, PathBuf)>, String> {
    let list = overlays(disks, mode);
    for (_, raw, overlay) in &list {
        if mode.replay() {
            if !overlay.is_file() {
                return Err(format!("{}: a reproducao precisa dos discos da gravacao", overlay.display()));
            }
            continue;
        }
        if let Some(parent) = overlay.parent() {
            std::fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
        }
        let size = std::fs::metadata(raw).map_err(|error| format!("{}: {error}", raw.display()))?.len();
        let backing = std::fs::canonicalize(raw).map_err(|error| format!("{}: {error}", raw.display()))?;
        qcow2::create_overlay(overlay, &backing, size)?;
    }
    Ok(list)
}

/// Tira de `arguments` os pares `-drive ...` e o `-device nvme,...`.
fn without_drives(arguments: Vec<String>) -> Vec<String> {
    let mut output = Vec::with_capacity(arguments.len());
    let mut iterator = arguments.into_iter().peekable();
    while let Some(argument) = iterator.next() {
        if argument == "-drive" {
            iterator.next();
            continue;
        }
        if argument == "-device" && iterator.peek().is_some_and(|value| value.starts_with("nvme,")) {
            iterator.next();
            continue;
        }
        output.push(argument);
    }
    output
}

/// Troca o valor de uma opção (`-rtc`, `-m`, `-smp`) nos argumentos.
fn replace_option(arguments: &mut [String], option: &str, value: &str) {
    if let Some(index) = arguments.iter().position(|argument| argument == option) {
        if let Some(slot) = arguments.get_mut(index + 1) {
            *slot = value.to_string();
        }
    }
}

/// A data fixa da CMOS de uma gravação nova (a hora do hospedeiro agora).
fn fixed_rtc_base() -> String {
    let seconds = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|duration| duration.as_secs()).unwrap_or(0);
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}", rest / 3600, rest % 3600 / 60, rest % 60)
}

/// Os argumentos da máquina para o modo pedido, sobre os argumentos comuns
/// (`base`). Devolve também a máquina efetiva (o TCG na gravação).
pub fn arguments(base: Vec<String>, disks: &Disks, machine: &MachineOptions, mode: &Mode, gdb_port: Option<u16>) -> Result<Vec<String>, String> {
    let list = prepare_overlays(disks, mode)?;
    let mut arguments = without_drives(base);
    match mode {
        Mode::Snapshots => {
            for (name, _, overlay) in &list {
                let file = overlay.display();
                match *name {
                    "os" => arguments.extend(["-drive".to_string(), format!("format=qcow2,file={file}")]),
                    "ntfs" => arguments.extend(["-drive".to_string(), format!("format=qcow2,if=ide,index=1,media=disk,file={file}")]),
                    _ => arguments.extend(["-drive".to_string(), format!("if=none,id=nvm,format=qcow2,file={file}"), "-device".to_string(), "nvme,serial=opennt,drive=nvm".to_string()]),
                }
            }
        }
        Mode::Record(file) | Mode::Replay(file) => {
            let recording = file.display().to_string();
            let machine_path = machine_file(file);
            let (rtc, memory, smp) = if mode.replay() {
                let text = std::fs::read_to_string(&machine_path).map_err(|error| format!("{}: {error}", machine_path.display()))?;
                let field = |key: &str| text.lines().find_map(|line| line.strip_prefix(key).map(|value| value.trim().to_string()));
                (field("rtc=").unwrap_or_default(), field("memoria=").unwrap_or_else(|| machine.memory_mb.to_string()), field("processadores=").unwrap_or_else(|| machine.smp.to_string()))
            } else {
                let rtc = format!("base={},clock=vm", fixed_rtc_base());
                std::fs::write(&machine_path, format!("rtc={rtc}\nmemoria={}\nprocessadores={}\n", machine.memory_mb, machine.smp)).map_err(|error| format!("{}: {error}", machine_path.display()))?;
                (rtc, machine.memory_mb.to_string(), machine.smp.to_string())
            };
            replace_option(&mut arguments, "-rtc", &rtc);
            replace_option(&mut arguments, "-m", &memory);
            replace_option(&mut arguments, "-smp", &smp);
            let rr = if mode.replay() { "replay" } else { "record" };
            // `OPENNT_RR_SHIFT` troca o passo do relógio virtual (padrão auto).
            let shift = std::env::var("OPENNT_RR_SHIFT").unwrap_or_else(|_| "auto".into());
            arguments.extend(["-icount".to_string(), format!("shift={shift},rr={rr},rrfile={recording},rrsnapshot={INITIAL_SNAPSHOT}")]);
            for (index, (name, _, overlay)) in list.iter().enumerate() {
                let file = overlay.display();
                arguments.extend(["-drive".to_string(), format!("if=none,id=disco{index},format=qcow2,file={file}")]);
                arguments.extend(["-drive".to_string(), format!("if=none,id=rr{index},driver=blkreplay,image=disco{index}")]);
                match *name {
                    "os" => arguments.extend(["-device".to_string(), format!("ide-hd,drive=rr{index},bus=ide.0,unit=0,bootindex=0")]),
                    "ntfs" => arguments.extend(["-device".to_string(), format!("ide-hd,drive=rr{index},bus=ide.0,unit=1")]),
                    _ => arguments.extend(["-device".to_string(), format!("nvme,serial=opennt,drive=rr{index}")]),
                }
            }
            if let (true, Some(port)) = (mode.replay(), gdb_port) {
                arguments.extend(["-gdb".to_string(), format!("tcp:127.0.0.1:{port}"), "-S".to_string()]);
            }
        }
    }
    Ok(arguments)
}

/// A máquina efetiva: a gravação e a reprodução só existem no TCG.
pub fn machine(machine: &MachineOptions, mode: &Mode) -> MachineOptions {
    let mut machine = machine.clone();
    if !matches!(mode, Mode::Snapshots) {
        machine.accelerator = "tcg".into();
    }
    machine
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drives_are_replaced() {
        let base: Vec<String> = ["-accel", "tcg", "-rtc", "base=x,clock=host", "-m", "4096", "-drive", "format=raw,file=os.img", "-drive", "format=raw,if=ide,index=1,file=ntfs.img", "-device", "nvme,serial=opennt,drive=nvm", "-device", "qemu-xhci"].iter().map(|text| text.to_string()).collect();
        let stripped = without_drives(base);
        assert_eq!(stripped, vec!["-accel", "tcg", "-rtc", "base=x,clock=host", "-m", "4096", "-device", "qemu-xhci"]);
        let mut arguments = stripped;
        replace_option(&mut arguments, "-rtc", "base=y,clock=vm");
        assert_eq!(arguments[3], "base=y,clock=vm");
        assert_eq!(with_suffix(Path::new("build/x/g.bin"), ".os.qcow2"), PathBuf::from("build/x/g.bin.os.qcow2"));
        let base = fixed_rtc_base();
        assert_eq!(base.len(), 19, "{base}");
        assert_eq!(&base[10..11], "T");
    }
}
