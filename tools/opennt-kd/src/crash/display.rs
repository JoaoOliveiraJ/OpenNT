//! A primeira tela pelo log: o que o WdLog do dxgkrnl diz das apresentações
//! e das mudanças de VidPn, e as linhas do dwm.exe.
//!
//! Do WdLog saem, por sequência, as entradas das funções que contam a
//! história do primeiro quadro: `DdiPresentDisplayOnly` (no anel de rastro:
//! p1 status, p2 origem do VidPn, p3 VA da origem), `DdiSetVidPnSourceVisibility`
//! (no anel de eventos: p1 status, p2 origem, p3 Visible), `DisplayOnOff`,
//! `CddSetOrigin`, os erros de `BLTQUEUE` e as trocas de dono da origem. Uma
//! apresentação com a VA da origem diferente da primeira (a primária do
//! cdd) sai marcada `NOVA-ORIGEM`.
//!
//! Do log saem o pid do dwm.exe (o último `criou dwm.exe (pid N)`), as
//! linhas `[win32k] PID:` dele, os `[crash] dwm.exe`, os HARDERROR com o pid,
//! as linhas `*** STOP`, o `LOGON_SCREEN_OK` e as linhas `[xtask] tela`.

use super::wdlog::{Entry, Section};

/// As funções cujas entradas no WdLog contam a história da primeira tela.
pub const FUNCTIONS: &[&str] = &["DdiPresentDisplayOnly", "SetVidPnSourceVisibility", "DisplayOnOff", "CddSetOrigin", "BLTQUEUE", "DisplayOnlyPresent", "SetVidPnSourceOwner", "DwmProcess"];

/// O nome de uma função na tabela é cortado neste tamanho.
const NAME_WIDTH: usize = 70;
/// As linhas do log são cortadas neste tamanho.
const LINE_WIDTH: usize = 230;

/// Uma entrada do WdLog de uma das [`FUNCTIONS`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub entry: Entry,
    pub name: String,
    /// `NOVA-ORIGEM`, `Visible=1` ou vazio.
    pub tag: String,
}

/// As entradas das [`FUNCTIONS`] em todas as seções, por sequência.
/// `name_of` dá o nome do endereço de retorno de uma entrada.
pub fn rows(sections: &[Section], name_of: &dyn Fn(u64) -> Option<String>) -> Vec<Row> {
    let mut rows: Vec<Row> = sections
        .iter()
        .flat_map(|section| section.entries.iter())
        .filter_map(|entry| {
            let name = name_of(entry.return_address)?;
            FUNCTIONS.iter().any(|function| name.contains(function)).then(|| Row { entry: entry.clone(), name, tag: String::new() })
        })
        .collect();
    rows.sort_by_key(|row| row.entry.sequence);
    let mut first_source: Option<u64> = None;
    for row in &mut rows {
        let source = row.entry.parameters[2];
        if row.name.contains("DdiPresentDisplayOnly") {
            let first = *first_source.get_or_insert(source);
            if source != first {
                row.tag = "NOVA-ORIGEM".into();
            }
        } else if row.name.contains("SetVidPnSourceVisibility") {
            row.tag = format!("Visible={source:x}");
        }
    }
    rows
}

fn cut(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    text.chars().take(width).collect()
}

/// As linhas em texto.
pub fn render(rows: &[Row]) -> String {
    let mut output = String::new();
    for row in rows {
        let thread = format!("{:x}", row.entry.thread);
        let thread = &thread[thread.len().saturating_sub(6)..];
        let parameters: Vec<String> = row.entry.parameters.iter().map(|value| format!("{value:x}")).collect();
        output.push_str(&format!("seq={:#x} thr={thread} {} p={}", row.entry.sequence, cut(&row.name, NAME_WIDTH), parameters.join(" ")));
        if !row.tag.is_empty() {
            output.push(' ');
            output.push_str(&row.tag);
        }
        output.push('\n');
    }
    output
}

/// O dwm.exe no log.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dwm {
    pub pid: Option<u64>,
    /// As linhas que interessam à primeira tela (índices).
    pub lines: Vec<usize>,
}

/// O pid do último `criou dwm.exe (pid N)`.
fn dwm_pid(line: &str) -> Option<u64> {
    let rest = &line[line.find("criou dwm.exe (pid ")? + "criou dwm.exe (pid ".len()..];
    rest.split(')').next()?.parse().ok()
}

/// `pid N` como palavra inteira na linha.
fn mentions_pid(line: &str, pid: u64) -> bool {
    let needle = format!("pid {pid}");
    line.match_indices(&needle).any(|(at, _)| !line[at + needle.len()..].starts_with(|character: char| character.is_ascii_digit()))
}

/// As linhas do dwm.exe e as da tela.
pub fn dwm(lines: &[String]) -> Dwm {
    let pid = lines.iter().filter_map(|line| dwm_pid(line)).last();
    let win32k = pid.map(|pid| format!("[win32k] {pid}:"));
    let selected = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| {
            let of_dwm = match (pid, &win32k) {
                (Some(pid), Some(win32k)) => line.contains(win32k.as_str()) || line.starts_with("[crash] dwm.exe") || (line.contains("HARDERROR") && mentions_pid(line, pid)),
                _ => false,
            };
            of_dwm || line.starts_with("*** STOP") || line.contains("LOGON_SCREEN_OK") || line.contains("[xtask] tela")
        })
        .map(|(index, _)| index)
        .collect();
    Dwm { pid, lines: selected }
}

/// As linhas do dwm em texto (as primeiras `limit`, ou todas com `None`).
pub fn render_dwm(dwm: &Dwm, lines: &[String], limit: Option<usize>) -> String {
    let mut output = match dwm.pid {
        Some(pid) => format!("dwm.exe: pid {pid}\n"),
        None => "dwm.exe: nao foi criado neste log\n".to_string(),
    };
    let shown = limit.map_or(dwm.lines.len(), |limit| limit.min(dwm.lines.len()));
    for &index in &dwm.lines[..shown] {
        output.push_str(&format!("L{} {}\n", index + 1, cut(&lines[index], LINE_WIDTH)));
    }
    if shown < dwm.lines.len() {
        output.push_str(&format!("... mais {} linhas (--all lista todas)\n", dwm.lines.len() - shown));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ring: u32, sequence: u64, return_address: u64, parameters: [u64; 5]) -> Entry {
        Entry { ring, offset: 0, sequence, thread: 0xffffc000c0091100, return_address, parameters }
    }

    #[test]
    fn presents_and_visibility_by_sequence() {
        let sections = vec![
            Section { id: 0x15, offset: 0, end: 0x100, entries: vec![entry(0x15, 0x892, 0x2000, [0, 0, 0x82d9000, 0, 1]), entry(0x15, 0x871, 0x2000, [0, 0, 0x7fd9000, 0, 1]), entry(0x15, 0x800, 0x3000, [0; 5])] },
            Section { id: 0x14, offset: 0x100, end: 0x200, entries: vec![entry(0x14, 0x850, 0x1000, [0, 0, 1, 0, 0])] },
        ];
        let name_of = |address: u64| match address {
            0x1000 => Some("DXGADAPTER::DdiSetVidPnSourceVisibility+0x43".to_string()),
            0x2000 => Some("DXGADAPTER::DdiPresentDisplayOnly+0xe".to_string()),
            _ => Some("DpiFdoDispatchPnp+0x10".to_string()),
        };
        let rows = rows(&sections, &name_of);
        let sequences: Vec<u64> = rows.iter().map(|row| row.entry.sequence).collect();
        assert_eq!(sequences, [0x850, 0x871, 0x892]);
        assert_eq!(rows[0].tag, "Visible=1");
        assert_eq!(rows[1].tag, "");
        assert_eq!(rows[2].tag, "NOVA-ORIGEM");
        let text = render(&rows);
        assert!(text.contains("seq=0x892 thr=091100 DXGADAPTER::DdiPresentDisplayOnly+0xe p=0 0 82d9000 0 1 NOVA-ORIGEM\n"), "{text}");
    }

    #[test]
    fn dwm_lines_follow_the_last_dwm_pid() {
        let lines: Vec<String> = [
            "[init] winlogon.exe (pid 200) criou dwm.exe (pid 504) por NtCreateUserProcess",
            "[win32k] 504:680 NtGdiDdDDIDDisplayEnum FALHOU com 0xc0000023 (chamador DispBroker.dll+0x605e)",
            "[init] winlogon.exe (pid 200) criou dwm.exe (pid 752) por NtCreateUserProcess",
            "[win32k] 504:592 NtGdiDdDDIDDisplayEnum FALHOU com 0xc0000023",
            "[win32k] 752:760 NtGdiDdDDIPresent FALHOU com 0xc01e000e",
            "[usermode] HARDERROR: status=0xf0464645 params= (pid 752, retorno 0x0)",
            "[usermode] HARDERROR: status=0xf0464645 params= (pid 7520, retorno 0x0)",
            "[crash] dwm.exe 752:584: NtRaiseHardError 0xf0464645",
            "[xtask] tela: 73 pixels desenhados",
            "*** STOP (KeBugCheckEx): 0x000000e2 (0x0, 0x0, 0x0, 0x0)",
        ]
        .iter()
        .map(|line| line.to_string())
        .collect();
        let found = dwm(&lines);
        assert_eq!(found.pid, Some(752));
        assert_eq!(found.lines, [4, 5, 7, 8, 9]);
        let text = render_dwm(&found, &lines, Some(2));
        assert!(text.starts_with("dwm.exe: pid 752\nL5 [win32k] 752:760"), "{text}");
        assert!(text.ends_with("... mais 3 linhas (--all lista todas)\n"), "{text}");
        assert_eq!(dwm(&lines[1..2]).pid, None);
    }
}
