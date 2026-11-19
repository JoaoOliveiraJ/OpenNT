//! Os processos pelo nome: `dwm.exe`, `dwm`, `svchost.exe#2` (a segunda
//! instância na ordem da lista do alvo), o PID ou o EPROCESS. Os roteiros
//! dos agentes faziam `ps` + `save-word` + `.process $x` para isso.

use kd_client::monitor::Process;
use kd_client::Client;

/// O processo pedido.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Wanted {
    /// PID ou EPROCESS.
    Number(u64),
    /// O nome (em minúsculas) e a instância (1 = a primeira).
    Name { name: String, instance: usize },
}

/// Lê o pedido.
pub fn parse(text: &str) -> Result<Wanted, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("processo vazio".into());
    }
    if let Some(number) = kd_client::parse_number(text) {
        return Ok(Wanted::Number(number));
    }
    let (name, instance) = match text.rsplit_once('#') {
        Some((name, count)) => (name, count.trim().parse::<usize>().ok().filter(|count| *count >= 1).ok_or_else(|| format!("{text}: instancia invalida (nome#N, N a partir de 1)"))?),
        None => (text, 1),
    };
    let name = name.trim().to_ascii_lowercase();
    if name.is_empty() {
        return Err(format!("{text}: falta o nome do processo"));
    }
    Ok(Wanted::Name { name, instance })
}

/// O nome bate com o pedido (com ou sem `.exe`, sem diferença de caixa).
pub fn same_name(wanted: &str, name: &str) -> bool {
    let (wanted, name) = (wanted.to_ascii_lowercase(), name.to_ascii_lowercase());
    wanted == name || name.strip_suffix(".exe") == Some(wanted.as_str()) || wanted.strip_suffix(".exe") == Some(name.as_str())
}

/// Os nomes da lista (para a mensagem de erro).
fn names(list: &[Process]) -> String {
    let mut names: Vec<&str> = Vec::new();
    for process in list {
        if !names.contains(&process.name.as_str()) {
            names.push(&process.name);
        }
    }
    let more = names.len().saturating_sub(40);
    names.truncate(40);
    let mut text = names.join(", ");
    if more > 0 {
        text.push_str(&format!(" e mais {more}"));
    }
    text
}

/// Escolhe na lista; `Ok(None)` quando o nome não está nela (o processo
/// ainda não existe).
pub fn pick<'a>(list: &'a [Process], wanted: &Wanted) -> Result<Option<&'a Process>, String> {
    match wanted {
        Wanted::Number(number) => list.iter().find(|process| process.pid == *number || process.eprocess == *number).map(Some).ok_or_else(|| format!("nenhum processo com PID ou EPROCESS {number:#x}")),
        Wanted::Name { name, instance } => {
            let matching: Vec<&Process> = list.iter().filter(|process| same_name(name, &process.name)).collect();
            if matching.is_empty() {
                return Ok(None);
            }
            matching.get(instance - 1).copied().map(Some).ok_or_else(|| format!("{name}: so {} instancia(s), pedida a {instance}", matching.len()))
        }
    }
}

/// O processo pelo pedido (`Ok(None)`: nome que não está rodando).
pub fn find(client: &mut Client, text: &str) -> Result<Option<Process>, String> {
    let wanted = parse(text)?;
    let list = client.processes()?;
    Ok(pick(&list, &wanted)?.cloned())
}

/// O processo pelo pedido, que precisa estar rodando.
pub fn resolve(client: &mut Client, text: &str) -> Result<Process, String> {
    let wanted = parse(text)?;
    let list = client.processes()?;
    match pick(&list, &wanted)? {
        Some(process) => Ok(process.clone()),
        None => Err(format!("processo {} nao encontrado; rodando: {}", text.trim(), names(&list))),
    }
}

/// O texto do processo para o alvo (`.process`, `uthreads`): um número vai
/// como está; um nome vira o EPROCESS.
pub fn argument(client: &mut Client, text: &str) -> Result<String, String> {
    match parse(text)? {
        Wanted::Number(_) => Ok(text.trim().to_string()),
        Wanted::Name { .. } => Ok(format!("{:#x}", resolve(client, text)?.eprocess)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: u64, name: &str) -> Process {
        Process { pid, eprocess: 0xffff_c000_0000_0000 + pid * 0x1000, cr3: 0, threads: 1, name: name.into() }
    }

    #[test]
    fn picks_processes_by_name_and_instance() {
        let list = vec![process(4, "System"), process(420, "svchost.exe"), process(500, "dwm.exe"), process(576, "svchost.exe")];
        assert_eq!(parse("dwm.exe"), Ok(Wanted::Name { name: "dwm.exe".into(), instance: 1 }));
        assert_eq!(parse("svchost.exe#2"), Ok(Wanted::Name { name: "svchost.exe".into(), instance: 2 }));
        assert_eq!(parse("0x1f4"), Ok(Wanted::Number(500)));
        assert!(parse("x#0").is_err());
        assert!(parse("#2").is_err());
        assert_eq!(pick(&list, &parse("DWM").unwrap()).unwrap().map(|process| process.pid), Some(500));
        assert_eq!(pick(&list, &parse("svchost.exe#2").unwrap()).unwrap().map(|process| process.pid), Some(576));
        assert!(pick(&list, &parse("svchost#3").unwrap()).unwrap_err().contains("so 2"));
        assert_eq!(pick(&list, &parse("LogonUI.exe").unwrap()), Ok(None));
        assert_eq!(pick(&list, &Wanted::Number(0xffff_c000_0000_0000 + 4 * 0x1000)).unwrap().map(|process| process.pid), Some(4));
        assert!(pick(&list, &Wanted::Number(9999)).is_err());
        assert!(same_name("system", "System"));
        assert!(!same_name("svc", "svchost.exe"));
        assert_eq!(names(&list), "System, svchost.exe, dwm.exe");
    }
}
