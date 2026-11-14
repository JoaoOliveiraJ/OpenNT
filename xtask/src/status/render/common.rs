//! Peças comuns das páginas: formatação, medidores, ícones, estados, a
//! moldura da página (cabeçalho, trilha e rodapé), as seções, a barra de
//! filtros e as notas longas. O CSS e os scripts ficam em `assets.rs`.

use super::super::{ComponentRow, ModuleState, PhaseRow, Report, State};
use super::assets::CSS;

// ---- formatação ----------------------------------------------------------------

pub fn escape(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            _ => output.push(character),
        }
    }
    output
}

/// Inteiro com separador de milhar pt-BR (`2.971`).
pub fn int(value: usize) -> String {
    let digits = value.to_string();
    let mut output = String::new();
    for (index, character) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            output.push('.');
        }
        output.push(character);
    }
    output
}

/// Porcentagem com uma casa e vírgula decimal (`27,1%`), em texto puro.
pub fn percent(part: usize, whole: usize) -> String {
    if whole == 0 {
        return "—".into();
    }
    let tenths = (part as u128 * 1000 + whole as u128 / 2) / whole as u128;
    if part > 0 && tenths == 0 {
        return "<0,1%".into();
    }
    format!("{},{}%", tenths / 10, tenths % 10)
}

pub fn ratio(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 / whole as f64
    }
}

fn css_width(part: usize, whole: usize) -> String {
    format!("{:.2}%", ratio(part, whole) * 100.0)
}

pub fn code(text: &str) -> String {
    format!("<code>{}</code>", escape(text))
}

/// Caminho de arquivo que só quebra linha depois de `/`.
pub fn path_code(text: &str) -> String {
    format!("<code class=\"path\">{}</code>", escape(text).replace('/', "/<wbr>"))
}

pub fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{} {}", int(count), if count == 1 { one } else { many })
}

/// Identificador para âncoras e nomes de arquivo (`Ke*Irql` -> `ke-irql`).
pub fn anchor(name: &str) -> String {
    let mut output = String::new();
    for character in name.chars() {
        let mapped = match character {
            'á' | 'à' | 'â' | 'ã' | 'Á' | 'Â' | 'Ã' => 'a',
            'é' | 'ê' | 'É' | 'Ê' => 'e',
            'í' | 'Í' => 'i',
            'ó' | 'ô' | 'õ' | 'Ó' | 'Ô' | 'Õ' => 'o',
            'ú' | 'Ú' => 'u',
            'ç' | 'Ç' => 'c',
            other if other.is_ascii_alphanumeric() => other.to_ascii_lowercase(),
            _ => '-',
        };
        if mapped == '-' && (output.is_empty() || output.ends_with('-')) {
            continue;
        }
        output.push(mapped);
    }
    output.trim_end_matches('-').to_string()
}

/// Texto em minúsculas para o atributo `data-text` dos filtros.
pub fn search_text(parts: &[&str]) -> String {
    escape(&parts.join(" ").to_lowercase())
}


// ---- medidores -----------------------------------------------------------------

/// Barra fina de progresso: cada trecho é (valor, classe CSS) sobre um
/// trilho que vale `whole`. Com `label`, a barra tem nome acessível; sem
/// ele, é decorativa, porque os números já estão escritos ao lado.
pub fn meter(segments: &[(usize, &str)], whole: usize, label: Option<&str>) -> String {
    let role = match label {
        Some(label) => format!(" role=\"img\" aria-label=\"{}\"", escape(label)),
        None => " aria-hidden=\"true\"".to_string(),
    };
    let mut bar = format!("<div class=\"meter\"{role}>");
    for (value, class) in segments {
        if *value > 0 {
            let class = if class.is_empty() { String::new() } else { format!(" class=\"{class}\"") };
            bar.push_str(&format!("<span{class} style=\"width:{}\"></span>", css_width(*value, whole)));
        }
    }
    bar.push_str("</div>");
    bar
}

fn stat_inner(label: &str, value: &str, of: &str, bar: &str, note: &str) -> String {
    let of = if of.is_empty() { String::new() } else { format!(" <span class=\"of\">{of}</span>") };
    let note = if note.is_empty() { String::new() } else { format!("<p class=\"stat-note\">{note}</p>") };
    format!("<p class=\"stat-label\">{label}</p><p class=\"stat-value\">{value}{of}</p>{bar}{note}")
}

/// Número de destaque: rótulo, valor (com "de N" opcional), barra e nota.
pub fn stat(label: &str, value: &str, of: &str, bar: &str, note: &str) -> String {
    format!("<div class=\"stat\">{}</div>", stat_inner(label, value, of, bar, note))
}

/// O mesmo número, como link para a página que o detalha.
pub fn stat_link(href: &str, label: &str, value: &str, of: &str, bar: &str, note: &str) -> String {
    format!("<a class=\"stat\" href=\"{href}\">{}</a>", stat_inner(label, value, of, bar, note))
}

// ---- ícones (24x24, traço) --------------------------------------------------------

fn icon_paths(name: &str) -> &'static str {
    match name {
        "cpu" => "<rect x=\"7\" y=\"7\" width=\"10\" height=\"10\" rx=\"2\"/><path d=\"M10 3v3M14 3v3M10 18v3M14 18v3M3 10h3M3 14h3M18 10h3M18 14h3\"/>",
        "memory" => "<rect x=\"3\" y=\"6\" width=\"18\" height=\"10\" rx=\"2\"/><path d=\"M7 10v2M11 10v2M15 10v2M6 16v3M10 16v3M14 16v3M18 16v3\"/>",
        "threads" => "<rect x=\"3\" y=\"4\" width=\"18\" height=\"6\" rx=\"2\"/><rect x=\"3\" y=\"14\" width=\"18\" height=\"6\" rx=\"2\"/><path d=\"M7 7h5M7 17h8\"/>",
        "io" => "<path d=\"M4 8h13M13 4l4 4-4 4M20 16H7M11 12l-4 4 4 4\"/>",
        "sliders" => "<path d=\"M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1\"/><circle cx=\"15\" cy=\"6\" r=\"2\"/><circle cx=\"9\" cy=\"12\" r=\"2\"/><circle cx=\"17\" cy=\"18\" r=\"2\"/>",
        "book" => "<path d=\"M5 4.5A1.5 1.5 0 0 1 6.5 3H19v15H6.5A1.5 1.5 0 0 0 5 19.5z\"/><path d=\"M5 19.5A1.5 1.5 0 0 0 6.5 21H19M9 7h6\"/>",
        "shield" => "<path d=\"M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z\"/><path d=\"M9 12l2 2 4-4\"/>",
        "database" => "<ellipse cx=\"12\" cy=\"6\" rx=\"7\" ry=\"3\"/><path d=\"M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3\"/>",
        "power" => "<path d=\"M12 3v8\"/><path d=\"M7.5 6.5a7 7 0 1 0 9 0\"/>",
        "folder" => "<path d=\"M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z\"/>",
        "chip" => "<rect x=\"4\" y=\"4\" width=\"16\" height=\"16\" rx=\"3\"/><rect x=\"9\" y=\"9\" width=\"6\" height=\"6\" rx=\"1\"/>",
        "terminal" => "<rect x=\"3\" y=\"4\" width=\"18\" height=\"16\" rx=\"2\"/><path d=\"M7 9l3 3-3 3M12 15h5\"/>",
        "plug" => "<path d=\"M9 3v5M15 3v5M6 8h12v3a6 6 0 0 1-12 0zM12 17v4\"/>",
        "window" => "<rect x=\"3\" y=\"4\" width=\"18\" height=\"16\" rx=\"2\"/><path d=\"M3 9h18M6.5 6.5h.01M9.5 6.5h.01\"/>",
        "check" => "<circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M8 12.5l2.5 2.5L16 9.5\"/>",
        "message" => "<path d=\"M4 5h16v11H9l-5 4z\"/>",
        "chart" => "<path d=\"M5 20V11M11 20V5M17 20v-7M3 20h18\"/>",
        "rocket" => "<path d=\"M12 3c3 2 5 5.5 5 10l-2 3H9l-2-3c0-4.5 2-8 5-10z\"/><circle cx=\"12\" cy=\"10\" r=\"1.8\"/><path d=\"M9.5 19l-1 2M14.5 19l1 2\"/>",
        "atom" => "<circle cx=\"12\" cy=\"12\" r=\"1.6\"/><ellipse cx=\"12\" cy=\"12\" rx=\"9\" ry=\"3.6\"/><ellipse cx=\"12\" cy=\"12\" rx=\"9\" ry=\"3.6\" transform=\"rotate(60 12 12)\"/><ellipse cx=\"12\" cy=\"12\" rx=\"9\" ry=\"3.6\" transform=\"rotate(120 12 12)\"/>",
        "keyboard" => "<rect x=\"2\" y=\"6\" width=\"20\" height=\"12\" rx=\"2\"/><path d=\"M6 10h.01M10 10h.01M14 10h.01M18 10h.01M8 14h8\"/>",
        "monitor" => "<rect x=\"3\" y=\"4\" width=\"18\" height=\"12\" rx=\"2\"/><path d=\"M8 20h8M12 16v4\"/>",
        "disk" => "<rect x=\"3\" y=\"5\" width=\"18\" height=\"14\" rx=\"2\"/><circle cx=\"12\" cy=\"12\" r=\"3\"/><path d=\"M17 16h.01\"/>",
        "bus" => "<circle cx=\"5\" cy=\"12\" r=\"2\"/><circle cx=\"19\" cy=\"6\" r=\"2\"/><circle cx=\"19\" cy=\"18\" r=\"2\"/><path d=\"M7 12h5l5-5M12 12l5 5\"/>",
        "lock" => "<rect x=\"5\" y=\"11\" width=\"14\" height=\"10\" rx=\"2\"/><path d=\"M8 11V8a4 4 0 0 1 8 0v3\"/>",
        "list" => "<path d=\"M9 6h11M9 12h11M9 18h11M4.5 6h.01M4.5 12h.01M4.5 18h.01\"/>",
        "layers" => "<path d=\"M12 3l9 5-9 5-9-5z\"/><path d=\"M3 13l9 5 9-5\"/>",
        "clock" => "<circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M12 7v5l3 2\"/>",
        "mouse" => "<rect x=\"7\" y=\"3\" width=\"10\" height=\"18\" rx=\"5\"/><path d=\"M12 7v3\"/>",
        "play" => "<circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M10 8.5l5 3.5-5 3.5z\"/>",
        "user" => "<circle cx=\"12\" cy=\"8\" r=\"4\"/><path d=\"M4 21a8 8 0 0 1 16 0\"/>",
        "search" => "<circle cx=\"11\" cy=\"11\" r=\"7\"/><path d=\"M20 20l-4-4\"/>",
        // "cube" e desconhecidos
        _ => "<path d=\"M12 3l8 4.5v9L12 21l-8-4.5v-9z\"/><path d=\"M12 12l8-4.5M12 12L4 7.5M12 12v9\"/>",
    }
}

pub fn icon(name: &str) -> String {
    format!("<svg class=\"ico\" viewBox=\"0 0 24 24\" aria-hidden=\"true\">{}</svg>", icon_paths(name))
}

pub fn icon_tile(name: &str, class: &str) -> String {
    format!("<span class=\"ico-tile {class}\">{}</span>", icon(name))
}

// ---- estados dos componentes ---------------------------------------------------

/// Ícone de estado (formas diferentes, para não depender só da cor).
pub fn state_icon(state: State) -> &'static str {
    match state {
        State::Works => {
            "<svg class=\"ic\" viewBox=\"0 0 16 16\" aria-hidden=\"true\"><circle class=\"f-good\" cx=\"8\" cy=\"8\" r=\"7.5\"/>\
             <path class=\"k-white\" d=\"M4.6 8.3l2.2 2.2 4.6-4.8\"/></svg>"
        }
        State::InDevelopment => {
            "<svg class=\"ic\" viewBox=\"0 0 16 16\" aria-hidden=\"true\"><circle class=\"k-warning\" cx=\"8\" cy=\"8\" r=\"6.6\"/>\
             <path class=\"f-warning\" d=\"M8 1.4a6.6 6.6 0 0 1 0 13.2z\"/></svg>"
        }
        State::Planned => {
            "<svg class=\"ic\" viewBox=\"0 0 16 16\" aria-hidden=\"true\"><circle class=\"k-neutral\" cx=\"8\" cy=\"8\" r=\"6.6\"/></svg>"
        }
        State::OutOfScope => {
            "<svg class=\"ic\" viewBox=\"0 0 16 16\" aria-hidden=\"true\"><circle class=\"k-neutral dash\" cx=\"8\" cy=\"8\" r=\"6.6\"/></svg>"
        }
    }
}

pub fn state_label(state: State) -> &'static str {
    match state {
        State::Works => "Funciona",
        State::InDevelopment => "Parcial",
        State::Planned => "Planejado",
        State::OutOfScope => "Fora do escopo",
    }
}

/// Valor do atributo `data-state` (usado pelo filtro de estado).
pub fn state_key(state: State) -> &'static str {
    match state {
        State::Works => "funciona",
        State::InDevelopment => "parcial",
        State::Planned => "planejado",
        State::OutOfScope => "fora",
    }
}

pub fn state_meaning(state: State) -> &'static str {
    match state {
        State::Works => {
            "o código existe e um teste automático de boot passa por ele. É o único estado que afirma que algo \
             funciona."
        }
        State::InDevelopment => {
            "só uma parte existe, ou o código existe mas nenhum teste automático o exercita ainda. As notas do item \
             dizem o que falta."
        }
        State::Planned => "ainda não implementado; a fase indicada diz em que etapa do roadmap ele entra.",
        State::OutOfScope => "não faz parte do roadmap atual.",
    }
}

/// Classe CSS do selo de estado (a cor de fundo).
fn state_class(state: State) -> &'static str {
    match state {
        State::Works => "ok",
        State::InDevelopment => "part",
        State::Planned => "plan",
        State::OutOfScope => "out",
    }
}

/// Selo de estado: ícone (forma diferente para cada estado, para não
/// depender só da cor) e rótulo, com a explicação no `title`.
pub fn state_badge(state: State) -> String {
    format!(
        "<span class=\"chip {}\" title=\"{}\">{}{}</span>",
        state_class(state),
        escape(state_meaning(state)),
        state_icon(state),
        state_label(state)
    )
}

/// Legenda dos estados de componente: o selo e o que ele quer dizer.
pub fn state_legend() -> String {
    let mut legend = String::from("<div class=\"legend\">");
    for state in super::super::STATES {
        legend.push_str(&format!("<div>{}<p>{}</p></div>", state_badge(*state), state_meaning(*state)));
    }
    legend.push_str("</div>");
    legend
}

pub fn phase_state(state: &str) -> State {
    match state {
        "concluída" | "concluida" => State::Works,
        "em andamento" => State::InDevelopment,
        _ => State::Planned,
    }
}

/// "6" -> "Fase 6 · loader PE e ntoskrnl"; "1 e 4" -> "Fases 1 e 4"; outro texto como está.
pub fn phase_label(phase: &str, phases: &[PhaseRow]) -> String {
    if let Some(row) = phases.iter().find(|row| row.number == phase) {
        return format!("Fase {} · {}", escape(&row.number), escape(&row.name));
    }
    if phase.starts_with(|character: char| character.is_ascii_digit()) {
        return format!("Fases {}", escape(phase));
    }
    let mut label = escape(phase);
    if let Some(first) = label.get(..1) {
        label = format!("{}{}", first.to_uppercase(), &label[1..]);
    }
    label
}

// ---- estados dos módulos -------------------------------------------------------

pub fn module_label(state: ModuleState) -> &'static str {
    match state {
        ModuleState::Done => "Com código",
        ModuleState::Partial => "Parcial",
        ModuleState::Pending => "Pendente",
        ModuleState::OutOfScope => "Fora da conta",
    }
}

pub fn module_key(state: ModuleState) -> &'static str {
    match state {
        ModuleState::Done => "codigo",
        ModuleState::Partial => "parcial",
        ModuleState::Pending => "pendente",
        ModuleState::OutOfScope => "fora",
    }
}

pub fn module_meaning(state: ModuleState) -> &'static str {
    match state {
        ModuleState::Done => "o arquivo Rust do módulo existe no repositório.",
        ModuleState::Partial => "o arquivo existe, mas só uma parte do módulo foi escrita; o motivo aparece ao lado.",
        ModuleState::Pending => "o arquivo ainda não existe.",
        ModuleState::OutOfScope => {
            "módulo descartado (diagnósticos e experimentos, por exemplo); não entra nas contas."
        }
    }
}

/// Marcador de estado do módulo, só com CSS (as tabelas têm centenas de
/// linhas): bolinha azul, meia amarela, anel cinza ou anel tracejado.
pub fn module_tag(state: ModuleState) -> String {
    format!("<span class=\"ms {}\">{}</span>", module_key(state), module_label(state))
}

/// O mesmo marcador, com a explicação no `title` (para a legenda).
pub fn module_badge(state: ModuleState) -> String {
    format!(
        "<span class=\"ms {}\" title=\"{}\">{}</span>",
        module_key(state),
        escape(module_meaning(state)),
        module_label(state)
    )
}

// ---- verificação dos componentes -----------------------------------------------

/// Testes de um componente cujo marcador existe nas fontes.
pub fn live_tests(row: &ComponentRow, report: &Report) -> Vec<usize> {
    row.tests.iter().copied().filter(|&index| report.tests[index].location.is_some()).collect()
}

pub fn test_link(index: usize, report: &Report, prefix: &str) -> String {
    let test = &report.tests[index];
    format!(
        "<a href=\"{prefix}#t-{}\" title=\"{}\">{}</a>",
        anchor(&test.id),
        escape(&test.description),
        escape(&test.title)
    )
}

pub fn component_anchor(row: &ComponentRow) -> String {
    format!("c-{}", anchor(&row.name))
}


// ---- notas longas ----------------------------------------------------------------

/// Notas até este tamanho (em caracteres) aparecem inteiras.
const NOTES_INLINE: usize = 360;

/// (abertura, resto, cortou no meio de uma frase). A abertura é a primeira
/// frase, se ela terminar até `NOTES_INLINE`; senão, o texto até o último
/// espaço antes de 280 caracteres.
fn split_notes(text: &str) -> Option<(&str, &str, bool)> {
    if text.chars().count() <= NOTES_INLINE {
        return None;
    }
    let mut boundary = None;
    for (index, _) in text.match_indices(". ") {
        let before = text[..index].chars().count();
        if before < 40 {
            continue;
        }
        if before > NOTES_INLINE {
            break;
        }
        if text[index + 2..].chars().next().is_some_and(|next| next.is_uppercase() || next.is_ascii_digit()) {
            boundary = Some(index + 1);
            break;
        }
    }
    let (lede, rest, cut) = match boundary {
        Some(end) => (&text[..end], text[end..].trim_start(), false),
        None => {
            let limit = text.char_indices().nth(280).map(|(index, _)| index).unwrap_or(text.len());
            let end = text[..limit].rfind(' ').unwrap_or(limit);
            (&text[..end], text[end..].trim_start(), true)
        }
    };
    if rest.chars().count() < 60 {
        return None;
    }
    Some((lede, rest, cut))
}

/// Notas de um item: as curtas aparecem inteiras; as longas mostram a
/// abertura e guardam o resto num `<details>` (que a busca do navegador
/// também encontra).
pub fn notes(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    match split_notes(text) {
        None => format!("<p class=\"notes\">{}</p>", escape(text)),
        Some((lede, rest, cut)) => format!(
            "<details class=\"notes\"><summary>{}{} <span class=\"toggle\"><span class=\"more\">ler mais</span>\
             <span class=\"less\">mostrar menos</span></span></summary><p>{}</p></details>",
            escape(lede),
            if cut { "<span class=\"ell\">…</span>" } else { "" },
            escape(rest)
        ),
    }
}

// ---- moldura da página -----------------------------------------------------------

const LOGO: &str = "<svg viewBox=\"0 0 16 16\" aria-hidden=\"true\"><rect x=\"2\" y=\"2\" width=\"5\" height=\"5\" rx=\"1\" fill=\"#fff\"/>\
<rect x=\"9\" y=\"2\" width=\"5\" height=\"5\" rx=\"1\" fill=\"#fff\" opacity=\".75\"/><rect x=\"2\" y=\"9\" width=\"5\" height=\"5\" rx=\"1\" \
fill=\"#fff\" opacity=\".75\"/><rect x=\"9\" y=\"9\" width=\"5\" height=\"5\" rx=\"1\" fill=\"#fff\" opacity=\".5\"/></svg>";

/// As páginas principais, na ordem do menu: (arquivo, rótulo curto,
/// complemento que só aparece em telas largas).
pub const NAV: &[(&str, &str, &str)] = &[
    ("index.html", "Visão geral", ""),
    ("componentes.html", "Componentes", " e drivers"),
    ("testes.html", "Testes", ""),
    ("ntoskrnl.html", "Exports", " do ntoskrnl"),
    ("modulos.html", "Módulos", " do kernel"),
];

/// Nome completo de uma página do menu ("Componentes e drivers").
pub fn page_name(file: &str) -> String {
    NAV.iter()
        .find(|(target, _, _)| *target == file)
        .map(|(_, short, long)| format!("{short}{long}"))
        .unwrap_or_default()
}

pub const CHEVRON: &str =
    "<svg class=\"chev\" viewBox=\"0 0 16 16\" aria-hidden=\"true\"><path d=\"M6 3.5L10.5 8 6 12.5\"/></svg>";

/// Moldura comum: `current` é a página do menu marcada como atual.
pub fn html_page(current: &str, title: &str, description: &str, body: &str, scripts: &[&str]) -> String {
    let nav: String = NAV
        .iter()
        .map(|(target, short, long)| {
            let mark = if *target == current { " aria-current=\"page\"" } else { "" };
            let long = if long.is_empty() { String::new() } else { format!("<span class=\"long\">{long}</span>") };
            format!("<li><a href=\"{target}\"{mark}>{short}{long}</a></li>")
        })
        .collect();
    let footer_nav: String = NAV
        .iter()
        .map(|(target, short, long)| format!("<li><a href=\"{target}\">{short}{long}</a></li>"))
        .collect();
    let scripts: String = scripts.iter().map(|script| format!("<script>{script}</script>\n")).collect();
    format!(
        "<!doctype html>\n<html lang=\"pt-BR\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n\
         <meta name=\"color-scheme\" content=\"light dark\">\n\
         <title>{title}</title>\n<meta name=\"description\" content=\"{description}\">\n\
         <script>document.documentElement.classList.add('js')</script>\n<style>{CSS}</style>\n</head>\n<body>\n\
         <a class=\"skip\" href=\"#conteudo\">Pular para o conteúdo</a>\n\
         <header class=\"site\"><div class=\"wrap bar\"><a class=\"brand\" href=\"index.html\"><span class=\"logo\">{LOGO}</span>\
         OpenNT<span class=\"tag\">status</span></a><nav class=\"nav\" aria-label=\"Páginas do site\"><ul>{nav}</ul></nav>\
         </div></header>\n<main id=\"conteudo\" class=\"wrap\" tabindex=\"-1\">\n{body}\n</main>\n\
         <footer class=\"site\"><div class=\"wrap\"><nav aria-label=\"Páginas do site (rodapé)\"><ul>{footer_nav}</ul></nav>\
         <p>Gerado por <code>cargo xtask status</code> a partir do código do repositório, de \
         <code>docs/status/components.toml</code> e da lista de exports do <code>ntoskrnl.exe</code>. Não edite estas \
         páginas à mão: edite os dados e gere de novo.</p></div></footer>\n\
         {scripts}</body>\n</html>\n",
        title = escape(title),
        description = escape(description),
    )
}

/// A trilha (Visão geral / ... / página atual) e o cabeçalho da página:
/// título, frase de abertura, explicação (HTML pronto, em geral um
/// `<p class="sub">`) e números de destaque. `trail` são os níveis
/// intermediários (link, rótulo); sem `current`, não há trilha.
pub fn page_head(trail: &[(&str, &str)], current: &str, title: &str, lead: &str, sub: &str, stats: &str) -> String {
    let mut head = String::new();
    if !current.is_empty() {
        let mut items = String::from("<li><a href=\"index.html\">Visão geral</a></li>");
        for (href, label) in trail {
            items.push_str(&format!("<li><a href=\"{href}\">{label}</a></li>"));
        }
        items.push_str(&format!("<li><span aria-current=\"page\">{current}</span></li>"));
        head.push_str(&format!("<nav class=\"crumbs\" aria-label=\"Você está em\"><ol>{items}</ol></nav>"));
    }
    let stats = if stats.is_empty() { String::new() } else { format!("<div class=\"stats\">{stats}</div>") };
    head.push_str(&format!("<header class=\"page-head\"><h1>{title}</h1><p class=\"lead\">{lead}</p>{sub}{stats}</header>"));
    head
}

/// Uma seção da página com título `<h2>` e, se houver, um parágrafo de abertura.
pub fn section(id: &str, title: &str, intro: &str, body: &str) -> String {
    let intro = if intro.is_empty() { String::new() } else { format!("<p class=\"intro\">{intro}</p>") };
    format!("<section class=\"block\" id=\"{id}\" aria-labelledby=\"{id}-t\"><h2 id=\"{id}-t\">{title}</h2>{intro}{body}</section>")
}

/// Um botão do filtro de estado: (valor de `data-state`, rótulo, quantos
/// itens têm esse estado, ícone).
pub type Toggle<'a> = (&'a str, &'a str, usize, &'a str);

/// Barra de busca e filtro (só aparece com JavaScript) para os
/// `[data-item]` dentro de `#target`. `unit` é (singular, plural).
pub fn filter_bar(target: &str, label: &str, placeholder: &str, toggles: &[Toggle], total: usize, unit: (&str, &str)) -> String {
    let mut buttons = format!("<button type=\"button\" data-value=\"\" aria-pressed=\"true\">Todos <span class=\"n\">{}</span></button>", int(total));
    for (value, text, count, icon) in toggles {
        buttons.push_str(&format!(
            "<button type=\"button\" data-value=\"{value}\" aria-pressed=\"false\">{icon}{} <span class=\"n\">{}</span></button>",
            escape(text),
            int(*count)
        ));
    }
    format!(
        "<div class=\"filters js-only\" role=\"search\" aria-label=\"{label}\" data-filter=\"{target}\"><div class=\"search\">{}\
         <label class=\"sr-only\" for=\"filtro\">Buscar</label><input id=\"filtro\" type=\"search\" placeholder=\"{}\" \
         autocomplete=\"off\" spellcheck=\"false\"></div><div class=\"toggles\" role=\"group\" aria-label=\"Mostrar\">{buttons}</div>\
         <p class=\"count\" aria-live=\"polite\" data-one=\"{one}\" data-many=\"{many}\">{}</p></div>\
         <p id=\"vazio\" class=\"empty\" hidden>Nada corresponde ao filtro. <button type=\"button\" class=\"linkish\" \
         data-clear>Limpar o filtro</button></p>",
        icon("search"),
        escape(placeholder),
        plural(total, unit.0, unit.1),
        label = escape(label),
        one = escape(unit.0),
        many = escape(unit.1),
    )
}
