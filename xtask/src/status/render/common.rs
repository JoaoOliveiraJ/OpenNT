//! Peças comuns das páginas: formatação, ícones, estados, CSS, a moldura da
//! página e o script de paginação.

use super::super::{ComponentRow, ModuleState, PhaseRow, Report, State};

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

/// Barra de progresso; `partial` desenha um segundo trecho amarelo.
pub fn meter(done: usize, partial: usize, whole: usize, label: &str) -> String {
    let mut bar = format!("<div class=\"meter\" role=\"img\" aria-label=\"{}\">", escape(label));
    if done > 0 {
        bar.push_str(&format!("<span style=\"width:{}\"></span>", css_width(done, whole)));
    }
    if partial > 0 {
        bar.push_str(&format!("<span class=\"partial\" style=\"width:{}\"></span>", css_width(partial, whole)));
    }
    bar.push_str("</div>");
    bar
}

/// Anel de progresso animado (o comprimento do traço vai de 0 ao valor).
pub fn ring(part: usize, whole: usize) -> String {
    let value = ratio(part, whole) * 100.0;
    let shown = if part > 0 { value.max(0.6) } else { 0.0 };
    format!(
        "<svg class=\"ring\" viewBox=\"0 0 100 100\" role=\"img\" aria-label=\"{pct}\"><circle class=\"ring-track\" \
         cx=\"50\" cy=\"50\" r=\"42\"/><circle class=\"ring-bar\" cx=\"50\" cy=\"50\" r=\"42\" pathLength=\"100\" \
         transform=\"rotate(-90 50 50)\" style=\"stroke-dashoffset:{offset:.2}\"/><text x=\"50\" y=\"56\" \
         text-anchor=\"middle\">{pct}</text></svg>",
        pct = escape(&percent(part, whole)),
        offset = 100.0 - shown
    )
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

pub fn state_badge(state: State) -> String {
    format!(
        "<span class=\"state\" title=\"{}\">{}{}</span>",
        escape(state_meaning(state)),
        state_icon(state),
        state_label(state)
    )
}

/// Legenda dos estados de componente, em lista de definição.
pub fn state_legend() -> String {
    let mut legend = String::from("<div class=\"legend\">");
    for state in super::super::STATES {
        legend.push_str(&format!("<div>{}<span>{}</span></div>", state_badge(*state), state_meaning(*state)));
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

// ---- moldura da página -----------------------------------------------------------

pub const CSS: &str = r#"
:root{color-scheme:light;--page:#f5f6fa;--surface:#ffffff;--raised:#ffffff;--ink:#0b0b10;--ink2:#474852;--muted:#62636d;
--grid:#e4e5ec;--border:rgba(20,22,40,.09);--accent:#2a78d6;--accent2:#6250d6;--accent-ink:#1c5cab;--accent-soft:#eaf2fc;
--track:#e6e7ee;--good:#0ca30c;--good-ink:#006300;--warning:#fab219;--neutral:#a3a3ad;--code:#eef0f5;--warn-ink:#c22f2f;
--hero:linear-gradient(135deg,#1c5cab 0%,#2a78d6 46%,#6250d6 100%);
--shadow:0 1px 2px rgba(16,24,40,.05),0 1px 3px rgba(16,24,40,.06);--shadow-hover:0 16px 36px -16px rgba(28,92,171,.5)}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--page:#0b0c10;--surface:#14151b;
--raised:#181a21;--ink:#f0f0f3;--ink2:#c5c6cf;--muted:#9a9ba6;--grid:#262832;--border:rgba(255,255,255,.08);--accent:#3987e5;
--accent2:#9085e9;--accent-ink:#86b6ef;--accent-soft:#16233a;--track:#272a35;--good-ink:#3ccf3c;--neutral:#6b6c78;
--code:#20222b;--warn-ink:#ff8a8a;--hero:linear-gradient(135deg,#0f2f5c 0%,#1a4f96 48%,#40349a 100%);--shadow:none;
--shadow-hover:0 16px 36px -16px rgba(0,0,0,.85)}}
:root[data-theme="dark"]{color-scheme:dark;--page:#0b0c10;--surface:#14151b;--raised:#181a21;--ink:#f0f0f3;--ink2:#c5c6cf;
--muted:#9a9ba6;--grid:#262832;--border:rgba(255,255,255,.08);--accent:#3987e5;--accent2:#9085e9;--accent-ink:#86b6ef;
--accent-soft:#16233a;--track:#272a35;--good-ink:#3ccf3c;--neutral:#6b6c78;--code:#20222b;--warn-ink:#ff8a8a;
--hero:linear-gradient(135deg,#0f2f5c 0%,#1a4f96 48%,#40349a 100%);--shadow:none;--shadow-hover:0 16px 36px -16px rgba(0,0,0,.85)}
*{box-sizing:border-box}
[hidden]{display:none!important}
html{-webkit-text-size-adjust:100%}
html:not(.js) .js-only{display:none!important}
html.js .no-js{display:none!important}
[id]{scroll-margin-top:84px}
body{margin:0;background:var(--page);color:var(--ink);font:16px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent-ink);text-underline-offset:2px}
.wrap{max-width:1120px;margin:0 auto;padding:0 16px}
header.top{position:sticky;top:0;z-index:10;background:color-mix(in srgb,var(--surface) 88%,transparent);
backdrop-filter:saturate(1.4) blur(10px);-webkit-backdrop-filter:saturate(1.4) blur(10px);border-bottom:1px solid var(--grid)}
header.top .wrap{display:flex;flex-wrap:wrap;align-items:center;gap:6px 28px;padding-top:10px;padding-bottom:10px}
.brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:18px;color:var(--ink);text-decoration:none;letter-spacing:-.01em}
.brand small{font-weight:500;font-size:14px;color:var(--muted)}
.logo{width:28px;height:28px;border-radius:8px;background:var(--hero);display:grid;place-items:center;box-shadow:0 4px 12px -4px rgba(42,120,214,.6)}
.logo svg{width:16px;height:16px}
nav.main{display:flex;flex-wrap:wrap;gap:4px 6px}
nav.main a{color:var(--ink2);text-decoration:none;padding:6px 12px;border-radius:999px;font-size:15px;transition:background .15s}
nav.main a:hover{background:var(--accent-soft)}
nav.main a[aria-current]{background:var(--accent-soft);color:var(--accent-ink);font-weight:650}
main{padding-bottom:56px}
.hero{position:relative;overflow:hidden;isolation:isolate;margin:22px 0 8px;padding:36px 32px 30px;border-radius:26px;
background:var(--hero);color:#fff;box-shadow:0 24px 60px -30px rgba(42,80,200,.7)}
.hero::before{content:"";position:absolute;inset:0;z-index:-1;background-image:radial-gradient(rgba(255,255,255,.18) 1px,transparent 1.4px);
background-size:20px 20px;-webkit-mask-image:linear-gradient(115deg,#000 5%,transparent 70%);mask-image:linear-gradient(115deg,#000 5%,transparent 70%)}
.hero::after{content:"";position:absolute;z-index:-1;width:520px;height:520px;right:-160px;top:-220px;border-radius:50%;
background:radial-gradient(circle,rgba(255,255,255,.26),transparent 64%)}
.hero .eyebrow{color:rgba(255,255,255,.82)}
.hero h1{font-size:clamp(34px,6vw,58px);font-weight:800;letter-spacing:-.03em;line-height:1.04;margin:6px 0 12px}
.hero .tagline{font-size:clamp(18px,2.5vw,22px);font-weight:550;max-width:44ch;margin:0 0 10px;line-height:1.35}
.hero .sub{color:rgba(255,255,255,.88);max-width:70ch;margin:0}
.hero code{background:rgba(255,255,255,.16);color:#fff}
.hero a{color:#fff}
.hero-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(230px,100%),1fr));gap:14px;margin-top:26px}
.glass{background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.24);border-radius:18px;padding:16px 18px;
backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);display:flex;align-items:center;gap:16px;min-width:0}
.glass .label{font-size:14px;font-weight:650;color:#fff;line-height:1.35}
.glass .big{font-size:clamp(28px,4vw,36px);font-weight:800;line-height:1.05;letter-spacing:-.02em;margin:2px 0}
.glass .sub2{font-size:13px;color:rgba(255,255,255,.84);line-height:1.4}
.ring{width:88px;height:88px;flex:none}
.ring circle{fill:none;stroke-width:10}
.ring-track{stroke:rgba(255,255,255,.24)}
.ring-bar{stroke:#fff;stroke-linecap:round;stroke-dasharray:100;animation:ring 1.6s cubic-bezier(.2,.8,.2,1) both}
.ring text{fill:#fff;font:800 19px system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;letter-spacing:-.02em}
@keyframes ring{from{stroke-dashoffset:100}}
.pagehead{margin:26px 0 8px}
.pagehead h1{font-size:clamp(30px,5vw,44px);line-height:1.1;letter-spacing:-.02em;margin:4px 0 10px}
.crumbs{font-size:14px;color:var(--muted);margin:0 0 4px}
.crumbs a{color:var(--muted)}
.eyebrow{text-transform:uppercase;letter-spacing:.09em;font-size:12px;font-weight:750;color:var(--accent-ink);margin:0 0 4px}
section.block{margin-top:48px}
h2{font-size:clamp(23px,3vw,28px);line-height:1.2;margin:0 0 10px;letter-spacing:-.015em}
h3{font-size:18px;margin:24px 0 8px}
p{margin:0 0 12px;max-width:76ch}
.lead{font-size:17px;color:var(--ink2);max-width:76ch}
.muted{color:var(--muted)}
.small{font-size:14px}
code{font:.86em ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;background:var(--code);padding:1px 5px;border-radius:5px;overflow-wrap:anywhere}
pre{background:var(--code);padding:12px 14px;border-radius:12px;overflow-x:auto;margin:0 0 12px}
pre code{background:none;padding:0}
.card{background:var(--raised);border:1px solid var(--border);border-radius:18px;padding:18px;box-shadow:var(--shadow);min-width:0}
.lift{transition:transform .2s ease,box-shadow .2s ease,border-color .2s ease}
.lift:hover{transform:translateY(-3px);box-shadow:var(--shadow-hover);border-color:color-mix(in srgb,var(--accent) 45%,var(--border))}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(320px,100%),1fr));gap:14px;margin:16px 0}
.grid.tight{grid-template-columns:repeat(auto-fit,minmax(min(260px,100%),1fr))}
.grid.three{grid-template-columns:repeat(auto-fit,minmax(min(280px,100%),1fr))}
.ico{width:22px;height:22px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.ico-tile{width:44px;height:44px;border-radius:13px;flex:none;display:grid;place-items:center;color:var(--accent-ink);
background:linear-gradient(135deg,color-mix(in srgb,var(--accent) 17%,transparent),color-mix(in srgb,var(--accent2) 19%,transparent))}
.ico-tile.good{color:var(--good-ink);background:linear-gradient(135deg,color-mix(in srgb,var(--good) 16%,transparent),color-mix(in srgb,var(--accent) 12%,transparent))}
.ico-tile.dim{color:var(--muted);background:var(--track)}
.ico-tile.sm{width:34px;height:34px;border-radius:10px}
.ico-tile.sm .ico{width:18px;height:18px}
.meter{height:10px;border-radius:5px;background:var(--track);overflow:hidden;display:flex;gap:2px;margin:8px 0 4px}
.meter span{display:block;height:100%;min-width:4px;border-radius:5px;background:linear-gradient(90deg,var(--accent),var(--accent2));
transform-origin:left center;animation:grow 1.3s cubic-bezier(.2,.8,.2,1) both}
.meter span.partial{background:var(--warning)}
@keyframes grow{from{transform:scaleX(0)}}
.explain{background:linear-gradient(135deg,var(--accent-soft),color-mix(in srgb,var(--accent2) 9%,var(--accent-soft)));border-radius:18px;padding:20px 22px}
.explain h3{margin-top:0}
.explain p:last-child,.explain ul:last-child{margin-bottom:0}
.glossary{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(300px,100%),1fr));gap:14px;margin:16px 0}
.glossary div{background:var(--raised);border:1px solid var(--border);border-radius:16px;padding:14px 16px}
.glossary dt{font-weight:750;display:flex;gap:8px;align-items:center}
.glossary dd{margin:4px 0 0;font-size:15px;color:var(--ink2)}
.steps{margin:8px 0 12px;padding-left:22px}
.steps li{margin:4px 0}
.highlight{display:flex;gap:14px;align-items:flex-start}
.highlight h3{margin:0 0 4px;font-size:16px;line-height:1.3}
.highlight h3 a{color:inherit;text-decoration:none}
.highlight h3 a:hover{text-decoration:underline}
.highlight p{margin:0;font-size:14px;color:var(--ink2)}
.highlight .by{font-size:13px;color:var(--muted);margin-top:6px}
.timeline{list-style:none;margin:22px 0 8px;padding:0;display:grid;grid-template-columns:repeat(7,minmax(0,1fr))}
.timeline li{position:relative;text-align:center;padding:0 6px}
.timeline li:not(:first-child)::before{content:"";position:absolute;top:19px;right:50%;width:100%;height:4px;border-radius:2px;background:var(--track)}
.timeline li.reached:not(:first-child)::before{background:linear-gradient(90deg,var(--good),var(--accent))}
.node{position:relative;z-index:1;width:42px;height:42px;margin:0 auto 10px;border-radius:50%;display:grid;place-items:center;
font-weight:800;background:var(--raised);border:3px solid var(--track);color:var(--muted)}
.node svg{width:20px;height:20px;fill:none;stroke:#fff;stroke-width:2.6;stroke-linecap:round;stroke-linejoin:round}
.node.done{background:var(--good);border-color:var(--good)}
.node.current{border-color:var(--warning);color:var(--ink)}
.node.current::after{content:"";position:absolute;inset:-9px;border-radius:50%;border:3px solid var(--warning);animation:pulse 2.2s ease-out infinite}
@keyframes pulse{from{transform:scale(.75);opacity:.7}to{transform:scale(1.3);opacity:0}}
.timeline .num{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.07em}
.timeline .name{font-weight:700;font-size:15px;line-height:1.3;margin:2px 0 6px}
@media (max-width:860px){.timeline{grid-template-columns:1fr}
.timeline li{display:grid;grid-template-columns:42px 1fr;column-gap:14px;text-align:left;padding:0 0 18px}
.timeline li .node{margin:0;grid-row:span 3}
.timeline li:not(:first-child)::before{display:none}
.timeline li:not(:last-child)::after{content:"";position:absolute;left:19px;top:42px;bottom:0;width:4px;border-radius:2px;background:var(--track)}
.timeline li.link:not(:last-child)::after{background:linear-gradient(180deg,var(--good),var(--accent))}}
.prefixes{display:grid;gap:10px;margin:14px 0}
.prefix{display:grid;grid-template-columns:auto minmax(0,1fr) 250px;gap:6px 16px;align-items:start}
.prefix .pill{font-weight:800;font-size:16px}
.prefix .examples{font-size:13px;color:var(--muted);margin-top:4px}
.prefix .examples code{font-size:12px}
.prefix .nums{font-size:14px;color:var(--ink2);font-variant-numeric:tabular-nums}
.prefix .nums strong{color:var(--ink);font-size:16px}
@media (max-width:760px){.prefix{grid-template-columns:auto minmax(0,1fr)}.prefix .nums{grid-column:1 / -1}}
.chart{background:var(--surface);border:1px solid var(--border);border-radius:18px;padding:8px;overflow-x:auto}
.chart svg{display:block;width:100%;height:auto;min-width:680px}
figure{margin:18px 0}
figcaption{font-size:14px;color:var(--muted);margin-top:10px}
.controls{display:flex;flex-wrap:wrap;gap:10px 14px;align-items:center;margin:14px 0;padding:12px 14px;background:var(--surface);
border:1px solid var(--border);border-radius:14px}
.controls label{display:flex;gap:8px;align-items:center;font-size:15px}
.controls input,.controls select{font:inherit;color:var(--ink);background:var(--raised);border:1px solid var(--grid);border-radius:10px;padding:7px 11px}
.controls input{width:min(300px,100%)}
.controls .count{margin-left:auto}
details{background:var(--raised);border:1px solid var(--border);border-radius:14px;margin:10px 0}
details>summary{cursor:pointer;padding:12px 16px;font-weight:650}
details>summary .muted{font-weight:400}
details .inner{padding:0 16px 14px}
.card details{border:0;background:none;margin:10px 0 0}
.card details>summary{padding:2px 0;font-size:14px;color:var(--ink2)}
.card details .inner{padding:4px 0 0}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%}
th,td{padding:8px 10px;border-bottom:1px solid var(--grid);text-align:left;vertical-align:top}
th{font-size:13px;font-weight:650;color:var(--ink2)}
tbody tr:last-child td{border-bottom:0}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.table-card{background:var(--raised);border:1px solid var(--border);border-radius:16px;padding:6px 10px;margin:14px 0}
.yes{color:var(--good-ink);font-weight:650}
.no{color:var(--muted)}
.ic{width:16px;height:16px;flex:none;display:block}
.f-good{fill:var(--good)}.f-warning{fill:var(--warning)}.f-accent{fill:var(--accent)}
.k-white{fill:none;stroke:#fff;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round}
.k-warning{fill:none;stroke:var(--warning);stroke-width:1.6}
.k-neutral{fill:none;stroke:var(--neutral);stroke-width:1.6}
.dash{stroke-dasharray:2.2 2.2}
.state{display:inline-flex;align-items:center;gap:6px;font-size:13px;font-weight:650;white-space:nowrap;
padding:3px 10px 3px 6px;border-radius:999px;background:var(--surface);border:1px solid var(--border)}
.small-state{font-size:12px;padding:2px 8px 2px 5px}
.ms{display:inline-flex;align-items:center;gap:6px;font-size:13px;font-weight:650;white-space:nowrap}
.ms::before{content:"";width:12px;height:12px;border-radius:50%;flex:none;box-sizing:border-box}
.ms.codigo::before{background:var(--accent)}
.ms.parcial::before{border:1.6px solid var(--warning);background:linear-gradient(90deg,transparent 50%,var(--warning) 50%)}
.ms.pendente::before{border:1.6px solid var(--neutral)}
.ms.fora::before{border:1.6px dashed var(--neutral)}
.small-state .ic{width:13px;height:13px}
.legend{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(300px,100%),1fr));gap:10px 18px;margin:12px 0}
.legend div{display:flex;gap:10px;align-items:baseline;font-size:14px;color:var(--ink2)}
.legend .state{flex:none}
.category-head{display:flex;gap:14px;align-items:flex-start}
.category-head h2{margin-bottom:4px}
.category-head .counts{font-size:14px;color:var(--muted);margin:0}
.component{display:flex;flex-direction:column;gap:10px}
.component .head{display:flex;gap:12px;align-items:flex-start}
.component .head .title{flex:1;min-width:0}
.component h3{margin:2px 0 4px;font-size:17px;line-height:1.3}
.component p{margin:0;font-size:15px}
.facts{display:grid;grid-template-columns:auto 1fr;gap:5px 12px;margin:0;font-size:14px}
.facts dt{color:var(--muted)}
.facts dd{margin:0;min-width:0}
.facts dd code{display:inline-block;margin:0 4px 3px 0}
.path{overflow-wrap:normal}
.verified{color:var(--good-ink);font-weight:650}
.unverified{color:var(--muted)}
.note{font-size:13px;color:var(--muted)}
.covers{margin:0;padding-left:20px;font-size:14px}
details.subsys{margin:8px 0}
details.subsys>summary{list-style:none;display:grid;grid-template-columns:34px minmax(0,1fr) minmax(90px,200px) 8.5em 14px;
gap:6px 14px;align-items:center;padding:10px 14px}
details.subsys>summary::-webkit-details-marker{display:none}
details.subsys .sname{font-weight:700;line-height:1.3}
details.subsys .sname code{font-weight:400;font-size:12px;margin-left:6px}
details.subsys .sdesc{font-weight:400;font-size:13px;color:var(--muted);line-height:1.35}
details.subsys .snums{font-weight:400;font-size:14px;color:var(--ink2);text-align:right;font-variant-numeric:tabular-nums}
details.subsys .meter{margin:0}
details.subsys .meter span{animation:none}
.chev{width:14px;height:14px;fill:none;stroke:var(--muted);stroke-width:2.2;transition:transform .15s}
details[open]>summary .chev{transform:rotate(90deg)}
@media (max-width:700px){details.subsys>summary{grid-template-columns:34px minmax(0,1fr) 14px}
details.subsys>summary .meter,details.subsys>summary .snums{grid-column:2 / 3}
details.subsys>summary .snums{text-align:left}details.subsys>summary .chev{grid-row:1;grid-column:3}}
.area{margin-top:28px}
.area>h3{display:flex;gap:10px;align-items:baseline}
.area>h3 .muted{font-size:14px;font-weight:400}
.links a.card{text-decoration:none;color:var(--ink);display:flex;gap:14px;align-items:flex-start}
.links h3{margin:0 0 4px}
.links p{margin:0}
.badges{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0 0}
.badges svg{display:block}
.warn{color:var(--warn-ink);font-size:13px}
.pager{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:10px 0 4px}
.pager button{font:inherit;font-size:14px;min-width:38px;padding:5px 11px;border-radius:10px;border:1px solid var(--grid);
background:var(--raised);color:var(--ink);cursor:pointer}
.pager button:hover:not(:disabled){border-color:var(--accent)}
.pager button[aria-current]{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:700}
.pager button:disabled{opacity:.45;cursor:default}
.pager .gap{color:var(--muted);padding:0 2px}
.pager .range{font-size:13px;color:var(--muted);margin-left:6px}
.empty{padding:14px 16px;border:1px dashed var(--grid);border-radius:14px;color:var(--muted)}
.groupnav{display:flex;flex-wrap:wrap;justify-content:space-between;gap:10px;margin:18px 0}
.groupnav a{text-decoration:none;padding:8px 14px;border:1px solid var(--border);border-radius:12px;background:var(--raised)}
.results{list-style:none;margin:8px 0 0;padding:0;display:grid;gap:6px}
.results li{display:flex;flex-wrap:wrap;gap:4px 12px;align-items:baseline;padding:8px 12px;background:var(--raised);
border:1px solid var(--border);border-radius:12px;font-size:14px}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}
.chips a{font-size:13px;text-decoration:none;padding:3px 10px;border-radius:999px;background:var(--accent-soft)}
.chips a[aria-current]{background:var(--accent);color:#fff;font-weight:700}
footer{border-top:1px solid var(--grid);background:var(--surface)}
footer .wrap{padding-top:16px;padding-bottom:28px;color:var(--muted);font-size:14px}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}.lift:hover{transform:none}}
"#;

const LOGO: &str = "<svg viewBox=\"0 0 16 16\" aria-hidden=\"true\"><rect x=\"2\" y=\"2\" width=\"5\" height=\"5\" rx=\"1\" fill=\"#fff\"/>\
<rect x=\"9\" y=\"2\" width=\"5\" height=\"5\" rx=\"1\" fill=\"#fff\" opacity=\".75\"/><rect x=\"2\" y=\"9\" width=\"5\" height=\"5\" rx=\"1\" \
fill=\"#fff\" opacity=\".75\"/><rect x=\"9\" y=\"9\" width=\"5\" height=\"5\" rx=\"1\" fill=\"#fff\" opacity=\".5\"/></svg>";

/// As páginas principais, na ordem do menu.
pub const NAV: &[(&str, &str)] = &[
    ("index.html", "Visão geral"),
    ("componentes.html", "Componentes e drivers"),
    ("testes.html", "Testes"),
    ("modulos.html", "Módulos do kernel"),
    ("ntoskrnl.html", "Exports do ntoskrnl"),
];

pub const CHEVRON: &str =
    "<svg class=\"chev\" viewBox=\"0 0 16 16\" aria-hidden=\"true\"><path d=\"M6 3.5L10.5 8 6 12.5\"/></svg>";

/// Moldura comum: `current` é a página do menu marcada como atual.
pub fn html_page(current: &str, title: &str, description: &str, body: &str, scripts: &[&str]) -> String {
    let nav: String = NAV
        .iter()
        .map(|(target, label)| {
            let mark = if *target == current { " aria-current=\"page\"" } else { "" };
            format!("<a href=\"{target}\"{mark}>{label}</a>")
        })
        .collect();
    let scripts: String = scripts.iter().map(|script| format!("<script>{script}</script>\n")).collect();
    format!(
        "<!doctype html>\n<html lang=\"pt-BR\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n\
         <title>{title}</title>\n<meta name=\"description\" content=\"{description}\">\n\
         <script>document.documentElement.classList.add('js')</script>\n<style>{CSS}</style>\n</head>\n<body>\n\
         <header class=\"top\"><div class=\"wrap\"><a class=\"brand\" href=\"index.html\"><span class=\"logo\">{LOGO}</span>\
         OpenNT <small>status</small></a><nav class=\"main\" aria-label=\"Páginas\">{nav}</nav></div></header>\n\
         <main class=\"wrap\">\n{body}\n</main>\n<footer><div class=\"wrap\">Gerado por <code>cargo xtask status</code> a \
         partir do código do repositório, de <code>docs/status/components.toml</code> e da lista de exports do \
         <code>ntoskrnl.exe</code>. Não edite estas páginas à mão: edite os dados e gere de novo.</div></footer>\n\
         {scripts}</body>\n</html>\n",
        title = escape(title),
        description = escape(description),
    )
}

pub fn hero(eyebrow: &str, title: &str, tagline: &str, sub: &str, stats: &str) -> String {
    format!(
        "<section class=\"hero\"><p class=\"eyebrow\">{eyebrow}</p><h1>{title}</h1><p class=\"tagline\">{tagline}</p>\
         <p class=\"sub\">{sub}</p><div class=\"hero-stats\">{stats}</div></section>"
    )
}

pub fn ring_stat(part: usize, whole: usize, label: &str, sub: &str) -> String {
    format!(
        "<div class=\"glass\">{}<div><div class=\"label\">{label}</div><div class=\"sub2\">{sub}</div></div></div>",
        ring(part, whole)
    )
}

pub fn big_stat(value: &str, label: &str, sub: &str) -> String {
    format!(
        "<div class=\"glass\"><div><div class=\"label\">{label}</div><div class=\"big\">{value}</div>\
         <div class=\"sub2\">{sub}</div></div></div>"
    )
}

pub fn section(id: &str, eyebrow: &str, title: &str, intro: &str, body: &str) -> String {
    let intro = if intro.is_empty() { String::new() } else { format!("<p class=\"lead\">{intro}</p>") };
    let id = if id.is_empty() { String::new() } else { format!(" id=\"{id}\"") };
    format!("<section class=\"block\"{id}><p class=\"eyebrow\">{eyebrow}</p><h2>{title}</h2>{intro}{body}</section>")
}

/// Barra de filtros (só aparece com JavaScript). `states` são pares
/// (valor de `data-state`, rótulo); `unit` é (singular, plural).
pub fn filter_bar(placeholder: &str, states: &[(&str, &str)], total: usize, unit: (&str, &str)) -> String {
    let mut options = String::from("<option value=\"\">todos</option>");
    for (value, label) in states {
        options.push_str(&format!("<option value=\"{value}\">{}</option>", escape(label)));
    }
    format!(
        "<div class=\"controls js-only\" role=\"search\"><label>Buscar <input id=\"filtro\" type=\"search\" \
         placeholder=\"{}\" autocomplete=\"off\"></label><label>Mostrar <select id=\"estado\">{options}</select></label>\
         <span id=\"contagem\" class=\"count muted small\" data-one=\"{one}\" data-many=\"{many}\" aria-live=\"polite\">\
         {}</span></div><p id=\"vazio\" class=\"empty\" hidden>Nada corresponde ao filtro.</p>",
        escape(placeholder),
        plural(total, unit.0, unit.1),
        one = escape(unit.0),
        many = escape(unit.1),
    )
}

/// Paginação e filtros, em JavaScript puro e sem dependências.
///
/// - `[data-paginate=N]` marca uma lista; os itens são os `[data-item]`
///   dentro dela. Sem JavaScript, todos os itens aparecem.
/// - `#filtro` (texto) e `#estado` (compara com `data-state`) filtram todas
///   as listas da página; `#contagem` mostra quantos itens sobraram.
/// - `[data-section]` some quando a sua lista fica vazia pelo filtro, e um
///   `[data-group]` some quando todas as suas seções sumiram; um
///   `<details>` com resultados abre sozinho enquanto há busca por texto.
/// - Um link `#id` para um item de outra página da lista mostra essa página.
pub const PAGER_SCRIPT: &str = r#"
(function(){
  var d=document;
  function all(s,r){return Array.prototype.slice.call((r||d).querySelectorAll(s));}
  function fold(s){s=(s||'').toLowerCase();return s.normalize?s.normalize('NFD').replace(/[̀-ͯ]/g,''):s;}
  var text=d.getElementById('filtro'),state=d.getElementById('estado'),count=d.getElementById('contagem'),empty=d.getElementById('vazio');
  var lists=all('[data-paginate]');
  function query(){return text?fold(text.value.trim()):'';}
  function filtering(){return !!(query()||(state&&state.value));}
  function ok(item){
    if(state&&state.value&&item.getAttribute('data-state')!==state.value)return false;
    var q=query();
    return !q||fold(item.getAttribute('data-text')||item.textContent).indexOf(q)>=0;
  }
  function button(label,page,disabled,current,name){
    return '<button type="button" data-p="'+page+'"'+(disabled?' disabled':'')+(current?' aria-current="page"':'')+
      ' aria-label="'+name+'">'+label+'</button>';
  }
  function numbers(current,total){
    var out=[],i;
    for(i=0;i<total;i++){
      if(i===0||i===total-1||Math.abs(i-current)<=1)out.push(i);
      else if(out[out.length-1]!==-1)out.push(-1);
    }
    return out;
  }
  function render(list){
    var items=all('[data-item]',list),shown=items.filter(ok),size=list.size;
    var pages=Math.max(1,Math.ceil(shown.length/size));
    if(list.page>=pages)list.page=pages-1;
    var start=list.page*size;
    items.forEach(function(item){item.hidden=true;});
    shown.forEach(function(item,n){item.hidden=n<start||n>=start+size;});
    var html='';
    if(pages>1){
      html+=button('&lsaquo; Anterior',list.page-1,list.page===0,false,'Página anterior');
      numbers(list.page,pages).forEach(function(p){
        html+=p<0?'<span class="gap">&hellip;</span>':button(String(p+1),p,false,p===list.page,'Página '+(p+1));
      });
      html+=button('Próxima &rsaquo;',list.page+1,list.page===pages-1,false,'Próxima página');
      html+='<span class="range">'+(start+1)+'&ndash;'+Math.min(start+size,shown.length)+' de '+shown.length+'</span>';
    }
    list.pager.innerHTML=html;
    list.pager.hidden=pages<2;
    var section=list.closest('[data-section]');
    if(section)section.hidden=filtering()&&shown.length===0;
    var details=list.closest('details');
    if(details&&filtering()&&shown.length>0&&query())details.open=true;
    return shown.length;
  }
  function update(reset){
    var total=0;
    lists.forEach(function(list){if(reset)list.page=0;total+=render(list);});
    all('[data-group]').forEach(function(group){
      group.hidden=filtering()&&all('[data-section]',group).every(function(section){return section.hidden;});
    });
    if(count){count.textContent=total+' '+(total===1?count.getAttribute('data-one'):count.getAttribute('data-many'));}
    if(empty)empty.hidden=total>0;
  }
  lists.forEach(function(list){
    list.page=0;list.size=parseInt(list.getAttribute('data-paginate'),10)||10;
    var nav=d.createElement('nav');nav.className='pager';nav.setAttribute('aria-label','Paginação');
    list.parentNode.insertBefore(nav,list.nextSibling);list.pager=nav;
    nav.addEventListener('click',function(event){
      var target=event.target.closest('button');
      if(!target||target.disabled)return;
      list.page=parseInt(target.getAttribute('data-p'),10);render(list);
      var top=list.getBoundingClientRect().top;
      if(top<0)list.scrollIntoView({block:'start'});
    });
  });
  if(text)text.addEventListener('input',function(){update(true);});
  if(state)state.addEventListener('change',function(){update(true);});
  function reveal(){
    var id=decodeURIComponent(location.hash.slice(1)),target=id&&d.getElementById(id);
    if(!target)return;
    var item=target.closest('[data-item]'),list=item&&item.closest('[data-paginate]');
    if(list){
      if(!ok(item)){if(text)text.value='';if(state)state.value='';update(true);}
      var n=all('[data-item]',list).filter(ok).indexOf(item);
      if(n>=0){list.page=Math.floor(n/list.size);render(list);}
    }
    var details=target.closest('details');
    if(details)details.open=true;
    target.scrollIntoView({block:'start'});
  }
  update(true);
  reveal();
  window.addEventListener('hashchange',reveal);
})();
"#;
