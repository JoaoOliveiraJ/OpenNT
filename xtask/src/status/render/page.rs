//! A moldura comum das páginas (cabeçalho, navegação, rodapé, tema claro e
//! escuro), o CSS, o script pequeno de filtro e as peças repetidas: selos
//! de estado, a captura de tela e a formatação de números.

use super::super::{Capture, RunState, State, TestRow};

// ---- formatação -----------------------------------------------------------------

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

/// Inteiro com separador de milhar pt-BR (`3.070`).
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

/// Porcentagem com uma casa e vírgula decimal (`63,7%`).
pub fn percent(part: usize, whole: usize) -> String {
    if whole == 0 {
        return "—".into();
    }
    let tenths = (part as u128 * 1000 + whole as u128 / 2) / whole as u128;
    format!("{},{}%", tenths / 10, tenths % 10)
}

pub fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{} {}", int(count), if count == 1 { one } else { many })
}

/// Identificador para âncoras (`acpi.sys como raiz` -> `acpi-sys-como-raiz`).
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

/// A primeira frase de um texto (até o primeiro ". " ou ": "), para
/// resumos; o texto inteiro fica num `<details>`.
pub fn first_sentence(text: &str) -> &str {
    let mut end = text.len();
    for separator in [". ", ": "] {
        if let Some(position) = text.find(separator) {
            end = end.min(position + 1);
        }
    }
    text[..end].trim_end_matches(':')
}

pub fn test_anchor(test: &TestRow) -> String {
    format!("teste-{}", anchor(&test.id))
}

pub fn test_link(test: &TestRow, prefix: &str) -> String {
    format!("<a href=\"{prefix}#{}\"><code>{}</code></a>", test_anchor(test), escape(&test.id))
}

// ---- estados --------------------------------------------------------------------

pub fn run_label(state: RunState) -> &'static str {
    match state {
        RunState::Runs => "Roda",
        RunState::Partial => "Parcial",
        RunState::DoesNotRun => "Não roda",
    }
}

pub fn run_class(state: RunState) -> &'static str {
    match state {
        RunState::Runs => "ok",
        RunState::Partial => "part",
        RunState::DoesNotRun => "no",
    }
}

/// O selo de estado: forma e texto, não só a cor.
pub fn run_chip(state: RunState, title: &str) -> String {
    let mark = match state {
        RunState::Runs => "●",
        RunState::Partial => "◐",
        RunState::DoesNotRun => "○",
    };
    let title = if title.is_empty() { String::new() } else { format!(" title=\"{}\"", escape(title)) };
    format!("<span class=\"chip {}\"{title}><span aria-hidden=\"true\">{mark}</span> {}</span>", run_class(state), run_label(state))
}

pub fn state_label(state: State) -> &'static str {
    match state {
        State::Works => "Funciona",
        State::Partial => "Parcial",
        State::Planned => "Planejado",
        State::OutOfScope => "Fora do escopo",
    }
}

pub fn state_chip(state: State) -> String {
    let (class, mark) = match state {
        State::Works => ("ok", "●"),
        State::Partial => ("part", "◐"),
        State::Planned => ("no", "○"),
        State::OutOfScope => ("no", "–"),
    };
    format!("<span class=\"chip {class}\"><span aria-hidden=\"true\">{mark}</span> {}</span>", state_label(state))
}

/// Selo de uma fase pelo texto do `estado` dela.
pub fn phase_chip(state: &str) -> String {
    let (class, mark) = if state.starts_with("concluíd") {
        ("ok", "●")
    } else if state.starts_with("em andamento") {
        ("part", "◐")
    } else {
        ("no", "○")
    };
    format!("<span class=\"chip {class}\"><span aria-hidden=\"true\">{mark}</span> {}</span>", escape(state))
}

// ---- captura --------------------------------------------------------------------

/// A captura do fim de um teste, com link para a imagem inteira. `prefix`
/// leva da página até `docs/site/` (vazio nas páginas do site).
pub fn capture_figure(test: &TestRow, class: &str) -> String {
    let Some(capture) = &test.capture else {
        return format!(
            "<p class=\"shot none {class}\">Sem captura ainda: <code>cargo xtask capturas --only {}</code></p>",
            escape(&test.id)
        );
    };
    let result = capture_result(capture);
    let serial = if capture.serial.is_empty() {
        String::new()
    } else {
        format!("<details class=\"serial\"><summary>Serial no fim do teste</summary><pre><code>{}</code></pre></details>", escape(&capture.serial))
    };
    format!(
        "<figure class=\"shot {class}\"><a href=\"{file}\"><img src=\"{file}\" width=\"{w}\" height=\"{h}\" loading=\"lazy\" \
         decoding=\"async\" alt=\"Tela do QEMU no fim do teste {id}: {title}\"></a>\
         <figcaption>Tela do QEMU no fim do teste <code>{id}</code>, {date}{result}</figcaption>{serial}</figure>",
        file = escape(&capture.file),
        w = capture.width,
        h = capture.height,
        id = escape(&test.id),
        title = escape(&test.title),
        date = escape(&date_label(&capture.date)),
    )
}

fn capture_result(capture: &Capture) -> String {
    if capture.passed() {
        String::new()
    } else if capture.result.is_empty() {
        " (resultado não registrado)".into()
    } else {
        format!(" — {}", escape(&capture.result.replace("TEST-BOOT FALHOU: ", "")))
    }
}

/// `2026-11-15` -> `15/11/2026`.
pub fn date_label(date: &str) -> String {
    let parts: Vec<&str> = date.split('-').collect();
    match parts.as_slice() {
        [year, month, day] => format!("{day}/{month}/{year}"),
        _ if date.is_empty() => "data não registrada".into(),
        _ => date.to_string(),
    }
}

// ---- moldura --------------------------------------------------------------------

pub struct Page<'a> {
    /// Arquivo da página (`o-que-roda.html`), para marcar a navegação.
    pub file: &'a str,
    pub title: &'a str,
    pub description: &'a str,
    pub body: String,
}

const NAV: &[(&str, &str)] = &[
    ("index.html", "Início"),
    ("o-que-roda.html", "O que roda"),
    ("componentes.html", "Componentes"),
    ("ntoskrnl.html", "Exports"),
    ("testes.html", "Testes"),
];

pub fn html(page: Page) -> String {
    let nav: String = NAV
        .iter()
        .map(|(file, label)| {
            let current = if *file == page.file { " aria-current=\"page\"" } else { "" };
            format!("<a href=\"{file}\"{current}>{label}</a>")
        })
        .collect();
    let title = if page.file == "index.html" { "OpenNT".to_string() } else { format!("{} · OpenNT", page.title) };
    format!(
        "<!doctype html>\n<html lang=\"pt-BR\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta name=\"description\" content=\"{description}\">\n<title>{title}</title>\n\
         <script>{THEME_BOOT}</script>\n<style>{CSS}</style>\n</head>\n<body>\n\
         <a class=\"skip\" href=\"#conteudo\">Pular para o conteúdo</a>\n\
         <header class=\"top\"><div class=\"wrap\"><a class=\"brand\" href=\"index.html\">OpenNT</a>\
         <nav aria-label=\"Páginas\">{nav}</nav>\
         <button type=\"button\" class=\"theme\" id=\"tema\" hidden>Tema: automático</button></div></header>\n\
         <main id=\"conteudo\" class=\"wrap\">\n{body}\n</main>\n\
         <footer class=\"wrap foot\"><p>Gerado por <code>cargo xtask status</code> a partir de \
         <code>docs/status/components.toml</code>, da tabela de exports do kernel e das capturas de \
         <code>cargo xtask capturas</code>. Nenhum binário da Microsoft entra no repositório: o build os copia do \
         Windows da máquina.</p></footer>\n<script>{SCRIPT}</script>\n</body>\n</html>\n",
        description = escape(page.description),
        title = escape(&title),
        body = page.body,
    )
}

/// Aplica o tema guardado antes da primeira pintura.
const THEME_BOOT: &str = "try{var t=localStorage.getItem('opennt-tema');if(t==='claro'||t==='escuro')\
document.documentElement.setAttribute('data-theme',t==='claro'?'light':'dark');}catch(e){}";

/// O botão de tema e os filtros (`data-filter` numa lista de itens com
/// `data-text` e `data-state`, ou de nomes em `.names li`, buscados pelo
/// texto). Sem JavaScript, as listas aparecem inteiras.
const SCRIPT: &str = r#"(function(){
var root=document.documentElement,b=document.getElementById('tema');
if(b){var names={auto:'automático',claro:'claro',escuro:'escuro'};
var cur=function(){var t=root.getAttribute('data-theme');return t==='light'?'claro':t==='dark'?'escuro':'auto';};
var show=function(){b.textContent='Tema: '+names[cur()];};
b.hidden=false;show();
b.addEventListener('click',function(){var n={auto:'claro',claro:'escuro',escuro:'auto'}[cur()];
if(n==='auto'){root.removeAttribute('data-theme');}else{root.setAttribute('data-theme',n==='claro'?'light':'dark');}
try{if(n==='auto'){localStorage.removeItem('opennt-tema');}else{localStorage.setItem('opennt-tema',n);}}catch(e){}
show();});}
document.querySelectorAll('[data-filter]').forEach(function(bar){
var scope=document.getElementById(bar.getAttribute('data-filter'));if(!scope)return;
var q=bar.querySelector('input[type=search]'),btns=bar.querySelectorAll('button[data-state]'),out=bar.querySelector('output');
var items=scope.querySelectorAll('[data-text],.names li'),state='';bar.hidden=false;
var key=function(it){return it.getAttribute('data-text')||it.textContent.toLowerCase();};
var run=function(){var text=q?q.value.trim().toLowerCase():'',n=0;
items.forEach(function(it){var ok=(!state||it.getAttribute('data-state')===state)&&(!text||key(it).indexOf(text)>=0);
it.hidden=!ok;if(ok)n++;});
scope.querySelectorAll('[data-group]').forEach(function(g){var any=g.querySelector('[data-text]:not([hidden]),.names li:not([hidden])');g.hidden=!any;
if(g.tagName==='DETAILS'&&text&&any)g.open=true;});
if(out)out.textContent=n+(n===1?' item':' itens');};
btns.forEach(function(x){x.addEventListener('click',function(){state=x.getAttribute('data-state');
btns.forEach(function(y){y.setAttribute('aria-pressed',y===x?'true':'false');});run();});});
if(q)q.addEventListener('input',run);run();});
})();"#;

/// A barra de filtro de uma lista: botões de estado (`(valor, rótulo)`,
/// valor vazio = todos) e a busca. Fica escondida até o script rodar.
pub fn filter_bar(target: &str, label: &str, states: &[(&str, String)]) -> String {
    let buttons: String = states
        .iter()
        .enumerate()
        .map(|(index, (value, text))| {
            format!(
                "<button type=\"button\" data-state=\"{value}\" aria-pressed=\"{}\">{text}</button>",
                if index == 0 { "true" } else { "false" }
            )
        })
        .collect();
    let group = if buttons.is_empty() { String::new() } else { format!("<div class=\"seg\" role=\"group\" aria-label=\"Estado\">{buttons}</div>") };
    format!(
        "<div class=\"filter\" data-filter=\"{target}\" hidden><label>{label} <input type=\"search\" \
         autocomplete=\"off\" spellcheck=\"false\"></label>{group}<output aria-live=\"polite\"></output></div>"
    )
}

const CSS: &str = r#"
:root{--bg:#fafaf8;--fg:#1c1c1a;--muted:#5a5954;--line:#dedcd5;--card:#fff;--soft:#f2f1ec;--accent:#1f5fbf;
--ok:#17692f;--ok-bg:#e3f2e7;--part:#7d5600;--part-bg:#fdf0cf;--no:#555;--no-bg:#ecebe7;color-scheme:light}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#141413;--fg:#eceae4;--muted:#aaa89f;--line:#36352f;
--card:#1c1c1a;--soft:#232320;--accent:#8ab4ff;--ok:#6fd08a;--ok-bg:#15301d;--part:#f0c050;--part-bg:#342a10;--no:#b4b2ab;
--no-bg:#2a2a27;color-scheme:dark}}
:root[data-theme=dark]{--bg:#141413;--fg:#eceae4;--muted:#aaa89f;--line:#36352f;--card:#1c1c1a;--soft:#232320;
--accent:#8ab4ff;--ok:#6fd08a;--ok-bg:#15301d;--part:#f0c050;--part-bg:#342a10;--no:#b4b2ab;--no-bg:#2a2a27;color-scheme:dark}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent)}a:focus-visible,button:focus-visible,input:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;font-size:.88em}
code{background:var(--soft);padding:.05em .3em;border-radius:4px;overflow-wrap:break-word}
pre{background:var(--soft);padding:10px 12px;border-radius:8px;overflow-x:auto;margin:.5em 0}pre code{background:none;padding:0}
.wrap{max-width:1120px;margin:0 auto;padding:0 16px}
.skip{position:absolute;left:-999px}.skip:focus{left:16px;top:8px;background:var(--card);padding:6px 10px;z-index:2}
.top{border-bottom:1px solid var(--line);background:var(--card)}
.top .wrap{display:flex;flex-wrap:wrap;align-items:center;gap:6px 18px;padding-top:10px;padding-bottom:10px}
.brand{font-weight:700;font-size:1.15rem;color:var(--fg);text-decoration:none}
nav{display:flex;flex-wrap:wrap;gap:2px 4px}nav a{padding:4px 8px;border-radius:6px;text-decoration:none;color:var(--fg)}
nav a:hover{background:var(--soft)}nav a[aria-current=page]{background:var(--soft);font-weight:600;box-shadow:inset 0 -2px 0 var(--accent)}
.theme{margin-left:auto;font:inherit;font-size:.85rem;background:none;color:var(--muted);border:1px solid var(--line);border-radius:6px;padding:3px 8px;cursor:pointer}
main{padding-top:8px;padding-bottom:24px}
h1{font-size:1.75rem;line-height:1.25;margin:20px 0 8px}h2{font-size:1.3rem;margin:32px 0 8px}h3{font-size:1.02rem;margin:0}
.lead{font-size:1.08rem;max-width:62rem;margin:0 0 12px}.muted{color:var(--muted)}.small{font-size:.88rem}
.foot{border-top:1px solid var(--line);color:var(--muted);font-size:.85rem;padding-top:12px;padding-bottom:28px}
.chip{display:inline-flex;align-items:center;gap:.3em;white-space:nowrap;font-size:.8rem;font-weight:600;line-height:1;padding:4px 8px;border-radius:999px}
.chip.ok{color:var(--ok);background:var(--ok-bg)}.chip.part{color:var(--part);background:var(--part-bg)}.chip.no{color:var(--no);background:var(--no-bg)}
.chip.tag{color:var(--muted);background:var(--soft);font-weight:500}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(220px,100%),1fr));gap:12px;margin:16px 0}
.stat{display:block;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;color:var(--fg);text-decoration:none}
a.stat:hover{border-color:var(--accent)}.stat b{display:block;font-size:1.7rem;line-height:1.2;font-variant-numeric:tabular-nums}
.stat span{color:var(--muted);font-size:.9rem}
.bar{display:flex;height:8px;border-radius:4px;overflow:hidden;background:var(--no-bg);margin-top:8px}
.bar i{display:block}.bar .ok{background:var(--ok)}.bar .part{background:var(--part)}
.mile{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:12px;margin:12px 0}
.mile>div{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.mile h2{margin:0 0 6px;font-size:1rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.mile p{margin:0 0 8px}
.cards{list-style:none;padding:0;margin:12px 0;display:grid;grid-template-columns:repeat(auto-fill,minmax(min(320px,100%),1fr));gap:12px}
.cards.wide{grid-template-columns:repeat(auto-fill,minmax(min(460px,100%),1fr))}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;display:flex;flex-direction:column;gap:6px;min-width:0}
.card header{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:6px}
.card p{margin:0}.card .stop{color:var(--muted)}.card .stop b{color:var(--fg);font-weight:600}
.shot{margin:4px 0 0}.shot img{display:block;width:100%;height:auto;max-height:300px;object-fit:contain;border-radius:6px;border:1px solid var(--line);background:#000}
.shot.tool img{max-height:none;background:none}
.shot figcaption{font-size:.8rem;color:var(--muted);margin-top:4px}
.serial summary{font-size:.85rem}.serial pre{font-size:.72rem;line-height:1.45;max-height:22rem;margin:4px 0 0}.shot.none{font-size:.85rem;color:var(--muted);border:1px dashed var(--line);border-radius:6px;padding:10px;margin-top:4px}
.filter{display:flex;flex-wrap:wrap;align-items:center;gap:8px 14px;margin:12px 0;padding:10px 12px;background:var(--card);border:1px solid var(--line);border-radius:10px}
.filter input{font:inherit;padding:4px 8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);width:min(260px,60vw)}
.seg{display:flex;flex-wrap:wrap;gap:4px}.seg button{font:inherit;font-size:.88rem;padding:3px 10px;border:1px solid var(--line);border-radius:999px;background:var(--bg);color:var(--fg);cursor:pointer}
.seg button[aria-pressed=true]{background:var(--fg);color:var(--bg);border-color:var(--fg)}
.filter output{color:var(--muted);font-size:.88rem}
.rows{list-style:none;padding:0;margin:8px 0;border:1px solid var(--line);border-radius:10px;background:var(--card)}
.rows>li{padding:10px 14px;border-top:1px solid var(--line)}.rows>li:first-child{border-top:0}
.rows .head{display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px}.rows .head h3{margin-right:auto}
.rows p{margin:4px 0 0}
details{margin-top:4px}summary{cursor:pointer;color:var(--accent)}details .more{margin:6px 0 0;font-size:.92rem}
table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:.85rem;color:var(--muted);font-weight:600}
td.num,th.num{text-align:right;white-space:nowrap}
.table{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--card);margin:8px 0}
.table table th:first-child,.table table td:first-child{padding-left:14px}
.mini{display:inline-block;width:90px;height:7px;border-radius:4px;background:var(--no-bg);vertical-align:middle;overflow:hidden}.mini i{display:block;height:100%;background:var(--ok)}
.groups details{border:1px solid var(--line);border-radius:10px;background:var(--card);padding:8px 14px;margin:8px 0}
.groups summary{display:flex;flex-wrap:wrap;gap:4px 12px;align-items:center;color:var(--fg);list-style:none}.groups summary b{min-width:6rem}
.groups summary::-webkit-details-marker{display:none}.groups summary::before{content:"▸";color:var(--muted)}.groups details[open]>summary::before{content:"▾"}
.names{list-style:none;padding:0;margin:6px 0 10px;display:grid;grid-template-columns:repeat(auto-fill,minmax(min(17rem,100%),1fr));gap:2px 16px;font-size:.86rem}
.names li{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}
.names.missing li{color:var(--muted)}
h4{margin:8px 0 2px;font-size:.9rem}
.phases{list-style:none;padding:0;margin:8px 0;display:grid;gap:6px}
.phases li{display:flex;flex-wrap:wrap;gap:4px 10px;align-items:baseline}.phases .n{font-weight:600;min-width:4.5rem}
.test{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,320px);gap:6px 16px;align-items:start}
@media (max-width:760px){.test{grid-template-columns:minmax(0,1fr)}}
@media (max-width:700px){.mile{grid-template-columns:minmax(0,1fr)}h1{font-size:1.45rem}}
@media (prefers-reduced-motion:reduce){*{scroll-behavior:auto!important}}
"#;
