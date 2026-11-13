//! `index.html`: os números principais, o glossário, o que já funciona, o
//! roadmap e os caminhos para as outras páginas.

use super::super::{PhaseRow, Report, State};
use super::common::{
    component_anchor, escape, hero, icon_tile, int, live_tests, html_page, phase_state, plural, ring_stat, section,
    state_icon, state_legend, test_link, PAGER_SCRIPT,
};
use super::svg::{component_badge, export_badge};

/// Cartões por página em "O que já funciona".
const HIGHLIGHTS_PER_PAGE: usize = 12;

fn timeline(phases: &[PhaseRow]) -> String {
    let states: Vec<State> = phases.iter().map(|phase| phase_state(&phase.state)).collect();
    let reached = |index: usize| states.get(index).is_some_and(|state| *state != State::Planned);
    let mut items = String::new();
    for (index, phase) in phases.iter().enumerate() {
        let state = states[index];
        let node = match state {
            State::Works => {
                "<span class=\"node done\"><svg viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"M6 12.5l4 4 8-9\"/>\
                 </svg></span>"
                    .to_string()
            }
            State::InDevelopment => format!("<span class=\"node current\">{}</span>", escape(&phase.number)),
            _ => format!("<span class=\"node\">{}</span>", escape(&phase.number)),
        };
        let mut classes = Vec::new();
        if reached(index) {
            classes.push("reached");
        }
        if reached(index + 1) {
            classes.push("link");
        }
        items.push_str(&format!(
            "<li class=\"{}\" title=\"{}\">{node}<div class=\"num\">Fase {}</div><div class=\"name\">{}</div><div>\
             <span class=\"state\">{}{}</span></div></li>",
            classes.join(" "),
            escape(&phase.scope),
            escape(&phase.number),
            escape(&phase.name),
            state_icon(state),
            escape(&phase.state)
        ));
    }
    format!("<ol class=\"timeline\">{items}</ol>")
}

fn glossary() -> String {
    let terms = [
        (
            "cube",
            "Componente",
            "Uma parte do sistema que se descreve numa frase: o gerenciador de memória, um driver, o shell. É a \
             unidade da página <a href=\"componentes.html\">Componentes e drivers</a>.",
        ),
        (
            "check",
            "Teste de boot",
            "Inicia o kernel numa máquina virtual (QEMU) e espera uma frase combinada na saída serial. É o que permite \
             dizer que algo <em>funciona</em>. Veja <a href=\"testes.html\">Testes</a>.",
        ),
        (
            "window",
            "Driver do Windows",
            "O próprio arquivo <code>.sys</code> ou <code>.dll</code> do Windows, carregado pelo OpenNT sem recompilar \
             nem modificar. Os binários vêm da máquina de build e nunca entram no repositório.",
        ),
        (
            "layers",
            "Módulo",
            "Uma unidade planejada de código do kernel, como <code>ntos/ob/handle_table</code>. Conta quando o arquivo \
             Rust existe: mede quanto do plano já foi escrito, não se funciona. Veja \
             <a href=\"modulos.html\">Módulos do kernel</a>.",
        ),
        (
            "list",
            "Export",
            "Uma rotina ou variável que o kernel oferece aos drivers pelo nome, como <code>IoCreateDevice</code>. Um \
             driver só carrega se todos os nomes que ele importa existirem. Veja \
             <a href=\"ntoskrnl.html\">Exports do ntoskrnl</a>.",
        ),
        (
            "rocket",
            "Fase",
            "Uma etapa do roadmap. Cada fase termina com o kernel compilando, iniciando no QEMU e passando nos testes \
             daquela parte.",
        ),
    ];
    let items: String = terms
        .iter()
        .map(|(icon, term, meaning)| {
            format!("<div><dt>{}{}</dt><dd>{}</dd></div>", icon_tile(icon, "sm"), escape(term), meaning)
        })
        .collect();
    format!(
        "<dl class=\"glossary\">{items}</dl><div class=\"explain\"><h3>Estados de um componente</h3>{}</div>",
        state_legend()
    )
}

fn highlights(report: &Report) -> String {
    let mut tiles = String::new();
    for row in report.components.iter().filter(|row| row.state == State::Works) {
        let tests: Vec<String> = live_tests(row, report).iter().map(|&index| test_link(index, report, "testes.html")).collect();
        tiles.push_str(&format!(
            "<article class=\"card lift highlight\" data-item>{}<div><h3><a href=\"componentes.html#{}\">{}</a></h3>\
             <p>{}</p><div class=\"by\">Verificado por: {}</div></div></article>",
            icon_tile(&row.icon, "good"),
            component_anchor(row),
            escape(&row.name),
            escape(&row.description),
            tests.join(", ")
        ));
    }
    let partial = report.count(State::InDevelopment);
    let more = if partial > 0 {
        format!(
            "<p class=\"small\">Além destes, {} — parte pronta ou ainda sem teste. Veja a lista completa em \
             <a href=\"componentes.html\">Componentes e drivers</a>.</p>",
            plural(partial, "componente está parcial", "componentes estão parciais")
        )
    } else {
        String::new()
    };
    format!("<div class=\"grid tight\" data-paginate=\"{HIGHLIGHTS_PER_PAGE}\">{tiles}</div>{more}")
}

pub fn page(report: &Report) -> String {
    let total = &report.exports.total;
    let (done, partial, planned) = report.module_totals();
    let works = report.count(State::Works);
    let components = report.components.len();
    let mut body = hero(
        "Kernel experimental · x86-64 · Rust",
        "OpenNT",
        "Um kernel com a arquitetura do Windows NT, escrito em Rust.",
        "A meta é carregar drivers e programas do Windows sem modificá-los. Estas páginas mostram onde o projeto está, \
         com números tirados do próprio código a cada geração.",
        &format!(
            "{}{}{}",
            ring_stat(
                works,
                components,
                "Componentes que funcionam",
                &format!("{} de {}: têm código e passam por um teste automático", int(works), int(components))
            ),
            ring_stat(
                done + partial,
                planned,
                "Módulos do plano com código",
                &format!("{} de {} ({} parciais); mede código escrito, não testado", int(done + partial), int(planned), int(partial))
            ),
            ring_stat(
                total.opennt,
                total.reference,
                "Exports do ntoskrnl.exe",
                &format!("{} dos {} nomes do Windows 10 também exportados", int(total.opennt), int(total.reference))
            ),
        ),
    );
    body.push_str(&format!(
        "<div class=\"badges\">{}{}</div>",
        export_badge(&report.exports, "ix-selo-ntoskrnl").trim(),
        component_badge(report, "ix-selo-componentes").trim()
    ));

    body.push_str(&section("glossario", "Glossário", "Como ler este site", "", &glossary()));

    body.push_str(&section(
        "funciona",
        "Hoje",
        "O que já funciona",
        &format!(
            "Os {} que têm código e passam por pelo menos um teste automático de boot.",
            plural(works, "componente", "componentes")
        ),
        &highlights(report),
    ));

    body.push_str(&section(
        "roadmap",
        "Roadmap",
        "Para onde o projeto vai",
        "O OpenNT avança em fases. Cada fase termina com o kernel compilando, iniciando no QEMU e passando nos testes \
         daquela parte.",
        &format!(
            "{}<p class=\"small\">O escopo de cada fase está em <a href=\"../ROADMAP.md\"><code>docs/ROADMAP.md</code></a>.</p>",
            timeline(&report.phases)
        ),
    ));

    body.push_str(&section(
        "paginas",
        "Explore",
        "As páginas",
        "",
        &format!(
            "<div class=\"grid links\">\
             <a class=\"card lift\" href=\"componentes.html\">{}<div><h3>Componentes e drivers →</h3><p class=\"small muted\">\
             O que cada parte do sistema faz, se já funciona, qual teste a verifica e em que fase do roadmap ela entra. \
             Por categoria: núcleo, drivers, sistemas de arquivos, programas.</p></div></a>\
             <a class=\"card lift\" href=\"testes.html\">{}<div><h3>Testes →</h3><p class=\"small muted\">Os testes \
             automáticos de boot: o que cada um confere e quais componentes cobre.</p></div></a>\
             <a class=\"card lift\" href=\"modulos.html\">{}<div><h3>Módulos do kernel →</h3><p class=\"small muted\">O \
             plano de código do kernel, subsistema por subsistema, com o que já foi escrito.</p></div></a>\
             <a class=\"card lift\" href=\"ntoskrnl.html\">{}<div><h3>Exports do ntoskrnl →</h3><p class=\"small muted\">\
             Quantos dos nomes que o <code>ntoskrnl.exe</code> do Windows 10 exporta o OpenNT também exporta, por área \
             do kernel, com busca por nome.</p></div></a></div>",
            icon_tile("cube", ""),
            icon_tile("check", ""),
            icon_tile("layers", ""),
            icon_tile("list", "")
        ),
    ));

    body.push_str(&section(
        "metodo",
        "Método",
        "Como estes números são obtidos",
        "",
        "<div class=\"grid three\"><div class=\"explain\"><h3>Componentes</h3><p>O estado de cada item é declarado em \
         <code>docs/status/components.toml</code>. O gerador confere que os arquivos citados existem e que o marcador \
         de cada teste aparece no código, e só mostra <em>Funciona</em> quando há teste.</p></div>\
         <div class=\"explain\"><h3>Módulos</h3><p>O plano lista os módulos de cada subsistema em \
         <code>docs/status/modulos-planejados.txt</code>. Conta como escrito o módulo que já tem arquivo Rust.</p></div>\
         <div class=\"explain\"><h3>Exports</h3><p>A referência é a tabela de exports do <code>ntoskrnl.exe</code> real \
         do Windows 10 22H2 (build 19045). Do lado do OpenNT conta só o que a tabela de exports do kernel contém de \
         fato.</p></div></div><h3>Gerar de novo</h3><pre><code>cargo xtask status</code></pre><p class=\"small\">O \
         comando reescreve <code>docs/site/</code>, os SVGs de <code>docs/status/</code> e o \
         <code>docs/ROADMAP.md</code> sem compilar o kernel. Ele não roda os testes; para isso, use \
         <code>cargo xtask test-boot</code>.</p>",
    ));
    html_page(
        "index.html",
        "OpenNT · status",
        "Estado do OpenNT, um kernel com a arquitetura do Windows NT escrito em Rust: o que funciona, como é testado e \
         o que vem a seguir.",
        &body,
        &[PAGER_SCRIPT],
    )
}
