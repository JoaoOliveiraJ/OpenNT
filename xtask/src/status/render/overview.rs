//! `index.html`: o que é o OpenNT, os números principais, o marco atual, o
//! que já funciona, o roadmap, os caminhos para as outras páginas, o
//! glossário e o método.

use super::super::{ComponentRow, PhaseRow, Report, State};
use super::common::{
    anchor, component_anchor, escape, html_page, icon_tile, int, live_tests, meter, percent, phase_state, plural,
    section, stat_link, state_icon, state_label, state_legend, test_link,
};
use super::components::{category_anchor, component_meter, state_counts, WINDOWS_DRIVERS};
use super::svg::{component_badge, export_badge};

const CHECK: &str = "<svg viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"M6 12.5l4 4 8-9\"/></svg>";

fn phase_anchor(phase: &PhaseRow) -> String {
    format!("fase-{}", anchor(&phase.number))
}

/// As fases em andamento e a próxima planejada depois delas.
fn current_phases(phases: &[PhaseRow]) -> (Vec<&PhaseRow>, Option<&PhaseRow>) {
    let now: Vec<&PhaseRow> = phases.iter().filter(|phase| phase_state(&phase.state) == State::InDevelopment).collect();
    let after = phases.iter().rposition(|phase| phase_state(&phase.state) != State::Planned).map_or(0, |index| index + 1);
    let next = phases.iter().skip(after).find(|phase| phase_state(&phase.state) == State::Planned);
    (now, next)
}

fn phase_ref(phase: &PhaseRow) -> String {
    format!("<a href=\"#{}\">Fase {} · {}</a>", phase_anchor(phase), escape(&phase.number), escape(&phase.name))
}

/// Uma faixa com um trecho por fase: verde concluída, amarela em andamento.
fn phase_strip(phases: &[PhaseRow]) -> String {
    let count = |state: State| phases.iter().filter(|phase| phase_state(&phase.state) == state).count();
    let label = format!(
        "{} de {} fases concluídas, {} em andamento",
        int(count(State::Works)),
        int(phases.len()),
        int(count(State::InDevelopment))
    );
    let spans: String = phases
        .iter()
        .map(|phase| match phase_state(&phase.state) {
            State::Works => "<span class=\"ok\"></span>",
            State::InDevelopment => "<span class=\"part\"></span>",
            _ => "<span></span>",
        })
        .collect();
    format!("<div class=\"meter steps\" role=\"img\" aria-label=\"{label}\">{spans}</div>")
}

/// "Agora" (fases em andamento) e "A seguir" (a próxima planejada).
fn now_banner(report: &Report) -> String {
    let (now, next) = current_phases(&report.phases);
    if now.is_empty() && next.is_none() {
        return String::new();
    }
    let mut rows = String::new();
    if !now.is_empty() {
        let items: String =
            now.iter().map(|phase| format!("<li>{} <span class=\"muted\">({})</span></li>", phase_ref(phase), escape(&phase.state))).collect();
        rows.push_str(&format!("<div class=\"now-row\"><span class=\"now-label\">Agora</span> <ul>{items}</ul></div>"));
    }
    if let Some(phase) = next {
        rows.push_str(&format!(
            "<div class=\"now-row\"><span class=\"now-label\">A seguir</span> <ul><li>{}</li></ul></div>",
            phase_ref(phase)
        ));
    }
    format!("<div class=\"milestone\" role=\"note\" aria-label=\"Marco atual\">{rows}{}</div>", phase_strip(&report.phases))
}

fn roadmap(report: &Report) -> String {
    let (_, next) = current_phases(&report.phases);
    let mut items = String::new();
    for phase in &report.phases {
        let state = phase_state(&phase.state);
        let (class, dot, chip_class) = match state {
            State::Works => ("done", CHECK.to_string(), "ok"),
            State::InDevelopment => ("now", escape(&phase.number), "part"),
            _ => ("later", escape(&phase.number), "plan"),
        };
        let next_chip = if next.is_some_and(|candidate| std::ptr::eq(candidate, phase)) {
            " <span class=\"chip next\">próxima</span>"
        } else {
            ""
        };
        let rows: Vec<&ComponentRow> = report.components.iter().filter(|row| row.phase == phase.number).collect();
        let components = if rows.is_empty() {
            String::new()
        } else {
            format!("<p class=\"phase-comp\">{}: {}</p>", plural(rows.len(), "componente", "componentes"), state_counts(&rows))
        };
        let scope = if phase.scope.is_empty() { String::new() } else { format!("<p class=\"phase-scope\">{}</p>", escape(&phase.scope)) };
        items.push_str(&format!(
            "<li class=\"phase {class}\" id=\"{id}\"><span class=\"phase-dot\">{dot}</span><div class=\"phase-body\">\
             <div class=\"phase-head\"><span class=\"phase-num\">Fase {number}</span> <span class=\"phase-name\">{name}</span> \
             <span class=\"chip {chip_class}\">{icon}{state}</span>{next_chip}</div>{scope}{components}</div></li>",
            id = phase_anchor(phase),
            number = escape(&phase.number),
            name = escape(&phase.name),
            icon = state_icon(state),
            state = escape(&phase.state),
        ));
    }
    format!("<ol class=\"phases\">{items}</ol>")
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
        "<dl class=\"glossary\">{items}</dl><div class=\"callout\"><h3>Estados de um componente</h3>{}</div>",
        state_legend()
    )
}

fn component_refs(rows: &[&ComponentRow]) -> String {
    let items: String = rows
        .iter()
        .map(|row| {
            format!(
                "<li><a href=\"componentes.html#{}\">{}{}<span class=\"sr-only\"> ({})</span></a></li>",
                component_anchor(row),
                state_icon(row.state),
                escape(&row.name),
                state_label(row.state).to_lowercase()
            )
        })
        .collect();
    format!("<ul class=\"refs\">{items}</ul>")
}

/// O que já funciona, por categoria, e o que está a caminho.
fn highlights(report: &Report) -> String {
    let mut html = String::new();
    for category in &report.categories {
        let rows: Vec<&ComponentRow> =
            report.components.iter().filter(|row| row.category == category.name && row.state == State::Works).collect();
        if rows.is_empty() {
            continue;
        }
        let cards: String = rows
            .iter()
            .map(|row| {
                let tests: Vec<String> =
                    live_tests(row, report).iter().map(|&index| test_link(index, report, "testes.html")).collect();
                format!(
                    "<article class=\"mini\">{}<div><h4><a href=\"componentes.html#{}\">{}</a></h4><p>{}</p>\
                     <p class=\"by\">Verificado por: {}</p></div></article>",
                    icon_tile(&row.icon, "good sm"),
                    component_anchor(row),
                    escape(&row.name),
                    escape(&row.description),
                    tests.join(", ")
                )
            })
            .collect();
        html.push_str(&format!(
            "<h3><a href=\"componentes.html#{}\">{}</a> <span class=\"count-badge\">{}</span></h3><div class=\"minis\">{cards}</div>",
            category_anchor(&category.name),
            escape(&category.name),
            int(rows.len())
        ));
    }
    let partial: Vec<&ComponentRow> = report.components.iter().filter(|row| row.state == State::InDevelopment).collect();
    let planned: Vec<&ComponentRow> =
        report.components.iter().filter(|row| matches!(row.state, State::Planned | State::OutOfScope)).collect();
    if !partial.is_empty() || !planned.is_empty() {
        html.push_str("<h3>A caminho</h3>");
        if !partial.is_empty() {
            html.push_str(&format!(
                "<p class=\"intro\">Além destes, {} — parte pronta ou ainda sem teste. Veja a lista completa em \
                 <a href=\"componentes.html\">Componentes e drivers</a>.</p>",
                plural(partial.len(), "componente está parcial", "componentes estão parciais")
            ));
        }
        let mut cards = String::new();
        if !partial.is_empty() {
            cards.push_str(&format!(
                "<div class=\"card\"><h4>Parciais <span class=\"count-badge\">{}</span></h4><p class=\"small muted\">Parte \
                 pronta, ou código ainda sem teste automático.</p>{}</div>",
                int(partial.len()),
                component_refs(&partial)
            ));
        }
        if !planned.is_empty() {
            cards.push_str(&format!(
                "<div class=\"card\"><h4>Planejados <span class=\"count-badge\">{}</span></h4><p class=\"small muted\">Ainda \
                 sem código; cada um entra numa fase do roadmap.</p>{}</div>",
                int(planned.len()),
                component_refs(&planned)
            ));
        }
        html.push_str(&format!("<div class=\"grid two\">{cards}</div>"));
    }
    html
}

fn explore(report: &Report) -> String {
    let total = &report.exports.total;
    let (done, partial, planned) = report.module_totals();
    let card = |href: &str, icon: &str, title: &str, big: String, text: &str| {
        format!(
            "<a href=\"{href}\"><span class=\"t\">{}<span>{title}</span></span> <span class=\"big\">{big}</span><p>{text}</p></a>",
            icon_tile(icon, "sm")
        )
    };
    format!(
        "<nav class=\"links\" aria-label=\"Páginas de detalhe\">{}{}{}{}</nav>",
        card(
            "componentes.html",
            "cube",
            "Componentes e drivers",
            format!("{} <small>de {} funcionam</small>", int(report.count(State::Works)), int(report.components.len())),
            "O que cada parte do sistema faz, se já funciona, qual teste a verifica e em que fase do roadmap ela entra. \
             Por categoria: núcleo, drivers, sistemas de arquivos, programas."
        ),
        card(
            "testes.html",
            "check",
            "Testes",
            format!("{} <small>testes de boot</small>", int(report.tests_found())),
            "Os testes automáticos de boot: o que cada um confere e quais componentes cobre."
        ),
        card(
            "ntoskrnl.html",
            "list",
            "Exports do ntoskrnl",
            format!("{} <small>dos exports</small>", escape(&percent(total.opennt, total.reference))),
            "Quantos dos nomes que o <code>ntoskrnl.exe</code> do Windows 10 exporta o OpenNT também exporta, por área do \
             kernel, com busca por nome."
        ),
        card(
            "modulos.html",
            "layers",
            "Módulos do kernel",
            format!("{} <small>de {} com código</small>", int(done + partial), int(planned)),
            "O plano de código do kernel, subsistema por subsistema, com o que já foi escrito."
        ),
    )
}

pub fn page(report: &Report) -> String {
    let total = &report.exports.total;
    let (done, partial, planned) = report.module_totals();
    let works = report.count(State::Works);
    let components = report.components.len();
    let all: Vec<&ComponentRow> = report.components.iter().collect();
    let windows: Vec<&ComponentRow> = report.components.iter().filter(|row| row.category == WINDOWS_DRIVERS).collect();
    let windows_works = windows.iter().filter(|row| row.state == State::Works).count();

    let stats = format!(
        "{}{}{}{}",
        stat_link(
            "componentes.html?estado=funciona#lista",
            "Componentes que funcionam",
            &int(works),
            &format!("de {}", int(components)),
            &component_meter(&all, true),
            &format!(
                "{} de {}: têm código e passam por um teste automático ({})",
                int(works),
                int(components),
                percent(works, components)
            )
        ),
        stat_link(
            &format!("componentes.html#{}", category_anchor(WINDOWS_DRIVERS)),
            "Drivers do Windows que rodam",
            &int(windows_works),
            &format!("de {}", int(windows.len())),
            &meter(
                &[(windows_works, "ok")],
                windows.len(),
                Some(&format!("{} de {} drivers do Windows rodam num teste automático", int(windows_works), int(windows.len())))
            ),
            &format!(
                "o binário do próprio Windows carrega e roda num teste automático ({})",
                percent(windows_works, windows.len())
            )
        ),
        stat_link(
            "ntoskrnl.html",
            "Exports do ntoskrnl.exe",
            &int(total.opennt),
            &format!("de {}", int(total.reference)),
            &meter(
                &[(total.opennt, "")],
                total.reference,
                Some(&format!("{} de {} exports ({})", int(total.opennt), int(total.reference), percent(total.opennt, total.reference)))
            ),
            &format!(
                "{} dos {} nomes do Windows 10 também exportados ({})",
                int(total.opennt),
                int(total.reference),
                percent(total.opennt, total.reference)
            )
        ),
        stat_link(
            "modulos.html",
            "Módulos do plano com código",
            &int(done + partial),
            &format!("de {}", int(planned)),
            &meter(
                &[(done, ""), (partial, "part")],
                planned,
                Some(&format!("{} de {} módulos com código, {} parciais", int(done + partial), int(planned), int(partial)))
            ),
            &format!(
                "{} de {} ({} parciais; {}); mede código escrito, não testado",
                int(done + partial),
                int(planned),
                int(partial),
                percent(done + partial, planned)
            )
        ),
    );
    let mut body = format!(
        "<header class=\"page-head home-head\"><ul class=\"pills\" aria-label=\"Em resumo\"><li>Kernel experimental</li>\
         <li>x86-64</li><li>Rust</li></ul><h1>OpenNT</h1><p class=\"lead\">Um kernel com a arquitetura do Windows NT, \
         escrito em Rust.</p><p class=\"sub\">A meta é carregar drivers e programas do Windows sem modificá-los. Estas \
         páginas mostram onde o projeto está, com números tirados do próprio código a cada geração.</p>{}\
         <div class=\"stats\">{stats}</div></header>",
        now_banner(report)
    );

    body.push_str(&section(
        "funciona",
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
        "O OpenNT avança em fases. Cada fase termina com o kernel compilando, iniciando no QEMU e passando nos testes \
         daquela parte.",
        &format!(
            "{}<p class=\"small\">O mesmo roadmap, com os componentes de cada fase, está em \
             <a href=\"../ROADMAP.md\"><code>docs/ROADMAP.md</code></a>.</p>",
            roadmap(report)
        ),
    ));

    body.push_str(&section("paginas", "Explore os detalhes", "", &explore(report)));

    body.push_str(&section("glossario", "Como ler este site", "", &glossary()));

    body.push_str(&section(
        "metodo",
        "Como estes números são obtidos",
        "",
        &format!(
            "<div class=\"grid\"><div class=\"card\"><h3>Componentes</h3><p>O estado de cada item é declarado em \
             <code>docs/status/components.toml</code>. O gerador confere que os arquivos citados existem e que o marcador \
             de cada teste aparece no código, e só mostra <em>Funciona</em> quando há teste.</p></div>\
             <div class=\"card\"><h3>Módulos</h3><p>O plano lista os módulos de cada subsistema em \
             <code>docs/status/modulos-planejados.txt</code>. Conta como escrito o módulo que já tem arquivo Rust.</p></div>\
             <div class=\"card\"><h3>Exports</h3><p>A referência é a tabela de exports do <code>ntoskrnl.exe</code> real \
             do Windows 10 22H2 (build 19045). Do lado do OpenNT conta só o que a tabela de exports do kernel contém de \
             fato.</p></div></div><h3>Gerar de novo</h3><pre><code>cargo xtask status</code></pre><p class=\"small\">O \
             comando reescreve <code>docs/site/</code>, os SVGs de <code>docs/status/</code> e o \
             <code>docs/ROADMAP.md</code> sem compilar o kernel. Ele não roda os testes; para isso, use \
             <code>cargo xtask test-boot</code>.</p><h3>Selos</h3><p class=\"small\">Os mesmos números, nos selos que o \
             README usa (<code>docs/status/</code>):</p><div class=\"badges\">{}{}</div>",
            export_badge(&report.exports, "ix-selo-ntoskrnl").trim(),
            component_badge(report, "ix-selo-componentes").trim()
        ),
    ));
    html_page(
        "index.html",
        "OpenNT · status do projeto",
        "Estado do OpenNT, um kernel com a arquitetura do Windows NT escrito em Rust: o que funciona, como é testado e \
         o que vem a seguir.",
        &body,
        &[],
    )
}
