//! `componentes.html`: as partes do kernel, por categoria, com o estado e o
//! teste que cobre cada uma. Os binários do Windows ficam em O que roda; os
//! componentes dessas categorias sem binário na lista (o suporte ao modo
//! usuário, alvos sem teste) aparecem aqui, em Outros.

use super::super::{ComponentRow, Report, State, STATES};
use super::page::{anchor, escape, filter_bar, html, plural, state_chip, state_label, test_link, Page};

fn state_key(state: State) -> &'static str {
    match state {
        State::Works => "ok",
        State::Partial => "part",
        State::Planned => "plan",
        State::OutOfScope => "out",
    }
}

fn row(report: &Report, component: &ComponentRow) -> String {
    let tests: Vec<String> = component.tests.iter().map(|&index| test_link(&report.tests[index], "testes.html")).collect();
    let tests = if tests.is_empty() { "<span class=\"muted\">sem teste automático</span>".to_string() } else { tests.join(", ") };
    let phase = if component.phase.is_empty() {
        String::new()
    } else {
        format!(" <a class=\"chip tag\" href=\"index.html#fase-{}\">fase {}</a>", anchor(&component.phase), escape(&component.phase))
    };
    let mut more = String::new();
    if !component.notes.is_empty() {
        more.push_str(&format!("<p class=\"more\">{}</p>", escape(&component.notes)));
    }
    if !component.paths.is_empty() {
        let paths: Vec<String> = component.paths.iter().map(|path| format!("<code>{}</code>", escape(path))).collect();
        more.push_str(&format!("<p class=\"more\">Código: {}</p>", paths.join(", ")));
    }
    let details = if more.is_empty() { String::new() } else { format!("<details><summary>Detalhes</summary>{more}</details>") };
    let text = format!("{} {} {}", component.name, component.description, component.notes).to_lowercase();
    format!(
        "<li id=\"{id}\" data-state=\"{state}\" data-text=\"{text}\"><div class=\"head\"><h3>{name}</h3>{chip}{phase}</div>\
         <p>{description}</p><p class=\"small\">Testes: {tests}</p>{details}</li>",
        id = anchor(&component.name),
        state = state_key(component.state),
        text = escape(&text),
        name = escape(&component.name),
        chip = state_chip(component.state),
        description = escape(&component.description),
    )
}

pub fn page(report: &Report) -> String {
    let shown: Vec<&ComponentRow> = report.components.iter().filter(|component| !report.listed_in_runs(component)).collect();
    let count = |state: State| shown.iter().filter(|component| component.state == state).count();
    let mut body = String::new();
    body.push_str(&format!(
        "<h1>Componentes do kernel</h1>\n<p class=\"lead\">As partes do OpenNT escritas em Rust: o que cada uma faz, se \
         funciona e qual teste de boot a cobre. {} de {} funcionam.</p>\n\
         <p class=\"small muted\">Funciona: implementado e coberto por um teste automático de boot. Parcial: só uma parte \
         existe, ou falta o teste. Planejado: previsto numa fase do roadmap. O estado de cada binário da Microsoft (drivers \
         e programas) está em <a href=\"o-que-roda.html\">O que roda</a>.</p>\n",
        count(State::Works),
        plural(shown.len(), "componente", "componentes"),
    ));
    let mut states = vec![("", format!("Todos ({})", shown.len()))];
    states.extend(
        STATES.iter().filter(|&&state| count(state) > 0).map(|&state| (state_key(state), format!("{} ({})", state_label(state), count(state)))),
    );
    body.push_str(&filter_bar("lista", "Buscar", &states));
    body.push_str("\n<div id=\"lista\">\n");
    let mut categories: Vec<(String, String)> = report
        .categories
        .iter()
        .filter(|category| !super::super::WINDOWS_CATEGORIES.contains(&category.name.as_str()))
        .map(|category| (category.name.clone(), category.description.clone()))
        .collect();
    categories.push((
        "Outros".to_string(),
        "Das categorias de binários do Windows, o que não é um binário da lista O que roda: o suporte do kernel ao modo \
         usuário e alvos de compatibilidade ainda sem teste."
            .to_string(),
    ));
    for (name, description) in &categories {
        let rows: String = shown
            .iter()
            .filter(|component| {
                let windows = super::super::WINDOWS_CATEGORIES.contains(&component.category.as_str());
                if name == "Outros" { windows } else { !windows && &component.category == name }
            })
            .map(|component| row(report, component))
            .collect();
        if rows.is_empty() {
            continue;
        }
        let id = anchor(name);
        body.push_str(&format!(
            "<section data-group aria-labelledby=\"{id}\"><h2 id=\"{id}\">{}</h2><p class=\"muted\">{}</p>\
             <ul class=\"rows\">{rows}</ul></section>\n",
            escape(name),
            escape(description)
        ));
    }
    body.push_str("</div>\n");
    html(Page {
        file: "componentes.html",
        title: "Componentes",
        description: "As partes do kernel do OpenNT, o estado de cada uma e o teste de boot que a cobre.",
        body,
    })
}
