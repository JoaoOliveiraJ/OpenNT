//! `o-que-roda.html`: cada binário real da Microsoft que o OpenNT exercita,
//! e os marcos, com o estado, o que funciona, onde para, o teste que prova
//! e a captura de tela do fim desse teste.

use super::super::{Group, Report, RunRow, RunState, GROUPS, RUN_STATES};
use super::page::{anchor, capture_figure, escape, filter_bar, html, run_chip, run_class, run_label, test_link, Page};

pub fn run_anchor(row: &RunRow) -> String {
    anchor(&row.name)
}

fn group_title(group: Group) -> (&'static str, &'static str, &'static str) {
    match group {
        Group::Milestone => (
            "marcos",
            "Marcos",
            "O que o sistema já faz de ponta a ponta com os binários da Microsoft, e o que ainda falta.",
        ),
        Group::Driver => (
            "drivers",
            "Drivers do Windows (modo kernel)",
            "Os .sys e .dll de modo kernel, carregados como estão: o Code Integrity da própria Microsoft valida cada \
             imagem e o carregador do OpenNT resolve os imports contra os exports do kernel.",
        ),
        Group::Program => (
            "programas",
            "Programas do Windows (modo usuário)",
            "Os .exe e .dll de modo usuário, no anel 3, que falam com o kernel pelas chamadas de sistema do Windows.",
        ),
    }
}

fn card(report: &Report, row: &RunRow) -> String {
    let tests: Vec<String> = row.tests.iter().map(|&index| test_link(&report.tests[index], "testes.html")).collect();
    let proof = match tests.len() {
        0 => "<p class=\"small muted\">Nenhum teste automático ainda.</p>".to_string(),
        1 => format!("<p class=\"small\">Teste: {}</p>", tests[0]),
        _ => format!("<p class=\"small\">Testes: {}</p>", tests.join(", ")),
    };
    let stops = if row.stops.is_empty() {
        String::new()
    } else {
        let label = if row.state == RunState::Runs { "Limite" } else { "Para" };
        format!("<p class=\"stop\"><b>{label}:</b> {}</p>", escape(&row.stops))
    };
    let shot = row.tests.first().map(|&index| capture_figure(&report.tests[index], "")).unwrap_or_default();
    let text = format!("{} {} {}", row.name, row.does, row.stops).to_lowercase();
    format!(
        "<li class=\"card\" id=\"{id}\" data-state=\"{state}\" data-text=\"{text}\"><header><h3>{name}</h3>{chip}</header>\
         <p>{does}</p>{stops}{proof}<p class=\"small muted\">Estado: {reason}.</p>{shot}</li>",
        id = run_anchor(row),
        state = run_class(row.state),
        text = escape(&text),
        name = escape(&row.name),
        chip = run_chip(row.state, ""),
        does = escape(&row.does),
        reason = escape(&row.reason),
    )
}

pub fn page(report: &Report) -> String {
    let count = |state: RunState| report.runs.iter().filter(|row| row.state == state).count();
    let mut body = String::new();
    body.push_str(&format!(
        "<h1>O que roda</h1>\n<p class=\"lead\">Os binários reais da Microsoft que o OpenNT carrega, sem recompilar nem \
         modificar, e os marcos que eles alcançam. Hoje: <b>{} de {} binários rodam</b>, {} são parciais e {} ainda não \
         rodam.</p>\n\
         <ul class=\"small muted\"><li>{} — um teste automático de boot passa e o binário faz o papel dele.</li>\
         <li>{} — carrega e roda até um ponto; o card diz onde para.</li>\
         <li>{} — ainda sem teste automático: um alvo, não um resultado.</li></ul>\n\
         <p class=\"small muted\">A captura de cada card é a tela do QEMU no fim do teste que o prova, com as linhas da \
         serial que mostram o resultado. O estado sai dos dados: do teste (uma falha conhecida dá Parcial) e do estado \
         declarado do componente do binário; cada card diz de onde veio.</p>\n",
        report.binaries(RunState::Runs),
        report.binaries_total(),
        report.binaries(RunState::Partial),
        report.binaries(RunState::DoesNotRun),
        run_chip(RunState::Runs, ""),
        run_chip(RunState::Partial, ""),
        run_chip(RunState::DoesNotRun, ""),
    ));
    let mut states = vec![("", format!("Todos ({})", report.runs.len()))];
    states.extend(RUN_STATES.iter().map(|&state| (run_class(state), format!("{} ({})", run_label(state), count(state)))));
    body.push_str(&filter_bar("itens", "Buscar", &states));
    body.push_str("\n<div id=\"itens\">\n");
    for &group in GROUPS {
        let rows: Vec<&RunRow> = report.runs.iter().filter(|row| row.group == group).collect();
        if rows.is_empty() {
            continue;
        }
        let (id, title, intro) = group_title(group);
        let class = if group == Group::Milestone { "cards wide" } else { "cards" };
        let cards: String = rows.iter().map(|row| card(report, row)).collect();
        body.push_str(&format!(
            "<section data-group aria-labelledby=\"{id}\"><h2 id=\"{id}\">{title}</h2><p class=\"muted\">{intro}</p>\
             <ul class=\"{class}\">{cards}</ul></section>\n"
        ));
    }
    body.push_str("</div>\n");
    html(Page {
        file: "o-que-roda.html",
        title: "O que roda",
        description: "Os binários reais da Microsoft que o OpenNT carrega: o estado de cada um, onde para, o teste que prova e a tela.",
        body,
    })
}
