//! `index.html` (Início): o que é o OpenNT, os números principais, o marco
//! atual e o próximo, os marcos e as fases.

use super::super::{Group, Report, RunState, State};
use super::page::{anchor, capture_figure, escape, html, int, percent, phase_chip, plural, run_chip, test_link, Page};
use super::runs::run_anchor;

/// Barra fina com os trechos (valor, classe) sobre `whole`; decorativa (os
/// números estão escritos ao lado).
pub fn bar(segments: &[(usize, &str)], whole: usize) -> String {
    let spans: String = segments
        .iter()
        .filter(|(value, _)| *value > 0 && whole > 0)
        .map(|(value, class)| format!("<i class=\"{class}\" style=\"width:{:.2}%\"></i>", *value as f64 * 100.0 / whole as f64))
        .collect();
    format!("<span class=\"bar\" aria-hidden=\"true\">{spans}</span>")
}

pub fn page(report: &Report) -> String {
    let runs = report.binaries(RunState::Runs);
    let partial = report.binaries(RunState::Partial);
    let not_yet = report.binaries(RunState::DoesNotRun);
    let binaries = report.binaries_total();
    let exports = &report.exports.total;
    let kernel: Vec<_> = report.components.iter().filter(|row| !report.listed_in_runs(row)).collect();
    let works = kernel.iter().filter(|row| row.state == State::Works).count();
    let kernel_partial = kernel.iter().filter(|row| row.state == State::Partial).count();
    let suites = crate::test_all::SUITE_CPUS.len();

    let mut body = String::new();
    body.push_str(
        "<h1>OpenNT</h1>\n<p class=\"lead\">O OpenNT é um kernel compatível com o Windows NT para x86-64, escrito em Rust. \
         Ele carrega os binários reais da Microsoft — drivers, o <code>smss.exe</code>, o <code>csrss.exe</code> e o \
         <code>win32k.sys</code> — e implementa só o lado do kernel: os exports do <code>ntoskrnl.exe</code>, as chamadas \
         de sistema e as estruturas do NT.</p>\n",
    );
    body.push_str(&format!(
        "<div class=\"stats\">\
         <a class=\"stat\" href=\"o-que-roda.html\"><b>{runs}</b><span>binários da Microsoft rodam; {partial} parciais e \
         {not_yet} ainda não, de {binaries}</span>{}</a>\
         <a class=\"stat\" href=\"ntoskrnl.html\"><b>{}</b><span>dos {} exports do <code>ntoskrnl.exe</code> do Windows 10 \
         22H2 o kernel também exporta ({})</span>{}</a>\
         <a class=\"stat\" href=\"componentes.html\"><b>{works}</b><span>de {} componentes do kernel funcionam com teste; \
         {kernel_partial} parciais</span>{}</a>\
         <a class=\"stat\" href=\"testes.html\"><b>{}</b><span>testes de boot no QEMU: {} cenários e {} suítes completas, \
         validados por <code>cargo xtask test-all</code></span></a></div>\n",
        bar(&[(runs, "ok"), (partial, "part")], binaries),
        int(exports.opennt),
        int(exports.reference),
        percent(exports.opennt, exports.reference),
        bar(&[(exports.opennt, "ok")], exports.reference),
        kernel.len(),
        bar(&[(works, "ok"), (kernel_partial, "part")], kernel.len()),
        report.tests.len() + suites,
        report.tests.len(),
        suites,
    ));

    let milestone = &report.milestone;
    let proof = milestone.test.map(|index| {
        let test = &report.tests[index];
        format!("<p class=\"small\">Prova: o teste {}.</p>{}", test_link(test, "testes.html"), capture_figure(test, ""))
    });
    body.push_str(&format!(
        "<section class=\"mile\" aria-label=\"Marco\"><div><h2>Marco atual</h2><p>{}</p>{}</div>\
         <div><h2>Próximo</h2><p>{}</p></div></section>\n",
        escape(&milestone.current),
        proof.unwrap_or_default(),
        escape(&milestone.next)
    ));

    let marks: String = report
        .runs
        .iter()
        .filter(|row| row.group == Group::Milestone)
        .map(|row| {
            format!(
                "<li><div class=\"head\"><h3><a href=\"o-que-roda.html#{}\">{}</a></h3>{}</div><p>{}</p></li>",
                run_anchor(row),
                escape(&row.name),
                run_chip(row.state, &row.reason),
                escape(&row.does)
            )
        })
        .collect();
    body.push_str(&format!(
        "<h2>Marcos</h2>\n<p class=\"muted\">Os que rodam são provados por um teste de boot; os outros ainda são alvos. A lista \
         completa, binário por binário e com as capturas de tela, está em <a href=\"o-que-roda.html\">O que roda</a>.</p>\n\
         <ul class=\"rows\">{marks}</ul>\n"
    ));

    let phases: String = report
        .phases
        .iter()
        .map(|phase| {
            format!(
                "<li id=\"fase-{}\"><span class=\"n\">Fase {}</span> <span>{}</span> {}</li>",
                anchor(&phase.number),
                escape(&phase.number),
                escape(&phase.name),
                phase_chip(&phase.state)
            )
        })
        .collect();
    body.push_str(&format!(
        "<h2>Fases</h2>\n<p class=\"muted\">O escopo de cada fase está no <a href=\"../ROADMAP.md\">roadmap</a>.</p>\n\
         <ul class=\"phases\">{phases}</ul>\n"
    ));

    body.push_str(&format!(
        "<h2>Experimentar</h2>\n<pre><code>cargo xtask run        # o shell numa janela do QEMU\n\
         cargo xtask test-all   # a validação inteira ({})\n\
         cargo xtask status     # regenera este site</code></pre>\n\
         <p class=\"small muted\">Precisa de Rust nightly e do QEMU; os binários da Microsoft vêm do Windows da máquina de \
         build e nunca entram no repositório.</p>\n",
        plural(report.tests.iter().filter(|test| !test.covered_by_suite).count() + suites, "execução", "execuções")
    ));

    html(Page {
        file: "index.html",
        title: "Início",
        description: "OpenNT: kernel compatível com o Windows NT em Rust que carrega os binários reais da Microsoft.",
        body,
    })
}
