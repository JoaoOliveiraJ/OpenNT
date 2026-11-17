//! `testes.html`: como validar (`cargo xtask test-all`), as suítes
//! completas e cada `[[teste]]`, com o comando, o marcador e a captura.

use super::super::{Report, TestRow};
use super::page::{capture_figure, escape, filter_bar, first_sentence, html, int, plural, test_anchor, Page};

fn test_item(test: &TestRow) -> String {
    let mut chips = String::new();
    if test.expected_failure {
        chips.push_str("<span class=\"chip part\" title=\"espera_falha = true no components.toml\"><span aria-hidden=\"true\">◐</span> falha conhecida</span>");
    }
    if test.covered_by_suite {
        chips.push_str(" <span class=\"chip tag\" title=\"coberto_pela_suite = true: as suítes já conferem os marcadores\">nas suítes</span>");
    }
    if let Some(accelerator) = &test.accelerator {
        chips.push_str(&format!(
            " <span class=\"chip tag\" title=\"acelerador = &quot;{0}&quot; no components.toml: roda sempre neste acelerador\">{0}</span>",
            escape(accelerator)
        ));
    }
    let summary = first_sentence(&test.description);
    let details = if summary.len() + 2 < test.description.len() {
        format!("<details><summary>Descrição completa</summary><p class=\"more\">{}</p></details>", escape(&test.description))
    } else {
        String::new()
    };
    let location = match &test.location {
        Some(path) => format!(" <span class=\"muted\">(em <code>{}</code>)</span>", escape(path)),
        None => " <span class=\"chip no\">o marcador não aparece nas fontes</span>".to_string(),
    };
    let text = format!("{} {} {}", test.id, test.title, test.description).to_lowercase();
    format!(
        "<li id=\"{anchor}\" data-state=\"{state}\" data-text=\"{text}\"><div class=\"test\"><div>\
         <div class=\"head\"><h3><code>{id}</code> {title}</h3>{chips}</div><p>{summary}</p>{details}\
         <p class=\"small\">Marcador: <code>{marker}</code>{location}</p><pre><code>{command}</code></pre></div>{shot}</div></li>",
        anchor = test_anchor(test),
        state = if test.expected_failure { "part" } else { "ok" },
        text = escape(&text),
        id = escape(&test.id),
        title = escape(&test.title),
        summary = escape(summary),
        marker = escape(&test.marker),
        command = escape(&test.command),
        shot = capture_figure(test, ""),
    )
}

pub fn page(report: &Report) -> String {
    let suites = crate::test_all::SUITE_CPUS;
    let expected = report.tests.iter().filter(|test| test.expected_failure).count();
    let covered = report.tests.iter().filter(|test| test.covered_by_suite).count();
    let captured = report.tests.iter().filter(|test| test.capture.is_some()).count();
    let mut body = String::new();
    body.push_str(&format!(
        "<h1>Testes</h1>\n<p class=\"lead\">Cada teste inicia o OpenNT no QEMU, com os binários da Microsoft no volume, e \
         espera frases combinadas (marcadores) na saída serial; um pânico, uma exceção de kernel ou um STOP reprova. São \
         {} completas e {}.</p>\n",
        plural(suites.len(), "suíte", "suítes"),
        plural(report.tests.len(), "cenário", "cenários"),
    ));
    body.push_str(&format!(
        "<h2>Validar tudo</h2>\n<pre><code>cargo xtask test-all</code></pre>\n<ul>\
         <li>Roda as suítes completas de autoteste (com 4 CPUs e com 1) e cada teste abaixo, em paralelo, cada um na própria \
         pasta <code>build/test-all/&lt;id&gt;</code>.</li>\
         <li>Monta cada imagem uma vez por configuração de build, sem dois builds no mesmo <code>target/</code>, e só sobe \
         um QEMU quando a memória livre do host o cobre.</li>\
         <li>No fim, mostra a tabela com o resultado e, de cada falha, o trecho da serial que a explica; sai com erro se \
         algum teste falhar.</li>\
         <li>Roda no WHPX (a virtualização do processador) quando o QEMU e a máquina o têm, senão no TCG; um teste com \
         <code>acelerador = \"tcg\"</code> no <code>components.toml</code> roda sempre no TCG.</li>\
         <li>{} marcado{} <code>espera_falha</code> (falha conhecida) fica fora da rodada padrão e roda com \
         <code>--espera-falha</code>, sem reprovar a rodada; {} com <code>coberto_pela_suite</code> só roda{} à parte \
         com <code>--only</code>. <code>--all</code> roda todos.</li></ul>\n\
         <p>Opções: <code>--only=ID,...</code>, <code>--skip=ID,...</code>, <code>--jobs=N</code>, <code>--repeat=N</code> \
         (falhas intermitentes), <code>--suite</code> ou <code>--no-suite</code>, <code>--espera-falha</code>, \
         <code>--all</code>, <code>--accel=tcg|whpx</code>, <code>--keep</code>, <code>--cpu-friendly</code> e \
         <code>--list</code>.</p>\n\
         <h2>Um teste só</h2>\n<pre><code>cargo xtask test-all --only=ntfs\ncargo xtask test-boot SMSS_CSRSS_OK 300000 \
         --initial-process=smss --smp=1</code></pre>\n\
         <h2>Capturas de tela</h2>\n<pre><code>cargo xtask capturas\ncargo xtask capturas --only=win32k-display</code></pre>\n\
         <p>Roda cada teste como o <code>test-all</code> e, no fim dele (passando ou não), grava a tela do QEMU em \
         <code>docs/site/capturas/&lt;id&gt;.png</code> pelo <code>screendump</code> do QMP, com a data e o resultado no PNG. \
         Depois, <code>cargo xtask status</code> regenera as páginas. Hoje {} de {} testes têm captura.</p>\n",
        if expected == 1 { "Um teste".to_string() } else { format!("{} testes", int(expected)) },
        if expected == 1 { "" } else { "s" },
        if covered == 1 { "um".to_string() } else { int(covered) },
        if covered == 1 { "" } else { "m" },
        int(captured),
        int(report.tests.len()),
    ));
    let markers: Vec<String> = report.suite_markers.iter().map(|marker| format!("<code>{}</code>", escape(marker))).collect();
    let suite_names: Vec<String> = suites.iter().map(|cpus| format!("<code>suite-smp{cpus}</code>")).collect();
    body.push_str(&format!(
        "<h2>Suítes completas</h2>\n<p>{} rodam todas as suítes de autoteste dentro do kernel, com {} CPUs, e conferem, \
         nesta ordem: {}.</p>\n",
        suite_names.join(" e "),
        suites.iter().map(|cpus| cpus.to_string()).collect::<Vec<_>>().join(" e com "),
        markers.join(", ")
    ));
    body.push_str(&format!("<h2>Os {} cenários</h2>\n", int(report.tests.len())));
    let states = [
        ("", format!("Todos ({})", report.tests.len())),
        ("ok", format!("Passam ({})", report.tests.len() - expected)),
        ("part", format!("Falha conhecida ({expected})")),
    ];
    body.push_str(&filter_bar("cenarios", "Buscar", &states));
    let items: String = report.tests.iter().map(test_item).collect();
    body.push_str(&format!("\n<ul class=\"rows\" id=\"cenarios\">{items}</ul>\n"));
    html(Page {
        file: "testes.html",
        title: "Testes",
        description: "Como validar o OpenNT (cargo xtask test-all) e cada teste de boot, com o comando, o marcador e a tela.",
        body,
    })
}
