//! HTML, SVG e Markdown das páginas de status. Tudo autocontido: CSS, SVG e
//! scripts inline, sem fontes nem recursos externos, para funcionar aberto
//! direto do disco (`file://`). As listas longas são paginadas por um script
//! pequeno; sem JavaScript, tudo aparece de uma vez. A saída não tem
//! data/hora, para que duas gerações com os mesmos dados produzam os mesmos
//! bytes.

mod common;
mod components;
mod exports;
mod modules;
mod overview;
mod roadmap;
mod svg;

use super::Report;

/// (arquivo, conteúdo) de cada saída: `.svg` vai para `docs/status/`, `.md`
/// para `docs/` e `.html` para `docs/site/`.
pub fn render(report: &Report) -> Vec<(String, String)> {
    let chart = svg::prefix_chart(&report.exports, "pc");
    let mut files = vec![
        ("selo-ntoskrnl.svg".to_string(), svg::export_badge(&report.exports, "selo-ntoskrnl")),
        ("selo-componentes.svg".to_string(), svg::component_badge(report, "selo-componentes")),
        ("ntoskrnl-por-prefixo.svg".to_string(), chart.clone()),
        ("index.html".to_string(), overview::page(report)),
        ("componentes.html".to_string(), components::page(report)),
        ("testes.html".to_string(), components::tests_page(report)),
        ("modulos.html".to_string(), modules::page(report)),
        ("ntoskrnl.html".to_string(), exports::page(report, &chart)),
        ("ROADMAP.md".to_string(), roadmap::markdown(report)),
    ];
    files.extend(exports::group_pages(report));
    files
}
