//! HTML, SVG e Markdown do site de status. Tudo autocontido: CSS, SVG e o
//! script de filtro inline, sem fontes, imagens externas nem CDN, para
//! funcionar aberto do disco (`file://`); as únicas imagens são as capturas
//! de `docs/site/capturas/`. Sem JavaScript, as listas aparecem inteiras.

mod badges;
mod components;
mod exports;
mod home;
mod page;
mod roadmap;
mod runs;
mod tests;

use super::Report;

/// (arquivo, conteúdo) de cada saída: `.svg` vai para `docs/status/`, `.md`
/// para `docs/` e `.html` para `docs/site/`.
pub fn render(report: &Report) -> Vec<(String, String)> {
    vec![
        ("selo-ntoskrnl.svg".to_string(), badges::export_badge(&report.exports)),
        ("selo-o-que-roda.svg".to_string(), badges::runs_badge(report)),
        ("ntoskrnl-por-prefixo.svg".to_string(), badges::prefix_chart(&report.exports)),
        ("index.html".to_string(), home::page(report)),
        ("o-que-roda.html".to_string(), runs::page(report)),
        ("componentes.html".to_string(), components::page(report)),
        ("ntoskrnl.html".to_string(), exports::page(report)),
        ("testes.html".to_string(), tests::page(report)),
        ("ROADMAP.md".to_string(), roadmap::markdown(report)),
    ]
}
