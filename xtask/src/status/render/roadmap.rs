//! `docs/ROADMAP.md`: as fases e o estado de cada componente.

use super::super::{ComponentRow, Report, State};
use super::common::{int, live_tests, percent, state_label};

pub fn markdown(report: &Report) -> String {
    let total = &report.exports.total;
    let (done, partial, planned) = report.module_totals();
    let mut text = String::new();
    text.push_str("# Roadmap do OpenNT\n\n");
    text.push_str("<!-- Gerado por `cargo xtask status` a partir de docs/status/components.toml. Não edite à mão. -->\n\n");
    text.push_str(
        "O OpenNT avança em fases. Cada fase termina com o kernel compilando, iniciando no QEMU e passando nos testes \
         automáticos daquela parte.\n\n",
    );
    text.push_str(
        "**Estados dos componentes.** *Funciona*: o código existe e um teste automático de boot passa por ele. \
         *Parcial*: só uma parte existe, ou o código existe mas ainda não tem teste automático. *Planejado*: ainda não \
         implementado. *Fora do escopo*: fora do roadmap atual. A coluna *Teste automático* diz qual teste cobre o \
         item.\n\n",
    );
    text.push_str("| Fase | Tema | Estado |\n| --- | --- | --- |\n");
    for phase in &report.phases {
        text.push_str(&format!("| {} | {} | {} |\n", phase.number, phase.name, phase.state));
    }
    text.push_str(&format!(
        "\nHoje: **{} de {}** componentes funcionam; **{} de {}** módulos do plano têm código ({} completos e {} \
         parciais; isso mede código escrito, não testado); o kernel exporta **{} dos {}** nomes do `ntoskrnl.exe` do \
         Windows 10 22H2 ({}).\n\nDetalhes nas páginas [Componentes e drivers](site/componentes.html), \
         [Testes](site/testes.html), [Módulos do kernel](site/modulos.html) e [Exports do ntoskrnl](site/ntoskrnl.html).\n",
        report.count(State::Works),
        report.components.len(),
        int(done + partial),
        int(planned),
        int(done),
        int(partial),
        int(total.opennt),
        int(total.reference),
        percent(total.opennt, total.reference)
    ));
    let mut assigned = vec![false; report.components.len()];
    for phase in &report.phases {
        text.push_str(&format!("\n## Fase {} — {} ({})\n\n", phase.number, phase.name, phase.state));
        if !phase.scope.is_empty() {
            text.push_str(&format!("{}\n\n", phase.scope));
        }
        let rows: Vec<(usize, &ComponentRow)> =
            report.components.iter().enumerate().filter(|(_, row)| row.phase == phase.number).collect();
        if rows.is_empty() {
            continue;
        }
        text.push_str("| Componente | Estado | Teste automático |\n| --- | --- | --- |\n");
        for (index, row) in rows {
            assigned[index] = true;
            text.push_str(&roadmap_row(row, report));
        }
    }
    let others: Vec<&ComponentRow> =
        report.components.iter().enumerate().filter(|(index, _)| !assigned[*index]).map(|(_, row)| row).collect();
    if !others.is_empty() {
        text.push_str("\n## Sem fase definida\n\n| Componente | Estado | Teste automático |\n| --- | --- | --- |\n");
        for row in others {
            text.push_str(&roadmap_row(row, report));
        }
    }
    text
}

fn roadmap_row(row: &ComponentRow, report: &Report) -> String {
    let tests: Vec<String> = live_tests(row, report).iter().map(|&index| report.tests[index].title.clone()).collect();
    let tests = if tests.is_empty() { "—".to_string() } else { tests.join(", ") };
    format!("| {} | {} | {} |\n", row.name.replace('|', "\\|"), state_label(row.state), tests)
}
