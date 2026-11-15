//! `docs/ROADMAP.md`: as fases, o marco atual e o estado dos componentes de
//! cada fase.

use super::super::{Report, RunState};
use super::page::{int, percent};

fn state_word(state: super::super::State) -> &'static str {
    super::page::state_label(state)
}

pub fn markdown(report: &Report) -> String {
    let mut text = String::from(
        "# Roadmap do OpenNT\n\n<!-- Gerado por `cargo xtask status` a partir de docs/status/components.toml. Não edite à mão. -->\n\n\
         O OpenNT avança em fases. Cada fase termina com o kernel compilando, iniciando no QEMU e passando nos testes \
         automáticos daquela parte.\n\n",
    );
    text.push_str("| Fase | Tema | Estado |\n| --- | --- | --- |\n");
    for phase in &report.phases {
        text.push_str(&format!("| {} | {} | {} |\n", phase.number, phase.name, phase.state));
    }
    let exports = &report.exports.total;
    text.push_str(&format!(
        "\n**Marco atual.** {}\n\n**Próximo.** {}\n\nHoje: **{} de {}** binários da Microsoft rodam ({} parciais); o kernel \
         exporta **{} dos {}** nomes do `ntoskrnl.exe` do Windows 10 22H2 ({}). Detalhes em [O que roda](site/o-que-roda.html), \
         [Componentes](site/componentes.html), [Exports](site/ntoskrnl.html) e [Testes](site/testes.html).\n",
        report.milestone.current,
        report.milestone.next,
        report.binaries(RunState::Runs),
        report.binaries_total(),
        report.binaries(RunState::Partial),
        int(exports.opennt),
        int(exports.reference),
        percent(exports.opennt, exports.reference),
    ));
    for phase in &report.phases {
        text.push_str(&format!("\n## Fase {} — {} ({})\n\n{}\n", phase.number, phase.name, phase.state, phase.scope));
        let rows: Vec<_> = report.components.iter().filter(|row| row.phase == phase.number).collect();
        if rows.is_empty() {
            continue;
        }
        text.push_str("\n| Componente | Estado | Teste automático |\n| --- | --- | --- |\n");
        for row in rows {
            let tests: Vec<&str> = row.tests.iter().map(|&index| report.tests[index].id.as_str()).collect();
            let tests = if tests.is_empty() { "—".to_string() } else { tests.join(", ") };
            text.push_str(&format!("| {} | {} | {} |\n", row.name, state_word(row.state), tests));
        }
    }
    text
}
