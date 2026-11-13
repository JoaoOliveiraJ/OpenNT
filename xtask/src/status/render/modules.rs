//! `modulos.html`: o plano de módulos do kernel, por subsistema, com o que
//! já tem código.

use super::super::{ModuleRow, Report, SubsystemRow, MODULE_STATES};
use super::common::{
    anchor, big_stat, code, escape, filter_bar, hero, html_page, icon_tile, int, meter, module_badge, module_key,
    module_label, module_meaning, module_tag, percent, phase_label, plural, ring_stat, section, CHEVRON, PAGER_SCRIPT,
};

/// Linhas por página na tabela de módulos de cada subsistema.
const MODULES_PER_PAGE: usize = 20;

/// Áreas da página, na ordem: (título, descrição).
const AREAS: &[(&str, &str)] = &[
    (
        "Núcleo do NT (ntos)",
        "O executive e o kernel propriamente dito: objetos, memória, processos, I/O, Registro, segurança, a tabela de \
         exports e a sequência de boot.",
    ),
    ("Hardware e nanokernel", "A camada mais baixa: interrupções, canais de mensagens, ACPI, PCI e firmware."),
    ("Drivers internos", "Drivers escritos em Rust que fazem parte do próprio OpenNT."),
    ("Aplicações e diagnósticos", "O shell e módulos de diagnóstico."),
    ("Autotestes", "Suítes de teste que rodam dentro do kernel; aqui cada módulo planejado é uma suíte."),
];

fn area_of(folder: &str) -> usize {
    if folder == "ntos/test" {
        4
    } else if folder.starts_with("ntos/") {
        0
    } else if folder == "nano" || folder == "hal" || folder.starts_with("hal/") {
        1
    } else if folder.starts_with("drivers/") {
        2
    } else {
        3
    }
}

/// Pasta comum dos arquivos Rust, omitida na tabela para encurtar as linhas.
const RUST_ROOT: &str = "kernel/src/";

/// Uma linha da tabela. Enxuta de propósito (a página tem centenas): o nome
/// vem sem a pasta do subsistema, o estado é um marcador só de CSS e a busca
/// usa o texto da própria linha.
fn module_row(module: &ModuleRow, folder: &str, tests_column: bool) -> String {
    let note = if module.note.is_empty() { String::new() } else { format!("<div class=\"note\">{}</div>", escape(&module.note)) };
    let rust = match &module.rust {
        Some(path) => code(path.strip_prefix(RUST_ROOT).unwrap_or(path)),
        None => "<span class=\"muted\">—</span>".to_string(),
    };
    let tested = match (tests_column, module.tested) {
        (false, _) => "",
        (true, true) => "<td class=\"yes\">sim</td>",
        (true, false) => "<td class=\"no\">—</td>",
    };
    format!(
        "<tr data-item data-state=\"{key}\"><td><code>{name}</code>{note}</td><td>{tag}</td><td>{rust}</td>{tested}</tr>",
        key = module_key(module.state),
        name = escape(module.name.strip_prefix(folder).and_then(|rest| rest.strip_prefix('/')).unwrap_or(&module.name)),
        tag = module_tag(module.state),
    )
}

fn subsystem_block(row: &SubsystemRow, report: &Report) -> String {
    let unit = if row.is_tests { ("suíte", "suítes") } else { ("módulo", "módulos") };
    let short = if row.planned == 0 {
        "fora da conta".to_string()
    } else {
        format!("<strong>{}</strong>/{} · {}", int(row.covered()), int(row.planned), percent(row.covered(), row.planned))
    };
    let mut facts = Vec::new();
    if row.planned > 0 {
        facts.push(format!(
            "<strong>{}</strong> de {} com código ({})",
            int(row.covered()),
            plural(row.planned, unit.0, unit.1),
            percent(row.covered(), row.planned)
        ));
        if row.partial > 0 {
            facts.push(format!("{} parcia{}", int(row.partial), if row.partial == 1 { "l" } else { "is" }));
        }
        facts.push(plural(row.pending(), "pendente", "pendentes"));
        if !row.is_tests {
            facts.push(plural(row.tested(), "usado por autotestes", "usados por autotestes"));
        }
    }
    if row.out_of_scope() > 0 {
        facts.push(format!("{} fora da conta", int(row.out_of_scope())));
    }
    let phase = if row.phase.is_empty() { String::new() } else { format!("{} · ", phase_label(&row.phase, &report.phases)) };
    let notes = if row.notes.is_empty() { String::new() } else { format!("<p class=\"note\">{}</p>", escape(&row.notes)) };
    let tests_column = !row.is_tests;
    let header = format!(
        "<th>{} (em {})</th><th>Estado</th><th>Arquivo Rust (em {})</th>{}",
        if tests_column { "Módulo planejado" } else { "Suíte planejada" },
        code(&format!("{}/", row.folder)),
        code(RUST_ROOT),
        if tests_column { "<th>Autoteste</th>" } else { "" }
    );
    let rows: String = row.modules.iter().map(|module| module_row(module, &row.folder, tests_column)).collect();
    format!(
        "<details class=\"subsys\" id=\"s-{id}\" data-section><summary>{tile}<div><div class=\"sname\">{name}{folder}</div>\
         <div class=\"sdesc\">{description}</div></div>{meter}<div class=\"snums\">{short}</div>{CHEVRON}</summary>\
         <div class=\"inner\"><p class=\"small\">{phase}{facts}</p>{notes}<div class=\"scroll\" \
         data-paginate=\"{MODULES_PER_PAGE}\"><table><thead><tr>{header}</tr></thead><tbody>{rows}</tbody></table></div>\
         </div></details>",
        id = anchor(&row.folder),
        tile = icon_tile(&row.icon, if row.covered() == 0 { "dim sm" } else { "sm" }),
        name = escape(&row.name),
        folder = code(&row.folder),
        description = escape(&row.description),
        meter = meter(row.done, row.partial, row.planned, &percent(row.covered(), row.planned)),
        facts = facts.join(" · "),
    )
}

pub fn page(report: &Report) -> String {
    let (done, partial, planned) = report.module_totals();
    let pending = planned - done - partial;
    let suites = report.subsystems.iter().filter(|row| row.is_tests).map(|row| row.planned).sum::<usize>();
    let out: usize = report.subsystems.iter().map(SubsystemRow::out_of_scope).sum();
    let mut body = hero(
        "Plano do kernel",
        "Módulos do kernel",
        "Quanto do plano de código do kernel já foi escrito, subsistema por subsistema.",
        "Um <strong>módulo</strong> é uma unidade planejada de código do kernel, com nome no formato \
         <code>pasta/nome</code>: por exemplo, <code>ntos/ob/handle_table</code> é a tabela de handles do \
         gerenciador de objetos. Um módulo conta quando o arquivo Rust dele existe. Isso mede quanto código já foi \
         escrito, <strong>não</strong> se ele funciona; para isso, veja os <a href=\"testes.html\">testes</a> e os \
         <a href=\"componentes.html\">componentes</a>.",
        &format!(
            "{}{}{}{}",
            ring_stat(
                done + partial,
                planned,
                "Módulos com código",
                &format!("{} de {} planejados ({} completos e {} parciais)", int(done + partial), int(planned), int(done), int(partial))
            ),
            big_stat(&int(pending), "Pendentes", "ainda sem arquivo Rust"),
            big_stat(&int(report.modules_tested()), "Usados por autotestes", "importados diretamente por uma suíte de teste"),
            big_stat(&int(suites), "Suítes de autoteste", "planejadas; entram no total de módulos"),
        ),
    );

    let mut legend = String::from("<div class=\"explain\"><div class=\"legend\">");
    for state in MODULE_STATES {
        legend.push_str(&format!("<div>{}<span>{}</span></div>", module_badge(*state), module_meaning(*state)));
    }
    legend.push_str(&format!(
        "</div><p class=\"small\"><strong>Autoteste: sim</strong> quer dizer que uma suíte de \
         <code>kernel/src/ntos/test/</code> importa o arquivo do módulo diretamente. Os demais podem ser exercitados \
         de forma indireta pelos <a href=\"testes.html\">testes de boot</a>. A barra de cada subsistema mostra os \
         módulos com código em azul e os parciais em amarelo. {} ficam fora de todas as contas.</p>\
         <p class=\"small\">De onde vêm os dados: a lista de módulos é <code>docs/status/modulos-planejados.txt</code>; \
         o gerador procura um arquivo Rust de mesma pasta e mesmo nome em <code>kernel/src</code>, ou o arquivo \
         declarado em <code>[correspondencias]</code> no <code>components.toml</code>. Parciais e fora da conta são \
         declarados nas tabelas <code>[parciais]</code> e <code>[fora_do_escopo]</code>.</p></div>",
        plural(out, "módulo descartado", "módulos descartados")
    ));
    body.push_str(&section("legenda", "Como ler", "O que significa cada estado", "", &legend));

    let states: Vec<(&str, &str)> = MODULE_STATES.iter().map(|state| (module_key(*state), module_label(*state))).collect();
    let total_modules: usize = report.subsystems.iter().map(|row| row.modules.len()).sum();
    let mut list = filter_bar("módulo ou arquivo, ex.: handle_table", &states, total_modules, ("módulo listado", "módulos listados"));
    list.push_str(
        "<p class=\"small muted\">Clique num subsistema para ver os módulos. A busca abre os subsistemas que têm \
         resultados.</p>",
    );
    for (index, (title, description)) in AREAS.iter().enumerate() {
        let rows: Vec<&SubsystemRow> = report.subsystems.iter().filter(|row| area_of(&row.folder) == index).collect();
        if rows.is_empty() {
            continue;
        }
        let covered: usize = rows.iter().map(|row| row.covered()).sum();
        let planned: usize = rows.iter().map(|row| row.planned).sum();
        let blocks: String = rows.iter().map(|row| subsystem_block(row, report)).collect();
        list.push_str(&format!(
            "<div class=\"area\" id=\"area-{}\" data-group><h3>{} <span class=\"muted\">{} · {} de {} com \
             código</span></h3><p class=\"small muted\">{}</p>{blocks}</div>",
            anchor(title),
            escape(title),
            plural(rows.len(), "subsistema", "subsistemas"),
            int(covered),
            plural(planned, "módulo", "módulos"),
            escape(description),
        ));
    }
    body.push_str(&section("subsistemas", "Por dentro", "Subsistemas", "", &list));
    html_page(
        "modulos.html",
        "Módulos do kernel · OpenNT",
        "O plano de módulos do kernel do OpenNT, por subsistema, e quais já têm código.",
        &body,
        &[PAGER_SCRIPT],
    )
}
