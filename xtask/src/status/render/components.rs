//! `componentes.html` (componentes e drivers por categoria) e `testes.html`
//! (os testes automáticos de boot e o que cada um cobre).

use super::super::{ComponentRow, Report, State, STATES};
use super::common::{
    anchor, big_stat, code, component_anchor, escape, filter_bar, hero, icon_tile, int, live_tests, html_page, path_code,
    phase_label, plural, ring_stat, search_text, section, state_badge, state_key, state_label, state_legend, test_link,
    PAGER_SCRIPT,
};

/// Categoria cujos itens são binários do próprio Windows (.sys/.dll),
/// carregados sem recompilar.
pub const WINDOWS_DRIVERS: &str = "Drivers do Windows";

/// Cartões por página em cada categoria.
const COMPONENTS_PER_PAGE: usize = 6;
const TESTS_PER_PAGE: usize = 12;

fn state_order(state: State) -> usize {
    STATES.iter().position(|candidate| *candidate == state).unwrap_or(STATES.len())
}

/// "3 funcionam · 2 parciais · 4 planejados" (só os estados presentes).
fn state_counts(rows: &[&ComponentRow]) -> String {
    let count = |state: State| rows.iter().filter(|row| row.state == state).count();
    let mut parts = Vec::new();
    for (state, one, many) in [
        (State::Works, "funciona", "funcionam"),
        (State::InDevelopment, "parcial", "parciais"),
        (State::Planned, "planejado", "planejados"),
        (State::OutOfScope, "fora do escopo", "fora do escopo"),
    ] {
        let value = count(state);
        if value > 0 {
            parts.push(plural(value, one, many));
        }
    }
    parts.join(" · ")
}

/// A linha "Verificação" do cartão: o que garante que o item funciona.
fn verification(row: &ComponentRow, report: &Report) -> String {
    let live = live_tests(row, report);
    let broken: Vec<String> = row
        .tests
        .iter()
        .filter(|&&index| report.tests[index].location.is_none())
        .map(|&index| {
            format!("{} <span class=\"warn\">(marcador não encontrado no código)</span>", escape(&report.tests[index].title))
        })
        .collect();
    let mut text = if !live.is_empty() {
        let links: Vec<String> = live.iter().map(|&index| test_link(index, report, "testes.html")).collect();
        let scope = if row.state == State::InDevelopment { " (cobre a parte pronta)" } else { "" };
        let binary = if row.category == WINDOWS_DRIVERS && row.state == State::Works {
            "<br><span class=\"small muted\">O teste carrega o binário do próprio Windows, sem recompilar.</span>"
        } else {
            ""
        };
        format!("<span class=\"verified\">Teste automático{scope}:</span> {}{binary}", links.join(", "))
    } else {
        match row.state {
            State::Planned | State::OutOfScope => "<span class=\"unverified\">Ainda não implementado.</span>".to_string(),
            _ if row.notes.is_empty() => "<span class=\"unverified\">Nenhum teste automático cobre este item ainda.</span>".to_string(),
            _ => "<span class=\"unverified\">Nenhum teste automático cobre este item ainda;</span> as notas abaixo dizem \
                  como ele foi verificado e o que falta."
                .to_string(),
        }
    };
    if !broken.is_empty() {
        text.push_str(&format!("<br>{}", broken.join(", ")));
    }
    text
}

fn component_card(row: &ComponentRow, report: &Report) -> String {
    let mut facts = format!("<dt>Verificação</dt><dd>{}</dd>", verification(row, report));
    if !row.phase.is_empty() {
        facts.push_str(&format!("<dt>Fase</dt><dd>{}</dd>", phase_label(&row.phase, &report.phases)));
    }
    if !row.paths.is_empty() {
        let paths: Vec<String> = row
            .paths
            .iter()
            .map(|path| {
                if path.exists {
                    path_code(&path.path)
                } else {
                    format!("{} <span class=\"warn\">(não encontrado)</span>", path_code(&path.path))
                }
            })
            .collect();
        facts.push_str(&format!("<dt>Código</dt><dd>{}</dd>", paths.join(" ")));
    }
    let notes = if row.notes.is_empty() { String::new() } else { format!("<p class=\"note\">{}</p>", escape(&row.notes)) };
    let tile_class = match row.state {
        State::Works => "good",
        State::InDevelopment => "",
        _ => "dim",
    };
    format!(
        "<article class=\"card lift component\" id=\"{id}\" data-item data-state=\"{key}\" data-text=\"{text}\">\
         <div class=\"head\">{tile}<div class=\"title\"><h3>{name}</h3>{badge}</div></div><p>{description}</p>\
         <dl class=\"facts\">{facts}</dl>{notes}</article>",
        id = component_anchor(row),
        key = state_key(row.state),
        text = search_text(&[&row.name, &row.description, &row.category]),
        tile = icon_tile(&row.icon, tile_class),
        name = escape(&row.name),
        badge = state_badge(row.state),
        description = escape(&row.description),
    )
}

fn category_anchor(name: &str) -> String {
    format!("cat-{}", anchor(name))
}

fn summary_table(report: &Report) -> String {
    let mut table = String::from(
        "<div class=\"table-card scroll\"><table><thead><tr><th>Categoria</th><th class=\"num\">Funciona</th>\
         <th class=\"num\">Parcial</th><th class=\"num\">Planejado</th><th class=\"num\">Fora do escopo</th>\
         <th class=\"num\">Total</th></tr></thead><tbody>",
    );
    let cell = |rows: &[&ComponentRow], state: State| {
        let value = rows.iter().filter(|row| row.state == state).count();
        if value == 0 {
            "<td class=\"num muted\">—</td>".to_string()
        } else {
            format!("<td class=\"num\">{}</td>", int(value))
        }
    };
    for category in &report.categories {
        let rows: Vec<&ComponentRow> = report.components.iter().filter(|row| row.category == category.name).collect();
        table.push_str(&format!(
            "<tr><td><a href=\"#{}\">{}</a></td>{}{}{}{}<td class=\"num\"><strong>{}</strong></td></tr>",
            category_anchor(&category.name),
            escape(&category.name),
            cell(&rows, State::Works),
            cell(&rows, State::InDevelopment),
            cell(&rows, State::Planned),
            cell(&rows, State::OutOfScope),
            int(rows.len())
        ));
    }
    let all: Vec<&ComponentRow> = report.components.iter().collect();
    table.push_str(&format!(
        "</tbody><tfoot><tr><th>Total</th>{}{}{}{}<th class=\"num\">{}</th></tr></tfoot></table></div>",
        cell(&all, State::Works).replace("td", "th"),
        cell(&all, State::InDevelopment).replace("td", "th"),
        cell(&all, State::Planned).replace("td", "th"),
        cell(&all, State::OutOfScope).replace("td", "th"),
        int(all.len())
    ));
    table
}

/// Os três níveis de evidência, do mais fraco ao mais forte.
pub fn evidence_levels(windows_link: &str) -> String {
    format!(
        "<h3>Como sabemos se algo funciona</h3><ol class=\"steps\">\
         <li><strong>Código no repositório.</strong> Os arquivos citados em <em>Código</em> existem; o gerador confere \
         cada caminho. Só isso não prova que funciona.</li>\
         <li><strong>Teste automático.</strong> Um teste de boot inicia o kernel numa máquina virtual (QEMU) e confere \
         a saída. A linha <em>Verificação</em> diz qual teste cobre o item; a página <a href=\"testes.html\">Testes</a> \
         explica cada um.</li>\
         <li><strong>Binário do Windows.</strong> Nos {windows_link}, o teste carrega o próprio arquivo <code>.sys</code> \
         ou <code>.dll</code> do Windows, sem recompilar nem modificar. É a prova mais forte de compatibilidade.</li></ol>"
    )
}

pub fn page(report: &Report) -> String {
    let total = report.components.len();
    let works = report.count(State::Works);
    let mut body = hero(
        "Estado do sistema",
        "Componentes e drivers",
        "Cada parte do OpenNT: o que faz, se já funciona e como isso é verificado.",
        "Um <strong>componente</strong> é uma parte do sistema que se descreve numa frase: o gerenciador de memória, \
         um driver, o shell. Só aparece como <em>Funciona</em> o que tem código no repositório <em>e</em> um teste \
         automático de boot que passa por ele.",
        &format!(
            "{}{}{}{}",
            ring_stat(works, total, "Funcionam", &format!("{} de {} componentes têm código e teste automático", int(works), int(total))),
            big_stat(&int(report.count(State::InDevelopment)), "Parciais", "parte pronta, ou código ainda sem teste"),
            big_stat(&int(report.count(State::Planned)), "Planejados", "ainda sem código; entram numa fase do roadmap"),
            big_stat(&int(report.tests_found()), "Testes de boot", "rodam o kernel no QEMU e conferem a saída"),
        ),
    );

    body.push_str(&section("resumo", "Resumo", "Por categoria", "", &summary_table(report)));

    let windows_link = if report.categories.iter().any(|category| category.name == WINDOWS_DRIVERS) {
        format!("<a href=\"#{}\">{}</a>", category_anchor(WINDOWS_DRIVERS), escape(WINDOWS_DRIVERS))
    } else {
        escape(WINDOWS_DRIVERS)
    };
    body.push_str(&section(
        "legenda",
        "Como ler",
        "O que significa cada estado",
        "",
        &format!("<div class=\"explain\">{}{}</div>", state_legend(), evidence_levels(&windows_link)),
    ));

    let states: Vec<(&str, &str)> = STATES.iter().map(|state| (state_key(*state), state_label(*state))).collect();
    body.push_str(&format!(
        "<section class=\"block\" id=\"lista\"><p class=\"eyebrow\">Lista</p><h2>Todos os componentes</h2>\
         <p class=\"lead\">Agrupados por categoria; em cada uma, primeiro o que funciona. Listas longas são divididas \
         em páginas.</p>{}</section>",
        filter_bar("nome ou descrição", &states, total, ("componente", "componentes"))
    ));

    for category in &report.categories {
        let mut rows: Vec<&ComponentRow> = report.components.iter().filter(|row| row.category == category.name).collect();
        rows.sort_by_key(|row| state_order(row.state));
        let cards: String = rows.iter().map(|row| component_card(row, report)).collect();
        let description =
            if category.description.is_empty() { String::new() } else { format!("<p class=\"lead\">{}</p>", escape(&category.description)) };
        body.push_str(&format!(
            "<section class=\"block\" id=\"{id}\" data-section><div class=\"category-head\">{tile}<div>\
             <p class=\"eyebrow\">Categoria</p><h2>{name}</h2><p class=\"counts\">{counts}</p></div></div>{description}\
             <div class=\"grid\" data-paginate=\"{COMPONENTS_PER_PAGE}\">{cards}</div></section>",
            id = category_anchor(&category.name),
            tile = icon_tile(&category.icon, ""),
            name = escape(&category.name),
            counts = state_counts(&rows),
        ));
    }

    if !report.warnings.is_empty() {
        let items: String = report.warnings.iter().map(|warning| format!("<li>{}</li>", escape(warning))).collect();
        body.push_str(&section(
            "avisos",
            "Geração",
            "Avisos",
            "Dados que o gerador não conseguiu conferir. Corrija <code>docs/status/components.toml</code> e gere de novo.",
            &format!("<ul class=\"small\">{items}</ul>"),
        ));
    }
    html_page(
        "componentes.html",
        "Componentes e drivers · OpenNT",
        "O que cada componente e driver do OpenNT faz, se já funciona e qual teste automático o verifica.",
        &body,
        &[PAGER_SCRIPT],
    )
}

// ---- testes.html -----------------------------------------------------------------

fn test_card(index: usize, report: &Report) -> String {
    let test = &report.tests[index];
    let (tile, status, location) = match &test.location {
        Some(path) => (
            icon_tile("check", "good"),
            "<span class=\"state small-state\">marcador encontrado no código</span>",
            path_code(path),
        ),
        None => (
            icon_tile("check", "dim"),
            "<span class=\"state small-state warn\">marcador não encontrado</span>",
            "<span class=\"warn\">o marcador não aparece nas fontes Rust; os componentes que dependem só deste teste \
             perdem o estado Funciona</span>"
                .to_string(),
        ),
    };
    let covered = report.covered_by(index);
    let covers = if covered.is_empty() {
        "<span class=\"muted\">nenhum componente cita este teste</span>".to_string()
    } else {
        let items: Vec<String> = covered
            .iter()
            .map(|row| {
                format!(
                    "<a href=\"componentes.html#{}\">{}</a> <span class=\"muted\">({})</span>",
                    component_anchor(row),
                    escape(&row.name),
                    state_label(row.state).to_lowercase()
                )
            })
            .collect();
        items.join(", ")
    };
    format!(
        "<article class=\"card component\" id=\"t-{id}\" data-item><div class=\"head\">{tile}<div class=\"title\">\
         <h3>{title}</h3>{status}</div></div><p>{description}</p><dl class=\"facts\"><dt>Marcador</dt><dd>{marker}</dd>\
         <dt>Onde</dt><dd>{location}</dd><dt>Comando</dt><dd>{command}</dd><dt>Cobre</dt><dd>{covers}</dd></dl></article>",
        id = anchor(&test.id),
        title = escape(&test.title),
        description = escape(&test.description),
        marker = code(&test.marker),
        command = code(&test.command),
    )
}

pub fn tests_page(report: &Report) -> String {
    let total = report.components.len();
    let covered = report.components.iter().filter(|row| !live_tests(row, report).is_empty()).count();
    let windows: Vec<&ComponentRow> = report.components.iter().filter(|row| row.category == WINDOWS_DRIVERS).collect();
    let windows_tested = windows.iter().filter(|row| row.state == State::Works).count();
    let mut body = hero(
        "Qualidade",
        "Testes automáticos",
        "Como o OpenNT confere que o que está implementado funciona.",
        "Cada teste compila o kernel, inicia uma máquina virtual no QEMU e espera uma frase combinada (o \
         <em>marcador</em>) na saída serial. Os testes rodam com <code>cargo xtask test-boot</code>.",
        &format!(
            "{}{}{}",
            big_stat(&int(report.tests_found()), "Testes de boot", &format!("de {} listados; marcador conferido no código", int(report.tests.len()))),
            ring_stat(covered, total, "Componentes cobertos", &format!("{} de {} têm pelo menos um teste", int(covered), int(total))),
            big_stat(
                &format!("{} de {}", int(windows_tested), int(windows.len())),
                "Drivers do Windows testados",
                "o binário do próprio Windows carrega e roda no teste"
            ),
        ),
    );

    body.push_str(&section(
        "como-funciona",
        "Para começar",
        "Como funciona um teste de boot",
        "",
        "<div class=\"grid\"><div class=\"explain\"><h3>Passo a passo</h3><ol class=\"steps\">\
         <li>O <code>xtask</code> compila o kernel. Com <code>--kernel-test-scope=all</code>, inclui as suítes de \
         autoteste, que rodam dentro do próprio kernel durante o boot.</li>\
         <li>Inicia o QEMU com a imagem de disco e lê a saída serial.</li>\
         <li>O teste <strong>passa</strong> quando o marcador aparece dentro do tempo limite.</li>\
         <li>O teste <strong>falha</strong> se aparecer um pânico (<code>*** PANIC</code>), uma exceção \
         (<code>*** EXCECAO</code>) ou <code>SELFTEST FALHOU</code>, ou se o tempo acabar.</li></ol></div>\
         <div class=\"explain\"><h3>O que esta página confere</h3><p>O gerador destas páginas não roda os testes: ele \
         confere que o marcador de cada teste aparece no código-fonte e mostra em que arquivo. Se um marcador some, o \
         teste fica marcado em vermelho e os componentes que dependem só dele deixam de aparecer como \
         <em>Funciona</em>.</p><p>O <em>Autoteste do kernel</em> roda as suítes de <code>kernel/src/ntos/test/</code>; \
         a página <a href=\"modulos.html#s-ntos-test\">Módulos do kernel</a> mostra quais módulos elas usam \
         diretamente.</p></div></div>",
    ));

    let cards: String = (0..report.tests.len()).map(|index| test_card(index, report)).collect();
    body.push_str(&section(
        "lista",
        "Lista",
        "Os testes",
        "Em <em>Cobre</em>, os componentes que citam o teste em <code>docs/status/components.toml</code>.",
        &format!("<div class=\"grid\" data-paginate=\"{TESTS_PER_PAGE}\">{cards}</div>"),
    ));

    body.push_str(&section(
        "rodar",
        "Na prática",
        "Rodar os testes",
        "",
        "<pre><code>cargo xtask test-boot</code></pre><p class=\"small\">Sem argumentos, espera o marcador do boot \
         completo. O comando de cada teste está no cartão dele; os drivers do Windows são copiados da máquina de build \
         e nunca entram no repositório.</p>",
    ));
    html_page(
        "testes.html",
        "Testes automáticos · OpenNT",
        "Os testes automáticos de boot do OpenNT: o que cada um verifica e quais componentes cobre.",
        &body,
        &[PAGER_SCRIPT],
    )
}
