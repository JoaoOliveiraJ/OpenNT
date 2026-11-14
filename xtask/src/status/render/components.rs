//! `componentes.html` (componentes e drivers por categoria) e `testes.html`
//! (os testes automáticos de boot e o que cada um cobre).

use super::super::{ComponentRow, Report, State, STATES};
use super::assets::FILTER_SCRIPT;
use super::common::{
    anchor, code, component_anchor, escape, filter_bar, html_page, icon_tile, int, live_tests, meter, notes, page_head,
    page_name, path_code, percent, phase_label, plural, search_text, section, stat, state_badge, state_icon, state_key,
    state_label, state_legend, test_link, Toggle,
};

/// Categoria cujos itens são binários do próprio Windows (.sys/.dll),
/// carregados sem recompilar.
pub const WINDOWS_DRIVERS: &str = "Drivers do Windows";

fn state_order(state: State) -> usize {
    STATES.iter().position(|candidate| *candidate == state).unwrap_or(STATES.len())
}

/// "3 funcionam · 2 parciais · 4 planejados" (só os estados presentes).
pub fn state_counts(rows: &[&ComponentRow]) -> String {
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

/// Barra dos componentes: verde o que funciona, amarelo o parcial, sobre o total.
pub fn component_meter(rows: &[&ComponentRow], label: bool) -> String {
    let works = rows.iter().filter(|row| row.state == State::Works).count();
    let partial = rows.iter().filter(|row| row.state == State::InDevelopment).count();
    let text = format!("{}, de {}", state_counts(rows), plural(rows.len(), "componente", "componentes"));
    meter(&[(works, "ok"), (partial, "part")], rows.len(), label.then_some(text.as_str()))
}

/// A linha "Verificação" do item: o que garante que ele funciona.
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

fn component_item(row: &ComponentRow, report: &Report) -> String {
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
    let tile_class = match row.state {
        State::Works => "good",
        State::InDevelopment => "",
        _ => "dim",
    };
    format!(
        "<article class=\"item\" id=\"{id}\" data-item data-state=\"{key}\" data-text=\"{text}\">{tile}\
         <div class=\"item-head\"><h4>{name}</h4>{badge}</div><p class=\"item-desc\">{description}</p>\
         <dl class=\"meta\">{facts}</dl>{notes}</article>",
        id = component_anchor(row),
        key = state_key(row.state),
        text = search_text(&[&row.name, &row.description, &row.category]),
        tile = icon_tile(&row.icon, tile_class),
        name = escape(&row.name),
        badge = state_badge(row.state),
        description = escape(&row.description),
        notes = notes(&row.notes),
    )
}

pub fn category_anchor(name: &str) -> String {
    format!("cat-{}", anchor(name))
}

fn summary_table(report: &Report) -> String {
    let mut table = String::from(
        "<div class=\"table-wrap\"><table><caption class=\"sr-only\">Componentes por categoria e estado</caption><thead><tr>\
         <th scope=\"col\">Categoria</th><th scope=\"col\" class=\"num\">Funciona</th><th scope=\"col\" class=\"num\">Parcial</th>\
         <th scope=\"col\" class=\"num\">Planejado</th><th scope=\"col\" class=\"num\">Fora do escopo</th>\
         <th scope=\"col\" class=\"num\">Total</th><th scope=\"col\">Andamento</th></tr></thead><tbody>",
    );
    let cell = |rows: &[&ComponentRow], state: State, tag: &str| {
        let value = rows.iter().filter(|row| row.state == state).count();
        if value == 0 {
            format!("<{tag} class=\"num muted\">—</{tag}>")
        } else {
            format!("<{tag} class=\"num\">{}</{tag}>", int(value))
        }
    };
    for category in &report.categories {
        let rows: Vec<&ComponentRow> = report.components.iter().filter(|row| row.category == category.name).collect();
        table.push_str(&format!(
            "<tr><th scope=\"row\"><a href=\"#{}\">{}</a></th>{}{}{}{}<td class=\"num\"><strong>{}</strong></td>\
             <td class=\"bar\">{}</td></tr>",
            category_anchor(&category.name),
            escape(&category.name),
            cell(&rows, State::Works, "td"),
            cell(&rows, State::InDevelopment, "td"),
            cell(&rows, State::Planned, "td"),
            cell(&rows, State::OutOfScope, "td"),
            int(rows.len()),
            component_meter(&rows, false)
        ));
    }
    let all: Vec<&ComponentRow> = report.components.iter().collect();
    table.push_str(&format!(
        "</tbody><tfoot><tr><th scope=\"row\">Total</th>{}{}{}{}<th class=\"num\">{}</th><td class=\"bar\">{}</td></tr></tfoot>\
         </table></div>",
        cell(&all, State::Works, "th"),
        cell(&all, State::InDevelopment, "th"),
        cell(&all, State::Planned, "th"),
        cell(&all, State::OutOfScope, "th"),
        int(all.len()),
        component_meter(&all, false)
    ));
    table
}

/// Os três níveis de evidência, do mais fraco ao mais forte.
pub fn evidence_levels(windows_link: &str) -> String {
    format!(
        "<h3>Como sabemos se algo funciona</h3><ol class=\"levels\">\
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
    let all: Vec<&ComponentRow> = report.components.iter().collect();
    let mut body = page_head(
        &[],
        "Componentes e drivers",
        "Componentes e drivers",
        "Cada parte do OpenNT: o que faz, se já funciona e como isso é verificado.",
        "<p class=\"sub\">Um <strong>componente</strong> é uma parte do sistema que se descreve numa frase: o \
         gerenciador de memória, um driver, o shell. Só aparece como <em>Funciona</em> o que tem código no repositório \
         <em>e</em> um teste automático de boot que passa por ele.</p>",
        &format!(
            "{}{}{}{}",
            stat(
                "Funcionam",
                &int(works),
                &format!("de {}", int(total)),
                &component_meter(&all, true),
                &format!("{} de {} componentes têm código e teste automático ({})", int(works), int(total), percent(works, total))
            ),
            stat("Parciais", &int(report.count(State::InDevelopment)), "", "", "parte pronta, ou código ainda sem teste"),
            stat("Planejados", &int(report.count(State::Planned)), "", "", "ainda sem código; entram numa fase do roadmap"),
            stat("Testes de boot", &int(report.tests_found()), "", "", "rodam o kernel no QEMU e conferem a saída"),
        ),
    );

    body.push_str(&section("resumo", "Por categoria", "", &summary_table(report)));

    let windows_link = if report.categories.iter().any(|category| category.name == WINDOWS_DRIVERS) {
        format!("<a href=\"#{}\">{}</a>", category_anchor(WINDOWS_DRIVERS), escape(WINDOWS_DRIVERS))
    } else {
        escape(WINDOWS_DRIVERS)
    };
    body.push_str(&section(
        "legenda",
        "O que significa cada estado",
        "",
        &format!("{}{}", state_legend(), evidence_levels(&windows_link)),
    ));

    let toggles: Vec<Toggle> = STATES
        .iter()
        .map(|state| (state_key(*state), state_label(*state), report.count(*state), state_icon(*state)))
        .filter(|toggle| toggle.2 > 0)
        .collect();
    let jump: String = report
        .categories
        .iter()
        .map(|category| {
            let count = report.components.iter().filter(|row| row.category == category.name).count();
            format!(
                "<li><a href=\"#{}\">{} <span class=\"n\">{}</span></a></li>",
                category_anchor(&category.name),
                escape(&category.name),
                int(count)
            )
        })
        .collect();
    let mut list = format!(
        "{}<nav aria-label=\"Categorias\"><ul class=\"jump\">{jump}</ul></nav>",
        filter_bar("lista", "Filtrar componentes", "Buscar por nome ou descrição", &toggles, total, ("componente", "componentes"))
    );
    for category in &report.categories {
        let mut rows: Vec<&ComponentRow> = report.components.iter().filter(|row| row.category == category.name).collect();
        rows.sort_by_key(|row| state_order(row.state));
        let items: String = rows.iter().map(|row| component_item(row, report)).collect();
        let description =
            if category.description.is_empty() { String::new() } else { format!("<p class=\"intro\">{}</p>", escape(&category.description)) };
        list.push_str(&format!(
            "<section class=\"category\" id=\"{id}\" data-section aria-labelledby=\"{id}-t\"><div class=\"category-head\">\
             {tile}<h3 id=\"{id}-t\">{name}</h3><p class=\"counts\">{counts}</p></div>{description}<div class=\"items\">{items}\
             </div></section>",
            id = category_anchor(&category.name),
            tile = icon_tile(&category.icon, "sm"),
            name = escape(&category.name),
            counts = state_counts(&rows),
        ));
    }
    body.push_str(&section(
        "lista",
        "Todos os componentes",
        "Agrupados por categoria; em cada uma, primeiro o que funciona.",
        &list,
    ));

    if !report.warnings.is_empty() {
        let items: String = report.warnings.iter().map(|warning| format!("<li>{}</li>", escape(warning))).collect();
        body.push_str(&section(
            "avisos",
            "Avisos da geração",
            "Dados que o gerador não conseguiu conferir. Corrija <code>docs/status/components.toml</code> e gere de novo.",
            &format!("<ul class=\"small\">{items}</ul>"),
        ));
    }
    html_page(
        "componentes.html",
        &format!("{} · OpenNT", page_name("componentes.html")),
        "O que cada componente e driver do OpenNT faz, se já funciona e qual teste automático o verifica.",
        &body,
        &[FILTER_SCRIPT],
    )
}

// ---- testes.html -----------------------------------------------------------------

fn test_item(index: usize, report: &Report) -> String {
    let test = &report.tests[index];
    let (tile, status, location) = match &test.location {
        Some(path) => (icon_tile("check", "good"), "<span class=\"chip ok\">marcador encontrado no código</span>", path_code(path)),
        None => (
            icon_tile("check", "dim"),
            "<span class=\"chip bad\">marcador não encontrado</span>",
            "<span class=\"warn\">o marcador não aparece nas fontes Rust; os componentes que dependem só deste teste \
             perdem o estado Funciona</span>"
                .to_string(),
        ),
    };
    let covered = report.covered_by(index);
    let covers = if covered.is_empty() {
        "<span class=\"muted\">nenhum componente cita este teste</span>".to_string()
    } else {
        let items: String = covered
            .iter()
            .map(|row| {
                format!(
                    "<li><a href=\"componentes.html#{}\" title=\"{}\">{}{}<span class=\"sr-only\"> ({})</span></a></li>",
                    component_anchor(row),
                    state_label(row.state),
                    state_icon(row.state),
                    escape(&row.name),
                    state_label(row.state).to_lowercase()
                )
            })
            .collect();
        format!("<ul class=\"refs\">{items}</ul>")
    };
    format!(
        "<article class=\"item\" id=\"t-{id}\">{tile}<div class=\"item-head\"><h3>{title}</h3>{status}</div>\
         <p class=\"item-desc\">{description}</p><dl class=\"meta\"><dt>Marcador</dt><dd>{marker}</dd><dt>Onde</dt>\
         <dd>{location}</dd><dt>Comando</dt><dd><pre><code>{command}</code></pre></dd><dt>Cobre</dt><dd>{covers}</dd></dl>\
         </article>",
        id = anchor(&test.id),
        title = escape(&test.title),
        description = escape(&test.description),
        marker = code(&test.marker),
        command = escape(&test.command),
    )
}

fn tests_index(report: &Report) -> String {
    let rows: String = report
        .tests
        .iter()
        .enumerate()
        .map(|(index, test)| {
            let covered = report.covered_by(index).len();
            let found = if test.location.is_some() {
                "<span class=\"mark yes\">encontrado</span>"
            } else {
                "<span class=\"mark no warn\">não encontrado</span>"
            };
            format!(
                "<tr><th scope=\"row\"><a href=\"#t-{}\">{}</a></th><td class=\"wrap-code\">{}</td><td>{found}</td>\
                 <td class=\"num\">{}</td></tr>",
                anchor(&test.id),
                escape(&test.title),
                code(&test.marker),
                int(covered)
            )
        })
        .collect();
    format!(
        "<div class=\"table-wrap\"><table><caption class=\"sr-only\">Índice dos testes de boot</caption><thead><tr>\
         <th scope=\"col\">Teste</th><th scope=\"col\">Marcador</th><th scope=\"col\">No código</th>\
         <th scope=\"col\" class=\"num\">Componentes</th></tr></thead><tbody>{rows}</tbody></table></div>"
    )
}

pub fn tests_page(report: &Report) -> String {
    let total = report.components.len();
    let covered = report.components.iter().filter(|row| !live_tests(row, report).is_empty()).count();
    let windows: Vec<&ComponentRow> = report.components.iter().filter(|row| row.category == WINDOWS_DRIVERS).collect();
    let windows_tested = windows.iter().filter(|row| row.state == State::Works).count();
    let mut body = page_head(
        &[],
        "Testes",
        "Testes automáticos",
        "Como o OpenNT confere que o que está implementado funciona.",
        "<p class=\"sub\">Cada teste compila o kernel, inicia uma máquina virtual no QEMU e espera uma frase combinada \
         (o <em>marcador</em>) na saída serial. Os testes rodam com <code>cargo xtask test-boot</code>.</p>",
        &format!(
            "{}{}{}",
            stat(
                "Testes de boot",
                &int(report.tests_found()),
                &format!("de {} listados", int(report.tests.len())),
                "",
                "marcador conferido no código"
            ),
            stat(
                "Componentes cobertos",
                &int(covered),
                &format!("de {}", int(total)),
                &meter(&[(covered, "ok")], total, Some(&format!("{} de {} componentes cobertos", int(covered), int(total)))),
                &format!("{} de {} têm pelo menos um teste ({})", int(covered), int(total), percent(covered, total))
            ),
            stat(
                "Drivers do Windows testados",
                &int(windows_tested),
                &format!("de {}", int(windows.len())),
                &meter(
                    &[(windows_tested, "ok")],
                    windows.len(),
                    Some(&format!("{} de {} drivers do Windows testados", int(windows_tested), int(windows.len())))
                ),
                "o binário do próprio Windows carrega e roda no teste"
            ),
        ),
    );

    body.push_str(&section(
        "como-funciona",
        "Como funciona um teste de boot",
        "",
        "<div class=\"grid two\"><div class=\"card\"><h3>Passo a passo</h3><ol class=\"steps-list\">\
         <li>O <code>xtask</code> compila o kernel. Com <code>--kernel-test-scope=all</code>, inclui as suítes de \
         autoteste, que rodam dentro do próprio kernel durante o boot.</li>\
         <li>Inicia o QEMU com a imagem de disco e lê a saída serial.</li>\
         <li>O teste <strong>passa</strong> quando o marcador aparece dentro do tempo limite.</li>\
         <li>O teste <strong>falha</strong> se aparecer um pânico (<code>*** PANIC</code>), uma exceção \
         (<code>*** EXCECAO</code>) ou <code>SELFTEST FALHOU</code>, ou se o tempo acabar.</li></ol></div>\
         <div class=\"card\"><h3>O que esta página confere</h3><p>O gerador destas páginas não roda os testes: ele \
         confere que o marcador de cada teste aparece no código-fonte e mostra em que arquivo. Se um marcador some, o \
         teste fica marcado em vermelho e os componentes que dependem só dele deixam de aparecer como \
         <em>Funciona</em>.</p><p>O <em>Autoteste do kernel</em> roda as suítes de <code>kernel/src/ntos/test/</code>; \
         a página <a href=\"modulos.html#s-ntos-test\">Módulos do kernel</a> mostra quais módulos elas usam \
         diretamente.</p></div></div>",
    ));

    let items: String = (0..report.tests.len()).map(|index| test_item(index, report)).collect();
    body.push_str(&section(
        "lista",
        "Os testes",
        "Em <em>Cobre</em>, os componentes que citam o teste em <code>docs/status/components.toml</code>.",
        &format!("{}<div class=\"items\">{items}</div>", tests_index(report)),
    ));

    body.push_str(&section(
        "rodar",
        "Rodar os testes",
        "",
        "<pre><code>cargo xtask test-boot</code></pre><p class=\"small\">Sem argumentos, espera o marcador do boot \
         completo. O comando de cada teste está no item dele; os drivers do Windows são copiados da máquina de build \
         e nunca entram no repositório.</p>",
    ));
    html_page(
        "testes.html",
        "Testes automáticos · OpenNT",
        "Os testes automáticos de boot do OpenNT: o que cada um verifica e quais componentes cobre.",
        &body,
        &[],
    )
}
