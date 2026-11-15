//! `ntoskrnl.html`: quantos exports do `ntoskrnl.exe` do Windows 10 22H2 o
//! kernel do OpenNT também exporta, por prefixo, com a lista inteira numa
//! página só (um grupo fechado por prefixo; a busca abre os que casam).

use super::super::{ExportRow, Report};
use super::page::{anchor, escape, filter_bar, html, int, percent, Page};

/// O que cada grupo de prefixo cobre, numa linha.
pub fn prefix_label(bucket: &str) -> &'static str {
    match bucket {
        "Ke" => "núcleo: threads, sincronização, DPC/APC",
        "Ke*Irql" => "nível de interrupção (IRQL)",
        "Mm" => "memória virtual e física",
        "Ob" => "gerenciador de objetos",
        "Ps" => "processos e threads",
        "Io" => "entrada e saída, drivers, IRPs",
        "Ex" => "executive: pool, locks, work items",
        "Rtl" => "biblioteca de runtime",
        "Se" => "segurança e tokens",
        "Zw/Nt" => "serviços do sistema",
        "Cm" => "Registro",
        "Po" => "energia",
        "Hal" => "abstração de hardware",
        "Wmi/Etw" => "instrumentação e rastreamento",
        "Fs/FsRtl" => "apoio a sistemas de arquivos",
        "Kd" => "depurador de kernel",
        "Inbv" => "vídeo do boot",
        _ => "cache, transações, CRT e outros",
    }
}

fn names(rows: &[&ExportRow], class: &str) -> String {
    let items: String = rows
        .iter()
        .map(|row| {
            let data = if row.data { " <span class=\"muted\">(dado)</span>" } else { "" };
            format!("<li>{}{data}</li>", escape(&row.name))
        })
        .collect();
    format!("<ul class=\"names {class}\">{items}</ul>")
}

fn mini(part: usize, whole: usize) -> String {
    let width = if whole == 0 { 0.0 } else { part as f64 * 100.0 / whole as f64 };
    format!("<span class=\"mini\" aria-hidden=\"true\"><i style=\"width:{width:.1}%\"></i></span>")
}

pub fn page(report: &Report) -> String {
    let exports = &report.exports;
    let total = &exports.total;
    let version = exports.file_version.as_deref().map(|version| format!(" (versão {version})")).unwrap_or_default();
    let mut body = String::new();
    body.push_str(&format!(
        "<h1>Exports do ntoskrnl</h1>\n<p class=\"lead\">Dos <b>{}</b> nomes que o <code>ntoskrnl.exe</code> do Windows 10 22H2 \
         exporta aos drivers{version}, o kernel do OpenNT também exporta <b>{}</b> ({}): {} de {} funções e {} de {} variáveis. \
         Cada um tem a semântica da rotina do NT; um driver que importa um nome que falta não carrega.</p>\n",
        int(total.reference),
        int(total.opennt),
        percent(total.opennt, total.reference),
        int(total.functions_opennt),
        int(total.functions),
        int(total.opennt - total.functions_opennt),
        int(total.reference - total.functions),
    ));

    let rows: String = exports
        .buckets
        .iter()
        .filter(|(_, tally)| tally.reference > 0)
        .map(|(bucket, tally)| {
            format!(
                "<tr><th scope=\"row\"><a href=\"#p-{}\">{}</a></th><td>{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td>\
                 <td class=\"num\">{}</td><td>{}</td></tr>",
                anchor(bucket),
                escape(bucket),
                prefix_label(bucket),
                int(tally.opennt),
                int(tally.reference),
                percent(tally.opennt, tally.reference),
                mini(tally.opennt, tally.reference)
            )
        })
        .collect();
    body.push_str(&format!(
        "<h2>Por prefixo</h2>\n<div class=\"table\"><table><caption class=\"muted small\" style=\"text-align:left;padding:8px 14px\">\
         Exports do OpenNT sobre os do Windows, por prefixo do nome</caption><thead><tr><th scope=\"col\">Prefixo</th>\
         <th scope=\"col\">Área</th><th scope=\"col\" class=\"num\">OpenNT</th><th scope=\"col\" class=\"num\">Windows</th>\
         <th scope=\"col\" class=\"num\">%</th><th scope=\"col\"><span class=\"muted\">cobertura</span></th></tr></thead>\
         <tbody>{rows}</tbody><tfoot><tr><th scope=\"row\">Total</th><td></td><td class=\"num\">{}</td><td class=\"num\">{}</td>\
         <td class=\"num\">{}</td><td>{}</td></tr></tfoot></table></div>\n",
        int(total.opennt),
        int(total.reference),
        percent(total.opennt, total.reference),
        mini(total.opennt, total.reference)
    ));

    body.push_str(
        "<h2>Todos os nomes</h2>\n<p class=\"muted\">Um grupo por prefixo, com o que o OpenNT exporta e o que falta. A busca \
         filtra os nomes e abre os grupos que casam.</p>\n",
    );
    body.push_str(&filter_bar("nomes", "Buscar export", &[]));
    body.push_str("\n<div id=\"nomes\" class=\"groups\">\n");
    for (bucket, tally) in exports.buckets.iter().filter(|(_, tally)| tally.reference > 0) {
        let present: Vec<&ExportRow> = exports.rows.iter().filter(|row| row.bucket == *bucket && row.opennt).collect();
        let missing: Vec<&ExportRow> = exports.rows.iter().filter(|row| row.bucket == *bucket && !row.opennt).collect();
        let mut inner = String::new();
        if !present.is_empty() {
            inner.push_str(&format!("<h4>O OpenNT exporta ({})</h4>{}", int(present.len()), names(&present, "")));
        }
        if !missing.is_empty() {
            inner.push_str(&format!("<h4>Faltam ({})</h4>{}", int(missing.len()), names(&missing, "missing")));
        }
        body.push_str(&format!(
            "<details id=\"p-{}\" data-group><summary><b>{}</b> <span>{} de {} ({})</span> {} <span class=\"muted small\">{}</span>\
             </summary>{inner}</details>\n",
            anchor(bucket),
            escape(bucket),
            int(tally.opennt),
            int(tally.reference),
            percent(tally.opennt, tally.reference),
            mini(tally.opennt, tally.reference),
            prefix_label(bucket)
        ));
    }
    body.push_str("</div>\n");
    if !exports.opennt_extra.is_empty() {
        let extra: String = exports.opennt_extra.iter().map(|name| format!("<li>{}</li>", escape(name))).collect();
        body.push_str(&format!(
            "<h2>Só no OpenNT</h2>\n<p class=\"muted\">{} nomes que o kernel exporta e o <code>ntoskrnl.exe</code> de referência \
             não exporta.</p>\n\
             <details><summary>Ver os nomes</summary><ul class=\"names\">{extra}</ul></details>\n",
            int(exports.opennt_extra.len())
        ));
    }
    body.push_str(
        "<p class=\"small muted\">A lista de referência fica em <code>docs/status/ntoskrnl-exports.def</code> (só os nomes, \
         lidos do <code>ntoskrnl.exe</code> pelo <code>cargo xtask status --reference</code>); a do OpenNT sai das tabelas de \
         exports do próprio kernel.</p>\n",
    );
    html(Page {
        file: "ntoskrnl.html",
        title: "Exports do ntoskrnl",
        description: "Quantos exports do ntoskrnl.exe do Windows 10 22H2 o kernel do OpenNT oferece, por prefixo, com busca.",
        body,
    })
}
