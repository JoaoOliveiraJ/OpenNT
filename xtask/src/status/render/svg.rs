//! Selos (no estilo shields.io) e o gráfico de exports por prefixo. Também
//! são gravados em `docs/status/` para o README.

use super::super::{ExportReport, Report, State};
use super::common::{escape, int, percent};
use super::exports::prefix_info;

const FONT: &str = "system-ui,-apple-system,Segoe UI,Roboto,sans-serif";

/// Largura aproximada de um texto em Verdana 11px (só para o espaçamento
/// dos selos; o `textLength` garante que o texto caiba).
fn badge_text_width(text: &str) -> f64 {
    text.chars()
        .map(|character| match character {
            ' ' => 3.9,
            '.' | ',' | ':' | ';' | '|' | 'i' | 'l' | 'j' | '!' | '\'' => 3.4,
            'f' | 't' | 'r' | '(' | ')' => 4.6,
            'm' | 'w' => 10.5,
            'M' | 'W' => 11.5,
            '%' => 11.9,
            'A'..='Z' => 7.6,
            '0'..='9' => 7.0,
            _ => 6.7,
        })
        .sum()
}

/// Selo com segmentos (texto, cor de fundo).
fn badge(id: &str, title: &str, parts: &[(String, &str)]) -> String {
    let widths: Vec<f64> = parts.iter().map(|(text, _)| badge_text_width(text).ceil() + 12.0).collect();
    let total: f64 = widths.iter().sum();
    let mut body = String::new();
    let mut x = 0.0;
    for ((_, color), width) in parts.iter().zip(&widths) {
        body.push_str(&format!("<rect x=\"{x}\" width=\"{width}\" height=\"20\" fill=\"{color}\"/>"));
        x += width;
    }
    body.push_str(&format!(
        "<rect width=\"{total}\" height=\"20\" fill=\"url(#{id}-g)\"/><g fill=\"#fff\" text-anchor=\"middle\" \
         font-family=\"Verdana,Geneva,DejaVu Sans,sans-serif\" font-size=\"11\">"
    ));
    let mut x = 0.0;
    for ((text, _), width) in parts.iter().zip(&widths) {
        let center = x + width / 2.0;
        let length = width - 12.0;
        let text = escape(text);
        body.push_str(&format!(
            "<text x=\"{center}\" y=\"15\" fill=\"#010101\" fill-opacity=\".3\" textLength=\"{length}\" \
             lengthAdjust=\"spacingAndGlyphs\">{text}</text><text x=\"{center}\" y=\"14\" textLength=\"{length}\" \
             lengthAdjust=\"spacingAndGlyphs\">{text}</text>"
        ));
        x += width;
    }
    body.push_str("</g>");
    format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{total}\" height=\"20\" viewBox=\"0 0 {total} 20\" \
         role=\"img\" aria-label=\"{title}\"><title>{title}</title><linearGradient id=\"{id}-g\" x2=\"0\" y2=\"100%\">\
         <stop offset=\"0\" stop-color=\"#bbb\" stop-opacity=\".1\"/><stop offset=\"1\" stop-opacity=\".1\"/>\
         </linearGradient><clipPath id=\"{id}-r\"><rect width=\"{total}\" height=\"20\" rx=\"3\"/></clipPath>\
         <g clip-path=\"url(#{id}-r)\">{body}</g></svg>\n",
        title = escape(title)
    )
}

pub fn export_badge(report: &ExportReport, id: &str) -> String {
    let total = &report.total;
    let value = format!("OpenNT {} de {} ({})", int(total.opennt), int(total.reference), percent(total.opennt, total.reference));
    let title = format!(
        "Nomes exportados pelo ntoskrnl.exe do Windows 10 22H2 que o kernel do OpenNT também exporta: {} de {} ({})",
        int(total.opennt),
        int(total.reference),
        percent(total.opennt, total.reference)
    );
    badge(id, &title, &[("exports ntoskrnl".into(), "#555"), (value, "#2a78d6")])
}

pub fn component_badge(report: &Report, id: &str) -> String {
    let value = format!("{} de {} funcionam", report.count(State::Works), report.components.len());
    let title = format!(
        "Componentes e drivers do OpenNT implementados e cobertos por teste automático de boot: {} de {}",
        report.count(State::Works),
        report.components.len()
    );
    badge(id, &title, &[("componentes".into(), "#555"), (value, "#006300")])
}

/// Barra horizontal com a ponta direita arredondada (4px) e a base reta.
fn bar_path(x: f64, y: f64, width: f64, height: f64) -> String {
    if width <= 0.0 {
        return String::new();
    }
    let radius = 4.0f64.min(width).min(height / 2.0);
    format!(
        "M{x:.1} {y:.1}h{h:.2}a{r} {r} 0 0 1 {r} {r}v{v}a{r} {r} 0 0 1 -{r} {r}h-{h:.2}z",
        h = width - radius,
        r = radius,
        v = height - 2.0 * radius
    )
}

/// Gráfico por prefixo: o comprimento de cada barra é o número de exports
/// do prefixo no Windows; a parte azul é o que o OpenNT também exporta.
pub fn prefix_chart(report: &ExportReport, id: &str) -> String {
    let width = 760.0;
    let label_x = 16.0;
    let bars_x = 258.0;
    let bars_width = 340.0;
    let text_x = bars_x + bars_width + 12.0;
    let row_height = 36.0;
    let top = 96.0;
    let largest = report.buckets.iter().map(|(_, tally)| tally.reference).max().unwrap_or(1).max(1);
    let height = top + report.buckets.len() as f64 * row_height + 12.0;
    let total = &report.total;

    let mut body = String::new();
    body.push_str(&format!(
        "<rect class=\"{id}-bg\" width=\"{width}\" height=\"{height}\" rx=\"10\"/>\
         <text class=\"{id}-t\" x=\"{label_x}\" y=\"30\">Exports do ntoskrnl.exe por prefixo</text>\
         <text class=\"{id}-s\" x=\"{label_x}\" y=\"51\">Windows 10 22H2: {} nomes. O kernel do OpenNT também exporta {} ({}); \
         faltam {}.</text>",
        int(total.reference),
        int(total.opennt),
        percent(total.opennt, total.reference),
        int(total.missing())
    ));
    body.push_str(&format!(
        "<rect class=\"{id}-a\" x=\"{label_x}\" y=\"64\" width=\"12\" height=\"12\" rx=\"3\"/>\
         <text class=\"{id}-v\" x=\"{}\" y=\"74\">o OpenNT também exporta</text>\
         <rect class=\"{id}-k\" x=\"{}\" y=\"64\" width=\"12\" height=\"12\" rx=\"3\"/>\
         <text class=\"{id}-v\" x=\"{}\" y=\"74\">falta (barra inteira = nomes do prefixo no Windows)</text>",
        label_x + 18.0,
        label_x + 190.0,
        label_x + 208.0
    ));
    for (index, (name, tally)) in report.buckets.iter().enumerate() {
        let y = top + index as f64 * row_height;
        let info = prefix_info(name);
        let track = bars_width * tally.reference as f64 / largest as f64;
        let covered = if tally.reference == 0 { 0.0 } else { track * tally.opennt as f64 / tally.reference as f64 };
        let value = format!("{} de {} · {}", int(tally.opennt), int(tally.reference), percent(tally.opennt, tally.reference));
        body.push_str(&format!(
            "<g><title>{name} ({short}): o OpenNT exporta {value}; faltam {missing}</title>\
             <text class=\"{id}-l\" x=\"{label_x}\" y=\"{name_y}\">{name}</text>\
             <text class=\"{id}-m\" x=\"{label_x}\" y=\"{short_y}\">{short}</text>\
             <path class=\"{id}-k\" d=\"{track_path}\"/><path class=\"{id}-a\" d=\"{covered_path}\"/>\
             <text class=\"{id}-v\" x=\"{text_x}\" y=\"{value_y}\">{value}</text></g>",
            name = escape(name),
            short = escape(info.short),
            missing = int(tally.missing()),
            name_y = y + 15.0,
            short_y = y + 29.0,
            track_path = bar_path(bars_x, y + 9.0, track.max(2.0), 12.0),
            covered_path = bar_path(bars_x, y + 9.0, covered, 12.0),
            value_y = y + 19.0,
            value = escape(&value),
        ));
    }
    let style = format!(
        ".{id}-bg{{fill:#fcfcfb}}.{id}-t{{font:600 16px {FONT};fill:#0b0b0b}}\
         .{id}-s,.{id}-v{{font:12px {FONT};fill:#52514e}}.{id}-v{{font-variant-numeric:tabular-nums}}\
         .{id}-l{{font:600 13px {FONT};fill:#0b0b0b}}.{id}-m{{font:11px {FONT};fill:#6b6a65}}\
         .{id}-k{{fill:#e8e7e1}}.{id}-a{{fill:#2a78d6}}\
         @media (prefers-color-scheme:dark){{.{id}-bg{{fill:#1a1a19}}.{id}-t,.{id}-l{{fill:#f0efec}}\
         .{id}-s,.{id}-v{{fill:#c3c2b7}}.{id}-m{{fill:#9d9b94}}.{id}-k{{fill:#2c2c2a}}.{id}-a{{fill:#3987e5}}}}"
    );
    let summary = format!(
        "Exports do ntoskrnl.exe do Windows 10 22H2 por prefixo: {} nomes no total; o kernel do OpenNT também exporta {} \
         ({}); faltam {}.",
        int(total.reference),
        int(total.opennt),
        percent(total.opennt, total.reference),
        int(total.missing())
    );
    format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width}\" height=\"{height}\" viewBox=\"0 0 {width} {height}\" \
         role=\"img\" aria-labelledby=\"{id}-title\"><title id=\"{id}-title\">{}</title><style>{style}</style>{body}</svg>\n",
        escape(&summary)
    )
}
