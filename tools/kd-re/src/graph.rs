//! A aba Grafo: o grafo de fluxo da função (blocos básicos com a
//! desmontagem, arestas verdadeira em verde, falsa em vermelho e salto
//! incondicional em azul), o bloco corrente destacado. Arrastar move,
//! Ctrl+roda aproxima, clique duplo numa linha vai à aba CPU.

use std::sync::Arc;

use eframe::egui::{self, Align2, Color32, FontId, Pos2, Rect, RichText, Sense, Stroke, TextStyle, Ui, Vec2};
use kd_client::analysis::cfg::EdgeKind;

use crate::app::*;
use crate::backend::{GraphView, Request, Status};

/// Espaço entre camadas e entre colunas (pontos, antes do zoom).
const LAYER_GAP: f32 = 46.0;
const COLUMN_GAP: f32 = 40.0;
const PADDING: f32 = 6.0;

/// As posições dos blocos (canto superior esquerdo e tamanho) num plano
/// sem zoom.
fn block_rects(graph: &GraphView, glyph: f32, line_height: f32) -> Vec<Rect> {
    let sizes: Vec<Vec2> = graph
        .blocks
        .iter()
        .map(|block| {
            let longest = block.lines.iter().map(|line| line.text.chars().count() + 10).max().unwrap_or(10).min(72);
            Vec2::new(longest as f32 * glyph + 2.0 * PADDING, block.lines.len().max(1) as f32 * line_height + 2.0 * PADDING)
        })
        .collect();
    let layers = graph.layout.layers.max(1);
    let columns = graph.layout.width.max(1);
    let mut layer_height = vec![0.0f32; layers];
    let mut column_width = vec![0.0f32; columns];
    for (index, size) in sizes.iter().enumerate() {
        let layer = graph.layout.layer.get(index).copied().unwrap_or(0).min(layers - 1);
        let column = graph.layout.column.get(index).copied().unwrap_or(0).min(columns - 1);
        layer_height[layer] = layer_height[layer].max(size.y);
        column_width[column] = column_width[column].max(size.x);
    }
    let mut layer_top = vec![0.0f32; layers];
    for layer in 1..layers {
        layer_top[layer] = layer_top[layer - 1] + layer_height[layer - 1] + LAYER_GAP;
    }
    let mut column_left = vec![0.0f32; columns];
    for column in 1..columns {
        column_left[column] = column_left[column - 1] + column_width[column - 1] + COLUMN_GAP;
    }
    sizes
        .iter()
        .enumerate()
        .map(|(index, size)| {
            let layer = graph.layout.layer.get(index).copied().unwrap_or(0).min(layers - 1);
            let column = graph.layout.column.get(index).copied().unwrap_or(0).min(columns - 1);
            // Centrado na coluna.
            let left = column_left[column] + (column_width[column] - size.x) / 2.0;
            Rect::from_min_size(Pos2::new(left, layer_top[layer]), *size)
        })
        .collect()
}

pub(crate) fn graph_tab(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    ui.horizontal(|ui| {
        let stopped = state.status == Status::Stopped;
        if ui.add_enabled(stopped, egui::Button::new("Grafo do RIP")).clicked() {
            state.requests.push(Request::Graph(String::new()));
        }
        if ui.add_enabled(stopped && state.selected_code.is_some(), egui::Button::new("Grafo da linha escolhida")).clicked() {
            if let Some(address) = state.selected_code {
                state.requests.push(Request::Graph(format!("{address:#x}")));
            }
        }
        if ui.button("Ajustar").clicked() {
            state.graph_fit = u64::MAX;
        }
        if ui.button("−").clicked() {
            state.graph_zoom = (state.graph_zoom / 1.25).max(0.15);
        }
        if ui.button("+").clicked() {
            state.graph_zoom = (state.graph_zoom * 1.25).min(3.0);
        }
        if let Some(graph) = &snapshot.graph {
            ui.label(RichText::new(format!("{}  {} blocos{}", graph.name, graph.blocks.len(), if graph.truncated { " (cortado no limite)" } else { "" })).strong());
        }
    });
    let Some(graph) = snapshot.graph.clone() else {
        hint(ui, "sem grafo: G na aba CPU (ou os botões acima) monta o grafo da função");
        return;
    };
    if let Some(error) = &graph.error {
        ui.label(RichText::new(error).color(colors.red));
        return;
    }
    let font_size = ui.text_style_height(&TextStyle::Monospace) - 1.0;
    let base_font = FontId::monospace(font_size);
    let glyph = ui.fonts_mut(|fonts| fonts.glyph_width(&base_font, '0'));
    let line_height = font_size + 3.0;
    let rects = block_rects(&graph, glyph, line_height);
    let bounds = rects.iter().fold(Rect::NOTHING, |all, rect| all.union(*rect));
    let (canvas, response) = ui.allocate_exact_size(ui.available_size(), Sense::click_and_drag());
    // Ajusta à área quando chega um grafo novo (ou com "Ajustar").
    let key = graph.function ^ ((graph.blocks.len() as u64) << 48) ^ graph.focus.rotate_left(17);
    if state.graph_fit != key && bounds.is_positive() {
        let zoom = (canvas.width() / (bounds.width() + 40.0)).min(canvas.height() / (bounds.height() + 40.0)).clamp(0.2, 1.0);
        state.graph_zoom = zoom;
        // O bloco corrente à vista: centrado em x, perto do topo.
        let anchor = graph.current.and_then(|index| rects.get(index)).copied().unwrap_or(bounds);
        state.graph_offset = Vec2::new(canvas.width() / 2.0 - anchor.center().x * zoom, 20.0 - (anchor.top() * zoom - canvas.height() * 0.25).max(0.0));
        state.graph_fit = key;
    }
    if response.dragged() {
        state.graph_offset += response.drag_delta();
    }
    if response.hovered() {
        let (scroll, zoom_delta) = ui.input(|input| (input.smooth_scroll_delta, input.zoom_delta()));
        if zoom_delta != 1.0 {
            let pointer = response.hover_pos().unwrap_or(canvas.center()) - canvas.min.to_vec2();
            let before = (pointer - state.graph_offset) / state.graph_zoom;
            state.graph_zoom = (state.graph_zoom * zoom_delta).clamp(0.15, 3.0);
            state.graph_offset = pointer - before * state.graph_zoom;
        } else {
            state.graph_offset += scroll;
        }
    }
    let zoom = state.graph_zoom;
    let origin = canvas.min.to_vec2() + state.graph_offset;
    let place = |rect: &Rect| Rect::from_min_size((rect.min.to_vec2() * zoom + origin).to_pos2(), rect.size() * zoom);
    let painter = ui.painter_at(canvas);
    painter.rect_filled(canvas, 0.0, ui.visuals().extreme_bg_color);
    let font = FontId::monospace((font_size * zoom).max(4.0));
    let rip = current_rip(&snapshot);
    // Arestas primeiro (os blocos por cima).
    for (index, block) in graph.blocks.iter().enumerate() {
        let from = place(&rects[index]);
        for (edge_index, (target, kind)) in block.edges.iter().enumerate() {
            let Some(to_rect) = rects.get(*target) else { continue };
            let to = place(to_rect);
            let color = match kind {
                EdgeKind::True => colors.green,
                EdgeKind::False => colors.red,
                EdgeKind::Jump | EdgeKind::Fallthrough => colors.blue,
            };
            let stroke = Stroke::new(1.4, color);
            let spread = (edge_index as f32 - (block.edges.len() as f32 - 1.0) / 2.0) * 12.0 * zoom;
            let start = Pos2::new(from.center().x + spread, from.bottom());
            let end = Pos2::new(to.center().x, to.top());
            let points = if to.top() > from.bottom() {
                let middle = (from.bottom() + to.top()) / 2.0;
                vec![start, Pos2::new(start.x, middle), Pos2::new(end.x, middle), Pos2::new(end.x, end.y - 6.0 * zoom)]
            } else {
                // Aresta para trás (laço): contorna pela esquerda.
                let left = from.left().min(to.left()) - (14.0 + 8.0 * edge_index as f32) * zoom;
                vec![start, Pos2::new(start.x, start.y + 10.0 * zoom), Pos2::new(left, start.y + 10.0 * zoom), Pos2::new(left, end.y - 14.0 * zoom), Pos2::new(end.x, end.y - 14.0 * zoom), Pos2::new(end.x, end.y - 6.0 * zoom)]
            };
            painter.add(egui::Shape::line(points, stroke));
            painter.add(egui::Shape::convex_polygon(vec![end, Pos2::new(end.x - 4.0 * zoom, end.y - 7.0 * zoom), Pos2::new(end.x + 4.0 * zoom, end.y - 7.0 * zoom)], color, Stroke::NONE));
        }
    }
    let mut clicked = None;
    let text_color = ui.visuals().text_color();
    for (index, block) in graph.blocks.iter().enumerate() {
        let rect = place(&rects[index]);
        if !rect.intersects(canvas) {
            continue;
        }
        let current = graph.current == Some(index);
        painter.rect_filled(rect, 2.0, ui.visuals().panel_fill);
        painter.rect_stroke(rect, 2.0, Stroke::new(if current { 2.5 } else { 1.0 }, if current { colors.red } else { colors.dim }), egui::StrokeKind::Inside);
        if zoom < 0.35 {
            continue;
        }
        for (row, line) in block.lines.iter().enumerate() {
            let top = rect.top() + (PADDING + row as f32 * line_height) * zoom;
            let line_rect = Rect::from_min_size(Pos2::new(rect.left(), top), Vec2::new(rect.width(), line_height * zoom));
            if Some(line.address) == rip {
                painter.rect_filled(line_rect, 0.0, colors.current);
            } else if state.selected_code == Some(line.address) {
                painter.rect_filled(line_rect, 0.0, colors.selection);
            }
            let color = if Some(line.address) == rip { Color32::WHITE } else { text_color };
            let label = state.label_at(line.address).map(|label| format!("{label}: ")).unwrap_or_default();
            let text = format!("{:08x}  {label}{}", line.address & 0xFFFF_FFFF, line.text);
            painter.text(Pos2::new(rect.left() + PADDING * zoom, line_rect.center().y), Align2::LEFT_CENTER, text, font.clone(), color);
            if let Some(pointer) = response.interact_pointer_pos() {
                if line_rect.contains(pointer) && (response.clicked() || response.double_clicked()) {
                    clicked = Some((line.address, response.double_clicked()));
                }
            }
        }
    }
    if let Some((address, double)) = clicked {
        state.selected_code = Some(address);
        if double {
            state.go_to_code(address);
        }
    }
    response.context_menu(|ui| {
        if let Some(address) = state.selected_code {
            if ui.button("Seguir na desmontagem").clicked() {
                state.go_to_code(address);
                ui.close();
            }
        }
        if ui.button("Ajustar à janela").clicked() {
            state.graph_fit = u64::MAX;
            ui.close();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::GraphBlock;
    use kd_client::analysis::cfg::Layout;

    #[test]
    fn layers_go_down_and_columns_side_by_side() {
        let block = |start: u64| GraphBlock { start, end: start + 1, lines: Vec::new(), edges: Vec::new(), exit: false };
        let graph = GraphView { blocks: vec![block(0), block(1), block(2), block(3)], layout: Layout { layer: vec![0, 1, 1, 2], column: vec![0, 0, 1, 0], layers: 3, width: 2 }, ..Default::default() };
        let rects = block_rects(&graph, 8.0, 16.0);
        assert!(rects[1].top() > rects[0].bottom());
        assert_eq!(rects[1].top(), rects[2].top());
        assert!(rects[2].left() > rects[1].right());
        assert!(rects[3].top() > rects[1].bottom());
    }
}
