//! O arranjo da janela entre execuções (no arquivo de estado, junto do
//! tema e das expressões observadas):
//!
//! - a posição e o tamanho da janela, em pixels físicos (com a escala da
//!   interface diferente de 1 os pontos do egui não são os do sistema, e a
//!   janela encolheria a cada abertura), e se estava maximizada;
//! - os tamanhos dos painéis divisíveis (os da aba CPU, a lista de módulos
//!   da aba Símbolos e o console), devolvidos ao egui antes do primeiro
//!   quadro;
//! - o arranjo das abas, lido à parte do resto do estado: um arranjo que
//!   esta versão não entende volta ao padrão sem levar junto o tema, as
//!   expressões e o histórico; as abas novas desta versão (que o arquivo
//!   não conhecia) entram na primeira folha;
//! - os textos do `egui_dock` (menu de contexto das abas, janelas soltas)
//!   em português: eles não vão para o arquivo e voltam em inglês a cada
//!   leitura.

use std::collections::BTreeMap;

use eframe::egui::{self, Pos2, Rect, Vec2};
use egui_dock::{DockState, Translations};
use serde::{Deserialize, Serialize};

use crate::app::Tab;

/// Os painéis cujo tamanho fica salvo (os ids dos `egui::Panel`).
pub const PANELS: [&str; 6] = ["cpu-bottom", "cpu-stack", "cpu-registers", "cpu-info", "re-symbol-modules", "re-console"];

/// Os tamanhos dos painéis do último quadro (na ordem de `PANELS`).
pub type PanelSizes = [Option<[f32; 2]>; PANELS.len()];

/// A posição e o tamanho da janela.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct WindowGeometry {
    /// O canto de cima à esquerda da moldura, em pixels físicos.
    pub x: f32,
    pub y: f32,
    /// O tamanho da área de dentro, em pixels físicos.
    pub width: f32,
    pub height: f32,
    /// Pixels físicos por ponto do sistema quando foi salvo (a escala do
    /// monitor).
    pub native_scale: f32,
    pub maximized: bool,
}

impl WindowGeometry {
    /// A geometria de agora (`None` minimizada, ou sem posição conhecida).
    pub fn current(context: &egui::Context) -> Option<WindowGeometry> {
        let pixels_per_point = context.pixels_per_point();
        context.input(|input| {
            let viewport = input.viewport();
            if viewport.minimized == Some(true) {
                return None;
            }
            let inner = viewport.inner_rect?;
            let outer = viewport.outer_rect.unwrap_or(inner);
            let geometry = WindowGeometry { x: outer.min.x * pixels_per_point, y: outer.min.y * pixels_per_point, width: inner.width() * pixels_per_point, height: inner.height() * pixels_per_point, native_scale: viewport.native_pixels_per_point.unwrap_or(1.0), maximized: viewport.maximized == Some(true) };
            geometry.valid().then_some(geometry)
        })
    }

    fn valid(&self) -> bool {
        [self.x, self.y, self.width, self.height, self.native_scale].iter().all(|value| value.is_finite()) && self.width > 0.0 && self.height > 0.0
    }

    /// Junta a de agora com a guardada: maximizada, o tamanho de antes fica
    /// (para a janela voltar a ele quando sair do maximizado).
    pub fn merged(self, previous: Option<WindowGeometry>) -> WindowGeometry {
        match previous {
            Some(previous) if self.maximized => WindowGeometry { maximized: true, ..previous },
            _ => self,
        }
    }

    /// O tamanho e a posição em pontos do sistema para o `ViewportBuilder`,
    /// dentro de limites (uma posição de um monitor que saiu volta para
    /// perto do canto).
    pub fn logical(&self) -> (Vec2, Pos2) {
        let scale = if self.native_scale.is_finite() && self.native_scale > 0.1 { self.native_scale } else { 1.0 };
        let finite = |value: f32, fallback: f32| if value.is_finite() { value } else { fallback };
        let size = Vec2::new(finite(self.width / scale, 1600.0).clamp(640.0, 7680.0), finite(self.height / scale, 1000.0).clamp(400.0, 4320.0));
        let position = Pos2::new(finite(self.x / scale, 0.0).clamp(-64.0, 7000.0), finite(self.y / scale, 0.0).clamp(0.0, 4000.0));
        (size, position)
    }
}

/// Os tamanhos dos painéis de agora (o retângulo de fora de cada um).
pub fn capture_panels(context: &egui::Context) -> PanelSizes {
    std::array::from_fn(|index| egui::PanelState::load(context, egui::Id::new(PANELS[index])).map(|state| [state.outer_rect.width(), state.outer_rect.height()]))
}

/// Os tamanhos para o arquivo de estado.
pub fn panels_map(sizes: &PanelSizes) -> BTreeMap<String, [f32; 2]> {
    PANELS.iter().zip(sizes.iter()).filter_map(|(name, size)| size.map(|size| (name.to_string(), size))).collect()
}

/// Devolve os tamanhos salvos ao egui (antes do primeiro quadro que mostra
/// os painéis).
pub fn restore_panels(context: &egui::Context, sizes: &BTreeMap<String, [f32; 2]>) {
    for name in PANELS {
        let Some(&[width, height]) = sizes.get(name) else { continue };
        if width.is_finite() && height.is_finite() && width >= 20.0 && height >= 20.0 {
            let state = egui::PanelState { outer_rect: Rect::from_min_size(Pos2::ZERO, Vec2::new(width, height)) };
            context.data_mut(|data| data.insert_persisted(egui::Id::new(name), state));
        }
    }
}

/// O nome de uma aba no arquivo de estado.
pub fn tab_key(tab: Tab) -> String {
    format!("{tab:?}")
}

/// As abas que esta versão conhece (vão para o arquivo junto do arranjo).
pub fn known_tabs() -> Vec<String> {
    Tab::ALL.iter().map(|tab| tab_key(*tab)).collect()
}

/// O arranjo salvo, ou `None` quando não serve (outra versão, vazio). As
/// abas que o arquivo não conhecia entram na primeira folha; as que o
/// usuário fechou continuam fechadas.
pub fn restore_layout(value: Option<serde_json::Value>, known: &[String]) -> Option<DockState<Tab>> {
    let mut value = value?;
    fill_unrendered_rects(&mut value);
    let mut dock: DockState<Tab> = serde_json::from_value(value).ok()?;
    if dock.iter_all_tabs().next().is_none() {
        return None;
    }
    if !known.is_empty() {
        let active = dock.find_active_focused().map(|(_, tab)| *tab);
        for tab in Tab::ALL {
            if !known.contains(&tab_key(tab)) && dock.find_tab(&tab).is_none() {
                dock.push_to_first_leaf(tab);
            }
        }
        if let Some(path) = active.and_then(|tab| dock.find_tab(&tab)) {
            let _ = dock.set_active_tab(path);
        }
    }
    dock.translations = translations();
    Some(dock)
}

/// Um arranjo gravado antes do primeiro quadro tem os retângulos das áreas
/// ainda sem medida (NaN), que o JSON grava como `null` e não lê de volta
/// como número. As coordenadas `x`/`y` nulas viram 0: o `egui_dock` mede
/// as áreas de novo a cada quadro.
fn fill_unrendered_rects(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, item) in map.iter_mut() {
                if (key == "x" || key == "y") && item.is_null() {
                    *item = serde_json::json!(0.0);
                } else {
                    fill_unrendered_rects(item);
                }
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(fill_unrendered_rects),
        _ => {}
    }
}

/// Os textos do `egui_dock` em português.
pub fn translations() -> Translations {
    let mut translations = Translations::english();
    let menu = &mut translations.tab_context_menu;
    menu.close_button = "Fechar a aba".into();
    menu.eject_button = "Soltar numa janela".into();
    menu.hide_tab_bar_button = "Esconder a barra de abas".into();
    menu.show_tab_bar_button = "Mostrar a barra de abas".into();
    let leaf = &mut translations.leaf;
    leaf.close_button_disabled_tooltip = "Esta área tem abas que não fecham.".into();
    leaf.close_all_button = "Fechar a janela".into();
    leaf.close_all_button_menu_hint = "Botão direito para fechar esta janela.".into();
    leaf.close_all_button_modifier_hint = "Segure Shift para fechar esta janela.".into();
    leaf.close_all_button_modifier_menu_hint = "Segure Shift ou use o botão direito para fechar esta janela.".into();
    leaf.close_all_button_disabled_tooltip = "Esta janela tem abas que não fecham.".into();
    leaf.minimize_button = "Minimizar".into();
    leaf.minimize_button_menu_hint = "Botão direito para minimizar esta janela.".into();
    leaf.minimize_button_modifier_hint = "Segure Shift para minimizar esta janela.".into();
    leaf.minimize_button_modifier_menu_hint = "Segure Shift ou use o botão direito para minimizar esta janela.".into();
    translations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry_survives_a_different_interface_scale() {
        // Salva com o monitor a 1,5: o tamanho volta em pontos do sistema.
        let geometry = WindowGeometry { x: 150.0, y: 75.0, width: 2400.0, height: 1500.0, native_scale: 1.5, maximized: false };
        let (size, position) = geometry.logical();
        assert_eq!(size, Vec2::new(1600.0, 1000.0));
        assert_eq!(position, Pos2::new(100.0, 50.0));
        // Fora dos limites e sem números: volta para dentro.
        let wild = WindowGeometry { x: -90_000.0, y: f32::NAN, width: 10.0, height: f32::INFINITY, native_scale: 0.0, maximized: false };
        let (size, position) = wild.logical();
        assert_eq!(size, Vec2::new(640.0, 1000.0));
        assert_eq!(position, Pos2::new(-64.0, 0.0));
        // Maximizada guarda o tamanho de antes.
        let maximized = WindowGeometry { x: 0.0, y: 0.0, width: 3840.0, height: 2100.0, native_scale: 1.0, maximized: true };
        let merged = maximized.merged(Some(geometry));
        assert!(merged.maximized);
        assert_eq!(merged.width, 2400.0);
        assert_eq!(maximized.merged(None), maximized);
        let text = serde_json::to_string(&geometry).expect("json");
        assert_eq!(serde_json::from_str::<WindowGeometry>(&text).expect("volta"), geometry);
    }

    #[test]
    fn layout_keeps_closed_tabs_and_adds_new_ones() {
        // Um arranjo com só duas abas, de uma versão que conhecia todas menos Snapshots.
        let mut dock = DockState::new(vec![Tab::Cpu, Tab::Log]);
        if let Some(path) = dock.find_tab(&Tab::Log) {
            let _ = dock.set_active_tab(path);
        }
        let value = serde_json::to_value(&dock).expect("json");
        let known: Vec<String> = known_tabs().into_iter().filter(|name| name != "Snapshots").collect();
        let restored = restore_layout(Some(value.clone()), &known).expect("arranjo");
        assert!(restored.find_tab(&Tab::Snapshots).is_some(), "a aba nova entra");
        assert!(restored.find_tab(&Tab::Graph).is_none(), "a aba fechada continua fechada");
        assert_eq!(restored.translations.tab_context_menu.eject_button, "Soltar numa janela");
        // Sem a lista de abas (arquivo antigo): o arranjo fica como estava.
        let old = restore_layout(Some(value), &[]).expect("arranjo");
        assert!(old.find_tab(&Tab::Snapshots).is_none());
        // Um arranjo que não se lê, ou vazio, volta ao padrão.
        assert!(restore_layout(Some(serde_json::json!({"surfaces": "?"})), &known).is_none());
        assert!(restore_layout(None, &known).is_none());
        let empty: DockState<Tab> = DockState::new(Vec::new());
        assert!(restore_layout(Some(serde_json::to_value(&empty).expect("json")), &known).is_none());
        assert_eq!(panels_map(&[Some([300.0, 200.0]), None, None, None, None, None]).get("cpu-bottom"), Some(&[300.0, 200.0]));
    }
}
