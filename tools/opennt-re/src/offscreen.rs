//! A janela desenhada fora da tela, sem GPU nem janela: o egui roda alguns
//! quadros com uma entrada sintética, as formas viram triângulos
//! (`tessellate`) e um rasterizador de software os pinta com as texturas
//! do egui (o atlas das fontes). É assim que o `--screenshot` e o teste de
//! fumaça tiram a captura do depurador parado num breakpoint.

use std::collections::HashMap;
use std::path::Path;

use eframe::egui::{self, epaint, Color32, ColorImage, Pos2, Rect, TextureId, Vec2};

use crate::app::DebuggerApp;

/// Desenha `frames` quadros da janela em `size` (pontos = pixels) e
/// devolve a imagem do último.
pub fn render(app: &mut DebuggerApp, size: [u32; 2], frames: usize) -> ColorImage {
    let context = egui::Context::default();
    super::configure(&context);
    let mut textures: HashMap<TextureId, ColorImage> = HashMap::new();
    let mut primitives = Vec::new();
    let screen = Rect::from_min_size(Pos2::ZERO, Vec2::new(size[0] as f32, size[1] as f32));
    for index in 0..frames.max(1) {
        let input = egui::RawInput { screen_rect: Some(screen), max_texture_side: Some(8192), time: Some(index as f64 * 0.25), focused: true, ..Default::default() };
        let mut output = context.run_ui(input, |ui| app.show(ui));
        for (id, deltas) in std::mem::take(&mut output.textures_delta.set) {
            for delta in deltas {
                let epaint::ImageData::Color(image) = &delta.image;
                match delta.pos {
                    None => {
                        textures.insert(id, (**image).clone());
                    }
                    Some([x, y]) => {
                        if let Some(target) = textures.get_mut(&id) {
                            for row in 0..image.height() {
                                for column in 0..image.width() {
                                    let (tx, ty) = (x + column, y + row);
                                    if tx < target.width() && ty < target.height() {
                                        let width = target.width();
                                        target.pixels[ty * width + tx] = image.pixels[row * image.width() + column];
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        primitives = context.tessellate(output.shapes, output.pixels_per_point);
        for id in std::mem::take(&mut output.textures_delta.free) {
            textures.remove(&id);
        }
    }
    let mut canvas = Canvas::new(size[0] as usize, size[1] as usize, context.global_style().visuals.panel_fill);
    for primitive in &primitives {
        if let epaint::Primitive::Mesh(mesh) = &primitive.primitive {
            canvas.draw(mesh, primitive.clip_rect, textures.get(&mesh.texture_id));
        }
    }
    canvas.into_image()
}

/// Grava a imagem como PNG (RGB).
pub fn save_png(image: &ColorImage, path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    let rgb: Vec<u8> = image.pixels.iter().flat_map(|pixel| [pixel.r(), pixel.g(), pixel.b()]).collect();
    let buffer = image::RgbImage::from_raw(image.width() as u32, image.height() as u32, rgb).ok_or("imagem com tamanho errado")?;
    buffer.save(path).map_err(|error| format!("{}: {error}", path.display()))
}

/// Pixels com alfa pré-multiplicado, em espaço gama (a mistura que o egui
/// espera de um backend sem sRGB).
struct Canvas {
    width: usize,
    height: usize,
    pixels: Vec<[f32; 4]>,
}

fn to_float(color: Color32) -> [f32; 4] {
    [color.r() as f32 / 255.0, color.g() as f32 / 255.0, color.b() as f32 / 255.0, color.a() as f32 / 255.0]
}

/// Sinal do lado de `point` em relação à aresta `from -> to`.
fn edge(from: Pos2, to: Pos2, point: Pos2) -> f32 {
    (point.x - from.x) * (to.y - from.y) - (point.y - from.y) * (to.x - from.x)
}

/// Desempate de um pixel exatamente sobre uma aresta: de duas faces que a
/// dividem (percorrida em sentidos opostos), só uma o pinta.
fn owns_edge(from: Pos2, to: Pos2) -> bool {
    let direction = to - from;
    direction.y > 0.0 || (direction.y == 0.0 && direction.x < 0.0)
}

impl Canvas {
    fn new(width: usize, height: usize, background: Color32) -> Canvas {
        Canvas { width, height, pixels: vec![to_float(background); width * height] }
    }

    fn draw(&mut self, mesh: &epaint::Mesh, clip: Rect, texture: Option<&ColorImage>) {
        let clip_x0 = clip.min.x.max(0.0).floor() as i64;
        let clip_y0 = clip.min.y.max(0.0).floor() as i64;
        let clip_x1 = (clip.max.x.min(self.width as f32).ceil() as i64).min(self.width as i64);
        let clip_y1 = (clip.max.y.min(self.height as f32).ceil() as i64).min(self.height as i64);
        for triangle in mesh.indices.chunks_exact(3) {
            let [a, mut b, mut c] = [mesh.vertices[triangle[0] as usize], mesh.vertices[triangle[1] as usize], mesh.vertices[triangle[2] as usize]];
            let mut area = edge(a.pos, b.pos, c.pos);
            if area.abs() < 1e-6 {
                continue;
            }
            if area < 0.0 {
                std::mem::swap(&mut b, &mut c);
                area = -area;
            }
            let x0 = (a.pos.x.min(b.pos.x).min(c.pos.x).floor() as i64).max(clip_x0);
            let y0 = (a.pos.y.min(b.pos.y).min(c.pos.y).floor() as i64).max(clip_y0);
            let x1 = (a.pos.x.max(b.pos.x).max(c.pos.x).ceil() as i64 + 1).min(clip_x1);
            let y1 = (a.pos.y.max(b.pos.y).max(c.pos.y).ceil() as i64 + 1).min(clip_y1);
            let (ca, cb, cc) = (to_float(a.color), to_float(b.color), to_float(c.color));
            let owns = [owns_edge(b.pos, c.pos), owns_edge(c.pos, a.pos), owns_edge(a.pos, b.pos)];
            for y in y0..y1 {
                for x in x0..x1 {
                    let point = Pos2::new(x as f32 + 0.5, y as f32 + 0.5);
                    let weights = [edge(b.pos, c.pos, point), edge(c.pos, a.pos, point), edge(a.pos, b.pos, point)];
                    if weights.iter().zip(owns).any(|(&weight, owns)| weight < 0.0 || (weight == 0.0 && !owns)) {
                        continue;
                    }
                    let [w0, w1, w2] = weights.map(|weight| weight / area);
                    let mut source = [0.0f32; 4];
                    for channel in 0..4 {
                        source[channel] = ca[channel] * w0 + cb[channel] * w1 + cc[channel] * w2;
                    }
                    if let Some(texture) = texture {
                        let uv = Pos2::new(a.uv.x * w0 + b.uv.x * w1 + c.uv.x * w2, a.uv.y * w0 + b.uv.y * w1 + c.uv.y * w2);
                        let texel = sample(texture, uv);
                        for channel in 0..4 {
                            source[channel] *= texel[channel];
                        }
                    }
                    let pixel = &mut self.pixels[y as usize * self.width + x as usize];
                    let keep = 1.0 - source[3].clamp(0.0, 1.0);
                    for channel in 0..4 {
                        pixel[channel] = (source[channel] + pixel[channel] * keep).clamp(0.0, 1.0);
                    }
                }
            }
        }
    }

    fn into_image(self) -> ColorImage {
        let pixels = self.pixels.iter().map(|pixel| Color32::from_rgb((pixel[0] * 255.0).round() as u8, (pixel[1] * 255.0).round() as u8, (pixel[2] * 255.0).round() as u8)).collect();
        ColorImage::new([self.width, self.height], pixels)
    }
}

/// Amostragem bilinear (o atlas das fontes usa filtro linear).
fn sample(texture: &ColorImage, uv: Pos2) -> [f32; 4] {
    let (width, height) = (texture.width(), texture.height());
    if width == 0 || height == 0 {
        return [1.0; 4];
    }
    let x = (uv.x * width as f32 - 0.5).clamp(0.0, (width - 1) as f32);
    let y = (uv.y * height as f32 - 0.5).clamp(0.0, (height - 1) as f32);
    let (x0, y0) = (x.floor() as usize, y.floor() as usize);
    let (x1, y1) = ((x0 + 1).min(width - 1), (y0 + 1).min(height - 1));
    let (fx, fy) = (x - x0 as f32, y - y0 as f32);
    let at = |column: usize, row: usize| to_float(texture.pixels[row * width + column]);
    let (p00, p10, p01, p11) = (at(x0, y0), at(x1, y0), at(x0, y1), at(x1, y1));
    let mut texel = [0.0; 4];
    for channel in 0..4 {
        let top = p00[channel] + (p10[channel] - p00[channel]) * fx;
        let bottom = p01[channel] + (p11[channel] - p01[channel]) * fx;
        texel[channel] = top + (bottom - top) * fy;
    }
    texel
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rasterizes_a_quad_without_seams() {
        // Um quadrado semitransparente em dois triângulos: a diagonal não
        // pode sair mais escura (pintada duas vezes).
        let mut mesh = epaint::Mesh::default();
        mesh.add_colored_rect(Rect::from_min_max(Pos2::new(2.0, 2.0), Pos2::new(10.0, 10.0)), Color32::from_rgba_premultiplied(100, 0, 0, 128));
        let mut canvas = Canvas::new(12, 12, Color32::BLACK);
        canvas.draw(&mesh, Rect::from_min_max(Pos2::ZERO, Pos2::new(12.0, 12.0)), None);
        let image = canvas.into_image();
        let inside: Vec<Color32> = (2..10).flat_map(|y| (2..10).map(move |x| (x, y))).map(|(x, y)| image.pixels[y * 12 + x]).collect();
        assert!(inside.iter().all(|pixel| *pixel == inside[0]), "{inside:?}");
        assert_eq!(inside[0].r(), 100);
        assert_eq!(image.pixels[0], Color32::BLACK);
        assert_eq!(image.pixels[11 * 12 + 11], Color32::BLACK);
    }
}
