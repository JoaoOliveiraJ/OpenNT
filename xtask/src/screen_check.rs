//! O que uma tela do QEMU mostra, para a vigia do `test-boot --watch-screen`
//! (`qemu::screen_thread`): o primeiro desenho depois do boot
//! ([`drawn_pixels`], o `FIRST_PIXEL_OK`), a tela de logon ([`logon_screen`]
//! em duas leituras seguidas iguais, [`same_screen`], o `LOGON_SCREEN_OK`) e
//! a área de trabalho ([`desktop_screen`], o `DESKTOP_OK`).

use std::collections::HashMap;

use crate::png::Image;

/// O marcador do primeiro desenho.
pub const FIRST_PIXEL_MARKER: &str = "FIRST_PIXEL_OK";
/// O marcador da tela de logon.
pub const LOGON_SCREEN_MARKER: &str = "LOGON_SCREEN_OK";
/// A vigia só procura a tela de logon depois deste marcador na serial: o
/// LogonUI.exe que o winlogon criou (`initial_process.rs`).
pub const LOGON_AFTER: &str = "LOGONUI_STARTED";
/// Pixels não pretos que uma tela gráfica precisa ter.
const DRAWN_MINIMUM: usize = 64;
/// Um canal acima disto não é preto.
const BLACK_LEVEL: u8 = 0x20;
/// O fundo da tela de bugcheck (`bgk/bugcheck_screen.rs`).
const BUGCHECK_BACKGROUND: [u8; 3] = [0x00, 0x77, 0xD6];

fn is_black(rgb: [u8; 3]) -> bool {
    rgb.iter().all(|&channel| channel <= BLACK_LEVEL)
}

/// Uma tela gráfica de pelo menos 800x600, como o vídeo de boot (1024x768):
/// a de texto da VGA (720x400) mostra o console do carregador, e o aviso do
/// QEMU antes da VGA iniciar ocupa 640x480.
///
/// Todas as conferências deste módulo leem o `screendump` do QEMU no tamanho
/// dele, nunca um PNG: o PNG de uma tela com foto sai reduzido à metade
/// (`png::encode_within`), e limites absolutos como o branco do relógio
/// ([`lock_screen_shown`]), o ponteiro e esta própria guarda só valem na
/// tela inteira. Cada PNG que o test-boot grava leva o tamanho da tela no
/// texto `opennt-tela`; para conferir um PNG de novo, amplie-o antes, pelo
/// vizinho mais próximo, para esse tamanho.
fn is_graphics(image: &Image) -> bool {
    image.width >= 800 && image.height >= 600
}

/// As `count` cores mais comuns, como `#rrggbb xN`.
fn palette(common: &[([u8; 3], usize)], count: usize) -> String {
    let colors: Vec<String> = common.iter().take(count).map(|(rgb, n)| format!("#{:02x}{:02x}{:02x} x{n}", rgb[0], rgb[1], rgb[2])).collect();
    colors.join(", ")
}

/// Os pixels desenhados numa tela do QEMU, ou None. Só conta uma tela
/// gráfica ([`is_graphics`]). O vídeo de boot do OpenNT é todo preto e o
/// kernel só desenha nele a tela de bugcheck, então pixels não pretos que não
/// são o fundo azul dela vêm de quem desenha na tela depois do boot.
pub fn drawn_pixels(image: &Image) -> Option<String> {
    if !is_graphics(image) {
        return None;
    }
    let mut drawn = 0usize;
    let mut bugcheck = 0usize;
    let mut colors: HashMap<[u8; 3], usize> = HashMap::new();
    let (mut left, mut top, mut right, mut bottom) = (usize::MAX, usize::MAX, 0usize, 0usize);
    for (index, pixel) in image.rgb.chunks_exact(3).enumerate() {
        let rgb = [pixel[0], pixel[1], pixel[2]];
        if rgb == BUGCHECK_BACKGROUND {
            bugcheck += 1;
        }
        if is_black(rgb) {
            continue;
        }
        drawn += 1;
        *colors.entry(rgb).or_default() += 1;
        let (x, y) = (index % image.width, index / image.width);
        left = left.min(x);
        right = right.max(x);
        top = top.min(y);
        bottom = bottom.max(y);
    }
    if drawn < DRAWN_MINIMUM || bugcheck * 2 > image.width * image.height {
        return None;
    }
    let mut common: Vec<([u8; 3], usize)> = colors.into_iter().collect();
    common.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    Some(format!(
        "{drawn} pixels desenhados na tela {}x{}, de ({left},{top}) a ({right},{bottom}); cores: {}",
        image.width,
        image.height,
        palette(&common, 4)
    ))
}

// ---- tela de logon ----------------------------------------------------------
//
// Numa instalação nova do 19041, a tela de bloqueio do LogonUI mostra o
// %SystemRoot%\Web\Screen\img100.jpg (3840x2160: a praia vista de dentro de
// uma caverna) esticado para cobrir a tela (UniformToFill): na tela de
// 1024x768 do vídeo de boot, a imagem fica com 1366x768 e aparece o meio
// dela; o relógio e a data vão em branco embaixo, à esquerda. Os limites
// abaixo vêm dessa imagem decodificada pelo WIC no tamanho de destino (como o
// XAML decodifica uma imagem maior que a tela) e por outros caminhos
// (decodificada inteira ou pela metade e reduzida pelo WIC, pelo GDI+
// bilinear e bicúbico), com e sem o texto, e alinhada à esquerda e à direita
// em vez do meio:
//
// - fora do preto: 43% da tela (35% alinhada à esquerda, 51% à direita): a
//   caverna é escura;
// - pares de vizinhos suaves: 84% a 94% dos pares desenhados;
// - cores com 512 pixels ou mais: 17 ou 18 (os tons do céu);
// - linhas com 1% ou mais de pixels desenhados: 84%; colunas: 86% (69%
//   alinhada à esquerda, 100% à direita).
//
// O texto ocupa 1% da tela e muda esses números em menos de um ponto: sem a
// fonte do relógio, a tela passa do mesmo jeito. Não passam:
//
// - a memória mostrada como pixels (os bytes do ntoskrnl.exe ou de uma hive
//   lidos como cor): 69% a 91% da tela fora do preto, 50 a 106 cores de 512
//   pixels, mas só 7% a 13% dos pares vizinhos suaves; ruído: menos de 1%;
// - a cor de destaque com o relógio, que o LogonUI mostra quando não
//   consegue a imagem, e a tela de status com uma linha de texto: 1 ou 2
//   cores;
// - um quadro rasgado com os 60% de cima da tela de bloqueio: desenho em 47%
//   das linhas; uma faixa do meio (de 30% a 70% da altura): 40% das linhas;
//   a metade da direita: 50% das colunas. Um quadro rasgado mais perto do fim
//   passa nesses números, mas não fica igual na leitura seguinte
//   ([`same_screen`]); uma transição (a imagem surgindo do preto) também não.
//
// Uma imagem nos lugares errados (repetida em ladrilhos, por exemplo) passa:
// a conferência separa uma imagem cobrindo a tela de lixo, de cor lisa e de
// quadro pela metade, e a tela de logon gravada mostra o resto.

/// Fora do preto: pelo menos um quarto da tela.
const LOGON_AREA_DIVISOR: usize = 4;
/// Dois pixels vizinhos na linha, os dois desenhados, são suaves quando
/// nenhum canal muda mais que isto de um para o outro: numa foto, num
/// degradê ou numa cor lisa quase todos são; em bytes quaisquer lidos como
/// cor, quase nenhum.
const SMOOTH_STEP: u8 = 16;
/// Pelo menos metade dos pares vizinhos desenhados é suave.
const LOGON_SMOOTH_DIVISOR: usize = 2;
/// Pelo menos tantas cores...
const LOGON_COLORS: usize = 8;
/// ...cada uma com pelo menos esta fração da tela (512 pixels em 1024x768):
/// uma imagem ou um degradê, não uma cor lisa com texto em cima (o texto
/// suavizado tem muitos tons, cada um com poucos pixels).
const LOGON_COLOR_SHARE: usize = 1536;
/// Uma linha (ou coluna) conta como desenhada com 1/100 dos pixels dela
/// fora do preto...
const LINE_SHARE: usize = 100;
/// ...e pelo menos 3/5 das linhas e 3/5 das colunas contam: a imagem de
/// fundo cobre a tela inteira.
const LOGON_SPREAD: (usize, usize) = (3, 5);
/// Duas leituras da tela de logon são a mesma tela quando diferem em até
/// esta fração dos pixels: o relógio que muda de minuto (um dígito, menos de
/// 1% da tela) e o ponteiro cabem; um quadro rasgado e uma transição não.
const SAME_SCREEN_DIVISOR: usize = 32;

/// As medidas de [`logon_screen`] numa tela gráfica.
struct LogonMeasures {
    width: usize,
    height: usize,
    /// Pixels fora do preto.
    drawn: usize,
    /// Pares de vizinhos na linha com os dois desenhados, e os suaves.
    pairs: usize,
    smooth: usize,
    /// As cores com pelo menos [`LOGON_COLOR_SHARE`] da tela, da mais comum
    /// para a menos.
    common: Vec<([u8; 3], usize)>,
    /// Linhas e colunas com 1/[`LINE_SHARE`] dos pixels desenhados.
    rows: usize,
    columns: usize,
    /// Pixels do fundo azul da tela de bugcheck.
    bugcheck: usize,
}

impl LogonMeasures {
    fn of(image: &Image) -> LogonMeasures {
        let (width, height) = (image.width, image.height);
        let mut measures = LogonMeasures { width, height, drawn: 0, pairs: 0, smooth: 0, common: Vec::new(), rows: 0, columns: 0, bugcheck: 0 };
        let mut colors: HashMap<[u8; 3], usize> = HashMap::new();
        let mut per_column = vec![0usize; width];
        for row in image.rgb.chunks_exact(width * 3).take(height) {
            let mut in_row = 0usize;
            let mut previous: Option<[u8; 3]> = None;
            for (x, pixel) in row.chunks_exact(3).enumerate() {
                let rgb = [pixel[0], pixel[1], pixel[2]];
                if rgb == BUGCHECK_BACKGROUND {
                    measures.bugcheck += 1;
                }
                if is_black(rgb) {
                    previous = None;
                    continue;
                }
                in_row += 1;
                per_column[x] += 1;
                *colors.entry(rgb).or_default() += 1;
                if let Some(left) = previous {
                    measures.pairs += 1;
                    if left.iter().zip(rgb).all(|(&a, b)| a.abs_diff(b) <= SMOOTH_STEP) {
                        measures.smooth += 1;
                    }
                }
                previous = Some(rgb);
            }
            measures.drawn += in_row;
            if in_row * LINE_SHARE >= width {
                measures.rows += 1;
            }
        }
        measures.columns = per_column.iter().filter(|&&count| count * LINE_SHARE >= height).count();
        let minimum = measures.color_minimum();
        measures.common = colors.into_iter().filter(|(_, count)| *count >= minimum).collect();
        measures.common.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        measures
    }

    fn total(&self) -> usize {
        self.width * self.height
    }

    /// Os pixels que uma cor precisa ter para contar.
    fn color_minimum(&self) -> usize {
        (self.total() / LOGON_COLOR_SHARE).max(1)
    }

    /// `parte` em porcento de `todo`.
    fn percent(part: usize, whole: usize) -> usize {
        part * 100 / whole.max(1)
    }

    /// O que falta para ser a tela de logon (vazio: nada).
    fn missing(&self) -> Vec<String> {
        let total = self.total();
        let (spread, of) = LOGON_SPREAD;
        let mut missing = Vec::new();
        if self.bugcheck * 2 > total {
            missing.push("e a tela de bugcheck".to_string());
        }
        if self.drawn * LOGON_AREA_DIVISOR < total {
            missing.push(format!("{}% da tela fora do preto (minimo {}%)", Self::percent(self.drawn, total), 100 / LOGON_AREA_DIVISOR));
        }
        if self.smooth * LOGON_SMOOTH_DIVISOR < self.pairs {
            missing.push(format!("{}% dos vizinhos suaves (minimo {}%)", Self::percent(self.smooth, self.pairs), 100 / LOGON_SMOOTH_DIVISOR));
        }
        if self.common.len() < LOGON_COLORS {
            missing.push(format!("{} cores com {} pixels ou mais (minimo {LOGON_COLORS})", self.common.len(), self.color_minimum()));
        }
        if self.rows * of < self.height * spread {
            missing.push(format!("desenho em {}% das linhas (minimo {}%)", Self::percent(self.rows, self.height), 100 * spread / of));
        }
        if self.columns * of < self.width * spread {
            missing.push(format!("desenho em {}% das colunas (minimo {}%)", Self::percent(self.columns, self.width), 100 * spread / of));
        }
        missing
    }

    fn describe(&self) -> String {
        format!(
            "{} de {} pixels desenhados ({}%), {}% dos vizinhos suaves, {} cores com {} pixels ou mais, desenho em {}% das linhas e {}% das colunas; cores: {}",
            self.drawn,
            self.total(),
            Self::percent(self.drawn, self.total()),
            Self::percent(self.smooth, self.pairs),
            self.common.len(),
            self.color_minimum(),
            Self::percent(self.rows, self.height),
            Self::percent(self.columns, self.width),
            palette(&self.common, 4)
        )
    }
}

/// A tela de logon numa tela do QEMU: a descrição dela, ou o que falta. É
/// uma tela gráfica ([`is_graphics`]) que não é a de bugcheck, com um quarto
/// ou mais fora do preto, a maior parte dos vizinhos suaves, pelo menos
/// [`LOGON_COLORS`] cores de 1/[`LOGON_COLOR_SHARE`] da tela cada e desenho
/// em 3/5 das linhas e 3/5 das colunas (os números medidos estão acima). O
/// primeiro pixel (o ponteiro do mouse, [`drawn_pixels`]) não basta.
pub fn logon_screen(image: &Image) -> Result<String, String> {
    if !is_graphics(image) {
        return Err(format!("tela {}x{}, nao e uma tela grafica de 800x600 ou mais", image.width, image.height));
    }
    let measures = LogonMeasures::of(image);
    let missing = measures.missing();
    if missing.is_empty() {
        Ok(measures.describe())
    } else {
        Err(missing.join("; "))
    }
}

/// Duas leituras da tela são a mesma tela: as mesmas dimensões e até
/// 1/[`SAME_SCREEN_DIVISOR`] dos pixels diferentes. A tela de logon só conta
/// quando passa em duas leituras seguidas iguais: um quadro pela metade
/// (rasgado na leitura) ou uma transição não fica igual na leitura seguinte.
pub fn same_screen(a: &Image, b: &Image) -> bool {
    if (a.width, a.height) != (b.width, b.height) || a.rgb.len() != b.rgb.len() {
        return false;
    }
    let different = a.rgb.chunks_exact(3).zip(b.rgb.chunks_exact(3)).filter(|(x, y)| x != y).count();
    different * SAME_SCREEN_DIVISOR <= a.width * a.height
}

// ---- ponteiro do mouse -------------------------------------------------------
//
// O `--mouse` do test-boot move o mouse PS/2 do QEMU pelo monitor e lê a tela
// antes e depois ([`cursor_moved`]). O ponteiro do Windows é a seta branca
// com contorno preto (12x19 pixels no tamanho padrão) que o adaptador de
// vídeo desenha por cima da tela. Quando ele anda, a tela muda onde ele
// estava e onde está; um controle que se acende sob o ponteiro (o botão de
// energia do LogonUI, 48x48) muda junto em volta da seta, então a seta é
// achada pela forma dela ([`arrows_in`]: o miolo branco fechado pelo
// contorno preto) dentro das mudanças, não pelo tamanho da mudança.

/// O marcador do ponteiro que andou.
pub const CURSOR_MOVED_MARKER: &str = "CURSOR_MOVED_OK";
/// O lado das células em que as mudanças da tela se agrupam: duas mudanças
/// a menos de uma célula uma da outra são do mesmo desenho.
const CURSOR_CELL: usize = 8;
/// O maior lado da seta do ponteiro (o miolo e o contorno).
const CURSOR_MAXIMUM: usize = 40;
/// Pixels brancos que o ponteiro tem, no mínimo (o preenchimento da seta).
const CURSOR_WHITE_MINIMUM: usize = 20;
/// Pixels pretos que o ponteiro tem, no mínimo (o contorno da seta).
const CURSOR_BLACK_MINIMUM: usize = 10;
/// O menor deslocamento que conta como o ponteiro ter andado.
const CURSOR_MINIMUM_STEP: i64 = 8;

/// Um grupo de pixels que mudaram de uma tela para a outra.
#[derive(Clone, Copy, Debug)]
struct Change {
    left: usize,
    top: usize,
    right: usize,
    bottom: usize,
}

impl Change {
    fn width(&self) -> usize {
        self.right - self.left + 1
    }

    fn height(&self) -> usize {
        self.bottom - self.top + 1
    }

    fn center(&self) -> (i64, i64) {
        (((self.left + self.right) / 2) as i64, ((self.top + self.bottom) / 2) as i64)
    }

    fn same_box(&self, other: &Change) -> bool {
        (self.left, self.top, self.right, self.bottom) == (other.left, other.top, other.right, other.bottom)
    }

    fn describe(&self) -> String {
        format!("{}x{} em ({},{})", self.width(), self.height(), self.left, self.top)
    }
}

/// As setas do ponteiro em `image` dentro de `area` (com uma margem do
/// contorno): cada miolo branco (os canais em 0xF0 ou mais, vizinhos na
/// linha ou na coluna) de [`CURSOR_WHITE_MINIMUM`] pixels ou mais, fechado
/// pelo contorno preto: dos pixels em volta dele, a metade ou mais são
/// pretos e pelo menos [`CURSOR_BLACK_MINIMUM`], e o miolo com o contorno
/// cabe em [`CURSOR_MAXIMUM`] de lado. Devolve a caixa de cada uma (o miolo
/// e o contorno). O fundo em volta não conta: a seta sobre um controle
/// aceso, sobre o branco ou sobre a foto é achada do mesmo jeito; o texto
/// branco sem contorno (o relógio) e uma área branca grande não passam.
fn arrows_in(image: &Image, area: &Change) -> Vec<Change> {
    let (width, height) = (image.width, image.height);
    let (left, top) = (area.left.saturating_sub(2), area.top.saturating_sub(2));
    let (right, bottom) = ((area.right + 2).min(width - 1), (area.bottom + 2).min(height - 1));
    let pixel = |x: usize, y: usize| {
        let at = (y * width + x) * 3;
        [image.rgb[at], image.rgb[at + 1], image.rgb[at + 2]]
    };
    let white = |x: usize, y: usize| pixel(x, y).iter().all(|&channel| channel >= 0xF0);
    let box_width = right - left + 1;
    let mut seen = vec![false; box_width * (bottom - top + 1)];
    let mut arrows = Vec::new();
    for y in top..=bottom {
        for x in left..=right {
            if seen[(y - top) * box_width + x - left] || !white(x, y) {
                continue;
            }
            // O miolo: os brancos ligados a este, até passar do tamanho da
            // seta (então é uma área branca, não a seta).
            let mut fill = vec![(x, y)];
            let mut pending = vec![(x, y)];
            seen[(y - top) * box_width + x - left] = true;
            let mut large = false;
            while let Some((cx, cy)) = pending.pop() {
                let neighbours = [(cx.wrapping_sub(1), cy), (cx + 1, cy), (cx, cy.wrapping_sub(1)), (cx, cy + 1)];
                for (nx, ny) in neighbours {
                    if nx < left || nx > right || ny < top || ny > bottom || seen[(ny - top) * box_width + nx - left] || !white(nx, ny) {
                        continue;
                    }
                    seen[(ny - top) * box_width + nx - left] = true;
                    fill.push((nx, ny));
                    pending.push((nx, ny));
                }
                if fill.len() > CURSOR_MAXIMUM * CURSOR_MAXIMUM {
                    large = true;
                }
            }
            if large || fill.len() < CURSOR_WHITE_MINIMUM {
                continue;
            }
            // O contorno: os pixels fora do miolo vizinhos dele.
            let mut outline: std::collections::HashSet<(usize, usize)> = std::collections::HashSet::new();
            for &(cx, cy) in &fill {
                for (nx, ny) in [(cx.wrapping_sub(1), cy), (cx + 1, cy), (cx, cy.wrapping_sub(1)), (cx, cy + 1)] {
                    if nx < width && ny < height && !white(nx, ny) {
                        outline.insert((nx, ny));
                    }
                }
            }
            let black: Vec<&(usize, usize)> = outline.iter().filter(|&&(nx, ny)| is_black(pixel(nx, ny))).collect();
            if black.len() < CURSOR_BLACK_MINIMUM || black.len() * 2 < outline.len() {
                continue;
            }
            let points = fill.iter().chain(black.iter().copied());
            let mut arrow = Change { left: usize::MAX, top: usize::MAX, right: 0, bottom: 0 };
            for &(px, py) in points {
                (arrow.left, arrow.right, arrow.top, arrow.bottom) = (arrow.left.min(px), arrow.right.max(px), arrow.top.min(py), arrow.bottom.max(py));
            }
            if arrow.width() <= CURSOR_MAXIMUM && arrow.height() <= CURSOR_MAXIMUM {
                arrows.push(arrow);
            }
        }
    }
    arrows
}

/// Os grupos de pixels que mudaram de `before` para `after` (mesmo tamanho):
/// as células de [`CURSOR_CELL`] pixels com mudança, ligadas pelos vizinhos
/// (inclusive na diagonal), com a caixa dos pixels mudados de cada grupo.
fn changes(before: &Image, after: &Image) -> Vec<Change> {
    let (columns, rows) = (before.width.div_ceil(CURSOR_CELL), before.height.div_ceil(CURSOR_CELL));
    let mut cells: Vec<Option<Change>> = (0..columns * rows).map(|_| None).collect();
    for (index, (old, new)) in before.rgb.chunks_exact(3).zip(after.rgb.chunks_exact(3)).enumerate() {
        if old == new {
            continue;
        }
        let (x, y) = (index % before.width, index / before.width);
        let cell = &mut cells[(y / CURSOR_CELL) * columns + x / CURSOR_CELL];
        match cell {
            Some(change) => {
                change.left = change.left.min(x);
                change.right = change.right.max(x);
                change.top = change.top.min(y);
                change.bottom = change.bottom.max(y);
            }
            None => *cell = Some(Change { left: x, top: y, right: x, bottom: y }),
        }
    }
    let mut groups = Vec::new();
    for start in 0..cells.len() {
        let Some(first) = cells[start].take() else { continue };
        let mut group = first;
        let mut pending = vec![start];
        while let Some(cell) = pending.pop() {
            let (column, row) = (cell % columns, cell / columns);
            for next_row in row.saturating_sub(1)..=(row + 1).min(rows - 1) {
                for next_column in column.saturating_sub(1)..=(column + 1).min(columns - 1) {
                    let next = next_row * columns + next_column;
                    if let Some(change) = cells[next].take() {
                        group.left = group.left.min(change.left);
                        group.right = group.right.max(change.right);
                        group.top = group.top.min(change.top);
                        group.bottom = group.bottom.max(change.bottom);
                        pending.push(next);
                    }
                }
            }
        }
        groups.push(group);
    }
    groups
}

/// Uma tela desenhada por baixo do ponteiro: a gráfica, com um quarto ou
/// mais fora do preto e sem ser a de bugcheck. O `--mouse` só anda o mouse
/// sobre ela (a tela de bloqueio, não o vídeo de boot preto com o ponteiro).
pub fn drawn_screen(image: &Image) -> Result<String, String> {
    if !is_graphics(image) {
        return Err(format!("a tela e {}x{}, nao a grafica", image.width, image.height));
    }
    let total = image.width * image.height;
    let drawn = image.rgb.chunks_exact(3).filter(|pixel| !is_black([pixel[0], pixel[1], pixel[2]])).count();
    let bugcheck = image.rgb.chunks_exact(3).filter(|pixel| [pixel[0], pixel[1], pixel[2]] == BUGCHECK_BACKGROUND).count();
    if bugcheck * 2 > total {
        return Err("a tela de bugcheck".into());
    }
    if drawn * 4 < total {
        return Err(format!("{}% da tela desenhada (minimo 25%)", drawn * 100 / total));
    }
    Ok(format!("{}% da tela desenhada", drawn * 100 / total))
}

/// O ponteiro andou de `before` para `after`, depois de o mouse andar
/// (`dx`, `dy`) (o sinal de cada eixo; a aceleração do Windows muda a
/// distância): dentro das mudanças da tela há uma seta ([`arrows_in`]) só
/// antes, onde ele estava, e uma só depois, onde ele está, a segunda
/// deslocada da primeira no sentido do movimento. Uma seta parada, o
/// relógio que virou o minuto e o controle que se acendeu sob o ponteiro não
/// contam. Devolve de onde para onde o ponteiro foi, ou o que faltou.
pub fn cursor_moved(before: &Image, after: &Image, dx: i32, dy: i32) -> Result<String, String> {
    if (before.width, before.height) != (after.width, after.height) || before.rgb.len() != after.rgb.len() {
        return Err(format!("a tela mudou de tamanho ({}x{} para {}x{})", before.width, before.height, after.width, after.height));
    }
    let groups = changes(before, after);
    if groups.is_empty() {
        return Err("a tela nao mudou".into());
    }
    let (mut left, mut arrived): (Vec<Change>, Vec<Change>) = (Vec::new(), Vec::new());
    for group in &groups {
        let (old, new) = (arrows_in(before, group), arrows_in(after, group));
        let stays = |arrow: &Change, others: &[Change]| others.iter().any(|other| arrow.same_box(other));
        left.extend(old.iter().filter(|arrow| !stays(arrow, &new)).copied());
        arrived.extend(new.iter().filter(|arrow| !stays(arrow, &old)).copied());
    }
    let all: Vec<String> = groups.iter().take(6).map(Change::describe).collect();
    let (old, new) = match (left.as_slice(), arrived.as_slice()) {
        ([old], [new]) => (old, new),
        _ => {
            return Err(format!(
                "{} mudanca(s) na tela ({}), {} com o ponteiro so antes e {} com o ponteiro so depois (esperado 1 e 1)",
                groups.len(),
                all.join(", "),
                left.len(),
                arrived.len()
            ))
        }
    };
    let ((x0, y0), (x1, y1)) = (old.center(), new.center());
    let (step_x, step_y) = (x1 - x0, y1 - y0);
    let follows = |step: i64, wanted: i32| match wanted.signum() {
        0 => true,
        sign => step.signum() == i64::from(sign),
    };
    if step_x.abs().max(step_y.abs()) < CURSOR_MINIMUM_STEP || !follows(step_x, dx) || !follows(step_y, dy) {
        return Err(format!("o ponteiro foi de ({x0},{y0}) para ({x1},{y1}), fora do sentido do mouse ({dx},{dy})"));
    }
    Ok(format!("o ponteiro foi de ({x0},{y0}) para ({x1},{y1}) com o mouse em ({dx},{dy})"))
}

// ---- tela de bloqueio dispensada --------------------------------------------
//
// O `--dismiss` do test-boot espera a tela de bloqueio parada, aperta a tecla
// e lê a tela até ela sair ([`lock_dismissed`]). A tela de bloqueio do
// LogonUI tem o relógio e a data em branco embaixo à esquerda; quando ela é
// dispensada, sobe e mostra a tela de credenciais por baixo, com outro fundo
// e sem o relógio.

/// O marcador da tela de bloqueio dispensada.
pub const LOGON_DISMISS_MARKER: &str = "LOGON_DISMISS_OK";
/// Pixels brancos que o relógio e a data da tela de bloqueio têm, no mínimo.
const CLOCK_WHITE_MINIMUM: usize = 500;

/// Os pixels brancos da área do relógio e da data da tela de bloqueio: as
/// 2/5 de baixo das linhas e as 3/5 da esquerda das colunas.
pub fn lock_clock(image: &Image) -> usize {
    let (left, right) = (0, image.width * 3 / 5);
    let (top, bottom) = (image.height * 3 / 5, image.height);
    (top..bottom)
        .flat_map(|y| (left..right).map(move |x| (x, y)))
        .filter(|&(x, y)| {
            let at = (y * image.width + x) * 3;
            image.rgb[at..at + 3].iter().all(|&channel| channel >= 0xF0)
        })
        .count()
}

/// `before` é a tela de bloqueio (desenhada, com o relógio e a data: ao
/// menos [`CLOCK_WHITE_MINIMUM`] pixels brancos em [`lock_clock`]); serve de
/// referência para [`lock_dismissed`].
pub fn lock_screen_shown(before: &Image) -> Result<String, String> {
    if !is_graphics(before) {
        return Err(format!("a tela e {}x{}, nao a grafica", before.width, before.height));
    }
    let clock = lock_clock(before);
    if clock < CLOCK_WHITE_MINIMUM {
        return Err(format!("{clock} pixels brancos na area do relogio (minimo {CLOCK_WHITE_MINIMUM})"));
    }
    let drawn = before.rgb.chunks_exact(3).filter(|pixel| !is_black([pixel[0], pixel[1], pixel[2]])).count();
    if drawn * 4 < before.width * before.height {
        return Err(format!("{}% da tela desenhada (minimo 25%)", drawn * 100 / (before.width * before.height)));
    }
    Ok(format!("{clock} pixels brancos na area do relogio, {}% da tela desenhada", drawn * 100 / (before.width * before.height)))
}

/// A tela de bloqueio `before` ([`lock_screen_shown`]) saiu em `after`: a
/// metade ou mais dos pixels mudou, o relógio e a data sumiram (na área
/// deles ficou 1/10 ou menos dos pixels brancos) e a tela continua
/// desenhada (um quarto ou mais fora do preto, sem ser a tela de bugcheck):
/// a tela de credenciais, não a tela apagada nem uma parada.
pub fn lock_dismissed(before: &Image, after: &Image) -> Result<String, String> {
    if (before.width, before.height) != (after.width, after.height) || before.rgb.len() != after.rgb.len() {
        return Err(format!("a tela mudou de tamanho ({}x{} para {}x{})", before.width, before.height, after.width, after.height));
    }
    let total = after.width * after.height;
    let changed = before.rgb.chunks_exact(3).zip(after.rgb.chunks_exact(3)).filter(|(x, y)| x != y).count();
    let (clock_before, clock_after) = (lock_clock(before), lock_clock(after));
    let drawn = after.rgb.chunks_exact(3).filter(|pixel| !is_black([pixel[0], pixel[1], pixel[2]])).count();
    let bugcheck = after.rgb.chunks_exact(3).filter(|pixel| [pixel[0], pixel[1], pixel[2]] == BUGCHECK_BACKGROUND).count();
    let mut missing = Vec::new();
    if changed * 2 < total {
        missing.push(format!("{}% dos pixels mudaram (minimo 50%)", changed * 100 / total));
    }
    if clock_after * 10 > clock_before {
        missing.push(format!("o relogio ainda na tela ({clock_after} de {clock_before} pixels brancos)"));
    }
    if drawn * 4 < total {
        missing.push(format!("{}% da tela desenhada (minimo 25%)", drawn * 100 / total));
    }
    if bugcheck * 2 > total {
        missing.push("a tela de bugcheck".into());
    }
    if !missing.is_empty() {
        return Err(missing.join("; "));
    }
    Ok(format!(
        "{}% dos pixels mudaram, o relogio saiu ({clock_before} -> {clock_after} pixels brancos), {}% da tela desenhada",
        changed * 100 / total,
        drawn * 100 / total
    ))
}

// ---- área de trabalho ---------------------------------------------------------
//
// Numa conta nova do 19041, o perfil Default dá o papel de parede
// `C:\Windows\Web\Wallpaper\Windows\img0.jpg` (1920x1200: o azul com os
// feixes de luz e a janela do Windows) em modo Preencher (WallpaperStyle
// 10) e o fundo preto (Colors\Background 0 0 0). O shell32 desenha o papel
// de parede na janela da área de trabalho, e o CTranscodedImage troca o
// img0 padrão pelo `Web\4K\Wallpaper\Windows\img0_1024x768.jpg` quando o
// monitor principal tem até 1024x768 (_CheckSystemWallpaperForBestMatch,
// shell32 0x5026a4; sem o arquivo fica o img0.jpg). A barra de tarefas (o
// tema escuro do sistema, o padrão do 19041) fica embaixo, com 40 linhas a
// 96 DPI, opaca ou translúcida sobre o papel de parede, com o Iniciar, a
// caixa de busca, os ícones fixados e a área de notificação. Os limites
// abaixo vêm das duas imagens decodificadas pelo GDI+ na tela de 1024x768
// (o img0.jpg reduzido para cobrir a tela e o img0_1024x768.jpg inteiro),
// com uma barra modelada de 40 linhas: opaca (#101010 ou #202020) ou #202020
// translúcida de 55% a 85%, com a caixa de busca clara de 344 colunas ou sem
// ela, em 800x600, 1024x768 e 1280x800:
//
// - o fundo acima da barra: 99% dos pixels azuis (o azul passa o vermelho
//   por 32 ou mais e não fica abaixo do verde), 99% dos vizinhos suaves, 204
//   a 320 cores com 512 pixels ou mais, cor média de #0287E4 a #038EEA e
//   verde médio de 166 ou 167 na metade esquerda (a dos feixes de luz) e de
//   105 a 117 na direita;
// - o canal mais forte de cada pixel do img0 vai de 169 a 255: nenhum pixel
//   dele conta como barra;
// - a barra: 40 linhas (30 e 48 nos outros tamanhos dela) com 56% a 93% dos
//   pixels escuros; a linha que cruza a caixa de busca clara fica com 32%
//   (800x600) a 58% (1280x800).
//
// Não passam:
//
// - a tela de bloqueio (o img100.jpg): 26% de pixels azuis, cor média
//   #1E3039, mais clara à direita, e o chão escuro da caverna dá centenas
//   de linhas escuras embaixo;
// - a cor de destaque com texto (a animação do primeiro logon, o
//   Bem-vindo, a tela de bugcheck): 1 ou 2 cores;
// - a área de trabalho sem a barra, ou a barra sobre o fundo preto do
//   perfil (o papel de parede que não carregou);
// - a imagem surgindo do preto (o img0 pela metade é todo escuro), memória
//   lida como cor, ruído e um quadro pela metade.

/// O marcador da área de trabalho.
pub const DESKTOP_MARKER: &str = "DESKTOP_OK";
/// A vigia só procura a área de trabalho depois deste marcador na serial:
/// o explorer.exe que o userinit.exe criou com o token do usuário
/// (`initial_process.rs`).
pub const DESKTOP_AFTER: &str = "EXPLORER_STARTED";
/// Um pixel da barra de tarefas: nenhum canal acima disto.
const TASKBAR_DARK: u8 = 0x80;
/// Uma linha é da barra com pelo menos 3/10 dos pixels escuros (a caixa de
/// busca clara e os ícones tiram até dois terços de uma linha em 800x600).
const TASKBAR_ROW: (usize, usize) = (3, 10);
/// A barra, contada de baixo para cima: 30 linhas com botões pequenos, 40 a
/// 96 DPI, 48 a 120%.
const TASKBAR_ROWS: core::ops::RangeInclusive<usize> = 24..=72;
/// Pelo menos 2/5 da barra escura.
const TASKBAR_SHARE: (usize, usize) = (2, 5);
/// Um pixel azul do papel de parede: o azul passa o vermelho pelo menos
/// por isto e não fica abaixo do verde.
const BLUE_OVER_RED: u16 = 32;
/// Pelo menos 3/5 do fundo azul.
const WALLPAPER_BLUE: (usize, usize) = (3, 5);
/// A cor média do fundo, canal a canal (o img0: #0287E4 a #038EEA).
const WALLPAPER_MEAN: ([u8; 3], [u8; 3]) = ([0x00, 0x60, 0xB0], [0x30, 0xC0, 0xFF]);
/// O verde médio da metade esquerda do fundo passa o da direita pelo menos
/// por isto (o img0: 51 a 61, os feixes de luz à esquerda).
const WALLPAPER_LEFT_LIGHTER: u64 = 0x18;

fn is_taskbar_dark(rgb: [u8; 3]) -> bool {
    rgb.iter().all(|&channel| channel <= TASKBAR_DARK)
}

fn is_wallpaper_blue(rgb: [u8; 3]) -> bool {
    !is_black(rgb) && u16::from(rgb[2]) >= u16::from(rgb[0]) + BLUE_OVER_RED && rgb[2] >= rgb[1]
}

/// As medidas de [`desktop_screen`] numa tela gráfica.
struct DesktopMeasures {
    width: usize,
    height: usize,
    /// As linhas da barra de tarefas, contadas de baixo para cima até a
    /// primeira com menos de 3/10 dos pixels escuros, e os pixels escuros
    /// nelas.
    taskbar: usize,
    taskbar_dark: usize,
    /// Os pixels do fundo (as linhas acima da barra), os azuis, os pares de
    /// vizinhos desenhados na linha e os suaves.
    wallpaper: usize,
    blue: usize,
    pairs: usize,
    smooth: usize,
    /// As cores do fundo com pelo menos 1/[`LOGON_COLOR_SHARE`] da tela.
    colors: usize,
    /// A cor média do fundo e o verde médio das metades esquerda e direita.
    mean: [u8; 3],
    left_green: u64,
    right_green: u64,
    /// Pixels do fundo azul da tela de bugcheck.
    bugcheck: usize,
}

impl DesktopMeasures {
    fn of(image: &Image) -> DesktopMeasures {
        let (width, height) = (image.width, image.height);
        let rows: Vec<&[u8]> = image.rgb.chunks_exact(width * 3).take(height).collect();
        let (row_part, row_whole) = TASKBAR_ROW;
        let (mut taskbar, mut taskbar_dark) = (0, 0);
        for row in rows.iter().rev() {
            let dark = row.chunks_exact(3).filter(|pixel| is_taskbar_dark([pixel[0], pixel[1], pixel[2]])).count();
            if dark * row_whole < width * row_part {
                break;
            }
            taskbar += 1;
            taskbar_dark += dark;
        }
        let above = rows.len() - taskbar;
        let mut measures = DesktopMeasures { width, height, taskbar, taskbar_dark, wallpaper: above * width, blue: 0, pairs: 0, smooth: 0, colors: 0, mean: [0; 3], left_green: 0, right_green: 0, bugcheck: 0 };
        let mut colors: HashMap<[u8; 3], usize> = HashMap::new();
        let mut sums = [0u64; 3];
        let (mut left, mut right) = (0u64, 0u64);
        for row in &rows[..above] {
            let mut previous: Option<[u8; 3]> = None;
            for (x, pixel) in row.chunks_exact(3).enumerate() {
                let rgb = [pixel[0], pixel[1], pixel[2]];
                if rgb == BUGCHECK_BACKGROUND {
                    measures.bugcheck += 1;
                }
                for (sum, channel) in sums.iter_mut().zip(rgb) {
                    *sum += u64::from(channel);
                }
                if x < width / 2 {
                    left += u64::from(rgb[1]);
                } else {
                    right += u64::from(rgb[1]);
                }
                *colors.entry(rgb).or_default() += 1;
                if is_wallpaper_blue(rgb) {
                    measures.blue += 1;
                }
                if is_black(rgb) {
                    previous = None;
                    continue;
                }
                if let Some(before) = previous {
                    measures.pairs += 1;
                    if before.iter().zip(rgb).all(|(&a, b)| a.abs_diff(b) <= SMOOTH_STEP) {
                        measures.smooth += 1;
                    }
                }
                previous = Some(rgb);
            }
        }
        let minimum = measures.color_minimum();
        measures.colors = colors.values().filter(|&&count| count >= minimum).count();
        let count = measures.wallpaper.max(1) as u64;
        measures.mean = sums.map(|sum| (sum / count) as u8);
        measures.left_green = left / (above * (width / 2)).max(1) as u64;
        measures.right_green = right / (above * (width - width / 2)).max(1) as u64;
        measures
    }

    fn total(&self) -> usize {
        self.width * self.height
    }

    /// Os pixels que uma cor do fundo precisa ter para contar.
    fn color_minimum(&self) -> usize {
        (self.total() / LOGON_COLOR_SHARE).max(1)
    }

    /// O que falta para ser a área de trabalho (vazio: nada).
    fn missing(&self) -> Vec<String> {
        let percent = LogonMeasures::percent;
        let mut missing = Vec::new();
        if self.bugcheck * 2 > self.total() {
            missing.push("e a tela de bugcheck".to_string());
        }
        if !TASKBAR_ROWS.contains(&self.taskbar) {
            missing.push(format!("barra de tarefas escura de {} linhas embaixo (de {} a {})", self.taskbar, TASKBAR_ROWS.start(), TASKBAR_ROWS.end()));
        } else if self.taskbar_dark * TASKBAR_SHARE.1 < self.taskbar * self.width * TASKBAR_SHARE.0 {
            missing.push(format!("{}% da barra de tarefas escura (minimo {}%)", percent(self.taskbar_dark, self.taskbar * self.width), 100 * TASKBAR_SHARE.0 / TASKBAR_SHARE.1));
        }
        if self.blue * WALLPAPER_BLUE.1 < self.wallpaper * WALLPAPER_BLUE.0 {
            missing.push(format!("{}% do fundo azul (minimo {}%)", percent(self.blue, self.wallpaper), 100 * WALLPAPER_BLUE.0 / WALLPAPER_BLUE.1));
        }
        if self.smooth * LOGON_SMOOTH_DIVISOR < self.pairs {
            missing.push(format!("{}% dos vizinhos do fundo suaves (minimo {}%)", percent(self.smooth, self.pairs), 100 / LOGON_SMOOTH_DIVISOR));
        }
        if self.colors < LOGON_COLORS {
            missing.push(format!("{} cores do fundo com {} pixels ou mais (minimo {LOGON_COLORS})", self.colors, self.color_minimum()));
        }
        let (low, high) = WALLPAPER_MEAN;
        if (0..3).any(|channel| self.mean[channel] < low[channel] || self.mean[channel] > high[channel]) {
            missing.push(format!(
                "cor media do fundo #{:02x}{:02x}{:02x} (de #{:02x}{:02x}{:02x} a #{:02x}{:02x}{:02x})",
                self.mean[0], self.mean[1], self.mean[2], low[0], low[1], low[2], high[0], high[1], high[2]
            ));
        }
        if self.left_green < self.right_green + WALLPAPER_LEFT_LIGHTER {
            missing.push(format!("verde medio de {} a esquerda e {} a direita (minimo {WALLPAPER_LEFT_LIGHTER} a mais a esquerda)", self.left_green, self.right_green));
        }
        missing
    }

    fn describe(&self) -> String {
        format!(
            "barra de tarefas de {} linhas embaixo ({}% escura); fundo: {}% azul, {}% dos vizinhos suaves, {} cores com {} pixels ou mais, cor media #{:02x}{:02x}{:02x}, verde medio {} a esquerda e {} a direita",
            self.taskbar,
            LogonMeasures::percent(self.taskbar_dark, self.taskbar * self.width),
            LogonMeasures::percent(self.blue, self.wallpaper),
            LogonMeasures::percent(self.smooth, self.pairs),
            self.colors,
            self.color_minimum(),
            self.mean[0],
            self.mean[1],
            self.mean[2],
            self.left_green,
            self.right_green
        )
    }
}

/// A área de trabalho do Windows 10 numa tela do QEMU: a descrição dela, ou
/// o que falta. É uma tela gráfica ([`is_graphics`]) que não é a de
/// bugcheck, com a barra de tarefas escura embaixo (de 24 a 72 linhas, cada
/// uma com 3/10 ou mais dos pixels escuros, e 2/5 ou mais da barra) e, acima
/// dela, o papel de parede azul do img0: 3/5 ou mais dos pixels azuis, a
/// maior parte dos vizinhos suaves, pelo menos [`LOGON_COLORS`] cores de
/// 1/[`LOGON_COLOR_SHARE`] da tela, a cor média dele e a metade esquerda
/// mais clara (os números medidos estão acima).
pub fn desktop_screen(image: &Image) -> Result<String, String> {
    if !is_graphics(image) {
        return Err(format!("tela {}x{}, nao e uma tela grafica de 800x600 ou mais", image.width, image.height));
    }
    let measures = DesktopMeasures::of(image);
    let missing = measures.missing();
    if missing.is_empty() {
        Ok(measures.describe())
    } else {
        Err(missing.join("; "))
    }
}

/// Telas sintéticas para os testes da vigia.
#[cfg(test)]
pub mod samples {
    use crate::png::Image;

    pub const WIDTH: usize = 1024;
    pub const HEIGHT: usize = 768;

    pub fn filled(width: usize, height: usize, fill: [u8; 3]) -> Image {
        Image { width, height, rgb: fill.iter().copied().cycle().take(width * height * 3).collect() }
    }

    pub fn paint(image: &mut Image, x: std::ops::Range<usize>, y: std::ops::Range<usize>, color: impl Fn(usize, usize) -> [u8; 3]) {
        for row in y {
            for column in x.clone() {
                let at = (row * image.width + column) * 3;
                image.rgb[at..at + 3].copy_from_slice(&color(column, row));
            }
        }
    }

    /// Os traços brancos do relógio e da data, embaixo à esquerda; `minute`
    /// muda o último dígito.
    pub fn clock(image: &mut Image, minute: usize) {
        const WHITE: [u8; 3] = [0xFF, 0xFF, 0xFF];
        for digit in 0..4 {
            let left = 48 + digit * 64 + usize::from(digit >= 2) * 24;
            let shape = if digit == 3 { minute % 3 } else { digit % 3 };
            paint(image, left..left + 8, 470..560, |_, _| WHITE);
            paint(image, left..left + 48, 470..478, |_, _| WHITE);
            paint(image, left..left + 48, 552..560, |_, _| WHITE);
            if shape != 0 {
                paint(image, left..left + 48, 511..519, |_, _| WHITE);
            }
            if shape == 2 {
                paint(image, left + 40..left + 48, 470..560, |_, _| WHITE);
            }
        }
        for word in 0..3 {
            let left = 54 + word * 150;
            paint(image, left..left + 120, 610..614, |_, _| WHITE);
            paint(image, left..left + 120, 632..636, |_, _| WHITE);
        }
    }

    /// Uma tela de bloqueio com a forma da do img100.jpg em 1024x768: a
    /// caverna escura em volta, a rocha iluminada à direita e a areia
    /// embaixo, com textura (nenhuma cor delas chega a 512 pixels), e o céu
    /// no meio em 17 faixas de degradê (as 17 cores de 512 pixels ou mais da
    /// imagem real); com `clock_too`, o relógio e a data em branco.
    pub fn lock_screen(clock_too: bool) -> Image {
        let mut image = filled(WIDTH, HEIGHT, [0x0C, 0x0A, 0x08]);
        paint(&mut image, 900..WIDTH, 0..540, |x, y| [0x50 + (y / 40) as u8, 0x3C + ((x / 4) % 16) as u8, 0x28 + ((y / 3) % 16) as u8]);
        paint(&mut image, 240..860, 110..440, |_, y| {
            let band = ((y - 110) / 20) as u8;
            [band * 6, 0x5E + band * 4, 0x9E + band * 3]
        });
        paint(&mut image, 300..WIDTH, 440..640, |x, y| {
            let step = ((y - 440) / 6) as u8;
            [0xC8 - step, 0x96 - step, 0x50 + ((x / 8) % 32) as u8]
        });
        if clock_too {
            clock(&mut image, 0);
        }
        image
    }

    /// A seta do ponteiro (12x19, contorno preto e miolo branco) com a
    /// ponta em (`x`, `y`).
    pub fn pointer(image: &mut Image, x: usize, y: usize) {
        for row in 0..19 {
            let width = (row + 1).min(12);
            for column in 0..width {
                let edge = column == 0 || column + 1 == width || row == 18;
                let at = ((y + row) * image.width + x + column) * 3;
                image.rgb[at..at + 3].copy_from_slice(if edge { &[0, 0, 0] } else { &[0xFF, 0xFF, 0xFF] });
            }
        }
    }

    /// As linhas fora de `rows` pretas: um quadro rasgado ou pela metade.
    pub fn only_rows(image: &Image, rows: std::ops::Range<usize>) -> Image {
        let mut out = filled(image.width, image.height, [0, 0, 0]);
        let line = image.width * 3;
        out.rgb[rows.start * line..rows.end * line].copy_from_slice(&image.rgb[rows.start * line..rows.end * line]);
        out
    }

    /// As colunas fora de `columns` pretas.
    pub fn only_columns(image: &Image, columns: std::ops::Range<usize>) -> Image {
        let mut out = filled(image.width, image.height, [0, 0, 0]);
        for row in 0..image.height {
            let (start, end) = ((row * image.width + columns.start) * 3, (row * image.width + columns.end) * 3);
            out.rgb[start..end].copy_from_slice(&image.rgb[start..end]);
        }
        out
    }

    /// Bytes quaisquer como cor: os do executável deste teste (código e
    /// dados de verdade), repetidos até encher a tela.
    pub fn memory_as_pixels() -> Image {
        let bytes = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let start = bytes.len().min(4096);
        let rgb = bytes[start..].iter().copied().cycle().take(WIDTH * HEIGHT * 3).collect();
        Image { width: WIDTH, height: HEIGHT, rgb }
    }

    /// Ruído: cada canal de um gerador congruente.
    pub fn noise() -> Image {
        let mut state = 0x2545_F491_u32;
        let rgb = (0..WIDTH * HEIGHT * 3)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect();
        Image { width: WIDTH, height: HEIGHT, rgb }
    }

    /// Um papel de parede com a forma do img0_1024x768.jpg: o azul, mais
    /// claro à esquerda, onde ficam os feixes de luz, em 16 faixas de 64
    /// colunas por 8 de 96 linhas (128 tons de 6144 pixels cada, como as
    /// centenas de tons de 512 pixels ou mais do img0).
    pub fn wallpaper() -> Image {
        let mut image = filled(WIDTH, HEIGHT, [0, 0, 0]);
        paint(&mut image, 0..WIDTH, 0..HEIGHT, |x, y| {
            let (column, row) = ((x / 64) as u8, (y / 96) as u8);
            [0x02, 0xB0 - column * 5 + row, 0xF8 - column * 3]
        });
        image
    }

    /// A barra de tarefas escura nas `height` linhas de baixo: #202020 com
    /// opacidade `alpha`/256 sobre o que está embaixo (256 = opaca), o
    /// logotipo do Iniciar, a caixa de busca clara de 344 colunas
    /// (`search_box`), os botões da Cortana e da Visão de Tarefas, quatro
    /// ícones fixados coloridos e a área de notificação com o relógio, todos
    /// cheios (o pior caso para a parte escura da barra).
    pub fn taskbar(image: &mut Image, height: usize, alpha: u32, search_box: bool) {
        const WHITE: [u8; 3] = [0xFF, 0xFF, 0xFF];
        let (width, top) = (image.width, image.height - height);
        let middle = top + height / 2;
        for channel in &mut image.rgb[top * width * 3..] {
            *channel = ((0x20 * alpha + u32::from(*channel) * (256 - alpha)) / 256) as u8;
        }
        for (x, y) in [(16, middle - 8), (25, middle - 8), (16, middle + 1), (25, middle + 1)] {
            paint(image, x..x + 7, y..y + 7, |_, _| WHITE);
        }
        if search_box {
            let bottom = image.height - 4;
            paint(image, 48..392, top + 4..bottom, |_, _| [0xF2, 0xF2, 0xF2]);
            paint(image, 60..74, middle - 7..middle + 7, |_, _| [0x20, 0x20, 0x20]);
        }
        paint(image, 408..424, middle - 8..middle + 8, |_, _| WHITE);
        for (x, y) in [(454..474, middle - 8..middle - 6), (454..474, middle + 6..middle + 8), (454..456, middle - 8..middle + 8), (472..474, middle - 8..middle + 8)] {
            paint(image, x, y, |_, _| WHITE);
        }
        for (index, color) in [[0x00, 0x78, 0xD7], [0xF8, 0xD7, 0x75], [0x00, 0x78, 0xD7], [0x00, 0x63, 0xB1]].into_iter().enumerate() {
            let left = 500 + index * 48;
            paint(image, left..left + 24, middle - 12..middle + 12, |_, _| color);
        }
        for left in [width - 200, width - 176, width - 152, width - 32] {
            paint(image, left..left + 16, middle - 8..middle + 8, |_, _| WHITE);
        }
        paint(image, width - 120..width - 60, middle - 12..middle - 4, |_, _| WHITE);
        paint(image, width - 120..width - 60, middle + 4..middle + 12, |_, _| WHITE);
    }

    /// A área de trabalho: o [`wallpaper`] com a [`taskbar`].
    pub fn desktop(height: usize, alpha: u32, search_box: bool) -> Image {
        let mut image = wallpaper();
        taskbar(&mut image, height, alpha, search_box);
        image
    }
}

#[cfg(test)]
mod tests {
    use super::samples::*;
    use super::*;

    #[test]
    fn drawn_pixels_needs_a_graphics_screen_with_drawing() {
        // Preto: o vídeo de boot.
        assert!(drawn_pixels(&filled(1024, 768, [0, 0, 0])).is_none());
        // A tela de texto da VGA (720x400) e o aviso do QEMU (640x480) não
        // contam.
        assert!(drawn_pixels(&filled(720, 400, [0xAA, 0xAA, 0xAA])).is_none());
        assert!(drawn_pixels(&filled(640, 480, [0xFF, 0xFF, 0xFF])).is_none());
        // A tela de bugcheck não conta.
        assert!(drawn_pixels(&filled(1024, 768, BUGCHECK_BACKGROUND)).is_none());
        // Um retângulo branco de 16x16 conta, com a caixa e a cor.
        let mut image = filled(1024, 768, [0, 0, 0]);
        paint(&mut image, 200..216, 100..116, |_, _| [0xFF, 0xFF, 0xFF]);
        let description = drawn_pixels(&image).expect("16x16 desenhados");
        assert!(description.starts_with("256 pixels desenhados na tela 1024x768, de (200,100) a (215,115)"), "{description}");
        assert!(description.contains("#ffffff x256"), "{description}");
        // Menos que o mínimo: ruído, não desenho.
        let mut few = filled(1024, 768, [0, 0, 0]);
        few.rgb[0..3].copy_from_slice(&[0xFF, 0, 0]);
        assert!(drawn_pixels(&few).is_none());
    }

    /// A tela de bloqueio sintética passa com e sem o relógio: a fonte que
    /// falta não reprova a tela de logon. Sem o relógio sobram as 17 cores
    /// do céu, como na imagem real.
    #[test]
    fn lock_screen_passes_with_and_without_the_clock() {
        for (clock_too, colors) in [(true, 18), (false, 17)] {
            let description = logon_screen(&lock_screen(clock_too)).unwrap_or_else(|missing| panic!("relogio {clock_too}: {missing}"));
            assert!(description.contains(&format!(", {colors} cores com 512 pixels ou mais")), "{description}");
        }
        let measures = LogonMeasures::of(&lock_screen(true));
        assert!(measures.smooth * 10 >= measures.pairs * 9, "a imagem e suave: {} de {}", measures.smooth, measures.pairs);
        // Esmaecida pela metade (a imagem surgindo do preto), ainda é ela.
        let mut faded = lock_screen(true);
        faded.rgb.iter_mut().for_each(|channel| *channel /= 2);
        assert!(logon_screen(&faded).is_ok(), "{:?}", logon_screen(&faded));
    }

    #[test]
    fn pointer_flat_colors_and_bugcheck_are_not_a_logon_screen() {
        // O ponteiro sobre o preto e uma tela de cor única não são a tela de
        // logon; a de bugcheck também não.
        let mut pointer = filled(1024, 768, [0, 0, 0]);
        pointer.rgb[0..3 * 73].fill(0xFF);
        assert!(logon_screen(&pointer).is_err());
        assert!(logon_screen(&filled(1024, 768, [0x10, 0x60, 0xA0])).unwrap_err().contains("cores com 512 pixels"));
        assert!(logon_screen(&filled(1024, 768, BUGCHECK_BACKGROUND)).unwrap_err().contains("bugcheck"));
        assert!(logon_screen(&filled(720, 400, [0xAA, 0xAA, 0xAA])).unwrap_err().contains("720x400"));
        // A cor de destaque com o relógio e a data (o LogonUI sem a imagem):
        // a cor lisa e o branco, nada mais.
        let mut accent = filled(1024, 768, [0x00, 0x78, 0xD7]);
        clock(&mut accent, 0);
        let missing = logon_screen(&accent).unwrap_err();
        assert!(missing.starts_with("2 cores com 512 pixels ou mais (minimo 8)"), "{missing}");
        // Metade da tela de cores, mas com só 4 cores: não basta.
        let mut four = filled(1024, 768, [0, 0, 0]);
        for (index, pixel) in four.rgb.chunks_exact_mut(3).enumerate().filter(|(index, _)| index % 1024 < 512) {
            pixel.copy_from_slice(&[0x80, (index % 4) as u8 * 0x30 + 0x40, 0x80]);
        }
        assert!(logon_screen(&four).is_err());
    }

    /// Lixo cobrindo a tela inteira, com muitas cores repetidas, não passa:
    /// os vizinhos não são suaves.
    #[test]
    fn memory_and_noise_are_not_a_logon_screen() {
        let memory = memory_as_pixels();
        let measures = LogonMeasures::of(&memory);
        assert!(measures.smooth * 2 < measures.pairs, "{} de {} pares suaves", measures.smooth, measures.pairs);
        assert!(logon_screen(&memory).unwrap_err().contains("dos vizinhos suaves"));
        let missing = logon_screen(&noise()).unwrap_err();
        assert!(missing.contains("dos vizinhos suaves") && missing.contains("0 cores"), "{missing}");
    }

    /// Um quadro pela metade não passa: a tela de bloqueio cobre a tela.
    #[test]
    fn partial_frames_are_not_a_logon_screen() {
        let full = lock_screen(true);
        let torn = logon_screen(&only_rows(&full, 0..HEIGHT / 2)).unwrap_err();
        assert!(torn.contains("% das linhas"), "{torn}");
        let band = logon_screen(&only_rows(&full, HEIGHT * 3 / 10..HEIGHT * 7 / 10)).unwrap_err();
        assert!(band.contains("% das linhas"), "{band}");
        for half in [0..WIDTH / 2, WIDTH / 2..WIDTH] {
            let missing = logon_screen(&only_columns(&full, half.clone())).unwrap_err();
            assert!(missing.contains("% das colunas"), "{half:?}: {missing}");
        }
    }

    /// O ponteiro que andou: a seta sai de um lugar e aparece no outro, no
    /// sentido do mouse, mesmo com o relógio virando o minuto; a tela
    /// parada, só o relógio, a seta no sentido contrário e a seta que sumiu
    /// não passam.
    #[test]
    fn cursor_moved_sees_the_arrow_leave_and_arrive() {
        let background = |minute| {
            let mut image = filled(WIDTH, HEIGHT, [0x00, 0x4A, 0x7F]);
            clock(&mut image, minute);
            image
        };
        let with_pointer = |minute, x, y| {
            let mut image = background(minute);
            pointer(&mut image, x, y);
            image
        };
        let before = with_pointer(0, 512, 384);
        let moved = cursor_moved(&before, &with_pointer(0, 640, 470), 150, 100).unwrap();
        assert!(moved.starts_with("o ponteiro foi de (517,393) para (645,479)"), "{moved}");
        let ticked = cursor_moved(&before, &with_pointer(1, 640, 470), 150, 100);
        assert!(ticked.is_ok(), "o relogio virou o minuto: {ticked:?}");
        assert_eq!(cursor_moved(&before, &before, 150, 100).unwrap_err(), "a tela nao mudou");
        let clock_only = cursor_moved(&before, &with_pointer(1, 512, 384), 150, 100).unwrap_err();
        assert!(clock_only.contains("0 com o ponteiro so antes e 0 com o ponteiro so depois"), "{clock_only}");
        let backwards = cursor_moved(&before, &with_pointer(0, 400, 300), 150, 100).unwrap_err();
        assert!(backwards.contains("fora do sentido do mouse"), "{backwards}");
        let gone = cursor_moved(&before, &background(0), 150, 100).unwrap_err();
        assert!(gone.contains("1 com o ponteiro so antes e 0 com o ponteiro so depois"), "{gone}");
        let resized = cursor_moved(&before, &filled(800, 600, [0, 0, 0]), 150, 100).unwrap_err();
        assert!(resized.contains("mudou de tamanho"), "{resized}");
        // O mouse só anda sobre uma tela desenhada: a de bloqueio passa; o
        // vídeo de boot preto com o ponteiro e a tela de bugcheck não.
        assert!(drawn_screen(&before).is_ok());
        let mut boot = filled(WIDTH, HEIGHT, [0, 0, 0]);
        pointer(&mut boot, 512, 384);
        assert!(drawn_screen(&boot).unwrap_err().contains("da tela desenhada"));
        assert!(drawn_screen(&filled(WIDTH, HEIGHT, BUGCHECK_BACKGROUND)).unwrap_err().contains("bugcheck"));
    }

    /// O ponteiro que para sobre um controle que se acende (como o botão de
    /// energia do LogonUI, 48x48 em (952,698)): o controle muda em volta da
    /// seta, numa mudança maior que ela, e a seta é achada pela forma com o
    /// fundo aceso escuro, claro ou branco. A seta parada sobre o controle que
    /// se acendeu não andou; a seta que anda pouco, com os dois lugares numa
    /// mudança só, andou.
    #[test]
    fn cursor_moved_finds_the_arrow_over_a_highlighted_control() {
        const BACKGROUND: [u8; 3] = [0x00, 0x4A, 0x7F];
        let screen = |highlight: Option<[u8; 3]>, x: usize, y: usize| {
            let mut image = filled(WIDTH, HEIGHT, BACKGROUND);
            paint(&mut image, 952..1000, 698..746, |_, _| highlight.unwrap_or(BACKGROUND));
            // O ícone do botão: um traço branco sem contorno.
            paint(&mut image, 968..984, 730..733, |_, _| [0xFF, 0xFF, 0xFF]);
            pointer(&mut image, x, y);
            image
        };
        let before = screen(None, 820, 610);
        for highlight in [[0x1A, 0x5C, 0x8E], [0xCC, 0xCC, 0xCC], [0xFF, 0xFF, 0xFF]] {
            let after = screen(Some(highlight), 960, 705);
            let moved = cursor_moved(&before, &after, 150, 100).unwrap_or_else(|missing| panic!("{highlight:?}: {missing}"));
            assert!(moved.starts_with("o ponteiro foi de (825,619) para (965,714)"), "{highlight:?}: {moved}");
        }
        let still = cursor_moved(&screen(None, 960, 705), &screen(Some([0x1A, 0x5C, 0x8E]), 960, 705), 150, 100).unwrap_err();
        assert!(still.contains("0 com o ponteiro so antes e 0 com o ponteiro so depois"), "{still}");
        let near = |x, y| {
            let mut image = filled(WIDTH, HEIGHT, BACKGROUND);
            pointer(&mut image, x, y);
            image
        };
        assert_eq!(changes(&near(512, 384), &near(528, 392)).len(), 1, "os dois lugares numa mudanca so");
        let moved = cursor_moved(&near(512, 384), &near(528, 392), 16, 8).unwrap();
        assert!(moved.starts_with("o ponteiro foi de (517,393) para (533,401)"), "{moved}");
    }

    /// A tela de bloqueio dispensada: a de credenciais (outro fundo, sem o
    /// relógio) passa; a mesma tela, só o ponteiro, a tela apagada e a de
    /// bugcheck não. Sem o relógio, a tela não serve de referência.
    #[test]
    fn lock_dismissed_needs_the_clock_gone_and_a_drawn_screen() {
        let mut lock = filled(WIDTH, HEIGHT, [0x00, 0x4A, 0x7F]);
        clock(&mut lock, 0);
        pointer(&mut lock, 512, 384);
        assert!(lock_screen_shown(&lock).is_ok(), "{:?}", lock_screen_shown(&lock));
        let flat = filled(WIDTH, HEIGHT, [0x00, 0x4A, 0x7F]);
        assert!(lock_screen_shown(&flat).unwrap_err().contains("area do relogio"));
        let mut black = filled(WIDTH, HEIGHT, [0, 0, 0]);
        clock(&mut black, 0);
        assert!(lock_screen_shown(&black).unwrap_err().contains("da tela desenhada"));

        let mut credentials = filled(WIDTH, HEIGHT, [0x00, 0x33, 0x58]);
        paint(&mut credentials, 900..930, 700..730, |_, _| [0xFF, 0xFF, 0xFF]);
        pointer(&mut credentials, 512, 384);
        let dismissed = lock_dismissed(&lock, &credentials).unwrap();
        assert!(dismissed.contains("o relogio saiu"), "{dismissed}");

        assert!(lock_dismissed(&lock, &lock).unwrap_err().contains("0% dos pixels mudaram"));
        let mut moved = lock.clone();
        pointer(&mut moved, 700, 500);
        assert!(lock_dismissed(&lock, &moved).unwrap_err().contains("o relogio ainda na tela"));
        assert!(lock_dismissed(&lock, &filled(WIDTH, HEIGHT, [0, 0, 0])).unwrap_err().contains("da tela desenhada"));
        assert!(lock_dismissed(&lock, &filled(WIDTH, HEIGHT, BUGCHECK_BACKGROUND)).unwrap_err().contains("bugcheck"));
        // O fundo que muda com o relógio ainda lá (a imagem da tela de
        // bloqueio que chegou tarde) não é a tela dispensada.
        let mut repainted = filled(WIDTH, HEIGHT, [0x30, 0x50, 0x20]);
        clock(&mut repainted, 0);
        assert!(lock_dismissed(&lock, &repainted).unwrap_err().contains("o relogio ainda na tela"));
    }

    #[test]
    fn same_screen_takes_the_clock_but_not_a_torn_frame() {
        let (twelve, one_more) = (lock_screen(true), {
            let mut image = lock_screen(false);
            clock(&mut image, 1);
            image
        });
        assert!(twelve != one_more);
        assert!(same_screen(&twelve, &twelve));
        assert!(same_screen(&twelve, &one_more), "o relogio muda de minuto");
        assert!(!same_screen(&twelve, &only_rows(&twelve, 0..HEIGHT * 3 / 4)), "quadro rasgado");
        let mut faded = twelve.clone();
        faded.rgb.iter_mut().for_each(|channel| *channel /= 2);
        assert!(!same_screen(&twelve, &faded), "transicao");
        assert!(!same_screen(&twelve, &filled(800, 600, [0, 0, 0])));
    }

    /// A área de trabalho sintética passa com a barra opaca ou translúcida
    /// (60%), com e sem a caixa de busca clara e nas alturas da barra do
    /// Windows 10 (30 linhas com botões pequenos, 40 a 96 DPI, 48 a 120%).
    #[test]
    fn desktop_passes_with_the_taskbar_opaque_or_translucent() {
        for (height, alpha, search_box) in [(40, 256, true), (40, 256, false), (40, 154, true), (30, 256, true), (48, 256, true)] {
            let description = desktop_screen(&desktop(height, alpha, search_box)).unwrap_or_else(|missing| panic!("{height} {alpha} {search_box}: {missing}"));
            assert!(description.starts_with(&format!("barra de tarefas de {height} linhas embaixo")), "{description}");
            assert!(description.contains("128 cores com 512 pixels ou mais"), "{description}");
        }
        let measures = DesktopMeasures::of(&desktop(40, 256, true));
        assert_eq!((measures.left_green, measures.right_green), (161, 121));
    }

    /// Sem a barra de tarefas, sem o papel de parede azul do img0 (uma cor
    /// lisa, o preto do fundo do perfil, a tela de bloqueio) ou com a barra
    /// alta demais, não é a área de trabalho; a tela de bugcheck e a de
    /// texto também não.
    #[test]
    fn desktop_needs_the_taskbar_and_the_blue_wallpaper() {
        let missing = desktop_screen(&wallpaper()).unwrap_err();
        assert!(missing.starts_with("barra de tarefas escura de 0 linhas embaixo"), "{missing}");
        assert!(desktop_screen(&desktop(96, 256, true)).unwrap_err().contains("96 linhas"));
        let mut accent = filled(WIDTH, HEIGHT, [0x00, 0x78, 0xD7]);
        taskbar(&mut accent, 40, 256, true);
        let missing = desktop_screen(&accent).unwrap_err();
        assert!(missing.starts_with("1 cores do fundo") && missing.contains("verde medio"), "{missing}");
        let mut black = filled(WIDTH, HEIGHT, [0, 0, 0]);
        taskbar(&mut black, 40, 256, true);
        assert!(desktop_screen(&black).unwrap_err().contains("768 linhas"));
        for clock_too in [false, true] {
            let mut lock = lock_screen(clock_too);
            assert!(desktop_screen(&lock).unwrap_err().contains("do fundo azul"));
            taskbar(&mut lock, 40, 256, true);
            assert!(desktop_screen(&lock).unwrap_err().contains("do fundo azul"));
        }
        assert!(desktop_screen(&filled(WIDTH, HEIGHT, BUGCHECK_BACKGROUND)).unwrap_err().contains("bugcheck"));
        assert!(desktop_screen(&filled(720, 400, [0xAA, 0xAA, 0xAA])).unwrap_err().contains("720x400"));
    }

    /// Lixo cobrindo a tela, um quadro pela metade e a imagem surgindo do
    /// preto não são a área de trabalho.
    #[test]
    fn memory_noise_and_partial_frames_are_not_a_desktop() {
        assert!(desktop_screen(&memory_as_pixels()).unwrap_err().contains("dos vizinhos do fundo suaves"));
        assert!(desktop_screen(&noise()).unwrap_err().contains("0 cores do fundo"));
        let full = desktop(40, 256, true);
        assert!(desktop_screen(&only_rows(&full, 0..HEIGHT / 2)).unwrap_err().contains("384 linhas"));
        assert!(desktop_screen(&only_rows(&full, HEIGHT / 2..HEIGHT)).unwrap_err().contains("do fundo azul"));
        for half in [0..WIDTH / 2, WIDTH / 2..WIDTH] {
            assert!(desktop_screen(&only_columns(&full, half.clone())).unwrap_err().contains("768 linhas"), "{half:?}");
        }
        let mut faded = full.clone();
        faded.rgb.iter_mut().for_each(|channel| *channel /= 2);
        assert!(desktop_screen(&faded).is_err());
        assert!(!same_screen(&full, &faded));
    }
}
