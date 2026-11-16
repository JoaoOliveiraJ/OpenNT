//! A tela de bugcheck do vídeo de boot (o BgpFwDisplayBugCheckScreen e as
//! rotinas Bcp* do ntoskrnl 19041) e a equivalente em modo texto.
//!
//! Como no ntoskrnl 19041:
//! - os textos vêm da tabela de mensagens da biblioteca de recursos de boot
//!   no idioma da instalação (o BcpFindMessage do BgpBcInitializeCriticalMode
//!   corta cada mensagem no primeiro CR ou LF): 0xC1008001 ("o dispositivo
//!   encontrou um problema..."), o segundo período conforme as flags
//!   (0xC1008008/0x41008009 com despejo, 0x41008010/0x41008011 sem; os
//!   primeiros com reinício automático), o progresso 0xC1008012/0xC1008013
//!   ("%1% concluído", cortado em volta do "%1"), 0x41008016 + 0x41008018
//!   (mais informações e a URL), 0xC1008003 (suporte), 0x41008015 (código de
//!   parada) e 0x41008014 (o que falhou). O OpenNT lê o bootres.dll.mui da
//!   instalação, que o build põe no bundle do kernel;
//! - o fundo é 0xFF0077D6 (o do BgpBcInitializeCriticalMode fora do Insider)
//!   e o texto é branco;
//! - a geometria é a tabela de cinco tipos de tela do kernel (0xc10f10): o
//!   tipo é o último cuja resolução mínima a tela alcança (BcpGetDisplayType;
//!   1024x768 é o tipo 2), e cada tipo dá as alturas de linha do texto
//!   pequeno, das informações, do texto principal e do ":(", a origem, a
//!   largura da caixa de texto, o recuo, os espaços entre blocos e o passo de
//!   linha;
//! - a ordem é a do BgpFwDisplayBugCheckScreen: tela limpa, ":(" na origem,
//!   o parágrafo na altura principal com quebra por palavra
//!   (BcpDisplayCriticalString: uma palavra que passa da borda direita vai
//!   para a linha seguinte, a linha desce a altura da maior célula mais o
//!   espaço de quebra), um espaço e o segundo período; o progresso logo
//!   abaixo (BcpGetComponentOffsets mede o "100%" para saber até onde
//!   apagar) e as informações do erro depois dele (BcpDisplayErrorInformation:
//!   a URL, o suporte, "Código de parada:" com o nome do código e, com um
//!   driver culpado, "O que falhou:" com o nome passado pelo
//!   BcpSanitizeDriverName, que troca por espaço o que não for letra,
//!   dígito, ponto, espaço ou sublinhado). Sem despejo (flag 4) não há
//!   progresso.
//!
//! O código QR do Windows é uma imagem da Microsoft e fica de fora (a
//! geometria segue a do kernel sem QR). A fonte é a do BIOS de vídeo
//! (`boot_font`). Sem framebuffer, a tela é a de modo texto do vídeo de
//! boot, com os mesmos textos em branco sobre azul.

use super::boot_font;
use super::graphics_information::{self, BootFrameBuffer};
use crate::hal::bundle;
use crate::ntos::inbv::display as inbv;
use crate::rtl::SpinLock;

const BACKGROUND: u32 = 0x0077D6;
const FOREGROUND: u32 = 0xFF_FFFF;
/// Branco sobre azul no modo texto.
const TEXT_ATTRIBUTE: u8 = 0x1F;

/// Flags do KiDisplayBlueScreen.
pub const FLAG_SKIP_SECOND_MESSAGE: u32 = 1;
pub const FLAG_NO_AUTO_REBOOT: u32 = 2;
pub const FLAG_NO_DUMP: u32 = 4;

const MESSAGE_PROBLEM: u32 = 0xC100_8001;
const MESSAGE_SUPPORT: u32 = 0xC100_8003;
const MESSAGE_COLLECTING_THEN_RESTART_FOR_YOU: u32 = 0xC100_8008;
const MESSAGE_COLLECTING_THEN_YOU_CAN_RESTART: u32 = 0x4100_8009;
const MESSAGE_RESTART_FOR_YOU: u32 = 0x4100_8010;
const MESSAGE_YOU_CAN_RESTART: u32 = 0x4100_8011;
const MESSAGE_PROGRESS_SINGULAR: u32 = 0xC100_8012;
pub const MESSAGE_PROGRESS: u32 = 0xC100_8013;
const MESSAGE_WHAT_FAILED: u32 = 0x4100_8014;
pub const MESSAGE_STOP_CODE: u32 = 0x4100_8015;
const MESSAGE_MORE_INFORMATION: u32 = 0x4100_8016;
const MESSAGE_URL: u32 = 0x4100_8018;

/// Um tipo de tela da tabela do kernel (os campos pelo deslocamento).
#[derive(Clone, Copy)]
struct Layout {
    /// +0x00, +0x04, +0x08, +0x0C: alturas de linha (suporte e código,
    /// informações, texto principal e progresso, ":(").
    small: u32,
    information: u32,
    main: u32,
    face: u32,
    /// +0x10, +0x14: origem; +0x18: largura da caixa de texto; +0x20: recuo
    /// do texto em relação à origem.
    x: u32,
    y: u32,
    width: u32,
    inset: u32,
    /// +0x24: espaço depois do ":("; +0x28: espaço entre linhas quebradas;
    /// +0x2C: passo de linha dos blocos; +0x3C: espaço antes das
    /// informações do erro.
    face_gap: u32,
    wrap_gap: u32,
    line_step: u32,
    error_gap: u32,
    /// +0x40, +0x44: a resolução mínima do tipo.
    minimum: (u32, u32),
}

const fn layout(fields: [u32; 18]) -> Layout {
    Layout {
        small: fields[0],
        information: fields[1],
        main: fields[2],
        face: fields[3],
        x: fields[4],
        y: fields[5],
        width: fields[6],
        inset: fields[8],
        face_gap: fields[9],
        wrap_gap: fields[10],
        line_step: fields[11],
        error_gap: fields[15],
        minimum: (fields[16], fields[17]),
    }
}

const LAYOUTS: [Layout; 5] = [
    layout([0x12, 0x16, 0x1A, 0x78, 0x50, 0x2D, 0x1D6, 0xB9, 0x7, 0x3, 0x1, 0x14, 0x1E, 0x28, 0xA, 0x22, 0, 0]),
    layout([0x12, 0x16, 0x20, 0xA0, 0x69, 0x3C, 0x1FE, 0xFA, 0xA, 0x5, 0x2, 0x16, 0x28, 0x2C, 0xF, 0x26, 0x281, 0x1E1]),
    layout([0x12, 0x16, 0x28, 0xC8, 0x87, 0x4B, 0x35C, 0x136, 0xC, 0x6, 0x2, 0x18, 0x32, 0x30, 0x11, 0x2A, 0x400, 0x300]),
    layout([0x18, 0x1E, 0x38, 0x118, 0xBE, 0x69, 0x3D4, 0x1B8, 0x11, 0x8, 0x3, 0x22, 0x46, 0x44, 0x14, 0x3C, 0x780, 0x438]),
    layout([0x22, 0x28, 0x48, 0x168, 0xF5, 0x87, 0x4E2, 0x262, 0x16, 0xB, 0x4, 0x31, 0x5A, 0x62, 0x19, 0x56, 0xA00, 0x5A0]),
];

/// BcpGetDisplayType.
pub fn display_type(width: u32, height: u32) -> usize {
    let mut kind = 0;
    while kind + 1 < LAYOUTS.len() && width >= LAYOUTS[kind + 1].minimum.0 && height >= LAYOUTS[kind + 1].minimum.1 {
        kind += 1;
    }
    kind
}

// ---- textos -----------------------------------------------------------------

/// Caracteres de um texto da tela (a maior linha montada, o parágrafo do
/// modo texto, tem uns 160).
const TEXT_CAPACITY: usize = 192;

/// Texto de tamanho fixo (sem alocação no bugcheck).
#[derive(Clone, Copy)]
pub struct Text {
    characters: [char; TEXT_CAPACITY],
    length: usize,
}

impl Text {
    pub const fn new() -> Self {
        Self { characters: ['\0'; TEXT_CAPACITY], length: 0 }
    }

    pub fn push(&mut self, character: char) {
        if self.length < self.characters.len() {
            self.characters[self.length] = character;
            self.length += 1;
        }
    }

    pub fn extend(&mut self, characters: impl IntoIterator<Item = char>) -> &mut Self {
        for character in characters {
            self.push(character);
        }
        self
    }

    pub fn from_chars(characters: impl IntoIterator<Item = char>) -> Self {
        let mut text = Self::new();
        text.extend(characters);
        text
    }

    pub fn as_slice(&self) -> &[char] {
        &self.characters[..self.length]
    }
}

impl Default for Text {
    fn default() -> Self {
        Self::new()
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?))
}

/// Os bytes da tabela de mensagens (RT_MESSAGETABLE 1, primeiro idioma)
/// do MUI de recursos de boot, lido em arquivo (RVAs pela tabela de seções).
fn boot_message_table() -> Option<&'static [u8]> {
    let file = bundle::read("apps/bootres.dll.mui")?;
    let pe = u32_at(file, 0x3C)? as usize;
    let sections = u16_at(file, pe + 6)? as usize;
    let optional = pe + 24;
    let table = optional + u16_at(file, pe + 20)? as usize;
    let to_offset = |rva: u32| -> Option<usize> {
        (0..sections).find_map(|index| {
            let at = table + index * 40;
            let (size, address, raw) = (u32_at(file, at + 8)?, u32_at(file, at + 12)?, u32_at(file, at + 20)?);
            (rva >= address && rva < address + size).then(|| (rva - address + raw) as usize)
        })
    };
    // O diretório de recursos: o terceiro do cabeçalho opcional, que começa
    // em +96 no PE32 (o MUI é uma DLL de recursos de 32 bits) e em +112 no
    // PE32+.
    let directories = if u16_at(file, optional)? == 0x10B { optional + 96 } else { optional + 112 };
    let root = to_offset(u32_at(file, directories + 16)?)?;
    let child = |directory: usize, identifier: Option<u32>| -> Option<u32> {
        let count = u16_at(file, directory + 12)? as usize + u16_at(file, directory + 14)? as usize;
        (0..count).find_map(|index| {
            let entry = directory + 16 + index * 8;
            let (id, target) = (u32_at(file, entry)?, u32_at(file, entry + 4)?);
            identifier.is_none_or(|wanted| wanted == id).then_some(target)
        })
    };
    let names = root + (child(root, Some(11))? & 0x7FFF_FFFF) as usize;
    let languages = root + (child(names, Some(1))? & 0x7FFF_FFFF) as usize;
    let data = root + child(languages, None)? as usize;
    let start = to_offset(u32_at(file, data)?)?;
    file.get(start..start + u32_at(file, data + 4)? as usize)
}

/// BcpFindMessage: a mensagem até o primeiro CR, LF ou NUL.
pub fn find_message(identifier: u32) -> Option<Text> {
    let table = boot_message_table()?;
    for block in 0..u32_at(table, 0)? as usize {
        let at = 4 + block * 12;
        let (low, high, offset) = (u32_at(table, at)?, u32_at(table, at + 4)?, u32_at(table, at + 8)? as usize);
        if identifier < low || identifier > high {
            continue;
        }
        let mut entry = offset;
        for _ in low..identifier {
            entry += u16_at(table, entry)? as usize;
        }
        let (length, flags) = (u16_at(table, entry)? as usize, u16_at(table, entry + 2)?);
        let bytes = table.get(entry + 4..entry + length.max(4))?;
        let mut text = Text::new();
        if flags & 1 != 0 {
            let units = bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
            text.extend(char::decode_utf16(units).map(|unit| unit.unwrap_or('?')).take_while(|&character| !matches!(character, '\0' | '\r' | '\n')));
        } else {
            text.extend(bytes.iter().map(|&byte| byte as char).take_while(|&character| !matches!(character, '\0' | '\r' | '\n')));
        }
        return Some(text);
    }
    None
}

/// BcpGetProgressMessages: o texto antes e depois do "%1".
pub fn progress_messages(identifier: u32) -> (Text, Text) {
    let Some(message) = find_message(identifier) else { return (Text::from_chars("".chars()), Text::from_chars("%".chars())) };
    let characters = message.as_slice();
    match characters.windows(2).position(|pair| pair == ['%', '1']) {
        Some(at) => (Text::from_chars(characters[..at].iter().copied()), Text::from_chars(characters[at + 2..].iter().copied())),
        None => (Text::new(), message),
    }
}

/// BcpSanitizeDriverName.
fn sanitize_driver_name(name: &str) -> Text {
    Text::from_chars(name.chars().map(|character| if character.is_ascii_alphanumeric() || matches!(character, ' ' | '.' | '_') { character } else { ' ' }))
}

/// O segundo período do parágrafo conforme as flags.
fn second_message(flags: u32) -> u32 {
    match (flags & FLAG_NO_AUTO_REBOOT != 0, flags & FLAG_NO_DUMP != 0) {
        (true, false) => MESSAGE_COLLECTING_THEN_YOU_CAN_RESTART,
        (true, true) => MESSAGE_YOU_CAN_RESTART,
        (false, false) => MESSAGE_COLLECTING_THEN_RESTART_FOR_YOU,
        (false, true) => MESSAGE_RESTART_FOR_YOU,
    }
}

fn number(value: u32) -> Text {
    let mut digits = [0u8; 10];
    let mut count = 0;
    let mut rest = value;
    loop {
        digits[count] = b'0' + (rest % 10) as u8;
        count += 1;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    Text::from_chars(digits[..count].iter().rev().map(|&digit| digit as char))
}

// ---- framebuffer --------------------------------------------------------------

/// O BcpCursor: canto da próxima célula (x, y) e a base da linha (z).
struct Painter {
    screen: BootFrameBuffer,
    layout: Layout,
    x: u32,
    y: u32,
    z: u32,
    /// BcpTextBoxLeftEdgeOverride.
    left_override: Option<u32>,
    draw: bool,
}

impl Painter {
    fn left(&self) -> u32 {
        self.left_override.unwrap_or(self.layout.x + self.layout.inset)
    }

    fn right(&self) -> u32 {
        self.layout.x + self.layout.width + self.layout.inset
    }

    /// BcpPrintSpaces: o resto da linha com o fundo.
    fn pad(&self, x: u32, y: u32, height: u32) {
        if self.draw && x < self.right() {
            boot_font::fill(&self.screen, x, y, self.right() - x, height, BACKGROUND);
        }
    }

    fn character(&self, character: char, x: u32, y: u32, height: u32) -> u32 {
        if self.draw {
            boot_font::draw_character(&self.screen, character, x, y, height, FOREGROUND, BACKGROUND)
        } else {
            boot_font::advance(height)
        }
    }

    /// BcpDisplayCriticalString.
    fn critical_string(&mut self, text: &[char], height: u32) {
        let advance = boot_font::advance(height);
        let (left, right) = (self.left(), self.right());
        let (mut x, mut y) = (self.x, self.y);
        let mut line = self.z.saturating_sub(self.y);
        let wrap = x + advance * text.len() as u32 > right;
        let separator = |character: char| matches!(character, '\0' | '\n' | '\r');
        let mut measured = 0;
        for (index, &character) in text.iter().enumerate() {
            if wrap && measured <= index && character != ' ' && !separator(character) {
                // A palavra que começa aqui cabe no resto da linha?
                measured = index;
                let mut word = 0;
                while measured < text.len() && !separator(text[measured]) {
                    word += advance;
                    measured += 1;
                    if right < word + x && line != 0 {
                        self.pad(x, y, line);
                        x = left;
                        y += self.layout.wrap_gap + line;
                        line = 0;
                        break;
                    }
                    if measured >= text.len() || text[measured] == ' ' {
                        break;
                    }
                }
            }
            if right < x + advance {
                self.pad(x, y, line.max(height));
                x = left;
                y += self.layout.wrap_gap + line;
                line = 0;
                if character == ' ' {
                    continue;
                }
            }
            x += self.character(character, x, y, height);
            line = line.max(height);
        }
        self.x = x;
        self.y = y;
        self.z = y + line;
    }

    /// BcpDisplayCriticalCharacter.
    fn critical_character(&mut self, character: char, height: u32) {
        self.x += self.character(character, self.x, self.y, height);
        self.z = self.z.max(self.y + height);
    }
}

/// O progresso na tela: posição, até onde apagar e a última porcentagem.
#[derive(Clone, Copy)]
struct Progress {
    screen: BootFrameBuffer,
    layout: Layout,
    x: u32,
    y: u32,
    end: u32,
    last: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    FrameBuffer { width: u32, height: u32, kind: usize },
    Text,
}

static PROGRESS: SpinLock<Option<Progress>> = SpinLock::new(None);
static TEXT_PROGRESS: SpinLock<Option<(usize, u32)>> = SpinLock::new(None);

/// BcpDisplayProgress: prefixo, número e sufixo na altura principal, e o
/// fundo até o fim do maior texto de progresso.
fn draw_progress(progress: &Progress, percent: u32, draw: bool) -> (u32, u32) {
    let (prefix, suffix) = progress_messages(if percent == 1 { MESSAGE_PROGRESS_SINGULAR } else { MESSAGE_PROGRESS });
    let mut painter = Painter { screen: progress.screen, layout: progress.layout, x: progress.x, y: progress.y, z: progress.y, left_override: None, draw };
    painter.critical_string(prefix.as_slice(), progress.layout.main);
    painter.critical_string(number(percent).as_slice(), progress.layout.main);
    painter.critical_string(suffix.as_slice(), progress.layout.main);
    if draw && painter.x < progress.end {
        boot_font::fill(&progress.screen, painter.x, painter.y, progress.end - painter.x, progress.layout.main, BACKGROUND);
    }
    (painter.x, painter.z)
}

/// BcpDisplayErrorInformation.
fn display_error_information(painter: &mut Painter, name: &[char], driver: Option<&str>) {
    let layout = painter.layout;
    let start = painter.x;
    painter.left_override = Some(start);
    if let Some(message) = find_message(MESSAGE_MORE_INFORMATION) {
        painter.critical_string(message.as_slice(), layout.information);
    }
    if let Some(message) = find_message(MESSAGE_URL) {
        painter.critical_string(message.as_slice(), layout.information);
    }
    let support = painter.z + layout.line_step;
    (painter.x, painter.y, painter.z) = (start, support, support + layout.line_step);
    if let Some(message) = find_message(MESSAGE_SUPPORT) {
        painter.critical_string(message.as_slice(), layout.small);
    }
    let stop = support + layout.line_step;
    (painter.x, painter.y, painter.z) = (start, stop, stop + layout.line_step);
    if let Some(message) = find_message(MESSAGE_STOP_CODE) {
        painter.critical_string(message.as_slice(), layout.small);
        painter.critical_character(' ', layout.small);
    }
    painter.critical_string(name, layout.small);
    if let Some(driver) = driver {
        let failed = stop + layout.line_step;
        (painter.x, painter.y, painter.z) = (start, failed, failed + layout.line_step);
        if let Some(message) = find_message(MESSAGE_WHAT_FAILED) {
            painter.critical_string(message.as_slice(), layout.small);
            painter.critical_character(' ', layout.small);
        }
        painter.critical_string(sanitize_driver_name(driver).as_slice(), layout.small);
    }
    painter.left_override = None;
}

/// BgpFwDisplayBugCheckScreen no framebuffer de boot.
fn display_frame_buffer(screen: BootFrameBuffer, name: &[char], driver: Option<&str>, flags: u32) -> Mode {
    let kind = display_type(screen.width, screen.height);
    let layout = LAYOUTS[kind];
    // BgpClearScreen.
    boot_font::fill(&screen, 0, 0, screen.width, screen.height, BACKGROUND);
    let mut painter = Painter { screen, layout, x: layout.x, y: layout.y, z: layout.y, left_override: None, draw: true };
    painter.critical_string(&[':', '('], layout.face);
    painter.y = painter.z + layout.face_gap;
    painter.x = layout.x + layout.inset;
    if let Some(message) = find_message(MESSAGE_PROBLEM) {
        painter.critical_string(message.as_slice(), layout.main);
    }
    painter.critical_character(' ', layout.main);
    if flags & FLAG_SKIP_SECOND_MESSAGE == 0 {
        if let Some(message) = find_message(second_message(flags)) {
            painter.critical_string(message.as_slice(), layout.main);
        }
    }
    // BcpGetComponentOffsets: o progresso logo abaixo do parágrafo, medido
    // no "100%", e as informações do erro depois dele.
    let left = layout.x + layout.inset;
    let progress_y = painter.z + layout.line_step;
    let show_progress = flags & FLAG_NO_DUMP == 0;
    let mut progress = Progress { screen, layout, x: left, y: progress_y, end: left, last: 0 };
    let below_progress = if show_progress {
        let (end, bottom) = draw_progress(&progress, 100, false);
        progress.end = end;
        bottom
    } else {
        progress_y + layout.line_step
    };
    let error_y = below_progress + layout.error_gap;
    (painter.x, painter.y, painter.z) = (left, error_y, error_y + layout.line_step);
    display_error_information(&mut painter, name, driver);
    if show_progress {
        draw_progress(&progress, 0, true);
        *PROGRESS.lock() = Some(progress);
    }
    Mode::FrameBuffer { width: screen.width, height: screen.height, kind }
}

// ---- modo texto ---------------------------------------------------------------

/// Linhas quebradas por palavra na largura dada, a partir da linha `row`;
/// devolve a linha seguinte.
fn text_paragraph(text: &[char], column: usize, row: usize, width: usize) -> usize {
    let mut line = [0u8; 128];
    let mut length = 0;
    let mut row = row;
    let flush = |line: &[u8], row: usize| inbv::display_string_at(column, row, line, TEXT_ATTRIBUTE);
    for word in text.split(|&character| character == ' ').filter(|word| !word.is_empty()) {
        let needed = word.len() + usize::from(length > 0);
        if length > 0 && length + needed > width {
            flush(&line[..length], row);
            row += 1;
            length = 0;
        }
        if length > 0 {
            line[length] = b' ';
            length += 1;
        }
        for &character in word.iter().take(width) {
            if length < width {
                line[length] = boot_font::code_page_437(character).0;
                length += 1;
            }
        }
    }
    if length > 0 {
        flush(&line[..length], row);
        row += 1;
    }
    row
}

fn draw_text_progress(row: usize, percent: u32) {
    let (prefix, suffix) = progress_messages(if percent == 1 { MESSAGE_PROGRESS_SINGULAR } else { MESSAGE_PROGRESS });
    let mut text = Text::new();
    text.extend(prefix.as_slice().iter().copied()).extend(number(percent).as_slice().iter().copied()).extend(suffix.as_slice().iter().copied()).extend("   ".chars());
    text_paragraph(text.as_slice(), 2, row, 76);
}

/// A tela de bugcheck no modo texto do vídeo de boot: os mesmos textos, em
/// branco sobre azul.
fn display_text(name: &[char], driver: Option<&str>, flags: u32) -> Mode {
    let (columns, _) = inbv::text_size();
    let width = columns - 4;
    inbv::solid_color_fill(TEXT_ATTRIBUTE);
    inbv::display_string_at(2, 1, b":(", TEXT_ATTRIBUTE);
    let mut paragraph = find_message(MESSAGE_PROBLEM).unwrap_or_default();
    paragraph.push(' ');
    if flags & FLAG_SKIP_SECOND_MESSAGE == 0 {
        if let Some(message) = find_message(second_message(flags)) {
            paragraph.extend(message.as_slice().iter().copied());
        }
    }
    let mut row = text_paragraph(paragraph.as_slice(), 2, 3, width) + 1;
    if flags & FLAG_NO_DUMP == 0 {
        draw_text_progress(row, 0);
        *TEXT_PROGRESS.lock() = Some((row, 0));
        row += 2;
    }
    let mut information = find_message(MESSAGE_MORE_INFORMATION).unwrap_or_default();
    information.extend(find_message(MESSAGE_URL).unwrap_or_default().as_slice().iter().copied());
    row = text_paragraph(information.as_slice(), 2, row, width) + 1;
    row = text_paragraph(find_message(MESSAGE_SUPPORT).unwrap_or_default().as_slice(), 2, row, width);
    let mut stop = find_message(MESSAGE_STOP_CODE).unwrap_or_default();
    stop.push(' ');
    stop.extend(name.iter().copied());
    row = text_paragraph(stop.as_slice(), 2, row, width);
    if let Some(driver) = driver {
        let mut failed = find_message(MESSAGE_WHAT_FAILED).unwrap_or_default();
        failed.push(' ');
        failed.extend(sanitize_driver_name(driver).as_slice().iter().copied());
        text_paragraph(failed.as_slice(), 2, row, width);
    }
    Mode::Text
}

// ---- entrada --------------------------------------------------------------------

/// A tela de bugcheck: no framebuffer de boot quando o carregador ligou um
/// (BgpFwDisplayBugCheckScreen), senão no modo texto. `name` é o nome do
/// código (KeGetBugMessageText) e `driver`, o KiBugCheckDriver.
pub fn display(name: &[char], driver: Option<&str>, flags: u32) -> Mode {
    match graphics_information::boot_frame_buffer() {
        Some(screen) => display_frame_buffer(screen, name, driver, flags),
        None => display_text(name, driver, flags),
    }
}

/// BgpFwDisplayBugCheckProgressUpdate: a porcentagem nova, se a tela tem
/// progresso e ela avançou.
pub fn update_progress(percent: u32) {
    let percent = percent.min(100);
    if let Some(progress) = PROGRESS.lock().as_mut() {
        if percent > progress.last {
            progress.last = percent;
            draw_progress(progress, percent, true);
        }
    }
    if let Some((row, last)) = TEXT_PROGRESS.lock().as_mut() {
        if percent > *last {
            *last = percent;
            draw_text_progress(*row, percent);
        }
    }
}

/// O framebuffer tem a fonte do BIOS de vídeo (o ":(" e os textos saem
/// desenhados).
pub fn font_ready() -> bool {
    boot_font::loaded()
}
