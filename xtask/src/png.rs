//! PNG sem dependências, para as capturas de tela do QEMU.
//!
//! O `screendump` do QEMU grava PPM (o QEMU desta máquina não tem a libpng);
//! aqui a imagem perde a moldura de cor de fundo, vira PNG com paleta quando
//! tem até 256 cores (a tela de texto da VGA tem 16) e é comprimida por um
//! deflate próprio (LZ77 com cadeias de hash e Huffman dinâmico). Uma tela
//! gráfica que ainda passe do limite é reduzida pela metade até caber.
//! Os textos (`tEXt`) guardam a data e o resultado do teste; `read_info` os
//! lê de volta, com as dimensões, para o `cargo xtask status`.

/// Imagem RGB de 8 bits por canal, linha a linha.
pub struct Image {
    pub width: usize,
    pub height: usize,
    pub rgb: Vec<u8>,
}

impl Image {
    fn pixel(&self, x: usize, y: usize) -> [u8; 3] {
        let at = (y * self.width + x) * 3;
        [self.rgb[at], self.rgb[at + 1], self.rgb[at + 2]]
    }
}

// ---- PPM --------------------------------------------------------------------

/// PPM binário (P6) de 8 bits, como o `screendump` do QEMU grava.
pub fn read_ppm(bytes: &[u8]) -> Result<Image, String> {
    let mut fields = Vec::new();
    let mut position = 0;
    while fields.len() < 4 {
        while position < bytes.len() && bytes[position].is_ascii_whitespace() {
            position += 1;
        }
        if bytes.get(position) == Some(&b'#') {
            while position < bytes.len() && bytes[position] != b'\n' {
                position += 1;
            }
            continue;
        }
        let start = position;
        while position < bytes.len() && !bytes[position].is_ascii_whitespace() {
            position += 1;
        }
        if start == position {
            return Err("PPM truncado no cabecalho".into());
        }
        fields.push(String::from_utf8_lossy(&bytes[start..position]).into_owned());
    }
    position += 1;
    if fields[0] != "P6" {
        return Err(format!("PPM {} nao suportado (so P6)", fields[0]));
    }
    let number = |text: &str| text.parse::<usize>().map_err(|_| format!("PPM: numero invalido {text}"));
    let (width, height, maximum) = (number(&fields[1])?, number(&fields[2])?, number(&fields[3])?);
    if maximum != 255 {
        return Err(format!("PPM com maxval {maximum} nao suportado"));
    }
    let size = width * height * 3;
    let data = bytes.get(position..position + size).ok_or("PPM truncado nos pixels")?;
    Ok(Image { width, height, rgb: data.to_vec() })
}

// ---- corte e redução --------------------------------------------------------

/// Tira a moldura da cor mais comum (o fundo), deixando `margin` pixels,
/// sem ficar menor que `minimum` (largura, altura): uma tela quase vazia
/// (só o cursor) continua parecendo uma tela. Uma imagem toda de fundo fica
/// como está.
pub fn crop(image: &Image, margin: usize, minimum: (usize, usize)) -> Image {
    let mut counts: std::collections::HashMap<[u8; 3], usize> = std::collections::HashMap::new();
    for pixel in image.rgb.chunks_exact(3) {
        *counts.entry([pixel[0], pixel[1], pixel[2]]).or_default() += 1;
    }
    let Some(background) = counts.into_iter().max_by_key(|(color, count)| (*count, *color)).map(|(color, _)| color) else {
        return Image { width: image.width, height: image.height, rgb: image.rgb.clone() };
    };
    let row_blank = |y: usize| (0..image.width).all(|x| image.pixel(x, y) == background);
    let column_blank = |x: usize, top: usize, bottom: usize| (top..bottom).all(|y| image.pixel(x, y) == background);
    let Some(top) = (0..image.height).find(|&y| !row_blank(y)) else {
        return Image { width: image.width, height: image.height, rgb: image.rgb.clone() };
    };
    let bottom = (0..image.height).rev().find(|&y| !row_blank(y)).map_or(image.height, |y| y + 1);
    let left = (0..image.width).find(|&x| !column_blank(x, top, bottom)).unwrap_or(0);
    let right = (0..image.width).rev().find(|&x| !column_blank(x, top, bottom)).map_or(image.width, |x| x + 1);
    let (top, left) = (top.saturating_sub(margin), left.saturating_sub(margin));
    let (bottom, right) = ((bottom + margin).min(image.height), (right + margin).min(image.width));
    // Cresce até o mínimo, para a direita e para baixo (o texto começa no
    // canto de cima), sem sair da imagem.
    let grow = |start: usize, end: usize, wanted: usize, limit: usize| {
        let wanted = wanted.min(limit);
        if end - start >= wanted {
            (start, end)
        } else if start + wanted <= limit {
            (start, start + wanted)
        } else {
            (limit - wanted, limit)
        }
    };
    let (left, right) = grow(left, right, minimum.0, image.width);
    let (top, bottom) = grow(top, bottom, minimum.1, image.height);
    let width = right - left;
    let mut rgb = Vec::with_capacity(width * (bottom - top) * 3);
    for y in top..bottom {
        let start = (y * image.width + left) * 3;
        rgb.extend_from_slice(&image.rgb[start..start + width * 3]);
    }
    Image { width, height: bottom - top, rgb }
}

/// Metade da largura e da altura, pela média de cada bloco de 2x2.
pub fn halve(image: &Image) -> Image {
    let (width, height) = ((image.width / 2).max(1), (image.height / 2).max(1));
    let mut rgb = Vec::with_capacity(width * height * 3);
    for y in 0..height {
        for x in 0..width {
            for channel in 0..3 {
                let mut sum = 0u32;
                for (dx, dy) in [(0, 0), (1, 0), (0, 1), (1, 1)] {
                    let (sx, sy) = ((2 * x + dx).min(image.width - 1), (2 * y + dy).min(image.height - 1));
                    sum += u32::from(image.rgb[(sy * image.width + sx) * 3 + channel]);
                }
                rgb.push(((sum + 2) / 4) as u8);
            }
        }
    }
    Image { width, height, rgb }
}

/// O PNG da captura: sem moldura e, se passar de `limit` bytes, reduzido
/// pela metade até caber. A tela de texto (720 pixels de largura) nunca é
/// reduzida: pela metade, as letras não se leem mais.
pub fn encode_capture(image: &Image, texts: &[(&str, &str)], limit: usize) -> Vec<u8> {
    let mut current = crop(image, 8, (480, 160));
    loop {
        let bytes = encode(&current, texts);
        if bytes.len() <= limit || current.width <= 800 {
            return bytes;
        }
        current = halve(&current);
    }
}

// ---- PNG --------------------------------------------------------------------

const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];

fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    for (index, entry) in table.iter_mut().enumerate() {
        let mut value = index as u32;
        for _ in 0..8 {
            value = if value & 1 != 0 { 0xedb8_8320 ^ (value >> 1) } else { value >> 1 };
        }
        *entry = value;
    }
    table
}

fn crc32(table: &[u32; 256], parts: &[&[u8]]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for part in parts {
        for &byte in *part {
            crc = table[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8);
        }
    }
    crc ^ 0xffff_ffff
}

fn chunk(output: &mut Vec<u8>, table: &[u32; 256], kind: &[u8; 4], data: &[u8]) {
    output.extend_from_slice(&(data.len() as u32).to_be_bytes());
    output.extend_from_slice(kind);
    output.extend_from_slice(data);
    output.extend_from_slice(&crc32(table, &[kind, data]).to_be_bytes());
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for block in data.chunks(5552) {
        for &byte in block {
            a += u32::from(byte);
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

fn paeth(left: u8, up: u8, corner: u8) -> u8 {
    let estimate = i16::from(left) + i16::from(up) - i16::from(corner);
    let (to_left, to_up, to_corner) =
        ((estimate - i16::from(left)).abs(), (estimate - i16::from(up)).abs(), (estimate - i16::from(corner)).abs());
    if to_left <= to_up && to_left <= to_corner {
        left
    } else if to_up <= to_corner {
        up
    } else {
        corner
    }
}

/// As linhas filtradas de uma imagem RGB: em cada linha, o filtro de menor
/// soma absoluta (a heurística do libpng).
fn filter_rgb(image: &Image) -> Vec<u8> {
    let stride = image.width * 3;
    let mut output = Vec::with_capacity((stride + 1) * image.height);
    let zero = vec![0u8; stride];
    let mut candidate = vec![0u8; stride];
    let mut best = vec![0u8; stride];
    for y in 0..image.height {
        let row = &image.rgb[y * stride..(y + 1) * stride];
        let up = if y == 0 { &zero[..] } else { &image.rgb[(y - 1) * stride..y * stride] };
        let mut best_kind = 0u8;
        let mut best_score = u64::MAX;
        for kind in 0..5u8 {
            for index in 0..stride {
                let left = if index >= 3 { row[index - 3] } else { 0 };
                let corner = if index >= 3 { up[index - 3] } else { 0 };
                let predicted = match kind {
                    0 => 0,
                    1 => left,
                    2 => up[index],
                    3 => ((u16::from(left) + u16::from(up[index])) / 2) as u8,
                    _ => paeth(left, up[index], corner),
                };
                candidate[index] = row[index].wrapping_sub(predicted);
            }
            let score: u64 = candidate.iter().map(|&value| u64::from((value as i8).unsigned_abs())).sum();
            if score < best_score {
                best_score = score;
                best_kind = kind;
                best.copy_from_slice(&candidate);
            }
        }
        output.push(best_kind);
        output.extend_from_slice(&best);
    }
    output
}

/// PNG da imagem: com paleta (1, 2, 4 ou 8 bits) até 256 cores, senão RGB.
pub fn encode(image: &Image, texts: &[(&str, &str)]) -> Vec<u8> {
    let table = crc_table();
    let mut palette: Vec<[u8; 3]> = Vec::new();
    let mut index_of: std::collections::HashMap<[u8; 3], u8> = std::collections::HashMap::new();
    let mut indexed = true;
    for pixel in image.rgb.chunks_exact(3) {
        let color = [pixel[0], pixel[1], pixel[2]];
        if !index_of.contains_key(&color) {
            if palette.len() == 256 {
                indexed = false;
                break;
            }
            index_of.insert(color, palette.len() as u8);
            palette.push(color);
        }
    }
    let (depth, color_type, raw) = if indexed {
        let depth: usize = match palette.len() {
            0..=2 => 1,
            3..=4 => 2,
            5..=16 => 4,
            _ => 8,
        };
        let per_byte = 8 / depth;
        let stride = image.width.div_ceil(per_byte);
        let mut raw = Vec::with_capacity((stride + 1) * image.height);
        for y in 0..image.height {
            raw.push(0);
            let mut row = vec![0u8; stride];
            for x in 0..image.width {
                let value = index_of[&image.pixel(x, y)];
                let shift = 8 - depth * (x % per_byte + 1);
                row[x / per_byte] |= value << shift;
            }
            raw.extend_from_slice(&row);
        }
        (depth as u8, 3u8, raw)
    } else {
        (8, 2, filter_rgb(image))
    };

    let mut output = SIGNATURE.to_vec();
    let mut header = Vec::new();
    header.extend_from_slice(&(image.width as u32).to_be_bytes());
    header.extend_from_slice(&(image.height as u32).to_be_bytes());
    header.extend_from_slice(&[depth, color_type, 0, 0, 0]);
    chunk(&mut output, &table, b"IHDR", &header);
    if indexed {
        let colors: Vec<u8> = palette.iter().flatten().copied().collect();
        chunk(&mut output, &table, b"PLTE", &colors);
    }
    for (keyword, text) in texts {
        let mut data = keyword.as_bytes().to_vec();
        data.push(0);
        // tEXt é Latin-1: o que não couber vira '?'.
        data.extend(text.chars().map(|character| if (character as u32) < 256 { character as u8 } else { b'?' }));
        chunk(&mut output, &table, b"tEXt", &data);
    }
    let mut zlib = vec![0x78, 0xda];
    zlib.extend_from_slice(&deflate(&raw));
    zlib.extend_from_slice(&adler32(&raw).to_be_bytes());
    chunk(&mut output, &table, b"IDAT", &zlib);
    chunk(&mut output, &table, b"IEND", &[]);
    output
}

/// O que o gerador das páginas lê de uma captura.
pub struct Info {
    pub width: u32,
    pub height: u32,
    pub texts: Vec<(String, String)>,
}

impl Info {
    pub fn text(&self, keyword: &str) -> Option<&str> {
        self.texts.iter().find(|(name, _)| name == keyword).map(|(_, value)| value.as_str())
    }
}

/// Dimensões e textos de um PNG (sem descomprimir os pixels).
pub fn read_info(bytes: &[u8]) -> Option<Info> {
    if bytes.get(..8)? != SIGNATURE {
        return None;
    }
    let mut position = 8;
    let mut info = Info { width: 0, height: 0, texts: Vec::new() };
    while position + 8 <= bytes.len() {
        let length = u32::from_be_bytes(bytes[position..position + 4].try_into().ok()?) as usize;
        let kind = &bytes[position + 4..position + 8];
        let data = bytes.get(position + 8..position + 8 + length)?;
        match kind {
            b"IHDR" if length >= 8 => {
                info.width = u32::from_be_bytes(data[0..4].try_into().ok()?);
                info.height = u32::from_be_bytes(data[4..8].try_into().ok()?);
            }
            b"tEXt" => {
                if let Some(split) = data.iter().position(|&byte| byte == 0) {
                    let latin1 = |slice: &[u8]| slice.iter().map(|&byte| byte as char).collect::<String>();
                    info.texts.push((latin1(&data[..split]), latin1(&data[split + 1..])));
                }
            }
            b"IEND" => break,
            _ => {}
        }
        position += 12 + length;
    }
    (info.width > 0).then_some(info)
}

// ---- deflate ----------------------------------------------------------------

const WINDOW: usize = 1 << 15;
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
const MAX_CHAIN: usize = 256;
const HASH_BITS: usize = 15;
/// Símbolos por bloco: cada bloco tem as próprias árvores de Huffman.
const BLOCK_SYMBOLS: usize = 1 << 16;

const LENGTH_BASE: [u16; 29] =
    [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LENGTH_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DISTANCE_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577,
];
const DISTANCE_EXTRA: [u8; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
/// Ordem dos comprimentos do alfabeto dos comprimentos no cabeçalho.
const CODE_LENGTH_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// Um literal (`distance == 0`) ou uma cópia de `length` bytes de
/// `distance` atrás.
#[derive(Clone, Copy)]
struct Symbol {
    length: u16,
    distance: u16,
}

fn length_code(length: u16) -> usize {
    LENGTH_BASE.iter().rposition(|&base| base <= length).unwrap()
}

fn distance_code(distance: u16) -> usize {
    DISTANCE_BASE.iter().rposition(|&base| base <= distance).unwrap()
}

fn hash(data: &[u8], position: usize) -> usize {
    let value = (u32::from(data[position]) << 16) | (u32::from(data[position + 1]) << 8) | u32::from(data[position + 2]);
    (value.wrapping_mul(2_654_435_761) >> (32 - HASH_BITS)) as usize
}

/// LZ77 com cadeias de hash e uma posição de avaliação adiada (como o
/// zlib nos níveis altos).
fn lz77(data: &[u8]) -> Vec<Symbol> {
    let mut head = vec![usize::MAX; 1 << HASH_BITS];
    let mut previous = vec![usize::MAX; WINDOW];
    let mut symbols = Vec::new();
    let insert = |head: &mut Vec<usize>, previous: &mut Vec<usize>, position: usize| {
        if position + MIN_MATCH <= data.len() {
            let key = hash(data, position);
            previous[position % WINDOW] = head[key];
            head[key] = position;
        }
    };
    let longest = |head: &Vec<usize>, previous: &Vec<usize>, position: usize| -> (usize, usize) {
        if position + MIN_MATCH > data.len() {
            return (0, 0);
        }
        let limit = (data.len() - position).min(MAX_MATCH);
        let mut candidate = head[hash(data, position)];
        let (mut best_length, mut best_distance) = (0, 0);
        let mut chain = 0;
        while candidate != usize::MAX && position - candidate <= WINDOW - 1 && chain < MAX_CHAIN {
            if data[candidate + best_length.min(limit - 1)] == data[position + best_length.min(limit - 1)] {
                let mut length = 0;
                while length < limit && data[candidate + length] == data[position + length] {
                    length += 1;
                }
                if length > best_length {
                    best_length = length;
                    best_distance = position - candidate;
                    if length == limit {
                        break;
                    }
                }
            }
            let next = previous[candidate % WINDOW];
            if next == usize::MAX || next >= candidate {
                break;
            }
            candidate = next;
            chain += 1;
        }
        (best_length, best_distance)
    };
    let mut position = 0;
    while position < data.len() {
        let (length, distance) = longest(&head, &previous, position);
        if length >= MIN_MATCH {
            // Adia: se a próxima posição tem cópia mais longa, este byte sai
            // como literal.
            insert(&mut head, &mut previous, position);
            let (next_length, _) = longest(&head, &previous, position + 1);
            if next_length > length {
                symbols.push(Symbol { length: u16::from(data[position]), distance: 0 });
                position += 1;
                continue;
            }
            symbols.push(Symbol { length: length as u16, distance: distance as u16 });
            for offset in 1..length {
                insert(&mut head, &mut previous, position + offset);
            }
            position += length;
        } else {
            insert(&mut head, &mut previous, position);
            symbols.push(Symbol { length: u16::from(data[position]), distance: 0 });
            position += 1;
        }
    }
    symbols
}

/// Comprimentos de código de Huffman de até `max_bits` bits, com o ajuste
/// de Kraft para cortar a árvore (como o miniz).
fn code_lengths(frequencies: &[u32], max_bits: usize) -> Vec<u8> {
    let mut lengths = vec![0u8; frequencies.len()];
    let mut used: Vec<usize> = (0..frequencies.len()).filter(|&symbol| frequencies[symbol] > 0).collect();
    match used.len() {
        0 => return lengths,
        1 => {
            // Uma árvore completa precisa de dois códigos.
            lengths[used[0]] = 1;
            lengths[if used[0] == 0 { 1 } else { 0 }] = 1;
            return lengths;
        }
        _ => {}
    }
    used.sort_by_key(|&symbol| (frequencies[symbol], symbol));
    // Huffman por duas filas: folhas em ordem e nós internos na ordem em
    // que nascem (já crescente).
    let count = used.len();
    let mut weight: Vec<u64> = used.iter().map(|&symbol| u64::from(frequencies[symbol])).collect();
    let mut parent = vec![0usize; 2 * count - 1];
    let (mut leaf, mut node) = (0usize, count);
    for next in count..2 * count - 1 {
        let mut pick = |weight: &Vec<u64>| {
            if leaf < count && (node >= next || weight[leaf] <= weight[node]) {
                leaf += 1;
                leaf - 1
            } else {
                node += 1;
                node - 1
            }
        };
        let first = pick(&weight);
        let second = pick(&weight);
        weight.push(weight[first] + weight[second]);
        parent[first] = next;
        parent[second] = next;
    }
    let root = 2 * count - 2;
    let mut depth = vec![0usize; 2 * count - 1];
    for index in (0..root).rev() {
        depth[index] = depth[parent[index]] + 1;
    }
    // Quantos códigos de cada comprimento, cortados em max_bits.
    let mut per_length = vec![0usize; max_bits + 1];
    for &value in &depth[..count] {
        per_length[value.min(max_bits)] += 1;
    }
    let kraft = |per_length: &Vec<usize>| -> usize { (1..=max_bits).map(|bits| per_length[bits] << (max_bits - bits)).sum() };
    while kraft(&per_length) > 1 << max_bits {
        per_length[max_bits] -= 1;
        if let Some(bits) = (1..max_bits).rev().find(|&bits| per_length[bits] > 0) {
            per_length[bits] -= 1;
            per_length[bits + 1] += 2;
        }
    }
    // Os mais frequentes ganham os códigos mais curtos.
    let mut symbols = used.iter().rev();
    for bits in 1..=max_bits {
        for _ in 0..per_length[bits] {
            if let Some(&symbol) = symbols.next() {
                lengths[symbol] = bits as u8;
            }
        }
    }
    lengths
}

/// Códigos canônicos dos comprimentos, já com os bits invertidos (o deflate
/// escreve do bit menos significativo).
fn canonical(lengths: &[u8]) -> Vec<u16> {
    let mut per_length = [0u16; 16];
    for &length in lengths {
        per_length[length as usize] += 1;
    }
    per_length[0] = 0;
    let mut next = [0u16; 16];
    let mut code = 0u16;
    for bits in 1..16 {
        code = (code + per_length[bits - 1]) << 1;
        next[bits] = code;
    }
    lengths
        .iter()
        .map(|&length| {
            if length == 0 {
                return 0;
            }
            let value = next[length as usize];
            next[length as usize] += 1;
            value.reverse_bits() >> (16 - length)
        })
        .collect()
}

struct BitWriter {
    output: Vec<u8>,
    buffer: u64,
    filled: u32,
}

impl BitWriter {
    fn put(&mut self, value: u32, bits: u32) {
        self.buffer |= u64::from(value) << self.filled;
        self.filled += bits;
        while self.filled >= 8 {
            self.output.push(self.buffer as u8);
            self.buffer >>= 8;
            self.filled -= 8;
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.filled > 0 {
            self.output.push(self.buffer as u8);
        }
        self.output
    }
}

/// Os comprimentos das duas árvores em run-length: (símbolo, extra, bits).
fn run_lengths(lengths: &[u8]) -> Vec<(u8, u8, u8)> {
    let mut output = Vec::new();
    let mut index = 0;
    while index < lengths.len() {
        let value = lengths[index];
        let run = lengths[index..].iter().take_while(|&&other| other == value).count();
        if value == 0 && run >= 3 {
            let take = run.min(138);
            output.push(if take >= 11 { (18, (take - 11) as u8, 7) } else { (17, (take - 3) as u8, 3) });
            index += take;
        } else if value != 0 && run >= 4 {
            output.push((value, 0, 0));
            let take = (run - 1).min(6);
            output.push((16, (take - 3) as u8, 2));
            index += 1 + take;
        } else {
            output.push((value, 0, 0));
            index += 1;
        }
    }
    output
}

fn write_block(writer: &mut BitWriter, symbols: &[Symbol], last: bool) {
    let mut literal_frequencies = vec![0u32; 286];
    let mut distance_frequencies = vec![0u32; 30];
    for symbol in symbols {
        if symbol.distance == 0 {
            literal_frequencies[symbol.length as usize] += 1;
        } else {
            literal_frequencies[257 + length_code(symbol.length)] += 1;
            distance_frequencies[distance_code(symbol.distance)] += 1;
        }
    }
    literal_frequencies[256] = 1;
    let literal_lengths = code_lengths(&literal_frequencies, 15);
    let mut distance_lengths = code_lengths(&distance_frequencies, 15);
    if distance_lengths.iter().all(|&length| length == 0) {
        distance_lengths[0] = 1;
        distance_lengths[1] = 1;
    }
    let literal_count = 257.max(literal_lengths.iter().rposition(|&length| length > 0).unwrap_or(0) + 1);
    let distance_count = 1.max(distance_lengths.iter().rposition(|&length| length > 0).unwrap_or(0) + 1);
    let mut all = literal_lengths[..literal_count].to_vec();
    all.extend_from_slice(&distance_lengths[..distance_count]);
    let runs = run_lengths(&all);
    let mut length_frequencies = vec![0u32; 19];
    for &(symbol, _, _) in &runs {
        length_frequencies[symbol as usize] += 1;
    }
    let length_lengths = code_lengths(&length_frequencies, 7);
    let length_codes = canonical(&length_lengths);
    let header_count = 4.max(CODE_LENGTH_ORDER.iter().rposition(|&symbol| length_lengths[symbol] > 0).unwrap_or(0) + 1);

    writer.put(u32::from(last), 1);
    writer.put(2, 2);
    writer.put((literal_count - 257) as u32, 5);
    writer.put((distance_count - 1) as u32, 5);
    writer.put((header_count - 4) as u32, 4);
    for &symbol in &CODE_LENGTH_ORDER[..header_count] {
        writer.put(u32::from(length_lengths[symbol]), 3);
    }
    for &(symbol, extra, bits) in &runs {
        writer.put(u32::from(length_codes[symbol as usize]), u32::from(length_lengths[symbol as usize]));
        if bits > 0 {
            writer.put(u32::from(extra), u32::from(bits));
        }
    }
    let literal_codes = canonical(&literal_lengths);
    let distance_codes = canonical(&distance_lengths);
    for symbol in symbols {
        if symbol.distance == 0 {
            let value = symbol.length as usize;
            writer.put(u32::from(literal_codes[value]), u32::from(literal_lengths[value]));
        } else {
            let code = length_code(symbol.length);
            writer.put(u32::from(literal_codes[257 + code]), u32::from(literal_lengths[257 + code]));
            if LENGTH_EXTRA[code] > 0 {
                writer.put(u32::from(symbol.length - LENGTH_BASE[code]), u32::from(LENGTH_EXTRA[code]));
            }
            let code = distance_code(symbol.distance);
            writer.put(u32::from(distance_codes[code]), u32::from(distance_lengths[code]));
            if DISTANCE_EXTRA[code] > 0 {
                writer.put(u32::from(symbol.distance - DISTANCE_BASE[code]), u32::from(DISTANCE_EXTRA[code]));
            }
        }
    }
    writer.put(u32::from(literal_codes[256]), u32::from(literal_lengths[256]));
}

/// Deflate (RFC 1951) com blocos de Huffman dinâmico.
pub fn deflate(data: &[u8]) -> Vec<u8> {
    let symbols = lz77(data);
    let mut writer = BitWriter { output: Vec::new(), buffer: 0, filled: 0 };
    if symbols.is_empty() {
        write_block(&mut writer, &[], true);
        return writer.finish();
    }
    let blocks: Vec<&[Symbol]> = symbols.chunks(BLOCK_SYMBOLS).collect();
    for (index, block) in blocks.iter().enumerate() {
        write_block(&mut writer, block, index + 1 == blocks.len());
    }
    writer.finish()
}

// ---- data -------------------------------------------------------------------

/// A data de hoje (UTC) como `AAAA-MM-DD`, sem crate de datas.
pub fn today() -> String {
    let seconds = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |time| time.as_secs());
    let days = (seconds / 86_400) as i64;
    // Do número de dias desde 1970-01-01 para o calendário civil.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Inflate mínimo (só para o teste): confere que o deflate é válido.
    fn inflate(data: &[u8]) -> Vec<u8> {
        struct Reader<'a> {
            data: &'a [u8],
            position: usize,
            bit: u32,
        }
        impl Reader<'_> {
            fn bits(&mut self, count: u32) -> u32 {
                let mut value = 0;
                for index in 0..count {
                    let byte = self.data[self.position];
                    value |= u32::from((byte >> self.bit) & 1) << index;
                    self.bit += 1;
                    if self.bit == 8 {
                        self.bit = 0;
                        self.position += 1;
                    }
                }
                value
            }
        }
        fn decode(reader: &mut Reader, lengths: &[u8]) -> usize {
            let codes = canonical(lengths);
            let (mut code, mut length) = (0u32, 0u8);
            loop {
                code |= reader.bits(1) << length;
                length += 1;
                if let Some(symbol) = (0..lengths.len()).find(|&symbol| lengths[symbol] == length && u32::from(codes[symbol]) == code) {
                    return symbol;
                }
            }
        }
        let mut reader = Reader { data, position: 0, bit: 0 };
        let mut output: Vec<u8> = Vec::new();
        loop {
            let last = reader.bits(1);
            assert_eq!(reader.bits(2), 2);
            let literal_count = reader.bits(5) as usize + 257;
            let distance_count = reader.bits(5) as usize + 1;
            let header_count = reader.bits(4) as usize + 4;
            let mut length_lengths = [0u8; 19];
            for &symbol in &CODE_LENGTH_ORDER[..header_count] {
                length_lengths[symbol] = reader.bits(3) as u8;
            }
            let mut all = Vec::new();
            while all.len() < literal_count + distance_count {
                match decode(&mut reader, &length_lengths) {
                    16 => {
                        let previous = *all.last().unwrap();
                        let count = reader.bits(2) + 3;
                        all.extend(std::iter::repeat_n(previous, count as usize));
                    }
                    17 => all.extend(std::iter::repeat_n(0, reader.bits(3) as usize + 3)),
                    18 => all.extend(std::iter::repeat_n(0, reader.bits(7) as usize + 11)),
                    value => all.push(value as u8),
                }
            }
            let (literals, distances) = all.split_at(literal_count);
            loop {
                let symbol = decode(&mut reader, literals);
                if symbol < 256 {
                    output.push(symbol as u8);
                } else if symbol == 256 {
                    break;
                } else {
                    let code = symbol - 257;
                    let length = LENGTH_BASE[code] as usize + reader.bits(u32::from(LENGTH_EXTRA[code])) as usize;
                    let code = decode(&mut reader, distances);
                    let distance = DISTANCE_BASE[code] as usize + reader.bits(u32::from(DISTANCE_EXTRA[code])) as usize;
                    for _ in 0..length {
                        output.push(output[output.len() - distance]);
                    }
                }
            }
            if last == 1 {
                return output;
            }
        }
    }

    #[test]
    fn deflate_round_trips() {
        let mut text = Vec::new();
        for index in 0..20_000u32 {
            text.extend_from_slice(format!("linha {} do teste {}\n", index % 97, index % 13).as_bytes());
        }
        text.extend((0..5000u32).map(|value| (value.wrapping_mul(2_654_435_761) >> 13) as u8));
        for sample in [&b""[..], &b"a"[..], &b"abcabcabcabcabc"[..], &text[..]] {
            assert_eq!(inflate(&deflate(sample)), sample);
        }
        assert!(deflate(&text).len() < text.len() / 4);
    }

    #[test]
    fn png_info_round_trips() {
        let image = Image { width: 3, height: 2, rgb: vec![0, 0, 0, 255, 255, 255, 0, 0, 0, 1, 2, 3, 0, 0, 0, 0, 0, 0] };
        let bytes = encode(&image, &[("opennt-data", "2026-11-15")]);
        let info = read_info(&bytes).unwrap();
        assert_eq!((info.width, info.height), (3, 2));
        assert_eq!(info.text("opennt-data"), Some("2026-11-15"));
        let ppm = [b"P6\n# x\n3 2\n255\n".to_vec(), image.rgb.clone()].concat();
        assert_eq!(read_ppm(&ppm).unwrap().rgb, image.rgb);
    }

    #[test]
    fn huffman_lengths_respect_the_limit() {
        let frequencies: Vec<u32> = (0..286).map(|index| if index < 40 { 1 << (index % 24) } else { 0 }).collect();
        let lengths = code_lengths(&frequencies, 15);
        assert!(lengths.iter().all(|&length| length <= 15));
        let kraft: u32 = lengths.iter().filter(|&&length| length > 0).map(|&length| 1 << (15 - length)).sum();
        assert!(kraft <= 1 << 15);
    }
}
