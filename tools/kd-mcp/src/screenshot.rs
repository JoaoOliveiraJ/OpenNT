//! A tela do convidado em PNG pelo `screendump` do monitor HMP do QEMU
//! (o `--monitor-port` que o `xtask` abre no `--launch`). Pede PNG direto;
//! um QEMU sem PNG grava PPM, convertido aqui (PNG sem compressão, blocos
//! armazenados do deflate).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

/// Lê o monitor até o prompt `(qemu)` (ou o prazo).
fn read_prompt(stream: &mut TcpStream, deadline: Instant) -> String {
    let mut text = Vec::new();
    let mut chunk = [0u8; 4096];
    while Instant::now() < deadline {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                text.extend_from_slice(&chunk[..count]);
                if text.windows(6).any(|window| window == b"(qemu)") && text.ends_with(b" ") {
                    break;
                }
            }
            Err(_) => {}
        }
    }
    String::from_utf8_lossy(&text).into_owned()
}

fn command(stream: &mut TcpStream, text: &str) -> Result<String, String> {
    stream.write_all(format!("{text}\n").as_bytes()).map_err(|error| format!("monitor HMP: {error}"))?;
    Ok(read_prompt(stream, Instant::now() + Duration::from_secs(10)))
}

/// Grava a tela em `path` (PNG); devolve largura e altura.
pub fn capture(monitor: &str, path: &Path) -> Result<(u32, u32), String> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut stream = TcpStream::connect(monitor).map_err(|error| format!("monitor HMP {monitor}: {error}"))?;
    stream.set_read_timeout(Some(Duration::from_millis(200))).ok();
    read_prompt(&mut stream, Instant::now() + Duration::from_secs(3));
    let _ = std::fs::remove_file(path);
    let shown = path.display().to_string().replace('\\', "/");
    let reply = command(&mut stream, &format!("screendump {shown} -f png"))?;
    for _ in 0..50 {
        if path.is_file() && std::fs::metadata(path).map(|metadata| metadata.len() > 0).unwrap_or(false) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if let Ok(bytes) = std::fs::read(path) {
        if bytes.starts_with(b"\x89PNG") {
            return png_size(&bytes).ok_or_else(|| "PNG sem cabecalho".to_string());
        }
        if bytes.starts_with(b"P6") {
            let (width, height, pixels) = parse_ppm(&bytes)?;
            std::fs::write(path, encode_png(width, height, &pixels)).map_err(|error| format!("{}: {error}", path.display()))?;
            return Ok((width, height));
        }
    }
    // Sem PNG no QEMU: PPM e a conversão.
    let ppm = path.with_extension("ppm");
    let shown = ppm.display().to_string().replace('\\', "/");
    let second = command(&mut stream, &format!("screendump {shown}"))?;
    for _ in 0..50 {
        if ppm.is_file() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let bytes = std::fs::read(&ppm).map_err(|error| format!("screendump: {error} ({} {})", reply.trim(), second.trim()))?;
    let _ = std::fs::remove_file(&ppm);
    let (width, height, pixels) = parse_ppm(&bytes)?;
    std::fs::write(path, encode_png(width, height, &pixels)).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok((width, height))
}

fn png_size(bytes: &[u8]) -> Option<(u32, u32)> {
    let width = u32::from_be_bytes(bytes.get(16..20)?.try_into().ok()?);
    let height = u32::from_be_bytes(bytes.get(20..24)?.try_into().ok()?);
    Some((width, height))
}

/// Um PPM binário (P6, 8 bits): largura, altura e os pixels RGB.
pub fn parse_ppm(bytes: &[u8]) -> Result<(u32, u32, Vec<u8>), String> {
    let mut fields = Vec::new();
    let mut position = 2;
    while fields.len() < 3 && position < bytes.len() {
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
        while position < bytes.len() && bytes[position].is_ascii_digit() {
            position += 1;
        }
        fields.push(std::str::from_utf8(&bytes[start..position]).ok().and_then(|text| text.parse::<u32>().ok()).ok_or("PPM invalido")?);
    }
    position += 1;
    let (width, height) = (fields[0], fields[1]);
    let size = width as usize * height as usize * 3;
    let pixels = bytes.get(position..position + size).ok_or("PPM curto")?.to_vec();
    Ok((width, height, pixels))
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    b << 16 | a
}

fn chunk(output: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    output.extend_from_slice(&(data.len() as u32).to_be_bytes());
    let mut body = kind.to_vec();
    body.extend_from_slice(data);
    output.extend_from_slice(&body);
    output.extend_from_slice(&crc32(&body).to_be_bytes());
}

/// PNG RGB de 8 bits sem compressão (zlib com blocos armazenados).
pub fn encode_png(width: u32, height: u32, rgb: &[u8]) -> Vec<u8> {
    let mut raw = Vec::with_capacity((width as usize * 3 + 1) * height as usize);
    for row in rgb.chunks(width as usize * 3) {
        raw.push(0);
        raw.extend_from_slice(row);
    }
    let mut zlib = vec![0x78, 0x01];
    let mut blocks = raw.chunks(65535).peekable();
    while let Some(block) = blocks.next() {
        zlib.push(if blocks.peek().is_none() { 1 } else { 0 });
        zlib.extend_from_slice(&(block.len() as u16).to_le_bytes());
        zlib.extend_from_slice(&(!(block.len() as u16)).to_le_bytes());
        zlib.extend_from_slice(block);
    }
    zlib.extend_from_slice(&adler32(&raw).to_be_bytes());
    let mut output = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut header = Vec::new();
    header.extend_from_slice(&width.to_be_bytes());
    header.extend_from_slice(&height.to_be_bytes());
    header.extend_from_slice(&[8, 2, 0, 0, 0]);
    chunk(&mut output, b"IHDR", &header);
    chunk(&mut output, b"IDAT", &zlib);
    chunk(&mut output, b"IEND", &[]);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_ppm_to_png() {
        let mut ppm = b"P6\n# comentario\n2 1\n255\n".to_vec();
        ppm.extend_from_slice(&[255, 0, 0, 0, 0, 255]);
        let (width, height, pixels) = parse_ppm(&ppm).unwrap();
        assert_eq!((width, height, pixels.len()), (2, 1, 6));
        let png = encode_png(width, height, &pixels);
        assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert_eq!(png_size(&png), Some((2, 1)));
        assert_eq!(crc32(b"IEND"), 0xAE42_6082);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }
}
