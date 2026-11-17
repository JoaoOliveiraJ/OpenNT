//! Um overlay qcow2 vazio sobre uma imagem crua, sem o `qemu-img`: o
//! cabeçalho da versão 3 (clusters de 64 KB), a extensão com o formato do
//! disco de trás (`raw`), o nome dele, a tabela de refcount com um bloco e
//! a tabela L1 zerada. Tudo o que o convidado grava vai para o overlay, e
//! os snapshots internos do QEMU (`savevm`) ficam nele.
//!
//! ```text
//! cluster 0: cabeçalho | extensões | nome do disco de trás
//! cluster 1: tabela de refcount (a entrada 0 aponta o cluster 2)
//! cluster 2: bloco de refcount (16 bits por cluster; os quatro primeiros = 1)
//! cluster 3: tabela L1 (uma entrada para cada 512 MB do disco, zeradas)
//! ```

use std::path::Path;

const MAGIC: u32 = 0x5146_49FB;
const CLUSTER_BITS: u32 = 16;
const CLUSTER: u64 = 1 << CLUSTER_BITS;
const HEADER_LENGTH: u32 = 104;
/// A extensão do formato do disco de trás.
const BACKING_FORMAT: u32 = 0xE279_2ACA;

/// O conteúdo do overlay de um disco de `size` bytes sobre `backing` (cru).
pub fn overlay_bytes(backing: &str, size: u64) -> Result<Vec<u8>, String> {
    // Cada entrada da L1 cobre uma tabela L2 de 8192 clusters (512 MB).
    let l1_size = size.div_ceil(CLUSTER * (CLUSTER / 8));
    if l1_size * 8 > CLUSTER {
        return Err(format!("disco grande demais para o overlay ({size} bytes)"));
    }
    let mut image = vec![0u8; 4 * CLUSTER as usize];
    let put32 = |image: &mut Vec<u8>, offset: usize, value: u32| image[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    let put64 = |image: &mut Vec<u8>, offset: usize, value: u64| image[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    // Extensões logo depois do cabeçalho: o formato e o fim.
    let mut offset = HEADER_LENGTH as usize;
    put32(&mut image, offset, BACKING_FORMAT);
    put32(&mut image, offset + 4, 3);
    image[offset + 8..offset + 11].copy_from_slice(b"raw");
    offset += 16;
    put32(&mut image, offset, 0);
    put32(&mut image, offset + 4, 0);
    offset += 8;
    let name = backing.as_bytes();
    if offset + name.len() > CLUSTER as usize || name.len() > 1023 {
        return Err(format!("caminho do disco de tras longo demais: {backing}"));
    }
    image[offset..offset + name.len()].copy_from_slice(name);
    put32(&mut image, 0, MAGIC);
    put32(&mut image, 4, 3);
    put64(&mut image, 8, offset as u64);
    put32(&mut image, 16, name.len() as u32);
    put32(&mut image, 20, CLUSTER_BITS);
    put64(&mut image, 24, size);
    put32(&mut image, 32, 0);
    put32(&mut image, 36, l1_size as u32);
    put64(&mut image, 40, 3 * CLUSTER);
    put64(&mut image, 48, CLUSTER);
    put32(&mut image, 56, 1);
    put32(&mut image, 60, 0);
    put64(&mut image, 64, 0);
    put64(&mut image, 72, 0);
    put64(&mut image, 80, 0);
    put64(&mut image, 88, 0);
    put32(&mut image, 96, 4);
    put32(&mut image, 100, HEADER_LENGTH);
    // Refcount: a tabela aponta o bloco; o bloco conta os quatro clusters.
    put64(&mut image, CLUSTER as usize, 2 * CLUSTER);
    for cluster in 0..4usize {
        let at = 2 * CLUSTER as usize + cluster * 2;
        image[at..at + 2].copy_from_slice(&1u16.to_be_bytes());
    }
    Ok(image)
}

/// Grava o overlay em `path` (substitui um anterior).
pub fn create_overlay(path: &Path, backing: &Path, size: u64) -> Result<(), String> {
    let shown = backing.display().to_string();
    // O caminho canônico do Windows (`\\?\C:\...`) sem o prefixo, que o
    // QEMU não abre como nome de arquivo do disco de trás.
    let shown = shown.strip_prefix(r"\\?\").unwrap_or(&shown).to_string();
    let bytes = overlay_bytes(&shown, size)?;
    std::fs::write(path, bytes).map_err(|error| format!("{}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn be32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    fn be64(bytes: &[u8], offset: usize) -> u64 {
        u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }

    #[test]
    fn header_and_tables() {
        let image = overlay_bytes("C:/build/os.img", 3 << 30).expect("overlay");
        assert_eq!(image.len(), 4 << 16);
        assert_eq!(be32(&image, 0), MAGIC);
        assert_eq!(be32(&image, 4), 3);
        assert_eq!(be64(&image, 24), 3 << 30);
        assert_eq!(be32(&image, 36), 6);
        assert_eq!(be64(&image, 40), 3 << 16);
        assert_eq!(be64(&image, 48), 1 << 16);
        assert_eq!(be32(&image, 100), 104);
        assert_eq!(be32(&image, 104), BACKING_FORMAT);
        let name_at = be64(&image, 8) as usize;
        let length = be32(&image, 16) as usize;
        assert_eq!(&image[name_at..name_at + length], b"C:/build/os.img");
        assert_eq!(be64(&image, 1 << 16), 2 << 16);
        assert_eq!(&image[(2 << 16)..(2 << 16) + 8], &[0, 1, 0, 1, 0, 1, 0, 1]);
        assert!(image[(3 << 16)..].iter().all(|&byte| byte == 0));
    }
}
