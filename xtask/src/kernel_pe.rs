//! Empacota o kernel ELF ligado como PE32+ de base fixa — transcrição de
//! `buildKernelPe` em `tools/kernel-pe.mjs`.
//!
//! Cada seção alocada mantém endereço e bytes; os offsets do arquivo são
//! iguais às RVAs para o stage2 carregar a imagem linearmente. A seção
//! `.kdata` guarda as globais exportadas e `.edata` o diretório de exports do
//! `ntoskrnl.exe`: os slots de função da ABI (na ordem dos grupos) apontam
//! para os trampolins MS-ABI de dez bytes ou para o corpo x64 próprio dos
//! exports nativos, seguidos dos exports de dados. Ordinal N = slot N-1, como
//! no `ntoskrnl.lib` dos drivers.

use crate::elf::{Elf, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS, SHT_PROGBITS};

#[path = "../../kernel/src/ntos/mm/kernel_data_layout.rs"]
#[allow(dead_code)]
mod kernel_data_layout;

#[path = "../../kernel/src/ntos/init/export_names.rs"]
#[allow(dead_code)]
mod abi_names;

#[path = "../../kernel/src/ntos/init/native_export_layout.rs"]
#[allow(dead_code)]
mod native_export_layout;

/// Bytes por trampolim (`hal::win32_thunk::STUB_SIZE`).
const STUB_SIZE: u64 = 10;

pub const BASE: u64 = 0x100000;
pub const ALIGN: u64 = 0x1000;
pub const MAX: u64 = 13 * 1024 * 1024;

fn align(value: u64) -> u64 {
    value.div_ceil(ALIGN) * ALIGN
}

fn check(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(format!("kernel PE: {message}"))
    }
}

struct PeSection<'a> {
    name: String,
    rva: u64,
    size: u64,
    raw_size: u64,
    characteristics: u32,
    data: &'a [u8],
}

fn put16(image: &mut [u8], at: usize, value: u16) {
    image[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(image: &mut [u8], at: usize, value: u32) {
    image[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(image: &mut [u8], at: usize, value: u64) {
    image[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

pub fn build_kernel_pe(elf_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let linked = Elf::parse(elf_bytes)?;

    let mut allocated: Vec<_> = linked
        .sections
        .iter()
        .filter(|section| section.flags & SHF_ALLOC != 0 && section.size != 0)
        .collect();
    allocated.sort_by_key(|section| section.address);

    let mut sections: Vec<PeSection> = Vec::new();
    let mut top = ALIGN;
    for section in allocated {
        check(
            section.kind == SHT_PROGBITS || section.kind == SHT_NOBITS,
            &format!("secao alocada nao suportada {}", section.name),
        )?;
        let name = if section.name == ".rodata" { ".rdata".to_string() } else { section.name.clone() };
        let rva = section.address.checked_sub(BASE).ok_or("kernel PE: secao abaixo da base")?;
        check(
            name.len() <= 8 && rva % ALIGN == 0 && rva >= top,
            &format!("secao sobreposta ou desalinhada {name}"),
        )?;
        top = rva + align(section.size);
        check(top <= MAX, "kernel excede a memoria reservada")?;
        let nobits = section.kind == SHT_NOBITS;
        let characteristics = (if section.flags & SHF_EXECINSTR != 0 {
            0x2000_0020
        } else if nobits {
            0x80
        } else {
            0x40
        }) | 0x4000_0000
            | if section.flags & SHF_WRITE != 0 { 0x8000_0000 } else { 0 };
        sections.push(PeSection {
            name,
            rva,
            size: section.size,
            raw_size: if nobits { 0 } else { align(section.size) },
            characteristics,
            data: if nobits { &[] } else { linked.range(section.offset, section.size)? },
        });
    }

    // ---- .kdata: globais exportadas (ntos/mm/kernel_data_layout.rs) --------
    let data_size = kernel_data_layout::required_byte_length();
    let mut data = vec![0u8; align(data_size) as usize];
    let mut data_targets = Vec::new();
    for (index, entry) in kernel_data_layout::DEFINITIONS.iter().enumerate() {
        let offset = kernel_data_layout::offset_of(index);
        check(
            entry.size > 0
                && entry.size <= 4096
                && entry.storage_size >= entry.size
                && [1, 2, 4, 8, 16].contains(&entry.alignment)
                && offset % entry.alignment == 0
                && entry.initial.len() as u64 == entry.size,
            "layout de exports de dados invalido",
        )?;
        data[offset as usize..offset as usize + entry.initial.len()].copy_from_slice(entry.initial);
        data_targets.push((entry.name, BASE + top + offset));
    }
    let kdata_rva = top;
    top += data.len() as u64;
    check(top <= MAX, "exports de dados excedem a memoria reservada")?;

    // ---- .edata: diretório de exports do ntoskrnl.exe -----------------------
    // Slots de função primeiro (id do trampolim = 32 + slot), depois os dados
    // que não repetem um nome de função.
    let thunk_base = *linked.symbols.get("opennt_win32_stubs").ok_or("kernel PE: tabela de trampolins ausente")?;
    let function_slots = abi_names::EXPORT_NAMES;
    check(function_slots.iter().collect::<std::collections::BTreeSet<_>>().len() == function_slots.len(), "exports de funcao duplicados")?;
    let mut export_targets: Vec<(&str, u64, bool)> = Vec::new();
    for (slot, name) in function_slots.iter().enumerate() {
        let target = match native_export_layout::lookup(name) {
            Some((symbol, _, _)) => *linked.symbols.get(&format!("opennt_{symbol}")).ok_or_else(|| format!("kernel PE: corpo nativo ausente: {name}"))?,
            None => thunk_base + (32 + slot as u64) * STUB_SIZE,
        };
        export_targets.push((name, target, true));
    }
    for (name, target) in &data_targets {
        if !function_slots.contains(name) {
            export_targets.push((name, *target, false));
        }
    }
    check(export_targets.len() <= 65535, "exports demais")?;
    let export_names: Vec<&str> = export_targets.iter().map(|(name, _, _)| *name).collect();
    let export_rva = top;
    let eat = 40usize;
    let names_at = eat + export_names.len() * 4;
    let ordinals_at = names_at + export_names.len() * 4;
    let mut cursor = ordinals_at + export_names.len() * 2;
    let mut strings: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut add_string = |value: &str, cursor: &mut usize| -> u32 {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        let offset = *cursor;
        *cursor += bytes.len();
        strings.push((offset, bytes));
        (export_rva + offset as u64) as u32
    };
    let dll_name = add_string("ntoskrnl.exe", &mut cursor);
    let mut sorted: Vec<(usize, &str)> = export_names.iter().copied().enumerate().collect();
    sorted.sort_by(|a, b| a.1.cmp(b.1));
    let name_rvas: Vec<u32> = sorted.iter().map(|(_, name)| add_string(name, &mut cursor)).collect();
    let mut export_data = vec![0u8; align(cursor as u64) as usize];
    put32(&mut export_data, 12, dll_name);
    put32(&mut export_data, 16, 1);
    put32(&mut export_data, 20, export_names.len() as u32);
    put32(&mut export_data, 24, export_names.len() as u32);
    put32(&mut export_data, 28, (export_rva + eat as u64) as u32);
    put32(&mut export_data, 32, (export_rva + names_at as u64) as u32);
    put32(&mut export_data, 36, (export_rva + ordinals_at as u64) as u32);
    for (index, (_, target, _)) in export_targets.iter().enumerate() {
        put32(&mut export_data, eat + index * 4, (target - BASE) as u32);
        put32(&mut export_data, names_at + index * 4, name_rvas[index]);
        put16(&mut export_data, ordinals_at + index * 2, sorted[index].0 as u16);
    }
    for (offset, bytes) in &strings {
        export_data[*offset..*offset + bytes.len()].copy_from_slice(bytes);
    }
    let export_size = cursor as u64;
    top += export_data.len() as u64;
    check(top <= MAX, "kernel excede a memoria reservada")?;
    sections.push(PeSection {
        name: ".kdata".into(),
        rva: kdata_rva,
        size: data_size,
        raw_size: data.len() as u64,
        characteristics: 0xC000_0040,
        data: &[],
    });
    sections.push(PeSection {
        name: ".edata".into(),
        rva: export_rva,
        size: export_size,
        raw_size: export_data.len() as u64,
        characteristics: 0x4000_0040,
        data: &[],
    });
    let owned_data: Vec<(u64, Vec<u8>)> = vec![(kdata_rva, data), (export_rva, export_data)];

    let executable = |address: u64| {
        sections.iter().any(|section| {
            section.characteristics & 0x20 != 0
                && address >= BASE + section.rva
                && address < BASE + section.rva + section.size
        })
    };
    check(
        linked.symbols.get("kernel_main") == Some(&linked.entry) && executable(linked.entry),
        "a entrada deve ser o kernel_main ligado",
    )?;
    for (name, target, function) in &export_targets {
        if *function {
            check(executable(*target) && executable(*target + STUB_SIZE - 1), &format!("export fora da secao de codigo: {name}"))?;
        }
    }
    check(0x80 + 24 + 240 + sections.len() * 40 <= ALIGN as usize, "cabecalhos excedem o espaco reservado")?;

    let mut image = vec![0u8; top as usize];
    // Cabeçalho DOS: uma invocação DOS sai com erro; só a entrada PE nativa vale.
    put16(&mut image, 0, 0x5A4D);
    put16(&mut image, 2, 0x80);
    put16(&mut image, 4, 1);
    put16(&mut image, 8, 4);
    put16(&mut image, 12, 0xFFFF);
    put16(&mut image, 16, 0xB8);
    put16(&mut image, 24, 0x40);
    image[0x40..0x45].copy_from_slice(&[0xB8, 0x01, 0x4C, 0xCD, 0x21]);
    put32(&mut image, 0x3C, 0x80);

    let pe = 0x80usize;
    let optional = pe + 24;
    put32(&mut image, pe, 0x4550);
    put16(&mut image, pe + 4, 0x8664);
    put16(&mut image, pe + 6, sections.len() as u16);
    put16(&mut image, pe + 20, 240);
    put16(&mut image, pe + 22, 0x23); // executável, large-address-aware, base fixa
    put16(&mut image, optional, 0x20B);
    let sum = |mask: u32, uninitialized: bool| -> u32 {
        sections
            .iter()
            .filter(|section| section.characteristics & mask != 0)
            .map(|section| if uninitialized { align(section.size) } else { section.raw_size })
            .sum::<u64>() as u32
    };
    put32(&mut image, optional + 4, sum(0x20, false));
    put32(&mut image, optional + 8, sum(0x40, false));
    put32(&mut image, optional + 12, sum(0x80, true));
    put32(&mut image, optional + 16, (linked.entry - BASE) as u32);
    let base_of_code = sections.iter().find(|section| section.characteristics & 0x20 != 0).unwrap().rva;
    put32(&mut image, optional + 20, base_of_code as u32);
    put64(&mut image, optional + 24, BASE);
    put32(&mut image, optional + 32, ALIGN as u32);
    put32(&mut image, optional + 36, ALIGN as u32);
    put16(&mut image, optional + 40, 10); // alvo de compatibilidade da ABI NT
    put16(&mut image, optional + 44, 1); // versão da imagem 1.0
    put16(&mut image, optional + 48, 10);
    put32(&mut image, optional + 56, top as u32);
    put32(&mut image, optional + 60, ALIGN as u32);
    put16(&mut image, optional + 68, 1); // subsistema nativo
    put32(&mut image, optional + 108, 16);
    put32(&mut image, optional + 112, export_rva as u32);
    put32(&mut image, optional + 116, export_size as u32);

    for (index, section) in sections.iter().enumerate() {
        let at = optional + 240 + index * 40;
        image[at..at + section.name.len()].copy_from_slice(section.name.as_bytes());
        put32(&mut image, at + 8, section.size as u32);
        put32(&mut image, at + 12, section.rva as u32);
        put32(&mut image, at + 16, section.raw_size as u32);
        put32(&mut image, at + 20, if section.raw_size != 0 { section.rva as u32 } else { 0 });
        put32(&mut image, at + 36, section.characteristics);
        if section.raw_size != 0 {
            let start = section.rva as usize;
            image[start..start + section.data.len()].copy_from_slice(section.data);
        }
    }
    for (rva, bytes) in &owned_data {
        image[*rva as usize..*rva as usize + bytes.len()].copy_from_slice(bytes);
    }

    let mut checksum: u64 = 0;
    for chunk in image.chunks(2) {
        let word = chunk[0] as u64 | (*chunk.get(1).unwrap_or(&0) as u64) << 8;
        checksum += word;
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    let checksum = ((checksum & 0xFFFF) + (checksum >> 16) + image.len() as u64) as u32;
    put32(&mut image, optional + 64, checksum);
    Ok(image)
}
