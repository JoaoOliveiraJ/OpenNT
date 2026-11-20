//! Acesso do depurador à memória virtual, sem travas e sem faltas.
//!
//! Com a máquina parada, o depurador não pode tomar travas do Mm (o dono
//! delas pode ser o código interrompido ou um processador congelado) nem
//! deixar uma falta de página acontecer. A tradução anda nas tabelas de
//! páginas do CR3 do processador escolhido, lendo as entradas pelo mapa
//! direto da memória física, e o acesso vai pelo mapa direto ao quadro: uma
//! página ausente termina a leitura ali, e a escrita passa por cima da
//! proteção da página (é assim que o breakpoint de software entra no código).

use crate::hal::physical::direct_map_limit;
use crate::ntos::mm::memory_map::direct_map;

const PRESENT: u64 = 1;
const LARGE_PAGE: u64 = 0x80;
const TABLE_ADDRESS: u64 = 0x000F_FFFF_FFFF_F000;
const PAGE_1G_ADDRESS: u64 = 0x000F_FFFF_C000_0000;
const PAGE_2M_ADDRESS: u64 = 0x000F_FFFF_FFE0_0000;

fn canonical(address: u64) -> bool {
    let high = address >> 47;
    high == 0 || high == 0x1_FFFF
}

/// Uma entrada de tabela de páginas pelo endereço físico.
fn table_entry(table: u64, index: u64) -> Option<u64> {
    let physical = (table & TABLE_ADDRESS) + index * 8;
    if physical + 8 > direct_map_limit() {
        return None;
    }
    // SAFETY: o mapa direto cobre toda a faixa física abaixo do limite.
    Some(unsafe { core::ptr::read_volatile(direct_map(physical) as *const u64) })
}

/// Endereço físico de `address` nas tabelas de `cr3`.
pub fn translate(cr3: u64, address: u64) -> Option<u64> {
    if !canonical(address) {
        return None;
    }
    let pml4 = table_entry(cr3, (address >> 39) & 511)?;
    if pml4 & PRESENT == 0 {
        return None;
    }
    let pdpt = table_entry(pml4, (address >> 30) & 511)?;
    if pdpt & PRESENT == 0 {
        return None;
    }
    if pdpt & LARGE_PAGE != 0 {
        return Some((pdpt & PAGE_1G_ADDRESS) + (address & 0x3FFF_FFFF));
    }
    let pd = table_entry(pdpt, (address >> 21) & 511)?;
    if pd & PRESENT == 0 {
        return None;
    }
    if pd & LARGE_PAGE != 0 {
        return Some((pd & PAGE_2M_ADDRESS) + (address & 0x1F_FFFF));
    }
    let pt = table_entry(pd, (address >> 12) & 511)?;
    if pt & PRESENT == 0 {
        return None;
    }
    // Uma página com breakpoint de memória tem o bit reservado ligado.
    let pt = if super::page_breakpoints::any() { super::page_breakpoints::unmarked(pt) } else { pt };
    Some((pt & TABLE_ADDRESS) + (address & 0xFFF))
}

/// O endereço físico da PTE de uma página de 4 KB (`None` numa página
/// grande ou sem tabela).
pub fn pte_address(cr3: u64, address: u64) -> Option<u64> {
    if !canonical(address) {
        return None;
    }
    let pml4 = table_entry(cr3, (address >> 39) & 511)?;
    if pml4 & PRESENT == 0 {
        return None;
    }
    let pdpt = table_entry(pml4, (address >> 30) & 511)?;
    if pdpt & PRESENT == 0 || pdpt & LARGE_PAGE != 0 {
        return None;
    }
    let pd = table_entry(pdpt, (address >> 21) & 511)?;
    if pd & PRESENT == 0 || pd & LARGE_PAGE != 0 {
        return None;
    }
    let physical = (pd & TABLE_ADDRESS) + ((address >> 12) & 511) * 8;
    (physical + 8 <= direct_map_limit()).then_some(physical)
}

/// Lê um qword físico pelo mapa direto.
pub fn read_physical_u64(physical: u64) -> u64 {
    // SAFETY: `physical` vem de `pte_address` (abaixo do limite).
    unsafe { core::ptr::read_volatile(direct_map(physical) as *const u64) }
}

/// Grava um qword físico pelo mapa direto.
pub fn write_physical_u64(physical: u64, value: u64) {
    // SAFETY: como em `read_physical_u64`.
    unsafe { core::ptr::write_volatile(direct_map(physical) as *mut u64, value) }
}

/// Pedaço acessível a partir de `address` (até o fim da página), como VA
/// do mapa direto.
fn window(cr3: u64, address: u64, wanted: usize) -> Option<(u64, usize)> {
    let physical = translate(cr3, address)?;
    let in_page = (0x1000 - (address & 0xFFF)) as usize;
    let length = wanted.min(in_page);
    if physical + length as u64 > direct_map_limit() {
        return None;
    }
    Some((direct_map(physical), length))
}

/// Lê até `output.len()` bytes; devolve quantos foram lidos antes da
/// primeira página inacessível.
pub fn read(cr3: u64, address: u64, output: &mut [u8]) -> usize {
    let mut done = 0;
    while done < output.len() {
        let Some((source, length)) = window(cr3, address.wrapping_add(done as u64), output.len() - done) else { break };
        for index in 0..length {
            // SAFETY: byte do mapa direto de um quadro traduzido.
            output[done + index] = unsafe { core::ptr::read_volatile((source + index as u64) as *const u8) };
        }
        done += length;
    }
    done
}

/// Escreve até `data.len()` bytes; devolve quantos foram escritos.
pub fn write(cr3: u64, address: u64, data: &[u8]) -> usize {
    let mut done = 0;
    while done < data.len() {
        let Some((target, length)) = window(cr3, address.wrapping_add(done as u64), data.len() - done) else { break };
        for index in 0..length {
            // SAFETY: byte do mapa direto de um quadro traduzido.
            unsafe { core::ptr::write_volatile((target + index as u64) as *mut u8, data[done + index]) };
        }
        done += length;
    }
    done
}

pub fn read_u8(cr3: u64, address: u64) -> Option<u8> {
    let mut byte = [0u8];
    (read(cr3, address, &mut byte) == 1).then_some(byte[0])
}

pub fn read_u16(cr3: u64, address: u64) -> Option<u16> {
    let mut bytes = [0u8; 2];
    (read(cr3, address, &mut bytes) == 2).then(|| u16::from_le_bytes(bytes))
}

pub fn read_u32(cr3: u64, address: u64) -> Option<u32> {
    let mut bytes = [0u8; 4];
    (read(cr3, address, &mut bytes) == 4).then(|| u32::from_le_bytes(bytes))
}

pub fn read_u64(cr3: u64, address: u64) -> Option<u64> {
    let mut bytes = [0u8; 8];
    (read(cr3, address, &mut bytes) == 8).then(|| u64::from_le_bytes(bytes))
}

pub fn write_u64(cr3: u64, address: u64, value: u64) -> bool {
    write(cr3, address, &value.to_le_bytes()) == 8
}
