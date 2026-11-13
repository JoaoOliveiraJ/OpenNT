//! A metade de usuário do espaço de endereços (PML4[0..256)).
//!
//! Como no NT, nada do kernel fica abaixo de MmSystemRangeStart: a imagem,
//! a pilha de boot, o heap, a arena, os aliases físicos e as janelas de
//! sistema moram na metade alta, e os dois únicos mapeamentos baixos do boot
//! (a identidade transitória do stage2 e a página do trampolim dos APs) saem
//! antes do fim da fase 0. O que existe na metade baixa depois disso são
//! páginas de usuário: imagens, pilhas, TEB/PEB, seções e a visão de usuário
//! da KUSER_SHARED_DATA em 0x7FFE0000. Este módulo percorre as tabelas reais
//! dessa metade atrás de uma folha presente que o anel 3 não alcança (algum
//! nível do caminho sem U/S): isso seria memória do kernel exposta no
//! espaço que pertence aos processos.

use alloc::vec::Vec;

use super::{memory_map as map, paging};

const FRAME_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// As folhas presentes de supervisor da metade de usuário, como (VA,
/// tamanho da página), até `limit` delas.
pub fn supervisor_mappings(limit: usize) -> Vec<(u64, u64)> {
    let mut found = Vec::new();
    walk(map::PML4_PHYS, 4, 0, true, limit, &mut found);
    found
}

fn walk(table: u64, level: u32, prefix: u64, user_path: bool, limit: usize, found: &mut Vec<(u64, u64)>) {
    let entries = if level == 4 { map::USER_PML4_ENTRIES } else { 512 };
    let shift = 12 + (level - 1) * 9;
    for index in 0..entries {
        if found.len() >= limit {
            return;
        }
        let entry = paging::read_entry(table + index * 8);
        if entry & paging::PAGE_PRESENT == 0 {
            continue;
        }
        let address = prefix | (index << shift);
        let user = user_path && entry & paging::PAGE_USER != 0;
        if level == 1 || (level < 4 && entry & paging::PAGE_PS != 0) {
            if !user {
                found.push((address, 1 << shift));
            }
            continue;
        }
        walk(entry & FRAME_MASK, level - 1, address, user, limit, found);
    }
}

/// Fim da fase 0: a metade de usuário não tem nenhuma folha de supervisor.
pub fn assert_user_only() {
    if let Some(&(address, size)) = supervisor_mappings(1).first() {
        panic!("kernel mapping left in the user half: {address:#x} (+{size:#x})");
    }
}
