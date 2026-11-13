//! Extensões "pendentes" (dangling) de memória persistente —
//! MiIsExtentDangling (0x8d0068), alcançado por FsRtlIsExtentDangling
//! (0x88c1d0) com Flags = 0.
//!
//! No NT uma página física é "dangling" quando o seu PFN tem o bit 49 de
//! +0x28 ligado (página de memória persistente cujo dispositivo saiu) ou
//! quando cai numa faixa da árvore de extensões removidas (raiz em
//! 0xc4cce0, sob push lock). A rotina devolve o primeiro PFN pendente de
//! [StartPage, StartPage + NumberOfPages) ou StartPage + NumberOfPages
//! quando nenhum é.
//!
//! O OpenNT não tem memória persistente/DAX nem remoção a quente: nenhum
//! PFN recebe a marca e a árvore de faixas removidas é sempre vazia. O
//! resultado é exatamente o que o NT devolve nessa configuração.

/// MiIsExtentDangling(StartPage, NumberOfPages, 0) -> PFN_NUMBER.
pub fn first_dangling_page(start_page: u64, page_count: u64) -> u64 {
    start_page.wrapping_add(page_count)
}
