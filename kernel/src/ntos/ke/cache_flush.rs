//! Invalidação dos caches de dados de todos os processadores
//! (KeInvalidateAllCaches e KeInvalidateRangeAllCaches).
//!
//! Segue o ntoskrnl 19041:
//! - KeInvalidateAllCaches (0x3a4700) sobe a SYNCH_LEVEL, manda a todos os
//!   processadores o pedido de IPI que executa o HalpAcpiFlushCache (WBINVD;
//!   o próprio processador também o executa) quando consegue marcar o
//!   KiCacheFlushTimeStamp (um flush já em curso cobre o pedido), volta ao
//!   IRQL anterior e devolve TRUE.
//! - KeInvalidateRangeAllCaches (0x51b030) com Length >= KiLargestCacheSize
//!   vira o KeInvalidateAllCaches; senão serializa os outros processadores e
//!   o KeInvalidateRangeAllCachesNoIpi faz CLFLUSH de cada linha de
//!   [Base alinhada a CFlushSize, Base + Length). O CLFLUSH invalida a linha
//!   em todos os caches do domínio de coerência, então a varredura local
//!   basta para o efeito; o OpenNT não tem o pacote de serialização remota.
//!
//! O WBINVD remoto do OpenNT é o da invalidação por NMI do `smp`, que já pede
//! WBINVD a cada processador online junto da invalidação de TLB.

use super::{irql, processor_topology, smp};
use crate::hal::cpu;

/// KeInvalidateAllCaches: WBINVD em todos os processadores; sempre TRUE.
pub fn invalidate_all_caches() -> bool {
    let previous = irql::raise_at_least(irql::SYNCH_LEVEL);
    cpu::flush_caches();
    // Um shootdown já em curso equivale ao KxSetTimeStampBusy que falha: o
    // flush dele cobre este pedido.
    let _ = smp::flush_remote_tlb(true);
    irql::lower_irql(previous as u64);
    true
}

/// KPRCB.CFlushSize como o KiSetFeatureBits grava: CPUID(1).EBX[15:8] * 8.
pub fn cache_flush_line_size() -> u64 {
    ((cpu::cpuid(1)[1] >> 5) & 0x7F8) as u64
}

/// KeInvalidateRangeAllCaches(BaseAddress, Length): faixas do tamanho do
/// maior cache viram o flush total; as demais são varridas linha a linha.
/// Devolve o valor do flush total (TRUE) ou 0 na varredura (o original não
/// define o retorno nesse caminho).
pub fn invalidate_range_all_caches(base: u64, length: u32) -> u64 {
    if length >= processor_topology::largest_cache_size() {
        return invalidate_all_caches() as u64;
    }
    let line = cache_flush_line_size();
    if line == 0 {
        return 0;
    }
    let end = base.wrapping_add(length as u64);
    let mut address = base & !(line - 1);
    while address < end {
        cpu::flush_cache_line(address);
        address += line;
    }
    0
}
