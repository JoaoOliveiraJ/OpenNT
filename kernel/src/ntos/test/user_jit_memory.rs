//! Memória de JIT e de alocador de modo usuário (o d3d10warp e o d3d11):
//! a troca RW→RX pelo commit, PAGE_TARGETS_*, PAGE_GUARD de uma vez,
//! MEM_WRITE_WATCH com NtGetWriteWatch/NtResetWriteWatch e a classe de alvos
//! de CFG do NtSetInformationVirtualMemory num processo sem CFG.

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::paging;
use crate::ntos::ps::user::memory;
use crate::ntos::ps::user::memory_query::{self, Context};
use crate::ntos::ps::user::state;

type Assert = fn(bool, &str);

pub fn run(assert: Assert) {
    let block = guest::alloc_bytes(0x100);
    let (base_pointer, size_pointer, rsp) = (block, block + 8, block + 0x40);
    let allocate = |base: u64, size: u64, kind: u32, protect: u32| {
        guest::write64(base_pointer, base);
        guest::write64(size_pointer, size);
        guest::write32(rsp + 0x28, kind);
        guest::write32(rsp + 0x30, protect);
        memory::nt_allocate_virtual_memory(u64::MAX, base_pointer, 0, size_pointer, rsp).unwrap_or(1)
    };
    let release = |base: u64| {
        guest::write64(base_pointer, base);
        guest::write64(size_pointer, 0);
        memory::nt_free_virtual_memory(u64::MAX, base_pointer, size_pointer, 0x8000, 0).unwrap_or(1)
    };
    let describe = |va: u64| memory_query::describe(va, &Context::current());
    // Os parâmetros que os serviços sondam como memória de usuário.
    if allocate(0, 0x2000, 0x3000, 4) != 0 {
        assert(false, "jitmemory: pagina de parametros");
        guest::free_bytes(block);
        return;
    }
    let scratch = guest::read64(base_pointer);
    let protect_rsp = block + 0x80;
    guest::write64(protect_rsp + 0x28, scratch + 0x10);
    let protect = |base: u64, size: u64, value: u64| {
        guest::write64(scratch, base);
        guest::write64(scratch + 8, size);
        memory::nt_protect_virtual_memory(u64::MAX, scratch, scratch + 8, value, protect_rsp).unwrap_or(1)
    };

    // RW→RX: o commit sobre páginas comitadas com outra proteção troca a
    // proteção da faixa (o MmProtectVirtualMemory do MiAllocateVirtualMemory).
    let committed = allocate(0, 0x2000, 0x3000, 4);
    let code = guest::read64(base_pointer);
    guest::write32(code, 0xC3C3_C3C3);
    let recommitted = committed == 0 && allocate(code, 0x2000, 0x1000, 0x20) == 0;
    assert(recommitted && describe(code).protect == 0x20 && paging::access_flags(code) & paging::PAGE_RW == 0 && guest::read32(code) == 0xC3C3_C3C3, "jitmemory: MEM_COMMIT sobre paginas RW passa a PAGE_EXECUTE_READ com o conteudo");
    // PAGE_TARGETS_NO_UPDATE só com proteção executável simples;
    // PAGE_TARGETS_INVALID só com proteção executável; sem CFG, sem efeito.
    assert(protect(code, 0x1000, 0x4000_0004) == 0xC000_00F2 && protect(code, 0x1000, 0x4000_0000) == 0xC000_0045 && protect(code, 0x1000, 0x4000_0040) == 0 && guest::read32(scratch + 0x10) == 0x20 && describe(code).protect == 0x40, "jitmemory: PAGE_TARGETS_NO_UPDATE conferido e retirado");
    let targets = allocate(0, 0x1000, 0x3000, 0x4000_0020);
    let invalid = guest::read64(base_pointer);
    assert(targets == 0 && describe(invalid).allocation_protect == 0x20 && release(invalid) == 0 && allocate(0, 0x1000, 0x3000, 0x4000_0004) == 0xC000_0045, "jitmemory: PAGE_TARGETS_INVALID so com protecao executavel");

    // PAGE_GUARD: PTE ausente, uma vez só; uma escrita numa guarda somente
    // leitura não tira a guarda.
    let guard = code + 0x1000;
    assert(protect(guard, 0x1000, 0x104) == 0 && describe(guard).protect == 0x104 && paging::access_flags(guard) & paging::PAGE_PRESENT == 0, "jitmemory: PAGE_GUARD deixa a PTE ausente com a protecao registrada");
    assert(!state::probe_user_read(guard, 8) && describe(guard).protect == 4 && state::probe_user_read(guard, 8), "jitmemory: o primeiro toque fora da pilha tira a guarda e falha; o seguinte passa");
    assert(protect(guard, 0x1000, 0x102) == 0 && !state::probe_user_write(guard, 8) && describe(guard).protect == 0x102 && !state::probe_user_read(guard, 8) && describe(guard).protect == 2, "jitmemory: escrita numa guarda somente leitura nao tira a guarda");
    let guarded = allocate(0, 0x1000, 0x3000, 0x104);
    let guarded_base = guest::read64(base_pointer);
    assert(guarded == 0 && describe(guarded_base).protect == 0x104 && paging::access_flags(guarded_base) & paging::PAGE_PRESENT == 0 && release(guarded_base) == 0 && allocate(0, 0x1000, 0x3000, 0x304) == 0xC000_0045, "jitmemory: commit com PAGE_GUARD e combinacao invalida");

    // MEM_WRITE_WATCH só numa reserva; NtGetWriteWatch/NtResetWriteWatch.
    let watched_status = allocate(0, 0x3000, 0x20_3000, 4);
    let watched = guest::read64(base_pointer);
    assert(watched_status == 0 && allocate(watched, 0x1000, 0x20_1000, 4) == 0xC000_000D, "jitmemory: MEM_WRITE_WATCH so com MEM_RESERVE");
    let (array, entries, granularity) = (scratch + 0x100, scratch + 0x20, scratch + 0x28);
    let watch_rsp = block + 0xC0;
    guest::write64(watch_rsp + 0x28, array);
    guest::write64(watch_rsp + 0x30, entries);
    guest::write64(watch_rsp + 0x38, granularity);
    let get = |flags: u64, base: u64, size: u64, limit: u64| {
        guest::write64(entries, limit);
        guest::write32(granularity, 0);
        crate::ntos::mm::write_watch::nt_get_write_watch(u64::MAX, flags, base, size, watch_rsp).unwrap_or(1)
    };
    assert(get(0, watched, 0x3000, 8) == 0 && guest::read64(entries) == 0 && guest::read32(granularity) == 0x1000, "jitmemory: write watch sem escrita");
    guest::write32(watched + 0x1000, 1);
    assert(get(0, watched, 0x3000, 8) == 0 && guest::read64(entries) == 1 && guest::read64(array) == watched + 0x1000, "jitmemory: a pagina escrita aparece");
    assert(get(1, watched, 0x3000, 8) == 0 && guest::read64(entries) == 1 && get(0, watched, 0x3000, 8) == 0 && guest::read64(entries) == 0, "jitmemory: WRITE_WATCH_FLAG_RESET limpa o que devolveu");
    guest::write32(watched, 1);
    guest::write32(watched + 0x2000, 1);
    assert(crate::ntos::mm::write_watch::nt_reset_write_watch(u64::MAX, watched, 0x3000).is_ok_and(|status| status == 0) && get(0, watched, 0x3000, 8) == 0 && guest::read64(entries) == 0, "jitmemory: NtResetWriteWatch limpa a faixa");
    guest::write32(watched + 0x2000, 1);
    guest::write32(watched, 1);
    guest::write32(watched + 0x1000, 1);
    let captured = protect(watched + 0x2000, 0x1000, 2) == 0;
    assert(captured && get(0, watched, 0x3000, 2) == 0 && guest::read64(entries) == 2 && guest::read64(array) == watched && guest::read64(array + 8) == watched + 0x1000 && get(0, watched + 0x2000, 0x1000, 8) == 0 && guest::read64(entries) == 1, "jitmemory: o vetor enche em ordem e a troca de protecao guarda o bit Dirty");
    assert(get(2, watched, 0x1000, 8) == 0xC000_00F0 && get(0, code, 0x1000, 8) == 0xC000_00EF && get(0, watched, 0, 8) == 0xC000_00F2 && get(0, watched, 0x4000, 8) == 0xC000_00EF && get(0, watched, 0x1000, 0) == 0xC000_00F3 && crate::ntos::mm::write_watch::nt_reset_write_watch(u64::MAX, watched, 0).is_ok_and(|status| status == 0xC000_00F1), "jitmemory: recusas do NtGetWriteWatch e do NtResetWriteWatch");
    assert(release(watched) == 0, "jitmemory: alocacao com write watch liberada");

    // VmCfgCallTargetInformation sem CFG: a lista é conferida e o resultado
    // é STATUS_INVALID_PAGE_PROTECTION com NumberOfEntriesProcessed 0.
    let (ranges, list, processed, call_targets) = (scratch + 0x200, scratch + 0x40, scratch + 0x80, scratch + 0x300);
    let cfg_rsp = block + 0xC0;
    let set_targets = |count: u32, offset: u64, flags: u64, ranges_count: u64, length: u32| {
        guest::write64(ranges, code);
        guest::write64(ranges + 8, 0x1000);
        guest::write64(ranges + 0x10, code + 0x1000);
        guest::write64(ranges + 0x18, 0x1000);
        guest::write32(list, count);
        guest::write32(list + 4, 0);
        guest::write64(list + 8, processed);
        guest::write64(list + 0x10, call_targets);
        guest::write64(list + 0x18, 0);
        guest::write64(list + 0x20, 0);
        guest::write64(call_targets, offset);
        guest::write64(call_targets + 8, flags);
        guest::write32(processed, 0xFFFF_FFFF);
        guest::write64(cfg_rsp + 0x28, list);
        guest::write32(cfg_rsp + 0x30, length);
        memory::nt_set_information_virtual_memory(u64::MAX, 2, ranges_count, ranges, cfg_rsp).unwrap_or(1)
    };
    assert(set_targets(1, 0x10, 1, 1, 0x28) == 0xC000_0045 && guest::read32(processed) == 0, "jitmemory: SetProcessValidCallTargets sem CFG");
    assert(set_targets(1, 0x18, 1, 1, 0x28) == 0xC000_000D && guest::read32(processed) == 0 && set_targets(1, 0x10, 8, 1, 0x28) == 0xC000_000D && set_targets(1, 0x10, 4, 1, 0x28) == 0xC000_0022, "jitmemory: alvos desalinhados, flags desconhecidas e supressao de exports");
    assert(set_targets(0, 0x10, 1, 1, 0x28) == 0xC000_00F3 && set_targets(1, 0x10, 1, 1, 0x20) == 0xC000_00F4 && set_targets(1, 0x10, 1, 2, 0x28) == 0xC000_00F2 && guest::read32(processed) == 0xFFFF_FFFF, "jitmemory: lista vazia, tamanho errado e mais de uma faixa");

    assert(release(code) == 0 && release(scratch) == 0, "jitmemory: regioes liberadas");
    guest::free_bytes(block);
}
