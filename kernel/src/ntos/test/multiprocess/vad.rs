//! O VAD por processo (`ps/user/memory`): cada EPROCESS possui as próprias
//! regiões de usuário. Os serviços Nt* de memória virtual agem sobre o
//! processo corrente, aqui o anexado: a região de A não aparece no
//! NtQueryVirtualMemory de B nem é liberada pelo NtFreeVirtualMemory de B, as
//! alocações de baixo para cima de cada processo ficam no VAD dele, e o
//! término de A devolve só as regiões de A.

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::MemoryBasicInformation;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::{paging, query_virtual};
use crate::ntos::ps::{cid, process};
use crate::ntos::ps::process_context;
use crate::ntos::ps::user::memory::{self, Space};
use crate::ntos::ps::user::{memory_query, process_state};

type Assert = fn(bool, &str);

const MEM_COMMIT: u32 = 0x1000;
const MEM_FREE: u32 = 0x1_0000;
const MEM_RELEASE: u64 = 0x8000;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// Ponteiros dos serviços numa área de kernel: BaseAddress, RegionSize e a
/// pilha de argumentos (arg5 em +0x28 do rsp).
struct Scratch(u64);

impl Scratch {
    fn base(&self) -> u64 {
        self.0
    }
    fn size(&self) -> u64 {
        self.0 + 8
    }
    fn rsp(&self) -> u64 {
        self.0 + 0x40
    }

    /// NtAllocateVirtualMemory(MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) sem
    /// base, no processo corrente: a base escolhida ou 0.
    fn allocate(&self, size: u64) -> u64 {
        guest::write64(self.base(), 0);
        guest::write64(self.size(), size);
        guest::write64(self.rsp() + 0x28, 0x3000);
        guest::write64(self.rsp() + 0x30, 4);
        match memory::nt_allocate_virtual_memory(u64::MAX, self.base(), 0, self.size(), self.rsp()) {
            Ok(0) => guest::read64(self.base()),
            _ => 0,
        }
    }

    /// NtFreeVirtualMemory(MEM_RELEASE) no processo corrente.
    fn release(&self, base: u64) -> u32 {
        guest::write64(self.base(), base);
        guest::write64(self.size(), 0);
        memory::nt_free_virtual_memory(u64::MAX, self.base(), self.size(), MEM_RELEASE, 0).unwrap_or(1)
    }

    /// MEMORY_BASIC_INFORMATION.State pelo NtQueryVirtualMemory do processo
    /// corrente; `out` é um buffer de usuário desse processo.
    fn query_state(&self, out: u64, base: u64) -> u32 {
        guest::write64(self.rsp() + 0x28, MemoryBasicInformation::SIZE);
        guest::write64(self.rsp() + 0x30, 0);
        match memory_query::query_virtual_memory(u64::MAX, base, 0, out, self.rsp()) {
            // SAFETY: buffer de usuário mapeado do processo corrente.
            Ok(0) => unsafe { MemoryBasicInformation::at(out) }.state.get(),
            _ => 0,
        }
    }
}

pub fn run(assert: Assert) {
    if process::get_current_thread() == 0 {
        assert(false, "vad: thread corrente para anexar");
        return;
    }
    let block = guest::alloc_bytes(0x100);
    let kernel_info = guest::alloc_bytes(MemoryBasicInformation::SIZE);
    let scratch = Scratch(block);
    let system_regions = Space::system().regions().len();
    let Ok(first) = process::create_process(cid::ALLOCATE, "vad-a.exe", 0, None) else {
        assert(false, "vad: processo A criado");
        return;
    };
    let Ok(second) = process::create_process(cid::ALLOCATE, "vad-b.exe", 0, None) else {
        let _ = process::terminate_process(first, 0);
        assert(false, "vad: processo B criado");
        return;
    };
    let within = |target: u64, body: &dyn Fn() -> u64| process_context::with_process(target, body).unwrap_or(0);
    let seen = |target: u64, base: u64| within(target, &|| memory::find_region(base).is_some() as u64) != 0;

    // Alocações de baixo para cima em A e em B, intercaladas: o buffer de
    // consulta e uma região em cada um, depois mais uma em A.
    let a_out = within(first, &|| scratch.allocate(0x1000));
    let b_out = within(second, &|| scratch.allocate(0x1000));
    let a_region = within(first, &|| scratch.allocate(0x3000));
    let b_region = within(second, &|| scratch.allocate(0x2000));
    let a_second = within(first, &|| scratch.allocate(0x1000));
    let bases = [a_out, b_out, a_region, b_region, a_second];
    assert(bases.iter().all(|&base| base != 0 && base % 0x1_0000 == 0) && bases.iter().enumerate().all(|(index, base)| !bases[..index].contains(base)), "vad: alocacoes de baixo para cima em A e em B");
    assert(seen(first, a_out) && seen(first, a_region) && seen(first, a_second) && !seen(first, b_out) && !seen(first, b_region), "vad: A rastreia so as proprias alocacoes");
    assert(seen(second, b_out) && seen(second, b_region) && !seen(second, a_out) && !seen(second, a_region) && !seen(second, a_second), "vad: B rastreia so as proprias alocacoes");
    assert(Space::of(first).regions().len() == 3 && Space::of(second).regions().len() == 2 && Space::system().regions().len() == system_regions, "vad: cada VAD com as suas regioes e o do System intacto");

    // NtQueryVirtualMemory: a região de A é MEM_COMMIT em A e MEM_FREE em B.
    let state_in = |target: u64, out: u64, base: u64| within(target, &|| scratch.query_state(out, base) as u64) as u32;
    assert(state_in(first, a_out, a_region) == MEM_COMMIT && state_in(second, b_out, a_region) == MEM_FREE && state_in(second, b_out, b_region) == MEM_COMMIT && state_in(first, a_out, b_region) == MEM_FREE, "vad: NtQueryVirtualMemory em B nao ve a regiao de A");
    // O ZwQueryVirtualMemory pelo pseudo-handle segue o processo anexado.
    let zw_state = |target: u64, base: u64| within(target, &|| if query_virtual::query(u64::MAX, base, 0, kernel_info, MemoryBasicInformation::SIZE, 0).is_ok_and(|status| status == 0) { unsafe { MemoryBasicInformation::at(kernel_info) }.state.get() as u64 } else { 0 }) as u32;
    assert(zw_state(first, a_region) == MEM_COMMIT && zw_state(second, a_region) == MEM_FREE, "vad: ZwQueryVirtualMemory em B nao ve a regiao de A");

    // NtFreeVirtualMemory em B não acha a região de A.
    let freed = within(second, &|| scratch.release(a_region) as u64) as u32;
    assert(freed == STATUS_INVALID_PARAMETER && seen(first, a_region) && paging::translate(a_region) != 0, "vad: NtFreeVirtualMemory em B nao libera a regiao de A");

    // O término de A devolve as regiões de A, e só elas.
    assert(process::terminate_process(first, 0).is_ok() && process_state::get(first).is_none() && [a_out, a_region, a_second].iter().all(|&base| paging::translate(base) == 0), "vad: termino de A devolve as regioes de A");
    assert(seen(second, b_out) && seen(second, b_region) && paging::translate(b_region) != 0 && state_in(second, b_out, b_region) == MEM_COMMIT && Space::of(second).regions().len() == 2, "vad: as regioes de B sobrevivem ao termino de A");

    // B libera a própria região e o término devolve o resto.
    let released = within(second, &|| scratch.release(b_region) as u64) as u32;
    assert(released == 0 && paging::translate(b_region) == 0 && !seen(second, b_region), "vad: B libera a propria regiao");
    assert(process::terminate_process(second, 0).is_ok() && paging::translate(b_out) == 0 && Space::system().regions().len() == system_regions, "vad: termino de B devolve o resto e o System segue intacto");
    guest::free_bytes(kernel_info);
    guest::free_bytes(block);
}
