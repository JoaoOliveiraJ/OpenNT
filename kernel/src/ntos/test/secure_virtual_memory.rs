//! Autotestes das faixas protegidas por MmSecureVirtualMemory(Ex) e das
//! flags do NtUnmapViewOfSectionEx, num processo de usuário, contra o
//! ntoskrnl 19041 (`mm/secure_memory.rs`, `mm/section/unmap_view.rs`):
//!
//! - MmSecureVirtualMemoryEx (rva 0x620040): Flags além de 0xF, ProbeMode
//!   fora de {1, 2, 4} (0x80000001 inclusive) e faixas inválidas dão NULL; um
//!   VAD NoChange (com entradas ou SEC_NO_CHANGE) recusa a entrada exclusiva
//!   (Flags 1), e a exclusiva recusa as outras; com Flags 2 o MiSecureVad
//!   compara as páginas para escrita mesmo com ProbeMode PAGE_READONLY.
//! - MiCheckSecuredVad (rva 0x6db108) nas trocas de proteção
//!   (MmProtectVirtualMemory), nas liberações (MmFreeVirtualMemory: o
//!   MEM_RELEASE confere o VAD inteiro; o MEM_DECOMMIT, da base pedida sem
//!   arredondar pelo número de páginas) e no MEM_COMMIT sobre o VAD
//!   (MiAllocateVirtualMemory): leitura protegida aceita só proteções
//!   legíveis, escrita protegida só graváveis, guarda nunca; a entrada de
//!   Flags 4 só vale para PreviousMode UserMode; a de Flags 2 só aceita a
//!   proteção exata das páginas.
//! - NtUnmapViewOfSectionEx (rva 0x61e440) / MiUnmapViewOfSection
//!   (rva 0x61e510): Flags além de 3 dão STATUS_INVALID_PARAMETER_3; com
//!   MEM_PRESERVE_PLACEHOLDER, base fora de página dá
//!   STATUS_INVALID_PARAMETER_2 e uma vista que não veio de placeholder
//!   STATUS_CONFLICTING_ADDRESSES, depois da checagem de segurança;
//!   MEM_UNMAP_WITH_TRANSIENT_BOOST desmapeia normalmente.

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::objects::section as section_objects;
use crate::ntos::ps::process;
use crate::ntos::ps::user::{memory, sections, state};
use crate::ntos::test::multiprocess::identity::with_test_process;
use crate::ntos::test::phase6::call_export;

type Assert = fn(bool, &str);

const MEM_COMMIT: u64 = 0x1000;
const MEM_RESERVE: u64 = 0x2000;
const MEM_DECOMMIT: u64 = 0x4000;
const MEM_RELEASE: u64 = 0x8000;
const PAGE_NOACCESS: u64 = 0x01;
const PAGE_READONLY: u64 = 0x02;
const PAGE_READWRITE: u64 = 0x04;
const PAGE_EXECUTE_READWRITE: u64 = 0x40;
const PAGE_GUARD: u64 = 0x100;
const SEC_COMMIT: u64 = 0x0800_0000;
const SEC_NO_CHANGE: u64 = 0x0040_0000;
const MEM_UNMAP_WITH_TRANSIENT_BOOST: u64 = 0x1;
const MEM_PRESERVE_PLACEHOLDER: u64 = 0x2;
const STATUS_CONFLICTING_ADDRESSES: u32 = 0xC000_0018;
const STATUS_NOT_MAPPED_VIEW: u32 = 0xC000_0019;
const STATUS_INVALID_PAGE_PROTECTION: u32 = 0xC000_0045;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;

/// O NTSTATUS de 32 bits como o export devolve.
fn status(value: Option<u64>) -> u32 {
    value.map_or(0xDEAD_BEEF, |value| value as u32)
}

pub fn run(assert: Assert) {
    let ran = with_test_process("secure.exe", None, |_| run_in(assert));
    assert(ran.is_some(), "securevm: processo de usuario do teste");
}

/// Células de usuário dos ponteiros dos serviços.
struct Cells {
    base: u64,
    size: u64,
    old: u64,
    rsp: u64,
}

impl Cells {
    fn set(&self, base: u64, size: u64) {
        guest::write64(self.base, base);
        guest::write64(self.size, size);
    }

    fn zw_allocate(&self, base: u64, size: u64, kind: u64, protect: u64) -> u32 {
        self.set(base, size);
        status(call_export("ZwAllocateVirtualMemory", &[u64::MAX, self.base, 0, self.size, kind, protect]))
    }

    fn zw_protect(&self, base: u64, size: u64, protect: u64) -> u32 {
        self.set(base, size);
        status(call_export("ZwProtectVirtualMemory", &[u64::MAX, self.base, self.size, protect, self.old]))
    }

    fn zw_free(&self, base: u64, size: u64, kind: u64) -> u32 {
        self.set(base, size);
        status(call_export("ZwFreeVirtualMemory", &[u64::MAX, self.base, self.size, kind]))
    }

    /// Um serviço Nt* de modo usuário (PreviousMode UserMode da thread do teste).
    fn nt(&self, name: &str, a1: u64, a2: u64, a3: u64, a4: u64) -> u32 {
        state::handler(name).map_or(1, |handler| handler(a1, a2, a3, a4, self.rsp).unwrap_or(1))
    }

    fn nt_protect(&self, base: u64, size: u64, protect: u64) -> u32 {
        self.set(base, size);
        guest::write64(self.rsp + 0x28, self.old);
        self.nt("NtProtectVirtualMemory", u64::MAX, self.base, self.size, protect)
    }

    fn nt_free(&self, base: u64, size: u64, kind: u64) -> u32 {
        self.set(base, size);
        self.nt("NtFreeVirtualMemory", u64::MAX, self.base, self.size, kind)
    }

    fn nt_unmap_ex(&self, base: u64, flags: u64) -> u32 {
        self.nt("NtUnmapViewOfSectionEx", u64::MAX, base, flags, 0)
    }
}

fn secure_ex(address: u64, size: u64, probe: u64, flags: u64) -> u64 {
    call_export("MmSecureVirtualMemoryEx", &[address, size, probe, flags]).unwrap_or(0)
}

fn secure(address: u64, size: u64, probe: u64) -> u64 {
    call_export("MmSecureVirtualMemory", &[address, size, probe]).unwrap_or(0)
}

fn unsecure(handle: u64) {
    let _ = call_export("MmUnsecureVirtualMemory", &[handle]);
}

fn run_in(assert: Assert) {
    let Ok(block) = memory::map_user_region(0x1000) else {
        assert(false, "securevm: memoria de usuario das celulas");
        return;
    };
    let cells = Cells { base: block, size: block + 8, old: block + 0x10, rsp: block + 0x100 };
    private_ranges(assert, &cells);
    view_unmapping(assert, &cells);
}

/// Faixas protegidas numa alocação privada de 4 páginas.
fn private_ranges(assert: Assert, cells: &Cells) {
    let allocated = cells.zw_allocate(0, 0x4000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    let a = guest::read64(cells.base);
    assert(allocated == 0 && a != 0, "securevm: regiao privada de 4 paginas");
    let refused = [(a, 0x1000, 4, 0x10), (a, 0x1000, 0x8000_0001, 0), (a, 0x1000, 3, 0), (a, 0, 4, 0), (a, 0x4001, 4, 0), (0x7FFF_FFFF_F000, 0x2000, 4, 0)];
    assert(refused.iter().all(|&(address, size, probe, flags)| secure_ex(address, size, probe, flags) == 0), "securevm: MmSecureVirtualMemoryEx recusa Flags, ProbeMode e faixas invalidas");

    // Página 2 com leitura protegida, página 0 com escrita protegida.
    let read = secure(a + 0x2000, 0x1000, PAGE_READONLY);
    let write = secure(a + 0x10, 0x10, PAGE_READWRITE);
    assert(read != 0 && write != 0 && read != write && secure_ex(a + 0x3000, 0x1000, 4, 1) == 0, "securevm: entradas de leitura e escrita; o VAD NoChange recusa a entrada exclusiva");

    // MmProtectVirtualMemory.
    let read_side = cells.zw_protect(a + 0x2000, 0x1000, PAGE_READONLY) == 0 && cells.zw_protect(a + 0x2000, 0x1000, PAGE_NOACCESS) == STATUS_INVALID_PAGE_PROTECTION && cells.zw_protect(a + 0x2000, 0x1000, PAGE_READWRITE | PAGE_GUARD) == STATUS_INVALID_PAGE_PROTECTION && cells.zw_protect(a + 0x1FFF, 2, PAGE_NOACCESS) == STATUS_INVALID_PAGE_PROTECTION;
    assert(read_side, "securevm: leitura protegida aceita PAGE_READONLY e recusa PAGE_NOACCESS, guarda e a faixa que cruza a pagina");
    let write_side = cells.zw_protect(a, 0x1000, PAGE_READONLY) == STATUS_INVALID_PAGE_PROTECTION && cells.zw_protect(a, 0x1000, PAGE_EXECUTE_READWRITE) == 0 && cells.zw_protect(a, 0x1000, PAGE_READWRITE) == 0;
    let outside = cells.zw_protect(a + 0x3000, 0x1000, PAGE_READONLY) == 0 && cells.zw_protect(a + 0x3000, 0x1000, PAGE_READWRITE) == 0;
    assert(write_side && outside, "securevm: escrita protegida so aceita protecao gravavel; fora das faixas a troca segue");

    // MiAllocateVirtualMemory: MEM_COMMIT sobre o VAD.
    let commits = cells.zw_allocate(a, 0x1000, MEM_COMMIT, PAGE_READONLY) == STATUS_INVALID_PAGE_PROTECTION && cells.zw_allocate(a + 0x2000, 0x1000, MEM_COMMIT, PAGE_READONLY) == 0;
    assert(commits, "securevm: MEM_COMMIT sobre a faixa segue a regra da troca de protecao");

    // MmFreeVirtualMemory.
    let frees = cells.zw_free(a + 0x2000, 0x1000, MEM_DECOMMIT) == STATUS_INVALID_PAGE_PROTECTION && cells.zw_free(a + 0x1800, 0x10, MEM_DECOMMIT) == STATUS_INVALID_PAGE_PROTECTION && cells.zw_free(a + 0x3000, 0x1000, MEM_RELEASE) == STATUS_INVALID_PAGE_PROTECTION && cells.zw_free(a, 0, MEM_RELEASE) == STATUS_INVALID_PAGE_PROTECTION && memory::find_region(a).is_some();
    assert(frees, "securevm: MEM_DECOMMIT da base sem arredondar e MEM_RELEASE de qualquer parte do VAD recusados");
    let decommits = cells.zw_free(a + 0x1000, 0x1000, MEM_DECOMMIT) == 0 && cells.zw_allocate(a + 0x1000, 0x1000, MEM_COMMIT, PAGE_READWRITE) == 0;
    assert(decommits, "securevm: MEM_DECOMMIT e MEM_COMMIT fora das faixas");

    // MmUnsecureVirtualMemory: a entrada sai; a última leva o NoChange.
    unsecure(read);
    assert(cells.zw_free(a + 0x2000, 0x1000, MEM_DECOMMIT) == 0 && cells.zw_free(a, 0, MEM_RELEASE) == STATUS_INVALID_PAGE_PROTECTION, "securevm: solta a leitura, a pagina descomita; a escrita ainda segura o VAD");
    unsecure(write);
    let exclusive = secure_ex(a, 0x1000, 4, 1);
    assert(exclusive != 0 && secure_ex(a, 0x1000, 4, 0) == 0 && secure_ex(a + 0x1000, 0x1000, 1, 0) == 0, "securevm: sem entradas o VAD aceita a exclusiva, que recusa as outras");
    unsecure(exclusive);

    // Flags 4: só PreviousMode UserMode.
    let user_only = secure_ex(a, 0x1000, 4, 4);
    let user_side = user_only != 0 && cells.nt_protect(a, 0x1000, PAGE_READONLY) == STATUS_INVALID_PAGE_PROTECTION && cells.nt_free(a, 0, MEM_RELEASE) == STATUS_INVALID_PAGE_PROTECTION && cells.zw_protect(a, 0x1000, PAGE_READONLY) == 0 && cells.nt_protect(a, 0x1000, PAGE_READWRITE) == 0;
    unsecure(user_only);
    assert(user_side, "securevm: a entrada de Flags 4 vale para o modo usuario e nao para o modo kernel");

    // Flags 2: só a proteção exata das páginas; a sonda é de escrita.
    let compare = secure_ex(a, 0x1000, 2, 2);
    let exact = compare != 0 && cells.zw_protect(a, 0x1000, PAGE_READWRITE) == 0 && cells.zw_protect(a, 0x1000, PAGE_EXECUTE_READWRITE) == STATUS_INVALID_PAGE_PROTECTION && cells.zw_free(a, 0x1000, MEM_DECOMMIT) == STATUS_INVALID_PAGE_PROTECTION;
    let read_only_page = cells.zw_protect(a + 0x1000, 0x1000, PAGE_READONLY) == 0;
    let read_only = secure_ex(a + 0x1000, 0x1000, 2, 0);
    let probe = read_only_page && secure_ex(a + 0x1000, 0x1000, 2, 2) == 0 && read_only != 0;
    unsecure(compare);
    unsecure(read_only);
    assert(exact && probe, "securevm: Flags 2 aceita so a protecao exata e sonda as paginas para escrita");
    assert(cells.zw_free(a, 0, MEM_RELEASE) == 0 && memory::find_region(a).is_none(), "securevm: sem entradas o VAD e liberado");
}

/// A vista `base` da seção `section`, se mapeada.
fn view_at(section: u64, base: u64) -> bool {
    sections::views().into_iter().any(|view| view.base == base && view.section.pointer() == section)
}

/// MmCreateSection de 2 páginas e uma vista RW no processo corrente: o
/// corpo da seção e a base.
fn mapped_section(attributes: u64) -> Option<(u64, u64)> {
    let block = guest::alloc_bytes(0x40);
    let (output, size, base, offset, view_size) = (block, block + 8, block + 0x10, block + 0x18, block + 0x20);
    guest::write64(size, 0x2000);
    let created = status(call_export("MmCreateSection", &[output, 6, 0, size, 4, attributes, 0, 0]));
    let body = guest::read64(output);
    guest::write64(base, 0);
    guest::write64(offset, 0);
    guest::write64(view_size, 0);
    let mapped = if created == 0 { status(call_export("MmMapViewOfSection", &[body, process::get_current_process(), base, 0, 0, offset, view_size, 2, 0, 4])) } else { created };
    let view = guest::read64(base);
    guest::free_bytes(block);
    if created == 0 && mapped != 0 {
        let _ = section_objects::dereference(body);
    }
    (mapped == 0).then_some((body, view))
}

/// NtUnmapViewOfSectionEx com as flags do 19041.
fn view_unmapping(assert: Assert, cells: &Cells) {
    let Some((body, view)) = mapped_section(SEC_COMMIT) else {
        assert(false, "securevm: secao e vista do teste");
        return;
    };
    let flags = cells.nt_unmap_ex(view, 4) == STATUS_INVALID_PARAMETER_3 && cells.nt_unmap_ex(view, 0x8000_0000) == STATUS_INVALID_PARAMETER_3 && cells.nt_unmap_ex(0x7FFF_FFFF_0000, 4) == STATUS_INVALID_PARAMETER_3 && cells.nt_unmap_ex(0x7FFF_FFFF_0000, 1) == STATUS_NOT_MAPPED_VIEW;
    assert(flags, "securevm: NtUnmapViewOfSectionEx recusa flags desconhecidas antes da base");
    let placeholder = cells.nt_unmap_ex(view + 0x10, MEM_PRESERVE_PLACEHOLDER) == STATUS_INVALID_PARAMETER_2 && cells.nt_unmap_ex(view + 0x1000, MEM_PRESERVE_PLACEHOLDER) == STATUS_CONFLICTING_ADDRESSES && cells.nt_unmap_ex(view, MEM_PRESERVE_PLACEHOLDER) == STATUS_CONFLICTING_ADDRESSES && view_at(body, view);
    assert(placeholder, "securevm: MEM_PRESERVE_PLACEHOLDER exige base de pagina e uma vista vinda de placeholder");
    let secured = secure(view + 0x1008, 0x10, PAGE_READWRITE);
    let refused = secured != 0 && cells.nt_unmap_ex(view, MEM_UNMAP_WITH_TRANSIENT_BOOST) == STATUS_INVALID_PAGE_PROTECTION && cells.nt_unmap_ex(view, MEM_PRESERVE_PLACEHOLDER) == STATUS_INVALID_PAGE_PROTECTION && view_at(body, view);
    unsecure(secured);
    assert(refused, "securevm: a faixa protegida recusa o desmapeamento antes da regra do placeholder");
    let boosted = cells.nt_unmap_ex(view + 0x10, MEM_UNMAP_WITH_TRANSIENT_BOOST) == 0 && !view_at(body, view) && cells.nt_unmap_ex(view, MEM_UNMAP_WITH_TRANSIENT_BOOST) == STATUS_NOT_MAPPED_VIEW;
    assert(boosted, "securevm: MEM_UNMAP_WITH_TRANSIENT_BOOST desmapeia a vista");
    let _ = section_objects::dereference(body);

    // Uma alocação privada não é vista.
    let private = cells.zw_allocate(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    let address = guest::read64(cells.base);
    assert(private == 0 && cells.nt_unmap_ex(address, MEM_UNMAP_WITH_TRANSIENT_BOOST) == STATUS_NOT_MAPPED_VIEW, "securevm: base privada nao e vista mapeada");
    let _ = cells.zw_free(address, 0, MEM_RELEASE);

    // Vista SEC_NO_CHANGE: o VAD já é NoChange e recusa a entrada exclusiva.
    let Some((body, view)) = mapped_section(SEC_COMMIT | SEC_NO_CHANGE) else {
        assert(false, "securevm: secao SEC_NO_CHANGE do teste");
        return;
    };
    let shared = secure_ex(view, 0x1000, 4, 0);
    assert(secure_ex(view, 0x1000, 4, 1) == 0 && shared != 0, "securevm: vista SEC_NO_CHANGE recusa a entrada exclusiva e aceita a comum");
    unsecure(shared);
    assert(cells.nt_unmap_ex(view, 0) == 0 && !view_at(body, view), "securevm: vista SEC_NO_CHANGE sem faixa protegida desmapeia");
    let _ = section_objects::dereference(body);
}
