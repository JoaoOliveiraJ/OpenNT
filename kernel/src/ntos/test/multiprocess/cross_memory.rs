//! Memória de outro processo (`mm/copy_virtual.rs`, o MmCopyVirtualMemory, e
//! os Nt*VirtualMemory e Nt(Un)MapViewOfSection com o handle de outro
//! processo).
//!
//! Um processo pai de teste (`with_test_process`, na raiz do System) cria um
//! filho pelo caminho único (`create_user_process`), parado e na raiz própria
//! dele, e o abre por CLIENT_ID duas vezes: com PROCESS_VM_OPERATION,
//! PROCESS_VM_READ, PROCESS_VM_WRITE e PROCESS_QUERY_INFORMATION, e só com
//! PROCESS_VM_READ. Pelos handlers de usuário, com os ponteiros e os buffers
//! na memória do pai:
//!
//! - NtAllocateVirtualMemory(filho) numa base fixa põe a região no VAD e na
//!   raiz do filho; o pai não vê nada ali (NtQueryVirtualMemory(-1) dá
//!   MEM_FREE);
//! - NtWriteVirtualMemory e NtReadVirtualMemory(filho) copiam 8 KB nos dois
//!   sentidos, e 148 KB em três blocos de 64 KB;
//! - uma leitura que cruza para uma página não mapeada do filho devolve
//!   STATUS_PARTIAL_COPY com a contagem exata: o que chegou ao buffer do
//!   pai, o resto intacto, também depois de dois blocos inteiros;
//! - NtProtectVirtualMemory(filho) deixa a segunda página somente leitura (a
//!   proteção anterior volta ao pai, a PTE do filho perde o RW), e uma
//!   gravação que cruza para ela para na fronteira com STATUS_PARTIAL_COPY;
//! - NtQueryVirtualMemory(filho) descreve as regiões do filho, e
//!   NtFreeVirtualMemory(filho) libera uma delas;
//! - NtMapViewOfSection(filho) mapeia uma seção do pai no filho, no mesmo
//!   frame da vista do pai; NtUnmapViewOfSection(filho) desfaz uma segunda
//!   vista; uma gravação pela vista do filho aparece na do pai;
//! - o export MmCopyVirtualMemory copia do filho para um buffer de kernel e
//!   de volta em KernelMode, para na página não mapeada, e em UserMode recusa
//!   a faixa de kernel com STATUS_ACCESS_VIOLATION;
//! - o handle só com PROCESS_VM_READ lê, mas a gravação, a alocação, a
//!   proteção, a liberação, a consulta, o mapeamento e o desmapeamento são
//!   recusados com STATUS_ACCESS_DENIED; outro tipo de handle dá
//!   STATUS_OBJECT_TYPE_MISMATCH, e tamanho zero nem olha o handle.
//!
//! Depois o filho roda e confere do lado dele o que o pai gravou (os dois
//! valores, a borda da gravação parcial, o valor do export e, na vista, o
//! valor do pai e a gravação feita pela vista do filho), responde na vista e
//! sai com um código que só sai com tudo certo; a resposta aparece na vista
//! do pai.

use alloc::vec::Vec;

use crate::hal::amd64::usermode;
use crate::ntos::ex::service_abi;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{ClientId, Eprocess, LargeInteger, MemoryBasicInformation, ObjectAttributes};
use crate::ntos::init::exports::signed_status;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::process_address_space as address_space;
use crate::ntos::mm::{kernel_stack, paging};
use crate::ntos::ob::close;
use crate::ntos::ps::create::{self, CreatedProcess, ImageOrigin};
use crate::ntos::ps::user::memory::{self, Space};
use crate::ntos::ps::user::process::{self as user_process, RunOptions};
use crate::ntos::ps::user::{process_state, state};
use crate::ntos::ps::{process, process_context};
use crate::ntos::test::multiprocess::identity::with_test_process;
use crate::ntos::test::phase6::call_export;

type Assert = fn(bool, &str);

const IMAGE_BASE: u64 = 0x1_4000_0000;
/// Onde o pai aloca no filho: uma base fixa, que o programa do filho conhece.
const CHILD_BASE: u64 = 0x2_0000_0000;
const CHILD_SIZE: u64 = 0x2000;
/// A região grande: reservada inteira, comitada só até `BIG_COMMIT`.
const BIG_SIZE: u64 = 0x3_0000;
const BIG_COMMIT: u64 = 0x2_5000;

// O que o pai grava e o filho confere, em CHILD_BASE.
/// [0x00], pelo NtWriteVirtualMemory.
const MAGIC_A: u64 = 0x0A0A_C3C3_1111_2222;
/// [0x08]: a base da vista da seção no filho.
const VIEW_SLOT: u64 = 0x08;
/// [0x18], pelo MmCopyVirtualMemory em KernelMode.
const EXPORT_SLOT: u64 = 0x18;
const MAGIC_E: u64 = 0x0E0E_C3C3_5555_6666;
/// [0x1000], na página que fica somente leitura.
const MAGIC_B: u64 = 0x0B0B_C3C3_3333_4444;
/// A gravação parcial começa 0x40 bytes antes da página somente leitura.
const TAIL_AT: u64 = 0x1000 - 0x40;
const TAIL_SIZE: u64 = 0x80;
// Na vista da seção.
/// [0x00], gravado pelo pai na vista dele.
const MAGIC_C: u64 = 0x0C0C_C3C3_7777_8888;
/// [0x10], pelo NtWriteVirtualMemory na vista do filho.
const MAGIC_W: u64 = 0x5757_C3C3_9999_AAAA;
/// [0x20], a resposta do filho.
const REPLY: u64 = 0x5252_C3C3_BBBB_CCCC;
/// O código de saída do filho com tudo conferido; a conferência `n` que
/// falha sai com 0x100 + n.
const CHILD_OK: u32 = 0xC3;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_PARTIAL_COPY: u32 = 0x8000_000D;
const PROCESS_VM_OPERATION: u32 = 0x8;
const PROCESS_VM_READ: u32 = 0x10;
const PROCESS_VM_WRITE: u32 = 0x20;
const PROCESS_QUERY_INFORMATION: u32 = 0x400;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const MEM_FREE: u32 = 0x1_0000;
const MEM_PRIVATE: u32 = 0x2_0000;
const MEM_MAPPED: u32 = 0x4_0000;
const PAGE_READONLY: u32 = 2;
const PAGE_READWRITE: u32 = 4;
const SEC_COMMIT: u64 = 0x0800_0000;
const SECTION_ALL_ACCESS: u64 = 0xF_001F;
const VIEW_UNMAP: u64 = 2;
/// Um handle que não existe na tabela do pai.
const BOGUS_HANDLE: u64 = 0x7FFF_FFF0;
const UNTOUCHED: u8 = 0xEE;
const USER_MODE: u8 = 1;
// Condições dos saltos (0F 8x).
const JZ: u8 = 0x84;
const JNE: u8 = 0x85;

// As células do pai (`Parent::scratch`).
const BASE_CELL: u64 = 0x00;
const SIZE_CELL: u64 = 0x08;
const HANDLE_CELL: u64 = 0x10;
const COUNT_CELL: u64 = 0x18;
const OLD_CELL: u64 = 0x20;
const RETURNED_CELL: u64 = 0x28;
const VALUE_CELL: u64 = 0x30;
const INFO: u64 = 0x40;
const ATTRIBUTES: u64 = 0x100;
const CLIENT: u64 = 0x140;
const MAXIMUM: u64 = 0x150;
/// A pilha de usuário dos handlers: os argumentos 5 em diante em
/// [rsp+0x28]...
const RSP: u64 = 0x800;
// Os buffers pequenos do pai (`Parent::small`).
const SOURCE: u64 = 0;
const TARGET: u64 = 0x2000;
const TAIL: u64 = 0x4000;
const EDGE: u64 = 0x4100;

/// O NtTerminateProcess pelo número nativo da ntdll carregada (o da tabela
/// medida, se ela não o publicou).
fn terminate_number() -> Option<u32> {
    let live = state::with(|state| state.name_by_number.iter().find(|(_, name)| name.as_str() == "NtTerminateProcess").map(|(&number, _)| number));
    live.or_else(|| service_abi::NATIVE.entries.iter().find(|entry| entry.1 == "NtTerminateProcess").map(|entry| entry.0))
}

/// O byte `offset` dos 8 KB que o pai grava no filho (os valores
/// conferidos por cima).
fn pattern(offset: u64) -> u8 {
    (offset.wrapping_mul(7) + 3) as u8
}

/// O byte `offset` da gravação de 148 KB.
fn big_pattern(offset: u64) -> u8 {
    (offset.wrapping_mul(13) ^ (offset >> 12)) as u8
}

/// O byte `offset` da gravação parcial.
fn tail_pattern(offset: u64) -> u8 {
    0xA0 ^ offset as u8
}

/// O qword que a gravação parcial deixa em CHILD_BASE + 0xFF8.
fn tail_edge() -> u64 {
    u64::from_le_bytes(core::array::from_fn(|index| tail_pattern(0x38 + index as u64)))
}

/// O programa do filho: confere o que o pai gravou, responde na vista e sai
/// com CHILD_OK.
fn child_program(terminate: u32) -> Vec<u8> {
    let mut code: Vec<u8> = Vec::new();
    let mut failures: Vec<usize> = Vec::new();
    let exit = |code: &mut Vec<u8>| {
        // mov rcx, -1; mov r10, rcx; mov eax, NtTerminateProcess; syscall; jmp $
        code.extend_from_slice(&[0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0x49, 0x89, 0xCA, 0xB8]);
        code.extend_from_slice(&terminate.to_le_bytes());
        code.extend_from_slice(&[0x0F, 0x05, 0xEB, 0xFE]);
    };
    // mov edx, 0x100 + n (o código de saída se a conferência n falhar)
    let number = |code: &mut Vec<u8>, number: u32| {
        code.push(0xBA);
        code.extend_from_slice(&(0x100 + number).to_le_bytes());
    };
    // Salto condicional (0F 8x) para a falha, remendado no fim.
    let to_failure = |code: &mut Vec<u8>, failures: &mut Vec<usize>, condition: u8| {
        code.extend_from_slice(&[0x0F, condition]);
        failures.push(code.len());
        code.extend_from_slice(&[0; 4]);
    };
    // A conferência n: mov rax, [base+d32]; mov rcx, valor; cmp rax, rcx;
    // jne falha. `base` é o ModRM: 0x83 = [rbx+d32], 0x86 = [rsi+d32].
    let check = |code: &mut Vec<u8>, failures: &mut Vec<usize>, (count, base, displacement, value): (u32, u8, u32, u64)| {
        number(code, count);
        code.extend_from_slice(&[0x48, 0x8B, base]);
        code.extend_from_slice(&displacement.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xB9]);
        code.extend_from_slice(&value.to_le_bytes());
        code.extend_from_slice(&[0x48, 0x39, 0xC8]);
        to_failure(code, failures, JNE);
    };
    // mov rbx, CHILD_BASE
    code.extend_from_slice(&[0x48, 0xBB]);
    code.extend_from_slice(&CHILD_BASE.to_le_bytes());
    for item in [(1, 0x83, 0, MAGIC_A), (2, 0x83, 0x1000, MAGIC_B), (3, 0x83, 0xFF8, tail_edge()), (4, 0x83, EXPORT_SLOT as u32, MAGIC_E)] {
        check(&mut code, &mut failures, item);
    }
    // mov rsi, [rbx+VIEW_SLOT]; test rsi, rsi; jz falha: a vista existe.
    number(&mut code, 5);
    code.extend_from_slice(&[0x48, 0x8B, 0x73, VIEW_SLOT as u8, 0x48, 0x85, 0xF6]);
    to_failure(&mut code, &mut failures, JZ);
    for item in [(6, 0x86, 0, MAGIC_C), (7, 0x86, 0x10, MAGIC_W)] {
        check(&mut code, &mut failures, item);
    }
    // mov rax, REPLY; mov [rsi+0x20], rax; mov edx, CHILD_OK
    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&REPLY.to_le_bytes());
    code.extend_from_slice(&[0x48, 0x89, 0x86, 0x20, 0x00, 0x00, 0x00, 0xBA]);
    code.extend_from_slice(&CHILD_OK.to_le_bytes());
    exit(&mut code);
    // A falha: sai com o edx da conferência.
    let failure = code.len();
    for at in failures {
        code[at..at + 4].copy_from_slice(&((failure as i64 - (at as i64 + 4)) as i32).to_le_bytes());
    }
    exit(&mut code);
    crate::ntos::test::phase7::single_section_image(IMAGE_BASE, 0x0022, b".text", 0x6000_0020, 0x1000, &code)
}

/// O que NtQueryVirtualMemory(MemoryBasicInformation) devolveu.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Basic {
    base: u64,
    allocation_base: u64,
    size: u64,
    state: u32,
    protect: u32,
    kind: u32,
}

/// A memória do pai: as células dos ponteiros e a pilha dos argumentos 5+
/// (`scratch`), os buffers pequenos (`small`) e os de 192 KB das cópias
/// grandes (`big`: a origem, depois o destino).
struct Parent {
    scratch: u64,
    small: u64,
    big: u64,
}

impl Parent {
    fn new() -> Option<Self> {
        let scratch = memory::map_user_region(0x1000).ok()?;
        let small = memory::map_user_region(0x8000).ok();
        let big = memory::map_user_region(2 * BIG_SIZE).ok();
        let parent = Self { scratch, small: small.unwrap_or(0), big: big.unwrap_or(0) };
        // OBJECT_ATTRIBUTES sem nome, para o NtOpenProcess e o NtCreateSection.
        // SAFETY: estrutura na página de usuário recém-mapeada do pai.
        unsafe { ObjectAttributes::at(parent.cell(ATTRIBUTES)) }.length.set(ObjectAttributes::SIZE as u32);
        (parent.small != 0 && parent.big != 0).then_some(parent)
    }

    fn cell(&self, offset: u64) -> u64 {
        self.scratch + offset
    }

    /// Chama o handler de usuário `name` como o portão nativo: os quatro
    /// primeiros argumentos em registradores, os seguintes na pilha do pai.
    fn call(&self, name: &str, arguments: &[u64]) -> u32 {
        let rsp = self.cell(RSP);
        for (index, &value) in arguments.iter().enumerate().skip(4) {
            guest::write64(rsp + 0x28 + (index as u64 - 4) * 8, value);
        }
        let argument = |index: usize| arguments.get(index).copied().unwrap_or(0);
        match state::handler(name) {
            Some(handler) => handler(argument(0), argument(1), argument(2), argument(3), rsp).unwrap_or_else(|error| if error.status != 0 { error.status } else { 0xC000_0001 }),
            None => 0xC000_0002,
        }
    }

    /// NtOpenProcess por CLIENT_ID.
    fn open(&self, process_id: u64, access: u32) -> Result<u64, u32> {
        // SAFETY: CLIENT_ID na página de usuário do pai.
        let client = unsafe { ClientId::at(self.cell(CLIENT)) };
        client.unique_process.set(process_id);
        client.unique_thread.set(0);
        match self.call("NtOpenProcess", &[self.cell(HANDLE_CELL), access as u64, self.cell(ATTRIBUTES), self.cell(CLIENT)]) {
            0 => Ok(guest::read64(self.cell(HANDLE_CELL))),
            status => Err(status),
        }
    }

    /// NtAllocateVirtualMemory: (status, base, tamanho).
    fn allocate(&self, process: u64, base: u64, size: u64, kind: u32, protect: u32) -> (u32, u64, u64) {
        guest::write64(self.cell(BASE_CELL), base);
        guest::write64(self.cell(SIZE_CELL), size);
        let status = self.call("NtAllocateVirtualMemory", &[process, self.cell(BASE_CELL), 0, self.cell(SIZE_CELL), kind as u64, protect as u64]);
        (status, guest::read64(self.cell(BASE_CELL)), guest::read64(self.cell(SIZE_CELL)))
    }

    fn free(&self, process: u64, base: u64, size: u64, kind: u32) -> u32 {
        guest::write64(self.cell(BASE_CELL), base);
        guest::write64(self.cell(SIZE_CELL), size);
        self.call("NtFreeVirtualMemory", &[process, self.cell(BASE_CELL), self.cell(SIZE_CELL), kind as u64])
    }

    /// NtProtectVirtualMemory: (status, proteção anterior).
    fn protect(&self, process: u64, base: u64, size: u64, protect: u32) -> (u32, u32) {
        guest::write64(self.cell(BASE_CELL), base);
        guest::write64(self.cell(SIZE_CELL), size);
        guest::write32(self.cell(OLD_CELL), 0xFFFF);
        let status = self.call("NtProtectVirtualMemory", &[process, self.cell(BASE_CELL), self.cell(SIZE_CELL), protect as u64, self.cell(OLD_CELL)]);
        (status, guest::read32(self.cell(OLD_CELL)))
    }

    /// NtReadVirtualMemory ou NtWriteVirtualMemory: (status, bytes).
    fn transfer(&self, name: &str, process: u64, address: u64, buffer: u64, size: u64) -> (u32, u64) {
        guest::write64(self.cell(COUNT_CELL), 0xDEAD);
        let status = self.call(name, &[process, address, buffer, size, self.cell(COUNT_CELL)]);
        (status, guest::read64(self.cell(COUNT_CELL)))
    }

    fn read(&self, process: u64, address: u64, buffer: u64, size: u64) -> (u32, u64) {
        self.transfer("NtReadVirtualMemory", process, address, buffer, size)
    }

    fn write(&self, process: u64, address: u64, buffer: u64, size: u64) -> (u32, u64) {
        self.transfer("NtWriteVirtualMemory", process, address, buffer, size)
    }

    /// Grava um qword do pai no processo do handle.
    fn write_value(&self, process: u64, address: u64, value: u64) -> (u32, u64) {
        guest::write64(self.cell(VALUE_CELL), value);
        self.write(process, address, self.cell(VALUE_CELL), 8)
    }

    /// NtQueryVirtualMemory(MemoryBasicInformation).
    fn query(&self, process: u64, address: u64) -> Result<Basic, u32> {
        let status = self.call("NtQueryVirtualMemory", &[process, address, 0, self.cell(INFO), MemoryBasicInformation::SIZE, self.cell(RETURNED_CELL)]);
        if status != 0 {
            return Err(status);
        }
        // SAFETY: a saída recém-escrita pelo serviço na página do pai.
        let info = unsafe { MemoryBasicInformation::at(self.cell(INFO)) };
        Ok(Basic { base: info.base_address.get(), allocation_base: info.allocation_base.get(), size: info.region_size.get(), state: info.state.get(), protect: info.protect.get(), kind: info.type_.get() })
    }

    /// NtCreateSection: uma página SEC_COMMIT sem arquivo nem nome.
    fn create_section(&self) -> Result<u64, u32> {
        // SAFETY: LARGE_INTEGER na página de usuário do pai.
        unsafe { LargeInteger::at(self.cell(MAXIMUM)) }.quad_part.set(0x1000);
        match self.call("NtCreateSection", &[self.cell(HANDLE_CELL), SECTION_ALL_ACCESS, self.cell(ATTRIBUTES), self.cell(MAXIMUM), PAGE_READWRITE as u64, SEC_COMMIT, 0]) {
            0 => Ok(guest::read64(self.cell(HANDLE_CELL))),
            status => Err(status),
        }
    }

    /// NtMapViewOfSection(seção, processo): a seção inteira, ViewUnmap,
    /// PAGE_READWRITE, na primeira faixa livre.
    fn map_view(&self, section: u64, process: u64) -> Result<u64, u32> {
        guest::write64(self.cell(BASE_CELL), 0);
        guest::write64(self.cell(SIZE_CELL), 0);
        match self.call("NtMapViewOfSection", &[section, process, self.cell(BASE_CELL), 0, 0, 0, self.cell(SIZE_CELL), VIEW_UNMAP, 0, PAGE_READWRITE as u64]) {
            0 => Ok(guest::read64(self.cell(BASE_CELL))),
            status => Err(status),
        }
    }

    fn unmap_view(&self, process: u64, base: u64) -> u32 {
        self.call("NtUnmapViewOfSection", &[process, base])
    }

    fn fill(&self, address: u64, size: u64, byte: impl Fn(u64) -> u8) {
        let bytes: Vec<u8> = (0..size).map(byte).collect();
        guest::write_bytes(address, &bytes);
    }

    fn bytes(&self, address: u64, size: u64) -> Vec<u8> {
        guest::read_bytes(address, size as usize)
    }
}

impl Drop for Parent {
    fn drop(&mut self) {
        for base in [self.scratch, self.small, self.big] {
            if let Some(region) = memory::find_region(base) {
                memory::release_private_region(&region);
            }
        }
    }
}

/// O qword `offset` de CHILD_BASE lido anexado ao filho.
fn child_value(child: u64, offset: u64) -> u64 {
    process_context::with_process(child, || guest::try_read::<u64>(CHILD_BASE + offset).unwrap_or(0)).unwrap_or(0)
}

pub fn run(assert: Assert) {
    if !usermode::ready() || process::get_current_thread() == 0 {
        assert(false, "memoria entre processos: anel 3 armado e thread corrente");
        return;
    }
    if state::with(|state| state.ntdll_exports.as_ref().is_none_or(|exports| !exports.contains_key("LdrInitializeThunk"))) {
        assert(false, "memoria entre processos: ntdll com LdrInitializeThunk mapeada");
        return;
    }
    let Some(terminate) = terminate_number() else {
        assert(false, "memoria entre processos: numero do NtTerminateProcess");
        return;
    };
    let ran = with_test_process("pai-c3.exe", None, |test| parent(assert, test.process, terminate));
    assert(ran.is_some(), "memoria entre processos: processo pai montado");
    kernel_stack::reap();
}

/// O lado do pai, como o processo corrente.
fn parent(assert: Assert, parent_process: u64, terminate: u32) {
    let Some(caller) = Parent::new() else {
        assert(false, "memoria entre processos: memoria do pai");
        return;
    };
    let request = user_process::windows_process_request(ImageOrigin::Bytes(child_program(terminate)), "filho-c3.exe", "C:\\filho-c3.exe", &RunOptions::default());
    let child = match create::create_user_process(&request) {
        Ok(child) => child,
        Err(failure) => {
            crate::debug_print!("[memoria-entre-processos] filho nao criado: {}", failure);
            assert(false, "memoria entre processos: o pai cria o filho parado");
            return;
        }
    };
    let child_pointer = child.process_pointer;
    process::reference(child_pointer);
    let full = caller.open(child.process_id, PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION);
    let limited = caller.open(child.process_id, PROCESS_VM_READ);
    let (Ok(full), Ok(limited)) = (full, limited) else {
        crate::debug_print!("[memoria-entre-processos] aberturas: {:x?} {:x?}", full, limited);
        assert(false, "memoria entre processos: o pai abre o filho por CLIENT_ID, com e sem PROCESS_VM_WRITE");
        drop(child);
        let _ = process::dereference(child_pointer);
        return;
    };
    let child_root = address_space::root_of(child_pointer).unwrap_or(0);
    let section = memory_in_child(assert, &caller, child_pointer, child_root, full);
    let views = section.and_then(|section| views_in_child(assert, &caller, child_pointer, child_root, full, section));
    let child_view = views.map_or(0, |(_, child_view)| child_view);
    copy_export(assert, child_pointer, parent_process, child_view);
    refusals(assert, &caller, full, limited, section.unwrap_or(BOGUS_HANDLE), child_view);
    run_child(assert, child, child_root, views.map(|(parent_view, _)| parent_view));
    if let Some((parent_view, _)) = views {
        assert(caller.unmap_view(u64::MAX, parent_view) == 0, "memoria entre processos: a vista do pai desfeita");
    }
    // O handle da seção é aberto por ponteiro: fecha pelo NtClose do Ob, que
    // procura nas duas tabelas.
    let closed: Vec<(u64, u32)> = [Some(full), Some(limited), section].into_iter().flatten().map(|handle| (handle, close::close(handle, Some(USER_MODE)).unwrap_or(0xC000_0001))).collect();
    crate::debug_print!("[memoria-entre-processos] fechamentos: {:x?}", closed);
    assert(closed.iter().all(|&(_, status)| status == 0), "memoria entre processos: o pai fecha os handles do filho e da secao");
    let _ = process::dereference(child_pointer);
    assert(address_space::root_of(child_pointer).is_none(), "memoria entre processos: a raiz do filho volta no ultimo dereference");
}

/// Alocar, copiar, reproteger, consultar e liberar no filho; devolve a seção
/// do pai para as vistas.
fn memory_in_child(assert: Assert, caller: &Parent, child: u64, child_root: u64, full: u64) -> Option<u64> {
    // NtAllocateVirtualMemory(filho) na base fixa: no VAD e na raiz do filho.
    let (status, base, size) = caller.allocate(full, CHILD_BASE, CHILD_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    let in_child = Space::of(child).find(CHILD_BASE).is_some_and(|region| region.base() == CHILD_BASE && region.size() == CHILD_SIZE) && paging::translate_in(child_root, CHILD_BASE) != 0 && paging::translate_in(child_root, CHILD_BASE + 0x1000) != 0;
    crate::debug_print!("[memoria-entre-processos] alocacao no filho: {:#x} base={:#x} tamanho={:#x} no filho={}", status, base, size, in_child);
    assert(status == 0 && base == CHILD_BASE && size == CHILD_SIZE && in_child, "memoria entre processos: NtAllocateVirtualMemory(filho) poe a regiao no VAD e na raiz do filho");
    let seen_by_parent = caller.query(u64::MAX, CHILD_BASE);
    assert(Space::current().find(CHILD_BASE).is_none() && seen_by_parent.is_ok_and(|info| info.state == MEM_FREE), "memoria entre processos: o pai nao ve a regiao do filho (MEM_FREE no proprio espaco)");

    // 8 KB nos dois sentidos.
    let (source, target) = (caller.small + SOURCE, caller.small + TARGET);
    caller.fill(source, CHILD_SIZE, pattern);
    guest::write64(source, MAGIC_A);
    guest::write64(source + 0x1000, MAGIC_B);
    let written = caller.write(full, CHILD_BASE, source, CHILD_SIZE);
    caller.fill(target, CHILD_SIZE, |_| UNTOUCHED);
    let read = caller.read(full, CHILD_BASE, target, CHILD_SIZE);
    crate::debug_print!("[memoria-entre-processos] 8 KB: gravacao {:x?} leitura {:x?}", written, read);
    assert(written == (0, CHILD_SIZE) && child_value(child, 0) == MAGIC_A && child_value(child, 0x1000) == MAGIC_B, "memoria entre processos: NtWriteVirtualMemory(filho) grava 8 KB na memoria do filho");
    assert(read == (0, CHILD_SIZE) && caller.bytes(target, CHILD_SIZE) == caller.bytes(source, CHILD_SIZE), "memoria entre processos: NtReadVirtualMemory(filho) le de volta os 8 KB");

    // Uma leitura que cruza para a página não mapeada depois da região.
    let edge = caller.small + EDGE;
    caller.fill(edge, 0x100, |_| UNTOUCHED);
    let partial = caller.read(full, CHILD_BASE + CHILD_SIZE - 0x30, edge, 0x100);
    let edge_bytes = caller.bytes(edge, 0x100);
    let exact = edge_bytes[..0x30] == caller.bytes(source + CHILD_SIZE - 0x30, 0x30)[..] && edge_bytes[0x30..].iter().all(|&byte| byte == UNTOUCHED);
    crate::debug_print!("[memoria-entre-processos] leitura parcial: {:x?}", partial);
    assert(partial == (STATUS_PARTIAL_COPY, 0x30) && exact, "memoria entre processos: leitura que cruza para pagina nao mapeada do filho da STATUS_PARTIAL_COPY com a contagem exata, o resto intacto");

    // 148 KB em três blocos de 64 KB; a leitura de 192 KB para no fim do commit.
    let (reserved, big, big_size) = caller.allocate(full, 0, BIG_SIZE, MEM_RESERVE, PAGE_READWRITE);
    let (committed, _, _) = caller.allocate(full, big, BIG_COMMIT, MEM_COMMIT, PAGE_READWRITE);
    let (big_source, big_target) = (caller.big, caller.big + BIG_SIZE);
    caller.fill(big_source, BIG_COMMIT, big_pattern);
    caller.fill(big_target, BIG_SIZE, |_| UNTOUCHED);
    let big_written = caller.write(full, big, big_source, BIG_COMMIT);
    let big_read = caller.read(full, big, big_target, BIG_SIZE);
    let target_bytes = caller.bytes(big_target, BIG_SIZE);
    let big_exact = target_bytes[..BIG_COMMIT as usize] == caller.bytes(big_source, BIG_COMMIT)[..] && target_bytes[BIG_COMMIT as usize..].iter().all(|&byte| byte == UNTOUCHED);
    crate::debug_print!("[memoria-entre-processos] grande: reserva {:#x} em {:#x}+{:#x}, commit {:#x}, gravacao {:x?}, leitura {:x?}", reserved, big, big_size, committed, big_written, big_read);
    assert(reserved == 0 && committed == 0 && big_size == BIG_SIZE && big_written == (0, BIG_COMMIT), "memoria entre processos: reserva e commit no filho, e 148 KB gravados em tres blocos de 64 KB");
    assert(big_read == (STATUS_PARTIAL_COPY, BIG_COMMIT) && big_exact, "memoria entre processos: leitura de 192 KB para no fim do commit com STATUS_PARTIAL_COPY e a contagem exata, depois de dois blocos inteiros");

    // A segunda página fica somente leitura; a gravação que cruza para ela para na fronteira.
    let (protected, old) = caller.protect(full, CHILD_BASE + 0x1000, 0x1000, PAGE_READONLY);
    let read_only = paging::query_page_in(child_root, CHILD_BASE + 0x1000, false).is_some_and(|page| page.access & paging::PAGE_RW == 0) && paging::query_page_in(child_root, CHILD_BASE, false).is_some_and(|page| page.access & paging::PAGE_RW != 0);
    assert(protected == 0 && old == PAGE_READWRITE && read_only, "memoria entre processos: NtProtectVirtualMemory(filho) devolve a protecao anterior e tira o RW da PTE do filho");
    let tail = caller.small + TAIL;
    caller.fill(tail, TAIL_SIZE, tail_pattern);
    let tail_written = caller.write(full, CHILD_BASE + TAIL_AT, tail, TAIL_SIZE);
    let tail_read = caller.read(full, CHILD_BASE + TAIL_AT, edge, TAIL_SIZE);
    let mut expected = caller.bytes(tail, 0x40);
    expected.extend_from_slice(&caller.bytes(source + 0x1000, TAIL_SIZE - 0x40));
    crate::debug_print!("[memoria-entre-processos] gravacao parcial: {:x?}, releitura {:x?}", tail_written, tail_read);
    assert(tail_written == (STATUS_PARTIAL_COPY, 0x40) && tail_read == (0, TAIL_SIZE) && caller.bytes(edge, TAIL_SIZE) == expected, "memoria entre processos: gravacao que cruza para a pagina somente leitura do filho para na fronteira com STATUS_PARTIAL_COPY");

    // NtQueryVirtualMemory e NtFreeVirtualMemory sobre o filho.
    let second = caller.query(full, CHILD_BASE + 0x1000);
    let first = caller.query(full, CHILD_BASE);
    crate::debug_print!("[memoria-entre-processos] consulta no filho: {:x?} {:x?}", first, second);
    assert(second == Ok(Basic { base: CHILD_BASE + 0x1000, allocation_base: CHILD_BASE, size: 0x1000, state: MEM_COMMIT, protect: PAGE_READONLY, kind: MEM_PRIVATE }) && first.is_ok_and(|info| info.size == 0x1000 && info.protect == PAGE_READWRITE && info.state == MEM_COMMIT), "memoria entre processos: NtQueryVirtualMemory(filho) descreve as paginas do filho");
    let freed = caller.free(full, big, 0, MEM_RELEASE);
    let gone = caller.query(full, big).is_ok_and(|info| info.state == MEM_FREE) && Space::of(child).find(big).is_none() && paging::translate_in(child_root, big) == 0;
    assert(freed == 0 && gone, "memoria entre processos: NtFreeVirtualMemory(filho) libera a regiao do filho");

    let section = caller.create_section();
    assert(section.is_ok(), "memoria entre processos: secao do pai criada");
    section.ok()
}

/// A seção do pai mapeada nele e no filho; devolve (vista do pai, vista do filho).
fn views_in_child(assert: Assert, caller: &Parent, child: u64, child_root: u64, full: u64, section: u64) -> Option<(u64, u64)> {
    let Ok(parent_view) = caller.map_view(section, u64::MAX) else {
        assert(false, "memoria entre processos: vista da secao no pai");
        return None;
    };
    guest::write64(parent_view, MAGIC_C);
    let child_view = caller.map_view(section, full);
    crate::debug_print!("[memoria-entre-processos] vistas: pai {:#x} filho {:x?}", parent_view, child_view);
    let Ok(child_view) = child_view else {
        assert(false, "memoria entre processos: NtMapViewOfSection(filho) mapeia a secao do pai no filho");
        return Some((parent_view, 0));
    };
    let frame = paging::translate(parent_view);
    let shared = frame != 0 && paging::translate_in(child_root, child_view) == frame && Space::of(child).find(child_view).is_some();
    let described = caller.query(full, child_view).is_ok_and(|info| info.base == child_view && info.state == MEM_COMMIT && info.kind == MEM_MAPPED);
    assert(shared && described, "memoria entre processos: NtMapViewOfSection(filho) mapeia a secao do pai no VAD do filho, no frame da vista do pai");
    let second = caller.map_view(section, full);
    let unmapped = second.map(|view| (view, caller.unmap_view(full, view)));
    let undone = unmapped.is_ok_and(|(view, status)| status == 0 && view != child_view && paging::translate_in(child_root, view) == 0 && Space::of(child).find(view).is_none() && caller.query(full, view).is_ok_and(|info| info.state == MEM_FREE));
    assert(undone, "memoria entre processos: NtUnmapViewOfSection(filho) desfaz uma vista do filho");
    // A base da vista para o programa do filho, e uma gravação pela vista do filho.
    let slot = caller.write_value(full, CHILD_BASE + VIEW_SLOT, child_view);
    let through = caller.write_value(full, child_view + 0x10, MAGIC_W);
    assert(slot == (0, 8) && through == (0, 8) && guest::read64(parent_view + 0x10) == MAGIC_W, "memoria entre processos: NtWriteVirtualMemory pela vista do filho aparece na vista do pai");
    Some((parent_view, child_view))
}

/// O export MmCopyVirtualMemory, em KernelMode e em UserMode.
fn copy_export(assert: Assert, child: u64, parent: u64, child_view: u64) {
    let buffer = guest::alloc_bytes(0x40);
    let count = buffer + 0x30;
    let copy = |from_process: u64, from: u64, to_process: u64, to: u64, size: u64, mode: u64| {
        guest::write64(count, 0xDEAD);
        (call_export("MmCopyVirtualMemory", &[from_process, from, to_process, to, size, mode, count]), guest::read64(count))
    };
    let from_child = copy(child, CHILD_BASE, parent, buffer, 0x10, 0);
    assert(from_child == (Some(0), 0x10) && guest::read64(buffer) == MAGIC_A && guest::read64(buffer + VIEW_SLOT) == child_view, "memoria entre processos: MmCopyVirtualMemory copia do filho para um buffer de kernel");
    guest::write64(buffer + 0x20, MAGIC_E);
    let to_child = copy(parent, buffer + 0x20, child, CHILD_BASE + EXPORT_SLOT, 8, 0);
    assert(to_child == (Some(0), 8) && child_value(child, EXPORT_SLOT) == MAGIC_E, "memoria entre processos: MmCopyVirtualMemory grava de um buffer de kernel no filho");
    let partial = copy(child, CHILD_BASE + CHILD_SIZE - 8, parent, buffer, 0x10, 0);
    let user_mode = copy(child, CHILD_BASE, parent, buffer, 8, 1);
    crate::debug_print!("[memoria-entre-processos] export: {:x?} {:x?} {:x?} {:x?}", from_child, to_child, partial, user_mode);
    assert(partial == (Some(signed_status(STATUS_PARTIAL_COPY)), 8) && user_mode == (Some(signed_status(STATUS_ACCESS_VIOLATION)), 0), "memoria entre processos: MmCopyVirtualMemory para na pagina nao mapeada e, em UserMode, recusa a faixa de kernel");
    guest::free_bytes(buffer);
}

/// As recusas pelo acesso do handle e pelo tipo.
fn refusals(assert: Assert, caller: &Parent, full: u64, limited: u64, section: u64, child_view: u64) {
    let (source, target) = (caller.small + SOURCE, caller.small + TARGET);
    let write = caller.write(limited, CHILD_BASE, source, 8);
    let read = caller.read(limited, CHILD_BASE, target, 8);
    crate::debug_print!("[memoria-entre-processos] handle so com VM_READ: gravacao {:x?} leitura {:x?}", write, read);
    assert(write == (STATUS_ACCESS_DENIED, 0) && read == (0, 8) && guest::read64(target) == MAGIC_A, "memoria entre processos: handle sem PROCESS_VM_WRITE le, mas NtWriteVirtualMemory e recusado com STATUS_ACCESS_DENIED");
    let operations = [
        caller.allocate(limited, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE).0,
        caller.protect(limited, CHILD_BASE, 0x1000, PAGE_READWRITE).0,
        caller.free(limited, CHILD_BASE, 0, MEM_RELEASE),
        caller.query(limited, CHILD_BASE).err().unwrap_or(0),
        caller.map_view(section, limited).err().unwrap_or(0),
        caller.unmap_view(limited, child_view),
    ];
    crate::debug_print!("[memoria-entre-processos] recusas sem VM_OPERATION/QUERY: {:x?}", operations);
    assert(operations.iter().all(|&status| status == STATUS_ACCESS_DENIED), "memoria entre processos: sem PROCESS_VM_OPERATION/QUERY_INFORMATION, alocar, reproteger, liberar, consultar, mapear e desmapear no filho sao recusados");
    let mismatch = caller.read(section, CHILD_BASE, target, 8);
    let empty = caller.read(BOGUS_HANDLE, CHILD_BASE, target, 0);
    assert(mismatch == (STATUS_OBJECT_TYPE_MISMATCH, 0) && empty == (0, 0) && caller.read(full, CHILD_BASE, target, 8) == (0, 8), "memoria entre processos: handle de secao da STATUS_OBJECT_TYPE_MISMATCH e tamanho zero nao olha o handle");
}

/// O filho roda, confere do lado dele e responde na vista.
fn run_child(assert: Assert, child: CreatedProcess, child_root: u64, parent_view: Option<u64>) {
    let child_pointer = child.process_pointer;
    let exit = user_process::start_created(child).and_then(user_process::wait_started);
    // SAFETY: EPROCESS retido pelo pai.
    let status = unsafe { Eprocess::at(child_pointer) }.exit_status.get() as u32;
    let reply = parent_view.map_or(0, |view| guest::read64(view + 0x20));
    crate::debug_print!("[memoria-entre-processos] filho saiu: {:x?} status={:#x} resposta={:#x}", exit.as_ref().map_err(|error| alloc::format!("{error}")), status, reply);
    assert(matches!(exit, Ok(CHILD_OK)) && status == CHILD_OK, "memoria entre processos: o filho confere do lado dele o que o pai gravou (valores, borda da gravacao parcial, export e vista) e sai com o codigo que prova");
    assert(reply == REPLY, "memoria entre processos: a resposta do filho na vista dele aparece na vista do pai");
    assert(process_state::get(child_pointer).is_none() && paging::translate_in(child_root, CHILD_BASE) == 0, "memoria entre processos: o filho sai e leva o VAD dele, com a regiao que o pai alocou");
}
