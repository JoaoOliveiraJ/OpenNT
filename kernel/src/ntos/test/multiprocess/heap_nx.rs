//! O heap do kernel e a arena não executam (`paging::map_kernel_heap_window`
//! monta a janela com NX): só a imagem do kernel, as imagens carregadas e as
//! alocações executáveis da janela de sistema executam.
//!
//! - As páginas de 2 MB da janela (uma VA da arena e uma do `kmalloc`) estão
//!   sem execução nas tabelas.
//! - Uma imagem de teste carregada pelo `pe_loader` (código na janela de
//!   imagens de sistema) chama, numa execução nativa possuída, um endereço da
//!   arena que contém `mov eax, 1234h; ret`. A busca da instrução falta (NX)
//!   e vira STATUS_ACCESS_VIOLATION com ExceptionInformation[0] = 8 (execução),
//!   despachada ao handler de linguagem da função da imagem, que desenrola
//!   (RtlUnwindEx) até o bloco de tratamento e devolve código e tipo. Com a
//!   janela executável, a chamada roda o código da arena e devolve 0x1234.
//! - O mesmo código numa alocação executável (MmAllocateContiguousNodeMemory
//!   com PAGE_EXECUTE_READWRITE) roda e devolve 0x1234 pela mesma função: o
//!   código que precisa executar tem onde ficar (o fixture dos callbacks de
//!   objeto da fase 3 usa a mesma alocação).
//! - Os tipos de pool seguem o Windows 10 19041 (`ex/pool_allocation.rs`):
//!   o código copiado num bloco do ExAllocatePoolWithTag(NonPagedPool), do
//!   ExAllocatePoolZero(NonPagedPool) e do ExAllocatePool2 com
//!   POOL_FLAG_NON_PAGED_EXECUTE roda pela mesma função e devolve 0x1234; o
//!   de um bloco do ExAllocatePoolWithTag(NonPagedPoolNx) e do
//!   ExAllocatePool2 com POOL_FLAG_NON_PAGED falta com o STATUS_ACCESS_VIOLATION
//!   de execução, tratado pelo SEH da imagem. As páginas dos blocos
//!   executáveis estão sem NX e as dos NX com NX nas tabelas.

use alloc::boxed::Box;
use alloc::string::String;

use crate::ntos::mm::contiguous_memory;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::memory_map as map;
use crate::ntos::mm::paging;
use crate::ntos::mm::pe_loader::{self as loader, LoadOptions};
use crate::ntos::rtl::{native_context, unwind};

type Assert = fn(bool, &str);

/// `mov eax, 1234h; ret`.
const CODE: [u8; 6] = [0xB8, 0x34, 0x12, 0x00, 0x00, 0xC3];
/// STATUS_ACCESS_VIOLATION com ExceptionInformation[0] = 8 (execução) na
/// parte alta.
const EXECUTE_FAULT: u64 = 8 << 32 | 0xC000_0005;

/// Tag dos blocos de pool do teste.
const TAG: u64 = u32::from_le_bytes(*b"HpNx") as u64;
/// NonPagedPool (o NonPagedPoolExecute) e NonPagedPoolNx.
const NON_PAGED_POOL: u64 = 0;
const NON_PAGED_POOL_NX: u64 = 0x200;
/// POOL_FLAG_NON_PAGED (NX) e POOL_FLAG_NON_PAGED_EXECUTE.
const POOL_FLAG_NON_PAGED: u64 = 0x40;
const POOL_FLAG_NON_PAGED_EXECUTE: u64 = 0x80;

/// A janela do heap não executa em `va`.
fn no_execute(va: u64) -> bool {
    paging::query_page(va, false).is_some_and(|mapping| mapping.nx)
}

/// Imagem com F (0x1300): `sub rsp, 28h; call rcx; nop; add rsp, 28h; ret`
/// (o valor do chamado; o `nop` deixa o retorno do `call` fora do epílogo,
/// onde o handler não vale), o bloco de tratamento (0x130C) `add rsp, 28h;
/// ret` e o handler de linguagem (0x1330): RtlUnwindEx(frame, 0x130C, record,
/// código | ExceptionInformation[0] << 32, NULL, NULL); devolve 1.
fn calling_image() -> alloc::vec::Vec<u8> {
    let mut bytes = crate::ntos::test::phase6::ntoskrnl_importer(b"ExRaiseStatus\0");
    for byte in &mut bytes[0x4442..0x4480] {
        *byte = 0;
    }
    bytes[0x4442..0x444E].copy_from_slice(b"RtlUnwindEx\0");
    let rel = |from_next: usize, to: usize| ((to as i64 - from_next as i64) as i32).to_le_bytes();
    let f = [0x48, 0x83, 0xEC, 0x28, 0xFF, 0xD1, 0x90, 0x48, 0x83, 0xC4, 0x28, 0xC3, 0x48, 0x83, 0xC4, 0x28, 0xC3];
    bytes[0x1300..0x1300 + f.len()].copy_from_slice(&f);
    let mut handler = alloc::vec![0x48, 0x83, 0xEC, 0x38, 0x48, 0x89, 0xC8, 0x48, 0x89, 0xD1, 0x48, 0x8D, 0x15];
    handler.extend_from_slice(&rel(0x1341, 0x130C));
    // mov r8, rax; mov r9d, [rax]; mov r10, [rax+20h]; shl r10, 20h; or r9, r10.
    handler.extend_from_slice(&[0x49, 0x89, 0xC0, 0x44, 0x8B, 0x08, 0x4C, 0x8B, 0x50, 0x20, 0x49, 0xC1, 0xE2, 0x20, 0x4D, 0x09, 0xD1]);
    handler.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0, 0x48, 0xC7, 0x44, 0x24, 0x28, 0, 0, 0, 0, 0xFF, 0x15]);
    handler.extend_from_slice(&rel(0x136A, 0x4210));
    handler.extend_from_slice(&[0x48, 0x83, 0xC4, 0x38, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]);
    bytes[0x1330..0x1330 + handler.len()].copy_from_slice(&handler);
    // UNWIND_INFO v1 com UNW_FLAG_EHANDLER: prólogo de 4 bytes, ALLOC_SMALL 28h, handler 0x1330.
    bytes[0x1400..0x1404].copy_from_slice(&[0x09, 0x04, 0x01, 0x00]);
    bytes[0x1404..0x1406].copy_from_slice(&(4u16 | (2 << 8) | (4 << 12)).to_le_bytes());
    bytes[0x1408..0x140C].copy_from_slice(&0x1330u32.to_le_bytes());
    // RUNTIME_FUNCTION de F.
    bytes[0x1500..0x1504].copy_from_slice(&0x1300u32.to_le_bytes());
    bytes[0x1504..0x1508].copy_from_slice(&0x1320u32.to_le_bytes());
    bytes[0x1508..0x150C].copy_from_slice(&0x1400u32.to_le_bytes());
    bytes
}

pub fn run(assert: Assert) {
    let arena = guest::alloc_bytes(16);
    let boxed = Box::new([0u8; 64]);
    let heap = boxed.as_ptr() as u64;
    let in_window = |va: u64| (map::KERNEL_HEAP_BASE..map::KERNEL_HEAP_TOP).contains(&va);
    assert(arena != 0 && in_window(arena) && in_window(heap) && no_execute(arena) && no_execute(heap), "heap nx: a arena e o heap do kernel ficam na janela do heap, sem execucao");

    let Ok(mut image) = loader::load(calling_image(), &LoadOptions { image_name: Some(String::from("opennt-heapnx.sys")), ..Default::default() }) else {
        assert(false, "heap nx: imagem de teste carregada");
        guest::free_bytes(arena);
        return;
    };
    let base = image.image_base;
    let added = unwind::add_function_table(base + 0x1500, 1, base);
    assert(added.is_ok_and(|added| added == 1) && !no_execute(base + 0x1300), "heap nx: a imagem de teste executa e tem a tabela de funcoes");

    guest::write_bytes(arena, &CODE);
    let from_heap = native_context::call(base + 0x1300, &[arena], 0);
    if !from_heap.as_ref().is_ok_and(|&value| value == EXECUTE_FAULT) {
        crate::debug_print!("[heap-nx] chamada a arena devolveu {:x?}", from_heap.as_ref().map_err(|error| alloc::format!("{error}")));
    }
    assert(from_heap.is_ok_and(|value| value == EXECUTE_FAULT), "heap nx: executar da arena falta (STATUS_ACCESS_VIOLATION de execucao) e o SEH da imagem a trata");

    let executable = contiguous_memory::allocate_node(0x1000, 0, u64::MAX, 0, 0x40, 0).unwrap_or(0);
    let ran = executable != 0 && !no_execute(executable) && {
        guest::write_bytes(executable, &CODE);
        native_context::call(base + 0x1300, &[executable], 0).is_ok_and(|value| value == 0x1234)
    };
    assert(ran, "heap nx: o mesmo codigo numa alocacao executavel (MmAllocateContiguousNodeMemory, PAGE_EXECUTE_READWRITE) roda");
    if executable != 0 {
        assert(contiguous_memory::free(executable).is_ok(), "heap nx: alocacao executavel devolvida");
    }
    pool_types(assert, base);
    let _ = unwind::delete_function_table(base + 0x1500);
    let _ = image.release();
    guest::free_bytes(arena);
    drop(boxed);
}

/// Copia o código num bloco de pool pedido por `export(arguments)` e o chama
/// pela função F da imagem em `base`: (bloco, sem NX nas tabelas, resultado).
fn run_from_pool(base: u64, export: &str, arguments: &[u64]) -> (u64, bool, Option<u64>) {
    let call_export = crate::ntos::test::phase6::call_export;
    let block = call_export(export, arguments).unwrap_or(0);
    if block == 0 {
        return (0, false, None);
    }
    guest::write_bytes(block, &CODE);
    let executable = !no_execute(block);
    let result = native_context::call(base + 0x1300, &[block], 0).ok();
    call_export("ExFreePoolWithTag", &[block, TAG]);
    (block, executable, result)
}

/// Os tipos de pool executáveis rodam o código; os NX faltam (o SEH trata).
fn pool_types(assert: Assert, base: u64) {
    let executes = |(block, executable, result): (u64, bool, Option<u64>)| block != 0 && executable && result == Some(0x1234);
    let faults = |(block, executable, result): (u64, bool, Option<u64>)| block != 0 && !executable && result == Some(EXECUTE_FAULT);
    let tagged = run_from_pool(base, "ExAllocatePoolWithTag", &[NON_PAGED_POOL, 64, TAG]);
    let zeroed = run_from_pool(base, "ExAllocatePoolZero", &[NON_PAGED_POOL, 64, TAG]);
    let pool2 = run_from_pool(base, "ExAllocatePool2", &[POOL_FLAG_NON_PAGED_EXECUTE, 64, TAG]);
    let tagged_nx = run_from_pool(base, "ExAllocatePoolWithTag", &[NON_PAGED_POOL_NX, 64, TAG]);
    let pool2_nx = run_from_pool(base, "ExAllocatePool2", &[POOL_FLAG_NON_PAGED, 64, TAG]);
    if !(executes(tagged) && executes(zeroed) && executes(pool2) && faults(tagged_nx) && faults(pool2_nx)) {
        crate::debug_print!("[heap-nx] pool: NonPagedPool {:x?} Zero {:x?} Pool2 exec {:x?} NonPagedPoolNx {:x?} Pool2 NX {:x?}", tagged, zeroed, pool2, tagged_nx, pool2_nx);
    }
    assert(executes(tagged) && executes(zeroed), "heap nx: codigo num bloco do ExAllocatePoolWithTag/ExAllocatePoolZero(NonPagedPool) roda (o NonPagedPool executa)");
    assert(executes(pool2), "heap nx: codigo num bloco do ExAllocatePool2 com POOL_FLAG_NON_PAGED_EXECUTE roda");
    assert(faults(tagged_nx), "heap nx: codigo num bloco do ExAllocatePoolWithTag(NonPagedPoolNx) falta e o SEH da imagem trata");
    assert(faults(pool2_nx), "heap nx: codigo num bloco do ExAllocatePool2 com POOL_FLAG_NON_PAGED (NX) falta e o SEH da imagem trata");
}
