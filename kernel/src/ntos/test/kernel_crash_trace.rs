//! Autoteste do diagnóstico das paradas do kernel (`ke/bugcheck_trace.rs`),
//! sem parar a máquina:
//! - o trampolim do export KeBugCheckEx sai como
//!   `ntoskrnl.exe+deslocamento (KeBugCheckEx+0x0)`, pela PsLoadedModuleList
//!   e pelo diretório de exports do PE do kernel;
//! - a chamada que volta num endereço é decodificada: `call [rip+disp32]`
//!   (o import pela IAT) lê o slot, e `call rel32` segue o
//!   `jmp [rip+disp32]` do destino até o mesmo slot;
//! - a cadeia de RBP a partir do autoteste tem pelo menos três quadros, todos
//!   na imagem do kernel;
//! - o leitor do diagnóstico lê o pool e recusa VAs de usuário, a página
//!   nula e VAs não canônicas.

use alloc::format;
use alloc::string::String;

use crate::hal::amd64::win32_thunk;
use crate::ntos::init::exports;
use crate::ntos::ke::bugcheck_trace::{self, MAX_FRAMES};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::memory_map::KERNEL_VIRTUAL_BASE;
use crate::ntos::mm::pe_loader::ResolvedImport;
use crate::ntos::mm::kernel_address;

type Assert = fn(bool, &str);

pub fn run(assert: Assert) {
    let Some(ResolvedImport::Thunk(id)) = exports::lookup("ntoskrnl.exe", "KeBugCheckEx") else {
        assert(false, "kcrash: KeBugCheckEx sem trampolim");
        return;
    };
    let (table, _) = win32_thunk::thunk_table();
    let stub = table + id as u64 * win32_thunk::STUB_SIZE;
    let mut text = String::new();
    bugcheck_trace::describe(&mut text, stub, 0x1000);
    let expected = format!("ntoskrnl.exe+{:#x} (KeBugCheckEx+0x0)", stub - KERNEL_VIRTUAL_BASE);
    assert(text == expected, &format!("kcrash: o trampolim do KeBugCheckEx sai como {text:?}, esperado {expected:?}"));

    // +0: call [rip+0x1A] (volta em +6); +8: call rel32 para +0x10 (volta em
    // +13); +0x10: jmp [rip+0xA]; +0x20: o slot com o trampolim.
    let buffer = guest::alloc_bytes(0x40);
    if buffer == 0 {
        assert(false, "kcrash: sem memoria para o autoteste");
        return;
    }
    guest::write_bytes(buffer, &[0; 0x40]);
    guest::write_bytes(buffer, &[0xFF, 0x15]);
    guest::write32(buffer + 2, 0x20 - 6);
    guest::write8(buffer + 8, 0xE8);
    guest::write32(buffer + 9, 0x10 - 13);
    guest::write_bytes(buffer + 0x10, &[0xFF, 0x25]);
    guest::write32(buffer + 0x12, 0x20 - 0x16);
    guest::write64(buffer + 0x20, stub);
    let calls = (bugcheck_trace::call_target(buffer + 6), bugcheck_trace::call_target(buffer + 13), bugcheck_trace::call_target(buffer + 0x20));
    assert(calls == (Some(stub), Some(stub), None), &format!("kcrash: chamadas decodificadas como {calls:x?}, esperado o trampolim {stub:#x} nas duas primeiras"));

    let mut frames = [0u64; MAX_FRAMES];
    let count = bugcheck_trace::kernel_frames(&mut frames);
    let size = kernel_address::image_size();
    let in_kernel = frames[..count].iter().all(|&frame| frame >= KERNEL_VIRTUAL_BASE && frame - KERNEL_VIRTUAL_BASE < size);
    assert(count >= 3 && in_kernel, &format!("kcrash: a cadeia de RBP do kernel deu {count} quadros {:x?}", &frames[..count]));

    let reads = (bugcheck_trace::readable(buffer, 0x40), bugcheck_trace::readable(0x1_0000, 8), bugcheck_trace::readable(0, 8), bugcheck_trace::readable(0x0000_8000_0000_0000, 8));
    assert(reads == (true, false, false, false), &format!("kcrash: leituras (pool, usuario, nula, nao canonica) = {reads:?}"));
    guest::free_bytes(buffer);
}
