//! OpenNT — kernel x86-64 em Rust, organizado como o kernel do Windows NT.
//!
//! O ponto de entrada (AddressOfEntryPoint do PE do kernel) prepara a HAL e
//! chama `ntos::init::main::kmain`.
//!
//! | Módulo      | Papel                                                   |
//! |-------------|---------------------------------------------------------|
//! | `hal`       | HAL: hardware, ACPI/PCI, código x64 (`hal::amd64`)      |
//! | `rtl`       | suporte do kernel em Rust: locks, serial, erros, tempo  |
//! | `nano`      | interrupções, IPC, registro de serviços                 |
//! | `ntos`      | o executive (o ntoskrnl): ke, mm, io, ob, ps, se, ex... |
//! | `drivers`   | drivers internos e sistemas de arquivos                 |
//! | `shell`     | shell e `sc`                                            |
//! | `apps`      | programas de exemplo                                    |
#![no_std]
#![no_main]

extern crate alloc;

#[macro_use]
pub mod rtl;
pub mod apps;
pub mod drivers;
pub mod hal;
pub mod nano;
pub mod ntos;
pub mod shell;

/// Versão exibida no banner.
pub const VERSION: &str = "0.6.0";

extern "C" {
    static mut __bss_start: u8;
    static mut __bss_end: u8;
}

/// Entrada 64-bit do kernel, na VA de sistema em que ele foi ligado. O
/// stage2 chega aqui com RSP = BOOT_STACK_TOP - 8 (pilha de boot de sistema,
/// alinhamento de quem acabou de receber um CALL), o GDTR pelo mapa direto,
/// o mapa direto de [0, 4 GB) em `DIRECT_MAP_BASE` e a identidade
/// transitória de [0, 2 MB), que sai antes de tudo.
#[no_mangle]
#[link_section = ".text.boot"]
pub extern "C" fn kernel_main() -> ! {
    // O boot carregou os bytes da imagem; o armazenamento BSS precisa
    // começar zerado antes de qualquer estado global ser usado.
    unsafe {
        let start = core::ptr::addr_of_mut!(__bss_start);
        let end = core::ptr::addr_of_mut!(__bss_end);
        let length = end as usize - start as usize;
        core::ptr::write_bytes(start, 0, length);
    }
    // As opções de carga que o loader deixou na memória baixa, antes de
    // qualquer uso delas.
    ntos::init::boot_config::capture();
    // Nada do kernel fica na metade de usuário: a página de 2 MB em que o
    // stage2 ligou a paginação deixa de existir.
    ntos::mm::paging::remove_boot_identity();

    // Disponibiliza a serial, o alocador e a arena de convidados.
    hal::host::init();

    hal::serial::puts("[OpenNT] kernel 64-bit vivo (BIOS real mode -> long mode)\n");
    // O teste de boot reconhece este marcador antes de entrar no kernel.
    hal::serial::puts("HELLO_KERNEL_OK\n");
    let options = ntos::init::boot_config::load_options();
    hal::serial::puts("[boot] opcoes de carga: ");
    hal::serial::puts(if options.is_empty() { "(nenhuma)" } else { options });
    hal::serial::puts("\n");

    ntos::init::main::kmain()
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Pânico: mensagem na serial e halt.
    hal::serial::puts("\n*** PANIC: ");
    rtl::print::write_args(format_args!("{}", info));
    hal::serial::puts(" ***\n");
    // A cadeia de RBP (o kernel é compilado com force-frame-pointers): os
    // endereços de retorno, para simbolizar pelo ELF do kernel.
    let mut frame: u64;
    // SAFETY: só lê o registrador.
    unsafe { core::arch::asm!("mov {}, rbp", out(reg) frame, options(nomem, nostack, preserves_flags)) };
    hal::serial::puts("pilha do panico:");
    for _ in 0..24 {
        if frame < 0xFFFF_8000_0000_0000 || frame & 7 != 0 || ntos::mm::paging::translate(frame & !0xFFF) == 0 || ntos::mm::paging::translate((frame + 8) & !0xFFF) == 0 {
            break;
        }
        // SAFETY: as páginas do quadro estão presentes (conferido acima).
        let (next, ret) = unsafe { (core::ptr::read_volatile(frame as *const u64), core::ptr::read_volatile((frame + 8) as *const u64)) };
        rtl::print::write_args(format_args!(" {:#x}", ret));
        if next <= frame {
            break;
        }
        frame = next;
    }
    hal::serial::puts("\n");
    // Com o depurador do kernel ligado, a máquina para antes de travar.
    ntos::kd::stop::panic_stop();
    hal::cpu::halt_forever()
}
