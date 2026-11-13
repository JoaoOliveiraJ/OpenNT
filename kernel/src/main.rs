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
    // Nada do kernel fica na metade de usuário: a página de 2 MB em que o
    // stage2 ligou a paginação deixa de existir.
    ntos::mm::paging::remove_boot_identity();

    // Disponibiliza a serial, o alocador e a arena de convidados.
    hal::host::init();

    hal::serial::puts("[OpenNT] kernel 64-bit vivo (BIOS real mode -> long mode)\n");
    // O teste de boot reconhece este marcador antes de entrar no kernel.
    hal::serial::puts("HELLO_KERNEL_OK\n");

    ntos::init::main::kmain()
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Pânico: mensagem na serial e halt.
    hal::serial::puts("\n*** PANIC: ");
    rtl::print::write_args(format_args!("{}", info));
    hal::serial::puts(" ***\n");
    hal::cpu::halt_forever()
}
