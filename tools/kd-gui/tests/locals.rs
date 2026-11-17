//! As variáveis locais pelo DWARF de um `kernel.elf` de verdade: os
//! parâmetros de `kernel::ntos::io::device::create_device` (o IoCreateDevice)
//! no meio da função. Usa o ELF de um build já feito (o do teste de fumaça,
//! `build/kd-gui`, ou `OPENNT_KD_GUI_ELF`); sem ele, o teste não roda.

use std::path::PathBuf;

use kd_client::unwind::Captured;
use kd_client::Symbols;
use kd_gui::source::LineTable;

#[test]
#[ignore = "precisa de um kernel.elf compilado: cargo test -p kd-gui --release -- --ignored"]
fn parameters_of_a_kernel_function() {
    let elf = std::env::var_os("OPENNT_KD_GUI_ELF").map(PathBuf::from).unwrap_or_else(|| kd_gui::workspace_root().join("build").join("kd-gui").join("kernel.elf"));
    if !elf.is_file() {
        eprintln!("sem {}: nada a conferir", elf.display());
        return;
    }
    let mut symbols = Symbols::default();
    symbols.load_kernel(&elf).unwrap();
    let start = symbols.lookup("kernel::ntos::io::device::create_device").unwrap();
    let table = LineTable::load(&elf).unwrap();
    // O arquivo e a linha da entrada da função (as tabelas de linha bastam).
    let position = table.locate(start).expect("create_device sem arquivo:linha no DWARF");
    assert!(position.file.replace('\\', "/").ends_with("ntos/io/device.rs") && position.line > 0, "{} {}", position.file, position.line);
    // Registradores e uma pilha de mentira: o que importa são os nomes.
    let stack = 0xffff_8000_0010_0000u64;
    let registers: Vec<(String, u64)> = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"].iter().map(|name| (name.to_string(), 0x1000)).chain([("rsp".to_string(), stack), ("rbp".to_string(), stack + 0x400)]).collect();
    let mut memory = Captured { regions: vec![(stack, vec![0u8; 0x1000])] };
    // Alguns endereços depois do prólogo: o primeiro com variáveis vale.
    let locals = (0x10..0x200u64).step_by(0x10).find_map(|offset| table.locals(start + offset, &registers, &mut memory).ok().filter(|locals| !locals.is_empty())).expect("nenhuma variavel no escopo de create_device");
    let names: Vec<&str> = locals.iter().map(|local| local.name.as_str()).collect();
    assert!(names.contains(&"driver") || names.contains(&"device_type"), "{locals:?}");
    assert!(locals.iter().any(|local| local.parameter), "{locals:?}");
}
