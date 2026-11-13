// A tabela única da ABI de syscalls do bring-up.
// Uma fonte, três consumidores: o build gera a ntdll.dll de bring-up (os
// stubs `mov r10, rcx; mov eax, N; syscall; ret`, como a ntdll da Microsoft),
// o loader avisa dos serviços ausentes e o kernel despacha número ->
// implementação. Números do Windows 10 22H2 (build 19045); só entram
// serviços com implementação real no kernel.
pub const SYSCALLS: &[(&str, u32)] = &[
    // Imprime uma UNICODE_STRING no console de boot.
    ("NtDisplayString", 0x27),
    // Sai do processo (handle -1 = processo corrente), código no segundo argumento.
    ("NtTerminateProcess", 0x2C),
];
