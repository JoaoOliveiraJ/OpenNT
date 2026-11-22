//! Autotestes do suporte de kernel ao WoW64 (`ps::wow64`).
//!
//! - GDT: os descritores de usuário do NT x64 em cada CPU (o código de 32
//!   bits 0x23, os dados planos de 32 bits 0x2B, o código de 64 bits 0x33 e
//!   o CMTEB 0x53 de 0x3C00 bytes);
//! - o modo de compatibilidade no anel 3: um `retf` para o seletor 0x23, a
//!   pilha de 32 bits (SS 0x2B com B=1), o FS do CMTEB (a base é o
//!   ETHREAD.UserFsBase da thread, como no SwapContext) e a volta ao código
//!   de 64 bits por outro `retf`; um laço longo no código de 32 bits é
//!   interrompido pelo relógio, o CONTEXT do intervalo guarda SegCs 0x23 e a
//!   retomada volta ao modo de compatibilidade;
//! - o cabeçalho PE32 i386 aceito pela seção de imagem (e o PE32 de outra
//!   máquina recusado) e a SECTION_IMAGE_INFORMATION dele (Machine e os
//!   tamanhos de pilha de 32 bits);
//! - o MiComputeProcessUserVa (2 GB sem LARGE_ADDRESS_AWARE, 4 GB num WoW64
//!   com ela, o padrão num nativo com ela) e o fim da escolha de VA;
//! - o PspWow64SetupCpuArea (a área de CPU no topo da pilha de 64 bits);
//! - o KeGet/SetExecuteOptions de um processo WoW64 e de um nativo;
//! - o `\KnownDlls32` do kernel só no boot sem o smss (na cadeia do smss os
//!   diretórios e as seções de KnownDlls são do smss.exe);
//! - a seção de imagem com SEC_IMAGE | 0x100000 (a KnownDll _wow64cpu do
//!   smss): a flag BaseBelow4gb do pacote e as vistas abaixo de 4 GB;
//! - a junção do contexto x86 (`ps::wow64::context`): o
//!   RtlpWow64SanitizeContextFlags, o RtlpWow64GetContextOnAmd64 e o
//!   RtlpWow64SetContextOnAmd64 com a thread parada no código de 32 bits e
//!   no de 64 bits, e o RtlFxToFnFrame/RtlFnToFxFrame do x87.

use alloc::vec::Vec;

use crate::hal::amd64::usermode;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types as nt;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::section::image_header;
use crate::ntos::ps::process;
use crate::ntos::ps::user::{memory, threads};

type Assert = fn(bool, &str);

pub fn run(assert: Assert) {
    gdt_descriptors(assert);
    image_headers(assert);
    process_user_va(assert);
    cpu_area(assert);
    execute_options(assert);
    known_dlls(assert);
    base_below_4gb(assert);
    context_merge(assert);
    x87_frames(assert);
    alpc_layout(assert);
    compatibility_mode(assert);
}

/// Um EPROCESS de teste zerado, WoW64 x86 com `wow64` (o EWOW64PROCESS logo
/// depois no mesmo bloco): devolve o bloco, que o chamador devolve ao pool.
fn test_process(wow64: bool) -> u64 {
    let size = nt::Eprocess::SIZE + nt::Ewow64process::SIZE;
    let block = guest::alloc_bytes(size);
    if block == 0 {
        return 0;
    }
    guest::write_bytes(block, &alloc::vec![0u8; size as usize]);
    if wow64 {
        let ewow64 = block + nt::Eprocess::SIZE;
        // SAFETY: o bloco de teste com o EPROCESS e o EWOW64PROCESS.
        unsafe { nt::Ewow64process::at(ewow64) }.machine.set(crate::ntos::ps::wow64::MACHINE_I386);
        unsafe { nt::Eprocess::at(block) }.wo_w64_process.set(ewow64);
    }
    block
}

fn execute_options(assert: Assert) {
    use crate::ntos::ke::execute_options::{get, set};
    let (wow64, native) = (test_process(true), test_process(false));
    if wow64 == 0 || native == 0 {
        assert(false, "wow64: EPROCESS de teste para as opcoes de execucao");
        return;
    }
    let initial = get(wow64);
    // ExecuteEnable liga também os dois DispatchEnable; ExecuteDisable
    // depois desliga ExecuteEnable e os outros bits ficam.
    let enable = (set(wow64, 0x2).unwrap_or(1), get(wow64));
    let disable = (set(wow64, 0x5).unwrap_or(1), get(wow64));
    let invalid = set(wow64, 0x80).unwrap_or(1);
    // Permanent: a próxima mudança é recusada.
    let permanent = (set(wow64, 0x8).unwrap_or(1), set(wow64, 0x2).unwrap_or(1), get(wow64));
    let native_result = (get(native), set(native, 0x2).unwrap_or(1));
    guest::free_bytes(wow64);
    guest::free_bytes(native);
    assert(initial == 0 && enable == (0, 0x32) && disable == (0, 0x35) && invalid == 0xC000_000D, "wow64: KeSetExecuteOptions liga o DispatchEnable com ExecuteEnable, ExecuteDisable desliga ExecuteEnable e bits fora dos sete sao recusados");
    assert(permanent == (0, 0xC000_0022, 0x3C),"wow64: opcoes de execucao permanentes recusam outra mudanca");
    assert(native_result == (0xD, 0xC000_000D), "wow64: processo nativo responde NX permanente (0xD) e nao aceita opcoes");
}

/// O `\KnownDlls32` do kernel só existe no boot sem o smss: na cadeia do
/// smss, os dois diretórios e as seções deles são do smss.exe e o kernel não
/// cria nem provisiona nada.
fn known_dlls(assert: Assert) {
    use crate::ntos::init::phase0::kernel_known_dll_directories;
    use crate::ntos::mm::section::open::kernel_known_dll;
    let smss = kernel_known_dll_directories(true, true).is_empty() && kernel_known_dll("\\KnownDlls32", "kernel32.dll", true).is_none() && kernel_known_dll("\\KnownDlls", "kernel32.dll", true).is_none();
    assert(smss, "wow64: na cadeia do smss o kernel nao cria nem provisiona \\KnownDlls e \\KnownDlls32");
    let directories = kernel_known_dll_directories(false, true);
    let native_only = kernel_known_dll_directories(false, false);
    let provisioned = kernel_known_dll("\\KNOWNDLLS32", "kernel32.dll", false);
    assert(directories == [("\\KnownDlls", "C:\\Windows\\System32"), ("\\KnownDlls32", "C:\\Windows\\SysWOW64")] && native_only.len() == 1, "wow64: sem o smss o kernel cria o \\KnownDlls32 so com o volume do WoW64");
    assert(provisioned.as_ref().is_some_and(|(directory, source)| *directory == "\\KnownDlls32" && source == "\\SystemRoot\\SysWOW64\\kernel32.dll"), "wow64: sem o smss o \\KnownDlls32 sai de SysWOW64");
}

/// O SEC_IMAGE | 0x100000 do smss para as DLLs de CPU do WoW64: o pacote
/// leva a flag BaseBelow4gb (o MiInitializeCreateSectionPacket), que a
/// criação aceita, e a vista da imagem fica abaixo de 4 GB.
fn base_below_4gb(assert: Assert) {
    use crate::ntos::mm::section::create::BASE_BELOW_4GB;
    use crate::ntos::mm::section::image_view::view_upper;
    use crate::ntos::mm::section::parameters::{decode, Decoded};
    let decoded = decode(0x0110_0000, 0x10, 0, 4, 0, false);
    let flagged = matches!(decoded, Decoded::Request(request) if request.flags & BASE_BELOW_4GB != 0 && request.attributes & 0x0100_0000 != 0);
    let plain = matches!(decode(0x0100_0000, 0x10, 0, 4, 0, false), Decoded::Request(request) if request.flags & BASE_BELOW_4GB == 0);
    assert(flagged && plain, "wow64: SEC_IMAGE com 0x100000 vira a flag BaseBelow4gb do pacote de criacao");
    assert(view_upper(0x7FFF_FFFE_FFFF, true) == 0xFFFF_FFFF && view_upper(0x7FFF_FFFE_FFFF, false) == 0x7FFF_FFFE_FFFF && view_upper(0x7FFE_FFFF, true) == 0x7FFE_FFFF, "wow64: a vista de uma imagem BaseBelow4gb fica abaixo de 4 GB");
}

/// A junção do RtlpWow64GetContextOnAmd64 e do RtlpWow64SetContextOnAmd64 em
/// cópias do kernel.
fn context_merge(assert: Assert) {
    use crate::ntos::inc::types::extra_wow64::Wow64Context;
    use crate::ntos::ps::wow64::context::{get_context_on_amd64, sanitize, set_context_on_amd64};
    assert(sanitize(0x1_0007) == Ok(0x1_0007) && sanitize(0x7) == Ok(0x1_0007) && sanitize(0x10_0003) == Ok(0x1_0003), "wow64: RtlpWow64SanitizeContextFlags aceita o x86 e converte outro ContextFlags de UserMode");
    let blocks = [guest::alloc_aligned(nt::Context::SIZE, 16, true), guest::alloc_bytes(Wow64Context::SIZE), guest::alloc_bytes(Wow64Context::SIZE)];
    if blocks.contains(&0) {
        assert(false, "wow64: copias de contexto de teste");
        return;
    }
    // SAFETY: as cópias de teste acabadas de alocar, zeradas.
    let (native, cpu, x86) = unsafe { (nt::Context::at(blocks[0]), Wow64Context::at(blocks[1]), Wow64Context::at(blocks[2])) };
    // A área de CPU com o que o wow64cpu salvou e o nativo com outros valores.
    cpu.eip.set(0x0040_1000);
    cpu.esp.set(0x0018_FF00);
    cpu.ebp.set(0x0018_FF40);
    cpu.e_flags.set(0xFFFF_FFFF);
    cpu.eax.set(0x1111);
    cpu.edi.set(0x2222);
    native.rip.set(0x7FFE_1234);
    native.rsp.set(0x0011_2200);
    native.rbp.set(0x0011_2240);
    native.e_flags.set(0x246);
    native.rax.set(0x3333);
    native.rdi.set(0x4444);
    native.context_flags.set(0x10_001F);
    let flags = 0x1_0007 | 0x4000_0000;
    // Parada no código de 64 bits: o controle e os inteiros da área de CPU.
    native.seg_cs.set(usermode::USER_DS + 8);
    x86.context_flags.set(flags);
    let status = get_context_on_amd64(cpu, native, x86);
    let from_cpu = status == 0 && x86.eip.get() == 0x0040_1000 && x86.esp.get() == 0x0018_FF00 && x86.e_flags.get() == 0x3F_0FD7 && x86.eax.get() == 0x1111 && x86.edi.get() == 0x2222 && x86.seg_cs.get() == 0x23 && x86.seg_ss.get() == 0x2B && x86.seg_fs.get() == 0x53 && x86.seg_ds.get() == 0x2B;
    assert(from_cpu && x86.context_flags.get() == flags | 0x8800_0000, "wow64: thread no codigo de 64 bits devolve o contexto x86 da area de CPU, com CONTEXT_EXCEPTION_ACTIVE");
    // Parada no código de 32 bits: tudo do CONTEXT nativo.
    native.seg_cs.set(usermode::USER_COMPAT_CS);
    x86.context_flags.set(0x1_0003);
    let status = get_context_on_amd64(cpu, native, x86);
    assert(status == 0 && x86.eip.get() == 0x7FFE_1234 && x86.esp.get() == 0x0011_2200 && x86.ebp.get() == 0x0011_2240 && x86.eax.get() == 0x3333 && x86.e_flags.get() == 0x246, "wow64: thread no codigo de 32 bits devolve os registradores do CONTEXT nativo");
    // A escrita com a thread no código de 64 bits: os inteiros vão à área de
    // CPU e o x87 pede o nativo.
    native.seg_cs.set(usermode::USER_DS + 8);
    x86.context_flags.set(0x1_000B);
    x86.eax.set(0x5555);
    x86.eip.set(0x0040_2000);
    let changed = set_context_on_amd64(cpu, native, x86);
    assert(changed && cpu.eax.get() == 0x5555 && cpu.eip.get() == 0x0040_2000 && native.rax.get() == 0x3333 && native.rip.get() == 0x7FFE_1234 && native.context_flags.get() == 0x10_0008, "wow64: SetContext no codigo de 64 bits vai a area de CPU e so o x87 ao CONTEXT nativo");
    // No código de 32 bits: o nativo recebe os registradores.
    native.seg_cs.set(usermode::USER_COMPAT_CS);
    x86.context_flags.set(0x1_0003);
    let changed = set_context_on_amd64(cpu, native, x86);
    assert(changed && native.rax.get() == 0x5555 && native.rip.get() == 0x0040_2000 && native.seg_cs.get() == 0x23 && native.seg_ss.get() == 0x2B, "wow64: SetContext no codigo de 32 bits vai ao CONTEXT nativo");
    for block in blocks {
        guest::free_bytes(block);
    }
}

/// O RtlFxToFnFrame e o RtlFnToFxFrame: ST(0) = 1.0 no físico 7 (TOP 7), o
/// resto vazio.
fn x87_frames(assert: Assert) {
    use crate::ntos::inc::types::extra_wow64::Wow64FloatingSaveArea;
    use crate::ntos::ps::wow64::context::{fn_to_fx, fx_to_fn};
    let (fx_block, fn_block, back_block) = (guest::alloc_aligned(nt::XsaveFormat::SIZE, 16, true), guest::alloc_bytes(0x70), guest::alloc_aligned(nt::XsaveFormat::SIZE, 16, true));
    if fx_block == 0 || fn_block == 0 || back_block == 0 {
        assert(false, "wow64: imagens x87 de teste");
        return;
    }
    // SAFETY: as imagens de teste acabadas de alocar, zeradas.
    let (fx, fn_area, back) = unsafe { (nt::XsaveFormat::at(fx_block), Wow64FloatingSaveArea::at(fn_block), nt::XsaveFormat::at(back_block)) };
    fx.control_word.set(0x37F);
    fx.status_word.set(7 << 11);
    fx.tag_word.set(0x80);
    fx.error_opcode.set(0x1D9);
    fx.error_selector.set(0x23);
    fx.float_registers[0].low.set(0x8000_0000_0000_0000);
    fx.float_registers[0].high.set(0x3FFF);
    fx_to_fn(fn_area, fx);
    let converted = fn_area.control_word.get() == 0x37F && fn_area.tag_word.get() == 0x3FFF && fn_area.error_selector.get() == 0x01D9_0023 && guest::read_bytes(fn_area.register_area[0].address(), 10) == [0, 0, 0, 0, 0, 0, 0, 0x80, 0xFF, 0x3F];
    fn_to_fx(back, fn_area);
    let returned = back.tag_word.get() == 0x80 && back.status_word.get() == 7 << 11 && back.error_opcode.get() == 0x1D9 && back.float_registers[0].low.get() == 0x8000_0000_0000_0000 && back.float_registers[0].high.get() & 0xFFFF == 0x3FFF;
    for block in [fx_block, fn_block, back_block] {
        guest::free_bytes(block);
    }
    assert(converted && returned, "wow64: o x87 do FXSAVE no FNSAVE do x86 (tag valida no fisico 7) e de volta");
}

/// A forma de 32 bits do PORT_MESSAGE e dos atributos ALPC
/// (`alpc::message::wow64`): a ida à forma nativa e a volta.
fn alpc_layout(assert: Assert) {
    use crate::ntos::alpc::message::wow64;
    let scratch = guest::alloc_bytes(16);
    guest::write64(scratch, 0);
    guest::write64(scratch + 8, 0x1000);
    let status = memory::do_user_allocate(scratch, scratch + 8, 0x3000, 4, 0x10000, 0x1_0000_0000, 0x10000).unwrap_or(1);
    let page = guest::read64(scratch);
    guest::free_bytes(scratch);
    if status != 0 || page == 0 {
        assert(false, "wow64: memoria de usuario para a mensagem ALPC");
        return;
    }
    // PORT_MESSAGE32: DataLength 4, TotalLength 0x1C, Type 1, sem
    // DataInfoOffset, ClientId 0x10/0x20, MessageId 0x30, CallbackId 0x40, e
    // os dados.
    let (message32, message64, back) = (page, page + 0x100, page + 0x200);
    let header: [u32; 6] = [0x001C_0004, 0x0000_0001, 0x10, 0x20, 0x30, 0x40];
    for (index, value) in header.iter().enumerate() {
        guest::write32(message32 + index as u64 * 4, *value);
    }
    guest::write32(message32 + 0x18, 0xDEAD_BEEF);
    let native = wow64::message_to_native(message32, message64).is_ok()
        && guest::read16(message64) == 4
        && guest::read16(message64 + 2) == 0x2C
        && guest::read64(message64 + 8) == 0x10
        && guest::read64(message64 + 0x10) == 0x20
        && guest::read32(message64 + 0x18) == 0x30
        && guest::read64(message64 + 0x20) == 0x40
        && guest::read32(message64 + 0x28) == 0xDEAD_BEEF;
    let round = wow64::message_to_wow64(message64, back).is_ok() && guest::read_bytes(back, 0x1C) == guest::read_bytes(message32, 0x1C);
    assert(native && round, "wow64: PORT_MESSAGE32 na forma nativa (TotalLength + 0x10, CLIENT_ID de 64 bits) e de volta");
    // Atributos: Security (QoS e ContextHandle -1), Context e Direct.
    let (attributes32, attributes64, attributes_back) = (page + 0x400, page + 0x500, page + 0x600);
    let allocated = 0x8000_0000u32 | 0x2000_0000 | 0x0400_0000;
    let words: [u32; 2 + 3 + 5 + 1] = [allocated, allocated, 0x1, 0x1234, 0xFFFF_FFFF, 0xA, 0xB, 0xC, 0xD, 0xE, 0xFFFF_FFFE];
    for (index, value) in words.iter().enumerate() {
        guest::write32(attributes32 + index as u64 * 4, *value);
    }
    let converted = wow64::attributes_to_native(attributes32, attributes64).is_ok()
        && guest::read64(attributes64 + 8 + 8) == 0x1234
        && guest::read64(attributes64 + 8 + 0x10) == u64::MAX
        && guest::read64(attributes64 + 8 + 0x18) == 0xA
        && guest::read64(attributes64 + 8 + 0x18 + 8) == 0xB
        && guest::read32(attributes64 + 8 + 0x18 + 0x10) == 0xC
        && guest::read64(attributes64 + 8 + 0x18 + 0x20) == 0xFFFF_FFFF_FFFF_FFFE;
    guest::write32(attributes_back, allocated);
    let returned = wow64::attributes_to_wow64(attributes64, attributes_back).is_ok() && guest::read_bytes(attributes_back, words.len() * 4) == guest::read_bytes(attributes32, words.len() * 4);
    assert(converted && returned, "wow64: atributos ALPC de 32 bits na forma nativa (handles com extensao de sinal) e de volta");
    if let Some(region) = memory::find_region(page) {
        memory::release_private_region(&region);
    }
}

/// Os descritores de usuário da GDT da CPU corrente.
fn gdt_descriptors(assert: Assert) {
    let gdt = crate::ntos::ke::pcr::current().gdt_base.get();
    let entry = |selector: u64| guest::read64(gdt + (selector & !7));
    let limit = {
        #[repr(C, packed)]
        struct Register {
            limit: u16,
            base: u64,
        }
        let mut register = Register { limit: 0, base: 0 };
        // SAFETY: só lê o GDTR.
        unsafe { core::arch::asm!("sgdt [{}]", in(reg) &mut register, options(nostack)) };
        register.limit
    };
    assert(entry(0x23) == 0x00CF_FB00_0000_FFFF && entry(0x2B) == 0x00CF_F300_0000_FFFF && entry(0x33) == 0x0020_FB00_0000_0000, "wow64: GDT com o codigo de 32 bits, os dados planos e o codigo de 64 bits do usuario");
    // O CMTEB: dados DPL 3 com B=1 e limite 0x3C00; a base é a da thread
    // do último intervalo nesta CPU.
    assert(entry(0x53) & 0xFFFF == 0x3C00 && (entry(0x53) >> 40) & 0xFF == 0xF3 && (entry(0x53) >> 52) & 0xF == 0x4 && limit >= 0x57, "wow64: GDT com o CMTEB 0x53 de 0x3C00 bytes");
    let (data, extra, teb): (u16, u16, u16);
    // SAFETY: só lê os seletores.
    unsafe { core::arch::asm!("mov {0:x}, ds", "mov {1:x}, es", "mov {2:x}, fs", out(reg) data, out(reg) extra, out(reg) teb, options(nomem, nostack, preserves_flags)) };
    assert((data, extra, teb) == (0x2B, 0x2B, 0x53), "wow64: DS e ES no KGDT64_R3_DATA e FS no CMTEB, como o KiSystemStartup deixa");
}

/// Um cabeçalho PE mínimo: DOS, NT com a máquina e o magic pedidos, os
/// alinhamentos, o SizeOfImage e o SizeOfHeaders e os tamanhos de pilha do
/// cabeçalho opcional de 32 bits.
fn header(machine: u16, magic: u16) -> Vec<u8> {
    let mut bytes = alloc::vec![0u8; 0x400];
    bytes[0] = b'M';
    bytes[1] = b'Z';
    bytes[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    let put16 = |bytes: &mut Vec<u8>, at: usize, value: u16| bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    let put32 = |bytes: &mut Vec<u8>, at: usize, value: u32| bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    put32(&mut bytes, 0x80, 0x4550);
    put16(&mut bytes, 0x84, machine);
    put16(&mut bytes, 0x94, 0xE0);
    put16(&mut bytes, 0x96, 0x102);
    let optional = 0x98;
    put16(&mut bytes, optional, magic);
    put32(&mut bytes, optional + 16, 0x1000);
    put32(&mut bytes, optional + 28, 0x40_0000);
    put32(&mut bytes, optional + 32, 0x1000);
    put32(&mut bytes, optional + 36, 0x200);
    put32(&mut bytes, optional + 56, 0x3000);
    put32(&mut bytes, optional + 60, 0x400);
    put16(&mut bytes, optional + 68, 3);
    put32(&mut bytes, optional + 72, 0x10_0000);
    put32(&mut bytes, optional + 76, 0x2000);
    bytes
}

fn image_headers(assert: Assert) {
    let parse = |bytes: &Vec<u8>| image_header::parse(bytes.len() as u64, &|offset, length| Ok(bytes.get(offset as usize..(offset + length) as usize).map(<[u8]>::to_vec))).ok().and_then(Result::ok);
    let x86 = header(0x14C, 0x10B);
    let parsed = parse(&x86);
    assert(parsed.is_some_and(|header| header.size_of_image == 0x3000 && header.size_of_headers == 0x400 && !header.flat), "wow64: cabecalho PE32 i386 aceito pela secao de imagem");
    assert(parse(&header(0x8664, 0x10B)).is_none() && parse(&header(0x14C, 0x20B)).is_none() && parse(&header(0x1C4, 0x10B)).is_none(), "wow64: PE32 de outra maquina e PE32+ i386 recusados");
    // A SECTION_IMAGE_INFORMATION do PE32: a entrada na base mapeada, os
    // tamanhos de pilha de 32 bits, o subsistema e a Machine.
    let source = crate::ntos::mm::sysload::kernel_image_source::MemorySource { name: alloc::string::String::new(), bytes: x86.clone() };
    let metadata = crate::ntos::rtl::image::pe_metadata_reader::MetadataReader::new(&source);
    let information = crate::ntos::rtl::image::pe_image_information::capture(&metadata, x86.len() as u64, 0x84, 0x98, 0x40_0000, false);
    let word = |information: &[u8], at: usize| u16::from_le_bytes([information[at], information[at + 1]]);
    let quad = |information: &[u8], at: usize| u64::from_le_bytes(information[at..at + 8].try_into().unwrap_or([0; 8]));
    assert(information.as_ref().is_ok_and(|information| quad(information, 0) == 0x40_1000 && quad(information, 0x10) == 0x10_0000 && quad(information, 0x18) == 0x2000 && word(information, 0x20) == 3 && word(information, 0x30) == 0x14C), "wow64: SECTION_IMAGE_INFORMATION do PE32 com a Machine e as pilhas de 32 bits");
}

fn process_user_va(assert: Assert) {
    use crate::ntos::mm::process_address_space::{allocation_top, compute_user_va};
    let block = guest::alloc_bytes(nt::Eprocess::SIZE);
    if block == 0 {
        assert(false, "wow64: EPROCESS de teste");
        return;
    }
    guest::write_bytes(block, &alloc::vec![0u8; nt::Eprocess::SIZE as usize]);
    // SAFETY: o bloco de teste do tamanho do EPROCESS.
    let eprocess = unsafe { nt::Eprocess::at(block) };
    compute_user_va(block, 0x102, true);
    let small = (eprocess.highest_user_address.get(), eprocess.wow64_va_space4_gb(), allocation_top(block));
    compute_user_va(block, 0x122, true);
    let large = (eprocess.highest_user_address.get(), eprocess.wow64_va_space4_gb());
    eprocess.flags.set(0);
    compute_user_va(block, 0x22, false);
    let native = (eprocess.highest_user_address.get(), allocation_top(block));
    compute_user_va(block, 0x2, false);
    let native_small = eprocess.highest_user_address.get();
    guest::free_bytes(block);
    assert(small == (0x7FFF_0000, 0, 0x7FFE_0000), "wow64: imagem x86 sem LARGE_ADDRESS_AWARE fica com 2 GB e a escolha de VA para em 0x7FFE0000");
    assert(large == (0xFFFF_0000, 1), "wow64: imagem x86 com LARGE_ADDRESS_AWARE fica com 4 GB e Wow64VaSpace4Gb");
    assert(native == (0x7FFF_FFFF_0000, 0x7FFF_FFFE_0000) && native_small == 0x7FFF_0000, "wow64: processo nativo com o MmUserProbeAddress, ou 2 GB sem LARGE_ADDRESS_AWARE");
}

fn cpu_area(assert: Assert) {
    use crate::ntos::ps::wow64::thread::setup_cpu_area;
    // Topo 0x10_0000: -4 e alinha a 4, -5 e alinha a 8, - 0x2CC, alinha a
    // 4, -4 e alinha a 16.
    let base = setup_cpu_area(0x10_0000);
    assert(base == 0xF_FD20 && base & 0xF == 0 && base + 4 + nt::extra_wow64::Wow64Context::SIZE <= 0x10_0000, "wow64: a area de CPU do PspWow64SetupCpuArea cabe no topo da pilha de 64 bits");
}

/// O modo de compatibilidade no anel 3, por um intervalo de escalonamento.
fn compatibility_mode(assert: Assert) {
    if !usermode::ready() {
        assert(false, "wow64: anel 3 armado");
        return;
    }
    let scratch = guest::alloc_bytes(16);
    let allocate = |size: u64, protect: u32| {
        guest::write64(scratch, 0);
        guest::write64(scratch + 8, size);
        let status = memory::do_user_allocate(scratch, scratch + 8, 0x3000, protect, 0x10000, 0x1_0000_0000, 0x10000).unwrap_or(1);
        if status == 0 { guest::read64(scratch) } else { 0 }
    };
    let (code, stack, data) = (allocate(0x1000, 0x40), allocate(0x4000, 4), allocate(0x1000, 4));
    if code == 0 || stack == 0 || data == 0 || code >= 0x1_0000_0000 || stack >= 0x1_0000_0000 {
        assert(false, "wow64: memoria de usuario abaixo de 4 GB");
        return;
    }
    guest::write32(data, 0x5A5A_0000);
    // Um UNICODE_STRING vazio em data + 8 para o NtDisplayString do fim.
    guest::write_bytes(data + 8, &[0; 16]);
    let stack_top = stack + 0x4000 - 0x40;
    // 64 bits: retfq para 0x23:compat. 32 bits: CS lido, um push/pop pela
    // pilha de 32 bits, FS:[0] (a base do CMTEB), um laço longo e o retf
    // de volta para 0x33. 64 bits: a soma em EDX e o NtDisplayString, que
    // encerra o intervalo com os registradores no CONTEXT.
    let mut program: Vec<u8> = Vec::new();
    program.extend_from_slice(&[0xBB, 0x78, 0x56, 0x34, 0x12]); // mov ebx, 0x12345678
    program.extend_from_slice(&[0x48, 0x8D, 0x05, 0x05, 0x00, 0x00, 0x00]); // lea rax, [rip + 5]
    program.extend_from_slice(&[0x6A, 0x23, 0x50, 0x48, 0xCB]); // push 0x23; push rax; retfq
    // compat:
    program.extend_from_slice(&[0x66, 0x8C, 0xC8, 0x0F, 0xB7, 0xC0]); // mov ax, cs; movzx eax, ax
    program.extend_from_slice(&[0x53, 0x5A]); // push ebx; pop edx
    program.extend_from_slice(&[0x64, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00]); // mov ecx, fs:[0]
    program.extend_from_slice(&[0x01, 0xCA]); // add edx, ecx
    program.extend_from_slice(&[0xBE, 0x00, 0x00, 0x00, 0x10, 0x4E, 0x75, 0xFD]); // mov esi, 0x10000000; dec esi; jnz -3
    program.extend_from_slice(&[0x6A, 0x33, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x05, 0xCB]); // push 0x33; call $+5; add [esp], 5; retf
    // back64:
    program.extend_from_slice(&[0x01, 0xC2]); // add edx, eax
    program.extend_from_slice(&[0x48, 0xB9]); // mov rcx, data + 8
    program.extend_from_slice(&(data + 8).to_le_bytes());
    program.extend_from_slice(&[0x49, 0x89, 0xCA, 0xB8, 0x27, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xEB, 0xFE]); // mov r10, rcx; mov eax, 0x27; syscall; jmp $
    guest::write_bytes(code, &program);
    // Uma thread de usuário própria, com o UserFsBase na página de dados: o
    // FS do código de 32 bits é a base do CMTEB que o SwapContext dá a ela.
    let previous = process::get_current_thread();
    let Ok(thread) = process::create_kernel_thread(process::get_current_process(), crate::ntos::ps::cid::ALLOCATE, true, 1, None) else {
        assert(false, "wow64: thread de usuario");
        return;
    };
    process::set_current_thread(thread);
    // SAFETY: a ETHREAD recém-criada acima.
    unsafe { nt::Ethread::at(thread) }.user_fs_base.set(data);
    let exit_cell = usermode::block().exit_code.get();
    let raw_context = guest::alloc_bytes(threads::CONTEXT_SIZE + 16);
    let context = (raw_context + 15) & !15;
    threads::initialize_context(context, code, stack_top, 0, 0);
    let (mut kind, mut rounds, mut compat_exits) = (2u32, 0u32, 0u32);
    while kind == 2 && rounds < 4096 {
        let _ = usermode::exec_user_context(context, 0);
        kind = usermode::block().exit_kind.get();
        // A primeira escrita numa página comprometida sob demanda (a pilha, a
        // página de dados) é resolvida como no despachante e a instrução
        // repete.
        let block = usermode::block();
        if kind == 3 && block.fault_vector.get() == 14 && crate::ntos::mm::page_residency::fault(block.fault_cr2.get(), block.error_code.get() as u32) {
            kind = 2;
        }
        // SAFETY: o CONTEXT do intervalo, na memória do kernel.
        if kind == 2 && unsafe { nt::Context::at(context) }.seg_cs.get() == usermode::USER_COMPAT_CS {
            compat_exits += 1;
        }
        rounds += 1;
    }
    // SAFETY: o CONTEXT do intervalo, na memória do kernel.
    let (result, segment) = { let saved = unsafe { nt::Context::at(context) }; (saved.rdx.get() as u32, saved.seg_cs.get()) };
    let expected = 0x1234_5678u32.wrapping_add(0x5A5A_0000).wrapping_add(0x23);
    // SAFETY: o CONTEXT do intervalo, na memória do kernel.
    let rip = unsafe { nt::Context::at(context) }.rip.get();
    crate::debug_print!("[wow64] modo de compatibilidade: saida {} apos {} intervalos ({} no codigo de 32 bits), EDX {:#x} (esperado {:#x}), CS {:#x}, RIP {:#x} (codigo em {:#x}), falta {:#x} CR2 {:#x}", kind, rounds, compat_exits, result, expected, segment, rip, code, usermode::block().fault_vector.get(), usermode::block().fault_cr2.get());
    process::set_current_thread(previous);
    let _ = process::release_thread(thread);
    usermode::block().exit_code.set(exit_cell);
    guest::free_bytes(raw_context);
    guest::free_bytes(scratch);
    for base in [code, stack, data] {
        if let Some(region) = memory::find_region(base) {
            memory::release_private_region(&region);
        }
    }
    assert(kind == 1 && result == expected && segment == 0x33, "wow64: codigo de 32 bits no anel 3 com CS 0x23, pilha de 32 bits, FS do CMTEB e a volta ao codigo de 64 bits");
    assert(compat_exits > 0, "wow64: o relogio interrompe o codigo de 32 bits, o CONTEXT guarda SegCs 0x23 e a retomada volta ao modo de compatibilidade");
}
