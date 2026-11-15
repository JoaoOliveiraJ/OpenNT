//! Autotestes (fase 6) da interface x86 BIOS da HAL, chamada pelos exports
//! x86Bios* (os mesmos que o BasicDisplay.sys importa) e pelo
//! HalQuerySystemInformation da HalDispatchTable.
//!
//! - O HaliQuerySystemInformation(HalDisplayBiosInformation) informa o BIOS
//!   emulado (1), com o tamanho copiado no ReturnedLength.
//! - x86BiosAllocateBuffer/FreeBuffer com as regras do ntoskrnl 19041: o
//!   buffer inteiro (2000:0000, 8 KB) uma vez só, a liberação pelo endereço
//!   linear 20000h (2000:0000 ou 1FFF:0010).
//! - x86BiosRead/WriteMemory sobre o mapa do primeiro megabyte: a IVT e a
//!   BDA copiadas da memória física (escritas ficam na cópia), o rascunho
//!   (lê zero), o buffer em 2000h e 3000h, a ROM de vídeo em C0000h, e o
//!   limite de 1 MB.
//! - O processador emulado, por um vetor livre da IVT copiada (60h)
//!   apontado para código no buffer de transferência: o PCI BIOS do INT 1Ah
//!   (B101h, B102h, B10Ah, B106h), o latch do mecanismo de configuração 1
//!   (CF8h/CFCh), o latch da CMOS (70h/71h), RETF ao quadro falso, e as
//!   paradas por HLT, opcode ilegal, limite de segmento e divisão por zero
//!   (FALSE, com o emulador pronto para a chamada seguinte).
//! - O BIOS de vídeo real da máquina pelo INT 10h: 4F00h devolve 'VESA',
//!   VBE 3.0, a memória do adaptador (o registrador VIDEO_MEMORY_64K da
//!   interface DISPI do adaptador do QEMU) e a lista de modos; 4F01h de um modo 1024x768x32 da lista dá
//!   o framebuffer linear no BAR0 do adaptador e a linha de 4096 bytes;
//!   4F02h liga o modo (os registradores DISPI e o GR06 da VGA o
//!   confirmam) e 4F03h o devolve; o INT 10h AX=0003h volta ao modo texto
//!   (VBE desligado, GR06 em texto no B8000h) antes de o console reaver a
//!   posse do vídeo.

use alloc::string::String;
use alloc::vec::Vec;

use super::phase6::call_export;
use crate::hal::amd64::native_call;
use crate::hal::{pci_config, physical, port, public_dispatch, rtc};
use crate::ntos::inbv::display as inbv;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_hal::X86BiosRegisters;
use crate::ntos::inc::types::HalDispatch;
use crate::ntos::mm::guest_memory as guest;

type Assert = fn(bool, &str);

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u64 = 0xC000_009A;
const STATUS_NOT_SUPPORTED: u64 = 0xC000_00BB;
/// Vetor livre da IVT para o código de teste.
const TEST_VECTOR: u32 = 0x60;
/// Onde o código de teste fica no buffer de transferência.
const CODE_OFFSET: u16 = 0x100;
/// Registradores de modo do adaptador VGA do QEMU (interface DISPI: porta
/// de índice 1CEh, de dados 1CFh).
const DISPI_INDEX_XRES: u16 = 1;
const DISPI_INDEX_YRES: u16 = 2;
const DISPI_INDEX_BPP: u16 = 3;
const DISPI_INDEX_ENABLE: u16 = 4;
const DISPI_INDEX_VIDEO_MEMORY_64K: u16 = 0xA;
const DISPI_ENABLED: u16 = 0x01;
const DISPI_LFB_ENABLED: u16 = 0x40;

fn status(name: &str, arguments: &[u64]) -> u64 {
    call_export(name, arguments).map_or(u64::MAX, |value| value as u32 as u64)
}

/// Registradores de entrada (EAX, ECX, EDX, EBX, ESI, EDI, DS, ES).
#[derive(Clone, Copy, Default)]
struct Input {
    eax: u32,
    ecx: u32,
    edx: u32,
    ebx: u32,
    esi: u32,
    edi: u32,
    ds: u16,
    es: u16,
}

/// Saída de uma chamada: o BOOLEAN e os registradores devolvidos.
struct Output {
    ok: bool,
    eax: u32,
    ecx: u32,
    edx: u32,
    ebx: u32,
}

fn bios_call(vector: u32, input: Input) -> Output {
    let address = guest::alloc_bytes(X86BiosRegisters::SIZE);
    // SAFETY: bloco de 0x20 bytes recém-alocado.
    let registers = unsafe { X86BiosRegisters::at(address) };
    registers.eax.set(input.eax);
    registers.ecx.set(input.ecx);
    registers.edx.set(input.edx);
    registers.ebx.set(input.ebx);
    registers.ebp.set(0);
    registers.esi.set(input.esi);
    registers.edi.set(input.edi);
    registers.seg_ds.set(input.ds);
    registers.seg_es.set(input.es);
    let ok = call_export("x86BiosCall", &[vector as u64, address]) == Some(1);
    let output = Output { ok, eax: registers.eax.get(), ecx: registers.ecx.get(), edx: registers.edx.get(), ebx: registers.ebx.get() };
    guest::free_bytes(address);
    output
}

fn read_memory(segment: u16, offset: u16, size: usize) -> (u64, Vec<u8>) {
    let buffer = guest::alloc_bytes(size.max(1) as u64);
    let result = status("x86BiosReadMemory", &[segment as u64, offset as u64, buffer, size as u64]);
    let bytes = guest::read_bytes(buffer, size);
    guest::free_bytes(buffer);
    (result, bytes)
}

fn write_memory(segment: u16, offset: u16, bytes: &[u8]) -> u64 {
    let buffer = guest::alloc_bytes(bytes.len().max(1) as u64);
    guest::write_bytes(buffer, bytes);
    let result = status("x86BiosWriteMemory", &[segment as u64, offset as u64, buffer, bytes.len() as u64]);
    guest::free_bytes(buffer);
    result
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]]) as u32
}

fn dword(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn dispi(index: u16) -> u16 {
    port::write16(0x1CE, index);
    port::read16(0x1CF)
}

fn graphics_register(index: u8) -> u8 {
    port::write8(0x3CE, index);
    port::read8(0x3CF)
}

/// O adaptador VGA (classe 03.00) do barramento 0: (dispositivo, função,
/// fabricante e dispositivo, BAR0).
fn vga_adapter() -> Option<(u32, u32, u32, u32)> {
    for device in 0..32 {
        for function in 0..8 {
            let id = pci_config::read(0, device, function, 0, 4).ok()?;
            if id & 0xFFFF == 0xFFFF {
                continue;
            }
            let class = pci_config::read(0, device, function, 8, 4).ok()? >> 16;
            if class == 0x0300 {
                return Some((device, function, id, pci_config::read(0, device, function, 0x10, 4).ok()? & !0xF));
            }
        }
    }
    None
}

pub fn run(assert: Assert) {
    query_system_information(assert);
    transfer_buffer(assert);
    memory_map(assert);
    emulated_code(assert);
    video_bios(assert);
}

/// HalDispatchTable->HalQuerySystemInformation(HalDisplayBiosInformation).
fn query_system_information(assert: Assert) {
    // SAFETY: a HalDispatchTable publicada pela HAL.
    let routine = unsafe { HalDispatch::at(public_dispatch::table_address()) }.hal_query_system_information.get();
    let (buffer, returned) = (guest::alloc_bytes(8), guest::alloc_bytes(4));
    guest::write64(buffer, u64::MAX);
    guest::write32(returned, 0xFFFF_FFFF);
    let full = native_call::call(routine, &[9, 8, buffer, returned]) as u32 as u64;
    let (value, length) = (guest::read64(buffer), guest::read32(returned));
    guest::write64(buffer, u64::MAX);
    let short = native_call::call(routine, &[9, 2, buffer, returned]) as u32 as u64;
    let (short_value, short_length) = (guest::read64(buffer), guest::read32(returned));
    let other = native_call::call(routine, &[1, 8, buffer, returned]) as u32 as u64;
    assert(
        full == STATUS_SUCCESS && value == 0xFFFF_FFFF_0000_0001 && length == 4 && short == STATUS_SUCCESS && short_value == 0xFFFF_FFFF_FFFF_0001 && short_length == 2 && other == STATUS_NOT_SUPPORTED && guest::read32(returned) == 0,
        "x86bios: HalQuerySystemInformation(HalDisplayBiosInformation) = HalDisplayEmulatedBios (4 bytes, ou o tamanho do buffer)",
    );
    guest::free_bytes(buffer);
    guest::free_bytes(returned);
}

/// x86BiosAllocateBuffer/x86BiosFreeBuffer.
fn transfer_buffer(assert: Assert) {
    let cells = guest::alloc_bytes(8);
    let (size, segment, offset) = (cells, cells + 4, cells + 6);
    guest::write32(size, 0x200);
    guest::write16(segment, 0xFFFF);
    guest::write16(offset, 0xFFFF);
    let first = status("x86BiosAllocateBuffer", &[size, segment, offset]);
    let granted = (guest::read32(size), guest::read16(segment), guest::read16(offset));
    guest::write32(size, 0x200);
    let second = status("x86BiosAllocateBuffer", &[size, segment, offset]);
    let wrong_free = status("x86BiosFreeBuffer", &[0x1000, 0]);
    let aliased_free = status("x86BiosFreeBuffer", &[0x1FFF, 0x10]);
    let double_free = status("x86BiosFreeBuffer", &[0x2000, 0]);
    guest::write32(size, 0x2001);
    let too_big = status("x86BiosAllocateBuffer", &[size, segment, offset]);
    guest::write32(size, 0x2000);
    let whole = status("x86BiosAllocateBuffer", &[size, segment, offset]);
    let freed = status("x86BiosFreeBuffer", &[0x2000, 0]);
    assert(
        first == STATUS_SUCCESS && granted == (0x2000, 0x2000, 0) && second == STATUS_INSUFFICIENT_RESOURCES && wrong_free == STATUS_INVALID_PARAMETER && aliased_free == STATUS_SUCCESS && double_free == STATUS_INVALID_PARAMETER && too_big == STATUS_INSUFFICIENT_RESOURCES && whole == STATUS_SUCCESS && freed == STATUS_SUCCESS,
        "x86bios: AllocateBuffer da 2000:0000 inteira uma vez; FreeBuffer pelo linear 20000h",
    );
    guest::free_bytes(cells);
}

/// x86BiosReadMemory/x86BiosWriteMemory sobre o mapa do primeiro megabyte.
fn memory_map(assert: Assert) {
    let (beyond, _) = read_memory(0xF000, 0xFFFF, 2);
    let (edge, _) = read_memory(0xFFFF, 0x10, 0);
    assert(beyond == STATUS_INVALID_PARAMETER && edge == STATUS_SUCCESS, "x86bios: ReadMemory recusa segmento*16 + deslocamento + tamanho acima de 1 MB");
    let (_, ivt) = read_memory(0, 0x40, 4);
    let (_, mode) = read_memory(0x40, 0x49, 1);
    let (_, rom) = read_memory(0xC000, 0, 3);
    assert(
        dword(&ivt, 0) == physical::read32(0x40) && mode[0] == physical::read8(0x449) && rom[..2] == [0x55, 0xAA] && rom[2] == physical::read8(0xC0002),
        "x86bios: IVT e BDA copiadas da memoria fisica; ROM de video em C000:0000",
    );
    let physical_byte = physical::read8(0x7F0);
    let written = write_memory(0, 0x7F0, &[!physical_byte, 0x5A]);
    let (_, private) = read_memory(0, 0x7F0, 2);
    assert(written == STATUS_SUCCESS && private == [!physical_byte, 0x5A] && physical::read8(0x7F0) == physical_byte, "x86bios: escrita na BDA fica na copia privada");
    write_memory(0x1000, 0, &[1, 2, 3, 4]);
    write_memory(0x0080, 0x10, &[9]);
    let (_, scratch) = read_memory(0x1000, 0, 4);
    let (_, above_low) = read_memory(0x0080, 0x10, 1);
    write_memory(0x2000, 0x1F0, &[0x77]);
    let (_, alias) = read_memory(0x3000, 0x1F0, 1);
    assert(scratch == [0; 4] && above_low == [0] && alias == [0x77], "x86bios: rascunho le zero; 3000h espelha o buffer de 2000h");
}

/// O processador emulado por código posto no buffer de transferência e
/// chamado pelo vetor 60h da IVT copiada.
fn emulated_code(assert: Assert) {
    let (_, saved_vector) = read_memory(0, (TEST_VECTOR * 4) as u16, 4);
    write_memory(0, (TEST_VECTOR * 4) as u16, &[CODE_OFFSET as u8, (CODE_OFFSET >> 8) as u8, 0x00, 0x20]);
    let run = |code: &[u8], input: Input| {
        write_memory(0x2000, CODE_OFFSET, code);
        bios_call(TEST_VECTOR, input)
    };
    // INT 1Ah; IRET.
    let int1a: &[u8] = &[0xCD, 0x1A, 0xCF];
    let present = run(int1a, Input { eax: 0xB101, ..Input::default() });
    assert(
        present.ok && present.edx == 0x2049_4350 && present.ebx & 0xFFFF == 0x0210 && present.ecx & 0xFF == 0xFF && present.eax & 0xFF00 == 0,
        "x86bios: INT 1Ah B101h pelo PCI BIOS emulado ('PCI ', versao 2.10, FFh barramentos)",
    );
    let adapter = vga_adapter();
    if let Some((device, function, id, _)) = adapter {
        let found = run(int1a, Input { eax: 0xB102, edx: id & 0xFFFF, ecx: id >> 16, ..Input::default() });
        let location = (device << 3) | function;
        let config = run(int1a, Input { eax: 0xB10A, ebx: location, edi: 0, ..Input::default() });
        let unsupported = run(int1a, Input { eax: 0xB106, ..Input::default() });
        assert(
            found.ok && found.ebx & 0xFFFF == location && found.eax & 0xFF00 == 0 && config.ok && config.ecx == id && unsupported.ok && unsupported.eax & 0xFF00 == 0x8100,
            "x86bios: INT 1Ah B102h acha o adaptador VGA, B10Ah le o seu id, B106h sem suporte (AH=81h)",
        );
        // mov eax, endereço; out CF8h; in CFCh; mov ebx, eax; in CF8h; iret.
        let address = 0x8000_0000 | (device << 11) | (function << 8) | 0x03;
        let mut latch = alloc::vec![0x66, 0xB8];
        latch.extend_from_slice(&address.to_le_bytes());
        latch.extend_from_slice(&[0xBA, 0xF8, 0x0C, 0x66, 0xEF, 0xBA, 0xFC, 0x0C, 0x66, 0xED, 0x66, 0x89, 0xC3, 0xBA, 0xF8, 0x0C, 0x66, 0xED, 0xCF]);
        let mechanism = run(&latch, Input::default());
        assert(mechanism.ok && mechanism.ebx == id && mechanism.eax == address & !3, "x86bios: CF8h/CFCh pelo latch do emulador (bits baixos limpos) e pela leitura de configuracao da HAL");
    } else {
        assert(false, "x86bios: adaptador VGA ausente no barramento 0");
    }
    // mov al, 0Ah; out 70h, al; in al, 70h; mov bl, al; in al, 71h; iret.
    let cmos = run(&[0xB0, 0x0A, 0xE6, 0x70, 0xE4, 0x70, 0x88, 0xC3, 0xE4, 0x71, 0xCF], Input::default());
    assert(cmos.ok && cmos.ebx & 0xFF == 0x0A && cmos.eax & 0x7F == (rtc::cmos_read(0x0A) & 0x7F) as u32, "x86bios: CMOS pelo latch do indice (70h) e pela transacao em 71h");
    let retf = run(&[0xCB], Input::default());
    let halt = run(&[0xF4], Input::default());
    let illegal = run(&[0x63, 0xC0, 0xCF], Input::default());
    // mov eax, 10000h; mov ax, [eax]; iret.
    let limit = run(&[0x66, 0xB8, 0x00, 0x00, 0x01, 0x00, 0x67, 0x8B, 0x00, 0xCF], Input::default());
    // xor cx, cx; div cx; iret.
    let divide = run(&[0x31, 0xC9, 0xF7, 0xF1, 0xCF], Input { eax: 1, ..Input::default() });
    let again = run(int1a, Input { eax: 0xB101, ..Input::default() });
    assert(retf.ok && !halt.ok && !illegal.ok && !limit.ok && !divide.ok && again.ok && again.edx == 0x2049_4350, "x86bios: RETF ao quadro falso termina; HLT, 63h, limite de segmento e divisao por zero dao FALSE");
    write_memory(0, (TEST_VECTOR * 4) as u16, &saved_vector);
}

/// O BIOS de vídeo da máquina pelo INT 10h (VBE).
fn video_bios(assert: Assert) {
    let cells = guest::alloc_bytes(8);
    guest::write32(cells, 0x200);
    let allocated = status("x86BiosAllocateBuffer", &[cells, cells + 4, cells + 6]);
    let (segment, offset) = (guest::read16(cells + 4), guest::read16(cells + 6));
    guest::free_bytes(cells);
    if allocated != STATUS_SUCCESS {
        assert(false, "x86bios: AllocateBuffer para o VBE");
        return;
    }
    write_memory(segment, offset, b"VBE2");
    let info_call = bios_call(0x10, Input { eax: 0x4F00, edi: offset as u32, es: segment, ..Input::default() });
    let (_, info) = read_memory(segment, offset, 0x200);
    let (mode_offset, mode_segment) = (word(&info, 0x0E) as u16, word(&info, 0x10) as u16);
    let (_, list) = read_memory(mode_segment, mode_offset, 0x200);
    let modes: Vec<u32> = (0..0x100).map(|index| word(&list, index * 2)).take_while(|&mode| mode != 0xFFFF).collect();
    let (_, oem) = read_memory(word(&info, 0x08) as u16, word(&info, 0x06) as u16, 64);
    let oem: String = oem.iter().take_while(|&&byte| byte != 0).map(|&byte| byte as char).collect();
    let memory = dispi(DISPI_INDEX_VIDEO_MEMORY_64K) as u32;
    assert(
        info_call.ok && info_call.eax & 0xFFFF == 0x004F && info[..4] == *b"VESA" && word(&info, 4) == 0x0300 && word(&info, 0x12) == memory && !modes.is_empty() && !oem.is_empty() && oem.bytes().all(|byte| (0x20..0x7F).contains(&byte)),
        "x86bios: INT 10h 4F00h devolve 'VESA', VBE 3.0, a memoria do adaptador e a lista de modos",
    );
    // 4F01h: o primeiro modo 1024x768x32 com framebuffer linear.
    let mut chosen = None;
    for &mode in modes.iter().filter(|&&mode| mode >= 0x100) {
        let mode_call = bios_call(0x10, Input { eax: 0x4F01, ecx: mode, edi: offset as u32 + 0x200, es: segment, ..Input::default() });
        let (_, mode_info) = read_memory(segment, offset + 0x200, 0x100);
        if mode_call.ok && mode_call.eax & 0xFFFF == 0x004F && word(&mode_info, 0x12) == 1024 && word(&mode_info, 0x14) == 768 && mode_info[0x19] == 32 && word(&mode_info, 0) & 0x90 == 0x90 {
            chosen = Some((mode, word(&mode_info, 0x10), dword(&mode_info, 0x28)));
            break;
        }
    }
    let bar0 = vga_adapter().map_or(0, |(_, _, _, bar)| bar);
    let Some((mode, pitch, framebuffer)) = chosen else {
        assert(false, "x86bios: INT 10h 4F01h sem modo 1024x768x32 com framebuffer linear");
        return;
    };
    assert(framebuffer == bar0 && bar0 != 0 && pitch == 4096, "x86bios: INT 10h 4F01h de um modo da lista da o framebuffer linear no BAR0 e a linha");
    // O vídeo passa do console ao "driver" durante as trocas de modo.
    inbv::notify_display_ownership_change(false, 0);
    let set = bios_call(0x10, Input { eax: 0x4F02, ebx: mode | 0x4000, ..Input::default() });
    let registers = (dispi(DISPI_INDEX_XRES), dispi(DISPI_INDEX_YRES), dispi(DISPI_INDEX_BPP), dispi(DISPI_INDEX_ENABLE));
    let graphics = graphics_register(6);
    let current = bios_call(0x10, Input { eax: 0x4F03, ..Input::default() });
    let text = bios_call(0x10, Input { eax: 0x0003, ..Input::default() });
    let (enable_after, graphics_after) = (dispi(DISPI_INDEX_ENABLE), graphics_register(6));
    inbv::notify_display_ownership_change(true, 0);
    let (_, bda_mode) = read_memory(0x40, 0x49, 1);
    debug_print!(
        "[x86bios] VBE '{}': {} modos, {} KB; modo {:#x} 1024x768x32 framebuffer {:#x} linha {}; 4F02h -> dispi {}x{}x{} enable {:#x} GR06 {:#x}; 4F03h -> {:#x}; modo 3 -> enable {:#x} GR06 {:#x}",
        oem, modes.len(), memory * 64, mode, framebuffer, pitch, registers.0, registers.1, registers.2, registers.3, graphics, current.ebx & 0xFFFF, enable_after, graphics_after
    );
    assert(
        set.ok && set.eax & 0xFFFF == 0x004F && registers == (1024, 768, 32, registers.3) && registers.3 & (DISPI_ENABLED | DISPI_LFB_ENABLED) == DISPI_ENABLED | DISPI_LFB_ENABLED && graphics & 1 == 1,
        "x86bios: INT 10h 4F02h liga o modo (DISPI 1024x768x32 com LFB, GR06 grafico)",
    );
    assert(current.ok && current.eax & 0xFFFF == 0x004F && current.ebx & 0xFFFF == mode | 0x4000, "x86bios: INT 10h 4F03h devolve o modo corrente");
    assert(text.ok && enable_after & DISPI_ENABLED == 0 && graphics_after & 0x0D == 0x0C && bda_mode == [3], "x86bios: INT 10h 0003h volta ao modo texto (VBE desligado, GR06 texto em B8000h, BDA modo 3)");
    assert(status("x86BiosFreeBuffer", &[segment as u64, offset as u64]) == STATUS_SUCCESS, "x86bios: FreeBuffer do buffer do VBE");
}
