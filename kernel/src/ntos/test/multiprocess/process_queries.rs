//! PsQueryProcessCommandLine e PsResumeProcess sobre processos reais.
//!
//! - Um processo de teste com os parâmetros normalizados (o CommandLine com
//!   o endereço absoluto, como depois do LdrpInitializeProcess):
//!   PsQueryProcessCommandLine devolve o UNICODE_STRING com o buffer logo
//!   depois dele (MaximumLength + 0x10 em ReturnLength) e o texto lido da
//!   memória do processo; um buffer pequeno dá STATUS_INFO_LENGTH_MISMATCH
//!   com o tamanho necessário; o System (sem PEB) dá STATUS_NOT_FOUND.
//! - Um processo criado pelo caminho único com a thread principal suspensa
//!   e uma linha de comando com argumentos:
//!   - os parâmetros ainda estão no formato auto-relativo (o Buffer é um
//!     deslocamento, que a ntdll normaliza na partida): a cópia a partir do
//!     deslocamento falha e o PsQueryProcessCommandLine devolve o erro dela,
//!     como no NT;
//!   - PsResumeProcess tira a suspensão da thread principal (contagem 1 ->
//!     0), e o processo roda e sai com o código.
//! - Depois do fim, com o EPROCESS retido, os dois devolvem
//!   STATUS_PROCESS_IS_TERMINATING (o rundown do processo encerrado).

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::ps::create::{self, CreateProcessRequest, ImageOrigin};
use crate::ntos::ps::process;
use crate::ntos::ps::process_parameters::ProcessParameters;
use crate::ntos::ps::user::process as user_process;
use crate::ntos::ps::user::threads;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::test::phase6::call_export;

type Assert = fn(bool, &str);

const EXIT_CODE: u32 = 0x62;
const IMAGE_NAME: &str = "consulta.exe";
const IMAGE_PATH: &str = "C:\\OpenNT\\consulta.exe";
const COMMAND_LINE: &str = "\"C:\\OpenNT\\consulta.exe\" -linha 42";
const THREAD_CREATE_SUSPENDED: u32 = 1;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;

/// NtTerminateProcess(-1, código) pela syscall da ntdll de bring-up, depois
/// do LdrInitializeThunk.
fn program() -> Vec<u8> {
    let code = EXIT_CODE.to_le_bytes();
    let entry: &[u8] = &[0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0xBA, code[0], code[1], code[2], code[3], 0x49, 0x89, 0xCA, 0xB8, 0x2C, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xEB, 0xFE];
    crate::ntos::test::phase7::single_section_image(0x1_4000_0000, 0x0022, b".text", 0x6000_0020, 0x1000, entry)
}

/// PsQueryProcessCommandLine num buffer de kernel: (status, ReturnLength,
/// Length, MaximumLength, Buffer, texto).
fn query(process_pointer: u64, length: u32) -> (u32, u32, u16, u16, u64, String) {
    let output = guest::alloc_bytes(0x200);
    guest::write_bytes(output, &[0xEE; 0x200]);
    let returned = guest::alloc_bytes(8);
    guest::write32(returned, 0);
    let status = call_export("PsQueryProcessCommandLine", &[process_pointer, output, length as u64, 0, returned]).map_or(u32::MAX, |status| status as u32);
    let (characters, maximum, buffer) = (guest::read16(output), guest::read16(output + 2), guest::read64(output + 8));
    let units: Vec<u16> = if status == 0 { (0..characters as u64 / 2).map(|index| guest::read16(output + 0x10 + index * 2)).collect() } else { Vec::new() };
    let text = String::from_utf16_lossy(&units);
    let result = (status, guest::read32(returned), characters, maximum, if buffer == output + 0x10 { 1 } else { buffer }, text);
    guest::free_bytes(returned);
    guest::free_bytes(output);
    result
}

/// Um processo de teste com os parâmetros normalizados na memória dele.
fn normalized_parameters(assert: Assert) {
    use crate::ntos::ps::user::memory;
    use crate::ntos::test::multiprocess::identity::with_test_process;
    let ran = with_test_process("consulta-normal", None, |test| {
        let Ok(block) = memory::map_user_region(0x1000) else { return false };
        let units: Vec<u16> = COMMAND_LINE.encode_utf16().collect();
        let text = block + 0x800;
        guest::write_bytes(text, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
        let bytes = units.len() as u16 * 2;
        // RTL_USER_PROCESS_PARAMETERS.CommandLine (+0x70), normalizado.
        guest::write16(block + 0x70, bytes);
        guest::write16(block + 0x72, bytes + 2);
        guest::write64(block + 0x78, text);
        guest::write64(test.peb + 0x20, block);
        let full = query(test.process, 0x200);
        assert(full.0 == 0 && full.2 == bytes && full.3 == bytes + 2 && full.1 == bytes as u32 + 2 + 0x10 && full.4 == 1 && full.5 == COMMAND_LINE, "consulta: PsQueryProcessCommandLine devolve a linha de comando do processo, com o buffer logo depois do UNICODE_STRING");
        let small = query(test.process, 0x10);
        assert(small.0 == STATUS_INFO_LENGTH_MISMATCH && small.1 == full.1, "consulta: buffer pequeno = STATUS_INFO_LENGTH_MISMATCH com o tamanho necessario");
        guest::write16(block + 0x70, bytes + 1);
        assert(query(test.process, 0x200).0 == STATUS_NOT_FOUND, "consulta: Length impar = STATUS_NOT_FOUND");
        if let Some(region) = memory::find_region(block) {
            memory::release_private_region(&region);
        }
        true
    });
    assert(ran == Some(true), "consulta: processo de teste com parametros normalizados");
    let system = query(process::get_system_process(), 0x200);
    assert(system.0 == STATUS_NOT_FOUND, "consulta: processo sem PEB = STATUS_NOT_FOUND");
}

pub fn run(assert: Assert) {
    normalized_parameters(assert);
    let mut parameters = ProcessParameters::for_image(IMAGE_PATH);
    parameters.command_line = String::from(COMMAND_LINE);
    let request = CreateProcessRequest { image: ImageOrigin::Bytes(program()), image_name: IMAGE_NAME, parameters, parent: None, thread_flags: THREAD_CREATE_SUSPENDED, inherit_handles_from: None, on_created: None };
    let created = match create::create_user_process(&request) {
        Ok(created) => created,
        Err(failure) => {
            crate::debug_print!("[consulta] {} nao criado: {}", IMAGE_NAME, failure);
            assert(false, "consulta: processo criado pelo caminho unico");
            return;
        }
    };
    let process_pointer = created.process_pointer;
    process::reference(process_pointer);
    let denormalized = query(process_pointer, 0x200);
    assert((denormalized.0 as i32) < 0 && denormalized.1 != 0, "consulta: parametros ainda auto-relativos (antes da ntdll) = a falha da copia do deslocamento");
    let suspended = |thread: u64| threads::find_by_pointer(thread).map(|thread| thread.with(|thread| thread.suspend_count));
    let before = suspended(created.thread_pointer);
    let resumed = call_export("PsResumeProcess", &[process_pointer]).map(|status| status as u32);
    let after = suspended(created.thread_pointer);
    assert(before == Some(1) && resumed == Some(0) && after == Some(0), "consulta: PsResumeProcess tira a suspensao da thread principal");
    let exit = user_process::run_created(created);
    assert(matches!(exit, Ok(EXIT_CODE)), "consulta: o processo retomado roda e sai com o codigo");
    let late_query = query(process_pointer, 0x200).0;
    let late_resume = call_export("PsResumeProcess", &[process_pointer]).map(|status| status as u32);
    assert(late_query == STATUS_PROCESS_IS_TERMINATING && late_resume == Some(STATUS_PROCESS_IS_TERMINATING), "consulta: depois do fim os dois devolvem STATUS_PROCESS_IS_TERMINATING");
    let _ = process::dereference(process_pointer);
}
