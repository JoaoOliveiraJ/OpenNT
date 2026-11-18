//! Diagnóstico: os serviços gráficos da tabela do win32k que devolvem
//! NTSTATUS e falharam.
//!
//! Os serviços do D3DKMT (NtGdiDdDDI*, NtDxgk*), da DirectComposition
//! (NtDComposition*), das superfícies de composição (*CompositionSurface*),
//! do gerenciador de tokens (NtTokenManager*), dos flip objects
//! (NtFlipObject*) e da configuração de vídeo (NtUser*DisplayConfig*) vão
//! do stub do win32u.dll direto à rotina do win32k, que chama o dxgkrnl;
//! ficam fora do registro de serviços nativos, então a
//! linha FALHOU de `index` não os vê, e uma falha do dxgkrnl, do dxgmms2 ou
//! do BasicRender só aparecia como o HRESULT final do processo.
//!
//! Uma falha (bit 31 do NTSTATUS) imprime
//! `[win32k] pid:tid Nome FALHOU com status (chamador módulo+deslocamento)`.
//! O chamador é o endereço de retorno do stub (`[rsp]` na entrada), com o
//! módulo pela lista InLoadOrder do PEB_LDR_DATA. Os nomes saem dos stubs do
//! win32u.dll do primeiro processo que falha (`mov r10, rcx; mov eax,
//! número`), uma vez: o número de cada serviço é o mesmo em todo processo.
//! Cada par (serviço, status) imprime as quatro primeiras vezes e depois uma
//! a cada 256, com a contagem. Só diagnóstico: o resultado volta ao modo
//! usuário como veio.
//!
//! Os serviços do redirecionamento que devolvem BOOL (`BOOL_SERVICES`) não
//! têm o bit 31 numa falha: um FALSE deles sai como `FALHOU com FALSE`. Para
//! isso, todo serviço da tabela do win32k que volta zero consulta a tabela de
//! nomes (uma busca no BTreeMap, sem cópia do nome).

use alloc::collections::BTreeMap;
use alloc::string::String;

use crate::ntos::inc::types::{Eprocess, ImageDosHeader, ImageExportDirectory, ImageNtHeaders64, LdrDataTableEntry, ListEntry, Peb, PebLdrData};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::process;
use crate::ntos::ps::user::state;
use crate::rtl::SpinLock;

/// Os prefixos dos serviços do win32u.dll que devolvem NTSTATUS e chegam ao
/// dxgkrnl ou à composição do win32k.
const PREFIXES: [&str; 5] = ["NtGdiDdDDI", "NtDxgk", "NtDComposition", "NtTokenManager", "NtFlipObject"];

/// Os serviços do redirecionamento do DWM que devolvem BOOL (win32kfull
/// 19041): o NtUserDwmKernelStartup (0x135da0, TRUE só quando o
/// zzzDwmStartRedirection dá certo), o NtUserSignalRedirectionStartComplete
/// (0x135a50, o NT_SUCCESS do ZwSetEvent dele), o NtGdiHLSurfGetInformation
/// (0xbc5c0) e o NtGdiHLSurfSetInformation (0x14d90). Um FALSE é a falha.
const BOOL_SERVICES: [&str; 4] = ["NtUserDwmKernelStartup", "NtUserSignalRedirectionStartComplete", "NtGdiHLSurfGetInformation", "NtGdiHLSurfSetInformation"];

/// Número do serviço -> nome; `None` até a primeira falha (ou o primeiro
/// zero) de um serviço da tabela do win32k num processo com o win32u.dll.
static NAMES: SpinLock<Option<BTreeMap<u32, String>>> = SpinLock::new(None);
/// (número, status) -> quantas vezes falhou.
static FAILURES: SpinLock<BTreeMap<(u32, u32), u32>> = SpinLock::new(BTreeMap::new());

/// O nome entra na lista dos serviços acompanhados: os prefixos, as
/// superfícies de composição, os serviços da configuração de vídeo
/// (NtUser*DisplayConfig*, o QueryDisplayConfig/DisplayConfigGetDeviceInfo
/// do dxgi, do dwmcore e do uDWM; a user32 converte o NTSTATUS deles com o
/// RtlNtStatusToDosError) e os serviços BOOL do redirecionamento.
pub fn watched(name: &str) -> bool {
    PREFIXES.iter().any(|prefix| name.starts_with(prefix)) || name.contains("CompositionSurface") || (name.starts_with("NtUser") && name.contains("DisplayConfig")) || returns_bool(name)
}

/// O serviço devolve BOOL (um dos `BOOL_SERVICES`).
pub fn returns_bool(name: &str) -> bool {
    BOOL_SERVICES.contains(&name)
}

/// A ocorrência `count` (a partir de 1) de um par (serviço, status) sai no
/// log: as quatro primeiras e depois uma a cada 256.
pub fn printed(count: u32) -> bool {
    count <= 4 || count % 256 == 0
}

/// Um serviço da tabela do win32k (número com o bit 0x1000) voltou com
/// `result`; `entry_rsp` é o RSP de usuário na entrada do syscall. Falha é
/// o bit 31 do NTSTATUS, ou o zero (FALSE) de um serviço BOOL.
pub fn returned(number: u32, result: u64, entry_rsp: u64) {
    let status = result as u32;
    let failed = if status & 0x8000_0000 != 0 {
        true
    } else if status == 0 {
        with_name(number, returns_bool).unwrap_or(false)
    } else {
        false
    };
    if !failed {
        return;
    }
    let Some(name) = name_of(number) else { return };
    let count = {
        let mut failures = FAILURES.lock();
        let entry = failures.entry((number, status)).or_insert(0);
        *entry = entry.saturating_add(1);
        *entry
    };
    if !printed(count) {
        return;
    }
    let caller = return_address(entry_rsp);
    let place = describe(caller);
    let repeated = if count > 4 { alloc::format!(" ({count} vezes)") } else { String::new() };
    let outcome = if status == 0 { String::from("FALSE") } else { alloc::format!("{status:#x}") };
    crate::debug_print!("[win32k] {}:{} {} FALHOU com {} (chamador {}){}", process::get_current_process_id(), process::get_current_thread_id(), name, outcome, place, repeated);
}

/// O nome de um serviço acompanhado; monta a tabela na primeira consulta.
fn name_of(number: u32) -> Option<String> {
    with_name(number, |name| String::from(name))
}

/// `inspect` sobre o nome de um serviço acompanhado, sem copiá-lo; monta a
/// tabela na primeira consulta.
fn with_name<R>(number: u32, inspect: impl FnOnce(&str) -> R) -> Option<R> {
    {
        let names = NAMES.lock();
        if let Some(names) = names.as_ref() {
            return names.get(&number).map(|name| inspect(name.as_str()));
        }
    }
    let built = build_names()?;
    let result = built.get(&number).map(|name| inspect(name.as_str()));
    let mut names = NAMES.lock();
    if names.is_none() {
        *names = Some(built);
    }
    result
}

/// Os serviços acompanhados do win32u.dll do processo corrente, pelo número
/// do stub de cada export.
fn build_names() -> Option<BTreeMap<u32, String>> {
    let (base, _) = modules().into_iter().find(|(_, (_, name))| name.eq_ignore_ascii_case("win32u.dll")).map(|(base, (size, _))| (base, size))?;
    let nt = base + state::user_struct::<ImageDosHeader>(base).and_then(|dos| dos.e_lfanew.probe_get()).ok()? as u64;
    let directory = state::user_struct::<ImageNtHeaders64>(nt).and_then(|headers| headers.optional_header.data_directory[0].virtual_address.probe_get()).ok()? as u64;
    let exports = state::user_struct::<ImageExportDirectory>(base + directory).ok()?;
    let (count, functions, names, ordinals) = (exports.number_of_names.probe_get().ok()?, exports.address_of_functions.probe_get().ok()? as u64, exports.address_of_names.probe_get().ok()? as u64, exports.address_of_name_ordinals.probe_get().ok()? as u64);
    let mut table = BTreeMap::new();
    for index in 0..count.min(0x4000) as u64 {
        let Ok(name_rva) = guest::try_read::<u32>(base + names + index * 4) else { continue };
        let Some(name) = read_ascii(base + name_rva as u64) else { continue };
        if !watched(&name) {
            continue;
        }
        let Ok(ordinal) = guest::try_read::<u16>(base + ordinals + index * 2) else { continue };
        let Ok(stub_rva) = guest::try_read::<u32>(base + functions + ordinal as u64 * 4) else { continue };
        let stub = base + stub_rva as u64;
        if !state::probe_user_read(stub, 8) {
            continue;
        }
        let Ok(code) = guest::try_read_bytes(stub, 8) else { continue };
        if code[..4] == [0x4C, 0x8B, 0xD1, 0xB8] {
            table.insert(u32::from_le_bytes([code[4], code[5], code[6], code[7]]), name);
        }
    }
    Some(table)
}

/// Um nome ASCII de export (até 96 caracteres) em memória de usuário, lido
/// por pedaços que não cruzam página (uma sonda por pedaço).
fn read_ascii(address: u64) -> Option<String> {
    let mut text = String::new();
    let mut cursor = address;
    while cursor - address < 96 {
        let chunk = (0x1000 - (cursor & 0xFFF)).min(96 - (cursor - address));
        if !state::probe_user_read(cursor, chunk) {
            return None;
        }
        let bytes = guest::try_read_bytes(cursor, chunk as usize).ok()?;
        if let Some(end) = bytes.iter().position(|&byte| byte == 0) {
            text.extend(bytes[..end].iter().map(|&byte| byte as char));
            return Some(text);
        }
        text.extend(bytes.iter().map(|&byte| byte as char));
        cursor += chunk;
    }
    None
}

/// O endereço de retorno do stub: `[rsp]` na entrada do syscall.
fn return_address(entry_rsp: u64) -> u64 {
    if entry_rsp == 0 || !state::probe_user_read(entry_rsp, 8) {
        return 0;
    }
    guest::try_read::<u64>(entry_rsp).unwrap_or(0)
}

/// `módulo+deslocamento` de um endereço de usuário, ou o endereço cru.
fn describe(address: u64) -> String {
    for (base, (size, name)) in modules() {
        if address >= base && address < base + size {
            return alloc::format!("{name}+{:#x}", address - base);
        }
    }
    alloc::format!("{address:#x}")
}

/// Os módulos do processo corrente pela lista InLoadOrder do PEB_LDR_DATA:
/// base -> (tamanho, nome).
fn modules() -> BTreeMap<u64, (u64, String)> {
    let mut found = BTreeMap::new();
    // SAFETY: o EPROCESS corrente.
    let peb = unsafe { Eprocess::at(process::get_current_process()) }.peb.get();
    let Ok(ldr) = state::user_struct::<Peb>(peb).and_then(|peb| peb.ldr.probe_get()) else { return found };
    let links = core::mem::offset_of!(LdrDataTableEntry, in_load_order_links) as u64;
    let head = ldr + core::mem::offset_of!(PebLdrData, in_load_order_module_list) as u64;
    let Ok(mut link) = state::user_struct::<ListEntry>(head).and_then(|head| head.flink.probe_get()) else { return found };
    for _ in 0..512 {
        if link == 0 || link == head {
            break;
        }
        let Ok(entry) = state::user_struct::<LdrDataTableEntry>(link - links) else { break };
        let (Ok(base), Ok(size), Ok(length), Ok(buffer)) = (entry.dll_base.probe_get(), entry.size_of_image.probe_get(), entry.base_dll_name.length.probe_get(), entry.base_dll_name.buffer.probe_get()) else { break };
        let name = state::try_read_user_wide_string(buffer, (length as u64 / 2).min(64)).unwrap_or_default();
        found.insert(base, (size as u64, name));
        let Ok(next) = state::user_struct::<ListEntry>(link).and_then(|link| link.flink.probe_get()) else { break };
        link = next;
    }
    found
}
