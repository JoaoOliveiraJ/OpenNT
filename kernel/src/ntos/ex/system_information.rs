//! Informações do sistema em modo kernel: Zw/NtQuerySystemInformation e
//! ZwSetSystemInformation.
//!
//! A consulta despacha cada classe para a folha dona (boot, Code Integrity,
//! Secure Boot, módulos, processadores, processos); a alteração aceita a
//! classe 131, que registra as rotinas de entropia que o RNG do kernel chama
//! ao coletar/resemear entropia.

use alloc::vec::Vec;

use crate::ntos::ex::boot_environment_information;
use crate::ntos::ke::processor_information;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::module_queries;
use crate::ntos::ps::system_process_information;
use crate::ntos::se::{code_integrity_information, secure_boot_information};
use crate::rtl::{KernelError, SpinLock};

/// Rotinas de entropia registradas por ZwSetSystemInformation(131): o RNG
/// do kernel as chama ao coletar/resemear entropia.
#[derive(Clone, Copy, Debug)]
pub struct EntropyRegistration {
    pub entropy_routine: u64,
    pub initialization_routine: u64,
    pub initialization_context: u64,
}

static ENTROPY_TIMING_REGISTRATIONS: SpinLock<Vec<EntropyRegistration>> = SpinLock::new(Vec::new());

/// Buffer da classe 131 (registro de entropia por tempo de interrupção).
#[repr(C)]
struct EntropyTimingInformation {
    entropy_routine: Field<u64>,
    initialization_routine: Field<u64>,
    initialization_context: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for EntropyTimingInformation {}

const _: () = assert!(core::mem::size_of::<EntropyTimingInformation>() == 24);

pub fn entropy_registrations() -> Vec<EntropyRegistration> {
    ENTROPY_TIMING_REGISTRATIONS.lock().clone()
}

/// SYSTEM_INFORMATION_CLASS das classes de tamanho fixo de `query_fixed`.
pub const SYSTEM_FLAGS_INFORMATION: u32 = 9;
pub const SYSTEM_KERNEL_DEBUGGER_INFORMATION: u32 = 35;
pub const SYSTEM_PHYSICAL_MEMORY_INFORMATION: u32 = 184;
pub const SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION: u32 = 197;

/// A classe é uma das de `query_fixed` com o buffer sondado com alinhamento
/// 4 (a SystemKernelDebuggerInformation sonda com alinhamento 1).
pub fn is_fixed_class(class: u32) -> bool {
    matches!(class, SYSTEM_FLAGS_INFORMATION | SYSTEM_PHYSICAL_MEMORY_INFORMATION | SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION)
}

/// Classes de tamanho fixo do ExpQuerySystemInformation 19041, com o buffer
/// já sondado (alinhamento 4) quando o chamador é de modo usuário. Devolve
/// (NTSTATUS, ReturnLength); o ReturnLength vale também na recusa de
/// tamanho. `None` para as classes que não são daqui.
///
/// - SystemFlagsInformation (9, rva 0x6cad8e): exatamente 4 bytes, o
///   NtGlobalFlag.
/// - SystemPhysicalMemoryInformation (184, rva 0x6ca3d3): exatamente 0x18
///   bytes: o total de RAM (MmGetNumberOfPhysicalPages << 12), o endereço do
///   menor frame (MmGetLowestPhysicalPage << 12) e o último byte do maior
///   (MmGetHighestPhysicalPage << 12 | 0xFFF).
/// - SystemKernelDebuggerInformation (35, rva 0x6cb336): pelo menos 2
///   bytes, o KdDebuggerEnabled e o KdDebuggerNotPresent
///   (SYSTEM_KERNEL_DEBUGGER_INFORMATION).
/// - SystemHypervisorSharedPageInformation (197, rva 0x6cced4): pelo menos
///   8 bytes, o endereço de usuário da página compartilhada do hypervisor
///   (MiState): a página de referência do QPC que a KUSER_SHARED_DATA
///   anuncia (o `shared_user_data` do Mm).
pub fn query_fixed(class: u32, output: u64, length: u32) -> Option<Result<(u32, u32), KernelError>> {
    // (tamanho, exato, dados)
    let (required, exact, data) = match class {
        SYSTEM_FLAGS_INFORMATION => (4, true, crate::ntos::rtl::shared_data::nt_global_flag().to_le_bytes().to_vec()),
        SYSTEM_PHYSICAL_MEMORY_INFORMATION => {
            let (lowest, highest) = crate::ntos::mm::pfn::physical_page_bounds();
            let mut data = Vec::with_capacity(0x18);
            data.extend_from_slice(&(crate::ntos::mm::pfn::total_count() << 12).to_le_bytes());
            data.extend_from_slice(&(lowest << 12).to_le_bytes());
            data.extend_from_slice(&((highest << 12) + 0xFFF).to_le_bytes());
            (0x18, true, data)
        }
        SYSTEM_KERNEL_DEBUGGER_INFORMATION => (2, false, alloc::vec![crate::ntos::kd::debugger::enabled() as u8, crate::ntos::kd::debugger::debugger_not_present() as u8]),
        SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION => (8, false, crate::ntos::mm::shared_user_data::hypervisor_shared_user_va().to_le_bytes().to_vec()),
        _ => return None,
    };
    let fits = if exact { length == required } else { length >= required };
    if !fits {
        return Some(Ok((STATUS_INFO_LENGTH_MISMATCH, required)));
    }
    Some(guest::try_write_bytes(output, &data).map(|()| (0, required)))
}

/// ZwQuerySystemInformation/NtQuerySystemInformation (o mesmo corpo).
pub fn query(class: u32, output: u64, length: u32, returned: u64) -> Result<u32, KernelError> {
    debug_print!("[zw] QuerySystemInformation classe {} buf={}", class, length);
    if let Some(result) = query_fixed(class, output, length) {
        let (status, required) = result?;
        if returned != 0 {
            // SAFETY: o PULONG ReturnLength do chamador de modo kernel.
            unsafe { Field::<u32>::at(returned) }.set(required);
        }
        return Ok(status);
    }
    match class {
        90 => return boot_environment_information::query(output, length as u64, returned, false),
        103 => return code_integrity_information::query(output, length as u64, returned, false),
        143 => return secure_boot_information::query(output, length as u64, returned, false),
        157 => return crate::ntos::ex::manufacturing_information::query(output, length as u64, returned, false),
        3 => return crate::ntos::ex::time_of_day_information::query(output, length as u64, returned, false),
        44 | 102 => return Ok(crate::ntos::ex::time_zone::query(class, output, length as u64, returned, false)),
        124 => return Ok(crate::ntos::ex::time_of_day_information::query_counter_class(output, length as u64, returned, false)),
        11 | 77 => return module_queries::query_system_modules(class, output, length as u64, returned),
        1 | 63 => return Ok(processor_information::query(output, length, returned, false, class == 63)),
        // SystemProcessorFeaturesInformation.
        154 => return Ok(processor_information::query_features(output, length, returned, false)),
        // SystemLogicalProcessorInformation: o KeBuildLogicalProcessorSystemInformation
        // do grupo da thread (o 0).
        73 => {
            let (status, required) = crate::ntos::ke::processor_topology::build_logical_processor_information(0, output, length, &mut |address, bytes| {
                guest::write_bytes(address, bytes);
                true
            });
            if returned != 0 {
                // SAFETY: o PULONG ReturnLength do chamador (modo kernel).
                unsafe { Field::<u32>::at(returned) }.set(required);
            }
            return Ok(status);
        }
        // SystemCodeIntegrityCertificateManagementInformation: nenhuma
        // operação de certificados pendente (o cng percorre e segue).
        117 => {
            guest::write_bytes(output, &alloc::vec![0u8; length as usize]);
            if returned != 0 {
                // SAFETY: o PULONG ReturnLength do chamador (modo kernel).
                unsafe { Field::<u32>::at(returned) }.set(length);
            }
            return Ok(0);
        }
        // SystemBootGraphicsInformation: a tela de boot (Bgk).
        126 => return crate::ntos::bgk::graphics_information::query_system_information(output, length, returned),
        // SystemBasicInformation e as variantes Emulation/NativeBasic x64.
        0 | 62 | 114 => return Ok(basic_information(output, length, returned)),
        // SystemPerformanceInformation e SystemPageFileInformation(Ex):
        // `mm/memory_information`.
        2 | 18 | 144 => return query_memory_information(class, output, length, returned),
        5 => {}
        _ => return Ok(0xC000_000D),
    }
    system_process_information::query(output, length as u64, returned, false)
}

/// SYSTEM_BASIC_INFORMATION para um chamador de modo kernel, com os valores
/// da consulta de modo usuário (`ps/user/syscalls_core.rs`): resolução do
/// timer de 15,625 ms, páginas de 4 KB, a memória física, a granularidade de
/// alocação, a faixa de endereços de usuário e os processadores ativos.
/// Buffer menor que a estrutura: STATUS_INFO_LENGTH_MISMATCH com o tamanho
/// em ReturnLength.
fn basic_information(output: u64, length: u32, returned: u64) -> u32 {
    use crate::ntos::inc::types::SystemBasicInformation;
    use crate::ntos::mm::memory_map;
    let size = SystemBasicInformation::SIZE as u32;
    if returned != 0 {
        // SAFETY: o PULONG ReturnLength do chamador (modo kernel).
        unsafe { Field::<u32>::at(returned) }.set(size);
    }
    if length < size {
        return 0xC000_0004;
    }
    let pages = crate::hal::kmalloc::ram_top() / 0x1000;
    let processors = crate::ntos::ke::smp::online_cpu_count();
    guest::write_bytes(output, &[0u8; SystemBasicInformation::SIZE as usize]);
    // SAFETY: o buffer de saída do chamador, com o tamanho da estrutura.
    let basic = unsafe { SystemBasicInformation::at(output) };
    basic.timer_resolution.set(156_250);
    basic.page_size.set(0x1000);
    basic.number_of_physical_pages.set(pages as u32);
    basic.highest_physical_page_number.set((pages - 1) as u32);
    basic.allocation_granularity.set(memory_map::ALLOCATION_GRANULARITY as u32);
    basic.minimum_user_mode_address.set(memory_map::LOWEST_USER_ADDRESS);
    basic.maximum_user_mode_address.set(memory_map::HIGHEST_USER_ADDRESS);
    basic.active_processors_affinity_mask.set((1u64 << processors) - 1);
    basic.number_of_processors.set(processors as i8);
    0
}

/// As classes de memória do Mm, de modo kernel.
fn query_memory_information(class: u32, output: u64, length: u32, returned: u64) -> Result<u32, KernelError> {
    use crate::ntos::mm::memory_information;
    let set_returned = |value: u32| {
        if returned != 0 {
            // SAFETY: o PULONG ReturnLength do chamador (modo kernel).
            unsafe { Field::<u32>::at(returned) }.set(value);
        }
    };
    if class != 2 {
        let entry = memory_information::page_file_entry_size(class == 144);
        if length < entry {
            set_returned(entry);
            return Ok(memory_information::STATUS_INFO_LENGTH_MISMATCH);
        }
    }
    let (status, size) = if class == 2 { memory_information::performance_information(output, length)? } else { memory_information::page_file_information(output, length, class == 144)? };
    set_returned(size);
    Ok(status)
}

// ---- NtQuerySystemInformationEx / ZwQuerySystemInformationEx (modo kernel) --
//
// O NtQuerySystemInformationEx do 19041 recusa entrada nula ou de tamanho 0
// (STATUS_INVALID_PARAMETER) e aceita só as classes que têm entrada (o resto
// é STATUS_INVALID_INFO_CLASS); com PreviousMode UserMode sonda a entrada
// com o alinhamento da classe. O ExpQuerySystemInformation lê a entrada da
// classe e despacha; o ReturnLength recebe o tamanho que a folha deixou na
// célula local (zerada no começo), inclusive nas falhas da folha.

const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// SystemLogicalProcessorAndGroupInformation: entrada LOGICAL_PROCESSOR_RELATIONSHIP.
const SYSTEM_LOGICAL_PROCESSOR_AND_GROUP_INFORMATION: u32 = 107;
/// SystemNodeDistanceInformation: entrada USHORT do nó.
const SYSTEM_NODE_DISTANCE_INFORMATION: u32 = 121;
/// SystemInterruptSteeringInformation: SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT.
const SYSTEM_INTERRUPT_STEERING_INFORMATION: u32 = 180;
/// Classes que o NtQuerySystemInformationEx aceita (as com entrada).
const EX_CLASSES: [u32; 21] = [8, 23, 42, 61, 72, 73, 83, 100, 107, 108, 121, 141, 160, 165, 175, 178, 180, 181, 209, 210, 211];

/// SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT (ntexapi): Gsiv, os três
/// BOOLEANs e o GROUP_AFFINITY alvo.
#[repr(C)]
struct InterruptSteeringInput {
    gsiv: Field<u32>,
    controller_interrupt: Field<u8>,
    edge_interrupt: Field<u8>,
    is_primary_interrupt: Field<u8>,
    _pad_07: crate::ntos::inc::field::Reserved<1>,
    target_affinity: crate::ntos::inc::types::GroupAffinity,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for InterruptSteeringInput {}

const _: () = assert!(core::mem::size_of::<InterruptSteeringInput>() == 0x18);

/// NtQuerySystemInformationEx/ZwQuerySystemInformationEx chamados por um
/// driver (PreviousMode KernelMode: entrada e saída sem sonda).
pub fn query_ex(class: u32, input: u64, input_length: u32, output: u64, length: u32, returned: u64) -> Result<u32, KernelError> {
    debug_print!("[zw] QuerySystemInformationEx classe {} entrada={} buf={}", class, input_length, length);
    if input == 0 || input_length == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if !EX_CLASSES.contains(&class) {
        return Ok(STATUS_INVALID_INFO_CLASS);
    }
    // A célula de tamanho do ExpQuerySystemInformation.
    let mut reported = 0u32;
    let status = match class {
        SYSTEM_LOGICAL_PROCESSOR_AND_GROUP_INFORMATION => {
            if input_length < 4 {
                return Ok(STATUS_INVALID_PARAMETER);
            }
            // SAFETY: entrada de modo kernel com 4 bytes conferidos.
            let relationship = unsafe { Field::<u32>::at(input) }.get();
            let cell = guest::alloc_bytes(4);
            if cell == 0 {
                return Ok(crate::ntos::inc::status::STATUS_INSUFFICIENT_RESOURCES);
            }
            // SAFETY: a célula ULONG recém-alocada.
            let length_cell = unsafe { Field::<u32>::at(cell) };
            length_cell.set(length);
            let status = crate::ntos::ke::processor_topology::query_logical_processor_relationship(None, relationship, output, cell);
            reported = length_cell.get();
            guest::free_bytes(cell);
            status?
        }
        SYSTEM_NODE_DISTANCE_INFORMATION => {
            use crate::ntos::ke::processor_group;
            if input_length < 2 {
                return Ok(STATUS_INVALID_PARAMETER);
            }
            // SAFETY: entrada de modo kernel com 2 bytes conferidos.
            let node = unsafe { Field::<u16>::at(input) }.get();
            let nodes = processor_group::number_nodes();
            if node >= nodes {
                return Ok(STATUS_INVALID_PARAMETER);
            }
            reported = nodes as u32 * 4;
            if length < reported {
                STATUS_INFO_LENGTH_MISMATCH
            } else {
                // KeNodeDistance[node * KeNumberNodes + destino], um ULONG por destino.
                for destination in 0..nodes {
                    let distance = processor_group::node_distance(node, destination).unwrap_or(0);
                    // SAFETY: saída de modo kernel com KeNumberNodes ULONGs conferidos.
                    unsafe { Field::<u32>::at(output + destination as u64 * 4) }.set(distance);
                }
                0
            }
        }
        SYSTEM_INTERRUPT_STEERING_INFORMATION => query_interrupt_steering(input, input_length, output, length, &mut reported),
        _ => {
            debug_print!("[zw] QuerySystemInformationEx classe {} (sem suporte)", class);
            return Ok(STATUS_INVALID_INFO_CLASS);
        }
    };
    if returned != 0 {
        // SAFETY: o PULONG ReturnLength do chamador (modo kernel).
        unsafe { Field::<u32>::at(returned) }.set(reported);
    }
    Ok(status)
}

/// ExpQueryInterruptSteeringInformation em modo kernel (em UserMode o NT
/// devolve STATUS_ACCESS_DENIED): entrada de exatamente 0x18 bytes e saída
/// de um ULONG, senão STATUS_INFO_LENGTH_MISMATCH (o tamanho 4 só vai ao
/// ReturnLength quando falta saída). A saída zera e liga o bit Enabled: para
/// a interrupção do próprio controlador (ControllerInterrupt com Gsiv -1),
/// se o steering está ligado; para outra, se ela tem modo de steering. No
/// sucesso o ReturnLength fica 0, como no NT.
fn query_interrupt_steering(input: u64, input_length: u32, output: u64, length: u32, reported: &mut u32) -> u32 {
    use crate::ntos::ke::interrupt_object;
    if input_length != 0x18 {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    // SAFETY: entrada de modo kernel com 0x18 bytes conferidos.
    let request = unsafe { InterruptSteeringInput::at(input) };
    let gsiv = request.gsiv.get();
    if length < 4 {
        *reported = 4;
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    // SAFETY: saída de modo kernel com um ULONG conferido.
    let enabled = unsafe { Field::<u32>::at(output) };
    enabled.set(0);
    let on = if request.controller_interrupt.get() != 0 && gsiv == u32::MAX {
        interrupt_object::interrupt_steering_enabled()
    } else {
        interrupt_object::interrupt_steering_mode(gsiv, request.edge_interrupt.get() != 0, request.is_primary_interrupt.get() != 0, &request.target_affinity) != 0
    };
    if on {
        enabled.set(1);
    }
    0
}

/// ZwSetSystemInformation: 131 registra as rotinas de entropia do chamador,
/// 82 troca a base de uma thread pelo CLIENT_ID; classes desconhecidas =
/// STATUS_INVALID_INFO_CLASS.
pub fn set(class: u32, buffer: u64, length: u32) -> u32 {
    let status_of = |error: KernelError| if error.status != 0 { error.status } else { 0xC000_0001 };
    match class {
        44 | 102 => return crate::ntos::ex::time_zone::set(class, buffer, length, false),
        SYSTEM_EXTEND_SERVICE_TABLE_INFORMATION => return extend_service_table(buffer, length).unwrap_or_else(status_of),
        SYSTEM_LOAD_GDI_DRIVER_INFORMATION => return load_gdi_driver(buffer, length, true).unwrap_or_else(status_of),
        SYSTEM_LOAD_GDI_DRIVER_IN_SYSTEM_SPACE => return load_gdi_driver(buffer, length, false).unwrap_or_else(status_of),
        SYSTEM_UNLOAD_GDI_DRIVER_INFORMATION => return unload_gdi_driver(buffer, length).unwrap_or_else(status_of),
        SYSTEM_THREAD_PRIORITY_CLIENT_ID_INFORMATION => return thread_priority_client_id(buffer, length, 0).unwrap_or_else(status_of),
        _ => {}
    }
    if class == 131 {
        if (length as u64) < EntropyTimingInformation::SIZE {
            return 0xC000_0004;
        }
        let count = {
            let mut registrations = ENTROPY_TIMING_REGISTRATIONS.lock();
            // SAFETY: buffer de entrada do chamador (modo kernel), tamanho conferido.
            let information = unsafe { EntropyTimingInformation::at(buffer) };
            registrations.push(EntropyRegistration { entropy_routine: information.entropy_routine.get(), initialization_routine: information.initialization_routine.get(), initialization_context: information.initialization_context.get() });
            registrations.len()
        };
        debug_print!("[zw] entropia: rotinas registradas ({} provedor(es))", count);
        return 0;
    }
    debug_print!("[zw] ZwSetSystemInformation classe {} (sem suporte)", class);
    0xC000_0003
}

// ---- SystemExtendServiceTableInformation (38): a carga do win32k.sys ------
//
// (append de `ke-service-tables` ao ex/system_information.rs. Usa o `Field`,
// o `NtStruct` e o `guest` já importados pelo arquivo, sem linhas `use` novas.)
//
// NtSetSystemInformation(38) no ntoskrnl 19041 (modo kernel): a entrada é uma
// UNICODE_STRING (Length != 0x10 -> STATUS_INFO_LENGTH_MISMATCH). Para
// "\SystemRoot\System32\win32k.sys" o LoadFlags é 0x80000005 (sessão +
// compactação das tabelas de serviço, `mm::sysload`); para outra imagem, só
// sessão. IMAGE_ALREADY_LOADED_AS_DLL vira IMAGE_ALREADY_LOADED; sem cabeçalho
// NT, descarrega e devolve INVALID_IMAGE_FORMAT; depois o
// ExpInitializeSessionDriver chama o ponto de entrada com um DRIVER_OBJECT
// zerado de 0x150 bytes (só o DriverStart = base) e RegistryPath NULL, e uma
// falha descarrega a imagem. O MmSessionSetUnloadAddress do sucesso guarda o
// DriverUnload na sessão corrente (MM_SESSION_SPACE.DriverUnload, 1 sem
// rotina): é ele que libera os callouts Win32 da sessão
// (MmSessionGetWin32Callouts) e o MmGetSessionById.

/// SYSTEM_INFORMATION_CLASS SystemExtendServiceTableInformation.
pub const SYSTEM_EXTEND_SERVICE_TABLE_INFORMATION: u32 = 38;
const EXTEND_SERVICE_TABLE_WIN32K: &str = "\\SystemRoot\\System32\\win32k.sys";
/// LoadFlags do win32k.sys e das demais imagens.
const EXTEND_SERVICE_TABLE_WIN32K_FLAGS: u32 = 0x8000_0005;
const EXTEND_SERVICE_TABLE_SESSION_FLAGS: u32 = 1;
const EXTEND_STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const EXTEND_STATUS_INVALID_IMAGE_FORMAT: u32 = 0xC000_007B;
const EXTEND_STATUS_IMAGE_ALREADY_LOADED: u32 = 0xC000_010E;
const EXTEND_STATUS_IMAGE_ALREADY_LOADED_AS_DLL: u32 = 0xC000_019D;

/// ExpInitializeSessionDriver(EntryPoint, ImageBase): o NTSTATUS do ponto de
/// entrada.
fn initialize_session_driver(entry_point: u64, image_base: u64) -> u32 {
    use crate::ntos::inc::types::DriverObject;
    let address = guest::alloc_bytes(DriverObject::SIZE);
    if address == 0 {
        return crate::ntos::inc::status::STATUS_INSUFFICIENT_RESOURCES;
    }
    guest::write_bytes(address, &alloc::vec![0u8; DriverObject::SIZE as usize]);
    // SAFETY: DRIVER_OBJECT recém-alocado e zerado.
    unsafe { DriverObject::at(address) }.driver_start.set(image_base);
    let status = crate::hal::amd64::native_call::call(entry_point, &[address, 0]) as u32;
    if status & 0x8000_0000 == 0 {
        crate::ntos::mm::session::set_unload_address(address);
    }
    guest::free_bytes(address);
    status
}

// ---- Os drivers do GDI: classes 26, 27 e 54 --------------------------------
//
// ntoskrnl 19041 (NtSetSystemInformation 0x708300 e 0x707e50), só de modo
// kernel (de modo usuário, STATUS_PRIVILEGE_NOT_HELD):
// - SystemLoadGdiDriverInformation (26) e SystemLoadGdiDriverInSystemSpace
//   (54): SYSTEM_GDI_DRIVER_INFORMATION de 0x38 bytes (senão
//   STATUS_INFO_LENGTH_MISMATCH); MmLoadSystemImage(DriverName, NULL, NULL,
//   LoadFlags) com MM_LOAD_IMAGE_IN_SESSION na 26 e 0 na 54 (o hidparse.sys
//   que o win32k carrega antes do win32kfull.sys). Sem chamar ponto de
//   entrada nenhum, a saída leva ImageAddress (a base), SectionPointer (o
//   ImageHandle), EntryPoint (base + AddressOfEntryPoint),
//   ExportSectionPointer (o diretório de exports mapeado) e ImageLength
//   (SizeOfImage). Uma falha não preenche nada;
//   IMAGE_ALREADY_LOADED_AS_DLL vira IMAGE_ALREADY_LOADED.
// - SystemUnloadGdiDriverInformation (27): um PVOID (senão
//   STATUS_INFO_LENGTH_MISMATCH), o ImageHandle que o MmUnloadSystemImage
//   solta; sempre sucesso.

/// SYSTEM_INFORMATION_CLASS dos drivers do GDI.
pub const SYSTEM_LOAD_GDI_DRIVER_INFORMATION: u32 = 26;
pub const SYSTEM_UNLOAD_GDI_DRIVER_INFORMATION: u32 = 27;
pub const SYSTEM_LOAD_GDI_DRIVER_IN_SYSTEM_SPACE: u32 = 54;
/// IMAGE_DIRECTORY_ENTRY_EXPORT.
const IMAGE_DIRECTORY_ENTRY_EXPORT: u32 = 0;

/// SystemLoadGdiDriverInformation (`session`) e
/// SystemLoadGdiDriverInSystemSpace: o NTSTATUS.
pub fn load_gdi_driver(buffer: u64, length: u32, session: bool) -> Result<u32, KernelError> {
    use crate::ntos::inc::types::extra_ps_user::SystemGdiDriverInformation;
    if length as u64 != SystemGdiDriverInformation::SIZE {
        return Ok(EXTEND_STATUS_INFO_LENGTH_MISMATCH);
    }
    // SAFETY: buffer de modo kernel com o tamanho conferido.
    let information = unsafe { SystemGdiDriverInformation::at(buffer) };
    let outputs = guest::alloc_bytes(24);
    if outputs == 0 {
        return Ok(crate::ntos::inc::status::STATUS_INSUFFICIENT_RESOURCES);
    }
    let status = crate::ntos::mm::sysload::load_system_image(information.driver_name.address(), 0, 0, session as u32, outputs, outputs + 8);
    // SAFETY: as duas células PVOID alocadas acima.
    let (handle, image_base) = unsafe { (Field::<u64>::at(outputs).get(), Field::<u64>::at(outputs + 8).get()) };
    let status = match status {
        Ok(status) if status & 0x8000_0000 == 0 => {
            let exports = crate::ntos::rtl::image::directory_entry(image_base, true, IMAGE_DIRECTORY_ENTRY_EXPORT, outputs + 16);
            let header = crate::ntos::rtl::image::nt_header(image_base);
            match (exports, header) {
                (Ok(exports), Ok(header)) if header != 0 => {
                    // SAFETY: o cabeçalho NT da imagem recém-carregada.
                    let optional = &unsafe { crate::ntos::inc::types::ImageNtHeaders64::at(header) }.optional_header;
                    information.export_section_pointer.set(exports);
                    information.image_address.set(image_base);
                    information.section_pointer.set(handle);
                    information.entry_point.set(image_base + optional.address_of_entry_point.get() as u64);
                    information.image_length.set(optional.size_of_image.get());
                    Ok(0)
                }
                (Err(error), _) | (_, Err(error)) => Err(error),
                _ => Ok(EXTEND_STATUS_INVALID_IMAGE_FORMAT),
            }
        }
        Ok(EXTEND_STATUS_IMAGE_ALREADY_LOADED_AS_DLL) => Ok(EXTEND_STATUS_IMAGE_ALREADY_LOADED),
        other => other,
    };
    guest::free_bytes(outputs);
    status
}

/// SystemUnloadGdiDriverInformation: MmUnloadSystemImage(*buffer).
pub fn unload_gdi_driver(buffer: u64, length: u32) -> Result<u32, KernelError> {
    if length != 8 {
        return Ok(EXTEND_STATUS_INFO_LENGTH_MISMATCH);
    }
    // SAFETY: buffer de modo kernel com um PVOID.
    let handle = unsafe { Field::<u64>::at(buffer) }.get();
    crate::ntos::mm::sysload::unload_system_image(handle)?;
    Ok(0)
}

// ---- SystemThreadPriorityClientIdInformation (82) --------------------------
//
// NtSetSystemInformation 19041 (rva 0x708638): a entrada é a
// SYSTEM_THREAD_CID_PRIORITY_INFORMATION (o CLIENT_ID e o KPRIORITY, 0x18
// bytes; menos é STATUS_INFO_LENGTH_MISMATCH). O SeIncreaseBasePriority
// Privilege vem antes de tudo (SeSinglePrivilegeCheck no modo anterior,
// senão STATUS_PRIVILEGE_NOT_HELD); de UserMode a estrutura é copiada. A
// prioridade fora de 1..31 é STATUS_INVALID_PARAMETER. O
// PsLookupProcessThreadByCid acha a thread do UniqueThread e exige o
// UniqueProcess dela igual ao pedido (senão STATUS_INVALID_CID); uma thread
// já sinalizada dá STATUS_THREAD_IS_TERMINATING. Senão o
// KeSetActualBasePriorityThread troca a base e o serviço devolve
// STATUS_PENDING (0x103), o status do 19041. O win32kfull chama a classe em
// KernelMode na RawInputThread e no SetThreadBasePriority.

pub const SYSTEM_THREAD_PRIORITY_CLIENT_ID_INFORMATION: u32 = 82;
/// SE_INCREASE_BASE_PRIORITY_PRIVILEGE.
const SE_INCREASE_BASE_PRIORITY_PRIVILEGE: u64 = 14;
const PRIORITY_STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const PRIORITY_STATUS_INVALID_CID: u32 = 0xC000_000B;
const PRIORITY_STATUS_THREAD_IS_TERMINATING: u32 = 0xC000_004B;
const PRIORITY_STATUS_PENDING: u32 = 0x103;

/// SystemThreadPriorityClientIdInformation no modo anterior
/// `previous_mode`: o NTSTATUS.
pub fn thread_priority_client_id(buffer: u64, length: u32, previous_mode: u32) -> Result<u32, KernelError> {
    use crate::ntos::inc::types::{ClientId, Ethread};
    if length < 0x18 {
        return Ok(EXTEND_STATUS_INFO_LENGTH_MISMATCH);
    }
    if !crate::ntos::se::privilege::single_privilege_check(SE_INCREASE_BASE_PRIORITY_PRIVILEGE, previous_mode) {
        return Ok(STATUS_PRIVILEGE_NOT_HELD);
    }
    let (process_id, thread_id, priority) = if previous_mode != 0 {
        let Ok(bytes) = guest::try_read_bytes(buffer, 0x18) else { return Ok(STATUS_ACCESS_VIOLATION) };
        let word = |offset: usize| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap_or([0; 8]));
        (word(0), word(8), word(16) as u32 as i32)
    } else {
        // SAFETY: entrada de modo kernel com 0x18 bytes conferidos.
        let cid = unsafe { ClientId::at(buffer) };
        // SAFETY: o KPRIORITY logo depois do CLIENT_ID.
        (cid.unique_process.get(), cid.unique_thread.get(), unsafe { Field::<i32>::at(buffer + 16) }.get())
    };
    if (priority as u32).wrapping_sub(1) > 30 {
        return Ok(PRIORITY_STATUS_INVALID_PARAMETER);
    }
    let cell = guest::alloc_bytes(8);
    if cell == 0 {
        return Ok(crate::ntos::inc::status::STATUS_INSUFFICIENT_RESOURCES);
    }
    let lookup = crate::ntos::ps::lookup_thread::lookup(thread_id, cell);
    let thread = guest::read64(cell);
    guest::free_bytes(cell);
    let status = lookup?;
    if status != 0 {
        return Ok(status);
    }
    // SAFETY: ETHREAD referenciada pela consulta.
    let ethread = unsafe { Ethread::at(thread) };
    let result = if ethread.cid.unique_process.get() != process_id {
        Ok(PRIORITY_STATUS_INVALID_CID)
    } else if ethread.tcb.header.signal_state.get() as u8 != 0 {
        Ok(PRIORITY_STATUS_THREAD_IS_TERMINATING)
    } else {
        crate::ntos::ke::thread_priority::set_actual_base_priority(thread, priority as i64 as u64).map(|_| PRIORITY_STATUS_PENDING)
    };
    crate::ntos::ps::lookup_thread::dereference(thread);
    result
}

// ---- NtSetSystemInformation de modo usuário --------------------------------
//
// ntoskrnl 19041 (NtSetSystemInformation 0x707b70) com PreviousMode =
// UserMode: o buffer é sondado primeiro (alinhamento 4, ou 1 na classe
// 0x59: STATUS_DATATYPE_MISALIGNMENT; fim acima de MmUserProbeAddress:
// STATUS_ACCESS_VIOLATION). A classe 38 (0x708159) exige Length 0x10, o
// processo corrente mestre de uma sessão (EPROCESS.Vm.Flags.SessionMaster) e
// o SeLoadDriverPrivilege habilitado; a UNICODE_STRING capturada tem de ser
// exatamente L"\SystemRoot\System32\win32k.sys" (Length 0x3e e memcmp), senão
// STATUS_PRIVILEGE_NOT_HELD. Passando, o serviço reentra pelo
// ZwSetSystemInformation(38) com uma UNICODE_STRING local sobre o texto do
// próprio kernel, já em KernelMode: o DriverEntry do win32k roda com
// PreviousMode = KernelMode na thread do smss.

const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
/// SE_LOAD_DRIVER_PRIVILEGE.
const SE_LOAD_DRIVER_PRIVILEGE: u64 = 10;
/// A classe cujo buffer só precisa de alinhamento 1.
const SET_INFORMATION_BYTE_ALIGNED_CLASS: u32 = 0x59;

/// NtSetSystemInformation com PreviousMode = UserMode: o NTSTATUS.
pub fn set_from_user_mode(class: u32, buffer: u64, length: u32) -> Result<u32, KernelError> {
    let alignment = if class == SET_INFORMATION_BYTE_ALIGNED_CLASS { 1 } else { 4 };
    if length != 0 {
        if buffer & (alignment - 1) != 0 {
            return Ok(STATUS_DATATYPE_MISALIGNMENT);
        }
        let end = buffer.wrapping_add(length as u64);
        if end > crate::ntos::mm::memory_map::USER_PROBE_ADDRESS || end < buffer {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    if matches!(class, 44 | 102) {
        return Ok(crate::ntos::ex::time_zone::set(class, buffer, length, true));
    }
    if matches!(class, SYSTEM_LOAD_GDI_DRIVER_INFORMATION | SYSTEM_UNLOAD_GDI_DRIVER_INFORMATION | SYSTEM_LOAD_GDI_DRIVER_IN_SYSTEM_SPACE) {
        let expected = if class == SYSTEM_UNLOAD_GDI_DRIVER_INFORMATION { 8 } else { crate::ntos::inc::types::extra_ps_user::SystemGdiDriverInformation::SIZE as u32 };
        return Ok(if length != expected { EXTEND_STATUS_INFO_LENGTH_MISMATCH } else { STATUS_PRIVILEGE_NOT_HELD });
    }
    if class == SYSTEM_THREAD_PRIORITY_CLIENT_ID_INFORMATION {
        return thread_priority_client_id(buffer, length, 1);
    }
    if class != SYSTEM_EXTEND_SERVICE_TABLE_INFORMATION {
        debug_print!("[usermode] NtSetSystemInformation classe {} (sem suporte de modo usuario)", class);
        return Ok(STATUS_INVALID_INFO_CLASS);
    }
    if length as u64 != crate::ntos::inc::types::UnicodeString::SIZE {
        return Ok(EXTEND_STATUS_INFO_LENGTH_MISMATCH);
    }
    // SAFETY: o EPROCESS corrente (PsGetCurrentProcess).
    let process = unsafe { crate::ntos::inc::types::Eprocess::at(crate::ntos::ps::process::get_current_process()) };
    if process.vm.instance.flags.session_master() == 0 || !crate::ntos::se::privilege::single_privilege_check(SE_LOAD_DRIVER_PRIVILEGE, 1) {
        return Ok(STATUS_PRIVILEGE_NOT_HELD);
    }
    // A captura da UNICODE_STRING e do texto, sondados (o __try do serviço).
    let Ok(string) = crate::ntos::inc::types::UnicodeString::try_at(buffer) else { return Ok(STATUS_ACCESS_VIOLATION) };
    let (Ok(name_length), Ok(name_buffer)) = (string.length.probe_get(), string.buffer.probe_get()) else { return Ok(STATUS_ACCESS_VIOLATION) };
    let expected: Vec<u8> = EXTEND_SERVICE_TABLE_WIN32K.encode_utf16().flat_map(u16::to_le_bytes).collect();
    if name_length as usize != expected.len() {
        return Ok(STATUS_PRIVILEGE_NOT_HELD);
    }
    let source = name_buffer.min(crate::ntos::mm::memory_map::USER_PROBE_ADDRESS);
    let Ok(text) = guest::try_read_bytes(source, expected.len()) else { return Ok(STATUS_ACCESS_VIOLATION) };
    if text != expected {
        return Ok(STATUS_PRIVILEGE_NOT_HELD);
    }
    // A UNICODE_STRING local do serviço, sobre o texto do kernel.
    let local = guest::alloc_bytes(crate::ntos::inc::types::UnicodeString::SIZE + expected.len() as u64 + 2);
    if local == 0 {
        return Ok(crate::ntos::inc::status::STATUS_INSUFFICIENT_RESOURCES);
    }
    let characters = local + crate::ntos::inc::types::UnicodeString::SIZE;
    guest::write_bytes(characters, &expected);
    guest::write_bytes(characters + expected.len() as u64, &[0, 0]);
    // SAFETY: UNICODE_STRING recém-alocada.
    let kernel_string = unsafe { crate::ntos::inc::types::UnicodeString::at(local) };
    kernel_string.length.set(expected.len() as u16);
    kernel_string.maximum_length.set(expected.len() as u16);
    kernel_string.buffer.set(characters);
    let status = crate::ntos::ps::previous_mode::with_kernel(|| set(SYSTEM_EXTEND_SERVICE_TABLE_INFORMATION, local, crate::ntos::inc::types::UnicodeString::SIZE as u32));
    guest::free_bytes(local);
    status
}

/// SystemExtendServiceTableInformation: carrega a imagem nomeada pela
/// UNICODE_STRING em `buffer` (convertendo as tabelas de serviço do
/// win32k.sys) e chama o ponto de entrada; devolve o NTSTATUS.
pub fn extend_service_table(buffer: u64, length: u32) -> Result<u32, KernelError> {
    use crate::ntos::mm::sysload;
    if length as u64 != crate::ntos::inc::types::UnicodeString::SIZE {
        return Ok(EXTEND_STATUS_INFO_LENGTH_MISMATCH);
    }
    let name = crate::ntos::rtl::guest_strings::read_unicode_string(buffer);
    let flags = if name == EXTEND_SERVICE_TABLE_WIN32K { EXTEND_SERVICE_TABLE_WIN32K_FLAGS } else { EXTEND_SERVICE_TABLE_SESSION_FLAGS };
    let outputs = guest::alloc_bytes(16);
    if outputs == 0 {
        return Ok(crate::ntos::inc::status::STATUS_INSUFFICIENT_RESOURCES);
    }
    let loaded = sysload::load_system_image_extending_services(buffer, flags, outputs, outputs + 8);
    // SAFETY: as duas células PVOID alocadas acima.
    let (handle, image_base) = unsafe { (Field::<u64>::at(outputs).get(), Field::<u64>::at(outputs + 8).get()) };
    guest::free_bytes(outputs);
    let status = loaded?;
    if status & 0x8000_0000 != 0 {
        return Ok(if status == EXTEND_STATUS_IMAGE_ALREADY_LOADED_AS_DLL { EXTEND_STATUS_IMAGE_ALREADY_LOADED } else { status });
    }
    let header = crate::ntos::rtl::image::nt_header(image_base)?;
    if header == 0 {
        sysload::unload_system_image(handle)?;
        return Ok(EXTEND_STATUS_INVALID_IMAGE_FORMAT);
    }
    // SAFETY: cabeçalho NT da imagem recém-carregada.
    let entry_point = image_base + unsafe { crate::ntos::inc::types::ImageNtHeaders64::at(header) }.optional_header.address_of_entry_point.get() as u64;
    // `--trace-driver-api` no boot do smss: o DriverEntry do driver de sessão
    // (o win32k.sys e o que ele carrega) imprime cada export que chama.
    // O rastreio volta ao estado anterior: depois do portão do smss ele
    // segue ligado para os drivers (o win32k da sessão seguinte não o
    // desliga).
    let trace = crate::ntos::init::boot_config::trace_driver_api() && crate::ntos::init::boot_config::smss_boot();
    let previous = crate::ntos::init::exports::api_trace_enabled();
    if trace {
        crate::ntos::init::exports::set_api_trace(true);
    }
    let status = initialize_session_driver(entry_point, image_base);
    if trace {
        crate::ntos::init::exports::set_api_trace(previous);
    }
    debug_print!("[ex] driver de sessao {}: DriverEntry -> {:#x}", name, status);
    crate::ntos::init::initial_process::session_driver_initialized(&name, image_base, status);
    if status & 0x8000_0000 != 0 {
        sysload::unload_system_image(handle)?;
    }
    Ok(status)
}
