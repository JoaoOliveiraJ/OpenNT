//! Descrição legada de hardware.
//!
//! Controlador 8042 na hive de hardware e IoQueryDeviceDescription. Mantém a
//! representação usada pelos drivers deste sistema; os serializadores legados
//! não equivalem a suporte geral de todos os layouts WDK.

use alloc::string::String;
use alloc::vec::Vec;

use super::registry;
use crate::hal::amd64::native_call;
use crate::rtl::KernelError;
use crate::ntos::{mm::guest_memory as guest, rtl::guest_strings};
use crate::ntos::inc::types::{KeyValueFullInformation, NtStruct, UnicodeString};
use core::mem::offset_of;

pub const HARDWARE_DESCRIPTION_PATH: &str = "\\Registry\\Machine\\Hardware\\Description\\System";
pub const DEVICE_MAP_PATH: &str = "\\Registry\\Machine\\Hardware\\DeviceMap";

/// INTERFACE_TYPE/CONFIGURATION_TYPE tratados por este provedor.
pub const OTHER_CONTROLLER: u32 = 22;
pub const OTHER_PERIPHERAL: u32 = 32;

fn controller_type_name(value: u32) -> Option<&'static str> {
    (value == OTHER_CONTROLLER).then_some("OtherController")
}

fn peripheral_type_name(value: u32) -> Option<&'static str> {
    (value == OTHER_PERIPHERAL).then_some("OtherPeripheral")
}

/// (BusType, nome do adaptador).
const BUS_TYPE_ADAPTERS: [(u32, &str); 1] = [(1, "MultifunctionAdapter")];

/// KEY_VALUE_FULL_INFORMATION de um valor, como o ZwQueryValueKey
/// (KeyValueFullInformation) que o NT usa aqui: NameLength em bytes, nome
/// sem terminador e DataOffset alinhado a ULONG.
fn build_value_information(value_type: u32, name: &str, data: &[u8]) -> u64 {
    let name_bytes: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let name_offset = offset_of!(KeyValueFullInformation, name) as u64;
    let aligned = (name_offset + name_bytes.len() as u64 + 3) & !3;
    let pointer = guest::alloc_bytes(aligned + data.len() as u64);
    // SAFETY: bloco próprio recém-alocado com cabeçalho, nome e dados.
    let information = unsafe { KeyValueFullInformation::at(pointer) };
    information.title_index.set(0);
    information.type_.set(value_type);
    information.data_offset.set(aligned as u32);
    information.data_length.set(data.len() as u32);
    information.name_length.set(name_bytes.len() as u32);
    guest::write_bytes(pointer + name_offset, &name_bytes);
    guest::write_bytes(pointer + aligned, data);
    pointer
}

/// Identifier, Configuration Data e Component Information do nível.
fn build_information_pointer_array(identifier: u64, configuration: u64, component: u64) -> u64 {
    let pointer = guest::alloc_bytes(3 * 8);
    // SAFETY: vetor próprio de três PKEY_VALUE_FULL_INFORMATION.
    let slots = unsafe { crate::ntos::inc::types::Field::<u64>::array_at(pointer, 3) };
    slots[0].set(identifier);
    slots[1].set(configuration);
    slots[2].set(component);
    pointer
}

/// Códigos dos caracteres + NUL; representação legada em bytes, embora o
/// Identifier seja registrado como REG_SZ.
fn encode_byte_string(text: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = text.encode_utf16().map(|unit| unit as u8).collect();
    bytes.push(0);
    bytes
}

/// Configuration Data é opcional; Component Information recebe quatro
/// bytes nulos quando ausente.
fn seed_entry(relative: &str, identifier: &str, configuration: Option<&[u8]>) -> Result<(), KernelError> {
    let handle = registry::open_or_create(&(String::from(HARDWARE_DESCRIPTION_PATH) + relative), None)?;
    registry::set_value(handle, "Identifier", 1, encode_byte_string(identifier));
    if let Some(configuration) = configuration {
        registry::set_value(handle, "Configuration Data", 3, configuration.to_vec());
    }
    registry::set_value(handle, "Component Information", 3, alloc::vec![0, 0, 0, 0]);
    registry::close_handle(handle);
    Ok(())
}

/// Os três argumentos são porta/tamanho ou nível/vetor/afinidade. Os campos
/// de oito bytes repetem a palavra baixa nos quatro bytes superiores, como
/// os deslocamentos de 32 bits do serializador legado.
fn build_partial_descriptor(descriptor_type: u8, start_or_level: u32, length_or_vector: u32, affinity: u32) -> Vec<u8> {
    let mut bytes = alloc::vec![descriptor_type, 0, 0, 0];
    let repeated = |value: u32| (0..8).map(move |offset| (value >> ((8 * offset) % 32)) as u8);
    if descriptor_type == 2 {
        bytes.extend(repeated(start_or_level));
        bytes.extend_from_slice(&length_or_vector.to_le_bytes());
    } else if descriptor_type == 3 {
        bytes.extend_from_slice(&start_or_level.to_le_bytes());
        bytes.extend_from_slice(&length_or_vector.to_le_bytes());
        bytes.extend(repeated(affinity));
    }
    bytes.resize(0x14, 0);
    bytes
}

/// Bytes de Configuration Data do 8042: contagem, interface, barramento,
/// versão/revisão (quatro bytes cada) e as portas 0x60/0x64 e a IRQ 1.
pub fn configuration_bytes() -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in [1u32, 1, 0, 1, 1, 3] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend(build_partial_descriptor(2, 0x60, 1, 0));
    bytes.extend(build_partial_descriptor(2, 0x64, 1, 0));
    bytes.extend(build_partial_descriptor(3, 1, 0x21, 0xFF));
    bytes
}

/// Chaves legadas do barramento ISA, do controlador e do teclado 8042.
pub fn seed_hardware_description() -> Result<(), KernelError> {
    let configuration = configuration_bytes();
    seed_entry("\\MultifunctionAdapter", "ISA Bus", None)?;
    seed_entry("\\MultifunctionAdapter\\0", "ISA Bus", None)?;
    seed_entry("\\MultifunctionAdapter\\0\\OtherController", "8042 Controller", None)?;
    seed_entry("\\MultifunctionAdapter\\0\\OtherController\\0", "8042 Controller", Some(&configuration))?;
    seed_entry("\\MultifunctionAdapter\\0\\OtherController\\0\\OtherPeripheral", "8042 Peripheral", None)?;
    seed_entry("\\MultifunctionAdapter\\0\\OtherController\\0\\OtherPeripheral\\0", "AT-Compatible 8042 Keyboard", Some(&configuration))?;
    // HARDWARE\DEVICEMAP nasce vazio junto da descrição (o
    // CmpInitializeHardwareConfiguration do NT): os drivers de classe
    // publicam nela os seus dispositivos (RtlWriteRegistryValue com
    // RTL_REGISTRY_DEVICEMAP, como KeyboardClass e PointerClass).
    registry::close_handle(registry::open_or_create(DEVICE_MAP_PATH, None)?);
    seed_central_processors()?;
    debug_print!("[hwdesc] arvore de hardware descrita (8042 ISA, processadores) semeada");
    Ok(())
}

/// O texto de registradores CPUID (EBX/EDX/ECX do leaf 0, ou EAX..EDX das
/// marcas 0x80000002..4), sem os NULs do fim.
fn cpuid_text(words: &[u32]) -> String {
    let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).take_while(|&byte| byte != 0).collect();
    String::from(String::from_utf8_lossy(&bytes).trim())
}

/// `CentralProcessor\<n>` de cada processador, com os valores que o
/// CmpInitializeMachineDependentConfiguration do NT grava a partir do CPUID:
/// Identifier ("AMD64/Intel64/VIA64 Family F Model M Stepping S", com a
/// família e o modelo estendidos), VendorIdentifier, ProcessorNameString,
/// ~MHz (a frequência medida do TSC) e FeatureSet. O smss lê esta chave para
/// o ambiente (PROCESSOR_IDENTIFIER, PROCESSOR_LEVEL...).
fn seed_central_processors() -> Result<(), KernelError> {
    use crate::hal::cpu::cpuid;
    let vendor_words = cpuid(0);
    let vendor = cpuid_text(&[vendor_words[1], vendor_words[3], vendor_words[2]]);
    let signature = cpuid(1)[0];
    let base_family = (signature >> 8) & 0xF;
    let family = if base_family == 0xF { base_family + ((signature >> 20) & 0xFF) } else { base_family };
    let model = ((signature >> 4) & 0xF) | if base_family == 0x6 || base_family == 0xF { ((signature >> 16) & 0xF) << 4 } else { 0 };
    let stepping = signature & 0xF;
    let architecture = match vendor.as_str() {
        "AuthenticAMD" => "AMD64",
        "CentaurHauls" => "VIA64",
        _ => "Intel64",
    };
    let identifier = alloc::format!("{architecture} Family {family} Model {model} Stepping {stepping}");
    let name = if cpuid(0x8000_0000)[0] >= 0x8000_0004 {
        let words: Vec<u32> = (0x8000_0002..=0x8000_0004u32).flat_map(cpuid).collect();
        cpuid_text(&words)
    } else {
        String::new()
    };
    let megahertz = (crate::ntos::ke::clock::tsc_frequency_hz() / 1_000_000) as u32;
    for index in 0..crate::ntos::ke::smp::online_cpu_count() {
        let handle = registry::open_or_create(&alloc::format!("{HARDWARE_DESCRIPTION_PATH}\\CentralProcessor\\{index}"), None)?;
        registry::set_value(handle, "Identifier", 1, registry::encode_wide(&identifier));
        registry::set_value(handle, "VendorIdentifier", 1, registry::encode_wide(&vendor));
        registry::set_value(handle, "ProcessorNameString", 1, registry::encode_wide(&name));
        registry::set_value(handle, "~MHz", 4, megahertz.to_le_bytes().to_vec());
        registry::set_value(handle, "FeatureSet", 4, 0u32.to_le_bytes().to_vec());
        registry::set_value(handle, "Component Information", 3, alloc::vec![0; 16]);
        registry::close_handle(handle);
    }
    Ok(())
}

/// Materializa os três valores de um nível na arena do convidado, com
/// identificador padrão e arrays vazios quando ausentes.
fn information_array_for_path(path: &str) -> u64 {
    let handle = registry::open(path).unwrap_or(0);
    if handle == 0 {
        return 0;
    }
    let identifier = registry::get_value(handle, "Identifier").map_or((1, encode_byte_string("Unknown")), |value| (value.value_type, value.data));
    let configuration = registry::get_value(handle, "Configuration Data").map_or((3, Vec::new()), |value| (value.value_type, value.data));
    let component = registry::get_value(handle, "Component Information").map_or((3, alloc::vec![0, 0, 0, 0]), |value| (value.value_type, value.data));
    let identifier = build_value_information(identifier.0, "Identifier", &identifier.1);
    let configuration = build_value_information(configuration.0, "Configuration Data", &configuration.1);
    let component = build_value_information(component.0, "Component Information", &component.1);
    let array = build_information_pointer_array(identifier, configuration, component);
    registry::close_handle(handle);
    array
}

/// UNICODE_STRING de 16 bytes com texto terminado em NUL.
fn make_unicode_string(text: &str) -> u64 {
    let length = text.encode_utf16().count() as u64 * 2;
    let buffer = guest::alloc_bytes(length + 2);
    guest_strings::write_wide_string(buffer, text);
    let structure = guest::alloc_bytes(UnicodeString::SIZE);
    // SAFETY: descritor próprio recém-alocado.
    let descriptor = unsafe { UnicodeString::at(structure) };
    descriptor.length.set(length as u16);
    descriptor.maximum_length.set(length as u16 + 2);
    descriptor.buffer.set(buffer);
    structure
}

fn optional_enumeration(pointer: u64) -> Option<u32> {
    (pointer != 0).then(|| super::out::<u32>(pointer).get())
}

/// IoQueryDeviceDescription: até quatro barramentos, controladores e
/// periféricos dos tipos reconhecidos, chamando o callout com onze
/// argumentos. Só os tipos de controlador e periférico filtram; as
/// estruturas temporárias pertencem ao chamador nativo.
#[allow(clippy::too_many_arguments)]
pub fn query_device_description(_bus_type: u64, _bus_number: u64, controller_type: u64, _controller_number: u64, peripheral_type: u64, _peripheral_number: u64, callout: u64, context: u64) -> u32 {
    let controller = optional_enumeration(controller_type);
    let peripheral = optional_enumeration(peripheral_type);
    let (Some(controller_name), Some(peripheral_name)) = (controller.and_then(controller_type_name), peripheral.and_then(peripheral_type_name)) else { return 0xC000_0034 };
    if callout == 0 {
        return 0xC000_0034;
    }
    for (bus_type, adapter) in BUS_TYPE_ADAPTERS {
        for bus_number in 0..4u64 {
            let controller_path = alloc::format!("{HARDWARE_DESCRIPTION_PATH}\\{adapter}\\{bus_number}\\{controller_name}");
            for controller_number in 0..4u64 {
                let peripheral_path = alloc::format!("{controller_path}\\{controller_number}\\{peripheral_name}");
                for peripheral_number in 0..4u64 {
                    let leaf = alloc::format!("{peripheral_path}\\{peripheral_number}");
                    let handle = registry::open(&leaf).unwrap_or(0);
                    if handle == 0 {
                        continue;
                    }
                    registry::close_handle(handle);
                    let bus_information = information_array_for_path(&alloc::format!("{HARDWARE_DESCRIPTION_PATH}\\{adapter}"));
                    let controller_information = information_array_for_path(&alloc::format!("{controller_path}\\{controller_number}"));
                    let peripheral_information = information_array_for_path(&leaf);
                    let path = make_unicode_string(&leaf);
                    // A enumeração para no primeiro sucesso do callout.
                    let status = native_call::call(callout, &[context, path, bus_type as u64, bus_number, bus_information, controller.unwrap_or(0) as u64, controller_number, controller_information, peripheral.unwrap_or(0) as u64, peripheral_number, peripheral_information]);
                    if status as u32 == 0 {
                        return 0;
                    }
                }
            }
        }
    }
    0xC000_0034
}
