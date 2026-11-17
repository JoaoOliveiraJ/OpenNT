//! O TPM 2.0 da máquina (`--tpm`).
//!
//! Com a opção, o QEMU tem um TPM 2.0 com interface CRB (tpm-crb): o
//! dispositivo `TPM` no `\_SB` da DSDT, com `_HID` MSFT0101 e a janela MMIO
//! em 0xFED40000, e a tabela ACPI TPM2 (start method 7, a área de controle
//! do CRB). O firmware manda o TPM2_Startup(SU_CLEAR) e estende os PCRs
//! dele antes do boot.
//!
//! Na árvore do PnP (`device_tree::build`), o acpi.sys relata o MSFT0101 sob
//! a raiz ACPI e o instalador o casa com o tpm.inf (`[Tpm2BaseInstall]`, o
//! serviço TPM, HardwareType 20). O tpm.sys real, um driver KMDF, recebe o
//! AddDevice e o START com o recurso de memória do `_CRS`; ele lê a tabela
//! TPM2 pelo HalGetCachedAcpiTable da HalDispatchTable, mapeia a área do CRB
//! e publica o `\??\TPM`.
//!
//! A ida e volta de comandos usa o caminho dos componentes de kernel do
//! Windows: o tbs.sys (o export driver da API de TPM de kernel), carregado
//! como biblioteca, abre o `\??\TPM` no Tbsi_Context_Create e manda cada
//! comando ao tpm.sys pelo Tbsip_Submit_Command. Os comandos são o
//! TPM2_Startup(SU_CLEAR), o TPM2_GetRandom de 16 bytes e o
//! TPM2_GetCapability da propriedade TPM_PT_MANUFACTURER. O tpm.sys bloqueia
//! o TPM2_Startup de todo cliente do TBS: o código 0x144 não está em nenhuma
//! das três listas de comandos permitidos por tipo de usuário do
//! Tpm20Scheduler::IsCommandBlocked, e a resposta é o cabeçalho com
//! TPM_E_COMMAND_BLOCKED; o GetRandom e o GetCapability estão nas três e vão
//! ao TPM. Depois o TPM2_PCR_Read do PCR 0 no banco SHA-256 vai para o log,
//! com o valor que as medições do firmware deixaram.
//!
//! Os marcadores: `TPM_DEVICE_FOUND` quando o acpi.sys relatou o
//! ACPI\MSFT0101 e a tabela TPM2 está no firmware; `TPM_STARTED` quando o
//! nó está iniciado com o FDO do \Driver\TPM; `TPM_COMMAND_OK` quando as três
//! respostas chegaram válidas pelo tbs.sys.
//!
//! Sem a opção nada disto roda e o boot comum não muda.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::hal::amd64::native_call;
use crate::ntos::inc::types::extra_tbs::TbsContextParams2;
use crate::ntos::inc::types::{DeviceObject, Field, NtStruct};
use crate::ntos::io::lifecycle;
use crate::ntos::io::pnp::devnode;
use crate::ntos::mm::guest_memory as guest;

/// `--tpm`: o TPM 2.0 do QEMU sobe pelo PnP.
pub fn enabled() -> bool {
    crate::ntos::init::boot_config::tpm()
}

/// O `_HID` do TPM 2.0 (TCG ACPI Specification).
const TPM2_DEVICE_ID: &str = "ACPI\\MSFT0101";

/// Campos da tabela TPM2 (TCG ACPI Specification, tabela 7).
const TPM2_START_METHOD_OFFSET: usize = 48;
const TPM2_CONTROL_AREA_OFFSET: usize = 40;

/// TBS_CONTEXT_PARAMS2: versão TBS_CONTEXT_VERSION_TWO e o bit
/// includeTpm20.
const TBS_CONTEXT_VERSION_TWO: u32 = 2;
const TBS_INCLUDE_TPM20: u32 = 1 << 2;
const TBS_COMMAND_LOCALITY_ZERO: u64 = 0;
const TBS_COMMAND_PRIORITY_NORMAL: u64 = 200;
const TBS_SUCCESS: u32 = 0;

/// TPM_ST_NO_SESSIONS e os códigos de comando e de resposta (TPM 2.0
/// Library, parte 2).
const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_CC_STARTUP: u32 = 0x144;
const TPM_CC_GET_RANDOM: u32 = 0x17B;
const TPM_CC_GET_CAPABILITY: u32 = 0x17A;
const TPM_SU_CLEAR: u16 = 0;
const TPM_RC_SUCCESS: u32 = 0;
/// O código que o tpm.sys põe na resposta de um comando bloqueado.
const TPM_E_COMMAND_BLOCKED: u32 = 0x8028_0400;
const TPM_CC_PCR_READ: u32 = 0x17E;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_CAP_TPM_PROPERTIES: u32 = 6;
const TPM_PT_MANUFACTURER: u32 = 0x105;
const RANDOM_BYTES: u16 = 16;

/// Um comando sem sessões: cabeçalho (tag, tamanho, código) e parâmetros.
fn command(code: u32, parameters: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(10 + parameters.len());
    bytes.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    bytes.extend_from_slice(&(10 + parameters.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&code.to_be_bytes());
    bytes.extend_from_slice(parameters);
    bytes
}

fn be16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

fn be32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// O cabeçalho de uma resposta: tag sem sessões e o tamanho igual ao
/// recebido; devolve o código de resposta.
fn response_code(response: &[u8]) -> Result<u32, String> {
    if response.len() < 10 {
        return Err(format!("resposta de {} bytes", response.len()));
    }
    let (tag, size) = (be16(response, 0), be32(response, 2));
    if tag != TPM_ST_NO_SESSIONS || size as usize != response.len() {
        return Err(format!("cabecalho da resposta: tag {tag:#06x}, tamanho {size} de {} recebidos", response.len()));
    }
    Ok(be32(response, 6))
}

/// O ACPI\MSFT0101 relatado e a tabela TPM2: (nó, start method, área de
/// controle).
fn check_device() -> Result<(devnode::DeviceNode, u32, u64), String> {
    let node = devnode::all().into_iter().find(|node| node.device_id.eq_ignore_ascii_case(TPM2_DEVICE_ID)).ok_or("o acpi.sys nao relatou o ACPI\\MSFT0101")?;
    let table = crate::hal::acpi::get_table("TPM2", 0, false).ok_or("o firmware nao tem a tabela TPM2")?;
    if table.bytes.len() < TPM2_START_METHOD_OFFSET + 4 {
        return Err(format!("tabela TPM2 de {} bytes", table.bytes.len()));
    }
    let start_method = u32::from_le_bytes(table.bytes[TPM2_START_METHOD_OFFSET..TPM2_START_METHOD_OFFSET + 4].try_into().unwrap());
    let control_area = u64::from_le_bytes(table.bytes[TPM2_CONTROL_AREA_OFFSET..TPM2_CONTROL_AREA_OFFSET + 8].try_into().unwrap());
    Ok((node, start_method, control_area))
}

/// O nó iniciado com o FDO do \Driver\TPM sobre o PDO do acpi.sys.
fn check_started(node: &devnode::DeviceNode) -> Result<(), String> {
    if node.state != devnode::State::Started {
        return Err(format!("{}: estado {:?}, problema {:#x}, servico {}", node.instance_path, node.state, node.problem, node.service.as_deref().unwrap_or("-")));
    }
    let driver = lifecycle::initialized_driver("TPM").ok_or("\\Driver\\TPM ausente")?;
    let fdo = node.function_device;
    // SAFETY: o FDO do nó.
    let owner = if fdo != 0 { unsafe { DeviceObject::at(fdo) }.driver_object.get() } else { 0 };
    if fdo == 0 || owner != driver || !crate::drivers::bus::device_tree::attached_above(node.pdo, fdo) {
        return Err(format!("{}: FDO {fdo:#x} do driver {owner:#x}, fora da pilha do PDO {:#x}", node.instance_path, node.pdo));
    }
    Ok(())
}

/// Um contexto do tbs.sys e o envio de comandos por ele.
struct TbsContext {
    submit: u64,
    close: u64,
    handle: u64,
}

impl TbsContext {
    /// Tbsi_Context_Create(TBS_CONTEXT_PARAMS2{versão 2, includeTpm20}).
    fn create() -> Result<TbsContext, String> {
        let library = crate::ntos::mm::sysload::load("tbs.sys").map_err(|error| format!("tbs.sys: {error}"))?;
        let export = |name: &str| library.exports.exports.get(name).copied().ok_or_else(|| format!("tbs.sys sem {name}"));
        let (create, submit, close) = (export("Tbsi_Context_Create")?, export("Tbsip_Submit_Command")?, export("Tbsip_Context_Close")?);
        let size = core::mem::size_of::<TbsContextParams2>() as u64;
        let block = guest::alloc_bytes(size + 8);
        if block == 0 {
            return Err(String::from("sem pool para o contexto"));
        }
        // SAFETY: bloco recém-alocado com os parâmetros e o TBS_HCONTEXT de saída.
        let (parameters, context) = unsafe { (TbsContextParams2::at(block), Field::<u64>::at(block + size)) };
        parameters.version.set(TBS_CONTEXT_VERSION_TWO);
        parameters.flags.set(TBS_INCLUDE_TPM20);
        context.set(0);
        let result = native_call::call(create, &[block, block + size]) as u32;
        let handle = context.get();
        guest::free_bytes(block);
        if result != TBS_SUCCESS || handle == 0 {
            return Err(format!("Tbsi_Context_Create -> {result:#x}"));
        }
        Ok(TbsContext { submit, close, handle })
    }

    /// Tbsip_Submit_Command na localidade 0, prioridade normal.
    fn submit(&self, command: &[u8]) -> Result<Vec<u8>, String> {
        const RESPONSE_MAX: u32 = 4096;
        let block = guest::alloc_bytes(command.len() as u64 + RESPONSE_MAX as u64 + 8);
        if block == 0 {
            return Err(String::from("sem pool para o comando"));
        }
        // O UINT32 do tamanho primeiro (alinhado), depois a resposta e o comando.
        let (length, output, input) = (block, block + 8, block + 8 + RESPONSE_MAX as u64);
        guest::write_bytes(input, command);
        // SAFETY: o UINT32 de entrada e saída do tamanho da resposta, no bloco.
        let received = unsafe { Field::<u32>::at(length) };
        received.set(RESPONSE_MAX);
        let result = native_call::call(self.submit, &[self.handle, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, input, command.len() as u64, output, length]) as u32;
        let received = received.get().min(RESPONSE_MAX);
        let response = guest::read_bytes(output, received as usize);
        guest::free_bytes(block);
        if result != TBS_SUCCESS {
            return Err(format!("Tbsip_Submit_Command -> {result:#x}"));
        }
        Ok(response)
    }
}

impl Drop for TbsContext {
    fn drop(&mut self) {
        native_call::call(self.close, &[self.handle]);
    }
}

/// O `\??\TPM` que o AddDevice do tpm.sys cria: o alvo do link e se ele
/// resolve num objeto (para o log quando o tbs.sys não abre o TPM).
fn describe_tpm_link() -> String {
    use crate::ntos::ob::object_manager;
    let (link, _) = object_manager::resolve_from("\\GLOBAL??\\TPM", 0, true, true, object_manager::ROOT);
    let Some(link) = link else { return String::from("\\GLOBAL??\\TPM ausente") };
    let node = object_manager::node(link);
    let target = node.as_ref().and_then(|node| node.data.as_ref()).and_then(|data| data.symlink_target.clone());
    let kind = node.as_ref().map(|node| node.type_name.clone()).unwrap_or_default();
    let resolved = object_manager::lookup("\\GLOBAL??\\TPM").and_then(object_manager::node).map(|node| node.type_name);
    format!("\\GLOBAL??\\TPM ({kind}) -> {:?}, resolve em {:?}", target, resolved)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// O TPM2_PCR_Read do PCR 0 no banco SHA-256: o digest, ou o código da
/// resposta. Só vai para o log.
fn read_pcr0(context: &TbsContext) -> Result<Vec<u8>, String> {
    // TPML_PCR_SELECTION: um banco, SHA-256, três bytes de seleção, o PCR 0.
    let mut parameters = Vec::new();
    parameters.extend_from_slice(&1u32.to_be_bytes());
    parameters.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    parameters.extend_from_slice(&[3, 0x01, 0x00, 0x00]);
    let response = context.submit(&command(TPM_CC_PCR_READ, &parameters))?;
    let code = response_code(&response)?;
    // pcrUpdateCounter (4), a seleção devolvida (10), TPML_DIGEST (4) e o
    // TPM2B_DIGEST (2 + 32).
    if code != TPM_RC_SUCCESS || response.len() < 62 || be32(&response, 24) != 1 || be16(&response, 28) != 32 {
        return Err(format!("{code:#x}, {}", hex(&response)));
    }
    Ok(response[30..62].to_vec())
}

/// A ida e volta: TPM2_Startup, TPM2_GetRandom e TPM2_GetCapability pelo
/// tbs.sys, com as respostas conferidas.
fn command_round_trip() -> Result<String, String> {
    let context = TbsContext::create()?;
    let startup = context.submit(&command(TPM_CC_STARTUP, &TPM_SU_CLEAR.to_be_bytes()))?;
    let startup_code = response_code(&startup)?;
    if startup_code != TPM_E_COMMAND_BLOCKED {
        return Err(format!("TPM2_Startup -> {startup_code:#x} (o tpm.sys bloqueia o comando: {TPM_E_COMMAND_BLOCKED:#x})"));
    }
    debug_print!("[tpm] TPM2_Startup(SU_CLEAR) -> {:#x} (TPM_E_COMMAND_BLOCKED do tpm.sys)", startup_code);
    let random = context.submit(&command(TPM_CC_GET_RANDOM, &RANDOM_BYTES.to_be_bytes()))?;
    let random_code = response_code(&random)?;
    if random_code != TPM_RC_SUCCESS || random.len() != 12 + RANDOM_BYTES as usize || be16(&random, 10) != RANDOM_BYTES {
        return Err(format!("TPM2_GetRandom -> {random_code:#x}, {}", hex(&random)));
    }
    let bytes = &random[12..];
    if bytes.iter().all(|&byte| byte == bytes[0]) {
        return Err(format!("TPM2_GetRandom devolveu bytes iguais: {}", hex(bytes)));
    }
    debug_print!("[tpm] TPM2_GetRandom(16) -> {}", hex(bytes));
    let mut parameters = Vec::new();
    for value in [TPM_CAP_TPM_PROPERTIES, TPM_PT_MANUFACTURER, 1] {
        parameters.extend_from_slice(&value.to_be_bytes());
    }
    let capability = context.submit(&command(TPM_CC_GET_CAPABILITY, &parameters))?;
    let capability_code = response_code(&capability)?;
    // moreData (1), capability (4), count (4), TPMS_TAGGED_PROPERTY (8).
    if capability_code != TPM_RC_SUCCESS || capability.len() < 27 || be32(&capability, 11) != TPM_CAP_TPM_PROPERTIES || be32(&capability, 15) != 1 || be32(&capability, 19) != TPM_PT_MANUFACTURER {
        return Err(format!("TPM2_GetCapability -> {capability_code:#x}, {}", hex(&capability)));
    }
    let manufacturer = be32(&capability, 23).to_be_bytes();
    let vendor: String = manufacturer.iter().map(|&byte| if byte.is_ascii_graphic() || byte == b' ' { byte as char } else { '.' }).collect();
    debug_print!("[tpm] TPM2_GetCapability(TPM_PT_MANUFACTURER) -> {:#010x} \"{}\"", be32(&capability, 23), vendor);
    match read_pcr0(&context) {
        Ok(digest) => debug_print!("[tpm] TPM2_PCR_Read(SHA-256, PCR 0) -> {}{}", hex(&digest), if digest.iter().all(|&byte| byte == 0) { " (sem medicoes)" } else { " (medido pelo firmware)" }),
        Err(error) => debug_print!("[tpm] TPM2_PCR_Read(SHA-256, PCR 0) -> {}", error),
    }
    Ok(format!("Startup bloqueado ({startup_code:#x}), GetRandom de {} bytes, fabricante \"{vendor}\"", bytes.len()))
}

/// Confere os marcadores do TPM na árvore montada (`device_tree::build`).
pub fn check() {
    let (node, start_method, control_area) = match check_device() {
        Ok(found) => found,
        Err(error) => {
            debug_print!("[tpm] TPM ausente: {}", error);
            return;
        }
    };
    debug_print!("[tpm] {}: tabela TPM2 com start method {} e area de controle {:#x}", node.instance_path, start_method, control_area);
    debug_print!("TPM_DEVICE_FOUND");
    if let Err(error) = check_started(&node) {
        debug_print!("[tpm] tpm.sys nao iniciou o TPM: {}", error);
        return;
    }
    debug_print!("[tpm] {}: tpm.sys iniciado (servico TPM)", node.instance_path);
    debug_print!("TPM_STARTED");
    // `--trace-driver-api` rastreia também o que o tbs.sys e o tpm.sys
    // chamam durante os comandos.
    let trace = crate::ntos::init::boot_config::trace_driver_api();
    crate::ntos::init::exports::set_api_trace(trace);
    let result = command_round_trip();
    crate::ntos::init::exports::set_api_trace(false);
    match result {
        Ok(summary) => {
            debug_print!("[tpm] comandos pelo tbs.sys: {}", summary);
            debug_print!("TPM_COMMAND_OK");
        }
        Err(error) => debug_print!("[tpm] comandos pelo tbs.sys: {} ({})", error, describe_tpm_link()),
    }
}
