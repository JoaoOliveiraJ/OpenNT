//! Segurança do Process Manager: o token primário de cada EPROCESS
//! (PsReferencePrimaryToken/PsDereferencePrimaryToken), as consultas de
//! atributos de segurança do token (SeQuerySecurityAttributesToken,
//! PsQueryProcessAttributesByToken) e as células SeTokenObjectType/SeExports.
//!
//! Usam os tokens e as referências mantidos pelo kernel; o gerenciador de
//! processos fornece o token primário de cada EPROCESS e o serializador de
//! atributos calcula o layout nativo da resposta.

use alloc::string::String;
use alloc::vec::Vec;

use super::process;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::UnicodeString;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_data;
use crate::ntos::se::security_attributes::{self, OutputWriter};
use crate::ntos::se::token::tokens::{self, Token};
use crate::rtl::KernelError;

/// Token do kernel; o nome da operação identifica o erro de uso.
fn owned_token(pointer: u64, operation: &str) -> Result<Token, KernelError> {
    tokens::get(pointer).ok_or_else(|| KernelError::new(alloc::format!("{operation}: invalid token")))
}

struct GuestWriter {
    base: u64,
}

impl OutputWriter for GuestWriter {
    // O serializador escolhe os offsets do layout nativo; cada escrita é um MOV.
    fn u8(&mut self, offset: u64, value: u8) {
        guest::write(self.base + offset, value);
    }
    fn u16(&mut self, offset: u64, value: u16) {
        guest::write(self.base + offset, value);
    }
    fn u32(&mut self, offset: u64, value: u32) {
        guest::write(self.base + offset, value);
    }
    fn u64(&mut self, offset: u64, value: u64) {
        guest::write(self.base + offset, value);
    }
}

/// SeQuerySecurityAttributesToken: filtra os atributos do token e os copia
/// para o buffer no layout nativo. Também usado por consumidores internos.
pub fn query_attributes(token_pointer: u64, names_pointer: u64, name_count: u32, output: u64, output_length: u32, returned_length: u64) -> Result<u32, KernelError> {
    if (output != 0) != (output_length != 0) {
        return Ok(0xC000_000D);
    }
    let token = owned_token(token_pointer, "SeQuerySecurityAttributesToken")?;
    // SAFETY: PULONG ReturnLength do chamador de kernel.
    let returned_length = unsafe { Field::<u32>::at(returned_length) };
    returned_length.set(0);
    // A seleção começa com todos; os filtros só valem para a lista não vazia.
    let all = &token.security_attributes;
    let mut selected = all.clone();
    if !all.is_empty() && names_pointer != 0 {
        // Valida todos os UNICODE_STRING antes de ler os nomes.
        let mut descriptors = Vec::new();
        let mut odd_length = false;
        // SAFETY: UNICODE_STRING Attributes[NumberOfAttributes] do chamador de kernel.
        for descriptor in unsafe { UnicodeString::array_at(names_pointer, name_count as usize) } {
            let length = descriptor.length.get();
            let maximum = descriptor.maximum_length.get();
            let text = descriptor.buffer.get();
            if length == 0 || maximum == 0 || length > maximum || text == 0 {
                return Ok(0xC000_000D);
            }
            descriptors.push((text, length));
            if length & 1 != 0 {
                odd_length = true;
            }
        }
        // Só pares completos de bytes viram unidades UTF-16.
        let names: Vec<String> = descriptors
            .iter()
            .map(|&(text, length)| {
                let bytes = guest::read_bytes(text, (length as usize / 2) * 2);
                let units: Vec<u16> = bytes.chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]])).collect();
                String::from_utf16_lossy(&units)
            })
            .collect();
        // Os nomes dos tokens têm comprimento par: um filtro ímpar não casa.
        let filtered = if odd_length { None } else { security_attributes::select(all, Some(&names))? };
        match filtered {
            Some(attributes) => selected = attributes,
            None => return Ok(0xC000_0225),
        }
    } else if !all.is_empty() && name_count != 0 {
        return Err(KernelError::new("SeQuerySecurityAttributesToken: null filter array"));
    }
    // Mede antes de escrever: buffer curto recebe só o tamanho necessário.
    let size = match security_attributes::measure(&selected) {
        Ok(size) => size,
        Err(status) => return Ok(status),
    };
    if (output_length as u64) < size {
        returned_length.set(size as u32);
        return Ok(0xC000_0023);
    }
    // Lista não vazia zera o buffer todo; a vazia toca só o cabeçalho.
    let clear = if all.is_empty() { 16 } else { output_length as u64 };
    guest::write_bytes(output, &alloc::vec![0; clear as usize]);
    let status = security_attributes::copy_out(&selected, output, output_length as u64, &mut GuestWriter { base: output }, !all.is_empty());
    returned_length.set(size as u32);
    Ok(status)
}

/// PsQueryProcessAttributesByToken: presença dos atributos de aplicativo do
/// sistema e de identidade de pacote, independente de flags e valores (nada
/// é deduzido do nome).
pub fn process_attributes(token_pointer: u64, system_application: u64, package_identity: u64) -> Result<u64, KernelError> {
    if system_application == 0 && package_identity == 0 {
        return Ok(0);
    }
    let token = owned_token(token_pointer, "PsQueryProcessAttributesByToken")?;
    let present = |name: &str| -> Result<u8, KernelError> { Ok(security_attributes::select(&token.security_attributes, Some(&[String::from(name)]))?.is_some() as u8) };
    if system_application != 0 {
        // SAFETY: PBOOLEAN de saída do chamador de kernel.
        unsafe { Field::<u8>::at(system_application) }.set(present("WIN://SYSAPPID")?);
    }
    if package_identity != 0 {
        // SAFETY: PBOOLEAN de saída do chamador de kernel.
        unsafe { Field::<u8>::at(package_identity) }.set(present("WIN://PKG")?);
    }
    Ok(0)
}

/// PsReferencePrimaryToken: retém o token primário antes de entregar seu
/// endereço.
pub fn reference_primary_token(process: u64) -> Result<u64, KernelError> {
    let token = process::get_primary_token(process).ok_or_else(|| KernelError::new("PsReferencePrimaryToken: invalid process"))?;
    tokens::retain(token)?;
    Ok(token)
}

/// PsDereferencePrimaryToken: devolve exatamente uma referência adquirida
/// pelo chamador.
pub fn dereference_primary_token(token: u64) -> Result<(), KernelError> {
    if tokens::get(token).is_none() {
        return Err(KernelError::new("PsDereferencePrimaryToken: invalid token"));
    }
    tokens::release(token)?;
    Ok(())
}

/// Célula exportada SeTokenObjectType: o valor é o endereço da célula, não
/// uma cópia.
pub fn token_object_type_cell() -> u64 {
    kernel_data::address("SeTokenObjectType").unwrap_or_else(|error| panic!("SeTokenObjectType: {error}"))
}

/// Célula exportada SeExports.
pub fn exports_cell() -> u64 {
    kernel_data::address("SeExports").unwrap_or_else(|error| panic!("SeExports: {error}"))
}

// ---- ps-impersonation: impersonação de thread (ntoskrnl 19041) -------------
// PsImpersonateClient 0x6d3b80, PsRevertToSelf 0x714500,
// PsReferenceImpersonationTokenEx 0x6cf720, PsDereferenceImpersonationToken
// 0x692740 e PspWriteTebImpersonationInfo 0x6d3f60. O estado vive no
// `se::token::thread` (que publica ETHREAD.ClientSecurity e CrossThreadFlags);
// a política é o SeTokenCanImpersonate de `se::token::impersonation`. O NT
// prefere o AdjustedClientToken (ETHREAD.AdjustedClientToken) quando existe;
// o OpenNT nunca o cria (não há TrustLevelSid). O TEB só é atualizado quando
// o dono da thread é o espaço de endereço corrente (o NT anexa com
// KeStackAttachProcess); TEB e TEB32 são memória de modo usuário, sondada.

const IMPERSONATION_STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const IMPERSONATION_TOKEN_IMPERSONATION: u32 = 2;
const IMPERSONATION_SECURITY_IDENTIFICATION: u32 = 1;
const IMPERSONATION_SECURITY_IMPERSONATION: u32 = 2;
/// IMAGE_FILE_MACHINE_I386 / IMAGE_FILE_MACHINE_ARMNT: processos com TEB32.
const IMPERSONATION_TEB32_MACHINES: [u16; 2] = [0x14C, 0x1C4];
const IMPERSONATION_PAGE_SIZE: u64 = 0x1000;

fn impersonation_thread(thread: u64) -> &'static crate::ntos::inc::types::Ethread {
    // SAFETY: PETHREAD do chamador (vivo enquanto a chamada dura).
    unsafe { crate::ntos::inc::types::Ethread::at(thread) }
}

/// PspWriteTebImpersonationInfo: TEB.IsImpersonating = ActiveImpersonationInfo
/// e TEB.MuiImpersonation = 0, também no TEB32 (TEB + ROUND_TO_PAGES(sizeof
/// TEB)) de processos x86/ARM32. Threads de sistema não têm TEB.
fn write_teb_impersonation_info(thread: u64) {
    use crate::ntos::inc::types::extra_obpsse::Teb32;
    use crate::ntos::inc::types::{Eprocess, Ewow64process, Teb};
    let object = impersonation_thread(thread);
    let teb = object.tcb.teb.get();
    if teb == 0 || object.tcb.system_thread() != 0 {
        return;
    }
    let owner = object.tcb.process.get();
    if owner != process::get_current_process() {
        return;
    }
    let active = crate::ntos::se::token::thread::get(thread).is_some() as u32;
    let Ok(user_teb) = Teb::try_at(teb) else { return };
    let _ = user_teb.is_impersonating.probe_set(active);
    let _ = user_teb.mui_impersonation.probe_set(0);
    // SAFETY: EPROCESS dono da thread, vivo enquanto ela vive.
    let wow64 = unsafe { Eprocess::at(owner) }.wo_w64_process.get();
    if wow64 == 0 {
        return;
    }
    // SAFETY: o EWOW64PROCESS vive enquanto o EPROCESS vive.
    if !IMPERSONATION_TEB32_MACHINES.contains(&unsafe { Ewow64process::at(wow64) }.machine.get()) {
        return;
    }
    let teb32_address = teb + (Teb::SIZE + IMPERSONATION_PAGE_SIZE - 1) / IMPERSONATION_PAGE_SIZE * IMPERSONATION_PAGE_SIZE;
    if let Ok(teb32) = Teb32::try_at(teb32_address) {
        let _ = teb32.is_impersonating.probe_set(active);
        let _ = teb32.mui_impersonation.probe_set(0);
    }
}

/// PsImpersonateClient(Thread, Token, CopyOnOpen, EffectiveOnly, Level):
/// Token NULL encerra a impersonação. Se o primário do dono da thread não
/// pode impersonar o cliente (SeTokenCanImpersonate), a thread recebe uma
/// cópia de identificação (SeCopyClientToken; Anonymous se o próprio token de
/// impersonação já for Anonymous). Devolve o NTSTATUS.
pub fn impersonate_client(thread: u64, token: u64, copy_on_open: bool, effective_only: bool, level: u32) -> Result<u32, KernelError> {
    use crate::ntos::se::token::{impersonation, thread as thread_tokens};
    if token == 0 {
        thread_tokens::release(thread)?;
        write_teb_impersonation_info(thread);
        return Ok(0);
    }
    let mut stored_level = level & 3;
    let mut copy = None;
    if let Some(primary) = process::get_primary_token(impersonation_thread(thread).tcb.process.get()) {
        if impersonation::can_impersonate(primary, token, level).is_err() {
            let (kind, token_level) = tokens::with(token, |record| (record.kind, record.impersonation_level)).ok_or_else(|| KernelError::new("PsImpersonateClient: invalid token"))?;
            let reduced = if kind == IMPERSONATION_TOKEN_IMPERSONATION && (token_level as i32) < IMPERSONATION_SECURITY_IDENTIFICATION as i32 { token_level } else { IMPERSONATION_SECURITY_IDENTIFICATION };
            // Só falhas com NTSTATUS explícito viram retorno, como o
            // SeCopyClientToken; as internas sobem.
            match tokens::duplicate(token, reduced, false, IMPERSONATION_TOKEN_IMPERSONATION) {
                Ok(duplicate) => copy = Some(duplicate),
                Err(error) if error.status != IMPERSONATION_STATUS_UNSUCCESSFUL => return Ok(error.status),
                Err(error) => return Err(error),
            }
            stored_level = reduced & 3;
        }
    }
    // A thread retém a sua referência; a de criação da cópia é devolvida.
    let assigned = thread_tokens::assign(thread, Some(copy.unwrap_or(token)), stored_level, copy_on_open, effective_only);
    if let Some(duplicate) = copy {
        tokens::release(duplicate)?;
    }
    assigned?;
    write_teb_impersonation_info(thread);
    Ok(0)
}

/// PsRevertToSelf = PsImpersonateClient(PsGetCurrentThread(), NULL, FALSE,
/// FALSE, SecurityImpersonation).
pub fn revert_to_self() -> Result<u32, KernelError> {
    impersonate_client(process::get_current_thread(), 0, false, false, IMPERSONATION_SECURITY_IMPERSONATION)
}

/// PsReferenceImpersonationToken(Thread, CopyOnOpen*, EffectiveOnly*,
/// Level*): sem ActiveImpersonationInfo devolve NULL sem tocar nas saídas;
/// senão referencia o token (ObfReferenceObject) e publica CopyTokenOnOpen,
/// EffectiveOnly e o nível de ETHREAD.ClientSecurity.
pub fn reference_impersonation_token(thread: u64, copy_on_open_out: &Field<u8>, effective_only_out: &Field<u8>, level_out: &Field<u32>) -> Result<u64, KernelError> {
    use crate::ntos::ob::{object_reference, reference_trace};
    let Some(state) = crate::ntos::se::token::thread::get(thread) else { return Ok(0) };
    object_reference::reference_with_tag(state.token, reference_trace::DEFAULT_TAG, true)?;
    copy_on_open_out.set(state.copy_on_open as u8);
    level_out.set(state.level & 3);
    effective_only_out.set(state.effective_only as u8);
    Ok(state.token)
}

/// PsDereferenceImpersonationToken: ObDereferenceObject se não for NULL.
pub fn dereference_impersonation_token(token: u64) -> Result<(), KernelError> {
    use crate::ntos::ob::{object_reference, reference_trace};
    if token != 0 {
        object_reference::dereference_with_tag(token, reference_trace::DEFAULT_TAG, true)?;
    }
    Ok(())
}
