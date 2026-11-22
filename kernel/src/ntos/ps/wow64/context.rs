//! O contexto x86 de uma thread WoW64 visto de fora: a classe
//! ThreadWow64Context (29) do NtQueryInformationThread e do
//! NtSetInformationThread, que o wow64cpu usa no GetThreadContext e no
//! SetThreadContext de 32 bits de outra thread (BTCpuGetContext e
//! BTCpuSetContext).
//!
//! O estado x86 de uma thread WoW64 fica em dois lugares. Enquanto ela roda
//! código de 32 bits (CS 0x23), os registradores x86 são os próprios
//! registradores da CPU, e o CONTEXT nativo da thread os guarda quando ela
//! para. Quando ela volta ao código de 64 bits (o wow64cpu, para uma syscall
//! ou uma exceção), o wow64cpu salva os registradores x86 no contexto da
//! área de CPU dela (TEB.TlsSlots[WOW64_TLS_CPURESERVED], `thread.rs`); o x87,
//! o MXCSR, os XMM6-15 e os de depuração continuam só no estado nativo.
//!
//! - [`get`] é o PspWow64GetContextThread (19041 0x67a4ec): o tamanho tem de
//!   ser o do WOW64_CONTEXT (0x2CC, senão STATUS_INFO_LENGTH_MISMATCH) e o
//!   processo da thread WoW64 x86 (senão STATUS_INVALID_PARAMETER); o
//!   ContextFlags do buffer, saneado (RtlpWow64SanitizeContextFlags); a cópia
//!   do contexto da área de CPU (PspWow64ReadOrWriteThreadCpuArea, anexado
//!   ao processo da thread); com a CPU de hardware (o bit
//!   WOW64_CPUFLAGS_SOFTWARE de WOW64INFO.CpuFlags desligado), o CONTEXT
//!   nativo (PspGetContextThreadInternal) e a junção do
//!   RtlpWow64GetContextOnAmd64: o RtlpWow64CtxFromAmd64 converte o nativo
//!   e, se a thread não parou no código de 32 bits, os registradores de
//!   controle, os inteiros, os segmentos e XMM0-5 vêm da área de CPU (e o
//!   CONTEXT_EXCEPTION_REQUEST responde CONTEXT_EXCEPTION_ACTIVE); com a CPU
//!   de software, só a área de CPU (RtlCopyContext). O RtlpWriteExtendedContext
//!   devolve o ContextFlags e os grupos pedidos (RtlpCopyLegacyContextX86).
//! - [`set`] é o PspWow64SetContextThread (0x67a140), o caminho inverso: o
//!   contexto pedido entra no nativo (RtlpWow64CtxToAmd64) e, com a thread
//!   no código de 64 bits, os registradores de controle e os inteiros e
//!   XMM0-5 vão à área de CPU, que pede ao wow64cpu a restauração completa
//!   (WOW64_CPURESERVED.Flags bit 0) quando os inteiros ou os estendidos
//!   mudaram; o x87, o MXCSR e os de depuração vão ao nativo. A área de CPU
//!   volta à thread e o nativo, se mudou, pelo PspSetContextThreadInternal.
//!   Com CheckStackExtents no processo, a thread corrente só troca o ESP por
//!   um dentro da pilha de 32 bits dela (RtlGuardIsValidWow64StackPointer).
//!
//! O CONTEXT_XSTATE de 32 bits segue o WOW64_CONTEXT num CONTEXT_EX (fora
//! dos 0x2CC bytes da classe, como no 19041): é o estado estendido nativo da
//! thread, nos dois sentidos; com a CPU de software, STATUS_NOT_SUPPORTED.

use core::mem::offset_of;

use crate::hal::amd64::usermode::{USER_COMPAT_CS, USER_COMPAT_FS, USER_DS};
use crate::ntos::ex::{push_lock, rundown};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_wow64::{Wow64Context, Wow64CpuReserved, Wow64FloatingSaveArea};
use crate::ntos::inc::types::{Context, Ethread, Kthread, Teb, Teb32, XsaveFormat};
use crate::ntos::ke::critical_region;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::memory_map::USER_ADDRESS_LIMIT;
use crate::ntos::ps::context::xstate as context_xstate;
use crate::ntos::ps::process_context;
use crate::ntos::ps::user::{set_thread_context, state};
use crate::rtl::KernelError;

use super::{TEB32_OFFSET, TLS_CPURESERVED};

/// O tamanho do WOW64_CONTEXT, o único que a classe aceita.
pub const LENGTH: u64 = Wow64Context::SIZE;

const CONTEXT_I386: u32 = 0x1_0000;
const CONTROL: u32 = CONTEXT_I386 | 0x1;
const INTEGER: u32 = CONTEXT_I386 | 0x2;
const SEGMENTS: u32 = CONTEXT_I386 | 0x4;
const FLOATING_POINT: u32 = CONTEXT_I386 | 0x8;
const DEBUG_REGISTERS: u32 = CONTEXT_I386 | 0x10;
const EXTENDED_REGISTERS: u32 = CONTEXT_I386 | 0x20;
const XSTATE: u32 = CONTEXT_I386 | 0x40;
/// O CONTEXT_XSTATE do x64 (os recursos habilitados no KUSER_SHARED_DATA).
const AMD64_XSTATE: u32 = 0x10_0040;
/// CONTEXT_EXCEPTION_REQUEST.
const EXCEPTION_REQUEST: u32 = 0x4000_0000;
/// CONTEXT_EXCEPTION_ACTIVE e CONTEXT_SERVICE_ACTIVE.
const ACTIVE: u32 = 0x1800_0000;
/// CONTEXT_EXCEPTION_REPORTING | CONTEXT_EXCEPTION_ACTIVE.
const REPORTING_EXCEPTION_ACTIVE: u32 = 0x8800_0000;
/// Os bits de estado do ContextFlags (REPORTING, SERVICE_ACTIVE e
/// EXCEPTION_ACTIVE), o complemento da máscara 0x67FFFFFF da cópia.
const REPORTED: u32 = 0x9800_0000;
/// O CONTEXT nativo lido: CONTEXT_AMD64 com CONTROL, INTEGER, SEGMENTS,
/// FLOATING_POINT e DEBUG_REGISTERS.
const NATIVE_ALL: u32 = 0x10_001F;
const NATIVE_FLOATING_POINT: u32 = 0x10_0008;
const NATIVE_DEBUG_REGISTERS: u32 = 0x10_0010;
/// As EFLAGS que o contexto x86 pode trazer, e IF com o bit 1 sempre ligados.
const EFLAGS_MASK: u32 = 0x3F_0DD5;
const EFLAGS_FIXED: u32 = 0x202;
/// Dr7 com algum comparador habilitado (o x64) e os bits locais (L0-L3).
const DR7_ACTIVE: u64 = 0x355;
const DR7_LOCAL: u32 = 0x55;
const DR7_X86_MASK: u32 = 0xFFFF_0155;
/// DR7.LE, que o RtlpWow64CtxToAmd64 liga com endereços sem comparador local.
const DR7_LOCAL_EXACT: u64 = 1 << 8;
/// WOW64_TLS_WOW64INFO e WOW64INFO.CpuFlags (+4) com WOW64_CPUFLAGS_SOFTWARE.
const TLS_WOW64INFO: usize = 10;
const WOW64INFO_CPU_FLAGS: u64 = 4;
const CPUFLAGS_SOFTWARE: u32 = 2;
/// XMM0..XMM5 em ExtendedRegisters (a imagem FXSAVE tem os XMM em +0xA0): os
/// que o wow64cpu salva na área de CPU, voláteis no x64.
const SAVED_XMM: usize = 0xA0;
const SAVED_XMM_BYTES: usize = 6 * 16;
/// Um registrador do x87: 80 bits em cada slot de 16 bytes do FXSAVE.
const X87_REGISTER_BYTES: usize = 10;

const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_THREAD_IS_TERMINATING: u32 = 0xC000_004B;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;

/// Um buffer do pool para as cópias do kernel, devolvido no fim do escopo.
struct Scratch(u64);

impl Scratch {
    fn new(size: u64) -> Result<Self, u32> {
        match guest::alloc_aligned(size, 16, true) {
            0 => Err(STATUS_INSUFFICIENT_RESOURCES),
            address => Ok(Self(address)),
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        guest::free_bytes(self.0);
    }
}

fn x86(address: u64) -> &'static Wow64Context {
    // SAFETY: uma cópia do kernel de LENGTH bytes (`Scratch`).
    unsafe { Wow64Context::at(address) }
}

fn native(address: u64) -> &'static Context {
    // SAFETY: um CONTEXT do kernel de Context::SIZE bytes (`Scratch`).
    unsafe { Context::at(address) }
}

fn selected(flags: u32, group: u32) -> bool {
    flags & group == group
}

/// Um NTSTATUS negativo (aviso ou erro), o `js` depois da chamada.
fn failed(status: u32) -> bool {
    (status as i32) < 0
}

/// Os grupos do contexto x86 como faixas de bytes contíguas.
fn group_ranges(flags: u32) -> impl Iterator<Item = (usize, usize)> {
    let span = |start: usize, end: usize| (start, end - start);
    [
        (CONTROL, span(offset_of!(Wow64Context, ebp), offset_of!(Wow64Context, extended_registers))),
        (INTEGER, span(offset_of!(Wow64Context, edi), offset_of!(Wow64Context, ebp))),
        (SEGMENTS, span(offset_of!(Wow64Context, seg_gs), offset_of!(Wow64Context, edi))),
        (FLOATING_POINT, span(offset_of!(Wow64Context, float_save), offset_of!(Wow64Context, seg_gs))),
        (DEBUG_REGISTERS, span(offset_of!(Wow64Context, dr0), offset_of!(Wow64Context, float_save))),
        (EXTENDED_REGISTERS, span(offset_of!(Wow64Context, extended_registers), Wow64Context::SIZE as usize)),
    ]
    .into_iter()
    .filter(move |&(group, _)| selected(flags, group))
    .map(|(_, range)| range)
}

/// RtlpCopyLegacyContextX86: o ContextFlags (sem os bits de estado, que só
/// voltam com CONTEXT_EXCEPTION_REQUEST) e os grupos selecionados de
/// `source` em `target`, os dois sondados (um deles pode ser do usuário).
fn copy_groups(target: u64, source: u64, flags: u32) -> Result<(), KernelError> {
    let mut written = flags & !REPORTED;
    if flags & EXCEPTION_REQUEST != 0 {
        written |= guest::try_read::<u32>(source)? & REPORTED;
    }
    for (offset, length) in group_ranges(flags) {
        let bytes = guest::try_read_bytes(source + offset as u64, length)?;
        guest::try_write_bytes(target + offset as u64, &bytes)?;
    }
    guest::try_write::<u32>(target, written)
}

/// RtlpWow64SanitizeContextFlags em UserMode: um ContextFlags que não é do
/// x86 (ou sem CONTEXT_i386) vira o do x86 com os grupos reconhecidos; o
/// CONTEXT_XSTATE sem recursos de XSTATE habilitados é STATUS_NOT_SUPPORTED.
pub(crate) fn sanitize(flags: u32) -> Result<u32, u32> {
    let architecture = flags & 0x27FF_FF80 == CONTEXT_I386 || flags & 0x27FF_FFA0 == 0x10_0000;
    let mut status = if architecture { 0 } else { STATUS_INVALID_PARAMETER };
    let xstate = selected(flags, AMD64_XSTATE) || selected(flags, XSTATE);
    if status == 0 && xstate && crate::ntos::ke::xsave::enabled_features() == 0 {
        status = STATUS_NOT_SUPPORTED;
    }
    if status == 0 && flags & CONTEXT_I386 == 0 {
        status = STATUS_INVALID_PARAMETER;
    }
    match status {
        0 => Ok(flags),
        STATUS_INVALID_PARAMETER => Ok((flags | CONTEXT_I386) & 0xD801_007F),
        status => Err(status),
    }
}

/// O `__except` em volta de um acesso a memória de usuário: a falha de sonda
/// vira o NTSTATUS devolvido.
fn guarded<T>(body: impl FnOnce() -> Result<Result<T, u32>, KernelError>) -> Result<Result<T, u32>, KernelError> {
    match body() {
        Err(error) if state::probe_fault(&error) => Ok(Err(error.status)),
        other => other,
    }
}

/// O que o PspWow64ReadOrWriteThreadCpuArea faz com a área de CPU.
#[derive(Clone, Copy)]
enum CpuAreaAccess {
    /// Copia o contexto x86 para `copy`.
    Read { copy: u64 },
    /// Grava `copy` no contexto x86 e `reserved` no WOW64_CPURESERVED.
    Write { copy: u64, reserved: u32 },
}

/// O que sai da área de CPU: o ULONG do WOW64_CPURESERVED (Flags e Machine)
/// e se a CPU é de software.
#[derive(Clone, Copy)]
struct CpuArea {
    reserved: u32,
    software: bool,
}

/// PspWow64ReadOrWriteThreadCpuArea(Process, Thread, Read, Context, ...):
/// sob o ETHREAD.ThreadLock compartilhado, numa região crítica, anexado ao
/// processo da thread. Sem TEB (a thread saindo), STATUS_THREAD_IS_TERMINATING;
/// sem área de CPU, STATUS_INVALID_PARAMETER; uma falha de sonda devolve o
/// código dela.
fn access_cpu_area(process: u64, thread: u64, access: CpuAreaAccess) -> Result<Result<CpuArea, u32>, KernelError> {
    // SAFETY: a ETHREAD retida pelo handle do chamador.
    let lock = unsafe { Ethread::at(thread) }.thread_lock.value.address();
    critical_region::with_critical(|| {
        push_lock::acquire_shared(lock, 0)?;
        // PsGetThreadTeb.
        // SAFETY: a KTHREAD retida pelo handle do chamador.
        let teb = unsafe { Kthread::at(thread) }.teb.get();
        let result = if teb == 0 { Ok(Err(STATUS_THREAD_IS_TERMINATING)) } else { process_context::with_process(process, || guarded(|| access_attached(teb, access))).and_then(|result| result) };
        push_lock::release_shared(lock, 0)?;
        result
    })
}

/// O corpo anexado do PspWow64ReadOrWriteThreadCpuArea: o RtlWow64GetCpuAreaInfo
/// (o contexto x86 logo depois do WOW64_CPURESERVED, alinhado a 4), a cópia
/// num sentido ou no outro e o WOW64INFO.CpuFlags (TlsSlots[WOW64_TLS_WOW64INFO]).
fn access_attached(teb: u64, access: CpuAreaAccess) -> Result<Result<CpuArea, u32>, KernelError> {
    let slots = &state::user_struct::<Teb>(teb)?.tls_slots;
    let cpu_area = slots[TLS_CPURESERVED].probe_get()?;
    if cpu_area == 0 {
        return Ok(Err(STATUS_INVALID_PARAMETER));
    }
    let context = (cpu_area + Wow64CpuReserved::CONTEXT_OFFSET + 3) & !3;
    if context.checked_add(LENGTH).is_none_or(|end| end > USER_ADDRESS_LIMIT) {
        return Ok(Err(STATUS_ACCESS_VIOLATION));
    }
    let reserved = match access {
        CpuAreaAccess::Read { copy } => {
            guest::write_bytes(copy, &guest::try_read_bytes(context, LENGTH as usize)?);
            guest::try_read::<u32>(cpu_area)?
        }
        CpuAreaAccess::Write { copy, reserved } => {
            if !state::probe_user_write(context, LENGTH) {
                return Ok(Err(STATUS_ACCESS_VIOLATION));
            }
            guest::try_write_bytes(context, &guest::read_bytes(copy, LENGTH as usize))?;
            guest::try_write::<u32>(cpu_area, reserved)?;
            reserved
        }
    };
    let info = slots[TLS_WOW64INFO].probe_get()?;
    let software = if info == 0 {
        false
    } else if info & 3 != 0 {
        return Ok(Err(STATUS_DATATYPE_MISALIGNMENT));
    } else {
        guest::try_read::<u32>(info + WOW64INFO_CPU_FLAGS)? & CPUFLAGS_SOFTWARE != 0
    };
    Ok(Ok(CpuArea { reserved, software }))
}

/// RtlFxToFnFrame: a imagem FXSAVE do x64 no formato FNSAVE do
/// FLOATING_SAVE_AREA do x86. O seletor de erro leva o opcode na metade de
/// cima; cada registrador da pilha do x87 (ST(i)) vai inteiro (80 bits); a
/// palavra de tags completa sai da abreviada, físico 7 primeiro, com a
/// classe do valor em cada registrador ocupado: 1 zero, 0 válido, 2 especial
/// (infinito, NaN, denormal ou não normalizado); 3 vazio.
pub(crate) fn fx_to_fn(target: &Wow64FloatingSaveArea, source: &XsaveFormat) {
    target.control_word.set(source.control_word.get() as u32);
    target.status_word.set(source.status_word.get() as u32);
    target.error_offset.set(source.error_offset.get());
    target.error_selector.set((source.error_opcode.get() as u32) << 16 | source.error_selector.get() as u32);
    target.data_offset.set(source.data_offset.get());
    target.data_selector.set(source.data_selector.get() as u32);
    let top = (source.status_word.get() >> 11) & 7;
    let mut physical = (7 - top) as usize;
    let mut abridged = source.tag_word.get();
    let mut tags: u16 = 0;
    for (index, register) in source.float_registers.iter().enumerate() {
        let bytes = guest::read_bytes(register.low.address(), X87_REGISTER_BYTES);
        guest::write_bytes(target.register_area[index * X87_REGISTER_BYTES].address(), &bytes);
        tags <<= 2;
        if abridged & 0x80 != 0 {
            tags |= 2;
            let value = &source.float_registers[physical];
            let exponent = value.high.get() as u16 & 0x7FFF;
            let mantissa = value.low.get();
            if exponent == 0 {
                if mantissa == 0 {
                    tags = (tags & !2) | 1;
                }
            } else if exponent != 0x7FFF && (mantissa as i64) < 0 {
                tags &= !3;
            }
        } else {
            tags |= 3;
        }
        abridged <<= 1;
        physical = physical.wrapping_sub(1) & 7;
    }
    target.tag_word.set(tags as u32);
}

/// RtlFnToFxFrame: o FLOATING_SAVE_AREA do x86 na imagem FXSAVE do x64 (o
/// resto da imagem fica): a tag abreviada marca ocupado cada registrador
/// cuja tag completa não é vazia.
pub(crate) fn fn_to_fx(target: &XsaveFormat, source: &Wow64FloatingSaveArea) {
    target.control_word.set(source.control_word.get() as u16);
    target.status_word.set(source.status_word.get() as u16);
    target.error_offset.set(source.error_offset.get());
    target.error_selector.set(source.error_selector.get() as u16);
    target.error_opcode.set((source.error_selector.get() >> 16) as u16);
    target.data_offset.set(source.data_offset.get());
    target.data_selector.set(source.data_selector.get() as u16);
    let mut tags = source.tag_word.get() as u16;
    let mut abridged: u8 = 0;
    for (index, register) in target.float_registers.iter().enumerate() {
        let bytes = guest::read_bytes(source.register_area[index * X87_REGISTER_BYTES].address(), X87_REGISTER_BYTES);
        guest::write_bytes(register.low.address(), &bytes);
        abridged = (abridged << 1) | (tags & 0xC000 != 0xC000) as u8;
        tags <<= 2;
    }
    target.tag_word.set(abridged);
}

/// RtlpWow64CtxFromAmd64(Flags, Amd64Context, X86Context): os grupos
/// pedidos do CONTEXT nativo no contexto x86 (os segmentos são os fixos do
/// modo de compatibilidade) e o ContextFlags, com os bits de estado do
/// nativo se o pedido tem CONTEXT_EXCEPTION_REQUEST.
fn ctx_from_amd64(flags: u32, source: &Context, target: &Wow64Context) {
    if selected(flags, CONTROL) {
        target.ebp.set(source.rbp.get() as u32);
        target.seg_cs.set(USER_COMPAT_CS as u32);
        target.eip.set(source.rip.get() as u32);
        target.seg_ss.set(USER_DS as u32);
        target.esp.set(source.rsp.get() as u32);
        target.e_flags.set(source.e_flags.get());
    }
    if selected(flags, INTEGER) {
        for (to, from) in integer_registers(target).into_iter().zip(native_integer_registers(source)) {
            to.set(from.get() as u32);
        }
    }
    if selected(flags, SEGMENTS) {
        fixed_segments(target);
    }
    if selected(flags, EXTENDED_REGISTERS) {
        guest::write_bytes(target.extended_registers.as_ptr() as u64, &guest::read_bytes(source.flt_save.control_word.address(), XsaveFormat::SIZE as usize));
    }
    if selected(flags, FLOATING_POINT) {
        target.float_save.cr0_npx_state.set(0);
        fx_to_fn(&target.float_save, &source.flt_save);
    }
    if selected(flags, DEBUG_REGISTERS) {
        let active = source.dr7.get() & DR7_ACTIVE != 0;
        for (to, from) in debug_registers(target).into_iter().zip(native_debug_registers(source)) {
            to.set(if active { from.get() as u32 } else { 0 });
        }
        if active {
            target.dr7.set(source.dr7.get() as u32 & DR7_X86_MASK);
        }
    }
    let flags = if flags & EXCEPTION_REQUEST != 0 { (flags & !REPORTED) | (source.context_flags.get() & REPORTED) } else { flags };
    target.context_flags.set(flags);
}

/// RtlpWow64CtxToAmd64(Flags, X86Context, Amd64Context): os grupos pedidos
/// do contexto x86 no CONTEXT nativo. Com a thread fora do código de 32 bits,
/// os registradores de controle, os inteiros e os segmentos ficam (estão na
/// área de CPU).
fn ctx_to_amd64(flags: u32, source: &Wow64Context, target: &Context) {
    let flags = if target.seg_cs.get() == USER_COMPAT_CS { flags } else { (flags & !7) | CONTEXT_I386 };
    if selected(flags, CONTROL) {
        target.seg_cs.set(USER_COMPAT_CS);
        target.seg_ss.set(USER_DS);
        target.rip.set(source.eip.get() as u64);
        target.rbp.set(source.ebp.get() as u64);
        target.rsp.set(source.esp.get() as u64);
        target.e_flags.set(source.e_flags.get());
    }
    if selected(flags, INTEGER) {
        for (to, from) in native_integer_registers(target).into_iter().zip(integer_registers(source)) {
            to.set(from.get() as u64);
        }
    }
    if selected(flags, EXTENDED_REGISTERS) {
        guest::write_bytes(target.flt_save.control_word.address(), &guest::read_bytes(source.extended_registers.as_ptr() as u64, XsaveFormat::SIZE as usize));
        target.mx_csr.set(target.flt_save.mx_csr.get());
    }
    if selected(flags, FLOATING_POINT) {
        fn_to_fx(&target.flt_save, &source.float_save);
    }
    if selected(flags, DEBUG_REGISTERS) {
        for (to, from) in native_debug_registers(target).into_iter().zip(debug_registers(source)) {
            to.set(from.get() as u64);
        }
        let addresses = [&source.dr0, &source.dr1, &source.dr2, &source.dr3];
        if source.dr7.get() & DR7_LOCAL == 0 && addresses.iter().any(|address| address.get() != 0) {
            target.dr7.set(target.dr7.get() | DR7_LOCAL_EXACT);
        }
    }
}

/// Edi, Esi, Ebx, Edx, Ecx e Eax.
fn integer_registers(context: &Wow64Context) -> [&crate::ntos::inc::field::Field<u32>; 6] {
    [&context.edi, &context.esi, &context.ebx, &context.edx, &context.ecx, &context.eax]
}

/// Rdi, Rsi, Rbx, Rdx, Rcx e Rax, na ordem de [`integer_registers`].
fn native_integer_registers(context: &Context) -> [&crate::ntos::inc::field::Field<u64>; 6] {
    [&context.rdi, &context.rsi, &context.rbx, &context.rdx, &context.rcx, &context.rax]
}

/// Dr0..Dr3, Dr6 e Dr7.
fn debug_registers(context: &Wow64Context) -> [&crate::ntos::inc::field::Field<u32>; 6] {
    [&context.dr0, &context.dr1, &context.dr2, &context.dr3, &context.dr6, &context.dr7]
}

fn native_debug_registers(context: &Context) -> [&crate::ntos::inc::field::Field<u64>; 6] {
    [&context.dr0, &context.dr1, &context.dr2, &context.dr3, &context.dr6, &context.dr7]
}

/// Os segmentos de dados fixos do código de 32 bits: DS, ES e GS no
/// KGDT64_R3_DATA e FS no descritor da TEB de 32 bits.
fn fixed_segments(context: &Wow64Context) {
    context.seg_gs.set(USER_DS as u32);
    context.seg_es.set(USER_DS as u32);
    context.seg_ds.set(USER_DS as u32);
    context.seg_fs.set(USER_COMPAT_FS as u32);
}

/// Os XMM0-5 de ExtendedRegisters de `source` em `target`.
fn copy_saved_xmm(target: &Wow64Context, source: &Wow64Context) {
    let offset = |context: &Wow64Context| context.extended_registers[SAVED_XMM].address();
    guest::write_bytes(offset(target), &guest::read_bytes(offset(source), SAVED_XMM_BYTES));
}

/// RtlpWow64GetContextOnAmd64(CpuAreaContext, Amd64Context, X86Context).
pub(crate) fn get_context_on_amd64(cpu: &Wow64Context, source: &Context, target: &Wow64Context) -> u32 {
    let flags = target.context_flags.get();
    if flags & 0x27FF_FF80 != CONTEXT_I386 {
        return STATUS_INVALID_PARAMETER;
    }
    ctx_from_amd64(flags, source, target);
    // Parada no código de 32 bits: tudo estava nos registradores.
    if source.seg_cs.get() == USER_COMPAT_CS {
        return 0;
    }
    if selected(flags, CONTROL) {
        target.ebp.set(cpu.ebp.get());
        target.eip.set(cpu.eip.get());
        target.seg_cs.set(USER_COMPAT_CS as u32);
        target.e_flags.set((cpu.e_flags.get() & EFLAGS_MASK) | EFLAGS_FIXED);
        target.esp.set(cpu.esp.get());
        target.seg_ss.set(USER_DS as u32);
    }
    if selected(flags, INTEGER) {
        for (to, from) in integer_registers(target).into_iter().zip(integer_registers(cpu)) {
            to.set(from.get());
        }
    }
    if selected(flags, SEGMENTS) {
        fixed_segments(target);
    }
    if selected(flags, EXTENDED_REGISTERS) {
        copy_saved_xmm(target, cpu);
    }
    // No código de 64 bits a thread está, para o x86, numa transição.
    let reported = target.context_flags.get();
    if flags & EXCEPTION_REQUEST != 0 && reported & ACTIVE == 0 {
        target.context_flags.set(reported | REPORTING_EXCEPTION_ACTIVE);
    }
    0
}

/// RtlpWow64SetContextOnAmd64(CpuAreaContext, Amd64Context, X86Context,
/// &Amd64Changed): o contexto pedido no nativo e, com a thread no código de
/// 64 bits, na área de CPU; devolve se o nativo mudou.
pub(crate) fn set_context_on_amd64(cpu: &Wow64Context, target: &Context, source: &Wow64Context) -> bool {
    let flags = source.context_flags.get();
    let stopped_in_x86 = target.seg_cs.get() == USER_COMPAT_CS;
    ctx_to_amd64(flags, source, target);
    if stopped_in_x86 {
        return true;
    }
    if selected(flags, CONTROL) {
        cpu.ebp.set(source.ebp.get());
        cpu.eip.set(source.eip.get());
        cpu.seg_cs.set(USER_COMPAT_CS as u32);
        cpu.e_flags.set((source.e_flags.get() & EFLAGS_MASK) | EFLAGS_FIXED);
        cpu.esp.set(source.esp.get());
        cpu.seg_ss.set(source.seg_ss.get());
    }
    if selected(flags, INTEGER) {
        for (to, from) in integer_registers(cpu).into_iter().zip(integer_registers(source)) {
            to.set(from.get());
        }
    }
    // O que fica no estado nativo: o x87 e o MXCSR (também com os
    // estendidos, cujos XMM6-15 são do nativo), os de depuração e o XSTATE.
    let mut native = if selected(flags, FLOATING_POINT) { NATIVE_FLOATING_POINT } else { 0 };
    if selected(flags, DEBUG_REGISTERS) {
        native |= NATIVE_DEBUG_REGISTERS;
    }
    if selected(flags, EXTENDED_REGISTERS) {
        copy_saved_xmm(cpu, source);
        native |= NATIVE_FLOATING_POINT;
    }
    if selected(flags, XSTATE) {
        native |= AMD64_XSTATE;
    }
    if native == 0 {
        return false;
    }
    target.context_flags.set(native);
    true
}

/// O processo da thread, se é WoW64 x86.
fn wow64_process(thread: u64) -> Option<u64> {
    // SAFETY: a KTHREAD retida pelo handle do chamador.
    let process = unsafe { Kthread::at(thread) }.process.get();
    super::is_x86_process(process).then_some(process)
}

/// O ContextFlags do buffer do chamador, sondado e saneado.
fn requested_flags(buffer: u64) -> Result<Result<u32, u32>, KernelError> {
    let flags = match guest::try_read::<u32>(buffer.min(USER_ADDRESS_LIMIT)) {
        Ok(flags) => flags,
        Err(error) if state::probe_fault(&error) => return Ok(Err(error.status)),
        Err(error) => return Err(error),
    };
    Ok(sanitize(flags))
}

/// O CONTEXT nativo de uma operação: uma cópia simples, ou, com o
/// CONTEXT_XSTATE de 32 bits, o CONTEXT estendido nativo cujo pedaço XSTATE
/// é o do chamador (o PspWow64SetContextThread aponta o XState do CONTEXT_EX
/// nativo para o do contexto x86).
enum NativeStorage {
    Plain(Scratch),
    Extended(context_xstate::Extended),
}

impl NativeStorage {
    fn address(&self) -> u64 {
        match self {
            Self::Plain(scratch) => scratch.0,
            Self::Extended(extended) => extended.context(),
        }
    }
}

/// O CONTEXT nativo da thread (PspGetContextThreadInternal com KernelMode
/// para o buffer) com `flags`.
fn native_context(thread: u64, storage: &NativeStorage, flags: u32) -> Result<u32, KernelError> {
    native(storage.address()).context_flags.set(flags);
    set_thread_context::get_kernel(thread, storage.address())
}

/// PspWow64GetContextThread(Thread, Context, Length, UserMode): o NTSTATUS;
/// `buffer` já foi sondado para escrita pelo NtQueryInformationThread. O
/// CONTEXT_XSTATE de 32 bits é o estado estendido nativo da thread (os YMM
/// altos e o resto), no pedaço do CONTEXT_EX que segue o WOW64_CONTEXT.
pub fn get(thread: u64, buffer: u64, length: u64) -> Result<u32, KernelError> {
    if length != LENGTH {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    let Some(process) = wow64_process(thread) else { return Ok(STATUS_INVALID_PARAMETER) };
    let flags = match requested_flags(buffer)? {
        Ok(flags) => flags,
        Err(status) => return Ok(status),
    };
    let xstate = selected(flags, XSTATE);
    // RtlpReadExtendedContext: o CONTEXT_EX do chamador conferido e os grupos
    // pedidos do buffer dele.
    if xstate {
        if let Err(status) = guarded(|| context_xstate::user_chunk_after(buffer, LENGTH as u32))? {
            return Ok(status);
        }
    }
    let (output, cpu) = match (Scratch::new(LENGTH), Scratch::new(LENGTH)) {
        (Ok(output), Ok(cpu)) => (output, cpu),
        _ => return Ok(STATUS_INSUFFICIENT_RESOURCES),
    };
    if let Err(status) = guarded(|| copy_groups(output.0, buffer, flags).map(Ok))? {
        return Ok(status);
    }
    x86(output.0).context_flags.set(flags);
    let area = match access_cpu_area(process, thread, CpuAreaAccess::Read { copy: cpu.0 })? {
        Ok(area) => area,
        Err(status) => return Ok(status),
    };
    if area.software {
        if xstate {
            return Ok(STATUS_NOT_SUPPORTED);
        }
        // RtlCopyContext: só a área de CPU.
        copy_groups(output.0, cpu.0, flags)?;
    } else {
        let storage = match Scratch::new(Context::SIZE) {
            Ok(scratch) => NativeStorage::Plain(scratch),
            Err(status) => return Ok(status),
        };
        let status = native_context(thread, &storage, EXCEPTION_REQUEST | NATIVE_ALL)?;
        if failed(status) {
            return Ok(status);
        }
        let status = get_context_on_amd64(x86(cpu.0), native(storage.address()), x86(output.0));
        if status != 0 {
            return Ok(status);
        }
    }
    // RtlpWriteExtendedContext: o ContextFlags, os grupos pedidos e o pedaço
    // XSTATE.
    if let Err(status) = guarded(|| copy_groups(buffer, output.0, flags).map(Ok))? {
        return Ok(status);
    }
    if !xstate {
        return Ok(0);
    }
    state::guarded(|| context_xstate::write_user_after(thread, buffer, LENGTH as u32))
}

/// RtlGuardIsValidWow64StackPointer(Esp, Teb): o ESP dentro da pilha de 32
/// bits da thread (NT_TIB32 da TEB de 32 bits).
fn valid_wow64_stack_pointer(esp: u32, teb: u64) -> Result<bool, KernelError> {
    let tib = &state::user_struct::<Teb32>(teb + TEB32_OFFSET)?.nt_tib;
    Ok(esp >= tib.stack_limit.probe_get()? && esp <= tib.stack_base.probe_get()?)
}

/// PspWow64SetContextThread(Thread, Context, Length, UserMode): o NTSTATUS;
/// `buffer` já foi sondado para leitura pelo NtSetInformationThread. O
/// CONTEXT_XSTATE de 32 bits vai ao estado estendido nativo da thread.
pub fn set(thread: u64, buffer: u64, length: u64) -> Result<u32, KernelError> {
    if length != LENGTH {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    let Some(process) = wow64_process(thread) else { return Ok(STATUS_INVALID_PARAMETER) };
    let flags = match requested_flags(buffer)? {
        Ok(flags) => flags,
        Err(status) => return Ok(status),
    };
    let xstate = selected(flags, XSTATE);
    // RtlpReadExtendedContext: o pedaço XSTATE do chamador num CONTEXT
    // estendido nativo, que será o CONTEXT nativo da operação.
    let storage = if xstate {
        match guarded(|| context_xstate::capture_user_after(buffer, LENGTH as u32, NATIVE_ALL | AMD64_XSTATE))? {
            Ok(extended) => NativeStorage::Extended(extended),
            Err(status) => return Ok(status),
        }
    } else {
        match Scratch::new(Context::SIZE) {
            Ok(scratch) => NativeStorage::Plain(scratch),
            Err(status) => return Ok(status),
        }
    };
    let (input, cpu) = match (Scratch::new(LENGTH), Scratch::new(LENGTH)) {
        (Ok(input), Ok(cpu)) => (input, cpu),
        _ => return Ok(STATUS_INSUFFICIENT_RESOURCES),
    };
    if let Err(status) = guarded(|| copy_groups(input.0, buffer, flags).map(Ok))? {
        return Ok(status);
    }
    x86(input.0).context_flags.set(flags);
    // A thread corrente de um processo com CheckStackExtents só aceita um
    // ESP dentro da própria pilha de 32 bits.
    // SAFETY: a KTHREAD retida pelo handle e o EPROCESS dela.
    let (kthread, eprocess) = unsafe { (Kthread::at(thread), crate::ntos::inc::types::Eprocess::at(process)) };
    if thread == crate::ntos::ps::process::get_current_thread() && eprocess.pcb.check_stack_extents() != 0 && selected(flags, CONTROL) {
        match guarded(|| valid_wow64_stack_pointer(x86(input.0).esp.get(), kthread.teb.get()).map(Ok))? {
            Ok(true) => {}
            Ok(false) => return Ok(STATUS_INVALID_PARAMETER),
            Err(status) => return Ok(status),
        }
    }
    let area = match access_cpu_area(process, thread, CpuAreaAccess::Read { copy: cpu.0 })? {
        Ok(area) => area,
        Err(status) => return Ok(status),
    };
    let mut reserved = area.reserved;
    let mut native_changed = false;
    if area.software {
        if xstate {
            return Ok(STATUS_NOT_SUPPORTED);
        }
        copy_groups(cpu.0, input.0, flags)?;
    } else {
        let status = native_context(thread, &storage, NATIVE_ALL)?;
        if failed(status) {
            return Ok(status);
        }
        let target = native(storage.address());
        native_changed = set_context_on_amd64(x86(cpu.0), target, x86(input.0));
        // Fora do código de 32 bits, o wow64cpu recarrega tudo da área de CPU
        // quando os inteiros, os estendidos ou o XSTATE mudaram.
        if target.seg_cs.get() != USER_COMPAT_CS && (xstate || selected(flags, INTEGER) || selected(flags, EXTENDED_REGISTERS)) {
            reserved |= Wow64CpuReserved::FLAG_RESET_STATE as u32;
        }
        if native_changed && xstate {
            target.context_flags.set(target.context_flags.get() | AMD64_XSTATE);
        }
    }
    if let Err(status) = access_cpu_area(process, thread, CpuAreaAccess::Write { copy: cpu.0, reserved })? {
        return Ok(status);
    }
    if !native_changed {
        return Ok(0);
    }
    set_thread_context::execute(thread, storage.address(), 0, 1)
}

/// ExAcquireRundownProtection da ETHREAD em volta do PspWow64SetContextThread
/// (o ramo da classe 29 do NtSetInformationThread, 0x64b078): uma thread que
/// já passou pela rundown dá STATUS_THREAD_IS_TERMINATING.
pub fn set_protected(thread: u64, buffer: u64, length: u64) -> Result<u32, KernelError> {
    // SAFETY: a ETHREAD retida pelo handle do chamador.
    let protection = unsafe { Ethread::at(thread) }.rundown_protect.count.address();
    if !rundown::acquire(protection)? {
        return Ok(STATUS_THREAD_IS_TERMINATING);
    }
    let result = set(thread, buffer, length);
    rundown::release(protection)?;
    result
}

