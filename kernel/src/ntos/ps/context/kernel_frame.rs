//! Vista NT de um frame de interrupção de kernel real.
//!
//! Cada registrador gravável tem uma posição restaurada pelos stubs de IRQ
//! (IRETQ). Não é o CONTEXT do chamador do gateway e não inventa um PC
//! interrompido.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::ntos::ps::context::registers;
use crate::hal::cpu;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{Context, Ethread, KnonvolatileContextPointers, KtrapFrame, M128a, MachineFrame, XsaveFormat};
use crate::ntos::ke::irql;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

/// HAL: seis empilhamentos não voláteis, nove voláteis, vetor e cinco
/// palavras de hardware. O RSP é o salvo pelo hardware. Ordem: Rax..R15 do
/// CONTEXT.
const RAW: [u64; 16] = [112, 104, 96, 40, 152, 32, 88, 80, 72, 64, 56, 48, 24, 16, 8, 0];
/// O quadro IRET de hardware (MACHINE_FRAME) no quadro do HAL, antes do
/// código de erro opcional.
const HARDWARE_FRAME: u64 = 128;
/// Estado do processador salvo pelo HAL: Dr0..Dr3, Dr6 e Dr7, GsBase e os
/// seletores Ds/Es/Fs/Gs.
const CPU_DEBUG_BYTES: u64 = 48;
const CPU_GS_BASE: u64 = 48;
const CPU_SELECTORS: u64 = 56;
/// KGDT64_R0_CODE.
const KERNEL_CODE_SELECTOR: u16 = 0x10;
/// CONTEXT_AMD64 | CONTEXT_ALL.
const CONTEXT_KERNEL_FLAGS: u32 = 0x10_001F;

/// Área de trabalho do despacho (layout do OpenNT): KTRAP_FRAME publicado
/// em KTHREAD.TrapFrame, o CONTEXT equivalente, os ponteiros não voláteis
/// e uma imagem FXSAVE do processador corrente.
#[repr(C)]
struct Workspace {
    trap: KtrapFrame,
    context: Context,
    _pad_660: Reserved<0x20>,
    pointers: KnonvolatileContextPointers,
    controls: XsaveFormat,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for Workspace {}

const _: () = {
    assert!(core::mem::offset_of!(Workspace, context) == 0x190);
    assert!(core::mem::offset_of!(Workspace, pointers) == 0x680);
    assert!(core::mem::offset_of!(Workspace, controls) == 0x780);
    assert!(core::mem::size_of::<Workspace>() == 0x980);
};

#[derive(Clone, Copy)]
struct Entry {
    thread: u64,
    workspace: u64,
}

impl Entry {
    fn space(&self) -> &'static Workspace {
        // SAFETY: a área de trabalho do despacho, viva enquanto a entrada
        // estiver em ACTIVE (a duração de `with_interrupt`).
        unsafe { Workspace::at(self.workspace) }
    }

    fn thread(&self) -> &'static Ethread {
        // SAFETY: a thread corrente durante o despacho.
        unsafe { Ethread::at(self.thread) }
    }
}

static ACTIVE: SpinLock<BTreeMap<u64, Vec<Entry>>> = SpinLock::new(BTreeMap::new());

fn copy(to: u64, from: u64, size: u64) {
    registers::copy(to, from, size);
}

/// Uma célula de 64 bits por ponteiro (slots do quadro do HAL e os alvos
/// de KNONVOLATILE_CONTEXT_POINTERS).
fn qword(address: u64) -> &'static Field<u64> {
    // SAFETY: slots do quadro de interrupção vivo ou campos da área de trabalho.
    unsafe { Field::<u64>::at(address) }
}

fn m128(address: u64) -> &'static M128a {
    // SAFETY: FloatingContext aponta para XMMs da área de trabalho.
    unsafe { M128a::at(address) }
}

fn copy_m128(target: &M128a, source: &M128a) {
    target.low.set(source.low.get());
    target.high.set(source.high.get());
}

/// Rax..R15 na ordem do CONTEXT (com Rsp).
fn registers_of(context: &Context) -> [&Field<u64>; 16] {
    [
        &context.rax, &context.rcx, &context.rdx, &context.rbx, &context.rsp, &context.rbp, &context.rsi, &context.rdi,
        &context.r8, &context.r9, &context.r10, &context.r11, &context.r12, &context.r13, &context.r14, &context.r15,
    ]
}

/// Voláteis guardados no KTRAP_FRAME: (CONTEXT, KTRAP_FRAME).
fn volatile<'a>(context: &'a Context, trap: &'a KtrapFrame) -> [(&'a Field<u64>, &'a Field<u64>); 7] {
    [
        (&context.rax, &trap.rax),
        (&context.rcx, &trap.rcx),
        (&context.rdx, &trap.rdx),
        (&context.r8, &trap.r8),
        (&context.r9, &trap.r9),
        (&context.r10, &trap.r10),
        (&context.r11, &trap.r11),
    ]
}

/// Não voláteis: (CONTEXT, slot de IntegerContext, campo do trap quando houver).
type Nonvolatile<'a> = (&'a Field<u64>, &'a Field<u64>, Option<&'a Field<u64>>);

fn nonvolatile<'a>(context: &'a Context, pointers: &'a KnonvolatileContextPointers, trap: &'a KtrapFrame) -> [Nonvolatile<'a>; 8] {
    [
        (&context.rbx, &pointers.rbx, Some(&trap.rbx)),
        (&context.rbp, &pointers.rbp, Some(&trap.rbp)),
        (&context.rsi, &pointers.rsi, Some(&trap.rsi)),
        (&context.rdi, &pointers.rdi, Some(&trap.rdi)),
        (&context.r12, &pointers.r12, None),
        (&context.r13, &pointers.r13, None),
        (&context.r14, &pointers.r14, None),
        (&context.r15, &pointers.r15, None),
    ]
}

fn debug<'a>(context: &'a Context, trap: &'a KtrapFrame) -> [(&'a Field<u64>, &'a Field<u64>); 6] {
    [
        (&context.dr0, &trap.dr0),
        (&context.dr1, &trap.dr1),
        (&context.dr2, &trap.dr2),
        (&context.dr3, &trap.dr3),
        (&context.dr6, &trap.dr6),
        (&context.dr7, &trap.dr7),
    ]
}

/// Xmm0..5 ficam no KTRAP_FRAME; Xmm6..15 por FloatingContext.
fn trap_xmm(trap: &KtrapFrame, pointers: &KnonvolatileContextPointers, index: usize) -> &'static M128a {
    let address = match index {
        0 => trap.xmm0.address(),
        1 => trap.xmm1.address(),
        2 => trap.xmm2.address(),
        3 => trap.xmm3.address(),
        4 => trap.xmm4.address(),
        5 => trap.xmm5.address(),
        _ => pointers.floating_context[index].get(),
    };
    m128(address)
}

fn control_from_trap(context: &Context, trap: &KtrapFrame) {
    context.rip.set(trap.rip.get());
    context.rsp.set(trap.rsp.get());
    context.seg_cs.set(trap.seg_cs.get());
    context.seg_ss.set(trap.seg_ss.get());
    context.e_flags.set(trap.e_flags.get());
    context.mx_csr.set(trap.mx_csr.get());
}

fn control_to_trap(trap: &KtrapFrame, context: &Context) {
    trap.rip.set(context.rip.get());
    trap.rsp.set(context.rsp.get());
    trap.seg_cs.set(context.seg_cs.get());
    trap.seg_ss.set(context.seg_ss.get());
    trap.e_flags.set(context.e_flags.get());
    trap.mx_csr.set(context.mx_csr.get());
}

fn from_trap(entry: &Entry) {
    let space = entry.space();
    let (context, trap, pointers) = (&space.context, &space.trap, &space.pointers);
    control_from_trap(context, trap);
    for (target, source) in volatile(context, trap) {
        target.set(source.get());
    }
    for (target, slot, _) in nonvolatile(context, pointers, trap) {
        target.set(qword(slot.get()).get());
    }
    for (index, target) in context.flt_save.xmm_registers.iter().enumerate() {
        copy_m128(target, trap_xmm(trap, pointers, index));
    }
    for (target, source) in debug(context, trap) {
        target.set(source.get());
    }
    context.flt_save.mx_csr.set(context.mx_csr.get());
}

fn to_trap(entry: &Entry) {
    let space = entry.space();
    let (context, trap, pointers) = (&space.context, &space.trap, &space.pointers);
    control_to_trap(trap, context);
    for (source, target) in volatile(context, trap) {
        target.set(source.get());
    }
    for (source, slot, _) in nonvolatile(context, pointers, trap) {
        qword(slot.get()).set(source.get());
    }
    for (index, source) in context.flt_save.xmm_registers.iter().enumerate() {
        copy_m128(trap_xmm(trap, pointers, index), source);
    }
    for (source, target) in debug(context, trap) {
        target.set(source.get());
    }
}

/// Expõe o frame de uma interrupção de kernel como KTRAP_FRAME/CONTEXT
/// durante `action` e devolve ao frame o que a ação alterou.
pub fn with_interrupt<R>(registers_frame: u64, fx: u64, cpu_state: u64, workspace: u64, action: impl FnOnce() -> R, hardware_offset: u64) -> Result<R, KernelError> {
    if hardware_offset != 0 && hardware_offset != 8 {
        return Err(KernelError::new("invalid hardware exception frame"));
    }
    let raw: Vec<u64> = RAW.iter().enumerate().map(|(index, &offset)| offset + if index == 4 { hardware_offset } else { 0 }).collect();
    // SAFETY: o quadro do HAL traz o IRET de hardware depois do código de erro opcional.
    let machine = unsafe { MachineFrame::at(registers_frame + HARDWARE_FRAME + hardware_offset) };
    // Frames de usuário pertencem ao escalonador de usuário; o bootstrap
    // pode rodar antes de existir um ETHREAD.
    if machine.seg_cs.get() != KERNEL_CODE_SELECTOR {
        return Ok(action());
    }
    let thread = process::get_current_thread();
    if thread == 0 {
        return Ok(action());
    }
    let entry = Entry { thread, workspace };
    let (space, owner) = (entry.space(), entry.thread());
    let (context, trap, pointers) = (&space.context, &space.trap, &space.pointers);
    // SAFETY: a imagem FXSAVE salva pelo HAL.
    let saved_fx = unsafe { XsaveFormat::at(fx) };
    let old_trap = owner.tcb.trap_frame.get();
    context.context_flags.set(CONTEXT_KERNEL_FLAGS);
    for (target, &offset) in registers_of(context).into_iter().zip(&raw) {
        target.set(qword(registers_frame + offset).get());
    }
    context.rip.set(machine.rip.get());
    copy(context.flt_save.address(), fx, XsaveFormat::SIZE);
    context.seg_cs.set(machine.seg_cs.get());
    context.seg_ss.set(machine.seg_ss.get());
    context.e_flags.set(machine.e_flags.get());
    context.mx_csr.set(saved_fx.mx_csr.get());
    for (index, selector) in [&context.seg_ds, &context.seg_es, &context.seg_fs, &context.seg_gs].into_iter().enumerate() {
        selector.set(guest::read::<u16>(cpu_state + CPU_SELECTORS + index as u64 * 2));
    }
    copy(context.dr0.address(), cpu_state, CPU_DEBUG_BYTES);
    trap.gs_base.set(qword(cpu_state + CPU_GS_BASE).get());
    trap.previous_mode.set(0);
    trap.previous_irql.set(irql::get_irql());
    // SegDs..SegGs do trap num único qword, como os seletores salvos.
    copy(trap.seg_ds.address(), cpu_state + CPU_SELECTORS, 8);
    trap.trap_frame.set(old_trap);
    for (field, slot, trap_field) in nonvolatile(context, pointers, trap) {
        slot.set(trap_field.map_or(field.address(), |trap_field| trap_field.address()));
    }
    for index in 6..16 {
        pointers.floating_context[index].set(context.flt_save.xmm_registers[index].address());
    }
    to_trap(&entry);
    ACTIVE.lock().entry(thread).or_default().push(entry);
    owner.tcb.trap_frame.set(trap.address());
    let result = action();
    let owned = owner.tcb.trap_frame.get() == trap.address();
    if owned {
        from_trap(&entry);
        for (source, &offset) in registers_of(context).into_iter().zip(&raw) {
            qword(registers_frame + offset).set(source.get());
        }
        machine.rip.set(context.rip.get());
        // Os slots do IRET são qwords inteiros: CS, RFLAGS e SS com zero-extensão.
        qword(machine.seg_cs.address()).set(context.seg_cs.get() as u64);
        qword(machine.e_flags.address()).set(context.e_flags.get() as u64);
        qword(machine.seg_ss.address()).set(context.seg_ss.get() as u64);
        copy(fx, context.flt_save.address(), XsaveFormat::SIZE);
        copy(cpu_state, context.dr0.address(), CPU_DEBUG_BYTES);
    }
    owner.tcb.trap_frame.set(old_trap);
    {
        let mut active = ACTIVE.lock();
        if let Some(stack) = active.get_mut(&thread) {
            stack.pop();
            if stack.is_empty() {
                active.remove(&thread);
            }
        }
    }
    if !owned {
        return Err(KernelError::new("kernel interrupt trap ownership changed"));
    }
    Ok(result)
}

fn current() -> Option<Entry> {
    ACTIVE.lock().get(&process::get_current_thread()).and_then(|stack| stack.last().copied())
}

/// CONTEXT do frame de interrupção vivo da thread corrente.
pub fn current_context() -> Option<u64> {
    current().map(|entry| entry.space().context.address())
}

/// Aplica um CONTEXT de KernelMode ao frame de interrupção vivo.
pub fn apply_kernel(source: u64) -> Result<u32, KernelError> {
    if irql::get_irql() > 1 {
        return Err(KernelError::new("kernel context operation requires IRQL <= APC_LEVEL"));
    }
    let live = |entry: &Entry| {
        let trap = &entry.space().trap;
        entry.thread().tcb.trap_frame.get() == trap.address() && trap.seg_cs.get() == KERNEL_CODE_SELECTOR
    };
    let Some(entry) = current().filter(live) else { return Ok(0xC000_0001) };
    from_trap(&entry);
    let space = entry.space();
    cpu::fxsave(space.controls.address());
    let mask = match space.controls.mx_csr_mask.get() {
        0 => 0xFFBF,
        mask => mask,
    };
    registers::write_saved_context(space.context.address(), source, 0, mask, space.controls.mx_csr.get())?;
    to_trap(&entry);
    Ok(0)
}

pub fn commit_current() -> Result<(), KernelError> {
    let Some(entry) = current() else { return Err(KernelError::new("no live kernel trap")) };
    to_trap(&entry);
    Ok(())
}
