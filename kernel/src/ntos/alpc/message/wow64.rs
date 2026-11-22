//! A forma de 32 bits das mensagens ALPC (ALPC_MSGFLG_WOW64_CALL).
//!
//! O wow64.dll passa adiante, sem converter, o PORT_MESSAGE32 e os
//! ALPC_MESSAGE_ATTRIBUTES de 32 bits de um processo x86 e liga o bit 31
//! (ALPC_MSGFLG_WOW64_CALL) nas flags do NtAlpcSendWaitReceivePort e do
//! NtAlpcConnectPort (whNtAlpcSendWaitReceivePort 0xa4be, whNtAlpcConnectPort
//! 0x13d83). No 19041 quem converte é o kernel: o
//! AlpcpProbeAndCaptureMessageHeader lê o PORT_MESSAGE32, os
//! AlpcpCapture*Attribute32 leem os atributos de 32 bits (os handles com
//! extensão de sinal) e os AlpcpExpose*Attribute32 os devolvem na forma de
//! 32 bits.
//!
//! Aqui a conversão fica na fronteira do serviço, no processo de quem chama
//! (uma thread de processo WoW64 x86): a mensagem e os atributos de 32 bits
//! viram a forma nativa numa região de rascunho do processo, abaixo do
//! limite de VA dele, o serviço nativo roda sobre ela (os argumentos da
//! pilha também vêm da cópia), e na volta a mensagem recebida, o
//! BufferLength e os atributos de saída voltam à forma de 32 bits nos
//! buffers de quem chamou; o rascunho é liberado.
//!
//! - PORT_MESSAGE32 (0x18 bytes): DataLength, TotalLength, Type e
//!   DataInfoOffset de 16 bits, o CLIENT_ID32, o MessageId e o
//!   ClientViewSize/CallbackId de 32 bits; a forma nativa tem 0x28 bytes, e
//!   o TotalLength e um DataInfoOffset não nulo diferem em 0x10.
//! - os atributos de 32 bits, do bit 31 ao 25: Security (0xC: Flags, QoS e
//!   ContextHandle), View (0x10: Flags, SectionHandle, ViewBase, ViewSize),
//!   Context (0x14: PortContext, MessageContext, Sequence, MessageId,
//!   CallbackId), Handle (0x10: Flags, Handle, ObjectType, DesiredAccess),
//!   Token (0x18, igual), Direct (4: Event) e WorkOnBehalf (8, igual).

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::AlpcMessageAttributes;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user::memory;
use crate::rtl::KernelError;

/// ALPC_MSGFLG_WOW64_CALL e o bit 30, que marca o mesmo pedido já na forma
/// nativa.
pub const WOW64_CALL: u32 = 0x8000_0000;
const NATIVE_LAYOUT: u32 = 0x4000_0000;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
/// Os dois cabeçalhos.
const HEADER32: u64 = 0x18;
const HEADER64: u64 = 0x28;
const HEADER_DELTA: u64 = HEADER64 - HEADER32;
/// A maior mensagem (TotalLength de 16 bits).
const MAXIMUM_MESSAGE: u64 = 0xFFFF;

/// Os atributos que ocupam espaço, do bit 31 ao 25: (flag, tamanho de 32
/// bits, tamanho nativo).
const ATTRIBUTES: [(u32, u64, u64); 7] = [(0x8000_0000, 0xC, 0x18), (0x4000_0000, 0x10, 0x20), (0x2000_0000, 0x14, 0x20), (0x1000_0000, 0x10, 0x18), (0x0800_0000, 0x18, 0x18), (0x0400_0000, 4, 8), (0x0200_0000, 8, 8)];

/// Um pedido de 32 bits de um processo WoW64 x86 (o bit 31 sem o 30).
pub fn is_wow64_call(flags: u32) -> bool {
    flags & (WOW64_CALL | NATIVE_LAYOUT) == WOW64_CALL && crate::ntos::ps::wow64::is_x86_process(crate::ntos::ps::process::get_current_process())
}

fn read16(address: u64) -> Result<u16, u32> {
    guest::try_read::<u16>(address).map_err(|_| STATUS_ACCESS_VIOLATION)
}
fn read32(address: u64) -> Result<u32, u32> {
    guest::try_read::<u32>(address).map_err(|_| STATUS_ACCESS_VIOLATION)
}
fn read64(address: u64) -> Result<u64, u32> {
    guest::try_read::<u64>(address).map_err(|_| STATUS_ACCESS_VIOLATION)
}
fn write16(address: u64, value: u16) -> Result<(), u32> {
    guest::try_write::<u16>(address, value).map_err(|_| STATUS_ACCESS_VIOLATION)
}
fn write32(address: u64, value: u32) -> Result<(), u32> {
    guest::try_write::<u32>(address, value).map_err(|_| STATUS_ACCESS_VIOLATION)
}
fn write64(address: u64, value: u64) -> Result<(), u32> {
    guest::try_write::<u64>(address, value).map_err(|_| STATUS_ACCESS_VIOLATION)
}
fn copy(from: u64, to: u64, length: u64) -> Result<(), u32> {
    if length == 0 {
        return Ok(());
    }
    let bytes = guest::try_read_bytes(from, length as usize).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    guest::try_write_bytes(to, &bytes).map_err(|_| STATUS_ACCESS_VIOLATION)
}
/// Um HANDLE de 32 bits com a extensão de sinal (os pseudo-handles).
fn handle(value: u32) -> u64 {
    value as i32 as i64 as u64
}

/// O tamanho de uma mensagem de 32 bits em `message` (o TotalLength do
/// cabeçalho, conferido com o DataLength como o AlpcpValidateMessage).
fn message_size32(message: u64) -> Result<u64, u32> {
    let data = read16(message)? as u64;
    let total = read16(message + 2)? as u64;
    if total != HEADER32 + data {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(total)
}

/// O PORT_MESSAGE32 de `from` (com os dados) na forma nativa em `to`.
pub fn message_to_native(from: u64, to: u64) -> Result<(), u32> {
    let data = read16(from)? as u64;
    write16(to, data as u16)?;
    write16(to + 2, (read16(from + 2)? as u64 + HEADER_DELTA) as u16)?;
    write16(to + 4, read16(from + 4)?)?;
    let offset = read16(from + 6)?;
    write16(to + 6, if offset != 0 { offset + HEADER_DELTA as u16 } else { 0 })?;
    write64(to + 8, read32(from + 8)? as u64)?;
    write64(to + 0x10, read32(from + 0xC)? as u64)?;
    write32(to + 0x18, read32(from + 0x10)?)?;
    write32(to + 0x1C, 0)?;
    write64(to + 0x20, read32(from + 0x14)? as u64)?;
    copy(from + HEADER32, to + HEADER64, data)
}

/// A mensagem nativa de `from` (com os dados) na forma de 32 bits em `to`.
pub fn message_to_wow64(from: u64, to: u64) -> Result<(), u32> {
    let data = read16(from)? as u64;
    write16(to, data as u16)?;
    write16(to + 2, (read16(from + 2)? as u64).saturating_sub(HEADER_DELTA) as u16)?;
    write16(to + 4, read16(from + 4)?)?;
    let offset = read16(from + 6)?;
    write16(to + 6, if offset as u64 > HEADER_DELTA { offset - HEADER_DELTA as u16 } else { 0 })?;
    write32(to + 8, read64(from + 8)? as u32)?;
    write32(to + 0xC, read64(from + 0x10)? as u32)?;
    write32(to + 0x10, read32(from + 0x18)?)?;
    write32(to + 0x14, read64(from + 0x20)? as u32)?;
    copy(from + HEADER64, to + HEADER32, data)
}

/// O tamanho nativo de um buffer de atributos com os `allocated`.
fn attributes_size64(allocated: u32) -> u64 {
    AlpcMessageAttributes::SIZE + ATTRIBUTES.iter().filter(|(flag, _, _)| allocated & flag != 0).map(|(_, _, size)| size).sum::<u64>()
}

/// Cada atributo alocado: (flag, endereço de 32 bits, endereço nativo).
fn attribute_slots(allocated: u32, base32: u64, base64: u64) -> alloc::vec::Vec<(u32, u64, u64)> {
    let (mut at32, mut at64) = (base32 + AlpcMessageAttributes::SIZE, base64 + AlpcMessageAttributes::SIZE);
    let mut slots = alloc::vec::Vec::new();
    for (flag, size32, size64) in ATTRIBUTES {
        if allocated & flag != 0 {
            slots.push((flag, at32, at64));
            at32 += size32;
            at64 += size64;
        }
    }
    slots
}

/// Os atributos de 32 bits de `from` na forma nativa em `to` (o
/// AlpcpCapture*Attribute32 de cada um): os alocados, os válidos e os campos
/// de cada atributo alocado.
pub fn attributes_to_native(from: u64, to: u64) -> Result<(), u32> {
    let allocated = read32(from)?;
    write32(to, allocated)?;
    write32(to + 4, read32(from + 4)?)?;
    for (flag, at32, at64) in attribute_slots(allocated, from, to) {
        match flag {
            0x8000_0000 => {
                write32(at64, read32(at32)?)?;
                write32(at64 + 4, 0)?;
                write64(at64 + 8, read32(at32 + 4)? as u64)?;
                write64(at64 + 0x10, handle(read32(at32 + 8)?))?;
            }
            0x4000_0000 => {
                write32(at64, read32(at32)?)?;
                write32(at64 + 4, 0)?;
                write64(at64 + 8, handle(read32(at32 + 4)?))?;
                write64(at64 + 0x10, read32(at32 + 8)? as u64)?;
                write64(at64 + 0x18, read32(at32 + 0xC)? as u64)?;
            }
            0x2000_0000 => {
                write64(at64, read32(at32)? as u64)?;
                write64(at64 + 8, read32(at32 + 4)? as u64)?;
                write32(at64 + 0x10, read32(at32 + 8)?)?;
                write32(at64 + 0x14, read32(at32 + 0xC)?)?;
                write32(at64 + 0x18, read32(at32 + 0x10)?)?;
                write32(at64 + 0x1C, 0)?;
            }
            0x1000_0000 => {
                write32(at64, read32(at32)?)?;
                write32(at64 + 4, 0)?;
                write64(at64 + 8, handle(read32(at32 + 4)?))?;
                write32(at64 + 0x10, read32(at32 + 8)?)?;
                write32(at64 + 0x14, read32(at32 + 0xC)?)?;
            }
            0x0400_0000 => write64(at64, handle(read32(at32)?))?,
            _ => copy(at32, at64, 8 + if flag == 0x0800_0000 { 0x10 } else { 0 })?,
        }
    }
    Ok(())
}

/// Os atributos nativos de `from` de volta à forma de 32 bits em `to` (o
/// AlpcpExpose*Attribute32): os válidos e os campos de cada atributo
/// alocado, com os valores de 64 bits truncados.
pub fn attributes_to_wow64(from: u64, to: u64) -> Result<(), u32> {
    let allocated = read32(to)?;
    write32(to + 4, read32(from + 4)?)?;
    for (flag, at32, at64) in attribute_slots(allocated, to, from) {
        match flag {
            0x8000_0000 => {
                write32(at32, read32(at64)?)?;
                write32(at32 + 4, read64(at64 + 8)? as u32)?;
                write32(at32 + 8, read64(at64 + 0x10)? as u32)?;
            }
            0x4000_0000 => {
                write32(at32, read32(at64)?)?;
                write32(at32 + 4, read64(at64 + 8)? as u32)?;
                write32(at32 + 8, read64(at64 + 0x10)? as u32)?;
                write32(at32 + 0xC, read64(at64 + 0x18)? as u32)?;
            }
            0x2000_0000 => {
                write32(at32, read64(at64)? as u32)?;
                write32(at32 + 4, read64(at64 + 8)? as u32)?;
                write32(at32 + 8, read32(at64 + 0x10)?)?;
                write32(at32 + 0xC, read32(at64 + 0x14)?)?;
                write32(at32 + 0x10, read32(at64 + 0x18)?)?;
            }
            0x1000_0000 => {
                write32(at32, read32(at64)?)?;
                write32(at32 + 4, read64(at64 + 8)? as u32)?;
                write32(at32 + 8, read32(at64 + 0x10)?)?;
                write32(at32 + 0xC, read32(at64 + 0x14)?)?;
            }
            0x0400_0000 => write32(at32, read64(at64)? as u32)?,
            _ => copy(at64, at32, 8 + if flag == 0x0800_0000 { 0x10 } else { 0 })?,
        }
    }
    Ok(())
}

/// Onde os argumentos de pilha do serviço ficam no rascunho.
const STACK_COPY: u64 = 0x80;

/// Os buffers de um pedido de 32 bits e as cópias nativas no rascunho.
struct Rewrite {
    /// A cópia nativa da mensagem enviada (só leitura do lado de 32 bits).
    send64: u64,
    /// O buffer de recepção (ou a mensagem de conexão, entrada e saída),
    /// com o BufferLength de quem chamou (um SIZE_T, o do wow64.dll).
    receive32: u64,
    receive64: u64,
    length_cell: u64,
    length64: u64,
    send_attributes32: u64,
    send_attributes64: u64,
    receive_attributes32: u64,
    receive_attributes64: u64,
}

/// Monta o rascunho de um pedido: a cópia dos argumentos de pilha de `rsp`
/// com os ponteiros de recepção trocados (os índices `receive_slots`:
/// mensagem, BufferLength e atributos de entrada), a mensagem enviada e os
/// atributos de envio na forma nativa e os buffers de saída nativos.
fn prepare(rsp: u64, send32: u64, send_attributes32: u64, receive32: u64, length_cell: u64, receive_attributes32: u64, receive_slots: [u64; 3], flags_slot: Option<u64>) -> Result<(u64, Rewrite), u32> {
    let send_size = if send32 != 0 { message_size32(send32)? + HEADER_DELTA } else { 0 };
    let receive_capacity = if receive32 == 0 { 0 } else if length_cell != 0 { read64(length_cell)?.min(MAXIMUM_MESSAGE) + HEADER_DELTA } else { MAXIMUM_MESSAGE + HEADER_DELTA };
    let send_attributes_size = if send_attributes32 != 0 { attributes_size64(read32(send_attributes32)?) } else { 0 };
    let receive_attributes_size = if receive_attributes32 != 0 { attributes_size64(read32(receive_attributes32)?) } else { 0 };
    let align = |value: u64| (value + 15) & !15;
    let total = STACK_COPY + align(send_size) + align(receive_capacity) + 16 + align(send_attributes_size) + align(receive_attributes_size);
    let base = memory::map_user_region(total).map_err(|error| if error.status != 0 { error.status } else { 0xC000_0017 })?;
    let mut cursor = base + STACK_COPY;
    let mut take = |size: u64| {
        let at = cursor;
        cursor += align(size);
        at
    };
    let send64 = if send32 != 0 { take(send_size) } else { 0 };
    let receive64 = if receive32 != 0 { take(receive_capacity) } else { 0 };
    let length64 = take(16);
    let send_attributes64 = if send_attributes32 != 0 { take(send_attributes_size) } else { 0 };
    let receive_attributes64 = if receive_attributes32 != 0 { take(receive_attributes_size) } else { 0 };
    let rewrite = Rewrite { send64, receive32, receive64, length_cell, length64, send_attributes32, send_attributes64, receive_attributes32, receive_attributes64 };
    let filled = (|| -> Result<(), u32> {
        copy(rsp, base, STACK_COPY)?;
        let slot = |index: u64| base + 0x28 + (index - 5) * 8;
        if let Some(index) = flags_slot {
            write32(slot(index), read32(rsp + 0x28 + (index - 5) * 8)? & !WOW64_CALL)?;
        }
        write64(slot(receive_slots[0]), receive64)?;
        write64(slot(receive_slots[1]), if length_cell != 0 { length64 } else { 0 })?;
        write64(slot(receive_slots[2]), receive_attributes64)?;
        if length_cell != 0 {
            write64(length64, receive_capacity)?;
        }
        // A mensagem de conexão é de entrada e saída: o envio é o próprio
        // buffer de recepção.
        if send32 != 0 {
            message_to_native(send32, send64)?;
        }
        if send_attributes32 != 0 {
            attributes_to_native(send_attributes32, send_attributes64)?;
        }
        if receive_attributes32 != 0 {
            write32(receive_attributes64, read32(receive_attributes32)?)?;
            write32(receive_attributes64 + 4, 0)?;
        }
        Ok(())
    })();
    match filled {
        Ok(()) => Ok((base, rewrite)),
        Err(status) => {
            release(base);
            Err(status)
        }
    }
}

/// Os resultados de volta aos buffers de 32 bits de quem chamou: o
/// BufferLength (o tamanho de 32 bits), a mensagem recebida, os atributos de
/// saída e os de envio (o ContextHandle do atributo de segurança volta).
fn finish(rewrite: &Rewrite, status: u32, delivered_into_receive: bool) -> Result<(), u32> {
    if rewrite.length_cell != 0 {
        let length = read64(rewrite.length64)?;
        if length >= HEADER64 {
            write64(rewrite.length_cell, length - HEADER_DELTA)?;
        }
    }
    if status == 0 && rewrite.receive32 != 0 && delivered_into_receive {
        message_to_wow64(rewrite.receive64, rewrite.receive32)?;
    }
    if rewrite.send_attributes32 != 0 {
        attributes_to_wow64(rewrite.send_attributes64, rewrite.send_attributes32)?;
    }
    if status == 0 && rewrite.receive_attributes32 != 0 {
        attributes_to_wow64(rewrite.receive_attributes64, rewrite.receive_attributes32)?;
    }
    Ok(())
}

fn release(base: u64) {
    if let Some(region) = memory::find_region(base) {
        memory::release_private_region(&region);
    }
}

/// O NtAlpcSendWaitReceivePort de 32 bits: a mensagem (`input`), os
/// atributos de envio e, da pilha, a recepção (argumentos 5 a 7) passam pelo
/// rascunho nativo, e `service` é o serviço nativo sobre ele.
pub fn send_wait_receive(handle: u64, flags: u32, input: u64, attributes: u64, rsp: u64, service: impl FnOnce(u64, u64, u64, u64, u64) -> Result<u32, KernelError>) -> Result<u32, KernelError> {
    let argument = |index: u64| crate::ntos::ps::user::state::stack_arg(rsp, index);
    let (receive, length, receive_attributes) = (argument(5), argument(6), argument(7));
    let (base, rewrite) = match prepare(rsp, input, attributes, receive, length, receive_attributes, [5, 6, 7], None) {
        Ok(prepared) => prepared,
        Err(status) => return Ok(status),
    };
    let status = service(handle, (flags & !WOW64_CALL) as u64, rewrite.send64, rewrite.send_attributes64, base);
    let result = match status {
        Ok(status) => finish(&rewrite, status, true).map(|_| status).or_else(Ok),
        Err(error) => Err(error),
    };
    release(base);
    result
}

/// O NtAlpcConnectPort(Ex) de 32 bits: as flags (argumento 5), a mensagem de
/// conexão de entrada e saída, o BufferLength e os atributos de envio e de
/// recepção (argumentos 7 a 10) passam pelo rascunho nativo; `service` é o
/// serviço nativo, chamado com a pilha do rascunho.
pub fn connect(rsp: u64, service: impl FnOnce(u64) -> Result<u32, KernelError>) -> Result<u32, KernelError> {
    let argument = |index: u64| crate::ntos::ps::user::state::stack_arg(rsp, index);
    let (message, length, send_attributes, receive_attributes) = (argument(7), argument(8), argument(9), argument(10));
    let (base, rewrite) = match prepare(rsp, message, send_attributes, message, length, receive_attributes, [7, 8, 10], Some(5)) {
        Ok(prepared) => prepared,
        Err(status) => return Ok(status),
    };
    // A mensagem de conexão nativa é de entrada e saída: a convertida vai
    // para o buffer de recepção do rascunho (o do argumento 7, com a
    // capacidade do BufferLength), onde a resposta volta; o argumento 9 (os
    // atributos de envio) aponta para a cópia nativa.
    let staged = (|| -> Result<(), u32> {
        if rewrite.send64 != 0 {
            copy(rewrite.send64, rewrite.receive64, message_size32(message)? + HEADER_DELTA)?;
        }
        write64(base + 0x28 + 4 * 8, rewrite.send_attributes64)
    })();
    if let Err(status) = staged {
        release(base);
        return Ok(status);
    }
    let status = service(base);
    let result = match status {
        Ok(status) => finish(&rewrite, status, rewrite.receive32 != 0).map(|_| status).or_else(Ok),
        Err(error) => Err(error),
    };
    release(base);
    result
}
