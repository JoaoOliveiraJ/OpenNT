//! Objetos de reserva de memória (NtAllocateReserveObject).
//!
//! Um objeto de reserva guarda de antemão a memória de uma operação que
//! não pode falhar por falta de pool: a KAPC de uma APC de usuário
//! (UserApcReserve, MemoryReserveUserApc = 0) ou o pacote de conclusão de
//! um NtSetIoCompletionEx (IoCompletionReserve, MemoryReserveIoCompletion =
//! 1). Como no ntoskrnl 19041:
//!
//! - os dois tipos vêm do PspInitPhase0: PspMemReserveMapping {0x20001,
//!   0x20002, 0x20000, 0xF0003}, ValidAccessMask 0xF0003, UnnamedObjectsOnly,
//!   InvalidAttributes 0xB0 (OBJ_PERMANENT, OBJ_EXCLUSIVE, OBJ_OPENIF),
//!   NonPagedPoolNx, cobrança não paginável do tamanho do corpo
//!   (PspMemoryReserveObjectSizes: 0x60 e 0x58), sem rotinas de tipo;
//! - NtAllocateReserveObject recusa outro tipo (STATUS_INVALID_PARAMETER),
//!   cria o objeto pelo ObCreateObjectEx no modo anterior, zera o corpo e,
//!   na reserva de conclusão, prepara o IO_MINI_COMPLETION_PACKET_USER
//!   embutido (PacketType 4, MiniPacketCallback = PspIoMiniPacketCallbackRoutine,
//!   Context = o próprio objeto) e abre o handle pelo ObInsertObjectEx com
//!   0xF0003;
//! - o corpo da reserva de conclusão começa com o ULONG InUse: o
//!   NtSetIoCompletionEx o toma por CAS antes de publicar o pacote embutido
//!   ([`take_completion_reserve`]) e o PspIoMiniPacketCallbackRoutine o
//!   devolve na retirada e solta a referência que o pacote levou
//!   ([`completion_packet_returned`]);
//! - a reserva de APC também começa com o InUse, seguido da KAPC: o
//!   NtQueueApcThreadEx2 com ReserveHandle o toma ([`take_user_apc_reserve`])
//!   e enfileira a KAPC embutida com o PspUserApcReserveRundownRoutine como
//!   KernelRoutine e RundownRoutine, que devolve o InUse e solta a
//!   referência ([`user_apc_reserve_routine`]).

use core::sync::atomic::Ordering;

use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{IoMiniCompletionPacketUser, Kapc};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_types::{self, TypeTemplate};
use crate::ntos::ob::{object_create, object_reference, reference_trace};
use crate::rtl::KernelError;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// STATUS_INVALID_PARAMETER_2: a reserva já está com um pacote na fila.
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
/// MEMORY_RESERVE_TYPE.
pub const MEMORY_RESERVE_USER_APC: u32 = 0;
pub const MEMORY_RESERVE_IO_COMPLETION: u32 = 1;
/// O acesso do handle de criação.
const RESERVE_ALL_ACCESS: u32 = 0xF_0003;
/// IO_MINI_COMPLETION_PACKET_USER.PacketType de um pacote de usuário.
const PACKET_USER: u32 = 4;
/// A rotina nativa que o pacote embutido chama na retirada.
const MINI_PACKET_CALLBACK: &str = "PspIoMiniPacketCallbackRoutine";

/// Corpo da IoCompletionReserve (0x58 bytes): o InUse e o pacote embutido.
#[repr(C)]
struct CompletionReserve {
    in_use: Field<u32>,
    _pad_04: Reserved<4>,
    packet: IoMiniCompletionPacketUser,
}

/// Corpo da UserApcReserve (0x60 bytes): o InUse e a KAPC embutida.
#[repr(C)]
struct UserApcReserve {
    in_use: Field<u32>,
    _pad_04: Reserved<4>,
    apc: Kapc,
}

// SAFETY: #[repr(C)] só de células e de structs do NT.
unsafe impl NtStruct for CompletionReserve {}
unsafe impl NtStruct for UserApcReserve {}

const _: () = {
    assert!(core::mem::size_of::<CompletionReserve>() == 0x58);
    assert!(core::mem::offset_of!(CompletionReserve, packet) == 8);
    assert!(core::mem::size_of::<UserApcReserve>() == 0x60);
    assert!(core::mem::offset_of!(UserApcReserve, apc) == 8);
};

const fn reserve_type(name: &'static str, size: u32) -> TypeTemplate {
    TypeTemplate { name, mapping: [0x2_0001, 0x2_0002, 0x2_0000, 0xF_0003], valid_access: 0xF_0003, flags: 0x02, object_type_code: 0, invalid_attributes: 0xB0, pool_type: 0x200, paged_charge: 0, non_paged_charge: size }
}

/// PspMemoryReserveObjectTypes, na ordem do MEMORY_RESERVE_TYPE, com os
/// PspMemoryReserveObjectSizes.
const RESERVE_TYPES: [TypeTemplate; 2] = [reserve_type("UserApcReserve", 0x60), reserve_type("IoCompletionReserve", 0x58)];

/// Cria os dois tipos (uma vez), como o PspInitPhase0.
pub fn initialize_types() {
    for template in &RESERVE_TYPES {
        object_types::ensure(template);
    }
}

/// O OBJECT_TYPE da reserva de conclusão.
pub fn completion_reserve_type() -> u64 {
    object_types::ensure(&RESERVE_TYPES[MEMORY_RESERVE_IO_COMPLETION as usize]).pointer
}

/// NtAllocateReserveObject(MemoryReserveHandle, ObjectAttributes, Type) no
/// modo `mode` (em UserMode o chamador já sondou a saída, e a gravação do
/// handle volta STATUS_ACCESS_VIOLATION se a página sumiu nesse meio tempo).
/// Devolve o NTSTATUS.
pub fn allocate(handle_out: u64, attributes: u64, reserve_type: u32, mode: u8) -> Result<u32, KernelError> {
    if reserve_type > MEMORY_RESERVE_IO_COMPLETION {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let template = &RESERVE_TYPES[reserve_type as usize];
    let type_pointer = object_types::ensure(template).pointer;
    let cells = guest::alloc_bytes(16);
    if cells == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    let status = object_create::create(mode, type_pointer, attributes, mode, template.non_paged_charge, 0, 0, cells);
    // SAFETY: as duas células PVOID/HANDLE alocadas acima.
    let (object_cell, handle_cell) = unsafe { (Field::<u64>::at(cells), Field::<u64>::at(cells + 8)) };
    let result = (|| -> Result<u32, KernelError> {
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        let object = object_cell.get();
        guest::write_bytes(object, &alloc::vec![0u8; template.non_paged_charge as usize]);
        if reserve_type == MEMORY_RESERVE_IO_COMPLETION {
            let callback = crate::ntos::init::exports::private_routines::address(MINI_PACKET_CALLBACK);
            if callback == 0 {
                return Err(KernelError::new("PspIoMiniPacketCallbackRoutine sem entrada nativa"));
            }
            // SAFETY: corpo IoCompletionReserve recém-criado e zerado.
            let packet = &unsafe { CompletionReserve::at(object) }.packet;
            packet.packet_type.set(PACKET_USER);
            packet.mini_packet_callback.set(callback);
            packet.context.set(object);
            packet.allocated.set(0);
        }
        let status = object_create::insert(object, RESERVE_ALL_ACCESS, 0, 0, handle_cell.address())?;
        if status & 0x8000_0000 == 0 {
            if mode != 0 {
                // O PHANDLE de usuário, sondado pelo chamador.
                if guest::try_write::<u64>(handle_out, handle_cell.get()).is_err() {
                    return Ok(STATUS_ACCESS_VIOLATION);
                }
            } else {
                // SAFETY: o PHANDLE de saída do chamador de modo kernel.
                unsafe { Field::<u64>::at(handle_out) }.set(handle_cell.get());
            }
        }
        Ok(status)
    })();
    guest::free_bytes(cells);
    result
}

/// ZwAllocateReserveObject: o NtAllocateReserveObject com PreviousMode
/// KernelMode (o handle vai para a tabela do System com OBJ_KERNEL_HANDLE).
pub fn allocate_kernel(handle_out: u64, attributes: u64, reserve_type: u32) -> Result<u32, KernelError> {
    crate::ntos::ps::previous_mode::with_kernel(|| allocate(handle_out, attributes, reserve_type, 0))?
}

/// Toma uma reserva do tipo `reserve_type`: referencia o handle (acesso 2,
/// no modo `mode`) e liga por CAS o InUse do início do corpo
/// (STATUS_INVALID_PARAMETER_2 se já está em uso). Devolve o corpo, com a
/// referência entregue a quem usa a reserva.
fn take_reserve(handle: u64, mode: u8, reserve_type: u32) -> Result<Result<u64, u32>, KernelError> {
    let slot = guest::alloc_bytes(8);
    if slot == 0 {
        return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
    }
    let type_pointer = object_types::ensure(&RESERVE_TYPES[reserve_type as usize]).pointer;
    let status = object_reference::reference_by_handle(handle, 2, type_pointer, mode, slot, 0)?;
    // SAFETY: célula PVOID recém-alocada.
    let object = unsafe { Field::<u64>::at(slot) }.get();
    guest::free_bytes(slot);
    if status != 0 {
        return Ok(Err(status as u32));
    }
    // SAFETY: os dois corpos de reserva começam com o ULONG InUse, retido
    // pela referência acima.
    let in_use = unsafe { Field::<u32>::at(object) };
    if in_use.atomic().compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        object_reference::dereference_with_tag(object, reference_trace::DEFAULT_TAG, false)?;
        return Ok(Err(STATUS_INVALID_PARAMETER_2));
    }
    Ok(Ok(object))
}

/// A metade do NtSetIoCompletionEx que toma a reserva (IoCompletionReserve).
/// Devolve o endereço do pacote embutido, com a referência entregue ao
/// pacote (solta por [`completion_packet_returned`] ou por
/// [`abandon_completion_reserve`] se a publicação falhar).
pub fn take_completion_reserve(handle: u64, mode: u8) -> Result<Result<u64, u32>, KernelError> {
    // SAFETY: corpo IoCompletionReserve retido pela referência da reserva.
    Ok(take_reserve(handle, mode, MEMORY_RESERVE_IO_COMPLETION)?.map(|object| unsafe { CompletionReserve::at(object) }.packet.address()))
}

/// A metade do NtQueueApcThreadEx2 que toma a reserva (UserApcReserve, no
/// modo `mode`). Devolve o endereço da KAPC embutida, com a referência
/// entregue à APC (solta pelo [`user_apc_reserve_routine`] na entrega, no
/// rundown ou na recusa da inserção).
pub fn take_user_apc_reserve(handle: u64, mode: u8) -> Result<Result<u64, u32>, KernelError> {
    // SAFETY: corpo UserApcReserve retido pela referência da reserva.
    Ok(take_reserve(handle, mode, MEMORY_RESERVE_USER_APC)?.map(|object| unsafe { UserApcReserve::at(object) }.apc.address()))
}

/// PspUserApcReserveRundownRoutine(Apc): a KernelRoutine e a RundownRoutine
/// da KAPC embutida numa UserApcReserve. Devolve a reserva (InUse = 0) e
/// solta a referência que o NtQueueApcThreadEx2 tomou; os outros argumentos
/// da rotina de kernel não são usados.
extern "win64" fn user_apc_reserve_rundown(apc: u64) {
    let object = apc - core::mem::offset_of!(UserApcReserve, apc) as u64;
    // SAFETY: corpo UserApcReserve retido pela referência da APC.
    unsafe { UserApcReserve::at(object) }.in_use.set(0);
    if let Err(error) = object_reference::dereference_with_tag(object, reference_trace::DEFAULT_TAG, false) {
        crate::debug_print!("[reserve] reserva de APC {:#x} sem referência: {}", object, error);
    }
}

/// O endereço do [`user_apc_reserve_rundown`] (KernelRoutine e
/// RundownRoutine da APC com reserva).
pub fn user_apc_reserve_routine() -> u64 {
    user_apc_reserve_rundown as extern "win64" fn(u64) as usize as u64
}

/// A inserção da APC com reserva foi recusada: devolve a reserva.
pub fn release_user_apc_reserve(apc: u64) {
    user_apc_reserve_rundown(apc);
}

/// A publicação do pacote embutido falhou: devolve o InUse e a referência.
pub fn abandon_completion_reserve(packet: u64) -> Result<(), KernelError> {
    let object = packet - core::mem::offset_of!(CompletionReserve, packet) as u64;
    // SAFETY: corpo IoCompletionReserve retido pela referência do pacote.
    unsafe { CompletionReserve::at(object) }.in_use.set(0);
    object_reference::dereference_with_tag(object, reference_trace::DEFAULT_TAG, false).map(|_| ())
}

/// PspIoMiniPacketCallbackRoutine(Packet, Context): a retirada do pacote
/// embutido devolve a reserva (InUse = 0) e solta a referência do pacote.
pub fn completion_packet_returned(_packet: u64, context: u64) -> Result<u64, KernelError> {
    // SAFETY: Context é o corpo IoCompletionReserve dono do pacote.
    unsafe { CompletionReserve::at(context) }.in_use.set(0);
    object_reference::dereference_with_tag(context, reference_trace::DEFAULT_TAG, false)?;
    Ok(0)
}
