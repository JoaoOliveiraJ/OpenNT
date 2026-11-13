//! Buffers ALPC_MESSAGE_ATTRIBUTES montados pelo próprio chamador, como o
//! `alpc\alpcmsg.c` do NT: AlpcInitializeMessageAttribute,
//! AlpcGetMessageAttribute e AlpcGetHeaderSize (ntoskrnl 19041, 0x34a380,
//! 0x34a340, 0x34a3e0). Funções puras sobre o buffer do chamador; o layout é
//! o mesmo que `ps::user::alpc::attribute_address` usa no transporte. As
//! funções que devolvem `u32` devolvem o NTSTATUS.

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::AlpcMessageAttributes;

const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;

/// Atributos que ocupam espaço depois do cabeçalho, do bit 31 ao 25:
/// Security (0x18), View (0x20), Context (0x20), Handle (0x18), Token (0x18),
/// Direct (8), WorkOnBehalf (8).
const ATTRIBUTE_SIZES: [(u32, u32); 7] = [(31, 0x18), (30, 0x20), (29, 0x20), (28, 0x18), (27, 0x18), (26, 8), (25, 8)];

/// AlpcGetHeaderSize: o cabeçalho ALPC_MESSAGE_ATTRIBUTES e cada atributo
/// presente em `flags`; os demais bits não ocupam espaço.
pub fn header_size(flags: u32) -> u32 {
    ATTRIBUTE_SIZES.iter().filter(|&&(bit, _)| (flags >> bit) & 1 != 0).map(|&(_, bytes)| bytes).sum::<u32>() + AlpcMessageAttributes::SIZE as u32
}

/// AlpcInitializeMessageAttribute(AttributeFlags, Buffer, BufferSize,
/// RequiredBufferSize*): sempre informa o tamanho (SIZE_T); buffer curto
/// devolve BUFFER_TOO_SMALL sem tocar no buffer; buffer NULL só mede.
pub fn initialize(flags: u32, buffer: Option<&AlpcMessageAttributes>, buffer_size: u64, required_out: &Field<u64>) -> u32 {
    let size = header_size(flags) as u64;
    required_out.set(size);
    if size > buffer_size {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if let Some(buffer) = buffer {
        buffer.valid_attributes.set(0);
        buffer.allocated_attributes.set(flags);
    }
    0
}

/// AlpcGetMessageAttribute(Buffer, AttributeFlag): um único bit, alocado; o
/// atributo fica depois dos alocados de bits mais altos
/// (AlpcGetHeaderSize(Allocated & -2*Flag)). Senão NULL.
pub fn get(buffer: &AlpcMessageAttributes, attribute: u32) -> u64 {
    let allocated = buffer.allocated_attributes.get();
    if attribute & allocated == 0 || attribute & attribute.wrapping_sub(1) != 0 {
        return 0;
    }
    buffer.address() + header_size(allocated & attribute.wrapping_mul(0xFFFF_FFFE)) as u64
}
