//! ObQueryNameInfo.
//!
//! O nome de um objeto mora no cabeçalho opcional de nome, antes do
//! OBJECT_HEADER (InfoMask bit 2): Directory (o OBJECT_DIRECTORY que o
//! contém), Name (só o componente final) e ReferenceCount. ObQueryNameInfo
//! devolve `Header - ObpInfoMaskToOffset[InfoMask & 3]` quando o bit está
//! ligado, ou NULL. Só os corpos com OBJECT_HEADER (os do ObCreateObject)
//! têm esse cabeçalho; os de outros donos do OpenNT devolvem NULL.

use crate::ntos::ob::object_header;

/// ObQueryNameInfo: o cabeçalho de nome de `object`, ou 0.
pub fn query(object: u64) -> u64 {
    object_header::name_info(object)
}
