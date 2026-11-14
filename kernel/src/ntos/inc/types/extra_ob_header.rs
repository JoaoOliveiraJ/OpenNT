//! Os cabeçalhos opcionais do OBJECT_HEADER e a informação de criação que
//! o ObCreateObject captura. Todos constam dos símbolos do ntoskrnl e são
//! gerados (`types/ob.rs`); este módulo só os reexporta para os caminhos
//! `extra_ob_header::` já usados.

pub use super::{
    ObjectCreateInformation, ObjectHandleCountDatabase, ObjectHandleCountEntry, ObjectHeaderAuditInfo,
    ObjectHeaderCreatorInfo, ObjectHeaderExtendedInfo, ObjectHeaderHandleInfo, ObjectHeaderPaddingInfo,
    ObjectHeaderProcessInfo, ObjectHeaderQuotaInfo,
};

