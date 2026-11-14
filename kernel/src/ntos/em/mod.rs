//! Errata Manager (Em*): provedores de entradas e callbacks de errata e a
//! avaliação de regras para os drivers clientes.
//!
//! No NT o banco (tipos de entrada, callbacks, regras e regras-alvo) vem do
//! INF de errata que o carregador de boot entrega ao kernel e que a fase 1
//! interpreta (EmpParseInfDatabase). O carregador do OpenNT não entrega
//! esse INF, então o banco fica vazio, exatamente como o do ntoskrnl sem o
//! INF: toda busca de entrada, callback ou regra falha. As rotinas seguem
//! as do ntoskrnl 19041 sobre esse banco: as validações, os blocos de pool
//! 'EMpr', a referência ao DRIVER_OBJECT do provedor e os status.

pub mod database;
pub mod exports;
pub mod provider;
pub mod rule;
