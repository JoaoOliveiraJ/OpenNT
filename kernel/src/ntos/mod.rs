//! O executive do NT (o ntoskrnl): um diretório por componente, como na
//! árvore do kernel do Windows. Cada componente é dono do seu código e das
//! rotinas que exporta (`<componente>/exports.rs`); `inc` guarda os layouts
//! das estruturas e `init` a inicialização e a tabela de exports.

pub mod cm;
pub mod dbgk;
pub mod etw;
pub mod ex;
pub mod ke;
pub mod mm;
pub mod ps;
pub mod rtl;
pub mod inc;
pub mod test;
pub mod io;
pub mod ob;
pub mod po;
pub mod se;
pub mod alpc;
pub mod init;
pub mod kd;
pub mod fsrtl;
pub mod kse;
pub mod cc;
pub mod tm;
pub mod vf;
pub mod whea;
pub mod bgk;
