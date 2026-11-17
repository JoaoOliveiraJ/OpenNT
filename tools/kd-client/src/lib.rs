//! Cliente do depurador do kernel do OpenNT, compartilhado pelo `cargo
//! xtask debug` (texto) e pelo `opennt-dbg` (gráfico, `tools/kd-gui`).
//!
//! O kernel com `--kd=com2` atende o protocolo remoto do GDB na COM2, que o
//! QEMU expõe num socket TCP, com as extensões do OpenNT pelo `qRcmd`
//! (`ps`, `threads`, `lm`, `cpus`, `context`, `obj`, `log`, `bl`,
//! `bugcheck`, `kd`, `process`, `thread`, `irp`, `devobj`, `drvobj`,
//! `handle`, `trace`) e o `qOpenNTTrace` (os registros do rastro). Módulos:
//!
//! - `rsp`: os pacotes (`$dados#cs`, confirmação, `O`, compressão `x*n`) e a
//!   conexão TCP;
//! - `stop`: a resposta de parada (`T05thread:1;swbreak:;`);
//! - `registers`: a ordem do pacote `g` do GDB para x86-64;
//! - `symbols`, `elf`, `pe`, `msf`, `pdb`, `demangle`: os símbolos do
//!   `kernel.elf` (com os nomes do Rust legíveis), dos exports dos PEs desta
//!   máquina e dos públicos dos PDBs (cache e servidor de símbolos);
//! - `unwind`: a pilha pela `.pdata` dos binários da Microsoft e pelos frame
//!   pointers do código do OpenNT;
//! - `tpi`, `types`: os tipos do PDB do ntoskrnl e as vistas tipadas;
//! - `expr`: as expressões (operadores, memória, símbolos e campos tipados);
//! - `bugcheck`: a análise de uma parada por bugcheck;
//! - `trace`: o rastro de instruções (formato, árvore de chamadas, diff);
//! - `x86`: o mínimo de decodificação para o passo por cima (o tamanho de
//!   um `call`), o prólogo e a classe de uma instrução;
//! - `monitor`: as tabelas do `qRcmd` em estruturas;
//! - `user`: os processos de usuário (`.process`, PEB.Ldr, handles, regiões,
//!   threads de usuário com o CONTEXT salvo);
//! - `client`, `commands`: a sessão (comandos de texto e a API tipada que a
//!   interface gráfica usa);
//! - `analysis`: decodificador, grafo de fluxo, limites de função e laços,
//!   argumentos de chamadas e protótipos, referências e strings, padrões,
//!   roteiros e as notas e patches por módulo + RVA;
//! - `image`: a imagem de um módulo para as análises (o arquivo desta
//!   máquina ou a memória do alvo);
//! - `launcher`: o `cargo xtask debug --launch --no-client` (build e QEMU)
//!   para os clientes que abrem o próprio alvo (`opennt-re`, `opennt-mcp`).

pub mod analysis;
pub mod bugcheck;
pub mod client;
pub mod commands;
pub mod demangle;
pub mod elf;
pub mod expr;
pub mod image;
pub mod launcher;
pub mod monitor;
pub mod msf;
pub mod pdb;
pub mod pe;
pub mod registers;
pub mod rsp;
pub mod stop;
pub mod symbols;
pub mod tpi;
pub mod trace;
pub mod types;
pub mod unwind;
pub mod user;
pub mod x86;

pub use client::{Breakpoint, BreakpointKind, Client};
pub use symbols::Symbols;

/// Número em hexadecimal (`0x...`, com `` ` `` ou `_` como separadores) ou
/// decimal.
pub fn parse_number(text: &str) -> Option<u64> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(&hex.replace('`', "").replace('_', ""), 16).ok()
    } else if text.chars().all(|character| character.is_ascii_digit()) && !text.is_empty() {
        text.parse().ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::parse_number;

    #[test]
    fn numbers() {
        assert_eq!(parse_number("0x10"), Some(16));
        assert_eq!(parse_number("0xfffff800`40000000"), Some(0xfffff800_40000000));
        assert_eq!(parse_number("42"), Some(42));
        assert_eq!(parse_number("x"), None);
        assert_eq!(parse_number(""), None);
    }
}
