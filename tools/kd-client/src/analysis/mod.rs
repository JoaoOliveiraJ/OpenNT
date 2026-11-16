//! Análises sobre o código e a memória lidos do alvo, sem depender da
//! sessão: servem ao cliente de texto e às interfaces gráficas.
//!
//! - `decode`: o decodificador x86-64 das análises (tamanho, fluxo,
//!   destino, operando de memória e imediato de cada instrução);
//! - `cfg`: o grafo de fluxo de controle de uma função e o arranjo em
//!   camadas para desenhá-lo;
//! - `refs`: strings usadas pelo código, referências a um endereço,
//!   constantes, chamadas para fora do módulo e chamadores;
//! - `search`: padrões de bytes com curingas e a varredura de strings;
//! - `script`: a linguagem de roteiros do depurador;
//! - `notes`: comentários, rótulos, marcadores e patches por módulo + RVA.

pub mod cfg;
pub mod decode;
pub mod notes;
pub mod refs;
pub mod script;
pub mod search;
