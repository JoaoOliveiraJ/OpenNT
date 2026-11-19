//! Análises sobre o código e a memória lidos do alvo, sem depender da
//! sessão: servem ao cliente de texto e às interfaces gráficas.
//!
//! - `decode`: o decodificador x86-64 das análises (tamanho, fluxo,
//!   destino, operando de memória e imediato de cada instrução);
//! - `cfg`: o grafo de fluxo de controle de uma função e o arranjo em
//!   camadas para desenhá-lo;
//! - `functions`: limites de função (`.pdata`, símbolos e fluxo) e laços,
//!   com as marcas dos colchetes da desmontagem;
//! - `args`: os argumentos de uma chamada x64 pelo preparo antes do `call`;
//! - `prototypes`: os protótipos das APIs comuns e o comentário de uma
//!   chamada com os argumentos decodificados;
//! - `refs`: strings usadas pelo código, referências a um endereço,
//!   constantes, chamadas para fora do módulo, chamadores e o índice de
//!   referências cruzadas de um módulo;
//! - `search`: padrões de bytes com curingas e a varredura de strings;
//! - `script`: a linguagem de roteiros do depurador;
//! - `notes`: comentários, rótulos, marcadores e patches por módulo + RVA.

pub mod args;
pub mod cfg;
pub mod decode;
pub mod functions;
pub mod notes;
pub mod prototypes;
pub mod refs;
pub mod script;
pub mod search;
