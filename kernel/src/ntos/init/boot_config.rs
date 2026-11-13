//! Configuração de boot. O `cargo xtask build` passa as opções como variáveis de
//! ambiente lidas em tempo de compilação.

const fn or_default(value: Option<&'static str>, default: &'static str) -> &'static str {
    match value {
        Some(value) => value,
        None => default,
    }
}

/// `--user-program`: programa iniciado depois do boot (`shell` por padrão).
pub const USER_PROGRAM: &str = or_default(option_env!("OPENNT_USER_PROGRAM"), "shell");

/// `--kernel-test-scope`: `none` no build normal; `all` roda o self-test.
pub const KERNEL_TEST_SCOPE: &str = or_default(option_env!("OPENNT_KERNEL_TEST_SCOPE"), "none");

/// `--start-driver`: serviço de driver iniciado pelo SCM antes do programa
/// de usuário, com a CI fiscalizando as cargas (vazio = nenhum).
pub const START_DRIVER: &str = or_default(option_env!("OPENNT_START_DRIVER"), "");

/// `--trace-driver-api`: imprime cada chamada de API do driver de
/// `--start-driver` enquanto ele inicia.
pub const TRACE_DRIVER_API: bool = option_env!("OPENNT_TRACE_DRIVER_API").is_some();

/// `--console-mirror`: espelha o texto do console na serial.
pub const CONSOLE_SERIAL_MIRROR: bool = option_env!("OPENNT_CONSOLE_MIRROR").is_some();
