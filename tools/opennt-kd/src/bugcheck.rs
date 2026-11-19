//! A análise de um bugcheck (o `!analyze` do depurador): o nome do código,
//! o que cada um dos quatro parâmetros significa, o driver culpado e a
//! pilha. Os nomes e o sentido dos parâmetros seguem a referência pública
//! de códigos de bugcheck do Windows.

/// Um código conhecido: nome, resumo e o rótulo de cada parâmetro.
pub struct Code {
    pub code: u32,
    pub name: &'static str,
    pub summary: &'static str,
    pub parameters: [&'static str; 4],
    /// O parâmetro (0-3) que é o endereço da instrução que falhou, quando há.
    pub instruction: Option<usize>,
}

const CODES: &[Code] = &[
    Code { code: 0x01, name: "APC_INDEX_MISMATCH", summary: "uma chamada de sistema voltou com APCs de kernel desligadas ou contagem errada", parameters: ["endereco da chamada de sistema", "ApcStateIndex da thread", "CombinedApcDisable da thread", "chamada (0 = sistema, 1 = trabalhador)"], instruction: Some(0) },
    Code { code: 0x0A, name: "IRQL_NOT_LESS_OR_EQUAL", summary: "acesso a memoria paginavel ou invalida com IRQL alto demais", parameters: ["endereco referenciado", "IRQL no acesso", "operacao (bit 0: escrita, bit 3: execucao)", "endereco da instrucao"], instruction: Some(3) },
    Code { code: 0x19, name: "BAD_POOL_HEADER", summary: "cabecalho de bloco do pool corrompido", parameters: ["tipo da violacao", "dependente do tipo", "dependente do tipo", "dependente do tipo"], instruction: None },
    Code { code: 0x1A, name: "MEMORY_MANAGEMENT", summary: "erro grave no gerenciador de memoria", parameters: ["subtipo", "dependente do subtipo", "dependente do subtipo", "dependente do subtipo"], instruction: None },
    Code { code: 0x1E, name: "KMODE_EXCEPTION_NOT_HANDLED", summary: "excecao de modo kernel sem tratador", parameters: ["codigo da excecao", "endereco da excecao", "parametro 0 da excecao", "parametro 1 da excecao"], instruction: Some(1) },
    Code { code: 0x20, name: "KERNEL_APC_PENDING_DURING_EXIT", summary: "uma thread terminou com APC de kernel pendente", parameters: ["APC pendente", "contagem de desligamento de APC da thread", "IRQL corrente", "reservado"], instruction: None },
    Code { code: 0x24, name: "NTFS_FILE_SYSTEM", summary: "falha no NTFS", parameters: ["arquivo e linha da origem", "registro da excecao (se houver)", "registro de contexto (se houver)", "reservado"], instruction: None },
    Code { code: 0x3B, name: "SYSTEM_SERVICE_EXCEPTION", summary: "excecao durante uma chamada de sistema", parameters: ["codigo da excecao", "endereco da instrucao", "registro de contexto", "0"], instruction: Some(1) },
    Code { code: 0x3D, name: "INTERRUPT_EXCEPTION_NOT_HANDLED", summary: "excecao numa rotina de interrupcao", parameters: ["registro da excecao", "registro de contexto", "0", "0"], instruction: None },
    Code { code: 0x3F, name: "NO_MORE_SYSTEM_PTES", summary: "acabaram as PTEs de sistema", parameters: ["tipo das PTEs", "tamanho do pedido", "total livre", "total de PTEs"], instruction: None },
    Code { code: 0x44, name: "MULTIPLE_IRP_COMPLETE_REQUESTS", summary: "um driver completou um IRP ja completado", parameters: ["IRP", "reservado", "reservado", "reservado"], instruction: None },
    Code { code: 0x4A, name: "IRQL_GT_ZERO_AT_SYSTEM_SERVICE", summary: "uma chamada de sistema voltou ao modo usuario com IRQL acima de PASSIVE_LEVEL", parameters: ["endereco da funcao de sistema", "IRQL na volta", "0", "0"], instruction: None },
    Code { code: 0x4E, name: "PFN_LIST_CORRUPT", summary: "a base de PFNs esta corrompida", parameters: ["subtipo", "dependente do subtipo", "dependente do subtipo", "dependente do subtipo"], instruction: None },
    Code { code: 0x50, name: "PAGE_FAULT_IN_NONPAGED_AREA", summary: "referencia a memoria invalida", parameters: ["endereco referenciado", "operacao (0 leitura, 2 escrita, 0x10 execucao)", "endereco da instrucao", "tipo da falta"], instruction: Some(2) },
    Code { code: 0x51, name: "REGISTRY_ERROR", summary: "erro grave no Registro (E/S de hive ou hive corrompida)", parameters: ["reservado", "reservado", "hive (se houver)", "retorno do HvCheckHive (hive corrompida)"], instruction: None },
    Code { code: 0x6B, name: "PROCESS1_INITIALIZATION_FAILED", summary: "a fase 1 da inicializacao falhou (o primeiro processo de usuario)", parameters: ["status da falha", "reservado", "reservado", "reservado"], instruction: None },
    Code { code: 0x76, name: "PROCESS_HAS_LOCKED_PAGES", summary: "processo terminou com paginas travadas", parameters: ["0", "processo", "paginas travadas", "ponteiro para as informacoes"], instruction: None },
    Code { code: 0x77, name: "KERNEL_STACK_INPAGE_ERROR", summary: "pagina da pilha de kernel nao pode ser lida", parameters: ["status ou 0", "dependente", "dependente", "dependente"], instruction: None },
    Code { code: 0x7A, name: "KERNEL_DATA_INPAGE_ERROR", summary: "pagina de dados do kernel nao pode ser lida", parameters: ["tipo de travamento ou PTE", "status de E/S", "dependente", "endereco"], instruction: None },
    Code { code: 0x7B, name: "INACCESSIBLE_BOOT_DEVICE", summary: "o dispositivo de boot ficou inacessivel", parameters: ["objeto de dispositivo ou nome ARC", "status", "0", "0"], instruction: None },
    Code { code: 0x7E, name: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", summary: "excecao sem tratador numa thread de sistema", parameters: ["codigo da excecao", "endereco da excecao", "registro da excecao", "registro de contexto"], instruction: Some(1) },
    Code { code: 0x7F, name: "UNEXPECTED_KERNEL_MODE_TRAP", summary: "trap inesperado no kernel (8 = falta dupla)", parameters: ["numero do trap", "reservado", "reservado", "reservado"], instruction: None },
    Code { code: 0x8E, name: "KERNEL_MODE_EXCEPTION_NOT_HANDLED", summary: "excecao de modo kernel sem tratador", parameters: ["codigo da excecao", "endereco da excecao", "quadro de trap", "reservado"], instruction: Some(1) },
    Code { code: 0x9F, name: "DRIVER_POWER_STATE_FAILURE", summary: "um driver ficou num estado de energia inconsistente", parameters: ["subtipo", "objeto de dispositivo", "dependente do subtipo", "IRP bloqueado"], instruction: None },
    Code { code: 0xB8, name: "ATTEMPTED_SWITCH_FROM_DPC", summary: "uma espera ou troca de thread pedida dentro de uma DPC", parameters: ["thread original", "thread nova", "endereco de pilha da thread original", "reservado"], instruction: None },
    Code { code: 0xBE, name: "ATTEMPTED_WRITE_TO_READONLY_MEMORY", summary: "escrita em memoria somente leitura", parameters: ["endereco", "PTE", "reservado", "reservado"], instruction: None },
    Code { code: 0xC2, name: "BAD_POOL_CALLER", summary: "pedido invalido ao pool", parameters: ["tipo da violacao", "dependente do tipo", "dependente do tipo", "dependente do tipo"], instruction: None },
    Code { code: 0xC4, name: "DRIVER_VERIFIER_DETECTED_VIOLATION", summary: "o verificador de drivers achou uma violacao", parameters: ["tipo da violacao", "dependente do tipo", "dependente do tipo", "dependente do tipo"], instruction: None },
    Code { code: 0xC5, name: "DRIVER_CORRUPTED_EXPOOL", summary: "acesso ao pool corrompido com IRQL alto", parameters: ["endereco referenciado", "IRQL", "operacao (0 leitura, 1 escrita)", "endereco da instrucao"], instruction: Some(3) },
    Code { code: 0xCE, name: "DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS", summary: "driver descarregado com operacoes pendentes", parameters: ["endereco referenciado", "operacao", "endereco da instrucao", "reservado"], instruction: Some(2) },
    Code { code: 0xD1, name: "DRIVER_IRQL_NOT_LESS_OR_EQUAL", summary: "driver acessou memoria paginavel ou invalida com IRQL alto", parameters: ["endereco referenciado", "IRQL no acesso", "operacao (0 leitura, 1 escrita, 8 execucao)", "endereco da instrucao"], instruction: Some(3) },
    Code { code: 0xD5, name: "DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL", summary: "driver usou memoria do pool especial ja liberada", parameters: ["endereco referenciado", "operacao", "endereco da instrucao", "reservado"], instruction: Some(2) },
    Code { code: 0xE2, name: "MANUALLY_INITIATED_CRASH", summary: "parada pedida pelo usuario (CrashOnCtrlScroll ou depurador)", parameters: ["0 ou definido pelo usuario", "0 ou definido pelo usuario", "0 ou definido pelo usuario", "0 ou definido pelo usuario"], instruction: None },
    Code { code: 0xEF, name: "CRITICAL_PROCESS_DIED", summary: "um processo critico terminou", parameters: ["objeto do processo", "se e o processo (0) ou thread (1)", "reservado", "reservado"], instruction: None },
    Code { code: 0xF4, name: "CRITICAL_OBJECT_TERMINATION", summary: "um processo ou thread critico terminou", parameters: ["tipo do objeto (3 processo, 6 thread)", "objeto que terminou", "nome da imagem do processo", "mensagem explicativa (ASCII)"], instruction: None },
    Code { code: 0xF7, name: "DRIVER_OVERRAN_STACK_BUFFER", summary: "estouro de buffer na pilha detectado pelo /GS", parameters: ["cookie encontrado", "cookie esperado", "complemento do cookie", "0"], instruction: None },
    Code { code: 0xFC, name: "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY", summary: "execucao em memoria sem permissao de execucao", parameters: ["endereco", "PTE", "reservado", "reservado"], instruction: None },
    Code { code: 0x101, name: "CLOCK_WATCHDOG_TIMEOUT", summary: "um processador nao atendeu a interrupcao do relogio", parameters: ["intervalo do relogio em tiques", "0", "PRCB do processador travado", "numero do processador"], instruction: None },
    Code { code: 0x109, name: "CRITICAL_STRUCTURE_CORRUPTION", summary: "codigo ou estrutura critica do kernel alterada", parameters: ["reservado", "reservado", "reservado", "tipo da regiao"], instruction: None },
    Code { code: 0x10E, name: "VIDEO_MEMORY_MANAGEMENT_INTERNAL", summary: "erro grave no gerenciador de memoria de video (dxgmms)", parameters: ["subtipo", "dependente do subtipo", "dependente do subtipo", "dependente do subtipo"], instruction: None },
    Code { code: 0x113, name: "VIDEO_DXGKRNL_FATAL_ERROR", summary: "o dxgkrnl encontrou um erro fatal", parameters: ["motivo da falha", "dependente do motivo", "dependente do motivo", "dependente do motivo"], instruction: None },
    Code { code: 0x116, name: "VIDEO_TDR_FAILURE", summary: "a recuperacao de um tempo esgotado do driver de video (TDR) falhou", parameters: ["contexto de recuperacao do TDR", "ponteiro para dentro do driver de video responsavel", "status da ultima operacao que falhou", "dado interno do contexto"], instruction: None },
    Code { code: 0x117, name: "VIDEO_TDR_TIMEOUT_DETECTED", summary: "o driver de video nao respondeu a tempo (TDR)", parameters: ["contexto de recuperacao do TDR", "ponteiro para dentro do driver de video responsavel", "status da ultima operacao que falhou", "dado interno do contexto"], instruction: None },
    Code { code: 0x119, name: "VIDEO_SCHEDULER_INTERNAL_ERROR", summary: "o escalonador de video encontrou uma violacao grave", parameters: ["tipo da falha", "dependente do tipo", "dependente do tipo", "dependente do tipo"], instruction: None },
    Code { code: 0x124, name: "WHEA_UNCORRECTABLE_ERROR", summary: "erro de hardware nao corrigivel", parameters: ["tipo do erro", "registro de erro WHEA", "dependente", "dependente"], instruction: None },
    Code { code: 0x133, name: "DPC_WATCHDOG_VIOLATION", summary: "DPC ou ISR demorou demais", parameters: ["0 (DPC unico) ou 1 (acumulado)", "tempo", "limite", "dependente"], instruction: None },
    Code { code: 0x139, name: "KERNEL_SECURITY_CHECK_FAILURE", summary: "o kernel detectou corrupcao de uma estrutura critica", parameters: ["tipo da corrupcao", "quadro de trap", "registro da excecao", "reservado"], instruction: None },
    Code { code: 0x13A, name: "KERNEL_MODE_HEAP_CORRUPTION", summary: "corrupcao do heap de modo kernel", parameters: ["tipo da corrupcao", "endereco do heap", "endereco da entrada", "reservado"], instruction: None },
    Code { code: 0x164, name: "WIN32K_CRITICAL_FAILURE", summary: "um componente do win32k encontrou uma falha critica", parameters: ["tipo da falha", "dependente do tipo", "dependente do tipo", "dependente do tipo"], instruction: None },
    Code { code: 0x1000007E, name: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M", summary: "excecao sem tratador numa thread de sistema", parameters: ["codigo da excecao", "endereco da excecao", "registro da excecao", "registro de contexto"], instruction: Some(1) },
    Code { code: 0x1000008E, name: "KERNEL_MODE_EXCEPTION_NOT_HANDLED_M", summary: "excecao de modo kernel sem tratador", parameters: ["codigo da excecao", "endereco da excecao", "quadro de trap", "reservado"], instruction: Some(1) },
    Code { code: 0xC000021A, name: "STATUS_SYSTEM_PROCESS_TERMINATED", summary: "um processo de sistema essencial terminou", parameters: ["mensagem", "status", "0", "0"], instruction: None },
];

/// Os códigos do `__fastfail` (FAST_FAIL_* do winnt.h), o parâmetro 1 do
/// KERNEL_SECURITY_CHECK_FAILURE.
const FAST_FAILS: &[(u64, &str)] = &[
    (0, "FAST_FAIL_LEGACY_GS_VIOLATION"),
    (1, "FAST_FAIL_VTGUARD_CHECK_FAILURE"),
    (2, "FAST_FAIL_STACK_COOKIE_CHECK_FAILURE"),
    (3, "FAST_FAIL_CORRUPT_LIST_ENTRY"),
    (4, "FAST_FAIL_INCORRECT_STACK"),
    (5, "FAST_FAIL_INVALID_ARG"),
    (6, "FAST_FAIL_GS_COOKIE_INIT"),
    (7, "FAST_FAIL_FATAL_APP_EXIT"),
    (8, "FAST_FAIL_RANGE_CHECK_FAILURE"),
    (9, "FAST_FAIL_UNSAFE_REGISTRY_ACCESS"),
    (10, "FAST_FAIL_GUARD_ICALL_CHECK_FAILURE"),
    (11, "FAST_FAIL_GUARD_WRITE_CHECK_FAILURE"),
    (12, "FAST_FAIL_INVALID_FIBER_SWITCH"),
    (13, "FAST_FAIL_INVALID_SET_OF_CONTEXT"),
    (14, "FAST_FAIL_INVALID_REFERENCE_COUNT"),
    (18, "FAST_FAIL_INVALID_JUMP_BUFFER"),
    (19, "FAST_FAIL_MRDATA_MODIFIED"),
    (20, "FAST_FAIL_CERTIFICATION_FAILURE"),
    (21, "FAST_FAIL_INVALID_EXCEPTION_CHAIN"),
    (22, "FAST_FAIL_CRYPTO_LIBRARY"),
    (23, "FAST_FAIL_INVALID_CALL_IN_DLL_CALLOUT"),
];

/// Os vetores de exceção do x64, o parâmetro 1 do UNEXPECTED_KERNEL_MODE_TRAP.
const TRAPS: &[(u64, &str)] = &[
    (0x0, "divisao por zero"),
    (0x1, "depuracao"),
    (0x2, "NMI"),
    (0x3, "breakpoint"),
    (0x4, "overflow"),
    (0x5, "BOUND"),
    (0x6, "opcode invalido"),
    (0x7, "FPU indisponivel"),
    (0x8, "falta dupla"),
    (0xA, "TSS invalido"),
    (0xB, "segmento ausente"),
    (0xC, "falta de pilha"),
    (0xD, "protecao geral"),
    (0xE, "falta de pagina"),
    (0x10, "erro de ponto flutuante"),
    (0x11, "alinhamento"),
    (0x12, "machine check"),
    (0x13, "SIMD"),
];

fn table_name(table: &[(u64, &'static str)], value: u64) -> Option<String> {
    table.iter().find(|(key, _)| *key == value).map(|(_, name)| (*name).to_string())
}

/// O nome de um NTSTATUS (exceções primeiro).
fn status_name(value: u64) -> Option<String> {
    let status = u32::try_from(value).ok().or_else(|| (value >> 32 == 0xFFFF_FFFF).then_some(value as u32))?;
    exception_name(status).or_else(|| super::ntstatus::name(status)).map(str::to_string)
}

/// O que o valor de um parâmetro quer dizer, quando o código o define (o
/// sentido no Windows 10 19041): o nome do status ou da exceção, o tipo de
/// acesso, o vetor do trap, o código do `__fastfail`, o subtipo.
pub fn parameter_note(code: u32, index: usize, parameters: &[u64; 4]) -> Option<String> {
    let value = *parameters.get(index)?;
    match (code, index) {
        (0x1E | 0x3B | 0x7E | 0x8E | 0x1000007E | 0x1000008E, 0) => status_name(value),
        // A violação de acesso: ExceptionInformation[0] é o tipo do acesso
        // (o kernel do OpenNT passa zeros quando não preenche os dois).
        (0x1E, 2) if parameters[0] == 0xC000_0005 && (parameters[2] != 0 || parameters[3] != 0) => match value {
            0 => Some("leitura".into()),
            1 => Some("escrita".into()),
            8 => Some("execucao (DEP)".into()),
            _ => None,
        },
        (0x0A | 0xD1, 2) => Some(if value & 8 != 0 { "execucao" } else if value & 1 != 0 { "escrita" } else { "leitura" }.into()),
        (0x50, 1) => match value {
            0 => Some("leitura".into()),
            1 | 2 => Some("escrita".into()),
            0x10 => Some("execucao".into()),
            _ => None,
        },
        (0x7F, 0) => table_name(TRAPS, value),
        (0x139, 0) => table_name(FAST_FAILS, value),
        (0x9F, 0) => match value {
            1 => Some("objeto de dispositivo liberado com um pedido de energia pendente".into()),
            2 => Some("IRP de energia completado sem PoStartNextPowerIrp".into()),
            3 => Some("um objeto de dispositivo segurou um IRP de energia por tempo demais".into()),
            4 => Some("tempo esgotado esperando a sincronizacao com o PnP".into()),
            _ => None,
        },
        (0xF4, 0) => match value {
            3 => Some("processo".into()),
            6 => Some("thread".into()),
            _ => None,
        },
        (0xEF, 1) => match value {
            0 => Some("o processo".into()),
            1 => Some("uma thread".into()),
            _ => None,
        },
        (0x133, 0) => match value {
            0 => Some("uma DPC ou ISR demorou demais".into()),
            1 => Some("tempo acumulado demais em DPC".into()),
            _ => None,
        },
        (0x6B, 0) | (0x7B, 1) | (0x116 | 0x117, 2) | (0xC000021A, 1) => status_name(value),
        _ => None,
    }
}

/// Nomes de NTSTATUS de exceções comuns.
const EXCEPTIONS: &[(u32, &str)] = &[
    (0x8000_0003, "STATUS_BREAKPOINT"),
    (0x8000_0004, "STATUS_SINGLE_STEP"),
    (0xC000_0005, "STATUS_ACCESS_VIOLATION"),
    (0xC000_001D, "STATUS_ILLEGAL_INSTRUCTION"),
    (0xC000_008C, "STATUS_ARRAY_BOUNDS_EXCEEDED"),
    (0xC000_0094, "STATUS_INTEGER_DIVIDE_BY_ZERO"),
    (0xC000_0095, "STATUS_INTEGER_OVERFLOW"),
    (0xC000_0096, "STATUS_PRIVILEGED_INSTRUCTION"),
    (0xC000_00FD, "STATUS_STACK_OVERFLOW"),
    (0xC000_0409, "STATUS_STACK_BUFFER_OVERRUN"),
    (0xC000_0420, "STATUS_ASSERTION_FAILURE"),
];

pub fn code(code: u32) -> Option<&'static Code> {
    CODES.iter().find(|entry| entry.code == code)
}

pub fn exception_name(status: u32) -> Option<&'static str> {
    EXCEPTIONS.iter().find(|(value, _)| *value == status).map(|(_, name)| *name)
}

/// Um parâmetro explicado.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameter {
    pub label: String,
    pub value: u64,
    /// O símbolo do endereço, o nome do NTSTATUS ou vazio.
    pub note: String,
}

/// O resultado do `!analyze`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Analysis {
    pub code: u32,
    pub name: String,
    pub summary: String,
    pub parameters: Vec<Parameter>,
    /// O módulo (driver) culpado e por quê.
    pub blamed: Option<(String, String)>,
    /// A pilha (endereço, símbolo).
    pub stack: Vec<(u64, String)>,
}

/// Módulos do próprio kernel e do caminho do bugcheck, que não levam a culpa.
fn is_system_module(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.is_empty() || lower == "kernel" || lower.starts_with("ntoskrnl") || lower.starts_with("ntkrnl") || lower.starts_with("hal")
}

/// Monta a análise. `module_of` dá o nome do módulo de um endereço e
/// `describe` o símbolo; `stack` são os quadros (endereço, símbolo).
pub fn analyze(code_value: u32, parameters: [u64; 4], stack: Vec<(u64, String)>, module_of: &dyn Fn(u64) -> Option<String>, describe: &dyn Fn(u64) -> String) -> Analysis {
    let known = code(code_value);
    let explained: Vec<Parameter> = (0..4)
        .map(|index| {
            let value = parameters[index];
            let label = known.map_or_else(|| format!("parametro {}", index + 1), |entry| entry.parameters[index].to_string());
            let note = if let Some(note) = parameter_note(code_value, index, &parameters) {
                note
            } else if label.contains("codigo da excecao") || label == "status" {
                exception_name(value as u32).unwrap_or("").to_string()
            } else if module_of(value).is_some() {
                describe(value)
            } else {
                String::new()
            };
            Parameter { label, value, note }
        })
        .collect();
    // O culpado: o módulo da instrução que falhou; senão o primeiro quadro
    // da pilha fora do kernel; senão o módulo de algum parâmetro.
    let mut blamed = None;
    if let Some(index) = known.and_then(|entry| entry.instruction) {
        if let Some(module) = module_of(parameters[index]).filter(|module| !is_system_module(module)) {
            blamed = Some((module, format!("contem o endereco da instrucao ({:#x})", parameters[index])));
        }
    }
    if blamed.is_none() {
        blamed = stack.iter().find_map(|(address, name)| module_of(*address).filter(|module| !is_system_module(module)).map(|module| (module, format!("primeiro quadro fora do kernel: {name}"))));
    }
    if blamed.is_none() {
        blamed = parameters.iter().find_map(|&value| module_of(value).filter(|module| !is_system_module(module)).map(|module| (module, format!("um parametro aponta para ele ({value:#x})"))));
    }
    Analysis {
        code: code_value,
        name: known.map_or_else(|| format!("BUGCHECK_{code_value:X}"), |entry| entry.name.to_string()),
        summary: known.map_or_else(|| "codigo sem descricao no depurador".to_string(), |entry| entry.summary.to_string()),
        parameters: explained,
        blamed,
        stack,
    }
}

impl Analysis {
    /// O texto do `!analyze`.
    pub fn text(&self) -> String {
        let mut output = format!("BUGCHECK {:#010x} {}\n{}\n\nparametros:\n", self.code, self.name, self.summary);
        for (index, parameter) in self.parameters.iter().enumerate() {
            output.push_str(&format!("  {} {:#018x}  {}", index + 1, parameter.value, parameter.label));
            if !parameter.note.is_empty() {
                output.push_str(&format!("  [{}]", parameter.note));
            }
            output.push('\n');
        }
        match &self.blamed {
            Some((module, reason)) => output.push_str(&format!("\nprovavel causa: {module} ({reason})\n")),
            None => output.push_str("\nprovavel causa: nenhum driver fora do kernel na pilha nem nos parametros\n"),
        }
        output.push_str("\npilha:\n");
        for (depth, (address, name)) in self.stack.iter().enumerate() {
            output.push_str(&format!("  #{depth:<2} {address:#018x} {name}\n"));
        }
        output
    }
}

/// O `monitor bugcheck`: `bugcheck 0x000000e2 (0x0, 0x0, 0x0, 0x0)`.
pub fn parse_monitor(text: &str) -> Option<(u32, [u64; 4])> {
    let rest = text.lines().find_map(|line| line.trim().strip_prefix("bugcheck "))?;
    let (code, parameters) = rest.split_once('(')?;
    let code = super::parse_number(code.trim())? as u32;
    let values: Vec<u64> = parameters.trim_end_matches(|character: char| character == ')' || character.is_whitespace()).split(',').filter_map(|value| super::parse_number(value.trim())).collect();
    let parameters: [u64; 4] = values.get(..4)?.try_into().ok()?;
    Some((code, parameters))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_explains_parameters() {
        let module_of = |address: u64| match address {
            0xfffff800_5000_0000..=0xfffff800_5010_0000 => Some("ntfs".to_string()),
            0xfffff800_4000_0000..=0xfffff800_4100_0000 => Some("kernel".to_string()),
            _ => None,
        };
        let describe = |address: u64| format!("simbolo@{address:x}");
        let stack = vec![(0xfffff800_4000_1000, "kernel::ntos::ke::bugcheck::bug_check_ex".to_string()), (0xfffff800_5000_1234, "ntfs!NtfsCommonCreate+0x1a3".to_string())];
        let analysis = analyze(0xD1, [0x10, 2, 0, 0xfffff800_5000_1234], stack.clone(), &module_of, &describe);
        assert_eq!(analysis.name, "DRIVER_IRQL_NOT_LESS_OR_EQUAL");
        assert_eq!(analysis.parameters[1].label, "IRQL no acesso");
        assert_eq!(analysis.parameters[3].note, "simbolo@fffff80050001234");
        assert_eq!(analysis.blamed.as_ref().map(|(module, _)| module.as_str()), Some("ntfs"));
        assert!(analysis.text().contains("provavel causa: ntfs"));
        // Sem instrução culpada: o primeiro quadro fora do kernel.
        let analysis = analyze(0xE2, [0; 4], stack, &module_of, &describe);
        assert_eq!(analysis.name, "MANUALLY_INITIATED_CRASH");
        assert!(analysis.blamed.as_ref().unwrap().1.contains("NtfsCommonCreate"));
        let analysis = analyze(0x1E, [0xC000_0005, 0x1, 0, 0], Vec::new(), &module_of, &describe);
        assert_eq!(analysis.parameters[0].note, "STATUS_ACCESS_VIOLATION");
        assert!(analysis.blamed.is_none());
        assert_eq!(analyze(0x12345, [0; 4], Vec::new(), &module_of, &describe).name, "BUGCHECK_12345");
    }

    #[test]
    fn explains_parameters_by_code() {
        let note = |code: u32, index: usize, parameters: [u64; 4]| parameter_note(code, index, &parameters);
        assert_eq!(note(0x1E, 0, [0xC000_0005, 0, 0, 0]).as_deref(), Some("STATUS_ACCESS_VIOLATION"));
        assert_eq!(note(0x3B, 0, [0xC000_001D, 0, 0, 0]).as_deref(), Some("STATUS_ILLEGAL_INSTRUCTION"));
        // Sem os parâmetros da exceção preenchidos, nada a dizer do acesso.
        assert_eq!(note(0x1E, 2, [0xC000_0005, 0x1000, 0, 0]), None);
        assert_eq!(note(0x1E, 2, [0xC000_0005, 0x1000, 1, 0x40]).as_deref(), Some("escrita"));
        assert_eq!(note(0xD1, 2, [0x10, 2, 8, 0]).as_deref(), Some("execucao"));
        assert_eq!(note(0x0A, 2, [0x10, 2, 1, 0]).as_deref(), Some("escrita"));
        assert_eq!(note(0x50, 1, [0x10, 2, 0, 0]).as_deref(), Some("escrita"));
        assert_eq!(note(0x7F, 0, [8, 0, 0, 0]).as_deref(), Some("falta dupla"));
        assert_eq!(note(0x139, 0, [3, 0, 0, 0]).as_deref(), Some("FAST_FAIL_CORRUPT_LIST_ENTRY"));
        assert_eq!(note(0xC000021A, 1, [0, 0xFFFF_FFFF_C000_0034, 0, 0]).as_deref(), Some("STATUS_OBJECT_NAME_NOT_FOUND"));
        assert_eq!(note(0x116, 2, [0, 0, 0xC000_0001, 0]).as_deref(), Some("STATUS_UNSUCCESSFUL"));
        assert_eq!(note(0xE2, 0, [0; 4]), None);
        assert_eq!(code(0x164).map(|entry| entry.name), Some("WIN32K_CRITICAL_FAILURE"));
        assert_eq!(code(0x116).map(|entry| entry.parameters[1]), Some("ponteiro para dentro do driver de video responsavel"));
    }

    #[test]
    fn parses_the_monitor_line() {
        assert_eq!(parse_monitor("bugcheck 0x000000e2 (0x0, 0x1, 0xfffff80040000000, 0x4)\n"), Some((0xE2, [0, 1, 0xfffff80040000000, 4])));
        assert_eq!(parse_monitor("nenhum bugcheck\n"), None);
    }
}
