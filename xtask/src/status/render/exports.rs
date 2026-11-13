//! `ntoskrnl.html` (resumo dos exports, gráfico, glossário e busca) e uma
//! página por grupo de prefixo (`ntoskrnl-<grupo>.html`) com a lista
//! paginada dos nomes.

use std::collections::{BTreeMap, BTreeSet};

use super::super::{ExportReport, Report, State, Tally};
use super::common::{
    anchor, big_stat, code, component_anchor, escape, filter_bar, hero, icon_tile, int, meter, html_page, percent, plural,
    ring_stat, section, PAGER_SCRIPT,
};
use super::components::WINDOWS_DRIVERS;

/// Linhas por página nas listas de cada grupo.
const EXPORTS_PER_PAGE: usize = 100;
/// Resultados mostrados pela busca da página principal.
const SEARCH_RESULTS: usize = 40;

// ---- textos fixos sobre o kernel do Windows ---------------------------------------

pub struct PrefixInfo {
    pub short: &'static str,
    pub long: &'static str,
    pub examples: &'static [&'static str],
}

pub fn prefix_info(bucket: &str) -> PrefixInfo {
    let (short, long, examples): (&str, &str, &[&str]) = match bucket {
        "Ke" => (
            "núcleo: threads, sincronização, DPC/APC",
            "Kernel propriamente dito: escalonamento de threads, objetos de sincronização (eventos, mutexes, \
             semáforos, timers), DPCs e APCs, spin locks e informações dos processadores. Inclui Kf, Ki e Kx.",
            &["KeWaitForSingleObject", "KeSetEvent", "KeInitializeDpc", "KeDelayExecutionThread"],
        ),
        "Ke*Irql" => (
            "nível de interrupção (IRQL)",
            "A parte do Ke que lê ou muda o IRQL, o nível de prioridade de interrupção em que o processador está \
             rodando. Quase todo driver usa essas rotinas, direta ou indiretamente.",
            &["KeGetCurrentIrql", "KfRaiseIrql", "KeLowerIrql"],
        ),
        "Mm" => (
            "memória virtual e física",
            "Memory Manager: mapeamento de memória física e de dispositivos, MDLs (descrições de buffers), seções, \
             memória contígua e endereços de rotinas do sistema.",
            &["MmMapIoSpace", "MmGetSystemRoutineAddress", "MmProbeAndLockPages", "MmAllocateContiguousMemory"],
        ),
        "Ob" => (
            "gerenciador de objetos",
            "Object Manager: tudo no kernel é um objeto com nome, contagem de referências e handles (processos, \
             arquivos, eventos, dispositivos). Ob cuida de referenciar, nomear e proteger esses objetos.",
            &["ObReferenceObjectByHandle", "ObfDereferenceObject", "ObRegisterCallbacks"],
        ),
        "Ps" => (
            "processos e threads",
            "Process Manager: criação e consulta de processos e threads e as notificações que drivers recebem \
             quando um processo, thread ou imagem é criado.",
            &["PsCreateSystemThread", "PsGetCurrentProcessId", "PsSetCreateProcessNotifyRoutineEx", "PsInitialSystemProcess"],
        ),
        "Io" => (
            "entrada e saída, drivers, IRPs",
            "I/O Manager: o contrato entre o kernel e os drivers. Criação de dispositivos, IRPs (pedidos de I/O), \
             pilhas de drivers, Plug and Play e work items.",
            &["IoCreateDevice", "IofCallDriver", "IofCompleteRequest", "IoCreateSymbolicLink"],
        ),
        "Ex" => (
            "executive: pool, locks, work items",
            "Executive: alocação de memória do pool, locks do executive (ERESOURCE, push locks, fast mutexes), \
             listas lookaside, filas de trabalho e callbacks.",
            &["ExAllocatePoolWithTag", "ExFreePoolWithTag", "ExAcquireResourceExclusiveLite", "ExQueueWorkItem"],
        ),
        "Rtl" => (
            "biblioteca de runtime",
            "Runtime Library: rotinas de apoio usadas por todo o kernel, como strings Unicode, listas, árvores, \
             bitmaps, conversões numéricas, SIDs e ACLs, compressão e consulta de versão.",
            &["RtlInitUnicodeString", "RtlCompareUnicodeString", "RtlGetVersion", "RtlInitializeBitMap"],
        ),
        "Se" => (
            "segurança e tokens",
            "Security Reference Monitor: tokens de acesso, verificação de permissões, privilégios e descritores \
             de segurança.",
            &["SeAccessCheck", "SeSinglePrivilegeCheck", "SeCaptureSubjectContext", "SeExports"],
        ),
        "Zw/Nt" => (
            "serviços do sistema",
            "As chamadas de sistema do NT (abrir arquivos, ler o Registro, consultar o sistema). As Nt* são as \
             que os programas chamam pela ntdll; as Zw* são a versão para chamar de dentro do kernel.",
            &["ZwCreateFile", "ZwReadFile", "ZwQuerySystemInformation", "NtClose"],
        ),
        "Cm" => (
            "Registro",
            "Configuration Manager, o dono do Registro. Os exports Cm são principalmente os callbacks que avisam \
             drivers sobre operações no Registro; o acesso às chaves em si passa pelas Zw*.",
            &["CmRegisterCallbackEx", "CmUnRegisterCallback"],
        ),
        "Po" => (
            "energia",
            "Power Manager: estados de energia do sistema e dos dispositivos, IRPs de energia e o framework de \
             gerência de energia por componente (PoFx).",
            &["PoCallDriver", "PoRequestPowerIrp", "PoSetPowerState"],
        ),
        "Hal" => (
            "abstração de hardware",
            "Hardware Abstraction Layer: o que esconde as diferenças entre plataformas, como barramentos, DMA, \
             relógio, reinício e firmware. No Windows 10 essas rotinas moram no próprio ntoskrnl.exe.",
            &["HalGetBusDataByOffset", "HalReturnToFirmware", "HalQueryRealTimeClock"],
        ),
        "Wmi/Etw" => (
            "instrumentação e rastreamento",
            "Windows Management Instrumentation e Event Tracing for Windows: publicação de eventos, contadores e \
             rastreamento de drivers. Inclui o WPP (Wpp*).",
            &["EtwRegister", "EtwWrite", "WmiQueryTraceInformation"],
        ),
        "Fs/FsRtl" => (
            "apoio a sistemas de arquivos",
            "File System Runtime Library: rotinas para quem escreve sistemas de arquivos e filtros, como oplocks, \
             travas de faixas de arquivo, comparação de nomes e notificações de mudança.",
            &["FsRtlIsNameInExpression", "FsRtlCheckOplock", "FsRtlNotifyFullReportChange"],
        ),
        "Kd" => (
            "depurador de kernel",
            "Kernel Debugger: o estado da conexão com o depurador de kernel e o controle dele.",
            &["KdDebuggerEnabled", "KdRefreshDebuggerNotPresent", "KdDisableDebugger"],
        ),
        "Inbv" => (
            "vídeo do boot",
            "Initialization Boot Video: a tela de texto do boot e da tela azul, usada antes de existir driver de \
             vídeo.",
            &["InbvDisplayString", "InbvResetDisplay", "InbvAcquireDisplayOwnership"],
        ),
        _ => (
            "cache, transações, CRT e outros",
            "O restante: Cache Manager (Cc), transações (Tm), erros de hardware (Whea), hipervisor (Hvl), Driver \
             Verifier (Vf), impressão de depuração (Dbg), comunicação local entre processos (Lpc/Alpc) e rotinas \
             da biblioteca C (memcpy, sprintf, _stricmp...).",
            &["CcCopyRead", "DbgPrint", "WheaReportHwError", "memcpy"],
        ),
    };
    PrefixInfo { short, long, examples }
}

fn prefix_icon(bucket: &str) -> &'static str {
    match bucket {
        "Ke" | "Ke*Irql" => "cpu",
        "Mm" => "memory",
        "Ob" => "cube",
        "Ps" => "threads",
        "Io" => "io",
        "Ex" => "sliders",
        "Rtl" => "book",
        "Se" => "shield",
        "Zw/Nt" => "layers",
        "Cm" => "database",
        "Po" => "power",
        "Hal" => "chip",
        "Wmi/Etw" => "chart",
        "Fs/FsRtl" => "folder",
        "Kd" => "check",
        "Inbv" => "monitor",
        _ => "cube",
    }
}

/// Descrições dos subprefixos mais comuns em "outros". Só os conhecidos;
/// os demais aparecem sem descrição.
fn other_prefix_meaning(prefix: &str) -> Option<&'static str> {
    Some(match prefix {
        "Cc" => "Cache Manager",
        "Tm" => "transações (KTM)",
        "Whea" => "erros de hardware",
        "Hvl" => "hipervisor",
        "Vf" => "Driver Verifier",
        "Dbg" => "depuração",
        "Em" => "Errata Manager",
        "Ldr" => "recursos de imagens",
        "Kse" => "Kernel Shim Engine",
        "Lpc" | "Alpc" => "comunicação entre processos",
        "Lsa" => "autenticação",
        "Nls" => "idiomas e páginas de código",
        "Pcw" => "contadores de desempenho",
        "Pfx" => "tabelas de prefixos",
        _ => return None,
    })
}

/// Os maiores subprefixos do grupo "outros" (`Cc`, `Tm`...), com a contagem.
fn other_prefixes(exports: &ExportReport) -> String {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for row in exports.rows.iter().filter(|row| row.bucket == "outros") {
        let first = row.name.chars().next().unwrap_or('_');
        let key = if !first.is_ascii_uppercase() {
            "CRT".to_string()
        } else {
            let tail: String = row.name.chars().skip(1).take_while(|c| c.is_ascii_lowercase()).collect();
            format!("{first}{tail}")
        };
        *counts.entry(key).or_default() += 1;
    }
    let mut ranked: Vec<(String, usize)> = counts.into_iter().collect();
    ranked.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
    ranked
        .iter()
        .take(10)
        .map(|(prefix, count)| {
            let meaning = if prefix == "CRT" {
                Some("biblioteca C: nomes em minúsculas ou com _")
            } else {
                other_prefix_meaning(prefix)
            };
            match meaning {
                Some(meaning) => format!("<strong>{}</strong> {} ({})", escape(prefix), int(*count), meaning),
                None => format!("<strong>{}</strong> {}", escape(prefix), int(*count)),
            }
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

// ---- grupos ------------------------------------------------------------------

pub fn group_file(bucket: &str) -> String {
    format!("ntoskrnl-{}.html", anchor(bucket))
}

/// Grupos com pelo menos um export, na ordem das páginas.
fn groups(exports: &ExportReport) -> Vec<(&'static str, &Tally)> {
    exports.buckets.iter().filter(|(_, tally)| tally.reference > 0).map(|(name, tally)| (*name, tally)).collect()
}

/// "841 funções e 15 variáveis".
fn kinds(functions: usize, variables: usize) -> String {
    match (functions, variables) {
        (_, 0) => plural(functions, "função", "funções"),
        (0, _) => plural(variables, "variável", "variáveis"),
        _ => format!("{} e {}", plural(functions, "função", "funções"), plural(variables, "variável", "variáveis")),
    }
}

fn examples(name: &str, names: &BTreeSet<&str>) -> String {
    let found: Vec<String> =
        prefix_info(name).examples.iter().filter(|example| names.contains(**example)).map(|example| code(example)).collect();
    if found.is_empty() {
        String::new()
    } else {
        format!("<div class=\"examples\">Exemplos: {}</div>", found.join(" "))
    }
}

fn prefix_row(name: &str, tally: &Tally, names: &BTreeSet<&str>, exports: &ExportReport) -> String {
    let info = prefix_info(name);
    let mut description = format!(
        "<a class=\"pill\" href=\"{}\">{}</a> · {}",
        group_file(name),
        escape(name),
        escape(info.long)
    );
    if name == "outros" {
        description.push_str(&format!("<div class=\"examples\">Maiores subgrupos: {}</div>", other_prefixes(exports)));
    }
    description.push_str(&examples(name, names));
    format!(
        "<div class=\"card lift prefix\" id=\"g-{id}\">{icon}<div>{description}</div><div class=\"nums\"><strong>{covered}\
         </strong> de {reference} no OpenNT · faltam {missing}{bar}<span class=\"muted\">{pct} · \
         <a href=\"{file}\">ver a lista</a></span></div></div>",
        id = anchor(name),
        icon = icon_tile(prefix_icon(name), ""),
        covered = int(tally.opennt),
        reference = int(tally.reference),
        missing = int(tally.missing()),
        bar = meter(tally.opennt, 0, tally.reference, &percent(tally.opennt, tally.reference)),
        pct = escape(&percent(tally.opennt, tally.reference)),
        file = group_file(name),
    )
}

/// Os dados da busca: um token por export, `<tipo><grupo><nome>`, onde o
/// tipo é `a` (função exportada), `b` (função que falta), `c` (variável
/// exportada) ou `d` (variável que falta) e o grupo é `a` + índice.
fn search_data(exports: &ExportReport) -> (String, String) {
    let groups = groups(exports);
    let tokens: Vec<String> = exports
        .rows
        .iter()
        .filter_map(|row| {
            let group = groups.iter().position(|(name, _)| *name == row.bucket)?;
            let kind = match (row.data, row.opennt) {
                (false, true) => 'a',
                (false, false) => 'b',
                (true, true) => 'c',
                (true, false) => 'd',
            };
            Some(format!("{kind}{}{}", (b'a' + group as u8) as char, row.name))
        })
        .collect();
    let labels: Vec<String> =
        groups.iter().map(|(name, _)| format!("[\"{}\",\"{}\"]", anchor(name), escape(name))).collect();
    (tokens.join(" "), format!("[{}]", labels.join(",")))
}

const SEARCH_SCRIPT: &str = r#"
(function(){
  var input=document.getElementById('busca'),out=document.getElementById('resultados'),info=document.getElementById('busca-info');
  var E=EXPORTS.split(' ');
  function rank(token,q){var l=token.slice(2).toLowerCase();return l===q?0:(l.indexOf(q)===0?1:2);}
  input.addEventListener('input',function(){
    var q=input.value.trim().toLowerCase(),hits=[],html='';
    if(!q){out.innerHTML='';info.textContent='';return;}
    E.forEach(function(token){if(token.slice(2).toLowerCase().indexOf(q)>=0)hits.push(token);});
    hits.sort(function(a,b){return rank(a,q)-rank(b,q)||(a.slice(2)<b.slice(2)?-1:1);});
    hits.slice(0,LIMIT).forEach(function(token){
      var kind=token.charAt(0),group=GROUPS[token.charCodeAt(1)-97],name=token.slice(2),yes=kind==='a'||kind==='c';
      html+='<li><a href="ntoskrnl-'+group[0]+'.html#e-'+name+'"><code>'+name+'</code></a><span class="muted">'+
        (kind<'c'?'função':'variável')+' · grupo '+group[1]+'</span>'+
        (yes?'<span class="yes">o OpenNT exporta</span>':'<span class="no">falta no OpenNT</span>')+'</li>';
    });
    out.innerHTML=html;
    info.textContent=hits.length===0?'Nenhum export do ntoskrnl.exe contém esse texto.':
      (hits.length>LIMIT?'Mostrando '+LIMIT+' de '+hits.length+' resultados; continue digitando para refinar.':
      hits.length+(hits.length===1?' resultado.':' resultados.'));
  });
})();
"#;

fn search_block(exports: &ExportReport) -> String {
    format!(
        "<div class=\"js-only\"><div class=\"controls\" role=\"search\"><label>Nome <input id=\"busca\" type=\"search\" \
         placeholder=\"ex.: IoCreateDevice\" autocomplete=\"off\"></label><span id=\"busca-info\" class=\"count muted \
         small\" aria-live=\"polite\"></span></div><ul id=\"resultados\" class=\"results\"></ul></div>\
         <p class=\"no-js small muted\">A busca precisa de JavaScript. Sem ele, abra a lista do grupo pelo prefixo do \
         nome (abaixo) e use a busca do navegador.</p><p class=\"small muted\">A busca procura entre os {} nomes do \
         <code>ntoskrnl.exe</code> do Windows; o link leva à lista do grupo.</p>",
        int(exports.total.reference)
    )
}

pub fn page(report: &Report, chart: &str) -> String {
    let exports = &report.exports;
    let total = &exports.total;
    let data = total.reference - total.functions;
    let data_opennt = total.opennt - total.functions_opennt;
    let opennt_all = total.opennt + exports.opennt_extra.len();
    let mut body = hero(
        "Compatibilidade com o Windows 10",
        "Exports do ntoskrnl",
        &format!(
            "Dos {} nomes que o ntoskrnl.exe do Windows 10 exporta para os drivers, quantos o kernel do OpenNT também \
             exporta.",
            int(total.reference)
        ),
        "<strong>O que é contado:</strong> um nome da lista do Windows conta quando aparece na tabela de exports do \
         kernel do OpenNT. Cada nome exportado tem uma rotina ou variável do OpenNT por trás, mas ter o nome não \
         garante que ela trate todos os casos que o Windows trata. Referência: <code>ntoskrnl.exe</code> do Windows \
         10 22H2 (build 19045).",
        &format!(
            "{}{}{}{}",
            ring_stat(total.opennt, total.reference, "Exportados pelo OpenNT", &format!("{} dos {} nomes da lista do Windows", int(total.opennt), int(total.reference))),
            big_stat(&int(total.reference), "Exports do Windows", &kinds(total.functions, data)),
            big_stat(&int(total.opennt), "Também no OpenNT", &kinds(total.functions_opennt, data_opennt)),
            big_stat(&int(total.missing()), "Faltam no OpenNT", &kinds(total.functions - total.functions_opennt, data - data_opennt)),
        ),
    );

    body.push_str(&section("consulta", "Consulta", "O OpenNT exporta este nome?", "", &search_block(exports)));

    let working: Vec<String> = report
        .components
        .iter()
        .filter(|row| row.category == WINDOWS_DRIVERS && row.state == State::Works)
        .map(|row| format!("<a href=\"componentes.html#{}\">{}</a>", component_anchor(row), escape(&row.name)))
        .collect();
    let working = if working.is_empty() {
        "Nenhum driver do Windows passa ainda por um teste automático.".to_string()
    } else {
        format!("Os drivers do Windows que já carregam e rodam nos testes automáticos usando estes exports: {}.", working.join(", "))
    };
    body.push_str(&section(
        "o-que-sao",
        "Para começar",
        "O que são exports e o que este número diz",
        "",
        &format!(
            "<div class=\"grid\"><div class=\"explain\"><h3>O que é um export?</h3>\
             <p>O <code>ntoskrnl.exe</code> é o kernel do Windows. Um driver (<code>.sys</code>) não traz o kernel \
             junto: na sua tabela de importação ele lista, pelo nome, as rotinas do kernel que vai chamar, como \
             <code>IoCreateDevice</code> para criar um dispositivo ou <code>ExAllocatePoolWithTag</code> para alocar \
             memória. Essas rotinas, e algumas variáveis globais como <code>PsInitialSystemProcess</code>, são os \
             <em>exports</em> do kernel.</p></div>\
             <div class=\"explain\"><h3>O que o número diz, e o que não diz</h3>\
             <p><strong>Diz</strong> quantos nomes da lista do Windows o kernel do OpenNT também exporta. Ao carregar \
             um driver, o kernel procura cada nome importado; se um único nome faltar, o driver não carrega.</p>\
             <p><strong>Não diz</strong> se cada rotina se comporta exatamente como a do Windows. Isso é verificado \
             pelos <a href=\"testes.html\">testes automáticos</a>. {working}</p></div></div>"
        ),
    ));

    body.push_str(&section(
        "grafico",
        "Visão por área",
        "Exports por prefixo",
        "O nome de cada export começa com um prefixo que indica a parte do kernel a que ele pertence.",
        &format!(
            "<figure><div class=\"chart\">{}</div><figcaption><strong>Como ler:</strong> cada barra é um prefixo. A \
             barra inteira é o número de exports do Windows com aquele prefixo (a mais longa é o maior grupo); a parte \
             azul é o que o OpenNT também exporta e a parte cinza, o que falta. À direita, a mesma conta em \
             números.</figcaption></figure>",
            chart.trim()
        ),
    ));

    let names: BTreeSet<&str> = exports.rows.iter().map(|row| row.name.as_str()).collect();
    let mut prefixes = String::from("<div class=\"prefixes\">");
    for (name, tally) in groups(exports) {
        prefixes.push_str(&prefix_row(name, tally, &names, exports));
    }
    prefixes.push_str(
        "</div><p class=\"small muted\">Regra de agrupamento: um nome pertence a um prefixo quando começa por ele \
         seguido de maiúscula, ou de <code>f</code>, <code>i</code>, <code>p</code> ou <code>x</code> e maiúscula (a \
         convenção do NT para rotinas rápidas, internas e privadas, como <code>ObfReferenceObject</code> e \
         <code>IofCallDriver</code>). Ke reúne Ke, Kf, Ki e Kx; Ke*Irql são os desses com <code>Irql</code> no nome; \
         Wmi/Etw inclui Wpp.</p>",
    );
    body.push_str(&section(
        "grupos",
        "Glossário e listas",
        "Os grupos de prefixo",
        "O que cada prefixo significa e quanto dele o OpenNT exporta. Cada grupo tem uma página com a lista completa \
         dos nomes, dividida em páginas de 100.",
        &prefixes,
    ));

    if !exports.opennt_extra.is_empty() {
        let names: Vec<String> = exports.opennt_extra.iter().map(|name| code(name)).collect();
        body.push_str(&section(
            "extras",
            "Além da lista",
            "Nomes extras do OpenNT",
            &format!(
                "No total, o kernel do OpenNT exporta {} nomes: os {} acima e mais {} que não estão na tabela do \
                 <code>ntoskrnl.exe</code> do Windows 10 22H2 (por exemplo, rotinas que no Windows 10 x64 ficam na \
                 HAL ou só existem em outras versões). Eles não entram na porcentagem.",
                int(opennt_all),
                int(total.opennt),
                int(exports.opennt_extra.len())
            ),
            &format!(
                "<details><summary>Ver os {} nomes extras</summary><div class=\"inner\"><p class=\"small\">{}</p></div>\
                 </details>",
                int(exports.opennt_extra.len()),
                names.join(" ")
            ),
        ));
    }

    body.push_str(&section(
        "fontes",
        "Fontes",
        "De onde vêm os números",
        "",
        &format!(
            "<ul class=\"small\"><li><strong>Windows</strong>: a tabela de exports do <code>ntoskrnl.exe</code> real \
             (arquivo {}), lida pelo próprio gerador e guardada em <code>docs/status/ntoskrnl-exports.def</code>; só os \
             nomes, nunca o binário. Um export é <em>variável</em> quando aponta para uma seção sem permissão de \
             execução.{}</li><li><strong>OpenNT</strong>: os nomes da tabela de exports do kernel, que vêm de \
             <code>kernel/src/ntos/init/export_names.rs</code> (funções) e \
             <code>kernel/src/ntos/mm/kernel_data_layout.rs</code> (variáveis), os mesmos arquivos que o \
             <code>xtask</code> usa para montar a tabela de exports do PE do kernel.</li></ul>",
            escape(exports.file_version.as_deref().unwrap_or("versão desconhecida")),
            if exports.unnamed > 0 {
                format!(" A tabela tem ainda {} só por número (ordinal), fora da conta.", plural(exports.unnamed, "entrada", "entradas"))
            } else {
                String::new()
            }
        ),
    ));

    let (tokens, labels) = search_data(exports);
    let search = format!("var EXPORTS=\"{tokens}\",GROUPS={labels},LIMIT={SEARCH_RESULTS};{SEARCH_SCRIPT}");
    html_page(
        "ntoskrnl.html",
        "Exports do ntoskrnl · OpenNT",
        "Quantos dos exports do ntoskrnl.exe do Windows 10 o kernel do OpenNT também exporta, por área do kernel.",
        &body,
        &[&search],
    )
}

fn group_nav(groups: &[(&'static str, &Tally)], index: usize) -> String {
    let previous = match index.checked_sub(1).and_then(|previous| groups.get(previous)) {
        Some((name, _)) => format!("<a href=\"{}\" rel=\"prev\">&larr; {}</a>", group_file(name), escape(name)),
        None => "<a href=\"ntoskrnl.html#grupos\">&larr; Todos os grupos</a>".to_string(),
    };
    let next = match groups.get(index + 1) {
        Some((name, _)) => format!("<a href=\"{}\" rel=\"next\">{} &rarr;</a>", group_file(name), escape(name)),
        None => "<a href=\"ntoskrnl.html#grupos\">Todos os grupos &rarr;</a>".to_string(),
    };
    format!("<nav class=\"groupnav\" aria-label=\"Grupos\">{previous}{next}</nav>")
}

fn group_page(report: &Report, groups: &[(&'static str, &Tally)], index: usize) -> String {
    let exports = &report.exports;
    let (name, tally) = groups[index];
    let info = prefix_info(name);
    let names: BTreeSet<&str> = exports.rows.iter().map(|row| row.name.as_str()).collect();
    let variables = tally.reference - tally.functions;
    let variables_opennt = tally.opennt - tally.functions_opennt;
    let mut extra = examples(name, &names);
    if name == "outros" {
        extra.push_str(&format!("<div class=\"examples\">Maiores subgrupos: {}</div>", other_prefixes(exports)));
    }
    let chips: String = groups
        .iter()
        .map(|(other, _)| {
            let mark = if *other == name { " aria-current=\"page\"" } else { "" };
            format!("<a href=\"{}\"{mark}>{}</a>", group_file(other), escape(other))
        })
        .collect();
    let mut body = format!(
        "<div class=\"pagehead\"><p class=\"crumbs\"><a href=\"ntoskrnl.html\">Exports do ntoskrnl</a> › grupo {} de {}</p>\
         <h1>{} <span class=\"muted\">· {}</span></h1><p class=\"lead\">{}</p><div class=\"card prefix\">{}<div>\
         <strong>{}</strong> de {} nomes deste grupo o OpenNT também exporta · faltam {}{}<span class=\"muted small\">{} \
         no Windows; {} no OpenNT</span>{}</div><div class=\"nums\"><strong>{}</strong></div></div></div>",
        int(index + 1),
        int(groups.len()),
        escape(name),
        escape(info.short),
        escape(info.long),
        icon_tile(prefix_icon(name), ""),
        int(tally.opennt),
        int(tally.reference),
        int(tally.missing()),
        meter(tally.opennt, 0, tally.reference, &percent(tally.opennt, tally.reference)),
        kinds(tally.functions, variables),
        kinds(tally.functions_opennt, variables_opennt),
        extra,
        escape(&percent(tally.opennt, tally.reference)),
    );
    body.push_str(&format!("<div class=\"chips\" aria-label=\"Outros grupos\">{chips}</div>"));
    body.push_str(&group_nav(groups, index));

    let mut rows = String::new();
    for row in exports.rows.iter().filter(|row| row.bucket == name) {
        rows.push_str(&format!(
            "<tr id=\"e-{name}\" data-item data-state=\"{state}\" data-text=\"{text}\"><td>{code}</td><td>{kind}</td>\
             <td>{opennt}</td></tr>",
            name = escape(&row.name),
            state = if row.opennt { "sim" } else { "nao" },
            text = escape(&row.name.to_lowercase()),
            code = code(&row.name),
            kind = if row.data { "variável" } else { "função" },
            opennt = if row.opennt { "<span class=\"yes\">exporta</span>" } else { "<span class=\"no\">falta</span>" },
        ));
    }
    let list = format!(
        "{}<div class=\"table-card scroll\" data-paginate=\"{EXPORTS_PER_PAGE}\"><table><thead><tr><th>Nome</th>\
         <th>Tipo</th><th>No OpenNT</th></tr></thead><tbody>{rows}</tbody></table></div>",
        filter_bar(
            "parte do nome",
            &[("sim", "que o OpenNT exporta"), ("nao", "que faltam no OpenNT")],
            tally.reference,
            ("export", "exports")
        )
    );
    body.push_str(&section(
        "lista",
        "Lista",
        &format!("Os {} exports do grupo {}", int(tally.reference), escape(name)),
        "<em>Função</em> é uma rotina que o driver chama; <em>variável</em> é um dado global exportado. \
         <em>Exporta</em> quer dizer que o nome está na tabela de exports do kernel do OpenNT.",
        &list,
    ));
    body.push_str(&group_nav(groups, index));
    html_page(
        "ntoskrnl.html",
        &format!("{name} · Exports do ntoskrnl · OpenNT"),
        &format!("Os exports {name} do ntoskrnl.exe do Windows 10 e quais o kernel do OpenNT também exporta."),
        &body,
        &[PAGER_SCRIPT],
    )
}

/// Uma página por grupo de prefixo com exports.
pub fn group_pages(report: &Report) -> Vec<(String, String)> {
    let groups = groups(&report.exports);
    (0..groups.len()).map(|index| (group_file(groups[index].0), group_page(report, &groups, index))).collect()
}
